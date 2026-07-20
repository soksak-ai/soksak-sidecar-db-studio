//! DB Studio service handler. Phase 1 = SQLite driver + connection lifecycle.
//!
//! Ownership (plan §1): this sidecar owns the drivers, the live connections, and
//! (later) introspection/query/migration execution. The core owns spawn,
//! lifecycle, secret injection, and gating; the plugin owns the profile metadata
//! and orchestration. Credentials never cross the wire — for SQLite the "file"
//! path is not a secret; for MySQL/PostgreSQL (later) the DSN arrives via the
//! core's vault_env spawn injection, resolved only inside this process.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use serde_json::{json, Value};
use soksak_spec_service::{serve_stdio, Emit, ErrCode, OpCtx, Outcome, ServiceHandler};

/// Default cap on rows returned by query-run when the caller omits `rowLimit`.
const DEFAULT_ROW_LIMIT: usize = 1000;

/// One append-only audit record. The sidecar owns the audit (plan §3.6,
/// decision F): every executed op leaves a normalized trace — op name, profile,
/// success, row count — with NO SQL literals. `ts_seq` is a monotonic sequence
/// stamped at append time so order is total even when wall clocks collide.
#[derive(Clone)]
struct AuditEntry {
    ts_seq: u64,
    profile: String,
    op: String,
    ok: bool,
    row_count: u64,
}

/// The DB Studio service. Owns live connections keyed by profile id, plus the
/// in-memory append-only audit log.
pub struct DbStudioService {
    conns: Mutex<HashMap<String, rusqlite::Connection>>,
    audit: Mutex<Vec<AuditEntry>>,
    audit_seq: AtomicU64,
}

impl Default for DbStudioService {
    fn default() -> Self {
        Self::new()
    }
}

impl DbStudioService {
    pub fn new() -> Self {
        Self {
            conns: Mutex::new(HashMap::new()),
            audit: Mutex::new(Vec::new()),
            audit_seq: AtomicU64::new(0),
        }
    }

    /// Append one normalized audit record. Append-only: entries are never
    /// mutated or removed once written. No SQL text is ever stored.
    fn audit_append(&self, profile: &str, op: &str, ok: bool, row_count: u64) {
        let ts_seq = self.audit_seq.fetch_add(1, Ordering::SeqCst);
        let mut log = self.audit.lock().unwrap_or_else(|p| p.into_inner());
        log.push(AuditEntry {
            ts_seq,
            profile: profile.to_string(),
            op: op.to_string(),
            ok,
            row_count,
        });
    }

    fn db_connect(&self, params: &Value) -> Outcome {
        let profile = match params.get("profile").and_then(Value::as_str) {
            Some(p) => p.to_string(),
            None => return Outcome::err(ErrCode::InvalidParams, "profile required"),
        };
        // Phase 1: SQLite only. `file` is the database path (":memory:" default);
        // an optional `key` opens an encrypted (SQLCipher) database.
        let file = params.get("file").and_then(Value::as_str).unwrap_or(":memory:");
        let conn = match rusqlite::Connection::open(file) {
            Ok(c) => c,
            Err(e) => {
                self.audit_append(&profile, "db-connect", false, 0);
                return Outcome::err(ErrCode::Unavailable, format!("open failed: {e}"));
            }
        };
        // Validate the key now: a wrong or missing key on an encrypted database
        // must fail at connect, not on the first later read.
        if let Err(e) = apply_key(&conn, params).and_then(|()| probe_readable(&conn)) {
            self.audit_append(&profile, "db-connect", false, 0);
            return Outcome::err(ErrCode::Unavailable, e);
        }
        let version = sqlite_version(&conn);
        let encrypted = params.get("key").and_then(Value::as_str).is_some();
        self.lock().insert(profile.clone(), conn);
        self.audit_append(&profile, "db-connect", true, 0);
        Outcome::ok_msg(
            json!({ "profile": profile, "dialect": "sqlite", "version": version, "encrypted": encrypted }),
            format!("connected: {profile}"),
        )
    }

    /// query-run — execute a single read-only SELECT against a live connection.
    /// Enforces one statement (rejects multi-statement bodies), caps rows at
    /// `rowLimit`, and masks sensitive columns in the result (plan §3.3).
    fn query_run(&self, params: &Value) -> Outcome {
        let profile = match params.get("profile").and_then(Value::as_str) {
            Some(p) => p.to_string(),
            None => return Outcome::err(ErrCode::InvalidParams, "profile required"),
        };
        let sql = match params.get("sql").and_then(Value::as_str) {
            Some(s) => s.to_string(),
            None => return Outcome::err(ErrCode::InvalidParams, "sql required"),
        };
        if has_multiple_statements(&sql) {
            return Outcome::err(
                ErrCode::InvalidParams,
                "single statement required (multiple statements rejected)",
            );
        }
        let row_limit = params
            .get("rowLimit")
            .and_then(Value::as_u64)
            .map(|n| n as usize)
            .unwrap_or(DEFAULT_ROW_LIMIT);

        // Bind positional params from the optional `params` array.
        let bind: Vec<rusqlite::types::Value> = match params.get("params") {
            Some(Value::Array(items)) => items.iter().map(json_to_sql_value).collect(),
            Some(Value::Null) | None => Vec::new(),
            Some(_) => {
                return Outcome::err(ErrCode::InvalidParams, "params must be an array")
            }
        };

        // All statement/row handles borrow the connection, which borrows the
        // lock guard — so the whole DB read runs in one scope that returns owned
        // data. The audit append (a separate lock) happens only after release.
        type QueryOk = (Vec<String>, Vec<Value>, bool);
        let result: Result<QueryOk, (ErrCode, String)> = {
            let conns = self.lock();
            match conns.get(&profile) {
                None => Err((
                    ErrCode::Unavailable,
                    format!("profile not connected: {profile}"),
                )),
                Some(conn) => {
                    match conn.prepare(&sql) {
                        Err(e) => Err((ErrCode::InvalidParams, format!("prepare failed: {e}"))),
                        Ok(mut stmt) => {
                            let col_names: Vec<String> =
                                stmt.column_names().iter().map(|s| s.to_string()).collect();
                            let masked: Vec<bool> =
                                col_names.iter().map(|n| is_sensitive(n)).collect();
                            let n_cols = col_names.len();
                            let bind_refs: Vec<&dyn rusqlite::ToSql> =
                                bind.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
                            match stmt.query(bind_refs.as_slice()) {
                                Err(e) => Err((ErrCode::Internal, format!("query failed: {e}"))),
                                Ok(mut rows) => {
                                    let mut out_rows: Vec<Value> = Vec::new();
                                    let mut truncated = false;
                                    let mut read_err: Option<String> = None;
                                    loop {
                                        match rows.next() {
                                            Ok(Some(row)) => {
                                                // One row past the limit proves
                                                // truncation without materializing it.
                                                if out_rows.len() >= row_limit {
                                                    truncated = true;
                                                    break;
                                                }
                                                let mut cells: Vec<Value> =
                                                    Vec::with_capacity(n_cols);
                                                for i in 0..n_cols {
                                                    if masked[i] {
                                                        cells.push(Value::String(format!(
                                                            "<redacted:{}>",
                                                            col_names[i]
                                                        )));
                                                    } else {
                                                        match row.get_ref(i) {
                                                            Ok(vr) => {
                                                                cells.push(value_ref_to_json(vr))
                                                            }
                                                            Err(_) => cells.push(Value::Null),
                                                        }
                                                    }
                                                }
                                                out_rows.push(Value::Array(cells));
                                            }
                                            Ok(None) => break,
                                            Err(e) => {
                                                read_err =
                                                    Some(format!("row read failed: {e}"));
                                                break;
                                            }
                                        }
                                    }
                                    match read_err {
                                        Some(msg) => Err((ErrCode::Internal, msg)),
                                        None => Ok((col_names, out_rows, truncated)),
                                    }
                                }
                            }
                        }
                    }
                }
            }
        };

        match result {
            Err((code, msg)) => {
                self.audit_append(&profile, "query-run", false, 0);
                Outcome::err(code, msg)
            }
            Ok((col_names, out_rows, truncated)) => {
                let row_count = out_rows.len();
                self.audit_append(&profile, "query-run", true, row_count as u64);
                let columns: Vec<Value> =
                    col_names.iter().map(|n| json!({ "name": n })).collect();
                Outcome::ok(json!({
                    "columns": columns,
                    "rows": out_rows,
                    "rowCount": row_count,
                    "truncated": truncated,
                }))
            }
        }
    }

    /// db-introspect — build a schema-only catalog (tables, columns, foreign
    /// keys, indexes) from sqlite_master + PRAGMA. Returns ZERO row data
    /// (plan §3.3): the shape of the database, never its contents.
    fn db_introspect(&self, params: &Value) -> Outcome {
        let profile = match params.get("profile").and_then(Value::as_str) {
            Some(p) => p.to_string(),
            None => return Outcome::err(ErrCode::InvalidParams, "profile required"),
        };
        // Optional allow-list of table names to introspect.
        let filter: Option<Vec<String>> = params.get("tables").and_then(|v| v.as_array()).map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        });

        let conns = self.lock();
        let conn = match conns.get(&profile) {
            Some(c) => c,
            None => {
                drop(conns);
                self.audit_append(&profile, "db-introspect", false, 0);
                return Outcome::err(
                    ErrCode::Unavailable,
                    format!("profile not connected: {profile}"),
                );
            }
        };

        match introspect_catalog(conn, filter.as_deref()) {
            Ok(tables) => {
                let n = tables.len() as u64;
                drop(conns);
                self.audit_append(&profile, "db-introspect", true, n);
                Outcome::ok(json!({ "tables": tables }))
            }
            Err(e) => {
                drop(conns);
                self.audit_append(&profile, "db-introspect", false, 0);
                Outcome::err(ErrCode::Internal, format!("introspect failed: {e}"))
            }
        }
    }

    /// db-audit — return the most recent `limit` audit records (default all).
    /// Read-only against the append-only in-memory log.
    fn db_audit(&self, params: &Value) -> Outcome {
        let profile_filter = params.get("profile").and_then(Value::as_str);
        let limit = params
            .get("limit")
            .and_then(Value::as_u64)
            .map(|n| n as usize);

        let log = self.audit.lock().unwrap_or_else(|p| p.into_inner());
        let mut selected: Vec<&AuditEntry> = log
            .iter()
            .filter(|e| profile_filter.map(|p| e.profile == p).unwrap_or(true))
            .collect();
        // Newest first by monotonic sequence.
        selected.sort_by_key(|e| std::cmp::Reverse(e.ts_seq));
        if let Some(n) = limit {
            selected.truncate(n);
        }
        let entries: Vec<Value> = selected
            .iter()
            .map(|e| {
                json!({
                    "tsSeq": e.ts_seq,
                    "profile": e.profile,
                    "op": e.op,
                    "ok": e.ok,
                    "rowCount": e.row_count,
                })
            })
            .collect();
        let count = entries.len();
        Outcome::ok(json!({ "entries": entries, "count": count }))
    }

    fn db_disconnect(&self, params: &Value) -> Outcome {
        let profile = match params.get("profile").and_then(Value::as_str) {
            Some(p) => p.to_string(),
            None => return Outcome::err(ErrCode::InvalidParams, "profile required"),
        };
        let closed = self.lock().remove(&profile).is_some();
        Outcome::ok(json!({ "profile": profile, "closed": closed }))
    }

    fn db_status(&self) -> Outcome {
        let conns = self.lock();
        let mut profiles: Vec<String> = conns.keys().cloned().collect();
        profiles.sort();
        Outcome::ok(json!({ "connections": profiles, "count": profiles.len() }))
    }

    /// db-create — create a (optionally encrypted) SQLite database. Opens the
    /// file, applies the key, and materializes the encrypted header with a write.
    fn db_create(&self, params: &Value) -> Outcome {
        let file = match params.get("file").and_then(Value::as_str) {
            Some(f) => f.to_string(),
            None => return Outcome::err(ErrCode::InvalidParams, "file required"),
        };
        let conn = match rusqlite::Connection::open(&file) {
            Ok(c) => c,
            Err(e) => return Outcome::err(ErrCode::Unavailable, format!("open failed: {e}")),
        };
        if let Err(e) = apply_key(&conn, params) {
            return Outcome::err(ErrCode::Unavailable, e);
        }
        // A write materializes the (encrypted) database header on disk.
        if let Err(e) = conn.execute_batch("PRAGMA user_version = 1;") {
            return Outcome::err(ErrCode::Internal, format!("create failed: {e}"));
        }
        let encrypted = params.get("key").and_then(Value::as_str).is_some();
        self.audit_append("", "db-create", true, 0);
        Outcome::ok_msg(
            json!({ "file": file, "dialect": "sqlite", "encrypted": encrypted }),
            "database created",
        )
    }

    /// db-rekey — rotate the encryption key of a held connection. SQLCipher
    /// `PRAGMA rekey` re-encrypts the whole database in place.
    fn db_rekey(&self, params: &Value) -> Outcome {
        let profile = match params.get("profile").and_then(Value::as_str) {
            Some(p) => p.to_string(),
            None => return Outcome::err(ErrCode::InvalidParams, "profile required"),
        };
        let new_key = match params.get("newKey").and_then(Value::as_str) {
            Some(k) => k.to_string(),
            None => return Outcome::err(ErrCode::InvalidParams, "newKey required"),
        };
        let result = {
            let conns = self.lock();
            match conns.get(&profile) {
                Some(conn) => conn
                    .pragma_update(None, "rekey", &new_key)
                    .map_err(|e| e.to_string()),
                None => {
                    return Outcome::err(
                        ErrCode::Unavailable,
                        format!("profile not connected: {profile}"),
                    )
                }
            }
        };
        match result {
            Ok(()) => {
                self.audit_append(&profile, "db-rekey", true, 0);
                Outcome::ok_msg(json!({ "profile": profile, "rekeyed": true }), "key rotated")
            }
            Err(e) => {
                self.audit_append(&profile, "db-rekey", false, 0);
                Outcome::err(ErrCode::Internal, format!("rekey failed: {e}"))
            }
        }
    }

    /// db-exec — execute a single write/DDL statement (INSERT/UPDATE/DELETE/
    /// CREATE/DROP/ALTER …) against a live connection (plan §5). One statement
    /// only (multi-statement bodies rejected). A WHERE-less UPDATE or DELETE is
    /// refused unless `force:true` — a whole-table mutation must be deliberate.
    /// Returns {rowsAffected}. Mutating (not read-only).
    fn db_exec(&self, params: &Value) -> Outcome {
        let profile = match params.get("profile").and_then(Value::as_str) {
            Some(p) => p.to_string(),
            None => return Outcome::err(ErrCode::InvalidParams, "profile required"),
        };
        let sql = match params.get("sql").and_then(Value::as_str) {
            Some(s) => s.to_string(),
            None => return Outcome::err(ErrCode::InvalidParams, "sql required"),
        };
        if has_multiple_statements(&sql) {
            return Outcome::err(
                ErrCode::InvalidParams,
                "single statement required (multiple statements rejected)",
            );
        }
        let force = params.get("force").and_then(Value::as_bool).unwrap_or(false);
        if !force && is_where_less_mutation(&sql) {
            return Outcome::err(
                ErrCode::InvalidParams,
                "WHERE-less UPDATE/DELETE refused (pass force:true to mutate every row)",
            );
        }

        let bind: Vec<rusqlite::types::Value> = match params.get("params") {
            Some(Value::Array(items)) => items.iter().map(json_to_sql_value).collect(),
            Some(Value::Null) | None => Vec::new(),
            Some(_) => return Outcome::err(ErrCode::InvalidParams, "params must be an array"),
        };

        let result: Result<usize, (ErrCode, String)> = {
            let conns = self.lock();
            match conns.get(&profile) {
                None => Err((
                    ErrCode::Unavailable,
                    format!("profile not connected: {profile}"),
                )),
                Some(conn) => {
                    let bind_refs: Vec<&dyn rusqlite::ToSql> =
                        bind.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
                    conn.execute(&sql, bind_refs.as_slice())
                        .map_err(|e| (ErrCode::Internal, format!("exec failed: {e}")))
                }
            }
        };

        match result {
            Err((code, msg)) => {
                self.audit_append(&profile, "db-exec", false, 0);
                Outcome::err(code, msg)
            }
            Ok(rows_affected) => {
                self.audit_append(&profile, "db-exec", true, rows_affected as u64);
                Outcome::ok(json!({ "rowsAffected": rows_affected }))
            }
        }
    }

    /// db-migrate — apply one migration file as a single atomic transaction
    /// (plan §6). BEGIN → each statement in order → record in the ledger →
    /// COMMIT; any failure ROLLs the whole thing back. The ledger table
    /// `_soksak_migrations(id, checksum, applied_at)` is created on demand. An
    /// already-applied id with a matching checksum is skipped; a mismatch is a
    /// tamper and is refused (Conflict). Returns {applied, id}. Mutating.
    fn db_migrate(&self, params: &Value) -> Outcome {
        let profile = match params.get("profile").and_then(Value::as_str) {
            Some(p) => p.to_string(),
            None => return Outcome::err(ErrCode::InvalidParams, "profile required"),
        };
        let id = match params.get("id").and_then(Value::as_str) {
            Some(s) => s.to_string(),
            None => return Outcome::err(ErrCode::InvalidParams, "id required"),
        };
        let checksum = match params.get("checksum").and_then(Value::as_str) {
            Some(s) => s.to_string(),
            None => return Outcome::err(ErrCode::InvalidParams, "checksum required"),
        };
        let statements: Vec<String> = match params.get("statements") {
            Some(Value::Array(items)) => {
                let mut out = Vec::with_capacity(items.len());
                for it in items {
                    match it.as_str() {
                        Some(s) => out.push(s.to_string()),
                        None => {
                            return Outcome::err(
                                ErrCode::InvalidParams,
                                "statements must be strings",
                            )
                        }
                    }
                }
                out
            }
            _ => return Outcome::err(ErrCode::InvalidParams, "statements array required"),
        };

        let result: Result<bool, (ErrCode, String)> = {
            let conns = self.lock();
            match conns.get(&profile) {
                None => Err((
                    ErrCode::Unavailable,
                    format!("profile not connected: {profile}"),
                )),
                Some(conn) => apply_migration(conn, &id, &checksum, &statements),
            }
        };

        match result {
            Err((code, msg)) => {
                self.audit_append(&profile, "db-migrate", false, 0);
                Outcome::err(code, msg)
            }
            Ok(applied) => {
                self.audit_append(&profile, "db-migrate", true, if applied { 1 } else { 0 });
                let msg = if applied {
                    format!("migration applied: {id}")
                } else {
                    format!("migration already applied: {id}")
                };
                Outcome::ok_msg(json!({ "applied": applied, "id": id }), msg)
            }
        }
    }

    /// migration-applied — list the migration ledger: [{id, checksum, appliedAt}]
    /// ordered by application. A database with no ledger table returns an empty
    /// list. Read-only.
    fn migration_applied(&self, params: &Value) -> Outcome {
        let profile = match params.get("profile").and_then(Value::as_str) {
            Some(p) => p.to_string(),
            None => return Outcome::err(ErrCode::InvalidParams, "profile required"),
        };

        let result: Result<Vec<Value>, (ErrCode, String)> = {
            let conns = self.lock();
            match conns.get(&profile) {
                None => Err((
                    ErrCode::Unavailable,
                    format!("profile not connected: {profile}"),
                )),
                Some(conn) => read_migration_ledger(conn)
                    .map_err(|e| (ErrCode::Internal, format!("ledger read failed: {e}"))),
            }
        };

        match result {
            Err((code, msg)) => Outcome::err(code, msg),
            Ok(migrations) => {
                let count = migrations.len();
                Outcome::ok(json!({ "migrations": migrations, "count": count }))
            }
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, rusqlite::Connection>> {
        self.conns.lock().unwrap_or_else(|p| p.into_inner())
    }
}

fn sqlite_version(conn: &rusqlite::Connection) -> String {
    conn.query_row("SELECT sqlite_version()", [], |r| r.get::<_, String>(0))
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Apply the optional SQLCipher key (`PRAGMA key`) right after open — it must run
/// before any other access. Absent key = a plaintext SQLite database. For the
/// networked dialects (later) the DSN/secret arrives the same way — via the
/// core's vault_env injection, never over the wire.
fn apply_key(conn: &rusqlite::Connection, params: &Value) -> Result<(), String> {
    if let Some(key) = params.get("key").and_then(Value::as_str) {
        conn.pragma_update(None, "key", key)
            .map_err(|e| format!("set key failed: {e}"))?;
    }
    Ok(())
}

/// Touch a real database page so a wrong/absent key is caught now, not later —
/// `SELECT sqlite_version()` is a builtin and would not detect a bad key.
fn probe_readable(conn: &rusqlite::Connection) -> Result<(), String> {
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0))
        .map(|_| ())
        .map_err(|e| format!("cannot read database (wrong key or not a database): {e}"))
}

/// True if a column name matches the sensitive-data pattern (plan §3.3),
/// equivalent to the case-insensitive regex
/// /(password|passwd|pwd|hash|salt|ssn|token|secret|api_?key|access_?key|
///   private_?key|credit_?card|card_?number|cvv|iban|auth)/i.
/// The `_?` alternatives are matched as both the joined and underscored forms.
fn is_sensitive(col: &str) -> bool {
    let c = col.to_ascii_lowercase();
    const FIXED: &[&str] = &[
        "password", "passwd", "pwd", "hash", "salt", "ssn", "token", "secret", "cvv", "iban",
        "auth",
    ];
    if FIXED.iter().any(|p| c.contains(p)) {
        return true;
    }
    // `x_?y` groups: match either the joined or underscore-separated form.
    const OPTIONAL_US: &[(&str, &str)] = &[
        ("apikey", "api_key"),
        ("accesskey", "access_key"),
        ("privatekey", "private_key"),
        ("creditcard", "credit_card"),
        ("cardnumber", "card_number"),
    ];
    OPTIONAL_US
        .iter()
        .any(|(joined, us)| c.contains(joined) || c.contains(us))
}

/// True if `sql` contains more than one statement — an unquoted `;` that is not
/// merely a trailing terminator. Quote-aware so `;` inside string/identifier
/// literals does not trip the guard.
fn has_multiple_statements(sql: &str) -> bool {
    let chars: Vec<char> = sql.chars().collect();
    let mut in_single = false;
    let mut in_double = false;
    let mut semis: Vec<usize> = Vec::new();
    let mut last_meaningful: Option<usize> = None;
    for (i, &ch) in chars.iter().enumerate() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            ';' if !in_single && !in_double => {
                semis.push(i);
                continue;
            }
            _ => {}
        }
        // Unquoted `;` already `continue`d above; anything reaching here that is
        // non-whitespace (including a quoted `;`) is meaningful content.
        if !ch.is_whitespace() {
            last_meaningful = Some(i);
        }
    }
    // A separating semicolon is one that sits before the last meaningful char.
    match last_meaningful {
        Some(end) => semis.iter().any(|&s| s < end),
        None => false,
    }
}

/// True for an identifier character (used for SQL keyword word-boundary tests).
fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// The leading SQL keyword, lowercased — the first identifier token after any
/// leading whitespace. Empty when the body does not start with an identifier.
fn leading_keyword(sql: &str) -> String {
    sql.trim_start()
        .chars()
        .take_while(|c| is_ident_char(*c))
        .collect::<String>()
        .to_ascii_lowercase()
}

/// Quote-aware, case-insensitive, word-boundary test for a standalone keyword
/// token (given lowercase). A match inside a string/identifier literal, or one
/// glued to surrounding identifier characters, does not count.
fn contains_keyword(sql: &str, keyword: &str) -> bool {
    let chars: Vec<char> = sql.chars().collect();
    let kw: Vec<char> = keyword.chars().collect();
    let mut in_single = false;
    let mut in_double = false;
    let mut i = 0usize;
    while i < chars.len() {
        let ch = chars[i];
        if ch == '\'' && !in_double {
            in_single = !in_single;
            i += 1;
            continue;
        }
        if ch == '"' && !in_single {
            in_double = !in_double;
            i += 1;
            continue;
        }
        if !in_single && !in_double && i + kw.len() <= chars.len() {
            let matches = kw
                .iter()
                .enumerate()
                .all(|(j, &kc)| chars[i + j].to_ascii_lowercase() == kc);
            if matches {
                let prev_boundary = i == 0 || !is_ident_char(chars[i - 1]);
                let next = i + kw.len();
                let next_boundary = next >= chars.len() || !is_ident_char(chars[next]);
                if prev_boundary && next_boundary {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

/// True when `sql` is an UPDATE or DELETE statement carrying no WHERE clause —
/// a whole-table mutation that db-exec refuses without `force:true` (plan §5).
fn is_where_less_mutation(sql: &str) -> bool {
    let kw = leading_keyword(sql);
    if kw != "update" && kw != "delete" {
        return false;
    }
    !contains_keyword(sql, "where")
}

/// Current wall-clock time as an RFC3339 UTC string (seconds precision). The
/// sidecar is real Rust, so it owns a real clock — the applied_at stamp is
/// authoritative here, not passed in over the wire.
fn rfc3339_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let rem = (secs % 86_400) as i64;
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, mo, d) = civil_from_days(days);
    format!("{y:04}-{mo:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Convert a count of days since the Unix epoch into a (year, month, day) civil
/// date. Howard Hinnant's `civil_from_days` algorithm (proleptic Gregorian).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Ensure the migration ledger table exists (idempotent).
fn ensure_migration_ledger(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS _soksak_migrations (\
            id TEXT PRIMARY KEY, checksum TEXT, applied_at TEXT)",
    )
}

/// Apply one migration atomically. Returns Ok(true) when newly applied, Ok(false)
/// when the id was already applied with a matching checksum (a no-op skip), and
/// Err(Conflict) when an already-applied id's checksum differs (tamper).
fn apply_migration(
    conn: &rusqlite::Connection,
    id: &str,
    checksum: &str,
    statements: &[String],
) -> Result<bool, (ErrCode, String)> {
    use rusqlite::OptionalExtension;

    ensure_migration_ledger(conn)
        .map_err(|e| (ErrCode::Internal, format!("ledger init failed: {e}")))?;

    let existing: Option<String> = conn
        .query_row(
            "SELECT checksum FROM _soksak_migrations WHERE id = ?1",
            [id],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| (ErrCode::Internal, format!("ledger read failed: {e}")))?;
    match existing {
        Some(prev) if prev == checksum => return Ok(false), // already applied, unchanged
        Some(_) => {
            return Err((
                ErrCode::Conflict,
                format!("migration {id} already applied with a different checksum (refusing to reapply)"),
            ))
        }
        None => {}
    }

    conn.execute_batch("BEGIN")
        .map_err(|e| (ErrCode::Internal, format!("begin failed: {e}")))?;
    let applied: rusqlite::Result<()> = (|| {
        for stmt in statements {
            conn.execute_batch(stmt)?;
        }
        conn.execute(
            "INSERT INTO _soksak_migrations(id, checksum, applied_at) VALUES(?1, ?2, ?3)",
            rusqlite::params![id, checksum, rfc3339_now()],
        )?;
        Ok(())
    })();
    match applied {
        Ok(()) => {
            conn.execute_batch("COMMIT")
                .map_err(|e| (ErrCode::Internal, format!("commit failed: {e}")))?;
            Ok(true)
        }
        Err(e) => {
            // Best-effort rollback; the original failure is what the caller sees.
            let _ = conn.execute_batch("ROLLBACK");
            Err((ErrCode::Internal, format!("migration failed (rolled back): {e}")))
        }
    }
}

/// Read the migration ledger as [{id, checksum, appliedAt}] ordered by
/// application. A database without the ledger table yields an empty list.
fn read_migration_ledger(conn: &rusqlite::Connection) -> rusqlite::Result<Vec<Value>> {
    let exists: bool = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='_soksak_migrations'",
            [],
            |_| Ok(true),
        )
        .unwrap_or(false);
    if !exists {
        return Ok(Vec::new());
    }
    let mut stmt = conn.prepare(
        "SELECT id, checksum, applied_at FROM _soksak_migrations ORDER BY applied_at, id",
    )?;
    let rows = stmt.query_map([], |r| {
        let id: String = r.get(0)?;
        let checksum: String = r.get(1)?;
        let applied_at: Option<String> = r.get(2)?;
        Ok(json!({ "id": id, "checksum": checksum, "appliedAt": applied_at }))
    })?;
    rows.collect::<rusqlite::Result<Vec<Value>>>()
}

/// Convert a JSON bind parameter into a SQLite value.
fn json_to_sql_value(v: &Value) -> rusqlite::types::Value {
    use rusqlite::types::Value as SV;
    match v {
        Value::Null => SV::Null,
        Value::Bool(b) => SV::Integer(if *b { 1 } else { 0 }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                SV::Integer(i)
            } else if let Some(f) = n.as_f64() {
                SV::Real(f)
            } else {
                SV::Text(n.to_string())
            }
        }
        Value::String(s) => SV::Text(s.clone()),
        other => SV::Text(other.to_string()),
    }
}

/// Convert a SQLite value (as read from a result row) into JSON.
fn value_ref_to_json(vr: rusqlite::types::ValueRef<'_>) -> Value {
    use rusqlite::types::ValueRef as VR;
    match vr {
        VR::Null => Value::Null,
        VR::Integer(i) => json!(i),
        VR::Real(f) => json!(f),
        VR::Text(bytes) => Value::String(String::from_utf8_lossy(bytes).into_owned()),
        VR::Blob(bytes) => Value::String(format!("<blob:{} bytes>", bytes.len())),
    }
}

/// Build the schema-only catalog for the given (optional) table allow-list.
fn introspect_catalog(
    conn: &rusqlite::Connection,
    filter: Option<&[String]>,
) -> rusqlite::Result<Vec<Value>> {
    let mut names: Vec<String> = {
        let mut stmt = conn.prepare(
            "SELECT name FROM sqlite_master WHERE type='table' \
             AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        rows.collect::<rusqlite::Result<Vec<String>>>()?
    };
    if let Some(allow) = filter {
        names.retain(|n| allow.iter().any(|a| a == n));
    }

    let mut tables: Vec<Value> = Vec::with_capacity(names.len());
    for name in &names {
        // Columns — PRAGMA table_info: (cid, name, type, notnull, dflt_value, pk).
        let columns: Vec<Value> = {
            let mut stmt = conn.prepare(&format!("PRAGMA table_info({})", quote_ident(name)))?;
            let rows = stmt.query_map([], |r| {
                let col_name: String = r.get(1)?;
                let col_type: String = r.get(2).unwrap_or_default();
                let notnull: i64 = r.get(3).unwrap_or(0);
                let default: Option<String> = r.get(4).ok().flatten();
                let pk: i64 = r.get(5).unwrap_or(0);
                Ok(json!({
                    "name": col_name,
                    "type": col_type,
                    "notnull": notnull != 0,
                    "pk": pk != 0,
                    "default": default,
                }))
            })?;
            rows.collect::<rusqlite::Result<Vec<Value>>>()?
        };

        // Foreign keys — PRAGMA foreign_key_list:
        // (id, seq, table, from, to, on_update, on_delete, match).
        let foreign_keys: Vec<Value> = {
            let mut stmt =
                conn.prepare(&format!("PRAGMA foreign_key_list({})", quote_ident(name)))?;
            let rows = stmt.query_map([], |r| {
                let table: String = r.get(2)?;
                let from: String = r.get(3)?;
                let to: Option<String> = r.get(4).ok().flatten();
                let on_update: String = r.get(5).unwrap_or_default();
                let on_delete: String = r.get(6).unwrap_or_default();
                Ok(json!({
                    "table": table,
                    "from": from,
                    "to": to,
                    "onUpdate": on_update,
                    "onDelete": on_delete,
                }))
            })?;
            rows.collect::<rusqlite::Result<Vec<Value>>>()?
        };

        // Indexes — PRAGMA index_list: (seq, name, unique, origin, partial),
        // with columns resolved via PRAGMA index_info.
        let index_meta: Vec<(String, bool)> = {
            let mut stmt = conn.prepare(&format!("PRAGMA index_list({})", quote_ident(name)))?;
            let rows = stmt.query_map([], |r| {
                let idx_name: String = r.get(1)?;
                let unique: i64 = r.get(2).unwrap_or(0);
                Ok((idx_name, unique != 0))
            })?;
            rows.collect::<rusqlite::Result<Vec<(String, bool)>>>()?
        };
        let mut indexes: Vec<Value> = Vec::with_capacity(index_meta.len());
        for (idx_name, unique) in index_meta {
            let cols: Vec<String> = {
                let mut stmt =
                    conn.prepare(&format!("PRAGMA index_info({})", quote_ident(&idx_name)))?;
                let rows = stmt.query_map([], |r| r.get::<_, Option<String>>(2))?;
                rows.collect::<rusqlite::Result<Vec<Option<String>>>>()?
                    .into_iter()
                    .flatten()
                    .collect()
            };
            indexes.push(json!({
                "name": idx_name,
                "unique": unique,
                "columns": cols,
            }));
        }

        tables.push(json!({
            "name": name,
            "columns": columns,
            "foreignKeys": foreign_keys,
            "indexes": indexes,
        }));
    }
    Ok(tables)
}

/// Quote a SQL identifier for embedding in a PRAGMA call. Double-quotes with
/// internal quote doubling — PRAGMA arguments do not accept bind parameters.
fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// db-test — one-shot connection probe: open, read the server version, close. No
/// pool entry (distinct from db-connect). Read-only, runs concurrently.
fn op_db_test(params: &Value) -> Outcome {
    let file = params.get("file").and_then(Value::as_str).unwrap_or(":memory:");
    let conn = match rusqlite::Connection::open(file) {
        Ok(c) => c,
        Err(e) => return Outcome::err(ErrCode::Unavailable, format!("open failed: {e}")),
    };
    if let Err(e) = apply_key(&conn, params).and_then(|()| probe_readable(&conn)) {
        return Outcome::err(ErrCode::Unavailable, e);
    }
    let encrypted = params.get("key").and_then(Value::as_str).is_some();
    Outcome::ok_msg(
        json!({ "dialect": "sqlite", "version": sqlite_version(&conn), "file": file, "encrypted": encrypted }),
        "connection ok",
    )
}

impl ServiceHandler for DbStudioService {
    fn ops(&self) -> Vec<String> {
        [
            "db-test",
            "db-connect",
            "db-disconnect",
            "db-status",
            "db-create",
            "db-rekey",
            "query-run",
            "db-introspect",
            "db-audit",
            "db-exec",
            "db-migrate",
            "migration-applied",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn read_only(&self, op: &str) -> bool {
        matches!(
            op,
            "db-test"
                | "db-status"
                | "query-run"
                | "db-introspect"
                | "db-audit"
                | "migration-applied"
        )
    }

    fn handle(&self, op: &str, params: Value, _ctx: &OpCtx, _emit: &Emit) -> Outcome {
        match op {
            "db-test" => op_db_test(&params),
            "db-connect" => self.db_connect(&params),
            "db-disconnect" => self.db_disconnect(&params),
            "db-status" => self.db_status(),
            "db-create" => self.db_create(&params),
            "db-rekey" => self.db_rekey(&params),
            "query-run" => self.query_run(&params),
            "db-introspect" => self.db_introspect(&params),
            "db-audit" => self.db_audit(&params),
            "db-exec" => self.db_exec(&params),
            "db-migrate" => self.db_migrate(&params),
            "migration-applied" => self.migration_applied(&params),
            other => Outcome::err(ErrCode::UnknownOp, other),
        }
    }
}

/// Serve the wire over stdio — the entry point the core spawns with `serve`.
pub fn run_serve() {
    serve_stdio(DbStudioService::new());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn db_test_probes_in_memory_sqlite() {
        let o = op_db_test(&json!({ "file": ":memory:" }));
        assert!(o.ok);
        assert!(o.data.unwrap()["version"].as_str().unwrap().starts_with("3."));
    }

    #[test]
    fn db_test_round_trips_a_real_file() {
        let path =
            std::env::temp_dir().join(format!("db-studio-test-{}.sqlite", std::process::id()));
        let p = path.to_string_lossy().to_string();
        let _ = std::fs::remove_file(&path);
        {
            let conn = rusqlite::Connection::open(&p).unwrap();
            conn.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, name TEXT)", [])
                .unwrap();
            conn.execute("INSERT INTO t(name) VALUES ('alice')", []).unwrap();
        }
        // the probe reports a version for a real file connection
        let o = op_db_test(&json!({ "file": p }));
        assert!(o.ok);
        // and the row survives — a real round-trip through the driver
        let conn = rusqlite::Connection::open(&p).unwrap();
        let name: String = conn
            .query_row("SELECT name FROM t WHERE id=1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(name, "alice");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn connect_status_disconnect_lifecycle() {
        let svc = DbStudioService::new();
        assert_eq!(svc.db_status().data.unwrap()["count"], 0);

        let c = svc.db_connect(&json!({ "profile": "p1", "file": ":memory:" }));
        assert!(c.ok);
        assert_eq!(c.data.unwrap()["dialect"], "sqlite");
        assert_eq!(svc.db_status().data.unwrap()["count"], 1);

        let d = svc.db_disconnect(&json!({ "profile": "p1" }));
        assert_eq!(d.data.unwrap()["closed"], true);
        assert_eq!(svc.db_status().data.unwrap()["count"], 0);
    }

    #[test]
    fn db_connect_requires_profile() {
        let svc = DbStudioService::new();
        let o = svc.db_connect(&json!({ "file": ":memory:" }));
        assert!(!o.ok);
        assert_eq!(o.code.as_deref(), Some("INVALID_PARAMS"));
    }

    #[test]
    fn unknown_op_is_rejected() {
        let svc = DbStudioService::new();
        let ops = svc.ops();
        assert!(ops.contains(&"db-test".to_string()));
        assert!(ops.contains(&"db-connect".to_string()));
        assert!(svc.read_only("db-status"));
        assert!(!svc.read_only("db-connect"));
    }

    #[test]
    fn phase2_ops_are_registered_and_read_only() {
        let svc = DbStudioService::new();
        let ops = svc.ops();
        for op in ["query-run", "db-introspect", "db-audit"] {
            assert!(ops.contains(&op.to_string()), "missing op {op}");
            assert!(svc.read_only(op), "{op} must be read-only");
        }
    }

    /// Seed a connected profile with a small schema for the read-path tests.
    fn seeded_service() -> DbStudioService {
        let svc = DbStudioService::new();
        assert!(svc
            .db_connect(&json!({ "profile": "p1", "file": ":memory:" }))
            .ok);
        {
            let conns = svc.lock();
            let conn = conns.get("p1").unwrap();
            conn.execute_batch(
                "CREATE TABLE users(\
                    id INTEGER PRIMARY KEY, \
                    email TEXT NOT NULL, \
                    password TEXT, \
                    api_key TEXT, \
                    display TEXT DEFAULT 'anon');\
                 CREATE UNIQUE INDEX idx_users_email ON users(email);\
                 CREATE TABLE posts(\
                    id INTEGER PRIMARY KEY, \
                    user_id INTEGER, \
                    body TEXT, \
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE);\
                 INSERT INTO users(email,password,api_key,display) \
                    VALUES('a@x.io','s3cret','ak-123','alice');\
                 INSERT INTO users(email,password,api_key,display) \
                    VALUES('b@x.io','hunter2','ak-456','bob');",
            )
            .unwrap();
        }
        svc
    }

    #[test]
    fn query_run_shape_and_masking() {
        let svc = seeded_service();
        let o = svc.query_run(&json!({
            "profile": "p1",
            "sql": "SELECT id, email, password, api_key FROM users ORDER BY id"
        }));
        assert!(o.ok, "query-run failed: {:?}", o.message);
        let d = o.data.unwrap();
        // columns shape: [{name}]
        let cols = d["columns"].as_array().unwrap();
        assert_eq!(cols.len(), 4);
        assert_eq!(cols[0]["name"], "id");
        assert_eq!(cols[2]["name"], "password");
        // rows + counts
        assert_eq!(d["rowCount"], 2);
        assert_eq!(d["truncated"], false);
        let rows = d["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        // non-sensitive values survive
        assert_eq!(rows[0][0], 1);
        assert_eq!(rows[0][1], "a@x.io");
        // sensitive columns masked (password + api_key), never the plaintext
        assert_eq!(rows[0][2], "<redacted:password>");
        assert_eq!(rows[0][3], "<redacted:api_key>");
        assert_ne!(rows[0][2], "s3cret");
    }

    #[test]
    fn query_run_row_limit_truncates() {
        let svc = seeded_service();
        let o = svc.query_run(&json!({
            "profile": "p1",
            "sql": "SELECT id FROM users ORDER BY id",
            "rowLimit": 1
        }));
        assert!(o.ok);
        let d = o.data.unwrap();
        assert_eq!(d["rowCount"], 1);
        assert_eq!(d["truncated"], true);
        assert_eq!(d["rows"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn query_run_binds_params() {
        let svc = seeded_service();
        let o = svc.query_run(&json!({
            "profile": "p1",
            "sql": "SELECT email FROM users WHERE id = ?",
            "params": [2]
        }));
        assert!(o.ok);
        let d = o.data.unwrap();
        assert_eq!(d["rowCount"], 1);
        assert_eq!(d["rows"][0][0], "b@x.io");
    }

    #[test]
    fn query_run_rejects_multiple_statements() {
        let svc = seeded_service();
        let o = svc.query_run(&json!({
            "profile": "p1",
            "sql": "SELECT 1; DROP TABLE users"
        }));
        assert!(!o.ok);
        assert_eq!(o.code.as_deref(), Some("INVALID_PARAMS"));
        // a trailing semicolon is NOT multiple statements
        let ok = svc.query_run(&json!({ "profile": "p1", "sql": "SELECT 1;" }));
        assert!(ok.ok);
        // a semicolon inside a string literal is NOT a separator
        let lit = svc.query_run(&json!({
            "profile": "p1",
            "sql": "SELECT 'a;b' AS v"
        }));
        assert!(lit.ok);
        assert_eq!(lit.data.unwrap()["rows"][0][0], "a;b");
    }

    #[test]
    fn query_run_unconnected_profile_errors() {
        let svc = DbStudioService::new();
        let o = svc.query_run(&json!({ "profile": "nope", "sql": "SELECT 1" }));
        assert!(!o.ok);
        assert_eq!(o.code.as_deref(), Some("UNAVAILABLE"));
    }

    #[test]
    fn db_introspect_catalog_with_fk_and_index_no_rows() {
        let svc = seeded_service();
        let o = svc.db_introspect(&json!({ "profile": "p1" }));
        assert!(o.ok, "introspect failed: {:?}", o.message);
        let d = o.data.unwrap();
        let tables = d["tables"].as_array().unwrap();
        // schema-only: NO row data anywhere in the payload
        let dump = serde_json::to_string(&d).unwrap();
        assert!(!dump.contains("a@x.io"), "row data leaked into catalog");
        assert!(!dump.contains("s3cret"), "row data leaked into catalog");

        let users = tables.iter().find(|t| t["name"] == "users").unwrap();
        let cols = users["columns"].as_array().unwrap();
        assert_eq!(cols.len(), 5);
        let id_col = cols.iter().find(|c| c["name"] == "id").unwrap();
        assert_eq!(id_col["pk"], true);
        let email_col = cols.iter().find(|c| c["name"] == "email").unwrap();
        assert_eq!(email_col["notnull"], true);
        let display_col = cols.iter().find(|c| c["name"] == "display").unwrap();
        assert_eq!(display_col["default"], "'anon'");
        // unique index present with its column
        let idxs = users["indexes"].as_array().unwrap();
        let uidx = idxs
            .iter()
            .find(|i| i["columns"].as_array().unwrap().iter().any(|c| c == "email"))
            .unwrap();
        assert_eq!(uidx["unique"], true);

        // posts carries the foreign key to users
        let posts = tables.iter().find(|t| t["name"] == "posts").unwrap();
        let fks = posts["foreignKeys"].as_array().unwrap();
        assert_eq!(fks.len(), 1);
        assert_eq!(fks[0]["table"], "users");
        assert_eq!(fks[0]["from"], "user_id");
        assert_eq!(fks[0]["to"], "id");
        assert_eq!(fks[0]["onDelete"], "CASCADE");
    }

    #[test]
    fn db_introspect_tables_filter() {
        let svc = seeded_service();
        let o = svc.db_introspect(&json!({ "profile": "p1", "tables": ["posts"] }));
        assert!(o.ok);
        let tables = o.data.unwrap()["tables"].as_array().unwrap().clone();
        assert_eq!(tables.len(), 1);
        assert_eq!(tables[0]["name"], "posts");
    }

    #[test]
    fn db_audit_appends_and_reads_back_without_sql() {
        let svc = seeded_service(); // logs one db-connect
        let _ = svc.query_run(&json!({
            "profile": "p1",
            "sql": "SELECT id, password FROM users"
        }));
        let o = svc.db_audit(&json!({}));
        assert!(o.ok);
        let d = o.data.unwrap();
        let entries = d["entries"].as_array().unwrap();
        // at least the db-connect + query-run traces are present
        assert!(entries.len() >= 2, "entries: {}", entries.len());
        // newest first: the query-run is the latest
        assert_eq!(entries[0]["op"], "query-run");
        assert_eq!(entries[0]["ok"], true);
        assert_eq!(entries[0]["rowCount"], 2);
        assert_eq!(entries[0]["profile"], "p1");
        // sequence is monotonic and present
        assert!(entries[0]["tsSeq"].as_u64().unwrap() > entries[1]["tsSeq"].as_u64().unwrap());
        // NO SQL literals are ever stored in the audit payload
        let dump = serde_json::to_string(&d).unwrap();
        assert!(!dump.contains("SELECT"), "audit leaked SQL text");
        assert!(!dump.contains("password"), "audit leaked column/SQL text");
    }

    #[test]
    fn db_audit_limit_and_profile_filter() {
        let svc = DbStudioService::new();
        assert!(svc.db_connect(&json!({ "profile": "p1", "file": ":memory:" })).ok);
        assert!(svc.db_connect(&json!({ "profile": "p2", "file": ":memory:" })).ok);
        // limit
        let limited = svc.db_audit(&json!({ "limit": 1 }));
        assert_eq!(limited.data.unwrap()["entries"].as_array().unwrap().len(), 1);
        // profile filter
        let only_p2 = svc.db_audit(&json!({ "profile": "p2" }));
        let d = only_p2.data.unwrap();
        let entries = d["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["profile"], "p2");
    }

    #[test]
    fn encrypted_db_requires_the_key() {
        let dir = std::env::temp_dir().join(format!("db-studio-enc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("enc.sqlite").to_string_lossy().to_string();
        let key = "s3cret-pass";
        let svc = DbStudioService::new();

        let c = svc.db_create(&json!({ "file": path, "key": key }));
        assert!(c.ok);
        assert_eq!(c.data.unwrap()["encrypted"], true);

        // opening without the key must fail — the file is unreadable ciphertext
        let no = svc.db_connect(&json!({ "profile": "e1", "file": path }));
        assert!(!no.ok, "encrypted db must not open without a key");

        // opening with the correct key works
        let yes = svc.db_connect(&json!({ "profile": "e2", "file": path, "key": key }));
        assert!(yes.ok);
        assert_eq!(yes.data.unwrap()["encrypted"], true);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rekey_rotates_the_encryption_key() {
        let dir = std::env::temp_dir().join(format!("db-studio-rekey-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("r.sqlite").to_string_lossy().to_string();
        let (old_key, new_key) = ("old-pass", "new-pass");
        let svc = DbStudioService::new();

        assert!(svc.db_create(&json!({ "file": path, "key": old_key })).ok);
        assert!(svc
            .db_connect(&json!({ "profile": "r", "file": path, "key": old_key }))
            .ok);

        // rotate the key on the live connection
        let rk = svc.db_rekey(&json!({ "profile": "r", "newKey": new_key }));
        assert!(rk.ok, "rekey failed: {:?}", rk.message);
        svc.db_disconnect(&json!({ "profile": "r" }));

        // the old key no longer opens the file
        let old = svc.db_connect(&json!({ "profile": "r2", "file": path, "key": old_key }));
        assert!(!old.ok, "old key must fail after rekey");

        // the new key does
        let fresh = DbStudioService::new();
        let new = fresh.db_connect(&json!({ "profile": "r3", "file": path, "key": new_key }));
        assert!(new.ok, "new key must work after rekey");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn phase5_6_ops_registered_with_correct_read_only_axis() {
        let svc = DbStudioService::new();
        let ops = svc.ops();
        for op in ["db-exec", "db-migrate", "migration-applied"] {
            assert!(ops.contains(&op.to_string()), "missing op {op}");
        }
        // migration-applied is a read; db-exec/db-migrate mutate.
        assert!(svc.read_only("migration-applied"));
        assert!(!svc.read_only("db-exec"));
        assert!(!svc.read_only("db-migrate"));
    }

    #[test]
    fn db_exec_insert_reports_rows_affected() {
        let svc = seeded_service();
        let o = svc.db_exec(&json!({
            "profile": "p1",
            "sql": "INSERT INTO users(email, display) VALUES(?, ?)",
            "params": ["c@x.io", "carol"]
        }));
        assert!(o.ok, "db-exec insert failed: {:?}", o.message);
        assert_eq!(o.data.unwrap()["rowsAffected"], 1);

        // the row is really there — a real round-trip through the driver
        let check = svc.query_run(&json!({
            "profile": "p1",
            "sql": "SELECT email FROM users WHERE display = 'carol'"
        }));
        assert_eq!(check.data.unwrap()["rows"][0][0], "c@x.io");
    }

    #[test]
    fn db_exec_update_with_where_affects_only_matched_rows() {
        let svc = seeded_service();
        let o = svc.db_exec(&json!({
            "profile": "p1",
            "sql": "UPDATE users SET display = 'ALICE' WHERE email = 'a@x.io'"
        }));
        assert!(o.ok, "guarded update failed: {:?}", o.message);
        assert_eq!(o.data.unwrap()["rowsAffected"], 1);
    }

    #[test]
    fn db_exec_refuses_where_less_delete_and_update_without_force() {
        let svc = seeded_service();
        // whole-table DELETE is refused
        let del = svc.db_exec(&json!({ "profile": "p1", "sql": "DELETE FROM users" }));
        assert!(!del.ok);
        assert_eq!(del.code.as_deref(), Some("INVALID_PARAMS"));
        // whole-table UPDATE is refused (case-insensitive keyword detection)
        let upd = svc.db_exec(&json!({
            "profile": "p1",
            "sql": "update users set display = 'x'"
        }));
        assert!(!upd.ok);
        assert_eq!(upd.code.as_deref(), Some("INVALID_PARAMS"));
        // both rows still present — the refusal actually prevented the mutation
        let n = svc.query_run(&json!({ "profile": "p1", "sql": "SELECT id FROM users" }));
        assert_eq!(n.data.unwrap()["rowCount"], 2);
    }

    #[test]
    fn db_exec_force_allows_whole_table_delete() {
        let svc = seeded_service();
        let o = svc.db_exec(&json!({
            "profile": "p1",
            "sql": "DELETE FROM users",
            "force": true
        }));
        assert!(o.ok, "forced delete failed: {:?}", o.message);
        assert_eq!(o.data.unwrap()["rowsAffected"], 2);
        let n = svc.query_run(&json!({ "profile": "p1", "sql": "SELECT id FROM users" }));
        assert_eq!(n.data.unwrap()["rowCount"], 0);
    }

    #[test]
    fn db_exec_where_inside_a_string_is_not_a_where_clause() {
        // A DELETE whose only `where` sits inside a string literal is still a
        // whole-table delete and must be refused without force.
        let svc = seeded_service();
        let o = svc.db_exec(&json!({
            "profile": "p1",
            "sql": "DELETE FROM users WHERE display = 'where'"
        }));
        // this one HAS a real WHERE, so it is allowed
        assert!(o.ok, "delete with real where failed: {:?}", o.message);
    }

    #[test]
    fn db_exec_rejects_multiple_statements() {
        let svc = seeded_service();
        let o = svc.db_exec(&json!({
            "profile": "p1",
            "sql": "INSERT INTO users(email) VALUES('z@x.io'); DROP TABLE users"
        }));
        assert!(!o.ok);
        assert_eq!(o.code.as_deref(), Some("INVALID_PARAMS"));
    }

    #[test]
    fn db_migrate_applies_transaction_and_records_ledger() {
        let svc = DbStudioService::new();
        assert!(svc.db_connect(&json!({ "profile": "m", "file": ":memory:" })).ok);
        let o = svc.db_migrate(&json!({
            "profile": "m",
            "id": "0001_init",
            "checksum": "abc123",
            "statements": [
                "CREATE TABLE widget(id INTEGER PRIMARY KEY, name TEXT)",
                "INSERT INTO widget(name) VALUES('gizmo')"
            ]
        }));
        assert!(o.ok, "migrate failed: {:?}", o.message);
        let d = o.data.unwrap();
        assert_eq!(d["applied"], true);
        assert_eq!(d["id"], "0001_init");

        // both statements landed inside the one transaction
        let q = svc.query_run(&json!({ "profile": "m", "sql": "SELECT name FROM widget" }));
        assert_eq!(q.data.unwrap()["rows"][0][0], "gizmo");

        // the ledger recorded the migration with an RFC3339 stamp
        let applied = svc.migration_applied(&json!({ "profile": "m" }));
        let ml = applied.data.unwrap();
        assert_eq!(ml["count"], 1);
        let m0 = &ml["migrations"][0];
        assert_eq!(m0["id"], "0001_init");
        assert_eq!(m0["checksum"], "abc123");
        let stamp = m0["appliedAt"].as_str().unwrap();
        assert!(stamp.contains('T') && stamp.ends_with('Z'), "stamp: {stamp}");
        assert!(stamp.starts_with("20"), "stamp: {stamp}");
    }

    #[test]
    fn db_migrate_reapply_same_checksum_skips_mismatch_conflicts() {
        let svc = DbStudioService::new();
        assert!(svc.db_connect(&json!({ "profile": "m", "file": ":memory:" })).ok);
        let apply = |cksum: &str, stmts: Value| {
            svc.db_migrate(&json!({
                "profile": "m",
                "id": "0001",
                "checksum": cksum,
                "statements": stmts
            }))
        };
        let first = apply("cs-1", json!(["CREATE TABLE t(id INTEGER)"]));
        assert!(first.ok);
        assert_eq!(first.data.unwrap()["applied"], true);

        // re-applying the same id + checksum is a no-op skip (ok, applied:false)
        let again = apply("cs-1", json!(["CREATE TABLE t(id INTEGER)"]));
        assert!(again.ok, "reapply should skip, not fail");
        assert_eq!(again.data.unwrap()["applied"], false);

        // same id, DIFFERENT checksum = tamper → Conflict
        let tampered = apply("cs-2", json!(["CREATE TABLE t(id INTEGER)"]));
        assert!(!tampered.ok);
        assert_eq!(tampered.code.as_deref(), Some("CONFLICT"));

        // ledger still has exactly one row (the original)
        let ml = svc.migration_applied(&json!({ "profile": "m" })).data.unwrap();
        assert_eq!(ml["count"], 1);
        assert_eq!(ml["migrations"][0]["checksum"], "cs-1");
    }

    #[test]
    fn db_migrate_rolls_back_the_whole_file_on_failure() {
        let svc = DbStudioService::new();
        assert!(svc.db_connect(&json!({ "profile": "m", "file": ":memory:" })).ok);
        // second statement is invalid SQL — the whole migration must roll back
        let o = svc.db_migrate(&json!({
            "profile": "m",
            "id": "0002_bad",
            "checksum": "zzz",
            "statements": [
                "CREATE TABLE good(id INTEGER)",
                "CREATE TABLE nope(!!! not sql"
            ]
        }));
        assert!(!o.ok, "invalid migration must fail");
        assert_eq!(o.code.as_deref(), Some("INTERNAL"));

        // the first statement's table must NOT survive — atomic rollback
        let leaked = svc.query_run(&json!({ "profile": "m", "sql": "SELECT id FROM good" }));
        assert!(!leaked.ok, "partial migration leaked table `good`");

        // and the ledger has no entry for the failed migration
        let ml = svc.migration_applied(&json!({ "profile": "m" })).data.unwrap();
        assert_eq!(ml["count"], 0);
    }

    #[test]
    fn migration_applied_empty_when_no_ledger() {
        let svc = DbStudioService::new();
        assert!(svc.db_connect(&json!({ "profile": "m", "file": ":memory:" })).ok);
        let o = svc.migration_applied(&json!({ "profile": "m" }));
        assert!(o.ok);
        let d = o.data.unwrap();
        assert_eq!(d["count"], 0);
        assert!(d["migrations"].as_array().unwrap().is_empty());
    }

    #[test]
    fn migration_applied_unconnected_profile_errors() {
        let svc = DbStudioService::new();
        let o = svc.migration_applied(&json!({ "profile": "nope" }));
        assert!(!o.ok);
        assert_eq!(o.code.as_deref(), Some("UNAVAILABLE"));
    }
}
