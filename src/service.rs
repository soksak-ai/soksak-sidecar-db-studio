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

const VERSION: &str = env!("CARGO_PKG_VERSION");

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
        // Phase 1: SQLite only. `file` is the database path (":memory:" default).
        let file = params.get("file").and_then(Value::as_str).unwrap_or(":memory:");
        match rusqlite::Connection::open(file) {
            Ok(conn) => {
                let version = sqlite_version(&conn);
                self.lock().insert(profile.clone(), conn);
                self.audit_append(&profile, "db-connect", true, 0);
                Outcome::ok_msg(
                    json!({ "profile": profile, "dialect": "sqlite", "version": version }),
                    format!("connected: {profile}"),
                )
            }
            Err(e) => {
                self.audit_append(&profile, "db-connect", false, 0);
                Outcome::err(ErrCode::Unavailable, format!("open failed: {e}"))
            }
        }
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

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, rusqlite::Connection>> {
        self.conns.lock().unwrap_or_else(|p| p.into_inner())
    }
}

fn sqlite_version(conn: &rusqlite::Connection) -> String {
    conn.query_row("SELECT sqlite_version()", [], |r| r.get::<_, String>(0))
        .unwrap_or_else(|_| "unknown".to_string())
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

/// ping — liveness + driver identity. Pure (no connection needed).
fn op_ping() -> Outcome {
    Outcome::ok_msg(
        json!({
            "plugin": "soksak-sidecar-db-studio",
            "version": VERSION,
            "driver": "sqlite",
            "sqlite_version": rusqlite::version(),
        }),
        "db-studio sidecar alive",
    )
}

/// db-test — one-shot connection probe: open, read the server version, close. No
/// pool entry (distinct from db-connect). Read-only, runs concurrently.
fn op_db_test(params: &Value) -> Outcome {
    let file = params.get("file").and_then(Value::as_str).unwrap_or(":memory:");
    match rusqlite::Connection::open(file) {
        Ok(conn) => Outcome::ok_msg(
            json!({ "dialect": "sqlite", "version": sqlite_version(&conn), "file": file }),
            "connection ok",
        ),
        Err(e) => Outcome::err(ErrCode::Unavailable, format!("open failed: {e}")),
    }
}

impl ServiceHandler for DbStudioService {
    fn ops(&self) -> Vec<String> {
        [
            "ping",
            "db-test",
            "db-connect",
            "db-disconnect",
            "db-status",
            "query-run",
            "db-introspect",
            "db-audit",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    fn read_only(&self, op: &str) -> bool {
        matches!(
            op,
            "ping" | "db-test" | "db-status" | "query-run" | "db-introspect" | "db-audit"
        )
    }

    fn handle(&self, op: &str, params: Value, _ctx: &OpCtx, _emit: &Emit) -> Outcome {
        match op {
            "ping" => op_ping(),
            "db-test" => op_db_test(&params),
            "db-connect" => self.db_connect(&params),
            "db-disconnect" => self.db_disconnect(&params),
            "db-status" => self.db_status(),
            "query-run" => self.query_run(&params),
            "db-introspect" => self.db_introspect(&params),
            "db-audit" => self.db_audit(&params),
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
    fn ping_reports_driver_and_versions() {
        let o = op_ping();
        assert!(o.ok);
        let d = o.data.unwrap();
        assert_eq!(d["plugin"], "soksak-sidecar-db-studio");
        assert_eq!(d["driver"], "sqlite");
        assert!(d["sqlite_version"].as_str().unwrap().starts_with("3."));
    }

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
        assert!(ops.contains(&"ping".to_string()));
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
}
