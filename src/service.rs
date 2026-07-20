//! DB Studio service handler. Phase 1 = SQLite driver + connection lifecycle.
//!
//! Ownership (plan §1): this sidecar owns the drivers, the live connections, and
//! (later) introspection/query/migration execution. The core owns spawn,
//! lifecycle, secret injection, and gating; the plugin owns the profile metadata
//! and orchestration. Credentials never cross the wire — for SQLite the "file"
//! path is not a secret; for MySQL/PostgreSQL (later) the DSN arrives via the
//! core's vault_env spawn injection, resolved only inside this process.

use std::collections::HashMap;
use std::sync::Mutex;

use serde_json::{json, Value};
use soksak_spec_service::{serve_stdio, Emit, ErrCode, OpCtx, Outcome, ServiceHandler};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The DB Studio service. Owns live connections keyed by profile id.
pub struct DbStudioService {
    conns: Mutex<HashMap<String, rusqlite::Connection>>,
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
        }
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
                Outcome::ok_msg(
                    json!({ "profile": profile, "dialect": "sqlite", "version": version }),
                    format!("connected: {profile}"),
                )
            }
            Err(e) => Outcome::err(ErrCode::Unavailable, format!("open failed: {e}")),
        }
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
        ["ping", "db-test", "db-connect", "db-disconnect", "db-status"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    fn read_only(&self, op: &str) -> bool {
        matches!(op, "ping" | "db-test" | "db-status")
    }

    fn handle(&self, op: &str, params: Value, _ctx: &OpCtx, _emit: &Emit) -> Outcome {
        match op {
            "ping" => op_ping(),
            "db-test" => op_db_test(&params),
            "db-connect" => self.db_connect(&params),
            "db-disconnect" => self.db_disconnect(&params),
            "db-status" => self.db_status(),
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
}
