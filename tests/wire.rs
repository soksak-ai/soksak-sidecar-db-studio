//! End-to-end wire test: spawn the real binary, speak the soksak-spec-service
//! NDJSON wire over stdio, and drive the read path against a real SQLite file.
//! This proves the deployed artifact works over the actual protocol against a
//! real database — no core, no publishing, no external server.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{json, Value};
use soksak_spec_service::{ReqCtx, ServiceIn, ServiceOut};

fn send(stdin: &mut ChildStdin, frame: &ServiceIn) {
    let line = serde_json::to_string(frame).unwrap();
    writeln!(stdin, "{line}").unwrap();
    stdin.flush().unwrap();
}

fn recv(stdout: &mut BufReader<ChildStdout>) -> ServiceOut {
    let mut line = String::new();
    let n = stdout.read_line(&mut line).unwrap();
    assert!(n > 0, "sidecar closed stdout unexpectedly");
    serde_json::from_str(line.trim()).unwrap_or_else(|e| panic!("bad frame {line:?}: {e}"))
}

fn req(id: u64, op: &str, params: Value) -> ServiceIn {
    ServiceIn::Req {
        id,
        op: op.into(),
        params,
        key: format!("k{id}"),
        ctx: ReqCtx {
            origin: "socket".into(),
            parent: None,
            deadline_ms: 5000,
        },
    }
}

/// Run one req and return (ok, data), skipping any streamed ev/act frames.
fn call_res(
    stdin: &mut ChildStdin,
    stdout: &mut BufReader<ChildStdout>,
    id: u64,
    op: &str,
    params: Value,
) -> (bool, Value) {
    send(stdin, &req(id, op, params));
    loop {
        match recv(stdout) {
            ServiceOut::Res {
                id: rid, ok, data, ..
            } => {
                assert_eq!(rid, id);
                return (ok, data.unwrap_or(Value::Null));
            }
            ServiceOut::Ev { .. } | ServiceOut::Act { .. } => continue,
            other => panic!("unexpected frame for {op}: {other:?}"),
        }
    }
}

/// Run one req that must succeed and return its data.
fn call(
    stdin: &mut ChildStdin,
    stdout: &mut BufReader<ChildStdout>,
    id: u64,
    op: &str,
    params: Value,
) -> Value {
    let (ok, data) = call_res(stdin, stdout, id, op, params);
    assert!(ok, "op {op} failed: {data:?}");
    data
}

/// Spawn the serve binary and complete the hello/ready handshake.
fn spawn_and_ready() -> (Child, ChildStdin, BufReader<ChildStdout>) {
    let mut child: Child = Command::new(env!("CARGO_BIN_EXE_soksak-sidecar-db-studio"))
        .arg("serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    match recv(&mut stdout) {
        ServiceOut::Hello(_) => {}
        other => panic!("first frame must be hello: {other:?}"),
    }
    send(&mut stdin, &ServiceIn::Ready);
    (child, stdin, stdout)
}

#[test]
fn wire_read_path_against_real_sqlite() {
    // 1. A real SQLite database with a schema worth introspecting + a sensitive column.
    let dir = std::env::temp_dir().join(format!("db-studio-wire-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let dbpath = dir.join("shop.sqlite").to_string_lossy().to_string();
    {
        let conn = rusqlite::Connection::open(&dbpath).unwrap();
        conn.execute_batch(
            "CREATE TABLE users(id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, password TEXT);
             CREATE TABLE orders(id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id), total REAL);
             CREATE INDEX idx_orders_user ON orders(user_id);
             INSERT INTO users(email, password) VALUES ('a@x.com', 'secret123');",
        )
        .unwrap();
    }

    // 2. Spawn the actual binary in serve mode.
    let mut child: Child = Command::new(env!("CARGO_BIN_EXE_soksak-sidecar-db-studio"))
        .arg("serve")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    // 3. hello (harness-emitted, PS5), then ready.
    match recv(&mut stdout) {
        ServiceOut::Hello(h) => {
            assert!(h.ops.contains(&"query-run".to_string()));
            assert!(h.ops.contains(&"db-introspect".to_string()));
        }
        other => panic!("first frame must be hello: {other:?}"),
    }
    send(&mut stdin, &ServiceIn::Ready);

    // 4. connect → introspect → query(masked) → audit against the real file.
    let d = call(
        &mut stdin,
        &mut stdout,
        1,
        "db-connect",
        json!({ "profile": "shop", "file": dbpath }),
    );
    assert_eq!(d["dialect"], "sqlite");

    let d = call(&mut stdin, &mut stdout, 2, "db-introspect", json!({ "profile": "shop" }));
    let tables = d["tables"].as_array().unwrap();
    let users = tables
        .iter()
        .find(|t| t["name"] == "users")
        .expect("users table introspected");
    assert!(users["columns"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["name"] == "password"));
    let orders = tables
        .iter()
        .find(|t| t["name"] == "orders")
        .expect("orders table introspected");
    assert!(
        !orders["foreignKeys"].as_array().unwrap().is_empty(),
        "orders FK introspected"
    );
    assert!(
        tables
            .iter()
            .any(|t| !t["indexes"].as_array().unwrap().is_empty()),
        "index introspected"
    );

    let d = call(
        &mut stdin,
        &mut stdout,
        3,
        "query-run",
        json!({ "profile": "shop", "sql": "SELECT email, password FROM users" }),
    );
    let rows = d["rows"].as_array().unwrap();
    assert_eq!(rows[0][0], "a@x.com");
    assert_eq!(
        rows[0][1], "<redacted:password>",
        "sensitive column masked over the wire before it leaves the sidecar"
    );

    let d = call(&mut stdin, &mut stdout, 4, "db-audit", json!({}));
    let entries = d["entries"].as_array().unwrap();
    assert!(entries.iter().any(|e| e["op"] == "query-run"));
    let audit_json = serde_json::to_string(&d).unwrap();
    assert!(
        !audit_json.contains("SELECT"),
        "audit stores no SQL literals"
    );

    // 5. drain + exit.
    send(&mut stdin, &ServiceIn::Shutdown);
    let status = child.wait().unwrap();
    assert!(status.success() || status.code().is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn wire_encryption_lifecycle_against_real_sqlite() {
    // Full at-rest encryption lifecycle over the wire on a real encrypted
    // SQLite (SQLCipher) file: create -> reject-without-key -> open-with-key ->
    // rekey -> old-key-fails/new-key-works. No server, no publishing.
    let dir = std::env::temp_dir().join(format!("db-studio-wire-enc-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("vault.sqlite").to_string_lossy().to_string();
    let (old_key, new_key) = ("old-secret", "new-secret");

    let (mut child, mut stdin, mut stdout) = spawn_and_ready();

    // create an encrypted database
    let d = call(
        &mut stdin,
        &mut stdout,
        1,
        "db-create",
        json!({ "file": path, "key": old_key }),
    );
    assert_eq!(d["encrypted"], true);

    // connecting without the key is refused over the wire
    let (ok, _) = call_res(
        &mut stdin,
        &mut stdout,
        2,
        "db-connect",
        json!({ "profile": "v", "file": path }),
    );
    assert!(!ok, "encrypted db must not open without a key");

    // connecting with the key works
    let d = call(
        &mut stdin,
        &mut stdout,
        3,
        "db-connect",
        json!({ "profile": "v", "file": path, "key": old_key }),
    );
    assert_eq!(d["encrypted"], true);

    // rotate the key in place, then drop the connection
    let d = call(
        &mut stdin,
        &mut stdout,
        4,
        "db-rekey",
        json!({ "profile": "v", "newKey": new_key }),
    );
    assert_eq!(d["rekeyed"], true);
    call(&mut stdin, &mut stdout, 5, "db-disconnect", json!({ "profile": "v" }));

    // the old key no longer opens it; the new key does
    let (ok_old, _) = call_res(
        &mut stdin,
        &mut stdout,
        6,
        "db-connect",
        json!({ "profile": "v2", "file": path, "key": old_key }),
    );
    assert!(!ok_old, "old key must fail after rekey");
    let (ok_new, _) = call_res(
        &mut stdin,
        &mut stdout,
        7,
        "db-connect",
        json!({ "profile": "v3", "file": path, "key": new_key }),
    );
    assert!(ok_new, "new key must work after rekey");

    send(&mut stdin, &ServiceIn::Shutdown);
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
}
