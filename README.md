# soksak-sidecar-db-studio

The DB Studio plugin's service sidecar. A core-routed plugin service (spawned by
the ServiceManager, driven headless over the `soksak-spec-service` NDJSON wire)
that owns the database drivers, the live connections, and — as the plan lands —
introspection, query execution, and migration runs.

The SQLite driver is in (via SQLCipher, so encrypted databases work); MySQL and
PostgreSQL follow. Credentials never cross the wire: for a plaintext SQLite file
the path is not a secret; the SQLCipher key and, later, the networked-dialect
DSNs arrive via the core's `vault_env` spawn injection and are resolved only
inside this process.

## Ops

Connection lifecycle:
- `ping` — liveness + driver identity (SQLite version).
- `db-test {file?, key?}` — one-shot connection probe (open, apply key, read version, close).
- `db-connect {profile, file?, key?}` — open a connection and hold it under the profile id. An encrypted (SQLCipher) database needs its `key`; a wrong/absent key fails at connect.
- `db-disconnect {profile}` — drop the held connection.
- `db-status` — list the open profiles.

Read path:
- `query-run {profile, sql, params?, rowLimit?}` — single SELECT; row cap with a `truncated` flag; sensitive columns are masked before results leave the sidecar.
- `db-introspect {profile, tables?}` — schema-only catalog (tables/columns/foreign keys/indexes); no row data.
- `db-audit {profile?, limit?}` — the sidecar's append-only audit (op/profile/ok/row-count, never SQL literals).

At-rest encryption (SQLite / SQLCipher):
- `db-create {file, key?}` — create a database; with a `key` it is encrypted.
- `db-rekey {profile, newKey}` — rotate the encryption key in place (whole-database re-encrypt).

## Build

```
cargo build
cargo test
```

The framing (hello, req/res, idempotency replay, the mutation mutex, mediated
calls) is not reimplemented here — it comes from the shared `serve` harness in
`soksak-spec-service`; this crate implements only the DB op handlers (PS17).
