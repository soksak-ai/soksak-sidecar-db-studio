# soksak-sidecar-db-studio

The DB Studio plugin's service sidecar. A core-routed plugin service (spawned by
the ServiceManager, driven headless over the `soksak-spec-service` NDJSON wire)
that owns the database drivers, the live connections, and — as the plan lands —
introspection, query execution, and migration runs.

Phase 1 ships the SQLite driver and the connection lifecycle; MySQL and
PostgreSQL follow. Credentials never cross the wire: for SQLite the database file
path is not a secret; for the networked dialects the DSN arrives via the core's
`vault_env` spawn injection and is resolved only inside this process.

## Ops (Phase 1)

- `ping` — liveness + driver identity (SQLite version).
- `db-test {file?}` — one-shot connection probe (open, read version, close).
- `db-connect {profile, file?}` — open a connection and hold it under the profile id.
- `db-disconnect {profile}` — drop the held connection.
- `db-status` — list the open profiles.

## Build

```
cargo build
cargo test
```

The framing (hello, req/res, idempotency replay, the mutation mutex, mediated
calls) is not reimplemented here — it comes from the shared `serve` harness in
`soksak-spec-service`; this crate implements only the DB op handlers (PS17).
