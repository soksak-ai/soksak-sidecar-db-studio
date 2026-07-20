//! DB Studio service sidecar.
//!
//! Spawned by the core ServiceManager with the `serve` subcommand; speaks the
//! soksak-spec-service NDJSON wire over stdio. The framing (hello, req/res,
//! idempotency, the mutation mutex) lives in the shared serve harness — this
//! binary only implements the DB op handlers (PS17).
//!
//!   soksak-sidecar-db-studio serve   # core-routed plugin service over stdio

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match argv.first().map(String::as_str) {
        Some("serve") | None => soksak_sidecar_db_studio::run_serve(),
        Some(other) => {
            eprintln!("soksak-sidecar-db-studio: unknown subcommand '{other}' (expected: serve)");
            std::process::exit(2);
        }
    }
}
