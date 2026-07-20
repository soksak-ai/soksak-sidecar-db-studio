# gate

`rules.json` (the language-neutral gate rule table) and `cases.json` (the
conformance cases) are copies. The canonical source is the plugin at
`soksak-plugin-db-studio/src/features/db/gate`. Both files are kept here as
committed build-time copies so the Rust sidecar and the TS UI classify gate
verdicts by the same rule table against the same fixtures.

The copies are currently synced by hand. A sync script that mirrors the plugin's
gate directory into this one is a follow-up; until then, edit the plugin source
and re-copy — do not diverge these files from the canonical ones.

- `rules.json` — ordered rule table; first matching rule wins (fail-closed
  catch-all last). Consumed by `src/gate.rs` via `include_str!`.
- `cases.json` — `[{name, input, expect:{grade, action}}]`; the sidecar test
  runs `classify_gate` over every case and asserts the TS-identical verdict.
