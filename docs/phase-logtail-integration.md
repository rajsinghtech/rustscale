# Phase: logtail integration + logpolicy

Wire `crates/logtail` into the daemon so rustscale actually ships logs to the
log server, porting Go's `logpolicy` setup. Full pre-digested research:
**`docs/specs/research-logtail-integration.md`** — read it first; it has the
Go startup order, config file format, and the rustscale call-site inventory.

## Scope (run 1: infrastructure)

1. **New crate `crates/logpolicy`** (port `logpolicy/logpolicy.go`, client
   subset): `Config { collection, private_id, public_id }`, JSON config file
   `{cmdname}.log.conf` load/save in the state/logs dir (research documents
   Go's locations; for rustscale use the state dir), `new()` that
   loads-or-creates. Collection constant `tailnode.log.tailscale.io`.
2. **ID unification**: reuse the already-persisted `{state_dir}/logid-private`
   PrivateID (from `crates/logid`, landed 2026-07-13) as the logtail auth ID —
   Hostinfo `BackendLogID` and the logtail PrivateID must be the same ID, as
   in Go. logpolicy should load that file rather than minting a second ID
   (keep backward compat with the existing file).
3. **`crates/logtail` gaps** (research §LogTail gaps): `log::Log` adapter
   (mirror each record to stderr and the logtail buffer; level gating),
   `SetEnabled`/disabled kill switch honoring `TS_NO_LOGS_NO_SUPPORT` (via
   crates/envknob) and the NoLogsNoSupport pref, flush-now API exposed for
   c2n.
4. **Wiring**: rustscaled startup creates logpolicy + logtail before the
   backend (Go order), installs the `log` adapter as the global logger
   (`log::set_boxed_logger`), starts the upload task; tsnet `Server` gets an
   optional handle so c2n `POST /logtail/flush` (currently a 204 stub in
   `crates/tsnet/src/c2n.rs`) triggers a real flush. `FrontendLogID` stays
   empty (GUI-only in Go).
5. Upload must be **opt-in-by-default-off for tsnet embedding** but on for
   rustscaled (matching tailscaled behavior); a `ServerBuilder` toggle +
   rustscaled flag `--no-logs-no-support` to disable.

## Scope (run 2: mechanical, same worktree, after run 1 lands)

Convert `eprintln!` call sites in `crates/rustscaled` (~60) and
`crates/tsnet` (~209) to `log::{error,warn,info,debug}!` macros with
sensible levels (errors → error/warn, lifecycle notices → info, chatty
diagnostics → debug). Keep message text unchanged apart from removing any
leading "tsnet:"-style prefixes only when the logger already adds context —
otherwise keep them. Do not convert other crates in this phase.

## Acceptance criteria (each run, run yourself)

- `cargo build --workspace && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all`
  (sandbox socket-bind failures in c2n/tsnet/DERP suites are environmental —
  note them, everything else must pass).
- logpolicy: config load/create/roundtrip tests; reuses existing
  logid-private file (test with a pre-seeded file).
- logtail adapter: unit test that a log record lands in the buffer with level
  gating; disabled mode drops.
- Update `docs/parity.md`: `Log policy / logtail setup` row, Logtail row,
  Hostinfo row note for BackendLogID unification.
- Do NOT modify `crates/magicsock`. Do not commit; do not spawn agents.
