# Phase: Wire LocalAPI to the rustscaled safesocket

Goal: replace the accept-and-drop TODO stub in the daemon with the real LocalAPI
handler, so a future CLI can talk to `rustscaled` over `/var/run/rustscaled.sock`.
This is the smallest phase in the CLI-parity track and a prerequisite for all of it.

## Current state (verified 2026-07-11)

- Daemon stub: `crates/rustscaled/src/daemon.rs:66-113` (`start_safesocket_listener`)
  accepts on `/var/run/rustscaled.sock` (fallback `<state_dir>/rustscaled.sock`) and
  drops the stream — `// TODO: LocalAPI (a later phase)` at `daemon.rs:104`.
- LocalAPI: `crates/tsnet/src/localapi.rs` — a complete hand-rolled HTTP/1.1-over-unix
  server with GET status/whois/prefs/netmap/metrics/health and POST ping (501).
  It is only spawned when the tsnet builder sets `.localapi(...)` (`lib.rs:848-878`,
  `1133-1163`); the daemon never sets it.
- `crates/safesocket` is real (listen/connect/retries/perms/darwin sameuserproof).

## Work items

1. Refactor `localapi.rs` so its accept-loop/dispatch can be driven by an
   externally-created `tokio::net::UnixListener` — expose something like
   `localapi::serve_on(listener, state)` in addition to the current
   spawn-from-path entrypoint. Keep the existing tsnet builder path working
   (it should now call the same `serve_on` internally).
2. In `crates/rustscaled/src/daemon.rs`, delete the accept-and-drop loop and hand the
   safesocket listener to `serve_on`, with the LocalAPI state built from the running
   `Server` (same wiring as `lib.rs:848-878` does for the builder path).
3. Socket permissions: keep the safesocket crate's semantics (0666 on peer-cred
   platforms, else 0600) rather than localapi.rs's own 0600 chmod — the listener is
   created by safesocket, LocalAPI must not re-chmod it.
4. `run --localapi-path <path>` flag on the daemon for tests (defaults stay:
   /var/run/rustscaled.sock → <state_dir>/rustscaled.sock fallback).
5. Integration test: start the daemon backend against `crates/testcontrol`'s in-process
   fake control server, connect with `safesocket::connect`, issue
   `GET /localapi/v0/status`, assert 200 + parseable JSON. Same for /health.

## Non-goals

New endpoints, IPN state machine, prefs writes, auth changes — all later phases.
This phase only connects two things that already exist.

## Acceptance criteria

- `cargo build --workspace && cargo test --workspace && cargo clippy --workspace
  --all-targets -- -D warnings && cargo fmt --all --check`
- The new integration test passes.
- `docs/parity.md` Tier-1 LocalAPI row updated to reflect daemon wiring.
