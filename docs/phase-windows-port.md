# Phase: Windows port (scheduled LAST — after cert/QR, taildrop, ssh/web)

Goal: make `cargo check --workspace --target x86_64-pc-windows-msvc` pass and
flip the two Windows CI legs from continue-on-error to blocking. Full Windows
*runtime* support (named pipes, wintun) is a follow-on; this phase is
compile-level portability plus the safesocket named-pipe transport.

## Known gaps (from docs/parity.md "Windows port" section, captured 2026-07-12)

Hard errors:
- `crates/tun/src/lib.rs:123-124` — AF_INET/AF_INET6 from libc (unix-only). The
  TUN crate is meaningless on Windows until wintun; cfg-gate the whole crate
  surface behind unix and provide a stub error type on windows.
- `crates/tcpinfo/src/lib.rs:14,19` — `as_raw_fd` unix-only. Gate with
  `#[cfg(unix)]`, expose a no-op/Unsupported on windows.

Dead-code warnings (become errors under -D warnings): netmon/state.rs:637,
netns/lib.rs:107,112, portmapper/gateway.rs:104,128 — re-audit; some may be
fixed by prior cfg sweeps.

Beyond those, expect a tail: crates/safesocket (unix sockets), rustscaled
(launchd, unix signals), cli socket path defaults, peerapi/netstack fd usage.
Enumerate with the cross-check and fix crate by crate.

## Work items

1. Sweep: `cargo check --workspace --target x86_64-pc-windows-msvc` on a
   windows runner (or locally with the target installed — msvc target checks
   type-check fine from macOS for non-linking `cargo check`); fix all errors
   with cfg-gating following the repo's established pattern. Stub types must
   return typed "unsupported on this platform" errors, not panic.
2. safesocket: implement the Windows named-pipe transport
   (`\\.\pipe\ProtectedPrefix\Administrators\Rustscale\rustscaled` path style,
   go ref safesocket/pipe_windows.go uses winio; Rust: `windows`/`winapi` or
   `tokio::net::windows::named_pipe`). LocalAPI serve + localclient connect
   over it. CLI default socket path per-OS (paths.rs equivalent of Go
   paths/paths.go).
3. rustscaled: windows service install is OUT of scope; `run` should work in a
   console with ctrl-c shutdown (tokio::signal::ctrl_c on windows).
4. CI: flip `continue-on-error` off for Check (windows) and the msvc
   cross-check; add `cargo test -p` for the crates that are actually
   windows-meaningful (ipn, localclient unit tests, tailcfg, key, disco) on the
   windows runner.
5. docs/parity.md: replace the "Windows port" gap table with status.

## Acceptance criteria

- Windows CI legs green with continue-on-error REMOVED.
- Standard four checks + musl clippy still clean (no unix regressions).
- `rustscale status` compiles for windows; named-pipe transport has a unit test
  (loopback pipe echo) that runs on the windows runner.
