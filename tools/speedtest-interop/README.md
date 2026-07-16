# Speedtest v2 Go↔Rust interop

This hermetic process harness compares `crates/speedtest` with the exported
`Serve` and `RunClient` APIs in `tailscale.com/net/speedtest` at the repository's
pinned Tailscale module version, `v1.100.0`.

Run it from the repository root:

```sh
tools/speedtest-interop.sh
```

The build may populate the normal Go module cache. The resulting peer runs with
an empty environment, binds or dials only random IPv4 loopback ports, reads no
credentials, and receives no secret files. Child output is capped at 16 KiB.
Every startup, session, process exit, and complete test run has a hard deadline;
children are killed and reaped on errors or cancellation.

The gate runs four five-second data sessions:

- Rust client → upstream Go server, upload and download;
- upstream Go client → bounded Rust server, upload and download.

It checks newline-delimited v2 JSON control, direction reversal, complete 2 MiB
blocks, interval and total result semantics, and deterministic fragmented I/O.
It also sends malformed and truncated control to the upstream Go server and
cancels an active upstream Go client by draining the bounded Rust server.

`main.go` is only a bounded process adapter. It imports and calls the published
upstream package directly and verifies its linked module version through Go
build information. No protocol implementation is copied into the fixture, so
these tests are live loopback process interop with the pinned module—not network
interop with a deployed Tailscale node. The Rust integration test skips quickly
under ordinary `cargo test` unless `RUSTSCALE_SPEEDTEST_GO_PEER` names the built
adapter; the script is the reproducible evidence gate.
