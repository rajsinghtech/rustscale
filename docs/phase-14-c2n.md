# Phase 14: C2N (Coordinator-to-Node) API

Port Go `cmd/coordinator/toNode` — the HTTP API that the control plane uses to query and command a running tailscaled node.

## Goal

Expose an HTTP server on the tailnet (listening on a per-node deterministic port) that the control plane (or debug tools like `tailscale debug`) can use to read node state — netmap, prefs, metrics, goroutine stacks, logs, DNS config — and issue commands like ping, portmap reset, and restart. The Go implementation serves this on a random port behind a tag-based ACL rule.

## CRITICAL: Stay strictly within scope

ONLY create `crates/c2n/` with the HTTP server, handler stubs, and auth middleware. Import and use types from existing crates (tailcfg, key, tsnet) — do NOT modify them. Do NOT modify: magicsock, netstack, portmapper, derp, controlclient, netmon, tun, filter, dns, wg. Only integration point: wire the C2N server into `tsnet::Server` startup.

## What to build

### `crates/c2n/` — new crate

```rust
pub struct C2NServer {
    lb: Arc<LocalBackend>,
    log_id: String,
}

impl C2NServer {
    pub fn new(lb: Arc<LocalBackend>, log_id: String) -> Self;
    pub async fn serve(self, listener: TcpListener) -> Result<()>;
}
```

### Auth middleware

- Reuse the existing `WhoIs` infrastructure from `tsnet::Server` to authenticate incoming connections
- Only allow connections from the control plane (identified by tailnet IP range or tag)
- Return 401 Unauthorized with structured JSON for failed auth

### Handler stubs (all return 501 Not Implemented for now — matching Go's `serveC2N`)

- `GET /` — list available endpoints
- `GET /debug/goroutines` — gzipped stack trace dump
- `GET /debug/pprof/` — pprof endpoints
- `GET /debug/pprof/profile` — CPU profile
- `GET /debug/pprof/heap` — heap profile
- `GET /metrics` — Prometheus metrics
- `GET /netmap` — current netmap (JSON)
- `GET /prefs` — current prefs (JSON)
- `GET /dns` — current DNS config (JSON)
- `GET /logtail/logs` — recent log lines
- `POST /local/{command}` — issue commands (ping, portmap-reset, restart)

### Port determination

Random high port on loopback, stored in `tsnet::Server`. The C2N listener address is exposed so the node can advertise it to the control plane via the next netmap update.

### Wire into tsnet

In `tsnet::Server::up()`, after the node is running:
1. Bind a TCP listener on localhost:0
2. Start the C2N HTTP server in a background task
3. Store the bound address so it can be included in HostInfo or node-update messages

## Go references

- `/Users/rajsingh/Documents/GitHub/tailscale/cmd/coordinator/toNode/toNode.go` — C2N server implementation
- `/Users/rajsingh/Documents/GitHub/tailscale/ipn/ipnlocal/local.go` — LocalBackend which C2N wraps
- `/Users/rajsingh/Documents/GitHub/tailscale/tsnet/tsnet.go` — how tsnet wires it in (search for `c2n`)

## Acceptance criteria

- `cargo build --workspace` passes
- `cargo test --workspace` passes
- `cargo clippy` passes
- C2N server starts on localhost on node startup
- All handler endpoints return 501 Not Implemented with structured JSON
- Auth middleware checks WhoIs identity
- Run build/test/clippy at the end and fix all errors

## Implementation order

1. Read Go C2N implementation
2. Create crates/c2n/Cargo.toml
3. Create crates/c2n/src/lib.rs with auth, router, handler stubs
4. Wire into tsnet::Server startup
5. Run cargo build && cargo test && cargo clippy
