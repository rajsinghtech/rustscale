# Phase 13: PeerAPI Server (DoH DNS + WhoIs)

Port Go `ipn/ipnlocal/peerapi.go`.

## Goal

Each node runs an HTTP server on a deterministic port per Tailscale IP, serving RFC 8484 DNS-over-HTTPS (`/dns-query`) for exit node DNS resolution, plus WhoIs identity. Critical for exit node DNS.

## CRITICAL: Stay strictly within scope

ONLY create the PeerAPI HTTP server module in `crates/tsnet/src/peerapi.rs`. Do NOT modify: magicsock, netstack, portmapper, derp, controlclient, netmon, tun, filter, dns (except wiring trait to the resolver), etc.

## What to build

### `crates/tsnet/src/peerapi.rs` (new)

```rust
/// Start the peer API listener on a Tailscale IP
pub async fn start_peer_api(
    tsnet: &Server,
    tailscale_ip: IpAddr,
    config: PeerApiConfig,
) -> Result<()>;

pub struct PeerApiConfig {
    pub resolver: Arc<dyn DnsQueryHandler>,
    pub whois: Arc<dyn WhoisHandler>,
}

#[async_trait]
pub trait DnsQueryHandler {
    async fn handle_peer_dns_query(
        &self,
        query: &[u8],
        remote_addr: SocketAddr,
        allow_func: Box<dyn Fn(&str) -> bool + Send>,
    ) -> Result<Vec<u8>>;
}
```

### DoH handler (`/dns-query`)

- Accept GET `?dns=<base64url>` (RFC 8484) and POST `application/dns-message`
- Auth: allow if same tailnet user, or if the requesting node is an exit node peer and the filter would accept TCP to 0.0.0.0:53
- Call `handle_peer_dns_query` on the DNS resolver with 5-second timeout
- Return `application/dns-message` or `application/json` for debug `?q=`

### Port determination

Deterministic port: `(32 << 10) | crc32(CRC32_IEEE, lower_3_bytes_of_IP)` with retries, falling back to ephemeral.

### `/` handler

Returns a greeting identifying the local node to the peer (JSON with Node + UserProfile).

### Debug handlers (`/v0/...`)

Stub all: `/v0/goroutines`, `/v0/metrics`, `/v0/magicsock`, `/v0/dnsfwd`, `/v0/interfaces`. Return 501 Not Implemented.

### WhoIs on incoming connections

The existing `Server::whois(remote_ip)` method resolves an IP to `(Node, UserProfile)`. Use this to auth each connection.

### Wire into `crates/tsnet/src/lib.rs`

In `Server::up()`, after the bootstrap, call `start_peer_api()` for each Tailscale IP.

## Go references

- `/Users/rajsingh/Documents/GitHub/tailscale/ipn/ipnlocal/peerapi.go` — full PeerAPI implementation
- `/Users/rajsingh/Documents/GitHub/rustscale/crates/tsnet/src/lib.rs` — existing WhoIs

## Acceptance criteria

- `cargo build --workspace` passes
- `cargo test --workspace` passes
- `cargo clippy` passes
- Peer API listener starts on each Tailscale IP on deterministic port
- DoH handler resolves DNS queries from exit node peers
- WhoIs identity returned on `/`
- Auth correctly restricts exit node DNS to authorized peers
- Run build/test/clippy at the end and fix all errors

## Implementation order

1. Read Go peerapi.go
2. Create crates/tsnet/src/peerapi.rs
3. Implement PeerApiConfig, handlers, port determination
4. Wire into Server::up
5. Run cargo build && cargo test && cargo clippy
