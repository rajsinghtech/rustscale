# Phase 11: DNS Fallback + DNS Cache

Port Go `net/dnsfallback` and `net/dnscache` to Rust.

## Goal

The control client needs a DNS resolution mechanism that works even when system DNS is broken (common in Docker/k8s/embedded). The Go client embeds a static DERP server IP list and uses DoH to those DERP servers as a fallback resolver. The Rust client must replicate this.

## CRITICAL: Stay strictly within scope

ONLY create `crates/dnsfallback/` and `crates/dnscache/` (or a combined crate). Make MINIMAL integration changes to `controlclient` to wire the fallback into the control channel dial path. DO NOT modify: magicsock, netstack, portmapper, derp, tsnet (except Cargo.toml deps), tun, filter, netmon, or any other crate.

## What to build

### 1. `crates/dnsfallback/` (or embed in a combined `crates/dnscache/`)

A new crate with the static DERP server IPs and the bootstrap DNS logic.

- Embed `dns-fallback-servers.json` from `/Users/rajsingh/Documents/GitHub/tailscale/net/dnsfallback/dns-fallback-servers.json` using `include_str!` or `include_bytes!`
- Expose:
```rust
pub struct DnsFallbackResolver;
impl DnsFallbackResolver {
    /// Resolve `host` by trying up to 6 randomly-selected DERP
    /// servers via HTTPS /bootstrap-dns?q=<host>.
    pub fn resolve(ctx: Context, host: &str) -> Result<Vec<IpAddr>>;
}
pub fn get_static_derp_map() -> DerpMap;
```
- The resolver takes the embedded DERP map, shuffles nodes, picks up to 6 alternating v4/v6, and for each sends an HTTPS GET to `https://{hostname}/bootstrap-dns?q={query}` via TLS to the node's IP. Returns the first successful DNS response.

### 2. `crates/dnscache/`

A caching DNS resolver:
```rust
pub struct DnsCache {
    forward: ...,
    fallback: Option<fn(ctx, host) -> Result<Vec<IpAddr>>>,
    ip_cache: Mutex<HashMap<String, IpCacheEntry>>,
    ttl: Duration,
    use_last_good: bool,
}
impl DnsCache {
    pub fn lookup_ip(ctx, host: &str) -> Result<(IpAddr, Option<IpAddr>, Vec<IpAddr>)>;
}
```
- TTL-based expiry (default 10 min)
- `UseLastGood` fallback: if refresh fails, serve stale entry
- Singleflight dedup for concurrent lookups
- Don't cache private IPs (captive portal protection)
- Cloud resolver support (GCP metadata DNS)

### 3. Integration into `crates/controlclient`

The control client's `dial_control` and `fetch_server_pub_key` should use `DnsCache` with `DnsFallbackResolver` as `LookupIPFallback`, matching Go `control/controlclient/direct.go` lines 334-368.

Specifically:
- Create a `DnsCache` with `fallback = Some(DnsFallbackResolver::resolve)` during control client initialization
- Use `dnscache::Dialer` (happy-eyeballs across address families) instead of bare `TcpStream::connect` for control-plane connections
- On dial failure with trustworthy-DNS check, try fallback DNS via the DERP servers

### 4. Add to workspace dependencies

Both `rustscale-dnsfallback` and `rustscale-dnscache` need to be in root `Cargo.toml` workspace deps.

## Go references

- `/Users/rajsingh/Documents/GitHub/tailscale/net/dnsfallback/dnsfallback.go` — main fallback logic
- `/Users/rajsingh/Documents/GitHub/tailscale/net/dnsfallback/dns-fallback-servers.json` — embedded DERP map
- `/Users/rajsingh/Documents/GitHub/tailscale/net/dnscache/dnscache.go` — caching resolver + dialer wrapper
- `/Users/rajsingh/Documents/GitHub/tailscale/control/controlclient/direct.go` lines 334-368 — how control client wires them in

## Acceptance criteria

- `cargo build --workspace` passes
- `cargo test --workspace` passes
- `cargo clippy --workspace --all-targets` passes
- The control client uses the DNS fallback when system DNS fails
- The DNS cache has TTL-based expiry and UseLastGood fallback
- Static DERP map is embedded from the Go JSON file
- Run build/test/clippy at the end and fix all errors

## Implementation order

1. Read all Go reference files
2. Create crates/dnsfallback/Cargo.toml
3. Create crates/dnsfallback/src/lib.rs
4. Embed dns-fallback-servers.json
5. Create crates/dnscache/Cargo.toml
6. Create crates/dnscache/src/lib.rs
7. Wire into controlclient
8. Run cargo build && cargo test && cargo clippy
