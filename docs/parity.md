# rustscale ↔ tailscale parity tracker

Tiered gap analysis vs the Go implementation (user-authored 2026-07-09).
Status legend: ✅ done · 🔶 partial · 🚧 in progress · ⬜ not started.
Active execution order is in CLAUDE.md; this file is the full inventory —
update statuses as phases land.

## Tier 1: Core compatibility (missing = incomplete client)

| Feature | Go source | Status |
| --- | --- | --- |
| MagicDNS + split DNS resolver | `net/dns/resolver/tsdns.go` | ✅ phase-20: split DNS via control `Routes` (most-specific suffix wins), Hosts/LocalDomains/SubdomainHosts, atomic SetConfig, PTR reverse (v4/v6), .onion NXDOMAIN, 4via6, TC bit + EDNS size, ANY qtype, TCP fallback + DoH upstream forwarder |
| Let's Encrypt certs via control | `ipn/ipnlocal/cert.go` | ✅ full ACME client (RFC 8555, ES256 JWS, dns-01 via set-dns, rcgen CSR); live LE-staging e2e green on ephemeral tailnet |
| WhoIs (peer identity from conn) | `tsnet.Server.WhoIs` | ✅ `Server::whois` + `ts_whois` FFI (UserProfiles from netmap) |
| Exit node support | LocalBackend/router/magicsock | ✅ port-5 done (advertise_exit_node builder opt adds 0.0.0.0/0+::/0 to RoutableIPs + filter localNets; Server::set_exit_node/clear_exit_node resolve exit-capable peer via IP/hostname + set RouteTable catch-all; TUN mode --exit-node installs /1 split routes on macOS, best-effort default on Linux; ts_set_exit_node/ts_clear_exit_node FFI; bypass routes for DERP/control in TUN+exit mode still ⬜ known limitation) |
| Network monitor (netmon) | `net/netmon/` | ✅ port-3 done (AF_ROUTE on macOS, polling fallback; State, ChangeDelta, major/minor change detection, wall-time jump; wired into magicsock link_changed + tsnet endpoint-update push) |
| Port mapping (NAT-PMP/PCP/UPnP) | `net/portmapper/` | ✅ port-4 done (`crates/portmapper`: Client facade with probe/create/renew/cache lifecycle; PMP/PCP byte-exact packet codec with RFC test vectors; UPnP SSDP M-SEARCH discovery + root-desc XML parse + AddPortMapping/DeletePortMapping/GetExternalIPAddress SOAP; fake IGD tests for all three protocols; magicsock publishes portmap endpoint best-effort alongside local/STUN endpoints; netcheck Report gains portmap capability booleans) |
| Health tracking | `health/` | ✅ port-7: crates/health Tracker + watchdog, wired control/DERP/certs/netmon, ServerStatus.health + FFI |

## Tier 2: Production features

| Feature | Go source | Status |
| --- | --- | --- |
| Serve/Funnel (ListenFunnel, ServeConfig, TCP fwd, reverse proxy) | `tsnet`, `ipn/serve*` | ✅ port-6 done (ServeConfig serde model: TCPPortHandler/WebServerConfig/HTTPHandler; Server::set_serve_config starts netstack listeners per port; TCP forward via copy_bidirectional; HTTP reverse proxy sets Host/X-Forwarded-For/Tailscale-User-Login/Name from WhoIs; static text handler; TLS-terminate with ControlCertProvider (self-signed fallback); listen_funnel validates port 443/8443/10000 + funnel node attr from netmap, returns typed FunnelError::NotEnabled on API-only tailnets; ts_serve_tcp FFI. Remaining: ingress peer Tailscale-Ingress-Target dispatch, Hostinfo.IngressEnabled advertisement) |
| Tailscale Services (ListenService, PROXY protocol) | `tsnet.Server.ListenService` | ⬜ |
| SOCKS5 proxy | `net/socks5/` | ✅ port-8: RFC 1928 CONNECT (v4/domain/v6), dials via shared tsnet resolve path, FFI; e2e green |
| LocalAPI | `ipn/localapi/` | ⬜ port-9 |
| Auto-update / ClientVersion | — | ⬜ |
| Multi-profile/login management | `ipn/ipnlocal/profiles.go` | ⬜ (single profile only) |

## macOS platform parity (phases 32–40, 2026-07-11)

| Feature | Go source | Status |
| --- | --- | --- |
| macOS DNS OS configurator | `net/dns/manager_darwin.go` | ✅ phase-32: `crates/dns` OsConfigurator trait + DarwinConfigurator (`/etc/resolver/$SUFFIX` split DNS, ownership header marker, search.tailscale file, stale cleanup, foreign files untouched); ✅ phase-39 wired into tsnet TUN mode via opt-in `configure_os_dns(true)` builder flag (build_os_dns_config from netmap DNS config, best-effort on permission errors, cleaned up on close) |
| Safe socket (CLI↔daemon IPC) | `safesocket/safesocket_darwin.go` | ✅ phase-33: `crates/safesocket` unix listen/connect (stale removal, perms) + darwin sameuserproof (macsys filename variant, macos lsof variant, set_credentials override, token gen) |
| Route table enumeration | `net/routetable/routetable_bsd.go` | ✅ phase-34: `crates/routetable` NET_RT_DUMP2 sysctl RIB fetch, rt_msghdr2 + 4-byte-aligned sockaddr parse, RTF flag decode, RTF_LOCAL skip, live default-route integration test |
| tcpinfo (RTT diagnostics) | `net/tcpinfo/tcpinfo_darwin.go` | ✅ phase-35: `crates/tcpinfo` darwin TCP_CONNECTION_INFO (tcpi_rttcur) + linux TCP_INFO (tcpi_rtt) |
| Break TCP connections | `ipn/ipnlocal/breaktcp_darwin.go` | ✅ phase-35: `break_tcp_conns()` fd 0..1000 scan+close (darwin); ✅ phase-39 called on set/clear_exit_node in TUN mode only (netstack embedders never affected) |
| Daemon + launchd install | `cmd/tailscaled/install_darwin.go` | ✅ phase-36: `crates/rustscaled` bin (run/install-system-daemon/uninstall-system-daemon), com.rustscale.rustscaled plist, launchctl lifecycle, safesocket listener stub (LocalAPI TODO) |
| Default route detection | `net/netmon/defaultroute_darwin.go` | ✅ phase-37: `default_route_interface_index()` RTM_GET sysctl w/ SIOCGIFDELEGATE utun delegation + utun exclusion; state.rs uses sysctl first, `route -n get` fallback |
| Interface enumeration (darwin) | `net/netmon/interfaces_darwin.go` | ✅ phase-37 (folded into defaultroute work) |

P3 status: hostinfo darwin ✅ phase-40 (OSVersion via kern.osproductversion,
DeviceModel via hw.model sysctlbyname) · quarantine xattr ✅ phase-40
(`crates/quarantine`, Go-format com.apple.quarantine value; Taildrop will
consume it) · peermtu darwin (no-op in Go too) ⬜ · sockstats ⬜.

## Tier 3: Specialized

Tailscale SSH (`ssh/tailssh/`, port-10) · Taildrop (`ipn/ipnlocal/files.go`) ·
Taildrive (`drive/`) · Tailnet Lock/TKA (`tka/`) · Device posture (`posture/`) ·
App connector (`appc/`) · NetNS socket binding (`net/netns/`) · Session
recording (`sessionrecording/`) · Workload identity federation
(`feature/identityfederation/`). All ⬜.

## Tier 4: Optimization & tools

Peer MTU discovery (`magicsock/peermtu.go`) · GSO/GRO batching
(`net/batching/`, Linux CI) · io_uring TUN+socket (Linux) · BPF disco filtering
(`magicsock_linux.go`) · Flow tracking (`net/flowtrack/`) · sockstats ·
tcpinfo · ICMP ping (`net/ping/`) · DNS cache + fallback (`net/dnscache/`,
`net/dnsfallback/`) ✅ phase-19 (`crates/dnscache` TTL+singleflight+last-good,
`crates/dnsfallback` bootstrap-dns over embedded DERP IPs + DERP map disk
cache; wired into controlclient dial) · CapturePcap · Logtail · Watchdog ·
Syspolicy · Captive
portal detection (Report field exists, unwired 🔶) · C2N debug endpoints
(✅ phase-21: real handlers for prefs/netmap/health/metrics/dns/
component-logging/goroutines/sockstats; only /debug/pprof/* remains 501 —
no Rust pprof) ·
Netmap disk cache (offline startup) (✅ phase-22: versioned envelope,
SHA-256 write dedup, save per MapResponse, clear on auth failure/key
expiry; Go columnar store layout not replicated — single-blob by design) · Web client UI ·
BIRD routing · Linux
ipset · envknob · version package · Freedesktop/DBus · System tray. All ⬜
unless noted. Control knobs (`control/controlknobs/`) ✅ phase-17
(`crates/controlknobs`, CapMap→knobs in controlclient, tsnet accessor).
PeerAPI (`ipn/ipnlocal/peerapi.go`) ✅ phase-18 (tsnet peerapi.rs: DoH
/dns-query, /v0/* endpoints, WhoIs auth, CRC32 port, peerapi4/6 Service
advertisement); Hostinfo ✅ phase-23 (all 36 Go fields, 10min update loop
with content-hash dedup, runtime setters).

## Tier 5: Server-side (out of scope for the client)

DERP relay server (`cmd/derper/`) · Peer relay server (`net/udprelay/` server
side). Roadmap tail.

## Already at parity (client core)

Wire types/keys/disco/DERP client/netcheck (STUN) · ts2021 Noise control
client (HTTP/2-over-Noise, streaming netmap deltas) · magicsock
(direct/DERP path selection, cross-region routing, reply-to-arrival-region;
peer-relay client is 🔶 partial — geneve codec + handshake types exist but
no relayManager loop, see docs/phase-peer-relay.md gap table)
· WireGuard data plane (boringtun) · userspace netstack (smoltcp,
event-driven) · packet filter (incl. stateful UDP) · subnet routing
(advertise/accept/forward) · TUN mode (macOS utun, Linux untested) · tsnet
embed API · C FFI (librustscale) + Python ctypes · bench harness (beats
tailscaled userspace: p50 ~170us vs 257us, 465–838 vs 384 Mbps).

## Test infrastructure

`crates/testcontrol` ✅ phase-28: in-process fake control server (Noise
server handshake, h2c, register, streaming map, Go-testcontrol-style test
API); tsnet self-test registers → Running → sees injected fake peer with
no network. `crates/derp` server ✅ phase-29: in-process DERP relay
(spawn_local + make_derp_map) for integration tests. tailcfg
null-tolerance ✅ phase-30: every wire field accepts Go nil + property
test nullifying each field. Full plan: docs/testcontrol-plan.md
(remaining: Phase B integration scenarios, Phase D UDP impairment shim,
Go-testcontrol interop harness).

## Release pipeline

`release.yml` ✅ phase-38: tag-triggered (`v*`) multi-platform build. macOS
job builds aarch64 + x86_64, lipos universal `librustscale.dylib` + `.a`,
regenerates `include/rustscale.h` via `tools/gen-header.sh`, and bundles a
single `rustscale-universal-apple-darwin.tar.gz`. Linux job matrix builds
x86_64-gnu, aarch64-gnu (cross-compiled via `gcc-aarch64-linux-gnu`), and
x86_64-musl (static via `musl-gcc`), each producing a per-target tar.gz.
Checksums job downloads all artifacts, computes `SHA256SUMS`, and creates the
GitHub Release via `softprops/action-gh-release`. Binary crates (e.g.
`rustscaled`) are wired via a `BIN_PKGS` env var — add the package name and
the workflow builds + lipos it automatically. `audit.yml` ✅ phase-38: weekly
`cargo-audit` (RUSTSEC) + `cargo-deny` (licenses/bans/advisories), also on PRs
touching `Cargo.lock` or `deny.toml`. Version stamping via
`crates/ffi/build.rs` (`git describe --tags --long --always --dirty` →
`RUSTSCALE_VERSION_LONG`, fallback `CARGO_PKG_VERSION`), exposed through
`ts_version()` FFI and `tools/version.sh`.

## Cross-client interop verification

`tools/interop.sh` runs 8 e2e tests against real Go tailscaled (1.98.8,
userspace mode) on an ephemeral tailnet: dial both directions, MagicDNS
name resolution, WhoIs identity, direct path (disco vs Go magicsock),
pinned-DERP relay, DERP→direct upgrade without byte loss, subnet route
accept. All green 2026-07-09. CI: `interop` job in e2e.yml.
