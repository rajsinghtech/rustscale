# rustscale ↔ tailscale parity tracker

Tiered gap analysis vs the Go implementation (user-authored 2026-07-09).
Status legend: ✅ done · 🔶 partial · 🚧 in progress · ⬜ not started.
Active execution order is in CLAUDE.md; this file is the full inventory —
update statuses as phases land.

## Tier 1: Core compatibility (missing = incomplete client)

| Feature | Go source | Status |
| --- | --- | --- |
| MagicDNS + split DNS resolver | `net/dns/resolver/tsdns.go` | 🔶 resolver + 100.100.100.100 responder + unified dial done; split DNS via control `Routes` still ⬜ |
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
(🔶 phase-14 server + auth done, most handlers stub 501 — see
docs/validation-2026-07-11.md) ·
Netmap disk cache (offline startup) (🔶 phase-15 single-blob cache in tsnet
state.rs; Go columnar store + controlclient wiring pending) · Web client UI ·
BIRD routing · Linux
ipset · envknob · version package · Freedesktop/DBus · System tray. All ⬜
unless noted. Control knobs (`control/controlknobs/`) ✅ phase-17
(`crates/controlknobs`, CapMap→knobs in controlclient, tsnet accessor).
PeerAPI (`ipn/ipnlocal/peerapi.go`) ✅ phase-18 (tsnet peerapi.rs: DoH
/dns-query, /v0/* endpoints, WhoIs auth, CRC32 port, peerapi4/6 Service
advertisement); Hostinfo 27/36 fields (gaps in validation doc).

## Tier 5: Server-side (out of scope for the client)

DERP relay server (`cmd/derper/`) · Peer relay server (`net/udprelay/` server
side). Roadmap tail.

## Already at parity (client core)

Wire types/keys/disco/DERP client/netcheck (STUN) · ts2021 Noise control
client (HTTP/2-over-Noise, streaming netmap deltas) · magicsock
(direct/DERP/peer-relay client, cross-region routing, reply-to-arrival-region)
· WireGuard data plane (boringtun) · userspace netstack (smoltcp,
event-driven) · packet filter (incl. stateful UDP) · subnet routing
(advertise/accept/forward) · TUN mode (macOS utun, Linux untested) · tsnet
embed API · C FFI (librustscale) + Python ctypes · bench harness (beats
tailscaled userspace: p50 ~170us vs 257us, 465–838 vs 384 Mbps).

## Cross-client interop verification

`tools/interop.sh` runs 8 e2e tests against real Go tailscaled (1.98.8,
userspace mode) on an ephemeral tailnet: dial both directions, MagicDNS
name resolution, WhoIs identity, direct path (disco vs Go magicsock),
pinned-DERP relay, DERP→direct upgrade without byte loss, subnet route
accept. All green 2026-07-09. CI: `interop` job in e2e.yml.
