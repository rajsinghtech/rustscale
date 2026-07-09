# rustscale ↔ tailscale parity tracker

Tiered gap analysis vs the Go implementation (user-authored 2026-07-09).
Status legend: ✅ done · 🔶 partial · 🚧 in progress · ⬜ not started.
Active execution order is in CLAUDE.md; this file is the full inventory —
update statuses as phases land.

## Tier 1: Core compatibility (missing = incomplete client)

| Feature | Go source | Status |
| --- | --- | --- |
| MagicDNS + split DNS resolver | `net/dns/resolver/tsdns.go` | 🔶 resolver + 100.100.100.100 responder + unified dial done; split DNS via control `Routes` still ⬜ |
| Let's Encrypt certs via control | `ipn/ipnlocal/cert.go` | 🔶 `ControlCertProvider` (cache/refresh/fallback) + `SetDNS` control call done; ACME order/finalize client deferred (needs HTTPS-enabled tailnet to e2e) |
| WhoIs (peer identity from conn) | `tsnet.Server.WhoIs` | ✅ `Server::whois` + `ts_whois` FFI (UserProfiles from netmap) |
| Exit node support | LocalBackend/router/magicsock | ⬜ port-5 |
| Network monitor (netmon) | `net/netmon/` | ⬜ port-3 |
| Port mapping (NAT-PMP/PCP/UPnP) | `net/portmapper/` | ⬜ port-4 |
| Health tracking | `health/` | ⬜ port-7 |

## Tier 2: Production features

| Feature | Go source | Status |
| --- | --- | --- |
| Serve/Funnel (ListenFunnel, ServeConfig, TCP fwd, reverse proxy) | `tsnet`, `ipn/serve*` | ⬜ port-6 (listen_tls exists, self-signed 🔶) |
| Tailscale Services (ListenService, PROXY protocol) | `tsnet.Server.ListenService` | ⬜ |
| SOCKS5 proxy | `net/socks5/` | ⬜ port-8 |
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
`net/dnsfallback/`) · CapturePcap · Logtail · Watchdog · Syspolicy · Captive
portal detection (Report field exists, unwired 🔶) · C2N debug endpoints ·
Netmap disk cache (offline startup) · Web client UI · BIRD routing · Linux
ipset · envknob · version package · Freedesktop/DBus · System tray. All ⬜
unless noted.

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
