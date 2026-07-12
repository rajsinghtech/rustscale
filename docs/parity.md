# rustscale ↔ tailscale parity tracker

Tiered gap analysis vs the Go implementation (user-authored 2026-07-09).
Status legend: ✅ done · 🔶 partial · 🚧 in progress · ⬜ not started.
Active execution order is in CLAUDE.md; this file is the full inventory —
update statuses as phases land.

## Verified gap audit (2026-07-12, re-verified 2026-07-13)

An independent three-way codebase comparison (`docs/audit/*.md`) plus an
adversarial verification pass (`docs/audit/verified.md`) found several rows
were **overstated** or **understated**. A follow-up 12-agent code-source
verification pass against the live codebase re-checked every item. Statuses
below reflect actual source code (`crates/*`) as of 2026-07-13.

## Tier 1: Core compatibility (missing = incomplete client)

| Feature | Go source | Status |
| --- | --- | --- |
| MagicDNS + split DNS resolver | `net/dns/resolver/tsdns.go` | ✅ full resolver (A/AAAA/PTR), split-DNS via control `Routes`, DoH upstream forwarder, TCP fallback, TC bit, .onion NXDOMAIN, 4via6, Hosts/LocalDomains, atomic SetConfig, macOS `/etc/resolver` configurator |
| Let's Encrypt certs via control | `ipn/ipnlocal/cert.go` | ✅ full ACME client (RFC 8555, ES256 JWS, dns-01 via set-dns, rcgen CSR); live LE-staging e2e; LocalAPI `GET /cert/<domain>`; `rustscale cert` CLI |
| WhoIs (peer identity from conn) | `tsnet.Server.WhoIs` | ✅ `Server::whois` + `ts_whois` FFI (UserProfiles from netmap); e2e + interop tests |
| Exit node support | LocalBackend/router/magicsock | ✅ set_exit_node/clear_exit_node, RouteTable catch-all, PATCH /prefs wiring, ExitNodeAllowLANAccess, TUN exit-node mode; bypass routes for DERP/control in TUN+exit mode ⬜ |
| Network monitor (netmon) | `net/netmon/` | ✅ AF_ROUTE (macOS), NETLINK_ROUTE (Linux, real-time), polling fallback; State/ChangeDelta, major/minor change detection, wall-time jump; wired into magicsock link_changed |
| Port mapping (NAT-PMP/PCP/UPnP) | `net/portmapper/` | ✅ Client facade (probe/create/renew/cache), PMP/PCP byte-exact packet codec with RFC test vectors, UPnP SSDP+SOAP, fake IGD tests, magicsock portmap endpoint publishing |
| Health tracking | `health/` | 🔶 Tracker+Watchdog complete, 12/20 Go warnables registered (WARN_CONTROL, DERP_HOME, CERT_FALLBACK, NETMON_CHANGE, CAPTIVE_PORTAL, PRODUCTIVITY, UDP, IPV4, IPV6, DERP_NO_REGION, IDLE, LOGIN), per-region DERP health tracking wired; control/DERP/certs/netmon integration, C2N/FFI endpoints; missing ~8 warnables (map-request errors, HTTP flood, DNS fallback, TKA state, etc.) |
| IPN state machine + notify bus | `ipn/backend.go`, `ipn/ipnlocal/local.go` | ✅ State enum (7 states wire-compatible), Notify with 16 Go fields incl. NetMap/PeersChanged/PeersRemoved/PeerChangedPatch/Health/ClientVersion/SuggestedExitNode/UserProfiles, NotifyBus broadcast channel (128-cap), IpnBackend with blocked/logged_out setters, state machine transition table with tests; LocalAPI GET /watch-ipn-bus |
| Interactive auth + prefs persistence | `ipn/prefs.go`, `cmd/tailscale/cli/up.go`, `ipn/localapi/localapi.go` | ✅ Prefs (16 fields + MaskedPrefs), prefs.json atomic persistence, start_localapi_only() NeedsLogin mode, bootstrap() full auth flow (register→AuthURL→wait→map), LocalAPI /start/login-interactive/logout/PATCH/GET prefs, CLI up/login/logout/down/set/get, daemon no longer requires TS_AUTHKEY |

## Tier 2: Production features

| Feature | Go source | Status |
| --- | --- | --- |
| Serve/Funnel (ListenFunnel, ServeConfig, TCP fwd, reverse proxy) | `tsnet`, `ipn/serve*` | ✅ ServeConfig serde + ETag + persistence; TCP/HTTP/HTTPS dispatch; reverse proxy with WhoIs headers (Tailscale-User-Login/Name); TLS-terminate via ControlCertProvider; HTTP-to-HTTPS redirect; HTTPHandler.Redirect with `${HOST}`/`${REQUEST_URI}` expansion; Ingress-Target header dispatch; listen_funnel port validation (443/8443/10000); LocalAPI GET/POST serve-config; CLI serve/funnel with status/reset |
| Tailscale Services (ListenService, PROXY protocol) | `tsnet.Server.ListenService` | ✅ listen_service(svc_name, ServiceMode) with VIP v4 addrs from CapMap (ServiceIPMappings); PROXY protocol v2 binary header encoder (byte-exact IPv4/IPv6/LOCAL); ServiceStream wrapping; IPv6 VIPs skipped (smoltcp proto-ipv4 only); remaining: TLS termination for service FQDN, serve-config TCP forwarding path |
| SOCKS5 proxy | `net/socks5/` | ✅ RFC 1928 CONNECT (v4/domain/v6); RFC 1929 username/password auth; pluggable SocksDialer; FFI; e2e tests |
| LocalAPI | `ipn/localapi/` | ✅ 17+ endpoints (status, whois, prefs GET+PATCH, netmap, metrics, health, ping(stub), watch-ipn-bus, start, login-interactive, logout, serve-config, profiles, cert, file-targets, debug, dial, dns-query, check-ip-forwarding) |
| Auto-update / ClientVersion | — | 🔶 `crates/clientupdate` API complete (ClientUpdater, CheckResult, version_to_track), MapResponse.ClientVersion field exists, Notify.ClientVersion field exists; auto_apply returns `AutoUpdateNotImplemented`; not wired into map-update loop |
| Multi-profile/login management | `ipn/ipnlocal/profiles.go` | ✅ ProfileManager with profiles.json + current-profile persistence; LocalAPI CRUD endpoints; CLI switch command; remaining: backend teardown+restart on switch, Windows LocalUserID |

## macOS platform parity (phases 32–40, 2026-07-11)

| Feature | Go source | Status |
| --- | --- | --- |
| macOS DNS OS configurator | `net/dns/manager_darwin.go` | ✅ DarwinConfigurator (/etc/resolver/$SUFFIX, ownership header, stale cleanup, foreign files untouched); wired into TUN mode |
| Safe socket (CLI↔daemon IPC) | `safesocket/safesocket_darwin.go` | ✅ unix listen/connect (stale removal, 0o666 perms); darwin sameuserproof (macsys file variant, lsof variant, set_credentials override, token gen) |
| Route table enumeration | `net/routetable/routetable_bsd.go` | ✅ NET_RT_DUMP2 sysctl RIB fetch, rt_msghdr2 + sockaddr parse, RTF flag decode, RTF_LOCAL skip, live default-route integration test |
| tcpinfo (RTT diagnostics) | `net/tcpinfo/tcpinfo_darwin.go` | ✅ darwin TCP_CONNECTION_INFO (tcpi_rttcur) + linux TCP_INFO (tcpi_rtt) |
| Break TCP connections | `ipn/ipnlocal/breaktcp_darwin.go` | ✅ fd 0..1000 scan+close (macOS); called on set/clear_exit_node in TUN mode only |
| Daemon + launchd install | `cmd/tailscaled/install_darwin.go` | ✅ rustscaled bin (run/install/uninstall), com.rustscale.rustscaled plist, launchctl lifecycle, safesocket LocalAPI; needs-login startup mode when no TS_AUTHKEY |
| Default route detection | `net/netmon/defaultroute_darwin.go` | ✅ RTM_GET sysctl + SIOCGIFDELEGATE utun delegation; route -n get fallback |
| Interface enumeration (darwin) | `net/netmon/interfaces_darwin.go` | ✅ getifaddrs + sockaddr_dl for MAC, ifa_data for MTU, IFF flags |

P3 status: hostinfo darwin ✅ (OSVersion + DeviceModel via sysctl) · quarantine xattr
✅ (com.apple.quarantine value) · peermtu darwin (no-op in Go too) ⬜ · sockstats 🔶
(endpoint wired, stub handler).

## Tier 2.5: Client infrastructure (Go packages not previously tracked)

| Package | Go source | Rust status |
| --- | --- | --- |
| Tailscale IP addr helpers | `net/tsaddr/` | 🔶 predicates scattered across c2n, peerapi, netns, netmon, routing, dns; no unified crate |
| Outbound dial abstraction | `net/tsdial/` | ⬜ `netns::dial_tcp()` exists but missing PeerAPI/DoH/DNS-map routing |
| Localhost port proxy map | `net/proxymap/` | ⬜ ephemeral localhost->remote IP port mapping for proxied conns |
| HTTP CONNECT proxy | `net/connectproxy/` | ✅ `crates/connectproxy`: `ConnectProxyConfig`, `parse_connect_request`, `handle_connect` with bidirectional tunnel |
| HTTP proxy env detection | `net/tshttpproxy/` | ⬜ `--http-proxy-server` flag exists but "not yet wired" |
| Embedded TLS roots fallback | `net/bakedroots/` | ⬜ container/minimal-Linux control-plane cert validation |
| OS-level route management | `wgengine/router/` | 🔶 `crates/routetable` reads routes via PF_ROUTE sysctl; `tun_pump.rs` installs routes via shell (route/ip); no clean router abstraction |
| LocalAPI authorization | `ipn/ipnauth/` | ⬜ socket 0600 permission only; no unix_peer_creds middleware |
| IPN audit logging | `ipn/auditlog/` | ⬜ |
| Service policy | `ipn/policy/` | ⬜ only `SSHPolicy` wire type exists; no policy engine |
| Config file format | `ipn/conffile/` | ⬜ HUP-reloadable JSON config for daemon |
| IPN extension system | `ipn/ipnext/` | ⬜ |
| Cloud log shipping | `logtail/` | 🔶 `crates/logtail` buffers entries with proc_id/proc_seq metadata; HTTP upload is TODO stub |
| Port enumeration | `portlist/` | ⬜ |
| Network flow logging | `wgengine/netlog/` | ⬜ |
| Network error classification | `net/neterror/` | ✅ `rustscale-neterror` crate with `treat_as_lost_udp`, `packet_was_truncated`, `should_disable_udp_gso`, `is_closed_pipe_error`; wired into magicsock (send/disco paths), portmapper (PMP/PCP mapping sends), dns forwarder (UDP recv) |
| Network traffic steering | `net/traffic/` | 🔶 split DNS OS config exists (macOS); no general traffic-steering abstraction |
| Subnet route health check | `net/routecheck/` | ⬜ |
| Captive portal detection | `net/captivedetection/` | ✅ `Detector` concurrent HTTP GETs, DERPMap endpoints, response validation (status + challenge + body), wired into netcheck prober + health Tracker |
| ICMP ping | `net/ping/` | 🔶 `crates/netcheck/src/icmp.rs` — internal pinger for netcheck fallback; CLI `ping` calls daemon but returns 501 |
| Socket statistics | `net/sockstats/` | 🔶 C2N + PeerAPI endpoints wired (stub handlers); no actual collection |
| In-memory test net | `net/memnet/` | ⬜ |
| Event bus | `util/eventbus/` | ✅ `crates/ipn/src/bus.rs`: NotifyBus backed by tokio::sync::broadcast (128-cap), NotifyBusReceiver for async streaming |
| Client metrics | `util/clientmetric/` | ✅ `crates/clientmetric`: Registry with Counter/Gauge (atomic-backed), to_prometheus_text() + to_json(); wired into LocalAPI /metrics |
| Deep hash / change detection | `util/deephash/` | ⬜ |
| Singleflight | `util/singleflight/` | 🔶 inline in `crates/dnscache` (inflight dedup HashMap); no standalone crate |
| LRU cache | `util/lru/` | 🔶 inline in `crates/filter/src/state.rs` (flow tracking LRU, max 512 entries); no standalone crate |
| Rate limiter | `util/limiter/` | 🔶 inline in `crates/derp/src/client.rs` (token-bucket for DERP send path); no standalone crate |
| Ring buffer logger | `util/ringlog/` | ⬜ |
| QR code rendering | `util/qrcodes/` | ✅ qrcode crate + hand-rolled 1-bit PNG encoder; `up --qr` / `login --qr` terminal half-block QR + data:image/png data URL |
| Dependency injection / tsd | `tsd/` | ⬜ |
| Feature gate system | `feature/` | 🔶 `crates/controlknobs` provides runtime feature flags from control plane CapMap; no compile-time gate system |
| Safe atomic file writes | `atomicfile/` | ✅ `crates/atomicfile`: write-temp+fsync+rename utility with perms 0o600 |
| Metrics registry | `metrics/` | ✅ via `crates/clientmetric`: Registry with Counter/Gauge, Prometheus text format, wired into LocalAPI /metrics replacing 4 hardcoded metrics |
| File path constants | `paths/` | ✅ `crates/paths`: default_state_dir/log_dir/config_dir/socket_path per platform (macOS/Linux/Windows) |
| Status/PeerStatus model | `ipn/ipnstate/` | 🔶 inline in `crates/tsnet/src/status.rs` + localapi build_status_json(); no dedicated crate |
| State persistence abstraction | `ipn/store/` | ✅ `crates/ipn/src/store.rs`: Store trait + MemStore (HashMap) + FileStore (one file per key) |
| IPN server actor loop | `ipn/ipnserver/` | ⬜ orchestration embedded in tsnet Server + lifecycle.rs; no dedicated actor loop |
| TSP protocol (alt control) | `control/tsp/` | ⬜ only ts2021 Noise control protocol implemented |
| Log policy / logtail setup | `logpolicy/` | ⬜ log dir creation in launchd.rs only; no rotation or policy |
| Packet parsing (headers) | `net/packet/` | ✅ `crates/packet`: IPv4Header, IPv6Header, ICMPHeader, UDPHeader, TCPFlag, Parsed rich decoded view, parse_packet(); GENEVE in udprelay |
| DNS name utilities | `util/dnsname/` | 🔶 FQDN handling in dns resolver + tsnet; no standalone crate with ValidLabel/SanitizeLabel |
| TLS dial config | `net/tlsdial/` | 🔶 tls_config() in DERP client + controlhttp + ACME; no unified tlsdial module |
| Network utility functions | `net/netutil/` | 🔶 proxy protocol detection in service.rs; interface helpers in netmon/netns; no consolidated crate |
| Socket options | `net/sockopts/` | ✅ SO_MARK + SO_BINDTODEVICE in `crates/netns/src/linux.rs` |
| TCP connection table | `net/netstat/` | 🔶 `crates/tcpinfo` iterates FDs 0..1000 on macOS; no full OS TCP connection enumeration |
| TCP keepalive timeout | `net/ktimeout/` | ⬜ no TCP keepalive setsockopt (keepidle/keepintvl/keepcnt) |
| Speedtest protocol | `net/speedtest/` | ⬜ |
| Desktop integration | `ipn/desktop/` | ✅ `crates/tsnet/src/hostinfo.rs`: reads `/proc/net/unix` for .X11-unix / wayland-1 socket detection |
| Alternative routing table | `net/art/` | ⬜ |
| BIRD routing client | `chirp/` | ⬜ |
| Cloud env detection | `util/cloudenv/` | ✅ `crates/tsnet/src/hostinfo.rs`: reads DMI sysfs for AWS/GCP/DigitalOcean; Azure detection constant defined but not wired |

## Tier 3: Specialized

| Feature | Status |
| --- | --- |
| Tailscale SSH (`ssh/tailssh/`, port-10) | ✅ policy engine (eval_ssh_policy with Any/Node/NodeIP/UserLogin, Reject/Accept), incubator (spawn shell with privilege drop), session recording (asciicast v2 to local .cast file), whois integration; remaining: HoldAndDelegate, remote recorder upload (PeerAPI stream) |
| Taildrop (`feature/taildrop/`) | ✅ TaildropManager with spool directory, conflict modes (skip/overwrite/rename), file-targets enumeration from netmap, PeerAPI PUT /v0/put/<filename>, LocalAPI files/file-targets/file-put/await-waiting-files, CLI file cp/get |
| Taildrive (`drive/`) | ⬜ |
| Tailnet Lock / TKA (`tka/`) | 🔶 wire types only (NodeKeySignature, UnsignedPeer fields on Node); no TKA verification or key management |
| Device posture (`posture/`) | ⬜ |
| App connector (`appc/`) | ✅ crates/appc: domain/wildcard matching, DNS response observation with CNAME resolution, dynamic route advertisement (RouteAdvertiser trait), Conn25 peer selection + split-DNS resolver map, RouteInfo persistence; tsnet wiring with TsnetRouteAdvertiser |
| NetNS socket binding (`net/netns/`) | ✅ `crates/netns`: dial_tcp/dial_tcp_addr with host resolution, SOCKS5 proxy fallback, localhost bypass; macOS IP_BOUND_IF; Linux SO_MARK + SO_BINDTODEVICE |
| Session recording (`sessionrecording/`) | ✅ asciicast v2 format write to local file (`<state_dir>/ssh-sessions/`); remote upload to recorder nodes ⬜ |
| Workload identity federation (`feature/identityfederation/`) | ⬜ |

## Tier 4: Optimization & tools

| Feature | Status |
| --- | --- |
| Peer MTU discovery (`magicsock/peermtu.go`) | ✅ WIRE_MTUS_TO_PROBE defined, set_pmtud_enabled/peer_mtu_enabled, PMTUD burst in send_pings, probe size tracking in endpoint; disabled by default |
| GSO/GRO batching (`net/batching/`) | ⬜ |
| io_uring TUN+socket (Linux) | ⬜ |
| BPF disco filtering (`magicsock_linux.go`) | ⬜ |
| Flow tracking (`net/flowtrack/`) | 🔶 LRU cache in filter state.rs (512-entry, UDP/SCTP 5-tuple); no time-based expiry, no ConnRecord/packet counters, no TCB tracking |
| sockstats | 🔶 C2N + PeerAPI endpoints wired (stub handlers); no actual socket statistics collection |
| tcpinfo | ✅ `crates/tcpinfo`: macOS TCP_CONNECTION_INFO + Linux TCP_INFO; break_tcp_conns() for macOS |
| ICMP ping (`net/ping/`) | ✅ `crates/netcheck/src/icmp.rs`: unprivileged DGRAM+IPPROTO_ICMP fallback to SOCK_RAW; integrated as fallback when STUN probes fail |
| DNS cache + fallback (`net/dnscache/`, `net/dnsfallback/`) | ✅ `crates/dnscache` (TTL, singleflight-inline, UseLastGood stale fallback, happy-eyeballs dialer); `crates/dnsfallback` (bootstrap-dns over DERP IPs, static + cached DERP map); wired into controlclient dial |
| C2N debug endpoints | ✅ 10+ handlers (echo, prefs, netmap, health, metrics, dns, goroutines, component-logging, sockstats, logtail/flush); only /debug/pprof/* remains 501 |
| Netmap disk cache | ✅ versioned envelope (v1), SHA-256 write dedup, save per MapResponse, clear on auth failure/key expiry; single-blob design |
| Web client UI | ✅ `rustscale web` with embedded HTML/JS, /api/status/up/down/logout handlers, loopback-only, --readonly, --unsafe-any-addr |
| Control knobs (`control/controlknobs/`) | ✅ HashMap<String,String> behind RwLock, typed accessors (get_bool/float/string), change-detection merge, on_change callbacks |
| PeerAPI (`ipn/ipnlocal/peerapi.go`) | ✅ DoH /dns-query (GET + POST), /v0/* endpoints (goroutines, env, metrics, magicsock, dnsfwd, interfaces, sockstats), WhoIs auth, CRC32 port [32768, 65535], Taildrop PUT handler, netstack + TUN spawners |
| Hostinfo | 🔶 ~22/42 fields populated (IPNVersion, OS, OSVersion, Machine, Hostname, Services, NetInfo, RoutableIPs, etc.); missing ~20 (FrontendLogID, BackendLogID, PushDeviceToken, ShareeNode, NoLogsNoSupport, WireIngress, AllowsUpdate, GoArchVar, RequestTags, WoLMACs, SSH_HostKeys, Userspace, AppConnector, PeerRelay, ServicesHash, Location, TPM, StateEncrypted, ShieldsUp, etc.) |
| CapturePcap | 🔶 API declared at `Server::capture_pcap()` but returns "not yet implemented" error |
| Logtail | 🔶 buffers + metadata + write(); HTTP upload is TODO stub (no network upload to log server) |
| Watchdog | ✅ tokio-based interval task, auto-fires warning if not feed() within interval, Drop-safe |
| Syspolicy | ⬜ |
| BIRD routing (`chirp/`) | ⬜ |
| Linux ipset | ⬜ |
| envknob | ⬜ |
| Version package | ✅ build.rs git describe --tags --long --always --dirty → RUSTSCALE_VERSION_LONG; fallback CARGO_PKG_VERSION |
| Freedesktop/DBus | ⬜ |
| System tray | ⬜ |
| Captive portal detection | ✅ full Detector with concurrent HTTP GETs, available_endpoints() from DERPMap, response_looks_like_captive(), wired into netcheck prober + health Tracker WARN_CAPTIVE_PORTAL |

## Tier 5: Server-side (out of scope for the client)

DERP relay server (`cmd/derper/`) · Peer relay server (`net/udprelay/` server
side). Roadmap tail.

## Already at parity (client core)

Wire types/keys/disco/DERP client/netcheck (STUN) · ts2021 Noise control
client (HTTP/2-over-Noise, streaming netmap deltas) · magicsock
(direct/DERP path selection, cross-region routing, reply-to-arrival-region;
peer-relay client ✅ — full relayManager loop: 1.5k loc event loop, alloc work,
handshake work, disco message routing, call-me-maybe via relay)
· WireGuard data plane (boringtun) · userspace netstack (smoltcp,
event-driven) · packet filter (incl. stateful UDP, capability ACLs, shields-up mode)
· subnet routing (advertise/accept/forward) · TUN mode (macOS utun, Linux)
· tsnet embed API · C FFI (librustscale) + Python ctypes · bench harness (beats
tailscaled userspace: p50 ~170us vs 257us, 465–838 vs 384 Mbps).

## Test infrastructure

`crates/testcontrol` ✅ in-process fake control server (Noise handshake, h2c,
register, streaming map, Go-testcontrol-style test API); RequireAuth/CompleteAuth/
AwaitAuthURL flows for interactive login testing. `crates/derp` server ✅
in-process DERP relay (spawn_local + make_derp_map) for integration tests.
tailcfg null-tolerance ✅ every wire field accepts Go nil + property test
nullifying each field. Full plan: docs/testcontrol-plan.md
(remaining: Phase B integration scenarios, Phase D UDP impairment shim,
Go-testcontrol interop harness).

## Release pipeline

`release.yml` ✅ tag-triggered (v*) multi-platform build. macOS universal
(aarch64 + x86_64 lipo'd dylib/.a + binaries). Linux matrix (x86_64-gnu,
aarch64-gnu, x86_64-musl). Windows x86_64-msvc. Docker multi-arch image
pushed to GHCR. Homebrew formula. SHA256SUMS + GitHub Release.
`audit.yml` ✅ weekly cargo-audit (RUSTSEC) + cargo-deny (licenses/bans),
also on PRs touching Cargo.lock or deny.toml. Version stamping ✅ via
build.rs (`git describe --tags --long --always --dirty` → RUSTSCALE_VERSION_LONG).

## CI pipeline

`ci.yml` ✅ OS matrix (ubuntu/macos/windows). Full build/test/clippy on
ubuntu + macOS. Windows: cargo check + select crate tests under bash.
Cross-compile matrix: aarch64/armv7/x86_64-musl linux, aarch64-darwin,
x86_64-windows. `--locked` on every cargo invocation. Dirty-tree guard.
MSRV 1.91. `alls-green` merge gate. All actions SHA-pinned.
`fuzz.yml` ✅ 5 cargo-fuzz targets (disco_decode, derp_frame, stun_parse,
portmapper_pmp, portmapper_pcp); 60s per target on PRs, daily cron, crash
artifacts. `sanitizer.yml` ✅ weekly ThreadSanitizer (nightly, linux) over
magicsock/derp/tsnet; continue-on-error (informational). Miri for codec
crates deferred.

## Cross-client interop verification

`tools/interop.sh` runs 8 userspace e2e tests + `tools/interop-tun.sh` runs
4 TUN-mode e2e tests against real Go tailscaled (1.98.8) on ephemeral
tailnets: dial both directions, MagicDNS name resolution, WhoIs identity,
direct path (disco vs Go magicsock), pinned-DERP relay, DERP→direct upgrade
without byte loss, subnet route accept, OS routes, subnet forwarding. All
green. CI: interop + interop-tun jobs in e2e.yml.

## CLI (`cmd/tailscale` equivalent)

`crates/cli` produces the `rustscale` binary; `crates/localclient` is the
LocalAPI HTTP client (Go `client/local` equivalent) over safesocket. Hand-
rolled arg parsing (no clap), `#![forbid(unsafe_code)]`, `#[tokio::main]`.
Global flags: `--socket <path>` (default `/var/run/rustscaled.sock` with
state-dir fallback probing), `--json`.

| Subcommand | Go source | Status |
| --- | --- | --- |
| `status` | `cli/status.go` | ✅ table + `--json` passthrough; `--peers=false`, `--active` flags; peer table (IP, hostname, owner, connection path, exit-node flag) |
| `ip` | `cli/ip.go` | ✅ `-4`/`-6`/`-1` filters; peer lookup by IP or hostname |
| `version` | `cli/version.go` | ✅ client version (build.rs git stamp) + `--daemon` daemon version from status; `--json` |
| `whois` | `cli/whois.go` | ✅ machine + user table; `--json` |
| `netcheck` | `cli/netcheck.go` | ✅ client-side STUN probe via `crates/netcheck`; DERPMap from daemon netmap; Go-style report (UDP, IPv4/6, MappingVariesByDestIP, DERP latencies sorted) |
| `metrics` | `cli/metrics.go` | ✅ raw Prometheus text passthrough |
| `health` | — | ✅ health warnings from daemon; `--json` |
| `down` | `cli/down.go` | ✅ EditPrefs WantRunning=false via PATCH /prefs |
| `ping` | `cli/ping.go` | 🔶 CLI calls `client.ping(ip, "disco")` but daemon returns 501 (magicsock disco-ping API pending) |
| `up` | `cli/up.go` | ✅ full runUp sequence (status → build prefs → watch-ipn-bus → /start → login-interactive → BrowseToURL → Running); flags: --auth-key, --hostname, --advertise-routes, --advertise-exit-node, --exit-node, --shields-up, --accept-routes, --accept-dns, --reset, --force-reauth, --timeout, --json, --qr |
| `login` | `cli/login.go` | ✅ login-interactive + watch-ipn-bus for BrowseToURL/Running; --qr |
| `logout` | `cli/logout.go` | ✅ POST /logout |
| `set` | `cli/set.go` | ✅ EditPrefs via PATCH /prefs; flags: hostname, accept-routes, accept-dns, shields-up, advertise-routes, advertise-exit-node, exit-node, route-all, advertise-tags, reset |
| `get` | `cli/prefs.go` | ✅ GET /prefs, JSON or human-readable |
| `switch` | `cli/wait.go` | ✅ `switch [--list] [--json] [<profile>]`; `wait` subcommand ⬜ |
| `serve`/`funnel` | `cli/serve.go` | ✅ serve/funnel status, reset, set with --bg/--https/--http/--tcp/--tls-terminated-tcp; foreground mode not yet supported |
| `cert` | `cli/cert.go` | ✅ `cert [--cert-file] [--key-file] [--min-validity] <domain>`; writes files, `-`=stdout; no-domain prints cert domains from status |
| `file` | `cli/file.go` | ✅ `file cp [--name] [--verbose] [--targets] <files...> <target>:`; `file get [--wait] [--conflict=skip\|overwrite\|rename] [--verbose] <dir>` |
| `ssh` | `cli/ssh.go` | ✅ `ssh [user@]host [args...]`; resolves peer, writes known_hosts, execs system ssh; 29 unit tests |
| `web` | `cli/web.go` | ✅ embedded single-file HTML; endpoints: /api/status/up/down/logout; --readonly, --unsafe-any-addr; 23 unit tests |
| `debug` | `cli/debug.go` | ✅ `debug <status\|metrics\|ipconfig>` |
| `exit-node` | `cli/exitnode.go` | ✅ lists exit-node-capable peers; `--suggest` for SuggestedExitNode; cannot select exit node via CLI |
| `dns` | `cli/dns.go` | ✅ queries daemon DNS resolver or prints MagicDNS status; `--type`, `--json` |
| `bugreport` | `cli/bugreport.go` | ✅ prints version/state/health summary |
| `nc` | `cli/nc.go` | 🔶 stub (not-yet-supported) |
| `id-token` | `cli/id-token.go` | 🔶 stub (not-yet-supported) |
| `update` | `cli/update.go` | 🔶 stub (not-yet-supported) |
| `drive` | `cli/drive.go` | ⬜ |
| `lock` | `cli/lock.go` | ⬜ |
| completion/man | — | ⬜ |

`crates/localclient`: async LocalAPI HTTP client over `safesocket::connect`,
hand-rolled HTTP/1.1 (no hyper), fake Host `local-rustscaled.sock`, typed
errors (AccessDenied 403, PreconditionsFailed 412, HttpStatus, PeerNotFound),
`watch_ipn_bus()` streaming method for newline-delimited JSON `Notify`
messages. Methods: start(), login_interactive(), logout(), edit_prefs(),
get_prefs(), status(), whois(), health(), metrics(), ping(), get_serve_config(),
set_serve_config(), cert_pair(), list_profiles(), current_profile(),
switch_profile(), delete_profile(), push_file(), waiting_files(),
get_waiting_file(), delete_waiting_file(), debug(), dial(), dns_query(),
check_ip_forwarding(). Integration tests: testcontrol + daemon over temp
socket, interactive auth flow.

## Windows port (x86_64-pc-windows-msvc)

Status: ✅ compile-level portability complete and warnings-clean. `cargo check
--workspace --target x86_64-pc-windows-msvc` and `cargo clippy --workspace
--all-targets --target x86_64-pc-windows-msvc -- -D warnings` both pass with
zero errors/warnings. Both Windows CI legs are blocking. Windows test step
runs under `shell: bash` with `RUSTFLAGS="-D warnings"`. Named-pipe transport
( `\\.\pipe\ProtectedPrefix\Administrators\Rustscale\rustscaled`) implemented
with `reject_remote_clients`, 256 KiB buffers, loopback test.

### Remaining Windows gaps (runtime, not compile)

- `crates/tun`: no wintun.dll backend — `create()` returns error on Windows.
- `crates/dns`: `system_nameservers()` reads `/etc/resolv.conf` (hardcoded fallback on Windows).
- `crates/routetable`: macOS-only parser (stub returns `Unsupported` on Windows).
- Windows service install (SCM registration) out of scope; `rustscaled run` works in console with ctrl-c shutdown.
