# rustscale ↔ tailscale parity tracker

Tiered gap analysis vs the Go implementation (user-authored 2026-07-09).
Status legend: ✅ done · 🔶 partial · 🚧 in progress · ⬜ not started.
Active execution order is in CLAUDE.md; this file is the full inventory —
update statuses as phases land.

## Tier 1: Core compatibility (missing = incomplete client)

| Feature | Go source | Status |
| --- | --- | --- |
| MagicDNS + split DNS resolver | `net/dns/resolver/tsdns.go` | ✅ phase-20: split DNS via control `Routes` (most-specific suffix wins), Hosts/LocalDomains/SubdomainHosts, atomic SetConfig, PTR reverse (v4/v6), .onion NXDOMAIN, 4via6, TC bit + EDNS size, ANY qtype, TCP fallback + DoH upstream forwarder |
| Let's Encrypt certs via control | `ipn/ipnlocal/cert.go` | ✅ full ACME client (RFC 8555, ES256 JWS, dns-01 via set-dns, rcgen CSR); live LE-staging e2e green on ephemeral tailnet; phase-cli-cert-qr: LocalAPI `GET /cert/<domain>?type=pair|cert|key&min_validity=` + `rustscale cert` CLI |
| WhoIs (peer identity from conn) | `tsnet.Server.WhoIs` | ✅ `Server::whois` + `ts_whois` FFI (UserProfiles from netmap) |
| Exit node support | LocalBackend/router/magicsock | ✅ port-5 done (advertise_exit_node builder opt adds 0.0.0.0/0+::/0 to RoutableIPs + filter localNets; Server::set_exit_node/clear_exit_node resolve exit-capable peer via IP/hostname + set RouteTable catch-all; TUN mode --exit-node installs /1 split routes on macOS, best-effort default on Linux; ts_set_exit_node/ts_clear_exit_node FFI; bypass routes for DERP/control in TUN+exit mode still ⬜ known limitation) |
| Network monitor (netmon) | `net/netmon/` | ✅ port-3 done (AF_ROUTE on macOS, polling fallback; State, ChangeDelta, major/minor change detection, wall-time jump; wired into magicsock link_changed + tsnet endpoint-update push) |
| Port mapping (NAT-PMP/PCP/UPnP) | `net/portmapper/` | ✅ port-4 done (`crates/portmapper`: Client facade with probe/create/renew/cache lifecycle; PMP/PCP byte-exact packet codec with RFC test vectors; UPnP SSDP M-SEARCH discovery + root-desc XML parse + AddPortMapping/DeletePortMapping/GetExternalIPAddress SOAP; fake IGD tests for all three protocols; magicsock publishes portmap endpoint best-effort alongside local/STUN endpoints; netcheck Report gains portmap capability booleans) |
| Health tracking | `health/` | ✅ port-7: crates/health Tracker + watchdog, wired control/DERP/certs/netmon, ServerStatus.health + FFI |
| IPN state machine + notify bus | `ipn/backend.go`, `ipn/ipnlocal/local.go` | ✅ phase-ipn-bus: `crates/ipn` (State enum serde-as-integer matching Go, Notify PascalCase JSON with omitted None, NotifyWatchOpt bitflags with explicit values, EngineStatus); StateMachine ports `nextStateLocked` truth table (table-driven tests); IpnBackend holds state+inputs+bus, emits Notify{State} on transitions, BrowseToURL on auth URL, LoginFinished on register success, ErrMessage on errors; NotifyBus broadcast channel (tokio::sync::broadcast, 128-capacity); `GET /localapi/v0/watch-ipn-bus?mask=` streaming newline-delimited JSON with per-message flush (connection-close delimited); status JSON reports live BackendState string |
| Interactive auth + prefs persistence | `ipn/prefs.go`, `cmd/tailscale/cli/up.go`, `ipn/localapi/localapi.go` | ✅ phase-interactive-auth: `crates/ipn` Prefs (15 fields, PascalCase serde, Go wire-compat) + MaskedPrefs (*Set bools, apply_to) + StartOptions (ipn.Options equiv); prefs.json disk persistence (atomic temp+rename); daemon-side login flow: `start_localapi_only()` brings up IpnBackend+LocalAPI in NeedsLogin without full bootstrap; bootstrap() splits into phase 1 (register → AuthURL → block on login_trigger) + phase 2 (UDP/map/DERP/netstack after auth completes); testcontrol RequireAuth/CompleteAuth/AwaitAuthURL flows; LocalAPI endpoints POST /start, POST /login-interactive, POST /logout, PATCH /prefs, GET /prefs (typed); LocalClient start/login_interactive/logout/edit_prefs/get_prefs; CLI up/login/logout/down/set/get commands; daemon no longer requires TS_AUTHKEY; integration test: testcontrol(require_auth) → start → BrowseToURL → complete_auth → Running |

## Tier 2: Production features

| Feature | Go source | Status |
| --- | --- | --- |
| Serve/Funnel (ListenFunnel, ServeConfig, TCP fwd, reverse proxy) | `tsnet`, `ipn/serve*` | ✅ port-6 + phase-serve-cli-profiles: ServeConfig serde model (TCPPortHandler/WebServerConfig/HTTPHandler) + ETag (SHA-256 of canonical JSON) + persistence (`<state_dir>/serve-config.json`, atomic save, reload on daemon start); Server::set_serve_config starts netstack listeners per port; TCP forward via copy_bidirectional; HTTP reverse proxy sets Host/X-Forwarded-For/Tailscale-User-Login/Name from WhoIs; static text handler; TLS-terminate with ControlCertProvider (self-signed fallback); listen_funnel validates port 443/8443/10000 + funnel node attr; LocalAPI `GET/POST /localapi/v0/serve-config` with If-Match/ETag/412; LocalClient get/set_serve_config; CLI `rustscale serve [--bg] [--https|--http|--tcp|--tls-terminated-tcp=<port>] [--set-path <path>] <target>`, `serve status [--json]`, `serve reset`; `rustscale funnel` variants (AllowFunnel + port validation client-side); foreground mode errors "not yet supported" without --bg. Remaining: ingress peer Tailscale-Ingress-Target dispatch, Hostinfo.IngressEnabled advertisement, foreground session-scoped serve |
| Tailscale Services (ListenService, PROXY protocol) | `tsnet.Server.ListenService` | ✅ `Server::listen_service(svc_name, ServiceMode)` resolves VIP v4 addrs from self node CapMap `service-host` key (`ServiceIPMappings`), adds them to netstack via `add_addr`, listens on each VIP:port via `listen_on`; merged accept channel from all VIP listeners; `ServiceName` newtype validates `svc:` prefix + DNS label; PROXY protocol v2 binary header encoder (byte-exact IPv4/IPv6/LOCAL); `ServiceStream` wraps `NetstackStream` with PROXY v2 prefix drained before app data; netstack `listen_on`/`add_addr` + `(IpAddr,port)` listener key; IPv6 VIPs skipped (smoltcp proto-ipv4 only). Remaining: TLS termination for service FQDN, serve-config TCP forwarding path, IPv6 VIP support |
| SOCKS5 proxy | `net/socks5/` | ✅ port-8: RFC 1928 CONNECT (v4/domain/v6), dials via shared tsnet resolve path, FFI; e2e green |
| LocalAPI | `ipn/localapi/` | ✅ port-9 + phase-ipn-bus + phase-interactive-auth + phase-serve-cli-profiles + phase-cli-cert-qr: full LocalAPI HTTP server on safesocket (status, whois, prefs GET+PATCH, netmap, metrics, health, ping, watch-ipn-bus, start, login-interactive, logout, serve-config GET+POST with ETag/If-Match/412, profiles GET+PUT/GET+POST+DELETE, cert `<domain>?type=pair|cert|key&min_validity=`); status reports live BackendState + CertDomains; serve-config persists to `<state_dir>/serve-config.json` and reloads on daemon start; profile manager persists to `profiles.json` + `current-profile`; integration tests: LocalAPI over safesocket, serve-config persistence across daemon restart, profile switch with two identities, cert endpoint 400/404 + cache-hit PEM paths |
| Auto-update / ClientVersion | — | ⬜ |
| Multi-profile/login management | `ipn/ipnlocal/profiles.go` | ✅ phase-serve-cli-profiles: `crates/ipn` LoginProfile/NetworkProfile/ProfileID/UserProfile structs (serde PascalCase, Go wire-compat); profile persistence (`profiles.json` + `current-profile` pointer file, atomic saves); LocalAPI endpoints `GET /profiles`, `PUT /profiles` (create+switch), `GET /profiles/current`, `GET/POST/DELETE /profiles/<id>`; LocalClient list/current/new/switch/delete profile methods; CLI `rustscale switch [--list] [--json] [<profile>]` (match by ID or name, poll for Running); integration test: two-profile create/switch/delete against testcontrol. Remaining: backend teardown+restart on switch (currently updates prefs only), Windows LocalUserID |

## macOS platform parity (phases 32–40, 2026-07-11)

| Feature | Go source | Status |
| --- | --- | --- |
| macOS DNS OS configurator | `net/dns/manager_darwin.go` | ✅ phase-32: `crates/dns` OsConfigurator trait + DarwinConfigurator (`/etc/resolver/$SUFFIX` split DNS, ownership header marker, search.tailscale file, stale cleanup, foreign files untouched); ✅ phase-39 wired into tsnet TUN mode via opt-in `configure_os_dns(true)` builder flag (build_os_dns_config from netmap DNS config, best-effort on permission errors, cleaned up on close) |
| Safe socket (CLI↔daemon IPC) | `safesocket/safesocket_darwin.go` | ✅ phase-33: `crates/safesocket` unix listen/connect (stale removal, perms) + darwin sameuserproof (macsys filename variant, macos lsof variant, set_credentials override, token gen) |
| Route table enumeration | `net/routetable/routetable_bsd.go` | ✅ phase-34: `crates/routetable` NET_RT_DUMP2 sysctl RIB fetch, rt_msghdr2 + 4-byte-aligned sockaddr parse, RTF flag decode, RTF_LOCAL skip, live default-route integration test |
| tcpinfo (RTT diagnostics) | `net/tcpinfo/tcpinfo_darwin.go` | ✅ phase-35: `crates/tcpinfo` darwin TCP_CONNECTION_INFO (tcpi_rttcur) + linux TCP_INFO (tcpi_rtt) |
| Break TCP connections | `ipn/ipnlocal/breaktcp_darwin.go` | ✅ phase-35: `break_tcp_conns()` fd 0..1000 scan+close (darwin); ✅ phase-39 called on set/clear_exit_node in TUN mode only (netstack embedders never affected) |
| Daemon + launchd install | `cmd/tailscaled/install_darwin.go` | ✅ phase-36 + phase-interactive-auth: `crates/rustscaled` bin (run/install-system-daemon/uninstall-system-daemon), com.rustscale.rustscaled plist, launchctl lifecycle, safesocket LocalAPI; daemon no longer requires TS_AUTHKEY — without it starts in NeedsLogin mode (start_localapi_only) and waits for CLI-driven start/login; with TS_AUTHKEY proceeds to full up() directly |
| Default route detection | `net/netmon/defaultroute_darwin.go` | ✅ phase-37: `default_route_interface_index()` RTM_GET sysctl w/ SIOCGIFDELEGATE utun delegation + utun exclusion; state.rs uses sysctl first, `route -n get` fallback |
| Interface enumeration (darwin) | `net/netmon/interfaces_darwin.go` | ✅ phase-37 (folded into defaultroute work) |

P3 status: hostinfo darwin ✅ phase-40 (OSVersion via kern.osproductversion,
DeviceModel via hw.model sysctlbyname) · quarantine xattr ✅ phase-40
(`crates/quarantine`, Go-format com.apple.quarantine value; Taildrop will
consume it) · peermtu darwin (no-op in Go too) ⬜ · sockstats ⬜.

## Tier 2.5: Client infrastructure (Go packages not previously tracked)

| Package | Go source | Rust status |
| --- | --- | --- |
| Tailscale IP addr helpers | `net/tsaddr/` | 🔶 partially inlined in `dns` + `tsnet/routing`; no dedicated crate |
| Outbound dial abstraction | `net/tsdial/` | ⬜ baked ad-hoc into netstack; no standalone module for PeerAPI/DoH/DNS-map routing |
| Localhost port proxy map | `net/proxymap/` | ⬜ ephemeral localhost->remote IP port mapping for proxied conns |
| HTTP CONNECT proxy | `net/connectproxy/` | ⬜ needed for outbound proxy support |
| HTTP proxy env detection | `net/tshttpproxy/` | ⬜ cross-platform proxy auto-detection (PAC/WPAD/registry) |
| Embedded TLS roots fallback | `net/bakedroots/` | ⬜ container/minimal-Linux control-plane cert validation |
| OS-level route management | `wgengine/router/` | ⬜ TUN mode uses ad-hoc route(8) calls; Go has clean interface + 4 platform impls |
| LocalAPI authorization | `ipn/ipnauth/` | ⬜ who-can-do-what on LocalAPI (unix peer creds, Windows ACLs) |
| IPN audit logging | `ipn/auditlog/` | ⬜ JSON audit trail for sensitive operations |
| Service policy | `ipn/policy/` | ⬜ which services to advertise (Serve/Funnel peer discovery) |
| Config file format | `ipn/conffile/` | ⬜ HUP-reloadable JSON config for daemon |
| IPN extension system | `ipn/ipnext/` | ⬜ LocalBackend plugin architecture |
| Cloud log shipping | `logtail/` | ⬜ uploads to log.tailscale.com |
| Port enumeration | `portlist/` | ⬜ firewall diagnostics / listening-port scan |
| Network flow logging | `wgengine/netlog/` | ⬜ TUN traffic logging → network flow logs |
| Network error classification | `net/neterror/` | ⬜ retry-loops benefit from typed error reasons |
| Network traffic steering | `net/traffic/` | ⬜ hash-based exit-node selection for split-DNS |
| Subnet route health check | `net/routecheck/` | ⬜ exit-node/subnet-router diagnostics |
| Captive portal detection | `net/captivedetection/` | ✅ `Detector` with concurrent HTTP GETs, DERPMap endpoint generation, response validation (status + challenge + body), wired into netcheck prober (`Report.captive_portal`) and health Tracker (`WARN_CAPTIVE_PORTAL`); per-interface binding deferred |
| ICMP ping | `net/ping/` | ⬜ |
| Socket statistics | `net/sockstats/` | ⬜ |
| In-memory test net | `net/memnet/` | ⬜ test infrastructure — in-memory net.Conn/Listener |
| Event bus (in progress) | `util/eventbus/` | 🚧 phase-ipn-bus covers this via broadcast channel |
| Client metrics | `util/clientmetric/` | ⬜ expvar-style counters; exposed by LocalAPI /metrics |
| Deep hash / change detection | `util/deephash/` | ⬜ Go uses for netmap change-detect; Rust PartialEq suffices mostly |
| Singleflight | `util/singleflight/` | ⬜ in-flight request dedup (control client reconnect) |
| LRU cache | `util/lru/` | ⬜ |
| Rate limiter | `util/limiter/` | ⬜ |
| Ring buffer logger | `util/ringlog/` | ⬜ tail-buffered log for diagnostics |
| QR code rendering | `util/qrcodes/` | ✅ phase-cli-cert-qr: `qrcode` crate + hand-rolled 1-bit PNG encoder (flate2+crc32fast); `up --qr` / `login --qr` terminal half-block QR + `QR` data:image/png;base64 field in `--json` |
| Dependency injection / tsd | `tsd/` | ⬜ global subsystem registry pattern |
| Feature gate system | `feature/` | ⬜ Rust `cfg!()` handles compile-time; runtime feature flags ⬜ |
| Safe atomic file writes | `atomicfile/` | ⬜ write-temp+rename, used by EVERY state persistence path |
| Metrics registry | `metrics/` | ⬜ expvar-style counters/gauges exposed by LocalAPI /metrics |
| File path constants | `paths/` | ⬜ central config/log/state dir paths for daemon |
| Status/PeerStatus model | `ipn/ipnstate/` | ⬜ data model queried by LocalAPI /status (860 lines) |
| State persistence abstraction | `ipn/store/` | ⬜ MemStore/FileStore for prefs and state (562 lines) |
| IPN server actor loop | `ipn/ipnserver/` | ⬜ orchestrates LocalBackend lifecycle, reconnect backoff, login flows (7 files) |
| TSP protocol (alt control) | `control/tsp/` | ⬜ alternative control protocol alongside ts2021 (1.4k lines) |
| Log policy / logtail setup | `logpolicy/` | ⬜ log dir setup, rotation, logtail stream config (1.1k lines) |
| Packet parsing (headers) | `net/packet/` | ⬜ IP/TCP/UDP/ICMP/Geneve header parse+marshal (17 files) |
| DNS name utilities | `util/dnsname/` | ⬜ FQDN formatting, DNS label validation (570 lines) |
| TLS dial config | `net/tlsdial/` | ⬜ custom tls.Config for control-plane Noise-over-HTTP |
| Network utility functions | `net/netutil/` | ⬜ interface helpers, multicast check, proxy protocol detection |
| Socket options | `net/sockopts/` | ⬜ platform-aware socket buffer tuning, SO_MARK, SO_BINDTODEVICE |
| TCP connection table | `net/netstat/` | ⬜ OS-level TCP connection enumeration |
| TCP keepalive timeout | `net/ktimeout/` | ⬜ per-platform TCP keepalive configuration |
| Speedtest protocol | `net/speedtest/` | ⬜ tailscale speedtest client+server |
| Desktop integration | `ipn/desktop/` | ⬜ Windows session change / macOS extension support |
| Alternative routing table | `net/art/` | ⬜ Adaptive Radix Tree for IP route lookups (2.6k lines) |
| BIRD routing client | `chirp/` | ⬜ BIRD Internet Routing Daemon client |
| Cloud env detection | `util/cloudenv/` | ⬜ AWS/GCP/Azure detection for NAT/connectivity |

## Tier 3: Specialized

Tailscale SSH (`ssh/tailssh/`, port-10) · Taildrop (`feature/taildrop/`) ✅
phase-taildrop (`crates/tsnet/src/taildrop.rs`: TaildropManager with file spool,
conflict modes skip/overwrite/rename, file-targets enumeration from netmap
peers with file-sharing cap; PeerAPI `PUT /v0/put/<filename>` receive handler
in `peerapi.rs`; LocalAPI endpoints `files/`, `file-targets`, `file-put/`,
`await-waiting-files` in `localapi.rs`; localclient file methods; CLI `file cp`
+ `file get` subcommands; `Notify.FilesWaiting` + `WaitingFile` type in
`crates/ipn`; integration tests for LocalAPI roundtrip, file-targets with cap,
conflict modes, multi-file get) ·
Taildrive (`drive/`) · Tailnet Lock/TKA (`tka/`) · Device posture (`posture/`) ·
App connector (`appc/`) ✅ phase-appc (`crates/appc`: AppConnector with
domain/wildcard matching, DNS response observation with CNAME chain
resolution, dynamic route advertisement via RouteAdvertiser trait, Conn25
peer selection + split-DNS resolver map, RouteInfo persistence, rate
logging; `crates/tailcfg` appctype types; DNS observer callback in
`crates/dns`; tsnet wiring with TsnetRouteAdvertiser) ·
NetNS socket binding (`net/netns/`) · Session
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
expiry; Go columnar store layout not replicated — single-blob by design) · Web client UI (✅ phase-cli-ssh-web: `rustscale web` minimal management UI — embedded single-file HTML with inline JS+fetch, /api/status + /api/up + /api/down + /api/logout handlers, loopback-only binding with --unsafe-any-addr override, --readonly mode; NOT a port of Go's React app) ·
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
peer-relay client ✅ — full relayManager loop (1.5k loc event loop, alloc work,
handshake work, disco message routing, call-me-maybe via relay)
· WireGuard data plane (boringtun) · userspace netstack (smoltcp,
event-driven) · packet filter (incl. stateful UDP) · subnet routing
(advertise/accept/forward) · TUN mode (macOS utun, Linux untested) · tsnet
embed API · C FFI (librustscale) + Python ctypes · bench harness (beats
tailscaled userspace: p50 ~170us vs 257us, 465–838 vs 384 Mbps).

## Test infrastructure

`crates/testcontrol` ✅ phase-28 + phase-interactive-auth: in-process fake control server (Noise server handshake, h2c, register, streaming map, Go-testcontrol-style test API); RequireAuth/CompleteAuth/AwaitAuthURL flows for interactive login testing; tsnet self-test registers → Running → sees injected fake peer with
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

## CI pipeline

`ci.yml` ✅ phase-ci-parity: OS matrix (ubuntu-latest, macos-latest,
windows-latest). Ubuntu + macOS run full build/test/clippy; Windows is
`cargo check --workspace` only (check-only, no tests — Windows compilation
not verified locally; cross-compile from macOS fails due to `ring` C code,
but Rust code has cfg guards for non-macOS/Linux platforms). Cross-compile
check matrix: aarch64-unknown-linux-gnu, armv7-unknown-linux-gnueabihf,
x86_64-unknown-linux-musl (ubuntu), aarch64-apple-darwin (macos),
x86_64-pc-windows-msvc (windows). `--locked` on every cargo invocation.
Dirty-tree guard (git diff + untracked-file check) on ubuntu. MSRV job
(1.91, dictated by smoltcp 0.13) — `rust-version = "1.91"` in workspace
Cargo.toml. `alls-green` merge-gate job (`re-actors/alls-green`) aggregating
check + cross + msrv + testcontrol. All actions SHA-pinned across all
workflows. `testcontrol` job (Go interop) preserved. `merge_group` trigger
added. `fuzz.yml` ✅ phase-ci-parity: cargo-fuzz targets for disco decode,
DERP frame codec, STUN parse, portmapper PMP/PCP codecs; 60s per target on
PRs touching parser crates, daily cron, crash artifacts uploaded.
`sanitizer.yml` ✅ phase-ci-parity: weekly ThreadSanitizer (nightly, linux)
over magicsock/derp/tsnet; `continue-on-error` (informational, non-blocking).
Miri for codec crates deferred. Full spec: `docs/phase-ci-parity.md`.

## Cross-client interop verification

`tools/interop.sh` runs 8 e2e tests against real Go tailscaled (1.98.8,
userspace mode) on an ephemeral tailnet: dial both directions, MagicDNS
name resolution, WhoIs identity, direct path (disco vs Go magicsock),
pinned-DERP relay, DERP→direct upgrade without byte loss, subnet route
accept. All green 2026-07-09. CI: `interop` job in e2e.yml.

## CLI (`cmd/tailscale` equivalent)

`crates/cli` produces the `rustscale` binary; `crates/localclient` is the
LocalAPI HTTP client (Go `client/local` equivalent) over safesocket. Hand-
rolled arg parsing (no clap), `#![forbid(unsafe_code)]`, `#[tokio::main]`.
Global flags: `--socket <path>` (default `/var/run/rustscaled.sock` with
state-dir fallback probing), `--json`.

| Subcommand | Go source | Status |
| --- | --- | --- |
| `status` | `cli/status.go` | ✅ table + `--json` passthrough; `--peers=false`, `--active` flags; peer table (IP, hostname, owner, connection path) |
| `ip` | `cli/ip.go` | ✅ `-4`/`-6`/`-1` filters; peer lookup by IP or hostname |
| `version` | `cli/version.go` | ✅ client version (build.rs git stamp) + `--daemon` daemon version from status; `--json` |
| `whois` | `cli/whois.go` | ✅ machine + user table; `--json` |
| `netcheck` | `cli/netcheck.go` | ✅ client-side STUN probe via `crates/netcheck`; DERPMap from daemon netmap endpoint; Go-style report (UDP, IPv4/6, MappingVariesByDestIP, DERP latencies sorted) |
| `metrics` | `cli/metrics.go` | ✅ raw Prometheus text passthrough |
| `health` | — | ✅ health warnings from daemon; `--json` |
| `down` | `cli/down.go` | ✅ phase-interactive-auth: EditPrefs WantRunning=false via PATCH /prefs |
| `ping` | `cli/ping.go` | 🔶 surfaces daemon 501 as "not yet supported" (magicsock disco-ping API pending) |
| `up` | `cli/up.go` | ✅ phase-interactive-auth: full runUp sequence (status → build prefs → watch-ipn-bus → /start → login-interactive if no node key → BrowseToURL loop → success on Running); flags: --auth-key, --hostname, --advertise-routes, --advertise-exit-node, --exit-node, --shields-up, --accept-routes, --accept-dns, --reset, --force-reauth, --timeout, --json, --qr (terminal QR + PNG data URL in --json) |
| `login` | `cli/login.go` | ✅ phase-interactive-auth: login-interactive + watch-ipn-bus for BrowseToURL/Running; --qr (terminal QR + PNG data URL in --json) |
| `logout` | `cli/logout.go` | ✅ phase-interactive-auth: POST /logout |
| `set` | `cli/set.go` | ✅ phase-interactive-auth: EditPrefs via PATCH /prefs from --hostname, --accept-routes, --accept-dns, --shields-up, --advertise-routes, --advertise-exit-node, --exit-node flags |
| `get` | `cli/prefs.go` | ✅ phase-interactive-auth: GET /prefs, JSON or human-readable |
| `wait`/`switch` | `cli/wait.go` | 🔶 `switch` ✅ phase-serve-cli-profiles: `rustscale switch [--list] [--json] [<profile>]`; `wait` ⬜ |
| `serve`/`funnel` | `cli/serve.go` | ✅ port-6 + phase-serve-cli-profiles: `rustscale serve [--bg] [--https|--http|--tcp|--tls-terminated-tcp=<port>] [--set-path <path>] <target>`, `serve status [--json]`, `serve reset`; `rustscale funnel` variants (AllowFunnel + port validation); foreground mode errors "not yet supported" without --bg |
| `cert` | `cli/cert.go` | ✅ phase-cli-cert-qr: `rustscale cert [--cert-file] [--key-file] [--min-validity] <domain>`; writes files (`-`=stdout); no-domain prints cert domain from status (CertDomains); LocalAPI `GET /cert/<domain>?type=pair|cert|key&min_validity=`; localclient `cert_pair`/`cert`/`cert_key`; reuses existing ACME/ControlCertProvider cache |
| `file` | `cli/file.go` | ✅ phase-taildrop: `file cp [--name] [--verbose] [--targets] <files...> <target>:`; `file get [--wait] [--conflict=skip|overwrite|rename] [--verbose] <dir>`; LocalAPI file-put/files/file-targets endpoints |
| `ssh` | `cli/ssh.go` | ✅ phase-cli-ssh-web: `rustscale ssh [user@]host [args...]`; resolves host against status peers (short name/FQDN/IP); execs system ssh with `-o HostName <resolved-ip>` + known_hosts trust options when peer advertises SSH_HostKeys; unix execvp, Windows "not supported"; 29 argv-construction unit tests |
| `web` | `cli/web.go` | ✅ phase-cli-ssh-web: `rustscale web [--listen <addr>] [--readonly] [--unsafe-any-addr]`; embedded single-file HTML (inline JS+fetch); handlers: GET /api/status, POST /api/up, /api/down, /api/logout; loopback-only by default; LocalApi trait with stub-based handler tests; 23 unit tests |
| `debug` | `cli/debug.go` | ⬜ |
| `exit-node` | `cli/exitnode.go` | ⬜ |
| `drive` | `cli/drive.go` | ⬜ |
| `lock` | `cli/lock.go` | ⬜ |
| completion/man | — | ⬜ |

`crates/localclient`: async LocalAPI HTTP client over `safesocket::connect`,
hand-rolled HTTP/1.1 (no hyper), fake Host `local-rustscaled.sock`, typed
errors (AccessDenied 403, PreconditionsFailed 412, HttpStatus, PeerNotFound),
`watch_ipn_bus()` streaming method for newline-delimited JSON `Notify`
messages. ✅ phase-interactive-auth: `start()` (POST /start with StartOptions),
`login_interactive()`, `logout()`, `edit_prefs()` (PATCH /prefs with
MaskedPrefs), `get_prefs()` (typed Prefs deserialization),
`send_request_with_body()` for POST/PATCH with body. Integration test boots
testcontrol + daemon with LocalAPI on a temp socket and exercises the
`status` path both via the library and the binary via `std::process`;
interactive_auth_flow test: testcontrol(require_auth) → start_localapi_only
→ /start → BrowseToURL → complete_auth → Running.

## Windows port (x86_64-pc-windows-msvc)

Status: 🚧 not started — full Windows support is out of scope per
`docs/phase-ci-parity.md`. The `Check (windows)` matrix leg and the
`x86_64-pc-windows-msvc` cross-check leg in `.github/workflows/ci.yml` are
`continue-on-error: true` (best-effort) until a dedicated Windows-port phase
lands. The failures below are what `cargo check --workspace --target
x86_64-pc-windows-msvc` reports today (confirmed 2026-07-12).

### Real compile errors (block `cargo check --workspace` on Windows)

| Crate | Location | Error | Cause |
| --- | --- | --- | --- |
| `crates/tun` | `src/lib.rs:123-124` | `E0425: cannot find value AF_INET/AF_INET6 in crate libc` | `pub const AF_INET: u8 = libc::AF_INET as u8` is ungated; these POSIX AF constants are not exported by `libc` on Windows. The consts feed the macOS utun 4-byte AF header framing — needs a Windows TUN driver path (`wintun`) or cfg-gating. |
| `crates/tcpinfo` | `src/lib.rs:14` | `E0433: cannot find unix in os` | `use std::os::unix::io::{AsRawFd, RawFd}` is Unix-only; Windows needs `std::os::windows::io::AsRawSocket` (or a cfg-gated import). |
| `crates/tcpinfo` | `src/lib.rs:19` | `E0599: no method named as_raw_fd found for &TcpStream` | `as_raw_fd` is Unix-only; on Windows use `as_raw_socket`. The `rtt()` entrypoint calls `rtt_impl(stream.as_raw_fd())` ungated. |

### Dead-code warnings (become errors under `-D warnings`)

These helper functions are only called from `#[cfg(target_os = "macos")]` /
`#[cfg(target_os = "linux")]` code paths, so on Windows they are unreferenced.
Under `cargo clippy -- -D warnings` (run by the linux/macOS clippy steps, not
the Windows check step) they would be errors. Fix by cfg-gating the function
definitions to `#[cfg(any(target_os = "macos", target_os = "linux"))]` or
adding `#[allow(dead_code)]` in a future Windows-port phase.

| Crate | Location | Symbol |
| --- | --- | --- |
| `crates/netmon` | `src/state.rs:637` | `find_self_ip_on_interface` |
| `crates/netns` | `src/lib.rs:107` | `is_cgnat_v4` |
| `crates/netns` | `src/lib.rs:112` | `is_tailscale_ula` |
| `crates/portmapper` | `src/gateway.rs:104` | `ip_for_interface` |
| `crates/portmapper` | `src/gateway.rs:128` | `is_link_local` |

### Notes for the future Windows-port phase

- `crates/tun` needs a real Windows TUN backend (wintun.dll) plus cfg-gated AF
  constants; the current `create()` is already `#[cfg(any(macos, linux))]` but
  the `AF_INET`/`AF_INET6`/`strip_af_header`/`prepend_af_header` helpers are
  ungated.
- `crates/tcpinfo` `rtt()` and `break_tcp_conns()` need Windows stubs
  (`io::ErrorKind::Unsupported` / no-op `Ok(0)`); the macOS and Linux
  `rtt_impl`/`break_tcp_conns_impl` are already cfg-gated, only the top-level
  `use` and `rtt()` wrapper are not.
- `crates/netns` already has an `other` fallback module; the dead-code warnings
  are purely from ungated helper predicates.
- After fixing the above, drop `continue-on-error: true` from the two Windows
  legs in `ci.yml` and remove this section's "not started" status.
