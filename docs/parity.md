# rustscale ↔ tailscale parity tracker

Tiered gap analysis against the Go implementation.
Status legend: ✅ done · 🔶 partial · 🚧 in progress · ⬜ not started.
Update statuses when implementation and tests land together.

## Verified gap audit (2026-07-12, re-verified 2026-07-13)

Statuses below were checked against the source and tests in `crates/*` as of
2026-07-13.

## Tier 1: Core compatibility (missing = incomplete client)

| Feature | Go source | Status |
| --- | --- | --- |
| MagicDNS + split DNS resolver | `net/dns/resolver/tsdns.go`, `net/dns/manager.go` | 🔶 local A/AAAA/PTR, ExtraRecords, `.onion` NXDOMAIN, 4via6, DoH, and supervised same-port UDP/TCP serving; forwarding applies atomically reconfigurable longest-suffix `DNSConfig.Routes`, authoritative empty routes, resolver failover/default fallback, transaction-ID checks, UDP TC preservation, TCP retry/framing, the upstream 4096-byte inbound cap, cancellation, and restart/rebind. Hermetic vectors are derived from pinned `tailscale.com@v1.100.0`; the remaining partial status is the intentionally narrow local wire-record surface rather than suffix/TCP transport behavior |
| Let's Encrypt certs via control | `ipn/ipnlocal/cert.go` | ✅ full ACME client (RFC 8555, ES256 JWS, dns-01 via set-dns, rcgen CSR); live LE-staging e2e; LocalAPI `GET /cert/<domain>`; `rustscale cert` CLI |
| WhoIs (peer identity from conn) | `tsnet.Server.WhoIs` | ✅ `Server::whois` + `ts_whois` FFI (UserProfiles from netmap); e2e + interop tests |
| Exit node support | LocalBackend/router/magicsock | ✅ set_exit_node/clear_exit_node, RouteTable catch-all, PATCH /prefs wiring, ExitNodeAllowLANAccess, TUN exit-node mode; unresolved requested exits retain a working peer or install capture/no-connect defaults before startup traffic; control/DERP/bootstrap/DNS/STUN/port-mapping underlay stays socket-scoped (no DNS/control destination route injection); LAN-deny captures every connected external prefix (including VPN/CGNAT/ULA) while LAN-allow uses Linux managed throw routes/direct Darwin connected routes; Darwin full-tunnel entry requires verified TCP/UDP IP_BOUND_IF capability and a verified com.apple/* PF emergency block (safe durable enable-token teardown, private owner-only rules file) around security-critical interface and kernel-route enumeration/refresh; map stream error/closure/watchdog also engages the same durable block; one ordered exit/map/link mutation gate prevents stale map or link snapshots from replacing newer API/config selections; provenance-latched map-loss/enumeration/transition blocks clear only after their owning recovery; every LAN-denied entry, refresh, exit removal, clear, or identity teardown verifies the kernel block before route/rule mutation, tracks attempted versus verified state, retains effective userspace blocking through API/config mutations and failed inverses, invalidates verification before unblock, and immediately re-establishes and verifies the block after any uncertain removal while retaining exit/underlay ownership through a successful retry; preference, pending-map, blocked-state, and router changes roll back transactionally |
| Network monitor (netmon) | `net/netmon/` | ✅ AF_ROUTE (macOS), NETLINK_ROUTE (Linux, real-time), polling fallback; State/ChangeDelta, major/minor change detection, wall-time jump; enumeration failures are emitted as explicit deltas; callback tasks, map producers, LocalAPI acceptors, and every per-connection route handler are owned, cancelled, and joined by async shutdown before route teardown; wired into magicsock link_changed |
| Port mapping (NAT-PMP/PCP/UPnP) | `net/portmapper/` | ✅ Client facade (probe/create/renew/cache), PMP/PCP byte-exact packet codec with RFC test vectors, UPnP SSDP+SOAP, fake IGD tests, magicsock portmap endpoint publishing |
| Health tracking | `health/` | ✅ Tracker+Watchdog complete, 20/20 Go warnables registered (WARN_CONTROL, DERP_HOME, CERT_FALLBACK, NETMON_CHANGE, CAPTIVE_PORTAL, PRODUCTIVITY, UDP, IPV4, IPV6, DERP_NO_REGION, IDLE, LOGIN, NOT_IN_MAP_POLL, MAP_RESPONSE_TIMEOUT, NO_DERP_CONNECTION, DERP_TIMEOUT, DERP_REGION_ERROR, TLS_CONNECTION_FAILED, TLS_CERT_PENDING, SUBSYSTEM_PREFIX), per-region DERP health tracking wired; control/DERP/certs/netmon integration plus a high-severity exit-route security warning, C2N/FFI endpoints; ARG_* key constants for dynamic text; WARN_NOT_IN_MAP_POLL + WARN_MAP_RESPONSE_TIMEOUT wired in map_update, WARN_NO_DERP_CONNECTION + WARN_DERP_REGION_ERROR wired in magicsock derp, WARN_DERP_TIMEOUT wired in staleness check |
| IPN state machine + notify bus | `ipn/backend.go`, `ipn/ipnlocal/local.go` | ✅ State enum (7 states wire-compatible), Notify with 16 Go fields incl. NetMap/PeersChanged/PeersRemoved/PeerChangedPatch/Health/ClientVersion/SuggestedExitNode/UserProfiles, NotifyBus broadcast channel (128-cap), IpnBackend with blocked/logged_out setters, state machine transition table with tests; LocalAPI GET /watch-ipn-bus |
| Interactive auth + prefs persistence | `ipn/prefs.go`, `cmd/tailscale/cli/up.go`, `ipn/localapi/localapi.go` | ✅ Prefs (16 fields + MaskedPrefs), prefs.json atomic persistence, start_localapi_only() NeedsLogin mode, bootstrap() full auth flow (register→AuthURL→wait→map), LocalAPI /start/login-interactive/logout/PATCH/GET prefs, CLI up/login/logout/down/set/get, daemon no longer requires TS_AUTHKEY |

## Tier 2: Production features

| Feature | Go source | Status |
| --- | --- | --- |
| Serve/Funnel (ListenFunnel, ServeConfig, TCP fwd, reverse proxy) | `tsnet`, `ipn/serve*` | ✅ ServeConfig serde + ETag + persistence; TCP/HTTP/HTTPS dispatch; reverse proxy with WhoIs headers (Tailscale-User-Login/Name); TLS-terminate via ControlCertProvider; HTTP-to-HTTPS redirect; HTTPHandler.Redirect with `${HOST}`/`${REQUEST_URI}` expansion; Ingress-Target header dispatch; listen_funnel port validation (443/8443/10000); LocalAPI GET/POST serve-config; CLI serve/funnel with status/reset |
| Tailscale Services (ListenService, PROXY protocol) | `tsnet.Server.ListenService` | ✅ listen_service(svc_name, ServiceMode) with VIP v4 addrs from CapMap (ServiceIPMappings); PROXY protocol v2 binary header encoder (byte-exact IPv4/IPv6/LOCAL); ServiceStream wrapping (Plain/WithProxy/Tls/TlsWithProxy); IPv6 VIPs skipped (smoltcp proto-ipv4 only); TLS termination for service FQDN via ControlCertProvider (HTTPS mode with cert fallback to self-signed); serve-config Services TCP forwarding path (TCPForward/TerminateTLS on service VIPs via ServeRunner) |
| SOCKS5 proxy | `net/socks5/` | ✅ RFC 1928 CONNECT (v4/domain/v6); RFC 1929 username/password auth; pluggable SocksDialer; FFI; e2e tests |
| LocalAPI | `ipn/localapi/` | ✅ 18+ endpoints (status, whois, prefs GET+PATCH, netmap, metrics, health, ping (disco/icmp/tsmp/peerapi), watch-ipn-bus, start, login-interactive, logout, serve-config, profiles, cert, id-token (Noise control forwarding), Tailnet Lock status/init/sign/disable/force-local-disable, file-targets, bounded Taildrive runtime status/config GET+PUT, debug, dial, dns-query, check-ip-forwarding); dial is read-write/operator-only, globally/per-identity admitted and deadline/cancellation bounded, using netstack in userspace mode or the current generation's tailnet-routed tsdial UserDial in TUN mode; TUN proxying resolves once and admits only an epoch-checked `UserDialPlan` backed by a live peer, accepted subnet, or proven selected-exit route; local-interface and directly preserved LAN targets are rejected, and the exact socket is protected to the managed TUN before asynchronous connect |
| Auto-update / ClientVersion | — | 🔶 control-plane ClientVersion notifications and status are wired; `crates/clientupdate` provides fail-closed manual GitHub release selection, bounded archive parsing, receipt-gated binary replacement, and journaled rollback. Homebrew is planning-only and unattended `auto_apply` remains intentionally unsupported. |
| Multi-profile/login management | `ipn/ipnlocal/profiles.go` | ✅ ProfileManager with profiles.json + current-profile persistence; LocalAPI CRUD endpoints; CLI switch command; backend teardown+restart on switch (`Server::switch_profile` → close + reload prefs + `up()`, `DaemonCommand::SwitchProfile` wired through daemon loop); durable node/TKA identity, authority Chonk, and netmap caches are isolated by ProfileID plus control identity and reject tailnet-identity changes; remaining: Windows LocalUserID |

## macOS platform parity (phases 32–40, 2026-07-11)

| Feature | Go source | Status |
| --- | --- | --- |
| macOS DNS OS configurator | `net/dns/manager_darwin.go` | ✅ DarwinConfigurator (`/etc/resolver/$SUFFIX`, ownership header, stale cleanup, foreign files untouched); wired into TUN mode, with pinned control-route-to-match-file and reconfiguration vectors |
| Safe socket (CLI↔daemon IPC) | `safesocket/safesocket_darwin.go` | ✅ unix listen/connect (stale removal, 0o666 perms); darwin sameuserproof (macsys file variant, lsof variant, set_credentials override, token gen) |
| Route table enumeration | `net/routetable/routetable_bsd.go` | ✅ NET_RT_DUMP2 sysctl RIB fetch, rt_msghdr2 + sockaddr parse, RTF flag decode, RTF_LOCAL skip, live default-route integration test |
| tcpinfo (RTT diagnostics) | `net/tcpinfo/tcpinfo_darwin.go` | ✅ darwin TCP_CONNECTION_INFO (tcpi_rttcur) + linux TCP_INFO (tcpi_rtt) |
| Break TCP connections | `ipn/ipnlocal/breaktcp_darwin.go` | ✅ fd 0..1000 scan+close (macOS); called on set/clear_exit_node in TUN mode only |
| Daemon + launchd install | `cmd/tailscaled/install_darwin.go` | ✅ rustscaled bin (run/install/uninstall), com.rustscale.rustscaled plist, launchctl lifecycle, safesocket LocalAPI; needs-login startup mode when no TS_AUTHKEY |
| Default route detection | `net/netmon/defaultroute_darwin.go` | ✅ RTM_GET sysctl + SIOCGIFDELEGATE utun delegation; route -n get fallback |
| Interface enumeration (darwin) | `net/netmon/interfaces_darwin.go` | ✅ getifaddrs + sockaddr_dl for MAC, ifa_data for MTU, IFF flags |

P3 status: hostinfo darwin ✅ (OSVersion + DeviceModel via sysctl) · quarantine xattr
✅ (com.apple.quarantine value) · peermtu darwin (no-op in Go too) ⬜ · sockstats ✅
(`crates/sockstats`: Label taxonomy, SockStats/LabelHandle atomics, CountedStream;
magicsock UDP4/UDP6 tx/rx instrumented; C2N /sockstats + PeerAPI /v0/sockstats emit
real JSON).

## Tier 2.5: Client infrastructure (Go packages not previously tracked)

| Package | Go source | Rust status |
| --- | --- | --- |
| Tailscale IP addr helpers | `net/tsaddr/` | ✅ `crates/tsaddr`: CGNAT/ULA/4via6/4to6/ephemeral ranges, service VIPs, `is_tailscale_ip`, `map_via`/`unmap_via`, exit-route helpers; all call sites migrated |
| Outbound dial abstraction | `net/tsdial/` | ✅ `crates/tsdial`: `Dialer` with SystemDial/UserDial/PeerDial paths, `DnsMap` MagicDNS resolution, `UserDialPlan`, netmon link-change callback stub, `ActiveConns` tracking; UserDial follows ordinary OS/TUN routes without infrastructure's physical-underlay bypass and its generation map is refreshed from complete authorization-filtered map snapshots; route-aware callers can classify one exact resolved address to avoid DNS TOCTOU, while LocalAPI submits it to an epoch-revalidating worker that creates a managed-TUN-bound socket; all direct product dial call sites use an explicit dial class |
| Localhost port proxy map | `net/proxymap/` | ✅ `crates/proxymap`: `Mapper` (register/unregister/whois_ipport with 0/10/20/50/100ms retry, reverse whois_by_ip); wired into `tsnet::Server` (RunningState.proxy_mapper, WhoIs fallback, register_proxy_identity/unregister_proxy_identity) |
| HTTP CONNECT proxy | `net/connectproxy/` | ✅ `crates/connectproxy`: `ConnectProxyConfig`, `parse_connect_request`, `handle_connect` with bidirectional tunnel |
| HTTP proxy env detection | `net/tshttpproxy/` | ✅ `crates/tshttpproxy`: `proxy_from_environment` + `http_connect` (HTTP/1.1 CONNECT tunnel w/ Proxy-Authorization); wired into controlhttp (`dial_control`, `fetch_server_pub_key`, `tls_connect`) and derp (`connect_insecure`, `connect_with_upgrade_dial_insecure` — downgrades upgrade→direct TLS over tunnel when proxied) |
| Embedded TLS roots fallback | `net/bakedroots/` | ✅ `crates/bakedroots`: ISRG Root X1+X2 PEMs and lazy `get()` store; tlsdial combines only native, caller-provided, and these baked roots, while the legacy `combined_root_store()` webpki bundle remains used by ACME and the DNS forwarder; `ServerBuilder::extra_root_certs` plumbing through `ControlClient` |
| OS-level route management | `wgengine/router/` | 🔶 `crates/router` provides normalized, deterministic, rollback-capable shell-backed `Router` implementations for macOS/Linux (including TUN routes, table-52 throw routes, connected-LAN override routes, and exit-node toggles); Linux policy rules use collision-detected per-interface priority slots plus a durable cross-process ownership registry, exclusive same-instance ownership, and exact mark/protocol/table cleanup selectors, preserving foreign same-priority rules; startup adopts a dead owner's exact base/protocol emergency rules for verified transactional cleanup while preserving foreign rules, and macOS similarly recovers only an owner-recorded exact rustscale anchor/rules/enable token using a durable active→release-pending→clear retirement state machine; transition/startup rollback aggregates inverse failures and retains exact dirty cleanup ownership for retry; close keeps the emergency block active until all route/rule cleanup succeeds; close/logout cleanup owners survive in a process-wide supervisor and block restart until cleanup succeeds; duplicate foreign routes fail without being claimed or deleted. Phase 2: native PF_ROUTE/netlink. |
| LocalAPI authorization | `ipn/ipnauth/` | ✅ `safesocket::peercred::ConnIdentity` (SO_PEERCRED/LOCAL_PEERCRED/getpeereid), `is_readwrite()` uid check, enforced at all mutating LocalAPI endpoints (403 on mismatch) |
| IPN audit logging | `ipn/auditlog/` | ✅ `crates/auditlog`: profile-scoped persistent queue, EventID deduplication, retry/backoff and final flush; Noise `/machine/audit-log` transport plus LocalAPI disconnect/logout wiring |
| Service policy | `ipn/policy/` | ✅ Go's package is a single `IsInterestingService` function — ported as `crates/portlist/src/policy.rs::is_interesting_service` (wired into portlist `to_services()`) |
| Config file format | `ipn/conffile/` | ✅ `crates/conffile` — `ConfigVAlpha` schema with `Load`/`ToPrefs`/`WantRunning`, `deny_unknown_fields`, version `"alpha0"` validation; `--config <path>` flag on rustscaled, `POST /localapi/v0/reload-config` endpoint, SIGHUP reload handler |
| IPN extension system | `ipn/ipnext/` | 🔶 `crates/ipnext`: deterministic registration, async startup rollback, reverse dependency-ordered shutdown, and state/profile notifications are wired into tsnet. Failed partial-init compensation has a private cleanup registry retried before active dependencies; it is excluded from active lookup and callback publication. LocalAPI generation handoff leaves the advertised endpoint untouched until final atomic publication and centrally fences every mutating route while allowing reads. Bootstrap/startup/pre-login rollback transfers to runtime-independent bounded owners; explicit close and logout also transfer their sole cleanup owner/resumable control-key-cache-prefs transaction to a process-lifetime supervisor before awaiting, so caller-runtime destruction cannot discard the exact retry phase. Explicit close remains retryable; `Server::drop` instead synchronously revokes network/publication authority and uses a bounded global deadline. Publication drain is nonblocking and extension shutdown callbacks run on detached runtime owners, so a blocked callback cannot pin caller-runtime destruction; non-cooperative callbacks or router cleanup are logged as intentional revoked leaks at the terminal bound. Control/netmap/filter/router and direct LocalAPI extension hooks remain deferred. |
| Cloud log shipping | `logtail/` | ✅ `crates/logtail` — async upload loop (background tokio task), HTTP POST to `{base_url}/c/{collection}/{private_id}`, zstd compression (>256B, >64B savings), Retry-After/30–60s backoff, RFC3339Nano `client_time`, buffer cap + drop_count, upload metrics |
| Port enumeration | `portlist/` | ✅ `crates/portlist`: `Poller` (same-count shortcut, 1s Linux / 5s macOS), Linux `/proc/net/{tcp,tcp6,udp,udp6}` hex parser + `/proc/*/fd` PID resolution, macOS `netstat -na` + `lsof -F` parser with sandbox-failure cache, `to_services()` with is_interesting_service policy; wired into tsnet via HostinfoHook + background poller task |
| Network flow logging | `wgengine/netlog/` | ✅ `crates/netlogtype` wire types plus `crates/netlog` aggregation/logtail upload; virtual traffic is counted by the filter and physical direct UDP, peer-relay, and DERP traffic is counted by an optional nonblocking magicsock hook with batch-aware tests |
| Network error classification | `net/neterror/` | ✅ `rustscale-neterror` crate with `treat_as_lost_udp`, `packet_was_truncated`, `should_disable_udp_gso`, `is_closed_pipe_error`; wired into magicsock (send/disco paths), portmapper (PMP/PCP mapping sends), dns forwarder (UDP recv) |
| Network traffic steering | `net/traffic/` | ✅ `crates/traffic`: location-priority scoring, memoization, and Go-vector-compatible FNV-1a rendezvous ordering; `tailcfg::Location.Priority` is wired into the model |
| Subnet route health check | `net/routecheck/` | 🔶 `crates/routecheck` groups HA routers by canonical prefix, excludes self and peer-owned address routes, applies traffic-score/rendezvous ordering, selects a compatible Tailscale address (IPv4 preferred), assumes WireGuard-only peers reachable, and performs injectable unprivileged disco probes with bounded concurrency, per-peer deadlines, cancellation, deterministic reports, and hermetic tests. The tsnet LocalAPI exposes `POST /localapi/v0/routecheck` using live peers and cancellation-safe magicsock probes; active `probe=true` requests require read-write authorization, share a server-wide single-report gate, clamp peer timeouts, cancel on disconnect, and have a 60-second whole-report deadline. Deferred: upstream's future background/incremental probe cache and using reports to alter live route choice; no OS/platform reachability claims. |
| Captive portal detection | `net/captivedetection/` | ✅ `Detector` concurrent HTTP GETs, DERPMap endpoints, response validation (status + challenge + body), wired into netcheck prober + health Tracker |
| ICMP ping | `net/ping/` | ✅ `crates/netcheck/src/icmp.rs` — public `Pinger` (unprivileged DGRAM+ICMP → raw fallback); CLI `ping --icmp` uses it; disco/tsmp/peerapi dispatch via LocalAPI |
| Socket statistics | `net/sockstats/` | ✅ `crates/sockstats`: per-label TX/RX byte counters (Label enum, SockStats registry, LabelHandle atomics, CountedStream); magicsock UDP4/UDP6 instrumented; C2N /sockstats + PeerAPI /v0/sockstats emit real JSON |
| In-memory test net | `net/memnet/` | ✅ `crates/memnet`: deterministic bounded FIFO connection pairs, TCP/logical address reporting, rendezvous listener dial/accept with cancellation, close wakeups and drain-before-EOF, cross-endpoint block injection, cancellation-safe per-waiter read/write deadlines, concurrent listener registry, deterministic port-0 allocation/reuse, and listener-lifetime tests. Rust `AsyncWrite::shutdown` intentionally provides idiomatic half-close; Go's custom listener connection factory hook is not exposed because no current caller uses it. |
| Event bus | `util/eventbus/` | ✅ `crates/ipn/src/bus.rs`: NotifyBus backed by tokio::sync::broadcast (128-cap), NotifyBusReceiver for async streaming |
| Client metrics | `util/clientmetric/` | ✅ `crates/clientmetric`: Registry with Counter/Gauge (atomic-backed), to_prometheus_text() + to_json(); wired into LocalAPI /metrics |
| Deep hash / change detection | `util/deephash/` | ✅ typed structural SHA-256 hashing with process-local seeding/type framing; primitive, float/raw-bit, string/byte, option, ordered-sequence, unordered map/set, smart-pointer, network, IPN, and active tailcfg types; maps/sets are iteration-order independent and pointers hash pointees, not addresses. Unsupported types fail at compile time; cyclic graphs require a custom `DeepHash` implementation that bounds or detects recursion rather than Go-style reflection. Used for existing filter, portmapper gateway, and app-connector route change detection. |
| Singleflight | `util/singleflight/` | 🔶 inline in `crates/dnscache` (inflight dedup HashMap); no standalone crate |
| LRU cache | `util/lru/` | ✅ standalone O(1) HashMap + index-linked-list implementation in `crates/flowtrack` (used by filter flow tracking) |
| Rate limiter | `util/limiter/` | 🔶 inline in `crates/derp/src/client.rs` (token-bucket for DERP send path); no standalone crate |
| Ring buffer logger | `util/ringlog/` | ✅ `crates/ringlog`: `RingLog<T>` generic fixed-capacity ring buffer (Mutex<VecDeque<T>>), `add`/`get_all`/`len`/`clear`, nil-safe via `Option`; full Go test suite ported |
| QR code rendering | `util/qrcodes/` | ✅ qrcode crate + hand-rolled 1-bit PNG encoder; `up --qr` / `login --qr` terminal half-block QR + data:image/png data URL |
| Dependency injection / tsd | `tsd/` | ✅ `crates/tsd`: concurrent typed and named set-once dependency container with snapshots and duplicate/type-safety tests |
| Feature gate system | `feature/` | ✅ `crates/feature`: deterministic thread-safe feature registration, comparable unavailable error, single-assignment `Hook`, ordered multi-party `Hooks`, and race-safe scoped test overrides |
| Safe atomic file writes | `atomicfile/` | ✅ `crates/atomicfile`: write-temp+fsync+rename utility with perms 0o600 |
| Metrics registry | `metrics/` | ✅ via `crates/clientmetric`: Registry with Counter/Gauge, Prometheus text format, wired into LocalAPI /metrics replacing 4 hardcoded metrics |
| File path constants | `paths/` | ✅ `crates/paths`: default_state_dir/log_dir/config_dir/socket_path per platform (macOS/Linux/Windows) |
| Status/PeerStatus model | `ipn/ipnstate/` | ✅ `crates/ipnstate`: Status, PeerStatus, StatusBuilder with Go-compatible merge logic; serde-serialized via StatusBuilder in LocalAPI /status; `Server::ipn_status()` returns the same barrier-consistent view; selected peers set `PeerStatus.ExitNode` and `ExitNodeStatus.ID` is the rotation-stable `StableNodeID`; legacy `ServerStatus`/`PeerInfo` kept for FFI/bench compat |
| State persistence abstraction | `ipn/store/` | ✅ `crates/ipn/src/store.rs`: Store trait + MemStore (HashMap) + FileStore (one file per key) |
| IPN server actor loop | `ipn/ipnserver/` | ⬜ orchestration embedded in tsnet Server + lifecycle.rs; no dedicated actor loop |
| TSP protocol (alt control) | `control/tsp/` | 🔶 additive `rustscale-tsp` client: reusable closeable Noise/H2 transport, key discovery/configuration, node files, registration, zstd map streaming/updates with strict limits, same-session C2N echo callbacks, and testcontrol integration; not wired into tsnet |
| Log policy / logtail setup | `logpolicy/` | ✅ `crates/logpolicy`: Go-compatible persisted `rustscaled.log.conf`, state-dir `logid-private` reuse, `TS_LOGS_DIR`/`TS_LOG_TARGET`, and daemon startup/shutdown wiring |
| Packet parsing (headers) | `net/packet/` | ✅ `crates/packet`: IPv4Header, IPv6Header, ICMPHeader, UDPHeader, TCPFlag, Parsed rich decoded view, parse_packet(); GENEVE in udprelay |
| DNS name utilities | `util/dnsname/` | ✅ `crates/dnsname`: `Fqdn` type (always-dot-terminated), `to_fqdn`/`valid_label`/`valid_hostname`/`sanitize_label`/`sanitize_hostname`/`has_suffix`/`trim_suffix`/`trim_common_suffixes`/`first_label`/`num_labels`/`contains`/`parent`; full Go table tests ported; adopted by `tailcfg::service::validate_dns_label`, `dns::peer_matches`, and `tsnet` first-label call sites |
| TLS dial config | `net/tlsdial/` | ✅ `crates/tlsdial`: native+extra+baked-ISRG trust policy, ALPN, SNI/expected-name and exact-leaf pin verification, handshake deadlines, error classification, and clock-skew/block-blame diagnostics adopted by control HTTP and DERP; ACME remains protocol-specific |
| Network utility functions | `net/netutil/` | 🔶 proxy protocol detection in service.rs; interface helpers in netmon/netns; no consolidated crate |
| Socket options | `net/sockopts/` | ✅ SO_MARK + SO_BINDTODEVICE in `crates/netns/src/linux.rs` |
| TCP connection table | `net/netstat/` | ✅ `crates/netstat` provides hard-deadline/cancellable, globally worker-capped read-only TCP snapshots with normalized endpoints/states. Linux strictly parses `/proc/net/tcp{,6}` using native-endian 32-bit lanes, tolerates only `NotFound` family absence, and performs bounded best-effort inode/PID association only across matching pre/post process start times. macOS invokes wide numeric `netstat` and rejects truncated or ambiguous IPv6 instead of repairing it. Windows invokes only the fixed `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` path and uses an embedded reflection-only P/Invoke wrapper around fixed `C:\Windows\System32\iphlpapi.dll` with a cleared child environment, only fixed `SystemRoot`/`WINDIR`, and a fixed system32 working directory (no inherited `PATH`, module lookup, CLR/COMPlus/DOTNET profiler or startup hooks, profile, `Add-Type`, compiler, or cache); Windows PowerShell 5.1 is required, and nonstandard Windows roots or missing runtimes fail closed. IPv4 and IPv6 are queried separately and each must emit its own success footer before a strict byte/line/token/row-bounded invariant numeric snapshot is accepted, so every native family error, omission, parse failure, or truncation is fatal. Readers/decoders are injectable on every platform. PID metadata remains diagnostic-only, including race-prone Windows owner PIDs, and the crate is intentionally not wired into connection breaking: table rows do not safely identify an owned file descriptor, and enumeration never opens, closes, duplicates, or otherwise modifies socket targets. |
| TCP keepalive timeout | `net/ktimeout/` | ✅ `crates/ktimeout` applies Linux `TCP_USER_TIMEOUT=15s` to each accepted in-process DERP server connection (no-op on other platforms) |
| Speedtest protocol | `net/speedtest/` | ✅ `crates/speedtest`: v2 newline-JSON control messages and raw 2 MiB data blocks, upload/download direction reversal, 1s interval plus total measurement semantics, decimal throughput helpers; strict 5–30s/control-frame/result/concurrency bounds, monotonic deadlines, cancellation, partial-I/O and malformed/truncated-peer handling; hermetic duplex/wire-vector tests plus bounded-server admission/isolation/drain coverage. `tools/speedtest-interop.sh` adds deadline/output/process-bounded loopback Go↔Rust upload/download evidence by calling the exported `Serve`/`RunClient` APIs from checksum-verified, replacement-free `tailscale.com@v1.100.0`, including fragmented I/O, malformed/truncated control, and cancellation. This is live pinned-module process interop, not a deployed-node or network-path claim. `rustscale speedtest` provides client and bounded server modes. |
| Desktop integration | `ipn/desktop/` | ✅ `crates/tsnet/src/hostinfo.rs`: reads `/proc/net/unix` for .X11-unix / wayland-1 socket detection |
| Alternative routing table | `net/art/` | ✅ `crates/art`: safe 8-bit-stride ART with normalized exact insert/replace/delete, allocation-free IPv4/IPv6 LPM, deterministic canonical iteration, independent clones/snapshots, delete compaction, and peak-live-route-bounded value storage; `tsnet::RouteTable` uses normalized ART entries, deduplicates equal prefixes across lookup/diagnostic/OS views while keeping the first owner, admits only host routes when route acceptance is off, and activates dual-stack defaults exclusively through explicit exit-node selection |
| BIRD routing client | `chirp/` | ✅ `crates/chirp`: async BIRD control-socket client with response framing, protocol enable/disable, validated IPv4/IPv6 route updates, reconnects, deadlines, and hermetic partial-I/O/error tests |
| Cloud env detection | `util/cloudenv/` | ✅ `crates/tsnet/src/hostinfo.rs`: reads DMI sysfs for AWS/GCP/DigitalOcean; Azure detection constant defined but not wired |

## Tier 3: Specialized

| Feature | Status |
| --- | --- |
| Tailscale SSH (`ssh/tailssh/`, port-10) | ✅ policy engine (Any/Node/NodeIP/UserLogin; only an unambiguous terminal `Accept` succeeds; Reject/malformed actions reject and unsupported HoldAndDelegate fails closed), policy-mapped local-account launch and recorder identity, `SessionDuration`, and live policy-revocation checks. PTY descriptors are RAII-owned across rejection/dup/launch paths. Shells use dedicated process groups; recorder/client/deadline/revocation failure closes pumps and stdin and performs bounded TERM→KILL with disappearance/reap verification, while normal exit drains PTY/stdout/stderr and the recorder before terminating and verifying any surviving descendants and closing the channel. Blocking NSS and launch work runs behind a capped `spawn_blocking` supervisor with cancellation/deadline/policy races; a post-fork process-group handoff plus runtime-independent RAII supervisor gives blocked, returned, or aborted child launches one transferable TERM→KILL/reap owner. SSH connection handlers isolate bounded per-channel data/EOF/signal/window/recording state for multiplexed sessions; pre-start data is globally/per-channel bounded and delivered in order, saturated stdin closes only the offending channel without blocking callbacks, SSH EOF drains and half-closes child input without cancellation, and environment requests have count/key/value/aggregate limits with validated replacement semantics. Prelaunch errors and unfinished-session drops send failure status and close through an owned runtime-independent channel supervisor while removing channel state; PTY half-close sends canonical VEOF sequencing so unterminated input can drain. Mandatory final upload errors/timeouts or server success/ACK EOF before queued-frame drain force a non-successful session; recorder connection and header/enqueue initialization follow fail-open/fail-closed policy without exposing partial recorders. Remote recording uses authenticated tailnet dials, HTTP/1.1 `/record` + h2c `/v2/record`, acknowledgement liveness, bounded buffering, and identical fail-open/fail-closed handling for stdout and non-PTY stderr; deprecated local `.cast` recording requires `TS_DEBUG_LOG_SSH` and is deliberately fail-closed when its path/file cannot be created. Recording start/upload failures emit the upstream `NotifyURL` event classes exactly once through the current generation-bound map Noise/H2 session without delaying session termination; parsed URL authorities are discarded and only normalized path/query values can reach that fixed transport. Per-profile/per-principal fair admission, reserved bounded capacity, globally capped generation workers with atomic tombstoned round-robin grants, separate queue TTL/dispatch deadlines, strict payload/response/redirect limits, single-attempt ambiguous-failure handling, receive-boundary expired-key latching before map/TKA buffering, explicit authenticated-replacement installation, synchronous profile/logout/close latching of the actual active generation key, truthful drop counters, and redacted diagnostics prevent SSRF, duplicate commit retries, and stale-generation delivery. Remaining: delegated HoldAndDelegate fetch, SFTP |
| Taildrop (`feature/taildrop/`) | ✅ TaildropManager with spool directory, conflict modes (skip/overwrite/rename), file-targets enumeration from netmap, PeerAPI PUT /v0/put/<filename>, LocalAPI files/file-targets/file-put/await-waiting-files, CLI file cp/get |
| Taildrive (`drive/`) | 🔶 additive secure server layer: validated share model, capability-confined no-symlink paths, atomic disabled-by-default runtime config, signed self `drive:share` gating, packet-filter grants bound to transport-authenticated WireGuard identity, linearizable map/config revocation, pre-body authorization and bounded admission, chunk-streamed PUT, and bounded `/v0/drive` WebDAV level 1. Unix PUT/COPY/DELETE/MOVE use atomic staging/exchange with FD-pinned inspection, exact restoration or owner-only quarantine, and never unlink special objects; unsupported platforms fail closed. LocalAPI status/config and CLI status/list/share/unshare are implemented; mutation requires a trusted kernel root/daemon UID or owning in-process client, never a loopback credential. Platform mounts, remote composition, persistence, UI, user switching, bookmarks, locks and range reads remain deferred. See `docs/taildrive.md`. |
| Tailnet Lock / TKA (`tka/`) | 🔶 `crates/tka` provides canonical CBOR wire/hash types, direct/rotation/wrapped-credential verification, disablement checks, bounded authority/bootstrap/inform/fork resolution, signed update builders, and file-backed Chonk storage with crash-recovered batch rollback. `tsnet` performs authenticated, deadline/body/count-bounded same-session Noise bootstrap and two-way `/machine/tka/sync/*`, persists verified authority changes in owner-only profile/control namespaces, handles control disablement proofs, sends its TKA head, and intersects stable-ID-reconciled full/delta/patch netmaps with signature authorization fail-closed (including rotation obsolescence). A serialized TKA operation spans each control decision/apply through notifications, router/resolver state, and the final tsdial publication; head/control transitions and LocalAPI init/resume immediately withdraw PeerAPI/Taildrive provenance, tunnels, routes, resolver/tsdial names, magicsock and generation-stamped direct/DERP/relay ciphertext authorization before authority commit or synchronization can await the control plane. Authorized init/resume and force-local-disable run as lifecycle-retained flights, so LocalAPI EOF, handler cancellation, close, or logout cannot abandon partial withdrawal/commit; cancellation retains the same JoinHandle and shutdown retries join it to observed completion before router teardown. Force-local-disable is the explicit node-local recovery escape hatch: it atomically persists the verified authority state ID in a bounded profile/control-scoped denylist before draining traffic and retiring Chonk, reports committed-but-incomplete cleanup for idempotent retry, and after restart ignores a restored denylisted authority. It publishes an unfiltered local generation only after a fresh authenticated bootstrap validates a genesis with that exact state ID; malformed or unconfirmed authority data remains withdrawn, while a changed state ID is treated as a new locked authority and must fully synchronize. This intentionally does not disable Tailnet Lock for other nodes. Stale disabled maps cannot bypass revocation, only a fresh validated decision can atomically republish peers, and revoked ciphertext is rejected before enqueue or at the delivery barrier. `UnsignedPeerAPIOnly` nodes are always conservatively dropped, including while local-disable is active, because restricted PeerAPI-only data-plane plumbing is deferred. Read-write-authorized LocalAPI and CLI flows cover status, self-safe init/resume, receipt acknowledgement, node signing, disablement, and local-disable. Init durably receipts the original disablement secrets before control RPCs and reports ambiguous commit/drop outcomes without replacement generation; hermetic tests exercise session binding, commit-then-drop recovery, filtering, partial-update rejection, signing, profile-isolated state recovery, local-disable persistence/rollback/concurrency/restart, and disable. Wrapped pre-auth keys are decoded and stripped before registration, with their delegated credential used to sign the fresh node key byte-compatibly. Deferred: trusted-key add/remove CLI flows, affected-signature re-signing, changelog UI, full compaction, and retroactive revocation orchestration. This is not full Tailnet Lock parity. |
| Device posture (`posture/`) | 🔶 production identity slice: exact PascalCase/null-tolerant C2N response, bounded Linux/macOS/Windows serial and non-loopback MAC collection (with Unicode WMI queries for the SMBIOS-backed Windows BIOS, baseboard, and enclosure serial classes, supervised by a globally capped blocking-worker pool), last-known MAC stability, and bounded live `PolicyEngine` snapshots for `always`/`never`/`user-decides` from Linux policy JSON, macOS `defaults`, and Windows machine-policy Registry providers. Provider failures and platforms without a provider fail closed. Posture prefs persist prospectively before serialized publication through one shared prefs state used by socket, loopback, and in-memory LocalAPI clients. Sensitive C2N has no production loopback listener (the legacy TCP harness is private and test-only): it runs only on the authenticated map Noise/H2 session, after map delivery, with strict HTTP limits/deadlines, four-request session concurrency, and disconnect cancellation. Hardware addresses are reported only for `hwaddrs=true`; serial collection remains unsupported outside Linux, macOS, and Windows. Windows reports upstream-equivalent SMBIOS system, baseboard, and chassis serials in class order; cancellation and deadline expiry return promptly while noncooperative WMI workers retain globally bounded permits. C2N propagates same-session cancellation and binds each sensitive result to the live preference generation; immediately before H2 `send_data`, one shared policy/preference publication barrier receives effective `PolicyEngine` generations through atomic subscribe-with-current commit state and a transactional pre-commit hook that acquires the sensitive publication write barrier before every applied, degraded, or failed status install; snapshot/status installation and callback capture occur while that barrier is held, releases are panic-safe, callbacks run reentrantly only after release, and provider refresh failures synchronously commit a new fail-closed unavailable generation. Request/publication checks read that subscribed state without provider reloads, and H2 revalidates both generations/state plus requested hardware-address scope, so a late opt-out discards buffered response bytes before any serial or MAC enters H2. Arbitrary posture signals/attestation remain deferred. |
| App connector (`appc/`) | ✅ crates/appc: domain/wildcard matching, DNS response observation with CNAME resolution, dynamic route advertisement (RouteAdvertiser trait), Conn25 peer selection + split-DNS resolver map, RouteInfo persistence; tsnet wiring with TsnetRouteAdvertiser |
| NetNS socket binding (`net/netns/`) | ✅ `crates/netns`: dial_tcp/dial_tcp_addr with host resolution, SOCKS5 proxy fallback, localhost bypass; macOS TCP/UDP IP_BOUND_IF fails closed on discovery/setsockopt errors and is capability-probed before full-tunnel routes; Linux SO_MARK + SO_BINDTODEVICE |
| Session recording (`sessionrecording/`) | ✅ byte-compatible asciicast v2 headers/events; policy-provided `AddrPort` recorders restricted to current authenticated netmap peers; ordered pre-stream failover; exact legacy chunked HTTP/1.1 and h2c V2 acknowledgement streams; bounded queue/frame/parser limits, dial/ack/drain deadlines, cancellation, and no mid-stream replay. Local files use mode 0600 under mode-0700 `<state_dir>/ssh-sessions/` only when `TS_DEBUG_LOG_SSH` is enabled. |
| Workload identity federation (`feature/identityfederation/`) | 🔶 `crates/identityfederation`: workload JWT exchange, tagged one-use auth-key creation, validation, feature hooks, and tsnet startup integration; cloud-specific provider discovery and expanded CLI plumbing remain deferred |

## Tier 4: Optimization & tools

| Feature | Status |
| --- | --- |
| Peer MTU discovery (`magicsock/peermtu.go`) | ✅ Full PMTUD: `crates/magicsock/src/pmtud/` platform modules (Linux `IP_MTU_DISCOVER`/`IP_PMTUDISC_DO`, Darwin `IP_DONTFRAG`/`IPV6_DONTFRAG`, stubs for unsupported); `update_pmtud` orchestration (env override → control knob `peer-mtu-enable` → default false), DF socket option set/clear via `setsockopt`, `should_log_disco_tx_err` EMSGSIZE suppression for padded disco pings, `reset_endpoint_states` on PMTUD toggle; `WIRE_MTUS_TO_PROBE` burst in `send_disco_ping`, per-endpoint `peer_mtu` tracking, `reset_peer_mtu` on state reset; wired via `Magicsock::update_pmtud()` on `link_changed` and control-knob re-evaluation |
| GSO/GRO batching (`net/batching/`) | 🔶 Linux direct UDP uses bounded `sendmmsg`/`recvmmsg`, capability-probed GSO, strict GRO ancillary/segment validation, exact successful-prefix accounting, and permanent runtime fallback from GSO, unsupported mmsg syscalls, or malformed GRO to plain UDP paths. Capability version 141's live `never-gso-equal-tail` knob applies upstream's smaller sentinel-tail mitigation (with the same small-batch plain-send threshold). Because a standalone `0x07` datagram has no trustworthy sentinel provenance, receive paths deliver and physically account it normally; the WireGuard protocol parser harmlessly rejects mitigation tails. The receive fast path keeps bounded jumbo scratch; non-Linux and other upstream batching surfaces remain incomplete. |
| io_uring TUN+socket (Linux) | ⬜ |
| BPF disco filtering (`magicsock_linux.go`) | ⬜ |
| Flow tracking (`net/flowtrack/`) | ✅ `crates/flowtrack`: packed v4-mapped 5-tuples, Go-compatible legacy JSON adapter, and O(1) generic LRU; filter uses its 512-entry UDP/SCTP cache and preserves active state across filter reloads |
| sockstats | ✅ `crates/sockstats`: Label taxonomy (13 labels), SockStats registry (Arc<Mutex> + AtomicU64), LabelHandle (cheap clone, record_tx/rx), CountedStream wrapper; magicsock UDP4/UDP6 tx/rx instrumented at send/recv; C2N /sockstats + PeerAPI /v0/sockstats emit JSON `{stats, current_interface_cellular}`; manual instrumentation (no Go runtime socktrace) |
| tcpinfo | ✅ `crates/tcpinfo`: macOS TCP_CONNECTION_INFO + Linux TCP_INFO; break_tcp_conns() for macOS |
| ICMP ping (`net/ping/`) | ✅ `crates/netcheck/src/icmp.rs`: public `Pinger` (unprivileged DGRAM+IPPROTO_ICMP → SOCK_RAW fallback); integrated as netcheck fallback when STUN probes fail; CLI `ping --icmp` dispatches via LocalAPI to the same pinger |
| DNS cache + fallback (`net/dnscache/`, `net/dnsfallback/`) | ✅ `crates/dnscache` (TTL, singleflight-inline, UseLastGood stale fallback, happy-eyeballs dialer); `crates/dnsfallback` (bootstrap-dns over DERP IPs, static + cached DERP map); wired into controlclient dial |
| C2N debug endpoints | ✅ 10+ handlers (echo, prefs, netmap, health, metrics, dns, goroutines, component-logging, sockstats, logtail/flush); only /debug/pprof/* remains 501 |
| Netmap disk cache | ✅ profile/control/tailnet-bound versioned envelope (v3) with SHA-256 write dedup; startup always prefers a fresh one-shot map, normalizes its complete peer set, and uses only that materialized snapshot as an offline fallback. Offline admission additionally requires the enrolled self identity, non-expired assigned IP, exact cached authenticated control key, and immediate degraded-control health; cached Tailnet-Lock peers remain withdrawn until a fresh authority decision. Independently optional streaming deltas never replace the restart cache; pre-normalization versions, invalid structure, auth failure, key expiry, and logout clear it. Hermetic restart coverage verifies fresh-map preference, cache invalidation, and offline health. |
| Web client UI | ✅ `rustscale web` with embedded HTML/JS, /api/status/up/down/logout handlers, explicit loopback default with post-bind enforcement, per-run CSRF and Host/Origin validation, --readonly, --unsafe-any-addr |
| Control knobs (`control/controlknobs/`) | ✅ HashMap<String,String> behind RwLock, typed accessors (get_bool/float/string), change-detection merge, on_change callbacks |
| PeerAPI (`ipn/ipnlocal/peerapi.go`) | ✅ DoH /dns-query (GET + POST), /v0/* endpoints (goroutines, env, metrics, magicsock, dnsfwd, interfaces, sockstats), WhoIs auth, CRC32 port [32768, 65535], Taildrop PUT handler, capability-authorized bounded Taildrive `/v0/drive`, netstack + TUN spawners |
| Hostinfo | ✅ ~41 fields populated: platform/runtime fields plus persisted `BackendLogID` (derived from the same `logid-private` used for logtail auth), override-supplied `FrontendLogID`, `WoLMACs`, `StateEncrypted`, and SSH host keys when the SSH listener is enabled. Intentional skips: PushDeviceToken, TPM, Location, ShareeNode, PeerRelay |
| CapturePcap | ✅ `crates/tsnet/src/capture.rs`: byte-exact LINKTYPE_USER0 pcap sink (Go `feature/capture` format), fanout with slow-client drop, hooks in TUN pump (FromLocal/FromPeer) + netstack pump (SynthesizedToPeer/ToLocal); `Server::capture_pcap(file)`, LocalAPI POST /debug-capture stream, CLI `rustscale debug capture -o` |
| Logtail | ✅ `crates/logtail` upload loop (HTTP POST, zstd, backoff), `log` facade adapter with stderr mirroring/level gating, per-client disable switch, and live C2N flush; uploads are opt-in for tsnet and enabled by rustscaled — see Tier 2.5 row |
| Watchdog | ✅ tokio-based interval task, auto-fires warning if not feed() within interval, Drop-safe |
| Syspolicy | 🔶 `crates/syspolicy` provides typed well-known definitions, device/profile/user scope and explicit managed/platform/debug precedence with per-item origins, immutable transactional generation snapshots/callbacks, typed default/error conversion (including upstream fallback for malformed preference options while retaining item diagnostics), concurrent deterministic allowlisted provider merging, coalesced asynchronous notifications, bounded Unix JSON/environment providers, and transactional removal/test overrides. Opt-in owned polling watches JSON files and native providers with bounded intervals/output/parse size, debounce and one-event coalescing; it detects content and identity changes across replacement/deletion/recreation, joins on cancellation, and keeps failed observations pending under bounded exponential retry without publishing a stale generation. Managed JSON uses no-follow, nonblocking regular-file opens, root ownership/non-writable production trust on Unix, injectable test trust, and bounded deadline/cancellation-aware reads. Provider removal uses cached last-successful managed values and diagnostics instead of failing open, and panicking callbacks are isolated and counted without stopping reloads. Native mapping covers requested existing well-known types in the macsys effective-preference domain and Windows HKLM current/legacy machine-policy trees (including DWORD/QWORD booleans and registry string-list forms); Windows is managed precedence, while macOS remains lower platform precedence because `defaults` cannot prove a value is MDM-forced. `InstallUpdates` is enforced on persisted `AutoUpdate` and `Hostinfo.AllowsUpdate` (including managed denial over the remote-update env knob) at startup, every LocalAPI/config preference mutation, and live provider changes; startup uses a subscribe-first generation handshake. Deferred: native Windows per-user stores/Group Policy notifications, authoritative Apple forced-preference detection, and LocalAPI/CLI policy diagnostics. |
| BIRD routing (`chirp/`) | ✅ standalone `rustscale-chirp` client; integration into a routing deployment remains opt-in |
| In-process IP prefix set (`net/ipset`) | ✅ `crates/ipset` ports the actual cross-platform upstream package: `false_contains_ip_func` and `new_contains_ip_func` build immutable IPv4/IPv6 membership predicates with the same empty, one/two-host, host-map, small linear-prefix, and larger ART-backed strategy selection. Prefix host bits are normalized for membership and address families remain distinct. The API exposes no iteration or serialization order. All upstream vectors and deterministic randomized differential tests against linear prefix containment pass; no kernel `ipset` command management is included. |
| envknob | ✅ wired: `TS_NO_LOGS_NO_SUPPORT`, `TS_ALLOW_ADMIN_CONSOLE_REMOTE_UPDATE`, `TS_WAKE_MAC`, `TS_DEBUG_USE_DERP_HTTP`, `TS_DNS_FORWARD_SKIP_TCP_RETRY`, `TS_PANIC_IF_HIT_MAIN_CONTROL`; `TSNET_FORCE_LOGIN` is intentionally skipped because tsnet has no cached-Running-state auth bypass |
| Version package | ✅ build.rs git describe --tags --long --always --dirty → RUSTSCALE_VERSION_LONG; fallback CARGO_PKG_VERSION |
| Freedesktop/DBus | 🔶 `crates/freedesktop` provides conservative Linux desktop/session detection, Desktop Entry `Exec` quoting, bounded shell-free HTTP(S) URL opening (`xdg-open` with `gio` fallback), and session-bus-aware notifications through `notify-send`. It also has an additive, unwired library API for transactional management of narrowly generated `rustscale-*.service` systemd user units: strict names/argv, deterministic credential-free unit bytes, owner-only atomic no-symlink storage, bounded cancellable/reaped `systemctl --user` commands, strict status parsing, idempotence, and compensating rollback, with injectable transports and hermetic tests. `rustscale web` opens its loopback URL by default (`--browser=false` disables it) and gracefully remains headless. Deferred: CLI/daemon wiring of the user-unit API, direct DBus bindings, tray/GUI, and Linux multi-user desktop-session tracking. |
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
· tsnet embed API · C FFI (librustscale) + Python ctypes · benchmark harness
with distinct embedded Rust, pinned embedded Go tsnet, daemon-proxy, and TUN
cells; historical SOCKS5/Serve numbers are not embedded-tsnet claims.

## Current embedded performance evidence (2026-07-23)

The latest matched high-fanout receive comparison used the tracked RSB1
userspace-tsnet upload workload on one 8-core ARM Neoverse-V2 AWS host running
Ubuntu 24.04 and Linux 6.17. This is a same-host software-path comparison, not
cross-machine or external-NIC evidence. A fixed Rust client sent 1,280-byte
application payload chunks to either accepted RustScale, the current RustScale
tree, or the pinned `tailscale.com/tsnet` v1.100.0 comparator. The current tree
used neither detached-pipeline force nor disable controls, so it exercised the
corrected default path.

Each P500/P1000 cell contains three valid 20-second trials in serial balanced
randomized blocks, following a separate three-second P1 direct-path warmup.
Every trial established, handshook, completed, and retained exactly the
requested 500 or 1,000 streams; reported 20/20 one-second samples; had no low,
zero, or stalled interval; and passed descriptor, memory, process, and state
cleanup checks. No trial was replaced and no valid outlier was removed.

| Streams | Accepted RustScale | Current RustScale | Go tsnet v1.100.0 | Current vs accepted | Current vs Go | Current CV |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 500 | 3134.669 Mbps | 5270.876 Mbps | 4788.978 Mbps | +68.15% | +10.06% | 0.552% |
| 1000 | 2853.839 Mbps | 5222.082 Mbps | 4875.703 Mbps | +82.98% | +7.10% | 0.301% |

Raw P500 samples in accepted/current/Go order were
`[3054.216704, 3170.086912, 3179.703296]`,
`[5271.126528, 5241.629696, 5299.870720]`, and
`[4794.399232, 4775.576064, 4796.958720]` Mbps. P1000 samples were
`[2873.769984, 2849.022464, 2838.724608]`,
`[5204.455424, 5227.130880, 5234.658816]`, and
`[4859.879936, 4880.611328, 4886.617088]` Mbps.

| Streams | Accepted cores / mean RSS | Current cores / mean RSS | Go cores / mean RSS |
| ---: | ---: | ---: | ---: |
| 500 | 1.277 / 576.7 MiB | 1.825 / 591.1 MiB | 2.540 / 1214.6 MiB |
| 1000 | 1.753 / 1134.2 MiB | 1.923 / 1137.5 MiB | 2.520 / 1441.7 MiB |

The current artifact came from committed clean tree
`6258ee659c58c78a92e644163dd103f384364188` and was built with Rust 1.97.1;
the native comparator used Go 1.26.4 and exactly matched the tracked
`tools/bench/go-tsnet/` sources. The workload maps to `crates/bench`, the
current receive implementation to `crates/tsnet/src/netstack_pump.rs`, and the
standard maintained matrix analogue to `tools/bench/gcp/`.

A follow-up P10 stability A/B on the same host compared that accepted receive
path with one additional bounded `recvmmsg` burst of detachable-buffer
headroom. A fixed sampler-corrected Rust sender was used for both arms. The
order `control,candidate,candidate,control,candidate,control,control,candidate,control,candidate`
was frozen before execution; each arm ran five fresh-tailnet 20-second trials,
and every outcome counted without retry or replacement. All ten trials were
direct, established/handshook/completed exactly 10 streams, produced exactly
20 one-second samples, and had no low, zero, or stalled interval.

| P10 upload | Trial totals (Mbps) | Mean | Population CV | Clean trials |
| --- | --- | ---: | ---: | ---: |
| Accepted receive path | `5286.489, 5016.107, 5484.906, 5447.920, 5321.950` | 5311.474 Mbps | 3.113% | 5/5 |
| One-burst pool headroom | `5544.594, 5667.583, 5705.693, 5344.741, 5327.224` | 5517.967 Mbps | 2.862% | 5/5 |

The candidate improved mean throughput by 3.89%. Mean receiver pool-wait time
fell from 1.661 seconds to 0.287 seconds per trial (82.7%), while mean receiver
CPU changed from 1.547 to 1.598 cores. Maximum observed receiver RSS was
58,780 KiB for control and 59,200 KiB for the candidate. The implementation
adds 128 fixed 2 KiB buffers (256 KiB per magicsock receive pool), keeps the
pool bounded, and leaves the separate 256-packet WireGuard handoff-credit cap
unchanged. The candidate artifact was built from committed clean tree
`54a89a6b0841c0c664ebc96b6bc3df0af730ddeb` with Rust 1.97.1; its SHA-256 was
`c425fc949cce34af13431b0103c5de71a12bb4146a0c08a49af89a4781fccbbd`.
The control/sender artifact SHA-256 was
`d1d533e901f234ce9c77c2a436bdafd98c52381cbfb37aa29c90bc1bbe1a9adc`.
This A/B validates the headroom change relative to the accepted RustScale
path; it is not a contemporaneous native-Tailscale P10 comparison.

The subsequent canonical GCP run
`gcp-20260723-064751-19775b4c5b` used two matched `n1-standard-4` VMs in
`us-central1-a` and `us-central1-b`, clean source commit
`70a7e09d460e33664bc570db8e68b77f694309a0`, and the pinned native Go tsnet
comparator. Every cell retained a direct path, exactly three valid 10-second
RSB1 download trials at P1/P10/P100/P500/P1000, and 200/200 latency exchanges.
No valid outcome was retried or replaced.

| Direct cross-host download | P1 | P10 | P100 | P500 | P1000 |
| --- | ---: | ---: | ---: | ---: | ---: |
| RustScale embedded | 2349.4 | 2296.8 | 2337.0 | 2231.3 | 2180.3 Mbps |
| Native Go tsnet | 1128.3 | 1510.4 | 1435.6 | 1331.6 | 1129.4 Mbps |
| RustScale/native ratio | 2.082x | 1.521x | 1.628x | 1.676x | 1.931x |
| RustScale TUN | 1549.9 | 1407.6 | 1053.3 | 545.6 | 417.4 Mbps |
| tailscaled TUN | 2277.2 | 2452.0 | 2203.8 | 1619.0 | 1329.3 Mbps |
| RustScale/tailscaled TUN ratio | 68.1% | 57.4% | 47.8% | 33.7% | 31.4% |

RustScale embedded p50/p95/p99 latency was
1123.879/1229.095/1286.476 microseconds versus
1140.439/1249.780/1370.256 for native Go tsnet. RustScale embedded also used
less average userspace CPU on both endpoints, 63.2% less server average RSS,
and a 32.5% smaller binary. Its client peak RSS was 40.4% higher, however, and
its single worst latency exchange was 13.511 ms versus 1.762 ms native. TUN
latency, CPU, RSS, and binary footprint favored RustScale, but the throughput
ratios above make TUN the primary known performance gap. Full raw arrays,
resource timelines, product hashes, endpoint metadata, and strict cleanup
evidence are tracked in
[`docs/performance/gcp-20260723-064751-19775b4c5b`](performance/gcp-20260723-064751-19775b4c5b/).

Together, the same-host upload and cross-host download evidence closes and
exceeds the measured direct embedded throughput gap from P1 through P1000 and
the measured p50/p95/p99 latency gap. It does not close kernel-TUN throughput,
the embedded client peak-RSS/cold-tail observations, bidirectional traffic,
DERP, startup, idle-resource, or universal compatibility parity; those remain
required before the overall parity goal or merge gate is complete.

A subsequent exact same-binary TUN A/B at clean source
`ab1e85009afebc88fa97acc179954d9a4c6ffc07` separated final inbound TUN
writes from the task that services outbound TUN reads. The opt-in worker
improved P1/P10/P100/P500/P1000 throughput by
1.00%/5.29%/10.17%/42.03%/35.44%, confirming that the bidirectional scheduling
boundary is a material high-fanout constraint. It simultaneously regressed
p50/p95/p99 latency by 32.79%/35.83%/41.82% and raised average userspace CPU
18.34% on the server and 25.76% on the client. It therefore remains a
Linux-only diagnostic behind `RUSTSCALE_TUN_INBOUND_WRITE_WORKER`, exclusive
with the earlier TUN pipeline experiments and disabled by default. Both exact
evidence bundles are tracked under
[`docs/performance/gcp-20260723-102120-681c1f93dd`](performance/gcp-20260723-102120-681c1f93dd/)
and
[`docs/performance/gcp-20260723-103928-732e18dea9`](performance/gcp-20260723-103928-732e18dea9/).

A follow-up hybrid at exact clean source
`6f0add024096a4a7bf80b9c741d065eb90dc4f82` kept an idle single-packet write
inline while sending bursts and queued work through the worker. In a matched
same-binary A/B it improved P500/P1000 throughput by 23.75%/20.89%, but
regressed P1/P10/P100 by 9.66%/11.21%/1.37%, raised average userspace CPU by
24.18% on the server and 6.10% on the client, and did not improve latency. The
hybrid is rejected and its code is not part of the parity PR. Its exact
evidence is retained under
[`docs/performance/gcp-20260723-113500-c9144435e6`](performance/gcp-20260723-113500-c9144435e6/)
and
[`docs/performance/gcp-20260723-115345-ae16d4040d`](performance/gcp-20260723-115345-ae16d4040d/).

## Test infrastructure

`crates/testcontrol` ✅ in-process fake control server (Noise handshake, h2c,
register, streaming map, bounded authenticated TKA init/bootstrap/sync/sign/disable,
Go-testcontrol-style test API); tsnet integration tests layer client-local TKA
denylisting and restart recovery over that server. RequireAuth/CompleteAuth/
AwaitAuthURL flows for interactive login testing. `crates/derp` server ✅
in-process DERP relay (spawn_local + make_derp_map) for integration tests.
tailcfg null-tolerance ✅ every wire field accepts Go nil + property test
nullifying each field. Compatibility contract drift ✅ `compat/` pins
`tailscale.com@v1.100.0` provenance and checked normalized CLI, Rust API, C ABI,
Python export, LocalAPI, and conceptual tsnet inventories; focused generator
tests plus `tools/compat/check.sh` perform deterministic offline regeneration in
CI and refuse silent denominator/API shrinkage. These inventories classify
surface differences and do not by themselves establish runtime parity.
Remaining work includes more integration scenarios and a UDP impairment shim;
Go-testcontrol interoperability is covered in CI.

## Release pipeline

`release.yml` ✅ tag-triggered (v*) multi-platform build. macOS universal
(aarch64 + x86_64 lipo'd dylib/.a + binaries). Linux matrix (x86_64-gnu,
aarch64-gnu, x86_64-musl). Windows x86_64-msvc. Docker multi-arch image
pushed to GHCR. Homebrew formula. SHA256SUMS + GitHub Release. The current
same-release SHA256SUMS provides download integrity, not independent offline
signature authenticity; a reproducible public-key signed-manifest pipeline is
deferred.
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

`tools/interop.sh` runs 8 userspace e2e tests against real Go tailscaled
(1.98.8) on ephemeral tailnets: dial both directions, MagicDNS name
resolution, WhoIs identity, direct path (disco vs Go magicsock), pinned-DERP
relay, DERP→direct upgrade without byte loss, and subnet route accept. The
separate `tools/interop-tun.sh` CI path runs one exact serial Linux privileged
regression test: fail-closed `up_tun`, real interface/rule/table-52 assertions,
and an OS-socket echo roundtrip through the packet pump. The corrected
out-of-process parity gate `tools/interop-tun-oops.sh` then runs an isolated
TUN-vs-TUN split: two independent rustscale TUN nodes in separate Linux
network namespaces, each with its own loopback, underlay veth, TUN device,
policy rules, and table 52. It requires namespace-local route lookup and
bidirectional TUN counters as well as full captured logs, the issue-#75-shaped
cadenced UDP traffic, and a TCP echo roundtrip. This is deliberately distinct
from embedded, proxy, and RustScale-TUN-to-Go-userspace coverage; the
in-process repro can pass while this isolated process/namespace topology
fails.
Additional ignored TUN tests retain inbound and subnet-forwarding coverage
for explicit manual runs.
CI: interop + interop-tun jobs in e2e.yml. The separate required
`linux-replacement` job installs a locally assembled release archive with the
shipped systemd unit and completes a kernel-TUN echo roundtrip to a pinned
`tailscale.com@v1.100.0` Go peer; exact assertions and credential boundaries
are documented in `docs/release-first-run.md`.

## CLI (`cmd/tailscale` equivalent)

`crates/cli` produces the `rustscale` binary; `crates/localclient` is the
LocalAPI HTTP client (Go `client/local` equivalent) over safesocket. Hand-
rolled arg parsing (no clap), `#![forbid(unsafe_code)]`, `#[tokio::main]`.
Global flags: `--socket <path>` (default `/var/run/rustscaled.sock` with
state-dir fallback probing), `--json`.

| Subcommand | Go source | Status |
| --- | --- | --- |
| `status` | `cli/status.go` | ✅ table + `--json` passthrough; `--peers=false`, `--active` flags; peer table (IP, hostname, owner, connection path, exit-node flag). `Active`, `CurAddr`, `Relay`, and `PeerRelay` require one current authenticated transport observation and fail closed on stale/malformed evidence. The protected two-process/two-namespace TUN gate correlates direct public output with captured underlay and delivered traffic, then proves authenticated DERP identity, idle expiry/filtering, timestamps, and web/ping agreement; peer-relay identity has a separate TLS transport integration regression. |
| `ip` | `cli/ip.go` | ✅ `-4`/`-6`/`-1` filters; peer lookup by IP or hostname |
| `version` | `cli/version.go` | ✅ client version (build.rs git stamp) + `--daemon` daemon version from status; `--json` |
| `whois` | `cli/whois.go` | ✅ machine + user table; `--json` |
| `netcheck` | `cli/netcheck.go` | ✅ client-side STUN probe via `crates/netcheck`; DERPMap from daemon netmap; Go-style report (UDP, IPv4/6, MappingVariesByDestIP, DERP latencies sorted) |
| `metrics` | `cli/metrics.go` | ✅ raw Prometheus text passthrough |
| `health` | — | ✅ health warnings from daemon; `--json` |
| `down` | `cli/down.go` | ✅ EditPrefs WantRunning=false via PATCH /prefs |
| `ping` | `cli/ping.go` | ✅ disco/icmp/tsmp/peerapi via LocalAPI /ping; DERP bootstrap + forced direct discovery (2026-07-13) |
| `speedtest` | `cmd/speedtest/` | ✅ standalone client/server command; server uses `speedtest::Server` bounded admission and Ctrl-C cancellation/draining |
| `up` | `cli/up.go` | ✅ full runUp sequence (status → build prefs → watch-ipn-bus → /start → login-interactive → BrowseToURL → Running); flags: --auth-key, --hostname, --advertise-routes, --advertise-exit-node, --exit-node, --shields-up, --accept-routes, --accept-dns, --reset, --force-reauth, --timeout, --json, --qr |
| `login` | `cli/login.go` | ✅ login-interactive + watch-ipn-bus for BrowseToURL/Running; --qr |
| `logout` | `cli/logout.go` | ✅ POST /logout |
| `set` | `cli/set.go` | ✅ EditPrefs via PATCH /prefs; flags: hostname, accept-routes, accept-dns, shields-up, advertise-routes, advertise-exit-node, exit-node, route-all, advertise-tags, reset |
| `get` | `cli/prefs.go` | ✅ GET /prefs, JSON or human-readable |
| `switch` | `cli/switch.go` | ✅ `switch [--list] [--json] [<profile>]` |
| `wait` | `cli/wait.go` | ✅ subscribe-first authenticated LocalAPI state watch with `NotifyInitialState`; waits for Running, a Tailscale IP, and the configured TUN interface; `--timeout`, cancellation, bounded fail-closed connection-close/HTTP chunked parsing, and immediate disconnect unregistration |
| `serve`/`funnel` | `cli/serve.go` | ✅ serve/funnel status, reset, set with --bg/--https/--http/--tcp/--tls-terminated-tcp; foreground mode not yet supported |
| `cert` | `cli/cert.go` | ✅ `cert [--cert-file] [--key-file] [--min-validity] <domain>`; writes files, `-`=stdout; no-domain prints cert domains from status |
| `file` | `cli/file.go` | ✅ `file cp [--name] [--verbose] [--targets] <files...> <target>:`; `file get [--wait] [--conflict=skip\|overwrite\|rename] [--verbose] <dir>` |
| `ssh` | `cli/ssh.go` | ✅ `ssh [user@]host [args...]`; resolves peer, writes known_hosts, execs system ssh; 29 unit tests |
| `web` | `cli/web.go` | ✅ embedded single-file HTML; endpoints: /api/status/up/down/logout; explicit loopback default plus post-bind address enforcement; per-run cryptographic CSRF token; strict Host/Origin checks and bounded HTTP parsing; --readonly, --unsafe-any-addr; Linux loopback browser opening through the bounded freedesktop transport (`--browser=false` disables) |
| `debug` | `cli/debug.go` | ✅ `debug <status\|metrics\|ipconfig>` |
| `exit-node` | `cli/exitnode.go`, `ipn/prefs.go` | ✅ list/select/clear plus suggestion; selection accepts upstream IP/base-name/FQDN forms and rotation-stable IDs, rejects ambiguous or offline choices, clears mutually exclusive prefs fields, and applies through PATCH `/prefs` to live daemon routes |
| `dns` | `cli/dns.go` | 🔶 explicit `dns status [--json]` and `dns query [--json] <name> [A\|AAAA]`; query forwards the requested name/type and filters the LocalAPI address list by family |
| `bugreport` | `cli/bugreport.go` | ✅ prints version/state/health summary |
| `nc` | `cli/nc.go` | ✅ `nc <hostname-or-IP> <port>` uses only the authorized LocalAPI `ts-dial` upgrade; strict target/HTTP validation, binary-safe bounded duplex pumps, stdin half-close with remote drain, Ctrl-C cancellation, bounded peer-DNS completion, command help, and hermetic process/duplex coverage |
| `id-token` | `cli/id-token.go` | ✅ OIDC machine ID token via LocalAPI and Noise `POST /machine/id-token`; raw JWT and `--json` output |
| `update` | `cli/update.go` | 🔶 `--yes`, `--dry-run`, `--track`, and `--version`; Linux/macOS archive apply is limited to intact `scripts/install.sh` ownership receipts with checksum integrity, bounded parsing, post-install version verification, and journaled rollback. Homebrew is dry-run planning only; other layouts fail explicitly without elevation. |
| `drive` | `cli/drive.go` | 🔶 first truthful local-share slice: read-write-authorized `status`/`list`; daemon/root-only `share` (add or replace) and `unshare` until per-caller filesystem authority exists; text/JSON output, static completion, strict no-follow canonical root/name validation, bounded/cancellable LocalAPI calls, and mandatory restart-unique nonce+generation+config-hash ETag CAS. PUT/DELETE/MOVE/COPY reject and publication-barrier re-stat every special object. Remote mounts/composition, rename/share-as, bookmarks, and persistence remain deferred and are rejected explicitly. |
| `lock` | `cli/lock.go` | 🔶 status, self-safe confirmed init with owner-only pre-RPC disablement receipts and `--resume`, node sign, disable, and profile-scoped `local-disable` denylisting are wired through authorized LocalAPI; add/remove, re-sign, pre-auth wrapping, log, and revoke-keys remain deferred |
| completion/man | `cli/ffcomplete/` | ✅ bash, zsh, and fish script generation plus hidden, side-effect-free runtime completion protocol; man pages are not provided upstream |

The Unix failure-path gate in `crates/cli/tests/failure_process_interop.rs`
runs each CLI and a credential-checking scripted daemon in separate processes
with hard waits and kill/reap cleanup. It covers wait disconnect followed by a
daemon restart, malformed chunk framing, SIGINT cancellation, `nc` authorization
and post-half-close drain, Drive ETag races, exact exit/stdout/stderr, and socket
cleanup. `crates/clientupdate/tests/process_interop.rs` runs real staged and
installed version-verifier children and proves a post-replacement mismatch
restores both binaries and the receipt and removes the completed rollback
journal. This is local process/IPC failure evidence, not deployed-node or
network interoperability evidence.

DNS CLI parity is intentionally partial. The current `dns-query` LocalAPI
returns peer IP strings rather than a DNS wire response, so the CLI supports
only A and AAAA; it does not yet expose arbitrary record types, response codes,
TTLs, answer records, or resolver metadata. `dns status` reports the MagicDNS
enablement, suffix, and certificate domains available in the status response;
it does not yet collect preferences, the full DNS config, OS DNS config, or the
upstream `--all` diagnostic view. The old implicit `rustscale dns [name]`
syntax is not retained because it ambiguously treated `status` and `query` as
hostnames; use the explicit subcommands above.

`crates/localclient`: async LocalAPI HTTP client over `safesocket::connect`,
hand-rolled HTTP/1.1 (no hyper), fake Host `local-rustscaled.sock`, typed
errors (AccessDenied 403, PreconditionsFailed 412, Timeout, HttpStatus, PeerNotFound),
`watch_ipn_bus()` streaming method for newline-delimited JSON `Notify`
messages, with bounded HTTP headers/frames/chunks/trailers, fragmented HTTP/1.1
chunked and connection-close framing, strict status/JSON validation, and
explicit EOF handling. The server-side LocalAPI reads bounded/deadlined headers
without consuming bodies, then performs route/identity authorization and
bounded global/per-identity admission before strict rate/deadline/size-limited
body reads. Methods: start(), login_interactive(), logout(), edit_prefs(),
get_prefs(), status(), whois(), health(), metrics(), ping(), get_serve_config(),
set_serve_config(), drive_status(), get_drive_config(), set_drive_config(), cert_pair(), tailnet_lock_status(), tailnet_lock_init(),
tailnet_lock_ack_init(), tailnet_lock_sign(), tailnet_lock_disable(), tailnet_lock_force_local_disable(), list_profiles(), current_profile(),
switch_profile(), delete_profile(), push_file(), waiting_files(),
get_waiting_file(), delete_waiting_file(), debug(), dial(), dial_tcp_stream(),
dns_query(), check_ip_forwarding(). The streaming dial path directly uses the
configured safesocket (never proxy environment or a raw destination socket),
strictly bounds and validates the HTTP/1.1 upgrade, and rejects `Dial-Self`
bypass responses. Server-side outbound admission requires read-write/operator
authorization, has global/per-identity limits and a whole-dial deadline, and
propagates disconnect cancellation into either netstack or TUN UserDial. TUN
proxying rejects every plan not classified through the current peer/subnet/exit
route snapshot, including local-interface and allow-LAN connected routes. It
snapshots in peer-gate→route order, releases locks before await, then revalidates
the epoch while creating an exact-IP socket protected to the managed TUN; map
changes cancel pending connects.
Canceled userspace dials explicitly unregister their pending TCP socket and
fixed buffers (with reply-closure fallback) rather than awaiting handshake
timeout. Integration tests: testcontrol + daemon over temp socket,
interactive auth flow, plus hermetic `nc` duplex/error/cancellation cases.

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
