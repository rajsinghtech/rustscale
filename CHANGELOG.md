# Changelog

## 0.1.5

Patch release for lifecycle reliability, Linux replacement behavior, truthful
path reporting, embedded connection capacity, and reproducible performance
evidence.

- Made daemon and CLI down/up, first-run, restart, and LocalAPI handoff paths
  cancellation-safe and bounded.
- Configured Linux MagicDNS through systemd-resolved and strengthened the exact
  installed replacement and isolated two-TUN acceptance gates.
- Reported peer paths only from fresh observed transport evidence.
- Fixed embedded userspace P500/P1000 setup, receive scheduling, cancellation,
  and cleanup limits, with deterministic high-load regressions.
- Added a pinned Go embedded-tsnet comparator and published a credential-free,
  checksum-verified five-mode canonical benchmark. The result discloses high
  Rust embedded variance at several concurrency levels and makes no stable
  winner claim.

## 0.1.4

Patch release for idle application UDP latency and release-readiness hardening.

- Fixed issue #75 by waking the netstack poll loop after a successful
  `UdpListener::send_to` enqueue, preventing idle sends from waiting for the
  one-second safety fallback and arriving in bursts.
- Added notification-only netstack regression coverage and an isolated 20 Hz,
  one-way tsnet interoperability cadence gate.
- Added pinned, generated compatibility inventories for the CLI, Rust API, C
  ABI, Python exports, LocalAPI, and conceptual tsnet surface. These inventories
  classify differences; they do not claim blanket runtime parity.
- Made Tailscale-compatible installer aliases fail closed and added a required
  installed Linux systemd/TUN replacement journey against pinned Go tooling.
- Added evidence-backed agent worktree/session reconciliation.
- Added the node-local Tailnet Lock recovery escape hatch with profile-scoped,
  bounded state-ID denylisting, retained traffic withdrawal, crash recovery,
  and `rustscale lock local-disable`; full TKA parity remains incomplete.

## 0.1.3

Linux artifact compatibility hotfix. GNU/Linux release binaries are built on
Ubuntu 22.04 and executed in Debian 12 before publication, avoiding the glibc
2.39 requirement present in v0.1.2. Also includes pinned Go speedtest
interoperability, complete CLI `wait` behavior, and transactional systemd user
units.

## 0.1.2

First-run reliability and daemon lifecycle hotfix.

- Fixed pre-runtime default-socket discovery and replaced runtime-affinity
  panics with typed errors.
- Made interactive login, logout, shutdown, LocalAPI handoff, and subsystem
  wakeups durable and cancellation-safe.
- Persisted and enforced the configured Unix operator while preserving
  read-only LocalAPI access for unrelated users.
- Restored wanted profiles after service restart, applied online preference
  updates, and made container authentication ownership deterministic.
- Hardened Unix socket replacement/cleanup and bounded daemon shutdown cleanup.
- Added a credential-free installed Linux gate covering real release binaries,
  root daemon startup, operator setup, delayed interactive login, restart,
  logout, root-state cleanup, and uninstall.
- Added bounded Windows TCP table snapshots and safe managed-policy watching.

## 0.1.1

Large compatibility, performance, and production-readiness update following
the first tagged release.

### Compatibility and client surface

- Expanded the workspace from 36 to 85 crates, including TKA, audit logging,
  baked roots, config files, flow tracking, network logging, proxy discovery,
  socket statistics, route management, and additional upstream utility ports.
- Filled out the CLI and LocalAPI surface with ping, wait, lock, drive, web,
  debug capture, update status, profile switching, and additional daemon flags.
- Added declarative configuration with SIGHUP reload, multi-profile backend
  restart, client-version notifications, hostinfo completion, and key rotation.
- Improved wire compatibility through Go-generated fixtures and stricter state
  machine invariants.

### Networking and performance

- Added Linux TUN VNET/GSO/GRO batching, reusable packet buffers, faster
  checksums, batched WireGuard handoff, direct UDP send/receive batching, and
  guarded UDP GRO.
- Improved direct-path convergence, disco-key refresh, PMTUD behavior, socket
  buffer sizing, heartbeat scheduling, and relay-to-direct migration.
- Added Linux netlink monitoring, router abstraction, packet capture, network
  flow logs, and expanded health reporting.

### Installation and release engineering

- Added checksum-verifying macOS/Linux and Windows one-line installers, an
  optional Tailscale-compatible command-alias mode, and Linux systemd assets.
- Added a multi-architecture GHCR image with Tailscale-compatible command names
  and containerboot-compatible environment variables.
- Added release-contract and installer tests covering every shipped archive
  mapping, checksum failure, required contents, aliases, uninstall, Pages
  assembly, and container entrypoint behavior.
- Hardened the release workflow with tag/version/release-note validation,
  deterministic checksums, OCI metadata, and commit-pinned Actions.

## 0.1.0

First tagged release. Rust reimplementation of Tailscale's client stack —
tsnet embedding API, TUN-mode client, C FFI, CLI, and daemon.

### Core protocol and data plane

- Curve25519/ed25519 keys, NaCl box crypto (`crates/key`)
- tailcfg wire types (Node, NetMap, DERPMap, MapRequest/Response) with null-tolerance property tests
- disco NAT-traversal message codec + box crypto (`crates/disco`)
- DERP relay client: frame codec, derphttp, auto-reconnect, keepalive (`crates/derp`)
- STUN-based network probing with per-region DERP latency (`crates/netcheck`)
- WireGuard data plane via boringtun noise::Tunn (`crates/wg`)
- Event-driven userspace TCP/IP stack via smoltcp (`crates/netstack`)
- Stateful packet filter — port of wgengine/filter, including stateful UDP (`crates/filter`)
- magicsock path selection: direct UDP, DERP relay, peer relay (`crates/magicsock`)
- Peer relay client: full relayManager event loop, disco routing, call-me-maybe (`crates/magicsock`)
- Peer relay server (`crates/udprelay`)
- Subnet routing: advertise, accept, forward
- netns socket binding: SO_MARK, IP_BOUND_IF, routing loop prevention (`crates/netns`)

### Control plane

- ts2021 Noise control channel: HTTP/2-over-Noise, register, streaming netmap deltas (`crates/controlclient`)
- Streaming netmap reconnection with NetInfo reporting
- Dynamic feature flags from control CapMap (`crates/controlknobs`)
- Hostinfo: all 36 Go fields, 10-min update loop with content-hash dedup
- Netmap disk cache: versioned envelope, SHA-256 dedup, auth-failure clear (`crates/dnscache`, `crates/dnsfallback`)
- DNS fallback: bootstrap DNS over embedded DERP IPs, DERP map disk cache (`crates/dnsfallback`)
- DNS cache: TTL, single-flight, last-good (`crates/dnscache`)
- Captive portal detection: concurrent HTTP GETs, health warnable (`crates/netcheck`)

### tsnet embedding API

- `Server::builder`, `up`, `up_tun`, `listen`, `dial`, `listen_tls` (`crates/tsnet`)
- `Server::whois` — peer identity from netmap by IP
- `Server::listen_socks5`, `listen_service`, `listen_ssh` (feature-gated)
- `Server::set_exit_node` / `clear_exit_node`
- `Server::set_serve_config`, `listen_funnel`
- Taildrop manager: file spool, conflict modes, PeerAPI receive handler
- App Connector wiring with `TsnetRouteAdvertiser`

### TUN mode

- macOS utun and Linux `/dev/net/tun` backends (`crates/tun`)
- `up_tun` data pump with `TunModeConfig`
- Exit node TUN routes: `/1` split routes on macOS
- macOS OS DNS configuration via `/etc/resolver` split DNS (opt-in builder flag)

### DNS

- MagicDNS resolver + in-process UDP DNS responder (`crates/dns`)
- Split DNS via control `Routes` (most-specific suffix wins)
- Hosts, LocalDomains, SubdomainHosts, PTR reverse (v4/v6), `.onion` NXDOMAIN, 4via6
- TC bit + EDNS size, ANY qtype, TCP fallback, DoH upstream forwarder
- macOS OS configurator: `/etc/resolver/$SUFFIX`, ownership header, stale cleanup (`crates/dns`)

### Certificates

- Let's Encrypt ACME client: RFC 8555, ES256 JWS, dns-01 via set-dns, rcgen CSR
- `ControlCertProvider` with cert cache and self-signed fallback
- CLI `rustscale cert` subcommand
- LocalAPI `GET /cert/<domain>?type=pair|cert|key&min_validity=`

### Network features

- Exit node support: advertise, select, TUN default routes, FFI
- Serve/Funnel: `ServeConfig` serde model, ETag, persistence, TCP forward, reverse proxy, port validation
- Tailscale Services: `listen_service` with PROXY protocol v2, VIP resolution from CapMap
- SOCKS5 proxy: RFC 1928 CONNECT (v4/domain/v6) (`crates/tsnet`)
- Tailscale SSH server: `listen_ssh` with WhoIs/policy wiring, `ssh` feature (`crates/ssh`)
- Taildrop: file `cp`/`get` via PeerAPI + LocalAPI, conflict modes, file-targets enumeration
- App Connector: DNS-domain dynamic route advertisement, DNS observer, CNAME chain resolution (`crates/appc`)
- Port mapping: NAT-PMP, PCP, UPnP IGD — gateway discovery, probe, create/renew, cache (`crates/portmapper`)

### Health and monitoring

- Health tracking: warnable tracker, watchdog, wired into control/DERP/certs/netmon (`crates/health`)
- Network monitor: AF_ROUTE on macOS, polling fallback, State, ChangeDelta, wall-time jump (`crates/netmon`)
- tcpinfo: darwin TCP_CONNECTION_INFO, linux TCP_INFO (`crates/tcpinfo`)
- `break_tcp_conns` on exit-node switch in TUN mode
- C2N debug endpoints: prefs, netmap, health, metrics, dns, component-logging, goroutines, sockstats (`crates/c2n`)

### IPN state machine and auth

- IPN state machine: State enum, `nextStateLocked` truth table, table-driven tests (`crates/ipn`)
- Notify bus: broadcast channel, `watch-ipn-bus` streaming endpoint
- Prefs: 15 fields, `MaskedPrefs`, `StartOptions`, atomic disk persistence
- Interactive auth: daemon-side login flow, `start_localapi_only`, split bootstrap phases
- Multi-profile management: `LoginProfile`, `NetworkProfile`, persistence, `switch` CLI

### CLI and daemon

- `rustscale` CLI: status, ip, version, whois, netcheck, metrics, health, up, login, logout, down, set, get, serve, funnel, cert, switch (`crates/cli`)
- `rustscaled` daemon: run, install-system-daemon, uninstall-system-daemon, launchd plist (`crates/rustscaled`)
- `localclient`: LocalAPI HTTP client over safesocket, `watch_ipn_bus` streaming (`crates/localclient`)
- QR codes: `up --qr`, `login --qr` — terminal half-block + PNG data URL in `--json`
- safesocket IPC: unix sockets + darwin sameuserproof, Windows named pipes (`crates/safesocket`)

### LocalAPI

- Full LocalAPI HTTP server on safesocket (`crates/tsnet`)
- Endpoints: status, whois, prefs (GET+PATCH), netmap, metrics, health, ping, watch-ipn-bus, start, login-interactive, logout, serve-config (GET+POST with ETag/If-Match), profiles (GET+PUT/GET+POST+DELETE), cert, files, file-targets, await-waiting-files

### Platform support

- macOS: safesocket sameuserproof, routetable (NET_RT_DUMP2), tcpinfo, break_tcp_conns, launchd daemon, netmon darwin (RTM_GET, utun exclusion), OS DNS configurator, hostinfo (osproductversion, hw.model), quarantine xattr
- Windows: compile-level portability (`cargo check --workspace --target x86_64-pc-windows-msvc` passes), safesocket named-pipe transport, cfg-gated unix-only code, blocking CI legs

### C FFI

- `librustscale` C ABI: opaque-handle API, libtailscale-equivalent (`crates/ffi`)
- FFI functions: `ts_version`, `ts_whois`, `ts_set_exit_node`, `ts_clear_exit_node`
- C header generation via cbindgen (`tools/gen-header.sh`)
- Version stamping: `git describe --tags --long --always --dirty` → `RUSTSCALE_VERSION_LONG`
- Python ctypes bindings

### Performance

- Event-driven netstack: p50 ~170us vs tailscaled 257us, throughput 465–838 vs 384 Mbps
- Async lock replacing try-lock, eliminated packet drops
- Eliminated per-packet allocations
- Benchmark harness: throughput and latency (`crates/bench`)

### Test infrastructure

- `testcontrol`: in-process fake control server with Noise handshake, register, streaming map (`crates/testcontrol`)
- In-process DERP relay server for integration tests (`crates/derp`)
- tailcfg null-tolerance property tests
- Go testcontrol interop harness
- Cross-client interop e2e suite: 8 tests against Go tailscaled 1.98.8 (`tools/interop.sh`)
- TUN-mode interop e2e suite (`tools/interop-tun.sh`)
- Fuzz targets: disco decode, DERP frame codec, STUN parse, portmapper PMP/PCP codecs
- ThreadSanitizer: weekly over magicsock/derp/tsnet

### Release pipeline and CI

- `release.yml`: tag-triggered (`v*`) multi-platform build — macOS universal (lipo), Linux per-target (gnu x86_64/aarch64, musl x86_64), SHA256SUMS, GitHub Release
- Homebrew tap publishing to `rajsinghtech/homebrew-tap`
- `audit.yml`: weekly cargo-audit + cargo-deny, also on PRs touching `Cargo.lock` or `deny.toml`
- `ci.yml`: OS matrix (ubuntu, macOS, Windows), cross-compile checks, MSRV 1.91, alls-green merge gate, SHA-pinned actions
- `fuzz.yml`, `sanitizer.yml`
- `scripts/install.sh`: build-from-source installer for librustscale + header

### Workspace

- 36 crates, all inheriting `workspace.package.version`
- `workspace.package.version = "0.1.0"`, `rust-version = "1.91"`, `edition = "2021"`
- `forbid(unsafe_code)` workspace-wide; pedantic clippy with noise suppressed
- Release profile: thin LTO, `codegen-units = 1`
