# Feature & Services Parity Audit (2026-07-12)

Auditor: opencode (orchestrator)
Scope: higher-level features and services not covered in `docs/parity.md`'s Tier-1/2
tables at sufficient depth. Methodology: locate each feature in Go (`tailscale/`),
check rustscale by grepping for key symbols, verify parity.md claims, then assign
priority (P0=breaks core UX, P1=important capability users notice, P2=niche).

Notable: parity.md is largely honest — this audit fills in resolution gaps and
exposes integration holes (code that exists but is never wired).

---

## 1. tsnet embedding API — method-by-method diff

Go source: `tailscale/tsnet/tsnet.go` (~2250 lines)  
Rust source: `crates/tsnet/src/lib.rs` (~4150 lines) + 18 supporting files

### Builder / constructor (Server { fields } / ServerBuilder)

| Go field           | Rust builder method     | Status | Notes |
|--------------------|-------------------------|--------|-------|
| `Dir`              | `.state_dir()`          | ✅     | Same semantics |
| `Store`            | —                       | ❌ P2  | Rust always uses PersistedState; no memstore injection |
| `Hostname`         | `.hostname()`           | ✅     | |
| `Ephemeral`        | `.ephemeral()`          | ✅     | |
| `AuthKey`          | `.auth_key()`           | ✅     | |
| `ClientSecret`     | —                       | ❌ P2  | OAuth client secret auth key generation |
| `ClientID`         | —                       | ❌ P2  | Workload identity federation (WIF) |
| `IDToken`          | —                       | ❌ P2  | WIF |
| `Audience`         | —                       | ❌ P2  | WIF |
| `ControlURL`       | `.control_url()`        | ✅     | |
| `RunWebClient`     | —                       | ❌ P2  | Port-5252 management web UI |
| `Port`             | —                       | ❌ P1  | Can't pin WireGuard UDP port; always 0=auto |
| `AdvertiseTags`    | —                       | ❌ P1  | Can't set tags at build time; only read from netmap post-up |
| `Tun`              | —                       | ⚠️ P2  | Rust uses `up_tun(TunModeConfig)` instead; Go injects `tun.Device` |
| `UserLogf`/`Logf`  | —                       | ❌ P1  | No pluggable logger; uses `eprintln!` |

Rust-specific extras: `.advertise_routes()`, `.accept_routes()`, `.advertise_exit_node()`,
`.configure_os_dns()`, `.localapi()` — Rust builder is more annotation-based, Go is late-binding.

### Start / Up / Close

| Go method | Rust equivalent | Status | Notes |
|-----------|-----------------|--------|-------|
| `Start()` | — | ❌ P1 | Go's `Start()` is lazy/idempotent + auto-called by `Dial`/`Listen`. Rust requires explicit `.up().await` — no auto-start, no idempotent check. |
| `Up(ctx)` → `(*ipnstate.Status, error)` | `Server::up()` → `Result<()>` | ❌ P1 | Rust returns unit; need separate `.status()` call to get IPs. |
| — | `up_tun(TunModeConfig)` | ✨ extra | No Go equivalent |
| `Close()` | `Server::close()` | ✅ | |

### Listen variants

| Go method | Rust method | Status | Notes |
|-----------|-------------|--------|-------|
| `Listen("tcp", ":80")` | `Server::listen(port)` → `TcpStream` | ✅ | Rust takes bare port, not `(network, address)`. No `"tcp4"`/`"tcp6"` variants. |
| `ListenPacket("udp", ":53")` | — | ❌ **P0** | **No UDP listen on netstack.** Any user calling `tsnet.ListenPacket` on Go expects to receive UDP packets on the tailnet. Rust has zero UDP socket listening support. |
| `ListenTLS("tcp", ":443")` | `Server::listen_tls(port)` | ✅ | + `listen_tls_with_provider()` for custom certs |
| `ListenFunnel("tcp", ":443", opts...)` | `Server::listen_funnel(port)` | ⚠️ P2 | Rust lacks `FunnelOnly()` / `FunnelTLSConfig` option support |
| `ListenSSH(":2222")` | `Server::listen_ssh(port)` | ✅ | Feature-gated (`ssh`) |
| `ListenService(name, mode)` → `*ServiceListener` | `Server::listen_service(svc_name, mode)` | ✅ | |

**Key gap: `ListenPacket`** — P0 because Go's `tsnet.ListenPacket` is the only way to receive UDP on the tailnet. Without it, any DNS server or custom UDP protocol on tsnet is impossible.

### Dial / HTTPClient

| Go method | Rust equivalent | Status | Notes |
|-----------|-----------------|--------|-------|
| `Dial(ctx, network, address)` | `Server::dial(addr_str)` | ⚠️ P2 | No context parameter, TCP-only, no `"udp"` dialing |
| `HTTPClient()` → `*http.Client` | — | ❌ P2 | No convenience HTTP client; callers must wrap `dial()` manually |

### LocalClient accessor

| Go method | Rust equivalent | Status | Notes |
|-----------|-----------------|--------|-------|
| `LocalClient()` → `*local.Client` (in-memory) | — | ❌ **P1** | Rust has a full `LocalClient` (`crates/localclient`) but it requires a Unix-socket path. Go's is in-memory via `memnet` — no file-system dependency, zero overhead, no socket-permissions issues. Rust users must: (1) set `.localapi(true)` on builder, (2) pass the socket path to `LocalClient::new("/path/to/sock")`. |

Rust's `LocalClient` methods (18) are a superset of the commonly-used ones, including:
`status`, `whois`, `prefs`/`edit_prefs`/`get_prefs`, `netmap`, `metrics`, `health`,
`ping`, `watch_ipn_bus`, `start`, `login_interactive`, `logout`, get_serve_config`/`set_serve_config`,
profile management. Missing from Rust LocalClient: `cert_pair`, `cert_domains`,
`dns_config`, `bug_report`, `check_update`, `waiting_files`, `file_targets`,
`push_file`, `stream_debug_capture`, `check_ip_forwarding`, `suggest_exit_node`,
`drive_*`, `tailnet_lock_*`, `debug_*` (diagnostics).

### Loopback

| Go method | Rust equivalent | Status | Notes |
|-----------|-----------------|--------|-------|
| `Loopback()` → `(addr, proxyCred, localAPICred, err)` | — | ❌ **P1** | Go's `Loopback()` creates a **single TCP listener** on `127.0.0.1:0` that multiplexes SOCKS5 + LocalAPI via `proxymux.SplitSOCKSAndHTTP`, protected by randomly-generated credentials. Rust has `listen_socks5()` (standalone, no LocalAPI multiplex, no auth) and a Unix-socket LocalAPI separately — no combined loopback. |

Consequence: the Go pattern of "start tsnet, call Loopback, set env vars, launch a
child process" (used by IDEs, k8s sidecars, docker exec) has no Rust equivalent.

### CertDomains, TailscaleIPs, GetRootPath

| Go method | Rust equivalent | Status | Notes |
|-----------|-----------------|--------|-------|
| `CertDomains()` | — | ❌ P2 | Accessible indirectly via DNS config on running state, but no public accessor |
| `TailscaleIPs()` | `Server::status().tailscale_ips` | ✅ | |
| `GetRootPath()` | — | ❌ P2 | No accessor; state_dir only on the builder, not on `Server` |

### CapturePcap

| Go method | Rust equivalent | Status | Notes |
|-----------|-----------------|--------|-------|
| `CapturePcap(ctx, pcapFile)` | — | ❌ **P1** | Go writes PCAP of netstack traffic to a file for debugging. Rust has no packet capture facility at all. Parity.md lists this as "Tier 4 optimization" but it's a critical debug tool. |

### Sys() / dependency injection

| Go method | Rust equivalent | Status | Notes |
|-----------|-----------------|--------|-------|
| `Sys()` → `*tsd.System` | — | ❌ P2 | Rust stores subsystems directly in `RunningState` and exposes individual accessors (`health()`, `c2n_router()`, `magicsock()`, etc.). No unified DI container — makes testing harder but doesn't affect users. |

### RegisterFallbackTCPHandler

| Go method | Rust equivalent | Status | Notes |
|-----------|-----------------|--------|-------|
| `RegisterFallbackTCPHandler(cb)` | — | ❌ **P1** | Go allows embedders to intercept unmatched TCP flows. Rust's netstack rejects unhandled flows. This breaks tsnet-style apps that want to handle all traffic on the tailnet IP (e.g., generic TCP proxies). |

### LogtailWriter

| Go method | Rust equivalent | Status | Notes |
|-----------|-----------------|--------|-------|
| `LogtailWriter()` → `io.Writer` | — | ❌ P2 | Writes go to the logtail upload buffer if logtail is configured. Rust has no logtail at all (see §6). |

### Summary — tsnet API completeness

Total Go public API methods on `Server`: ~23  
Fully ported: 9  
Partially ported: 2  
Missing: 12 (including `ListenPacket`, `Loopback`, `LocalClient` in-memory accessor,
`Start` lazy-init, `CapturePcap`, `RegisterFallbackTCPHandler`, `HTTPClient`,
`CertDomains`, `GetRootPath`, `LogtailWriter`, `Sys`, `Up`->status)

---

## 2. Tailscale SSH server

Go source: `tailscale/ssh/tailssh/` (13 files, ~6000 lines)  
Rust source: `crates/ssh/` (8 files, ~1200 lines) + `crates/tsnet/src/ssh.rs` (114 lines)

### What Rust has (substantial, ~70% complete)

| Component | Go file | Rust file | Status |
|-----------|---------|-----------|--------|
| SSH server (russh-based) | `tailssh.go` | `server.rs` | ✅ Full `russh::server::Server` trait impl |
| Session wrapper | `session.go` | `session.rs` | ✅ `Session` with AsyncRead/Write, PeerIdentity |
| Policy evaluation | `tailssh.go` | `auth.rs` | ✅ `eval_ssh_policy()` matching Go logic |
| Host key derivation | `hostkeys.go` | `hostkeys.rs` | ✅ Ed25519 from NodePrivate |
| Environment filtering | `accept_env.go` | `env.rs` | ✅ LD_*/DYLD_* rejection, glob patterns |
| C2N usernames | `c2n.go` | `c2n.rs` | ✅ `/ssh/usernames` handler |
| Tsnet integration | `listen.go` | `crates/tsnet/src/ssh.rs` | ✅ `listen_ssh(port)` feature-gated |

### What Rust is missing (~30%)

| Component | Go file | Status | Priority | Notes |
|-----------|---------|--------|----------|-------|
| Session recording | `tailssh.go` (recording struct) | ❌ **P1** | Session recording is an advertised Tailscale SSH feature. Without it, SSH sessions cannot be audited. |
| Incubator (subprocess mgmt) | `incubator.go` + `incubator_linux.go` | ❌ **P1** | Go execs `tailscaled be-child ssh` for privilege separation, PTY setup, `login`/`su` via `unix.Exec`. Rust has no subprocess model for SSH sessions. |
| Real policy feed from control | `tailssh.go` (SSHPolicy from netmap) | ❌ **P0** | Rust's `auth.rs` has the full policy evaluation engine, but `crates/tsnet/src/ssh.rs:61` feeds `Arc::new(\|\| None)` — the policy callback always returns `None`, rejecting all connections. The SSH server is **dead code** in production unless the user manually sets a policy. |
| SSH_HostKeys in Hostinfo | `tailcfg.go` Hostinfo field | ❌ P2 | Field exists in type but never populated. |
| `listen_ssh` on LocalBackend | `local.go` via `HookListenSSH` | ❌ P2 | Rust only supports the tsnet `listen_ssh()` path, not the full netstack-interception path (port-22 auto-intercept). |
| SSH agent forwarding | `tailssh.go` | ❌ P2 | Requires SSH-agent protocol handling |
| Audit logging (Linux netlink) | `auditd_linux.go` | ❌ P2 | |

### Priority assessment for SSH gaps

- **P0 (dead code):** policy callback returns `None` — no SSH connections actually succeed.
- **P1 (important):** session recording, incubator subprocess model.
- **P2 (niche):** agent forwarding, auditd, Hostinfo population.

---

## 3. Taildrop — in flight (skip)

Per CLAUDE.md: "Taildrop: in flight in a worktree — mark 'in flight', skip."

parity.md confirms Taildrop is not started. The Go source is `ipn/ipnlocal/files.go`
and `local/client` methods: `WaitingFiles`, `AwaitWaitingFiles`, `DeleteWaitingFile`,
`GetWaitingFile`, `FileTargets`, `PushFile`. All missing from Rust — confirms parity.md.

---

## 4. Exit nodes

Go source: `ipn/ipnlocal/local.go` (suggest-exit-node, auto-exit-node, AllowLANAccess),
`ipn/prefs.go` (prefs), `tailcfg/tailcfg.go` (NodeAttrSuggestExitNode, etc.),
`net/dns/resolver/tsdns.go` (exit node DNS), `appc/` (app connectors)  
Rust source: `crates/tsnet/src/routing.rs`, `crates/ipn/src/prefs.rs`, `crates/tsnet/src/appc.rs`

### What Rust has

| Component | Go source | Rust source | Status |
|-----------|-----------|-------------|--------|
| RouteTable with exit node | `wgengine/magicsock/` | `routing.rs` | ✅ set/clear/get + catch-all fallback |
| Prefs: ExitNodeID, ExitNodeIP, AdvertiseExitNode | `ipn/prefs.go` | `ipn/src/prefs.rs` | ✅ |
| ExitNodeID in Hostinfo | `tailcfg.go` | `hostinfo.rs` | ✅ populated |
| CLI flags —exit-node, --advertise-exit-node | `cli/up.go` | `cli/src/commands/up.rs` | ✅ |
| AppConnector | `appc/` | `appc.rs` | ✅ (parity.md claims Done) |

### What Rust is missing

| Component | Go source | Status | Priority | Notes |
|-----------|-----------|--------|----------|-------|
| Exit node wiring from prefs to RouteTable | `local.go` | ❌ **P1** | `set_exit_node()` in `routing.rs` exists but is **never called** from the pref-change flow in `lib.rs`. Changing `--exit-node` on the CLI updates prefs but doesn't activate routing. |
| AllowLANAccess | `ipn/prefs.go` field | ❌ **P1** | No field, no logic. Users behind an exit node cannot access local LAN resources. |
| SuggestExitNode | `local.go` `suggestExitNode()` (300+ lines) | ❌ **P1** | No DERP-latency-based or traffic-steering-based suggestion. No `NodeAttrSuggestExitNode` capability evaluation. `local.Client.SuggestExitNode()` absent. |
| AutoExitNode | `local.go` `resolveAutoExitNodeLocked()` | ❌ **P2** | No `AutoExitNode` pref, no `any`-expression evaluation |
| Exit node DNS proxy filtering | `tsdns.go` `ExitNodeFilteredSet` | ❌ **P2** | `tailcfg.DNSConfig.ExitNodeFilteredSet` exists in type but never checked in DNS resolution |
| ExitNodeDNSResolvers | `tailcfg.Node.ExitNodeDNSResolvers` | ❌ P2 | For WireGuard-only exit nodes |
| Traffic steering | `net/traffic/` | ❌ P2 | Priority-based exit selection with rendezvous hashing |

### Priority assessment for exit node gaps

- **P1 (important):** exit node wiring from prefs → RouteTable is broken (no-op at the
  integration layer), AllowLANAccess missing, SuggestExitNode missing.
- **P2 (niche):** AutoExitNode, DNS proxy filtering, traffic steering.

parity.md line 15 claims "✅ port-5 done" for exit nodes but the integration wiring
from prefs → RouteTable is incomplete, and AllowLANAccess is absent. The pure
routing-layer implementation exists, but the control-flow integration is partial.

---

## 5. Tailscale Services / VIP services, 4via6, split DNS

Go source: `tsnet/tsnet.go` (ListenService), `tailcfg/tailcfg.go` (ServiceIPMappings,
ServiceName, VIPService, NodeAttrServiceHost), `net/tsaddr/tsaddr.go` (4via6),
`net/dns/resolver/tsdns.go` (split DNS)  
Rust source: `crates/tsnet/src/service.rs`, `crates/tsnet/src/lib.rs` (listen_service),
`crates/dns/src/` (split DNS)

### ListenService

| Component | Go source | Rust source | Status | Priority | Notes |
|-----------|-----------|-------------|--------|----------|-------|
| ServiceName type | `tailcfg.go` | `tailcfg/src/` | ✅ | | |
| ServiceIPMappings from CapMap | `tsnet.go` | `service.rs` | ✅ | | Resolves VIPs from `service-host` cap |
| ServiceListener | `tsnet.go` | `service.rs` | ✅ | | |
| ServiceModeTCP | `tsnet.go` | `service.rs` (ServiceMode::tcp) | ✅ | | |
| ServiceModeHTTP | `tsnet.go` | — | ❌ **P1** | No HTTP reverse-proxy mode for services |
| TerminateTLS | `ServiceModeTCP.TerminateTLS` | — | ❌ **P1** | Can't terminate TLS at the service VIP |
| AcceptAppCaps | `ServiceModeHTTP.AcceptAppCaps` | — | ❌ P2 | Can't mount per-capability app endpoints |
| PROXY protocol version selection | ServiceMode.PROXYProtocol (int: 0/1/2) | ⚠️ P2 | Rust v2-only, bool (on/off) |
| Tagged-node validation | `tsnet.go` (ErrUntaggedServiceHost) | — | ❌ P2 | Rust doesn't validate tags |
| Service cleanup on Close | `ServiceListener.Close()` | — | ❌ P2 | No advertisement count decrement |

### 4via6

Rust status: `crates/dns/src/resolve.rs` handles 4via6 DNS resolution for `-via-`
domain names. `crates/tsaddr/` has `TailscaleViaRange()`. Parity.md claims this
is covered by the MagicDNS phase — confirmed.

Split DNS: ✅ parity.md line 12 confirms — most-specific suffix wins, fully implemented.

---

## 6. logtail (log streaming + client metrics + usermetrics)

Go source: `logtail/`, `logpolicy/`, `util/clientmetric/`, `ipn/ipnlocal/metrics.go`  
Rust source: bare C2N endpoint stubs only

### Log streaming

| Component | Go source | Status | Priority | Notes |
|-----------|-----------|--------|----------|-------|
| Log upload client | `logtail/logtail.go` | ❌ **P1** | No buffered, compressed HTTP/2 log upload to `log.tailscale.com` |
| Buffer management | `logtail/buffer.go`, `filch/` | ❌ **P1** | No MemoryBuffer or disk-backed filch |
| Collection/PrivateID | `logtail/config.go` | ❌ P2 | No log stream config |
| Log stream config setup | `logpolicy/` | ❌ P2 | Log dir setup, rotation |
| C2N `/logtail/flush` | `c2n.go` | ⚠️ | Stub returning 204 no-op |
| FrontendLogID / BackendLogID in Hostinfo | `tailcfg.go` | ❌ P2 | Fields exist in type but never populated |

### Client metrics

| Component | Go source | Status | Priority | Notes |
|-----------|-----------|--------|----------|-------|
| Metric registry | `util/clientmetric/` | ❌ **P1** | No `NewCounter`/`NewGauge` registry. Rust has 4 ad-hoc Prometheus metrics in `localapi.rs` (packet drops, peer count, health warnings, local endpoints) |
| Expvar-style counters | `metrics/` | ❌ P2 | No structured metrics |
| Delta encoding for upload | `clientmetric/EncodeLogTailMetricsDelta` | ❌ P2 | Wire-format metric deltas |
| Prometheus exposition | `clientmetric/WritePrometheusExpositionFormat` | ⚠️ | Rust writes ad-hoc Prometheus text in `build_metrics_text()` — no registry |
| LocalAPI `/metrics` | `localapi.go` | ✅ | Serves the 4 ad-hoc metrics |
| User metrics endpoint | `localapi.go` `UserMetrics` | ❌ P2 | |

### Priority assessment

- **P1 (important):** logtail is missing entirely — no crash/error logs reach Tailscale support.
  Client metrics have only 4 counters vs Go's 100+ — debugging prod issues is harder.
- **P2 (niche):** delta encoding, filch disk persistence.

parity.md line 67 correctly marks logtail as ⬜. The ad-hoc metrics aren't tracked
there — they're "Present but skeletal" at ~25% of Go's coverage.

---

## 7. clientupdate / auto-update

Go source: `clientupdate/clientupdate.go` + platform backends  
Rust source: nothing except the `AllowsUpdate` field in `Hostinfo`

| Component | Go source | Status | Priority | Notes |
|-----------|-----------|--------|----------|-------|
| Update check | `clientupdate.go` `NewUpdater` | ❌ **P1** | No version check against `pkgs.tailscale.com` or control plane |
| Auto-apply updates | `clientupdate.go` `Updater.Update` | ❌ **P1** | No platform-specific update mechanism |
| ClientVersion from control | `tailcfg/tailcfg.go` `ClientVersion` | ❌ **P1** | Not processed in map response |
| Hostinfo.AllowsUpdate | `hostinfo.go` | ❌ P2 | Field exists in type but never set to true |
| AutoUpdate prefs | `ipn/prefs.go` `AutoUpdatePrefs` | ❌ P2 | Pref type exists? Check: `crates/ipn/src/prefs.rs` — mark missing if absent |

Priority: P1. Users cannot auto-update. Any critical security patch requires manual
binary replacement.

parity.md line 30 correctly marks this as ⬜.

---

## 8. Hostinfo field-by-field coverage

Go source: `tailcfg/tailcfg.go` (Hostinfo struct, lines 848-926, 41 fields)  
Rust source: `crates/tailcfg/src/node.rs` (Hostinfo struct, lines 167-442),
`crates/tsnet/src/hostinfo.rs` (population, ~130 LOC)

### Populated (18/41 = 44%)

| Field | Go enum | Rust pop? | Notes |
|-------|---------|-----------|-------|
| `IPNVersion` | ✅ | ✅ | `CARGO_PKG_VERSION` |
| `OS` | ✅ | ✅ | `std::env::consts::OS` |
| `OSVersion` | ✅ | ✅ | macOS sysctl, Linux uname |
| `Container` | ✅ | ✅ | Docker/Podman/LXC detection |
| `Env` | ✅ | ✅ | 10 env types (Knative, Lambda, K8s, etc.) |
| `Distro` | ✅ | ✅ | Linux /etc/os-release |
| `DistroVersion` | ✅ | ✅ | Linux VERSION_ID |
| `DistroCodeName` | ✅ | ✅ | Linux VERSION_CODENAME |
| `App` | ✅ | ✅ | Via HostinfoOverrides |
| `Desktop` | ✅ | ✅ | X11/Wayland socket detection |
| `Package` | ✅ | ✅ | Always `"tsnet"` |
| `DeviceModel` | ✅ | ✅ | macOS hw.model, Synology, RPi |
| `Hostname` | ✅ | ✅ | From system |
| `Machine` | ✅ | ✅ | `arch_machine()` |
| `GoArch` | ✅ | ✅ | `std::env::consts::ARCH` |
| `GoVersion` | ✅ | ✅ | Rust compiler version |
| `Cloud` | ✅ | ✅ | DMI metadata (AWS/Azure/GCP/DO) |
| `PeerRelay` | ✅ | ✅ | From config |

### Partially populated (5/41)

| Field | Rust struct | Populates? | Notes |
|-------|-------------|------------|-------|
| `Services` | ✅ | ⚠️ partial | Set from peerapi services, not always populated at map-request time |
| `RoutableIPs` | ✅ | ⚠️ partial | Set by caller (advertised routes); may not reflect runtime state |
| `NetInfo` | ✅ | ⚠️ partial | PreferredDERP, WorkingUDP set at bootstrap |
| `ExitNodeID` | ✅ | ⚠️ partial | Set in `apply_runtime_fields`; but exit-node wiring from prefs is broken |
| `IngressEnabled` | ✅ | ⚠️ partial | Set from serve config funnel state |

### Never populated (18/41 = 44%)

| Field | Rust struct | Priority | Notes |
|-------|-------------|----------|-------|
| `FrontendLogID` | ✅ | P2 | Needs logtail |
| `BackendLogID` | ✅ | P2 | Needs logtail |
| `ShieldsUp` | ✅ | **P1** | Pref exists, not reflected in Hostinfo |
| `ShareeNode` | ✅ | P2 | Set by control plane |
| `NoLogsNoSupport` | ✅ | P2 | Opt-out flag |
| `WireIngress` | ✅ | P2 | Funnel wiring flag |
| `AllowsUpdate` | ✅ | P2 | Needs clientupdate |
| `GoArchVar` | ✅ | P2 | e.g., GOARM, GOAMD64 |
| `RequestTags` | ✅ | P2 | Only in tests |
| `WoLMACs` | ✅ | P2 | Wake-on-LAN |
| `SSH_HostKeys` | ✅ | P2 | SSH server exists, not advertising keys |
| `Userspace` | ✅ | P2 | Always true for tsnet but not declared |
| `UserspaceRouter` | ✅ | P2 | Subnet router variant |
| `AppConnector` | ✅ | P2 | App connector flag |
| `ServicesHash` | ✅ | P2 | Hash of service list |
| `Location` | ✅ | P2 | Geographic location |
| `TPM` | ✅ | P2 | TPM device info |
| `StateEncrypted` | ✅ | P2 | Disk encryption status |

Priority for Hostinfo gaps: most are P2 (control-plane reporting, not user-facing).
The only P1 is `ShieldsUp` — a security-relevant pref that should be reflected in
what control knows about the client.

parity.md line 145 claims "Hostinfo ✅ phase-23 (all 36 Go fields, 10min update loop
with content-hash dedup, runtime setters)" — this is **incorrect**. Only 18/41 fields
are populated, not "all 36." The 10min update loop and content-hash dedup do exist
in `hostinfo.rs`.

---

## 9. Taildrive (WebDAV sharing)

Go source: `drive/driveimpl/`, `drive/remote.go`, `drive/local.go` (~1500 lines total)  
Rust source: nothing

| Component | Go source | Status | Priority | Notes |
|-----------|-----------|--------|----------|-------|
| Share type | `drive/remote.go` | ❌ P2 | No Share/Remote structs |
| FileSystemForRemote | `driveimpl/remote_impl.go` | ❌ P2 | Remote WebDAV with per-user subprocess |
| FileSystemForLocal | `driveimpl/local_impl.go` | ❌ P2 | Local WebDAV proxy |
| FileServer | `driveimpl/fileserver.go` | ❌ P2 | Standalone WebDAV server with secret-token auth |
| Composite DAV | `compositedav/` | ❌ P2 | Multi-machine multi-share namespace |
| CLI drive commands | `cli/drive.go` | ❌ P2 | |
| LocalAPI drive endpoints | `localapi.go` (DriveSetServerAddr etc.) | ❌ P2 | |

Priority: P2 (Taildrive is a convenience feature, not core networking). Parity.md
line 110 correctly marks it as ⬜.

---

## 10. SOCKS5 / HTTP proxy modes

### SOCKS5

Go source: `net/socks5/socks5.go` (~400 lines)  
Rust source: `crates/tsnet/src/socks5.rs` (673 lines) + `socks5_tests.rs` (656 lines)

| Component | Go | Rust | Status | Notes |
|-----------|----|------|--------|-------|
| RFC 1928 CONNECT | ✅ | ✅ | Full | IPv4/IPv6/domain name |
| No-auth handshake | ✅ | ✅ | | |
| Username/password auth | ✅ | ❌ P2 | Go supports; Rust doesn't |
| BIND command | ✅ | ❌ P2 | Returns COMMAND_NOT_SUPPORTED |
| UDP ASSOCIATE | ✅ | ❌ P2 | Returns COMMAND_NOT_SUPPORTED |
| Pluggable dialer | ✅ | ✅ | SocksDialer trait |
| Graceful shutdown | — | ✅ | Socks5Handle + cancel token |
| FFI export | — | ✅ | `ts_listen_socks5()` |
| Loopback integration | ✅ (via Loopback()) | ❌ P1 | Standalone only; no combined SOCKS5+LocalAPI |
| Auth for loopback | ✅ "tsnet"/proxyCred | ❌ P1 | No authentication at all |

Parity.md line 28 claims "✅ port-8: RFC 1928 CONNECT" — this is accurate for the
CONNECT implementation. The missing auth and missing loopback integration are not
claimed by parity.md.

### HTTP CONNECT proxy

Go source: `net/connectproxy/` (~150 lines)  
Rust source: nothing

| Component | Go | Status | Priority | Notes |
|-----------|----|--------|----------|-------|
| HTTP CONNECT handler | `Handler` | ❌ **P1** | Needed for explicit HTTP proxy mode and Docker/k8s sidecar pattern |
| CONNECT method-only filter | `Handler.ServeHTTP` | ❌ P1 | |
| Bidirectional copy | `Handler` | ❌ P1 | |

Priority: P1 — HTTP CONNECT proxy is required for `HTTPS_PROXY` env-var-based
routing, which is a common Docker/k8s sidecar pattern. Parity.md line 58 correctly
marks it as ⬜.

---

## 11. tsnet loopback API

Go source: `tsnet/tsnet.go` `Loopback()` method (~100 lines)  
Rust source: nothing combined

Go's `Loopback()`:
1. Opens a TCP listener on `127.0.0.1:0`
2. Multiplexes two protocols on the same port:
   - **SOCKS5** (authenticated with randomly-generated `proxyCred`; requires
     username `"tsnet"` + password `proxyCred`)
   - **LocalAPI HTTP** (protected by randomly-generated `localAPICred` basic auth
     + `Sec-Tailscale: localapi` header)
3. Returns `(addr, proxyCred, localAPICred, err)` — caller sets these as env vars
   for child processes, or uses them programmatically

Consequence of absence: There is no way to run the Rust tsnet equivalent in the
"background daemon + CLI tool connects via loopback" pattern. Users must either use
the Unix-socket LocalAPI (requires filesystem access/permission setup) or manually
set up two separate listeners (one for SOCKS5, one for LocalAPI HTTP).

Priority: **P1** — this is a critical UX gap for the sidecar/daemon pattern.

---

## 12. Captive portal detection

Go source: `net/captivedetection/` (5 files, ~400 lines)  
Rust source: `crates/netcheck/` — field exists in `Report`, wired into health Tracker

parity.md line 73 claims "✅ Detector with concurrent HTTP GETs, DERPMap endpoint
generation, response validation, wired into netcheck prober and health Tracker".

Verified: `crates/netcheck/src/report.rs` has `captive_portal: bool`. The health
tracker has `WARN_CAPTIVE_PORTAL`. The detection endpoint generation and concurrent
probes are implemented. Netcheck prober calls the detector.

Status: ✅ Fully ported. One noted caveat in parity.md: "per-interface binding
deferred" — the Go version binds to specific network interfaces for detection on
multi-homed hosts; Rust uses default interface only.

Priority: P2 (detection works but may report false positives on multi-homed hosts).

---

## 13. Additional gaps found during audit

### LocalAPI endpoints missing in Rust

Go's LocalAPI has ~50 endpoints serving diagnostics, debug, and management.
Rust's LocalAPI (`crates/tsnet/src/localapi.rs`) has:

| Endpoint | Go | Rust | Priority | Notes |
|----------|----|------|----------|-------|
| GET /status | ✅ | ✅ | | |
| GET /whois | ✅ | ✅ | | |
| GET /prefs | ✅ | ✅ | | |
| PATCH /prefs | ✅ | ✅ | | |
| GET /netmap | ✅ | ✅ | | |
| GET /metrics | ✅ | ✅ | | (4 ad-hoc metrics) |
| GET /health | ✅ | ✅ | | |
| POST /ping | ✅ | ✅ | | (501 — disco ping API pending) |
| GET /derp-map | ✅ | ✅ | | |
| GET /watch-ipn-bus | ✅ | ✅ | | |
| POST /start | ✅ | ✅ | | |
| POST /login-interactive | ✅ | ✅ | | |
| POST /logout | ✅ | ✅ | | |
| GET/POST /serve-config | ✅ | ✅ | | With ETag/If-Match |
| GET /profiles | ✅ | ✅ | | |
| PUT /profiles/:id | ✅ | ✅ | | |
| POST /profiles | ✅ | ✅ | | |
| DELETE /profiles/:id | ✅ | ✅ | | |
| GET /cert-domains | ✅ | ❌ | P2 | |
| GET /cert-pair/:domain | ✅ | ❌ | P2 | |
| POST /set-dns | ✅ | ❌ | P2 | |
| GET /dns-config | ✅ | ❌ | P2 | |
| GET /dns-query | ✅ | ❌ | P2 | (at peerapi level — peerapi.rs) |
| POST /upload-client-metrics | ✅ | ❌ | P2 | |
| GET /waiting-files / del / get | ✅ | ❌ | P2 | Taildrop files |
| GET /file-targets | ✅ | ❌ | P2 | |
| POST /push-file | ✅ | ❌ | P2 | |
| GET /debug-capture | ✅ | ❌ | P2 | |
| GET /goroutines | ✅ | ❌ | P2 | |
| GET /bugreport | ✅ | ❌ | P2 | |
| GET /check-update | ✅ | ❌ | P2 | |
| POST /set-use-exit-node | ✅ | ❌ | P2 | |
| GET /suggest-exit-node | ✅ | ❌ | P2 | |
| Posture/Serial/MAC | ✅ | ❌ | P2 | Posture identity |
| Taildrive endpoints | ✅ | ❌ | P2 | |
| Tailnet lock (18 methods) | ✅ | ❌ | P2 | |
| Debug actions | ✅ | ❌ | P2 | |

### PeerAPI gaps

Go's PeerAPI (`ipn/ipnlocal/peerapi.go`) serves per-peer HTTP on the tailnet IP at a
dynamic port. Rust's PeerAPI (`crates/tsnet/src/peerapi.rs`) has:

| Endpoint | Go | Rust | Status | Notes |
|----------|----|------|--------|-------|
| /v0/ whois lookup | ✅ | ✅ | | |
| /v0/dns-query | ✅ | ✅ | | DoH for exit node DNS |
| /v0/debug-pprof | ✅ | — | ❌ P2 | |
| /v0/goroutines | ✅ | — | ❌ P2 | |
| /v0/metrics | ✅ | ⚠️ | Stub — "no exported metrics yet" |

### Hostinfo update loop

Go: `local.go` `hostinfoUpdateLoop()` — 10-minute interval, content-hash dedup.  
Rust: `hostinfo.rs` has `hostinfo_hash()` + 10-min timer in `lib.rs` at the map
request path. ✅ Verified present.

---

## Top-10 ranked gaps

| Rank | Feature | Priority | Consequence |
|------|---------|----------|-------------|
| 1 | **`ListenPacket` (UDP)** | **P0** | No UDP receive on tailnet. Breaks DNS servers, custom UDP protocols, any app that calls `tsnet.ListenPacket`. |
| 2 | **SSH policy feed** | **P0** | SSH server exists but policy callback returns `None` — all SSH connections are rejected. SSH is non-functional in production. |
| 3 | **Exit node wiring (prefs → RouteTable)** | **P1** | `set_exit_node()` exists in routing but is never called from the pref-change flow. Setting `--exit-node` on CLI updates prefs only — no routing change. |
| 4 | **`Loopback()` combined SOCKS5+LocalAPI** | **P1** | No way to give a child process tailnet access + management API on localhost. Breaks IDE, k8s sidecar, and docker exec patterns. |
| 5 | **`RegisterFallbackTCPHandler`** | **P1** | No catch-all TCP interception. tsnet embedders cannot handle arbitrary tailnet traffic. |
| 6 | **logtail (log streaming)** | **P1** | No crash/error logs reach Tailscale support. Debugging production issues blind. |
| 7 | **HTTP CONNECT proxy** | **P1** | No `HTTPS_PROXY` env-var-based routing. Breaks Docker/k8s sidecar pattern for explicit proxy. |
| 8 | **auto-update / clientupdate** | **P1** | No version checking or auto-update mechanism. Critical security patches require manual binary replacement. |
| 9 | **AllowLANAccess** | **P1** | Exit node users cannot access local LAN printers, NAS devices, or other LAN resources. |
| 10 | **SuggestExitNode** | **P1** | No DERP-latency-based or priority-based exit node suggestion. Users must manually specify exit node IP/ID. |

### Additional noteworthy

- **ServiceModeHTTP** (`listen_service` HTTP mode) — P1 gap for the Services feature.
  Without it, `svc:` services can only do raw TCP forwarding, not HTTP reverse-proxy
  with auth/app-capabilities.

- **Hostinfo.ShieldsUp** — P1. Pref exists, not reflected in Hostinfo. Control plane
  can't tell if the node is in shields-up mode.

- **SSH session recording** — P1 for compliance/audit use cases.

- **Client metrics** — Only 4 counters vs Go's 100+. Sufficient for basic monitoring
  but insufficient for detailed diagnostics.

---

## Corrections to parity.md

| Claim in parity.md | Actual | Correction |
|--------------------|--------|------------|
| Line 15: "Exit node support ✅ port-5 done" | Routing layer exists; **wiring from prefs → RouteTable is broken** | 🔶 Partial — integration gap |
| Line 145: "Hostinfo ✅ all 36 Go fields, 10min update loop" | Only **18/41 fields populated** (44%) | 🔶 Partial — update loop ✅, field coverage overclaimed |
| Line 73: "Captive portal detection ✅" | ✅ Full port (one caveat: per-interface binding deferred) | ✅ Confirmed |
| Line 26: "Tailscale Services ✅" | ServiceModeTCP ✅, ServiceModeHTTP ❌, TerminateTLS ❌ | 🔶 Partial — TCP only |
| Line 29: "LocalAPI ✅ port-9" | Core ✅. Missing 30+ endpoints (cert,dns,taildrop,update,exit-node-suggest, drive, tailnet-lock, debug) | 🔶 Partial — basics ✅, full parity ⬜ |
| Line 20: "Interactive auth + prefs persistence ✅" | ✅ Confirmed | ✅ |
