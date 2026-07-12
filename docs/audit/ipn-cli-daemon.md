# IPN / Daemon / CLI / LocalAPI — Parity Audit

Audit date: 2026-07-12
Scope: Go `master` (`tailscale/tailscale`) → Rust `master` (`rustscale`). **Taildrop and cert/QR are in flight in `.worktrees/`; marked "in flight", not flagged as missing.**

---

## 1. Prefs — Field-by-Field Diff

**Go source:** `tailscale/ipn/prefs.go:58` → `Prefs` struct (33 fields)
**Rust source:** `crates/ipn/src/prefs.rs:28` → `Prefs` struct (15 fields)

### Fields present in both

| Field | Go type | Rust type | Notes |
|-------|---------|-----------|-------|
| ControlURL | `string` | `String` | |
| WantRunning | `bool` | `bool` | |
| LoggedOut | `bool` | `bool` | |
| RouteAll | `bool` | `bool` | |
| ExitNodeID | `tailcfg.StableNodeID` | `String` | Go uses typed ID |
| ExitNodeIP | `netip.Addr` | `String` | Go uses typed Addr |
| CorpDNS | `bool` | `bool` | |
| ShieldsUp | `bool` | `bool` | |
| Hostname | `string` | `String` | |
| AdvertiseRoutes | `[]netip.Prefix` | `Vec<String>` | Go uses typed prefixes |
| AdvertiseTags | `[]string` | `Vec<String>` | |
| OperatorUser | `string` | `String` | |

### Fields MISSING from Rust (13 fields)

| Field | Go type | Priority | Notes |
|-------|---------|----------|-------|
| **ExitNodeAllowLANAccess** | `bool` | **P0** | CLI exposes `--exit-node-allow-lan-access`; required for exit node feature |
| **RunSSH** | `bool` | **P0** | Tailscale SSH server control; CLI exposes `--ssh` |
| **AutoExitNode** | `ExitNodeExpression` | **P0** | Auto-selected exit node expression (e.g. `any`) |
| **AutoUpdate** | `AutoUpdatePrefs` | **P1** | `{Check, Apply}` — Go CLI `--auto-update` flag |
| **NetfilterMode** | `preftype.NetfilterMode` | **P1** | Linux: `on`/`nodivert`/`off`; CLI `--netfilter-mode` flag |
| **NoSNAT** | `bool` | **P1** | Linux: source NAT for advertised routes; CLI `--snat-subnet-routes` |
| **NoStatefulFiltering** | `opt.Bool` | **P2** | Linux: stateful filtering for forwarded packets |
| **PostureChecking** | `bool` | **P1** | Collection of device posture data; CLI `--report-posture` |
| **AppConnector** | `AppConnectorPrefs` | **P1** | Advertise as app connector; CLI `--advertise-connector` |
| **ProfileName** | `string` | **P2** | User-visible profile display name |
| **RunWebClient** | `bool` | **P1** | Web client on port 5252 |
| **InternalExitNodePrior** | `StableNodeID` | **P2** | Internal: prior exit node for toggle |
| **AdvertiseServices** | `[]string` | **P2** | Service advertisement for VIP services |
| **NetfilterKind** | `string` | **P2** | Linux: iptables vs nftables |
| **DriveShares** | `[]*drive.Share` | **P2** | Taildrive share config |
| **RelayServerPort** | `*uint16` | **P2** | Peer relay server port |
| **RelayServerStaticEndpoints** | `[]netip.AddrPort` | **P2** | Static relay endpoints |
| **ForceDaemon** | `bool` | **P3** | Windows-only |
| **Egg** | `bool` | **P3** | Debug flag, rarely used |
| **NotepadURLs** | `bool` | **P3** | Windows-only |
| **AllowSingleHosts** | `bool` | **P3** | Legacy, always true |
| **Persist** | `*persist.Persist` | **P3** | Legacy persisted keys |
| **Sync** | `opt.Bool` | **P3** | Sync config from control (testing) |

### Rust-only Prefs fields

| Field | Purpose |
|-------|---------|
| `Ephemeral` | Ephemeral node flag |
| `AcceptRoutes` | Alias for RouteAll in CLI wiring |

### MaskedPrefs — Rust `MaskedPrefs` has 15 `*Set` bools; Go has 30+.
Missing Rust `MaskedPrefs` `*Set` fields mirror the Prefs gap above.

---

## 2. Notify — Field-by-Field Diff

**Go source:** `tailscale/ipn/backend.go` (approx line 250) → `Notify` struct (20+ fields)
**Rust source:** `crates/ipn/src/lib.rs:213` → `Notify` struct (9 fields)

### Fields present in both

| Field | Rust type | Consumers |
|-------|-----------|-----------|
| Version | `Option<String>` | watch-ipn-bus initial message |
| SessionID | `Option<String>` | WatchIPNBus session identification |
| ErrMessage | `Option<String>` | CLI error display |
| LoginFinished | `Option<bool>` | `tailscale up` waits for this |
| State | `Option<State>` | State machine transitions |
| Prefs | `Option<serde_json::Value>` | Pref change notifications |
| Engine | `Option<EngineStatus>` | Engine updates |
| BrowseToURL | `Option<String>` | Auth URL for CLI |
| InitialStatus | `Option<serde_json::Value>` | Initial status snapshot |

### Fields MISSING from Rust (14+)

| Field | Go type | Priority | Key Consumers |
|-------|---------|----------|---------------|
| **NetMap** | `*netmap.NetworkMap` | **P0** | `WatchIPNBus` subscribers, GUI, status |
| **PeersChanged** | `[]*tailcfg.Node` | **P0** | Peer delta notifications |
| **PeersRemoved** | `[]tailcfg.NodeID` | **P0** | Peer delta notifications |
| **PeerChangedPatch** | `[]*tailcfg.PeerChange` | **P0** | Field-level peer patches |
| **UserProfiles** | `map[UserID]UserProfileView` | **P1** | User profile updates |
| **Health** | `*health.State` | **P1** | Health tracking consumers |
| **ClientVersion** | `*tailcfg.ClientVersion` | **P1** | `tailscale update` |
| **SuggestedExitNode** | `*tailcfg.StableNodeID` | **P1** | Exit node suggestion |
| **DriveShares** | `views.SliceView` | **P2** | Taildrive |
| **OutgoingFiles** | `[]*OutgoingFile` | **P2** | Taildrop (in flight) |
| **LocalTCPPort** | `*uint16` | **P2** | macOS Network Extension |
| **SelfChange** | `*tailcfg.Node` | **P2** | Self node attribute changes |
| **InitialStatus** on Go: includes full `ipnstate.Status` | `*ipnstate.Status` | **P0** | Initial full-status snapshot |
| **PeerState** | `map[StableNodeID]PeerState` | **P2** | WireGuard session states |

### NotifyWatchOpt — Rust defines all same bits (0-16, 18), Go also has bits.
Rust constants match Go exactly (explicit bit values).

---

## 3. LocalAPI — Handler Inventory

**Go source:** `tailscale/ipn/localapi/localapi.go:70` + `debug.go`, `cert.go`, `serve.go`, `tailnetlock.go`, `localapi_drive.go`, `syspolicy_api.go`
**Rust source:** `crates/tsnet/src/localapi.rs:464`

### Handlers present in both (14)

| Path | Go | Rust |
|------|----|------|
| `GET /localapi/v0/status` | `serveStatus` | `build_status_json` |
| `GET /localapi/v0/whois` | `serveWhoIs` | `handle_whois` |
| `GET/PATCH /localapi/v0/prefs` | `servePrefs` | inline + `handle_patch_prefs` |
| `POST /localapi/v0/start` | `serveStart` | `handle_start` |
| `POST /localapi/v0/login-interactive` | `serveLoginInteractive` | inline (notify trigger) |
| `POST /localapi/v0/logout` | `serveLogout` | `handle_logout` |
| `GET /localapi/v0/metrics` | `serveMetrics` | `build_metrics_text` |
| `GET /localapi/v0/health` | (via ServeConfig) | `build_health_json` |
| `GET /localapi/v0/netmap` | (via debug) | `build_netmap_json` |
| `POST /localapi/v0/ping` | `servePing` | `handle_ping` (returns 501) |
| `GET /localapi/v0/watch-ipn-bus` | `serveWatchIPNBus` | `handle_watch_ipn_bus` |
| `GET/POST /localapi/v0/serve-config` | `serveServeConfig` | `handle_get/post_serve_config` |
| `GET/PUT/POST/DELETE /localapi/v0/profiles` | `serveProfiles` | `handle_list/new/profile_subpath` |
| `GET /` | `serveLocalAPIRoot` | inline (lists endpoints) |

### Go endpoints MISSING from Rust

#### Core (always registered) — P0/P1

| Path | Method | Priority | Description |
|------|--------|----------|-------------|
| `check-prefs` | POST | **P1** | Validate prefs before applying |
| `derpmap` | GET | **P1** | DERP map for netcheck |
| `dns-config` | GET | **P1** | DNS config from netmap |
| `goroutines` | GET | **P2** | Goroutine dump |
| `peer-by-id` | GET | **P2** | Peer lookup by NodeID |
| `reload-config` | POST | **P2** | Reload declarative config |
| `reset-auth` | POST | **P1** | Reset auth state |
| `services` | GET | **P2** | Node services list |
| `set-expiry-sooner` | POST | **P1** | Set node expiry earlier |
| `shutdown` | POST | **P1** | Shut down daemon |
| `user-profile` | GET | **P2** | User profile by UserID |
| `check-so-mark-in-use` | GET | **P3** | Linux SO_MARK check |
| `cert-domains` | GET | **P1** | List cert domains |

#### Feature-gated (always compiled in Rust for now)

| Path | Go Feature Gate | Priority | Description |
|------|----------------|----------|-------------|
| `appc-route-info` | HasAppConnectors | **P1** | App connector route info |
| `check-ip-forwarding` | HasAdvertiseRoutes | **P1** | Check IP forwarding |
| `check-udp-gro-forwarding` | HasAdvertiseRoutes | **P2** | Check UDP GRO |
| `set-udp-gro-forwarding` | HasAdvertiseRoutes | **P2** | Set UDP GRO |
| `upload-client-metrics` | HasClientMetrics | **P1** | Upload client metrics |
| `update/check` | HasClientUpdate | **P1** | Check for updates |
| `suggest-exit-node` | HasUseExitNode | **P1** | Suggest exit node |
| `set-use-exit-node-enabled` | HasUseExitNode | **P1** | Toggle exit node |
| `set-dns` | HasACME | **P1** | Set DNS record (ACME) |
| `bugreport` | HasDebug | **P1** | Bug report generation |
| `pprof` | HasDebug | **P2** | Go pprof (not applicable) |
| `dns-osconfig` | HasDNS | **P1** | OS DNS config |
| `dns-query` | HasDNS | **P1** | DNS query via internal resolver |
| `usermetrics` | HasUserMetrics | **P2** | User-facing metrics |
| `query-feature` | HasServe | **P2** | Query feature enablement |
| `dial` | HasOutboundProxy\|SSH | **P1** | WebSocket dial |
| `disconnect-control` | HasDebug\|Routes | **P2** | Disconnect from control |
| `id-token` | HasDebug | **P1** | OIDC ID token |
| `alpha-set-device-attrs` | HasDebug | **P2** | Set device attributes |
| `handle-push-message` | HasDebug | **P3** | Handle push message |
| `set-push-device-token` | HasDebug | **P3** | Set push device token |
| `set-gui-visible` | HasDebug\|Win\|Mac | **P3** | GUI visibility |
| `logtap` | HasLogTail | **P2** | Stream daemon logs |

#### Debug handlers (in Go `localapi/debug.go`)

| Path | Priority | Description |
|------|----------|-------------|
| `component-debug-logging` | **P2** | Get/set component debug logging |
| `debug` | **P2** | Generic debug actions |
| `debug-rotate-disco-key` | **P2** | Rotate disco key |
| `dev-set-state-store` | **P2** | Dev: set state store value |
| `debug-bus-events` | **P2** | Stream event bus events |
| `debug-bus-graph` | **P2** | Event bus graph |
| `debug-bus-queues` | **P2** | Event bus queues |
| `debug-derp-region` | **P2** | DERP region debug |
| `debug-dial-types` | **P2** | Dial types debug |
| `debug-log` | **P2** | Debug logging |
| `debug-packet-filter-matches` | **P2** | Packet filter matches |
| `debug-packet-filter-rules` | **P2** | Packet filter rules |
| `debug-peer-endpoint-changes` | **P2** | Peer endpoint changes |
| `debug-optional-features` | **P2** | Optional features |

#### Cert/TKA/Drive (separate Go files)

| Path | Priority | Description |
|------|----------|-------------|
| `cert/` | **P0** | TLS cert pair retrieval (in flight) |
| `tka/status`, `tka/init`, `tka/sign`, `tka/modify`, etc (12 paths) | **P2** | Tailnet Lock (TKA) |
| `drive/fileserver-address` | **P2** | Taildrive server addr |
| `drive/shares` | **P2** | Taildrive shares CRUD |
| `policy/` | **P3** | Syspolicy API |

---

## 4. CLI — Subcommand + Flag Diff

**Go source:** `tailscale/cmd/tailscale/cli/` (86 files, ~35 subcommands)
**Rust source:** `crates/cli/src/commands/` (16 subcommand modules)

### Subcommands in both

| Subcommand | Go Flags (notable) | Rust | Rust flag gaps |
|-----------|-------------------|------|----------------|
| `up` | 28 flags | ✅ | **Missing flags:** `--accept-risk`, `--advertise-connector`, `--audience`, `--client-id`, `--client-secret`, `--exit-node-allow-lan-access`, `--id-token`, `--login-server`, `--netfilter-mode`, `--nickname`, `--operator`, `--qr`, `--qr-format`, `--snat-subnet-routes`, `--ssh`, `--stateful-filtering`, `--unattended` |
| `down` | — | ✅ | |
| `login` | `--json`, `--timeout` | ✅ | Lacks `--nickname` |
| `logout` | — | ✅ | |
| `switch` | `--list`, `--json` | ✅ | |
| `status` | `--json`, `--self`, `--peers`, `--active`, `--web`, `--watch`, `--monitor-ipn` | ✅ | **Missing flags:** `--self`, `--web`, `--watch`, `--monitor-ipn` |
| `set` | 17 flags | ✅ | **Missing flags:** `--accept-risk`, `--auto-update`, `--advertise-connector`, `--exit-node-allow-lan-access`, `--netfilter-mode`, `--operator`, `--posture-checking`, `--snat-subnet-routes`, `--ssh`, `--stateful-filtering`, `--unattended` |
| `get` | `--json` | ✅ | |
| `ip` | `-4`, `-6`, `-1` | ✅ | |
| `version` | `--json`, `--daemon` | ✅ | |
| `whois` | `--json` | ✅ | **Missing:** `nodekey:` prefix support, `--socket` |
| `netcheck` | — | ✅ | |
| `ping` | `--c`, `--until`, `--size`, `--verbose`, `--tsmp`, `--peer-api` | ⚠️ (stub) | Returns 501; all flags missing |
| `metrics` | — | ✅ | |
| `serve` | `--bg`, `--https`, `--http`, `--tcp`, `--tls-terminated-tcp`, `--set-path`, `--foreground` | ✅ | **Missing:** `--foreground` / foreground mode (CLI says "not supported") |
| `funnel` | same as serve | ✅ | Same gaps |
| `health` | (implied by `status --health`) | ✅ | Rust has dedicated `health` cmd |

### Go subcommands MISSING from Rust

| Subcommand | Priority | Go source | Description |
|-----------|----------|-----------|-------------|
| **`file cp` / `file get`** | **P0** | `file.go` | Taildrop file send/receive (in flight) |
| **`cert`** | **P0** | `cert.go` | TLS cert management (in flight) |
| **`debug`** | **P1** | `debug.go` | Debug subcommands (netmap, disco-key, prefs, watch-ipn, derp-map, peer-endpoint-changes, metrics, component-logs, capture, etc) |
| **`bugreport`** | **P1** | `bugreport.go` | Bug report generation |
| **`ssh`** | **P1** | `ssh.go` | SSH to a Tailscale node |
| **`nc`** | **P1** | `nc.go` | Netcat over tailnet |
| **`id-token`** | **P1** | `id-token.go` | OIDC ID token request |
| **`exit-node list`/`suggest`** | **P1** | `exitnode.go` | Exit node listing/suggestion |
| **`update`** | **P1** | `update.go` | Auto-update check/apply |
| **`dns status`/`query`** | **P1** | `dns.go` | DNS status and queries |
| **`configure`** | **P2** | `configure.go` | Host configuration |
| **`licenses`** | **P2** | `licenses.go` | Open source licenses |
| **`tailnet lock`** | **P2** | `tailnet-lock.go` | Tailnet Lock management |
| **`drive`** | **P2** | `drive.go` | Taildrive share management |
| **`web`** | **P2** | `web.go` | Web client |
| **`systray`** | **P3** | `systray.go` | Systray control (GUI) |
| **`wait`** | **P2** | `wait.go` | Wait for tailscaled |
| **`appc-routes`** | **P2** | `appcroutes.go` | App connector routes |
| **`headscale`** | **P3** | (via flag) | Headscale specific |

---

## 5. Daemon (tailscaled / rustscaled) — Startup Modes + Flags

**Go source:** `tailscale/cmd/tailscaled/tailscaled.go`
**Rust source:** `crates/rustscaled/src/main.rs`

### Startup modes

| Mode | Go | Rust | Notes |
|------|----|------|-------|
| Normal daemon | ✅ | `run` | Default |
| `install-system-daemon` | ✅ (launchd+systemd) | ✅ (launchd only) | Rust: macOS only |
| `uninstall-system-daemon` | ✅ | ✅ (launchd only) | Rust: macOS only |
| `--cleanup` | ✅ | ❌ **MISSING P1** | Remove netfilter rules, routes |
| Windows service | ✅ | ❌ **P3** | n/a for now |
| `be-child` | ✅ | ❌ **P3** | Internal child mode |

### Daemon flags

| Flag | Go | Rust | Priority | Notes |
|------|----|------|----------|-------|
| `--tun` | ✅ | `--tun` | — | Both support flag-only mode |
| `--statedir` | ✅ | `--statedir` | — | Both |
| `--hostname` | ✅ | `--hostname` | — | Rust: daemon-level flag |
| `--port` | ✅ | ❌ **P1** | UDP listen port (or PORT env) |
| `--state` | ✅ | ❌ **P1** | Separate from `--statedir`; supports `kube:/` `arn:/` `mem:` |
| `--socket` | ✅ | ❌ **P1** | Socket path override |
| `--socks5-server` | ✅ | ❌ **P1** | SOCKS5 proxy address |
| `--http-proxy-server` | ✅ | ❌ **P1** | HTTP proxy address |
| `--debug` | ✅ | ❌ **P2** | Debug server listen address |
| `--verbose` | ✅ | ❌ **P2** | Log verbosity level |
| `--no-logs-no-support` | ✅ | ❌ **P2** | Disable log uploads |
| `--config` | ✅ | ❌ **P2** | Config file path |
| `--bird-socket` | ✅ | ❌ **P3** | BIRD routing socket |
| `--encrypt-state` | ✅ | ❌ **P3** | TPM-based state encryption |
| `--hardware-attestation` | ✅ | ❌ **P3** | Hardware-backed keys |

### Environment variable knobs

| Env var | Go | Rust | Priority | Notes |
|---------|----|------|----------|-------|
| `PORT` | ✅ | ❌ | **P1** | UDP port override |
| `TS_AUTHKEY` | — | ✅ | — | Rust uses this for auto-up |
| `TS_LOG_VERBOSITY` | ✅ | ❌ | **P2** | Default log verbosity |
| `TS_BE_CLI` | ✅ | ❌ | **P3** | Force CLI mode |
| `TS_DEBUG_BACKEND_DELAY_SEC` | ✅ | ❌ | **P3** | Testing |
| `TS_DEBUG_CONTROL_FLAGS` | ✅ | ❌ | **P3** | Testing |
| `TS_DEBUG_WHOIS` | ✅ | ❌ | **P3** | Debug whois |
| `TS_PARENT_DEATH_FD` | ✅ | ❌ | **P3** | Parent death FD |

---

## 6. LocalClient — Method Surface

**Go source:** `tailscale/client/local/local.go` (~1550 lines, ~60+ methods)
**Rust source:** `crates/localclient/src/lib.rs` (~600 lines, 21 methods)

### Methods present in both (14)

| Method | Go | Rust |
|--------|----|------|
| `Status(ctx)` | ✅ | `status()` |
| `WhoIs(ctx, addr)` | ✅ | `whois(addr)` |
| `GetPrefs(ctx)` | ✅ | `get_prefs()` |
| `EditPrefs(ctx, mp)` | ✅ | `edit_prefs(masked)` |
| `StartLoginInteractive(ctx)` | ✅ | `login_interactive()` |
| `Logout(ctx)` | ✅ | `logout()` |
| `Ping(ctx, ip, pingtype)` | ✅ | `ping(ip, pingtype)` |
| `PingWithOpts(...)` | ✅ | — (no opts variant) |
| `GetServeConfig(ctx)` | ✅ | `get_serve_config()` |
| `SetServeConfig(ctx, config)` | ✅ | `set_serve_config()` |
| `ProfileStatus(ctx)` | ✅ | `list_profiles()` / `current_profile()` |
| `NewProfile(ctx)` | ✅ | `new_profile()` |
| `SwitchProfile(ctx, id)` | ✅ | `switch_profile(id)` |
| `DeleteProfile(ctx, id)` | ✅ | `delete_profile(id)` |
| (netmap) | — | `netmap()` (Rust-only, no Go equivalent) |
| (metrics) | — | `metrics()` (Rust-only from localapi) |
| (health) | — | `health()` (Rust-only) |
| (derp_map) | — | `derp_map()` (Rust-only convenience) |
| (watch_ipn_bus) | — | `watch_ipn_bus()` (Rust-only) |

### Go LocalClient methods MISSING from Rust

| Method Group | Missing Methods | Priority |
|-------------|----------------|----------|
| **Taildrop** | `WaitingFiles`, `AwaitWaitingFiles`, `DeleteWaitingFile`, `GetWaitingFile`, `FileTargets`, `PushFile` | **P0** (in flight) |
| **Cert/ACME** | `CertPair`, `CertPairWithValidity`, `CertDomains`, `SetDNS`, `GetCertificate`, `ExpandSNIName` | **P0** (in flight) |
| **Status** | `StatusWithoutPeers` | **P2** |
| **WhoIs** | `WhoIsForService`, `WhoIsForIP`, `WhoIsNodeKey`, `WhoIsProto` | **P1** |
| **Start** | `Start(ctx, opts)` (full options) | **P1** (Rust has simpler `start(options)`) |
| **Ping** | `PingWithOpts` | **P2** |
| **Tailnet Lock** | `TailnetLockStatus/Init/Sign/Modify/Disable/Log/AffectedSigs/...` (15+ methods) | **P2** |
| **Debug** | `Goroutines`, `DaemonMetrics`, `UserMetrics`, `Pprof`, `BugReport`, `DebugAction`, `DebugActionBody`, `DebugResultJSON`, `IncrementCounter/Gauge`, `SetGauge`, `TailDaemonLogs`, `QueryOptionalFeatures`, `SetDevStoreKeyValue`, `SetComponentDebugLogging`, `DebugPortmap`, `EventBusGraph/Queues/StreamBusEvents` | **P1** |
| **Network** | `CheckIPForwarding`, `CheckUDPGROForwarding`, `SetUDPGROForwarding`, `DisconnectControl` | **P1** |
| **DNS** | `GetDNSOSConfig`, `QueryDNS`, `CurrentDERPMap`, `DNSConfig` | **P1** |
| **Auth/Config** | `IDToken`, `ReloadConfig`, `CheckPrefs`, `DoLocalRequest` | **P1** |
| **Dial** | `DialTCP`, `UserDial` | **P1** |
| **Routes** | `RouteCheckProbe`, `RouteCheck` | **P2** |
| **Policy** | `GetEffectivePolicy`, `ReloadEffectivePolicy` | **P2** |
| **SetExpirySooner** | `SetExpirationSooner` | **P1** |
| **UploadClientMetrics** | `UploadClientMetrics` | **P2** |

---

## 7. State Machine

Both Go (`ipn.State`) and Rust (`crates/ipn/src/lib.rs:44`) define the same 7 states with identical integer values (0-6) and string names.

### Rust backend `update_inputs` — wiring gaps

The Rust `IpnBackend.update_inputs` in `crates/ipn/src/backend.rs:88` hardcodes two inputs that Go's `LocalBackend` manages dynamically:
- `logged_out: false` — Go sets this from `b.prefs.LoggedOut`
- `blocked: false` — Go sets this from `b.blocked` (`InUseOtherUser` path)

**Impact:** The state machine can never enter `InUseOtherUser`, and logout may not correctly transition `NeedsLogin` → `Stopped` in all cases. **P1.**

### Go `LocalBackend` additional methods not in `IpnBackend`

Go's LocalBackend has ~80 public methods. Rust's `IpnBackend` has 17. The rest are handled via LocalAPI commands or don't exist yet. This is by design (Rust uses a command-pattern rather than direct-method-call architecture), but means:
- No `StartLoginInteractiveAs` actor-based auth (P2)
- No `EditPrefsAs` actor-based prefs (P2)
- No `SetWantRunning` toggle (P1 — the daemon sets this at startup and never toggles it dynamically)
- No `SetExpirySooner` (P1)
- No `Logout` actor-based (P1 — handled by LocalAPI directly)
- No `Ping` backend implementation (P1 — returns 501)
- No `SetDeviceAttrs` (P2)
- No `SuggestExitNode` (P1)

---

## 8. C2N Handler Coverage

**Go source:** `tailscale/ipn/ipnlocal/c2n.go`, `cert.go`, `serve.go`
**Rust source:** `crates/c2n/src/lib.rs`

### Go C2N handlers

| Path | Go handler | Rust covered? | Notes |
|------|-----------|---------------|-------|
| `/echo` | `handleC2NEcho` | ✅ (stub) | |
| `POST /logtail/flush` | `handleC2NLogtailFlush` | ✅ (no-op 204) | |
| `POST /sockstats` | `handleC2NSockStats` | ✅ (stub) | |
| `/debug/pprof/heap` | `handleC2NPprof` | ⚠️ (returns 501) | No Rust pprof |
| `/debug/pprof/allocs` | `handleC2NPprof` | ⚠️ (returns 501) | No Rust pprof |
| `/debug/goroutines` | `handleC2NDebugGoroutines` | ✅ (stub) | Returns explanatory text |
| `/debug/prefs` | `handleC2NDebugPrefs` | ✅ | Via C2nBackend trait |
| `/debug/metrics` | `handleC2NDebugMetrics` | ✅ | Prometheus text |
| `/debug/component-logging` | `handleC2NDebugComponentLogging` | ✅ | |
| `/debug/logheap` | `handleC2NDebugLogHeap` | ✅ (stub) | |
| `/debug/netmap` | `handleC2NDebugNetMap` | ✅ | |
| `/debug/health` | `handleC2NDebugHealth` | ✅ | |
| `POST /netfilter-kind` | `handleC2NSetNetfilterKind` | ❌ **P2** | Linux-only |
| `GET /tls-cert-status` | `handleC2NTLSCertStatus` | ❌ **P1** | TLS cert status (in flight) |
| `GET /vip-services` | `handleC2NVIPServicesGet` | ❌ **P2** | VIP services |

### Rust C2N handle `/local/*` paths
Rust C2N explicitly returns 501 for `/local/*` paths. Go handles these via the embedded LocalAPI server. **P2.**

---

## 9. Serve/Funnel Config Surface

**Go source:** `tailscale/ipn/serve.go`, `tailscale/ipn/ipnlocal/serve.go`
**Rust source:** `crates/tsnet/src/serve.rs`

### ServeConfig fields

| Field | Go | Rust | Notes |
|-------|----|------|-------|
| `TCP` | `map[uint16]*TCPPortHandler` | `BTreeMap<u16, TCPPortHandler>` | Equivalent |
| `Web` | `map[HostPort]*WebServerConfig` | `BTreeMap<HostPort, WebServerConfig>` | Equivalent |
| `AllowFunnel` | `map[HostPort]bool` | `BTreeMap<HostPort, bool>` | Equivalent |
| `Services` | `map[ServiceName]*ServiceConfig` | ❌ **P1** | VIP service config |
| **`Foreground`** | `map[string]*ServeConfig` | ❌ **P1** | Ephemeral per-session foreground configs |
| `ETag` | `string` | (computed via `etag()`) | Equivalent |

### TCPPortHandler fields

| Field | Go | Rust | Notes |
|-------|----|------|-------|
| `HTTPS` | `bool` | `bool` | |
| `HTTP` | `bool` | `bool` | |
| `TCPForward` | `string` | `String` | |
| `TerminateTLS` | `string` | `String` | |
| `ProxyProtocol` | `int` | ❌ **P2** | PROXY protocol header version |

### HTTPHandler fields

| Field | Go | Rust | Notes |
|-------|----|------|-------|
| `Proxy` | `string` | `String` | |
| `Text` | `string` | `String` | |
| `Path` | `string` | `String` | Rust: present but file-serving not implemented |
| `Redirect` | `string` | ❌ **P1** | Redirect target URL |
| `AcceptAppCaps` | `[]PeerCapability` | ❌ **P2** | Peer caps for grant header |

### Serve/Funnel Rust gaps

| Feature | Priority | Notes |
|---------|----------|-------|
| **Foreground sessions** | **P1** | Go's `serve --bg` flag is required; Rust CLI refuses foreground mode with error |
| **HTTPS redirect** (HTTP→HTTPS) | **P1** | Go automatically redirects HTTP to HTTPS on serve ports |
| **File serving** (`HTTPHandler.Path`) | **P2** | Field present, serving not implemented |
| **Tailscale-Ingress-Target header dispatch** | **P1** | Go dispatches funnel traffic via this header; Rust uses direct listener dispatch |
| **Funnel node attribute check** | **P1** | Rust has `check_funnel_access` but `HostInfo.IngressEnabled` wiring is pending |
| **ProxyProtocol** | **P3** | PROXY protocol v1/v2 support |
| **Serve config file watching** | **P2** | Go `conffile` packages watches config file; Rust requires LocalAPI POST |
| **ServiceConfig** (`ServeConfig.Services`) | **P1** | VIP service mappings from netmap |
| **Log stream / `--foreground` in CLI** | **P1** | Go serve foreground mode streams access logs to terminal |
| **Mount cleanup on IPN bus disconnection** | **P1** | Go's `DeleteForegroundSession` on IPN bus disconnect |

---

## 10. Profile Manager

**Go source:** `tailscale/ipn/ipnlocal/profiles.go` — full `profileManager` with auto-switch, key renewal, control URL tracking
**Rust source:** `crates/ipn/src/profiles.rs` — basic load/save/CRUD, `crates/tsnet/src/localapi.rs` — profiles handlers

### Rust gaps

| Feature | Priority | Notes |
|---------|----------|-------|
| **Auto profile switch on login** | **P1** | Go switches to a new or existing profile after login; Rust does not auto-detect/login |
| **Seamless key renewal across profiles** | **P1** | Go handles node key expiration with profile-aware re-registration |
| **Profile's ControlURL tracking in daemon** | **P2** | Rust LocalAPI switches ControlURL in prefs on profile switch |
| **NetworkProfile from netmap** | **P2** | Go stores DomainName/DisplayName per profile; Rust tracks but doesn't auto-fill from netmap |
| **Multiple profiles auto-detection** | **P1** | Go detects when state is from a different user; Rust doesn't check |
| **UserProfile.Lookup on login** | **P2** | Go fills ProfileName/UserProfile from control response |

---

## 11. Captive Portal Detection

**Go source:** `tailscale/ipn/ipnlocal/captiveportal.go` — runs periodic captive portal detection loop, integrates with health tracker
**Rust source:** `crates/netcheck/src/captivedetection.rs` — modular detection logic, `crates/netcheck/src/prober.rs` — runs during netcheck

Captive portal detection is partially implemented in Rust:
- Detection logic (DERP challenge, body comparison): ✅ **DONE**
- Integration with netcheck report: ✅ **DONE** (as `captive_portal: Option<bool>`)
- **Missing:** Integration with health tracker (`WARN_CAPTIVE_PORTAL` is defined but never set from detection) — **P1**
- **Missing:** Backend periodic detection loop independent of netcheck — **P2**
- **Missing:** C2N captive portal status endpoint — **P3**

---

## Gap Summary by Priority

### P0 — Blockers for CLI/daemon parity
1. Prefs: **ExitNodeAllowLANAccess**, **RunSSH**, **AutoExitNode** missing
2. Notify: **NetMap**, **PeersChanged**, **PeersRemoved**, **PeerChangedPatch** missing
3. LocalAPI: **cert/** endpoints missing (in flight)
4. CLI: **file**, **cert** subcommands missing (in flight)
5. State machine: `logged_out`, `blocked` hardcoded to `false` — never enters `InUseOtherUser`
6. Serve: Foreground sessions not supported; HTTPS redirect missing

### P1 — Important near-term gaps
1. Prefs: AutoUpdate, NetfilterMode, NoSNAT, PostureChecking, AppConnector, RunWebClient missing
2. Notify: Health, ClientVersion, SuggestedExitNode, UserProfiles, InitialStatus (full) missing
3. LocalAPI: check-prefs, set-expiry-sooner, shutdown, start (full), bugreport, id-token, dial, update/check, dns-config, dns-query, suggest-exit-node, set-use-exit-node-enabled, set-dns, derpmap, whois-for-service, whois-nodekey missing
4. CLI: debug, bugreport, ssh, nc, id-token, exit-node, update, dns subcommands missing; many flags missing from up/set
5. Daemon: --port, --state, --socket, --socks5-server, --http-proxy-server, --cleanup missing
6. LocalClient: Debug actions, cert/ACME, taildrop, dial, DNS query, check-ip-forwarding, whois variants missing
7. Serve: Foreground mode, HTTPS redirect, Tailscale-Ingress-Target dispatch, ServiceConfig, HTTPHandler.Redirect
8. Captive portal: health tracker integration
9. C2N: tls-cert-status missing (in flight)
10. Profile manager: auto switch on login, key renewal across profiles, auto-detection

### P2 — Secondary gaps
1. Prefs: NoStatefulFiltering, ProfileName, AdvertiseServices, DriveShares, InternalExitNodePrior, NetfilterKind, RelayServerPort/Endpoints
2. Notify: DriveShares, OutgoingFiles, LocalTCPPort, SelfChange, PeerState
3. LocalAPI: goroutines, pprof, debug-bus-*, component-debug-logging, dev-set-state-store, peer-by-id, user-profile, services, reload-config, reset-auth, tka/* (12 paths), drive/*, logs/tap, set-device-attrs, usermetrics
4. CLI: configure, licenses, tailnet lock, drive, web, wait, appc-routes
5. Daemon: --debug, --verbose, --no-logs-no-support, --config
6. Serve: HTTPHandler.Path file serving, ProxyProtocol, config file watching
7. C2N: /local/*, netfilter-kind, vip-services
8. TKA control plane integration
9. State machine: more nuanced transition handling (deferred cleanup)

### P3 — Low priority
1. Windows-specific: ForceDaemon, NotepadURLs, --unattended, Windows service mode, systray command
2. Legacy: Egg, Persist, AllowSingleHosts, Sync
3. Edge: headscale subcommand, be-child mode, bird-socket, hardware-attestation
4. set-gui-visible, handle-push-message, set-push-device-token

---

## Top 10 Ranked Items

| Rank | Gap | Category | Priority | Effort | Impact |
|------|-----|----------|----------|--------|--------|
| 1 | **State machine never enters `InUseOtherUser` or `Stopped` correctly** (`logged_out`/`blocked` wiring) | State Machine | P0 | 1 day | Fundamental state correctness; all downstream consumers switch on BackendState |
| 2 | **Notify missing NetMap + peer delta fields** | Notify | P0 | 3 days | `watch-ipn-bus` lacks peer lists; GUI/status consumers get empty peers |
| 3 | **Ping returns 501** (no disco ping API in magicsock) | LocalAPI/CLI | P0 | 3 days | `tailscale ping` is broken; core debugging tool |
| 4 | **Prefs missing ExitNodeAllowLANAccess + RunSSH + AutoExitNode** | Prefs | P0 | 2 days | `--exit-node-allow-lan-access`, `--ssh`, auto exit-node selection don't work |
| 5 | **CLI missing `debug` subcommand** | CLI | P1 | 5 days | No way to dump netmap, prefs, disco key, watch-ipn from CLI |
| 6 | **Daemon missing `--socks5-server` and `--http-proxy-server`** | Daemon | P1 | 3 days | Required for SOCKS5/HTTP proxy sidecar patterns |
| 7 | **Serve foreground mode + HTTPS redirect not supported** | Serve | P1 | 5 days | CLI requires `--bg` flag; HTTP→HTTPS redirect missing |
| 8 | **LocalAPI missing `bugreport`, `set-expiry-sooner`, `shutdown`, `update/check`** | LocalAPI | P1 | 4 days | CLI tooling depends on these for basic lifecycle |
| 9 | **Captive portal detection not wired to health tracker** | Health | P1 | 1 day | `WARN_CAPTIVE_PORTAL` never fires; health status incomplete |
| 10 | **Profile manager: no auto-switch on login, no key renewal across profiles** | Profiles | P1 | 3 days | Multi-profile support is fragile; manual switching required |

---

## Appendix: Go Source Paths (Reference)

| Area | Go source |
|------|-----------|
| Prefs definition | `tailscale/ipn/prefs.go` |
| Notify/State | `tailscale/ipn/backend.go` |
| LocalAPI core | `tailscale/ipn/localapi/localapi.go` |
| LocalAPI debug | `tailscale/ipn/localapi/debug.go` |
| LocalAPI cert | `tailscale/ipn/localapi/cert.go` |
| LocalAPI serve | `tailscale/ipn/localapi/serve.go` |
| LocalAPI drive | `tailscale/ipn/localapi/localapi_drive.go` |
| LocalAPI tailnetlock | `tailscale/ipn/localapi/tailnetlock.go` |
| LocalAPI pprof | `tailscale/ipn/localapi/pprof.go` |
| LocalAPI syspolicy | `tailscale/ipn/localapi/syspolicy_api.go` |
| C2N | `tailscale/ipn/ipnlocal/c2n.go` |
| LocalBackend | `tailscale/ipn/ipnlocal/local.go` |
| Serve config | `tailscale/ipn/serve.go` |
| Backend serve | `tailscale/ipn/ipnlocal/serve.go` |
| Captive portal | `tailscale/ipn/ipnlocal/captiveportal.go` |
| Profile manager | `tailscale/ipn/ipnlocal/profiles.go` |
| Expiry manager | `tailscale/ipn/ipnlocal/expiry.go` |
| CLI main | `tailscale/cmd/tailscale/cli/cli.go` |
| CLI up | `tailscale/cmd/tailscale/cli/up.go` |
| CLI set | `tailscale/cmd/tailscale/cli/set.go` |
| CLI serve | `tailscale/cmd/tailscale/cli/serve_v2.go` |
| CLI funnel | `tailscale/cmd/tailscale/cli/funnel.go` |
| CLI debug | `tailscale/cmd/tailscale/cli/debug.go` |
| CLI status | `tailscale/cmd/tailscale/cli/status.go` |
| CLI cert | `tailscale/cmd/tailscale/cli/cert.go` |
| CLI file | `tailscale/cmd/tailscale/cli/file.go` |
| CLI bugreport | `tailscale/cmd/tailscale/cli/bugreport.go` |
| tailscaled | `tailscale/cmd/tailscaled/tailscaled.go` |
| ipnserver | `tailscale/ipn/ipnserver/server.go` |
| safesocket | `tailscale/safesocket/safesocket.go` |
| LocalClient | `tailscale/client/local/local.go` |
| Health state | `tailscale/health/health.go` (not ipn/ but relevant) |
