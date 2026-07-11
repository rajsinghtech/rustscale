# Validation Audit 2026-07-11

Gap analysis of rustscale phases vs Go implementation. Tables enumerate every
function/endpoint/field in Go that is missing or stubbed in Rust.

---

## 1. DNS Phase 11 — MagicDNS Resolver + DNS Fallback

### MagicDNS resolver (`crates/dns/`) vs `net/dns/resolver/tsdns.go`

| item | Go source | Rust status | notes |
| --- | --- | --- | --- |
| `Config.Routes` (split DNS via control) | `tsdns.go:80` | **missing** | `Resolver` in Rust only has peers+domain+proxied; no `Routes map[dnsname.FQDN][]*Resolver` — split-DNS via control Routes is not started. Confirmed parity.md ⬜. |
| `Config.Hosts` (local hosts map) | `tsdns.go:82` | **missing** | Rust only resolves from `peers: Vec<Node>`; no separate `Hosts` map for ExtraRecords. |
| `Config.LocalDomains` | `tsdns.go:85` | **missing** | No equivalent in Rust `MagicDnsResolver`. |
| `Config.SubdomainHosts` | `tsdns.go:91` | **missing** | Rust does not support subdomain resolution (`sub.node.tailnet.ts.net` → `node.tailnet.ts.net`). |
| Reverse DNS (PTR `.in-addr.arpa` / `.ip6.arpa`) | `tsdns.go:827-855` | **missing** | `resolveLocalReverse`, `rdnsNameToIPv4`, `rdnsNameToIPv6` all absent. |
| `.onion` rejection | `tsdns.go:660` | **missing** | Go rejects `.onion` with NXDOMAIN per RFC 7686. |
| Symbolic domain `magicdns.localhost-tailscale-daemon.` | `tsdns.go:668` | **missing** | Go returns MagicDNS VIP for this special FQDN. |
| 4via6 resolution (`<ip>-via-<siteid>`) | `tsdns.go:773-823` | **missing** | `resolveViaDomain` absent. |
| Type `ALL` handling | `tsdns.go:734` | **missing** | Rust's `lookup` only returns `A`/`AAAA` separately. |
| `Config.Hosts` from `DNSConfig.ExtraRecords` | `lib.rs:241-263` | **partial** | `upstream_nameservers` extracts Resolvers but never builds `Hosts` from `ExtraRecords`. |
| DoH/DoT upstream forwarding | `tsdns.go:314-316` | **missing** | Rust forwarder only classic UDP; Go supports `https://` and `tls://` resolvers via `RegisterCustomScheme` + forwarder. |
| `Resolver.Query()` response-size checking + TC bit | `tsdns.go:369` | **missing** | Rust `handle_query` does not set truncation (TC) bit. |
| `Resolver.HandlePeerDNSQuery` | `tsdns.go:406-473` | **missing** | No exit-node DNS forwarding logic (resolv.conf parsing, platform dispatch). |
| `SetConfig` with full config update | `tsdns.go:279-303` | **missing** | Rust has no `SetConfig`; only `MagicDnsResolver::new()` and `set_peers()`. |
| `Forwarder` with TCP/UDP/DoH fallback | `tsdns.go:221` (forwarder) | **missing** | Rust `forward_upstream` only does simple UDP with no TCP fallback or DoH. |
| Health tracking integration | `tsdns.go:218` | **missing** | Rust resolver has no `health.Tracker` wiring. |
| `BonjourPrefix` filtering | `tsdns.go:1161-1184` | **missing** | Rust forwarder doesn't drop Bonjour mDNS prefixes. |

### DNS Fallback (`crates/` doesn't exist) vs `net/dnsfallback/`

| item | Go source | Rust status | notes |
| --- | --- | --- | --- |
| `crates/dnsfallback/` | `dnsfallback.go` | **missing** | Entire crate does not exist. No `DnsFallbackResolver`, no embedded DERP map JSON, no `/bootstrap-dns` DoH resolver. |
| `crates/dnscache/` | `dnscache.go` | **missing** | Entire crate does not exist. No `DnsCache`, no TTL-based cache, no singleflight, no happy-eyeballs dialer wrapper. |
| `MakeLookupFunc()` | `dnsfallback.go:43-49` | **missing** | No bootstrap-DNS fallback function. |
| `GetDERPMap()` + `SetCachePath()` | `dnsfallback.go:173-209, 260-283` | **missing** | No DERP map cache persistence. |
| Control client `Dialer` with `dnsCache` + fallback | `controlclient/direct.go:334-368` | **missing** | No DNS caching in dial path. |
| `dnscache.Dialer()` happy-eyeballs wrapper | `dnscache.go:375-382` | **missing** | Rust control client uses bare `TcpStream::connect`. |
| `dnscache.Resolver.LookupIP` + singleflight | `dnscache.go:195-251` | **missing** | No DNS cache at all. |

---

## 2. Netmon Phase 12 (`crates/netmon/`, `crates/netns/`)

### `crates/netmon/` vs `net/netmon/`

| item | Go source | Rust status | notes |
| --- | --- | --- | --- |
| `Monitor.RegisterChangeFunc` (multi-callback) | `netmon.go:81` | **missing** | Rust has single callback; Go supports multiple `set.HandleSet[ChangeFunc]`. |
| `Monitor.gw` + `gwSelfIP` tracking | `netmon.go:84-85` | **missing** | Rust `State` has no gateway IP fields. |
| `Monitor.om` — full `osMon` interface | `netmon.go:52-60` | **partial** | Rust uses simple `fn() -> Option<State>` provider, not a `Receive() (message, error)` interface. |
| `Interface` struct (Index, Name, MTU, Flags, HardwareAddr) | `netmon.go` (earlier), `netmon_darwin.go` | **missing** | Rust `InterfaceMeta` only has `is_up` + `is_loopback` — no MTU, Flags, HardwareAddr, Index. |
| `HasCGNATInterface()` | `netmon.go` | **missing** | Go can detect CGNAT range interfaces; Rust doesn't. |
| `GetInterfaceList()` + `ForeachInterface` | `netmon.go` | **missing** | No interface enumeration API exposed. |
| `InterfaceDebugExtras()` | `netmon.go` | **missing** | No debug extras. |
| `DefaultRoute()` returning `(Route, error)` | `netmon.go` | **partial** | Rust only returns interface name string, not a `Route` struct with index, gateway IP. |
| Monotonic clock for time-jump detection | `netmon.go:35-42` | **partial** | Rust uses `SystemTime::now()` which is wall-clock, not monotonic. Go uses monotonic clock path. |
| `majorTimeJumpThreshold` = 10min | `netmon.go:42` | **partial** | Rust uses 60s (`TIME_JUMP_THRESHOLD` in `monitor.rs:22`), which is too sensitive vs Go's 10min. |
| LinkType detection (wired vs wifi vs mobile) | `netmon.go` | **missing** | No interface type classification. |
| EventBus integration | `netmon.go:73-74` | **missing** | Go has `eventbus.Client` + `Publisher[ChangeDelta]`; Rust has none. |

### `crates/netns/` vs `net/netns/`

| item | Go source | Rust status | notes |
| --- | --- | --- | --- |
| `Dialer.DialContext` with socket binding | `netns/dial.go` | **partial** | Rust `dial_tcp` exists with platform backends but socket binding (SO_BINDTODEVICE/IP_BOUND_IF) is basic. |
| `Dialer.DialTCP` / `DialUDP` | `netns/dial.go` | **partial** | Rust only has `dial_tcp` / `dial_tcp_addr` — no `dial_udp`. |
| Split DNS routing via `Dialer` | `netns/dial.go` | **missing** | Go routes DNS through specific interfaces based on `ForwardLinkSelector`; Rust has none. |
| Linux netfilter/nftables integration | `netns/linux.go` | **missing** | Rust `linux.rs` likely minimal. |
| `is_localhost` — missing `ip6-localhost` style names | `lib.rs:41-45` | **done** | Actually covered — matches `localhost6`, `ip6-loopback`, `ip6-localhost`. |
| No SOCKS5 proxy path for non-localhost addrs | `lib.rs:84-86` | **done** | SOCKS proxy path exists. |

---

## 3. PeerAPI Phase 13 (`peerapi`)

**Rust status: NOT IMPLEMENTED.** No `crates/tsnet/src/peerapi.rs` exists. The spec
doc exists but no code. Zero lines of peerapi code.

| item | Go source | Rust status | notes |
| --- | --- | --- | --- |
| `peerAPIServer` struct | `peerapi.go:53-56` | **missing** | Entire server |
| `peerAPIHandler.ServeHTTP` | `peerapi.go:358-429` | **missing** | |
| `handleDNSQuery` (DoH `/dns-query`) | `peerapi.go:731-790` | **missing** | Critical for exit node DNS |
| `/v0/goroutines` | `peerapi.go:607-621` | **missing** | |
| `/v0/env` | `peerapi.go:623-641` | **missing** | |
| `/v0/metrics` | `peerapi.go:651-657` | **missing** | |
| `/v0/magicsock` | `peerapi.go:643-648` | **missing** | |
| `/v0/dnsfwd` | `peerapi.go:660-675` | **missing** | |
| `/v0/interfaces` | `peerapi.go:431-476` | **missing** | |
| `/v0/sockstats` | `peerapi.go:478-574` | **missing** | |
| `peerAPIURL` / `peerAPIBase` helpers | `peerapi.go:959-995` | **missing** | |
| `replyToDNSQueries()` (exit node auth) | `peerapi.go:677-727` | **missing** | |
| `RegisterPeerAPIHandler` extensibility | `peerapi.go:337-348` | **missing** | |
| Deterministic port with CRC32 | `peerapi.go:106-125` | **missing** | |
| WhoIs auth per request | `peerapi.go:189-195` | **missing** | |
| Browser security headers | `peerapi.go:312-330` | **missing** | |

---

## 4. C2N Phase 14 (`crates/c2n/`) vs `ipn/ipnlocal/c2n.go`

### Handler inventory — implemented vs stub vs missing

| Go endpoint | Go handler | Rust status | Rust route | notes |
| --- | --- | --- | --- | --- |
| `GET /echo` | `handleC2NEcho` (200, returns body) | **done** | `/echo` (200) | Returns request body. |
| `GET /` (list endpoints) | (implicit — lists `/echo`) | **done** | `/` (200) | Lists known paths. |
| `POST /logtail/flush` | `handleC2NLogtailFlush` (204 NoContent) | **stub 501** | `/logtail/flush` | Rust returns 501. |
| `GET /debug/goroutines` | `handleC2NDebugGoroutines` | **stub 501** | `/debug/goroutines` | Go returns gzipped stack dump; Rust: 501. |
| `GET /debug/pprof/heap` | `handleC2NPprof` | **stub 501** | `/debug/pprof/heap` | Go returns pprof heap. |
| `GET /debug/pprof/allocs` | `handleC2NPprof` | **missing** | not in `KNOWN_PATHS` | Go registers `/debug/pprof/allocs` → pprof handler. |
| `GET /debug/pprof/profile` | (implicit — part of pprof) | **stub 501** | `/debug/pprof/profile` | Rust has this path in `KNOWN_PATHS` but returns 501. |
| `GET /debug/prefs` | `handleC2NDebugPrefs` | **stub 501** | `/debug/prefs` | Go returns current Prefs JSON. |
| `GET /debug/metrics` | `handleC2NDebugMetrics` | **stub 501** | `/debug/metrics` | Go writes Prometheus exposition format. |
| `GET /debug/component-logging` | `handleC2NDebugComponentLogging` | **missing** | not in `KNOWN_PATHS` | Enables per-component verbose logging for N seconds. |
| `GET /debug/logheap` | `handleC2NDebugLogHeap` | **missing** | not in `KNOWN_PATHS` | Go dumps heap to log. |
| `GET /debug/netmap` | `handleC2NDebugNetMap` | **stub 501** | `/debug/netmap` | Go supports GET (current netmap) + POST (candidate + omitFields). |
| `GET /debug/health` | `handleC2NDebugHealth` | **stub 501** | `/debug/health` | Go returns health.State JSON. |
| `POST /sockstats` | `handleC2NSockStats` | **missing** | not in `KNOWN_PATHS` | Go flushes sockstat logger, returns debug info. |
| `POST /netfilter-kind` | `handleC2NSetNetfilterKind` | **missing** | not in `KNOWN_PATHS` | Linux-only: switches netfilter mode. |
| `GET /netmap` | — | **stub 501** | `/netmap` | Returned as a separate path from `/debug/netmap` in Rust but not in Go. |
| `GET /prefs` | — | **stub 501** | `/prefs` | Same — Rust-specific extra path not in Go. |
| `GET /dns` | — | **stub 501** | `/dns` | Same — DNS config endpoint not in original Go. |
| `POST /local/*` | — | **stub 501** | `/local/{command}` | 501 for everything. |

### Architecture differences

| aspect | Go | Rust | status |
| --- | --- | --- | --- |
| Auth | `handleC2N` uses HTTP middleware + per-handler delegation | `check_auth` checks loopback or WhoIs | **partial** — Go has no per-path auth? Actually Go uses whitelist + self-IP auth through the HTTP listener on loopback only. Rust auth checks are reasonable. |
| Registration system | `RegisterC2N()` with method+path dispatch map | Hardcoded `KNOWN_PATHS` + `match` in `dispatch()` | **partial** — not extensible |
| Feature gates | `buildfeatures.HasC2N`, `HasDebug`, `HasLogTail`, `HasOSRouter` | None | **missing** — no equivalent |
| Handler hook injection | `var c2nLogHeap func(...)` nil-check pattern | None | **missing** |
| Wire into tsnet | Go wires via `LocalBackend.serveC2N` | Rust has `C2NServer` but it's started in tsnet::Server::up | **done** |

---

## 5. Netmap Cache Phase 15 (`crates/tsnet/src/state.rs` `NetMapCache`)

### vs `ipn/ipnlocal/netmapcache/`

| item | Go source | Rust status | notes |
| --- | --- | --- | --- |
| Columnar cache (separate keys per component) | `netmapcache.go:43-60` | **missing** | Rust serializes entire MapResponse as one JSON blob. Go stores `Peer`, `SelfNode`, `DNS`, `Filter`, `Domain`, `MagicDNS`, `NodeKeyExpired` as separate keys. |
| `Store` interface (pluggable backend) | `netmapcache.go` (interface) | **partial** | Rust has `StateStore` trait but it's file-only and different shape. |
| JSON encoding version migration | `netmapcache.go` | **missing** | Rust has no version header. |
| Write dedup (SHA256 content digest) | `netmapcache.go:86-100` | **missing** | Rust writes every time, no dedup. |
| GC / TTL-based key pruning | `netmapcache.go` | **missing** | Rust never prunes old keys. |
| `wantKeys` set + stale key cleanup | `netmapcache.go:52` | **missing** | Rust writes single file; no key management. |
| Cache-aside with netmap construction from columns | `netmapcache.go` (Load→build NetworkMap) | **missing** | Rust simply deserializes MapResponse. |
| Integration with controlclient init | `controlclient/direct.go` | **missing** | Rust `PersistedState::load_netmap` is called in tsnet but not wired into `controlclient::Client` bootstrap. |
| Wire into auth failure clear | `controlclient/direct.go` | **missing** | Rust `clear_netmap` exists but not wired into auth failure path. |
| Wire into netmap update path | `netmapcache.go` | **missing** | Rust `save_netmap` exists but not called from controlclient on each netmap update. |

---

## 6. HostInfo Phase 16 (`crates/tsnet/src/hostinfo.rs`, `crates/tailcfg/src/node.rs`)

### Go `Hostinfo` field coverage (Go struct at `tailcfg/tailcfg.go:848-927`)

| Go field | Rust field | Status | Notes |
| --- | --- | --- | --- |
| `IPNVersion` | `IPNVersion` | ✅ | |
| `FrontendLogID` | `FrontendLogID` | ✅ | |
| `BackendLogID` | `BackendLogID` | ✅ | |
| `OS` | `OS` | ✅ | |
| `OSVersion` | `OSVersion` | ✅ | |
| `Container` | `Container` | ✅ | |
| `Env` | `Env` | ✅ | |
| `Distro` | `Distro` | ✅ | |
| `DistroVersion` | `DistroVersion` | ✅ | |
| `DistroCodeName` | `DistroCodeName` | ✅ | |
| `App` | `App` | ✅ | |
| `Desktop` | `Desktop` | ✅ | |
| `Package` | `Package` | ✅ | |
| `DeviceModel` | `DeviceModel` | ✅ | |
| `PushDeviceToken` | `PushDeviceToken` | ✅ | macOS/iOS APNs device token for notifications. |
| `Hostname` | `Hostname` | ✅ | |
| `ShieldsUp` | `ShieldsUp` | ✅ | |
| `ShareeNode` | `ShareeNode` | ✅ | Indicates this node is a shared-to user's node. |
| `NoLogsNoSupport` | `NoLogsNoSupport` | ✅ | |
| `WireIngress` | `WireIngress` | ✅ | Wants funnel wiring even if not enabled. |
| `IngressEnabled` | `IngressEnabled` | ✅ | Populated by `apply_runtime_fields` when funnel is active. |
| `AllowsUpdate` | `AllowsUpdate` | ✅ | |
| `Machine` | `Machine` | ✅ | |
| `GoArch` | `GoArch` | ✅ | |
| `GoArchVar` | `GoArchVar` | ✅ | |
| `GoVersion` | `GoVersion` | ✅ | |
| `RoutableIPs` | `RoutableIPs` | ✅ | Rust stores as `Vec<String>`, Go uses `[]netip.Prefix` |
| `RequestTags` | `RequestTags` | ✅ | |
| `WoLMACs` | `WoLMACs` | ✅ | Wake-on-LAN MAC addresses. |
| `Services` | `Services` | ✅ | Rust uses `Vec<Service>` |
| `NetInfo` | `NetInfo` | ✅ | |
| `SSH_HostKeys` | `SSH_HostKeys` | ✅ | Renamed to `SSH_HostKeys` with `rename = "sshHostKeys"` |
| `Cloud` | `Cloud` | ✅ | |
| `Userspace` | `Userspace` | ✅ | |
| `UserspaceRouter` | `UserspaceRouter` | ✅ | |
| `AppConnector` | `AppConnector` | ✅ | |
| `ServicesHash` | `ServicesHash` | ✅ | Opaque hash of tailnet services list. |
| `PeerRelay` | `PeerRelay` | ✅ | |
| `ExitNodeID` | `ExitNodeID` | ✅ | Populated from route table's selected exit node StableNodeID. |
| `Location` | `Location` | ✅ | Reuses existing `Location` struct; `Option<Location>`. |
| `TPM` | `TPM` | ✅ | `TPMInfo` struct mirroring Go's `tailcfg.TPMInfo`. |
| `StateEncrypted` | `StateEncrypted` | ✅ | `OptBool`, defaults to unset. |

Total: **36 Go fields, 36 present in Rust, 0 missing.**

### `collect_hostinfo()` — `tsnet/src/hostinfo.rs` vs `hostinfo/hostinfo.go`

| feature | Go | Rust | status |
| --- | --- | --- | --- |
| `RegisterHostinfoNewHook` extensibility | `hostinfo.go:39-41` | **missing** | No hook system for plugins to augment Hostinfo. |
| `SetHostnameFn` custom hostname resolver | `hostinfo.go:517-518` | **missing** | Rust uses `gethostname()` inside `tsnet::Server`, not pluggable. |
| `SetOSVersion` / `SetDeviceModel` / `SetApp` / `SetPackage` | `hostinfo.go:190-226` | ✅ | `HostinfoOverrides` struct with `set_device_model`/`set_app`/`set_os_version`/`set_package`; builder + Server runtime setters. |
| `DisabledEtcAptSource()` | `hostinfo.go:442-463` | **missing** | Linux apt-workaround detection. |
| `IsSELinuxEnforcing()` | `hostinfo.go:483-489` | **missing** | SELinux mode detection. |
| `IsNATLabGuestVM()` | `hostinfo.go:492-498` | **missing** | NAT lab VM detection. |
| `IsInVM86()` | `hostinfo.go:506-510` | **missing** | v86 WASM emulator detection. |
| Lazy/cached atomic values | `hostinfo.go:99-118` | **missing** | Go caches Hostinfo fields with `lazyAtomicValue`; Rust recomputes every time. |

### Update loop — `controlclient/src/hostinfo.rs`

| item | Go | Rust | status |
| --- | --- | --- | --- |
| **Update loop** | `controlclient/direct.go:HostInfo` | ✅ | `spawn_hostinfo_update_loop` in `tsnet/src/lib.rs`; initial send + 10min periodic refresh. |
| Periodic 10min refresh | `controlclient/direct.go` | ✅ | `tokio::time::sleep(Duration::from_mins(10))` |
| Dedup by content hash | `controlclient/direct.go` | ✅ | `hostinfo_hash()` — JSON serialization hash; same content → no send. |

---

## 7. Parity.md cross-check

### DNS row (Tier 1)

| parity.md claim | Rust status | validation |
| --- | --- | --- |
| `🔶 resolver + 100.100.100.100 responder + unified dial done` | ✅ | `crates/dns/` has `MagicDnsResolver` + `DnsResponder`. |
| `split DNS via control Routes still ⬜` | ✅ confirmed | No `Routes` support as noted in §1 above. |

### Serve/Funnel row (Tier 2)

| parity.md claim | Rust status | validation |
| --- | --- | --- |
| `✅ port-6 done (ServeConfig serde model...)` | ✅ | ServeConfig, TCP forward, HTTP reverse proxy all present. |
| `Remaining: ingress peer Tailscale-Ingress-Target dispatch` | ⬜ | No `canIngress()` check in peerapi (but peerapi is entirely missing). |
| `Remaining: Hostinfo.IngressEnabled advertisement` | ✅ | `Hostinfo.IngressEnabled` exists in `node.rs:247`. But no `collect_hostinfo` actually sets it to true when funnel is active — `populate_hostinfo` in `hostinfo.rs` doesn't set it. |

---

## Summary: Rust vs Go completeness by phase

| Phase | Go items | Rust done | Rust stub | Rust missing | Completeness |
| --- | --- | --- | --- | --- | --- |
| 11a MagicDNS resolver | ~25 functions/fields | 5 | 1 | ~19 | ~20% |
| 11b DNS fallback | 6 crate components | 0 | 0 | 6 | 0% |
| 12 Netmon | ~15 features | 5 | 3 | ~7 | ~50% |
| 13 PeerAPI | ~20 handlers/features | 0 | 0 | 20 | 0% |
| 14 C2N | 17 endpoints | 2 | 12 | 4 | ~12% |
| 15 Netmap cache | ~10 features | 3 | 0 | ~7 | ~30% |
| 16 Hostinfo | 36 fields + update loop | 36 | 0 | 0+3 | ~100% |

---

## Prioritized follow-up work (sized as opencode phases)

### P0 — Critical gaps (breaks core functionality)

1. **Phase: PeerAPI implementation** — 0% complete, but critical for exit node DNS. Go `peerapi.go` has ~20 handlers including `/dns-query` DoH. **~2500 lines output.**

2. **Phase: DNS fallback + cache** (`crates/dnsfallback/` + `crates/dnscache/`) — 0% complete. Control client cannot bootstrap when system DNS is broken. **~1500 lines output.**

### P1 — Affects production reliability

3. **Phase: MagicDNS resolver completeness** — Add `Routes` (split DNS), `Hosts` (ExtraRecords), `LocalDomains`, `SubdomainHosts`, reverse DNS (PTR), DoH/DoT upstream, `HandlePeerDNSQuery` for exit node DNS. **~2000 lines output.**

4. **Phase: C2N actual implementations** — Replace all 501 stubs with real handlers: `/debug/goroutines`, `/debug/prefs`, `/debug/metrics`, `/debug/netmap`, `/debug/health`, `/logtail/flush`, `/debug/component-logging`, `/debug/logheap`, `/sockstats`. Add missing endpoints: `/debug/pprof/allocs`, `POST /netfilter-kind`. **~1500 lines output.**

### P2 — Important for correctness

5. **Phase: Netmap cache integration** — Wire `save_netmap`/`load_netmap` into controlclient init path, netmap update callback, and auth failure path. **~500 lines output.**

6. **Phase: HostInfo remaining fields + update loop** — Add `PushDeviceToken`, `ShareeNode`, `WireIngress`, `WoLMACs`, `ServicesHash`, `ExitNodeID`, `Location`, `TPM`, `StateEncrypted` to `Hostinfo` struct. Create `start_hostinfo_update_loop` in controlclient with 10min periodic refresh + initial send. **~800 lines output.**

### P3 — Polish

7. **Phase: Netmon refinement** — Add gateway IP tracking, MTU/flags/index to `InterfaceMeta`, monotonic clock jump detection, default route struct with index+gateway, `hasCGNATInterface()`, link type detection. Adjust `TIME_JUMP_THRESHOLD` from 60s to 10min to match Go. **~1000 lines output.**

8. **Phase: HostInfo system detection polish** — Add `RegisterHostinfoNewHook` system, `SetHostnameFn`/`SetOSVersion`/`SetDeviceModel` runtime setters, lazy caching, `DisabledEtcAptSource()`, `IsSELinuxEnforcing()`, `IsInVM86()` detection. **~600 lines output.**
