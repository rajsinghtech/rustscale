# Core networking / protocol stack: feature-parity audit

Date: 2026-07-12  
Method: Side-by-side comparison of Go source at `~/tailscale/` and Rust `crates/`.  
Verification of `docs/parity.md` claims by reading actual source code.  
P0 = correctness/security bug risk, P1 = important missing capability, P2 = nice-to-have.

---

## 1. Control plane: controlclient / tailcfg

### Go files
- `control/controlclient/{client,direct,auto,map}.go` — `Client` interface, `Direct` (register + map-poll + set-dns), `Auto` (3-goroutine state machine with auth/map/update routines, backoff), `mapSession` (delta accumulation, `patchifyPeersChanged`, `removeUnwantedDiscoUpdates`, `tryHandleIncrementally`)
- `control/controlknobs/controlknobs.go` — 25+ atomic knobs updated from `Node.CapMap` per map response
- `control/controlhttp/client.go` — Noise/ts2021 with 80/443 dual-path, `DialPlan` support, ACE proxy, macOS Screen Time detection
- `tailcfg/tailcfg.go` — ~3621 lines of wire types; `Node`, `NetMap`, `MapRequest/Response`, `RegisterRequest/Response`, `Hostinfo` (42+ fields), `NetInfo`, `PeerChange`, `ControlDialPlan`, `PingRequest`

### rustscale files
- `crates/controlclient/src/{client,controlbase,controlhttp,c2n}.rs` — Noise IK handshake, HTTP/2-over-Noise, register, map-stream, set-dns, control-knob extraction
- `crates/tailcfg/src/{node,map,register,derpmap,dns,filter,ssh,caps}.rs` — wire types

### Parity.md claims
- "ts2021 Noise control client (HTTP/2-over-Noise, streaming netmap deltas)" ✅ done  
- "control knobs" ✅ done (`crates/controlknobs`)

### Gaps

| Gap | Go ref | Rust ref | Prio | Consequence |
|-----|--------|----------|------|-------------|
| **No logout** — no API to send `POST /machine/logout` | `direct.go:TryLogout` | absent from `client.rs` | P0 | Node key stays registered on control; reused key can be rejected, orphan identity |
| **No key rotation / re-registration** — `OldNodeKey` in `RegisterRequest` is never populated; no expiry-triggered re-register | `auto.go` authRoutine + `direct.go:doLogin` | absent | P0 | Node key expiry causes permanent disconnection; no graceful regen |
| **No zstd decompression** — `MapRequest.Compress: "zstd"` is sent but compressed map responses are not decompressed | `direct.go:sendMapRequest` (zstd decompress with fast path) | `client.rs:stream_map()` reads raw JSON after 4-byte length | P0 | Map responses with zstd compression (Tailscale default) produce garbage parse errors → permanent map-poll failure |
| **No delta processing** — `PeersChanged`/`PeersRemoved` / `PeersChangedPatch` fields exist in `MapResponse` but no delta-apply logic; tsnet has ad-hoc full-replace | `map.go:handleNonKeepAliveMapResponse` + `patchifyPeersChanged` + `tryHandleIncrementally` | `tsnet/src/lib.rs:stream_map_loop()` replaces entire peer list | P1 | Full netmap rebuild on every delta → unnecessary CPU for large tailnets; control server expects delta clients to work efficiently |
| **No map session handles** — `MapSessionHandle`+`Seq` fields exist but never used | `map.go:mapSession` stateful session | absent | P1 | No reattach on reconnect; server cannot deduplicate and may send full state on every reconnect |
| **No keepalive watchdog** — Go has 120s watchdog for map-poll timeout | `direct.go:watchdogTimeout` | absent | P2 | Map-poll hang undetected until next caller timeout |
| **No debug flag emission** — `MapRequest.DebugFlags` is never populated | `health/health.go:AppendWarnableDebugFlags` | absent | P2 | Server-side debug feedback lost |
| **Missing Node fields**: `KeySignature`, `LastSeen`, `IsJailed`, `IsWireGuardOnly`, `Expired`, `UnsignedPeerAPIOnly` | `tailcfg.go:Node` | `node.rs:Node` | P1 | Can't detect jailed/WG-only peers; key rotation verification not possible; `LastSeen` online-state heuristics lost |
| **Missing MapResponse fields**: `Debug`, `PingRequest`, `ControlDialPlan`, `ClientVersion`, `TKAInfo`, `Health` | `tailcfg.go:MapResponse` | `map.rs:MapResponse` | P2 | No server-side ping, no dial plan (important for control connectivity), no TKA, no server health messages |
| **No `NetInfo` processing** — `NetInfo` (NAT type, IPv6, portmap presence) constructed but never wired to magicsock | `direct.go:SetNetInfo` → Auto calls `updateControl()` | absent | P1 | DERP home selection cannot use netcheck data; control server receives zeros |
| **No `UpdateEndpoints` / endpoint streaming** — endpoints change without lite map request | `direct.go:SetEndpoints` → `updateControl()` → `SendUpdate()` | absent | P1 | Control out of sync with discovered endpoints |
| **No `LoginFlags` variant support** — `LoginEphemeral`, `LoginInteractive` not plumbed | `auto.go:Login(flags)` | absent from tsnet | P1 | Ephemeral node support broken; interactive auth flow works through separate path |

---

## 2. Data plane: magicsock (path selection, DISCO, DERP routing)

### Go files
- `wgengine/magicsock/magicsock.go` — `Conn` type, UDP sockets (`RebindingUDPConn`), disco handling, DERP management, `peerSet`/`peerMap`, endpoint refresh, `setNearestDERP`, STUN loop, pinger, conveyer belt for periodic re-probing, `handleDiscoMessage` (Ping/Pong/CallMeMaybe peer-learn)
- `wgengine/magicsock/endpoint.go` — per-peer endpoint state machine: `heartbeat()` (3s interval), `betterAddr()` (weighted path quality with hysteresis), UDP lifetime probing, `trustBestAddrUntil`, `pongHistory` (64 entries), disco key advertisement (2min)
- `wgengine/magicsock/relaymanager.go` — full event-loop for peer relay: allocation, handshake, CallMeMaybeVia, disco message routing, lamport-id dedup
- `wgengine/magicsock/peermtu.go` — PMTUD with DF-bit, padded disco pings at `WireMTUsToProbe` sizes, EMSGSIZE detection
- `wgengine/magicsock/peermap.go` — multi-index peer lookup (by NodeKey, NodeID, DiscoKey, epAddr)

### rustscale files
- `crates/magicsock/src/lib.rs` — `Magicsock`, `DerpManager`, `spawn_recv_tasks`, path selection, disco handling, relay discovery
- `crates/magicsock/src/endpoint.rs` — per-peer endpoint state: `BestPath`, candidates, trust-on-pong
- `crates/magicsock/src/relay_manager.rs` — full relay manager event loop

### Parity.md claims
- "magicsock (direct/DERP path selection, cross-region routing, reply-to-arrival-region; peer-relay client ✅)"  
- "WireGuard data plane (boringtun)"  

### Gaps

| Gap | Go ref | Rust ref | Prio | Consequence |
|-----|--------|----------|------|-------------|
| **No periodic re-STUN / background probing** — Go re-STUNs every ~20-26s while active; Rust only probes once on `set_netmap` | `magicsock.go:runSTUN()` / periodic endpoint refresh | absent | P0 | Endpoints stale after NAT rebind → connectivity loss until netmap refresh (minutes) |
| **No continuous disco pinger / heartbeat** — Go sends disco pings every 3s (heartbeat) and full pings every 1m; Rust sends one probe per endpoint at `set_netmap` only | `endpoint.go:heartbeatInterval` (3s), `upgradeUDPDirectInterval` (1m) | `endpoint.rs` — no timer | P0 | Direct path unreachable after NAT rebind unless peer coincidentally re-probes; DERP fallback persists when direct path would work |
| **No UDP lifetime probing** — Go probes path liveness at cliff intervals (10/30/60s) when endpoint has not received data recently | `endpoint.go:probeUDPLifetime` + `udpLifetimeProbeCliff` | absent | P0 | Silent path death: pongs are never sent without active pinging; peer thinks path is alive when pinhole closed |
| **No MTU / PMTUD** — zero MTU awareness anywhere in magicsock | `peermtu.go` with DF-bit, padded pings, `WireMTUsToProbe` | absent | P0 | Path MTU changes go undetected → WireGuard oversized packets silently dropped or IP fragmentation fails |
| **No `derpRoute` expiry** — `last_recv_derp_region` is set but never cleared | `magicsock.go:derpRoute` cache with expiry | `endpoint.rs:last_recv_derp_region` never reset | P1 | Stale DERP reply routing persists after peer moves home → wrong DERP region used for replies |
| **No `PeerGone` handling** — DERP `PeerGone` frames are received but never processed by magicsock | `magicsock.go:handlePeerGone` | absent | P1 | Dead peer detection delayed; stale peer state persists |
| **No endpoint type tracking** — Candidates stored as `Vec<SocketAddr>` without `EndpointType` marks (LOCAL/STUN/PORTMAPPED) | `endpoint.go:epAddr` + `EndpointType` | `endpoint.rs:candidates: Vec<SocketAddr>` | P1 | No debug visibility into endpoint origin; path ranking cannot distinguish local from STUN |
| **No `NotePreferred` DERP frame sent** — Rust never tells the DERP server it's the home region | `derphttp_client.go:NotePreferred(true)` | absent from `DerpIo` | P1 | DERP server may route through suboptimal region; home region preference not signaled |
| **No pong piggyback learning** — `Ping` with `NodeKey` is parsed but not used to populate `addr_to_peer` mapping | `magicsock.go:handlePingLocked` (learns disco key from Ping NodeKey) | `endpoint.rs` ignores node key | P1 | Lost opportunity to learn peer identity from direct-path pings; identity only learned via DERP/disco |
| **No multiple candidate probing** — Rust pings first candidate only; Go probes all candidates | `endpoint.go:pickPingCandidate` | `lib.rs:probe_peer` picks first | P1 | Direct path may not be discovered if first candidate is stale |
| **No `CallMeMaybe` retriggering** — `call_me_maybe_sent` set once, never cleared; no periodic re-send | `endpoint.go:sendCallMeMaybe` | `endpoint.rs:call_me_maybe_sent: bool` set once | P1 | NAT rebind after initial CallMeMaybe → no re-invitation to peer; direct path never re-established |
| **WireGuard per-peer tunnel, not single device** — Go creates one `wireguard-go Device` with `Bind` interface; Rust creates `N` tunnels, no roaming, no `Reconfig` | `wgengine/userspace.go` + `wireguard-go` | `tsnet/src/lib.rs:wg_tunnels: HashMap<NodePublic, Arc<Mutex<WgTunn>>>` per-peer | P1 | No source-address roaming; WireGuard peer reuse broken; high per-peer overhead; no `SetPrivateKey` for key rotation |

---

## 3. DERP client + protocol

### Go files
- `derp/derp.go` — 16 frame types, protocol v2, `MaxPacketSize=64KB`, `KeepAlive=60s`
- `derp/derp_client.go` — 3-way handshake, send/recv, ping/pong, forward packet, mesh frames, token-bucket rate limit
- `derp/derphttp/derphttp_client.go` — auto-reconnecting HTTP client with `Upgrade: DERP`, metacert pinned-key verify, `FastStartHeader`, `IdealNodeHeader`, DNS cache, WS support
- `derp/derphttp/mesh_client.go` — `RunWatchConnectionLoop` for DERP mesh peering
- `derp/derpserver/derpserver.go` — metacert generation, client tracking, mesh routing, priority queuing, rate limiting, duplicate connection handling

### rustscale files
- `crates/derp/src/{frame,protocol,client,server}.rs`

### Parity.md claims
- "DERP client" ✅ done at parity

### Gaps

| Gap | Go ref | Rust ref | Prio | Consequence |
|-----|--------|----------|------|-------------|
| **No DERP pinned-key verify** — Rust's `DerpClient::from_stream` accepts any server key; Go verifies against control-conveyed DERP map public key | `derphttp_client.go:verifyServerKey` using metacert or `Derp-Public-Key` header | `client.rs:from_stream` stores server key but never validates against known key | P0 | MITM on DERP connections undetectable; attacker could intercept all relay traffic |
| **No token-bucket rate limiting on client sends** — `derp_client.go:Client.rate` (token bucket) limits send to server-configured rate; Rust has no limits | `derp_client.go:Client.Send` checks `rate.Allow()` | `client.rs:send_packet` writes unconditionally | P0 | Client can overrun the DERP server's queue → server drops packets with head-of-line blocking penalty |
| **No mesh routing** — `ForwardPacket`, `WatchConns`, `ClosePeer` frames sent/received but server discards them; no mesh client loop | `derphttp/mesh_client.go:RunWatchConnectionLoop` + server mesh handlers | `server.rs` says "Not mesh; discard body" | P1 | DERP mesh topology unusable; all traffic between peered DERP servers goes through control plane, higher latency |
| **No auto-pong on server Ping** — Go's client recv loop auto-sends pong for incoming FramePing; Rust's `DerpIo` does handle this but the raw `DerpClient.recv()` does not | `derp_client.go:Client.recv` dispatches Ping → calls `sendPong` | `client.rs:recv` returns Ping as message, caller must send pong | P1 | Server pings go unanswered → server considers client dead → connection reset |
| **Server is test-grade** — no rate limiting, no connection admission, no STUN integration, no health reporting, no TCP write timeout, no duplicate connection handling | `derpserver/derpserver.go` full production server | `server.rs` minimal echo | P2 | Cannot serve production relay traffic |

---

## 4. Disco protocol codec

### Go files
- `disco/disco.go` — all 9 message types, `Magic="TS💬"`, NaCl box envelope, golden vectors

### rustscale files
- `crates/disco/src/{lib,message,wire}.rs`

### Parity.md claims
- "disco" ✅ done at parity

### Gaps

| Gap | Go ref | Rust ref | Prio | Consequence |
|-----|--------|----------|------|-------------|
| **No lamport clock on CallMeMaybe** — Go's CallMeMaybe has no lamport; but UDP relay bind handshake uses lamport ID for ordering; Rust discards lamport-id dedup info | `disco.go:CallMeMaybe` (no lamport) vs `relaymanager.go:handleCallMeMaybeVia` (lamport dedup) | `message.rs:CallMeMaybe` has no lamport field | P2 | Race between concurrent relay allocations not deduplicated on the protocol level |

---

## 5. netcheck (STUN probing)

### Go files
- `net/netcheck/netcheck.go` — `Report`, `Client`, `GetReport()` with full/incremental probe plans, `makeProbePlanInitial`/`makeProbePlan`, `preferredDERPAbsoluteDiff=10ms` stickiness, `PreferredDERPFrameTime=8s`, ICMP fallback, DNS resolution, `MappingVariesByDestIP`, `GlobalV4Counters`, captive portal detection

### rustscale files
- `crates/netcheck/src/{lib,prober,report,captivedetection,stun}.rs`

### Parity.md claims
- "netcheck (STUN)" ✅ done at parity

### Gaps

| Gap | Go ref | Rust ref | Prio | Consequence |
|-----|--------|----------|------|-------------|
| **No ICMP probing** — `Report.ICMPv4` field exists in Rust but is never set | `netcheck.go:icmpProbe` (1s timeout) | absent | P1 | UDP working but ICMP blocked goes undetected; inconsistent network diagnostics |
| **No DNS resolution for STUN targets** — Rust only probes explicit IPs from DERPMap; Go resolves hostnames via `dnscache.Resolver` | `netcheck.go:nodeAddrPort` falls back to DNS | `prober.rs` uses only pre-resolved IPs | P1 | DERP nodes with only hostnames in DERPMap are skipped entirely → incomplete probe |
| **No incremental probe plan** — Go has full-vs-incremental (3 fastest regions + home DERP, retries=4/2/1); Rust probes all regions every time | `netcheck.go:makeProbePlan` vs `makeProbePlanInitial` | `prober.rs` always uses `build_probe_plan` | P2 | Wastes bandwidth/CPU probing all regions when only delta needed (5s vs 200ms reports) |
| **No preferred-DERP frame-time stickiness** — Go uses 5-minute frame-time check to avoid DERP-home flapping | `netcheck.go:PreferredDERPFrameTime` = 8s | `report.rs:pick_preferred` uses simple hysteresis | P2 | DERP home region may flap on transient latency jitter |

---

## 6. Portmapper (NAT-PMP/PCP/UPnP)

### Go files
- `net/portmapper/portmapper.go` — `Client` with probe, create, cache, renewal, epoch invalidation, gateway detection, `NoMappingError`
- `net/portmapper/{pcp,upnp}.go` — PCP nonce, UPnP `selectBestService`

### rustscale files
- `crates/portmapper/src/{client,pmp,pcp,upnp,gateway}.rs`

### Parity.md claims
- "portmapper" ✅ done at parity

### Gaps

| Gap | Go ref | Rust ref | Prio | Consequence |
|-----|--------|----------|------|-------------|
| No PCP FORCE_UNICAST for broken middleboxes | `pcp.go:ForceUnicast` | absent | P2 | Some broken NAT-PMP/PCP implementations need unicast; may not respond to multicast |

**Verdict**: Portmapper is the most complete port — no P0/P1 gaps found.

---

## 7. Packet filter

### Go files
- `wgengine/filter/filter.go` — `Filter` with `local4/local6` funcs, `cap4/cap6` cap-check matches, `shieldsUp`, `IngressAllowHooks`, `LinkLocalAllowHooks`, `lruMax=512` conntrack, `Response` enum (Drop/DropSilently/Accept/NoVerdict), pre-check (multicast/link-local drop, fragment accept)
- `wgengine/filter/match.go` — `matches` with `CapTestFunc` for dynamic capability evaluation

### rustscale files
- `crates/filter/src/{lib,packet,parse,state,match,prefix}.rs`

### Parity.md claims
- "packet filter (incl. stateful UDP)" ✅ done at parity

### Gaps

| Gap | Go ref | Rust ref | Prio | Consequence |
|-----|--------|----------|------|-------------|
| **No capability evaluation during filtering** — `CapMatch` structs are parsed from FilterRules and stored but never evaluated; Rust uses a no-op `no_cap` function that always returns `false` | `filter.go:cap4/cap6` checked via `CapTestFunc` callback | `lib.rs:no_cap(_: &IpAddr, _: &str) -> bool { false }` | P1 | Capability-based ACLs (e.g., `cap:https://example.com/web` grants) silently pass-through unfiltered or blocked; security boundary broken |
| **No shields-up mode** — Go's `shieldsUp` bool rejects all inbound non-peer traffic | `filter.go:Filter.shieldsUp` | absent | P1 | No emergency lock-down mode |
| **No TSMP message parsing** — TSMP accepted but not parsed for message types (used for clique health, disco key advertisement, rejected packets) | `filter.go:pre` accepts fragments + uses TSMP for pong generation | `lib.rs:pre` accepts TSMP as passthrough | P2 | Internal TSMP signals not processed; health/debug features using TSMP broken |

---

## 8. Network monitor (netmon)

### Go files
- `net/netmon/netmon.go` — `Monitor` with platform `osMon` (AF_ROUTE on macOS, netlink on Linux), `ChangeDelta` with `DefaultInterfaceChanged`, `IsLessExpensive`, `InterfaceIPsChanged`, `AvailableProtocolsChanged`, `RebindLikelyRequired`, wall-clock jump detection (10min threshold, 15s poll)
- `net/netmon/{state,interfaces}.go` — `State`, `Interface`, `filterRoutableIPs`, `isInterestingInterfaceChange`

### rustscale files
- `crates/netmon/src/{monitor,state,interfaces,os,defaultroute}.rs`
- `crates/netmon/src/{os_darwin,os_poll}.rs`

### Parity.md claims
- "Network monitor (netmon)" ✅ done at parity

### Gaps

| Gap | Go ref | Rust ref | Prio | Consequence |
|-----|--------|----------|------|-------------|
| **No Linux netlink support** — Rust uses polling (10s interval) on Linux; Go uses netlink for instant notification | `netmon_linux.go` | `os_poll.rs` on Linux | P1 | 10-second delay detecting network transitions on Linux; slow link-failure recovery, stale endpoints |
| **No per-interface IP change tracking** — Rust re-enumerates all interfaces and compares full state; Go tracks per-interface changes | `netmon.go:interfaceState` | `state.rs:gather_state` full rebuild | P2 | CPU cost on every interface change proportional to number of interfaces (minor) |
| **No `LogLikelyHomeRouterIP`** — Go logs home router IP changes for diagnostics | `state.go:LikelyHomeRouterIP` | `state.rs:likely_home_router_ip` exists but not logged on change | P2 | Debugging NAT/gateway issues harder |

---

## 9. DNS resolver

### Go files
- `net/dns/resolver/tsdns.go` — `Resolver` listening on `100.100.100.100:53`, split DNS, `Hosts`/`LocalDomains`/`SubdomainHosts`, PTR reverse, 4via6, TC+EDNS, ANY qtype, TCP fallback, `maxActiveQueries=256`, `idleTimeoutTCP=45s`, `ResponseMapper` hook
- `net/dns/manager.go` — `Manager` with `compileConfig` (5 strategies for OS split-DNS vs quad-100 proxy), platform `OSConfigurator` trait
- `net/dns/manager_darwin.go` — `/etc/resolver/` split DNS files

### rustscale files
- `crates/dns/src/{lib,forwarder,osconfig,osconfig_darwin,wire}.rs`

### Parity.md claims
- "MagicDNS + split DNS resolver" ✅ done at parity

### Gaps

| Gap | Go ref | Rust ref | Prio | Consequence |
|-----|--------|----------|------|-------------|
| **No DNS cache** — every query hits the upstream resolver | `net/dnscache/dnscache.go` (TTL cache with singleflight) | absent | P1 | Unnecessary upstream load; latency on repeated queries; no offline fallback |
| **No DNS-over-TLS** — only DoH supported for encrypted upstream | `resolver/forwarder.go` supports `tls://` URIs | `forwarder.rs` supports UDP+TCP+DOH only | P2 | Some corporate environments require DoT; can't use `tls://` resolvers |
| **No Linux DNS OS configurator** — Rust uses `NoopConfigurator` on Linux; Go supports `resolved`, `NetworkManager`, `direct resolv.conf` | `manager_linux.go`, `direct.go`, `resolved.go`, `nm.go` | `osconfig.rs` — `build_os_dns_config` only, no `SetDNS` | P2 | Linux users must manually configure resolv.conf; no split DNS on Linux |
| **No `maxActiveQueries` limit** — Rust has no concurrent query limit | `tsdns.go:maxActiveQueries=256` | absent | P2 | Upstream query flood possible under heavy load |
| **No DNS-over-HTTPS for exit node DNS forwarding** — Go's `tsdial` supports exit node DoH proxy | `tsdial.go:dohclient.go` | absent from dns forwarder | P2 | Exit node DNS resolution unavailable when using exit nodes |

---

## 10. Health tracking

### Go files
- `health/health.go` — `Tracker` with ~20 registered Warnables (DERP home/region/connectivity, map-poll staleness, IP forwarding, UDP4 bind, TLS connection, warming-up, IPN state, update available), `Warnable` dependency chains (warming up suppresses all others), delayed visibility (`TimeToVisible`), `ReceiveFuncStats` for magicsock receive-liveness, `AppendWarnableDebugFlags`, `OverallError() error`, `CurrentState() *State` snapshot

### rustscale files
- `crates/health/src/lib.rs` — `Tracker` with 5 built-in warnables: CONTROL, DERP_HOME, CERT_FALLBACK, NETMON_CHANGE, CAPTIVE_PORTAL; `Watchdog` for map-poll staleness

### Parity.md claims
- "Health tracking" ✅ done at parity

### Gaps

| Gap | Go ref | Rust ref | Prio | Consequence |
|-----|--------|----------|------|-------------|
| **Only 5 of ~20+ warnables defined** — missing: IP forwarding, UDP4 bind, TLS connection failure, warming-up suppression, IPN state (wantrunning false), update available, magicsock-receive-func, map-response-timeout, no-DERP-connection, DERP-timeout, DERP-region-error | `health/warnings.go` (all registered Warnables) | `lib.rs` only 5 | P1 | Many critical health issues silently invisible to user and `health` CLI; reduced debuggability |
| **No dependency chain / delayed visibility** — Go suppresses all warnings during startup (5s warming up) and has variable `TimeToVisible` per warnable | `health.go:Warnable.DependsOn` + `TimeToVisible` | absent | P1 | Transient startup warnings fire immediately, cluttering status output; false positives |
| **No `OverallError`** — Go aggregates all warnings into a single error for programmatic checks | `health.go:Tracker.OverallError()` | absent | P2 | No single "is everything ok?" boolean |
| **No `ReceiveFuncStats`** — Go detects stuck magicsock receive goroutines | `health.go:ReceiveFuncStats` + `checkReceiveFuncsLocked` | absent | P1 | Dead magicsock receive task undetected; silent connectivity loss |
| **No per-region DERP health** — Go tracks per-region connectivity, frame receipt timestamps, stall detection | `health.go:derpRegionConnected`, `derpRegionHealthProblem`, `derpRegionLastFrame` | absent | P1 | DERP region failures invisible to user; no DIAG path for multi-region issues |

---

## 11. Other packages

| Go package | Rust crate | Status | Gaps |
|------------|-----------|--------|------|
| `net/netns/` (socket binding) | `crates/netns/` | 🔶 partial | macOS `IP_BOUND_IF` ✓, Linux `SO_BINDTODEVICE` ✓, no listen API, no `BindToInterface` for raw sockets |
| `net/tsaddr/` (IP helpers) | inlined in `dns` + `tsnet/routing` | 🔶 partial | No dedicated crate; `TailscaleServiceIP`, `CGNATRange`, `TailscaleULARange`, `IsTailscaleIP` scattered across crates |
| `net/tsdial/` (dial abstraction) | absent | ⬜ | No link-aware conn tracking, no PeerAPI HTTP client, no exit node DoH dialer; dial logic ad-hoc in tsnet |
| `net/dnscache/` | `crates/dnscache/` | ✅ parity | Verified: TTL cache, singleflight, last-good fallback |
| `net/dnsfallback/` | `crates/dnsfallback/` | ✅ parity | Verified: bootstrap-dns over embedded DERP IPs |
| `net/tstun/` (TUN wrapper) | `crates/tun/` | 🔶 partial | TUN device creation ✓ (macOS utun); no `Wrapper` with filter chain, SNAT/DNAT, disco key injection, GRO/GSO, TSMP pong |
| `net/sockstats/` | absent | ⬜ | No socket-level stats |
| `wgengine/netlog/` (flow logging) | absent | ⬜ | No network flow logging to tailscale cloud |
| `wgengine/router/` (OS routes) | ad-hoc route(8) calls in tsnet | ⬜ | No clean `Router` interface; no platform-specific route config (Linux netfilter, macOS route CLI) |
| `net/packet/` (packet headers) | `crates/filter/src/packet.rs` | 🔶 minimal | IP/TCP/UDP header parse only; no Geneve, no ICMP, no TSMP |
| `net/neterror/` | absent | ⬜ | No typed network errors for retry loops |
| `health/healthmsg/` | absent | ⬜ | No warning message constants |

---

## 12. Parity.md claims: verified true vs false

| Claim in parity.md | Actual status | Evidence |
|--------------------|--------------|----------|
| "ts2021 Noise control client" ✅ | ✅ | Full Noise IK handshake + h2 `client.rs` |
| "streaming netmap deltas" ✅ | 🔶 | Streams raw JSON but no delta processing (`PeersChanged`/`PeersRemoved`/`PeersChangedPatch` ignored at client level) |
| "magicsock (direct/DERP path selection, cross-region routing)" ✅ | 🔶 | Core path selection works but no periodic re-STUN, no continuous pinger, no heartbeat |
| "peer-relay client ✅" | ✅ | Full relay manager event loop verified |
| "WireGuard data plane (boringtun)" ✅ | ✅ | `WgTunn` wrapping boringtun, wired into tsnet |
| "packet filter (incl. stateful UDP)" ✅ | 🔶 | **FALSE** — capability-based ACLs not evaluated (`no_cap` always false); shields up absent |
| "Health tracking" ✅ | 🔶 | **OVERSTATED** — only 5 of 20+ warnables; no DERP per-region health; no dependency chains; no `ReceiveFuncStats` |
| "DERP client" ✅ | 🔶 | **OVERSTATED** — no pinned-key verify (P0); no token-bucket rate limiting on client; no auto-pong on server Ping |
| "netcheck (STUN)" ✅ | 🔶 | **OVERSTATED** — no ICMP probing; no DNS resolution for STUN targets; no incremental probe plan |
| "Network monitor (netmon)" ✅ | 🔶 | No Linux netlink (polling only); no per-interface IP change tracking |
| "Port mapping" ✅ | ✅ | Most complete port — no P0/P1 gaps |

---

## Top 10 most important gaps

| Rank | Area | Gap | Impact |
|------|------|-----|--------|
| **1** | magicsock | **No periodic re-STUN / heartbeat pinger** — Go re-probes endpoints every ~20s; Rust probes once per netmap set | After NAT rebind (common on WiFi/cellular), Rust's endpoints are stale until the next netmap (minutes). Silent connectivity loss. Go's `endpoint.go:heartbeatInterval=3s` detects this in seconds. |
| **2** | controlclient | **No zstd decompression** — `MapRequest.Compress: "zstd"` sent, compressed responses produce parse errors | **Immediate production blocker**: Tailscale servers will zstd-compress map responses by default. Rust `serde_json::from_slice` on zstd data produces garbage errors → permanent map-poll failure. |
| **3** | DERP | **No pinned-key verify** — `DerpClient::from_stream` accepts any server key | Any attacker who intercepts a DERP connection (compromised TLS cert, captive portal, corporate proxy) can MITM all relay traffic. Go verifies via metacert or `Derp-Public-Key` header. |
| **4** | magicsock | **No MTU/PMTUD** — zero MTU awareness | Path MTU changes undetected → WireGuard oversized packets silently dropped. Go's `peermtu.go` uses DF-bit + padded pings to detect and adapt. |
| **5** | controlclient | **No key rotation / re-registration on expiry** — `OldNodeKey` never populated, no expiry loop | Node key expiry = permanent disconnection. No graceful regeneration. |
| **6** | filter | **Capability ACLs not evaluated** — `CapMatch` parsed but `no_cap` always returns false | All capability-based ACL rules silently pass either fully open or fully blocked depending on direction. Security boundary broken for feature-gated access. |
| **7** | health | **Missing 15 of 20 warnables** — no DERP per-region health, no IP-forwarding check, no UDP4 bind check, no TLS failure, no magicsock receive-func monitoring | Critical failures invisible to operator. `health` CLI reports nothing when core subsystems are broken. |
| **8** | controlclient | **No logout** — no API to deregister from control | Orphan node identity on control server. Reconnection with same key may be rejected if control marks session terminated. |
| **9** | controlclient | **No endpoint streaming** — `SetEndpoints` changes never sent to control | Control server has stale endpoint list; cannot relay CallMeMaybe to newly discovered endpoints. |
| **10a** | netcheck | **No DNS resolution for STUN targets** — only probes pre-resolved IPs | DERP regions with hostname-only nodes skipped entirely → incomplete probe → wrong home DERP selected. |
| **10b** | controlclient/map | **No delta processing** — full peer list rebuild on every map response | CPU overhead proportionally scales with tailnet size; control may throttle clients that don't use deltas. |

*Note: Items 10a and 10b are tied for 10th place.*

---

## Summary for parity.md corrections needed

**Status downgrades needed:**
- `packet filter` ✅ → 🔶 (cap-based ACLs not evaluated, no shields-up)
- `Health tracking` ✅ → 🔶 (5/20 warnables, no DERP region health, no dependency chain)
- `DERP client` ✅ → 🔶 (no pinned-key verify P0, no client rate limiting, no auto-pong)
- `netcheck (STUN)` ✅ → 🔶 (no ICMP, no DNS resolution, no incremental probes)
- `Network monitor` ✅ → 🔶 (no Linux netlink)
- `magicsock` ✅ → 🔶 (no re-STUN, no heartbeat, no PMTUD, no endpoint type tracking, no PeerGone handling, no derpRoute expiry)

**New gaps to add:**
- `controlclient`: missing logout, key rotation, zstd decompression, delta processing, endpoint streaming, map session handles
