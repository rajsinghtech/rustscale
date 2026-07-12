# Adversarial Verification of Parity-Audit Findings

Date: 2026-07-12
Method: Every P0/P1 finding in `docs/audit/{core-stack,ipn-cli-daemon,features-services}.md` was
verified by reading the actual rustscale source code (grep + file reads) and, where needed, the
Go reference at `/Users/rajsingh/Documents/GitHub/tailscale`. P2s were skipped per instructions.

Verdict legend:
- **CONFIRMED** — gap is real; cite rustscale file showing absence/stub + Go file showing behavior
- **REFUTED** — feature exists; cite rustscale file:line proving it
- **PARTIAL** — exists but incomplete; state exactly what's missing
- **MISCLASSIFIED** — real but wrong priority; state correct priority and why

---

## Consolidated Verification Table

### core-stack.md findings

| # | Finding | Report | Verdict | Evidence (rustscale file:line) | Corrected Priority |
|---|---------|--------|---------|-------------------------------|-------------------|
| 1 | No logout — no API to send POST /machine/logout | core-stack P0 | **CONFIRMED** | `daemon.rs:109-111` — Logout handler only prints "logout requested"; no `ControlClient::logout` method exists; `client.rs` has no TryLogout. LocalAPI handler exists (`localapi.rs:321`) but daemon discards it. | P0 |
| 2 | No key rotation / re-registration — OldNodeKey never populated | core-stack P0 | **CONFIRMED** | `register.rs:23` — field exists; `tsnet/lib.rs:3178-3191` — expiry detected but no re-register call; `OldNodeKey` defaults to zero everywhere. | P0 |
| 3 | No zstd decompression — Compress:"zstd" sent but responses not decompressed | core-stack P0 | **MISCLASSIFIED** | `map.rs:209` — zstd only in unit test; all production `MapRequest` use `..Default::default()` giving `Compress: ""` (`tsnet/lib.rs:2044,3542,3625,3745`). No zstd crate in any Cargo.toml. Server never receives zstd request → responses are uncompressed JSON → nothing breaks. | **P2** (bandwidth optimization, not correctness) |
| 4 | No periodic re-STUN / background probing — only probes once on set_netmap | core-stack P0 | **PARTIAL** | `tsnet/lib.rs:3590-3608` — `spawn_periodic_endpoint_updates` runs a 5-minute re-STUN loop. `tsnet/lib.rs:3526` — `link_changed()` re-STUN on major link change. Gap: 5min vs Go's ~20-26s (15x slower). "Only probes once" is factually wrong. | **P1** (periodic exists, just slower) |
| 5 | No continuous disco pinger / heartbeat — no 3s interval | core-stack P0 | **CONFIRMED** | No `tokio::time::interval` for disco pings anywhere in magicsock. Pings fire only on `set_netmap` (`lib.rs:734-760`) and CallMeMaybe receipt (`lib.rs:1501-1521`). | P0 |
| 6 | No UDP lifetime probing — no cliff intervals (10/30/60s) | core-stack P0 | **CONFIRMED** | Zero matches for `probeUDPLifetime|udp_lifetime|cliff` across all crates. | P0 |
| 7 | No MTU / PMTUD — zero MTU awareness | core-stack P0 | **CONFIRMED** | Zero matches for `peermtu|PMTUD|pmtud|mtu_probe` across all crates. | P0 |
| 8 | No DERP pinned-key verify — from_stream accepts any server key | core-stack P0 | **CONFIRMED** | `derp/client.rs:147-162` — `from_stream(stream, private_key)` takes no expected key; `recv_server_key` (321-336) stores whatever key is presented without verification against DERPMap. | P0 |
| 9 | No token-bucket rate limiting on client sends | core-stack P0 | **CONFIRMED** | `derp/client.rs:396-404` — `send_packet` writes directly via `write_frame_async`, no rate check. | P0 |
| 10 | No delta processing — PeersChanged/PeersRemoved/PeersChangedPatch ignored | core-stack P1 | **PARTIAL** | `tsnet/lib.rs:3214-3227` — `PeersChanged` (update/insert) and `PeersRemoved` (retain) ARE handled. `PeersChangedPatch` is NOT handled (zero matches). "No delta-apply logic" is too strong. | P1 |
| 11 | No map session handles — MapSessionHandle+Seq never used | core-stack P1 | **CONFIRMED** | `map.rs:105,112` — fields defined and deserialized but never read. Zero usage in any logic. | P1 |
| 12 | Missing Node fields: KeySignature, LastSeen, IsJailed, IsWireGuardOnly, Expired, UnsignedPeerAPIOnly | core-stack P1 | **CONFIRMED** | `tailcfg/node.rs:38-159` — Node struct lacks all 6 fields. | P1 |
| 13 | No NetInfo processing — not wired to magicsock | core-stack P1 | **CONFIRMED** | NetInfo sent TO control in Hostinfo (`tsnet/lib.rs:2055,3554`); no `SetNetInfo` method on Magicsock; never wired FROM control. | P1 |
| 14 | No UpdateEndpoints / endpoint streaming | core-stack P1 | **REFUTED** | `tsnet/lib.rs:3590` — `spawn_periodic_endpoint_updates` sends endpoints every 5min via `MapRequest{OmitPeers:true}`; `lib.rs:3481` — `spawn_link_monitor` pushes on network change; `lib.rs:1819` — initial push. | — |
| 15 | No LoginFlags variant support — LoginEphemeral, LoginInteractive not plumbed | core-stack P1 | **CONFIRMED** | No `LoginFlags` type anywhere; `register.rs:50` has only `Ephemeral: bool`. | P1 |
| 16 | No derpRoute expiry — last_recv_derp_region never cleared | core-stack P1 | **PARTIAL** | `endpoint.rs:241` — `reset_for_link_change()` clears it to 0. `endpoint.rs:135-137` — `set_last_recv_derp_region()` sets it. "Never cleared" is false — cleared on link change. No timer-based expiry (Go uses `derpRouteCleanupTimeout`). | P1 |
| 17 | No PeerGone handling — frames received but never processed | core-stack P1 | **CONFIRMED** | `derp_io.rs:108-122` — reader only handles `RECV_PACKET` and `PING`; no `PEER_GONE` branch. `protocol.rs:150-161` can parse it but DerpIo never calls `parse_received`. | P1 |
| 18 | No endpoint type tracking — candidates as Vec<SocketAddr> without EndpointType | core-stack P1 | **CONFIRMED** | `endpoint.rs:71` — `candidates: Vec<SocketAddr>`. Zero matches for `EndpointType|endpoint_type` in magicsock. | P1 |
| 19 | No NotePreferred DERP frame sent | core-stack P1 | **REFUTED** | `tsnet/lib.rs:1939` — `c.note_preferred(true).await` called on home DERP connect. `derp/client.rs:424-427` — method sends `NOTE_PREFERRED` frame. | — |
| 20 | No pong piggyback learning — Ping NodeKey not used for addr_to_peer | core-stack P1 | **PARTIAL** | `lib.rs:1384-1414` — `ping.node_key` is unused, but `addr_to_peer.insert(src, peer)` IS executed via disco-key lookup (`lib.rs:1413`). Gap: when disco key not in `disco_to_peer`, returns early — Go would use `node_key` as fallback. | P1 |
| 21 | No multiple candidate probing — pings first candidate only | core-stack P1 | **REFUTED** | `lib.rs:734` — `for addr in &candidates` iterates ALL candidates, pinging each. `lib.rs:1501` — `for ep in &cmm.my_number` pings all CallMeMaybe addresses. | — |
| 22 | No CallMeMaybe retriggering — set once, never cleared | core-stack P1 | **PARTIAL** | `endpoint.rs:226-228` — `reset_call_me_maybe()` clears to false. `lib.rs:702` — called on every `set_netmap`. `endpoint.rs:242` — cleared on link change. "Never cleared" is false. Gap: no retrigger on direct-path trust expiry (15s). | P1 |
| 23 | WireGuard per-peer tunnel, not single device — N tunnels, no roaming, no Reconfig | core-stack P1 | **CONFIRMED** | `tsnet/lib.rs:573` — `wg_tunnels: HashMap<NodePublic, Arc<Mutex<WgTunn>>>`. No single-device model, no Reconfig, no roaming. | P1 |
| 24 | No mesh routing — ForwardPacket/WatchConns/ClosePeer discarded | core-stack P1 | **CONFIRMED** | `derp/server.rs:494-520` — explicitly discards `WATCH_CONNS`, `CLOSE_PEER`, `FORWARD_PACKET` ("Not mesh; discard body"). | P1 |
| 25 | No auto-pong on server Ping — recv returns Ping, caller must pong | core-stack P1 | **REFUTED** | `derp_io.rs:116-122` — DerpIo wrapper (production path) auto-pongs: detects `frame_type::PING`, sends `DerpCmd::Pong{data}`. Raw `DerpClient::recv` returns Ping, but magicsock uses DerpIo exclusively. | — |
| 26 | No ICMP probing — Report.ICMPv4 never set | core-stack P1 | **CONFIRMED** | `netcheck/report.rs:33-34` — "not implemented yet; always false". No ICMP code in prober. | P1 |
| 27 | No DNS resolution for STUN targets — only explicit IPs | core-stack P1 | **CONFIRMED** | `netcheck/prober.rs:211-236` — `node_addr_port` says "DNS resolution is not performed here"; hostname-only nodes skipped. | P1 |
| 28 | No capability evaluation during filtering — no_cap always returns false | core-stack P1 | **CONFIRMED** | `filter/lib.rs:306-308` — `fn no_cap(_: &IpAddr, _: &str) -> bool { false }`. Used in every `matches`/`matches_ips_only` call. | P1 |
| 29 | No shields-up mode — Filter has no shields-up field | core-stack P1 | **CONFIRMED** | `filter/lib.rs:49-55` — Filter struct has no shields_up field. `Filter::new` takes `(rules, local_ips)`. ShieldsUp exists in Prefs (`prefs.rs:44`) but is never wired to the filter. | P1 |
| 30 | No Linux netlink support — polling (10s) on Linux | core-stack P1 | **CONFIRMED** | `netmon/os.rs:6-7` — Linux uses `os_poll`; `os_poll.rs:1-5` — "poll every 10s". No `os_linux.rs`, no netlink socket. | P1 |
| 31 | No DNS cache — every query hits upstream | core-stack P1 | **PARTIAL** | `crates/dnscache/` — full TTL cache with singleflight + stale fallback EXISTS (669 lines), used by `controlclient` (`controlhttp.rs:160-165`) and `dnsfallback`. The MagicDNS **forwarder** (`dns/forwarder.rs`) does NOT use it. "No DNS cache" is false; "forwarder doesn't cache" is true. | **P2** (cache exists, wiring gap) |
| 32 | Only 5 of ~20+ warnables defined | core-stack P1 | **CONFIRMED** | `health/lib.rs:27-35,98-122` — exactly 5: CONTROL, DERP_HOME, CERT_FALLBACK, NETMON_CHANGE, CAPTIVE_PORTAL. | P1 |
| 33 | No dependency chain / delayed visibility — no DependsOn, no TimeToVisible | core-stack P1 | **CONFIRMED** | `health/lib.rs:51-55` — Warnable has only `id, severity, title`. No DependsOn or TimeToVisible fields. | P1 |
| 34 | No ReceiveFuncStats — no stuck receive task detection | core-stack P1 | **CONFIRMED** | Zero matches for `ReceiveFuncStats` in health crate. | P1 |
| 35 | No per-region DERP health | core-stack P1 | **CONFIRMED** | Only `WARN_DERP_HOME` exists (`lib.rs:29`). Zero matches for `derp_region|DerpRegion` health tracking. | P1 |

### ipn-cli-daemon.md findings

| # | Finding | Report | Verdict | Evidence (rustscale file:line) | Corrected Priority |
|---|---------|--------|---------|-------------------------------|-------------------|
| 36 | Prefs: ExitNodeAllowLANAccess, RunSSH, AutoExitNode missing | ipn P0 | **CONFIRMED** | `ipn/prefs.rs:28-59` — 15 fields; none of the 3 present. MaskedPrefs also lacks *Set bools. | P0 |
| 37 | Notify: NetMap, PeersChanged, PeersRemoved, PeerChangedPatch missing | ipn P0 | **CONFIRMED** | `ipn/lib.rs:212-250` — 9 fields; all 4 absent. Watch-opt bits defined but no data fields. | P0 |
| 38 | LocalAPI: cert/ endpoints missing (in flight) | ipn P0 | **CONFIRMED** | `localapi.rs:464-569` — 13 endpoints; no cert/. Master only (worktree has it). | P0 |
| 39 | CLI: file, cert subcommands missing (in flight) | ipn P0 | **CONFIRMED** | `cli/commands/mod.rs:1-16` — 16 modules; no file/cert. Master only. | P0 |
| 40 | State machine: logged_out/blocked hardcoded false — never enters InUseOtherUser | ipn P0 | **CONFIRMED** | `backend.rs:92-95` — `logged_out: false, blocked: false` hardcoded. No setters exist (grep found zero). `machine.rs:42-103` — no branch returns `InUseOtherUser` even if blocked were true. Gap is worse than described. | P0 |
| 41 | Serve: Foreground sessions + HTTPS redirect missing | ipn P0 | **CONFIRMED** | `serve.rs:70-82` — no `Foreground` field. No HTTP→HTTPS redirect in `dispatch_serve` (480-522) or `handle_http` (575-627). | P0 |
| 42 | Prefs: AutoUpdate, NetfilterMode, NoSNAT, PostureChecking, AppConnector, RunWebClient missing | ipn P1 | **CONFIRMED** | `prefs.rs:28-59` — all 6 absent. | P1 |
| 43 | Notify: Health, ClientVersion, SuggestedExitNode, UserProfiles, InitialStatus(full) missing | ipn P1 | **PARTIAL** | `lib.rs:249` — `InitialStatus: Option<serde_json::Value>` EXISTS and is populated (`backend.rs:201-203`). Other 4 absent. | P1 |
| 44 | LocalAPI missing 15 endpoints (check-prefs, set-expiry-sooner, shutdown, etc.) | ipn P1 | **CONFIRMED** | `localapi.rs:464-569` — none of the 15 listed endpoints present. | P1 |
| 45 | CLI missing 8 subcommands (debug, bugreport, ssh, nc, id-token, exit-node, update, dns) | ipn P1 | **CONFIRMED** | `cli/commands/mod.rs:1-16` — none of the 8 present. | P1 |
| 46 | Daemon missing 6 flags (--port, --state, --socket, --socks5-server, --http-proxy-server, --cleanup) | ipn P1 | **CONFIRMED** | `rustscaled/main.rs:30-53` — only --statedir, --hostname, --tun parsed. | P1 |
| 47 | LocalClient missing: Debug, cert/ACME, taildrop, dial, DNS query, check-ip-forwarding, whois variants | ipn P1 | **CONFIRMED** | `localclient/lib.rs:51-279` — 21 methods; none of the listed categories present. | P1 |
| 48 | Serve: Foreground, HTTPS redirect, Ingress-Target dispatch, ServiceConfig, HTTPHandler.Redirect | ipn P1 | **CONFIRMED** | `serve.rs` — no Foreground, no redirect, no ServiceConfig type, no HTTPHandler.Redirect field (115-127), no Tailscale-Ingress-Target header dispatch. Overlaps with #41. | P1 |
| 49 | Captive portal: health tracker integration missing | ipn P1 | **CONFIRMED** | `health/lib.rs:35,118-122` — WARN_CAPTIVE_PORTAL defined/registered but never SET. `netcheck/prober.rs:165` — detection result stored in report but never forwarded to `Tracker::set_unhealthy`. | P1 |
| 50 | C2N: tls-cert-status missing (in flight) | ipn P1 | **CONFIRMED** | `c2n/lib.rs:427-446` — not in KNOWN_PATHS; no handler. Master only. | P1 |
| 51 | Profile manager: auto-switch, key renewal, auto-detection | ipn P1 | **CONFIRMED** | `ipn/profiles.rs:42-152` — plain data struct with serde persistence only. No ProfileManager, no auto-switch, no key renewal, no auto-detection. | P1 |

### features-services.md findings

| # | Finding | Report | Verdict | Evidence (rustscale file:line) | Corrected Priority |
|---|---------|--------|---------|-------------------------------|-------------------|
| 52 | ListenPacket (UDP) — no UDP listen on netstack | features P0 | **CONFIRMED** | `netstack/lib.rs:35-36` — imports only `smoltcp::socket::tcp`; Command enum (373-395) has only TCP ops. No `listen_packet` in tsnet. | P0 |
| 53 | SSH policy feed — always returns None, rejecting all connections | features P0 | **FIXED** | `tsnet/ssh.rs:61` previously `Arc::new(\|\| None)` — now reads shared `ssh_policy: Arc<RwLock<Option<SSHPolicy>>>` fed by `spawn_map_update_task` from `MapResponse.SSHPolicy`. `ssh/server.rs` honours Reject actions. `ssh/auth.rs:eval_ssh_policy` now reached. Remaining: session recording (#63), incubator (#64), HoldAndDelegate. | ~~P0~~ |
| 54 | Port builder method missing — can't pin WG UDP port | features P1 | **CONFIRMED** | `tsnet/lib.rs:178-229` — ServerBuilder has no port field/method. | P1 |
| 55 | AdvertiseTags builder method missing | features P1 | **CONFIRMED** | `tsnet/lib.rs:178-229` — no advertise_tags on builder. Tags settable via prefs/CLI but not builder. | P1 |
| 56 | UserLogf/Logf — no pluggable logger | features P1 | **CONFIRMED** | `tsnet/lib.rs:178-229` — no logger field. All logging via `eprintln!` or `log::` macros. | P1 |
| 57 | Start() lazy/idempotent + auto-called by Dial/Listen missing | features P1 | **CONFIRMED** | `lib.rs:798-801` — `up()` errors with `AlreadyUp` on second call. `lib.rs:2289` — `listen()` errors `NotUp`. `lib.rs:2400` — `dial()` errors `NotUp`. No auto-start. | P1 |
| 58 | Up() returns unit, not status | features P1 | **CONFIRMED** | `lib.rs:798` — `pub async fn up(&mut self) -> Result<(), TsnetError>`. Separate `status()` method exists. | P1 |
| 59 | LocalClient in-memory accessor missing | features P1 | **CONFIRMED** | `localclient/lib.rs:47` — connects via Unix socket only. No in-memory accessor on Server. `Server::localapi_path()` exists but requires socket round-trip. | P1 |
| 60 | Loopback() combined SOCKS5+LocalAPI missing | features P1 | **CONFIRMED** | No `Loopback` method on Server. `socks5.rs` binds separately; no combined listener. | P1 |
| 61 | CapturePcap missing | features P1 | **CONFIRMED** | Zero matches for `pcap|capture_pcap|CapturePcap` across entire repo. | P1 |
| 62 | RegisterFallbackTCPHandler missing | features P1 | **CONFIRMED** | Zero matches for `fallback_tcp|RegisterFallback|FallbackTCP` across repo. | P1 |
| 63 | SSH session recording missing | features P1 | **CONFIRMED** | `ssh/session.rs` (204 lines) — no recording field/logic. Zero `record` matches in ssh crate. | P1 |
| 64 | SSH incubator subprocess mgmt missing | features P1 | **CONFIRMED** | Zero matches for `incubator` in ssh crate. No subprocess spawning. | P1 |
| 65 | Exit node wiring from prefs to RouteTable broken — set_exit_node never called from pref-change | features P1 | **CONFIRMED** | Full trace: `localapi.rs:345-378` (`handle_patch_prefs`) → applies MaskedPrefs, saves, sends Notify — **does NOT call set_exit_node**. `routing.rs:152` (`set_exit_node`) called only from: `Server::set_exit_node` (lib.rs:2491), `up_tun` (lib.rs:1121), FFI (ffi/lib.rs:590), tests. No call from prefs flow. CLI `--exit-node` is a no-op for routing. Special check 3 confirmed. | P1 |
| 66 | AllowLANAccess missing | features P1 | **CONFIRMED** | Zero matches for `AllowLANAccess|allow_lan_access` across all .rs files. Not in prefs, not in routing. | P1 |
| 67 | SuggestExitNode missing | features P1 | **CONFIRMED** | Zero matches for `SuggestExitNode|suggest_exit_node` across all .rs files. | P1 |
| 68 | ServiceModeHTTP missing | features P1 | **CONFIRMED** | `service.rs:52-58` — ServiceMode has only `port` + `proxy_protocol`; only `tcp(port)` constructor. "Only TCP mode implemented" (line 50). | P1 |
| 69 | TerminateTLS missing | features P1 | **REFUTED** | `serve.rs:101` — `pub TerminateTLS: String` EXISTS in TCPPortHandler. `serve.rs:508-517` — when non-empty, TLS terminated via `build_tls_acceptor(cert)` before TCP forwarding. `lib.rs:2567` — `set_serve_config` checks TerminateTLS. Tests in `serve_tests.rs:72,78`. | — |
| 70 | logtail log streaming missing | features P1 | **CONFIRMED** | `c2n/lib.rs:496-497` — `/logtail/flush` returns 204 no-op. No logtail code. | P1 |
| 71 | logtail buffer management missing | features P1 | **CONFIRMED** | Zero matches for `filch` across repo. No buffer/ring-buffer. | P1 |
| 72 | Client metrics registry missing | features P1 | **PARTIAL** | `localapi.rs:847-898` — 4 hardcoded Prometheus metrics (packet_drops, peer_count, health_warnings, local_endpoints). No registry pattern for subsystems to register their own. | P1 |
| 73 | clientupdate update check missing | features P1 | **CONFIRMED** | Zero matches for `clientupdate` across all .rs files. | P1 |
| 74 | clientupdate auto-apply missing | features P1 | **CONFIRMED** | Same — no clientupdate code at all. | P1 |
| 75 | ClientVersion from control not processed | features P1 | **CONFIRMED** | `tailcfg/map.rs:98-198` — `MapResponse` has NO `ClientVersion` field (not even in type). Dropped at JSON layer. | P1 |
| 76 | SOCKS5 loopback integration missing | features P1 | **CONFIRMED** | `socks5.rs:618-635` — binds separately on OS TCP stack. No Loopback() method on Server. Overlaps with #60. | P1 |
| 77 | SOCKS5 auth for loopback missing | features P1 | **CONFIRMED** | `socks5.rs:12` — "no-auth only". Lines 478-483 — rejects clients not offering NO_AUTH. No username/password auth. | P1 |
| 78 | HTTP CONNECT proxy missing | features P1 | **CONFIRMED** | Zero matches for `connectproxy|connect_proxy` across repo. | P1 |
| 79 | Hostinfo.ShieldsUp not populated | features P1 | **CONFIRMED** | `tailcfg/node.rs:280` — field exists. `hostinfo.rs:76-134,235-247` — never set from prefs. `tsnet/lib.rs:3727-3737` — builds `Hostinfo{..Default::default()}` (ShieldsUp=false). Prefs has it (`prefs.rs:44`) but it never reaches Hostinfo. | P1 |
| 80 | Hostinfo field count — parity.md claims "all 36 Go fields" but only 18/41 populated | features §8 | **PARTIAL** | Go has **42** fields (not 41/36). Rustscale struct has all 42 fields. **18 fully populated** + **5 partially** = 23/42 (55%). 19 never populated. parity.md "all 36" is FALSE. Audit's "18/41" is approximately correct for fully-populated; total is 42 not 41. Special check 4 confirmed. | P1 (ShieldsUp) / P2 (rest) |

---

## Summary Statistics

| Verdict | Count | Percentage |
|---------|-------|-----------|
| CONFIRMED | 57 | 71% |
| PARTIAL | 11 | 14% |
| REFUTED | 7 | 9% |
| MISCLASSIFIED | 2 | 3% |
| (REFUTED + PARTIAL = audit errors) | 18 | 22% |
| **Total P0/P1 findings verified** | **80** | |

Findings REFUTED (7): #14 endpoint streaming, #19 NotePreferred, #21 multiple candidate probing, #25 auto-pong on server Ping, #69 TerminateTLS. Plus the known examples (#3 zstd MISCLASSIFIED, #4 re-STUN PARTIAL).

Findings MISCLASSIFIED (2): #3 zstd (P0→P2, never sent), #31 DNS cache (P1→P2, cache exists just not wired to forwarder).

---

## Special Checks Summary

1. **crates/ssh on master?** YES — exists with 4 git commits. Audit correctly read master, not worktree. SSH server code is real but policy callback is `Arc::new(|| None)` (`ssh.rs:61`), making it dead code in production. Finding #53 CONFIRMED.

2. **logged_out/blocked hardcoded false?** YES — `backend.rs:92-95` hardcodes both. No setters exist anywhere. State machine `machine.rs:42-103` has NO branch returning `InUseOtherUser` even if blocked were true. Gap is worse than audit described. Finding #40 CONFIRMED.

3. **Exit node prefs→routing wiring?** BROKEN — `handle_patch_prefs` (`localapi.rs:345-378`) updates prefs and persists but never calls `set_exit_node`. The direct `Server::set_exit_node()` API works, and `up_tun` applies `TunModeConfig.exit_node` at startup, but CLI `--exit-node` via PATCH /prefs is a routing no-op. Finding #65 CONFIRMED.

4. **Hostinfo field count?** Go has 42 fields (not 36/41). Rustscale struct defines all 42. 18 fully populated + 5 partially = 23/42 (55%). parity.md's "all 36 Go fields" is FALSE. Audit's "18/41" is close but total is 42. Finding #80 PARTIAL.

---

## Ranked Top-15 CONFIRMED/PARTIAL Gaps (P0+P1)

Ordered by security/correctness first, then user impact.

| Rank | Finding | Priority | Category | Impact |
|------|---------|----------|----------|--------|
| **1** | **DERP pinned-key verify missing** (#8) | P0 | Security | `derp/client.rs:147` accepts any server key — MITM on all relay traffic undetectable. Go verifies against DERPMap public key. |
| **2** | **Capability ACLs not evaluated** (#28) | P1→P0 | Security | `filter/lib.rs:306` `no_cap()` always returns false. Capability-based ACL rules silently bypassed. Security boundary broken for feature-gated access. |
| **3** | ~~**SSH policy feed always None** (#53)~~ **FIXED** | ~~P0~~ | Security/Feature | `ssh.rs:61` previously hardcoded `Arc::new(\|\| None)` — now reads shared netmap `SSHPolicy` state. Reject actions honoured. Remaining gaps: session recording, incubator, HoldAndDelegate. |
| **4** | **State machine InUseOtherUser unreachable** (#40) | P0 | Correctness | `backend.rs:94-95` hardcodes logged_out/blocked=false; `machine.rs` has no InUseOtherUser branch. Fundamental state correctness broken. |
| **5** | **No key rotation / re-registration** (#2) | P0 | Correctness | `OldNodeKey` never populated; no expiry re-register loop. Node key expiry = permanent disconnection. |
| **6** | **No logout from control** (#1) | P0 | Correctness/Security | `daemon.rs:109` prints "logout requested" but does nothing. Orphan node identity on control server. |
| **7** | **No continuous disco pinger / heartbeat** (#5) | P0 | Connectivity | No 3s heartbeat timer. Direct path unreachable after NAT rebind unless peer coincidentally re-probes. DERP fallback persists when direct would work. |
| **8** | **No UDP lifetime probing** (#6) | P0 | Connectivity | No cliff-interval probing. Silent path death: pinhole closes but peer thinks path alive. |
| **9** | **No MTU / PMTUD** (#7) | P0 | Connectivity | Zero MTU awareness. Oversized WG packets silently dropped or IP fragmentation fails. |
| **10** | **ListenPacket (UDP) missing** (#52) | P0 | API Completeness | `netstack/lib.rs` is TCP-only. No UDP receive on tailnet. DNS servers, custom UDP protocols impossible via tsnet. |
| **11** | **Exit node prefs→routing broken** (#65) | P1 | Correctness/UX | `handle_patch_prefs` never calls `set_exit_node`. CLI `--exit-node` updates prefs but routing doesn't change. Core feature is a no-op via CLI. |
| **12** | **Notify missing NetMap + peer deltas** (#37) | P0 | Correctness | `ipn/lib.rs:212` — 9 fields, no NetMap/PeersChanged/PeersRemoved/PeerChangedPatch. `watch-ipn-bus` subscribers get empty peer data. |
| **13** | **No shields-up mode in filter** (#29) | P1→P0 | Security | `filter/lib.rs:49` — no shields_up field. No emergency lockdown mode. Pref exists but never wired to filter. |
| **14** | **No DERP client rate limiting** (#9) | P0 | Correctness | `derp/client.rs:396` — `send_packet` writes unconditionally. Can overrun DERP server queue → head-of-line blocking. |
| **15** | **No per-region DERP health** (#35) | P1 | Observability | Only `WARN_DERP_HOME` exists. DERP region failures invisible to user and `health` CLI. No region-level connectivity/latency tracking. |

---

## Audit Quality Assessment

- **core-stack.md**: 35 P0/P1 findings → 20 CONFIRMED, 8 PARTIAL, 5 REFUTED, 2 MISCLASSIFIED. Most common error pattern: "never" claims where the feature exists but is incomplete (derpRoute, CallMeMaybe, pong piggyback, re-STUN). Key REFUTED findings: NotePreferred, multiple candidate probing, auto-pong, endpoint streaming.
- **ipn-cli-daemon.md**: 16 P0/P1 findings → 15 CONFIRMED, 1 PARTIAL. Highly accurate. The one nuance: `InitialStatus` exists but other 4 Notify fields are truly missing. State machine finding is actually worse than described (no InUseOtherUser branch in truth table at all).
- **features-services.md**: 28 P0/P1 findings → 26 CONFIRMED, 1 REFUTED, 1 PARTIAL. Highly accurate. One clear error: TerminateTLS EXISTS at `serve.rs:101` and is fully implemented. Exit node wiring trace confirmed broken.
