# Phase 7: Packet Filter Enforcement

You are a senior Rust systems engineer porting Tailscale's Go client stack to Rust.
The Go reference is at `/Users/rajsingh/Documents/GitHub/tailscale` (READ ONLY — never modify).
Before reading Go sources, check `docs/porting-notes.md` for already-distilled facts.
Run `tools/check.sh` to verify (silent on success, ~50 lines on failure — do NOT dump full cargo output).
Run `tools/clippy-all.sh <crate>` to see ALL clippy warnings in one pass. Fix them all before re-running.
Do NOT fetch docs.rs or explore `~/.cargo/registry/` for crate APIs. If you need a crate not in
`docs/porting-notes.md`, hand-roll it instead.
To find a specific function in your own files, use `grep -n 'fn name'` instead of re-reading the whole file.

## GO REFERENCE FILES (read only the specific sections you need)

- `wgengine/filter/filter.go` (743 lines) — Filter struct, New(), RunIn/RunOut, pre(), runIn4/runIn6
- `wgengine/filter/match.go` (107 lines) — match(), matchIPsOnly(), matchProtoAndIPsOnlyIfAllPorts()
- `wgengine/filter/tailcfg.go` (178 lines) — MatchesFromFilterRules(), parseIPSet(), defaultProtos
- `wgengine/filter/filtertype/filtertype.go` (116 lines) — Match, NetPortRange, PortRange, CapMatch types
- `wgengine/filter/filter_test.go` (1384 lines) — test cases to port (TestFilter, TestUDPState, TestMatchesFromFilterRules)
- `tailcfg/tailcfg.go` lines 1493-1750 — PortRange, NetPortRange, CapGrant, FilterRule types
- `tailcfg/tailcfg.go` lines 2065-2101 — MapResponse.PacketFilter / PacketFilters fields with docs

## GO SEMANTICS TO REPLICATE (distilled — read Go only to verify edge cases)

### Response enum
```
Drop, DropSilently, Accept, NoVerdict (internal)
```

### IP protocol constants
```
UNKNOWN=0, ICMPv4=1, IGMP=2, TCP=6, UDP=17, IPv6Frag=44, ICMPv6=58, SCTP=132, TSMP=99
```

### pre() — direction-agnostic checks (run before runIn/runOut)
1. Empty buffer (len==0) → Accept (WireGuard keepalive)
2. len < 20 → Drop ("too short")
3. proto == Unknown → Drop ("unknown proto")
4. dst is multicast → Drop ("multicast")
5. dst is link-local unicast → Drop ("link-local-unicast") [unless allowed hook — skip hooks for now]
6. proto == Fragment (IPv6Frag=44) → Accept ("fragment")
7. Otherwise → NoVerdict (continue to runIn/runOut)

### runIn (inbound filter — the core)
First check: is dst IP in our local IP set? If NOT → NoVerdict ("destination not allowed").
(This is critical: a compromised peer could send packets to IPs we didn't advertise. The localNets
check prevents that. The packet is dropped later if no IngressAllowHooks match — we have none, so
it becomes Drop.)

Then by protocol:
- **ICMPv4/ICMPv6**: if echo-response or error → Accept ("icmp response ok"). Else if any rule
  matches src+dst IPs only (ignoring ports/proto) → Accept ("icmp ok"). Else NoVerdict.
- **TCP**: if NOT a SYN packet → **Accept** ("tcp non-syn"). This is the key stateful TCP rule:
  only SYN packets are filtered against rules. Non-SYN continuation packets always pass, because
  a new incoming session can't be initiated without a SYN. If IS a SYN → check rules; if match →
  Accept ("tcp ok"), else NoVerdict.
- **UDP/SCTP**: look up the 5-tuple (proto, src_addr:src_port, dst_addr:dst_port) in the flow
  state LRU cache. If found → Accept ("cached"). Else check rules; if match → Accept ("ok").
  Else NoVerdict.
- **TSMP (99)**: Accept ("tsmp ok").
- **Default (unknown proto)**: if any rule matches proto+src+dst with ALL ports (0-65535) →
  Accept ("other-portless ok"). Else NoVerdict.
- If still NoVerdict after all checks → Drop ("no rules matched").

### runOut (outbound filter)
Always Accept ("ok out"), BUT calls `UpdateOutboundFlowState` first:
- For UDP/SCTP: records the **reversed** 5-tuple (proto, dst_addr:dst_port, src_addr:src_port)
  in the LRU cache. This is how return UDP traffic gets accepted by the runIn UDP path above.
- For other protocols: no-op.
- The LRU cache has a max of **512 entries** (size-based eviction, NOT time-based). There is NO
  time-based timeout in Go's filter — the flowtrack.Cache is purely an LRU by size.

### Rule matching (match.go)
A Match has: IPProto (list of protos), Srcs (list of CIDR prefixes), Dsts (list of NetPortRange
= prefix + port range), SrcCaps (capability-based src matching — skip for now, keep the field).

`matches.match(q)`:
1. For each Match in order:
   a. If q.proto not in match.IPProto → skip
   b. If q.src not in any of match.Srcs prefixes → skip (SrcsContains)
   c. For each dst in match.Dsts: if q.dst IP in dst.Net prefix AND q.dst_port in dst.Ports → true
2. Return false if no match

`matches.matchIPsOnly(q)`: same but ignores proto and ports — just src in Srcs AND dst IP in any dst.Net.

`matches.matchProtoAndIPsOnlyIfAllPorts(q)`: same as match() but only considers dst entries where
Ports == AllPorts (0-65535).

### Rule parsing (tailcfg.go MatchesFromFilterRules + parseIPSet)

`parseIPSet(arg)` converts a string to a list of CIDR prefixes:
- `"*"` → [0.0.0.0/0, ::/0] (both families)
- `"cap:foo"` → capability "foo" (no prefixes) — store in SrcCaps
- CIDR `"192.168.0.0/16"` → [that prefix] (error if non-network bits set)
- IP range `"1.0.0.0-2.1.2.3"` → minimal set of CIDR prefixes covering the range
  (use the standard range-to-prefixes algorithm)
- Bare IP `"8.8.8.8"` → [8.8.8.8/32] (or /128 for IPv6)

`MatchesFromFilterRules(rules)`:
- For each FilterRule:
  - If SrcBits non-empty → error (deprecated, modern client should never get it)
  - IPProto: if empty → defaultProtos = [TCP, UDP, ICMPv4, ICMPv6]; else filter to 0-255 range
  - For each SrcIPs entry: parseIPSet → add to Srcs; if cap → add to SrcCaps
  - For each DstPorts entry: if Bits non-nil → error; parseIPSet on IP field → for each prefix,
    create NetPortRange{Net: prefix, Ports: {First, Last}}
  - For each CapGrant: for each dstNet, for each cap → CapMatch{Dst, Cap}
  (CapGrant/CapMatch: keep the types but capability matching can be a no-op for now)
- Returns (matches, error) where error is accumulated (non-fatal)

### MapResponse PacketFilter / PacketFilters delta handling

`PacketFilter` (singular, `Option<Vec<FilterRule>>`):
- `None` = unchanged (keep previous — field absent in JSON)
- `Some(vec![])` = block everything (empty non-nil list)
- `Some(vec![...])` = full replacement of the "base" key

`PacketFilters` (plural, `Option<BTreeMap<String, Option<Vec<FilterRule>>>>`):
- Key `"*"` with `None` value = clear ALL named filters (including "base")
- Other key with `None`/empty = delete that key
- Other key with `Some(vec)` = set/replace that key's rules

Combining: maintain a `BTreeMap<String, Vec<FilterRule>>` across map updates:
1. If PacketFilter is Some: set named["base"] = that value (even if empty)
2. If PacketFilters is Some:
   - If key "*" with None: clear the map
   - For each other key: None/empty → remove; Some(vec) → set
3. Final rules = concatenate all map values sorted by key name
4. Rebuild Filter from final rules + our local IPs
5. If neither PacketFilter nor PacketFilters is set: unchanged

IMPORTANT serde detail: use `Option<Vec<FilterRule>>` with `skip_serializing_if = "Option::is_none"`
(NOT skip_default) so that `Some(vec![])` (block all) is distinguishable from `None` (unchanged).
Same for PacketFilters: `Option<BTreeMap<...>>` with `skip_serializing_if = "Option::is_none"`.

## IMPLEMENTATION PLAN

### 1. crates/tailcfg — add filter wire types

Add to `crates/tailcfg/src/` a new module `filter.rs` (or add to existing modules):
- `PortRange { First: u16, Last: u16 }` — inclusive range
- `NetPortRange { IP: String, Bits: Option<i32>, Ports: PortRange }` — IP is string (wildcard/CIDR/range)
- `CapGrant { Dsts: Vec<String>, Caps: Vec<PeerCapability>, CapMap: PeerCapMap }`
  (Dsts as String for now — Go uses netip.Prefix but we parse in the filter crate)
  Actually: Go's CapGrant.Dsts is `[]netip.Prefix`. Use `Vec<String>` and parse in filter crate,
  OR use a simpler representation. Keep it simple: `Vec<String>`.
- `PeerCapability = String` (type alias, already exists as `NodeCapability`)
- `PeerCapMap = BTreeMap<String, Vec<RawMessage>>`
- `FilterRule { SrcIPs: Vec<String>, SrcBits: Vec<i32>, DstPorts: Vec<NetPortRange>, IPProto: Vec<i32>, CapGrant: Vec<CapGrant> }`
- `FILTER_ALLOW_ALL` constant: `vec![FilterRule{ SrcIPs: vec!["*".into()], DstPorts: vec![NetPortRange{ IP: "*".into(), Ports: PortRange{ First: 0, Last: 65535 } }], ..default }]`

Add to `MapResponse` in `map.rs`:
- `pub PacketFilter: Option<Vec<FilterRule>>` with `#[serde(default, skip_serializing_if = "Option::is_none")]`
- `pub PacketFilters: Option<BTreeMap<String, Option<Vec<FilterRule>>>>` with same serde attrs

REMEMBER: `crates/tailcfg` already has `#![allow(non_snake_case)]` — keep PascalCase field names
to match Go's JSON wire format.

Add a roundtrip test for MapResponse with PacketFilter/PacketFilters.

### 2. crates/filter — the packet filter crate

Create `crates/filter/` with:
```
Cargo.toml — depends on rustscale-tailcfg, ipnet (or hand-rolled)
src/
  lib.rs   — Filter, Response, check_in, check_out, update_outbound
  parse.rs — FilterRule → Match conversion, parse_ip_set
  match.rs — Match, NetPortRange, PortRange, match logic
  state.rs — FlowState (LRU cache, 512 max)
  packet.rs — minimal IP header parser (PacketInfo from raw bytes)
  tests.rs — ported test cases
```

**Do NOT add external crates** (no `ipnet`, no `lru`). Hand-roll:
- IP prefix as `(IpAddr, u8)` — addr + prefix length. Containment: bitwise compare first `prefix_len` bits.
- IP range → prefixes: standard algorithm (for a range [start, end], find the largest CIDR block
  that fits within the range starting at the current position, emit it, advance).
- LRU cache: `HashMap<FlowTuple, ()>` + `VecDeque<FlowTuple>` for eviction order. On access, remove
  from VecDeque and push back. On insert, if >512, pop front from VecDeque and remove from map.
  FlowTuple = (proto: u8, src: IpAddr, src_port: u16, dst: IpAddr, dst_port: u16).

**PacketInfo parser** (packet.rs): parse raw IP packet bytes → PacketInfo:
```
struct PacketInfo {
    version: u8,       // 4 or 6
    proto: u8,         // IP protocol number
    src: IpAddr,
    dst: IpAddr,
    src_port: u16,     // 0 if not TCP/UDP
    dst_port: u16,     // 0 if not TCP/UDP
    tcp_flags: u8,     // TCP flags byte (offset 13 in TCP header), 0 if not TCP
    is_tcp_syn: bool,  // SYN flag (0x02) set AND ACK (0x10) NOT set
    is_icmp_echo_reply: bool,
    is_icmp_error: bool,
}
```
IPv4 header: version/IHL at byte 0, proto at byte 9, src at 12-15, dst at 16-19.
IPv6 header: version in byte 0 top nibble, next-header at byte 6, src at 8-23, dst at 24-39.
TCP header (after IP header): src_port at 0-1, dst_port at 2-3, flags at byte 13.
UDP header: src_port at 0-1, dst_port at 2-3.
ICMP: type at byte 0 (echo-reply=0, echo=8; error types: 3=dest-unreachable, 4=source-quench,
11=time-exceeded, 12=param-problem). echo-reply=0 → is_icmp_echo_reply. types 3/4/11/12 → is_icmp_error.

**Filter struct:**
```
pub struct Filter {
    matches4: Vec<Match>,   // rules for IPv4
    matches6: Vec<Match>,   // rules for IPv6
    local4: Vec<IpPrefix>,  // our local IPv4 addresses
    local6: Vec<IpPrefix>,  // our local IPv6 addresses
    state: FlowState,       // UDP/SCTP flow tracking LRU
}
```

**Public API:**
- `Filter::new(rules: &[FilterRule], local_ips: &[IpAddr]) -> Result<Filter, FilterError>`
  Compiles rules into matches4/matches6 (partition by address family), stores local IPs.
- `Filter::allow_all() -> Filter` — accepts everything (for tests)
- `Filter::allow_none() -> Filter` — rejects everything
- `Filter::check_in(pkt: &[u8]) -> Response` — parse raw IP packet + run inbound filter
- `Filter::check_in_info(info: &PacketInfo) -> Response` — run inbound filter on pre-parsed info
- `Filter::update_outbound(pkt: &[u8])` — parse + record UDP flow state (reversed tuple)
- `Filter::update_outbound_info(info: &PacketInfo)` — record flow state from pre-parsed info
- `Filter::check(src: IpAddr, dst: IpAddr, proto: u8, dst_port: u16, is_syn: bool) -> Response`
  — low-level check (Go's Check/CheckTCP equivalent, for tests)

**Response:**
```
pub enum Response { Accept, Drop, DropSilently }
impl Response { pub fn is_drop(&self) -> bool { ... } }
```

### 3. Tests — port from filter_test.go

Port at least 15 cases from `TestFilter` (the accept/drop matrix at lines 104-197), including:
- The basic allow/drop matrix (8.1.1.1→1.2.3.4:22 accept, :21 drop, etc.)
- Wildcard rules (*→*:443, *→100.122.98.50:*)
- IPv6 rules (::1→2001::1:22)
- localNets prefilter (dst not in localNets → Drop even if rule matches)
- SCTP proto-specific rules
- Unknown proto with all-ports rule (testAllowedProto=116)
- Port from `TestUDPState` (lines 199-234): unsolicited UDP dropped, outbound records flow,
  return UDP accepted.
- Port from `TestMatchesFromFilterRules` (lines 847-936): rule parsing with implicit/explicit protos.

Use the same `newFilter` test setup (lines 73-102): same matches, same localNets. Create a
Rust `new_test_filter()` helper that builds the same rule set. Use the same IPs and ports.

The Go test uses `parsed(proto, src, dst, src_port, dst_port)` which creates a Parsed with SYN flag
set for TCP. Mirror this: TCP tests should use is_syn=true unless the test specifically tests non-SYN.

### 4. Integration in crates/tsnet

In `crates/tsnet/src/lib.rs`:

**Add Filter to RunningState:**
```rust
struct RunningState {
    // ... existing fields ...
    filter: Arc<Mutex<rustscale_filter::Filter>>,
}
```

**Build filter from netmap:**
- In `bootstrap()`: build initial filter from first MapResponse's PacketFilter/PacketFilters.
  If neither is present, use Filter::allow_all() (or allow_none if empty).
  Local IPs = tailscale_ips.
- Store the named filter map (`BTreeMap<String, Vec<FilterRule>>`) for delta handling.

**Update filter in map update task:**
- In `spawn_map_update_task`: process PacketFilter/PacketFilters deltas per the semantics above.
  Maintain the named filter map across updates. Rebuild Filter when rules change.
  Store behind `Arc<Mutex<Filter>>` so the pump tasks can access it.

**Enforce in netstack pump (run_netstack_pump):**
- Inbound: after WG decapsulation, before `netstack.push_rx(pt)`:
  `if filter.check_in(&pt).is_drop() { drop_count += 1; continue; }`
- Outbound: after `netstack.pop_tx()`, before encapsulation:
  `filter.update_outbound(&pkt);` (records UDP flow state for return traffic)

**Enforce in TUN pump (run_tun_pump):**
- Inbound: after WG decapsulation, before `tun.write_packet(&pt)`:
  `if filter.check_in(&pt).is_drop() { drop_count += 1; continue; }`
- Outbound: after TUN read, before encapsulation:
  `filter.update_outbound(&pkt);`

**Drop counter:**
- Add `packet_drops: Arc<std::sync::atomic::AtomicU64>` to RunningState.
- Increment on each drop.
- Add `pub packet_drops: u64` to `ServerStatus` in `status.rs`.
- Report in `Server::status()`.

### 5. Workspace Cargo.toml

Add `crates/filter` to workspace members (it's already `members = ["crates/*"]` so it's automatic).
Add `rustscale-filter = { path = "crates/filter" }` to tsnet's Cargo.toml dependencies.

## ACCEPTANCE CRITERIA

1. `tools/check.sh` passes clean (build + test + clippy, all workspace).
2. At least 15 test cases ported from filter_test.go, covering the accept/drop matrix, wildcards,
   port ranges, IPv6, localNets prefilter, SCTP, unknown proto, and UDP stateful return flow.
3. FilterRule/NetPortRange/PortRange types added to tailcfg with correct JSON wire format (PascalCase).
4. MapResponse has PacketFilter + PacketFilters fields with correct None-vs-empty semantics.
5. tsnet builds Filter from netmap, handles PacketFilter/PacketFilters deltas (including "base" key
   and "*" clear-all), and enforces in both netstack and TUN inbound paths.
6. Drop counter in ServerStatus.
7. No new external crate dependencies (hand-roll IP prefix, range-to-prefixes, LRU cache).

## CONSTRAINTS

- `#![forbid(unsafe_code)]` everywhere (workspace policy).
- `#![allow(non_snake_case)]` in tailcfg (already set) and any crate mirroring Go wire types.
- Keep the tsnet public API C-representable (no generics/lifetimes in public surface that can't
  map to C handles). The filter crate is internal — use Rust idioms freely.
- Do NOT run e2e tests yourself. The e2e ACL is accept *:* so traffic still flows.

## SUMMARY TO REPORT

When done, report:
1. Which Go semantics you replicated (especially: TCP non-SYN always accept, UDP flow state LRU
   with reversed tuple, localNets prefilter, pre() checks, PacketFilters delta with "base" key).
2. The test cases you ported and their results.
3. Any deviations from Go and why.
4. The files you created/modified.
