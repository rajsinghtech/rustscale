# flowtrack crate — pre-digested spec

## 1. Go sources

### 1.1 `net/flowtrack/flowtrack.go` — the target

**`Tuple` struct** (packed, no pointers, no zone):

```go
type Tuple struct {
    src     [16]byte
    dst     [16]byte
    srcPort uint16
    dstPort uint16
    proto   ipproto.Proto   // u8
}
```

Constructed via `MakeTuple(proto ipproto.Proto, src, dst netip.AddrPort) Tuple` which calls `.Addr().As16()` + `.Port()` on each AddrPort.

Accessor methods: `SrcAddr() netip.Addr`, `DstAddr() netip.Addr`, `SrcPort() uint16`, `DstPort() uint16`.

**String format**: `"(<proto> <srcAddr>:srcPort => <dstAddr>:dstPort)"` — e.g. `"(UDP 1.2.3.4:5678 => 5.6.7.8:443)"`.

**JSON marshaling**: the external shape is `{"proto":17,"src":"1.2.3.4:5678","dst":"5.6.7.8:443"}` using an adapter type `tupleOld`. The IPv6 zone in `netip.AddrPort` is dropped on unmarshal (As16 truncates it). A Rust serde impl must produce identical JSON.

**`Cache[Value any]`** — generic LRU keyed by Tuple:

```go
type Cache[Value any] struct {
    MaxEntries int
    ll         *list.List          // container/list
    m          map[Tuple]*list.Element // of *entry
}
```

Methods:
- `Add(key Tuple, value Value)` — insert-or-update, move to front, evict LRU if `Len() > MaxEntries > 0`
- `Get(key Tuple) (value *Value, ok bool)` — move to front on hit
- `Remove(key Tuple)` — delete if present
- `RemoveOldest()` — pop back of list
- `Len() int`

Zero value is ready to use (nil maps/lists are lazily allocated in `Add`).

**NOT safe for concurrent access.** Caller must lock.

### 1.2 `util/lru/lru.go` — alternative (NOT used by filter, but note)

The generic `lru.Cache[K, V]` uses a ring buffer (`head *entry` with prev/next pointers pointing back to form a ring). Method names differ: `Set`/`Get`/`GetOk`/`PeekOk`/`Contains`/`Delete`/`DeleteOldest`/`Clear`/`ForEach`/`DumpHTML`.

`flowtrack.Cache` is a simpler wrapper on `container/list` + `map[Tuple]*list.Element`. The spec target is `flowtrack.Cache`, not `util/lru`.

### 1.3 `wgengine/filter/filter.go` — consumer #1 (packet filter)

```go
type filterState struct {
    mu  sync.Mutex
    lru *flowtrack.Cache[struct{}]
}
const lruMax = 512
```

Initialized in `New()`:
```go
state = &filterState{
    lru: &flowtrack.Cache[struct{}]{MaxEntries: lruMax},
}
```

**State sharing**: when `shareStateWith` is non-nil (hot reload of filter rules), the old filter's `filterState` pointer is reused — the cache survives across rule updates:
```go
if shareStateWith != nil {
    state = shareStateWith.state
} else {
    state = &filterState{lru: ...}
}
```

**Inbound** (`runIn4`/`runIn6` — UDP/SCTP only):
```go
case ipproto.UDP, ipproto.SCTP:
    t := flowtrack.MakeTuple(q.IPProto, q.Src, q.Dst)
    f.state.mu.Lock()
    _, ok := f.state.lru.Get(t)
    f.state.mu.Unlock()
    if ok {
        return Accept, "cached"
    }
    if f.matches4.match(q, f.srcIPHasCap) {
        return Accept, "ok"
    }
```

**Outbound** (`runOut` — UDP/SCTP only, always accept, record flow):
```go
case ipproto.UDP, ipproto.SCTP:
    tuple := flowtrack.MakeTuple(q.IPProto, q.Dst, q.Src) // src/dst reversed
    f.state.mu.Lock()
    f.state.lru.Add(tuple, struct{}{})
    f.state.mu.Unlock()
```

Key detail: outbound reverses src/dst so the inbound check matches the reversed tuple (return traffic). Value is always `struct{}{}` — no side-channel data.

**No time-based expiry.** Purely LRU-by-size at 512 entries. No timestamps stored.

### 1.4 `wgengine/pendopen.go` — consumer #2 (TCP open timeout)

Uses raw `flowtrack.Tuple` as a map key, NOT the Cache. Time-based via `time.AfterFunc(5s, ...)`. NOT in scope for this crate — it's a separate concern. Only note that Tuple must be `Hash + Eq` for use as a HashMap key.

### 1.5 `wgengine/netlog/` — does NOT use flowtrack

The netlog package uses its own `netlogtype.Connection` (3-field: `Proto, Src, Dst` as `netip.AddrPort`). No `flowtrack.Tuple` dependency. The netlog crate already has `Connection` and using flowtrack::Tuple there would be a future refactor, not required now.

## 2. Current rustscale state: `crates/filter/src/state.rs`

```rust
pub struct FlowTuple {
    pub proto: u8,
    pub src: IpAddr,
    pub src_port: u16,
    pub dst: IpAddr,
    pub dst_port: u16,
}
```

- Derives `Clone, Debug, PartialEq, Eq, Hash`
- Uses `std::net::IpAddr` (16 bytes for IPv4, 32 bytes for IPv6 due to enum tag) — less compact than Go's `[16]byte`
- `reversed_tuple()` free function creates a swapped copy

```rust
pub struct FlowState {
    entries: HashMap<FlowTuple, ()>,
    order: VecDeque<FlowTuple>,
    max: usize,
}
```

- `new()` → max=512
- `get(&mut self, tuple: &FlowTuple) -> bool` — linear scan via `self.order.retain()` then `push_back` (O(n)!)
- `add(&mut self, tuple: FlowTuple)` — O(n) on update due to `retain`
- `len()` / `is_empty()`

**Problems**:
1. `FlowState.get()` is O(n) on hit (retain to remove, push_back to re-add) — should be O(1)
2. `FlowTuple` uses `IpAddr` which is 16–32 bytes + tag vs Go's fixed 16-byte arrays
3. No generic value: always `()`, hard-coded
4. No `remove()` or `RemoveOldest()` public API
5. Coupled to filter crate (not a standalone reusable crate)

**Call sites in filter/src/lib.rs**:

- `run_in4` (line 370): constructs `FlowTuple { proto, src, src_port, dst, dst_port }` from packet info, calls `self.state.get(&t)` → Accept if cached
- `run_in6` (line 423): identical pattern
- `update_outbound_info` (line 306): calls `reversed_tuple(q.proto, q.src, q.src_port, q.dst, q.dst_port)` then `self.state.add(tuple)`
- `Filter.state: FlowState` field (line 67), initialized in 3 constructors
- No `shareStateWith` equivalent (filter always creates fresh state)

## 3. Rustscale netlog types (`crates/netlogtype/src/lib.rs`)

```rust
pub struct AddrPort(pub IpAddr, pub u16);   // Hash, Eq, Clone, Copy
pub struct Connection {
    pub proto: u8,
    pub src: AddrPort,
    pub dst: AddrPort,
}
```

Used as `HashMap<Connection, CountsAndType>` in `record.rs`. The `Connection` type is isomorphic to `flowtrack.Tuple` but with `AddrPort` (which wraps `IpAddr`). If flowtrack::Tuple becomes the canonical packed representation, `Connection` could eventually be `flowtrack::Tuple` directly, but that's a future refactor.

## 4. Suggested Rust design

### New crate: `crates/flowtrack`

```rust
// Tuple — packed, no pointers, Hash+Eq for use as map key
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Tuple {
    src: [u16; 8],      // 16 bytes (stores IPv6 as 8×u16, or IPv4 in last 2)
    dst: [u16; 8],
    src_port: u16,
    dst_port: u16,
    proto: u8,
}
```

Alternative: use `[u8; 16]` like Go. Either is fine. The key is it's packed, pointer-free, Copy. Provide:
- `Tuple::new(proto: u8, src: IpAddr, src_port: u16, dst: IpAddr, dst_port: u16) -> Self`
- `Tuple::reversed(&self) -> Self` (swaps src↔dst)
- `fn src_addr(&self) -> IpAddr`, `fn dst_addr(&self) -> IpAddr`
- `fn src_port(&self) -> u16`, `fn dst_port(&self) -> u16`
- `fn proto(&self) -> u8`
- `Display` → Go's `"(<proto> <src>:port => <dst>:port)"`
- `Serialize`/`Deserialize` → Go's `{"proto":..., "src":"...", "dst":"..."}`

```rust
// Cache — generic LRU keyed by Tuple
pub struct Cache<V> {
    max_entries: usize,
    // doubly-linked list + lookup map (or use generational arena)
    entries: HashMap<Tuple, NonNull<Node<V>>>,
    head: *mut Node<V>,
    tail: *mut Node<V>,
    len: usize,
}
```

Or use a safe arena approach. Must be `!Send + !Sync` (or document not thread-safe).

Methods:
- `Cache::new(max_entries: usize) -> Self`
- `get(&mut self, key: &Tuple) -> Option<&V>` — move-to-front on hit
- `get_mut(&mut self, key: &Tuple) -> Option<&mut V>` — move-to-front on hit
- `add(&mut self, key: Tuple, value: V)` — insert-or-update, evict oldest if over capacity
- `remove(&mut self, key: &Tuple)`
- `remove_oldest(&mut self)`
- `len(&self) -> usize`
- `contains(&mut self, key: &Tuple) -> bool`

### Migration: `crates/filter/src/state.rs` replacement

After the crate exists:
- Delete `FlowTuple` and `FlowState` from `state.rs`
- `pub use rustscale_flowtrack::{Tuple as FlowTuple, Cache as FlowState}` — or write a thin wrapper alias
- Change `state: FlowState` → `state: flowtrack::Cache<()>` in `Filter`
- Constructor: `state: flowtrack::Cache::new(512)`
- `self.state.get(&t)` → O(1) move-to-front
- `self.state.add(tuple, ())` → O(1) insert
- `reversed_tuple()` function becomes `Tuple::reversed()` method

### State sharing

Add an optional `share_state_with: Option<&Filter>` parameter to `Filter::new()` to match Go's `shareStateWith` parameter (or handle it at the tsnet/backend level):

```rust
pub fn new(
    rules: &[FilterRule],
    local_ips: &[IpAddr],
    cap_holders: &BTreeMap<IpAddr, BTreeSet<String>>,
    share_state_with: Option<&Filter>,  // <-- new
) -> Result<Self, FilterError>
```

When `Some(filter)`, the new filter clones `filter.state` (or takes an `Arc<Mutex<Cache<()>>>`). Note: Go shares the pointer — the cache is NOT cloned. If we want exact semantics, use `Arc<Mutex<Cache<()>>>` inside Filter so clone is cheap. But FlowState is currently inline (`state: FlowState` not `Box<FlowState>`), so this requires changing the field type.

Minimum viable for now: just use `Arc<Mutex<Cache<()>>>` as the field, init fresh on construction but let the caller `Arc::clone()` if they want sharing.

### Netlog — optional future adoption

`netlogtype::Connection` could become `flowtrack::Tuple` or wrap it:

```rust
// Option A: type alias
pub type Connection = flowtrack::Tuple;

// Option B: newtype
pub struct Connection(flowtrack::Tuple);
```

Not required for this phase. The AddrPort -> [u16;8] mapping is straightforward: `IpAddr::V4(a)` → `[0, 0, 0, 0, 0, 0, 0, a.to_bits() as u16? no...]`. Actually need `[u8; 16]` for byte-level compatibility. The packed representation should use `[u8; 16]` like Go to avoid alignment gaps.

## 5. Acceptance criteria for coding agent

1. New crate `crates/flowtrack` with `Tuple` and `Cache<V>` as described
2. `cargo build` + `cargo test` pass for the new crate
3. filter crate migrates to use `flowtrack::Cache<()>` — remove `FlowTuple`/`FlowState` from `state.rs`, re-export from `flowtrack`
4. `cargo test --workspace` passes
5. `cargo clippy --workspace --all-targets` passes
6. No regressions in filter behavior:
   - UDP/SCTP return traffic still accepted via cache
   - LRU eviction at 512 entries
   - Outbound `update_outbound_info` still records reversed tuples

## 6. References

| Go path | rustscale path |
|---|---|
| `net/flowtrack/flowtrack.go` | `crates/flowtrack/src/lib.rs` |
| `wgengine/filter/filter.go` (flowtrack usage) | `crates/filter/src/lib.rs` lines 369–377, 422–431, 304–312 |
| `wgengine/filter/filter.go` (state sharing) | _not yet ported_ — `Filter::new` needs `share_state_with` param |
| `util/lru/lru.go` | _not porting_ — flowtrack has its own simpler LRU |
| `wgengine/pendopen.go` (Tuple as map key) | _not in scope_ |
| `types/netlogtype/netlogtype.go` → `Connection` | `crates/netlogtype/src/lib.rs` (stays as-is for now) |
