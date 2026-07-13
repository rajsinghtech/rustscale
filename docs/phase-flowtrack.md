# Phase: flowtrack crate (`net/flowtrack` port)

Create `crates/flowtrack` mirroring Go's `net/flowtrack`, and migrate the
packet filter's inline flow LRU (`crates/filter/src/state.rs`) onto it.

Go references (read-only, verified 2026-07-13):
- `/Users/rajsingh/Documents/GitHub/tailscale/net/flowtrack/flowtrack.go` (165 loc — whole package)
- `/Users/rajsingh/Documents/GitHub/tailscale/net/flowtrack/flowtrack_test.go`
- `/Users/rajsingh/Documents/GitHub/tailscale/wgengine/filter/filter.go` (search `lruMax` and `flowtrack.` for filter usage)

## `crates/flowtrack`

### Tuple

Packed 5-tuple exactly as Go (post-2024 layout): `src: [u8; 16]`,
`dst: [u8; 16]` (IPv4 stored as v4-mapped v6, `As16`), `src_port: u16`,
`dst_port: u16`, `proto: u8`. Derive `Clone, Copy, PartialEq, Eq, Hash, Debug`.

- `Tuple::new(proto, src: SocketAddr, dst: SocketAddr)` = Go `MakeTuple`
  (map v4 into 16-byte form).
- Accessors `src_addr()`/`dst_addr()` return `IpAddr` **unmapped** (Go calls
  `.Unmap()` — a v4-mapped v6 comes back out as v4).
- `Display`: `(<proto> <src> => <dst>)` matching Go's `String()` (proto as its
  Go ipproto string where we have one — reuse whatever proto-display the
  filter/packet crates already have; a numeric fallback is fine, document it).
- serde JSON via the **old adapter format** (Go keeps wire compat):
  `{"proto": <u8>, "src": "<ip>:<port>", "dst": "<ip>:<port>"}` — src/dst as
  Go `netip.AddrPort` strings (v6 as `[::1]:80`). Round-trip test required.

### Cache<V>

Generic LRU keyed by `Tuple`, mirroring Go semantics:
- `max_entries: usize` (0 = unlimited), zero-value/`Default` valid.
- `add(key, value)` — insert or update + move to front; evict LRU when over.
- `get(&key) -> Option<&V>` / `get_mut` — hit moves to front.
- `remove(&key)`, `len()`, plus `oldest()` if trivial (check Go's API surface
  in flowtrack.go/flowtrack_test.go and match it; don't invent extras).
- O(1) operations: HashMap + doubly-linked order list. No new external
  dependencies — implement with an index/slab-based linked list (the
  workspace avoids heavyweight deps; match existing crate style,
  `#![forbid(unsafe_code)]` if achievable).
- Not thread-safe (like Go); callers lock.

Port the behavioral tests from flowtrack_test.go (add/get/evict order,
update-moves-to-front) plus the JSON round-trip.

## Filter migration (`crates/filter`)

`crates/filter/src/state.rs` currently hand-rolls `FlowTuple` +
`FlowState` (HashMap + VecDeque, O(n) touch via `retain`). Replace the
internals with `flowtrack::{Tuple, Cache<()>}`:
- Keep `FlowState`'s public API (`get`, `add`, `len`, `is_empty`,
  `reversed_tuple`) so `crates/filter` callers don't churn — `FlowTuple` can
  become a thin alias/wrapper or be replaced outright if call sites are few
  (grep them; prefer the smaller diff).
- Keep max 512 (Go `lruMax`); confirm against Go filter.go and cite the
  constant in a comment.
- Existing state.rs tests must keep passing (adapt types minimally).

Do NOT touch `crates/netlog`/`crates/netlogtype` in this phase (Tuple adoption
there is a possible later cleanup — leave a one-line note in the netlog row of
docs/parity.md only if you touch nothing else there).

## Docs

Update `docs/parity.md`: `Flow tracking (net/flowtrack)` row → ✅ with a
summary; adjust the `LRU cache (util/lru)` row to mention the standalone
implementation now living in crates/flowtrack.

## Acceptance criteria (run yourself)

- `cargo build --workspace && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all`
- flowtrack unit tests: LRU behavior parity, JSON adapter round-trip
  (exact field names `proto`/`src`/`dst`), v4-mapped storage with unmapped
  accessors, Display format.
- Do NOT modify `crates/magicsock`. Do not commit; do not spawn agents.
