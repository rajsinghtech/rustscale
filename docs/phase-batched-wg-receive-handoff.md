# Batched WireGuard Receive Handoff

## Goal

Raise Linux TUN throughput without changing the packet-level queue bound or
control-path semantics. The steady direct-UDP path should carry one kernel
receive batch through magicsock and the TUN pump with one channel-capacity
reservation, one peer-map snapshot, and one WireGuard tunnel lock per
contiguous peer run.

The pre-phase same-zone direct baseline is
`bench-results/gcp-20260713-163805` at commit `330504e`:

- P1: 805.933 Mbps
- P10: 683.802 Mbps
- P100: 839.590 Mbps
- latency p50: 1,390 us
- peak RSS: 15,232 KiB
- binary: 15,409,880 bytes

## Current bottlenecks

1. `crates/magicsock/src/lib.rs::spawn_recv_tasks` receives as many as 128
   logical datagrams, but awaits `handle_udp_packet` for each one.
2. Direct WireGuard data performs an address-map lookup, endpoint write-lock,
   allocation, and bounded-channel send for every packet.
3. `crates/tsnet/src/tun_pump.rs::collect_tun_inbound` reacquires the tunnel
   map and the same peer tunnel mutex for every item in an already-drained
   burst.
4. Successful benchmark JSON discards the daemon logs containing
   `udp_gro_stats`, so a fast result does not prove GRO utilization or absence
   of fallback/loss events.

Tailscale's `wgengine/magicsock/magicsock.go::mkReceiveFunc` returns an entire
receive batch to WireGuard. Its Linux bind advertises `conn.IdealBatchSize`.
Rustscale should preserve its existing architecture while eliminating the
avoidable packet-granularity coordination.

## Required implementation

### Magicsock fast path

- Keep `mpsc::channel(256)` and its `WgDatagram` element type. Capacity is a
  packet bound, not a batch bound. Do not replace it with a channel whose
  capacity counts batches.
- Add a Linux receive-batch handler for the common case where every logical
  datagram is ordinary WireGuard UDP, not disco and not Geneve.
- Scan the published `ReceiveBatch` first. If any packet is disco or Geneve,
  use the existing sequential handler for the entire batch so control effects,
  relay behavior, and ordering remain unchanged.
- On the all-WireGuard path, hold one `addr_to_peer` read guard and one
  `endpoints` write guard while identifying packets and recording UDP receive
  activity. Copy accepted ciphertext into owned `WgDatagram` values in input
  order, then drop both guards before touching the async channel.
- Preserve unknown-source drops and sockstats accounting exactly.
- Try to reserve capacity for the full accepted packet prefix with Tokio
  `try_reserve_many`. If it succeeds, publish through those permits in order.
  If it reports insufficient capacity, fall back to the current ordered
  `send().await` behavior. This preserves the 256-packet bound, streaming
  backpressure, and sender fairness under pressure. A closed receiver stops
  publication without panicking.
- Reuse the outer pending-vector allocation across receive iterations. Nested
  ciphertext vectors must be dropped after ownership moves to the channel;
  do not retain 128 large packet buffers while idle.
- Keep scalar old-kernel fallback and non-Linux receive behavior unchanged.

### TUN pump receive runs

- Keep the existing triggering receive plus immediate drain capped at
  `TunPacketBatch::MAX_PACKETS`.
- Build maximal contiguous runs of equal peer keys from the drained datagrams.
  Missing tunnels are explicit drop boundaries and noncontiguous runs for the
  same peer must not be merged across another peer or missing entry.
- Acquire the tunnel-map read guard once to resolve run tunnel handles, then
  release it before acquiring any tunnel mutex.
- Acquire each run's tunnel mutex once and decapsulate its datagrams in exact
  channel order. Release the mutex before filtering, capture, reply sends, or
  TUN writes. Never hold an async lock across network or device I/O.
- Filter and capture accepted plaintext in original packet order. Preserve
  reply-before-TUN-write behavior and the single `write_batch` call.
- Keep plaintext and reply ownership bounded to the current 128-packet burst.
  Clear nested buffers after flush as the current code does.
- Do not alter netstack behavior in this phase unless sharing a helper is
  required and equivalence is covered by tests.

### Benchmark evidence

- Extend successful `rs-tun` JSON with bounded server and client runtime-stat
  text captured before daemon cleanup. Retain only lines matching
  `udp_gro_stats`, the GRO capability message, RXQ overflow, and any new
  handoff statistic; do not place arbitrary daemon logs or credentials in the
  result.
- Keep existing result fields and failure `log_tail` behavior compatible.
- Add/update shell self-tests for successful capture, empty matches, quoting,
  and cleanup ordering.

## Tests

- Magicsock fast path preserves order across multiple known sources and drops
  unknown sources without shifting accepted packets.
- Full-capacity fast reservation publishes exactly once and in order.
- Insufficient capacity uses ordered fallback without exceeding 256 queued
  packets; a concurrently draining receiver can make progress.
- Closed receiver is handled without panic or retained permits.
- A batch containing a disco or Geneve packet selects the sequential path.
- TUN inbound run construction covers one peer, alternating peers, missing
  tunnels, and noncontiguous repetition.
- One run lock processes ordered ciphertext correctly and produces the same
  plaintext/replies as scalar processing.
- Existing immediate-burst cap, filtering, capture-before-rewrite, reply
  ordering, and one-write tests remain green.

## Gates

1. `cargo fmt --all --check`
2. Focused magicsock and tsnet tests, including a Linux target compile.
3. `cargo clippy --workspace --all-targets -- -D warnings`
4. `RUST_TEST_THREADS=1 tools/check.sh`
5. Same-zone direct `rs-tun --profile --repeat 3` benchmark.
6. Runtime stats must show GRO enabled, coalesced messages increasing, zero
   parse failures, zero permanent fallbacks, and zero RXQ overflow delta.
7. Merge only with no repeatable throughput regression and no material RSS or
   latency regression. Push `master` after the merge.

