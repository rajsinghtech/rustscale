# Magicsock receive-batch handoff phase

## Profile evidence

The reusable plaintext run `gcp-20260713-194820` reduced allocator and
decapsulation CPU but did not improve throughput relative to
`gcp-20260713-191038`:

- P1: 1900.061 to 1873.665 Mbps (-1.39%, overlapping samples).
- P10: 1948.682 to 1946.834 Mbps (-0.10%).
- P100: 1544.772 to 1440.511 Mbps (-6.75%).
- `malloc`: about 200.9 to 110.6 ms sampled CPU (-45%).
- Rust WG decapsulation wrapper: about 120.5 to 44.9 ms (-63%).
- BoringTun decapsulation: about 85.6 to 55.3 ms (-35%).
- Kernel copy/page work increased while the old per-result enqueue symbol
  disappeared.

The remaining handoff expands a Linux `recvmmsg`/GRO burst into individual
Tokio channel entries and then immediately drains those entries back into a
TUN batch. Relevant paths are `crates/magicsock/src/udp_batch.rs`,
`crates/magicsock/src/lib.rs`, and `crates/tsnet/src/tun_pump.rs`.

## Goal

Preserve receive bursts as one channel item from magicsock to tsnet while
keeping backpressure bounded by packets, not batches. Do not change packet
ordering, path/control handling, DERP progress, or UDP parsing behavior.

## Required design

- Introduce an owned `WgReceiveBatch` carrying ordered `WgDatagram` values with
  a logical maximum of 128 packets.
- Publish one channel item per receive burst rather than one per datagram.
- Bound queued work with a packet-credit semaphore sized to the current total
  packet allowance (256). A batch acquires credits equal to its packet count
  before publication and owns that permit while queued; consuming
  `WgReceiveBatch` releases it immediately, while dropping a queued batch also
  releases it.
- Linux direct receive owns 512 fixed buffers: 128 remain installed as
  `recvmmsg` scratch and 384 are available as zero-copy replacements. After a
  known direct batch acquires its channel credits, each available replacement
  is swapped into the scratch slot and the old fixed buffer is detached. If
  retained ciphertexts exhaust the replacements, only that logical datagram
  falls back to an owned copy; the scratch slot and its `iovec` stay installed.
- DERP/scalar packets must use the same credit accounting and remain able to
  make progress under sustained direct UDP traffic.
- The TUN path must move a received batch directly into its inbound scratch
  ordering. The netstack path must process the same batch abstraction without
  changing its scalar semantics.
- Preserve direct/DERP ordering as observed at the existing publication point,
  missing-peer behavior, control/disco fallback, filtering, capture timing,
  reply ordering, and cancellation/closed-channel cleanup.
- Vector-backed scalar and DERP frames retain their existing owned storage and
  range semantics. Only Linux direct WireGuard ciphertexts use the fixed pool.

## Verification

- Differential scalar-versus-batch ordering for TUN and netstack consumers.
- Exact 128-packet burst ordering.
- Mixed DERP/direct traffic under the 256-packet credit limit.
- Channel credits return when a batch is consumed, dropped, publication is
  cancelled, or the channel is closed. Detached fixed buffers return to the
  recycler when their individual ciphertexts drop.
- Retaining consumed direct ciphertexts can exhaust all 384 replacements;
  subsequent datagrams use bounded per-packet copy fallback without blocking,
  panicking, losing buffers, or changing installed scratch `iovec` pointers.
- The 512-buffer total, recycled-buffer reuse, and refreshed `iovec`
  replacement invariants hold.
- A full batch cannot turn the queue into 256 batches/32K packets.
- Scalar control/disco fallback and missing-peer behavior remain unchanged.
- Focused magicsock/tsnet tests, clippy, and `tools/check.sh` pass.
- Native Linux direct benchmark uses the same topology/path/repeat/profile
  command as the two evidence runs. Acceptance requires no meaningful P1/P10
  regression, recovery of P100, no latency/RSS regression beyond run noise,
  and reduced channel enqueue/pop pressure in the profile.

## Non-goals

- Do not replace BoringTun or Ring crypto.
- Do not redesign UDP GRO/GSO parsing.
- Do not hold a borrowed socket receive buffer across an await or next receive.
- Do not increase the effective packet queue capacity.
