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
  packet allowance (256). A batch must acquire credits equal to its packet
  count before publication and retain the permit until the batch is consumed
  or dropped.
- DERP/scalar packets must use the same credit accounting and remain able to
  make progress under sustained direct UDP traffic.
- The TUN path must move a received batch directly into its inbound scratch
  ordering. The netstack path must process the same batch abstraction without
  changing its scalar semantics.
- Preserve direct/DERP ordering as observed at the existing publication point,
  missing-peer behavior, control/disco fallback, filtering, capture timing,
  reply ordering, and cancellation/closed-channel cleanup.
- The first implementation may retain each `WgDatagram`'s owned `Vec<u8>`.
  Pooling or moving UDP receive slots across an await boundary is explicitly a
  later profile-gated phase.

## Verification

- Differential scalar-versus-batch ordering for TUN and netstack consumers.
- Exact 128-packet burst ordering.
- Mixed DERP/direct traffic under the 256-packet credit limit.
- Credits return when a batch is consumed, dropped, publication is cancelled,
  or the channel is closed.
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
