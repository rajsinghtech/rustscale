# Phase: Contiguous-peer TUN outbound batching

## Evidence

The same-zone direct Linux benchmark after VNET/GSO TUN reads reached 385.30,
507.76, and 318.95 Mbps at 1, 10, and 100 streams. Tailscale reached 1,899.41,
2,075.20, and 1,400.72 Mbps on the same VM pair. The pre-VNET profile placed
48.6% inclusive CPU in the TUN pump, 29.7% in encapsulate/send, 21.9% in
`Magicsock::send`, and 20.4% in Tokio UDP `send_to`.

VNET now supplies up to 128 ordered IP packets in one `TunPacketBatch`, but
Rustscale still processes each packet through separate route-table, tunnel-map,
tunnel-mutex, endpoint-accounting, and path-selection operations. It also
allocates a ciphertext `Vec` for every packet. The heartbeat phase removed
per-packet task churn; this phase must consume the batch as a batch before
changing Linux UDP syscall behavior.

## Scope

Batch only the outbound kernel-TUN path. Resolve one ordered TUN read into
contiguous same-peer runs, reuse ciphertext storage, and send each run through
one Magicsock activity/path snapshot. Keep the userspace netstack pump,
inbound path, WireGuard protocol, filtering policy, UDP scalar syscalls,
DERP/relay wire formats, and public single-datagram behavior unchanged.

Do not add `sendmmsg`, UDP GSO/GRO, parallel encryption, peer grouping that
reorders packets, or a netstack last-peer cache in this phase.

## Reusable WireGuard datagram batch

Add a small public batch type in `crates/wg` that owns `Vec<Vec<u8>>` plus a
logical length:

1. `clear` resets the logical length without dropping inner buffers or their
   capacities.
2. A push/copy operation reuses the next inner buffer, clears it, and copies
   the current BoringTun `WriteToNetwork` slice into it. Grow only on demand.
3. `packets` exposes exactly the initialized prefix as read-only packet
   buffers. No stale packet may be visible after clear, error, or `Done`.
4. Add `WgTunn::encapsulate_into(plaintext, batch)`. It appends zero or one
   ciphertext datagram and preserves the existing `WgError` mapping.
5. Keep `WgTunn::encapsulate` source- and behavior-compatible. It may retain
   its existing implementation or delegate without making the single-packet
   API slower.

The BoringTun output aliases `WgTunn::encap_buf` and is overwritten by the
next encapsulation, so every produced datagram must be copied before the next
call. Retained batch buffers remove steady-state allocations without holding
the tunnel mutex across network `.await` points.

## TUN batch scratch and routing

Add a private reusable scratch object for `run_tun_pump`, created beside its
`TunPacketBatch`. It retains:

- one route result per input packet;
- a vector of contiguous outbound runs containing peer key, cloned tunnel
  `Arc`, and input index range;
- the reusable WireGuard datagram batch.

For every successful TUN read:

1. Clear scratch logical lengths.
2. Acquire the packet-filter mutex once and the route-table read guard once.
   Visit every input packet in order. Call `Filter::update_outbound` exactly
   once for every packet, including malformed/unroutable packets, then parse
   its destination and store `RouteTable::lookup` or `None`. Release both
   guards before any `.await` other than the already-completed route read.
3. Acquire the tunnels-map read guard once. Linear-scan route results and form
   maximal contiguous runs of equal route result. `None` is an explicit
   skipped run and separates routed runs. For routed runs, clone the current
   tunnel `Arc`; a missing tunnel is also a skipped run. Release the map guard
   before locking a peer tunnel.
4. Process runs strictly by increasing input range. Never hash-group peers:
   `A,A,B,A` must remain three sends (`A,A`, then `B`, then `A`).
5. For a routed run, clear the ciphertext batch, acquire its peer tunnel mutex
   once, call `encapsulate_into` for each input packet in order, ignore an
   individual encapsulation error as the current pump does, then release the
   mutex before Magicsock I/O.
6. Send the initialized ciphertext batch once through
   `Magicsock::send_batch`. Continue to later runs if sending fails, matching
   the pump's existing best-effort behavior.

Route and tunnel maps are snapshots for one TUN read. A concurrent map update
waits only for the short synchronous snapshot construction. Cloned tunnel
`Arc`s remain valid after the map guard is released; the next TUN read sees the
new map. No Tokio guard or tunnel mutex may be held across UDP/DERP `.await`.

## Magicsock batch API

Add a public generic batch method accepting a slice of datagram-like values,
for example `send_batch<T: AsRef<[u8]>>`. It is the semantic batch boundary for
later platform-specific syscall batching.

1. An empty batch is a no-op and returns `Ok(())` without endpoint activity,
   discovery, or path lookup.
2. A nonempty batch performs endpoint TX accounting, conditional heartbeat
   arming, best-path selection, and DERP-region selection once, using one
   endpoint write-lock acquisition and one timestamp. Missing peers still
   return `PeerNotFound`.
3. Start rate-limited direct discovery at most once for a DERP/None batch.
4. Snapshot the selected path for the complete batch. A better path learned
   concurrently is used on the next run; packets in this microburst stay in
   order on one path.
5. Direct UDP remains one Tokio `send_to` per datagram. Record socket stats for
   each successful datagram. Preserve `treat_as_lost_udp` behavior.
6. Relay mode Geneve-frames and sends each datagram in order. DERP known-region
   and fanout modes likewise send every datagram in order.
7. Attempt the whole batch even if one datagram gets a non-lost I/O/NoPath
   error. Return the first such error after attempting the suffix. This
   preserves the TUN pump's current behavior, where individual send errors are
   ignored and later packets are still attempted.
8. Refactor the existing `send` to delegate a one-element slice to the batch
   implementation without allocation. Its result and path behavior must stay
   compatible.

Do not expose a public `PathSnapshot` or a path-specific send method. Keeping
snapshot ownership inside Magicsock prevents callers from retaining stale
paths beyond one batch.

## Tests

### `crates/wg`

- `encapsulate_into` output decrypts identically to existing `encapsulate`.
- Clear/reuse retains inner allocation/capacity and exposes only the logical
  prefix.
- `Done` and error do not expose a stale slot.
- Multiple ordered plaintext packets yield ordered ciphertext packets that
  remain valid after the tunnel's scratch buffer is reused.

### `crates/magicsock`

- Empty batch is a no-op, including for an unknown peer.
- A direct UDP batch arrives in order and accounts every successful datagram.
- Multiple datagrams cause one activity/path snapshot and at most one
  heartbeat generation.
- DERP and relay batch paths preserve order and framing using existing fake
  transports.
- A failed element does not prevent later elements from being attempted, and
  the first non-lost error is returned.
- Existing single `send`, discovery, direct, DERP, relay, heartbeat, and error
  tests continue to pass.

### `crates/tsnet`

- Pure run construction covers empty, one packet, `A,A,A`, `A,B,A`,
  `A,None,A`, malformed IP, and missing-tunnel cases with exact ranges/order.
- Filter observation proves every input packet is updated once in input order,
  including skipped runs.
- An end-to-end mock TUN batch with multiple same-peer packets decrypts and
  arrives in order before the next TUN read.
- Interleaved peers preserve `A,B,A` run order.
- Concurrent route/tunnel-map replacement cannot deadlock or invalidate the
  cloned run snapshot.
- Existing one-read-batch, single-packet, filter, route, and WireGuard pump
  tests remain green.

Use test-only counters or helpers to prove one route guard, one tunnels-map
guard, one tunnel lock, and one Magicsock snapshot per applicable batch/run;
do not add production indirection solely to count locks.

## Validation

- `cargo fmt --check`
- `cargo test -p rustscale-wg`
- `cargo test -p rustscale-magicsock`
- `cargo test -p rustscale-tsnet tun`
- `cargo clippy -p rustscale-wg -p rustscale-magicsock -p rustscale-tsnet --all-targets -- -D warnings`
- `cargo check -p rustscale-tsnet --target x86_64-unknown-linux-musl`
- `RUST_TEST_THREADS=1 tools/check.sh`
- Repeat the same-zone direct `rs-tun` benchmark and collect a Linux profile.
  Compare throughput, CPU, latency, RSS, route/tunnel locking, Magicsock, and
  UDP-send samples against `gcp-20260713-115706` before implementing
  `sendmmsg`.
