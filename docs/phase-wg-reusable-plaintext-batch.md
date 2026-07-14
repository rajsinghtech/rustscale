# Reusable WireGuard Plaintext Batch

## Evidence

The `gcp-20260713-191038` receiver profile attributes 1.90% exclusive CPU to
`malloc`, 1.14% to `WgTunn::decapsulate`, and 0.81% to inbound enqueueing.
`WgTunn::decapsulate` currently copies every BoringTun plaintext result into a
fresh `Vec`, and `tun_pump` drops all inner allocations after every TUN write.

BoringTun's output slice aliases `WgTunn::decap_buf` and cannot survive another
decapsulation call. This phase must still copy those bytes, but it can copy into
retained caller-owned slots. Full in-place decryption would require changing or
forking BoringTun and is out of scope.

## Required change

- Keep the existing public `DecapResult` and scalar `WgTunn::decapsulate`
  behavior unchanged.
- Add a reusable plaintext batch in `rustscale-wg`. It owns `Vec<Vec<u8>>`
  slots plus a logical initialized length; clearing the batch retains each
  slot allocation.
- Add `WgTunn::decapsulate_into` that implements the same BoringTun protocol
  loop as `decapsulate`, copies plaintext into the next retained slot, and
  returns immediate network replies without exposing a borrowed BoringTun
  output slice.
- The batch must support stable in-place retention/compaction and mutable
  access to only its initialized prefix. Production callers must not be able to
  expose stale slots as initialized packets.
- Convert the kernel-TUN inbound burst path to append plaintext directly into
  the reusable batch while each peer tunnel is locked, record its peer in an
  aligned side vector, then release all tunnel locks before filtering,
  capture, replies, or TUN I/O.
- Apply filtering and capture in original packet order, stably compact accepted
  plaintext, and call `Tun::write_batch` on the initialized prefix. After
  success, error, or cancellation-safe return, reset only the logical length.
- Linux write-side GRO may mutate packet contents and lengths. Every reused
  slot must be cleared and fully overwritten before becoming initialized
  again.
- Preserve reply ordering, missing-peer drop boundaries, packet-drop metrics,
  burst cap, capture-before-GRO behavior, and all scalar/netstack callers.
- Do not retain ciphertext datagrams across reply I/O or a blocked TUN write.
- Keep retained capacity bounded by the existing 128-packet burst and maximum
  WireGuard message size. Do not add unsafe code or a new allocator/dependency.

## Verification

- Differential scalar-versus-batched WireGuard tests must cover handshake
  replies, IPv4/IPv6 data, keepalive/garbage behavior, and packet order.
- Prove slot pointer/capacity reuse across consecutive decapsulation batches.
- Cover stable filter-drop compaction with mixed accepted/dropped packets,
  aligned peer identity, capture before a mutating TUN write, reuse after GRO
  mutation, TUN write error, and the 128-packet burst boundary.
- `cargo test -p rustscale-wg -p rustscale-tsnet` and clippy for both crates.
- `tools/check.sh` and Linux cross-compilation must pass. Exercise the merged
  path on native Linux through the production kernel-TUN benchmark.
- Re-run the same-zone direct profiled benchmark. Accept only if allocation
  and wrapper costs materially fall without throughput, latency, RSS, packet
  ordering, filtering, capture, or handshake regressions.
