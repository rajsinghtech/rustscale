# Phase: Linux UDP GRO receive batching

## Evidence

The focused direct-path profiles show the Linux UDP receive path still issuing
one `recvfrom` syscall per datagram:

- `gcp-20260713-092151`: `__x64_sys_recvfrom` 1.84% inclusive.
- `gcp-20260713-103722`: `__x64_sys_recvfrom` 2.46% inclusive after UDP GSO.

The profile is collected on the reverse-iperf server, so it under-represents
the client that receives the bulk data stream. The current Rustscale receive
task in `crates/magicsock/src/lib.rs::spawn_recv_tasks` performs one awaited
`recv_from`, then repeatedly calls `try_recv_from`. This reduces Tokio wakeups
but not receive syscalls or kernel skb delivery overhead.

Tailscale's Linux path uses `recvmmsg` plus `UDP_GRO` in
`../tailscale/net/batching/conn_linux.go`. When GRO is enabled it reads into two
large messages at the tail of a 128-message batch and splits their `UDP_GRO`
segments into the reusable head messages before returning them to magicsock.

## Goal

Port the same Linux receive contract to Rustscale: receive direct UDP bursts
with `recvmmsg`, accept kernel UDP GRO coalescing when supported, and present
the existing packet handlers with the original ordered logical datagrams.

No disco, WireGuard, Geneve, path-selection, accounting, or non-Linux behavior
may change.

## Scope

### Socket capability

In `crates/magicsock/src/udp_batch.rs`:

1. Define the Linux `UDP_GRO` socket option using the platform ABI value.
2. Add a capability setup helper that enables `UDP_GRO` with `setsockopt` and
   returns whether it succeeded.
3. Do not infer GRO support from GSO support. Probe them independently.
4. Keep failure best-effort. Unsupported kernels continue with `recvmmsg`
   without GRO; non-Linux continues through the existing Tokio receive path.

Do not add a permanent heap allocation to `Inner` for the receive batch. The
single receive task owns and reuses its scratch storage.

### Receive batch

Add a Linux-only reusable receive batch helper in `udp_batch.rs` with these
properties:

- Maximum logical batch size is the existing `MAX_BATCH` (128).
- Use nonblocking `recvmmsg` on the Tokio socket's raw fd.
- Preserve source `SocketAddr`, logical datagram length, and input order.
- Reject truncated messages instead of passing partial packets to disco/WG.
- Reinitialize all kernel-written header lengths and flags before each call.
- Keep every pointer target alive and stable for the complete syscall.
- Use ABI-derived, `cmsghdr`-aligned ancillary storage. Do not hard-code a
  byte array whose alignment is insufficient.

When GRO is unavailable, receive up to 128 ordinary messages directly into
reusable packet buffers.

When GRO is available, mirror Tailscale's bounded layout:

1. Reserve the final two message slots as 65,536-byte kernel receive buffers.
2. Call `recvmmsg` only on those two tail slots.
3. Parse the `SOL_UDP/UDP_GRO` native-endian `u16` segment size from each
   returned message's control data.
4. A message without a valid nonzero GRO size is one logical datagram.
5. Split a coalesced message into `ceil(total_len / segment_size)` logical
   datagrams. All segments except the final one have exactly `segment_size`
   bytes; the final segment may be smaller.
6. Copy the logical datagrams into reusable head buffers and return borrowed
   packet views for only the duration of dispatch. Do not allocate a `Vec` per
   received datagram.
7. Fail the batch, without dispatching a partial prefix, if ancillary data is
   malformed, the split would exceed 128 messages, a source address is
   invalid, or a logical packet exceeds its destination buffer.

Normal direct WireGuard and disco packets fit the logical packet buffers. Use
a capacity derived from the current maximum UDP/TUN packet expectations, at
least 2,048 bytes, and make oversize handling explicit rather than truncating.

### Async receive task

In `crates/magicsock/src/lib.rs::spawn_recv_tasks`, Linux should:

1. Own one reusable receive batch for the task lifetime.
2. Await socket readability, then call the nonblocking batch helper.
3. Retry readiness on `WouldBlock`.
4. For every returned logical datagram, in order, call `record_udp_rx` with
   the logical length and then the existing `handle_udp_packet`.
5. Keep all existing Geneve, disco, WireGuard, candidate-learning, and
   sockstats behavior downstream of that boundary.

If a runtime error proves `recvmmsg` unavailable, disable `UDP_GRO` before
falling back to scalar `recv_from`; scalar reads must never consume an opaque
coalesced GRO payload without its segment control message. Ordinary packet
errors may retain the existing receive-task termination behavior.

Do not introduce another channel or task between socket receive and packet
dispatch in this phase.

### Non-Linux

Keep the existing awaited `recv_from` plus `try_recv_from` drain unchanged on
non-Linux targets. Linux-only imports and helpers must be cfg-gated so macOS
workspace clippy stays clean.

## Tests

Add Linux tests for:

- Plain `recvmmsg` loopback reception preserves multiple datagrams and source
  addresses in order.
- GRO setup is best-effort and independently testable from GSO.
- A GSO loopback send received through GRO is split back into the exact
  original equal segments plus a smaller tail. Skip only when the running
  kernel reports the relevant offload option unsupported.
- Two coalesced tail messages split into one ordered logical batch.
- Missing GRO control data yields one datagram.
- Malformed control data, truncation, invalid source family, oversize logical
  packets, and more than 128 split segments are rejected.
- Scratch reuse across consecutive receives does not expose stale lengths,
  flags, control data, sources, or packet bytes.

Preserve all existing GSO planner, partial-progress, and loopback tests.

## Acceptance

- `cargo fmt --all --check`
- `RUST_TEST_THREADS=1 cargo test -p rustscale-magicsock`
- `cargo clippy -p rustscale-magicsock --all-targets -- -D warnings`
- `RUST_TEST_THREADS=1 tools/check.sh`
- Linux release build has no new warnings.
- Direct disco/CLI integration tests still pass.
- No increase to the steady-state receive task allocation rate per datagram.

After merge, rerun the focused same-zone/direct `rs-tun --profile` cell and
compare throughput, latency tails, RSS, `recvfrom`/`recvmmsg`, and total CPU
against both `gcp-20260713-092151` and `gcp-20260713-103722`.
