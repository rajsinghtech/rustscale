# Parallel single-peer WireGuard decryption

## Evidence

The accepted direct Linux run at `bench-results/gcp-20260713-235632`
(`33b6b4a`, merged by `f2aed71`) reached 1968.383/2009.813/1637.574 Mbps
at P1/P10/P100 with 931 microsecond p50 latency. On the receiving client:

- task clock was 10.839 seconds for the 10-second reverse P10 profile;
- ChaCha20-Poly1305 open consumed 24.20% exclusive and 28.09% inclusive,
  about 2.6-3.0 seconds of CPU;
- TUN write children consumed 14.37% and `recvmmsg` 11.59%, but their
  absolute CPU time was effectively flat relative to the slower
  `gcp-20260713-213538` baseline;
- process CPU averaged 76.87% and peaked at 120% on a four-vCPU host.

Rustscale currently processes a received run under one
`Mutex<WgTunn>` in `crates/tsnet/src/tun_pump.rs`, so one peer cannot use spare
cores. Tailscale's pinned wireguard-go fork instead submits ordered per-peer
containers to a global pool of `runtime.NumCPU` decryption workers, waits for
each container in receive order, then performs replay validation and the TUN
write sequentially. See `device/receive.go` in
`github.com/tailscale/wireguard-go@ffb138071028`.

BoringTun 0.7.1's public `Tunn::decapsulate` requires `&mut self`, but its
`Session::receive_packet_data` already uses `&self`; the sending counter is
atomic and the receiving replay window is protected by a mutex. A narrow
upstream-style batch API can expose this existing concurrency without cloning
keys or reimplementing WireGuard.

## Phase boundary

First implement and measure the smallest safe BoringTun batch-decrypt API.
Do not change the production TUN pump until the API passes differential tests
and demonstrates at least 1.3x throughput on an established 128-packet,
single-session decrypt benchmark with two persistent workers.

Use a repository-owned patch of the exact BoringTun 0.7.1 source so the change
is reproducible. Keep the patch narrow and suitable for upstreaming. Do not
duplicate session keys in rustscale, call `Tunn::decapsulate` concurrently,
or bypass BoringTun's counter checks.

## Batch API requirements

1. The serialized `Tunn` owner parses and rate-limits input, resolves the
   immutable session for each transport packet, and preserves handshake,
   cookie, queued-output, and error behavior on the existing scalar path.
2. Data AEAD opens may run concurrently through shared `Session` references.
   Use bounded persistent workers; never create operating-system threads per
   packet or per batch.
3. Each packet has independent caller-owned output storage. Results remain in
   exact input order regardless of worker completion order.
4. Replay protection remains atomic. Concurrent duplicates are accepted at
   most once; corrupt AEAD packets never mark a counter; too-old and
   out-of-window counters match scalar behavior.
5. After worker completion, the `Tunn` owner commits current-session selection,
   packet validation, timers, counters, and byte accounting in input order.
6. Cancellation, worker shutdown, panic, and partial invalid input return all
   buffers and cannot leave a batch visible as complete.
7. Bound in-flight work to two 128-packet containers initially. Retain worker
   and output allocations between iterations.

## Spike verification

- Differential scalar-versus-batch tests cover ordered IPv4/IPv6 data,
  keepalives, garbage, handshake boundaries, key rotation, and session-ring
  changes.
- Counter tests cover duplicates racing on different workers, reverse-order
  packets within the 1024-packet window, too-old counters, large gaps, and a
  corrupted tag followed by the valid packet with the same counter.
- A deterministic benchmark or ignored performance test reports packets per
  second and bytes per second for scalar, one-worker, and two-worker operation
  after an established handshake. It must validate output bytes, not only
  timing.
- `cargo test -p boringtun` (or the patched crate's equivalent),
  `cargo test -p rustscale-wg`, strict clippy, formatting, and `git diff
  --check` pass.
- Do not merge or integrate a result below 1.3x two-worker decrypt throughput.

## Spike result

The isolated macOS implementation preserved ordered replay commits and passed
the focused RustScale WireGuard tests and strict clippy, but failed the
performance gate. For 128 established-session packets with 1,400-byte
payloads, the enforced release run measured:

| Path | Packets/second | Relative to scalar |
| --- | ---: | ---: |
| Scalar | 840,562 | 1.000x |
| One persistent worker | 546,908 | 0.651x |
| Two persistent workers | 623,828 | 0.742x |

A separate diagnostic run produced the same conclusion: 0.761x for one worker
and 0.771x for two. The safe API copied ciphertext into worker-owned storage,
used channel handoff for every packet, and waited for ordered owner commits.
Those fixed costs exceeded the available parallel AEAD gain on this host.

The implementation was not committed or integrated into the production TUN
pump. A later attempt must first remove per-packet ownership transfer and
channel overhead, then demonstrate the 1.3x microbenchmark gate on Linux before
repeating any end-to-end GCP run. Full vendoring is not justified until that
narrower primitive passes.

## Production gate after the spike

Production integration must retain packet/filter/capture/reply order, direct
and DERP fairness, bounded magicsock credits and pool inventory, handshake
progress, and scalar public APIs. Run the exact same-zone/direct
`rs-tun --profile --repeat 3` benchmark. Require a material P1/P10 gain, no
P100 or latency regression, bounded RSS growth, complete profile artifacts,
and complete VM/tailnet cleanup.

## Rejected next steps

- TUN multiqueue: Tailscale serializes Linux TUN writes, and current TUN
  absolute CPU stayed flat while throughput rose.
- Parallel work only across peers: the benchmark and common point-to-point
  transfer are single-peer.
- In-place decode alone: it also requires a BoringTun patch but the current
  profile identifies AEAD compute, not a named user-space copy, as the larger
  opportunity.
- Replacing the WireGuard engine: this has a much larger protocol and parity
  blast radius than exposing concurrency already present in BoringTun's
  session internals.
