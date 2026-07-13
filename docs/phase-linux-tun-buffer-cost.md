# Linux TUN per-packet buffer cost

## Baseline

The clean 2026-07-13 same-zone direct run in
`bench-results/gcp-20260713-034309` measured:

| Config | P=1 | P=10 | P=100 | p50 | p99 |
| --- | ---: | ---: | ---: | ---: | ---: |
| rustscale TUN | 287.88 Mbps | 186.15 Mbps | 315.43 Mbps | 1,440 us | 24,300 us |
| Tailscale TUN | 2,308.42 Mbps | 2,501.39 Mbps | 1,672.50 Mbps | 1,870 us | 2,310 us |

Both CLI gates reported `direct`. The Rustscale server averaged 90.6% CPU, so the
first pass should reduce per-packet work before adding concurrency.

## Problem

On Linux, `TunDevice::read_packet` allocates and zeroes 65,535 bytes for every
packet even though the configured TUN MTU is 1,280 bytes. `write_packet` also
copies every packet into a new `Vec` solely to support a partial-write loop.
Linux TUN packet writes are datagram-like; a short positive write must be treated
as an error rather than retrying the remainder as another packet.

This phase intentionally does not add `IFF_VNET_HDR`, GSO/GRO, `readv`, or UDP
batching. An ordinary Linux `readv` does not batch independent TUN packets.

## Required changes

1. Size the Linux read allocation from the configured MTU instead of the maximum
   IPv4 packet size. Reject an unusable zero MTU or otherwise make the allocation
   safe without restoring the 65,535-byte hot-path zeroing cost.
2. Remove the unconditional `packet.to_vec()` in the Linux write path. Preserve
   Tokio `AsyncFd` readiness handling and return a clear error for a short write.
3. Add focused unit-testable helpers for buffer sizing and write-result handling,
   since real Linux TUN creation is privileged and the main development host is
   macOS.
4. Keep the public `Tun` trait and non-Linux implementations unchanged.

## Acceptance

- Focused tests cover configured MTU sizing, zero/invalid sizing, full writes,
  short writes, and syscall errors.
- `tools/check.sh` passes.
- A fresh same-zone direct `rs-tun,ts-tun` benchmark completes with both paths
  reported direct.
- Rustscale p50 latency does not regress materially. Throughput is recorded even
  if the isolated allocation change is smaller than expected; do not hide a null
  result by combining later batching work into this phase.
