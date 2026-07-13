# Phase: TUN Internet Checksum ILP

## Objective

Reduce the CPU cost of the Internet checksum used by Linux TUN GSO splitting
and TCP GRO validation without changing packet acceptance, segmentation, byte
order, or offload metadata semantics.

The same-zone direct `rs-tun` profile from
`bench-results/gcp-20260713-180547` attributes 5.27% client self CPU and 5.97%
server self CPU to `rustscale_tun::offload::checksum`. The current 128-byte
loop feeds sixteen words through one carry dependency chain. This phase should
expose instruction-level parallelism with multiple independent accumulators;
it must not skip checksum validation or weaken Tailscale parity.

## Required Behavior

1. Replace the serialized large-buffer checksum loop with a portable four-lane
   one's-complement accumulator over 32-byte stripes.
2. Preserve exact RFC 1071 output for every input length, alignment, initial
   value, host endianness, and carry pattern.
3. Add a no-fold internal accumulator/composition seam so pseudo-header pieces
   can be composed without repeatedly folding tiny slices, when this is both
   simpler and measurably useful.
4. Keep the scalar tail and final fold explicit and safe. Target-specific SIMD
   or runtime feature dispatch is outside this phase.
5. Preserve all existing GSO/GRO behavior:
   - TCPv4, TCPv6, and UDP GSO segments receive correct transport checksums.
   - IPv4 header checksums remain correct.
   - Invalid GRO heads and merge candidates remain uncoalesced.
   - Valid prepend and append candidates continue to coalesce.
   - TUN offload flags and virtio-net metadata do not change.

## Tests

- Differential checksum coverage for lengths `0..=4096`, offsets `0..=31`,
  and initial values `0`, `1`, `0x1234`, and `0xffff`.
- Adversarial all-zero/all-`0xff` data and carry-boundary lengths around 32 and
  128 bytes, including odd lengths and odd starting offsets.
- Existing TCPv4/TCPv6/UDP split fixtures must continue verifying every output
  packet's IP and transport checksum.
- Existing GRO invalid-checksum and valid prepend/append coverage must remain
  green; add focused cases if current coverage does not prove both head and
  candidate rejection.
- Add a deterministic ignored release microbenchmark or equivalent harness for
  64, 512, 1440, and 65535-byte buffers. It must compare the optimized and
  scalar reference outputs and report throughput without adding a production
  dependency.

## Gates

- `cargo fmt --all --check`
- `cargo test -p rustscale-tun -- --nocapture`
- `cargo clippy -p rustscale-tun --all-targets -- -D warnings`
- Native Linux `rustscale-tun` tests.
- Workspace `RUST_TEST_THREADS=1 tools/check.sh`.

## Benchmark Acceptance

Repeat the same-zone, direct, profiled `rs-tun` benchmark three times using the
same machine class and workload as `gcp-20260713-180547`.

- Checksum self CPU must fall by at least 30% relative on both endpoints, or to
  at most 3.5% each.
- P1, P10, and P100 median throughput must not regress by more than 3%; target
  at least a 5% P1/P10 improvement.
- Latency p50 and p95 must not regress by more than 5%.
- GRO parse failures and permanent fallbacks remain zero; RXQ loss must not
  materially increase.
- RSS and binary-size movement must be negligible.

If the controlled benchmark shows a repeatable material regression, revert the
phase instead of retaining an optimization justified only by a microbenchmark.
