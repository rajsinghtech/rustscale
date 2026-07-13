# Phase: TUN checksum fast path

## Evidence

The focused same-zone direct profile at
`bench-results/gcp-20260713-085426/same-zone/direct/profile/` captured the
production `rustscaled` server during a reverse P10 iperf run. Its self profile
attributes 8.66% of task clock to `rustscale_tun::offload::checksum`, second
only to ChaCha20-Poly1305 sealing at 9.50%. The current checksum implementation
in `crates/tun/src/offload.rs` consumes two input bytes per loop iteration.

The wireguard-go implementation used as the behavioral reference processes
native-endian 64-bit words, explicitly propagates carry, unrolls the bulk loop
to 128 bytes, and folds only after accumulation. Rustscale already ports the
surrounding `gsoSplit` behavior, but not this checksum fast path.

## Scope

Optimize only the platform-neutral Internet checksum helper used by virtio-net
GSO splitting and checksum completion.

1. Replace the two-byte bulk loop with a safe Rust port of wireguard-go's
   `checksumNoFold` strategy:
   - use native-endian 64-bit loads from byte arrays, without pointer casts or
     alignment assumptions;
   - accumulate with end-around carry;
   - process a 128-byte unrolled bulk block, then 64/32/16/8/4/2/1-byte tails;
   - preserve the current big-endian Internet-checksum result and the meaning
     of the initial non-complemented sum.
2. Keep `split_virtio`, packet segmentation, pseudo-header construction,
   checksum placement, error behavior, and all public APIs unchanged.
3. Do not add dependencies, architecture-specific assembly, SIMD intrinsics,
   `unsafe`, runtime CPU detection, or unrelated offload changes.
4. Keep all platforms supported. This helper is platform-neutral even though
   the measured caller is the Linux VNET read path.

## Correctness tests

Retain the existing packet-level offload tests and add a test-only scalar
reference matching the old two-byte algorithm. Differentially compare the fast
implementation with the scalar reference for:

- empty input and every length from 1 through at least 512 bytes;
- deterministic contents that exercise carry propagation;
- multiple non-zero initial sums, including `0xffff`;
- subslices starting at offsets 0 through 7 to cover every alignment;
- lengths around every bulk/tail boundary: 1, 2, 3, 4, 7, 8, 15, 16, 31,
  32, 63, 64, 127, 128, 129, 255, 256, and 511 bytes.

Tests must remain deterministic and dependency-free.

## Validation

- `cargo test -p rustscale-tun`
- `cargo clippy -p rustscale-tun --all-targets -- -D warnings`
- `cargo check -p rustscale-tun --target x86_64-unknown-linux-musl`
- `RUST_TEST_THREADS=1 tools/check.sh`
- `git diff --check`

After merge, run the same focused same-zone direct `rs-tun --profile` benchmark
and compare checksum self overhead plus P1/P10/P100 throughput against
`gcp-20260713-085426`. Treat throughput as noisy because that run's direct gate
needed a retry; the primary acceptance signal is byte-identical differential
coverage and a material reduction in checksum self CPU.

## Non-goals

- UDP `recvmmsg` or GRO
- TUN write GRO
- WireGuard encryption parallelism
- preserving virtio metadata across the WireGuard wire format
- benchmark CLI or discovery behavior changes
