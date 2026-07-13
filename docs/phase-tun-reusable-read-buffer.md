# TUN Reusable Read Buffer

## Goal

Remove the per-packet heap allocation from the TUN outbound hot path without
changing packet framing, scheduling, or batching behavior.

The former `Tun::read_packet` returned a fresh `Vec<u8>`. The current
`Tun::read_batch` reuses packet storage. Linux previously allocated and
initializes an MTU-sized vector for every packet, while macOS allocates a maximum
packet buffer and then allocates again when stripping the utun address-family
header. The production TUN pump consumes each packet before beginning the next
read, so it can retain one vector for its lifetime.

## Required changes

1. Replace the allocating trait method with a caller-owned reusable batch
   contract. The method must clear/replace the previous contents and return raw
   IPv4 or IPv6 packets in read order. Keep the trait object-safe under
   `async_trait`.
2. Allocate the production pump batch once, outside its select loop, and reuse
   it for every TUN read. Do not hold packet slices across the next read.
3. On Linux, reserve at least the configured MTU and read directly into retained
   vector capacity. Only expose the bytes initialized by a successful syscall.
   A cancelled read, readiness retry, EOF, or syscall error must leave a valid
   vector and must never expose uninitialized memory.
4. On macOS, reuse retained storage for a maximum-size utun frame, validate the
   four-byte address-family header, and remove it in place. The current macOS
   implementation does not apply the configured MTU to the kernel interface,
   so the MTU is not a safe read bound. Preserve the public raw-IP packet
   contract without a second packet allocation.
5. Update `MockTun`, crate tests, and all `Tun` call sites. Preserve mock channel
   ownership and EOF behavior.
6. Add focused tests proving capacity is reused across successive reads and that
   malformed/short macOS framing remains rejected. Keep unsafe code small and
   explain its initialization invariant.

## Non-goals

- `readv` batching. Ordinary `readv` does not return independent TUN packets.
- Linux `IFF_VNET_HDR`, GRO, GSO, `recvmmsg`, `sendmmsg`, or parallel crypto.
- Public compatibility with the old allocating `Tun::read_packet` signature;
  all in-repository consumers should migrate together.

## Validation

- `cargo fmt --check`
- `cargo test -p rustscale-tun`
- `cargo test -p rustscale-tsnet`
- `cargo check -p rustscale-tun --target x86_64-unknown-linux-musl`
- `cargo clippy -p rustscale-tun --tests --target x86_64-unknown-linux-musl -- -D warnings`
- `RUST_TEST_THREADS=1 tools/check.sh`
- A clean same-zone, direct-only `rs-tun,ts-tun` GCP matrix after merge.
