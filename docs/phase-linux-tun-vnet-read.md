# Phase: Linux TUN VNET/GSO receive batching

## Evidence

The production `rs-tun` profile in
`bench-results/gcp-20260713-053900/profile/` captured 5,308 samples with none
lost. The TUN pump accounted for 48.6% inclusive CPU, outbound encapsulation
29.7%, `Magicsock::send` 21.9%, and Tokio UDP `send_to` 20.4%. WireGuard plus
ChaCha encryption was only about 6%. Futex wakeups, context switches, and one
TUN/UDP syscall per packet dominate the direct path.

Tailscale's Linux TUN requests `IFF_VNET_HDR`. The kernel can then return one
coalesced TCP/UDP GSO frame; wireguard-go splits it into a packet vector and
handles the vector in one scheduler turn. Rustscale currently requests only
`IFF_TUN | IFF_NO_PI` and wakes for every MTU-sized packet.

Authoritative sources:

- `/Users/rajsingh/go/pkg/mod/github.com/tailscale/wireguard-go@v0.0.0-20260611001507-ffb138071028/tun/tun_linux.go`
  (`handleVirtioRead`, `Read`, `initFromFlags`, `CreateTUN`)
- The same directory's `offload_linux.go`, `offload.go`,
  `offload_linux_test.go`, `offload_test.go`, and checksum helpers.

## Scope

Implement receive-side Linux VNET/GSO and reusable TUN packet batches. Do not
add TUN write GRO, UDP socket GSO/GRO, `sendmmsg`, or unrelated pump changes in
this phase.

## Packet batch API

1. Replace the one-packet TUN read contract with a reusable `TunPacketBatch`
   that owns its packet buffers and exposes read-only packet slices after a
   successful read. The batch must retain allocations across reads, clear
   logical lengths on reuse, and never expose partially initialized data.
2. Cap a batch at 128 packets, matching wireguard-go `conn.IdealBatchSize`.
   Grow segment buffers only to the produced segment length; do not allocate
   128 full 65,535-byte buffers eagerly.
3. Linux fills one packet in plain fallback mode and one or more packets in
   VNET mode. Darwin and `MockTun` remain one-packet implementations.
4. Update `run_tun_pump` to process every packet in the returned batch in order
   during the same selected read branch. Preserve per-packet filter, route,
   WireGuard, and magicsock semantics. Do not spawn a task per segment.

## Linux negotiation

1. First open and configure a fresh `/dev/net/tun` fd with
   `IFF_TUN | IFF_NO_PI | IFF_VNET_HDR` (`IFF_VNET_HDR = 0x4000`). After
   `TUNSETIFF`, enable `TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6` using
   `TUNSETOFFLOAD`.
2. If VNET flags or required TCP offloads fail with an unsupported-operation
   error, close that fd and repeat the complete open/`TUNSETIFF` sequence on a
   fresh fd using `IFF_TUN | IFF_NO_PI`. Do not continue on a partially
   configured descriptor and do not hide permission, invalid-name, or other
   creation errors as a fallback.
3. Track whether VNET is active in `TunDevice`. Keep MTU application and
   nonblocking/close-on-exec behavior unchanged.
4. Plain mode reads at most the configured MTU. VNET mode reads into one
   retained `10 + 65_535` byte raw-frame buffer because a coalesced GSO frame
   is larger than the interface MTU.

## Virtio header

Parse the 10-byte native-endian Linux `virtio_net_hdr` without struct casts:

```text
flags:u8, gso_type:u8, hdr_len:u16, gso_size:u16,
csum_start:u16, csum_offset:u16
```

Support `GSO_NONE=0`, `GSO_TCPV4=1`, `GSO_UDP_L4=3`, and `GSO_TCPV6=4` plus
`F_NEEDS_CSUM=1`. Reject unknown types, short frames, invalid offsets, and more
than 128 segments with `InvalidData`.

Do not trust `hdr_len` for GSO reads. For UDP use `csum_start + 8`. For TCP,
read the data-offset nibble at `csum_start + 12`, require a 20..=60 byte header,
and use `csum_start + tcp_header_len`. All additions and conversions must be
checked. A nonzero GSO type requires `gso_size > 0`.

## GSO splitting

Port wireguard-go `GSOSplit` behavior into safe Rust:

1. Validate the checksum location, header bounds, IP version/GSO type pairing,
   minimum IPv4/IPv6 and TCP lengths, output segment cap, and every computed
   slice before mutation.
2. `GSO_NONE`, or a payload shorter than `gso_size`, produces one packet. If
   `F_NEEDS_CSUM` is set, treat the existing checksum field as the initial
   pseudo-header sum, zero the field, and write the complemented checksum over
   the transport bytes.
3. Each real segment copies the IP and transport headers plus its payload.
   For IPv4, set total length, increment the original ID by the segment index
   with wrapping `u16` arithmetic, zero and recompute the IPv4 header checksum.
   For IPv6, update payload length.
4. For TCP, set sequence to `first_seq + gso_size * segment_index` with wrapping
   `u32` arithmetic. Clear FIN and PSH on every non-final segment and preserve
   all other flags. For UDP, update the UDP length.
5. Zero and recompute each TCP/UDP checksum from the IPv4/IPv6 pseudo-header,
   transport header, and segment payload. Port the checksum helpers rather than
   adding a dependency or using unaligned/native struct reads.
6. On any error, report no successful batch to the pump. The batch remains
   valid and reusable on retry, cancellation, EOF, or syscall failure.

## Tests

- Platform-neutral tests cover TCPv4, TCPv6, UDPv4, and UDPv6 splitting with
  two full segments and a shorter tail; verify lengths, payloads, TCP sequence,
  FIN/PSH placement, IPv4 ID/length/checksum, IPv6 payload length, UDP length,
  and transport checksums.
- Cover `GSO_NONE` with and without `F_NEEDS_CSUM`, a deliberately untrusted
  kernel `hdr_len`, native-endian virtio decoding, zero `gso_size`, short TCP
  data offset, invalid checksum offsets, IP/GSO mismatch, overflow/bounds, and
  more than 128 segments.
- Linux-specific tests verify exact `ifreq` flags, offload constants, VNET read
  bound, and fallback classification. Existing Darwin framing, mock TUN, pump,
  and reusable-buffer tests must continue to pass.
- Add a pump test proving all packets in one injected batch traverse in order
  without an intervening TUN read.

## Validation

- `cargo fmt --check`
- `cargo test -p rustscale-tun`
- `cargo test -p rustscale-tsnet tun`
- `cargo clippy -p rustscale-tun -p rustscale-tsnet --all-targets -- -D warnings`
- `cargo check -p rustscale-tun --target x86_64-unknown-linux-gnu`
- `cargo clippy -p rustscale-tun --tests --target x86_64-unknown-linux-gnu -- -D warnings`
- `RUST_TEST_THREADS=1 tools/check.sh`
- On Linux, create a real TUN device and verify `TUNGETIFF` includes
  `IFF_VNET_HDR` before repeating the direct `rs-tun,ts-tun` benchmark.
