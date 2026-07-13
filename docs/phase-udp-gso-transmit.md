# Phase: Linux UDP GSO transmit

## Goal

Reduce the dominant per-datagram Linux UDP/IP/device cost on the direct
WireGuard transmit path by coalescing ordered ciphertext datagrams with
`UDP_SEGMENT`. Preserve the current `sendmmsg` path as the capability and
runtime fallback.

The controlled profile in `bench-results/gcp-20260713-092151` attributes only
0.59% self time to `__sendmmsg`, but 39.24% inclusive time to the kernel UDP,
IP, and device path below it. Linux TUN vnet offload already gives the outbound
pump runs of full-size packets, and `WgDatagramBatch` preserves those runs as
equal-size WireGuard ciphertexts. This is the workload UDP GSO is designed to
coalesce.

Reference implementation:
`/Users/rajsingh/Documents/GitHub/tailscale/net/batching/conn_linux.go`, notably
`tryEnableUDPOffload`, `coalesceMessages`, `setGSOSizeInControl`, and
`WriteBatchTo`.

## Scope

- Linux direct UDP only. DERP, peer relay, and non-Linux behavior do not change.
- Extend `crates/magicsock/src/udp_batch.rs` to plan and send GSO-coalesced
  messages using `sendmmsg` and a `SOL_UDP` / `UDP_SEGMENT` control message.
- Probe TX GSO availability on the magicsock UDP socket with
  `getsockopt(IPPROTO_UDP, UDP_SEGMENT)`. Do not set a default segment size on
  the socket; each coalesced message carries its own cmsg.
- Store runtime TX-GSO availability on `MagicsockInner` as an `AtomicBool`.
- In `send_direct_batch_linux`, prefer GSO when available. On the Linux `EIO`
  identified by `rustscale_neterror::should_disable_udp_gso`, atomically
  disable GSO and retry the entire unsent input through the existing plain
  `sendmmsg` path.
- Do not add configuration, control-plane knobs, dependencies, or public API.

## Coalescing contract

Input and output datagram order must be identical. Walk the input once and
form maximal GSO messages subject to all of these limits:

1. A GSO message starts with the first remaining datagram. Its length is the
   segment size.
2. Following datagrams may join only while their length is equal to the
   segment size. A single smaller final datagram may be the tail of that GSO
   message, after which the message ends. A larger or second non-equal
   datagram starts a new message.
3. A message contains at most 64 UDP segments.
4. Its total UDP payload must not exceed 65,507 bytes for IPv4 or 65,527 bytes
   for IPv6.
5. A one-datagram message is sent without `UDP_SEGMENT` control data.
6. Packet storage remains borrowed for the syscall. Use scatter/gather iovecs;
   do not concatenate or clone ciphertext payloads.

The Tailscale sentinel-tail workaround is controlled by a live control knob
and is disabled in the normal path. Rustscale has no corresponding knob, so it
is deliberately out of this phase. Keep the planner structured so that a
workaround can be added without changing ordering rules if a target kernel is
shown to need it.

`sendmmsg` partial success is an exact prefix in terms of planned kernel
messages, but a GSO message represents multiple original datagrams. The helper
must return progress in original datagram units so the caller neither retries
already-sent ciphertext nor skips an unsent packet. A zero result is treated as
`WouldBlock`, as in the current helper.

## Error behavior

- Preserve Tokio `AsyncFd::async_io(WRITABLE, ...)` readiness ownership.
- If the initial capability probe fails, use plain `sendmmsg` without logging
  per packet or treating this as an error.
- If a GSO send fails with `EIO`, disable GSO for subsequent sends and retry
  the same unsent datagram suffix through plain `sendmmsg`.
- Other errors follow the existing `advance_direct_batch` and
  `treat_as_lost_udp` behavior. Do not silently retry an ambiguous partial GSO
  success.
- Continue recording UDP TX accounting once per original datagram and with
  the original ciphertext length.

## Tests

Add Linux-focused unit tests for a pure coalescing planner or equivalent
observable helper:

- equal-size packets coalesce and report the correct segment size;
- a smaller tail joins once and ends the message;
- a larger or differently sized packet starts a new message;
- 64-segment and IPv4/IPv6 payload limits split without reordering;
- singleton messages carry no GSO control data;
- planned-message progress maps back to the exact original datagram prefix;
- cmsg header level, type, length, and native-endian `u16` payload are correct.

Add a Linux loopback test that sends a GSO-eligible batch and receives the
original datagrams in order. Skip only when the kernel reports that
`UDP_SEGMENT` is unsupported. Retain the existing plain `sendmmsg` tests and
ensure the fallback helper remains independently exercised.

## Acceptance

- `cargo fmt --all --check`
- `cargo test -p rustscale-magicsock`
- `cargo clippy -p rustscale-magicsock --all-targets -- -D warnings`
- Linux GNU build and musl check remain green.
- `RUST_TEST_THREADS=1 tools/check.sh`
- No functional diff outside Linux direct UDP batching.

After merge, rerun the one-cell focused GCP profile. Compare P1/P10/P100
throughput and the inclusive UDP/IP/device bucket against
`gcp-20260713-092151`; checksum and ChaCha self percentages are secondary.
