# Phase: Linux direct UDP `sendmmsg`

## Evidence

The same-zone direct benchmark after heartbeat coalescing and contiguous-peer
TUN batching reached 509.92, 606.89, and 572.93 Mbps at 1, 10, and 100 iperf
streams. The immediately preceding retained baseline reached 385.30, 507.76,
and 318.95 Mbps. P50 latency improved from 1,380 us to 797 us and peak RSS
remained about 13 MiB.

Tailscale reached 2,192.93, 2,212.66, and 1,704.61 Mbps on the same new VM
pair. Rustscale therefore delivers 23.3%, 27.4%, and 33.6% of Tailscale's
throughput while using less CPU and memory. The earlier Linux profile placed
20.4% inclusive CPU in Tokio UDP `send_to` and only about 6% in WireGuard plus
ChaCha. The new `Magicsock::send_batch` still performs one awaited `send_to`
per datagram, so Linux syscall batching is the next bounded phase before any
parallel-encryption redesign.

Reference behavior:

- `../tailscale/net/batching/conn_linux.go`: `WriteBatchTo` and `writeBatch`
- `../tailscale/wgengine/magicsock/rebinding_conn.go`:
  `WriteWireGuardBatchTo`
- Tokio `UdpSocket::async_io` and `try_io` writable-readiness APIs

## Scope

Batch only non-relay direct WireGuard UDP sends on Linux. Keep DERP, peer
relay/Geneve, discovery, PMTUD, receive paths, non-Linux behavior, public
single-datagram behavior, path selection, and WireGuard encryption unchanged.

Do not add UDP GSO/GRO, `recvmmsg`, parallel encryption, extra UDP sockets,
socket conversion to `AsyncFd`, a blocking task, or a new dependency.

## Platform helper

Add a private Linux module in `crates/magicsock`, isolated like the existing
PMTUD platform code so the crate-wide `unsafe_code = "deny"` policy remains in
force elsewhere.

1. Expose a synchronous helper that attempts one `sendmmsg` call on a
   `tokio::net::UdpSocket` raw fd for an ordered, nonempty prefix of
   same-destination datagrams.
2. Use the existing `libc` dependency and one reviewed `libc::sendmmsg` unsafe
   call. Do not add `nix`, `mio`, or `rustix` solely for this syscall.
3. Build `sockaddr_in` or `sockaddr_in6` from `SocketAddr`, including network
   byte order, IPv6 flow info, and scope ID. Point every message at the same
   live sockaddr value for the duration of the syscall.
4. Build at most 128 `iovec` and `mmsghdr` values, matching the TUN batch cap.
   Use fixed stack arrays or another allocation-free representation; do not
   allocate header vectors for every microburst.
5. Each message has exactly one iovec referencing its caller-owned datagram.
   The helper must not retain pointers or references after it returns.
6. Call `sendmmsg` with `MSG_DONTWAIT`. A positive result is the exact sent
   prefix length. Zero is treated as `WouldBlock`. `-1` maps `last_os_error`.
   Reject an empty input or an input larger than the fixed cap before entering
   unsafe code.
7. Keep the raw helper small and independently test its sockaddr/header
   construction where possible. Document the safety invariants immediately
   around the unsafe call.

## Tokio readiness and partial sends

Add a private async direct-batch sender used by `Magicsock::send_batch` only on
Linux.

1. Use the existing `Arc<UdpSocket>` and `UdpSocket::async_io` with
   `Interest::WRITABLE`. Tokio already owns registration for this socket; do
   not convert or duplicate the fd.
2. Maintain a `head` index into the original datagram slice. On a positive
   `sendmmsg` result, record TX bytes for every datagram in that sent prefix,
   advance `head`, and immediately try the remaining suffix while the socket
   is writable.
3. On `WouldBlock`, return `WouldBlock` from the `async_io` closure so Tokio
   clears readiness and waits before retrying the same suffix. Never busy-loop
   and never advance `head` on `WouldBlock`.
4. Linux reports an error only when no message from that syscall invocation
   was sent. If a non-`WouldBlock` error occurs at suffix head, preserve the
   first non-lost error, skip exactly that one datagram, and continue trying
   the later suffix. Apply `treat_as_lost_udp` to the error before deciding
   whether to retain it. This matches the scalar batch contract that one bad
   element cannot prevent later elements from being attempted.
5. Return the first retained error after every element has either been sent or
   skipped for an error. Successful prefixes remain successfully accounted
   even if a later element fails.
6. An empty batch remains the existing no-op before peer/path lookup. A
   one-element batch remains behavior-compatible with `send`.

Do not assume `sendmmsg` exposes a per-message errno. `mmsghdr.msg_len` is a
length for successfully sent messages, not an error slot.

## Magicsock integration

1. In `BestPath::Direct`, when direct paths are enabled and a UDP socket is
   present, call the Linux batch sender once for the selected path snapshot.
2. On non-Linux targets retain the current scalar ordered `send_to` loop.
3. When no UDP socket exists, retain the current per-datagram DERP fallback.
4. Leave `BestPath::Relay` scalar in this phase. Geneve framing currently
   allocates one buffer per datagram and needs a separately measured ownership
   design; mixing it into this phase obscures the direct-path result.
5. Leave `BestPath::Derp`, `BestPath::None`, discovery arming, heartbeat
   transitions, endpoint locking, and path/DERP snapshots unchanged.
6. Keep socket statistics exact: record only successfully sent datagrams and
   use the original plaintext WireGuard datagram lengths, matching the current
   direct path.

## Tests

### Platform-neutral

- Existing `send`, empty batch, heartbeat generation, DERP, relay, discovery,
  and first-error behavior tests continue to pass.
- Non-Linux compilation proves the direct path retains the scalar loop and
  does not reference Linux libc types.

### Linux

- A loopback batch of distinct datagrams arrives in exact order.
- IPv4 and IPv6 sockaddr construction preserves address, port, flow info, and
  scope ID.
- Empty and over-cap inputs are rejected without a syscall.
- A successful prefix reports its exact count and lengths for accounting.
- A test seam around the async advancement logic covers: full success,
  partial/partial/full, `WouldBlock` followed by success, a lost error at the
  head followed by suffix success, and a retained first error followed by
  suffix success. Do not add a broad socket abstraction solely for tests.
- Existing direct UDP integration test exercises the Linux batch path with
  more than one datagram.

## Validation

- `cargo fmt --check`
- `cargo test -p rustscale-magicsock`
- `cargo clippy -p rustscale-magicsock --all-targets -- -D warnings`
- `cargo check -p rustscale-magicsock --target x86_64-unknown-linux-gnu`
- `cargo check -p rustscale-magicsock --target x86_64-unknown-linux-musl`
- `RUST_TEST_THREADS=1 tools/check.sh`
- Repeat the focused same-zone direct `rs-tun,ts-tun` matrix and collect a
  Linux CPU profile. Compare against `gcp-20260713-073604` before selecting
  UDP GSO, TUN write GRO, or parallel encryption.
