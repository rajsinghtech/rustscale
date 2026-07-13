# Phase: Linux UDP GRO receive re-enable

## Evidence

The paired same-zone direct run at `bench-results/gcp-20260713-152623`
measured Rustscale at 433.82, 386.55, and 648.67 Mbps median throughput for
P1/P10/P100. Tailscale measured 2,145.68, 2,308.67, and 1,508.09 Mbps on the
same VM pair. Rustscale retained lower p50 latency, RSS, CPU, and binary size,
but the receiver remains the throughput bottleneck:

- receiver profile: 816 samples and 4.10 seconds task clock;
- sender profile: 494 samples and 2.48 seconds task clock;
- receiver `recvmmsg`: 16.54% inherited;
- receiver TUN `writev`: 12.62% inherited;
- receiver ChaCha20-Poly1305 open: 11.03% self.

The first UDP GRO implementation at `791bfe0` collapsed direct throughput to
about 0.05 Mbps and was removed by the recvmmsg remediation. The failure now
has a concrete ABI explanation:

1. Linux declares the UDP GRO receive `gso_size` as `int` and emits it with
   `put_cmsg(..., UDP_GRO, sizeof(gso_size), &gso_size)`, producing four bytes
   of control-message data.
2. Rustscale allocated `CMSG_SPACE(2)` and required the UDP GRO data length to
   equal two bytes. On normal Linux ABIs, alignment makes `CMSG_SPACE(2)` and
   `CMSG_SPACE(4)` equal, so the deterministic failure was the exact-length
   parser rejecting the kernel's four-byte payload. `MSG_CTRUNC` is an
   additional possibility only on an ABI where that storage is insufficient.
3. The receive task atomically discarded the already-consumed invalid batch
   and left GRO enabled, repeating the loss.
4. Tailscale accepts at least two bytes and reads the native-endian `u16`
   prefix from the Linux `int`. That handles the little-endian Linux benchmark
   hosts; Rustscale can parse the native `int` directly and remain correct on
   big-endian Linux too.

Authoritative references:

- Linux `include/linux/udp.h`, `udp_cmsg_recv`;
- `../tailscale/net/batching/conn_linux.go`, `ReadBatch`,
  `splitCoalescedMessages`, and `getGSOSizeFromControl`;
- Rustscale commit `791bfe0`, `ReceiveBatch` and `gro_size`;
- current Rustscale Linux plain-`recvmmsg` implementation in
  `crates/magicsock/src/udp_batch.rs`.

## Scope

Re-enable UDP GRO only for the current Linux direct UDP receive task. Preserve
the current plain `recvmmsg` implementation as the runtime fallback. Do not
change send batching/GSO, WireGuard, disco, Geneve, DERP, path selection,
accounting, TUN GRO, non-Linux behavior, or public APIs.

Do not restore the old implementation wholesale. Port only the bounded receive
layout after correcting the kernel ABI and adding a runtime circuit breaker.

## Kernel ABI

1. Allocate control storage using ABI-derived alignment and enough capacity
   for both `CMSG_SPACE(size_of::<libc::c_int>())` for UDP GRO and
   `CMSG_SPACE(size_of::<u32>())` for `SO_RXQ_OVFL` on every GRO receive slot.
2. Submit the complete control capacity in `msg_controllen` before every
   `recvmmsg` call and reset all kernel-written lengths and flags.
3. Parse control messages using their reported `cmsg_len`; ignore unrelated
   well-formed control messages.
4. For `SOL_UDP/UDP_GRO`, parse the four-byte native-endian `libc::c_int`
   emitted by Linux, require it to fit a nonzero `u16`, and use that as the
   segment size. An exact two-byte native-endian `u16` may be accepted for a
   compatible synthetic/external source. Do not read the first `u16` of a
   four-byte integer because that is incorrect on big-endian Linux.
5. Treat `MSG_TRUNC`, `MSG_CTRUNC`, malformed headers, impossible padding,
   duplicate UDP GRO messages, invalid sources, and split overflow as a GRO
   batch error. Never dispatch a partial logical prefix.

## Receive layout

Mirror the current Tailscale bounded layout while retaining Rust ownership:

1. Keep the logical batch cap at 128.
2. When GRO is active, submit two 65,536-byte tail messages to `recvmmsg` and
   split their logical datagrams into reusable head buffers.
3. A message without a UDP GRO control message remains one logical datagram.
4. Split a coalesced message into `ceil(total_len / segment_size)` datagrams.
   All but the last must have the advertised segment size; the last may be
   smaller.
5. Preserve source address, order, zero-length plain datagrams, and per-logical
   packet byte accounting.
6. Keep scratch storage task-owned and reusable. Do not allocate per received
   datagram or retain borrowed packet views across an await.
7. Enable `SO_RXQ_OVFL` best-effort and parse its cumulative native-endian
   `u32` from any well-formed control-message position. Track the wrapping
   delta so a two-message GRO read that receives mostly non-coalesced traffic
   cannot hide kernel queue loss.

## Circuit breaker

GRO must never be able to cause a persistent receive-drop loop again.

1. If a GRO-enabled receive returns a control, truncation, source, size, or
   split error, discard only that consumed batch, disable `UDP_GRO` on the
   socket, reset the reusable batch to plain mode, and continue with
   `recvmmsg`.
2. If disabling GRO fails, terminate the receive task with a clear error rather
   than consume opaque coalesced payloads through the plain path.
3. `ENOSYS` retains the current scalar Tokio fallback, but GRO must be disabled
   successfully before entering it.
4. Emit one bounded, observable diagnostic when GRO is enabled, unavailable,
   or disabled, including the circuit-break reason. A disable failure must be
   recorded before its detached receive task terminates. Do not log per packet
   or retry GRO during the lifetime of that socket.
5. Add a startup kill switch, `RUSTSCALE_DISABLE_UDP_GRO`, that prevents GRO
   enablement without disabling plain `recvmmsg`. Read it once when the socket
   receive task is created; do not add a per-packet environment lookup.

## Observability

Add low-cost counters for GRO kernel messages, logical datagrams produced,
coalesced messages, parse/truncation failures, permanent fallbacks, and RX queue
overflow deltas. Counters must not allocate or lock per datagram. They are
diagnostic evidence for the live canary, not a new public metrics API. The
benchmark must be able to establish that the circuit-break count stayed zero.

## Tests

Retain all current plain-`recvmmsg` tests and add:

- a parser test accepting the real four-byte Linux UDP GRO payload while
  reading it as a native-endian `c_int`, plus a big-endian reasoning fixture or
  platform-neutral helper test that prevents first-`u16` parsing;
- rejection tests for zero, shorter-than-two, malformed, duplicate, truncated,
  and overflowing control messages;
- two tail messages splitting into one ordered logical batch, including a
  smaller final segment and unrelated well-formed control data;
- UDP GRO and RXQ overflow control messages in both orders, including wrapping
  overflow-counter delta behavior;
- reuse tests proving kernel-written flags, lengths, sources, and control bytes
  cannot leak into the next receive;
- circuit-breaker tests proving the first GRO parse/truncation failure disables
  GRO once and the next plain `recvmmsg` batch is delivered;
- disable-failure coverage proving the task cannot continue through a plain
  reader while GRO remains active;
- kill-switch coverage proving GRO is not enabled while plain `recvmmsg`
  remains active.

Most importantly, run an end-to-end test on Linux, not a fabricated control
buffer: enable `UDP_GRO` on the receiver, send equal UDP segments plus a smaller
tail using `UDP_SEGMENT`, receive with the production batch helper, and assert
the exact original datagrams and order. When `UDP_GRO` enablement succeeds,
this test must not skip. Record or assert that the kernel-returned GRO control
data is at least two bytes and is accepted when it is four bytes.

On the benchmark GCP image, both UDP GRO enablement and the UDP GSO probe must
succeed or phase validation fails. Assert that the returned GRO control payload
is exactly `size_of::<libc::c_int>()` there and feed it through the production
parser. General Linux CI may skip only after recording an explicit unsupported
capability result. Also run a burst of uncoalesced small datagrams to prove the
two-tail-message layout does not create persistent loss when GRO cannot merge
the traffic.

## Validation

- `cargo fmt --all --check`
- `RUST_TEST_THREADS=1 cargo test -p rustscale-magicsock`
- `cargo clippy -p rustscale-magicsock --all-targets -- -D warnings`
- `cargo check -p rustscale-magicsock --target x86_64-unknown-linux-gnu`
- `cargo check -p rustscale-magicsock --target x86_64-unknown-linux-musl`
- `RUST_TEST_THREADS=1 tools/check.sh`
- Run the real GRO/GSO loopback test on the same GCP Linux image used by the
  production benchmark before merging.
- `git diff --check`

After merge, run focused same-zone direct `rs-tun --profile --repeat 3` and
compare raw samples, medians, latency, RSS, CPU, total receiver task clock,
`recvmmsg`, TUN `writev`, and ChaCha open against
`gcp-20260713-152623`. Revert or leave GRO disabled if any parallelism has a
repeatable material throughput regression, direct-path reliability declines,
the circuit breaker activates, or RSS grows by more than 2 MiB without a
commensurate throughput gain.

Acceptance also requires circuit-break count zero, no unexplained RX queue
overflow delta, no persistent packet loss in the coalesced or uncoalesced
canary, and recorded GRO utilization as logical datagrams per kernel message
or `recvmmsg` calls per logical datagram. The expected extra GRO scratch is
about 128 KiB for the task, well below the 2 MiB guardrail; report the observed
RSS change rather than treating that estimate as a waiver.

## Non-goals

- changing the current TCP GRO TUN write path;
- io_uring, AF_XDP, zero-copy UDP, or additional receive tasks;
- parallel WireGuard decryption;
- raising the 128-packet logical batch cap;
- changing benchmark workload or result schema;
- treating a lower profile percentage alone as proof of improvement.
