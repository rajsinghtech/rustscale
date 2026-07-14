# In-place WireGuard receive spike

## Evidence

The accepted Linux direct run at `bench-results/gcp-20260713-235632`
identifies ChaCha20-Poly1305 receive processing as the largest serialized
receiver cost. BoringTun 0.7.1 `Session::receive_packet_data` copies the entire
ciphertext body into `dst`, then immediately calls `ring::aead::LessSafeKey`
`open_in_place` on that copy.

RustScale uniquely owns every inbound `WgCiphertext` until decapsulation.
Linux direct packets own detached fixed receive buffers; DERP/scalar packets
own a `Vec` and a visible range. This makes an in-place BoringTun receive
primitive possible without shared mutation or key export.

The previous persistent-worker spike failed its gate: two workers reached only
0.742x scalar because it copied ciphertext into worker storage and sent one
channel message per packet. Do not add concurrency in this phase.

## Phase boundary

Implement and measure only the smallest safe BoringTun 0.7.1 in-place data
receive primitive. Do not change production magicsock, tsnet, TUN, filtering,
capture, or buffer-pool code unless the isolated primitive first demonstrates
a material release-mode gain.

Use a repository-owned copy of the exact BoringTun 0.7.1 crate for the spike.
Keep the semantic patch narrow and suitable for upstream review. Do not use
unsafe code, clone/export session keys, bypass replay checks, or alter scalar
`Tunn::decapsulate` behavior.

## Required API behavior

1. Accept one mutable, uniquely owned WireGuard transport datagram.
2. Parse and rate-limit before mutation. Handshake, cookie, malformed, empty,
   and queued-output behavior remains on the existing scalar API.
3. For an established data packet, authenticate and decrypt the encrypted body
   directly within its existing datagram storage. Return the plaintext range;
   do not shift bytes solely to make the range start at zero.
4. Preserve receiver-index checks, quick replay rejection, authenticated-open
   failure behavior, replay marking, current-session selection, timers,
   plaintext validation, and byte/packet accounting in the same order as the
   scalar path.
5. A corrupt tag never consumes its counter. Duplicate and too-old counters
   match scalar behavior. A failed call may mutate ciphertext bytes because
   AEAD APIs do not promise restoration; callers must treat the input as
   consumed.
6. Keep normal `Tunn::new` and scalar callers allocation- and thread-neutral.

## Microbenchmark gate

Add an ignored deterministic release benchmark for 128 established-session
IPv4 packets with 1,400-byte payloads. Recreate tunnel/session state for every
measured round so replay protection is exercised. Preallocate all datagrams
and validation storage outside the timed region.

Report packets/second and bytes/second for:

- scalar copy-then-open using the existing BoringTun API;
- in-place receive using the new primitive.

Validate every plaintext byte after timing. Use enough rounds and report a
median so sub-millisecond timer noise cannot determine the result. Require at
least 1.10x in-place throughput on macOS to retain the spike for a Linux
microbenchmark. Production integration still requires a Linux microbenchmark
gain and the exact GCP acceptance run; a macOS result alone is insufficient.

## Correctness verification

- Differential scalar/in-place IPv4, IPv6, and keepalive results.
- Duplicate, reverse-order within the replay window, too-old, large-gap, bad
  tag followed by the valid same-counter packet, wrong receiver index, and no
  current session.
- Handshake/cookie/malformed/empty inputs are rejected from the data-only API
  without changing scalar behavior.
- Session-ring/key-rotation boundaries remain scalar-only until established
  data is eligible again.
- Focused BoringTun and `rustscale-wg` tests, formatting, strict clippy, and
  `git diff --check` pass.

## Production gate

If and only if both host and Linux microbenchmarks pass, design owned plaintext
storage that can carry an interior mutable range through filtering, capture,
Linux GRO planning, TUN write, cancellation, and pool recycling. Preserve the
128-packet burst cap, packet credits, fixed-buffer inventory, stable order,
reply order, and capture-before-GRO contract. Then run the exact same-zone,
direct `rs-tun --profile --repeat 3` workflow and reject any material P100,
latency, RSS, or correctness regression.

## Result

Rejected on the macOS host gate on 2026-07-14. The final 31-round release
median measured 992,248 packets/second (1,389,147,287 bytes/second) through
the stock scalar copy-then-open path and 1,015,204 packets/second
(1,421,285,978 bytes/second) through the in-place path: a 1.023x speedup,
below the required 1.10x threshold.

The focused differential and replay tests passed, but the small throughput
gain does not justify vendoring and maintaining a patched BoringTun. No
production magicsock, tsnet, TUN, filtering, capture, or pool code was changed.
The next experiment should amortize synchronization and scheduling across two
borrowed packet chunks while retaining scalar handling at protocol boundaries.
