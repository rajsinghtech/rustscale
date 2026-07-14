# Two-chunk borrowed WireGuard decrypt spike

## Evidence

The accepted native direct run at `bench-results/gcp-20260713-235632`
reached 1968.383/2009.813/1637.574 Mbps at P1/P10/P100.  The receiving
client profile attributed 24.20% exclusive and 28.09% inclusive CPU to
ChaCha20-Poly1305 open while total process CPU remained below one core on
average.

Two narrower experiments did not justify production changes:

- persistent per-packet workers copied ciphertext and performed one channel
  handoff per packet, reaching only 0.742x scalar throughput;
- scalar in-place BoringTun receive removed the ciphertext copy but reached
  only 1.023x scalar throughput.

Tailscale's pinned wireguard-go at
`github.com/tailscale/wireguard-go@ffb138071028/device/receive.go` hands one
borrowed `QueueInboundElementsContainer` to a persistent decrypt worker, then
performs replay validation and receive-side state updates sequentially.  It
does not split one single-peer container across workers.  RustScale therefore
needs to prove that two coarse borrowed chunks can profitably expose
single-peer AEAD parallelism without reintroducing the copy and per-packet
scheduling costs already measured.

## Phase boundary

Implement and measure an isolated BoringTun 0.7.1 data-only receive primitive.
Do not integrate it into `rustscale-wg`, magicsock, the TUN pump, filtering,
capture, or production buffer ownership in this phase.

Use a repository-owned copy of the exact BoringTun 0.7.1 source selected by
`Cargo.lock`.  Keep the semantic patch narrow enough for upstream review.
The normal scalar `Tunn` API must remain allocation- and thread-neutral.

Do not add unsafe code, export or clone session keys, bypass the rate limiter
or replay window, weaken protocol validation, create threads per packet or per
batch, or send one work message per packet.

## Required primitive

1. Add a data-only batch entry point on `Tunn`; do not expose `Session` or its
   keys to RustScale.  The entry point accepts uniquely owned mutable transport
   datagrams and returns ordered per-datagram outcomes as ranges and metadata,
   not slices tied to BoringTun scratch storage.
2. Parse and rate-limit every datagram serially before mutation.  Only valid
   established transport-data packets are eligible.  Empty, malformed,
   handshake, cookie, queued-output, wrong-index, and no-session cases remain
   on the existing scalar path or are rejected by the data-only API without
   changing scalar behavior.
3. Perform the initial replay-window quick check serially.  Capture only the
   immutable session reference, counter, mutable encrypted-body range, and
   original position needed for the parallel phase.
4. Split eligible work into two contiguous, near-equal chunks.  Execute the
   chunks on a dedicated persistent two-thread pool.  One submission per chunk
   is permitted; per-packet channels, ownership transfers, and ciphertext
   copies are forbidden.  Decrypt each encrypted body in place through the
   session's existing `ring::aead::LessSafeKey`.  Form disjoint mutable chunks
   with safe slice splitting and scoped lifetimes; `&mut [u8]` is `Send` for
   this storage, so neither `'static` lifetime extension nor raw pointers are
   necessary.
5. Treat pool construction, session establishment, packet construction,
   datagram storage, result storage, and validation storage as caller-owned
   setup outside the measured region.  Empty and one-packet batches must avoid
   parallel dispatch.
6. After both chunks finish, commit successful replay counters serially in
   original input order.  A corrupt tag never consumes its counter.  Racing
   duplicates may both authenticate but at most the first ordered commit is
   accepted.  Reverse-order, too-old, and large-gap behavior must match the
   scalar path.
7. For each accepted commit, preserve current-session selection, receive and
   data timers, IP version/length/source extraction, byte accounting, and
   packet-loss accounting (`receive_cnt`), and keepalive behavior in the same
   order as scalar `handle_data`.  A failed call may consume the mutable
   datagram, but must not expose it as plaintext.
8. The pool barrier must provide a clear happens-before edge before ordered
   commits or result inspection.  Panic, shutdown, and partial-invalid-input
   paths must return all borrowed storage and must not report an incomplete
   batch as successful.

The implementation may add a small private prepare/open/commit split to
`Session`, but the externally exercised operation belongs on `Tunn` so the
session ring cannot be mutated while workers hold immutable session borrows.
A compile-time test must prove that the scoped immutable borrow of the
`sessions` field ends before `Tunn` mutably updates `current`, timers, and
accounting; do not clone or move a session out of the ring to satisfy the
borrow checker.
A scoped call installed on a dedicated persistent pool is acceptable: the
caller may synchronously hold its `WgTunn` mutex guard while the two chunks
run, because the current scalar path already performs the same CPU work under
that guard and the scope contains no await.

## Correctness verification

- Differential scalar/one-chunk/two-chunk IPv4, IPv6, and keepalive results.
- Exact input-order results when the second chunk finishes first.
- Duplicate counters on one chunk and across the chunk boundary.
- Reverse-order counters inside the 1024-packet replay window, too-old
  counters, and a gap larger than the window.
- Corrupt tag followed by the valid same-counter packet.
- Wrong receiver index and no current session.
- Empty, one-packet, odd-sized, and 128-packet batches.
- Handshake, cookie, malformed, and empty inputs remain scalar-only.
- Session-ring and key-rotation boundaries fall back to scalar until a stable
  established data batch is eligible again.
- Worker panic/shutdown does not commit counters or leak borrowed storage.
- Existing unmodified BoringTun tests and focused `rustscale-wg` tests pass.

## Microbenchmark gate

Add an ignored deterministic release benchmark for 128 established-session
IPv4 transport packets with 1,400-byte plaintexts.  Prebuild independent
session/datagram sets for every measured round so replay protection is active
and no setup, allocation, cloning, or ciphertext copying occurs in the timed
region.  Validate every plaintext byte after timing.

Report median packets/second and bytes/second across at least 31 rounds for:

- stock scalar copy-then-open;
- one borrowed in-place chunk, to isolate dispatch and copy removal;
- two borrowed in-place chunks on the dedicated pool.

The scalar baseline is the unmodified BoringTun 0.7.1
`Session::receive_packet_data` copy-then-open behavior.  Do not move the scalar
baseline onto the new in-place primitive or otherwise narrow the measured
production delta.

Retain the spike only if two chunks reach at least 1.30x stock scalar on the
host and on a Linux N2 machine with at least four vCPUs.  Also require two
chunks to beat one borrowed chunk by at least 1.20x.  These are decrypt-only
microbenchmark gates; production Amdahl estimates are not a reason to lower
them.  Reject the spike if either gate fails, if any timed allocation or
ciphertext copy remains, or if correctness differs from scalar behavior.

Use the repository check wrappers for final validation:

```bash
tools/check.sh rustscale-wg
tools/check.sh
git diff --check
```

Run the ignored release benchmark with the exact command added by the spike
and record that command and all three medians in this document.  Do not start
a paid production TUN matrix or design production ownership changes unless the
Linux microbenchmark passes.

## Production gate after the spike

Passing the microbenchmark permits a separate production-integration phase;
it does not merge the vendored primitive automatically.  That later phase
must preserve the 128-packet burst cap, magicsock packet credits and fixed
buffer inventory, direct/DERP ordering, scalar protocol fallback, filtering,
capture-before-GRO, reply order, cancellation, TUN write error handling, and
pool recycling.  It must then pass the exact focused same-zone/direct
`rs-tun --profile --repeat 3` comparison without P100, latency, RSS, cleanup,
or correctness regressions.

## Result

Rejected on the host gate. The isolated vendored BoringTun 0.7.1 spike was
removed; no production crate, wrapper, transport, or ownership code was
changed.

Command:

```bash
cargo test --manifest-path vendor/boringtun-0.7.1/Cargo.toml --release --lib two_chunk_borrowed_decrypt_microbenchmark -- --ignored --nocapture
```

Host: MacBook Pro (Mac16,7), Apple M4 Pro (14 cores), macOS 26.5.2 / Darwin
25.5.0 arm64. The 31-round medians for 128 established IPv4 packets with
1,400-byte plaintexts were:

| Mode | Median | Packets/s | Bytes/s | Ratio |
| --- | ---: | ---: | ---: | ---: |
| Stock scalar copy-then-open | 163.459 µs | 783,070.98 | 1,096,299,377.83 | 1.000x |
| One borrowed in-place chunk | 146.708 µs | 872,481.39 | 1,221,473,948.25 | 1.114x |
| Two borrowed in-place chunks | 171.458 µs | 746,538.51 | 1,045,153,915.24 | 0.953x stock / 0.856x one |

The two-chunk result missed both required host thresholds: 1.30x versus stock
scalar and 1.20x versus one borrowed chunk. The dedicated-pool dispatch cost
was not recovered at this batch size on this host, so the spike is rejected
and no Linux N2 or production TUN measurement was started.
