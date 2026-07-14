# TUN inbound decrypt/write pipeline spike

## Evidence

The accepted same-zone direct profile at
`bench-results/gcp-20260713-235632` measured 1968.383/2009.813/1637.574
Mbps at P1/P10/P100. The receiving client averaged 76.87% CPU, peaked at
120%, and ended with 605 UDP receive-queue overflows. Its largest relevant
costs were:

- ChaCha20-Poly1305 open: 24.20% self;
- BoringTun rate limiting: 1.16% self;
- `WgTunn::decapsulate_into`: 0.74% self;
- `WgPlaintextBatch::push_copy`: 0.32% self;
- TUN `writev`: 12.98% inclusive;
- write-side checksum accumulation: 1.67% self.

Magicsock UDP receive already runs separately from the TUN pump. The missing
overlap is narrower: `collect_tun_inbound_batch` decrypts burst N completely,
then the same pump task filters, captures, sends protocol replies, and writes
that burst to the TUN before beginning burst N+1.

The previous per-packet worker and two-chunk decrypt spikes reached only
0.742x and 0.953x scalar throughput. This phase must not split a burst across
crypto workers. It tests pipeline overlap between two existing serial stages,
not faster AEAD.

Tailscale's pinned wireguard-go at
`github.com/tailscale/wireguard-go@ffb138071028` is the ordering reference,
not an equivalent scheduler. `device/receive.go:228-272` sends a peer container
to the global decryption and ordered per-peer queues. `RoutineDecryption` does
only AEAD work; `RoutineSequentialReceiver` at `receive.go:430-566` waits,
replay-validates, updates peer state, and writes to the TUN in FIFO order.

## Phase boundary

Implement a default-off TUN-mode spike that overlaps AEAD open for at most one
next established-data burst with filter/capture/reply/TUN processing for the
current burst. Do not change magicsock UDP receive, netstack mode, the filter
contract, packet formats, routing, or TUN offload logic.

Current BoringTun 0.7.1 cannot safely run full `decapsulate_into` ahead of TUN
delivery. `Session::receive_packet_data` marks the replay counter during open,
and `Tunn::handle_data` then updates the current session and receive timers;
validation updates the data timer and byte accounting. Wireguard-go's worker
does only AEAD open and leaves replay/session/timer/accounting commits to the
ordered per-peer receiver. Preserve that boundary by vendoring the exact
BoringTun 0.7.1 selected by `Cargo.lock` and adding a narrow data-only
prepare/open/commit API. Keep all scalar APIs and behavior unchanged.

Use safe Rust only. Keep exactly two reusable inbound scratch buffers after
warm-up. Do not allocate per packet, clone ciphertext, export or clone session
keys, extend channel or packet-credit limits, split a `WgReceiveBatch`, or
allow more than one burst to be opened or queued ahead of the burst being
committed to the TUN.

Select the spike with `RUSTSCALE_TUN_INBOUND_PIPELINE=1`. The existing scalar
path remains the default until the exact Linux gate passes. Parse the switch
once when the TUN pump starts; do not read the environment in the packet path.

## Required ownership and ordering

1. Keep `run_tun_pump` as the owner of outbound TUN reads, timer arbitration,
   ordered protocol commits, filtering, capture, reply I/O, and TUN writes. A
   persistent child task may preflight, prepare, and AEAD-open established
   data, but it must be joined or aborted during pump shutdown.
2. Pass whole owned burst scratch objects through bounded channels. A scratch
   object contains the ciphertext datagrams, peer runs, plaintext slots,
   aligned peer identities, and protocol replies needed by the existing
   helpers. A buffer is owned by exactly one of the pump, worker, or channel at
   any time.
3. Start with two scratch objects. One may be committed and flushed by the
   pump while the other is prepared/opened by the worker. After
   `Tun::write_batch` returns, clear all logical lengths and return that same
   storage for reuse. Warm steady state must not grow either scratch object's
   packet vectors.
4. Preserve the 128-packet cap and `take_immediate_receive_batches` rule: a
   whole next channel item that does not fit is deferred without splitting,
   releasing its credit, or being overtaken by later WireGuard input.
5. Consuming a prefetched `WgReceiveBatch` releases its channel credit
   immediately. Its pooled datagrams retain fixed-buffer inventory until the
   speculative result commits or falls back and the ciphertext is cleared.
   Only a non-fitting deferred whole `WgReceiveBatch` retains channel credit.
   Release committed/fallback ciphertext before reply I/O or a blocked TUN
   write, and retain no more than one prefetched burst's pool inventory.
6. Use the explicit FIFO state machine `EMPTY -> FILLED -> OPENING -> OPENED ->
   COMMITTING -> FILTER/CAPTURE -> REPLIES -> TUN_WRITE -> EMPTY`. Only
   `OPENING` or `OPENED` for N+1 may overlap post-open work for N. N+1 cannot
   enter `COMMITTING` until N reaches `EMPTY` after its TUN write completes.
7. Output bursts commit in input order. Within a burst, preserve direct/DERP
   order, missing-peer drop boundaries, same-peer tunnel locking, plaintext
   order, and reply order.
8. For each burst, send WireGuard protocol replies before its one TUN batch
   write. Capture every accepted packet before write-side GRO may mutate its
   buffer. Never recycle plaintext storage until the write future completes,
   including its error path.
9. Do not concurrently mutate one `WgTunn`. The worker holds a per-peer tunnel
   guard only for synchronous preflight/prepare/open, then drops it before
   publishing `OPENED`. No tunnel guard or borrow may cross a channel or await.
   The pump reacquires the guard for ordered commit. Do not hold the
   tunnels-map read lock during cryptography or I/O.
10. An opened item owns an opaque scalar-eligibility token covering session
    generation plus queued-packet/handshake-output generation, receiver/session
    identity, counter, authenticated-open outcome metadata, and its plaintext
    destination range, but no exported key or borrowed input. Quick replay
    validation happens before open. Replay marking, current-session selection,
    timers, IP validation, byte/loss accounting, and plaintext publication
    happen only during ordered commit. A bad tag never consumes a counter.
11. Preflight the complete burst without mutation before the first AEAD open.
    Handshake, cookie, malformed, empty, queued-output, wrong-index,
    no-session, key-rotation-boundary, and mixed-protocol bursts wait for the
    prior burst to reach `EMPTY` and use the scalar path. After any arbitration
    opportunity and before the first commit, rerun the complete mutation-free
    eligibility preflight. If any session or queued-output state changed,
    discard every speculative plaintext result and run the complete original
    ciphertext burst, including its required empty-datagram output loop,
    through the scalar path. The original ciphertext remains unchanged and
    owned until that decision. One-packet data bursts may use the pipeline but
    must not create a thread or allocation per packet.
12. Bound changed arbitration. At most one inbound burst may be prefetched.
    After N reaches `EMPTY`, give the outer pump loop one opportunity to
    service an already-ready outbound TUN read or timer before committing or
    falling back N+1. Sustained inbound load must not starve outbound traffic
    or timer ticks.
13. Cancellation must wake worker input, output, and scratch-recycle waits.
    Channel closure, worker panic before commit, TUN error, and daemon shutdown
    must drop all owned datagrams and permits exactly once. Make ordered commit
    synchronous, non-awaiting, and non-panicking by construction after all
    fallible validation. An unexpected panic during commit is fatal because
    replay/timer/accounting mutations cannot be rolled back transactionally.

The implementation may split the current `InboundBatchScratch` into clearer
job/result types if that makes ownership explicit. Refactor collection only as
needed to place preflight/prepare/open in the worker and every protocol commit
in the pump. Reuse `filter_tun_inbound_batch` and `flush_inbound_burst` rather
than duplicating their packet logic.

## Required BoringTun split

Keep the vendor patch confined to BoringTun's receive data path in
`src/noise/session.rs` and `src/noise/mod.rs`. The exact public names may follow
the crate's conventions, but the semantic split is mandatory:

1. **Preflight/prepare:** prove every item in the complete burst is eligible
   established transport data and that queued scalar output is absent. Parse
   and rate-check each datagram, resolve its session slot and receiver index,
   extract its counter, capture an opaque scalar-eligibility token covering the
   receive session and queued-packet/handshake-output state, and run the
   existing quick replay-window check. Do not mark replay state, tick timers,
   select a current session, or update accounting.
2. **Open:** in one synchronous non-awaiting scope, use the resolved session's
   existing `ring::aead::LessSafeKey` to copy-then-open into caller-owned
   destination storage. Consume every borrowed session and encrypted-input
   value before returning an owned authenticated outcome containing the
   scalar-eligibility token, session identity, counter, and plaintext
   length/range. Do not expose or clone the key and do not commit protocol
   state. A prepared borrowed value must never be stored self-referentially in
   the owning burst or sent through a channel.
3. **Commit:** rerun complete mutation-free eligibility and validate every
   opaque token after the pump reacquires the tunnel. If the receive session,
   queued packets, or handshake-output state changed, return a stale-burst
   outcome without mutation so the caller can discard speculative plaintext
   and use scalar decapsulation plus its empty-datagram output loop on the
   retained ciphertext. Otherwise mark replay counters,
   update `current`, tick `TimeLastPacketReceived`, validate/truncate IPv4 or
   IPv6 plaintext, tick `TimeLastDataPacketReceived`, and update `rx_bytes` in
   the same per-packet order as the scalar path. Keepalive and every error must
   match scalar `TunnResult` behavior.

The generation token, retained ciphertext, and all-or-scalar fallback preserve
behavior if the tunnel changes between open and commit. Normal `Tunn::new`,
scalar `decapsulate`, and callers outside this spike remain allocation- and
thread-neutral. Add focused differential tests inside the vendored crate
before integrating the split into `rustscale-wg` or the TUN pump.

## Profile bound and retain gate

This phase overlaps stages; it does not remove their CPU work. From the
accepted receiver profile, the known prepare/open cost is at least 25.36%
(24.20 AEAD + 1.16 rate limiting), while the known post-open TUN/checksum cost
is represented by at least 14.65% of named samples (12.98 inclusive TUN write
+ 1.67 checksum self). Using only those named samples gives an illustrative
ideal factor:

```text
illustrative speedup = 1 / (1 - 0.1465) = 1.17165x
2009.813 Mbps P10 * 1.17165 = 2354.8 Mbps
```

These sampled symbols omit filter, wrapper, scheduling, capture, and reply
work and are not wall-stage durations. The factor is neither a strict ceiling
nor a forecast. Channel wakeups, imbalance, fallback, and periods without a
queued next burst reduce realized overlap. This phase alone is not expected
to close the complete 2507 Mbps Tailscale gap.

Do not use a crypto-only benchmark as an acceptance proxy. After deterministic
tests pass, run five paired, alternating scalar/pipeline measurements on the
same VMs with exact same-zone direct provenance and `--profile`. Rebaseline on
the candidate's actual parent commit; historical absolute numbers are context,
not acceptance gates.

For each parallelism, define the paired result as the median of the five
candidate/baseline ratios, with each pair run consecutively on the same VMs.
Compare CPU efficiency, RSS, and overflow using the same five paired parent
runs, not a historical absolute. Retain the spike only if all of these hold:

- paired-median P1 and P10 throughput each improve by at least 1.05x;
- P100 throughput does not regress by more than 2%;
- p50, p95, and p99 latency do not regress by more than 5%;
- normalized client CPU percent per Mbps does not exceed 1.03x baseline;
- peak and average RSS grow by no more than 1 MiB;
- UDP receive-queue overflow and packet/pool overflow counters do not worsen;
- direct-path classification, cleanup, and all correctness tests remain clean.

If the gate passes, remove the environment switch and make the bounded path
the default in the same reviewed phase. If it fails, remove the pipeline code
and record the measured scalar/pipeline results here.

## Correctness verification

- A deterministic fake TUN blocks the write for burst N while proving the
  worker reaches `OPENED` for N+1, then proves N+1 cannot mark replay state,
  update timers/accounting, or publish plaintext until N's write completes.
- No next burst available: behavior and output match the scalar path without
  waiting for speculative work.
- A full 128-packet burst followed by another whole batch remains ordered and
  bounded; a non-fitting batch is deferred intact.
- Mixed direct/DERP inputs, alternating peers, missing peers, handshake
  replies, keepalives, malformed packets, and decrypt failures match scalar
  results and reply order.
- Whole-burst preflight proves that a scalar-only item at the tail prevents
  every earlier data item from opening; a session or queued-output generation
  becoming stale after open discards all speculative results and produces
  byte-identical scalar output and replies.
- Duplicate counters in one burst and across the slot boundary, reverse-order
  counters within the replay window, too-old and large-gap counters, a corrupt
  tag followed by valid same-counter data, and session/key rotation boundaries
  match scalar commit behavior.
- Filter drops compact plaintext and peer identities stably. Capture observes
  accepted pre-GRO bytes. A write-side mutating fake TUN cannot corrupt the
  next reuse.
- A ready outbound TUN read and an expired timer are serviced under sustained
  inbound load; neither starves behind the prefetched burst.
- Cancellation while waiting on worker input, worker output, buffer recycle,
  tunnel mutex, reply send, and TUN write terminates without leaked tasks or
  permits.
- Injected worker panic before commit and closed-channel tests fail closed
  without writing a partial burst. Commit contains no injected panic test; an
  unexpected commit panic is process-fatal rather than rollback-safe.
- Channel-credit tests prove consuming a `WgReceiveBatch` releases its channel
  credit while pooled ciphertext retains fixed-buffer inventory until drop;
  the two-slot path never retains more than its documented bounded inventory.
- Scalar and pipeline modes pass the existing TUN pump and end-to-end tests.

Run the repository wrappers before any GCP measurement:

```bash
tools/check.sh rustscale-tsnet
tools/check.sh
git diff --check
```
