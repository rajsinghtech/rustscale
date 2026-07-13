# Phase: Linux TUN TCP GRO batch writes

## Evidence

The dual-endpoint profile in
`bench-results/gcp-20260713-132051/same-zone/direct/profile/` captured the
normal `rs-tun` reverse P10 workload on both VMs. On the receiving client,
the TUN `writev` subtree accounts for 31.93% of inherited samples, ahead of
UDP receive (10.09%) and WireGuard open (9.94%). The inbound pump already
drains immediately available WireGuard datagrams, but
`process_tun_inbound` awaits `Tun::write_packet` for every decrypted packet.
Linux therefore injects every plain TCP segment as a separate zero-header
VNET frame and syscall.

Current Tailscale uses the write-side TCP GRO implementation in the exact
wireguard-go module pinned by its `go.mod`:

- `/Users/rajsingh/go/pkg/mod/github.com/tailscale/wireguard-go@v0.0.0-20260611001507-ffb138071028/tun/tun_linux.go`, `NativeTun.Write`
- the same module's `tun/offload_linux.go`, especially `tcpFlowKey`,
  `tcpGROTable`, `tcpGROItem`, `tcpPacketsCanCoalesce`,
  `coalesceTCPPackets`, `tcpGRO`, `applyTCPCoalesceAccounting`,
  `packetIsGROCandidate`, and `handleGRO`
- the same module's `tun/offload_linux_test.go`

Port the TCP4/TCP6 behavior faithfully. Do not substitute a contiguous-only
coalescer: wireguard-go deliberately joins interleaved flows and supports
prepend plus append for out-of-order segments.

## Scope

Add one semantic TUN batch-write boundary, accumulate one bounded decrypted
burst in the TUN pump, and implement TCP4/TCP6 GRO for Linux VNET writes.
Keep scalar behavior on macOS, mocks, non-VNET Linux, and non-TCP packets.

Do not add UDP GRO, UDP socket GRO, io_uring, parallel WireGuard decryption,
new dependencies, a new benchmark result schema, or changes to path
selection. The prior UDP GRO receive experiment collapsed a direct run to
approximately 0.05 Mbps and is not part of this phase.

## TUN batch API

1. Add an object-safe async `Tun::write_batch` accepting a mutable slice of
   owned packet buffers. The mutable contract must document that an OS-backed
   implementation may rewrite transport/offload headers while the call is in
   progress. An empty batch is a successful no-op.
2. Provide a default scalar implementation that calls `write_packet` in
   order. Preserve the existing single-packet API without allocating or
   copying its packet merely to reach the batch API.
3. The default implementation should attempt the complete batch and return
   the first I/O error after later packets have also been attempted, matching
   wireguard-go's best-effort vector behavior as closely as `io::Result`
   permits.
4. Mock TUN observation, Darwin framing, and all existing `Tun`
   implementations must retain their current externally visible packet order
   and bytes.

## Inbound pump boundary

1. Replace the per-datagram `process_tun_inbound`/`write_packet` sequence in
   `run_tun_pump` with reusable inbound scratch containing plaintext packet
   buffers and pending WireGuard replies. Process the first received datagram
   and at most 127 immediately available datagrams, matching
   `TunPacketBatch::MAX_PACKETS == 128`; leave additional channel entries for
   the next scheduler turn.
2. For every datagram, preserve peer lookup, tunnel locking, decapsulation,
   inbound filter accounting, packet-drop accounting, and capture semantics.
   Only accepted plaintext enters the TUN batch. Capture the original plain
   packet before Linux is allowed to mutate its headers for GRO.
3. Drop every tunnel/filter guard before async TUN or magicsock I/O. Call
   `tun.write_batch` once for the accepted plaintext burst. An empty plaintext
   burst performs no TUN write.
4. Retain and send all decapsulation replies with their peer identities after
   the batch write, in input and reply order. A TUN write error must not
   suppress required WireGuard protocol replies, and one reply send error
   must not suppress later replies.
5. Reuse vector capacity between loop iterations. Do not add a steady-state
   clone of plaintext or ciphertext buffers.

## TCP GRO planner

Keep the pure parsing, checksum, flow-table, and output-plan logic in
`crates/tun/src/offload.rs` so it is unit-tested on every development host.
The plan must refer to packet indexes and payload ranges rather than retain
self-referential Rust borrows. Linux may materialize `libc::iovec` values from
the plan immediately before each syscall.

1. Preserve write order by assigning every scalar packet or new GRO item an
   output index at its first insertion. A coalesced segment contributes a
   payload fragment to that output and does not create another output.
2. Key TCP flows by source address, destination address, source port,
   destination port, received ACK value, and IPv4/IPv6. A flow can contain
   multiple sequence-disjoint items. Search items in reverse insertion order
   and never merge items with each other after insertion, matching
   wireguard-go.
3. Candidate rules must match `packetIsGROCandidate` and `tcpGRO`:
   - IPv4 requires IHL 5, TCP protocol, at least 40 bytes, exact total length,
     and no fragmentation; IPv4 options are scalar fallback.
   - IPv6 requires TCP as the immediate next header, at least 60 bytes, the
     fixed 40-byte header, and exact payload length; extension headers are
     scalar fallback.
   - TCP data offset must be 20 through 60 bytes and fit the packet.
   - Only ACK or ACK|PSH segments with nonempty payload are candidates.
   - Malformed, oversized, zero-payload, SYN/FIN/RST/URG, fragment, and other
     protocol packets remain separate scalar VNET writes rather than failing
     the whole batch.
4. Coalescing compatibility must match `tcpPacketsCanCoalesce`:
   - equal TCP header length and byte-identical TCP options;
   - equal IPv4 ToS, DF/reserved flags, and TTL, or equal IPv6 traffic class
     and hop limit;
   - total coalesced IP length no greater than `u16::MAX`;
   - no more than Linux `UIO_MAXIOV`/1024 scatter-gather fragments including
     virtio header and head packet;
   - adjacent sequence numbers with wraparound behavior matching Go `uint32`;
   - append only when the current tail has no PSH, no prior short tail, and
     the new segment is not larger than the established GSO size;
   - prepend only when the new segment has no PSH, is not smaller than the
     established GSO size, and does not put multiple smaller segments behind
     a newly larger head.
5. Validate the original head checksum lazily on the first attempted merge
   and every incoming segment checksum before merging. An invalid head stays
   as its original scalar output and is removed from the flow table. An
   invalid incoming packet stays scalar and is not inserted as a candidate.
6. Append moves only the incoming payload range and propagates PSH to the
   head. Prepend replaces the head packet, inserts the old head payload as the
   first fragment, and updates the starting sequence. Track accumulated
   payload length and the maximum GSO size exactly as wireguard-go does.

## Coalesced VNET accounting

For an output with more than one TCP segment:

1. Emit the native-endian 10-byte `virtio_net_hdr` with
   `VIRTIO_NET_HDR_F_NEEDS_CSUM`, `GSO_TCPV4` or `GSO_TCPV6`, `hdr_len` equal
   to IP plus TCP header length, `gso_size` from the GRO item, `csum_start`
   equal to IP header length, and TCP `csum_offset` 16.
2. For IPv4, rewrite total length, zero and recompute the IPv4 header
   checksum. For IPv6, rewrite payload length. Do not rewrite scalar packets.
3. Replace the head TCP checksum with the non-complemented TCP pseudo-header
   checksum seed for the new transport length. The kernel completes it
   because `NEEDS_CSUM` is set. Use the existing checksum/pseudo-header
   primitives and preserve their byte-order behavior.
4. A scalar VNET output keeps the all-zero virtio header and complete original
   packet exactly as today.

## Linux write execution

1. Add one write-operation mutex/scratch owner to `TunDevice`, equivalent to
   wireguard-go's `writeOpMu`, because flow tables, headers, output plans, and
   packet mutation cannot be shared by overlapping `&self` calls. Reset all
   logical state after success or error while retaining allocations.
2. When VNET is unavailable, use the scalar batch fallback. When VNET is
   active, build the TCP-only plan and issue one `writev` per planned output,
   in plan order. UDP and every other noncandidate remain individual outputs.
3. Retry `EINTR` immediately. Route `EAGAIN`/`WouldBlock` back through
   `AsyncFd` readiness and retry without rebuilding or losing the plan.
   Convert `EBADF` consistently with the existing device behavior.
4. Treat a short frame write as an error; never retry a suffix as a new TUN
   frame. Attempt later planned outputs and return the first error after the
   batch, unless the async descriptor itself is closed and cannot continue.
5. Check total frame length, iovec count, and C integer conversions before
   the syscall. No unsafe slice may outlive the locked packets/header scratch
   used to construct it.

## Tests

Port representative TCP portions of wireguard-go
`Test_handleGRO` and `Test_packetIsGROCandidate` into platform-neutral Rust
tests. Cover at least:

- interleaved TCP4/TCP6 flows and equal-flow merging;
- ACK as part of the flow key;
- PSH ending a group and a following group beginning independently;
- out-of-order prepend then append;
- invalid original-head and invalid incoming TCP checksums;
- unequal IPv4 TTL, ToS, DF/reserved flags, and fragments;
- unequal IPv6 hop limit and traffic class;
- unequal TCP header/options, zero payload, unsupported flags, malformed
  lengths/data offsets, IPv4 options, IPv6 extension headers, and oversized
  aggregate fallback;
- smaller final segment, rejected larger append, valid larger prepend, and
  scatter-gather boundary behavior;
- exact TCP4/TCP6 virtio header bytes, IP lengths/checksums, pseudo-header
  checksum seed, fragment ranges, output count, and reset/reuse behavior;
- mixed TCP and UDP input proving TCP coalesces while UDP remains scalar and
  byte-identical;
- default `Tun::write_batch` ordering, best-effort errors, and empty input;
- TUN pump burst acceptance/filter/drop/capture behavior, 128-datagram cap,
  one batch call, retained reply ordering, and replies surviving a TUN write
  failure;
- Linux syscall helpers for full/short writes, `EINTR`, `EAGAIN`, invalid
  iovec limits, and scalar VNET framing without requiring privileged TUN.

Existing single-packet, read-batch, VNET split, mock TUN, pump, direct, DERP,
relay, filter, and capture tests must remain green.

## Validation

1. Run focused checks through `tools/check.sh tun` and
   `tools/check.sh tsnet` while iterating.
2. Run `RUST_TEST_THREADS=1 tools/check.sh` for the complete workspace.
3. Run `git diff --check` and inspect the unsafe syscall diff separately.
4. After merge, run:

   ```bash
   set -a
   source .secrets/tailscale.env
   set +a
   tools/bench/gcp/run-matrix.sh \
     --topology same-zone --path direct --config rs-tun --profile
   ```

5. Require successful CLI `ping --until-direct`, complete VM/tailnet cleanup,
   and nonempty server/client profiles. Compare P1/P10/P100 throughput,
   latency, RSS, CPU, and receiver `writev` inherited cost against
   `gcp-20260713-132051`. A correctness pass is not evidence of a performance
   win; retain or revise the phase based on the live result.
