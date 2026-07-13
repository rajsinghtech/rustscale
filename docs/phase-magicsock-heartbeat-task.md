# Phase: Coalesce magicsock peer heartbeat tasks

## Evidence

The same-zone direct Linux benchmark after VNET/GSO TUN reads reached 385.30,
507.76, and 318.95 Mbps at 1, 10, and 100 iperf streams. Tailscale reached
1,899.41, 2,075.20, and 1,400.72 Mbps on the same retained VM pair. Rustscale
already leads p50 latency (1.38 ms versus 2.09 ms) and memory (13.5 MiB versus
47.8 MiB), so this phase targets CPU and scheduler work without changing wire
or path-selection behavior.

`Magicsock::send` calls `arm_heartbeat` for every WireGuard datagram.
`arm_heartbeat` unconditionally spawns a Tokio task, replaces the peer's map
entry, and aborts the previous task. At about 500 Mbps with MTU-sized packets,
that is on the order of 50,000 spawn/replace/abort cycles per second. It also
resets the task's initial three-second sleep on every packet, so sustained
traffic can prevent the documented heartbeat from firing.

Relevant code:

- `crates/magicsock/src/lib.rs`: `Magicsock::send`, `arm_heartbeat`,
  `peer_background_task`, `abort_background_tasks`, and endpoint removal.
- `crates/magicsock/src/endpoint.rs`: TX activity, idle state, heartbeat, and
  UDP-lifetime cliff state.

## Scope

Arm the existing per-peer background task only when TX changes the endpoint
from inactive to active. Do not add a new task record, wake channel,
TUN/WireGuard batch API, `sendmmsg`, UDP GSO, change heartbeat or lifetime
constants, or alter direct/DERP/peer-relay selection in this phase.

## Required behavior

1. Change endpoint TX accounting to report whether the endpoint was inactive
   immediately before this send. Compute the transition using the same
   `SESSION_ACTIVE_TIMEOUT` and timestamp as the activity update, then always
   store the new `last_send_ext` value.
2. In `Magicsock::send`, capture that transition under the existing endpoints
   write lock. Call `arm_heartbeat` only when it is true. A missing endpoint
   must retain the existing `PeerNotFound` behavior during path lookup.
3. The first send and the first send after at least 45 seconds of TX inactivity
   arm the existing task. Sends during an active session only refresh the
   timestamp; they must not spawn, replace, or abort a task.
4. Heartbeat cadence is therefore independent of ordinary TX. Continuous
   traffic must not reset the initial or recurring three-second timer.
5. A send after the task entered the idle UDP-lifetime phase is an
   inactive-to-active transition. Preserve the current behavior: re-arming
   aborts/replaces that idle task, and the new task resumes heartbeat mode.
6. Peer removal and network-link changes retain the existing task termination
   and `abort_background_tasks` semantics. Link reset clears activity, so the
   next send re-arms normally.
7. Keep locks out of `.await` regions exactly as the current code does. Do not
   widen this phase into background-task map lifecycle changes.

## Tests

Use paused Tokio time and a test-only spawn/generation observation where
needed:

- Endpoint activity reports true for no/stale TX, false for recent TX, and
  refreshes `last_send_ext` in every case, including the timeout boundary.
- Many sends less than three seconds apart keep one peer task/generation, and
  a heartbeat still fires when the independent three-second deadline advances.
- TX after idle re-arms and aborts/replaces the lifetime-probe task.
- Link reset makes the next TX report an inactive-to-active transition.
- `abort_background_tasks` drains and aborts all records.
- Existing direct, DERP, relay, send-error, heartbeat, and UDP-lifetime tests
  remain unchanged and pass.

## Validation

- `cargo fmt --check`
- `cargo test -p rustscale-magicsock`
- `cargo clippy -p rustscale-magicsock --all-targets -- -D warnings`
- `RUST_TEST_THREADS=1 tools/check.sh`
- Repeat the same-zone direct `rs-tun` benchmark before starting route,
  WireGuard, magicsock, or UDP syscall batching.

## Deferred batching sequence

After measuring this phase, consume each `TunPacketBatch` as contiguous
same-peer runs. Preserve packet order; hold route and tunnel lookup locks once
per run, encapsulate in order, then use a `Magicsock::send_batch` API. Only
after that API exists should Linux direct UDP add `sendmmsg`, including partial
send advancement, writable readiness, accounting for only the sent prefix,
and scalar fallback for errors. DERP, relay, and non-Linux paths remain scalar
until separately measured.
