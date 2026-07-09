# Phase 10d — Event-driven netstack (kill the latency gap)

## Problem

rustscale p50 latency is 10.1ms vs tailscaled's 257us — a 40x gap. Root cause:
the smoltcp poll loop runs on a fixed 2ms `tokio::time::interval`, and the
tsnet data pump uses a fixed 5ms interval. Every packet round-trip accumulates
timer-delay latency (up to 2ms + 5ms per hop = ~14ms RTT worst case).

## Solution

Make the stack event-driven: wake on packet arrival / app I/O / socket
creation, not on a timer. Use smoltcp's own `poll_delay()` for the fallback
timer (it knows exactly when retransmits/timers are due).

### Changes

#### 1. `crates/netstack/src/lib.rs` — event-driven poll loop

- **Remove** `POLL_INTERVAL` const and the `tokio::time::interval`.
- **Add** `tx_notify: Arc<Notify>` to `Netstack` — fires when smoltcp produces
  outbound packets (so the tsnet pump can wake immediately).
- **Add** `notify: Arc<Notify>` to `NetstackStream` — so app `poll_write` and
  `poll_read` can wake the poll loop immediately.
- **Update** `make_stream_and_conn` to pass the poll-loop `Notify` into the
  stream.
- **poll_loop select!**: replace `interval.tick()` with:
  - `notify.notified()` — immediate wakeup on packet/app-IO/command
  - `cmd_rx.recv()` — listen/dial commands (already there)
  - Fallback timer: after each poll cycle, compute
    `iface.poll_delay(smol_now(), &sockets)` → `Option<smoltcp::time::Duration>`.
    If `Some(d)`, sleep `std::time::Duration::from_micros(d.total_micros())`.
    If `None`, block indefinitely on notify/cmd (nothing pending).
    Use `tokio::select!` with the sleep + notify + cmd.
- **Notify on app write**: `NetstackStream::poll_write` calls
  `self.notify.notify_one()` after a successful `tx.try_send`.
- **Notify on app read**: `NetstackStream::poll_read` calls
  `self.notify.notify_one()` after receiving data from the rx channel (frees
  buffer space, so the poll loop can resume reading from the socket).
- **Expose** `Netstack::tx_notify() -> Arc<Notify>` for the tsnet pump.
- `push_rx` already calls `self.notify.notify_one()` — keep it.

#### 2. `crates/netstack/src/device.rs` — notify on outbound packet

- **Add** `tx_notify: Arc<Notify>` to `LoopbackDevice` and `OwnedTxToken`.
- **Fire** `tx_notify.notify_one()` in `OwnedTxToken::consume` after pushing to
  the tx queue.
- Pass `tx_notify` through `LoopbackDevice::new()` from `Netstack::new()`.

#### 3. `crates/tsnet/src/lib.rs` — event-driven data pump

- **Replace** the 5ms ticker in `run_netstack_pump` with:
  - `magicsock.poll_recv()` (already event-driven)
  - `netstack.tx_notify().notified()` — wake when netstack has outbound packets
  - 250ms ticker for WG timer ticks only (was implicitly every 5ms before)
- The `run_tun_pump` already uses a 250ms ticker for WG timers and is
  event-driven via `tun.read_packet()` and `magicsock.poll_recv()` — no change.

#### 4. Test rig updates — `crates/netstack/src/tests.rs` + `crates/tsnet/src/tests.rs`

- Update test pumps to use `tx_notify` instead of `sleep(1ms)` when idle:
  `tokio::select!` on both netstacks' `tx_notify().notified()` with a small
  fallback timeout (10ms) for WG timer ticks.
- **Add latency test** in `crates/netstack/src/tests.rs`:
  `latency_small_message_round_trip` — set up back-to-back rig, do N ping-pong
  rounds with 8-byte messages, assert p50 < 20ms (generous CI margin), log the
  actual p50/p95/p99.

#### 5. `docs/benchmarks.md` — update before/after

Record p50/p95/p99 and throughput before and after the change.

## Acceptance

- `tools/check.sh` clean (build + test + clippy)
- `tools/e2e.sh` fully green
- `tools/bench/run-local.sh`: p50 well under 1ms (localhost direct), throughput
  not below ~800 Mbps
- `docs/benchmarks.md` updated with before/after numbers
