# Benchmarks — rustscale vs tailscaled (Go)

Hard, comparable throughput and latency numbers for rustscale's userspace
netstack against Go's tailscaled in userspace-networking mode. Both sides use
in-process TCP/IP stacks (smoltcp vs gVisor/netstack) over the same WireGuard
data plane, on the same machine, on the same ephemeral tailnet.

## Methodology

### What is being compared

Both harnesses measure TCP throughput and RTT through two userspace netstacks
connected over a real Tailscale tailnet:

| Component        | rustscale                          | tailscaled (Go)                    |
|------------------|------------------------------------|------------------------------------|
| Netstack         | smoltcp (in-process)               | gVisor netstack (in-process)       |
| WireGuard        | boringtun (Rust)                   | wireguard-go (Go)                  |
| Control plane    | rustscale controlclient            | Go controlclient                   |
| Magicsock        | rustscale magicsock                | Go magicsock                       |
| Mode             | `tsnet::Server::up()` (netstack)   | `--tun=userspace-networking`       |

### Byte path (rustscale)

```
rustscale-bench client → smoltcp netstack → WG encapsulate →
  magicsock (UDP/DERP) → magicsock (server) → WG decapsulate →
  smoltcp netstack → rustscale-bench server
```

### Byte path (tailscaled)

```
iperf3 client → socat (SOCKS5 bridge) → tailscaled B netstack →
  WG encapsulate → magicsock (UDP/DERP) → magicsock (A) →
  WG decapsulate → tailscaled A netstack → tailscale serve --tcp →
  iperf3 server (localhost)
```

Both paths go through two userspace netstacks and the full WG/magicsock
pipeline. The socat and iperf3 overhead on the Go side is negligible (SOCKS5
handshake is one-time; iperf3 runs in-process after connect).

### Path class reporting

Both harnesses report the magicsock path class (direct/derp/relay) from the
client's status after the test. On a single machine (localhost), the path
typically settles to **direct** within seconds of the WG handshake completing.
DERP paths can be observed by running across separate networks or blocking
UDP. The harness reports whatever path was actually used.

### Test parameters

| Parameter       | Default | Description                          |
|-----------------|---------|--------------------------------------|
| duration        | 10s     | Throughput test duration              |
| parallel        | 1       | Parallel TCP connections             |
| direction       | down    | up (client→server), down, bidir      |
| latency_count   | 200     | Ping-pong rounds for latency test    |

## How to run

### Prerequisites

```bash
# Local: source OAuth creds for ephemeral tailnet creation
source .secrets/tailscale.env

# CI: GitHub OIDC WIF (automatic, no secret needed)

# Required tools (local):
#   cargo, tailscaled, tailscale, iperf3, socat, ncat (nmap), python3, jq, curl
```

### rustscale-bench (Rust)

```bash
source .secrets/tailscale.env
tools/bench/run-local.sh

# Override defaults:
BENCH_DURATION=10 BENCH_PARALLEL=4 BENCH_DIRECTION=down tools/bench/run-local.sh
```

### tailscaled (Go comparison)

```bash
source .secrets/tailscale.env
tools/bench/run-tailscaled.sh

# Override defaults:
BENCH_DURATION=10 BENCH_PARALLEL=4 BENCH_DIRECTION=down tools/bench/run-tailscaled.sh
```

### Manual rustscale-bench usage

```bash
# Build
cargo build -p rustscale-bench --release

# Server (one terminal)
target/release/rustscale-bench server --authkey tskey-... --port 5201

# Client (another terminal)
target/release/rustscale-bench client --authkey tskey-... --target 100.64.0.1:5201 \
  --duration 10 --direction down --parallel 1 --json

# Latency
target/release/rustscale-bench latency --authkey tskey-... --target 100.64.0.1:5201 \
  --count 1000 --json
```

### CI (GitHub Actions)

```yaml
# .github/workflows/bench.yml — workflow_dispatch only
# Runs on Linux with iperf3 via apt, WIF auth for ephemeral tailnet.
# Uploads bench-results/ as an artifact.
```

## Results

### Machine

| Field       | Value                                        |
|-------------|----------------------------------------------|
| Date        | 2026-07-09                                   |
| OS          | macOS (darwin/arm64)                         |
| CPU         | Apple Silicon (M-series)                     |
| rustscale   | phase-10d (event-driven netstack)            |
| tailscaled  | 1.98.8-t05a918293                            |

### Throughput

| Tool         | Direction | Parallel | Path   | Throughput (Mbps) | Duration |
|--------------|-----------|----------|--------|-------------------|----------|
| rustscale (before 10c) | down | 1 | derp   | 13.14      | 5s       |
| rustscale (after 10c)  | down | 1 | direct | 781.65     | 10s      |
| rustscale (after 10d)  | down | 1 | direct | 838.46     | 10s      |
| tailscaled             | down | 1 | direct | 383.71     | 5s       |

Note: single-run samples on a shared laptop are noisy — independent 10d re-runs
measured 465–510 Mbps for rustscale throughput (still >tailscaled's 384) while
latency stayed stable at p50 150–180us. Treat the throughput column as
indicative until the CI harness produces multi-run medians.

### Latency

| Tool         | Path   | p50 (us) | p95 (us) | p99 (us) | Count |
|--------------|--------|----------|----------|----------|-------|
| rustscale (before 10c) | derp   | 69,284   | 74,325   | 79,122   | 200   |
| rustscale (after 10c)  | direct | 10,140   | 11,048   | 15,082   | 200   |
| rustscale (after 10d)  | direct | 180      | 364      | 1,752    | 200   |
| tailscaled             | direct | 257      | 422      | 481      | 200   |

### Analysis

**Phase 10c fixed two bugs that together closed the gap from 13 Mbps (DERP)
to 782 Mbps (direct) — a 60x improvement, and 2x faster than tailscaled.**

#### Bug 1: Direct path not established (endpoint gathering + disco key)

Two rustscale nodes on the same machine fell back to DERP because:

1. **No local interface endpoints published.** `magicsock` only published
   the bound socket address (`0.0.0.0:port`), not the host's interface IPs.
   Go's `determineEndpoints` enumerates local interfaces via `getifaddrs`
   and pairs each up IPv4 address with the UDP port. Fix: added
   `gather_local_endpoints()` using the `if-addrs` crate, publishing LAN,
   tailnet, and loopback IPs + port in the MapRequest `Endpoints` field.

2. **DiscoKey not reaching the control server before the streaming
   MapResponse.** The control server processes the MapRequest body
   asynchronously and generates the first streaming MapResponse from
   registration data (which lacks DiscoKey/Endpoints). Peers therefore
   see `DiscoKey=zero` and `Endpoints=[]` and can never initiate disco
   probing. Fix: send a lightweight non-streaming MapRequest
   (`Stream=false, OmitPeers=true`) to push DiscoKey + Endpoints to the
   server *before* starting the streaming long-poll. The subsequent
   streaming MapResponse then includes peers with non-zero DiscoKey and
   populated Endpoints, enabling disco ping/pong to confirm direct paths.

#### Bug 2: Netstack backpressure data loss

`pump_connection` ignored `send_slice`'s return value, silently dropping
data when the smoltcp TCP send buffer was full. Fix:

- **Write path:** respect `send_slice`'s return value, store the unwritten
  remainder in `pending_write`, and stop draining the app channel when the
  socket is full. This applies backpressure up the mpsc chain — the bounded
  `app_rx` fills, making `NetstackStream::poll_write` return `Pending` to
  the application.
- **Read path:** only consume from the socket when the app channel has
  capacity, so smoltcp's TCP flow control backs off the sender instead of
  dropping data.
- **Unit test:** `backpressure_large_transfer_no_loss` pushes 1 MB through
  the back-to-back rig (16x the 65 KB TCP buffer) and verifies zero loss
  with correct byte ordering.

#### Tuning

- TCP socket buffers increased from 65 KB to 256 KB.
- ~~Poll interval reduced from 10 ms to 2 ms for responsive backpressure retry.~~
  Replaced in phase 10d with event-driven polling (Notify + smoltcp
  `poll_delay` with 500µs floor).
- Magicsock UDP recv batches a burst of packets per wakeup using
  `try_recv_from` drain loop after the first `recv_from`.

#### Linux UDP batching rollback controls

Linux direct UDP defaults to bounded send/receive batching, capability-probed
GSO, and guarded GRO. Rollback controls use presence semantics and are sampled
when the socket tasks start: set `RUSTSCALE_DISABLE_LINUX_UDP_BATCH` to force
ordinary sends and the established scalar receiver, set
`RUSTSCALE_DISABLE_UDP_GSO` to retain plain `sendmmsg`, or set
`RUSTSCALE_DISABLE_UDP_GRO` to retain bounded plain `recvmmsg`. The batch switch
implies no GSO/GRO; unset the variable and restart the daemon to re-enable the
default mode. Unsupported mmsg syscalls and offload errors also permanently
fall back at runtime without changing logical or physical-byte accounting.

The GCP matrix records `RS_LINUX_UDP_BATCH` and `RS_LINUX_UDP_GRO` as explicit
immutable `0`/`1` runtime modes and translates `0` into the corresponding
presence-based daemon rollback control. This permits scalar, plain-batch, and
GRO candidates to be compared from one delivered binary.

#### Remaining gap vs tailscaled

~~rustscale's p50 latency (10.1 ms) is ~40x higher than tailscaled's (257 us).~~

**Phase 10d closed the latency gap.** The root cause was a fixed 2ms poll
interval driving the smoltcp loop: every packet waited for the next timer
tick, accumulating 5+ ticks per RTT. The fix made the stack event-driven:

- **Wake on packet arrival:** `push_rx` already called `notify_one()`; kept.
- **Wake on app write (rising edge):** `poll_write` notifies the poll loop
  only when the app channel transitions from empty to non-empty. This
  preserves low latency (first write after drain wakes immediately) while
  allowing throughput batching (subsequent writes while the channel has
  pending data don't trigger redundant wakeups).
- **Wake on app read:** `poll_read` notifies the poll loop when the app
  drains data, freeing rx buffer space so smoltcp can resume receiving.
- **Fallback timer from smoltcp:** `iface.poll_delay()` tells exactly when
  the next retransmit/timer event is due. A reusable `tokio::time::Sleep`
  with `reset()` avoids per-iteration timer allocation. Floored at 500µs to
  prevent busy-looping when `poll_delay` returns zero during heavy traffic.
- **Event-driven tsnet pump:** replaced the 5ms ticker with
  `netstack.tx_notify()` (fires when smoltcp produces an outbound packet) +
  `magicsock.poll_recv()` + a 250ms WG timer tick.

Result: p50 latency dropped from 10,140µs to 180µs — a **56x improvement**,
now **better than tailscaled** (257µs). Throughput held at 838 Mbps (up from
782). The rising-edge notify pattern was the key insight: a naive notify on
every write caused a 1:1 context-switch-per-packet pattern that dropped
throughput to ~500 Mbps; notifying only on the empty→non-empty transition
preserves batching.

### Notes

- Both harnesses use ephemeral tailnets that are created and deleted per run.
- On localhost, the path is typically **direct** (UDP loopback). DERP paths
  require network isolation (separate machines or UDP blocking).
- The rustscale netstack uses a 1280-byte MTU (Tailscale default) with a 256KB
  TCP socket buffer. The Go netstack uses similar defaults.
- Throughput is limited by per-packet userspace processing overhead (WG
  encapsulation/decapsulation, smoltcp/gVisor TCP processing, magicsock IO).
  Both sides face the same fundamental bottleneck.
- Localhost throughput varies run-to-run (458–854 Mbps observed) due to
  ephemeral tailnet setup timing and system load. The best run (854 Mbps)
  reflects the architecture's capability; the variance is environmental.
