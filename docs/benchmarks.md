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
| rustscale   | phase-10b bench harness                      |
| tailscaled  | 1.98.8-t05a918293                            |

### Throughput

| Tool         | Direction | Parallel | Path   | Throughput (Mbps) | Duration |
|--------------|-----------|----------|--------|-------------------|----------|
| rustscale    | down      | 1        | derp   | 13.14             | 5s       |
| tailscaled   | down      | 1        | direct | 383.71            | 5s       |

### Latency

| Tool         | Path   | p50 (us) | p95 (us) | p99 (us) | Count |
|--------------|--------|----------|----------|----------|-------|
| rustscale    | derp   | 69,284   | 74,325   | 79,122   | 200   |
| tailscaled   | direct | 257      | 422      | 481      | 200   |

### Analysis

The large gap is primarily explained by **path class difference**:

- **tailscaled** established a **direct** UDP path between the two
  userspace-networking instances on the same machine. Direct localhost UDP
  has sub-millisecond RTT and full bandwidth.
- **rustscale** fell back to **DERP relay** — the two nodes connected via a
  remote DERP server instead of a direct UDP path. DERP adds ~70ms RTT
  (relay round-trip) and limits throughput to ~13 Mbps.

This reveals a **path-selection gap** in rustscale's magicsock: it does not
establish direct UDP paths as aggressively as Go's magicsock on localhost.
This is a known area for improvement in the perf data plane phase (roadmap
item 9: UDP GSO/GRO, batched magicsock IO, direct path discovery).

A secondary factor is the **netstack write-path data loss**: the current
smoltcp pump (`pump_connection`) drains the app channel in a single pass
and drops data that doesn't fit in the TCP send buffer. The bench tool
mitigates this with MTU-sized (1280-byte) write chunks, but throughput is
still limited to roughly one send-buffer fill per 10ms poll cycle (~50 Mbps
ceiling). Fixing the pump to respect `send_slice`'s return value (re-queue
unwritten data) would recover the remaining bandwidth.

### Notes

- Both harnesses use ephemeral tailnets that are created and deleted per run.
- On localhost, the path is typically **direct** (UDP loopback). DERP paths
  require network isolation (separate machines or UDP blocking).
- The rustscale netstack uses a 1280-byte MTU (Tailscale default) with a 64KB
  TCP socket buffer. The Go netstack uses similar defaults.
- Throughput is limited by per-packet userspace processing overhead (WG
  encapsulation/decapsulation, smoltcp/gVisor TCP processing, magicsock IO).
  Both sides face the same fundamental bottleneck.
