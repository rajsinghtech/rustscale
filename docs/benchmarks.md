# Benchmarks — rustscale vs tailscaled (Go)

The maintained TUN comparison, optimized runtime profile, raw samples, and
footprint summary live in [`PERFORMANCE.md`](../PERFORMANCE.md). This document
describes the broader benchmark methodology and harnesses.

The maintained matrix separates embedded implementations from daemon-proxy
and kernel-TUN evidence. The matched embedded comparison runs the same RSB1
server and client semantics inside RustScale tsnet and pinned upstream Go
tsnet. The older tailscaled SOCKS5/Serve route remains useful daemon-proxy
evidence, but it is not described or ranked as embedded tsnet.

## Methodology

### What is being compared

The routine matrix has five distinct cells:

| Cell | Implementation boundary | RSB1 endpoint | Declared mode |
|---|---|---|---|
| `rs-userspace` | `rustscale_tsnet::Server` in the workload process | `rustscale-bench` | embedded Rust tsnet |
| `ts-embedded` | `tailscale.com/tsnet.Server` in the workload process | `go-tsnet-rsb1` | embedded Go tsnet |
| `ts-userspace` | separate `tailscaled --tun=userspace-networking`, SOCKS5 bridge, and Serve | `rustscale-bench` over loopback kernel TCP | daemon-proxy evidence |
| `rs-tun` | `rustscaled` plus kernel TUN/TCP | `rustscale-bench` | RustScale TUN |
| `ts-tun` | `tailscaled` plus kernel TUN/TCP | `rustscale-bench` | tailscaled TUN |

`go-tsnet-rsb1` is built from `tailscale.com@v1.100.0`; `go.mod`, `go.sum`,
the native `go1.26.4.linux-amd64.tar.gz` toolchain archive
(`1153d3d50e0ac764b447adfe05c2bcf08e889d42a02e0fe0259bd47f6733ad7f`),
and the resulting executable identity are pinned or checksum-recorded. It
implements the same 14-byte RSB1 header,
ready/GO barrier, 1280-byte download writes, setup deadline, stream lifecycle
counts, and 8-byte latency exchanges as `rustscale-bench`.

### Embedded byte paths

```
rustscale-bench client → embedded Rust tsnet/smoltcp → WG/magicsock →
  embedded Rust tsnet/smoltcp → rustscale-bench server

go-tsnet-rsb1 client → embedded Go tsnet/gVisor netstack → WG/magicsock →
  embedded Go tsnet/gVisor netstack → go-tsnet-rsb1 server
```

### Daemon-proxy byte path (not embedded tsnet)

```
rustscale-bench kernel-TCP client → ncat → tailscaled SOCKS5/netstack →
  WG/magicsock → tailscaled netstack → Tailscale Serve →
  rustscale-bench kernel-TCP server on loopback
```

This cell includes extra kernel TCP, ncat, SOCKS5, daemon IPC/configuration,
and Serve boundaries. Those processes are measured and identified, but the
result is not an in-process Go tsnet comparator.

### Path class reporting

Embedded Rust and Go clients classify the exact target peer from their
in-process status (`direct`, `derp`, or peer `relay`). Daemon and TUN cells use
bounded product-CLI path gates before and after RSB1. A selected cell is
publishable only when warmup, measured trials, latency, and the post gate agree
with the requested direct/DERP class; requested path labels are never evidence.

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

# CI runs credential-free harness self-tests only. Paid benchmark runs require
# local credentials and are never started by pull-request CI.

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

### Pinned Go tsnet endpoint

The production matrix builds `tools/bench/go-tsnet` on each endpoint. Its
credential-free protocol, lifecycle, path-classification, and P100 tests run
with the benchmark gate:

```bash
(cd tools/bench/go-tsnet && go mod verify && go test ./...)
tools/bench/check.sh
```

The binary exposes matching `server`, `client`, and `latency` subcommands; use
`(cd tools/bench/go-tsnet && go run . --version)` verifies its pinned identity. Paid
comparison runs should use the matrix so workload, resources, path, cleanup,
and provenance are gated together.

### tailscaled daemon-proxy evidence

```bash
source .secrets/tailscale.env
tools/bench/run-tailscaled.sh

# Override defaults:
BENCH_DURATION=10 BENCH_PARALLEL=4 BENCH_DIRECTION=down tools/bench/run-tailscaled.sh
```

This retained local harness is a tailscaled SOCKS5/Serve daemon-proxy test. It
is not embedded Go tsnet evidence.

### Manual rustscale-bench usage

```bash
# Build
cargo build -p rustscale-bench --release

# Put the key in an owner-only file so it never appears in process argv.
umask 077
printf '%s\n' "$TS_AUTHKEY" > /tmp/rustscale-bench-authkey
unset TS_AUTHKEY

# Server (one terminal)
target/release/rustscale-bench server --authkey-file /tmp/rustscale-bench-authkey --port 5201

# Client (another terminal)
target/release/rustscale-bench client --authkey-file /tmp/rustscale-bench-authkey \
  --target 100.64.0.1:5201 --duration 10 --direction down --parallel 1 --json

# Latency
target/release/rustscale-bench latency --authkey-file /tmp/rustscale-bench-authkey \
  --target 100.64.0.1:5201 --count 1000 --json

rm -f /tmp/rustscale-bench-authkey
```

### GCP five-cell matched matrix

The ordinary paid GCP run is one affordable same-region/cross-zone, direct-path
slice with all five cells and the routine load: three 10-second repeats at 1,
10, and 100 streams. Each freshly minted key is written to a temporary
owner-only local file, copied to owner-only files on the two VMs, and removed
at cell exit. Only file paths cross local or remote argv/rendered-command
boundaries; self-tests fail closed on permissions, symlinks, malformed content,
or a secret value in the run-config argument vector.

```bash
# Credential-free command, provenance, aggregation, and dashboard validation.
MATRIX_SKIP_COLLECT=1 tools/bench/gcp/run-matrix.sh --dry-run

# Ordinary five-cell matched run (the defaults shown above).
tools/bench/gcp/run-matrix.sh

# Compatibility alias for the same exact certification stream contract.
tools/bench/gcp/run-matrix.sh --scale-streams
```

Every selected cell executes byte-identical RSB1 download semantics (direction
`down`, 1280-byte writes), one P1/3-second warmup before sampling, the ordered
throughput points and repeats, and 200 complete 8-byte TCP ping-pongs with raw
nanosecond samples. Rust, daemon-proxy, and TUN cells use `rustscale-bench`;
`ts-embedded` uses `go-tsnet-rsb1`. The daemon-proxy bridge admits 1100
simultaneous connections, above the public P1000 contract.

Certification accepts exactly the ordered stream set
`1,10,100,500,1000`; `--parallelism` rejects every other list and
`--scale-streams` is a compatibility alias for that same set. No cell is capped
or silently truncated. Every measured trial must report exactly
the requested `established`, `handshaken`, and `completed` counts after all
connections finish the RSB1 ready/GO barrier under one bounded setup deadline.
Embedded Rust resolves the target once and admits TCP plus RSB1 setup in a
bounded listener-safe window; it does not retry, serialize, truncate, or submit
an unbounded P500/P1000 SYN/header burst. Outbound TCP ports start at a fresh
process offset and remain collision-owned through socket teardown, preventing
restarted trial processes from immediately reusing live peer four-tuples.
Credential-free Rust regressions retain
all P500 netstack streams, bound a failing P1000 request's pending ownership, and
exercise the complete P500 RSB1 lifecycle. The Go package has a hermetic P100
lifecycle gate; Rust also retains its local P1000 kernel setup gate. Paid P1000
publication still requires all selected cells to complete the requested point.

The warmup, each measured throughput trial, and latency are each attempted
exactly once. One failed or incomplete trial discards the cell. Every trial uses
a new client process, while every cell retains one transport identity per
endpoint. Embedded Rust and Go clients reopen durable, non-ephemeral state
under one stable hostname between trials. Rust rotates its process-local disco
identity, and peers replace stale WireGuard session state when that disco key
changes. Both endpoint samplers run
continuously from after warmup through throughput, three-second gaps, and
latency. Dynamic exact-name process sets are:

- `rs-userspace`: `rustscale-bench` on both endpoints.
- `ts-embedded`: `go-tsnet-rsb1` on both endpoints.
- `ts-userspace` (daemon proxy): server `tailscaled` + `rustscale-bench`;
  client `tailscaled` + every exact-name ncat listener/connector +
  `rustscale-bench`.
- `rs-tun`: `rustscaled` and `rustscale-bench` on both endpoints.
- `ts-tun`: `tailscaled` and `rustscale-bench` on both endpoints.

A successful result requires each endpoint to contain observed, nonempty RSS
and CPU data, a monotonic series in which every declared process subject was
actually observed, the exact declared process-set scope, and executable
path/version/SHA-256 identities for every subject. The primary transport binary
has its own positive on-disk size and
identity binding. Scopes include no descendants by inference and no kernel
CPU; TUN kernel work is therefore excluded, and shared ncat pages can be
counted more than once.

Results retain every throughput repeat and stream lifecycle, all latency
samples, both endpoint timelines, path gates, and verified cleanup. Each
throughput point reports its raw repeat vector, median, min/max, population
standard deviation, and coefficient of variation; a median alone is not
presented as repeat stability. Publication
occurs only after samplers, workloads, helpers, daemons/listeners, state, DNS,
and TUN interfaces satisfy cell postconditions. Unsafe handoff aborts the
matrix.

Manifest schema 4 records the five semantic cell identities, pinned Go build,
selection source, and load preset. Result schema 6 binds canonical mode,
manifest digest, exact RSB1 completion, valid latency, endpoint CPU/RSS,
resource scope, endpoint binary identities, path gates, and cleanup. Historical
manifest 1–3 and result 3–5 data remain parseable as historical/partial
evidence, but old `ts-userspace` data retains its historical userspace label
and is never rewritten as embedded Go tsnet. The current summary envelope is
self-contained.

`--peer-count` records requested context only. Peer generation and observed
peer load are not implemented, so current manifests explicitly record
`effective=null`, `observed=null`, and `status=not-applied`; dashboards must not
call it configured or effective load. The historical `same-zone` harness label
currently provisions `us-central1-a` and `us-central1-b`, so reports describe
it accurately as same-region/cross-zone.

### Isolated native baseline

The opt-in Linux runner collects a native embedded-Rust P1/P10/P100 sample,
exact lifecycle counts, observed path classification, and the benchmark
executable SHA-256 inside the disposable remote source tree.
Unlike a matched matrix cell, this smoke baseline intentionally gives each trial its own ephemeral named
client identity and records that identity scope; the connected ephemeral
server identity remains live until tailnet teardown. Every workload process is attempted exactly once; partial setup is a failed run:

```bash
# With credentials already provisioned in the remote SSH environment:
tools/agent/remote-validate.sh baseline

# Or, only for an explicitly authorized disposable builder:
source .secrets/tailscale.env
tools/agent/remote-validate.sh baseline --allow-local-tailnet-credentials
```

For the independent low-rate application-UDP wakeup baseline, run
`tools/agent/remote-validate.sh interop`. Its isolated cadence gate sends 16
one-way packets at 20 Hz after warmup, requires all ordered payloads and source
addresses, rejects fallback-sized batching, and reports path, arrival span, and
maximum one-way delay under `--nocapture`. Both journeys default to remote-provisioned credentials and require confirmed
cleanup. Local forwarding requires the explicit envelope opt-in described in
`docs/agent-harness.md`; credential values are excluded from source, command
arguments, output, and provenance.

### CI (GitHub Actions)

`.github/workflows/bench.yml` runs the credential-free `tools/bench/check.sh`
self-tests on pull requests and manual dispatch. It does not authenticate to
GCP or Tailscale, create paid resources, execute the production benchmark, or
upload `bench-results/`. Production runs are explicit local operator actions.

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
| tailscaled daemon proxy | down | 1 | direct | 383.71     | 5s       |

Note: single-run samples on a shared laptop are noisy — independent 10d re-runs
measured 465–510 Mbps for RustScale throughput while latency stayed stable at
p50 150–180us. The 384 Mbps tailscaled row is historical SOCKS5/Serve
daemon-proxy evidence, not an embedded-Go comparison; do not infer an embedded
winner from this table.

### Latency

| Tool         | Path   | p50 (us) | p95 (us) | p99 (us) | Count |
|--------------|--------|----------|----------|----------|-------|
| rustscale (before 10c) | derp   | 69,284   | 74,325   | 79,122   | 200   |
| rustscale (after 10c)  | direct | 10,140   | 11,048   | 15,082   | 200   |
| rustscale (after 10d)  | direct | 180      | 364      | 1,752    | 200   |
| tailscaled daemon proxy | direct | 257      | 422      | 481      | 200   |

### Analysis

**Phase 10c fixed two bugs that together moved this historical RustScale run
from 13 Mbps (DERP) to 782 Mbps (direct), a 60x improvement.** The old 2x
statement compared against the daemon-proxy route and is not an embedded-tsnet
claim.

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
The live `never-gso-equal-tail` node capability enables the upstream smaller
sentinel-tail workaround; sub-eight-packet batches conservatively skip GSO.

The GCP matrix records `RS_LINUX_UDP_BATCH` and `RS_LINUX_UDP_GRO` as explicit
immutable `0`/`1` runtime modes and translates `0` into the corresponding
presence-based daemon rollback control. This permits scalar, plain-batch, and
GRO candidates to be compared from one delivered binary.

The GCP matrix also records independent immutable `RS_LINUX_UDP_GSO=0|1`
(default `1`) and translates `0` to `RUSTSCALE_DISABLE_UDP_GSO` on both
RustScale endpoints. TX GSO is independent of GRO but requires batching, so
scalar mode records `RS_LINUX_UDP_GSO=0` because batch disable forces GSO off.

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
below the historical daemon-proxy sample (257µs). Throughput held at 838 Mbps (up from
782). The rising-edge notify pattern was the key insight: a naive notify on
every write caused a 1:1 context-switch-per-packet pattern that dropped
throughput to ~500 Mbps; notifying only on the empty→non-empty transition
preserves batching.

### Notes

- Both harnesses use ephemeral tailnets that are created and deleted per run.
- On localhost, the path is typically **direct** (UDP loopback). DERP paths
  require network isolation (separate machines or UDP blocking).
- The rustscale netstack uses a 1280-byte MTU and fixed 256 KiB TCP send and
  receive buffers per socket. Pinned Tailscale 1.100.0 uses the pinned gVisor
  defaults of 1 MiB send and 1 MiB receive, with Tailscale maxima of 8 MiB RX
  and 6 MiB TX on non-iOS builds. The matrix does not normalize this
  buffer/window asymmetry. This is disclosed as a certification blocker rather
  than treated as comparable: paid publication remains prohibited until a
  controlled same-binary Rust A/B at 256 KiB and 1 MiB is captured with the
  same exact matrix and demonstrates an immaterial effect, or both stacks are
  normalized. No current data may support a winner claim.
- Throughput is limited by per-packet userspace processing overhead (WG
  encapsulation/decapsulation, smoltcp/gVisor TCP processing, magicsock IO).
  Both sides face the same fundamental bottleneck.
- Historical localhost throughput varied from 458–854 Mbps across unmatched
  single runs. Those samples did not isolate setup timing from system load and
  do not support a comparative or architectural-capability claim.
