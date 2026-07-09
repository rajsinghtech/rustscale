# Phase GCP Bench — rustscale vs tailscaled: performance + footprint, userspace + TUN

## Goal

Run a rigorous, side-by-side comparison of rustscale and tailscaled on GCP,
across both networking modes (userspace-netstack and kernel-TUN), measuring:

1. **Throughput** — iperf3 TCP sweep (P=1,10,25,50,100, `-t 30`), steady-state.
2. **Latency** — ping-pong p50/p95/p99.
3. **Footprint** — RSS (peak/avg), CPU% (peak/avg), binary size on disk.

All measurements happen on dedicated GCP VMs (n1-standard-4, no CPU bursting),
in a single session per topology so variance is comparable across configs.

## Test matrix

Two independent dimensions:

| Mode    | rustscale                                | tailscaled                                   |
|---------|------------------------------------------|----------------------------------------------|
| userspace | smoltcp netstack via `rustscale-bench` | gVisor netstack via `--tun=userspace-networking` + SOCKS5 |
| TUN     | `rustscale-tun --apply-routes` + kernel iperf3 | default `tailscaled` + kernel iperf3   |

Crossed with:

- **Topology**: same-zone (us-central1-a/b, <1ms RTT) and cross-region (us-central1-a / us-west1-a, ~34ms RTT). Run back-to-back.
- **Path**: direct (normal) and DERP-forced (`iptables` UDP block except DNS).

Full matrix: 2 topologies x 2 paths x 4 configs = **16 runs**, each running the
full iperf3 sweep (5 stream counts x 30s) + latency + footprint.

## VM provisioning

### Machine config

- **Type**: `n1-standard-4` (4 dedicated vCPUs, no bursting). Per network-testing methodology.
- **Image**: `ubuntu-2204-lts` family (`ubuntu-os-cloud` project).
- **Disk**: 200 GB pd-standard (IOPS scale with size; enough for cargo build + pcaps).
- **Network**: `--subnet default` (required for default VPC).
- **Zone pairing**:
  - same-zone: `us-central1-a` + `us-central1-b`
  - cross-region: `us-central1-a` + `us-west1-a`

### Startup script

```bash
#!/bin/bash
set -ex
apt-get update -qq
apt-get install -y -qq iperf3 tcpdump zstd sysstat procps jq curl python3 socat ncat git build-essential pkg-config
# Rust toolchain for building rustscale
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
source /root/.cargo/env
# Tailscale (for tailscaled comparison)
curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/jammy.noarmor.gpg | tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null
curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/jammy.tailscale-keyring.list | tee /etc/apt/sources.list.d/tailscale.list
apt-get update -qq && apt-get install -y -qq tailscale
echo "DONE" > /tmp/startup-done
```

### Source delivery

Build rustscale on-VM from the local source tree (deterministic, no GitHub auth needed):

```bash
git archive --format=tar.gz -o /tmp/rustscale-src.tar.gz HEAD
gcloud compute scp /tmp/rustscale-src.tar.gz <vm>:/tmp/ --zone=<zone>
# On VM:
cd /root && tar xzf /tmp/rustscale-src.tar.gz -C /root/rustscale
cd /root/rustscale && cargo build --release -p rustscale-bench
cargo build --release --example rustscale-tun -p rustscale-tsnet
```

Two release binaries land in `target/release/`:
- `rustscale-bench` (userspace bench tool)
- `rustscale-tun` (TUN-mode CLI, built as an example)

## Config runners

Each config is a pair of server-side + client-side functions. The orchestrator
runs them via `gcloud compute ssh ... --command`.

### Config 1: rustscale userspace

- **Server VM**: `rustscale-bench server --authkey K --port 5201 --hostname rs-srv --state-dir /tmp/rs-srv`
- **Client VM**: `rustscale-bench client --authkey K --target <server-ts-ip>:5201 --duration 30 --direction down --parallel N --json`
- **Latency**: `rustscale-bench latency --authkey K --target <ip>:5201 --count 200 --json`
- **Footprint PID**: the `rustscale-bench server` PID on the server VM.
- Matches existing `tools/bench/run-local.sh` logic, just over SSH.

### Config 2: rustscale TUN

- **Both VMs**: `sudo rustscale-tun --authkey K --hostname <name> --apply-routes --tun-name utun0`
- **Server VM**: `iperf3 -s -p 5201` (binds all interfaces, reachable via tailnet IP through utun0)
- **Client VM**: `iperf3 -c <server-ts-ip> -p 5201 -t 30 -P N -R -J` (download direction)
- **Latency**: `ping -c 200 <server-ts-ip>` (kernel ICMP through TUN)
- **Footprint PID**: the `rustscale-tun` PID on whichever VM we're sampling.

### Config 3: tailscaled userspace

- **Both VMs**: `tailscaled --tun=userspace-networking --socket=<sock> --statedir=<dir> --port=<port>`
- **Client VM** also adds `--socks5-server=127.0.0.1:11080`
- **Server VM**: `tailscale serve --tcp 5201 --bg localhost:5201` + `iperf3 -s -p 5201 -B 127.0.0.1`
- **Client VM**: iperf3 through `socat TCP-LISTEN:5300,fork SOCKS5-CONNECT:127.0.0.1:11080:<server-ip>:5201`
- Matching existing `tools/bench/run-tailscaled.sh` logic.
- **Footprint PID**: `tailscaled` PID on the server VM.

### Config 4: tailscaled TUN (default)

- **Both VMs**: `tailscaled --socket=<sock> --statedir=<dir>` (kernel TUN, default mode)
- **Server VM**: `iperf3 -s -p 5201` (reachable on tailnet IP via tailscale0 interface)
- **Client VM**: `iperf3 -c <server-ts-ip> -p 5201 -t 30 -P N -R -J`
- **Latency**: `ping -c 200 <server-ts-ip>`
- **Footprint PID**: `tailscaled` PID on the server VM.

## Footprint measurement

For every config, sample the tunnel process (the thing being compared: rustscale-bench
/ rustscale-tun / tailscaled) every 1 second during the iperf3 sweep.

### Collect

```bash
# pidstat (from sysstat) gives per-process RSS + CPU% in one shot:
pidstat -p $PID -rud 1 > $FOOTPRINT_FILE &
SAMPLER_PID=$!
# ... run iperf3 sweep ...
kill $SAMPLER_PID
```

Falls back to `ps -o rss=,pcpu= -p $PID` in a loop if `pidstat` unavailable.

### Parse

Extract from the samples:
- `rss_peak_kb` — max RSS across all samples
- `rss_avg_kb` — mean RSS
- `cpu_peak_pct` — max CPU%
- `cpu_avg_pct` — mean CPU%
- `binary_size_bytes` — `stat -c %s <binary>` (rustscale-bench, rustscale-tun, /usr/sbin/tailscaled)

## DERP forcing

After the direct-path runs for all 4 configs, force DERP:

```bash
# On BOTH VMs: block all outbound UDP except DNS (port 53)
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p udp -j DROP
```

Verify with `tailscale ping <peer>` — should show "via DERP". Re-run all 4 configs.
Restore direct after: `iptables -F OUTPUT` (or delete the two rules).

## Orchestration flow

```
run-gcp.sh
├── 1. bench_provision_tailnet     (reuse tools/bench/lib.sh)
├── 2. provision VMs               (gcloud create x2 + wait for startup-done)
├── 3. deliver + build source      (git archive + scp + cargo build on each VM)
├── 4. for topology in same-zone, cross-region:
│      ├── provision that topology's VMs (if not already up)
│      ├── for path in direct, derp:
│      │    ├── [if derp] apply iptables rules on both VMs
│      │    ├── install ACL + authkey
│      │    ├── for config in rs-userspace, rs-tun, ts-userspace, ts-tun:
│      │    │    ├── start server-side tunnel
│      │    │    ├── start client-side tunnel
│      │    │    ├── wait for path + IP
│      │    │    ├── start footprint sampler (pidstat)
│      │    │    ├── run iperf3 sweep (P=1,10,25,50,100, t=30)
│      │    │    ├── run latency test
│      │    │    ├── stop sampler, parse
│      │    │    ├── kill tunnels (both VMs)
│      │    │    └── write <config>.json
│      │    └── [if derp] remove iptables rules
│      └── tear down topology VMs (or reuse for next topology)
├── 5. teardown: delete VMs, delete tailnet (bench_cleanup_tailnet trap)
└── 6. write combined results JSON + markdown summary
```

## Results format

Each run produces a JSON file under `bench-results/gcp-<stamp>/<topology>/<path>/<config>.json`:

```json
{
  "tool": "rustscale" | "tailscaled",
  "mode": "userspace" | "tun",
  "topology": "same-zone" | "cross-region",
  "path": "direct" | "derp",
  "config": "rs-userspace" | "rs-tun" | "ts-userspace" | "ts-tun",
  "throughput": [
    {"parallel": 1, "mbps": 781.65, "duration_s": 30},
    {"parallel": 10, "mbps": 1200.0, "duration_s": 30}
  ],
  "latency": {
    "p50_us": 180, "p95_us": 364, "p99_us": 1752, "count": 200
  },
  "footprint": {
    "binary_size_bytes": 12345678,
    "rss_peak_kb": 45678,
    "rss_avg_kb": 40000,
    "cpu_peak_pct": 85.3,
    "cpu_avg_pct": 45.2,
    "samples": 150
  },
  "path_class_reported": "direct"
}
```

Final outputs:

- `bench-results/gcp-<stamp>/summary.json` — machine-readable combined results
- `bench-results/gcp-<stamp>/dashboard.html` — standalone interactive HTML dashboard (see below)
- a markdown table appended to `docs/benchmarks.md`

## HTML dashboard

A **single self-contained `.html`** file (no external CDN, no server) that
visualizes the 16-run matrix. Generated by a Rust binary `rustscale-bench`
subcommand (`rustscale-bench report <summary.json> --html <out>`) or, simpler,
by a Python script `tools/bench/gcp/render-html.py` that reads `summary.json`
and emits the HTML.

### Dashboard sections

1. **Header** — run timestamp, topology, commit hash, tailscale version, rustscale version.
2. **Throughput charts** — grouped bar chart: x-axis = parallel stream count (1, 10, 25, 50, 100), one grouped bar per config (4 colors), separate chart per (topology, path) combo (4 charts: same-zone/direct, same-zone/derp, cross-region/direct, cross-region/derp). Y-axis Mbps.
3. **Latency chart** — grouped bar: p50/p95/p99 for each config, one cluster per (topology, path). Or shared axes with filter.
4. **Footprint table** — sortable table per config: binary size, RSS peak/avg, CPU peak/avg. Red/green conditional formatting on best value.
5. **Per-config detail cards** — click a bar to expand a card with the raw JSON, server log excerpt, and path verification.

### Implementation

- Charting: embed `chart.umd.js` (Chart.js ~200KB) inline as a `<script>` blob. No network dep.
- Layout: single HTML doc with `<style>` block, four `<canvas>` elements for throughput, one for latency, one `<table>` for footprint.
- Theming: dark-mode default (matches terminal aesthetic), optional light-mode toggle.
- Must open directly in a browser via `file://` — no HTTP server required.

### Dashboard filters

- Toggle: include/exclude TUN configs (so userspace-only comparison is one click).
- Toggle: include/exclude DERP runs.
- Topology switch: same-zone | cross-region | both.

## File layout (what opencode builds)

```
tools/bench/gcp/
  lib.sh              — GCP helpers: VM create/delete, SSH helper, source delivery
  provision.sh        — create 2 VMs + wait for startup
  footprint.sh        — start/stop/parse pidstat sampler
  run-config.sh       — run ONE config on given VMs (called by run-matrix.sh)
  run-matrix.sh       — main orchestrator (loops topology/path/config)
  teardown.sh         — delete VMs
```

## Acceptance criteria

- `tools/bench/gcp/run-matrix.sh` completes all 16 runs without manual intervention.
- `bench-results/gcp-<stamp>/` contains 16 JSON files + `summary.json`.
- All runs report `path_class_reported` matching the expected path (direct/derp).
- RSS + binary size captured for all 4 configs.
- No leaked VMs or tailnets after completion (cleanup trap verified).
- `docs/benchmarks.md` updated with a results section.

## Key references (for the implementing agent)

- `tools/bench/lib.sh` — tailnet provisioning (reuse `bench_provision_tailnet`, `bench_mint_authkey`, `bench_cleanup_tailnet`)
- `tools/bench/run-local.sh` — rustscale userspace logic (server/client/latency)
- `tools/bench/run-tailscaled.sh` — tailscaled userspace logic (SOCKS5, serve, iperf3)
- `crates/tsnet/examples/rustscale-tun.rs` — TUN CLI flags
- `crates/bench/src/main.rs` — rustscale-bench CLI
- network-testing skill: test methodology (30s duration, 3+ iterations, CPU monitoring, qdisc checks)
