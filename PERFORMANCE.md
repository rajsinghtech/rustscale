# Performance

This document tracks reproducible RustScale and upstream `tailscaled` performance.
It distinguishes **throughput-optimized** settings from project defaults and records
the measurements behind each comparison. Results are evidence for the listed
build, machine, topology, and runtime only; they are not universal performance
claims.

## Current matched comparison

The latest matched comparison used back-to-back runs on independently
provisioned, identically specified GCP `n1-standard-4` VM pairs in two
`us-central1` zones, a confirmed direct UDP path, Linux 6.8, and TUN mode. The
harness labels this topology `same-zone`, although the observed server and
client zones are `us-central1-a` and `us-central1-b`. Each throughput point is
the median of three 10-second reverse `iperf3` samples. The latency sample
contains 50 pings at 100 ms intervals. Both products reported zero ping packet
loss.

- RustScale source: `ca56c1d0583249e97a3c68ca3ad00a48a0b95553`
- RustScale version: 0.1.1
- tailscaled version: 1.98.9, commit `4fb758c39ae5b208b974af14ba6bc896a250394c`
- Server: `n1-standard-4`, Intel Haswell, `us-central1-a`
- Client: `n1-standard-4`, Intel Haswell, `us-central1-b`
- Image: Ubuntu 22.04, Linux `6.8.0-1063-gcp`
- Rust toolchain: rustc 1.97.0
- Harness topology label: `same-zone`; observed topology: same-region, cross-zone
- Path: direct UDP
- RustScale run ID: `gcp-20260715-085022-076e87bd41`
- tailscaled run ID: `gcp-20260715-090601-02788a10b4`

### Throughput

| Parallel streams | RustScale median | tailscaled median | RustScale delta |
|---:|---:|---:|---:|
| 1 | 2152.1 Mbps | 2071.4 Mbps | **+3.9%** |
| 10 | 2237.5 Mbps | 2355.8 Mbps | **-5.0%** |
| 100 | 1818.3 Mbps | 1602.3 Mbps | **+13.5%** |

Raw throughput samples:

| Product | P1 samples (Mbps) | P10 samples (Mbps) | P100 samples (Mbps) |
|---|---|---|---|
| RustScale | 2177.4, 2152.1, 2105.1 | 2237.5, 2191.1, 2252.4 | 1723.9, 1896.5, 1818.3 |
| tailscaled | 2071.4, 2152.0, 1993.1 | 2345.6, 2355.8, 2400.1 | 1618.7, 1577.9, 1602.3 |

RustScale leads at one and 100 streams in this run. tailscaled leads at ten
streams. Do not infer a current winner from results collected on different
machine families or commits.

### Latency and footprint

CPU and RSS are samples of the server daemon over the throughput and latency
workload. Binary size is the executable on disk. CPU percentages may exceed
100% because a daemon can use more than one logical CPU.

| Metric | RustScale | tailscaled | RustScale delta |
|---|---:|---:|---:|
| Ping p50 | 1080 us | 1990 us | **-45.7%** |
| Ping p95 | 1180 us | 2160 us | **-45.4%** |
| Ping p99 | 4000 us | 2260 us | **+77.0%** |
| Average CPU | 97.30% | 152.43% | **-36.2%** |
| Peak CPU | 152.00% | 248.00% | **-38.7%** |
| Average RSS | 17.91 MiB | 51.54 MiB | **-65.2%** |
| Peak RSS | 18.00 MiB | 57.75 MiB | **-68.8%** |
| Daemon binary | 15.82 MiB | 39.22 MiB | **-59.7%** |
| Ping packet loss | 0% | 0% | equal |

The 50-ping latency set is useful for regression detection but too small for a
strong tail-latency claim. In particular, the RustScale p99 result is one
reason the outbound pipeline remains opt-in. The loss field covers these pings;
TCP retransmissions and kernel receive-queue overflow are not summarized as a
loss percentage by this result schema.

The matched artifacts predate the explicit `linux_udp_gso` provenance field.
They record batching, GRO, and outbound-pipeline modes, but cannot independently
prove TX-GSO state from immutable metadata. The later TX-GSO A/B below closes
that provenance gap for the GSO decision, but is not substituted into this
cross-product comparison because it used a different commit and machine
family.

## Throughput-optimized operation

### RustScale

For maximum measured Linux TUN throughput:

1. Use a release build and TUN mode.
2. Keep direct paths enabled and verify that the selected path is direct.
3. Leave Linux UDP batching, GRO, and TX-GSO enabled. They are enabled by
   default on supported Linux kernels.
4. Enable the Linux outbound crypto/send pipeline at daemon startup:

```sh
sudo env RUSTSCALE_TUN_OUTBOUND_SEND_PIPELINE=1 rustscaled run
```

Do **not** set these rollback variables in the throughput profile:

```text
RUSTSCALE_DISABLE_LINUX_UDP_BATCH
RUSTSCALE_DISABLE_UDP_GRO
RUSTSCALE_DISABLE_UDP_GSO
RUSTSCALE_TUN_INBOUND_PIPELINE
```

`RUSTSCALE_TUN_OUTBOUND_SEND_PIPELINE` is deliberately not the default. It
improved throughput by 10.2-17.5% in the matched A/B below, but increased CPU and
showed a latency-tail regression. The normal default is the balanced profile;
the environment variable selects the throughput profile.

### tailscaled

Run the release `tailscaled` system daemon in kernel TUN mode with its normal
Linux defaults. Do not use userspace networking or force DERP when measuring
direct-path TUN performance. Confirm the peer path is direct before accepting a
result. The benchmark harness installs and records the exact upstream package,
version, and executable digest; it does not apply private or undocumented
performance knobs.

## Optimization evidence

### RustScale outbound pipeline A/B

This is a same-binary A/B at source `ca56c1d0583249e97a3c68ca3ad00a48a0b95553`
on the `n1-standard-4` setup above. UDP batching and GRO were enabled in both
runs; only `RUSTSCALE_TUN_OUTBOUND_SEND_PIPELINE` changed.

| Metric | Pipeline off | Pipeline on | Change |
|---|---:|---:|---:|
| P1 throughput | 1940.6 Mbps | 2152.1 Mbps | **+10.9%** |
| P10 throughput | 1904.6 Mbps | 2237.5 Mbps | **+17.5%** |
| P100 throughput | 1650.5 Mbps | 1818.3 Mbps | **+10.2%** |
| Ping p50 / p95 / p99 | 976 / 1110 / 1160 us | 1080 / 1180 / 4000 us | mixed |
| Average / peak CPU | 76.0 / 123.0% | 97.3 / 152.0% | higher |
| Average / peak RSS | 17.79 / 17.88 MiB | 17.91 / 18.00 MiB | approximately equal |

Run IDs:

- Off: `gcp-20260715-083739-35bbc8e50f`
- On: `gcp-20260715-085022-076e87bd41`

Every enabled throughput sample exceeded every disabled sample at the matching
parallelism. Both runs measured zero ping packet loss.

### Linux UDP TX-GSO A/B

This same-binary `n2-standard-4` A/B kept the outbound pipeline enabled and
changed only Linux UDP TX-GSO. GSO-on is the supported default.

| Parallel streams | GSO on | GSO off | Off versus on |
|---:|---:|---:|---:|
| 1 | 2512.4 Mbps | 2150.3 Mbps | **-14.4%** |
| 10 | 2793.1 Mbps | 2310.5 Mbps | **-17.3%** |
| 100 | 2235.6 Mbps | 1783.9 Mbps | **-20.2%** |

| Footprint/latency | GSO on | GSO off |
|---|---:|---:|
| Average / peak CPU | 93.86 / 147.0% | 105.49 / 161.0% |
| Average / peak RSS | 20.37 / 20.38 MiB | 20.67 / 20.75 MiB |
| Ping p50 / p95 / p99 | 1300 / 1360 / 1380 us | 1360 / 1440 / 1460 us |
| Ping packet loss | 0% | 0% |

Run IDs:

- GSO on: `gcp-20260715-155001-291b2f8199`
- GSO off: `gcp-20260715-160228-3c2ea81f80`

## Running a current comparison

Paid GCP runs require an authenticated `gcloud` project and the Tailscale test
credentials documented in [`docs/benchmarks.md`](docs/benchmarks.md). The
following command runs a new comparison from the current checkout and current
configured image/tool dependencies; it does not reproduce the historical
commits and packages byte-for-byte:

```sh
export GCP_PROJECT=your-project
export GCP_MACHINE=n1-standard-4
export RS_TUN_OUTBOUND_SEND_PIPELINE=1
export RS_LINUX_UDP_BATCH=1
export RS_LINUX_UDP_GRO=1
export RS_LINUX_UDP_GSO=1

tools/bench/gcp/run-matrix.sh \
  --repeat 3 \
  --topology same-zone \
  --path direct \
  --config rs-tun,ts-tun
```

The harness records source commit, dirty state, build command, runtime modes,
machine type, image, CPU model, kernel, product version and SHA-256, path class,
raw samples, latency, CPU, RSS, and binary size. A result is not suitable for
this document if provenance is incomplete, the path is not confirmed direct,
the ping test reports loss, or the products were measured under materially
different conditions.

The machine-readable values copied into this document are tracked in
[`docs/performance/benchmarks-2026-07-15.json`](docs/performance/benchmarks-2026-07-15.json).
That snapshot also records SHA-256 digests of the complete, credential-free
result JSON retained by project maintainers.

## Maintenance policy

Update the **current matched comparison** only when all of the following hold:

1. RustScale and tailscaled were run by the same harness on the same machine
   type, image, topology, path class, duration, parallelism, and repeat count.
2. RustScale was built from a committed, clean source tree.
3. Product versions and executable hashes are present.
4. Runtime modes are explicit and immutable in the manifest. The historical
   comparison above is explicitly grandfathered with its missing TX-GSO field;
   a future replacement must not have that limitation.
5. The direct path is observed rather than assumed.
6. Raw samples, medians, latency, CPU, RSS, binary size, and ping loss are
   copied into this file with the run IDs.
7. A compact machine-readable snapshot and SHA-256 digests of the complete
   result files are committed under `docs/performance/`.
8. `tools/bench/check.sh` and `git diff --check` pass.

Keep older A/B evidence when it explains a current default or opt-in control.
Do not replace a matched comparison with a faster unmatched result, and do not
claim compatibility or performance from a benchmark that cannot be reproduced.

## Fresh RSB1 userspace/TUN parity (2026-07-17)

Run `gcp-20260717-100908-a708151c79` measured RustScale's identical RSB1
reverse-throughput workload over userspace tsnet and production kernel TUN on
same-zone GCP `n2-standard-16` endpoints. Both cells observed a direct path and
record three complete 10-second samples at 1, 10, 100, 500, and 1000 streams,
plus 50 RTT samples and 1-second server/client process CPU and RSS timelines.

The manifest, complete result JSON, and SHA-256 list are tracked in
[`docs/performance/gcp-20260717-100908-a708151c79`](docs/performance/gcp-20260717-100908-a708151c79/).
The requested peer-load label is 1; observed membership was not instrumented,
so this evidence does not claim peer-load scaling. The linked Pages dashboard
renders the retained raw series without publishing failed cells.
