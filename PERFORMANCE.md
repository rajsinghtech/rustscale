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

For the currently accepted Linux TUN configuration:

1. Use a release build and TUN mode.
2. Keep direct paths enabled and verify that the selected path is direct.
3. Leave Linux UDP batching, GRO, and TX-GSO enabled. They are enabled by
   default on supported Linux kernels.
4. Leave both experimental TUN pipelines disabled. They are opt-in and are not
   part of the accepted performance configuration.

Do **not** set these rollback variables in the throughput profile:

```text
RUSTSCALE_DISABLE_LINUX_UDP_BATCH
RUSTSCALE_DISABLE_UDP_GRO
RUSTSCALE_DISABLE_UDP_GSO
RUSTSCALE_TUN_INBOUND_PIPELINE
RUSTSCALE_TUN_OUTBOUND_SEND_PIPELINE
```

The outbound send pipeline improved an older three-point workload, which is why
the rollback control remains available. The current five-point A/B below
regressed throughput and latency, so it supersedes that historical operating
recommendation. The receive parallel-open experiment also regressed every
point and was not merged.

### tailscaled

Run the release `tailscaled` system daemon in kernel TUN mode with its normal
Linux defaults. Do not use userspace networking or force DERP when measuring
direct-path TUN performance. Confirm the peer path is direct before accepting a
result. The benchmark harness installs and records the exact upstream package,
version, and executable digest; it does not apply private or undocumented
performance knobs.

## Optimization evidence

### Current RustScale outbound pipeline rejection

Run `gcp-20260723-075354-e37065209b` tested the current PR product at clean
source `7e0eb07f5afd03ecba34ae7f6ad7c29735b17e26`. It enabled only
`RUSTSCALE_TUN_OUTBOUND_SEND_PIPELINE`; the inbound pipeline remained off and
Linux UDP batching, GRO, and GSO remained on. All 15 direct DOWN trials were
retained without retry or replacement.

| Parallel streams | Pipeline-on median | Versus current default |
|---:|---:|---:|
| 1 | 1457.3 Mbps | **-6.0%** |
| 10 | 1016.4 Mbps | **-27.8%** |
| 100 | 791.6 Mbps | **-24.8%** |
| 500 | 283.5 Mbps | **-48.0%** |
| 1000 | 216.9 Mbps | **-48.0%** |

Pipeline-on p50/p95/p99 latency was 1344.380/1597.294/1726.958 us, or
9.0%/19.4%/26.2% above the current default. This evidence rejects enabling the
pipeline for current operation. The complete credential-free result and
checksums are tracked in
[`docs/performance/gcp-20260723-075354-e37065209b`](docs/performance/gcp-20260723-075354-e37065209b/).

### Receive parallel-open candidate rejection

Run `gcp-20260723-081840-984481bfc6` tested the unmerged candidate
`931170f997cc266e4e818486d6b26204c7ab9693`, which parallelized bulk receive
authentication before ordered replay-state commit. Both runtime pipelines were
off and Linux UDP batching, GRO, and GSO were on. All 15 direct DOWN trials were
retained without retry or replacement.

| Parallel streams | Candidate median | Versus current default |
|---:|---:|---:|
| 1 | 1066.5 Mbps | **-31.2%** |
| 10 | 779.8 Mbps | **-44.6%** |
| 100 | 707.9 Mbps | **-32.8%** |
| 500 | 433.5 Mbps | **-20.5%** |
| 1000 | 305.1 Mbps | **-26.9%** |

Candidate p50/p95/p99 latency was 1376.262/1547.904/1703.883 us, or
11.6%/15.7%/24.5% above the current default. The hypothesis is rejected and
the product change is not part of the parity PR. The complete credential-free
result and checksums are tracked in
[`docs/performance/gcp-20260723-081840-984481bfc6`](docs/performance/gcp-20260723-081840-984481bfc6/).

### Historical RustScale outbound pipeline A/B (superseded)

This is a same-binary A/B at source `ca56c1d0583249e97a3c68ca3ad00a48a0b95553`
on the `n1-standard-4` setup above. UDP batching and GRO were enabled in both
runs; only `RUSTSCALE_TUN_OUTBOUND_SEND_PIPELINE` changed. It is retained to
explain the experiment's origin, but the current five-point rejection above is
the operating authority.

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

## Previous canonical five-configuration RSB1 matrix (2026-07-21)

Run `gcp-20260721-080637-4aca6f6c1e` was the prior matched evidence set for
RustScale embedded tsnet, pinned Tailscale Go tsnet, RustScale kernel TUN, the
retained tailscaled SOCKS5/Serve daemon proxy, and tailscaled kernel TUN. It ran
from clean source commit `395bf8db6648e67f61bc571e1a755b27cd714e12` on matched
GCP `n1-standard-4` endpoints in `us-central1-a` and `us-central1-b`. Every
cell observed a direct path and completed three 10-second RSB1 samples at each
of P1/P10/P100/P500/P1000 with exact connection lifecycle denominators, plus
200/200 latency exchanges with no timeout or malformed reply.

Median throughput is in Mbps; the parenthesized value is population CV across
the three retained samples.

| Configuration | P1 | P10 | P100 | P500 | P1000 |
|---|---:|---:|---:|---:|---:|
| RustScale embedded tsnet | 84.0 (53.2%) | 328.5 (11.0%) | 124.7 (1.2%) | 19.6 (57.8%) | 59.7 (60.5%) |
| Tailscale embedded Go tsnet | 1395.9 (0.3%) | 1564.8 (0.3%) | 1430.5 (4.8%) | 1289.1 (2.3%) | 1178.9 (6.4%) |
| RustScale kernel TUN | 1613.3 (0.6%) | 1513.6 (0.3%) | 1215.5 (1.6%) | 511.1 (0.8%) | 366.2 (9.2%) |
| tailscaled daemon proxy | 1333.0 (1.3%) | 1343.4 (1.0%) | 1114.4 (3.2%) | 852.5 (1.0%) | 685.6 (2.7%) |
| tailscaled kernel TUN | 2243.7 (1.7%) | 2185.6 (1.2%) | 1902.2 (0.7%) | 1343.4 (2.5%) | 931.4 (1.7%) |

| Configuration | p50 us | p95 us | p99 us | Successful/requested |
|---|---:|---:|---:|---:|
| RustScale embedded tsnet | 1069.747 | 1167.274 | 1218.603 | 200/200 |
| Tailscale embedded Go tsnet | 1142.742 | 1322.729 | 1651.217 | 200/200 |
| RustScale kernel TUN | 1185.821 | 1298.025 | 1328.048 | 200/200 |
| tailscaled daemon proxy | 1551.578 | 1660.892 | 1700.585 | 200/200 |
| tailscaled kernel TUN | 1321.159 | 1444.654 | 1493.460 | 200/200 |

Resource values cover each endpoint's declared userspace process set from
after warmup through latency. CPU is average/peak percent and RSS is
average/peak MiB.

| Configuration | Endpoint | Samples (missing) | CPU avg/peak | RSS avg/peak MiB |
|---|---|---:|---:|---:|
| RustScale embedded tsnet | client | 365 (82) | 62.59/219.16% | 38.54/204.12 |
| RustScale embedded tsnet | server | 365 (1) | 70.18/276.89% | 2094.11/8943.43 |
| Tailscale embedded Go tsnet | client | 308 (78) | 156.81/322.14% | 280.84/852.68 |
| Tailscale embedded Go tsnet | server | 306 (1) | 161.56/401.68% | 2169.55/6433.65 |
| RustScale kernel TUN | client | 215 (1) | 105.68/173.99% | 37.08/52.54 |
| RustScale kernel TUN | server | 214 (1) | 112.69/173.57% | 31.84/34.62 |
| tailscaled daemon proxy | client | 300 (1) | 143.50/386.73% | 2952.25/10802.55 |
| tailscaled daemon proxy | server | 326 (1) | 132.18/403.60% | 1186.66/2744.95 |
| tailscaled kernel TUN | client | 213 (1) | 208.68/327.94% | 543.30/740.63 |
| tailscaled kernel TUN | server | 212 (1) | 226.15/337.22% | 99.64/160.56 |

These process-scope resource numbers exclude kernel CPU, and the daemon-proxy
set can count shared pages in more than one ncat process. They are not total
system cost. The RustScale embedded throughput samples have 53–60% CV at
P1/P500/P1000, so this run does not support a stable winner claim or a derived
performance ratio for that mode. The daemon-proxy cell is also a distinct
architecture, retained and labeled for continuity rather than presented as
embedded Go tsnet.

The complete credential-free manifest, five cell results, endpoint metadata,
summary, generated dashboard, and per-file SHA-256 list are tracked in
[`docs/performance/gcp-20260721-080637-4aca6f6c1e`](docs/performance/gcp-20260721-080637-4aca6f6c1e/).
The independently archived run (including its untracked execution log) has
SHA-256 `fb2ddc6221cc07e70aa19ba592f3cb8319bdbb7b0afb9e4591ad7c164b61f663`.
The harness exited successfully only after all five cells, aggregate
validation, and teardown passed; independent postflight found zero remaining
VMs, disks, addresses, tailnets, benchmark processes, shared tailnet records,
or auth-key files.

## Current canonical five-configuration RSB1 matrix (2026-07-23)

Run `gcp-20260723-064751-19775b4c5b` measured the PR #107 tree at clean
source commit `70a7e09d460e33664bc570db8e68b77f694309a0` on matched GCP
`n1-standard-4` endpoints in `us-central1-a` and `us-central1-b`. The pinned
native comparator used `tailscale.com@v1.100.0` and Go 1.26.4. Every cell
observed a direct path and completed three 10-second RSB1 download samples at
P1/P10/P100/P500/P1000 with exact connection lifecycle denominators, followed
by 200/200 latency exchanges. No valid outcome was retried or replaced.

Median throughput is in Mbps; population CV is parenthesized.

| Configuration | P1 | P10 | P100 | P500 | P1000 |
|---|---:|---:|---:|---:|---:|
| RustScale embedded tsnet | 2349.4 (1.2%) | 2296.8 (1.1%) | 2337.0 (0.3%) | 2231.3 (2.0%) | 2180.3 (1.0%) |
| Tailscale embedded Go tsnet | 1128.3 (3.9%) | 1510.4 (1.7%) | 1435.6 (3.1%) | 1331.6 (1.7%) | 1129.4 (3.2%) |
| RustScale kernel TUN | 1549.9 (1.3%) | 1407.6 (0.5%) | 1053.3 (0.2%) | 545.6 (4.0%) | 417.4 (8.2%) |
| tailscaled daemon proxy | 1209.8 (2.5%) | 1273.9 (1.3%) | 1083.8 (1.7%) | 795.6 (1.7%) | 630.0 (1.8%) |
| tailscaled kernel TUN | 2277.2 (0.4%) | 2452.0 (1.0%) | 2203.8 (0.2%) | 1619.0 (1.5%) | 1329.3 (2.9%) |

RustScale embedded throughput was 2.082x, 1.521x, 1.628x, 1.676x, and
1.931x native Go tsnet at the five stream counts. Kernel-TUN throughput is the
remaining direct-path performance gap: RustScale reached only 68.1%, 57.4%,
47.8%, 33.7%, and 31.4% of tailscaled. The P1000 RustScale TUN samples were
`417.442, 426.234, 353.256` Mbps, so that cell's 8.2% CV is also a stability
warning rather than a precise point estimate. The daemon-proxy result remains
context only; its loopback kernel TCP, ncat, SOCKS5, Serve, and daemon process
boundaries are not an embedded or TUN parity denominator.

| Configuration | p50 us | p95 us | p99 us | Successful/requested |
|---|---:|---:|---:|---:|
| RustScale embedded tsnet | 1123.879 | 1229.095 | 1286.476 | 200/200 |
| Tailscale embedded Go tsnet | 1140.439 | 1249.780 | 1370.256 | 200/200 |
| RustScale kernel TUN | 1232.880 | 1338.271 | 1368.507 | 200/200 |
| tailscaled daemon proxy | 1691.700 | 1845.124 | 1906.000 | 200/200 |
| tailscaled kernel TUN | 1442.183 | 1572.326 | 1620.317 | 200/200 |

RustScale embedded p50/p95/p99 were 1.5%, 1.7%, and 6.1% lower than native
Go tsnet. RustScale TUN p50/p95/p99 were 14.5%, 14.9%, and 15.5% lower than
tailscaled. The first RustScale embedded latency exchange was a 13.511 ms
outlier, however, versus a 1.762 ms native maximum; the percentile win does not
close that cold-tail observation.

CPU is average/peak userspace percent and RSS is average/peak MiB across each
endpoint's declared process set.

| Configuration | Endpoint | Samples (missing) | CPU avg/peak | RSS avg/peak MiB |
|---|---|---:|---:|---:|
| RustScale embedded tsnet | client | 358 (81) | 127.43/294.94% | 204.66/1226.05 |
| RustScale embedded tsnet | server | 357 (1) | 105.03/287.69% | 682.62/2447.27 |
| Tailscale embedded Go tsnet | client | 309 (78) | 151.83/317.80% | 269.23/872.97 |
| Tailscale embedded Go tsnet | server | 308 (1) | 145.45/400.20% | 1853.05/5801.74 |
| RustScale kernel TUN | client | 216 (1) | 108.00/181.73% | 34.74/53.68 |
| RustScale kernel TUN | server | 215 (1) | 134.51/244.29% | 31.75/34.83 |
| tailscaled daemon proxy | client | 300 (1) | 145.20/395.47% | 2959.88/10870.33 |
| tailscaled daemon proxy | server | 330 (1) | 113.04/399.23% | 1072.70/2367.65 |
| tailscaled kernel TUN | client | 212 (1) | 220.18/346.87% | 866.78/1315.59 |
| tailscaled kernel TUN | server | 212 (1) | 203.96/312.81% | 78.43/117.53 |

RustScale used less average userspace CPU in both matched embedded and TUN
comparisons. Its embedded server average/peak RSS was 63.2%/57.8% lower, while
the RustScale embedded client peak was 40.4% higher than native despite a
24.0% lower average. The RustScale benchmark binary was 20.35 MiB versus
30.14 MiB for the Go comparator; `rustscaled` was 21.10 MiB versus 39.22 MiB
for tailscaled.

The complete credential-free matrix, endpoint metadata, result JSON,
dashboard, summary, and per-file hashes are tracked in
[`docs/performance/gcp-20260723-064751-19775b4c5b`](docs/performance/gcp-20260723-064751-19775b4c5b/).
The summary SHA-256 is
`6e739c2800f0592a33fde55c8faf75f0d3c23a23e1dba7294763643e8ae9de8c`.
Strict aggregation reported five expected/five successful/zero failed/zero
missing cells. Postflight found zero labeled VMs, disks, addresses, processes,
locks, auth roots, or credential findings, and independently confirmed the
ephemeral tailnet was gone.
