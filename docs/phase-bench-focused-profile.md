# Phase: Focused benchmark manifests and Linux profiles

## Evidence

Filtered production runs now use the product CLIs and build only the selected
artifacts, but the result pipeline still assumes every run is the full 16-cell
matrix. A successful `--topology same-zone --path direct --config
rs-tun,ts-tun` run therefore prints 14 false `MISSING` warnings, renders empty
charts, and reports itself as incomplete. `collect.sh` also indexes aborted
directories containing no run JSON.

The Linux direct `sendmmsg` phase improved the focused Rustscale result from
509.92/606.89/572.93 to 539.10/652.43/601.73 Mbps at P1/P10/P100. That bounded
5-8% gain leaves Rustscale at 23-32% of Tailscale throughput, so the next phase
must be selected from a fresh production profile rather than the pre-batching
`gcp-20260713-053900` profile.

## Scope

Persist the requested matrix shape with each run and add an opt-in profile for
the production `rs-tun` server. Keep the default workload, result objects,
product startup, CLI `ping --until-direct` gate, tailnet lifecycle, and VM
cleanup unchanged.

Do not add a Rust profiling dependency, always profile normal runs, retain VMs,
change iperf parameters, or add profiling to Tailscale/userspace configurations.

## Matrix manifest

1. After argument validation, write `matrix.json` in the result root containing
   schema version 1 and the exact selected topology, path, and config arrays.
   It is run metadata, not a benchmark result, and must not be globbed as one.
2. `aggregate.py` reads the manifest when present and warns only for missing
   cells in its selected Cartesian product. For historical result directories
   without a manifest, retain the full 16-cell expectation.
3. Keep `summary.json` as the existing sorted array so downstream consumers do
   not need a migration.
4. `render-html.py` reads the sibling manifest and renders/counts only selected
   topologies, paths, and configurations. Hide irrelevant filter choices and
   omit empty chart/table groups. A two-cell focused run must say two runs and
   zero missing.
5. `collect.sh` must not list directories that contain no run JSON. Failed
   cells with valid stub JSON remain visible and counted. Historical manifests
   are optional.

## Opt-in profile

1. Add `--profile` to `run-matrix.sh`. Require the final filtered selection to
   contain `rs-tun`; reject `--profile` in dry-run only if the profile workflow
   itself cannot be represented by a deterministic stub/self-test.
2. Pass the option explicitly to `run-config.sh`; do not use an ambient setting
   that can accidentally profile unrelated configurations. Non-`rs-tun`
   configurations ignore no profile state because they never receive it.
3. On the `rs-tun` server, verify/install the distro `perf` package before
   starting the profile workload. Fail the `rs-tun` cell with a clear stub if
   profiling was requested but cannot be prepared; never silently emit a
   normal result without the requested profile.
4. Run the normal P1/P10/P100 throughput, latency, footprint, and JSON emission
   unchanged. After those measurements and before daemon cleanup, run one
   additional P10 reverse/download iperf workload solely for profiling.
5. Attach `perf record` to the server `rustscaled` PID at 199 Hz with call
   graphs. Start recording before the extra iperf workload, cover its complete
   duration, wait for recording to finish, then generate local artifacts under
   `<results>/profile/`:
   - `perf.data` (compressed transfer is acceptable);
   - `perf-children.txt` with inherited cost;
   - `perf-self.txt` without children;
   - `metadata.json` containing commit, topology/path/config, profiled parallel
     count, duration, frequency, PID/command, and matching result JSON path.
6. A profile failure must still run the existing daemon/TUN cleanup before the
   cell returns. The matrix EXIT trap remains the final VM/tailnet safety net.
7. Do not include the profile-only P10 run in throughput, latency, CPU/RSS, or
   dashboard values.

## Tests

- Aggregate a focused two-cell fixture with a manifest: no missing warnings,
  two sorted results, and unchanged result objects.
- Remove one expected focused cell: exactly one missing warning.
- Aggregate the same fixture without a manifest: retain historical full-matrix
  missing behavior.
- Render the focused fixture: only same-zone/direct and the two selected
  configs appear; the header reports zero missing.
- `collect.sh` omits a zero-JSON aborted directory but retains a failed stub.
- Shell self-tests cover `--profile` validation, exact run-config propagation,
  profile command ordering, the extra P10 workload, artifact names, and cleanup
  on profile failure without invoking GCP or `perf`.

## Validation

- `bash -n tools/bench/gcp/*.sh`
- `python3 -m py_compile tools/bench/gcp/aggregate.py
  tools/bench/gcp/render-html.py`
- `tools/bench/gcp/run-matrix.sh --self-test`
- `tools/bench/gcp/run-config.sh --self-test`
- Focused dry runs for `rs-tun,ts-tun` and `rs-tun --profile`.
- Render the retained `gcp-20260713-082348` results with a focused manifest and
  verify no false missing state.
- Run a live same-zone direct `rs-tun --profile`, verify direct CLI gating,
  nonempty profile artifacts, result JSON, and complete cloud cleanup.
- `git diff --check`
