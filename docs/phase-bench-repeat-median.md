# Phase: Repeatable focused TUN benchmarks

## Context

The production GCP TUN harness now starts both products through their normal
daemons and gates direct runs with the same `ping --until-direct` CLI command.
The retained `rs-tun` results still vary enough between otherwise similar runs
that a single ten-second iperf sample cannot prove a dataplane improvement. The
Linux TCP GRO run, for example, reduced receiver `writev` CPU substantially but
had mixed P1/P10/P100 throughput.

## Scope

Make focused production TUN runs statistically useful without adding a second
benchmark driver or changing product startup, path gating, topology, VM, or
tailnet ownership.

1. Add `--repeat N` to `tools/bench/gcp/run-matrix.sh`. `N` must be an integer
   in `1..=9` and defaults to 3. Pass it explicitly to every selected
   `run-config.sh` cell as `--repeat N`; do not use an ambient environment
   variable.
2. Extend `run-config.sh` option parsing so `--profile` and `--repeat N` are
   order independent. Reject duplicates, missing values, invalid ranges, and
   unknown options. Preserve the direct CLI gate exactly: both products run
   their own `ping --until-direct` before any measured traffic.
3. For production TUN measurement, run one three-second reverse P1 warmup after
   the path gate and before footprint sampling. The warmup is excluded from all
   result fields. Fail the cell if it fails; do not report cold-start data.
4. For each existing parallelism (1, 10, 100), run `N` reverse iperf samples
   using the existing ten-second duration. Keep the loop grouped by
   parallelism, insert the existing settle delay between samples, and reject a
   zero/invalid sample rather than letting it bias the aggregate.
5. Preserve each throughput row's existing `parallel`, `mbps`, and
   `duration_s` fields. Set `mbps` to the median of the successful raw samples
   and add `samples_mbps` in execution order plus `statistic: "median"`. With
   an even count, use the arithmetic mean of the middle two values.
6. Record the selected repeat count and warmup shape in `matrix.json` without
   changing its selected topology/path/config arrays. Readers that only know
   schema version 1 must continue to work; extra manifest fields are metadata.
7. Apply the same warmup, repeat loop, validation, and result row shape to
   `rs-tun` and `ts-tun`. Do not change userspace workloads in this phase.
8. Keep the profile-only P10 workload separate and excluded from normal
   results. Add the repeat count to profile metadata, but do not repeat the
   profiling workload.

## Tests

- Matrix self-tests cover the default, explicit propagation, invalid values,
  and a selected mixed Rust/Tailscale TUN matrix.
- Run-config self-tests cover option order, rejection cases, warmup ordering,
  exact sample count, median behavior for odd/even inputs, zero-sample failure,
  and unchanged `ping --until-direct` command parity.
- Existing focused manifest/dashboard fixtures continue to pass with both old
  and enriched throughput rows.
- Dry-run stubs contain the selected repeat count and deterministic median/raw
  sample fields without invoking GCP.

## Validation

- `bash -n tools/bench/gcp/*.sh`
- `python3 -m py_compile tools/bench/gcp/*.py`
- `tools/bench/gcp/run-matrix.sh --self-test`
- `tools/bench/gcp/run-config.sh --self-test`
- Focused dry runs with default repeats and `--repeat 1 --profile`
- `tools/check.sh`
- `git diff --check`
- After merge, run same-zone/direct `rs-tun --profile --repeat 3`, verify all
  raw samples, medians, direct CLI evidence, profile artifacts, and complete
  VM/tailnet cleanup.

## Non-goals

- Changing iperf duration, direction, or parallelism.
- Restarting daemons between samples.
- Adding a new result aggregation service or statistics dependency.
- Claiming TCP GRO throughput improvement from the earlier single run.
