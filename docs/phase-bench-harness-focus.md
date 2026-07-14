# Focused native benchmark harness

## Goal

Make the default GCP benchmark an exact same-zone, direct, production-TUN
comparison between RustScale and Tailscale, using the product CLIs to wait for
a direct path. Failures must remain attributable: a remote command failure is
not an SSH transport failure, a direct-path timeout is not a generic CLI
failure, and incomplete latency samples are not successful results.

This phase changes benchmark tooling only. Do not change Rust production code,
the product CLI, release/package work, or accepted benchmark artifacts.

## SSH execution contract

`tools/bench/gcp/lib.sh` currently retries every nonzero `ssh` status. Replace
that behavior with the following fail-closed contract:

1. A remote command status is returned immediately and is never retried.
2. Retry only SSH's transport-level status 255, at most three total attempts.
3. Preserve stdout, stderr, dry-run behavior, connection options, and callers'
   ability to inspect the original status.
4. Add a local self-test using a controlled fake SSH invocation. Prove that a
   remote status such as 1 or 124 runs once, status 255 can recover on a later
   attempt, and three status-255 attempts return 255. Tests must not sleep.
5. Update stale comments that say nonzero remote commands are retried.

## Focused matrix default

`tools/bench/gcp/run-matrix.sh` defaults to exactly:

- topology: `same-zone`;
- path: `direct`;
- configs, in order: `rs-tun,ts-tun`;
- parallelism: `1,10,100`;
- repeat: `3`.

Add a strict, duplicate-rejecting `--full` flag which restores the historical
two-topology, two-path, four-config matrix. Explicit `--topology`, `--path`, and
`--config` filters remain valid with either mode and select from the complete
allowed value set. Update help, header comments, dry-run behavior, and option
self-tests. The default dry-run manifest must contain exactly the two focused
cells. `--full --dry-run` must contain the historical 16 cells.

`--profile` with the focused defaults profiles only `rs-tun` after both normal
measurements, while retaining the existing one-topology/one-path restriction.

## Direct-path gate

For a direct TUN cell, invoke both product CLIs with identical ping arguments:

```text
ping --until-direct --c=0 TARGET
```

Wrap that remote command in one explicit 180-second GNU `timeout`, including a
short kill grace period. Retain the path transcript. Treat timeout status 124
as a distinct `direct-path-timeout` failure and other nonzero statuses as a
`path-cli-failed` failure; neither may be retried by the SSH layer. Only a
successful transcript classified as direct opens the throughput gate. DERP
cells keep `--until-direct=false --c=1` and require a DERP transcript.

Extend command-shape and path-gate self-tests to cover RustScale and Tailscale,
argument ordering, status propagation, timeout classification, and a
successful direct transcript. Do not infer directness from requested flags.

## Latency completeness

The production TUN latency sample requests exactly 50 replies. Parse ping
output into a result containing at least requested/transmitted, received,
loss, count, and p50/p95/p99 microseconds. The measurement fails unless all 50
replies are present and the summary is internally consistent. Zero or partial
reply sets must never reach a successful result.

`tools/bench/gcp/aggregate.py` must enforce the complete-sample fields for
current schema results. Update manifest/result fixtures and negative tests so
partial samples are rejected. Preserve historical partial rendering only
where its existing legacy contract explicitly allows it; do not label legacy
data as current-schema success.

## Remaining correctness cleanup

Fix the userspace DERP readiness check to compare elapsed time with the selected
`timeout` variable rather than the stale literal 180.

Replace `.github/workflows/bench.yml`'s three incomparable local tailnet runs
with a lightweight harness-validation workflow. It should run shell syntax,
the `run-config.sh` and `run-matrix.sh` self-tests, the manifest/aggregate tests,
and a representative focused dry-run without provisioning credentials or
installing Tailscale. Add one quiet `tools/bench/check.sh` entry point used by
CI and agents for the same local checks. It must clean temporary dry-run output
and print detailed output only on failure plus one concise success line.

## Verification

- `tools/bench/check.sh`
- `tools/bench/gcp/run-config.sh --self-test`
- `tools/bench/gcp/run-matrix.sh --self-test`
- a focused `--dry-run` proving exactly two expected cells
- a `--full --dry-run` proving exactly 16 expected cells
- `python3 tools/bench/gcp/test-manifest.py`
- `git diff --check`

Do not run a paid GCP benchmark in this phase. Do not commit or merge from the
coding-agent worktree; the orchestrator reviews and merges it.
