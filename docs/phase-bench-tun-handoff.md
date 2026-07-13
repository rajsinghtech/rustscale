# Phase: Focused TUN benchmark handoff

## Evidence

The corrected `same-zone/direct` run at `bench-results/gcp-20260713-022244`
proved Rustscale reached a direct path and measured 391.39 Mbps best throughput,
1.03 ms p50 latency, 14.4 MB RSS, and a 12.48 MB daemon binary. The following
Tailscale configuration failed because `tailscale0` was still busy. The current
Rustscale cleanup waits 20 seconds but exits success even when the daemon or TUN
remains, hiding the handoff failure.

## Scope

1. Harden `cleanup_rs_tun` in `tools/bench/gcp/run-config.sh`.
   - Send TERM to the PID and matching `rustscaled` processes.
   - Wait a short bounded interval for both process exit and `tailscale0` removal.
   - If still present, capture useful process/TUN ownership diagnostics, send KILL,
     and wait again.
   - Return failure if the process or interface is still present after the forced
     cleanup. Do not silently continue into Tailscale with a busy device.
   - Keep cleanup idempotent when files, processes, or interfaces are absent.
2. Make the default focused comparison substantially faster while preserving a
   single-flow, moderate-parallel, and high-parallel signal:
   - iperf parallelism: 1, 10, 100
   - duration: 10 seconds
   - latency samples: 50, using a 0.1-second ping interval
   - Ensure result and stub JSON are generated from the configured parallelism,
     duration, and latency count rather than duplicated hard-coded arrays.
3. Preserve CLI `--until-direct` gates and observed path classification exactly.
4. Add shell self-tests or a dry-run test that covers successful graceful cleanup,
   forced cleanup, cleanup failure, and the new result shape where practical.

## Acceptance

- `bash -n tools/bench/gcp/run-config.sh tools/bench/gcp/run-matrix.sh`
- `GCP_DRY_RUN=1` exercises the focused result shape without cloud access.
- Existing benchmark CLI/path classifier self-tests still pass.
- No production Rust crates should change in this phase.
