# Focused benchmark CLI parity

## Problem

The focused `rs-tun,ts-tun` run on 2026-07-13 exposed two benchmark ownership
and CLI parity failures:

- Installing the Tailscale package starts the system `tailscaled`, which owns
  `/dev/net/tun` and `tailscale0` before either measured daemon starts.
- Rustscale accepts `ping --count`, while the installed Tailscale CLI accepts
  `ping --c`. The shared benchmark command therefore failed on Tailscale.

## Required changes

1. In GCP VM startup, stop and disable the package-managed `tailscaled` after
   package installation. Remove stale state needed to guarantee that no
   `tailscaled` process or `tailscale0` interface remains before writing
   `/tmp/startup-done`; fail startup if the invariant cannot be established.
2. Make `rustscale ping` accept Tailscale-compatible `--c` and `--c=<count>`.
   Retain the existing `--count` and `-c` spellings for compatibility.
3. Make both TUN benchmark gates use the identical CLI shape:
   `ping --until-direct --c=120 <ip>` for direct and
   `ping --until-direct=false --c=1 <ip>` for DERP.
4. Avoid SSH retries when the optional benchmark `iperf3` process is already
   absent during cleanup.

## Acceptance

- CLI parser tests cover all count spellings and invalid values.
- Benchmark command-shape tests assert the same ping arguments for Rustscale
  and Tailscale.
- Startup/cleanup behavior has a focused test or a testable command helper.
- `tools/bench/gcp/run-config.sh --self-test` and
  `tools/bench/gcp/run-matrix.sh --self-test` pass.
- Focused CLI tests and `tools/check.sh --check --no-test` pass.
- A fresh same-zone direct `rs-tun,ts-tun` run owns both daemons explicitly and
  produces path-gated results.
