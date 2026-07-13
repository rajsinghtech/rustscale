# Phase: Simplify production benchmark execution

## Goal

Reduce GCP benchmark setup time and duplicated shell without changing the
measured workload, JSON schema, product CLI path gate, or cleanup guarantees.
Keep all four configurations available, but make filtered production TUN runs
pay only for the artifacts they use.

The clean `--config rs-tun` profile run still built `rustscale-bench` on both
VMs and spent 4m47s in the release build. A `ts-tun`-only run currently ships
the entire Rust source tree and builds three Rust binaries it never executes.
`run_rs_tun` and `run_ts_tun` also duplicate their iperf server, P1/P10/P100
sweep, kernel ping latency, footprint, binary-size, and result-JSON blocks.

## Config-aware build

Update `tools/bench/gcp/run-matrix.sh`:

1. Derive the Rust package list from the already validated, filtered `CONFIGS`
   array:
   - `rs-userspace` requires `rustscale-bench`.
   - `rs-tun` requires `rustscale-cli` and `rustscale-rustscaled`.
   - `ts-userspace` and `ts-tun` require no Rust source or build.
2. Deduplicate packages while preserving a deterministic command shape. When
   no Rust config is selected, skip both `deliver_source` calls and both
   remote builds and print one explicit skip message.
3. When any Rust config is selected, retain sequential source delivery and
   parallel server/client builds with the existing aggregation/failure policy.
4. Expand command-shape self-tests for each single config, the combined Rust
   configs, and a Tailscale-only selection. A full matrix must still build all
   three existing packages.

## Shared TUN measurement

Refactor only `tools/bench/gcp/run-config.sh` production TUN measurement:

1. Extract one helper used after `tun_path_gate` by both `run_rs_tun` and
   `run_ts_tun`. Parameterize the product label, whether remote commands need
   root, server IP, daemon PID file, footprint file, and binary path.
2. The helper must preserve exactly:
   - iperf3 reverse/download mode, port, duration, and P1/P10/P100 order;
   - the three-second inter-run delay;
   - kernel ICMP count/interval and latency parser;
   - production daemon PID sampling and binary size;
   - stderr milestone text with the appropriate `rs-tun`/`ts-tun` label.
3. Return the throughput, latency, footprint, and binary-size values to the
   caller without serializing and reparsing an intermediate result file.
   Bash globals with a clear helper-specific prefix are acceptable because
   `run-config.sh` executes only one config per process.
4. Extract one TUN result emitter parameterized by tool name. Preserve every
   field and type in the existing JSON schema and the final `wrote` milestone.
5. Keep product startup, CLI IP lookup, `ping --until-direct` classification,
   Rustscale cleanup/handoff status 86, Tailscale DNS restoration, and all
   failure stubs in their existing product-specific functions.

Do not combine the userspace harnesses, delete compatibility wrapper scripts,
extract a new Rust bench crate, or change benchmark parameters in this phase.

## Validation

- `bash -n tools/bench/gcp/run-matrix.sh tools/bench/gcp/run-config.sh`
- `tools/bench/gcp/run-matrix.sh --self-test`
- `tools/bench/gcp/run-config.sh --self-test`
- Dry runs for `--config rs-tun`, `--config ts-tun`, and
  `--config rs-userspace,rs-tun`; verify build/skip command milestones and all
  emitted result JSON files.
- Compare representative dry-run `rs-tun` and `ts-tun` JSON keys/types before
  and after the refactor.
- `git diff --check`
