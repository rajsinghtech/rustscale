# Phase: CLI-gated direct TUN benchmark

## Goal

Make the GCP TUN comparison exercise the shipped daemons and CLIs with the
same workflow on both sides. A direct benchmark must not start until the
product CLI has observed a direct path. Remove benchmark-only readiness and
path-label assumptions from the TUN cases.

This phase does not remove the userspace/tsnet benchmark. The direct TUN
comparison is the priority because it produced the current 2,507 Mbps versus
35 Mbps result.

## Required CLI compatibility

Match the behavior in Tailscale's
`cmd/tailscale/cli/ping.go`:

- `--until-direct` defaults to true for disco pings.
- Accept `--until-direct=false` as well as `--until-direct=true`.
- `--count`, `-c`, `--count=N`, and `-c=N` are accepted. A count of zero means
  retry indefinitely.
- Accept `--timeout`, `--timeout=N`, and Go-style duration values such as
  `5s`, `500ms`, and `1m`. Apply the timeout to each LocalAPI ping request.
- If the maximum count is reached after one or more non-direct pongs while
  `--until-direct` is enabled, exit non-zero with
  `direct connection not established`.
- If no ping receives a reply, exit non-zero with `no reply`.
- Preserve the existing Go-compatible pong output because the benchmark uses
  it as an auditable path record.
- Add focused parser/behavior tests. Parsing must return errors for malformed
  values and unknown flags rather than silently substituting defaults.

## TUN benchmark workflow

Update `tools/bench/gcp/run-config.sh` and the matrix/retry build commands:

1. Build and run the production `rustscaled` and `rustscale` binaries for
   `rs-tun`; do not run the `rustscale-tun` example.
2. Start `rustscaled run --tun` with an explicit state directory, socket,
   hostname, and `TS_AUTHKEY`, mirroring `tailscaled` plus `tailscale up` as
   closely as the current daemon lifecycle permits.
3. Discover each server IP through its product CLI (`rustscale ip -4` or
   `tailscale ip -4`), not log markers.
4. Before iperf or kernel ICMP latency in a direct scenario, run the client
   product CLI against the server IP with `ping --until-direct --count=120`.
   Capture its output. If it does not establish direct, emit a failed result
   and do not record throughput.
5. For DERP scenarios, run one product CLI ping with
   `--until-direct=false --count=1` and require output containing `via DERP`.
6. Set `path_class_reported` from the observed CLI output (`direct`, `derp`,
   or `peer-relay`), never from `PATH_TAG`.
7. Factor duplicated path-gating logic into small shell helpers shared by the
   rs-tun and ts-tun functions. Avoid adding another benchmark protocol or
   readiness marker.
8. Sample the production daemon PID and report the production daemon binary
   size for both implementations.
9. Cleanup must stop daemons and restore networking on all success and error
   paths.

The userspace configs may retain their embedded harness because they exercise
an embedding API rather than a system daemon. Do not expand their scope in
this phase.

## Validation

- `tools/check.sh rustscale-cli`
- `tools/check.sh rustscale-rustscaled`
- `bash -n tools/bench/gcp/run-config.sh`
- `bash -n tools/bench/gcp/run-matrix.sh`
- `bash -n tools/bench/gcp/run-matrix-samezone.sh`
- `bash -n tools/bench/gcp/run-samezone-retry.sh`
- Run the matrix dry-run and verify both TUN configs show the equivalent
  daemon, CLI IP lookup, CLI path gate, iperf, latency, and cleanup stages.

