# Phase: CLI ping DERP bootstrap

## Evidence

During the focused run `gcp-20260713-085426`, the first production Rustscale
`ping --until-direct --c=120` command returned only five-second timeouts for
several minutes even though both peers were online and present in magicsock. A
retry of the same command then reached direct and the benchmark succeeded. The
next fresh run reached direct promptly, confirming that the failure is
intermittent bootstrap state rather than a persistent tunnel failure.

`Magicsock::cli_ping` sends a DERP disco ping only when
`Endpoint::derp_send_region()` is positive. API-only tailnets may report
`HomeDERP=0`; the normal WireGuard send path already handles this by fanning out
through `send_via_derp`, but CLI ping does not. If UDP candidates are also not
usable yet, each CLI attempt waits its full five-second timeout without sending
a relay bootstrap probe.

The benchmark currently uses `--c=120`. With Rustscale's compatible five-second
per-ping timeout and one-second retry delay, a failed gate can take about twelve
minutes. This is too long for a focused benchmark failure bound.

## Scope

1. In `crates/magicsock`, make CLI disco ping use the same DERP routing
   semantics as normal datagrams:
   - a known positive DERP region sends to that region;
   - region zero fans out to the connected and DERP-map regions already used by
     `send_via_derp`;
   - keep one CLI request id and pending ping for the sealed disco packet;
   - direct candidate pings remain independent and unchanged;
   - send failures continue to resolve through the existing CLI timeout/error
     contract.
2. Reuse the existing DERP fanout implementation rather than maintaining a
   second region-selection algorithm. Adjust misleading data-specific debug
   wording if necessary, without changing behavior.
3. Add focused deterministic coverage that proves a zero-region CLI ping uses
   the fanout-capable send path and a known region remains targeted. Prefer a
   small pure routing helper if the existing DERP transport is not practical to
   instantiate in a unit test.
4. In `tools/bench/gcp/run-config.sh`, retain matching Rustscale and Tailscale
   product CLI commands with `--until-direct`, but reduce the direct retry count
   from 120 to 30. Keep the default compatible per-ping timeout. The resulting
   worst-case gate is about three minutes. Update command-shape self-tests.
5. Do not change Rustscale CLI flag parsing, output text, default ping count,
   LocalAPI schemas, result classification, throughput/latency measurement, or
   DERP-only gate behavior.

## Invariants

- Register the CLI callback and endpoint pending ping before any send.
- Never hold endpoint, DERP connection, or DERP map locks across `.await`.
- Do not leak callback entries after timeout.
- A DERP pong may complete the current CLI attempt; a later UDP pong must still
  confirm the endpoint's direct path as it does today.
- No auth key or tailnet credential may enter logs, metadata, or tests.

## Validation

- focused magicsock tests for known and unknown DERP routing
- `cargo test -p rustscale-magicsock`
- `cargo clippy -p rustscale-magicsock --all-targets -- -D warnings`
- `tools/bench/gcp/run-config.sh --self-test`
- `tools/bench/gcp/run-matrix.sh --dry-run --topology same-zone --path direct --config rs-tun,ts-tun`
- `RUST_TEST_THREADS=1 tools/check.sh`
- `git diff --check`

## Non-goals

- changing the first-pong callback/oneshot contract
- heartbeat policy changes
- reSTUN implementation
- persistent LocalAPI HTTP connections
- dataplane receive batching or GRO
