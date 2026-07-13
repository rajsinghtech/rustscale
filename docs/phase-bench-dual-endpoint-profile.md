# Dual-endpoint rs-tun profiling

## Goal

Make the focused GCP `rs-tun` profile identify both halves of the measured
reverse P10 data path. The existing profile samples only the server-side
`rustscaled` process, so it cannot distinguish server transmit costs from
client receive, decrypt, and TUN-delivery costs.

This phase changes profiling evidence only. It must not change the normal
benchmark workload, result JSON schema, matrix selection rules, or CLI.

## Workload

Keep the existing extra profile workload:

```text
iperf3 -c <server-tailnet-ip> -p <port> -t <duration> -P 10 -R -J
```

The workload is intentionally outside `tun_measure` and the normal result
JSON. With `-R`, the server is the payload sender and the client is the
payload receiver.

## Required behavior

Implement the change in `tools/bench/gcp/run-config.sh` and its shell
self-tests.

1. `profile_prepare` installs or verifies `perf` on both the server and client
   VMs, preserving the existing idempotent package fallback behavior.
2. `profile_rs_tun` reads and validates both `/tmp/rs-tun-srv.pid` and
   `/tmp/rs-tun-cli.pid` as non-empty decimal process IDs.
3. Start `perf record -F 199 -g -p <pid>` on both endpoints before starting
   iperf. Use distinct remote filenames so cleanup and collection cannot mix
   endpoint data.
4. Wait for both perf processes with independent bounded waits. Capture each
   status explicitly; do not rely on `wait` with multiple job arguments to
   aggregate failures.
5. Generate children and self reports on both endpoints and require all six
   artifacts to exist and be non-empty. A partial profile must fail the
   profile cell rather than being represented as complete evidence.
6. Store artifacts under:

   ```text
   profile/server/perf.data
   profile/server/perf-children.txt
   profile/server/perf-self.txt
   profile/client/perf.data
   profile/client/perf-children.txt
   profile/client/perf-self.txt
   profile/metadata.json
   ```

7. Metadata must retain the existing commit, topology, path, config, duration,
   frequency, parallelism, and result reference and add:

   ```json
   {
     "workload_direction": "server_to_client",
     "reverse": true,
     "endpoints": {
       "server": {"pid": 1, "command": "rustscaled", "role": "sender"},
       "client": {"pid": 2, "command": "rustscaled", "role": "receiver"}
     }
   }
   ```

8. Cleanup is idempotent and runs against both endpoints on success and every
   failure path. It terminates only validated perf wrapper PIDs and removes
   endpoint-specific perf files. The client-side iperf JSON is removed from
   the client VM. Do not put an auth key in commands, metadata, logs, or local
   artifacts.
9. Preserve the current `--profile` UX: it remains valid only for exactly one
   selected `rs-tun` topology/path cell and runs after normal metrics.

## Self-test acceptance

Extend `profile_command_self_test` with endpoint-aware mocks and verify:

- both PID files are read and invalid PID input fails before the workload;
- two distinct perf records target the expected server and client PIDs;
- both perf records are issued before the iperf command;
- independent wait/report commands target both endpoint perf PID files;
- all six artifacts are copied into their endpoint subdirectories;
- missing or empty output from either endpoint fails profiling;
- workload or endpoint setup failure cleans both endpoints; and
- cleanup removes both endpoint filename sets from their correct VMs.

## Validation

Run:

```bash
bash tools/bench/gcp/run-config.sh --self-test
bash tools/bench/gcp/run-matrix.sh --self-test
tools/bench/gcp/run-matrix.sh --dry-run --topology same-zone --path direct --config rs-tun --profile
RUST_TEST_THREADS=1 tools/check.sh
```

After merge, run the live focused profile and verify the six non-empty perf
artifacts and metadata roles before using the reports to select a dataplane
optimization.
