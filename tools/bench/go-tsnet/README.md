# Pinned Go tsnet RSB1 endpoint

`go-tsnet-rsb1` is the embedded-Go cell for the matched benchmark matrix. It
pins `tailscale.com@v1.100.0` and runs the RSB1 listener/client directly inside
`tsnet.Server`. It does **not** start `tailscaled`, SOCKS5, Tailscale Serve, or a
kernel-TCP bridge.

The CLI mirrors the userspace portion of `rustscale-bench`:

```text
go-tsnet-rsb1 server  --authkey KEY --port 5201 --port-count 1 --hostname NAME --state-dir DIR
go-tsnet-rsb1 client  --authkey KEY --target IP:PORT --duration 10 --direction down --parallel 100 --hostname NAME --state-dir DIR --json
go-tsnet-rsb1 latency --authkey KEY --target IP:PORT --count 50 --hostname NAME --state-dir DIR --json
```

A supplied state directory is a non-ephemeral, restart-stable identity. Every
throughput result reports exact `established`, `handshaken`, and `completed`
counts. Timing starts only after all streams receive RSB1 ready and cross the
common GO barrier. Latency succeeds only with every requested, byte-exact
8-byte reply. Path class comes from the exact target peer in the embedded local
status. On RustScale, TCP dials and RSB1 header/ACK exchanges each use the
four-stream setup window. Pinned Go uses a bounded sixteen-stream window, far
below pinned gVisor `gonet`'s 4096-connection listen backlog, so P1000 setup
has room to finish inside the process deadline without recreating the failed
unbounded burst. Paid acceptance still requires exact P1000 completion. Setup
is outside the timed RSB1 data phase. Each requested stream is attempted once,
results retain request order, and any failure cancels pending
setup and closes every completed connection without publishing partial
measurements.

The matrix starts the long-lived server with one consecutive destination port
for the warmup, every measured process trial, and latency. Each restarted
client process receives a unique target, preventing its fresh userspace TCP
stack from reusing a four-tuple that the peer still owns. `--port-count`
defaults to one for ordinary standalone use and accepts at most 1024 ports.

Credential-free checks:

```bash
go mod verify
go test ./...
go vet ./...
```

The GCP harness additionally records the executable path, `--version`, SHA-256,
the pinned native Go archive name and SHA-256, module checksum, endpoint process
scope, CPU, and RSS. Rust and pinned Go/gVisor both use 1 MiB TCP send and
receive buffers per socket for the matched userspace cells.
See [`docs/benchmarks.md`](../../../docs/benchmarks.md) for the five-cell
contract and the separately labeled tailscaled daemon-proxy evidence.
