# Phase: tailscale-rs Benchmark Harness

## Goal

Add `tailscale-rs` (the official Tailscale Rust implementation at `../tailscale-rs`,
v0.4.0) as a third benchmark target alongside `rustscale-bench` and `tailscaled (Go)`.
Create a new crate `crates/bench-tsrs` that implements the same RSB1 wire protocol and
CLI as the existing `rustscale-bench`, but uses `tailscale::Device` instead of
`rustscale_tsnet::Server`. Add a runner script `tools/bench/run-tailscale-rs.sh`.

**Do NOT modify the tailscale-rs repo.** It is a read-only path dependency.

## File layout (all in rustscale repo)

```
crates/bench-tsrs/
  Cargo.toml          — depends on tailscale (path = "../../tailscale-rs"), tokio, clap, serde_json
  src/main.rs         — CLI: server / client / latency subcommands, JSON output
  src/protocol.rs     — RSB1 wire protocol (same as rustscale-bench, generic over AsyncRead/AsyncWrite)
  src/server.rs       — server mode: Device::new + tcp_listen + RSB1 handler
  src/throughput.rs   — client mode: Device::new + tcp_connect + throughput measurement
  src/latency.rs      — latency mode: Device::new + tcp_connect + ping-pong RTT
tools/bench/run-tailscale-rs.sh  — runner script (mirrors run-local.sh pattern)
```

Also: add `crates/bench-tsrs` to workspace members in root `Cargo.toml`.

## tailscale-rs API reference (v0.4.0, read from ../tailscale-rs/src/lib.rs)

### Device creation
```rust
use tailscale::{Config, Device};

// Config requires a key file (created if missing)
let mut config = Config::default_with_key_file(&key_file_path).await?;
config.requested_hostname = Some("bench-server".to_string());
config.control_server_url = url::Url::parse(&control_url)?;

// Auth key is Option<String>
let dev = Device::new(&config, Some(auth_key)).await?;

// Get tailnet IP
let ip = dev.ipv4_addr().await?;  // Ipv4Addr

// TCP listen
let listener = dev.tcp_listen((ip, port).into()).await?;  // tailscale::netstack::TcpListener

// TCP connect (auto-binds local tailnet IP + random ephemeral port)
let stream = dev.tcp_connect(remote_sockaddr).await?;  // tailscale::netstack::TcpStream

// Shutdown
dev.shutdown(Some(Duration::from_secs(10))).await;
```

### CRITICAL: env var requirement
tailscale-rs requires `TS_RS_EXPERIMENT=this_is_unstable_software` to be set or
`Device::new()` returns an error. The bench binary must set this in main() before
creating any Device:
```rust
std::env::set_var("TS_RS_EXPERIMENT", "this_is_unstable_software");
```

### Stream types
`tailscale::netstack::TcpStream` implements `tokio::io::AsyncRead + AsyncWrite`.
`tailscale::netstack::TcpListener` has `accept().await -> Result<TcpStream, Error>`.

### Key differences from rustscale
- No `Server::builder()` pattern — use `Config` + `Device::new()`
- No `Server::status()` or `Server::dial()` — use `dev.tcp_connect(SocketAddr)` directly
- No path class reporting — tailscale-rs doesn't expose magicsock path info
- DERP-only (no direct connections) per tailscale-rs README — path will be "derp"
- Config uses key file (PersistState) not state dir — use a temp file per process
- `tcp_connect` takes a `SocketAddr` — parse the target string to SocketAddr

## Wire protocol (same as rustscale-bench)

```
Header (client -> server, 14 bytes):
  magic [4]          = b"RSB1"
  mode  u8           = 0=throughput, 1=latency
  dir   u8           = 0=up, 1=down, 2=bidir (throughput only)
  duration_secs u32  = BE (throughput only)
  count u32          = BE (latency only)

Ack (server -> client, 4 bytes):
  magic [4]          = b"RSB1"
```

Constants:
- `FIREHOSE_BUF_SIZE = 1280` (MTU-sized write chunks)
- `READ_BUF_SIZE = 65535`
- `PING_SIZE = 8`

## CLI interface (must match rustscale-bench for runner script compatibility)

```
tsrs-bench server   --authkey <key> --port <port> [--hostname <name>] [--control-url <url>] [--state-dir <dir>]
tsrs-bench client   --authkey <key> --target <ip:port> --duration <secs> --direction <up|down|bidir> --parallel <n> [--hostname <name>] [--control-url <url>] [--state-dir <dir>] --json
tsrs-bench latency  --authkey <key> --target <ip:port> --count <n> [--hostname <name>] [--control-url <url>] [--state-dir <dir>] --json
```

The `--state-dir` flag maps to the key file path: `<state-dir>/tsrs_keys.json`.
If not provided, use a temp file.

Server mode must print these lines to stderr (same as rustscale-bench for the runner):
```
BENCH_IP <ip>
BENCH_PORT <port>
BENCH_READY 1
```

JSON output format must match rustscale-bench exactly (same field names) so the
runner script's jq queries work unchanged.

## Runner script: tools/bench/run-tailscale-rs.sh

Mirror `tools/bench/run-local.sh` but use `tsrs-bench` binary. Key changes:
- Binary: `target/release/tsrs-bench`
- Build: `cargo build -p tsrs-bench --release`
- Results saved to `bench-results/<timestamp>/tailscale-rs.json`
- JSON field `"tool"` = `"tsrs-bench"`
- Path class will be "derp" (tailscale-rs is DERP-only)
- Source `tools/bench/lib.sh` for ephemeral tailnet provisioning (same as run-local.sh)

## Cargo.toml for crates/bench-tsrs

```toml
[package]
name = "tsrs-bench"
description = "Throughput and latency benchmark harness for tailscale-rs"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true

[lints]
workspace = true

[dependencies]
tailscale = { path = "../../tailscale-rs" }
serde.workspace = true
serde_json.workspace = true
tokio.workspace = true
clap = { version = "4", features = ["derive"] }
```

Note: `tailscale` crate uses edition 2024 internally but that's fine — edition is
per-crate and cargo handles cross-edition path deps. The `tokio` feature is already
enabled in tailscale's dependencies (`ts_netstack_smoltcp` with `features = ["tokio"]`).

## Implementation notes

1. **Protocol module**: Make `write_header`, `read_header`, `write_ack`, `read_ack`
   generic over `T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin` instead of
   taking `NetstackStream` directly. This lets them work with `tailscale::netstack::TcpStream`.

2. **Server**: Create Device, get IP, listen, accept loop. For each connection, read
   header, send ack, then handle throughput or latency mode. Same logic as
   `crates/bench/src/server.rs`.

3. **Client/throughput**: Create Device, get IP, parse target to SocketAddr, dial,
   exchange header+ack, run firehose. Same measurement logic as
   `crates/bench/src/throughput.rs`. No path class — hardcode "derp".

4. **Latency**: Same ping-pong as `crates/bench/src/latency.rs`. No path class — hardcode "derp".

5. **No `wait_for_peer`**: tailscale-rs doesn't expose netmap/peer status. Just sleep
   a few seconds after Device::new before dialing.

6. **Key file handling**: Each process needs its own key file to avoid identity
   conflicts. Use `--state-dir` to determine the key file path: `<state-dir>/tsrs_keys.json`.
   If no state-dir, create a temp file.

7. **Parallel connections**: Same as rustscale-bench — dial N connections, run test
   on each concurrently.

## Acceptance criteria

```bash
cargo build -p tsrs-bench --release
cargo clippy -p tsrs-bench --all-targets
```

Both must pass with zero warnings (workspace lints are pedantic).

The runner script must work:
```bash
source .secrets/tailscale.env
tools/bench/run-tailscale-rs.sh
```

## Reference files in rustscale repo (read these for exact patterns)

- `crates/bench/src/main.rs` — CLI structure, JSON output format
- `crates/bench/src/protocol.rs` — RSB1 wire protocol
- `crates/bench/src/server.rs` — server handler logic
- `crates/bench/src/throughput.rs` — throughput measurement, sampling, stats
- `crates/bench/src/latency.rs` — latency ping-pong, percentile computation
- `tools/bench/run-local.sh` — runner script pattern
- `tools/bench/lib.sh` — ephemeral tailnet provisioning

## Reference files in tailscale-rs (read-only, do NOT modify)

- `../tailscale-rs/src/lib.rs` — Device API
- `../tailscale-rs/src/config.rs` — Config type
- `../tailscale-rs/examples/tcp_echo/main.rs` — TCP listener example
- `../tailscale-rs/ts_netstack_smoltcp_socket/src/tcp/stream.rs` — TcpStream impl
- `../tailscale-rs/ts_netstack_smoltcp_socket/src/tcp/listener.rs` — TcpListener impl
