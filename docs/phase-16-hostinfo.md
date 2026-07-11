# Phase 16: HostInfo / NodeUpInfo

Port the Go HostInfo self-description and NodeUpInfo structures — the metadata each node sends to the control plane so the coordination server knows the node's OS, environment, services, capabilities, and more.

## Goal

The control plane relies on `tailcfg.HostInfo` and `tailcfg.NodeUpInfo` to make routing decisions (e.g., should this node be an exit node?), display node metadata in the admin console, and detect environment changes. The Rust client currently sends a minimal or missing HostInfo. This phase populates it fully from the running system and wires it into the netmap update flow.

## CRITICAL: Stay strictly within scope

ONLY modify `crates/tailcfg` (add serialization for the already-existing types if needed) and `crates/controlclient` (populate and send HostInfo). Create a new module `crates/tsnet/src/hostinfo.rs` (or `crates/controlclient/src/hostinfo.rs`) that collects system metadata. Do NOT modify: magicsock, netstack, portmapper, derp, netmon, tun, filter, dns, wg.

## What to build

### 1. Ensure HostInfo types in tailcfg are complete

Check `crates/tailcfg/src/lib.rs` for `HostInfo` and `NodeUpInfo` structs. They should match `tailcfg.HostInfo` and `tailcfg.NodeUpInfo` from the Go source. Add any missing fields:

```rust
pub struct HostInfo {
    pub os: String,
    pub os_version: String,
    pub hostname: String,
    pub backend_process_name: Option<String>,
    pub env: Option<String>,
    pub container: Option<Vec<String>>,
    pub app: Option<String>,
    pub desktop: Option<String>,
    pub services: Vec<HostService>,
    pub ipn_version: Option<String>,
    pub frontend_log_id: Option<String>,
    pub backend_log_id: Option<String>,
    pub firewalls: Option<Vec<FirewallRule>>,
    pub public_key: Option<key::NodePublic>,
    pub device: Option<DeviceAttributes>,
    pub router: Option<RouterInfo>,
    pub etc: Option<String>,
    pub userspace: bool,
    pub userspace_router: bool,
    pub allow_local_lan: bool,
    pub client_version: Option<String>,
    pub daemon_version: Option<String>,
    pub daemon_supported: Option<String>,
    pub machine: Option<String>,
}

pub struct HostService {
    pub proto: HostServiceProtocol,
    pub port: u16,
    pub description: Option<String>,
}

pub struct FirewallRule {
    pub src: Vec<IpNet>,
    pub dst: Vec<IpNet>,
    pub allowed: bool,
}

pub enum HostServiceProtocol {
    Tcp,
    Udp,
    PeerApi,
    Unknown(String),
}
```

### 2. `crates/tsnet/src/hostinfo.rs` — populate from system

```rust
pub fn collect_hostinfo(log_id: &str, version: &str) -> HostInfo;
```

- OS: `std::env::consts::OS` (e.g. "linux", "macos", "windows")
- OS version: read from `/etc/os-release` (Linux) or `sw_vers` (macOS) or registry (Windows)
- Hostname: `gethostname()` or `/proc/sys/kernel/hostname`
- Services: read from the PeerAPI listener and any registered services
- Userspace: always `true`
- Client version: the crate version string
- env: match `$TS_ENV` or default `Some("dev")`

### 3. `crates/controlclient/src/hostinfo.rs` — update loop

```rust
pub fn start_hostinfo_update_loop(
    control_client: &Client,
    get_hostinfo: Arc<dyn Fn() -> HostInfo + Send + Sync>,
    interval: Duration,
);
```

- On initial connect: send HostInfo immediately
- Periodic refresh: every 10 minutes, or on network change notification
- On SIGUSR1 / forced refresh: resend immediately
- The Go implementation deduplicates by hash; start with always-send and add dedup later

### 4. Wire into tsnet::Server::up()

- Call `collect_hostinfo()` during startup
- Pass the result to `controlclient::Client` as the initial HostInfo
- Start the update loop

## Go references

- `/Users/rajsingh/Documents/GitHub/tailscale/tailcfg/tailcfg.go` — HostInfo struct (search for `HostInfo`)
- `/Users/rajsingh/Documents/GitHub/tailscale/hostinfo/hostinfo.go` — host info collection
- `/Users/rajsingh/Documents/GitHub/tailscale/hostinfo/hostinfo_linux.go` — Linux-specific
- `/Users/rajsingh/Documents/GitHub/tailscale/control/controlclient/direct.go` — where HostInfo is sent in netmap update

## Acceptance criteria

- `cargo build --workspace` passes
- `cargo test --workspace` passes
- `cargo clippy` passes
- HostInfo sent with every netmap update
- All major fields populated (OS, version, hostname, client version, services)
- Periodic refresh loop runs every 10 minutes
- Run build/test/clippy at the end and fix all errors

## Implementation order

1. Read Go HostInfo types and hostinfo package
2. Complete HostInfo type in crates/tailcfg
3. Create hostinfo collection module
4. Create update loop in controlclient
5. Wire into tsnet::Server startup
6. Run cargo build && cargo test && cargo clippy
