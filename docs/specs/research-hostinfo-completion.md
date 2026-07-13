# Hostinfo completion + ktimeout/envknob wiring

## Part A — Hostinfo field inventory

### Already populated (actual status ~37/42)

All fields below are populated in `crates/tsnet/src/hostinfo.rs` (either
`populate_hostinfo` for platform detection or `apply_runtime_fields` for
runtime-derived state), plus the inline `Hostinfo { .. }` literals in
`crates/tsnet/src/link_monitor.rs` and `crates/tsnet/src/lifecycle.rs`.

| Field | Where populated | Notes |
|---|---|---|
| `IPNVersion` | `populate_hostinfo` | `CARGO_PKG_VERSION` |
| `Package` | `populate_hostinfo` | `"tsnet"` |
| `App` | `populate_hostinfo` | `"tsnet"` (override via `HostinfoOverrides`) |
| `GoArch` | `populate_hostinfo` | `std::env::consts::ARCH` |
| `GoArchVar` | `populate_hostinfo` | runtime `target_feature` detection (v1–v4, SVE, GOARM) |
| `GoVersion` | `populate_hostinfo` | `option_env!("RUSTC_VERSION")` |
| `OS` | `populate_hostinfo` | `std::env::consts::OS` |
| `OSVersion` | `populate_hostinfo` | `uname -r` (Linux), `kern.osproductversion` (macOS) |
| `Machine` | `populate_hostinfo` | `uname -m` → `arm64`/`amd64` mapping |
| `Distro` | `populate_hostinfo` | `/etc/os-release` |
| `DistroVersion` | `populate_hostinfo` | `/etc/os-release` |
| `DistroCodeName` | `populate_hostinfo` | `/etc/os-release` |
| `Container` | `populate_hostinfo` | `/.dockerenv`, `/run/.containerenv`, `/proc/1/cgroup` |
| `Env` | `populate_hostinfo` | env-var heuristics (Knative, Lambda, Heroku, …) |
| `Desktop` | `populate_hostinfo` | `/proc/net/unix` X11/wayland check |
| `DeviceModel` | `populate_hostinfo` | Synology, RPi, macOS hw.model |
| `Cloud` | `populate_hostinfo` | DMI BIOS vendor detection |
| `Userspace` | `populate_hostinfo` + `apply_runtime_fields` | `OptBool::True` for tsnet |
| `Hostname` | bootstrap literal + `RuntimeHostinfo` | from config / OS |
| `RoutableIPs` | bootstrap literal | from advertise routes |
| `NetInfo` | bootstrap literal | from netcheck/STUN |
| `Services` | hostinfo hook + `collect_hostinfo` | from serve config + portlist |
| `ServicesHash` | `collect_hostinfo` | hash of serialized Services |
| `ShieldsUp` | `apply_runtime_fields` | from `Prefs::ShieldsUp` |
| `ExitNodeID` | `apply_runtime_fields` | from route table |
| `IngressEnabled` | `apply_runtime_fields` | from serve runner |
| `WireIngress` | `apply_runtime_fields` | from serve runner (only when `!IngressEnabled`) |
| `AllowsUpdate` | `apply_runtime_fields` | from `Prefs::AutoUpdate` |
| `AppConnector` | `apply_runtime_fields` | from `Prefs::AppConnector.Advertise` |
| `RequestTags` | `apply_runtime_fields` | from `Prefs::AdvertiseTags` |
| `SSH_HostKeys` | `apply_runtime_fields` | from `RuntimeHostinfo` (currently always empty in `link_monitor.rs`) |
| `NoLogsNoSupport` | `apply_runtime_fields` | from `RuntimeHostinfo` (currently always `false` in `link_monitor.rs`) |
| `ShareeNode` | `apply_runtime_fields` | from `RuntimeHostinfo` (currently always `false` in `link_monitor.rs`) |
| `UserspaceRouter` | `apply_runtime_fields` | `OptBool::True` for tsnet |
| `PeerRelay` | `apply_runtime_fields` | from `RuntimeHostinfo` (currently always `false` in `link_monitor.rs`) |

### Genuinely missing (5 fields)

#### 1. `FrontendLogID` / `BackendLogID`

**Go source** (`ipn/ipnlocal/local.go:3054-3055`):
```go
hostinfo.BackendLogID = b.backendLogID.String()
hostinfo.FrontendLogID = opts.FrontendLogID
```

**Go plumbing** (`ipn/ipnlocal/local.go:244,631`):
```go
backendLogID   logid.PublicID   // stored on LocalBackend

// in NewLocalBackend (line 631):
backendLogID: logID,
```

**Go logid type** (`types/logid/id.go`):
- `PrivateID` = 32-byte random, `NewPrivateID()` via `crypto/rand`
- `PublicID` = SHA-256 of PrivateID, access via `privateID.Public()`
- Serialized as hex string via `.String()`
- The `PrivateID` is persisted to disk (tsnet creates via `logpolicy.NewConfig`)

**Rust status**: crates/logtail has no equivalent of `logid::PublicID`. FrontendLogID/BackendLogID are `String` fields on Hostinfo but never set.

**Recommended action — IMPLEMENT NOW**:
1. Create `crates/logid` (or add to `crates/key`) with `PrivateID([u8; 32])` and `PublicID([u8; 32])` types, where `PublicID = sha256(PrivateID)`, with hex serialization.
2. Store the `PrivateID` in the tsnet state directory (persisted across restarts, like Go's `logpolicy.Config.Save`/`Load`).
3. In the bootstrap path (`lifecycle.rs`), generate/load the PrivateID on `Server::up`, derive `PublicID`, store it in the server state.
4. In `spawn_hostinfo_update_loop` (`link_monitor.rs`), add `backend_log_id: String` to the parameters and pass it through `RuntimeHostinfo`.
5. Use `HostinfoOverrides` for `FrontendLogID` (caller-supplied, like Go's `opts.FrontendLogID`).

#### 2. `PushDeviceToken`

**Go source** (`ipn/ipnlocal/local.go:5711`):
```go
hi.PushDeviceToken = b.pushDeviceToken.Load()
```

Loaded from an `atomic.Value` that is set by platform-specific push notification
registration (APNs on macOS/iOS, FCM on Android). Not used on Linux/tsnet.

**Recommended action — SKIP**: Requires platform notification APIs (APNs, FCM).
tsnet on Linux/server has no push notification path. Add to `RuntimeHostinfo` as
`push_device_token: String` with default empty, leave unwired. The TODO at
hostinfo.rs:318 already acknowledges this.

#### 3. `WoLMACs`

**Go source** (`feature/wakeonlan/wakeonlan.go:169-206`):
```go
func getWoLMACs() (macs []string) {
    switch runtime.GOOS {
    case "ios", "android": return nil
    }
    if s := wakeMAC(); s != "" {
        switch s {
        case "auto":
            ifs, _ := net.Interfaces()
            for _, iface := range ifs {
                if iface.Flags&net.FlagLoopback != 0 { continue }
                if iface.Flags&net.FlagBroadcast==0 || iface.Flags&net.FlagRunning==0 || iface.Flags&net.FlagUp==0 { continue }
                if keepMAC(iface.Name, iface.HardwareAddr) { macs = append(macs, iface.HardwareAddr.String()) }
                if len(macs) == 10 { break }
            }
            return macs
        case "false", "off": return nil
        }
        mac, err := net.ParseMAC(s)
        if err != nil { return nil }
        return []string{mac.String()}
    }
    return nil
}
```

Where `wakeMAC()` reads the env var:
```go
var wakeMAC = envknob.RegisterString("TS_WAKE_MAC")
```

**Recommended action — IMPLEMENT NOW (simple)**:
1. Add `crates/envknob::{string}` call for `"TS_WAKE_MAC"`.
2. In `apply_runtime_fields` (or a dedicated function), enumerate non-loopback/up/running interfaces using `std::net::NetworkInterface` (or platform net-interface crate like `if-addrs`).
3. Populate `hi.WoLMACs` with up to 10 MAC addresses.
4. Or: add `wol_macs: Vec<String>` to `RuntimeHostinfo`, compute from the
   `RuntimeHostinfo` construction site, matching existing pattern.

The env-knob lookup belongs in the tsnet server init (read the env var at boot
and pass through), and the interface enumeration can be done in
`spawn_hostinfo_update_loop` or factored into a pure helper.

#### 4. `TPM`

**Go source** (`feature/tpm/tpm.go:85-147`):
- Opens `/dev/tpm0` (or `/dev/tpmrm0`) via `tpm2.Open()`
- Queries TPM properties: manufacturer, vendor strings, spec revision, model,
  firmware version, family indicator
- Uses `go-tpm` library (`github.com/google/go-tpm`)
- Wrapped in `sync.OnceValue(info)` so the costly probe runs once

**Recommended action — SKIP**: Requires Linux TPM device access (`/dev/tpm0`),
a Rust TPM 2.0 library (`tss-esapi` or similar), and is unused in the tsnet
scenario (servers without discrete TPMs). Mark in `RuntimeHostinfo` and leave
as TODO. The comment at hostinfo.rs:318 already covers this.

#### 5. `StateEncrypted`

**Go source** (`ipn/ipnlocal/local.go:9133-9153`):
```go
func (b *LocalBackend) stateEncrypted() opt.Bool {
    switch runtime.GOOS {
    case "android", "ios": return opt.NewBool(true)
    case "darwin":
        switch {
        case version.IsMacAppStore(): return opt.NewBool(true)
        case version.IsMacSysExt():
            sp, _ := b.polc.GetBoolean(pkey.EncryptState, true)
            return opt.NewBool(sp)
        default: return opt.NewBool(false)
        }
    default:
        _, ok := b.store.(ipn.EncryptedStateStore)
        return opt.NewBool(ok)
    }
}
```

**Recommended action — IMPLEMENT NOW (trivial, but only for macOS)**:
On macOS, detect if state is in Keychain (the `tsnet` state dir is a plain file
on disk, so not encrypted). For now, always report `OptBool::False` on non-Apple
platforms and `OptBool::False` on macOS too (since tsnet stores state in a file,
not the Keychain). This is the correct answer because rustscale's tsnet doesn't
use `EncryptedStateStore`. Add a default to `RuntimeHostinfo`.

#### 6. `Location`

**Go source**: Only set on *peer* nodes by the control server, never on the
local node's own Hostinfo. The field is `*Location` (pointer) on the Go struct.

**Recommended action — SKIP**: Not applicable for the local node. No code
needed.

### Updated parity.md claim

The correct count is ~37/42 fields populated after the work above. Only
`PushDeviceToken`, `TPM`, `Location` are intentionally skipped. `FrontendLogID`,
`BackendLogID`, `WoLMACs`, `StateEncrypted` should be implemented now.

---

## Part A wiring — how fields reach `RuntimeHostinfo` today

The single production path is `spawn_hostinfo_update_loop` in
`crates/tsnet/src/link_monitor.rs`. It constructs `RuntimeHostinfo` at lines
285-299:

```rust
let rt = RuntimeHostinfo {
    exit_node_id: exit_node_id.clone(),
    ingress_enabled,
    wire_ingress,
    shields_up: prefs.ShieldsUp,
    app_connector: prefs.AppConnector.Advertise,
    request_tags: prefs.AdvertiseTags.clone(),
    no_logs_no_support: false,
    allows_update: prefs.AutoUpdate.unwrap_or(false),
    sharee_node: false,
    ssh_host_keys: Vec::new(),
    userspace: true,
    userspace_router: true,
    peer_relay: false,
};
```

Prefs are loaded from disk inside the same function (line 281-284):
```rust
let prefs = state_dir.as_ref()
    .and_then(|d| rustscale_ipn::Prefs::load(d).ok())
    .unwrap_or_default();
```

**What the coding agent needs to add**:
1. `RuntimeHostinfo` struct (`hostinfo.rs:234-268`): add fields `backend_log_id: String`, `frontend_log_id: String`, `wol_macs: Vec<String>`, `state_encrypted: OptBool`. Keep defaulting to empty/false/unset.
2. `apply_runtime_fields`: add assignments for these 4 new fields.
3. `link_monitor.rs:285-299`: wire from new function parameters.
4. `lifecycle.rs` bootstrap path: ensure the log ID flows through from Server startup.

---

## Part B — ktimeout wiring

### What `ktimeout` provides

`crates/ktimeout/src/lib.rs`:
- `set_user_timeout(fd, Duration)` — `setsockopt(fd, SOL_TCP, TCP_USER_TIMEOUT)` (Linux)
- `user_timeout_control(Duration)` — returns `impl Fn(&TcpStream) -> io::Result<()>` for use with `TcpBuilder` or `TcpStream::set_nonblocking` patterns.

### Go call site

**Single production caller**: `cmd/derper/derper.go:320-326`:

```go
lc := net.ListenConfig{
    Control:   ktimeout.UserTimeout(*tcpUserTimeout),  // 15s default
    KeepAlive: *tcpKeepAlive,                           // 10min
}
lc.SetMultipathTCP(false)   // MPTCP + TCP_USER_TIMEOUT incompatible
```

This wraps every accepted DERP connection with a 15-second user timeout (if the
peer stops ACKing data, the kernel kills the connection within 15s). The
10-minute keepalive is long — the user timeout is the primary dead-peer
detection mechanism for the DERP server.

### Rustscale target: DERP server TCP listener

`crates/derp/src/server.rs` (or `crates/derp/src/derp_http.rs`) — search for
`TcpListener` or `tokio::net::TcpListener` creation. The 15-second user timeout
must be applied to the listener or the accepted streams.

**Wiring pattern**:
```rust
use crate::ktimeout::{user_timeout_control, set_user_timeout};
use std::time::Duration;

let timeout = Duration::from_secs(15);
// Option A: after accept(), on the TcpStream
let ctrl = user_timeout_control(timeout);
ctrl(&accepted_stream)?;

// Option B: using socket2 to set before listen
//   socket2::Socket::new(...).set_tcp_user_timeout(timeout)?
```

Apply before handing the stream to TLS/TCP framing.

### Non-DERP listeners

Go's `tsnet` or `LocalBackend` does NOT apply `ktimeout` to non-DERP listeners.
The only production use is `cmd/derper`. If rustscale's tsnet has an HTTP server
listener that serves DERP, it should use `ktimeout`. Other tsnet listeners
(serve/funnel/peerapi) do NOT need it per Go precedent.

---

## Part C — envknob wiring

### How `crates/envknob/src/lib.rs` works

Two API forms:
- **Global**: `envknob::bool("TS_NO_LOGS_NO_SUPPORT")` — reads env var each call, records access.
- **Registered**: `envknob::register_bool("TS_NO_LOGS_NO_SUPPORT")` — returns `impl Fn() -> Option<bool>`, caches at registration time, updates via `setenv()`.

Both handle `"true"/"1"/"t"/"T"` → `Some(true)`, `"false"/"0"/"f"/"F"` → `Some(false)`, unset → `None`.

### ~10 most impactful envknobs mapped to rustscale call sites

| Env var | Go location | Behavior | Rustscale target | Priority |
|---|---|---|---|---|
| `TS_NO_LOGS_NO_SUPPORT` | `hostinfo/hostinfo.go:66` → `envknob.NoLogsNoSupport()` | Sets hostinfo.NoLogsNoSupport=true | `crates/tsnet/src/hostinfo.rs` `populate_hostinfo()`: add `hi.NoLogsNoSupport = envknob::bool("TS_NO_LOGS_NO_SUPPORT").unwrap_or(false)` | **High** |
| `TS_ALLOW_ADMIN_CONSOLE_REMOTE_UPDATE` | `hostinfo/hostinfo.go:67` + `local.go:6628` | Sets hostinfo.AllowsUpdate (override with auto-update pref) | `crates/tsnet/src/hostinfo.rs` `apply_runtime_fields()`: add `hi.AllowsUpdate |= envknob::bool("TS_ALLOW_ADMIN_CONSOLE_REMOTE_UPDATE").unwrap_or(false)` | **High** |
| `TS_WAKE_MAC` | `feature/wakeonlan/wakeonlan.go` → envknob.RegisterString | Controls WoL MAC enumeration (auto/specific/false) | `crates/tsnet/src/hostinfo.rs` `RuntimeHostinfo` construction site: read env, enumerate interfaces | **High** (for WoLMACs) |
| `TS_DEBUG_USE_DERP_HTTP` | `derp/derphttp/derphttp_client.go:250` | Forces DERP client to use HTTP (no TLS) | `crates/derp/src/derp_http.rs` (client): check before selecting scheme/port | **Medium** (debug) |
| `TS_DEBUG_PERMIT_HTTP_C2N` | `control/controlclient/direct.go:1641` | Allows c2n callback over non-Noise HTTP | `crates/controlclient/src/direct.rs`: check before clearing c2n | **Medium** (dev safety) |
| `TS_DNS_FORWARD_SKIP_TCP_RETRY` | `net/dns/resolver/forwarder.go:617` | Skip TCP retry on truncated DNS responses | `crates/netstack/src/dns/forwarder.rs`: check before retrying | **Medium** |
| `TS_DEBUG_MAGIC_DNS_DUAL_STACK` | `net/dns/config.go:66` | Force dual-stack MagicDNS (IPv4+IPv6) | `crates/netstack/src/dns/config.rs`: check before building DNS IP list | **Medium** |
| `TSNET_FORCE_LOGIN` | `tsnet/tsnet.go:960` | Force re-login even if state is Running | `crates/tsnet/src/lifecycle.rs` bootstrap: check before skipping auth | **Medium** |
| `TS_PANIC_IF_HIT_MAIN_CONTROL` | `control/controlclient/direct.go:419` | Panic if connecting to prod control | `crates/controlclient/src/direct.rs` constructor: check server URL | **Low** (dev only) |
| `TS_DEBUG_PROXY_DNS` | `control/controlclient/direct.go:1588` | Force DNS Proxied=true in netmap | `crates/controlclient/src/map.rs`: check after building netmap | **Low** (debug) |

### Wiring pattern for each

**For `TS_NO_LOGS_NO_SUPPORT`** (hostinfo.rs `populate_hostinfo`):
```rust
use rustscale_envknob;

// Inside populate_hostinfo, around line 147:
if hi.NoLogsNoSupport.is_unset_or_false() { // or just always set it
    hi.NoLogsNoSupport = envknob::bool("TS_NO_LOGS_NO_SUPPORT").unwrap_or(false);
}
```

**For `TS_ALLOW_ADMIN_CONSOLE_REMOTE_UPDATE`** (hostinfo.rs `apply_runtime_fields`):
```rust
// Inside apply_runtime_fields, after the existing AllowsUpdate line:
hi.AllowsUpdate = hi.AllowsUpdate || envknob::bool("TS_ALLOW_ADMIN_CONSOLE_REMOTE_UPDATE").unwrap_or(false);
```

**For `TS_DEBUG_USE_DERP_HTTP`** (derp_http client):
Inside `Client::connect` or wherever the HTTPS scheme/port is chosen:
```rust
let use_https = !envknob::bool("TS_DEBUG_USE_DERP_HTTP").unwrap_or(false);
```

**For `TSNET_FORCE_LOGIN`** (lifecycle.rs bootstrap):
```rust
if state == ipn::State::NeedsLogin || envknob::bool("TSNET_FORCE_LOGIN").unwrap_or(false) {
    // call StartLoginInteractive
}
```

**For `TS_DEBUG_PERMIT_HTTP_C2N`** (controlclient):
```rust
// Before responding to c2n over non-Noise transport:
if !is_noise && !envknob::bool("TS_DEBUG_PERMIT_HTTP_C2N").unwrap_or(false) {
    log::warn!("refusing c2n ping without noise");
    return;
}
```

### Implementation order

1. **Do first (hostinfo.rs + link_monitor.rs)**: `TS_NO_LOGS_NO_SUPPORT`, `TS_ALLOW_ADMIN_CONSOLE_REMOTE_UPDATE`, `TS_WAKE_MAC` — these affect the Hostinfo wire payload, which matters for control-plane features.
2. **Do second (derp client)**: `TS_DEBUG_USE_DERP_HTTP` — relevant for DERP relay testing.
3. **Do third (tsnet lifecycle)**: `TSNET_FORCE_LOGIN` — simple check in bootstrap.
4. **Do fourth (controlclient)**: `TS_DEBUG_PERMIT_HTTP_C2N`, `TS_PANIC_IF_HIT_MAIN_CONTROL`, `TS_DEBUG_PROXY_DNS` — dev safety.
5. **Do fifth (dns)**: `TS_DNS_FORWARD_SKIP_TCP_RETRY`, `TS_DEBUG_MAGIC_DNS_DUAL_STACK` — if dns crate is ported.

---

## Files that need changes

### Part A (Hostinfo fields)

| File | Change |
|---|---|
| `crates/tsnet/src/hostinfo.rs` | Add `backend_log_id`, `frontend_log_id`, `wol_macs`, `state_encrypted` to `RuntimeHostinfo`. Add assignments in `apply_runtime_fields`. Add envknob check for `TS_NO_LOGS_NO_SUPPORT` in `populate_hostinfo`. Add envknob check for `TS_ALLOW_ADMIN_CONSOLE_REMOTE_UPDATE` in `apply_runtime_fields`. |
| `crates/tsnet/src/link_monitor.rs` | Wire new `RuntimeHostinfo` fields from function parameters. Read `TS_WAKE_MAC` env and enumerate interfaces for `wol_macs`. |
| `crates/tsnet/src/lifecycle.rs` | Pass `backend_log_id` (from persisted logid) into `spawn_hostinfo_update_loop`. Read `TSNET_FORCE_LOGIN`. |
| `crates/tsnet/src/server.rs` (or lib.rs) | Generate/load `PrivateID` on startup, compute `PublicID`, store hex string for backend_log_id. Accept `FrontendLogID` from caller. |
| (new) `crates/logid/src/lib.rs` | Types `PrivateID([u8;32])` + `PublicID([u8;32])` with SHA-256 derivation, hex serde, random generation. |

### Part B (ktimeout)

| File | Change |
|---|---|
| `crates/derp/src/server.rs` (or derp_http.rs) | Import `ktimeout::user_timeout_control` and apply 15s timeout to accepted `TcpStream` before handing to TLS/HTTP. |

### Part C (envknob wiring)

| File | Change |
|---|---|
| `crates/derp/src/derp_http.rs` | Add `TS_DEBUG_USE_DERP_HTTP` check before scheme/port selection. |
| `crates/controlclient/src/direct.rs` | Add `TS_DEBUG_PERMIT_HTTP_C2N`, `TS_PANIC_IF_HIT_MAIN_CONTROL` checks. |
| `crates/netstack/src/dns/config.rs` (if exists) | Add `TS_DEBUG_MAGIC_DNS_DUAL_STACK` check. |
| `crates/netstack/src/dns/forwarder.rs` (if exists) | Add `TS_DNS_FORWARD_SKIP_TCP_RETRY` check. |
