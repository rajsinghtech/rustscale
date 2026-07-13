# Router abstraction: porting Go's wgengine/router to Rust

## 1. Go `Router` interface

**Source:** `wgengine/router/router.go`

```go
type Router interface {
    Up() error
    Set(*Config) error
    Close() error
}
```

The `Config` struct (lines 106–140):

```go
type Config struct {
    LocalAddrs          []netip.Prefix       // our CGNAT + ULA IPs (typically /32 and /128)
    Routes              []netip.Prefix       // routes into the tailscale iface (/32 peer routes + accepted subnets)
    LocalRoutes         []netip.Prefix       // CIDRs to NOT route through Tailscale (throw routes on Linux)
    NewMTU              int                  // macOS extension only; ignored elsewhere
    SubnetRoutes        []netip.Prefix       // routes *we advertise* (only used for netflow logging)
    SNATSubnetRoutes    bool                 // Linux-only: SNAT traffic to local subnets
    StatefulFiltering   bool                 // Linux-only: stateful filter on inbound subnet→tailnet
    NetfilterMode       preftype.NetfilterMode  // Linux-only: on/nodivert/off
    NetfilterKind       string               // Linux-only: "nftables" or "iptables"
    RemoveCGNATDropRule bool                 // Linux-only: allow non-Tailscale CGNAT inbound
}
```

**Registration mechanism:** `wgengine/router/osrouter/osrouter.go` — each OS init() registers via `router.HookNewUserspaceRouter.Set(fn)`. `router.New()` calls the hook.

## 2. Darwin/BSD — userspaceBSDRouter

**Source:** `wgengine/router/osrouter/router_userspace_bsd.go` (builds on `darwin || freebsd`, lines 1–211)

### State

```go
type userspaceBSDRouter struct {
    logf    logger.Logf
    netMon  *netmon.Monitor
    health  *health.Tracker
    tunname string
    local   []netip.Prefix       // current interface addresses
    routes  map[netip.Prefix]bool  // current routes
}
```

### `Up()` (line 93)
```go
func (r *userspaceBSDRouter) Up() error {
    ifup := []string{"ifconfig", r.tunname, "up"}
    if out, err := cmd(ifup...).CombinedOutput(); err != nil {
        ...
    }
    return nil
}
```

### `Set()` (line 109) — incremental diff against stored state
1. Compute `addrsToRemove` / `addrsToAdd` from `r.local` vs `cfg.LocalAddrs`
2. If removing all addrs → set `resetRoutes = true` (re-add all routes next cycle)
3. **Remove old addrs:** `ifconfig <tun> inet <addr> -alias` (or `inet6`)
4. **Add new addrs:** `ifconfig <tun> inet <addr> <dest>` (dest = addr itself for `/32`)
5. **Delete old routes not in new set:** `route -q -n delete -inet <net>/<mask> -iface <tun>`
6. **Add new routes not in old set:** `route -q -n add -inet <net>/<mask> -iface <tun>`
7. FreeBSD: skips ULA route because the `/48` interface addr already created it
8. macOS: uses `delete` not `del` (line 170–172), uses `route` with `-q -n`
9. Stores new local/routes state only on success

### `Close()` (line 209)
```go
func (r *userspaceBSDRouter) Close() error { return nil }
```
**IMPORTANT:** BSD Close does NOT remove routes. Cleanup happens only if the caller calls `Set(&shutdownConfig)` (nil → empty Config), which causes the diff to remove everything. The shutdown config (`var shutdownConfig router.Config` in `osrouter.go`) is zero-valued, meaning LocalAddrs=nil, Routes=nil → removes all.

### Key macOS commands issued
| Operation | Command |
|-----------|---------|
| Interface up | `ifconfig utunN up` |
| Add address | `ifconfig utunN inet 100.x.y.z/32 100.x.y.z` (addr + dest) |
| Remove address | `ifconfig utunN inet 100.x.y.z/32 -alias` |
| Add route | `route -q -n add -inet 100.64.0.0/10 -iface utunN` |
| Delete route | `route -q -n delete -inet 100.64.0.0/10 -iface utunN` |
| Add route (v6) | `route -q -n add -inet6 fd7a:115c:a1e0::/48 -iface utunN` |
| Delete route (v6) | `route -q -n delete -inet6 fd7a:115c:a1e0::/48 -iface utunN` |

## 3. Linux — linuxRouter

**Source:** `wgengine/router/osrouter/router_linux.go` (1736 lines, ~350 of which are route/address/rule manipulation)

### State (lines 57–95)
```go
type linuxRouter struct {
    closed        atomic.Bool
    logf, tunname string
    cmd           commandRunner  // abstracts ip command or netlink
    nfr           linuxfw.NetfilterRunner
    ipRuleAvailable bool
    v6Available     bool
    ipPolicyPrefBase int            // 5200 (or 1300 with mwan3)

    mu                sync.Mutex
    addrs             map[netip.Prefix]bool
    routes            map[netip.Prefix]bool
    localRoutes       map[netip.Prefix]bool  // "throw" routes to bypass Tailscale
    snatSubnetRoutes  bool
    statefulFiltering bool
    netfilterMode     preftype.NetfilterMode
    magicsockPortV4/6 uint16
}
```

### `Set()` — incremental (line 417)
Uses `cidrDiff()` (line 1608) for each of: `localRoutes`, `routes`, `addrs`. Pattern:
```
cidrDiff("kind", oldMap, newSlice, addFn, delFn, logf)
```
Adds new entries first, then removes stale ones. Returns the new map (partial success possible).

### `addRoute()` / `delRoute()` — table 52 (line 942)
```go
func (r *linuxRouter) addRoute(cidr netip.Prefix) error {
    // If no ip rules: add to main table (0)
    // If ip rules active: add to tailscaleRouteTable.Num (52)
    return netlink.RouteReplace(&netlink.Route{
        LinkIndex: linkIndex,
        Dst:       netipx.PrefixIPNet(cidr.Masked()),
        Table:     r.routeTable(),   // 52 or 0
    })
}
```
Fallback via `ip route add <cidr> dev <tun> table 52`.

### `addThrowRoute()` / `delThrowRoute()` — line 964
Adds `RTN_THROW` routes for `LocalRoutes` CIDRs in table 52, so traffic to those networks falls through to the main routing table instead of hitting the tunnel. This is the "LAN bypass" feature.

### Policy routing (line 1257)
`justAddIPRules()` installs 4 rules per addr family at priority `baseIPPrefBase + {10, 30, 50, 70}`:
1. fwmark bypass → main table (pref 5210)
2. fwmark bypass → default table (pref 5230)
3. fwmark bypass → unreachable (pref 5250)
4. all traffic → table 52 (pref 5270)

Uses fwmark `0x80000` (from `tsconst.LinuxBypassMarkNum`), mask `0xffffff`.

### `Close()` (line 367)
Cleans up: downInterface, delIPRules, setNetfilterMode(off), delRoutes (removes throw routes only — routes are implicitly removed when the interface goes down). On linux the `ip link set dev tun down` removes routes pointing at it.

### `delRoutes()` (line 1477)
Only removes `localRoutes` (throw routes). Regular routes are cleaned up by the interface going down.

## 4. Current rustscale implementation

**Source:** `crates/tsnet/src/tun_pump.rs` lines 229–351

### `apply_tun_routes()` (line 230) — called once at TUN creation
```rust
#[cfg(target_os = "macos")]
{
    run_cmd("ifconfig", &["-v", ifname, "inet", &format!("{v4_str}/32"), "up"])?;
    run_cmd("route", &["-q", "add", "-net", &cgnat, "-interface", ifname])?;
}
#[cfg(target_os = "linux")]
{
    run_cmd("ip", &["link", "set", ifname, "up"])?;
    run_cmd("ip", &["addr", "add", &format!("{v4_str}/32"), "dev", ifname])?;
    run_cmd("ip", &["route", "add", &cgnat, "dev", ifname])?;
}
```

### `apply_accepted_subnet_routes()` (line 267) — called once at TUN creation
Iterates `RouteTable::entries()`, skips tailnet IPs, adds per-subnet routes:
```rust
#[cfg(target_os = "macos")] { let _ = run_cmd("route", &["-q", "add", "-net", &cidr, "-interface", ifname]); }
#[cfg(target_os = "linux")]  { let _ = run_cmd("ip", &["route", "add", &cidr, "dev", ifname]); }
```

### `apply_exit_node_routes()` (line 305) — called once at TUN creation when exit node is configured
```rust
#[cfg(target_os = "macos")]
{
    run_cmd("route", &["-q", "add", "-net", "0.0.0.0/1", "-interface", ifname])?;
    run_cmd("route", &["-q", "add", "-net", "128.0.0.0/1", "-interface", ifname])?;
    run_cmd("route", &["-q", "add", "-inet6", "::/1", "-interface", ifname])?;
    run_cmd("route", &["-q", "add", "-inet6", "8000::/1", "-interface", ifname])?;
}
#[cfg(target_os = "linux")]
{
    let _ = run_cmd("ip", &["route", "add", "0.0.0.0/0", "dev", ifname]);
    let _ = run_cmd("ip", &["-6", "route", "add", "::/0", "dev", ifname]);
}
```

### `run_cmd()` (line 338)
```rust
fn run_cmd(prog: &str, args: &[&str]) -> Result<(), TsnetError> {
    let status = std::process::Command::new(prog)
        .args(args).stdout(Stdio::null()).stderr(Stdio::piped())
        .status()?;
    if !status.success() { return Err(...) }
    Ok(())
}
```

## 5. Call sites — when routes are applied today

| Site | Function | What it does | File:line |
|------|----------|-------------|-----------|
| `create_tun_device()` | `apply_tun_routes()` | Brings interface up, adds CGNAT route | `tun_pump.rs:200` |
| `create_tun_device()` | `apply_accepted_subnet_routes()` | Adds per-peer subnet routes | `tun_pump.rs:203` |
| `create_tun_device()` | `apply_exit_node_routes()` | Adds default-route overrides for exit node | `tun_pump.rs:206` |
| `set_exit_node()` api | (none) | Only updates `RouteTable` in-process; no OS route change | `api.rs:448` |
| `clear_exit_node()` api | (none) | Only clears `RouteTable`; installed exit routes never removed | `api.rs:466` |
| `up_tun()` lifecycle | exit node config | Sets RouteTable exit_node before TUN creation | `lifecycle.rs:544` |
| `spawn_map_update_task()` updates | (none) | RouteTable is rebuilt from netmap peers; no OS route sync | `map_update.rs` |
| `Close()` on server | (none) | No route teardown at all | lifecycle.rs |

**Gaps:**
- **No incremental route updates.** Routes are applied once at startup. Later netmap changes (peers coming/going, subnet route changes) update only the in-process `RouteTable`, not the OS routing table.
- **No route removal on exit node change.** `set_exit_node`/`clear_exit_node` update `RouteTable` but never call OS route commands.
- **No Close/teardown.** When the server shuts down, `apply_exit_node_routes` / `apply_accepted_subnet_routes` / `apply_tun_routes` are never undone. The CGNAT route and exit node `/1` routes persist in the OS routing table forever.
- **No `LocalRoutes` support.** No way to declare CIDRs that should bypass the tunnel.

## 6. Existing read-side route crate

**Source:** `crates/routetable/`

- `lib.rs`: `RouteType` enum, `RouteDestination`, `RouteEntry` struct, `get_route_table(max)` function
- `darwin.rs`: PF_ROUTE sysctl (`NET_RT_DUMP2`), parses `rt_msghdr2` records
- macOS only (Linux stubbed out)
- Read-only: no route manipulation code

This crate provides the infrastructure for Phase 2 (native route management via PF_ROUTE on macOS), but right now the write side is all shell commands in `tun_pump.rs`.

## 7. Proposed Rust design

### New crate: `crates/router`

```
crates/router/
  Cargo.toml
  src/
    lib.rs          -- Router trait, RouterConfig, NewRouter
    darwin.rs       -- DarwinRouter (shell-command Phase 1, netlink Phase 2)
    linux.rs        -- LinuxRouter (shell-command Phase 1, netlink Phase 2)
    command.rs      -- shared run_cmd abstraction + commandRunner trait
```

### `RouterConfig` struct

Fields relevant for a non-Linux-firewall client:

```rust
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RouterConfig {
    pub local_addrs: Vec<IpAddr>,       // our CGNAT/ULA IPs (the Go Config uses netip.Prefix with /32)
    pub routes: Vec<IpPrefix>,          // CGNAT + per-peer /32 + accepted subnets → tun
    pub local_routes: Vec<IpPrefix>,    // CIDRs that should NOT go through the tun (LAN bypass)
    pub exit_node: Option<IpAddr>,      // if Some, install default-route overrides
    // Linux-only fields (ignored on macOS for now):
    pub snat_subnet_routes: bool,
    pub stateful_filtering: bool,
}
```

The Go `Config.SubnetRoutes` (routes *we advertise*) is NOT included — it's only used for netflow logging. The Go `Config.NewMTU` is handled by the TUN crate.

### `Router` trait

```rust
#[cfg_attr(not(any(target_os = "macos", target_os = "linux")), allow(unused))]
pub trait Router: Send + Sync {
    /// Bring the interface up.
    fn up(&mut self) -> Result<(), RouterError>;

    /// Apply a new config incrementally (diff against previous, add/remove only what changed).
    fn set(&mut self, config: &RouterConfig) -> Result<(), RouterError>;

    /// Tear down: remove routes, bring interface down. Idempotent.
    fn close(&mut self) -> Result<(), RouterError>;
}
```

### `NewRouter` constructor

```rust
pub fn new(tun_name: &str) -> Box<dyn Router>;
```

Platform dispatch via `#[cfg]` — same pattern as `create_tun_device`.

### Phase 1: shell commands behind trait with config diffing

#### `DarwinRouter` (Phase 1) — wraps the same `run_cmd` calls

State: `tun_name`, `config: Option<RouterConfig>` (stored for diffing).

**`up()`:**
- `ifconfig <tun> up`

**`set(&config)`:**
- Comparing to stored config:
  1. Compute `addrs_to_remove` / `addrs_to_add` (same algorithm as Go's `addrsToAdd`/`addrsToRemove`)
  2. Compute `routes_to_remove` / `routes_to_add` (same set-diff as Go's `r.routes` map)
  3. Compute `exit_changed` (exit node IP changed or was added/removed)
  4. **Address changes:** `ifconfig <tun> inet <addr>/32 -alias` / `ifconfig <tun> inet <addr>/32 <addr>`
  5. **Route changes:** `route -q -n delete -inet <cidr> -iface <tun>` / `route -q -n add -inet <cidr> -iface <tun>`
  6. **Exit node changes:** If exit node added, install `/1` routes. If removed or changed, remove old `/1` routes, add new ones.
  7. Store new config on success.

**`close()`:**
- Remove all routes (the BSD Go impl returns nil; but we want to clean up):
  - Remove exit node `/1` routes
  - Remove accepted subnet routes
  - Remove CGNAT route
  - Remove interface addrs (ifconfig ... -alias)
  - Bring interface down (`ifconfig <tun> down`)
- Clear stored config.

#### `LinuxRouter` (Phase 1) — wraps `ip` commands

State: `tun_name`, `config: Option<RouterConfig>`.

**`up()`:**
- `ip link set <tun> up`

**`set(&config)`:**
- Addr diff: `ip addr add <addr>/32 dev <tun>` / `ip addr del <addr>/32 dev <tun>`
- Route diff: `ip route add <cidr> dev <tun>` / `ip route del <cidr> dev <tun>`
- LocalRoute diff: `ip route add throw <cidr>` / `ip route del throw <cidr>` (no `dev`, goes in table main)
- Exit node: `ip route add 0.0.0.0/0 dev <tun>` / `ip route del 0.0.0.0/0 dev <tun>` (v4 + v6)
- No policy routing (Phase 2; for now routes go in main table, which is OK for basic client)

**`close()`:**
- Remove all throw routes
- Remove all routes
- Remove addrs  
- `ip link set <tun> down`
- Clear stored config

### Phase 2: native netlink/PF_ROUTE (note only)

- **Linux:** Replace `ip` commands with `netlink` crate (`neli` or `rtnetlink`). Implement policy routing (table 52, fwmark 0x80000, ip rules 5210/5230/5250/5270). Needed for correct exit node operation (so Tailscale daemon traffic bypasses the tunnel).
- **macOS:** Replace `route` / `ifconfig` commands with `PF_ROUTE` socket writes using `RTM_ADD`/`RTM_DELETE` messages. The `crates/routetable` already reads via `PF_ROUTE sysctl`; writing would use `PF_ROUTE` socket (`socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC)`) + `write()` with `rt_msghdr` structs. Same message format, just `RTM_ADD` / `RTM_DELETE` / `RTM_GET` instead of `NET_RT_DUMP2`.

### Wiring: replacing tun_pump calls

| Current | New API call |
|---------|-------------|
| `apply_tun_routes(ifname, ips, mtu)` | `router.set(&RouterConfig { local_addrs: ips, routes: [cgnat_range], .. })` |
| `apply_accepted_subnet_routes(ifname, rt)` | `router.set(&RouterConfig { routes: accepted_subnets, .. })` (merged with CGNAT) |
| `apply_exit_node_routes(ifname)` | `router.set(&RouterConfig { exit_node: Some(ip), .. })` |
| `create_tun_device` → all three | Single `router.set()` with full config |
| `set_exit_node()` → no OS change | `router.set()` with updated exit node |
| `clear_exit_node()` → no OS change | `router.set()` with `exit_node: None` |
| `Close()` → nothing | `router.close()` removes everything |
| netmap update → `RouteTable` rebuild | Also call `router.set()` with updated `routes` |

The `router` instance lives in `RunningState` alongside `route_table` (the in-process read-side). Every time `route_table` changes (exit node selection, netmap peer update), `router.set()` is called with the merged config.

## 8. Integration points

### Where the `Router` lives

```rust
// In RunningState (lifecycle.rs)
pub(crate) struct RunningState {
    // ... existing fields ...
    router: Option<Box<dyn Router>>,  // set in up_tun; None in netstack mode
}
```

### When `router.set()` is called

1. **TUN creation** (`create_tun_device` in `tun_pump.rs`): replaces the three `apply_*` calls with a single `router.set()` containing local addrs, CGNAT route, accepted subnet routes, and exit node (if configured).

2. **Exit node change** (`set_exit_node` / `clear_exit_node` in `api.rs`): after updating `RouteTable`, also calls `router.set()` with the new exit node IP (or None).

3. **Netmap update** (inside `spawn_map_update_task` in `map_update.rs`): after rebuilding `RouteTable` from peer Node.AllowedIPs, also calls `router.set()` with the updated route set for the OS routing table.

4. **Server close** (`close()` in `lifecycle.rs`): calls `router.close()` to remove all OS routes.

The three `apply_*` functions in `tun_pump.rs` are replaced entirely and removed.

### `RouterConfig` merging strategy

Rather than calling `router.set()` multiple times for separate concerns, build a single merge function:

```rust
fn build_router_config(
    local_addrs: &[IpAddr],
    route_table: &RouteTable,
    exit_node: Option<IpAddr>,
    accept_routes: bool,
) -> RouterConfig {
    let mut routes = vec![rustscale_tsaddr::cgnat_range()];

    if accept_routes {
        for (net, prefix, _peer) in route_table.entries() {
            if !rustscale_tsaddr::is_tailscale_ip(net) {
                routes.push(IpPrefix { addr: net, prefix });
            }
        }
    }

    RouterConfig {
        local_addrs: local_addrs.to_vec(),
        routes,
        exit_node,
        local_routes: vec![], // TODO: populate from prefs (AllowLANAccess)
    }
}
```

This merge function is called on any state change that affects OS routes.

## 9. Teardown audit

| Route type | Today | With `Router::close()` |
|-----------|-------|----------------------|
| CGNAT (100.64.0.0/10) | Never removed | Removed |
| Peer subnet routes | Never removed | Removed |
| Exit node `/1` routes | Never removed | Removed |
| Interface address | Never removed | Removed |
| Interface up → down | Never brought down | Brought down |
| Linux throw routes | N/A (not implemented) | Removed |
| Linux policy rules | N/A (not implemented) | Removed |

## 10. Error handling

`RouterError` enum:

```rust
pub enum RouterError {
    Command { program: String, args: Vec<String>, exit_code: Option<i32>, stderr: String },
    NotFound(String),    // route to delete doesn't exist (non-fatal)
    AlreadyExists(String), // route to add already exists (non-fatal)
    Unsupported,         // operation not supported on this platform
}
```

The `set()` method collects errors (like Go's `setErr` pattern) and returns the first one, continuing on non-fatal errors (route already exists / not found).

**Shell command differences vs Go for macOS:**
- Go uses `delete` not `del`: confirmed by version.OS() check at lines 170-172.
- Go uses `-n` flag to skip DNS resolution: `route -q -n add/delete`
- rustscale already uses `-q` (quiet) and the platform-appropriate verb

## 11. Acceptance criteria

Phase 1:
- `cargo build --workspace` — no new deps beyond `std::process::Command`
- `tools/check.sh crates/router` — tests use a fake `CommandRunner` trait (same pattern as Go's `runner.go`)
- `cargo clippy --workspace --all-targets` — clean
- All current tun_pump tests pass unchanged
- No regressions in TUN data-plane integration tests
- Exit node change at runtime actually updates OS routes (verified manually with `netstat -rn`)
- Server close removes all installed routes

Phase 2 (later):
- Linux policy routing (table 52, fwmark rules)
- Linux netlink (rtnetlink crate) replaces ip command fallback
- macOS RTM_ADD via PF_ROUTE socket
