# Phase 12 — Network Monitor (netmon)

Port of Tailscale's `net/netmon` to rustscale. The network monitor detects
interface/route changes (Wi-Fi ↔ Ethernet, sleep/wake, DHCP renumbering) and
notifies the data plane so it can re-gather endpoints, re-STUN, re-publish to
control, reset DERP, and re-probe direct paths.

## Goals

1. New crate `crates/netmon` providing:
   - A `State` snapshot type: up, non-loopback, non-Tailscale interfaces with
     their routable IPs + the default-route interface name.
   - A `Monitor` that detects changes and fires a **debounced** callback with a
     `ChangeDelta { major, time_jumped, jump_duration, old, new }`.
   - Two detection strategies behind one API:
     - **macOS**: `AF_ROUTE` routing socket (`socket(PF_ROUTE, SOCK_RAW, 0)`)
       read in a blocking thread; any RTM message triggers a re-poll.
     - **Fallback / non-macOS**: poll every 10 s comparing snapshots.
   - **Wall-clock jump detection**: if the monotonic-vs-wall elapsed exceeds
     60 s (sleep/wake), emit a change with `time_jumped = true`.
   - A change is **major** when the set of `(interface, routable IPs, up/down)`
     for *interesting* interfaces differs — mirroring Go's
     `State.isInterestingInterfaceChange` / `EqualFiltered`. Transient flag /
     MTU / hw-addr changes are NOT major.

2. Integration in `crates/magicsock`:
   - `Magicsock::link_changed()` — re-gather local endpoints, reset confirmed
     direct paths (clear `best_addr` / pending pings / `last_recv_derp_region`
     per peer, keep candidates + HomeDERP), and close all DERP connections so
     they reconnect lazily.
   - `local_udp_addrs` becomes `RwLock<Vec<String>>` so `link_changed` can
     refresh it; accessors return `Vec<String>` (clone).

3. Integration in `crates/tsnet`:
   - `up()` / `up_tun()` construct a `Monitor`, start it with an async callback
     that, on a **major** change:
     a. calls `magicsock.link_changed()` (re-gather + reset paths + close DERP),
     b. re-runs netcheck (`Prober.run`) and appends `Report.global_v4` to the
        endpoint list if present (best-effort),
     c. pushes updated endpoints to control via the lightweight non-streaming
        `MapRequest { Stream: false, OmitPeers: true }` (same shape as the
        startup endpoint push),
     d. disco re-probes automatically via the reset (candidates are kept).
   - The `MonitorHandle` is stored in `RunningState` and shut down in
     `Server::close()`.

4. Tests:
   - Unit tests for `State` comparison (equal, major vs minor, IP add/remove,
     up/down transition, interface add/remove).
   - A poll-monitor test with an **injected fake state provider** that detects a
     synthetic state change (no real network mutation).
   - Existing tests still pass.

## Constraints

- `tsnet` public API stays C-representable (no new public types leak that
  can't be expressed behind the FFI; netmon types are internal).
- **`unsafe_code`**: the netmon crate needs `libc` syscalls for the AF_ROUTE
  socket. Like `crates/tun`, it does **not** inherit workspace lints and sets
  `[lints.rust] unsafe_code = "allow"` + re-states the clippy pedantic allows
  locally. All other crates keep `unsafe_code = "forbid"`.
- Acceptance: `cargo build --workspace && cargo test --workspace &&
  cargo clippy --workspace --all-targets -- -D warnings &&
  cargo fmt --all --check` all clean.

## File layout (target)

```
crates/netmon/
  Cargo.toml
  src/
    lib.rs          — re-exports, IpPrefix, InterfaceMeta
    state.rs        — State, gather_state(), default_route_interface(),
                      interesting-interface filter, equal / is_major_change_from
    monitor.rs      — Monitor, MonitorHandle, ChangeDelta, start()
    os_darwin.rs    — AF_ROUTE route socket reader (cfg macos)
    os_poll.rs      — 10s polling fallback (cfg not macos + fallback)
    tests.rs        — unit + injected-state tests
```

## Go reference paths (read-only)

- `net/netmon/netmon.go` — Monitor: pump + debounce, wall-time jump, ChangeDelta.
- `net/netmon/state.go` — State, Equal, getState, isUsableV4/V6, filterRoutableIPs.
- `net/netmon/netmon_darwin.go` — AF_ROUTE socket, isInterestingInterface.
- `net/netmon/netmon_linux.go` — netlink (reference only; rustscale uses polling
  fallback on Linux for now).
- `net/netmon/polling.go` — 10s polling fallback.
- `net/netmon/defaultroute_darwin.go` — default route lookup.
- `wgengine/magicsock/magicsock.go` — `onLinkChange` / `ReSTUN` reaction.
