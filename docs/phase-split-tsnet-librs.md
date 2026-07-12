# Phase: Split tsnet/src/lib.rs into modules

## Goal

`crates/tsnet/src/lib.rs` is 4,526 lines with a single 2,446-line `impl Server`
block. It was read 731× and edited 513× across 76 build sessions — the #1 token
sink in the project. Split it into focused modules so most future phases only
read/edit the module they're touching.

## Current structure

- `lib.rs` (4,526 lines) — `TsnetError`, `ServerBuilder`, `Server` struct,
  the massive `impl Server` block (lines 668–3114), plus ~1,400 lines of
  free functions (netstack pump, TUN pump, filter building, link monitor,
  route application, DNS resolution, exit node resolution)
- Already-extracted modules: `acme.rs`, `appc.rs`, `c2n.rs`, `hostinfo.rs`,
  `localapi.rs`, `peerapi.rs`, `proxyproto.rs`, `routing.rs`, `serve.rs`,
  `service.rs`, `socks5.rs`, `ssh.rs`, `state.rs`, `status.rs`, `taildrop.rs`,
  `tls.rs`, `tests.rs`

## Target structure

Extract from `lib.rs` into new modules. Keep `Server` struct and `ServerBuilder`
in `lib.rs` (they're the public API). Move impl blocks into their domain modules
using `impl Server` in each (Rust allows impl blocks in any module within the
same crate).

New modules to create:
1. `netstack_pump.rs` — `run_netstack_pump`, `handle_inbound_wg`,
   `process_tun_inbound`, `encapsulate_and_send`, `tick_wg_timers`
2. `tun_pump.rs` — `run_tun_pump`, `create_tun_device` (both macOS + Linux
   variants), `apply_tun_routes`, `apply_accepted_subnet_routes`,
   `apply_exit_node_routes`, `is_tailnet_cidr`, `run_cmd`
3. `filter_build.rs` — `build_filter_from_map_response`,
   `process_filter_deltas`, `rebuild_filter`, `extract_tailscale_ips`,
   `extract_node_ips`, `build_cap_holders`
4. `link_monitor.rs` — `spawn_link_monitor`, `spawn_periodic_endpoint_updates`,
   `spawn_hostinfo_update_loop`, `connect_home_derp`
5. `map_update.rs` — `spawn_map_update_task`
6. `dns_resolve.rs` — `resolve_addr`, `resolve_addr_with`, `resolve_exit_node`
7. `util.rs` — `CancelToken`, `TunModeConfig`, `ensure_ring_provider`,
   `rand_index`, `first_v4`, `break_tcp_conns_best_effort`

## Rules

- **Public API must not change.** `Server`, `ServerBuilder`, `TsnetError`,
  and all public methods on `Server` keep their signatures. Only the file
  layout changes.
- **Use `impl Server` in each new module** — Rust allows multiple impl blocks
  across files in the same crate. Add `use crate::Server;` at the top of each.
- **Mark private functions `pub(crate)` or `pub(super)`** if they're called
  cross-module, or keep them `fn` if they stay within one module.
- **Update `mod` declarations** in `lib.rs` to include the new modules.
- **Do NOT change any logic.** This is a pure move-refactor. No behavior
  changes, no API changes, no renaming.
- **Tests must pass unchanged.** `tests.rs` references functions by path;
  update import paths if needed but don't change test logic.

## Acceptance criteria

- `cargo build -p rustscale-tsnet` passes
- `cargo test -p rustscale-tsnet` passes
- `cargo clippy -p rustscale-tsnet --all-targets -- -D warnings` passes
- `cargo fmt --all --check` passes
- `lib.rs` is under ~800 lines (struct defs + builder + public API + mod decls)
- No public API changes (diff should be pure moves)
