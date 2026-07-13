# Phase: router abstraction (`wgengine/router` port, phase 1)

Replace the ad-hoc shell route installs in `crates/tsnet/src/tun_pump.rs`
with a proper `crates/router` abstraction: config diffing, incremental
add/remove, teardown on close. Full pre-digested research:
**`docs/specs/research-router-abstraction.md`** — read it first (Go interface
inventory, current rustscale command list, the 4 gaps).

## Scope

1. **New crate `crates/router`**:
   - `RouterConfig { local_addrs: Vec<IpNet-ish>, routes: Vec<...>, local_routes: Vec<...>, exit_node: bool }`
     (subset of Go `router.Config`; use the workspace's existing prefix/route
     types — grep how routetable/tsaddr represent prefixes; don't add an
     external ipnet dep if one isn't already used).
   - `trait Router { fn up(&mut self); fn set(&mut self, cfg: &RouterConfig) -> Result<..>; fn close(&mut self) -> Result<..>; }`
     mirroring Go `router.Router` (skip `UpdateMagicsockPort` for now — note it).
   - `DarwinRouter` / `LinuxRouter`: **phase 1 wraps the existing shell
     commands** (`route add/delete`, `ifconfig` on macOS; `ip addr/route` on
     Linux — the exact current commands are inventoried in the research file
     and in tun_pump.rs:227-335). The key upgrades over today:
     - `set()` diffs previous vs new config and issues only add/remove deltas;
       idempotent when unchanged; re-runnable on every netmap update.
     - `close()` removes everything it installed (track installed state).
     - stub `FakeRouter` for tests (records calls; unit-test the diffing
       logic platform-independently — diffing must be pure and tested).
2. **Migrate call sites** in `crates/tsnet`:
   - `tun_pump.rs` `apply_tun_routes` / `apply_accepted_subnet_routes` /
     `apply_exit_node_routes` / `run_cmd` are replaced by building a
     `RouterConfig` and calling `router.set()`; the Router instance lives on
     the TUN-mode state and `close()` runs during `Server::close` teardown.
   - Runtime changes call `set()` with a new config: exit-node
     set/clear (grep set_exit_node in api.rs/lifecycle.rs), accepted subnet
     route changes on netmap update (research maps the call sites).
3. Phase 2 (native netlink/PF_ROUTE, Linux table-52 policy routing) is OUT of
   scope — add a short "phase 2" note in the crate docs and parity.md.

## Acceptance criteria (run yourself)

- `cargo build --workspace && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all`
  (sandbox socket-bind failures in c2n/tsnet/DERP suites are environmental —
  note them, everything else must pass; shell `route`/`ip` invocations must
  be behind the trait so tests never execute them — use FakeRouter).
- Diff-logic unit tests: no-op set, addr change, route add+remove mix,
  exit-node toggle, close-removes-all.
- Update `docs/parity.md` `OS-level route management` row.
- Do NOT modify `crates/magicsock`. Do not commit; do not spawn agents.
