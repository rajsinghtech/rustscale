# Phase: Tailscale SSH (port-10)

Goal: port Tailscale SSH — the `tailscale.com/ssh/tailssh` package — so that
tsnet embedders can call `listen_ssh(addr)` and accept SSH connections on the
tailnet authenticated by the control plane's SSH grants.

## Go references (read these files)

- `/Users/rajsingh/Documents/GitHub/tailscale/ssh/tailssh/tailssh.go` — main server, auth, grant checking, session loop
- `/Users/rajsingh/Documents/GitHub/tailscale/ssh/tailssh/listen.go` — listener setup
- `/Users/rajsingh/Documents/GitHub/tailscale/ssh/tailssh/session.go` — Session type
- `/Users/rajsingh/Documents/GitHub/tailscale/ssh/tailssh/hostkeys.go` — host key generation from node key
- `/Users/rajsingh/Documents/GitHub/tailscale/ssh/tailssh/user.go` — user resolution
- `/Users/rajsingh/Documents/GitHub/tailscale/ssh/tailssh/accept_env.go` — SSH environment variable filtering
- `/Users/rajsingh/Documents/GitHub/tailscale/ssh/tailssh/c2n.go` — c2n debug commands
- `/Users/rajsingh/Documents/GitHub/tailscale/ssh/tailssh/incubator.go` — subprocess incubator
- `/Users/rajsingh/Documents/GitHub/tailscale/tsnet/tsnet.go` lines 1267-1291 — `ListenSSH`
- `/Users/rajsingh/Documents/GitHub/tailscale/ipn/ipnlocal/local.go` — grep for `ssh` grants

## Existing Rust crates to use

- `crates/key` — NodeKey, MachineKey
- `crates/tailcfg` — tailcfg types (Node, NetMap, UserProfile, SSHGrant)
- `crates/netstack` — TCP listener on tailnet IPs
- `crates/tsnet` — Server, Backend, WhoIs, netmap access
- `crates/ipn` — State machine, Notify
- `crates/controlknobs` — feature gate flags
- `crates/health` — health tracking
- `crates/ffi` — C FFI if needed
- `crates/filter` — packet filter

Use the `russh` crate for the SSH protocol (pure Rust, well-maintained).

## Work items

1. **New `crates/ssh`**:
   - `src/lib.rs` — public API
   - `src/server.rs` — SSH server loop, auth (grant checking), accept
   - `src/session.rs` — Session type wrapping shell/exec
   - `src/hostkeys.rs` — deterministic Ed25519 host key from node key
   - `src/auth.rs` — SSHGrant evaluation from netmap
   - `src/env.rs` — environment acceptance filtering
   - `src/c2n.rs` — c2n command handlers for SSH

2. **Wire into tsnet**:
   - `crates/tsnet/src/ssh.rs` (feature-gated via `#[cfg(feature = "ssh")]`)
   - Add `ssh` feature to `crates/tsnet/Cargo.toml`
   - `listen_ssh(&self, addr: &str) -> Result<impl Listener>` on Server
   - Feature gate: `crates/tsnet/Cargo.toml` has `ssh = ["dep:russh", "crates/ssh"]`

3. **Auth flow**: On SSH connect → WhoIs peer → check SSHGrants in netmap → match against target user on host → allow/deny

4. **Host keys**: Derive Ed25519 keypair deterministically from the node private key (port `hostkeys.go`)

5. **Session**: Spawn shell for the authenticated OS user (phase 1), with environment filtering

## Acceptance criteria

1. `cargo build --workspace` passes
2. `cargo test --workspace` passes
3. `cargo clippy --workspace --all-targets` passes
4. `cargo fmt --all --check` passes
5. Test: create tsnet Server, register with testcontrol, call `listen_ssh`, accept SSH connection
6. SSH feature flag: compiles without `ssh` feature, adds `listen_ssh` with it
7. Host key generation from node key produces stable keys
8. SSHGrants from netmap are checked on connection (deny without grant)
9. `docs/parity.md` updated (Tailscale SSH row in Tier 3)
