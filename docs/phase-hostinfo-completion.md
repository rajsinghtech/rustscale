# Phase: Hostinfo completion + ktimeout/envknob wiring

Full pre-digested research (field inventory, Go quotes, call-site map):
**`docs/specs/research-hostinfo-completion.md`** — read it first. This spec is
the decision layer on top of it.

Caveat: the research file's rustscale paths are approximate — verify each one
(e.g. DNS lives in `crates/dns`, not `crates/netstack/src/dns`; check the
actual controlclient/derp file names with grep) and adapt.

## Scope

### 1. `crates/logid` (new, tiny) + BackendLogID/FrontendLogID

- `PrivateID([u8; 32])` random via getrandom/rand (match workspace deps),
  `PublicID = sha256(private)`, hex `Display`/serde, `PrivateID::public()`.
  Mirror `types/logid/id.go` semantics.
- tsnet: on `Server::up`, load-or-create the PrivateID persisted in the state
  dir (atomicfile, like other state files), derive PublicID, thread its hex
  string into the hostinfo path as `BackendLogID`.
- `FrontendLogID`: add to `HostinfoOverrides` (caller-supplied, default empty).

### 2. RuntimeHostinfo additions (`crates/tsnet/src/hostinfo.rs`)

Add `backend_log_id: String`, `wol_macs: Vec<String>`,
`state_encrypted: OptBool` to `RuntimeHostinfo`; assign in
`apply_runtime_fields`. `state_encrypted`: always `OptBool::False` for tsnet
(plain-file state store — see research §5) — set it at the construction site,
not hardcoded in apply.

### 3. WoLMACs (`TS_WAKE_MAC`)

Port `feature/wakeonlan/wakeonlan.go:getWoLMACs` (quoted in research §3):
env values `auto` (enumerate up/running/broadcast non-loopback interfaces,
collect MACs, cap 10), `false`/`off`/unset → none, else parse as a literal
MAC. Interface enumeration: reuse `crates/netmon`'s existing interface
enumeration (it already reads MACs via getifaddrs/sockaddr_dl on macOS and
netlink/sysfs on Linux) rather than adding a new dependency; add an accessor
there if needed. Pure-function the filtering logic and unit-test it.

### 4. SSH_HostKeys

`link_monitor.rs` currently passes `ssh_host_keys: Vec::new()`. When the SSH
server is enabled, populate from the host keys `crates/ssh` generates/loads
(find where host keys live — grep crates/ssh for host key generation; format
as OpenSSH public key lines like Go's `ssh.MarshalAuthorizedKey` output,
trimmed). If SSH is disabled, keep empty.

### 5. envknob wiring (crates/envknob exists, has zero consumers)

Wire these (research §Part C has the Go references and patterns; verify each
rustscale target path yourself):
- `TS_NO_LOGS_NO_SUPPORT` → hostinfo NoLogsNoSupport (populate_hostinfo or
  apply_runtime_fields; OR-combine with the RuntimeHostinfo field).
- `TS_ALLOW_ADMIN_CONSOLE_REMOTE_UPDATE` → OR into AllowsUpdate.
- `TS_WAKE_MAC` → item 3 above.
- `TS_DEBUG_USE_DERP_HTTP` → DERP client scheme selection (`crates/derp`).
- `TSNET_FORCE_LOGIN` → tsnet bootstrap re-login check (`lifecycle.rs`).
- `TS_DNS_FORWARD_SKIP_TCP_RETRY` → `crates/dns` forwarder TCP-retry path.
- `TS_PANIC_IF_HIT_MAIN_CONTROL` → controlclient constructor: panic if the
  control URL is https://controlplane.tailscale.com and the knob is set.
Skip anything that would touch `crates/magicsock` (another agent owns it).
Skip knobs whose rustscale code path doesn't exist yet — list skips in your
final summary.

### 6. ktimeout wiring

Go's only production call site is the DERP server listener (15s
TCP_USER_TIMEOUT — research §Part B). Apply `crates/ktimeout` to accepted
connections in the in-process DERP server (`crates/derp` server module) on
Linux; no-op elsewhere (ktimeout is Linux-only — keep the call
platform-gated the way the crate exposes it).

### 7. Docs

Update `docs/parity.md`: Hostinfo row (recount populated fields, list the
intentional skips: PushDeviceToken, TPM, Location, ShareeNode, PeerRelay),
envknob row, ktimeout row.

## Acceptance criteria (run yourself)

- `cargo build --workspace && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all`
- logid: unit tests for sha256 derivation (golden vector), hex roundtrip,
  persistence load-or-create.
- WoLMACs: pure-helper unit tests (auto/off/literal-MAC/invalid).
- Hostinfo: test that a collect_hostinfo pass with the new runtime fields
  emits BackendLogID/WoLMACs/StateEncrypted in JSON with Go field names.
- Do NOT modify `crates/magicsock`. Do not commit; do not spawn other agents.
