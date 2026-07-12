# Phase: IPN Notify fields + state machine wiring

Closes verified-audit P0 gaps #37 (Notify missing NetMap + peer deltas) and
#40 (state machine InUseOtherUser unreachable).

## Goal

### 1. Add missing Notify fields
Add `NetMap`, `PeersChanged`, `PeersRemoved`, `PeerChangedPatch` to the
`Notify` struct in `crates/ipn`, and wire them from the map-update task in
`crates/tsnet` so `watch-ipn-bus` subscribers receive peer data.

### 2. Wire blocked/logged_out setters in IpnBackend
The `IpnBackend::new()` hardcodes `logged_out: false, blocked: false` with
no setters. Wire them so the state machine can actually transition:
- `blocked = true` when entering `NeedsLogin` (matching Go's
  `blockEngineUpdatesLocked` called from `enterStateLocked` on NeedsLogin).
- `logged_out = true` on logout (matching Go's `Logout` writing
  `Prefs{LoggedOut: true, WantRunning: false}`).
- `blocked = false` on successful auth/login.

### 3. InUseOtherUser handling
Go does NOT produce `InUseOtherUser` from `nextStateLocked`. It's injected
by the ipnserver when a different local OS user hits the LocalAPI socket
(`ipnserver/server.go:255`, `localapi.go:860`). For Rustscale's
single-user daemon model, add a method to force `InUseOtherUser` state on
the backend (for future multi-user scenarios) and ensure the state machine
test covers the `blocked=true` → non-Stopped transition. The key fix is
making `blocked` and `logged_out` settable so the truth table is actually
exercisable.

## Go source reference

All in `/Users/rajsingh/Documents/GitHub/tailscale/`:

### Notify struct
- `ipn/backend.go:202-381` — `type Notify struct`
- `:259` — `NetMap *netmap.NetworkMap`
- `:279` — `PeerChangedPatch []*tailcfg.PeerChange`
- `:292` — `PeersChanged []*tailcfg.Node`
- `:298` — `PeersRemoved []tailcfg.NodeID`

### NotifyWatchOpt bitmask values
- `ipn/backend.go:70-181`
- `NotifyInitialNetMap = 1 << 3` (line 88)
- `NotifyPeerChanges = 1 << 12` (line 125) — gates PeersChanged/PeersRemoved
- `NotifyNoNetMap = 1 << 13` (line 134) — suppresses runtime NetMap
- `NotifyInitialStatus = 1 << 14` (line 143)
- `NotifyPeerPatches = 1 << 15` (line 158) — gates PeerChangedPatch

### Notify population
- `ipn/ipnlocal/local.go:2123-2134` — full netmap path: `SelfChange`,
  `PeersChanged` (all peers if watcher registered), `NetMap` (legacy
  platforms only)
- `ipn/ipnlocal/local.go:2433` — `UpdateNetmapDelta(muts)` — delta handler
- `ipn/ipnlocal/local.go:2554-2583` — builds Notify from mutations:
  `NodeMutationUpsert` → `PeersChanged`, `NodeMutationRemove` →
  `PeersRemoved`, patches → `PeerChangedPatch`
- `ipn/ipnlocal/local.go:4078-4176` — `notifyForSessionLocked` per-watcher
  mask filtering + patch→full-Node promotion

### State machine blocked/logged_out
- `ipn/ipnlocal/local.go:352` — `blocked bool` field
- `ipn/ipnlocal/local.go:5897-5906` — `blockEngineUpdatesLocked(block)`
  sole setter
- `ipn/ipnlocal/local.go:4262` — set true on key expiry
- `ipn/ipnlocal/local.go:6783` — set true on NeedsLogin enter
- `ipn/ipnlocal/local.go:1935,1941` — set false on auth success
- `ipn/ipnlocal/local.go:6851,6855` — `loggedOut` read from Prefs
- `ipn/ipnlocal/local.go:7068-7074` — `Logout` sets `LoggedOut=true`

## Current Rust state

- `crates/ipn/src/lib.rs:212-255` — `Notify` struct with 9 fields (Version,
  SessionID, ErrMessage, LoginFinished, State, Prefs, Engine, BrowseToURL,
  InitialStatus, FilesWaiting). Missing: NetMap, PeersChanged,
  PeersRemoved, PeerChangedPatch.
- `crates/ipn/src/backend.rs:94-95` — `logged_out: false, blocked: false`
  hardcoded in `IpnBackend::new()`. No setters exist.
- `crates/ipn/src/machine.rs` — truth table with `logged_out` and `blocked`
  inputs. Tests exercise `blocked=true` and `logged_out=true` but the
  production backend never sets them.
- `crates/tsnet/src/lib.rs:3054` — `inner.ipn_backend.bus().send(Notify{...})`
  sends state notifications. Map update task processes `PeersChanged` and
  `PeersRemoved` from MapResponse but does NOT forward them to the notify
  bus.

## Implementation plan

### 1. Notify struct fields
Add to `crates/ipn/src/lib.rs`:
```rust
/// Full network map (deprecated; only sent on initial request or legacy platforms).
#[serde(default, skip_serializing_if = "Option::is_none")]
pub NetMap: Option<serde_json::Value>,

/// Peers that were added or changed (full Node objects).
#[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "deserialize_null_to_default")]
pub PeersChanged: Option<Vec<serde_json::Value>>,

/// Peer IDs that were removed.
#[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "deserialize_null_to_default")]
pub PeersRemoved: Option<Vec<i64>>,

/// Partial peer changes (patch format).
#[serde(default, skip_serializing_if = "Option::is_none", deserialize_with = "deserialize_null_to_default")]
pub PeerChangedPatch: Option<Vec<serde_json::Value>>,
```
Use `serde_json::Value` for peer/netmap objects to avoid a hard dependency
on the full tailcfg Node type in the ipn crate (the tsnet crate will
populate them with serialized Node values). Add `deserialize_null_to_default`
on Vec fields since Go nil slices marshal as JSON `null`.

Add NotifyWatchOpt bits if not already present:
- `NotifyInitialNetMap = 1 << 3`
- `NotifyPeerChanges = 1 << 12`
- `NotifyNoNetMap = 1 << 13`
- `NotifyPeerPatches = 1 << 15`
Check `crates/ipn/src/lib.rs` for existing NotifyWatchOpt definition and
add missing bits.

### 2. Wire notify from map updates
In `crates/tsnet/src/lib.rs`, in the map-update task (where MapResponse is
processed, around `PeersChanged`/`PeersRemoved` handling):
- When peers are added/updated: send `Notify { PeersChanged: Some(nodes) }`
- When peers are removed: send `Notify { PeersRemoved: Some(ids) }`
- On full netmap received: send `Notify { NetMap: Some(netmap_json) }`
  (optionally gated by whether any watcher requested NotifyInitialNetMap)
- For `PeersChangedPatch` from `MapResponse.PeerChangedPatch`: send
  `Notify { PeerChangedPatch: Some(patches) }`

The notify bus is `inner.ipn_backend.bus()` (a
`tokio::sync::broadcast::Sender<Notify>`).

### 3. Wire blocked/logged_out setters
In `crates/ipn/src/backend.rs`:
- Add `pub fn set_blocked(&mut self, blocked: bool)` setter.
- Add `pub fn set_logged_out(&mut self, logged_out: bool)` setter.
- In the state transition logic (wherever `enter_state` is called):
  - On entering `NeedsLogin`: call `set_blocked(true)`.
  - On successful auth/login: call `set_blocked(false)`.
- On logout: set `logged_out = true` (the logout flow already exists in
  tsnet; add the backend setter call there).

### 4. State machine test coverage
- Ensure `machine.rs` tests cover `blocked=true, want_running=true` →
  should NOT return `Stopped` (it should return `Starting` or
  `NeedsMachineAuth` depending on other inputs).
- Add a test for `logged_out=true, want_running=false, has_node_key=true`
  → should return `NeedsLogin` not `Stopped`.

## Acceptance criteria

- `tools/check.sh` passes (build + test + clippy -D warnings + fmt).
- `Notify` struct has all 13 Go fields (9 existing + 4 new).
- `watch-ipn-bus` subscribers receive PeersChanged/PeersRemoved when the
  map updates (integration test or unit test on the notify bus).
- `IpnBackend` has `set_blocked` and `set_logged_out` methods.
- State machine tests exercise blocked=true and logged_out=true paths.
- Existing tests still pass.

## Constraints

- Do NOT fetch docs.rs or explore `~/.cargo/registry/`.
- Before reading Go sources, check `docs/porting-notes.md` for distilled facts.
- Use `tools/check.sh --check rustscale-ipn` during iteration.
  Use `tools/check.sh rustscale-ipn` for full build.
  Use `tools/check.sh` (workspace) only at the end.
- Add `#![allow(non_snake_case)]` — fields mirror Go's PascalCase JSON.
- Go nil slices/maps marshal as JSON `null`; use
  `deserialize_null_to_default` on all Vec/map fields the server sends.
- In your OWN files, NEVER re-read the whole file — use `grep -n` or
  `tools/where.sh` to find line numbers, read narrow windows.
