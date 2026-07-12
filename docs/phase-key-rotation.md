# Phase: Key rotation / re-registration

Closes verified-audit P0 gap #2 (rank 5): no key rotation / re-registration.
Node key expiry = permanent disconnection.

## Goal

When the control server reports that the node key has expired (via
`Node.KeyExpiry` in the netmap), the client must:
1. Detect expiry and transition to `NeedsLogin` (already partially done:
   `key_expired` AtomicBool is set from MapResponse).
2. **Generate a new node key**, save the old key as `OldPrivateNodeKey`,
   and re-register with the control server sending both `OldNodeKey`
   (public of old key) and `NodeKey` (public of new key).
3. On successful re-registration, promote the new key to
   `PrivateNodeKey` and transition back to Running.

Additionally, handle `RegisterResponse.NodeKeyExpired = true` by
immediately retrying with a fresh key (Go's `doLoginOrRegen` pattern).

## Go source reference

All in `/Users/rajsingh/Documents/GitHub/tailscale/`:

### Key expiry detection
- `control/controlclient/direct.go:675` — `expired = !c.expiry.IsZero() && c.expiry.Before(clock.Now())`
- `control/controlclient/direct.go:690-695` — `if expired { regen = true }`
- `control/controlclient/auto.go:474` — `c.expiry = nm.SelfKeyExpiry()` (learned from netmap)
- `ipn/ipnlocal/local.go:1920-1936` — `b.keyExpired` set from `nm.SelfKeyExpiry()`
- `ipn/ipnlocal/local.go:6887` — `keyExpired → NeedsLogin` in state machine
- `types/netmap/netmap.go:280-287` — `SelfKeyExpiry()`

### Re-registration flow
- `control/controlclient/direct.go:739-748` — save old key, generate new:
  `persist.OldPrivateNodeKey = persist.PrivateNodeKey; tryingNewKey = key.NewNode()`
- `control/controlclient/direct.go:788-804` — build RegisterRequest with OldNodeKey + NodeKey
- `control/controlclient/direct.go:890-896` — `resp.NodeKeyExpired → mustRegen=true`
- `control/controlclient/direct.go:917-926` — commit: `persist.PrivateNodeKey = tryingNewKey`
- `control/controlclient/direct.go:575-586` — `doLoginOrRegen` auto-retry on mustRegen
- `types/persist/persist.go:21-25` — `OldPrivateNodeKey` field

### LoginFlags
- `control/controlclient/client.go:18-26` — `LoginInteractive` forces regen, `LoginEphemeral` sets ephemeral

### Server-side (testcontrol)
- `tstest/integration/testcontrol/testcontrol.go:930-950` — OldNodeKey handling: stages new key, transfers identity

## Current Rust state

- `crates/tailcfg/src/register.rs:23` — `OldNodeKey: NodePublic` field EXISTS in RegisterRequest but is never populated (always zero).
- `crates/tailcfg/src/node.rs:60` — `KeyExpiry: Option<DateTime<Utc>>` EXISTS on Node.
- `crates/tsnet/src/lib.rs:496,637` — `key_expired: Arc<AtomicBool>` EXISTS, set from MapResponse at line 3466-3469.
- `crates/tsnet/src/lib.rs:3476-3485` — TODO comment: "should re-register with OldNodeKey set"
- `crates/tsnet/src/lib.rs:1880` — `set_key_expired(true)` called on expiry detection.
- `crates/controlclient/src/client.rs:119` — `register()` method exists, sends RegisterRequest.
- **Missing**: `OldPrivateNodeKey` persistence, key regen logic, re-registration call, `NodeKeyExpired` response handling, `LoginFlags`.

## Implementation plan

### 1. Add OldPrivateNodeKey to persisted state
In `crates/tsnet/src/lib.rs`, the persisted state struct (grep for `NodeState` or similar state struct that saves to disk):
- Add `old_node_key: Option<NodePrivate>` field.
- When generating a new key for re-registration: save current key to `old_node_key`.
- On successful re-registration: promote new key to `node_key`, keep `old_node_key` for potential retries.
- Clear `old_node_key` on logout.

### 2. Add key expiry → re-registration flow
In `crates/tsnet/src/lib.rs`, in the map-update task where `key_expired` is detected (around line 3466-3485):
- When expiry is detected AND not already re-registering:
  1. Save current node private key as `old_node_key`.
  2. Generate a new node private key (`rustscale_key::NodePrivate::new()` or equivalent).
  3. Build a `RegisterRequest` with `OldNodeKey = old_key.public()`, `NodeKey = new_key.public()`.
  4. Call `control_client.register(&req).await`.
  5. If `resp.NodeKeyExpired == true`: generate yet another key and retry (max 2 retries).
  6. If `resp.AuthURL` is empty: promote new key, clear `key_expired`, transition to Running.
  7. If `resp.AuthURL` is non-empty: emit BrowseToURL notify, wait for interactive auth completion, then promote.

### 3. Handle NodeKeyExpired in RegisterResponse
In `crates/tailcfg/src/register.rs` or the register response type:
- Ensure `NodeKeyExpired: bool` field exists on `RegisterResponse` (check if already present).
- In the register flow: if `NodeKeyExpired == true`, set `must_regen = true` and retry.

### 4. Add LoginFlags
In `crates/tailcfg/src/register.rs` or `crates/controlclient`:
- Add `LoginFlags` bitflags: `LoginDefault = 0`, `LoginInteractive = 1`, `LoginEphemeral = 2`.
- When `LoginInteractive` is set, force key regen even if not expired.

### 5. Wire key_expired → set_blocked (already partially done)
The previous phase wired `set_blocked(true)` on NeedsLogin. Ensure key expiry triggers the same:
- `set_key_expired(true)` should also call `set_blocked(true)` (blocking engine updates while waiting for re-auth).
- On successful re-registration: `set_key_expired(false)` + `set_blocked(false)`.

### 6. testcontrol support for key rotation
In `crates/testcontrol`:
- Handle `RegisterRequest.OldNodeKey` non-zero: transfer the node's identity from old key to new key (matching Go testcontrol at `testcontrol.go:930-950`).
- Add a test method to force key expiry on a registered node.

## Acceptance criteria

- `tools/check.sh` passes (build + test + clippy -D warnings + fmt).
- `OldPrivateNodeKey` is persisted and sent in `RegisterRequest.OldNodeKey` on re-registration.
- Key expiry detection triggers re-registration with old+new key.
- `RegisterResponse.NodeKeyExpired` triggers immediate retry with fresh key.
- On successful re-registration, new key is promoted and state transitions back to Running.
- Integration test: register → force expiry → re-register with OldNodeKey → Running with new key.
- `LoginFlags` type exists and `LoginInteractive` forces key regen.

## Constraints

- Do NOT fetch docs.rs or explore `~/.cargo/registry/`.
- Before reading Go sources, check `docs/porting-notes.md` for distilled facts.
- Use `tools/check.sh --check <crate>` during iteration (fast type-check).
- Use `tools/check.sh <crate>` for full single-crate build.
- Use `tools/check.sh` (workspace) ONLY at the very end.
- NEVER run raw cargo build/test/clippy/fmt — use `tools/check.sh`.
- In your OWN files, NEVER re-read the whole file — use `grep -n` or `tools/where.sh`.
- Add `#![allow(non_snake_case)]` if mirroring Go field names.
- Go nil slices/maps → JSON null; use `deserialize_null_to_default` on Vec/map fields.
