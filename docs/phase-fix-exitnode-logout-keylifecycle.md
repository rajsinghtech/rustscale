# Fix phase: exit-node CLI wiring + logout + key lifecycle

Three verified correctness gaps that share the prefs/backend path
(docs/audit/verified.md #11, #6, #5). Grouped because they all live in
crates/tsnet backend + crates/rustscaled daemon + crates/ipn.

## Gap 1: exit-node prefs → routing (#11, do FIRST, smallest)
`handle_patch_prefs` in crates/tsnet/src/localapi.rs applies prefs but never
calls `Server::set_exit_node`/`clear_exit_node` (which already exist and work —
port-5). So `rustscale set --exit-node <x>` / `up --exit-node` updates the
stored pref but routing never changes.

Work: when PATCH /prefs changes ExitNodeID/ExitNodeIP, call the existing
set_exit_node/clear_exit_node accordingly. Same for ExitNodeAllowLANAccess if
that pref is present (add the pref field if missing). Apply on daemon start too
(stored pref → routing) so it survives restart.

Go ref: `ipn/ipnlocal/local.go` applyPrefsToEngine exit-node handling.

## Gap 2: logout actually logs out (#6)
`crates/rustscaled/src/daemon.rs` (~line 109) prints "logout requested" and
does nothing. Go's Logout sends a logout RegisterRequest to control (expiring
the node), clears node state, and transitions to NeedsLogin.

Work: implement backend logout — send the control logout/register-with-expiry
(controlclient), clear persisted node key/state (crates/tsnet state.rs), set
prefs LoggedOut=true + WantRunning=false, drive the state machine to NeedsLogin,
emit Notify. Wire POST /localapi/v0/logout to it (endpoint exists but is inert).

Go refs: `ipn/ipnlocal/local.go` `Logout`/`logout`, `control/controlclient`
logout path.

## Gap 3: key rotation / re-registration (#5)
No expiry-driven re-register: `OldNodeKey` never populated, no loop that
re-registers before/after node-key expiry, so key expiry = permanent
disconnect. Go re-registers (interactive or via authkey) and rotates keys.

Work: detect node-key expiry (netmap self KeyExpiry / control signal), trigger
re-registration reusing the phase-interactive-auth login flow (emit BrowseToURL
if interactive needed), populate OldNodeKey on the RegisterRequest for seamless
rotation. Transition through the state machine correctly.

Go refs: `control/controlclient/direct.go` register w/ OldNodeKey,
`ipn/ipnlocal/local.go` key-expiry handling.

## Tests
- Exit-node: PATCH prefs with ExitNodeIP calls set_exit_node (assert route
  table / a spy); clearing calls clear_exit_node; survives restart.
- Logout: testcontrol-driven — up → Running → logout → node key cleared, state
  NeedsLogin, control saw logout.
- Key rotation: testcontrol issues expiry → client re-registers with OldNodeKey
  → back to Running. (Extend testcontrol if needed.)

## Acceptance
- Standard four checks + musl-target clippy, clean.
- docs/parity.md exit-node + key-lifecycle rows updated.
- Do the three in the order above; if key-rotation (#3) proves too large,
  land #1 and #2, commit, and leave #3 clearly stubbed with a TODO + parity row
  kept ⬜ rather than half-doing it.
