# Phase: IPN state machine + notify bus + watch-ipn-bus

Goal: replace the binary up/not-up model with Tailscale's IPN state machine and a
notification bus, exposed over LocalAPI as `GET /localapi/v0/watch-ipn-bus?mask=`.
This is the backbone of the entire CLI UX (`up`, `wait`, interactive login all
consume it). Depends on phase-safesocket-localapi (LocalAPI served on the daemon
socket).

## Go references (read these files)

- `ipn/backend.go:23-33` — `State` enum: `NoState=0, InUseOtherUser=1, NeedsLogin=2,
  NeedsMachineAuth=3, Stopped=4, Starting=5, Running=6`, string table at :39.
- `ipn/backend.go:207-381` — `Notify` struct (JSON, all-optional pointer fields).
- `ipn/backend.go:72-193` — `NotifyWatchOpt` bitmask (explicit values, serialized over
  LocalAPI) + `ValidateNotifyWatchOpt`.
- `ipn/ipnlocal/local.go:6835-6908` — `nextStateLocked()`: THE truth table. Inputs:
  wantRunning, loggedOut, blocked, hasNodeKey, netMap==nil, AuthCantContinue,
  keyExpired, MachineStatus, engine status (NumLive/LiveDERPs).
- `ipn/ipnlocal/local.go:6707-6812` — `enterStateLocked()`: per-state side effects +
  `sendLocked(Notify{State})` at :6775.
- `ipn/localapi/localapi.go:886-935` — `serveWatchIPNBus`: streaming
  newline-delimited JSON with flush per message.
- `client/local/local.go:1367,1469-1500` — client side: long-lived GET + streaming
  JSON decode (`IPNBusWatcher.Next()`).

## Work items

1. **New `crates/ipn`**: `State` enum (serde as integer, matching Go), `Notify` struct
   (serde PascalCase, `skip_serializing_if = "Option::is_none"` everywhere — wire-compatible
   with Go's JSON), `NotifyWatchOpt` bitflags, `EngineStatus`. Start with the Notify
   fields rustscale can actually populate: Version, SessionID, ErrMessage,
   LoginFinished, State, Prefs (as serde_json::Value for now), BrowseToURL, Engine,
   InitialStatus (reuse localapi status JSON). Leave peer-delta fields for later.
2. **Bus in tsnet**: a `tokio::sync::broadcast`-based (or watch+mpsc) notifier owned by
   the Server. `Server` emits `Notify{State}` on every transition, `Notify{BrowseToURL}`
   when control returns an AuthURL, `Notify{LoginFinished}` on successful register,
   `Notify{ErrMessage}` on backend errors.
3. **State machine**: port `nextStateLocked` semantics into the tsnet backend. rustscale
   inputs available today: want_running (up called / daemon running), have node key
   (PersistedState.node_key), netmap present, auth-cant-continue (register returned
   AuthURL / error), key expired (netmap self expiry), engine status (magicsock has
   DERP home / live peers). MachineStatus → NeedsMachineAuth from netmap self
   MachineAuthorized. Replace the hardcoded `"Running"` in
   `crates/tsnet/src/localapi.rs` status JSON with the live state's string form.
4. **LocalAPI endpoint** `GET /localapi/v0/watch-ipn-bus?mask=<u64>`: validate mask,
   send initial-state messages per NotifyInitialState/InitialPrefs/InitialStatus bits,
   then stream bus messages as newline-delimited JSON, flushing per message; connection
   close ends the watch. The hand-rolled HTTP/1.1 server must support a streaming
   (chunked or connection-close-delimited) response for this one endpoint.
5. **Session ID + Version** on the first message when NotifyInitialState is set,
   matching Go.
6. Unit tests: state-machine truth-table tests (table-driven, mirroring Go inputs →
   expected state); watch-ipn-bus integration test over a unix socket asserting the
   initial state message and a transition message arrive as separate JSON lines.

## Non-goals

Prefs editing, StartLoginInteractive endpoint (next phase), peer-delta notifies,
rate limiting (NotifyRateLimit can be rejected as unsupported for now), Windows.

## Acceptance criteria

- cargo build/test/clippy/fmt clean (workspace, -D warnings).
- watch-ipn-bus integration test green.
- `status` JSON reports the real BackendState string.
- docs/parity.md updated (IPN state machine / LocalAPI rows).
