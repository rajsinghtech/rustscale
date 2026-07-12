# Phase: Interactive auth + up/login/logout/down + prefs persistence

Goal: `rustscale up` with browser-based interactive auth — the daemon drives
control's AuthURL flow and streams BrowseToURL/LoginFinished over the IPN bus;
the CLI prints the URL and waits for Running. Plus real prefs with disk
persistence. Depends on phase-ipn-bus and phase-cli-core.

## Go references

- `cmd/tailscale/cli/up.go:500-822` — runUp: watch BEFORE start, notification loop,
  BrowseToURL dedupe/printing, NeedsMachineAuth handling, success detection
  (state==Running, SelfChange.Key for force-reauth).
- `ipn/ipnlocal/local.go:3004` (Start), `:4591` (StartLoginInteractive), `:7054` (Logout).
- `ipn/localapi/localapi.go:937-996` — login-interactive / start / logout handlers.
- `ipn/backend.go:551` — `ipn.Options{AuthKey, UpdatePrefs}` (start POST body).
- `ipn/prefs.go` — Prefs + MaskedPrefs (the `*Set` bool pattern for PATCH).
- Control client register/AuthURL polling: `control/controlclient/direct.go`
  (WaitLoginURL / login flow).

## Work items

1. **Daemon-side login flow** (`crates/controlclient` + `crates/tsnet`): when register
   returns an AuthURL, do NOT error (current behavior: TsnetError::AuthRequired at
   lib.rs:1330). Instead emit `Notify{BrowseToURL}`, enter NeedsLogin/Starting per the
   state machine, and poll/follow-up register until control reports login complete
   (study how Go's direct.go continues the register conversation), then emit
   LoginFinished and proceed to map polling.
2. **Prefs struct** (`crates/ipn`): a real Prefs type (serde PascalCase, Go-compatible
   JSON): ControlURL, WantRunning, LoggedOut, RouteAll, ExitNodeID/IP, CorpDNS,
   ShieldsUp, Hostname, AdvertiseRoutes, AdvertiseTags, OperatorUser as applicable to
   what rustscale supports; unsupported fields still serialize for wire compat.
   MaskedPrefs with `<Field>Set` bools for PATCH edits.
3. **Prefs persistence**: store prefs JSON in <state_dir> next to tsnet-state.json
   (single default profile file, e.g. `prefs.json`; keep the format
   forward-compatible with a future profiles phase). Daemon loads on start; `run`
   flags become defaults only when no stored prefs exist.
4. **LocalAPI endpoints**: `POST /start` (ipn.Options body: AuthKey, UpdatePrefs),
   `POST /login-interactive`, `POST /logout`, `GET/PATCH /prefs` (PATCH takes
   MaskedPrefs, applies masked fields, persists, emits Notify{Prefs}).
5. **CLI commands** (`crates/cli`):
   - `up` — flags: `--auth-key`, `--hostname`, `--advertise-routes`,
     `--advertise-exit-node`, `--exit-node`, `--shields-up`, `--accept-routes`,
     `--accept-dns`, `--reset`, `--force-reauth`, `--timeout`, `--qr` (skip QR
     rendering initially: print URL only), `--json`. Implement the Go runUp sequence:
     status → build prefs → WatchIPNBus → start → (login-interactive if no node key)
     → loop printing BrowseToURL → success on Running.
   - `login` / `logout` / `down` (down = EditPrefs WantRunning=false).
   - `set` — EditPrefs for the supported flags.
   - `get` — print prefs.
6. **Daemon changes**: `rustscaled run` no longer requires TS_AUTHKEY — without it,
   start in NeedsLogin and wait for CLI-driven start/login. TS_AUTHKEY still honored.
7. Tests: prefs round-trip + MaskedPrefs apply; testcontrol-driven integration test:
   daemon starts logged-out → CLI up → testcontrol issues AuthURL → complete login →
   CLI sees Running. (testcontrol may need a "hold register until approved" knob —
   check crates/testcontrol; Go's tstest/integration/testcontrol has SetAuthURL-style
   flows to mirror.)

## Non-goals

Multi-profile (later phase), QR codes, OAuth/WIF resolution hooks in the CLI,
NeedsMachineAuth UX beyond printing the state, Windows.

## Acceptance criteria

- cargo build/test/clippy/fmt clean; integration test green.
- Manual: `rustscaled run` (no authkey) + `rustscale up` prints a real AuthURL against
  an ephemeral tailnet and completes login when visited — document in phase notes
  (tools/tailnet/*.sh; clean up the tailnet).
- docs/parity.md updated (auth flow, prefs, CLI rows).
