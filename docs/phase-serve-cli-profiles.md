# Phase: serve/funnel CLI + ServeConfig persistence (+ profiles groundwork)

Goal: `rustscale serve` / `rustscale funnel` CLI with daemon-side ServeConfig
persistence and ETag concurrency, plus `rustscale switch` multi-profile support.
Depends on phase-cli-core and phase-interactive-auth.

## Go references

- `cmd/tailscale/cli/serve_v2.go` — command surface (serve/funnel share code),
  applyWebServe/applyTCPServe/applyFunnel, messageForPort output.
- `client/local/serve.go` — GetServeConfig (ETag from header) / SetServeConfig
  (If-Match).
- `ipn/localapi/serve.go` — handler: GET returns config+ETag; POST verifies If-Match,
  412 on mismatch.
- `ipn/serve.go` — ServeConfig type (rustscale already has this in
  crates/tsnet/src/serve.rs, serde-compatible).
- Profiles: `ipn/prefs.go:1069-1110` LoginProfile; `ipn/localapi/localapi.go:1535-1608`
  profiles/ endpoints; `client/local/local.go:1224-1280` client methods;
  `cmd/tailscale/cli/switch.go`.

## Work items

1. **ServeConfig LocalAPI**: `GET/POST /localapi/v0/serve-config` on the daemon —
   GET returns current config with an ETag header (SHA-256 of canonical JSON); POST
   requires If-Match when config exists, 412 on mismatch, applies via the existing
   `Server::set_serve_config`, persists to `<state_dir>/serve-config.json`, reloads
   on daemon start.
2. **CLI `serve` / `funnel`**: the v2 surface subset that maps to rustscale's
   ServeConfig support: `rustscale serve [--bg] [--https=<port>|--http=<port>|--tcp=<port>|--tls-terminated-tcp=<port>] [--set-path <path>] <target>`,
   `rustscale serve status [--json]`, `rustscale serve reset`, and `funnel` variants
   (funnel = AllowFunnel[hostport]=true, ports 443/8443/10000 validation client-side
   too). Foreground mode (no --bg) holds the config only while the CLI runs (Go
   semantics: session-scoped via watch-ipn-bus disconnect) — if session-scoped is too
   big, implement --bg-only first and error "foreground serve not yet supported"
   without --bg.
3. **Profiles**: `crates/ipn` LoginProfile struct; daemon-side profile manager —
   per-profile state files (`profile-<id>.json` prefs + keyed tsnet-state), current
   profile pointer file; LocalAPI `GET/PUT /profiles/`, `GET /profiles/current`,
   `GET/POST/DELETE /profiles/<id>`; CLI `rustscale switch [--list] <profile>`.
   Switching tears down the running backend and brings it up with the target
   profile's state (reuse the daemon's existing shutdown/startup path).
4. Tests: ETag mismatch → 412 unit test; serve-config persistence across daemon
   restart; profile switch integration test with two testcontrol identities.

## Non-goals

Foreground-session serve semantics if hard (see above), drive shares, cert CLI
(certs already work programmatically; `rustscale cert` can be a fast follow),
Windows profiles (LocalUserID).

## Acceptance criteria

- cargo build/test/clippy/fmt clean; new tests green.
- Manual smoke vs ephemeral tailnet: `rustscale serve --bg --https=443 localhost:3000`
  then `rustscale serve status` shows it; survives daemon restart. Documented in
  phase notes; tailnet cleaned up.
- docs/parity.md updated (serve/funnel CLI, multi-profile rows).
