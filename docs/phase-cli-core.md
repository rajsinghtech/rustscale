# Phase: `rustscale` CLI binary — core subcommands (Tier A)

Goal: a `rustscale` CLI binary (Go `tailscale` equivalent) that talks to `rustscaled`
over safesocket. This phase covers the thin LocalAPI-wrapper subcommands only.
Depends on phase-safesocket-localapi. (Commands that need the IPN bus — `up`,
`login`, `wait`, `switch` — are the next phase.)

## Go references

- `cmd/tailscale/cli/cli.go` — root command assembly (ffcli), `--socket` global flag,
  `CleanUpArgs` (`--authkey`→`--auth-key`).
- Per-command sources in `cmd/tailscale/cli/`: `status.go`, `ip.go`, `version.go`,
  `whois.go`, `ping.go`, `netcheck.go`, `metrics.go`, `down.go`, `get.go`, `set.go`,
  `logout.go`, `dns-status.go`.
- `client/local/local.go` — LocalClient request helpers (`send`, `get200`), fake Host
  header `local-tailscaled.sock`, unix-socket HTTP transport.
- Output formats matter: `status.go` peer-table rendering, `--json` flags.

## Work items

1. **New `crates/cli`** producing bin `rustscale` (`[[bin]] name = "rustscale"`).
   Hand-rolled subcommand dispatch like `rustscaled` (repo style: no clap; keep it
   simple — match on argv[1], per-command flag loops). Global flags: `--socket <path>`
   (default /var/run/rustscaled.sock with <state_dir> fallback probing), `--json`
   where the Go command has it.
2. **New `crates/localclient`** (or module in cli): a minimal LocalAPI HTTP client over
   `safesocket::connect` — request builder with Host `local-rustscaled.sock`, JSON
   decode, error mapping (403/412/5xx → typed errors). Async (tokio) to match the
   workspace, but the CLI main can be a small `#[tokio::main]`.
3. **Subcommands** (each mirrors the Go flags/output where reasonable):
   - `status` (`--json`, `--peers=false`, `--active`) — GET status; render peer table
     like Go: IP, hostname, owner, OS, connection path (direct/relay), rx/tx.
   - `ip` (`-4`, `-6`, optional peer arg) — from status JSON.
   - `version` (`--json`) — client version from a new `version` module stamped at
     build time (env!("CARGO_PKG_VERSION") + git rev via build.rs, matching release.yml
     stamping) + daemon version from status.
   - `whois [--json] ip[:port]` — GET whois.
   - `netcheck` — this one is client-side: reuse `crates/netcheck` directly to run a
     probe and print the Go-style report (UDP, IPv4/6, MappingVariesByDestIP, DERP
     latencies sorted). Needs a DERP map: GET /localapi/v0/netmap for the DERPMap, or
     fall back to embedded default if daemon down.
   - `metrics` — GET metrics, print raw Prometheus text.
   - `health` — GET health (rustscale-specific but trivially useful).
   - `down` — needs prefs edit: add a minimal `PATCH /localapi/v0/prefs` handling
     WantRunning only IF the prefs-write path is trivial in the current daemon;
     otherwise print "not yet supported" and leave for the IPN phase. Do not build the
     full MaskedPrefs machinery in this phase.
   - `ping` — LocalAPI ping is currently 501; implement CLI to call it and surface the
     501 as "not yet supported by rustscaled". (Endpoint gets real in a later
     magicsock phase.)
4. **Release wiring**: add `rustscale-cli:rustscale` to BIN_PKGS in
   .github/workflows/release.yml so tarballs ship both binaries.
5. Tests: localclient unit tests against a stub unix-socket HTTP server (spawn the
   real localapi handler from crates/tsnet with a fake state); golden-output test for
   `status --json` passthrough; flag-parsing tests.

## Non-goals

up/login/logout interactive flows, watch-ipn-bus consumers, serve/funnel CLI,
cert, file, ssh, debug, completion, man pages, Windows named pipes.

## Acceptance criteria

- cargo build/test/clippy/fmt clean.
- Manual smoke documented in the phase notes: `rustscaled run` + `rustscale status`
  against testcontrol works end-to-end (add an integration test doing exactly this).
- docs/parity.md gains a CLI row/section with per-subcommand status.
