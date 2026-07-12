# Phase: `rustscale cert` + QR codes for up/login

Two small CLI-surface items combined.

## cert subcommand

Go refs: `cmd/tailscale/cli/cert.go`, `client/local/cert.go`,
`ipn/localapi/cert.go` (endpoint `GET /localapi/v0/cert/<domain>?type=pair|cert|key&min_validity=`).

rustscale already has a full ACME client (LE certs via control — see docs/parity.md
Tier 1 row; the tsnet cert provisioning lives in crates/tsnet, search `acme`/`cert`).
This phase exposes it:

1. LocalAPI `GET /localapi/v0/cert/<domain>` — `type=pair` (default; PEM cert+key
   concatenated like Go), `type=cert`, `type=key`; `min_validity=<dur>` optional.
   Domain must match the node's MagicDNS name (or cert domains from netmap);
   404/400 otherwise. Reuse the existing cert provisioning/caching path.
2. localclient: `cert_pair(domain)` etc.
3. CLI: `rustscale cert [--cert-file <path>] [--key-file <path>] [--min-validity <dur>] <domain>`
   — writes files (`-` = stdout), matching Go flags/behavior. `rustscale cert` with
   no domain prints the node's cert domain (from status) as Go does.

## QR codes

Go ref: `cmd/tailscale/cli/up.go --qr`, `util/qrcodes`.

1. Add a `qrcode` dependency (pick a well-maintained pure-Rust crate, e.g. `qrcode`;
   check deny.toml licenses pass).
2. `rustscale up --qr` / `login --qr`: render the BrowseToURL auth URL as a
   terminal QR (unicode half-blocks like Go's ANSI output). With `--json`, include
   `QR` as a data:image/png;base64 field only if trivially supported by the crate —
   otherwise omit and document (Go parity is nice-to-have here).

## Acceptance criteria

- cargo build/test/clippy(-D warnings)/fmt clean, PLUS
  `cargo clippy --workspace --all-targets --target x86_64-unknown-linux-musl -- -D warnings`.
- Unit test: cert endpoint 400/404 paths; integration test with the existing
  testcontrol harness hitting /cert with a self-signed/test path if a real ACME
  flow isn't testable in-process (document what's covered).
- QR rendering unit test (known URL → expected module matrix or golden string).
- docs/parity.md rows updated (cert CLI, QR).
