# Phase: dnsname + ringlog utility crates

Two small Go utility packages as standalone crates, plus adoption at existing
call sites. Both are tiny — port faithfully rather than redesigning.

Go references (read-only):
- `/Users/rajsingh/Documents/GitHub/tailscale/util/dnsname/dnsname.go` (278 loc)
  and `dnsname_test.go` (292 loc)
- `/Users/rajsingh/Documents/GitHub/tailscale/util/ringlog/ringlog.go` (78 loc)
  and `ringlog_test.go` (55 loc)

## 1. `crates/dnsname`

Port the whole package: `FQDN` type (always-dot-terminated, lowercase
canonicalization, `ToFQDN`, `WithTrailingDot`/`WithoutTrailingDot`,
`Contains`, `NumLabels`), `SanitizeLabel`, `ValidLabel`, `ValidHostname`,
`FirstLabel`, `TrimSuffix`/`TrimCommonSuffixes`, `HasSuffix` — read the Go
file for the exact function set and port all of it, including the label
length (63) and name length (253/254-with-dot) rules and error strings'
semantics (Rust errors need not match Go text verbatim, but conditions must).
Port the full `dnsname_test.go` table tests.

Adoption: `docs/parity.md` notes FQDN handling is duplicated inline in the
dns resolver + tsnet. Grep `crates/dns` and `crates/tsnet` for ad-hoc FQDN
normalization (trailing-dot handling, lowercase, label validation — e.g.
MagicDNS name matching) and migrate the clear-cut call sites to
`crates/dnsname`. Only migrate sites where behavior is identical — if a site
does something subtly different, leave it and list it in your final summary
instead of changing behavior.

## 2. `crates/ringlog`

Port `util/ringlog`: a fixed-capacity ring buffer of recent entries
(`Add`, `GetAll`, generic over T; read the Go file for the exact API) with
the Go tests. Thread-safety: match Go (it uses a mutex internally — keep
`Mutex<VecDeque<T>>` or equivalent).

Adoption: wire ringlog where Go uses it for in-memory diagnostics — Go's DNS
forwarder and magicsock keep recent-event rings. SKIP magicsock (another
agent owns it). If `crates/dns` has a natural recent-queries/errors debug
surface (grep for any existing ring/recent-log structure), adopt it there;
otherwise the standalone crate + tests is acceptable for this phase — state
which you did.

## Acceptance criteria (run yourself)

- `cargo build --workspace && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all`
- Both crates `#![forbid(unsafe_code)]`, no new external dependencies.
- Full Go table tests ported for both crates.
- Update `docs/parity.md`: `DNS name utilities` row and `Ring buffer logger`
  row with precise summaries.
- Do NOT modify `crates/magicsock`. Do not commit; do not spawn other agents.
