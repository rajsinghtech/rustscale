# Phase wire-fixtures: Go wire-compat byte fixture harness

## Goal

Build a `crates/wire-fixture` crate + test harness that captures real
Go-encoded Tailscale wire-protocol message bytes and asserts rustscale
serializes them byte-identical. This is the regression gate for the entire
wire layer — the rustscale equivalent of Bun's "language-independent test
suite" (see `docs/regression-strategy.md` G3, L1).

## Why this matters

A `serde` rename, field-order change, `skip_serializing_if` tweak, or
`deserialize_null_to_default` drift can silently break wire compat with Go.
Unit tests only check roundtrip (Rust→Rust); they cannot catch divergence
from Go's `encoding/json`. This harness freezes Go's output as the source of
truth and fails any Rust change that diverges.

## File layout

- `crates/wire-fixture/Cargo.toml` — new crate, workspace member
- `crates/wire-fixture/src/lib.rs` — fixture loader + assertion helpers
- `crates/wire-fixture/fixtures/` — captured Go byte fixtures
  - `register_request_minimal.json` — RegisterRequest with only required fields
  - `register_request_full.json` — all fields populated
  - `register_response_full.json` — RegisterResponse with auth + node + user
  - `map_request_minimal.json` — MapRequest with only required fields
  - `map_request_full.json` — all fields populated
  - `map_response_full.json` — MapResponse with peers + dns + derp + filter
  - `map_response_peers_changed.json` — streaming delta (PeersChanged only)
  - `map_response_peers_removed.json` — streaming delta (PeersRemoved only)
  - `map_response_peer_change_patch.json` — PeerChange incremental
  - `derp_map_full.json` — DERPMap with regions + nodes
  - `node_full.json` — Node with all fields + Hostinfo + Endpoints
  - `hostinfo_full.json` — Hostinfo with all 36 fields
  - `dns_config_full.json` — DNSConfig with routes + hosts + fallback
  - `filter_full.json` — FilterRule packet filter
  - `ssh_policy_full.json` — SSHPolicy with rules
  - `disco_ping.bin` — disco Ping message (binary, not JSON)
  - `disco_pong.bin` — disco Pong message (binary)
  - `disco_call_me_maybe.bin` — disco CallMeMaybe (binary)
  - `derp_frame.bin` — DERP frame (binary: type byte + len-prefixed payload)
  - `stun_binding_response.bin` — STUN binding response (binary)
- `crates/wire-fixture/tests/wire_compat.rs` — the assertion tests
- `tools/gen-wire-fixtures.sh` — script that regenerates fixtures from the Go
  repo (runs a small Go program under `tailscale/` that marshals each type;
  checked in so future agents can regenerate after Go bumps)

## What each test asserts

For each JSON fixture:
1. Rust can deserialize the Go-produced bytes (catches missing fields, null
   handling, type mismatches).
2. Rust re-serializes to **byte-identical** JSON (catches field-order,
   `skip_serializing_if`, `omitempty` vs `skip_serializing_if = "Option::is_none"`
   drift). Use `serde_json::to_string` (canonical, no whitespace) and compare
   with `assert_eq!` against the fixture's compact form.
3. For fields where Go uses `omitempty` and rustscale uses
   `skip_serializing_if`, verify that a zero-value Rust struct serializes to
   the same subset as Go.

For each binary fixture (disco/DERP/STUN):
1. Rust can decode the Go-produced bytes.
2. Rust re-encodes to byte-identical output (these are length-prefixed binary
   formats where byte order matters).

## Cross-crate dependencies

- `rustscale_tailcfg` — all wire types (RegisterRequest, MapRequest,
  MapResponse, Node, Hostinfo, DERPMap, DNSConfig, FilterRule, SSHPolicy,
  PeerChange)
- `rustscale_disco` — disco message encode/decode
- `rustscale_derp` — DERP frame codec
- `rustscale_netcheck` — STUN parse (for the STUN fixture)

## Go reference

The fixtures are generated from the Go repo at
`/Users/rajsingh/Documents/GitHub/tailscale`. The generator program
(`tools/gen-wire-fixtures.sh` writes a temp `gen_fixtures.go`) constructs each
type with representative values and calls `json.Marshal` (or binary encode for
disco/DERP/STUN). Key Go files to reference for field construction:
- `tailcfg/tailcfg.go` — RegisterRequest (~line 600), MapRequest (~line 900),
  MapResponse (~line 1000), Node (~line 400), Hostinfo (~line 1100)
- `tailcfg/derpmap.go` — DERPMap, DERPRegion, DERPNode
- `tailcfg/dns.go` — DNSConfig (if separate; else in tailcfg.go)
- `disco/disco.go` — disco message types + Marshal
- `derp/derp_server.go` — frame encoding (type byte + 4-byte BE len + payload)
- `net/netcheck/stuntest/stuntest.go` — STUN binding response construction

Do NOT read full files — use `docs/porting-notes.md` type→line maps.

## Fixture generation approach

Since we cannot run Go in the Rust CI, the fixtures are **checked in as static
files**. The generator script (`tools/gen-wire-fixtures.sh`) is for manual
regeneration when the Go repo bumps. The agent should:

1. Write a small Go program (`gen_fixtures.go`) that imports `tailscale.com/tailcfg`
   and constructs each type with realistic values, then `json.Marshal`s to
   `crates/wire-fixture/fixtures/*.json` and binary-encodes to `*.bin`.
2. Run it once locally (the agent has access to the Go repo at
   `/Users/rajsingh/Documents/GitHub/tailscale` and Go is installed).
3. Check in the generated fixtures + the generator script.
4. Write the Rust tests that load + assert against the checked-in fixtures.

If the agent cannot run Go, it may construct the expected JSON by hand from
the Go struct definitions + `encoding/json` rules (PascalCase keys, omitempty
semantics, nil slices → `null` unless `omitempty`, etc.), but MUST document
this in a `fixtures/README.md` and mark hand-constructed fixtures with a
comment. Generated-via-Go is strongly preferred.

## Acceptance criteria

- `tools/check.sh rustscale-wire-fixture` passes.
- `tools/check.sh` passes (full workspace — the new crate is a workspace member).
- At least 15 JSON fixtures + 5 binary fixtures checked in.
- Each fixture has a corresponding `#[test]` that deserializes + re-serializes
  and asserts byte-identical (for JSON) or byte-identical (for binary).
- `tools/gen-wire-fixtures.sh` exists and is documented in `fixtures/README.md`.
- No `#[ignore]` tests in this crate.
- `cargo fmt --all --check` clean.

## Known gotchas (preempt these)

- **Go `omitempty` vs Rust `skip_serializing_if`**: Go omits a field if it's
  the zero value; Rust's `skip_serializing_if = "Option::is_none"` only omits
  `None`. For non-Option fields with `omitempty`, rustscale uses
  `skip_serializing_if = "skip_default"` or similar — verify the fixture
  roundtrips correctly for both populated and zero-value cases.
- **Go `null` vs Rust default**: Go sends `null` for nil slices/maps; rustscale
  uses `deserialize_null_to_default`. The fixture MUST include a `null` case
  for at least one slice/map field to exercise this.
- **PascalCase JSON keys**: rustscale uses `#![allow(non_snake_case)]` in
  tailcfg. The fixture loader must not mangle case.
- **`serde_json::to_string` vs `to_string_pretty`**: use `to_string` (compact,
  no whitespace) to match Go's `json.Marshal` default.
- **Binary fixtures are NOT JSON**: load with `include_bytes!` and decode with
  the crate's binary decoder, not serde_json.
- **Field order in JSON**: Go's `json.Marshal` preserves struct field order.
  `serde_json::to_string` also preserves struct field order. So byte-identical
  is achievable IF the Rust struct fields are in the same order as Go. If they
  aren't, the test will catch it — that's the point.
- **`OptBool`**: rustscale has a custom `OptBool` type for tri-state booleans
  (true/false/unset). Verify it serializes identically to Go's `*bool` with
  omitempty.
- See `docs/prompt-notes.md` for serde/clippy gotchas that cost past phases.

## Out of scope

- Property-based testing of wire types (fuzz-style) — the fuzz targets already
  cover disco/DERP/STUN parsing. This phase is about byte-identical fixtures.
- testcontrol Phase B scenarios — separate phase (G2).
- Coverage measurement — separate phase (G1).
