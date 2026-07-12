# rustscale regression strategy

As rustscale approaches feature parity with the Go Tailscale client, the risk
shifts from "missing feature" to "silent regression in an area that used to
work." This doc is the contract for catching those regressions before they
ship. It is grounded in the current repo state (not generic advice) and folds
in lessons from Bun's Zig→Rust rewrite (bun.com/blog/bun-in-rust, 2026-07-08).

## Current coverage layers (already in repo)

| Layer | Where | Count |
| --- | --- | --- |
| Unit tests | `crates/*/src/**` + `crates/*/tests/**` | 1,377 across 34 crates |
| In-process fake control plane | `crates/testcontrol` | Phase A (register + map stream) |
| In-process DERP server | `crates/derp` server mode | phase-29 |
| E2e against ephemeral tailnet | `crates/tsnet/src/tests.rs` (`e2e_*`, `#[ignore]`) | 13 |
| Cross-client interop (Go tailscaled) | `interop_*` via `tools/interop.sh` + `interop-tun.sh` | 13 |
| Fuzz (parsers) | `fuzz/fuzz_targets/` | 5 (disco, derp, stun, pmp, pcp) |
| ThreadSanitizer | `.github/workflows/sanitizer.yml` | weekly, non-blocking |
| CI matrix | `.github/workflows/ci.yml` | ubuntu/macos/windows + cross + msrv |
| Audit | `.github/workflows/audit.yml` | RUSTSEC + deny |

## Critical gaps (ranked by blast radius)

### G1. No coverage measurement
No `cargo-llvm-cov` / `tarpaulin` gate. "Regression" is undefined without a
baseline. **Action**: add `coverage.yml` job on PRs; fail if overall drops
>1%. Target ≥80% on wire-format + state-machine crates
(`tailcfg`, `disco`, `derp`, `netcheck`, `controlclient`, `magicsock`,
`filter`, `ipn`).

### G2. testcontrol Phase B scenarios not built
`docs/testcontrol-plan.md` Phase B/C is unfinished. Go's `integration_test.go`
covers 16+ scenarios: interrupted auth, force-reauth, key expiry → NeedsLogin
→ re-enable, PeersRemoved delta, PeersChanged AllowedIPs (VIP route), C2N
ping, logout-removes-all-peers, IP persistence across restart, NAT
masquerade ping, client-side jailing. These are the scenarios most likely to
silently regress as the state machine evolves. **Action**: schedule Phase B
as a dedicated phase; each scenario is an in-process test against testcontrol
+ in-process DERP. See `docs/testcontrol-plan.md` §3 for the scenario list.

### G3. No wire-compat byte fixtures
A `serde` rename, field-order change, or `skip_serializing_if` tweak can
silently break wire compat with Go. Highest-risk regression class. **Action**:
`crates/wire-fixture` — capture real Go-encoded message bytes, assert Rust
serializes byte-identical. See `docs/phase-wire-fixtures.md` for the spec.
This is the rustscale equivalent of Bun's "language-independent test suite"
asset: a frozen assertion set that survives any internal refactor.

### G4. Restart/persistence regression under-tested
Persisted state: `prefs.json`, `profiles.json`, `serve-config.json`, netmap
cache, key ring. Only the exit-node logout test covers the "state in → kill
daemon → restart → assert restored" path. **Action**: `crates/ipn/tests/
persistence.rs` matrix — write known state, drop process, reboot, assert
every field roundtrips. One row per persisted artifact.

### G5. No natlab equivalent — magicsock path selection untested across NAT types
Go has 8x8 NAT-type pair matrix in VMs (`tstest/natlab/vnet`, `nat_test.go`)
classifying derp/local/direct outcomes. rustscale only tests the lucky path
on GitHub runners. **Action**: `crates/natlab` test crate — in-memory UDP
packet simulator with EasyNAT/HardNAT/EasyAFNAT behaviors. Even a 4x4 matrix
covers the real failure modes. Schedule as a phase; substantial port.

### G6. No property-based test for IPN state machine
`nextStateLocked` is table-driven (good), but the state × input graph has
many combinations. **Action**: `proptest` over `(state, input)` tuples
asserting invariants: no transition to terminal state without `WantRunning`
honored, `blocked` never silently true in `Running`, `logged_out` triggers
`NeedsLogin`. Finds the one unreachable/blocked state hand-written tables
miss.

### G7. Feature-end-to-end matrix is sparse
Features with unit tests but no full-stack test through testcontrol: `serve`
(no HTTP connect → WhoIS auth → upstream), `taildrop` (no two-node PUT/GET in
all 3 conflict modes against testcontrol), `ssh` (no session test — flagged
in `docs/audit/verified.md`), `appc` (no DNS-observe → route-advertise
end-to-end). **Action**: `crates/tsnet/tests/feature_matrix.rs` with one
`#[ignore]` e2e per feature row in `parity.md` Tier 1/2. Smoke tests catch
the worst regressions.

### G8. Concurrency stress for magicsock
tsan is weekly + non-blocking. **Action**: regular-CI stress test — send/recv
storm with concurrent map-stream updates + disco pings + endpoint refresh,
assert no panics/deadlocks over 10k iterations. magicsock is where 90% of the
hard concurrency lives.

## Lessons from Bun's Zig→Rust rewrite

Bun rewrote 535k lines of Zig → Rust in 11 days with LLM-driven loops and
shipped with **0 tests skipped or deleted** and only 19 known regressions
(all fixed). The applicable lessons:

### L1. Language-independent test suite is the golden asset
Bun's test suite was in TypeScript, not the implementation language — the
same million assertions validated both Zig and Rust versions. rustscale can't
inherit Go tests directly, but we can extract three kinds of
language-independent artifacts from the Go repo into `tests/fixtures/`:
- **Wire-format byte fixtures** (→ G3)
- **State-machine truth tables** as data, not re-derived tests
- **Scenario scripts** as observable end-state assertions (→ G2)

### L2. Adversarial review as a discipline
Bun used 1 implementer + 2 adversarial reviewers per task. Reviewer's only
job: find reasons the code doesn't work. Implementer never reviewed;
reviewer never implemented. **For rustscale**: after every phase, spin up an
adversarial-only opencode session: "find five reasons this code does not
match Go source at `<path>:<line>` or breaks an invariant in `parity.md`."
`docs/audit/verified.md` already proved this pattern catches overstated
status — institutionalize it as a post-phase gate.

### L3. Regressions come from semantic mismatches, not bugs
Bun's 19 regressions all came from code that looks syntactically identical
but behaves differently. Their examples map 1:1 to Go→Rust risks:

| Bun bug (Zig→Rust) | rustscale analog (Go→Rust) |
| --- | --- |
| `debug_assert!` erases side effects in release | Go `assert` runs in all builds vs Rust `debug_assert!` erased in release |
| `bytemuck::cast_slice` panics on odd length vs Zig `@divTrunc` ignores trailing byte | Go `len(s)/2` truncation vs Rust `try_into` panic on odd |
| `comptime` format strings vs runtime `format_args` | Go `const` evaluation vs Rust runtime |
| `ReleaseFast` removes bounds checks; Rust keeps them | Go unsafe slice tricks surface as Rust panics — latent bugs become visible |

**Action**: `docs/porting-semantics.md` registry — every Go pattern, its
naive Rust translation, and why they differ at runtime. Adversarial reviewer
rejects any PR introducing an undocumented Go→Rust pattern. Existing
`docs/porting-notes.md` is the seed; promote to a contract.

### L4. Prep documents before porting
Bun produced `PORTING.md` (pattern mapping) + `LIFETIMES.tsv` (per-field
ownership) before any translation, both adversarially reviewed. rustscale has
`docs/porting-notes.md` and `docs/prompt-notes.md` as notes, not contracts.
**Action**: promote to `docs/porting-contract.md` (mandatory Go→Rust
conversions) + `docs/lifetime-audit.tsv` (per-field ownership for magicsock,
controlclient, ipn, tsnet structs).

### L5. Fuzzer-to-PR loop
Bun runs 24/7 fuzz; crashes auto-PR'd by Claude with reproducer + fix, human
reviewed. rustscale has 5 fuzz targets but no fix loop. **Action**: wire
`fuzz.yml` crash capture → new opencode phase prompt with stacktrace → agent
attempts fix against testcontrol. Even 50% success catches bugs humans
won't.

### L6. "0 tests skipped or deleted" is an absolute rule
Bun never allowed a test to be skipped or deleted to make the port pass.
**Action**: add a CI guard — `rg "#\[ignore\]"` count must not increase on
PRs touching `crates/` without an explicit `Regression-Exception:` trailer in
the commit message. Prevents the slow drift where flaky tests get `#[ignore]`
instead of fixed.

### L7. Compiler errors as a work queue
Bun treated compiler errors as the to-do list, fixing crate-by-crate with
adversarial review per crate. rustscale's opencode harness already does this;
keep the discipline that a fix cycle must end with `tools/check.sh` green,
not with a `#[allow]` or stub.

## Acceptance gate (what "regression-covered" means)

A phase is regression-covered when ALL of:
1. `tools/check.sh` green (build + test + clippy + fmt).
2. No new `#[ignore]` without a `Regression-Exception:` trailer.
3. Wire-fixture roundtrip passes for any touched wire type (G3).
4. Persistence matrix passes if the phase touches persisted state (G4).
5. State-machine proptest passes if the phase touches the IPN state machine (G6).
6. Adversarial review session run and findings addressed (L2).
7. `parity.md` status column updated with evidence (file:line or test name).

## Phasing order (priority)

1. **G3 wire-fixtures** — 2 days, infinite ROI, gates the entire wire layer.
2. **G1 coverage job** — 1 day, gives us numbers to prioritize with.
3. **G4 persistence matrix + G6 proptest** — 2 days, cheap in-process gates.
4. **L6 #[ignore] count guard** — half day, prevents drift.
5. **G2 testcontrol Phase B** — 1 week, the scenario coverage gap.
6. **G7 feature matrix** — incremental, one row per remaining feature.
7. **G5 natlab** — substantial, schedule as a standalone phase.
8. **G8 concurrency stress** — incremental.
9. **L3/L4 porting-contract + lifetime-audit** — living docs, maintained per phase.
10. **L5 fuzzer-to-PR loop** — infrastructure, schedule after G3.

## Reference

- Bun blog: https://bun.com/blog/bun-in-rust (2026-07-08)
- Go integration scenarios: `tailscale/ipn/ipnlocal/integration_test.go`
- rustscale testcontrol plan: `docs/testcontrol-plan.md`
- rustscale gap inventory: `docs/parity.md`
- rustscale verified audit: `docs/audit/verified.md`
