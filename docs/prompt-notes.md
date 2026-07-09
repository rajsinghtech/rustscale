# Prompt notes — patterns that worked / failed

Running log for the orchestrator to fold into future phase prompts. Each entry
cites the session that surfaced it.

## Worked

- **"READ the Go files at <path>, never modify"** — agents respected the
  read-only boundary and used exact paths. Keep giving exact file paths.
  *(phase-1-scaffold-key-tailcfg)*
- **Build one crate first to catch API issues early.** The phase-1 prompt had
  the agent build `rustscale-key` before touching `tailcfg`; the
  `crypto_box` `from_bytes` mismatch surfaced there instead of across two
  crates. Keep this as a default step. *(phase-1)*
- **State acceptance criteria explicitly** (`cargo build`/`test`/`clippy`).
  Agents ran them unprompted and self-verified. Keep doing this. *(phase-1)*
- **Filter compiler output in bash.** The agent learned to pipe
  `cargo build ... | grep -E "^(error|warning)" | head -40` instead of dumping
  full logs. Now codified in `tools/check.sh` (silent on success, ~50 lines on
  failure). Tell agents to run `tools/check.sh` instead of raw cargo. *(phase-1)*
- **`tools/check.sh` adopted by later phases.** Phase-3a used
  `tools/check.sh rustscale-netcheck` and `tools/check.sh` directly — clean,
  no cargo dumps. Phase-3b also used it for final verification. Keep telling
  agents to use it. *(phase-3a, phase-3b)*
- **Hand-rolling Noise IK instead of using the `snow` crate.** The phase-3b
  agent correctly chose to hand-roll the Noise IK handshake with
  curve25519-dalek + chacha20poly1305 + blake2 rather than pulling in the
  `snow` crate, giving full control over the Tailscale protocol-version
  prologue mixing. This matched the Go implementation's approach. *(phase-3b)*
- **boringtun `noise::Tunn` wrapping strategy.** The phase-4 agent correctly
  used boringtun's low-level `Tunn` API (not its device layer) for a
  transport-agnostic per-peer tunnel, which is exactly what magicsock needs.
  *(phase-4)*

## Failed / costly (and the fix)

- **No type→line map for `tailcfg.go`** → the agent read the 3631-line file
  **11 times** in scattered offset/limit slices (~61K chars of reference
  reads), the single biggest token sink. **Fix**: `docs/porting-notes.md` now
  has a type→line-range table. Future prompts should say "see
  `docs/porting-notes.md` for the tailcfg.go type map; read only the line
  ranges you need." *(phase-1)*
- **`crypto_box::SecretKey::from_bytes` takes `[u8;32]` by value, not `&`** →
  agent guessed `&[u8;32]`, hit E0308 across all call sites, needed 2 fix
  cycles. **Fix**: porting-notes now nails the exact API. Tell agents the API
  shape up front when porting a new external crate. *(phase-1)*
- **Go PascalCase JSON fields → `non_snake_case` lint storm** in the tailcfg
  crate → 1 fix cycle to allow it crate-wide. **Fix**: porting-notes records
  the `#![allow(non_snake_case)]` rule; preempt it in the prompt for any crate
  mirroring Go wire types. *(phase-1)*
- **clippy `doc_markdown` + `manual_assert`** → 1 fix cycle. `doc_markdown` is
  now allowed workspace-wide; `manual_assert` is real and should be fixed
  (`if x { panic! }` → `assert!`). *(phase-1)*
- **Test assertion math bugs** (clamping arithmetic `0xff & 127 | 64`, hex
  length, zero-key edge cases) → the agent wrote wrong test *assertions*, not
  wrong product code, then debugged itself. Low-cost but avoidable: tell
  agents to keep test arithmetic trivial and pre-compute expected values.
  *(phase-1)*
- **`is_unset` needs `&self` for `#[serde(skip_serializing_if = "...")]`** →
  trivial signature fix but cost a build cycle. Note in porting-notes. *(phase-1)*
- **Import path botches** (`NodeCapMap` referenced from crate root but defined
  in module) → 1 fix cycle. Remind agents to keep module re-exports consistent.
  *(phase-1)*
- **netcheck.go full read (60K chars)** → the agent read the entire 1759-line
  file in one shot, then re-read a portion. **Fix**: porting-notes now has a
  type→line map for netcheck.go. Tell agents to read only the `GetReport` /
  `Client` / `Report` line ranges. *(phase-3a)*
- **Cargo registry grepping for crypto crate APIs (~20 bash calls, ~15K chars
  output)** → the phase-3b agent spent ~20 calls exploring `curve25519-dalek`,
  `chacha20poly1305`, `blake2`, `hkdf` APIs in `~/.cargo/registry/`, including
  creating a temp test crate to resolve version compatibility. This was the
  #1 token sink in the session. **Fix**: porting-notes now documents the exact
  crate versions, API shapes, and the critical `hkdf`+`blake2` incompatibility
  gotcha. Tell agents: "For Noise/BLAKE2s/ChaChaPoly, see porting-notes before
  exploring cargo registry — versions and API patterns are already distilled."
  *(phase-3b)*
- **`hkdf` crate doesn't work with `blake2` 0.10** → the agent tried
  `hkdf::Hkdf::new(Some(salt), ikm)` with blake2 and hit a BufferKind
  mismatch. Had to hand-roll HMAC-BLAKE2s + HKDF. Cost 2 fix cycles.
  **Fix**: porting-notes now states "Do not add `hkdf` or `digest` to
  Cargo.toml — hand-roll HMAC-BLAKE2s" with a reference to the working
  implementation. *(phase-3b)*
- **`XChaCha20Poly1305` vs `ChaCha20Poly1305`** → the agent initially used
  XChaCha20Poly1305 (24-byte nonce) but Go uses standard ChaCha20Poly1305
  (12-byte all-zero nonce). Cost 1 fix cycle. **Fix**: porting-notes now
  explicitly states which variant to use. *(phase-3b)*
- **`direct.go` re-read 3x (24K chars)** → the agent re-read the same Go file
  three times instead of caching the relevant sections. **Fix**: porting-notes
  now has a `direct.go` file map. *(phase-3b)*
- **boringtun docs.rs webfetches (8 fetches, ~160K chars)** → the phase-4
  agent fetched 8 docs.rs pages for boringtun's `Tunn`, `TunnResult`,
  `StaticSecret`, `PublicKey`. This was the #1 token sink by far. **Fix**:
  porting-notes now has the complete boringtun API with code examples. Tell
  agents: "For boringtun, see porting-notes — do NOT fetch docs.rs."
  *(phase-4)*
- **Own test file re-read 12x (~21K chars)** → the phase-4 agent kept
  re-reading `crates/magicsock/src/tests.rs` in small offset/limit slices
  while iteratively editing. **Fix**: tell agents to use `grep -n` to find
  specific test functions/line numbers in their own files instead of
  re-reading the whole file repeatedly. *(phase-4)*
- **Repeated clippy cycles (6+ runs, each grepping for different warnings)**
  → the phase-4 agent ran `cargo clippy` 6+ times, each time filtering for a
  different lint warning, fixing one, re-running. **Fix**: `tools/clippy-all.sh`
  now shows ALL warnings grouped by type in one pass. Tell agents to fix all
  clippy warnings in a single pass, not one-at-a-time. *(phase-4)*

## Patterns to fold into future phase prompts

1. Include the line: "Before reading Go sources, check `docs/porting-notes.md`
   for already-distilled facts (key formats, crypto_box API, tailcfg.go type
   map, Noise crypto crates, boringtun API, Go source file maps). Only read
   the specific Go line ranges you still need."
2. Include the line: "Run `tools/check.sh` (or `tools/check.sh <crate>`) to
   verify. It is silent on success and prints only ~50 lines on failure — do
   NOT dump full `cargo` output into your context."
3. For any new external crate, state the exact constructor/entry API up front
   (by-value vs by-ref, feature flags). Check porting-notes first — many
   crates are already documented there (crypto_box, curve25519-dalek,
   chacha20poly1305, blake2, boringtun).
4. For any crate mirroring Go wire types, preempt:
   "Add `#![allow(non_snake_case)]` at the crate root since fields mirror
   Go's PascalCase JSON."
5. Keep phases to one crate-cluster; build the leaf crate first.
6. Include the line: "Do NOT fetch docs.rs or explore `~/.cargo/registry/`
   for crate APIs — the APIs for all crates used so far are distilled in
   `docs/porting-notes.md`. If you need a crate not documented there, ask
   the orchestrator instead of grepping the registry."
7. Include the line: "To find a specific function/test in your own files,
   use `grep -n 'fn name'` instead of re-reading the whole file. Only
   re-read if you need surrounding context for an edit."
8. Include the line: "Run `tools/clippy-all.sh <crate>` to see ALL clippy
   warnings in one pass. Fix them all before re-running — do not fix one
   warning at a time."
9. For Noise/control-protocol work, preempt the known gotchas: "Use
   `ChaCha20Poly1305` (12-byte nonce), NOT `XChaCha20Poly1305`. Do not add
   `hkdf` or `digest` crates — hand-roll HMAC-BLAKE2s. See
   `crates/controlclient/src/controlbase.rs` for the working pattern."
