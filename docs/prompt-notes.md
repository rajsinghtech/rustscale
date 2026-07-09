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

## Patterns to fold into future phase prompts

1. Include the line: "Before reading Go sources, check `docs/porting-notes.md`
   for already-distilled facts (key formats, crypto_box API, tailcfg.go type
   map). Only read the specific Go line ranges you still need."
2. Include the line: "Run `tools/check.sh` (or `tools/check.sh <crate>`) to
   verify. It is silent on success and prints only ~50 lines on failure — do
   NOT dump full `cargo` output into your context."
3. For any new external crate, state the exact constructor/entry API up front
   (by-value vs by-ref, feature flags).
4. For any crate mirroring Go wire types, preempt:
   "Add `#![allow(non_snake_case)]` at the crate root since fields mirror
   Go's PascalCase JSON."
5. Keep phases to one crate-cluster; build the leaf crate first.
