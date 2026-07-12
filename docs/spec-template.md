# Foundational-phase spec template

Use this for phases that touch core, interconnected code (tsnet, magicsock,
netstack, controlclient, wg). These phases consume 10× more tokens than
feature phases because the agent needs to understand cross-crate boundaries.
Front-loading the spec pays back 10× in reduced fix cycles.

## Structure

```markdown
# Phase N: <title>

## Goal
One sentence: what the agent will build.

## File layout
Exact paths the agent should create/modify. No ambiguity:
- `crates/<crate>/src/<module>.rs` — <what goes here>
- `crates/<crate>/src/tests.rs` — <test file>

## Type signatures (REQUIRED for foundational phases)

List every public type and function signature the agent must implement.
This eliminates the "guess the API" fix cycle:

\`\`\`rust
pub struct Foo {
    pub field: Type,
    // ...
}

impl Foo {
    pub fn new(arg: &str) -> Result<Self, Error> { ... }
    pub async fn bar(&self, input: u32) -> Result<Vec<u8>, Error> { ... }
}
\`\`\`

## Cross-crate dependencies
What this crate imports from other rustscale crates, and what API it expects:
- `rustscale_tailcfg::Node` — fields used: <list>
- `rustscale_magicsock::MagicSock` — methods called: <list>

## Go reference
Exact file paths + line ranges to read (after checking docs/porting-notes.md):
- `/path/to/go/file.go:100-200` — <what's there>
- Do NOT read the full file — read only these ranges.

## Acceptance criteria
- `tools/check.sh <crate>` passes
- `tools/check.sh` passes (full workspace)
- Specific test: <name> passes and asserts <what>

## Known gotchas (preempt these)
- <Gotcha 1 from docs/prompt-notes.md that applies>
- <Gotcha 2>
```

## Why this matters

The 5 foundational phases consumed 445M tokens (20% of all 2.2B). Each needed
7+ continue cycles. The root cause: agents guessed at APIs, hit type mismatches
across crate boundaries, and iterated through compiler errors one at a time.
With explicit signatures upfront, the agent writes correct code on the first
pass and the continue count drops to 0-2.
