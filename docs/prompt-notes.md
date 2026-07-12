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
  **Update (post-phase-10): `tools/check.sh` now mirrors the CI gate exactly —
  `build --all-targets`, `test`, `clippy -- -D warnings`, and `cargo fmt --all
  --check` — so a local `ok` means CI-green. It is silent on success and prints
  only ~50 lines on failure. Agents should use it as their ONLY verify command,
  not raw `cargo`.**
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
- **Re-reading its own large files dozens of times (THE #1 sink in phases 5–7)**
  → `crates/tsnet/src/lib.rs` was re-read 28× (phase 5), **38×** (phase 6), and
  **53×** (phase 7) — 124K chars in phase 7 alone. Other own files re-read 10–15×
  each: `controlbase.rs` 11×, `controlhttp.rs` 10×, `filter/lib.rs` 15×,
  `filter/state.rs` 14×, `filter/tests.rs` 13×, `tun/darwin.rs` 5×. Once an own
  file exceeds ~300 lines, full re-reads dominate the token budget. **Fix**: tell
  agents "In your OWN files, NEVER re-read the whole file to find/edit one spot —
  use `tools/where.sh <pattern> <file>` (prints `grep -n` line numbers) or read a
  narrow offset/limit window around the target line. Only re-read a whole file
  once, at the start, to learn its shape." *(phase-5, phase-6, phase-7)*
- **`tools/clippy-all.sh` can dump 49K chars in one call (phase 7)** → the
  filter crate had hundreds of unique warning lines; the dedupe is line-level so
  they all printed in one 48,960-char output. **Fix**: `clippy-all.sh` now caps
  at 50 unique warning lines with a "(N more…)" note. *(phase-7)*
- **`sleep N && ps -p PID && tail log` busy-polling a backgrounded build
  (phase 7)** → 10 calls, 16K chars, each costing a full agent turn. **Fix**: use
  `tools/wait-build.sh <pid> <logfile> [timeout]` which polls internally and
  prints only the final log tail + exit code. Or, better, don't background the
  build — run it foreground with a timeout; the agent can't do useful work while
  waiting anyway. *(phase-7)*
- **Cargo-registry / tokio-source grepping for low-level APIs (phase 6)** → the
  TUN agent read `tokio-1.52.1/src/io/async_fd.rs` (8.5K) and grepped
  `libc-0.2.186` for utun/syscall constants — same anti-pattern as phase-3b's
  crypto-registry crawl, now for platform syscalls. **Fix**: porting-notes now
  distills the macOS utun syscall sequence + the tokio `AsyncFd` API, so future
  TUN/low-level agents don't grep the registry. *(phase-6)*
- **Real-server e2e debugging surfaced 8 non-obvious control-plane wire facts
  (phase 5)** → HTTP/2-over-Noise, the `/key` fetch, initiation-in-`X-Tailscale-
  Handshake`-header, tx/rx cipher direction, `PeersChanged`-as-initial-list,
  4-byte-LE map framing, Go-nil→JSON-`null` deserialization, DERP-SNI-must-be-
  hostname. Each cost a full register/map e2e iteration to rediscover. **Fix**:
  all distilled into `docs/porting-notes.md` § "Control-plane wire protocol
  (ts2021)". Future control-plane agents MUST read that section first.
  *(phase-5)*
- **Raw `cargo clippy`/`cargo build` instead of `tools/check.sh` (phase-10 a/b/c)**
  → phase-10a-subnet-serve, phase-10b-bench-harness, and phase-10c-perf-fixes
  each ran `cargo clippy --workspace --all-targets` raw (1× per session, zero
  `tools/*.sh` calls), dumping warning output straight into context; only
  phase-10d-latency used `tools/` (3×, clean). Raw cargo also diverges from CI:
  the CI gate fails on ANY clippy warning (`-D warnings`) and on `cargo fmt`
  drift, so an agent that runs plain `cargo clippy` can think it's green when
  CI will fail. **Fix**: `tools/check.sh` now mirrors CI exactly (build
  --all-targets + test + clippy `-D warnings` + `cargo fmt --all --check`),
  silent on success. Tell agents: "Use `tools/check.sh` as your ONLY verify
  command; never run raw `cargo build`/`cargo test`/`cargo clippy`/`cargo fmt`
  — it both dumps full output into your context and can hide CI-only
  failures." *(phase-10a, phase-10b, phase-10c vs phase-10d)*

## Patterns to fold into future phase prompts

1. Include the line: "Before reading Go sources, check `docs/porting-notes.md`
   for already-distilled facts (key formats, crypto_box API, tailcfg.go type
   map, Noise crypto crates, boringtun API, **control-plane wire protocol
   (ts2021)**, TUN platform API, rustls provider, Go source file maps). Only
   read the specific Go line ranges you still need."
2. Include the line: "Verify with `tools/check.sh` (or `tools/check.sh <crate>`)
   — it runs the FULL CI gate (`build --all-targets`, `test`, `clippy --
   -D warnings`, `cargo fmt --all --check`) and is silent on success / ~50
   lines on failure. Do NOT run raw `cargo build`/`test`/`clippy`/`fmt`
   yourself: that dumps full output into your context AND can diverge from CI
   (CI fails on any clippy warning and on unformatted code). A local
   `tools/check.sh` 'ok' means CI-green."
3. For any new external crate, state the exact constructor/entry API up front
   (by-value vs by-ref, feature flags). Check porting-notes first — many
   crates are already documented there (crypto_box, curve25519-dalek,
   chacha20poly1305, blake2, boringtun, smoltcp, h2, tokio AsyncFd).
4. For any crate mirroring Go wire types, preempt:
   "Add `#![allow(non_snake_case)]` at the crate root since fields mirror
   Go's PascalCase JSON."
5. Keep phases to one crate-cluster; build the leaf crate first.
6. Include the line: "Do NOT fetch docs.rs or explore `~/.cargo/registry/`
   for crate APIs — the APIs for all crates used so far are distilled in
   `docs/porting-notes.md`. If you need a crate not documented there, ask
   the orchestrator instead of grepping the registry."
7. Include the line: "To find a specific function/test in your own files,
   use `tools/where.sh <pattern> <file>` (or `grep -n`) instead of re-reading
   the whole file. Only re-read if you need surrounding context for an edit.
   NEVER re-read a >300-line file of your own just to locate one function."
8. Include the line: "Run `tools/clippy-all.sh <crate>` to see ALL clippy
   warnings in one pass (capped at 50 lines). Fix them all before re-running
   — do not fix one warning at a time."
9. For Noise/control-protocol work, preempt the known gotchas: "Use
   `ChaCha20Poly1305` (12-byte nonce), NOT `XChaCha20Poly1305`. Do not add
   `hkdf` or `digest` crates — hand-roll HMAC-BLAKE2s. See
   `crates/controlclient/src/controlbase.rs` for the working pattern. **And
   read `docs/porting-notes.md` § "Control-plane wire protocol (ts2021)"
   before touching the control plane** — it covers the /key fetch, the
   X-Tailscale-Handshake header, HTTP/2-over-Noise, tx/rx cipher direction,
   PeersChanged-as-initial-list, 4-byte-LE map framing, Go-nil→null
   deserialization, and DERP SNI. Rediscovering these costs 8+ real-server
   iterations."
10. For any server-received Go wire struct, preempt: "Go nil slices/maps
    marshal as JSON `null`; use `deserialize_null_to_default` on all
    Vec/map fields the server sends (Peers, PeersChanged, Addresses,
    AllowedIPs, Capabilities, CapMap values, DERPMap.Regions, …). And
    `RawMessage` must accept any JSON type — use `serde_json::Value`."
11. For TUN/platform work, preempt: "macOS utun syscall sequence, AF-header
    framing, and tokio `AsyncFd` are in porting-notes § TUN device platform
    API. Linux is `/dev/net/tun` + `TUNSETIFF`, no AF header. The `tun`
    crate sets `#![allow(unsafe_code)]` because workspace forbids it."
12. For long background builds, do NOT background-then-poll with `sleep`.
    Either run foreground with a timeout, or use `tools/wait-build.sh`.
13. **(New)** To find Go type/function definitions in the reference Go tree:
    "Use `tools/go-find.sh -t <TypeName>` (structs) or `tools/go-find.sh -f <FuncName> <subdir>`
    (functions) to locate definitions. This grep the Go tree without reading
    full files. Once you know the file:line, read a narrow offset/limit window.
    Do NOT read a full Go file just to find where a struct is defined."
14. **(New)** During iterative development (editing one crate), use the fast verification
    path: "Use `tools/check.sh --check <crate>` (type-check only via `cargo check`,
    ~2x faster than build) during iteration. Only use `tools/check.sh <crate>`
    (full build) or `tools/check.sh` (workspace build + test + clippy + fmt) at the
    end. Never run `cargo build --workspace` during iterative editing of a single
    crate — it wastes time on codegen for all other crates."
15. **(New)** Never re-read your own large Rust files: "After the initial full read of
    any own crate file, NEVER re-read it fully. To understand structure, run
    `grep -n '^fn \|^pub fn\|^struct\|^enum\|^impl\|^mod\|^type\|^trait' <file>`
    to produce a compact ~20-line index. To find a specific function, use
    `tools/where.sh <pattern> <file>`. To see context before an edit, read a
    narrow window (offset=LINE-5, limit=20). Cost: a full re-read of
    `tsnet/src/lib.rs` is ~8K chars; 15 re-reads = 120K chars wasted."

## 2026-07-11: Excessive cargo build cycles in app-connector (37 cargo cmds/137 msgs)

**Symptom**: The `app-connector` session ran 37 cargo build/test/clippy commands
in 137 messages (27% of all tool calls), with an estimated 350K+ chars of tool
output. Each cycle: edit → `cargo build` → wait → parse errors → edit again. Many
of these were `cargo build --workspace` when only one crate changed.

**Fix**: 
1. Use `tools/check.sh <crate>` (single crate) instead of workspace-wide builds
   during development iteration. Only run workspace-wide at the end for merge CI.
2. Use `tools/check.sh --check <crate>` for pure type-checking (skips codegen,
   ~2x faster than `cargo build`). Use `--check` during iterative edit-fix cycles.
3. Use `tools/check.sh` (no args, workspace-wide) only for the final verification
   before declaring done.
4. Tell agents: "During iterative development, use `tools/check.sh --check <crate>`
   for type-check-only verification (fastest). Only run `tools/check.sh` (full gate)
   at the end. Never run workspace-wide `cargo build` unless you changed cross-crate
   interfaces."

**Estimated savings**: 37 cargo → ~15 with single-crate + --check would save
~200K chars and ~15 agent turns (~$0.15-0.30 per session at median rates).

## 2026-07-11: Go type/function location still done by reading full files (ssh-finish, listen-service)

**Symptom**: Despite `tools/where.sh` and `docs/porting-notes.md` having file maps,
the `ssh-finish` session read `tailssh.go` 7 times (529K chars total) and
`listen-service` read `tailcfg.go` 3 times (937K chars). The agents still read large
Go files to find type definitions because `where.sh` requires knowing the file first.

**Fix**: `tools/go-find.sh` now searches the entire Go tree by type/function/pattern,
printing `file:line:context` without reading the full file. Tell agents:
"To FIND a Go type or function definition, use `tools/go-find.sh -t <name>` or
`tools/go-find.sh -f <name> <package-dir>`. This prints `file:line:matched-line`
so you can then read a narrow window. Do NOT read a full Go file just to locate
a definition."

**Estimated savings**: 7× tailssh.go reads (~80K chars) per ssh session; 3× tailcfg.go
reads (~90K chars). With go-find.sh: 1 grep call (~500 chars output) → ~$0.05-0.10
per session saved.

## 2026-07-11: Own Rust files still re-read despite where.sh (interactive-auth)

**Symptom**: `interactive-auth` read `tsnet/src/lib.rs` 15 times (1.5M chars session),
`listen-service` 4 times, `app-connector` 4 times. The `where.sh` tool was created
to fix this but agents still re-read because they need *surrounding context* for
edits, not just line numbers.

**Observation**: 15 reads of the same file suggests the agent edited the file,
added a function, then re-read the whole thing to understand what it just wrote
before adding the next function. This is working memory loss — the model doesn't
retain the file's structure between turns.

**Mitigation**: Tell agents: "After your FIRST full read of an own file, NEVER
re-read it fully. To find a line number, use `tools/where.sh`. To see surrounding
context before editing, read a narrow offset/limit window (e.g. offset=LINE-5, limit=20).
If you need to understand the file's overall structure a SECOND time, use
`tools/go-find.sh -f <function-prefix> <file-rel-to-crate>` or `grep -n "^fn\|^pub fn\|^struct\|^enum\|^impl\|^mod "` 
on the file to produce a ~20-line index without reading 500+ lines."

**Estimated savings**: 15 reads of tsnet/src/lib.rs → ~20K chars × 14 excess reads
= ~280K chars per session; 4-5 such sessions per phase @ ~$0.15 each.

## 2026-07-11: Cargo.lock conflict auto-resolution in worktree-merge.sh

**Symptom**: Parallel worktree agents adding workspace dependency lines
caused Cargo.toml + Cargo.lock merge conflicts.

**Fix**: `tools/agent/worktree-merge.sh` now auto-resolves Cargo.lock
conflicts by accepting `--theirs` for Cargo.lock, union-merging Cargo.toml
(keeping both sides' deps), regenerating with `cargo generate-lockfile`,
and re-running checks before finalizing the merge. It also runs
`cargo fmt --all --check` post-merge with a hint if formatting drift is
found. Orchestrators can merge without manual conflict resolution.

## 2026-07-11: Empty-first-turn investigation (toolsmith-openocode-perms)

**Symptom**: Build agents frequently produce empty assistant turns (reasoning
only, no text/tool calls) and the harness watchdog re-prompts once with
"Begin now. Re-read the task...".

**Root cause found**: This is **NOT a permissions issue**. External directory
reads from `/Users/rajsingh/Documents/GitHub/tailscale/` work correctly — the
session-create API passes `permission:[{permission:"*",pattern:"*",action:"allow"}]`
which matches the `external_directory` permission kind (confirmed by reading the
opencode JSON schema at `opencode.ai/config.json` — `external_directory` is a
first-class key in `PermissionConfig`).

**Actual cause**: The model (glm-5.2) frequently outputs its reasoning in the
`reasoning` attribute and then makes tool calls, with **zero-length or
whitespace-only text** in the `text` part. Our harness only checked `text`
content to decide "empty turn", so it falsely re-prompted working agents. Of 58
assistant messages in a healthy phase-28 session, 22 had empty text — but every
one had completed tool calls. The model was working, just not emitting visible
text.

**Evidence consulted**:
- Session exports: `ses_0aca18301ffebzdQ9H5Hr7UVXx` (phase-28, healthy, 58 msgs)
  and `ses_0aca0af7fffenpxxuJprD8f5Es` (phase-30, re-prompted once)
- opencode permission docs at `opencode.ai/docs/permissions/` (external_directory
  default "ask", overridable in `permission` config)
- opencode JSON schema at `opencode.ai/config.json` (confirms `external_directory`
  in PermissionConfig)
- `opencode --help`, `opencode serve --help`
- Global config at `~/.config/opencode/config.json`

**Config added**:
- `opencode.json` at project root: explicit `external_directory` permissions for
  `/Users/rajsingh/Documents/GitHub/tailscale/**` and
  `/Users/rajsingh/Documents/GitHub/tailscale-client-go-v2/**`. This is a
  belt-and-suspenders measure — the session-create API already allows these paths
  — but having it checked in makes the permission policy visible and survives
  any future changes to session-creation defaults.

**Harness fix** (`tools/agent/opencode-task.sh`):
- Re-prompt now checks for **completed tool calls** in the last assistant
  message, not just text content. Only re-prompts when a message has no text AND
  no completed tool calls.
- Harvest output now prints a tool call summary instead of "(no output)" when
  the final message has tool calls but no text.

**If it recurs**:
1. Export the session: `opencode export <sessionID> > /tmp/ses.json`
2. Run the analysis script: `python3 -c "import json,sys; d=json.loads(open(sys.argv[1]).read()); ms=d['messages']; [print(f'msg {i:2d} {m[\"info\"][\"role\"]:10s} text={sum(len(p.get(\"text\",\"\")) for p in m[\"parts\"] if p.get(\"type\")==\"text\"):5d} tools={sum(1 for p in m[\"parts\"] if p.get(\"type\") in (\"tool\",\"tool_use\")):2d} res={sum(1 for p in m[\"parts\"] if p.get(\"type\")==\"tool_result\"):2d}') for i,m in enumerate(ms)]" /tmp/ses.json`
3. Check if the "empty" turns have tool_use parts → model working, watchdog
   heuristic too aggressive
4. Check if `/Users/rajsingh/Documents/GitHub/tailscale` reads return permission
   denials → check `opencode.json` exists and has `external_directory` entries
