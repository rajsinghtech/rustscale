# Phase: release-ci-green

Unblock the v0.1.0 release by fixing two CI/E2E failures on master.

## Context

The latest master push (14e1d8c) triggered two failing workflows:
- **CI** (run 29200512811): Windows `Check (windows)` job fails at the
  `Clippy` step with `error: function wait_for_shutdown is never used`
  at `crates/rustscaled/src/daemon.rs:220:10` (`-D dead_code` via `-D warnings`).
- **E2E** (run 29200512807): `TUN-mode interop` job fails because the
  ephemeral tailnet creation got an HTTP 500 then repeated 400s.

All other jobs (Linux/Mac build+test+clippy, MSRV, all cross-checks,
testcontrol, ephemeral-tailnet E2E, cross-client interop) pass.

## Fix 1: Windows clippy dead_code (CI blocker)

File: `crates/rustscaled/src/daemon.rs`

There are two `wait_for_shutdown()` definitions:
- Line 208: `#[cfg(unix)] async fn wait_for_shutdown()` — IS called by
  the unix `wait_for_shutdown_signal()` (line 226).
- Line 220: `#[cfg(not(unix))] async fn wait_for_shutdown()` — NOT
  called by anyone on Windows. The Windows `wait_for_shutdown_signal()`
  (line 231) calls `tokio::signal::ctrl_c()` directly, bypassing
  `wait_for_shutdown()`.

On Windows the `not(unix)` `wait_for_shutdown()` is dead code → clippy
`dead_code` lint → fails under `-D warnings`.

**Fix:** Delete the unused `#[cfg(not(unix))] async fn wait_for_shutdown()`
function (lines 219-222). The Windows `wait_for_shutdown_signal()` already
has the correct `ctrl_c()` logic inline and does not call
`wait_for_shutdown()`. Do NOT change the unix path — it calls
`wait_for_shutdown()` and that function must stay.

After the edit, verify locally:
```
cargo clippy --workspace --all-targets -- -D warnings   # at least on host
```
(Windows-specific dead_code won't reproduce on macOS, but the deletion is
safe: the function is provably uncalled on Windows.)

## Fix 2: E2E tailnet-creation retry collision (E2E flakiness)

File: `tools/bench/lib.sh`, function `bench_provision_tailnet()` (line 62).

Current code (line 77):
```sh
created=$(curl -fsS --retry 5 --retry-delay 5 --retry-all-errors \
  -X POST "$BENCH_API/api/v2/organizations/-/tailnets" \
  -H "Authorization: Bearer $TS_ORG_TOKEN" -H 'Content-Type: application/json' \
  -d "{\"displayName\":\"$name\"}")
```

The `name` is fixed for all retries (`rustscale-bench-$(date +%s)`). When the
Tailscale API returns a transient 500, the tailnet may be partially created on
the server side. Subsequent `--retry` attempts reuse the same displayName and
get a permanent 400 ("already exists") — which `--retry-all-errors` dutifully
retries forever (up to 5 times), never succeeding.

**Fix:** Replace the single `curl --retry` call with a shell-level retry loop
that generates a **fresh** displayName on every attempt (append a random
suffix or a sub-second counter so each attempt is unique). Keep `--retry 3`
on the curl itself for transient network errors, but the outer loop handles
the 500→400-collision case. Example shape:

```sh
local created=""
for attempt in 1 2 3 4 5; do
  name="rustscale-bench-$(date +%s)-$attempt"
  echo "[bench] creating ephemeral tailnet: $name (attempt $attempt)" >&2
  created=$(curl -fsS --retry 3 --retry-delay 3 --retry-all-errors \
    -X POST "$BENCH_API/api/v2/organizations/-/tailnets" \
    -H "Authorization: Bearer $TS_ORG_TOKEN" -H 'Content-Type: application/json' \
    -d "{\"displayName\":\"$name\"}" 2>/dev/null) && break
  echo "[bench] attempt $attempt failed, retrying..." >&2
  sleep $((attempt * 3))
done
```

Then the existing `BENCH_DNS`/`BENCH_CHILD_*` extraction and validation
continues unchanged. Make sure `$name` is updated so downstream uses
`$BENCH_DNS` (from the response), not the local `$name`.

Also update the `echo "[bench] creating ephemeral tailnet: $name"` line to
reflect the new per-attempt name (move it inside the loop).

## Acceptance criteria

1. `cargo build --workspace` passes.
2. `cargo clippy --workspace --all-targets -- -D warnings` passes on the host.
3. `cargo test --workspace` passes.
4. The Windows dead_code error is resolved (function removed, not annotated
   with `#[allow(dead_code)]` — we remove dead code, we don't silence it).
5. `tools/bench/lib.sh` still passes `shellcheck` (if available) or at least
   `bash -n tools/bench/lib.sh`.
6. Commit as a single commit on a branch `agent/phase-release-ci-green`,
   push it, and open a PR targeting master. Use commit author
   rajsinghcpre@gmail.com / Raj Singh — NO Claude/AI branding in the
   commit message or PR description.

## Do NOT

- Do not add `#[allow(dead_code)]` to silence the lint — remove the dead
  function.
- Do not touch the unix `wait_for_shutdown()` or `wait_for_shutdown_signal()`
  — they are correct and used.
- Do not change any other CI workflow files.
- Do not tag anything — the orchestrator handles the tag after CI is green.
