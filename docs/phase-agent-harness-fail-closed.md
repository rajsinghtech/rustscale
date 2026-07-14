# Agent harness fail-closed phase

## Goal

Make provider/model routing and worktree integration mechanically enforce the
development policy in `CLAUDE.md`. A mistaken invocation must fail before an
agent can edit product code, and ambiguous worktree or merge state must be
reported rather than guessed or auto-resolved.

## Required changes

### Codex implementation wrapper

- Add `tools/agent/codex-task.sh <title> <prompt> [deadline-seconds]`.
- Refuse an existing branch or worktree, a dirty main tree, or a main tree that
  is not on `master`.
- Create `.worktrees/<title>` on `agent/<title>` from the current `master`.
- Run exactly `codex -a never exec -m gpt-5.6-terra -s workspace-write -C
  <worktree> <prompt>` with a hard deadline when the platform provides one.
- Tell the coding agent not to commit and not to spawn agents.
- Preserve the worktree on failure and print an unambiguous status containing
  its path and branch. Never silently delete dirty work.

### OpenCode research wrapper

- Make `deepseek/deepseek-v4-flash` the default and only normal model.
- Remove OpenCode worktree creation and all documentation that directs
  OpenCode or GLM to perform implementation.
- Reject a non-DeepSeek model before creating a session. A deliberately named
  environment escape hatch may permit diagnostics, but must be off by default.
- Treat server or status timeouts as unknown/error, not idle completion.

### Worktree status

- Classify every registered tree as one of `MAIN`, `DIRTY_UNCOMMITTED`,
  `AHEAD_UNMERGED`, `EMPTY_STALE`, or `MERGED_CLEAN`.
- A dirty tree whose `HEAD` is already an ancestor of master must be
  `DIRTY_UNCOMMITTED`, never merged.
- Report unregistered directories immediately under `.worktrees/` as orphans.
- Keep human-readable, JSON, and porcelain output useful to callers. Return
  nonzero when any non-main worktree needs attention.

### Merge helper

- Require a clean `master`, the expected registered path/branch, and a clean
  committed agent worktree before beginning integration.
- Do not stage or commit agent changes automatically.
- Do not auto-resolve Rust, manifest, or lockfile conflicts. Abort the merge
  and preserve the agent worktree for explicit resolution.
- Do not suppress fetch, merge, commit, formatting, or validation failures.
- Validate the agent head before merge and the resulting master after merge.
- Clean the worktree and branch only after the final merged-master gate passes.

## Verification

- Add shell-level regression coverage using a temporary Git repository and
  stubbed `codex`/`opencode` where external execution would otherwise occur.
- Cover model rejection, exact Codex arguments, dirty-main refusal, dirty
  ancestor classification, ahead-unmerged classification, empty-stale
  classification, orphan detection, uncommitted-work refusal, conflict
  refusal, and preservation after a failed final gate.
- Existing supported happy paths must remain usable.
- `tools/check.sh` and the new focused harness tests must pass.

## Non-goals

- Do not clean, merge, or edit existing user worktrees.
- Do not redesign the entire durable task-state system in this phase.
- Do not change product crates or benchmark behavior.
