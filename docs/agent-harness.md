# Optional AI agent harness

RustScale includes the local harness used during development. It is public project tooling, not a required build dependency.

## Codex implementation worktrees

`tools/agent/codex-task.sh` starts a Codex task in an isolated `agent/<title>` branch under `.worktrees/`, enforces a deadline, and records logs and resumable session metadata under `.agent-runs/`.

```bash
tools/agent/codex-task.sh "fix-name" "Implement and test ..." 2400
tools/agent/codex-task.sh --continue "fix-name" "Address these review notes ..." 2400
tools/agent/agent-review.sh "fix-name"
```

The wrapper currently defaults to the model recorded in the script so resumed runs remain reproducible. Set `CODEX_MODEL` before a new run to use another Codex CLI model.

Each implementation prompt should contain a focused goal, the relevant Rust and upstream Go locations, constraints, and the acceptance gate. Use `--continue` with the same title for compiler errors or review feedback so the saved session and worktree remain the source of truth.

## Pi read-only research

`tools/agent/pi-research.sh` runs Pi non-interactively with only its `read`, `grep`, `find`, and `ls` tools enabled. It disables extensions, skills, and prompt templates, does not save a session, enforces a wall-clock deadline, and rejects the result if tracked or untracked repository state changes.

```bash
tools/agent/pi-research.sh "research-name" "Compare ..." 1200

PI_PROVIDER=anthropic \
PI_MODEL=claude-sonnet \
tools/agent/pi-research.sh "research-name" "Compare ..." 1200
```

When `PI_PROVIDER` or `PI_MODEL` is unset, Pi uses its normal configured default. The wrapper is deliberately ephemeral and read-only; use interactive Pi directly when a task needs a saved session or implementation tools.

## Review and merge lifecycle

After a run, inspect the preserved worktree and run the task-specific gate:

```bash
tools/worktree-status.sh
tools/agent/agent-review.sh "fix-name"
```

The review command checks staleness, shows a bounded status and diff summary, runs `git diff --check`, and selects `tools/check.sh`, `tools/bench/check.sh`, or `tools/agent/check.sh` based on the changed paths. It does not commit work.

Once the worktree is reviewed and committed, `tools/agent/worktree-merge.sh "fix-name"` validates the branch, merges it, validates the merged tree, and only then removes the worktree and local branch. A conflict or failed gate preserves the worktree for repair.

## Prompting and recovery

- Keep one coherent implementation objective per worktree.
- Provide exact file or package names and use `tools/go-find.sh` for the pinned upstream `tailscale.com` module.
- State the expected validation gate in the prompt.
- On failure, pass the concise compiler or review diagnostic to `--continue`; do not discard the worktree or start broad research again.
- Treat timeout, interruption, missing session metadata, repository mutation, and stale `master` as failures requiring explicit review.

## Safety and validation

The harness is fail-closed: it preserves incomplete worktrees, refuses ambiguous or dirty starting states, validates work before merge, and never stores credentials in the repository. Run its focused test suite with:

```bash
tools/agent/check.sh
```

`tools/worktree-status.sh` summarizes registered worktrees. Review any `DIRTY_UNCOMMITTED` or `AHEAD_UNMERGED` entry manually; do not delete it as cleanup.
