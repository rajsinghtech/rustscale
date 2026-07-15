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

## OpenCode read-only research

`tools/agent/opencode-task.sh` talks to a local OpenCode server for read-only research. It rejects repository mutations and aborts work that exceeds the deadline.

```bash
OPENCODE_PROVIDER=provider-id \
OPENCODE_MODEL=provider/model \
tools/agent/opencode-task.sh "research-name" "Compare ..." 1200
```

The provider, model, server URL, warmup, and abort grace are configurable with the `OPENCODE_PROVIDER`, `OPENCODE_MODEL`, `OPENCODE_URL`, `OPENCODE_WARMUP`, and `OPENCODE_ABORT_GRACE` environment variables.

## Safety and validation

The harness is fail-closed: it preserves incomplete worktrees, refuses ambiguous or dirty starting states, validates work before merge, and never stores credentials in the repository. Run its focused test suite with:

```bash
tools/agent/check.sh
```

`tools/worktree-status.sh` summarizes registered worktrees. Review any `DIRTY_UNCOMMITTED` or `AHEAD_UNMERGED` entry manually; do not delete it as cleanup.
