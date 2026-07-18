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

## Optional remote Linux validation

`tools/agent/remote-validate.sh` is an opt-in SSH backend for native Linux validation. Its remembered default is `ubuntu@raj-builder`; select another OpenSSH host or alias with `RUSTSCALE_REMOTE_TARGET`, or disable all connections with `RUSTSCALE_REMOTE_DISABLE=1`. The wrapper uses the user's normal OpenSSH configuration and `known_hosts`, but requires strict host-key verification, `BatchMode`, no TTY, no forwarding (including SSH-agent forwarding), a bounded connect timeout, keepalives, and an outer process-group deadline. Review and add a new host key with ordinary interactive `ssh` before using the non-interactive harness; the harness never accepts an unknown or changed key.

Start with the credential-free preflight:

```bash
tools/agent/remote-validate.sh preflight

RUSTSCALE_REMOTE_TARGET=builder-alias \
  tools/agent/remote-validate.sh check
RUSTSCALE_REMOTE_TARGET=builder-alias \
  tools/agent/remote-validate.sh check rustscale-tsnet
```

The preflight records Linux distribution/kernel, architecture, CPUs, memory, free disk, open-file limits, archive integrity, and Rust/Go/optional-tool availability. It installs nothing. The ephemeral remote runner raises only its inherited soft open-file limit, up to 65,536 or the existing hard limit, and requires at least 4,096 so the 1,000-stream workspace acceptance test is not weakened; it never changes persistent host limits. Missing prerequisites produce exact, copyable bootstrap commands in the terminal and result JSON; a user or administrator must review and run them separately. In particular, toolchain setup is never hidden inside a validation run.

Each run captures `HEAD`, the current index tree, and a SHA-256 of the complete tracked diff from `HEAD`. It constructs a temporary candidate tree by applying the captured unstaged tracked diff to the reviewed Git index, then sends a hash-verified source archive. Staged new files are included; untracked and ignored files are not. Stage a new file only after reviewing it if it must be part of the candidate. The archive rejects `.git`, `target`, `.agent-runs`, `.worktrees`, secret directories, private-key/credential-like paths, and environment files. No existing remote checkout is read or modified.

The remote side extracts into a new mode-0700 `rustscale-remote.*` temporary directory. Remote GNU `timeout` runs the command in a new session; local timeout, disconnect, `HUP`, interruption, and normal completion terminate the remote process group and remove that directory. Build targets, Cargo/Go caches, temporary files, and XDG state are redirected beneath it. Absence of the remote cleanup acknowledgement is a failed, `cleanup_unconfirmed` run.

Available journeys are:

```bash
tools/agent/remote-validate.sh check                 # bounded tools/check.sh
tools/agent/remote-validate.sh check rustscale-wg    # focused package gate
tools/agent/remote-validate.sh interop               # tools/interop.sh
tools/agent/remote-validate.sh tun --allow-privileged
tools/agent/remote-validate.sh install \
  --allow-privileged --allow-install
```

`interop` and `tun` never copy local credentials or `.secrets`; they can consume only Tailscale credentials separately provisioned in the remote SSH environment. The TUN journey additionally requires passwordless `sudo` and `/dev/net/tun`. `install` runs the fail-closed Linux replacement journey with its required-mode setting and can mutate standard install/systemd/TUN paths, so it requires two explicit flags and must be used only on a disposable, unoccupied builder. None of these commands forwards AI-provider, cloud, GitHub, SSH-agent, or local filesystem credentials.

Machine-readable provenance is written atomically under the ignored `.agent-runs/remote-validation/` directory. It contains hashes, bounded resource facts, missing prerequisite names, bootstrap commands, status, and cleanup evidence, but no command log, environment values, credential values, or absolute local path. Terminal and SSH output is intentionally not retained by the harness. The builder or access layer may independently record SSH sessions; assume remote commands and terminal output are observable and never print or transfer secrets.

A successful `raj-builder` run is authoritative only for the exact source hash and native Linux **aarch64** behavior that the selected journey exercised. It does not establish x86_64 or musl compatibility, macOS/Windows behavior, published archive/container correctness, cross-platform packaging, coverage, fuzzing, Pages, release signing, or protected real-control interop. Local platform gates and the corresponding GitHub Actions jobs remain authoritative for those scopes; required CI cannot be replaced by this optional backend.

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

`tools/worktree-status.sh` summarizes registered worktrees and includes an evidence column. `MERGED_CLEAN` means the worktree HEAD is an ancestor of `master`. For a clean, non-ancestor branch, `SQUASH_INTEGRATED` requires either an exact HEAD tree found in `master` history or an exact stable patch ID match between the branch's aggregate merge-base-to-HEAD diff and a commit after that merge base. An unmatched branch remains `AHEAD_UNMERGED`; the tool does not infer integration from branch titles or commit subjects. Dirty state takes precedence over all integration checks.

Generate a session reconciliation snapshot without changing any worktree or branch with:

```bash
tools/agent/reconcile-report.sh
```

The default report is the ignored `.agent-runs/reconciliation-report.tsv`. It contains every registered non-main worktree. Codex sessions are linked only when their recorded worktree path and branch both match Git's registry; an existing branch without its recorded worktree is `STALE_SESSION`, and a record with neither is `ORPHAN_SESSION`. Older run directories without standard metadata are conservatively reported as `ORPHAN_SESSION` rather than linked by matching their directory names. `MISMATCHED_SESSION`, `DIRTY_UNCOMMITTED`, and `AHEAD_UNMERGED` entries require manual review. Never delete or merge them as cleanup.
