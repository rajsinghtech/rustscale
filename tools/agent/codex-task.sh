#!/usr/bin/env bash
# codex-task.sh — fail-closed implementation-agent worktree wrapper.
# Usage: tools/agent/codex-task.sh <title> <prompt> [deadline-seconds]
set -euo pipefail

TITLE="${1:?usage: codex-task.sh <title> <prompt> [deadline-seconds]}"
PROMPT="${2:?usage: codex-task.sh <title> <prompt> [deadline-seconds]}"
DEADLINE="${3:-2400}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
START_DIR="$(git -C "$SCRIPT_DIR/../.." rev-parse --show-toplevel)"

fail() {
  echo "[codex-task] $*" >&2
  echo "##STATUS:FAILED title=$TITLE" >&2
  exit 1
}

[[ "$TITLE" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] \
  || fail "invalid title (use letters, digits, '.', '_' or '-')"
[[ "$DEADLINE" =~ ^[1-9][0-9]*$ ]] || fail "deadline must be a positive integer"

# The first registered worktree is Git's primary checkout. Do not treat a
# secondary checkout of master as the main tree.
MAIN_DIR="$(git -C "$START_DIR" worktree list --porcelain | sed -n 's/^worktree //p' | sed -n '1p')"
[[ -n "$MAIN_DIR" ]] || fail "could not determine the main worktree"
MAIN_DIR="$(cd "$MAIN_DIR" && pwd -P)"

[[ "$(git -C "$MAIN_DIR" branch --show-current)" == "master" ]] \
  || fail "main worktree is not on master: $MAIN_DIR"
git -C "$MAIN_DIR" diff --quiet || fail "main worktree has unstaged changes"
git -C "$MAIN_DIR" diff --cached --quiet || fail "main worktree has staged changes"
[[ -z "$(git -C "$MAIN_DIR" ls-files --others --exclude-standard)" ]] \
  || fail "main worktree has untracked files"

WT_DIR="$MAIN_DIR/.worktrees/$TITLE"
WT_BRANCH="agent/$TITLE"
git -C "$MAIN_DIR" show-ref --verify --quiet "refs/heads/$WT_BRANCH" \
  && fail "branch already exists: $WT_BRANCH"
[[ ! -e "$WT_DIR" ]] || fail "worktree path already exists: $WT_DIR"

echo "[codex-task] creating $WT_DIR on $WT_BRANCH" >&2
git -C "$MAIN_DIR" worktree add "$WT_DIR" -b "$WT_BRANCH" master

AGENT_PROMPT=$'Do not commit changes and do not spawn agents.\n\n'"$PROMPT"
if command -v timeout >/dev/null 2>&1; then
  RUNNER=(timeout "$DEADLINE")
elif command -v gtimeout >/dev/null 2>&1; then
  RUNNER=(gtimeout "$DEADLINE")
else
  RUNNER=()
  echo "[codex-task] no timeout command found; running without a platform deadline" >&2
fi

if [[ ${#RUNNER[@]} -gt 0 ]]; then
  RUN_COMMAND=("${RUNNER[@]}" codex -a never exec -m gpt-5.6-terra -s workspace-write -C "$WT_DIR" "$AGENT_PROMPT")
else
  RUN_COMMAND=(codex -a never exec -m gpt-5.6-terra -s workspace-write -C "$WT_DIR" "$AGENT_PROMPT")
fi

if "${RUN_COMMAND[@]}"; then
  echo "##STATUS:DONE path=$WT_DIR branch=$WT_BRANCH" >&2
else
  status=$?
  echo "[codex-task] Codex failed (exit $status); worktree preserved" >&2
  echo "##STATUS:FAILED path=$WT_DIR branch=$WT_BRANCH exit=$status" >&2
  exit "$status"
fi
