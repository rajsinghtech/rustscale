#!/usr/bin/env bash
# worktree-merge.sh — verify agent worktree and merge into master.
# Usage: tools/agent/worktree-merge.sh <title>
# Runs cargo build/test/clippy (or tools/check.sh if present) in the worktree.
# If green, merges agent/<title> into master (--no-ff), removes the worktree
# and branch. On red, prints failures and leaves the worktree in place.
set -euo pipefail

TITLE="${1:?usage: worktree-merge.sh <title>}"
WT_DIR=".worktrees/$TITLE"
WT_BRANCH="agent/$TITLE"
REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

if [ ! -d "$REPO_DIR/$WT_DIR" ]; then
  echo "worktree not found: $WT_DIR" >&2
  exit 1
fi

run_checks() {
  if [ -x "$REPO_DIR/tools/check.sh" ]; then
    "$REPO_DIR/tools/check.sh"
  else
    cargo build --workspace --all-targets
    cargo test --workspace
    cargo clippy --workspace --all-targets -- -D warnings
  fi
}

echo "[merge] running checks in $WT_DIR ..."
CHECK_OUT=$(cd "$REPO_DIR/$WT_DIR" && run_checks 2>&1) || {
  echo "$CHECK_OUT"
  echo "[merge] CHECKS FAILED — worktree left in place for inspection"
  echo "[merge]   cd $REPO_DIR/$WT_DIR && tools/check.sh"
  exit 1
}

echo "[merge] checks green, merging $WT_BRANCH into master"
(cd "$REPO_DIR" && git checkout master && git merge --no-ff "$WT_BRANCH" -m "Merge $WT_BRANCH")

echo "[merge] cleaning up worktree and branch"
(cd "$REPO_DIR" && git worktree remove "$WT_DIR" && git branch -d "$WT_BRANCH")

echo "[merge] done — $WT_BRANCH merged to master"
