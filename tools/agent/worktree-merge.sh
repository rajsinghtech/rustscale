#!/usr/bin/env bash
# worktree-merge.sh — verify agent worktree and merge into master.
# Usage: tools/agent/worktree-merge.sh <title>
# Runs cargo build/test/clippy (or tools/check.sh if present) in the worktree.
# If green, merges agent/<title> into master (--no-ff), removes the worktree
# and branch. On red, prints failures and leaves the worktree in place.
# Auto-resolves Cargo.lock conflicts (union-merges Cargo.toml deps) if the
# merge fails from parallel-dependency additions across worktree agents.
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

# Agents often write files without committing. Stage and commit any uncommitted
# changes in the worktree before merging, otherwise the work is lost.
cd "$REPO_DIR/$WT_DIR"
if ! git diff --cached --quiet 2>/dev/null || ! git diff --quiet 2>/dev/null || [ -n "$(git ls-files --others --exclude-standard 2>/dev/null)" ]; then
  echo "[merge] committing uncommitted agent changes in worktree ..."
  git add -A
  git -c user.name=rajsinghtech -c user.email=rajsinghcpre@gmail.com \
    commit -q -m "agent: $TITLE" --no-verify 2>/dev/null || true
fi

cd "$REPO_DIR"
git checkout master
MERGE_EXIT=0
MERGE_OUT=$(git merge --no-ff "$WT_BRANCH" -m "Merge $WT_BRANCH" 2>&1) || MERGE_EXIT=$?

if [ "$MERGE_EXIT" -ne 0 ]; then
  CONFLICTED=$(git diff --name-only --diff-filter=U 2>/dev/null || true)
  if echo "$CONFLICTED" | grep -q '^Cargo\.lock$'; then
    echo "[merge] Cargo.lock conflict detected — auto-resolving"
    git checkout --theirs Cargo.lock 2>/dev/null || true
    if echo "$CONFLICTED" | grep -q '^Cargo\.toml$'; then
      echo "[merge] Cargo.toml conflict — union-merging (deps kept from both sides)"
      git show :1:Cargo.toml > /tmp/_cargo_base 2>/dev/null || true
      git show :2:Cargo.toml > /tmp/_cargo_ours 2>/dev/null || true
      git show :3:Cargo.toml > /tmp/_cargo_theirs 2>/dev/null || true
      if [ -f /tmp/_cargo_ours ] && [ -f /tmp/_cargo_base ] && [ -f /tmp/_cargo_theirs ]; then
        cp /tmp/_cargo_ours Cargo.toml
        git merge-file --union Cargo.toml /tmp/_cargo_base /tmp/_cargo_theirs 2>/dev/null || true
        git add Cargo.toml
      fi
      rm -f /tmp/_cargo_*
    fi
    cargo generate-lockfile 2>/dev/null || cargo update --workspace 2>/dev/null || true
    git add Cargo.lock
    echo "[merge] re-running checks after conflict resolution ..."
    CHECK_OUT=$(run_checks 2>&1) || {
      echo "$CHECK_OUT"
      echo "[merge] CHECKS FAILED after conflict resolution — manual resolution needed"
      echo "[merge]   git status"
      exit 1
    }
    GIT_EDITOR=true git merge --continue --no-edit 2>/dev/null \
      || git commit -m "Merge $WT_BRANCH (with cargo conflict resolution)" --no-edit 2>/dev/null || true
  else
    echo "[merge] MERGE FAILED with conflicts outside Cargo.lock — manual resolution needed"
    echo "[merge]   conflicted files:"
    echo "$CONFLICTED"
    exit "$MERGE_EXIT"
  fi
fi

echo "[merge] checking formatting across workspace ..."
(cargo fmt --all --check 2>&1) || {
  echo "[merge] WARNING: formatting drift detected in workspace crates."
  echo "[merge]   Run 'cargo fmt --all' to fix, then commit cleanly."
  echo "[merge]   (This is a hint — the merge itself succeeded.)"
}

echo "[merge] cleaning up worktree and branch"
git worktree remove "$WT_DIR" && git branch -d "$WT_BRANCH"

echo "[merge] done — $WT_BRANCH merged to master"
