#!/usr/bin/env bash
# worktree-merge.sh — validate a committed agent branch, then merge it safely.
# Usage: tools/agent/worktree-merge.sh <title>
set -euo pipefail

TITLE="${1:?usage: worktree-merge.sh <title>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
START_DIR="$(git -C "$SCRIPT_DIR/../.." rev-parse --show-toplevel)"
WT_BRANCH="agent/$TITLE"

fail() {
  echo "[merge] $*" >&2
  echo "##STATUS:FAILED title=$TITLE" >&2
  exit 1
}

[[ "$TITLE" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] \
  || fail "invalid title (use letters, digits, '.', '_' or '-')"
MAIN_DIR="$(git -C "$START_DIR" worktree list --porcelain | sed -n 's/^worktree //p' | sed -n '1p')"
[[ -n "$MAIN_DIR" ]] || fail "could not determine main worktree"
MAIN_DIR="$(cd "$MAIN_DIR" && pwd -P)"
WT_DIR="$MAIN_DIR/.worktrees/$TITLE"

[[ "$(git -C "$MAIN_DIR" branch --show-current)" == master ]] \
  || fail "main worktree is not on master: $MAIN_DIR"
git -C "$MAIN_DIR" diff --quiet || fail "master has unstaged changes"
git -C "$MAIN_DIR" diff --cached --quiet || fail "master has staged changes"
[[ -z "$(git -C "$MAIN_DIR" ls-files --others --exclude-standard)" ]] \
  || fail "master has untracked files"

[[ -d "$WT_DIR" ]] || fail "worktree not found: $WT_DIR"
registered_branch="$(git -C "$MAIN_DIR" worktree list --porcelain | awk -v target="$WT_DIR" '
  /^worktree / { path=substr($0, 10); next }
  /^branch / && path == target { sub("refs/heads/", "", $0); sub("branch ", "", $0); print; exit }
')"
[[ "$registered_branch" == "$WT_BRANCH" ]] \
  || fail "expected registered $WT_DIR on $WT_BRANCH (found ${registered_branch:-nothing})"
[[ "$(git -C "$WT_DIR" branch --show-current)" == "$WT_BRANCH" ]] \
  || fail "worktree branch does not match $WT_BRANCH"

require_clean() {
  local dir="$1" label="$2"
  git -C "$dir" diff --quiet || fail "$label has unstaged changes"
  git -C "$dir" diff --cached --quiet || fail "$label has staged changes"
  [[ -z "$(git -C "$dir" ls-files --others --exclude-standard)" ]] \
    || fail "$label has untracked files"
}

run_checks() {
  local dir="$1"
  if [[ -x "$dir/tools/check.sh" ]]; then
    (cd "$dir" && ./tools/check.sh)
  else
    (cd "$dir" && cargo build --workspace --all-targets && cargo test --workspace && cargo clippy --workspace --all-targets -- -D warnings && cargo fmt --all --check)
  fi
}

require_clean "$WT_DIR" "agent worktree"
echo "[merge] validating committed agent head $WT_BRANCH" >&2
run_checks "$WT_DIR" || fail "validation failed for $WT_BRANCH; worktree preserved"
require_clean "$WT_DIR" "agent worktree after validation"
require_clean "$MAIN_DIR" "master before merge"

echo "[merge] merging $WT_BRANCH into master" >&2
if ! git -C "$MAIN_DIR" merge --no-ff "$WT_BRANCH" -m "Merge $WT_BRANCH"; then
  echo "[merge] merge conflict; aborting and preserving $WT_DIR" >&2
  git -C "$MAIN_DIR" merge --abort || fail "merge conflict and merge --abort failed"
  fail "merge conflict; resolve it explicitly with the preserved worktree"
fi

echo "[merge] validating merged master" >&2
run_checks "$MAIN_DIR" || fail "merged-master validation failed; master and worktree preserved"

echo "[merge] cleaning up $WT_DIR and $WT_BRANCH" >&2
git -C "$MAIN_DIR" worktree remove "$WT_DIR"
git -C "$MAIN_DIR" branch -d "$WT_BRANCH"
echo "##STATUS:MERGED path=$WT_DIR branch=$WT_BRANCH" >&2
