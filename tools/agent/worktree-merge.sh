#!/usr/bin/env bash
# worktree-merge.sh — verify agent worktree and merge into master.
# Usage: tools/agent/worktree-merge.sh <title>
# Runs tools/check.sh in the worktree, then merges agent/<title> into
# master (--no-ff), removes the worktree and branch. On failure prints
# clear instructions and leaves the worktree in place.
#
# Auto-resolves:
#   - Cargo.lock conflicts (accept --theirs, regenerate)
#   - Cargo.toml conflicts (union-merge, keeping both sides' deps)
#   - Rust file conflicts in disjoint-feature worktrees (union-merge,
#     then checks; reverts if tests fail)
set -euo pipefail

TITLE="${1:?usage: worktree-merge.sh <title>}"
WT_DIR=".worktrees/$TITLE"
WT_BRANCH="agent/$TITLE"
REPO_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

if [ ! -d "$REPO_DIR/$WT_DIR" ]; then
  echo "[merge] worktree not found: $WT_DIR" >&2
  echo "##STATUS:FAILED worktree_not_found=$WT_DIR" >&2
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
  echo "[merge] CHECKS FAILED — worktree left in place for inspection" >&2
  echo "[merge]   cd $REPO_DIR/$WT_DIR && tools/check.sh" >&2
  echo "##STATUS:FAILED checks_in_worktree" >&2
  exit 1
}

echo "[merge] checks green, merging $WT_BRANCH into master"

# Stage and commit any uncommitted changes in the worktree before merging.
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
  echo "[merge] conflicts detected:"
  echo "$CONFLICTED" | sed 's/^/  /'

  # --- Cargo.lock: accept theirs + regenerate ---
  if echo "$CONFLICTED" | grep -q '^Cargo\.lock$'; then
    echo "[merge] Cargo.lock conflict — accepting --theirs and regenerating"
    git checkout --theirs Cargo.lock 2>/dev/null || true
    git add Cargo.lock
  fi

  # --- Cargo.toml: three-way union merge ---
  if echo "$CONFLICTED" | grep -q '^Cargo\.toml$'; then
    echo "[merge] Cargo.toml conflict — union-merging"
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

  # --- Rust files (.rs): union-merge for disjoint feature worktrees ---
  RS_CONFLICTS=$(echo "$CONFLICTED" | grep '\.rs$' || true)
  if [ -n "$RS_CONFLICTS" ]; then
    echo "[merge] Rust file conflicts — attempting union-merge"
    FAILED_RS=""
    while IFS= read -r f; do
      base="/tmp/_rs_base_$$_$(basename "$f")"
      ours="/tmp/_rs_ours_$$_$(basename "$f")"
      theirs="/tmp/_rs_theirs_$$_$(basename "$f")"
      git show ":1:$f" > "$base" 2>/dev/null || true
      git show ":2:$f" > "$ours" 2>/dev/null || true
      git show ":3:$f" > "$theirs" 2>/dev/null || true
      if [ -f "$ours" ] && [ -f "$base" ] && [ -f "$theirs" ]; then
        cp "$ours" "$f"
        git merge-file --union "$f" "$base" "$theirs" 2>/dev/null || true
        if git merge-file --check "$f" "$base" "$theirs" 2>/dev/null; then
          git add "$f"
          echo "[merge]   resolved: $f"
        else
          FAILED_RS="$FAILED_RS $f"
        fi
      fi
      rm -f "$base" "$ours" "$theirs"
    done <<< "$RS_CONFLICTS"
    if [ -n "$FAILED_RS" ]; then
      echo "[merge]   UNION-MERGE FAILED for:$FAILED_RS"
      echo "[merge]   These files need manual resolution (both sides modified same lines)"
    fi
  fi

  # Regenerate lockfile if Cargo files were involved
  if echo "$CONFLICTED" | grep -q '^Cargo\.\(lock\|toml\)$'; then
    cargo generate-lockfile 2>/dev/null || cargo update --workspace 2>/dev/null || true
    git add Cargo.lock 2>/dev/null || true
  fi

  # Check whether all conflicts were resolved
  REMAINING=$(git diff --name-only --diff-filter=U 2>/dev/null || true)
  if [ -z "$REMAINING" ]; then
    echo "[merge] all conflicts resolved — re-running checks ..."
    CHECK_OUT=$(run_checks 2>&1) || {
      echo "$CHECK_OUT"
      echo "[merge] CHECKS FAILED after conflict resolution — manual resolution needed" >&2
      echo "[merge]   git status" >&2
      echo "##STATUS:FAILED post_merge_checks" >&2
      exit 1
    }
    GIT_EDITOR=true git merge --continue --no-edit 2>/dev/null \
      || git commit -m "Merge $WT_BRANCH (with conflict resolution)" --no-edit 2>/dev/null || true
  else
    echo "[merge] REMAINING UNRESOLVED CONFLICTS:" >&2
    echo "$REMAINING" | sed 's/^/  /' >&2
    echo "[merge] To resolve: edit each file, remove conflict markers, git add, then git commit" >&2
    echo "[merge] Or abort with: git merge --abort" >&2
    echo "##STATUS:FAILED unresolved_conflicts" >&2
    exit 1
  fi
fi

echo "[merge] checking formatting across workspace ..."
(cargo fmt --all --check 2>&1) || {
  echo "[merge] WARNING: formatting drift detected — run 'cargo fmt --all' then commit" >&2
}

echo "[merge] cleaning up worktree and branch"
git worktree remove "$WT_DIR" && git branch -d "$WT_BRANCH"

echo "[merge] done — $WT_BRANCH merged to master"
echo "##STATUS:MERGED branch=$WT_BRANCH" >&2
