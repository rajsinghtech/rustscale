#!/usr/bin/env bash
# agent-review.sh -- inspect a preserved agent worktree without changing it.
# Usage: tools/agent/agent-review.sh <title>
set -euo pipefail

TITLE="${1:?usage: agent-review.sh <title>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
START_DIR="$(git -C "$SCRIPT_DIR/../.." rev-parse --show-toplevel)"
MAIN_DIR="$(git -C "$START_DIR" worktree list --porcelain | sed -n 's/^worktree //p' | sed -n '1p')"
WT_DIR=""

fail() {
  echo "[agent-review] $*" >&2
  echo "NEXT: inspect the preserved worktree manually: $WT_DIR" >&2
  exit 1
}

[[ "$TITLE" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] \
  || { echo "[agent-review] invalid title" >&2; exit 2; }
[[ -n "$MAIN_DIR" ]] || { echo "[agent-review] could not determine main worktree" >&2; exit 1; }
MAIN_DIR="$(cd "$MAIN_DIR" && pwd -P)"
WT_DIR="$MAIN_DIR/.worktrees/$TITLE"
WT_BRANCH="agent/$TITLE"
TMP="$(mktemp "${TMPDIR:-/tmp}/rustscale-agent-review.XXXXXX")"
trap 'rm -f "$TMP"' EXIT
[[ -d "$WT_DIR" ]] || fail "worktree not found: $WT_DIR"
[[ "$(git -C "$WT_DIR" branch --show-current)" == "$WT_BRANCH" ]] \
  || fail "worktree is not on $WT_BRANCH"
git -C "$MAIN_DIR" fetch origin master || fail "could not fetch origin master"
git -C "$MAIN_DIR" rev-parse --verify --quiet origin/master >/dev/null \
  || fail "origin/master is unavailable after fetch"
MASTER_SHA="$(git -C "$MAIN_DIR" rev-parse master)"
ORIGIN_MASTER_SHA="$(git -C "$MAIN_DIR" rev-parse origin/master)"
if [[ "$MASTER_SHA" != "$ORIGIN_MASTER_SHA" ]]; then
  echo "##STATUS:STALE path=$WT_DIR branch=$WT_BRANCH local_master=$MASTER_SHA origin_master=$ORIGIN_MASTER_SHA" >&2
  echo "NEXT: reconcile local master with origin/master, then rerun tools/agent/agent-review.sh $TITLE" >&2
  exit 1
fi

BASE="$(git -C "$WT_DIR" merge-base "$MASTER_SHA" HEAD)"
HEAD="$(git -C "$WT_DIR" rev-parse HEAD)"
ahead="$(git -C "$WT_DIR" rev-list --count master..HEAD)"
behind="$(git -C "$WT_DIR" rev-list --count HEAD..master)"
echo "[agent-review] worktree=$WT_DIR branch=$WT_BRANCH" >&2
echo "[agent-review] base=$BASE head=$HEAD ahead=$ahead behind=$behind" >&2
if (( behind > 0 )); then
  echo "##STATUS:STALE path=$WT_DIR branch=$WT_BRANCH behind=$behind" >&2
  echo "NEXT: rebase $WT_BRANCH onto master, then rerun tools/agent/agent-review.sh $TITLE" >&2
  exit 1
fi
echo "[agent-review] status (first 60 lines):" >&2
git -C "$WT_DIR" status --short | head -60 >&2
echo "[agent-review] diff stat (first 60 lines):" >&2
git -C "$WT_DIR" diff --stat "$BASE" HEAD | head -60 >&2
git -C "$WT_DIR" diff --stat | head -60 >&2
git -C "$WT_DIR" diff --cached --stat | head -60 >&2

if ! git -C "$WT_DIR" diff --check "$BASE" HEAD >"$TMP" 2>&1 \
  || ! git -C "$WT_DIR" diff --check >>"$TMP" 2>&1 \
  || ! git -C "$WT_DIR" diff --cached --check >>"$TMP" 2>&1; then
  head -80 "$TMP" >&2
  fail "git diff --check failed"
fi

changed=()
while IFS= read -r path; do
  [[ -n "$path" ]] && changed+=("$path")
done < <(
  { git -C "$WT_DIR" diff --name-only "$BASE" HEAD; git -C "$WT_DIR" diff --name-only; git -C "$WT_DIR" diff --cached --name-only; git -C "$WT_DIR" ls-files --others --exclude-standard; } \
    | awk 'NF && !seen[$0]++'
)
validator=(tools/check.sh)
if (( ${#changed[@]} > 0 )); then
  bench_only=1
  harness_policy_only=1
  crate_dir=""
  for path in "${changed[@]}"; do
    if [[ "$path" != tools/bench/* ]]; then
      bench_only=0
    fi
    if [[ "$path" =~ ^crates/([^/]+)/ ]]; then
      candidate="${BASH_REMATCH[1]}"
      if [[ -z "$crate_dir" ]]; then
        crate_dir="$candidate"
      elif [[ "$crate_dir" != "$candidate" ]]; then
        crate_dir="multiple"
      fi
    else
      crate_dir="multiple"
    fi
    case "$path" in
      .gitignore|AGENTS.md|CLAUDE.md|tools/check.sh|tools/agent/*) ;;
      *) harness_policy_only=0 ;;
    esac
  done
  if (( harness_policy_only == 1 )); then
    validator=(tools/agent/check.sh)
  elif (( bench_only == 1 )); then
    validator=(tools/bench/check.sh)
  elif [[ "$crate_dir" != "" && "$crate_dir" != multiple && -f "$WT_DIR/crates/$crate_dir/Cargo.toml" ]]; then
    package="$(sed -n 's/^name[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$WT_DIR/crates/$crate_dir/Cargo.toml" | sed -n '1p')"
    if [[ -n "$package" ]]; then
      validator=(tools/check.sh "$package")
    fi
  fi
fi

echo "[agent-review] validator: ${validator[*]}" >&2
if ! (cd "$WT_DIR" && "${validator[@]}") >"$TMP" 2>&1; then
  head -120 "$TMP" >&2
  fail "validator failed"
fi
git -C "$MAIN_DIR" fetch origin master || fail "could not refresh origin/master after validation"
MASTER_AFTER="$(git -C "$MAIN_DIR" rev-parse master)"
ORIGIN_MASTER_AFTER="$(git -C "$MAIN_DIR" rev-parse origin/master)"
if [[ "$MASTER_AFTER" != "$MASTER_SHA" || "$ORIGIN_MASTER_AFTER" != "$MASTER_SHA" ]]; then
  echo "##STATUS:STALE path=$WT_DIR branch=$WT_BRANCH master_changed=1" >&2
  echo "NEXT: rerun tools/agent/agent-review.sh $TITLE against the current master" >&2
  exit 1
fi
echo "##STATUS:REVIEWED path=$WT_DIR branch=$WT_BRANCH" >&2
if [[ -n "$(git -C "$WT_DIR" status --porcelain)" ]]; then
  echo "NEXT: resolve or commit the preserved worktree changes before tools/agent/worktree-merge.sh $TITLE" >&2
else
  echo "NEXT: tools/agent/worktree-merge.sh $TITLE" >&2
fi
