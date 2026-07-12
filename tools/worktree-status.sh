#!/usr/bin/env bash
# tools/worktree-status.sh — one-shot overview of ALL git worktrees.
# Shows branch, dirty status, ahead/behind master, and whether each
# branch is already merged into master.
#
# Also checks the main repo for an in-progress merge (conflicts).
#
# Usage:
#   tools/worktree-status.sh              # human-readable table
#   tools/worktree-status.sh --json       # machine-readable JSON
#   tools/worktree-status.sh --porcelain  # tab-separated, one per line
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
MODE="${1:-table}"

main_tree_status() {
  local mstate="" conflicts=""
  if [ -f "$REPO_DIR/.git/MERGE_MSG" ]; then
    mstate="MERGE_IN_PROGRESS"
    local branch
    branch="$(git -C "$REPO_DIR" branch --show-current 2>/dev/null || echo "detached")"
    conflicts="$(git -C "$REPO_DIR" diff --name-only --diff-filter=U 2>/dev/null | tr '\n' ' ')"
    mstate="MERGE_INTO_${branch}_CONFLICTS:${conflicts}"
  fi
  echo "$mstate"
}

worktree_info() {
  local wt_dir="$1"
  local branch dirty ahead_behind merged

  branch="$(git -C "$wt_dir" branch --show-current 2>/dev/null || echo "(detached)")"
  dirty="$(git -C "$wt_dir" status --short 2>/dev/null | wc -l | tr -d ' ')"

  # ahead/behind master
  local ahead=0 behind=0
  ahead="$(git -C "$wt_dir" rev-list --count master..HEAD 2>/dev/null || echo 0)"
  behind="$(git -C "$wt_dir" rev-list --count HEAD..master 2>/dev/null || echo 0)"
  ahead_behind="${ahead}|${behind}"

  # merged if HEAD is an ancestor of master
  local merged="no"
  if git -C "$wt_dir" merge-base --is-ancestor HEAD master 2>/dev/null; then
    merged="yes"
  fi

  # last commit
  local last_commit last_subject
  last_commit="$(git -C "$wt_dir" log --oneline -1 HEAD 2>/dev/null || echo "?")"

  printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$(basename "$wt_dir")" "$branch" "$dirty" "$ahead_behind" "$merged" "$last_commit"
}

case "$MODE" in
  --json)
    merge_state="$(main_tree_status)"
    printf '{"main_tree":"%s","worktrees":[' "$merge_state"
    first=1
    while IFS=$'\t' read -r name branch dirty ahead_behind merged last; do
      [ "$first" = 0 ] && echo ","
      first=0
      ahead="${ahead_behind%%|*}"
      behind="${ahead_behind##*|}"
      m=$([ "$merged" = "yes" ] && echo true || echo false)
      printf '{"name":"%s","branch":"%s","dirty":%s,"ahead":%s,"behind":%s,"merged":%s,"last":"%s"}' \
        "$name" "$branch" "$dirty" "$ahead" "$behind" "$m" "$(printf '%s' "$last" | sed 's/"/\\"/g')"
    done < <(worktree_info "$REPO_DIR"; git -C "$REPO_DIR" worktree list --porcelain 2>/dev/null | grep '^worktree ' | while read -r _ w; do [ "$w" != "$REPO_DIR" ] && worktree_info "$w"; done)
    echo "]}" ;;
  --porcelain)
    worktree_info "$REPO_DIR"
    git -C "$REPO_DIR" worktree list --porcelain 2>/dev/null | grep '^worktree ' | while read -r _ w; do
      [ "$w" != "$REPO_DIR" ] && worktree_info "$w"
    done
    ;;
  *)
    merge_state="$(main_tree_status)"
    echo "Main tree: $([ -z "$merge_state" ] && echo 'clean' || echo "$merge_state")"
    printf '%-24s %-28s %s %-8s %-4s %s\n' "WORKTREE" "BRANCH" "DIRTY" "A/B" "MERGED" "LAST COMMIT"
    printf '%-24s %-28s %s %-8s %-4s %s\n' "-------" "------" "----" "---" "------" "-----------"
    worktree_info "$REPO_DIR"
    git -C "$REPO_DIR" worktree list --porcelain 2>/dev/null | grep '^worktree ' | while read -r _ w; do
      [ "$w" != "$REPO_DIR" ] && worktree_info "$w"
    done | while IFS=$'\t' read -r name branch dirty ahead_behind merged last; do
      ahead="${ahead_behind%%|*}"
      behind="${ahead_behind##*|}"
      printf '%-24s %-28s %-4s %2s/%-3s %-6s %s\n' \
        "$name" "$branch" "$dirty" "$ahead" "$behind" "$merged" "$last"
    done
    ;;
esac
