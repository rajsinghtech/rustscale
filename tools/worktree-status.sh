#!/usr/bin/env bash
# tools/worktree-status.sh — fail-closed overview of registered worktrees.
# Usage: tools/worktree-status.sh [--json|--porcelain]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
START_DIR="$(git -C "$SCRIPT_DIR/.." rev-parse --show-toplevel)"
MODE="${1:-table}"

case "$MODE" in table|--json|--porcelain) ;; *) echo "usage: worktree-status.sh [--json|--porcelain]" >&2; exit 2 ;; esac

die() { echo "[worktree-status] $*" >&2; exit 1; }
json_escape() { sed 's/\\/\\\\/g; s/"/\\"/g; s/	/\\t/g'; }

MAIN_DIR="$(git -C "$START_DIR" worktree list --porcelain | sed -n 's/^worktree //p' | sed -n '1p')"
[[ -n "$MAIN_DIR" ]] || die "could not determine main worktree"
MAIN_DIR="$(cd "$MAIN_DIR" && pwd -P)"
git -C "$MAIN_DIR" rev-parse --verify --quiet master >/dev/null || die "master does not exist"

TMP="$(mktemp "${TMPDIR:-/tmp}/worktree-status.XXXXXX")"
trap 'rm -f "$TMP"' EXIT
REGISTERED=()
while IFS= read -r path; do
  [[ -n "$path" ]] || continue
  path="$(cd "$path" && pwd -P)"
  REGISTERED+=("$path")
done < <(git -C "$MAIN_DIR" worktree list --porcelain | sed -n 's/^worktree //p')

write_registered() {
  local path="$1" branch dirty ahead behind class last
  branch="$(git -C "$path" branch --show-current)"
  dirty="$(git -C "$path" status --porcelain | wc -l | tr -d ' ')"
  ahead="$(git -C "$path" rev-list --count master..HEAD)"
  behind="$(git -C "$path" rev-list --count HEAD..master)"
  last="$(git -C "$path" log -1 --oneline HEAD)"

  if [[ "$path" == "$MAIN_DIR" ]]; then
    class="MAIN"
  elif [[ "$dirty" != 0 ]]; then
    class="DIRTY_UNCOMMITTED"
  elif [[ "$(git -C "$path" rev-parse HEAD)" == "$(git -C "$MAIN_DIR" rev-parse master)" ]]; then
    class="EMPTY_STALE"
  elif git -C "$path" merge-base --is-ancestor HEAD master; then
    class="MERGED_CLEAN"
  elif [[ "$ahead" != 0 ]]; then
    class="AHEAD_UNMERGED"
  else
    class="EMPTY_STALE"
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$class" "$path" "$branch" "$dirty" "$ahead" "$behind" "$last" >>"$TMP"
}

for path in "${REGISTERED[@]}"; do
  write_registered "$path"
done

is_registered() {
  local candidate="$1" path
  for path in "${REGISTERED[@]}"; do
    [[ "$path" == "$candidate" ]] && return 0
  done
  return 1
}

if [[ -d "$MAIN_DIR/.worktrees" ]]; then
  for path in "$MAIN_DIR/.worktrees"/*; do
    [[ -d "$path" ]] || continue
    path="$(cd "$path" && pwd -P)"
    if ! is_registered "$path"; then
      printf 'ORPHAN\t%s\t-\t-\t-\t-\tunregistered directory\n' "$path" >>"$TMP"
    fi
  done
fi

attention=0
while IFS=$'\t' read -r class path _; do
  case "$class" in
    MAIN|MERGED_CLEAN) ;;
    DIRTY_UNCOMMITTED|AHEAD_UNMERGED|EMPTY_STALE|ORPHAN) attention=1 ;;
    *) die "unknown worktree status: $class" ;;
  esac
done <"$TMP"

case "$MODE" in
  --porcelain)
    cat "$TMP"
    ;;
  --json)
    printf '{"worktrees":['
    first=1
    while IFS=$'\t' read -r class path branch dirty ahead behind last; do
      [[ "$first" == 1 ]] || printf ','
      first=0
      if [[ "$class" == ORPHAN ]]; then
        printf '{"status":"%s","path":"%s","branch":null,"dirty":null,"ahead":null,"behind":null,"last":"%s"}' \
          "$(printf '%s' "$class" | json_escape)" "$(printf '%s' "$path" | json_escape)" \
          "$(printf '%s' "$last" | json_escape)"
      else
        printf '{"status":"%s","path":"%s","branch":"%s","dirty":%s,"ahead":%s,"behind":%s,"last":"%s"}' \
          "$(printf '%s' "$class" | json_escape)" "$(printf '%s' "$path" | json_escape)" \
          "$(printf '%s' "$branch" | json_escape)" "$dirty" "$ahead" "$behind" \
          "$(printf '%s' "$last" | json_escape)"
      fi
    done <"$TMP"
    echo ']}'
    ;;
  table)
    printf '%-20s %-38s %-24s %5s %5s %5s %s\n' STATUS WORKTREE BRANCH DIRTY AHEAD BEHIND 'LAST COMMIT'
    printf '%-20s %-38s %-24s %5s %5s %5s %s\n' ------ -------- ------ ----- ----- ------ -------------
    while IFS=$'\t' read -r class path branch dirty ahead behind last; do
      printf '%-20s %-38s %-24s %5s %5s %5s %s\n' "$class" "$(basename "$path")" "$branch" "$dirty" "$ahead" "$behind" "$last"
    done <"$TMP"
    ;;
esac

exit "$attention"
