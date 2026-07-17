#!/usr/bin/env bash
# Generate an ignored, evidence-backed worktree and session reconciliation report.
# Usage: tools/agent/reconcile-report.sh [output|-]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
ROOT="$(git -C "$SCRIPT_DIR/../.." rev-parse --show-toplevel)"
MAIN_DIR="$(git -C "$ROOT" worktree list --porcelain | sed -n 's/^worktree //p' | sed -n '1p')"
[[ -n "$MAIN_DIR" ]] || { echo "[reconcile] could not determine main worktree" >&2; exit 1; }
MAIN_DIR="$(cd "$MAIN_DIR" && pwd -P)"
OUTPUT="${1:-$MAIN_DIR/.agent-runs/reconciliation-report.tsv}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/rustscale-reconcile.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
WT_STATUS="$TMP/worktrees.tsv"
REPORT="$TMP/report.tsv"
REGISTRY="$TMP/registry.tsv"

set +e
"$ROOT/tools/worktree-status.sh" --porcelain >"$WT_STATUS"
status=$?
set -e
(( status <= 1 )) || { echo "[reconcile] worktree status failed" >&2; exit "$status"; }

: >"$REGISTRY"
while IFS= read -r path; do
  [[ -n "$path" && -d "$path" ]] || continue
  path="$(cd "$path" && pwd -P)"
  printf '%s\t%s\n' "$path" "$(git -C "$path" branch --show-current)" >>"$REGISTRY"
done < <(git -C "$MAIN_DIR" worktree list --porcelain | sed -n 's/^worktree //p')

printf 'RECORD\tSTATUS\tID\tBRANCH\tRUN_STATE\tDIRTY\tAHEAD\tBEHIND\tEVIDENCE\n' >"$REPORT"
while IFS=$'\t' read -r class path branch dirty ahead behind _last evidence; do
  [[ "$class" != MAIN ]] || continue
  printf 'WORKTREE\t%s\t%s\t%s\t-\t%s\t%s\t%s\t%s\n' \
    "$class" "$(basename "$path")" "$branch" "$dirty" "$ahead" "$behind" "$evidence" >>"$REPORT"
done <"$WT_STATUS"

if [[ -d "$MAIN_DIR/.agent-runs" ]]; then
  while IFS= read -r -d '' run_dir; do
    namespace="$(basename "$(dirname "$run_dir")")"
    run_id="$(basename "$run_dir")"
    metadata="$run_dir/metadata.json"
    if [[ "$namespace" != codex || ! -f "$metadata" ]]; then
      printf 'SESSION\tORPHAN_SESSION\t%s/%s\t-\t-\t-\t-\t-\tno-standard-metadata\n' \
        "$namespace" "$run_id" >>"$REPORT"
      continue
    fi

    if ! fields="$(python3 - "$metadata" <<'PYEOF'
import json
import sys
try:
    with open(sys.argv[1], encoding="ascii") as handle:
        data = json.load(handle)
    values = [data.get(key, "") for key in ("branch", "worktree", "status")]
    if not all(isinstance(value, str) for value in values):
        raise ValueError("non-string reconciliation field")
    print("\t".join(value.replace("\t", " ").replace("\n", " ") for value in values))
except (OSError, ValueError, json.JSONDecodeError):
    sys.exit(1)
PYEOF
)"; then
      printf 'SESSION\tORPHAN_SESSION\tcodex/%s\t-\t-\t-\t-\t-\tinvalid-metadata\n' \
        "$run_id" >>"$REPORT"
      continue
    fi
    IFS=$'\t' read -r branch recorded_worktree run_state <<<"$fields"
    registered_branch="$(awk -F '\t' -v path="$recorded_worktree" '$1 == path { print $2; exit }' "$REGISTRY")"
    if [[ -n "$registered_branch" && "$registered_branch" == "$branch" ]]; then
      session_class="MATCHED_SESSION"
      session_evidence="metadata-path+branch-match"
    elif [[ -n "$registered_branch" ]]; then
      session_class="MISMATCHED_SESSION"
      session_evidence="metadata-path-registered-branch-mismatch"
    elif [[ -n "$branch" ]] && git -C "$MAIN_DIR" show-ref --verify --quiet "refs/heads/$branch"; then
      session_class="STALE_SESSION"
      session_evidence="branch-exists-worktree-unregistered"
    else
      session_class="ORPHAN_SESSION"
      session_evidence="branch-missing-worktree-unregistered"
    fi
    printf 'SESSION\t%s\tcodex/%s\t%s\t%s\t-\t-\t-\t%s\n' \
      "$session_class" "$run_id" "${branch:--}" "${run_state:--}" "$session_evidence" >>"$REPORT"
  done < <(find "$MAIN_DIR/.agent-runs" -mindepth 2 -maxdepth 2 -type d -print0 | sort -z)
fi

if [[ "$OUTPUT" == - ]]; then
  cat "$REPORT"
  exit 0
fi
mkdir -p "$(dirname "$OUTPUT")"
git -C "$MAIN_DIR" check-ignore --quiet "$OUTPUT" \
  || { echo "[reconcile] refusing to write a non-ignored report: $OUTPUT" >&2; exit 1; }
cp "$REPORT" "$OUTPUT"
echo "[reconcile] wrote $OUTPUT" >&2
