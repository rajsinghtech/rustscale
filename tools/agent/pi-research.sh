#!/usr/bin/env bash
# pi-research.sh -- fail-closed, read-only Pi research wrapper.
# Usage: tools/agent/pi-research.sh <title> <prompt> [deadline-seconds]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
ROOT="$(git -C "$SCRIPT_DIR/../.." rev-parse --show-toplevel)"
TITLE="${1:?usage: pi-research.sh <title> <prompt> [deadline-seconds]}"
PROMPT="${2:?usage: pi-research.sh <title> <prompt> [deadline-seconds]}"
DEADLINE="${3:-1200}"
PROVIDER="${PI_PROVIDER:-}"
MODEL="${PI_MODEL:-}"
BEFORE=""
HEAD_BEFORE=""
GUARD_ACTIVE=0

fail() {
  echo "[pi-research] $*" >&2
  echo "##STATUS:FAILED title=$TITLE" >&2
  exit 1
}

# shellcheck disable=SC2329 # Invoked indirectly by the EXIT trap below.
guard_exit() {
  local status="$?" after after_head
  if [[ "$GUARD_ACTIVE" == 1 ]]; then
    after="$(git -C "$ROOT" status --porcelain=v2 --untracked-files=all)"
    after_head="$(git -C "$ROOT" rev-parse HEAD)"
    if [[ "$after" != "$BEFORE" || "$after_head" != "$HEAD_BEFORE" ]]; then
      echo "[pi-research] repository changed during research; rejecting result" >&2
      echo "##STATUS:FAILED title=$TITLE reason=repository_modified" >&2
      status=1
    fi
  fi
  trap - EXIT
  exit "$status"
}

[[ "$TITLE" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] \
  || fail "invalid title (use letters, digits, '.', '_' or '-')"
[[ "$DEADLINE" =~ ^[1-9][0-9]*$ ]] || fail "deadline must be a positive integer"
command -v pi >/dev/null 2>&1 || fail "pi is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required for deadline enforcement"

BEFORE="$(git -C "$ROOT" status --porcelain=v2 --untracked-files=all)"
HEAD_BEFORE="$(git -C "$ROOT" rev-parse HEAD)"
GUARD_ACTIVE=1
trap guard_exit EXIT
[[ -z "$BEFORE" ]] || fail "repository is already dirty; refusing research run"

run_command=(
  pi
  --print
  --no-session
  --no-extensions
  --no-skills
  --no-prompt-templates
  --tools "read,grep,find,ls"
  --name "$TITLE"
)
[[ -z "$PROVIDER" ]] || run_command+=(--provider "$PROVIDER")
[[ -z "$MODEL" ]] || run_command+=(--model "$MODEL")
run_command+=(
  $'This is a read-only research task. Do not modify files, run shell commands, commit changes, or start other agents.\n\n'"$PROMPT"
)

set +e
python3 "$SCRIPT_DIR/run-with-deadline.py" "$DEADLINE" -- "${run_command[@]}"
status=$?
set -e

if (( status == 0 )); then
  echo "##STATUS:DONE title=$TITLE" >&2
  exit 0
fi
if (( status == 124 )); then
  echo "[pi-research] deadline reached; research terminated" >&2
  echo "##STATUS:TIMED_OUT title=$TITLE deadline=$DEADLINE" >&2
  exit 124
fi
echo "[pi-research] Pi failed with exit $status" >&2
echo "##STATUS:FAILED title=$TITLE exit=$status" >&2
exit "$status"
