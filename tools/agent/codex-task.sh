#!/usr/bin/env bash
# codex-task.sh -- fail-closed implementation-agent worktree wrapper.
# Usage:
#   tools/agent/codex-task.sh <title> <prompt> [deadline-seconds]
#   tools/agent/codex-task.sh --continue <title> <prompt> [deadline-seconds]
if [[ "${RUSTSCALE_CODEX_TASK_SIGINT_RESET:-}" != 1 ]]; then
  command -v python3 >/dev/null 2>&1 || {
    echo "[codex-task] python3 is required for SIGINT-safe execution" >&2
    exit 1
  }
  export RUSTSCALE_CODEX_TASK_SIGINT_RESET=1
  exec python3 - "$0" "$@" <<'PYEOF'
import os
import signal
import sys

signal.signal(signal.SIGINT, signal.SIG_DFL)
os.execve(sys.argv[1], [sys.argv[1], *sys.argv[2:]], os.environ)
PYEOF
fi
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
START_DIR="$(git -C "$SCRIPT_DIR/../.." rev-parse --show-toplevel)"
MODE=new
if [[ "${1:-}" == "--continue" ]]; then
  MODE="continue"
  shift
fi
TITLE="${1:?usage: codex-task.sh [--continue] <title> <prompt> [deadline-seconds]}"
PROMPT="${2:?usage: codex-task.sh [--continue] <title> <prompt> [deadline-seconds]}"
DEADLINE="${3:-2400}"
MODEL="${CODEX_MODEL:-gpt-5.6-terra}"
WT_DIR=""
WT_BRANCH="agent/$TITLE"
RUN_DIR=""
META=""
LOG=""
FINAL=""
BASE_SHA=""
SESSION_ID=""
STARTED_AT=""
HELPER_PID=""
RUN_ACTIVE=0
# shellcheck disable=SC2034 # Read from the EXIT trap string.
NEXT_EMITTED=0

next_action() {
  # shellcheck disable=SC2034 # Read from the EXIT trap string.
  NEXT_EMITTED=1
  if [[ -n "$WT_DIR" && -d "$WT_DIR" ]]; then
    printf 'NEXT: tools/agent/agent-review.sh %s\n' "$TITLE" >&2
  else
    printf 'NEXT: reconcile master with origin/master, then rerun tools/agent/codex-task.sh %s ...\n' "$TITLE" >&2
  fi
}

trap 'if (( NEXT_EMITTED == 0 )); then next_action; fi' EXIT

fail() {
  echo "[codex-task] $*" >&2
  echo "##STATUS:FAILED title=$TITLE" >&2
  next_action
  exit 1
}

# shellcheck disable=SC2329 # Invoked by INT/TERM/HUP traps.
handle_signal() {
  local signal_name="$1" signal_status="$2" ended_at attempt_session_id terminal_status
  if [[ -n "$HELPER_PID" ]]; then
    kill -"$signal_name" "$HELPER_PID" 2>/dev/null || true
    set +e
    wait "$HELPER_PID"
    set -e
  fi
  if (( RUN_ACTIVE == 1 )); then
    attempt_session_id=""
    [[ -f "$LOG" ]] && attempt_session_id="$(extract_session_id || true)"
    terminal_status="INTERRUPTED"
    if [[ "$MODE" == continue ]]; then
      if [[ -n "$attempt_session_id" && "$attempt_session_id" != "$SESSION_ID" ]]; then
        echo "[codex-task] interrupted resumed run emitted a mismatched session ID; treating run as failed" >&2
        terminal_status="FAILED"
      fi
    else
      SESSION_ID="$attempt_session_id"
    fi
    ended_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    write_metadata "$ended_at" "$signal_status" "$terminal_status"
    echo "##STATUS:$terminal_status path=$WT_DIR branch=$WT_BRANCH session=$SESSION_ID exit=$signal_status" >&2
  else
    echo "##STATUS:FAILED title=$TITLE signal=$signal_name" >&2
  fi
  next_action
  trap - INT TERM HUP
  exit "$signal_status"
}

[[ "$TITLE" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] \
  || fail "invalid title (use letters, digits, '.', '_' or '-')"
[[ "$DEADLINE" =~ ^[1-9][0-9]*$ ]] || fail "deadline must be a positive integer"
command -v python3 >/dev/null 2>&1 || fail "python3 is required for portable deadline enforcement"

# The first registered worktree is Git's primary checkout. Do not treat a
# secondary checkout of master as the main tree.
MAIN_DIR="$(git -C "$START_DIR" worktree list --porcelain | sed -n 's/^worktree //p' | sed -n '1p')"
[[ -n "$MAIN_DIR" ]] || fail "could not determine the main worktree"
MAIN_DIR="$(cd "$MAIN_DIR" && pwd -P)"
WT_DIR="$MAIN_DIR/.worktrees/$TITLE"
RUN_DIR="$MAIN_DIR/.agent-runs/codex/$TITLE"
META="$RUN_DIR/metadata.json"
LOG="$RUN_DIR/run.jsonl"
FINAL="$RUN_DIR/final-message.txt"

write_metadata() {
  local ended_at="$1" exit_code="$2" status="$3"
  mkdir -p "$RUN_DIR"
  python3 - "$META" "$TITLE" "$BASE_SHA" "$WT_BRANCH" "$WT_DIR" "$MODEL" "$SESSION_ID" \
    "$STARTED_AT" "$ended_at" "$exit_code" "$status" "$LOG" "$FINAL" <<'PYEOF'
import json
import os
import sys

keys = ("title", "base_sha", "branch", "worktree", "model", "session_id", "started_at",
        "ended_at", "exit_code", "status", "jsonl_log", "final_message")
data = dict(zip(keys, sys.argv[2:]))
tmp = sys.argv[1] + ".tmp"
with open(tmp, "w", encoding="ascii") as handle:
    json.dump(data, handle, sort_keys=True, indent=2)
    handle.write("\n")
os.replace(tmp, sys.argv[1])
PYEOF
}

read_metadata() {
  local field="$1"
  python3 - "$META" "$field" <<'PYEOF'
import json
import sys
with open(sys.argv[1], encoding="ascii") as handle:
    value = json.load(handle).get(sys.argv[2], "")
if value is not None:
    print(value)
PYEOF
}

extract_session_id() {
  python3 - "$LOG" <<'PYEOF'
import json
import sys

def find(value):
    if isinstance(value, dict):
        for key in ("thread_id", "session_id"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate:
                return candidate
        for candidate in value.values():
            found = find(candidate)
            if found:
                return found
    elif isinstance(value, list):
        for candidate in value:
            found = find(candidate)
            if found:
                return found
    return ""

for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    try:
        session_id = find(json.loads(line))
    except json.JSONDecodeError:
        continue
    if session_id:
        print(session_id)
        break
PYEOF
}

require_clean_main() {
  [[ "$(git -C "$MAIN_DIR" branch --show-current)" == master ]] \
    || fail "main worktree is not on master: $MAIN_DIR"
  git -C "$MAIN_DIR" diff --quiet || fail "main worktree has unstaged changes"
  git -C "$MAIN_DIR" diff --cached --quiet || fail "main worktree has staged changes"
  [[ -z "$(git -C "$MAIN_DIR" ls-files --others --exclude-standard)" ]] \
    || fail "main worktree has untracked files"
}

if [[ "$MODE" == new ]]; then
  require_clean_main
  git -C "$MAIN_DIR" fetch origin master || fail "could not fetch origin master"
  git -C "$MAIN_DIR" rev-parse --verify --quiet origin/master >/dev/null \
    || fail "origin/master is unavailable after fetch"
  [[ "$(git -C "$MAIN_DIR" rev-parse master)" == "$(git -C "$MAIN_DIR" rev-parse origin/master)" ]] \
    || fail "local master and origin/master differ; refusing to create a worktree"
  BASE_SHA="$(git -C "$MAIN_DIR" rev-parse master)"
  git -C "$MAIN_DIR" show-ref --verify --quiet "refs/heads/$WT_BRANCH" \
    && fail "branch already exists: $WT_BRANCH"
  [[ ! -e "$WT_DIR" ]] || fail "worktree path already exists: $WT_DIR"
  [[ ! -e "$RUN_DIR" ]] || fail "run metadata already exists: $RUN_DIR (use --continue or choose a new title)"
  echo "[codex-task] creating $WT_DIR on $WT_BRANCH" >&2
  git -C "$MAIN_DIR" worktree add "$WT_DIR" -b "$WT_BRANCH" master
else
  [[ -f "$META" ]] || fail "no saved run metadata for title: $TITLE"
  WT_DIR="$(read_metadata worktree)"
  WT_BRANCH="$(read_metadata branch)"
  BASE_SHA="$(read_metadata base_sha)"
  MODEL="$(read_metadata model)"
  SESSION_ID="$(read_metadata session_id)"
  [[ -n "$MODEL" ]] || fail "saved run has no model ID"
  [[ -n "$WT_DIR" && -d "$WT_DIR" ]] || fail "saved worktree is unavailable: ${WT_DIR:-unknown}"
  [[ "$(git -C "$WT_DIR" branch --show-current)" == "$WT_BRANCH" ]] \
    || fail "saved worktree branch does not match metadata"
  [[ -n "$SESSION_ID" ]] || fail "saved run has no Codex session ID; cannot resume exactly"
fi

mkdir -p "$RUN_DIR"
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
attempt="$(date -u +%Y%m%dT%H%M%SZ)-$$"
LOG="$RUN_DIR/$attempt.jsonl"
FINAL="$RUN_DIR/final-$attempt.txt"
write_metadata "" "" "RUNNING"
RUN_ACTIVE=1
trap 'handle_signal INT 130' INT
trap 'handle_signal TERM 143' TERM
trap 'handle_signal HUP 129' HUP
AGENT_PROMPT=$'Do not commit changes and do not spawn agents.\n\n'"$PROMPT"

if [[ "$MODE" == new ]]; then
  RUN_COMMAND=(codex -a never exec --json -o "$FINAL" -m "$MODEL" -s workspace-write -C "$WT_DIR" "$AGENT_PROMPT")
else
  RUN_COMMAND=(codex -a never exec -m "$MODEL" -s workspace-write -C "$WT_DIR" resume --json -o "$FINAL" "$SESSION_ID" "$AGENT_PROMPT")
fi

python3 "$SCRIPT_DIR/run-with-deadline.py" "$DEADLINE" -- "${RUN_COMMAND[@]}" >"$LOG" 2>&1 &
HELPER_PID=$!
set +e
wait "$HELPER_PID"
status=$?
set -e
RUN_ACTIVE=0
HELPER_PID=""
ATTEMPT_SESSION_ID="$(extract_session_id || true)"
if [[ "$MODE" == continue ]]; then
  if [[ "$ATTEMPT_SESSION_ID" != "$SESSION_ID" ]]; then
    echo "[codex-task] resumed Codex session ID did not match saved session; treating run as failed" >&2
    status=1
  fi
else
  SESSION_ID="$ATTEMPT_SESSION_ID"
fi
if (( status == 0 )) && [[ -z "$SESSION_ID" ]]; then
  echo "[codex-task] Codex completed without a session ID; treating run as failed" >&2
  status=1
fi
ENDED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
if (( status == 0 )); then
  write_metadata "$ENDED_AT" "$status" "DONE"
  echo "##STATUS:DONE path=$WT_DIR branch=$WT_BRANCH session=$SESSION_ID" >&2
  if [[ -s "$FINAL" ]]; then
    tail -n 80 "$FINAL"
  fi
  next_action
  exit 0
fi

if (( status == 124 )); then
  run_status="TIMED_OUT"
else
  run_status="FAILED"
fi
write_metadata "$ENDED_AT" "$status" "$run_status"
echo "[codex-task] Codex $run_status (exit $status); worktree preserved" >&2
echo "##STATUS:$run_status path=$WT_DIR branch=$WT_BRANCH session=$SESSION_ID exit=$status" >&2
tail -n 80 "$LOG" >&2 || true
next_action
exit "$status"
