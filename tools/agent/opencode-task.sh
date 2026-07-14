#!/usr/bin/env bash
# opencode-task.sh — unattended, research-only OpenCode server wrapper.
# Usage:
#   tools/agent/opencode-task.sh [--model deepseek/deepseek-v4-flash] <title> <prompt> [deadline]
set -euo pipefail

URL="${OPENCODE_URL:-http://127.0.0.1:4096}"
PROVIDER="${OPENCODE_PROVIDER:-ai}"
MODEL="${OPENCODE_MODEL:-deepseek/deepseek-v4-flash}"
DIR="$(cd "$(dirname "$0")/../.." && pwd -P)"
SID=""

fail() {
  echo "[opencode-task] $*" >&2
  echo "##STATUS:FAILED${SID:+ session=$SID}" >&2
  exit 1
}

RESEARCH_BEFORE=""
RESEARCH_HEAD_BEFORE=""
RESEARCH_GUARD_ACTIVE=0
research_guard_exit() {
  local status="$?" after after_head
  if [[ "$RESEARCH_GUARD_ACTIVE" == 1 ]]; then
    after="$(git -C "$DIR" status --porcelain=v2 --untracked-files=all)"
    after_head="$(git -C "$DIR" rev-parse HEAD)"
    if [[ "$after" != "$RESEARCH_BEFORE" || "$after_head" != "$RESEARCH_HEAD_BEFORE" ]]; then
      echo "[opencode-task] repository changed during research; rejecting result" >&2
      echo "##STATUS:FAILED${SID:+ session=$SID} reason=repository_modified" >&2
      status=1
    fi
  fi
  trap - EXIT
  exit "$status"
}

while [[ "${1:-}" == -* ]]; do
  case "$1" in
    --continue) echo "[opencode-task] --continue is not permitted: research sessions must be newly read-only" >&2; exit 2 ;;
    --model) MODEL="${2:?--model requires a model ID}"; shift 2 ;;
    --model=*) MODEL="${1#*=}"; shift ;;
    --worktree) echo "[opencode-task] --worktree is not supported: OpenCode is research-only" >&2; exit 2 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

TITLE="${1:?title}"
PROMPT="${2:?prompt text}"
DEADLINE="${3:-2400}"
[[ "$DEADLINE" =~ ^[1-9][0-9]*$ ]] || fail "deadline must be a positive integer"

if [[ "$MODEL" != "deepseek/deepseek-v4-flash" && "${OPENCODE_ALLOW_NON_DEEPSEEK_DIAGNOSTICS:-}" != "1" ]]; then
  fail "refusing model '$MODEL'; only deepseek/deepseek-v4-flash is permitted (set OPENCODE_ALLOW_NON_DEEPSEEK_DIAGNOSTICS=1 for diagnostics)"
fi

# A research session must leave the repository byte-for-byte unchanged. Compare
# porcelain-v2 snapshots at every exit, including watchdog and API failures.
RESEARCH_BEFORE="$(git -C "$DIR" status --porcelain=v2 --untracked-files=all)"
RESEARCH_HEAD_BEFORE="$(git -C "$DIR" rev-parse HEAD)"
RESEARCH_GUARD_ACTIVE=1
trap research_guard_exit EXIT
[[ -z "$RESEARCH_BEFORE" ]] || fail "repository is already dirty; refusing research run"

if ! curl -fsS --max-time 3 "$URL/api/health" >/dev/null; then
  echo "[opencode-task] starting opencode server at $URL" >&2
  nohup opencode serve --hostname 127.0.0.1 --port "${URL##*:}" >/tmp/opencode-serve.log 2>&1 &
  for _ in $(seq 1 20); do
    sleep 1
    curl -fsS --max-time 2 "$URL/api/health" >/dev/null && break
  done
  curl -fsS --max-time 3 "$URL/api/health" >/dev/null \
    || fail "server did not become healthy at $URL (see /tmp/opencode-serve.log)"
fi

SID="$(curl -fsS --max-time 10 -X POST "$URL/session?directory=$DIR" -H 'Content-Type: application/json' \
  -d "$(jq -n --arg t "$TITLE" '{title:$t, permission:[{permission:"bash",pattern:"*",action:"deny"},{permission:"write",pattern:"*",action:"deny"},{permission:"edit",pattern:"*",action:"deny"},{permission:"patch",pattern:"*",action:"deny"}]}')" \
  | jq -er '.id')" || fail "session creation failed"
[[ "$SID" == ses_* ]] || fail "session creation returned an invalid ID"
echo "[opencode-task] session $SID ($TITLE)" >&2

RESEARCH_GUARD=$'This is a research, review, documentation, or toolsmith task. Do not implement product code, create worktrees, commit changes, or spawn agents.\n\n'
curl -fsS --max-time 10 -o /dev/null -X POST "$URL/session/$SID/prompt_async?directory=$DIR" \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --arg pid "$PROVIDER" --arg mid "$MODEL" --arg t "$RESEARCH_GUARD$PROMPT" \
    '{model:{providerID:$pid,modelID:$mid},parts:[{type:"text",text:$t}]}')" \
  || fail "prompt admission failed"

messages() {
  curl -fsS --max-time 10 "$URL/session/$SID/message?directory=$DIR" \
    | jq -e 'if type == "array" then . else error("expected message array") end'
}

status_busy() {
  local status
  status="$(curl -fsS --max-time 5 "$URL/session/status?directory=$DIR")" || return 1
  jq -e 'type == "object"' >/dev/null <<<"$status" || return 1
  if jq -e --arg sid "$SID" 'has($sid)' >/dev/null <<<"$status"; then
    printf '1\n'
  else
    printf '0\n'
  fi
}

wait_for_idle_after_abort() {
  local grace="${OPENCODE_ABORT_GRACE:-30}" now deadline busy
  [[ "$grace" =~ ^[1-9][0-9]*$ ]] || return 1
  deadline=$(( $(date +%s) + grace ))
  while :; do
    busy="$(status_busy)" || return 1
    [[ "$busy" == 0 ]] && return 0
    now="$(date +%s)"
    (( now < deadline )) || return 1
    sleep 1
  done
}

START="$(date +%s)"
SEEN_BUSY=0
# Cold-start grace: right after prompt_async the session may not yet be in the
# busy set, and its assistant row can exist with empty parts. Do not accept an
# empty/stuck result as final until we have observed the session busy at least
# once, or this many seconds have elapsed.
WARMUP="${OPENCODE_WARMUP:-45}"
while :; do
  now="$(date +%s)"
  elapsed=$((now - START))
  if (( elapsed >= DEADLINE )); then
    curl -fsS --max-time 5 -o /dev/null -X POST "$URL/session/$SID/abort?directory=$DIR" \
      || fail "deadline reached but session abort failed"
    wait_for_idle_after_abort || fail "deadline reached but session did not become idle after abort"
    echo "##STATUS:ABORTED session=$SID watchdog=$DEADLINE" >&2
    echo "$SID"
    exit 3
  fi

  if ! busy="$(status_busy)"; then
    fail "session status is unknown (server error or timeout)"
  fi
  if [[ "$busy" == 1 ]]; then
    SEEN_BUSY=1
  else
    if ! output="$(messages | jq -r '
      [.[] | select(.info.role == "assistant")] | last |
      if . == null then "STUCK:empty_session"
      else ([.parts[]? | select(.type == "text") | .text] | join("")) end')"; then
      fail "message retrieval is unknown (server error or timeout)"
    fi
    if [[ -z "$output" || "$output" == STUCK:* ]]; then
      # Empty result. If we have not warmed up yet, this is the cold-start
      # race, not a real finish — keep polling.
      if [[ "$SEEN_BUSY" == 1 || "$elapsed" -ge "$WARMUP" ]]; then
        echo "##STATUS:STUCK session=$SID duration=${elapsed}s detail=${output:-STUCK:empty_output}" >&2
        echo "${output:-STUCK:empty_output}"
        exit 4
      fi
    else
      echo "##STATUS:DONE session=$SID duration=${elapsed}s" >&2
      echo "$output"
      exit 0
    fi
  fi
  sleep 5
done
