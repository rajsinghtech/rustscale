#!/usr/bin/env bash
# opencode-task.sh — unattended opencode orchestration via the server HTTP API.
#
# `opencode run` is synchronous with no timeout: when the model stalls the call
# blocks forever and the caller leaks a zombie process. This harness uses the
# persistent server instead: async prompt admission (204), allow-all permission
# ruleset at session create (replaces --auto), a hard watchdog deadline with
# abort, and result harvesting.
#
# Usage:
#   tools/agent/opencode-task.sh [--worktree] [--model <id>] "<title>" "<prompt>" [deadline]
#   tools/agent/opencode-task.sh --continue <sessionID> "<prompt>" [deadline]
#
# Flags (must appear before positional args):
#   --worktree       create an isolated git worktree (.worktrees/<title>) on a
#                    branch agent/<title> off master; the agent operates in that
#                    worktree instead of the repo root. On success prints the
#                    worktree path and branch name for subsequent review/merge.
#   --model <id>     override OPENCODE_MODEL for this invocation (see model
#                    tiering policy in docs/toolsmith.md).
#
# Model tiering:
#   ai/deepseek/deepseek-v4-flash     — research, review, docs (cheap/model)
#   ai/vercel-ent/zai/glm-5.2         — complex coding (default)
#   Override via OPENCODE_MODEL env var or --model flag.
#
# Env: OPENCODE_URL   (default http://127.0.0.1:4096)
#      OPENCODE_MODEL (default ai/vercel-ent/zai/glm-5.2), OPENCODE_PROVIDER (ai)
#
# Exit: 0 completed; 3 watchdog abort (prints sessionID for --continue); 1 error.
set -euo pipefail

URL="${OPENCODE_URL:-http://127.0.0.1:4096}"
PROVIDER="${OPENCODE_PROVIDER:-ai}"
MODEL="${OPENCODE_MODEL:-ai/vercel-ent/zai/glm-5.2}"
DIR="$(cd "$(dirname "$0")/../.." && pwd)"

CONTINUE=""
WORKTREE=""

# Parse leading flags before positional args.
while [[ "${1:-}" == -* ]]; do
  case "$1" in
    --continue)  CONTINUE="${2:?--continue requires a session ID}"; shift 2 ;;
    --worktree)  WORKTREE=1; shift ;;
    --model)     MODEL="${2:?--model requires a model ID}"; shift 2 ;;
    --model=*)   MODEL="${1#*=}"; shift ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

if [[ -n "$CONTINUE" ]]; then
  TITLE="$CONTINUE"
  PROMPT="${1:?prompt text}"
  DEADLINE="${2:-2400}"
else
  TITLE="${1:?title}"
  PROMPT="${2:?prompt text}"
  DEADLINE="${3:-2400}"   # 40 min default
fi

# 0a. Optional worktree setup.
if [[ -n "$WORKTREE" ]]; then
  # Ensure .gitignore covers .worktrees/.
  if ! grep -qxF '.worktrees/' "$DIR/.gitignore" 2>/dev/null; then
    echo '.worktrees/' >> "$DIR/.gitignore"
  fi
  WT_DIR=".worktrees/$TITLE"
  WT_BRANCH="agent/$TITLE"
  echo "[harness] creating worktree $WT_DIR on $WT_BRANCH" >&2
  git worktree add "$WT_DIR" -b "$WT_BRANCH" master
  DIR="$(cd "$DIR/$WT_DIR" && pwd)"
fi

# 0. Ensure server is up. (Concurrent harness launches may both attempt to start
#    `opencode serve`; only one binds the port — the loser exits and the shared
#    server serves both. We verify health after the wait regardless.)
if ! curl -sf --max-time 3 "$URL/api/health" >/dev/null 2>&1; then
  echo "[harness] starting opencode server at $URL" >&2
  nohup opencode serve --hostname 127.0.0.1 --port "${URL##*:}" >/tmp/opencode-serve.log 2>&1 &
  # `|| true` so a loop that exhausts without break (server still down) doesn't
  # trip `set -e` before the explicit health check below can print a clear error.
  for _ in $(seq 1 20); do sleep 1; curl -sf --max-time 2 "$URL/api/health" >/dev/null 2>&1 && break; done || true
  curl -sf --max-time 3 "$URL/api/health" >/dev/null 2>&1 \
    || { echo "[harness] opencode server did not come up at $URL (see /tmp/opencode-serve.log)" >&2; exit 1; }
fi

# 1. Create session (allow-all permissions = unattended) or reuse.
if [[ -n "$CONTINUE" ]]; then
  SID="$CONTINUE"
  echo "[harness] continuing session $SID" >&2
else
  SID=$(curl -sfS -X POST "$URL/session?directory=$DIR" -H 'Content-Type: application/json' \
    -d "$(jq -n --arg t "$TITLE" \
      '{title:$t, permission:[{permission:"*",pattern:"*",action:"allow"}]}')" | jq -r .id)
  [[ "$SID" == ses_* ]] || { echo "[harness] session create failed" >&2; exit 1; }
  echo "[harness] session $SID ($TITLE)" >&2
fi

# 2. Async prompt admission — returns 204 immediately.
curl -sfS --max-time 10 -o /dev/null -X POST "$URL/session/$SID/prompt_async?directory=$DIR" \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --arg pid "$PROVIDER" --arg mid "$MODEL" --arg t "$PROMPT" \
    '{model:{providerID:$pid,modelID:$mid},parts:[{type:"text",text:$t}]}')" \
  || { echo "[harness] prompt admission failed for session $SID" >&2; exit 1; }
echo "[harness] prompt admitted; watchdog ${DEADLINE}s model=$MODEL" >&2

msg_count() {
  curl -s --max-time 5 "$URL/session/$SID/message?directory=$DIR" | jq 'length' 2>/dev/null || echo 0
}
is_busy() {
  # /session/status returns {sessionID: {...}} only for busy/queued sessions.
  # --max-time is critical: without it a hung server stalls this poll forever,
  # which would defeat the watchdog deadline below.
  # directory param is required: sessions created in a worktree don't appear
  # in the default-directory status map, which made the watchdog think a busy
  # worktree session was idle after 30s.
  curl -s --max-time 5 "$URL/session/status?directory=$DIR" | jq -e --arg s "$SID" 'has($s)' >/dev/null 2>&1 && echo 1 || echo 0
}

# 3. Watchdog loop. glm-5.2 occasionally emits an empty first turn (reasoning
#    part only, no text/tool calls) and goes idle ~30s in; when that happens we
#    re-prompt once with a short "proceed" nudge instead of failing the run.
NUDGED=0
START=$(date +%s); LAST=0; IDLE=0
while :; do
  sleep 15
  ELAPSED=$(( $(date +%s) - START ))
  BUSY=$(is_busy); COUNT=$(msg_count)
  if [[ "$COUNT" != "$LAST" ]]; then
    echo "[harness] t=${ELAPSED}s messages=$COUNT busy=$BUSY" >&2
    LAST="$COUNT"; IDLE=0
  fi
  if [[ "$BUSY" == "0" ]]; then
    IDLE=$((IDLE+1))
    if [[ $IDLE -ge 2 ]]; then
      # Idle: check whether we actually got assistant text before accepting.
      FINAL=$(curl -s --max-time 10 "$URL/session/$SID/message?directory=$DIR" | jq -r '
        [.[] | select(.info.role=="assistant")] | last
        | if . == null then "" else [.parts[]? | select(.type=="text") | .text] | join("\n") end')
      if [[ -z "$FINAL" && $NUDGED -eq 0 ]]; then
        echo "[harness] empty first turn — re-prompting once" >&2
        NUDGED=1; IDLE=0
        curl -sfS --max-time 10 -o /dev/null -X POST "$URL/session/$SID/prompt_async?directory=$DIR" \
          -H 'Content-Type: application/json' \
          -d "$(jq -n --arg pid "$PROVIDER" --arg mid "$MODEL" \
            '{model:{providerID:$pid,modelID:$mid},parts:[{type:"text",text:"Please proceed with the task described above."}]}')" \
          || { echo "[harness] re-prompt failed" >&2; break; }
        continue
      fi
      break
    fi
  else
    IDLE=0
  fi
  if (( ELAPSED > DEADLINE )); then
    echo "[harness] DEADLINE ${DEADLINE}s exceeded — aborting session" >&2
    curl -sS --max-time 5 -o /dev/null -X POST "$URL/session/$SID/abort?directory=$DIR" || true
    echo "$SID"
    exit 3
  fi
done

# 4. Harvest final assistant text.
echo "[harness] done in $(( $(date +%s) - START ))s; session $SID" >&2
curl -s --max-time 10 "$URL/session/$SID/message?directory=$DIR" | jq -r '
  [.[] | select(.info.role=="assistant")] | last
  | if . == null then "(no assistant message produced — session may have aborted)"
    else [.parts[]? | select(.type=="text") | .text] | join("\n") end'

# 5. On success with --worktree, print merge instructions.
if [[ -n "$WORKTREE" ]]; then
  echo "[harness] worktree: $WT_DIR  branch: $WT_BRANCH" >&2
  echo "[harness] run tools/agent/worktree-merge.sh \"$TITLE\" to verify and merge" >&2
fi
