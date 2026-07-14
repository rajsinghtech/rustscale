#!/usr/bin/env bash
# Hermetic regression coverage for the agent harnesses.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd -P)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/rustscale-harness.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
assert_contains() { [[ "$1" == *"$2"* ]] || fail "missing '$2'"; }
expect_failure() {
  local output
  if output=$("$@" 2>&1); then
    fail "command unexpectedly succeeded: $*"
  fi
  printf '%s' "$output"
}
expect_success() {
  local output
  if ! output=$("$@" 2>&1); then
    fail "command unexpectedly failed: $*"
  fi
  printf '%s' "$output"
}

# shellcheck disable=SC2016 # The temporary check script must retain its variables.
new_repo() {
  local name="$1"
  REPO="$TMP/$name"
  git init -q "$REPO"
  REPO="$(cd "$REPO" && pwd -P)"
  git -C "$REPO" checkout -q -b master
  git -C "$REPO" config user.name harness-test
  git -C "$REPO" config user.email harness@example.invalid
  mkdir -p "$REPO/tools/agent"
  cp "$ROOT/tools/agent/codex-task.sh" "$ROOT/tools/agent/opencode-task.sh" \
    "$ROOT/tools/agent/worktree-merge.sh" "$REPO/tools/agent/"
  cp "$ROOT/tools/worktree-status.sh" "$REPO/tools/"
  chmod +x "$REPO/tools/agent/"*.sh "$REPO/tools/worktree-status.sh"
  printf '%s\n' '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'if [[ "${FAIL_MAIN_GATE:-0}" == 1 && "$(git branch --show-current)" == master ]]; then exit 1; fi' \
    'exit 0' >"$REPO/tools/check.sh"
  chmod +x "$REPO/tools/check.sh"
  printf '%s\n' '.worktrees/' 'bin/' 'args' 'expected' 'curl.log' >"$REPO/.gitignore"
  printf 'base\n' >"$REPO/shared.txt"
  git -C "$REPO" add .
  git -C "$REPO" commit -qm initial
}

# shellcheck disable=SC2016 # The temporary curl stub must retain its variables.
test_model_rejection() {
  new_repo model-rejection
  mkdir "$REPO/bin"
  printf '%s\n' '#!/usr/bin/env bash' 'echo curl-called >>"$CURL_LOG"; exit 1' >"$REPO/bin/curl"
  chmod +x "$REPO/bin/curl"
  : >"$REPO/curl.log"
  output=$(expect_failure env PATH="$REPO/bin:$PATH" CURL_LOG="$REPO/curl.log" OPENCODE_MODEL=not-deepseek \
    "$REPO/tools/agent/opencode-task.sh" research prompt)
  assert_contains "$output" 'refusing model'
  [[ ! -s "$REPO/curl.log" ]] || fail 'rejected model contacted the server'
}

# shellcheck disable=SC2016 # The temporary curl stub must retain its variables.
test_opencode_default_model() {
  new_repo opencode-default
  mkdir "$REPO/bin"
  printf '%s\n' '#!/usr/bin/env bash' \
    'set -eu' \
    'args="$*"' \
    'printf "%s\\n" "$args" >>"$CURL_LOG"' \
    'case "$args" in' \
    '  *api/health*) exit 0 ;;' \
    '  *"/session?"*) printf "%s\\n" "{\"id\":\"ses_test\"}" ;;' \
    '  *prompt_async*) exit 0 ;;' \
    '  *session/status*) printf "%s\\n" "{}" ;;' \
    '  *"/message?"*) printf "%s\\n" "[{\"info\":{\"role\":\"assistant\"},\"parts\":[{\"type\":\"text\",\"text\":\"research complete\"}]}]" ;;' \
    '  *) exit 1 ;;' \
    'esac' >"$REPO/bin/curl"
  chmod +x "$REPO/bin/curl"
  : >"$REPO/curl.log"
  output=$(env PATH="$REPO/bin:$PATH" CURL_LOG="$REPO/curl.log" "$REPO/tools/agent/opencode-task.sh" research prompt)
  [[ "$output" == 'research complete' ]] || fail 'OpenCode default path did not return its result'
  assert_contains "$(cat "$REPO/curl.log")" 'deepseek/deepseek-v4-flash'
}

# shellcheck disable=SC2016 # The temporary Codex stub must retain its variables.
test_codex_arguments_and_dirty_main() {
  new_repo codex
  mkdir "$REPO/bin"
  printf '%s\n' '#!/usr/bin/env bash' 'printf "%s\\n" "$@" >"$CODEX_ARGS"' >"$REPO/bin/codex"
  chmod +x "$REPO/bin/codex"
  PATH="$REPO/bin:$PATH" CODEX_ARGS="$REPO/args" "$REPO/tools/agent/codex-task.sh" exact 'implement this'
  printf '%s\n' -a never exec -m gpt-5.6-terra -s workspace-write -C "$REPO/.worktrees/exact" >"$REPO/expected"
  diff -u "$REPO/expected" <(sed -n '1,9p' "$REPO/args") || fail 'Codex argument order changed'
  assert_contains "$(sed -n '10,$p' "$REPO/args")" 'Do not commit changes and do not spawn agents.'
  assert_contains "$(sed -n '10,$p' "$REPO/args")" 'implement this'

  printf 'dirty\n' >>"$REPO/shared.txt"
  output=$(expect_failure env PATH="$REPO/bin:$PATH" CODEX_ARGS="$REPO/args" \
    "$REPO/tools/agent/codex-task.sh" dirty-main prompt)
  assert_contains "$output" 'main worktree has unstaged changes'
  git -C "$REPO" show-ref --verify --quiet refs/heads/agent/dirty-main \
    && fail 'dirty main created a branch'
  [[ ! -e "$REPO/.worktrees/dirty-main" ]] || fail 'dirty main created a worktree'
}

test_merged_clean_status_is_not_attention() {
  new_repo merged-clean
  git -C "$REPO" worktree add -q -b agent/merged "$REPO/.worktrees/merged" master
  printf 'merged\n' >"$REPO/.worktrees/merged/merged.txt"
  git -C "$REPO/.worktrees/merged" add merged.txt
  git -C "$REPO/.worktrees/merged" commit -qm merged-change
  git -C "$REPO" merge -q --no-ff agent/merged -m 'Merge agent/merged'

  output=$(expect_success "$REPO/tools/worktree-status.sh" --porcelain)
  assert_contains "$output" $'MERGED_CLEAN\t'
}

test_attention_statuses_fail() {
  new_repo status-dirty
  git -C "$REPO" worktree add -q -b agent/dirty "$REPO/.worktrees/dirty" master
  printf 'dirty\n' >>"$REPO/.worktrees/dirty/shared.txt"
  output=$(expect_failure "$REPO/tools/worktree-status.sh" --porcelain)
  assert_contains "$output" $'DIRTY_UNCOMMITTED\t'

  new_repo status-ahead
  git -C "$REPO" worktree add -q -b agent/ahead "$REPO/.worktrees/ahead" master
  printf 'ahead\n' >"$REPO/.worktrees/ahead/ahead.txt"
  git -C "$REPO/.worktrees/ahead" add ahead.txt
  git -C "$REPO/.worktrees/ahead" commit -qm ahead
  output=$(expect_failure "$REPO/tools/worktree-status.sh" --porcelain)
  assert_contains "$output" $'AHEAD_UNMERGED\t'

  new_repo status-stale
  git -C "$REPO" worktree add -q -b agent/stale "$REPO/.worktrees/stale" master
  output=$(expect_failure "$REPO/tools/worktree-status.sh" --porcelain)
  assert_contains "$output" $'EMPTY_STALE\t'

  new_repo status-orphan
  mkdir -p "$REPO/.worktrees/orphan"
  output=$(expect_failure "$REPO/tools/worktree-status.sh" --porcelain)
  assert_contains "$output" $'ORPHAN\t'
  json=$("$REPO/tools/worktree-status.sh" --json || true)
  assert_contains "$json" '"status":"ORPHAN"'
}

test_uncommitted_work_refusal() {
  new_repo uncommitted
  git -C "$REPO" worktree add -q -b agent/dirty "$REPO/.worktrees/dirty" master
  printf 'uncommitted\n' >>"$REPO/.worktrees/dirty/shared.txt"
  output=$(expect_failure "$REPO/tools/agent/worktree-merge.sh" dirty)
  assert_contains "$output" 'agent worktree has unstaged changes'
  [[ -d "$REPO/.worktrees/dirty" ]] || fail 'dirty worktree was removed'
  git -C "$REPO" show-ref --verify --quiet refs/heads/agent/dirty || fail 'dirty branch was removed'
}

test_conflict_refusal() {
  new_repo conflict
  git -C "$REPO" worktree add -q -b agent/conflict "$REPO/.worktrees/conflict" master
  printf 'agent\n' >"$REPO/.worktrees/conflict/shared.txt"
  git -C "$REPO/.worktrees/conflict" add shared.txt
  git -C "$REPO/.worktrees/conflict" commit -qm agent-change
  printf 'master\n' >"$REPO/shared.txt"
  git -C "$REPO" add shared.txt
  git -C "$REPO" commit -qm master-change
  output=$(expect_failure "$REPO/tools/agent/worktree-merge.sh" conflict)
  assert_contains "$output" 'merge conflict'
  [[ -d "$REPO/.worktrees/conflict" ]] || fail 'conflicted worktree was removed'
  git -C "$REPO" rev-parse -q --verify MERGE_HEAD >/dev/null && fail 'conflicted merge was not aborted'
  [[ "$(cat "$REPO/shared.txt")" == master ]] || fail 'master was changed after conflict'
}

test_final_gate_preserves_worktree() {
  new_repo final-gate
  git -C "$REPO" worktree add -q -b agent/final "$REPO/.worktrees/final" master
  printf 'agent\n' >"$REPO/.worktrees/final/agent.txt"
  git -C "$REPO/.worktrees/final" add agent.txt
  git -C "$REPO/.worktrees/final" commit -qm agent-change
  output=$(expect_failure env FAIL_MAIN_GATE=1 "$REPO/tools/agent/worktree-merge.sh" final)
  assert_contains "$output" 'merged-master validation failed'
  [[ -d "$REPO/.worktrees/final" ]] || fail 'worktree removed after final gate failure'
  git -C "$REPO" show-ref --verify --quiet refs/heads/agent/final || fail 'branch removed after final gate failure'
  [[ -f "$REPO/agent.txt" ]] || fail 'expected merged master was not preserved for repair'
}

test_model_rejection
test_opencode_default_model
test_codex_arguments_and_dirty_main
test_merged_clean_status_is_not_attention
test_attention_statuses_fail
test_uncommitted_work_refusal
test_conflict_refusal
test_final_gate_preserves_worktree
echo 'harness fail-closed tests: ok'
