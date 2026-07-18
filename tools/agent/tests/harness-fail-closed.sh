#!/usr/bin/env bash
# Hermetic regression coverage for the agent harnesses.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd -P)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/rustscale-harness.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
assert_contains() { [[ "$1" == *"$2"* ]] || fail "missing '$2'"; }
assert_not_contains() { [[ "$1" != *"$2"* ]] || fail "unexpected '$2'"; }
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
    printf '%s\n' "$output" >&2
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
  cp "$ROOT/tools/agent/codex-task.sh" "$ROOT/tools/agent/pi-research.sh" \
    "$ROOT/tools/agent/worktree-merge.sh" "$ROOT/tools/agent/agent-review.sh" \
    "$ROOT/tools/agent/reconcile-report.sh" "$ROOT/tools/agent/remote-validate.sh" \
    "$ROOT/tools/agent/run-with-deadline.py" "$ROOT/tools/agent/check.sh" \
    "$REPO/tools/agent/"
  cp "$ROOT/tools/worktree-status.sh" "$REPO/tools/"
  chmod +x "$REPO/tools/agent/"*.sh "$REPO/tools/worktree-status.sh"
  printf '%s\n' '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'if [[ -n "${REVIEW_VALIDATOR_MARKER:-}" ]]; then printf ran >"$REVIEW_VALIDATOR_MARKER"; fi' \
    'if [[ -n "${REVIEW_MOVE_MASTER:-}" ]]; then printf moved >"$REVIEW_MOVE_MASTER/master-moved.txt"; git -C "$REVIEW_MOVE_MASTER" add master-moved.txt; git -C "$REVIEW_MOVE_MASTER" commit -qm review-moved; fi' \
    'if [[ "${FAIL_MAIN_GATE:-0}" == 1 && "$(git branch --show-current)" == master ]]; then exit 1; fi' \
    'exit 0' >"$REPO/tools/check.sh"
  chmod +x "$REPO/tools/check.sh"
  printf '%s\n' '.worktrees/' '.agent-runs/' 'bin/' 'args' 'expected' 'curl.log' >"$REPO/.gitignore"
  printf 'base\n' >"$REPO/shared.txt"
  git -C "$REPO" add .
  git -C "$REPO" commit -qm initial
  git init -q --bare "$TMP/$name-origin.git"
  git -C "$REPO" remote add origin "$TMP/$name-origin.git"
  git -C "$REPO" push -qu origin master
}

test_production_wrappers_are_executable() {
  local wrapper
  for wrapper in codex-task.sh pi-research.sh agent-review.sh reconcile-report.sh remote-validate.sh check.sh; do
    [[ -x "$ROOT/tools/agent/$wrapper" ]] || fail "production wrapper is not executable: $wrapper"
  done
}

test_check_failure_runs_once() {
  local check_repo output count
  check_repo="$TMP/check-once"
  mkdir -p "$check_repo/bin"
  cp "$ROOT/tools/check.sh" "$check_repo/check.sh"
  chmod +x "$check_repo/check.sh"
  # shellcheck disable=SC2016 # The temporary cargo stub must retain its variables.
  printf '%s\n' '#!/usr/bin/env bash' \
    'printf x >>"$CARGO_COUNT"' \
    'echo "error: intentional failure" >&2' \
    'exit 1' >"$check_repo/bin/cargo"
  chmod +x "$check_repo/bin/cargo"
  : >"$check_repo/count"
  output=$(expect_failure env PATH="$check_repo/bin:$PATH" CARGO_COUNT="$check_repo/count" \
    "$check_repo/check.sh" --no-test --no-fmt)
  count="$(wc -c <"$check_repo/count" | tr -d ' ')"
  [[ "$count" == 1 ]] || fail "check reran failed cargo command ($count executions)"
  assert_contains "$output" 'intentional failure'
}

# Build a Linux-shaped fake transport. The fake ssh executes the supplied
# remote command locally, while tar and timeout wrappers record every use.
make_remote_fakes() {
  local real_tar real_shasum
  real_tar="$(command -v tar)"
  real_shasum="$(command -v shasum)"
  FAKE_LOCAL_BIN="$TMP/remote-local-bin"
  FAKE_REMOTE_BIN="$TMP/remote-command-bin"
  FAKE_REMOTE_HOME="$TMP/remote-home"
  FAKE_REMOTE_TMP="$TMP/remote-tmp"
  mkdir -p "$FAKE_LOCAL_BIN" "$FAKE_REMOTE_BIN" "$FAKE_REMOTE_HOME" "$FAKE_REMOTE_TMP"

  # shellcheck disable=SC2016 # Fake commands expand their test environment at runtime.
  printf '%s\n' '#!/usr/bin/env bash' \
    'printf "%s\\n" "$*" >>"$FAKE_TAR_LOG"' \
    'exec "$REAL_TAR" "$@"' >"$FAKE_LOCAL_BIN/tar"
  cp "$FAKE_LOCAL_BIN/tar" "$FAKE_REMOTE_BIN/tar"

  # shellcheck disable=SC2016 # Fake commands expand their test environment at runtime.
  printf '%s\n' '#!/usr/bin/env bash' \
    'printf "%s\\n" "$*" >>"$FAKE_TIMEOUT_LOG"' \
    'while [[ "${1:-}" == --* ]]; do shift; done' \
    '[[ "${1:-}" =~ ^[0-9]+s$ ]] || exit 92' \
    'shift' \
    'if [[ -n "${FAKE_TIMEOUT_EXIT:-}" ]]; then exit "$FAKE_TIMEOUT_EXIT"; fi' \
    'exec "$@"' >"$FAKE_REMOTE_BIN/timeout"

  # macOS does not ship setsid; use a tiny equivalent so process-group cleanup
  # in the production remote entrypoint is exercised rather than bypassed.
  cat >"$FAKE_REMOTE_BIN/setsid" <<'EOF'
#!/usr/bin/env python3
import os
import sys
os.setsid()
os.execvp(sys.argv[1], sys.argv[1:])
EOF
  cat >"$FAKE_REMOTE_BIN/uname" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  -s) echo Linux ;;
  -m) echo aarch64 ;;
  -r) echo 6.8.0-fake ;;
  *) echo Linux fake 6.8.0-fake aarch64 ;;
esac
EOF
  cat >"$FAKE_REMOTE_BIN/lsb_release" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  -is) echo Ubuntu ;;
  -rs) echo 24.04 ;;
  *) exit 1 ;;
esac
EOF
  cat >"$FAKE_REMOTE_BIN/free" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' '              total        used        free' 'Mem:       33554432           1    33554431'
EOF
  cat >"$FAKE_REMOTE_BIN/df" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' 'Filesystem 1024-blocks Used Available Capacity Mounted on' \
  'fake       100000000    1  99999999       1% /tmp'
EOF
  # shellcheck disable=SC2016 # Fake command expands REAL_SHASUM at runtime.
  printf '%s\n' '#!/usr/bin/env bash' \
    'exec "$REAL_SHASUM" -a 256 "$@"' >"$FAKE_REMOTE_BIN/sha256sum"

  # shellcheck disable=SC2016 # Fake ssh must preserve and execute its final argument.
  cat >"$FAKE_LOCAL_BIN/ssh" <<'EOF'
#!/usr/bin/env bash
count=$#
(( count > 0 )) || exit 90
remote_command=${!count}
: >"$FAKE_SSH_ARGS"
for ((index = 1; index < count; index++)); do
  printf '%s\n' "${!index}" >>"$FAKE_SSH_ARGS"
done
cat >"$FAKE_SSH_BUNDLE"
env PATH="$FAKE_REMOTE_BIN:/usr/bin:/bin" HOME="$FAKE_REMOTE_HOME" \
  TMPDIR="$FAKE_REMOTE_TMP" USER=builder LOGNAME=builder \
  FAKE_TAR_LOG="$FAKE_TAR_LOG" FAKE_TIMEOUT_LOG="$FAKE_TIMEOUT_LOG" \
  FAKE_TIMEOUT_EXIT="${FAKE_TIMEOUT_EXIT:-}" REAL_TAR="$REAL_TAR" \
  REAL_SHASUM="$REAL_SHASUM" bash -c "$remote_command" <"$FAKE_SSH_BUNDLE"
EOF
  chmod +x "$FAKE_LOCAL_BIN/ssh" "$FAKE_LOCAL_BIN/tar" "$FAKE_REMOTE_BIN/"*
  export REAL_TAR="$real_tar" REAL_SHASUM="$real_shasum"
}

test_remote_validation_is_hermetic_and_fail_closed() {
  local output result extract listing
  new_repo remote-validation
  make_remote_fakes
  FAKE_SSH_ARGS="$REPO/args"
  FAKE_SSH_BUNDLE="$REPO/expected"
  FAKE_TAR_LOG="$REPO/tar.log"
  FAKE_TIMEOUT_LOG="$REPO/timeout.log"
  : >"$FAKE_TAR_LOG"
  : >"$FAKE_TIMEOUT_LOG"

  printf 'dirty tracked\n' >"$REPO/shared.txt"
  printf 'reviewed index\n' >"$REPO/reviewed.txt"
  git -C "$REPO" add reviewed.txt
  printf 'never transfer this token\n' >"$REPO/private-untracked.txt"
  mkdir -p "$REPO/.secrets" "$REPO/target" "$REPO/.worktrees/local"
  printf 'secret material\n' >"$REPO/.secrets/token"
  printf 'build output\n' >"$REPO/target/output"

  output=$(expect_failure env PATH="$FAKE_LOCAL_BIN:$PATH" \
    RUSTSCALE_REMOTE_TARGET=builder@fake-host \
    RUSTSCALE_REMOTE_MIN_MEMORY_MIB=1 RUSTSCALE_REMOTE_MIN_DISK_MIB=1 \
    FAKE_SSH_ARGS="$FAKE_SSH_ARGS" FAKE_SSH_BUNDLE="$FAKE_SSH_BUNDLE" \
    FAKE_TAR_LOG="$FAKE_TAR_LOG" FAKE_TIMEOUT_LOG="$FAKE_TIMEOUT_LOG" \
    FAKE_LOCAL_BIN="$FAKE_LOCAL_BIN" FAKE_REMOTE_BIN="$FAKE_REMOTE_BIN" \
    FAKE_REMOTE_HOME="$FAKE_REMOTE_HOME" FAKE_REMOTE_TMP="$FAKE_REMOTE_TMP" \
    REAL_TAR="$REAL_TAR" REAL_SHASUM="$REAL_SHASUM" \
    "$REPO/tools/agent/remote-validate.sh" preflight)
  assert_contains "$output" 'remote prerequisites are incomplete'
  assert_contains "$output" $'RUSTSCALE_REMOTE\tmissing.required\tcargo'
  assert_contains "$output" 'rustup component add clippy rustfmt'
  assert_not_contains "$output" 'never transfer this token'
  assert_contains "$(cat "$FAKE_SSH_ARGS")" 'BatchMode=yes'
  assert_contains "$(cat "$FAKE_SSH_ARGS")" 'StrictHostKeyChecking=yes'
  assert_contains "$(cat "$FAKE_SSH_ARGS")" 'ForwardAgent=no'
  assert_contains "$(cat "$FAKE_SSH_ARGS")" 'ClearAllForwardings=yes'
  [[ -s "$FAKE_TAR_LOG" ]] || fail 'remote validation did not use the fake tar command'
  [[ -s "$FAKE_TIMEOUT_LOG" ]] || fail 'remote validation did not use the fake timeout command'

  extract="$TMP/remote-extract"
  mkdir -p "$extract/control" "$extract/source"
  "$REAL_TAR" -xf "$FAKE_SSH_BUNDLE" -C "$extract/control"
  "$REAL_TAR" -xf "$extract/control/source.tar" -C "$extract/source"
  [[ "$(cat "$extract/source/shared.txt")" == 'dirty tracked' ]] \
    || fail 'remote archive omitted the explicit working-tree diff'
  [[ "$(cat "$extract/source/reviewed.txt")" == 'reviewed index' ]] \
    || fail 'remote archive omitted the reviewed index addition'
  listing=$(find "$extract/source" -print)
  assert_not_contains "$listing" 'private-untracked.txt'
  if find "$extract/source" \( -name .git -o -name target -o -name .agent-runs \
      -o -name .worktrees -o -name .secrets -o -name secrets \) -print -quit \
      | grep -q .; then
    fail 'remote source contained a prohibited path'
  fi
  if find "$FAKE_REMOTE_TMP" -maxdepth 1 -name 'rustscale-remote.*' | grep -q .; then
    fail 'remote temporary directory survived preflight'
  fi

  result=$(find "$REPO/.agent-runs/remote-validation" -type f -name '*.json' -print | sed -n '1p')
  [[ -n "$result" ]] || fail 'remote validation did not write provenance'
  assert_contains "$(cat "$result")" '"status": "blocked"'
  assert_contains "$(cat "$result")" '"cleanup": "confirmed"'
  assert_contains "$(cat "$result")" '"archive_integrity": "verified"'
  assert_contains "$(cat "$result")" '"untracked_files_excluded"'
  assert_not_contains "$(cat "$result")" "$REPO"
  assert_not_contains "$(cat "$result")" 'secret material'
}

test_remote_validation_runs_focused_check() {
  local output result
  new_repo remote-focused-check
  make_remote_fakes
  FAKE_SSH_ARGS="$REPO/args"
  FAKE_SSH_BUNDLE="$REPO/expected"
  FAKE_TAR_LOG="$REPO/tar.log"
  FAKE_TIMEOUT_LOG="$REPO/timeout.log"
  : >"$FAKE_TAR_LOG"
  : >"$FAKE_TIMEOUT_LOG"

  cat >"$FAKE_REMOTE_BIN/cargo" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  --version) echo 'cargo 1.91.0 (fake)' ;;
  clippy) echo 'clippy 0.1.91 (fake)' ;;
  fmt) echo 'rustfmt 1.91.0 (fake)' ;;
  *) exit 0 ;;
esac
EOF
  cat >"$FAKE_REMOTE_BIN/rustc" <<'EOF'
#!/usr/bin/env bash
echo 'rustc 1.91.0 (fake)'
EOF
  printf '%s\n' '#!/usr/bin/env bash' 'exit 0' \
    >"$FAKE_REMOTE_BIN/pkg-config"
  cp "$FAKE_REMOTE_BIN/pkg-config" "$FAKE_REMOTE_BIN/cmake"
  chmod +x "$FAKE_REMOTE_BIN/cargo" "$FAKE_REMOTE_BIN/rustc" \
    "$FAKE_REMOTE_BIN/pkg-config" "$FAKE_REMOTE_BIN/cmake"
  printf '%s\n' '#!/usr/bin/env bash' \
    'echo "remote check args:$*"' 'exit 0' >"$REPO/tools/check.sh"
  chmod +x "$REPO/tools/check.sh"

  output=$(expect_success env PATH="$FAKE_LOCAL_BIN:$PATH" \
    RUSTSCALE_REMOTE_TARGET=builder@fake-host \
    RUSTSCALE_REMOTE_MIN_MEMORY_MIB=1 RUSTSCALE_REMOTE_MIN_DISK_MIB=1 \
    FAKE_SSH_ARGS="$FAKE_SSH_ARGS" FAKE_SSH_BUNDLE="$FAKE_SSH_BUNDLE" \
    FAKE_TAR_LOG="$FAKE_TAR_LOG" FAKE_TIMEOUT_LOG="$FAKE_TIMEOUT_LOG" \
    FAKE_LOCAL_BIN="$FAKE_LOCAL_BIN" FAKE_REMOTE_BIN="$FAKE_REMOTE_BIN" \
    FAKE_REMOTE_HOME="$FAKE_REMOTE_HOME" FAKE_REMOTE_TMP="$FAKE_REMOTE_TMP" \
    REAL_TAR="$REAL_TAR" REAL_SHASUM="$REAL_SHASUM" \
    "$REPO/tools/agent/remote-validate.sh" check rustscale-key)
  assert_contains "$output" 'remote check args:rustscale-key'
  assert_contains "$output" $'RUSTSCALE_REMOTE\tfact.open_files_soft\t'
  assert_contains "$output" $'RUSTSCALE_REMOTE\tfact.open_files_hard\t'
  assert_contains "$output" $'RUSTSCALE_REMOTE\tstatus\tpassed'
  result=$(find "$REPO/.agent-runs/remote-validation" -type f -name '*.json' -print | sed -n '1p')
  assert_contains "$(cat "$result")" '"status": "passed"'
  assert_contains "$(cat "$result")" '"cleanup": "confirmed"'
  assert_contains "$(cat "$result")" '"open_files_soft"'
  assert_contains "$(cat "$result")" '"open_files_hard"'
}

test_remote_validation_disable_privilege_and_timeout_guards() {
  local output result
  new_repo remote-guards
  make_remote_fakes
  FAKE_SSH_ARGS="$REPO/args"
  FAKE_SSH_BUNDLE="$REPO/expected"
  FAKE_TAR_LOG="$REPO/tar.log"
  FAKE_TIMEOUT_LOG="$REPO/timeout.log"
  : >"$FAKE_TAR_LOG"
  : >"$FAKE_TIMEOUT_LOG"

  output=$(expect_success env PATH="$FAKE_LOCAL_BIN:$PATH" RUSTSCALE_REMOTE_DISABLE=1 \
    FAKE_SSH_ARGS="$FAKE_SSH_ARGS" FAKE_SSH_BUNDLE="$FAKE_SSH_BUNDLE" \
    FAKE_TAR_LOG="$FAKE_TAR_LOG" FAKE_TIMEOUT_LOG="$FAKE_TIMEOUT_LOG" \
    "$REPO/tools/agent/remote-validate.sh" preflight)
  assert_contains "$output" 'explicitly disabled'
  [[ ! -e "$FAKE_SSH_ARGS" ]] || fail 'disabled remote validation invoked ssh'
  [[ ! -s "$FAKE_TAR_LOG" ]] || fail 'disabled remote validation invoked tar'
  result=$(find "$REPO/.agent-runs/remote-validation" -type f -name '*.json' -print | sed -n '1p')
  assert_contains "$(cat "$result")" '"status": "disabled"'

  output=$(expect_failure "$REPO/tools/agent/remote-validate.sh" tun)
  assert_contains "$output" 'requires the explicit --allow-privileged flag'
  output=$(expect_failure "$REPO/tools/agent/remote-validate.sh" install --allow-privileged)
  assert_contains "$output" 'requires the additional --allow-install flag'

  rm -rf "$REPO/.agent-runs/remote-validation"
  output=$(expect_failure env PATH="$FAKE_LOCAL_BIN:$PATH" \
    RUSTSCALE_REMOTE_TARGET=builder@fake-host RUSTSCALE_REMOTE_TIMEOUT=1 \
    RUSTSCALE_REMOTE_MIN_MEMORY_MIB=1 RUSTSCALE_REMOTE_MIN_DISK_MIB=1 \
    FAKE_TIMEOUT_EXIT=124 FAKE_SSH_ARGS="$FAKE_SSH_ARGS" \
    FAKE_SSH_BUNDLE="$FAKE_SSH_BUNDLE" FAKE_TAR_LOG="$FAKE_TAR_LOG" \
    FAKE_TIMEOUT_LOG="$FAKE_TIMEOUT_LOG" FAKE_LOCAL_BIN="$FAKE_LOCAL_BIN" \
    FAKE_REMOTE_BIN="$FAKE_REMOTE_BIN" FAKE_REMOTE_HOME="$FAKE_REMOTE_HOME" \
    FAKE_REMOTE_TMP="$FAKE_REMOTE_TMP" REAL_TAR="$REAL_TAR" \
    REAL_SHASUM="$REAL_SHASUM" "$REPO/tools/agent/remote-validate.sh" preflight)
  assert_contains "$output" 'status: timed_out'
  result=$(find "$REPO/.agent-runs/remote-validation" -type f -name '*.json' -print | sed -n '1p')
  assert_contains "$(cat "$result")" '"status": "timed_out"'
  assert_contains "$(cat "$result")" '"cleanup": "confirmed"'
  if find "$FAKE_REMOTE_TMP" -maxdepth 1 -name 'rustscale-remote.*' | grep -q .; then
    fail 'remote temporary directory survived timeout'
  fi
}

test_remote_validation_rejects_tracked_secrets() {
  local output
  new_repo remote-secret-rejection
  mkdir -p "$REPO/.secrets"
  printf 'tracked secret\n' >"$REPO/.secrets/token"
  git -C "$REPO" add .secrets/token
  output=$(expect_failure env RUSTSCALE_REMOTE_TARGET=builder@fake-host \
    "$REPO/tools/agent/remote-validate.sh" preflight)
  assert_contains "$output" 'prohibited candidate path'
  assert_contains "$output" 'prohibited secret or generated path'
}

test_pi_arguments_and_model_override() {
  new_repo pi-arguments
  mkdir "$REPO/bin"
  # shellcheck disable=SC2016 # The temporary Pi stub must retain its variables.
  printf '%s\n' '#!/usr/bin/env bash' \
    'printf "%s\\n" "$@" >"$PI_ARGS"' \
    'printf "%s\\n" "research complete"' >"$REPO/bin/pi"
  chmod +x "$REPO/bin/pi"
  output=$(env PATH="$REPO/bin:$PATH" PI_ARGS="$REPO/args" PI_PROVIDER=example-provider \
    PI_MODEL=example/model "$REPO/tools/agent/pi-research.sh" research 'compare behavior')
  [[ "$output" == 'research complete' ]] || fail 'Pi wrapper did not return its result'
  assert_contains "$(cat "$REPO/args")" '--print'
  assert_contains "$(cat "$REPO/args")" '--no-session'
  assert_contains "$(cat "$REPO/args")" '--no-extensions'
  assert_contains "$(cat "$REPO/args")" 'read,grep,find,ls'
  assert_contains "$(cat "$REPO/args")" 'example-provider'
  assert_contains "$(cat "$REPO/args")" 'example/model'
  assert_contains "$(cat "$REPO/args")" 'Do not modify files'
  assert_contains "$(cat "$REPO/args")" 'compare behavior'
}

# shellcheck disable=SC2016 # The temporary Codex stub must retain its variables.
test_codex_arguments_and_dirty_main() {
  new_repo codex
  mkdir "$REPO/bin"
  # shellcheck disable=SC2016 # The temporary Codex stub must retain its variables.
  printf '%s\n' '#!/usr/bin/env bash' \
    'printf "%s\\n" "$@" >"$CODEX_ARGS"' \
    'out=""; previous=""' \
    'for arg in "$@"; do if [[ "$previous" == -o ]]; then out="$arg"; fi; previous="$arg"; done' \
    'printf "%s\\n" "final answer" >"$out"' \
    'printf "%s\\n" "$CODEX_JSON"' >"$REPO/bin/codex"
  chmod +x "$REPO/bin/codex"
  PATH="$REPO/bin:$PATH" CODEX_MODEL=example-model CODEX_ARGS="$REPO/args" CODEX_JSON='{"type":"thread.started","thread_id":"thread_exact"}' \
    "$REPO/tools/agent/codex-task.sh" exact 'implement this'
  assert_contains "$(cat "$REPO/args")" 'exec'
  assert_contains "$(cat "$REPO/args")" '--json'
  assert_contains "$(cat "$REPO/args")" 'example-model'
  assert_contains "$(cat "$REPO/args")" 'Do not commit changes and do not spawn agents.'
  assert_contains "$(cat "$REPO/args")" 'implement this'
  assert_contains "$(cat "$REPO/.agent-runs/codex/exact/metadata.json")" 'thread_exact'
  assert_contains "$(cat "$REPO/.agent-runs/codex/exact/metadata.json")" "$(git -C "$REPO" rev-parse master)"
  assert_contains "$(cat "$REPO/.agent-runs/codex/exact/metadata.json")" '"jsonl_log"'
  assert_contains "$(cat "$REPO/.agent-runs/codex/exact/metadata.json")" '"final_message"'
  assert_contains "$(cat "$REPO/.agent-runs/codex/exact/metadata.json")" '"status": "DONE"'

  printf 'dirty\n' >>"$REPO/shared.txt"
  output=$(expect_failure env PATH="$REPO/bin:$PATH" CODEX_ARGS="$REPO/args" \
    "$REPO/tools/agent/codex-task.sh" dirty-main prompt)
  assert_contains "$output" 'main worktree has unstaged changes'
  git -C "$REPO" show-ref --verify --quiet refs/heads/agent/dirty-main \
    && fail 'dirty main created a branch'
  [[ ! -e "$REPO/.worktrees/dirty-main" ]] || fail 'dirty main created a worktree'
}

test_codex_resume_and_deadline() {
  new_repo codex-resume
  mkdir "$REPO/bin"
  # shellcheck disable=SC2016 # The temporary Codex stub must retain its variables.
  printf '%s\n' '#!/usr/bin/env bash' \
    'printf "%s\\n" "$@" >"$CODEX_ARGS"' \
    'out=""; previous=""' \
    'for arg in "$@"; do if [[ "$previous" == -o ]]; then out="$arg"; fi; previous="$arg"; done' \
    'printf "%s\\n" "final answer" >"$out"' \
    'printf "%s\\n" "$CODEX_JSON"' \
    'if grep -qx resume "$CODEX_ARGS"; then' \
    '  resume_line="$(grep -n "^resume$" "$CODEX_ARGS" | sed -n "1s/:.*//p")"' \
    '  for option in -m -s -C; do' \
    '    line="$(grep -n "^${option}$" "$CODEX_ARGS" | sed -n "1s/:.*//p")"' \
    '    [[ -n "$line" && "$line" -lt "$resume_line" ]] || exit 91' \
    '  done' \
    '  for option in --json -o; do' \
    '    line="$(grep -n "^${option}$" "$CODEX_ARGS" | sed -n "1s/:.*//p")"' \
    '    [[ -n "$line" && "$line" -gt "$resume_line" ]] || exit 92' \
    '  done' \
    'fi' >"$REPO/bin/codex"
  chmod +x "$REPO/bin/codex"
  PATH="$REPO/bin:$PATH" CODEX_ARGS="$REPO/args" CODEX_JSON='{"thread_id":"thread_resume"}' \
    "$REPO/tools/agent/codex-task.sh" resume-me initial
  first_log="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["jsonl_log"])' "$REPO/.agent-runs/codex/resume-me/metadata.json")"
  PATH="$REPO/bin:$PATH" CODEX_ARGS="$REPO/args" CODEX_JSON='{"thread_id":"thread_resume"}' \
    "$REPO/tools/agent/codex-task.sh" --continue resume-me follow-up
  current_log="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["jsonl_log"])' "$REPO/.agent-runs/codex/resume-me/metadata.json")"
  assert_contains "$(cat "$REPO/args")" 'resume'
  assert_contains "$(cat "$REPO/args")" 'thread_resume'
  assert_contains "$(cat "$REPO/args")" "$REPO/.worktrees/resume-me"
  [[ "$first_log" != "$current_log" && -f "$first_log" && -f "$current_log" ]] \
    || fail 'Codex attempt logs were not preserved independently'

  new_repo codex-deadline
  mkdir "$REPO/bin"
  printf '%s\n' '#!/usr/bin/env bash' 'sleep 20' >"$REPO/bin/codex"
  chmod +x "$REPO/bin/codex"
  started="$(date +%s)"
  output=$(expect_failure env PATH="$REPO/bin:$PATH" "$REPO/tools/agent/codex-task.sh" deadline prompt 1)
  elapsed=$(( $(date +%s) - started ))
  (( elapsed < 10 )) || fail "deadline was not enforced promptly (${elapsed}s)"
  assert_contains "$output" 'TIMED_OUT'
}

test_codex_missing_session_id_fails() {
  new_repo codex-missing-session
  mkdir "$REPO/bin"
  # shellcheck disable=SC2016 # The temporary Codex stub must retain its variables.
  printf '%s\n' '#!/usr/bin/env bash' \
    'out=""; previous=""' \
    'for arg in "$@"; do if [[ "$previous" == -o ]]; then out="$arg"; fi; previous="$arg"; done' \
    'printf "%s\\n" "final answer" >"$out"' >"$REPO/bin/codex"
  chmod +x "$REPO/bin/codex"
  output=$(expect_failure env PATH="$REPO/bin:$PATH" "$REPO/tools/agent/codex-task.sh" missing-session prompt)
  assert_contains "$output" 'completed without a session ID'
  assert_contains "$(cat "$REPO/.agent-runs/codex/missing-session/metadata.json")" '"status": "FAILED"'
  [[ -d "$REPO/.worktrees/missing-session" ]] || fail 'missing-session worktree was not preserved'
}

test_codex_resume_session_mismatch_fails() {
  new_repo codex-resume-mismatch
  mkdir "$REPO/bin"
  # shellcheck disable=SC2016 # The temporary Codex stub must retain its variables.
  printf '%s\n' '#!/usr/bin/env bash' \
    'out=""; previous=""' \
    'for arg in "$@"; do if [[ "$previous" == -o ]]; then out="$arg"; fi; previous="$arg"; done' \
    'printf "%s\\n" "final answer" >"$out"' \
    'printf "%s\\n" "$CODEX_JSON"' >"$REPO/bin/codex"
  chmod +x "$REPO/bin/codex"
  PATH="$REPO/bin:$PATH" CODEX_JSON='{"thread_id":"thread_saved"}' \
    "$REPO/tools/agent/codex-task.sh" resume-mismatch initial
  output=$(expect_failure env PATH="$REPO/bin:$PATH" CODEX_JSON='{"thread_id":"thread_other"}' \
    "$REPO/tools/agent/codex-task.sh" --continue resume-mismatch follow-up)
  assert_contains "$output" 'session ID did not match saved session'
  assert_contains "$(cat "$REPO/.agent-runs/codex/resume-mismatch/metadata.json")" '"session_id": "thread_saved"'
  assert_contains "$(cat "$REPO/.agent-runs/codex/resume-mismatch/metadata.json")" '"status": "FAILED"'
}

test_codex_wrapper_signal_updates_metadata() {
  local signal_name expected_status session_id title wrapper status started_at elapsed
  for signal_name in TERM INT; do
    case "$signal_name" in
      TERM) expected_status=143; session_id=thread_term; title=interrupted-term ;;
      INT) expected_status=130; session_id=thread_int; title=interrupted-int ;;
    esac
    new_repo "codex-wrapper-$signal_name"
    mkdir "$REPO/bin"
    # shellcheck disable=SC2016 # The temporary Codex stub must retain its variables.
    printf '%s\n' '#!/usr/bin/env bash' \
      'printf "%s\\n" "$CODEX_JSON"' \
      'sleep 30 &' \
      'printf "%s" "$!" >"$CODEX_CHILD"' \
      'touch "$CODEX_STARTED"' \
      'wait' >"$REPO/bin/codex"
    chmod +x "$REPO/bin/codex"
    env PATH="$REPO/bin:$PATH" CODEX_CHILD="$REPO/child.pid" CODEX_STARTED="$REPO/started" \
      CODEX_JSON="{\"thread_id\":\"$session_id\"}" \
      "$REPO/tools/agent/codex-task.sh" "$title" prompt 30 >"$TMP/codex-wrapper-$signal_name.log" 2>&1 &
    wrapper=$!
    for _ in $(seq 1 30); do
      [[ -f "$REPO/started" ]] && break
      sleep 0.1
    done
    if [[ ! -f "$REPO/started" ]]; then
      cat "$TMP/codex-wrapper-$signal_name.log" >&2 || true
      fail "Codex wrapper $signal_name test did not start Codex"
    fi
    started_at="$(date +%s)"
    kill -"$signal_name" "$wrapper"
    set +e
    wait "$wrapper"
    status=$?
    set -e
    elapsed=$(( $(date +%s) - started_at ))
    [[ "$status" == "$expected_status" ]] || fail "Codex wrapper $signal_name exit was $status, expected $expected_status"
    (( elapsed < 10 )) || fail "Codex wrapper $signal_name did not exit promptly (${elapsed}s)"
    assert_contains "$(cat "$REPO/.agent-runs/codex/$title/metadata.json")" '"status": "INTERRUPTED"'
    assert_contains "$(cat "$REPO/.agent-runs/codex/$title/metadata.json")" "\"session_id\": \"$session_id\""
    for _ in $(seq 1 20); do
      kill -0 "$(cat "$REPO/child.pid")" 2>/dev/null || break
      sleep 0.1
    done
    ! kill -0 "$(cat "$REPO/child.pid")" 2>/dev/null || fail "Codex child survived wrapper $signal_name"
  done
}

test_deadline_process_group_cleanup() {
  local grace_script linger marker pidfile runner status output
  linger="$TMP/linger.py"
  printf '%s\n' \
    'import subprocess, sys, time' \
    'child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])' \
    'open(sys.argv[1], "w", encoding="ascii").write(str(child.pid))' \
    'time.sleep(30)' >"$linger"

  pidfile="$TMP/timeout-child.pid"
  set +e
  output="$(python3 "$ROOT/tools/agent/run-with-deadline.py" 1 -- python3 "$linger" "$pidfile" 2>&1)"
  status=$?
  set -e
  [[ "$status" == 124 ]] || fail "deadline helper exit was $status, expected 124"
  [[ -s "$pidfile" ]] || fail 'deadline helper did not start the grandchild'
  for _ in $(seq 1 20); do
    kill -0 "$(cat "$pidfile")" 2>/dev/null || break
    sleep 0.1
  done
  ! kill -0 "$(cat "$pidfile")" 2>/dev/null || fail 'grandchild survived deadline cleanup'
  assert_contains "$output" 'deadline reached'

  grace_script="$TMP/deadline-grace.py"
  marker="$TMP/deadline-grace.marker"
  printf '%s\n' \
    'import signal, sys, time' \
    'def terminate(_signum, _frame):' \
    '    with open(sys.argv[1], "a", encoding="ascii") as handle: handle.write("term\\n")' \
    '    time.sleep(0.5)' \
    '    with open(sys.argv[1], "a", encoding="ascii") as handle: handle.write("done\\n")' \
    '    raise SystemExit(143)' \
    'signal.signal(signal.SIGTERM, terminate)' \
    'time.sleep(30)' >"$grace_script"
  set +e
  output="$(env RUSTSCALE_DEADLINE_GRACE_SECONDS=2 \
    python3 "$ROOT/tools/agent/run-with-deadline.py" 1 -- \
      python3 "$grace_script" "$marker" 2>&1)"
  status=$?
  set -e
  [[ "$status" == 124 ]] || fail "deadline helper grace exit was $status, expected 124"
  [[ -f "$marker" ]] || fail 'deadline helper did not deliver TERM during configurable grace'
  assert_contains "$(cat "$marker")" 'done'

  pidfile="$TMP/term-child.pid"
  python3 "$ROOT/tools/agent/run-with-deadline.py" 30 -- python3 "$linger" "$pidfile" >"$TMP/term.log" 2>&1 &
  runner=$!
  for _ in $(seq 1 20); do
    [[ -s "$pidfile" ]] && break
    sleep 0.1
  done
  [[ -s "$pidfile" ]] || fail 'termination test did not start the grandchild'
  kill -TERM "$runner"
  set +e
  wait "$runner"
  status=$?
  set -e
  [[ "$status" == 143 ]] || fail "SIGTERM exit was $status, expected 143"
  for _ in $(seq 1 20); do
    kill -0 "$(cat "$pidfile")" 2>/dev/null || break
    sleep 0.1
  done
  ! kill -0 "$(cat "$pidfile")" 2>/dev/null || fail 'grandchild survived SIGTERM cleanup'

  pidfile="$TMP/hup-child.pid"
  python3 "$ROOT/tools/agent/run-with-deadline.py" 30 -- python3 "$linger" "$pidfile" >"$TMP/hup.log" 2>&1 &
  runner=$!
  for _ in $(seq 1 20); do
    [[ -s "$pidfile" ]] && break
    sleep 0.1
  done
  [[ -s "$pidfile" ]] || fail 'SIGHUP test did not start the grandchild'
  kill -HUP "$runner"
  set +e
  wait "$runner"
  status=$?
  set -e
  [[ "$status" == 129 ]] || fail "SIGHUP exit was $status, expected 129"
  for _ in $(seq 1 20); do
    kill -0 "$(cat "$pidfile")" 2>/dev/null || break
    sleep 0.1
  done
  ! kill -0 "$(cat "$pidfile")" 2>/dev/null || fail 'grandchild survived SIGHUP cleanup'
}

test_codex_diverged_master_refusal() {
  new_repo codex-diverged
  git -C "$REPO" commit --allow-empty -qm local-ahead
  output=$(expect_failure "$REPO/tools/agent/codex-task.sh" stale prompt)
  assert_contains "$output" 'local master and origin/master differ'
  [[ ! -e "$REPO/.worktrees/stale" ]] || fail 'diverged master created a worktree'
}

test_pi_dirty_rejection() {
  new_repo pi-dirty
  mkdir "$REPO/bin"
  # shellcheck disable=SC2016 # The temporary Pi stub must retain its variables.
  printf '%s\n' '#!/usr/bin/env bash' 'printf changed >>"$RESEARCH_FILE"' 'printf "%s\\n" done' >"$REPO/bin/pi"
  chmod +x "$REPO/bin/pi"
  output=$(expect_failure env PATH="$REPO/bin:$PATH" RESEARCH_FILE="$REPO/shared.txt" "$REPO/tools/agent/pi-research.sh" dirty prompt)
  assert_contains "$output" 'repository changed during research'
}

test_pi_initial_dirty_refusal() {
  new_repo pi-initial-dirty
  mkdir "$REPO/bin"
  # shellcheck disable=SC2016 # The temporary Pi stub must retain its variables.
  printf '%s\n' '#!/usr/bin/env bash' 'printf called >>"$PI_LOG"; exit 1' >"$REPO/bin/pi"
  chmod +x "$REPO/bin/pi"
  : >"$REPO/pi.log"
  printf 'already dirty\n' >>"$REPO/shared.txt"
  output=$(expect_failure env PATH="$REPO/bin:$PATH" PI_LOG="$REPO/pi.log" "$REPO/tools/agent/pi-research.sh" research prompt)
  assert_contains "$output" 'repository is already dirty'
  [[ ! -s "$REPO/pi.log" ]] || fail 'dirty research started Pi'
}

test_pi_head_change_rejection() {
  new_repo pi-head-change
  mkdir "$REPO/bin"
  # shellcheck disable=SC2016 # The temporary Pi stub must retain its variables.
  printf '%s\n' '#!/usr/bin/env bash' 'git -C "$RESEARCH_DIR" commit --allow-empty -qm research-mutation' 'printf "%s\\n" done' >"$REPO/bin/pi"
  chmod +x "$REPO/bin/pi"
  output=$(expect_failure env PATH="$REPO/bin:$PATH" RESEARCH_DIR="$REPO" "$REPO/tools/agent/pi-research.sh" head-change prompt)
  assert_contains "$output" 'repository changed during research'
}

test_pi_deadline() {
  new_repo pi-deadline
  mkdir "$REPO/bin"
  printf '%s\n' '#!/usr/bin/env bash' 'sleep 20' >"$REPO/bin/pi"
  chmod +x "$REPO/bin/pi"
  set +e
  output=$(env PATH="$REPO/bin:$PATH" "$REPO/tools/agent/pi-research.sh" deadline prompt 1 2>&1)
  status=$?
  set -e
  if [[ "$status" != 124 ]]; then
    printf '%s\n' "$output" >&2
    fail "Pi deadline exit was $status, expected 124"
  fi
  assert_contains "$output" '##STATUS:TIMED_OUT'
}

test_review_next_action() {
  new_repo review
  git -C "$REPO" worktree add -q -b agent/review "$REPO/.worktrees/review" master
  printf 'review\n' >"$REPO/.worktrees/review/review.txt"
  output=$(expect_success "$REPO/tools/agent/agent-review.sh" review)
  assert_contains "$output" '##STATUS:REVIEWED'
  assert_contains "$output" 'NEXT: resolve or commit the preserved worktree changes'
}

test_review_harness_policy_selection() {
  new_repo review-policy
  git -C "$REPO" worktree add -q -b agent/review-policy "$REPO/.worktrees/review-policy" master
  # shellcheck disable=SC2016 # The temporary validator must retain its variables.
  printf '%s\n' '#!/usr/bin/env bash' 'printf selected >"$REVIEW_VALIDATOR"' >"$REPO/.worktrees/review-policy/tools/agent/check.sh"
  chmod +x "$REPO/.worktrees/review-policy/tools/agent/check.sh"
  printf 'policy\n' >"$REPO/.worktrees/review-policy/tools/agent/policy-note.txt"
  output=$(env REVIEW_VALIDATOR="$REPO/selected" "$REPO/tools/agent/agent-review.sh" review-policy 2>&1)
  assert_contains "$output" 'validator: tools/agent/check.sh'
  [[ "$(cat "$REPO/selected")" == selected ]] || fail 'review did not select the agent harness gate'
}

test_review_stale_branch_refusal() {
  new_repo review-stale
  git -C "$REPO" worktree add -q -b agent/review-stale "$REPO/.worktrees/review-stale" master
  printf 'master advances\n' >"$REPO/master-advance.txt"
  git -C "$REPO" add master-advance.txt
  git -C "$REPO" commit -qm master-advance
  git -C "$REPO" push -q origin master
  output=$(expect_failure env REVIEW_VALIDATOR_MARKER="$REPO/validator-ran" \
    "$REPO/tools/agent/agent-review.sh" review-stale)
  assert_contains "$output" '##STATUS:STALE'
  assert_contains "$output" 'NEXT: rebase agent/review-stale onto master'
  [[ ! -e "$REPO/validator-ran" ]] || fail 'stale review ran its validator'
}

test_review_remote_staleness_refusal() {
  new_repo review-remote-stale
  git -C "$REPO" worktree add -q -b agent/review-remote-stale "$REPO/.worktrees/review-remote-stale" master
  writer="$TMP/review-remote-writer"
  git clone -q "$TMP/review-remote-stale-origin.git" "$writer"
  git -C "$writer" config user.name harness-test
  git -C "$writer" config user.email harness@example.invalid
  printf 'remote advances\n' >"$writer/remote-advance.txt"
  git -C "$writer" add remote-advance.txt
  git -C "$writer" commit -qm remote-advance
  git -C "$writer" push -q origin master
  output=$(expect_failure env REVIEW_VALIDATOR_MARKER="$REPO/validator-ran" \
    "$REPO/tools/agent/agent-review.sh" review-remote-stale)
  assert_contains "$output" 'local_master='
  assert_contains "$output" 'NEXT: reconcile local master with origin/master'
  [[ ! -e "$REPO/validator-ran" ]] || fail 'remote-stale review ran its validator'
}

test_review_master_movement_refusal() {
  new_repo review-master-movement
  git -C "$REPO" worktree add -q -b agent/review-master-movement "$REPO/.worktrees/review-master-movement" master
  output=$(expect_failure env REVIEW_MOVE_MASTER="$REPO" \
    "$REPO/tools/agent/agent-review.sh" review-master-movement)
  assert_contains "$output" '##STATUS:STALE'
  assert_contains "$output" 'master_changed=1'
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

test_squash_integrated_statuses_are_evidence_backed() {
  local output
  new_repo status-squash-tree
  git -C "$REPO" worktree add -q -b agent/squash-tree "$REPO/.worktrees/squash-tree" master
  printf 'squashed\n' >"$REPO/.worktrees/squash-tree/squashed.txt"
  git -C "$REPO/.worktrees/squash-tree" add squashed.txt
  git -C "$REPO/.worktrees/squash-tree" commit -qm squash-source
  git -C "$REPO" merge -q --squash agent/squash-tree
  git -C "$REPO" commit -qm squash-destination
  output=$(expect_success "$REPO/tools/worktree-status.sh" --porcelain)
  assert_contains "$output" $'SQUASH_INTEGRATED\t'
  assert_contains "$output" $'\ttree:'
  assert_not_contains "$output" $'AHEAD_UNMERGED\t'

  new_repo status-squash-patch
  git -C "$REPO" worktree add -q -b agent/squash-patch "$REPO/.worktrees/squash-patch" master
  printf 'feature\n' >"$REPO/.worktrees/squash-patch/feature.txt"
  git -C "$REPO/.worktrees/squash-patch" add feature.txt
  git -C "$REPO/.worktrees/squash-patch" commit -qm patch-source
  printf 'unrelated\n' >"$REPO/unrelated.txt"
  git -C "$REPO" add unrelated.txt
  git -C "$REPO" commit -qm unrelated-master-change
  git -C "$REPO" merge -q --squash agent/squash-patch
  git -C "$REPO" commit -qm patch-destination
  [[ "$(git -C "$REPO" rev-parse 'master^{tree}')" != \
    "$(git -C "$REPO/.worktrees/squash-patch" rev-parse 'HEAD^{tree}')" ]] \
    || fail 'patch fixture unexpectedly had tree equivalence'
  output=$(expect_success "$REPO/tools/worktree-status.sh" --porcelain)
  assert_contains "$output" $'SQUASH_INTEGRATED\t'
  assert_contains "$output" $'\tpatch:'
  assert_not_contains "$output" $'AHEAD_UNMERGED\t'
}

test_reconciliation_report_links_sessions_by_metadata() {
  local output
  new_repo reconciliation-report
  git -C "$REPO" worktree add -q -b agent/matched "$REPO/.worktrees/matched" master
  git -C "$REPO" branch agent/stale-session master
  mkdir -p "$REPO/.agent-runs/codex/matched" "$REPO/.agent-runs/codex/stale" \
    "$REPO/.agent-runs/codex/orphan" "$REPO/.agent-runs/pi-impl/legacy"
  python3 - "$REPO" <<'PYEOF'
import json
import os
import sys
root = sys.argv[1]
records = {
    "matched": ("agent/matched", os.path.join(root, ".worktrees", "matched"), "DONE"),
    "stale": ("agent/stale-session", os.path.join(root, ".worktrees", "missing"), "DONE"),
    "orphan": ("agent/missing-session", os.path.join(root, ".worktrees", "missing"), "RUNNING"),
}
for name, (branch, worktree, status) in records.items():
    path = os.path.join(root, ".agent-runs", "codex", name, "metadata.json")
    with open(path, "w", encoding="ascii") as handle:
        json.dump({"branch": branch, "worktree": worktree, "status": status}, handle)
PYEOF
  output=$(expect_success "$REPO/tools/agent/reconcile-report.sh" -)
  assert_contains "$output" $'WORKTREE\tEMPTY_STALE\tmatched\tagent/matched'
  assert_contains "$output" $'SESSION\tMATCHED_SESSION\tcodex/matched\tagent/matched'
  assert_contains "$output" $'SESSION\tSTALE_SESSION\tcodex/stale\tagent/stale-session'
  assert_contains "$output" $'SESSION\tORPHAN_SESSION\tcodex/orphan\tagent/missing-session\tRUNNING'
  assert_contains "$output" $'SESSION\tORPHAN_SESSION\tpi-impl/legacy\t-\t-'
  assert_not_contains "$output" "$REPO"
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

test_production_wrappers_are_executable
test_check_failure_runs_once
test_remote_validation_is_hermetic_and_fail_closed
test_remote_validation_runs_focused_check
test_remote_validation_disable_privilege_and_timeout_guards
test_remote_validation_rejects_tracked_secrets
test_pi_arguments_and_model_override
test_codex_arguments_and_dirty_main
test_codex_resume_and_deadline
test_codex_missing_session_id_fails
test_codex_resume_session_mismatch_fails
test_codex_wrapper_signal_updates_metadata
test_deadline_process_group_cleanup
test_codex_diverged_master_refusal
test_pi_dirty_rejection
test_pi_initial_dirty_refusal
test_pi_head_change_rejection
test_pi_deadline
test_review_next_action
test_review_harness_policy_selection
test_review_stale_branch_refusal
test_review_remote_staleness_refusal
test_review_master_movement_refusal
test_merged_clean_status_is_not_attention
test_squash_integrated_statuses_are_evidence_backed
test_reconciliation_report_links_sessions_by_metadata
test_attention_statuses_fail
test_uncommitted_work_refusal
test_conflict_refusal
test_final_gate_preserves_worktree
echo 'harness fail-closed tests: ok'
