#!/usr/bin/env bash
# Quiet validation for agent-harness and policy-only changes.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd -P)"
TMP="$(mktemp "${TMPDIR:-/tmp}/rustscale-agent-check.XXXXXX")"
trap 'rm -f "$TMP"' EXIT

run() {
  if ! "$@" >"$TMP" 2>&1; then
    echo "=== agent harness check failed: $* ===" >&2
    head -120 "$TMP" >&2
    exit 1
  fi
}

cd "$ROOT"
run bash -n tools/check.sh tools/agent/*.sh
run bash tools/agent/tests/harness-fail-closed.sh
run git diff --check
if command -v shellcheck >/dev/null 2>&1; then
  run shellcheck tools/check.sh tools/agent/*.sh tools/agent/tests/harness-fail-closed.sh
fi
echo "agent harness checks: OK"
