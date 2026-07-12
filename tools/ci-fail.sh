#!/usr/bin/env bash
# tools/ci-fail.sh — extract the first real error from a failed GitHub Actions run.
# Strips ANSI codes, skips noise, prints the compiler error with file:line context.
# Replaces 47+ ad-hoc `gh run view --log-failed | grep | sed | awk` pipelines.
#
# Usage:
#   tools/ci-fail.sh                 # latest failed run
#   tools/ci-fail.sh <run-id>        # specific run
#   tools/ci-fail.sh <run-id> macos  # filter by job name substring
set -euo pipefail

RUN="${1:-}"
JOB_FILTER="${2:-}"

if [[ -z "$RUN" ]]; then
  RUN=$(gh run list --limit 10 --json databaseId,conclusion -q '[.[] | select(.conclusion=="failure")][0].databaseId' 2>/dev/null) || true
  [[ -n "$RUN" ]] || { echo "no failed runs found" >&2; exit 1; }
fi

echo "=== Run $RUN ===" >&2

RAW=$(gh run view "$RUN" --log-failed 2>/dev/null || true)
[[ -n "$RAW" ]] || { echo "could not fetch logs for run $RUN" >&2; exit 1; }

# Strip ANSI escape codes
CLEAN=$(printf '%s' "$RAW" | sed $'s/\x1b\[[0-9;]*m//g')

# If job filter specified, narrow to that job
if [[ -n "$JOB_FILTER" ]]; then
  CLEAN=$(printf '%s' "$CLEAN" | grep -i "$JOB_FILTER" || true)
fi

# Extract: Rust compiler errors (error[E0xxx]), panics, test failures, or generic errors
printf '%s' "$CLEAN" | grep -E '^error(\[|\[E[0-9]|:)' | head -20
echo "---" >&2
printf '%s' "$CLEAN" | grep -E '^error\[' -A5 | head -40
echo "---" >&2
printf '%s' "$CLEAN" | grep -E '(panic|FAILED|test result:.*failed|assertion|Error:)' | head -10
