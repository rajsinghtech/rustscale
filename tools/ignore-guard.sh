#!/usr/bin/env bash
# tools/ignore-guard.sh — L6: prevent #[ignore] count from drifting upward.
#
# On master (IGNORE_GUARD_MODE=baseline): writes the current #[ignore] count
# to .github/ignore-baseline.txt.
#
# On PRs (IGNORE_GUARD_MODE=check): compares the current count against the
# baseline. If the count increased, prints the diff and exits 1.
#
# See docs/regression-strategy.md L6.
set -euo pipefail

cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

BASELINE_FILE=".github/ignore-baseline.txt"

# Count #[ignore] attributes in crates/ (lines starting with #[ignore,
# not comments that mention #[ignore]).
count_ignores() {
  rg '^\s*#\[(ignore|ignore\s*=)' crates/ -c 2>/dev/null | awk -F: '{s+=$2} END{print s+0}'
}

MODE="${IGNORE_GUARD_MODE:-auto}"

# Auto-detect mode from GitHub Actions environment.
if [ "$MODE" = "auto" ]; then
  if [ "${GITHUB_REF:-}" = "refs/heads/master" ]; then
    MODE="baseline"
  else
    MODE="check"
  fi
fi

CURRENT=$(count_ignores)

if [ "$MODE" = "baseline" ]; then
  echo "$CURRENT" > "$BASELINE_FILE"
  echo "#[ignore] baseline set to $CURRENT (written to $BASELINE_FILE)"
  exit 0
fi

# Check mode: compare against baseline.
if [ ! -f "$BASELINE_FILE" ]; then
  echo "WARNING: $BASELINE_FILE not found — run with IGNORE_GUARD_MODE=baseline on master to create it."
  echo "Current #[ignore] count: $CURRENT"
  exit 0
fi

BASELINE=$(cat "$BASELINE_FILE" | tr -d '[:space:]')

if [ "$CURRENT" -gt "$BASELINE" ]; then
  echo "#[ignore] count increased ($BASELINE -> $CURRENT). Add a Regression-Exception: trailer to the commit or fix the test. See docs/regression-strategy.md L6."
  exit 1
fi

echo "#[ignore] count: $CURRENT (baseline: $BASELINE) — OK"
