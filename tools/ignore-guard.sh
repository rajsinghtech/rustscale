#!/usr/bin/env bash
# tools/ignore-guard.sh — L6: prevent #[ignore] count from drifting upward.
#
# In check mode, compares the current count against the tracked baseline. In
# baseline mode, explicitly refreshes that file after maintainers review newly
# ignored tests.
set -euo pipefail

cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

BASELINE_FILE=".github/ignore-baseline.txt"

# Count #[ignore] attributes in crates/ (lines starting with #[ignore,
# not comments that mention #[ignore]).
count_ignores() {
  if command -v rg >/dev/null 2>&1; then
    rg '^\s*#\[(ignore|ignore\s*=)' crates/ -c 2>/dev/null \
      | awk -F: '{s+=$2} END{print s+0}'
  else
    grep -R -h -E '^[[:space:]]*#\[(ignore|ignore[[:space:]]*=)' \
      --include='*.rs' crates/ 2>/dev/null | awk 'END{print NR+0}'
  fi
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
  echo "#[ignore] count increased ($BASELINE -> $CURRENT). Re-enable the test or update the reviewed baseline."
  exit 1
fi

echo "#[ignore] count: $CURRENT (baseline: $BASELINE) — OK"
