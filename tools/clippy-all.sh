#!/usr/bin/env bash
# tools/clippy-all.sh — show ALL clippy warnings in one pass, grouped by type.
# Prevents the anti-pattern of running clippy 6+ times, each grepping for a
# different warning. Run this once, fix everything, re-run.
#
# Usage:
#   tools/clippy-all.sh              # full workspace
#   tools/clippy-all.sh <crate>      # single crate, e.g. tools/clippy-all.sh rustscale-wg
#
# Output: unique warning lines (deduplicated), sorted. Silent if clean.
set -euo pipefail

CRATE=""
for a in "$@"; do
  case "$a" in
    --*) echo "unknown flag: $a" >&2; exit 2 ;;
    *) CRATE="$a" ;;
  esac
done

if [ -n "$CRATE" ]; then
  PKG=(-p "$CRATE"); WS=()
else
  PKG=(); WS=(--workspace)
fi

# Run clippy once, capture all output, extract warning lines, deduplicate.
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

cargo clippy "${PKG[@]}" "${WS[@]}" --all-targets 2>&1 > "$TMP" || true

# Extract unique warning lines, strip ANSI, sort for stable output.
sed 's/\x1b\[[0-9;]*m//g' "$TMP" \
  | grep -E '^warning:' \
  | sort -u

# If there were errors, show those too.
if grep -qE '^error' "$TMP"; then
  echo "=== ERRORS ==="
  sed 's/\x1b\[[0-9;]*m//g' "$TMP" | grep -E '^error' | head -30
fi

# Summary count.
COUNT=$(sed 's/\x1b\[[0-9;]*m//g' "$TMP" | grep -cE '^warning:' || true)
if [ "$COUNT" -eq 0 ]; then
  echo "clippy: clean"
else
  echo "clippy: $COUNT warning(s) (deduplicated)"
fi
