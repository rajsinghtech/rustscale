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
# CAP at 50 unique lines — a crate can emit hundreds of unique warnings and
# dumping them all (49K chars seen in phase 7) wastes the agent's context.
CAP=50
WARNINGS=$(sed 's/\x1b\[[0-9;]*m//g' "$TMP" \
  | grep -E '^warning:' \
  | sort -u)
TOTAL=$(printf '%s\n' "$WARNINGS" | grep -c . || true)
printf '%s\n' "$WARNINGS" | head -n "$CAP"

# If there were errors, show those too.
if grep -qE '^error' "$TMP"; then
  echo "=== ERRORS ==="
  sed 's/\x1b\[[0-9;]*m//g' "$TMP" | grep -E '^error' | head -30
fi

# Summary count (reflects the full unique set, not just what was printed).
if [ "$TOTAL" -eq 0 ]; then
  echo "clippy: clean"
else
  if [ "$TOTAL" -gt "$CAP" ]; then
    echo "clippy: $TOTAL unique warning(s) (showing first $CAP; run 'cargo clippy ${PKG[*]:-}${WS[*]:-} --all-targets' for the full list)"
  else
    echo "clippy: $TOTAL warning(s) (deduplicated)"
  fi
fi
