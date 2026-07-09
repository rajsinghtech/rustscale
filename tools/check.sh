#!/usr/bin/env bash
# tools/check.sh — run the rustscale acceptance gate: build + test + clippy.
# Silent on success. On failure prints only the first ~50 lines of the failing
# step, so build agents don't dump full compiler output into their context.
#
# Usage:
#   tools/check.sh              # full workspace gate (build+test+clippy)
#   tools/check.sh <crate>      # single crate, e.g. tools/check.sh rustscale-key
#   tools/check.sh --no-test    # skip tests (compile-only sanity check)
#   tools/check.sh --no-clippy  # skip clippy
set -euo pipefail

CRATE=""
RUN_TEST=1
RUN_CLIPPY=1
for a in "$@"; do
  case "$a" in
    --no-test)  RUN_TEST=0 ;;
    --no-clippy) RUN_CLIPPY=0 ;;
    --*) echo "unknown flag: $a" >&2; exit 2 ;;
    *) CRATE="$a" ;;
  esac
done

if [ -n "$CRATE" ]; then
  PKG=(-p "$CRATE"); WS=()
else
  PKG=(); WS=(--workspace)
fi

fail() {
  local label="$1"; shift
  echo "=== $label FAILED ===" >&2
  "$@" 2>&1 | grep -E '^(error|warning)' | head -50 >&2 || true
  echo "(run '$*' to see full output)" >&2
  exit 1
}

cargo build "${PKG[@]}" "${WS[@]}" >/dev/null 2>&1 || fail "build" cargo build "${PKG[@]}" "${WS[@]}"

if [ "$RUN_TEST" = 1 ]; then
  cargo test "${PKG[@]}" "${WS[@]}" >/dev/null 2>&1 || fail "test" cargo test "${PKG[@]}" "${WS[@]}"
fi

if [ "$RUN_CLIPPY" = 1 ]; then
  cargo clippy "${PKG[@]}" "${WS[@]}" --all-targets >/dev/null 2>&1 \
    || fail "clippy" cargo clippy "${PKG[@]}" "${WS[@]}" --all-targets
fi

echo "ok"
