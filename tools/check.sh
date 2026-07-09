#!/usr/bin/env bash
# tools/check.sh — the rustscale acceptance gate. Matches the CI gate
# (.github/workflows/ci.yml) so a local "ok" means CI-green:
#   cargo build  --workspace --all-targets
#   cargo test   --workspace
#   cargo clippy --workspace --all-targets -- -D warnings
#   cargo fmt    --all --check
# Silent on success. On failure prints only the first ~50 lines of the failing
# step, so build agents don't dump full compiler output into their context.
#
# Usage:
#   tools/check.sh              # full workspace gate (build+test+clippy+fmt)
#   tools/check.sh <crate>      # single crate, e.g. tools/check.sh rustscale-key
#   tools/check.sh --no-test    # skip tests
#   tools/check.sh --no-clippy  # skip clippy
#   tools/check.sh --no-fmt     # skip cargo fmt --check
set -euo pipefail

CRATE=""
RUN_TEST=1
RUN_CLIPPY=1
RUN_FMT=1
for a in "$@"; do
  case "$a" in
    --no-test)   RUN_TEST=0 ;;
    --no-clippy) RUN_CLIPPY=0 ;;
    --no-fmt)    RUN_FMT=0 ;;
    --*) echo "unknown flag: $a" >&2; exit 2 ;;
    *) CRATE="$a" ;;
  esac
done

if [ -n "$CRATE" ]; then
  PKG=(-p "$CRATE"); WS=()
else
  PKG=(); WS=(--workspace)
fi

# Capture the command's output once, then show filtered errors/warnings (fmt's
# "Diff in" lines included) or fall back to the raw head — never re-run a slow
# build twice, and never dump full output into the agent's context.
fail() {
  local label="$1"; shift
  echo "=== $label FAILED ===" >&2
  local out hits
  out="$("$@" 2>&1 || true)"
  hits="$(printf '%s\n' "$out" | grep -E '^(error|warning|Diff in )' | head -50 || true)"
  if [ -n "$hits" ]; then
    printf '%s\n' "$hits" >&2
  else
    printf '%s\n' "$out" | head -50 >&2
  fi
  echo "(run '$*' to see full output)" >&2
  exit 1
}

cargo build "${PKG[@]}" "${WS[@]}" --all-targets >/dev/null 2>&1 \
  || fail "build" cargo build "${PKG[@]}" "${WS[@]}" --all-targets

if [ "$RUN_TEST" = 1 ]; then
  cargo test "${PKG[@]}" "${WS[@]}" >/dev/null 2>&1 || fail "test" cargo test "${PKG[@]}" "${WS[@]}"
fi

if [ "$RUN_CLIPPY" = 1 ]; then
  # -D warnings matches CI: any clippy warning fails the gate.
  cargo clippy "${PKG[@]}" "${WS[@]}" --all-targets -- -D warnings >/dev/null 2>&1 \
    || fail "clippy" cargo clippy "${PKG[@]}" "${WS[@]}" --all-targets -- -D warnings
fi

# fmt is workspace-wide (cargo fmt has no -p); always --all --check like CI.
if [ "$RUN_FMT" = 1 ]; then
  cargo fmt --all --check >/dev/null 2>&1 || fail "fmt" cargo fmt --all --check
fi

echo "ok"
