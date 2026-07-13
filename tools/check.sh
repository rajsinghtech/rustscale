#!/usr/bin/env bash
# tools/check.sh — the rustscale acceptance gate. Matches the CI gate
# (.github/workflows/ci.yml) so a local "ok" means CI-green:
#   cargo clippy --workspace --all-targets -- -D warnings  (type-checks + lints)
#   cargo test  --workspace                                  (builds + runs tests)
#   cargo fmt   --all --check
# Silent on success. On failure prints only the first ~50 lines of the failing
# step, so build agents don't dump full compiler output into their context.
#
# Clippy runs first (no separate build step — clippy already type-checks).
# Then cargo test builds its own test binaries.
#
# If sccache is installed, RUSTC_WRAPPER is set automatically for faster
# rebuilds across worktrees.
#
# Usage:
#   tools/check.sh              # full workspace gate (clippy+test+fmt)
#   tools/check.sh <crate>      # single crate, e.g. tools/check.sh rustscale-key
#   tools/check.sh --no-test    # skip tests
#   tools/check.sh --no-clippy  # skip clippy
#   tools/check.sh --no-fmt     # skip cargo fmt --check
#   tools/check.sh --check      # use `cargo check` (type-check only, ~2x faster)
#                             # instead of full clippy+lint
set -euo pipefail

# sccache: if installed, use it — no-op rebuilds are ~instant
if command -v sccache >/dev/null 2>&1; then
  export RUSTC_WRAPPER=sccache
fi

CRATE=""
RUN_TEST=1
RUN_CLIPPY=1
RUN_FMT=1
RUN_CHECK=0
for a in "$@"; do
  case "$a" in
    --no-test)   RUN_TEST=0 ;;
    --no-clippy) RUN_CLIPPY=0 ;;
    --no-fmt)    RUN_FMT=0 ;;
    --check|-c)  RUN_CHECK=1 ;;
    --*) echo "unknown flag: $a" >&2; exit 2 ;;
    *) CRATE="$a" ;;
  esac
done

if [ -n "$CRATE" ]; then
  PKG=(-p "$CRATE"); WS=()
else
  PKG=(); WS=(--workspace)
fi

# --- Failure excerpt helper ---
# For clippy/build steps: grep for error/warning lines.
# For the test step: grep for FAILED/panicked/failures: context (shows the
# actual failing test name and assertion) before falling back to head -50.
fail() {
  local label="$1"; shift
  echo "=== $label FAILED ===" >&2
  local out hits
  out="$("$@" 2>&1 || true)"
  if [[ "$label" == "test" ]]; then
    if printf '%s\n' "$out" | grep -q -E '(FAILED|panicked|failures:)'; then
      # Test failures — show the structured failures block from "failures:" to end.
      # This captures actual test failure messages instead of preceding "test ... ok" lines.
      printf '%s\n' "$out" | sed -n '/^failures:/,$ p' | head -120 >&2
    else
      # Compilation error (no test runner output) — show the start where errors live.
      printf '%s\n' "$out" | head -60 >&2
    fi
  else
    hits="$(printf '%s\n' "$out" | grep -E '^(error|warning|Diff in )' | head -50 || true)"
    if [ -n "$hits" ]; then
      printf '%s\n' "$hits" >&2
    else
      printf '%s\n' "$out" | head -50 >&2
    fi
  fi
  echo "(run '$*' to see full output)" >&2
  exit 1
}

# --- Step 1: clippy (type-checks AND lints — no separate build step) ---
# If --check is used, run `cargo check` instead (type-check only, faster).
if [ "$RUN_CLIPPY" = 1 ] && [ "$RUN_CHECK" = 0 ]; then
  cargo clippy "${PKG[@]}" "${WS[@]}" --all-targets -- -D warnings >/dev/null 2>&1 \
    || fail "clippy" cargo clippy "${PKG[@]}" "${WS[@]}" --all-targets -- -D warnings
elif [ "$RUN_CHECK" = 1 ]; then
  cargo check "${PKG[@]}" "${WS[@]}" --all-targets >/dev/null 2>&1 \
    || fail "check" cargo check "${PKG[@]}" "${WS[@]}" --all-targets
fi

# --- Step 2: tests (builds test binaries) ---
if [ "$RUN_TEST" = 1 ]; then
  cargo test "${PKG[@]}" "${WS[@]}" >/dev/null 2>&1 || fail "test" cargo test "${PKG[@]}" "${WS[@]}"
fi

# --- Step 3: formatting ---
if [ "$RUN_FMT" = 1 ]; then
  cargo fmt --all --check >/dev/null 2>&1 || fail "fmt" cargo fmt --all --check
fi

echo "ok"
