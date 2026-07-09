#!/usr/bin/env bash
# tools/ffi-smoke.sh — compile the C echo example against the built librustscale.
#
# Usage:
#   tools/ffi-smoke.sh              # compile-only (no creds needed)
#   tools/ffi-smoke.sh --run        # compile + run (requires TS_E2E_* env)
#
# CI runs compile-only mode to verify the C ABI is usable from C without
# needing tailnet credentials.
set -euo pipefail
cd "$(dirname "$0")/.."

RUN=0
for a in "$@"; do
  case "$a" in
    --run) RUN=1 ;;
    *) echo "unknown flag: $a" >&2; exit 2 ;;
  esac
done

# Build the dylib first (silent).
cargo build -p rustscale-ffi >/dev/null 2>&1 || {
  echo "cargo build -p rustscale-ffi failed" >&2
  exit 1
}

DYLIB="target/debug/librustscale.dylib"
if [[ ! -f "$DYLIB" ]]; then
  # Linux
  DYLIB="target/debug/librustscale.so"
fi
if [[ ! -f "$DYLIB" ]]; then
  echo "dylib not found (expected .dylib or .so)" >&2
  exit 1
fi

OUT="target/debug/ffi-echo"
echo "compiling examples/c/echo.c → $OUT"
cc -Wall -Wextra -o "$OUT" examples/c/echo.c \
  -I include \
  -L target/debug \
  -lrustscale \
  -Wl,-rpath,"$(pwd)/target/debug"

echo "compile OK"

if [ "$RUN" = 1 ]; then
  if [ -z "${TS_E2E_AUTHKEY:-}" ]; then
    echo "TS_E2E_AUTHKEY not set; cannot run live" >&2
    exit 2
  fi
  echo "running live e2e..."
  "$OUT"
else
  echo "(compile-only mode; pass --run with TS_E2E_* env to run live)"
fi
