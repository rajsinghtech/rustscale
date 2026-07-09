#!/usr/bin/env bash
# tools/gen-header.sh — regenerate include/rustscale.h via cbindgen.
#
# This runs `cargo build -p rustscale-ffi` which triggers build.rs to
# invoke cbindgen and write the header into include/rustscale.h.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build -p rustscale-ffi 2>&1 | grep -v "^warning" || true

if [ ! -f include/rustscale.h ]; then
  echo "include/rustscale.h was not generated" >&2
  exit 1
fi

echo "generated include/rustscale.h ($(wc -l < include/rustscale.h) lines)"
