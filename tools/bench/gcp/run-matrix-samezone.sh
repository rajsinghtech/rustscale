#!/usr/bin/env bash
# Compatibility entry point for the historical same-zone matrix command.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
for arg in "$@"; do
  [[ "$arg" == --topology || "$arg" == --topology=* ]] && exec "$SCRIPT_DIR/run-matrix.sh" "$@"
done
exec "$SCRIPT_DIR/run-matrix.sh" "$@" --topology same-zone
