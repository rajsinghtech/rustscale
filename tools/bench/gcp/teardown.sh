#!/usr/bin/env bash
# tools/bench/gcp/teardown.sh — standalone VM + tailnet cleanup.
#
# Duplicated by the EXIT trap in run-matrix.sh, but exposed as a separate
# entry point so you can clean up after a killed run (or a run that leaked
# VMs because SKIP_VM_DELETE=1 was set).
#
# Usage:
#   tools/bench/gcp/teardown.sh SERVER_VM SERVER_ZONE CLIENT_VM CLIENT_ZONE
#
# Also deletes the tailnet recorded in .secrets/last-bench-tailnet.json
# (via bench_cleanup_tailnet from tools/bench/lib.sh).

set -euo pipefail

# shellcheck source=../../lib.sh
source "$(dirname "$0")/../lib.sh"
# shellcheck source=./lib.sh
source "$(dirname "$0")/lib.sh"

if [[ $# -lt 4 ]]; then
  echo "usage: $0 SERVER_VM SERVER_ZONE CLIENT_VM CLIENT_ZONE" >&2
  echo "       (VM names may be empty strings to skip VM deletion)" >&2
  exit 2
fi

SVM="$1"; SZONE="$2"; CVM="$3"; CZONE="$4"

if [[ -n "$SVM" ]]; then
  delete_vm "$SVM" "$SZONE" || true
fi
if [[ -n "$CVM" ]]; then
  delete_vm "$CVM" "$CZONE" || true
fi

bench_cleanup_tailnet || true
echo "[gcp] teardown complete"
