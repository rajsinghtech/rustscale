#!/usr/bin/env bash
# Credential-free validation for the GCP benchmark harness.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/rustscale-bench-check.XXXXXX")
log="$tmp/check.log"
trap 'rm -rf "$tmp"' EXIT

run() {
  if ! "$@" >>"$log" 2>&1; then
    cat "$log" >&2
    exit 1
  fi
}

expect_status() {
  local expected="$1" actual
  shift
  if "$@" >>"$log" 2>&1; then
    actual=0
  else
    actual=$?
  fi
  if (( actual != expected )); then
    cat "$log" >&2
    exit 1
  fi
}

cd "$ROOT"
run bash -n tools/bench/gcp/lib.sh tools/bench/gcp/run-config.sh tools/bench/gcp/run-matrix.sh tools/bench/check.sh
run tools/bench/gcp/run-config.sh --self-test
run tools/bench/gcp/run-matrix.sh --self-test
run python3 tools/bench/gcp/test-manifest.py
run env MATRIX_SKIP_COLLECT=1 MATRIX_RESULTS_DIR="$tmp/focused" tools/bench/gcp/run-matrix.sh --dry-run
run python3 - "$tmp/focused/matrix.json" <<'PYEOF'
import json, sys
m = json.load(open(sys.argv[1]))
assert (m["topologies"], m["paths"], m["configs"]) == (
    ["same-zone"], ["direct"], ["rs-tun", "ts-tun"])
assert len(m["topologies"]) * len(m["paths"]) * len(m["configs"]) == 2
PYEOF
run env MATRIX_SKIP_COLLECT=1 MATRIX_RESULTS_DIR="$tmp/full" tools/bench/gcp/run-matrix.sh --full --dry-run
run python3 - "$tmp/full/matrix.json" <<'PYEOF'
import json, sys
m = json.load(open(sys.argv[1]))
assert len(m["topologies"]) * len(m["paths"]) * len(m["configs"]) == 16
PYEOF
run env MATRIX_SKIP_COLLECT=1 MATRIX_RESULTS_DIR="$tmp/focused-filter" tools/bench/gcp/run-matrix.sh --dry-run --topology cross-region --path derp --config rs-userspace
run env MATRIX_SKIP_COLLECT=1 MATRIX_RESULTS_DIR="$tmp/full-filter" tools/bench/gcp/run-matrix.sh --full --dry-run --topology same-zone --path direct --config ts-tun
expect_status 2 tools/bench/gcp/run-matrix.sh --dry-run --config rs-tun,rs-tun
run python3 - "$tmp/focused-filter/matrix.json" "$tmp/full-filter/matrix.json" <<'PYEOF'
import json, sys
focused, full = (json.load(open(path)) for path in sys.argv[1:])
assert (focused["topologies"], focused["paths"], focused["configs"]) == (
    ["cross-region"], ["derp"], ["rs-userspace"])
assert (full["topologies"], full["paths"], full["configs"]) == (
    ["same-zone"], ["direct"], ["ts-tun"])
PYEOF
run git diff --check
echo "bench harness checks: OK"
