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
# GCP_MACHINE is an input to immutable provenance, so supported overrides must
# also pass the command/provenance self-tests before any paid VM work starts.
run env GCP_MACHINE=n2-standard-4 tools/bench/gcp/run-config.sh --self-test
run env GCP_MACHINE=n2-standard-4 tools/bench/gcp/run-matrix.sh --self-test
# Startup self-tests must be independent of the externally selected Linux UDP
# experiment mode; these are all valid provenance/runtime combinations.
for mode in '0 0 0' '1 0 1' '1 1 0'; do
  read -r batch gro gso <<<"$mode"
  run env RS_LINUX_UDP_BATCH="$batch" RS_LINUX_UDP_GRO="$gro" RS_LINUX_UDP_GSO="$gso" tools/bench/gcp/run-config.sh --self-test
  run env RS_LINUX_UDP_BATCH="$batch" RS_LINUX_UDP_GRO="$gro" RS_LINUX_UDP_GSO="$gso" tools/bench/gcp/run-matrix.sh --self-test
done
run python3 tools/bench/gcp/test-manifest.py
run env MATRIX_SKIP_COLLECT=1 MATRIX_RESULTS_DIR="$tmp/focused" tools/bench/gcp/run-matrix.sh --dry-run
run python3 - "$tmp/focused" <<'PYEOF'
import json, pathlib, sys
root = next(pathlib.Path(sys.argv[1]).glob("gcp-*/matrix.json")).parent
m = json.load(open(root / "matrix.json"))
assert (m["topologies"], m["paths"], m["configs"]) == (
    ["same-zone"], ["direct"], ["rs-tun", "ts-tun"])
assert len(m["topologies"]) * len(m["paths"]) * len(m["configs"]) == 2
assert m["schema_version"] == 2 and root.name == m["run"]["id"]
assert m["run"]["cloud"]["requested_machine_type"] == "n1-standard-4"
assert m["run"]["runtime"] == {"rs_tun_inbound_pipeline": False, "rs_tun_outbound_send_pipeline": False, "linux_udp_batch": True, "linux_udp_gro": True, "linux_udp_gso": True}
for cell in (root / "same-zone" / "direct").glob("*.json"):
    r = json.load(open(cell))
    assert r["schema_version"] == 3 and r["run"] == m["run"] and r["observed"]["resolved_image"] == "dry-run"
PYEOF
run env GCP_MACHINE=n2-standard-4 MATRIX_SKIP_COLLECT=1 MATRIX_RESULTS_DIR="$tmp/machine-n2" tools/bench/gcp/run-matrix.sh --dry-run --config rs-tun
run python3 - "$tmp/machine-n2" <<'PYEOF'
import json, pathlib, sys
root = next(pathlib.Path(sys.argv[1]).glob("gcp-*/matrix.json")).parent
manifest = json.load(open(root / "matrix.json"))
assert manifest["run"]["cloud"]["requested_machine_type"] == "n2-standard-4"
# The cell result is emitted only after run-config preflights this selected
# observed sidecar against the requested machine. Dry-run metadata remains a
# deliberate sentinel, so it must not invent endpoint hardware facts.
observed = json.load(open(root / "metadata/same-zone/rs-tun-observed.json"))
assert set(observed.values()) == {"dry-run"}
cell = json.load(open(root / "same-zone/direct/rs-tun.json"))
assert cell["run"] == manifest["run"] and cell["observed"] == observed
PYEOF
check_matrix_runtime_mode() {
  local batch="$1" gro="$2" gso="$3" name="$4"
  run env RS_LINUX_UDP_BATCH="$batch" RS_LINUX_UDP_GRO="$gro" RS_LINUX_UDP_GSO="$gso" MATRIX_SKIP_COLLECT=1 MATRIX_RESULTS_DIR="$tmp/$name" tools/bench/gcp/run-matrix.sh --dry-run --config rs-tun
  run python3 - "$tmp/$name" "$batch" "$gro" "$gso" <<'PYEOF'
import json, pathlib, sys
root = next(pathlib.Path(sys.argv[1]).glob("gcp-*/matrix.json")).parent
runtime = json.load(open(root / "matrix.json"))["run"]["runtime"]
assert runtime["linux_udp_batch"] is (sys.argv[2] == "1")
assert runtime["linux_udp_gro"] is (sys.argv[3] == "1")
assert runtime["linux_udp_gso"] is (sys.argv[4] == "1")
PYEOF
}
check_matrix_runtime_mode 0 0 0 scalar
check_matrix_runtime_mode 1 0 1 plain
check_matrix_runtime_mode 1 1 0 gso-off
unset RS_LINUX_UDP_GSO
run env RS_LINUX_UDP_BATCH=0 RS_LINUX_UDP_GRO=0 MATRIX_SKIP_COLLECT=1 MATRIX_RESULTS_DIR="$tmp/scalar-legacy" tools/bench/gcp/run-matrix.sh --dry-run --config rs-tun
run python3 - "$tmp/scalar-legacy" <<'PYEOF'
import json, pathlib, sys
root = next(pathlib.Path(sys.argv[1]).glob("gcp-*/matrix.json")).parent
runtime = json.load(open(root / "matrix.json"))["run"]["runtime"]
assert runtime["linux_udp_batch"] is False
assert runtime["linux_udp_gro"] is False
assert runtime["linux_udp_gso"] is False
PYEOF
run env RS_TUN_INBOUND_PIPELINE=1 MATRIX_SKIP_COLLECT=1 MATRIX_RESULTS_DIR="$tmp/pipeline-on" tools/bench/gcp/run-matrix.sh --dry-run --config rs-tun
run python3 - "$tmp/pipeline-on" <<'PYEOF'
import json, pathlib, sys
root = next(pathlib.Path(sys.argv[1]).glob("gcp-*/matrix.json")).parent
m = json.load(open(root / "matrix.json"))
r = json.load(open(root / "same-zone/direct/rs-tun.json"))
assert m["run"]["runtime"] == {"rs_tun_inbound_pipeline": True, "rs_tun_outbound_send_pipeline": False, "linux_udp_batch": True, "linux_udp_gro": True, "linux_udp_gso": True}
assert r["run"] == m["run"]
PYEOF
expect_status 2 env RS_TUN_INBOUND_PIPELINE=invalid tools/bench/gcp/run-matrix.sh --dry-run
expect_status 2 env RS_TUN_INBOUND_PIPELINE=invalid tools/bench/gcp/run-config.sh --self-test
expect_status 2 env RS_TUN_INBOUND_PIPELINE= tools/bench/gcp/run-matrix.sh --dry-run
run env RS_TUN_OUTBOUND_SEND_PIPELINE=1 MATRIX_SKIP_COLLECT=1 MATRIX_RESULTS_DIR="$tmp/outbound-pipeline-on" tools/bench/gcp/run-matrix.sh --dry-run --config rs-tun
run python3 - "$tmp/outbound-pipeline-on" <<'PYEOF'
import json, pathlib, sys
root = next(pathlib.Path(sys.argv[1]).glob("gcp-*/matrix.json")).parent
assert json.load(open(root / "matrix.json"))["run"]["runtime"]["rs_tun_outbound_send_pipeline"] is True
PYEOF
expect_status 2 env RS_TUN_OUTBOUND_SEND_PIPELINE=invalid tools/bench/gcp/run-matrix.sh --dry-run
expect_status 2 env RS_TUN_OUTBOUND_SEND_PIPELINE= tools/bench/gcp/run-config.sh --self-test
expect_status 2 env RS_LINUX_UDP_BATCH=invalid tools/bench/gcp/run-matrix.sh --dry-run
expect_status 2 env RS_LINUX_UDP_GRO=invalid tools/bench/gcp/run-config.sh --self-test
expect_status 2 env RS_LINUX_UDP_GSO=invalid tools/bench/gcp/run-matrix.sh --dry-run
expect_status 2 env RS_LINUX_UDP_GSO=invalid tools/bench/gcp/run-config.sh --self-test
expect_status 2 env RS_LINUX_UDP_BATCH=0 RS_LINUX_UDP_GSO=1 tools/bench/gcp/run-matrix.sh --dry-run
expect_status 2 env RS_LINUX_UDP_BATCH=0 RS_LINUX_UDP_GSO=1 tools/bench/gcp/run-config.sh --self-test
expect_status 2 env RS_LINUX_UDP_BATCH=0 RS_LINUX_UDP_GRO=1 tools/bench/gcp/run-matrix.sh --dry-run
expect_status 2 env RS_LINUX_UDP_BATCH=0 RS_LINUX_UDP_GRO=1 tools/bench/gcp/run-config.sh --self-test
run env MATRIX_SKIP_COLLECT=1 MATRIX_RESULTS_DIR="$tmp/full" tools/bench/gcp/run-matrix.sh --full --dry-run
run python3 - "$tmp/full" <<'PYEOF'
import json, pathlib, sys
m = json.load(open(next(pathlib.Path(sys.argv[1]).glob("gcp-*/matrix.json"))))
assert len(m["topologies"]) * len(m["paths"]) * len(m["configs"]) == 16
assert m["schema_version"] == 2
PYEOF
run env MATRIX_SKIP_COLLECT=1 MATRIX_RESULTS_DIR="$tmp/focused-filter" tools/bench/gcp/run-matrix.sh --dry-run --topology cross-region --path derp --config rs-userspace
run env MATRIX_SKIP_COLLECT=1 MATRIX_RESULTS_DIR="$tmp/full-filter" tools/bench/gcp/run-matrix.sh --full --dry-run --topology same-zone --path direct --config ts-tun
expect_status 2 tools/bench/gcp/run-matrix.sh --dry-run --config rs-tun,rs-tun
run python3 - "$tmp/focused-filter" "$tmp/full-filter" <<'PYEOF'
import json, pathlib, sys
focused, full = (json.load(open(next(pathlib.Path(path).glob("gcp-*/matrix.json")))) for path in sys.argv[1:])
assert (focused["topologies"], focused["paths"], focused["configs"]) == (
    ["cross-region"], ["derp"], ["rs-userspace"])
assert (full["topologies"], full["paths"], full["configs"]) == (
    ["same-zone"], ["direct"], ["ts-tun"])
PYEOF
run git diff --check
echo "bench harness checks: OK"
