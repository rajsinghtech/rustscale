#!/usr/bin/env bash
# tools/bench/gcp/run-matrix.sh — main orchestrator for the GCP bench matrix.
#
# Runs the full 2x2x4 = 16-run matrix (topology × path × config) on dedicated
# GCP VMs, writing per-run JSON + a combined summary.json + a standalone HTML
# dashboard into bench-results/gcp-<stamp>/.
#
# Reuses tools/bench/lib.sh for ephemeral tailnet provisioning.
#
# Usage:
#   tools/bench/gcp/run-matrix.sh            # full run
#   tools/bench/gcp/run-matrix.sh --dry-run  # validate args, no gcloud/API
#
# Environment:
#   TS_ORG_TOKEN or TS_ORG_CLIENT_ID/SECRET  — tailnet creds (see tools/bench/lib.sh)
#   GCP_PROJECT                              — auto-detected from gcloud config
#   GCP_DRY_RUN                              — set by --dry-run; propagated to lib.sh
#   SKIP_VM_DELETE=1                         — keep VMs at the end (debugging)

set -euo pipefail

# Resolve repo root (this file is at tools/bench/gcp/run-matrix.sh).
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$REPO_ROOT"

# shellcheck source=../lib.sh
source tools/bench/lib.sh
# shellcheck source=./lib.sh
source tools/bench/gcp/lib.sh
# shellcheck source=./footprint.sh
source tools/bench/gcp/footprint.sh

MATRIX_SELF_TEST=0
if [[ "${1:-}" == "--self-test" ]]; then
  MATRIX_SELF_TEST=1
  shift
fi

# Must match the distinct status returned by run-config.sh when rustscaled or
# tailscale0 remains after its forced cleanup.  This is unsafe to hand off.
FATAL_HANDOFF_STATUS=86

rust_build_command() {
  local config candidate existing seen
  local -a requested=() packages=()

  for config in "${CONFIGS[@]}"; do
    case "$config" in
      rs-userspace) requested=(rustscale-bench) ;;
      rs-tun) requested=(rustscale-cli rustscale-rustscaled) ;;
      *) continue ;;
    esac
    for candidate in "${requested[@]}"; do
      seen=0
      for existing in "${packages[@]}"; do
        [[ "$candidate" == "$existing" ]] && seen=1
      done
      (( seen )) || packages+=("$candidate")
    done
  done

  (( ${#packages[@]} )) || return 0
  printf '%s' 'export RUSTUP_HOME=/opt/rust CARGO_HOME=/opt/rust/cargo; cd /opt/rustscale && cargo build --release'
  for package in "${packages[@]}"; do
    printf ' -p %s' "$package"
  done
}

matrix_command_shape_self_test() {
  local actual
  CONFIGS=(rs-userspace)
  actual=$(rust_build_command)
  [[ "$actual" == 'export RUSTUP_HOME=/opt/rust CARGO_HOME=/opt/rust/cargo; cd /opt/rustscale && cargo build --release -p rustscale-bench' ]] || return 1
  CONFIGS=(rs-tun)
  actual=$(rust_build_command)
  [[ "$actual" == 'export RUSTUP_HOME=/opt/rust CARGO_HOME=/opt/rust/cargo; cd /opt/rustscale && cargo build --release -p rustscale-cli -p rustscale-rustscaled' ]] || return 1
  CONFIGS=(rs-userspace rs-tun)
  actual=$(rust_build_command)
  [[ "$actual" == 'export RUSTUP_HOME=/opt/rust CARGO_HOME=/opt/rust/cargo; cd /opt/rustscale && cargo build --release -p rustscale-bench -p rustscale-cli -p rustscale-rustscaled' ]] || return 1
  CONFIGS=(ts-userspace ts-tun)
  [[ -z "$(rust_build_command)" ]] || return 1
  CONFIGS=(rs-userspace rs-tun ts-userspace ts-tun)
  actual=$(rust_build_command)
  [[ "$actual" == 'export RUSTUP_HOME=/opt/rust CARGO_HOME=/opt/rust/cargo; cd /opt/rustscale && cargo build --release -p rustscale-bench -p rustscale-cli -p rustscale-rustscaled' ]] || return 1
  [[ "$actual" != *'-p rustscaled'* ]] || return 1
}

wait_for_remote_builds() {
  local server_pid="$1" client_pid="$2" status=0

  if ! wait "$server_pid"; then
    echo "[gcp] server remote build failed" >&2
    status=1
  fi
  if ! wait "$client_pid"; then
    echo "[gcp] client remote build failed" >&2
    status=1
  fi
  return "$status"
}

matrix_remote_build_aggregation_self_test() {
  local first_pid second_pid

  (exit 0) & first_pid=$!
  (exit 0) & second_pid=$!
  wait_for_remote_builds "$first_pid" "$second_pid" || return 1

  (exit 0) & first_pid=$!
  (exit 1) & second_pid=$!
  if wait_for_remote_builds "$first_pid" "$second_pid" 2>/dev/null; then
    return 1
  fi
}

matrix_run_config_with_policy() {
  local config="$1" success_suffix="$2" status
  shift 2

  if "$@"; then
    echo "[gcp] $config: OK$success_suffix"
  else
    status=$?
    if (( status == FATAL_HANDOFF_STATUS )); then
      echo "[gcp] FATAL: $config left an unsafe TUN handoff; aborting matrix" >&2
      exit "$FATAL_HANDOFF_STATUS"
    fi
    echo "[gcp] $config: FAILED (continuing)" >&2
  fi
}

matrix_config_failure_policy_self_test() {
  local output status

  matrix_test_success() { return 0; }
  matrix_test_ordinary_failure() { return 1; }
  matrix_test_fatal_handoff() { return "$FATAL_HANDOFF_STATUS"; }
  matrix_test_config_flow() {
    local config="$1"
    matrix_run_config_with_policy "$config" "" "${@:2}"
    echo "sentinel: $config"
  }

  output=$(matrix_test_config_flow success matrix_test_success 2>&1) || return 1
  [[ "$output" == $'[gcp] success: OK\nsentinel: success' ]] || return 1

  output=$(matrix_test_config_flow ordinary matrix_test_ordinary_failure 2>&1) || return 1
  [[ "$output" == $'[gcp] ordinary: FAILED (continuing)\nsentinel: ordinary' ]] || return 1

  if output=$(matrix_test_config_flow fatal matrix_test_fatal_handoff 2>&1); then
    return 1
  else
    status=$?
  fi
  (( status == FATAL_HANDOFF_STATUS )) || return 1
  [[ "$output" == '[gcp] FATAL: fatal left an unsafe TUN handoff; aborting matrix' ]] || return 1
  unset -f matrix_test_success matrix_test_ordinary_failure \
    matrix_test_fatal_handoff matrix_test_config_flow
}

matrix_profile_self_test() {
  local config
  local -a calls=()
  REPEAT=4
  PROFILE=1
  matrix_test_record_run_config() { calls+=("$1|${*:4}"); }

  # Exercise the same selected-cell loop used by the matrix, with its
  # run-config policy call mocked locally. Both cells must receive the same
  # repeat, while only rustscale receives the rs-tun-only profiling flag.
  for config in rs-tun ts-tun; do
    matrix_run_config_cell "$config" s c sz cz key dir host client matrix_test_record_run_config
  done
  unset -f matrix_test_record_run_config

  [[ ${#calls[@]} -eq 2 ]] || return 1
  [[ "${calls[0]}" == 'rs-tun|rs-tun s c sz cz key dir host client --repeat 4 --profile' ]] || return 1
  [[ "${calls[1]}" == 'ts-tun|ts-tun s c sz cz key dir host client --repeat 4' ]] || return 1
}

# Build the directly invocable run-config command shape used by each cell.
# Args: CONFIG SERVER_VM CLIENT_VM SERVER_ZONE CLIENT_ZONE AUTHKEY RESULTS_DIR
#       SERVER_HOSTNAME CLIENT_HOSTNAME
matrix_build_run_config_args() {
  local config="$1"
  RUN_CONFIG_ARGS=(
    "$config" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" --repeat "$REPEAT"
  )
  if [[ "$config" == rs-tun && $PROFILE -eq 1 ]]; then
    RUN_CONFIG_ARGS+=(--profile)
  fi
}

# Run one already-selected matrix cell. Keeping this invocation shape in a
# helper lets the local self-test exercise the same loop without GCP access.
matrix_run_config_cell() {
  local config="$1" server_vm="$2" client_vm="$3" server_zone="$4" client_zone="$5"
  local authkey="$6" results_dir="$7" server_hostname="$8" client_hostname="$9"
  local policy_fn="${10:-matrix_run_config_with_policy}"

  matrix_build_run_config_args "$config" "$server_vm" "$client_vm" "$server_zone" "$client_zone" \
    "$authkey" "$results_dir" "$server_hostname" "$client_hostname"
  "$policy_fn" "$config" " -> $results_dir/$config.json" \
    tools/bench/gcp/run-config.sh "${RUN_CONFIG_ARGS[@]}"
}

# Parse command-line options without contacting GCP.  Keeping this separate
# makes the strict option contract directly self-testable.
matrix_parse_args() {
  DRY_RUN=0
  PROFILE=0
  REPEAT=3
  SHOW_HELP=0
  TOPOLOGY_FILTER=""
  PATH_FILTER=""
  CONFIG_FILTER=""
  local seen_dry_run=0 seen_profile=0 seen_repeat=0
  local seen_topology=0 seen_path=0 seen_config=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --topology)
        (( seen_topology == 0 )) || { echo "duplicate option: --topology" >&2; return 2; }
        [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || { echo "--topology requires a value" >&2; return 2; }
        TOPOLOGY_FILTER="$2"; seen_topology=1; shift 2 ;;
      --topology=*)
        (( seen_topology == 0 )) || { echo "duplicate option: --topology" >&2; return 2; }
        TOPOLOGY_FILTER="${1#*=}"
        [[ -n "$TOPOLOGY_FILTER" ]] || { echo "--topology requires a value" >&2; return 2; }
        seen_topology=1; shift ;;
      --path)
        (( seen_path == 0 )) || { echo "duplicate option: --path" >&2; return 2; }
        [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || { echo "--path requires a value" >&2; return 2; }
        PATH_FILTER="$2"; seen_path=1; shift 2 ;;
      --path=*)
        (( seen_path == 0 )) || { echo "duplicate option: --path" >&2; return 2; }
        PATH_FILTER="${1#*=}"
        [[ -n "$PATH_FILTER" ]] || { echo "--path requires a value" >&2; return 2; }
        seen_path=1; shift ;;
      --config)
        (( seen_config == 0 )) || { echo "duplicate option: --config" >&2; return 2; }
        [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || { echo "--config requires a value" >&2; return 2; }
        CONFIG_FILTER="$2"; seen_config=1; shift 2 ;;
      --config=*)
        (( seen_config == 0 )) || { echo "duplicate option: --config" >&2; return 2; }
        CONFIG_FILTER="${1#*=}"
        [[ -n "$CONFIG_FILTER" ]] || { echo "--config requires a value" >&2; return 2; }
        seen_config=1; shift ;;
      --repeat)
        (( seen_repeat == 0 )) || { echo "duplicate option: --repeat" >&2; return 2; }
        [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || { echo "--repeat requires a value" >&2; return 2; }
        [[ "$2" =~ ^[1-9]$ ]] || { echo "--repeat must be an integer in 1..=9" >&2; return 2; }
        REPEAT="$2"; seen_repeat=1; shift 2 ;;
      --profile)
        (( seen_profile == 0 )) || { echo "duplicate option: --profile" >&2; return 2; }
        PROFILE=1; seen_profile=1; shift ;;
      --dry-run|-n)
        (( seen_dry_run == 0 )) || { echo "duplicate option: $1" >&2; return 2; }
        DRY_RUN=1; seen_dry_run=1; shift ;;
      -h|--help)
        # Preserve the long-standing behavior: help wins wherever it occurs
        # and never reaches the GCP setup path.
        SHOW_HELP=1; return 0 ;;
      *) echo "unknown arg: $1" >&2; return 2 ;;
    esac
  done
}

matrix_option_parsing_self_test() {
  local actual status
  actual=$(matrix_parse_args; printf '%s/%s/%s/%s/%s/%s\n' "$REPEAT" "$PROFILE" "$DRY_RUN" "$TOPOLOGY_FILTER" "$PATH_FILTER" "$CONFIG_FILTER") || return 1
  [[ "$actual" == '3/0/0///' ]] || return 1
  actual=$(matrix_parse_args --repeat 1 --profile --topology same-zone --path direct --config rs-tun,ts-tun; printf '%s/%s/%s/%s/%s/%s\n' "$REPEAT" "$PROFILE" "$DRY_RUN" "$TOPOLOGY_FILTER" "$PATH_FILTER" "$CONFIG_FILTER") || return 1
  [[ "$actual" == '1/1/0/same-zone/direct/rs-tun,ts-tun' ]] || return 1
  actual=$(matrix_parse_args --dry-run --help --not-an-error; printf '%s/%s/%s\n' "$DRY_RUN" "$SHOW_HELP" "$REPEAT") || return 1
  [[ "$actual" == '1/1/3' ]] || return 1
  local -a case_args=()
  for args in '--repeat' '--repeat 0' '--repeat 10' '--repeat 1.5' '--repeat 1 --repeat 2' '--profile --profile'; do
    read -r -a case_args <<< "$args"
    if ( matrix_parse_args "${case_args[@]}" ) >/dev/null 2>&1; then
      return 1
    else
      status=$?
      (( status == 2 )) || return 1
    fi
  done
}

matrix_write_manifest() {
  local output="$1" repeat="$2" dry_run="${MATRIX_MANIFEST_DRY_RUN:-0}"
  shift 2

  python3 - "$output" "$repeat" "$dry_run" "$@" <<'PYEOF'
import json
import re
import sys

out, repeat_value, dry_run_value, *args = sys.argv[1:]
if not re.fullmatch(r"[1-9][0-9]*", repeat_value):
    raise ValueError("repeat must be a positive integer")
if dry_run_value not in ("0", "1"):
    raise ValueError("dry-run marker must be 0 or 1")

parts, current = [], []
for arg in args:
    if arg == "--":
        parts.append(current)
        current = []
    else:
        current.append(arg)
parts.append(current)
if len(parts) != 4:
    raise ValueError("manifest requires topology, path, config, and parallelism groups")

parallelism = []
for value in parts[3]:
    if not re.fullmatch(r"[1-9][0-9]*", value):
        raise ValueError(f"parallelism must be a positive integer: {value!r}")
    parallelism.append(int(value))
if not parallelism:
    raise ValueError("parallelism must not be empty")

with open(out, "w", encoding="utf-8") as f:
    json.dump({"schema_version": 1, "topologies": parts[0], "paths": parts[1],
               "configs": parts[2], "parallelism": parallelism, "repeat": int(repeat_value),
               "dry_run": dry_run_value == "1",
               "warmup": {"parallel": 1, "duration_s": 3, "reverse": True}}, f, indent=2)
    f.write("\n")
PYEOF
}

# Render into a sibling temporary file and publish only a complete document.
# This preserves a prior dashboard if the renderer itself fails or is killed.
matrix_render_dashboard() {
  local summary="$1" dashboard="$2" renderer="${3:-tools/bench/gcp/render-html.py}"
  local dashboard_tmp
  dashboard_tmp=$(mktemp "$(dirname "$dashboard")/.dashboard.html.XXXXXX") || return 1
  if python3 "$renderer" "$summary" >"$dashboard_tmp"; then
    mv "$dashboard_tmp" "$dashboard"
  else
    rm -f "$dashboard_tmp"
    return 1
  fi
}

# Finalization has two deliberately distinct contracts. Production is strict:
# any failed/null cell fails before a dashboard is published. Dry-run cells are
# intentionally failed/null stubs, so they are aggregated with --allow-partial,
# rendered as DRY-RUN/PARTIAL, and return success with ##STATUS:DRY_RUN.
matrix_finalize_results() {
  local results_dir="$1" dry_run="$2" renderer="${3:-tools/bench/gcp/render-html.py}"
  local summary="$results_dir/summary.json" dashboard="$results_dir/dashboard.html"
  local summary_tmp aggregate_status
  local -a aggregate_args=()
  (( dry_run )) && aggregate_args+=(--allow-partial)

  echo "[gcp] aggregating results -> $summary"
  summary_tmp=$(mktemp "$results_dir/.summary.json.XXXXXX") || {
    echo "##STATUS:FAILED"
    return 1
  }
  if python3 tools/bench/gcp/aggregate.py "${aggregate_args[@]}" "$results_dir" >"$summary_tmp"; then
    :
  else
    aggregate_status=$?
    rm -f "$summary_tmp"
    echo "##STATUS:FAILED"
    echo "[gcp] result validation failed; dashboard is intentionally not marked complete" >&2
    return "$aggregate_status"
  fi

  echo "[gcp] rendering dashboard -> $dashboard"
  if ! matrix_render_dashboard "$summary_tmp" "$dashboard" "$renderer"; then
    rm -f "$summary_tmp"
    echo "##STATUS:FAILED"
    echo "[gcp] dashboard rendering failed; preserved any prior dashboard" >&2
    return 1
  fi
  mv "$summary_tmp" "$summary"

  # A collection failure must not change the completed run's contract; it only
  # affects the convenience cross-run index.
  if [[ "${MATRIX_SKIP_COLLECT:-0}" != 1 ]]; then
    tools/bench/gcp/collect.sh "$(dirname "$results_dir")" >/dev/null || true
  fi

  echo ""
  if (( dry_run )); then
    echo "═══ GCP bench dry-run finalized — PARTIAL ═══"
    echo "##STATUS:DRY_RUN"
  else
    echo "═══ GCP bench complete ═══"
    echo "##STATUS:OK"
  fi
  echo "  results:  $results_dir"
  echo "  summary:  $summary"
  echo "  dashboard: $dashboard"
  echo "  index:    $(dirname "$results_dir")/gcp-index.html"
}

matrix_finalization_self_test() {
  local temp_dir dry_dir prod_dir output status
  temp_dir=$(mktemp -d)
  dry_dir="$temp_dir/dry"; prod_dir="$temp_dir/prod"
  mkdir -p "$dry_dir/same-zone/direct" "$prod_dir/same-zone/direct"
  MATRIX_MANIFEST_DRY_RUN=1 matrix_write_manifest "$dry_dir/matrix.json" 1 same-zone -- direct -- rs-tun -- 1
  MATRIX_MANIFEST_DRY_RUN=0 matrix_write_manifest "$prod_dir/matrix.json" 1 same-zone -- direct -- rs-tun -- 1
  if ! python3 - "$dry_dir" "$prod_dir" <<'PYEOF'
import json
import sys
from pathlib import Path

dry, prod = map(Path, sys.argv[1:])
failed = {"schema_version": 2, "status": "failed", "tool": "rustscale", "mode": "tun",
          "topology": "same-zone", "path": "direct", "config": "rs-tun", "repeat": 1,
          "parallelism_requested": [1], "error": "dry-run", "log_tail": "",
          "throughput": None, "latency": None, "footprint": None, "path_class_reported": "unknown"}
(dry / "same-zone/direct/rs-tun.json").write_text(json.dumps(failed))
ok = {"schema_version": 2, "status": "ok", "tool": "rustscale", "mode": "tun",
      "topology": "same-zone", "path": "direct", "config": "rs-tun", "repeat": 1,
      "parallelism_requested": [1], "error": "", "log_tail": "",
      "throughput": [{"parallel": 1, "mbps": 1.0, "duration_s": 1.0,
                      "samples_mbps": [1.0], "statistic": "median"}],
      "latency": {"p50_us": 1, "p95_us": 2, "p99_us": 3, "count": 1},
      "footprint": {"binary_size_bytes": 1, "rss_peak_kb": 1, "rss_avg_kb": 1,
                    "cpu_peak_pct": 0, "cpu_avg_pct": 0, "samples": 1},
      "path_class_reported": "direct"}
(prod / "same-zone/direct/rs-tun.json").write_text(json.dumps(ok))
PYEOF
  then rm -rf "$temp_dir"; return 1; fi

  MATRIX_SKIP_COLLECT=1 output=$(matrix_finalize_results "$dry_dir" 1 2>&1) || { rm -rf "$temp_dir"; return 1; }
  [[ "$output" == *'##STATUS:DRY_RUN'* && "$output" != *'##STATUS:OK'* && "$output" != *'complete'* ]] || { rm -rf "$temp_dir"; return 1; }
  grep -q 'DRY-RUN — PARTIAL' "$dry_dir/dashboard.html" || { rm -rf "$temp_dir"; return 1; }
  grep -q 'DRY-RUN' "$dry_dir/dashboard.html" || { rm -rf "$temp_dir"; return 1; }

  # Production success has its own explicit status, unlike dry-run success.
  MATRIX_SKIP_COLLECT=1 output=$(matrix_finalize_results "$prod_dir" 0 2>&1) || { rm -rf "$temp_dir"; return 1; }
  [[ "$output" == *'##STATUS:OK'* && "$output" != *'##STATUS:DRY_RUN'* ]] || { rm -rf "$temp_dir"; return 1; }

  printf '%s\n' 'import sys; sys.exit(7)' >"$temp_dir/bad-renderer.py"
  printf '%s' 'prior dashboard' >"$prod_dir/dashboard.html"
  if MATRIX_SKIP_COLLECT=1 output=$(matrix_finalize_results "$prod_dir" 0 "$temp_dir/bad-renderer.py" 2>&1); then
    rm -rf "$temp_dir"; return 1
  else
    status=$?
  fi
  (( status != 0 )) && [[ "$output" == *'##STATUS:FAILED'* ]] || { rm -rf "$temp_dir"; return 1; }
  [[ "$(<"$prod_dir/dashboard.html")" == 'prior dashboard' ]] || { rm -rf "$temp_dir"; return 1; }
  ! compgen -G "$prod_dir/.dashboard.html.*" >/dev/null || { rm -rf "$temp_dir"; return 1; }
  ! compgen -G "$prod_dir/.summary.json.*" >/dev/null || { rm -rf "$temp_dir"; return 1; }
  rm -rf "$temp_dir"
}

matrix_manifest_self_test() {
  local temp_dir manifest invalid_manifest
  temp_dir=$(mktemp -d)
  manifest="$temp_dir/matrix.json"
  invalid_manifest="$temp_dir/invalid.json"

  if ! matrix_write_manifest "$manifest" 3 same-zone -- direct -- rs-tun -- 1 10 100; then
    rm -rf "$temp_dir"
    return 1
  fi
  if ! python3 - "$manifest" "$temp_dir" <<'PYEOF'
import json
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text())
assert manifest["parallelism"] == [1, 10, 100]
assert all(type(value) is int for value in manifest["parallelism"])

root = Path(sys.argv[2])
cell = root / "same-zone/direct/rs-tun.json"
cell.parent.mkdir(parents=True)
parallelism = manifest["parallelism"]
cell.write_text(json.dumps({
    "schema_version": 2, "status": "ok", "tool": "rustscale", "mode": "tun",
    "topology": "same-zone", "path": "direct", "config": "rs-tun", "repeat": 3,
    "parallelism_requested": parallelism, "error": "", "log_tail": "",
    "throughput": [{"parallel": value, "mbps": float(value), "duration_s": 1,
                    "samples_mbps": [float(value)] * 3, "statistic": "median"}
                   for value in parallelism],
    "latency": {"p50_us": 1, "p95_us": 2, "p99_us": 3, "count": 1},
    "footprint": {"binary_size_bytes": 1, "rss_peak_kb": 1, "rss_avg_kb": 1,
                  "cpu_peak_pct": 0, "cpu_avg_pct": 0, "samples": 1},
    "path_class_reported": "direct",
}))
PYEOF
  then
    rm -rf "$temp_dir"
    return 1
  fi
  if ! python3 tools/bench/gcp/aggregate.py "$temp_dir" >/dev/null; then
    rm -rf "$temp_dir"
    return 1
  fi
  local malformed
  for malformed in 0 -1 1.0 +1 ' 1' abc; do
    if matrix_write_manifest "$invalid_manifest" 3 same-zone -- direct -- rs-tun -- "$malformed" >/dev/null 2>&1; then
      rm -rf "$temp_dir"
      return 1
    fi
    [[ ! -e "$invalid_manifest" ]] || { rm -rf "$temp_dir"; return 1; }
  done
  rm -rf "$temp_dir"
}

matrix_command_shape_self_test
matrix_remote_build_aggregation_self_test
matrix_config_failure_policy_self_test
matrix_profile_self_test
matrix_option_parsing_self_test
matrix_manifest_self_test
matrix_finalization_self_test

if (( MATRIX_SELF_TEST )); then
  package_tailscaled_cleanup_self_test
  startup_script_self_test
  echo "run-matrix self-tests: OK" >&2
  exit 0
fi

# ---------------------------------------------------------------------------
# Arg parsing.
# ---------------------------------------------------------------------------
matrix_usage() {
  cat <<EOF
usage: $0 [--dry-run] [--profile] [--repeat N] [--topology LIST] [--path LIST] [--config LIST]
Runs the full 16-run GCP bench matrix.
  --dry-run  validate args + script structure without gcloud or API calls.
  --topology comma-separated subset: same-zone,cross-region
  --path     comma-separated subset: direct,derp
  --config   comma-separated subset: rs-userspace,rs-tun,ts-userspace,ts-tun
  --repeat N run each production TUN throughput parallelism N times (1..=9; default 3)
  --profile  profile only the selected rs-tun cell after normal metrics
EOF
}
matrix_parse_args "$@" || exit $?
if (( SHOW_HELP )); then
  matrix_usage
  exit 0
fi

if [[ $DRY_RUN -eq 1 ]]; then
  export GCP_DRY_RUN=1
  echo "[dry-run] enabled — gcloud/API mutations skipped, stub JSONs emitted"
fi

# ---------------------------------------------------------------------------
# Zone pairings.
# ---------------------------------------------------------------------------
declare -A ZONES=(
  [same-zone]="us-central1-a:us-central1-b"
  [cross-region]="us-central1-a:us-west1-a"
)
TOPOLOGIES=(same-zone cross-region)
PATHS=(direct derp)
CONFIGS=(rs-userspace rs-tun ts-userspace ts-tun)
# This is serialized into matrix.json and must exactly match every result's
# parallelism_requested list; changing the sweep is therefore self-describing.
PARALLELS=(1 10 100)
select_values() {
  local filter="$1"; shift
  local -a available=("$@") selected=()
  [[ -z "$filter" ]] && { SELECTED=("${available[@]}"); return; }
  local item candidate found
  IFS=, read -r -a selected <<< "$filter"
  for item in "${selected[@]}"; do
    found=0
    for candidate in "${available[@]}"; do
      if [[ "$item" == "$candidate" ]]; then
        found=1
      fi
    done
    (( found )) || { echo "invalid selection: $item" >&2; exit 2; }
  done
  SELECTED=("${selected[@]}")
}
select_values "$TOPOLOGY_FILTER" "${TOPOLOGIES[@]}"; TOPOLOGIES=("${SELECTED[@]}")
select_values "$PATH_FILTER" "${PATHS[@]}"; PATHS=("${SELECTED[@]}")
select_values "$CONFIG_FILTER" "${CONFIGS[@]}"; CONFIGS=("${SELECTED[@]}")
if (( PROFILE )); then
  found=0
  for cfg in "${CONFIGS[@]}"; do [[ "$cfg" == rs-tun ]] && found=1; done
  (( found )) || { echo "--profile requires selected config rs-tun" >&2; exit 2; }
  [[ ${#TOPOLOGIES[@]} -eq 1 && ${#PATHS[@]} -eq 1 ]] || {
    echo "--profile requires exactly one selected topology and one selected path" >&2; exit 2;
  }
fi
RUST_BUILD_COMMAND=$(rust_build_command)
if [[ -z "$RUST_BUILD_COMMAND" ]]; then
  echo "[gcp] skipping Rust source delivery and builds (no Rust configs selected)" >&2
fi

STAMP=$(date +%Y%m%d-%H%M%S)
RESULTS_DIR="bench-results/gcp-$STAMP"
mkdir -p "$RESULTS_DIR"
MATRIX_MANIFEST_DRY_RUN="$DRY_RUN" matrix_write_manifest "$RESULTS_DIR/matrix.json" "$REPEAT" \
  "${TOPOLOGIES[@]}" -- "${PATHS[@]}" -- "${CONFIGS[@]}" -- "${PARALLELS[@]}"

# Track VMs created for cleanup. ASSUMES one pair per topology; we delete each
# topology's VMs before starting the next to keep quota usage at 2 VMs.
ACTIVE_SRV=""
ACTIVE_SRV_ZONE=""
ACTIVE_CLI=""
ACTIVE_CLI_ZONE=""
CLEANUP_RAN=0

 # ---------------------------------------------------------------------------
 # Cleanup trap. Deletes VMs + tailnet. Always best-effort.
 # Set AFTER bench_provision_tailnet calls its own trap, so this overrides it.
 # ---------------------------------------------------------------------------
 gcp_bench_cleanup() {
   [[ $CLEANUP_RAN -eq 0 ]] || return
   CLEANUP_RAN=1
   set +e
   echo "[gcp] cleanup: deleting VMs + tailnet" >&2
   if [[ -n "$ACTIVE_SRV" ]]; then
     delete_vm "$ACTIVE_SRV" "$ACTIVE_SRV_ZONE"
   fi
   if [[ -n "$ACTIVE_CLI" ]]; then
     delete_vm "$ACTIVE_CLI" "$ACTIVE_CLI_ZONE"
   fi
   bench_cleanup_tailnet
 }

gcp_bench_on_signal() {
  local signal="$1"
  echo "[gcp] received $signal; exiting" >&2
  exit 1
}

# ---------------------------------------------------------------------------
# Provision tailnet (skipped in dry-run to avoid API calls).
# A FRESH authkey is minted per config invocation inside the main loop to
# avoid key expiry / invalidation across the ~40-min matrix run.  The
# org-level child token / DNS / API base are exported so that bench_mint_authkey
# (defined in tools/bench/lib.sh) works inside run-config.sh if ever needed.
# ---------------------------------------------------------------------------
if [[ $DRY_RUN -eq 1 ]]; then
  echo "[dry-run] skipping tailnet provisioning" >&2
  AUTHKEY="tskey-dryrun-placeholder"
else
  bench_provision_tailnet
  export BENCH_DNS BENCH_CHILD_TOKEN BENCH_CHILD_CID BENCH_CHILD_CSEC BENCH_API
  echo "[gcp] tailnet provisioned; authkeys will be minted per-config" >&2
fi

# Register cleanup handler AFTER bench_provision_tailnet so our trap overrides it.
# Signal handlers exit nonzero; the EXIT trap performs the cleanup exactly once.
trap 'gcp_bench_on_signal INT' INT
trap 'gcp_bench_on_signal TERM' TERM
trap gcp_bench_cleanup EXIT

# ---------------------------------------------------------------------------
# Main matrix loop.
# ---------------------------------------------------------------------------
for TOPO in "${TOPOLOGIES[@]}"; do
  IFS=: read -r Z_A Z_B <<< "${ZONES[$TOPO]}"
  SERVER_VM="rs-bench-${STAMP}-${TOPO}-srv"
  CLIENT_VM="rs-bench-${STAMP}-${TOPO}-cli"
  ACTIVE_SRV="$SERVER_VM"
  ACTIVE_SRV_ZONE="$Z_A"
  ACTIVE_CLI="$CLIENT_VM"
  ACTIVE_CLI_ZONE="$Z_B"

  echo ""
  echo "[gcp] === topology: $TOPO (zones $Z_A / $Z_B) ==="

  # Provision VMs (no-op in dry-run).
  create_vms "$SERVER_VM" "$Z_A" "$CLIENT_VM" "$Z_B"

  if [[ -n "$RUST_BUILD_COMMAND" ]]; then
    # Deliver source sequentially, then build on both VMs in parallel.
    deliver_source "$SERVER_VM" "$Z_A"
    deliver_source "$CLIENT_VM" "$Z_B"
    echo "[gcp] building rustscale on both VMs in parallel..." >&2
    ssh_cmd "$SERVER_VM" "$Z_A" "$RUST_BUILD_COMMAND" &
    SERVER_BUILD_PID=$!
    ssh_cmd "$CLIENT_VM" "$Z_B" "$RUST_BUILD_COMMAND" &
    CLIENT_BUILD_PID=$!
    wait_for_remote_builds "$SERVER_BUILD_PID" "$CLIENT_BUILD_PID"
  fi

  # Path loop.
  for PATH_TAG in "${PATHS[@]}"; do
    echo ""
    echo "[gcp] --- path: $PATH_TAG ---"

    if [[ "$PATH_TAG" == "derp" ]]; then
      apply_derp_block "$SERVER_VM" "$Z_A"
      apply_derp_block "$CLIENT_VM" "$Z_B"
      # Brief settle for in-flight UDP to drain.
      sleep 5
    fi

    for CFG in "${CONFIGS[@]}"; do
      echo ""
      echo "[gcp] >>> config: $CFG (topo=$TOPO path=$PATH_TAG) <<<"
      export BENCH_MATRIX="${TOPO}/${PATH_TAG}"

      # Mint a FRESH authkey per config.  Reusing a single ephemeral key
      # across all 16 configs causes "invalid key" / "node not found" errors
      # as the key expires or its ephemeral nodes are reaped mid-run.
      if [[ $DRY_RUN -eq 1 ]]; then
        AUTHKEY="tskey-dryrun-placeholder"
      else
        AUTHKEY=$(bench_mint_authkey)
        echo "[gcp] minted fresh authkey for $CFG" >&2
      fi

      matrix_run_config_cell "$CFG" "$SERVER_VM" "$CLIENT_VM" "$Z_A" "$Z_B" \
        "$AUTHKEY" "$RESULTS_DIR/$TOPO/$PATH_TAG" "rs-srv-$TOPO" "rs-cli-$TOPO"
    done

    if [[ "$PATH_TAG" == "derp" ]]; then
      remove_derp_block "$SERVER_VM" "$Z_A"
      remove_derp_block "$CLIENT_VM" "$Z_B"
    fi
  done

  # Tear down this topology's VMs before the next (keep quota at 2).
  if [[ -z "${SKIP_VM_DELETE:-}" ]]; then
    delete_vms "$SERVER_VM" "$Z_A" "$CLIENT_VM" "$Z_B"
    ACTIVE_SRV=""
    ACTIVE_CLI=""
  fi
done

# ---------------------------------------------------------------------------
# Aggregate + render. Any finalization return exits through gcp_bench_cleanup,
# including the successful DRY_RUN contract and renderer failures.
# ---------------------------------------------------------------------------
matrix_finalize_results "$RESULTS_DIR" "$DRY_RUN" || exit $?

# Clear the trap's VM deletion now that we're done; tailnet cleanup still runs.
ACTIVE_SRV=""
ACTIVE_CLI=""
