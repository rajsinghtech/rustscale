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

matrix_command_shape_self_test
matrix_remote_build_aggregation_self_test
matrix_config_failure_policy_self_test
matrix_profile_self_test
matrix_option_parsing_self_test

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
python3 - "$RESULTS_DIR/matrix.json" "$REPEAT" "${TOPOLOGIES[@]}" -- "${PATHS[@]}" -- "${CONFIGS[@]}" <<'PYEOF'
import json, sys
out = sys.argv[1]
repeat = int(sys.argv[2])
parts, cur = [], []
for arg in sys.argv[3:]:
    if arg == "--": parts.append(cur); cur = []
    else: cur.append(arg)
parts.append(cur)
with open(out, "w", encoding="utf-8") as f:
    json.dump({"schema_version": 1, "topologies": parts[0], "paths": parts[1], "configs": parts[2],
               "repeat": repeat,
               "warmup": {"parallel": 1, "duration_s": 3, "reverse": True}}, f, indent=2)
    f.write("\n")
PYEOF

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
# Aggregate + render.
# ---------------------------------------------------------------------------
echo ""
echo "[gcp] aggregating results -> $RESULTS_DIR/summary.json"
# aggregate.py is pure python (no gcloud/API) so it runs in dry-run too,
# exercising the glob+sort path against the stub JSONs run-config.sh wrote.
python3 tools/bench/gcp/aggregate.py "$RESULTS_DIR" > "$RESULTS_DIR/summary.json"

echo "[gcp] rendering dashboard -> $RESULTS_DIR/dashboard.html"
python3 tools/bench/gcp/render-html.py "$RESULTS_DIR/summary.json" > "$RESULTS_DIR/dashboard.html"

# Refresh the cross-run index so every dashboard is reachable from one page.
tools/bench/gcp/collect.sh "$(dirname "$RESULTS_DIR")" >/dev/null || true

echo ""
echo "═══ GCP bench complete ═══"
echo "  results:  $RESULTS_DIR"
echo "  summary:  $RESULTS_DIR/summary.json"
echo "  dashboard: $RESULTS_DIR/dashboard.html"
echo "  index:    $(dirname "$RESULTS_DIR")/gcp-index.html"

# Clear the trap's VM deletion now that we're done; tailnet cleanup still runs.
ACTIVE_SRV=""
ACTIVE_CLI=""
