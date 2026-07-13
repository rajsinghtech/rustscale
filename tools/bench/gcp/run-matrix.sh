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

rust_build_command() {
  printf '%s' 'export RUSTUP_HOME=/opt/rust CARGO_HOME=/opt/rust/cargo; cd /opt/rustscale && cargo build --release -p rustscale-bench -p rustscale-cli -p rustscale-rustscaled'
}

matrix_command_shape_self_test() {
  [[ "$(rust_build_command)" == *'-p rustscale-rustscaled'* ]] || return 1
  [[ "$(rust_build_command)" != *'-p rustscaled'* ]] || return 1
}

matrix_command_shape_self_test

# ---------------------------------------------------------------------------
# Arg parsing.
# ---------------------------------------------------------------------------
DRY_RUN=0
TOPOLOGY_FILTER=""
PATH_FILTER=""
CONFIG_FILTER=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --topology)
      [[ $# -ge 2 && -n "$2" ]] || { echo "--topology requires a value" >&2; exit 2; }
      TOPOLOGY_FILTER="$2"; shift 2 ;;
    --topology=*) TOPOLOGY_FILTER="${1#*=}"; shift ;;
    --path)
      [[ $# -ge 2 && -n "$2" ]] || { echo "--path requires a value" >&2; exit 2; }
      PATH_FILTER="$2"; shift 2 ;;
    --path=*) PATH_FILTER="${1#*=}"; shift ;;
    --config)
      [[ $# -ge 2 && -n "$2" ]] || { echo "--config requires a value" >&2; exit 2; }
      CONFIG_FILTER="$2"; shift 2 ;;
    --config=*) CONFIG_FILTER="${1#*=}"; shift ;;
    --dry-run|-n) DRY_RUN=1; shift ;;
    -h|--help)
      cat <<EOF
usage: $0 [--dry-run] [--topology LIST] [--path LIST] [--config LIST]
Runs the full 16-run GCP bench matrix.
  --dry-run  validate args + script structure without gcloud or API calls.
  --topology comma-separated subset: same-zone,cross-region
  --path     comma-separated subset: direct,derp
  --config   comma-separated subset: rs-userspace,rs-tun,ts-userspace,ts-tun
EOF
      exit 0
      ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

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

STAMP=$(date +%Y%m%d-%H%M%S)
RESULTS_DIR="bench-results/gcp-$STAMP"
mkdir -p "$RESULTS_DIR"

# Track VMs created for cleanup. ASSUMES one pair per topology; we delete each
# topology's VMs before starting the next to keep quota usage at 2 VMs.
ACTIVE_SRV=""
ACTIVE_SRV_ZONE=""
ACTIVE_CLI=""
ACTIVE_CLI_ZONE=""

 # ---------------------------------------------------------------------------
 # Cleanup trap. Deletes VMs + tailnet. Always best-effort.
 # Set AFTER bench_provision_tailnet calls its own trap, so this overrides it.
 # ---------------------------------------------------------------------------
 gcp_bench_cleanup() {
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
trap gcp_bench_cleanup INT TERM EXIT

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

  # Deliver source + build on both VMs. Deliver sequentially (fast: git archive+scp),
  # then build in parallel (saves ~10min).
  deliver_source "$SERVER_VM" "$Z_A"
  deliver_source "$CLIENT_VM" "$Z_B"
  echo "[gcp] building rustscale on both VMs in parallel..." >&2
  ssh_cmd "$SERVER_VM" "$Z_A" \
    "$(rust_build_command)" &
  ssh_cmd "$CLIENT_VM" "$Z_B" \
    "$(rust_build_command)" &
  wait

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

      if tools/bench/gcp/run-config.sh \
          "$CFG" "$SERVER_VM" "$CLIENT_VM" "$Z_A" "$Z_B" \
          "$AUTHKEY" "$RESULTS_DIR/$TOPO/$PATH_TAG" \
          "rs-srv-$TOPO" "rs-cli-$TOPO"; then
        echo "[gcp] $CFG: OK -> $RESULTS_DIR/$TOPO/$PATH_TAG/$CFG.json"
      else
        echo "[gcp] $CFG: FAILED (continuing)" >&2
      fi
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
