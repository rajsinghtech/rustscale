#!/usr/bin/env bash
# tools/bench/gcp/run-matrix-samezone.sh — same-zone only GCP bench
#
# Just like run-matrix.sh but only does same-zone topology.
# Usage:
#   tools/bench/gcp/run-matrix-samezone.sh [--dry-run]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$REPO_ROOT"

source tools/bench/lib.sh
source tools/bench/gcp/lib.sh
source tools/bench/gcp/footprint.sh

DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --dry-run|-n) DRY_RUN=1 ;;
    -h|--help) echo "usage: $0 [--dry-run]"; exit 0 ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done

if [[ $DRY_RUN -eq 1 ]]; then
  export GCP_DRY_RUN=1
  echo "[dry-run] enabled — gcloud/API mutations skipped"
fi

STAMP=$(date +%Y%m%d-%H%M%S)
RESULTS_DIR="bench-results/gcp-$STAMP"
mkdir -p "$RESULTS_DIR"

ACTIVE_SRV=""
ACTIVE_SRV_ZONE=""
ACTIVE_CLI=""
ACTIVE_CLI_ZONE=""

ZONES_SAME="us-central1-a:us-central1-b"
TOPOLOGIES=(same-zone)
PATHS=(direct derp)
CONFIGS=(rs-userspace rs-tun ts-userspace ts-tun)

# Tailnet
if [[ $DRY_RUN -eq 1 ]]; then
  echo "[dry-run] skipping tailnet provisioning" >&2
  AUTHKEY="tskey-dryrun-placeholder"
else
  bench_provision_tailnet
  export BENCH_DNS BENCH_CHILD_TOKEN BENCH_CHILD_CID BENCH_CHILD_CSEC BENCH_API
  echo "[gcp] tailnet provisioned; authkeys will be minted per-config" >&2
fi

trap 'set +e; echo "[gcp] cleanup: deleting VMs + tailnet" >&2;
  [[ -n "$ACTIVE_SRV" ]] && delete_vm "$ACTIVE_SRV" "$ACTIVE_SRV_ZONE";
  [[ -n "$ACTIVE_CLI" ]] && delete_vm "$ACTIVE_CLI" "$ACTIVE_CLI_ZONE";
  bench_cleanup_tailnet' INT TERM EXIT

for TOPO in "${TOPOLOGIES[@]}"; do
  IFS=: read -r Z_A Z_B <<< "$ZONES_SAME"
  SERVER_VM="rs-bench-${STAMP}-${TOPO}-srv"
  CLIENT_VM="rs-bench-${STAMP}-${TOPO}-cli"
  ACTIVE_SRV="$SERVER_VM"
  ACTIVE_SRV_ZONE="$Z_A"
  ACTIVE_CLI="$CLIENT_VM"
  ACTIVE_CLI_ZONE="$Z_B"

  echo ""
  echo "[gcp] === topology: $TOPO (zones $Z_A / $Z_B) ==="

  create_vms "$SERVER_VM" "$Z_A" "$CLIENT_VM" "$Z_B"

  deliver_source "$SERVER_VM" "$Z_A"
  deliver_source "$CLIENT_VM" "$Z_B"
  echo "[gcp] building rustscale on both VMs in parallel..." >&2
  ssh_cmd "$SERVER_VM" "$Z_A" \
    'export RUSTUP_HOME=/opt/rust CARGO_HOME=/opt/rust/cargo; cd /opt/rustscale && cargo build --release -p rustscale-bench && cargo build --release --example rustscale-tun -p rustscale-tsnet' &
  ssh_cmd "$CLIENT_VM" "$Z_B" \
    'export RUSTUP_HOME=/opt/rust CARGO_HOME=/opt/rust/cargo; cd /opt/rustscale && cargo build --release -p rustscale-bench && cargo build --release --example rustscale-tun -p rustscale-tsnet' &
  wait

  for PATH_TAG in "${PATHS[@]}"; do
    echo ""
    echo "[gcp] --- path: $PATH_TAG ---"

    if [[ "$PATH_TAG" == "derp" ]]; then
      apply_derp_block "$SERVER_VM" "$Z_A"
      apply_derp_block "$CLIENT_VM" "$Z_B"
      sleep 5
    fi

    for CFG in "${CONFIGS[@]}"; do
      echo ""
      echo "[gcp] >>> config: $CFG (topo=$TOPO path=$PATH_TAG) <<<"
      export BENCH_MATRIX="${TOPO}/${PATH_TAG}"

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

  if [[ -z "${SKIP_VM_DELETE:-}" ]]; then
    delete_vms "$SERVER_VM" "$Z_A" "$CLIENT_VM" "$Z_B"
    ACTIVE_SRV=""
    ACTIVE_CLI=""
  fi
done

echo ""
echo "[gcp] aggregating results -> $RESULTS_DIR/summary.json"
python3 tools/bench/gcp/aggregate.py "$RESULTS_DIR" > "$RESULTS_DIR/summary.json"

echo "[gcp] rendering dashboard -> $RESULTS_DIR/dashboard.html"
python3 tools/bench/gcp/render-html.py "$RESULTS_DIR/summary.json" > "$RESULTS_DIR/dashboard.html"

tools/bench/gcp/collect.sh "$(dirname "$RESULTS_DIR")" >/dev/null || true

echo ""
echo "═══ GCP bench complete ═══"
echo "  results:  $RESULTS_DIR"
echo "  summary:  $RESULTS_DIR/summary.json"
echo "  dashboard: $RESULTS_DIR/dashboard.html"

ACTIVE_SRV=""
ACTIVE_CLI=""
