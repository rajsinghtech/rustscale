#!/usr/bin/env bash
# tools/bench/gcp/run-samezone-retry.sh — re-run just the 2 failed DERP configs
#
# Creates fresh VMs, delivers source, builds rustscale (faster on 2nd run
# due to crate cache), and runs only rs-userspace + rs-tun under DERP.
#
# Usage:
#   tools/bench/gcp/run-samezone-retry.sh [--dry-run]

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

[[ $DRY_RUN -eq 1 ]] && export GCP_DRY_RUN=1

STAMP=$(date +%Y%m%d-%H%M%S)-derp-retry
RESULTS_DIR="bench-results/gcp-$STAMP"
mkdir -p "$RESULTS_DIR"

ACTIVE_SRV="" ACTIVE_SRV_ZONE="" ACTIVE_CLI="" ACTIVE_CLI_ZONE=""

Z_A="us-central1-a"
Z_B="us-central1-b"
SERVER_VM="rs-bench-${STAMP}-srv"
CLIENT_VM="rs-bench-${STAMP}-cli"
ACTIVE_SRV="$SERVER_VM"; ACTIVE_SRV_ZONE="$Z_A"
ACTIVE_CLI="$CLIENT_VM"; ACTIVE_CLI_ZONE="$Z_B"

if [[ $DRY_RUN -eq 1 ]]; then
  AUTHKEY="tskey-dryrun-placeholder"
else
  bench_provision_tailnet
  export BENCH_DNS BENCH_CHILD_TOKEN BENCH_CHILD_CID BENCH_CHILD_CSEC BENCH_API
fi

trap 'set +e; echo "[gcp] cleanup" >&2;
  [[ -n "$ACTIVE_SRV" ]] && delete_vm "$ACTIVE_SRV" "$ACTIVE_SRV_ZONE" 2>/dev/null;
  [[ -n "$ACTIVE_CLI" ]] && delete_vm "$ACTIVE_CLI" "$ACTIVE_CLI_ZONE" 2>/dev/null;
  bench_cleanup_tailnet' INT TERM EXIT

create_vms "$SERVER_VM" "$Z_A" "$CLIENT_VM" "$Z_B"
deliver_source "$SERVER_VM" "$Z_A"
deliver_source "$CLIENT_VM" "$Z_B"

echo "[gcp] building rustscale on both VMs in parallel..." >&2
ssh_cmd "$SERVER_VM" "$Z_A" \
  'export RUSTUP_HOME=/opt/rust CARGO_HOME=/opt/rust/cargo; cd /opt/rustscale && cargo build --release -p rustscale-bench && cargo build --release --example rustscale-tun -p rustscale-tsnet' &
ssh_cmd "$CLIENT_VM" "$Z_B" \
  'export RUSTUP_HOME=/opt/rust CARGO_HOME=/opt/rust/cargo; cd /opt/rustscale && cargo build --release -p rustscale-bench && cargo build --release --example rustscale-tun -p rustscale-tsnet' &
wait

# Apply DERP block
apply_derp_block "$SERVER_VM" "$Z_A"
apply_derp_block "$CLIENT_VM" "$Z_B"
sleep 5

for CFG in rs-userspace rs-tun; do
  echo ""
  echo "[gcp] >>> config: $CFG (derp) <<<"
  export BENCH_MATRIX="same-zone/derp"
  AUTHKEY=$(bench_mint_authkey)
  echo "[gcp] minted fresh authkey for $CFG" >&2

  if tools/bench/gcp/run-config.sh \
      "$CFG" "$SERVER_VM" "$CLIENT_VM" "$Z_A" "$Z_B" \
      "$AUTHKEY" "$RESULTS_DIR/same-zone/derp" \
      "rs-srv-retry" "rs-cli-retry"; then
    echo "[gcp] $CFG: OK -> $RESULTS_DIR/same-zone/derp/$CFG.json"
  else
    echo "[gcp] $CFG: FAILED (will examine logs)" >&2
  fi
done

remove_derp_block "$SERVER_VM" "$Z_A"
remove_derp_block "$CLIENT_VM" "$Z_B"

# Merge results into the main run dir (copy retry JSONs over)
MAIN_RUN="bench-results/gcp-20260713-032001"
echo "[gcp] merging retry results into $MAIN_RUN/same-zone/derp/"
mkdir -p "$MAIN_RUN/same-zone/derp"
cp "$RESULTS_DIR/same-zone/derp/"*.json "$MAIN_RUN/same-zone/derp/" 2>/dev/null || true
python3 tools/bench/gcp/aggregate.py "$MAIN_RUN" > "$MAIN_RUN/summary.json"
python3 tools/bench/gcp/render-html.py "$MAIN_RUN/summary.json" > "$MAIN_RUN/dashboard.html"

echo ""
echo "═══ DERP retry complete ═══"
echo "  merged into: $MAIN_RUN/same-zone/derp/"
echo "  summary:     $MAIN_RUN/summary.json"
echo "  dashboard:   $MAIN_RUN/dashboard.html"

ACTIVE_SRV="" ACTIVE_CLI=""
