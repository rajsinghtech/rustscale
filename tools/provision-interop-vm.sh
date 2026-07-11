#!/usr/bin/env bash
# Provision a single GCP VM for rustscale interop testing.
set -euo pipefail
cd "$(dirname "$0")/.."
source tools/bench/gcp/lib.sh

VM_NAME="rs-gcp-interop"
ZONE="us-east1-b"

create_vm "$VM_NAME" "$ZONE"
wait_for_startup "$VM_NAME" "$ZONE" 600

echo "[done] VM $VM_NAME is ready in $ZONE"
# Print external IP
gcloud compute instances describe "$VM_NAME" --zone="$ZONE" \
  --format='value(networkInterfaces[0].accessConfigs[0].natIP)'
