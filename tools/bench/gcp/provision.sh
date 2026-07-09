#!/usr/bin/env bash
# tools/bench/gcp/provision.sh — create two GCP VMs and wait for startup.
#
# Wraps create_vms from lib.sh with a standalone entry point so it can be
# invoked directly for debugging or by run-matrix.sh via `source`.
#
# Usage:
#   tools/bench/gcp/provision.sh SERVER_NAME SERVER_ZONE CLIENT_NAME CLIENT_ZONE
#
# Exits 0 when both VMs report /tmp/startup-done. Idempotent: reuses
# existing VMs.

set -euo pipefail

# shellcheck source=./lib.sh
source "$(dirname "$0")/lib.sh"

if [[ $# -lt 4 ]]; then
  echo "usage: $0 SERVER_NAME SERVER_ZONE CLIENT_NAME CLIENT_ZONE" >&2
  exit 2
fi

create_vms "$1" "$2" "$3" "$4"
echo "[gcp] both VMs ready: $1 ($2), $3 ($4)"
