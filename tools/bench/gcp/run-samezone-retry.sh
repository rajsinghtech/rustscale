#!/usr/bin/env bash
# Compatibility entry point for re-running the historical same-zone DERP pair.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
extra=()
for arg in "$@"; do
  case "$arg" in
    --topology|--topology=*|--path|--path=*|--config|--config=*) ;;
    *) continue ;;
  esac
  case "$arg" in
    --topology|--topology=*) topology_set=1 ;;
    --path|--path=*) path_set=1 ;;
    --config|--config=*) config_set=1 ;;
  esac
done
[[ -n "${topology_set:-}" ]] || extra+=(--topology same-zone)
[[ -n "${path_set:-}" ]] || extra+=(--path derp)
[[ -n "${config_set:-}" ]] || extra+=(--config rs-userspace,rs-tun)
exec "$SCRIPT_DIR/run-matrix.sh" "$@" "${extra[@]}"
