#!/usr/bin/env bash
# Credential-free regression for bounded TUN interop child cleanup.
set -euo pipefail
cd "$(dirname "$0")/../.."

# shellcheck disable=SC1091
source tools/interop-tun-cleanup.sh

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

start_child() {
  local mode="$1"
  local ready="$TMP/$mode.ready"
  mkfifo "$ready"
  if [[ "$mode" == "graceful" ]]; then
    bash -c 'trap "exit 0" TERM; printf "ready\n" >"$1"; while :; do :; done' _ "$ready" &
  else
    bash -c 'trap "" TERM; printf "ready\n" >"$1"; while :; do :; done' _ "$ready" &
  fi
  CHILD_PID=$!
  read -r marker <"$ready"
  [[ "$marker" == ready ]]
}

start_child graceful
interop_tun_stop_child "$CHILD_PID" "graceful regression child" 2
if kill -0 "$CHILD_PID" 2>/dev/null; then
  echo "graceful child leaked after cleanup" >&2
  exit 1
fi

start_child stubborn
start_seconds=$SECONDS
interop_tun_stop_child "$CHILD_PID" "stubborn regression child" 1
elapsed=$((SECONDS - start_seconds))
if kill -0 "$CHILD_PID" 2>/dev/null; then
  echo "stubborn child leaked after cleanup" >&2
  exit 1
fi
(( elapsed <= 3 )) || {
  echo "stubborn cleanup exceeded bound: ${elapsed}s" >&2
  exit 1
}

echo "interop TUN bounded cleanup regression passed"
