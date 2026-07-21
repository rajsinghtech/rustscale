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

if tail --help 2>&1 | grep -q -- '--pid' && command -v timeout >/dev/null 2>&1; then
  bench_cleanup_tailnet() { return 0; }
  interop_tun_cleanup_tailnet 2

  bench_cleanup_tailnet() {
    trap '' TERM
    while :; do :; done
  }
  start_seconds=$SECONDS
  if interop_tun_cleanup_tailnet 1; then
    echo "stubborn tailnet cleanup unexpectedly passed" >&2
    exit 1
  fi
  elapsed=$((SECONDS - start_seconds))
  (( elapsed <= 4 )) || {
    echo "tailnet cleanup exceeded outer bound: ${elapsed}s" >&2
    exit 1
  }
fi

echo "interop TUN bounded cleanup regression passed"
