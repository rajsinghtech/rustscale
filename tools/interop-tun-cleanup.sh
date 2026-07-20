#!/usr/bin/env bash
# Bounded child-process cleanup shared by the trusted TUN interop journey and
# its credential-free regression.

interop_tun_stop_child() {
  local pid="$1" label="$2" grace_seconds="${3:-10}"
  local watchdog="" child_status=0

  if ! kill -0 "$pid" 2>/dev/null; then
    wait "$pid" 2>/dev/null || true
    return 0
  fi

  kill -TERM "$pid" 2>/dev/null || true
  (
    sleep "$grace_seconds"
    if kill -0 "$pid" 2>/dev/null; then
      echo "[interop-tun] WARNING: $label did not stop after ${grace_seconds}s; sending KILL" >&2
      kill -KILL "$pid" 2>/dev/null || true
    fi
  ) &
  watchdog=$!

  wait "$pid" 2>/dev/null || child_status=$?
  kill "$watchdog" 2>/dev/null || true
  wait "$watchdog" 2>/dev/null || true

  if kill -0 "$pid" 2>/dev/null; then
    echo "[interop-tun] ERROR: $label remained alive after TERM/KILL cleanup (status=$child_status)" >&2
    return 1
  fi
  return 0
}
