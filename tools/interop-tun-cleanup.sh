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

interop_tun_cleanup_tailnet() {
  local deadline_seconds="${1:-45}"
  local tailnet_pid=""

  bench_cleanup_tailnet &
  tailnet_pid=$!
  if ! timeout --foreground --signal=TERM --kill-after=2s "${deadline_seconds}s" \
      tail --pid="$tailnet_pid" -f /dev/null; then
    kill -TERM "$tailnet_pid" 2>/dev/null || true
    kill -KILL "$tailnet_pid" 2>/dev/null || true
    wait "$tailnet_pid" 2>/dev/null || true
    echo "[interop-tun] ERROR: ephemeral tailnet cleanup exceeded ${deadline_seconds}s" >&2
    return 1
  fi
  if ! wait "$tailnet_pid"; then
    echo "[interop-tun] ERROR: ephemeral tailnet cleanup failed" >&2
    return 1
  fi
  return 0
}
