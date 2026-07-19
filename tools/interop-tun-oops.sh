#!/usr/bin/env bash
# tools/interop-tun-oops.sh — out-of-process TUN repro harness.
#
# Corrected privileged TUN parity gate. The in-process repro
# (tests::interop_tun_rust_dials_go, run by tools/interop-tun.sh) succeeds
# even though the failure mode only appears when the endpoints live in
# separate processes, like the benchmark harness. This harness runs the
# bench-style split: two independent rustscale TUN nodes as separate OS
# processes under sudo, each with its own TUN device, state directory, and
# full captured log:
#
#   server: up_tun + Linux kernel-state assertions, then TCP/UDP echo on its
#           tailnet IP until one full TCP session completes.
#   client: up_tun + Linux kernel-state assertions in its own process, waits
#           for the server in its netmap, runs the issue-#75-shaped cadenced
#           UDP exchange and a TCP echo roundtrip through the kernel/TUN
#           path, then closes the session so both processes exit 0.
#
# The gate fails unless both processes exit 0 AND both logs contain the full
# structured OOPS_* evidence. Full logs from both sides are always printed.
#
# Usage:
#   source .secrets/tailscale.env && tools/interop-tun-oops.sh
#
# Requires: cargo, curl, jq, sudo (passwordless), iproute2, /dev/net/tun
set -euo pipefail
cd "$(dirname "$0")/.."

# shellcheck disable=SC1091
source tools/bench/lib.sh

UDP_DATAGRAMS=10
TCP_PORT="${OOPS_TCP_PORT:-18282}"
UDP_PORT="${OOPS_UDP_PORT:-18283}"
STATE_DIR=""
SERVER_PID=""
CLIENT_PID=""
SERVER_LOG=""
CLIENT_LOG=""

# ---------------------------------------------------------------------------
# Cleanup: kill both nodes, remove root-owned state, delete the tailnet.
# Installed via `trap oops_cleanup INT TERM EXIT` after provisioning.
# shellcheck disable=SC2329
# ---------------------------------------------------------------------------
oops_cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    sudo -n kill "$SERVER_PID" 2>/dev/null || true
  fi
  if [[ -n "$CLIENT_PID" ]]; then
    sudo -n kill "$CLIENT_PID" 2>/dev/null || true
  fi
  if [[ -n "$STATE_DIR" && -d "$STATE_DIR" ]]; then
    sudo rm -rf "$STATE_DIR"
  fi
  bench_cleanup_tailnet
}

dump_logs() {
  echo "===== BEGIN server full log ====="
  cat "$SERVER_LOG" 2>/dev/null || echo "(server log missing)"
  echo "===== END server full log ====="
  echo "===== BEGIN client full log ====="
  cat "$CLIENT_LOG" 2>/dev/null || echo "(client log missing)"
  echo "===== END client full log ====="
}

fail() {
  echo "[interop-tun-oops] ERROR: $*" >&2
  dump_logs
  exit 1
}

require_marker() {
  local file="$1" marker="$2" label="$3"
  grep -qF "$marker" "$file" || fail "$label log is missing marker: $marker"
}

# Wait for a sudo child to exit within a deadline; return its exit status.
wait_for_exit() {
  local pid="$1" timeout="$2" label="$3"
  local elapsed=0
  while sudo -n kill -0 "$pid" 2>/dev/null; do
    if (( elapsed >= timeout )); then
      fail "$label did not exit within ${timeout}s"
    fi
    sleep 1
    (( elapsed++ ))
  done
  local rc=0
  wait "$pid" || rc=$?
  return "$rc"
}

# ---------------------------------------------------------------------------
# Check tools, then establish the credential-free Linux TUN prerequisites
# before the first tailnet API call.
# ---------------------------------------------------------------------------
for cmd in cargo curl jq; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "[interop-tun-oops] ERROR: required tool '$cmd' not found" >&2
    exit 1
  }
done

tools/interop-tun-preflight.sh

echo "[interop-tun-oops] out-of-process TUN repro: rustscale TUN server <-> rustscale TUN client" >&2

# ---------------------------------------------------------------------------
# Provision ephemeral tailnet.
# ---------------------------------------------------------------------------
bench_provision_tailnet
AUTHKEY=$(bench_mint_authkey)
echo "[interop-tun-oops] tailnet: $BENCH_DNS" >&2

trap oops_cleanup INT TERM EXIT

STATE_DIR=$(mktemp -d /tmp/interop-tun-oops.XXXXXX)
SERVER_LOG="$STATE_DIR/server.log"
CLIENT_LOG="$STATE_DIR/client.log"

# ---------------------------------------------------------------------------
# Build the node binary unprivileged, then run both roles under sudo.
# ---------------------------------------------------------------------------
echo "[interop-tun-oops] building interop-tun-node example (unprivileged)..." >&2
cargo build -p rustscale-tsnet --example interop-tun-node 2>&1 || {
  echo "[interop-tun-oops] ERROR: build failed" >&2
  exit 1
}
NODE_BIN="target/debug/examples/interop-tun-node"
if [[ ! -x "$NODE_BIN" ]]; then
  echo "[interop-tun-oops] ERROR: $NODE_BIN not found" >&2
  exit 1
fi
echo "[interop-tun-oops] node binary: $NODE_BIN" >&2

# ---------------------------------------------------------------------------
# Start the server process.
# ---------------------------------------------------------------------------
echo "[interop-tun-oops] starting server process under sudo..." >&2
# Log redirects intentionally run as the invoking user so the evidence files
# stay user-owned; sudo only elevates the node process itself.
# shellcheck disable=SC2024
sudo -n "$NODE_BIN" server \
  --authkey "$AUTHKEY" \
  --hostname "rs-oops-server-$$" \
  --state-dir "$STATE_DIR/server-state" \
  --tun-name "roops-s" \
  --port "$TCP_PORT" \
  --udp-port "$UDP_PORT" \
  >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
echo "[interop-tun-oops] server PID: $SERVER_PID" >&2

if ! _bench_wait_for_pattern "$SERVER_LOG" "OOPS_SERVER_READY" 150; then
  fail "server never reported OOPS_SERVER_READY"
fi
SERVER_IP=$(grep -m1 -F "OOPS_SERVER_READY" "$SERVER_LOG" \
  | sed -n 's/.*\bip=\([0-9.]*\).*/\1/p')
[[ -n "$SERVER_IP" ]] || fail "could not parse server IP from OOPS_SERVER_READY"
echo "[interop-tun-oops] server tailnet IP: $SERVER_IP" >&2

# ---------------------------------------------------------------------------
# Start the client process; the client drives the UDP cadence exchange and
# the TCP roundtrip, then closes the session.
# ---------------------------------------------------------------------------
echo "[interop-tun-oops] starting client process under sudo..." >&2
# shellcheck disable=SC2024
sudo -n "$NODE_BIN" client \
  --authkey "$AUTHKEY" \
  --hostname "rs-oops-client-$$" \
  --state-dir "$STATE_DIR/client-state" \
  --tun-name "roops-c" \
  --peer "$SERVER_IP" \
  --port "$TCP_PORT" \
  --udp-port "$UDP_PORT" \
  >"$CLIENT_LOG" 2>&1 &
CLIENT_PID=$!
echo "[interop-tun-oops] client PID: $CLIENT_PID" >&2

CLIENT_RC=0
wait_for_exit "$CLIENT_PID" 300 "client" || CLIENT_RC=$?
if (( CLIENT_RC != 0 )); then
  fail "client process exited with status $CLIENT_RC"
fi

# Once the client closes its write side the server finishes its session.
SERVER_RC=0
wait_for_exit "$SERVER_PID" 90 "server" || SERVER_RC=$?
if (( SERVER_RC != 0 )); then
  fail "server process exited with status $SERVER_RC"
fi

# ---------------------------------------------------------------------------
# Assert the complete evidence contract on both sides.
# ---------------------------------------------------------------------------
require_marker "$SERVER_LOG" "OOPS_KERNEL_OK role=server" "server"
require_marker "$SERVER_LOG" "OOPS_SERVER_READY" "server"
require_marker "$SERVER_LOG" "OOPS_SERVER_TCP_ACCEPT" "server"
require_marker "$SERVER_LOG" "OOPS_SERVER_TCP_DONE" "server"
require_marker "$SERVER_LOG" "OOPS_SERVER_DONE" "server"

require_marker "$CLIENT_LOG" "OOPS_KERNEL_OK role=client" "client"
require_marker "$CLIENT_LOG" "OOPS_CLIENT_PEER_OK" "client"
require_marker "$CLIENT_LOG" "OOPS_CLIENT_UDP_ROUNDTRIP_OK count=$UDP_DATAGRAMS" "client"
require_marker "$CLIENT_LOG" "OOPS_CLIENT_TCP_ROUNDTRIP_OK" "client"
require_marker "$CLIENT_LOG" "OOPS_CLIENT_DONE" "client"

# The server must have echoed every cadenced datagram: the roundtrip crossed
# the process boundary exactly UDP_DATAGRAMS times in each direction.
SERVER_UDP_COUNT=$(grep -c -F "OOPS_SERVER_UDP_ECHO" "$SERVER_LOG" || true)
if [[ "$SERVER_UDP_COUNT" -ne "$UDP_DATAGRAMS" ]]; then
  fail "server echoed $SERVER_UDP_COUNT UDP datagrams, expected $UDP_DATAGRAMS"
fi

# ---------------------------------------------------------------------------
# Success: publish the full logs from both processes as the evidence record.
# ---------------------------------------------------------------------------
dump_logs
echo "[interop-tun-oops] PASS: out-of-process TUN split repro — server+client Linux kernel state, issue-#75 UDP cadence, and TCP roundtrip across the process boundary" >&2
