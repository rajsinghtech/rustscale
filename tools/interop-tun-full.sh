#!/usr/bin/env bash
# tools/interop-tun-full.sh — full TUN mode both sides (Linux netns, CI-only).
#
# Both rustscale and Go tailscaled run in real TUN mode inside isolated
# network namespaces connected via a veth bridge. This tests subnet-route
# forwarding and exit-node data-path where Go also needs a kernel interface.
#
# Architecture:
#   netns-rust (rustscale TUN) ←veth-pair→ netns-go (Go TUN)
#
# The veth bridge provides layer-2 connectivity between the two namespaces
# so both TUN devices can send/receive real IP packets through their
# kernel stacks. DERP and control traffic go through the host's default
# route (each namespace routes 0.0.0.0/0 via the veth to the host).
#
# Usage (CI only — requires root + Linux):
#   sudo tools/interop-tun-full.sh
#
# Requires: tailscaled, tailscale, python3, curl, jq, ip (iproute2), unshare
set -euo pipefail
cd "$(dirname "$0")/.."

# shellcheck disable=SC1091
source tools/bench/lib.sh

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
GO_HOSTNAME="go-interop-tunfull-$$"
GO_ECHO_PORT=18084
GO_SUBNET="10.99.0.0/24"
NS_RUST="ts-interop-rust-$$"
NS_GO="ts-interop-go-$$"
VETH_RUST="veth-rust-$$"
VETH_GO="veth-go-$$"
BRIDGE="ts-interop-br-$$"
STATE_DIR_RUST=""
STATE_DIR_GO=""
GO_PID=""
RUST_PID=""
ECHO_GO_PID=""

# ---------------------------------------------------------------------------
# Cleanup: kill processes, delete namespaces, bridge, state dirs, tailnet.
# shellcheck disable=SC2329
# ---------------------------------------------------------------------------
interop_tunfull_cleanup() {
  # Kill processes in namespaces.
  if [[ -n "$RUST_PID" ]]; then kill "$RUST_PID" 2>/dev/null || true; fi
  if [[ -n "$GO_PID" ]]; then kill "$GO_PID" 2>/dev/null || true; fi
  if [[ -n "$ECHO_GO_PID" ]]; then kill "$ECHO_GO_PID" 2>/dev/null || true; fi

  # Delete namespaces (also removes veth peers).
  ip netns del "$NS_RUST" 2>/dev/null || true
  ip netns del "$NS_GO" 2>/dev/null || true

  # Delete bridge.
  ip link del "$BRIDGE" 2>/dev/null || true

  # Remove state dirs.
  [[ -n "$STATE_DIR_RUST" && -d "$STATE_DIR_RUST" ]] && rm -rf "$STATE_DIR_RUST"
  [[ -n "$STATE_DIR_GO" && -d "$STATE_DIR_GO" ]] && rm -rf "$STATE_DIR_GO"

  bench_cleanup_tailnet
}

# ---------------------------------------------------------------------------
# Check prerequisites.
# ---------------------------------------------------------------------------
if [[ "$(id -u)" -ne 0 ]]; then
  echo "[interop-tun-full] ERROR: requires root (sudo)" >&2
  exit 1
fi
for cmd in tailscaled tailscale ip python3 curl jq; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "[interop-tun-full] ERROR: '$cmd' not found" >&2
    exit 1
  }
done

echo "[interop-tun-full] Full TUN both sides (Linux netns)" >&2

# ---------------------------------------------------------------------------
# Provision ephemeral tailnet.
# ---------------------------------------------------------------------------
bench_provision_tailnet
AUTHKEY=$(bench_mint_authkey)
echo "[interop-tun-full] tailnet: $BENCH_DNS" >&2

trap interop_tunfull_cleanup INT TERM EXIT

export TS_E2E_TAILNET="$BENCH_DNS"
export TS_E2E_AUTHKEY="$AUTHKEY"
export TS_E2E_API_TOKEN="$BENCH_CHILD_TOKEN"

# ---------------------------------------------------------------------------
# Create network namespaces + veth bridge.
# ---------------------------------------------------------------------------
echo "[interop-tun-full] creating namespaces: $NS_RUST, $NS_GO" >&2
ip netns add "$NS_RUST"
ip netns add "$NS_GO"

# Create veth pair connecting the two namespaces.
ip link add "$VETH_RUST" type veth peer name "$VETH_GO"
ip link set "$VETH_RUST" netns "$NS_RUST"
ip link set "$VETH_GO" netns "$NS_GO"

# Configure addresses in each namespace.
ip netns exec "$NS_RUST" ip addr add 172.20.1.1/24 dev "$VETH_RUST"
ip netns exec "$NS_RUST" ip link set "$VETH_RUST" up
ip netns exec "$NS_RUST" ip link set lo up
# Default route via the veth (for DERP/control traffic to reach the host).
# In a real setup, the host would forward. For CI we rely on the host's
# network being accessible from the namespace via the veth.
ip netns exec "$NS_RUST" ip route add default dev "$VETH_RUST" 2>/dev/null || true

ip netns exec "$NS_GO" ip addr add 172.20.1.2/24 dev "$VETH_GO"
ip netns exec "$NS_GO" ip link set "$VETH_GO" up
ip netns exec "$NS_GO" ip link set lo up
ip netns exec "$NS_GO" ip route add default dev "$VETH_GO" 2>/dev/null || true

echo "[interop-tun-full] namespaces configured" >&2

# ---------------------------------------------------------------------------
# Start Go tailscaled in TUN mode inside ns-go.
# ---------------------------------------------------------------------------
STATE_DIR_GO=$(mktemp -d /tmp/interop-tunfull-go.XXXXXX)
GO_SOCK="$STATE_DIR_GO/tailscaled.sock"
GO_LOG="$STATE_DIR_GO/tailscaled.log"

echo "[interop-tun-full] starting Go tailscaled (TUN) in $NS_GO" >&2
ip netns exec "$NS_GO" tailscaled \
  --socket="$GO_SOCK" \
  --statedir="$STATE_DIR_GO" \
  --port=41646 \
  >"$GO_LOG" 2>&1 &
GO_PID=$!

for _ in $(seq 1 30); do
  [[ -S "$GO_SOCK" ]] && break
  sleep 1
done
[[ -S "$GO_SOCK" ]] || { echo "[interop-tun-full] ERROR: Go socket never appeared" >&2; cat "$GO_LOG" >&2; exit 1; }

ip netns exec "$NS_GO" tailscale --socket="$GO_SOCK" up \
  --authkey="$AUTHKEY" \
  --hostname="$GO_HOSTNAME" \
  --advertise-routes="$GO_SUBNET" \
  --timeout=60s 2>>"$GO_LOG"

GO_IP=$(ip netns exec "$NS_GO" tailscale --socket="$GO_SOCK" ip -4 2>>"$GO_LOG")
echo "[interop-tun-full] Go node: ip=$GO_IP" >&2

# Approve subnet route.
DEVICE_ID=""
for _ in $(seq 1 30); do
  DEVICE_ID=$(curl -fsS "$BENCH_API/api/v2/tailnet/$BENCH_DNS/devices" \
    -H "Authorization: Bearer $BENCH_CHILD_TOKEN" 2>/dev/null \
    | python3 -c "
import json,sys
d=json.load(sys.stdin)
for dev in d.get('devices',[]):
    if '$GO_HOSTNAME' in dev.get('name',''):
        print(dev.get('id',''))
        break
" 2>/dev/null || echo "")
  if [[ -n "$DEVICE_ID" ]]; then break; fi
  sleep 2
done
if [[ -n "$DEVICE_ID" ]]; then
  curl -fsS -X POST "$BENCH_API/api/v2/device/$DEVICE_ID/routes" \
    -H "Authorization: Bearer $BENCH_CHILD_TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{\"routes\":[\"$GO_SUBNET\"]}" >/dev/null 2>&1 || true
fi

# Set up Go serve echo (in TUN mode, Go can use its tailnet IP directly).
# Start a localhost echo backend in ns-go.
ip netns exec "$NS_GO" python3 -c "
import socket, threading
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $GO_ECHO_PORT))
s.listen(8)
def echo(c):
    try:
        while True:
            data = c.recv(4096)
            if not data: break
            c.sendall(data)
    except: pass
    finally: c.close()
while True:
    c, _ = s.accept()
    threading.Thread(target=echo, args=(c,), daemon=True).start()
" >/dev/null 2>&1 &
ECHO_GO_PID=$!

# tailscale serve to forward tailnet port → localhost echo.
ip netns exec "$NS_GO" tailscale --socket="$GO_SOCK" serve --tcp "$GO_ECHO_PORT" --bg "localhost:$GO_ECHO_PORT" 2>>"$GO_LOG" || true

# ---------------------------------------------------------------------------
# Export env vars for the rustscale test binary (runs in ns-rust).
# ---------------------------------------------------------------------------
GO_NAME=$(ip netns exec "$NS_GO" tailscale --socket="$GO_SOCK" status --json 2>/dev/null \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('Self',{}).get('DNSName',''))" 2>/dev/null || echo "")
if [[ -z "$GO_NAME" ]]; then
  GO_NAME="${GO_HOSTNAME}.${BENCH_DNS}."
fi

export TS_INTEROP_GO_IP="$GO_IP"
export TS_INTEROP_GO_NAME="$GO_NAME"
export TS_INTEROP_GO_ECHO_PORT="$GO_ECHO_PORT"
export TS_INTEROP_GO_SUBNET="$GO_SUBNET"
# No SOCKS5 in full TUN mode (Go has a real interface).
export TS_INTEROP_SOCKS=""

echo "[interop-tun-full] env:" >&2
echo "[interop-tun-full]   TS_INTEROP_GO_IP=$GO_IP" >&2
echo "[interop-tun-full]   TS_INTEROP_GO_NAME=$GO_NAME" >&2
echo "[interop-tun-full]   TS_INTEROP_GO_ECHO_PORT=$GO_ECHO_PORT" >&2

sleep 3

# ---------------------------------------------------------------------------
# Run the rustscale TUN interop tests inside ns-rust.
# ---------------------------------------------------------------------------
echo "[interop-tun-full] running cargo test (TUN interop) in $NS_RUST" >&2
ip netns exec "$NS_RUST" env \
  TS_E2E_TAILNET="$TS_E2E_TAILNET" \
  TS_E2E_AUTHKEY="$TS_E2E_AUTHKEY" \
  TS_E2E_API_TOKEN="$TS_E2E_API_TOKEN" \
  TS_INTEROP_GO_IP="$TS_INTEROP_GO_IP" \
  TS_INTEROP_GO_NAME="$TS_INTEROP_GO_NAME" \
  TS_INTEROP_GO_ECHO_PORT="$TS_INTEROP_GO_ECHO_PORT" \
  TS_INTEROP_SOCKS="$TS_INTEROP_SOCKS" \
  TS_INTEROP_GO_SUBNET="$TS_INTEROP_GO_SUBNET" \
  PATH="$PATH" \
  HOME="$HOME" \
  cargo test -p rustscale-tsnet -- --ignored interop_tun_
TEST_RC=$?

echo "[interop-tun-full] test suite exited with code $TEST_RC" >&2
exit "$TEST_RC"
