#!/usr/bin/env bash
# tools/interop-tun.sh — TUN-mode cross-client interop harness.
#
# Same as tools/interop.sh but the rustscale test binary runs under sudo so
# it can create a real TUN device and apply OS routes. The Go node stays in
# userspace-networking mode (no root for Go). Tests use OS sockets instead
# of Server::dial/listen — traffic flows through the kernel TCP stack and
# the TUN device, exercising the full TUN data-plane pump.
#
# Usage:
#   source .secrets/tailscale.env && tools/interop-tun.sh
#
# Requires: tailscaled, tailscale, python3, curl, jq, sudo
set -euo pipefail
cd "$(dirname "$0")/.."

# shellcheck disable=SC1091
source tools/bench/lib.sh

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
GO_HOSTNAME="go-interop-tun-$$"
GO_SOCKS_PORT=11081
GO_ECHO_PORT=18082
GO_ECHO_BACKEND=18083
GO_SUBNET="10.99.0.0/24"
STATE_DIR=""
GO_PID=""
ECHO_BACKEND_PID=""
PIDFILE=""

# ---------------------------------------------------------------------------
# Cleanup: kill tailscaled + echo backend, delete tailnet, remove state dir.
# Invoked via `trap interop_tun_cleanup INT TERM EXIT` below.
# shellcheck disable=SC2329
# ---------------------------------------------------------------------------
interop_tun_cleanup() {
  if [[ -n "$GO_PID" ]]; then
    kill "$GO_PID" 2>/dev/null || true
    wait "$GO_PID" 2>/dev/null || true
  fi
  if [[ -n "$ECHO_BACKEND_PID" ]]; then
    kill "$ECHO_BACKEND_PID" 2>/dev/null || true
    wait "$ECHO_BACKEND_PID" 2>/dev/null || true
  fi
  if [[ -n "$STATE_DIR" && -d "$STATE_DIR" ]]; then
    rm -rf "$STATE_DIR"
  fi
  bench_cleanup_tailnet
}

# ---------------------------------------------------------------------------
# Check tools.
# ---------------------------------------------------------------------------
for cmd in tailscaled tailscale python3 curl jq; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "[interop-tun] ERROR: required tool '$cmd' not found" >&2
    exit 1
  }
done

# Check sudo availability (TUN device creation requires root).
if [[ "$(id -u)" -ne 0 ]]; then
  if ! sudo -n true 2>/dev/null; then
    echo "[interop-tun] ERROR: TUN mode requires root. Run under sudo or configure passwordless sudo." >&2
    exit 1
  fi
  SUDO="sudo"
else
  SUDO=""
fi

echo "[interop-tun] rustscale TUN <-> Go tailscaled userspace cross-client e2e" >&2

# ---------------------------------------------------------------------------
# Provision ephemeral tailnet.
# ---------------------------------------------------------------------------
bench_provision_tailnet
AUTHKEY=$(bench_mint_authkey)
echo "[interop-tun] tailnet: $BENCH_DNS" >&2

# Replace the bench trap with our combined cleanup.
trap interop_tun_cleanup INT TERM EXIT

export TS_E2E_TAILNET="$BENCH_DNS"
export TS_E2E_AUTHKEY="$AUTHKEY"
export TS_E2E_API_TOKEN="$BENCH_CHILD_TOKEN"

# Enable HTTPS cert provisioning (best-effort).
if curl -sS -o /dev/null -w '%{http_code}' -X PATCH \
     "$BENCH_API/api/v2/tailnet/$BENCH_DNS/settings" \
     -H "Authorization: Bearer $BENCH_CHILD_TOKEN" \
     -H 'Content-Type: application/json' \
     --data '{"httpsEnabled": true}' | grep -q 200; then
  export TS_E2E_HTTPS=1
  export RUSTSCALE_ACME_URL="${RUSTSCALE_ACME_URL:-https://acme-staging-v02.api.letsencrypt.org/directory}"
fi

# ---------------------------------------------------------------------------
# Start echo backend.
# ---------------------------------------------------------------------------
STATE_DIR=$(mktemp -d /tmp/interop-tun-go.XXXXXX)
GO_SOCK="$STATE_DIR/tailscaled.sock"
GO_LOG="$STATE_DIR/tailscaled.log"
PIDFILE="$STATE_DIR/tailscaled.pid"

echo "[interop-tun] starting echo backend on 127.0.0.1:$GO_ECHO_BACKEND" >&2
python3 -c "
import socket, threading
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $GO_ECHO_BACKEND))
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
ECHO_BACKEND_PID=$!
sleep 1

# ---------------------------------------------------------------------------
# Start Go tailscaled in userspace-networking mode (no root for Go).
# ---------------------------------------------------------------------------
echo "[interop-tun] starting Go tailscaled (userspace): hostname=$GO_HOSTNAME" >&2
tailscaled \
  --tun=userspace-networking \
  --socket="$GO_SOCK" \
  --statedir="$STATE_DIR" \
  --port=41645 \
  --socks5-server="127.0.0.1:$GO_SOCKS_PORT" \
  >"$GO_LOG" 2>&1 &
GO_PID=$!
echo "$GO_PID" > "$PIDFILE"

for _ in $(seq 1 30); do
  [[ -S "$GO_SOCK" ]] && break
  sleep 1
done
[[ -S "$GO_SOCK" ]] || { echo "[interop-tun] ERROR: socket never appeared" >&2; cat "$GO_LOG" >&2; exit 1; }

tailscale --socket="$GO_SOCK" up \
  --authkey="$AUTHKEY" \
  --hostname="$GO_HOSTNAME" \
  --advertise-routes="$GO_SUBNET" \
  --timeout=60s 2>>"$GO_LOG"

GO_IP=$(tailscale --socket="$GO_SOCK" ip -4 2>>"$GO_LOG")
GO_NAME=$(tailscale --socket="$GO_SOCK" status --json 2>/dev/null \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('Self',{}).get('DNSName',''))" 2>/dev/null || echo "")
if [[ -z "$GO_NAME" ]]; then
  GO_NAME="${GO_HOSTNAME}.${BENCH_DNS}."
fi
echo "[interop-tun] Go node: ip=$GO_IP name=$GO_NAME" >&2

# Serve echo.
tailscale --socket="$GO_SOCK" serve --tcp "$GO_ECHO_PORT" --bg "localhost:$GO_ECHO_BACKEND" 2>>"$GO_LOG" || {
  tailscale --socket="$GO_SOCK" serve --tcp "$GO_ECHO_PORT" --bg "$GO_ECHO_BACKEND" 2>>"$GO_LOG" || {
    echo "[interop-tun] ERROR: serve --tcp failed" >&2; cat "$GO_LOG" >&2; exit 1
  }
}

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
  echo "[interop-tun] subnet route $GO_SUBNET approved" >&2
fi

# ---------------------------------------------------------------------------
# Export interop env vars.
# ---------------------------------------------------------------------------
export TS_INTEROP_GO_IP="$GO_IP"
export TS_INTEROP_GO_NAME="$GO_NAME"
export TS_INTEROP_GO_ECHO_PORT="$GO_ECHO_PORT"
export TS_INTEROP_SOCKS="127.0.0.1:$GO_SOCKS_PORT"
export TS_INTEROP_GO_SUBNET="$GO_SUBNET"

echo "[interop-tun] env:" >&2
echo "[interop-tun]   TS_INTEROP_GO_IP=$GO_IP" >&2
echo "[interop-tun]   TS_INTEROP_GO_ECHO_PORT=$GO_ECHO_PORT" >&2
echo "[interop-tun]   TS_INTEROP_SOCKS=127.0.0.1:$GO_SOCKS_PORT" >&2
echo "[interop-tun]   TS_INTEROP_GO_SUBNET=$GO_SUBNET" >&2

sleep 3

# ---------------------------------------------------------------------------
# Run the TUN interop test suite under sudo.
# ---------------------------------------------------------------------------
echo "[interop-tun] running cargo test (TUN interop) under $SUDO" >&2
$SUDO env \
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

echo "[interop-tun] test suite exited with code $TEST_RC" >&2
exit "$TEST_RC"
