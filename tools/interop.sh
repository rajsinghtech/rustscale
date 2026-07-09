#!/usr/bin/env bash
# tools/interop.sh — cross-client interoperability e2e harness.
#
# Provisions an ephemeral tailnet, starts ONE Go tailscaled in userspace-
# networking mode, exposes a `tailscale serve --tcp` echo forwarder, approves
# a subnet route the Go node advertises, exports TS_INTEROP_* + TS_E2E_* env
# vars, then runs the `interop_` test suite against it. Tears everything down
# via trap (kill tailscaled by pidfile, delete tailnet, remove state dirs).
#
# Auth (either):
#   TS_ORG_TOKEN                            — pre-minted org token (CI/WID path)
#   TS_ORG_CLIENT_ID + TS_ORG_CLIENT_SECRET — OAuth client creds (local path;
#                                             `source .secrets/tailscale.env`)
#
# Usage:
#   source .secrets/tailscale.env && tools/interop.sh
#
# Requires: tailscaled, tailscale, python3, curl, jq
set -euo pipefail
cd "$(dirname "$0")/.."

# shellcheck disable=SC1091
source tools/bench/lib.sh

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
GO_HOSTNAME="go-interop-$$"
GO_SOCKS_PORT=11080
GO_ECHO_PORT=18080
GO_ECHO_BACKEND=18081   # localhost backend that ncat/python echoes on
GO_SUBNET="10.99.0.0/24"
STATE_DIR=""
GO_PID=""
ECHO_BACKEND_PID=""
PIDFILE=""

# ---------------------------------------------------------------------------
# Cleanup: kill tailscaled + echo backend, delete tailnet, remove state dir.
# Invoked via `trap interop_cleanup INT TERM EXIT` below.
# shellcheck disable=SC2329
# ---------------------------------------------------------------------------
interop_cleanup() {
  # Kill Go tailscaled.
  if [[ -n "$GO_PID" ]]; then
    kill "$GO_PID" 2>/dev/null || true
    wait "$GO_PID" 2>/dev/null || true
  fi
  # Kill echo backend.
  if [[ -n "$ECHO_BACKEND_PID" ]]; then
    kill "$ECHO_BACKEND_PID" 2>/dev/null || true
    wait "$ECHO_BACKEND_PID" 2>/dev/null || true
  fi
  # Remove state dir.
  if [[ -n "$STATE_DIR" && -d "$STATE_DIR" ]]; then
    rm -rf "$STATE_DIR"
  fi
  # Delete the tailnet (bench_cleanup_tailnet is trapped via bench_provision).
  bench_cleanup_tailnet
}

# ---------------------------------------------------------------------------
# Check tools.
# ---------------------------------------------------------------------------
for cmd in tailscaled tailscale python3 curl jq; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "[interop] ERROR: required tool '$cmd' not found" >&2
    exit 1
  }
done

echo "[interop] rustscale <-> Go tailscaled cross-client e2e" >&2

# ---------------------------------------------------------------------------
# Provision ephemeral tailnet (reuses bench/lib.sh — same provisioning as
# tools/e2e.sh and run-tailscaled.sh). Sets up trap for tailnet cleanup.
# ---------------------------------------------------------------------------
bench_provision_tailnet
AUTHKEY=$(bench_mint_authkey)
echo "[interop] tailnet: $BENCH_DNS" >&2
echo "[interop] authkey minted" >&2

# Register interop_cleanup AFTER bench_provision_tailnet (which traps
# bench_cleanup_tailnet). We need to kill tailscaled BEFORE deleting the
# tailnet, so replace the trap with our combined cleanup.
trap interop_cleanup INT TERM EXIT

# Export shared e2e env vars (same as tools/e2e.sh).
export TS_E2E_TAILNET="$BENCH_DNS"
export TS_E2E_AUTHKEY="$AUTHKEY"
export TS_E2E_API_TOKEN="$BENCH_CHILD_TOKEN"

# Enable HTTPS cert provisioning (best-effort, like e2e.sh).
if curl -sS -o /dev/null -w '%{http_code}' -X PATCH \
     "$BENCH_API/api/v2/tailnet/$BENCH_DNS/settings" \
     -H "Authorization: Bearer $BENCH_CHILD_TOKEN" \
     -H 'Content-Type: application/json' \
     --data '{"httpsEnabled": true}' | grep -q 200; then
  export TS_E2E_HTTPS=1
  export RUSTSCALE_ACME_URL="${RUSTSCALE_ACME_URL:-https://acme-staging-v02.api.letsencrypt.org/directory}"
else
  echo "[interop] WARN: could not enable httpsEnabled" >&2
fi

# ---------------------------------------------------------------------------
# Start a localhost echo backend (python3 — portable across macOS/Linux).
# ---------------------------------------------------------------------------
STATE_DIR=$(mktemp -d /tmp/interop-go.XXXXXX)
GO_SOCK="$STATE_DIR/tailscaled.sock"
GO_LOG="$STATE_DIR/tailscaled.log"
PIDFILE="$STATE_DIR/tailscaled.pid"

echo "[interop] starting echo backend on 127.0.0.1:$GO_ECHO_BACKEND" >&2
python3 -c "
import socket, threading, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', $GO_ECHO_BACKEND))
s.listen(8)
def echo(c):
    try:
        while True:
            data = c.recv(4096)
            if not data:
                break
            c.sendall(data)
    except:
        pass
    finally:
        c.close()
while True:
    c, _ = s.accept()
    threading.Thread(target=echo, args=(c,), daemon=True).start()
" >/dev/null 2>&1 &
ECHO_BACKEND_PID=$!
sleep 1

# ---------------------------------------------------------------------------
# Start Go tailscaled in userspace-networking mode.
# ---------------------------------------------------------------------------
echo "[interop] starting Go tailscaled: hostname=$GO_HOSTNAME socks5=127.0.0.1:$GO_SOCKS_PORT" >&2
tailscaled \
  --tun=userspace-networking \
  --socket="$GO_SOCK" \
  --statedir="$STATE_DIR" \
  --port=41644 \
  --socks5-server="127.0.0.1:$GO_SOCKS_PORT" \
  >"$GO_LOG" 2>&1 &
GO_PID=$!
echo "$GO_PID" > "$PIDFILE"

# Wait for the socket to appear (hard 30s deadline).
for _ in $(seq 1 30); do
  [[ -S "$GO_SOCK" ]] && break
  sleep 1
done
if [[ ! -S "$GO_SOCK" ]]; then
  echo "[interop] ERROR: tailscaled socket never appeared" >&2
  cat "$GO_LOG" >&2
  exit 1
fi
echo "[interop] tailscaled socket ready" >&2

# ---------------------------------------------------------------------------
# tailscale up — advertise the subnet route + tagged authkey.
# ---------------------------------------------------------------------------
echo "[interop] tailscale up (hostname=$GO_HOSTNAME, advertise=$GO_SUBNET)" >&2
tailscale --socket="$GO_SOCK" up \
  --authkey="$AUTHKEY" \
  --hostname="$GO_HOSTNAME" \
  --advertise-routes="$GO_SUBNET" \
  --timeout=60s 2>>"$GO_LOG"

GO_IP=$(tailscale --socket="$GO_SOCK" ip -4 2>>"$GO_LOG")
echo "[interop] Go node IP: $GO_IP" >&2

# Get the Go node's MagicDNS FQDN from tailscale status --json (.Self.DNSName).
GO_NAME=$(tailscale --socket="$GO_SOCK" status --json 2>/dev/null \
  | python3 -c "import json,sys; print(json.load(sys.stdin).get('Self',{}).get('DNSName',''))" 2>/dev/null || echo "")
if [[ -z "$GO_NAME" ]]; then
  echo "[interop] WARN: could not get DNSName from status; falling back to hostname" >&2
  GO_NAME="${GO_HOSTNAME}.${BENCH_DNS}."
fi
echo "[interop] Go MagicDNS name: $GO_NAME" >&2

# ---------------------------------------------------------------------------
# Set up tailscale serve --tcp: forward tailnet port $GO_ECHO_PORT to the
# localhost echo backend on $GO_ECHO_BACKEND.
# ---------------------------------------------------------------------------
echo "[interop] configuring tailscale serve --tcp $GO_ECHO_PORT -> localhost:$GO_ECHO_BACKEND" >&2
tailscale --socket="$GO_SOCK" serve --tcp "$GO_ECHO_PORT" --bg "localhost:$GO_ECHO_BACKEND" 2>>"$GO_LOG" || {
  # Fallback: some versions use a bare port number as the target.
  tailscale --socket="$GO_SOCK" serve --tcp "$GO_ECHO_PORT" --bg "$GO_ECHO_BACKEND" 2>>"$GO_LOG" || {
    echo "[interop] ERROR: tailscale serve --tcp failed" >&2
    cat "$GO_LOG" >&2
    exit 1
  }
}
echo "[interop] serve --tcp $GO_ECHO_PORT configured" >&2

# ---------------------------------------------------------------------------
# Approve the Go node's advertised subnet route via the API.
# ---------------------------------------------------------------------------
echo "[interop] approving Go node's subnet route $GO_SUBNET" >&2
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
  if [[ -n "$DEVICE_ID" ]]; then
    break
  fi
  sleep 2
done

if [[ -n "$DEVICE_ID" ]]; then
  echo "[interop] Go device_id=$DEVICE_ID, approving routes" >&2
  curl -fsS -X POST "$BENCH_API/api/v2/device/$DEVICE_ID/routes" \
    -H "Authorization: Bearer $BENCH_CHILD_TOKEN" \
    -H 'Content-Type: application/json' \
    -d "{\"routes\":[\"$GO_SUBNET\"]}" >/dev/null 2>&1 || {
      echo "[interop] WARN: route approval failed (subnet interop test may fail)" >&2
    }
  echo "[interop] subnet route $GO_SUBNET approved" >&2
else
  echo "[interop] WARN: could not find Go device ID for route approval" >&2
fi

# ---------------------------------------------------------------------------
# Export interop env vars for the test suite.
# ---------------------------------------------------------------------------
export TS_INTEROP_GO_IP="$GO_IP"
export TS_INTEROP_GO_NAME="$GO_NAME"
export TS_INTEROP_GO_ECHO_PORT="$GO_ECHO_PORT"
export TS_INTEROP_SOCKS="127.0.0.1:$GO_SOCKS_PORT"
export TS_INTEROP_GO_SUBNET="$GO_SUBNET"

echo "[interop] env exported:" >&2
echo "[interop]   TS_INTEROP_GO_IP=$GO_IP" >&2
echo "[interop]   TS_INTEROP_GO_NAME=$GO_NAME" >&2
echo "[interop]   TS_INTEROP_GO_ECHO_PORT=$GO_ECHO_PORT" >&2
echo "[interop]   TS_INTEROP_SOCKS=127.0.0.1:$GO_SOCKS_PORT" >&2
echo "[interop]   TS_INTEROP_GO_SUBNET=$GO_SUBNET" >&2

# Give peers a moment to establish.
sleep 3

# ---------------------------------------------------------------------------
# Run the interop test suite.
# ---------------------------------------------------------------------------
echo "[interop] running cargo test -p rustscale-tsnet -- --ignored interop_" >&2
cargo test -p rustscale-tsnet -- --ignored interop_
TEST_RC=$?

echo "[interop] test suite exited with code $TEST_RC" >&2
exit "$TEST_RC"
