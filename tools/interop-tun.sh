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
    sudo rm -rf "$STATE_DIR"
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

# Establish Linux TUN, iproute2, and privilege prerequisites before the first
# tailnet API call. Once this succeeds, the Rust test must fail on every
# up_tun error; a startup failure can no longer be reported as a skip.
tools/interop-tun-preflight.sh

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
# Build the test binary unprivileged, then exec it under sudo.
# `sudo cargo test` doesn't work reliably — cargo re-execs and may use root's
# toolchain. Instead: compile as the current user, find the test binary, and
# run THAT under sudo with env passed through.
# ---------------------------------------------------------------------------
echo "[interop-tun] building library test binary (unprivileged)..." >&2
cargo test -p rustscale-tsnet --lib --no-run 2>&1 || {
  echo "[interop-tun] ERROR: build failed" >&2
  exit 1
}

# Find the library unit-test binary. Restricting Cargo to --lib prevents an
# integration-test executable from being selected merely because it appeared
# first in Cargo's JSON stream.
TEST_BIN=$(cargo test -p rustscale-tsnet --lib --no-run --message-format=json 2>/dev/null \
  | python3 -c "
import json, sys
for line in sys.stdin:
    try:
        d = json.loads(line)
        target = d.get('target', {})
        if (d.get('profile', {}).get('test')
                and target.get('name') == 'rustscale_tsnet'
                and 'lib' in target.get('kind', [])):
            print(d['executable'])
            break
    except: pass
" 2>/dev/null || echo "")
if [[ -z "$TEST_BIN" || ! -x "$TEST_BIN" ]]; then
  echo "[interop-tun] ERROR: could not find library test binary" >&2
  exit 1
fi
echo "[interop-tun] test binary: $TEST_BIN" >&2

# Fail closed unless the selected executable has exactly one copy of the
# reviewed ignored test. libtest exits successfully when an exact filter matches
# zero tests, so both list selection and its count are contract assertions.
selected_count=$("$TEST_BIN" --ignored --list \
  | grep -Fxc 'tests::interop_tun_rust_dials_go: test' || true)
if [[ "$selected_count" != 1 ]]; then
  echo "[interop-tun] ERROR: exact TUN selector matched $selected_count tests (expected 1)" >&2
  exit 1
fi

# Validate the required interop environment and exec the test within the same
# privileged process. Otherwise a second sudo policy decision could drop the
# variables, causing the ignored test to return early while libtest reports a
# passing test. Preserve only the variables this exact gate consumes.
echo "[interop-tun] running focused TUN regression gate under sudo..." >&2
sudo --preserve-env=TS_E2E_AUTHKEY,TS_INTEROP_GO_IP,TS_INTEROP_GO_NAME,TS_INTEROP_GO_ECHO_PORT,TS_INTEROP_SOCKS \
  sh -c "
    set -eu
    if ! test -n \"\${TS_E2E_AUTHKEY:-}\" ||
       ! test -n \"\${TS_INTEROP_GO_IP:-}\" ||
       ! test -n \"\${TS_INTEROP_GO_NAME:-}\" ||
       ! test -n \"\${TS_INTEROP_GO_ECHO_PORT:-}\" ||
       ! test -n \"\${TS_INTEROP_SOCKS:-}\"; then
      echo '[interop-tun] ERROR: sudo did not preserve the required interop environment' >&2
      exit 1
    fi
    export RUSTSCALE_REQUIRE_TUN_INTEROP=1
    export RUSTSCALE_REQUIRE_TUN_DNS_FAILURE=1
    exec \"\$@\"
  " sh "$TEST_BIN" \
  --ignored --exact tests::interop_tun_rust_dials_go \
  --nocapture --test-threads=1
TEST_RC=$?

echo "[interop-tun] test suite exited with code $TEST_RC" >&2
exit "$TEST_RC"
