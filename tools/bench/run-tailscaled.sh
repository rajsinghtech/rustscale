#!/usr/bin/env bash
# tools/bench/run-tailscaled.sh — tailscaled daemon-proxy evidence harness.
#
# Runs two tailscaled instances in userspace-networking mode on the same
# ephemeral tailnet, then iperf3 throughput + a Python-based latency test
# through the client's SOCKS5 proxy. Produces JSON results comparable to
# rustscale-bench.
#
# Byte path (throughput):
#   iperf3 client → socat (SOCKS5 bridge) → tailscaled B netstack →
#   WireGuard → tailscaled A netstack → tailscale serve --tcp → iperf3 server (localhost)
#
# Byte path (latency):
#   python ping-pong → SOCKS5 → tailscaled B netstack →
#   WireGuard → tailscaled A netstack → tailscale serve --tcp → ncat echo (localhost)
#
# This deliberately retained route is not embedded Go tsnet: it includes
# separate daemon, kernel-loopback TCP, SOCKS5, bridge, and Serve boundaries.
#
# Usage:
#   source .secrets/tailscale.env && tools/bench/run-tailscaled.sh
#
# Requires: tailscaled, tailscale, iperf3, socat, ncat (nmap), python3

set -euo pipefail
cd "$(dirname "$0")/../.."

# shellcheck source=./lib.sh
source tools/bench/lib.sh

DURATION="${BENCH_DURATION:-10}"
PARALLEL="${BENCH_PARALLEL:-1}"
DIRECTION="${BENCH_DIRECTION:-down}"
LATENCY_COUNT="${BENCH_LATENCY_COUNT:-200}"
PORT_THROUGHPUT=5201
PORT_LATENCY=5202
SOCKS_PORT=11080

echo "[bench-go] tailscaled daemon-proxy harness: ${DURATION}s / ${PARALLEL} parallel / ${DIRECTION}"

# Check tools.
for cmd in tailscaled tailscale iperf3 socat ncat python3; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "[bench-go] ERROR: required tool '$cmd' not found" >&2
    exit 1
  }
done

# Provision ephemeral tailnet.
bench_provision_tailnet
AUTHKEY=$(bench_mint_authkey)
echo "[bench-go] authkey minted" >&2

# Timestamped results dir.
STAMP=$(date +%Y%m%d-%H%M%S)
RESULTS_DIR="bench-results/${STAMP}-go"
mkdir -p "$RESULTS_DIR"

# Temp dirs for tailscaled state (unique per instance).
STATE_A=$(mktemp -d /tmp/bench-go-a.XXXXXX)
STATE_B=$(mktemp -d /tmp/bench-go-b.XXXXXX)
SOCK_A="$STATE_A/tailscaled.sock"
SOCK_B="$STATE_B/tailscaled.sock"
LOG_A="$RESULTS_DIR/tailscaled-a.log"
LOG_B="$RESULTS_DIR/tailscaled-b.log"
PID_A=""
PID_B=""
IPERF3_PID=""
NCAT_PID=""

# ---------------------------------------------------------------------------
# Start tailscaled A (server side).
# ---------------------------------------------------------------------------
echo "[bench-go] starting tailscaled A (server)..." >&2
tailscaled \
  --tun=userspace-networking \
  --socket="$SOCK_A" \
  --statedir="$STATE_A" \
  --port=41642 \
  >"$LOG_A" 2>&1 &
PID_A=$!

# Wait for socket to appear.
for i in $(seq 1 30); do
  [[ -S "$SOCK_A" ]] && break
  sleep 1
done
[[ -S "$SOCK_A" ]] || { echo "[bench-go] ERROR: tailscaled A socket never appeared" >&2; cat "$LOG_A" >&2; exit 1; }

tailscale --socket="$SOCK_A" up --authkey="$AUTHKEY" --hostname="bench-go-server-$$" --timeout=60s 2>>"$LOG_A"
SERVER_IP=$(tailscale --socket="$SOCK_A" ip -4 2>>"$LOG_A")
echo "[bench-go] server IP: $SERVER_IP" >&2

# Start iperf3 server on A's localhost (in background, not -D daemon mode).
iperf3 -s -p "$PORT_THROUGHPUT" -B 127.0.0.1 >"$RESULTS_DIR/iperf3-server.log" 2>&1 &
IPERF3_PID=$!
sleep 1

# Expose iperf3 server on the tailnet via tailscale serve --tcp.
tailscale --socket="$SOCK_A" serve --tcp "$PORT_THROUGHPUT" --bg "localhost:$PORT_THROUGHPUT" 2>>"$LOG_A" || {
  echo "[bench-go] WARN: tailscale serve --tcp failed, trying alternate syntax" >&2
  tailscale --socket="$SOCK_A" serve --tcp "$PORT_THROUGHPUT" --bg "$PORT_THROUGHPUT" 2>>"$LOG_A" || {
    echo "[bench-go] ERROR: could not set up tailscale serve --tcp" >&2
    cat "$LOG_A" >&2
    exit 1
  }
}
echo "[bench-go] serve --tcp $PORT_THROUGHPUT configured on A" >&2

# ---------------------------------------------------------------------------
# Start tailscaled B (client side) with SOCKS5 proxy.
# ---------------------------------------------------------------------------
echo "[bench-go] starting tailscaled B (client)..." >&2
tailscaled \
  --tun=userspace-networking \
  --socket="$SOCK_B" \
  --statedir="$STATE_B" \
  --port=41643 \
  --socks5-server="127.0.0.1:$SOCKS_PORT" \
  >"$LOG_B" 2>&1 &
PID_B=$!

for i in $(seq 1 30); do
  [[ -S "$SOCK_B" ]] && break
  sleep 1
done
[[ -S "$SOCK_B" ]] || { echo "[bench-go] ERROR: tailscaled B socket never appeared" >&2; cat "$LOG_B" >&2; exit 1; }

tailscale --socket="$SOCK_B" up --authkey="$AUTHKEY" --hostname="bench-go-client-$$" --timeout=60s 2>>"$LOG_B"
CLIENT_IP=$(tailscale --socket="$SOCK_B" ip -4 2>>"$LOG_B")
echo "[bench-go] client IP: $CLIENT_IP" >&2

# Give peers a moment to establish.
sleep 5

# ---------------------------------------------------------------------------
# Throughput test via iperf3 through SOCKS5 bridge (socat).
# ---------------------------------------------------------------------------
# Start socat: local TCP 5300 → SOCKS5 → A's tailnet IP:PORT_THROUGHPUT
SOCAT_PORT=5300
echo "[bench-go] starting socat SOCKS5 bridge on port $SOCAT_PORT → $SERVER_IP:$PORT_THROUGHPUT" >&2
socat TCP-LISTEN:$SOCAT_PORT,fork,reuseaddr \
  "SOCKS5-CONNECT:127.0.0.1:$SOCKS_PORT:$SERVER_IP:$PORT_THROUGHPUT" \
  >"$RESULTS_DIR/socat.log" 2>&1 &
SOCAT_PID=$!
sleep 1

# Run iperf3 client through the socat bridge.
# iperf3 default = client→server (upload) = our "up"
# iperf3 --reverse = server→client (download) = our "down"
IPERF3_ARGS=(-c 127.0.0.1 -p "$SOCAT_PORT" -t "$DURATION" -J)
if [[ "$DIRECTION" == "down" ]]; then
  IPERF3_ARGS+=(--reverse)
elif [[ "$DIRECTION" == "bidir" ]]; then
  IPERF3_ARGS+=(--bidir)
fi
if [[ "$PARALLEL" -gt 1 ]]; then
  IPERF3_ARGS+=(-P "$PARALLEL")
fi

echo "[bench-go] running iperf3: ${IPERF3_ARGS[*]}" >&2
# Run iperf3 with a timeout (duration + 10s grace).
IPERF3_TIMEOUT=$((DURATION + 10))
IPERF3_JSON=""
if IPERF3_JSON=$(iperf3 "${IPERF3_ARGS[@]}" --connect-timeout 5000 2>"$RESULTS_DIR/iperf3-client.log"); then
  : # success
else
  echo "[bench-go] WARN: iperf3 exited with code $?" >&2
  head -5 "$RESULTS_DIR/iperf3-client.log" >&2 2>/dev/null || true
fi

# Extract throughput from iperf3 JSON.
if [[ -n "${IPERF3_JSON:-}" ]]; then
  TOTAL_MBPS=$(echo "$IPERF3_JSON" | python3 -c "
import json,sys
d=json.load(sys.stdin)
end=d.get('end',{})
s=end.get('sum_received',end.get('sum',{}))
bits=s.get('bits_per_second',0)
print(f'{bits/1e6:.2f}')
" 2>/dev/null || echo "0")
else
  TOTAL_MBPS="0"
  IPERF3_JSON='{"error":"iperf3 failed"}'
fi

# Kill socat.
kill "$SOCAT_PID" 2>/dev/null || true
wait "$SOCAT_PID" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Latency test via Python ping-pong through SOCKS5.
# ---------------------------------------------------------------------------
echo "[bench-go] setting up latency test..." >&2

# Reset serve config and set up echo server on port PORT_LATENCY.
tailscale --socket="$SOCK_A" serve reset 2>>"$LOG_A" || true
ncat -l "$PORT_LATENCY" --exec "/bin/cat" --keep-open >"$RESULTS_DIR/ncat.log" 2>&1 &
NCAT_PID=$!
sleep 1

tailscale --socket="$SOCK_A" serve --tcp "$PORT_LATENCY" --bg "localhost:$PORT_LATENCY" 2>>"$LOG_A" || {
  tailscale --socket="$SOCK_A" serve --tcp "$PORT_LATENCY" --bg "$PORT_LATENCY" 2>>"$LOG_A" || true
}
sleep 2

# Python latency test through SOCKS5.
LATENCY_JSON=$(python3 - "$SERVER_IP" "$PORT_LATENCY" "$SOCKS_PORT" "$LATENCY_COUNT" <<'PYEOF'
import socket, struct, sys, time, json, statistics

target_ip, target_port, socks_port, count = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(('127.0.0.1', socks_port))

    # SOCKS5 handshake: no auth
    s.sendall(b'\x05\x01\x00')
    resp = s.recv(2)
    if resp != b'\x05\x00':
        print(json.dumps({"error": f"socks5 auth failed: {resp.hex()}"}))
        sys.exit(0)

    # SOCKS5 CONNECT
    ip_bytes = socket.inet_aton(target_ip)
    s.sendall(b'\x05\x01\x00\x01' + ip_bytes + struct.pack('>H', target_port))
    resp = s.recv(10)
    if resp[1] != 0:
        print(json.dumps({"error": f"socks5 connect failed: {resp[1]}"}))
        sys.exit(0)

    # Ping-pong
    rtts = []
    for i in range(count):
        start = time.perf_counter_ns()
        s.sendall(b'PING')
        data = b''
        while len(data) < 4:
            chunk = s.recv(4 - len(data))
            if not chunk:
                break
            data += chunk
        elapsed_us = (time.perf_counter_ns() - start) // 1000
        rtts.append(elapsed_us)

    s.close()

    rtts.sort()
    n = len(rtts)
    def pct(p):
        idx = int(round((n - 1) * p))
        return rtts[min(idx, n - 1)]

    result = {
        "tool": "tailscaled-daemon-proxy",
        "mode": "latency",
        "count": n,
        "min_us": rtts[0] if rtts else 0,
        "max_us": rtts[-1] if rtts else 0,
        "mean_us": round(statistics.mean(rtts), 1) if rtts else 0,
        "p50_us": pct(0.50),
        "p95_us": pct(0.95),
        "p99_us": pct(0.99),
    }
    print(json.dumps(result))
except Exception as e:
    print(json.dumps({"error": str(e)}))
PYEOF
)

LAT_P50=$(echo "$LATENCY_JSON" | jq -r '.p50_us // 0')
LAT_P95=$(echo "$LATENCY_JSON" | jq -r '.p95_us // 0')
LAT_P99=$(echo "$LATENCY_JSON" | jq -r '.p99_us // 0')
echo "[bench-go] latency: p50=${LAT_P50}us p95=${LAT_P95}us p99=${LAT_P99}us" >&2

# Kill ncat.
kill "$NCAT_PID" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Extract path class from tailscale status.
# ---------------------------------------------------------------------------
PATH_CLASS=$(tailscale --socket="$SOCK_B" status --json 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin)
peers = d.get('Peer',{})
for k,v in peers.items():
    if 'bench-go-server' in v.get('HostName',''):
        cur = v.get('CurAddr','')
        relay = v.get('Relay','')
        if cur:
            print('direct')
        elif relay:
            print('derp')
        else:
            print('none')
        sys.exit(0)
print('unknown')
" 2>/dev/null || echo "unknown")

echo "[bench-go] path class: $PATH_CLASS" >&2

# ---------------------------------------------------------------------------
# Cleanup: kill tailscaled instances and iperf3 server.
# ---------------------------------------------------------------------------
kill "$PID_A" "$PID_B" "$IPERF3_PID" "$NCAT_PID" 2>/dev/null || true
wait "$PID_A" "$PID_B" 2>/dev/null || true
rm -rf "$STATE_A" "$STATE_B"

# ---------------------------------------------------------------------------
# Write combined results.
# ---------------------------------------------------------------------------
jq -n \
  --arg tool "tailscaled-daemon-proxy" \
  --arg stamp "$STAMP" \
  --arg direction "$DIRECTION" \
  --arg path_class "$PATH_CLASS" \
  --arg total_mbps "$TOTAL_MBPS" \
  --argjson latency "$LATENCY_JSON" \
  --argjson iperf3_raw "${IPERF3_JSON:-null}" \
  '{tool: $tool, stamp: $stamp, direction: $direction, path_class: $path_class,
    throughput_mbps: ($total_mbps | tonumber), latency: $latency,
    iperf3_raw: $iperf3_raw}' \
  > "$RESULTS_DIR/tailscaled.json"

echo "[bench-go] results saved to $RESULTS_DIR/tailscaled.json" >&2
echo ""
echo "═══ tailscaled daemon-proxy results (not embedded tsnet) ═══"
echo "  throughput ($DIRECTION): ${TOTAL_MBPS} Mbps  (path: $PATH_CLASS)"
echo "  latency:  p50=${LAT_P50}us  p95=${LAT_P95}us  p99=${LAT_P99}us"
echo "  results:  $RESULTS_DIR/tailscaled.json"
