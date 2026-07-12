#!/usr/bin/env bash
# tools/bench/run-tailscale-rs.sh — local A/B harness for tsrs-bench (tailscale-rs).
#
# Starts two tsrs-bench processes (server+client) joining an ephemeral
# tailnet, runs throughput + latency tests, and collects JSON results into
# bench-results/<timestamp>/tailscale-rs.json.
#
# Usage:
#   source .secrets/tailscale.env && tools/bench/run-tailscale-rs.sh
#
# Options (env vars):
#   BENCH_DURATION   — test duration in seconds (default 10)
#   BENCH_PARALLEL   — parallel connections (default 1)
#   BENCH_DIRECTION  — up|down|bidir (default "down")
#   BENCH_LATENCY_COUNT — ping count for latency test (default 200)
#   BENCH_PORT       — server listen port (default 5201)

set -euo pipefail
cd "$(dirname "$0")/../.."

# shellcheck source=./lib.sh
source tools/bench/lib.sh

DURATION="${BENCH_DURATION:-10}"
PARALLEL="${BENCH_PARALLEL:-1}"
DIRECTION="${BENCH_DIRECTION:-down}"
LATENCY_COUNT="${BENCH_LATENCY_COUNT:-200}"
PORT="${BENCH_PORT:-5201}"

TS="${DURATION:-10}s / ${PARALLEL:-1} parallel / ${DIRECTION:-down}"

echo "[bench] tsrs-bench local harness: $TS"

# Build the bench binary.
echo "[bench] building tsrs-bench..." >&2
cargo build --manifest-path crates/bench-tsrs/Cargo.toml --release 2>&1 | tail -1 >&2
BENCH_BIN="crates/bench-tsrs/target/release/tsrs-bench"

# Provision ephemeral tailnet.
bench_provision_tailnet
AUTHKEY=$(bench_mint_authkey)
echo "[bench] authkey minted" >&2

# Timestamped results dir.
STAMP=$(date +%Y%m%d-%H%M%S)
RESULTS_DIR="bench-results/$STAMP"
mkdir -p "$RESULTS_DIR"

# Temp dirs for state (unique per process to avoid key conflicts).
STATE_A=$(mktemp -d /tmp/tsrs-bench-a.XXXXXX)
STATE_B=$(mktemp -d /tmp/tsrs-bench-b.XXXXXX)
SERVER_LOG="$RESULTS_DIR/server.log"
CLIENT_LOG="$RESULTS_DIR/client.log"
SERVER_READY="$RESULTS_DIR/server_ready.flag"

# ---------------------------------------------------------------------------
# Start the server process.
# ---------------------------------------------------------------------------
echo "[bench] starting server..." >&2
"$BENCH_BIN" server \
  --authkey "$AUTHKEY" \
  --port "$PORT" \
  --hostname "bench-tsrs-server-$$" \
  --state-dir "$STATE_A" \
  >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
echo "[bench] server PID: $SERVER_PID" >&2

# Wait for server to print its IP.
if ! _bench_wait_for_pattern "$SERVER_LOG" "BENCH_READY 1" 120; then
  echo "[bench] ERROR: server failed to start" >&2
  echo "--- server log ---" >&2; cat "$SERVER_LOG" >&2
  kill "$SERVER_PID" 2>/dev/null || true
  exit 1
fi
SERVER_IP=$(grep '^BENCH_IP ' "$SERVER_LOG" | awk '{print $2}')
echo "[bench] server IP: $SERVER_IP" >&2

# Give the server a few seconds to stabilize after printing ready.
sleep 3

# ---------------------------------------------------------------------------
# Run throughput test.
# ---------------------------------------------------------------------------
TARGET="${SERVER_IP}:${PORT}"
echo "[bench] throughput test: direction=$DIRECTION duration=${DURATION}s parallel=$PARALLEL" >&2

THROUGHPUT_JSON=$("$BENCH_BIN" client \
  --authkey "$AUTHKEY" \
  --target "$TARGET" \
  --duration "$DURATION" \
  --direction "$DIRECTION" \
  --parallel "$PARALLEL" \
  --hostname "bench-tsrs-client-$$" \
  --state-dir "$STATE_B" \
  --json 2>"$CLIENT_LOG")

# Extract path class from the JSON.
PATH_CLASS=$(echo "$THROUGHPUT_JSON" | jq -r '.path_class // "unknown"')
TOTAL_MBPS=$(echo "$THROUGHPUT_JSON" | jq -r '.total_mbps // 0')
echo "[bench] throughput result: ${TOTAL_MBPS} Mbps (path: $PATH_CLASS)" >&2

# Save throughput JSON.
echo "$THROUGHPUT_JSON" | jq '.' > "$RESULTS_DIR/tailscale-rs-throughput.json"

# ---------------------------------------------------------------------------
# Run latency test (reuse the same client state dir for key persistence).
# ---------------------------------------------------------------------------
STATE_C=$(mktemp -d /tmp/tsrs-bench-lat.XXXXXX)
echo "[bench] latency test: count=$LATENCY_COUNT" >&2

LATENCY_JSON=$("$BENCH_BIN" latency \
  --authkey "$AUTHKEY" \
  --target "$TARGET" \
  --count "$LATENCY_COUNT" \
  --hostname "bench-tsrs-latency-$$" \
  --state-dir "$STATE_C" \
  --json 2>>"$CLIENT_LOG")

LAT_P50=$(echo "$LATENCY_JSON" | jq -r '.p50_us // 0')
LAT_P95=$(echo "$LATENCY_JSON" | jq -r '.p95_us // 0')
LAT_P99=$(echo "$LATENCY_JSON" | jq -r '.p99_us // 0')
LAT_PATH=$(echo "$LATENCY_JSON" | jq -r '.path_class // "unknown"')
echo "[bench] latency result: p50=${LAT_P50}us p95=${LAT_P95}us p99=${LAT_P99}us (path: $LAT_PATH)" >&2

echo "$LATENCY_JSON" | jq '.' > "$RESULTS_DIR/tailscale-rs-latency.json"

# ---------------------------------------------------------------------------
# Kill the server.
# ---------------------------------------------------------------------------
kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true

# Cleanup temp dirs.
rm -rf "$STATE_A" "$STATE_B" "$STATE_C"

# ---------------------------------------------------------------------------
# Write combined results.
# ---------------------------------------------------------------------------
jq -n \
  --argjson throughput "$THROUGHPUT_JSON" \
  --argjson latency "$LATENCY_JSON" \
  --arg stamp "$STAMP" \
  --arg direction "$DIRECTION" \
  --arg path_class "$PATH_CLASS" \
  '{tool: "tsrs-bench", stamp: $stamp, throughput: $throughput, latency: $latency}' \
  > "$RESULTS_DIR/tailscale-rs.json"

echo "[bench] results saved to $RESULTS_DIR/tailscale-rs.json" >&2
echo ""
echo "=== tsrs-bench results ==="
echo "  throughput ($DIRECTION): ${TOTAL_MBPS} Mbps  (path: $PATH_CLASS)"
echo "  latency:  p50=${LAT_P50}us  p95=${LAT_P95}us  p99=${LAT_P99}us  (path: $LAT_PATH)"
echo "  results:  $RESULTS_DIR/tailscale-rs.json"
