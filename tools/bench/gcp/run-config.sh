#!/usr/bin/env bash
# tools/bench/gcp/run-config.sh — run ONE bench config across two GCP VMs.
#
# Usage:
#   run-config.sh CONFIG SERVER_VM CLIENT_VM SERVER_ZONE CLIENT_ZONE \
#                 AUTHKEY RESULTS_DIR SERVER_HOSTNAME CLIENT_HOSTNAME
#
# CONFIG ∈ {rs-userspace, rs-tun, ts-userspace, ts-tun}
# Emits <RESULTS_DIR>/<CONFIG>.json with the schema from docs/phase-gcp-bench.md.
#
# Environment:
#   BENCH_MATRIX  — optional, set by run-matrix.sh; "topo/path" for tagging.
#   GCP_DRY_RUN   — when set, commands are echoed not executed (still emits a stub JSON).
#
# Returns 0 on success.

set -euo pipefail

# shellcheck source=./lib.sh
source "$(dirname "$0")/lib.sh"
# shellcheck source=./footprint.sh
source "$(dirname "$0")/footprint.sh"

# ---------------------------------------------------------------------------
# Usage.
# ---------------------------------------------------------------------------
usage() {
  cat >&2 <<EOF
usage: $0 CONFIG SERVER_VM CLIENT_VM SERVER_ZONE CLIENT_ZONE \
AUTHKEY RESULTS_DIR SERVER_HOSTNAME CLIENT_HOSTNAME

CONFIG: rs-userspace | rs-tun | ts-userspace | ts-tun
EOF
  exit 2
}

[[ $# -ge 9 ]] || usage

CONFIG="$1"
SVM="$2"
CVM="$3"
SZONE="$4"
CZONE="$5"
AUTHKEY="$6"
RDIR="$7"
SHOST="$8"
CHOST="$9"

PARALLELS=(1 10 25 50 100)
DURATION=30
LATENCY_COUNT=200
PORT=5201

# BENCH_MATRIX is "<topo>/<path>" — set by run-matrix.sh.
TOPOLOGY="${BENCH_MATRIX%%/*}"
PATH_TAG="${BENCH_MATRIX##*/}"
[[ -z "${TOPOLOGY:-}" ]] && TOPOLOGY="unknown"
[[ -z "${PATH_TAG:-}" ]] && PATH_TAG="unknown"

mkdir -p "$RDIR"
OUT="$RDIR/$CONFIG.json"

# Rust env vars for non-root user.
export RUSTUP_HOME=/opt/rust CARGO_HOME=/opt/rust/cargo

echo "[gcp] config=$CONFIG topo=$TOPOLOGY path=$PATH_TAG server=$SVM client=$CVM" >&2

# ---------------------------------------------------------------------------
# Helpers shared across all configs.
# ---------------------------------------------------------------------------

# Capture the last N lines (default 40) of a remote log file.
# Args: VM ZONE LOGFILE [LINES]
capture_log_tail() {
  local vm="$1" zone="$2" logfile="$3" lines="${4:-40}"
  ssh_cmd "$vm" "$zone" "tail -n $lines '$logfile' 2>/dev/null" 2>/dev/null \
    || echo "(log unavailable: $logfile on $vm)"
}

# Wait for a tailscale peer to appear on a VM.
# Polls `tailscale status --json` until Peer count > 0.
# Args: VM ZONE SOCK [TIMEOUT=120]
wait_ts_peer() {
  local vm="$1" zone="$2" sock="$3" timeout="${4:-120}"
  local elapsed=0
  while (( elapsed < timeout )); do
    local count
    count=$(ssh_cmd "$vm" "$zone" \
      "tailscale --socket=$sock status --json 2>/dev/null \
       | python3 -c 'import json,sys; print(len(json.load(sys.stdin).get(\"Peer\",{})))' 2>/dev/null" \
      2>/dev/null || echo "0")
    if [[ "$count" -gt 0 ]] 2>/dev/null; then
      return 0
    fi
    sleep 5
    elapsed=$((elapsed + 5))
  done
  return 1
}

# Write a stub JSON (used in dry-run or on failure).
# Args: ERROR_STRING [LOG_TAIL]
emit_stub() {
  local err="${1:-dry-run}"
  local log_tail="${2:-}"
  local tool mode
  case "$CONFIG" in
    rs-*) tool=rustscale; mode=userspace ;;
    ts-*) tool=tailscaled; mode=tun ;;
  esac
  [[ "$CONFIG" == *-tun ]] && mode=tun
  [[ "$CONFIG" == *-userspace ]] && mode=userspace

  # Use Python so log_tail (which may contain quotes, newlines, etc.) is
  # properly JSON-escaped. Pass log_tail via a temp file to avoid argv limits.
  local _lt_tmp
  _lt_tmp=$(mktemp)
  printf '%s' "$log_tail" > "$_lt_tmp"
  python3 - "$CONFIG" "$TOPOLOGY" "$PATH_TAG" "$tool" "$mode" "$err" \
    "$DURATION" "$LATENCY_COUNT" "$_lt_tmp" >"$OUT" <<'PYEOF'
import json, sys
config, topo, path_tag, tool, mode, err, dur, lat_count, lt_path = sys.argv[1:10]
try:
    with open(lt_path) as f:
        log_tail = f.read()
except OSError:
    log_tail = ""
obj = {
    "tool": tool,
    "mode": mode,
    "topology": topo,
    "path": path_tag,
    "config": config,
    "error": err,
    "log_tail": log_tail,
    "throughput": [
        {"parallel": p, "mbps": 0, "duration_s": int(dur)}
        for p in [1, 10, 25, 50, 100]
    ],
    "latency": {"p50_us": 0, "p95_us": 0, "p99_us": 0, "count": int(lat_count)},
    "footprint": {"binary_size_bytes": 0, "rss_peak_kb": 0, "rss_avg_kb": 0,
                   "cpu_peak_pct": 0, "cpu_avg_pct": 0, "samples": 0},
    "path_class_reported": path_tag,
}
print(json.dumps(obj, indent=2))
PYEOF
  rm -f "$_lt_tmp"
}

if [[ -n "${GCP_DRY_RUN:-}" ]]; then
  echo "[dry-run] would run $CONFIG on $SVM/$CVM ($TOPOLOGY/$PATH_TAG)" >&2
  emit_stub "dry-run"
  exit 0
fi

# Helper: extract throughput mbps from a JSON blob on stdin.
# Handles both rustscale-bench JSON (.total_mbps) and iperf3 JSON (.end.sum_received.bits_per_second).
iperf3_mbps() {
  python3 -c '
import json,sys
d=json.load(sys.stdin)
if "total_mbps" in d:
    print("%.2f" % d["total_mbps"])
elif "down_mbps" in d:
    print("%.2f" % d["down_mbps"])
elif "up_mbps" in d:
    print("%.2f" % d["up_mbps"])
else:
    end=d.get("end",{})
    s=end.get("sum_received",end.get("sum",{}))
    print("%.2f" % (s.get("bits_per_second",0)/1e6))
'
}

# Helper: parse ping rtt percentiles from ping stdout on stdin.
# Emits JSON: {"p50_us":..,"p95_us":..,"p99_us":..,"count":..}
ping_latency() {
  python3 -c '
import json,sys,re
rtts=[]
for line in sys.stdin:
    m=re.search(r"time=([0-9.]+ ms|([0-9.]+))", line)
    if m:
        s=m.group(1)
        if "ms" in s:
            rtts.append(float(s.replace(" ms",""))*1000)
        else:
            rtts.append(float(s)*1000)
rtts.sort()
n=len(rtts)
def pct(p):
    return rtts[min(int(round((n-1)*p)), n-1)] if rtts else 0
print(json.dumps({
    "p50_us": round(pct(0.50)),
    "p95_us": round(pct(0.95)),
    "p99_us": round(pct(0.99)),
    "count": n,
}))
'
}

# ===========================================================================
# Config: rs-userspace — rustscale-bench server + client
# ===========================================================================
run_rs_userspace() {
  echo "[gcp] rs-userspace: starting bench server on $SVM" >&2
  ssh_cmd "$SVM" "$SZONE" \
    "nohup /opt/rustscale/target/release/rustscale-bench server \
       --authkey $AUTHKEY --port $PORT --hostname $SHOST --state-dir /tmp/rs-srv \
       > /tmp/rs-srv.log 2>&1 & echo \$! > /tmp/rs-srv.pid"

  # Wait for BENCH_READY 1. DERP path (UDP blocked) can take significantly longer
  # than direct for the control plane handshake and IP assignment.
  local timeout=180
  [[ "$PATH_TAG" == "derp" ]] && timeout=300
  local elapsed=0
  while (( elapsed < timeout )); do
    if ssh_cmd "$SVM" "$SZONE" 'grep -q "BENCH_READY 1" /tmp/rs-srv.log 2>/dev/null' 2>/dev/null; then
      break
    fi
    sleep 5
    elapsed=$((elapsed + 5))
  done
  if (( elapsed >= 180 )); then
    echo "[gcp] ERROR: rustscale-bench server never became ready" >&2
    local _lt
    _lt=$(capture_log_tail "$SVM" "$SZONE" /tmp/rs-srv.log)
    emit_stub "server-not-ready" "$_lt"
    return 1
  fi

  local server_ip
  server_ip=$(ssh_cmd "$SVM" "$SZONE" "grep '^BENCH_IP ' /tmp/rs-srv.log | awk '{print \$2}'")
  echo "[gcp] rs-userspace: server IP=$server_ip" >&2

  # Footprint sampler for the server PID.
  local srv_pid
  srv_pid=$(ssh_cmd "$SVM" "$SZONE" 'cat /tmp/rs-srv.pid')
  remote_start_footprint "$SVM" "$SZONE" "$srv_pid" /tmp/rs-srv.footprint

  # Throughput sweep on client.
  local tp_json="[]"
  for N in "${PARALLELS[@]}"; do
    echo "[gcp] rs-userspace: throughput N=$N" >&2
    local mbps
    mbps=$(ssh_cmd "$CVM" "$CZONE" \
      "/opt/rustscale/target/release/rustscale-bench client \
         --authkey $AUTHKEY --target $server_ip:$PORT --duration $DURATION \
         --parallel $N --hostname $CHOST-$N --state-dir /tmp/rs-cli-$N --json 2>/tmp/rs-cli-$N.log" \
      | iperf3_mbps 2>/dev/null || echo "0")
    tp_json=$(echo "$tp_json" | python3 -c "
import json,sys
arr=json.load(sys.stdin)
arr.append({'parallel': $N, 'mbps': float('$mbps'), 'duration_s': $DURATION})
print(json.dumps(arr))
")
    sleep 3
  done

  # Latency.
  echo "[gcp] rs-userspace: latency" >&2
  local lat_json
  lat_json=$(ssh_cmd "$CVM" "$CZONE" \
    "/opt/rustscale/target/release/rustscale-bench latency \
       --authkey $AUTHKEY --target $server_ip:$PORT --count $LATENCY_COUNT \
       --hostname $CHOST-lat --state-dir /tmp/rs-cli-lat --json 2>/tmp/rs-cli-lat.log" || echo '{}')

  local path_class
  path_class=$(echo "$lat_json" | python3 -c "import json,sys; print(json.load(sys.stdin).get('path_class','unknown'))" 2>/dev/null || echo unknown)

  # Stop footprint, parse.
  local foot_json
  foot_json=$(remote_stop_footprint "$SVM" "$SZONE" /tmp/rs-srv.footprint)

  # Binary size.
  local bin_size
  bin_size=$(ssh_cmd "$SVM" "$SZONE" 'stat -c %s /opt/rustscale/target/release/rustscale-bench 2>/dev/null || echo 0')

  # Kill server.
  ssh_cmd "$SVM" "$SZONE" "kill \$(cat /tmp/rs-srv.pid 2>/dev/null) 2>/dev/null; pkill -f rustscale-bench 2>/dev/null" || true

  # Emit result JSON.
  python3 - "$CONFIG" "$TOPOLOGY" "$PATH_TAG" "$path_class" "$bin_size" "$tp_json" "$lat_json" "$foot_json" >"$OUT" <<'PYEOF'
import json, sys
config, topo, path_tag, path_class, bin_size, tp, lat, foot = sys.argv[1:9]
obj = {
    "tool": "rustscale",
    "mode": "userspace",
    "topology": topo,
    "path": path_tag,
    "config": config,
    "error": "",
    "log_tail": "",
    "throughput": json.loads(tp),
    "latency": json.loads(lat) if lat and lat != "{}" else {"p50_us":0,"p95_us":0,"p99_us":0,"count":0},
    "footprint": dict(json.loads(foot), binary_size_bytes=int(bin_size)),
    "path_class_reported": path_class,
}
print(json.dumps(obj, indent=2))
PYEOF
  echo "[gcp] rs-userspace: wrote $OUT" >&2
}

# ===========================================================================
# Config: rs-tun — rustscale-tun on both VMs + kernel iperf3
# ===========================================================================
run_rs_tun() {
  echo "[gcp] rs-tun: starting tunnels on both VMs" >&2
  # Remove stale log/pid files from a prior run (may be root-owned).
  ssh_sudo "$SVM" "$SZONE"  'rm -f /tmp/rs-tun-srv.log /tmp/rs-tun-srv.pid'
  ssh_sudo "$CVM" "$CZONE"  'rm -f /tmp/rs-tun-cli.log /tmp/rs-tun-cli.pid'
  ssh_sudo "$SVM" "$SZONE" \
    "nohup /opt/rustscale/target/release/examples/rustscale-tun \
       --authkey $AUTHKEY --hostname $SHOST --apply-routes --tun-name utun0 \
       --state-dir /tmp/rs-tun-srv > /tmp/rs-tun-srv.log 2>&1 & echo \$! > /tmp/rs-tun-srv.pid"
  ssh_sudo "$CVM" "$CZONE" \
    "nohup /opt/rustscale/target/release/examples/rustscale-tun \
       --authkey $AUTHKEY --hostname $CHOST --apply-routes --tun-name utun0 \
       --state-dir /tmp/rs-tun-cli > /tmp/rs-tun-cli.log 2>&1 & echo \$! > /tmp/rs-tun-cli.pid"

  # Wait for BENCH_READY 1 on both VMs. rustscale-tun prints this once it
  # has a tailnet IP AND at least one peer — NOT merely after up_tun()
  # returns, which was the old bug (online: true was printed before the
  # netmap settled, causing false "ready" detection and zeroed iperf3 runs).
  for vm_zone in "$SVM:$SZONE" "$CVM:$CZONE"; do
    local vm="${vm_zone%%:*}" zone="${vm_zone##*:}" logfile
    [[ "$vm" == "$SVM" ]] && logfile=/tmp/rs-tun-srv.log || logfile=/tmp/rs-tun-cli.log
    local elapsed=0
    local timeout=120
    [[ "$PATH_TAG" == "derp" ]] && timeout=300
    while (( elapsed < timeout )); do
      if ssh_cmd "$vm" "$zone" "grep -q 'BENCH_READY 1' $logfile 2>/dev/null" 2>/dev/null; then
        break
      fi
      sleep 5
      elapsed=$((elapsed + 5))
    done
    if (( elapsed >= 120 )); then
      echo "[gcp] ERROR: rustscale-tun on $vm never became ready (no BENCH_READY 1 in $logfile)" >&2
      local _lt
      _lt=$(capture_log_tail "$vm" "$zone" "$logfile")
      emit_stub "tun-not-ready" "$_lt"
      ssh_sudo "$SVM" "$SZONE" 'pkill -f rustscale-tun 2>/dev/null' || true
      ssh_sudo "$CVM" "$CZONE" 'pkill -f rustscale-tun 2>/dev/null' || true
      return 1
    fi
  done

  # Get server tailnet IP from the BENCH_IP marker (same as rs-userspace).
  local server_ip
  server_ip=$(ssh_cmd "$SVM" "$SZONE" "grep '^BENCH_IP ' /tmp/rs-tun-srv.log | awk '{print \$2}'" 2>/dev/null)
  if [[ -z "$server_ip" ]]; then
    # Fallback: extract from the tailscale IPs line.
    server_ip=$(ssh_cmd "$SVM" "$SZONE" "grep 'tailscale IPs' /tmp/rs-tun-srv.log | head -1" \
      | grep -oE '100\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  fi
  echo "[gcp] rs-tun: server tailnet IP=$server_ip" >&2

  # Start iperf3 server on server VM. Bind to 0.0.0.0 (all interfaces) so
  # the client can reach it via the server's tailnet IP on the utun. Binding
  # to the tailnet IP specifically can fail if the address isn't fully
  # configured on the TUN device yet.
  ssh_cmd "$SVM" "$SZONE" "pkill -x iperf3 2>/dev/null; nohup iperf3 -s -p $PORT > /tmp/iperf3-srv.log 2>&1 & echo \$! > /tmp/iperf3-srv.pid"
  sleep 2

  # Footprint sampler for rustscale-tun PID on server VM.
  local srv_pid
  srv_pid=$(ssh_cmd "$SVM" "$SZONE" 'cat /tmp/rs-tun-srv.pid')
  remote_start_footprint "$SVM" "$SZONE" "$srv_pid" /tmp/rs-tun-srv.footprint

  # Throughput sweep (download, -R).
  local tp_json="[]"
  for N in "${PARALLELS[@]}"; do
    echo "[gcp] rs-tun: iperf3 N=$N" >&2
    local mbps
    mbps=$(ssh_cmd "$CVM" "$CZONE" \
      "iperf3 -c $server_ip -p $PORT -t $DURATION -P $N -R -J 2>/dev/null" \
      | iperf3_mbps 2>/dev/null || echo "0")
    tp_json=$(echo "$tp_json" | python3 -c "
import json,sys
arr=json.load(sys.stdin)
arr.append({'parallel': $N, 'mbps': float('$mbps'), 'duration_s': $DURATION})
print(json.dumps(arr))
")
    sleep 3
  done

  # Latency via ping.
  echo "[gcp] rs-tun: latency" >&2
  local lat_json
  lat_json=$(ssh_cmd "$CVM" "$CZONE" "ping -c $LATENCY_COUNT $server_ip 2>/dev/null" | ping_latency)

  local path_class="$PATH_TAG"

  # Stop footprint.
  local foot_json
  foot_json=$(remote_stop_footprint "$SVM" "$SZONE" /tmp/rs-tun-srv.footprint)

  # Binary size of rustscale-tun example.
  local bin_size
  bin_size=$(ssh_cmd "$SVM" "$SZONE" 'stat -c %s /opt/rustscale/target/release/examples/rustscale-tun 2>/dev/null || echo 0')

  # Cleanup.
  ssh_cmd "$SVM" "$SZONE" "kill \$(cat /tmp/iperf3-srv.pid 2>/dev/null) 2>/dev/null; pkill -x iperf3 2>/dev/null" || true
  ssh_sudo "$SVM" "$SZONE" 'pkill -f rustscale-tun 2>/dev/null' || true
  ssh_sudo "$CVM" "$CZONE" 'pkill -f rustscale-tun 2>/dev/null' || true

  python3 - "$CONFIG" "$TOPOLOGY" "$PATH_TAG" "$path_class" "$bin_size" "$tp_json" "$lat_json" "$foot_json" >"$OUT" <<'PYEOF'
import json, sys
config, topo, path_tag, path_class, bin_size, tp, lat, foot = sys.argv[1:9]
obj = {
    "tool": "rustscale",
    "mode": "tun",
    "topology": topo,
    "path": path_tag,
    "config": config,
    "error": "",
    "log_tail": "",
    "throughput": json.loads(tp),
    "latency": json.loads(lat),
    "footprint": dict(json.loads(foot), binary_size_bytes=int(bin_size)),
    "path_class_reported": path_class,
}
print(json.dumps(obj, indent=2))
PYEOF
  echo "[gcp] rs-tun: wrote $OUT" >&2
}

# ===========================================================================
# Config: ts-userspace — tailscaled userspace-networking + SOCKS5
# ===========================================================================
run_ts_userspace() {
  echo "[gcp] ts-userspace: starting tailscaled on both VMs" >&2

  # Server VM: tailscaled A + iperf3 + serve.
  ssh_cmd "$SVM" "$SZONE" \
    "nohup tailscaled --tun=userspace-networking --socket=/tmp/ts-srv.sock \
       --statedir=/tmp/ts-srv --port=41642 > /tmp/ts-srv.log 2>&1 & echo \$! > /tmp/ts-srv.pid"
  sleep 3
  if ! ssh_cmd "$SVM" "$SZONE" \
    "tailscale --socket=/tmp/ts-srv.sock up --authkey=$AUTHKEY --hostname=$SHOST --timeout=120s 2>>/tmp/ts-srv.log"; then
    echo "[gcp] ERROR: tailscale up failed on server" >&2
    local _lt
    _lt=$(capture_log_tail "$SVM" "$SZONE" /tmp/ts-srv.log)
    emit_stub "ts-up-failed-srv" "$_lt"
    ssh_cmd "$SVM" "$SZONE" "kill \$(cat /tmp/ts-srv.pid 2>/dev/null) 2>/dev/null; pkill -x tailscaled 2>/dev/null" || true
    return 1
  fi
  local server_ip
  server_ip=$(ssh_cmd "$SVM" "$SZONE" "tailscale --socket=/tmp/ts-srv.sock ip -4 2>>/tmp/ts-srv.log")
  if [[ -z "$server_ip" ]]; then
    echo "[gcp] ERROR: no tailnet IP on server" >&2
    local _lt
    _lt=$(capture_log_tail "$SVM" "$SZONE" /tmp/ts-srv.log)
    emit_stub "ts-no-ip-srv" "$_lt"
    ssh_cmd "$SVM" "$SZONE" "kill \$(cat /tmp/ts-srv.pid 2>/dev/null) 2>/dev/null; pkill -x tailscaled 2>/dev/null" || true
    return 1
  fi
  echo "[gcp] ts-userspace: server IP=$server_ip" >&2

  # Clear any stale serve config from a prior run before setting up ours.
  ssh_cmd "$SVM" "$SZONE" "tailscale --socket=/tmp/ts-srv.sock serve reset 2>>/tmp/ts-srv.log" || true
  ssh_cmd "$SVM" "$SZONE" \
    "tailscale --socket=/tmp/ts-srv.sock serve --tcp $PORT --bg 127.0.0.1:$PORT 2>>/tmp/ts-srv.log"
  ssh_cmd "$SVM" "$SZONE" \
    "pkill -x iperf3 2>/dev/null; nohup iperf3 -s -p $PORT -B 127.0.0.1 > /tmp/iperf3-srv.log 2>&1 & echo \$! > /tmp/iperf3-srv.pid"
  sleep 2

  # Client VM: tailscaled B with SOCKS5.
  ssh_cmd "$CVM" "$CZONE" \
    "nohup tailscaled --tun=userspace-networking --socket=/tmp/ts-cli.sock \
       --statedir=/tmp/ts-cli --port=41643 --socks5-server=127.0.0.1:11080 \
       > /tmp/ts-cli.log 2>&1 & echo \$! > /tmp/ts-cli.pid"
  sleep 3
  if ! ssh_cmd "$CVM" "$CZONE" \
    "tailscale --socket=/tmp/ts-cli.sock up --authkey=$AUTHKEY --hostname=$CHOST --timeout=120s 2>>/tmp/ts-cli.log"; then
    echo "[gcp] ERROR: tailscale up failed on client" >&2
    local _lt
    _lt=$(capture_log_tail "$CVM" "$CZONE" /tmp/ts-cli.log)
    emit_stub "ts-up-failed-cli" "$_lt"
    ssh_cmd "$SVM" "$SZONE" "kill \$(cat /tmp/ts-srv.pid 2>/dev/null) 2>/dev/null; pkill -x tailscaled 2>/dev/null" || true
    ssh_cmd "$CVM" "$CZONE" "kill \$(cat /tmp/ts-cli.pid 2>/dev/null) 2>/dev/null; pkill -x tailscaled 2>/dev/null" || true
    return 1
  fi

  # Wait for the peer to appear (replaces fixed sleep 5 which was too short
  # on slower VMs, causing iperf3 to connect before the peer was established).
  if ! wait_ts_peer "$CVM" "$CZONE" /tmp/ts-cli.sock 120; then
    echo "[gcp] ERROR: no tailscale peer appeared on client after 120s" >&2
    local _lt
    _lt=$(capture_log_tail "$CVM" "$CZONE" /tmp/ts-cli.log)
    emit_stub "ts-no-peer" "$_lt"
    ssh_cmd "$SVM" "$SZONE" "kill \$(cat /tmp/ts-srv.pid 2>/dev/null) 2>/dev/null; pkill -x tailscaled 2>/dev/null" || true
    ssh_cmd "$CVM" "$CZONE" "kill \$(cat /tmp/ts-cli.pid 2>/dev/null) 2>/dev/null; pkill -x tailscaled 2>/dev/null" || true
    return 1
  fi

  # socat SOCKS5 bridge on client.
  ssh_cmd "$CVM" "$CZONE" \
    "pkill -x socat 2>/dev/null; nohup socat TCP-LISTEN:5300,fork,reuseaddr \
       SOCKS5-CONNECT:127.0.0.1:11080:$server_ip:$PORT > /tmp/socat.log 2>&1 & echo \$! > /tmp/socat.pid"
  sleep 2

  # Footprint sampler for tailscaled PID on server VM.
  local srv_pid
  srv_pid=$(ssh_cmd "$SVM" "$SZONE" 'cat /tmp/ts-srv.pid')
  remote_start_footprint "$SVM" "$SZONE" "$srv_pid" /tmp/ts-srv.footprint

  # Throughput sweep via socat bridge.
  local tp_json="[]"
  for N in "${PARALLELS[@]}"; do
    echo "[gcp] ts-userspace: iperf3 N=$N via socat" >&2
    local mbps
    mbps=$(ssh_cmd "$CVM" "$CZONE" \
      "iperf3 -c 127.0.0.1 -p 5300 -t $DURATION -P $N -R -J --connect-timeout 5000 2>/tmp/iperf3-cli-$N.log" \
      | iperf3_mbps 2>/dev/null || echo "0")
    tp_json=$(echo "$tp_json" | python3 -c "
import json,sys
arr=json.load(sys.stdin)
arr.append({'parallel': $N, 'mbps': float('$mbps'), 'duration_s': $DURATION})
print(json.dumps(arr))
")
    sleep 3
  done

  # Latency: python ping-pong through SOCKS5 to ncat echo on server.
  echo "[gcp] ts-userspace: latency via SOCKS5 ping-pong" >&2
  ssh_cmd "$SVM" "$SZONE" \
    "tailscale --socket=/tmp/ts-srv.sock serve reset 2>>/tmp/ts-srv.log; \
     pkill -x ncat 2>/dev/null; \
     nohup ncat -l 5202 --exec '/bin/cat' --keep-open > /tmp/ncat.log 2>&1 & echo \$! > /tmp/ncat.pid; \
     sleep 1; \
     tailscale --socket=/tmp/ts-srv.sock serve --tcp 5202 --bg 127.0.0.1:5202 2>>/tmp/ts-srv.log || \
     tailscale --socket=/tmp/ts-srv.sock serve --tcp 5202 --bg 127.0.0.1:5202 2>>/tmp/ts-srv.log"
  sleep 2

  local lat_json
  lat_json=$(ssh_cmd "$CVM" "$CZONE" \
    "python3 - '$server_ip' 5202 11080 $LATENCY_COUNT" <<'PYEOF'
import socket, struct, sys, time, json, statistics
target_ip, target_port, socks_port, count = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(('127.0.0.1', socks_port))
    s.sendall(b'\x05\x01\x00')
    resp = s.recv(2)
    if resp != b'\x05\x00':
        print(json.dumps({"error": f"socks5 auth failed: {resp.hex()}"})); sys.exit(0)
    ip_bytes = socket.inet_aton(target_ip)
    s.sendall(b'\x05\x01\x00\x01' + ip_bytes + struct.pack('>H', target_port))
    resp = s.recv(10)
    if resp[1] != 0:
        print(json.dumps({"error": f"socks5 connect failed: {resp[1]}"})); sys.exit(0)
    rtts = []
    for i in range(count):
        start = time.perf_counter_ns()
        s.sendall(b'PING')
        data = b''
        while len(data) < 4:
            chunk = s.recv(4 - len(data))
            if not chunk: break
            data += chunk
        rtts.append((time.perf_counter_ns() - start) // 1000)
    s.close()
    rtts.sort()
    n = len(rtts)
    def pct(p):
        return rtts[min(int(round((n-1)*p)), n-1)] if rtts else 0
    print(json.dumps({
        "p50_us": int(pct(0.50)), "p95_us": int(pct(0.95)), "p99_us": int(pct(0.99)),
        "count": n,
    }))
except Exception as e:
    print(json.dumps({"p50_us":0,"p95_us":0,"p99_us":0,"count":0,"error":str(e)}))
PYEOF
)

  # Path class from tailscale status.
  local path_class
  path_class=$(ssh_cmd "$CVM" "$CZONE" \
    "tailscale --socket=/tmp/ts-cli.sock status --json 2>/dev/null" \
    | python3 -c "
import json,sys
d=json.load(sys.stdin)
peers=d.get('Peer',{})
for k,v in peers.items():
    if v.get('CurAddr',''): print('direct'); sys.exit(0)
    if v.get('Relay',''): print('derp'); sys.exit(0)
print('unknown')
" 2>/dev/null || echo unknown)

  # Stop footprint.
  local foot_json
  foot_json=$(remote_stop_footprint "$SVM" "$SZONE" /tmp/ts-srv.footprint)

  # Binary size of tailscaled.
  local bin_size
  bin_size=$(ssh_cmd "$SVM" "$SZONE" 'stat -c %s /usr/sbin/tailscaled 2>/dev/null || echo 0')

  # Cleanup.
  ssh_cmd "$CVM" "$CZONE" "kill \$(cat /tmp/socat.pid 2>/dev/null) 2>/dev/null; pkill -x socat 2>/dev/null" || true
  ssh_cmd "$SVM" "$SZONE" "tailscale --socket=/tmp/ts-srv.sock serve reset 2>/dev/null; kill \$(cat /tmp/iperf3-srv.pid 2>/dev/null) \$(cat /tmp/ncat.pid 2>/dev/null) 2>/dev/null; pkill -x iperf3 2>/dev/null; pkill -x ncat 2>/dev/null" || true
  ssh_cmd "$SVM" "$SZONE" "kill \$(cat /tmp/ts-srv.pid 2>/dev/null) 2>/dev/null; pkill -x tailscaled 2>/dev/null" || true
  ssh_cmd "$CVM" "$CZONE" "kill \$(cat /tmp/ts-cli.pid 2>/dev/null) 2>/dev/null; pkill -x tailscaled 2>/dev/null" || true

  python3 - "$CONFIG" "$TOPOLOGY" "$PATH_TAG" "$path_class" "$bin_size" "$tp_json" "$lat_json" "$foot_json" >"$OUT" <<'PYEOF'
import json, sys
config, topo, path_tag, path_class, bin_size, tp, lat, foot = sys.argv[1:9]
obj = {
    "tool": "tailscaled",
    "mode": "userspace",
    "topology": topo,
    "path": path_tag,
    "config": config,
    "error": "",
    "log_tail": "",
    "throughput": json.loads(tp),
    "latency": json.loads(lat),
    "footprint": dict(json.loads(foot), binary_size_bytes=int(bin_size)),
    "path_class_reported": path_class,
}
print(json.dumps(obj, indent=2))
PYEOF
  echo "[gcp] ts-userspace: wrote $OUT" >&2
}

# ===========================================================================
# Config: ts-tun — default tailscaled with kernel TUN
# ===========================================================================
run_ts_tun() {
  echo "[gcp] ts-tun: starting tailscaled on both VMs (kernel TUN)" >&2

  # Use unique paths so root-owned files from ts-tun don't clash with
  # ts-userspace's non-root files.  Also remove any stale leftovers from a
  # prior run (root-owned log/pid/sock that non-root SSH can't truncate).
  ssh_sudo "$SVM" "$SZONE" \
    "rm -f /tmp/ts-tun-srv.log /tmp/ts-tun-srv.pid /tmp/ts-tun-srv.sock; rm -rf /tmp/ts-tun-srv"
  ssh_sudo "$CVM" "$CZONE" \
    "rm -f /tmp/ts-tun-cli.log /tmp/ts-tun-cli.pid /tmp/ts-tun-cli.sock; rm -rf /tmp/ts-tun-cli"

  # Back up /etc/resolv.conf before tailscaled (root) overwrites it for
  # MagicDNS.  If tailscaled is killed without `tailscale down', resolv.conf
  # stays pointed at 100.100.100.100 and every subsequent config that relies
  # on system DNS (rustscale) fails with "Temporary failure in name resolution".
  ssh_sudo "$SVM" "$SZONE"  'cp /etc/resolv.conf /etc/resolv.conf.bench-bak 2>/dev/null || true'
  ssh_sudo "$CVM" "$CZONE"  'cp /etc/resolv.conf /etc/resolv.conf.bench-bak 2>/dev/null || true'

  ssh_sudo "$SVM" "$SZONE" \
    "nohup tailscaled --socket=/tmp/ts-tun-srv.sock --statedir=/tmp/ts-tun-srv > /tmp/ts-tun-srv.log 2>&1 & echo \$! > /tmp/ts-tun-srv.pid"
  sleep 3
  if ! ssh_sudo "$SVM" "$SZONE" \
    "tailscale --socket=/tmp/ts-tun-srv.sock up --authkey=$AUTHKEY --hostname=$SHOST --timeout=120s 2>>/tmp/ts-tun-srv.log"; then
    echo "[gcp] ERROR: tailscale up failed on server" >&2
    local _lt
    _lt=$(capture_log_tail "$SVM" "$SZONE" /tmp/ts-tun-srv.log)
    emit_stub "ts-up-failed-srv" "$_lt"
    ssh_sudo "$SVM" "$SZONE" \
      'tailscale --socket=/tmp/ts-tun-srv.sock down 2>/dev/null; pkill -x tailscaled 2>/dev/null; cp /etc/resolv.conf.bench-bak /etc/resolv.conf 2>/dev/null || true' || true
    return 1
  fi
  local server_ip
  server_ip=$(ssh_sudo "$SVM" "$SZONE" "tailscale --socket=/tmp/ts-tun-srv.sock ip -4 2>>/tmp/ts-tun-srv.log")
  if [[ -z "$server_ip" ]]; then
    echo "[gcp] ERROR: no tailnet IP on server" >&2
    local _lt
    _lt=$(capture_log_tail "$SVM" "$SZONE" /tmp/ts-tun-srv.log)
    emit_stub "ts-no-ip-srv" "$_lt"
    ssh_sudo "$SVM" "$SZONE" \
      'tailscale --socket=/tmp/ts-tun-srv.sock down 2>/dev/null; pkill -x tailscaled 2>/dev/null; cp /etc/resolv.conf.bench-bak /etc/resolv.conf 2>/dev/null || true' || true
    return 1
  fi
  echo "[gcp] ts-tun: server IP=$server_ip" >&2

  ssh_sudo "$CVM" "$CZONE" \
    "nohup tailscaled --socket=/tmp/ts-tun-cli.sock --statedir=/tmp/ts-tun-cli > /tmp/ts-tun-cli.log 2>&1 & echo \$! > /tmp/ts-tun-cli.pid"
  sleep 3
  if ! ssh_sudo "$CVM" "$CZONE" \
    "tailscale --socket=/tmp/ts-tun-cli.sock up --authkey=$AUTHKEY --hostname=$CHOST --timeout=120s 2>>/tmp/ts-tun-cli.log"; then
    echo "[gcp] ERROR: tailscale up failed on client" >&2
    local _lt
    _lt=$(capture_log_tail "$CVM" "$CZONE" /tmp/ts-tun-cli.log)
    emit_stub "ts-up-failed-cli" "$_lt"
    ssh_sudo "$SVM" "$SZONE" \
      'tailscale --socket=/tmp/ts-tun-srv.sock down 2>/dev/null; pkill -x tailscaled 2>/dev/null; cp /etc/resolv.conf.bench-bak /etc/resolv.conf 2>/dev/null || true' || true
    ssh_sudo "$CVM" "$CZONE" \
      'tailscale --socket=/tmp/ts-tun-cli.sock down 2>/dev/null; pkill -x tailscaled 2>/dev/null; cp /etc/resolv.conf.bench-bak /etc/resolv.conf 2>/dev/null || true' || true
    return 1
  fi

  # Wait for the peer to appear (replaces fixed sleep 5).
  if ! wait_ts_peer "$CVM" "$CZONE" /tmp/ts-tun-cli.sock 120; then
    echo "[gcp] ERROR: no tailscale peer appeared on client after 120s" >&2
    local _lt
    _lt=$(capture_log_tail "$CVM" "$CZONE" /tmp/ts-tun-cli.log)
    emit_stub "ts-no-peer" "$_lt"
    ssh_sudo "$SVM" "$SZONE" \
      'tailscale --socket=/tmp/ts-tun-srv.sock down 2>/dev/null; pkill -x tailscaled 2>/dev/null; cp /etc/resolv.conf.bench-bak /etc/resolv.conf 2>/dev/null || true' || true
    ssh_sudo "$CVM" "$CZONE" \
      'tailscale --socket=/tmp/ts-tun-cli.sock down 2>/dev/null; pkill -x tailscaled 2>/dev/null; cp /etc/resolv.conf.bench-bak /etc/resolv.conf 2>/dev/null || true' || true
    return 1
  fi

  # iperf3 server.
  ssh_sudo "$SVM" "$SZONE" \
    "pkill -x iperf3 2>/dev/null; nohup iperf3 -s -p $PORT > /tmp/iperf3-srv.log 2>&1 & echo \$! > /tmp/iperf3-srv.pid"
  sleep 2

  # Footprint for tailscaled PID on server VM.
  local srv_pid
  srv_pid=$(ssh_sudo "$SVM" "$SZONE" 'cat /tmp/ts-tun-srv.pid')
  remote_start_footprint "$SVM" "$SZONE" "$srv_pid" /tmp/ts-tun-srv.footprint

  # Throughput sweep.
  local tp_json="[]"
  for N in "${PARALLELS[@]}"; do
    echo "[gcp] ts-tun: iperf3 N=$N" >&2
    local mbps
    mbps=$(ssh_sudo "$CVM" "$CZONE" \
      "iperf3 -c $server_ip -p $PORT -t $DURATION -P $N -R -J 2>/dev/null" \
      | iperf3_mbps 2>/dev/null || echo "0")
    tp_json=$(echo "$tp_json" | python3 -c "
import json,sys
arr=json.load(sys.stdin)
arr.append({'parallel': $N, 'mbps': float('$mbps'), 'duration_s': $DURATION})
print(json.dumps(arr))
")
    sleep 3
  done

  # Latency via ping.
  echo "[gcp] ts-tun: latency" >&2
  local lat_json
  lat_json=$(ssh_sudo "$CVM" "$CZONE" "ping -c $LATENCY_COUNT $server_ip 2>/dev/null" | ping_latency)

  local path_class="$PATH_TAG"

  # Stop footprint.
  local foot_json
  foot_json=$(remote_stop_footprint "$SVM" "$SZONE" /tmp/ts-tun-srv.footprint)

  # Binary size.
  local bin_size
  bin_size=$(ssh_cmd "$SVM" "$SZONE" 'stat -c %s /usr/sbin/tailscaled 2>/dev/null || echo 0')

  # Cleanup: `tailscale down' restores /etc/resolv.conf; then kill + restore
  # resolv.conf backup as a belt-and-suspenders safeguard.
  ssh_sudo "$SVM" "$SZONE" \
    "kill \$(cat /tmp/iperf3-srv.pid 2>/dev/null) 2>/dev/null; pkill -x iperf3 2>/dev/null; \
     tailscale --socket=/tmp/ts-tun-srv.sock down 2>/dev/null; \
     kill \$(cat /tmp/ts-tun-srv.pid 2>/dev/null) 2>/dev/null; pkill -x tailscaled 2>/dev/null; \
     cp /etc/resolv.conf.bench-bak /etc/resolv.conf 2>/dev/null || true; \
     rm -f /etc/resolv.conf.bench-bak" || true
  ssh_sudo "$CVM" "$CZONE" \
    "tailscale --socket=/tmp/ts-tun-cli.sock down 2>/dev/null; \
     kill \$(cat /tmp/ts-tun-cli.pid 2>/dev/null) 2>/dev/null; pkill -x tailscaled 2>/dev/null; \
     cp /etc/resolv.conf.bench-bak /etc/resolv.conf 2>/dev/null || true; \
     rm -f /etc/resolv.conf.bench-bak" || true

  python3 - "$CONFIG" "$TOPOLOGY" "$PATH_TAG" "$path_class" "$bin_size" "$tp_json" "$lat_json" "$foot_json" >"$OUT" <<'PYEOF'
import json, sys
config, topo, path_tag, path_class, bin_size, tp, lat, foot = sys.argv[1:9]
obj = {
    "tool": "tailscaled",
    "mode": "tun",
    "topology": topo,
    "path": path_tag,
    "config": config,
    "error": "",
    "log_tail": "",
    "throughput": json.loads(tp),
    "latency": json.loads(lat),
    "footprint": dict(json.loads(foot), binary_size_bytes=int(bin_size)),
    "path_class_reported": path_class,
}
print(json.dumps(obj, indent=2))
PYEOF
  echo "[gcp] ts-tun: wrote $OUT" >&2
}

# ---------------------------------------------------------------------------
# Dispatch.
# ---------------------------------------------------------------------------
case "$CONFIG" in
  rs-userspace)  run_rs_userspace ;;
  rs-tun)        run_rs_tun ;;
  ts-userspace)  run_ts_userspace ;;
  ts-tun)        run_ts_tun ;;
  *)
    echo "[gcp] ERROR: unknown config '$CONFIG'" >&2
    usage
    ;;
esac
