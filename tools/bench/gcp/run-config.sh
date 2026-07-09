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

# Helper: write a stub JSON (used in dry-run or on failure).
emit_stub() {
  local err="${1:-dry-run}"
  local tool mode
  case "$CONFIG" in
    rs-*) tool=rustscale; mode=userspace ;;
    ts-*) tool=tailscaled; mode=tun ;;
  esac
  [[ "$CONFIG" == *-tun ]] && mode=tun
  [[ "$CONFIG" == *-userspace ]] && mode=userspace
  cat >"$OUT" <<EOF
{
  "tool": "$tool",
  "mode": "$mode",
  "topology": "$TOPOLOGY",
  "path": "$PATH_TAG",
  "config": "$CONFIG",
  "error": "$err",
  "throughput": [
    {"parallel": 1, "mbps": 0, "duration_s": $DURATION},
    {"parallel": 10, "mbps": 0, "duration_s": $DURATION},
    {"parallel": 25, "mbps": 0, "duration_s": $DURATION},
    {"parallel": 50, "mbps": 0, "duration_s": $DURATION},
    {"parallel": 100, "mbps": 0, "duration_s": $DURATION}
  ],
  "latency": {"p50_us": 0, "p95_us": 0, "p99_us": 0, "count": $LATENCY_COUNT},
  "footprint": {"binary_size_bytes": 0, "rss_peak_kb": 0, "rss_avg_kb": 0, "cpu_peak_pct": 0, "cpu_avg_pct": 0, "samples": 0},
  "path_class_reported": "$PATH_TAG"
}
EOF
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

  # Wait for BENCH_READY 1.
  local elapsed=0
  while (( elapsed < 180 )); do
    if ssh_cmd "$SVM" "$SZONE" 'grep -q "BENCH_READY 1" /tmp/rs-srv.log 2>/dev/null' 2>/dev/null; then
      break
    fi
    sleep 5
    elapsed=$((elapsed + 5))
  done
  if (( elapsed >= 180 )); then
    echo "[gcp] ERROR: rustscale-bench server never became ready" >&2
    ssh_cmd "$SVM" "$SZONE" 'tail -50 /tmp/rs-srv.log' >&2 || true
    emit_stub "server-not-ready"
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
  ssh_sudo "$SVM" "$SZONE" \
    "nohup /opt/rustscale/target/release/examples/rustscale-tun \
       --authkey $AUTHKEY --hostname $SHOST --apply-routes --tun-name utun0 \
       --state-dir /tmp/rs-tun-srv > /tmp/rs-tun-srv.log 2>&1 & echo \$! > /tmp/rs-tun-srv.pid"
  ssh_sudo "$CVM" "$CZONE" \
    "nohup /opt/rustscale/target/release/examples/rustscale-tun \
       --authkey $AUTHKEY --hostname $CHOST --apply-routes --tun-name utun0 \
       --state-dir /tmp/rs-tun-cli > /tmp/rs-tun-cli.log 2>&1 & echo \$! > /tmp/rs-tun-cli.pid"

  # Wait for 'online: true' and 'tailscale IPs' on both.
  for vm_zone in "$SVM:$SZONE" "$CVM:$CZONE"; do
    local vm="${vm_zone%%:*}" zone="${vm_zone##*:}" logfile
    [[ "$vm" == "$SVM" ]] && logfile=/tmp/rs-tun-srv.log || logfile=/tmp/rs-tun-cli.log
    local elapsed=0
    while (( elapsed < 180 )); do
      if ssh_cmd "$vm" "$zone" "grep -q 'online: true' $logfile && grep -q 'tailscale IPs' $logfile" 2>/dev/null; then
        break
      fi
      sleep 5
      elapsed=$((elapsed + 5))
    done
    if (( elapsed >= 180 )); then
      echo "[gcp] ERROR: rustscale-tun on $vm never came online" >&2
      ssh_cmd "$vm" "$zone" "tail -50 $logfile" >&2 || true
      emit_stub "tun-not-online"
      ssh_sudo "$SVM" "$SZONE" 'pkill -f rustscale-tun 2>/dev/null' || true
      ssh_sudo "$CVM" "$CZONE" 'pkill -f rustscale-tun 2>/dev/null' || true
      return 1
    fi
  done

  # Get server tailnet IP.
  local server_ip
  server_ip=$(ssh_cmd "$SVM" "$SZONE" "grep 'tailscale IPs' /tmp/rs-tun-srv.log | head -1" \
    | grep -oE '100\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  echo "[gcp] rs-tun: server tailnet IP=$server_ip" >&2

  # Start iperf3 server on server VM bound to tailnet IP.
  ssh_cmd "$SVM" "$SZONE" "pkill -x iperf3 2>/dev/null; nohup iperf3 -s -p $PORT -B $server_ip > /tmp/iperf3-srv.log 2>&1 & echo \$! > /tmp/iperf3-srv.pid"
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
  ssh_cmd "$SVM" "$SZONE" \
    "tailscale --socket=/tmp/ts-srv.sock up --authkey=$AUTHKEY --hostname=$SHOST --timeout=120s 2>>/tmp/ts-srv.log"
  local server_ip
  server_ip=$(ssh_cmd "$SVM" "$SZONE" "tailscale --socket=/tmp/ts-srv.sock ip -4 2>>/tmp/ts-srv.log")
  echo "[gcp] ts-userspace: server IP=$server_ip" >&2

  ssh_cmd "$SVM" "$SZONE" \
    "tailscale --socket=/tmp/ts-srv.sock serve --tcp $PORT --bg localhost:$PORT 2>>/tmp/ts-srv.log || \
     tailscale --socket=/tmp/ts-srv.sock serve --tcp $PORT --bg $PORT 2>>/tmp/ts-srv.log"
  ssh_cmd "$SVM" "$SZONE" \
    "pkill -x iperf3 2>/dev/null; nohup iperf3 -s -p $PORT -B 127.0.0.1 > /tmp/iperf3-srv.log 2>&1 & echo \$! > /tmp/iperf3-srv.pid"
  sleep 2

  # Client VM: tailscaled B with SOCKS5.
  ssh_cmd "$CVM" "$CZONE" \
    "nohup tailscaled --tun=userspace-networking --socket=/tmp/ts-cli.sock \
       --statedir=/tmp/ts-cli --port=41643 --socks5-server=127.0.0.1:11080 \
       > /tmp/ts-cli.log 2>&1 & echo \$! > /tmp/ts-cli.pid"
  sleep 3
  ssh_cmd "$CVM" "$CZONE" \
    "tailscale --socket=/tmp/ts-cli.sock up --authkey=$AUTHKEY --hostname=$CHOST --timeout=120s 2>>/tmp/ts-cli.log"

  sleep 5  # peer establishment

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
     tailscale --socket=/tmp/ts-srv.sock serve --tcp 5202 --bg localhost:5202 2>>/tmp/ts-srv.log || \
     tailscale --socket=/tmp/ts-srv.sock serve --tcp 5202 --bg 5202 2>>/tmp/ts-srv.log"
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
  ssh_cmd "$SVM" "$SZONE" "kill \$(cat /tmp/iperf3-srv.pid 2>/dev/null) \$(cat /tmp/ncat.pid 2>/dev/null) 2>/dev/null; pkill -x iperf3 2>/dev/null; pkill -x ncat 2>/dev/null" || true
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
  ssh_sudo "$SVM" "$SZONE" \
    "nohup tailscaled --socket=/tmp/ts-srv.sock --statedir=/tmp/ts-srv > /tmp/ts-srv.log 2>&1 & echo \$! > /tmp/ts-srv.pid"
  sleep 3
  ssh_sudo "$SVM" "$SZONE" \
    "tailscale --socket=/tmp/ts-srv.sock up --authkey=$AUTHKEY --hostname=$SHOST --timeout=120s 2>>/tmp/ts-srv.log"
  local server_ip
  server_ip=$(ssh_sudo "$SVM" "$SZONE" "tailscale --socket=/tmp/ts-srv.sock ip -4 2>>/tmp/ts-srv.log")
  echo "[gcp] ts-tun: server IP=$server_ip" >&2

  ssh_sudo "$CVM" "$CZONE" \
    "nohup tailscaled --socket=/tmp/ts-cli.sock --statedir=/tmp/ts-cli > /tmp/ts-cli.log 2>&1 & echo \$! > /tmp/ts-cli.pid"
  sleep 3
  ssh_sudo "$CVM" "$CZONE" \
    "tailscale --socket=/tmp/ts-cli.sock up --authkey=$AUTHKEY --hostname=$CHOST --timeout=120s 2>>/tmp/ts-cli.log"

  sleep 5

  # iperf3 server.
  ssh_sudo "$SVM" "$SZONE" \
    "pkill -x iperf3 2>/dev/null; nohup iperf3 -s -p $PORT > /tmp/iperf3-srv.log 2>&1 & echo \$! > /tmp/iperf3-srv.pid"
  sleep 2

  # Footprint for tailscaled PID on server VM.
  local srv_pid
  srv_pid=$(ssh_sudo "$SVM" "$SZONE" 'cat /tmp/ts-srv.pid')
  remote_start_footprint "$SVM" "$SZONE" "$srv_pid" /tmp/ts-srv.footprint

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
  foot_json=$(remote_stop_footprint "$SVM" "$SZONE" /tmp/ts-srv.footprint)

  # Binary size.
  local bin_size
  bin_size=$(ssh_cmd "$SVM" "$SZONE" 'stat -c %s /usr/sbin/tailscaled 2>/dev/null || echo 0')

  # Cleanup.
  ssh_sudo "$SVM" "$SZONE" "kill \$(cat /tmp/iperf3-srv.pid 2>/dev/null) 2>/dev/null; pkill -x iperf3 2>/dev/null; kill \$(cat /tmp/ts-srv.pid 2>/dev/null) 2>/dev/null; pkill -x tailscaled 2>/dev/null; tailscale --socket=/tmp/ts-srv.sock down 2>/dev/null" || true
  ssh_sudo "$CVM" "$CZONE" "kill \$(cat /tmp/ts-cli.pid 2>/dev/null) 2>/dev/null; pkill -x tailscaled 2>/dev/null; tailscale --socket=/tmp/ts-cli.sock down 2>/dev/null" || true

  python3 - "$CONFIG" "$TOPOLOGY" "$PATH_TAG" "$path_class" "$bin_size" "$tp_json" "$lat_json" "$foot_json" >"$OUT" <<'PYEOF'
import json, sys
config, topo, path_tag, path_class, bin_size, tp, lat, foot = sys.argv[1:9]
obj = {
    "tool": "tailscaled",
    "mode": "tun",
    "topology": topo,
    "path": path_tag,
    "config": config,
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
