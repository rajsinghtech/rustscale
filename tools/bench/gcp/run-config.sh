#!/usr/bin/env bash
# tools/bench/gcp/run-config.sh — run ONE bench config across two GCP VMs.
#
# Usage:
#   run-config.sh CONFIG SERVER_VM CLIENT_VM SERVER_ZONE CLIENT_ZONE \
#                 AUTHKEY RESULTS_DIR SERVER_HOSTNAME CLIENT_HOSTNAME [--profile]
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
--profile: rs-tun only; collect a Linux perf profile after normal metrics
EOF
  exit 2
}

SELF_TEST=0
if [[ "${1:-}" == "--self-test" ]]; then
  SELF_TEST=1
  shift
fi

if (( SELF_TEST )); then
  CONFIG=rs-tun
  SVM=self-test-server
  CVM=self-test-client
  SZONE=self-test-zone
  CZONE=self-test-zone
  AUTHKEY=self-test-authkey
  RDIR=$(mktemp -d)
  SHOST=self-test-server
  CHOST=self-test-client
  PROFILE=1
else
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
  shift 9
  PROFILE=0
  if [[ "${1:-}" == --profile ]]; then PROFILE=1; shift; fi
  [[ $# -eq 0 ]] || usage
fi
if (( PROFILE )) && [[ "$CONFIG" != rs-tun ]]; then
  echo "--profile is only valid for rs-tun" >&2
  exit 2
fi

PARALLELS=(1 10 100)
DURATION=10
LATENCY_COUNT=50
LATENCY_INTERVAL=0.1
PORT=5201
# Reserved for an unsafe rs-tun → tailscaled handoff.  Keep this distinct from
# ordinary benchmark failures so run-matrix can destroy the affected VMs.
FATAL_HANDOFF_STATUS=86

# BENCH_MATRIX is "<topo>/<path>" — set by run-matrix.sh.
BENCH_MATRIX="${BENCH_MATRIX:-}"
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

# Run a product CLI command, optionally as root for kernel-TUN configurations.
# Args: AS_ROOT VM ZONE COMMAND
run_tun_command() {
  local as_root="$1" vm="$2" zone="$3" command="$4"
  if [[ "$as_root" == 1 ]]; then
    ssh_sudo "$vm" "$zone" "$command"
  else
    ssh_cmd "$vm" "$zone" "$command"
  fi
}

# Wait until the product CLI can report an IPv4 tailnet address.
# Args: AS_ROOT VM ZONE CLI SOCKET LOGFILE
wait_tun_ip() {
  local as_root="$1" vm="$2" zone="$3" cli="$4" socket="$5" logfile="$6"
  local elapsed=0 ip
  while (( elapsed < 120 )); do
    ip=$(run_tun_command "$as_root" "$vm" "$zone" "$cli --socket=$socket ip -4 2>>$logfile" 2>/dev/null || true)
    if [[ -n "$ip" ]]; then
      printf '%s\n' "$ip"
      return 0
    fi
    sleep 5
    elapsed=$((elapsed + 5))
  done
  return 1
}

# Classify a product CLI ping transcript. Requested paths are not evidence.
classify_cli_path() {
  awk '
    /^pong .* via peer-relay\(/ { peer_relay = 1; next }
    /^pong .* via DERP\(/ { derp = 1; next }
    /^pong .* via / { direct = 1 }
    END {
      if (direct) print "direct"
      else if (peer_relay) print "peer-relay"
      else if (derp) print "derp"
      else print "unknown"
    }'
}

classifier_self_test() {
  local input expected actual
  while IFS='|' read -r input expected; do
    actual=$(printf '%s\n' "$input" | classify_cli_path)
    [[ "$actual" == "$expected" ]] || {
      echo "classifier self-test failed: expected $expected, got $actual" >&2
      return 1
    }
  done <<'EOF'
pong from node (100.64.0.1) via 192.0.2.1:41641 in 1ms|direct
pong from node (100.64.0.1) via DERP(ord) in 1ms|derp
pong from node (100.64.0.1) via peer-relay(node) in 1ms|peer-relay
ping error: unavailable|unknown
EOF
}

# Build a standard CLI ping invocation, with flags preceding the target.
# Args: CLI SOCKET PATH_TAG SERVER_IP
tun_ping_invocation() {
  local cli="$1" socket="$2" path_tag="$3" server_ip="$4"
  local ping_args
  if [[ "$path_tag" == direct ]]; then
    ping_args="--until-direct --c=120"
  else
    ping_args="--until-direct=false --c=1"
  fi
  printf '%s --socket=%s ping %s %s' "$cli" "$socket" "$ping_args" "$server_ip"
}

command_shape_self_test() {
  local ts_direct rs_direct ts_derp rs_derp
  ts_direct=$(tun_ping_invocation tailscale /tmp/ts.sock direct 100.64.0.1)
  rs_direct=$(tun_ping_invocation /opt/rustscale/target/release/rustscale /tmp/rs.sock direct 100.64.0.1)
  ts_derp=$(tun_ping_invocation tailscale /tmp/ts.sock derp 100.64.0.1)
  rs_derp=$(tun_ping_invocation /opt/rustscale/target/release/rustscale /tmp/rs.sock derp 100.64.0.1)
  [[ "$ts_direct" == 'tailscale --socket=/tmp/ts.sock ping --until-direct --c=120 100.64.0.1' ]] || return 1
  [[ "$rs_direct" == '/opt/rustscale/target/release/rustscale --socket=/tmp/rs.sock ping --until-direct --c=120 100.64.0.1' ]] || return 1
  [[ "${ts_direct#* ping }" == "${rs_direct#* ping }" ]] || return 1
  [[ "$ts_derp" == 'tailscale --socket=/tmp/ts.sock ping --until-direct=false --c=1 100.64.0.1' ]] || return 1
  [[ "$rs_derp" == '/opt/rustscale/target/release/rustscale --socket=/tmp/rs.sock ping --until-direct=false --c=1 100.64.0.1' ]] || return 1
  [[ "${ts_derp#* ping }" == "${rs_derp#* ping }" ]] || return 1
}

# Gate kernel benchmarks on a product CLI ping and return its observed class.
# Args: AS_ROOT VM ZONE CLI SOCKET SERVER_IP PATH_TAG PATH_LOG
tun_path_gate() {
  local as_root="$1" vm="$2" zone="$3" cli="$4" socket="$5" server_ip="$6" path_tag="$7" path_log="$8"
  local ping_command
  ping_command=$(tun_ping_invocation "$cli" "$socket" "$path_tag" "$server_ip")
  run_tun_command "$as_root" "$vm" "$zone" \
    "$ping_command >$path_log 2>&1" || return 1
  local transcript observed
  transcript=$(run_tun_command "$as_root" "$vm" "$zone" "cat $path_log" 2>/dev/null || true)
  observed=$(printf '%s\n' "$transcript" | classify_cli_path)
  [[ "$path_tag" != direct || "$observed" == direct ]] || return 1
  [[ "$path_tag" != derp || "$observed" == derp ]] || return 1
  printf '%s\n' "$observed"
}

cleanup_rs_tun() {
  local status=0
  # This runs as root because rs-tun may have left root-owned benchmark files.
  # It is deliberately idempotent: an already-absent optional iperf3 server
  # must not make ssh_sudo retry before the next non-root config starts.
  if ! ssh_sudo "$SVM" "$SZONE" "$(rs_tun_iperf_cleanup_command)"; then
    echo "[gcp] ERROR: rs-tun iperf3 cleanup failed on server $SVM" >&2
    status=1
  fi

  # Run both endpoints even if one remains dirty.  ssh_cmd retries a nonzero
  # remote result, so the remote action is deliberately idempotent.
  if ! ssh_sudo "$SVM" "$SZONE" "$(rs_tun_cleanup_command srv)"; then
    echo "[gcp] ERROR: rs-tun cleanup failed on server $SVM" >&2
    status=1
  fi
  if ! ssh_sudo "$CVM" "$CZONE" "$(rs_tun_cleanup_command cli)"; then
    echo "[gcp] ERROR: rs-tun cleanup failed on client $CVM" >&2
    status=1
  fi
  return "$status"
}

# Print the root-side iperf3 cleanup program used before rs-tun hands a VM to
# the next configuration.  Remove both files even when the optional process
# is already absent so a non-root benchmark can create them.
rs_tun_iperf_cleanup_command() {
  printf '%s\n' \
'pidfile=/tmp/iperf3-srv.pid' \
'kill "$(cat "$pidfile" 2>/dev/null)" 2>/dev/null || true' \
'pkill -x iperf3 2>/dev/null || true' \
'rm -f "$pidfile" /tmp/iperf3-srv.log'
}

# Clear root-owned iperf3 leftovers before rs-tun measures as the SSH user.
rs_tun_measurement_preflight() {
  ssh_sudo "$SVM" "$SZONE" "$(rs_tun_iperf_cleanup_command)"
}

# Print the root-side cleanup program for one rs-tun endpoint.  It intentionally
# contains no single quotes because ssh_sudo wraps the command in `bash -c '…'`.
rs_tun_cleanup_command() {
  local role="$1"
  printf '%s\n' "pidfile=/tmp/rs-tun-${role}.pid" \
'is_clear() {' \
'  ! pgrep -x rustscaled >/dev/null 2>&1 && ! ip link show dev tailscale0 >/dev/null 2>&1' \
'}' \
'wait_for_clear() {' \
'  local elapsed=0 timeout=10' \
'  while (( elapsed < timeout )); do' \
'    is_clear && return 0' \
'    sleep 1' \
'    elapsed=$((elapsed + 1))' \
'  done' \
'  is_clear' \
'}' \
'diagnose() {' \
'  echo "[gcp] rs-tun cleanup diagnostics: rustscaled processes and tailscale0 ownership" >&2' \
'  pgrep -a -x rustscaled >&2 || true' \
'  ps -eo pid,ppid,user,stat,comm,args | grep "[r]ustscaled" >&2 || true' \
'  ip -d link show dev tailscale0 >&2 || true' \
'  ls -l /sys/class/net/tailscale0 >&2 || true' \
'  fuser -v /dev/net/tun >&2 || true' \
'}' \
'signal_daemons() {' \
'  local signal="$1" pid=""' \
'  if [[ -r "$pidfile" ]]; then' \
'    pid=$(cat "$pidfile" 2>/dev/null || true)' \
'    case "$pid" in' \
'      ""|*[!0-9]*) ;;' \
'      *) kill "-$signal" "$pid" 2>/dev/null || true ;;' \
'    esac' \
'  fi' \
'  pkill "-$signal" -x rustscaled 2>/dev/null || true' \
'}' \
'signal_daemons TERM' \
'if wait_for_clear; then exit 0; fi' \
'diagnose' \
'signal_daemons KILL' \
'if wait_for_clear; then exit 0; fi' \
'diagnose' \
'echo "[gcp] ERROR: rs-tun cleanup left rustscaled or tailscale0 behind" >&2' \
'exit 1'
}

cleanup_ts_tun() {
  ssh_sudo "$SVM" "$SZONE" \
    "kill \$(cat /tmp/iperf3-srv.pid 2>/dev/null) 2>/dev/null; pkill -x iperf3 2>/dev/null; \
     tailscale --socket=/tmp/ts-tun-srv.sock down 2>/dev/null; \
     kill \$(cat /tmp/ts-tun-srv.pid 2>/dev/null) 2>/dev/null; pkill -x tailscaled 2>/dev/null; \
     cp /etc/resolv.conf.bench-bak /etc/resolv.conf 2>/dev/null || true; rm -f /etc/resolv.conf.bench-bak" || true
  ssh_sudo "$CVM" "$CZONE" \
    "tailscale --socket=/tmp/ts-tun-cli.sock down 2>/dev/null; \
     kill \$(cat /tmp/ts-tun-cli.pid 2>/dev/null) 2>/dev/null; pkill -x tailscaled 2>/dev/null; \
     cp /etc/resolv.conf.bench-bak /etc/resolv.conf 2>/dev/null || true; rm -f /etc/resolv.conf.bench-bak" || true
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
    "$DURATION" "$LATENCY_COUNT" "${PARALLELS[@]}" "$_lt_tmp" >"$OUT" <<'PYEOF'
import json, sys
config, topo, path_tag, tool, mode, err, dur, lat_count, *rest = sys.argv[1:]
*parallel_values, lt_path = rest
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
        for p in map(int, parallel_values)
    ],
    "latency": {"p50_us": 0, "p95_us": 0, "p99_us": 0, "count": int(lat_count)},
    "footprint": {"binary_size_bytes": 0, "rss_peak_kb": 0, "rss_avg_kb": 0,
                   "cpu_peak_pct": 0, "cpu_avg_pct": 0, "samples": 0},
    "path_class_reported": "unknown",
}
print(json.dumps(obj, indent=2))
PYEOF
  rm -f "$_lt_tmp"
}

cleanup_self_test() {
  local state result events command iperf_events preflight_call cleanup_failure
  local -a cases=(absent graceful forced failure)

  # These mocks exercise the remote cleanup program's transitions without a
  # TUN device or GCP: TERM clears one state, KILL clears another, and the
  # final state must return failure.  `sleep` is a no-op to keep it fast.
  pgrep() {
    [[ "$CLEANUP_TEST_PRESENT" == 1 ]]
  }
  ip() {
    [[ "$CLEANUP_TEST_PRESENT" == 1 ]]
  }
  pkill() {
    CLEANUP_TEST_EVENTS+=" pkill:$1"
    case "$CLEANUP_TEST_STATE:$1" in
      graceful:-TERM|forced:-KILL) CLEANUP_TEST_PRESENT=0 ;;
    esac
    return 0
  }
  sleep() { :; }
  ps() { :; }
  fuser() { :; }
  test_remote_cleanup() { source /dev/stdin <<< "$1"; }

  for state in "${cases[@]}"; do
    CLEANUP_TEST_STATE="$state"
    CLEANUP_TEST_PRESENT=1
    CLEANUP_TEST_EVENTS=""
    [[ "$state" == absent ]] && CLEANUP_TEST_PRESENT=0
    command=$(rs_tun_cleanup_command self-test)
    command=${command//$'exit 0'/$'return 0'}
    command=${command//$'exit 1'/$'return 1'}
    if test_remote_cleanup "$command" 2>/dev/null; then
      result=0
    else
      result=1
    fi
    events="$CLEANUP_TEST_EVENTS"
    case "$state" in
      absent|graceful)
        [[ "$result" == 0 && "$events" != *"pkill:-KILL"* ]] || return 1
        ;;
      forced)
        [[ "$result" == 0 && "$events" == *"pkill:-KILL"* ]] || return 1
        ;;
      failure)
        [[ "$result" == 1 && "$events" == *"pkill:-KILL"* ]] || return 1
        ;;
    esac
  done

  # The optional iperf3 process can already be absent.  Its cleanup must still
  # succeed and remove files that were created by the root-run rs-tun benchmark
  # before a later non-root configuration attempts to create them.
  if ! iperf_events=$(
    CLEANUP_TEST_EVENTS=""
    cat() { CLEANUP_TEST_EVENTS+=" cat"; return 1; }
    kill() { CLEANUP_TEST_EVENTS+=" kill"; return 1; }
    pkill() { CLEANUP_TEST_EVENTS+=" pkill"; return 1; }
    rm() { CLEANUP_TEST_EVENTS+=" rm:$*"; return 0; }
    source /dev/stdin <<< "$(rs_tun_iperf_cleanup_command)"
    printf '%s\n' "$CLEANUP_TEST_EVENTS"
  ); then
    return 1
  fi
  [[ "$iperf_events" == ' kill pkill rm:-f /tmp/iperf3-srv.pid /tmp/iperf3-srv.log' ]] || return 1

  # The measurement preflight must use the server and root execution path,
  # while reusing the exact narrowly scoped iperf3 cleanup program.
  preflight_call=$(
    ssh_sudo() { printf '%s|%s|%s\n' "$1" "$2" "$3"; }
    rs_tun_measurement_preflight
  ) || return 1
  [[ "$preflight_call" == "$SVM|$SZONE|$(rs_tun_iperf_cleanup_command)" ]] || return 1

  # An iperf3 cleanup failure makes the handoff unsafe, but must not skip
  # either daemon endpoint cleanup.
  cleanup_failure=$(
    CLEANUP_TEST_SSH_CALLS=""
    ssh_sudo() {
      CLEANUP_TEST_SSH_CALLS+=" $1:$2"
      [[ "$3" == "$(rs_tun_iperf_cleanup_command)" ]] && return 1
      return 0
    }
    if cleanup_rs_tun; then
      result=0
    else
      result=$?
    fi
    printf '%s|%s\n' "$result" "$CLEANUP_TEST_SSH_CALLS"
  ) || return 1
  [[ "$cleanup_failure" == "1| $SVM:$SZONE $SVM:$SZONE $CVM:$CZONE" ]] || return 1

  unset -f pgrep ip pkill sleep ps fuser test_remote_cleanup
}

result_shape_self_test() {
  emit_stub self-test
  python3 - "$OUT" "$DURATION" "$LATENCY_COUNT" "${PARALLELS[@]}" <<'PYEOF'
import json, sys
path, duration, latency_count, *parallels = sys.argv[1:]
with open(path) as f:
    result = json.load(f)
assert [row["parallel"] for row in result["throughput"]] == [int(p) for p in parallels]
assert all(row["duration_s"] == int(duration) for row in result["throughput"])
assert result["latency"]["count"] == int(latency_count)
PYEOF

  # render-html consumes an aggregate JSON list, not one per-config object.
  # Verify its chart registry is driven solely by the configured result shape.
  local summary="$RDIR/summary.json" dashboard="$RDIR/dashboard.html"
  python3 - "$OUT" "$summary" <<'PYEOF'
import json, sys
with open(sys.argv[1]) as f:
    result = json.load(f)
with open(sys.argv[2], "w") as f:
    json.dump([result], f)
PYEOF
  python3 "$(cd "$(dirname "$0")/../../.." && pwd)/tools/bench/gcp/render-html.py" "$summary" >"$dashboard"
  python3 - "$dashboard" "${PARALLELS[@]}" <<'PYEOF'
import json, re, sys
with open(sys.argv[1]) as f:
    html = f.read()
match = re.search(r"window\.__chartData = (.*?);</script>", html, re.DOTALL)
assert match, "chart registry missing"
registry = json.loads(match.group(1))
expected = [int(p) for p in sys.argv[2:]]
assert all(data["parallels"] == expected
           for chart, data in registry.items() if chart.startswith("tp-"))
PYEOF
}

classifier_self_test
command_shape_self_test

if (( SELF_TEST )); then
  cleanup_self_test
  result_shape_self_test
  rm -rf "$RDIR"
fi

if [[ -n "${GCP_DRY_RUN:-}" ]]; then
  echo "[dry-run] would run $CONFIG on $SVM/$CVM ($TOPOLOGY/$PATH_TAG)" >&2
  (( PROFILE )) && echo "[dry-run] would profile rs-tun after normal metrics" >&2
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

# Measure a production kernel-TUN path after its product CLI path gate.
# Args: LABEL AS_ROOT SERVER_IP DAEMON_PID_FILE FOOTPRINT_FILE BINARY_PATH
# Results are returned in TUN_MEASURE_{THROUGHPUT,LATENCY,FOOTPRINT,BIN_SIZE}.
tun_measure() {
  local label="$1" as_root="$2" server_ip="$3" daemon_pid_file="$4"
  local footprint_file="$5" binary_path="$6" srv_pid mbps
  local tp_json="[]"

  run_tun_command "$as_root" "$SVM" "$SZONE" \
    "pkill -x iperf3 2>/dev/null; nohup iperf3 -s -p $PORT > /tmp/iperf3-srv.log 2>&1 & echo \$! > /tmp/iperf3-srv.pid"
  sleep 2

  srv_pid=$(run_tun_command "$as_root" "$SVM" "$SZONE" "cat $daemon_pid_file")
  remote_start_footprint "$SVM" "$SZONE" "$srv_pid" "$footprint_file"

  for N in "${PARALLELS[@]}"; do
    echo "[gcp] $label: iperf3 N=$N" >&2
    mbps=$(run_tun_command "$as_root" "$CVM" "$CZONE" \
      "iperf3 -c $server_ip -p $PORT -t $DURATION -P $N -R -J 2>/dev/null" \
      | iperf3_mbps 2>/dev/null || echo "0")
    tp_json=$(printf '%s' "$tp_json" | python3 -c "
import json,sys
arr=json.load(sys.stdin)
arr.append({'parallel': $N, 'mbps': float('$mbps'), 'duration_s': $DURATION})
print(json.dumps(arr))
")
    sleep 3
  done

  echo "[gcp] $label: latency" >&2
  TUN_MEASURE_LATENCY=$(run_tun_command "$as_root" "$CVM" "$CZONE" \
    "ping -i $LATENCY_INTERVAL -c $LATENCY_COUNT $server_ip 2>/dev/null" | ping_latency)
  TUN_MEASURE_FOOTPRINT=$(remote_stop_footprint "$SVM" "$SZONE" "$footprint_file")
  TUN_MEASURE_BIN_SIZE=$(ssh_cmd "$SVM" "$SZONE" \
    "stat -c %s $binary_path 2>/dev/null || echo 0")
  TUN_MEASURE_THROUGHPUT="$tp_json"
}

# Emit a production kernel-TUN result. Args: TOOL LABEL PATH_CLASS
tun_emit_result() {
  local tool="$1" label="$2" path_class="$3"
  python3 - "$CONFIG" "$TOPOLOGY" "$PATH_TAG" "$path_class" \
    "$TUN_MEASURE_BIN_SIZE" "$TUN_MEASURE_THROUGHPUT" "$TUN_MEASURE_LATENCY" \
    "$TUN_MEASURE_FOOTPRINT" "$tool" >"$OUT" <<'PYEOF'
import json, sys
config, topo, path_tag, path_class, bin_size, tp, lat, foot, tool = sys.argv[1:10]
obj = {
    "tool": tool,
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
  echo "[gcp] $label: wrote $OUT" >&2
}

# Profile only the production rs-tun server after normal measurements. The
# authkey is deliberately absent from commands, metadata, and artifacts.
profile_prepare() {
  ssh_sudo "$SVM" "$SZONE" "if command -v perf >/dev/null; then exit 0; fi; apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq linux-perf || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq linux-tools-common linux-tools-\$(uname -r) || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq linux-tools-common || true; command -v perf >/dev/null"
}

profile_remote_cleanup() {
  ssh_sudo "$SVM" "$SZONE" "pid=\$(cat /tmp/rs-tun-perf.pid 2>/dev/null || true); case \$pid in *[!0-9]*|\"\") ;; *) kill \$pid 2>/dev/null || true ;; esac; rm -f /tmp/rs-tun-perf.pid /tmp/rs-tun-perf.data /tmp/rs-tun-perf-children.txt /tmp/rs-tun-perf-self.txt /tmp/rs-tun-perf.log /tmp/rs-tun-profile-iperf.json" || true
}

profile_rs_tun() {
  local profile_dir="$RDIR/profile" srv_pid remote_data=/tmp/rs-tun-perf.data commit
  mkdir -p "$profile_dir"
  if ! srv_pid=$(ssh_sudo "$SVM" "$SZONE" "cat /tmp/rs-tun-srv.pid"); then
    profile_remote_cleanup; return 1
  fi
  case "$srv_pid" in *[!0-9]*|"") profile_remote_cleanup; return 1 ;; esac
  if ! ssh_sudo "$SVM" "$SZONE" "rm -f $remote_data /tmp/rs-tun-perf-children.txt /tmp/rs-tun-perf-self.txt; nohup perf record -F 199 -g -p $srv_pid -o $remote_data -- sleep $((DURATION + 3)) >/tmp/rs-tun-perf.log 2>&1 & echo \$! >/tmp/rs-tun-perf.pid"; then
    profile_remote_cleanup; return 1
  fi
  # This extra P10 is intentionally outside tun_measure and result JSON.
  if ! run_tun_command 0 "$CVM" "$CZONE" "iperf3 -c $server_ip -p $PORT -t $DURATION -P 10 -R -J >/tmp/rs-tun-profile-iperf.json"; then
    profile_remote_cleanup; return 1
  fi
  if ! ssh_sudo "$SVM" "$SZONE" "elapsed=0; while kill -0 \$(cat /tmp/rs-tun-perf.pid) 2>/dev/null; do (( elapsed < $((DURATION + 30)) )) || exit 1; sleep 1; elapsed=\$((elapsed + 1)); done; test -s $remote_data && perf report --stdio --children -i $remote_data > /tmp/rs-tun-perf-children.txt && perf report --stdio --no-children -i $remote_data > /tmp/rs-tun-perf-self.txt && chmod 0644 $remote_data /tmp/rs-tun-perf-children.txt /tmp/rs-tun-perf-self.txt"; then
    profile_remote_cleanup; return 1
  fi
  if ! scp_from "$SVM" "$SZONE" "$remote_data" "$profile_dir/perf.data" ||
     ! scp_from "$SVM" "$SZONE" /tmp/rs-tun-perf-children.txt "$profile_dir/perf-children.txt" ||
     ! scp_from "$SVM" "$SZONE" /tmp/rs-tun-perf-self.txt "$profile_dir/perf-self.txt" ||
     [[ ! -s "$profile_dir/perf.data" || ! -s "$profile_dir/perf-children.txt" || ! -s "$profile_dir/perf-self.txt" ]]; then
    profile_remote_cleanup; return 1
  fi
  if ! commit=$(git -C "$(cd "$(dirname "$0")/../../.." && pwd)" rev-parse HEAD); then
    profile_remote_cleanup; return 1
  fi
  if ! python3 - "$profile_dir/metadata.json" "$commit" "$TOPOLOGY" "$PATH_TAG" "$CONFIG" "$DURATION" "$srv_pid" "$OUT" <<'PYEOF'
import json, sys
out, commit, topo, path, config, duration, pid, result = sys.argv[1:]
json.dump({"commit":commit,"topology":topo,"path":path,"config":config,
           "parallel":10,"duration_s":int(duration),"frequency_hz":199,
           "pid":int(pid),"command":"rustscaled","result_json":result}, open(out,"w"), indent=2)
PYEOF
  then
    profile_remote_cleanup; return 1
  fi
  profile_remote_cleanup
}

profile_command_self_test() {
  local log=""
  ssh_sudo() { log+=" sudo:$3"; [[ "$3" == *'perf report'* ]] && return 1; [[ "$3" == *'cat /tmp/rs-tun-srv.pid'* ]] && { printf '42\n'; return 0; }; return 0; }
  run_tun_command() { log+=" iperf:$4"; return 0; }
  scp_from() { log+=" copy:$3"; : >"$4"; }
  server_ip=100.64.0.1
  if profile_rs_tun; then return 1; fi
  [[ "$log" == *'perf record -F 199 -g -p'* && "$log" == *'iperf3 -c 100.64.0.1 -p 5201 -t 10 -P 10 -R'* ]] || return 1
  [[ "${log#*perf record}" == *'iperf:'* ]] || return 1
  [[ "$log" == *'rm -f /tmp/rs-tun-perf.pid'* ]] || return 1
  unset -f ssh_sudo run_tun_command scp_from
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
# Config: rs-tun — production rustscaled + rustscale CLIs + kernel iperf3
# ===========================================================================
run_rs_tun() {
  echo "[gcp] rs-tun: starting production rustscaled daemons" >&2
  if (( PROFILE )) && ! profile_prepare; then
    emit_stub "rs-tun-perf-prepare-failed"
    cleanup_rs_tun || return "$FATAL_HANDOFF_STATUS"
    return 1
  fi
  ssh_sudo "$SVM" "$SZONE"  'rm -rf /tmp/rs-tun-srv; rm -f /tmp/rs-tun-srv.log /tmp/rs-tun-srv.pid /tmp/rs-tun-srv.sock'
  ssh_sudo "$CVM" "$CZONE"  'rm -rf /tmp/rs-tun-cli; rm -f /tmp/rs-tun-cli.log /tmp/rs-tun-cli.pid /tmp/rs-tun-cli.sock'
  ssh_sudo "$SVM" "$SZONE" \
    "TS_AUTHKEY=$AUTHKEY nohup /opt/rustscale/target/release/rustscaled run --tun \
       --statedir /tmp/rs-tun-srv --socket /tmp/rs-tun-srv.sock --hostname $SHOST \
       > /tmp/rs-tun-srv.log 2>&1 & echo \$! > /tmp/rs-tun-srv.pid"
  ssh_sudo "$CVM" "$CZONE" \
    "TS_AUTHKEY=$AUTHKEY nohup /opt/rustscale/target/release/rustscaled run --tun \
       --statedir /tmp/rs-tun-cli --socket /tmp/rs-tun-cli.sock --hostname $CHOST \
       > /tmp/rs-tun-cli.log 2>&1 & echo \$! > /tmp/rs-tun-cli.pid"

  local server_ip
  server_ip=$(wait_tun_ip 1 "$SVM" "$SZONE" /opt/rustscale/target/release/rustscale /tmp/rs-tun-srv.sock /tmp/rs-tun-srv.log) || {
    emit_stub "rs-no-ip-srv" "$(capture_log_tail "$SVM" "$SZONE" /tmp/rs-tun-srv.log)"
    if ! cleanup_rs_tun; then return "$FATAL_HANDOFF_STATUS"; fi
    return 1
  }
  wait_tun_ip 1 "$CVM" "$CZONE" /opt/rustscale/target/release/rustscale /tmp/rs-tun-cli.sock /tmp/rs-tun-cli.log >/dev/null || {
    emit_stub "rs-no-ip-cli" "$(capture_log_tail "$CVM" "$CZONE" /tmp/rs-tun-cli.log)"
    if ! cleanup_rs_tun; then return "$FATAL_HANDOFF_STATUS"; fi
    return 1
  }
  echo "[gcp] rs-tun: server tailnet IP=$server_ip" >&2

  local path_class
  path_class=$(tun_path_gate 1 "$CVM" "$CZONE" /opt/rustscale/target/release/rustscale /tmp/rs-tun-cli.sock "$server_ip" "$PATH_TAG" /tmp/rs-tun-cli.path.log) || {
    emit_stub "rs-cli-path-gate-failed" "$(capture_log_tail "$CVM" "$CZONE" /tmp/rs-tun-cli.path.log)"
    if ! cleanup_rs_tun; then return "$FATAL_HANDOFF_STATUS"; fi
    return 1
  }

  if ! rs_tun_measurement_preflight; then
    echo "[gcp] ERROR: could not clear rs-tun iperf3 leftovers on $SVM" >&2
    emit_stub "rs-tun-iperf-preflight-failed" "$(capture_log_tail "$SVM" "$SZONE" /tmp/iperf3-srv.log)"
    if ! cleanup_rs_tun; then return "$FATAL_HANDOFF_STATUS"; fi
    return 1
  fi

  tun_measure rs-tun 0 "$server_ip" /tmp/rs-tun-srv.pid \
    /tmp/rs-tun-srv.footprint /opt/rustscale/target/release/rustscaled

  if (( PROFILE )) && ! profile_rs_tun; then
    emit_stub "rs-tun-profile-failed" "$(capture_log_tail "$SVM" "$SZONE" /tmp/rs-tun-perf.log)"
    cleanup_rs_tun || return "$FATAL_HANDOFF_STATUS"
    return 1
  fi

  # Cleanup.
  if ! cleanup_rs_tun; then
    emit_stub "rs-tun-cleanup-failed" "$(capture_log_tail "$SVM" "$SZONE" /tmp/rs-tun-srv.log)"
    return "$FATAL_HANDOFF_STATUS"
  fi

  tun_emit_result rustscale rs-tun "$path_class"
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
        time.sleep(0.1)
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
    cleanup_ts_tun
    return 1
  fi
  local server_ip
  if ! server_ip=$(wait_tun_ip 1 "$SVM" "$SZONE" tailscale /tmp/ts-tun-srv.sock /tmp/ts-tun-srv.log); then
    echo "[gcp] ERROR: no tailnet IP on server" >&2
    local _lt
    _lt=$(capture_log_tail "$SVM" "$SZONE" /tmp/ts-tun-srv.log)
    emit_stub "ts-no-ip-srv" "$_lt"
    cleanup_ts_tun
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
    cleanup_ts_tun
    return 1
  fi

  if ! wait_tun_ip 1 "$CVM" "$CZONE" tailscale /tmp/ts-tun-cli.sock /tmp/ts-tun-cli.log >/dev/null; then
    echo "[gcp] ERROR: tailscale CLI did not report a client IP" >&2
    local _lt
    _lt=$(capture_log_tail "$CVM" "$CZONE" /tmp/ts-tun-cli.log)
    emit_stub "ts-no-ip-cli" "$_lt"
    cleanup_ts_tun
    return 1
  fi

  local path_class
  path_class=$(tun_path_gate 1 "$CVM" "$CZONE" tailscale /tmp/ts-tun-cli.sock "$server_ip" "$PATH_TAG" /tmp/ts-tun-cli.path.log) || {
    emit_stub "ts-cli-path-gate-failed" "$(capture_log_tail "$CVM" "$CZONE" /tmp/ts-tun-cli.path.log)"; cleanup_ts_tun; return 1; }

  tun_measure ts-tun 1 "$server_ip" /tmp/ts-tun-srv.pid \
    /tmp/ts-tun-srv.footprint /usr/sbin/tailscaled

  cleanup_ts_tun

  tun_emit_result tailscaled ts-tun "$path_class"
}

# ---------------------------------------------------------------------------
# Dispatch.
# ---------------------------------------------------------------------------
if (( SELF_TEST )); then
  profile_command_self_test
  echo "run-config self-tests: OK" >&2
  exit 0
fi
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
