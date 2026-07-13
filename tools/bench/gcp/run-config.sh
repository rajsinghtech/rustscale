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
--repeat N: production TUN samples per parallelism (1..=9; default 3)
EOF
  exit 2
}

# Parse trailing options independently of their order.  It intentionally has
# no GCP dependencies so the CLI contract can be tested locally.
parse_run_config_options() {
  PROFILE=0
  REPEAT=3
  local seen_profile=0 seen_repeat=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --profile)
        (( seen_profile == 0 )) || { echo "duplicate option: --profile" >&2; return 2; }
        PROFILE=1; seen_profile=1; shift ;;
      --repeat)
        (( seen_repeat == 0 )) || { echo "duplicate option: --repeat" >&2; return 2; }
        [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || { echo "--repeat requires a value" >&2; return 2; }
        [[ "$2" =~ ^[1-9]$ ]] || { echo "--repeat must be an integer in 1..=9" >&2; return 2; }
        REPEAT="$2"; seen_repeat=1; shift 2 ;;
      *) echo "unknown option: $1" >&2; return 2 ;;
    esac
  done
}

run_config_option_parsing_self_test() {
  local actual status
  actual=$(parse_run_config_options --profile --repeat 1; printf '%s/%s\n' "$PROFILE" "$REPEAT") || return 1
  [[ "$actual" == '1/1' ]] || return 1
  actual=$(parse_run_config_options --repeat 9 --profile; printf '%s/%s\n' "$PROFILE" "$REPEAT") || return 1
  [[ "$actual" == '1/9' ]] || return 1
  actual=$(parse_run_config_options; printf '%s/%s\n' "$PROFILE" "$REPEAT") || return 1
  [[ "$actual" == '0/3' ]] || return 1
  local -a case_args=()
  for args in '--repeat' '--repeat 0' '--repeat 10' '--repeat 1.5' '--repeat 1 --repeat 2' '--profile --profile' '--unknown'; do
    read -r -a case_args <<< "$args"
    if ( parse_run_config_options "${case_args[@]}" ) >/dev/null 2>&1; then
      return 1
    else
      status=$?
      (( status == 2 )) || return 1
    fi
  done
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
  REPEAT=3
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
  parse_run_config_options "$@" || exit $?
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
RUNTIME_STATS_MAX_LINES=80
RUNTIME_STATS_MAX_COLUMNS=512
RUNTIME_STATS_MAX_BYTES=16384
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

# Apply the result bounds locally as well as remotely. This keeps a mocked or
# unexpectedly chatty SSH transport from widening the captured JSON field.
bound_rs_tun_runtime_stats() {
  sed -n "1,${RUNTIME_STATS_MAX_LINES}p" \
    | cut -c1-"$RUNTIME_STATS_MAX_COLUMNS" \
    | head -c "$RUNTIME_STATS_MAX_BYTES"
}

# Capture only bounded, transport-relevant daemon diagnostics. This intentionally
# does not copy a log tail: daemon logs can contain control-plane output and
# credentials. Args: VM ZONE LOGFILE.
capture_rs_tun_runtime_stats() {
  local vm="$1" zone="$2" logfile="$3" quoted_log
  printf -v quoted_log '%q' "$logfile"
  ssh_cmd "$vm" "$zone" \
    "grep -E 'rustscale: (Linux UDP GRO receive (enabled|unavailable|disabled|permanently disabled)|udp_gro_stats|.*RXQ overflow|SO_RXQ_OVFL|.*wg_handoff_stats|magicsock_udp_socket_buffers)' $quoted_log 2>/dev/null | tail -n $RUNTIME_STATS_MAX_LINES | cut -c1-$RUNTIME_STATS_MAX_COLUMNS | head -c $RUNTIME_STATS_MAX_BYTES" \
    2>/dev/null | bound_rs_tun_runtime_stats || true
}

# Final rs-tun result lifecycle. Capture while the daemons are alive, then
# clean them up, and only then write the result. Keeping this as one callable
# unit makes the ordering executable and locally testable.
finalize_rs_tun_measurement() {
  local path_class="$1" runtime_server runtime_client
  runtime_server=$(capture_rs_tun_runtime_stats "$SVM" "$SZONE" /tmp/rs-tun-srv.log)
  runtime_client=$(capture_rs_tun_runtime_stats "$CVM" "$CZONE" /tmp/rs-tun-cli.log)

  if ! cleanup_rs_tun; then
    emit_stub "rs-tun-cleanup-failed" "$(capture_log_tail "$SVM" "$SZONE" /tmp/rs-tun-srv.log)"
    return "$FATAL_HANDOFF_STATUS"
  fi

  tun_emit_result rustscale rs-tun "$path_class" "$runtime_server" "$runtime_client"
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
    ping_args="--until-direct --c=30"
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
  [[ "$ts_direct" == 'tailscale --socket=/tmp/ts.sock ping --until-direct --c=30 100.64.0.1' ]] || return 1
  [[ "$rs_direct" == '/opt/rustscale/target/release/rustscale --socket=/tmp/rs.sock ping --until-direct --c=30 100.64.0.1' ]] || return 1
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
  if ! ssh_sudo "$SVM" "$SZONE" "$(rs_tun_iperf_cleanup_command server)"; then
    echo "[gcp] ERROR: rs-tun iperf3 cleanup failed on server $SVM" >&2
    status=1
  fi
  if ! ssh_sudo "$CVM" "$CZONE" "$(rs_tun_iperf_cleanup_command client)"; then
    echo "[gcp] ERROR: rs-tun iperf3 cleanup failed on client $CVM" >&2
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

# Label-specific iperf3 artifacts keep the non-root rs-tun client separate
# from root-owned ts-tun artifacts when a matrix reuses the same VMs.
tun_iperf_server_pid_path() { printf '/tmp/%s-iperf3-srv.pid' "$1"; }
tun_iperf_server_log_path() { printf '/tmp/%s-iperf3-srv.log' "$1"; }
tun_iperf_warmup_path() { printf '/tmp/%s-iperf3-warmup.json' "$1"; }
tun_iperf_sample_path() { printf '/tmp/%s-iperf3-current.json' "$1"; }

# Print the root-side iperf3 cleanup program used before rs-tun hands a VM to
# the next configuration.  Remove its label-specific files even when the
# optional process is already absent so a non-root benchmark can create them.
# Args: server | client
rs_tun_iperf_cleanup_command() {
  local role="${1:-server}"
  if [[ "$role" == client ]]; then
    printf 'rm -f %s %s\n' "$(tun_iperf_warmup_path rs-tun)" "$(tun_iperf_sample_path rs-tun)"
    return 0
  fi
  printf '%s\n' \
"pidfile=$(tun_iperf_server_pid_path rs-tun)" \
'kill "$(cat "$pidfile" 2>/dev/null)" 2>/dev/null || true' \
'pkill -x iperf3 2>/dev/null || true' \
"rm -f \"\$pidfile\" $(tun_iperf_server_log_path rs-tun)"
}

# Clear root-owned rs-tun artifacts before its non-root measurement.
rs_tun_measurement_preflight() {
  ssh_sudo "$SVM" "$SZONE" "$(rs_tun_iperf_cleanup_command server)" \
    && ssh_sudo "$CVM" "$CZONE" "$(rs_tun_iperf_cleanup_command client)"
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
    "kill \$(cat $(tun_iperf_server_pid_path ts-tun) 2>/dev/null) 2>/dev/null; pkill -x iperf3 2>/dev/null; \
     tailscale --socket=/tmp/ts-tun-srv.sock down 2>/dev/null; \
     kill \$(cat /tmp/ts-tun-srv.pid 2>/dev/null) 2>/dev/null; pkill -x tailscaled 2>/dev/null; \
     cp /etc/resolv.conf.bench-bak /etc/resolv.conf 2>/dev/null || true; rm -f /etc/resolv.conf.bench-bak $(tun_iperf_server_pid_path ts-tun) $(tun_iperf_server_log_path ts-tun)" || true
  ssh_sudo "$CVM" "$CZONE" \
    "tailscale --socket=/tmp/ts-tun-cli.sock down 2>/dev/null; \
     kill \$(cat /tmp/ts-tun-cli.pid 2>/dev/null) 2>/dev/null; pkill -x tailscaled 2>/dev/null; \
     cp /etc/resolv.conf.bench-bak /etc/resolv.conf 2>/dev/null || true; rm -f /etc/resolv.conf.bench-bak $(tun_iperf_warmup_path ts-tun) $(tun_iperf_sample_path ts-tun)" || true
}

# ts-tun also removes its own root-owned artifacts before each measurement so
# direct/DERP reruns cannot reuse a prior sample diagnostic.
ts_tun_measurement_preflight() {
  ssh_sudo "$SVM" "$SZONE" \
    "kill \$(cat $(tun_iperf_server_pid_path ts-tun) 2>/dev/null) 2>/dev/null || true; pkill -x iperf3 2>/dev/null || true; rm -f $(tun_iperf_server_pid_path ts-tun) $(tun_iperf_server_log_path ts-tun)" \
    && ssh_sudo "$CVM" "$CZONE" \
      "rm -f $(tun_iperf_warmup_path ts-tun) $(tun_iperf_sample_path ts-tun)"
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
    "$DURATION" "$LATENCY_COUNT" "$REPEAT" "${PARALLELS[@]}" "$_lt_tmp" >"$OUT" <<'PYEOF'
import json, sys
config, topo, path_tag, tool, mode, err, dur, lat_count, repeat, *rest = sys.argv[1:]
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
    "repeat": int(repeat),
    "error": err,
    "log_tail": log_tail,
    "throughput": [
        {"parallel": p,
         "mbps": 0, "duration_s": int(dur),
         "samples_mbps": [0] * int(repeat), "statistic": "median"}
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
  local state result events command iperf_events preflight_call preflight_expected ts_preflight cleanup_failure
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
    source /dev/stdin <<< "$(rs_tun_iperf_cleanup_command server)"
    printf '%s\n' "$CLEANUP_TEST_EVENTS"
  ); then
    return 1
  fi
  [[ "$iperf_events" == ' kill pkill rm:-f /tmp/rs-tun-iperf3-srv.pid /tmp/rs-tun-iperf3-srv.log' ]] || return 1

  local client_cleanup
  client_cleanup=$(rs_tun_iperf_cleanup_command client)
  [[ "$client_cleanup" == 'rm -f /tmp/rs-tun-iperf3-warmup.json /tmp/rs-tun-iperf3-current.json' ]] || return 1

  # The measurement preflight must use root on both endpoints, clearing the
  # server and client artifacts before a non-root rs-tun client creates them.
  preflight_call=$(
    ssh_sudo() { printf '%s|%s|%s\n' "$1" "$2" "$3"; }
    rs_tun_measurement_preflight
  ) || return 1
  preflight_expected="$SVM|$SZONE|$(rs_tun_iperf_cleanup_command server)"$'\n'"$CVM|$CZONE|$(rs_tun_iperf_cleanup_command client)"
  [[ "$preflight_call" == "$preflight_expected" ]] || return 1

  ts_preflight=$(
    ssh_sudo() { printf '%s|%s|%s\n' "$1" "$2" "$3"; }
    ts_tun_measurement_preflight
  ) || return 1
  [[ "$ts_preflight" == *"$SVM|$SZONE|"*"/tmp/ts-tun-iperf3-srv.pid"* ]] || return 1
  [[ "$ts_preflight" == *"$CVM|$CZONE|rm -f /tmp/ts-tun-iperf3-warmup.json /tmp/ts-tun-iperf3-current.json"* ]] || return 1

  # An iperf3 cleanup failure makes the handoff unsafe, but must not skip
  # either daemon endpoint cleanup.
  cleanup_failure=$(
    CLEANUP_TEST_SSH_CALLS=""
    ssh_sudo() {
      CLEANUP_TEST_SSH_CALLS+=" $1:$2"
      [[ "$3" == "$(rs_tun_iperf_cleanup_command server)" ]] && return 1
      return 0
    }
    if cleanup_rs_tun; then
      result=0
    else
      result=$?
    fi
    printf '%s|%s\n' "$result" "$CLEANUP_TEST_SSH_CALLS"
  ) || return 1
  [[ "$cleanup_failure" == "1| $SVM:$SZONE $CVM:$CZONE $SVM:$SZONE $CVM:$CZONE" ]] || return 1

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
assert result["repeat"] == 3
assert all(row["statistic"] == "median" and len(row["samples_mbps"]) == 3
           for row in result["throughput"])
assert all(row["samples_mbps"] == [0, 0, 0] and row["mbps"] == 0
           for row in result["throughput"])
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

runtime_stats_self_test() {
  local log_file stats command line bytes
  log_file=$(mktemp "$RDIR/runtime-stats-test.XXXXXX")
  ssh_cmd() {
    printf '%s\n' "$3" >"$log_file"
    for ((line = 0; line <= RUNTIME_STATS_MAX_LINES; line++)); do
      printf 'rustscale: udp_gro_stats %*s\n' "$((RUNTIME_STATS_MAX_COLUMNS + 100))" '' \
        | tr ' ' x
    done
  }
  stats=$(capture_rs_tun_runtime_stats "$SVM" "$SZONE" '/tmp/rs tun.log')
  [[ "$stats" == *'udp_gro_stats'* ]] || return 1
  bytes=$(LC_ALL=C printf '%s' "$stats" | wc -c)
  (( bytes <= RUNTIME_STATS_MAX_BYTES )) || return 1
  (( $(printf '%s\n' "$stats" | wc -l) <= RUNTIME_STATS_MAX_LINES )) || return 1
  while IFS= read -r line; do
    (( ${#line} <= RUNTIME_STATS_MAX_COLUMNS )) || return 1
  done <<<"$stats"

  # Check the additional diagnostic independently so it cannot replace the
  # oversized fixture that exercises the line, column, and byte bounds above.
  ssh_cmd() {
    printf '%s\n' "$3" >"$log_file"
    printf '%s\n' 'rustscale: magicsock_udp_socket_buffers requested=7340032 recv_outcome=force_failed_portable_ok send_outcome=force_failed_portable_ok actual_recv=425984 actual_send=425984'
  }
  stats=$(capture_rs_tun_runtime_stats "$SVM" "$SZONE" '/tmp/rs tun.log')
  [[ "$stats" == *'magicsock_udp_socket_buffers'* ]] || return 1
  command=$(<"$log_file")
  [[ "$command" == *"grep -E"* && "$command" == *"tail -n $RUNTIME_STATS_MAX_LINES"* \
    && "$command" == *"cut -c1-$RUNTIME_STATS_MAX_COLUMNS"* \
    && "$command" == *"head -c $RUNTIME_STATS_MAX_BYTES"* \
    && "$command" == *'magicsock_udp_socket_buffers'* \
    && "$command" == *'/tmp/rs\'*' tun.log'* ]] || return 1

  ssh_cmd() { :; }
  [[ -z "$(capture_rs_tun_runtime_stats "$SVM" "$SZONE" /tmp/rs-tun-empty.log)" ]] || return 1
  rm -f "$log_file"
  unset -f ssh_cmd
}

rs_tun_lifecycle_self_test() {
  local events
  events=$(mktemp "$RDIR/rs-tun-lifecycle-test.XXXXXX")
  capture_rs_tun_runtime_stats() {
    printf 'capture:%s\n' "$1" >>"$events"
    printf 'stats-%s' "$1"
  }
  cleanup_rs_tun() { printf '%s\n' cleanup >>"$events"; }
  tun_emit_result() {
    printf 'emit:%s:%s:%s:%s:%s\n' "$1" "$2" "$3" "$4" "$5" >>"$events"
  }

  finalize_rs_tun_measurement direct
  [[ "$(<"$events")" == $'capture:self-test-server\ncapture:self-test-client\ncleanup\nemit:rustscale:rs-tun:direct:stats-self-test-server:stats-self-test-client' ]] || return 1
  rm -f "$events"
  unset -f capture_rs_tun_runtime_stats cleanup_rs_tun tun_emit_result
}

classifier_self_test
command_shape_self_test
run_config_option_parsing_self_test

if (( SELF_TEST )); then
  cleanup_self_test
  result_shape_self_test
  runtime_stats_self_test
  rs_tun_lifecycle_self_test
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

# Extract one positive, finite iperf3 throughput sample.  This is deliberately
# separate from iperf3_mbps so userspace measurement behavior remains intact.
tun_iperf3_mbps() {
  python3 -c '
import json, math, sys
d = json.load(sys.stdin)
if "total_mbps" in d:
    value = d["total_mbps"]
elif "down_mbps" in d:
    value = d["down_mbps"]
elif "up_mbps" in d:
    value = d["up_mbps"]
else:
    end = d.get("end", {})
    value = end.get("sum_received", end.get("sum", {})).get("bits_per_second", 0) / 1e6
try:
    value = float(value)
except (TypeError, ValueError):
    raise SystemExit("invalid iperf3 throughput sample")
if not math.isfinite(value) or value <= 0:
    raise SystemExit("invalid iperf3 throughput sample")
print(repr(value))
'
}

# Add one TUN throughput row, preserving execution order while calculating the
# mathematically exact median (including an arithmetic mean for even repeats).
# Args: CURRENT_JSON PARALLEL DURATION SAMPLE...
append_tun_throughput_row() {
  local current="$1" parallel="$2" duration="$3"
  shift 3
  python3 - "$current" "$parallel" "$duration" "$@" <<'PYEOF'
import json, math, sys
rows = json.loads(sys.argv[1])
parallel, duration = int(sys.argv[2]), int(sys.argv[3])
samples = [float(value) for value in sys.argv[4:]]
if not samples or any(not math.isfinite(value) or value <= 0 for value in samples):
    raise SystemExit("invalid TUN throughput samples")
ordered = sorted(samples)
middle = len(ordered) // 2
median = ordered[middle] if len(ordered) % 2 else (ordered[middle - 1] + ordered[middle]) / 2
rows.append({"parallel": parallel, "mbps": median, "duration_s": duration,
             "samples_mbps": samples, "statistic": "median"})
print(json.dumps(rows))
PYEOF
}

# Measure a production kernel-TUN path after its product CLI path gate.
# Args: LABEL AS_ROOT SERVER_IP DAEMON_PID_FILE FOOTPRINT_FILE BINARY_PATH
# Results are returned in TUN_MEASURE_{THROUGHPUT,LATENCY,FOOTPRINT,BIN_SIZE}.
tun_measure() {
  local label="$1" as_root="$2" server_ip="$3" daemon_pid_file="$4"
  local footprint_file="$5" binary_path="$6" srv_pid mbps sample_json N repeat_index
  local server_pid_path server_log_path warmup_path sample_path
  local tp_json="[]" footprint_started=0 sample_number=0 total_samples
  local -a samples=()
  total_samples=$((${#PARALLELS[@]} * REPEAT))
  server_pid_path=$(tun_iperf_server_pid_path "$label")
  server_log_path=$(tun_iperf_server_log_path "$label")
  warmup_path=$(tun_iperf_warmup_path "$label")
  sample_path=$(tun_iperf_sample_path "$label")
  TUN_MEASURE_FAILURE_STAGE=""

  TUN_MEASURE_FAILURE_STAGE=server-start
  run_tun_command "$as_root" "$SVM" "$SZONE" \
    "pkill -x iperf3 2>/dev/null; nohup iperf3 -s -p $PORT > $server_log_path 2>&1 & echo \$! > $server_pid_path" || return 1
  sleep 2

  # This reverse P1 primes the established TUN/TCP path, but is intentionally
  # before footprint sampling and never added to normal result data.
  echo "[gcp] $label: warmup reverse P1 (3s)" >&2
  TUN_MEASURE_FAILURE_STAGE=warmup
  run_tun_command "$as_root" "$CVM" "$CZONE" \
    "iperf3 -c $server_ip -p $PORT -t 3 -P 1 -R -J >$warmup_path 2>&1" || return 1

  TUN_MEASURE_FAILURE_STAGE=daemon-pid
  srv_pid=$(run_tun_command "$as_root" "$SVM" "$SZONE" "cat $daemon_pid_file") || return 1
  TUN_MEASURE_FAILURE_STAGE=footprint-start
  footprint_started=1
  remote_start_footprint "$SVM" "$SZONE" "$srv_pid" "$footprint_file" || {
    remote_stop_footprint "$SVM" "$SZONE" "$footprint_file" >/dev/null || true
    footprint_started=0
    return 1
  }

  for N in "${PARALLELS[@]}"; do
    samples=()
    for ((repeat_index = 1; repeat_index <= REPEAT; repeat_index++)); do
      echo "[gcp] $label: iperf3 N=$N sample=$repeat_index/$REPEAT" >&2
      TUN_MEASURE_FAILURE_STAGE=measured-sample
      sample_json=$(run_tun_command "$as_root" "$CVM" "$CZONE" \
        "iperf3 -c $server_ip -p $PORT -t $DURATION -P $N -R -J >$sample_path 2>&1; status=\$?; cat $sample_path; exit \$status") || {
          (( footprint_started )) && remote_stop_footprint "$SVM" "$SZONE" "$footprint_file" >/dev/null || true
          return 1
        }
      mbps=$(printf '%s' "$sample_json" | tun_iperf3_mbps) || {
        (( footprint_started )) && remote_stop_footprint "$SVM" "$SZONE" "$footprint_file" >/dev/null || true
        return 1
      }
      samples+=("$mbps")
      sample_number=$((sample_number + 1))
      if (( sample_number < total_samples )); then
        sleep 3
      fi
    done
    tp_json=$(append_tun_throughput_row "$tp_json" "$N" "$DURATION" "${samples[@]}") || {
      (( footprint_started )) && remote_stop_footprint "$SVM" "$SZONE" "$footprint_file" >/dev/null || true
      return 1
    }
  done

  echo "[gcp] $label: latency" >&2
  TUN_MEASURE_FAILURE_STAGE=latency
  TUN_MEASURE_LATENCY=$(run_tun_command "$as_root" "$CVM" "$CZONE" \
    "ping -i $LATENCY_INTERVAL -c $LATENCY_COUNT $server_ip 2>/dev/null" | ping_latency) || {
      remote_stop_footprint "$SVM" "$SZONE" "$footprint_file" >/dev/null || true
      return 1
    }
  TUN_MEASURE_FAILURE_STAGE=footprint-stop
  TUN_MEASURE_FOOTPRINT=$(remote_stop_footprint "$SVM" "$SZONE" "$footprint_file") || return 1
  TUN_MEASURE_FAILURE_STAGE=binary-stat
  TUN_MEASURE_BIN_SIZE=$(ssh_cmd "$SVM" "$SZONE" \
    "stat -c %s $binary_path 2>/dev/null || echo 0") || return 1
  TUN_MEASURE_THROUGHPUT="$tp_json"
  TUN_MEASURE_FAILURE_STAGE=""
}

# Select a diagnostic that corresponds to the actual failed TUN stage.  A
# successful earlier iperf artifact is never presented as evidence for a
# later latency, footprint, or binary-stat failure.
# Args: LABEL FAILURE_STAGE
tun_measure_failure_tail() {
  local label="$1" stage="${2:-unknown}"
  case "$stage" in
    server-start|daemon-pid)
      capture_log_tail "$SVM" "$SZONE" "$(tun_iperf_server_log_path "$label")" ;;
    warmup)
      capture_log_tail "$CVM" "$CZONE" "$(tun_iperf_warmup_path "$label")" ;;
    measured-sample)
      capture_log_tail "$CVM" "$CZONE" "$(tun_iperf_sample_path "$label")" ;;
    footprint-start|latency|footprint-stop|binary-stat)
      printf '[gcp] %s: tun_measure failed during %s; no iperf diagnostic applies\n' "$label" "$stage" ;;
    *)
      printf '[gcp] %s: tun_measure failed at unknown stage; no diagnostic file selected\n' "$label" ;;
  esac
}

# Emit a production kernel-TUN result. Args: TOOL LABEL PATH_CLASS
tun_emit_result() {
  local tool="$1" label="$2" path_class="$3" runtime_server="${4:-}" runtime_client="${5:-}"
  python3 - "$CONFIG" "$TOPOLOGY" "$PATH_TAG" "$path_class" \
    "$TUN_MEASURE_BIN_SIZE" "$TUN_MEASURE_THROUGHPUT" "$TUN_MEASURE_LATENCY" \
    "$TUN_MEASURE_FOOTPRINT" "$tool" "$REPEAT" "$runtime_server" "$runtime_client" >"$OUT" <<'PYEOF'
import json, sys
config, topo, path_tag, path_class, bin_size, tp, lat, foot, tool, repeat, runtime_server, runtime_client = sys.argv[1:13]
obj = {
    "tool": tool,
    "mode": "tun",
    "topology": topo,
    "path": path_tag,
    "config": config,
    "repeat": int(repeat),
    "error": "",
    "log_tail": "",
    "throughput": json.loads(tp),
    "latency": json.loads(lat),
    "footprint": dict(json.loads(foot), binary_size_bytes=int(bin_size)),
    "path_class_reported": path_class,
}
if config == "rs-tun":
    obj["runtime_stats"] = {"server": runtime_server, "client": runtime_client}

print(json.dumps(obj, indent=2))
PYEOF
  echo "[gcp] $label: wrote $OUT" >&2
}

tun_measure_self_test() {
  local log_file count_file sleep_file rows odd even
  local saved_repeat="$REPEAT"
  local -a saved_parallels=("${PARALLELS[@]}")
  log_file=$(mktemp "$RDIR/tun-measure-test.XXXXXX")
  count_file=$(mktemp "$RDIR/tun-measure-count.XXXXXX")
  sleep_file=$(mktemp "$RDIR/tun-measure-sleeps.XXXXXX")
  printf '0' >"$count_file"

  run_tun_command() {
    printf '%s\n' "$4" >>"$log_file"
    case "$4" in
      'cat /tmp/test-daemon.pid') printf '42\n' ;;
      *'iperf3 -c'*'-t 10'*)
        [[ "${TUN_TEST_FAIL_AFTER_START:-0}" != 1 ]] || return 1
        [[ "${TUN_TEST_ZERO_SAMPLE:-0}" != 1 ]] || { printf '%s' '{"total_mbps": 0}'; return 0; }
        TUN_TEST_SAMPLE=$(<"$count_file")
        TUN_TEST_SAMPLE=$((TUN_TEST_SAMPLE + 1))
        printf '%s' "$TUN_TEST_SAMPLE" >"$count_file"
        case "$TUN_TEST_SAMPLE" in
          1) printf '%s' '{"total_mbps": 100}' ;;
          2) printf '%s' '{"total_mbps": 200}' ;;
          3) printf '%s' '{"total_mbps": 300}' ;;
          4) printf '%s' '{"total_mbps": 400}' ;;
        esac ;;
      *'ping '*) printf '%s\n' '64 bytes from test: time=1 ms' ;;
    esac
  }
  remote_start_footprint() { printf '%s\n' 'footprint-start' >>"$log_file"; }
  remote_stop_footprint() { printf '%s\n' 'footprint-stop' >>"$log_file"; printf '%s' '{"rss_peak_kb":1,"rss_avg_kb":1,"cpu_peak_pct":1,"cpu_avg_pct":1,"samples":1}'; }
  ssh_cmd() { printf '%s' '123'; }
  sleep() { printf '%s\n' "$1" >>"$sleep_file"; }

  REPEAT=2
  PARALLELS=(1 10)
  tun_measure self-test 0 100.64.0.1 /tmp/test-daemon.pid /tmp/test.footprint /bin/test || return 1
  rows="$TUN_MEASURE_THROUGHPUT"
  python3 - "$rows" "$log_file" "$sleep_file" <<'PYEOF'
import json, sys
rows = json.loads(sys.argv[1])
assert [row["samples_mbps"] for row in rows] == [[100.0, 200.0], [300.0, 400.0]]
assert [row["mbps"] for row in rows] == [150.0, 350.0]
assert all(row["statistic"] == "median" for row in rows)
lines = open(sys.argv[2]).read().splitlines()
warmup = next(i for i, line in enumerate(lines) if "-t 3 -P 1 -R" in line)
footprint = lines.index("footprint-start")
samples = [line for line in lines if "iperf3 -c" in line and "-t 10" in line]
assert warmup < footprint and len(samples) == 4
assert lines.count("footprint-stop") == 1
assert "/tmp/self-test-iperf3-warmup.json" in lines[warmup]
assert all("/tmp/self-test-iperf3-current.json" in line and "2>&1; status=$?; cat" in line
           for line in samples)
assert not any("/tmp/iperf3-warmup.json" in line or " /tmp/iperf3-srv" in line for line in lines)
sleeps = open(sys.argv[3]).read().splitlines()
assert sleeps == ["2", "3", "3", "3"]
assert sleeps.count("2") == 1
assert sleeps.count("3") == len(samples) - 1
PYEOF

  tun_emit_result rustscale self-test direct
  python3 - "$OUT" <<'PYEOF'
import json, sys
with open(sys.argv[1]) as f:
    result = json.load(f)
assert result["repeat"] == 2
assert result["runtime_stats"] == {"server": "", "client": ""}
PYEOF

  # A zero-valued JSON sample is a measurement failure, not a transport
  # failure: stop the sampler once, make no later measured sample, and leave
  # the previously successful state and result file intact.
  : >"$log_file"
  printf '0' >"$count_file"
  printf 'previous-result\n' >"$OUT"
  TUN_MEASURE_THROUGHPUT='["previous-success"]'
  TUN_TEST_ZERO_SAMPLE=1
  if tun_measure self-test 0 100.64.0.1 /tmp/test-daemon.pid /tmp/test.footprint /bin/test; then
    return 1
  fi
  unset TUN_TEST_ZERO_SAMPLE
  [[ "$TUN_MEASURE_FAILURE_STAGE" == measured-sample ]] || return 1
  [[ "$TUN_MEASURE_THROUGHPUT" == '["previous-success"]' ]] || return 1
  [[ "$(<"$OUT")" == previous-result ]] || return 1
  python3 - "$log_file" <<'PYEOF'
import sys
lines = open(sys.argv[1]).read().splitlines()
samples = [line for line in lines if "iperf3 -c" in line and "-t 10" in line]
assert len(samples) == 1
assert "-P 1" in samples[0]
assert lines.count("footprint-start") == 1
assert lines.count("footprint-stop") == 1
PYEOF

  # Once sampling has been requested, every measurement failure makes one
  # best-effort stop attempt. Cover both a rejected start and a later sample
  # failure; the remaining return sites follow the same stop-before-return
  # pattern in tun_measure.
  : >"$log_file"
  TUN_TEST_FAIL_AFTER_START=1
  if tun_measure self-test 0 100.64.0.1 /tmp/test-daemon.pid /tmp/test.footprint /bin/test; then
    return 1
  fi
  unset TUN_TEST_FAIL_AFTER_START
  python3 - "$log_file" <<'PYEOF'
import sys
lines = open(sys.argv[1]).read().splitlines()
assert lines.count("footprint-start") == 1
assert lines.count("footprint-stop") == 1
PYEOF

  remote_start_footprint() { printf '%s\n' 'footprint-start' >>"$log_file"; return 1; }
  : >"$log_file"
  if tun_measure self-test 0 100.64.0.1 /tmp/test-daemon.pid /tmp/test.footprint /bin/test; then
    return 1
  fi
  [[ "$TUN_MEASURE_FAILURE_STAGE" == footprint-start ]] || return 1
  python3 - "$log_file" <<'PYEOF'
import sys
lines = open(sys.argv[1]).read().splitlines()
assert lines.count("footprint-start") == 1
assert lines.count("footprint-stop") == 1
PYEOF

  odd=$(append_tun_throughput_row '[]' 1 10 10 30 20) || return 1
  even=$(append_tun_throughput_row '[]' 1 10 10 30) || return 1
  python3 - "$odd" "$even" <<'PYEOF'
import json, sys
assert json.loads(sys.argv[1])[0]["mbps"] == 20.0
assert json.loads(sys.argv[2])[0]["mbps"] == 20.0
PYEOF
  if printf '%s' '{"total_mbps": 0}' | tun_iperf3_mbps >/dev/null 2>&1; then
    return 1
  fi

  # Failure stubs select diagnostics by stage: a pre-sample warmup failure,
  # a measured sample failure, and a post-sample latency failure must not be
  # conflated with one another or with a successful earlier sample.
  local failure_tail
  failure_tail=$(capture_log_tail() { printf '%s|%s|%s\n' "$1" "$2" "$3"; }; tun_measure_failure_tail rs-tun warmup)
  [[ "$failure_tail" == "$CVM|$CZONE|/tmp/rs-tun-iperf3-warmup.json" ]] || return 1
  failure_tail=$(capture_log_tail() { printf '%s|%s|%s\n' "$1" "$2" "$3"; }; tun_measure_failure_tail rs-tun server-start)
  [[ "$failure_tail" == "$SVM|$SZONE|/tmp/rs-tun-iperf3-srv.log" ]] || return 1
  failure_tail=$(capture_log_tail() { printf '%s|%s|%s\n' "$1" "$2" "$3"; }; tun_measure_failure_tail ts-tun measured-sample)
  [[ "$failure_tail" == "$CVM|$CZONE|/tmp/ts-tun-iperf3-current.json" ]] || return 1
  failure_tail=$(capture_log_tail() { printf 'stale-file:%s\n' "$3"; }; tun_measure_failure_tail ts-tun latency)
  [[ "$failure_tail" == '[gcp] ts-tun: tun_measure failed during latency; no iperf diagnostic applies' ]] || return 1

  REPEAT="$saved_repeat"
  PARALLELS=("${saved_parallels[@]}")
  rm -f "$log_file" "$count_file" "$sleep_file"
  unset -f run_tun_command remote_start_footprint remote_stop_footprint ssh_cmd sleep
}

# Profile both halves of the production rs-tun data path after normal
# measurements.  The authkey is deliberately absent from commands, metadata,
# and artifacts.
profile_perf_install_command() {
  printf '%s' 'if command -v perf >/dev/null; then exit 0; fi; apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq linux-perf || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq linux-tools-common linux-tools-$(uname -r) || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq linux-tools-common || true; command -v perf >/dev/null'
}

profile_prepare() {
  local status=0 command
  command=$(profile_perf_install_command)
  if ! ssh_sudo "$SVM" "$SZONE" "$command"; then
    status=1
  fi
  if ! ssh_sudo "$CVM" "$CZONE" "$command"; then
    status=1
  fi
  return "$status"
}

profile_endpoint_prefix() {
  local endpoint="$1"
  printf '/tmp/rs-tun-perf-%s' "$endpoint"
}

# Remove exactly one endpoint's profiler files.  The wrapper PID is validated
# before it is signalled, so malformed stale files cannot cause arbitrary kill.
profile_remote_cleanup_endpoint() {
  local endpoint="$1" vm="$2" zone="$3" prefix command
  prefix=$(profile_endpoint_prefix "$endpoint")
  command="pid=\$(cat ${prefix}.pid 2>/dev/null || true); case \$pid in \"\"|0|0[0-9]*|*[!0-9]*) ;; *) kill \"\$pid\" 2>/dev/null || true ;; esac; rm -f ${prefix}.pid ${prefix}.status ${prefix}.data ${prefix}-children.txt ${prefix}-self.txt ${prefix}.log"
  [[ "$endpoint" == client ]] && command+=" /tmp/rs-tun-profile-iperf.json"
  ssh_sudo "$vm" "$zone" "$command"
}

# Always attempt both cleanup actions, including after setup or workload
# failures.  This deliberately does not use a broad process-name kill.
profile_remote_cleanup() {
  local status=0
  if ! profile_remote_cleanup_endpoint server "$SVM" "$SZONE"; then
    status=1
  fi
  if ! profile_remote_cleanup_endpoint client "$CVM" "$CZONE"; then
    status=1
  fi
  return "$status"
}

profile_start_command() {
  local endpoint="$1" daemon_pid="$2" prefix duration
  prefix=$(profile_endpoint_prefix "$endpoint")
  duration=$((DURATION + 3))
  # No single quotes: ssh_sudo wraps this program in a single-quoted bash -c.
  printf 'rm -f %s.pid %s.status %s.data %s-children.txt %s-self.txt %s.log; nohup bash -c "perf record -F 199 -g -p %s -o %s.data -- sleep %s; status=\$?; printf \\"%%s\\n\\" \\"\$status\\" > %s.status; exit \\"\$status\\"" >%s.log 2>&1 & echo $! >%s.pid' \
    "$prefix" "$prefix" "$prefix" "$prefix" "$prefix" "$prefix" "$daemon_pid" "$prefix" "$duration" "$prefix" "$prefix" "$prefix"
}

profile_wait_command() {
  local endpoint="$1" prefix timeout
  prefix=$(profile_endpoint_prefix "$endpoint")
  timeout=$((DURATION + 30))
  printf 'pid=$(cat %s.pid 2>/dev/null || true); case $pid in ""|0|0[0-9]*|*[!0-9]*) exit 1 ;; esac; elapsed=0; while kill -0 "$pid" 2>/dev/null; do (( elapsed < %s )) || exit 1; sleep 1; elapsed=$((elapsed + 1)); done; status=$(cat %s.status 2>/dev/null || true); [[ "$status" == 0 ]]' \
    "$prefix" "$timeout" "$prefix"
}

profile_report_command() {
  local endpoint="$1" prefix
  prefix=$(profile_endpoint_prefix "$endpoint")
  printf 'test -s %s.data && perf report --stdio --children -i %s.data > %s-children.txt && perf report --stdio --no-children -i %s.data > %s-self.txt && test -s %s-children.txt && test -s %s-self.txt && chmod 0644 %s.data %s-children.txt %s-self.txt' \
    "$prefix" "$prefix" "$prefix" "$prefix" "$prefix" "$prefix" "$prefix" "$prefix" "$prefix" "$prefix"
}

profile_rs_tun() {
  local profile_dir="$RDIR/profile" server_dir="$RDIR/profile/server" client_dir="$RDIR/profile/client"
  local srv_pid cli_pid commit status=0 server_wait_status=0 client_wait_status=0
  mkdir -p "$server_dir" "$client_dir"

  if ! srv_pid=$(ssh_sudo "$SVM" "$SZONE" 'cat /tmp/rs-tun-srv.pid'); then
    status=1
  elif ! cli_pid=$(ssh_sudo "$CVM" "$CZONE" 'cat /tmp/rs-tun-cli.pid'); then
    status=1
  elif [[ ! "$srv_pid" =~ ^[1-9][0-9]*$ || ! "$cli_pid" =~ ^[1-9][0-9]*$ ]]; then
    status=1
  elif ! ssh_sudo "$SVM" "$SZONE" "$(profile_start_command server "$srv_pid")"; then
    status=1
  elif ! ssh_sudo "$CVM" "$CZONE" "$(profile_start_command client "$cli_pid")"; then
    status=1
  # This extra P10 is intentionally outside tun_measure and result JSON.
  elif ! run_tun_command 0 "$CVM" "$CZONE" "iperf3 -c $server_ip -p $PORT -t $DURATION -P 10 -R -J >/tmp/rs-tun-profile-iperf.json"; then
    status=1
  else
    # Do not combine waits: each endpoint's profiler status is independently
    # bounded and retained so a failure cannot be hidden by the other side.
    if ssh_sudo "$SVM" "$SZONE" "$(profile_wait_command server)"; then
      server_wait_status=0
    else
      server_wait_status=$?
    fi
    if ssh_sudo "$CVM" "$CZONE" "$(profile_wait_command client)"; then
      client_wait_status=0
    else
      client_wait_status=$?
    fi
    if (( server_wait_status != 0 || client_wait_status != 0 )); then
      status=1
    elif ! ssh_sudo "$SVM" "$SZONE" "$(profile_report_command server)"; then
      status=1
    elif ! ssh_sudo "$CVM" "$CZONE" "$(profile_report_command client)"; then
      status=1
    elif ! scp_from "$SVM" "$SZONE" /tmp/rs-tun-perf-server.data "$server_dir/perf.data" ||
         ! scp_from "$SVM" "$SZONE" /tmp/rs-tun-perf-server-children.txt "$server_dir/perf-children.txt" ||
         ! scp_from "$SVM" "$SZONE" /tmp/rs-tun-perf-server-self.txt "$server_dir/perf-self.txt" ||
         ! scp_from "$CVM" "$CZONE" /tmp/rs-tun-perf-client.data "$client_dir/perf.data" ||
         ! scp_from "$CVM" "$CZONE" /tmp/rs-tun-perf-client-children.txt "$client_dir/perf-children.txt" ||
         ! scp_from "$CVM" "$CZONE" /tmp/rs-tun-perf-client-self.txt "$client_dir/perf-self.txt" ||
         [[ ! -s "$server_dir/perf.data" || ! -s "$server_dir/perf-children.txt" || ! -s "$server_dir/perf-self.txt" || ! -s "$client_dir/perf.data" || ! -s "$client_dir/perf-children.txt" || ! -s "$client_dir/perf-self.txt" ]]; then
      status=1
    elif ! commit=$(git -C "$(cd "$(dirname "$0")/../../.." && pwd)" rev-parse HEAD); then
      status=1
    elif ! python3 - "$profile_dir/metadata.json" "$commit" "$TOPOLOGY" "$PATH_TAG" "$CONFIG" "$DURATION" "$REPEAT" "$srv_pid" "$cli_pid" "$OUT" <<'PYEOF'
import json, sys
out, commit, topo, path, config, duration, repeat, srv_pid, cli_pid, result = sys.argv[1:]
json.dump({"commit":commit,"topology":topo,"path":path,"config":config,
           "parallel":10,"duration_s":int(duration),"repeat":int(repeat),"frequency_hz":199,
           "result_json":result,"workload_direction":"server_to_client",
           "reverse":True,"endpoints":{
             "server":{"pid":int(srv_pid),"command":"rustscaled","role":"sender"},
             "client":{"pid":int(cli_pid),"command":"rustscaled","role":"receiver"}}},
          open(out,"w"), indent=2)
PYEOF
    then
      status=1
    fi
  fi

  if ! profile_remote_cleanup; then
    status=1
  fi
  return "$status"
}

profile_command_self_test() {
  local log="" log_file server_ip=100.64.0.1 result
  local -a copied=(server/perf.data server/perf-children.txt server/perf-self.txt client/perf.data client/perf-children.txt client/perf-self.txt)
  mkdir -p "$RDIR"
  log_file=$(mktemp "$RDIR/profile-test.XXXXXX")

  ssh_sudo() { printf ' sudo:%s:%s' "$1" "$3" >>"$log_file"; }
  profile_prepare || return 1
  log=$(<"$log_file")
  [[ "$log" == *"sudo:$SVM:"*'command -v perf'* && "$log" == *"sudo:$CVM:"*'command -v perf'* ]] || return 1

  # The happy path proves two recordings start before reverse P10, endpoint
  # waits/reports are independent, all artifacts are copied, and both remote
  # filename sets are cleaned up.
  ssh_sudo() {
    printf ' sudo:%s:%s' "$1" "$3" >>"$log_file"
    case "$3" in
      'cat /tmp/rs-tun-srv.pid') printf '42\n' ;;
      'cat /tmp/rs-tun-cli.pid') printf '84\n' ;;
    esac
    return 0
  }
  run_tun_command() { printf ' iperf:%s:%s' "$2" "$4" >>"$log_file"; }
  scp_from() { printf ' copy:%s:%s:%s' "$1" "$3" "$4" >>"$log_file"; printf x >"$4"; }
  profile_rs_tun || return 1
  log=$(<"$log_file")
  [[ "$log" == *"perf record -F 199 -g -p 42"* && "$log" == *"perf record -F 199 -g -p 84"* ]] || return 1
  [[ "${log%% iperf:*}" == *"perf record -F 199 -g -p 42"* && "${log%% iperf:*}" == *"perf record -F 199 -g -p 84"* ]] || return 1
  [[ "$log" == *"sudo:$SVM:"*"rs-tun-perf-server.status"* && "$log" == *"sudo:$CVM:"*"rs-tun-perf-client.status"* && "$log" == *"perf report --stdio --children -i /tmp/rs-tun-perf-server.data"* && "$log" == *"perf report --stdio --children -i /tmp/rs-tun-perf-client.data"* ]] || return 1
  for artifact in "${copied[@]}"; do [[ "$log" == *"$RDIR/profile/$artifact"* ]] || return 1; done
  [[ "$log" == *"rm -f /tmp/rs-tun-perf-server.pid"* && "$log" == *"rm -f /tmp/rs-tun-perf-client.pid"* && "$log" == *"/tmp/rs-tun-profile-iperf.json"* ]] || return 1
  python3 - "$RDIR/profile/metadata.json" <<'PYEOF'
import json, sys
with open(sys.argv[1]) as f:
    metadata = json.load(f)
assert metadata["workload_direction"] == "server_to_client"
assert metadata["reverse"] is True
assert metadata["repeat"] == 3
assert metadata["endpoints"]["server"] == {"pid": 42, "command": "rustscaled", "role": "sender"}
assert metadata["endpoints"]["client"] == {"pid": 84, "command": "rustscaled", "role": "receiver"}
PYEOF

  # A malformed PID is rejected before either profile start or workload.
  : >"$log_file"
  ssh_sudo() { printf ' sudo:%s:%s' "$1" "$3" >>"$log_file"; [[ "$3" == 'cat /tmp/rs-tun-srv.pid' ]] && printf 'not-a-pid\n'; return 0; }
  if profile_rs_tun; then return 1; fi
  log=$(<"$log_file")
  [[ "$log" == *'cat /tmp/rs-tun-srv.pid'* && "$log" == *'cat /tmp/rs-tun-cli.pid'* && "$log" != *'perf record'* && "$log" != *'iperf3 -c'* ]] || return 1

  # A failure starting either endpoint profiler skips the workload but still
  # cleans both endpoint filename sets.
  : >"$log_file"
  ssh_sudo() {
    printf ' sudo:%s:%s' "$1" "$3" >>"$log_file"
    case "$3" in
      'cat /tmp/rs-tun-srv.pid') printf '42\n' ;;
      'cat /tmp/rs-tun-cli.pid') printf '84\n' ;;
    esac
    [[ "$1" == "$CVM" && "$3" == *'perf record'* ]] && return 1
    return 0
  }
  if profile_rs_tun; then return 1; fi
  log=$(<"$log_file")
  [[ "$log" == *"perf record -F 199 -g -p 42"* && "$log" == *"perf record -F 199 -g -p 84"* && "$log" != *'iperf3 -c'* && "$log" == *"rm -f /tmp/rs-tun-perf-server.pid"* && "$log" == *"rm -f /tmp/rs-tun-perf-client.pid"* ]] || return 1

  # Empty or missing endpoint artifacts fail the profile instead of producing
  # partial evidence; cleanup still reaches both endpoint VMs.
  local empty_endpoint
  for empty_endpoint in server client; do
    : >"$log_file"
    ssh_sudo() {
      printf ' sudo:%s:%s' "$1" "$3" >>"$log_file"
      case "$3" in
        'cat /tmp/rs-tun-srv.pid') printf '42\n' ;;
        'cat /tmp/rs-tun-cli.pid') printf '84\n' ;;
      esac
      return 0
    }
    scp_from() { printf ' copy:%s:%s:%s' "$1" "$3" "$4" >>"$log_file"; [[ "$3" == *"$empty_endpoint-self.txt" ]] && : >"$4" || printf x >"$4"; }
    if profile_rs_tun; then return 1; fi
    log=$(<"$log_file")
    [[ "$log" == *"copy:"*"/tmp/rs-tun-perf-$empty_endpoint-self.txt"* && "$log" == *"rm -f /tmp/rs-tun-perf-server.pid"* && "$log" == *"rm -f /tmp/rs-tun-perf-client.pid"* ]] || return 1
  done

  # A workload failure also cleans both endpoints.
  : >"$log_file"
  run_tun_command() { printf ' iperf:%s:%s' "$2" "$4" >>"$log_file"; return 1; }
  scp_from() { return 1; }
  if profile_rs_tun; then return 1; fi
  log=$(<"$log_file")
  [[ "$log" == *'iperf3 -c 100.64.0.1 -p 5201 -t 10 -P 10 -R'* && "$log" == *"rm -f /tmp/rs-tun-perf-server.pid"* && "$log" == *"rm -f /tmp/rs-tun-perf-client.pid"* ]] || return 1
  rm -f "$log_file"
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
    profile_remote_cleanup || true
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
    emit_stub "rs-tun-iperf-preflight-failed" "$(capture_log_tail "$SVM" "$SZONE" "$(tun_iperf_server_log_path rs-tun)")"
    if ! cleanup_rs_tun; then return "$FATAL_HANDOFF_STATUS"; fi
    return 1
  fi

  if ! tun_measure rs-tun 0 "$server_ip" /tmp/rs-tun-srv.pid \
    /tmp/rs-tun-srv.footprint /opt/rustscale/target/release/rustscaled; then
    emit_stub "rs-tun-measure-failed" "$(tun_measure_failure_tail rs-tun "$TUN_MEASURE_FAILURE_STAGE")"
    if ! cleanup_rs_tun; then return "$FATAL_HANDOFF_STATUS"; fi
    return 1
  fi

  if (( PROFILE )) && ! profile_rs_tun; then
    emit_stub "rs-tun-profile-failed" "$(capture_log_tail "$SVM" "$SZONE" /tmp/rs-tun-perf-server.log)"
    cleanup_rs_tun || return "$FATAL_HANDOFF_STATUS"
    return 1
  fi

  finalize_rs_tun_measurement "$path_class"
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

  if ! ts_tun_measurement_preflight; then
    emit_stub "ts-tun-iperf-preflight-failed" "$(capture_log_tail "$SVM" "$SZONE" "$(tun_iperf_server_log_path ts-tun)")"
    cleanup_ts_tun
    return 1
  fi

  if ! tun_measure ts-tun 1 "$server_ip" /tmp/ts-tun-srv.pid \
    /tmp/ts-tun-srv.footprint /usr/sbin/tailscaled; then
    emit_stub "ts-tun-measure-failed" "$(tun_measure_failure_tail ts-tun "$TUN_MEASURE_FAILURE_STAGE")"
    cleanup_ts_tun
    return 1
  fi

  cleanup_ts_tun

  tun_emit_result tailscaled ts-tun "$path_class"
}

# ---------------------------------------------------------------------------
# Dispatch.
# ---------------------------------------------------------------------------
if (( SELF_TEST )); then
  profile_command_self_test
  tun_measure_self_test
  rm -rf "$RDIR"
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
