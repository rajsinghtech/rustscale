#!/usr/bin/env bash
# tools/bench/gcp/run-config.sh — run ONE bench config across two GCP VMs.
#
# Usage:
#   run-config.sh CONFIG SERVER_VM CLIENT_VM SERVER_ZONE CLIENT_ZONE \
#                 AUTHKEY RESULTS_DIR SERVER_HOSTNAME CLIENT_HOSTNAME [--profile]
#
# CONFIG ∈ {rs-userspace, rs-tun, ts-userspace, ts-tun}
# Emits <RESULTS_DIR>/<CONFIG>.json with benchmark results and provenance.
#
# Environment:
#   BENCH_MATRIX  — optional, set by run-matrix.sh; "topo/path" for tagging.
#   GCP_DRY_RUN   — when set, commands are echoed not executed (still emits a stub JSON).
#   RS_TUN_INBOUND_PIPELINE / RS_TUN_OUTBOUND_SEND_PIPELINE — rs-tun pipeline toggles: 0 (default) or 1.
#   RS_LINUX_UDP_BATCH / RS_LINUX_UDP_GRO — Linux receive modes: 0 (disabled) or 1 (default).
#   RS_LINUX_UDP_GSO — Linux TX-GSO mode: 0 (plain sendmmsg) or 1 (default/probed; requires batch=1).
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
--profile-only: rs-tun only; collect a Linux perf diagnostic without writing metrics
--repeat N: measured samples per parallelism (1..=9; default 3)
--parallelism LIST: ordered unique stream counts, each in 1..=1000
--duration N: measured throughput duration in seconds (3..=120)
--peer-count N: configured remote-peer load, including the benchmark peer (1..=1000)
--manifest FILE and --observed FILE: current-run immutable provenance inputs
EOF
  exit 2
}

# Parse trailing options independently of their order.  It intentionally has
# no GCP dependencies so the CLI contract can be tested locally.
parse_run_config_options() {
  PROFILE=0
  PROFILE_ONLY=0
  REPEAT=3
  PARALLELISM_CSV="1,10,100"
  DURATION=10
  PEER_COUNT=1
  RESULT_MANIFEST=""
  OBSERVED_METADATA=""
  local seen_profile=0 seen_profile_only=0 seen_repeat=0 seen_parallelism=0 seen_duration=0 seen_peer_count=0 seen_manifest=0 seen_observed=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --profile)
        (( seen_profile == 0 )) || { echo "duplicate option: --profile" >&2; return 2; }
        PROFILE=1; seen_profile=1; shift ;;
      --profile-only)
        (( seen_profile_only == 0 )) || { echo "duplicate option: --profile-only" >&2; return 2; }
        PROFILE_ONLY=1; seen_profile_only=1; shift ;;
      --repeat)
        (( seen_repeat == 0 )) || { echo "duplicate option: --repeat" >&2; return 2; }
        [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || { echo "--repeat requires a value" >&2; return 2; }
        [[ "$2" =~ ^[1-9]$ ]] || { echo "--repeat must be an integer in 1..=9" >&2; return 2; }
        REPEAT="$2"; seen_repeat=1; shift 2 ;;
      --parallelism)
        (( seen_parallelism == 0 )) || { echo "duplicate option: --parallelism" >&2; return 2; }
        [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || { echo "--parallelism requires a value" >&2; return 2; }
        validate_parallelism_csv "$2" || return 2
        PARALLELISM_CSV="$2"; seen_parallelism=1; shift 2 ;;
      --duration)
        (( seen_duration == 0 )) || { echo "duplicate option: --duration" >&2; return 2; }
        [[ $# -ge 2 && "$2" =~ ^[0-9]+$ && "$2" -ge 3 && "$2" -le 120 ]] || { echo "--duration must be an integer in 3..=120" >&2; return 2; }
        DURATION="$2"; seen_duration=1; shift 2 ;;
      --peer-count)
        (( seen_peer_count == 0 )) || { echo "duplicate option: --peer-count" >&2; return 2; }
        [[ $# -ge 2 && "$2" =~ ^[0-9]+$ && "$2" -ge 1 && "$2" -le 1000 ]] || { echo "--peer-count must be an integer in 1..=1000" >&2; return 2; }
        PEER_COUNT="$2"; seen_peer_count=1; shift 2 ;;
      --manifest)
        (( seen_manifest == 0 )) || { echo "duplicate option: --manifest" >&2; return 2; }
        [[ $# -ge 2 && -n "$2" ]] || { echo "--manifest requires a file" >&2; return 2; }
        RESULT_MANIFEST="$2"; seen_manifest=1; shift 2 ;;
      --observed)
        (( seen_observed == 0 )) || { echo "duplicate option: --observed" >&2; return 2; }
        [[ $# -ge 2 && -n "$2" ]] || { echo "--observed requires a file" >&2; return 2; }
        OBSERVED_METADATA="$2"; seen_observed=1; shift 2 ;;
      *) echo "unknown option: $1" >&2; return 2 ;;
    esac
  done
  (( !(PROFILE && PROFILE_ONLY) )) || { echo "--profile and --profile-only are mutually exclusive" >&2; return 2; }
}

validate_parallelism_csv() {
  local csv="$1" item seen=","
  [[ -n "$csv" && "$csv" != *, && "$csv" != ,* && "$csv" != *,,* ]] || { echo "invalid --parallelism list" >&2; return 1; }
  local -a values
  IFS=, read -r -a values <<<"$csv"
  for item in "${values[@]}"; do
    [[ "$item" =~ ^[1-9][0-9]*$ && "$item" -le 1000 ]] || { echo "--parallelism values must be integers in 1..=1000" >&2; return 1; }
    [[ "$seen" != *",$item,"* ]] || { echo "duplicate --parallelism value: $item" >&2; return 1; }
    seen+="$item,"
  done
}

run_config_option_parsing_self_test() {
  local actual status
  actual=$(parse_run_config_options --profile --repeat 1; printf '%s/%s/%s\n' "$PROFILE" "$PROFILE_ONLY" "$REPEAT") || return 1
  [[ "$actual" == '1/0/1' ]] || return 1
  actual=$(parse_run_config_options --profile-only --repeat 1; printf '%s/%s/%s\n' "$PROFILE" "$PROFILE_ONLY" "$REPEAT") || return 1
  [[ "$actual" == '0/1/1' ]] || return 1
  actual=$(parse_run_config_options --repeat 9 --profile; printf '%s/%s/%s\n' "$PROFILE" "$PROFILE_ONLY" "$REPEAT") || return 1
  [[ "$actual" == '1/0/9' ]] || return 1
  actual=$(parse_run_config_options; printf '%s/%s/%s\n' "$PROFILE" "$PROFILE_ONLY" "$REPEAT") || return 1
  [[ "$actual" == '0/0/3' ]] || return 1
  actual=$(parse_run_config_options --parallelism 1,10,100,1000 --duration 20 --peer-count 250; printf '%s/%s/%s\n' "$PARALLELISM_CSV" "$DURATION" "$PEER_COUNT") || return 1
  [[ "$actual" == '1,10,100,1000/20/250' ]] || return 1
  local -a case_args=()
  for args in '--repeat' '--repeat 0' '--repeat 10' '--repeat 1.5' '--repeat 1 --repeat 2' '--parallelism' '--parallelism 1,1' '--parallelism 0' '--parallelism 1001' '--parallelism 1,a' '--parallelism 1 --parallelism 2' '--duration 2' '--duration 121' '--peer-count 0' '--peer-count 1001' '--profile --profile' '--profile-only --profile-only' '--profile --profile-only' '--unknown'; do
    read -r -a case_args <<< "$args"
    if ( parse_run_config_options "${case_args[@]}" ) >/dev/null 2>&1; then
      return 1
    else
      status=$?
      (( status == 2 )) || return 1
    fi
  done
}

rs_tun_inbound_pipeline_self_test() {
  local actual status
  actual=$(export RS_TUN_INBOUND_PIPELINE=1; configure_rs_tun_inbound_pipeline; printf '%s' "$RS_TUN_INBOUND_PIPELINE") || return 1
  [[ "$actual" == 1 ]] || return 1
  actual=$(unset RS_TUN_INBOUND_PIPELINE; configure_rs_tun_inbound_pipeline; printf '%s' "$RS_TUN_INBOUND_PIPELINE") || return 1
  [[ "$actual" == 0 ]] || return 1
  if ( export RS_TUN_INBOUND_PIPELINE=enabled; configure_rs_tun_inbound_pipeline ) >/dev/null 2>&1; then
    return 1
  else
    status=$?
  fi
  (( status == 2 )) || return 1
  if ( export RS_TUN_INBOUND_PIPELINE=; configure_rs_tun_inbound_pipeline ) >/dev/null 2>&1; then
    return 1
  else
    status=$?
  fi
  (( status == 2 ))
}

rs_tun_outbound_send_pipeline_self_test() {
  local actual status
  actual=$(export RS_TUN_OUTBOUND_SEND_PIPELINE=1; configure_rs_tun_outbound_send_pipeline; printf '%s' "$RS_TUN_OUTBOUND_SEND_PIPELINE") || return 1
  [[ "$actual" == 1 ]] || return 1
  actual=$(unset RS_TUN_OUTBOUND_SEND_PIPELINE; configure_rs_tun_outbound_send_pipeline; printf '%s' "$RS_TUN_OUTBOUND_SEND_PIPELINE") || return 1
  [[ "$actual" == 0 ]] || return 1
  if ( export RS_TUN_OUTBOUND_SEND_PIPELINE=enabled; configure_rs_tun_outbound_send_pipeline ) >/dev/null 2>&1; then return 1; else status=$?; fi
  (( status == 2 ))
}

linux_udp_receive_modes_self_test() {
  local actual status
  for actual in 0/0 1/0 1/1; do
    local batch="${actual%/*}" gro="${actual#*/}"
    [[ "$(export RS_LINUX_UDP_BATCH="$batch" RS_LINUX_UDP_GRO="$gro"; configure_linux_udp_receive_modes; printf '%s/%s' "$RS_LINUX_UDP_BATCH" "$RS_LINUX_UDP_GRO")" == "$actual" ]] || return 1
  done
  if ( export RS_LINUX_UDP_BATCH=0 RS_LINUX_UDP_GRO=1; configure_linux_udp_receive_modes ) >/dev/null 2>&1; then return 1; else status=$?; fi
  (( status == 2 )) || return 1
  for variable in RS_LINUX_UDP_BATCH RS_LINUX_UDP_GRO; do
    if ( export "$variable"=invalid; configure_linux_udp_receive_modes ) >/dev/null 2>&1; then return 1; else status=$?; fi
    (( status == 2 )) || return 1
  done
}

linux_udp_tx_gso_mode_self_test() {
  local actual status
  # Every case sets its complete mode explicitly. These startup self-tests
  # also run before a scalar/plain/GSO-off matrix invocation, so they must not
  # inherit a caller's selected runtime mode as their supposed default.
  actual=$(export RS_LINUX_UDP_BATCH=1 RS_LINUX_UDP_GRO=1 RS_LINUX_UDP_GSO=0; configure_linux_udp_tx_gso_mode; printf '%s' "$RS_LINUX_UDP_GSO") || return 1
  [[ "$actual" == 0 ]] || return 1
  actual=$(export RS_LINUX_UDP_BATCH=1 RS_LINUX_UDP_GRO=1; unset RS_LINUX_UDP_GSO; configure_linux_udp_tx_gso_mode; printf '%s' "$RS_LINUX_UDP_GSO") || return 1
  [[ "$actual" == 1 ]] || return 1
  actual=$(export RS_LINUX_UDP_BATCH=0 RS_LINUX_UDP_GRO=0; unset RS_LINUX_UDP_GSO; configure_linux_udp_tx_gso_mode; printf '%s' "$RS_LINUX_UDP_GSO") || return 1
  [[ "$actual" == 0 ]] || return 1
  if ( export RS_LINUX_UDP_BATCH=1 RS_LINUX_UDP_GRO=1 RS_LINUX_UDP_GSO=invalid; configure_linux_udp_tx_gso_mode ) >/dev/null 2>&1; then return 1; else status=$?; fi
  (( status == 2 )) || return 1
  if ( export RS_LINUX_UDP_BATCH=0 RS_LINUX_UDP_GRO=0 RS_LINUX_UDP_GSO=1; configure_linux_udp_tx_gso_mode ) >/dev/null 2>&1; then return 1; else status=$?; fi
  (( status == 2 ))
}

validate_rs_tun_daemon_input() {
  local authkey="$1" hostname="$2"
  [[ "$authkey" =~ ^tskey-[A-Za-z0-9_-]+$ ]] || { echo "invalid rs-tun auth key" >&2; return 2; }
  [[ "$hostname" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ ]] || { echo "invalid rs-tun hostname" >&2; return 2; }
}

validate_rs_tun_daemon_inputs() {
  validate_rs_tun_daemon_input "$AUTHKEY" "$SHOST" || return $?
  validate_rs_tun_daemon_input "$AUTHKEY" "$CHOST"
}

rs_tun_daemon_input_self_test() {
  local value status
  validate_rs_tun_daemon_input tskey-auth-selftest rs-srv-same-zone || return 1
  for value in '' 'tskey-auth bad' "tskey-auth-'bad" 'tskey-auth-bad;id' 'tskey-auth-$(id)' 'not-a-tskey'; do
    if ( validate_rs_tun_daemon_input "$value" rs-srv-same-zone ) >/dev/null 2>&1; then
      return 1
    else
      status=$?
    fi
    (( status == 2 )) || return 1
  done
  for value in '' 'bad host' "bad'host" 'bad;id' 'bad$(id)' '-bad' 'bad-'; do
    if ( validate_rs_tun_daemon_input tskey-auth-selftest "$value" ) >/dev/null 2>&1; then
      return 1
    else
      status=$?
    fi
    (( status == 2 )) || return 1
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
  AUTHKEY=tskey-auth-selftest
  RDIR=$(mktemp -d)
  SHOST=self-test-server
  CHOST=self-test-client
  PROFILE=1
  PROFILE_ONLY=0
  REPEAT=3
  PARALLELISM_CSV="1,10,100"
  DURATION=10
  PEER_COUNT=1
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
configure_rs_tun_inbound_pipeline || exit $?
configure_rs_tun_outbound_send_pipeline || exit $?
configure_linux_udp_receive_modes || exit $?
configure_linux_udp_tx_gso_mode || exit $?
if (( PROFILE || PROFILE_ONLY )) && [[ "$CONFIG" != rs-tun ]]; then
  echo "--profile and --profile-only are only valid for rs-tun" >&2
  exit 2
fi
if [[ "$CONFIG" == rs-tun ]]; then
  validate_rs_tun_daemon_inputs || exit $?
fi

IFS=, read -r -a PARALLELS <<<"$PARALLELISM_CSV"
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
if (( SELF_TEST )); then
  TOPOLOGY=same-zone
  PATH_TAG=direct
fi

mkdir -p "$RDIR"
OUT="$RDIR/$CONFIG.json"
PENDING_OUT="$OUT.pending"
PROVENANCE_HELPER="$(dirname "$0")/provenance.py"

if (( SELF_TEST )); then
  RESULT_MANIFEST="$RDIR/matrix.json"
  OBSERVED_METADATA="$RDIR/observed.json"
  self_commit=$(git -C "$(cd "$(dirname "$0")/../../.." && pwd)" rev-parse HEAD)
  python3 "$PROVENANCE_HELPER" manifest "$RESULT_MANIFEST" --run-id gcp-20260714-000000-selftest \
    --started-at-utc 2026-07-14T00:00:00Z --commit "$self_commit" --dirty 0 --project dry-run \
    --image-project ubuntu-os-cloud --image-family ubuntu-2204-lts --machine "$GCP_MACHINE" --network default \
    --disk-type pd-standard --disk-gb 200 --rs-tun-inbound-pipeline "$RS_TUN_INBOUND_PIPELINE" --rs-tun-outbound-send-pipeline "$RS_TUN_OUTBOUND_SEND_PIPELINE" --linux-udp-batch "$RS_LINUX_UDP_BATCH" --linux-udp-gro "$RS_LINUX_UDP_GRO" --linux-udp-gso "$RS_LINUX_UDP_GSO" --dry-run --topologies same-zone --paths direct --configs rs-tun --parallelism 1 10 100 --repeat 3
  # The self-test config intentionally uses a non-production topology; the
  # provenance helper only validates endpoint identity when it is non-dry.
  python3 "$PROVENANCE_HELPER" dry-observed "$OBSERVED_METADATA"
  python3 - "$RESULT_MANIFEST" "$GCP_MACHINE" <<'PYEOF'
import json, sys
assert json.load(open(sys.argv[1]))["run"]["cloud"]["requested_machine_type"] == sys.argv[2]
PYEOF
fi

preflight_current_metadata() {
  [[ -n "$RESULT_MANIFEST" && -n "$OBSERVED_METADATA" ]] || return 1
  python3 "$PROVENANCE_HELPER" preflight --manifest "$RESULT_MANIFEST" --observed "$OBSERVED_METADATA" \
    --config "$CONFIG" --topology "$TOPOLOGY" --path "$PATH_TAG" --server-zone "$SZONE" --client-zone "$CZONE" \
    --rs-tun-inbound-pipeline "$RS_TUN_INBOUND_PIPELINE" --rs-tun-outbound-send-pipeline "$RS_TUN_OUTBOUND_SEND_PIPELINE" --linux-udp-batch "$RS_LINUX_UDP_BATCH" --linux-udp-gro "$RS_LINUX_UDP_GRO" --linux-udp-gso "$RS_LINUX_UDP_GSO" \
    --parallelism "${PARALLELS[@]}" --duration "$DURATION" --peer-count "$PEER_COUNT"
}

if ! preflight_current_metadata; then
  echo "current-run provenance is missing, malformed, or mismatched" >&2
  exit 2
fi

finalize_result_metadata() {
  (( PROFILE_ONLY )) && return 0
  local result_path="${1:-$OUT}"
  python3 "$PROVENANCE_HELPER" attach --manifest "$RESULT_MANIFEST" --observed "$OBSERVED_METADATA" "$result_path"
}

metadata_preflight_self_test() {
  local saved="$OBSERVED_METADATA" saved_path="$PATH_TAG" broken="$RDIR/broken-observed.json"
  printf '%s\n' '{}' >"$broken"
  OBSERVED_METADATA="$broken"
  if preflight_current_metadata >/dev/null 2>&1; then
    return 1
  fi
  OBSERVED_METADATA="$saved"
  # This is deliberately only a preflight call: an excluded path must fail
  # before daemon startup, profiling, or any measurement command can run.
  PATH_TAG=derp
  if preflight_current_metadata >/dev/null 2>&1; then
    return 1
  fi
  PATH_TAG="$saved_path"
  preflight_current_metadata >/dev/null
}

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

# Wait for one tailscaled instance to report a running local backend.
# Args: VM ZONE SOCK [TIMEOUT=120]
wait_ts_online() {
  local vm="$1" zone="$2" sock="$3" timeout="${4:-120}" elapsed=0
  while (( elapsed < timeout )); do
    if ssh_cmd "$vm" "$zone" \
      "tailscale --socket=$sock status --json 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); raise SystemExit(0 if d.get(\"BackendState\")==\"Running\" and d.get(\"Self\",{}).get(\"Online\") is not False else 1)'" \
      >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
    elapsed=$((elapsed + 2))
  done
  return 1
}

# Wait for the specific expected IPv4 peer, not merely any tailnet member.
# Args: VM ZONE SOCK PEER_IP [TIMEOUT=120]
wait_ts_peer_ip() {
  local vm="$1" zone="$2" sock="$3" peer_ip="$4" timeout="${5:-120}" elapsed=0
  [[ "$peer_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 2
  while (( elapsed < timeout )); do
    if ssh_cmd "$vm" "$zone" \
      "tailscale --socket=$sock status --json 2>/dev/null | python3 -c 'import json,sys; target=sys.argv[1]; peers=json.load(sys.stdin).get(\"Peer\",{}).values(); raise SystemExit(0 if any(target in p.get(\"TailscaleIPs\",[]) and p.get(\"Online\") is not False for p in peers) else 1)' $peer_ip" \
      >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
    elapsed=$((elapsed + 2))
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
    ping_args="--until-direct --c=0"
  else
    ping_args="--until-direct=false --c=1"
  fi
  printf '%s --socket=%s ping %s %s' "$cli" "$socket" "$ping_args" "$server_ip"
}

# Direct gates get one bounded product-CLI invocation. GNU timeout's short
# kill grace prevents a stuck CLI from holding a benchmark VM indefinitely.
tun_path_gate_command() {
  local ping_command="$1" path_tag="$2"
  if [[ "$path_tag" == direct ]]; then
    printf '%s' "timeout --kill-after=5s 180s $ping_command"
  else
    printf '%s' "$ping_command"
  fi
}

nohup_background_command() {
  local environment="$1" program="$2" logfile="$3" pidfile="$4"
  # The literal $! reaches the root-side bash -c through ssh_sudo's enclosing
  # single quotes, where it expands to the nohup process PID.
  printf '%snohup %s > %s 2>&1 & echo $! > %s' "$environment" "$program" "$logfile" "$pidfile"
}

linux_udp_environment() {
  local batch="$1" gro="$2" gso environment=""
  if (( $# >= 3 )); then
    gso="$3"
  elif [[ "$batch" == 0 ]]; then
    gso=0
  else
    gso=1
  fi
  [[ "$batch" == 0 || "$batch" == 1 ]] || return 2
  [[ "$gro" == 0 || "$gro" == 1 ]] || return 2
  [[ "$gso" == 0 || "$gso" == 1 ]] || return 2
  [[ "$batch" != 0 || "$gro" == 0 ]] || return 2
  [[ "$batch" != 0 || "$gso" == 0 ]] || return 2
  [[ "$gso" == 0 ]] && environment="RUSTSCALE_DISABLE_UDP_GSO=1 $environment"
  [[ "$batch" == 0 ]] && environment="RUSTSCALE_DISABLE_LINUX_UDP_BATCH=1 $environment"
  [[ "$gro" == 0 ]] && environment="RUSTSCALE_DISABLE_UDP_GRO=1 $environment"
  printf '%s' "$environment"
}

rs_tun_daemon_start_command() {
  local pipeline="$1" batch="$2" gro="$3" authkey="$4" statedir="$5" socket="$6" hostname="$7" logfile="$8" pidfile="$9" outbound="${10:-0}" gso environment
  if (( $# >= 11 )); then
    gso="${11}"
  elif [[ "$batch" == 0 ]]; then
    gso=0
  else
    gso=1
  fi
  [[ "$pipeline" == 0 || "$pipeline" == 1 ]] || return 2
  [[ "$outbound" == 0 || "$outbound" == 1 ]] || return 2
  [[ "$batch" == 0 || "$batch" == 1 ]] || return 2
  [[ "$gro" == 0 || "$gro" == 1 ]] || return 2
  [[ "$gso" == 0 || "$gso" == 1 ]] || return 2
  [[ "$batch" != 0 || "$gro" == 0 ]] || return 2
  [[ "$batch" != 0 || "$gso" == 0 ]] || return 2
  validate_rs_tun_daemon_input "$authkey" "$hostname" || return $?
  environment="$(linux_udp_environment "$batch" "$gro" "$gso")TS_AUTHKEY=$authkey "
  [[ "$pipeline" == 1 ]] && environment="RUSTSCALE_TUN_INBOUND_PIPELINE=1 $environment"
  [[ "$outbound" == 1 ]] && environment="RUSTSCALE_TUN_OUTBOUND_SEND_PIPELINE=1 $environment"
  nohup_background_command "$environment" \
    "prlimit --nofile=65535:65535 -- /opt/rustscale/target/release/rustscaled run --tun --statedir $statedir --socket $socket --hostname $hostname" \
    "$logfile" "$pidfile"
}

rs_userspace_server_start_command() {
  local batch="$1" gro="$2" gso="$3" authkey="$4" port="$5" hostname="$6" statedir="$7" logfile="$8" pidfile="$9" environment
  environment="$(linux_udp_environment "$batch" "$gro" "$gso")"
  nohup_background_command "$environment" \
    "prlimit --nofile=65535:65535 -- /opt/rustscale/target/release/rustscale-bench server --authkey $authkey --port $port --hostname $hostname --state-dir $statedir" \
    "$logfile" "$pidfile"
}

rs_userspace_client_command() {
  local batch="$1" gro="$2" gso="$3" authkey="$4" target="$5" duration="$6" parallel="$7" hostname="$8" statedir="$9" logfile="${10}" environment
  environment="$(linux_udp_environment "$batch" "$gro" "$gso")"
  printf '%s/opt/rustscale/target/release/rustscale-bench client --authkey %s --target %s --duration %s --parallel %s --hostname %s --state-dir %s --json 2>%s' \
    "$environment" "$authkey" "$target" "$duration" "$parallel" "$hostname" "$statedir" "$logfile"
}

# Start the shared kernel-TCP RSB1 server after a configuration has prepared
# its transport. ts-userspace binds loopback; TUN cells bind all interfaces.
# Args: BIND_ADDRESS
start_kernel_rsb1_server() {
  local bind="$1"
  [[ "$bind" == 127.0.0.1 || "$bind" == 0.0.0.0 ]] || return 2
  ssh_cmd "$SVM" "$SZONE" \
    "rm -f /tmp/rsb1-server.{log,pid}; nohup prlimit --nofile=65535:65535 -- /opt/rustscale/target/release/rustscale-bench server --transport kernel-tcp --bind $bind --port $PORT >/tmp/rsb1-server.log 2>&1 & echo \$! >/tmp/rsb1-server.pid" || return 1
  local elapsed=0
  while (( elapsed < 30 )); do
    if ssh_cmd "$SVM" "$SZONE" \
      'pid=$(cat /tmp/rsb1-server.pid 2>/dev/null); kill -0 "$pid" 2>/dev/null && grep -q "BENCH_READY 1" /tmp/rsb1-server.log' \
      >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  return 1
}

# Require the exact Serve TCP forward used by the RSB1 endpoint.
verify_ts_serve_rsb1() {
  ssh_cmd "$SVM" "$SZONE" \
    "tailscale --socket=/tmp/ts-srv.sock serve status --json 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); tcp=d.get(\"TCP\",{}); entry=tcp.get(\"$PORT\", tcp.get($PORT, {})); text=json.dumps(entry,sort_keys=True); raise SystemExit(0 if \"127.0.0.1:$PORT\" in text else 1)'"
}

# Start and verify the loopback-only SOCKS5 bridge. Every forked socat child is
# included by exact process name in the client resource process set.
start_ts_userspace_bridge() {
  ssh_cmd "$CVM" "$CZONE" \
    "pkill -x socat 2>/dev/null || true; rm -f /tmp/socat.{pid,log}; nohup prlimit --nofile=65535:65535 -- socat TCP4-LISTEN:5300,bind=127.0.0.1,reuseaddr,fork,nodelay SOCKS5-CONNECT:127.0.0.1:$1:$PORT,socksport=11080,nodelay >/tmp/socat.log 2>&1 & echo \$! >/tmp/socat.pid" || return 1
  local elapsed=0
  while (( elapsed < 30 )); do
    if ssh_cmd "$CVM" "$CZONE" \
      'pid=$(cat /tmp/socat.pid 2>/dev/null); kill -0 "$pid" 2>/dev/null && awk '\''/Max open files/ {exit !($4 >= 65535 && $5 >= 65535)}'\'' /proc/$pid/limits && ss -H -ltn '\''sport = :5300'\'' | grep -Eq '\''^[^ ]+[[:space:]]+[^ ]+[[:space:]]+127\.0\.0\.1:5300([[:space:]]|$)'\'' && ! ss -H -ltn '\''sport = :5300'\'' | grep -Eq '\''(0\.0\.0\.0|\[::\]):5300'\''' \
      >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  return 1
}

command_shape_self_test() {
  local ts_direct rs_direct ts_derp rs_derp rs_server_off rs_client_off rs_server_on rs_client_on rs_server_outbound rs_server_scalar rs_server_plain rs_server_gso_off rs_userspace_server rs_userspace_client
  ts_direct=$(tun_ping_invocation tailscale /tmp/ts.sock direct 100.64.0.1)
  rs_direct=$(tun_ping_invocation /opt/rustscale/target/release/rustscale /tmp/rs.sock direct 100.64.0.1)
  ts_derp=$(tun_ping_invocation tailscale /tmp/ts.sock derp 100.64.0.1)
  rs_derp=$(tun_ping_invocation /opt/rustscale/target/release/rustscale /tmp/rs.sock derp 100.64.0.1)
  [[ "$ts_direct" == 'tailscale --socket=/tmp/ts.sock ping --until-direct --c=0 100.64.0.1' ]] || return 1
  [[ "$rs_direct" == '/opt/rustscale/target/release/rustscale --socket=/tmp/rs.sock ping --until-direct --c=0 100.64.0.1' ]] || return 1
  [[ "${ts_direct#* ping }" == "${rs_direct#* ping }" ]] || return 1
  [[ "$ts_derp" == 'tailscale --socket=/tmp/ts.sock ping --until-direct=false --c=1 100.64.0.1' ]] || return 1
  [[ "$rs_derp" == '/opt/rustscale/target/release/rustscale --socket=/tmp/rs.sock ping --until-direct=false --c=1 100.64.0.1' ]] || return 1
  [[ "${ts_derp#* ping }" == "${rs_derp#* ping }" ]] || return 1
  [[ "$(tun_path_gate_command "$ts_direct" direct)" == "timeout --kill-after=5s 180s $ts_direct" ]] || return 1
  [[ "$(tun_path_gate_command "$rs_direct" direct)" == "timeout --kill-after=5s 180s $rs_direct" ]] || return 1
  rs_server_off=$(rs_tun_daemon_start_command 0 1 1 tskey-auth-selftest /tmp/srv /tmp/srv.sock srv /tmp/srv.log /tmp/srv.pid)
  rs_client_off=$(rs_tun_daemon_start_command 0 1 1 tskey-auth-selftest /tmp/cli /tmp/cli.sock cli /tmp/cli.log /tmp/cli.pid)
  [[ "$rs_server_off" != *RUSTSCALE_TUN_INBOUND_PIPELINE* && "$rs_client_off" != *RUSTSCALE_TUN_INBOUND_PIPELINE* ]] || return 1
  [[ "$rs_server_off" == 'TS_AUTHKEY=tskey-auth-selftest nohup prlimit --nofile=65535:65535 -- /opt/rustscale/target/release/rustscaled run --tun --statedir /tmp/srv --socket /tmp/srv.sock --hostname srv > /tmp/srv.log 2>&1 & echo $! > /tmp/srv.pid' ]] || return 1
  [[ "$rs_client_off" == 'TS_AUTHKEY=tskey-auth-selftest nohup prlimit --nofile=65535:65535 -- /opt/rustscale/target/release/rustscaled run --tun --statedir /tmp/cli --socket /tmp/cli.sock --hostname cli > /tmp/cli.log 2>&1 & echo $! > /tmp/cli.pid' ]] || return 1
  rs_server_on=$(rs_tun_daemon_start_command 1 1 1 tskey-auth-selftest /tmp/srv /tmp/srv.sock srv /tmp/srv.log /tmp/srv.pid)
  rs_client_on=$(rs_tun_daemon_start_command 1 1 1 tskey-auth-selftest /tmp/cli /tmp/cli.sock cli /tmp/cli.log /tmp/cli.pid)
  [[ "$rs_server_on" == 'RUSTSCALE_TUN_INBOUND_PIPELINE=1 TS_AUTHKEY=tskey-auth-selftest nohup prlimit --nofile=65535:65535 -- /opt/rustscale/target/release/rustscaled run --tun --statedir /tmp/srv --socket /tmp/srv.sock --hostname srv > /tmp/srv.log 2>&1 & echo $! > /tmp/srv.pid' ]] || return 1
  [[ "$rs_client_on" == 'RUSTSCALE_TUN_INBOUND_PIPELINE=1 TS_AUTHKEY=tskey-auth-selftest nohup prlimit --nofile=65535:65535 -- /opt/rustscale/target/release/rustscaled run --tun --statedir /tmp/cli --socket /tmp/cli.sock --hostname cli > /tmp/cli.log 2>&1 & echo $! > /tmp/cli.pid' ]] || return 1
  [[ "${rs_server_on#RUSTSCALE_TUN_INBOUND_PIPELINE=1 }" != *RUSTSCALE_TUN_INBOUND_PIPELINE* && "${rs_client_on#RUSTSCALE_TUN_INBOUND_PIPELINE=1 }" != *RUSTSCALE_TUN_INBOUND_PIPELINE* ]] || return 1
  rs_server_outbound=$(rs_tun_daemon_start_command 0 1 1 tskey-auth-selftest /tmp/srv /tmp/srv.sock srv /tmp/srv.log /tmp/srv.pid 1)
  [[ "$rs_server_outbound" == 'RUSTSCALE_TUN_OUTBOUND_SEND_PIPELINE=1 TS_AUTHKEY=tskey-auth-selftest nohup prlimit --nofile=65535:65535 -- /opt/rustscale/target/release/rustscaled run --tun --statedir /tmp/srv --socket /tmp/srv.sock --hostname srv > /tmp/srv.log 2>&1 & echo $! > /tmp/srv.pid' ]] || return 1
  rs_server_scalar=$(rs_tun_daemon_start_command 0 0 0 tskey-auth-selftest /tmp/srv /tmp/srv.sock srv /tmp/srv.log /tmp/srv.pid)
  [[ "$rs_server_scalar" == 'RUSTSCALE_DISABLE_UDP_GRO=1 RUSTSCALE_DISABLE_LINUX_UDP_BATCH=1 RUSTSCALE_DISABLE_UDP_GSO=1 TS_AUTHKEY=tskey-auth-selftest nohup prlimit --nofile=65535:65535 -- /opt/rustscale/target/release/rustscaled run --tun --statedir /tmp/srv --socket /tmp/srv.sock --hostname srv > /tmp/srv.log 2>&1 & echo $! > /tmp/srv.pid' ]] || return 1
  [[ "$(linux_udp_environment 0 0)" == 'RUSTSCALE_DISABLE_UDP_GRO=1 RUSTSCALE_DISABLE_LINUX_UDP_BATCH=1 RUSTSCALE_DISABLE_UDP_GSO=1 ' ]] || return 1
  rs_server_plain=$(rs_tun_daemon_start_command 0 1 0 tskey-auth-selftest /tmp/srv /tmp/srv.sock srv /tmp/srv.log /tmp/srv.pid)
  [[ "$rs_server_plain" == 'RUSTSCALE_DISABLE_UDP_GRO=1 TS_AUTHKEY=tskey-auth-selftest nohup prlimit --nofile=65535:65535 -- /opt/rustscale/target/release/rustscaled run --tun --statedir /tmp/srv --socket /tmp/srv.sock --hostname srv > /tmp/srv.log 2>&1 & echo $! > /tmp/srv.pid' ]] || return 1
  rs_server_gso_off=$(rs_tun_daemon_start_command 0 1 1 tskey-auth-selftest /tmp/srv /tmp/srv.sock srv /tmp/srv.log /tmp/srv.pid 0 0)
  [[ "$rs_server_gso_off" == 'RUSTSCALE_DISABLE_UDP_GSO=1 TS_AUTHKEY=tskey-auth-selftest nohup prlimit --nofile=65535:65535 -- /opt/rustscale/target/release/rustscaled run --tun --statedir /tmp/srv --socket /tmp/srv.sock --hostname srv > /tmp/srv.log 2>&1 & echo $! > /tmp/srv.pid' ]] || return 1
  if rs_tun_daemon_start_command 0 0 1 tskey-auth-selftest /tmp/srv /tmp/srv.sock srv /tmp/srv.log /tmp/srv.pid >/dev/null 2>&1; then return 1; else status=$?; fi
  (( status == 2 )) || return 1
  if rs_tun_daemon_start_command 0 0 0 tskey-auth-selftest /tmp/srv /tmp/srv.sock srv /tmp/srv.log /tmp/srv.pid 0 1 >/dev/null 2>&1; then return 1; else status=$?; fi
  (( status == 2 )) || return 1
  if linux_udp_environment 0 0 1 >/dev/null 2>&1; then return 1; else status=$?; fi
  (( status == 2 )) || return 1
  rs_userspace_server=$(rs_userspace_server_start_command 1 1 0 tskey-auth-selftest 7777 srv /tmp/rs-srv /tmp/rs-srv.log /tmp/rs-srv.pid)
  [[ "$rs_userspace_server" == 'RUSTSCALE_DISABLE_UDP_GSO=1 nohup prlimit --nofile=65535:65535 -- /opt/rustscale/target/release/rustscale-bench server --authkey tskey-auth-selftest --port 7777 --hostname srv --state-dir /tmp/rs-srv > /tmp/rs-srv.log 2>&1 & echo $! > /tmp/rs-srv.pid' ]] || return 1
  rs_userspace_client=$(rs_userspace_client_command 1 1 0 tskey-auth-selftest 100.64.0.1:7777 10 1 cli /tmp/rs-cli /tmp/rs-cli.log)
  [[ "$rs_userspace_client" == 'RUSTSCALE_DISABLE_UDP_GSO=1 /opt/rustscale/target/release/rustscale-bench client --authkey tskey-auth-selftest --target 100.64.0.1:7777 --duration 10 --parallel 1 --hostname cli --state-dir /tmp/rs-cli --json 2>/tmp/rs-cli.log' ]] || return 1
}

pid_capture_semantics_self_test() {
  local directory pipeline environment command remote_command pidfile pid attempt
  directory=$(mktemp -d "$RDIR/pid-capture-test.XXXXXX") || return 1
  for pipeline in 0 1; do
    pidfile="$directory/$pipeline.pid"
    environment='TS_AUTHKEY=authkey '
    [[ "$pipeline" == 1 ]] && environment="RUSTSCALE_TUN_INBOUND_PIPELINE=1 $environment"
    command=$(nohup_background_command "$environment" 'sleep 30' "$directory/$pipeline.log" "$pidfile") || { rm -rf "$directory"; return 1; }
    remote_command=$(ssh_sudo_remote_command "$command") || { rm -rf "$directory"; return 1; }
    # This is the remote login shell followed by ssh_sudo's root-side bash -c.
    bash -c "${remote_command#sudo }" || { rm -rf "$directory"; return 1; }
    pid=$(<"$pidfile")
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] && kill -0 "$pid" 2>/dev/null || { rm -rf "$directory"; return 1; }
    kill "$pid" 2>/dev/null || { rm -rf "$directory"; return 1; }
    for attempt in {1..20}; do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.05
    done
    ! kill -0 "$pid" 2>/dev/null || { kill -KILL "$pid" 2>/dev/null || true; rm -rf "$directory"; return 1; }
  done
  rm -rf "$directory"
}

# Gate kernel benchmarks on a product CLI ping and return its observed class.
# Args: AS_ROOT VM ZONE CLI SOCKET SERVER_IP PATH_TAG PATH_LOG
tun_path_gate() {
  local as_root="$1" vm="$2" zone="$3" cli="$4" socket="$5" server_ip="$6" path_tag="$7" path_log="$8"
  local ping_command command status transcript observed
  ping_command=$(tun_ping_invocation "$cli" "$socket" "$path_tag" "$server_ip")
  command=$(tun_path_gate_command "$ping_command" "$path_tag")
  if run_tun_command "$as_root" "$vm" "$zone" "$command >$path_log 2>&1"; then
    :
  else
    status=$?
    return "$status"
  fi
  transcript=$(run_tun_command "$as_root" "$vm" "$zone" "cat $path_log" 2>/dev/null || true)
  observed=$(printf '%s\n' "$transcript" | classify_cli_path)
  [[ "$path_tag" != direct || "$observed" == direct ]] || return 1
  [[ "$path_tag" != derp || "$observed" == derp ]] || return 1
  printf '%s\n' "$observed"
}

path_gate_self_test() {
  local result status original_run_tun_command
  original_run_tun_command=$(declare -f run_tun_command)
  PATH_GATE_TEST_TRANSCRIPT='pong from node (100.64.0.1) via 192.0.2.1:41641 in 1ms'
  PATH_GATE_TEST_STATUS=0
  run_tun_command() {
    [[ "$4" == "cat "* ]] && { printf '%s\n' "$PATH_GATE_TEST_TRANSCRIPT"; return 0; }
    return "$PATH_GATE_TEST_STATUS"
  }
  result=$(tun_path_gate 1 vm zone tailscale /tmp/ts.sock 100.64.0.1 direct /tmp/path.log) || return 1
  [[ "$result" == direct ]] || return 1
  PATH_GATE_TEST_STATUS=124
  if tun_path_gate 1 vm zone tailscale /tmp/ts.sock 100.64.0.1 direct /tmp/path.log >/dev/null; then return 1; else status=$?; fi
  (( status == 124 )) || return 1
  PATH_GATE_TEST_STATUS=7
  if tun_path_gate 1 vm zone /opt/rustscale/target/release/rustscale /tmp/rs.sock 100.64.0.1 direct /tmp/path.log >/dev/null; then return 1; else status=$?; fi
  (( status == 7 )) || return 1
  PATH_GATE_TEST_STATUS=0
  PATH_GATE_TEST_TRANSCRIPT='pong from node (100.64.0.1) via DERP(ord) in 1ms'
  if tun_path_gate 1 vm zone tailscale /tmp/ts.sock 100.64.0.1 direct /tmp/path.log >/dev/null; then return 1; else status=$?; fi
  (( status == 1 )) || return 1
  eval "$original_run_tun_command"
  unset PATH_GATE_TEST_TRANSCRIPT PATH_GATE_TEST_STATUS
}

rsb1_workload_cleanup_command() {
  printf '%s\n' \
'pidfile=/tmp/rsb1-server.pid' \
'pid=$(cat "$pidfile" 2>/dev/null || true)' \
'case "$pid" in ""|*[!0-9]*) ;; *) kill -TERM "$pid" 2>/dev/null || true ;; esac' \
'pkill -TERM -x rustscale-bench 2>/dev/null || true' \
'elapsed=0' \
'while (( elapsed < 10 )) && pgrep -x rustscale-bench >/dev/null 2>&1; do sleep 1; elapsed=$((elapsed + 1)); done' \
'pkill -KILL -x rustscale-bench 2>/dev/null || true' \
'rm -f /tmp/rsb1-server.pid /tmp/rsb1-server.log /tmp/rsb1-server.footprint* /tmp/rsb1-client.footprint* /tmp/rsb1-*.log /tmp/rs-footprint-set.py' \
'! pgrep -x rustscale-bench >/dev/null 2>&1 && ! ss -H -ltn | grep -Eq ":(5201|5300)[[:space:]]"'
}

cleanup_rs_tun() {
  local status=0
  remote_stop_footprint "$SVM" "$SZONE" /tmp/rsb1-server.footprint >/dev/null || true
  remote_stop_footprint "$CVM" "$CZONE" /tmp/rsb1-client.footprint >/dev/null || true
  remote_stop_footprint "$SVM" "$SZONE" /tmp/rs-tun-srv.footprint >/dev/null || true

  # Stop workload listeners before tearing down their transport. Leaving an
  # RSB1 listener and sockets attached to tailscale0 can strand the SSH cleanup
  # session behind routes owned by the daemon being terminated.
  if ! ssh_sudo "$SVM" "$SZONE" "$(rsb1_workload_cleanup_command)"; then
    echo "[gcp] WARN: rs-tun RSB1 workload cleanup failed on server $SVM; forcing VM reset" >&2
    status=1; reset_vm "$SVM" "$SZONE" || true
  fi
  if ! ssh_sudo "$CVM" "$CZONE" "$(rsb1_workload_cleanup_command)"; then
    echo "[gcp] WARN: rs-tun RSB1 workload cleanup failed on client $CVM; forcing VM reset" >&2
    status=1; reset_vm "$CVM" "$CZONE" || true
  fi

  if ! ssh_sudo "$SVM" "$SZONE" "$(rs_tun_iperf_cleanup_command server)"; then
    echo "[gcp] WARN: rs-tun diagnostic cleanup failed on server $SVM; forcing VM reset" >&2
    status=1; reset_vm "$SVM" "$SZONE" || true
  fi
  if ! ssh_sudo "$CVM" "$CZONE" "$(rs_tun_iperf_cleanup_command client)"; then
    echo "[gcp] WARN: rs-tun diagnostic cleanup failed on client $CVM; forcing VM reset" >&2
    status=1; reset_vm "$CVM" "$CZONE" || true
  fi

  # Run both transport endpoints even if one remains dirty.
  if ! ssh_sudo "$SVM" "$SZONE" "$(rs_tun_cleanup_command srv)"; then
    echo "[gcp] WARN: in-guest rs-tun cleanup failed on server $SVM; forcing VM reset" >&2
    status=1; reset_vm "$SVM" "$SZONE" || true
  fi
  if ! ssh_sudo "$CVM" "$CZONE" "$(rs_tun_cleanup_command cli)"; then
    echo "[gcp] WARN: in-guest rs-tun cleanup failed on client $CVM; forcing VM reset" >&2
    status=1; reset_vm "$CVM" "$CZONE" || true
  fi
  (( status == 0 )) && CELL_CLEANED=1
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

# Profile-only emits no metrics, but its reverse workload must use the exact
# same labeled rs-tun iperf server contract as a production measurement.
tun_start_iperf_server() {
  local label="$1" as_root="$2" server_pid_path server_log_path
  server_pid_path=$(tun_iperf_server_pid_path "$label")
  server_log_path=$(tun_iperf_server_log_path "$label")
  run_tun_command "$as_root" "$SVM" "$SZONE" \
    "pkill -x iperf3 2>/dev/null; nohup iperf3 -s -p $PORT > $server_log_path 2>&1 & echo \$! > $server_pid_path" || return 1
  # Match production measurement: a reverse client must not race the server
  # bind/listen transition (the historical profile-only bad-FD failure).
  sleep 2
}

# Profile-only is a diagnostic, not a second measurement implementation. Keep
# its preflight, labeled server, readiness settle, and profile workload in the
# same production helper so it cannot regress into racing a server bind.
# Cleanup intentionally remains the caller's fail-closed responsibility.
profile_only_rs_tun_workload() {
  rs_tun_measurement_preflight || return 1
  tun_start_iperf_server rs-tun 0 || return 1
  profile_rs_tun
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
'# A crashed daemon can leave a persistent TUN link. Once every daemon has' \
'# been signaled, explicitly remove that benchmark-owned interface.' \
'ip link delete dev tailscale0 2>/dev/null || true' \
'if wait_for_clear; then exit 0; fi' \
'diagnose' \
'echo "[gcp] ERROR: rs-tun cleanup left rustscaled or tailscale0 behind" >&2' \
'exit 1'
}

ts_tun_cleanup_command() {
  local role="$1" socket state pidfile
  if [[ "$role" == srv ]]; then
    socket=/tmp/ts-tun-srv.sock; state=/tmp/ts-tun-srv; pidfile=/tmp/ts-tun-srv.pid
  else
    socket=/tmp/ts-tun-cli.sock; state=/tmp/ts-tun-cli; pidfile=/tmp/ts-tun-cli.pid
  fi
  printf '%s\n' \
"socket=$socket" "state=$state" "pidfile=$pidfile" \
'tailscale --socket="$socket" serve reset 2>/dev/null || true' \
'tailscale --socket="$socket" down 2>/dev/null || true' \
'for file in /tmp/rsb1-server.pid "$pidfile" /tmp/socat.pid; do pid=$(cat "$file" 2>/dev/null || true); case "$pid" in ""|*[!0-9]*) ;; *) kill -TERM "$pid" 2>/dev/null || true ;; esac; done' \
'pkill -TERM -x rustscale-bench 2>/dev/null || true' \
'pkill -TERM -x socat 2>/dev/null || true' \
'pkill -TERM -x tailscaled 2>/dev/null || true' \
'is_clear() { ! pgrep -x rustscale-bench >/dev/null 2>&1 && ! pgrep -x socat >/dev/null 2>&1 && ! pgrep -x tailscaled >/dev/null 2>&1 && ! ip link show dev tailscale0 >/dev/null 2>&1 && ! ss -H -ltn | grep -Eq ":(5201|5300)[[:space:]]"; }' \
'elapsed=0; while (( elapsed < 15 )); do is_clear && break; sleep 1; elapsed=$((elapsed + 1)); done' \
'if ! is_clear; then pkill -KILL -x rustscale-bench 2>/dev/null || true; pkill -KILL -x socat 2>/dev/null || true; pkill -KILL -x tailscaled 2>/dev/null || true; ip link delete dev tailscale0 2>/dev/null || true; fi' \
'dns_ok=0' \
'if [[ -f /etc/resolv.conf.bench-bak ]]; then cp /etc/resolv.conf.bench-bak /etc/resolv.conf && cmp -s /etc/resolv.conf.bench-bak /etc/resolv.conf && dns_ok=1; fi' \
'rm -rf "$state" /tmp/rsb1-* /tmp/rs-footprint-set.py' \
'rm -f /etc/resolv.conf.bench-bak "$socket" "$pidfile" /tmp/ts-tun-*.path*.log /tmp/socat.*' \
'(( dns_ok == 1 )) && is_clear'
}

cleanup_ts_tun() {
  local status=0
  remote_stop_footprint "$SVM" "$SZONE" /tmp/rsb1-server.footprint >/dev/null || true
  remote_stop_footprint "$CVM" "$CZONE" /tmp/rsb1-client.footprint >/dev/null || true
  remote_stop_footprint "$SVM" "$SZONE" /tmp/ts-tun-srv.footprint >/dev/null || true
  if ! ssh_sudo "$SVM" "$SZONE" "$(ts_tun_cleanup_command srv)"; then
    echo "[gcp] ERROR: ts-tun server cleanup postconditions failed; resetting VM" >&2
    status=1; reset_vm "$SVM" "$SZONE" || true
  fi
  if ! ssh_sudo "$CVM" "$CZONE" "$(ts_tun_cleanup_command cli)"; then
    echo "[gcp] ERROR: ts-tun client cleanup postconditions failed; resetting VM" >&2
    status=1; reset_vm "$CVM" "$CZONE" || true
  fi
  (( status == 0 )) && CELL_CLEANED=1
  return "$status"
}

userspace_cleanup_command() {
  local role="$1" socket pidfile
  if [[ "$role" == srv ]]; then socket=/tmp/ts-srv.sock; pidfile=/tmp/ts-srv.pid; else socket=/tmp/ts-cli.sock; pidfile=/tmp/ts-cli.pid; fi
  printf '%s\n' \
"socket=$socket" "pidfile=$pidfile" \
'tailscale --socket="$socket" serve reset 2>/dev/null || true' \
'tailscale --socket="$socket" down 2>/dev/null || true' \
'for file in /tmp/rs-srv.pid /tmp/rsb1-server.pid "$pidfile" /tmp/socat.pid; do pid=$(cat "$file" 2>/dev/null || true); case "$pid" in ""|*[!0-9]*) ;; *) kill -TERM "$pid" 2>/dev/null || true ;; esac; done' \
'pkill -TERM -x rustscale-bench 2>/dev/null || true' \
'pkill -TERM -x socat 2>/dev/null || true' \
'pkill -TERM -x tailscaled 2>/dev/null || true' \
'is_clear() { ! pgrep -x rustscale-bench >/dev/null 2>&1 && ! pgrep -x socat >/dev/null 2>&1 && ! pgrep -x tailscaled >/dev/null 2>&1 && ! ip link show dev tailscale0 >/dev/null 2>&1 && ! ss -H -ltn | grep -Eq ":(5201|5300|11080)[[:space:]]"; }' \
'elapsed=0; while (( elapsed < 15 )); do is_clear && break; sleep 1; elapsed=$((elapsed + 1)); done' \
'if ! is_clear; then pkill -KILL -x rustscale-bench 2>/dev/null || true; pkill -KILL -x socat 2>/dev/null || true; pkill -KILL -x tailscaled 2>/dev/null || true; fi' \
'rm -rf /tmp/rs-srv /tmp/rs-cli-* /tmp/rs-parity-client /tmp/ts-srv /tmp/ts-cli /tmp/rsb1-*' \
'rm -f /tmp/rs-srv.* /tmp/ts-srv.* /tmp/ts-cli.* /tmp/socat.* /tmp/rs-footprint-set.py' \
'is_clear'
}

cleanup_userspace_endpoints() {
  local status=0
  remote_stop_footprint "$SVM" "$SZONE" /tmp/rsb1-server.footprint >/dev/null || true
  remote_stop_footprint "$CVM" "$CZONE" /tmp/rsb1-client.footprint >/dev/null || true
  remote_stop_footprint "$SVM" "$SZONE" /tmp/rs-parity-server.footprint >/dev/null || true
  remote_stop_footprint "$CVM" "$CZONE" /tmp/rs-parity-client.footprint >/dev/null || true
  remote_stop_footprint "$SVM" "$SZONE" /tmp/rs-srv.footprint >/dev/null || true
  remote_stop_footprint "$SVM" "$SZONE" /tmp/ts-srv.footprint >/dev/null || true
  if ! ssh_cmd "$SVM" "$SZONE" "$(userspace_cleanup_command srv)"; then
    echo "[gcp] ERROR: userspace server cleanup postconditions failed; resetting VM" >&2
    status=1; reset_vm "$SVM" "$SZONE" || true
  fi
  if ! ssh_cmd "$CVM" "$CZONE" "$(userspace_cleanup_command cli)"; then
    echo "[gcp] ERROR: userspace client cleanup postconditions failed; resetting VM" >&2
    status=1; reset_vm "$CVM" "$CZONE" || true
  fi
  (( status == 0 )) && CELL_CLEANED=1
  return "$status"
}

cleanup_rs_userspace() { cleanup_userspace_endpoints; }
cleanup_ts_userspace() { cleanup_userspace_endpoints; }

# Args: CLEANUP_FUNCTION ERROR_STRING [LOG_TAIL].  This is the sole failure
# exit used after a userspace daemon has been started, making cleanup ordering
# explicit and testable.
fail_userspace_config() {
  local cleanup_fn="$1" err="$2" log_tail="${3:-}"
  emit_stub "$err" "$log_tail" || true
  "$cleanup_fn" || true
  return 1
}

# ts-tun also removes its own root-owned artifacts before each measurement so
# direct/DERP reruns cannot reuse a prior sample diagnostic.
ts_tun_measurement_preflight() {
  ssh_sudo "$SVM" "$SZONE" \
    "kill \$(cat $(tun_iperf_server_pid_path ts-tun) 2>/dev/null) 2>/dev/null || true; pkill -x iperf3 2>/dev/null || true; rm -f $(tun_iperf_server_pid_path ts-tun) $(tun_iperf_server_log_path ts-tun)" \
    && ssh_sudo "$CVM" "$CZONE" \
      "rm -f $(tun_iperf_warmup_path ts-tun) $(tun_iperf_sample_path ts-tun)"
}

# Write an explicit failed-cell JSON (used in dry-run or on failure).  A
# failure is not a zero-valued benchmark: consumers must never chart it as one.
# Args: ERROR_STRING [LOG_TAIL]
emit_stub() {
  local err="${1:-dry-run}"
  local log_tail="${2:-}"
  if (( PROFILE_ONLY )); then
    echo "[gcp] profile-only rs-tun failed: $err" >&2
    return
  fi
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
    "schema_version": 5,
    "status": "failed",
    "tool": tool,
    "mode": mode,
    "topology": topo,
    "path": path_tag,
    "config": config,
    "repeat": int(repeat),
    "error": err,
    "log_tail": log_tail,
    "parallelism_requested": [int(p) for p in parallel_values],
    "throughput": None,
    "latency": None,
    "footprint": None,
    "path_class_reported": "unknown",
}
print(json.dumps(obj, indent=2))
PYEOF
  # A failed-cell attachment error must not short-circuit caller cleanup. The
  # un-attached result remains fail-closed at strict aggregation.
  if ! finalize_result_metadata; then
    echo "[gcp] failed to attach provenance to failed cell" >&2
  fi
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
    remote_stop_footprint() { :; }
    reset_vm() { return 0; }
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
  [[ "$cleanup_failure" == "1| $SVM:$SZONE $CVM:$CZONE $SVM:$SZONE $CVM:$CZONE $SVM:$SZONE $CVM:$CZONE" ]] || return 1

  # Failure injection uses the same helper as the post-start userspace
  # throughput exits.  Cleanup must finish before a later matrix cell starts.
  local injection_events injection_result
  injection_events=$(mktemp "$RDIR/userspace-failure-test.XXXXXX")
  injection_result=$(
    emit_stub() { printf 'stub:%s\n' "$1" >>"$injection_events"; }
    cleanup_rs_userspace() { printf 'cleanup:rs-userspace\n' >>"$injection_events"; }
    if fail_userspace_config cleanup_rs_userspace injected-throughput-failure; then
      exit 1
    fi
    printf 'next-cell\n' >>"$injection_events"
  ) || return 1
  [[ "$(<"$injection_events")" == $'stub:injected-throughput-failure\ncleanup:rs-userspace\nnext-cell' ]] || return 1
  rm -f "$injection_events"

  unset -f pgrep ip pkill sleep ps fuser test_remote_cleanup
}

result_shape_self_test() {
  emit_stub self-test
  python3 - "$OUT" "$DURATION" "$LATENCY_COUNT" "$RS_TUN_INBOUND_PIPELINE" "$RS_TUN_OUTBOUND_SEND_PIPELINE" "$RS_LINUX_UDP_BATCH" "$RS_LINUX_UDP_GRO" "$RS_LINUX_UDP_GSO" "${PARALLELS[@]}" <<'PYEOF'
import json, sys
path, duration, latency_count, inbound_pipeline, outbound_pipeline, udp_batch, udp_gro, udp_gso, *parallels = sys.argv[1:]
with open(path) as f:
    result = json.load(f)
assert result["schema_version"] == 5 and result["status"] == "failed"
assert result["run"]["source"]["includes_uncommitted_changes"] is False
assert result["run"]["runtime"] == {"rs_tun_inbound_pipeline": inbound_pipeline == "1", "rs_tun_outbound_send_pipeline": outbound_pipeline == "1", "linux_udp_batch": udp_batch == "1", "linux_udp_gro": udp_gro == "1", "linux_udp_gso": udp_gso == "1"}
assert result["observed"]["resolved_image"] == "dry-run"
assert result["parallelism_requested"] == [int(p) for p in parallels]
assert result["throughput"] is None and result["latency"] is None and result["footprint"] is None
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
expected = [int(value) for value in sys.argv[2:]]
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

profile_only_server_contract_self_test() {
  local calls=""
  ssh_sudo() { calls+="$1|$2|$3"$'\n'; }
  run_tun_command() { calls+="$1|$2|$3|$4"$'\n'; }
  sleep() { calls+="sleep|$1"$'\n'; }
  profile_rs_tun() { calls+="profile"$'\n'; }
  local expected="$SVM|$SZONE|$(rs_tun_iperf_cleanup_command server)"$'\n'"$CVM|$CZONE|$(rs_tun_iperf_cleanup_command client)"$'\n'"0|$SVM|$SZONE|pkill -x iperf3 2>/dev/null; nohup iperf3 -s -p $PORT > /tmp/rs-tun-iperf3-srv.log 2>&1 & echo \$! > /tmp/rs-tun-iperf3-srv.pid"$'\n''sleep|2'$'\n''profile'$'\n'
  profile_only_rs_tun_workload || return 1
  [[ "$calls" == "$expected" ]] || return 1

  # A profile failure must be returned to run_rs_tun, which owns the
  # fail-closed cleanup path; the helper itself must not continue or emit.
  calls=""
  profile_rs_tun() { calls+="profile-failed"$'\n'; return 1; }
  if profile_only_rs_tun_workload; then
    return 1
  fi
  expected="${expected%profile$'\n'}profile-failed"$'\n'
  [[ "$calls" == "$expected" ]] || return 1

  # A failed paid preflight must stop before server start or profiling.
  calls=""
  ssh_sudo() { calls+="preflight-failed"$'\n'; return 1; }
  if profile_only_rs_tun_workload; then
    return 1
  fi
  [[ "$calls" == $'preflight-failed\n' ]] || return 1
  unset -f ssh_sudo run_tun_command sleep profile_rs_tun
}

classifier_self_test
command_shape_self_test
pid_capture_semantics_self_test
path_gate_self_test
run_config_option_parsing_self_test
rs_tun_inbound_pipeline_self_test
rs_tun_outbound_send_pipeline_self_test
linux_udp_receive_modes_self_test
linux_udp_tx_gso_mode_self_test
rs_tun_daemon_input_self_test

if (( SELF_TEST )); then
  metadata_preflight_self_test
  cleanup_self_test
  result_shape_self_test
  runtime_stats_self_test
  rs_tun_lifecycle_self_test
  profile_only_server_contract_self_test
fi

if [[ -n "${GCP_DRY_RUN:-}" ]]; then
  echo "[dry-run] would run $CONFIG on $SVM/$CVM ($TOPOLOGY/$PATH_TAG)" >&2
  if (( PROFILE_ONLY )); then
    echo "[dry-run] would profile rs-tun without writing metrics" >&2
    exit 0
  fi
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

# Helper: parse a complete production ping sample from stdin.
# Args: REQUESTED. Emits requested/transmitted/received/loss/count plus RTTs.
ping_latency() {
  local requested="$1"
  python3 -c '
import json, re, sys
requested = int(sys.argv[1])
rtts=[]
transmitted = received = None
loss = None
for line in sys.stdin:
    m = re.search(r"time=([0-9.]+)\s*ms", line)
    if m:
        rtts.append(float(m.group(1)) * 1000)
    summary = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received, ([0-9.]+)% packet loss", line)
    if summary:
        transmitted, received, loss = int(summary.group(1)), int(summary.group(2)), float(summary.group(3))
rtts.sort()
n=len(rtts)
def pct(p):
    return rtts[min(int(round((n-1)*p)), n-1)] if rtts else 0
print(json.dumps({
    "requested": requested,
    "transmitted": transmitted,
    "received": received,
    "loss": loss,
    "p50_us": round(pct(0.50)),
    "p95_us": round(pct(0.95)),
    "p99_us": round(pct(0.99)),
    "count": n,
}))
' "$requested"
}

# A TUN latency result is production data only when every requested reply and
# the ping summary agree. This rejects partial samples before result emission.
complete_tun_latency() {
  python3 -c '
import json, math, sys
expected = int(sys.argv[1])
try:
    sample = json.load(sys.stdin)
except (ValueError, TypeError):
    raise SystemExit(1)
numbers = ("p50_us", "p95_us", "p99_us")
if (sample.get("requested") != expected or sample.get("transmitted") != expected or
        sample.get("received") != expected or sample.get("count") != expected or
        sample.get("loss") != 0 or
        not all(isinstance(sample.get(k), (int, float)) and not isinstance(sample[k], bool) and math.isfinite(sample[k]) and sample[k] > 0 for k in numbers) or
        [sample[k] for k in numbers] != sorted(sample[k] for k in numbers)):
    raise SystemExit(1)
print(json.dumps(sample))
' "$LATENCY_COUNT"
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
  tun_start_iperf_server "$label" "$as_root" || return 1

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
    "ping -i $LATENCY_INTERVAL -c $LATENCY_COUNT $server_ip 2>/dev/null" \
    | ping_latency "$LATENCY_COUNT" | complete_tun_latency) || {
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
    "$TUN_MEASURE_FOOTPRINT" "$tool" "$REPEAT" "$runtime_server" "$runtime_client" "${PARALLELS[@]}" >"$OUT" <<'PYEOF'
import json, sys
config, topo, path_tag, path_class, bin_size, tp, lat, foot, tool, repeat, runtime_server, runtime_client, *parallel_values = sys.argv[1:]
obj = {
    "schema_version": 2,
    "status": "ok",
    "tool": tool,
    "mode": "tun",
    "topology": topo,
    "path": path_tag,
    "config": config,
    "repeat": int(repeat),
    "parallelism_requested": [int(value) for value in parallel_values],
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
  finalize_result_metadata
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
      *'ping '*)
        local replies="$LATENCY_COUNT"
        [[ "${TUN_TEST_PARTIAL_LATENCY:-0}" == 1 ]] && replies=$((LATENCY_COUNT - 1))
        for ((i = 1; i <= replies; i++)); do
          printf '%s\n' '64 bytes from test: time=1 ms'
        done
        printf '%s\n' "$LATENCY_COUNT packets transmitted, $replies received, $((100 - (100 * replies / LATENCY_COUNT)))% packet loss" ;;
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
assert result["parallelism_requested"] == [1, 10]
assert result["runtime_stats"] == {"server": "", "client": ""}
PYEOF

  # A partial reply set has a successful ping transport status but is not a
  # production latency sample and must fail before a result can be emitted.
  : >"$log_file"
  printf '0' >"$count_file"
  TUN_TEST_PARTIAL_LATENCY=1
  if tun_measure self-test 0 100.64.0.1 /tmp/test-daemon.pid /tmp/test.footprint /bin/test; then
    return 1
  fi
  unset TUN_TEST_PARTIAL_LATENCY
  [[ "$TUN_MEASURE_FAILURE_STAGE" == latency ]] || return 1

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
  local srv_pid cli_pid status=0 server_wait_status=0 client_wait_status=0
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
    elif ! python3 - "$profile_dir/metadata.json" "$TOPOLOGY" "$PATH_TAG" "$CONFIG" "$DURATION" "$REPEAT" "$srv_pid" "$cli_pid" "$OUT" <<'PYEOF'
import json, sys
out, topo, path, config, duration, repeat, srv_pid, cli_pid, result = sys.argv[1:]
json.dump({"topology":topo,"path":path,"config":config,
           "parallel":10,"duration_s":int(duration),"repeat":int(repeat),"frequency_hz":199,
           "result_json":result,"workload_direction":"server_to_client",
           "reverse":True,"endpoints":{
             "server":{"pid":int(srv_pid),"command":"rustscaled","role":"sender"},
             "client":{"pid":int(cli_pid),"command":"rustscaled","role":"receiver"}}},
          open(out,"w"), indent=2)
PYEOF
    then
      status=1
    elif ! python3 "$PROVENANCE_HELPER" profile --manifest "$RESULT_MANIFEST" --observed "$OBSERVED_METADATA" --config "$CONFIG" "$profile_dir/metadata.json"; then
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
assert metadata["run"]["id"] == "gcp-20260714-000000-selftest"
assert metadata["source_commit"] == metadata["run"]["source"]["commit"]
assert metadata["observed"]["resolved_image"] == "dry-run"
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

# Run one configuration-neutral RSB1 suite after the caller has prepared its
# transport, endpoint, path gate, process subjects, and teardown function. The
# sole warmup may retry before sampling; every measured throughput/latency
# process is invoked exactly once and an incomplete lifecycle fails the cell.
# Args: CLI_TRANSPORT REPORTED_TRANSPORT TARGET PRE_GATED_PATH
rsb1_measure() {
  local cli_transport="$1" reported_transport="$2" target="$3" gated_path="$4"
  local auth_args="" path_class warmup_json warmup_evidence tp_json="[]" trial_json="[]" lat_json server_foot client_foot bin_size
  local server_subjects client_subjects
  RS_PARITY_FAILURE_LOG=/tmp/rsb1-setup.log
  RSB1_MEASURE_PATH_POST=unknown
  (( ${#RSB1_SERVER_SUBJECTS[@]} > 0 && ${#RSB1_CLIENT_SUBJECTS[@]} > 0 )) || return 2
  [[ "$cli_transport" == userspace ]] && auth_args="--authkey $AUTHKEY"

  RS_PARITY_FAILURE_LOG=/tmp/rsb1-warmup.log
  local warmup_attempt
  warmup_json=""
  for warmup_attempt in 1 2 3; do
    warmup_json=$(ssh_cmd "$CVM" "$CZONE" "prlimit --nofile=65535:65535 -- /opt/rustscale/target/release/rustscale-bench client --transport $cli_transport $auth_args --target $target --duration 3 --parallel 1 --direction down --hostname $CHOST-warmup-$warmup_attempt --state-dir /tmp/rsb1-warmup-$warmup_attempt --json 2>/tmp/rsb1-warmup.log") && break
    echo "[gcp] RSB1 warmup retry $warmup_attempt/3" >&2
    sleep 5
    warmup_json=""
  done
  [[ -n "$warmup_json" ]] || return 1
  path_class=$(printf '%s' "$warmup_json" | python3 -c 'import json,math,sys; d=json.load(sys.stdin); transport=sys.argv[1]; assert d["transport"]==transport and d["protocol"]=="RSB1" and d["direction"]=="down" and d["parallel"]==1 and d["established"]==1 and d["handshaken"]==1 and d["completed"]==1; value=float(d["total_mbps"]); assert math.isfinite(value) and value>0; print(d["path_class"])' "$reported_transport") || return 1
  warmup_evidence=$(printf '%s' "$warmup_json" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(json.dumps({k:d[k] for k in ("transport","protocol","direction","duration_secs","parallel","established","handshaken","completed","total_mbps","path_class")}))') || return 1
  [[ "$reported_transport" == kernel-tcp ]] && path_class="$gated_path"
  [[ "$PATH_TAG" == direct && "$path_class" == direct || "$PATH_TAG" == derp && "$path_class" == derp ]] || {
    echo "[gcp] RSB1 warmup observed wrong path: $path_class" >&2
    return 1
  }

  remote_start_footprint_set "$SVM" "$SZONE" /tmp/rsb1-server.footprint "${RSB1_SERVER_SUBJECTS[@]}" >/dev/null || return 1
  remote_start_footprint_set "$CVM" "$CZONE" /tmp/rsb1-client.footprint "${RSB1_CLIENT_SUBJECTS[@]}" >/dev/null || return 1
  sleep 2
  ssh_cmd "$SVM" "$SZONE" "grep -q '^RSSET ' /tmp/rsb1-server.footprint" || return 1
  ssh_cmd "$CVM" "$CZONE" "grep -q '^RSSET ' /tmp/rsb1-client.footprint" || return 1

  local sample_number=0 total_samples=$((${#PARALLELS[@]} * REPEAT)) N sample_index sample_json mbps
  for N in "${PARALLELS[@]}"; do
    local -a samples=()
    for ((sample_index=1; sample_index<=REPEAT; sample_index++)); do
      echo "[gcp] $CONFIG: RSB1 N=$N sample=$sample_index/$REPEAT" >&2
      RS_PARITY_FAILURE_LOG=/tmp/rsb1-$N-$sample_index.log
      sample_json=$(ssh_cmd "$CVM" "$CZONE" "prlimit --nofile=65535:65535 -- /opt/rustscale/target/release/rustscale-bench client --transport $cli_transport $auth_args --target $target --duration $DURATION --parallel $N --direction down --hostname $CHOST-$N-$sample_index --state-dir /tmp/rsb1-$N-$sample_index --json 2>/tmp/rsb1-$N-$sample_index.log") || return 1
      mbps=$(printf '%s' "$sample_json" | python3 -c 'import json,math,sys; d=json.load(sys.stdin); transport,parallel,expected=sys.argv[1],int(sys.argv[2]),sys.argv[3]; assert d["transport"]==transport and d["protocol"]=="RSB1" and d["direction"]=="down" and d["parallel"]==parallel and d["established"]==parallel and d["handshaken"]==parallel and d["completed"]==parallel; assert transport=="kernel-tcp" or d["path_class"]==expected; v=float(d["total_mbps"]); assert math.isfinite(v) and v>0; print(repr(v))' "$reported_transport" "$N" "$PATH_TAG") || return 1
      samples+=("$mbps")
      trial_json=$(printf '%s' "$sample_json" | python3 -c 'import json,sys; rows=json.loads(sys.argv[1]); d=json.load(sys.stdin); rows.append({"parallel":d["parallel"],"repeat_index":int(sys.argv[2]),"transport":d["transport"],"protocol":d["protocol"],"direction":d["direction"],"duration_s":d["duration_secs"],"established":d["established"],"handshaken":d["handshaken"],"completed":d["completed"],"total_mbps":d["total_mbps"],"path_class":d["path_class"]}); print(json.dumps(rows))' "$trial_json" "$sample_index") || return 1
      sample_number=$((sample_number+1))
      (( sample_number == total_samples )) || sleep 3
    done
    tp_json=$(append_tun_throughput_row "$tp_json" "$N" "$DURATION" "${samples[@]}") || return 1
  done

  # Latency is the final measured trial and receives the same inter-trial gap.
  sleep 3
  RS_PARITY_FAILURE_LOG=/tmp/rsb1-latency.log
  lat_json=$(ssh_cmd "$CVM" "$CZONE" "prlimit --nofile=65535:65535 -- /opt/rustscale/target/release/rustscale-bench latency --transport $cli_transport $auth_args --target $target --count $LATENCY_COUNT --hostname $CHOST-latency --state-dir /tmp/rsb1-latency --json 2>/tmp/rsb1-latency.log") || return 1
  lat_json=$(printf '%s' "$lat_json" | python3 -c 'import json,sys; d=json.load(sys.stdin); transport,n,expected=sys.argv[1],int(sys.argv[2]),sys.argv[3]; assert d["transport"]==transport and d["protocol"]=="RSB1-tcp-pingpong" and d["requested"]==n and d["successful"]==n and d["timed_out"]==0 and d["malformed"]==0 and len(d["samples_ns"])==n and all(type(v) is int and v>0 for v in d["samples_ns"]); assert transport=="kernel-tcp" or d["path_class"]==expected; print(json.dumps(d))' "$reported_transport" "$LATENCY_COUNT" "$PATH_TAG") || return 1
  RSB1_MEASURE_PATH_POST=$(printf '%s' "$lat_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["path_class"])') || return 1
  [[ "$reported_transport" == kernel-tcp ]] && RSB1_MEASURE_PATH_POST="$gated_path"

  server_foot=$(remote_stop_footprint "$SVM" "$SZONE" /tmp/rsb1-server.footprint) || return 1
  client_foot=$(remote_stop_footprint "$CVM" "$CZONE" /tmp/rsb1-client.footprint) || return 1
  bin_size=$(ssh_cmd "$SVM" "$SZONE" 'stat -c %s /opt/rustscale/target/release/rustscale-bench') || return 1
  server_subjects=$(IFS=,; printf '%s' "${RSB1_SERVER_SUBJECTS[*]}")
  client_subjects=$(IFS=,; printf '%s' "${RSB1_CLIENT_SUBJECTS[*]}")

  python3 - "$CONFIG" "$TOPOLOGY" "$PATH_TAG" "$path_class" "$reported_transport" "$bin_size" "$tp_json" "$trial_json" "$warmup_evidence" "$lat_json" "$server_foot" "$client_foot" "$REPEAT" "$server_subjects" "$client_subjects" "${PARALLELS[@]}" >"$PENDING_OUT" <<'PYEOF'
import json, sys
config, topo, requested_path, observed_path, transport, size, tp, trials, warmup_evidence, lat, server, client, repeat, server_subjects, client_subjects, *parallels = sys.argv[1:]
server, client = json.loads(server), json.loads(client)
subject_sets = [server_subjects.split(","), client_subjects.split(",")]
for endpoint in (server, client):
    assert endpoint["samples"] > 0 and endpoint["samples"] > endpoint["missing_samples"]
    assert endpoint["rss_peak_kb"] > 0 and endpoint["series"]
scope = {"kind":"dynamic_process_set","includes_descendants":False,"includes_kernel":False}
implementation = "rustscale" if config.startswith("rs-") else "tailscale"
mode = "userspace" if config.endswith("userspace") else "tun"
transport_path = {
    "rs-userspace":"embedded-tsnet",
    "rs-tun":"kernel-tcp-via-rustscaled-tun",
    "ts-userspace":"kernel-tcp-via-loopback-socat-socks5-tailscaled-serve",
    "ts-tun":"kernel-tcp-via-tailscaled-tun",
}[config]
portmapping = "disabled" if config == "rs-userspace" else "not-applicable"
obj={"schema_version":5,"status":"ok","tool":"rustscale" if implementation=="rustscale" else "tailscaled",
 "implementation":implementation,"mode":mode,"topology":topo,"path":requested_path,"config":config,
 "repeat":int(repeat),"parallelism_requested":[int(x) for x in parallels],"error":"","log_tail":"",
 "path_class_reported":observed_path,"transport":transport,
 "workload":{"implementation":"rustscale-bench","protocol":"RSB1","direction":"down","payload_bytes":1280,
             "warmup":{"parallel":1,"duration_s":3,"max_attempts":3},
             "client_lifecycle":"new_benchmark_process_per_trial","measured_trial_attempts":1,
             "latency_protocol":"RSB1-tcp-pingpong","latency_payload_bytes":8,
             "latency_count":50,"transport_path":transport_path,"userspace_portmapping":portmapping},
 "warmup_evidence":json.loads(warmup_evidence),"throughput":json.loads(tp),
 "throughput_trials":json.loads(trials),"latency":json.loads(lat),
 "resources":{"phase_set":["measured_client_process_lifecycle","inter_trial_gap","latency"],"sample_cadence_ms":1000,
              "server":dict(server,endpoint="server",subjects=subject_sets[0],scope=scope),
              "client":dict(client,endpoint="client",subjects=subject_sets[1],scope=scope)},
 "footprint":dict(server,binary_size_bytes=int(size),subject="rustscale-bench",endpoint="server",scope=scope),
 "binary":{"subject":"rustscale-bench","size_bytes":int(size)}}
print(json.dumps(obj,indent=2))
PYEOF
}

# Publish only after a post-suite path gate and verified clean teardown. The
# pending file is never considered by aggregate.py's three-level cell scan.
publish_rsb1_result() {
  local pre_path="$1" post_path="$2"
  [[ -f "$PENDING_OUT" && "$pre_path" == "$post_path" && "$post_path" == "$PATH_TAG" ]] || return 1
  python3 - "$PENDING_OUT" "$pre_path" "$post_path" <<'PYEOF'
import json, os, sys, tempfile
path, pre, post = sys.argv[1:]
with open(path) as f: obj=json.load(f)
obj["path_class_reported"] = post
obj["path_gate"] = {"requested": obj["path"], "pre": pre, "post": post, "matched": pre == post == obj["path"]}
obj["cleanup"] = {"status":"clean","samplers_stopped":True,"workload_stopped":True,"transport_stopped":True,"postconditions_verified":True}
fd, temporary = tempfile.mkstemp(prefix=".rsb1-publish.", dir=os.path.dirname(path))
with os.fdopen(fd, "w") as f: json.dump(obj, f, indent=2); f.write("\n")
os.replace(temporary, path)
PYEOF
  finalize_result_metadata "$PENDING_OUT" || return 1
  mv -f "$PENDING_OUT" "$OUT"
}

CELL_CLEANUP_FN=""
CELL_MUTATED=0
CELL_CLEANED=1
arm_cell_cleanup() {
  CELL_CLEANUP_FN="$1"
  CELL_MUTATED=1
  CELL_CLEANED=0
}

# Unexpected set -e exits and signals cannot hand a dirty VM to the next cell.
cell_exit_cleanup() {
  local status=$?
  trap - EXIT INT TERM
  set +e
  if (( CELL_MUTATED && ! CELL_CLEANED )) && [[ -n "$CELL_CLEANUP_FN" ]]; then
    "$CELL_CLEANUP_FN"
    local cleanup_status=$?
    (( status == 0 )) && status=1
    (( cleanup_status == 0 )) || status=$FATAL_HANDOFF_STATUS
  fi
  rm -f "$PENDING_OUT"
  exit "$status"
}

rsb1_lifecycle_self_test() {
  local command event status definition
  command=$(ts_tun_cleanup_command srv) || return 1
  bash -n <<<"$command" || return 1
  [[ "$command" == *'tailscale --socket="$socket" down'* \
    && "$command" == *'cmp -s /etc/resolv.conf.bench-bak /etc/resolv.conf'* \
    && "$command" == *'ip link delete dev tailscale0'* \
    && "$command" == *'pkill -KILL -x tailscaled'* ]] || return 1
  command=$(userspace_cleanup_command cli) || return 1
  bash -n <<<"$command" || return 1
  [[ "$command" == *'serve reset'* && "$command" == *'pkill -KILL -x socat'* \
    && "$command" == *'11080'* && "$command" == *'ip link show dev tailscale0'* ]] || return 1

  # The measured suite contains retries only in the pre-sampling warmup.
  definition=$(declare -f rsb1_measure)
  [[ $(grep -c 'RSB1 warmup retry' <<<"$definition") -eq 1 \
    && "$definition" != *'measured retry'* \
    && "$definition" == *'throughput_trials'* ]] || return 1

  event=$(mktemp "$RDIR/cell-exit-test.XXXXXX") || return 1
  if ( set +e; CELL_MUTATED=1; CELL_CLEANED=0; CELL_CLEANUP_FN=self_test_cleanup; self_test_cleanup() { printf clean >"$event"; return 0; }; false; cell_exit_cleanup ); then
    rm -f "$event"; return 1
  else
    status=$?
  fi
  [[ "$status" == 1 && "$(<"$event")" == clean ]] || { rm -f "$event"; return 1; }
  if ( set +e; CELL_MUTATED=1; CELL_CLEANED=0; CELL_CLEANUP_FN=self_test_cleanup; self_test_cleanup() { return 1; }; false; cell_exit_cleanup ); then
    rm -f "$event"; return 1
  else
    status=$?
  fi
  [[ "$status" == "$FATAL_HANDOFF_STATUS" ]] || { rm -f "$event"; return 1; }
  rm -f "$event"
}

# ===========================================================================
# Config: rs-userspace — rustscale-bench server + client
# ===========================================================================
run_rs_userspace() {
  arm_cell_cleanup cleanup_rs_userspace
  echo "[gcp] rs-userspace: starting bench server on $SVM" >&2
  ssh_cmd "$SVM" "$SZONE" \
    "$(rs_userspace_server_start_command "$RS_LINUX_UDP_BATCH" "$RS_LINUX_UDP_GRO" "$RS_LINUX_UDP_GSO" "$AUTHKEY" "$PORT" "$SHOST" /tmp/rs-srv /tmp/rs-srv.log /tmp/rs-srv.pid)"

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
  if (( elapsed >= timeout )); then
    echo "[gcp] ERROR: rustscale-bench server never became ready" >&2
    local _lt
    _lt=$(capture_log_tail "$SVM" "$SZONE" /tmp/rs-srv.log)
    fail_userspace_config cleanup_rs_userspace "server-not-ready" "$_lt"
    return 1
  fi

  local server_ip
  server_ip=$(ssh_cmd "$SVM" "$SZONE" "grep '^BENCH_IP ' /tmp/rs-srv.log | awk '{print \$2}'")
  echo "[gcp] rs-userspace: server IP=$server_ip" >&2

  RSB1_SERVER_SUBJECTS=(rustscale-bench)
  RSB1_CLIENT_SUBJECTS=(rustscale-bench)
  if rsb1_measure userspace userspace-tsnet "$server_ip:$PORT" "$PATH_TAG"; then
    local post_path="$RSB1_MEASURE_PATH_POST"
    if ! cleanup_rs_userspace; then
      emit_stub "rs-userspace-cleanup-failed"
      return 1
    fi
    if publish_rsb1_result "$PATH_TAG" "$post_path"; then
      echo "[gcp] rs-userspace: wrote matched RSB1 result $OUT" >&2
      return 0
    fi
    emit_stub "rs-userspace-result-publish-failed"
    return 1
  fi
  fail_userspace_config cleanup_rs_userspace "rs-userspace-rsb1-measure-failed" "$(capture_log_tail "$CVM" "$CZONE" "${RS_PARITY_FAILURE_LOG:-/tmp/rsb1-setup.log}")"
  return 1

}

# ===========================================================================
# Config: rs-tun — production rustscaled path + kernel-TCP RSB1 workload
# ===========================================================================
run_rs_tun() {
  arm_cell_cleanup cleanup_rs_tun
  echo "[gcp] rs-tun: starting production rustscaled daemons" >&2
  if (( PROFILE || PROFILE_ONLY )) && ! profile_prepare; then
    emit_stub "rs-tun-perf-prepare-failed"
    profile_remote_cleanup || true
    cleanup_rs_tun || return "$FATAL_HANDOFF_STATUS"
    return 1
  fi
  ssh_sudo "$SVM" "$SZONE"  'rm -rf /tmp/rs-tun-srv; rm -f /tmp/rs-tun-srv.log /tmp/rs-tun-srv.pid /tmp/rs-tun-srv.sock'
  ssh_sudo "$CVM" "$CZONE"  'rm -rf /tmp/rs-tun-cli; rm -f /tmp/rs-tun-cli.log /tmp/rs-tun-cli.pid /tmp/rs-tun-cli.sock'
  ssh_sudo "$SVM" "$SZONE" "$(rs_tun_daemon_start_command "$RS_TUN_INBOUND_PIPELINE" "$RS_LINUX_UDP_BATCH" "$RS_LINUX_UDP_GRO" "$AUTHKEY" /tmp/rs-tun-srv /tmp/rs-tun-srv.sock "$SHOST" /tmp/rs-tun-srv.log /tmp/rs-tun-srv.pid "$RS_TUN_OUTBOUND_SEND_PIPELINE" "$RS_LINUX_UDP_GSO")"
  ssh_sudo "$CVM" "$CZONE" "$(rs_tun_daemon_start_command "$RS_TUN_INBOUND_PIPELINE" "$RS_LINUX_UDP_BATCH" "$RS_LINUX_UDP_GRO" "$AUTHKEY" /tmp/rs-tun-cli /tmp/rs-tun-cli.sock "$CHOST" /tmp/rs-tun-cli.log /tmp/rs-tun-cli.pid "$RS_TUN_OUTBOUND_SEND_PIPELINE" "$RS_LINUX_UDP_GSO")"

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
  if path_class=$(tun_path_gate 1 "$CVM" "$CZONE" /opt/rustscale/target/release/rustscale /tmp/rs-tun-cli.sock "$server_ip" "$PATH_TAG" /tmp/rs-tun-cli.path.log); then
    :
  else
    local path_status=$?
    local path_error=path-cli-failed
    [[ "$PATH_TAG" == direct && $path_status -eq 124 ]] && path_error=direct-path-timeout
    emit_stub "rs-$path_error" "$(capture_log_tail "$CVM" "$CZONE" /tmp/rs-tun-cli.path.log)"
    if ! cleanup_rs_tun; then return "$FATAL_HANDOFF_STATUS"; fi
    return 1
  fi

  # The matrix invokes this diagnostic only after every normal selected cell.
  # It deliberately bypasses tun_measure and result emission, preserving the
  # already accepted rs-tun measurement JSON while reusing setup, gating, and
  # the labeled iperf server lifecycle.
  if (( PROFILE_ONLY )); then
    if ! profile_only_rs_tun_workload; then
      cleanup_rs_tun || return "$FATAL_HANDOFF_STATUS"
      return 1
    fi
    cleanup_rs_tun || return "$FATAL_HANDOFF_STATUS"
    return 0
  fi

  if ! start_kernel_rsb1_server 0.0.0.0; then
    emit_stub "rs-tun-rsb1-server-not-ready" "$(capture_log_tail "$SVM" "$SZONE" /tmp/rsb1-server.log)"
    cleanup_rs_tun || return "$FATAL_HANDOFF_STATUS"
    return 1
  fi
  RSB1_SERVER_SUBJECTS=(rustscaled rustscale-bench)
  RSB1_CLIENT_SUBJECTS=(rustscaled rustscale-bench)
  if rsb1_measure kernel-tcp kernel-tcp "$server_ip:$PORT" "$path_class"; then
    local post_path
    post_path=$(tun_path_gate 1 "$CVM" "$CZONE" /opt/rustscale/target/release/rustscale /tmp/rs-tun-cli.sock "$server_ip" "$PATH_TAG" /tmp/rs-tun-cli.path-post.log) || {
      emit_stub "rs-post-path-gate-failed" "$(capture_log_tail "$CVM" "$CZONE" /tmp/rs-tun-cli.path-post.log)"
      cleanup_rs_tun || return "$FATAL_HANDOFF_STATUS"
      return 1
    }
    if (( PROFILE )) && ! profile_rs_tun; then
      emit_stub "rs-tun-profile-failed" "$(capture_log_tail "$SVM" "$SZONE" /tmp/rs-tun-perf-server.log)"
      cleanup_rs_tun || return "$FATAL_HANDOFF_STATUS"
      return 1
    fi
    if ! cleanup_rs_tun; then
      emit_stub "rs-tun-cleanup-failed"
      return "$FATAL_HANDOFF_STATUS"
    fi
    if publish_rsb1_result "$path_class" "$post_path"; then
      echo "[gcp] rs-tun: wrote matched RSB1 result $OUT" >&2
      return 0
    fi
    emit_stub "rs-tun-result-publish-failed"
    return 1
  fi
  emit_stub "rs-tun-rsb1-measure-failed" "$(capture_log_tail "$CVM" "$CZONE" "${RS_PARITY_FAILURE_LOG:-/tmp/rsb1-latency.log}")"
  cleanup_rs_tun || return "$FATAL_HANDOFF_STATUS"
  return 1


}

# ===========================================================================
# Config: ts-userspace — tailscaled userspace-networking + SOCKS5
# ===========================================================================
run_ts_userspace() {
  arm_cell_cleanup cleanup_ts_userspace
  echo "[gcp] ts-userspace: preparing loopback RSB1 server and tailscaled userspace path" >&2

  # The local RSB1 listener is authoritative readiness gate one and is never
  # exposed on a host interface; tailscale Serve owns the tailnet-side port.
  if ! start_kernel_rsb1_server 127.0.0.1; then
    fail_userspace_config cleanup_ts_userspace "ts-userspace-rsb1-server-not-ready" "$(capture_log_tail "$SVM" "$SZONE" /tmp/rsb1-server.log)"
    return 1
  fi

  ssh_cmd "$SVM" "$SZONE" \
    "rm -rf /tmp/ts-srv; rm -f /tmp/ts-srv.{sock,log,pid}; nohup prlimit --nofile=65535:65535 -- tailscaled --tun=userspace-networking --socket=/tmp/ts-srv.sock --statedir=/tmp/ts-srv --port=41642 >/tmp/ts-srv.log 2>&1 & echo \$! >/tmp/ts-srv.pid" || {
      fail_userspace_config cleanup_ts_userspace "ts-userspace-daemon-start-failed-srv"
      return 1
    }
  sleep 2
  if ! ssh_cmd "$SVM" "$SZONE" \
    "tailscale --socket=/tmp/ts-srv.sock up --authkey=$AUTHKEY --hostname=$SHOST --timeout=120s 2>>/tmp/ts-srv.log"; then
    fail_userspace_config cleanup_ts_userspace "ts-up-failed-srv" "$(capture_log_tail "$SVM" "$SZONE" /tmp/ts-srv.log)"
    return 1
  fi
  local server_ip
  server_ip=$(wait_tun_ip 0 "$SVM" "$SZONE" tailscale /tmp/ts-srv.sock /tmp/ts-srv.log) || {
    fail_userspace_config cleanup_ts_userspace "ts-no-ip-srv" "$(capture_log_tail "$SVM" "$SZONE" /tmp/ts-srv.log)"
    return 1
  }

  ssh_cmd "$CVM" "$CZONE" \
    "rm -rf /tmp/ts-cli; rm -f /tmp/ts-cli.{sock,log,pid}; nohup prlimit --nofile=65535:65535 -- tailscaled --tun=userspace-networking --socket=/tmp/ts-cli.sock --statedir=/tmp/ts-cli --port=41643 --socks5-server=127.0.0.1:11080 >/tmp/ts-cli.log 2>&1 & echo \$! >/tmp/ts-cli.pid" || {
      fail_userspace_config cleanup_ts_userspace "ts-userspace-daemon-start-failed-cli"
      return 1
    }
  sleep 2
  if ! ssh_cmd "$CVM" "$CZONE" \
    "tailscale --socket=/tmp/ts-cli.sock up --authkey=$AUTHKEY --hostname=$CHOST --timeout=120s 2>>/tmp/ts-cli.log"; then
    fail_userspace_config cleanup_ts_userspace "ts-up-failed-cli" "$(capture_log_tail "$CVM" "$CZONE" /tmp/ts-cli.log)"
    return 1
  fi
  local client_ip
  client_ip=$(wait_tun_ip 0 "$CVM" "$CZONE" tailscale /tmp/ts-cli.sock /tmp/ts-cli.log) || {
    fail_userspace_config cleanup_ts_userspace "ts-no-ip-cli" "$(capture_log_tail "$CVM" "$CZONE" /tmp/ts-cli.log)"
    return 1
  }

  # Both local backends and both exact peer identities must be online before
  # Serve or SOCKS setup can be treated as benchmark readiness.
  if ! wait_ts_online "$SVM" "$SZONE" /tmp/ts-srv.sock 120 \
      || ! wait_ts_online "$CVM" "$CZONE" /tmp/ts-cli.sock 120 \
      || ! wait_ts_peer_ip "$SVM" "$SZONE" /tmp/ts-srv.sock "$client_ip" 120 \
      || ! wait_ts_peer_ip "$CVM" "$CZONE" /tmp/ts-cli.sock "$server_ip" 120; then
    fail_userspace_config cleanup_ts_userspace "ts-specific-peer-not-online" "$(capture_log_tail "$CVM" "$CZONE" /tmp/ts-cli.log)"
    return 1
  fi
  if ! ssh_cmd "$SVM" "$SZONE" 'pid=$(cat /tmp/ts-srv.pid); awk '\''/Max open files/ {exit !($4 >= 65535 && $5 >= 65535)}'\'' /proc/$pid/limits' \
      || ! ssh_cmd "$CVM" "$CZONE" 'pid=$(cat /tmp/ts-cli.pid); awk '\''/Max open files/ {exit !($4 >= 65535 && $5 >= 65535)}'\'' /proc/$pid/limits'; then
    fail_userspace_config cleanup_ts_userspace "ts-userspace-nofile-limit-too-low"
    return 1
  fi

  if ! ssh_cmd "$SVM" "$SZONE" \
      "tailscale --socket=/tmp/ts-srv.sock serve reset 2>>/tmp/ts-srv.log || true; tailscale --socket=/tmp/ts-srv.sock serve --tcp $PORT --bg 127.0.0.1:$PORT 2>>/tmp/ts-srv.log" \
      || ! verify_ts_serve_rsb1; then
    fail_userspace_config cleanup_ts_userspace "ts-userspace-serve-gate-failed" "$(capture_log_tail "$SVM" "$SZONE" /tmp/ts-srv.log)"
    return 1
  fi
  if ! start_ts_userspace_bridge "$server_ip"; then
    fail_userspace_config cleanup_ts_userspace "ts-userspace-socat-gate-failed" "$(capture_log_tail "$CVM" "$CZONE" /tmp/socat.log)"
    return 1
  fi

  local path_class
  path_class=$(tun_path_gate 0 "$CVM" "$CZONE" tailscale /tmp/ts-cli.sock "$server_ip" "$PATH_TAG" /tmp/ts-cli.path.log) || {
    fail_userspace_config cleanup_ts_userspace "ts-userspace-path-gate-failed" "$(capture_log_tail "$CVM" "$CZONE" /tmp/ts-cli.path.log)"
    return 1
  }

  RSB1_SERVER_SUBJECTS=(tailscaled rustscale-bench)
  RSB1_CLIENT_SUBJECTS=(tailscaled socat rustscale-bench)
  if ! rsb1_measure kernel-tcp kernel-tcp 127.0.0.1:5300 "$path_class"; then
    fail_userspace_config cleanup_ts_userspace "ts-userspace-rsb1-measure-failed" "$(capture_log_tail "$CVM" "$CZONE" "${RS_PARITY_FAILURE_LOG:-/tmp/rsb1-setup.log}")"
    return 1
  fi

  local post_path
  post_path=$(tun_path_gate 0 "$CVM" "$CZONE" tailscale /tmp/ts-cli.sock "$server_ip" "$PATH_TAG" /tmp/ts-cli.path-post.log) || {
    fail_userspace_config cleanup_ts_userspace "ts-userspace-post-path-gate-failed" "$(capture_log_tail "$CVM" "$CZONE" /tmp/ts-cli.path-post.log)"
    return 1
  }
  if ! cleanup_ts_userspace; then
    emit_stub "ts-userspace-cleanup-failed"
    return "$FATAL_HANDOFF_STATUS"
  fi
  if ! publish_rsb1_result "$path_class" "$post_path"; then
    emit_stub "ts-userspace-result-publish-failed"
    return 1
  fi
  echo "[gcp] ts-userspace: wrote matched RSB1 result $OUT" >&2
}

# ===========================================================================
# Config: ts-tun — default tailscaled with kernel TUN
# ===========================================================================
run_ts_tun() {
  arm_cell_cleanup cleanup_ts_tun
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
  if ! ssh_sudo "$SVM" "$SZONE" "cp /etc/resolv.conf /etc/resolv.conf.bench-bak" \
      || ! ssh_sudo "$CVM" "$CZONE" "cp /etc/resolv.conf /etc/resolv.conf.bench-bak"; then
    emit_stub "ts-tun-dns-backup-failed"
    cleanup_ts_tun || true
    return "$FATAL_HANDOFF_STATUS"
  fi

  ssh_sudo "$SVM" "$SZONE" \
    "nohup prlimit --nofile=65535:65535 -- tailscaled --socket=/tmp/ts-tun-srv.sock --statedir=/tmp/ts-tun-srv > /tmp/ts-tun-srv.log 2>&1 & echo \$! > /tmp/ts-tun-srv.pid"
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
    "nohup prlimit --nofile=65535:65535 -- tailscaled --socket=/tmp/ts-tun-cli.sock --statedir=/tmp/ts-tun-cli > /tmp/ts-tun-cli.log 2>&1 & echo \$! > /tmp/ts-tun-cli.pid"
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

  local client_ip
  if ! client_ip=$(wait_tun_ip 1 "$CVM" "$CZONE" tailscale /tmp/ts-tun-cli.sock /tmp/ts-tun-cli.log); then
    echo "[gcp] ERROR: tailscale CLI did not report a client IP" >&2
    local _lt
    _lt=$(capture_log_tail "$CVM" "$CZONE" /tmp/ts-tun-cli.log)
    emit_stub "ts-no-ip-cli" "$_lt"
    cleanup_ts_tun
    return 1
  fi
  if ! wait_ts_online "$SVM" "$SZONE" /tmp/ts-tun-srv.sock 120 \
      || ! wait_ts_online "$CVM" "$CZONE" /tmp/ts-tun-cli.sock 120 \
      || ! wait_ts_peer_ip "$SVM" "$SZONE" /tmp/ts-tun-srv.sock "$client_ip" 120 \
      || ! wait_ts_peer_ip "$CVM" "$CZONE" /tmp/ts-tun-cli.sock "$server_ip" 120; then
    emit_stub "ts-specific-peer-not-online" "$(capture_log_tail "$CVM" "$CZONE" /tmp/ts-tun-cli.log)"
    cleanup_ts_tun
    return 1
  fi
  if ! ssh_sudo "$SVM" "$SZONE" 'pid=$(cat /tmp/ts-tun-srv.pid); awk '\''/Max open files/ {exit !($4 >= 65535 && $5 >= 65535)}'\'' /proc/$pid/limits' \
      || ! ssh_sudo "$CVM" "$CZONE" 'pid=$(cat /tmp/ts-tun-cli.pid); awk '\''/Max open files/ {exit !($4 >= 65535 && $5 >= 65535)}'\'' /proc/$pid/limits'; then
    emit_stub "ts-tun-nofile-limit-too-low"
    cleanup_ts_tun
    return 1
  fi

  local path_class
  if path_class=$(tun_path_gate 1 "$CVM" "$CZONE" tailscale /tmp/ts-tun-cli.sock "$server_ip" "$PATH_TAG" /tmp/ts-tun-cli.path.log); then
    :
  else
    local path_status=$?
    local path_error=path-cli-failed
    [[ "$PATH_TAG" == direct && $path_status -eq 124 ]] && path_error=direct-path-timeout
    emit_stub "ts-$path_error" "$(capture_log_tail "$CVM" "$CZONE" /tmp/ts-tun-cli.path.log)"; cleanup_ts_tun; return 1
  fi

  if ! start_kernel_rsb1_server 0.0.0.0; then
    emit_stub "ts-tun-rsb1-server-not-ready" "$(capture_log_tail "$SVM" "$SZONE" /tmp/rsb1-server.log)"
    cleanup_ts_tun || return "$FATAL_HANDOFF_STATUS"
    return 1
  fi
  RSB1_SERVER_SUBJECTS=(tailscaled rustscale-bench)
  RSB1_CLIENT_SUBJECTS=(tailscaled rustscale-bench)
  if ! rsb1_measure kernel-tcp kernel-tcp "$server_ip:$PORT" "$path_class"; then
    emit_stub "ts-tun-rsb1-measure-failed" "$(capture_log_tail "$CVM" "$CZONE" "${RS_PARITY_FAILURE_LOG:-/tmp/rsb1-setup.log}")"
    cleanup_ts_tun || return "$FATAL_HANDOFF_STATUS"
    return 1
  fi
  local post_path
  post_path=$(tun_path_gate 1 "$CVM" "$CZONE" tailscale /tmp/ts-tun-cli.sock "$server_ip" "$PATH_TAG" /tmp/ts-tun-cli.path-post.log) || {
    emit_stub "ts-tun-post-path-gate-failed" "$(capture_log_tail "$CVM" "$CZONE" /tmp/ts-tun-cli.path-post.log)"
    cleanup_ts_tun || return "$FATAL_HANDOFF_STATUS"
    return 1
  }
  if ! cleanup_ts_tun; then
    emit_stub "ts-tun-cleanup-failed"
    return "$FATAL_HANDOFF_STATUS"
  fi
  if ! publish_rsb1_result "$path_class" "$post_path"; then
    emit_stub "ts-tun-result-publish-failed"
    return 1
  fi
  echo "[gcp] ts-tun: wrote matched RSB1 result $OUT" >&2
}

# ---------------------------------------------------------------------------
# Dispatch.
# ---------------------------------------------------------------------------
if (( SELF_TEST )); then
  profile_command_self_test
  tun_measure_self_test
  rsb1_lifecycle_self_test
  rm -rf "$RDIR"
  echo "run-config self-tests: OK" >&2
  exit 0
fi
trap cell_exit_cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
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
