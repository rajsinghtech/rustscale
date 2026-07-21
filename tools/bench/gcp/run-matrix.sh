#!/usr/bin/env bash
# tools/bench/gcp/run-matrix.sh — main orchestrator for the GCP bench matrix.
#
# Defaults to the routine same-zone/direct five-cell matched matrix. --full
# expands topology/path coverage to the 2x2x5 = 20-cell matrix on dedicated
# GCP VMs, writing per-run JSON + a combined summary.json + a standalone HTML
# dashboard into bench-results/gcp-<stamp>/.
#
# Reuses tools/bench/lib.sh for ephemeral tailnet provisioning.
#
# Usage:
#   tools/bench/gcp/run-matrix.sh            # five-cell routine run
#   tools/bench/gcp/run-matrix.sh --dry-run  # validate args, no gcloud/API
#
# Environment:
#   TS_ORG_TOKEN or TS_ORG_CLIENT_ID/SECRET  — tailnet creds (see tools/bench/lib.sh)
#   GCP_PROJECT                              — auto-detected from gcloud config
#   GCP_DRY_RUN                              — set by --dry-run; propagated to lib.sh
#   SKIP_VM_DELETE=1                         — keep VMs at the end (debugging)
#   MATRIX_RESULTS_DIR                        — parent/root for the run-ID directory override
#   RS_TUN_INBOUND_PIPELINE / RS_TUN_OUTBOUND_SEND_PIPELINE — rs-tun pipeline toggles: 0 (default) or 1
#   RS_LINUX_UDP_BATCH / RS_LINUX_UDP_GRO     — Linux receive modes: 0 (disabled) or 1 (default)
#   RS_LINUX_UDP_GSO                          — Linux TX-GSO mode: 0 (plain sendmmsg) or 1 (default/probed; requires batch=1)

set -euo pipefail

# Resolve repo root (this file is at tools/bench/gcp/run-matrix.sh).
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$REPO_ROOT"

# shellcheck source=../lib.sh
source tools/bench/lib.sh
# shellcheck source=./lib.sh
source tools/bench/gcp/lib.sh
# shellcheck source=./footprint.sh
source tools/bench/gcp/footprint.sh

# Defaults make pure local self-tests deterministic. The real invocation
# replaces these immediately before publishing matrix.json.
MATRIX_RUN_ID="gcp-20260714-000000-selftest"
MATRIX_STARTED_AT_UTC="2026-07-14T00:00:00Z"
MATRIX_SOURCE_COMMIT="$(git rev-parse HEAD)"
MATRIX_WORKTREE_DIRTY=0
MATRIX_PROJECT="dry-run"
MATRIX_MANIFEST_PATH="/dev/null"
MATRIX_OBSERVED_PATH="/dev/null"
DURATION=10
PEER_COUNT=1
PARALLELISM_CSV="1,10,100,500,1000"
MATRIX_PRESET="custom"
LOAD_PRESET="routine-v1"
TOPOLOGY_SOURCE="explicit"
PATH_SOURCE="explicit"
CONFIG_SOURCE="explicit"

# `same-zone` is the historical label; every candidate remains a same-region,
# cross-zone us-central1 pair. Candidates are ordered and finite rather than an
# open-ended retry policy. A selected pair is retained in endpoint provenance.
declare -A ZONE_PAIR_CANDIDATES=(
  [same-zone]="us-central1-a:us-central1-b us-central1-c:us-central1-f us-central1-a:us-central1-f"
  [cross-region]="us-central1-a:us-west1-a us-central1-c:us-west1-a"
)
ACTIVE_SRV=""
ACTIVE_SRV_ZONE=""
ACTIVE_CLI=""
ACTIVE_CLI_ZONE=""

capacity_exhausted() {
  grep -Eq 'ZONE_RESOURCE_POOL_EXHAUSTED|RESOURCE_EXHAUSTED|resource pool.*exhausted' "$1"
}

# Try each approved pair at most once. Only a documented capacity exhaustion
# advances to the next equivalent pair; all other create failures fail closed.
# ACTIVE_* is set before each attempt so an interrupt cannot leak a partial VM.
provision_topology_pair() {
  local topology="$1" server="$2" client="$3" pair server_zone client_zone log status
  for pair in ${ZONE_PAIR_CANDIDATES[$topology]}; do
    IFS=: read -r server_zone client_zone <<<"$pair"
    ACTIVE_SRV="$server"; ACTIVE_SRV_ZONE="$server_zone"
    ACTIVE_CLI="$client"; ACTIVE_CLI_ZONE="$client_zone"
    log=$(mktemp) || return 1
    if create_vms "$server" "$server_zone" "$client" "$client_zone" 2>"$log"; then
      cat "$log" >&2
      rm -f "$log"
      Z_A="$server_zone"; Z_B="$client_zone"
      echo "[gcp] capacity preflight selected $topology zones $Z_A / $Z_B" >&2
      return 0
    fi
    status=$?
    cat "$log" >&2
    if ! capacity_exhausted "$log"; then
      rm -f "$log"
      return "$status"
    fi
    rm -f "$log"
    echo "[gcp] capacity exhausted for approved $topology pair $server_zone / $client_zone; cleaning up before the next pair" >&2
    delete_vms "$server" "$server_zone" "$client" "$client_zone" || return 1
    ACTIVE_SRV=""; ACTIVE_SRV_ZONE=""; ACTIVE_CLI=""; ACTIVE_CLI_ZONE=""
  done
  echo "[gcp] no approved $topology zone pair has capacity for $GCP_MACHINE; no benchmark cell was started" >&2
  return 1
}

matrix_zone_pair_self_test() (
  local calls=""
  create_vms() {
    calls+=" create:$2/$4"
    [[ "$2/$4" != us-central1-a/us-central1-b ]] || { echo ZONE_RESOURCE_POOL_EXHAUSTED >&2; return 1; }
  }
  delete_vms() { calls+=" delete:$2/$4"; }
  provision_topology_pair same-zone server client || return 1
  [[ "$Z_A/$Z_B" == us-central1-c/us-central1-f ]] || return 1
  [[ "$calls" == ' create:us-central1-a/us-central1-b delete:us-central1-a/us-central1-b create:us-central1-c/us-central1-f' ]]
)

MATRIX_SELF_TEST=0
if [[ "${1:-}" == "--self-test" ]]; then
  MATRIX_SELF_TEST=1
  shift
fi

# Must match the distinct status returned by run-config.sh when rustscaled or
# tailscale0 remains after its forced cleanup.  This is unsafe to hand off.
FATAL_HANDOFF_STATUS=86

rust_build_command() {
  local config candidate existing seen
  local -a requested=() packages=()

  for config in "${CONFIGS[@]}"; do
    case "$config" in
      rs-userspace|ts-userspace|ts-tun) requested=(rustscale-bench) ;;
      rs-tun) requested=(rustscale-bench rustscale-cli rustscale-rustscaled) ;;
      ts-embedded) continue ;;
      *) continue ;;
    esac
    for candidate in "${requested[@]}"; do
      seen=0
      for existing in "${packages[@]}"; do
        [[ "$candidate" == "$existing" ]] && seen=1
      done
      (( seen )) || packages+=("$candidate")
    done
  done

  (( ${#packages[@]} )) || return 0
  printf '%s' 'export RUSTUP_HOME=/opt/rust CARGO_HOME=/opt/rust/cargo'
  [[ -z "${RUSTFLAGS:-}" ]] || { printf ' RUSTFLAGS='; printf '%q' "$RUSTFLAGS"; }
  [[ -z "${CARGO_PROFILE_RELEASE_LTO:-}" ]] || { printf ' CARGO_PROFILE_RELEASE_LTO='; printf '%q' "$CARGO_PROFILE_RELEASE_LTO"; }
  [[ -z "${CARGO_PROFILE_RELEASE_CODEGEN_UNITS:-}" ]] || { printf ' CARGO_PROFILE_RELEASE_CODEGEN_UNITS='; printf '%q' "$CARGO_PROFILE_RELEASE_CODEGEN_UNITS"; }
  printf '%s' '; cd /opt/rustscale && cargo build --release'
  for package in "${packages[@]}"; do
    printf ' -p %s' "$package"
  done
}

go_build_command() {
  local config
  for config in "${CONFIGS[@]}"; do
    if [[ "$config" == ts-embedded ]]; then
      printf '%s' 'export GOTOOLCHAIN=local; cd /opt/rustscale/tools/bench/go-tsnet && test "$(go env GOVERSION)" = go1.26.4 && go mod verify && mkdir -p /opt/rustscale/bin && go build -trimpath -buildvcs=false -ldflags=-buildid= -o /opt/rustscale/bin/go-tsnet-rsb1 .'
      return 0
    fi
  done
}

remote_build_command() {
  local rust_command go_command
  rust_command=$(rust_build_command)
  go_command=$(go_build_command)
  if [[ -n "$rust_command" && -n "$go_command" ]]; then
    printf '%s && %s' "$rust_command" "$go_command"
  else
    printf '%s%s' "$rust_command" "$go_command"
  fi
}

matrix_command_shape_self_test() {
  local actual go_actual remote_actual
  CONFIGS=(rs-userspace)
  actual=$(rust_build_command)
  [[ "$actual" == 'export RUSTUP_HOME=/opt/rust CARGO_HOME=/opt/rust/cargo; cd /opt/rustscale && cargo build --release -p rustscale-bench' ]] || return 1
  CONFIGS=(rs-tun)
  actual=$(rust_build_command)
  [[ "$actual" == 'export RUSTUP_HOME=/opt/rust CARGO_HOME=/opt/rust/cargo; cd /opt/rustscale && cargo build --release -p rustscale-bench -p rustscale-cli -p rustscale-rustscaled' ]] || return 1
  CONFIGS=(rs-userspace rs-tun)
  actual=$(rust_build_command)
  [[ "$actual" == 'export RUSTUP_HOME=/opt/rust CARGO_HOME=/opt/rust/cargo; cd /opt/rustscale && cargo build --release -p rustscale-bench -p rustscale-cli -p rustscale-rustscaled' ]] || return 1
  CONFIGS=(ts-userspace ts-tun)
  actual=$(rust_build_command)
  [[ "$actual" == 'export RUSTUP_HOME=/opt/rust CARGO_HOME=/opt/rust/cargo; cd /opt/rustscale && cargo build --release -p rustscale-bench' ]] || return 1
  CONFIGS=(rs-userspace rs-tun ts-embedded ts-userspace ts-tun)
  actual=$(rust_build_command)
  [[ "$actual" == 'export RUSTUP_HOME=/opt/rust CARGO_HOME=/opt/rust/cargo; cd /opt/rustscale && cargo build --release -p rustscale-bench -p rustscale-cli -p rustscale-rustscaled' ]] || return 1
  [[ "$actual" != *'-p rustscaled'* ]] || return 1
  go_actual=$(go_build_command)
  [[ "$go_actual" == *'GOTOOLCHAIN=local'* && "$go_actual" == *'test "$(go env GOVERSION)" = go1.26.4'* \
    && "$go_actual" == *'go mod verify'* && "$go_actual" == *'-trimpath -buildvcs=false -ldflags=-buildid='* \
    && "$go_actual" == *'/opt/rustscale/bin/go-tsnet-rsb1'* ]] || return 1
  remote_actual=$(remote_build_command)
  [[ "$remote_actual" == "$actual && $go_actual" ]] || return 1
  CONFIGS=(ts-embedded)
  [[ -z "$(rust_build_command)" && "$(remote_build_command)" == "$(go_build_command)" ]] || return 1
  CONFIGS=(rs-userspace)
  [[ -z "$(go_build_command)" && "$(remote_build_command)" == "$(rust_build_command)" ]] || return 1
  RUSTFLAGS='-C target-cpu=native'; CARGO_PROFILE_RELEASE_LTO=thin; CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
  CONFIGS=(rs-tun); actual=$(rust_build_command)
  [[ "$actual" == *'RUSTFLAGS=-C\ target-cpu=native'* && "$actual" == *'CARGO_PROFILE_RELEASE_LTO=thin'* && "$actual" == *'CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1'* ]] || return 1
  unset RUSTFLAGS CARGO_PROFILE_RELEASE_LTO CARGO_PROFILE_RELEASE_CODEGEN_UNITS
}

wait_for_remote_builds() {
  local server_pid="$1" client_pid="$2" status=0

  if ! wait "$server_pid"; then
    echo "[gcp] server remote build failed" >&2
    status=1
  fi
  if ! wait "$client_pid"; then
    echo "[gcp] client remote build failed" >&2
    status=1
  fi
  return "$status"
}

matrix_remote_build_aggregation_self_test() {
  local first_pid second_pid

  (exit 0) & first_pid=$!
  (exit 0) & second_pid=$!
  wait_for_remote_builds "$first_pid" "$second_pid" || return 1

  (exit 0) & first_pid=$!
  (exit 1) & second_pid=$!
  if wait_for_remote_builds "$first_pid" "$second_pid" 2>/dev/null; then
    return 1
  fi
}

matrix_run_config_with_policy() {
  local config="$1" success_suffix="$2" status
  shift 2

  if "$@"; then
    echo "[gcp] $config: OK$success_suffix"
  else
    status=$?
    if (( status == FATAL_HANDOFF_STATUS )); then
      echo "[gcp] FATAL: $config left an unsafe TUN handoff; aborting matrix" >&2
      exit "$FATAL_HANDOFF_STATUS"
    fi
    echo "[gcp] $config: FAILED (continuing)" >&2
  fi
}

# Embedded clients reopen one state directory from a new process for every
# trial, so their transport identity must survive each intentional disconnect.
matrix_authkey_ephemeral_for_config() {
  case "$1" in
    rs-userspace|ts-embedded) printf '%s' false ;;
    rs-tun|ts-userspace|ts-tun) printf '%s' true ;;
    *) return 2 ;;
  esac
}

matrix_authkey_policy_self_test() {
  [[ "$(matrix_authkey_ephemeral_for_config rs-userspace)" == false ]] || return 1
  [[ "$(matrix_authkey_ephemeral_for_config ts-embedded)" == false ]] || return 1
  local config
  for config in rs-tun ts-userspace ts-tun; do
    [[ "$(matrix_authkey_ephemeral_for_config "$config")" == true ]] || return 1
  done
  if matrix_authkey_ephemeral_for_config invalid >/dev/null 2>&1; then return 1; fi
  if bench_mint_authkey invalid >/dev/null 2>&1; then return 1; else [[ $? -eq 2 ]]; fi
}

# Write one credential to an owner-only local file. Only the path crosses the
# run-matrix -> run-config argv boundary.
ACTIVE_AUTHKEY_FILE=""
matrix_create_authkey_file() {
  local value="$1"
  umask 077
  ACTIVE_AUTHKEY_FILE=$(mktemp "${TMPDIR:-/tmp}/rustscale-bench-authkey.XXXXXX") || return 1
  printf '%s\n' "$value" >"$ACTIVE_AUTHKEY_FILE"
  chmod 600 "$ACTIVE_AUTHKEY_FILE"
}
matrix_remove_authkey_file() {
  [[ -z "$ACTIVE_AUTHKEY_FILE" ]] || rm -f "$ACTIVE_AUTHKEY_FILE"
  ACTIVE_AUTHKEY_FILE=""
}
matrix_authkey_file_self_test() {
  local directory mode args secret=tskey-fixture-sentinel
  directory=$(mktemp -d) || return 1
  TMPDIR="$directory" matrix_create_authkey_file "$secret" || return 1
  mode=$(portable_file_mode "$ACTIVE_AUTHKEY_FILE") || return 1
  [[ "$mode" == 600 && "$(cat "$ACTIVE_AUTHKEY_FILE")" == "$secret" ]] || return 1
  REPEAT=3; PARALLELISM_CSV=1,10,100,500,1000; DURATION=10; PEER_COUNT=1
  MATRIX_MANIFEST_PATH=/dev/null; MATRIX_OBSERVED_PATH=/dev/null
  matrix_build_run_config_args rs-userspace s c sz cz "$ACTIVE_AUTHKEY_FILE" out srv cli
  args="${RUN_CONFIG_ARGS[*]}"
  [[ "$args" == *"$ACTIVE_AUTHKEY_FILE"* && "$args" != *"$secret"* ]] || return 1
  matrix_remove_authkey_file
  [[ ! -e "$directory"/rustscale-bench-authkey.* ]] || return 1
  rmdir "$directory"
}

matrix_config_failure_policy_self_test() {
  local output status

  matrix_test_success() { return 0; }
  matrix_test_ordinary_failure() { return 1; }
  matrix_test_fatal_handoff() { return "$FATAL_HANDOFF_STATUS"; }
  matrix_test_config_flow() {
    local config="$1"
    matrix_run_config_with_policy "$config" "" "${@:2}"
    echo "sentinel: $config"
  }

  output=$(matrix_test_config_flow success matrix_test_success 2>&1) || return 1
  [[ "$output" == $'[gcp] success: OK\nsentinel: success' ]] || return 1

  output=$(matrix_test_config_flow ordinary matrix_test_ordinary_failure 2>&1) || return 1
  [[ "$output" == $'[gcp] ordinary: FAILED (continuing)\nsentinel: ordinary' ]] || return 1

  if output=$(matrix_test_config_flow fatal matrix_test_fatal_handoff 2>&1); then
    return 1
  else
    status=$?
  fi
  (( status == FATAL_HANDOFF_STATUS )) || return 1
  [[ "$output" == '[gcp] FATAL: fatal left an unsafe TUN handoff; aborting matrix' ]] || return 1
  unset -f matrix_test_success matrix_test_ordinary_failure \
    matrix_test_fatal_handoff matrix_test_config_flow
}

matrix_profile_self_test() {
  local config
  local -a calls=()
  REPEAT=4
  PARALLELISM_CSV="1,10,100,500,1000"
  DURATION=10
  PEER_COUNT=1
  PROFILE=1
  matrix_test_record_run_config() { calls+=("$1|${*:4}"); }
  matrix_test_record_profile() { calls+=("profile|$*"); }

  # The profile diagnostic must be distinct from, and follow, all normal
  # selected cells. Its profile-only option preserves the accepted rs-tun JSON.
  for config in rs-tun ts-tun; do
    matrix_run_config_cell "$config" s c sz cz /tmp/authkey-file dir host client matrix_test_record_run_config
  done
  matrix_run_profile_diagnostic s c sz cz /tmp/profile-authkey-file dir host client matrix_test_record_profile
  unset -f matrix_test_record_run_config matrix_test_record_profile

  [[ ${#calls[@]} -eq 3 ]] || return 1
  [[ "${calls[0]}" == 'rs-tun|rs-tun s c sz cz /tmp/authkey-file dir host client --repeat 4 --parallelism 1,10,100,500,1000 --duration 10 --peer-count 1 --manifest /dev/null --observed /dev/null' ]] || return 1
  [[ "${calls[1]}" == 'ts-tun|ts-tun s c sz cz /tmp/authkey-file dir host client --repeat 4 --parallelism 1,10,100,500,1000 --duration 10 --peer-count 1 --manifest /dev/null --observed /dev/null' ]] || return 1
  [[ "${calls[2]}" == 'profile|rs-tun s c sz cz /tmp/profile-authkey-file dir host client --repeat 4 --parallelism 1,10,100,500,1000 --duration 10 --peer-count 1 --profile-only --manifest /dev/null --observed /dev/null' ]] || return 1
}

# Build the directly invocable run-config command shape used by each cell.
# Args: CONFIG SERVER_VM CLIENT_VM SERVER_ZONE CLIENT_ZONE AUTHKEY_FILE RESULTS_DIR
#       SERVER_HOSTNAME CLIENT_HOSTNAME
matrix_build_run_config_args() {
  local config="$1"
  RUN_CONFIG_ARGS=(
    "$config" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" --repeat "$REPEAT" \
    --parallelism "$PARALLELISM_CSV" --duration "$DURATION" --peer-count "$PEER_COUNT" \
    --manifest "$MATRIX_MANIFEST_PATH" --observed "$MATRIX_OBSERVED_PATH"
  )
}

# Run one already-selected matrix cell. Keeping this invocation shape in a
# helper lets the local self-test exercise the same loop without GCP access.
matrix_run_config_cell() {
  local config="$1" server_vm="$2" client_vm="$3" server_zone="$4" client_zone="$5"
  local authkey_file="$6" results_dir="$7" server_hostname="$8" client_hostname="$9"
  local policy_fn="${10:-matrix_run_config_with_policy}"

  matrix_build_run_config_args "$config" "$server_vm" "$client_vm" "$server_zone" "$client_zone" \
    "$authkey_file" "$results_dir" "$server_hostname" "$client_hostname"
  "$policy_fn" "$config" " -> $results_dir/$config.json" \
    tools/bench/gcp/run-config.sh "${RUN_CONFIG_ARGS[@]}"
}

# Run the one post-measurement rs-tun profile diagnostic. Unlike ordinary
# cells, a failure here returns to the caller so a requested profile is never
# silently treated as a successful matrix run.
matrix_run_profile_diagnostic() {
  local server_vm="$1" client_vm="$2" server_zone="$3" client_zone="$4"
  local authkey_file="$5" results_dir="$6" server_hostname="$7" client_hostname="$8"
  local runner="${9:-tools/bench/gcp/run-config.sh}"
  "$runner" rs-tun "$server_vm" "$client_vm" "$server_zone" "$client_zone" \
    "$authkey_file" "$results_dir" "$server_hostname" "$client_hostname" \
    --repeat "$REPEAT" --parallelism "$PARALLELISM_CSV" --duration "$DURATION" --peer-count "$PEER_COUNT" \
    --profile-only --manifest "$MATRIX_MANIFEST_PATH" --observed "$MATRIX_OBSERVED_PATH"
}

# Parse command-line options without contacting GCP.  Keeping this separate
# makes the strict option contract directly self-testable.
matrix_parse_args() {
  DRY_RUN=0
  PROFILE=0
  REPEAT=3
  PARALLELISM_CSV="1,10,100,500,1000"
  DURATION=10
  PEER_COUNT=1
  SCALE_STREAMS=0
  LOAD_PRESET="routine-v1"
  SHOW_HELP=0
  TOPOLOGY_FILTER=""
  PATH_FILTER=""
  CONFIG_FILTER=""
  FULL=0
  local seen_dry_run=0 seen_profile=0 seen_repeat=0 seen_parallelism=0 seen_duration=0 seen_peer_count=0 seen_scale=0 seen_full=0
  local seen_topology=0 seen_path=0 seen_config=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --full)
        (( seen_full == 0 )) || { echo "duplicate option: --full" >&2; return 2; }
        FULL=1; seen_full=1; shift ;;
      --topology)
        (( seen_topology == 0 )) || { echo "duplicate option: --topology" >&2; return 2; }
        [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || { echo "--topology requires a value" >&2; return 2; }
        TOPOLOGY_FILTER="$2"; seen_topology=1; shift 2 ;;
      --topology=*)
        (( seen_topology == 0 )) || { echo "duplicate option: --topology" >&2; return 2; }
        TOPOLOGY_FILTER="${1#*=}"
        [[ -n "$TOPOLOGY_FILTER" ]] || { echo "--topology requires a value" >&2; return 2; }
        seen_topology=1; shift ;;
      --path)
        (( seen_path == 0 )) || { echo "duplicate option: --path" >&2; return 2; }
        [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || { echo "--path requires a value" >&2; return 2; }
        PATH_FILTER="$2"; seen_path=1; shift 2 ;;
      --path=*)
        (( seen_path == 0 )) || { echo "duplicate option: --path" >&2; return 2; }
        PATH_FILTER="${1#*=}"
        [[ -n "$PATH_FILTER" ]] || { echo "--path requires a value" >&2; return 2; }
        seen_path=1; shift ;;
      --config)
        (( seen_config == 0 )) || { echo "duplicate option: --config" >&2; return 2; }
        [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || { echo "--config requires a value" >&2; return 2; }
        CONFIG_FILTER="$2"; seen_config=1; shift 2 ;;
      --config=*)
        (( seen_config == 0 )) || { echo "duplicate option: --config" >&2; return 2; }
        CONFIG_FILTER="${1#*=}"
        [[ -n "$CONFIG_FILTER" ]] || { echo "--config requires a value" >&2; return 2; }
        seen_config=1; shift ;;
      --repeat)
        (( seen_repeat == 0 )) || { echo "duplicate option: --repeat" >&2; return 2; }
        [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || { echo "--repeat requires a value" >&2; return 2; }
        [[ "$2" =~ ^[3-9]$ ]] || { echo "--repeat must be an integer in 3..=9" >&2; return 2; }
        REPEAT="$2"; seen_repeat=1; shift 2 ;;
      --parallelism)
        (( seen_parallelism == 0 && seen_scale == 0 )) || { echo "--parallelism conflicts with a duplicate or --scale-streams" >&2; return 2; }
        [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || { echo "--parallelism requires a value" >&2; return 2; }
        validate_matrix_parallelism_csv "$2" || return 2
        PARALLELISM_CSV="$2"; LOAD_PRESET=custom; seen_parallelism=1; shift 2 ;;
      --scale-streams)
        (( seen_scale == 0 && seen_parallelism == 0 )) || { echo "--scale-streams conflicts with a duplicate or --parallelism" >&2; return 2; }
        PARALLELISM_CSV="1,10,100,500,1000"; LOAD_PRESET=routine-v1; SCALE_STREAMS=1; seen_scale=1; shift ;;
      --duration)
        (( seen_duration == 0 )) || { echo "duplicate option: --duration" >&2; return 2; }
        [[ $# -ge 2 && "$2" =~ ^[0-9]+$ && "$2" -ge 3 && "$2" -le 120 ]] || { echo "--duration must be an integer in 3..=120" >&2; return 2; }
        DURATION="$2"; seen_duration=1; shift 2 ;;
      --peer-count)
        (( seen_peer_count == 0 )) || { echo "duplicate option: --peer-count" >&2; return 2; }
        [[ $# -ge 2 && "$2" =~ ^[0-9]+$ && "$2" -ge 1 && "$2" -le 1000 ]] || { echo "--peer-count must be an integer in 1..=1000" >&2; return 2; }
        PEER_COUNT="$2"; seen_peer_count=1; shift 2 ;;
      --profile)
        (( seen_profile == 0 )) || { echo "duplicate option: --profile" >&2; return 2; }
        PROFILE=1; seen_profile=1; shift ;;
      --dry-run|-n)
        (( seen_dry_run == 0 )) || { echo "duplicate option: $1" >&2; return 2; }
        DRY_RUN=1; seen_dry_run=1; shift ;;
      -h|--help)
        # Preserve the long-standing behavior: help wins wherever it occurs
        # and never reaches the GCP setup path.
        SHOW_HELP=1; return 0 ;;
      *) echo "unknown arg: $1" >&2; return 2 ;;
    esac
  done
}

validate_matrix_parallelism_csv() {
  local csv="$1" item seen=","
  [[ -n "$csv" && "$csv" != *, && "$csv" != ,* && "$csv" != *,,* ]] || { echo "invalid --parallelism list" >&2; return 1; }
  local -a values
  IFS=, read -r -a values <<<"$csv"
  for item in "${values[@]}"; do
    [[ "$item" =~ ^[1-9][0-9]*$ && "$item" -le 1000 ]] || { echo "--parallelism values must be integers in 1..=1000" >&2; return 1; }
    [[ "$seen" != *",$item,"* ]] || { echo "duplicate --parallelism value: $item" >&2; return 1; }
    seen+="$item,"
  done
  [[ "$csv" == "1,10,100,500,1000" ]] || { echo "--parallelism must be exactly 1,10,100,500,1000" >&2; return 1; }
}

matrix_option_parsing_self_test() {
  local actual status
  actual=$(matrix_parse_args; printf '%s/%s/%s/%s/%s/%s/%s\n' "$REPEAT" "$PROFILE" "$DRY_RUN" "$FULL" "$TOPOLOGY_FILTER" "$PATH_FILTER" "$CONFIG_FILTER") || return 1
  [[ "$actual" == '3/0/0/0///' ]] || return 1
  actual=$(matrix_parse_args --full --repeat 3 --profile --topology same-zone --path direct --config rs-tun,ts-tun; printf '%s/%s/%s/%s/%s/%s/%s\n' "$REPEAT" "$PROFILE" "$DRY_RUN" "$FULL" "$TOPOLOGY_FILTER" "$PATH_FILTER" "$CONFIG_FILTER") || return 1
  [[ "$actual" == '3/1/0/1/same-zone/direct/rs-tun,ts-tun' ]] || return 1
  actual=$(matrix_parse_args --dry-run --help --not-an-error; printf '%s/%s/%s\n' "$DRY_RUN" "$SHOW_HELP" "$REPEAT") || return 1
  [[ "$actual" == '1/1/3' ]] || return 1
  actual=$(matrix_parse_args --parallelism 1,10,100,500,1000 --duration 20 --peer-count 250; printf '%s/%s/%s\n' "$PARALLELISM_CSV" "$DURATION" "$PEER_COUNT") || return 1
  [[ "$actual" == '1,10,100,500,1000/20/250' ]] || return 1
  actual=$(matrix_parse_args --scale-streams; printf '%s' "$PARALLELISM_CSV") || return 1
  [[ "$actual" == '1,10,100,500,1000' ]] || return 1
  local -a case_args=()
  for args in '--repeat' '--repeat 0' '--repeat 10' '--repeat 1.5' '--repeat 1 --repeat 2' '--profile --profile' '--full --full' '--parallelism 1,1' '--parallelism 0' '--parallelism 1001' '--parallelism 1 --parallelism 2' '--scale-streams --scale-streams' '--scale-streams --parallelism 1' '--duration 2' '--duration 121' '--peer-count 0' '--peer-count 1001'; do
    read -r -a case_args <<< "$args"
    if ( matrix_parse_args "${case_args[@]}" ) >/dev/null 2>&1; then
      return 1
    else
      status=$?
      (( status == 2 )) || return 1
    fi
  done
}

matrix_launch_worktree_dirty() {
  [[ -n "$(git status --porcelain=v1 --untracked-files=all)" ]]
}

matrix_dirty_detection_self_test() {
  local kind
  for kind in tracked staged untracked; do
    if ! (
      git() { printf '%s\n' "$kind-change"; }
      matrix_launch_worktree_dirty
    ); then return 1; fi
  done
  if (
    git() { :; }
    matrix_launch_worktree_dirty
  ); then return 1; fi
  # The immutable source assertion is enforced by the structured validator,
  # independent of which category made the launch worktree dirty.
  python3 - <<'PYEOF'
import sys
sys.path.insert(0, "tools/bench/gcp")
import provenance
run = {"id":"gcp-20260714-000000-dirtytest", "started_at_utc":"2026-07-14T00:00:00Z",
       "source":{"commit":"a"*40,"delivery":"git-archive-head","includes_uncommitted_changes":False,"launch_worktree_dirty":True},
       "cloud":{"provider":"gcp","project":"dry-run","requested_image_project":"ubuntu-os-cloud","requested_image_family":"ubuntu-2204-lts","requested_machine_type":"n1-standard-4","network":"default","disk_type":"pd-standard","disk_gb":200},
       "build":{"command":"","rustflags":"","cargo_profile_release_lto":"","cargo_profile_release_codegen_units":""},
       "runtime":{"rs_tun_inbound_pipeline":False,"rs_tun_outbound_send_pipeline":False,"linux_udp_batch":True,"linux_udp_gro":True,"linux_udp_gso":True}}
provenance.validate_run(run)
PYEOF
}

# GCE names must be unique for each immutable run, even when two runs begin in
# the same second.  Keep the run suffix at the end if a future run-id format
# grows, because it contains the uniqueness component.
matrix_vm_name() {
  local run_id="$1" topology="$2" role="$3" run_component prefix max
  case "$topology/$role" in
    same-zone/srv|same-zone/cli|cross-region/srv|cross-region/cli) ;;
    *) return 1 ;;
  esac
  run_component="${run_id#gcp-}"
  [[ "$run_component" != "$run_id" && "$run_component" =~ ^[a-z0-9_-]+$ ]] || return 1
  run_component="${run_component//_/-}"
  prefix="rs-bench-${topology}-${role}-"
  max=$((63 - ${#prefix}))
  (( max > 0 )) || return 1
  if (( ${#run_component} > max )); then
    run_component="${run_component: -max}"
  fi
  printf '%s%s\n' "$prefix" "$run_component"
}

matrix_vm_name_self_test() {
  local one two long
  one=$(matrix_vm_name gcp-20260714-010203-aaaaaaaaaa same-zone srv) || return 1
  two=$(matrix_vm_name gcp-20260714-010203-bbbbbbbbbb same-zone srv) || return 1
  [[ "$one" != "$two" && ${#one} -le 63 && ${#two} -le 63 ]] || return 1
  [[ "$one" =~ ^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || return 1
  [[ "$two" =~ ^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || return 1
  long=$(matrix_vm_name "gcp-$(printf 'a%.0s' {1..80})" cross-region cli) || return 1
  [[ ${#long} -le 63 && "$long" =~ ^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || return 1
}

# Every product identity is interrogated through the exact binary that the
# harness invokes. Native --version probes avoid package-metadata aliases.
matrix_remote_observation_program() {
  cat <<'PYEOF'
python3 - <<'PY'
import hashlib, json, os, platform, shutil, subprocess
toolchain_env = {**os.environ, "RUSTUP_HOME": "/opt/rust", "CARGO_HOME": "/opt/rust/cargo"}
def output(argv, env=None):
    return subprocess.check_output(argv, text=True, stderr=subprocess.STDOUT, timeout=15, env=env).strip()
products=[]
def utility(name, version_args):
    path = shutil.which(name)
    if not path:
        return None
    try: version = output([path, *version_args])
    except Exception: version = "version probe failed"
    return {"path": path, "version": version, "sha256": hashlib.sha256(open(path,"rb").read()).hexdigest()}
for name, explicit in (
    ("rustscale-bench", "/opt/rustscale/target/release/rustscale-bench"),
    ("rustscale", "/opt/rustscale/target/release/rustscale"),
    ("rustscaled", "/opt/rustscale/target/release/rustscaled"),
    ("go-tsnet-rsb1", "/opt/rustscale/bin/go-tsnet-rsb1"),
):
    if os.path.isfile(explicit):
        products.append({"path": explicit, "version": output(["timeout", "15", explicit, "--version"]), "version_source": "executable --version", "sha256": hashlib.sha256(open(explicit,"rb").read()).hexdigest()})
for name, explicit in (("tailscaled","/usr/sbin/tailscaled"),("tailscale","/usr/bin/tailscale")):
    if os.path.isfile(explicit):
        products.append({"path": explicit, "version": output(["timeout", "15", explicit, "--version"]), "version_source": "executable --version", "sha256": hashlib.sha256(open(explicit,"rb").read()).hexdigest()})
os_name=""
for line in open("/etc/os-release", encoding="utf-8"):
    if line.startswith("PRETTY_NAME="): os_name=line.split("=",1)[1].strip().strip('"'); break
cpu=output(["lscpu", "-J"])
try: cpu_model=next(x["data"] for x in json.loads(cpu)["lscpu"] if x["field"].strip()=="Model name:")
except Exception: raise SystemExit("unable to determine CPU model")
utilities = [entry for entry in (utility("iperf3", ["--version"]), utility("socat", ["-V"]), utility("ncat", ["--version"]), utility("pidstat", ["-V"]), utility("python3", ["--version"])) if entry]
print(json.dumps({"cpu_model":cpu_model,"logical_cpus":os.cpu_count(),"kernel_release":platform.release(),"os_pretty_name":os_name,"cargo":output(["/opt/rust/cargo/bin/cargo","--version"], env=toolchain_env),"rustc_verbose":output(["/opt/rust/cargo/bin/rustc","-Vv"], env=toolchain_env),"go":output(["/usr/local/go/bin/go","version"]),"product":products,"measurement_tools":utilities}))
PY
PYEOF
}

matrix_product_observation_self_test() {
  local program
  program=$(matrix_remote_observation_program) || return 1
  [[ "$program" == *'("rustscale-bench", "/opt/rustscale/target/release/rustscale-bench")'* ]] || return 1
  [[ "$program" == *'("rustscale", "/opt/rustscale/target/release/rustscale")'* ]] || return 1
  [[ "$program" == *'("rustscaled", "/opt/rustscale/target/release/rustscaled")'* ]] || return 1
  [[ "$program" == *'("go-tsnet-rsb1", "/opt/rustscale/bin/go-tsnet-rsb1")'* ]] || return 1
  [[ "$program" == *'output(["/usr/local/go/bin/go","version"])'* ]] || return 1
  [[ "$program" == *'output(["timeout", "15", explicit, "--version"])'* ]] || return 1
  [[ "$program" == *'utility("iperf3", ["--version"])'* && "$program" == *'utility("pidstat", ["-V"])'* ]] || return 1
  # On a fresh VM /usr/local/bin/cargo is a rustup shim and the SSH user's
  # default rustup home is empty. Observation must use the provisioned
  # toolchain and preserve its homes just as the remote build does.
  [[ "$program" == *'toolchain_env = {**os.environ, "RUSTUP_HOME": "/opt/rust", "CARGO_HOME": "/opt/rust/cargo"}'* ]] || return 1
  [[ "$program" == *'output(["/opt/rust/cargo/bin/cargo","--version"], env=toolchain_env)'* ]] || return 1
  [[ "$program" == *'output(["/opt/rust/cargo/bin/rustc","-Vv"], env=toolchain_env)'* ]] || return 1
  [[ "$program" != *'output(["cargo","--version"])'* && "$program" != *'output(["rustc","-Vv"])'* ]] || return 1
  [[ "$program" != *cargo*metadata* && "$program" != *'--help'* && "$program" != *'exit 1'* ]] || return 1
  # The fast shell suite does not compile or execute benchmarks. Shared target
  # directories can hold another worktree's stale binary, so only the source
  # contract is checked here; remote production still probes delivered release
  # binaries with --version above.
  sed -n '/#\[command(/,/)]/p' crates/bench/src/main.rs | grep -Fxq '    version' || return 1
  grep -Fq 'fn metadata_version()' crates/bench/src/main.rs || return 1
  grep -Fq 'matches!(args[1].as_str(), "--version" | "-V")' crates/cli/src/main.rs || return 1
  grep -Fq 'matches!(arg.as_str(), "--version" | "-V")' crates/rustscaled/src/main.rs || return 1
  grep -Fq 'toolVersion = "tailscale.com/v1.100.0"' tools/bench/go-tsnet/main.go || return 1
  grep -Fxq 'require tailscale.com v1.100.0' tools/bench/go-tsnet/go.mod || return 1
  grep -Fxq 'tailscale.com v1.100.0 h1:nm/M/dEaW9RaRsGUjW2HsSDpsZ60Jwd9k4gNW9tTFiE=' tools/bench/go-tsnet/go.sum || return 1
}

# Atomically publish command stdout in the result directory. The command is
# invoked as argv so callers can safely pass shell functions (such as ssh_cmd)
# without eval. A subshell confines its signal cleanup trap to this capture.
matrix_atomic_capture() (
  local destination="$1" directory base temporary command_status
  shift
  directory=$(dirname "$destination")
  base=$(basename "$destination")
  mkdir -p "$directory" || exit $?
  temporary=$(mktemp "$directory/.${base}.XXXXXX") || exit $?
  trap 'rm -f "$temporary"; exit 128' HUP INT TERM
  trap 'rm -f "$temporary"' EXIT
  "$@" >"$temporary"
  command_status=$?
  if (( command_status != 0 )); then
    exit "$command_status"
  fi
  mv -f "$temporary" "$destination" || exit $?
  trap - EXIT
)

matrix_atomic_capture_self_test() {
  local temp_dir destination command_status
  temp_dir=$(mktemp -d) || return 1
  destination="$temp_dir/sidecar.json"
  printf '%s\n' old >"$destination"
  matrix_atomic_capture "$destination" printf '%s\n' new || { rm -rf "$temp_dir"; return 1; }
  [[ "$(<"$destination")" == new ]] || { rm -rf "$temp_dir"; return 1; }
  printf '%s\n' preserved >"$destination"
  if matrix_atomic_capture "$destination" bash -c 'printf "%s\\n" partial; exit 37'; then
    rm -rf "$temp_dir"; return 1
  else
    command_status=$?
  fi
  (( command_status == 37 )) || { rm -rf "$temp_dir"; return 1; }
  [[ "$(<"$destination")" == preserved ]] || { rm -rf "$temp_dir"; return 1; }
  ! compgen -G "$temp_dir/.sidecar.json.*" >/dev/null || { rm -rf "$temp_dir"; return 1; }
  rm -rf "$temp_dir"
}

# Capture the exact instance identity needed to resolve its immutable boot
# image. `disks` is repeated, so this must project `disks[].source`.
matrix_capture_instance_metadata() {
  local destination="$1" instance="$2" zone="$3"
  matrix_atomic_capture "$destination" gcloud compute instances describe "$instance" \
    --project="$GCP_PROJECT" --zone="$zone" \
    --format='json(machineType,cpuPlatform,zone,disks[].source)'
}

matrix_instance_metadata_capture_self_test() (
  local temp_dir
  local -a calls=()
  temp_dir=$(mktemp -d) || return 1
  matrix_atomic_capture() { calls+=("$*"); }
  matrix_capture_instance_metadata "$temp_dir/server.json" server us-central1-a
  matrix_capture_instance_metadata "$temp_dir/client.json" client us-central1-b
  [[ ${#calls[@]} -eq 2 ]] || { rm -rf "$temp_dir"; return 1; }
  [[ "${calls[0]}" == *'instances describe server'* && "${calls[1]}" == *'instances describe client'* ]] || { rm -rf "$temp_dir"; return 1; }
  for call in "${calls[@]}"; do
    [[ "$call" == *'--format=json(machineType,cpuPlatform,zone,disks[].source)'* && "$call" != *'disks.source'* ]] || { rm -rf "$temp_dir"; return 1; }
  done
  rm -rf "$temp_dir"
)

matrix_write_manifest() {
  local output="$1" repeat="$2" dry_run="${MATRIX_MANIFEST_DRY_RUN:-0}"
  shift 2
  local -a groups=() current=() topologies paths configs parallelism dry_flag=()
  local value
  for value in "$@"; do
    if [[ "$value" == -- ]]; then groups+=("${current[*]}"); current=(); else current+=("$value"); fi
  done
  groups+=("${current[*]}")
  [[ ${#groups[@]} -eq 4 ]] || return 1
  read -r -a topologies <<<"${groups[0]}"; read -r -a paths <<<"${groups[1]}"
  read -r -a configs <<<"${groups[2]}"; read -r -a parallelism <<<"${groups[3]}"
  [[ "$repeat" =~ ^[1-9][0-9]*$ ]] || return 1
  for value in "${parallelism[@]}"; do [[ "$value" =~ ^[1-9][0-9]*$ ]] || return 1; done
  local selected_load_preset="$LOAD_PRESET"
  [[ "$selected_load_preset" != routine-v1 || "${parallelism[*]}" == "1 10 100 500 1000" ]] || selected_load_preset=custom
  [[ "$selected_load_preset" != scale-streams-v1 || "${parallelism[*]}" == "1 2 4 8 16 32 64 100 200 500 1000" ]] || selected_load_preset=custom
  [[ "$dry_run" == 1 ]] && dry_flag=(--dry-run)
  python3 tools/bench/gcp/provenance.py manifest "$output" \
    --run-id "$MATRIX_RUN_ID" --started-at-utc "$MATRIX_STARTED_AT_UTC" --commit "$MATRIX_SOURCE_COMMIT" \
    --dirty "$MATRIX_WORKTREE_DIRTY" --project "$MATRIX_PROJECT" --image-project "$GCP_IMAGE_PROJECT" \
    --image-family "$GCP_IMAGE" --machine "$GCP_MACHINE" --network "$GCP_NETWORK" --disk-type pd-standard \
    --disk-gb "$GCP_DISK_GB" --build-command "${RUST_BUILD_COMMAND:-}" --go-build-command "${GO_BUILD_COMMAND:-}" --rustflags "${RUSTFLAGS:-}" \
    --lto "${CARGO_PROFILE_RELEASE_LTO:-}" --codegen-units "${CARGO_PROFILE_RELEASE_CODEGEN_UNITS:-}" \
    --rs-tun-inbound-pipeline "$RS_TUN_INBOUND_PIPELINE" --rs-tun-outbound-send-pipeline "$RS_TUN_OUTBOUND_SEND_PIPELINE" \
    --linux-udp-batch "$RS_LINUX_UDP_BATCH" --linux-udp-gro "$RS_LINUX_UDP_GRO" --linux-udp-gso "$RS_LINUX_UDP_GSO" \
    "${dry_flag[@]}" --topologies "${topologies[@]}" --paths "${paths[@]}" \
    --configs "${configs[@]}" --parallelism "${parallelism[@]}" --repeat "$repeat" \
    --duration "$DURATION" --peer-count "$PEER_COUNT" --matrix-preset "$MATRIX_PRESET" \
    --load-preset "$selected_load_preset" --topology-source "$TOPOLOGY_SOURCE" \
    --path-source "$PATH_SOURCE" --config-source "$CONFIG_SOURCE"
}

# Render into a sibling temporary file and publish only a complete document.
# This preserves a prior dashboard if the renderer itself fails or is killed.
matrix_render_dashboard() {
  local summary="$1" dashboard="$2" renderer="${3:-tools/bench/gcp/render-html.py}"
  local dashboard_tmp
  dashboard_tmp=$(mktemp "$(dirname "$dashboard")/.dashboard.html.XXXXXX") || return 1
  if python3 "$renderer" "$summary" >"$dashboard_tmp"; then
    mv "$dashboard_tmp" "$dashboard"
  else
    rm -f "$dashboard_tmp"
    return 1
  fi
}

# Finalization has two deliberately distinct contracts. Production is strict:
# any failed/null cell fails before a dashboard is published. Dry-run cells are
# intentionally failed/null stubs, so they are aggregated with --allow-partial,
# rendered as DRY-RUN/PARTIAL, and return success with ##STATUS:DRY_RUN.
matrix_finalize_results() {
  local results_dir="$1" dry_run="$2" renderer="${3:-tools/bench/gcp/render-html.py}"
  local summary="$results_dir/summary.json" dashboard="$results_dir/dashboard.html"
  local summary_tmp aggregate_status
  local -a aggregate_args=()
  (( dry_run )) && aggregate_args+=(--allow-partial)

  echo "[gcp] aggregating results -> $summary"
  summary_tmp=$(mktemp "$results_dir/.summary.json.XXXXXX") || {
    echo "##STATUS:FAILED"
    return 1
  }
  if python3 tools/bench/gcp/aggregate.py "${aggregate_args[@]}" "$results_dir" >"$summary_tmp"; then
    :
  else
    aggregate_status=$?
    rm -f "$summary_tmp"
    echo "##STATUS:FAILED"
    echo "[gcp] result validation failed; dashboard is intentionally not marked complete" >&2
    return "$aggregate_status"
  fi

  echo "[gcp] rendering dashboard -> $dashboard"
  if ! matrix_render_dashboard "$summary_tmp" "$dashboard" "$renderer"; then
    rm -f "$summary_tmp"
    echo "##STATUS:FAILED"
    echo "[gcp] dashboard rendering failed; preserved any prior dashboard" >&2
    return 1
  fi
  mv "$summary_tmp" "$summary"

  # A collection failure must not change the completed run's contract; it only
  # affects the convenience cross-run index.
  if [[ "${MATRIX_SKIP_COLLECT:-0}" != 1 ]]; then
    tools/bench/gcp/collect.sh "$(dirname "$results_dir")" >/dev/null || true
  fi

  echo ""
  if (( dry_run )); then
    echo "═══ GCP bench dry-run finalized — PARTIAL ═══"
    echo "##STATUS:DRY_RUN"
  else
    echo "═══ GCP bench complete ═══"
    echo "##STATUS:OK"
  fi
  echo "  results:  $results_dir"
  echo "  summary:  $summary"
  echo "  dashboard: $dashboard"
  echo "  index:    $(dirname "$results_dir")/gcp-index.html"
}

matrix_finalization_self_test() {
  local temp_dir dry_dir prod_dir output status saved_project="$MATRIX_PROJECT"
  temp_dir=$(mktemp -d)
  dry_dir="$temp_dir/gcp-20260714-000000-dry"; prod_dir="$temp_dir/gcp-20260714-000000-prod"
  mkdir -p "$dry_dir/same-zone/direct" "$prod_dir/same-zone/direct"
  MATRIX_RUN_ID=$(basename "$dry_dir")
  MATRIX_MANIFEST_DRY_RUN=1 matrix_write_manifest "$dry_dir/matrix.json" 1 same-zone -- direct -- rs-tun -- 1
  MATRIX_RUN_ID=$(basename "$prod_dir")
  MATRIX_PROJECT=fixture-project
  MATRIX_MANIFEST_DRY_RUN=0 matrix_write_manifest "$prod_dir/matrix.json" 1 same-zone -- direct -- rs-tun -- 1
  if ! python3 - "$dry_dir" "$prod_dir" "$GCP_MACHINE" <<'PYEOF'
import hashlib
import json
import sys
from pathlib import Path

machine = sys.argv[3]
dry, prod = map(Path, sys.argv[1:3])
def endpoint(zone): return {"zone":zone,"machine_type":machine,"cpu_platform":"fixture","cpu_model":"fixture","logical_cpus":4,"kernel_release":"fixture","os_pretty_name":"fixture"}
def observed(dry_run):
    if dry_run: return {"resolved_image":"dry-run","server":"dry-run","client":"dry-run","toolchain":"dry-run","product":"dry-run"}
    products=[{"path":"/opt/rustscale/target/release/rustscale","version":"rustscale 1.0","version_source":"executable --version","sha256":"a"*64},{"path":"/opt/rustscale/target/release/rustscaled","version":"rustscaled 1.0","version_source":"executable --version","sha256":"b"*64},{"path":"/opt/rustscale/target/release/rustscale-bench","version":"rustscale-bench 1.0","version_source":"executable --version","sha256":"c"*64}]
    return {"resolved_image":"fixture-image","server":endpoint("us-central1-a"),"client":endpoint("us-central1-b"),"toolchain":{"server_cargo":"cargo fixture","server_rustc_verbose":"rustc fixture","client_cargo":"cargo fixture","client_rustc_verbose":"rustc fixture"},"product":{"server":products,"client":products}}
def result(root, status):
    manifest=json.loads((root/"matrix.json").read_text()); run=manifest["run"]
    obs=observed(status=="failed")
    common={"schema_version":6,"run":run,"observed":obs,"status":status,"tool":"rustscale","implementation":"rustscale","mode":"tun",
          "topology":"same-zone","path":"direct","config":"rs-tun","repeat":1,
          "parallelism_requested":[1],"duration_s_requested":10,"sample_cadence_s":1,
          "peer_count_requested":1,"error":"dry-run","log_tail":"","throughput":None,"latency":None,"footprint":None,"path_class_reported":"unknown"}
    if status=="ok":
        series={"rss_peak_kb":1,"rss_avg_kb":1,"cpu_peak_pct":0,"cpu_avg_pct":0,"samples":1,"missing_samples":0,"sample_cadence_s":1,"clock":"monotonic","series":[{"offset_ms":0,"rss_kb":1,"cpu_pct":0,"included_processes":["1:rustscaled","2:rustscale-bench"],"status":"observed"}],"series_truncated":False}
        scope={"kind":"dynamic_process_set","includes_descendants":False,"includes_kernel":False}
        samples=list(range(1,201))
        common.update({"error":"","transport":"kernel-tcp","throughput":[{"parallel":1,"mbps":1.0,"duration_s":10,"samples_mbps":[1.0],"statistic":"median","min_mbps":1.0,"max_mbps":1.0,"population_stddev_mbps":0.0,"coefficient_of_variation_pct":0.0}],
          "warmup_evidence":{"transport":"kernel-tcp","protocol":"RSB1","direction":"down","duration_secs":3,"parallel":1,"established":1,"handshaken":1,"completed":1,"total_mbps":1.0,"path_class":"externally-gated"},
          "throughput_trials":[{"parallel":1,"repeat_index":1,"transport":"kernel-tcp","protocol":"RSB1","direction":"down","duration_s":10,"established":1,"handshaken":1,"completed":1,"total_mbps":1.0,"path_class":"externally-gated"}],
          "latency":{"protocol":"RSB1-tcp-pingpong","requested":200,"successful":200,"timed_out":0,"malformed":0,"count":200,"min_ns":1,"mean_ns":100.5,"p50_ns":101,"p95_ns":190,"p99_ns":198,"max_ns":200,"min_us":0.001,"mean_us":0.1005,"p50_us":0.101,"p95_us":0.19,"p99_us":0.198,"max_us":0.2,"samples_ns":samples},
          "footprint":dict(series,binary_size_bytes=1,subject="rustscaled",scope=scope),
          "workload":{"implementation":"rustscale-bench","protocol":"RSB1","direction":"down","payload_bytes":1280,"warmup":{"parallel":1,"duration_s":3,"max_attempts":1},"client_lifecycle":"new_benchmark_process_per_trial","transport_identity_lifecycle":"one_persisted_identity_per_endpoint_cell","measured_trial_attempts":1,"latency_protocol":"RSB1-tcp-pingpong","latency_payload_bytes":8,"latency_count":200,"transport_path":"kernel-tcp-via-rustscaled-tun","userspace_portmapping":"not-applicable"},
          "resources":{"phase_set":["measured_client_process_lifecycle","inter_trial_gap","latency"],"sample_cadence_ms":1000,"server":dict(series,endpoint="server",subjects=["rustscaled","rustscale-bench"],scope=scope,binary_identities=[obs["product"]["server"][1],obs["product"]["server"][2]]),"client":dict(series,endpoint="client",subjects=["rustscaled","rustscale-bench"],scope=scope,binary_identities=[obs["product"]["client"][1],obs["product"]["client"][2]])},
          "binary":dict(obs["product"]["server"][1],subject="rustscaled",size_bytes=1),
          "path_class_reported":"direct","path_gate":{"requested":"direct","pre":"direct","post":"direct","matched":True},"cleanup":{"status":"clean","samplers_stopped":True,"workload_stopped":True,"transport_stopped":True,"postconditions_verified":True},
          "identity":{"key":"same-zone/direct/rs-tun","cell_id":"rs-tun","implementation":"rustscale","mode":"tun","topology":"same-zone","path":"direct"},
          "load":{"preset":manifest["load"]["preset"],"parallelism_requested":[1],"repeat":1,"duration_s":10,"peer_load":manifest["load"]["peer_load"]},
          "manifest_sha256":hashlib.sha256((root/"matrix.json").read_bytes()).hexdigest()})
    return common
(dry/"same-zone/direct/rs-tun.json").write_text(json.dumps(result(dry,"failed")))
(prod/"same-zone/direct/rs-tun.json").write_text(json.dumps(result(prod,"ok")))
PYEOF
  then rm -rf "$temp_dir"; return 1; fi

  MATRIX_SKIP_COLLECT=1 output=$(matrix_finalize_results "$dry_dir" 1 2>&1) || { rm -rf "$temp_dir"; return 1; }
  [[ "$output" == *'##STATUS:DRY_RUN'* && "$output" != *'##STATUS:OK'* && "$output" != *'complete'* ]] || { rm -rf "$temp_dir"; return 1; }
  grep -q 'DRY-RUN — PARTIAL' "$dry_dir/dashboard.html" || { rm -rf "$temp_dir"; return 1; }
  grep -q 'DRY-RUN' "$dry_dir/dashboard.html" || { rm -rf "$temp_dir"; return 1; }

  # Production success has its own explicit status, unlike dry-run success.
  MATRIX_SKIP_COLLECT=1 output=$(matrix_finalize_results "$prod_dir" 0 2>&1) || { rm -rf "$temp_dir"; return 1; }
  [[ "$output" == *'##STATUS:OK'* && "$output" != *'##STATUS:DRY_RUN'* ]] || { rm -rf "$temp_dir"; return 1; }

  printf '%s\n' 'import sys; sys.exit(7)' >"$temp_dir/bad-renderer.py"
  printf '%s' 'prior dashboard' >"$prod_dir/dashboard.html"
  if MATRIX_SKIP_COLLECT=1 output=$(matrix_finalize_results "$prod_dir" 0 "$temp_dir/bad-renderer.py" 2>&1); then
    rm -rf "$temp_dir"; return 1
  else
    status=$?
  fi
  (( status != 0 )) && [[ "$output" == *'##STATUS:FAILED'* ]] || { rm -rf "$temp_dir"; return 1; }
  [[ "$(<"$prod_dir/dashboard.html")" == 'prior dashboard' ]] || { rm -rf "$temp_dir"; return 1; }
  ! compgen -G "$prod_dir/.dashboard.html.*" >/dev/null || { rm -rf "$temp_dir"; return 1; }
  ! compgen -G "$prod_dir/.summary.json.*" >/dev/null || { rm -rf "$temp_dir"; return 1; }
  rm -rf "$temp_dir"; MATRIX_PROJECT="$saved_project"
}

matrix_manifest_self_test() {
  local temp_dir manifest invalid_manifest saved_project="$MATRIX_PROJECT"
  MATRIX_PROJECT=fixture-project
  temp_dir=$(mktemp -d)
  manifest="$temp_dir/matrix.json"
  invalid_manifest="$temp_dir/invalid.json"
  matrix_write_manifest "$manifest" 3 same-zone -- direct -- rs-tun -- 1 10 100 500 1000 || { rm -rf "$temp_dir"; return 1; }
  python3 tools/bench/gcp/provenance.py validate --manifest "$manifest" || { rm -rf "$temp_dir"; return 1; }
  python3 - "$manifest" "$GCP_MACHINE" "$RS_TUN_INBOUND_PIPELINE" "$RS_TUN_OUTBOUND_SEND_PIPELINE" "$RS_LINUX_UDP_BATCH" "$RS_LINUX_UDP_GRO" "$RS_LINUX_UDP_GSO" <<'PYEOF' || { rm -rf "$temp_dir"; return 1; }
import json, sys
data=json.load(open(sys.argv[1])); runtime=data["run"]["runtime"]; build=data["run"]["build"]; assert data["schema_version"] == 4 and data["parallelism"] == [1,10,100,500,1000] and data["load"]["preset"] == "routine-v1" and data["run"]["cloud"]["disk_gb"] == 200 and data["run"]["cloud"]["requested_machine_type"] == sys.argv[2] and build["go_toolchain"] == "go1.26.4" and build["go_toolchain_archive"] == "go1.26.4.linux-amd64.tar.gz" and build["go_toolchain_archive_sha256"] == "1153d3d50e0ac764b447adfe05c2bcf08e889d42a02e0fe0259bd47f6733ad7f" and build["go_module_version"] == "v1.100.0" and build["go_module_sum"] == "h1:nm/M/dEaW9RaRsGUjW2HsSDpsZ60Jwd9k4gNW9tTFiE=" and runtime == {"rs_tun_inbound_pipeline": sys.argv[3] == "1", "rs_tun_outbound_send_pipeline": sys.argv[4] == "1", "linux_udp_batch": sys.argv[5] == "1", "linux_udp_gro": sys.argv[6] == "1", "linux_udp_gso": sys.argv[7] == "1"}
PYEOF
  if matrix_write_manifest "$invalid_manifest" 3 same-zone -- direct -- rs-tun -- 0 >/dev/null 2>&1 || [[ -e "$invalid_manifest" ]]; then
    rm -rf "$temp_dir"; return 1
  fi
  rm -rf "$temp_dir"; MATRIX_PROJECT="$saved_project"
}

matrix_inbound_pipeline_self_test() {
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

matrix_outbound_send_pipeline_self_test() {
  local actual status
  actual=$(export RS_TUN_OUTBOUND_SEND_PIPELINE=1; configure_rs_tun_outbound_send_pipeline; printf '%s' "$RS_TUN_OUTBOUND_SEND_PIPELINE") || return 1
  [[ "$actual" == 1 ]] || return 1
  actual=$(unset RS_TUN_OUTBOUND_SEND_PIPELINE; configure_rs_tun_outbound_send_pipeline; printf '%s' "$RS_TUN_OUTBOUND_SEND_PIPELINE") || return 1
  [[ "$actual" == 0 ]] || return 1
  if ( export RS_TUN_OUTBOUND_SEND_PIPELINE=invalid; configure_rs_tun_outbound_send_pipeline ) >/dev/null 2>&1; then return 1; else status=$?; fi
  (( status == 2 ))
}

matrix_linux_udp_receive_modes_self_test() {
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

matrix_linux_udp_tx_gso_mode_self_test() {
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

configure_rs_tun_inbound_pipeline || exit $?
configure_rs_tun_outbound_send_pipeline || exit $?
configure_linux_udp_receive_modes || exit $?
configure_linux_udp_tx_gso_mode || exit $?

matrix_command_shape_self_test
matrix_remote_build_aggregation_self_test
matrix_authkey_policy_self_test
matrix_authkey_file_self_test
matrix_config_failure_policy_self_test
matrix_profile_self_test
matrix_option_parsing_self_test
matrix_dirty_detection_self_test
matrix_vm_name_self_test
matrix_product_observation_self_test
matrix_atomic_capture_self_test
matrix_instance_metadata_capture_self_test
matrix_manifest_self_test
matrix_inbound_pipeline_self_test
matrix_outbound_send_pipeline_self_test
matrix_linux_udp_receive_modes_self_test
matrix_linux_udp_tx_gso_mode_self_test
matrix_zone_pair_self_test
matrix_finalization_self_test

if (( MATRIX_SELF_TEST )); then
  ssh_cmd_self_test
  gcloud_project_self_test
  package_tailscaled_cleanup_self_test
  startup_script_self_test
  echo "run-matrix self-tests: OK" >&2
  exit 0
fi

# ---------------------------------------------------------------------------
# Arg parsing.
# ---------------------------------------------------------------------------
matrix_usage() {
  cat <<EOF
usage: $0 [--dry-run] [--full] [--profile] [--repeat N] [--parallelism LIST] [--scale-streams] [--duration N] [--peer-count N] [--topology LIST] [--path LIST] [--config LIST]
Runs same-zone/direct rs-userspace,rs-tun,ts-embedded,ts-userspace,ts-tun with one matched RSB1 workload.
  --dry-run  validate args + script structure without gcloud or API calls.
  --full     expand to both topologies and both paths; all five configs remain selected.
  --topology comma-separated subset: same-zone,cross-region
  --path     comma-separated subset: direct,derp
  --config   comma-separated subset: rs-userspace,rs-tun,ts-embedded,ts-userspace,ts-tun
  --repeat N run each throughput point N times (3..=9; default 3)
  --parallelism LIST ordered unique stream counts in 1..=1000 (required 1,10,100,500,1000)
  --scale-streams compatibility alias for the required 1,10,100,500,1000 RSB1 sweep
  --duration N measured throughput seconds (3..=120; default 10)
  --peer-count N record configured remote-peer load (1..=1000; default 1)
  --profile  profile only the selected rs-tun cell after normal metrics
EOF
}
matrix_parse_args "$@" || exit $?
if (( SHOW_HELP )); then
  matrix_usage
  exit 0
fi
if [[ $DRY_RUN -eq 1 ]]; then
  export GCP_DRY_RUN=1
  echo "[dry-run] enabled — gcloud/API mutations skipped, stub JSONs emitted"
else
  # Never invoke browser/device login here. This selects only an already valid
  # active account, ADC, workload identity, or service-account credential.
  gcloud_auth_preflight || exit $?
  if [[ -z "${GCP_PROJECT:-}" || "$GCP_PROJECT" == "(unset)" ]]; then
    GCP_PROJECT=$(gcloud config get-value core/project 2>/dev/null || true)
  fi
  echo "[gcp] noninteractive auth route: $GCP_AUTH_ROUTE" >&2
fi

# ---------------------------------------------------------------------------
# Zone pairings are selected by the bounded preflight declared above.
# ---------------------------------------------------------------------------
ALL_TOPOLOGIES=(same-zone cross-region)
ALL_PATHS=(direct derp)
ALL_CONFIGS=(rs-userspace rs-tun ts-embedded ts-userspace ts-tun)
if (( FULL )); then
  TOPOLOGIES=("${ALL_TOPOLOGIES[@]}")
  PATHS=("${ALL_PATHS[@]}")
  CONFIGS=("${ALL_CONFIGS[@]}")
else
  TOPOLOGIES=(same-zone)
  PATHS=(direct)
  CONFIGS=("${ALL_CONFIGS[@]}")
fi
# This is serialized into matrix.json and must exactly match every result's
# parallelism_requested list; changing the sweep is therefore self-describing.
IFS=, read -r -a PARALLELS <<<"$PARALLELISM_CSV"
select_values() {
  local filter="$1"; shift
  local -a available=("$@") selected=() seen_items=()
  [[ -z "$filter" ]] && { SELECTED=("${available[@]}"); return; }
  local item candidate found already_selected
  IFS=, read -r -a selected <<< "$filter"
  for item in "${selected[@]}"; do
    [[ -n "$item" ]] || { echo "invalid selection: empty value" >&2; exit 2; }
    already_selected=0
    for candidate in "${seen_items[@]}"; do [[ "$item" == "$candidate" ]] && already_selected=1; done
    (( already_selected == 0 )) || { echo "duplicate selection: $item" >&2; exit 2; }
    found=0
    for candidate in "${available[@]}"; do
      if [[ "$item" == "$candidate" ]]; then
        found=1
      fi
    done
    (( found )) || { echo "invalid selection: $item" >&2; exit 2; }
    seen_items+=("$item")
  done
  SELECTED=("${selected[@]}")
}
select_values "$TOPOLOGY_FILTER" "${ALL_TOPOLOGIES[@]}"; [[ -n "$TOPOLOGY_FILTER" ]] && TOPOLOGIES=("${SELECTED[@]}")
select_values "$PATH_FILTER" "${ALL_PATHS[@]}"; [[ -n "$PATH_FILTER" ]] && PATHS=("${SELECTED[@]}")
select_values "$CONFIG_FILTER" "${ALL_CONFIGS[@]}"; [[ -n "$CONFIG_FILTER" ]] && CONFIGS=("${SELECTED[@]}")
TOPOLOGY_SOURCE=$([[ -n "$TOPOLOGY_FILTER" ]] && echo explicit || { (( FULL )) && echo full || echo default; })
PATH_SOURCE=$([[ -n "$PATH_FILTER" ]] && echo explicit || { (( FULL )) && echo full || echo default; })
CONFIG_SOURCE=$([[ -n "$CONFIG_FILTER" ]] && echo explicit || { (( FULL )) && echo full || echo default; })
if (( FULL )) && [[ -z "$TOPOLOGY_FILTER$PATH_FILTER$CONFIG_FILTER" ]]; then
  MATRIX_PRESET=full-v1
elif (( ! FULL )) && [[ -z "$TOPOLOGY_FILTER$PATH_FILTER$CONFIG_FILTER" ]]; then
  MATRIX_PRESET=normal-v1
else
  MATRIX_PRESET=custom
fi
# Every selected cell uses the byte-identical RSB1 workload and exact requested
# list. Rust cells and daemon/TUN evidence use rustscale-bench; ts-embedded uses
# the pinned Go endpoint. Capacity or lifecycle shortfalls fail the whole cell;
# the harness never caps,
# truncates, or substitutes an effective stream count.
if (( PROFILE )); then
  found=0
  for cfg in "${CONFIGS[@]}"; do [[ "$cfg" == rs-tun ]] && found=1; done
  (( found )) || { echo "--profile requires selected config rs-tun" >&2; exit 2; }
  [[ ${#TOPOLOGIES[@]} -eq 1 && ${#PATHS[@]} -eq 1 ]] || {
    echo "--profile requires exactly one selected topology and one selected path" >&2; exit 2;
  }
fi
RUST_BUILD_COMMAND=$(rust_build_command)
GO_BUILD_COMMAND=$(go_build_command)
REMOTE_BUILD_COMMAND=$(remote_build_command)
if [[ -z "$REMOTE_BUILD_COMMAND" ]]; then
  echo "[gcp] skipping source delivery and builds (no source-built configs selected)" >&2
fi

MATRIX_STARTED_AT_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
STAMP="${MATRIX_STARTED_AT_UTC:0:4}${MATRIX_STARTED_AT_UTC:5:2}${MATRIX_STARTED_AT_UTC:8:2}-${MATRIX_STARTED_AT_UTC:11:2}${MATRIX_STARTED_AT_UTC:14:2}${MATRIX_STARTED_AT_UTC:17:2}"
MATRIX_SOURCE_COMMIT="$(git rev-parse HEAD)"
if matrix_launch_worktree_dirty; then
  MATRIX_WORKTREE_DIRTY=1
  echo "[gcp] WARNING: launch worktree is dirty; git archive HEAD (not uncommitted files) will be benchmarked" >&2
else
  MATRIX_WORKTREE_DIRTY=0
fi
MATRIX_PROJECT="${GCP_PROJECT:-}"
(( DRY_RUN )) && MATRIX_PROJECT="dry-run"
[[ -n "$MATRIX_PROJECT" ]] || { echo "GCP_PROJECT is required for a real benchmark" >&2; exit 2; }
MATRIX_RUN_ID="gcp-${STAMP}-$(printf '%s' "${MATRIX_SOURCE_COMMIT}${$}${RANDOM}" | shasum -a 256 | cut -c1-10)"
RESULTS_DIR="${MATRIX_RESULTS_DIR:+$MATRIX_RESULTS_DIR/}$MATRIX_RUN_ID"
[[ -n "${MATRIX_RESULTS_DIR:-}" ]] || RESULTS_DIR="bench-results/$MATRIX_RUN_ID"
mkdir -p "$RESULTS_DIR"
MATRIX_MANIFEST_DRY_RUN="$DRY_RUN" matrix_write_manifest "$RESULTS_DIR/matrix.json" "$REPEAT" \
  "${TOPOLOGIES[@]}" -- "${PATHS[@]}" -- "${CONFIGS[@]}" -- "${PARALLELS[@]}"
MATRIX_MANIFEST_PATH="$RESULTS_DIR/matrix.json"

matrix_collect_observed() {
  local topology="$1" server="$2" server_zone="$3" client="$4" client_zone="$5"
  local metadata_dir server_instance client_instance server_endpoint client_endpoint server_disk client_disk
  metadata_dir="$RESULTS_DIR/metadata/$topology"
  server_instance="$metadata_dir/server-instance.json"; client_instance="$metadata_dir/client-instance.json"
  server_endpoint="$metadata_dir/server-endpoint.json"; client_endpoint="$metadata_dir/client-endpoint.json"
  server_disk="$metadata_dir/server-boot-disk.json"; client_disk="$metadata_dir/client-boot-disk.json"
  mkdir -p "$metadata_dir"
  if (( DRY_RUN )); then
    python3 tools/bench/gcp/provenance.py dry-observed "$metadata_dir/base-observed.json"
    return
  fi
  # Persist only the identity fields needed below, never arbitrary instance
  # metadata or service-account configuration.
  matrix_capture_instance_metadata "$server_instance" "$server" "$server_zone"
  matrix_capture_instance_metadata "$client_instance" "$client" "$client_zone"
  # Resolve the image through the boot disk created for this instance.  Do not
  # query an image family here: family resolution is intentionally racy.
  local server_disk_name client_disk_name
  server_disk_name=$(python3 - "$server_instance" <<'PYEOF'
import json, sys
d=json.load(open(sys.argv[1])); print(d["disks"][0]["source"].rsplit("/", 1)[-1])
PYEOF
)
  client_disk_name=$(python3 - "$client_instance" <<'PYEOF'
import json, sys
d=json.load(open(sys.argv[1])); print(d["disks"][0]["source"].rsplit("/", 1)[-1])
PYEOF
)
  matrix_atomic_capture "$server_disk" gcloud compute disks describe "$server_disk_name" --project="$GCP_PROJECT" --zone="$server_zone" --format='json(sourceImage)'
  matrix_atomic_capture "$client_disk" gcloud compute disks describe "$client_disk_name" --project="$GCP_PROJECT" --zone="$client_zone" --format='json(sourceImage)'
  local remote_program
  remote_program=$(matrix_remote_observation_program)
  matrix_atomic_capture "$server_endpoint" ssh_cmd "$server" "$server_zone" "$remote_program"
  matrix_atomic_capture "$client_endpoint" ssh_cmd "$client" "$client_zone" "$remote_program"
  python3 tools/bench/gcp/provenance.py observed-real "$metadata_dir/base-observed.json" --server-instance "$server_instance" --client-instance "$client_instance" --server-boot-disk "$server_disk" --client-boot-disk "$client_disk" --server-endpoint "$server_endpoint" --client-endpoint "$client_endpoint"
}

matrix_select_cell_observed() {
  local topology="$1" config="$2" server_zone="$3" client_zone="$4"
  local base="$RESULTS_DIR/metadata/$topology/base-observed.json"
  MATRIX_OBSERVED_PATH="$RESULTS_DIR/metadata/$topology/$config-observed.json"
  local -a dry_flag=()
  (( DRY_RUN )) && dry_flag=(--dry-run)
  python3 tools/bench/gcp/provenance.py select-observed "$MATRIX_OBSERVED_PATH" --input "$base" --config "$config" \
    --topology "$topology" --server-zone "$server_zone" --client-zone "$client_zone" --machine "$GCP_MACHINE" "${dry_flag[@]}"
}

# Track VMs created for cleanup. We delete each topology's pair before the
# next to keep quota usage at two VMs, including a partial capacity attempt.
CLEANUP_RAN=0

 # ---------------------------------------------------------------------------
 # Cleanup trap. Deletes VMs + tailnet. Always best-effort.
 # Set AFTER bench_provision_tailnet calls its own trap, so this overrides it.
 # ---------------------------------------------------------------------------
 gcp_bench_cleanup() {
   [[ $CLEANUP_RAN -eq 0 ]] || return 0
   CLEANUP_RAN=1
   local status=0
   matrix_remove_authkey_file || status=1
   echo "[gcp] cleanup: finalizing VMs + tailnet before result publication" >&2
   if [[ -z "${SKIP_VM_DELETE:-}" ]]; then
     if [[ -n "$ACTIVE_SRV" ]]; then delete_vm "$ACTIVE_SRV" "$ACTIVE_SRV_ZONE" || status=1; fi
     if [[ -n "$ACTIVE_CLI" ]]; then delete_vm "$ACTIVE_CLI" "$ACTIVE_CLI_ZONE" || status=1; fi
   elif [[ -n "$ACTIVE_SRV$ACTIVE_CLI" ]]; then
     echo "[gcp] cleanup: retaining requested debug VMs: $ACTIVE_SRV $ACTIVE_CLI" >&2
   fi
   bench_cleanup_tailnet || status=1
   return "$status"
 }

gcp_bench_on_signal() {
  local signal="$1"
  echo "[gcp] received $signal; exiting" >&2
  exit 1
}

# ---------------------------------------------------------------------------
# Provision tailnet (skipped in dry-run to avoid API calls).
# A FRESH authkey is minted per config invocation inside the main loop to
# avoid key expiry across the bounded matrix. Embedded clients use durable,
# non-ephemeral identities between trial processes; continuously running
# daemon cells remain ephemeral. The org-level child token / DNS / API base
# are exported so that bench_mint_authkey
# (defined in tools/bench/lib.sh) works inside run-config.sh if ever needed.
# ---------------------------------------------------------------------------
if [[ $DRY_RUN -eq 1 ]]; then
  echo "[dry-run] skipping tailnet provisioning" >&2
  :
else
  bench_provision_tailnet
  export BENCH_DNS BENCH_CHILD_TOKEN BENCH_CHILD_CID BENCH_CHILD_CSEC BENCH_API
  echo "[gcp] tailnet provisioned; authkeys will be minted per-config" >&2
fi

# Register cleanup handler AFTER bench_provision_tailnet so our trap overrides it.
# Signal handlers exit nonzero; the EXIT trap performs the cleanup exactly once.
trap 'gcp_bench_on_signal INT' INT
trap 'gcp_bench_on_signal TERM' TERM
trap gcp_bench_cleanup EXIT

# ---------------------------------------------------------------------------
# Main matrix loop.
# ---------------------------------------------------------------------------
for TOPO in "${TOPOLOGIES[@]}"; do
  SERVER_VM=$(matrix_vm_name "$MATRIX_RUN_ID" "$TOPO" srv)
  CLIENT_VM=$(matrix_vm_name "$MATRIX_RUN_ID" "$TOPO" cli)

  echo ""
  echo "[gcp] === topology: $TOPO (approved zone-pair preflight) ==="

  # Provision the first capacity-available approved pair (no-op in dry-run).
  provision_topology_pair "$TOPO" "$SERVER_VM" "$CLIENT_VM"
  echo "[gcp] === topology: $TOPO (zones $Z_A / $Z_B) ==="

  if [[ -n "$REMOTE_BUILD_COMMAND" ]]; then
    # Deliver source sequentially, then build every selected source endpoint on
    # both VMs in parallel. The Go module and toolchain are independently pinned.
    deliver_source "$SERVER_VM" "$Z_A"
    deliver_source "$CLIENT_VM" "$Z_B"
    echo "[gcp] building selected source endpoints on both VMs in parallel..." >&2
    ssh_cmd "$SERVER_VM" "$Z_A" "$REMOTE_BUILD_COMMAND" &
    SERVER_BUILD_PID=$!
    ssh_cmd "$CLIENT_VM" "$Z_B" "$REMOTE_BUILD_COMMAND" &
    CLIENT_BUILD_PID=$!
    wait_for_remote_builds "$SERVER_BUILD_PID" "$CLIENT_BUILD_PID"
  fi

  # Capture immutable environment/toolchain/product identity after startup and
  # any Rust build, before the topology's first measured cell.
  matrix_collect_observed "$TOPO" "$SERVER_VM" "$Z_A" "$CLIENT_VM" "$Z_B"

  # Path loop.
  for PATH_TAG in "${PATHS[@]}"; do
    echo ""
    echo "[gcp] --- path: $PATH_TAG ---"

    if [[ "$PATH_TAG" == "derp" ]]; then
      apply_derp_block "$SERVER_VM" "$Z_A"
      apply_derp_block "$CLIENT_VM" "$Z_B"
      # Brief settle for in-flight UDP to drain.
      sleep 5
    fi

    for CFG in "${CONFIGS[@]}"; do
      echo ""
      echo "[gcp] >>> config: $CFG (topo=$TOPO path=$PATH_TAG) <<<"
      export BENCH_MATRIX="${TOPO}/${PATH_TAG}"
      matrix_select_cell_observed "$TOPO" "$CFG" "$Z_A" "$Z_B"

      # Mint a fresh key per config. Reusing one key across a long matrix risks
      # expiry, while an ephemeral embedded identity can be reaped during the
      # intentional disconnect between measured client processes.
      if [[ $DRY_RUN -eq 1 ]]; then
        AUTHKEY_VALUE="tskey-dryrun-placeholder"
      else
        AUTHKEY_VALUE=$(bench_mint_authkey "$(matrix_authkey_ephemeral_for_config "$CFG")")
        echo "[gcp] minted fresh authkey for $CFG" >&2
      fi
      matrix_create_authkey_file "$AUTHKEY_VALUE" || exit 1
      unset AUTHKEY_VALUE

      matrix_run_config_cell "$CFG" "$SERVER_VM" "$CLIENT_VM" "$Z_A" "$Z_B" \
        "$ACTIVE_AUTHKEY_FILE" "$RESULTS_DIR/$TOPO/$PATH_TAG" "rs-srv-$TOPO" "rs-cli-$TOPO"
      matrix_remove_authkey_file
    done

    if (( PROFILE )); then
      # Keep the profile diagnostic outside the normal selected-cell loop: it
      # gets a fresh key and cannot repeat or overwrite rs-tun measurements.
      if [[ $DRY_RUN -eq 1 ]]; then
        AUTHKEY_VALUE="tskey-dryrun-placeholder"
      else
        AUTHKEY_VALUE=$(bench_mint_authkey true)
        echo "[gcp] minted fresh authkey for rs-tun profile diagnostic" >&2
      fi
      matrix_create_authkey_file "$AUTHKEY_VALUE" || exit 1
      unset AUTHKEY_VALUE
      matrix_select_cell_observed "$TOPO" rs-tun "$Z_A" "$Z_B"
      echo "[gcp] >>> profile: rs-tun (topo=$TOPO path=$PATH_TAG) <<<"
      if matrix_run_profile_diagnostic "$SERVER_VM" "$CLIENT_VM" "$Z_A" "$Z_B" \
        "$ACTIVE_AUTHKEY_FILE" "$RESULTS_DIR/$TOPO/$PATH_TAG" "rs-srv-$TOPO" "rs-cli-$TOPO"; then
        matrix_remove_authkey_file
        echo "[gcp] rs-tun profile: OK"
      else
        profile_status=$?
        matrix_remove_authkey_file
        echo "[gcp] rs-tun profile: FAILED" >&2
        exit "$profile_status"
      fi
    fi

    if [[ "$PATH_TAG" == "derp" ]]; then
      remove_derp_block "$SERVER_VM" "$Z_A"
      remove_derp_block "$CLIENT_VM" "$Z_B"
    fi
  done

  # Tear down this topology's VMs before the next (keep quota at 2).
  if [[ -z "${SKIP_VM_DELETE:-}" ]]; then
    delete_vms "$SERVER_VM" "$Z_A" "$CLIENT_VM" "$Z_B"
    ACTIVE_SRV=""
    ACTIVE_CLI=""
  fi
done

# ---------------------------------------------------------------------------
# Shared resources must be gone (or explicitly retained) before any complete
# summary/dashboard is published. The EXIT trap remains an idempotent fallback.
# ---------------------------------------------------------------------------
if ! gcp_bench_cleanup; then
  echo "[gcp] ERROR: run-level cleanup failed; refusing to publish complete results" >&2
  exit 1
fi
matrix_finalize_results "$RESULTS_DIR" "$DRY_RUN" || exit $?
ACTIVE_SRV=""
ACTIVE_CLI=""
