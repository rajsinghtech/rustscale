#!/usr/bin/env bash
# tools/bench/gcp/run-matrix.sh — main orchestrator for the GCP bench matrix.
#
# Defaults to the focused same-zone/direct rs-tun,ts-tun matrix. --full
# restores the historical 2x2x4 = 16-cell matrix on dedicated
# GCP VMs, writing per-run JSON + a combined summary.json + a standalone HTML
# dashboard into bench-results/gcp-<stamp>/.
#
# Reuses tools/bench/lib.sh for ephemeral tailnet provisioning.
#
# Usage:
#   tools/bench/gcp/run-matrix.sh            # focused run
#   tools/bench/gcp/run-matrix.sh --dry-run  # validate args, no gcloud/API
#
# Environment:
#   TS_ORG_TOKEN or TS_ORG_CLIENT_ID/SECRET  — tailnet creds (see tools/bench/lib.sh)
#   GCP_PROJECT                              — auto-detected from gcloud config
#   GCP_DRY_RUN                              — set by --dry-run; propagated to lib.sh
#   SKIP_VM_DELETE=1                         — keep VMs at the end (debugging)
#   MATRIX_RESULTS_DIR                        — parent/root for the run-ID directory override
#   RS_TUN_INBOUND_PIPELINE                   — rs-tun inbound pipeline toggle: 0 (default) or 1

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
      rs-userspace) requested=(rustscale-bench) ;;
      rs-tun) requested=(rustscale-cli rustscale-rustscaled) ;;
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

matrix_command_shape_self_test() {
  local actual
  CONFIGS=(rs-userspace)
  actual=$(rust_build_command)
  [[ "$actual" == 'export RUSTUP_HOME=/opt/rust CARGO_HOME=/opt/rust/cargo; cd /opt/rustscale && cargo build --release -p rustscale-bench' ]] || return 1
  CONFIGS=(rs-tun)
  actual=$(rust_build_command)
  [[ "$actual" == 'export RUSTUP_HOME=/opt/rust CARGO_HOME=/opt/rust/cargo; cd /opt/rustscale && cargo build --release -p rustscale-cli -p rustscale-rustscaled' ]] || return 1
  CONFIGS=(rs-userspace rs-tun)
  actual=$(rust_build_command)
  [[ "$actual" == 'export RUSTUP_HOME=/opt/rust CARGO_HOME=/opt/rust/cargo; cd /opt/rustscale && cargo build --release -p rustscale-bench -p rustscale-cli -p rustscale-rustscaled' ]] || return 1
  CONFIGS=(ts-userspace ts-tun)
  [[ -z "$(rust_build_command)" ]] || return 1
  CONFIGS=(rs-userspace rs-tun ts-userspace ts-tun)
  actual=$(rust_build_command)
  [[ "$actual" == 'export RUSTUP_HOME=/opt/rust CARGO_HOME=/opt/rust/cargo; cd /opt/rustscale && cargo build --release -p rustscale-bench -p rustscale-cli -p rustscale-rustscaled' ]] || return 1
  [[ "$actual" != *'-p rustscaled'* ]] || return 1
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
  PROFILE=1
  matrix_test_record_run_config() { calls+=("$1|${*:4}"); }
  matrix_test_record_profile() { calls+=("profile|$*"); }

  # The profile diagnostic must be distinct from, and follow, all normal
  # selected cells. Its profile-only option preserves the accepted rs-tun JSON.
  for config in rs-tun ts-tun; do
    matrix_run_config_cell "$config" s c sz cz key dir host client matrix_test_record_run_config
  done
  matrix_run_profile_diagnostic s c sz cz profile-key dir host client matrix_test_record_profile
  unset -f matrix_test_record_run_config matrix_test_record_profile

  [[ ${#calls[@]} -eq 3 ]] || return 1
  [[ "${calls[0]}" == 'rs-tun|rs-tun s c sz cz key dir host client --repeat 4 --manifest /dev/null --observed /dev/null' ]] || return 1
  [[ "${calls[1]}" == 'ts-tun|ts-tun s c sz cz key dir host client --repeat 4 --manifest /dev/null --observed /dev/null' ]] || return 1
  [[ "${calls[2]}" == 'profile|rs-tun s c sz cz profile-key dir host client --repeat 4 --profile-only --manifest /dev/null --observed /dev/null' ]] || return 1
}

# Build the directly invocable run-config command shape used by each cell.
# Args: CONFIG SERVER_VM CLIENT_VM SERVER_ZONE CLIENT_ZONE AUTHKEY RESULTS_DIR
#       SERVER_HOSTNAME CLIENT_HOSTNAME
matrix_build_run_config_args() {
  local config="$1"
  RUN_CONFIG_ARGS=(
    "$config" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" --repeat "$REPEAT" \
    --manifest "$MATRIX_MANIFEST_PATH" --observed "$MATRIX_OBSERVED_PATH"
  )
}

# Run one already-selected matrix cell. Keeping this invocation shape in a
# helper lets the local self-test exercise the same loop without GCP access.
matrix_run_config_cell() {
  local config="$1" server_vm="$2" client_vm="$3" server_zone="$4" client_zone="$5"
  local authkey="$6" results_dir="$7" server_hostname="$8" client_hostname="$9"
  local policy_fn="${10:-matrix_run_config_with_policy}"

  matrix_build_run_config_args "$config" "$server_vm" "$client_vm" "$server_zone" "$client_zone" \
    "$authkey" "$results_dir" "$server_hostname" "$client_hostname"
  "$policy_fn" "$config" " -> $results_dir/$config.json" \
    tools/bench/gcp/run-config.sh "${RUN_CONFIG_ARGS[@]}"
}

# Run the one post-measurement rs-tun profile diagnostic. Unlike ordinary
# cells, a failure here returns to the caller so a requested profile is never
# silently treated as a successful matrix run.
matrix_run_profile_diagnostic() {
  local server_vm="$1" client_vm="$2" server_zone="$3" client_zone="$4"
  local authkey="$5" results_dir="$6" server_hostname="$7" client_hostname="$8"
  local runner="${9:-tools/bench/gcp/run-config.sh}"
  "$runner" rs-tun "$server_vm" "$client_vm" "$server_zone" "$client_zone" \
    "$authkey" "$results_dir" "$server_hostname" "$client_hostname" \
    --repeat "$REPEAT" --profile-only --manifest "$MATRIX_MANIFEST_PATH" --observed "$MATRIX_OBSERVED_PATH"
}

# Parse command-line options without contacting GCP.  Keeping this separate
# makes the strict option contract directly self-testable.
matrix_parse_args() {
  DRY_RUN=0
  PROFILE=0
  REPEAT=3
  SHOW_HELP=0
  TOPOLOGY_FILTER=""
  PATH_FILTER=""
  CONFIG_FILTER=""
  FULL=0
  local seen_dry_run=0 seen_profile=0 seen_repeat=0 seen_full=0
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
        [[ "$2" =~ ^[1-9]$ ]] || { echo "--repeat must be an integer in 1..=9" >&2; return 2; }
        REPEAT="$2"; seen_repeat=1; shift 2 ;;
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

matrix_option_parsing_self_test() {
  local actual status
  actual=$(matrix_parse_args; printf '%s/%s/%s/%s/%s/%s/%s\n' "$REPEAT" "$PROFILE" "$DRY_RUN" "$FULL" "$TOPOLOGY_FILTER" "$PATH_FILTER" "$CONFIG_FILTER") || return 1
  [[ "$actual" == '3/0/0/0///' ]] || return 1
  actual=$(matrix_parse_args --full --repeat 1 --profile --topology same-zone --path direct --config rs-tun,ts-tun; printf '%s/%s/%s/%s/%s/%s/%s\n' "$REPEAT" "$PROFILE" "$DRY_RUN" "$FULL" "$TOPOLOGY_FILTER" "$PATH_FILTER" "$CONFIG_FILTER") || return 1
  [[ "$actual" == '1/1/0/1/same-zone/direct/rs-tun,ts-tun' ]] || return 1
  actual=$(matrix_parse_args --dry-run --help --not-an-error; printf '%s/%s/%s\n' "$DRY_RUN" "$SHOW_HELP" "$REPEAT") || return 1
  [[ "$actual" == '1/1/3' ]] || return 1
  local -a case_args=()
  for args in '--repeat' '--repeat 0' '--repeat 10' '--repeat 1.5' '--repeat 1 --repeat 2' '--profile --profile' '--full --full'; do
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
       "runtime":{"rs_tun_inbound_pipeline":False}}
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
import hashlib, json, os, platform, subprocess
toolchain_env = {**os.environ, "RUSTUP_HOME": "/opt/rust", "CARGO_HOME": "/opt/rust/cargo"}
def output(argv, env=None):
    return subprocess.check_output(argv, text=True, stderr=subprocess.STDOUT, timeout=15, env=env).strip()
products=[]
for name, explicit in (
    ("rustscale-bench", "/opt/rustscale/target/release/rustscale-bench"),
    ("rustscale", "/opt/rustscale/target/release/rustscale"),
    ("rustscaled", "/opt/rustscale/target/release/rustscaled"),
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
print(json.dumps({"cpu_model":cpu_model,"logical_cpus":os.cpu_count(),"kernel_release":platform.release(),"os_pretty_name":os_name,"cargo":output(["/opt/rust/cargo/bin/cargo","--version"], env=toolchain_env),"rustc_verbose":output(["/opt/rust/cargo/bin/rustc","-Vv"], env=toolchain_env),"product":products}))
PY
PYEOF
}

matrix_product_observation_self_test() {
  local program
  program=$(matrix_remote_observation_program) || return 1
  [[ "$program" == *'("rustscale-bench", "/opt/rustscale/target/release/rustscale-bench")'* ]] || return 1
  [[ "$program" == *'("rustscale", "/opt/rustscale/target/release/rustscale")'* ]] || return 1
  [[ "$program" == *'("rustscaled", "/opt/rustscale/target/release/rustscaled")'* ]] || return 1
  [[ "$program" == *'output(["timeout", "15", explicit, "--version"])'* ]] || return 1
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
  grep -Fq 'fn clap_metadata_exposes_package_version()' crates/bench/src/main.rs || return 1
  grep -Fq 'matches!(args[1].as_str(), "--version" | "-V")' crates/cli/src/main.rs || return 1
  grep -Fq 'matches!(arg.as_str(), "--version" | "-V")' crates/rustscaled/src/main.rs || return 1
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
  [[ "$dry_run" == 1 ]] && dry_flag=(--dry-run)
  python3 tools/bench/gcp/provenance.py manifest "$output" \
    --run-id "$MATRIX_RUN_ID" --started-at-utc "$MATRIX_STARTED_AT_UTC" --commit "$MATRIX_SOURCE_COMMIT" \
    --dirty "$MATRIX_WORKTREE_DIRTY" --project "$MATRIX_PROJECT" --image-project "$GCP_IMAGE_PROJECT" \
    --image-family "$GCP_IMAGE" --machine "$GCP_MACHINE" --network "$GCP_NETWORK" --disk-type pd-standard \
    --disk-gb "$GCP_DISK_GB" --build-command "${RUST_BUILD_COMMAND:-}" --rustflags "${RUSTFLAGS:-}" \
    --lto "${CARGO_PROFILE_RELEASE_LTO:-}" --codegen-units "${CARGO_PROFILE_RELEASE_CODEGEN_UNITS:-}" \
    --rs-tun-inbound-pipeline "$RS_TUN_INBOUND_PIPELINE" \
    "${dry_flag[@]}" --topologies "${topologies[@]}" --paths "${paths[@]}" \
    --configs "${configs[@]}" --parallelism "${parallelism[@]}" --repeat "$repeat"
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
  if ! python3 - "$dry_dir" "$prod_dir" <<'PYEOF'
import json
import sys
from pathlib import Path

dry, prod = map(Path, sys.argv[1:])
def endpoint(zone): return {"zone":zone,"machine_type":"n1-standard-4","cpu_platform":"fixture","cpu_model":"fixture","logical_cpus":4,"kernel_release":"fixture","os_pretty_name":"fixture"}
def observed(dry_run):
    if dry_run: return {"resolved_image":"dry-run","server":"dry-run","client":"dry-run","toolchain":"dry-run","product":"dry-run"}
    products=[{"path":"/opt/rustscale/target/release/rustscale","version":"rustscale 1.0","version_source":"executable --version","sha256":"a"*64},{"path":"/opt/rustscale/target/release/rustscaled","version":"rustscaled 1.0","version_source":"executable --version","sha256":"b"*64}]
    return {"resolved_image":"fixture-image","server":endpoint("us-central1-a"),"client":endpoint("us-central1-b"),"toolchain":{"server_cargo":"cargo fixture","server_rustc_verbose":"rustc fixture","client_cargo":"cargo fixture","client_rustc_verbose":"rustc fixture"},"product":{"server":products,"client":products}}
def result(root, status):
    run=json.loads((root/"matrix.json").read_text())["run"]
    common={"schema_version":3,"run":run,"observed":observed(status=="failed"),"status":status,"tool":"rustscale","mode":"tun",
          "topology": "same-zone", "path": "direct", "config": "rs-tun", "repeat": 1,
          "parallelism_requested": [1], "error": "dry-run", "log_tail": "",
          "throughput": None, "latency": None, "footprint": None, "path_class_reported": "unknown"}
    if status=="ok": common.update({"error":"","throughput":[{"parallel": 1, "mbps": 1.0, "duration_s": 1.0,
                      "samples_mbps": [1.0], "statistic": "median"}],
      "latency": {"requested": 50, "transmitted": 50, "received": 50, "loss": 0,
                  "p50_us": 1, "p95_us": 2, "p99_us": 3, "count": 50},
      "footprint": {"binary_size_bytes": 1, "rss_peak_kb": 1, "rss_avg_kb": 1,
                  "cpu_peak_pct": 0, "cpu_avg_pct": 0, "samples": 1},
      "path_class_reported": "direct"})
    return common
(dry / "same-zone/direct/rs-tun.json").write_text(json.dumps(result(dry,"failed")))
(prod / "same-zone/direct/rs-tun.json").write_text(json.dumps(result(prod,"ok")))
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
  matrix_write_manifest "$manifest" 3 same-zone -- direct -- rs-tun -- 1 10 100 || { rm -rf "$temp_dir"; return 1; }
  python3 tools/bench/gcp/provenance.py validate --manifest "$manifest" || { rm -rf "$temp_dir"; return 1; }
  python3 - "$manifest" "$RS_TUN_INBOUND_PIPELINE" <<'PYEOF' || { rm -rf "$temp_dir"; return 1; }
import json, sys
data=json.load(open(sys.argv[1])); assert data["schema_version"] == 2 and data["parallelism"] == [1,10,100] and data["run"]["cloud"]["disk_gb"] == 200 and data["run"]["runtime"]["rs_tun_inbound_pipeline"] is (sys.argv[2] == "1")
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

configure_rs_tun_inbound_pipeline || exit $?

matrix_command_shape_self_test
matrix_remote_build_aggregation_self_test
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
usage: $0 [--dry-run] [--full] [--profile] [--repeat N] [--topology LIST] [--path LIST] [--config LIST]
Runs the focused same-zone/direct rs-tun,ts-tun GCP bench matrix.
  --dry-run  validate args + script structure without gcloud or API calls.
  --full     restore the historical two-topology, two-path, four-config matrix.
  --topology comma-separated subset: same-zone,cross-region
  --path     comma-separated subset: direct,derp
  --config   comma-separated subset: rs-userspace,rs-tun,ts-userspace,ts-tun
  --repeat N run each production TUN throughput parallelism N times (1..=9; default 3)
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
fi

# ---------------------------------------------------------------------------
# Zone pairings.
# ---------------------------------------------------------------------------
declare -A ZONES=(
  [same-zone]="us-central1-a:us-central1-b"
  [cross-region]="us-central1-a:us-west1-a"
)
ALL_TOPOLOGIES=(same-zone cross-region)
ALL_PATHS=(direct derp)
ALL_CONFIGS=(rs-userspace rs-tun ts-userspace ts-tun)
if (( FULL )); then
  TOPOLOGIES=("${ALL_TOPOLOGIES[@]}")
  PATHS=("${ALL_PATHS[@]}")
  CONFIGS=("${ALL_CONFIGS[@]}")
else
  TOPOLOGIES=(same-zone)
  PATHS=(direct)
  CONFIGS=(rs-tun ts-tun)
fi
# This is serialized into matrix.json and must exactly match every result's
# parallelism_requested list; changing the sweep is therefore self-describing.
PARALLELS=(1 10 100)
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
if (( PROFILE )); then
  found=0
  for cfg in "${CONFIGS[@]}"; do [[ "$cfg" == rs-tun ]] && found=1; done
  (( found )) || { echo "--profile requires selected config rs-tun" >&2; exit 2; }
  [[ ${#TOPOLOGIES[@]} -eq 1 && ${#PATHS[@]} -eq 1 ]] || {
    echo "--profile requires exactly one selected topology and one selected path" >&2; exit 2;
  }
fi
RUST_BUILD_COMMAND=$(rust_build_command)
if [[ -z "$RUST_BUILD_COMMAND" ]]; then
  echo "[gcp] skipping Rust source delivery and builds (no Rust configs selected)" >&2
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

# Track VMs created for cleanup. ASSUMES one pair per topology; we delete each
# topology's VMs before starting the next to keep quota usage at 2 VMs.
ACTIVE_SRV=""
ACTIVE_SRV_ZONE=""
ACTIVE_CLI=""
ACTIVE_CLI_ZONE=""
CLEANUP_RAN=0

 # ---------------------------------------------------------------------------
 # Cleanup trap. Deletes VMs + tailnet. Always best-effort.
 # Set AFTER bench_provision_tailnet calls its own trap, so this overrides it.
 # ---------------------------------------------------------------------------
 gcp_bench_cleanup() {
   [[ $CLEANUP_RAN -eq 0 ]] || return
   CLEANUP_RAN=1
   set +e
   echo "[gcp] cleanup: deleting VMs + tailnet" >&2
   if [[ -n "$ACTIVE_SRV" ]]; then
     delete_vm "$ACTIVE_SRV" "$ACTIVE_SRV_ZONE"
   fi
   if [[ -n "$ACTIVE_CLI" ]]; then
     delete_vm "$ACTIVE_CLI" "$ACTIVE_CLI_ZONE"
   fi
   bench_cleanup_tailnet
 }

gcp_bench_on_signal() {
  local signal="$1"
  echo "[gcp] received $signal; exiting" >&2
  exit 1
}

# ---------------------------------------------------------------------------
# Provision tailnet (skipped in dry-run to avoid API calls).
# A FRESH authkey is minted per config invocation inside the main loop to
# avoid key expiry / invalidation across the ~40-min matrix run.  The
# org-level child token / DNS / API base are exported so that bench_mint_authkey
# (defined in tools/bench/lib.sh) works inside run-config.sh if ever needed.
# ---------------------------------------------------------------------------
if [[ $DRY_RUN -eq 1 ]]; then
  echo "[dry-run] skipping tailnet provisioning" >&2
  AUTHKEY="tskey-dryrun-placeholder"
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
  IFS=: read -r Z_A Z_B <<< "${ZONES[$TOPO]}"
  SERVER_VM=$(matrix_vm_name "$MATRIX_RUN_ID" "$TOPO" srv)
  CLIENT_VM=$(matrix_vm_name "$MATRIX_RUN_ID" "$TOPO" cli)
  ACTIVE_SRV="$SERVER_VM"
  ACTIVE_SRV_ZONE="$Z_A"
  ACTIVE_CLI="$CLIENT_VM"
  ACTIVE_CLI_ZONE="$Z_B"

  echo ""
  echo "[gcp] === topology: $TOPO (zones $Z_A / $Z_B) ==="

  # Provision VMs (no-op in dry-run).
  create_vms "$SERVER_VM" "$Z_A" "$CLIENT_VM" "$Z_B"

  if [[ -n "$RUST_BUILD_COMMAND" ]]; then
    # Deliver source sequentially, then build on both VMs in parallel.
    deliver_source "$SERVER_VM" "$Z_A"
    deliver_source "$CLIENT_VM" "$Z_B"
    echo "[gcp] building rustscale on both VMs in parallel..." >&2
    ssh_cmd "$SERVER_VM" "$Z_A" "$RUST_BUILD_COMMAND" &
    SERVER_BUILD_PID=$!
    ssh_cmd "$CLIENT_VM" "$Z_B" "$RUST_BUILD_COMMAND" &
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

      # Mint a FRESH authkey per config.  Reusing a single ephemeral key
      # across all 16 configs causes "invalid key" / "node not found" errors
      # as the key expires or its ephemeral nodes are reaped mid-run.
      if [[ $DRY_RUN -eq 1 ]]; then
        AUTHKEY="tskey-dryrun-placeholder"
      else
        AUTHKEY=$(bench_mint_authkey)
        echo "[gcp] minted fresh authkey for $CFG" >&2
      fi

      matrix_run_config_cell "$CFG" "$SERVER_VM" "$CLIENT_VM" "$Z_A" "$Z_B" \
        "$AUTHKEY" "$RESULTS_DIR/$TOPO/$PATH_TAG" "rs-srv-$TOPO" "rs-cli-$TOPO"
    done

    if (( PROFILE )); then
      # Keep the profile diagnostic outside the normal selected-cell loop: it
      # gets a fresh key and cannot repeat or overwrite rs-tun measurements.
      if [[ $DRY_RUN -eq 1 ]]; then
        AUTHKEY="tskey-dryrun-placeholder"
      else
        AUTHKEY=$(bench_mint_authkey)
        echo "[gcp] minted fresh authkey for rs-tun profile diagnostic" >&2
      fi
      matrix_select_cell_observed "$TOPO" rs-tun "$Z_A" "$Z_B"
      echo "[gcp] >>> profile: rs-tun (topo=$TOPO path=$PATH_TAG) <<<"
      if matrix_run_profile_diagnostic "$SERVER_VM" "$CLIENT_VM" "$Z_A" "$Z_B" \
        "$AUTHKEY" "$RESULTS_DIR/$TOPO/$PATH_TAG" "rs-srv-$TOPO" "rs-cli-$TOPO"; then
        echo "[gcp] rs-tun profile: OK"
      else
        profile_status=$?
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
# Aggregate + render. Any finalization return exits through gcp_bench_cleanup,
# including the successful DRY_RUN contract and renderer failures.
# ---------------------------------------------------------------------------
matrix_finalize_results "$RESULTS_DIR" "$DRY_RUN" || exit $?

# Clear the trap's VM deletion now that we're done; tailnet cleanup still runs.
ACTIVE_SRV=""
ACTIVE_CLI=""
