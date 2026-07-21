#!/usr/bin/env bash
# tools/bench/gcp/lib.sh — GCP VM helpers for the bench harness.
#
# Sourced by run-matrix.sh and run-config.sh. NOT meant to be run directly.
# Provides: create_vms, delete_vms, ssh_cmd, scp_to, scp_from, deliver_source,
#           apply_derp_block, remove_derp_block, vm_exec.
#
# Requires: gcloud (authenticated), GCP_PROJECT set (auto-detected from gcloud
# config if unset), and the standard ubuntu-2204-lts image family.
#
# Globals:
#   GCP_PROJECT  — project ID (auto-detected if unset)
#   GCP_IMAGE    — image family (default: ubuntu-2204-lts from ubuntu-os-cloud)
#   GCP_MACHINE  — machine type (default: n1-standard-4)
#   GCP_DISK_GB  — boot disk size (default: 200)
#   GCP_NETWORK  — VPC network (default: default)
#   GCP_DRY_RUN  — when non-empty, gcloud mutations are echoed, not executed

# shellcheck shell=bash
: "${GCP_IMAGE:=ubuntu-2204-lts}"
: "${GCP_MACHINE:=n1-standard-4}"
: "${GCP_DISK_GB:=200}"
: "${GCP_NETWORK:=default}"
: "${GCP_IMAGE_PROJECT:=ubuntu-os-cloud}"
: "${GCP_DRY_RUN:=}"

# Print an owner/group/other mode portably. GNU stat accepts BSD's -f operand
# as a filesystem-format request and may succeed with non-mode output, so each
# candidate must be validated before it is accepted.
portable_file_mode() {
  local path="$1" mode
  if mode=$(stat -c %a -- "$path" 2>/dev/null) && [[ "$mode" =~ ^[0-7]{3,4}$ ]]; then
    printf '%s\n' "$mode"
    return 0
  fi
  if mode=$(stat -f %Lp "$path" 2>/dev/null) && [[ "$mode" =~ ^[0-7]{3,4}$ ]]; then
    printf '%s\n' "$mode"
    return 0
  fi
  return 1
}

configure_rs_tun_inbound_pipeline() {
  [[ -n "${RS_TUN_INBOUND_PIPELINE+x}" ]] || RS_TUN_INBOUND_PIPELINE=0
  case "$RS_TUN_INBOUND_PIPELINE" in
    0|1) export RS_TUN_INBOUND_PIPELINE ;;
    *) echo "RS_TUN_INBOUND_PIPELINE must be 0 or 1" >&2; return 2 ;;
  esac
}

configure_rs_tun_outbound_send_pipeline() {
  [[ -n "${RS_TUN_OUTBOUND_SEND_PIPELINE+x}" ]] || RS_TUN_OUTBOUND_SEND_PIPELINE=0
  case "$RS_TUN_OUTBOUND_SEND_PIPELINE" in
    0|1) export RS_TUN_OUTBOUND_SEND_PIPELINE ;;
    *) echo "RS_TUN_OUTBOUND_SEND_PIPELINE must be 0 or 1" >&2; return 2 ;;
  esac
}

# Benchmark runtime modes are explicit 0/1 values so one delivered binary can
# measure the scalar baseline, plain batch, or guarded-GRO candidate. The
# daemon's production controls are presence-based disable switches, so `0`
# below deliberately adds the corresponding RUSTSCALE_DISABLE_* variable.
configure_linux_udp_receive_modes() {
  [[ -n "${RS_LINUX_UDP_BATCH+x}" ]] || RS_LINUX_UDP_BATCH=1
  [[ -n "${RS_LINUX_UDP_GRO+x}" ]] || RS_LINUX_UDP_GRO=1
  case "$RS_LINUX_UDP_BATCH" in
    0|1) export RS_LINUX_UDP_BATCH ;;
    *) echo "RS_LINUX_UDP_BATCH must be 0 or 1" >&2; return 2 ;;
  esac
  case "$RS_LINUX_UDP_GRO" in
    0|1) export RS_LINUX_UDP_GRO ;;
    *) echo "RS_LINUX_UDP_GRO must be 0 or 1" >&2; return 2 ;;
  esac
  if [[ "$RS_LINUX_UDP_BATCH" == 0 && "$RS_LINUX_UDP_GRO" == 1 ]]; then
    echo "RS_LINUX_UDP_GRO=1 requires RS_LINUX_UDP_BATCH=1" >&2
    return 2
  fi
}

# TX GSO is independent of GRO, but requires Linux UDP batching. A scalar
# rollback therefore records GSO off because the production sender disables it.
configure_linux_udp_tx_gso_mode() {
  if [[ -z "${RS_LINUX_UDP_GSO+x}" ]]; then
    # Preserve legacy scalar invocations: production batch rollback disables
    # GSO, so an unrecorded mode must become the physically effective mode.
    if [[ "${RS_LINUX_UDP_BATCH:-1}" == 0 ]]; then
      RS_LINUX_UDP_GSO=0
    else
      RS_LINUX_UDP_GSO=1
    fi
  fi
  case "$RS_LINUX_UDP_GSO" in
    0|1) export RS_LINUX_UDP_GSO ;;
    *) echo "RS_LINUX_UDP_GSO must be 0 or 1" >&2; return 2 ;;
  esac
  if [[ "${RS_LINUX_UDP_BATCH:-1}" == 0 && "$RS_LINUX_UDP_GSO" == 1 ]]; then
    echo "RS_LINUX_UDP_GSO=1 requires RS_LINUX_UDP_BATCH=1" >&2
    return 2
  fi
}

# SSH connection cache (populated by ssh_cmd on first use per VM).
declare -A _SSH_IP=()
declare -A _SSH_USER=()
_SSH_KEY="$HOME/.ssh/google_compute_engine"

# Select an already configured noninteractive credential without changing the
# user's gcloud configuration or starting an interactive login. An expired
# active account is deliberately not preferred over a valid ADC/service-account
# file. CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE lets gcloud refresh the existing
# credential for the bounded matrix instead of pinning a printed access token.
gcloud_auth_preflight() {
  local candidate
  if gcloud auth print-access-token >/dev/null 2>&1; then
    GCP_AUTH_ROUTE=active-gcloud-account
    return 0
  fi
  for candidate in "${CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE:-}" "${GOOGLE_APPLICATION_CREDENTIALS:-}" "$HOME/.config/gcloud/application_default_credentials.json"; do
    [[ -n "$candidate" && -r "$candidate" ]] || continue
    if CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE="$candidate" gcloud auth print-access-token >/dev/null 2>&1; then
      export CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE="$candidate"
      GCP_AUTH_ROUTE=credential-file-override
      return 0
    fi
  done
  echo "[gcp] no valid noninteractive gcloud credential; configure ADC, workload identity, or a service-account credential before a paid run" >&2
  return 2
}

# Auto-detect project if not set. A real run repeats this after auth selection,
# because the configured account can be expired while a documented ADC file is
# still valid.
if [[ -z "${GCP_PROJECT:-}" ]]; then
  GCP_PROJECT=$(gcloud config get-value core/project 2>/dev/null || true)
fi

# ---------------------------------------------------------------------------
# Echo a gcloud command (or run it) honoring GCP_DRY_RUN.
# ---------------------------------------------------------------------------
_gc() {
  if [[ -n "$GCP_DRY_RUN" ]]; then
    echo "[dry-run] $*" >&2
  else
    "$@"
  fi
}

# ---------------------------------------------------------------------------
# Print the root-side program that removes the package-managed tailscaled
# before benchmark daemons are allowed to own the kernel TUN.  The benchmark
# always starts its own tailscaled instances with /tmp state directories.
# ---------------------------------------------------------------------------
package_tailscaled_cleanup_command() {
  printf '%s\n' \
'systemctl stop tailscaled.service 2>/dev/null || true' \
'systemctl disable tailscaled.service 2>/dev/null || true' \
'systemctl mask tailscaled.service 2>/dev/null || true' \
'is_clear() {' \
'  ! pgrep -x tailscaled >/dev/null 2>&1 && ! ip link show dev tailscale0 >/dev/null 2>&1' \
'}' \
'wait_for_clear() {' \
'  local elapsed=0 timeout=15' \
'  while (( elapsed < timeout )); do' \
'    is_clear && return 0' \
'    sleep 1' \
'    elapsed=$((elapsed + 1))' \
'  done' \
'  is_clear' \
'}' \
'diagnose() {' \
'  echo "[gcp] package tailscaled cleanup diagnostics" >&2' \
'  systemctl status tailscaled.service --no-pager >&2 || true' \
'  pgrep -a -x tailscaled >&2 || true' \
'  ps -eo pid,ppid,user,stat,comm,args | grep "[t]ailscaled" >&2 || true' \
'  ip -d link show dev tailscale0 >&2 || true' \
'  fuser -v /dev/net/tun >&2 || true' \
'}' \
'pkill -TERM -x tailscaled 2>/dev/null || true' \
'if ! wait_for_clear; then' \
'  diagnose' \
'  pkill -KILL -x tailscaled 2>/dev/null || true' \
'  if ! wait_for_clear; then' \
'    diagnose' \
'    echo "[gcp] ERROR: package tailscaled or tailscale0 remains after cleanup" >&2' \
'    exit 1' \
'  fi' \
'fi' \
'rm -f /var/lib/tailscale/tailscaled.state /run/tailscale/tailscaled.sock /var/run/tailscale/tailscaled.sock'
}

# Exercise the generated startup program without systemd, a TUN device, or
# GCP.  It verifies service isolation, graceful/forced termination, failure
# diagnostics, and that package state is removed only once the host is clean.
package_tailscaled_cleanup_self_test() {
  local state result events command
  local -a cases=(graceful forced failure)

  systemctl() { PACKAGE_TEST_EVENTS+=" systemctl:$*"; return 0; }
  pgrep() { [[ "$PACKAGE_TEST_PRESENT" == 1 ]]; }
  ip() { [[ "$PACKAGE_TEST_PRESENT" == 1 ]]; }
  pkill() {
    PACKAGE_TEST_EVENTS+=" pkill:$1"
    case "$PACKAGE_TEST_STATE:$1" in
      graceful:-TERM|forced:-KILL) PACKAGE_TEST_PRESENT=0 ;;
    esac
    return 0
  }
  rm() { PACKAGE_TEST_EVENTS+=" rm:$*"; }
  sleep() { :; }
  ps() { :; }
  fuser() { :; }
  test_package_cleanup() { eval "$1"; }

  for state in "${cases[@]}"; do
    PACKAGE_TEST_STATE="$state"
    PACKAGE_TEST_PRESENT=1
    PACKAGE_TEST_EVENTS=""
    command=$(package_tailscaled_cleanup_command)
    command=${command//$'exit 1'/$'return 1'}
    if test_package_cleanup "$command" 2>/dev/null; then result=0; else result=1; fi
    events="$PACKAGE_TEST_EVENTS"
    [[ "$events" == *"systemctl:stop tailscaled.service"* ]] || return 1
    [[ "$events" == *"systemctl:disable tailscaled.service"* ]] || return 1
    [[ "$events" == *"systemctl:mask tailscaled.service"* ]] || return 1
    case "$state" in
      graceful) [[ "$result" == 0 && "$events" != *"pkill:-KILL"* && "$events" == *"rm:-f /var/lib/tailscale/tailscaled.state"* ]] || return 1 ;;
      forced) [[ "$result" == 0 && "$events" == *"pkill:-KILL"* && "$events" == *"rm:-f /var/lib/tailscale/tailscaled.state"* ]] || return 1 ;;
      failure) [[ "$result" == 1 && "$events" == *"pkill:-KILL"* && "$events" != *" rm:"* ]] || return 1 ;;
    esac
  done
  unset -f systemctl pgrep ip pkill rm sleep ps fuser test_package_cleanup
}

# Render the VM startup program.  Keep the static portions in quoted heredocs
# so this host never expands remote variables, command substitutions, or
# comments containing backticks.
render_startup_script() {
  cat <<'STARTUP_HEAD'
#!/bin/bash
set -ex
# Ensure the hostname resolves before anything else. Debian/Ubuntu GCE images
# do not add the instance hostname to /etc/hosts by default, so every sudo in
# later SSH sessions stalls with "unable to resolve host" + DNS timeout.
HN=$(hostname)
grep -q "\b$HN\b" /etc/hosts || echo "127.0.1.1 $HN" >> /etc/hosts
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  iperf3 tcpdump zstd sysstat procps psmisc jq curl python3 socat ncat git \
  build-essential pkg-config ca-certificates iptables iproute2 iputils-ping
# Install rustup to a world-readable location so non-root SSH users can build.
export RUSTUP_HOME=/opt/rust
export CARGO_HOME=/opt/rust/cargo
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --no-modify-path
cp /opt/rust/cargo/bin/cargo /usr/local/bin/cargo
cp /opt/rust/cargo/bin/rustc /usr/local/bin/rustc
cp /opt/rust/cargo/bin/rustup /usr/local/bin/rustup
chmod 755 /usr/local/bin/cargo /usr/local/bin/rustc /usr/local/bin/rustup
# Build the embedded Go comparator with one checksum-pinned native toolchain.
curl -fsSLo /tmp/go1.26.4.linux-amd64.tar.gz https://go.dev/dl/go1.26.4.linux-amd64.tar.gz
echo '1153d3d50e0ac764b447adfe05c2bcf08e889d42a02e0fe0259bd47f6733ad7f  /tmp/go1.26.4.linux-amd64.tar.gz' | sha256sum -c -
rm -rf /usr/local/go
tar -C /usr/local -xzf /tmp/go1.26.4.linux-amd64.tar.gz
ln -sf /usr/local/go/bin/go /usr/local/bin/go
rm -f /tmp/go1.26.4.linux-amd64.tar.gz
# World-writable build dir for the non-root SSH user (gcloud ssh runs as GCP account user).
mkdir -p /opt/rustscale && chmod 777 /opt/rustscale
# The non-root SSH user runs `cargo build`, which writes the registry cache
# under CARGO_HOME. rustup installed it as root, so make the whole tree
# group/other-writable or cargo fails with "Permission denied" creating
# /opt/rust/cargo/registry/cache.
chmod -R 777 /opt/rust
curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/jammy.noarmor.gpg \
  | tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null
curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/jammy.tailscale-keyring.list \
  | tee /etc/apt/sources.list.d/tailscale.list
apt-get update -qq && apt-get install -y -qq tailscale
STARTUP_HEAD
  package_tailscaled_cleanup_command
  cat <<'STARTUP_TAIL'
echo "DONE" > /tmp/startup-done
STARTUP_TAIL
}

startup_script_self_test() {
  local script cleanup_marker='rm -f /var/lib/tailscale/tailscaled.state /run/tailscale/tailscaled.sock /var/run/tailscale/tailscaled.sock'

  script=$(render_startup_script)
  bash -n <<<"$script" || return 1
  [[ "$script" == *'HN=$(hostname)'* ]] || return 1
  [[ "$script" == *'go1.26.4.linux-amd64.tar.gz'* \
    && "$script" == *'1153d3d50e0ac764b447adfe05c2bcf08e889d42a02e0fe0259bd47f6733ad7f'* \
    && "$script" == *'sha256sum -c -'* ]] || return 1
  [[ "$script" == *'`cargo build`'* ]] || return 1
  [[ "$script" == *'systemctl stop tailscaled.service 2>/dev/null || true'* ]] || return 1
  [[ "$script" == *'systemctl disable tailscaled.service 2>/dev/null || true'* ]] || return 1
  [[ "$script" == *'systemctl mask tailscaled.service 2>/dev/null || true'* ]] || return 1
  [[ "$script" != *'package_tailscaled_cleanup_command'* ]] || return 1
  [[ "$script" != *'$(package_tailscaled_cleanup_command)'* ]] || return 1
  [[ "${script#*"$cleanup_marker"}" == *'echo "DONE" > /tmp/startup-done'* ]] || return 1
  [[ "$script" != *'exit 0'* ]] || return 1
}

# ---------------------------------------------------------------------------
# Create a single VM. Args: NAME ZONE
# Idempotent: if the VM already exists, returns 0.
# ---------------------------------------------------------------------------
create_vm() {
  local name="$1" zone="$2"
  echo "[gcp] creating VM $name in $zone" >&2
  # Check existence first.
  if _gc gcloud compute instances describe "$name" --project="$GCP_PROJECT" --zone="$zone" >/dev/null 2>&1; then
    echo "[gcp] VM $name already exists, reusing" >&2
    return 0
  fi
  render_startup_script | _gc gcloud compute instances create "$name" \
    --project="$GCP_PROJECT" \
    --zone="$zone" \
    --machine-type="$GCP_MACHINE" \
    --image-family="$GCP_IMAGE" \
    --image-project="$GCP_IMAGE_PROJECT" \
    --boot-disk-size="${GCP_DISK_GB}GB" \
    --boot-disk-type=pd-standard \
    --network="$GCP_NETWORK" \
    --subnet=default \
    --boot-disk-auto-delete \
    --labels=rustscale-benchmark=true \
    --metadata-from-file startup-script=/dev/stdin
}

# ---------------------------------------------------------------------------
# Create two VMs in parallel. Args: SERVER_NAME SERVER_ZONE CLIENT_NAME CLIENT_ZONE
# ---------------------------------------------------------------------------
create_vms() {
  local srv_name="$1" srv_zone="$2" cli_name="$3" cli_zone="$4"
  create_vm "$srv_name" "$srv_zone"
  create_vm "$cli_name" "$cli_zone"
  wait_for_startup "$srv_name" "$srv_zone"
  wait_for_startup "$cli_name" "$cli_zone"
}

# ---------------------------------------------------------------------------
# Wait for /tmp/startup-done on a VM. Args: NAME ZONE [timeout_secs=900]
# ---------------------------------------------------------------------------
wait_for_startup() {
  local name="$1" zone="$2" timeout="${3:-900}"
  if [[ -n "$GCP_DRY_RUN" ]]; then
    echo "[dry-run] wait_for_startup $name $zone" >&2
    return 0
  fi
  echo "[gcp] waiting for startup-done on $name ($zone), timeout=${timeout}s" >&2
  local elapsed=0
  while (( elapsed < timeout )); do
    if gcloud compute ssh "$name" --project="$GCP_PROJECT" --zone="$zone" \
        --command='test -f /tmp/startup-done && echo OK' 2>/dev/null | grep -q OK; then
      echo "[gcp] $name startup complete (${elapsed}s)" >&2
      return 0
    fi
    sleep 10
    elapsed=$((elapsed + 10))
  done
  echo "[gcp] ERROR: timed out waiting for startup on $name" >&2
  gcloud compute instances get-serial-port-output "$name" --project="$GCP_PROJECT" --zone="$zone" --port=1 2>/dev/null \
    | tail -n 80 >&2 || true
  return 1
}

# ---------------------------------------------------------------------------
# Run a command on a VM via gcloud ssh. Args: NAME ZONE COMMAND
# Prints stdout of the remote command to stdout. SSH errors go to stderr.
# Remote command statuses are returned immediately. Only SSH's transport
# status 255 is retried, at most three times in total.
# Honors GCP_DRY_RUN (just echoes the command).
# ---------------------------------------------------------------------------
ssh_cmd() {
  local name="$1" zone="$2" cmd="$3"
  if [[ -n "$GCP_DRY_RUN" ]]; then
    echo "[dry-run] ssh $name ($zone): $cmd" >&2
    return 0
  fi
  # Resolve VM external IP + SSH user once, cache in globals.
  if [[ -z "${_SSH_IP[$name]:-}" ]]; then
    _SSH_IP[$name]=$(gcloud compute instances describe "$name" --project="$GCP_PROJECT" --zone="$zone" \
      --format='value(networkInterfaces[0].accessConfigs[0].natIP)' 2>/dev/null)
    # Extract the SSH username from gcloud's dry-run output (the user portion
    # of the ssh target, which may differ from the gcloud account email).
    _SSH_USER[$name]=$(gcloud compute ssh "$name" --project="$GCP_PROJECT" --zone="$zone" --dry-run 2>&1 | grep -oE '[a-zA-Z0-9._-]+@[0-9.]+' | head -1 | cut -d@ -f1)
    [[ -z "${_SSH_USER[$name]}" ]] && _SSH_USER[$name]=$(gcloud config get-value account 2>/dev/null | cut -d@ -f1)
    _SSH_KEY="$HOME/.ssh/google_compute_engine"
  fi
  local ip="${_SSH_IP[$name]}" user="${_SSH_USER[$name]}"
  local attempt=0 max=3 status
  while (( attempt < max )); do
    if ssh -i "$_SSH_KEY" \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes \
      -o ConnectTimeout=30 -o ServerAliveInterval=15 -o ServerAliveCountMax=4 \
      "$user@$ip" "$cmd"; then
      status=0
    else
      status=$?
    fi
    (( status == 0 )) && return 0
    (( status == 255 )) || return "$status"
    attempt=$((attempt + 1))
    (( attempt < max )) || return 255
    echo "[gcp] ssh retry $attempt/$max for $name" >&2
    sleep 5
  done
  return 255
}

# Exercise ssh_cmd without gcloud or a network connection. The fake ssh and
# sleep functions make retry behavior deterministic and never sleep.
ssh_cmd_self_test() {
  local status
  _SSH_IP[self-test]=192.0.2.1
  _SSH_USER[self-test]=tester
  SSH_TEST_SLEPT=0
  ssh() {
    local next="${SSH_TEST_STATUSES[$SSH_TEST_ATTEMPTS]}"
    SSH_TEST_ATTEMPTS=$((SSH_TEST_ATTEMPTS + 1))
    return "$next"
  }
  sleep() { SSH_TEST_SLEPT=1; }

  for expected in 1 124; do
    SSH_TEST_STATUSES=("$expected")
    SSH_TEST_ATTEMPTS=0; SSH_TEST_SLEPT=0
    if ssh_cmd self-test zone command >/dev/null 2>&1; then return 1; else status=$?; fi
    (( status == expected && SSH_TEST_ATTEMPTS == 1 && SSH_TEST_SLEPT == 0 )) || return 1
  done
  SSH_TEST_STATUSES=(255 0)
  SSH_TEST_ATTEMPTS=0; SSH_TEST_SLEPT=0
  ssh_cmd self-test zone command >/dev/null 2>&1 || return 1
  (( SSH_TEST_ATTEMPTS == 2 && SSH_TEST_SLEPT == 1 )) || return 1
  SSH_TEST_STATUSES=(255 255 255)
  SSH_TEST_ATTEMPTS=0; SSH_TEST_SLEPT=0
  if ssh_cmd self-test zone command >/dev/null 2>&1; then return 1; else status=$?; fi
  (( status == 255 && SSH_TEST_ATTEMPTS == 3 && SSH_TEST_SLEPT == 1 )) || return 1
  unset -f ssh sleep
  unset SSH_TEST_STATUSES SSH_TEST_ATTEMPTS SSH_TEST_SLEPT
}

# Verify every compute lifecycle/identity command explicitly carries the
# configured project, without invoking gcloud or a network transport.
gcloud_project_self_test() {
  local log old_project original_render
  log=$(mktemp); old_project="$GCP_PROJECT"; GCP_PROJECT=fixture-project
  original_render=$(declare -f render_startup_script)
  _gc() { printf '%s\n' "$*" >>"$log"; [[ "$*" == *'instances describe'* ]] && return 1; return 0; }
  render_startup_script() { printf '#!/bin/bash\n'; }
  create_vm project-test us-central1-a
  delete_vm project-test us-central1-a
  gcloud() {
    printf '%s\n' "$*" >>"$log"
    [[ "$*" == *'instances describe'* ]] && { printf '192.0.2.1\n'; return 0; }
    [[ "$*" == *'compute ssh'* ]] && { printf 'tester@192.0.2.1\n'; return 0; }
    return 0
  }
  ssh() { :; }
  unset '_SSH_IP[project-test]' '_SSH_USER[project-test]'
  ssh_cmd project-test us-central1-a true
  gcloud compute disks describe disk --project="$GCP_PROJECT" --zone=us-central1-a >>"$log"
  grep -q -- 'instances create project-test --project=fixture-project' "$log" || return 1
  grep -q -- 'instances describe project-test --project=fixture-project' "$log" || return 1
  grep -q -- 'instances delete project-test --project=fixture-project' "$log" || return 1
  grep -q -- 'disks delete project-test --project=fixture-project' "$log" || return 1
  grep -q -- 'compute ssh project-test --project=fixture-project --zone=us-central1-a --dry-run' "$log" || return 1
  grep -q -- 'compute disks describe disk --project=fixture-project' "$log" || return 1
  rm -f "$log"; GCP_PROJECT="$old_project"
  unset -f _gc gcloud ssh
  eval "$original_render"
}

# ---------------------------------------------------------------------------
# Run a sudo command on a VM. Args: NAME ZONE COMMAND
# ---------------------------------------------------------------------------
ssh_sudo_remote_command() {
  # Callers must not include single quotes: this is intentionally one remote
  # shell word whose contents are evaluated only by the root-side bash -c.
  printf "sudo bash -c '%s'" "$1"
}

ssh_sudo() {
  local name="$1" zone="$2" cmd="$3"
  ssh_cmd "$name" "$zone" "$(ssh_sudo_remote_command "$cmd")"
}

# ---------------------------------------------------------------------------
# Copy a local file to a VM. Args: LOCAL_PATH NAME ZONE REMOTE_PATH
# ---------------------------------------------------------------------------
scp_to() {
  local local_path="$1" name="$2" zone="$3" remote_path="$4"
  if [[ -n "$GCP_DRY_RUN" ]]; then
    echo "[dry-run] scp $local_path -> $name:$remote_path" >&2
    return 0
  fi
  # Resolve VM external IP + SSH user (same cache as ssh_cmd).
  if [[ -z "${_SSH_IP[$name]:-}" ]]; then
    _SSH_IP[$name]=$(gcloud compute instances describe "$name" --project="$GCP_PROJECT" --zone="$zone" \
      --format='value(networkInterfaces[0].accessConfigs[0].natIP)' 2>/dev/null)
    _SSH_USER[$name]=$(gcloud compute ssh "$name" --project="$GCP_PROJECT" --zone="$zone" --dry-run 2>&1 | grep -oE '[a-zA-Z0-9._-]+@[0-9.]+' | head -1 | cut -d@ -f1)
    [[ -z "${_SSH_USER[$name]}" ]] && _SSH_USER[$name]=$(gcloud config get-value account 2>/dev/null | cut -d@ -f1)
  fi
  local ip="${_SSH_IP[$name]}" user="${_SSH_USER[$name]}"
  scp -i "$_SSH_KEY" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes \
    -o ConnectTimeout=30 \
    "$local_path" "$user@$ip:$remote_path"
}

# Copy a VM file to local storage. Args: NAME ZONE REMOTE_PATH LOCAL_PATH.
scp_from() {
  local name="$1" zone="$2" remote_path="$3" local_path="$4"
  if [[ -n "$GCP_DRY_RUN" ]]; then
    echo "[dry-run] scp $name:$remote_path -> $local_path" >&2
    : >"$local_path"
    return 0
  fi
  ssh_cmd "$name" "$zone" ':' >/dev/null
  scp -i "$_SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes \
    -o ConnectTimeout=30 "${_SSH_USER[$name]}@${_SSH_IP[$name]}:$remote_path" "$local_path"
}

# ---------------------------------------------------------------------------
# Deliver the rustscale source tree to a VM. Args: NAME ZONE
# Packs the current working tree with `git archive`, scp's it, and extracts
# to /opt/rustscale on the VM. Idempotent: overwrites prior tree.
# ---------------------------------------------------------------------------
deliver_source() {
  local name="$1" zone="$2"
  local tmpdir
  tmpdir=$(mktemp -d /tmp/rustscale-src.XXXXXX)
  local tarball="$tmpdir/rustscale-src.tar.gz"
  echo "[gcp] archiving source tree -> $tarball" >&2
  git archive --format=tar.gz -o "$tarball" HEAD
  scp_to "$tarball" "$name" "$zone" /tmp/rustscale-src.tar.gz
  ssh_cmd "$name" "$zone" 'mkdir -p /opt/rustscale && tar xzf /tmp/rustscale-src.tar.gz -C /opt/rustscale'
  rm -rf "$tmpdir"
}

# ---------------------------------------------------------------------------
# Reset a VM when an in-guest TUN transition has made SSH unreachable.
# Args: NAME ZONE
# ---------------------------------------------------------------------------
reset_vm() {
  local name="$1" zone="$2"
  echo "[gcp] resetting VM $name ($zone) to quiesce unreachable TUN state" >&2
  _gc gcloud compute instances reset "$name" --project="$GCP_PROJECT" --zone="$zone" -q || return 1
  unset '_SSH_IP[$name]' '_SSH_USER[$name]'
  wait_for_startup "$name" "$zone" 300
}

# ---------------------------------------------------------------------------
# Delete a single VM + its boot disk. Args: NAME ZONE
# ---------------------------------------------------------------------------
delete_vm() {
  local name="$1" zone="$2" status=0
  echo "[gcp] deleting VM $name ($zone)" >&2
  _gc gcloud compute instances delete "$name" --project="$GCP_PROJECT" --zone="$zone" --delete-disks=all -q || status=$?
  # Older harness versions disabled boot-disk auto-delete. Remove a same-name
  # unattached disk even when the instance has already disappeared.
  if _gc gcloud compute disks describe "$name" --project="$GCP_PROJECT" --zone="$zone" >/dev/null 2>&1; then
    _gc gcloud compute disks delete "$name" --project="$GCP_PROJECT" --zone="$zone" -q || status=$?
  fi
  return "$status"
}

# ---------------------------------------------------------------------------
# Delete two VMs. Args: SERVER_NAME SERVER_ZONE CLIENT_NAME CLIENT_ZONE
# ---------------------------------------------------------------------------
delete_vms() {
  local srv_name="$1" srv_zone="$2" cli_name="$3" cli_zone="$4"
  delete_vm "$srv_name" "$srv_zone"
  delete_vm "$cli_name" "$cli_zone"
}

# ---------------------------------------------------------------------------
# Force DERP path: block all outbound UDP except DNS (port 53).
# Applied on a VM. Args: NAME ZONE
# ---------------------------------------------------------------------------
apply_derp_block() {
  local name="$1" zone="$2"
  echo "[gcp] applying DERP-forcing iptables block on $name" >&2
  ssh_sudo "$name" "$zone" \
    'iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT; iptables -A OUTPUT -p udp --dport 53 -j ACCEPT; iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT; iptables -A OUTPUT -p udp -j DROP; iptables -L OUTPUT -n -v'
}

# ---------------------------------------------------------------------------
# Remove DERP-forcing rules. Args: NAME ZONE
# ---------------------------------------------------------------------------
remove_derp_block() {
  local name="$1" zone="$2"
  echo "[gcp] removing DERP-forcing iptables block on $name" >&2
  ssh_sudo "$name" "$zone" \
    'iptables -D OUTPUT -p tcp --dport 53 -j ACCEPT 2>/dev/null; iptables -D OUTPUT -p udp --dport 53 -j ACCEPT 2>/dev/null; iptables -D OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; iptables -D OUTPUT -p udp -j DROP 2>/dev/null; iptables -L OUTPUT -n -v'
}

# ---------------------------------------------------------------------------
# Verify DERP path on a VM by tailscale-pinging a peer. Args: NAME ZONE PEER_IP_OR_HOST
# Prints "via DERP" or "direct" or "unknown".
# ---------------------------------------------------------------------------
verify_derp_path() {
  local name="$1" zone="$2" peer="$3"
  ssh_cmd "$name" "$zone" "tailscale ping '$peer' 2>&1 | head -5" \
    | grep -q 'via DERP' && echo "via DERP" || echo "direct-or-unknown"
}
