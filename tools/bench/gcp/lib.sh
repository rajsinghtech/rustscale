#!/usr/bin/env bash
# tools/bench/gcp/lib.sh — GCP VM helpers for the bench harness.
#
# Sourced by run-matrix.sh and run-config.sh. NOT meant to be run directly.
# Provides: create_vms, delete_vms, ssh_cmd, scp_to, deliver_source,
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

# SSH connection cache (populated by ssh_cmd on first use per VM).
declare -A _SSH_IP=()
declare -A _SSH_USER=()
_SSH_KEY="$HOME/.ssh/google_compute_engine"

# Auto-detect project if not set.
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
# Create a single VM. Args: NAME ZONE
# Idempotent: if the VM already exists, returns 0.
# ---------------------------------------------------------------------------
create_vm() {
  local name="$1" zone="$2"
  echo "[gcp] creating VM $name in $zone" >&2
  # Check existence first.
  if _gc gcloud compute instances describe "$name" --zone="$zone" >/dev/null 2>&1; then
    echo "[gcp] VM $name already exists, reusing" >&2
    return 0
  fi
  _gc gcloud compute instances create "$name" \
    --zone="$zone" \
    --machine-type="$GCP_MACHINE" \
    --image-family="$GCP_IMAGE" \
    --image-project="$GCP_IMAGE_PROJECT" \
    --boot-disk-size="${GCP_DISK_GB}GB" \
    --boot-disk-type=pd-standard \
    --network="$GCP_NETWORK" \
    --subnet=default \
    --no-boot-disk-auto-delete \
    --metadata-from-file startup-script=/dev/stdin <<'STARTUP'
#!/bin/bash
set -ex
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  iperf3 tcpdump zstd sysstat procps jq curl python3 socat ncat git \
  build-essential pkg-config ca-certificates iptables iproute2 iputils-ping
# Install rustup to a world-readable location so non-root SSH users can build.
export RUSTUP_HOME=/opt/rust
export CARGO_HOME=/opt/rust/cargo
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --no-modify-path
cp /opt/rust/cargo/bin/cargo /usr/local/bin/cargo
cp /opt/rust/cargo/bin/rustc /usr/local/bin/rustc
cp /opt/rust/cargo/bin/rustup /usr/local/bin/rustup
chmod 755 /usr/local/bin/cargo /usr/local/bin/rustc /usr/local/bin/rustup
# World-writable build dir for the non-root SSH user (gcloud ssh runs as GCP account user).
mkdir -p /opt/rustscale && chmod 777 /opt/rustscale
curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/jammy.noarmor.gpg \
  | tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null
curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/jammy.tailscale-keyring.list \
  | tee /etc/apt/sources.list.d/tailscale.list
apt-get update -qq && apt-get install -y -qq tailscale
echo "DONE" > /tmp/startup-done
STARTUP
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
# Wait for /tmp/startup-done on a VM. Args: NAME ZONE [timeout_secs=600]
# ---------------------------------------------------------------------------
wait_for_startup() {
  local name="$1" zone="$2" timeout="${3:-600}"
  if [[ -n "$GCP_DRY_RUN" ]]; then
    echo "[dry-run] wait_for_startup $name $zone" >&2
    return 0
  fi
  echo "[gcp] waiting for startup-done on $name ($zone), timeout=${timeout}s" >&2
  local elapsed=0
  while (( elapsed < timeout )); do
    if gcloud compute ssh "$name" --zone="$zone" \
        --command='test -f /tmp/startup-done && echo OK' 2>/dev/null | grep -q OK; then
      echo "[gcp] $name startup complete (${elapsed}s)" >&2
      return 0
    fi
    sleep 10
    elapsed=$((elapsed + 10))
  done
  echo "[gcp] ERROR: timed out waiting for startup on $name" >&2
  return 1
}

# ---------------------------------------------------------------------------
# Run a command on a VM via gcloud ssh. Args: NAME ZONE COMMAND
# Prints stdout of the remote command to stdout. SSH errors go to stderr.
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
    _SSH_IP[$name]=$(gcloud compute instances describe "$name" --zone="$zone" \
      --format='value(networkInterfaces[0].accessConfigs[0].natIP)' 2>/dev/null)
    # Extract the SSH username from gcloud's dry-run output (the user portion
    # of the ssh target, which may differ from the gcloud account email).
    _SSH_USER[$name]=$(gcloud compute ssh "$name" --zone="$zone" --dry-run 2>&1 | grep -oE '[a-zA-Z0-9._-]+@[0-9.]+' | head -1 | cut -d@ -f1)
    [[ -z "${_SSH_USER[$name]}" ]] && _SSH_USER[$name]=$(gcloud config get-value account 2>/dev/null | cut -d@ -f1)
    _SSH_KEY="$HOME/.ssh/google_compute_engine"
  fi
  local ip="${_SSH_IP[$name]}" user="${_SSH_USER[$name]}"
  local attempt=0 max=3
  while (( attempt < max )); do
    if ssh -i "$_SSH_KEY" \
      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes \
      -o ConnectTimeout=30 -o ServerAliveInterval=15 -o ServerAliveCountMax=4 \
      "$user@$ip" "$cmd"; then
      return 0
    fi
    attempt=$((attempt + 1))
    echo "[gcp] ssh retry $attempt/$max for $name" >&2
    sleep 5
  done
  return 1
}

# ---------------------------------------------------------------------------
# Run a sudo command on a VM. Args: NAME ZONE COMMAND
# ---------------------------------------------------------------------------
ssh_sudo() {
  local name="$1" zone="$2" cmd="$3"
  ssh_cmd "$name" "$zone" "sudo bash -c '$cmd'"
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
    _SSH_IP[$name]=$(gcloud compute instances describe "$name" --zone="$zone" \
      --format='value(networkInterfaces[0].accessConfigs[0].natIP)' 2>/dev/null)
    _SSH_USER[$name]=$(gcloud compute ssh "$name" --zone="$zone" --dry-run 2>&1 | grep -oE '[a-zA-Z0-9._-]+@[0-9.]+' | head -1 | cut -d@ -f1)
    [[ -z "${_SSH_USER[$name]}" ]] && _SSH_USER[$name]=$(gcloud config get-value account 2>/dev/null | cut -d@ -f1)
  fi
  local ip="${_SSH_IP[$name]}" user="${_SSH_USER[$name]}"
  scp -i "$_SSH_KEY" \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes \
    -o ConnectTimeout=30 \
    "$local_path" "$user@$ip:$remote_path"
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
# Delete a single VM + its boot disk. Args: NAME ZONE
# ---------------------------------------------------------------------------
delete_vm() {
  local name="$1" zone="$2"
  echo "[gcp] deleting VM $name ($zone)" >&2
  _gc gcloud compute instances delete "$name" --zone="$zone" --delete-disks=all -q
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
    'iptables -A OUTPUT -p udp --dport 53 -j ACCEPT; iptables -A OUTPUT -p udp -j DROP; iptables -L OUTPUT -n -v'
}

# ---------------------------------------------------------------------------
# Remove DERP-forcing rules. Args: NAME ZONE
# ---------------------------------------------------------------------------
remove_derp_block() {
  local name="$1" zone="$2"
  echo "[gcp] removing DERP-forcing iptables block on $name" >&2
  ssh_sudo "$name" "$zone" \
    'iptables -D OUTPUT -p udp --dport 53 -j ACCEPT 2>/dev/null; iptables -D OUTPUT -p udp -j DROP 2>/dev/null; iptables -L OUTPUT -n -v'
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
