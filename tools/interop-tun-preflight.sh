#!/usr/bin/env bash
# Credential-free Linux preflight for the real-TUN interop gate.
# Run this before minting tokens or provisioning an ephemeral tailnet.
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ "$(uname -s)" != Linux ]]; then
  echo "[interop-tun-preflight] ERROR: the CI real-TUN gate requires Linux" >&2
  exit 1
fi
for cmd in ip sudo resolvectl getent; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "[interop-tun-preflight] ERROR: required tool '$cmd' not found" >&2
    exit 1
  }
done
if ! sudo -n true 2>/dev/null; then
  echo "[interop-tun-preflight] ERROR: passwordless sudo is required" >&2
  exit 1
fi
# The privileged MagicDNS gate exercises the systemd-resolved per-link D-Bus
# API. A runner without it is unsupported and must fail before credentials are
# minted; it is never a passing skip or a resolv.conf fallback.
if ! resolvectl status >/dev/null 2>&1; then
  echo "[interop-tun-preflight] ERROR: systemd-resolved/resolvectl is unavailable" >&2
  exit 1
fi
if [[ ! -c /dev/net/tun ]]; then
  echo "[interop-tun-preflight] ERROR: /dev/net/tun is not a character device" >&2
  exit 1
fi

probe="rsci$$"
cleanup() {
  sudo -n ip link delete dev "$probe" 2>/dev/null || true
}
trap cleanup EXIT

sudo -n ip tuntap add dev "$probe" mode tun
sudo -n ip link set dev "$probe" mtu 1280 up

ifindex=$(<"/sys/class/net/$probe/ifindex")
flags=$(<"/sys/class/net/$probe/flags")
mtu=$(<"/sys/class/net/$probe/mtu")
if [[ ! "$ifindex" =~ ^[1-9][0-9]*$ ]]; then
  echo "[interop-tun-preflight] ERROR: $probe has invalid ifindex '$ifindex'" >&2
  exit 1
fi
if (( (16#${flags#0x} & 1) == 0 )); then
  echo "[interop-tun-preflight] ERROR: $probe is not administratively up" >&2
  exit 1
fi
if [[ "$mtu" != 1280 ]]; then
  echo "[interop-tun-preflight] ERROR: $probe has MTU $mtu, expected 1280" >&2
  exit 1
fi

cleanup
trap - EXIT
echo "[interop-tun-preflight] Linux TUN prerequisites established (ifindex=$ifindex)" >&2
