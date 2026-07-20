#!/usr/bin/env bash
# Hermetic Linux kernel regression for TUN node/service address ownership.
set -euo pipefail

if [[ "$(uname -s)" != Linux ]] || ! command -v ip >/dev/null; then
  echo "linux TUN source namespace regression unavailable on this host"
  exit 0
fi

sudo -n unshare --net -- bash -se <<'NS'
set -euo pipefail
MAGIC=100.100.100.100
PEER=100.88.2.90

assert_absent() {
  local routes
  ! ip -4 -o addr show | grep -Fq "$MAGIC/32"
  # iproute2 reports a missing non-main table as an error; after teardown that
  # is the expected empty-table state, so normalize it before asserting.
  routes=$(ip -4 route show table 52 2>/dev/null || true)
  ! grep -Eq '(^| )100\.64\.0\.0/10( |$)|(^| )100\.100\.100\.100( |/32 |$)' <<<"$routes"
}

configure() {
  local node=$1
  ip link add tun0 type dummy
  ip link set lo up
  ip link set tun0 up
  ip addr add "$node/32" dev tun0
  # The DNS listener is local, but its service identity is not a node source.
  ip addr add "$MAGIC/32" dev lo
  ip route add 100.64.0.0/10 dev tun0 table 52
  ip route add "$MAGIC/32" dev tun0 table 52

  ip -4 -o addr show dev tun0 | grep -Fq "inet $node/32"
  ! ip -4 -o addr show dev tun0 | grep -Fq "$MAGIC/32"
  ip -4 -o addr show dev lo | grep -Fq "inet $MAGIC/32"
  ip -4 route show exact "$MAGIC/32" table 52 | grep -Fq "dev tun0"
  route=$(ip -4 route get "$PEER" table 52)
  grep -Fq "dev tun0" <<<"$route"
  grep -Fq "src $node" <<<"$route"
  ! grep -Fq "src $MAGIC" <<<"$route"
}

clear_config() {
  ip route del "$MAGIC/32" dev tun0 table 52
  ip route del 100.64.0.0/10 dev tun0 table 52
  ip addr del "$MAGIC/32" dev lo
  ip addr del "$1/32" dev tun0
  ip link del tun0
  assert_absent
}

assert_absent
configure 100.115.224.78
clear_config 100.115.224.78
# A restart must own only its new node address and leave no prior generation.
configure 100.77.66.55
! ip -4 -o addr show | grep -Fq '100.115.224.78/32'
clear_config 100.77.66.55

echo 'LINUX_TUN_SOURCE_NAMESPACE_OK address route-source dns-route restart down cleanup'
NS
