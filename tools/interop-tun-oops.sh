#!/usr/bin/env bash
# tools/interop-tun-oops.sh — isolated, out-of-process TUN regression gate.
#
# Runs two RustScale TUN endpoints in distinct Linux network namespaces. Each
# namespace has an independent loopback, veth uplink, TUN device, policy rules,
# and table 52, so table-52 routes cannot collide as they did in the shared
# host namespace. The host bridge/NAT is only the encrypted underlay; TCP and
# UDP application traffic is bound to tailnet IPs and must traverse each TUN.
#
# This is deliberately distinct from tools/interop-tun.sh (RustScale TUN to Go
# userspace) and userspace/embedded/proxy modes. It is a focused two-TUN test.
#
# Usage: source .secrets/tailscale.env && tools/interop-tun-oops.sh
# Requires: Linux, passwordless sudo, iproute2, iptables, /dev/net/tun, cargo,
# curl, jq, and an ephemeral-tailnet credential accepted by tools/bench/lib.sh.
set -euo pipefail
cd "$(dirname "$0")/.."

# shellcheck disable=SC1091
source tools/bench/lib.sh

UDP_DATAGRAMS=10
TCP_PORT="${OOPS_TCP_PORT:-18282}"
UDP_PORT="${OOPS_UDP_PORT:-18283}"
SUBNET="198.18.83.0/24" # RFC 2544 benchmarking range; fails if already routed.
GATE_ID="roops-$$"
NS_SERVER="${GATE_ID}-s"
NS_CLIENT="${GATE_ID}-c"
BRIDGE="${GATE_ID}-br"
VETH_SERVER="${GATE_ID}s"
VETH_CLIENT="${GATE_ID}c"
STATE_DIR=""
SERVER_PID=""
CLIENT_PID=""
WEB_PID=""
CAPTURE_PID=""
UNDERLAY_PCAP=""
SERVER_LOG=""
CLIENT_LOG=""
READY_FIFO=""
PHASE_FIFO=""
EGRESS=""
IP_FORWARD_ORIGINAL=""
IP_FORWARD_CHANGED=0
NAT_RULE_ADDED=0
FORWARD_OUT_RULE_ADDED=0
FORWARD_IN_RULE_ADDED=0
BRIDGE_CREATED=0
VETH_SERVER_CREATED=0
VETH_CLIENT_CREATED=0
SERVER_NS_CREATED=0
CLIENT_NS_CREATED=0

# Linux interface names are limited to 15 bytes. A normal PID is at most five
# digits on the runners; reject an unexpected value rather than truncating and
# possibly touching a foreign interface.
if (( ${#BRIDGE} > 15 || ${#VETH_SERVER} > 15 || ${#VETH_CLIENT} > 15 )); then
  echo "[interop-tun-oops] ERROR: generated interface name exceeds Linux limit" >&2
  exit 1
fi

fail() {
  echo "[interop-tun-oops] ERROR: $*" >&2
  if [[ -n "$SERVER_LOG$CLIENT_LOG" ]]; then
    dump_logs
  fi
  exit 1
}

require_marker() {
  local file="$1" marker="$2" label="$3"
  grep -qF "$marker" "$file" || fail "$label log is missing marker: $marker"
}

require_exactly_one_marker() {
  local file="$1" marker="$2" label="$3" count
  count=$(grep -cF "$marker" "$file" || true)
  [[ "$count" -eq 1 ]] || fail "$label log has $count copies of marker $marker, expected 1"
}

dump_logs() {
  echo "===== BEGIN server full log ====="
  cat "$SERVER_LOG" 2>/dev/null || echo "(server log missing)"
  echo "===== END server full log ====="
  echo "===== BEGIN client full log ====="
  cat "$CLIENT_LOG" 2>/dev/null || echo "(client log missing)"
  echo "===== END client full log ====="
}

# Cleanup is fail-closed. Every potentially blocking operation has its own
# deadline, the server wrapper is terminated and reaped before namespace
# removal, and success is published only after absence checks pass.
cleanup() {
  local original_rc=$? cleanup_rc=0 tailnet_pid=""
  trap - EXIT INT TERM
  set +e

  if [[ -n "$CAPTURE_PID" ]]; then
    kill -TERM "$CAPTURE_PID" 2>/dev/null
    timeout --foreground --signal=TERM --kill-after=2s 10s tail --pid="$CAPTURE_PID" -f /dev/null \
      || { echo "[interop-tun-oops] ERROR: underlay capture did not stop" >&2; cleanup_rc=1; }
    wait "$CAPTURE_PID" 2>/dev/null
  fi

  if [[ -n "$WEB_PID" ]]; then
    kill -TERM "$WEB_PID" 2>/dev/null
    wait "$WEB_PID" 2>/dev/null
  fi
  if [[ -n "$CLIENT_PID" ]]; then
    if kill -0 "$CLIENT_PID" 2>/dev/null; then
      kill -TERM "$CLIENT_PID" 2>/dev/null
      timeout --foreground --signal=TERM --kill-after=2s 10s tail --pid="$CLIENT_PID" -f /dev/null >/dev/null 2>&1 || true
    fi
    wait "$CLIENT_PID" 2>/dev/null
  fi

  if [[ -n "$SERVER_PID" ]]; then
    if kill -0 "$SERVER_PID" 2>/dev/null; then
      kill -TERM "$SERVER_PID" 2>/dev/null
      if ! timeout --foreground --signal=TERM --kill-after=2s 20s tail --pid="$SERVER_PID" -f /dev/null; then
        kill -KILL "$SERVER_PID" 2>/dev/null
        timeout --foreground --signal=TERM --kill-after=2s 5s tail --pid="$SERVER_PID" -f /dev/null || cleanup_rc=1
      fi
    fi
    wait "$SERVER_PID" 2>/dev/null
    kill -0 "$SERVER_PID" 2>/dev/null && cleanup_rc=1
  fi
  if [[ -n "$STATE_DIR" ]] && timeout 5s sudo -n pgrep -f -- "[i]nterop-tun-node.*--state-dir $STATE_DIR/server-state" >/dev/null 2>&1; then
    timeout 5s sudo -n pkill -TERM -f -- "[i]nterop-tun-node.*--state-dir $STATE_DIR/server-state" >/dev/null 2>&1
    timeout 5s sudo -n pkill -KILL -f -- "[i]nterop-tun-node.*--state-dir $STATE_DIR/server-state" >/dev/null 2>&1
  fi
  if [[ -n "$STATE_DIR" ]] && timeout 5s sudo -n pgrep -f -- "[i]nterop-tun-node.*--state-dir $STATE_DIR/server-state" >/dev/null 2>&1; then
    echo "[interop-tun-oops] ERROR: leaked server child process" >&2
    cleanup_rc=1
  fi

  if (( SERVER_NS_CREATED )); then
    timeout 10s sudo -n ip netns del "$NS_SERVER" 2>/dev/null \
      || { echo "[interop-tun-oops] ERROR: could not delete server namespace" >&2; cleanup_rc=1; }
  fi
  if (( CLIENT_NS_CREATED )); then
    timeout 10s sudo -n ip netns del "$NS_CLIENT" 2>/dev/null \
      || { echo "[interop-tun-oops] ERROR: could not delete client namespace" >&2; cleanup_rc=1; }
  fi
  if (( VETH_SERVER_CREATED )) && timeout 5s sudo -n ip link show dev "$VETH_SERVER" >/dev/null 2>&1; then
    timeout 10s sudo -n ip link del "$VETH_SERVER" 2>/dev/null \
      || { echo "[interop-tun-oops] ERROR: could not delete server veth" >&2; cleanup_rc=1; }
  fi
  if (( VETH_CLIENT_CREATED )) && timeout 5s sudo -n ip link show dev "$VETH_CLIENT" >/dev/null 2>&1; then
    timeout 10s sudo -n ip link del "$VETH_CLIENT" 2>/dev/null \
      || { echo "[interop-tun-oops] ERROR: could not delete client veth" >&2; cleanup_rc=1; }
  fi
  if (( BRIDGE_CREATED )); then
    timeout 10s sudo -n ip link del "$BRIDGE" 2>/dev/null \
      || { echo "[interop-tun-oops] ERROR: could not delete bridge" >&2; cleanup_rc=1; }
  fi

  if (( NAT_RULE_ADDED )); then
    timeout 10s sudo -n iptables -w 5 -t nat -D POSTROUTING -s "$SUBNET" -o "$EGRESS" \
      -m comment --comment "${GATE_ID}-nat" -j MASQUERADE 2>/dev/null \
      || { echo "[interop-tun-oops] ERROR: could not delete tagged NAT rule" >&2; cleanup_rc=1; }
  fi
  if (( FORWARD_OUT_RULE_ADDED )); then
    timeout 10s sudo -n iptables -w 5 -D FORWARD -i "$BRIDGE" -o "$EGRESS" \
      -m comment --comment "${GATE_ID}-out" -j ACCEPT 2>/dev/null \
      || { echo "[interop-tun-oops] ERROR: could not delete tagged outbound rule" >&2; cleanup_rc=1; }
  fi
  if (( FORWARD_IN_RULE_ADDED )); then
    timeout 10s sudo -n iptables -w 5 -D FORWARD -i "$EGRESS" -o "$BRIDGE" \
      -m conntrack --ctstate ESTABLISHED,RELATED \
      -m comment --comment "${GATE_ID}-in" -j ACCEPT 2>/dev/null \
      || { echo "[interop-tun-oops] ERROR: could not delete tagged inbound rule" >&2; cleanup_rc=1; }
  fi
  if (( IP_FORWARD_CHANGED )); then
    timeout 10s sudo -n sysctl -q -w "net.ipv4.ip_forward=$IP_FORWARD_ORIGINAL" >/dev/null 2>&1 \
      || { echo "[interop-tun-oops] ERROR: could not restore IPv4 forwarding" >&2; cleanup_rc=1; }
  fi

  if [[ -n "$STATE_DIR" ]]; then
    timeout 10s sudo -n rm -rf "$STATE_DIR" 2>/dev/null \
      || { echo "[interop-tun-oops] ERROR: could not delete state directory" >&2; cleanup_rc=1; }
  fi

  # Run API cleanup in a subshell so its complete retry sequence also has an
  # outer deadline. The credential record remains preserved if this fails.
  bench_cleanup_tailnet &
  tailnet_pid=$!
  if ! timeout --foreground --signal=TERM --kill-after=2s 45s tail --pid="$tailnet_pid" -f /dev/null; then
    kill -TERM "$tailnet_pid" 2>/dev/null
    kill -KILL "$tailnet_pid" 2>/dev/null
    cleanup_rc=1
  fi
  wait "$tailnet_pid" \
    || { echo "[interop-tun-oops] ERROR: ephemeral tailnet cleanup failed" >&2; cleanup_rc=1; }

  if timeout 5s sudo -n ip netns list | awk '{print $1}' | grep -Eq "^(${NS_SERVER}|${NS_CLIENT})$"; then
    echo "[interop-tun-oops] ERROR: leaked network namespace" >&2
    cleanup_rc=1
  fi
  for link in "$BRIDGE" "$VETH_SERVER" "${VETH_SERVER}p" "$VETH_CLIENT" "${VETH_CLIENT}p"; do
    if timeout 5s sudo -n ip link show dev "$link" >/dev/null 2>&1; then
      echo "[interop-tun-oops] ERROR: leaked link $link" >&2
      cleanup_rc=1
    fi
  done
  if timeout 5s sudo -n iptables -w 3 -S | grep -Fq -- "--comment ${GATE_ID}-" \
    || timeout 5s sudo -n iptables -w 3 -t nat -S | grep -Fq -- "--comment ${GATE_ID}-"; then
    echo "[interop-tun-oops] ERROR: leaked tagged firewall rule" >&2
    cleanup_rc=1
  fi
  if [[ -n "$STATE_DIR" && -e "$STATE_DIR" ]]; then
    echo "[interop-tun-oops] ERROR: leaked state directory $STATE_DIR" >&2
    cleanup_rc=1
  fi

  if (( cleanup_rc )); then
    echo "[interop-tun-oops] ERROR: cleanup was incomplete" >&2
    exit 1
  fi
  echo "[interop-tun-oops] OOPS_CLEANUP_COMPLETE gate=$GATE_ID" >&2
  exit "$original_rc"
}

[[ "$(uname -s)" == Linux ]] || fail "isolated two-TUN gate requires Linux"
for cmd in cargo curl jq ip iptables sudo tcpdump timeout; do
  command -v "$cmd" >/dev/null 2>&1 || fail "required tool '$cmd' not found"
done
tools/interop-tun-preflight.sh

WORKLOAD_HEAD_SHA=$(git rev-parse HEAD)
if [[ -n "${OOPS_EXPECTED_HEAD_SHA:-}" && "$WORKLOAD_HEAD_SHA" != "$OOPS_EXPECTED_HEAD_SHA" ]]; then
  fail "workload HEAD $WORKLOAD_HEAD_SHA does not match expected $OOPS_EXPECTED_HEAD_SHA"
fi
echo "[interop-tun-oops] OOPS_WORKLOAD_HEAD_SHA=$WORKLOAD_HEAD_SHA" >&2

# The namespace bridge needs a real host egress route. Do not guess an
# interface or modify a host that already routes the reserved test subnet.
EGRESS=$(ip -4 route show default | awk '/default/ { for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }')
[[ -n "$EGRESS" ]] || fail "could not determine IPv4 default-route interface"
if ip -4 route show exact "$SUBNET" | grep -q .; then
  fail "refusing to use already-routed isolated test subnet $SUBNET"
fi

trap cleanup INT TERM EXIT

# Refuse a PID-wrap collision before creating or later deleting anything. The
# cleanup flags below only authorize removal of resources this invocation made.
for ns in "$NS_SERVER" "$NS_CLIENT"; do
  if sudo -n ip netns list | awk '{print $1}' | grep -Fxq "$ns"; then
    fail "refusing to reuse existing namespace $ns"
  fi
done
for link in "$BRIDGE" "$VETH_SERVER" "${VETH_SERVER}p" "$VETH_CLIENT" "${VETH_CLIENT}p"; do
  if sudo -n ip link show dev "$link" >/dev/null 2>&1; then
    fail "refusing to reuse existing link $link"
  fi
done
if sudo -n iptables -w -S | grep -Fq -- "--comment ${GATE_ID}-" \
  || sudo -n iptables -w -t nat -S | grep -Fq -- "--comment ${GATE_ID}-"; then
  fail "refusing to reuse existing firewall rule tag $GATE_ID"
fi

IP_FORWARD_ORIGINAL=$(sysctl -n net.ipv4.ip_forward)
[[ "$IP_FORWARD_ORIGINAL" =~ ^[01]$ ]] || fail "unexpected net.ipv4.ip_forward value '$IP_FORWARD_ORIGINAL'"
if [[ "$IP_FORWARD_ORIGINAL" != 1 ]]; then
  sudo -n sysctl -q -w net.ipv4.ip_forward=1 >/dev/null
  IP_FORWARD_CHANGED=1
fi

# Allow only this temporary RFC-2544 subnet to reach the existing host egress.
sudo -n iptables -w -A FORWARD -i "$BRIDGE" -o "$EGRESS" \
  -m comment --comment "${GATE_ID}-out" -j ACCEPT
FORWARD_OUT_RULE_ADDED=1
sudo -n iptables -w -A FORWARD -i "$EGRESS" -o "$BRIDGE" \
  -m conntrack --ctstate ESTABLISHED,RELATED \
  -m comment --comment "${GATE_ID}-in" -j ACCEPT
FORWARD_IN_RULE_ADDED=1
sudo -n iptables -w -t nat -A POSTROUTING -s "$SUBNET" -o "$EGRESS" \
  -m comment --comment "${GATE_ID}-nat" -j MASQUERADE
NAT_RULE_ADDED=1

sudo -n ip link add "$BRIDGE" type bridge
BRIDGE_CREATED=1
sudo -n ip addr add 198.18.83.1/24 dev "$BRIDGE"
sudo -n ip link set "$BRIDGE" up
sudo -n ip netns add "$NS_SERVER"
SERVER_NS_CREATED=1
sudo -n ip netns add "$NS_CLIENT"
CLIENT_NS_CREATED=1
sudo -n ip link add "$VETH_SERVER" type veth peer name "${VETH_SERVER}p"
VETH_SERVER_CREATED=1
sudo -n ip link set "$VETH_SERVER" master "$BRIDGE"
sudo -n ip link set "$VETH_SERVER" up
sudo -n ip link set "${VETH_SERVER}p" netns "$NS_SERVER"
sudo -n ip link add "$VETH_CLIENT" type veth peer name "${VETH_CLIENT}p"
VETH_CLIENT_CREATED=1
sudo -n ip link set "$VETH_CLIENT" master "$BRIDGE"
sudo -n ip link set "$VETH_CLIENT" up
sudo -n ip link set "${VETH_CLIENT}p" netns "$NS_CLIENT"

for spec in "$NS_SERVER ${VETH_SERVER}p 198.18.83.2" "$NS_CLIENT ${VETH_CLIENT}p 198.18.83.3"; do
  read -r ns veth address <<<"$spec"
  sudo -n ip netns exec "$ns" ip link set lo up
  sudo -n ip netns exec "$ns" ip addr add "${address}/24" dev "$veth"
  sudo -n ip netns exec "$ns" ip link set "$veth" up
  sudo -n ip netns exec "$ns" ip route add default via 198.18.83.1
  sudo -n ip netns exec "$ns" ip route get 1.1.1.1 | grep -Fq 'via 198.18.83.1' \
    || fail "$ns lacks isolated underlay default route"
done

HOST_NETNS=$(readlink /proc/self/ns/net)
SERVER_NETNS=$(sudo -n ip netns exec "$NS_SERVER" readlink /proc/self/ns/net)
CLIENT_NETNS=$(sudo -n ip netns exec "$NS_CLIENT" readlink /proc/self/ns/net)
[[ "$SERVER_NETNS" != "$CLIENT_NETNS" && "$SERVER_NETNS" != "$HOST_NETNS" && "$CLIENT_NETNS" != "$HOST_NETNS" ]] \
  || fail "network namespace isolation was not established"
echo "[interop-tun-oops] OOPS_NETNS_ISOLATED server=$SERVER_NETNS client=$CLIENT_NETNS" >&2

# bench_provision_tailnet installs its own trap. Restore the complete local
# cleanup trap even on provisioning failure so namespaces and host rules never
# outlive this invocation.
set +e
bench_provision_tailnet
PROVISION_RC=$?
trap cleanup INT TERM EXIT
set -e
(( PROVISION_RC == 0 )) || fail "ephemeral tailnet provisioning failed"

STATE_DIR=$(mktemp -d /tmp/interop-tun-oops.XXXXXX)
chmod 700 "$STATE_DIR"
SERVER_LOG="$STATE_DIR/server.log"
CLIENT_LOG="$STATE_DIR/client.log"
READY_FIFO="$STATE_DIR/server.ready"
PHASE_FIFO="$STATE_DIR/client.phase"
mkfifo -m 600 "$READY_FIFO" "$PHASE_FIFO"
AUTHKEY_FILE="$STATE_DIR/authkey"
UNDERLAY_PCAP="$STATE_DIR/underlay.pcap"
# Capture at the bridge before host NAT. Later assertions correlate each
# namespace source address to the other node's advertised local UDP endpoint,
# independent of RustScale's path enum or configured candidates. This also
# excludes public DERP/STUN traffic from the direct-underlay packet counts.
# Log redirection intentionally remains owned by the invoking user; tcpdump
# alone needs privilege and writes the pcap removed by root cleanup.
# shellcheck disable=SC2024
sudo -n tcpdump -U -n -i "$BRIDGE" -w "$UNDERLAY_PCAP" udp >"$STATE_DIR/tcpdump.log" 2>&1 &
CAPTURE_PID=$!
# tcpdump signals readiness on stderr after opening the interface. Follow that
# file event with an outer deadline rather than polling.
set +o pipefail
timeout 10s tail --pid="$CAPTURE_PID" -n +1 -f "$STATE_DIR/tcpdump.log" \
  | grep -m1 -q "listening on"
CAPTURE_READY_RC=$?
set -o pipefail
(( CAPTURE_READY_RC == 0 )) || fail "underlay packet capture did not become ready"
AUTHKEY=$(bench_mint_authkey)
printf '%s' "$AUTHKEY" > "$AUTHKEY_FILE"
chmod 600 "$AUTHKEY_FILE"
unset AUTHKEY

BUILD_LOG="$STATE_DIR/build.log"
echo "[interop-tun-oops] building isolated TUN node (unprivileged)" >&2
if ! cargo build -p rustscale-tsnet --example interop-tun-node >"$BUILD_LOG" 2>&1 \
  || ! cargo build -p rustscale-cli --bin rustscale >>"$BUILD_LOG" 2>&1; then
  tail -n 80 "$BUILD_LOG" >&2
  fail "interop TUN node or CLI build failed"
fi
NODE_BIN="$(pwd)/target/debug/examples/interop-tun-node"
CLI_BIN="$(pwd)/target/debug/rustscale"
[[ -x "$NODE_BIN" ]] || fail "expected node binary is missing: $NODE_BIN"
[[ -x "$CLI_BIN" ]] || fail "expected CLI binary is missing: $CLI_BIN"

# Exact marker cardinality prevents a renamed/missing workload from silently
# succeeding. The FIFO is a blocking readiness handoff, not a polling loop.
echo "[interop-tun-oops] starting isolated server in $NS_SERVER" >&2
timeout --foreground --signal=TERM --kill-after=15s 300s \
  sudo -n ip netns exec "$NS_SERVER" "$NODE_BIN" server \
    --authkey-file "$AUTHKEY_FILE" \
    --hostname "rs-oops-server-$$" \
    --state-dir "$STATE_DIR/server-state" \
    --tun-name tun0 \
    --port "$TCP_PORT" \
    --udp-port "$UDP_PORT" \
    --ready-fifo "$READY_FIFO" \
  >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
READY_LINE=$(timeout 150s head -n 1 "$READY_FIFO") || fail "server did not signal readiness"
[[ "$READY_LINE" == OOPS_SERVER_READY* ]] || fail "invalid server readiness signal: $READY_LINE"

# The client uses the server tailnet address published only after its TUN and
# listener are ready. No shared namespace, userspace stack, or proxy is used.
SERVER_IP=$(sed -n 's/.*ip=\([0-9.]*\).*/\1/p' "$SERVER_LOG" | head -n 1)
[[ -n "$SERVER_IP" ]] || fail "could not parse server tailnet IP"
echo "[interop-tun-oops] starting isolated client in $NS_CLIENT" >&2
timeout --foreground --signal=TERM --kill-after=15s 300s \
  sudo -n ip netns exec "$NS_CLIENT" "$NODE_BIN" client \
    --authkey-file "$AUTHKEY_FILE" \
    --hostname "rs-oops-client-$$" \
    --state-dir "$STATE_DIR/client-state" \
    --tun-name tun0 \
    --peer "$SERVER_IP" \
    --port "$TCP_PORT" \
    --udp-port "$UDP_PORT" \
    --phase-fifo "$PHASE_FIFO" \
  >"$CLIENT_LOG" 2>&1 &
CLIENT_PID=$!

# Wait for delivered TUN traffic to establish a direct path before reading any
# public status. This follows the log event and exits if the child dies; it is
# not status polling and cannot manufacture path evidence.
set +o pipefail
timeout 180s tail --pid="$CLIENT_PID" -n +1 -f "$CLIENT_LOG" \
  | grep -m1 -q "OOPS_CLIENT_PATH_EVIDENCE_READY"
PATH_READY_RC=$?
set -o pipefail
(( PATH_READY_RC == 0 )) || fail "client did not reach the public path evidence phase"

CLIENT_SOCKET="$STATE_DIR/client-state/localapi.sock"
DIRECT_JSON="$STATE_DIR/status-direct.json"
DIRECT_TABLE="$STATE_DIR/status-direct.txt"
DIRECT_ACTIVE="$STATE_DIR/status-direct-active.txt"
DIRECT_PING="$STATE_DIR/ping-direct.txt"
DERP_JSON="$STATE_DIR/status-derp.json"
DERP_TABLE="$STATE_DIR/status-derp.txt"
DERP_PING="$STATE_DIR/ping-derp.txt"
IDLE_JSON="$STATE_DIR/status-idle.json"
IDLE_CONFIRM_JSON="$STATE_DIR/status-idle-confirm.json"
IDLE_TABLE="$STATE_DIR/status-idle.txt"
IDLE_ACTIVE="$STATE_DIR/status-idle-active.txt"
WEB_LOG="$STATE_DIR/web.log"
WEB_JSON="$STATE_DIR/web-status.json"

run_client_cli() {
  timeout 20s sudo -n ip netns exec "$NS_CLIENT" "$CLI_BIN" --socket "$CLIENT_SOCKET" "$@"
}
peer_for_server() {
  jq -c --arg ip "$SERVER_IP"     '[.Peer[] | select((.TailscaleIPs // []) | index($ip))] | if length == 1 then .[0] else error("server peer cardinality") end' "$1"
}
assert_public_web_status() {
  local expected_json="$1" phase="$2"
  : >"$WEB_LOG"
  timeout --foreground --signal=TERM --kill-after=2s 30s \
    sudo -n ip netns exec "$NS_CLIENT" "$CLI_BIN" --socket "$CLIENT_SOCKET" web \
      --listen=127.0.0.1:18088 --browser=false --readonly=true >"$WEB_LOG" 2>&1 &
  WEB_PID=$!
  set +o pipefail
  timeout 10s tail --pid="$WEB_PID" -n +1 -f "$WEB_LOG" | grep -m1 -q "http://127.0.0.1:18088/"
  local ready_rc=$?
  set -o pipefail
  (( ready_rc == 0 )) || fail "$phase web output did not become ready"
  timeout 10s sudo -n ip netns exec "$NS_CLIENT" curl -fsS \
    -H 'Host: 127.0.0.1:18088' -H 'Origin: http://127.0.0.1:18088' \
    http://127.0.0.1:18088/api/status >"$WEB_JSON"
  kill -TERM "$WEB_PID" 2>/dev/null
  wait "$WEB_PID" 2>/dev/null || true
  WEB_PID=""
  local expected_peer web_peer
  expected_peer=$(peer_for_server "$expected_json")
  web_peer=$(peer_for_server "$WEB_JSON")
  diff -u \
    <(jq -S '{Active, CurAddr, Relay, PeerRelay}' <<<"$expected_peer") \
    <(jq -S '{Active, CurAddr, Relay, PeerRelay}' <<<"$web_peer") \
    || fail "$phase web and CLI/LocalAPI current path fields disagree"
}

SERVER_DIRECT_PORT=$(sed -n 's/.*local UDP endpoints: .*198\.18\.83\.2:\([0-9][0-9]*\).*/\1/p' "$SERVER_LOG" | tail -n 1)
[[ "$SERVER_DIRECT_PORT" =~ ^[1-9][0-9]*$ ]] || fail "could not identify server direct endpoint before status gate"
SERVER_DIRECT_ADDR="198.18.83.2:$SERVER_DIRECT_PORT"
run_client_cli status --json >"$DIRECT_JSON"
DIRECT_PEER=$(peer_for_server "$DIRECT_JSON") || fail "direct LocalAPI output lacks exactly one server peer"
jq -e --arg addr "$SERVER_DIRECT_ADDR" \
  '.Active == true and .CurAddr == $addr and ((.Relay // "") == "") and ((.PeerRelay // "") == "") and .LastSeen != "1970-01-01T00:00:00Z" and .LastHandshake != "1970-01-01T00:00:00Z"' \
  <<<"$DIRECT_PEER" >/dev/null || fail "direct LocalAPI fields are inconsistent: $DIRECT_PEER"
# Suppress only the client's established public TLS transports while asking
# CLI ping to certify direct. Otherwise its intentionally concurrent DERP pong
# can arrive after the direct pong and truthfully change the later status view.
# Direct namespace UDP and the already delivered TUN workload remain intact.
sudo -n ip netns exec "$NS_CLIENT" iptables -w -I OUTPUT -p tcp --dport 443 -j DROP
run_client_cli ping "$SERVER_IP" --count=3 --timeout=5s >"$DIRECT_PING"
grep -Fq "via $SERVER_DIRECT_ADDR" "$DIRECT_PING" || fail "CLI ping did not agree with the direct status address"
run_client_cli status --json >"$DIRECT_JSON"
DIRECT_PEER=$(peer_for_server "$DIRECT_JSON") || fail "post-ping direct LocalAPI output lacks exactly one server peer"
jq -e --arg addr "$SERVER_DIRECT_ADDR" \
  '.Active == true and .CurAddr == $addr and ((.Relay // "") == "") and ((.PeerRelay // "") == "")' \
  <<<"$DIRECT_PEER" >/dev/null || fail "post-ping direct fields are inconsistent: $DIRECT_PEER"
run_client_cli status >"$DIRECT_TABLE"
grep -Fq "active; direct $SERVER_DIRECT_ADDR" "$DIRECT_TABLE" || fail "CLI direct label does not match CurAddr"
run_client_cli status --active >"$DIRECT_ACTIVE"
grep -Fq "rs-oops-server-$$" "$DIRECT_ACTIVE" || fail "status --active omitted the active direct peer"
assert_public_web_status "$DIRECT_JSON" direct
sudo -n ip netns exec "$NS_CLIENT" iptables -w -D OUTPUT -p tcp --dport 443 -j DROP

echo "[interop-tun-oops] OOPS_PUBLIC_DIRECT_EVIDENCE cur_addr=$SERVER_DIRECT_ADDR delivered_udp=$UDP_DATAGRAMS" >&2

# Block only the two namespace-local direct UDP destinations. Public DERP/TLS
# remains reachable through each namespace default route. An authenticated
# disco pong received through DERP must replace, rather than coexist with, the
# direct public identity.
sudo -n ip netns exec "$NS_CLIENT" iptables -w -I OUTPUT -p udp -d 198.18.83.2 -j DROP
sudo -n ip netns exec "$NS_SERVER" iptables -w -I OUTPUT -p udp -d 198.18.83.3 -j DROP
run_client_cli ping "$SERVER_IP" --until-direct=false --count=3 --timeout=5s >"$DERP_PING"
grep -Eq ' via DERP\([^)]+\) ' "$DERP_PING" || fail "CLI ping did not identify its authenticated DERP transport"
run_client_cli status --json >"$DERP_JSON"
DERP_PEER=$(peer_for_server "$DERP_JSON") || fail "DERP LocalAPI output lacks exactly one server peer"
jq -e '.Active == true and ((.CurAddr // "") == "") and ((.PeerRelay // "") == "") and ((.Relay // "") | test("^derp-[1-9][0-9]*$")) and ((.LastHandshake // "1970-01-01T00:00:00Z") == "1970-01-01T00:00:00Z")' \
  <<<"$DERP_PEER" >/dev/null || fail "DERP LocalAPI fields are inconsistent: $DERP_PEER"
DERP_REGION=$(jq -r '.Relay' <<<"$DERP_PEER")
run_client_cli status >"$DERP_TABLE"
grep -Fq "active; relay \"$DERP_REGION\"" "$DERP_TABLE" || fail "CLI DERP label does not agree with LocalAPI"
assert_public_web_status "$DERP_JSON" derp

echo "[interop-tun-oops] OOPS_PUBLIC_DERP_EVIDENCE relay=$DERP_REGION transport=authenticated-disco-pong" >&2

# Externally isolate the client from its authenticated DERP/control TLS
# transports as well as the already blocked direct UDP underlay. This prevents
# real peer heartbeats from continually refreshing LastSeen while leaving the
# LocalAPI and namespace loopback web surface available. With no candidate or
# local-send shortcut, the production 45s freshness deadline must expire.
sudo -n ip netns exec "$NS_CLIENT" iptables -w -I OUTPUT -p tcp --dport 443 -j DROP
sudo -n ip netns exec "$NS_CLIENT" iptables -w -I INPUT -p tcp --sport 443 -j DROP
timeout 50s tail -f /dev/null || [[ $? -eq 124 ]]
run_client_cli status --json >"$IDLE_JSON"
IDLE_PEER=$(peer_for_server "$IDLE_JSON") || fail "idle LocalAPI output lacks exactly one server peer"
jq -e '.Active == false and ((.CurAddr // "") == "") and ((.Relay // "") == "") and ((.PeerRelay // "") == "") and .LastSeen != "1970-01-01T00:00:00Z" and ((.LastHandshake // "1970-01-01T00:00:00Z") == "1970-01-01T00:00:00Z")' \
  <<<"$IDLE_PEER" >/dev/null || fail "idle LocalAPI fields are inconsistent: $IDLE_PEER"
run_client_cli status --json >"$IDLE_CONFIRM_JSON"
IDLE_CONFIRM_PEER=$(peer_for_server "$IDLE_CONFIRM_JSON") || fail "idle confirmation lacks exactly one server peer"
[[ "$(jq -r '.LastSeen' <<<"$IDLE_PEER")" == "$(jq -r '.LastSeen' <<<"$IDLE_CONFIRM_PEER")" ]] \
  || fail "read-only idle status changed LastSeen"
[[ "$(jq -r '.LastWrite // "1970-01-01T00:00:00Z"' <<<"$IDLE_PEER")" == "$(jq -r '.LastWrite // "1970-01-01T00:00:00Z"' <<<"$IDLE_CONFIRM_PEER")" ]] \
  || fail "read-only idle status changed LastWrite"
run_client_cli status >"$IDLE_TABLE"
grep -Fq "rs-oops-server-$$" "$IDLE_TABLE" || fail "ordinary status omitted the online idle peer"
grep -Fq "idle" "$IDLE_TABLE" || fail "ordinary status did not label the expired peer idle"
run_client_cli status --active >"$IDLE_ACTIVE"
! grep -Fq "rs-oops-server-$$" "$IDLE_ACTIVE" || fail "status --active retained the expired peer"
assert_public_web_status "$IDLE_JSON" idle

echo "[interop-tun-oops] OOPS_PUBLIC_IDLE_EVIDENCE active=false filtered=true fields=clear" >&2

# Peer-relay identity is exercised by the separate TLS hermetic integration
# regression. This namespace gate makes no peer-relay claim because these two
# nodes were not configured as peer-relay servers.
sudo -n ip netns exec "$NS_CLIENT" iptables -w -D INPUT -p tcp --sport 443 -j DROP
sudo -n ip netns exec "$NS_CLIENT" iptables -w -D OUTPUT -p tcp --dport 443 -j DROP
sudo -n ip netns exec "$NS_CLIENT" iptables -w -D OUTPUT -p udp -d 198.18.83.2 -j DROP
sudo -n ip netns exec "$NS_SERVER" iptables -w -D OUTPUT -p udp -d 198.18.83.3 -j DROP
printf 'continue\n' >"$PHASE_FIFO"

set +e
wait "$CLIENT_PID"
CLIENT_RC=$?
CLIENT_PID=""
wait "$SERVER_PID"
SERVER_RC=$?
set -e
(( CLIENT_RC == 0 )) || fail "client process exited with status $CLIENT_RC"
(( SERVER_RC == 0 )) || fail "server process exited with status $SERVER_RC"

require_exactly_one_marker "$SERVER_LOG" "OOPS_KERNEL_OK role=server" server
require_exactly_one_marker "$SERVER_LOG" "OOPS_SERVER_READY" server
require_exactly_one_marker "$SERVER_LOG" "OOPS_SERVER_TUN_ROUTE" server
require_exactly_one_marker "$SERVER_LOG" "OOPS_SERVER_TUN_TRAFFIC" server
require_exactly_one_marker "$SERVER_LOG" "OOPS_SERVER_TCP_ACCEPT" server
require_exactly_one_marker "$SERVER_LOG" "OOPS_SERVER_TCP_DONE" server
require_exactly_one_marker "$SERVER_LOG" "OOPS_SERVER_DONE" server
require_exactly_one_marker "$CLIENT_LOG" "OOPS_KERNEL_OK role=client" client
require_exactly_one_marker "$CLIENT_LOG" "OOPS_CLIENT_PEER_OK" client
require_exactly_one_marker "$CLIENT_LOG" "OOPS_CLIENT_TUN_ROUTE" client
require_exactly_one_marker "$CLIENT_LOG" "OOPS_CLIENT_DIRECT_PROBE_OK" client
require_exactly_one_marker "$CLIENT_LOG" "OOPS_CLIENT_TUN_TRAFFIC" client
require_exactly_one_marker "$CLIENT_LOG" "OOPS_CLIENT_UDP_ROUNDTRIP_OK count=$UDP_DATAGRAMS" client
require_exactly_one_marker "$CLIENT_LOG" "OOPS_CLIENT_TCP_ROUNDTRIP_OK" client
require_exactly_one_marker "$CLIENT_LOG" "OOPS_CLIENT_DONE" client

require_exactly_one_marker "$SERVER_LOG" "OOPS_SERVER_DIRECT_PROBE_ECHO" server
SERVER_UDP_COUNT=$(grep -cF "OOPS_SERVER_UDP_ECHO" "$SERVER_LOG" || true)
[[ "$SERVER_UDP_COUNT" -eq "$UDP_DATAGRAMS" ]] \
  || fail "server echoed $SERVER_UDP_COUNT cadenced UDP datagrams, expected $UDP_DATAGRAMS"

kill -TERM "$CAPTURE_PID" 2>/dev/null
if ! timeout --foreground --signal=TERM --kill-after=2s 10s tail --pid="$CAPTURE_PID" -f /dev/null; then
  fail "underlay packet capture did not stop"
fi
wait "$CAPTURE_PID" || fail "underlay packet capture failed"
CAPTURE_PID=""
CLIENT_DIRECT_PORT=$(sed -n 's/.*local UDP endpoints: .*198\.18\.83\.3:\([0-9][0-9]*\).*/\1/p' "$CLIENT_LOG" | tail -n 1)
[[ "$SERVER_DIRECT_PORT" =~ ^[1-9][0-9]*$ && "$CLIENT_DIRECT_PORT" =~ ^[1-9][0-9]*$ ]] \
  || fail "could not identify both advertised local UDP endpoint ports"
CLIENT_DIRECT_PACKETS=$(sudo -n tcpdump -n -r "$UNDERLAY_PCAP" \
  "src host 198.18.83.3 and dst host 198.18.83.2 and udp dst port $SERVER_DIRECT_PORT" 2>/dev/null | wc -l | tr -d ' ')
SERVER_DIRECT_PACKETS=$(sudo -n tcpdump -n -r "$UNDERLAY_PCAP" \
  "src host 198.18.83.2 and dst host 198.18.83.3 and udp dst port $CLIENT_DIRECT_PORT" 2>/dev/null | wc -l | tr -d ' ')
[[ "$SERVER_DIRECT_PACKETS" =~ ^[1-9][0-9]*$ ]] \
  || fail "no externally captured direct UDP underlay packets from server to client"
[[ "$CLIENT_DIRECT_PACKETS" =~ ^[1-9][0-9]*$ ]] \
  || fail "no externally captured direct UDP underlay packets from client to server"
echo "[interop-tun-oops] OOPS_DIRECT_UNDERLAY_EVIDENCE server_to_client_packets=$SERVER_DIRECT_PACKETS client_to_server_packets=$CLIENT_DIRECT_PACKETS server_endpoint=198.18.83.2:$SERVER_DIRECT_PORT client_endpoint=198.18.83.3:$CLIENT_DIRECT_PORT" >&2

# `OOPS_KERNEL_OK` is emitted only after each live endpoint has verified its
# own namespace-local table-52 route. Routes are intentionally retired by
# Server::close before this parent process observes the child exit.
dump_logs
echo "[interop-tun-oops] PASS: isolated TUN-vs-TUN TCP/UDP workload crossed both namespace-local TUN devices" >&2
