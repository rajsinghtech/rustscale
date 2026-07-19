#!/usr/bin/env bash
# Installed Linux replacement journey. Builds a release archive, installs it
# through scripts/install.sh with explicit Tailscale-compatible aliases, starts
# the shipped systemd unit, enrolls against pinned Go testcontrol, and proves a
# kernel-TUN packet roundtrip to a pinned Go tailscaled peer.

set -euo pipefail

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
LABEL='[linux-replacement]'
REQUIRE=${RUSTSCALE_REQUIRE_LINUX_REPLACEMENT:-0}

skip() {
  local reason=$1
  if [[ "$REQUIRE" == 1 ]]; then
    echo "$LABEL ERROR: required journey unavailable: $reason" >&2
    exit 1
  fi
  echo "$LABEL SKIP: $reason" >&2
  exit 0
}

timestamp() {
  date -u '+%Y-%m-%dT%H:%M:%SZ'
}

# `is-system-running --wait` is systemd's native bounded readiness primitive.
# Do not replace this with an instantaneous state probe or a polling loop: a
# fresh GitHub runner can still be `starting` while systemd is fully usable.
wait_for_systemd_manager() {
  local seconds=$1 scope=$2 state status
  shift 2
  echo "$LABEL $(timestamp) wait: systemd manager ($scope, deadline=${seconds}s)" >&2
  if state=$("$@" timeout --signal=KILL "${seconds}s" \
      systemctl is-system-running --wait 2>&1); then
    status=0
  else
    status=$?
  fi
  state=$(printf '%s' "$state" | tr -d '\r\n')
  case "$state" in
    running)
      if [[ "$status" == 0 ]]; then
        return 0
      fi
      ;;
    degraded)
      echo "$LABEL $(timestamp) systemd manager is degraded; collecting bounded failed-unit diagnostics" >&2
      if ! "$@" timeout --signal=KILL 8s systemctl --failed --no-pager >&2; then
        echo "$LABEL $(timestamp) systemd failed-unit diagnostics were unavailable" >&2
      fi
      echo "$LABEL $(timestamp) accepting degraded systemd manager as an operational final state" >&2
      return 0
      ;;
  esac
  echo "$LABEL ERROR: systemd manager did not reach an acceptable final state (scope=$scope state=${state:-unknown} status=$status)" >&2
  return 1
}

CURRENT_PHASE=starting
record_phase() {
  local phase=$1 now
  now=$(timestamp)
  CURRENT_PHASE=$phase
  echo "$LABEL $now phase: $phase" >&2
  if [[ "${GITHUB_ACTIONS:-false}" == true ]]; then
    echo "::notice title=Linux replacement::$phase at $now" >&2
  fi
  if [[ -n "${RUSTSCALE_LINUX_REPLACEMENT_PHASE_FILE:-}" ]]; then
    printf '%s\n' "$phase" >"$RUSTSCALE_LINUX_REPLACEMENT_PHASE_FILE"
  fi
}

run_bounded() {
  local seconds=$1 operation=$2 status
  shift 2
  echo "$LABEL $(timestamp) start: $operation (deadline=${seconds}s)" >&2
  if timeout --signal=TERM --kill-after=5s "${seconds}s" "$@"; then
    echo "$LABEL $(timestamp) finish: $operation" >&2
  else
    status=$?
    echo "$LABEL $(timestamp) ERROR: $operation failed (status=$status, deadline=${seconds}s)" >&2
    return "$status"
  fi
}

run_root_bounded() {
  local seconds=$1 operation=$2 status
  shift 2
  echo "$LABEL $(timestamp) start: $operation (root deadline=${seconds}s)" >&2
  if sudo -n timeout --signal=TERM --kill-after=5s "${seconds}s" "$@"; then
    echo "$LABEL $(timestamp) finish: $operation" >&2
  else
    status=$?
    echo "$LABEL $(timestamp) ERROR: $operation failed (status=$status, root deadline=${seconds}s)" >&2
    return "$status"
  fi
}

run_runner_supervised_bounded() {
  local seconds=$1 operation=$2 status runner_uid runner_gid
  shift 2
  runner_uid=$(id -u)
  runner_gid=$(id -g)
  echo "$LABEL $(timestamp) start: $operation (runner uid=$runner_uid, root-supervised deadline=${seconds}s)" >&2
  if sudo -n timeout --signal=TERM --kill-after=5s "${seconds}s" \
      setpriv --reuid="$runner_uid" --regid="$runner_gid" --init-groups -- \
        env "HOME=${HOME:-/tmp}" "PATH=$PATH" "$@"; then
    echo "$LABEL $(timestamp) finish: $operation" >&2
  else
    status=$?
    echo "$LABEL $(timestamp) ERROR: $operation failed (status=$status, root-supervised deadline=${seconds}s)" >&2
    return "$status"
  fi
}

run_as_user_bounded() {
  local user=$1 seconds=$2 operation=$3 status
  shift 3
  echo "$LABEL $(timestamp) start: $operation (user=$user deadline=${seconds}s)" >&2
  if sudo -n -u "$user" -- timeout --signal=TERM --kill-after=5s \
      "${seconds}s" "$@"; then
    echo "$LABEL $(timestamp) finish: $operation" >&2
  else
    status=$?
    echo "$LABEL $(timestamp) ERROR: $operation failed (status=$status, user=$user deadline=${seconds}s)" >&2
    return "$status"
  fi
}

case "$REQUIRE" in
  0|1) ;;
  *) echo "$LABEL ERROR: RUSTSCALE_REQUIRE_LINUX_REPLACEMENT must be 0 or 1" >&2; exit 2 ;;
esac

if [[ $# -ne 0 ]]; then
  echo "usage: tools/packaging/test-linux-replacement.sh" >&2
  exit 2
fi

os=$(uname -s)
[[ "$os" == Linux ]] || skip "requires Linux; found $os"

# Run the journey itself as the invoking user inside a root-manager-owned
# transient service. KillMode=control-group sends TERM to the runner shell and
# every current child so the shell can run its EXIT diagnostics/cleanup; after
# the bounded grace the system manager can kill every process in the cgroup
# regardless of uid. This closes the process-group privilege gap for sudo
# descendants.
if [[ "${RUSTSCALE_LINUX_REPLACEMENT_INNER:-0}" != 1 ]]; then
  for command_name in date id setpriv sudo systemctl systemd-run timeout; do
    command -v "$command_name" >/dev/null 2>&1 \
      || skip "required supervisor command '$command_name' is not available"
  done
  sudo -n true 2>/dev/null || skip "passwordless sudo is unavailable"

  deadline=${RUSTSCALE_LINUX_REPLACEMENT_TIMEOUT:-900}
  teardown_deadline=${RUSTSCALE_LINUX_REPLACEMENT_TEARDOWN_TIMEOUT:-90}
  for value_name in deadline teardown_deadline; do
    value=${!value_name}
    case "$value" in
      ''|*[!0-9]*) echo "$LABEL ERROR: $value_name must be a positive integer" >&2; exit 2 ;;
    esac
    (( value > 0 )) \
      || { echo "$LABEL ERROR: $value_name must be positive" >&2; exit 2; }
  done

  if ! wait_for_systemd_manager 60 supervisor sudo -n; then
    skip "systemd manager is unavailable for privileged cgroup supervision"
  fi

  unit="rustscale-linux-replacement-$(id -u)-$$.service"
  stop_supervised_unit() {
    trap - HUP INT TERM
    echo "$LABEL $(timestamp) supervisor: forcing $unit closed" >&2
    sudo -n timeout --signal=KILL 10s systemctl stop "$unit" >/dev/null 2>&1 || true
    sudo -n timeout --signal=KILL 10s \
      systemctl kill --kill-whom=all --signal=KILL "$unit" >/dev/null 2>&1 || true
  }
  trap 'stop_supervised_unit; exit 129' HUP
  trap 'stop_supervised_unit; exit 130' INT
  trap 'stop_supervised_unit; exit 143' TERM

  environment=(
    "HOME=${HOME:-/tmp}"
    "PATH=$PATH"
    "RUSTSCALE_LINUX_REPLACEMENT_INNER=1"
    "RUSTSCALE_REQUIRE_LINUX_REPLACEMENT=$REQUIRE"
    "RUSTSCALE_LINUX_REPLACEMENT_TIMEOUT=$deadline"
    "RUSTSCALE_LINUX_REPLACEMENT_TEARDOWN_TIMEOUT=$teardown_deadline"
  )
  for variable in CARGO_HOME CARGO_TARGET_DIR CI GITHUB_ACTIONS \
    RUSTUP_HOME RUSTFLAGS TMPDIR \
    CARGO_PROFILE_RELEASE_LTO CARGO_PROFILE_RELEASE_CODEGEN_UNITS \
    CARGO_PROFILE_RELEASE_OPT_LEVEL RUSTSCALE_LINUX_REPLACEMENT_PHASE_FILE; do
    if [[ -n "${!variable:-}" ]]; then
      environment+=("$variable=${!variable}")
    fi
  done

  echo "$LABEL $(timestamp) supervisor: unit=$unit run=${deadline}s teardown=${teardown_deadline}s uid=$(id -u)" >&2
  set +e
  sudo -n systemd-run --quiet --wait --pipe --collect \
    --unit="$unit" --service-type=exec \
    --uid="$(id -u)" --gid="$(id -g)" --working-directory="$ROOT" \
    --property="RuntimeMaxSec=${deadline}s" \
    --property="TimeoutStopSec=${teardown_deadline}s" \
    --property=KillMode=control-group --property=SendSIGKILL=yes \
    /usr/bin/env "${environment[@]}" \
      bash "$ROOT/tools/packaging/test-linux-replacement.sh"
  status=$?
  set -e
  trap - HUP INT TERM
  if sudo -n timeout --signal=KILL 5s systemctl is-active --quiet "$unit" 2>/dev/null; then
    echo "$LABEL $(timestamp) ERROR: supervised unit remained active after systemd-run" >&2
    stop_supervised_unit
    [[ "$status" != 0 ]] || status=1
  fi
  exit "$status"
fi

record_phase preflight
for command_name in awk cargo cmp cp curl date find getconf go grep id install ip journalctl \
  mktemp ps python3 readlink sed setpriv sha256sum sudo systemctl systemd-run tail tar \
  tee timeout tr wc; do
  command -v "$command_name" >/dev/null 2>&1 \
    || skip "required command '$command_name' is not available"
done

if ! sudo -n true 2>/dev/null; then
  skip "passwordless sudo is unavailable"
fi
if ! wait_for_systemd_manager 60 journey; then
  skip "systemd manager did not become ready for the installed journey"
fi
[[ -c /dev/net/tun ]] || skip "/dev/net/tun is not a character device"
if ! getconf GNU_LIBC_VERSION >/dev/null 2>&1; then
  skip "the installed service journey requires the GNU/Linux release artifact"
fi
if ! id nobody >/dev/null 2>&1; then
  skip "the unrelated LocalAPI identity 'nobody' is unavailable"
fi

case "$(uname -m)" in
  x86_64|amd64)
    MACHINE=x86_64
    ARCHIVE=rustscale-x86_64-unknown-linux-gnu.tar.gz
    ;;
  aarch64|arm64)
    MACHINE=aarch64
    ARCHIVE=rustscale-aarch64-unknown-linux-gnu.tar.gz
    ;;
  *) skip "unsupported Linux architecture $(uname -m)" ;;
esac

# This journey intentionally owns the standard RustScale installation and TUN
# names. Refuse an occupied host before creating any fixture or root-owned file.
for command_name in rustscale rustscaled tailscale tailscaled; do
  if command -v "$command_name" >/dev/null 2>&1; then
    skip "command '$command_name' already exists at $(command -v "$command_name")"
  fi
done
if timeout --signal=KILL 5s systemctl cat rustscaled.service >/dev/null 2>&1; then
  skip "rustscaled.service already exists"
fi
for path in \
  /usr/local/bin/rustscale \
  /usr/local/bin/rustscaled \
  /usr/local/bin/tailscale \
  /usr/local/bin/tailscaled \
  /usr/local/bin/.rustscale-install-receipt-v1 \
  /usr/local/lib/librustscale.so \
  /usr/local/lib/librustscale.a \
  /usr/local/include/rustscale.h \
  /etc/systemd/system/rustscaled.service \
  /etc/systemd/system/rustscaled.service.d \
  /etc/default/rustscaled \
  /etc/default/rustscaled-install-journey \
  /etc/rustscale-install-journey.json \
  /var/lib/rustscale \
  /var/cache/rustscale \
  /run/rustscale \
  /var/run/rustscaled.sock \
  /var/lib/tailscale \
  /run/tailscale \
  /var/run/tailscaled.sock \
  /sys/class/net/tun0; do
  if [[ -e "$path" || -L "$path" ]]; then
    skip "safety path already exists: $path"
  fi
done
if timeout --signal=KILL 5s ip -4 -details rule show | grep -q 'proto 201' \
    || timeout --signal=KILL 5s ip -6 -details rule show | grep -q 'proto 201'; then
  skip "an existing protocol-201 policy rule makes cleanup attribution ambiguous"
fi

if ! tun_preflight=$(run_bounded 30 real-tun-preflight \
    "$ROOT/tools/interop-tun-preflight.sh" 2>&1); then
  tun_preflight=${tun_preflight//$'\n'/'; '}
  skip "Linux TUN preflight failed: $tun_preflight"
fi
echo "$tun_preflight" >&2

TMP=$(mktemp -d "${TMPDIR:-/tmp}/rustscale-linux-replacement.XXXXXX")
CONTROL_PID=
GO_PID=
ECHO_PID=
INSTALL_STARTED=0
OFFICIAL_SENTINELS=0
RULE_BASE=
JOURNEY_FINISHED=0
CONFIG_PATH=/etc/rustscale-install-journey.json
DROPIN_DIR=/etc/systemd/system/rustscaled.service.d
JOURNEY_ENV=/etc/default/rustscaled-install-journey
PREFIX=/usr/local
DEFAULT_SOCKET=/var/run/rustscaled.sock
TUN_NAME=tun0
# The credential-free readiness test has independently attributable names.
# Keep them in the journey tempdir and reject collisions before it can mutate
# the kernel, so the EXIT fallback can safely remove only this journey's state.
DNS_TUN_NAME="rsdns-$$"
DNS_SOCKET="$TMP/required-tun-dns.sock"
[[ ${#DNS_TUN_NAME} -le 15 ]] \
  || { echo "$LABEL ERROR: required TUN DNS interface name is too long: $DNS_TUN_NAME" >&2; exit 1; }
[[ ! -e "/sys/class/net/$DNS_TUN_NAME" ]] \
  || skip "required TUN DNS interface already exists: $DNS_TUN_NAME"
[[ ! -e "$DNS_SOCKET" && ! -L "$DNS_SOCKET" ]] \
  || skip "required TUN DNS LocalAPI socket already exists: $DNS_SOCKET"
DNS_BASELINE_TARGET=$(readlink -f /etc/resolv.conf)
cp -L /etc/resolv.conf "$TMP/resolv.conf.baseline"

stop_pid() {
  local pid=$1 label=$2
  echo "$LABEL $(timestamp) cleanup: stop $label (deadline=4s)" >&2
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 0
  if kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
    for _ in {1..30}; do
      kill -0 "$pid" 2>/dev/null || break
      if [[ -r "/proc/$pid/stat" ]] \
          && [[ "$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null)" == Z ]]; then
        break
      fi
      sleep 0.1
    done
    if kill -0 "$pid" 2>/dev/null; then
      echo "$LABEL cleanup: killing stuck $label process $pid" >&2
      kill -KILL "$pid" 2>/dev/null || true
    fi
  fi
  wait "$pid" 2>/dev/null || true
}

uninstall_release() {
  run_runner_supervised_bounded 30 public-uninstall \
    env INSTALL_SERVICE=1 PREFIX="$PREFIX" RUSTSCALE_UNAME_S=Linux \
      RUSTSCALE_UNAME_M="$MACHINE" RUSTSCALE_LIBC=gnu \
      sh "$ROOT/scripts/install.sh" --uninstall
}

run_required_tun_dns_failure_gate() {
  local test_json selected_count
  local -a test_bins

  # Compile as the journey runner, not root. Cargo's JSON is the sole source
  # for the libtest executable; reject ambiguity rather than selecting first.
  test_json="$TMP/required-tun-dns-test.json"
  run_bounded 300 required-tun-dns-build \
    cargo test -p rustscale-tsnet --lib --no-run --message-format=json >"$test_json"
  mapfile -t test_bins < <(python3 - "$test_json" <<'PYTHON'
import json
import sys

matches = []
for line in open(sys.argv[1], encoding="utf-8"):
    try:
        item = json.loads(line)
    except json.JSONDecodeError:
        continue
    target = item.get("target", {})
    if (item.get("profile", {}).get("test")
            and target.get("name") == "rustscale_tsnet"
            and "lib" in target.get("kind", [])
            and item.get("executable")):
        matches.append(item["executable"])
if len(matches) == 1:
    print(matches[0])
else:
    raise SystemExit(f"expected one rustscale_tsnet libtest executable, found {len(matches)}")
PYTHON
)
  if [[ ${#test_bins[@]} != 1 || ! -x "${test_bins[0]:-}" ]]; then
    echo "$LABEL ERROR: required TUN DNS gate could not resolve one executable" >&2
    return 1
  fi
  TEST_BIN=${test_bins[0]}

  selected_count=$("$TEST_BIN" --ignored --list \
    | grep -Fxc 'tests::interop_tun_rust_dials_go: test' || true)
  if [[ "$selected_count" != 1 ]]; then
    echo "$LABEL ERROR: required TUN DNS exact selector matched $selected_count tests (expected 1)" >&2
    return 1
  fi

  # This is intentionally a dedicated mode of the existing reviewed selector.
  # It neither receives nor can fall through to the secret-backed interop path.
  echo "$LABEL $(timestamp) start: required TUN DNS readiness (root deadline=180s)" >&2
  if ! sudo -n timeout --signal=TERM --kill-after=5s 180s \
      env RUSTSCALE_REQUIRED_TUN_DNS_FAILURE=1 \
        RUSTSCALE_REQUIRED_TUN_DNS_TUN_NAME="$DNS_TUN_NAME" \
        RUSTSCALE_REQUIRED_TUN_DNS_SOCKET="$DNS_SOCKET" \
      sh -ceu '
        test "$(uname -s)" = Linux || { echo "required TUN DNS gate requires Linux" >&2; exit 1; }
        test "$(id -u)" -eq 0 || { echo "required TUN DNS gate did not run as root" >&2; exit 1; }
        test -c /dev/net/tun || { echo "required TUN DNS gate requires /dev/net/tun" >&2; exit 1; }
        command -v ip >/dev/null || { echo "required TUN DNS gate requires ip" >&2; exit 1; }
        test "${RUSTSCALE_REQUIRED_TUN_DNS_FAILURE:-}" = 1 || exit 1
        test -n "${RUSTSCALE_REQUIRED_TUN_DNS_TUN_NAME:-}" || exit 1
        test -n "${RUSTSCALE_REQUIRED_TUN_DNS_SOCKET:-}" || exit 1
        exec "$@"
      ' sh "$TEST_BIN" \
      --ignored --exact tests::interop_tun_rust_dials_go \
      --nocapture --test-threads=1; then
    echo "$LABEL ERROR: required TUN DNS readiness gate failed" >&2
    return 1
  fi
  echo "$LABEL $(timestamp) finish: required TUN DNS readiness" >&2
}

# Last-resort host restoration for an interrupted or wedged service stop. The
# preflight rejects every one of these names/selectors before the journey, so
# this removes only state attributable to this isolated run. Successful journey
# assertions happen before this function can be used.
emergency_kernel_cleanup() {
  local family preference table ifindex rules tun_name socket_name
  sudo -n timeout --signal=KILL 5s \
    systemctl kill --kill-whom=all --signal=KILL rustscaled.service \
    >/dev/null 2>&1 || true
  if [[ -z "$RULE_BASE" && -r "/sys/class/net/$TUN_NAME/ifindex" ]]; then
    ifindex=$(<"/sys/class/net/$TUN_NAME/ifindex")
    if [[ "$ifindex" =~ ^[1-9][0-9]*$ ]]; then
      RULE_BASE=$((5000 + (ifindex % 200) * 100))
    fi
  fi
  if [[ -n "$RULE_BASE" ]]; then
    for family in -4 -6; do
      for preference in $((RULE_BASE + 70)) $((RULE_BASE + 50)) \
        $((RULE_BASE + 30)) $((RULE_BASE + 10)); do
        case "$preference" in
          $((RULE_BASE + 70)))
            sudo -n timeout --signal=KILL 3s \
              ip "$family" rule del pref "$preference" protocol 201 table 52 \
              >/dev/null 2>&1 || true
            ;;
          $((RULE_BASE + 50)))
            sudo -n timeout --signal=KILL 3s \
              ip "$family" rule del pref "$preference" \
              fwmark 0x80000/0xff0000 protocol 201 type unreachable \
              >/dev/null 2>&1 || true
            ;;
          *)
            table=main
            [[ "$preference" == $((RULE_BASE + 30)) ]] && table=default
            sudo -n timeout --signal=KILL 3s \
              ip "$family" rule del pref "$preference" \
              fwmark 0x80000/0xff0000 protocol 201 table "$table" \
              >/dev/null 2>&1 || true
            ;;
        esac
      done
    done
    sudo -n timeout --signal=KILL 3s \
      rm -f "/run/rustscale/rule-owners/$RULE_BASE" || true
  fi
  # Preflight proved that no protocol-201 rule existed before this journey.
  # Sweep every such rule so an interrupted restart with a new TUN ifindex
  # cannot leave either generation's chain or emergency direct-traffic block.
  for family in -4 -6; do
    for _ in {1..16}; do
      rules=$(timeout --signal=KILL 3s ip "$family" -details rule show 2>/dev/null || true)
      preference=$(printf '%s\n' "$rules" \
        | awk '/proto 201([[:space:]]|$)/ {sub(":", "", $1); print $1; exit}')
      [[ "$preference" =~ ^[0-9]+$ ]] || break
      sudo -n timeout --signal=KILL 3s \
        ip "$family" rule del pref "$preference" protocol 201 \
        >/dev/null 2>&1 || break
    done
  done
  sudo -n timeout --signal=KILL 3s \
    rm -rf /run/rustscale/rule-owners >/dev/null 2>&1 || true
  for tun_name in "$TUN_NAME" "$DNS_TUN_NAME"; do
    sudo -n timeout --signal=KILL 3s \
      ip link delete dev "$tun_name" >/dev/null 2>&1 || true
  done
  for socket_name in "$DEFAULT_SOCKET" "$DNS_SOCKET"; do
    sudo -n timeout --signal=KILL 3s rm -f "$socket_name" || true
  done
}

assert_kernel_clean() {
  local socket_must_be_absent=${1:-yes}
  local leaked=0 family rules preference routes
  local tun_name socket_name
  for tun_name in "$TUN_NAME" "$DNS_TUN_NAME"; do
    if [[ -e "/sys/class/net/$tun_name" ]]; then
      echo "$LABEL cleanup leak: interface $tun_name still exists" >&2
      leaked=1
    fi
  done
  if [[ "$socket_must_be_absent" == yes ]]; then
    for socket_name in "$DEFAULT_SOCKET" "$DNS_SOCKET"; do
      if [[ -e "$socket_name" || -L "$socket_name" ]]; then
        echo "$LABEL cleanup leak: LocalAPI path $socket_name still exists" >&2
        leaked=1
      fi
    done
  fi
  if [[ -n "$RULE_BASE" ]]; then
    for family in -4 -6; do
      rules=$(timeout --signal=KILL 3s ip "$family" -details rule show 2>/dev/null || true)
      for preference in $((RULE_BASE + 10)) $((RULE_BASE + 30)) \
        $((RULE_BASE + 50)) $((RULE_BASE + 70)); do
        if printf '%s\n' "$rules" \
          | grep -E "^[[:space:]]*${preference}:.*proto 201([[:space:]]|$)" >/dev/null; then
          echo "$LABEL cleanup leak: IPv${family#-} rule $preference remains" >&2
          leaked=1
        fi
      done
    done
    if [[ -e "/run/rustscale/rule-owners/$RULE_BASE" \
        || -L "/run/rustscale/rule-owners/$RULE_BASE" ]]; then
      echo "$LABEL cleanup leak: policy-rule owner record $RULE_BASE remains" >&2
      leaked=1
    fi
  fi
  for family in -4 -6; do
    rules=$(timeout --signal=KILL 3s ip "$family" -details rule show 2>/dev/null || true)
    if printf '%s\n' "$rules" | grep -E 'proto 201([[:space:]]|$)' >/dev/null; then
      echo "$LABEL cleanup leak: IPv${family#-} protocol-201 rule remains" >&2
      leaked=1
    fi
  done
  routes=$(timeout --signal=KILL 3s ip -4 route show table 52 2>/dev/null || true)
  for tun_name in "$TUN_NAME" "$DNS_TUN_NAME"; do
    if printf '%s\n' "$routes" | grep -F "dev $tun_name" >/dev/null; then
      echo "$LABEL cleanup leak: table 52 still routes through $tun_name" >&2
      leaked=1
    fi
  done
  [[ "$leaked" == 0 ]]
}

verify_official_sentinels() {
  [[ "$OFFICIAL_SENTINELS" == 1 ]] || return 0
  local expected='official-tailscale-state-must-not-change'
  [[ "$(sudo -n timeout --signal=KILL 3s cat /var/lib/tailscale/.rustscale-install-journey 2>/dev/null || true)" == "$expected" ]] \
    || { echo "$LABEL official state sentinel changed" >&2; return 1; }
  [[ "$(sudo -n timeout --signal=KILL 3s cat /run/tailscale/.rustscale-install-journey 2>/dev/null || true)" == "$expected" ]] \
    || { echo "$LABEL official runtime sentinel changed" >&2; return 1; }
  [[ "$(sudo -n timeout --signal=KILL 3s find /var/lib/tailscale -mindepth 1 -maxdepth 1 -print 2>/dev/null | wc -l | tr -d ' ')" == 1 ]] \
    || { echo "$LABEL official state directory gained unexpected entries" >&2; return 1; }
  [[ "$(sudo -n timeout --signal=KILL 3s find /run/tailscale -mindepth 1 -maxdepth 1 -print 2>/dev/null | wc -l | tr -d ' ')" == 1 ]] \
    || { echo "$LABEL official runtime directory gained unexpected entries" >&2; return 1; }
}

capture_failure_diagnostics() {
  local log_file
  echo "$LABEL $(timestamp) diagnostics: failure in phase=$CURRENT_PHASE" >&2
  if [[ "$INSTALL_STARTED" == 1 ]]; then
    sudo -n timeout --signal=KILL 8s \
      systemctl status rustscaled.service --no-pager >&2 || true
    sudo -n timeout --signal=KILL 8s \
      systemctl show rustscaled.service \
        -p ActiveState -p SubState -p Result -p MainPID -p ControlPID >&2 || true
    sudo -n timeout --signal=KILL 10s \
      journalctl -u rustscaled.service -n 120 --no-pager >&2 || true
    timeout --signal=KILL 5s \
      /usr/local/bin/tailscale status --json >&2 || true
  fi
  timeout --signal=KILL 5s ip -brief link show >&2 || true
  timeout --signal=KILL 5s ip -4 -details rule show >&2 || true
  timeout --signal=KILL 5s ip -4 route show table 52 >&2 || true
  timeout --signal=KILL 5s ps -eo pid,ppid,pgid,sid,uid,stat,comm,args >&2 || true
  for log_file in testcontrol.log go-tailscaled.log echo.log install.log uninstall.log; do
    if [[ -f "$TMP/$log_file" ]]; then
      echo "$LABEL diagnostics: tail $log_file" >&2
      tail -n 120 "$TMP/$log_file" >&2 || true
    fi
  done
  echo "$LABEL $(timestamp) diagnostics: capture complete" >&2
}

cleanup() {
  local primary_status=$? cleanup_failed=0 alias target
  trap - EXIT INT TERM
  set +e

  # Preserve the original failure while every cleanup stage runs. A successful
  # later stage must never mask either that failure or an earlier cleanup leak.
  if [[ "$primary_status" != 0 ]]; then
    capture_failure_diagnostics
  fi
  echo "$LABEL $(timestamp) cleanup: begin (deadline=${RUSTSCALE_LINUX_REPLACEMENT_TEARDOWN_TIMEOUT:-90}s)" >&2

  if [[ "$INSTALL_STARTED" == 1 ]]; then
    if ! run_root_bounded 20 cleanup-stop-service \
        systemctl disable --now rustscaled.service >/dev/null 2>&1; then
      cleanup_failed=1
      emergency_kernel_cleanup
    fi
    run_runner_supervised_bounded 20 cleanup-uninstall \
      env INSTALL_SERVICE=1 PREFIX="$PREFIX" RUSTSCALE_UNAME_S=Linux \
        RUSTSCALE_UNAME_M="$MACHINE" RUSTSCALE_LIBC=gnu \
        sh "$ROOT/scripts/install.sh" --uninstall >/dev/null 2>&1 \
      || cleanup_failed=1
    # Failure fallback. Safety preflight proved these names were free before
    # this journey set INSTALL_STARTED.
    run_root_bounded 5 cleanup-public-files rm -f \
      /etc/systemd/system/rustscaled.service /etc/default/rustscaled \
      "$DROPIN_DIR/10-rustscale-install-journey.conf" "$JOURNEY_ENV" \
      "$PREFIX/bin/rustscale" "$PREFIX/bin/rustscaled" \
      "$PREFIX/bin/.rustscale-install-receipt-v1" \
      "$PREFIX/lib/librustscale.so" "$PREFIX/lib/librustscale.a" \
      "$PREFIX/include/rustscale.h" || cleanup_failed=1
    run_root_bounded 5 cleanup-drop-in rmdir "$DROPIN_DIR" >/dev/null 2>&1 || true
    run_root_bounded 5 cleanup-daemon-reload systemctl daemon-reload \
      >/dev/null 2>&1 || cleanup_failed=1
    for alias in tailscale tailscaled; do
      target=rustscale
      [[ "$alias" == tailscaled ]] && target=rustscaled
      if [[ -L "$PREFIX/bin/$alias" ]] \
          && [[ "$(readlink "$PREFIX/bin/$alias")" == "$target" ]]; then
        run_root_bounded 3 "cleanup-$alias-alias" rm -f "$PREFIX/bin/$alias" \
          || cleanup_failed=1
      fi
    done
  fi

  stop_pid "$GO_PID" 'Go tailscaled'
  stop_pid "$ECHO_PID" 'echo backend'
  stop_pid "$CONTROL_PID" testcontrol

  if ! assert_kernel_clean; then
    cleanup_failed=1
    # This also owns the dedicated readiness mode's names, even when it
    # failed before the install phase set INSTALL_STARTED.
    emergency_kernel_cleanup || cleanup_failed=1
    assert_kernel_clean || cleanup_failed=1
  fi
  if [[ "$INSTALL_STARTED" == 1 ]]; then
    run_root_bounded 8 cleanup-rustscale-state rm -rf \
      "$CONFIG_PATH" "$JOURNEY_ENV" \
      "$DROPIN_DIR/10-rustscale-install-journey.conf" \
      /var/lib/rustscale /var/cache/rustscale /run/rustscale \
      || cleanup_failed=1
    run_root_bounded 3 cleanup-empty-drop-in rmdir "$DROPIN_DIR" \
      >/dev/null 2>&1 || true
  fi

  if ! verify_official_sentinels; then
    cleanup_failed=1
  fi
  if [[ "$OFFICIAL_SENTINELS" == 1 ]]; then
    run_root_bounded 5 cleanup-official-sentinels rm -f \
      /var/lib/tailscale/.rustscale-install-journey \
      /run/tailscale/.rustscale-install-journey || cleanup_failed=1
    run_root_bounded 5 cleanup-official-directories \
      rmdir /var/lib/tailscale /run/tailscale >/dev/null 2>&1 \
      || cleanup_failed=1
  fi

  run_bounded 5 cleanup-temporary-files rm -rf "$TMP" || cleanup_failed=1
  if [[ "$cleanup_failed" != 0 ]]; then
    echo "$LABEL $(timestamp) ERROR: bounded cleanup did not restore the isolated host" >&2
  elif [[ "$JOURNEY_FINISHED" == 1 ]]; then
    echo "$LABEL $(timestamp) cleanup: service, processes, fixture state, and sentinels removed" >&2
  fi
  if [[ "$primary_status" != 0 ]]; then
    exit "$primary_status"
  fi
  [[ "$cleanup_failed" == 0 ]] || exit 1
  exit 0
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

backend_state() {
  python3 -c 'import json,sys; print(json.load(sys.stdin).get("BackendState", ""))'
}

status_ip() {
  python3 -c 'import json,sys; values=json.load(sys.stdin).get("TailscaleIPs") or []; print(next((value for value in values if "." in value), ""))'
}

wait_backend() {
  local expected=$1 seconds=${2:-60} output state deadline
  deadline=$((SECONDS + seconds))
  echo "$LABEL $(timestamp) wait: LocalAPI BackendState=$expected (deadline=${seconds}s)" >&2
  while (( SECONDS < deadline )); do
    if output=$(timeout --signal=KILL 3s \
        /usr/local/bin/tailscale status --json 2>/dev/null); then
      state=$(printf '%s' "$output" | backend_state 2>/dev/null || true)
      if [[ "$state" == "$expected" ]]; then
        printf '%s' "$output"
        return 0
      fi
    fi
    # Restart=always has an intentional inactive transition between the
    # logout generation and its fresh NeedsLogin generation. Do not mistake
    # that bounded handoff for a terminal service failure.
    timeout --signal=KILL 3s systemctl is-active --quiet rustscaled.service || true
    sleep 0.25
  done
  echo "$LABEL $(timestamp) ERROR: timed out waiting for LocalAPI BackendState=$expected" >&2
  timeout --signal=KILL 5s systemctl status rustscaled.service --no-pager >&2 || true
  return 1
}

node_count() {
  curl --max-time 2 -fsS "$CONTROL_URL/testapi/nodes" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["count"])'
}

wait_node_count() {
  local wanted=$1 seconds=${2:-30} count='' deadline
  deadline=$((SECONDS + seconds))
  echo "$LABEL $(timestamp) wait: testcontrol nodes >= $wanted (deadline=${seconds}s)" >&2
  while (( SECONDS < deadline )); do
    count=$(node_count 2>/dev/null || true)
    if [[ "$count" =~ ^[0-9]+$ ]] && (( count >= wanted )); then
      echo "$count"
      return 0
    fi
    sleep 0.25
  done
  echo "$LABEL $(timestamp) ERROR: testcontrol did not reach $wanted nodes (last=${count:-unavailable})" >&2
  return 1
}

write_config() {
  local include_key=$1 output=$2
  python3 - "$CONTROL_URL" "$OPERATOR" "$include_key" >"$output" <<'PY'
import json
import sys
value = {
    "Version": "alpha0",
    "ServerURL": sys.argv[1],
    "Hostname": "rustscale-installed-journey",
    "OperatorUser": sys.argv[2],
}
if sys.argv[3] == "yes":
    value["AuthKey"] = "tskey-testcontrol"
json.dump(value, sys.stdout, separators=(",", ":"))
sys.stdout.write("\n")
PY
}

# Run the credential-free real-TUN readiness contract before the install
# mutates system state. Its exact ignored selector cannot report a zero-test
# success and its fallback cleanup remains attributable to this journey.
record_phase required-tun-dns-readiness
run_required_tun_dns_failure_gate
assert_kernel_clean

# Build every artifact before touching system state.
record_phase rust-release-build
echo "$LABEL building real release binaries and libraries" >&2
run_bounded 600 rust-release-build \
  cargo build --release --locked \
    -p rustscale-cli -p rustscale-rustscaled -p rustscale-ffi

record_phase pinned-go-build
TESTCONTROL_BIN="$TMP/testcontrol"
GO_CLIENT_DIR="$TMP/go-client"
run_bounded 300 pinned-go-build \
  env TESTCONTROL_OUTPUT="$TESTCONTROL_BIN" TESTCONTROL_GO_CLIENT_DIR="$GO_CLIENT_DIR" \
    "$ROOT/tools/testcontrol/build.sh"
GO_CLI="$GO_CLIENT_DIR/tailscale"
GO_DAEMON="$GO_CLIENT_DIR/tailscaled"
GO_VERSION=$(timeout --signal=KILL 10s "$GO_CLI" version | sed -n '1p')
[[ "$GO_VERSION" == 1.100.0* ]] \
  || { echo "$LABEL ERROR: unexpected pinned Go client version: $GO_VERSION" >&2; exit 1; }

VERSION=$(awk '
  /^\[workspace.package\]/ { workspace = 1; next }
  workspace && /^version = / { gsub(/[" ]/, "", $3); print $3; exit }
' "$ROOT/Cargo.toml")
[[ -n "$VERSION" ]] || { echo "$LABEL ERROR: workspace version not found" >&2; exit 1; }
RELEASE_DIR="$TMP/releases/download/v$VERSION"
STAGE="$TMP/stage"
mkdir -p "$RELEASE_DIR" "$STAGE"
install -m 755 "$ROOT/target/release/rustscale" "$STAGE/rustscale"
install -m 755 "$ROOT/target/release/rustscaled" "$STAGE/rustscaled"
install -m 755 "$ROOT/target/release/librustscale.so" "$STAGE/librustscale.so"
install -m 644 "$ROOT/target/release/librustscale.a" "$STAGE/librustscale.a"
install -m 644 "$ROOT/include/rustscale.h" "$STAGE/rustscale.h"
install -m 644 "$ROOT/packaging/systemd/rustscaled.service" "$STAGE/rustscaled.service"
install -m 644 "$ROOT/packaging/systemd/rustscaled.default" "$STAGE/rustscaled.default"
install -m 644 "$ROOT/LICENSE" "$STAGE/LICENSE"
run_bounded 30 package-release-archive \
  tar --format=ustar -czf "$RELEASE_DIR/$ARCHIVE" -C "$STAGE" .
printf '%s  %s\n' "$(sha256sum "$RELEASE_DIR/$ARCHIVE" | awk '{print $1}')" "$ARCHIVE" \
  >"$RELEASE_DIR/SHA256SUMS"

# Start the standalone pinned-Go control plane and retain all logs for a failed
# run without writing generated binaries into the checkout.
record_phase control-start
"$TESTCONTROL_BIN" >"$TMP/testcontrol.url" 2>"$TMP/testcontrol.log" &
CONTROL_PID=$!
CONTROL_URL=
for _ in {1..200}; do
  if [[ -s "$TMP/testcontrol.url" ]]; then
    IFS= read -r CONTROL_URL <"$TMP/testcontrol.url" || true
    [[ -n "$CONTROL_URL" ]] && break
  fi
  kill -0 "$CONTROL_PID" 2>/dev/null \
    || { cat "$TMP/testcontrol.log" >&2; echo "$LABEL ERROR: testcontrol exited" >&2; exit 1; }
  sleep 0.05
done
[[ "$CONTROL_URL" =~ ^http://127[.]0[.]0[.]1:[1-9][0-9]*$ ]] \
  || { echo "$LABEL ERROR: invalid testcontrol URL '$CONTROL_URL'" >&2; exit 1; }
curl --max-time 2 -fsS "$CONTROL_URL/testapi/health" >/dev/null

# Place canaries in the official Tailscale state locations. Compatibility
# aliases must remain command-name shims only; RustScale uses its own unit,
# state directory, and LocalAPI socket.
printf '%s\n' 'official-tailscale-state-must-not-change' >"$TMP/official-sentinel"
run_root_bounded 10 install-official-sentinels \
  install -d -m 700 /var/lib/tailscale /run/tailscale
run_root_bounded 10 install-official-state-sentinel \
  install -m 600 "$TMP/official-sentinel" \
    /var/lib/tailscale/.rustscale-install-journey
run_root_bounded 10 install-official-runtime-sentinel \
  install -m 600 "$TMP/official-sentinel" \
    /run/tailscale/.rustscale-install-journey
OFFICIAL_SENTINELS=1

OPERATOR=$(id -un)
INSTALL_STARTED=1

# Keep the first installed startup local and log-upload-free without modifying
# either checked-in systemd artifact. The test-only drop-in resets the base
# EnvironmentFile list, supplies a no-key local config, and leaves ExecStart
# unchanged. The public uninstaller handles the public files; trap cleanup owns
# only this drop-in and its environment file.
write_config no "$TMP/config-without-key.json"
run_root_bounded 10 install-keyless-config \
  install -m 600 "$TMP/config-without-key.json" "$CONFIG_PATH"
printf 'FLAGS="--config %s --no-logs-no-support"\n' "$CONFIG_PATH" \
  >"$TMP/rustscaled-install-journey.env"
cat >"$TMP/rustscaled-install-journey.conf" <<EOF
[Service]
EnvironmentFile=
EnvironmentFile=$JOURNEY_ENV
EOF
run_root_bounded 10 install-journey-environment \
  install -m 644 "$TMP/rustscaled-install-journey.env" "$JOURNEY_ENV"
run_root_bounded 10 create-service-drop-in install -d -m 755 "$DROPIN_DIR"
run_root_bounded 10 install-service-drop-in \
  install -m 644 "$TMP/rustscaled-install-journey.conf" \
    "$DROPIN_DIR/10-rustscale-install-journey.conf"

record_phase install-and-first-start
echo "$LABEL installing archive with explicit aliases and shipped systemd service" >&2
run_runner_supervised_bounded 120 archive-install \
  env INSTALL_SERVICE=1 PREFIX="$PREFIX" \
    RUSTSCALE_RELEASE_BASE="file://$TMP/releases" \
    RUSTSCALE_HTTP_CLIENT=curl RUSTSCALE_UNAME_S=Linux \
    RUSTSCALE_UNAME_M="$MACHINE" RUSTSCALE_LIBC=gnu \
    sh "$ROOT/scripts/install.sh" --version "$VERSION" --tailscale-compatible \
  | tee "$TMP/install.log"

[[ "$(readlink /usr/local/bin/tailscale)" == rustscale ]]
[[ "$(readlink /usr/local/bin/tailscaled)" == rustscaled ]]
[[ "$(sha256sum /usr/local/bin/rustscale | awk '{print $1}')" \
   == "$(sha256sum "$STAGE/rustscale" | awk '{print $1}')" ]]
[[ "$(sha256sum /usr/local/bin/rustscaled | awk '{print $1}')" \
   == "$(sha256sum "$STAGE/rustscaled" | awk '{print $1}')" ]]
[[ "$(sha256sum /usr/local/lib/librustscale.so | awk '{print $1}')" \
   == "$(sha256sum "$STAGE/librustscale.so" | awk '{print $1}')" ]]
[[ "$(sha256sum /usr/local/lib/librustscale.a | awk '{print $1}')" \
   == "$(sha256sum "$STAGE/librustscale.a" | awk '{print $1}')" ]]
[[ "$(sha256sum /usr/local/include/rustscale.h | awk '{print $1}')" \
   == "$(sha256sum "$STAGE/rustscale.h" | awk '{print $1}')" ]]
[[ "$(sha256sum /etc/default/rustscaled | awk '{print $1}')" \
   == "$(sha256sum "$STAGE/rustscaled.default" | awk '{print $1}')" ]]
run_bounded 5 verify-service-enabled systemctl is-enabled --quiet rustscaled.service
run_bounded 5 verify-service-active systemctl is-active --quiet rustscaled.service
initial_status=$(wait_backend NeedsLogin)
[[ -S "$DEFAULT_SOCKET" ]]
[[ "$(printf '%s' "$initial_status" | backend_state)" == NeedsLogin ]]
verify_official_sentinels

# Point the exact shipped service at local testcontrol and enroll with its
# documented test key. The key is removed before persistence is tested.
record_phase rust-node-enrollment
write_config yes "$TMP/config-with-key.json"
run_root_bounded 10 install-enrollment-config \
  install -m 600 "$TMP/config-with-key.json" "$CONFIG_PATH"
run_root_bounded 45 restart-for-enrollment systemctl restart rustscaled.service
running_status=$(wait_backend Running 80)
RUST_IP=$(printf '%s' "$running_status" | status_ip)
[[ "$RUST_IP" == 100.* ]] \
  || { echo "$LABEL ERROR: enrolled Rust node has invalid IP '$RUST_IP'" >&2; exit 1; }
[[ "$(wait_node_count 1)" -ge 1 ]]
curl --max-time 2 -fsS "$CONTROL_URL/testapi/nodes" \
  | python3 -c 'import json,sys; wanted=sys.argv[1]; data=json.load(sys.stdin); raise SystemExit(0 if any((node.get("ip") or "").split("/", 1)[0] == wanted for node in data["nodes"]) else 1)' \
      "$RUST_IP"
[[ -S "$DEFAULT_SOCKET" ]]

# Exercise kernel peer credentials through the default LocalAPI socket.
run_as_user_bounded nobody 10 unrelated-status \
  /usr/local/bin/tailscale status --json >/dev/null
echo "$LABEL $(timestamp) start: unrelated-logout denial (deadline=10s)" >&2
if nobody_logout=$(sudo -n -u nobody -- timeout --signal=TERM --kill-after=5s \
    10s /usr/local/bin/tailscale logout 2>&1); then
  echo "$LABEL ERROR: unrelated LocalAPI identity performed logout" >&2
  exit 1
fi
echo "$LABEL $(timestamp) finish: unrelated-logout denied" >&2
printf '%s\n' "$nobody_logout" >"$TMP/nobody-logout.out"
grep -q 'access denied' "$TMP/nobody-logout.out"

# Prove the installed service owns a live Linux TUN and its interface-derived
# protocol-201 policy chain.
[[ -d "/sys/class/net/$TUN_NAME" ]]
ifindex=$(<"/sys/class/net/$TUN_NAME/ifindex")
flags=$(<"/sys/class/net/$TUN_NAME/flags")
mtu=$(<"/sys/class/net/$TUN_NAME/mtu")
[[ "$ifindex" =~ ^[1-9][0-9]*$ ]]
(( (16#${flags#0x} & 1) != 0 ))
[[ "$mtu" == 1280 ]]
RULE_BASE=$((5000 + (ifindex % 200) * 100))
rules=$(timeout --signal=KILL 5s ip -4 -details rule show)
for expectation in \
  "$((RULE_BASE + 10)):lookup main" \
  "$((RULE_BASE + 30)):lookup default" \
  "$((RULE_BASE + 50)):unreachable" \
  "$((RULE_BASE + 70)):lookup 52"; do
  preference=${expectation%%:*}
  target=${expectation#*:}
  rule=$(printf '%s\n' "$rules" \
    | grep -E "^[[:space:]]*${preference}:.*proto 201([[:space:]]|$)" || true)
  [[ -n "$rule" && "$rule" == *"$target"* ]] \
    || { echo "$LABEL ERROR: missing policy rule $preference ($target)" >&2; exit 1; }
done
timeout --signal=KILL 5s ip -4 route show table 52 \
  | grep -E "^100[.]64[.]0[.]0/10 .*dev $TUN_NAME([[:space:]]|$)" >/dev/null

# Start a real userspace-networking Go peer from the same pinned module as the
# control server, expose a TCP echo service, and connect with an OS socket. The
# packet must cross Linux TCP, tun0, RustScale WireGuard/magicsock, and Go's
# netstack before returning.
cat >"$TMP/echo.py" <<'PY'
import socket
import sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 0))
s.listen(8)
with open(sys.argv[1], "w", encoding="ascii") as handle:
    handle.write(str(s.getsockname()[1]) + "\n")
while True:
    connection, _ = s.accept()
    with connection:
        while True:
            data = connection.recv(4096)
            if not data:
                break
            connection.sendall(data)
PY
python3 "$TMP/echo.py" "$TMP/echo.port" >"$TMP/echo.log" 2>&1 &
ECHO_PID=$!
for _ in {1..100}; do
  [[ -s "$TMP/echo.port" ]] && break
  kill -0 "$ECHO_PID" 2>/dev/null || { cat "$TMP/echo.log" >&2; exit 1; }
  sleep 0.05
done
BACKEND_PORT=$(<"$TMP/echo.port")
[[ "$BACKEND_PORT" =~ ^[1-9][0-9]*$ ]]

record_phase go-peer-start
GO_STATE="$TMP/go-state"
GO_SOCKET="$TMP/go-tailscaled.sock"
mkdir -p "$GO_STATE"
"$GO_DAEMON" --tun=userspace-networking --socket="$GO_SOCKET" \
  --statedir="$GO_STATE" --port=0 --no-logs-no-support \
  >"$TMP/go-tailscaled.log" 2>&1 &
GO_PID=$!
for _ in {1..200}; do
  [[ -S "$GO_SOCKET" ]] && break
  kill -0 "$GO_PID" 2>/dev/null \
    || { cat "$TMP/go-tailscaled.log" >&2; echo "$LABEL ERROR: Go tailscaled exited" >&2; exit 1; }
  sleep 0.05
done
[[ -S "$GO_SOCKET" ]]
run_bounded 45 go-peer-enrollment \
  "$GO_CLI" --socket="$GO_SOCKET" up \
    --login-server="$CONTROL_URL" --auth-key=tskey-testcontrol \
    --hostname=go-installed-journey --timeout=30s \
  >>"$TMP/go-tailscaled.log" 2>&1
GO_IP=$(timeout --signal=KILL 10s "$GO_CLI" --socket="$GO_SOCKET" ip -4 \
  | sed -n '1p')
[[ "$GO_IP" == 100.* ]] \
  || { echo "$LABEL ERROR: pinned Go peer has invalid IP '$GO_IP'" >&2; exit 1; }
[[ "$(wait_node_count 2)" -ge 2 ]]
curl --max-time 2 -fsS "$CONTROL_URL/testapi/nodes" \
  | python3 -c 'import json,sys; wanted=set(sys.argv[1:]); found={(node.get("ip") or "").split("/", 1)[0] for node in json.load(sys.stdin)["nodes"]}; raise SystemExit(0 if wanted <= found else 1)' \
      "$RUST_IP" "$GO_IP"
PEER_PORT=18082
run_bounded 15 go-peer-serve \
  "$GO_CLI" --socket="$GO_SOCKET" serve --bg --tcp="$PEER_PORT" \
    "tcp://127.0.0.1:$BACKEND_PORT" >>"$TMP/go-tailscaled.log" 2>&1

record_phase kernel-roundtrip
run_bounded 180 kernel-roundtrip python3 - "$GO_IP" "$PEER_PORT" <<'PY'
import socket
import sys
import time
host, port = sys.argv[1], int(sys.argv[2])
payload = b"installed-linux-replacement-roundtrip\n"
last = None
for _ in range(60):
    try:
        with socket.create_connection((host, port), timeout=2) as connection:
            connection.settimeout(2)
            connection.sendall(payload)
            received = b""
            while len(received) < len(payload):
                chunk = connection.recv(len(payload) - len(received))
                if not chunk:
                    break
                received += chunk
            if received != payload:
                raise RuntimeError(f"echo mismatch: {received!r}")
            print("kernel TUN -> pinned Go peer echo: ok")
            raise SystemExit(0)
    except (OSError, RuntimeError) as error:
        last = error
        time.sleep(0.5)
raise SystemExit(f"Go peer echo did not become reachable: {last}")
PY

# Remove the bootstrap key, then prove the persisted profile and address survive
# an actual systemd restart without another registration credential.
record_phase restart-persistence
write_config no "$TMP/config-without-key.json"
run_root_bounded 10 remove-bootstrap-key \
  install -m 600 "$TMP/config-without-key.json" "$CONFIG_PATH"
sudo -n timeout --signal=KILL 5s cat /var/lib/rustscale/prefs.json \
  | python3 -c 'import json,sys; prefs=json.load(sys.stdin); assert prefs.get("WantRunning") is True; assert prefs.get("LoggedOut", False) is False; assert not any("auth" in key.lower() for key in prefs)'
PID_BEFORE=$(timeout --signal=KILL 5s \
  systemctl show -p MainPID --value rustscaled.service)
run_root_bounded 45 restart-without-key systemctl restart rustscaled.service
persisted_status=$(wait_backend Running 80)
PID_AFTER=$(timeout --signal=KILL 5s \
  systemctl show -p MainPID --value rustscaled.service)
[[ "$PID_BEFORE" =~ ^[1-9][0-9]*$ && "$PID_AFTER" =~ ^[1-9][0-9]*$ ]]
[[ "$PID_BEFORE" != "$PID_AFTER" ]]
[[ "$(printf '%s' "$persisted_status" | status_ip)" == "$RUST_IP" ]]
[[ "$(wait_node_count 2)" -ge 2 ]]

run_bounded 120 restart-persistence-roundtrip \
  python3 - "$GO_IP" "$PEER_PORT" <<'PY'
import socket
import sys
import time
payload = b"restart-persistence-roundtrip\n"
last = None
for _ in range(40):
    try:
        with socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=2) as connection:
            connection.settimeout(2)
            connection.sendall(payload)
            received = b""
            while len(received) < len(payload):
                chunk = connection.recv(len(payload) - len(received))
                if not chunk:
                    break
                received += chunk
            if received == payload:
                raise SystemExit(0)
            raise RuntimeError(f"echo mismatch: {received!r}")
    except (OSError, RuntimeError) as error:
        last = error
        time.sleep(0.5)
raise SystemExit(f"post-restart Go peer echo failed: {last}")
PY

# Prove public down/up is an in-process lifecycle transition rather than a
# daemon restart. Both commands must return only after their kernel and LocalAPI
# state is immediately truthful, while persisted identity remains unchanged.
record_phase public-down-up-lifecycle
run_bounded 15 enable-lifecycle-dns \
  /usr/local/bin/tailscale set --accept-dns=true
PID_LIFECYCLE=$(timeout --signal=KILL 5s \
  systemctl show -p MainPID --value rustscaled.service)
[[ "$PID_LIFECYCLE" =~ ^[1-9][0-9]*$ ]]
NODE_COUNT_BEFORE=$(node_count)
NODE_IDENTITY_BEFORE=$(curl --max-time 2 -fsS "$CONTROL_URL/testapi/nodes" \
  | python3 -c 'import json,sys; wanted=sys.argv[1]; nodes=json.load(sys.stdin)["nodes"]; matches=[node for node in nodes if (node.get("ip") or "").split("/",1)[0] == wanted]; assert len(matches) == 1; node=matches[0]; print("{}|{}|{}".format(node["key"], node["id"], node["ip"]))' "$RUST_IP")
DNS_ACTIVE_TARGET=$(readlink -f /etc/resolv.conf)
cp -L /etc/resolv.conf "$TMP/resolv.conf.active"

run_bounded 45 public-down /usr/local/bin/tailscale down
DOWN_STATUS=$(run_bounded 10 immediate-down-status \
  /usr/local/bin/tailscale status --json)
[[ "$(printf '%s' "$DOWN_STATUS" | backend_state)" == Stopped ]]
run_bounded 10 immediate-down-prefs \
  /usr/local/bin/tailscale get --json \
  | python3 -c 'import json,sys; prefs=json.load(sys.stdin); assert isinstance(prefs, dict); assert prefs.get("WantRunning", False) is False; assert prefs.get("LoggedOut", False) is False; assert prefs.get("CorpDNS") is True'
[[ "$(timeout --signal=KILL 5s systemctl show -p MainPID --value rustscaled.service)" \
   == "$PID_LIFECYCLE" ]]
[[ ! -e "/sys/class/net/$TUN_NAME" ]]
for family in -4 -6; do
  rules=$(timeout --signal=KILL 5s ip "$family" -details rule show)
  if grep -Eq 'proto 201([[:space:]]|$)' <<<"$rules"; then
    echo "$LABEL ERROR: protocol-201 rule remained after public down ($family)" >&2
    exit 1
  fi
  routes=$(timeout --signal=KILL 5s ip "$family" route show table 52)
  if grep -Fq "dev $TUN_NAME" <<<"$routes"; then
    echo "$LABEL ERROR: table-52 route remained after public down ($family)" >&2
    exit 1
  fi
done
[[ "$(readlink -f /etc/resolv.conf)" == "$DNS_BASELINE_TARGET" ]]
cmp -s "$TMP/resolv.conf.baseline" /etc/resolv.conf
run_bounded 15 peer-withdrawal python3 - "$GO_IP" "$PEER_PORT" <<'PY'
import socket
import sys
host, port = sys.argv[1], int(sys.argv[2])
for _ in range(4):
    try:
        with socket.create_connection((host, port), timeout=1):
            raise SystemExit("peer remained reachable after public down")
    except OSError:
        pass
print("peer reachability withdrawn: ok")
PY

# Down flushes its disconnect audit before returning. Prove the control server
# is still alive and that exactly one strictly validated inner-Noise audit event
# was accepted before public-up can mask a control-plane failure.
run_bounded 10 audit-log-after-public-down \
  python3 - "$CONTROL_URL" <<'PY'
import json
import re
import sys
import urllib.request
base = sys.argv[1]
with urllib.request.urlopen(base + "/testapi/health", timeout=2) as response:
    assert response.status == 200
    assert json.load(response) == {"ok": True}
with urllib.request.urlopen(base + "/testapi/audit-log", timeout=2) as response:
    assert response.status == 200
    stats = json.load(response)
assert stats["accepted"] == 1, stats
assert stats["rejected"] == 0, stats
assert stats["action"] == "DISCONNECT_NODE", stats
assert stats["detailsLen"] > 0, stats
assert stats["timestampSet"] is True, stats
assert re.fullmatch(r"[0-9a-f]{64}", stats["bodySHA256"]), stats
assert stats["lastError"] == "", stats
PY

run_bounded 90 public-up \
  /usr/local/bin/tailscale up --accept-dns=true --timeout=60
UP_STATUS=$(run_bounded 10 immediate-up-status \
  /usr/local/bin/tailscale status --json)
[[ "$(printf '%s' "$UP_STATUS" | backend_state)" == Running ]]
[[ "$(printf '%s' "$UP_STATUS" | status_ip)" == "$RUST_IP" ]]
run_bounded 10 immediate-up-prefs \
  /usr/local/bin/tailscale get --json \
  | python3 -c 'import json,sys; prefs=json.load(sys.stdin); assert prefs["WantRunning"] is True; assert prefs.get("LoggedOut", False) is False; assert prefs["CorpDNS"] is True'
[[ "$(timeout --signal=KILL 5s systemctl show -p MainPID --value rustscaled.service)" \
   == "$PID_LIFECYCLE" ]]
[[ -d "/sys/class/net/$TUN_NAME" ]]
ifindex=$(<"/sys/class/net/$TUN_NAME/ifindex")
[[ "$ifindex" =~ ^[1-9][0-9]*$ ]]
RULE_BASE=$((5000 + (ifindex % 200) * 100))
rules=$(timeout --signal=KILL 5s ip -4 -details rule show)
for expectation in \
  "$((RULE_BASE + 10)):lookup main" \
  "$((RULE_BASE + 30)):lookup default" \
  "$((RULE_BASE + 50)):unreachable" \
  "$((RULE_BASE + 70)):lookup 52"; do
  preference=${expectation%%:*}
  target=${expectation#*:}
  rule=$(printf '%s\n' "$rules" \
    | grep -E "^[[:space:]]*${preference}:.*proto 201([[:space:]]|$)" || true)
  [[ -n "$rule" && "$rule" == *"$target"* ]]
done
timeout --signal=KILL 5s ip -4 route show table 52 \
  | grep -E "^100[.]64[.]0[.]0/10 .*dev $TUN_NAME([[:space:]]|$)" >/dev/null
[[ "$(readlink -f /etc/resolv.conf)" == "$DNS_ACTIVE_TARGET" ]]
cmp -s "$TMP/resolv.conf.active" /etc/resolv.conf
[[ "$(node_count)" == "$NODE_COUNT_BEFORE" ]]
NODE_IDENTITY_AFTER=$(curl --max-time 2 -fsS "$CONTROL_URL/testapi/nodes" \
  | python3 -c 'import json,sys; wanted=sys.argv[1]; nodes=json.load(sys.stdin)["nodes"]; matches=[node for node in nodes if (node.get("ip") or "").split("/",1)[0] == wanted]; assert len(matches) == 1; node=matches[0]; print("{}|{}|{}".format(node["key"], node["id"], node["ip"]))' "$RUST_IP")
[[ "$NODE_IDENTITY_AFTER" == "$NODE_IDENTITY_BEFORE" ]]
# `tailscale up` returned Running only after this generation committed every
# public resource above; one immediate roundtrip is therefore the assertion.
run_bounded 5 lifecycle-restored-roundtrip \
  python3 - "$GO_IP" "$PEER_PORT" <<'PY'
import socket
import sys
payload = b"public-down-up-roundtrip\n"
with socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=2) as connection:
    connection.settimeout(2)
    connection.sendall(payload)
    received = connection.recv(len(payload))
    if received != payload:
        raise SystemExit(f"post-up Go peer echo mismatch: {received!r}")
PY

# Logout is durable before the LocalAPI call returns. Restart=always then starts
# a fresh NeedsLogin generation; that generation must not retain TUN state.
record_phase logout
PID_BEFORE_LOGOUT=$(timeout --signal=KILL 5s \
  systemctl show -p MainPID --value rustscaled.service)
run_bounded 45 localapi-logout /usr/local/bin/tailscale logout
logged_out_status=$(wait_backend NeedsLogin 80)
PID_AFTER_LOGOUT=$(timeout --signal=KILL 5s \
  systemctl show -p MainPID --value rustscaled.service)
[[ "$PID_AFTER_LOGOUT" =~ ^[1-9][0-9]*$ ]]
[[ "$PID_BEFORE_LOGOUT" != "$PID_AFTER_LOGOUT" ]]
[[ "$(printf '%s' "$logged_out_status" | backend_state)" == NeedsLogin ]]
[[ -S "$DEFAULT_SOCKET" ]]
assert_kernel_clean keep-socket
verify_official_sentinels

# Exercise the public uninstaller rather than cleaning files directly. Stateful
# identity is intentionally retained by uninstall; this isolated test removes
# it only after checking service, route/rule, socket, and artifact cleanup.
record_phase uninstall
echo "$LABEL uninstalling through scripts/install.sh" >&2
uninstall_release | tee "$TMP/uninstall.log"
if timeout --signal=KILL 5s systemctl is-active --quiet rustscaled.service; then
  echo "$LABEL ERROR: rustscaled.service remains active after uninstall" >&2
  exit 1
fi
if timeout --signal=KILL 5s systemctl is-enabled --quiet rustscaled.service; then
  echo "$LABEL ERROR: rustscaled.service remains enabled after uninstall" >&2
  exit 1
fi
[[ ! -e /etc/systemd/system/rustscaled.service ]]
[[ ! -e /etc/default/rustscaled ]]
for path in \
  /usr/local/bin/rustscale \
  /usr/local/bin/rustscaled \
  /usr/local/bin/tailscale \
  /usr/local/bin/tailscaled \
  /usr/local/bin/.rustscale-install-receipt-v1 \
  /usr/local/lib/librustscale.so \
  /usr/local/lib/librustscale.a \
  /usr/local/include/rustscale.h; do
  [[ ! -e "$path" && ! -L "$path" ]]
done
assert_kernel_clean
verify_official_sentinels
run_root_bounded 10 remove-journey-config rm -f \
  "$CONFIG_PATH" "$JOURNEY_ENV" \
  "$DROPIN_DIR/10-rustscale-install-journey.conf"
run_root_bounded 5 remove-journey-drop-in rmdir "$DROPIN_DIR"
run_root_bounded 10 reload-after-uninstall systemctl daemon-reload
run_root_bounded 10 remove-retained-rustscale-state \
  rm -rf /var/lib/rustscale /var/cache/rustscale /run/rustscale
INSTALL_STARTED=0

JOURNEY_FINISHED=1
record_phase complete
echo "$LABEL PASS: installed archive + explicit aliases + systemd + LocalAPI + restart/logout/uninstall" >&2
echo "$LABEL PASS: real Linux tun0 packet roundtrip to pinned Go peer $GO_VERSION ($GO_IP:$PEER_PORT)" >&2
