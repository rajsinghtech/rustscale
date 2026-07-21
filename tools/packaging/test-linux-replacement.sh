#!/usr/bin/env bash
# Installed Linux replacement journey. Consumes a candidate's already-built
# production archive and SHA256SUMS, installs it through the ordinary documented
# installer (including its default aliases), starts the shipped systemd unit,
# enrolls against pinned Go testcontrol, and proves a kernel-TUN packet
# roundtrip to a pinned Go tailscaled peer. This is intentionally build-free.

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

# Hosted runners can retain a manager-wide `starting` state because of
# unrelated units even while transient services are fully operational. Probe
# the exact create/wait/collect lifecycle required by this journey instead.
probe_systemd_supervisor() {
  "$ROOT/tools/packaging/probe-systemd-supervisor.sh" "$@"
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

  if ! probe_systemd_supervisor 30 supervisor sudo -n; then
    skip "systemd manager cannot supervise and collect a privileged transient service"
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
    CARGO_PROFILE_RELEASE_OPT_LEVEL RUSTSCALE_LINUX_REPLACEMENT_PHASE_FILE \
    RUSTSCALE_RELEASE_DIR RUSTSCALE_RELEASE_TAG RUSTSCALE_RELEASE_SHA \
    RUSTSCALE_RELEASE_VERSION; do
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
for command_name in awk cmp cp curl date find getconf go grep id install ip journalctl \
  mktemp ps python3 readlink sed setpriv sha256sum sudo systemctl systemd-run tail tar \
  tee timeout tr wc; do
  command -v "$command_name" >/dev/null 2>&1 \
    || skip "required command '$command_name' is not available"
done

if ! sudo -n true 2>/dev/null; then
  skip "passwordless sudo is unavailable"
fi
# The inner journey intentionally runs as the invoking user inside the
# root-owned supervisor unit. Starting a second transient service still needs
# the same passwordless privilege proved by preflight; without this prefix,
# systemd-run asks for interactive authorization inside the noninteractive
# unit even though the manager is operational.
if ! probe_systemd_supervisor 30 journey sudo -n; then
  skip "systemd manager cannot supervise and collect the installed journey"
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

# Last-resort host restoration for an interrupted or wedged service stop. The
# preflight rejects every one of these names/selectors before the journey, so
# this removes only state attributable to this isolated run. Successful journey
# assertions happen before this function can be used.
emergency_kernel_cleanup() {
  local family preference table ifindex rules
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
  sudo -n timeout --signal=KILL 3s \
    ip link delete dev "$TUN_NAME" >/dev/null 2>&1 || true
  sudo -n timeout --signal=KILL 3s rm -f "$DEFAULT_SOCKET" || true
}

assert_kernel_clean() {
  local socket_must_be_absent=${1:-yes}
  local leaked=0 family rules preference routes
  if [[ -e "/sys/class/net/$TUN_NAME" ]]; then
    echo "$LABEL cleanup leak: interface $TUN_NAME still exists" >&2
    leaked=1
  fi
  if [[ "$socket_must_be_absent" == yes ]] \
      && [[ -e "$DEFAULT_SOCKET" || -L "$DEFAULT_SOCKET" ]]; then
    echo "$LABEL cleanup leak: LocalAPI path $DEFAULT_SOCKET still exists" >&2
    leaked=1
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
  if printf '%s\n' "$routes" | grep -F "dev $TUN_NAME" >/dev/null; then
    echo "$LABEL cleanup leak: table 52 still routes through $TUN_NAME" >&2
    leaked=1
  fi
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

assert_cli_contract() {
  local stdout stderr
  stdout="$TMP/cli.stdout"
  stderr="$TMP/cli.stderr"

  # Top-level help retains the documented usage stream and success code.
  if ! /usr/local/bin/tailscale --help >"$stdout" 2>"$stderr"; then
    echo "$LABEL ERROR: tailscale --help did not exit successfully" >&2
    return 1
  fi
  if ! [[ ! -s "$stdout" ]] || ! grep -Fq 'usage:' "$stderr"; then
    echo "$LABEL ERROR: tailscale --help stream contract changed" >&2
    return 1
  fi

  # Both command-help spellings must be offline, successful, and stdout-only.
  for help_args in 'status --help' 'help status'; do
    # Intentional word splitting: each case is a fixed two-argument vector.
    # shellcheck disable=SC2086
    if ! /usr/local/bin/tailscale $help_args >"$stdout" 2>"$stderr"; then
      echo "$LABEL ERROR: tailscale $help_args did not exit successfully" >&2
      return 1
    fi
    if ! [[ -s "$stdout" && ! -s "$stderr" ]] \
        || ! grep -Fq 'usage: tailscale status' "$stdout"; then
      echo "$LABEL ERROR: tailscale $help_args stream contract changed" >&2
      return 1
    fi
  done

  if /usr/local/bin/tailscale definitely-not-a-command >"$stdout" 2>"$stderr"; then
    echo "$LABEL ERROR: invalid tailscale command unexpectedly succeeded" >&2
    return 1
  fi
  if ! [[ ! -s "$stdout" && -s "$stderr" ]] \
      || ! grep -Fq "unknown subcommand 'definitely-not-a-command'" "$stderr"; then
    echo "$LABEL ERROR: invalid tailscale command stream contract changed" >&2
    return 1
  fi
}

wait_backend() {
  local expected=$1 seconds=${2:-60} expected_ipv4=${3:-} output state observed_ipv4 deadline
  deadline=$((SECONDS + seconds))
  echo "$LABEL $(timestamp) wait: LocalAPI BackendState=$expected${expected_ipv4:+ IPv4=$expected_ipv4} (deadline=${seconds}s)" >&2
  while (( SECONDS < deadline )); do
    if output=$(timeout --signal=KILL 3s \
        /usr/local/bin/tailscale status --json 2>/dev/null); then
      state=$(printf '%s' "$output" | backend_state 2>/dev/null || true)
      observed_ipv4=$(printf '%s' "$output" | status_ip 2>/dev/null || true)
      # A Running answer is readiness evidence only when this one LocalAPI
      # snapshot also carries the expected current-generation tailnet IP.
      if [[ "$state" == "$expected" \
        && ( -z "$expected_ipv4" || "$observed_ipv4" == "$expected_ipv4" ) ]]; then
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
  echo "$LABEL $(timestamp) ERROR: timed out waiting for LocalAPI BackendState=$expected${expected_ipv4:+ IPv4=$expected_ipv4}" >&2
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

# The journey must consume the already-published candidate bytes, never a
# source build. The producing CI job provides this exact release tree:
# <base>/download/<candidate-tag>/{archive,SHA256SUMS}.
RELEASE_DIR=${RUSTSCALE_RELEASE_DIR:-}
RELEASE_TAG=${RUSTSCALE_RELEASE_TAG:-}
RELEASE_SHA=${RUSTSCALE_RELEASE_SHA:-}
RELEASE_VERSION=${RUSTSCALE_RELEASE_VERSION:-}
[[ -n "$RELEASE_DIR" && -n "$RELEASE_TAG" && -n "$RELEASE_SHA" && -n "$RELEASE_VERSION" ]] \
  || { echo "$LABEL ERROR: release artifact directory, tag, SHA, and version are required" >&2; exit 2; }
[[ "$RELEASE_SHA" =~ ^[0-9a-f]{40}$ ]] \
  || { echo "$LABEL ERROR: candidate SHA must be a full lowercase git SHA" >&2; exit 2; }
[[ -d "$RELEASE_DIR" && ! -L "$RELEASE_DIR" ]] \
  || { echo "$LABEL ERROR: candidate release directory is missing or symlinked: $RELEASE_DIR" >&2; exit 1; }
[[ "$(basename "$RELEASE_DIR")" == "$RELEASE_TAG" && "$(basename "$(dirname "$RELEASE_DIR")")" == download ]] \
  || { echo "$LABEL ERROR: candidate archive is not in download/$RELEASE_TAG" >&2; exit 1; }
RELEASE_BASE="file://$(dirname "$(dirname "$RELEASE_DIR")")"

record_phase exact-production-artifact
[[ -f "$RELEASE_DIR/$ARCHIVE" && ! -L "$RELEASE_DIR/$ARCHIVE" && -f "$RELEASE_DIR/SHA256SUMS" && ! -L "$RELEASE_DIR/SHA256SUMS" ]] \
  || { echo "$LABEL ERROR: exact production archive and SHA256SUMS are required" >&2; exit 1; }
expected_archive_sha=$(awk -v name="$ARCHIVE" '$2 == name || $2 == "*" name { print $1; exit }' "$RELEASE_DIR/SHA256SUMS")
[[ "$expected_archive_sha" =~ ^[0-9a-f]{64}$ ]] \
  || { echo "$LABEL ERROR: SHA256SUMS lacks a valid checksum for $ARCHIVE" >&2; exit 1; }
actual_archive_sha=$(sha256sum "$RELEASE_DIR/$ARCHIVE" | awk '{print $1}')
[[ "$actual_archive_sha" == "$expected_archive_sha" ]] \
  || { echo "$LABEL ERROR: candidate production archive checksum mismatch" >&2; exit 1; }
# Archive extraction here is verification only. The installer below downloads
# the same archive and SHA256SUMS through its ordinary release URL.
ARTIFACT_STAGE=$(mktemp -d "$TMP/artifact-stage.XXXXXX")
run_bounded 30 verify-production-archive \
  tar --format=ustar -xzf "$RELEASE_DIR/$ARCHIVE" -C "$ARTIFACT_STAGE"
for candidate_file in rustscale rustscaled librustscale.so librustscale.a rustscale.h rustscaled.service rustscaled.default LICENSE RUSTSCALE_BUILD_SHA; do
  [[ -f "$ARTIFACT_STAGE/$candidate_file" && ! -L "$ARTIFACT_STAGE/$candidate_file" ]] \
    || { echo "$LABEL ERROR: production archive is missing $candidate_file" >&2; exit 1; }
done
ARTIFACT_BUILD_SHA=$(tr -d '\r\n' < "$ARTIFACT_STAGE/RUSTSCALE_BUILD_SHA")
[[ "$ARTIFACT_BUILD_SHA" == "$RELEASE_SHA" ]] \
  || { echo "$LABEL ERROR: archive build identity $ARTIFACT_BUILD_SHA does not match $RELEASE_SHA" >&2; exit 1; }
CLI_VERSION=$(timeout --signal=KILL 10s "$ARTIFACT_STAGE/rustscale" --version)
DAEMON_VERSION=$(timeout --signal=KILL 10s "$ARTIFACT_STAGE/rustscaled" --version)
[[ "$CLI_VERSION" == *"$RELEASE_VERSION"* && "$CLI_VERSION" == *"${RELEASE_SHA:0:7}"* ]] \
  || { echo "$LABEL ERROR: CLI embedded version does not identify $RELEASE_VERSION/$RELEASE_SHA" >&2; exit 1; }
[[ "$DAEMON_VERSION" == "rustscaled $RELEASE_VERSION" ]] \
  || { echo "$LABEL ERROR: daemon embedded version does not identify $RELEASE_VERSION" >&2; exit 1; }

echo "$LABEL verified exact production archive $ARCHIVE for $RELEASE_TAG ($RELEASE_SHA)" >&2

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
echo "$LABEL installing exact candidate archive with ordinary aliases and shipped systemd service" >&2
run_runner_supervised_bounded 120 archive-install \
  env INSTALL_SERVICE=1 PREFIX="$PREFIX" \
    RUSTSCALE_RELEASE_BASE="$RELEASE_BASE" \
    RUSTSCALE_HTTP_CLIENT=curl RUSTSCALE_UNAME_S=Linux \
    RUSTSCALE_UNAME_M="$MACHINE" RUSTSCALE_LIBC=gnu \
    sh "$ROOT/scripts/install.sh" --version "$RELEASE_TAG" \
  | tee "$TMP/install.log"

[[ "$(readlink /usr/local/bin/tailscale)" == rustscale ]]
[[ "$(readlink /usr/local/bin/tailscaled)" == rustscaled ]]
[[ "$(sha256sum /usr/local/bin/rustscale | awk '{print $1}')" \
   == "$(sha256sum "$ARTIFACT_STAGE/rustscale" | awk '{print $1}')" ]]
[[ "$(sha256sum /usr/local/bin/rustscaled | awk '{print $1}')" \
   == "$(sha256sum "$ARTIFACT_STAGE/rustscaled" | awk '{print $1}')" ]]
[[ "$(sha256sum /usr/local/lib/librustscale.so | awk '{print $1}')" \
   == "$(sha256sum "$ARTIFACT_STAGE/librustscale.so" | awk '{print $1}')" ]]
[[ "$(sha256sum /usr/local/lib/librustscale.a | awk '{print $1}')" \
   == "$(sha256sum "$ARTIFACT_STAGE/librustscale.a" | awk '{print $1}')" ]]
[[ "$(sha256sum /usr/local/include/rustscale.h | awk '{print $1}')" \
   == "$(sha256sum "$ARTIFACT_STAGE/rustscale.h" | awk '{print $1}')" ]]
[[ "$(sha256sum /etc/default/rustscaled | awk '{print $1}')" \
   == "$(sha256sum "$ARTIFACT_STAGE/rustscaled.default" | awk '{print $1}')" ]]
[[ "$(/usr/local/bin/tailscale --version)" == *"$RELEASE_VERSION"* && "$(/usr/local/bin/tailscale --version)" == *"${RELEASE_SHA:0:7}"* ]]
[[ "$(/usr/local/bin/tailscaled --version)" == "rustscaled $RELEASE_VERSION" ]]
assert_cli_contract
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
# Require one current-generation LocalAPI snapshot to prove both Running
# and the original IPv4 identity after restart; a stale handoff listener or
# cache may not satisfy this readiness boundary.
persisted_status=$(wait_backend Running 80 "$RUST_IP")
PID_AFTER=$(timeout --signal=KILL 5s \
  systemctl show -p MainPID --value rustscaled.service)
[[ "$PID_BEFORE" =~ ^[1-9][0-9]*$ && "$PID_AFTER" =~ ^[1-9][0-9]*$ ]] \
  || { echo "$LABEL ERROR: invalid restart PIDs before='$PID_BEFORE' after='$PID_AFTER'" >&2; exit 1; }
[[ "$PID_BEFORE" != "$PID_AFTER" ]] \
  || { echo "$LABEL ERROR: systemd restart retained daemon PID $PID_BEFORE" >&2; exit 1; }
persisted_ip=$(printf '%s' "$persisted_status" | status_ip)
[[ "$persisted_ip" == "$RUST_IP" ]] \
  || { echo "$LABEL ERROR: restart changed tailnet IP from '$RUST_IP' to '$persisted_ip'" >&2; exit 1; }
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
echo "$LABEL PASS: exact artifact + ordinary aliases + systemd + LocalAPI + restart/logout/uninstall" >&2
echo "$LABEL PASS: real Linux tun0 packet roundtrip to pinned Go peer $GO_VERSION ($GO_IP:$PEER_PORT)" >&2
