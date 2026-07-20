#!/usr/bin/env bash
# Prove that the system manager can create, wait for, collect, and clean a
# transient service. Manager-wide SystemState may remain "starting" on hosted
# runners because of unrelated units, so it is not an operational readiness
# barrier for RustScale's independently bounded service.

set -euo pipefail

LABEL='[systemd-supervisor-probe]'

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <deadline-seconds> <scope> [command-prefix ...]" >&2
  exit 2
fi

seconds=$1
scope=$2
shift 2
case "$seconds" in
  ''|*[!0-9]*) echo "$LABEL ERROR: deadline must be a positive integer" >&2; exit 2 ;;
esac
(( seconds > 0 )) || { echo "$LABEL ERROR: deadline must be positive" >&2; exit 2; }

unit="rustscale-systemd-probe-$(id -u)-$$.service"
force_closed() {
  "$@" timeout --signal=KILL 5s systemctl stop "$unit" >/dev/null 2>&1 || true
  "$@" timeout --signal=KILL 5s \
    systemctl kill --kill-whom=all --signal=KILL "$unit" >/dev/null 2>&1 || true
}

echo "$LABEL probe: systemd transient service (scope=$scope deadline=${seconds}s unit=$unit)" >&2
set +e
"$@" timeout --signal=TERM --kill-after=5s "${seconds}s" \
  systemd-run --quiet --wait --collect --service-type=exec \
    --unit="$unit" --property=KillMode=control-group \
    --property=SendSIGKILL=yes /usr/bin/true
status=$?
set -e
if [[ "$status" != 0 ]]; then
  echo "$LABEL ERROR: transient service probe failed (scope=$scope status=$status)" >&2
fi

if "$@" timeout --signal=KILL 5s systemctl is-active --quiet "$unit" >/dev/null 2>&1; then
  echo "$LABEL ERROR: transient service remained active after --wait --collect (scope=$scope)" >&2
  status=1
fi
force_closed "$@"
exit "$status"
