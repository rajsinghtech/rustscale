#!/usr/bin/env bash
# Credential-free regression for transient-service readiness and cleanup.

set -euo pipefail
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
PROBE="$ROOT/tools/packaging/probe-systemd-supervisor.sh"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/rustscale-systemd-probe-test.XXXXXX")
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
mkdir -p "$TMP/bin"

cat >"$TMP/bin/sudo" <<'EOF'
#!/bin/sh
[ "${1:-}" != -n ] || shift
exec "$@"
EOF
cat >"$TMP/bin/timeout" <<'EOF'
#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in
    --signal=*|--kill-after=*) shift ;;
    *s) shift; break ;;
    *) break ;;
  esac
done
exec "$@"
EOF
cat >"$TMP/bin/systemd-run" <<'EOF'
#!/bin/sh
printf 'run %s\n' "$*" >>"$PROBE_LOG"
case "${PROBE_SCENARIO:-success}" in
  success|leak) exit 0 ;;
  killed) exit 137 ;;
  *) exit 2 ;;
esac
EOF
cat >"$TMP/bin/systemctl" <<'EOF'
#!/bin/sh
printf 'systemctl %s\n' "$*" >>"$PROBE_LOG"
if [ "${1:-}" = is-active ]; then
  [ "${PROBE_SCENARIO:-success}" = leak ] && exit 0
  exit 3
fi
exit 0
EOF
chmod +x "$TMP/bin/"*

export PATH="$TMP/bin:$PATH" PROBE_LOG="$TMP/probe.log"

# An unrelated manager-wide "starting" state is deliberately absent from the
# contract: successful create/wait/collect is the operational proof we need.
PROBE_SCENARIO=success "$PROBE" 5 regression sudo -n
grep -Fq 'run --quiet --wait --collect' "$PROBE_LOG" \
  || { echo 'probe did not execute a collected transient service' >&2; exit 1; }
grep -Fq 'systemctl stop rustscale-systemd-probe-' "$PROBE_LOG" \
  || { echo 'probe did not execute deterministic cleanup' >&2; exit 1; }

# Both outer readiness and the inner journey run the operational probe through
# passwordless sudo. The inner script is deliberately launched as the runner
# user by systemd, so omitting this prefix reproduces hosted runners' exact
# "Interactive authentication required" terminal failure.
grep -Fq 'probe_systemd_supervisor 30 supervisor sudo -n' \
  "$ROOT/tools/packaging/test-linux-replacement.sh" \
  || { echo 'outer supervisor probe lost its noninteractive privilege' >&2; exit 1; }
grep -Fq 'probe_systemd_supervisor 30 journey sudo -n' \
  "$ROOT/tools/packaging/test-linux-replacement.sh" \
  || { echo 'inner journey probe lost its noninteractive privilege' >&2; exit 1; }

: >"$PROBE_LOG"
if PROBE_SCENARIO=killed "$PROBE" 5 regression sudo -n; then
  echo 'exit-137 transient-service failure was accepted' >&2
  exit 1
fi
grep -Fq 'systemctl kill --kill-whom=all --signal=KILL rustscale-systemd-probe-' "$PROBE_LOG" \
  || { echo 'failed probe did not force cgroup cleanup' >&2; exit 1; }

: >"$PROBE_LOG"
if PROBE_SCENARIO=leak "$PROBE" 5 regression sudo -n; then
  echo 'active transient-service leak was accepted' >&2
  exit 1
fi
grep -Fq 'systemctl stop rustscale-systemd-probe-' "$PROBE_LOG" \
  || { echo 'active probe unit was not stopped' >&2; exit 1; }

echo 'systemd supervisor probe regression passed'
