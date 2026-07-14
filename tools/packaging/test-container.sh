#!/bin/sh
# Exercise container/entrypoint.sh with fake daemon and CLI processes. This
# verifies containerboot-compatible environment mapping without Docker or TUN.

set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
TMP=$(mktemp -d /tmp/rustscale-container-test.XXXXXX)
ENTRYPOINT_PID=
trap '
    if [ -n "$ENTRYPOINT_PID" ]; then kill "$ENTRYPOINT_PID" 2>/dev/null || true; fi
    rm -rf "$TMP"
' EXIT

mkdir -p "$TMP/bin" "$TMP/state"

cat > "$TMP/bin/rustscaled" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" > "$FAKE_DAEMON_ARGS"
socket=
previous=
for arg in "$@"; do
    if [ "$previous" = --socket ]; then socket="$arg"; fi
    previous="$arg"
done
test -n "$socket"
exec python3 -c '
import os, signal, socket, sys, time
path = sys.argv[1]
try:
    os.unlink(path)
except FileNotFoundError:
    pass
s = socket.socket(socket.AF_UNIX)
s.bind(path)
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
while True:
    time.sleep(1)
' "$socket"
EOF

cat > "$TMP/bin/rustscale" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_CLI_ARGS"
case " $* " in
    *" status "*)
        if [ "${FAKE_RUNNING:-0}" = 1 ]; then echo Running; else echo Stopped; fi
        ;;
esac
EOF
chmod +x "$TMP/bin/rustscaled" "$TMP/bin/rustscale"
printf 'tskey-from-file\n' > "$TMP/authkey"

run_entrypoint() {
    output="$1"
    shift
    env PATH="$TMP/bin:$PATH" \
        FAKE_DAEMON_ARGS="$TMP/daemon.args" FAKE_CLI_ARGS="$TMP/cli.args" \
        TS_STATE_DIR="$TMP/state" TS_SOCKET="$TMP/rustscaled.sock" \
        "$@" sh "$ROOT/container/entrypoint.sh" > "$output" 2>&1 &
    ENTRYPOINT_PID=$!
    ready=0
    attempts=0
    while [ "$attempts" -lt 200 ]; do
        if grep -q 'container ready' "$output" 2>/dev/null; then ready=1; break; fi
        if ! kill -0 "$ENTRYPOINT_PID" 2>/dev/null; then break; fi
        sleep 0.1
        attempts=$((attempts + 1))
    done
    if [ "$ready" != 1 ]; then
        cat "$output" >&2
        echo "container entrypoint did not become ready" >&2
        exit 1
    fi
    kill -TERM "$ENTRYPOINT_PID"
    wait "$ENTRYPOINT_PID" 2>/dev/null || true
    ENTRYPOINT_PID=
}

run_entrypoint "$TMP/first.out" \
    TS_AUTHKEY="file:$TMP/authkey" TS_HOSTNAME=test-container \
    TS_USERSPACE=0 TS_ROUTES=10.0.0.0/24 TS_ACCEPT_DNS=true \
    TS_ACCEPT_ROUTES=1 TS_EXIT_NODE=100.64.0.1 \
    TS_SOCKS5_SERVER=127.0.0.1:1080 \
    TS_OUTBOUND_HTTP_PROXY_LISTEN=127.0.0.1:8080 \
    TS_TAILSCALED_EXTRA_ARGS='--port 41641' TS_EXTRA_ARGS='--shields-up'

grep -q -- '--tun' "$TMP/daemon.args"
grep -q -- '--hostname test-container' "$TMP/daemon.args"
grep -q -- '--socks5-server 127.0.0.1:1080' "$TMP/daemon.args"
grep -q -- '--http-proxy-server 127.0.0.1:8080' "$TMP/daemon.args"
grep -q -- '--port 41641' "$TMP/daemon.args"
grep -q -- 'up .*--auth-key tskey-from-file' "$TMP/cli.args"
grep -q -- '--advertise-routes 10.0.0.0/24' "$TMP/cli.args"
grep -q -- '--accept-dns' "$TMP/cli.args"
grep -q -- '--accept-routes' "$TMP/cli.args"
grep -q -- '--exit-node 100.64.0.1' "$TMP/cli.args"
grep -q -- '--shields-up' "$TMP/cli.args"
if grep -q 'tskey-from-file' "$TMP/first.out"; then
    echo "container entrypoint leaked its auth key to output" >&2
    exit 1
fi

# TS_AUTH_ONCE=true preserves an already-running login and skips `up`.
: > "$TMP/cli.args"
run_entrypoint "$TMP/second.out" FAKE_RUNNING=1 TS_AUTH_ONCE=true
if grep -q ' up ' "$TMP/cli.args"; then
    echo "TS_AUTH_ONCE=true unexpectedly reauthenticated" >&2
    exit 1
fi

echo "container entrypoint tests: ok"
