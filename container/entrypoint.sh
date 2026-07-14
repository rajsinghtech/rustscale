#!/bin/sh
# rustscale container entrypoint — a mini containerboot.
#
# Reads TS_* environment variables (same names as Tailscale's containerboot),
# starts rustscaled, authenticates with rustscale up, and keeps the container
# alive.
#
# Env vars (all optional except TS_AUTHKEY for first-time login):
#   TS_AUTHKEY          Auth key for headless login. Also accepts TS_AUTH_KEY.
#                       If the value starts with "file:", it is read from that path.
#   TS_HOSTNAME         Hostname to request for the node.
#   TS_USERSPACE        Run in userspace networking mode (default: 1).
#                       Set to 0 for TUN mode (requires --privileged + /dev/net/tun).
#   TS_STATE_DIR        State directory (default: /var/lib/rustscale).
#   TS_ROUTES           Subnet routes to advertise (comma-separated CIDRs).
#   TS_ACCEPT_DNS       Set to 1 to accept tailnet DNS configuration.
#   TS_ACCEPT_ROUTES    Set to 1 to accept advertised routes from peers.
#   TS_EXIT_NODE        IP of the exit node to route all traffic through.
#   TS_SOCKS5_SERVER    Address for SOCKS5 proxy into the tailnet.
#   TS_OUTBOUND_HTTP_PROXY_LISTEN
#                       Address for an outbound HTTP proxy into the tailnet.
#   TS_EXTRA_ARGS       Extra arguments to pass to `rustscale up`.
#   TS_TAILSCALED_EXTRA_ARGS  Extra arguments to pass to `rustscaled run`.
#   TS_AUTH_ONCE        If 1, only login if not already logged in (default: 0,
#                       matching Tailscale containerboot).
#                       Set to 0 to force re-auth on every start.

set -eu

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log() { echo "[entrypoint] $*"; }

err() { echo "[entrypoint] ERROR: $*" >&2; exit 1; }

# Read a value from a file: prefix.
maybe_read_file() {
    val="$1"
    case "$val" in
        file:*) cat "${val#file:}" || err "failed to read file: ${val#file:}" ;;
        *)      echo "$val" ;;
    esac
}

bool_false() {
    case "$1" in
        ""|0|false|False|FALSE|no|No|NO) return 0 ;;
        *) return 1 ;;
    esac
}

# Wait for the daemon socket to appear.
wait_for_socket() {
    socket="${1}"
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
        if [ -S "$socket" ]; then return 0; fi
        sleep 0.5
    done
    err "daemon socket $socket did not appear within 15s"
}

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

STATE_DIR="${TS_STATE_DIR:-/var/lib/rustscale}"
SOCKET="${TS_SOCKET:-/var/run/rustscaled.sock}"
USERSPACE="${TS_USERSPACE:-1}"
AUTH_ONCE="${TS_AUTH_ONCE:-0}"

# Resolve auth key from TS_AUTHKEY or TS_AUTH_KEY (file: prefix supported).
AUTH_KEY=""
if [ -n "${TS_AUTHKEY:-}" ]; then
    AUTH_KEY=$(maybe_read_file "$TS_AUTHKEY")
elif [ -n "${TS_AUTH_KEY:-}" ]; then
    AUTH_KEY=$(maybe_read_file "$TS_AUTH_KEY")
fi

mkdir -p "$STATE_DIR"

# ---------------------------------------------------------------------------
# Start rustscaled
# ---------------------------------------------------------------------------

DAEMON_ARGS="run --statedir $STATE_DIR --socket $SOCKET"

# TUN mode unless userspace is explicitly enabled.
if bool_false "$USERSPACE"; then
    DAEMON_ARGS="$DAEMON_ARGS --tun"
fi

# Hostname passed to daemon if set.
if [ -n "${TS_HOSTNAME:-}" ]; then
    DAEMON_ARGS="$DAEMON_ARGS --hostname $TS_HOSTNAME"
fi
if [ -n "${TS_SOCKS5_SERVER:-}" ]; then
    DAEMON_ARGS="$DAEMON_ARGS --socks5-server $TS_SOCKS5_SERVER"
fi
if [ -n "${TS_OUTBOUND_HTTP_PROXY_LISTEN:-}" ]; then
    DAEMON_ARGS="$DAEMON_ARGS --http-proxy-server $TS_OUTBOUND_HTTP_PROXY_LISTEN"
fi

# Extra daemon args.
if [ -n "${TS_TAILSCALED_EXTRA_ARGS:-}" ]; then
    DAEMON_ARGS="$DAEMON_ARGS $TS_TAILSCALED_EXTRA_ARGS"
fi

log "starting rustscaled"
# shellcheck disable=SC2086 # intentional word splitting for args
rustscaled $DAEMON_ARGS &
DAEMON_PID=$!

# Trap exit to clean up the daemon.
trap 'kill '"$DAEMON_PID"' 2>/dev/null; wait '"$DAEMON_PID"' 2>/dev/null || true' EXIT

wait_for_socket "$SOCKET"
log "daemon is ready"

# ---------------------------------------------------------------------------
# Authenticate
# ---------------------------------------------------------------------------

# Check if already logged in.
ALREADY_UP=false
STATUS=$(rustscale --socket "$SOCKET" status 2>/dev/null || echo "")
case "$STATUS" in
    *"Running"*) ALREADY_UP=true; log "already running" ;;
esac

# Determine if we should login.
SHOULD_LOGIN=true
if [ "$ALREADY_UP" = true ] && bool_false "${AUTH_ONCE:-0}"; then
    # AUTH_ONCE=0 means always re-auth.
    SHOULD_LOGIN=true
elif [ "$ALREADY_UP" = true ]; then
    SHOULD_LOGIN=false
fi

if [ "$SHOULD_LOGIN" = true ]; then
    UP_ARGS=""

    if [ -n "$AUTH_KEY" ]; then
        UP_ARGS="$UP_ARGS --auth-key $AUTH_KEY"
    fi
    if [ -n "${TS_HOSTNAME:-}" ]; then
        UP_ARGS="$UP_ARGS --hostname $TS_HOSTNAME"
    fi
    if [ -n "${TS_ROUTES:-}" ]; then
        UP_ARGS="$UP_ARGS --advertise-routes $TS_ROUTES"
    fi
    if [ -n "${TS_EXIT_NODE:-}" ]; then
        UP_ARGS="$UP_ARGS --exit-node $TS_EXIT_NODE"
    fi
    if ! bool_false "${TS_ACCEPT_DNS:-0}"; then
        UP_ARGS="$UP_ARGS --accept-dns"
    fi
    if ! bool_false "${TS_ACCEPT_ROUTES:-0}"; then
        UP_ARGS="$UP_ARGS --accept-routes"
    fi
    if [ -n "${TS_EXTRA_ARGS:-}" ]; then
        UP_ARGS="$UP_ARGS $TS_EXTRA_ARGS"
    fi

    log "running rustscale up"
    # shellcheck disable=SC2086 # intentional word splitting for args
    if ! rustscale --socket "$SOCKET" up $UP_ARGS; then
        err "rustscale up failed"
    fi
    log "login complete"
fi

# ---------------------------------------------------------------------------
# Keep the container alive
# ---------------------------------------------------------------------------

log "rustscale is up; container ready"

# Wait for the daemon to exit. If it dies, the container should exit too.
set +e
wait $DAEMON_PID
EXIT_CODE=$?
set -e
log "rustscaled exited with code $EXIT_CODE"
exit $EXIT_CODE
