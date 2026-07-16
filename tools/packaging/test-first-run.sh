#!/usr/bin/env bash
# Installed Linux first-run release acceptance gate. Builds real release-mode
# binaries, then delegates the privileged journey to the serial Rust harness.

set -euo pipefail

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"

case "$(uname -s)" in
  Linux) ;;
  *)
    echo "installed first-run gate: Linux only; skipped"
    exit 0
    ;;
esac

sudo -n true

WATCHDOG_DIR=$(mktemp -d "${TMPDIR:-/tmp}/rustscale-first-run-watchdog.XXXXXX")
PGID_FILE="$WATCHDOG_DIR/daemon.pgid"
SOCKET_OWNERSHIP_FILE="$WATCHDOG_DIR/socket-owned"
FIXTURE_PARENT="$WATCHDOG_DIR/fixture"
mkdir -p "$FIXTURE_PARENT"
# The installed CLI is executed as nobody; every fixture ancestor must be
# traversable without making watchdog metadata writable.
chmod 0711 "$WATCHDOG_DIR" "$FIXTURE_PARENT"
cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [ -s "$PGID_FILE" ]; then
    IFS= read -r pgid < "$PGID_FILE" || true
    if [[ "$pgid" =~ ^[1-9][0-9]*$ ]]; then
      sudo -n kill -TERM -- "-$pgid" 2>/dev/null || true
      for _ in {1..50}; do
        sudo -n kill -0 -- "-$pgid" 2>/dev/null || break
        sleep 0.1
      done
      sudo -n kill -KILL -- "-$pgid" 2>/dev/null || true
    fi
  fi
  if [ -e "$SOCKET_OWNERSHIP_FILE" ]; then
    sudo -n rm -f -- /var/run/rustscaled.sock 2>/dev/null || true
  fi
  sudo -n rm -rf -- "$WATCHDOG_DIR" 2>/dev/null || rm -rf "$WATCHDOG_DIR"
  exit "$status"
}
trap cleanup EXIT INT TERM

cargo build --release --locked -p rustscale-cli -p rustscale-rustscaled
timeout --signal=TERM --kill-after=15s 300s \
  env RUSTSCALE_RELEASE_CLI="$ROOT/target/release/rustscale" \
  RUSTSCALE_RELEASE_DAEMON="$ROOT/target/release/rustscaled" \
  RUSTSCALE_DAEMON_PGID_FILE="$PGID_FILE" \
  RUSTSCALE_SOCKET_OWNERSHIP_FILE="$SOCKET_OWNERSHIP_FILE" \
  RUSTSCALE_FIXTURE_PARENT="$FIXTURE_PARENT" \
  cargo test --release --locked -p rustscale-rustscaled \
    --test release_first_run -- --ignored --nocapture --test-threads=1
