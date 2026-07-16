#!/usr/bin/env bash
# Build the pinned upstream Go speedtest peer and run loopback Go↔Rust v2 interop.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PEER_DIR="$ROOT/tools/speedtest-interop"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
if [[ "$TARGET_DIR" != /* ]]; then
  TARGET_DIR="$ROOT/$TARGET_DIR"
fi
PEER_BIN="$TARGET_DIR/speedtest-interop/speedtest-go-peer"

command -v go >/dev/null 2>&1 || {
  echo "speedtest interop requires Go 1.26 or newer" >&2
  exit 1
}
command -v cargo >/dev/null 2>&1 || {
  echo "speedtest interop requires cargo" >&2
  exit 1
}

mkdir -p "$(dirname "$PEER_BIN")"
(
  cd "$PEER_DIR"
  GOTOOLCHAIN=local go build -mod=readonly -trimpath -buildvcs=false -o "$PEER_BIN" .
)

RUSTSCALE_SPEEDTEST_GO_PEER="$PEER_BIN" \
  cargo test --manifest-path "$ROOT/Cargo.toml" -p rustscale-speedtest \
    --test go_interop --locked -- --nocapture --test-threads=1
