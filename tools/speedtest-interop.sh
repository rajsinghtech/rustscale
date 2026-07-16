#!/usr/bin/env bash
# Build a checksum-verified pinned Go peer and run loopback Go↔Rust speedtest v2 interop.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
PEER_DIR="$ROOT/tools/speedtest-interop"
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
if [[ "$TARGET_DIR" != /* ]]; then
  TARGET_DIR="$ROOT/$TARGET_DIR"
fi
PEER_ROOT="$TARGET_DIR/speedtest-interop"
PEER_BIN="$PEER_ROOT/speedtest-go-peer"
EXPECTED_MODULE="tailscale.com"
EXPECTED_VERSION="v1.100.0"
EXPECTED_SUM="h1:nm/M/dEaW9RaRsGUjW2HsSDpsZ60Jwd9k4gNW9tTFiE="

command -v cargo >/dev/null 2>&1 || {
  echo "speedtest interop requires cargo" >&2
  exit 1
}
GO_COMMAND="$(command -v go 2>/dev/null || true)"
[[ -n "$GO_COMMAND" ]] || {
  echo "speedtest interop requires Go 1.26.4 or newer in the 1.26 release" >&2
  exit 1
}
if [[ "$GO_COMMAND" != /* ]]; then
  GO_COMMAND="$(cd "$(dirname "$GO_COMMAND")" && pwd -P)/$(basename "$GO_COMMAND")"
fi
GO_BIN="$(cd "$(dirname "$GO_COMMAND")" && pwd -P)/$(basename "$GO_COMMAND")"
[[ -f "$GO_BIN" && -x "$GO_BIN" ]] || {
  echo "speedtest interop Go toolchain is not an executable regular file" >&2
  exit 1
}
GO_BIN_DIR="$(dirname "$GO_BIN")"
mkdir -p "$PEER_ROOT"
CACHE_ROOT="$(mktemp -d "$PEER_ROOT/verified-cache.XXXXXX")"
cleanup() {
  chmod -R u+w "$CACHE_ROOT" 2>/dev/null || true
  rm -rf "$CACHE_ROOT"
}
trap cleanup INT TERM EXIT
TOOLCHAIN_HOME="$CACHE_ROOT/toolchain-home"
mkdir -p "$TOOLCHAIN_HOME"

ENV_BIN="$(command -p -v env)"
[[ "$ENV_BIN" == /* && -f "$ENV_BIN" && -x "$ENV_BIN" ]] || {
  echo "speedtest interop cannot locate the system env executable" >&2
  exit 1
}
GO_VERSION_OUTPUT="$(
  "$ENV_BIN" -i \
    HOME="$TOOLCHAIN_HOME" PATH="$GO_BIN_DIR" GOENV=off GOFLAGS=-mod=readonly GOWORK=off \
    GOPROXY=off GOTOOLCHAIN=local \
    "$GO_BIN" version
)"
if [[ ! "$GO_VERSION_OUTPUT" =~ ^go[[:space:]]version[[:space:]]go1\.26\.([0-9]+)[[:space:]] ]]; then
  echo "speedtest interop requires an explicit Go 1.26.x toolchain; got: $GO_VERSION_OUTPUT" >&2
  exit 1
fi
if (( 10#${BASH_REMATCH[1]} < 4 )); then
  echo "speedtest interop requires Go 1.26.4 or newer; got: $GO_VERSION_OUTPUT" >&2
  exit 1
fi

PINNED_SUM=""
while read -r module version sum extra; do
  if [[ "$module" == "$EXPECTED_MODULE" && "$version" == "$EXPECTED_VERSION" ]]; then
    [[ -z "${extra:-}" && -z "$PINNED_SUM" ]] || {
      echo "speedtest interop found ambiguous pinned module checksums" >&2
      exit 1
    }
    PINNED_SUM="$sum"
  fi
done < "$PEER_DIR/go.sum"
[[ "$EXPECTED_SUM" == h1:* && -n "${EXPECTED_SUM#h1:}" ]] || {
  echo "speedtest interop has no nonempty expected module checksum" >&2
  exit 1
}
[[ "$PINNED_SUM" == "$EXPECTED_SUM" ]] || {
  echo "speedtest interop pinned go.sum checksum does not match the expected module" >&2
  exit 1
}

BUILD_HOME="$CACHE_ROOT/home"
BUILD_GOCACHE="$CACHE_ROOT/gocache"
BUILD_GOMODCACHE="$CACHE_ROOT/gomodcache"
BUILD_GOPATH="$CACHE_ROOT/gopath"
RUNTIME_ROOT="$CACHE_ROOT/runtime"
mkdir -p \
  "$BUILD_HOME" "$BUILD_GOCACHE" "$BUILD_GOMODCACHE" "$BUILD_GOPATH" \
  "$RUNTIME_ROOT/home" "$RUNTIME_ROOT/gocache" "$RUNTIME_ROOT/gomodcache" "$RUNTIME_ROOT/gopath"

run_go() {
  "$ENV_BIN" -i \
    HOME="$BUILD_HOME" \
    GOCACHE="$BUILD_GOCACHE" \
    GOMODCACHE="$BUILD_GOMODCACHE" \
    GOPATH="$BUILD_GOPATH" \
    PATH="$GO_BIN_DIR" \
    GOENV=off \
    GOFLAGS=-mod=readonly \
    GOWORK=off \
    GOPROXY=https://proxy.golang.org \
    GOSUMDB=sum.golang.org \
    GONOSUMDB= \
    GONOPROXY= \
    GOPRIVATE= \
    GOTOOLCHAIN=local \
    "$GO_BIN" "$@"
}

(
  cd "$PEER_DIR"
  run_go mod download "$EXPECTED_MODULE@$EXPECTED_VERSION"
  run_go mod verify
  chmod -R a-w "$BUILD_GOMODCACHE"
  run_go mod verify
  run_go test -mod=readonly ./...
  run_go build -mod=readonly -trimpath -buildvcs=false -o "$PEER_BIN" .
)

BUILD_INFO="$(run_go version -m "$PEER_BIN")"
EXPECTED_DEP_LINE=$'\tdep\t'"$EXPECTED_MODULE"$'\t'"$EXPECTED_VERSION"$'\t'"$EXPECTED_SUM"
[[ "$BUILD_INFO" == *"$EXPECTED_DEP_LINE"* ]] || {
  echo "speedtest interop binary lacks exact pinned module version and checksum metadata" >&2
  exit 1
}
[[ "$BUILD_INFO" != *$'\t=>\t'* ]] || {
  echo "speedtest interop binary contains a forbidden module replacement" >&2
  exit 1
}

RUSTSCALE_SPEEDTEST_GO_PEER="$PEER_BIN" \
RUSTSCALE_SPEEDTEST_GO_TOOLCHAIN="$GO_BIN" \
RUSTSCALE_SPEEDTEST_GO_RUNTIME_ROOT="$RUNTIME_ROOT" \
  cargo test --manifest-path "$ROOT/Cargo.toml" -p rustscale-speedtest \
    --test go_interop --locked -- --nocapture --test-threads=1
