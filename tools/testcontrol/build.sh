#!/bin/bash
# build.sh — builds the testcontrol Go binary that wraps Tailscale's fake
# control server for wire-format interop testing against rustscale's tsnet.
#
# Output: tools/testcontrol/bin/testcontrol, or TESTCONTROL_OUTPUT when set.
# When TESTCONTROL_GO_CLIENT_DIR is set, also build the pinned upstream
# tailscale and tailscaled commands into that directory for local peer tests.
#
# The Go program uses the pinned tailscale.com module published from
# github.com/tailscale/tailscale.
set -euo pipefail

cd "$(dirname "$0")"

if ! command -v go >/dev/null 2>&1; then
    echo "build.sh: go toolchain not found in PATH" >&2
    exit 1
fi

output="${TESTCONTROL_OUTPUT:-bin/testcontrol}"
case "$output" in
    /*) ;;
    *) output="$(pwd)/$output" ;;
esac
mkdir -p "$(dirname "$output")"

go mod download
./with-audit-patch.sh build -o "$output" .

echo "Built: $output"

if [[ -n "${TESTCONTROL_GO_CLIENT_DIR:-}" ]]; then
    client_dir="$TESTCONTROL_GO_CLIENT_DIR"
    case "$client_dir" in
        /*) ;;
        *) client_dir="$(pwd)/$client_dir" ;;
    esac
    mkdir -p "$client_dir"

    module_version="$(go list -m -f '{{.Version}}' tailscale.com)"
    [[ "$module_version" == v1.100.0 ]] || {
        echo "build.sh: unexpected tailscale.com version: $module_version" >&2
        exit 1
    }
    module_dir="$(go list -m -f '{{.Dir}}' tailscale.com)"
    [[ -n "$module_dir" && -d "$module_dir" ]] || {
        echo "build.sh: pinned tailscale.com module directory not found" >&2
        exit 1
    }
    (
        cd "$module_dir"
        go build -o "$client_dir/tailscale" ./cmd/tailscale
        go build -o "$client_dir/tailscaled" ./cmd/tailscaled
    )
    echo "Built pinned Go clients: $client_dir/tailscale, $client_dir/tailscaled"
fi
