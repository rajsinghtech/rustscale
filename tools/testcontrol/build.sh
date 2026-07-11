#!/bin/bash
# build.sh — builds the testcontrol Go binary that wraps Tailscale's fake
# control server for wire-format interop testing against rustscale's tsnet.
#
# Output: tools/testcontrol/bin/testcontrol
#
# The Go program requires the tailscale.com module. By default it uses a
# replace directive pointing at TS_GO_PATH (defaults to
# /Users/rajsingh/Documents/GitHub/tailscale). In CI, set TS_GO_PATH to
# a checkout of github.com/tailscale/tailscale.
set -euo pipefail

cd "$(dirname "$0")"

TS_GO_PATH="${TS_GO_PATH:-/Users/rajsingh/Documents/GitHub/tailscale}"

if ! command -v go >/dev/null 2>&1; then
    echo "build.sh: go toolchain not found in PATH" >&2
    exit 1
fi

if [ ! -d "$TS_GO_PATH" ]; then
    echo "build.sh: tailscale checkout not found at $TS_GO_PATH" >&2
    echo "  Set TS_GO_PATH to a checkout of github.com/tailscale/tailscale" >&2
    exit 1
fi

# Update the replace directive to point at the requested checkout, then tidy
# and build. Using go mod edit ensures the path is always correct regardless
# of what's committed in go.mod.
go mod edit -replace "tailscale.com=$TS_GO_PATH"
go mod tidy
go build -o bin/testcontrol .

echo "Built: $(pwd)/bin/testcontrol"
