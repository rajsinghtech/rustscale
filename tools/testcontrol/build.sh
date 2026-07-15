#!/bin/bash
# build.sh — builds the testcontrol Go binary that wraps Tailscale's fake
# control server for wire-format interop testing against rustscale's tsnet.
#
# Output: tools/testcontrol/bin/testcontrol
#
# The Go program uses the pinned tailscale.com module published from
# github.com/tailscale/tailscale.
set -euo pipefail

cd "$(dirname "$0")"

if ! command -v go >/dev/null 2>&1; then
    echo "build.sh: go toolchain not found in PATH" >&2
    exit 1
fi

go mod download
go build -o bin/testcontrol .

echo "Built: $(pwd)/bin/testcontrol"
