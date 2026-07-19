#!/usr/bin/env bash
# Focused regression gate for the hermetic testcontrol audit-log contract.
set -euo pipefail

cd "$(dirname "$0")"
go mod download
./with-audit-patch.sh test tailscale.com/tstest/integration/testcontrol
./with-audit-patch.sh test .
