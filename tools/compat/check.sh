#!/usr/bin/env bash
# Offline compatibility-contract gate: build local extractable artifacts, run
# focused generator tests, and require byte-for-byte manifest regeneration.
set -euo pipefail

cd "$(dirname "$0")/../.."
export PYTHONDONTWRITEBYTECODE=1
export CARGO_NET_OFFLINE=true

cargo build -p rustscale-cli -p rustscale-ffi --locked
cargo doc -p rustscale-tsnet --no-deps --all-features --locked
python3 -B -m unittest discover -s tools/compat/tests -p 'test_*.py'
python3 -B tools/compat/generate.py generate --check

echo "compat contracts ok"
