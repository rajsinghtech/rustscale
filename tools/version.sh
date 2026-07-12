#!/usr/bin/env bash
# tools/version.sh — print the rustscale version string.
#
# Uses `git describe --tags --long --always --dirty` when a git checkout is
# available, falling back to the workspace version in Cargo.toml otherwise
# (e.g. when building from a crates.io tarball).  The same logic is embedded
# in crates/ffi/build.rs so that the FFI library exposes the string at runtime
# via ts_version(); this script exists for the release workflow and shell-based
# tooling that needs the version outside of cargo.
set -euo pipefail
cd "$(dirname "$0")/.."

v=$(git describe --tags --long --always --dirty 2>/dev/null || true)
if [ -n "$v" ]; then
    echo "$v"
else
    # Fall back to the workspace.package.version field.
    sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1
fi
