#!/bin/sh
# Static release-contract checks shared by local development and CI.

set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$ROOT"

version=$(awk '
    /^\[workspace.package\]/ { workspace = 1; next }
    workspace && /^version = / { gsub(/[" ]/, "", $3); print $3; exit }
' Cargo.toml)
test -n "$version"
test -s "docs/release-notes-$version.md"
test -s LICENSE

# Every workspace member must inherit the release version and package metadata.
for manifest in crates/*/Cargo.toml; do
    case "$manifest" in crates/bench-tsrs/Cargo.toml) continue ;; esac
    grep -q '^version.workspace = true' "$manifest" || {
        echo "$manifest does not inherit workspace version" >&2
        exit 1
    }
    grep -q '^license.workspace = true' "$manifest" || {
        echo "$manifest does not inherit workspace license" >&2
        exit 1
    }
    grep -q '^repository.workspace = true' "$manifest" || {
        echo "$manifest does not inherit workspace repository" >&2
        exit 1
    }
done

cargo metadata --no-deps --format-version 1 | jq -e --arg version "$version" '
    ([.packages[] | select(.version != $version)] | length == 0) and
    ([.packages[] | select(.publish != []) | select(.description == null)] | length == 0) and
    ([.packages[].dependencies[] |
        select(.path != null and .req == "*" and .kind != "dev")] | length == 0)
' >/dev/null

# All action references must be immutable commit SHAs, never moving tags.
if awk '
    /^[[:space:]]*-?[[:space:]]*uses:/ {
        ref = $0
        sub(/^.*uses:[[:space:]]*/, "", ref)
        sub(/[[:space:]]*#.*/, "", ref)
        split(ref, parts, "@")
        if (parts[2] !~ /^[0-9a-f]{40}$/) print FILENAME ":" FNR ":" $0
    }
' .github/workflows/*.yml | grep .; then
    echo "workflow action references above are not SHA-pinned" >&2
    exit 1
fi

for target in \
    universal-apple-darwin \
    x86_64-unknown-linux-gnu \
    aarch64-unknown-linux-gnu \
    x86_64-unknown-linux-musl \
    x86_64-pc-windows-msvc; do
    grep -q "$target" .github/workflows/release.yml
done

grep -q 'body_path:.*needs.metadata.outputs.notes' .github/workflows/release.yml
grep -q 'SHA256SUMS' scripts/install.sh
grep -q 'SHA256SUMS' scripts/install.ps1
grep -q 'packaging/systemd/rustscaled.service' .github/workflows/release.yml
grep -Fq "rustscaled run --state /var/lib/rustscale --socket /var/run/rustscaled.sock --tun \$FLAGS" packaging/systemd/rustscaled.service
if grep -Eq -- '--(state|statedir|socket)=' packaging/systemd/rustscaled.service; then
    echo "systemd unit uses unsupported --flag=value daemon syntax" >&2
    exit 1
fi
grep -q 'ln -s rustscale /usr/local/bin/tailscale' Dockerfile
grep -q 'org.opencontainers.image.version' Dockerfile
test "$(grep -c '^FROM .*@sha256:[0-9a-f]\{64\}' Dockerfile)" -eq 2
grep -q "v$version" site/index.html

echo "release contract: v$version ok"
