#!/bin/sh
# End-to-end tests for the release installer contract. All downloads use a
# temporary file:// release tree and every install goes to a temporary prefix.

set -eu
unset GH_TOKEN GITHUB_TOKEN || true

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/rustscale-packaging-test.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

VERSION=v0.1.1
RELEASE_DIR="$TMP/releases/download/$VERSION"
mkdir -p "$RELEASE_DIR"

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

make_unix_archive() {
    archive="$1"
    extension="$2"
    stage="$TMP/stage-$archive"
    mkdir -p "$stage"
    printf '#!/bin/sh\necho rustscale-test\n' > "$stage/rustscale"
    printf '#!/bin/sh\necho rustscaled-test\n' > "$stage/rustscaled"
    chmod +x "$stage/rustscale" "$stage/rustscaled"
    printf 'shared library\n' > "$stage/librustscale.$extension"
    printf 'static library\n' > "$stage/librustscale.a"
    printf '/* header */\n' > "$stage/rustscale.h"
    cp "$ROOT/LICENSE" "$stage/LICENSE"
    if [ "$extension" = so ]; then
        cp "$ROOT/packaging/systemd/rustscaled.service" "$stage/"
        cp "$ROOT/packaging/systemd/rustscaled.default" "$stage/"
    fi
    tar --format=ustar -czf "$RELEASE_DIR/$archive" -C "$stage" .
}

make_unix_archive rustscale-universal-apple-darwin.tar.gz dylib
make_unix_archive rustscale-x86_64-unknown-linux-gnu.tar.gz so
make_unix_archive rustscale-aarch64-unknown-linux-gnu.tar.gz so
make_unix_archive rustscale-x86_64-unknown-linux-musl.tar.gz so

for archive in "$RELEASE_DIR"/*.tar.gz; do
    name=$(basename "$archive")
    printf '%s  %s\n' "$(sha256_file "$archive")" "$name"
done > "$RELEASE_DIR/SHA256SUMS"

mkdir -p "$TMP/releases/latest"
ln -s "../download/$VERSION" "$TMP/releases/latest/download"
RELEASE_BASE="file://$TMP/releases"

run_case() {
    name="$1"
    uname_s="$2"
    uname_m="$3"
    prefix="$TMP/prefix-$name"
    INSTALL_SERVICE=0 PREFIX="$prefix" RUSTSCALE_RELEASE_BASE="$RELEASE_BASE" \
        RUSTSCALE_UNAME_S="$uname_s" RUSTSCALE_UNAME_M="$uname_m" \
        sh "$ROOT/scripts/install.sh" --version 0.1.1 --tailscale-compatible >/dev/null

    test -x "$prefix/bin/rustscale"
    test -x "$prefix/bin/rustscaled"
    test -f "$prefix/bin/.rustscale-install-receipt-v1"
    grep -q '^installer=scripts/install.sh$' "$prefix/bin/.rustscale-install-receipt-v1"
    test "$(awk -F= '/^rustscale_sha256=/ { print $2 }' "$prefix/bin/.rustscale-install-receipt-v1")" = "$(sha256_file "$prefix/bin/rustscale")"
    test "$(awk -F= '/^rustscaled_sha256=/ { print $2 }' "$prefix/bin/.rustscale-install-receipt-v1")" = "$(sha256_file "$prefix/bin/rustscaled")"
    test -L "$prefix/bin/tailscale"
    test -L "$prefix/bin/tailscaled"
    test -f "$prefix/lib/librustscale.a"
    test -f "$prefix/include/rustscale.h"

    INSTALL_SERVICE=0 PREFIX="$prefix" RUSTSCALE_UNAME_S="$uname_s" \
        RUSTSCALE_UNAME_M="$uname_m" sh "$ROOT/scripts/install.sh" --uninstall >/dev/null
    test ! -e "$prefix/bin/rustscale"
    test ! -e "$prefix/bin/.rustscale-install-receipt-v1"
    test ! -e "$prefix/bin/tailscale"
}

run_case darwin-amd64 Darwin x86_64
run_case darwin-arm64 Darwin arm64
run_case linux-amd64 Linux x86_64
run_case linux-arm64 Linux aarch64

# Exercise the no-version latest-release path.
prefix="$TMP/prefix-latest"
INSTALL_SERVICE=0 PREFIX="$prefix" RUSTSCALE_RELEASE_BASE="$RELEASE_BASE" \
    RUSTSCALE_UNAME_S=Linux RUSTSCALE_UNAME_M=x86_64 \
    sh "$ROOT/scripts/install.sh" >/dev/null
test -x "$prefix/bin/rustscale"

# Uninstall must not remove an upstream installation that rustscale did not
# create. This is the safety boundary for drop-in replacement mode.
prefix="$TMP/prefix-upstream"
mkdir -p "$prefix/bin"
printf 'official tailscale\n' > "$prefix/bin/tailscale"
ln -s /opt/tailscale/tailscaled "$prefix/bin/tailscaled"
INSTALL_SERVICE=0 PREFIX="$prefix" RUSTSCALE_RELEASE_BASE="$RELEASE_BASE" \
    RUSTSCALE_UNAME_S=Linux RUSTSCALE_UNAME_M=x86_64 \
    sh "$ROOT/scripts/install.sh" --version "$VERSION" >/dev/null
INSTALL_SERVICE=0 PREFIX="$prefix" RUSTSCALE_UNAME_S=Linux \
    RUSTSCALE_UNAME_M=x86_64 sh "$ROOT/scripts/install.sh" --uninstall >/dev/null
grep -q 'official tailscale' "$prefix/bin/tailscale"
test "$(readlink "$prefix/bin/tailscaled")" = /opt/tailscale/tailscaled

# Exercise wget separately with a deterministic file:// implementation.
mkdir -p "$TMP/fakebin"
cat > "$TMP/fakebin/wget" <<'EOF'
#!/bin/sh
test "$1" = -q
test "$2" = -O
output="$3"
url="$4"
cp "${url#file://}" "$output"
EOF
chmod +x "$TMP/fakebin/wget"
prefix="$TMP/prefix-wget"
PATH="$TMP/fakebin:$PATH" INSTALL_SERVICE=0 PREFIX="$prefix" \
    RUSTSCALE_HTTP_CLIENT=wget RUSTSCALE_RELEASE_BASE="$RELEASE_BASE" \
    RUSTSCALE_UNAME_S=Linux RUSTSCALE_UNAME_M=x86_64 \
    sh "$ROOT/scripts/install.sh" --version "$VERSION" >/dev/null
test -x "$prefix/bin/rustscale"

# A modified archive must fail closed before anything is installed.
printf 'tamper\n' >> "$RELEASE_DIR/rustscale-x86_64-unknown-linux-gnu.tar.gz"
prefix="$TMP/prefix-tampered"
if INSTALL_SERVICE=0 PREFIX="$prefix" RUSTSCALE_RELEASE_BASE="$RELEASE_BASE" \
    RUSTSCALE_UNAME_S=Linux RUSTSCALE_UNAME_M=x86_64 \
    sh "$ROOT/scripts/install.sh" --version "$VERSION" >/dev/null 2>&1; then
    echo "tampered archive unexpectedly installed" >&2
    exit 1
fi
test ! -e "$prefix/bin/rustscale"

# Help/error paths never build or mutate the host.
sh "$ROOT/scripts/install.sh" --help >/dev/null
sh "$ROOT/scripts/install-from-source.sh" --help >/dev/null
if sh "$ROOT/scripts/install.sh" --not-a-real-flag >/dev/null 2>&1; then
    echo "unknown installer flag unexpectedly succeeded" >&2
    exit 1
fi

echo "packaging installer tests: ok"
