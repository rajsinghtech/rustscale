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
    printf '#!/bin/sh\necho %s\n' "$archive" > "$stage/rustscale"
    printf '#!/bin/sh\necho rustscaled-%s\n' "$archive" > "$stage/rustscaled"
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
    libc="$4"
    expected_archive="$5"
    prefix="$TMP/prefix-$name"
    INSTALL_SERVICE=0 PREFIX="$prefix" RUSTSCALE_RELEASE_BASE="$RELEASE_BASE" \
        RUSTSCALE_UNAME_S="$uname_s" RUSTSCALE_UNAME_M="$uname_m" \
        RUSTSCALE_LIBC="$libc" \
        sh "$ROOT/scripts/install.sh" --version 0.1.1 >/dev/null

    test -x "$prefix/bin/rustscale"
    test "$("$prefix/bin/rustscale")" = "$expected_archive"
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
        RUSTSCALE_UNAME_M="$uname_m" RUSTSCALE_LIBC="$libc" \
        sh "$ROOT/scripts/install.sh" --uninstall >/dev/null
    test ! -e "$prefix/bin/rustscale"
    test ! -e "$prefix/bin/.rustscale-install-receipt-v1"
    test ! -e "$prefix/bin/tailscale"
}

run_case darwin-amd64 Darwin x86_64 ignored rustscale-universal-apple-darwin.tar.gz
run_case darwin-arm64 Darwin arm64 ignored rustscale-universal-apple-darwin.tar.gz
run_case linux-amd64-gnu Linux x86_64 gnu rustscale-x86_64-unknown-linux-gnu.tar.gz
run_case linux-amd64-musl Linux x86_64 musl rustscale-x86_64-unknown-linux-musl.tar.gz
run_case linux-arm64-gnu Linux aarch64 gnu rustscale-aarch64-unknown-linux-gnu.tar.gz

# Exercise libc auto-detection deterministically through getconf and ldd.
mkdir -p "$TMP/fake-libc-bin"
cat > "$TMP/fake-libc-bin/getconf" <<'EOF'
#!/bin/sh
if [ "${TEST_LIBC:-}" = gnu ] && [ "$1" = GNU_LIBC_VERSION ]; then
    echo 'glibc 2.39'
    exit 0
fi
exit 1
EOF
cat > "$TMP/fake-libc-bin/ldd" <<'EOF'
#!/bin/sh
if [ "${TEST_LIBC:-}" = musl ]; then
    echo 'musl libc (x86_64)' >&2
    exit 1
fi
echo 'ldd (GNU libc) 2.39'
EOF
chmod +x "$TMP/fake-libc-bin/getconf" "$TMP/fake-libc-bin/ldd"
for libc in gnu musl; do
    prefix="$TMP/prefix-detected-$libc"
    PATH="$TMP/fake-libc-bin:$PATH" TEST_LIBC="$libc" \
        INSTALL_SERVICE=0 PREFIX="$prefix" RUSTSCALE_RELEASE_BASE="$RELEASE_BASE" \
        RUSTSCALE_UNAME_S=Linux RUSTSCALE_UNAME_M=x86_64 \
        sh "$ROOT/scripts/install.sh" --version 0.1.1 >/dev/null
    test "$("$prefix/bin/rustscale")" = "rustscale-x86_64-unknown-linux-$libc.tar.gz"
done

# No aarch64-musl release is published; reject it before selecting an HTTP client.
prefix="$TMP/prefix-linux-arm64-musl"
if INSTALL_SERVICE=0 PREFIX="$prefix" RUSTSCALE_RELEASE_BASE="$TMP/does-not-exist" \
    RUSTSCALE_UNAME_S=Linux RUSTSCALE_UNAME_M=aarch64 RUSTSCALE_LIBC=musl \
    RUSTSCALE_HTTP_CLIENT=not-a-client \
    sh "$ROOT/scripts/install.sh" --version 0.1.1 >"$TMP/aarch64-musl.out" 2>&1; then
    echo "aarch64 musl unexpectedly selected a release archive" >&2
    exit 1
fi
grep -q 'no published release archive for linux-aarch64-musl' "$TMP/aarch64-musl.out"
test ! -e "$prefix/bin/rustscale"

# Exercise the no-version latest-release path.
prefix="$TMP/prefix-latest"
INSTALL_SERVICE=0 PREFIX="$prefix" RUSTSCALE_RELEASE_BASE="$RELEASE_BASE" \
    RUSTSCALE_UNAME_S=Linux RUSTSCALE_UNAME_M=x86_64 RUSTSCALE_LIBC=gnu \
    sh "$ROOT/scripts/install.sh" >/dev/null
test -x "$prefix/bin/rustscale"

# An explicit no-alias install and its uninstall must not remove an upstream
# installation that RustScale did not create.
prefix="$TMP/prefix-upstream"
mkdir -p "$prefix/bin"
printf 'official tailscale\n' > "$prefix/bin/tailscale"
ln -s /opt/tailscale/tailscaled "$prefix/bin/tailscaled"
INSTALL_SERVICE=0 PREFIX="$prefix" RUSTSCALE_RELEASE_BASE="$RELEASE_BASE" \
    RUSTSCALE_UNAME_S=Linux RUSTSCALE_UNAME_M=x86_64 RUSTSCALE_LIBC=gnu \
    sh "$ROOT/scripts/install.sh" --version "$VERSION" --no-tailscale-compatible >/dev/null
INSTALL_SERVICE=0 PREFIX="$prefix" RUSTSCALE_UNAME_S=Linux \
    RUSTSCALE_UNAME_M=x86_64 RUSTSCALE_LIBC=gnu \
    sh "$ROOT/scripts/install.sh" --uninstall >/dev/null
grep -q 'official tailscale' "$prefix/bin/tailscale"
test "$(readlink "$prefix/bin/tailscaled")" = /opt/tailscale/tailscaled

# The ordinary documented installation must fail before installing anything
# when either default alias would replace an official command. Exercise each
# destination so validation cannot accidentally stop after only the CLI alias.
prefix="$TMP/prefix-compat-cli-collision"
mkdir -p "$prefix/bin"
printf 'official tailscale\n' > "$prefix/bin/tailscale"
if INSTALL_SERVICE=0 PREFIX="$prefix" RUSTSCALE_RELEASE_BASE="$RELEASE_BASE" \
    RUSTSCALE_UNAME_S=Linux RUSTSCALE_UNAME_M=x86_64 RUSTSCALE_LIBC=gnu \
    sh "$ROOT/scripts/install.sh" --version "$VERSION" \
        >"$TMP/compat-cli-collision.out" 2>&1; then
    echo "ordinary install unexpectedly replaced the official CLI" >&2
    exit 1
fi
grep -q 'refusing to replace existing compatibility command' "$TMP/compat-cli-collision.out"
grep -q 'official tailscale' "$prefix/bin/tailscale"
test ! -e "$prefix/bin/rustscale"
test ! -e "$prefix/bin/rustscaled"
test ! -e "$prefix/bin/.rustscale-install-receipt-v1"

prefix="$TMP/prefix-compat-daemon-collision"
mkdir -p "$prefix/bin"
ln -s rustscale "$prefix/bin/tailscale"
ln -s /opt/tailscale/tailscaled "$prefix/bin/tailscaled"
if INSTALL_SERVICE=0 PREFIX="$prefix" RUSTSCALE_RELEASE_BASE="$RELEASE_BASE" \
    RUSTSCALE_UNAME_S=Linux RUSTSCALE_UNAME_M=x86_64 RUSTSCALE_LIBC=gnu \
    sh "$ROOT/scripts/install.sh" --version "$VERSION" \
        >"$TMP/compat-daemon-collision.out" 2>&1; then
    echo "ordinary install unexpectedly replaced the official daemon alias" >&2
    exit 1
fi
grep -q 'refusing to replace existing compatibility command' "$TMP/compat-daemon-collision.out"
test "$(readlink "$prefix/bin/tailscale")" = rustscale
test "$(readlink "$prefix/bin/tailscaled")" = /opt/tailscale/tailscaled
test ! -e "$prefix/bin/rustscale"
test ! -e "$prefix/bin/rustscaled"
test ! -e "$prefix/bin/.rustscale-install-receipt-v1"

# Pre-existing installer-owned default links are idempotent and remain
# relative. The installer never redirects aliases into official state/socket
# paths; those remain the RustScale paths encoded by the shipped unit.
prefix="$TMP/prefix-compat-owned"
mkdir -p "$prefix/bin"
ln -s rustscale "$prefix/bin/tailscale"
ln -s rustscaled "$prefix/bin/tailscaled"
INSTALL_SERVICE=0 PREFIX="$prefix" RUSTSCALE_RELEASE_BASE="$RELEASE_BASE" \
    RUSTSCALE_UNAME_S=Linux RUSTSCALE_UNAME_M=x86_64 RUSTSCALE_LIBC=gnu \
    sh "$ROOT/scripts/install.sh" --version "$VERSION" >/dev/null
test "$(readlink "$prefix/bin/tailscale")" = rustscale
test "$(readlink "$prefix/bin/tailscaled")" = rustscaled

# An explicit opt-out is portable-install behavior only; ordinary installs
# above remain the replacement journey's default contract.
prefix="$TMP/prefix-no-aliases"
INSTALL_SERVICE=0 PREFIX="$prefix" RUSTSCALE_RELEASE_BASE="$RELEASE_BASE" \
    RUSTSCALE_UNAME_S=Linux RUSTSCALE_UNAME_M=x86_64 RUSTSCALE_LIBC=gnu \
    sh "$ROOT/scripts/install.sh" --version "$VERSION" --no-tailscale-compatible >/dev/null
test ! -e "$prefix/bin/tailscale"
test ! -e "$prefix/bin/tailscaled"

grep -Fq '/var/lib/rustscale' "$ROOT/packaging/systemd/rustscaled.service"
grep -Fq '/var/run/rustscaled.sock' "$ROOT/packaging/systemd/rustscaled.service"
if grep -Eq '/var/(lib|run)/tailscale|/var/run/tailscaled[.]sock' \
    "$ROOT/packaging/systemd/rustscaled.service"; then
    echo "rustscaled service unexpectedly uses official Tailscale state" >&2
    exit 1
fi

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
    RUSTSCALE_UNAME_S=Linux RUSTSCALE_UNAME_M=x86_64 RUSTSCALE_LIBC=gnu \
    sh "$ROOT/scripts/install.sh" --version "$VERSION" >/dev/null
test -x "$prefix/bin/rustscale"

# A modified archive must fail closed before anything is installed.
printf 'tamper\n' >> "$RELEASE_DIR/rustscale-x86_64-unknown-linux-gnu.tar.gz"
prefix="$TMP/prefix-tampered"
if INSTALL_SERVICE=0 PREFIX="$prefix" RUSTSCALE_RELEASE_BASE="$RELEASE_BASE" \
    RUSTSCALE_UNAME_S=Linux RUSTSCALE_UNAME_M=x86_64 RUSTSCALE_LIBC=gnu \
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
