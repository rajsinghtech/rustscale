#!/bin/sh
# rustscale installer - builds from source and installs the C library + header.
#
# Modeled on Tailscale's scripts/installer.sh: POSIX sh, set -eu, all logic
# wrapped in main() invoked at the bottom so a truncated download never
# executes half a script.
#
# Environment variables:
#   PREFIX         Install prefix (default: /usr/local).
#                  Libs -> $PREFIX/lib, header -> $PREFIX/include,
#                  optional CLI -> $PREFIX/bin.
#   RUSTSCALE_REPO Git URL to clone from when not run inside the repo
#                  (default: https://github.com/rajsinghtech/rustscale).
#   RUSTSCALE_REF  Git ref (branch/tag/commit) to pin after clone
#                  (default: unset -> repository default branch).
#
# Flags:
#   --with-tun     Also build and install the rustscale-tun CLI example.
#   --uninstall    Remove the files this script installs.
#   --help, -h     Show this help.
#
# Examples:
#   sh scripts/install.sh
#   PREFIX=$HOME/.local sh scripts/install.sh --with-tun
#   curl -fsSL https://rustscale.dev/install.sh | PREFIX=/opt/rustscale sh

set -eu

PREFIX="${PREFIX:-/usr/local}"
RUSTSCALE_REPO="${RUSTSCALE_REPO:-https://github.com/rajsinghtech/rustscale}"
RUSTSCALE_REF="${RUSTSCALE_REF:-}"

# Working directory of a source clone, emptied when building in place. The trap
# guard keeps set -u happy when WORKDIR is never assigned.
WORKDIR=
trap '[ -n "$WORKDIR" ] && rm -rf "$WORKDIR"' EXIT

usage() {
    cat <<'EOF'
rustscale installer - builds from source and installs the C library + header.

Environment variables:
  PREFIX         Install prefix (default: /usr/local).
                 Libs -> $PREFIX/lib, header -> $PREFIX/include,
                 optional CLI -> $PREFIX/bin.
  RUSTSCALE_REPO Git URL to clone when not run inside the repo
                 (default: https://github.com/rajsinghtech/rustscale).
  RUSTSCALE_REF  Git ref (branch/tag/commit) to pin after clone
                 (default: unset -> default branch).

Flags:
  --with-tun     Also build and install the rustscale-tun CLI example.
  --uninstall    Remove the files this script installs.
  --help, -h     Show this help.

Examples:
  sh scripts/install.sh
  PREFIX=$HOME/.local sh scripts/install.sh --with-tun
  curl -fsSL https://rustscale.dev/install.sh | PREFIX=/opt/rustscale sh
EOF
}

# Run a command, escalating through sudo/doas only when INSTALL_SUDO is set.
# shellcheck disable=SC2086
run_as_root() {
    if [ -n "$INSTALL_SUDO" ]; then
        $INSTALL_SUDO "$@"
    else
        "$@"
    fi
}

main() {
    WITH_TUN=0
    UNINSTALL=0
    for arg in "$@"; do
        case "$arg" in
            --with-tun) WITH_TUN=1 ;;
            --uninstall) UNINSTALL=1 ;;
            --help|-h) usage; exit 0 ;;
            *)
                echo "rustscale: unknown option '$arg' (try --help)" >&2
                exit 1
                ;;
        esac
    done

    detect_os

    if [ "$UNINSTALL" = 1 ]; then
        do_uninstall
        return
    fi

    preflight
    acquire_source
    build
    choose_sudo
    do_install
    post_install
}

# Step 1: detect OS via uname and pick the shared-library extension.
detect_os() {
    case "$(uname -s)" in
        Darwin) OS=darwin; DYEXT=dylib ;;
        Linux)  OS=linux;  DYEXT=so ;;
        *)
            echo "rustscale: unsupported OS '$(uname -s)' (only darwin/linux are supported)" >&2
            exit 1
            ;;
    esac
}

# Step 2: preflight - cargo is mandatory; git is checked at clone time.
preflight() {
    if ! command -v cargo >/dev/null 2>&1; then
        echo "rustscale: 'cargo' was not found on PATH." >&2
        echo "Install the Rust toolchain with rustup:" >&2
        echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh" >&2
        exit 1
    fi
}

# Step 3: acquire source. Build in place when run from inside the repo
# (script sits next to Cargo.toml and include/rustscale.h), otherwise clone.
acquire_source() {
    script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
    if [ -f "$script_dir/../Cargo.toml" ] && [ -f "$script_dir/../include/rustscale.h" ]; then
        SRCDIR=$(CDPATH='' cd -- "$script_dir/.." && pwd)
        return
    fi

    if ! command -v git >/dev/null 2>&1; then
        echo "rustscale: 'git' was not found (needed to clone the source tree)." >&2
        exit 1
    fi

    WORKDIR=$(mktemp -d -t rustscale-install)
    SRCDIR="$WORKDIR/rustscale"
    echo "rustscale: cloning $RUSTSCALE_REPO"
    if [ -n "$RUSTSCALE_REF" ]; then
        git clone "$RUSTSCALE_REPO" "$SRCDIR"
        git -C "$SRCDIR" checkout "$RUSTSCALE_REF"
    else
        git clone --depth 1 "$RUSTSCALE_REPO" "$SRCDIR"
    fi
}

# Step 4: build release artifacts. --quiet suppresses progress noise while
# rustc diagnostics still surface on failure.
build() {
    manifest="$SRCDIR/Cargo.toml"
    echo "rustscale: building release artifacts (this can take a while)"
    if ! cargo build --manifest-path "$manifest" -p rustscale-ffi --release --quiet; then
        echo "rustscale: cargo build of rustscale-ffi failed" >&2
        exit 1
    fi
    if [ "$WITH_TUN" = 1 ]; then
        if ! cargo build --manifest-path "$manifest" -p rustscale-tsnet --release --example rustscale-tun --quiet; then
            echo "rustscale: cargo build of the rustscale-tun example failed" >&2
            exit 1
        fi
    fi

    SHARED_LIB="$SRCDIR/target/release/librustscale.$DYEXT"
    STATIC_LIB="$SRCDIR/target/release/librustscale.a"
    HEADER="$SRCDIR/include/rustscale.h"
    TUN_BIN="$SRCDIR/target/release/examples/rustscale-tun"

    for f in "$SHARED_LIB" "$STATIC_LIB" "$HEADER"; do
        if [ ! -f "$f" ]; then
            echo "rustscale: expected build output not found: $f" >&2
            exit 1
        fi
    done
    if [ "$WITH_TUN" = 1 ] && [ ! -f "$TUN_BIN" ]; then
        echo "rustscale: expected build output not found: $TUN_BIN" >&2
        exit 1
    fi
}

# Step 5: decide how to escalate for the install copy. The build itself never
# runs as root, mirroring Tailscale's installer keeping privileged work narrow.
choose_sudo() {
    INSTALL_SUDO=
    if [ -w "$PREFIX" ] 2>/dev/null; then
        return
    fi
    if [ "$(id -u)" = 0 ]; then
        return
    fi
    if command -v sudo >/dev/null 2>&1; then
        INSTALL_SUDO=sudo
    elif command -v doas >/dev/null 2>&1; then
        INSTALL_SUDO=doas
    else
        echo "rustscale: $PREFIX is not writable and neither sudo nor doas is available." >&2
        echo "Re-run as root or point PREFIX at a directory you own." >&2
        exit 1
    fi
}

# Step 6: install. 755 for the shared lib and binary, 644 for the static lib
# and header.
do_install() {
    echo "rustscale: installing to $PREFIX"
    run_as_root install -d -m 755 "$PREFIX/lib" "$PREFIX/include"
    run_as_root install -m 755 "$SHARED_LIB" "$PREFIX/lib/"
    run_as_root install -m 644 "$STATIC_LIB" "$PREFIX/lib/"
    run_as_root install -m 644 "$HEADER" "$PREFIX/include/"
    if [ "$WITH_TUN" = 1 ]; then
        run_as_root install -d -m 755 "$PREFIX/bin"
        run_as_root install -m 755 "$TUN_BIN" "$PREFIX/bin/"
    fi
    if [ "$OS" = linux ]; then
        # Refresh the dynamic linker cache; best-effort, ignore failure.
        run_as_root ldconfig 2>/dev/null || true
    fi
}

# Step 7: report what landed where and how to compile against it.
post_install() {
    echo
    echo "rustscale: installed:"
    echo "  $PREFIX/lib/librustscale.$DYEXT"
    echo "  $PREFIX/lib/librustscale.a"
    echo "  $PREFIX/include/rustscale.h"
    [ "$WITH_TUN" = 1 ] && echo "  $PREFIX/bin/rustscale-tun"
    echo
    echo "Compile against rustscale with:"
    echo "  cc app.c -I$PREFIX/include -L$PREFIX/lib -lrustscale"
    echo "See $PREFIX/include/rustscale.h for the C API."
    if [ "$OS" = darwin ]; then
        case "$PREFIX" in
            /usr/local|/usr) ;;
            *) echo "At runtime export DYLD_LIBRARY_PATH=$PREFIX/lib so the dylib is found." ;;
        esac
    elif [ "$OS" = linux ]; then
        case "$PREFIX" in
            /usr/local|/usr|/usr/lib) ;;
            *) echo "At runtime add $PREFIX/lib to the linker cache, e.g." \
                  "echo '$PREFIX/lib' | sudo tee /etc/ld.so.conf.d/rustscale.conf && sudo ldconfig" ;;
        esac
    fi
}

# --uninstall: remove exactly the files do_install would have placed.
do_uninstall() {
    choose_sudo
    echo "rustscale: uninstalling from $PREFIX"
    any=0
    for f in "$PREFIX/lib/librustscale.$DYEXT" "$PREFIX/lib/librustscale.a" \
             "$PREFIX/include/rustscale.h" "$PREFIX/bin/rustscale-tun"; do
        if [ -e "$f" ] || [ -L "$f" ]; then
            run_as_root rm -f "$f" && echo "  removed $f"
            any=1
        fi
    done
    if [ "$OS" = linux ]; then
        run_as_root ldconfig 2>/dev/null || true
    fi
    if [ "$any" = 0 ]; then
        echo "rustscale: nothing found to remove in $PREFIX"
    fi
}

main "$@"
