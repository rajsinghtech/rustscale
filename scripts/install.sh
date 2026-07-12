#!/bin/sh
# rustscale binary installer — downloads prebuilt binaries from GitHub Releases
# and installs them. One-liner on macOS and Linux:
#
#   curl -fsSL https://rajsinghtech.github.io/rustscale/install.sh | sh
#
# Detects OS (macOS/Linux) and architecture (x86_64/aarch64), downloads the
# matching release archive, and installs:
#   rustscale        CLI          -> $PREFIX/bin
#   rustscaled       daemon       -> $PREFIX/bin
#   librustscale.*   shared lib   -> $PREFIX/lib   (when present in archive)
#   librustscale.a   static lib   -> $PREFIX/lib   (when present in archive)
#   rustscale.h      C header     -> $PREFIX/include (when present in archive)
#
# Environment variables:
#   PREFIX    Install prefix (default: /usr/local).
#   VERSION   Pin to a specific release tag (e.g. "v0.1.0").
#             Default: latest release.
#
# Flags:
#   --uninstall       Remove installed files.
#   --version <tag>   Pin to a specific release tag.
#   --help, -h        Show this help.
#
# Examples:
#   curl -fsSL https://rajsinghtech.github.io/rustscale/install.sh | sh
#   curl -fsSL https://rajsinghtech.github.io/rustscale/install.sh | PREFIX=$HOME/.local sh
#   sh scripts/install.sh --version v0.1.0
#
# POSIX sh, set -eu, all logic wrapped in main() at the bottom so a truncated
# download never executes half a script.

set -eu

PREFIX="${PREFIX:-/usr/local}"
VERSION="${VERSION:-}"
REPO="rajsinghtech/rustscale"
# Fallback version when the GitHub API is unreachable (e.g. private repos,
# rate limits, offline). Bump this with each release.
DEFAULT_VERSION="v0.1.0"

# Kept empty until assigned; the trap guard keeps set -u happy.
WORKDIR=
trap '[ -n "$WORKDIR" ] && rm -rf "$WORKDIR"' EXIT

usage() {
    cat <<'EOF'
rustscale binary installer — downloads prebuilt binaries from GitHub Releases.

Environment variables:
  PREFIX    Install prefix (default: /usr/local).
  VERSION   Pin to a specific release tag (e.g. "v0.1.0").

Flags:
  --uninstall       Remove installed files.
  --version <tag>   Pin to a specific release tag.
  --help, -h        Show this help.

Examples:
  curl -fsSL https://rajsinghtech.github.io/rustscale/install.sh | sh
  curl -fsSL https://rajsinghtech.github.io/rustscale/install.sh | PREFIX=$HOME/.local sh
  sh scripts/install.sh --version v0.1.0
EOF
}

# Run a command, escalating through sudo/doas only when INSTALL_SUDO is set.
run_as_root() {
    if [ -n "$INSTALL_SUDO" ]; then
        $INSTALL_SUDO "$@"
    else
        "$@"
    fi
}

main() {
    UNINSTALL=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --uninstall) UNINSTALL=1 ;;
            --version)
                shift
                if [ $# -eq 0 ]; then
                    echo "rustscale: --version requires a value" >&2
                    exit 1
                fi
                VERSION="$1"
                ;;
            --help|-h) usage; exit 0 ;;
            *)
                echo "rustscale: unknown option '$1' (try --help)" >&2
                exit 1
                ;;
        esac
        shift
    done

    detect_platform
    choose_sudo

    if [ "$UNINSTALL" = 1 ]; then
        do_uninstall
        return
    fi

    download_and_install
}

# Detect OS, architecture, and pick the archive name + shared-lib extension.
detect_platform() {
    OS=
    ARCH=
    ARCHIVE=
    DYEXT=

    case "$(uname -s)" in
        Darwin) OS=darwin; DYEXT=dylib ;;
        Linux)  OS=linux;  DYEXT=so ;;
        *)
            echo "rustscale: unsupported OS '$(uname -s)' (only darwin/linux)" >&2
            exit 1
            ;;
    esac

    case "$(uname -m)" in
        x86_64|amd64)   ARCH=x86_64 ;;
        aarch64|arm64)  ARCH=aarch64 ;;
        *)
            echo "rustscale: unsupported architecture '$(uname -m)'" >&2
            exit 1
            ;;
    esac

    # Map to the release archive naming convention from .github/workflows/release.yml.
    case "$OS-$ARCH" in
        darwin-x86_64)  ARCHIVE="rustscale-universal-apple-darwin.tar.gz" ;;
        darwin-aarch64) ARCHIVE="rustscale-universal-apple-darwin.tar.gz" ;;
        linux-x86_64)   ARCHIVE="rustscale-x86_64-unknown-linux-gnu.tar.gz" ;;
        linux-aarch64)  ARCHIVE="rustscale-aarch64-unknown-linux-gnu.tar.gz" ;;
        *)
            echo "rustscale: no release archive for $OS-$ARCH" >&2
            exit 1
            ;;
    esac
}

# Decide how to escalate for the install copy. The download itself never
# runs as root.
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

# Resolve the download URL. Tries, in order:
#   1. Explicit --version / VERSION env var
#   2. GitHub releases/latest redirect (works for public repos, no API needed)
#   3. GitHub API (works for public repos, returns JSON)
#   4. DEFAULT_VERSION fallback (works when offline or repo is private)
resolve_url() {
    if [ -n "$VERSION" ]; then
        DOWNLOAD_URL="https://github.com/$REPO/releases/download/$VERSION/$ARCHIVE"
        return
    fi

    # Approach 2: follow the releases/latest redirect and extract the tag
    # from the final URL (302 → /releases/tag/v0.1.0).
    TAG=$(curl -fsSI -o /dev/null -w '%{url_effective}' \
        "https://github.com/$REPO/releases/latest" 2>/dev/null \
        | grep -oE 'tag/[^"]+' | head -1 | sed 's|tag/||')
    if [ -n "$TAG" ]; then
        VERSION="$TAG"
        DOWNLOAD_URL="https://github.com/$REPO/releases/download/$TAG/$ARCHIVE"
        return
    fi

    # Approach 3: GitHub API.
    API_URL="https://api.github.com/repos/$REPO/releases/latest"
    TAG=$($CURL "$API_URL" 2>/dev/null | grep -m1 '"tag_name"' \
        | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')
    if [ -n "$TAG" ] && [ "$TAG" != "null" ]; then
        VERSION="$TAG"
        DOWNLOAD_URL="https://github.com/$REPO/releases/download/$TAG/$ARCHIVE"
        return
    fi

    # Approach 4: fallback to the hardcoded default.
    VERSION="$DEFAULT_VERSION"
    DOWNLOAD_URL="https://github.com/$REPO/releases/download/$VERSION/$ARCHIVE"
}

# Pick a HTTP client.
pick_curl() {
    CURL=
    if command -v curl >/dev/null 2>&1; then
        CURL="curl -fsSL"
    elif command -v wget >/dev/null 2>&1; then
        CURL="wget -q -O-"
    else
        echo "rustscale: needs either curl or wget to download." >&2
        exit 1
    fi
}

download_and_install() {
    pick_curl
    resolve_url

    echo "rustscale: downloading $ARCHIVE from release $VERSION"
    WORKDIR=$(mktemp -d -t rustscale-install)
    if ! $CURL -o "$WORKDIR/$ARCHIVE" "$DOWNLOAD_URL" 2>/dev/null; then
        echo "rustscale: download failed: $DOWNLOAD_URL" >&2
        echo >&2
        echo "rustscale: this can happen if:" >&2
        echo "  - the repository is private (release assets require auth)" >&2
        echo "  - the version '$VERSION' doesn't have an asset named '$ARCHIVE'" >&2
        echo "  - there's a network issue" >&2
        echo >&2
        echo "If the repo is private, download the archive from:" >&2
        echo "  https://github.com/$REPO/releases" >&2
        echo "and install manually, or build from source:" >&2
        echo "  git clone https://github.com/$REPO && sh rustscale/scripts/install-from-source.sh" >&2
        exit 1
    fi

    echo "rustscale: extracting"
    tar xzf "$WORKDIR/$ARCHIVE" -C "$WORKDIR"

    # The archive contains rustscale, rustscaled, and optionally libs + header
    # at the root level (see the Bundle step in release.yml).
    install_files
    post_install
}

# Install the extracted files to $PREFIX.
install_files() {
    echo "rustscale: installing to $PREFIX"
    run_as_root install -d -m 755 "$PREFIX/bin"

    for bin in rustscale rustscaled; do
        if [ -f "$WORKDIR/$bin" ]; then
            run_as_root install -m 755 "$WORKDIR/$bin" "$PREFIX/bin/"
        fi
    done

    # Libraries and header are optional — present in macOS/Linux archives,
    # absent in Windows (Windows uses a separate .ps1 installer).
    if [ -f "$WORKDIR/librustscale.$DYEXT" ]; then
        run_as_root install -d -m 755 "$PREFIX/lib"
        run_as_root install -m 755 "$WORKDIR/librustscale.$DYEXT" "$PREFIX/lib/"
    fi
    if [ -f "$WORKDIR/librustscale.a" ]; then
        run_as_root install -d -m 755 "$PREFIX/lib"
        run_as_root install -m 644 "$WORKDIR/librustscale.a" "$PREFIX/lib/"
    fi
    if [ -f "$WORKDIR/rustscale.h" ]; then
        run_as_root install -d -m 755 "$PREFIX/include"
        run_as_root install -m 644 "$WORKDIR/rustscale.h" "$PREFIX/include/"
    fi

    if [ "$OS" = linux ]; then
        run_as_root ldconfig 2>/dev/null || true
    fi
}

post_install() {
    echo
    echo "rustscale: installed:"
    [ -f "$WORKDIR/rustscale" ]  && echo "  $PREFIX/bin/rustscale"
    [ -f "$WORKDIR/rustscaled" ] && echo "  $PREFIX/bin/rustscaled"
    [ -f "$WORKDIR/librustscale.$DYEXT" ] && echo "  $PREFIX/lib/librustscale.$DYEXT"
    [ -f "$WORKDIR/librustscale.a" ]      && echo "  $PREFIX/lib/librustscale.a"
    [ -f "$WORKDIR/rustscale.h" ]         && echo "  $PREFIX/include/rustscale.h"
    echo
    echo "Get started:"
    echo "  sudo rustscaled run          # start the daemon"
    echo "  rustscale up                 # connect to a tailnet"
    echo "  rustscale status             # check state"
    if [ "$OS" = darwin ]; then
        case "$PREFIX" in
            /usr/local|/usr) ;;
            *) echo; echo "If $PREFIX/bin is not on your PATH, add it:" \
                  "export PATH=$PREFIX/bin:\$PATH" ;;
        esac
    fi
}

do_uninstall() {
    echo "rustscale: uninstalling from $PREFIX"
    any=0
    for f in "$PREFIX/bin/rustscale" "$PREFIX/bin/rustscaled" \
             "$PREFIX/lib/librustscale.$DYEXT" "$PREFIX/lib/librustscale.a" \
             "$PREFIX/include/rustscale.h"; do
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
