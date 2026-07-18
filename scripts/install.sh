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
#   VERSION   Pin to a specific release tag (e.g. "v0.1.1").
#             Default: latest release.
#   INSTALL_SERVICE
#             Install and start the system daemon when possible (default:
#             auto for /usr/local or /usr; set to 0 to disable).
#   GH_TOKEN / GITHUB_TOKEN
#             GitHub token used to download assets from a private repository.
#   RUSTSCALE_LIBC
#             Override Linux libc detection: "gnu" or "musl".
#
# Flags:
#   --uninstall       Remove installed files.
#   --version <tag>   Pin to a specific release tag.
#   --no-service      Do not install or start a system service.
#   --tailscale-compatible
#                     Install tailscale/tailscaled command aliases. Existing
#                     commands are never replaced; use only on an isolated
#                     replacement host. RustScale keeps its own state paths.
#   --help, -h        Show this help.
#
# Examples:
#   curl -fsSL https://rajsinghtech.github.io/rustscale/install.sh | sh
#   curl -fsSL https://rajsinghtech.github.io/rustscale/install.sh | PREFIX=$HOME/.local sh
#   sh scripts/install.sh --version v0.1.1
#
# POSIX sh, set -eu, all logic wrapped in main() at the bottom so a truncated
# download never executes half a script.

set -eu

PREFIX="${PREFIX:-/usr/local}"
VERSION="${VERSION:-}"
INSTALL_SERVICE="${INSTALL_SERVICE:-auto}"
RUSTSCALE_REPO="${RUSTSCALE_REPO:-rajsinghtech/rustscale}"
RUSTSCALE_RELEASE_BASE="${RUSTSCALE_RELEASE_BASE:-https://github.com/$RUSTSCALE_REPO/releases}"

# Kept empty until assigned; the trap guard keeps set -u happy.
WORKDIR=
trap '[ -n "$WORKDIR" ] && rm -rf "$WORKDIR"' EXIT

usage() {
    cat <<'EOF'
rustscale binary installer — downloads prebuilt binaries from GitHub Releases.

Environment variables:
  PREFIX    Install prefix (default: /usr/local).
  VERSION   Pin to a specific release tag (e.g. "v0.1.1").
  INSTALL_SERVICE
            Install and start the system daemon when possible (default: auto).
  GH_TOKEN / GITHUB_TOKEN
            GitHub token for private release assets.
  RUSTSCALE_LIBC
            Override Linux libc detection: "gnu" or "musl".

Flags:
  --uninstall       Remove installed files.
  --version <tag>   Pin to a specific release tag.
  --no-service      Do not install or start a system service.
  --tailscale-compatible
                    Install tailscale/tailscaled aliases without replacing
                    existing commands. Use only on an isolated replacement
                    host; RustScale keeps separate state and socket paths.
  --help, -h        Show this help.

Examples:
  curl -fsSL https://rajsinghtech.github.io/rustscale/install.sh | sh
  curl -fsSL https://rajsinghtech.github.io/rustscale/install.sh | PREFIX=$HOME/.local sh
  sh scripts/install.sh --version v0.1.1
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
    TAILSCALE_COMPATIBLE=0
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
            --no-service) INSTALL_SERVICE=0 ;;
            --tailscale-compatible) TAILSCALE_COMPATIBLE=1 ;;
            --help|-h) usage; exit 0 ;;
            *)
                echo "rustscale: unknown option '$1' (try --help)" >&2
                exit 1
                ;;
        esac
        shift
    done

    case "$VERSION" in
        ""|v*) ;;
        *) VERSION="v$VERSION" ;;
    esac

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
    LIBC=

    uname_s="${RUSTSCALE_UNAME_S:-$(uname -s)}"
    uname_m="${RUSTSCALE_UNAME_M:-$(uname -m)}"

    case "$uname_s" in
        Darwin) OS=darwin; DYEXT=dylib ;;
        Linux)  OS=linux;  DYEXT=so ;;
        *)
            echo "rustscale: unsupported OS '$uname_s' (only darwin/linux)" >&2
            exit 1
            ;;
    esac

    case "$uname_m" in
        x86_64|amd64)   ARCH=x86_64 ;;
        aarch64|arm64)  ARCH=aarch64 ;;
        *)
            echo "rustscale: unsupported architecture '$uname_m'" >&2
            exit 1
            ;;
    esac

    if [ "$OS" = linux ]; then
        if [ "${UNINSTALL:-0}" = 1 ]; then
            LIBC=uninstall
        else
            detect_linux_libc
        fi
    fi

    # Map to the release archive naming convention from .github/workflows/release.yml.
    case "$OS-$ARCH-${LIBC:-none}" in
        darwin-x86_64-none) ARCHIVE="rustscale-universal-apple-darwin.tar.gz" ;;
        darwin-aarch64-none) ARCHIVE="rustscale-universal-apple-darwin.tar.gz" ;;
        linux-x86_64-gnu) ARCHIVE="rustscale-x86_64-unknown-linux-gnu.tar.gz" ;;
        linux-x86_64-musl) ARCHIVE="rustscale-x86_64-unknown-linux-musl.tar.gz" ;;
        linux-aarch64-gnu) ARCHIVE="rustscale-aarch64-unknown-linux-gnu.tar.gz" ;;
        linux-aarch64-musl)
            echo "rustscale: no published release archive for linux-aarch64-musl" >&2
            exit 1
            ;;
        linux-x86_64-uninstall|linux-aarch64-uninstall) ;;
        *)
            echo "rustscale: no release archive for $OS-$ARCH-${LIBC:-unknown}" >&2
            exit 1
            ;;
    esac
}

# Detect the Linux C library without executing a downloaded binary. The
# override mirrors the existing uname test hooks and makes installer fixtures
# deterministic. Unknown libc implementations fail closed.
detect_linux_libc() {
    case "${RUSTSCALE_LIBC:-}" in
        gnu|musl) LIBC="$RUSTSCALE_LIBC"; return ;;
        "") ;;
        *)
            echo "rustscale: unsupported RUSTSCALE_LIBC '${RUSTSCALE_LIBC}' (expected gnu or musl)" >&2
            exit 1
            ;;
    esac

    if command -v getconf >/dev/null 2>&1 \
        && getconf GNU_LIBC_VERSION >/dev/null 2>&1; then
        LIBC=gnu
        return
    fi

    if command -v ldd >/dev/null 2>&1; then
        ldd_version=$(LC_ALL=C ldd --version 2>&1 || true)
        ldd_lower=$(printf '%s\n' "$ldd_version" | tr '[:upper:]' '[:lower:]')
        case "$ldd_lower" in
            *musl*) LIBC=musl; return ;;
            *glibc*|*"gnu libc"*|*"free software foundation"*) LIBC=gnu; return ;;
        esac
    fi

    for loader in /lib/ld-musl-*.so.1 /lib64/ld-musl-*.so.1 /usr/lib/ld-musl-*.so.1; do
        if [ -e "$loader" ]; then
            LIBC=musl
            return
        fi
    done
    for loader in /lib64/ld-linux-*.so.* /lib/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.*; do
        if [ -e "$loader" ]; then
            LIBC=gnu
            return
        fi
    done

    echo "rustscale: could not determine Linux libc (gnu or musl); set RUSTSCALE_LIBC explicitly" >&2
    exit 1
}

# Decide how to escalate for the install copy. The download itself never
# runs as root.
choose_sudo() {
    INSTALL_SUDO=
    probe="$PREFIX"
    while [ ! -e "$probe" ] && [ "$probe" != "/" ]; do
        probe=$(dirname "$probe")
    done
    if [ -w "$probe" ] 2>/dev/null; then
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

# Resolve immutable URLs for a pinned version, or GitHub's stable latest-release
# redirect when no version was requested. This avoids API rate limits and a
# hard-coded fallback that has to be changed before every release.
resolve_url() {
    token="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
    if [ -n "$token" ]; then
        if [ -n "$VERSION" ]; then
            RELEASE_API="https://api.github.com/repos/$RUSTSCALE_REPO/releases/tags/$VERSION"
            DISPLAY_VERSION="$VERSION"
        else
            RELEASE_API="https://api.github.com/repos/$RUSTSCALE_REPO/releases/latest"
            DISPLAY_VERSION="latest"
        fi
        fetch_private_release "$token"
        DOWNLOAD_URL=$(private_asset_url "$ARCHIVE")
        CHECKSUM_URL=$(private_asset_url SHA256SUMS)
        if [ -z "$DOWNLOAD_URL" ] || [ -z "$CHECKSUM_URL" ]; then
            echo "rustscale: release API response is missing $ARCHIVE or SHA256SUMS" >&2
            exit 1
        fi
        return
    fi

    if [ -n "$VERSION" ]; then
        RELEASE_ROOT="$RUSTSCALE_RELEASE_BASE/download/$VERSION"
        DISPLAY_VERSION="$VERSION"
    else
        RELEASE_ROOT="$RUSTSCALE_RELEASE_BASE/latest/download"
        DISPLAY_VERSION="latest"
    fi
    DOWNLOAD_URL="$RELEASE_ROOT/$ARCHIVE"
    CHECKSUM_URL="$RELEASE_ROOT/SHA256SUMS"
}

fetch_private_release() {
    token="$1"
    case "$HTTP_CLIENT" in
        curl)
            curl --proto '=https' --tlsv1.2 -fsSL --retry 3 \
                -H "Authorization: Bearer $token" \
                -H 'Accept: application/vnd.github+json' \
                -H 'X-GitHub-Api-Version: 2022-11-28' \
                -o "$WORKDIR/release.json" "$RELEASE_API"
            ;;
        wget)
            wget -q --header="Authorization: Bearer $token" \
                --header='Accept: application/vnd.github+json' \
                -O "$WORKDIR/release.json" "$RELEASE_API"
            ;;
    esac
}

# GitHub's JSON is pretty-printed with each asset's API URL preceding its name.
private_asset_url() {
    asset_name="$1"
    awk -v wanted="$asset_name" '
        /^[[:space:]]*"url":[[:space:]]*"/ {
            url = $0
            sub(/^[^:]*:[[:space:]]*"/, "", url)
            sub(/",?[[:space:]]*$/, "", url)
        }
        /^[[:space:]]*"name":[[:space:]]*"/ {
            name = $0
            sub(/^[^:]*:[[:space:]]*"/, "", name)
            sub(/",?[[:space:]]*$/, "", name)
            if (name == wanted) { print url; exit }
        }
    ' "$WORKDIR/release.json"
}

# Pick and invoke an HTTP client. RUSTSCALE_HTTP_CLIENT also makes the wget
# path independently testable on machines that provide both clients.
pick_http_client() {
    HTTP_CLIENT="${RUSTSCALE_HTTP_CLIENT:-}"
    if [ -z "$HTTP_CLIENT" ]; then
        if command -v curl >/dev/null 2>&1; then
            HTTP_CLIENT=curl
        elif command -v wget >/dev/null 2>&1; then
            HTTP_CLIENT=wget
        else
            echo "rustscale: needs either curl or wget to download." >&2
            exit 1
        fi
    fi
    case "$HTTP_CLIENT" in
        curl|wget) ;;
        *) echo "rustscale: unsupported HTTP client '$HTTP_CLIENT'" >&2; exit 1 ;;
    esac
    if ! command -v "$HTTP_CLIENT" >/dev/null 2>&1; then
        echo "rustscale: requested HTTP client '$HTTP_CLIENT' was not found." >&2
        exit 1
    fi
}

download_to() {
    url="$1"
    output="$2"
    token="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
    case "$url" in http://*|https://*) ;; *) token= ;; esac
    case "$HTTP_CLIENT" in
        curl)
            if [ -n "$token" ]; then
                curl --proto '=https,file' --tlsv1.2 -fsSL --retry 3 \
                    --retry-delay 1 -H "Authorization: Bearer $token" \
                    -H 'Accept: application/octet-stream' \
                    -o "$output" "$url"
            else
                curl --proto '=https,file' --tlsv1.2 -fsSL --retry 3 \
                    --retry-delay 1 -o "$output" "$url"
            fi
            ;;
        wget)
            if [ -n "$token" ]; then
                wget -q --header="Authorization: Bearer $token" \
                    --header='Accept: application/octet-stream' -O "$output" "$url"
            else
                wget -q -O "$output" "$url"
            fi
            ;;
    esac
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        echo "rustscale: needs sha256sum or shasum to verify the release." >&2
        exit 1
    fi
}

verify_download() {
    expected=$(awk -v name="$ARCHIVE" '
        $2 == name || $2 == "*" name { print $1; exit }
    ' "$WORKDIR/SHA256SUMS")
    if [ -z "$expected" ]; then
        echo "rustscale: SHA256SUMS has no entry for $ARCHIVE" >&2
        exit 1
    fi
    actual=$(sha256_file "$WORKDIR/$ARCHIVE")
    if [ "$actual" != "$expected" ]; then
        echo "rustscale: checksum mismatch for $ARCHIVE" >&2
        echo "  expected: $expected" >&2
        echo "  actual:   $actual" >&2
        exit 1
    fi
    echo "rustscale: checksum verified"
}

validate_archive() {
    listing="$WORKDIR/archive.list"
    tar tzf "$WORKDIR/$ARCHIVE" > "$listing"
    unsafe=$(awk '
        /^\// { print; exit }
        /(^|\/)\.\.($|\/)/ { print; exit }
    ' "$listing")
    if [ -n "$unsafe" ]; then
        echo "rustscale: unsafe path in release archive: $unsafe" >&2
        exit 1
    fi
}

download_and_install() {
    pick_http_client
    WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/rustscale-install.XXXXXX")
    resolve_url

    echo "rustscale: downloading $ARCHIVE from $DISPLAY_VERSION release"
    if ! download_to "$DOWNLOAD_URL" "$WORKDIR/$ARCHIVE" 2>/dev/null; then
        echo "rustscale: download failed: $DOWNLOAD_URL" >&2
        echo >&2
        echo "rustscale: verify that the release and $ARCHIVE asset exist, then retry." >&2
        echo "For a private repository, set GH_TOKEN to a token with Contents: read." >&2
        echo "Release page: https://github.com/$RUSTSCALE_REPO/releases" >&2
        exit 1
    fi
    if ! download_to "$CHECKSUM_URL" "$WORKDIR/SHA256SUMS" 2>/dev/null; then
        echo "rustscale: checksum download failed: $CHECKSUM_URL" >&2
        exit 1
    fi

    verify_download
    validate_archive
    echo "rustscale: extracting"
    tar xzf "$WORKDIR/$ARCHIVE" -C "$WORKDIR"

    for required in rustscale rustscaled; do
        if [ ! -f "$WORKDIR/$required" ]; then
            echo "rustscale: release archive is missing required file '$required'" >&2
            exit 1
        fi
    done

    validate_alias_targets
    install_files
    install_system_service
    post_install
}

# Compatibility mode is explicit and must never adopt or replace commands from
# an official Tailscale installation. Validate both destinations before the
# first installed file is mutated so a collision cannot leave a partial
# RustScale installation behind.
validate_alias_targets() {
    [ "$TAILSCALE_COMPATIBLE" = 1 ] || return 0
    for alias in tailscale tailscaled; do
        case "$alias" in
            tailscale) expected=rustscale ;;
            tailscaled) expected=rustscaled ;;
        esac
        alias_path="$PREFIX/bin/$alias"
        if [ ! -e "$alias_path" ] && [ ! -L "$alias_path" ]; then
            continue
        fi
        if [ -L "$alias_path" ] && [ "$(readlink "$alias_path")" = "$expected" ]; then
            continue
        fi
        echo "rustscale: refusing to replace existing compatibility command $alias_path" >&2
        echo "Remove or relocate the existing Tailscale installation, or install without --tailscale-compatible." >&2
        exit 1
    done
}

install_aliases() {
    [ "$TAILSCALE_COMPATIBLE" = 1 ] || return 0
    echo "rustscale: installing Tailscale-compatible command aliases"
    for alias in tailscale tailscaled; do
        case "$alias" in
            tailscale) expected=rustscale ;;
            tailscaled) expected=rustscaled ;;
        esac
        alias_path="$PREFIX/bin/$alias"
        # validate_alias_targets accepted an existing installer-owned link.
        # Leave it in place. For a new link, never use a force option: if an
        # official command appears after validation, ln fails rather than
        # replacing it.
        if [ -L "$alias_path" ] && [ "$(readlink "$alias_path")" = "$expected" ]; then
            continue
        fi
        run_as_root ln -s "$expected" "$alias_path"
    done
}

install_system_service() {
    SERVICE_INSTALLED=0
    case "$INSTALL_SERVICE" in
        0|false|False|FALSE|no|No|NO) return 0 ;;
        auto)
            case "$PREFIX" in /usr/local|/usr) ;; *) return 0 ;; esac
            ;;
        1|true|True|TRUE|yes|Yes|YES) ;;
        *) echo "rustscale: invalid INSTALL_SERVICE value '$INSTALL_SERVICE'" >&2; exit 1 ;;
    esac

    case "$PREFIX" in
        /usr/local|/usr) ;;
        *)
            echo "rustscale: system service installation requires PREFIX=/usr/local or PREFIX=/usr" >&2
            echo "Use --no-service for a portable/custom-prefix installation." >&2
            exit 1
            ;;
    esac

    if [ "$OS" = linux ] && command -v systemctl >/dev/null 2>&1 \
        && [ -f "$WORKDIR/rustscaled.service" ]; then
        run_as_root install -d -m 755 /etc/systemd/system /etc/default
        run_as_root install -m 644 "$WORKDIR/rustscaled.service" /etc/systemd/system/
        if [ -f "$WORKDIR/rustscaled.default" ]; then
            run_as_root install -m 644 "$WORKDIR/rustscaled.default" /etc/default/rustscaled
        fi
        run_as_root systemctl daemon-reload
        run_as_root systemctl enable --now rustscaled.service
        SERVICE_INSTALLED=1
        return
    fi

    if [ "$OS" = darwin ] && [ "$PREFIX" = /usr/local ]; then
        run_as_root "$PREFIX/bin/rustscaled" install-system-daemon
        SERVICE_INSTALLED=1
    fi
}

# Install the extracted files to $PREFIX.
install_files() {
    echo "rustscale: installing to $PREFIX"
    run_as_root install -d -m 755 "$PREFIX/bin"

    for bin in rustscale rustscaled; do
        run_as_root install -m 755 "$WORKDIR/$bin" "$PREFIX/bin/"
    done
    write_install_receipt
    install_aliases

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

    if [ "$OS" = linux ] && command -v ldconfig >/dev/null 2>&1; then
        case "$PREFIX" in /usr/local|/usr) run_as_root ldconfig 2>/dev/null || true ;; esac
    fi
}

# Record ownership of exactly the binaries installed by this script. The
# updater requires this receipt and verifies both hashes before replacing
# anything, so merely colocated/package-managed binaries are never adopted.
write_install_receipt() {
    cli_sha=$(sha256_file "$WORKDIR/rustscale")
    daemon_sha=$(sha256_file "$WORKDIR/rustscaled")
    receipt="$WORKDIR/rustscale-install-receipt-v1"
    {
        echo "rustscale-install-receipt-v1"
        echo "installer=scripts/install.sh"
        echo "rustscale_sha256=$cli_sha"
        echo "rustscaled_sha256=$daemon_sha"
    } > "$receipt"
    run_as_root install -m 644 "$receipt" "$PREFIX/bin/.rustscale-install-receipt-v1"
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
    if [ "${SERVICE_INSTALLED:-0}" = 1 ]; then
        echo "  sudo rustscale set --operator \"\$USER\"  # one-time ordinary-user access"
    else
        echo "  sudo rustscaled run          # start the daemon"
        echo "  sudo rustscale set --operator \"\$USER\"  # one-time ordinary-user access"
    fi
    echo "  rustscale up                 # connect to a tailnet"
    echo "  rustscale status             # check state"
    if [ "${SERVICE_INSTALLED:-0}" = 1 ]; then
        echo
        echo "The rustscaled system service is installed and running; do not start a second daemon."
    fi
    case "$PREFIX" in
        /usr/local|/usr) ;;
        *) echo; echo "If $PREFIX/bin is not on your PATH, add it:" \
              "export PATH=$PREFIX/bin:\$PATH" ;;
    esac
    if [ "$TAILSCALE_COMPATIBLE" = 1 ]; then
        echo
        echo "Tailscale-compatible aliases installed: tailscale, tailscaled"
        echo "RustScale state remains separate: /var/lib/rustscale and /var/run/rustscaled.sock"
    fi
}

do_uninstall() {
    echo "rustscale: uninstalling from $PREFIX"
    any=0
    case "$PREFIX" in
        /usr/local|/usr)
            if [ "$OS" = linux ] && [ -f /etc/systemd/system/rustscaled.service ]; then
                run_as_root systemctl disable --now rustscaled.service 2>/dev/null || true
                run_as_root rm -f /etc/systemd/system/rustscaled.service /etc/default/rustscaled
                run_as_root systemctl daemon-reload 2>/dev/null || true
            elif [ "$OS" = darwin ] && [ -x "$PREFIX/bin/rustscaled" ]; then
                run_as_root "$PREFIX/bin/rustscaled" uninstall-system-daemon 2>/dev/null || true
            fi
            ;;
    esac
    for f in "$PREFIX/bin/rustscale" "$PREFIX/bin/rustscaled" \
             "$PREFIX/bin/.rustscale-install-receipt-v1" \
             "$PREFIX/lib/librustscale.$DYEXT" "$PREFIX/lib/librustscale.a" \
             "$PREFIX/include/rustscale.h"; do
        if [ -e "$f" ] || [ -L "$f" ]; then
            run_as_root rm -f "$f" && echo "  removed $f"
            any=1
        fi
    done
    for alias in tailscale tailscaled; do
        alias_path="$PREFIX/bin/$alias"
        case "$alias" in
            tailscale) expected=rustscale ;;
            tailscaled) expected=rustscaled ;;
        esac
        if [ -L "$alias_path" ] && [ "$(readlink "$alias_path")" = "$expected" ]; then
            run_as_root rm -f "$alias_path" && echo "  removed $alias_path"
            any=1
        fi
    done
    if [ "$OS" = linux ] && command -v ldconfig >/dev/null 2>&1; then
        case "$PREFIX" in /usr/local|/usr) run_as_root ldconfig 2>/dev/null || true ;; esac
    fi
    if [ "$any" = 0 ]; then
        echo "rustscale: nothing found to remove in $PREFIX"
    fi
}

main "$@"
