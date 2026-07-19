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
grep -q 'runs-on: ubuntu-22.04' .github/workflows/release.yml
grep -q 'name: Linux glibc compatibility' .github/workflows/release.yml
grep -q 'debian:12-slim' .github/workflows/release.yml
grep -Fq 'pattern: rustscale-*' .github/workflows/release.yml
grep -q 'SHA256SUMS' scripts/install.sh
grep -q 'SHA256SUMS' scripts/install.ps1
grep -q 'packaging/systemd/rustscaled.service' .github/workflows/release.yml
grep -q 'tools/packaging/test-first-run.sh' .github/workflows/ci.yml
grep -q 'tools/packaging/test-linux-replacement.sh' .github/workflows/ci.yml
grep -q 'tools/interop-tun\*\.sh' .github/workflows/ci.yml
test -x tools/packaging/test-linux-replacement.sh
test -s docs/release-first-run.md
grep -q 'Protected real-control smoke gate' docs/release-first-run.md
grep -q 'Installed Linux replacement journey' docs/release-first-run.md
grep -q 'RUSTSCALE_REQUIRE_LINUX_REPLACEMENT' .github/workflows/ci.yml
grep -q 'RUSTSCALE_LINUX_REPLACEMENT_TEARDOWN_TIMEOUT' .github/workflows/ci.yml
grep -q 'python3 tools/agent/run-with-deadline.py 1200' .github/workflows/ci.yml
grep -q 'Replay replacement failure diagnostics' .github/workflows/ci.yml
grep -q 'systemd-run --quiet --wait --pipe --collect' tools/packaging/test-linux-replacement.sh
grep -q 'KillMode=control-group' tools/packaging/test-linux-replacement.sh
grep -q 'RuntimeMaxSec=' tools/packaging/test-linux-replacement.sh
# The protected replacement job carries the credential-free real-TUN contract;
# no new workflow context may replace or hide that required journey.
grep -q 'name: Installed Linux replacement journey' .github/workflows/ci.yml
grep -q 'needs: \[check, cross, msrv, testcontrol, linux-replacement, ignore-guard\]' .github/workflows/ci.yml
grep -Fq 'systemctl is-system-running --wait' tools/packaging/test-linux-replacement.sh
if grep -Fq 'systemd_attempt' tools/packaging/test-linux-replacement.sh; then
    echo "systemd readiness must use native --wait, not a polling loop" >&2
    exit 1
fi
grep -q 'timeout-minutes: 50' .github/workflows/ci.yml
grep -q 'TESTCONTROL_GO_CLIENT_DIR' tools/testcontrol/build.sh

# The privileged TUN job must establish local kernel prerequisites before it
# mints any external credential, then run one exact serial fail-closed test.
tun_job=$(awk '
    /^  interop-tun:/ { job = 1 }
    job && /^  [A-Za-z0-9_-]+:/ && $1 != "interop-tun:" { exit }
    job { print }
' .github/workflows/e2e.yml)
preflight_line=$(printf '%s\n' "$tun_job" | grep -n -m1 'tools/interop-tun-preflight.sh' | cut -d: -f1)
token_line=$(printf '%s\n' "$tun_job" | grep -n -m1 'Mint Tailscale org token' | cut -d: -f1)
test -n "$preflight_line"
test -n "$token_line"
test "$preflight_line" -lt "$token_line"
grep -Fq -- 'cargo test -p rustscale-tsnet --lib --no-run' tools/interop-tun.sh
grep -Fq -- "target.get('name') == 'rustscale_tsnet'" tools/interop-tun.sh
grep -Fq -- "'lib' in target.get('kind', [])" tools/interop-tun.sh
grep -Fq -- "selected_count=\$(\"\$TEST_BIN\" --ignored --list" tools/interop-tun.sh
grep -Fq -- "grep -Fxc 'tests::interop_tun_rust_dials_go: test'" tools/interop-tun.sh
grep -Fq -- "if [[ \"\$selected_count\" != 1 ]]; then" tools/interop-tun.sh
grep -Fq -- "exact TUN selector matched \$selected_count tests (expected 1)" tools/interop-tun.sh
grep -Fq -- 'sudo --preserve-env=TS_E2E_AUTHKEY,TS_INTEROP_GO_IP,TS_INTEROP_GO_NAME,TS_INTEROP_GO_ECHO_PORT,TS_INTEROP_SOCKS' tools/interop-tun.sh
grep -Fq -- 'set -eu' tools/interop-tun.sh
grep -Fq -- 'sudo did not preserve the required interop environment' tools/interop-tun.sh
grep -Fq -- 'export RUSTSCALE_REQUIRE_TUN_INTEROP=1' tools/interop-tun.sh
if grep -R -Fq -- 'RUSTSCALE_REQUIRE_TUN_DNS_FAILURE' tools/interop-tun.sh crates/tsnet/src/tests.rs; then
    echo "DNS readiness must not be coupled to secret-backed interop" >&2
    exit 1
fi
# The installed replacement journey is the required credential-free TUN/DNS
# contract. It must build one libtest runner, count one existing ignored
# selector, enter dedicated mode under root, and never accept a zero match.
grep -Fq -- 'record_phase required-tun-dns-readiness' tools/packaging/test-linux-replacement.sh
grep -Fq -- 'cargo test -p rustscale-tsnet --lib --no-run --message-format=json' tools/packaging/test-linux-replacement.sh
grep -Fq -- 'target.get("name") == "rustscale_tsnet"' tools/packaging/test-linux-replacement.sh
grep -Fq -- 'expected one rustscale_tsnet libtest executable' tools/packaging/test-linux-replacement.sh
grep -Fq -- "grep -Fxc 'tests::interop_tun_rust_dials_go: test'" tools/packaging/test-linux-replacement.sh
grep -Fq -- "required TUN DNS exact selector matched \$selected_count tests (expected 1)" tools/packaging/test-linux-replacement.sh
grep -Fq -- 'RUSTSCALE_REQUIRED_TUN_DNS_FAILURE=1' tools/packaging/test-linux-replacement.sh
grep -Fq -- '--ignored --exact tests::interop_tun_rust_dials_go' tools/packaging/test-linux-replacement.sh
grep -Fq -- '--nocapture --test-threads=1' tools/packaging/test-linux-replacement.sh
grep -Fq -- "test \"\$(id -u)\" -eq 0" tools/packaging/test-linux-replacement.sh
grep -Fq -- 'test -c /dev/net/tun' tools/packaging/test-linux-replacement.sh
grep -Fq -- 'command -v ip' tools/packaging/test-linux-replacement.sh
grep -Fq -- 'RUSTSCALE_REQUIRED_TUN_DNS_TUN_NAME' crates/tsnet/src/tests.rs
grep -Fq -- 'if required_tun_dns_failure_mode()' crates/tsnet/src/tests.rs
grep -Fq -- 'run_required_tun_dns_failure_scenario().await' crates/tsnet/src/tests.rs
# Match exact source text retaining the escaped child argv.
# shellcheck disable=SC2016
grep -Fq -- 'exec \"\$@\"' tools/interop-tun.sh
grep -Fq -- '--ignored --exact tests::interop_tun_rust_dials_go' tools/interop-tun.sh
grep -Fq -- '--nocapture --test-threads=1' tools/interop-tun.sh
grep -Fq 'std::env::var("RUSTSCALE_REQUIRE_TUN_INTEROP")' crates/tsnet/src/tests.rs
grep -Fq 'required TUN interop environment is missing or invalid' crates/tsnet/src/tests.rs
grep -Fq 'required TUN interop test is not running as root' crates/tsnet/src/tests.rs
grep -Fq 'up_tun failed after privileged TUN prerequisites were established' crates/tsnet/src/tests.rs
if grep -Fq 'up_tun_or_skip' crates/tsnet/src/tests.rs; then
    echo "privileged TUN startup errors can still be converted into skips" >&2
    exit 1
fi
grep -Fq "rustscaled run --state /var/lib/rustscale --socket /var/run/rustscaled.sock --tun \$FLAGS" packaging/systemd/rustscaled.service
grep -Fxq 'Restart=always' packaging/systemd/rustscaled.service
if grep -Eq -- '--(state|statedir|socket)=' packaging/systemd/rustscaled.service; then
    echo "systemd unit uses unsupported --flag=value daemon syntax" >&2
    exit 1
fi
grep -Fq 'COPY vendor/boringtun/ ./vendor/boringtun/' Dockerfile
grep -Fq 'ARG RUSTSCALE_LTO=thin' Dockerfile
grep -Fq "CARGO_PROFILE_RELEASE_LTO=\$RUSTSCALE_LTO cargo build" Dockerfile
docker_job=$(awk '
    /^  docker:/ { docker = 1; next }
    docker && /^  [A-Za-z0-9_-]+:/ { exit }
    docker { print }
' .github/workflows/release.yml)
printf '%s\n' "$docker_job" | grep -Fq 'needs: [metadata, linux, linux-compat]'
printf '%s\n' "$docker_job" | grep -Fq 'timeout-minutes: 20'
printf '%s\n' "$docker_job" | grep -Fq 'pattern: rustscale-*-unknown-linux-gnu'
printf '%s\n' "$docker_job" | grep -Fq 'file: ./Dockerfile.release'
grep -q 'ln -s rustscale /usr/local/bin/tailscale' Dockerfile
grep -q 'org.opencontainers.image.version' Dockerfile
test "$(grep -c '^FROM .*@sha256:[0-9a-f]\{64\}' Dockerfile)" -eq 2
grep -Fq "COPY container-binaries/\${TARGETARCH}/rustscale " Dockerfile.release
grep -Fq "COPY container-binaries/\${TARGETARCH}/rustscaled " Dockerfile.release
grep -q 'org.opencontainers.image.version' Dockerfile.release
test "$(grep -c '^FROM .*@sha256:[0-9a-f]\{64\}' Dockerfile.release)" -eq 1
grep -q "v$version" site/index.html
python3 tools/packaging/check-pages-performance.py

echo "release contract: v$version ok"
