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
grep -q 'tools/packaging/assemble-linux-release.sh' .github/workflows/release.yml
grep -q 'packaging/systemd/rustscaled.service' tools/packaging/assemble-linux-release.sh
grep -q 'tools/packaging/test-first-run.sh' .github/workflows/ci.yml
grep -q 'tools/packaging/test-linux-replacement.sh' .github/workflows/ci.yml
grep -q 'linux-release-candidate' .github/workflows/ci.yml
grep -q 'Assemble exact Linux release candidate' .github/workflows/ci.yml
grep -q 'actions/download-artifact' .github/workflows/ci.yml
grep -q 'RUSTSCALE_RELEASE_DIR' .github/workflows/ci.yml
grep -q 'tools/interop-tun\*\.sh' .github/workflows/ci.yml
test -x tools/packaging/assemble-linux-release.sh
test -x tools/packaging/test-linux-replacement.sh
test -x tools/packaging/probe-systemd-supervisor.sh
test -x tools/packaging/test-systemd-supervisor-probe.sh
tools/packaging/test-systemd-supervisor-probe.sh
test -s docs/release-first-run.md
grep -q 'Protected real-control smoke gate' docs/release-first-run.md
grep -q 'Installed Linux replacement journey' docs/release-first-run.md
grep -q 'RUSTSCALE_REQUIRE_LINUX_REPLACEMENT' .github/workflows/ci.yml
grep -q 'RUSTSCALE_LINUX_REPLACEMENT_TEARDOWN_TIMEOUT' .github/workflows/ci.yml
grep -q 'exact production candidate' .github/workflows/ci.yml
grep -q 'Replay replacement failure diagnostics' .github/workflows/ci.yml
grep -q 'systemd-run --quiet --wait --pipe --collect' tools/packaging/test-linux-replacement.sh
grep -q 'exact production archive and SHA256SUMS are required' tools/packaging/test-linux-replacement.sh
grep -q 'assert_cli_contract' tools/packaging/test-linux-replacement.sh
grep -q 'KillMode=control-group' tools/packaging/test-linux-replacement.sh
grep -q 'RuntimeMaxSec=' tools/packaging/test-linux-replacement.sh
# The protected replacement job carries the credential-free real-TUN contract;
# no new workflow context may replace or hide that required journey.
grep -q 'name: Installed Linux replacement journey' .github/workflows/ci.yml
grep -Fq 'needs: [check, cross, msrv, testcontrol, linux-release-candidate, linux-replacement, ignore-guard]' .github/workflows/ci.yml
grep -Fq 'probe-systemd-supervisor.sh' tools/packaging/test-linux-replacement.sh
grep -Fq 'systemd-run --quiet --wait --collect' tools/packaging/probe-systemd-supervisor.sh
if grep -Fq 'systemctl is-system-running --wait' tools/packaging/test-linux-replacement.sh; then
    echo "manager-wide systemd state must not block an operational transient-service probe" >&2
    exit 1
fi
grep -q 'timeout-minutes: 50' .github/workflows/ci.yml
grep -q 'TESTCONTROL_GO_CLIENT_DIR' tools/testcontrol/build.sh

# TSan changes crate ABI, so std and every dependency must be rebuilt together
# for one explicit target in an isolated sanitizer target directory.
grep -Fq 'components: rust-src' .github/workflows/sanitizer.yml
grep -Fq 'targets: x86_64-unknown-linux-gnu' .github/workflows/sanitizer.yml
# shellcheck disable=SC2016 # Literal GitHub matrix expression contract.
grep -Fq 'CARGO_TARGET_DIR: target/tsan/${{ matrix.crate }}' .github/workflows/sanitizer.yml
grep -Fq 'cargo +nightly test -Zbuild-std' .github/workflows/sanitizer.yml
grep -Fq -- '--target x86_64-unknown-linux-gnu' .github/workflows/sanitizer.yml
grep -Fq -- '--locked --lib --tests' .github/workflows/sanitizer.yml
grep -Fq -- '-- --test-threads=1' .github/workflows/sanitizer.yml
grep -Fq 'TSAN_OPTIONS: halt_on_error=1' .github/workflows/sanitizer.yml
grep -Fq 'set -euo pipefail' .github/workflows/sanitizer.yml
grep -Fq 'TSan executed zero tests' .github/workflows/sanitizer.yml
if grep -Fq 'continue-on-error' .github/workflows/sanitizer.yml; then
    echo "TSan workflow must fail when a sanitizer job fails" >&2
    exit 1
fi
if grep -Fq -- '-Cunsafe-allow-abi-mismatch=sanitizer' .github/workflows/sanitizer.yml; then
    echo "TSan workflow must rebuild std, not permit sanitizer ABI mismatch" >&2
    exit 1
fi

# The privileged TUN job must establish local kernel prerequisites before it
# mints any external credential, then run one exact serial fail-closed test.
tun_job=$(awk '
    /^  interop-tun:/ { job = 1 }
    job && /^  [A-Za-z0-9_-]+:/ && $1 != "interop-tun:" { exit }
    job { print }
' .github/workflows/e2e.yml)
preflight_line=$(printf '%s\n' "$tun_job" | grep -n -m1 'tools/interop-tun-preflight.sh' | cut -d: -f1)
build_line=$(printf '%s\n' "$tun_job" | grep -n -m1 'Build TUN interop binaries (credential-free)' | cut -d: -f1)
token_line=$(printf '%s\n' "$tun_job" | grep -n -m1 'Mint Tailscale org token' | cut -d: -f1)
cleanup_line=$(printf '%s\n' "$tun_job" | grep -n -m1 'Clean up recorded TUN interop tailnet' | cut -d: -f1)
test -n "$preflight_line"
test -n "$build_line"
test -n "$token_line"
test -n "$cleanup_line"
test "$preflight_line" -lt "$token_line"
test "$preflight_line" -lt "$build_line"
test "$build_line" -lt "$token_line"
test "$token_line" -lt "$cleanup_line"
printf '%s\n' "$tun_job" | grep -Fq 'timeout-minutes: 50'
printf '%s\n' "$tun_job" | grep -Fq 'tools/agent/run-with-deadline.py 1800'
printf '%s\n' "$tun_job" | grep -Fq 'tools/agent/run-with-deadline.py 900 -- tools/interop-tun.sh'
printf '%s\n' "$tun_job" | grep -Fq 'RUSTSCALE_DEADLINE_GRACE_SECONDS: "120"'
printf '%s\n' "$tun_job" | grep -Fq 'if: always()'
printf '%s\n' "$tun_job" | grep -Fq 'tools/agent/run-with-deadline.py 120 -- bash -c'
printf '%s\n' "$tun_job" | grep -Fq '_bench_cleanup_leftover'
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
# The producer and consumer form one exact, build-free artifact journey.
# The candidate must use the release assembler, retain full-SHA identity, and
# send the same named archive/checksum tree to the protected consumer.
grep -Fq 'Attest producer checkout' .github/workflows/ci.yml
# shellcheck disable=SC2016 # Literal GitHub expression contract.
grep -Fq 'RUSTSCALE_VERSION_LONG="${version}-g${candidate_sha:0:7}"' .github/workflows/ci.yml
grep -Fq 'tools/packaging/assemble-linux-release.sh' .github/workflows/ci.yml
# shellcheck disable=SC2016 # Literal GitHub expression contract.
grep -Fq 'linux-release-candidate-${{ steps.candidate.outputs.sha }}' .github/workflows/ci.yml
grep -Fq 'RUSTSCALE_BUILD_SHA' tools/packaging/assemble-linux-release.sh
grep -Fq 'SHA256SUMS' tools/packaging/assemble-linux-release.sh
grep -Fq 'Attest consumer checkout' .github/workflows/ci.yml
grep -Fq 'BUILD_FREE_CONSUMER' .github/workflows/ci.yml
grep -Fq 'for tool in cargo rustc rustup' .github/workflows/ci.yml
grep -Fq 'exact production archive and SHA256SUMS are required' tools/packaging/test-linux-replacement.sh
grep -Fq 'archive build identity' tools/packaging/test-linux-replacement.sh
consumer_job=$(awk '
    /^  linux-replacement:/ { job = 1 }
    job && /^  [A-Za-z0-9_-]+:/ && $1 != "linux-replacement:" { exit }
    job { print }
' .github/workflows/ci.yml)
printf '%s\n' "$consumer_job" | grep -Fq 'needs: [linux-release-candidate]'
printf '%s\n' "$consumer_job" | grep -Fq 'actions/download-artifact'
printf '%s\n' "$consumer_job" | grep -Fq 'RUSTSCALE_RELEASE_SHA'
if printf '%s\n' "$consumer_job" | grep -Eq 'rust-toolchain|rust-cache|^[[:space:]]*(cargo|rustc|rustup)[[:space:]]'; then
    echo "artifact consumer configures or invokes a Rust build tool" >&2
    exit 1
fi
if grep -Eqi '\b(cargo|rustc|rustup)\b' tools/packaging/test-linux-replacement.sh; then
    echo "artifact consumer journey invokes a Rust build tool" >&2
    exit 1
fi

# Match exact source text retaining the escaped child argv.
# shellcheck disable=SC2016
grep -Fq -- 'exec timeout --foreground --signal=TERM --kill-after=15s 600s \"\$@\"' tools/interop-tun.sh
grep -Fq -- 'source tools/interop-tun-cleanup.sh' tools/interop-tun.sh
# shellcheck disable=SC2016
grep -Fq -- 'interop_tun_stop_child "$GO_PID" "Go tailscaled" 10' tools/interop-tun.sh
# shellcheck disable=SC2016
grep -Fq -- 'interop_tun_stop_child "$ECHO_BACKEND_PID" "echo backend" 5' tools/interop-tun.sh
grep -Fq -- 'interop_tun_cleanup_tailnet 45' tools/interop-tun.sh
grep -Fq -- '--connect-timeout 10 --max-time 20' tools/bench/lib.sh
grep -Fq -- '--retry-max-time 45' tools/bench/lib.sh
tools/packaging/test-interop-tun-cleanup.sh
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
