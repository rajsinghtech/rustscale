# Tailscale Build & Release Pipeline Research

Research notes from reading the Go Tailscale repo at `/Users/rajsingh/Documents/GitHub/tailscale`.
Goal: inform an equivalent release pipeline for this Rust workspace.

---

## 1. Tailscale CI Workflows

All workflows live in `.github/workflows/`. There is **no `ci.yml`** — the main CI file is `test.yml`.

### test.yml — main CI (`name: CI`)
Triggers: `push` to `main` + `release-branch/*`, all PRs, `merge_group` on `main`.
Concurrency cancels in-progress PR runs on new pushes.

| Job | Matrix dims | What it does |
|-----|-------------|--------------|
| `gomod-cache` | — | Shared `go mod download` cache keyed on `hashFiles(go.mod, go.sum)`, cross-OS archived. |
| `test` | `goarch`: amd64, amd64+`-race`×3 shards, `386` | Build all, build variant CLIs (`--extra-small`, `--box`), run `testwrapper` sharded, bench smoke, verify no file changes. |
| `race-root-integration` | shard `1/4`–`4/4` | Integration tests as root with `-race`. |
| `windows` | bench, shard `1/2`, `2/2` | Self-hosted runner with cigocacher remote Go cache. |
| `macos` | — | Build + test on `macos-latest`. |
| `privileged` | — | `golang:latest` container `--privileged`; tests that need root. |
| `vm` | — | Self-hosted Linux VM; `TestRunUbuntu2404` full VM integration test. |
| `cross` | `goos`×`goarch`: linux{arm64,386,loong64,arm5,arm7}, darwin{amd64,arm64}, windows{amd64,arm64}, freebsd, openbsd | Cross-compile `./cmd/...` + build test binaries (`CGO_ENABLED=0`). |
| `crossmin` | plan9, aix, solaris, illumos | Build only `cmd/tailscale` + `cmd/tailscaled`. |
| `ios` | — | `GOOS=ios GOARCH=arm64` smoke build of subset. |
| `android` | — | `GOOS=android GOARCH=arm64` smoke `go install` of subset. |
| `wasm` | — | Build `tsconnect` wasm + headless Chrome browser tests. |
| `tailscale_go` | — | Tests requiring Tailscale's custom Go toolchain. |
| `fuzz` | — | OSS-Fuzz cifuzz build + run; toggled by `TS_FUZZ_CURRENTLY_BROKEN`. |
| `depaware` | — | Dependency-surface allowlist check via `make depaware`. |
| `go_generate` | — | `go generate` + `genreadme` must be clean (no diff). |
| `make_tidy` | — | `go mod tidy` must be clean. |
| `licenses` | — | `TestLicenseHeaders` test must exist and pass. |
| `staticcheck` | macOS/Windows/Linux/portable×4 shards | Runs `honnef.co/go/tools/cmd/staticcheck` over package lists. |
| `notify_slack` | — | Slack webhook on push failures only. |
| `merge_blocker` / `check_mergeability_strict` / `check_mergeability` | — | `re-actors/alls-green` gate aggregating required jobs for branch protection. |

### golangci-lint.yml
Triggers: PRs on `*.go`/`go.mod`/`go.sum`/self + `workflow_dispatch`. Runs `golangci-lint-action` v2.10.1, `only-new-issues: true`, 10m timeout.

### govulncheck.yml
Triggers: daily cron 12:00 UTC + `workflow_dispatch` + PR on self file. Installs `govulncheck@latest`, scans `./...` with `-test`. Slack notify on scheduled failure.

### checklocks.yml
Triggers: push to `main` + PRs on `*.go`. Builds `gvisor.dev/gvisor/tools/checklocks` vet tool, runs on a curated package list (`envknob`, `ipn/store/mem`, `net/stun/stuntest`, `net/wsconn`, `proxymap`).

### codeql-analysis.yml
Triggers: push to `main`/`release-branch/*`, PRs to `main`, merge_group, weekly cron (Fri 14:31). Matrix: `language: [go]`. Standard init→autobuild→analyze.

### installer.yml
Triggers: daily cron 15:00 UTC, push to `main` on `scripts/installer.sh`, PRs on same. Matrix: ~20 distro images (debian, ubuntu, fedora, alpine, arch, opensuse, oraclelinux, rockylinux, amazonlinux, kali, elementary, parrotsec) × `deps` (curl/wget) × optional `TAILSCALE_VERSION` pinning. Runs `scripts/installer.sh` as root in container, checks `tailscale --version`.

### docker-base.yml
Triggers: `workflow_dispatch` + PRs on `Dockerfile.base`. Builds base image, verifies legacy `iptables`/`ip6tables` present.

### docker-file-build.yml
Triggers: push to `main`, all PRs. `docker build .` smoke.

---

## 2. Release Artifact Production

### build_dist.sh (repo root, 75 lines)
Thin wrapper over `go build` that stamps version + git info via `-ldflags`.

**Version derivation flow:**
1. `eval $(CGO_ENABLED=0 go run ./cmd/mkversion)` — `cmd/mkversion` invokes `version/mkversion.InfoFrom("")`.
2. `mkversion.go` (`version/mkversion/mkversion.go:117`) finds git root, reads `VERSION.txt` (currently `1.101.0`), then:
   - `git rev-parse HEAD` → commit hash
   - `git log -n1 --format=%ct HEAD` → commit date
   - `git rev-list --max-count=1 <hash> -- VERSION.txt` → base version commit
   - `git rev-list --count <hash> ^<baseHash>` → changeCount (commits since last VERSION.txt bump)
3. Outputs shell vars: `VERSION_MAJOR`, `VERSION_MINOR`, `VERSION_PATCH`, `VERSION_SHORT` (`x.y.z`), `VERSION_LONG` (`x.y.z[-changeSuffix][-t<hash>][-g<otherHash>]`), `VERSION_GIT_HASH`, `VERSION_TRACK` (`stable` if minor even, `unstable` if odd).
4. `build_dist.sh shellvars` subcommand emits these for sourcing by `build_docker.sh`.

**ldflags stamping (`build_dist.sh:32`):**
```
-X tailscale.com/version.longStamp=${VERSION_LONG}
-X tailscale.com/version.shortStamp=${VERSION_SHORT}
```
Plus `-trimpath`. Variants: `--extra-small` (strips `-w -s`, adds minimal feature tags), `--min` (even smaller), `--box` (adds `ts_include_cli` tag).

### version/ package (`version/version.go`)
Runtime version resolution: if stamps are set (via ldflags), returns them verbatim. Otherwise falls back to `debug.ReadBuildInfo()` VCS settings (`vcs.revision`, `vcs.time`, `vcs.modified`). So a plain `go build` yields `x.y.z-devYYYYMMDD-t<hash>[-dirty]`.

### cmd/dist (release package builder)
`cmd/dist/dist.go` — CLI entrypoint using `ffcli`. Subcommands: `list`, `build`, `gen-key`, `sign-key`, `verify-key-signature`, `verify-package-signature`.

`build` targets come from `release/dist/`:
- `release/dist/dist.go` — `Build` struct holds repo path, output dir, `mkversion.VersionInfo`, temp dir. Concurrency-limited `go build` invocation (CPU-count semaphore). `BuildGoBinary` memoizes per (path, env, tags).
- `release/dist/unixpkgs/targets.go` — defines tarball/deb/rpm target matrices:
  - **tarballs**: linux/{386,amd64,arm,arm64,mips64,mips64le,mips,mipsle,riscv64} + special geode(386+softfloat)
  - **debs**: linux/{386,amd64,arm,arm64,riscv64,mipsle,mips64le,mips}
  - **rpms**: linux/{386,amd64,arm,arm64,riscv64,mipsle,mips64le}
  - Uses `nfpm/v2` (`deb` + `rpm` registrars) for package creation.
- `release/dist/synology/` — `.spk` packages per DSM version × arch.
- `release/dist/qnap/` — QNAP `.qpkg` with GCP KMS signing.
- `release/deb/` — `debian.postinst.sh`, `debian.postrm.sh`, `debian.prerm.sh` maintainer scripts.
- `release/rpm/` — `rpm.postinst.sh`, `rpm.postrm.sh`, `rpm.prerm.sh`.
- `release/dist/cli/cli.go` — `dist build [filters]`, `--manifest`, `--out`, `--web-client-root`. Also `gen-key`/`sign-key` (distsign: root + signing key hierarchy for package signature verification).

### build_docker.sh (repo root, 155 lines)
Uses `github.com/tailscale/mkctr` to build multi-arch OCI images. Targets: `client` (tailscale+tailscaled+containerboot), `k8s-operator`, `k8s-nameserver`, `tsidp`, `k8s-proxy`. Sources version from `./build_dist.sh shellvars`. Multi-arch: `arm,arm64,amd64,386,riscv64`. OCI annotations set.

### Makefile (repo root, 163 lines)
Convenience wrappers: `vet`, `tidy`, `lint` (golangci-lint), `depaware`/`updatedeps`, `buildwindows`/`build386`/`buildlinuxarm`/`buildwasm`/`buildplan9`/`buildlinuxloong64`, `check` (staticcheck+vet+depaware+cross-builds), `kube-generate-*`, `spk`/`spkall` (synology via `cmd/dist`), `publishdevimage` (→ `build_docker.sh`), `sshintegrationtest`, `generate`, `pin-github-actions` (frizbee), `help`.

---

## 3. Concrete Proposal: Rustscale Release Pipeline

### Existing workflows (do not duplicate)
- `.github/workflows/ci.yml` — build+test+clippy+fmt on push to `master` + PRs. Also `testcontrol` Go interop job.
- `.github/workflows/e2e.yml` — ephemeral tailnet E2E + interop + TUN interop (master-only, OIDC WIF).
- `.github/workflows/bench.yml` — throughput benchmarks (manual dispatch).

### What is MISSING — proposed new workflows

#### (a) `.github/workflows/release.yml` — tag-triggered release builds

```
on:
  push:
    tags: ['v*']

jobs:
  build-macos:
    runs-on: macos-latest
    strategy:
      matrix:
        target: [aarch64-apple-darwin, x86_64-apple-darwin]
    steps:
      - checkout (fetch-depth: 0 for git describe)
      - dtolnay/rust-toolchain@stable + target add
      - Swatinem/rust-cache@v2
      - cargo build -p rustscale-ffi --release --target ${{ matrix.target }}
      - lipo both arches → librustscale.dylib (universal)
      - lipo staticlibs → librustscale.a (universal)
      - tools/gen-header.sh  (regenerate include/rustscale.h)
      - upload-artifact: librustscale.{dylib,a}, include/rustscale.h

  build-linux:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        include:
          - target: x86_64-unknown-linux-gnu
          - target: aarch64-unknown-linux-gnu
          - target: x86_64-unknown-linux-musl   # static
          - target: aarch64-unknown-linux-musl
    steps:
      - checkout (fetch-depth: 0)
      - rustup target add ${{ matrix.target }}
      - cargo build -p rustscale-ffi --release --target ${{ matrix.target }}
      - upload-artifact per target

  release:
    needs: [build-macos, build-linux]
    runs-on: ubuntu-latest
    permissions: { contents: write }
    steps:
      - download all artifacts
      - compute sha256 checksums → SHA256SUMS
      - softprops/action-gh-release: upload universal dylib/a, per-target 
        staticlibs, include/rustscale.h, SHA256SUMS
```

Key points:
- `fetch-depth: 0` so `git describe` works in build.rs version stamping.
- FFI crate (`crates/ffi`) produces `cdylib` + `staticlib` (see `crates/ffi/Cargo.toml:14`).
- `tools/gen-header.sh` runs `cargo build -p rustscale-ffi` which triggers `crates/ffi/build.rs` (cbindgen → `include/rustscale.h`).
- macOS universal: `lipo -create -output librustscale.dylib <aarch64> <x86_64>`.
- Linux musl: fully static `librustscale.a` / `librustscale.so`.

#### (b) `.github/workflows/security.yml` — cargo-audit + cargo-deny

```
on:
  push: { branches: [master] }
  pull_request:
  schedule:
    - cron: '0 12 * * *'
  workflow_dispatch:

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - checkout
      - rustup install stable
      - cargo install cargo-audit
      - cargo audit
  deny:
    runs-on: ubuntu-latest
    steps:
      - checkout
      - cargo install cargo-deny
      - cargo deny check
```

Mirrors Tailscale's `govulncheck.yml` cron + PR-on-self pattern.

#### (c) Version stamping via build.rs + git describe

Add a workspace-level `build.rs` (or `crates/version/build.rs`) that:
1. Runs `git describe --tags --always --dirty` at build time.
2. Sets `cargo:rustc-env=RUSTSCALE_VERSION=<output>`.
3. Exposes via a `crates/version` crate: `env!("RUSTSCALE_VERSION")`.

Pattern (Cargo build script):
```rust
fn main() {
    let ver = std::process::Command::new("git")
        .args(["describe", "--tags", "--always", "--dirty"])
        .output().ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "0.0.0-unknown".into());
    println!("cargo:rustc-env=RUSTSCALE_VERSION={ver}");
    println!("cargo:rerun-if-changed=.git/HEAD");
}
```

This mirrors Tailscale's `build_dist.sh` + `version/mkversion` → ldflags stamping, but idiomatic for Rust. Fallback to `debug.ReadBuildInfo()` equivalent: VCS info is not embedded by `cargo build` by default (unlike Go), so the build script is the primary mechanism. For release builds, tag must be fetched with `fetch-depth: 0`.

The existing `workspace.package.version = "0.1.0"` (`Cargo.toml:7`) stays the crate version; the git-describe stamp is a separate runtime version string for `--version` output and diagnostics.

---

## 4. Existing Rustscale FFI Build Steps

Exact current pipeline, from source:

**`crates/ffi/Cargo.toml`** (48 lines):
- Crate name: `rustscale-ffi`, lib name: `rustscale`
- `crate-type = ["cdylib", "staticlib", "rlib"]` (line 14)
  - cdylib → `librustscale.dylib` / `librustscale.so`
  - staticlib → `librustscale.a`
  - rlib → for Rust-internal tests
- `[build-dependencies] cbindgen = "0.27"` (line 48)
- `[lints.rust] unsafe_code = "allow"` (line 21) — FFI crate needs raw pointers; workspace forbids unsafe elsewhere.
- Dependencies: `rustscale-tsnet`, `rustscale-netstack`, `rustscale-health`, `serde`, `serde_json`, `tokio`.

**`crates/ffi/build.rs`** (32 lines):
- Runs `cbindgen::Builder` with config from `crates/ffi/cbindgen.toml`.
- Output: `include/rustscale.h` (workspace-relative, computed via `crate_dir.parent().parent()`).
- `cargo:rerun-if-changed=src/lib.rs` + `cbindgen.toml`.
- On cbindgen failure: prints `cargo:warning` but does **not** fail the build (committed header may already exist).

**`crates/ffi/cbindgen.toml`** (30 lines):
- `language = "C"`, `include_guard = "RUSTSCALE_H"`, `style = "both"`, `sort_by = "Name"`, `usize_is_size_t = true`.
- `parse_deps = false` — only generates bindings for the `rustscale-ffi` crate itself, not transitive deps.

**`tools/gen-header.sh`** (16 lines):
- Runs `cargo build -p rustscale-ffi` (triggers `build.rs` → cbindgen → `include/rustscale.h`).
- Verifies `include/rustscale.h` exists post-build; prints line count.

**`tools/ffi-smoke.sh`** (56 lines):
- Builds `rustscale-ffi` (debug), locates `target/debug/librustscale.dylib` (or `.so` on Linux).
- Compiles `examples/c/echo.c` with `cc -I include -L target/debug -lrustscale -Wl,-rpath`.
- `--run` flag executes the binary (requires `TS_E2E_AUTHKEY`); default is compile-only.

**`include/rustscale.h`** — committed C header, regenerated by `build.rs` / `tools/gen-header.sh`.

**`tools/check.sh`** (75 lines) — local CI gate: `cargo build --workspace --all-targets`, `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all --check`. Matches `.github/workflows/ci.yml` exactly.
