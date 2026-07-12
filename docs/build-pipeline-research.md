# Build Pipeline Research: tailscale → rustscale gaps

## 1. Tailscale CI workflows

### test.yml (main CI — `test.yml:1-1021`)
Fires on: push to `main`/`release-branch/*`, all PRs, merge_group.
Matrix dims:
- **gomod-cache**: single ubuntu-24.04, computes + populates go module cache keyed on go.sum.
- **race-root-integration**: 4 shards, ubuntu-24.04, builds testwrapper, runs `tstest/integration/` under sudo with -race.
- **test**: ubuntu-24.04, 4 entries: plain amd64 build+test, 3 race shards, `386` arch.
- **windows**: ci-windows-github-1 runner, 3 entries: 2 test shards + benchmarks.
- **macos**: macos-latest, single test run.
- **privileged**: ubuntu-24.04 in privileged docker container, runs root-needing tests.
- **vm**: self-hosted VM runner, runs `tstest/integration/vms`.
- **cross**: 11 entries (linux/arm64/386/loong64/arm5/arm7, darwin/amd64/arm64, windows/amd64/arm64, freebsd/amd64, openbsd/amd64) — build only, CGO_ENABLED=0.
- **ios / android / wasm**: platform-specific smoke builds.
- **crossmin**: plan9/aix/solaris/illumos amd64 — cmd/tailscale{,d} only.
- **fuzz**: OSS-Fuzz, PR-only, 150s fuzz duration.
- **depaware / go_generate / make_tidy / licenses / staticcheck**: code hygiene.
- **notify_slack / merge_blocker / check_mergeability_strict / check_mergeability**: aggregate status.

### golangci-lint.yml (`golangci-lint.yml:1-47`)
Fires on PRs touching `*.go`/go.mod/go.sum. Single job, golangci-lint v2.10.1 with `only-new-issues: true`.

### govulncheck.yml (`govulncheck.yml:1-51`)
Scheduled daily 12:00 UTC, also PR on workflow-file change. Runs `govulncheck -test ./...`.

### checklocks.yml (`checklocks.yml:1-34`)
Fires on push to main + PRs touching `*.go`. Builds gvisor checklocks, runs vet on selected packages.

### codeql-analysis.yml (`codeql-analysis.yml:1-83`)
Fires on push/PR to main/release-branch/* + weekly schedule. Go language, GitHub CodeQL autobuild + analyze.

### installer.yml (`installer.yml:1-144`)
Tests `scripts/installer.sh` across ~20 Docker images (debian/ubuntu/elementary/parrot/oraclelinux/fedora/rocky/amazonlinux/opensuse/archlinux/alpine/kali). Scheduled daily + on pushes/PRs touching the installer script.

### docker-base.yml (`docker-base.yml:1-29`)
Validates Dockerfile.base has legacy iptables. PR-only on Dockerfile.base changes.

## 2. Release artifact production: cmd/dist + build_dist.sh

### Version derivation (`version/mkversion/mkversion.go:400-455`, `version/version.go:73-104`)
Version comes from `VERSION.txt` (currently `1.101.0`). `mkversion.InfoFrom(dir)` runs `git rev-list --count` from the commit that last touched `VERSION.txt` to HEAD — that count becomes the patch number for unstable (odd-minor) builds or appears as a suffix for stable branch pre-release builds. Output is shell variables (`VERSION_SHORT`, `VERSION_LONG`, `VERSION_GIT_HASH`).

### build_dist.sh (`build_dist.sh:1-75`)
Entry point for binary distribution builds:
1. Runs `CGO_ENABLED=0 go run ./cmd/mkversion` to get version vars.
2. Sets `-ldflags` to stamp `version.longStamp` and `version.shortStamp` at link time.
3. Supports flags: `--extra-small` (strip + min feature tags), `--box` (include CLI in tailscaled), `--strip` (strip symbols), `--min` (benchmark-only).
4. Falls through to `go build -trimpath -ldflags ... "$@"`.

### cmd/dist + release/ (`cmd/dist/dist.go:33-57`, `release/dist/unixpkgs/targets.go:22-71`)
Universal release builder producing:
- **.tgz tarballs**: linux/{386,amd64,arm,arm64,mips64,mips64le,mips,mipsle,riscv64} + geode special case.
- **.deb packages**: linux/{386,amd64,arm,arm64,riscv64,mipsle,mips64le,mips}.
- **.rpm packages**: same as deb plus mips64.
- **Synology .spk**: via release/dist/synology.
- **QNAP**: via release/dist/qnap with cloud KMS signing.
- **Docker images**: via build_docker.sh using mkctr (multi-arch, across arm/arm64/amd64/386/riscv64).

### Docker image building (`build_docker.sh:25-69`)
Uses `build_dist.sh shellvars` for version, then `mkctr` with `--gopaths`, `--ldflags` (stamps `longStamp`, `shortStamp`, `gitCommitStamp`), multi-platform via `--goarch` / `--target`.

## 3. Concrete proposal: what rustscale is missing

### (a) release.yml — automated GitHub Releases on tag push

**rustscale has NO release workflow.** Tailscale uses `cmd/dist` + `build_dist.sh` + `build_docker.sh` + manually-tagged releases.

Proposed `.github/workflows/release.yml` — triggers on `push: tags: ['v*']`:

**Build matrix**:
| Target | Runner | Cargo target | Notes |
|---|---|---|---|
| macOS universal | `macos-latest` | `aarch64-apple-darwin` + `x86_64-apple-darwin` | Build both, `lipo -create -output` |
| Linux x86_64 gnu | `ubuntu-latest` | `x86_64-unknown-linux-gnu` | |
| Linux aarch64 gnu | `ubuntu-latest` | `aarch64-unknown-linux-gnu` | cross-compile |
| Linux x86_64 musl | `ubuntu-latest` | `x86_64-unknown-linux-musl` | static binary |
| Linux aarch64 musl | `ubuntu-latest` | `aarch64-unknown-linux-musl` | cross-compile |

**FFI artifacts per target** (from `crates/ffi/Cargo.toml:14`: `cdylib` + `staticlib`):
- `librustscale.dylib` / `librustscale.so` / `librustscale.a`
- Generated C header via `cbindgen` (already wired in `crates/ffi/build.rs:1-32` and `tools/gen-header.sh`)
- Archive into `rustscale-{version}-{target}.tar.gz`

**Per-target binary artifact**: `cargo build --release -p rustscale-tsnet` → strip → `rustscale-{version}-{target}.tar.gz`

**Steps**:
1. Resolve version from `git describe --tags --always` or tag name.
2. For each target: `cargo build --release --target $TARGET --workspace --exclude rustscale-bench-tsrs`.
3. For macOS universal: build both archs, `lipo -create -output` into a single `rustscale-{version}-macos-universal`.
4. Collect FFI artifacts from `target/$TARGET/release/`.
5. `sha256sum *.tar.gz > SHA256SUMS`.
6. `gh release create` with all tarballs + SHA256SUMS.

Required: add `--target` installations to setup (e.g., `rustup target add aarch64-unknown-linux-gnu aarch64-unknown-linux-musl x86_64-unknown-linux-musl`).

### (b) security workflow — cargo-audit + cargo-deny

Tailscale has `govulncheck.yml` (Go vuln scanning) and `codeql-analysis.yml`. rustscale has neither.

Proposed `.github/workflows/security.yml` — triggers: schedule (weekly), PR on `Cargo.lock` changes.

**Jobs**:
- **audit**: `cargo audit` (from `rustsec/rustsec` crate) — checks for known vulnerabilities in dependencies.
- **deny**: `cargo deny check` (from `EmbarkStudios/cargo-deny`) — license compliance, duplicate crate versions, advisory bans.
- **codeql**: use `github/codeql-action` — Rust language analysis.

### (c) Version stamping from git describe

Tailscale stamps `version.longStamp`/`version.shortStamp` via `-ldflags` at build time, sourced from `git describe` counts (`version/mkversion/mkversion.go:108-176`).

rustscale currently hardcodes `version = "0.1.0"` in workspace `Cargo.toml:8`. Proposal:

**Add a `version` crate** (e.g., `crates/version/build.rs`):
- At build time, run `git describe --tags --always --dirty` and `git rev-parse HEAD`.
- Set `cargo:rustc-env=RUSTSCALE_VERSION=...`, `cargo:rustc-env=RUSTSCALE_GIT_HASH=...`, `cargo:rustc-env=RUSTSCALE_GIT_DIRTY=...`.
- Provide a `version` module with `fn long()`, `fn short()`, `fn git_hash()` — analogous to `tailscale.com/version/version.go:73-104`.

**Consumers**: tsnet crate can expose version in `Server::up` responses, health crate can report it, FFI can surface it.

**Tag-based release workflow integration**: When CI runs on a `v*` tag, override the build.rs env with the tag value (e.g., strip leading `v` → `1.2.3`).

### Summary table

| Capability | Tailscale | rustscale | Missing |
|---|---|---|---|
| CI (build+test+lint) | `test.yml`, `golangci-lint.yml` | `ci.yml` | None (rustscale has build+test+clippy+fmt) |
| Cross-compile smoke | `cross`, `crossmin` jobs | None | Add cross-compile check job |
| Fuzz testing | OSS-Fuzz via `test.yml` | None | Nice-to-have |
| Security scanning | `govulncheck.yml`, `codeql-analysis.yml` | None | **(b): cargo-audit + cargo-deny + CodeQL** |
| Release automation | `cmd/dist`, `build_dist.sh`, manual tagging | None | **(a): release.yml on `v*` tag** |
| macOS binary | Not distributed as universal binary | None | macOS universal (aarch64+x86_64 + lipo) |
| Linux static binaries | Not distributed (CGO_ENABLED=0 but glibc-linked) | None | musl-static builds |
| FFI distribution | Client libraries not open-source | cdylib+staticlib in `crates/ffi` | **(a): include in release tarballs** |
| Package formats | deb/rpm/spk/tgz/docker | None | Nice-to-have (debian packaging) |
| Version stamping | `version/mkversion` + `-ldflags` | Hardcoded `0.1.0` | **(c): build.rs git-describe stamping** |
| Checksums | Built into pkgs.tailscale.com | None | SHA256SUMS generation |
| Windows support | `windows` job, MSI installer | None | Future |
