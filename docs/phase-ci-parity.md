# Phase: CI parity with tailscale/tailscale

Goal: close the highest-value CI gaps vs the Go repo's `.github/workflows/` (researched
2026-07-11; see summary below). Rust translations only — do not port Go-specific or
corp-specific jobs (gomod-cache, golangci-lint, checklocks, cigocacher, self-hosted
runners, reviewer bots, Nix/FlakeHub, kube/webclient).

## Current rustscale CI (keep, don't regress)

- `ci.yml` — ubuntu check job (build/test/clippy/fmt) + testcontrol interop vs Go repo.
- `audit.yml` — weekly + Cargo.lock-PR cargo-audit + cargo-deny.
- `e2e.yml` — WIF/OIDC ephemeral-tailnet e2e + Go-interop (userspace + TUN), repo-gated.
- `bench.yml` — dispatch-only comparative bench vs tailscaled.
- `release.yml` — tag-driven macOS universal + linux gnu/aarch64/musl artifacts.

## Work items (in priority order)

1. **OS matrix on PR**: extend `ci.yml` check job to `[ubuntu-latest, macos-latest, windows-latest]`.
   Tests that require a network/TUN must be skipped or feature-gated per OS — expect some
   `#[cfg]`/test-gating work, especially Windows (which has never been built in CI).
   Windows may need `--no-default-features` or excluding `crates/tun` initially; if
   the workspace doesn't compile on windows-msvc, make the Windows job
   `cargo check --workspace` only and file the failures in docs/parity.md rather than
   fixing everything in this phase.
2. **Cross-compile check matrix** (build-only, PR): `cargo check --workspace --target` for
   `aarch64-unknown-linux-gnu`, `armv7-unknown-linux-gnueabihf`, `x86_64-unknown-linux-musl`,
   `aarch64-apple-darwin` (on macos runner), `x86_64-pc-windows-msvc` (on windows runner).
   Install targets via rustup; use gcc-aarch64/musl-tools as release.yml already does.
3. **`--locked` everywhere**: add `--locked` to every cargo build/test/check invocation in
   all workflows (Cargo.lock drift guard, analog of Go's `make tidy` check).
4. **Dirty-tree guard**: after the build+test steps, `git diff --exit-code` and assert no
   new untracked files (analog of their `git status --porcelain` check).
5. **Merge gate**: add a final `alls-green` job (`re-actors/alls-green`) aggregating the
   strict set (check matrix, cross-compile, audit) so branch protection points at one job.
   e2e/interop/bench stay out of the strict set (flaky-tolerant, repo-gated).
6. **SHA-pin all actions**: replace floating tags (`actions/checkout@v6`, `dtolnay/rust-toolchain@stable`,
   `Swatinem/rust-cache@v2`, etc.) with commit SHAs + version comments, in every workflow.
7. **cargo-fuzz targets** (new `fuzz/` dir + PR-time short run, 60–150s like cifuzz):
   highest-value parse surfaces: disco message decode (`crates/disco`), DERP frame codec
   (`crates/derp`), STUN response parse (`crates/netcheck`), PMP/PCP/UPnP packet codec
   (`crates/portmapper`), tailcfg JSON (serde — lower value, skip initially).
   Job: build fuzz targets, run each for a fixed short budget, upload artifacts on crash.
8. **Nightly sanitizer job** (cron, not PR-blocking): TSan (`RUSTFLAGS=-Zsanitizer=thread`,
   nightly, linux) over the concurrency-heavy crates (magicsock, derp, tsnet); optionally
   Miri for the pure codec crates. Allowed to fail without blocking merges initially.
9. **MSRV job**: pin an MSRV in workspace Cargo.toml (`rust-version`), add a CI job
   building with exactly that toolchain.

## Acceptance criteria

- All workflows green on a PR from the phase branch (macOS/Windows jobs may be
  check-only if full test parity is deferred — but they must be green, not skipped).
- `cargo build --workspace --locked && cargo test --workspace --locked && cargo clippy
  --workspace --all-targets -- -D warnings` locally.
- Every action in every workflow SHA-pinned.
- `fuzz/` builds and each target survives its short CI budget.
- docs/parity.md updated (CI/infra rows).

## Non-goals (this phase)

Natlab-style QEMU NAT testing (future phase — big), installer-script distro matrix
(no installer yet), CodeQL-for-Rust (beta; revisit), Slack notifications (no webhook),
Docker image (no container product yet), bench-on-PR regression tracking.
