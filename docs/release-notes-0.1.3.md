# rustscale 0.1.3

rustscale 0.1.3 supersedes v0.1.2. It contains the first-run and lifecycle
hotfixes from v0.1.2 and rebuilds GNU/Linux artifacts on Ubuntu 22.04 so they
run on Debian 12 and other glibc 2.35+ systems.

The v0.1.2 GNU/Linux binaries were linked against glibc 2.39 and do not start
on Debian 12. Linux users should install v0.1.3 instead. The release workflow
now executes the exact x86_64 GNU archive inside `debian:12-slim` before
publishing any GitHub release.

## First-run and service fixes

- Fixed default LocalAPI socket discovery before Tokio startup.
- Made interactive login, logout, shutdown, and subsystem wakeups durable
  across early-arrival and cancellation races.
- Persisted and enforced `Prefs.OperatorUser`, preserving read-only LocalAPI
  access for unrelated users.
- Restored wanted profiles after daemon restart and made `Running` a committed
  readiness boundary.
- Applied online preference updates and made container authentication ownership
  deterministic.
- Hardened socket replacement, cleanup, systemd restart behavior, and bounded
  daemon shutdown.
- Runtime-affine synchronous APIs return typed errors rather than panic outside
  an entered Tokio runtime.

## Acceptance and interoperability

- The installed Linux gate uses real release-mode binaries, the default root
  daemon socket, kernel peer credentials, an ordinary operator, delayed
  interactive login, restart restoration, logout, cleanup, and uninstall.
- Tailnet and Go-client E2E scenarios now isolate unrelated NAT mapping cleanup
  while dedicated portmapper coverage remains strict.
- Added pinned Go speedtest interoperability, complete CLI `wait` behavior, and
  transactional systemd user-unit management.

## Install

### macOS and Linux

```sh
curl -fsSL https://rajsinghtech.github.io/rustscale/install.sh | sh
```

Pin this release with `--version v0.1.3`. Downloads are verified against
`SHA256SUMS`.

### Windows

```powershell
irm https://rajsinghtech.github.io/rustscale/install.ps1 | iex
```

Use `-Version v0.1.3` to pin the release.

### Homebrew

```sh
brew install rajsinghtech/tap/rustscale
```

### Container

```sh
docker run -d --name rustscale \
  -e TS_AUTHKEY=tskey-... \
  -e TS_HOSTNAME=my-container \
  -v rustscale-state:/var/lib/rustscale \
  ghcr.io/rajsinghtech/rustscale:v0.1.3
```

## Release assets

- `rustscale-universal-apple-darwin.tar.gz`
- `rustscale-x86_64-unknown-linux-gnu.tar.gz`
- `rustscale-aarch64-unknown-linux-gnu.tar.gz`
- `rustscale-x86_64-unknown-linux-musl.tar.gz`
- `rustscale-x86_64-pc-windows-msvc.zip`
- `SHA256SUMS`
