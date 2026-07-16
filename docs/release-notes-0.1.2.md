# rustscale 0.1.2

rustscale 0.1.2 is a first-run reliability and service-lifecycle hotfix. It
replaces v0.1.1 for Linux daemon installations, especially the documented
root daemon plus unprivileged operator workflow.

## First-run and service fixes

- Fixed default LocalAPI socket discovery before Tokio startup, eliminating the
  first-run reactor panic and broken-pipe failure.
- Made interactive login, logout, shutdown, and other lifecycle wakeups durable
  across early-arrival races.
- Persisted and enforced `Prefs.OperatorUser`: root or the configured operator
  can mutate LocalAPI while unrelated local users remain read-only.
- Restored wanted, non-logged-out profiles after daemon restart and made
  `BackendState=Running` a committed readiness boundary.
- Applied online `up` preference changes and made auth-key/container bootstrap
  ownership deterministic.
- Installed the systemd service with `Restart=always`, while preserving clean
  logout and intentional shutdown behavior.
- Refused to replace regular files or symlinks at explicit Unix socket paths,
  and removed only actual socket files during cleanup.

## Runtime and shutdown hardening

- Runtime-affine synchronous APIs now return typed errors instead of panicking
  when called outside an entered Tokio runtime.
- Startup can be cancelled cleanly before login, bootstrap, or LocalAPI
  handoff; incomplete ownership is retained for retry.
- Daemon shutdown retries retained cleanup and treats only unconfirmed external
  NAT mapping deletion as best-effort after a bounded retry window. Other
  cleanup failures remain fatal.
- Added bounded Windows TCP-table snapshots and safe managed-policy source
  watching.

## Release acceptance

The Linux release contract now installs the real release-mode binaries, starts
an isolated root daemon on the default socket, configures an ordinary operator,
performs delayed interactive login against local testcontrol, verifies restart
restoration, logs out, removes root-owned state, and uninstalls. The watchdog
also terminates detached privileged processes on failure or timeout. No account,
auth key, public control plane, or production log upload is used.

## Install

### macOS and Linux

```sh
curl -fsSL https://rajsinghtech.github.io/rustscale/install.sh | sh
```

Pin this release with `--version v0.1.2`. The installer verifies the selected
archive against `SHA256SUMS`.

### Windows

```powershell
irm https://rajsinghtech.github.io/rustscale/install.ps1 | iex
```

To pin the release, download the script and run it with `-Version v0.1.2`.

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
  ghcr.io/rajsinghtech/rustscale:v0.1.2
```

## Release assets

- `rustscale-universal-apple-darwin.tar.gz`
- `rustscale-x86_64-unknown-linux-gnu.tar.gz`
- `rustscale-aarch64-unknown-linux-gnu.tar.gz`
- `rustscale-x86_64-unknown-linux-musl.tar.gz`
- `rustscale-x86_64-pc-windows-msvc.zip`
- `SHA256SUMS`
