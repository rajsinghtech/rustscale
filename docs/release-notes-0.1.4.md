# rustscale 0.1.4

rustscale 0.1.4 is a patch release for idle application UDP latency and
release-readiness hardening. It supersedes v0.1.3.

## Idle application UDP latency (issue #75)

- `rustscale_netstack::UdpListener::send_to` now wakes the netstack poll loop
  only after its outbound datagram has been successfully enqueued. An idle
  listener therefore no longer waits for the poll loop's one-second safety
  fallback, which could delay traffic for almost a second and release queued
  datagrams in a burst.
- Notification-only, back-to-back netstack tests cover both an idle datagram
  and a paced 20 Hz stream without the former 10 ms external pump fallback.
- The cross-client harness runs a separate one-way `Server::listen_packet`
  cadence scenario on two RustScale nodes so continuously active scenarios
  cannot mask a missing application-send wakeup. The generous timing bounds are
  regression guards, not general network-latency guarantees.

Previous bulk iperf and interoperability gates did **not** exercise idle
application `UdpListener` send wake latency. The iperf workloads use sustained
TCP bulk traffic, and the existing interoperability scenarios were TCP/bulk or
otherwise continuously active. They did not leave the netstack poll loop idle
and then originate a one-way datagram through application
`UdpListener::send_to`. The older in-process UDP test also had an independent
10 ms pump fallback that proved eventual delivery while masking the missing
inner wakeup. Direct-path selection and high bulk throughput therefore did not
establish this idle-send latency property.

## Compatibility and client surface

- Added deterministic compatibility inventories for the CLI, all-features
  `rustscale-tsnet` Rust API, C ABI, explicit Python exports, LocalAPI routes,
  and the conceptual tsnet surface. Upstream snapshots and provenance are
  pinned to `tailscale.com@v1.100.0` and routine drift checks run offline.
- Compatibility entries distinguish exact, semantic, shimmed, and unsupported
  items. These inventories make the denominator reviewable; they do not claim
  blanket runtime parity.
- Improved shell-completion command and flag coverage, including accepted flag
  aliases and current lock, update, wait, ping, speedtest, and operator options.

## Installation and release acceptance

- Ordinary installation now provides collision-safe `tailscale` and
  `tailscaled` aliases by default; it refuses to replace either existing command
  before installing files. `--no-tailscale-compatible` is the explicit portable
  opt-out. RustScale continues to use its own state and socket paths.
- Added a credential-free installed Linux replacement journey that consumes the
  exact separately assembled production candidate archive plus `SHA256SUMS`,
  verifies checksums and embedded candidate versions, installs the shipped
  systemd unit, checks help/error streams, LocalAPI authorization and
  restart/logout behavior, and proves a real kernel-TUN roundtrip to pinned Go
  tooling. The release workflow uses the same archive assembly helper and
  remains authoritative for executing the separately uploaded GNU archive on
  Debian 12.
- Added evidence-backed worktree and saved-session reconciliation for the
  optional agent harness.

## Install

### macOS and Linux

```sh
curl -fsSL https://rajsinghtech.github.io/rustscale/install.sh | sh
```

Pin this release with `--version v0.1.4`. Downloads are verified against
`SHA256SUMS`.

### Windows

```powershell
irm https://rajsinghtech.github.io/rustscale/install.ps1 | iex
```

Use `-Version v0.1.4` to pin the release.

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
  ghcr.io/rajsinghtech/rustscale:v0.1.4
```

## Release assets

- `rustscale-universal-apple-darwin.tar.gz`
- `rustscale-x86_64-unknown-linux-gnu.tar.gz`
- `rustscale-aarch64-unknown-linux-gnu.tar.gz`
- `rustscale-x86_64-unknown-linux-musl.tar.gz`
- `rustscale-x86_64-pc-windows-msvc.zip`
- `SHA256SUMS`
