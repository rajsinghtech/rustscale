# rustscale 0.1.1

rustscale 0.1.1 is a large compatibility and production-readiness update. The
workspace now contains 85 Rust crates and substantially expands client, CLI,
LocalAPI, network-monitoring, routing, logging, and TKA coverage. Linux TUN and
direct-UDP hot paths received extensive batching and allocation work.

See [CHANGELOG.md](../CHANGELOG.md) for the detailed feature summary.

## Performance

The maintained matched direct-TUN comparison is published in
[PERFORMANCE.md](../PERFORMANCE.md), including raw samples, latency, CPU, RSS,
binary size, runtime settings, and reproduction guidance. These historical
pre-release measurements used RustScale commit `ca56c1d`, not the final v0.1.1
tag. On matched `n1-standard-4` runs, throughput-optimized RustScale measured
2152, 2238, and 1818 Mbps at 1, 10, and 100 streams, compared with tailscaled
1.98.9 at 2071, 2356, and 1602 Mbps. RustScale used 36% less average CPU, 65% less average RSS,
and a 60% smaller daemon binary in that workload.

The throughput profile enables the Linux-only, opt-in outbound send pipeline.
It is not the default because it trades higher RustScale CPU and a weaker
latency tail for throughput. The project Pages site presents a compact graph;
the performance document remains authoritative for methodology and caveats.

## Install

### macOS and Linux

```sh
curl -fsSL https://rajsinghtech.github.io/rustscale/install.sh | sh
```

The installer verifies the selected archive against the release's
`SHA256SUMS` before extracting it. Pin this release with `--version v0.1.1`.
Use `--tailscale-compatible` to add `tailscale` and `tailscaled` command aliases
when replacing an existing installation; do not enable it alongside the
official Tailscale client.

### Windows

```powershell
irm https://rajsinghtech.github.io/rustscale/install.ps1 | iex
```

The default user-scoped install needs no administrator privileges. For options,
download the script and run `./install.ps1 -Version v0.1.1`, or invoke the
downloaded script block with parameters as documented in the README.

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
  ghcr.io/rajsinghtech/rustscale:v0.1.1
```

The image is published for `linux/amd64` and `linux/arm64`. It exposes both the
`rustscale`/`rustscaled` and `tailscale`/`tailscaled` command names.

## Release assets

- `rustscale-universal-apple-darwin.tar.gz`
- `rustscale-x86_64-unknown-linux-gnu.tar.gz`
- `rustscale-aarch64-unknown-linux-gnu.tar.gz`
- `rustscale-x86_64-unknown-linux-musl.tar.gz`
- `rustscale-x86_64-pc-windows-msvc.zip`
- `SHA256SUMS`

Each desktop archive contains the CLI, daemon, and BSD-3-Clause license. macOS
and Linux archives also contain the C header plus static and dynamic libraries;
Linux archives include systemd service defaults.
