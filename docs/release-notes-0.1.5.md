# rustscale 0.1.5

rustscale 0.1.5 is a patch release for client lifecycle reliability, Linux
replacement behavior, truthful path reporting, embedded connection capacity,
and reproducible performance evidence. It supersedes v0.1.4.

## Lifecycle and Linux integration

- Daemon and CLI down/up transitions now preserve the selected profile,
  reconnect across bounded LocalAPI handoffs, and avoid stale or uncertain
  logout state during restart and shutdown.
- First-run Tailscale-compatible replacement behavior now uses the shipped
  command aliases and exact release artifact consistently.
- Linux MagicDNS configuration uses systemd-resolved with policy-routing
  coverage for the created TUN interface.
- The protected acceptance suite builds the exact Linux candidate, exercises
  the installed systemd replacement journey, and runs the isolated two-process
  kernel-TUN roundtrip.

## Embedded networking and status

- Peer path status is derived only from fresh observed direct, peer-relay, or
  DERP evidence; configured fallbacks are no longer reported as active paths.
- Embedded userspace setup uses bounded ordered admission, collision-owned
  client ports, fair receive batching, and explicit cancellation/close
  ownership. Deterministic regressions cover the P500 and P1000 lifecycle
  limits that blocked the prior certification run.
- Rust userspace TCP buffers now match the pinned Tailscale/gVisor 1 MiB
  defaults used by the comparator. This removes one known configuration
  asymmetry but is not, by itself, a performance claim.

## Canonical benchmark evidence

The repository now includes a native comparator embedded in
`tailscale.com/tsnet.Server@v1.100.0` and a credential-free canonical result
tree at `docs/performance/gcp-20260721-080637-4aca6f6c1e/`.

The accepted same-region, cross-zone direct-path run measured five separately
labeled configurations: Rust embedded userspace, Go embedded tsnet, Rust TUN,
tailscaled userspace daemon proxy, and tailscaled TUN. Every cell completed
P1/P10/P100/P500/P1000 with three 10-second repeats, exact connection lifecycle
denominators, 200 valid latency samples, bilateral process CPU/RSS and
executable identity, immutable provenance, and verified cleanup.

The Pages summary exposes all configurations and all concurrency levels. Rust
embedded repeat coefficients of variation are high at P1, P500, and P1000, so
this release makes no stable winner claim. See `PERFORMANCE.md` for the measured
values, resource tables, workload definition, and interpretation limits.

## Install

### macOS and Linux

```sh
curl -fsSL https://rajsinghtech.github.io/rustscale/install.sh | sh
```

Pin this release with `--version v0.1.5`. Downloads are verified against
`SHA256SUMS`.

### Windows

```powershell
irm https://rajsinghtech.github.io/rustscale/install.ps1 | iex
```

Use `-Version v0.1.5` to pin the release.

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
  ghcr.io/rajsinghtech/rustscale:v0.1.5
```

## Release assets

- `rustscale-universal-apple-darwin.tar.gz`
- `rustscale-x86_64-unknown-linux-gnu.tar.gz`
- `rustscale-aarch64-unknown-linux-gnu.tar.gz`
- `rustscale-x86_64-unknown-linux-musl.tar.gz`
- `rustscale-x86_64-pc-windows-msvc.zip`
- `SHA256SUMS`
