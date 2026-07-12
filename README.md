<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/rustscale-logo.svg">
    <img src="assets/rustscale-logo.svg" alt="rustscale" height="40">
  </picture>
</p>

<p align="center">
  <strong>A Rust implementation of Tailscale's client stack</strong>
</p>

---

A from-scratch Rust implementation of Tailscale's client stack — the equivalent
of Go's [`tsnet`](https://pkg.go.dev/tailscale.com/tsnet) embedding API — plus a
TUN-mode client and a C FFI (`librustscale`). It joins a tailnet, dials and
listens over WireGuard, and routes packets through direct UDP, DERP relay, and
peer-relay paths. This is an independent reimplementation; the Tailscale Go
source is used only as a read-only reference for protocol semantics and wire
formats.

## Usage

Rust embedding API (userspace netstack — `listen`/`dial` in-process):

```rust
use rustscale_tsnet::Server;

let mut server = Server::builder()
    .hostname("my-app")
    .auth_key("tskey-...")
    .ephemeral(true)
    .build()?;

server.up().await?;

let status = server.status();
println!("tailscale IP: {:?}", status.tailscale_ips);

let mut listener = server.listen(8080).await?;
// loop { let stream = listener.accept().await?; ... }

let stream = server.dial("100.64.0.2:443").await?;
server.close().await;
```

For a full-client TUN device instead of the in-process netstack, use
`server.up_tun(config)` with a `TunModeConfig` — see
`crates/tsnet/examples/rustscale-tun.rs`. `listen`/`dial` are unavailable in
TUN mode; packets flow between a real OS TUN device and the data plane.

Install the C library and header:

```sh
sh scripts/install.sh
```

`PREFIX` (default `/usr/local`) selects the install location; `--with-tun`
also installs the `rustscale-tun` CLI; `--uninstall` removes everything. See
the `scripts/install.sh` header for the full flag set.

## Build and test

```sh
cargo build --workspace
cargo test  --workspace
tools/check.sh   # the CI gate: build + test + clippy -D warnings + fmt --check
```

## Workspace layout

```
crates/
  key/           curve25519 node/machine/disco keys + NaCl box
  tailcfg/       control-plane wire types (Node, NetMap, DERPMap, MapRequest/Response)
  disco/         NAT-traversal discovery message codec + box crypto
  derp/          DERP relay client protocol (frame codec, derphttp client)
  netcheck/      STUN-based network probing + per-region DERP latency
  controlclient/ ts2021 Noise control channel: register + map long-poll
  magicsock/     path selection — direct UDP, DERP relay, peer relay
  wg/            WireGuard data plane (boringtun noise::Tunn wrapper)
  netstack/      userspace TCP/IP stack (smoltcp) for tsnet listen/dial
  tun/           OS TUN device abstraction (macOS utun, Linux /dev/net/tun)
  filter/        stateful packet filter (wgengine/filter port)
  dns/           MagicDNS resolver + in-process UDP DNS responder
  netmon/        network change monitor (AF_ROUTE on macOS) → re-STUN/DERP
  tsnet/         public embedding API: Server::builder, up, up_tun, listen, dial
  ffi/           C ABI (librustscale) — opaque-handle API, libtailscale-equivalent
  bench/         throughput and latency benchmark harness for tsnet
```

## License

BSD-3-Clause, matching the upstream Tailscale license.
