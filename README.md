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

### CLI + daemon

Start the daemon (root needed for TUN mode):

```
sudo rustscaled run
```

The daemon listens at `/var/run/rustscaled.sock`; override with `--socket
<path>`. Pass `--json` for structured output on any command that supports it.

Connect to a tailnet:

```
rustscale up                              # interactive auth (QR code)
rustscale up --auth-key tskey-...         # headless auth
```

Common commands:

```
rustscale status          # daemon state and connections
rustscale ip              # show Tailscale IPs
rustscale ip -4 [peer]    # show IPv4 for this node or a peer
rustscale whois <ip>      # machine and user for a Tailscale IP
rustscale serve <target>  # expose a local service on the tailnet
rustscale funnel <target> # expose a local service on the internet
rustscale cert <domain>   # get TLS certs for a domain
rustscale switch          # switch between accounts
rustscale switch --list   # list saved profiles
rustscale down            # disconnect
rustscale logout          # disconnect and log out
```

Run `rustscale help` for the full flag set.

### Rust embedding API (userspace netstack — `listen`/`dial` in-process)

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

### TUN mode

For a full-client TUN device instead of the in-process netstack, use
`server.up_tun(config)` with a `TunModeConfig` — see
`crates/tsnet/examples/rustscale-tun.rs`. `listen`/`dial` are unavailable in
TUN mode; packets flow between a real OS TUN device and the data plane.

## Install

### Homebrew

```sh
brew install rajsinghtech/tap/rustscale
```

Installs the `rustscale` CLI and `rustscaled` daemon. The GitHub release
archive also includes `librustscale` (static + dynamic) and `rustscale.h`.

### From source

Build and install the C library and header:

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

## License

BSD-3-Clause, matching the upstream Tailscale license.
