# rustscale 0.1.0

First tagged release. Rust reimplementation of Tailscale's client stack —
tsnet embedding API, TUN-mode client, C FFI (`librustscale`), CLI, and daemon.

See `CHANGELOG.md` for the full feature inventory.

## Install

### macOS

```sh
brew install rajsinghtech/tap/rustscale
```

Installs the `rustscale` CLI and `rustscaled` daemon. The release archive also
includes `librustscale` (static + dynamic) and `rustscale.h`.

Alternatively, download `rustscale-universal-apple-darwin.tar.gz` from the
release page and extract:

```sh
tar xzf rustscale-universal-apple-darwin.tar.gz
sudo install -m 755 rustscale /usr/local/bin/
sudo install -m 755 rustscaled /usr/local/bin/
sudo install -m 644 librustscale.dylib /usr/local/lib/
sudo install -m 644 librustscale.a /usr/local/lib/
sudo install -m 644 rustscale.h /usr/local/include/
```

### Linux

Download the archive matching your architecture:

- `rustscale-x86_64-unknown-linux-gnu.tar.gz` — x86_64 (glibc)
- `rustscale-aarch64-unknown-linux-gnu.tar.gz` — ARM64 (glibc)
- `rustscale-x86_64-unknown-linux-musl.tar.gz` — x86_64 (static, musl)

Extract and install:

```sh
tar xzf rustscale-x86_64-unknown-linux-gnu.tar.gz
sudo install -m 755 rustscale /usr/local/bin/
sudo install -m 755 rustscaled /usr/local/bin/
sudo install -m 755 librustscale.so /usr/local/lib/
sudo install -m 644 librustscale.a /usr/local/lib/
sudo install -m 644 rustscale.h /usr/local/include/
sudo ldconfig
```

### Windows

Download `rustscale-x86_64-pc-windows-msvc.zip` from the release page and
extract. Contains:

- `rustscale.exe` — CLI
- `rustscaled.exe` — daemon

Add the extracted directory to your `PATH` or copy the executables to a
directory already on it.

### From source

Build and install the C library and header:

```sh
sh scripts/install.sh
```

`PREFIX` (default `/usr/local`) selects the install location; `--with-tun`
also installs the `rustscale-tun` CLI example; `--uninstall` removes
everything. Requires the Rust toolchain (`rustup`).

## Getting started

Start the daemon (root needed for TUN mode):

```
sudo rustscaled run
```

Connect to a tailnet:

```
rustscale up                        # interactive auth (QR code)
rustscale up --auth-key tskey-...   # headless auth
```

Common commands:

```
rustscale status          # daemon state and connections
rustscale ip              # show Tailscale IPs
rustscale whois <ip>      # machine and user for a Tailscale IP
rustscale serve <target>  # expose a local service on the tailnet
rustscale funnel <target> # expose a local service on the internet
rustscale cert <domain>   # get TLS certs for a domain
rustscale down            # disconnect
rustscale logout          # disconnect and log out
```

Run `rustscale help` for the full flag set.

## Rust embedding API

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
let stream = server.dial("100.64.0.2:443").await?;
```

## Verify checksums

Each release includes a `SHA256SUMS` file. Verify after download:

```sh
sha256sum -c SHA256SUMS --ignore-missing
```
