# rustscale

A from-scratch Rust implementation of Tailscale's client stack — the equivalent
of Go's [`tsnet`](https://pkg.go.dev/tailscale.com/tsnet) package — supporting
direct (UDP hole-punched) connections, DERP relay, and peer relay, with the
long-term goal of a full TUN-mode client.

This is an independent reimplementation. The Tailscale Go source is used only as
a read-only reference for protocol semantics and wire formats.

## Status

Early stages. Phase 1 provides the cargo workspace foundation plus the
`key` and `tailcfg` crates:

- `crates/key` — Curve25519 node/machine/disco keys with NaCl `box`
  seal/open (nonce-prepended, wire-compatible with Go's
  `key.{NodePrivate,MachinePrivate,DiscoShared}`), typed hex text marshaling
  (`nodekey:`, `mkey:`, `discokey:`, `privkey:`).
- `crates/tailcfg` — core control-plane wire types (`Node`, `Hostinfo`,
  `NetInfo`, `DERPMap`, `MapRequest`/`MapResponse`,
  `RegisterRequest`/`RegisterResponse`) with exact Go JSON field naming, an
  `OptBool` tri-state matching `opt.Bool`, and int-keyed map encoding for
  `DERPMap.Regions`.

Later phases add `disco`, `derp`, `netcheck`, `controlclient`, `magicsock`,
`relayclient`, `wg`, `netstack`, and the `tsnet` embedding API.

## Build

```bash
cargo build --workspace
cargo test  --workspace
cargo clippy --workspace --all-targets
```

## Layout

```
crates/
  key/        node/machine/disco keys + NaCl box
  tailcfg/    control-plane wire types
```

## License

BSD-3-Clause, matching the upstream Tailscale license.
