# Vendored BoringTun provenance

This directory is derived from BoringTun 0.7.1.

- crates.io archive: <https://crates.io/api/v1/crates/boringtun/0.7.1/download>
- archive SHA-256: `15dd6a8a89cbe8997f37ca0cf035e6ea4d64cd2ecea4aed83ffb9f99f7126939`
- upstream git revision: `051c9d47dc9c5cb36e461b7d36dcd673820dc98b`
- license: BSD-3-Clause; see `LICENSE`.

Local modifications are limited to `src/noise/mod.rs` and
`src/noise/session.rs` for the bounded inbound pipeline's opaque prepared and
opened receive capabilities.
