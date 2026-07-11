//! Interop harness: runs rustscale's tsnet client against Tailscale's real
//! Go testcontrol server to surface wire-format mismatches in local tests.
//!
//! The harness spawns `tools/testcontrol/bin/testcontrol` (built by
//! `tools/testcontrol/build.sh`), reads the control URL from stdout, then
//! creates tsnet [`Server`] instances pointed at it. Five scenarios exercise
//! registration, peer discovery, fake-node injection, key expiry, and raw
//! MapResponse injection (PeersRemoved).
//!
//! Tests skip gracefully if the binary or `go` toolchain is missing.

#![forbid(unsafe_code)]

/// All test infrastructure and test cases are gated behind `#[cfg(test)]`
/// because they are only exercised when `cargo test` runs the interop suite.
#[cfg(test)]
mod tests;
