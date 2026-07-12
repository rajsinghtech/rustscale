//! Subcommand implementations. Each module mirrors the corresponding Go
//! `cmd/tailscale/cli/*.go` source in output format and flag semantics.

pub mod down;
pub mod health;
pub mod ip;
pub mod metrics;
pub mod netcheck;
pub mod ping;
pub mod status;
pub mod version;
pub mod whois;
