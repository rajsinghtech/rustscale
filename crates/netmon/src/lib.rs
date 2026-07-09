//! Network change monitor for rustscale.
//!
//! Ports the semantics of Go's `net/netmon` package. Detects network
//! interface and route changes (and wall-clock time jumps from sleep/wake)
//! so the data plane can re-gather endpoints, re-STUN, and reconnect DERP.
//!
//! - [`Monitor`] owns a [`State`] snapshot and a debounce loop.
//! - On macOS, an AF_ROUTE socket delivers events in real time; on other
//!   platforms a 10-second polling fallback is used.
//! - Wall-clock jumps (>60s elapsed between checks) are treated as major
//!   changes (machine woke from sleep — NAT mappings are stale).
//!
//! # Unsafe
//!
//! This crate uses `unsafe` libc calls for the AF_ROUTE socket on macOS.
//! The `unsafe_code` lint is allowed via `Cargo.toml` (not inherited from
//! the workspace `forbid` policy).

mod monitor;
mod os;

#[cfg(target_os = "macos")]
mod os_darwin;

#[cfg(not(target_os = "macos"))]
mod os_poll;

mod state;

#[cfg(test)]
mod tests;

pub use monitor::{ChangeDelta, Monitor, MonitorHandle, NetmonError, StateProvider};
pub use state::{default_route_interface, gather_state, InterfaceMeta, IpPrefix, State};
