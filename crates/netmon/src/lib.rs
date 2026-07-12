//! Network change monitor for rustscale.
//!
//! Ports the semantics of Go's `net/netmon` package. Detects network
//! interface and route changes (and wall-clock time jumps from sleep/wake)
//! so the data plane can re-gather endpoints, re-STUN, and reconnect DERP.
//!
//! - [`Monitor`] owns a [`State`] snapshot and a debounce loop.
//! - On macOS, an AF_ROUTE socket delivers events in real time; on Linux, a
//!   NETLINK_ROUTE socket subscribed to link/address/route multicast groups
//!   delivers events in real time; on other platforms a 10-second polling
//!   fallback is used.
//! - Wall-clock jumps (monotonic-vs-wall delta > 10 min) are treated as
//!   major changes (machine woke from sleep — NAT mappings are stale).
//!
//! # Unsafe
//!
//! This crate uses `unsafe` libc calls for the AF_ROUTE socket on macOS
//! and `getifaddrs`/`ioctl` for interface metadata. The `unsafe_code` lint
//! is allowed via `Cargo.toml` (not inherited from the workspace `forbid`
//! policy).

mod defaultroute;
mod interfaces;
mod monitor;
mod os;

#[cfg(target_os = "macos")]
mod os_darwin;

#[cfg(target_os = "linux")]
mod os_linux;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod os_poll;

mod state;

#[cfg(test)]
mod tests;

pub use defaultroute::default_route_interface_index;
pub use monitor::{
    ChangeCallbackHandle, ChangeDelta, Monitor, MonitorHandle, NetmonError, StateProvider,
};
pub use state::{
    default_route, default_route_interface, gather_state, get_interface_list, has_cgnat_interface,
    InterfaceEntry, InterfaceMeta, IpPrefix, LinkType, Route, State,
};
