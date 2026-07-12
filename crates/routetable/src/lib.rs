//! System route table enumeration for rustscale.
//!
//! Ports Go's `net/routetable` package. On macOS, fetches the kernel
//! routing table via the PF_ROUTE sysctl (`NET_RT_DUMP2`) and parses the
//! `rt_msghdr2` records and their trailing sockaddrs. On other platforms,
//! returns an `Unsupported` error so the workspace builds on Linux CI.
//!
//! # Unsafe
//!
//! This crate uses `unsafe` libc calls for `sysctl` and `if_indextoname`
//! on macOS. The `unsafe_code` lint is allowed via `Cargo.toml` (not
//! inherited from the workspace `forbid` policy).

mod parser;

#[cfg(target_os = "macos")]
mod darwin;

#[cfg(not(target_os = "macos"))]
mod stub;

use std::net::IpAddr;

pub use parser::RouteType;

/// The destination of a route — similar to an IP prefix but with an optional
/// IPv6 zone (interface name or numeric index).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteDestination {
    /// The destination IP address.
    pub addr: IpAddr,
    /// The prefix length (number of leading 1-bits in the netmask).
    pub bits: u8,
    /// The IPv6 zone (interface name or numeric index string), empty if none.
    pub zone: String,
}

/// An entry in the system route table.
///
/// Mirrors Go's `routetable.RouteEntry` + `RouteEntryBSD` (combined into a
/// single struct for the Rust API).
#[derive(Clone, Debug)]
pub struct RouteEntry {
    /// The IP family of the route: 4 or 6.
    pub family: u8,
    /// The type of this route.
    pub route_type: RouteType,
    /// The destination of the route.
    pub dst: RouteDestination,
    /// The gateway IP address, if the gateway is an IP address.
    pub gateway: Option<IpAddr>,
    /// The name of the gateway interface, if the gateway is a link-layer
    /// address (e.g. a `sockaddr_dl` pointing at an interface).
    pub gateway_iface: Option<String>,
    /// The name of the output interface for this route. May be empty if the
    /// interface index could not be resolved.
    pub iface: String,
    /// String representations of the route flags (sorted alphabetically).
    pub flags: Vec<String>,
    /// The raw OS-specific route flags.
    pub raw_flags: i32,
}

/// Fetch route entries from the system route table, limited to at most `max`
/// results.
///
/// On macOS, uses the PF_ROUTE sysctl (`NET_RT_DUMP2`). On other platforms,
/// returns an `Unsupported` error.
pub fn get_route_table(max: usize) -> std::io::Result<Vec<RouteEntry>> {
    #[cfg(target_os = "macos")]
    {
        darwin::get_route_table(max)
    }
    #[cfg(not(target_os = "macos"))]
    {
        stub::get_route_table(max)
    }
}
