//! Non-macOS stub: returns an `Unsupported` error.
//!
//! The workspace must build on Linux CI. A real Linux implementation
//! would parse `/proc/net/route` and `/proc/net/ipv6_route`.

use std::io;

use crate::RouteEntry;

pub(crate) fn get_route_table(_max: usize) -> io::Result<Vec<RouteEntry>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "get_route_table is only implemented on macOS",
    ))
}
