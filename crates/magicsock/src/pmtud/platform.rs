//! Platform-specific DF bit control for PMTUD.
//!
//! Mirrors Go's peermtu_unix.go (connControl, getIPProto).

use std::os::fd::RawFd;

/// Error returned when the socket is not a real UDP socket (e.g. in tests
/// where the pconn is wrapped or the fd is invalid). Mirrors Go's
/// `errUnsupportedConnType`.
#[derive(Debug, thiserror::Error)]
#[error("unsupported connection type for PMTUD")]
pub(crate) struct UnsupportedConnType;

/// Run `f` with the raw fd of the socket. In Rust, `UdpSocket` implements
/// `AsRawFd`, so we can get the fd directly without the `SyscallConn`
/// indirection Go uses. Mirrors Go's `connControl()`.
pub(crate) fn conn_control(
    fd: RawFd,
    f: &mut impl FnMut(RawFd),
) -> Result<(), UnsupportedConnType> {
    if fd < 0 {
        return Err(UnsupportedConnType);
    }
    f(fd);
    Ok(())
}

/// Return the `IPPROTO_*` constant for the given network ("udp4" or "udp6").
/// Mirrors Go's `getIPProto`.
pub(crate) fn ip_proto(network: &str) -> i32 {
    if network == "udp4" {
        libc::IPPROTO_IP
    } else {
        libc::IPPROTO_IPV6
    }
}
