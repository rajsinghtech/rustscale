#![forbid(unsafe_code)]

//! Network error classification — a typed enum wrapping [`io::Error`] for
//! retry/diagnostics logic.
//!
//! Ports `tailscale.com/net/neterror`.

use std::io;

/// Classified network error variants.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum NetError {
    #[error("timeout")]
    Timeout,
    #[error("refused")]
    Refused,
    #[error("reset")]
    Reset,
    #[error("host_unreachable")]
    HostUnreachable,
    #[error("net_unreachable")]
    NetUnreachable,
    #[error("broken_pipe")]
    BrokenPipe,
    #[error("not_connected")]
    NotConnected,
    #[error("addr_in_use")]
    AddrInUse,
    #[error("addr_not_available")]
    AddrNotAvailable,
    #[error("permission_denied")]
    PermissionDenied,
    #[error("interrupted")]
    Interrupted,
    #[error("would_block")]
    WouldBlock,
    #[error("{0}")]
    Other(String),
}

impl NetError {
    /// Human-readable label for display/logging.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Refused => "refused",
            Self::Reset => "reset",
            Self::HostUnreachable => "host_unreachable",
            Self::NetUnreachable => "net_unreachable",
            Self::BrokenPipe => "broken_pipe",
            Self::NotConnected => "not_connected",
            Self::AddrInUse => "addr_in_use",
            Self::AddrNotAvailable => "addr_not_available",
            Self::PermissionDenied => "permission_denied",
            Self::Interrupted => "interrupted",
            Self::WouldBlock => "would_block",
            Self::Other(_) => "other",
        }
    }

    /// Returns `true` if this is a timeout.
    #[must_use]
    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Timeout)
    }

    /// Returns `true` if this is a connection refused.
    #[must_use]
    pub fn is_refused(&self) -> bool {
        matches!(self, Self::Refused)
    }

    /// Returns `true` if this is a connection reset.
    #[must_use]
    pub fn is_reset(&self) -> bool {
        matches!(self, Self::Reset)
    }

    /// Returns `true` for errors where retrying the operation may succeed.
    ///
    /// Timeout, refused, and reset are generally retryable; host/network
    /// unreachable may be transient but are not classified as retryable here
    /// (consistent with Go's use in magicsock).
    #[must_use]
    pub fn should_retry(&self) -> bool {
        matches!(self, Self::Timeout | Self::Refused | Self::Reset)
    }
}

/// Classify a raw OS error code (Unix `errno`) into a [`NetError`] variant.
///
/// On non-Unix platforms this always returns [`NetError::Other`].
#[cfg(unix)]
fn classify_os_error(code: i32) -> NetError {
    match code {
        libc::ETIMEDOUT => NetError::Timeout,
        libc::ECONNREFUSED => NetError::Refused,
        libc::ECONNRESET => NetError::Reset,
        libc::EHOSTUNREACH => NetError::HostUnreachable,
        libc::ENETUNREACH => NetError::NetUnreachable,
        libc::EPIPE => NetError::BrokenPipe,
        libc::ENOTCONN => NetError::NotConnected,
        libc::EADDRINUSE => NetError::AddrInUse,
        libc::EADDRNOTAVAIL => NetError::AddrNotAvailable,
        libc::EACCES | libc::EPERM => NetError::PermissionDenied,
        libc::EINTR => NetError::Interrupted,
        // POSIX defines EWOULDBLOCK == EAGAIN; only match EWOULDBLOCK.
        libc::EWOULDBLOCK => NetError::WouldBlock,
        _ => NetError::Other(format!("os_error_{code}")),
    }
}

#[cfg(not(unix))]
fn classify_os_error(_code: i32) -> NetError {
    NetError::Other("os_error".into())
}

/// Classify a raw OS error code (Windows) into a [`NetError`] variant.
#[cfg(windows)]
fn classify_wsa_error(code: i32) -> NetError {
    // Winsock error codes (WSA prefix) — these are distinct from general
    // Windows error codes; the WSAGetLastError / GetLastError mapping is
    // handled by std at the ErrorKind level, so we only hit these as a
    // fallback when std maps to ErrorKind::Other.
    match code {
        10_060 => NetError::Timeout,          // WSAETIMEDOUT
        10_061 => NetError::Refused,          // WSAECONNREFUSED
        10_054 => NetError::Reset,            // WSAECONNRESET
        10_070 => NetError::HostUnreachable,  // WSAEHOSTUNREACH
        10_065 => NetError::NetUnreachable,   // WSAENETUNREACH
        10_048 => NetError::AddrInUse,        // WSAEADDRINUSE
        10_049 => NetError::AddrNotAvailable, // WSAEADDRNOTAVAIL
        10_057 => NetError::NotConnected,     // WSAENOTCONN
        _ => NetError::Other(format!("wsa_error_{code}")),
    }
}

impl From<io::Error> for NetError {
    fn from(err: io::Error) -> Self {
        // First try raw OS error for codes std doesn't map to its own ErrorKind.
        if let Some(raw) = err.raw_os_error() {
            let classified = classify_os_error(raw);
            // If classify_os_error returned Other, still check ErrorKind first.
            if !matches!(classified, NetError::Other(_)) {
                return classified;
            }
        }

        match err.kind() {
            io::ErrorKind::TimedOut => Self::Timeout,
            io::ErrorKind::ConnectionRefused => Self::Refused,
            io::ErrorKind::ConnectionReset => Self::Reset,
            io::ErrorKind::BrokenPipe => Self::BrokenPipe,
            io::ErrorKind::NotConnected => Self::NotConnected,
            io::ErrorKind::AddrInUse => Self::AddrInUse,
            io::ErrorKind::AddrNotAvailable => Self::AddrNotAvailable,
            io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            io::ErrorKind::Interrupted => Self::Interrupted,
            io::ErrorKind::WouldBlock => Self::WouldBlock,
            _ => {
                // Last resort: try raw OS error on non-Unix.
                #[cfg(windows)]
                if let Some(raw) = err.raw_os_error() {
                    return classify_wsa_error(raw);
                }

                Self::Other(err.to_string())
            }
        }
    }
}

impl From<io::ErrorKind> for NetError {
    fn from(kind: io::ErrorKind) -> Self {
        match kind {
            io::ErrorKind::TimedOut => Self::Timeout,
            io::ErrorKind::ConnectionRefused => Self::Refused,
            io::ErrorKind::ConnectionReset => Self::Reset,
            io::ErrorKind::BrokenPipe => Self::BrokenPipe,
            io::ErrorKind::NotConnected => Self::NotConnected,
            io::ErrorKind::AddrInUse => Self::AddrInUse,
            io::ErrorKind::AddrNotAvailable => Self::AddrNotAvailable,
            io::ErrorKind::PermissionDenied => Self::PermissionDenied,
            io::ErrorKind::Interrupted => Self::Interrupted,
            io::ErrorKind::WouldBlock => Self::WouldBlock,
            _ => Self::Other(format!("{kind}")),
        }
    }
}

// ---------------------------------------------------------------------------
// Go-package utility functions
// ---------------------------------------------------------------------------

/// Returns `true` if `err` is an `EPERM` error on Linux, indicating that a UDP
/// send was blocked by an outbound firewall rule (`-j DROP` / `-j REJECT`).
///
/// Such "errors" are not really send failures — the packet was simply discarded
/// by the local kernel and should be treated as a lost UDP datagram.
#[cfg(target_os = "linux")]
#[must_use]
pub fn treat_as_lost_udp(err: &io::Error) -> bool {
    err.raw_os_error() == Some(libc::EPERM)
}

/// Stub: on non-Linux, this always returns `false`.
#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn treat_as_lost_udp(_err: &io::Error) -> bool {
    false
}

/// Returns `true` if `err` indicates that a UDP datagram was received but
/// truncated (buffer too small). On Windows this corresponds to
/// `WSAEMSGSIZE`; on POSIX systems truncated datagrams are silently
/// discarded at the kernel level so this always returns `false`.
#[cfg(windows)]
#[must_use]
pub fn packet_was_truncated(err: &io::Error) -> bool {
    err.raw_os_error() == Some(10_040) // WSAEMSGSIZE
}

#[cfg(not(windows))]
#[must_use]
pub fn packet_was_truncated(_err: &io::Error) -> bool {
    false
}

/// Returns `true` if `err` indicates that UDP segmentation offload (GSO)
/// should be disabled — on Linux this is `EIO` from `sendmsg` with
/// `UDP_SEGMENT`, meaning the NIC does not support tx checksum offload.
#[cfg(target_os = "linux")]
#[must_use]
pub fn should_disable_udp_gso(err: &io::Error) -> bool {
    err.raw_os_error() == Some(libc::EIO)
}

#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn should_disable_udp_gso(_err: &io::Error) -> bool {
    false
}

/// An error indicating that UDP GSO was disabled at runtime, typically after
/// a send failed with `EIO` on a NIC that does not support tx checksum offload.
#[derive(Debug, Clone)]
pub struct ErrUdpGsoDisabled {
    pub on_laddr: String,
    pub retry_err: Option<String>,
}

impl ErrUdpGsoDisabled {
    #[must_use]
    pub fn new(on_laddr: impl Into<String>, retry_err: Option<String>) -> Self {
        Self {
            on_laddr: on_laddr.into(),
            retry_err,
        }
    }
}

impl std::fmt::Display for ErrUdpGsoDisabled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "disabled UDP GSO on {}, NIC(s) may not support checksum offload",
            self.on_laddr
        )
    }
}

impl std::error::Error for ErrUdpGsoDisabled {}

/// Returns `true` if `err` resulted from reading or writing to a closed or
/// broken pipe. On Unix this catches `EPIPE` and `ENOTCONN`; on Windows it
/// also catches `ERROR_NO_DATA` (232). Also matches `io::ErrorKind::BrokenPipe`
/// and `io::ErrorKind::NotConnected`.
#[must_use]
pub fn is_closed_pipe_error(err: &io::Error) -> bool {
    if matches!(
        err.kind(),
        io::ErrorKind::BrokenPipe | io::ErrorKind::NotConnected
    ) {
        return true;
    }
    if let Some(raw) = err.raw_os_error() {
        #[cfg(windows)]
        if raw == 232 {
            return true; // ERROR_NO_DATA
        }
        #[cfg(unix)]
        if raw == libc::EPIPE || raw == libc::ENOTCONN {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests;
