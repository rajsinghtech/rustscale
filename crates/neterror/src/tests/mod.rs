use std::io;

use crate::{is_closed_pipe_error, treat_as_lost_udp, NetError};

// ---------------------------------------------------------------------------
// From<io::ErrorKind>
// ---------------------------------------------------------------------------

#[test]
fn from_error_kind_timeout() {
    assert_eq!(NetError::from(io::ErrorKind::TimedOut), NetError::Timeout);
}

#[test]
fn from_error_kind_refused() {
    assert_eq!(
        NetError::from(io::ErrorKind::ConnectionRefused),
        NetError::Refused
    );
}

#[test]
fn from_error_kind_reset() {
    assert_eq!(
        NetError::from(io::ErrorKind::ConnectionReset),
        NetError::Reset
    );
}

#[test]
fn from_error_kind_broken_pipe() {
    assert_eq!(
        NetError::from(io::ErrorKind::BrokenPipe),
        NetError::BrokenPipe
    );
}

#[test]
fn from_error_kind_not_connected() {
    assert_eq!(
        NetError::from(io::ErrorKind::NotConnected),
        NetError::NotConnected
    );
}

#[test]
fn from_error_kind_addr_in_use() {
    assert_eq!(
        NetError::from(io::ErrorKind::AddrInUse),
        NetError::AddrInUse
    );
}

#[test]
fn from_error_kind_addr_not_available() {
    assert_eq!(
        NetError::from(io::ErrorKind::AddrNotAvailable),
        NetError::AddrNotAvailable
    );
}

#[test]
fn from_error_kind_permission_denied() {
    assert_eq!(
        NetError::from(io::ErrorKind::PermissionDenied),
        NetError::PermissionDenied
    );
}

#[test]
fn from_error_kind_interrupted() {
    assert_eq!(
        NetError::from(io::ErrorKind::Interrupted),
        NetError::Interrupted
    );
}

#[test]
fn from_error_kind_would_block() {
    assert_eq!(
        NetError::from(io::ErrorKind::WouldBlock),
        NetError::WouldBlock
    );
}

#[test]
fn from_error_kind_other() {
    let err = NetError::from(io::ErrorKind::Other);
    assert!(matches!(err, NetError::Other(_)));
    assert_eq!(err.kind(), "other");
}

#[test]
fn from_error_kind_write_zero() {
    let err = NetError::from(io::ErrorKind::WriteZero);
    assert!(matches!(err, NetError::Other(_)));
}

// ---------------------------------------------------------------------------
// From<io::Error> — ErrorKind-based
// ---------------------------------------------------------------------------

#[test]
fn from_io_error_timeout() {
    let e = io::Error::new(io::ErrorKind::TimedOut, "timed out");
    assert_eq!(NetError::from(e), NetError::Timeout);
}

#[test]
fn from_io_error_refused() {
    let e = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
    assert_eq!(NetError::from(e), NetError::Refused);
}

#[test]
fn from_io_error_reset() {
    let e = io::Error::new(io::ErrorKind::ConnectionReset, "reset");
    assert_eq!(NetError::from(e), NetError::Reset);
}

#[test]
fn from_io_error_other() {
    let e = io::Error::other("something else");
    let err = NetError::from(e);
    assert!(matches!(err, NetError::Other(_)));
    assert_eq!(err.kind(), "other");
}

// ---------------------------------------------------------------------------
// OS error code mapping (Unix-only)
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod unix_tests {
    use std::io;

    use crate::NetError;

    fn make_os_error(raw: i32) -> io::Error {
        io::Error::from_raw_os_error(raw)
    }

    #[test]
    fn os_etimedout() {
        assert_eq!(
            NetError::from(make_os_error(libc::ETIMEDOUT)),
            NetError::Timeout
        );
    }

    #[test]
    fn os_econnrefused() {
        assert_eq!(
            NetError::from(make_os_error(libc::ECONNREFUSED)),
            NetError::Refused
        );
    }

    #[test]
    fn os_econnreset() {
        assert_eq!(
            NetError::from(make_os_error(libc::ECONNRESET)),
            NetError::Reset
        );
    }

    #[test]
    fn os_ehostunreach() {
        assert_eq!(
            NetError::from(make_os_error(libc::EHOSTUNREACH)),
            NetError::HostUnreachable
        );
    }

    #[test]
    fn os_enetunreach() {
        assert_eq!(
            NetError::from(make_os_error(libc::ENETUNREACH)),
            NetError::NetUnreachable
        );
    }

    #[test]
    fn os_epipe() {
        assert_eq!(
            NetError::from(make_os_error(libc::EPIPE)),
            NetError::BrokenPipe
        );
    }

    #[test]
    fn os_enotconn() {
        assert_eq!(
            NetError::from(make_os_error(libc::ENOTCONN)),
            NetError::NotConnected
        );
    }

    #[test]
    fn os_eaddrinuse() {
        assert_eq!(
            NetError::from(make_os_error(libc::EADDRINUSE)),
            NetError::AddrInUse
        );
    }

    #[test]
    fn os_eaddrnotavail() {
        assert_eq!(
            NetError::from(make_os_error(libc::EADDRNOTAVAIL)),
            NetError::AddrNotAvailable
        );
    }

    #[test]
    fn os_eacces() {
        assert_eq!(
            NetError::from(make_os_error(libc::EACCES)),
            NetError::PermissionDenied
        );
    }

    #[test]
    fn os_eperm() {
        assert_eq!(
            NetError::from(make_os_error(libc::EPERM)),
            NetError::PermissionDenied
        );
    }

    #[test]
    fn os_eintr() {
        assert_eq!(
            NetError::from(make_os_error(libc::EINTR)),
            NetError::Interrupted
        );
    }

    #[test]
    fn os_ewouldblock() {
        assert_eq!(
            NetError::from(make_os_error(libc::EWOULDBLOCK)),
            NetError::WouldBlock
        );
    }

    #[test]
    fn os_eagain() {
        // EAGAIN == EWOULDBLOCK on POSIX; both must map to WouldBlock.
        let err = NetError::from(make_os_error(libc::EAGAIN));
        assert_eq!(err, NetError::WouldBlock);
    }

    #[test]
    fn os_unknown() {
        let err = NetError::from(make_os_error(9999));
        assert!(matches!(err, NetError::Other(_)));
        // kind() works for Other too
        assert_eq!(err.kind(), "other");
    }

    #[test]
    fn os_unknown_display() {
        let err = NetError::from(make_os_error(9999));
        let msg = err.to_string();
        // The message depends on how std formats the raw OS error;
        // just verify it's an Other variant with a non-empty string.
        assert!(!msg.is_empty(), "got empty message");
        assert_eq!(err.kind(), "other");
    }
}

// ---------------------------------------------------------------------------
// NetError methods
// ---------------------------------------------------------------------------

#[test]
fn kind_labels() {
    assert_eq!(NetError::Timeout.kind(), "timeout");
    assert_eq!(NetError::Refused.kind(), "refused");
    assert_eq!(NetError::Reset.kind(), "reset");
    assert_eq!(NetError::HostUnreachable.kind(), "host_unreachable");
    assert_eq!(NetError::NetUnreachable.kind(), "net_unreachable");
    assert_eq!(NetError::BrokenPipe.kind(), "broken_pipe");
    assert_eq!(NetError::NotConnected.kind(), "not_connected");
    assert_eq!(NetError::AddrInUse.kind(), "addr_in_use");
    assert_eq!(NetError::AddrNotAvailable.kind(), "addr_not_available");
    assert_eq!(NetError::PermissionDenied.kind(), "permission_denied");
    assert_eq!(NetError::Interrupted.kind(), "interrupted");
    assert_eq!(NetError::WouldBlock.kind(), "would_block");
    assert_eq!(NetError::Other("x".into()).kind(), "other");
}

#[test]
fn is_timeout() {
    assert!(NetError::Timeout.is_timeout());
    assert!(!NetError::Refused.is_timeout());
}

#[test]
fn is_refused() {
    assert!(NetError::Refused.is_refused());
    assert!(!NetError::Timeout.is_refused());
}

#[test]
fn is_reset() {
    assert!(NetError::Reset.is_reset());
    assert!(!NetError::Timeout.is_reset());
}

#[test]
fn should_retry_timeout() {
    assert!(NetError::Timeout.should_retry());
}

#[test]
fn should_retry_refused() {
    assert!(NetError::Refused.should_retry());
}

#[test]
fn should_retry_reset() {
    assert!(NetError::Reset.should_retry());
}

#[test]
fn should_not_retry_host_unreachable() {
    assert!(!NetError::HostUnreachable.should_retry());
}

#[test]
fn should_not_retry_net_unreachable() {
    assert!(!NetError::NetUnreachable.should_retry());
}

#[test]
fn should_not_retry_broken_pipe() {
    assert!(!NetError::BrokenPipe.should_retry());
}

#[test]
fn should_not_retry_not_connected() {
    assert!(!NetError::NotConnected.should_retry());
}

#[test]
fn should_not_retry_other() {
    assert!(!NetError::Other("x".into()).should_retry());
}

// ---------------------------------------------------------------------------
// Display (via thiserror)
// ---------------------------------------------------------------------------

#[test]
fn display_variants() {
    assert_eq!(NetError::Timeout.to_string(), "timeout");
    assert_eq!(NetError::Refused.to_string(), "refused");
    assert_eq!(NetError::Reset.to_string(), "reset");
    assert_eq!(NetError::Other("custom".into()).to_string(), "custom");
}

// ---------------------------------------------------------------------------
// Clone + PartialEq
// ---------------------------------------------------------------------------

#[test]
fn clone_and_eq() {
    let a = NetError::Timeout;
    let b = a.clone();
    assert_eq!(a, b);

    let c = NetError::Other("msg".into());
    let d = c.clone();
    assert_eq!(c, d);
    assert_ne!(a, c);
}

// ---------------------------------------------------------------------------
// Debug
// ---------------------------------------------------------------------------

#[test]
fn debug_format() {
    let s = format!("{:?}", NetError::Timeout);
    assert_eq!(s, "Timeout");
}

// ---------------------------------------------------------------------------
// Go-package utility functions
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn test_treat_as_lost_udp_eperm() {
    let e = io::Error::from_raw_os_error(libc::EPERM);
    assert!(treat_as_lost_udp(&e));
}

#[cfg(target_os = "linux")]
#[test]
fn test_treat_as_lost_udp_other() {
    let e = io::Error::from_raw_os_error(libc::EHOSTUNREACH);
    assert!(!treat_as_lost_udp(&e));
}

#[cfg(not(target_os = "linux"))]
#[test]
fn test_treat_as_lost_udp_always_false() {
    let e = io::Error::new(io::ErrorKind::PermissionDenied, "test");
    assert!(!treat_as_lost_udp(&e));
}

#[test]
fn test_packet_was_truncated() {
    // Always false on non-Windows; on Windows only for WSAEMSGSIZE.
    let e = io::Error::other("test");
    assert!(!crate::packet_was_truncated(&e));
}

#[test]
fn test_should_disable_udp_gso() {
    let e = io::Error::other("test");
    assert!(!crate::should_disable_udp_gso(&e));
}

#[test]
fn test_udp_gso_disabled_error() {
    let err = crate::ErrUdpGsoDisabled::new("0.0.0.0:1234", None);
    let msg = err.to_string();
    assert!(msg.contains("disabled UDP GSO on"));
    assert!(msg.contains("0.0.0.0:1234"));
}

#[test]
fn test_udp_gso_disabled_with_retry() {
    let err = crate::ErrUdpGsoDisabled::new("0.0.0.0:1234", Some("EIO".into()));
    assert_eq!(err.retry_err.as_deref(), Some("EIO"));
}

#[test]
fn test_is_closed_pipe_error_broken_pipe() {
    let e = io::Error::new(io::ErrorKind::BrokenPipe, "broken pipe");
    assert!(is_closed_pipe_error(&e));
}

#[test]
fn test_is_closed_pipe_error_not_connected() {
    let e = io::Error::new(io::ErrorKind::NotConnected, "not connected");
    assert!(is_closed_pipe_error(&e));
}

#[test]
fn test_is_closed_pipe_error_other() {
    let e = io::Error::other("other");
    assert!(!is_closed_pipe_error(&e));
}

#[cfg(unix)]
#[test]
fn test_is_closed_pipe_error_epipe() {
    let e = io::Error::from_raw_os_error(libc::EPIPE);
    assert!(is_closed_pipe_error(&e));
}

#[cfg(unix)]
#[test]
fn test_is_closed_pipe_error_enotconn() {
    let e = io::Error::from_raw_os_error(libc::ENOTCONN);
    assert!(is_closed_pipe_error(&e));
}

// ---------------------------------------------------------------------------
// Round-trip: OS error -> NetError -> Display -> kind
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn round_trip_error_consistency() {
    let cases = [
        (libc::ETIMEDOUT, "timeout"),
        (libc::ECONNREFUSED, "refused"),
        (libc::ECONNRESET, "reset"),
        (libc::EHOSTUNREACH, "host_unreachable"),
        (libc::ENETUNREACH, "net_unreachable"),
        (libc::EPIPE, "broken_pipe"),
        (libc::ENOTCONN, "not_connected"),
        (libc::EADDRINUSE, "addr_in_use"),
        (libc::EADDRNOTAVAIL, "addr_not_available"),
        (libc::EPERM, "permission_denied"),
    ];

    for (raw, expected_kind) in &cases {
        let err = io::Error::from_raw_os_error(*raw);
        let net_err = NetError::from(err);
        assert_eq!(
            net_err.kind(),
            *expected_kind,
            "mismatch for raw_os_error {raw}"
        );
        assert_eq!(net_err.to_string(), *expected_kind);
    }
}
