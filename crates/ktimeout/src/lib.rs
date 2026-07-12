use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::Duration;

/// Sets the TCP user timeout (`TCP_USER_TIMEOUT` on Linux) on the given file
/// descriptor. The user timeout specifies the maximum age of unacknowledged
/// data on the connection before the connection is terminated. This timer has
/// no effect on limiting the lifetime of idle connections.
///
/// On Linux this calls `setsockopt(fd, SOL_TCP, TCP_USER_TIMEOUT, ...)`.
/// On other platforms this is a no-op that returns `Ok(())`.
///
/// # Errors
///
/// Returns `io::Error` if the underlying `setsockopt` call fails (Linux only).
pub fn set_user_timeout(fd: RawFd, timeout: Duration) -> io::Result<()> {
    set_user_timeout_impl(fd, timeout)
}

/// Returns a closure that applies [`set_user_timeout`] to a [`TcpStream`].
///
/// The returned closure calls `stream.as_raw_fd()` to obtain the file
/// descriptor and passes it to `set_user_timeout`.
///
/// # Errors
///
/// Returns `io::Error` if the underlying `setsockopt` call fails (Linux only).
pub fn user_timeout_control(timeout: Duration) -> impl Fn(&std::net::TcpStream) -> io::Result<()> {
    move |stream: &std::net::TcpStream| set_user_timeout(stream.as_raw_fd(), timeout)
}

// ---------------------------------------------------------------------------
// Linux — setsockopt SOL_TCP / TCP_USER_TIMEOUT
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn set_user_timeout_impl(fd: RawFd, timeout: Duration) -> io::Result<()> {
    let timeout_ms: libc::c_int = timeout.as_millis().try_into().unwrap_or(libc::c_int::MAX);
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_TCP,
            libc::TCP_USER_TIMEOUT,
            &timeout_ms as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Non-Linux — no-op
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "linux"))]
fn set_user_timeout_impl(_fd: RawFd, _timeout: Duration) -> io::Result<()> {
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    #[test]
    fn test_set_user_timeout_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = TcpStream::connect(addr).unwrap();
        let _accepted = listener.accept().unwrap();

        set_user_timeout(stream.as_raw_fd(), Duration::from_secs(30)).unwrap();
        set_user_timeout(stream.as_raw_fd(), Duration::ZERO).unwrap();
    }

    #[test]
    fn test_user_timeout_control() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = TcpStream::connect(addr).unwrap();
        let _accepted = listener.accept().unwrap();

        let ctrl = user_timeout_control(Duration::from_secs(30));
        ctrl(&stream).unwrap();
    }
}
