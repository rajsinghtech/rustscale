//! Best-effort UDP socket-buffer policy for magicsock direct paths.
//!
//! This mirrors Tailscale's `net/sockopts.SetBufferSize`: Linux first uses
//! the privileged force options, then falls back to the portable setter when
//! force is unavailable. Other platforms use the portable setter directly.

use std::io;

use socket2::SockRef;
use tokio::net::UdpSocket;

/// Tailscale's magicsock socket buffer request: 7 MiB.
pub(crate) const SOCKET_BUFFER_SIZE: usize = 7 << 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::enum_variant_names)]
enum BufferOutcome {
    #[cfg(target_os = "linux")]
    ForceSucceeded,
    #[cfg(target_os = "linux")]
    ForceFailedPortableSucceeded,
    #[cfg(target_os = "linux")]
    ForceAndPortableFailed,
    #[cfg(not(target_os = "linux"))]
    PortableSucceeded,
    #[cfg(not(target_os = "linux"))]
    PortableFailed,
}

impl BufferOutcome {
    const fn diagnostic_class(self) -> &'static str {
        match self {
            #[cfg(target_os = "linux")]
            Self::ForceSucceeded => "force_ok",
            #[cfg(target_os = "linux")]
            Self::ForceFailedPortableSucceeded => "force_failed_portable_ok",
            #[cfg(target_os = "linux")]
            Self::ForceAndPortableFailed => "force_failed_portable_failed",
            #[cfg(not(target_os = "linux"))]
            Self::PortableSucceeded => "portable_ok",
            #[cfg(not(target_os = "linux"))]
            Self::PortableFailed => "portable_failed",
        }
    }
}

/// Apply the policy and emit its one bounded, structured diagnostic. Failure
/// is intentionally non-fatal: platforms may clamp values or deny the Linux
/// force options without affecting socket usability.
pub(crate) fn configure(socket: &UdpSocket) {
    let recv = set_direction(socket, Direction::Receive);
    let send = set_direction(socket, Direction::Send);
    let socket = SockRef::from(socket);
    let actual_recv = socket.recv_buffer_size().ok();
    let actual_send = socket.send_buffer_size().ok();

    // Keep this single-line and value-only: it is captured by the benchmark
    // harness and must not expose descriptors, addresses, or credentials.
    eprintln!(
        "rustscale: magicsock_udp_socket_buffers requested={} recv_outcome={} send_outcome={} actual_recv={} actual_send={}",
        SOCKET_BUFFER_SIZE,
        recv.diagnostic_class(),
        send.diagnostic_class(),
        actual_recv.map_or_else(|| "unavailable".to_owned(), |size| size.to_string()),
        actual_send.map_or_else(|| "unavailable".to_owned(), |size| size.to_string()),
    );
}

#[derive(Clone, Copy)]
enum Direction {
    Receive,
    Send,
}

#[cfg(target_os = "linux")]
fn set_direction(socket: &UdpSocket, direction: Direction) -> BufferOutcome {
    apply_linux_policy(
        || set_force(socket, direction),
        || set_portable(socket, direction),
    )
}

#[cfg(not(target_os = "linux"))]
fn set_direction(socket: &UdpSocket, direction: Direction) -> BufferOutcome {
    if set_portable(socket, direction).is_ok() {
        BufferOutcome::PortableSucceeded
    } else {
        BufferOutcome::PortableFailed
    }
}

#[cfg(target_os = "linux")]
fn apply_linux_policy<E>(
    force: impl FnOnce() -> Result<(), E>,
    portable: impl FnOnce() -> Result<(), E>,
) -> BufferOutcome {
    if force().is_ok() {
        BufferOutcome::ForceSucceeded
    } else if portable().is_ok() {
        BufferOutcome::ForceFailedPortableSucceeded
    } else {
        BufferOutcome::ForceAndPortableFailed
    }
}

fn set_portable(socket: &UdpSocket, direction: Direction) -> io::Result<()> {
    let socket = SockRef::from(socket);
    match direction {
        Direction::Receive => socket.set_recv_buffer_size(SOCKET_BUFFER_SIZE),
        Direction::Send => socket.set_send_buffer_size(SOCKET_BUFFER_SIZE),
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn set_force(socket: &UdpSocket, direction: Direction) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let option = match direction {
        Direction::Receive => libc::SO_RCVBUFFORCE,
        Direction::Send => libc::SO_SNDBUFFORCE,
    };
    let size = SOCKET_BUFFER_SIZE as libc::c_int;
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            option,
            std::ptr::addr_of!(size).cast::<libc::c_void>(),
            std::mem::size_of_val(&size) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn linux_force_success_skips_portable_fallback() {
        let portable_calls = std::cell::Cell::new(0);
        let result = apply_linux_policy(
            || Ok::<_, ()>(()),
            || {
                portable_calls.set(portable_calls.get() + 1);
                Ok::<_, ()>(())
            },
        );
        assert_eq!(result, BufferOutcome::ForceSucceeded);
        assert_eq!(portable_calls.get(), 0);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn linux_force_failure_uses_successful_portable_fallback() {
        let portable_calls = std::cell::Cell::new(0);
        let result = apply_linux_policy(
            || Err::<(), _>(()),
            || {
                portable_calls.set(portable_calls.get() + 1);
                Ok::<_, ()>(())
            },
        );
        assert_eq!(result, BufferOutcome::ForceFailedPortableSucceeded);
        assert_eq!(portable_calls.get(), 1);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn linux_dual_failure_is_reported() {
        let result = apply_linux_policy(|| Err::<(), _>(()), || Err::<(), _>(()));
        assert_eq!(result, BufferOutcome::ForceAndPortableFailed);
    }

    #[tokio::test]
    async fn real_udp_socket_buffers_do_not_decrease() {
        let socket = match UdpSocket::bind("127.0.0.1:0").await {
            Ok(socket) => socket,
            // Some hermetic test sandboxes forbid socket creation. Native
            // Unix CI runs the assertions below against the real kernel.
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("magicsock test UDP socket buffers skipped: {error}");
                return;
            }
            Err(error) => panic!("bind real UDP socket: {error}"),
        };
        let socket = Arc::new(socket);
        let before = SockRef::from(socket.as_ref());
        let recv_before = before.recv_buffer_size().unwrap();
        let send_before = before.send_buffer_size().unwrap();

        configure(&socket);

        let after = SockRef::from(socket.as_ref());
        let recv_after = after.recv_buffer_size().unwrap();
        let send_after = after.send_buffer_size().unwrap();
        eprintln!("magicsock test UDP socket buffers: recv={recv_after} send={send_after}");
        assert!(recv_after >= recv_before);
        assert!(send_after >= send_before);
    }
}
