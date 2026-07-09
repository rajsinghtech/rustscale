//! macOS OS event source: AF_ROUTE socket with polling fallback.
//!
//! Ports Go's `net/netmon/netmon_darwin.go` (`darwinRouteMon`). Opens a
//! `PF_ROUTE` raw socket and reads route messages; any message signals a
//! potential network change. On read timeout (EAGAIN), also sends a signal
//! so the debounce loop periodically re-polls state — this catches changes
//! that don't generate route messages (e.g. DHCP lease expiry). If the
//! socket cannot be opened, falls back to a polling loop at `poll_interval`.

use std::sync::{atomic::AtomicBool, Arc};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Spawn the macOS OS event source on a blocking thread.
///
/// Tries to open an AF_ROUTE socket. On success, blocks on `read` with a
/// 1-second timeout so it can periodically check the `stopped` flag and
/// send a periodic poll signal. On failure, falls back to a polling loop
/// at `poll_interval`.
pub(crate) fn spawn_os_source(
    signal_tx: mpsc::Sender<()>,
    stopped: Arc<AtomicBool>,
    poll_interval: Duration,
) -> JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        let fd = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, 0) };
        if fd < 0 {
            eprintln!("netmon: AF_ROUTE socket failed; falling back to polling");
            polling_loop(signal_tx, &stopped, poll_interval);
            return;
        }

        let tv = libc::timeval {
            tv_sec: 1,
            tv_usec: 0,
        };
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                std::ptr::addr_of!(tv).cast::<libc::c_void>(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }

        let mut buf = vec![0u8; 2048];
        loop {
            if stopped.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
            if n < 0 {
                let errno = unsafe { *libc::__error() };
                if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                    let _ = signal_tx.try_send(());
                    continue;
                }
                if errno == libc::EINTR {
                    continue;
                }
                break;
            }
            if n > 0 {
                let _ = signal_tx.blocking_send(());
            }
        }
        unsafe {
            libc::close(fd);
        }
    })
}

/// Polling fallback: sleep `poll_interval`, send a signal, repeat.
fn polling_loop(signal_tx: mpsc::Sender<()>, stopped: &Arc<AtomicBool>, poll_interval: Duration) {
    loop {
        if stopped.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
        std::thread::sleep(poll_interval);
        if stopped.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
        let _ = signal_tx.try_send(());
    }
}
