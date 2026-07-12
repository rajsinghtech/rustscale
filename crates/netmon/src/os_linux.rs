//! Linux OS event source: NETLINK_ROUTE socket with polling fallback.
//!
//! Ports Go's `net/netmon/netmon_linux.go` (`newOSMon` / `nlConn.Receive`).
//! Opens a `NETLINK_ROUTE` socket subscribed to link, address, and route
//! multicast groups. Any netlink message signals a potential network change.
//! On read timeout (EAGAIN), also sends a periodic poll signal so the debounce
//! loop can catch changes that don't generate netlink messages. If the socket
//! cannot be opened (e.g. Google Cloud Run), falls back to polling.
//!
//! # Unsafe
//!
//! Uses raw libc syscalls (`socket`, `bind`, `recv`, `close`, `setsockopt`).
//! The `unsafe_code` lint is allowed via `Cargo.toml` for this crate.

use std::sync::{atomic::AtomicBool, Arc};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

// Netlink multicast groups — from <linux/rtnetlink.h>. These are not exposed
// by the `libc` crate on all targets, so we define them locally.
const RTMGRP_LINK: u32 = 1;
const RTMGRP_IPV4_IFADDR: u32 = 0x10;
const RTMGRP_IPV4_ROUTE: u32 = 0x40;
const RTMGRP_IPV6_IFADDR: u32 = 0x100;
const RTMGRP_IPV6_ROUTE: u32 = 0x400;

/// Spawn the Linux OS event source on a blocking thread.
///
/// Tries to open a `NETLINK_ROUTE` socket subscribed to link/address/route
/// multicast groups. On success, blocks on `recv` with a 1-second timeout so
/// it can periodically check the `stopped` flag and send a periodic poll
/// signal. On failure, falls back to a polling loop at `poll_interval`.
pub(crate) fn spawn_os_source(
    signal_tx: mpsc::Sender<()>,
    stopped: Arc<AtomicBool>,
    poll_interval: Duration,
) -> JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        let groups = RTMGRP_LINK
            | RTMGRP_IPV4_IFADDR
            | RTMGRP_IPV6_IFADDR
            | RTMGRP_IPV4_ROUTE
            | RTMGRP_IPV6_ROUTE;

        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
        if fd < 0 {
            eprintln!("netmon: NETLINK_ROUTE socket failed; falling back to polling");
            polling_loop(signal_tx, &stopped, poll_interval);
            return;
        }

        // Bind to the multicast groups. nl_pid = 0 means the kernel assigns
        // the pid (appropriate for a multicast listener).
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        addr.nl_groups = groups;

        let ret = unsafe {
            libc::bind(
                fd,
                std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            eprintln!("netmon: NETLINK_ROUTE bind failed; falling back to polling");
            unsafe {
                libc::close(fd);
            }
            polling_loop(signal_tx, &stopped, poll_interval);
            return;
        }

        // 1-second receive timeout so we can check `stopped` periodically.
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

        let mut buf = vec![0u8; 4096];
        loop {
            if stopped.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }
            let n =
                unsafe { libc::recv(fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len(), 0) };
            if n < 0 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
                    // Timeout — send a periodic poll signal.
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
