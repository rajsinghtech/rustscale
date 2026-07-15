//! System dial path — outbound-to-internet connections (control plane, DERPs,
//! upstream DNS). Uses `netns::dial_tcp` for proxy/SOCKS/bind-to-interface,
//! and tracks in-flight dials for link-change teardown.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use tokio::net::TcpStream;

use crate::dns_map::split_host_port;

/// Registry of active system connections for link-change teardown.
///
/// V1: tracks in-flight dial count. On link change, [`close_all`] is called
/// (currently a no-op — the streams are owned by callers; a future `SysConn`
/// wrapper with a shutdown channel would allow forcibly closing them).
pub(crate) struct ActiveConns {
    inner: Mutex<HashMap<u64, ()>>,
    next_id: AtomicU64,
}

impl ActiveConns {
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(0),
        }
    }

    /// Register an in-flight dial. Returns its assigned ID.
    pub(crate) fn register(&self) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.inner.lock().expect("active_conns lock").insert(id, ());
        id
    }

    /// Unregister a completed dial.
    pub(crate) fn unregister(&self, id: u64) {
        self.inner.lock().expect("active_conns lock").remove(&id);
    }

    /// Close all tracked connections. V1: clears the registry. The actual
    /// streams are owned by callers and cannot be forcibly closed without a
    /// `SysConn` wrapper (future work).
    pub(crate) fn close_all(&self) {
        self.inner.lock().expect("active_conns lock").clear();
    }

    /// Number of tracked connections.
    pub(crate) fn len(&self) -> usize {
        self.inner.lock().expect("active_conns lock").len()
    }
}

/// Dial a system-level TCP connection, tracking the dial in `active`.
pub(crate) async fn system_dial_tracked(
    active: &ActiveConns,
    network: &str,
    addr: &str,
) -> std::io::Result<TcpStream> {
    if !is_tcp_network(network) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unsupported network: {network}"),
        ));
    }
    let id = active.register();
    let result = dial_addr(addr).await;
    active.unregister(id);
    result
}

/// Dial a system-level TCP connection without tracking. Used by the global
/// free function and by call sites that don't have a `Dialer` instance.
pub async fn system_dial_untracked(network: &str, addr: &str) -> std::io::Result<TcpStream> {
    if !is_tcp_network(network) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unsupported network: {network}"),
        ));
    }
    dial_addr(addr).await
}

fn is_tcp_network(network: &str) -> bool {
    matches!(network, "tcp" | "tcp4" | "tcp6")
}

async fn dial_addr(addr: &str) -> std::io::Result<TcpStream> {
    // Always go through dial_tcp (not dial_tcp_addr) so that localhost
    // detection and SOCKS proxy handling work correctly. dial_tcp_addr
    // skips the is_localhost check, which causes interface-binding failures
    // when connecting to 127.0.0.1 with netns enabled.
    if let Some((host, port)) = split_host_port(addr) {
        return rustscale_netns::dial_system_tcp(&host, port).await;
    }
    // Fallback: let tokio resolve it directly.
    tokio::net::TcpStream::connect(addr).await
}
