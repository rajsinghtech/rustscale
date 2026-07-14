#[allow(clippy::wildcard_imports)]
use super::*;

/// Configuration for TUN-mode operation ([`Server::up_tun`]).
///
/// In TUN mode the server routes plaintext IP packets between a real OS TUN
/// device and the WireGuard/magicsock data plane, instead of an in-process
/// userspace netstack. `listen`/`dial` are unavailable in this mode.
#[derive(Clone, Debug, Default)]
pub struct TunModeConfig {
    /// TUN device parameters (name hint + MTU). On macOS the default name
    /// `"utun"` auto-selects a unit.
    pub tun: rustscale_tun::TunConfig,
    /// If true, bring the interface up and add tailnet routes on macOS via
    /// `ifconfig`/`route`. **Requires root.** Default `false`, in which case
    /// you must configure the interface and routes yourself (or rely on the
    /// data-plane pump alone for in-process traffic).
    pub apply_routes: bool,
    /// If set, select this peer as the exit node at startup. The value is a
    /// tailnet IP or MagicDNS hostname, resolved against the netmap after the
    /// first `MapResponse`. The peer must be exit-node-capable (`AllowedIPs`
    /// containing `0.0.0.0/0`); otherwise `up_tun` returns an error.
    ///
    /// When `apply_routes` is also true, OS-level default-route overrides are
    /// installed so that all non-tailnet traffic enters the TUN device:
    /// - **macOS**: two `/1` routes (`0.0.0.0/1` + `128.0.0.0/1`) pointing at
    ///   the utun, which together cover all of IPv4 and are more specific than
    ///   the default route — mirroring how `tailscaled` overrides the default
    ///   without deleting it. IPv6 uses `::/1` + `8000::/1`.
    /// - **Linux**: `ip route add 0.0.0.0/0 dev <tun>` and `::/0 dev <tun>`
    ///   (best-effort; may conflict with an existing default route).
    ///
    /// **Known limitation (TUN + exit node):** magicsock's UDP socket is bound
    /// to `0.0.0.0` and sends DERP/control/peer-discovery traffic via the OS
    /// routing table. With `/1` exit routes installed, that traffic enters the
    /// TUN and would loop back through the exit node. rustscale does **not**
    /// yet install bypass routes (host routes for DERP/control IPs via the
    /// physical gateway) like the Go client does. For exit-node usage without
    /// this limitation, use netstack mode ([`Server::up`] +
    /// [`Server::set_exit_node`]), which has no loop issue because magicsock
    /// uses the OS stack directly and the TUN is not in the path.
    pub exit_node: Option<String>,
}

/// Simple cancellation token.
pub(crate) struct CancelToken {
    cancelled: std::sync::atomic::AtomicBool,
    notify: tokio::sync::Notify,
}

impl CancelToken {
    pub(crate) fn new() -> Self {
        Self {
            cancelled: std::sync::atomic::AtomicBool::new(false),
            notify: tokio::sync::Notify::new(),
        }
    }
    pub(crate) fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.notify.notify_waiters();
    }
    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Wait for cancellation without a lost-notification race.
    pub(crate) async fn cancelled(&self) {
        loop {
            if self.is_cancelled() {
                return;
            }
            let notified = self.notify.notified();
            tokio::pin!(notified);
            // Register before the second load: `notify_waiters` does not
            // retain a permit for a future waiter.
            notified.as_mut().enable();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}
/// Ensure the rustls ring crypto provider is installed process-wide.
pub(crate) fn ensure_ring_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

pub(crate) fn rand_index() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// Extract the first IPv4 from a list of tailnet IPs.
pub(crate) fn first_v4(ips: &[IpAddr]) -> Result<Ipv4Addr, TsnetError> {
    ips.iter()
        .find_map(|ip| match ip {
            IpAddr::V4(v4) => Some(*v4),
            _ => None,
        })
        .ok_or_else(|| TsnetError::Builder("no IPv4 tailnet address".into()))
}
/// Best-effort: close all TCP connections visible to this process. Called
/// after exit-node route changes in TUN mode so that existing TCP
/// connections pick up the new routing. Logs the closed count on success
/// and the error on failure. Never called in netstack mode or tests —
/// closing the process's own DERP/control TCP fds there would kill the
/// data plane.
pub(crate) fn break_tcp_conns_best_effort() {
    match rustscale_tcpinfo::break_tcp_conns() {
        Ok(n) => {
            log::debug!("tsnet: broke {n} TCP connection(s) on exit-node change");
        }
        Err(e) => {
            log::warn!("tsnet: break_tcp_conns failed (non-fatal): {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CancelToken;
    use std::sync::Arc;

    #[tokio::test]
    async fn cancel_token_registered_waiter_wakes_after_cancel_race_window() {
        let cancel = Arc::new(CancelToken::new());
        let waiter = tokio::spawn({
            let cancel = cancel.clone();
            async move { cancel.cancelled().await }
        });
        // Yield after construction so the waiter has registered its Notify
        // future. `cancelled` performs a second atomic load after enabling
        // that waiter, which is the notify_waiters race this protects.
        tokio::task::yield_now().await;
        cancel.cancel();
        tokio::time::timeout(std::time::Duration::from_millis(250), waiter)
            .await
            .expect("cancelled waiter lost its wake")
            .expect("cancelled waiter panicked");
    }
}
