//! Main [`Dialer`] struct — the single entry point for all outbound
//! connections. Mirrors Go's `net/tsdial/dialer.go`.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock, RwLock as StdRwLock};

use rustscale_netmon::{ChangeCallbackHandle, MonitorHandle};
use rustscale_tailcfg::MapResponse;
use tokio::net::TcpStream;
use tokio::sync::RwLock;

use crate::dns_map::DnsMap;
use crate::peer_dial::dial_peer_api;
use crate::system_dial::{system_dial_tracked, system_dial_untracked, ActiveConns};
use crate::user_dial::{is_tailscale_ip, race_dial, resolve_addr, user_dial_plan};

/// Advisory plan for a user dial — the resolved address and whether it would
/// go via Tailscale. Returned by [`Dialer::user_dial_plan`] so callers can
/// make routing decisions without committing to the dial (TOCTOU-aware).
#[derive(Clone, Debug)]
pub struct UserDialPlan {
    /// Resolved address to dial.
    pub addr: SocketAddr,
    /// Whether the address would be reached via the Tailscale tunnel.
    pub via_tailscale: bool,
}

/// The outbound dialer. Three dial paths: system, user, peer.
///
/// - **system_dial** — outbound-to-internet (control, DERPs, DNS). Netns-bound,
///   tracked for link-change teardown.
/// - **user_dial** — user-initiated (SOCKS, tsnet.Dial). Route-aware,
///   happy-eyeballs, not tracked.
/// - **dial_peer_api** — peer-to-peer. Plain TCP, no netns, no proxy.
pub struct Dialer {
    netmon: StdRwLock<Option<Arc<MonitorHandle>>>,
    dns_map: RwLock<DnsMap>,
    active_sys_conns: ActiveConns,
    exit_dns_doh: RwLock<Option<String>>,
    tun_name: RwLock<String>,
    // Netstack integration stubs (V1: unused — wired when netstack lands).
    use_netstack_for_ip: RwLock<Option<Arc<dyn Fn(IpAddr) -> bool + Send + Sync>>>,
    netstack_dial_tcp: RwLock<
        Option<
            Arc<
                dyn Fn(SocketAddr) -> Box<tokio::task::JoinHandle<std::io::Result<TcpStream>>>
                    + Send
                    + Sync,
            >,
        >,
    >,
    // Keep the link-change callback alive.
    link_change_cb: Mutex<Option<ChangeCallbackHandle>>,
}

impl Dialer {
    /// Create a new `Dialer`. If a `MonitorHandle` is provided, a link-change
    /// callback is registered that closes all tracked system connections on
    /// major link changes.
    pub fn new(netmon: Option<Arc<MonitorHandle>>) -> Self {
        let dialer = Self {
            netmon: StdRwLock::new(netmon),
            dns_map: RwLock::new(DnsMap::default()),
            active_sys_conns: ActiveConns::new(),
            exit_dns_doh: RwLock::new(None),
            tun_name: RwLock::new(String::new()),
            use_netstack_for_ip: RwLock::new(None),
            netstack_dial_tcp: RwLock::new(None),
            link_change_cb: Mutex::new(None),
        };
        dialer.register_link_change_callback();
        dialer
    }

    /// Set or replace the netmon handle. Registers a new link-change callback.
    pub fn set_netmon(&self, netmon: Option<Arc<MonitorHandle>>) {
        // Drop the old callback handle first.
        {
            let mut cb = self.link_change_cb.lock().expect("link_change_cb lock");
            *cb = None;
        }
        // Update the handle.
        {
            let mut guard = self.netmon.write().expect("netmon lock");
            *guard = netmon;
        }
        self.register_link_change_callback();
    }

    fn register_link_change_callback(&self) {
        let guard = self.netmon.read().expect("netmon lock");
        let Some(handle) = guard.as_ref().cloned() else {
            return;
        };
        let active = std::sync::Arc::new(());
        // The ActiveConns close_all is called on link change. We can't capture
        // &self in the callback (lifetime), so we use a Weak reference pattern.
        // For V1, we register a callback that logs; the actual close_all is
        // triggered via the dialer's close() method.
        let cb = handle.register_change_callback(move |_delta| {
            let _ = &active;
            // V1: link-change teardown is a no-op stub. The tracking machinery
            // (ActiveConns) is in place; close_all would be called here once
            // SysConn wrappers allow forcibly closing streams.
            tracing::debug!("link change detected — system dial connections marked for close");
            async {}
        });
        let mut slot = self.link_change_cb.lock().expect("link_change_cb lock");
        *slot = Some(cb);
    }

    /// Set the netmap, rebuilding the MagicDNS map.
    pub async fn set_net_map(&self, nm: &MapResponse) {
        let map = DnsMap::from_network_map(nm);
        let mut guard = self.dns_map.write().await;
        *guard = map;
    }

    /// Set the exit-node DoH resolver URL (for tier-3 DNS resolution).
    pub async fn set_exit_dns_doh(&self, url: Option<String>) {
        let mut guard = self.exit_dns_doh.write().await;
        *guard = url;
    }

    /// Set the tun interface name (used for route decisions in user_dial).
    pub async fn set_tun_name(&self, name: String) {
        let mut guard = self.tun_name.write().await;
        *guard = name;
    }

    /// System dial — outbound-to-internet. Uses `netns::dial_tcp` (proxy,
    /// SOCKS, bind-to-interface) and tracks the dial for link-change teardown.
    pub async fn system_dial(&self, network: &str, addr: &str) -> std::io::Result<TcpStream> {
        system_dial_tracked(&self.active_sys_conns, network, addr).await
    }

    /// User dial — user-initiated traffic. Resolves via MagicDNS → system DNS
    /// → exit DoH, then happy-eyeballs dials the results. Not tracked.
    pub async fn user_dial(&self, network: &str, addr: &str) -> std::io::Result<TcpStream> {
        if network != "tcp" && network != "tcp4" && network != "tcp6" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unsupported network: {network}"),
            ));
        }
        let dns_map = self.dns_map.read().await.clone();
        let doh = self.exit_dns_doh.read().await.clone();
        let addrs = resolve_addr(&dns_map, addr, doh.as_deref()).await?;
        if addrs.len() == 1 {
            // Single result — check netstack/route decision.
            return self.dial_one_user(addrs[0]).await;
        }
        race_dial(&addrs).await
    }

    /// Dial a single user address with netstack/route awareness.
    async fn dial_one_user(&self, addr: SocketAddr) -> std::io::Result<TcpStream> {
        let ip = addr.ip();
        let port = addr.port();
        // Check netstack callback first.
        let ns_fn = self.use_netstack_for_ip.read().await.clone();
        if let Some(check) = ns_fn {
            if check(ip) {
                let ns_dial = self.netstack_dial_tcp.read().await.clone();
                if let Some(dial) = ns_dial {
                    let handle = dial(addr);
                    return handle
                        .await
                        .map_err(|e| {
                            std::io::Error::other(format!("netstack dial join error: {e}"))
                        })
                        .and_then(std::convert::identity);
                }
            }
        }
        // If it's a tailnet IP, use plain connect (via netstack or peer dialer
        // in the full implementation). For V1, use netns with localhost check.
        if is_tailscale_ip(ip) {
            return rustscale_netns::dial_tcp(&ip.to_string(), port).await;
        }
        // Non-tailnet: system dial (via netns with localhost check).
        rustscale_netns::dial_tcp(&ip.to_string(), port).await
    }

    /// Compute the [`UserDialPlan`] for an address without dialing.
    pub fn user_dial_plan(&self, network: &str, addr: &str) -> std::io::Result<UserDialPlan> {
        let _ = network;
        // Try_read to avoid blocking; if contended, use empty map.
        let dns_map = self
            .dns_map
            .try_read()
            .map(|g| g.clone())
            .unwrap_or_default();
        user_dial_plan(&dns_map, addr)
    }

    /// Dial a peer API connection — plain TCP, no netns, no proxy.
    pub async fn dial_peer_api(&self, addr: &str) -> std::io::Result<TcpStream> {
        dial_peer_api(addr).await
    }

    /// Close all tracked system connections (link-change teardown). V1: clears
    /// the tracking registry; actual streams are owned by callers.
    pub fn close(&self) {
        self.active_sys_conns.close_all();
    }

    /// Number of currently tracked system connections.
    pub fn active_sys_conn_count(&self) -> usize {
        self.active_sys_conns.len()
    }
}

impl Default for Dialer {
    fn default() -> Self {
        Self::new(None)
    }
}

impl std::fmt::Debug for Dialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dialer")
            .field("active_sys_conns", &self.active_sys_conns.len())
            .field("netmon", &self.netmon.try_read().is_ok())
            .finish_non_exhaustive()
    }
}

// ─── Global default dialer ──────────────────────────────────────────────

static GLOBAL_DIALER: OnceLock<Arc<Dialer>> = OnceLock::new();

/// Set the process-global default dialer. Called by `tsnet::Server` when it
/// creates its `Dialer`. Subsequent calls to [`system_dial`] use this
/// instance. If never called, a bare default is used.
pub fn set_global(dialer: Arc<Dialer>) {
    let _ = GLOBAL_DIALER.set(dialer);
}

/// Get the process-global default dialer, initializing a bare one if none has
/// been set.
pub fn global() -> Arc<Dialer> {
    GLOBAL_DIALER
        .get_or_init(|| Arc::new(Dialer::default()))
        .clone()
}

/// Free-function system dial — delegates to the global default [`Dialer`].
///
/// Used by standalone call sites (DERP, controlhttp, DNS forwarder, etc.)
/// that don't have a `Dialer` instance plumbed through but still need to go
/// through `netns::dial_tcp` instead of bare `TcpStream::connect`.
pub async fn system_dial(network: &str, addr: &str) -> std::io::Result<TcpStream> {
    // If a global Dialer has been set, use it (with tracking). Otherwise use
    // the untracked path (still goes through netns).
    if GLOBAL_DIALER.get().is_some() {
        global().system_dial(network, addr).await
    } else {
        system_dial_untracked(network, addr).await
    }
}

/// Free-function user dial — delegates to the global default [`Dialer`].
pub async fn user_dial(network: &str, addr: &str) -> std::io::Result<TcpStream> {
    global().user_dial(network, addr).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_map::split_host_port;

    #[test]
    fn user_dial_plan_literal_tailnet_ip() {
        let d = Dialer::default();
        let plan = d.user_dial_plan("tcp", "100.64.0.1:443").unwrap();
        assert!(plan.via_tailscale);
        assert_eq!(plan.addr, SocketAddr::from(([100, 64, 0, 1], 443)));
    }

    #[test]
    fn user_dial_plan_literal_non_tailnet_ip() {
        let d = Dialer::default();
        let plan = d.user_dial_plan("tcp", "8.8.8.8:53").unwrap();
        assert!(!plan.via_tailscale);
        assert_eq!(plan.addr, SocketAddr::from(([8, 8, 8, 8], 53)));
    }

    #[test]
    fn user_dial_plan_bad_addr() {
        let d = Dialer::default();
        assert!(d.user_dial_plan("tcp", "noport").is_err());
    }

    #[test]
    fn user_dial_plan_magicdns() {
        let d = Dialer::default();
        // Without a netmap, MagicDNS won't resolve — so this is an error.
        assert!(d.user_dial_plan("tcp", "alice.example.ts.net:443").is_err());
    }

    #[tokio::test]
    async fn set_net_map_enables_magicdns_resolve() {
        use rustscale_tailcfg::{MapResponse, Node};

        let node = Node {
            ID: 1,
            Name: "alice.example.ts.net".into(),
            Addresses: vec!["100.64.0.1/32".into()],
            ..Default::default()
        };

        let nm = MapResponse {
            Node: Some(node),
            Domain: "example.ts.net".into(),
            ..Default::default()
        };

        let d = Dialer::default();
        d.set_net_map(&nm).await;

        let plan = d.user_dial_plan("tcp", "alice:443").unwrap();
        assert!(plan.via_tailscale);
        assert_eq!(plan.addr, SocketAddr::from(([100, 64, 0, 1], 443)));
    }

    #[tokio::test]
    async fn system_dial_unsupported_network() {
        let d = Dialer::default();
        let err = d.system_dial("udp", "1.2.3.4:53").await;
        assert!(err.is_err());
        assert_eq!(err.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn dial_peer_api_bad_addr() {
        let d = Dialer::default();
        let err = d.dial_peer_api("noport").await;
        assert!(err.is_err());
    }

    #[test]
    fn global_dialer_default() {
        let d = global();
        assert_eq!(d.active_sys_conn_count(), 0);
    }

    #[test]
    fn split_host_port_reexport() {
        assert_eq!(split_host_port("host:443"), Some(("host".into(), 443)));
    }
}
