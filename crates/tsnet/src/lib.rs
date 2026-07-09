//! Public embedding API for rustscale — a Rust equivalent of Go's
//! [`tailscale.com/tsnet`](https://pkg.go.dev/tailscale.com/tsnet).
//!
//! # Quick start
//!
//! ```no_run
//! use rustscale_tsnet::Server;
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! let mut server = Server::builder()
//!     .hostname("my-app")
//!     .auth_key("tskey-...")
//!     .ephemeral(true)
//!     .build()?;
//!
//! server.up().await?;
//!
//! let status = server.status();
//! println!("tailscale IP: {:?}", status.tailscale_ips);
//!
//! let mut listener = server.listen(8080).await?;
//! // loop { let stream = listener.accept().await?; ... }
//!
//! let stream = server.dial("100.64.0.2:443").await?;
//! server.close().await;
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]

mod state;
mod status;

pub use state::{PersistedState, StateError};
pub use status::{PeerInfo, ServerStatus};

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use rustscale_controlclient::client::{ControlClient, RegisterError, StreamMapError};
use rustscale_controlclient::controlhttp;
use rustscale_derp::DerpClient;
use rustscale_key::{DiscoPrivate, MachinePrivate, NodePrivate, NodePublic};
use rustscale_magicsock::{Magicsock, MagicsockConfig, MagicsockError, PathClass};
use rustscale_netstack::{Netstack, NetstackError, NetstackStream, DEFAULT_MTU};
use rustscale_tailcfg::{DERPMap, Hostinfo, MapRequest, MapResponse, Node, RegisterRequest};
use rustscale_wg::{WgError, WgTunn};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::task::JoinHandle;

/// Default control-plane URL.
pub const DEFAULT_CONTROL_URL: &str = "controlplane.tailscale.com";

/// Capability version we advertise to the control plane (matches the
/// current Tailscale `CurrentCapabilityVersion`).
const CAPABILITY_VERSION: i32 = 141;

/// Protocol version for the Noise handshake (ts2021). This is the
/// `CurrentCapabilityVersion` as a u16, matching Go's
/// `cmp.Or(nc.opts.ProtocolVersion, uint16(tailcfg.CurrentCapabilityVersion))`.
const PROTOCOL_VERSION: u16 = 141;

/// Errors from tsnet operations.
#[derive(Debug, thiserror::Error)]
pub enum TsnetError {
    #[error("server already up")]
    AlreadyUp,
    #[error("server is not up (call up() first)")]
    NotUp,
    #[error("builder validation: {0}")]
    Builder(String),
    #[error("state file error: {0}")]
    State(#[from] StateError),
    #[error("control register error: {0}")]
    Register(#[from] RegisterError),
    #[error("map stream error: {0}")]
    MapStream(#[from] StreamMapError),
    #[error("magicsock error: {0}")]
    Magicsock(#[from] MagicsockError),
    #[error("netstack error: {0}")]
    Netstack(#[from] NetstackError),
    #[error("wireguard error: {0}")]
    Wg(#[from] WgError),
    #[error("auth required: visit {0}")]
    AuthRequired(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("hostname not found in netmap: {0}")]
    HostnameNotFound(String),
    #[error("derp error: {0}")]
    Derp(#[from] rustscale_derp::DerpError),
    #[error("netcheck error: {0}")]
    Netcheck(#[from] rustscale_netcheck::NetcheckError),
    #[error("timeout waiting for first map response")]
    MapTimeout,
}

/// A builder for configuring a [`Server`].
#[derive(Clone, Debug, Default)]
pub struct ServerBuilder {
    hostname: String,
    auth_key: Option<String>,
    control_url: String,
    state_dir: Option<PathBuf>,
    ephemeral: bool,
}

impl ServerBuilder {
    /// Set the hostname.
    pub fn hostname(mut self, h: impl Into<String>) -> Self {
        self.hostname = h.into();
        self
    }

    /// Set the auth key.
    pub fn auth_key(mut self, k: impl Into<String>) -> Self {
        self.auth_key = Some(k.into());
        self
    }

    /// Set the control-plane URL.
    pub fn control_url(mut self, u: impl Into<String>) -> Self {
        self.control_url = u.into();
        self
    }

    /// Set the state directory for persistent keys.
    pub fn state_dir(mut self, d: impl Into<PathBuf>) -> Self {
        self.state_dir = Some(d.into());
        self
    }

    /// Set the ephemeral flag.
    pub fn ephemeral(mut self, e: bool) -> Self {
        self.ephemeral = e;
        self
    }

    /// Validate and construct a [`Server`].
    pub fn build(self) -> Result<Server, TsnetError> {
        if self.hostname.is_empty() {
            return Err(TsnetError::Builder("hostname must not be empty".into()));
        }
        Ok(Server {
            config: self,
            inner: None,
        })
    }
}

/// Internal running state.
struct RunningState {
    tailscale_ips: Vec<IpAddr>,
    magicsock: Arc<Magicsock>,
    netstack: Arc<Netstack>,
    wg_tunnels: Arc<RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>>,
    peers: Arc<RwLock<Vec<Node>>>,
    derp_map: Arc<RwLock<Option<DERPMap>>>,
    home_derp: i32,
    cancel: Arc<CancelToken>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

/// Simple cancellation token.
struct CancelToken {
    cancelled: std::sync::atomic::AtomicBool,
}

impl CancelToken {
    fn new() -> Self {
        Self {
            cancelled: std::sync::atomic::AtomicBool::new(false),
        }
    }
    fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// An embedded Tailscale server.
pub struct Server {
    config: ServerBuilder,
    inner: Option<RunningState>,
}

impl Server {
    /// Create a new builder with defaults.
    pub fn builder() -> ServerBuilder {
        ServerBuilder {
            hostname: "rustscale".into(),
            control_url: DEFAULT_CONTROL_URL.into(),
            ..Default::default()
        }
    }

    /// Whether the server is up.
    pub fn is_up(&self) -> bool {
        self.inner.is_some()
    }

    /// Bring the server online.
    pub async fn up(&mut self) -> Result<(), TsnetError> {
        if self.inner.is_some() {
            return Err(TsnetError::AlreadyUp);
        }

        // Ensure the rustls ring crypto provider is installed before any TLS
        // operations (control-plane dial, DERP connect). Guarded by Once so
        // it's a no-op after the first call.
        ensure_ring_provider();

        // 1. Load or generate persistent state.
        let mut state = self.load_or_create_state()?;
        if state.is_zero() {
            state = PersistedState::generate();
            self.save_state(&state)?;
        }

        let node_pub = state.node_key.public();
        let disco_pub = state.disco_key.public();

        // 2. Fetch the server's Noise public key (GET /key?v=<version> over HTTPS).
        let server_pub_key =
            controlhttp::fetch_server_pub_key(&self.config.control_url, PROTOCOL_VERSION)
                .await
                .map_err(|e| {
                    TsnetError::Register(rustscale_controlclient::RegisterError::Dial(e))
                })?;

        // 3. Create the control client with the server's real public key.
        let auth_key = self
            .config
            .auth_key
            .as_ref()
            .ok_or_else(|| TsnetError::Builder("auth_key is required".into()))?;

        let cc = ControlClient::new(
            self.config.control_url.clone(),
            state.machine_key.clone(),
            server_pub_key.clone(),
            PROTOCOL_VERSION,
        );

        let reg_req = RegisterRequest {
            Version: CAPABILITY_VERSION,
            NodeKey: node_pub.clone(),
            Auth: Some(rustscale_tailcfg::RegisterResponseAuth {
                AuthKey: auth_key.clone(),
            }),
            Hostinfo: Some(Hostinfo {
                OS: std::env::consts::OS.to_string(),
                Hostname: self.config.hostname.clone(),
                ..Default::default()
            }),
            Ephemeral: self.config.ephemeral,
            ..Default::default()
        };

        let reg_resp = cc.register(&reg_req).await?;
        if !reg_resp.AuthURL.is_empty() {
            return Err(TsnetError::AuthRequired(reg_resp.AuthURL));
        }

        state.node_id = reg_resp.User.ID;
        self.save_state(&state)?;

        // 3. Start map long-poll.
        let map_req = MapRequest {
            Version: CAPABILITY_VERSION,
            KeepAlive: true,
            NodeKey: node_pub.clone(),
            DiscoKey: disco_pub.clone(),
            Stream: true,
            Hostinfo: Some(Hostinfo {
                OS: std::env::consts::OS.to_string(),
                Hostname: self.config.hostname.clone(),
                ..Default::default()
            }),
            ..Default::default()
        };

        let (map_tx, mut map_rx) = mpsc::channel(32);
        let cc2 = ControlClient::new(
            self.config.control_url.clone(),
            state.machine_key.clone(),
            server_pub_key,
            PROTOCOL_VERSION,
        );
        let map_task = tokio::spawn(async move {
            let _ = cc2.stream_map(&map_req, map_tx).await;
        });

        // Wait for first MapResponse.
        let first = tokio::time::timeout(std::time::Duration::from_secs(30), map_rx.recv())
            .await
            .map_err(|_| TsnetError::MapTimeout)?
            .ok_or(TsnetError::MapTimeout)?;

        let map_resp: MapResponse = first?;

        let tailscale_ips = extract_tailscale_ips(&map_resp);
        if tailscale_ips.is_empty() {
            return Err(TsnetError::Builder("no tailscale IPs assigned".into()));
        }
        let our_v4 = tailscale_ips
            .iter()
            .find_map(|ip| match ip {
                IpAddr::V4(v4) => Some(*v4),
                _ => None,
            })
            .ok_or_else(|| TsnetError::Builder("no IPv4 tailnet address".into()))?;

        // 5. Netcheck to pick home DERP. If netcheck can't probe (no explicit
        // IPs in the DERP map), fall back to the first region.
        let derp_map = map_resp.DERPMap.clone().unwrap_or_default();
        let home_derp = if !derp_map.Regions.is_empty() {
            match rustscale_netcheck::Prober::default()
                .run(&derp_map, &rustscale_netcheck::ProberOpts::default())
                .await
            {
                Ok(r) if r.preferred_derp > 0 => r.preferred_derp,
                _ => {
                    // Fall back to the first non-Avoid region.
                    derp_map
                        .Regions
                        .values()
                        .find(|r| !r.Avoid)
                        .or_else(|| derp_map.Regions.values().next())
                        .map(|r| r.RegionID)
                        .unwrap_or(0)
                }
            }
        } else {
            0
        };

        // 6. Connect home DERP.
        let derp_client = connect_home_derp(&derp_map, home_derp, &state.node_key)
            .await
            .ok();

        // 7. Create magicsock.
        let magicsock = Arc::new(
            Magicsock::new(MagicsockConfig {
                private_key: state.node_key.clone(),
                disco_key: state.disco_key.clone(),
                derp_client,
                udp_bind: Some(SocketAddr::from(([0, 0, 0, 0], 0u16))),
            })
            .await?,
        );

        // The server may send peers via Peers (full list) or PeersChanged
        // (delta). The first response often uses PeersChanged, not Peers.
        let mut peers = map_resp.Peers.clone();
        if peers.is_empty() && !map_resp.PeersChanged.is_empty() {
            peers = map_resp.PeersChanged.clone();
        }
        magicsock.set_netmap(peers.clone()).await?;

        // 8. Create netstack.
        let netstack = Arc::new(Netstack::new(our_v4, DEFAULT_MTU));

        // 9. Create per-peer WG tunnels.
        let wg_tunnels = Arc::new(RwLock::new(HashMap::new()));
        {
            let mut tunnels = wg_tunnels.write().await;
            for peer in &peers {
                if peer.Key.is_zero() {
                    continue;
                }
                let tunn = WgTunn::new(&state.node_key, &peer.Key, rand_index())?;
                tunnels.insert(peer.Key.clone(), Arc::new(Mutex::new(tunn)));
            }
        }

        let peers_arc = Arc::new(RwLock::new(peers.clone()));
        let derp_arc = Arc::new(RwLock::new(map_resp.DERPMap.clone()));
        let cancel = Arc::new(CancelToken::new());

        let running = RunningState {
            tailscale_ips: tailscale_ips.clone(),
            magicsock: magicsock.clone(),
            netstack: netstack.clone(),
            wg_tunnels: wg_tunnels.clone(),
            peers: peers_arc.clone(),
            derp_map: derp_arc.clone(),
            home_derp,
            cancel: cancel.clone(),
            tasks: Mutex::new(vec![map_task]),
        };

        // Start the data-plane pump.
        let pump = tokio::spawn(run_data_pump(
            magicsock.clone(),
            netstack.clone(),
            wg_tunnels.clone(),
            peers_arc.clone(),
            cancel.clone(),
        ));
        running.tasks.lock().await.push(pump);

        // Start the map update task — processes streaming MapResponse deltas.
        let ms = magicsock.clone();
        let wg = wg_tunnels.clone();
        let nk = state.node_key.clone();
        let cancel2 = cancel.clone();
        let map_update = tokio::spawn(async move {
            loop {
                if cancel2.is_cancelled() {
                    break;
                }
                match map_rx.recv().await {
                    Some(Ok(resp)) => {
                        // Skip keep-alive messages.
                        if resp.KeepAlive {
                            continue;
                        }

                        // Merge peer deltas into the current peer list.
                        // Peers = full list (first response), PeersChanged = deltas.
                        {
                            let mut peers = peers_arc.write().await;
                            if !resp.Peers.is_empty() {
                                // Full peer list replaces.
                                *peers = resp.Peers.clone();
                            }
                            if !resp.PeersChanged.is_empty() {
                                // Merge changed peers by node key.
                                for changed in &resp.PeersChanged {
                                    if let Some(existing) =
                                        peers.iter_mut().find(|p| p.Key == changed.Key)
                                    {
                                        *existing = changed.clone();
                                    } else {
                                        peers.push(changed.clone());
                                    }
                                }
                            }
                            if !resp.PeersRemoved.is_empty() {
                                peers.retain(|p| !resp.PeersRemoved.contains(&p.ID));
                            }
                        }

                        // Feed the updated peer list to magicsock.
                        let peers = peers_arc.read().await.clone();
                        let _ = ms.set_netmap(peers.clone()).await;

                        // Create WG tunnels for any new peers.
                        let mut tunnels = wg.write().await;
                        for peer in &peers {
                            if peer.Key.is_zero() {
                                continue;
                            }
                            if !tunnels.contains_key(&peer.Key) {
                                if let Ok(t) = WgTunn::new(&nk, &peer.Key, rand_index()) {
                                    tunnels.insert(peer.Key.clone(), Arc::new(Mutex::new(t)));
                                }
                            }
                        }
                    }
                    Some(Err(_)) | None => break,
                }
            }
        });
        running.tasks.lock().await.push(map_update);

        self.inner = Some(running);
        Ok(())
    }

    /// Get the current server status.
    pub fn status(&self) -> ServerStatus {
        let Some(ref inner) = self.inner else {
            return ServerStatus {
                up: false,
                tailscale_ips: vec![],
                peer_count: 0,
                peers: vec![],
                hostname: self.config.hostname.clone(),
            };
        };
        let peers: Vec<PeerInfo> = inner
            .peers
            .try_read()
            .map(|p| {
                p.iter()
                    .filter(|n| !n.Key.is_zero())
                    .map(|n| PeerInfo {
                        node_key: n.Key.clone(),
                        name: n.Name.clone(),
                        ips: extract_node_ips(n),
                        path_class: inner.magicsock.peer_path_class(&n.Key),
                    })
                    .collect()
            })
            .unwrap_or_default();
        ServerStatus {
            up: true,
            tailscale_ips: inner.tailscale_ips.clone(),
            peer_count: peers.len(),
            peers,
            hostname: self.config.hostname.clone(),
        }
    }

    /// Listen for incoming TCP connections on `port`.
    pub async fn listen(&self, port: u16) -> Result<rustscale_netstack::Listener, TsnetError> {
        let inner = self.inner.as_ref().ok_or(TsnetError::NotUp)?;
        Ok(inner.netstack.listen(port).await?)
    }

    /// Dial a remote `ip:port` or `hostname:port`.
    pub async fn dial(&self, addr: &str) -> Result<NetstackStream, TsnetError> {
        let inner = self.inner.as_ref().ok_or(TsnetError::NotUp)?;
        let socket_addr = resolve_addr(addr, inner)?;
        Ok(inner.netstack.dial(socket_addr).await?)
    }

    /// Shut down the server.
    pub async fn close(&mut self) {
        if let Some(inner) = self.inner.take() {
            inner.cancel.cancel();
            let mut tasks = inner.tasks.lock().await;
            for task in tasks.drain(..) {
                task.abort();
            }
        }
    }

    // --- internal helpers ---

    fn load_or_create_state(&self) -> Result<PersistedState, TsnetError> {
        if let Some(ref dir) = self.config.state_dir {
            let path = dir.join("tsnet-state.json");
            if path.exists() {
                return Ok(PersistedState::load(&path)?);
            }
        }
        Ok(PersistedState::default())
    }

    fn save_state(&self, state: &PersistedState) -> Result<(), TsnetError> {
        if let Some(ref dir) = self.config.state_dir {
            let path = dir.join("tsnet-state.json");
            state.save(&path)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Data pump
// ---------------------------------------------------------------------------

async fn run_data_pump(
    magicsock: Arc<Magicsock>,
    netstack: Arc<Netstack>,
    wg_tunnels: Arc<RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>>,
    peers: Arc<RwLock<Vec<Node>>>,
    cancel: Arc<CancelToken>,
) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_millis(5));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        if cancel.is_cancelled() {
            break;
        }

        tokio::select! {
            _ = ticker.tick() => {}
            result = magicsock.poll_recv() => {
                if let Ok(dgram) = result {
                    let tunn = {
                        let tunnels = wg_tunnels.read().await;
                        tunnels.get(&dgram.peer).cloned()
                    };
                    if let Some(tunn) = tunn {
                        if let Ok(mut t) = tunn.try_lock() {
                            if let Ok(decap) = t.decapsulate(&dgram.data) {
                                if let Some(pt) = decap.plaintext {
                                    netstack.push_rx(pt);
                                }
                                for reply in decap.replies {
                                    let _ = magicsock.send(dgram.peer.clone(), &reply).await;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Drain outbound IP packets from netstack.
        while let Some(pkt) = netstack.pop_tx() {
            if let Some(IpAddr::V4(dst_v4)) = WgTunn::dst_address(&pkt) {
                let peer_key = {
                    let p = peers.read().await;
                    find_peer_for_ip(&p, dst_v4)
                };
                if let Some(peer_key) = peer_key {
                    let tunnels = wg_tunnels.read().await;
                    if let Some(tunn) = tunnels.get(&peer_key) {
                        if let Ok(mut t) = tunn.try_lock() {
                            if let Ok(dgrams) = t.encapsulate(&pkt) {
                                for dg in dgrams {
                                    let _ = magicsock.send(peer_key.clone(), &dg).await;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Tick WG timers.
        let tunnels = wg_tunnels.read().await;
        for (peer_key, tunn) in tunnels.iter() {
            if let Ok(mut t) = tunn.try_lock() {
                for dg in t.tick_timers() {
                    let _ = magicsock.send(peer_key.clone(), &dg).await;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn extract_tailscale_ips(map: &MapResponse) -> Vec<IpAddr> {
    map.Node.as_ref().map(extract_node_ips).unwrap_or_default()
}

fn extract_node_ips(node: &Node) -> Vec<IpAddr> {
    node.Addresses
        .iter()
        .filter_map(|s| s.split('/').next().and_then(|ip| ip.parse::<IpAddr>().ok()))
        .collect()
}

async fn connect_home_derp(
    derp_map: &DERPMap,
    home_region: i32,
    node_key: &NodePrivate,
) -> Result<DerpClient, rustscale_derp::DerpError> {
    let region = derp_map
        .Regions
        .get(&home_region)
        .ok_or_else(|| rustscale_derp::DerpError::BadFrame("unknown DERP region".into()))?;
    let nodes = region
        .Nodes
        .as_ref()
        .ok_or_else(|| rustscale_derp::DerpError::BadFrame("no DERP nodes".into()))?;
    let node = nodes
        .iter()
        .find(|n| !n.STUNOnly)
        .or_else(|| nodes.first())
        .ok_or_else(|| rustscale_derp::DerpError::BadFrame("no DERP node".into()))?;
    let port = if node.DERPPort > 0 {
        node.DERPPort as u16
    } else {
        443
    };

    // Use the explicit IPv4 for TCP dialing if available, but always use
    // the hostname for TLS SNI (DERP servers reject IP-based SNI).
    let tls_host = node.HostName.clone();
    let dial_addr = if !node.IPv4.is_empty() && node.IPv4 != "none" {
        node.IPv4.clone()
    } else {
        node.HostName.clone()
    };

    DerpClient::connect_with_upgrade_dial(&dial_addr, &tls_host, port, true, node_key.clone()).await
}

/// Ensure the rustls ring crypto provider is installed process-wide.
fn ensure_ring_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn rand_index() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static NEXT: AtomicU32 = AtomicU32::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

fn find_peer_for_ip(peers: &[Node], ip: Ipv4Addr) -> Option<NodePublic> {
    for peer in peers {
        if peer.Key.is_zero() {
            continue;
        }
        let allowed: &[String] = if peer.AllowedIPs.is_empty() {
            &peer.Addresses
        } else {
            &peer.AllowedIPs
        };
        for cidr in allowed {
            if ip_in_cidr(ip, cidr) {
                return Some(peer.Key.clone());
            }
        }
    }
    None
}

fn ip_in_cidr(ip: Ipv4Addr, cidr: &str) -> bool {
    let Some((net_str, prefix_str)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(net) = net_str.parse::<Ipv4Addr>() else {
        return false;
    };
    let Ok(prefix) = prefix_str.parse::<u32>() else {
        return false;
    };
    if prefix > 32 {
        return false;
    }
    let mask = if prefix == 0 {
        0u32
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(ip) & mask) == (u32::from(net) & mask)
}

fn resolve_addr(addr: &str, inner: &RunningState) -> Result<SocketAddr, TsnetError> {
    if let Ok(sa) = addr.parse::<SocketAddr>() {
        return Ok(sa);
    }
    let (host, port) = addr
        .rsplit_once(':')
        .ok_or_else(|| TsnetError::Builder(format!("invalid address: {addr}")))?;
    let port: u16 = port
        .parse()
        .map_err(|_| TsnetError::Builder(format!("invalid port: {addr}")))?;

    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }

    let peers = inner
        .peers
        .try_read()
        .map_err(|_| TsnetError::HostnameNotFound(host.to_string()))?;
    let host_lower = host.to_lowercase();
    let host_trimmed = host_lower.trim_end_matches('.');

    for peer in peers.iter() {
        let name = peer.Name.to_lowercase();
        let name_trimmed = name.trim_end_matches('.');
        if name_trimmed == host_trimmed
            || name_trimmed.ends_with(&format!(".{host_trimmed}"))
            || peer.StableID.eq_ignore_ascii_case(host)
        {
            if let Some(ip) = extract_node_ips(peer).first() {
                return Ok(SocketAddr::new(*ip, port));
            }
        }
    }

    Err(TsnetError::HostnameNotFound(host.to_string()))
}

#[cfg(test)]
mod tests;
