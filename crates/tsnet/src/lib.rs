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

mod routing;
mod state;
mod status;

pub use routing::RouteTable;
pub use state::{PersistedState, StateError};
pub use status::{PeerInfo, ServerStatus};

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use rustscale_controlclient::client::{ControlClient, RegisterError, StreamMapError};
use rustscale_controlclient::controlhttp;
use rustscale_derp::DerpClient;
use rustscale_filter::Filter;
use rustscale_key::{NodePrivate, NodePublic};
use rustscale_magicsock::{Magicsock, MagicsockConfig, MagicsockError};
use rustscale_netstack::{Netstack, NetstackError, NetstackStream, DEFAULT_MTU};
use rustscale_tailcfg::{
    DERPMap, FilterRule, Hostinfo, MapRequest, MapResponse, Node, RegisterRequest,
};
use rustscale_tun::Tun;
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
    #[error("tun device error: {0}")]
    Tun(#[from] rustscale_tun::TunError),
    #[error("listen/dial not available in TUN mode (no userspace netstack)")]
    NotAvailableInTunMode,
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
    data_plane: DataPlane,
    wg_tunnels: Arc<RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>>,
    peers: Arc<RwLock<Vec<Node>>>,
    route_table: Arc<RwLock<RouteTable>>,
    derp_map: Arc<RwLock<Option<DERPMap>>>,
    home_derp: i32,
    cancel: Arc<CancelToken>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    filter: Arc<std::sync::Mutex<Filter>>,
    packet_drops: Arc<AtomicU64>,
}

/// Which data plane is wired up: userspace netstack (tsnet listen/dial) or a
/// real TUN device (full-client packet routing).
enum DataPlane {
    Netstack(Arc<Netstack>),
    Tun(Arc<dyn Tun>),
}

/// Configuration for TUN-mode operation ([`Server::up_tun`]).
///
/// In TUN mode the server routes plaintext IP packets between a real OS TUN
/// device and the WireGuard/magicsock data plane, instead of an in-process
/// userspace netstack. `listen`/`dial` are unavailable in this mode.
#[derive(Clone, Debug)]
pub struct TunModeConfig {
    /// TUN device parameters (name hint + MTU). On macOS the default name
    /// `"utun"` auto-selects a unit.
    pub tun: rustscale_tun::TunConfig,
    /// If true, bring the interface up and add tailnet routes on macOS via
    /// `ifconfig`/`route`. **Requires root.** Default `false`, in which case
    /// you must configure the interface and routes yourself (or rely on the
    /// data-plane pump alone for in-process traffic).
    pub apply_routes: bool,
}

impl Default for TunModeConfig {
    fn default() -> Self {
        Self {
            tun: rustscale_tun::TunConfig::default(),
            apply_routes: false,
        }
    }
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

/// Result of the shared control-plane bootstrap — everything `up()` and
/// `up_tun()` need to start their respective data-plane pumps.
struct Bootstrap {
    tailscale_ips: Vec<IpAddr>,
    our_v4: Ipv4Addr,
    magicsock: Arc<Magicsock>,
    wg_tunnels: Arc<RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>>,
    peers: Arc<RwLock<Vec<Node>>>,
    route_table: Arc<RwLock<RouteTable>>,
    derp_map: Arc<RwLock<Option<DERPMap>>>,
    home_derp: i32,
    cancel: Arc<CancelToken>,
    map_rx: mpsc::Receiver<Result<MapResponse, StreamMapError>>,
    map_task: JoinHandle<()>,
    node_key: NodePrivate,
    filter: Arc<std::sync::Mutex<Filter>>,
    packet_drops: Arc<AtomicU64>,
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

    /// Bring the server online in userspace netstack mode (tsnet listen/dial).
    ///
    /// This is the classic tsnet embedding path: an in-process smoltcp netstack
    /// backs `listen`/`dial`. For a full-client TUN device instead, use
    /// [`Server::up_tun`].
    pub async fn up(&mut self) -> Result<(), TsnetError> {
        if self.inner.is_some() {
            return Err(TsnetError::AlreadyUp);
        }

        ensure_ring_provider();

        let b = self.bootstrap().await?;

        // Userspace netstack bound to our tailnet IPv4.
        let netstack = Arc::new(Netstack::new(b.our_v4, DEFAULT_MTU));

        // Netstack data-plane pump: netstack <-> WG <-> magicsock.
        let pump = tokio::spawn(run_netstack_pump(
            b.magicsock.clone(),
            netstack.clone(),
            b.wg_tunnels.clone(),
            b.route_table.clone(),
            b.filter.clone(),
            b.packet_drops.clone(),
            b.cancel.clone(),
        ));

        // Map-stream update task (peer/route deltas).
        let map_update = spawn_map_update_task(
            b.map_rx,
            b.magicsock.clone(),
            b.wg_tunnels.clone(),
            b.peers.clone(),
            b.route_table.clone(),
            b.node_key.clone(),
            b.filter.clone(),
            b.tailscale_ips.clone(),
            b.cancel.clone(),
        );

        self.inner = Some(RunningState {
            tailscale_ips: b.tailscale_ips,
            magicsock: b.magicsock,
            data_plane: DataPlane::Netstack(netstack),
            wg_tunnels: b.wg_tunnels,
            peers: b.peers,
            route_table: b.route_table,
            derp_map: b.derp_map,
            home_derp: b.home_derp,
            cancel: b.cancel,
            tasks: Mutex::new(vec![b.map_task, pump, map_update]),
            filter: b.filter,
            packet_drops: b.packet_drops,
        });
        Ok(())
    }

    /// Bring the server online in **TUN mode**: route plaintext IP packets
    /// between a real OS TUN device and the WireGuard/magicsock data plane,
    /// instead of an in-process netstack.
    ///
    /// `listen`/`dial` are unavailable in TUN mode. Creating the TUN device
    /// requires root on both macOS (`utun`) and Linux (`/dev/net/tun`). If
    /// `config.apply_routes` is true, the interface is brought up and tailnet
    /// routes are added via `ifconfig`/`route` (macOS) or `ip` (Linux) — also
    /// requiring root.
    pub async fn up_tun(&mut self, config: TunModeConfig) -> Result<(), TsnetError> {
        if self.inner.is_some() {
            return Err(TsnetError::AlreadyUp);
        }

        ensure_ring_provider();

        let b = self.bootstrap().await?;

        // Real TUN device.
        let tun: Arc<dyn Tun> = {
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            {
                let dev = rustscale_tun::create(&config.tun)?;
                if config.apply_routes {
                    apply_tun_routes(dev.name(), &b.tailscale_ips, config.tun.mtu)?;
                }
                Arc::new(dev)
            }
            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            {
                return Err(TsnetError::Builder(
                    "TUN mode not supported on this platform".into(),
                ));
            }
        };

        // TUN data-plane pump: TUN <-> WG <-> magicsock.
        let pump = tokio::spawn(run_tun_pump(
            b.magicsock.clone(),
            tun.clone(),
            b.wg_tunnels.clone(),
            b.route_table.clone(),
            b.filter.clone(),
            b.packet_drops.clone(),
            b.cancel.clone(),
        ));

        let map_update = spawn_map_update_task(
            b.map_rx,
            b.magicsock.clone(),
            b.wg_tunnels.clone(),
            b.peers.clone(),
            b.route_table.clone(),
            b.node_key.clone(),
            b.filter.clone(),
            b.tailscale_ips.clone(),
            b.cancel.clone(),
        );

        self.inner = Some(RunningState {
            tailscale_ips: b.tailscale_ips,
            magicsock: b.magicsock,
            data_plane: DataPlane::Tun(tun),
            wg_tunnels: b.wg_tunnels,
            peers: b.peers,
            route_table: b.route_table,
            derp_map: b.derp_map,
            home_derp: b.home_derp,
            cancel: b.cancel,
            tasks: Mutex::new(vec![b.map_task, pump, map_update]),
            filter: b.filter,
            packet_drops: b.packet_drops,
        });
        Ok(())
    }

    // --- shared control-plane bootstrap ---

    /// Shared bootstrapping for `up()` and `up_tun()`: load state, register
    /// with control, start the map long-poll, wait for the first `MapResponse`,
    /// netcheck for a home DERP, connect it, build magicsock + per-peer WG
    /// tunnels + the routing table. Returns the shared handles plus the
    /// still-open map receiver for the update task.
    async fn bootstrap(&mut self) -> Result<Bootstrap, TsnetError> {
        // 1. Load or generate persistent state.
        let mut state = self.load_or_create_state()?;
        if state.is_zero() {
            state = PersistedState::generate();
            self.save_state(&state)?;
        }

        let node_pub = state.node_key.public();
        let disco_pub = state.disco_key.public();

        // 2. Fetch the server's Noise public key (GET /key?v=<version>).
        let server_pub_key =
            controlhttp::fetch_server_pub_key(&self.config.control_url, PROTOCOL_VERSION)
                .await
                .map_err(|e| {
                    TsnetError::Register(rustscale_controlclient::RegisterError::Dial(e))
                })?;

        // 3. Register with the control plane.
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

        // 4. Start the map long-poll.
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

        // 5. Wait for the first MapResponse.
        let first = tokio::time::timeout(std::time::Duration::from_secs(30), map_rx.recv())
            .await
            .map_err(|_| TsnetError::MapTimeout)?
            .ok_or(TsnetError::MapTimeout)?;
        let map_resp: MapResponse = first?;

        let tailscale_ips = extract_tailscale_ips(&map_resp);
        if tailscale_ips.is_empty() {
            return Err(TsnetError::Builder("no tailscale IPs assigned".into()));
        }
        let our_v4 = first_v4(&tailscale_ips)?;

        // 6. Netcheck to pick a home DERP (fall back to the first region).
        let derp_map = map_resp.DERPMap.clone().unwrap_or_default();
        let home_derp = if !derp_map.Regions.is_empty() {
            match rustscale_netcheck::Prober::default()
                .run(&derp_map, &rustscale_netcheck::ProberOpts::default())
                .await
            {
                Ok(r) if r.preferred_derp > 0 => r.preferred_derp,
                _ => derp_map
                    .Regions
                    .values()
                    .find(|r| !r.Avoid)
                    .or_else(|| derp_map.Regions.values().next())
                    .map(|r| r.RegionID)
                    .unwrap_or(0),
            }
        } else {
            0
        };

        // 7. Connect home DERP.
        let derp_client = connect_home_derp(&derp_map, home_derp, &state.node_key)
            .await
            .ok();

        // 8. Create magicsock.
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
        // (delta). The first response often uses PeersChanged.
        let mut peers = map_resp.Peers.clone();
        if peers.is_empty() && !map_resp.PeersChanged.is_empty() {
            peers = map_resp.PeersChanged.clone();
        }
        magicsock.set_netmap(peers.clone()).await?;

        // 9. Per-peer WG tunnels + routing table.
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
        let route_table = Arc::new(RwLock::new(RouteTable::from_peers(&peers)));
        let derp_arc = Arc::new(RwLock::new(map_resp.DERPMap.clone()));
        let cancel = Arc::new(CancelToken::new());

        // Build the initial packet filter from the first MapResponse.
        let (filter, _named_filters) = build_filter_from_map_response(&map_resp, &tailscale_ips);
        let filter = Arc::new(std::sync::Mutex::new(filter));
        let packet_drops = Arc::new(AtomicU64::new(0));

        Ok(Bootstrap {
            tailscale_ips: tailscale_ips.clone(),
            our_v4,
            magicsock,
            wg_tunnels,
            peers: peers_arc,
            route_table,
            derp_map: derp_arc,
            home_derp,
            cancel,
            map_rx,
            map_task,
            node_key: state.node_key.clone(),
            filter,
            packet_drops,
        })
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
                packet_drops: 0,
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
        let packet_drops = inner
            .packet_drops
            .load(std::sync::atomic::Ordering::Relaxed);
        ServerStatus {
            up: true,
            tailscale_ips: inner.tailscale_ips.clone(),
            peer_count: peers.len(),
            peers,
            hostname: self.config.hostname.clone(),
            packet_drops,
        }
    }

    /// Listen for incoming TCP connections on `port` (netstack mode only).
    ///
    /// Returns an error in TUN mode — there is no in-process netstack to
    /// accept connections.
    pub async fn listen(&self, port: u16) -> Result<rustscale_netstack::Listener, TsnetError> {
        let inner = self.inner.as_ref().ok_or(TsnetError::NotUp)?;
        match &inner.data_plane {
            DataPlane::Netstack(ns) => Ok(ns.listen(port).await?),
            DataPlane::Tun(_) => Err(TsnetError::NotAvailableInTunMode),
        }
    }

    /// Dial a remote `ip:port` or `hostname:port` (netstack mode only).
    ///
    /// Returns an error in TUN mode.
    pub async fn dial(&self, addr: &str) -> Result<NetstackStream, TsnetError> {
        let inner = self.inner.as_ref().ok_or(TsnetError::NotUp)?;
        let socket_addr = resolve_addr(addr, inner)?;
        match &inner.data_plane {
            DataPlane::Netstack(ns) => Ok(ns.dial(socket_addr).await?),
            DataPlane::Tun(_) => Err(TsnetError::NotAvailableInTunMode),
        }
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
// Data-plane pumps
// ---------------------------------------------------------------------------

/// Netstack data-plane pump: netstack <-> WG <-> magicsock.
///
/// Inbound: magicsock recv → WG decapsulate → netstack.push_rx.
/// Outbound: netstack.pop_tx → route lookup → WG encapsulate → magicsock send.
/// Also ticks WG timers every loop iteration.
async fn run_netstack_pump(
    magicsock: Arc<Magicsock>,
    netstack: Arc<Netstack>,
    wg_tunnels: Arc<RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>>,
    route_table: Arc<RwLock<RouteTable>>,
    filter: Arc<std::sync::Mutex<Filter>>,
    packet_drops: Arc<AtomicU64>,
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
                    let f = filter.clone();
                    let drops = packet_drops.clone();
                    let ns = netstack.clone();
                    handle_inbound_wg(&magicsock, &wg_tunnels, &dgram, move |pt| {
                        let dropped = {
                            let mut filt = f.lock().unwrap();
                            filt.check_in(&pt).is_drop()
                        };
                        if dropped {
                            drops.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            return;
                        }
                        ns.push_rx(pt);
                    }).await;
                }
            }
        }

        // Drain outbound IP packets from netstack → route → WG → magicsock.
        while let Some(pkt) = netstack.pop_tx() {
            {
                let mut filt = filter.lock().unwrap();
                filt.update_outbound(&pkt);
            }
            encapsulate_and_send(&magicsock, &wg_tunnels, &route_table, &pkt).await;
        }

        tick_wg_timers(&magicsock, &wg_tunnels).await;
    }
}

/// TUN data-plane pump: TUN device <-> WG <-> magicsock.
///
/// Inbound (from network): magicsock recv -> WG decapsulate -> TUN write.
/// Outbound (from OS): TUN read -> route lookup -> WG encapsulate -> magicsock send.
/// WG timer ticks run on a 250ms interval.
async fn run_tun_pump(
    magicsock: Arc<Magicsock>,
    tun: Arc<dyn Tun>,
    wg_tunnels: Arc<RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>>,
    route_table: Arc<RwLock<RouteTable>>,
    filter: Arc<std::sync::Mutex<Filter>>,
    packet_drops: Arc<AtomicU64>,
    cancel: Arc<CancelToken>,
) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_millis(250));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        if cancel.is_cancelled() {
            break;
        }

        tokio::select! {
            // TUN read -> route -> WG encapsulate -> magicsock send.
            result = tun.read_packet() => {
                match result {
                    Ok(pkt) => {
                        {
                            let mut filt = filter.lock().unwrap();
                            filt.update_outbound(&pkt);
                        }
                        encapsulate_and_send(&magicsock, &wg_tunnels, &route_table, &pkt).await;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => {
                        eprintln!("tun read error: {e}");
                        break;
                    }
                }
            }
            // magicsock recv -> WG decapsulate -> filter -> TUN write.
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
                                    let dropped = {
                                        let mut filt = filter.lock().unwrap();
                                        filt.check_in(&pt).is_drop()
                                    };
                                    if dropped {
                                        packet_drops.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                    } else {
                                        let _ = tun.write_packet(&pt).await;
                                    }
                                }
                                for reply in decap.replies {
                                    let _ = magicsock.send(dgram.peer.clone(), &reply).await;
                                }
                            }
                        }
                    }
                }
            }
            _ = ticker.tick() => {
                tick_wg_timers(&magicsock, &wg_tunnels).await;
            }
        }
    }
}

/// Handle an inbound WG datagram: decapsulate, deliver plaintext via `deliver`,
/// and send any WG protocol replies back over magicsock.
async fn handle_inbound_wg(
    magicsock: &Magicsock,
    wg_tunnels: &RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>,
    dgram: &rustscale_magicsock::WgDatagram,
    deliver: impl Fn(Vec<u8>),
) {
    let tunn = {
        let tunnels = wg_tunnels.read().await;
        tunnels.get(&dgram.peer).cloned()
    };
    if let Some(tunn) = tunn {
        if let Ok(mut t) = tunn.try_lock() {
            if let Ok(decap) = t.decapsulate(&dgram.data) {
                if let Some(pt) = decap.plaintext {
                    deliver(pt);
                }
                for reply in decap.replies {
                    let _ = magicsock.send(dgram.peer.clone(), &reply).await;
                }
            }
        }
    }
}

/// Route a plaintext IP packet to the right peer, encapsulate it via WG, and
/// send the resulting datagrams over magicsock.
async fn encapsulate_and_send(
    magicsock: &Magicsock,
    wg_tunnels: &RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>,
    route_table: &RwLock<RouteTable>,
    pkt: &[u8],
) {
    let Some(dst) = WgTunn::dst_address(pkt) else {
        return;
    };
    let peer_key = {
        let rt = route_table.read().await;
        rt.lookup(dst)
    };
    let Some(peer_key) = peer_key else {
        return;
    };
    let tunnels = wg_tunnels.read().await;
    if let Some(tunn) = tunnels.get(&peer_key) {
        if let Ok(mut t) = tunn.try_lock() {
            if let Ok(dgrams) = t.encapsulate(pkt) {
                for dg in dgrams {
                    let _ = magicsock.send(peer_key.clone(), &dg).await;
                }
            }
        }
    }
}

/// Tick WG timers for all peers and send any resulting datagrams.
async fn tick_wg_timers(
    magicsock: &Magicsock,
    wg_tunnels: &RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>,
) {
    let tunnels = wg_tunnels.read().await;
    for (peer_key, tunn) in tunnels.iter() {
        if let Ok(mut t) = tunn.try_lock() {
            for dg in t.tick_timers() {
                let _ = magicsock.send(peer_key.clone(), &dg).await;
            }
        }
    }
}

/// Spawn the map-stream delta update task. Shared by `up()` and `up_tun()`:
/// processes Peers/PeersChanged/PeersRemoved, feeds the new peer list to
/// magicsock, rebuilds the route table, and creates WG tunnels for new peers.
fn spawn_map_update_task(
    mut map_rx: mpsc::Receiver<Result<MapResponse, StreamMapError>>,
    magicsock: Arc<Magicsock>,
    wg_tunnels: Arc<RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>>,
    peers_arc: Arc<RwLock<Vec<Node>>>,
    route_table: Arc<RwLock<RouteTable>>,
    node_key: NodePrivate,
    filter_arc: Arc<std::sync::Mutex<Filter>>,
    tailscale_ips: Vec<IpAddr>,
    cancel: Arc<CancelToken>,
) -> JoinHandle<()> {
    let mut named_filters: BTreeMap<String, Vec<FilterRule>> = BTreeMap::new();
    tokio::spawn(async move {
        loop {
            if cancel.is_cancelled() {
                break;
            }
            match map_rx.recv().await {
                Some(Ok(resp)) => {
                    if resp.KeepAlive {
                        continue;
                    }

                    // Merge peer deltas.
                    {
                        let mut peers = peers_arc.write().await;
                        if !resp.Peers.is_empty() {
                            *peers = resp.Peers.clone();
                        }
                        if !resp.PeersChanged.is_empty() {
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

                    // Feed the updated peer list to magicsock + rebuild routes.
                    let peers = peers_arc.read().await.clone();
                    let _ = magicsock.set_netmap(peers.clone()).await;
                    route_table.write().await.rebuild(&peers);

                    // Create WG tunnels for new peers.
                    let mut tunnels = wg_tunnels.write().await;
                    for peer in &peers {
                        if peer.Key.is_zero() {
                            continue;
                        }
                        if !tunnels.contains_key(&peer.Key) {
                            if let Ok(t) = WgTunn::new(&node_key, &peer.Key, rand_index()) {
                                tunnels.insert(peer.Key.clone(), Arc::new(Mutex::new(t)));
                            }
                        }
                    }
                    drop(tunnels);

                    // Process PacketFilter / PacketFilters deltas and rebuild
                    // the filter if anything changed.
                    let filter_changed = process_filter_deltas(&resp, &mut named_filters);
                    if filter_changed {
                        rebuild_filter(&filter_arc, &named_filters, &tailscale_ips);
                    }
                }
                Some(Err(_)) | None => break,
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Packet filter helpers
// ---------------------------------------------------------------------------

/// Build a [`Filter`] from a [`MapResponse`]'s PacketFilter/PacketFilters
/// fields. Returns the filter and the initial named-filter map.
fn build_filter_from_map_response(
    resp: &MapResponse,
    local_ips: &[IpAddr],
) -> (Filter, BTreeMap<String, Vec<FilterRule>>) {
    let mut named: BTreeMap<String, Vec<FilterRule>> = BTreeMap::new();

    // PacketFilter (singular): sets the "base" key.
    if let Some(pf) = &resp.PacketFilter {
        named.insert("base".into(), pf.clone());
    }

    // PacketFilters (plural): named delta updates.
    if let Some(pfs) = &resp.PacketFilters {
        // "*" with None = clear all.
        if let Some(None) = pfs.get("*") {
            named.clear();
        }
        for (key, val) in pfs {
            if key == "*" {
                continue;
            }
            match val {
                None => {
                    named.remove(key);
                }
                Some(rules) if rules.is_empty() => {
                    named.remove(key);
                }
                Some(rules) => {
                    named.insert(key.clone(), rules.clone());
                }
            }
        }
    }

    // If no rules at all, default to allow-all (matches Go behavior when
    // the control server sends no filter).
    let all_rules: Vec<FilterRule> = if named.is_empty() {
        rustscale_tailcfg::filter_allow_all()
    } else {
        named.values().flatten().cloned().collect()
    };

    let filter = Filter::new(&all_rules, local_ips).unwrap_or_else(|_| Filter::allow_all());
    (filter, named)
}

/// Process PacketFilter/PacketFilters deltas from a MapResponse into the
/// named-filter map. Returns true if the map changed (and the filter should
/// be rebuilt).
fn process_filter_deltas(
    resp: &MapResponse,
    named: &mut BTreeMap<String, Vec<FilterRule>>,
) -> bool {
    let mut changed = false;

    if let Some(pf) = &resp.PacketFilter {
        named.insert("base".into(), pf.clone());
        changed = true;
    }

    if let Some(pfs) = &resp.PacketFilters {
        if let Some(None) = pfs.get("*") {
            named.clear();
            changed = true;
        }
        for (key, val) in pfs {
            if key == "*" {
                continue;
            }
            match val {
                None => {
                    if named.remove(key).is_some() {
                        changed = true;
                    }
                }
                Some(rules) if rules.is_empty() => {
                    if named.remove(key).is_some() {
                        changed = true;
                    }
                }
                Some(rules) => {
                    named.insert(key.clone(), rules.clone());
                    changed = true;
                }
            }
        }
    }

    changed
}

/// Rebuild the filter from the named-filter map and update the shared
/// `Arc<Mutex<Filter>>`.
fn rebuild_filter(
    filter_arc: &Arc<std::sync::Mutex<Filter>>,
    named: &BTreeMap<String, Vec<FilterRule>>,
    local_ips: &[IpAddr],
) {
    let all_rules: Vec<FilterRule> = if named.is_empty() {
        rustscale_tailcfg::filter_allow_all()
    } else {
        named.values().flatten().cloned().collect()
    };
    if let Ok(new_filter) = Filter::new(&all_rules, local_ips) {
        *filter_arc.lock().unwrap() = new_filter;
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

/// Extract the first IPv4 from a list of tailnet IPs.
fn first_v4(ips: &[IpAddr]) -> Result<Ipv4Addr, TsnetError> {
    ips.iter()
        .find_map(|ip| match ip {
            IpAddr::V4(v4) => Some(*v4),
            _ => None,
        })
        .ok_or_else(|| TsnetError::Builder("no IPv4 tailnet address".into()))
}

/// Bring the TUN interface up and add tailnet routes. Requires root.
///
/// On macOS: `ifconfig <name> up <our_v4>/32`, `route add 100.64.0.0/10 -interface <name>`.
/// On Linux: `ip link set <name> up`, `ip addr add <our_v4>/32 dev <name>`,
/// `ip route add 100.64.0.0/10 dev <name>`.
fn apply_tun_routes(ifname: &str, tailscale_ips: &[IpAddr], _mtu: usize) -> Result<(), TsnetError> {
    let our_v4 = first_v4(tailscale_ips)?;
    let v4_str = our_v4.to_string();

    #[cfg(target_os = "macos")]
    {
        run_cmd(
            "ifconfig",
            &["-v", ifname, "inet", &format!("{v4_str}/32"), "up"],
        )?;
        run_cmd(
            "route",
            &["-q", "add", "-net", "100.64.0.0/10", "-interface", ifname],
        )?;
    }
    #[cfg(target_os = "linux")]
    {
        run_cmd("ip", &["link", "set", ifname, "up"])?;
        run_cmd(
            "ip",
            &["addr", "add", &format!("{v4_str}/32"), "dev", ifname],
        )?;
        run_cmd("ip", &["route", "add", "100.64.0.0/10", "dev", ifname])?;
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (ifname, v4_str);
    }
    Ok(())
}

/// Run a command, returning an error if it exits non-zero.
fn run_cmd(prog: &str, args: &[&str]) -> Result<(), TsnetError> {
    let status = std::process::Command::new(prog)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .status()
        .map_err(|e| TsnetError::Builder(format!("spawn {prog}: {e}")))?;
    if !status.success() {
        return Err(TsnetError::Builder(format!(
            "{prog} {:?} exited with {status}",
            args
        )));
    }
    Ok(())
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
