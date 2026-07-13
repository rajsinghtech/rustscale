//! Path-selection engine for rustscale: direct UDP, DERP relay, and peer relay.
//!
//! Ports the semantics of Go's `wgengine/magicsock` in simplified form. Owns
//! UDP sockets (v4+v6), a set of DERP client connections (one per region,
//! lazily created), and per-peer endpoint state. Disco ping/pong probing
//! discovers direct paths; CallMeMaybe via DERP punches NAT; DERP is the
//! fallback data path.
//!
//! # Multi-region DERP routing
//!
//! Each peer has a `HomeDERP` region (assigned by the control plane). To reach
//! a peer via DERP, we must send to the **peer's** home DERP region, not our
//! own. The [`DerpManager`] lazily opens connections to regions on first use
//! and reuses them thereafter. Recv tasks for all connected regions feed the
//! same WG/disco demux path.
//!
//! # API
//!
//! - [`Magicsock::new`] — bind UDP, connect home DERP (if provided), start I/O.
//! - [`Magicsock::set_netmap`] — create/update peer endpoints, start probing.
//! - [`Magicsock::send`] — send a WG datagram to a peer over the best path.

#![deny(unsafe_code)]

mod derp_io;
mod disco_io;
mod endpoint;
mod pmtud;
mod relay;
mod relay_manager;
mod relay_server;

pub use endpoint::{
    BestPath, DiscoPingPurpose, Endpoint, PathClass, PendingPing, ProbeUDPLifetime,
    TRUST_BEST_ADDR_DURATION,
};
pub use relay::{
    decode_geneve, decode_geneve_full, encode_geneve, encode_geneve_disco,
    encode_geneve_disco_control, encode_geneve_wireguard, looks_like_geneve_disco,
    looks_like_geneve_wireguard, RelayHandshake, RelayPhase, GENEVE_HEADER_LEN,
    GENEVE_PROTOCOL_DISCO, GENEVE_PROTOCOL_WIREGUARD,
};
pub use relay_manager::{
    discover_relay_servers, spawn_relay_manager, CandidatePeerRelay, RelayManagerContext,
    RelayManagerHandle, ServerEndpoint,
};
pub use relay_server::RelayServerExtension;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use rustscale_derp::DerpClient;
use rustscale_disco::{CallMeMaybe, Message, Ping, Pong};
use rustscale_key::{DiscoPrivate, DiscoPublic, NodePrivate, NodePublic};
use rustscale_neterror::treat_as_lost_udp;
use rustscale_tailcfg::{DERPMap, Node};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use derp_io::{DerpEvent, DerpIo};
use disco_io::DiscoIo;

/// Heartbeat interval: how often to ping the best UDP path to keep it alive.
/// Mirrors Go's `heartbeatInterval` (magicsock.go:4032).
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(3);

/// Session active timeout: how long since last activity before the session is
/// considered idle and heartbeats stop. Mirrors Go's `sessionActiveTimeout`
/// (magicsock.go:4016).
const SESSION_ACTIVE_TIMEOUT: Duration = Duration::from_secs(45);

/// How long to wait for a pong reply before considering a ping timed out.
/// Mirrors Go's `pingTimeoutDuration` (magicsock.go:4052).
const PING_TIMEOUT_DURATION: Duration = Duration::from_secs(5);

/// Minimum interval between full candidate discovery rounds started by data.
const DISCOVERY_PING_INTERVAL: Duration = Duration::from_secs(5);

/// Slack subtracted from a UDP lifetime cliff duration when scheduling a
/// probe. Mirrors Go's `udpLifetimeProbeCliffSlack` (endpoint.go:164).
const UDP_LIFETIME_CLIFF_SLACK: Duration = Duration::from_secs(2);

/// MTU sizes to probe when PMTUD is enabled. Mirrors Go's
/// `tstun.WireMTUsToProbe` (net/tstun/mtu.go:85).
const WIRE_MTUS_TO_PROBE: &[usize] = &[1280, 1320, 1400, 1500, 8000, 9000];

/// Size of a complete disco ping packet without any padding.
/// `MAGIC(6) + sender_pub(32) + nonce(24) + tag(16) + header(2) + ping(44)`.
/// Mirrors Go's `discoPingSize` (endpoint.go:1249-1250).
const DISCO_PING_SIZE: usize = 124;

/// Errors from magicsock operations.
#[derive(Debug, thiserror::Error)]
pub enum MagicsockError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("derp error: {0}")]
    Derp(#[from] rustscale_derp::DerpError),
    #[error("no usable path to peer")]
    NoPath,
    #[error("peer not found in netmap")]
    PeerNotFound,
    #[error("ping timed out")]
    Timeout,
}

/// Configuration for constructing a [`Magicsock`].
pub struct MagicsockConfig {
    /// Our WireGuard node private key.
    pub private_key: NodePrivate,
    /// Our disco private key (for NAT-traversal path discovery).
    pub disco_key: DiscoPrivate,
    /// An already-connected DERP client for our home region, if any.
    /// `None` means DERP is not used (unless `derp_map` is provided for
    /// lazy connections).
    pub derp_client: Option<DerpClient>,
    /// The DERPMap for lazy multi-region connections. When provided, magicsock
    /// can connect to any peer's home DERP region on demand. The home region
    /// connection from `derp_client` is registered as region `home_derp_region`.
    pub derp_map: Option<DERPMap>,
    /// Our home DERP region ID (used to register the pre-connected
    /// `derp_client`). 0 if unknown.
    pub home_derp_region: i32,
    /// Optional UDP bind address (`None` = no direct UDP; DERP-only mode).
    /// Ignored when `udp_socket` is provided.
    pub udp_bind: Option<SocketAddr>,
    /// An already-bound UDP socket to use instead of binding from `udp_bind`.
    /// When provided, magicsock takes ownership and starts the recv task on
    /// it. This lets the caller bind early, gather local interface endpoints
    /// from the bound port, and advertise them in the MapRequest before
    /// magicsock is fully constructed (magicsock otherwise needs the DERPMap
    /// from the first MapResponse, which is sent after endpoints are set).
    pub udp_socket: Option<Arc<UdpSocket>>,
    /// Optional port-mapping client (NAT-PMP/PCP/UPnP). When provided,
    /// magicsock publishes the port-mapped external endpoint alongside its
    /// local/STUN endpoints. Best-effort: never blocks or fails endpoint
    /// gathering if no portmapper is present.
    pub portmapper: Option<rustscale_portmapper::Client>,
    /// Optional health tracker. When provided, magicsock reports DERP home
    /// region connection state (healthy on connect, unhealthy on failure).
    pub health: Option<rustscale_health::Tracker>,
    /// Test-support: when true, suppress all direct-path establishment and
    /// force direct sends via DERP. Disco pings are not sent in `set_netmap`,
    /// CallMeMaybe-initiated pings are skipped, and inbound disco Pings over
    /// UDP are not answered — so neither side confirms a direct path. `send`
    /// also ignores any Direct best path and routes via DERP. Relay paths
    /// (established by the relay manager) still work normally — this flag
    /// only suppresses direct UDP, not relay UDP. Production code should
    /// leave this false.
    pub disable_direct_paths: bool,
    /// When true, start a `udprelay::Server` and handle incoming
    /// `AllocateUDPRelayEndpointRequest` disco messages received via DERP.
    /// Sets `Hostinfo.PeerRelay = true` at the tsnet layer. Default false.
    pub peer_relay_server: bool,
    /// Optional override for the relay server's `ServerConfig`. When `None`,
    /// defaults are used (30s bind lifetime, 5min steady-state). Tests use
    /// shortened lifetimes. Only effective when `peer_relay_server` is true.
    pub relay_server_config: Option<rustscale_udprelay::ServerConfig>,
    /// Optional socket-statistics registry. When provided, magicsock records
    /// UDP TX/RX bytes per label (`MagicsockConnUDP4` / `MagicsockConnUDP6`).
    /// Best-effort: instrumentation never affects send/recv error paths.
    pub sockstats: Option<Arc<rustscale_sockstats::SockStats>>,
    /// Optional control knobs for PMTUD and other feature toggles.
    /// When provided, `update_pmtud` reads `PeerMTUEnable` from the knobs.
    pub control_knobs: Option<Arc<rustscale_controlknobs::ControlKnobs>>,
}

/// A received WG datagram with its sender identified.
pub struct WgDatagram {
    /// The peer's WireGuard public key.
    pub peer: NodePublic,
    /// The raw WG ciphertext datagram.
    pub data: Vec<u8>,
}

/// The path-selection engine.
pub struct Magicsock {
    inner: Arc<Inner>,
}

struct Inner {
    node_public: RwLock<NodePublic>,
    disco: DiscoIo,
    udp: Option<Arc<UdpSocket>>,
    local_udp_addrs: RwLock<Vec<String>>,
    /// Multi-region DERP connection manager.
    derp: DerpManager,
    endpoints: RwLock<HashMap<NodePublic, Endpoint>>,
    disco_to_peer: RwLock<HashMap<DiscoPublic, NodePublic>>,
    addr_to_peer: RwLock<HashMap<SocketAddr, NodePublic>>,
    wg_send: mpsc::Sender<WgDatagram>,
    /// Optional port-mapping client for NAT-PMP/PCP/UPnP external endpoints.
    portmapper: Option<rustscale_portmapper::Client>,
    /// Test-support: suppress direct paths and force DERP (see MagicsockConfig).
    disable_direct_paths: bool,
    /// Relay manager for peer relay discovery, allocation, and handshake.
    /// Stored in a RwLock because the relay manager's event loop holds an
    /// Arc<Inner> (for RelayManagerContext), creating a circular reference
    /// that prevents Arc::get_mut from working at construction time.
    relay_manager: RwLock<Option<RelayManagerHandle>>,
    /// Relay server extension: owns a `udprelay::Server` when this node is
    /// configured as a relay server. Handles `AllocateUDPRelayEndpointRequest`
    /// disco messages received via DERP.
    relay_server: Option<Arc<RelayServerExtension>>,
    /// Self node's CapMap — used to check `NODE_ATTR_DISABLE_RELAY_SERVER`.
    self_cap_map: Arc<RwLock<rustscale_tailcfg::NodeCapMap>>,
    /// Whether peer path MTU discovery is enabled. Disabled by default,
    /// matching Go's `ShouldPMTUD` returning false (peermtu.go:56).
    peer_mtu_enabled: Arc<AtomicBool>,
    /// Optional control knobs for PMTUD and other feature toggles.
    control_knobs: Option<Arc<rustscale_controlknobs::ControlKnobs>>,
    /// Per-peer background task handles (heartbeat + UDP lifetime probe).
    /// At most one task per peer; replaced on new TX activity.
    background_tasks: RwLock<HashMap<NodePublic, tokio::task::JoinHandle<()>>>,
    /// Last NetInfo received from control (or from local probing). Used to
    /// deduplicate updates and track PreferredDERP / connectivity changes.
    net_info: RwLock<Option<rustscale_tailcfg::NetInfo>>,
    /// Per-label socket TX/RX counters for magicsock's UDP socket.
    /// `None` when no sockstats registry was injected. Best-effort: recording
    /// is a relaxed atomic increment and never affects send/recv error paths.
    sockstats_udp4: Option<rustscale_sockstats::LabelHandle>,
    sockstats_udp6: Option<rustscale_sockstats::LabelHandle>,
    /// Pending CLI-initiated pings, keyed by peer node key. When a pong
    /// arrives with `DiscoPingPurpose::CLI`, the matching sender is fired
    /// with the latency and endpoint info. Mirrors Go's callback-based
    /// `Conn.Ping` (magicsock.go:1181-1206).
    cli_ping_callbacks: RwLock<
        HashMap<
            NodePublic,
            HashMap<u64, tokio::sync::oneshot::Sender<rustscale_ipnstate::PingResult>>,
        >,
    >,
    next_cli_ping_id: AtomicU64,
}

/// Manages DERP connections across multiple regions.
///
/// The home region connection is provided at construction time (from the
/// pre-connected `DerpClient`). Connections to other regions are created
/// lazily on first send to a peer whose `HomeDERP` is in that region.
/// All connections' recv tasks feed the same `wg_send` + disco demux path
/// via a shared packet channel.
struct DerpManager {
    /// region_id -> DerpIo connection.
    connections: RwLock<HashMap<i32, Arc<DerpIo>>>,
    /// The DERPMap for looking up region configs when lazily connecting.
    derp_map: RwLock<Option<DERPMap>>,
    /// Our node private key (needed to establish new DERP connections).
    node_private: NodePrivate,
    /// Our home DERP region (for diagnostics + health reporting).
    home_region: i32,
    /// Channel for DERP recv tasks to forward received packets to the main
    /// demux loop. Each lazy connection spawns a recv task that sends to
    /// this channel.
    derp_recv_tx: mpsc::Sender<(i32, DerpEvent)>,
    /// Channel for DERP recv consumers to signal that their underlying
    /// connection has died and needs reconnection. The reconnect supervisor
    /// task (spawned in [`spawn_recv_tasks`]) listens on this channel and
    /// calls [`DerpManager::reconnect_region`] with exponential backoff.
    reconnect_tx: mpsc::UnboundedSender<i32>,
    /// Optional health tracker for reporting DERP home reachability.
    health: Option<rustscale_health::Tracker>,
}

impl DerpManager {
    fn new(
        home_client: Option<DerpClient>,
        derp_map: Option<DERPMap>,
        node_private: NodePrivate,
        home_region: i32,
        health: Option<rustscale_health::Tracker>,
    ) -> (
        Self,
        mpsc::Receiver<(i32, DerpEvent)>,
        mpsc::UnboundedReceiver<i32>,
    ) {
        let (derp_recv_tx, derp_recv_rx) = mpsc::channel(256);
        let (reconnect_tx, reconnect_rx) = mpsc::unbounded_channel();

        let mut connections = HashMap::new();

        // Register the pre-connected home region client.
        if let Some(client) = home_client {
            let region = if home_region > 0 { home_region } else { 1 };
            let io = Arc::new(DerpIo::spawn(client));
            spawn_derp_recv_consumer(
                region,
                io.clone(),
                derp_recv_tx.clone(),
                reconnect_tx.clone(),
            );
            connections.insert(region, io);
        }

        let mgr = Self {
            connections: RwLock::new(connections),
            derp_map: RwLock::new(derp_map),
            node_private,
            home_region,
            derp_recv_tx,
            reconnect_tx,
            health,
        };

        (mgr, derp_recv_rx, reconnect_rx)
    }

    /// Get the DerpIo for a region, lazily connecting if needed.
    /// Returns None if the region is unknown or connection fails.
    async fn get_or_connect(&self, region_id: i32) -> Option<Arc<DerpIo>> {
        // Fast path: already connected.
        {
            let conns = self
                .connections
                .read()
                .expect("derp connections lock poisoned");
            if let Some(io) = conns.get(&region_id) {
                return Some(io.clone());
            }
        }

        // Slow path: look up the region config and connect.
        let derp_map = self
            .derp_map
            .read()
            .expect("derp_map lock poisoned")
            .clone();
        let map = derp_map?;
        let region = map.Regions.get(&region_id)?;
        let nodes = region.Nodes.as_ref()?;
        let node = nodes
            .iter()
            .find(|n| !n.STUNOnly)
            .or_else(|| nodes.first())?;

        let port = if node.DERPPort > 0 {
            node.DERPPort as u16
        } else {
            443
        };
        let tls_host = node.HostName.clone();
        let dial_addr = if !node.IPv4.is_empty() && node.IPv4 != "none" {
            node.IPv4.clone()
        } else {
            node.HostName.clone()
        };

        if debug_enabled() {
            eprintln!(
                "DBG derp_connect region={region_id} host={dial_addr}:{port} name={}",
                region.RegionName
            );
        }

        let client = match DerpClient::connect_with_upgrade_dial_insecure(
            &dial_addr,
            &tls_host,
            port,
            !node.InsecureForTests,
            node.InsecureForTests,
            self.node_private.clone(),
            None,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                if debug_enabled() {
                    eprintln!("DBG derp_connect region={region_id} FAILED: {e}");
                }
                // Report DERP home unreachability for the home region.
                if region_id == self.home_region {
                    if let Some(ref health) = self.health {
                        health.set_unhealthy(
                            rustscale_health::WARN_DERP_HOME,
                            format!("derp home region {region_id} unreachable: {e}"),
                        );
                    }
                }
                // Report the per-region connection-down warnable.
                if let Some(ref health) = self.health {
                    health.set_unhealthy(
                        rustscale_health::WARN_NO_DERP_CONNECTION,
                        format!(
                            "{{\"{}\":{},\"{}\":\"\",\"{}\":\"{}\"}}",
                            rustscale_health::ARG_DERP_REGION_ID,
                            region_id,
                            rustscale_health::ARG_DERP_REGION_NAME,
                            rustscale_health::ARG_ERROR,
                            e,
                        ),
                    );
                }
                return None;
            }
        };

        if debug_enabled() {
            eprintln!("DBG derp_connect region={region_id} OK");
        }

        // Report DERP home healthy on successful (re)connect.
        if region_id == self.home_region {
            if let Some(ref health) = self.health {
                health.set_healthy(rustscale_health::WARN_DERP_HOME);
            }
        }
        // Clear the per-region connection-down warnable on success.
        if let Some(ref health) = self.health {
            health.set_healthy(rustscale_health::WARN_NO_DERP_CONNECTION);
        }

        let io = Arc::new(DerpIo::spawn(client));

        // Insert and spawn recv consumer.
        {
            let mut conns = self
                .connections
                .write()
                .expect("derp connections lock poisoned");
            // Another task may have connected in the meantime; reuse if so.
            if let Some(existing) = conns.get(&region_id) {
                return Some(existing.clone());
            }
            conns.insert(region_id, io.clone());
        }

        spawn_derp_recv_consumer(
            region_id,
            io.clone(),
            self.derp_recv_tx.clone(),
            self.reconnect_tx.clone(),
        );

        Some(io)
    }

    /// Reconnect to a DERP region after the previous connection died.
    /// Removes the stale connection from the map, then retries with
    /// exponential backoff (2 s, 4 s, 8 s, …, 60 s cap) until a new
    /// connection is established or the region is no longer in the
    /// DERPMap. [`get_or_connect`] spawns the new recv consumer
    /// automatically on success.
    async fn reconnect_region(&self, region_id: i32) {
        // Remove the dead connection (if still present) and abort its tasks.
        {
            let mut conns = self
                .connections
                .write()
                .expect("derp connections lock poisoned");
            if let Some(old_io) = conns.remove(&region_id) {
                old_io.close();
            }
        }

        // If the region doesn't exist in the DERPMap, there's nothing to
        // reconnect to — give up.
        let has_region = {
            let map = self.derp_map.read().expect("derp_map lock poisoned");
            map.as_ref()
                .is_some_and(|m| m.Regions.contains_key(&region_id))
        };
        if !has_region {
            if debug_enabled() {
                eprintln!("DBG derp_reconnect region={region_id} no DERPMap entry, giving up");
            }
            return;
        }

        let mut delay = Duration::from_secs(2);
        let max_delay = Duration::from_secs(60);

        loop {
            if debug_enabled() {
                eprintln!("DBG derp_reconnect region={region_id} attempt delay={delay:?}");
            }
            tokio::time::sleep(delay).await;

            if self.get_or_connect(region_id).await.is_some() {
                if debug_enabled() {
                    eprintln!("DBG derp_reconnect region={region_id} OK");
                }
                return;
            }

            if debug_enabled() {
                eprintln!("DBG derp_reconnect region={region_id} failed, backing off");
            }
            delay = (delay * 2).min(max_delay);
        }
    }

    /// Send a packet to `dst` via the DERP server for `region_id`.
    async fn send_packet(&self, region_id: i32, dst: NodePublic, data: Vec<u8>) -> bool {
        // Try to get the connection without awaiting (fast path).
        let io = {
            let conns = self
                .connections
                .read()
                .expect("derp connections lock poisoned");
            conns.get(&region_id).cloned()
        };

        let io = match io {
            Some(io) => io,
            None => {
                if let Some(io) = self.get_or_connect(region_id).await {
                    io
                } else {
                    eprintln!(
                        "magicsock: no DERP connection to region {region_id} for peer, dropping"
                    );
                    return false;
                }
            }
        };

        io.send_packet(dst, data).await;
        true
    }

    /// The home DERP region ID.
    fn home_region(&self) -> i32 {
        self.home_region
    }

    /// Close all DERP connections so they reconnect lazily on next use.
    fn close_all(&self) {
        let conns: Vec<Arc<DerpIo>> = {
            let mut conns = self
                .connections
                .write()
                .expect("derp connections lock poisoned");
            conns.drain().map(|(_, io)| io).collect()
        };
        for io in conns {
            io.close();
        }
    }
}

/// Spawn a task that reads from a DerpIo connection and forwards received
/// events to the shared derp_recv channel for demux. When the underlying
/// connection dies (reader task exits, `try_recv` returns `None`), the
/// region is signaled for automatic reconnection via `reconnect_tx`.
fn spawn_derp_recv_consumer(
    region_id: i32,
    io: Arc<DerpIo>,
    tx: mpsc::Sender<(i32, DerpEvent)>,
    reconnect_tx: mpsc::UnboundedSender<i32>,
) {
    tokio::spawn(async move {
        while let Some(event) = io.try_recv().await {
            if tx.send((region_id, event)).await.is_err() {
                break;
            }
        }
        // Recv loop exited — the underlying DERP connection has died.
        // Signal for reconnection with exponential backoff.
        let _ = reconnect_tx.send(region_id);
    });
}

impl Magicsock {
    /// Create a new Magicsock: bind UDP (if configured), connect DERP, and
    /// launch background I/O tasks.
    ///
    /// Returns the Magicsock and the WG datagram receiver. The caller should
    /// move the receiver into the pump task that consumes WG packets — it is
    /// a single-consumer channel, so there is no need for a Mutex.
    pub async fn new(
        config: MagicsockConfig,
    ) -> Result<(Self, mpsc::Receiver<WgDatagram>), MagicsockError> {
        let node_public = config.private_key.public();
        let disco = DiscoIo::new(config.disco_key);

        let (wg_send, wg_recv) = mpsc::channel(256);

        // Bind UDP socket if configured. A pre-bound socket (udp_socket)
        // takes precedence over udp_bind.
        let (udp, local_udp_addrs) = if let Some(sock) = config.udp_socket {
            let port = sock.local_addr()?.port();
            let eps = gather_local_endpoints(port);
            if debug_enabled() && !eps.is_empty() {
                eprintln!("DBG magicsock local endpoints: {eps:?}");
            }
            (Some(sock), eps)
        } else if let Some(bind_addr) = config.udp_bind {
            let sock = UdpSocket::bind(bind_addr).await?;
            let port = sock.local_addr()?.port();
            // Gather local interface endpoints: the bound UDP port paired
            // with each up, non-link-local IPv4 address on the host (plus
            // loopback). This mirrors Go magicsock's determineEndpoints
            // (local interface enumeration) so peers on the same LAN/host
            // can disco-ping us directly instead of falling back to DERP.
            // Without this, two nodes on the same machine never publish
            // usable candidates and stay on the DERP relay path.
            let eps = gather_local_endpoints(port);
            if debug_enabled() && !eps.is_empty() {
                eprintln!("DBG magicsock local endpoints: {eps:?}");
            }
            (Some(Arc::new(sock)), eps)
        } else {
            (None, Vec::new())
        };

        // Create the DERP manager with the home region connection + DERPMap.
        let (derp, derp_recv_rx, reconnect_rx) = DerpManager::new(
            config.derp_client,
            config.derp_map,
            config.private_key.clone(),
            config.home_derp_region,
            config.health.clone(),
        );

        // Self node's CapMap — shared between Inner and RelayServerExtension.
        let self_cap_map = Arc::new(RwLock::new(std::collections::BTreeMap::new()));

        // Per-label UDP sockstat handles (best-effort, fire-and-forget).
        let (sockstats_udp4, sockstats_udp6) = match &config.sockstats {
            Some(stats) => (
                Some(stats.label_handle(rustscale_sockstats::Label::MagicsockConnUDP4)),
                Some(stats.label_handle(rustscale_sockstats::Label::MagicsockConnUDP6)),
            ),
            None => (None, None),
        };

        // Start the relay server extension if enabled.
        let relay_server = if config.peer_relay_server {
            let ext =
                RelayServerExtension::new(true, config.relay_server_config, self_cap_map.clone())
                    .await;
            Some(Arc::new(ext))
        } else {
            None
        };

        let inner = Arc::new(Inner {
            node_public: RwLock::new(node_public),
            disco,
            udp,
            local_udp_addrs: RwLock::new(local_udp_addrs),
            derp,
            endpoints: RwLock::new(HashMap::new()),
            disco_to_peer: RwLock::new(HashMap::new()),
            addr_to_peer: RwLock::new(HashMap::new()),
            wg_send,
            portmapper: config.portmapper,
            disable_direct_paths: config.disable_direct_paths,
            relay_manager: RwLock::new(None),
            relay_server,
            self_cap_map,
            peer_mtu_enabled: Arc::new(AtomicBool::new(false)),
            control_knobs: config.control_knobs,
            background_tasks: RwLock::new(HashMap::new()),
            net_info: RwLock::new(None),
            sockstats_udp4,
            sockstats_udp6,
            cli_ping_callbacks: RwLock::new(HashMap::new()),
            next_cli_ping_id: AtomicU64::new(1),
        });

        // Spawn the relay manager event loop. The handle is stored in Inner
        // for use by set_netmap and disco receive paths. We use RwLock
        // because spawn_relay_manager takes an Arc<Inner> clone (for the
        // RelayManagerContext impl), preventing Arc::get_mut.
        let rm_handle = relay_manager::spawn_relay_manager(inner.clone());
        {
            let mut guard = inner
                .relay_manager
                .write()
                .expect("relay_manager lock poisoned");
            *guard = Some(rm_handle);
        }

        // Launch background recv tasks (UDP + DERP demux + reconnect supervisor).
        spawn_recv_tasks(inner.clone(), derp_recv_rx, reconnect_rx);

        Ok((Self { inner }, wg_recv))
    }

    /// Our node public key.
    pub fn node_public(&self) -> NodePublic {
        self.inner
            .node_public
            .read()
            .expect("node_public lock poisoned")
            .clone()
    }

    /// The home DERP region ID.
    pub fn home_derp_region(&self) -> i32 {
        self.inner.derp.home_region()
    }

    /// Update the node private key after a key rotation. Updates the
    /// stored node public key so subsequent disco messages, relay
    /// negotiations, and netmap self-checks use the new identity.
    /// Existing WG tunnels should be cleared and recreated separately
    /// to pick up the new key.
    pub fn set_node_key(&self, new_key: &NodePrivate) {
        let new_pub = new_key.public();
        *self
            .inner
            .node_public
            .write()
            .expect("node_public lock poisoned") = new_pub;
    }

    /// Our disco public key.
    pub fn disco_public(&self) -> DiscoPublic {
        self.inner.disco.public()
    }

    /// Our local UDP addresses (for sharing in CallMeMaybe).
    pub fn local_udp_addrs(&self) -> Vec<String> {
        self.inner
            .local_udp_addrs
            .read()
            .expect("local_udp_addrs lock poisoned")
            .clone()
    }

    /// The actual address the UDP socket is bound on, if any. This is the
    /// address peers should use to reach us when the socket is bound to a
    /// specific interface (e.g. loopback in tests). Distinct from
    /// `local_udp_addrs`, which enumerates all host interface IPs paired
    /// with the port for control-plane advertisement.
    pub fn bound_udp_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.udp.as_ref()?.local_addr().ok()
    }

    /// Local interface endpoints (IP:port) to advertise in the MapRequest
    /// `Endpoints` field and in CallMeMaybe. Includes the bound UDP port
    /// paired with each up, non-link-local IPv4 interface address on the
    /// host (plus loopback for same-machine direct paths).
    pub fn local_endpoints(&self) -> Vec<String> {
        self.inner
            .local_udp_addrs
            .read()
            .expect("local_udp_addrs lock poisoned")
            .clone()
    }

    /// Best-effort port-mapped external endpoint (from NAT-PMP/PCP/UPnP),
    /// if a portmapper client was provided and has a cached mapping.
    /// Non-blocking: returns `None` immediately if no mapping is cached.
    /// The background creation task (started by
    /// `get_cached_mapping_or_start_creating_one`) will populate the cache
    /// asynchronously.
    pub fn portmap_endpoint(&self) -> Option<String> {
        let pm = self.inner.portmapper.as_ref()?;
        let (ext, ok) = pm.get_cached_mapping_or_start_creating_one();
        if ok {
            ext.map(|addr| addr.to_string())
        } else {
            None
        }
    }

    /// All endpoints to advertise: local interface endpoints + port-mapped
    /// external endpoint (if available). Best-effort: portmap failure never
    /// blocks or reduces the local endpoint set.
    pub fn all_endpoints(&self) -> Vec<String> {
        let mut eps = self.local_endpoints();
        if let Some(pm_ep) = self.portmap_endpoint() {
            if !eps.contains(&pm_ep) {
                eps.push(pm_ep);
            }
        }
        eps
    }

    /// Start a background port-mapping probe + creation task (best-effort,
    /// 2 s overall timeout). No-op if no portmapper client was configured.
    pub fn start_portmap(&self) {
        if let Some(pm) = &self.inner.portmapper {
            // Probe in the background; the result populates the cache that
            // `portmap_endpoint` reads.
            let pm = pm.clone();
            tokio::spawn(async move {
                let _ = tokio::time::timeout(std::time::Duration::from_secs(2), pm.probe()).await;
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    pm.create_or_get_mapping(),
                )
                .await;
            });
        }
    }

    /// Update the peer set from a netmap. Creates/updates per-peer endpoints,
    /// starts disco probing, and sends CallMeMaybe via the peer's home DERP.
    pub async fn set_netmap(&self, peers: Vec<Node>) -> Result<(), MagicsockError> {
        // Phase 1: update endpoint state under the lock.
        let probe_list: Vec<(NodePublic, DiscoPublic, Vec<SocketAddr>, i32)> = {
            let mut endpoints = self
                .inner
                .endpoints
                .write()
                .expect("endpoints lock poisoned");
            let mut d2p = self
                .inner
                .disco_to_peer
                .write()
                .expect("disco_to_peer lock poisoned");

            let mut probes = Vec::new();
            for peer in &peers {
                if peer.Key.is_zero() {
                    continue;
                }
                let candidates: Vec<SocketAddr> = peer
                    .Endpoints
                    .iter()
                    .filter_map(|s| s.parse().ok())
                    .collect();

                let ep = endpoints.entry(peer.Key.clone()).or_insert_with(|| {
                    Endpoint::new(peer.Key.clone(), peer.DiscoKey.clone(), peer.HomeDERP)
                });

                // An existing endpoint must follow netmap disco-key updates:
                // CLI pings and discovery read the key from the endpoint.
                // Only remove the old reverse mapping if it still belongs to
                // this peer; another peer may have claimed it in the meantime.
                if let Some(previous_disco) = ep.update_peer_disco_key(peer.DiscoKey.clone()) {
                    if !previous_disco.is_zero()
                        && d2p
                            .get(&previous_disco)
                            .is_some_and(|mapped_peer| mapped_peer == &peer.Key)
                    {
                        d2p.remove(&previous_disco);
                    }
                }

                // Update HomeDERP if it changed.
                if peer.HomeDERP != ep.home_derp() {
                    ep.set_home_derp(peer.HomeDERP);
                }

                ep.set_candidates(candidates.clone());
                ep.reset_call_me_maybe();

                if !peer.DiscoKey.is_zero() {
                    d2p.insert(peer.DiscoKey.clone(), peer.Key.clone());
                }

                probes.push((
                    peer.Key.clone(),
                    peer.DiscoKey.clone(),
                    candidates,
                    ep.derp_send_region(),
                ));
                if debug_enabled() {
                    eprintln!(
                        "DBG set_netmap peer={} HomeDERP={} candidates={} disco_zero={}",
                        peer.Name,
                        peer.HomeDERP,
                        peer.Endpoints.len(),
                        peer.DiscoKey.is_zero(),
                    );
                }
            }
            probes
        };

        // Phase 2: send disco pings and CallMeMaybe (async, outside the lock).
        // When disable_direct_paths is set, skip all direct-path probing —
        // both sides stay on DERP.
        for (peer_key, peer_disco, candidates, derp_region) in probe_list {
            // Send disco Pings to each candidate over UDP.
            if !self.inner.disable_direct_paths && self.inner.udp.is_some() {
                for addr in &candidates {
                    self.inner
                        .send_disco_ping(
                            &peer_key,
                            &peer_disco,
                            *addr,
                            DiscoPingPurpose::Discovery,
                            0,
                            None,
                        )
                        .await;
                }

                // Send CallMeMaybe via the peer's home DERP region.
                if !peer_disco.is_zero() {
                    let should = {
                        let mut endpoints = self
                            .inner
                            .endpoints
                            .write()
                            .expect("endpoints lock poisoned");
                        endpoints
                            .get_mut(&peer_key)
                            .is_some_and(endpoint::Endpoint::should_send_call_me_maybe)
                    };
                    if should {
                        let local_addrs = self.local_udp_addrs();
                        let cmm = Message::CallMeMaybe(CallMeMaybe {
                            my_number: local_addrs
                                .iter()
                                .filter_map(|s| s.parse::<SocketAddr>().ok())
                                .map(rustscale_disco::AddrPort::from)
                                .collect(),
                        });
                        if let Some(packet) = self.inner.disco.seal(&peer_disco, &cmm) {
                            if derp_region > 0 {
                                self.inner
                                    .derp
                                    .send_packet(derp_region, peer_key.clone(), packet)
                                    .await;
                            } else {
                                // Fan out CallMeMaybe to all connected DERP regions
                                // (peer's home DERP is unknown).
                                let regions: Vec<i32> = {
                                    let conns = self
                                        .inner
                                        .derp
                                        .connections
                                        .read()
                                        .expect("derp connections lock poisoned");
                                    conns.keys().copied().collect()
                                };
                                for r in regions {
                                    self.inner
                                        .derp
                                        .send_packet(r, peer_key.clone(), packet.clone())
                                        .await;
                                }
                            }
                        }
                    }
                }
            }
        }

        // Discover relay server candidates from the netmap and update the
        // relay manager. Ports Go's `updateRelayServersSet`.
        if let Some(rm) = self
            .inner
            .relay_manager
            .read()
            .expect("relay_manager lock poisoned")
            .as_ref()
        {
            let servers = relay_manager::discover_relay_servers(
                &rustscale_tailcfg::Node {
                    Key: self
                        .inner
                        .node_public
                        .read()
                        .expect("node_public lock poisoned")
                        .clone(),
                    DiscoKey: self.inner.disco.public(),
                    Cap: rustscale_tailcfg::CAP_VERSION_RELAY,
                    ..Default::default()
                },
                &peers,
            );

            rm.handle_relay_servers_set(servers);

            // Start relay path discovery for peers that don't already have
            // active relay work.
            for peer in &peers {
                if peer.Key.is_zero() || peer.DiscoKey.is_zero() {
                    continue;
                }
                rm.start_discovery(peer.Key.clone(), peer.DiscoKey.clone());
            }
        }

        Ok(())
    }

    /// Send a WG datagram to `peer` over the best available path.
    pub async fn send(&self, peer: NodePublic, datagram: &[u8]) -> Result<(), MagicsockError> {
        // Note TX activity and arm heartbeat before path lookup.
        {
            let mut endpoints = self
                .inner
                .endpoints
                .write()
                .expect("endpoints lock poisoned");
            if let Some(ep) = endpoints.get_mut(&peer) {
                ep.note_tx_activity(std::time::Instant::now());
            }
        }
        self.arm_heartbeat(&peer);

        let (path, derp_region) = {
            let endpoints = self
                .inner
                .endpoints
                .read()
                .expect("endpoints lock poisoned");
            let ep = endpoints.get(&peer).ok_or(MagicsockError::PeerNotFound)?;
            (
                ep.best_path(std::time::Instant::now()),
                ep.derp_send_region(),
            )
        };

        // DERP is a fallback, not the end of discovery. Start a bounded,
        // rate-limited candidate round in the background so packet delivery
        // never waits on UDP probes or CallMeMaybe.
        if !self.inner.disable_direct_paths
            && matches!(
                path,
                endpoint::BestPath::Derp { .. } | endpoint::BestPath::None
            )
        {
            self.start_discovery(peer.clone());
        }

        match path {
            endpoint::BestPath::Direct { addr, .. } => {
                if self.inner.disable_direct_paths {
                    return self.send_via_derp(peer, derp_region, datagram).await;
                }
                if let Some(ref udp) = self.inner.udp {
                    if let Err(e) = udp.send_to(datagram, addr).await {
                        if !treat_as_lost_udp(&e) {
                            return Err(MagicsockError::Io(e));
                        }
                    } else {
                        self.inner.record_udp_tx(addr, datagram.len());
                    }
                    return Ok(());
                }
                self.send_via_derp(peer, derp_region, datagram).await
            }
            endpoint::BestPath::Relay { addr, vni } => {
                // Relay paths work even when direct paths are disabled —
                // the relay path is established by the relay manager, not
                // by direct disco pinging.
                if let Some(ref udp) = self.inner.udp {
                    let framed = relay::encode_geneve(vni, datagram);
                    if let Err(e) = udp.send_to(&framed, addr).await {
                        if !treat_as_lost_udp(&e) {
                            return Err(MagicsockError::Io(e));
                        }
                    } else {
                        self.inner.record_udp_tx(addr, framed.len());
                    }
                    return Ok(());
                }
                self.send_via_derp(peer, derp_region, datagram).await
            }
            endpoint::BestPath::Derp { .. } | endpoint::BestPath::None => {
                self.send_via_derp(peer, derp_region, datagram).await
            }
        }
    }

    /// Inspect the current best path class for a peer (for testing).
    pub fn peer_path_class(&self, peer: &NodePublic) -> PathClass {
        let endpoints = self
            .inner
            .endpoints
            .read()
            .expect("endpoints lock poisoned");
        endpoints
            .get(peer)
            .map(|ep| ep.best_path(std::time::Instant::now()).class())
            .unwrap_or_default()
    }

    /// React to a major link change: re-gather local interface endpoints from
    /// the bound UDP port, reset all peers' confirmed direct paths (so disco
    /// re-probes), and close all DERP connections (so they reconnect fresh).
    pub fn link_changed(&self) {
        if let Some(ref udp) = self.inner.udp {
            if let Ok(port) = udp.local_addr().map(|a| a.port()) {
                let eps = gather_local_endpoints(port);
                *self
                    .inner
                    .local_udp_addrs
                    .write()
                    .expect("local_udp_addrs lock poisoned") = eps;
            }
        }
        // Abort all heartbeat/UDP-lifetime background tasks — they'll be
        // re-armed on next TX activity.
        self.abort_background_tasks();
        {
            let mut endpoints = self
                .inner
                .endpoints
                .write()
                .expect("endpoints lock poisoned");
            for ep in endpoints.values_mut() {
                ep.reset_for_link_change();
            }
        }
        self.inner.derp.close_all();
        self.update_pmtud();
    }

    /// Whether a peer's direct path is still trusted (for testing).
    pub fn peer_direct_trusted(&self, peer: &NodePublic) -> bool {
        let endpoints = self
            .inner
            .endpoints
            .read()
            .expect("endpoints lock poisoned");
        endpoints
            .get(peer)
            .is_some_and(|ep| ep.trusted_direct_addr(std::time::Instant::now()).is_some())
    }

    /// Update the self node's CapMap from the latest MapResponse. Used to
    /// check `NODE_ATTR_DISABLE_RELAY_SERVER` for the relay server extension.
    pub fn set_self_cap_map(&self, cap_map: rustscale_tailcfg::NodeCapMap) {
        let mut guard = self
            .inner
            .self_cap_map
            .write()
            .expect("self_cap_map lock poisoned");
        *guard = cap_map;
    }

    /// Snapshot of the self node's CapMap. Used by service listeners to
    /// resolve VIP service IP addresses from the `service-host` capability.
    pub fn self_cap_map(&self) -> rustscale_tailcfg::NodeCapMap {
        self.inner
            .self_cap_map
            .read()
            .expect("self_cap_map lock poisoned")
            .clone()
    }

    /// Arc handle to the self node's CapMap. Used by the serve runner to
    /// resolve VIP service IP addresses for serve-config TCP forwarding.
    pub fn self_cap_map_arc(&self) -> Arc<RwLock<rustscale_tailcfg::NodeCapMap>> {
        self.inner.self_cap_map.clone()
    }

    /// The relay server extension, if this node is configured as a relay
    /// server. Returns `None` when `peer_relay_server` was not enabled.
    pub fn relay_server(&self) -> Option<&Arc<RelayServerExtension>> {
        self.inner.relay_server.as_ref()
    }

    /// Enable or disable peer path MTU discovery. When enabled, discovery
    /// pings are sent at multiple sizes from `WIRE_MTUs_TO_PROBE` and the
    /// largest succeeding size is recorded per peer. Disabled by default,
    /// matching Go's `ShouldPMTUD` (peermtu.go:56).
    ///
    /// This is a manual override. The internal `update_pmtud` manages the
    /// socket option side (DF bit) and the decision logic (envknob +
    /// control knobs); `set_pmtud_enabled` manages the probe side.
    /// They should be kept consistent: `update_pmtud` probes the socket
    /// capability and updates the `peer_mtu_enabled` atomic, which
    /// `send_pings` reads.
    pub fn set_pmtud_enabled(&self, enabled: bool) {
        self.inner
            .peer_mtu_enabled
            .store(enabled, Ordering::Relaxed);
    }

    /// Re-evaluate PMTUD configuration from control knobs / env and apply
    /// the DF socket option accordingly. Mirrors Go's `Conn.UpdatePMTUD()`.
    ///
    /// If the effective PMTUD status changed, resets all endpoint PMTU
    /// state so discovery re-probes path MTUs.
    pub fn update_pmtud(&self) {
        let current = self.inner.peer_mtu_enabled.load(Ordering::Relaxed);
        let (new_enabled, changed) = pmtud::update_pmtud(
            self.inner.udp.as_deref(),
            self.inner.control_knobs.as_deref(),
            current,
        );
        self.inner
            .peer_mtu_enabled
            .store(new_enabled, Ordering::Relaxed);
        if changed {
            self.reset_endpoint_states();
        }
    }

    /// Whether PMTUD should be enabled based on control knobs and env.
    /// Mirrors Go's `Conn.ShouldPMTUD()`.
    pub fn should_pmtud(&self) -> bool {
        pmtud::should_pmtud(self.inner.control_knobs.as_deref())
    }

    /// Query the DF bit state on the UDP socket.
    /// Mirrors Go's `Conn.DontFragSetting()`.
    pub fn dont_frag_setting(&self) -> Result<bool, pmtud::SetDfError> {
        pmtud::dont_frag_setting(self.inner.udp.as_deref())
    }

    /// Reset per-peer PMTU values and endpoint state so discovery re-probes.
    /// Mirrors Go's `Conn.resetEndpointStates()`.
    fn reset_endpoint_states(&self) {
        let mut endpoints = self
            .inner
            .endpoints
            .write()
            .expect("endpoints lock poisoned");
        for ep in endpoints.values_mut() {
            ep.reset_for_link_change();
            ep.reset_peer_mtu();
        }
    }

    /// Apply a NetInfo update received from the control server. Stores the
    /// NetInfo for endpoint tracking and connectivity diagnostics, deduplicating
    /// when the new value is basically equal to the last. Mirrors Go's
    /// `direct.SetNetInfo` dedup path.
    pub fn set_net_info(&self, ni: &rustscale_tailcfg::NetInfo) {
        let mut guard = self.inner.net_info.write().expect("net_info lock poisoned");
        if let Some(ref prev) = *guard {
            if prev.PreferredDERP == ni.PreferredDERP
                && prev.WorkingUDP == ni.WorkingUDP
                && prev.WorkingIPv6 == ni.WorkingIPv6
                && prev.MappingVariesByDestIP == ni.MappingVariesByDestIP
            {
                return;
            }
        }
        *guard = Some(ni.clone());
    }

    /// Snapshot of the last NetInfo applied via [`set_net_info`].
    pub fn net_info(&self) -> Option<rustscale_tailcfg::NetInfo> {
        self.inner
            .net_info
            .read()
            .expect("net_info lock poisoned")
            .clone()
    }

    /// Whether PMTUD is currently enabled.
    pub fn peer_mtu_enabled(&self) -> bool {
        self.inner.peer_mtu_enabled.load(Ordering::Relaxed)
    }

    /// The largest PMTUD probe size that succeeded for `peer` (0 = not probed).
    pub fn peer_mtu(&self, peer: &NodePublic) -> usize {
        let endpoints = self
            .inner
            .endpoints
            .read()
            .expect("endpoints lock poisoned");
        endpoints.get(peer).map_or(0, endpoint::Endpoint::peer_mtu)
    }

    /// Send a CLI-initiated disco ping to `peer_key`. Returns a
    /// [`rustscale_ipnstate::PingResult`] with latency, endpoint, and path
    /// info. Mirrors Go's `Conn.Ping` (magicsock.go:1181-1206).
    ///
    /// Sends disco pings with [`DiscoPingPurpose::CLI`] to every candidate
    /// endpoint and independently through the peer's DERP route. The first
    /// pong to arrive fires the callback and completes the future. If no pong
    /// arrives within 5 seconds, returns
    /// [`MagicsockError::Timeout`].
    pub async fn cli_ping(
        &self,
        peer_key: &NodePublic,
        peer_name: &str,
        peer_ip: IpAddr,
        size: usize,
    ) -> Result<rustscale_ipnstate::PingResult, MagicsockError> {
        use std::time::Duration;

        // Look up the endpoint to get its disco key, UDP candidates, and
        // preferred DERP send route.
        let (peer_disco, candidates, derp_region) = {
            let endpoints = self
                .inner
                .endpoints
                .read()
                .expect("endpoints lock poisoned");
            let ep = endpoints.get(peer_key).ok_or(MagicsockError::NoPath)?;
            (
                ep.peer_disco_key().clone(),
                ep.candidates(),
                ep.derp_send_region(),
            )
        };

        // Register the callback BEFORE sending pings so we don't miss the pong.
        // The request id keeps a timeout from an older concurrent CLI ping from
        // deleting the callback installed by a newer one.
        let request_id = self.inner.next_cli_ping_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = tokio::sync::oneshot::channel::<rustscale_ipnstate::PingResult>();
        {
            let mut callbacks = self
                .inner
                .cli_ping_callbacks
                .write()
                .expect("cli_ping_callbacks lock poisoned");
            callbacks
                .entry(peer_key.clone())
                .or_default()
                .insert(request_id, tx);
        }

        // Send direct and DERP CLI pings independently. A relay pong is a
        // useful result even if direct candidates were advertised.
        if !peer_disco.is_zero() {
            for addr in &candidates {
                self.inner
                    .send_disco_ping(
                        peer_key,
                        &peer_disco,
                        *addr,
                        DiscoPingPurpose::CLI,
                        size,
                        Some(request_id),
                    )
                    .await;
            }
            if derp_region > 0 {
                let tx_id = random_tx_id();
                let ping = Message::Ping(Ping {
                    tx_id,
                    node_key: self
                        .inner
                        .node_public
                        .read()
                        .expect("node_public lock poisoned")
                        .clone(),
                    padding: 0,
                });
                if let Some(packet) = self.inner.disco.seal(&peer_disco, &ping) {
                    // Register the pending ping on the endpoint so match_pong
                    // can find it.
                    {
                        let mut endpoints = self
                            .inner
                            .endpoints
                            .write()
                            .expect("endpoints lock poisoned");
                        if let Some(ep) = endpoints.get_mut(peer_key) {
                            ep.add_pending_ping(
                                tx_id,
                                SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
                                std::time::Instant::now(),
                                DiscoPingPurpose::CLI,
                                0,
                                Some(request_id),
                            );
                        }
                    }
                    self.inner
                        .derp
                        .send_packet(derp_region, peer_key.clone(), packet)
                        .await;
                }
            }
        }

        // Wait for the pong callback or timeout.
        let result = tokio::time::timeout(Duration::from_secs(5), rx).await;
        let result = match result {
            Ok(Ok(mut pr)) => {
                pr.IP = peer_ip.to_string();
                pr.NodeName = peer_name.to_string();
                Ok(pr)
            }
            Ok(Err(_)) => {
                // Callback was dropped (replaced by another ping). Return a
                // timeout-style error.
                Err(MagicsockError::NoPath)
            }
            Err(_) => {
                // Timeout — remove the callback so a stale pong doesn't fire later.
                let mut callbacks = self
                    .inner
                    .cli_ping_callbacks
                    .write()
                    .expect("cli_ping_callbacks lock poisoned");
                if let Some(requests) = callbacks.get_mut(peer_key) {
                    requests.remove(&request_id);
                    if requests.is_empty() {
                        callbacks.remove(peer_key);
                    }
                }
                Err(MagicsockError::Timeout)
            }
        };
        result
    }

    /// Arm (or re-arm) the per-peer background task for heartbeats and UDP
    /// lifetime probing. Called on TX activity. Aborts any existing task
    /// for this peer to ensure at most one background task at a time.
    /// Mirrors Go's `noteTxActivityExtTriggerLocked` arming the heartbeat
    /// timer (endpoint.go:974-979).
    fn arm_heartbeat(&self, peer_key: &NodePublic) {
        let mut tasks = self
            .inner
            .background_tasks
            .write()
            .expect("background_tasks lock");
        let handle = tokio::spawn(peer_background_task(self.inner.clone(), peer_key.clone()));
        if let Some(old) = tasks.insert(peer_key.clone(), handle) {
            old.abort();
        }
    }

    fn start_discovery(&self, peer_key: NodePublic) {
        let work = {
            let now = std::time::Instant::now();
            let mut endpoints = self
                .inner
                .endpoints
                .write()
                .expect("endpoints lock poisoned");
            endpoints.get_mut(&peer_key).and_then(|ep| {
                ep.should_start_discovery(now, DISCOVERY_PING_INTERVAL)
                    .then(|| {
                        (
                            ep.peer_disco_key().clone(),
                            ep.candidates(),
                            ep.derp_send_region(),
                            true,
                        )
                    })
            })
        };
        if let Some((peer_disco, candidates, derp_region, send_cmm)) = work {
            let inner = self.inner.clone();
            tokio::spawn(async move {
                inner
                    .send_discovery_round(peer_key, peer_disco, candidates, derp_region, send_cmm)
                    .await;
            });
        }
    }

    /// Abort all background tasks (heartbeat + UDP lifetime probes).
    /// Called on link changes.
    fn abort_background_tasks(&self) {
        let mut tasks = self
            .inner
            .background_tasks
            .write()
            .expect("background_tasks lock");
        for (_, handle) in tasks.drain() {
            handle.abort();
        }
    }

    /// Send a WG datagram to `peer` via DERP region `region`.
    /// If `region` is 0 (unknown), fans out to ALL connected DERP regions
    /// so the peer receives the packet on whichever region it's on.
    /// Once a reply arrives, `last_recv_derp_region` is set and future
    /// sends go to that single region.
    async fn send_via_derp(
        &self,
        peer: NodePublic,
        region: i32,
        datagram: &[u8],
    ) -> Result<(), MagicsockError> {
        if region > 0 {
            // Known region — send directly.
            if self
                .inner
                .derp
                .send_packet(region, peer.clone(), datagram.to_vec())
                .await
            {
                if debug_enabled() {
                    eprintln!(
                        "DBG derp_send peer={} region={} wg_len={}",
                        short_key(&peer),
                        region,
                        datagram.len()
                    );
                }
                return Ok(());
            }
            return Err(MagicsockError::NoPath);
        }

        // Unknown region — fan out to ALL DERP regions (connected + lazily
        // connected from the DERPMap). This is the bootstrap path: when a
        // peer's HomeDERP is 0 (not reported by the control plane for
        // API-only tailnets), we don't know which DERP server the peer is
        // connected to. Send to all regions so the peer receives the packet
        // on whichever region it's homed to. Once we get a reply,
        // `last_recv_derp_region` is set and future sends are targeted.
        let all_regions: Vec<i32> = {
            let conns = self
                .inner
                .derp
                .connections
                .read()
                .expect("derp connections lock poisoned");
            let mut regions: Vec<i32> = conns.keys().copied().collect();
            // Also include regions from the DERPMap that aren't connected yet.
            if let Some(map) = self
                .inner
                .derp
                .derp_map
                .read()
                .expect("derp_map lock poisoned")
                .as_ref()
            {
                for &region_id in map.Regions.keys() {
                    if !regions.contains(&region_id) {
                        regions.push(region_id);
                    }
                }
            }
            regions
        };

        if debug_enabled() {
            eprintln!(
                "DBG derp_fanout peer={} regions={:?} wg_len={}",
                short_key(&peer),
                all_regions,
                datagram.len()
            );
        }

        if all_regions.is_empty() {
            return Err(MagicsockError::NoPath);
        }

        for r in all_regions {
            self.inner
                .derp
                .send_packet(r, peer.clone(), datagram.to_vec())
                .await;
        }
        Ok(())
    }
}

/// Launch background UDP recv task + DERP demux task.
fn spawn_recv_tasks(
    inner: Arc<Inner>,
    derp_recv_rx: mpsc::Receiver<(i32, DerpEvent)>,
    reconnect_rx: mpsc::UnboundedReceiver<i32>,
) {
    // UDP recv task. After the first async recv_from wakes us, drain any
    // additional immediately-available packets with try_recv_from before
    // awaiting again. This batches a burst of packets per wakeup (e.g. a
    // train of WG data packets arriving together) into a single scheduler
    // turn, reducing per-packet wake/context-switch overhead on the hot
    // path.
    if let Some(ref udp) = inner.udp {
        let udp = udp.clone();
        let inner = inner.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_536];
            loop {
                match udp.recv_from(&mut buf).await {
                    Ok((len, addr)) => {
                        inner.record_udp_rx(addr, len);
                        inner.handle_udp_packet(&buf[..len], addr).await;
                        // Drain the rest of the currently-ready packet burst
                        // without another await on the socket.
                        while let Ok((len2, addr2)) = udp.try_recv_from(&mut buf) {
                            inner.record_udp_rx(addr2, len2);
                            inner.handle_udp_packet(&buf[..len2], addr2).await;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    }

    // DERP demux task: consumes from all DERP region recv consumers and
    // dispatches to handle_derp_packet / handle_derp_peer_gone. This single
    // task handles packets from ALL connected regions (home + lazy).
    let inner2 = inner.clone();
    tokio::spawn(async move {
        let mut derp_recv_rx = derp_recv_rx;
        while let Some((region_id, event)) = derp_recv_rx.recv().await {
            match event {
                DerpEvent::RecvPacket { source, data } => {
                    inner2.handle_derp_packet(&data, source, region_id).await;
                }
                DerpEvent::PeerGone { peer, reason } => {
                    inner2.handle_derp_peer_gone(peer, region_id, reason);
                }
                DerpEvent::Health { problem } => {
                    // Update DERP region health. Empty problem = healthy.
                    if let Some(ref health) = inner2.derp.health {
                        health.set_derp_region_health(region_id, problem.is_empty());
                        if problem.is_empty() {
                            health.set_healthy(rustscale_health::WARN_DERP_REGION_ERROR);
                        } else {
                            health.set_unhealthy(
                                rustscale_health::WARN_DERP_REGION_ERROR,
                                format!(
                                    "{{\"{}\":{},\"{}\":\"{}\"}}",
                                    rustscale_health::ARG_DERP_REGION_ID,
                                    region_id,
                                    rustscale_health::ARG_ERROR,
                                    problem,
                                ),
                            );
                        }
                    }
                }
            }
        }
    });

    // DERP reconnect supervisor: listens for dead-connection signals from
    // recv consumers and spawns a per-region reconnect task with
    // exponential backoff. Each region gets its own task so multiple
    // regions can reconnect in parallel without blocking each other.
    let inner3 = inner;
    tokio::spawn(async move {
        let mut reconnect_rx = reconnect_rx;
        while let Some(region_id) = reconnect_rx.recv().await {
            let inner = inner3.clone();
            tokio::spawn(async move {
                inner.derp.reconnect_region(region_id).await;
            });
        }
    });
}

/// Per-peer background task: heartbeat pings + UDP lifetime probing.
///
/// **Phase 1 — Heartbeat**: every `HEARTBEAT_INTERVAL` (3s), if the session
/// is active (TX within `SESSION_ACTIVE_TIMEOUT` = 45s), sends a heartbeat
/// ping to the best direct path. Mirrors Go's `heartbeat()`
/// (endpoint.go:829-895).
///
/// **Phase 2 — UDP lifetime probe**: when the session goes idle, checks
/// whether UDP lifetime probing is eligible (lower disco key wins) and
/// cycles through the cliffs [10s, 30s, 60s]. At each cliff, sends a ping
/// and waits for a pong; on timeout, clears `best_addr` (demotes direct
/// path). Mirrors Go's `heartbeatForLifetime()` (endpoint.go:778-824) and
/// `probeUDPLifetimeCliffDoneLocked` (endpoint.go:1166-1194).
///
/// The task self-terminates when the peer is removed, the probe cycle
/// completes, or TX activity resumes (a new task is spawned by
/// `arm_heartbeat`).
async fn peer_background_task(inner: Arc<Inner>, peer_key: NodePublic) {
    use std::time::Instant;

    loop {
        tokio::time::sleep(HEARTBEAT_INTERVAL).await;
        let now = Instant::now();

        // Read endpoint state under a short-lived lock.
        let (idle, best_addr, peer_disco) = {
            let endpoints = inner.endpoints.read().expect("endpoints lock poisoned");
            let ep = match endpoints.get(&peer_key) {
                Some(ep) => ep,
                None => return, // peer removed from netmap
            };
            let idle = !ep.session_active(now, SESSION_ACTIVE_TIMEOUT);
            (
                idle,
                ep.trusted_direct_addr(now),
                ep.peer_disco_key().clone(),
            )
        };

        if idle {
            // Session idle — stop heartbeating, try UDP lifetime probe.
            break;
        }

        // Send heartbeat ping to the best direct path.
        if let Some(addr) = best_addr {
            inner
                .send_disco_ping(
                    &peer_key,
                    &peer_disco,
                    addr,
                    DiscoPingPurpose::Heartbeat,
                    0,
                    None,
                )
                .await;
        } else {
            // Trust expired on best_addr — retrigger CallMeMaybe so the
            // peer knows to re-establish a direct path. Mirrors Go's
            // `sendDiscoPingsLocked(now, true)` calling
            // `enqueueCallMeMaybe` when trust has expired
            // (endpoint.go:1375-1407).
            let retriggered = {
                let mut endpoints = inner.endpoints.write().expect("endpoints lock poisoned");
                endpoints
                    .get_mut(&peer_key)
                    .is_some_and(|ep| ep.maybe_retrigger_call_me_maybe(now))
            };
            if retriggered && !peer_disco.is_zero() {
                let derp_region = {
                    let endpoints = inner.endpoints.read().expect("endpoints lock poisoned");
                    endpoints
                        .get(&peer_key)
                        .map_or(0, endpoint::Endpoint::derp_send_region)
                };
                let region = if derp_region > 0 {
                    derp_region
                } else {
                    inner.derp.home_region()
                };
                let local_addrs = inner
                    .local_udp_addrs
                    .read()
                    .expect("local_udp_addrs lock poisoned")
                    .clone();
                let cmm = Message::CallMeMaybe(CallMeMaybe {
                    my_number: local_addrs
                        .iter()
                        .filter_map(|s| s.parse::<SocketAddr>().ok())
                        .map(rustscale_disco::AddrPort::from)
                        .collect(),
                });
                if let Some(reply) = inner.disco.seal(&peer_disco, &cmm) {
                    inner
                        .derp
                        .send_packet(region, peer_key.clone(), reply)
                        .await;
                }
            }
        }
    }

    // Phase 2: UDP lifetime probe (if eligible).
    udp_lifetime_probe_phase(&inner, &peer_key).await;
}

/// UDP lifetime probe phase: schedule and execute cliff probes after the
/// session goes idle.
async fn udp_lifetime_probe_phase(inner: &Arc<Inner>, peer_key: &NodePublic) {
    use std::time::Instant;

    let our_disco = inner.disco.public();

    loop {
        let now = Instant::now();

        // Check eligibility and get the inactivity threshold.
        let after_inactivity = {
            let endpoints = inner.endpoints.read().expect("endpoints lock poisoned");
            let ep = match endpoints.get(peer_key) {
                Some(ep) => ep,
                None => return, // peer removed
            };
            // If session became active again, exit (send() will spawn a new
            // heartbeat task via arm_heartbeat).
            if ep.session_active(now, SESSION_ACTIVE_TIMEOUT) {
                return;
            }
            match ep.maybe_probe_udp_lifetime(now, &our_disco, UDP_LIFETIME_CLIFF_SLACK) {
                Some(after) => after,
                None => return, // not eligible (higher disco key, no best_addr, etc.)
            }
        };

        // Compute the sleep time: cliff_duration - cliff_slack - inactive_time.
        let inactive_for = {
            let endpoints = inner.endpoints.read().expect("endpoints lock poisoned");
            endpoints
                .get(peer_key)
                .map_or(Duration::from_secs(u64::MAX / 2), |ep| {
                    ep.inactivity_duration(now)
                })
        };

        let sleep_time = after_inactivity.saturating_sub(inactive_for);
        if sleep_time == Duration::ZERO {
            return;
        }

        tokio::time::sleep(sleep_time).await;

        // Re-check after sleeping: best_addr must be unchanged and session
        // must still be idle.
        let now = Instant::now();
        let (best_addr_now, peer_disco_now, cycle_active, best_addr_matches) = {
            let endpoints = inner.endpoints.read().expect("endpoints lock poisoned");
            let ep = match endpoints.get(peer_key) {
                Some(ep) => ep,
                None => return,
            };
            if ep.session_active(now, SESSION_ACTIVE_TIMEOUT) {
                return; // session resumed
            }
            (
                ep.trusted_direct_addr(now),
                ep.peer_disco_key().clone(),
                ep.udp_lifetime_cycle_active(),
                ep.udp_lifetime_best_addr_matches(),
            )
        };

        if !best_addr_matches && !cycle_active {
            // best_addr changed since scheduling — start a fresh cycle.
            {
                let mut endpoints = inner.endpoints.write().expect("endpoints lock poisoned");
                if let Some(ep) = endpoints.get_mut(peer_key) {
                    ep.start_udp_lifetime_cycle(now);
                }
            }
        } else if !best_addr_matches {
            // best_addr changed and cycle was already active — abort.
            return;
        }

        let addr = match best_addr_now {
            Some(a) => a,
            None => return,
        };

        // Send the probe ping.
        inner
            .send_disco_ping(
                peer_key,
                &peer_disco_now,
                addr,
                DiscoPingPurpose::HeartbeatForUDPLifetime,
                0,
                None,
            )
            .await;

        // Wait for pong or timeout.
        tokio::time::sleep(PING_TIMEOUT_DURATION).await;

        // Check if the probe ping was answered (pong handler removed it
        // from pending_pings) or timed out.
        let (pong_received, has_more_cliffs) = {
            let mut endpoints = inner.endpoints.write().expect("endpoints lock poisoned");
            let ep = match endpoints.get_mut(peer_key) {
                Some(ep) => ep,
                None => return,
            };
            let pong_received = ep.is_last_udp_lifetime_ping_answered();
            let has_more = if pong_received {
                ep.advance_udp_lifetime_cliff()
            } else {
                ep.clear_best_addr();
                ep.complete_udp_lifetime_cycle();
                false
            };
            (pong_received, has_more)
        };

        if debug_enabled() {
            eprintln!(
                "DBG udp_lifetime_probe peer={} pong={pong_received} more_cliffs={has_more_cliffs}",
                short_key(peer_key)
            );
        }

        if !has_more_cliffs {
            return;
        }
    }
}

impl relay_manager::RelayManagerContext for Inner {
    fn seal_disco(&self, peer_disco: &DiscoPublic, msg: &Message) -> Option<Vec<u8>> {
        self.disco.seal(peer_disco, msg)
    }

    fn send_disco_udp(&self, addr: SocketAddr, vni: u32, control: bool, packet: &[u8]) {
        if let Some(ref udp) = self.udp {
            let framed = if control {
                relay::encode_geneve_disco_control(vni, packet)
            } else {
                relay::encode_geneve_disco(vni, packet)
            };
            let udp = udp.clone();
            let framed = framed.clone();
            let handle = match addr {
                SocketAddr::V4(_) => self.sockstats_udp4.clone(),
                SocketAddr::V6(_) => self.sockstats_udp6.clone(),
            };
            tokio::spawn(async move {
                if let Err(e) = udp.send_to(&framed, addr).await {
                    if !treat_as_lost_udp(&e) {
                        log::debug!("magicsock: disco UDP send failed: {e}");
                    }
                } else if let Some(ref h) = handle {
                    h.record_tx(framed.len());
                }
            });
        }
    }

    fn send_disco_derp(&self, region: i32, dst_key: NodePublic, packet: Vec<u8>) {
        let io = {
            let conns = self
                .derp
                .connections
                .read()
                .expect("derp connections lock poisoned");
            conns.get(&region).cloned()
        };
        if let Some(io) = io {
            tokio::spawn(async move {
                io.send_packet(dst_key, packet).await;
            });
        }
    }

    fn our_disco_public(&self) -> DiscoPublic {
        self.disco.public()
    }

    fn our_node_public(&self) -> NodePublic {
        self.node_public
            .read()
            .expect("node_public lock poisoned")
            .clone()
    }

    fn peer_disco_key(&self, peer_key: &NodePublic) -> Option<DiscoPublic> {
        let endpoints = self.endpoints.read().expect("endpoints lock poisoned");
        endpoints
            .get(peer_key)
            .map(|ep| ep.peer_disco_key().clone())
    }

    fn peer_derp_region(&self, peer_key: &NodePublic) -> i32 {
        let endpoints = self.endpoints.read().expect("endpoints lock poisoned");
        endpoints
            .get(peer_key)
            .map_or(0, endpoint::Endpoint::derp_send_region)
    }

    fn set_relay(&self, peer_key: &NodePublic, addr: SocketAddr, vni: u32) {
        let mut endpoints = self.endpoints.write().expect("endpoints lock poisoned");
        if let Some(ep) = endpoints.get_mut(peer_key) {
            ep.set_relay(addr, vni);
            if debug_enabled() {
                eprintln!(
                    "DBG relay_set peer={} addr={addr} vni={vni}",
                    short_key(peer_key)
                );
            }
        }
    }

    fn send_pong_via_relay(
        &self,
        addr: SocketAddr,
        vni: u32,
        peer_disco: &DiscoPublic,
        tx_id: [u8; 12],
    ) {
        let pong = Message::Pong(Pong {
            tx_id,
            src: rustscale_disco::AddrPort::from(addr),
        });
        if let Some(sealed) = self.disco.seal(peer_disco, &pong) {
            self.send_disco_udp(addr, vni, false, &sealed);
        }
    }

    fn is_self_node(&self, node_key: &NodePublic) -> bool {
        *node_key == *self.node_public.read().expect("node_public lock poisoned")
    }

    fn handle_self_alloc_request(
        &self,
        client_disco: [DiscoPublic; 2],
        generation: u32,
    ) -> Option<rustscale_disco::AllocateUdpRelayEndpointResponse> {
        // In-process shortcut: when the relay server is self, bypass DERP
        // and call the local extension directly (Go magicsock.go:1946-1963).
        if let Some(ref rs) = self.relay_server {
            return rs.handle_alloc_request(client_disco, generation);
        }
        None
    }
}

impl Inner {
    /// Probe every current UDP candidate and, once per discovery cycle, tell
    /// the peer our observed addresses via DERP. Called from a detached,
    /// rate-limited task started by the WireGuard send path.
    async fn send_discovery_round(
        &self,
        peer_key: NodePublic,
        peer_disco: DiscoPublic,
        candidates: Vec<SocketAddr>,
        derp_region: i32,
        send_cmm: bool,
    ) {
        if peer_disco.is_zero() {
            return;
        }
        for addr in candidates {
            self.send_disco_ping(
                &peer_key,
                &peer_disco,
                addr,
                DiscoPingPurpose::Discovery,
                0,
                None,
            )
            .await;
        }
        if !send_cmm {
            return;
        }
        let local_addrs = self
            .local_udp_addrs
            .read()
            .expect("local_udp_addrs lock poisoned")
            .clone();
        let cmm = Message::CallMeMaybe(CallMeMaybe {
            my_number: local_addrs
                .iter()
                .filter_map(|addr| addr.parse::<SocketAddr>().ok())
                .map(rustscale_disco::AddrPort::from)
                .collect(),
        });
        if let Some(packet) = self.disco.seal(&peer_disco, &cmm) {
            let region = if derp_region > 0 {
                derp_region
            } else {
                self.derp.home_region()
            };
            self.derp.send_packet(region, peer_key, packet).await;
        }
    }

    /// Record `n` bytes sent over the UDP socket to `addr` on the matching
    /// v4/v6 sockstats label. Best-effort: no-op when no registry is wired.
    fn record_udp_tx(&self, addr: SocketAddr, n: usize) {
        if n == 0 {
            return;
        }
        match addr {
            SocketAddr::V4(_) => {
                if let Some(ref h) = self.sockstats_udp4 {
                    h.record_tx(n);
                }
            }
            SocketAddr::V6(_) => {
                if let Some(ref h) = self.sockstats_udp6 {
                    h.record_tx(n);
                }
            }
        }
    }

    /// Record `n` bytes received over the UDP socket from `addr` on the
    /// matching v4/v6 sockstats label. Best-effort: no-op when no registry is
    /// wired.
    fn record_udp_rx(&self, addr: SocketAddr, n: usize) {
        if n == 0 {
            return;
        }
        match addr {
            SocketAddr::V4(_) => {
                if let Some(ref h) = self.sockstats_udp4 {
                    h.record_rx(n);
                }
            }
            SocketAddr::V6(_) => {
                if let Some(ref h) = self.sockstats_udp6 {
                    h.record_rx(n);
                }
            }
        }
    }

    /// Send a disco ping to `addr` for `peer_key` with the given purpose.
    /// When PMTUD is enabled and the purpose is `Discovery`, sends multiple
    /// pings at sizes from `WIRE_MTUs_TOProbe`. Mirrors Go's
    /// `startDiscoPingLocked` (endpoint.go:1308-1372).
    async fn send_disco_ping(
        &self,
        peer_key: &NodePublic,
        peer_disco: &DiscoPublic,
        addr: SocketAddr,
        purpose: DiscoPingPurpose,
        size: usize,
        cli_request_id: Option<u64>,
    ) {
        // Determine ping sizes: PMTUD burst for discovery pings when enabled.
        let sizes: Vec<usize> = if size > 0 {
            vec![size]
        } else if self.peer_mtu_enabled.load(Ordering::Relaxed)
            && purpose == DiscoPingPurpose::Discovery
        {
            WIRE_MTUS_TO_PROBE.to_vec()
        } else {
            vec![0]
        };

        for s in sizes {
            let tx_id = random_tx_id();
            let padding = s.saturating_sub(DISCO_PING_SIZE);

            {
                let mut endpoints = self.endpoints.write().expect("endpoints lock poisoned");
                if let Some(ep) = endpoints.get_mut(peer_key) {
                    let now = std::time::Instant::now();
                    ep.expire_pending_pings(now, PING_TIMEOUT_DURATION);
                    ep.add_pending_ping(tx_id, addr, now, purpose, s, cli_request_id);
                    if purpose == DiscoPingPurpose::HeartbeatForUDPLifetime {
                        ep.set_udp_lifetime_tx_id(tx_id);
                    }
                }
            }

            let ping = Message::Ping(Ping {
                tx_id,
                node_key: self
                    .node_public
                    .read()
                    .expect("node_public lock poisoned")
                    .clone(),
                padding,
            });
            if let Some(packet) = self.disco.seal(peer_disco, &ping) {
                if let Some(ref udp) = self.udp {
                    if debug_enabled() {
                        eprintln!(
                            "DBG disco_ping send to {addr} peer={} purpose={:?} size={s}",
                            short_key(peer_key),
                            purpose
                        );
                    }
                    if let Err(e) = udp.send_to(&packet, addr).await {
                        if !treat_as_lost_udp(&e) && pmtud::should_log_disco_tx_err(&ping, &e) {
                            log::debug!("magicsock: disco ping send failed: {e}");
                        }
                    } else {
                        self.record_udp_tx(addr, packet.len());
                    }
                }
            }
        }
    }

    async fn handle_udp_packet(&self, data: &[u8], src: SocketAddr) {
        // Check for Geneve-encapsulated packets first (relay path).
        if relay::looks_like_geneve_disco(data) {
            if let Some((_proto, vni, _control, inner)) = relay::decode_geneve_full(data) {
                self.handle_disco_udp_relay(inner, src, vni);
                return;
            }
        }
        if relay::looks_like_geneve_wireguard(data) {
            if let Some((_proto, vni, _control, inner)) = relay::decode_geneve_full(data) {
                self.handle_wg_udp_relay(inner, src, vni).await;
                return;
            }
        }
        if DiscoIo::looks_like_disco(data) {
            self.handle_disco_udp(data, src).await;
        } else {
            self.handle_wg_udp(data, src).await;
        }
    }

    async fn handle_derp_packet(&self, data: &[u8], source: NodePublic, region_id: i32) {
        // Note DERP region frame for health tracking.
        if let Some(ref health) = self.derp.health {
            health.note_derp_region_frame(region_id);
        }

        // Record the arrival DERP region on the peer's endpoint so future
        // replies route to this region (Go's derpRoute caching).
        {
            let mut endpoints = self.endpoints.write().expect("endpoints lock poisoned");
            if let Some(ep) = endpoints.get_mut(&source) {
                ep.set_last_recv_derp_region(region_id);
            }
        }

        let is_disco = DiscoIo::looks_like_disco(data);
        if debug_enabled() {
            eprintln!(
                "DBG derp_recv src={} region={} kind={} len={}",
                short_key(&source),
                region_id,
                if is_disco { "disco" } else { "wg" },
                data.len()
            );
        }

        if is_disco {
            self.handle_disco_derp(data, source).await;
        } else {
            // WG datagram via DERP — deliver to caller.
            let _ = self
                .wg_send
                .send(WgDatagram {
                    peer: source,
                    data: data.to_vec(),
                })
                .await;
        }
    }

    /// Handle a PeerGone frame from a DERP server. Removes the peer's DERP
    /// route cache entry so future sends fall back to the peer's home DERP.
    /// Mirrors Go's `removeDerpPeerRoute` (derp.go:52-59) called from the
    /// DERP recv loop on PeerGoneMessage (derp.go:651-664).
    fn handle_derp_peer_gone(&self, peer: NodePublic, region_id: i32, reason: u8) {
        if debug_enabled() {
            eprintln!(
                "DBG derp_peer_gone peer={} region={} reason={}",
                short_key(&peer),
                region_id,
                reason
            );
        }
        let mut endpoints = self.endpoints.write().expect("endpoints lock poisoned");
        if let Some(ep) = endpoints.get_mut(&peer) {
            ep.remove_derp_route();
        }
    }

    async fn handle_wg_udp(&self, data: &[u8], src: SocketAddr) {
        let peer = {
            let map = self
                .addr_to_peer
                .read()
                .expect("addr_to_peer lock poisoned");
            map.get(&src).cloned()
        };
        if let Some(peer) = peer {
            // Note UDP recv activity for heartbeat / UDP lifetime probe.
            {
                let mut endpoints = self.endpoints.write().expect("endpoints lock poisoned");
                if let Some(ep) = endpoints.get_mut(&peer) {
                    ep.note_recv_udp(std::time::Instant::now());
                }
            }
            let _ = self
                .wg_send
                .send(WgDatagram {
                    peer,
                    data: data.to_vec(),
                })
                .await;
        }
        // Unknown source address — drop the packet.
    }

    /// Handle a Geneve-encapsulated disco message received via UDP (relay
    /// path). The Geneve header has already been stripped; `data` is the
    /// raw disco envelope.
    fn handle_disco_udp_relay(&self, data: &[u8], src: SocketAddr, vni: u32) {
        let (sender_disco, msg) = match self.disco.open(data) {
            Some(v) => v,
            None => return,
        };

        if debug_enabled() {
            eprintln!(
                "DBG disco_relay recv from {src} vni={vni} type={}",
                msg.summary()
            );
        }

        match &msg {
            Message::BindUdpRelayEndpointChallenge(_) | Message::Ping(_) | Message::Pong(_) => {
                if let Some(rm) = self
                    .relay_manager
                    .read()
                    .expect("relay_manager lock poisoned")
                    .as_ref()
                {
                    rm.handle_rx_disco_msg(relay_manager::RelayDiscoMsg {
                        msg,
                        disco: sender_disco,
                        from: src,
                        vni,
                        relay_server_node_key: None,
                        source_node_key: None,
                    });
                }
            }
            _ => {}
        }
    }

    /// Handle a Geneve-encapsulated WireGuard data packet received via UDP
    /// (relay path). The Geneve header has already been stripped; `data` is
    /// the raw WG datagram.
    async fn handle_wg_udp_relay(&self, data: &[u8], src: SocketAddr, _vni: u32) {
        // Look up the peer by source address. In the relay path, the source
        // is the relay server, not the peer — but we record the relay addr
        // → peer mapping when set_relay is called. For now, use the
        // addr_to_peer map.
        let peer = {
            let map = self
                .addr_to_peer
                .read()
                .expect("addr_to_peer lock poisoned");
            map.get(&src).cloned()
        };
        if let Some(peer) = peer {
            let _ = self
                .wg_send
                .send(WgDatagram {
                    peer,
                    data: data.to_vec(),
                })
                .await;
        }
    }

    async fn handle_disco_udp(&self, packet: &[u8], src: SocketAddr) {
        let (sender_disco, msg) = match self.disco.open(packet) {
            Some(v) => v,
            None => return,
        };

        // Try to identify the peer by disco key first.
        let peer = {
            let map = self
                .disco_to_peer
                .read()
                .expect("disco_to_peer lock poisoned");
            map.get(&sender_disco).cloned()
        };

        // Fallback: if the disco key is not in disco_to_peer, try to
        // identify the peer by other means. Mirrors Go's
        // `unambiguousNodeKeyOfPingLocked` for pings (magicsock.go:2511)
        // and `forEachEndpointWithDiscoKey` for pongs (magicsock.go:2320).
        let peer = match peer {
            Some(p) => p,
            None => match &msg {
                Message::Ping(ping) => {
                    // Use the ping's node_key to look up the endpoint.
                    if ping.node_key.is_zero() {
                        return;
                    }
                    let endpoints = self.endpoints.read().expect("endpoints lock poisoned");
                    if endpoints.contains_key(&ping.node_key) {
                        // Record the disco→peer mapping for future lookups.
                        drop(endpoints);
                        let mut d2p = self
                            .disco_to_peer
                            .write()
                            .expect("disco_to_peer lock poisoned");
                        d2p.insert(sender_disco.clone(), ping.node_key.clone());
                        ping.node_key.clone()
                    } else {
                        return;
                    }
                }
                Message::Pong(pong) => {
                    // Search all endpoints for one with a matching pending
                    // ping tx_id. This mirrors Go's forEachEndpointWithDiscoKey
                    // which tries each endpoint's handlePongConnLocked
                    // (magicsock.go:2320-2326).
                    let mut found_peer: Option<NodePublic> = None;
                    let endpoints = self.endpoints.read().expect("endpoints lock poisoned");
                    for (node_key, ep) in endpoints.iter() {
                        if ep.has_pending_ping(&pong.tx_id) {
                            found_peer = Some(node_key.clone());
                            break;
                        }
                    }
                    drop(endpoints);
                    match found_peer {
                        Some(p) => p,
                        None => return,
                    }
                }
                _ => return,
            },
        };

        match msg {
            Message::Ping(ping) => {
                if debug_enabled() {
                    eprintln!("DBG disco_ping recv from {src} peer={}", short_key(&peer));
                }
                // Note UDP recv activity for heartbeat / UDP lifetime probe.
                {
                    let mut endpoints = self.endpoints.write().expect("endpoints lock poisoned");
                    if let Some(ep) = endpoints.get_mut(&peer) {
                        ep.note_recv_udp(std::time::Instant::now());
                        // The packet was authenticated with this peer's disco
                        // key, so its observed source is safe to retain for
                        // future direct probing.
                        ep.learn_candidate(src);
                    }
                }
                // When direct paths are disabled, don't respond to pings —
                // this prevents the peer from confirming a direct path to us.
                if self.disable_direct_paths {
                    return;
                }
                // Respond with a Pong over UDP to the source address.
                let pong = Message::Pong(Pong {
                    tx_id: ping.tx_id,
                    src: rustscale_disco::AddrPort::from(src),
                });
                if let Some(reply) = self.disco.seal(&sender_disco, &pong) {
                    if let Some(ref udp) = self.udp {
                        if debug_enabled() {
                            eprintln!("DBG disco_pong send to {src} peer={}", short_key(&peer));
                        }
                        if let Err(e) = udp.send_to(&reply, src).await {
                            if !treat_as_lost_udp(&e) {
                                log::debug!("magicsock: disco pong send failed: {e}");
                            }
                        } else {
                            self.record_udp_tx(src, reply.len());
                        }
                    }
                }
                // Also record the addr→peer mapping so future WG packets
                // from this address are recognized.
                {
                    let mut map = self
                        .addr_to_peer
                        .write()
                        .expect("addr_to_peer lock poisoned");
                    map.insert(src, peer);
                }
            }
            Message::Pong(pong) => {
                // Match the pong to a pending ping and confirm the direct path.
                if debug_enabled() {
                    eprintln!("DBG disco_pong recv from {src} peer={}", short_key(&peer));
                }
                let matched = {
                    let mut endpoints = self.endpoints.write().expect("endpoints lock poisoned");
                    if let Some(ep) = endpoints.get_mut(&peer) {
                        if let Some(pp) = ep.match_pong(&pong.tx_id) {
                            ep.confirm_direct(src, std::time::Instant::now());
                            ep.note_recv_udp(std::time::Instant::now());
                            // Record PMTUD probe size if this was a sized probe.
                            if pp.size > 0 {
                                ep.set_peer_mtu(pp.size);
                            }
                            if debug_enabled() {
                                eprintln!(
                                    "DBG direct_confirmed peer={} addr={src}",
                                    short_key(&peer)
                                );
                            }
                            Some((src, pp))
                        } else {
                            if debug_enabled() {
                                eprintln!("DBG disco_pong nomatch peer={}", short_key(&peer));
                            }
                            None
                        }
                    } else {
                        None
                    }
                };
                if let Some((addr, pp)) = matched {
                    {
                        let mut map = self
                            .addr_to_peer
                            .write()
                            .expect("addr_to_peer lock poisoned");
                        map.insert(addr, peer.clone());
                    }
                    // Fire CLI ping callback if this was a CLI-purpose ping.
                    if pp.purpose == DiscoPingPurpose::CLI {
                        let latency = std::time::Instant::now()
                            .duration_since(pp.sent_at)
                            .as_secs_f64();
                        let pr = rustscale_ipnstate::PingResult {
                            LatencySeconds: latency,
                            Endpoint: addr.to_string(),
                            ..Default::default()
                        };
                        let mut callbacks = self
                            .cli_ping_callbacks
                            .write()
                            .expect("cli_ping_callbacks lock poisoned");
                        if let Some(request_id) = pp.cli_request_id {
                            if let Some(requests) = callbacks.get_mut(&peer) {
                                if let Some(tx) = requests.remove(&request_id) {
                                    let _ = tx.send(pr);
                                }
                                if requests.is_empty() {
                                    callbacks.remove(&peer);
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    async fn handle_disco_derp(&self, packet: &[u8], source: NodePublic) {
        let (sender_disco, msg) = match self.disco.open(packet) {
            Some(v) => v,
            None => return,
        };

        // Look up the peer's DERP send region (last-recv-region > HomeDERP).
        let derp_region = {
            let endpoints = self.endpoints.read().expect("endpoints lock poisoned");
            endpoints
                .get(&source)
                .map_or(0, endpoint::Endpoint::derp_send_region)
        };

        match msg {
            Message::Ping(ping) => {
                // Respond with a Pong via the peer's DERP region (arrival
                // region is already recorded by handle_derp_packet).
                let pong = Message::Pong(Pong {
                    tx_id: ping.tx_id,
                    src: rustscale_disco::AddrPort::new(
                        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                        0,
                    ),
                });
                if let Some(reply) = self.disco.seal(&sender_disco, &pong) {
                    let region = if derp_region > 0 {
                        derp_region
                    } else {
                        self.derp.home_region()
                    };
                    self.derp.send_packet(region, source, reply).await;
                }
            }
            Message::Pong(pong) => {
                // Pong via DERP — match pending CLI pings so they complete
                // with DERP path info (mirrors Go's handlePongConnLocked
                // being called for DERP pongs too).
                let matched = {
                    let mut endpoints = self.endpoints.write().expect("endpoints lock poisoned");
                    if let Some(ep) = endpoints.get_mut(&source) {
                        ep.match_pong(&pong.tx_id)
                    } else {
                        None
                    }
                };
                if let Some(pp) = matched {
                    if pp.purpose == DiscoPingPurpose::CLI {
                        let latency = std::time::Instant::now()
                            .duration_since(pp.sent_at)
                            .as_secs_f64();
                        let derp_id = if derp_region > 0 {
                            derp_region
                        } else {
                            self.derp.home_region()
                        };
                        let pr = rustscale_ipnstate::PingResult {
                            LatencySeconds: latency,
                            DERPRegionID: derp_id,
                            ..Default::default()
                        };
                        let mut callbacks = self
                            .cli_ping_callbacks
                            .write()
                            .expect("cli_ping_callbacks lock poisoned");
                        if let Some(request_id) = pp.cli_request_id {
                            if let Some(requests) = callbacks.get_mut(&source) {
                                if let Some(tx) = requests.remove(&request_id) {
                                    let _ = tx.send(pr);
                                }
                                if requests.is_empty() {
                                    callbacks.remove(&source);
                                }
                            }
                        }
                    }
                }
            }
            Message::CallMeMaybe(cmm) => {
                // When direct paths are disabled, don't ping the peer's
                // advertised addresses — we won't use a direct path anyway.
                if self.disable_direct_paths {
                    return;
                }
                // The peer is telling us its UDP addresses. Ping each.
                let peer_disco = sender_disco.clone();
                for ep in &cmm.my_number {
                    let addr = SocketAddr::from(*ep);
                    self.send_disco_ping(
                        &source,
                        &peer_disco,
                        addr,
                        DiscoPingPurpose::Discovery,
                        0,
                        None,
                    )
                    .await;
                }
            }
            Message::CallMeMaybeVia(cmmv) => {
                // The peer is telling us about a relay endpoint it allocated.
                // Route to the relay manager to start a handshake.
                if let Some(rm) = self
                    .relay_manager
                    .read()
                    .expect("relay_manager lock poisoned")
                    .as_ref()
                {
                    let peer_disco = {
                        let endpoints = self.endpoints.read().expect("endpoints lock poisoned");
                        endpoints
                            .get(&source)
                            .map(|ep| ep.peer_disco_key().clone())
                            .unwrap_or(sender_disco.clone())
                    };
                    rm.handle_call_me_maybe_via(source.clone(), peer_disco, &cmmv);
                }
            }
            Message::AllocateUdpRelayEndpointResponse(_) => {
                // Response to our allocation request, arriving via DERP.
                // Route to the relay manager.
                if let Some(rm) = self
                    .relay_manager
                    .read()
                    .expect("relay_manager lock poisoned")
                    .as_ref()
                {
                    rm.handle_rx_disco_msg(relay_manager::RelayDiscoMsg {
                        msg,
                        disco: sender_disco,
                        from: SocketAddr::new(
                            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                            0,
                        ),
                        vni: 0,
                        relay_server_node_key: Some(source.clone()),
                        source_node_key: Some(source.clone()),
                    });
                }
            }
            Message::AllocateUdpRelayEndpointRequest(alloc_req) => {
                // A peer is asking us to allocate a relay endpoint. If we
                // have a relay server extension, authenticate the sender
                // is a known tailnet peer and call allocate_endpoint.
                if let Some(ref rs) = self.relay_server {
                    // Authenticate: the sender's disco key must map to a
                    // known peer in our netmap. Since the message arrived
                    // via DERP, the `source` NodePublic is the DERP-claimed
                    // sender, and `sender_disco` is the authenticated disco
                    // key from the NaCl box. Both must match a known peer.
                    let peer_known = {
                        let d2p = self
                            .disco_to_peer
                            .read()
                            .expect("disco_to_peer lock poisoned");
                        d2p.contains_key(&sender_disco)
                    };
                    if !peer_known {
                        return;
                    }

                    if let Some(resp) = rs
                        .handle_alloc_request(alloc_req.client_disco.clone(), alloc_req.generation)
                    {
                        // Send the response via DERP back to the requester.
                        let resp_msg = Message::AllocateUdpRelayEndpointResponse(resp);
                        if let Some(sealed) = self.disco.seal(&sender_disco, &resp_msg) {
                            let region = if derp_region > 0 {
                                derp_region
                            } else {
                                self.derp.home_region()
                            };
                            self.derp.send_packet(region, source, sealed).await;
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// Generate a random 12-byte disco ping tx_id.
fn random_tx_id() -> [u8; 12] {
    use rand::RngCore;
    let mut tx = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut tx);
    tx
}

/// Gather local interface endpoints for the MapRequest `Endpoints` field
/// and CallMeMaybe. Pairs `udp_port` with each up, non-link-local IPv4
/// address on the host (plus loopback) so peers on the same LAN/host can
/// reach us directly. Mirrors Go magicsock's `determineEndpoints` local
/// interface enumeration (`netmon.LocalAddresses` + bound port).
pub fn gather_local_endpoints(udp_port: u16) -> Vec<String> {
    use std::collections::HashSet;
    use std::net::IpAddr;

    let ifaces = match if_addrs::get_if_addrs() {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut eps: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut loopback_eps: Vec<String> = Vec::new();

    for iface in &ifaces {
        if !iface.is_oper_up() {
            continue;
        }
        let v4 = match iface.ip() {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => continue, // UDP socket is v4; netstack is v4-only.
        };
        // Skip unspecified (0.0.0.0) and link-local (169.254/16).
        if v4.is_unspecified() || is_link_local_v4(v4) {
            continue;
        }
        let s = format!("{v4}:{udp_port}");
        if v4.is_loopback() {
            if seen.insert(s.clone()) {
                loopback_eps.push(s);
            }
        } else if seen.insert(s.clone()) {
            eps.push(s);
        }
    }

    if eps.is_empty() {
        eps.append(&mut loopback_eps);
    }
    eps
}

/// Whether an IPv4 address is link-local (169.254.0.0/16).
fn is_link_local_v4(addr: std::net::Ipv4Addr) -> bool {
    let o = addr.octets();
    o[0] == 169 && o[1] == 254
}

/// Check if debug tracing is enabled (RUSTSCALE_DEBUG=1).
fn debug_enabled() -> bool {
    std::env::var("RUSTSCALE_DEBUG").as_deref() == Ok("1")
}

/// Short 4-byte hex prefix of a node key for log lines.
fn short_key(k: &NodePublic) -> String {
    hex::encode(&k.raw32()[..4])
}

#[cfg(test)]
mod tests;
