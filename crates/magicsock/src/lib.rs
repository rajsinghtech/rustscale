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
//! - [`Magicsock::poll_recv`] — receive the next WG datagram from any peer.
//! - [`Magicsock::send`] — send a WG datagram to a peer over the best path.

#![forbid(unsafe_code)]

mod derp_io;
mod disco_io;
mod endpoint;
mod relay;

pub use endpoint::{BestPath, Endpoint, PathClass, TRUST_BEST_ADDR_DURATION};
pub use relay::{decode_geneve, encode_geneve, RelayHandshake, RelayPhase, GENEVE_HEADER_LEN};

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use rustscale_derp::DerpClient;
use rustscale_disco::{CallMeMaybe, Message, Ping, Pong};
use rustscale_key::{DiscoPrivate, DiscoPublic, NodePrivate, NodePublic};
use rustscale_tailcfg::{DERPMap, Node};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use derp_io::DerpIo;
use disco_io::DiscoIo;

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
    /// force every send via DERP. Disco pings are not sent in `set_netmap`,
    /// CallMeMaybe-initiated pings are skipped, and inbound disco Pings over
    /// UDP are not answered — so neither side confirms a direct path. `send`
    /// also ignores any Direct/Relay best path and routes via DERP. This
    /// pins both directions to DERP, letting interop tests assert relayed
    /// connectivity in isolation. Production code should leave this false.
    pub disable_direct_paths: bool,
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
    wg_recv: tokio::sync::Mutex<mpsc::Receiver<WgDatagram>>,
}

struct Inner {
    node_public: NodePublic,
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
    derp_recv_tx: mpsc::Sender<(i32, NodePublic, Vec<u8>)>,
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
        mpsc::Receiver<(i32, NodePublic, Vec<u8>)>,
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

        let client = match DerpClient::connect_with_upgrade_dial(
            &dial_addr,
            &tls_host,
            port,
            true,
            self.node_private.clone(),
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
/// packets to the shared derp_recv channel for demux. When the underlying
/// connection dies (reader task exits, `try_recv` returns `None`), the
/// region is signaled for automatic reconnection via `reconnect_tx`.
fn spawn_derp_recv_consumer(
    region_id: i32,
    io: Arc<DerpIo>,
    tx: mpsc::Sender<(i32, NodePublic, Vec<u8>)>,
    reconnect_tx: mpsc::UnboundedSender<i32>,
) {
    tokio::spawn(async move {
        while let Some((source, data)) = io.try_recv().await {
            if tx.send((region_id, source, data)).await.is_err() {
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
    pub async fn new(config: MagicsockConfig) -> Result<Self, MagicsockError> {
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

        let inner = Arc::new(Inner {
            node_public,
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
        });

        // Launch background recv tasks (UDP + DERP demux + reconnect supervisor).
        spawn_recv_tasks(inner.clone(), derp_recv_rx, reconnect_rx);

        Ok(Self {
            inner,
            wg_recv: tokio::sync::Mutex::new(wg_recv),
        })
    }

    /// Our node public key.
    pub fn node_public(&self) -> NodePublic {
        self.inner.node_public.clone()
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
            if !self.inner.disable_direct_paths {
                if let Some(ref udp) = self.inner.udp {
                    for addr in &candidates {
                        let tx_id = random_tx_id();
                        {
                            let mut endpoints = self
                                .inner
                                .endpoints
                                .write()
                                .expect("endpoints lock poisoned");
                            if let Some(ep) = endpoints.get_mut(&peer_key) {
                                ep.add_pending_ping(tx_id, *addr, std::time::Instant::now());
                            }
                        }
                        let ping = Message::Ping(Ping {
                            tx_id,
                            node_key: self.inner.node_public.clone(),
                            padding: 0,
                        });
                        if let Some(packet) = self.inner.disco.seal(&peer_disco, &ping) {
                            if debug_enabled() {
                                eprintln!(
                                    "DBG disco_ping send to {addr} peer={}",
                                    short_key(&peer_key)
                                );
                            }
                            let _ = udp.send_to(&packet, addr).await;
                        }
                    }
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

        Ok(())
    }

    /// Receive the next WG datagram from any peer. Blocks until one is ready.
    pub async fn poll_recv(&self) -> Result<WgDatagram, MagicsockError> {
        self.wg_recv
            .lock()
            .await
            .recv()
            .await
            .ok_or(MagicsockError::NoPath)
    }

    /// Send a WG datagram to `peer` over the best available path.
    pub async fn send(&self, peer: NodePublic, datagram: &[u8]) -> Result<(), MagicsockError> {
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

        match path {
            endpoint::BestPath::Direct { addr, .. } => {
                if self.inner.disable_direct_paths {
                    return self.send_via_derp(peer, derp_region, datagram).await;
                }
                if let Some(ref udp) = self.inner.udp {
                    udp.send_to(datagram, addr).await?;
                    return Ok(());
                }
                self.send_via_derp(peer, derp_region, datagram).await
            }
            endpoint::BestPath::Relay { addr, vni } => {
                if self.inner.disable_direct_paths {
                    return self.send_via_derp(peer, derp_region, datagram).await;
                }
                if let Some(ref udp) = self.inner.udp {
                    let framed = relay::encode_geneve(vni, datagram);
                    udp.send_to(&framed, addr).await?;
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
    derp_recv_rx: mpsc::Receiver<(i32, NodePublic, Vec<u8>)>,
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
                        inner.handle_udp_packet(&buf[..len], addr).await;
                        // Drain the rest of the currently-ready packet burst
                        // without another await on the socket.
                        while let Ok((len2, addr2)) = udp.try_recv_from(&mut buf) {
                            inner.handle_udp_packet(&buf[..len2], addr2).await;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    }

    // DERP demux task: consumes from all DERP region recv consumers and
    // dispatches to handle_derp_packet. This single task handles packets
    // from ALL connected regions (home + lazy).
    let inner2 = inner.clone();
    tokio::spawn(async move {
        let mut derp_recv_rx = derp_recv_rx;
        while let Some((region_id, source, data)) = derp_recv_rx.recv().await {
            inner2.handle_derp_packet(&data, source, region_id).await;
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

impl Inner {
    async fn handle_udp_packet(&self, data: &[u8], src: SocketAddr) {
        if DiscoIo::looks_like_disco(data) {
            self.handle_disco_udp(data, src).await;
        } else {
            self.handle_wg_udp(data, src).await;
        }
    }

    async fn handle_derp_packet(&self, data: &[u8], source: NodePublic, region_id: i32) {
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

    async fn handle_wg_udp(&self, data: &[u8], src: SocketAddr) {
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
        // Unknown source address — drop the packet.
    }

    async fn handle_disco_udp(&self, packet: &[u8], src: SocketAddr) {
        let (sender_disco, msg) = match self.disco.open(packet) {
            Some(v) => v,
            None => return,
        };

        let peer = {
            let map = self
                .disco_to_peer
                .read()
                .expect("disco_to_peer lock poisoned");
            map.get(&sender_disco).cloned()
        };
        let peer = match peer {
            Some(p) => p,
            None => return,
        };

        match msg {
            Message::Ping(ping) => {
                if debug_enabled() {
                    eprintln!("DBG disco_ping recv from {src} peer={}", short_key(&peer));
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
                        let _ = udp.send_to(&reply, src).await;
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
                let confirmed_addr = {
                    let mut endpoints = self.endpoints.write().expect("endpoints lock poisoned");
                    if let Some(ep) = endpoints.get_mut(&peer) {
                        if ep.match_pong(&pong.tx_id).is_some() {
                            ep.confirm_direct(src, std::time::Instant::now());
                            if debug_enabled() {
                                eprintln!(
                                    "DBG direct_confirmed peer={} addr={src}",
                                    short_key(&peer)
                                );
                            }
                            Some(src)
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
                if let Some(addr) = confirmed_addr {
                    let mut map = self
                        .addr_to_peer
                        .write()
                        .expect("addr_to_peer lock poisoned");
                    map.insert(addr, peer);
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
            Message::Pong(_) => {
                // Pong via DERP — no useful address to confirm; just ignore.
            }
            Message::CallMeMaybe(cmm) => {
                // When direct paths are disabled, don't ping the peer's
                // advertised addresses — we won't use a direct path anyway.
                if self.disable_direct_paths {
                    return;
                }
                // The peer is telling us its UDP addresses. Add them as
                // candidates and start pinging.
                let peer_disco = sender_disco.clone();
                for ep in &cmm.my_number {
                    let addr = SocketAddr::from(*ep);
                    let tx_id = random_tx_id();
                    {
                        let mut endpoints =
                            self.endpoints.write().expect("endpoints lock poisoned");
                        if let Some(ep_state) = endpoints.get_mut(&source) {
                            ep_state.add_pending_ping(tx_id, addr, std::time::Instant::now());
                        }
                    }
                    let ping = Message::Ping(Ping {
                        tx_id,
                        node_key: self.node_public.clone(),
                        padding: 0,
                    });
                    if let Some(reply) = self.disco.seal(&peer_disco, &ping) {
                        if let Some(ref udp) = self.udp {
                            let _ = udp.send_to(&reply, addr).await;
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
