//! Path-selection engine for rustscale: direct UDP, DERP relay, and peer relay.
//!
//! Ports the semantics of Go's `wgengine/magicsock` in simplified form. Owns
//! UDP sockets (v4+v6), a DERP client for the home region, and per-peer
//! endpoint state. Disco ping/pong probing discovers direct paths; CallMeMaybe
//! via DERP punches NAT; DERP is the fallback data path.
//!
//! # API
//!
//! - [`Magicsock::new`] — bind UDP, connect DERP, start background I/O.
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
    /// An already-connected DERP client, if any. `None` means DERP is not used.
    pub derp_client: Option<DerpClient>,
    /// Optional UDP bind address (`None` = no direct UDP; DERP-only mode).
    pub udp_bind: Option<SocketAddr>,
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
    local_udp_addrs: Vec<String>,
    derp: Option<Arc<DerpIo>>,
    endpoints: RwLock<HashMap<NodePublic, Endpoint>>,
    disco_to_peer: RwLock<HashMap<DiscoPublic, NodePublic>>,
    addr_to_peer: RwLock<HashMap<SocketAddr, NodePublic>>,
    wg_send: mpsc::Sender<WgDatagram>,
}

impl Magicsock {
    /// Create a new Magicsock: bind UDP (if configured), start DERP I/O, and
    /// launch background recv tasks.
    pub async fn new(config: MagicsockConfig) -> Result<Self, MagicsockError> {
        let node_public = config.private_key.public();
        let disco = DiscoIo::new(config.disco_key);

        let (wg_send, wg_recv) = mpsc::channel(256);

        // Bind UDP socket if configured.
        let (udp, local_udp_addrs) = if let Some(bind_addr) = config.udp_bind {
            let sock = UdpSocket::bind(bind_addr).await?;
            let local = sock.local_addr()?.to_string();
            (Some(Arc::new(sock)), vec![local])
        } else {
            (None, Vec::new())
        };

        // Start DERP I/O if a client was provided.
        let derp = config.derp_client.map(|c| Arc::new(DerpIo::spawn(c)));

        let inner = Arc::new(Inner {
            node_public,
            disco,
            udp,
            local_udp_addrs,
            derp,
            endpoints: RwLock::new(HashMap::new()),
            disco_to_peer: RwLock::new(HashMap::new()),
            addr_to_peer: RwLock::new(HashMap::new()),
            wg_send,
        });

        // Launch background recv tasks.
        spawn_recv_tasks(inner.clone());

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
    pub fn local_udp_addrs(&self) -> &[String] {
        &self.inner.local_udp_addrs
    }

    /// Update the peer set from a netmap. Creates/updates per-peer endpoints,
    /// starts disco probing, and sends CallMeMaybe via DERP.
    pub async fn set_netmap(&self, peers: Vec<Node>) -> Result<(), MagicsockError> {
        // Phase 1: update endpoint state under the lock.
        let probe_list: Vec<(NodePublic, DiscoPublic, Vec<SocketAddr>)> = {
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

                ep.set_candidates(candidates.clone());
                ep.reset_call_me_maybe();

                if !peer.DiscoKey.is_zero() {
                    d2p.insert(peer.DiscoKey.clone(), peer.Key.clone());
                }

                probes.push((peer.Key.clone(), peer.DiscoKey.clone(), candidates));
            }
            probes
        };

        // Phase 2: send disco pings and CallMeMaybe (async, outside the lock).
        for (peer_key, peer_disco, candidates) in probe_list {
            // Send disco Pings to each candidate over UDP.
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
                        let _ = udp.send_to(&packet, addr).await;
                    }
                }
            }

            // Send CallMeMaybe via DERP.
            if let Some(ref derp) = self.inner.derp {
                if !peer_disco.is_zero() {
                    let should = {
                        let mut endpoints = self
                            .inner
                            .endpoints
                            .write()
                            .expect("endpoints lock poisoned");
                        endpoints
                            .get_mut(&peer_key)
                            .is_some_and(|ep| ep.should_send_call_me_maybe())
                    };
                    if should {
                        let cmm = Message::CallMeMaybe(CallMeMaybe {
                            my_number: self
                                .inner
                                .local_udp_addrs
                                .iter()
                                .filter_map(|s| s.parse::<SocketAddr>().ok())
                                .map(rustscale_disco::AddrPort::from)
                                .collect(),
                        });
                        if let Some(packet) = self.inner.disco.seal(&peer_disco, &cmm) {
                            derp.send_packet(peer_key, packet).await;
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
        let path = {
            let endpoints = self
                .inner
                .endpoints
                .read()
                .expect("endpoints lock poisoned");
            let ep = endpoints.get(&peer).ok_or(MagicsockError::PeerNotFound)?;
            ep.best_path(std::time::Instant::now())
        };

        match path {
            endpoint::BestPath::Direct { addr, .. } => {
                if let Some(ref udp) = self.inner.udp {
                    udp.send_to(datagram, addr).await?;
                    return Ok(());
                }
                // No UDP socket; fall through to DERP.
                self.send_via_derp(peer, datagram).await
            }
            endpoint::BestPath::Relay { addr, vni } => {
                if let Some(ref udp) = self.inner.udp {
                    let framed = relay::encode_geneve(vni, datagram);
                    udp.send_to(&framed, addr).await?;
                    return Ok(());
                }
                self.send_via_derp(peer, datagram).await
            }
            endpoint::BestPath::Derp { .. } => self.send_via_derp(peer, datagram).await,
            endpoint::BestPath::None => self.send_via_derp(peer, datagram).await,
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

    async fn send_via_derp(&self, peer: NodePublic, datagram: &[u8]) -> Result<(), MagicsockError> {
        if let Some(ref derp) = self.inner.derp {
            derp.send_packet(peer, datagram.to_vec()).await;
            Ok(())
        } else {
            Err(MagicsockError::NoPath)
        }
    }
}

/// Launch background UDP and DERP recv tasks. Each task holds an `Arc<Inner>`
/// clone and dispatches incoming packets to the disco/WG handlers.
fn spawn_recv_tasks(inner: Arc<Inner>) {
    // UDP recv task.
    if let Some(ref udp) = inner.udp {
        let udp = udp.clone();
        let inner = inner.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_536];
            loop {
                match udp.recv_from(&mut buf).await {
                    Ok((len, addr)) => {
                        inner.handle_udp_packet(&buf[..len], addr).await;
                    }
                    Err(_) => break,
                }
            }
        });
    }

    // DERP recv task.
    if let Some(ref derp) = inner.derp {
        let derp = derp.clone();
        let inner = inner.clone();
        tokio::spawn(async move {
            while let Some((source, data)) = derp.try_recv().await {
                inner.handle_derp_packet(&data, source).await;
            }
        });
    }
}

impl Inner {
    async fn handle_udp_packet(&self, data: &[u8], src: SocketAddr) {
        if DiscoIo::looks_like_disco(data) {
            self.handle_disco_udp(data, src).await;
        } else {
            self.handle_wg_udp(data, src).await;
        }
    }

    async fn handle_derp_packet(&self, data: &[u8], source: NodePublic) {
        if DiscoIo::looks_like_disco(data) {
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
                // Respond with a Pong over UDP to the source address.
                let pong = Message::Pong(Pong {
                    tx_id: ping.tx_id,
                    src: rustscale_disco::AddrPort::from(src),
                });
                if let Some(reply) = self.disco.seal(&sender_disco, &pong) {
                    if let Some(ref udp) = self.udp {
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
                let confirmed_addr = {
                    let mut endpoints = self.endpoints.write().expect("endpoints lock poisoned");
                    if let Some(ep) = endpoints.get_mut(&peer) {
                        if ep.match_pong(&pong.tx_id).is_some() {
                            ep.confirm_direct(src, std::time::Instant::now());
                            Some(src)
                        } else {
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

        match msg {
            Message::Ping(ping) => {
                // Respond with a Pong via DERP.
                let pong = Message::Pong(Pong {
                    tx_id: ping.tx_id,
                    src: rustscale_disco::AddrPort::new(
                        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                        0,
                    ),
                });
                if let Some(reply) = self.disco.seal(&sender_disco, &pong) {
                    if let Some(ref derp) = self.derp {
                        derp.send_packet(source, reply).await;
                    }
                }
            }
            Message::Pong(_) => {
                // Pong via DERP — no useful address to confirm; just ignore.
            }
            Message::CallMeMaybe(cmm) => {
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

#[cfg(test)]
mod tests;
