//! Relay manager: discovers relay servers, allocates endpoints, runs the
//! client-side 3-way bind handshake, and probes latency via disco ping/pong.
//!
//! Ports Go's `wgengine/magicsock/relaymanager.go` and the relay-related
//! sections of `magicsock.go` (`updateRelayServersSet`, `candidatePeerRelay`,
//! `sendDiscoAllocateUDPRelayEndpointRequest`).
//!
//! # Architecture
//!
//! The relay manager runs as a background tokio task with an event loop.
//! Events are fed via an unbounded mpsc channel. Allocation and handshake
//! work are spawned as sub-tasks that report results back through the same
//! channel. The event loop owns all mutable state (server set, in-flight
//! work maps) and processes events serially.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use rustscale_disco::{
    AllocateUdpRelayEndpointRequest, AllocateUdpRelayEndpointResponse, BindUdpRelayEndpoint,
    BindUdpRelayEndpointAnswer, BindUdpRelayEndpointCommon, CallMeMaybeVia, Message, Ping,
    UdpRelayEndpoint,
};
use rustscale_key::{DiscoPublic, NodePublic};
use rustscale_tailcfg::{
    cap_ver_is_relay_capable, has_capability, Node, PEER_CAPABILITY_RELAY_TARGET,
};

#[cfg(test)]
use rustscale_disco::BindUdpRelayEndpointChallenge;

/// Allocation request timeout (Go: `allocateUDPRelayEndpointRequestTimeout`).
const ALLOC_TIMEOUT: Duration = Duration::from_secs(10);

/// Retry interval for allocation requests (Go: `udprelay.ServerRetryAfter`).
const ALLOC_RETRY: Duration = Duration::from_secs(3);

/// Maximum handshake lifetime, independent of server-configured BindLifetime.
const MAX_HANDSHAKE_LIFETIME: Duration = Duration::from_secs(30);

/// Maximum number of pings to send during handshake probing.
const MAX_PINGS: usize = 10;

/// A candidate peer relay server discovered from the netmap.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CandidatePeerRelay {
    pub node_key: NodePublic,
    pub disco_key: DiscoPublic,
    pub derp_home_region: u16,
}

impl CandidatePeerRelay {
    pub fn is_valid(&self) -> bool {
        !self.node_key.is_zero() && !self.disco_key.is_zero()
    }
}

/// An allocated relay server endpoint. Mirrors Go's
/// `udprelay.ServerEndpoint`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerEndpoint {
    pub server_disco: DiscoPublic,
    pub client_disco: [DiscoPublic; 2],
    pub lamport_id: u64,
    pub vni: u32,
    pub addr_ports: Vec<SocketAddr>,
    pub bind_lifetime: Duration,
    pub steady_state_lifetime: Duration,
}

impl ServerEndpoint {
    pub fn from_udp_relay_endpoint(ep: &UdpRelayEndpoint) -> Self {
        Self {
            server_disco: ep.server_disco.clone(),
            client_disco: ep.client_disco.clone(),
            lamport_id: ep.lamport_id,
            vni: ep.vni,
            addr_ports: ep.addr_ports.iter().map(|ap| (*ap).into()).collect(),
            bind_lifetime: ep.bind_lifetime,
            steady_state_lifetime: ep.steady_state_lifetime,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct AddrPortVni {
    addr: SocketAddr,
    vni: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ServerDiscoVni {
    server_disco: DiscoPublic,
    vni: u32,
}

fn sort_pair(a: &DiscoPublic, b: &DiscoPublic) -> [DiscoPublic; 2] {
    if a.raw32() <= b.raw32() {
        [a.clone(), b.clone()]
    } else {
        [b.clone(), a.clone()]
    }
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

enum RelayEvent {
    StartDiscovery {
        peer_key: NodePublic,
        peer_disco: DiscoPublic,
    },
    CancelWork {
        peer_key: NodePublic,
    },
    ServersUpdate(Vec<CandidatePeerRelay>),
    ServerUpsert(CandidatePeerRelay),
    ServerRemove(NodePublic),
    NewServerEndpoint {
        peer_key: NodePublic,
        peer_disco: DiscoPublic,
        server_endpoint: ServerEndpoint,
        server: Option<CandidatePeerRelay>,
    },
    DiscoMsg(RelayDiscoMsg),
    DerpHomeChange {
        node_key: NodePublic,
        region: u16,
    },
    AllocWorkDone(AllocWorkResult),
    HandshakeWorkDone(HandshakeWorkResult),
}

pub struct RelayDiscoMsg {
    pub msg: Message,
    pub disco: DiscoPublic,
    pub from: SocketAddr,
    pub vni: u32,
    pub relay_server_node_key: Option<NodePublic>,
    pub source_node_key: Option<NodePublic>,
}

struct AllocWorkResult {
    peer_key: NodePublic,
    peer_disco: DiscoPublic,
    server: CandidatePeerRelay,
    #[allow(dead_code)]
    disco_keys: [DiscoPublic; 2],
    server_endpoint: Option<ServerEndpoint>,
}

struct HandshakeWorkResult {
    peer_key: NodePublic,
    server_disco: DiscoPublic,
    vni: u32,
    pong_from: Option<SocketAddr>,
    latency: Duration,
}

// ---------------------------------------------------------------------------
// In-flight work tracking
// ---------------------------------------------------------------------------

struct AllocWork {
    #[allow(dead_code)]
    server: CandidatePeerRelay,
    disco_keys: [DiscoPublic; 2],
    #[allow(dead_code)]
    alloc_gen: u32,
    cancel: tokio::sync::oneshot::Sender<()>,
    response_tx: tokio::sync::mpsc::Sender<AllocateUdpRelayEndpointResponse>,
}

struct HandshakeWork {
    #[allow(dead_code)]
    server_disco: DiscoPublic,
    vni: u32,
    lamport_id: u64,
    cancel: tokio::sync::oneshot::Sender<()>,
    disco_msg_tx: tokio::sync::mpsc::Sender<(Message, SocketAddr, u32)>,
}

// ---------------------------------------------------------------------------
// Relay manager state
// ---------------------------------------------------------------------------

struct RelayManagerState {
    servers_by_node_key: HashMap<NodePublic, CandidatePeerRelay>,
    alloc_work: HashMap<NodePublic, HashMap<CandidatePeerRelay, AllocWork>>,
    handshake_work: HashMap<NodePublic, HashMap<DiscoPublic, HandshakeWork>>,
    handshake_by_sdv: HashMap<ServerDiscoVni, NodePublic>,
    handshake_awaiting_pong: HashMap<AddrPortVni, NodePublic>,
    handshake_generation: u32,
    alloc_generation: u32,
}

impl RelayManagerState {
    fn new() -> Self {
        Self {
            servers_by_node_key: HashMap::new(),
            alloc_work: HashMap::new(),
            handshake_work: HashMap::new(),
            handshake_by_sdv: HashMap::new(),
            handshake_awaiting_pong: HashMap::new(),
            handshake_generation: 0,
            alloc_generation: 0,
        }
    }

    fn has_active_work_for(&self, peer_key: &NodePublic) -> bool {
        self.alloc_work.contains_key(peer_key) || self.handshake_work.contains_key(peer_key)
    }

    fn next_handshake_gen(&mut self) -> u32 {
        self.handshake_generation = self.handshake_generation.wrapping_add(1);
        if self.handshake_generation == 0 {
            self.handshake_generation = 1;
        }
        self.handshake_generation
    }

    fn next_alloc_gen(&mut self) -> u32 {
        self.alloc_generation = self.alloc_generation.wrapping_add(1);
        if self.alloc_generation == 0 {
            self.alloc_generation = 1;
        }
        self.alloc_generation
    }
}

// ---------------------------------------------------------------------------
// Public handle
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct RelayManagerHandle {
    tx: tokio::sync::mpsc::UnboundedSender<RelayEvent>,
}

impl RelayManagerHandle {
    pub fn start_discovery(&self, peer_key: NodePublic, peer_disco: DiscoPublic) {
        let _ = self.tx.send(RelayEvent::StartDiscovery {
            peer_key,
            peer_disco,
        });
    }

    pub fn cancel_work(&self, peer_key: NodePublic) {
        let _ = self.tx.send(RelayEvent::CancelWork { peer_key });
    }

    pub fn handle_relay_servers_set(&self, servers: Vec<CandidatePeerRelay>) {
        let _ = self.tx.send(RelayEvent::ServersUpdate(servers));
    }

    pub fn handle_relay_server_upsert(&self, server: CandidatePeerRelay) {
        let _ = self.tx.send(RelayEvent::ServerUpsert(server));
    }

    pub fn handle_relay_server_remove(&self, node_key: NodePublic) {
        let _ = self.tx.send(RelayEvent::ServerRemove(node_key));
    }

    pub fn handle_call_me_maybe_via(
        &self,
        peer_key: NodePublic,
        peer_disco: DiscoPublic,
        dm: &CallMeMaybeVia,
    ) {
        let se = ServerEndpoint::from_udp_relay_endpoint(&dm.endpoint);
        let _ = self.tx.send(RelayEvent::NewServerEndpoint {
            peer_key,
            peer_disco,
            server_endpoint: se,
            server: None,
        });
    }

    pub fn handle_rx_disco_msg(&self, msg: RelayDiscoMsg) {
        let _ = self.tx.send(RelayEvent::DiscoMsg(msg));
    }

    pub fn handle_derp_home_change(&self, node_key: NodePublic, region: u16) {
        let _ = self
            .tx
            .send(RelayEvent::DerpHomeChange { node_key, region });
    }
}

/// Discover relay server candidates from the netmap.
pub fn discover_relay_servers(self_node: &Node, peers: &[Node]) -> Vec<CandidatePeerRelay> {
    let mut servers = Vec::new();
    for node in peers.iter().chain(std::iter::once(self_node)) {
        if node.Key.is_zero() {
            continue;
        }
        if node.ID != self_node.ID && !cap_ver_is_relay_capable(node.Cap) {
            continue;
        }
        if !has_capability(&node.CapMap, PEER_CAPABILITY_RELAY_TARGET) {
            continue;
        }
        // Check Hostinfo.PeerRelay (Go: `p.Hostinfo().PeerRelay`).
        let peer_relay = node
            .Hostinfo
            .as_ref()
            .is_some_and(|hi| hi.PeerRelay);
        if !peer_relay && node.ID != self_node.ID {
            continue;
        }
        if !node.DiscoKey.is_zero() {
            servers.push(CandidatePeerRelay {
                node_key: node.Key.clone(),
                disco_key: node.DiscoKey.clone(),
                derp_home_region: node.HomeDERP.max(0) as u16,
            });
        }
    }
    servers
}

/// Trait providing I/O capabilities the relay manager needs.
pub trait RelayManagerContext: Send + Sync + 'static {
    fn seal_disco(&self, peer_disco: &DiscoPublic, msg: &Message) -> Option<Vec<u8>>;
    fn send_disco_udp(&self, addr: SocketAddr, vni: u32, control: bool, packet: &[u8]);
    fn send_disco_derp(&self, region: i32, dst_key: NodePublic, packet: Vec<u8>);
    fn our_disco_public(&self) -> DiscoPublic;
    fn our_node_public(&self) -> NodePublic;
    fn peer_disco_key(&self, peer_key: &NodePublic) -> Option<DiscoPublic>;
    fn peer_derp_region(&self, peer_key: &NodePublic) -> i32;
    fn set_relay(&self, peer_key: &NodePublic, addr: SocketAddr, vni: u32);
    fn send_pong_via_relay(
        &self,
        addr: SocketAddr,
        vni: u32,
        peer_disco: &DiscoPublic,
        tx_id: [u8; 12],
    );
    fn is_self_node(&self, node_key: &NodePublic) -> bool;
    fn handle_self_alloc_request(
        &self,
        client_disco: [DiscoPublic; 2],
        generation: u32,
    ) -> Option<AllocateUdpRelayEndpointResponse>;
}

/// Spawn the relay manager event loop.
pub fn spawn_relay_manager<RM: RelayManagerContext>(ctx: std::sync::Arc<RM>) -> RelayManagerHandle {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let handle = RelayManagerHandle { tx: tx.clone() };
    tokio::spawn(run_event_loop(rx, tx, ctx));
    handle
}

/// The event loop.
async fn run_event_loop<RM: RelayManagerContext>(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<RelayEvent>,
    event_tx: tokio::sync::mpsc::UnboundedSender<RelayEvent>,
    ctx: std::sync::Arc<RM>,
) {
    let mut state = RelayManagerState::new();

    while let Some(event) = rx.recv().await {
        match event {
            RelayEvent::StartDiscovery {
                peer_key,
                peer_disco,
            } => {
                if !state.has_active_work_for(&peer_key) {
                    allocate_all_servers(&mut state, &ctx, &event_tx, peer_key, peer_disco);
                }
            }
            RelayEvent::CancelWork { peer_key } => {
                stop_work(&mut state, &peer_key);
            }
            RelayEvent::ServersUpdate(servers) => {
                handle_servers_update(&mut state, servers);
            }
            RelayEvent::ServerUpsert(server) => {
                state
                    .servers_by_node_key
                    .insert(server.node_key.clone(), server);
            }
            RelayEvent::ServerRemove(node_key) => {
                state.servers_by_node_key.remove(&node_key);
            }
            RelayEvent::NewServerEndpoint {
                peer_key,
                peer_disco,
                server_endpoint,
                server,
            } => {
                handle_new_server_endpoint(
                    &mut state,
                    &ctx,
                    &event_tx,
                    peer_key,
                    peer_disco,
                    server_endpoint,
                    server,
                );
            }
            RelayEvent::DiscoMsg(msg) => {
                handle_rx_disco_msg(&mut state, &ctx, msg);
            }
            RelayEvent::DerpHomeChange { node_key, region } => {
                if let Some(s) = state.servers_by_node_key.get_mut(&node_key) {
                    s.derp_home_region = region;
                }
            }
            RelayEvent::AllocWorkDone(result) => {
                handle_alloc_work_done(&mut state, &ctx, &event_tx, result);
            }
            RelayEvent::HandshakeWorkDone(result) => {
                handle_handshake_work_done(&mut state, &ctx, result);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Server set management
// ---------------------------------------------------------------------------

fn handle_servers_update(state: &mut RelayManagerState, servers: Vec<CandidatePeerRelay>) {
    let new_set: HashMap<NodePublic, CandidatePeerRelay> = servers
        .into_iter()
        .filter(CandidatePeerRelay::is_valid)
        .map(|s| (s.node_key.clone(), s))
        .collect();
    state.servers_by_node_key = new_set;
}

// ---------------------------------------------------------------------------
// Allocation
// ---------------------------------------------------------------------------

fn allocate_all_servers<RM: RelayManagerContext>(
    state: &mut RelayManagerState,
    ctx: &std::sync::Arc<RM>,
    event_tx: &tokio::sync::mpsc::UnboundedSender<RelayEvent>,
    peer_key: NodePublic,
    peer_disco: DiscoPublic,
) {
    if state.servers_by_node_key.is_empty() {
        return;
    }

    let our_disco = ctx.our_disco_public();
    let disco_keys = sort_pair(&our_disco, &peer_disco);

    for (_, server) in state.servers_by_node_key.clone() {
        let alloc_gen = state.next_alloc_gen();
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
        let (resp_tx, resp_rx) = tokio::sync::mpsc::channel::<AllocateUdpRelayEndpointResponse>(1);

        let work = AllocWork {
            server: server.clone(),
            disco_keys: disco_keys.clone(),
            alloc_gen,
            cancel: cancel_tx,
            response_tx: resp_tx,
        };

        state
            .alloc_work
            .entry(peer_key.clone())
            .or_default()
            .insert(server.clone(), work);

        let ctx2 = ctx.clone();
        let event_tx2 = event_tx.clone();
        let peer_key2 = peer_key.clone();
        let peer_disco2 = peer_disco.clone();
        let server2 = server.clone();
        tokio::spawn(spawn_alloc_work(
            ctx2,
            event_tx2,
            peer_key2,
            peer_disco2,
            server2,
            disco_keys.clone(),
            alloc_gen,
            cancel_rx,
            resp_rx,
        ));
    }
}

async fn spawn_alloc_work<RM: RelayManagerContext>(
    ctx: std::sync::Arc<RM>,
    event_tx: tokio::sync::mpsc::UnboundedSender<RelayEvent>,
    peer_key: NodePublic,
    peer_disco: DiscoPublic,
    server: CandidatePeerRelay,
    disco_keys: [DiscoPublic; 2],
    alloc_gen: u32,
    cancel_rx: tokio::sync::oneshot::Receiver<()>,
    mut resp_rx: tokio::sync::mpsc::Receiver<AllocateUdpRelayEndpointResponse>,
) {
    let dm = AllocateUdpRelayEndpointRequest {
        client_disco: disco_keys.clone(),
        generation: alloc_gen,
    };

    // In-process shortcut: when the relay server is self, bypass DERP and
    // call the local extension directly (Go magicsock.go:1946-1963).
    if ctx.is_self_node(&server.node_key) {
        if let Some(resp) = ctx.handle_self_alloc_request(disco_keys.clone(), alloc_gen) {
            if resp.generation == alloc_gen {
                let sorted = sort_pair(
                    &resp.endpoint.client_disco[0],
                    &resp.endpoint.client_disco[1],
                );
                if sorted == disco_keys {
                    let se = ServerEndpoint::from_udp_relay_endpoint(&resp.endpoint);
                    let _ = event_tx.send(RelayEvent::AllocWorkDone(AllocWorkResult {
                        peer_key,
                        peer_disco,
                        server,
                        disco_keys,
                        server_endpoint: Some(se),
                    }));
                    return;
                }
            }
        }
        let _ = event_tx.send(RelayEvent::AllocWorkDone(AllocWorkResult {
            peer_key,
            peer_disco,
            server,
            disco_keys,
            server_endpoint: None,
        }));
        return;
    }

    let sealed = if let Some(p) = ctx.seal_disco(
        &server.disco_key,
        &Message::AllocateUdpRelayEndpointRequest(dm.clone()),
    ) {
        p
    } else {
        let _ = event_tx.send(RelayEvent::AllocWorkDone(AllocWorkResult {
            peer_key,
            peer_disco,
            server,
            disco_keys,
            server_endpoint: None,
        }));
        return;
    };

    let derp_region = i32::from(server.derp_home_region);
    ctx.send_disco_derp(derp_region, server.node_key.clone(), sealed.clone());

    let retry_ctx = ctx.clone();
    let retry_sealed = sealed.clone();
    let retry_key = server.node_key.clone();
    let retry_region = derp_region;
    tokio::spawn(async move {
        tokio::time::sleep(ALLOC_RETRY).await;
        retry_ctx.send_disco_derp(retry_region, retry_key, retry_sealed);
    });

    let timeout = tokio::time::sleep(ALLOC_TIMEOUT);
    tokio::pin!(timeout);

    tokio::select! {
        _ = cancel_rx => {}
        () = &mut timeout => {}
        resp = resp_rx.recv() => {
            if let Some(resp) = resp {
                if resp.generation == alloc_gen {
                    let sorted = sort_pair(
                        &resp.endpoint.client_disco[0],
                        &resp.endpoint.client_disco[1],
                    );
                    if sorted == disco_keys {
                        let se = ServerEndpoint::from_udp_relay_endpoint(&resp.endpoint);
                        let _ = event_tx.send(RelayEvent::AllocWorkDone(AllocWorkResult {
                            peer_key,
                            peer_disco,
                            server,
                            disco_keys,
                            server_endpoint: Some(se),
                        }));
                        return;
                    }
                }
            }
        }
    }

    let _ = event_tx.send(RelayEvent::AllocWorkDone(AllocWorkResult {
        peer_key,
        peer_disco,
        server,
        disco_keys,
        server_endpoint: None,
    }));
}

fn handle_alloc_work_done<RM: RelayManagerContext>(
    state: &mut RelayManagerState,
    ctx: &std::sync::Arc<RM>,
    event_tx: &tokio::sync::mpsc::UnboundedSender<RelayEvent>,
    result: AllocWorkResult,
) {
    let peer_key = &result.peer_key;
    let peer_disco = &result.peer_disco;

    if let Some(by_server) = state.alloc_work.get_mut(peer_key) {
        by_server.remove(&result.server);
        if by_server.is_empty() {
            state.alloc_work.remove(peer_key);
        }
    }

    if let Some(se) = &result.server_endpoint {
        handle_new_server_endpoint(
            state,
            ctx,
            event_tx,
            peer_key.clone(),
            peer_disco.clone(),
            se.clone(),
            Some(result.server.clone()),
        );
    }
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

fn handle_new_server_endpoint<RM: RelayManagerContext>(
    state: &mut RelayManagerState,
    ctx: &std::sync::Arc<RM>,
    event_tx: &tokio::sync::mpsc::UnboundedSender<RelayEvent>,
    peer_key: NodePublic,
    peer_disco: DiscoPublic,
    se: ServerEndpoint,
    server: Option<CandidatePeerRelay>,
) {
    let sdv = ServerDiscoVni {
        server_disco: se.server_disco.clone(),
        vni: se.vni,
    };

    // LamportID dedup: check existing work for the same (server_disco, VNI).
    if let Some(existing_peer) = state.handshake_by_sdv.get(&sdv).cloned() {
        if let Some(by_sd) = state.handshake_work.get(&existing_peer) {
            if let Some(existing) = by_sd.get(&se.server_disco) {
                if existing.lamport_id >= se.lamport_id {
                    return;
                }
            }
        }
        cancel_handshake(state, &existing_peer, &se.server_disco);
    }

    // Check existing work for the same (peer, server_disco).
    if let Some(by_sd) = state.handshake_work.get(&peer_key) {
        if let Some(existing) = by_sd.get(&se.server_disco) {
            if se.lamport_id <= existing.lamport_id {
                return;
            }
        }
        cancel_handshake(state, &peer_key, &se.server_disco);
    }

    // Send CallMeMaybeVia if we allocated this endpoint.
    if server.as_ref().is_some_and(CandidatePeerRelay::is_valid) {
        send_call_me_maybe_via(ctx, &peer_key, &se);
    }

    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
    let (disco_msg_tx, disco_msg_rx) = tokio::sync::mpsc::channel::<(Message, SocketAddr, u32)>(16);

    let handshake_gen = state.next_handshake_gen();
    let work = HandshakeWork {
        server_disco: se.server_disco.clone(),
        vni: se.vni,
        lamport_id: se.lamport_id,
        cancel: cancel_tx,
        disco_msg_tx,
    };

    state
        .handshake_work
        .entry(peer_key.clone())
        .or_default()
        .insert(se.server_disco.clone(), work);

    state.handshake_by_sdv.insert(sdv, peer_key.clone());

    let ctx2 = ctx.clone();
    let event_tx2 = event_tx.clone();
    tokio::spawn(spawn_handshake_work(
        ctx2,
        event_tx2,
        peer_key,
        peer_disco,
        se,
        handshake_gen,
        cancel_rx,
        disco_msg_rx,
    ));
}

fn send_call_me_maybe_via<RM: RelayManagerContext>(
    ctx: &std::sync::Arc<RM>,
    peer_key: &NodePublic,
    se: &ServerEndpoint,
) {
    let peer_disco = match ctx.peer_disco_key(peer_key) {
        Some(d) => d,
        None => return,
    };
    let derp_region = ctx.peer_derp_region(peer_key);
    if derp_region <= 0 {
        return;
    }

    let cmmv = Message::CallMeMaybeVia(CallMeMaybeVia {
        endpoint: UdpRelayEndpoint {
            server_disco: se.server_disco.clone(),
            client_disco: se.client_disco.clone(),
            lamport_id: se.lamport_id,
            vni: se.vni,
            bind_lifetime: se.bind_lifetime,
            steady_state_lifetime: se.steady_state_lifetime,
            addr_ports: se.addr_ports.iter().map(|sa| (*sa).into()).collect(),
        },
    });

    if let Some(sealed) = ctx.seal_disco(&peer_disco, &cmmv) {
        ctx.send_disco_derp(derp_region, peer_key.clone(), sealed);
    }
}

async fn spawn_handshake_work<RM: RelayManagerContext>(
    ctx: std::sync::Arc<RM>,
    event_tx: tokio::sync::mpsc::UnboundedSender<RelayEvent>,
    peer_key: NodePublic,
    peer_disco: DiscoPublic,
    se: ServerEndpoint,
    handshake_gen: u32,
    mut cancel_rx: tokio::sync::oneshot::Receiver<()>,
    mut disco_msg_rx: tokio::sync::mpsc::Receiver<(Message, SocketAddr, u32)>,
) {
    let common = BindUdpRelayEndpointCommon {
        vni: se.vni,
        generation: handshake_gen,
        remote_key: peer_disco.clone(),
        challenge: [0u8; 32],
    };

    // Step 1: Send BindUDPRelayEndpoint to all server addr_ports.
    let bind_msg = Message::BindUdpRelayEndpoint(BindUdpRelayEndpoint {
        common: common.clone(),
    });

    let sealed_bind = if let Some(p) = ctx.seal_disco(&se.server_disco, &bind_msg) {
        p
    } else {
        let _ = event_tx.send(RelayEvent::HandshakeWorkDone(HandshakeWorkResult {
            peer_key,
            server_disco: se.server_disco,
            vni: se.vni,
            pong_from: None,
            latency: Duration::ZERO,
        }));
        return;
    };

    for addr in &se.addr_ports {
        ctx.send_disco_udp(*addr, se.vni, true, &sealed_bind);
    }

    let timeout = tokio::time::sleep(se.bind_lifetime.min(MAX_HANDSHAKE_LIFETIME));
    tokio::pin!(timeout);

    let mut sent_ping_at: HashMap<[u8; 12], Instant> = HashMap::new();
    let mut handshake_state: u8 = 0; // 0=bind_sent, 1=answer_sent
    let mut challenge_from: Option<SocketAddr> = None;
    let ping_retry = tokio::time::sleep(Duration::from_secs(2));
    tokio::pin!(ping_retry);
    let mut result = HandshakeWorkResult {
        peer_key: peer_key.clone(),
        server_disco: se.server_disco.clone(),
        vni: se.vni,
        pong_from: None,
        latency: Duration::ZERO,
    };

    loop {
        tokio::select! {
            _ = &mut cancel_rx => break,
            () = &mut timeout => break,
            () = &mut ping_retry, if handshake_state >= 1 => {
                // Periodically resend Pings until we get a Pong or time out.
                // This handles the case where the first Ping was dropped
                // because the peer hadn't bound yet.
                if sent_ping_at.len() < MAX_PINGS {
                    if let Some(from) = challenge_from {
                        let tx_id = random_tx_id();
                        sent_ping_at.insert(tx_id, Instant::now());
                        let ping = Message::Ping(Ping {
                            tx_id,
                            node_key: ctx.our_node_public(),
                            padding: 0,
                        });
                        if let Some(sealed) = ctx.seal_disco(&peer_disco, &ping) {
                            ctx.send_disco_udp(from, se.vni, false, &sealed);
                        }
                    }
                }
                ping_retry.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(2));
            }
            msg_data = disco_msg_rx.recv() => {
                let (msg, from, vni) = match msg_data {
                    Some(d) => d,
                    None => break,
                };
                if vni != se.vni {
                    continue;
                }
                match msg {
                    Message::BindUdpRelayEndpointChallenge(challenge) => {
                        if challenge.common.vni != se.vni
                            || challenge.common.remote_key != peer_disco
                        {
                            continue;
                        }
                        if handshake_state >= 1 {
                            continue;
                        }
                        handshake_state = 1;
                        challenge_from = Some(from);

                        // Step 2: Send Answer + Ping.
                        let answer = Message::BindUdpRelayEndpointAnswer(
                            BindUdpRelayEndpointAnswer {
                                common: BindUdpRelayEndpointCommon {
                                    vni: se.vni,
                                    generation: handshake_gen,
                                    remote_key: peer_disco.clone(),
                                    challenge: challenge.common.challenge,
                                },
                            },
                        );
                        if let Some(sealed) = ctx.seal_disco(&se.server_disco, &answer) {
                            ctx.send_disco_udp(from, se.vni, true, &sealed);
                        }

                        let tx_id = random_tx_id();
                        sent_ping_at.insert(tx_id, Instant::now());
                        let ping = Message::Ping(Ping {
                            tx_id,
                            node_key: ctx.our_node_public(),
                            padding: 0,
                        });
                        if let Some(sealed) = ctx.seal_disco(&peer_disco, &ping) {
                            ctx.send_disco_udp(from, se.vni, false, &sealed);
                        }
                    }
                    Message::Ping(_) => {
                        if handshake_state < 1 {
                            continue;
                        }
                        if sent_ping_at.len() >= MAX_PINGS {
                            continue;
                        }
                        let tx_id = random_tx_id();
                        sent_ping_at.insert(tx_id, Instant::now());
                        let ping = Message::Ping(Ping {
                            tx_id,
                            node_key: ctx.our_node_public(),
                            padding: 0,
                        });
                        if let Some(sealed) = ctx.seal_disco(&peer_disco, &ping) {
                            ctx.send_disco_udp(from, se.vni, false, &sealed);
                        }
                    }
                    Message::Pong(pong) => {
                        if let Some(sent_at) = sent_ping_at.get(&pong.tx_id) {
                            result.pong_from = Some(from);
                            result.latency = Instant::now().duration_since(*sent_at);
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    let _ = event_tx.send(RelayEvent::HandshakeWorkDone(result));
}

fn handle_handshake_work_done<RM: RelayManagerContext>(
    state: &mut RelayManagerState,
    ctx: &std::sync::Arc<RM>,
    result: HandshakeWorkResult,
) {
    let peer_key = &result.peer_key;
    let sdv = ServerDiscoVni {
        server_disco: result.server_disco.clone(),
        vni: result.vni,
    };

    state.handshake_by_sdv.remove(&sdv);

    if let Some(by_sd) = state.handshake_work.get_mut(peer_key) {
        by_sd.remove(&result.server_disco);
        if by_sd.is_empty() {
            state.handshake_work.remove(peer_key);
        }
    }

    // Also clean up awaiting-pong entries for this work.
    state.handshake_awaiting_pong.retain(|_, pk| pk != peer_key);

    if let Some(pong_from) = result.pong_from {
        ctx.set_relay(peer_key, pong_from, result.vni);
    }
}

// ---------------------------------------------------------------------------
// Disco message routing
// ---------------------------------------------------------------------------

fn handle_rx_disco_msg<RM: RelayManagerContext>(
    state: &mut RelayManagerState,
    ctx: &std::sync::Arc<RM>,
    msg: RelayDiscoMsg,
) {
    let apv = AddrPortVni {
        addr: msg.from,
        vni: msg.vni,
    };

    match &msg.msg {
        Message::AllocateUdpRelayEndpointResponse(resp) => {
            // Route to the matching alloc work's response channel.
            let relay_server_node_key = match &msg.relay_server_node_key {
                Some(k) => k.clone(),
                None => return,
            };
            let sorted = sort_pair(
                &resp.endpoint.client_disco[0],
                &resp.endpoint.client_disco[1],
            );

            // Find the alloc work for this server + disco key pair.
            for by_server in state.alloc_work.values() {
                for (server, work) in by_server {
                    if server.node_key == relay_server_node_key && work.disco_keys == sorted {
                        let _ = work.response_tx.try_send(resp.clone());
                        return;
                    }
                }
            }
        }

        Message::BindUdpRelayEndpointChallenge(_) => {
            let sdv = ServerDiscoVni {
                server_disco: msg.disco.clone(),
                vni: msg.vni,
            };
            let peer_key = match state.handshake_by_sdv.get(&sdv).cloned() {
                Some(k) => k,
                None => return,
            };
            if state.handshake_awaiting_pong.contains_key(&apv) {
                return;
            }
            state
                .handshake_awaiting_pong
                .insert(apv.clone(), peer_key.clone());

            // Route to the handshake work's disco message channel.
            if let Some(by_sd) = state.handshake_work.get(&peer_key) {
                if let Some(work) = by_sd.get(&msg.disco) {
                    let _ = work
                        .disco_msg_tx
                        .try_send((msg.msg.clone(), msg.from, msg.vni));
                }
            }
        }

        Message::Ping(ping) => {
            // Always send a pong for relayed pings.
            if msg.vni > 0 {
                ctx.send_pong_via_relay(msg.from, msg.vni, &msg.disco, ping.tx_id);
            }

            // Route to handshake work if we have one awaiting.
            if let Some(peer_key) = state.handshake_awaiting_pong.get(&apv).cloned() {
                if let Some(by_sd) = state.handshake_work.get(&peer_key) {
                    for work in by_sd.values() {
                        if work.vni == msg.vni {
                            let _ = work.disco_msg_tx.try_send((
                                msg.msg.clone(),
                                msg.from,
                                msg.vni,
                            ));
                            break;
                        }
                    }
                }
            }
        }

        Message::Pong(_) => {
            if let Some(peer_key) = state.handshake_awaiting_pong.get(&apv).cloned() {
                if let Some(by_sd) = state.handshake_work.get(&peer_key) {
                    // Pongs are sent by the peer (not the relay server),
                    // so msg.disco is the peer's disco key — it won't
                    // match the server_disco key. Route to the work whose
                    // VNI matches.
                    for work in by_sd.values() {
                        if work.vni == msg.vni {
                            let _ = work.disco_msg_tx.try_send((
                                msg.msg.clone(),
                                msg.from,
                                msg.vni,
                            ));
                            break;
                        }
                    }
                }
            }
        }

        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Cancellation
// ---------------------------------------------------------------------------

fn stop_work(state: &mut RelayManagerState, peer_key: &NodePublic) {
    if let Some(by_server) = state.alloc_work.remove(peer_key) {
        for (_, work) in by_server {
            let _ = work.cancel.send(());
        }
    }
    if let Some(by_sd) = state.handshake_work.remove(peer_key) {
        for (server_disco, work) in by_sd {
            let sdv = ServerDiscoVni {
                server_disco,
                vni: work.vni,
            };
            state.handshake_by_sdv.remove(&sdv);
            let _ = work.cancel.send(());
        }
    }
    state.handshake_awaiting_pong.retain(|_, pk| pk != peer_key);
}

fn cancel_handshake(
    state: &mut RelayManagerState,
    peer_key: &NodePublic,
    server_disco: &DiscoPublic,
) {
    if let Some(by_sd) = state.handshake_work.get_mut(peer_key) {
        if let Some(work) = by_sd.remove(server_disco) {
            let sdv = ServerDiscoVni {
                server_disco: server_disco.clone(),
                vni: work.vni,
            };
            state.handshake_by_sdv.remove(&sdv);
            let _ = work.cancel.send(());
        }
        if by_sd.is_empty() {
            state.handshake_work.remove(peer_key);
        }
    }
}

fn random_tx_id() -> [u8; 12] {
    use rand::RngCore;
    let mut tx = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut tx);
    tx
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rustscale_key::{DiscoPrivate, NodePrivate};
    use rustscale_tailcfg::RawMessage;
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_candidate() -> CandidatePeerRelay {
        CandidatePeerRelay {
            node_key: NodePrivate::generate().public(),
            disco_key: DiscoPrivate::generate().public(),
            derp_home_region: 1,
        }
    }

    #[test]
    fn candidate_peer_relay_validity() {
        let c = make_candidate();
        assert!(c.is_valid());
        let zero = CandidatePeerRelay {
            node_key: NodePublic::from_raw32([0u8; 32]),
            disco_key: DiscoPublic::from_raw32([0u8; 32]),
            derp_home_region: 0,
        };
        assert!(!zero.is_valid());
    }

    #[test]
    fn server_endpoint_from_udp_relay_endpoint() {
        let server_disco = DiscoPrivate::generate().public();
        let client_disco = [
            DiscoPrivate::generate().public(),
            DiscoPrivate::generate().public(),
        ];
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 5678);
        let ep = UdpRelayEndpoint {
            server_disco: server_disco.clone(),
            client_disco: client_disco.clone(),
            lamport_id: 42,
            vni: 100,
            bind_lifetime: Duration::from_secs(30),
            steady_state_lifetime: Duration::from_secs(300),
            addr_ports: vec![rustscale_disco::AddrPort::from(addr)],
        };
        let se = ServerEndpoint::from_udp_relay_endpoint(&ep);
        assert_eq!(se.server_disco, server_disco);
        assert_eq!(se.client_disco, client_disco);
        assert_eq!(se.lamport_id, 42);
        assert_eq!(se.vni, 100);
        assert_eq!(se.addr_ports, vec![addr]);
    }

    #[test]
    fn discover_relay_servers_from_netmap() {
        let self_key = NodePrivate::generate().public();
        let self_disco = DiscoPrivate::generate().public();
        let self_node = Node {
            Key: self_key.clone(),
            DiscoKey: self_disco,
            Cap: 120,
            CapMap: {
                let mut m = BTreeMap::new();
                m.insert(
                    PEER_CAPABILITY_RELAY_TARGET.to_string(),
                    vec![RawMessage::default()],
                );
                m
            },
            ..Default::default()
        };

        let peer1_key = NodePrivate::generate().public();
        let peer1_disco = DiscoPrivate::generate().public();
        let peer1 = Node {
            Key: peer1_key.clone(),
            DiscoKey: peer1_disco.clone(),
            Cap: 120,
            CapMap: {
                let mut m = BTreeMap::new();
                m.insert(
                    PEER_CAPABILITY_RELAY_TARGET.to_string(),
                    vec![RawMessage::default()],
                );
                m
            },
            HomeDERP: 5,
            ..Default::default()
        };

        let peer2 = Node {
            Key: NodePrivate::generate().public(),
            DiscoKey: DiscoPrivate::generate().public(),
            Cap: 119,
            ..Default::default()
        };

        let peer3 = Node {
            Key: NodePrivate::generate().public(),
            DiscoKey: DiscoPrivate::generate().public(),
            Cap: 120,
            ..Default::default()
        };

        let servers = discover_relay_servers(&self_node, &[peer1, peer2, peer3]);
        assert_eq!(servers.len(), 2);
        assert!(servers.iter().any(|s| s.node_key == self_key));
        assert!(servers
            .iter()
            .any(|s| s.node_key == peer1_key && s.derp_home_region == 5));
    }

    #[test]
    fn lamport_id_dedup_cancels_old() {
        let mut state = RelayManagerState::new();
        let peer_key = NodePrivate::generate().public();
        let server_disco = DiscoPrivate::generate().public();

        let (cancel, mut cancel_rx) = tokio::sync::oneshot::channel();
        let (dm_tx, _dm_rx) = tokio::sync::mpsc::channel(16);
        state
            .handshake_work
            .entry(peer_key.clone())
            .or_default()
            .insert(
                server_disco.clone(),
                HandshakeWork {
                    server_disco: server_disco.clone(),
                    vni: 100,
                    lamport_id: 5,
                    cancel,
                    disco_msg_tx: dm_tx,
                },
            );
        state.handshake_by_sdv.insert(
            ServerDiscoVni {
                server_disco: server_disco.clone(),
                vni: 100,
            },
            peer_key.clone(),
        );

        cancel_handshake(&mut state, &peer_key, &server_disco);

        assert!(cancel_rx.try_recv().is_ok());
        assert!(!state
            .handshake_work
            .get(&peer_key)
            .is_some_and(|m| m.contains_key(&server_disco)));
        assert!(!state.handshake_by_sdv.contains_key(&ServerDiscoVni {
            server_disco: server_disco.clone(),
            vni: 100,
        }));
    }

    #[test]
    fn stop_work_cancels_all() {
        let mut state = RelayManagerState::new();
        let peer_key = NodePrivate::generate().public();
        let server = make_candidate();
        let server_disco = DiscoPrivate::generate().public();

        let (alloc_cancel, mut alloc_cancel_rx) = tokio::sync::oneshot::channel();
        let (resp_tx, _resp_rx) = tokio::sync::mpsc::channel(1);
        state
            .alloc_work
            .entry(peer_key.clone())
            .or_default()
            .insert(
                server.clone(),
                AllocWork {
                    server: server.clone(),
                    disco_keys: [
                        DiscoPrivate::generate().public(),
                        DiscoPrivate::generate().public(),
                    ],
                    alloc_gen: 1,
                    cancel: alloc_cancel,
                    response_tx: resp_tx,
                },
            );

        let (hs_cancel, mut hs_cancel_rx) = tokio::sync::oneshot::channel();
        let (dm_tx, _dm_rx) = tokio::sync::mpsc::channel(16);
        state
            .handshake_work
            .entry(peer_key.clone())
            .or_default()
            .insert(
                server_disco.clone(),
                HandshakeWork {
                    server_disco: server_disco.clone(),
                    vni: 42,
                    lamport_id: 1,
                    cancel: hs_cancel,
                    disco_msg_tx: dm_tx,
                },
            );
        state.handshake_by_sdv.insert(
            ServerDiscoVni {
                server_disco: server_disco.clone(),
                vni: 42,
            },
            peer_key.clone(),
        );
        state.handshake_awaiting_pong.insert(
            AddrPortVni {
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234),
                vni: 42,
            },
            peer_key.clone(),
        );

        stop_work(&mut state, &peer_key);

        assert!(alloc_cancel_rx.try_recv().is_ok());
        assert!(hs_cancel_rx.try_recv().is_ok());
        assert!(!state.alloc_work.contains_key(&peer_key));
        assert!(!state.handshake_work.contains_key(&peer_key));
        assert!(!state
            .handshake_awaiting_pong
            .values()
            .any(|pk| pk == &peer_key));
    }

    #[test]
    fn server_set_update_replaces() {
        let mut state = RelayManagerState::new();
        let s1 = make_candidate();
        let s2 = make_candidate();

        handle_servers_update(&mut state, vec![s1.clone()]);
        assert_eq!(state.servers_by_node_key.len(), 1);

        handle_servers_update(&mut state, vec![s2.clone()]);
        assert_eq!(state.servers_by_node_key.len(), 1);
        assert!(state.servers_by_node_key.contains_key(&s2.node_key));
        assert!(!state.servers_by_node_key.contains_key(&s1.node_key));

        handle_servers_update(&mut state, vec![]);
        assert!(state.servers_by_node_key.is_empty());
    }

    #[test]
    fn sort_pair_consistent() {
        let a = DiscoPrivate::generate().public();
        let b = DiscoPrivate::generate().public();
        let p1 = sort_pair(&a, &b);
        let p2 = sort_pair(&b, &a);
        assert_eq!(p1, p2);
    }

    #[test]
    fn generation_counters_increment() {
        let mut state = RelayManagerState::new();
        let g1 = state.next_alloc_gen();
        let g2 = state.next_alloc_gen();
        assert_ne!(g1, g2);
        assert!(g1 > 0);

        let h1 = state.next_handshake_gen();
        let h2 = state.next_handshake_gen();
        assert_ne!(h1, h2);
        assert!(h1 > 0);
    }

    #[test]
    fn has_active_work_checks() {
        let mut state = RelayManagerState::new();
        assert!(!state.has_active_work_for(&NodePrivate::generate().public()));

        let peer_key = NodePrivate::generate().public();
        let server = make_candidate();
        let (cancel, _) = tokio::sync::oneshot::channel();
        let (resp_tx, _resp_rx) = tokio::sync::mpsc::channel(1);
        state
            .alloc_work
            .entry(peer_key.clone())
            .or_default()
            .insert(
                server,
                AllocWork {
                    server: make_candidate(),
                    disco_keys: [
                        DiscoPrivate::generate().public(),
                        DiscoPrivate::generate().public(),
                    ],
                    alloc_gen: 1,
                    cancel,
                    response_tx: resp_tx,
                },
            );

        assert!(state.has_active_work_for(&peer_key));

        let other = NodePrivate::generate().public();
        assert!(!state.has_active_work_for(&other));
    }

    #[test]
    fn call_me_maybe_via_roundtrip_encoding() {
        let server_disco = DiscoPrivate::generate().public();
        let client_disco = [
            DiscoPrivate::generate().public(),
            DiscoPrivate::generate().public(),
        ];
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9999);

        let original = CallMeMaybeVia {
            endpoint: UdpRelayEndpoint {
                server_disco: server_disco.clone(),
                client_disco: client_disco.clone(),
                lamport_id: 77,
                vni: 0xABCDEF,
                bind_lifetime: Duration::from_secs(30),
                steady_state_lifetime: Duration::from_secs(300),
                addr_ports: vec![rustscale_disco::AddrPort::from(addr)],
            },
        };

        let msg = Message::CallMeMaybeVia(original);
        let bytes = msg.marshal();

        let parsed = Message::parse(&bytes).expect("parse");
        match parsed {
            Message::CallMeMaybeVia(m) => {
                assert_eq!(m.endpoint.server_disco, server_disco);
                assert_eq!(m.endpoint.client_disco, client_disco);
                assert_eq!(m.endpoint.lamport_id, 77);
                assert_eq!(m.endpoint.vni, 0xABCDEF);
                assert_eq!(m.endpoint.bind_lifetime, Duration::from_secs(30));
                assert_eq!(m.endpoint.steady_state_lifetime, Duration::from_secs(300));
                assert_eq!(m.endpoint.addr_ports.len(), 1);
                let parsed_addr: SocketAddr = m.endpoint.addr_ports[0].into();
                assert_eq!(parsed_addr, addr);
            }
            _ => panic!("wrong message type"),
        }
    }

    #[test]
    fn handle_disco_msg_challenge_sets_awaiting_pong() {
        let mut state = RelayManagerState::new();
        let peer_key = NodePrivate::generate().public();
        let server_disco = DiscoPrivate::generate().public();
        let vni = 42;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4242);

        let (cancel, _) = tokio::sync::oneshot::channel();
        let (dm_tx, _dm_rx) = tokio::sync::mpsc::channel(16);
        state
            .handshake_work
            .entry(peer_key.clone())
            .or_default()
            .insert(
                server_disco.clone(),
                HandshakeWork {
                    server_disco: server_disco.clone(),
                    vni,
                    lamport_id: 1,
                    cancel,
                    disco_msg_tx: dm_tx,
                },
            );
        state.handshake_by_sdv.insert(
            ServerDiscoVni {
                server_disco: server_disco.clone(),
                vni,
            },
            peer_key.clone(),
        );

        let challenge = BindUdpRelayEndpointChallenge {
            common: BindUdpRelayEndpointCommon {
                vni,
                generation: 1,
                remote_key: DiscoPrivate::generate().public(),
                challenge: [0u8; 32],
            },
        };

        let msg = RelayDiscoMsg {
            msg: Message::BindUdpRelayEndpointChallenge(challenge),
            disco: server_disco,
            from: addr,
            vni,
            relay_server_node_key: None,
            source_node_key: None,
        };

        let ctx = MockCtx;
        handle_rx_disco_msg(&mut state, &std::sync::Arc::new(ctx), msg);

        let apv = AddrPortVni { addr, vni };
        assert!(state.handshake_awaiting_pong.contains_key(&apv));
    }

    #[test]
    fn handle_disco_msg_duplicate_challenge_ignored() {
        let mut state = RelayManagerState::new();
        let peer_key = NodePrivate::generate().public();
        let server_disco = DiscoPrivate::generate().public();
        let vni = 42;
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4242);

        let (cancel, _) = tokio::sync::oneshot::channel();
        let (dm_tx, _dm_rx) = tokio::sync::mpsc::channel(16);
        state
            .handshake_work
            .entry(peer_key.clone())
            .or_default()
            .insert(
                server_disco.clone(),
                HandshakeWork {
                    server_disco: server_disco.clone(),
                    vni,
                    lamport_id: 1,
                    cancel,
                    disco_msg_tx: dm_tx,
                },
            );
        state.handshake_by_sdv.insert(
            ServerDiscoVni {
                server_disco: server_disco.clone(),
                vni,
            },
            peer_key.clone(),
        );
        state
            .handshake_awaiting_pong
            .insert(AddrPortVni { addr, vni }, peer_key.clone());

        let challenge = BindUdpRelayEndpointChallenge {
            common: BindUdpRelayEndpointCommon {
                vni,
                generation: 1,
                remote_key: DiscoPrivate::generate().public(),
                challenge: [0u8; 32],
            },
        };

        let msg = RelayDiscoMsg {
            msg: Message::BindUdpRelayEndpointChallenge(challenge),
            disco: server_disco,
            from: addr,
            vni,
            relay_server_node_key: None,
            source_node_key: None,
        };

        let ctx = MockCtx;
        handle_rx_disco_msg(&mut state, &std::sync::Arc::new(ctx), msg);

        assert_eq!(state.handshake_awaiting_pong.len(), 1);
    }

    struct MockCtx;

    impl RelayManagerContext for MockCtx {
        fn seal_disco(&self, _: &DiscoPublic, _: &Message) -> Option<Vec<u8>> {
            None
        }
        fn send_disco_udp(&self, _: SocketAddr, _: u32, _: bool, _: &[u8]) {}
        fn send_disco_derp(&self, _: i32, _: NodePublic, _: Vec<u8>) {}
        fn our_disco_public(&self) -> DiscoPublic {
            DiscoPrivate::generate().public()
        }
        fn our_node_public(&self) -> NodePublic {
            NodePrivate::generate().public()
        }
        fn peer_disco_key(&self, _: &NodePublic) -> Option<DiscoPublic> {
            None
        }
        fn peer_derp_region(&self, _: &NodePublic) -> i32 {
            0
        }
        fn set_relay(&self, _: &NodePublic, _: SocketAddr, _: u32) {}
        fn send_pong_via_relay(&self, _: SocketAddr, _: u32, _: &DiscoPublic, _: [u8; 12]) {}
        fn is_self_node(&self, _: &NodePublic) -> bool {
            false
        }
        fn handle_self_alloc_request(
            &self,
            _: [DiscoPublic; 2],
            _: u32,
        ) -> Option<AllocateUdpRelayEndpointResponse> {
            None
        }
    }
}
