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
#[cfg(target_os = "linux")]
mod udp_batch;
mod udp_socket_buffers;

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
use std::fmt;
#[cfg(any(target_os = "linux", test))]
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::Deref;
use std::ops::Range;
use std::panic::{catch_unwind, AssertUnwindSafe};
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use rustscale_derp::DerpClient;
use rustscale_disco::{CallMeMaybe, Message, Ping, Pong};
use rustscale_key::{DiscoPrivate, DiscoPublic, NodePrivate, NodePublic};
#[cfg(target_os = "linux")]
use rustscale_neterror::should_disable_udp_gso;
use rustscale_neterror::treat_as_lost_udp;
use rustscale_tailcfg::{DERPMap, Node};
#[cfg(target_os = "linux")]
use tokio::io::Interest;
use tokio::net::UdpSocket;
#[cfg(any(target_os = "linux", test))]
use tokio::sync::TryAcquireError;
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};

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
#[cfg(any(target_os = "linux", test))]
const LINUX_UDP_FAST_PACKET_CAPACITY: usize = 2_048;

/// Fake endpoint address used to identify DERP regions in physical netlog
/// tuples. Mirrors `tailcfg.DerpMagicIPAddr`.
const DERP_MAGIC_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 3, 3, 40));

/// Callback for physical transport accounting.
///
/// The tuple and count semantics match `netlogfunc.ConnectionCounter`:
/// protocol, source, destination, packets, bytes, and receive direction.
/// Magicsock always reports protocol 0 and source port 0. Implementations
/// must be cheap and nonblocking; the netlog implementation only enqueues an
/// event on an unbounded channel.
pub type ConnectionCounter =
    Arc<dyn Fn(u8, (IpAddr, u16), (IpAddr, u16), u64, u64, bool) + Send + Sync>;

/// Dynamically replaceable connection counter. Callback panics are contained
/// outside the lock so a faulty optional observer cannot poison transport
/// state or unwind a send/receive task.
#[derive(Default)]
struct ConnectionCounterHook {
    counter: RwLock<Option<ConnectionCounter>>,
}

impl ConnectionCounterHook {
    fn set(&self, counter: Option<ConnectionCounter>) {
        if let Ok(mut current) = self.counter.write() {
            *current = counter;
        }
    }

    fn record(
        &self,
        source: Option<IpAddr>,
        destination: SocketAddr,
        packets: u64,
        bytes: u64,
        recv: bool,
    ) {
        if packets == 0 {
            return;
        }
        let Some(source) = source else {
            return;
        };
        let counter = self.counter.read().ok().and_then(|counter| counter.clone());
        let Some(counter) = counter else {
            return;
        };
        let _ = catch_unwind(AssertUnwindSafe(|| {
            counter(
                0,
                (source, 0),
                (destination.ip(), destination.port()),
                packets,
                bytes,
                recv,
            );
        }));
    }
}

#[cfg(any(target_os = "linux", test))]
fn batch_counts<T: AsRef<[u8]>>(datagrams: &[T]) -> (u64, u64) {
    (
        datagrams.len() as u64,
        datagrams
            .iter()
            .map(|datagram| datagram.as_ref().len() as u64)
            .sum(),
    )
}

/// Keep upstream netlog in original-datagram units while sockstats reflects
/// every physical payload byte submitted to the UDP socket.
#[cfg(any(target_os = "linux", test))]
fn linux_udp_send_accounting<T: AsRef<[u8]>>(
    datagrams: &[T],
    wire_bytes: usize,
) -> (u64, u64, usize) {
    let (packets, logical_bytes) = batch_counts(datagrams);
    debug_assert!(wire_bytes >= logical_bytes as usize);
    (packets, logical_bytes, wire_bytes)
}

fn first_node_addr(node: &Node) -> Option<IpAddr> {
    node.Addresses.first().and_then(|prefix| {
        prefix
            .split_once('/')
            .map_or(prefix.as_str(), |(addr, _)| addr)
            .parse()
            .ok()
    })
}

/// Whether a kernel-received UDP packet must use the established scalar
/// handler. The fast handoff only applies to ordinary direct WireGuard UDP.
#[cfg(any(target_os = "linux", test))]
fn udp_batch_needs_scalar_handler(data: &[u8]) -> bool {
    // Jumbo packets are fully received in bounded kernel scratch, but do not
    // fit a detachable pooled ciphertext slot. Keep the whole received burst
    // sequential so packet order and ownership remain exact.
    data.len() > LINUX_UDP_FAST_PACKET_CAPACITY
        || DiscoIo::looks_like_disco(data)
        || relay::looks_like_geneve_disco(data)
        || relay::looks_like_geneve_wireguard(data)
}

/// Whether a Linux kernel receive batch must stay on the established scalar
/// path. One control or malformed entry keeps the *entire* burst scalar so
/// routing updates and ordinary WireGuard packets retain receive order.
#[cfg(any(target_os = "linux", test))]
fn linux_batch_requires_scalar_handler<'a>(
    packets: impl IntoIterator<Item = Option<&'a [u8]>>,
) -> bool {
    packets.into_iter().any(|packet| match packet {
        Some(data) => udp_batch_needs_scalar_handler(data),
        None => true,
    })
}

/// Linux UDP send configuration sampled once when the socket is installed.
/// Runtime capability failures may only turn these features off.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LinuxUdpSendConfig {
    use_batch: bool,
    disable_udp_gso: bool,
}

#[cfg(any(target_os = "linux", test))]
fn never_gso_equal_tail(control_knobs: Option<&rustscale_controlknobs::ControlKnobs>) -> bool {
    control_knobs.is_some_and(|knobs| {
        knobs.get_bool(rustscale_tailcfg::NODE_ATTR_NEVER_GSO_EQUAL_TAIL, false)
    })
}

#[cfg(any(target_os = "linux", test))]
impl LinuxUdpSendConfig {
    #[cfg(target_os = "linux")]
    fn from_environment() -> Self {
        Self::from_environment_presence(
            std::env::var_os("RUSTSCALE_DISABLE_LINUX_UDP_BATCH").is_some(),
            std::env::var_os("RUSTSCALE_DISABLE_UDP_GSO").is_some(),
        )
    }

    fn from_environment_presence(disable_batch: bool, disable_gso: bool) -> Self {
        Self {
            use_batch: !disable_batch,
            disable_udp_gso: disable_batch || disable_gso,
        }
    }
}

/// Linux UDP receive configuration sampled once when the receive task starts.
///
/// The bounded `recvmmsg` receive and handoff path, including its guarded UDP
/// GRO receiver, is the normal mode. `RUSTSCALE_ENABLE_LINUX_UDP_BATCH` and
/// `RUSTSCALE_ENABLE_UDP_GRO` remain compatibility no-ops for deployments
/// that already set them. Explicit disable switches always win.
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LinuxUdpReceiveConfig {
    use_batch: bool,
    disable_udp_gro: bool,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy)]
struct LinuxUdpReceiveEnvironment {
    disable_linux_udp_batch: bool,
    _enable_linux_udp_batch: bool,
    disable_udp_gro: bool,
    _enable_udp_gro: bool,
}

#[cfg(any(target_os = "linux", test))]
impl LinuxUdpReceiveConfig {
    #[cfg(target_os = "linux")]
    fn from_environment() -> Self {
        Self::from_environment_presence(LinuxUdpReceiveEnvironment {
            disable_linux_udp_batch: std::env::var_os("RUSTSCALE_DISABLE_LINUX_UDP_BATCH")
                .is_some(),
            _enable_linux_udp_batch: std::env::var_os("RUSTSCALE_ENABLE_LINUX_UDP_BATCH").is_some(),
            disable_udp_gro: std::env::var_os("RUSTSCALE_DISABLE_UDP_GRO").is_some(),
            _enable_udp_gro: std::env::var_os("RUSTSCALE_ENABLE_UDP_GRO").is_some(),
        })
    }

    fn from_environment_presence(environment: LinuxUdpReceiveEnvironment) -> Self {
        Self {
            // Explicit safety switches remain effective even in deployments
            // that still carry the old opt-in variables. Scalar mode never
            // constructs a batch receiver, so it necessarily has no GRO.
            use_batch: !environment.disable_linux_udp_batch,
            disable_udp_gro: environment.disable_linux_udp_batch || environment.disable_udp_gro,
        }
    }
}

/// Maximum number of ordered WireGuard packets carried by one receive item.
pub const WG_RECEIVE_BATCH_MAX_PACKETS: usize = 128;

/// Total number of WireGuard packets that may wait between magicsock and its
/// consumer. This is deliberately packet-counted, even though the channel
/// transports batches.
const WG_RECEIVE_PACKET_CAPACITY: usize = 256;

/// Publish an owned receive batch. The permit is stored in the item until the
/// consumer takes or drops it, so cancellation and closed-channel paths return
/// packet credits without bespoke cleanup.
async fn publish_wg_batch(
    sender: &mpsc::Sender<WgReceiveBatch>,
    credits: &Arc<Semaphore>,
    datagrams: Vec<WgDatagram>,
) {
    if datagrams.is_empty() {
        return;
    }
    assert!(
        datagrams.len() <= WG_RECEIVE_BATCH_MAX_PACKETS,
        "receive batch exceeds its 128-packet maximum"
    );
    let count = u32::try_from(datagrams.len()).expect("receive batch count fits u32");
    let Ok(permit) = credits.clone().acquire_many_owned(count).await else {
        return;
    };
    // If this await is cancelled or the receiver is closed, `batch` is
    // dropped and its owned permit returns all packet credits.
    let batch = WgReceiveBatch::new(datagrams, permit);
    let _ = sender.send(batch).await;
}

/// Publish ciphertexts after a Linux direct receive has reserved their packet
/// credits before detaching scratch storage. No borrow or map lock crosses the
/// await in this helper.
#[cfg(target_os = "linux")]
async fn publish_reserved_wg_batch(
    sender: &mpsc::Sender<WgReceiveBatch>,
    datagrams: Vec<WgDatagram>,
    channel_permit: OwnedSemaphorePermit,
    pool_reservation: Arc<PoolInventoryReservation>,
) {
    debug_assert!(!datagrams.is_empty());
    let batch = WgReceiveBatch::new_pooled(datagrams, channel_permit, pool_reservation);
    let _ = sender.send(batch).await;
}

/// Test-only publication helper for pre-owned staged datagrams.
#[cfg(test)]
async fn publish_linux_wg_batch(
    sender: &mpsc::Sender<WgReceiveBatch>,
    credits: &Arc<Semaphore>,
    pending: &mut Vec<WgDatagram>,
) {
    let datagrams = std::mem::take(pending);
    publish_wg_batch(sender, credits, datagrams).await;
}

/// Identify ordinary direct WireGuard source runs before awaiting capacity.
/// The source map is consulted once for every contiguous run; the resulting
/// per-packet peer identities let detachment happen later without any lock.
#[derive(Debug)]
#[cfg(any(target_os = "linux", test))]
struct IdentifiedLinuxWg {
    peers: Vec<Option<NodePublic>>,
    received_at: std::time::Instant,
}

#[cfg(any(target_os = "linux", test))]
fn identify_linux_wg_peers(
    sources: impl IntoIterator<Item = SocketAddr>,
    peers: &HashMap<SocketAddr, NodePublic>,
    received_at: std::time::Instant,
) -> IdentifiedLinuxWg {
    let mut identified = Vec::with_capacity(WG_RECEIVE_BATCH_MAX_PACKETS);
    let mut previous = None;
    let mut peer = None;
    for source in sources {
        if previous != Some(source) {
            peer = peers.get(&source).cloned();
            previous = Some(source);
        }
        identified.push(peer.clone());
    }
    IdentifiedLinuxWg {
        peers: identified,
        received_at,
    }
}

/// Detach identified ordinary direct WireGuard packets in receive order.
/// `ReceiveBatch` fixed boxes are replaced before the next recvmmsg; no plain
/// packet payload is copied. UDP GRO already copied its coalesced logical
/// tails into those fixed boxes during split, which remains necessary so each
/// published segment has independent stable storage.
#[cfg(target_os = "linux")]
fn detach_linux_wg_datagrams(
    batch: &mut udp_batch::ReceiveBatch,
    count: usize,
    identified: &IdentifiedLinuxWg,
    pool_reservation: &Arc<PoolInventoryReservation>,
    endpoints: &mut HashMap<NodePublic, Endpoint>,
    pending: &mut Vec<WgDatagram>,
    mut note_recv_udp: impl FnMut(&NodePublic, &mut Endpoint, std::time::Instant),
    mut record_rx: impl FnMut(usize, usize),
    mut record_phys_rx: impl FnMut(Option<IpAddr>, SocketAddr, u64, u64),
) {
    debug_assert_eq!(identified.peers.len(), count);
    let (mut udp4_rx_bytes, mut udp6_rx_bytes) = (0, 0);
    let mut previous = None;
    let mut physical_run: Option<(Option<IpAddr>, SocketAddr, u64, u64)> = None;

    for (index, peer) in identified.peers.iter().enumerate() {
        let (len, addr) = batch
            .datagram_meta(index)
            .expect("published receive batch has metadata for every logical datagram");
        if previous != Some(addr) {
            previous = Some(addr);
            if let Some(peer) = peer {
                if let Some(endpoint) = endpoints.get_mut(peer) {
                    note_recv_udp(peer, endpoint, identified.received_at);
                }
            }
        }
        match addr {
            SocketAddr::V4(_) => udp4_rx_bytes += len,
            SocketAddr::V6(_) => udp6_rx_bytes += len,
        }
        if let Some(peer) = peer {
            let node_addr = endpoints.get(peer).and_then(Endpoint::node_addr);
            match physical_run.as_mut() {
                Some((run_node, run_addr, packets, bytes))
                    if *run_node == node_addr && *run_addr == addr =>
                {
                    *packets += 1;
                    *bytes += len as u64;
                }
                _ => {
                    if let Some((node, destination, packets, bytes)) = physical_run.take() {
                        record_phys_rx(node, destination, packets, bytes);
                    }
                    physical_run = Some((node_addr, addr, 1, len as u64));
                }
            }
            let (packet, detached_source) = batch
                .detach_datagram(index)
                .expect("reserved receive credit always has fixed pooled replacement");
            debug_assert_eq!(addr, detached_source);
            pending.push(WgDatagram {
                peer: peer.clone(),
                data: WgCiphertext::from_pooled(packet, pool_reservation.clone()),
            });
        } else if let Some((node, destination, packets, bytes)) = physical_run.take() {
            record_phys_rx(node, destination, packets, bytes);
        }
    }

    if let Some((node, destination, packets, bytes)) = physical_run {
        record_phys_rx(node, destination, packets, bytes);
    }
    record_rx(udp4_rx_bytes, udp6_rx_bytes);
}

// Keep the source-run accounting seam executable independently of recvmmsg.
// Linux production uses the detach variant above; this test version models
// only ordering/accounting with ordinary owned vectors.
#[cfg(test)]
fn stage_linux_wg_datagrams<'a>(
    packets: impl IntoIterator<Item = (&'a [u8], SocketAddr)>,
    peers: &HashMap<SocketAddr, NodePublic>,
    endpoints: &mut HashMap<NodePublic, Endpoint>,
    pending: &mut Vec<WgDatagram>,
    note_recv_udp: impl FnMut(&NodePublic, &mut Endpoint, std::time::Instant),
    record_rx: impl FnMut(usize, usize),
) {
    stage_linux_wg_datagrams_at(
        packets,
        peers,
        endpoints,
        pending,
        std::time::Instant::now(),
        note_recv_udp,
        record_rx,
    );
}

#[cfg(test)]
fn stage_linux_wg_datagrams_at<'a>(
    packets: impl IntoIterator<Item = (&'a [u8], SocketAddr)>,
    peers: &HashMap<SocketAddr, NodePublic>,
    endpoints: &mut HashMap<NodePublic, Endpoint>,
    pending: &mut Vec<WgDatagram>,
    received_at: std::time::Instant,
    mut note_recv_udp: impl FnMut(&NodePublic, &mut Endpoint, std::time::Instant),
    mut record_rx: impl FnMut(usize, usize),
) {
    let mut packets = packets.into_iter().peekable();
    let now = received_at;
    let (mut udp4_rx_bytes, mut udp6_rx_bytes) = (0, 0);
    while let Some((mut data, addr)) = packets.next() {
        let peer = peers.get(&addr);
        if let Some(peer) = peer {
            if let Some(endpoint) = endpoints.get_mut(peer) {
                note_recv_udp(peer, endpoint, now);
            }
        }
        let mut run_bytes = 0;
        loop {
            run_bytes += data.len();
            if let Some(peer) = peer {
                pending.push(WgDatagram {
                    peer: peer.clone(),
                    data: data.to_vec().into(),
                });
            }
            let Some((next_data, _)) = packets.next_if(|(_, next)| *next == addr) else {
                break;
            };
            data = next_data;
        }
        match addr {
            SocketAddr::V4(_) => udp4_rx_bytes += run_bytes,
            SocketAddr::V6(_) => udp6_rx_bytes += run_bytes,
        }
    }
    record_rx(udp4_rx_bytes, udp6_rx_bytes);
}

/// Size of a complete disco ping packet without any padding.
/// `MAGIC(6) + sender_pub(32) + nonce(24) + tag(16) + header(2) + ping(44)`.
/// Mirrors Go's `discoPingSize` (endpoint.go:1249-1250).
const DISCO_PING_SIZE: usize = 124;

/// Advance one Linux direct-batch attempt. This deliberately small seam keeps
/// partial-send/error policy deterministic without abstracting the UDP socket.
#[cfg(any(target_os = "linux", test))]
fn advance_direct_batch(
    head: &mut usize,
    len: usize,
    first_error: &mut Option<io::Error>,
    result: io::Result<usize>,
) -> usize {
    match result {
        Ok(sent) => {
            debug_assert!(sent > 0 && sent <= len - *head);
            *head += sent;
            sent
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => 0,
        Err(error) => {
            if !treat_as_lost_udp(&error) {
                first_error.get_or_insert(error);
            }
            *head += 1;
            0
        }
    }
}

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

/// Owned WireGuard ciphertext.
///
/// This is a deliberate v0.1 migration from `WgDatagram { data: Vec<u8> }`:
/// a direct Linux packet can borrow a fixed receive buffer without copying, so
/// it cannot be represented by a public `Vec` field. Use `vec.into()` when
/// constructing a datagram, and use `AsRef<[u8]>`/slice indexing when reading
/// one. `WgCiphertext` intentionally is not `Clone`: cloning pooled storage
/// would either copy a packet or make its lifetime surprising.
pub struct WgCiphertext {
    storage: WgCiphertextStorage,
}

enum WgCiphertextStorage {
    Vec {
        bytes: Vec<u8>,
        range: Range<usize>,
    },
    #[cfg(target_os = "linux")]
    Pooled {
        packet: udp_batch::PooledPacket,
        // Keep this after `packet`: Rust drops fields in declaration order,
        // so the fixed buffer returns to the recycler before the last shared
        // inventory permit can wake a receiver that needs a replacement.
        _pool_reservation: Arc<PoolInventoryReservation>,
    },
}

/// Reservation of detached fixed-buffer inventory for one Linux receive
/// batch. This is independent from channel backpressure credits: pooled
/// ciphertexts retain it until every detached buffer from the batch returns.
#[cfg(any(target_os = "linux", test))]
struct PoolInventoryReservation {
    _permit: OwnedSemaphorePermit,
}

#[cfg(any(target_os = "linux", test))]
impl PoolInventoryReservation {
    async fn acquire(inventory: Arc<Semaphore>, count: usize) -> Option<Arc<Self>> {
        let count = u32::try_from(count).expect("pool reservation count fits u32");
        let permit = match inventory.clone().try_acquire_many_owned(count) {
            Ok(permit) => permit,
            Err(TryAcquireError::NoPermits) => inventory.acquire_many_owned(count).await.ok()?,
            Err(TryAcquireError::Closed) => return None,
        };
        Some(Arc::new(Self { _permit: permit }))
    }
}

impl WgCiphertext {
    /// Keep an existing owned frame and expose only its selected range.
    pub fn from_vec_range(bytes: Vec<u8>, range: Range<usize>) -> Self {
        assert!(
            range.start <= range.end && range.end <= bytes.len(),
            "ciphertext range must be within its owned frame"
        );
        Self {
            storage: WgCiphertextStorage::Vec { bytes, range },
        }
    }

    #[cfg(target_os = "linux")]
    fn from_pooled(
        packet: udp_batch::PooledPacket,
        pool_reservation: Arc<PoolInventoryReservation>,
    ) -> Self {
        Self {
            storage: WgCiphertextStorage::Pooled {
                packet,
                _pool_reservation: pool_reservation,
            },
        }
    }

    /// Clone only ordinary owned-vector storage without copying a pooled
    /// receive buffer. `None` means this ciphertext is pooled and must remain
    /// uniquely owned until processing completes.
    pub fn try_clone(&self) -> Option<Self> {
        match &self.storage {
            WgCiphertextStorage::Vec { bytes, range } => {
                Some(Self::from_vec_range(bytes.clone(), range.clone()))
            }
            #[cfg(target_os = "linux")]
            WgCiphertextStorage::Pooled { .. } => None,
        }
    }
}

impl From<Vec<u8>> for WgCiphertext {
    fn from(bytes: Vec<u8>) -> Self {
        let len = bytes.len();
        Self::from_vec_range(bytes, 0..len)
    }
}

impl AsRef<[u8]> for WgCiphertext {
    fn as_ref(&self) -> &[u8] {
        match &self.storage {
            WgCiphertextStorage::Vec { bytes, range } => &bytes[range.clone()],
            #[cfg(target_os = "linux")]
            WgCiphertextStorage::Pooled { packet, .. } => packet.as_slice(),
        }
    }
}

impl Deref for WgCiphertext {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl fmt::Debug for WgCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("WgCiphertext").field(&self.as_ref()).finish()
    }
}

impl PartialEq for WgCiphertext {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl Eq for WgCiphertext {}

impl PartialEq<Vec<u8>> for WgCiphertext {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.as_ref() == other.as_slice()
    }
}

impl PartialEq<WgCiphertext> for Vec<u8> {
    fn eq(&self, other: &WgCiphertext) -> bool {
        self.as_slice() == other.as_ref()
    }
}

impl PartialEq<&[u8]> for WgCiphertext {
    fn eq(&self, other: &&[u8]) -> bool {
        self.as_ref() == *other
    }
}

impl<const N: usize> PartialEq<&[u8; N]> for WgCiphertext {
    fn eq(&self, other: &&[u8; N]) -> bool {
        self.as_ref() == other.as_slice()
    }
}

/// A received WG datagram with its sender identified.
pub struct WgDatagram {
    /// The peer's WireGuard public key.
    pub peer: NodePublic,
    /// The raw WG ciphertext datagram.
    pub data: WgCiphertext,
}

/// Ordered WireGuard receive burst handed to one tsnet consumer.
///
/// Its owned channel permit accounts for every contained packet while queued.
/// Consuming it through [`WgReceiveBatch::into_datagrams`] releases that
/// backpressure permit immediately. Linux pooled ciphertexts separately keep
/// their fixed-buffer inventory reservation until their buffers are dropped.
pub struct WgReceiveBatch {
    datagrams: Vec<WgDatagram>,
    // Kept separately from `_pool_reservation` so channel backpressure has
    // the same lifetime as the pre-pool implementation.
    _channel_permit: OwnedSemaphorePermit,
    // Pooled ciphertexts also own this Arc. Keeping one in the queued batch
    // makes cancellation and closed-channel cleanup explicit and ensures a
    // malformed empty pooled publication cannot leak its reservation.
    #[cfg(target_os = "linux")]
    _pool_reservation: Option<Arc<PoolInventoryReservation>>,
}

impl WgReceiveBatch {
    /// Number of ordered ciphertext datagrams in this batch.
    pub fn len(&self) -> usize {
        self.datagrams.len()
    }

    /// Whether this batch contains no datagrams.
    pub fn is_empty(&self) -> bool {
        self.datagrams.is_empty()
    }

    /// Consume this handoff item and return its datagrams in receive order.
    ///
    /// This releases the batch's channel backpressure permit immediately.
    /// Pooled ciphertexts retain only their separate buffer reservation.
    pub fn into_datagrams(self) -> Vec<WgDatagram> {
        self.datagrams
    }

    /// Constructs an unqueued batch for consumer tests.
    ///
    /// This does not reserve receive credits and must not be used to publish
    /// into Magicsock's receive channel; production publication is private to
    /// [`publish_wg_batch`]. Keeping the test constructor here lets downstream
    /// consumer tests exercise the real owned handoff type.
    #[doc(hidden)]
    pub fn from_datagrams_for_test(datagrams: Vec<WgDatagram>) -> Self {
        assert!(
            datagrams.len() <= WG_RECEIVE_BATCH_MAX_PACKETS,
            "receive batch exceeds its 128-packet maximum"
        );
        let permit = Arc::new(Semaphore::new(0))
            .try_acquire_many_owned(0)
            .expect("zero-credit test permit is always available");
        Self::new(datagrams, permit)
    }

    fn new(datagrams: Vec<WgDatagram>, permit: OwnedSemaphorePermit) -> Self {
        Self {
            datagrams,
            _channel_permit: permit,
            #[cfg(target_os = "linux")]
            _pool_reservation: None,
        }
    }

    #[cfg(target_os = "linux")]
    fn new_pooled(
        datagrams: Vec<WgDatagram>,
        channel_permit: OwnedSemaphorePermit,
        pool_reservation: Arc<PoolInventoryReservation>,
    ) -> Self {
        Self {
            datagrams,
            _channel_permit: channel_permit,
            _pool_reservation: Some(pool_reservation),
        }
    }
}

/// The path-selection engine.
pub struct Magicsock {
    inner: Arc<Inner>,
}

struct Inner {
    node_public: RwLock<NodePublic>,
    disco: DiscoIo,
    udp: Option<Arc<UdpSocket>>,
    /// TX `sendmmsg` availability. Linux starts batched when permitted by the
    /// process configuration, then permanently falls back to ordinary Tokio
    /// sends if the syscall is unavailable or blocked.
    #[cfg(target_os = "linux")]
    udp_tx_batch: AtomicBool,
    /// TX UDP GSO availability, probed once per direct UDP socket and disabled
    /// permanently if a GSO send reports an unsupported/checksum-offload error.
    #[cfg(target_os = "linux")]
    udp_tx_gso: AtomicBool,
    local_udp_addrs: RwLock<Vec<String>>,
    /// Multi-region DERP connection manager.
    derp: DerpManager,
    endpoints: RwLock<HashMap<NodePublic, Endpoint>>,
    disco_to_peer: RwLock<HashMap<DiscoPublic, NodePublic>>,
    addr_to_peer: RwLock<HashMap<SocketAddr, NodePublic>>,
    wg_send: mpsc::Sender<WgReceiveBatch>,
    /// The actual receive queue bound. The mpsc channel has enough item slots
    /// for the worst case of 256 one-packet batches; permits make its effective
    /// capacity packet-counted rather than batch-counted.
    wg_receive_credits: Arc<Semaphore>,
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
    /// At most one task per peer; replaced when TX resumes an idle session.
    background_tasks: RwLock<HashMap<NodePublic, tokio::task::JoinHandle<()>>>,
    /// Number of heartbeat tasks armed, used to verify TX coalescing.
    #[cfg(test)]
    heartbeat_task_generations: AtomicUsize,
    /// Last NetInfo received from control (or from local probing). Used to
    /// deduplicate updates and track PreferredDERP / connectivity changes.
    net_info: RwLock<Option<rustscale_tailcfg::NetInfo>>,
    /// Per-label socket TX/RX counters for magicsock's UDP socket.
    /// `None` when no sockstats registry was injected. Best-effort: recording
    /// is a relaxed atomic increment and never affects send/recv error paths.
    sockstats_udp4: Option<rustscale_sockstats::LabelHandle>,
    sockstats_udp6: Option<rustscale_sockstats::LabelHandle>,
    /// Optional physical-transport accounting observer.
    connection_counter: ConnectionCounterHook,
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

/// Owns all state registered by one `cli_ping` call. Synchronous cleanup in
/// `Drop` makes the async operation cancellation-safe, including task aborts
/// and timeouts imposed by callers outside magicsock.
struct CliPingRegistration {
    inner: Arc<Inner>,
    peer_key: NodePublic,
    request_id: u64,
}

impl Drop for CliPingRegistration {
    fn drop(&mut self) {
        {
            let mut callbacks = self
                .inner
                .cli_ping_callbacks
                .write()
                .expect("cli_ping_callbacks lock poisoned");
            if let Some(requests) = callbacks.get_mut(&self.peer_key) {
                requests.remove(&self.request_id);
                if requests.is_empty() {
                    callbacks.remove(&self.peer_key);
                }
            }
        }
        let mut endpoints = self
            .inner
            .endpoints
            .write()
            .expect("endpoints lock poisoned");
        for endpoint in endpoints.values_mut() {
            endpoint.remove_cli_request_pings(self.request_id);
        }
    }
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

        let certificate_policy =
            rustscale_derp::CertificatePolicy::from_derp_cert_name(&node.CertName);
        let connect_result = match certificate_policy {
            Ok(policy) => {
                DerpClient::connect_with_upgrade_dial_policy(
                    &dial_addr,
                    &tls_host,
                    port,
                    !node.InsecureForTests,
                    node.InsecureForTests,
                    policy,
                    self.node_private.clone(),
                    None,
                )
                .await
            }
            Err(error) => Err(rustscale_derp::DerpError::Tls(error)),
        };
        let client = match connect_result {
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
    ) -> Result<(Self, mpsc::Receiver<WgReceiveBatch>), MagicsockError> {
        let node_public = config.private_key.public();
        let disco = DiscoIo::new(config.disco_key);

        let (wg_send, wg_recv) = mpsc::channel(WG_RECEIVE_PACKET_CAPACITY);
        let wg_receive_credits = Arc::new(Semaphore::new(WG_RECEIVE_PACKET_CAPACITY));

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

        // Configure the socket selected above, whether it came from
        // `udp_socket` or `udp_bind`, before probing/spawning UDP I/O.
        if let Some(socket) = udp.as_deref() {
            rustscale_netns::configure_udp_socket(socket)?;
        }
        configure_selected_udp_socket(udp.as_deref(), udp_socket_buffers::configure);

        #[cfg(target_os = "linux")]
        let udp_send_config = LinuxUdpSendConfig::from_environment();
        #[cfg(target_os = "linux")]
        let udp_tx_batch = udp_send_config.use_batch;
        #[cfg(target_os = "linux")]
        let udp_tx_gso = udp_tx_batch
            && !udp_send_config.disable_udp_gso
            && udp
                .as_ref()
                .is_some_and(|socket| udp_batch::supports_gso(socket));

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
            #[cfg(target_os = "linux")]
            udp_tx_batch: AtomicBool::new(udp_tx_batch),
            #[cfg(target_os = "linux")]
            udp_tx_gso: AtomicBool::new(udp_tx_gso),
            local_udp_addrs: RwLock::new(local_udp_addrs),
            derp,
            endpoints: RwLock::new(HashMap::new()),
            disco_to_peer: RwLock::new(HashMap::new()),
            addr_to_peer: RwLock::new(HashMap::new()),
            wg_send,
            wg_receive_credits,
            portmapper: config.portmapper,
            disable_direct_paths: config.disable_direct_paths,
            relay_manager: RwLock::new(None),
            relay_server,
            self_cap_map,
            peer_mtu_enabled: Arc::new(AtomicBool::new(false)),
            control_knobs: config.control_knobs,
            background_tasks: RwLock::new(HashMap::new()),
            #[cfg(test)]
            heartbeat_task_generations: AtomicUsize::new(0),
            net_info: RwLock::new(None),
            sockstats_udp4,
            sockstats_udp6,
            connection_counter: ConnectionCounterHook::default(),
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

    /// Replace the DERP map used for lazy DERP connections.
    pub fn set_derp_map(&self, map: &DERPMap) {
        *self
            .inner
            .derp
            .derp_map
            .write()
            .expect("derp_map lock poisoned") = Some(map.clone());
    }

    /// Return a snapshot of the latest DERP map, if one has been supplied.
    pub fn get_derp_map(&self) -> Option<DERPMap> {
        self.inner
            .derp
            .derp_map
            .read()
            .expect("derp_map lock poisoned")
            .clone()
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

                // Update the physical-netlog identity and HomeDERP from the
                // latest netmap without disturbing path state.
                ep.set_node_addr(first_node_addr(peer));
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

    /// Install or remove the physical transport connection counter.
    ///
    /// The hook is optional and may be changed while I/O tasks are running.
    /// Callback panics are contained and a missing/poisoned hook is a no-op.
    pub fn set_connection_counter(&self, counter: Option<ConnectionCounter>) {
        self.inner.connection_counter.set(counter);
    }

    /// Send a WG datagram to `peer` over the best available path.
    pub async fn send(&self, peer: NodePublic, datagram: &[u8]) -> Result<(), MagicsockError> {
        self.send_batch(peer, std::slice::from_ref(&datagram)).await
    }

    /// Send ordered WireGuard datagrams over one snapshot of the peer's path.
    pub async fn send_batch<T: AsRef<[u8]>>(
        &self,
        peer: NodePublic,
        datagrams: &[T],
    ) -> Result<(), MagicsockError> {
        if datagrams.is_empty() {
            return Ok(());
        }
        // Note TX activity before path lookup. Only an inactive-to-active
        // transition arms the independent heartbeat cadence.
        let (arm_heartbeat, path, derp_region, node_addr) = {
            let mut endpoints = self
                .inner
                .endpoints
                .write()
                .expect("endpoints lock poisoned");
            let now = std::time::Instant::now();
            let ep = endpoints
                .get_mut(&peer)
                .ok_or(MagicsockError::PeerNotFound)?;
            (
                ep.note_tx_activity_transition(now, SESSION_ACTIVE_TIMEOUT),
                ep.best_path(now),
                ep.derp_send_region(),
                ep.node_addr(),
            )
        };
        if arm_heartbeat {
            self.arm_heartbeat(&peer);
        }

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

        let mut first_error = None;
        match path {
            endpoint::BestPath::Direct { addr, .. } => {
                if self.inner.disable_direct_paths {
                    for datagram in datagrams {
                        if let Err(e) = self
                            .send_data_via_derp(
                                peer.clone(),
                                node_addr,
                                derp_region,
                                datagram.as_ref(),
                            )
                            .await
                        {
                            first_error.get_or_insert(e);
                        }
                    }
                    return first_error.map_or(Ok(()), Err);
                }
                if let Some(ref udp) = self.inner.udp {
                    #[cfg(target_os = "linux")]
                    {
                        return self
                            .send_direct_batch_linux(udp, addr, node_addr, datagrams)
                            .await;
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        let (mut sent_packets, mut sent_bytes) = (0, 0);
                        for datagram in datagrams {
                            let datagram = datagram.as_ref();
                            if let Err(e) = udp.send_to(datagram, addr).await {
                                if !treat_as_lost_udp(&e) {
                                    first_error.get_or_insert(MagicsockError::Io(e));
                                }
                            } else {
                                self.inner.record_udp_tx(addr, datagram.len());
                                sent_packets += 1;
                                sent_bytes += datagram.len() as u64;
                            }
                        }
                        self.inner.connection_counter.record(
                            node_addr,
                            addr,
                            sent_packets,
                            sent_bytes,
                            false,
                        );
                        return first_error.map_or(Ok(()), Err);
                    }
                }
                for datagram in datagrams {
                    if let Err(e) = self
                        .send_data_via_derp(peer.clone(), node_addr, derp_region, datagram.as_ref())
                        .await
                    {
                        first_error.get_or_insert(e);
                    }
                }
            }
            endpoint::BestPath::Relay { addr, vni } => {
                // Relay paths work even when direct paths are disabled —
                // the relay path is established by the relay manager, not
                // by direct disco pinging.
                if let Some(ref udp) = self.inner.udp {
                    let (mut sent_packets, mut sent_bytes) = (0, 0);
                    for datagram in datagrams {
                        let datagram = datagram.as_ref();
                        let framed = relay::encode_geneve(vni, datagram);
                        if let Err(e) = udp.send_to(&framed, addr).await {
                            if !treat_as_lost_udp(&e) {
                                first_error.get_or_insert(MagicsockError::Io(e));
                            }
                        } else {
                            self.inner.record_udp_tx(addr, framed.len());
                            sent_packets += 1;
                            // Upstream physical netlog excludes the Geneve
                            // header on transmit.
                            sent_bytes += datagram.len() as u64;
                        }
                    }
                    self.inner.connection_counter.record(
                        node_addr,
                        addr,
                        sent_packets,
                        sent_bytes,
                        false,
                    );
                    return first_error.map_or(Ok(()), Err);
                }
                for datagram in datagrams {
                    if let Err(e) = self
                        .send_data_via_derp(peer.clone(), node_addr, derp_region, datagram.as_ref())
                        .await
                    {
                        first_error.get_or_insert(e);
                    }
                }
            }
            endpoint::BestPath::Derp { .. } | endpoint::BestPath::None => {
                for datagram in datagrams {
                    if let Err(e) = self
                        .send_data_via_derp(peer.clone(), node_addr, derp_region, datagram.as_ref())
                        .await
                    {
                        first_error.get_or_insert(e);
                    }
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    /// Linux direct-path sender. `async_io` owns readiness registration for
    /// this Tokio socket; the raw helper only performs the one nonblocking IO.
    #[cfg(target_os = "linux")]
    async fn send_direct_batch_linux<T: AsRef<[u8]>>(
        &self,
        udp: &Arc<UdpSocket>,
        addr: SocketAddr,
        node_addr: Option<IpAddr>,
        datagrams: &[T],
    ) -> Result<(), MagicsockError> {
        // Match upstream's per-write atomic snapshot: a live knob update takes
        // effect on the next API batch, never halfway through this one.
        let never_gso_equal_tail = never_gso_equal_tail(self.inner.control_knobs.as_deref());
        let mut head = 0;
        let mut first_error = None;
        let (mut sent_packets, mut sent_bytes) = (0, 0);
        while head < datagrams.len() {
            let use_batch = self.inner.udp_tx_batch.load(Ordering::Relaxed);
            let use_gso = use_batch && self.inner.udp_tx_gso.load(Ordering::Relaxed);
            let result = if use_batch {
                let end = (head + udp_batch::MAX_BATCH).min(datagrams.len());
                udp.async_io(Interest::WRITABLE, || {
                    if use_gso {
                        udp_batch::send_gso(udp, addr, &datagrams[head..end], never_gso_equal_tail)
                    } else {
                        udp_batch::send(udp, addr, &datagrams[head..end]).map(|sent| {
                            udp_batch::SendOutcome {
                                datagrams: sent,
                                wire_bytes: datagrams[head..head + sent]
                                    .iter()
                                    .map(|datagram| datagram.as_ref().len())
                                    .sum(),
                            }
                        })
                    }
                })
                .await
            } else {
                let datagram = datagrams[head].as_ref();
                udp.send_to(datagram, addr).await.and_then(|sent| {
                    if sent == datagram.len() {
                        Ok(udp_batch::SendOutcome {
                            datagrams: 1,
                            wire_bytes: sent,
                        })
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "UDP send reported a partial datagram",
                        ))
                    }
                })
            };
            if use_gso && result.as_ref().is_err_and(should_disable_udp_gso) {
                if self.inner.udp_tx_gso.swap(false, Ordering::Relaxed) {
                    eprintln!(
                        "rustscale: Linux UDP GSO send failed; permanently falling back to plain sends"
                    );
                }
                // `sendmmsg` reports no progress with an error, so retry this
                // exact unsent suffix without UDP_SEGMENT metadata.
                continue;
            }
            if use_batch
                && result
                    .as_ref()
                    .is_err_and(udp_batch::sendmmsg_is_unsupported)
            {
                if self.inner.udp_tx_batch.swap(false, Ordering::Relaxed) {
                    self.inner.udp_tx_gso.store(false, Ordering::Relaxed);
                    eprintln!(
                        "rustscale: Linux sendmmsg unavailable; permanently falling back to ordinary UDP sends"
                    );
                }
                // The failed batch made no progress. Retry its exact head with
                // Tokio's ordinary UDP path, preserving ordering and accounting.
                continue;
            }
            let wire_bytes = result.as_ref().map_or(0, |outcome| outcome.wire_bytes);
            let sent = advance_direct_batch(
                &mut head,
                datagrams.len(),
                &mut first_error,
                result.map(|outcome| outcome.datagrams),
            );
            let sent_datagrams = &datagrams[head - sent..head];
            let (packets, bytes, sockstats_bytes) =
                linux_udp_send_accounting(sent_datagrams, wire_bytes);
            self.inner.record_udp_tx(addr, sockstats_bytes);
            sent_packets += packets;
            sent_bytes += bytes;
        }
        self.inner
            .connection_counter
            .record(node_addr, addr, sent_packets, sent_bytes, false);
        first_error.map_or(Ok(()), |error| Err(MagicsockError::Io(error)))
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
        // This must be created immediately after callback registration. Every
        // subsequent return, panic unwind, timeout, or future cancellation
        // drops it and removes both callback and transaction state.
        let _registration = CliPingRegistration {
            inner: self.inner.clone(),
            peer_key: peer_key.clone(),
            request_id,
        };

        // Send direct and DERP CLI pings independently. A relay pong is a
        // useful result even if direct candidates were advertised.
        if !peer_disco.is_zero() {
            // A CLI ping is an explicit request to establish a direct path.
            // Advertise our current UDP addresses without inheriting the
            // background discovery rate limit; repeated CLI attempts provide
            // their own retry cadence.
            if !self.inner.disable_direct_paths {
                let cmm = Message::CallMeMaybe(CallMeMaybe {
                    my_number: self
                        .local_udp_addrs()
                        .iter()
                        .filter_map(|addr| addr.parse::<SocketAddr>().ok())
                        .map(rustscale_disco::AddrPort::from)
                        .collect(),
                });
                if let Some(packet) = self.inner.disco.seal(&peer_disco, &cmm) {
                    // Use the regular DERP sender so an unknown region takes
                    // its bootstrap fanout path.
                    let _ = self
                        .send_via_derp(peer_key.clone(), derp_region, &packet)
                        .await;
                }
            }

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
                // Use the regular DERP sender so an unknown region takes
                // its bootstrap fanout path, just like a normal datagram.
                // A send failure remains observable through the existing
                // CLI timeout/error contract.
                let _ = self
                    .send_via_derp(peer_key.clone(), derp_region, &packet)
                    .await;
            }
        }

        // Wait for the pong callback or timeout.
        let result = tokio::time::timeout(Duration::from_secs(5), rx).await;
        match result {
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
            Err(_) => Err(MagicsockError::Timeout),
        }
    }

    /// Arm (or re-arm) the per-peer background task for heartbeats and UDP
    /// lifetime probing when TX transitions from inactive to active. Aborts
    /// any existing task for this peer to ensure at most one task at a time.
    /// Mirrors Go's `noteTxActivityExtTriggerLocked` arming the heartbeat
    /// timer (endpoint.go:974-979).
    fn arm_heartbeat(&self, peer_key: &NodePublic) {
        let mut tasks = self
            .inner
            .background_tasks
            .write()
            .expect("background_tasks lock");
        #[cfg(test)]
        self.inner
            .heartbeat_task_generations
            .fetch_add(1, Ordering::Relaxed);
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

    /// Send one user WireGuard datagram through DERP and account it once.
    /// Discovery/control callers use [`Self::send_via_derp`] directly and are
    /// deliberately excluded from physical traffic.
    async fn send_data_via_derp(
        &self,
        peer: NodePublic,
        node_addr: Option<IpAddr>,
        region: i32,
        datagram: &[u8],
    ) -> Result<(), MagicsockError> {
        let accounting_region = self.send_via_derp(peer, region, datagram).await?;
        if let Ok(region) = u16::try_from(accounting_region) {
            if region != 0 {
                self.inner.connection_counter.record(
                    node_addr,
                    SocketAddr::new(DERP_MAGIC_IP, region),
                    1,
                    datagram.len() as u64,
                    false,
                );
            }
        }
        Ok(())
    }

    /// Send a packet to `peer` via DERP region `region`.
    /// If `region` is 0 (unknown), fans out to ALL connected DERP regions
    /// so the peer receives the packet on whichever region it's on.
    /// Once a reply arrives, `last_recv_derp_region` is set and future
    /// sends go to that single region.
    async fn send_via_derp(
        &self,
        peer: NodePublic,
        region: i32,
        datagram: &[u8],
    ) -> Result<i32, MagicsockError> {
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
                        "DBG derp_send peer={} region={} packet_len={}",
                        short_key(&peer),
                        region,
                        datagram.len()
                    );
                }
                return Ok(region);
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
                "DBG derp_fanout peer={} regions={:?} packet_len={}",
                short_key(&peer),
                all_regions,
                datagram.len()
            );
        }

        if all_regions.is_empty() {
            return Err(MagicsockError::NoPath);
        }

        let mut accounting_region = 0;
        for r in all_regions {
            if self
                .inner
                .derp
                .send_packet(r, peer.clone(), datagram.to_vec())
                .await
                && accounting_region == 0
            {
                // Fanout is bootstrap duplication of one logical packet.
                // Attribute it once, to the first region that accepted it.
                accounting_region = r;
            }
        }
        Ok(accounting_region)
    }
}

/// Launch background UDP recv task + DERP demux task.
fn spawn_recv_tasks(
    inner: Arc<Inner>,
    derp_recv_rx: mpsc::Receiver<(i32, DerpEvent)>,
    reconnect_rx: mpsc::UnboundedReceiver<i32>,
) {
    // Linux owns one reusable recvmmsg batch for this task. Tokio owns socket
    // readiness; the raw helper only performs one nonblocking receive syscall.
    #[cfg(target_os = "linux")]
    if let Some(ref udp) = inner.udp {
        let udp = udp.clone();
        let inner = inner.clone();
        tokio::spawn(async move {
            // Read deployment configuration once. Neither receive mode nor
            // UDP GRO selection consults the process environment on the hot
            // path.
            let receive_config = LinuxUdpReceiveConfig::from_environment();
            if !receive_config.use_batch {
                eprintln!(
                    "rustscale: Linux UDP receive mode=scalar (RUSTSCALE_DISABLE_LINUX_UDP_BATCH present)"
                );
                let mut buf = vec![0u8; 65_536];
                loop {
                    match udp.recv_from(&mut buf).await {
                        Ok((len, addr)) => {
                            inner.record_udp_rx(addr, len);
                            inner.handle_udp_packet(&buf[..len], addr).await;
                            while let Ok((len2, addr2)) = udp.try_recv_from(&mut buf) {
                                inner.record_udp_rx(addr2, len2);
                                inner.handle_udp_packet(&buf[..len2], addr2).await;
                            }
                        }
                        Err(_) => return,
                    }
                }
            }

            // The guarded, circuit-broken GRO receiver is the batch default.
            // The explicit GRO kill switch keeps the 128-slot plain recvmmsg
            // path available without changing batch handoff behavior.
            let mut batch = udp_batch::ReceiveBatch::new(&udp, receive_config.disable_udp_gro);
            // `pending` only stages ownership; pooled ciphertext ownership moves
            // into the channel or is dropped before the next receive.
            let mut pending = Vec::with_capacity(udp_batch::MAX_BATCH);
            loop {
                match udp.async_io(Interest::READABLE, || batch.recv(&udp)).await {
                    Ok(count) => {
                        // This must precede every classification, lock, and
                        // semaphore await: endpoint activity records packet
                        // arrival rather than consumer backpressure delay.
                        let received_at = std::time::Instant::now();
                        if inner
                            .prepare_linux_udp_batch(&mut batch, count, &mut pending, received_at)
                            .await
                        {
                            for index in 0..count {
                                let Some((data, addr)) = batch.datagram(index) else {
                                    return;
                                };
                                inner.record_udp_rx(addr, data.len());
                                inner.handle_udp_packet(data, addr).await;
                            }
                        }
                    }
                    Err(error) if udp_batch::recvmmsg_is_unsupported(&error) => {
                        eprintln!(
                            "rustscale: Linux UDP batch receive unavailable; falling back to scalar: {error}"
                        );
                        break;
                    }
                    Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                        // `recvmmsg` already consumed this entire kernel batch.
                        // ReceiveBatch leaves its count unpublished on parse,
                        // source, truncation, or size failures, so drop all of
                        // it atomically and keep the direct UDP task alive.
                    }
                    Err(_) => return,
                }
            }

            // Allocate the scalar buffer only after an old kernel has proved
            // that it does not implement recvmmsg.
            let mut scalar_buf = vec![0u8; 65_536];
            loop {
                match udp.recv_from(&mut scalar_buf).await {
                    Ok((len, addr)) => {
                        inner.record_udp_rx(addr, len);
                        inner.handle_udp_packet(&scalar_buf[..len], addr).await;
                        while let Ok((len2, addr2)) = udp.try_recv_from(&mut scalar_buf) {
                            inner.record_udp_rx(addr2, len2);
                            inner.handle_udp_packet(&scalar_buf[..len2], addr2).await;
                        }
                    }
                    Err(_) => return,
                }
            }
        });
    }

    // Keep the established awaited receive plus immediate drain path exactly
    // as-is on platforms without Linux recvmmsg support.
    #[cfg(not(target_os = "linux"))]
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
                DerpEvent::RecvPacket {
                    source,
                    frame,
                    payload,
                } => {
                    inner2
                        .handle_derp_packet(frame, payload, source, region_id)
                        .await;
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
/// completes, or TX resumes after becoming idle (which replaces it with a
/// heartbeat task).
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

    /// Record the aggregate direct-receive bytes from one Linux kernel batch.
    /// Each populated address family performs one relaxed counter update.
    #[cfg(target_os = "linux")]
    fn record_linux_udp_batch_rx(&self, udp4_rx_bytes: usize, udp6_rx_bytes: usize) {
        if udp4_rx_bytes != 0 {
            if let Some(ref h) = self.sockstats_udp4 {
                h.record_rx(udp4_rx_bytes);
            }
        }
        if udp6_rx_bytes != 0 {
            if let Some(ref h) = self.sockstats_udp6 {
                h.record_rx(udp6_rx_bytes);
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
                self.handle_wg_udp_relay(inner, src, vni, data.len()).await;
                return;
            }
        }
        if DiscoIo::looks_like_disco(data) {
            self.handle_disco_udp(data, src).await;
        } else {
            self.handle_wg_udp(data, src).await;
        }
    }

    /// Returns true when the caller must run the established sequential
    /// handler. Control traffic deliberately takes the scalar path for the
    /// *whole* batch: disco and Geneve handling can update routing state and
    /// has historically been interleaved with direct WireGuard delivery in
    /// packet order. The normal path identifies source runs, then awaits
    /// credits with no batch borrow or map lock before detaching fixed slots.
    #[cfg(target_os = "linux")]
    async fn prepare_linux_udp_batch(
        &self,
        batch: &mut udp_batch::ReceiveBatch,
        count: usize,
        pending: &mut Vec<WgDatagram>,
        received_at: std::time::Instant,
    ) -> bool {
        if linux_batch_requires_scalar_handler(
            (0..count).map(|index| batch.datagram(index).map(|(data, _)| data)),
        ) {
            // A successful receive batch must always have a source and a
            // logical packet for each slot. No staged data may survive a
            // scalar fallback, even though normal publication drains it
            // before the next batch.
            pending.clear();
            return true;
        }

        let identified = {
            let peers = self
                .addr_to_peer
                .read()
                .expect("addr_to_peer lock poisoned");
            identify_linux_wg_peers(
                (0..count).map(|index| {
                    batch
                        .datagram_meta(index)
                        .expect("published receive batch has every logical datagram")
                        .1
                }),
                &peers,
                received_at,
            )
        };
        let known = identified
            .peers
            .iter()
            .filter(|peer| peer.is_some())
            .count();
        if known == 0 {
            pending.clear();
            // Unknown ordinary direct packets are still accounted below, but
            // need neither a credit nor a pooled detach.
            let mut udp4_rx_bytes = 0;
            let mut udp6_rx_bytes = 0;
            for index in 0..count {
                let (len, source) = batch
                    .datagram_meta(index)
                    .expect("published receive batch has every logical datagram");
                match source {
                    SocketAddr::V4(_) => udp4_rx_bytes += len,
                    SocketAddr::V6(_) => udp6_rx_bytes += len,
                }
            }
            self.record_linux_udp_batch_rx(udp4_rx_bytes, udp6_rx_bytes);
            return false;
        }
        // No ReceiveBatch slice borrow or endpoint/address lock survives
        // either await. Channel backpressure keeps its established queued
        // lifetime; fixed-buffer inventory is a separate 384-slot limit.
        let Ok(channel_permit) = self
            .wg_receive_credits
            .clone()
            .acquire_many_owned(u32::try_from(known).expect("known batch count fits u32"))
            .await
        else {
            return false;
        };
        let pool_inventory = batch.pool_inventory();
        let Some(pool_reservation) = PoolInventoryReservation::acquire(pool_inventory, known).await
        else {
            return false;
        };

        pending.clear();
        {
            let mut endpoints = self.endpoints.write().expect("endpoints lock poisoned");
            detach_linux_wg_datagrams(
                batch,
                count,
                &identified,
                &pool_reservation,
                &mut endpoints,
                pending,
                |_, endpoint, now| endpoint.note_recv_udp(now),
                |udp4_rx_bytes, udp6_rx_bytes| {
                    self.record_linux_udp_batch_rx(udp4_rx_bytes, udp6_rx_bytes);
                },
                |node_addr, source, packets, bytes| {
                    self.connection_counter
                        .record(node_addr, source, packets, bytes, true);
                },
            );
        }
        debug_assert_eq!(pending.len(), known);
        let datagrams = std::mem::take(pending);
        publish_reserved_wg_batch(&self.wg_send, datagrams, channel_permit, pool_reservation).await;
        false
    }

    async fn handle_derp_packet(
        &self,
        frame: Vec<u8>,
        payload: Range<usize>,
        source: NodePublic,
        region_id: i32,
    ) {
        // Note DERP region frame for health tracking.
        if let Some(ref health) = self.derp.health {
            health.note_derp_region_frame(region_id);
        }

        // Record the arrival DERP region on the peer's endpoint so future
        // replies route to this region (Go's derpRoute caching).
        let node_addr = {
            let mut endpoints = self.endpoints.write().expect("endpoints lock poisoned");
            endpoints.get_mut(&source).map(|ep| {
                ep.set_last_recv_derp_region(region_id);
                ep.node_addr()
            })
        }
        .flatten();

        let data = &frame[payload.clone()];
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
            // WG datagram via DERP — account only after peer lookup and before
            // delivery. Disco/control frames took the branch above.
            if let Ok(region) = u16::try_from(region_id) {
                if region != 0 {
                    self.connection_counter.record(
                        node_addr,
                        SocketAddr::new(DERP_MAGIC_IP, region),
                        1,
                        data.len() as u64,
                        true,
                    );
                }
            }
            publish_wg_batch(
                &self.wg_send,
                &self.wg_receive_credits,
                vec![WgDatagram {
                    peer: source,
                    data: WgCiphertext::from_vec_range(frame, payload),
                }],
            )
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
            let node_addr = {
                let mut endpoints = self.endpoints.write().expect("endpoints lock poisoned");
                endpoints.get_mut(&peer).map(|ep| {
                    ep.note_recv_udp(std::time::Instant::now());
                    ep.node_addr()
                })
            }
            .flatten();
            self.connection_counter
                .record(node_addr, src, 1, data.len() as u64, true);
            publish_wg_batch(
                &self.wg_send,
                &self.wg_receive_credits,
                vec![WgDatagram {
                    peer,
                    data: data.to_vec().into(),
                }],
            )
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
    async fn handle_wg_udp_relay(
        &self,
        data: &[u8],
        src: SocketAddr,
        _vni: u32,
        physical_len: usize,
    ) {
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
            let node_addr = self
                .endpoints
                .read()
                .ok()
                .and_then(|endpoints| endpoints.get(&peer).and_then(Endpoint::node_addr));
            // Receive accounting includes the Geneve header, matching
            // upstream's geneveInclusivePacketLen behavior.
            self.connection_counter
                .record(node_addr, src, 1, physical_len as u64, true);
            publish_wg_batch(
                &self.wg_send,
                &self.wg_receive_credits,
                vec![WgDatagram {
                    peer,
                    data: data.to_vec().into(),
                }],
            )
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
                // The peer is telling us its UDP addresses. Retain every
                // authenticated address before probing so later discovery and
                // CLI rounds can reuse them. Drop the endpoint lock before
                // awaiting any network IO.
                let addrs: Vec<SocketAddr> = cmm
                    .my_number
                    .iter()
                    .copied()
                    .map(SocketAddr::from)
                    .collect();
                {
                    let mut endpoints = self.endpoints.write().expect("endpoints lock poisoned");
                    if let Some(endpoint) = endpoints.get_mut(&source) {
                        for &addr in &addrs {
                            endpoint.learn_candidate(addr);
                        }
                    }
                }

                // When direct paths are disabled, don't ping the peer's
                // advertised addresses — we won't use a direct path anyway.
                if self.disable_direct_paths {
                    return;
                }

                // Ping each advertised address.
                let peer_disco = sender_disco.clone();
                for addr in addrs {
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

/// Configure the optional direct-UDP socket after `udp_socket`/`udp_bind`
/// precedence has selected it. Keeping this shared post-selection hook small
/// makes both constructor alternatives exercise the same buffer policy.
fn configure_selected_udp_socket<T>(socket: Option<T>, configure: impl FnOnce(T)) {
    if let Some(socket) = socket {
        configure(socket);
    }
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
mod linux_batch_tests {
    use super::*;

    fn endpoint(peer: NodePublic) -> Endpoint {
        Endpoint::new(peer, DiscoPrivate::generate().public(), 0)
    }

    fn pending(count: usize) -> Vec<WgDatagram> {
        let peer = NodePrivate::generate().public();
        (0..count)
            .map(|index| WgDatagram {
                peer: peer.clone(),
                data: vec![index as u8].into(),
            })
            .collect()
    }

    #[test]
    fn owned_ciphertext_range_exposes_exact_derp_payload() {
        let frame = b"prefix-derp-ciphertext-suffix".to_vec();
        let ciphertext = WgCiphertext::from_vec_range(frame, 7..22);
        assert_eq!(ciphertext.as_ref(), b"derp-ciphertext");
        assert_eq!(&*ciphertext, b"derp-ciphertext");
    }

    #[test]
    fn ciphertext_v01_migration_api_is_ergonomic_for_owned_vectors() {
        let ciphertext: WgCiphertext = vec![1, 2, 3].into();
        assert_eq!(ciphertext.as_ref(), [1, 2, 3]);
        assert_eq!(&*ciphertext, [1, 2, 3]);
        assert_eq!(ciphertext, vec![1, 2, 3]);
        assert_eq!(vec![1, 2, 3], ciphertext);
        assert_eq!(ciphertext.try_clone().unwrap().as_ref(), [1, 2, 3]);
        assert_eq!(format!("{ciphertext:?}"), "WgCiphertext([1, 2, 3])");
        let _datagram = WgDatagram {
            peer: NodePrivate::generate().public(),
            data: vec![4, 5].into(),
        };
    }

    // This seam is intentionally platform-neutral: macOS test builds do not
    // compile Linux recvmmsg storage, but they still verify the two permit
    // lifetimes that the Linux pooled path combines below.
    #[tokio::test]
    async fn consumed_batch_releases_channel_credit_before_pool_inventory() {
        let channel_credits = Arc::new(Semaphore::new(1));
        let pool_inventory = Arc::new(Semaphore::new(1));
        let channel_permit = channel_credits.clone().try_acquire_owned().unwrap();
        let pool_reservation = PoolInventoryReservation::acquire(pool_inventory.clone(), 1)
            .await
            .expect("open pool inventory reserves one buffer");
        let batch = WgReceiveBatch::new(pending(1), channel_permit);

        let datagrams = batch.into_datagrams();
        assert_eq!(channel_credits.available_permits(), 1);
        assert_eq!(pool_inventory.available_permits(), 0);
        drop(datagrams);
        assert_eq!(pool_inventory.available_permits(), 0);
        drop(pool_reservation);
        assert_eq!(pool_inventory.available_permits(), 1);
    }

    #[tokio::test]
    async fn pool_inventory_reservation_acquires_immediately_or_waits_for_capacity() {
        let inventory = Arc::new(Semaphore::new(2));

        let immediate = PoolInventoryReservation::acquire(inventory.clone(), 2)
            .await
            .expect("available inventory acquires immediately");
        assert_eq!(inventory.available_permits(), 0);
        drop(immediate);
        assert_eq!(inventory.available_permits(), 2);

        let held = inventory
            .clone()
            .try_acquire_many_owned(2)
            .expect("test inventory has capacity to hold");
        let waiting_inventory = inventory.clone();
        let waiting =
            tokio::spawn(
                async move { PoolInventoryReservation::acquire(waiting_inventory, 1).await },
            );
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished(), "unavailable inventory waits fairly");
        drop(held);

        let waited = tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .expect("released inventory wakes the waiter")
            .expect("waiter task completes")
            .expect("open inventory reserves capacity");
        assert_eq!(inventory.available_permits(), 1);
        drop(waited);
        assert_eq!(inventory.available_permits(), 2);

        inventory.close();
        assert!(PoolInventoryReservation::acquire(inventory, 1)
            .await
            .is_none());
    }

    #[test]
    fn direct_identification_keeps_pre_backpressure_arrival_timestamp() {
        let address: SocketAddr = "127.0.0.1:10001".parse().unwrap();
        let peer = NodePrivate::generate().public();
        let arrival = std::time::Instant::now();
        let identified =
            identify_linux_wg_peers([address], &HashMap::from([(address, peer)]), arrival);
        std::thread::sleep(Duration::from_millis(10));

        assert_eq!(identified.peers.len(), 1);
        assert_eq!(identified.received_at, arrival);
        assert!(identified.received_at.elapsed() >= Duration::from_millis(10));
    }

    #[test]
    fn delayed_capacity_still_notes_direct_endpoint_at_arrival() {
        let peer = NodePrivate::generate().public();
        let address: SocketAddr = "127.0.0.1:10001".parse().unwrap();
        let arrival = std::time::Instant::now();
        std::thread::sleep(Duration::from_millis(10));
        let mut noted = Vec::new();
        stage_linux_wg_datagrams_at(
            [(b"packet".as_slice(), address)],
            &HashMap::from([(address, peer.clone())]),
            &mut HashMap::from([(peer.clone(), endpoint(peer.clone()))]),
            &mut Vec::new(),
            arrival,
            |_, _, timestamp| noted.push(timestamp),
            |_, _| {},
        );
        assert_eq!(noted, vec![arrival]);
    }

    fn advance_sequence(
        lengths: &[usize],
        results: impl IntoIterator<Item = io::Result<usize>>,
    ) -> (usize, Vec<usize>, Option<io::Error>) {
        let mut head = 0;
        let mut first_error = None;
        let mut accounted = Vec::new();
        for result in results {
            let before = head;
            let sent = advance_direct_batch(&mut head, lengths.len(), &mut first_error, result);
            accounted.extend_from_slice(&lengths[before..before + sent]);
        }
        (head, accounted, first_error)
    }

    #[test]
    fn equal_tail_accounting_separates_original_netlog_and_physical_sockstats() {
        let datagrams = vec![vec![0x08; 32]; 8];
        assert_eq!(
            linux_udp_send_accounting(&datagrams, 8 * 32 + 1),
            (8, 8 * 32, 8 * 32 + 1),
            "sentinel is physical sockstats only"
        );
        assert_eq!(
            linux_udp_send_accounting(&datagrams, 8 * 32),
            (8, 8 * 32, 8 * 32),
            "plain fallback has no sentinel byte"
        );
    }

    #[test]
    fn direct_batch_advancement_accounts_successful_prefixes() {
        let (head, accounted, error) = advance_sequence(&[3, 5, 7, 11], [Ok(4)]);
        assert_eq!(head, 4);
        assert_eq!(accounted, [3, 5, 7, 11]);
        assert!(error.is_none());

        let (head, accounted, error) = advance_sequence(&[3, 5, 7, 11], [Ok(1), Ok(2), Ok(1)]);
        assert_eq!(head, 4);
        assert_eq!(accounted, [3, 5, 7, 11]);
        assert!(error.is_none());
    }

    #[test]
    fn would_block_retains_the_same_suffix() {
        let (head, accounted, error) = advance_sequence(
            &[3, 5],
            [Err(io::Error::from(io::ErrorKind::WouldBlock)), Ok(2)],
        );
        assert_eq!(head, 2);
        assert_eq!(accounted, [3, 5]);
        assert!(error.is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn lost_error_skips_only_its_head() {
        let (head, accounted, error) = advance_sequence(
            &[3, 5, 7],
            [Err(io::Error::from_raw_os_error(libc::EPERM)), Ok(2)],
        );
        assert_eq!(head, 3);
        assert_eq!(accounted, [5, 7]);
        assert!(error.is_none());
    }

    #[test]
    fn retained_error_is_first_and_later_suffix_still_sends() {
        let (head, accounted, error) = advance_sequence(
            &[3, 5, 7],
            [
                Err(io::Error::from_raw_os_error(libc::EINVAL)),
                Err(io::Error::from_raw_os_error(libc::EIO)),
                Ok(1),
            ],
        );
        assert_eq!(head, 3);
        assert_eq!(accounted, [7]);
        assert_eq!(
            error.and_then(|error| error.raw_os_error()),
            Some(libc::EINVAL)
        );
    }

    #[test]
    fn mixed_control_disco_batch_falls_back_without_reordering_ordinary_wg() {
        let mut disco = vec![
            0;
            rustscale_disco::MAGIC.len()
                + rustscale_disco::KEY_LEN
                + rustscale_disco::NONCE_LEN
        ];
        disco[..rustscale_disco::MAGIC.len()].copy_from_slice(&rustscale_disco::MAGIC);
        let geneve_wg = relay::encode_geneve_wireguard(7, b"wg");
        assert!(DiscoIo::looks_like_disco(&disco));
        assert!(udp_batch_needs_scalar_handler(&disco));
        assert!(udp_batch_needs_scalar_handler(&geneve_wg));
        assert!(!udp_batch_needs_scalar_handler(b"\x07"));
        assert!(!udp_batch_needs_scalar_handler(b"ordinary-wireguard"));
        assert!(linux_batch_requires_scalar_handler([
            Some(b"ordinary-wireguard-before".as_slice()),
            Some(disco.as_slice()),
            Some(b"ordinary-wireguard-after".as_slice()),
            Some(geneve_wg.as_slice()),
        ]));
        assert!(!linux_batch_requires_scalar_handler([
            Some(b"ordinary-wireguard-before".as_slice()),
            Some(b"ordinary-wireguard-after".as_slice()),
        ]));
        assert!(linux_batch_requires_scalar_handler([None]));
        // `spawn_recv_tasks` handles the true branch by iterating the same
        // receive indexes in ascending order through `handle_udp_packet`;
        // ordinary packets therefore cannot leap over disco/Geneve control.
    }

    #[test]
    fn jumbo_pmtud_disco_packets_stay_on_the_sequential_path() {
        for length in [8 * 1024, 9 * 1024] {
            let mut disco = vec![0; length];
            disco[..rustscale_disco::MAGIC.len()].copy_from_slice(&rustscale_disco::MAGIC);
            assert!(DiscoIo::looks_like_disco(&disco));
            assert!(udp_batch_needs_scalar_handler(&disco));
            assert!(linux_batch_requires_scalar_handler([
                Some(b"ordinary-before".as_slice()),
                Some(disco.as_slice()),
                Some(b"ordinary-after".as_slice()),
            ]));
        }
    }

    #[test]
    fn linux_send_configuration_preserves_independent_fallbacks() {
        assert_eq!(
            LinuxUdpSendConfig::from_environment_presence(false, false),
            LinuxUdpSendConfig {
                use_batch: true,
                disable_udp_gso: false,
            }
        );
        assert_eq!(
            LinuxUdpSendConfig::from_environment_presence(false, true),
            LinuxUdpSendConfig {
                use_batch: true,
                disable_udp_gso: true,
            }
        );
        assert_eq!(
            LinuxUdpSendConfig::from_environment_presence(true, false),
            LinuxUdpSendConfig {
                use_batch: false,
                disable_udp_gso: true,
            }
        );
    }

    #[test]
    fn never_gso_equal_tail_reads_each_live_knob_update() {
        let knobs = rustscale_controlknobs::ControlKnobs::new();
        assert!(!never_gso_equal_tail(Some(&knobs)));
        knobs.apply(HashMap::from([(
            rustscale_tailcfg::NODE_ATTR_NEVER_GSO_EQUAL_TAIL.to_string(),
            "true".to_string(),
        )]));
        assert!(never_gso_equal_tail(Some(&knobs)));
        knobs.apply(HashMap::from([(
            rustscale_tailcfg::NODE_ATTR_NEVER_GSO_EQUAL_TAIL.to_string(),
            "false".to_string(),
        )]));
        assert!(!never_gso_equal_tail(Some(&knobs)));
    }

    #[test]
    fn linux_receive_defaults_to_batched_gro() {
        let config = LinuxUdpReceiveConfig::from_environment_presence(LinuxUdpReceiveEnvironment {
            disable_linux_udp_batch: false,
            _enable_linux_udp_batch: false,
            disable_udp_gro: false,
            _enable_udp_gro: false,
        });
        assert!(config.use_batch);
        assert!(!config.disable_udp_gro);
    }

    #[test]
    fn linux_receive_scalar_kill_switch_disables_batch_and_gro() {
        let config = LinuxUdpReceiveConfig::from_environment_presence(LinuxUdpReceiveEnvironment {
            disable_linux_udp_batch: true,
            _enable_linux_udp_batch: true,
            disable_udp_gro: false,
            _enable_udp_gro: true,
        });
        assert!(!config.use_batch);
        assert!(config.disable_udp_gro);
    }

    #[test]
    fn linux_receive_gro_kill_switch_overrides_legacy_gro_opt_in() {
        let config = LinuxUdpReceiveConfig::from_environment_presence(LinuxUdpReceiveEnvironment {
            disable_linux_udp_batch: false,
            _enable_linux_udp_batch: true,
            disable_udp_gro: true,
            _enable_udp_gro: true,
        });
        assert!(config.use_batch);
        assert!(config.disable_udp_gro);
    }

    #[test]
    fn linux_receive_legacy_opt_ins_remain_compatible_with_defaults() {
        let config = LinuxUdpReceiveConfig::from_environment_presence(LinuxUdpReceiveEnvironment {
            disable_linux_udp_batch: false,
            _enable_linux_udp_batch: true,
            disable_udp_gro: false,
            _enable_udp_gro: true,
        });
        assert!(config.use_batch);
        assert!(!config.disable_udp_gro);
    }

    #[test]
    fn direct_batch_keeps_known_sources_ordered_and_drops_unknown() {
        let a = NodePrivate::generate().public();
        let b = NodePrivate::generate().public();
        let a_addr: SocketAddr = "127.0.0.1:10001".parse().unwrap();
        let b_addr: SocketAddr = "127.0.0.1:10002".parse().unwrap();
        let unknown_addr: SocketAddr = "127.0.0.1:10003".parse().unwrap();
        let peers = HashMap::from([(a_addr, a.clone()), (b_addr, b.clone())]);
        let packets = [
            (b"a-first".to_vec(), a_addr),
            (b"unknown".to_vec(), unknown_addr),
            (b"b-only".to_vec(), b_addr),
            (b"a-last".to_vec(), a_addr),
        ];
        let mut endpoints = HashMap::new();
        let mut pending = Vec::new();
        let mut accounted = Vec::new();
        let mut noted = Vec::new();
        stage_linux_wg_datagrams(
            packets.iter().map(|(data, addr)| (data.as_slice(), *addr)),
            &peers,
            &mut endpoints,
            &mut pending,
            |peer, endpoint, now| {
                noted.push((peer.clone(), now));
                endpoint.note_recv_udp(now);
            },
            |udp4_bytes, udp6_bytes| accounted.push((udp4_bytes, udp6_bytes)),
        );
        assert_eq!(accounted, [(26, 0)], "sockstats sees every packet");
        assert_eq!(noted, [], "no endpoint means no activity callback");
        assert_eq!(
            pending
                .iter()
                .map(|datagram| (datagram.peer.clone(), datagram.data.as_ref().to_vec()))
                .collect::<Vec<_>>(),
            vec![
                (a.clone(), b"a-first".to_vec()),
                (b, b"b-only".to_vec()),
                (a, b"a-last".to_vec()),
            ]
        );
    }

    #[test]
    fn direct_128_same_source_stages_in_exact_order_with_one_endpoint_note() {
        let peer = NodePrivate::generate().public();
        let addr: SocketAddr = "127.0.0.1:10001".parse().unwrap();
        let peers = HashMap::from([(addr, peer.clone())]);
        let packets = (0..WG_RECEIVE_BATCH_MAX_PACKETS)
            .map(|index| (vec![index as u8], addr))
            .collect::<Vec<_>>();
        let mut endpoints = HashMap::from([(peer.clone(), endpoint(peer.clone()))]);
        let mut pending = Vec::new();
        let mut noted = Vec::new();
        let mut accounted = Vec::new();

        stage_linux_wg_datagrams(
            packets.iter().map(|(data, addr)| (data.as_slice(), *addr)),
            &peers,
            &mut endpoints,
            &mut pending,
            |peer, endpoint, now| {
                noted.push((peer.clone(), now));
                endpoint.note_recv_udp(now);
            },
            |udp4_bytes, udp6_bytes| accounted.push((udp4_bytes, udp6_bytes)),
        );

        assert_eq!(noted.len(), 1);
        assert_eq!(noted[0].0, peer);
        assert_eq!(accounted, [(WG_RECEIVE_BATCH_MAX_PACKETS, 0)]);
        assert_eq!(
            pending
                .into_iter()
                .map(|datagram| datagram.data)
                .collect::<Vec<_>>(),
            (0..WG_RECEIVE_BATCH_MAX_PACKETS)
                .map(|index| vec![index as u8])
                .collect::<Vec<_>>(),
        );
    }

    #[test]
    fn direct_source_runs_do_not_merge_across_an_intervening_address() {
        let a = NodePrivate::generate().public();
        let b = NodePrivate::generate().public();
        let a_addr: SocketAddr = "127.0.0.1:10001".parse().unwrap();
        let b_addr: SocketAddr = "127.0.0.1:10002".parse().unwrap();
        let peers = HashMap::from([(a_addr, a.clone()), (b_addr, b.clone())]);
        let packets = [
            (b"a-1".to_vec(), a_addr),
            (b"a-2".to_vec(), a_addr),
            (b"b-1".to_vec(), b_addr),
            (b"a-3".to_vec(), a_addr),
        ];
        let mut endpoints = HashMap::from([
            (a.clone(), endpoint(a.clone())),
            (b.clone(), endpoint(b.clone())),
        ]);
        let mut pending = Vec::new();
        let mut noted = Vec::new();

        stage_linux_wg_datagrams(
            packets.iter().map(|(data, addr)| (data.as_slice(), *addr)),
            &peers,
            &mut endpoints,
            &mut pending,
            |peer, endpoint, now| {
                noted.push((peer.clone(), now));
                endpoint.note_recv_udp(now);
            },
            |_, _| {},
        );

        assert_eq!(
            noted.iter().map(|(peer, _)| peer).collect::<Vec<_>>(),
            [&a, &b, &a],
        );
        assert!(
            noted.windows(2).all(|notes| notes[0].1 == notes[1].1),
            "all run activity uses one batch timestamp"
        );
        assert_eq!(
            pending
                .into_iter()
                .map(|datagram| datagram.data)
                .collect::<Vec<_>>(),
            vec![
                b"a-1".to_vec(),
                b"a-2".to_vec(),
                b"b-1".to_vec(),
                b"a-3".to_vec(),
            ],
        );
    }

    #[test]
    fn one_byte_07_stays_attached_to_mixed_reordered_peer_sources() {
        let a = NodePrivate::generate().public();
        let b = NodePrivate::generate().public();
        let a_addr: SocketAddr = "127.0.0.1:10001".parse().unwrap();
        let b_addr: SocketAddr = "127.0.0.1:10002".parse().unwrap();
        let peers = HashMap::from([(a_addr, a.clone()), (b_addr, b.clone())]);
        let packets = [
            (b"\x07".to_vec(), a_addr),
            (b"peer-b".to_vec(), b_addr),
            (b"\x07".to_vec(), a_addr),
        ];
        let mut pending = Vec::new();
        let mut accounted = Vec::new();

        stage_linux_wg_datagrams(
            packets.iter().map(|(data, addr)| (data.as_slice(), *addr)),
            &peers,
            &mut HashMap::new(),
            &mut pending,
            |_, _, _| {},
            |udp4_bytes, udp6_bytes| accounted.push((udp4_bytes, udp6_bytes)),
        );

        assert_eq!(accounted, [(8, 0)]);
        assert_eq!(
            pending
                .into_iter()
                .map(|datagram| (datagram.peer, datagram.data.as_ref().to_vec()))
                .collect::<Vec<_>>(),
            [
                (a.clone(), b"\x07".to_vec()),
                (b, b"peer-b".to_vec()),
                (a, b"\x07".to_vec()),
            ]
        );
    }

    #[test]
    fn direct_unknown_sources_are_dropped_but_bytes_are_counted() {
        let unknown4: SocketAddr = "127.0.0.1:10003".parse().unwrap();
        let unknown6: SocketAddr = "[::1]:10003".parse().unwrap();
        let packets = [(b"four".to_vec(), unknown4), (b"sixsix".to_vec(), unknown6)];
        let mut pending = Vec::new();
        let mut accounted = Vec::new();

        stage_linux_wg_datagrams(
            packets.iter().map(|(data, addr)| (data.as_slice(), *addr)),
            &HashMap::new(),
            &mut HashMap::new(),
            &mut pending,
            |_, _, _| panic!("unknown sources do not note endpoints"),
            |udp4_bytes, udp6_bytes| accounted.push((udp4_bytes, udp6_bytes)),
        );

        assert!(pending.is_empty());
        assert_eq!(accounted, [(4, 6)]);
    }

    #[test]
    fn direct_batch_aggregates_ipv4_and_ipv6_rx_bytes() {
        let v4: SocketAddr = "127.0.0.1:10004".parse().unwrap();
        let v6: SocketAddr = "[::1]:10004".parse().unwrap();
        let packets = [
            (b"one".to_vec(), v4),
            (b"twotwo".to_vec(), v6),
            (b"tri".to_vec(), v4),
        ];
        let mut totals = Vec::new();

        stage_linux_wg_datagrams(
            packets.iter().map(|(data, addr)| (data.as_slice(), *addr)),
            &HashMap::new(),
            &mut HashMap::new(),
            &mut Vec::new(),
            |_, _, _| unreachable!(),
            |udp4_bytes, udp6_bytes| totals.push((udp4_bytes, udp6_bytes)),
        );

        assert_eq!(totals, [(6, 6)]);
    }

    #[test]
    fn direct_empty_batch_has_no_endpoint_activity_or_bytes() {
        let mut noted = false;
        let mut totals = Vec::new();
        let mut pending = Vec::new();
        stage_linux_wg_datagrams(
            std::iter::empty(),
            &HashMap::new(),
            &mut HashMap::new(),
            &mut pending,
            |_, _, _| noted = true,
            |udp4_bytes, udp6_bytes| totals.push((udp4_bytes, udp6_bytes)),
        );

        assert!(!noted);
        assert!(pending.is_empty());
        assert_eq!(totals, [(0, 0)]);
    }

    #[tokio::test]
    async fn direct_128_packet_burst_is_one_ordered_receive_item() {
        let (sender, mut receiver) = mpsc::channel(WG_RECEIVE_PACKET_CAPACITY);
        let credits = Arc::new(Semaphore::new(WG_RECEIVE_PACKET_CAPACITY));
        let mut staged = pending(WG_RECEIVE_BATCH_MAX_PACKETS);
        publish_linux_wg_batch(&sender, &credits, &mut staged).await;

        assert!(staged.is_empty());
        assert_eq!(receiver.len(), 1, "burst occupies one channel item");
        assert_eq!(credits.available_permits(), 128);
        let batch = receiver.recv().await.expect("receive burst");
        assert_eq!(batch.len(), WG_RECEIVE_BATCH_MAX_PACKETS);
        let datagrams = batch.into_datagrams();
        assert_eq!(
            datagrams
                .iter()
                .map(|datagram| datagram.data.as_ref().to_vec())
                .collect::<Vec<_>>(),
            (0..WG_RECEIVE_BATCH_MAX_PACKETS)
                .map(|index| vec![index as u8])
                .collect::<Vec<_>>()
        );
        assert_eq!(
            credits.available_permits(),
            WG_RECEIVE_PACKET_CAPACITY,
            "test vectors are ordinary owned ciphertexts"
        );
        drop(datagrams);
        assert_eq!(credits.available_permits(), WG_RECEIVE_PACKET_CAPACITY);
    }

    #[tokio::test]
    async fn queued_direct_burst_bounds_derp_progress_under_sustained_direct_work() {
        let (sender, mut receiver) = mpsc::channel(WG_RECEIVE_PACKET_CAPACITY);
        let credits = Arc::new(Semaphore::new(WG_RECEIVE_PACKET_CAPACITY));
        let mut first = pending(WG_RECEIVE_BATCH_MAX_PACKETS);
        let mut second = pending(WG_RECEIVE_BATCH_MAX_PACKETS);
        publish_linux_wg_batch(&sender, &credits, &mut first).await;
        publish_linux_wg_batch(&sender, &credits, &mut second).await;
        assert_eq!(receiver.len(), 2, "256 packets are two, not 256, batches");
        assert_eq!(credits.available_permits(), 0);

        // A third direct burst is already waiting for its atomic 128 credits
        // when DERP arrives. This is the adverse case: the scalar cannot
        // overtake established receive order, but it must not be overtaken by
        // direct work that arrives after it.
        let queued_direct_sender = sender.clone();
        let queued_direct_credits = credits.clone();
        let queued_direct = tokio::spawn(async move {
            publish_wg_batch(
                &queued_direct_sender,
                &queued_direct_credits,
                pending(WG_RECEIVE_BATCH_MAX_PACKETS),
            )
            .await;
        });
        tokio::task::yield_now().await;

        let derp_sender = sender.clone();
        let derp_credits = credits.clone();
        let derp_peer = NodePrivate::generate().public();
        let derp = tokio::spawn(async move {
            publish_wg_batch(
                &derp_sender,
                &derp_credits,
                vec![WgDatagram {
                    peer: derp_peer,
                    data: b"derp".to_vec().into(),
                }],
            )
            .await;
        });
        tokio::task::yield_now().await;

        // This fourth burst models the sustained direct source. Tokio's fair
        // semaphore queues it after DERP, so it cannot extend DERP's wait.
        let sustained_direct_sender = sender.clone();
        let sustained_direct_credits = credits.clone();
        let sustained_direct = tokio::spawn(async move {
            publish_wg_batch(
                &sustained_direct_sender,
                &sustained_direct_credits,
                pending(WG_RECEIVE_BATCH_MAX_PACKETS),
            )
            .await;
        });
        tokio::task::yield_now().await;

        // Releasing the first queued batch admits the older direct waiter.
        // Releasing the second then admits DERP before the later direct work;
        // its progress is therefore bounded by the two batches that preceded
        // it at the packet-credit semaphore.
        drop(receiver.recv().await.expect("first direct batch"));
        tokio::time::timeout(std::time::Duration::from_secs(1), queued_direct)
            .await
            .expect("queued direct burst receives its preceding credits")
            .expect("queued direct publisher task");
        assert_eq!(credits.available_permits(), 0);

        drop(receiver.recv().await.expect("second direct batch"));
        tokio::time::timeout(std::time::Duration::from_secs(1), derp)
            .await
            .expect("DERP packet progresses behind only the queued direct burst")
            .expect("DERP publisher task");

        let third = receiver.recv().await.expect("queued direct batch");
        assert_eq!(third.len(), WG_RECEIVE_BATCH_MAX_PACKETS);
        drop(third);
        let derp = receiver.recv().await.expect("DERP receive item");
        assert_eq!(derp.len(), 1);
        let derp = derp.into_datagrams();
        assert_eq!(derp[0].data, b"derp");
        drop(derp);

        // The post-DERP direct burst may now acquire and publish, but it
        // cannot have delayed the scalar publication above.
        tokio::time::timeout(std::time::Duration::from_secs(1), sustained_direct)
            .await
            .expect("sustained direct publisher resumes after DERP")
            .expect("sustained direct publisher task");
        drop(receiver.recv().await.expect("post-DERP direct batch"));
        assert_eq!(credits.available_permits(), WG_RECEIVE_PACKET_CAPACITY);
    }

    #[tokio::test]
    async fn receive_batch_permits_return_after_consume_drop_cancel_and_close() {
        let (sender, mut receiver) = mpsc::channel(WG_RECEIVE_PACKET_CAPACITY);
        let credits = Arc::new(Semaphore::new(WG_RECEIVE_PACKET_CAPACITY));
        let mut staged = pending(3);
        publish_linux_wg_batch(&sender, &credits, &mut staged).await;
        assert_eq!(credits.available_permits(), 253);
        let consumed = receiver.recv().await.expect("batch");
        let datagrams = consumed.into_datagrams();
        assert_eq!(
            credits.available_permits(),
            WG_RECEIVE_PACKET_CAPACITY,
            "ordinary Vec ciphertexts do not need a retained pool credit"
        );
        drop(datagrams);
        assert_eq!(credits.available_permits(), WG_RECEIVE_PACKET_CAPACITY);

        let mut staged = pending(4);
        publish_linux_wg_batch(&sender, &credits, &mut staged).await;
        assert_eq!(credits.available_permits(), 252);
        drop(receiver.recv().await.expect("batch to drop"));
        assert_eq!(credits.available_permits(), WG_RECEIVE_PACKET_CAPACITY);

        let mut full = pending(WG_RECEIVE_BATCH_MAX_PACKETS);
        publish_linux_wg_batch(&sender, &credits, &mut full).await;
        let mut full = pending(WG_RECEIVE_BATCH_MAX_PACKETS);
        publish_linux_wg_batch(&sender, &credits, &mut full).await;
        let cancelled_sender = sender.clone();
        let cancelled_credits = credits.clone();
        let cancelled = tokio::spawn(async move {
            publish_wg_batch(&cancelled_sender, &cancelled_credits, pending(1)).await;
        });
        tokio::task::yield_now().await;
        cancelled.abort();
        let _ = cancelled.await;
        assert_eq!(
            credits.available_permits(),
            0,
            "cancelled waiter owns no credit"
        );
        drop(receiver);
        assert_eq!(credits.available_permits(), WG_RECEIVE_PACKET_CAPACITY);

        let (closed_sender, closed_receiver) = mpsc::channel(WG_RECEIVE_PACKET_CAPACITY);
        drop(closed_receiver);
        publish_wg_batch(&closed_sender, &credits, pending(1)).await;
        assert_eq!(credits.available_permits(), WG_RECEIVE_PACKET_CAPACITY);
    }
}

#[cfg(test)]
mod tests;
