//! Userspace TCP/IP stack for rustscale, built on smoltcp.
//!
//! Bridges plaintext IP packets from the WireGuard data plane
//! ([`rustscale_wg::WgTunn`]) into a [`smoltcp::iface::Interface`] via a custom
//! in-memory [`Device`] impl. Outbound smoltcp packets are delivered to the
//! caller for WireGuard encapsulation.
//!
//! # Architecture
//!
//! A single background poll-loop task owns the smoltcp `Interface`,
//! `SocketSet`, and `Device`. The public API communicates with it via a
//! command channel. Each TCP connection is bridged to an async
//! [`NetstackStream`] through a pair of `mpsc` channels: the poll loop reads
//! from the smoltcp socket and sends data to the stream's rx channel; it
//! receives data from the stream's tx channel and writes to the socket.
//!
//! # API
//!
//! - [`Netstack::new`] — create a netstack bound to a tailnet IPv4 address.
//! - [`Netstack::push_rx`] — feed a decapsulated IP packet from WireGuard.
//! - [`Netstack::pop_tx`] — drain an outbound IP packet for WireGuard encapsulation.
//! - [`Netstack::listen`] — accept incoming TCP connections on a port.
//! - [`Netstack::dial`] — connect to a remote `ip:port`.
//! - [`NetstackStream`] — an accepted/dialed connection implementing
//!   [`tokio::io::AsyncRead`] + [`tokio::io::AsyncWrite`].

#![forbid(unsafe_code)]

mod device;

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp::{self, State};
use smoltcp::socket::udp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot, Notify};
use tokio_util::sync::PollSender;

use bytes::Bytes;
use rustscale_key::NodePublic;
use rustscale_packet::{Parsed, TCPFlag, TCP};

use device::LoopbackDevice;

/// Default MTU (Tailscale tailnet MTU is 1280).
pub const DEFAULT_MTU: usize = 1280;

/// TCP send/recv buffer size. Tuned up from 65 KB to 256 KB so the socket
/// can absorb more in-flight data per ACK round-trip, raising throughput
/// before backpressure kicks in. (Go's gVisor netstack uses similar or
/// larger defaults.)
const TCP_BUF: usize = 256 * 1024;

/// Number of passive listening sockets maintained per port. Each smoltcp
/// TCP socket can only handle one connection at a time (Listen →
/// SynReceived → Established), so a single listening socket drops SYNs that
/// arrive while a handshake is in progress. Maintaining a pool of N
/// listening sockets allows N simultaneous handshakes — the same role as
/// the OS `listen(backlog)` parameter.
const LISTEN_BACKLOG: usize = 32;

/// Depth of the accept channel between the poll loop and the application's
/// `Listener::accept()` call. Large enough to buffer a burst of accepted
/// connections without blocking the poll loop.
const ACCEPT_CHANNEL_DEPTH: usize = 64;

/// Number of packets a UDP socket can buffer (in each direction).
const UDP_PACKET_COUNT: usize = 64;

/// Total payload bytes a UDP socket can buffer (in each direction).
const UDP_PAYLOAD_SIZE: usize = 64 * 1024;

/// Depth of the channel between the poll loop and the application's
/// `UdpListener::recv_from()` / `send_to()` calls.
const UDP_CHANNEL_DEPTH: usize = 64;

/// Ephemeral port range for UDP listeners requesting port 0, matching
/// Tailscale's tsnet range (tsnet.go:2013-2014).
const UDP_EPHEMERAL_MIN: u16 = 10002;
const UDP_EPHEMERAL_MAX: u16 = 19999;

/// Errors from netstack operations.
#[derive(Debug, thiserror::Error)]
pub enum NetstackError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("connection refused")]
    ConnectionRefused,
    #[error("connection reset")]
    ConnectionReset,
    #[error("connection closed")]
    ConnectionClosed,
    #[error("listen failed: {0}")]
    ListenFailed(String),
    #[error("dial failed: {0}")]
    DialFailed(String),
    #[error("udp listen failed: {0}")]
    UdpListenFailed(String),
    #[error("tls error: {0}")]
    Tls(String),
    #[error("netstack is shutting down")]
    ShuttingDown,
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A userspace TCP/IP stack bridging WireGuard plaintext to smoltcp.
pub struct Netstack {
    addr: Ipv4Addr,
    rx_queue: Arc<std::sync::Mutex<VecDeque<Vec<u8>>>>,
    tx_queue: Arc<std::sync::Mutex<VecDeque<Vec<u8>>>>,
    inbound_flows: Arc<std::sync::Mutex<HashMap<TcpFlow, NodePublic>>>,
    cmd_tx: mpsc::Sender<Command>,
    notify: Arc<Notify>,
    tx_notify: Arc<Notify>,
}

/// A TCP listener accepting incoming tailnet connections.
pub struct Listener {
    accept_rx: mpsc::Receiver<Result<NetstackStream, NetstackError>>,
    cmd_tx: mpsc::Sender<Command>,
    key: (IpAddr, u16),
    close_on_drop: bool,
}

impl Listener {
    /// Accept the next incoming connection.
    pub async fn accept(&mut self) -> Result<NetstackStream, NetstackError> {
        self.accept_rx
            .recv()
            .await
            .ok_or(NetstackError::ShuttingDown)?
    }

    /// Consume the listener and return the underlying accept channel
    /// receiver. Used by [`ServiceListener`](crate::service::ServiceListener)
    /// to merge multiple VIP listeners into a single accept stream.
    pub fn into_receiver(mut self) -> mpsc::Receiver<Result<NetstackStream, NetstackError>> {
        self.close_on_drop = false;
        let (_tx, rx) = mpsc::channel(1);
        std::mem::replace(&mut self.accept_rx, rx)
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        if self.close_on_drop {
            let _ = self.cmd_tx.try_send(Command::CloseTcp { key: self.key });
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct TcpFlow {
    remote: SocketAddr,
    local: SocketAddr,
}

/// A received UDP packet.
#[derive(Debug)]
pub struct UdpPacket {
    /// The packet payload.
    pub data: Bytes,
    /// The source address.
    pub src: SocketAddr,
}

/// A UDP listener that receives datagrams on the tailnet.
///
/// Created by [`Netstack::listen_packet`]. Incoming packets are dequeued via
/// [`recv_from`](Self::recv_from); outbound packets are sent via
/// [`send_to`](Self::send_to). Dropping the listener unregisters the
/// underlying smoltcp socket.
pub struct UdpListener {
    recv_rx: mpsc::Receiver<UdpPacket>,
    send_tx: mpsc::Sender<OutboundUdpPacket>,
    local_addr: SocketAddr,
    cmd_tx: mpsc::Sender<Command>,
    key: (IpAddr, u16),
}

impl UdpListener {
    /// Receive the next inbound UDP packet, returning the payload and source.
    pub async fn recv_from(&mut self) -> Result<(Bytes, SocketAddr), NetstackError> {
        self.recv_rx
            .recv()
            .await
            .map(|p| (p.data, p.src))
            .ok_or(NetstackError::ShuttingDown)
    }

    /// Send a UDP packet to `dst` through the tailnet.
    pub async fn send_to(&self, data: &[u8], dst: SocketAddr) -> Result<(), NetstackError> {
        self.send_tx
            .send(OutboundUdpPacket {
                data: data.to_vec(),
                dst,
            })
            .await
            .map_err(|_| NetstackError::ShuttingDown)
    }

    /// The local address the listener is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Drop for UdpListener {
    fn drop(&mut self) {
        let _ = self.cmd_tx.try_send(Command::CloseUdp { key: self.key });
    }
}

/// A bidirectional TCP stream over the tailnet, implementing
/// [`AsyncRead`] + [`AsyncWrite`].
pub struct NetstackStream {
    rx: mpsc::Receiver<Bytes>,
    tx: PollSender<Bytes>,
    read_buf: Bytes,
    remote_closed: bool,
    notify: Arc<Notify>,
    remote_addr: Option<SocketAddr>,
    peer_node_key: Option<NodePublic>,
}

impl NetstackStream {
    fn new(
        rx: mpsc::Receiver<Bytes>,
        tx: PollSender<Bytes>,
        notify: Arc<Notify>,
        remote_addr: Option<SocketAddr>,
        peer_node_key: Option<NodePublic>,
    ) -> Self {
        Self {
            rx,
            tx,
            read_buf: Bytes::new(),
            remote_closed: false,
            notify,
            remote_addr,
            peer_node_key,
        }
    }

    /// The remote peer's socket address, if known. Populated on accept
    /// (from the smoltcp socket's remote endpoint) and dial (from the
    /// requested destination). Returns `None` if the address is unavailable.
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }

    /// WireGuard node key that authenticated the inbound TCP flow. Outbound
    /// dials and legacy packets injected without provenance return `None`.
    pub fn peer_node_key(&self) -> Option<&NodePublic> {
        self.peer_node_key.as_ref()
    }
}

impl AsyncRead for NetstackStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if !self.read_buf.is_empty() {
            let n = self.read_buf.len().min(buf.remaining());
            buf.put_slice(&self.read_buf[..n]);
            self.read_buf = self.read_buf.slice(n..);
            return std::task::Poll::Ready(Ok(()));
        }
        if self.remote_closed {
            return std::task::Poll::Ready(Ok(()));
        }
        match self.rx.poll_recv(cx) {
            std::task::Poll::Ready(Some(data)) => {
                if data.is_empty() {
                    self.remote_closed = true;
                    return std::task::Poll::Ready(Ok(()));
                }
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    self.read_buf = data.slice(n..);
                }
                self.notify.notify_one();
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(None) => {
                self.remote_closed = true;
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl AsyncWrite for NetstackStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return std::task::Poll::Ready(Ok(0));
        }
        let chunk_len = buf.len().min(TCP_BUF);
        let was_empty = self
            .tx
            .get_ref()
            .is_some_and(|s| s.capacity() == s.max_capacity());
        match self.tx.poll_reserve(cx) {
            std::task::Poll::Ready(Ok(())) => {
                let _ = self.tx.send_item(Bytes::copy_from_slice(&buf[..chunk_len]));
                if was_empty {
                    self.notify.notify_one();
                }
                std::task::Poll::Ready(Ok(chunk_len))
            }
            std::task::Poll::Ready(Err(_)) => std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "connection closed",
            ))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if let Some(sender) = self.tx.get_ref() {
            let _ = sender.try_send(Bytes::new());
        }
        std::task::Poll::Ready(Ok(()))
    }
}

impl Drop for NetstackStream {
    fn drop(&mut self) {
        if let Some(sender) = self.tx.get_ref() {
            let _ = sender.try_send(Bytes::new());
        }
    }
}

// ---------------------------------------------------------------------------
// Netstack implementation
// ---------------------------------------------------------------------------

impl Netstack {
    /// Create a new netstack bound to `addr` (the node's tailnet IPv4).
    ///
    /// Spawns a background poll-loop task that drives the smoltcp interface.
    pub fn new(addr: Ipv4Addr, mtu: usize) -> Self {
        let rx_queue = Arc::new(std::sync::Mutex::new(VecDeque::new()));
        let tx_queue = Arc::new(std::sync::Mutex::new(VecDeque::new()));
        let notify = Arc::new(Notify::new());
        let tx_notify = Arc::new(Notify::new());
        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        let inbound_flows = Arc::new(std::sync::Mutex::new(HashMap::new()));

        let device =
            LoopbackDevice::new(rx_queue.clone(), tx_queue.clone(), mtu, tx_notify.clone());
        tokio::spawn(poll_loop(
            addr,
            device,
            cmd_rx,
            notify.clone(),
            inbound_flows.clone(),
        ));

        Self {
            addr,
            rx_queue,
            tx_queue,
            inbound_flows,
            cmd_tx,
            notify,
            tx_notify,
        }
    }

    /// Feed a decapsulated plaintext IP packet without peer provenance.
    /// Production WireGuard delivery should use [`Self::push_rx_from`].
    pub fn push_rx(&self, packet: Vec<u8>) {
        self.push_rx_inner(packet, None);
    }

    /// Feed a decapsulated packet together with the WireGuard key that opened
    /// it. TCP SYN provenance is attached to the resulting accepted stream.
    pub fn push_rx_from(&self, packet: Vec<u8>, peer: NodePublic) {
        self.push_rx_inner(packet, Some(peer));
    }

    fn push_rx_inner(&self, packet: Vec<u8>, peer: Option<NodePublic>) {
        if let Some(peer) = peer {
            let parsed = Parsed::decode(&packet);
            if parsed.ip_proto == TCP && parsed.tcp_flags.contains(TCPFlag::SYN) {
                let flow = TcpFlow {
                    remote: SocketAddr::new(parsed.src, parsed.src_port),
                    local: SocketAddr::new(parsed.dst, parsed.dst_port),
                };
                if let Ok(mut flows) = self.inbound_flows.lock() {
                    if flows.len() >= 4096 && !flows.contains_key(&flow) {
                        flows.clear();
                    }
                    flows.insert(flow, peer);
                }
            }
        }
        if let Ok(mut queue) = self.rx_queue.lock() {
            queue.push_back(packet);
        }
        self.notify.notify_one();
    }

    /// Drain one outbound IP packet (for WireGuard encapsulation).
    pub fn pop_tx(&self) -> Option<Vec<u8>> {
        self.tx_queue.lock().ok()?.pop_front()
    }

    /// Whether outbound packets remain after a bounded pump drain.
    ///
    /// This is a predicate, not a wakeup mechanism: callers use it to avoid
    /// sleeping after a `Notify` permit has already been consumed.
    pub fn has_tx_packets(&self) -> bool {
        self.tx_queue.lock().is_ok_and(|queue| !queue.is_empty())
    }

    #[cfg(test)]
    pub(crate) fn push_tx_for_test(&self, packet: Vec<u8>) {
        self.tx_queue
            .lock()
            .expect("netstack tx queue lock")
            .push_back(packet);
        self.tx_notify.notify_one();
    }

    /// Start listening for incoming TCP connections on `port` bound to the
    /// netstack's primary tailnet IPv4 address.
    pub async fn listen(&self, port: u16) -> Result<Listener, NetstackError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::Listen {
                port,
                reply: reply_tx,
            })
            .await
            .map_err(|_| NetstackError::ShuttingDown)?;
        let accept_rx = reply_rx.await.map_err(|_| NetstackError::ShuttingDown)??;
        Ok(Listener {
            accept_rx,
            cmd_tx: self.cmd_tx.clone(),
            key: (IpAddr::V4(self.addr), port),
            close_on_drop: true,
        })
    }

    /// Start listening for incoming TCP connections on a specific local `addr`
    /// and `port`. Used by service listeners that bind to a VIP address
    /// distinct from the node's primary tailnet IP. The address must first be
    /// added via [`Netstack::add_addr`].
    pub async fn listen_on(&self, addr: IpAddr, port: u16) -> Result<Listener, NetstackError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::ListenOn {
                addr,
                port,
                reply: reply_tx,
            })
            .await
            .map_err(|_| NetstackError::ShuttingDown)?;
        let accept_rx = reply_rx.await.map_err(|_| NetstackError::ShuttingDown)??;
        Ok(Listener {
            accept_rx,
            cmd_tx: self.cmd_tx.clone(),
            key: (addr, port),
            close_on_drop: true,
        })
    }

    /// Add an additional IP address to the smoltcp interface. Required before
    /// [`Netstack::listen_on`] can accept connections addressed to this IP.
    /// Currently only IPv4 is supported; IPv6 returns an error.
    pub async fn add_addr(&self, addr: IpAddr) -> Result<(), NetstackError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::AddAddr {
                addr,
                reply: reply_tx,
            })
            .await
            .map_err(|_| NetstackError::ShuttingDown)?;
        reply_rx.await.map_err(|_| NetstackError::ShuttingDown)?
    }

    /// Dial a remote `ip:port` over the tailnet.
    pub async fn dial(&self, remote: SocketAddr) -> Result<NetstackStream, NetstackError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::Dial {
                remote,
                reply: reply_tx,
            })
            .await
            .map_err(|_| NetstackError::ShuttingDown)?;
        reply_rx.await.map_err(|_| NetstackError::ShuttingDown)?
    }

    /// Start listening for UDP datagrams on `addr:port`.
    ///
    /// If `port` is 0, an ephemeral port is allocated from the range
    /// 10002–19999 (matching Tailscale's tsnet ephemeral range).
    pub async fn listen_packet(
        &self,
        addr: IpAddr,
        port: u16,
    ) -> Result<UdpListener, NetstackError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::ListenPacket {
                addr,
                port,
                reply: reply_tx,
            })
            .await
            .map_err(|_| NetstackError::ShuttingDown)?;
        let parts = reply_rx.await.map_err(|_| NetstackError::ShuttingDown)??;
        Ok(UdpListener {
            recv_rx: parts.recv_rx,
            send_tx: parts.send_tx,
            local_addr: parts.local_addr,
            cmd_tx: self.cmd_tx.clone(),
            key: parts.key,
        })
    }

    /// Wake the poll loop (e.g. after pushing rx packets from a sync context).
    pub fn wake(&self) {
        self.notify.notify_one();
    }

    /// Returns the notify handle that fires when smoltcp produces outbound
    /// packets, so the data-plane pump can wake immediately instead of polling
    /// on a fixed interval.
    pub fn tx_notify(&self) -> Arc<Notify> {
        self.tx_notify.clone()
    }
}

// ---------------------------------------------------------------------------
// Poll loop internals
// ---------------------------------------------------------------------------

/// Command from the public API to the poll loop.
enum Command {
    Listen {
        port: u16,
        reply: oneshot::Sender<
            Result<mpsc::Receiver<Result<NetstackStream, NetstackError>>, NetstackError>,
        >,
    },
    ListenOn {
        addr: IpAddr,
        port: u16,
        reply: oneshot::Sender<
            Result<mpsc::Receiver<Result<NetstackStream, NetstackError>>, NetstackError>,
        >,
    },
    AddAddr {
        addr: IpAddr,
        reply: oneshot::Sender<Result<(), NetstackError>>,
    },
    Dial {
        remote: SocketAddr,
        reply: oneshot::Sender<Result<NetstackStream, NetstackError>>,
    },
    ListenPacket {
        addr: IpAddr,
        port: u16,
        reply: oneshot::Sender<Result<UdpListenerParts, NetstackError>>,
    },
    CloseUdp {
        key: (IpAddr, u16),
    },
    CloseTcp {
        key: (IpAddr, u16),
    },
}

/// State for an established connection, held inside the poll loop.
struct ConnState {
    app_tx: mpsc::Sender<Bytes>,
    app_rx: mpsc::Receiver<Bytes>,
    pending_write: Vec<u8>,
}

/// A TCP listener's socket backlog + accept channel sender.
struct ListenerEntry {
    /// Pool of passive listening sockets. Each can accept one connection
    /// (Listen → SynReceived → Established). When one transitions to
    /// Established it's removed from the pool and re-added as a connection;
    /// a fresh listening socket takes its place, maintaining the backlog
    /// depth.
    handles: Vec<SocketHandle>,
    /// Delivers accepted connections to the application's `Listener`.
    accept_tx: mpsc::Sender<Result<NetstackStream, NetstackError>>,
}

/// A pending dial awaiting connection establishment.
struct PendingDial {
    reply: oneshot::Sender<Result<NetstackStream, NetstackError>>,
    remote: SocketAddr,
}

/// Outbound UDP packet sent from `UdpListener::send_to` to the poll loop.
struct OutboundUdpPacket {
    data: Vec<u8>,
    dst: SocketAddr,
}

/// Channels and metadata returned to `Netstack::listen_packet` so it can
/// assemble a `UdpListener` (which also needs the command sender for Drop).
struct UdpListenerParts {
    recv_rx: mpsc::Receiver<UdpPacket>,
    send_tx: mpsc::Sender<OutboundUdpPacket>,
    local_addr: SocketAddr,
    key: (IpAddr, u16),
}

/// Per-socket state held by the poll loop for a bound UDP listener.
struct UdpSocketState {
    handle: SocketHandle,
    recv_tx: mpsc::Sender<UdpPacket>,
    send_rx: mpsc::Receiver<OutboundUdpPacket>,
}

/// Create a smoltcp TCP socket with Vec-backed buffers.
fn new_tcp_socket() -> tcp::Socket<'static> {
    let rx = tcp::SocketBuffer::new(vec![0u8; TCP_BUF]);
    let tx = tcp::SocketBuffer::new(vec![0u8; TCP_BUF]);
    tcp::Socket::new(rx, tx)
}

/// Create a smoltcp UDP socket with Vec-backed packet buffers.
fn new_udp_socket() -> udp::Socket<'static> {
    let rx_meta: Vec<udp::PacketMetadata> = (0..UDP_PACKET_COUNT)
        .map(|_| udp::PacketMetadata::EMPTY)
        .collect();
    let tx_meta: Vec<udp::PacketMetadata> = (0..UDP_PACKET_COUNT)
        .map(|_| udp::PacketMetadata::EMPTY)
        .collect();
    let rx_buffer = udp::PacketBuffer::new(rx_meta, vec![0u8; UDP_PAYLOAD_SIZE]);
    let tx_buffer = udp::PacketBuffer::new(tx_meta, vec![0u8; UDP_PAYLOAD_SIZE]);
    udp::Socket::new(rx_buffer, tx_buffer)
}

/// Allocate an ephemeral UDP port from the 10002–19999 range, skipping
/// any already in `allocated`.
fn allocate_ephemeral_udp_port(allocated: &HashSet<u16>) -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(UDP_EPHEMERAL_MIN);
    loop {
        let p = NEXT.fetch_add(1, Ordering::Relaxed);
        if !(UDP_EPHEMERAL_MIN..=UDP_EPHEMERAL_MAX).contains(&p) {
            NEXT.store(UDP_EPHEMERAL_MIN, Ordering::Relaxed);
            continue;
        }
        if !allocated.contains(&p) {
            return p;
        }
    }
}

/// Simple monotonic ephemeral port allocator.
fn ephemeral_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(49152);
    let p = NEXT.fetch_add(1, Ordering::Relaxed);
    if p < 49152 {
        NEXT.store(49152, Ordering::Relaxed);
        49152
    } else {
        p
    }
}

/// Convert an Ipv4Addr to a smoltcp IpAddress.
fn to_smoltcp_v4(addr: Ipv4Addr) -> IpAddress {
    IpAddress::v4(
        addr.octets()[0],
        addr.octets()[1],
        addr.octets()[2],
        addr.octets()[3],
    )
}

/// Create the channel pair + stream for a new connection.
/// Returns (stream, ConnState).
fn make_stream_and_conn(
    notify: Arc<Notify>,
    remote_addr: Option<SocketAddr>,
    peer_node_key: Option<NodePublic>,
) -> (NetstackStream, ConnState) {
    let (app_tx, stream_rx) = mpsc::channel(64);
    let (stream_tx, app_rx) = mpsc::channel(64);
    let poll_sender = PollSender::new(stream_tx);
    let stream = NetstackStream::new(stream_rx, poll_sender, notify, remote_addr, peer_node_key);
    let conn = ConnState {
        app_tx,
        app_rx,
        pending_write: Vec::new(),
    };
    (stream, conn)
}

/// The poll loop task.
async fn poll_loop(
    addr: Ipv4Addr,
    mut device: LoopbackDevice,
    mut cmd_rx: mpsc::Receiver<Command>,
    notify: Arc<Notify>,
    inbound_flows: Arc<std::sync::Mutex<HashMap<TcpFlow, NodePublic>>>,
) {
    let start = std::time::Instant::now();
    let smol_now = || SmolInstant::from_millis(start.elapsed().as_millis() as i64);

    let mut config = smoltcp::iface::Config::new(HardwareAddress::Ip);
    config.random_seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0xdead_beef, |d| d.as_nanos() as u64);
    let mut iface = Interface::new(config, &mut device, smol_now());
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(to_smoltcp_v4(addr), 32));
    });

    let mut sockets: SocketSet<'static> = SocketSet::new(vec![]);
    let mut conns: HashMap<SocketHandle, ConnState> = HashMap::new();
    let mut pending_dials: HashMap<SocketHandle, PendingDial> = HashMap::new();
    // (ip, port) -> (listener_socket_handle, accept_sender)
    let mut listeners: HashMap<(IpAddr, u16), ListenerEntry> = HashMap::new();
    // UDP listener state: (ip, port) -> UdpSocketState
    let mut udp_sockets: HashMap<(IpAddr, u16), UdpSocketState> = HashMap::new();
    // Track allocated ephemeral UDP ports to avoid collisions.
    let mut udp_allocated_ports: HashSet<u16> = HashSet::new();

    let sleep = tokio::time::sleep(std::time::Duration::from_secs(1));
    tokio::pin!(sleep);

    loop {
        let fallback = match iface.poll_delay(smol_now(), &sockets) {
            Some(d) => {
                let micros = d.total_micros();
                std::time::Duration::from_micros(micros.max(1))
            }
            None => std::time::Duration::from_secs(1),
        };
        sleep.as_mut().reset(tokio::time::Instant::now() + fallback);

        tokio::select! {
            () = &mut sleep => {}
            () = notify.notified() => {}
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(Command::Listen { port, reply }) => {
                        let result = do_listen(&mut sockets, &mut listeners, IpAddr::V4(addr), port);
                        let _ = reply.send(result);
                    }
                    Some(Command::ListenOn { addr: listen_addr, port, reply }) => {
                        let result = do_listen(&mut sockets, &mut listeners, listen_addr, port);
                        let _ = reply.send(result);
                    }
                    Some(Command::AddAddr { addr: add_addr, reply }) => {
                        let result = do_add_addr(&mut iface, add_addr);
                        let _ = reply.send(result);
                    }
                    Some(Command::Dial { remote, reply }) => {
                        do_dial(&mut iface, &mut sockets, &mut pending_dials, addr, remote, reply);
                    }
                    Some(Command::ListenPacket { addr: bind_addr, port, reply }) => {
                        let result = do_listen_packet(
                            &mut sockets,
                            &mut udp_sockets,
                            &mut udp_allocated_ports,
                            bind_addr,
                            port,
                        );
                        let _ = reply.send(result);
                    }
                    Some(Command::CloseUdp { key }) => {
                        if let Some(state) = udp_sockets.remove(&key) {
                            let _ = sockets.remove(state.handle);
                        }
                        udp_allocated_ports.remove(&key.1);
                    }
                    Some(Command::CloseTcp { key }) => {
                        if let Some(entry) = listeners.remove(&key) {
                            for handle in entry.handles {
                                let _ = sockets.remove(handle);
                            }
                        }
                    }
                    None => break,
                }
            }
        }

        // Poll smoltcp.
        let now = smol_now();
        let _ = iface.poll(now, &mut device, &mut sockets);

        // Pass 1: process listeners (accept new connections + replenish
        // backlog). Each listening socket can accept exactly one connection
        // (Listen → SynReceived → Established). We scan all sockets in each
        // listener's backlog pool, accept any that reached Established, and
        // replace them with fresh listening sockets so the backlog depth is
        // maintained. Dead sockets (failed handshakes, timed out) are also
        // replaced.
        {
            let listener_keys: Vec<(IpAddr, u16)> = listeners.keys().copied().collect();
            for key in listener_keys {
                let (listen_ip, port) = key;
                let smol_addr = match listen_ip {
                    IpAddr::V4(v4) => to_smoltcp_v4(v4),
                    IpAddr::V6(_) => continue,
                };
                let endpoint = IpListenEndpoint::from((smol_addr, port));

                // Collect handles to process (Established or dead).
                let mut to_accept: Vec<SocketHandle> = Vec::new();
                let mut to_replace: Vec<SocketHandle> = Vec::new();
                if let Some(entry) = listeners.get(&key) {
                    for &h in &entry.handles {
                        let state = sockets.get::<tcp::Socket>(h).state();
                        match state {
                            State::Established => to_accept.push(h),
                            State::Closed | State::TimeWait => to_replace.push(h),
                            _ => {}
                        }
                    }
                }

                // Accept established connections. Skip if the accept channel
                // is full — leave the socket in the pool for the next cycle
                // so the TCP stack applies flow control to the sender.
                for lh in to_accept {
                    let can_accept = listeners
                        .get(&key)
                        .is_some_and(|e| e.accept_tx.capacity() > 0);
                    if !can_accept {
                        continue;
                    }

                    // Remove from the backlog pool.
                    if let Some(entry) = listeners.get_mut(&key) {
                        entry.handles.retain(|&h| h != lh);
                    }

                    // Move the accepted socket into the connection map.
                    let remote_addr =
                        sockets
                            .get::<tcp::Socket>(lh)
                            .remote_endpoint()
                            .and_then(|ep| match ep.addr {
                                IpAddress::Ipv4(v4) => {
                                    Some(SocketAddr::new(IpAddr::V4(v4), ep.port))
                                }
                                #[allow(unreachable_patterns)]
                                _ => None,
                            });
                    let accepted = sockets.remove(lh);
                    let conn_handle = sockets.add(accepted);
                    let peer_node_key = remote_addr.and_then(|remote| {
                        inbound_flows.lock().ok()?.remove(&TcpFlow {
                            remote,
                            local: SocketAddr::new(listen_ip, port),
                        })
                    });
                    let (stream, conn) =
                        make_stream_and_conn(notify.clone(), remote_addr, peer_node_key);
                    conns.insert(conn_handle, conn);

                    if let Some(entry) = listeners.get(&key) {
                        let _ = entry.accept_tx.try_send(Ok(stream));
                    }

                    // Replenish the backlog with a fresh listening socket.
                    let mut fresh = new_tcp_socket();
                    let _ = fresh.listen(endpoint);
                    let fresh_handle = sockets.add(fresh);
                    if let Some(entry) = listeners.get_mut(&key) {
                        entry.handles.push(fresh_handle);
                    }
                }

                // Replace dead listening sockets (failed handshakes, etc.).
                for lh in to_replace {
                    if let Some(entry) = listeners.get_mut(&key) {
                        entry.handles.retain(|&h| h != lh);
                    }
                    let _ = sockets.remove(lh);

                    let mut fresh = new_tcp_socket();
                    let _ = fresh.listen(endpoint);
                    let fresh_handle = sockets.add(fresh);
                    if let Some(entry) = listeners.get_mut(&key) {
                        entry.handles.push(fresh_handle);
                    }
                }
            }
        }

        // Pass 2: process pending dials.
        let dial_handles: Vec<SocketHandle> = pending_dials.keys().copied().collect();
        for handle in dial_handles {
            let state = sockets.get::<tcp::Socket>(handle).state();
            match state {
                State::Established => {
                    let pd = pending_dials.remove(&handle);
                    if let Some(pd) = pd {
                        let (stream, conn) =
                            make_stream_and_conn(notify.clone(), Some(pd.remote), None);
                        conns.insert(handle, conn);
                        let _ = pd.reply.send(Ok(stream));
                    }
                }
                State::Closed | State::TimeWait => {
                    let pd = pending_dials.remove(&handle);
                    if let Some(pd) = pd {
                        let _ = pd.reply.send(Err(NetstackError::ConnectionRefused));
                    }
                    let _ = sockets.remove(handle);
                }
                _ => {}
            }
        }

        // Pass 3: pump data for established connections.
        let conn_handles: Vec<SocketHandle> = conns.keys().copied().collect();
        let mut did_work = false;
        for handle in conn_handles {
            if pump_connection(&mut sockets, handle, &mut conns) {
                did_work = true;
            }
        }
        // Flush any TCP segments queued by pump_connection without a full loop
        // iteration. Calling iface.poll() directly avoids a notify→select!
        // round-trip that would otherwise add latency and hurt throughput.
        if did_work {
            iface.poll(smol_now(), &mut device, &mut sockets);
        }

        // Pass 4: pump UDP sockets (drain received packets, process outbound).
        if pump_udp(&mut sockets, &mut udp_sockets, &mut udp_allocated_ports) {
            iface.poll(smol_now(), &mut device, &mut sockets);
        }

        // Pass 5: clean up closed connections.
        cleanup_closed(&mut sockets, &mut conns, &mut listeners);
    }
}

/// Create a listening socket for `addr:port`.
///
/// Creates `LISTEN_BACKLOG` passive listening sockets so multiple SYNs can
/// be processed concurrently — mirroring the OS `listen(fd, backlog)` API
/// that smoltcp lacks.
fn do_listen(
    sockets: &mut SocketSet<'static>,
    listeners: &mut HashMap<(IpAddr, u16), ListenerEntry>,
    addr: IpAddr,
    port: u16,
) -> Result<mpsc::Receiver<Result<NetstackStream, NetstackError>>, NetstackError> {
    let key = (addr, port);
    if listeners.contains_key(&key) {
        return Err(NetstackError::ListenFailed(format!(
            "port {port} already in use on {addr}"
        )));
    }
    let smol_addr = match addr {
        IpAddr::V4(v4) => to_smoltcp_v4(v4),
        IpAddr::V6(_) => {
            return Err(NetstackError::ListenFailed("IPv6 not supported".into()));
        }
    };
    let endpoint = IpListenEndpoint::from((smol_addr, port));
    let mut handles = Vec::with_capacity(LISTEN_BACKLOG);
    for _ in 0..LISTEN_BACKLOG {
        let mut socket = new_tcp_socket();
        socket
            .listen(endpoint)
            .map_err(|e| NetstackError::ListenFailed(format!("{e:?}")))?;
        handles.push(sockets.add(socket));
    }

    let (accept_tx, accept_rx) = mpsc::channel(ACCEPT_CHANNEL_DEPTH);
    listeners.insert(key, ListenerEntry { handles, accept_tx });
    Ok(accept_rx)
}

/// Add an additional IP address to the smoltcp interface.
fn do_add_addr(iface: &mut Interface, addr: IpAddr) -> Result<(), NetstackError> {
    match addr {
        IpAddr::V4(v4) => {
            iface.update_ip_addrs(|addrs| {
                let cidr = IpCidr::new(to_smoltcp_v4(v4), 32);
                if !addrs.contains(&cidr) {
                    let _ = addrs.push(cidr);
                }
            });
            Ok(())
        }
        IpAddr::V6(_) => Err(NetstackError::ListenFailed("IPv6 not supported".into())),
    }
}

/// Initiate a dial to `remote`. Stores the reply sender in `pending_dials`;
/// the poll loop sends `Ok(stream)` when connected or `Err(...)` on failure.
#[allow(clippy::similar_names)]
fn do_dial(
    iface: &mut Interface,
    sockets: &mut SocketSet<'static>,
    pending_dials: &mut HashMap<SocketHandle, PendingDial>,
    local_addr: Ipv4Addr,
    remote: SocketAddr,
    reply: oneshot::Sender<Result<NetstackStream, NetstackError>>,
) {
    let mut socket = new_tcp_socket();
    let local_port = ephemeral_port();
    let local_ep = IpListenEndpoint::from((to_smoltcp_v4(local_addr), local_port));

    let remote_ip = match remote.ip() {
        IpAddr::V4(v4) => to_smoltcp_v4(v4),
        IpAddr::V6(_) => {
            let _ = reply.send(Err(NetstackError::DialFailed("IPv6 not supported".into())));
            return;
        }
    };
    let remote_ep = IpEndpoint::new(remote_ip, remote.port());

    let cx = iface.context();
    if let Err(e) = socket.connect(cx, remote_ep, local_ep) {
        let _ = reply.send(Err(NetstackError::DialFailed(format!("{e:?}"))));
        return;
    }
    let handle = sockets.add(socket);
    pending_dials.insert(handle, PendingDial { reply, remote });
}

/// Create a bound UDP socket for `addr:port` and register it in the poll loop.
fn do_listen_packet(
    sockets: &mut SocketSet<'static>,
    udp_sockets: &mut HashMap<(IpAddr, u16), UdpSocketState>,
    allocated_ports: &mut HashSet<u16>,
    addr: IpAddr,
    mut port: u16,
) -> Result<UdpListenerParts, NetstackError> {
    match addr {
        IpAddr::V4(_) => {}
        IpAddr::V6(_) => {
            return Err(NetstackError::UdpListenFailed("IPv6 not supported".into()));
        }
    }

    if port == 0 {
        port = allocate_ephemeral_udp_port(allocated_ports);
    }

    let key = (addr, port);
    if udp_sockets.contains_key(&key) {
        return Err(NetstackError::UdpListenFailed(format!(
            "port {port} already in use on {addr}"
        )));
    }

    let smol_addr = to_smoltcp_v4(match addr {
        IpAddr::V4(v4) => v4,
        _ => unreachable!(),
    });
    let endpoint = IpListenEndpoint::from((smol_addr, port));

    let mut socket = new_udp_socket();
    socket
        .bind(endpoint)
        .map_err(|e| NetstackError::UdpListenFailed(format!("{e:?}")))?;

    let handle = sockets.add(socket);

    let (recv_tx, recv_rx) = mpsc::channel(UDP_CHANNEL_DEPTH);
    let (send_tx, send_rx) = mpsc::channel(UDP_CHANNEL_DEPTH);

    udp_sockets.insert(
        key,
        UdpSocketState {
            handle,
            recv_tx,
            send_rx,
        },
    );
    allocated_ports.insert(port);

    Ok(UdpListenerParts {
        recv_rx,
        send_tx,
        local_addr: SocketAddr::new(addr, port),
        key,
    })
}

/// Drain received UDP packets from smoltcp to the listener and process
/// outbound packets from the listener. Also cleans up sockets whose
/// listener has been dropped.
fn pump_udp(
    sockets: &mut SocketSet<'static>,
    udp_sockets: &mut HashMap<(IpAddr, u16), UdpSocketState>,
    allocated_ports: &mut HashSet<u16>,
) -> bool {
    let mut did_work = false;
    let keys: Vec<(IpAddr, u16)> = udp_sockets.keys().copied().collect();

    for key in keys {
        // Clean up if the listener was dropped (recv_tx closed).
        let listener_gone = udp_sockets.get(&key).is_some_and(|s| s.recv_tx.is_closed());
        if listener_gone {
            if let Some(state) = udp_sockets.remove(&key) {
                let _ = sockets.remove(state.handle);
            }
            allocated_ports.remove(&key.1);
            continue;
        }

        let Some(handle) = udp_sockets.get(&key).map(|s| s.handle) else {
            continue;
        };

        // --- Inbound: drain received packets from smoltcp → listener ---
        loop {
            let has_room = udp_sockets
                .get(&key)
                .is_some_and(|s| s.recv_tx.capacity() > 0);
            if !has_room {
                break;
            }
            let socket = sockets.get_mut::<udp::Socket>(handle);
            if !socket.can_recv() {
                break;
            }
            match socket.recv() {
                Ok((data, meta)) => {
                    let src = SocketAddr::new(IpAddr::from(meta.endpoint.addr), meta.endpoint.port);
                    if let Some(s) = udp_sockets.get(&key) {
                        let _ = s.recv_tx.try_send(UdpPacket {
                            data: Bytes::copy_from_slice(data),
                            src,
                        });
                    }
                    did_work = true;
                }
                Err(_) => break,
            }
        }

        // --- Outbound: listener → smoltcp ---
        loop {
            let outbound = udp_sockets
                .get_mut(&key)
                .and_then(|s| s.send_rx.try_recv().ok());
            let Some(pkt) = outbound else {
                break;
            };

            let dst_ip = match pkt.dst.ip() {
                IpAddr::V4(v4) => to_smoltcp_v4(v4),
                IpAddr::V6(_) => continue,
            };
            let dst_ep = IpEndpoint::new(dst_ip, pkt.dst.port());
            let socket = sockets.get_mut::<udp::Socket>(handle);
            match socket.send_slice(&pkt.data, dst_ep) {
                Ok(()) => did_work = true,
                Err(_) => break,
            }
        }
    }

    did_work
}

/// Pump data between a smoltcp socket and the application stream channels.
fn pump_connection(
    sockets: &mut SocketSet<'static>,
    handle: SocketHandle,
    conns: &mut HashMap<SocketHandle, ConnState>,
) -> bool {
    let mut did_work = false;
    // --- Read: socket -> app ---
    // Only consume from the socket when the app channel has capacity, so
    // smoltcp's TCP flow control applies backpressure to the sender instead
    // of us dropping data when the app reads slower than the network
    // delivers. If the channel is full, we leave the data in the socket's
    // recv buffer; the TCP receive window shrinks and the sender backs off.
    let can_recv = sockets.get::<tcp::Socket>(handle).can_recv();
    if can_recv {
        let has_room = conns
            .get(&handle)
            .is_some_and(|conn| conn.app_tx.capacity() > 0);
        if has_room {
            let socket = sockets.get_mut::<tcp::Socket>(handle);
            let mut data = Bytes::new();
            let result = socket.recv(|buf| {
                data = Bytes::copy_from_slice(buf);
                (buf.len(), ())
            });
            if result.is_ok() && !data.is_empty() {
                if let Some(conn) = conns.get(&handle) {
                    let _ = conn.app_tx.try_send(data);
                }
            }
        }
    }

    // Detect remote half-close.
    let socket = sockets.get::<tcp::Socket>(handle);
    let may_recv = socket.may_recv();
    if !may_recv && !can_recv {
        if let Some(conn) = conns.get(&handle) {
            let _ = conn.app_tx.try_send(Bytes::new());
        }
    }

    // --- Write: app -> socket ---
    // Flush any leftover from a previous cycle first, then drain the app
    // channel. We respect `send_slice`'s return value: if it writes fewer
    // bytes than offered (TCP send buffer full), we keep the remainder in
    // `pending_write` and STOP draining the app channel. This applies
    // backpressure up the mpsc chain — the bounded app_rx fills, which
    // makes `NetstackStream::poll_write` return Pending to the app.
    let can_send = sockets.get::<tcp::Socket>(handle).can_send();
    if can_send {
        if let Some(conn) = conns.get_mut(&handle) {
            // 1. Flush a previously-stored unwritten tail.
            if !conn.pending_write.is_empty() {
                let socket = sockets.get_mut::<tcp::Socket>(handle);
                let written = socket.send_slice(&conn.pending_write).unwrap_or(0);
                if written > 0 {
                    conn.pending_write.drain(..written);
                    did_work = true;
                }
                // If the tail still isn't fully flushed, wait for the next
                // poll cycle (when ACKs free up send capacity).
                if !conn.pending_write.is_empty() {
                    return did_work;
                }
            }

            // 2. Drain newly-arrived app data.
            while let Ok(data) = conn.app_rx.try_recv() {
                if data.is_empty() {
                    // App signaled close.
                    let socket = sockets.get_mut::<tcp::Socket>(handle);
                    socket.close();
                    break;
                }
                let socket = sockets.get_mut::<tcp::Socket>(handle);
                let written = socket.send_slice(&data).unwrap_or(0);
                if written > 0 {
                    did_work = true;
                }
                if written < data.len() {
                    // Socket send buffer filled — keep the remainder and
                    // stop draining so the app channel applies pressure.
                    conn.pending_write = data[written..].to_vec();
                    break;
                }
            }
        }
    }
    did_work
}

/// Remove fully closed connections and stale listeners.
fn cleanup_closed(
    sockets: &mut SocketSet<'static>,
    conns: &mut HashMap<SocketHandle, ConnState>,
    listeners: &mut HashMap<(IpAddr, u16), ListenerEntry>,
) {
    // Connections.
    let dead: Vec<SocketHandle> = conns
        .keys()
        .filter(|h| {
            let s = sockets.get::<tcp::Socket>(**h);
            s.state() == State::Closed || s.state() == State::TimeWait
        })
        .copied()
        .collect();
    for h in dead {
        conns.remove(&h);
        let _ = sockets.remove(h);
    }

    // Listeners whose accept channel is closed.
    let stale_keys: Vec<(IpAddr, u16)> = listeners
        .iter()
        .filter(|(_, entry)| entry.accept_tx.is_closed())
        .map(|(k, _)| *k)
        .collect();
    for key in stale_keys {
        if let Some(entry) = listeners.remove(&key) {
            for handle in entry.handles {
                let _ = sockets.remove(handle);
            }
        }
    }
}

#[cfg(test)]
mod tests;
