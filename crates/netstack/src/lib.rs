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

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp::{self, State};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot, Notify};

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
    #[error("netstack is shutting down")]
    ShuttingDown,
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A userspace TCP/IP stack bridging WireGuard plaintext to smoltcp.
pub struct Netstack {
    rx_queue: Arc<std::sync::Mutex<VecDeque<Vec<u8>>>>,
    tx_queue: Arc<std::sync::Mutex<VecDeque<Vec<u8>>>>,
    cmd_tx: mpsc::Sender<Command>,
    notify: Arc<Notify>,
    tx_notify: Arc<Notify>,
}

/// A TCP listener accepting incoming tailnet connections.
pub struct Listener {
    accept_rx: mpsc::Receiver<Result<NetstackStream, NetstackError>>,
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
    pub fn into_receiver(self) -> mpsc::Receiver<Result<NetstackStream, NetstackError>> {
        self.accept_rx
    }
}

/// A bidirectional TCP stream over the tailnet, implementing
/// [`AsyncRead`] + [`AsyncWrite`].
pub struct NetstackStream {
    /// Receives data read from the remote by the poll loop.
    rx: mpsc::Receiver<Vec<u8>>,
    /// Sends data to the poll loop for writing to the remote.
    tx: mpsc::Sender<Vec<u8>>,
    /// Buffered data from a partial read.
    read_buf: Vec<u8>,
    /// Whether the remote has half-closed (EOF delivered).
    remote_closed: bool,
    /// Wakes the poll loop on app read/write so it can process immediately.
    notify: Arc<Notify>,
    /// Remote peer address (populated on accept/dial; None if unavailable).
    remote_addr: Option<SocketAddr>,
}

impl NetstackStream {
    fn new(
        rx: mpsc::Receiver<Vec<u8>>,
        tx: mpsc::Sender<Vec<u8>>,
        notify: Arc<Notify>,
        remote_addr: Option<SocketAddr>,
    ) -> Self {
        Self {
            rx,
            tx,
            read_buf: Vec::new(),
            remote_closed: false,
            notify,
            remote_addr,
        }
    }

    /// The remote peer's socket address, if known. Populated on accept
    /// (from the smoltcp socket's remote endpoint) and dial (from the
    /// requested destination). Returns `None` if the address is unavailable.
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }
}

impl AsyncRead for NetstackStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Drain buffered data first.
        if !self.read_buf.is_empty() {
            let n = self.read_buf.len().min(buf.remaining());
            let data: Vec<u8> = self.read_buf.drain(..n).collect();
            buf.put_slice(&data);
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
                    self.read_buf = data[n..].to_vec();
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
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return std::task::Poll::Ready(Ok(0));
        }
        let chunk_len = buf.len().min(TCP_BUF);
        let was_empty = self.tx.capacity() == self.tx.max_capacity();
        match self.tx.try_send(buf[..chunk_len].to_vec()) {
            Ok(()) => {
                if was_empty {
                    self.notify.notify_one();
                }
                std::task::Poll::Ready(Ok(chunk_len))
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            }
            Err(_) => std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "connection closed",
            ))),
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
        let _ = self.tx.try_send(Vec::new());
        std::task::Poll::Ready(Ok(()))
    }
}

impl Drop for NetstackStream {
    fn drop(&mut self) {
        let _ = self.tx.try_send(Vec::new());
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

        let device =
            LoopbackDevice::new(rx_queue.clone(), tx_queue.clone(), mtu, tx_notify.clone());
        tokio::spawn(poll_loop(addr, device, cmd_rx, notify.clone()));

        Self {
            rx_queue,
            tx_queue,
            cmd_tx,
            notify,
            tx_notify,
        }
    }

    /// Feed a decapsulated plaintext IP packet from the WireGuard data plane.
    pub fn push_rx(&self, packet: Vec<u8>) {
        if let Ok(mut q) = self.rx_queue.lock() {
            q.push_back(packet);
        }
        self.notify.notify_one();
    }

    /// Drain one outbound IP packet (for WireGuard encapsulation).
    pub fn pop_tx(&self) -> Option<Vec<u8>> {
        self.tx_queue.lock().ok()?.pop_front()
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
        Ok(Listener { accept_rx })
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
        Ok(Listener { accept_rx })
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
}

/// State for an established connection, held inside the poll loop.
struct ConnState {
    /// Sends data (read from the smoltcp socket) to the application stream.
    app_tx: mpsc::Sender<Vec<u8>>,
    /// Receives data (from the application stream) to write to the socket.
    app_rx: mpsc::Receiver<Vec<u8>>,
    /// Unwritten tail of an app message that didn't fully fit in the smoltcp
    /// TCP send buffer. Held until the socket has send capacity again. This
    /// is the backpressure fix: previously `send_slice`'s return value was
    /// ignored and the remainder was silently dropped, causing data loss
    /// whenever the app produced faster than the TCP stack could push out.
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

/// Create a smoltcp TCP socket with Vec-backed buffers.
fn new_tcp_socket() -> tcp::Socket<'static> {
    let rx = tcp::SocketBuffer::new(vec![0u8; TCP_BUF]);
    let tx = tcp::SocketBuffer::new(vec![0u8; TCP_BUF]);
    tcp::Socket::new(rx, tx)
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
) -> (NetstackStream, ConnState) {
    let (app_tx, stream_rx) = mpsc::channel(64);
    let (stream_tx, app_rx) = mpsc::channel(64);
    let stream = NetstackStream::new(stream_rx, stream_tx, notify, remote_addr);
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

    let sleep = tokio::time::sleep(std::time::Duration::from_secs(1));
    tokio::pin!(sleep);

    loop {
        let fallback = match iface.poll_delay(smol_now(), &sockets) {
            Some(d) => {
                let micros = d.total_micros();
                std::time::Duration::from_micros(micros.max(500))
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
                    let (stream, conn) = make_stream_and_conn(notify.clone(), remote_addr);
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
                        let (stream, conn) = make_stream_and_conn(notify.clone(), Some(pd.remote));
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
        for handle in conn_handles {
            pump_connection(&mut sockets, handle, &mut conns);
        }

        // Pass 4: clean up closed connections.
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

/// Pump data between a smoltcp socket and the application stream channels.
fn pump_connection(
    sockets: &mut SocketSet<'static>,
    handle: SocketHandle,
    conns: &mut HashMap<SocketHandle, ConnState>,
) {
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
            let mut data = Vec::new();
            let result = socket.recv(|buf| {
                data = buf.to_vec();
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
            // Signal EOF once.
            let _ = conn.app_tx.try_send(Vec::new());
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
                }
                // If the tail still isn't fully flushed, wait for the next
                // poll cycle (when ACKs free up send capacity).
                if !conn.pending_write.is_empty() {
                    return;
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
                if written < data.len() {
                    // Socket send buffer filled — keep the remainder and
                    // stop draining so the app channel applies pressure.
                    conn.pending_write = data[written..].to_vec();
                    break;
                }
            }
        }
    }
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
