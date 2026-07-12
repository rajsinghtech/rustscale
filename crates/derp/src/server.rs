//! In-process DERP relay server for integration testing.
//!
//! Ports the core relay logic from Go's `derp/derpserver/derpserver.go`:
//! the accept loop over plain TCP, the `ServerKey`/`ClientInfo`/`ServerInfo`
//! handshake with NaCl box crypto, packet relay via `RecvPacket` frames,
//! `PeerGone` on disconnect, `PING`/`PONG` keepalive, and last-writer-wins
//! duplicate-key handling.
//!
//! The server speaks the same HTTP upgrade path (`GET /derp`) that the Rust
//! [`crate::client::DerpClient`] expects, including the `Derp-Fast-Start`
//! header that suppresses the `101 Switching Protocols` response.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::task::JoinHandle;

use rustscale_key::{NodePrivate, NodePublic};

use crate::frame::{
    self, decode_frame_header, frame_type, peer_gone_reason, KEY_LEN, MAGIC, MAX_PACKET_SIZE,
    NONCE_LEN, PROTOCOL_VERSION,
};
use crate::protocol::{ClientInfo, ServerInfo};

/// Maximum frame body size the server will accept in a single read.
const MAX_FRAME_SIZE: u32 = (MAX_PACKET_SIZE as u32) * 2;

/// Default per-client send queue depth (matches Go's `defaultPerClientSendQueueDepth`).
const SEND_QUEUE_DEPTH: usize = 32;

/// Keepalive interval (Go uses 30s; we use the same).
const KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Outbound message enqueued to a client's send loop.
enum Outbound {
    /// Relay a packet from `src` to this client.
    RecvPacket { src: NodePublic, data: Vec<u8> },
    /// Peer disconnected or is not at this server.
    PeerGone { peer: NodePublic, reason: u8 },
    /// Pong reply (echo of ping payload).
    Pong([u8; 8]),
    /// Keepalive frame.
    KeepAlive,
}

/// Per-client state held in the server's client map.
struct ClientEntry {
    /// Sender half of the outbound channel feeding this client's send loop.
    tx: mpsc::Sender<Outbound>,
    /// Notify used to signal the client's read loop to stop (used by
    /// last-writer-wins replacement).
    close_notify: Arc<Notify>,
}

/// Shared server state.
struct ServerShared {
    private_key: NodePrivate,
    public_key: NodePublic,
    /// Public key -> active client connection. Last writer wins: registering
    /// a new connection for an existing key closes the old one.
    clients: Mutex<HashMap<NodePublic, ClientEntry>>,
}

impl ServerShared {
    async fn register_client(&self, key: NodePublic, tx: mpsc::Sender<Outbound>) -> Arc<Notify> {
        let close_notify = Arc::new(Notify::new());
        let entry = ClientEntry {
            tx,
            close_notify: close_notify.clone(),
        };
        let mut clients = self.clients.lock().await;
        if let Some(old) = clients.insert(key, entry) {
            // Close the previous connection for this key. Use notify_one so
            // the permit is stored even if the old client's read loop is
            // currently busy reading a frame (not yet waiting on notified()).
            old.close_notify.notify_one();
        }
        close_notify
    }

    /// Remove `key` from the client map, but only if the current entry's
    /// `close_notify` matches `ours`. Returns `true` if the entry was
    /// removed (i.e. this client was still the active one for the key).
    async fn unregister_client(&self, key: &NodePublic, ours: &Arc<Notify>) -> bool {
        let mut clients = self.clients.lock().await;
        if let Some(entry) = clients.get(key) {
            if Arc::ptr_eq(&entry.close_notify, ours) {
                clients.remove(key);
                return true;
            }
        }
        false
    }

    /// Look up the send channel for `dst`, returning a clone of the sender.
    async fn lookup_dst(&self, dst: &NodePublic) -> Option<mpsc::Sender<Outbound>> {
        let clients = self.clients.lock().await;
        clients.get(dst).map(|e| e.tx.clone())
    }

    /// Send a `PeerGone` to every client that is NOT the given `gone_key`.
    async fn broadcast_peer_gone(&self, gone_key: &NodePublic, reason: u8) {
        let clients = self.clients.lock().await;
        for (key, entry) in clients.iter() {
            if key != gone_key {
                let _ = entry.tx.try_send(Outbound::PeerGone {
                    peer: gone_key.clone(),
                    reason,
                });
            }
        }
    }
}

/// A running DERP server handle. Dropping it stops the accept loop and all
/// client connections.
pub struct DerpServerHandle {
    /// Shared state (kept alive so client tasks can finish).
    shared: Arc<ServerShared>,
    /// Join handle for the accept loop.
    accept_task: JoinHandle<()>,
    /// The address the server is listening on.
    addr: SocketAddr,
}

impl DerpServerHandle {
    /// The local address the server is listening on.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// The server's public key (needed by clients to verify the ServerKey frame).
    pub fn public_key(&self) -> NodePublic {
        self.shared.public_key.clone()
    }

    /// Stop the server gracefully: drop the accept loop and close the listener.
    pub fn shutdown(self) {
        self.accept_task.abort();
    }
}

/// Configuration for creating a [`DerpServer`].
pub struct DerpServer {
    private_key: NodePrivate,
}

impl DerpServer {
    /// Create a new DERP server with the given private key.
    pub fn new(private_key: NodePrivate) -> Self {
        Self { private_key }
    }

    /// Create a new DERP server with a freshly generated key.
    pub fn with_random_key() -> Self {
        Self::new(NodePrivate::generate())
    }

    /// Bind to `127.0.0.1:0` (ephemeral port) and start the accept loop.
    ///
    /// Returns the bound address and a handle for managing the server.
    pub async fn spawn_local(self) -> std::io::Result<(SocketAddr, DerpServerHandle)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let public_key = self.private_key.public();
        let shared = Arc::new(ServerShared {
            private_key: self.private_key,
            public_key: public_key.clone(),
            clients: Mutex::new(HashMap::new()),
        });

        let shared_clone = shared.clone();
        let accept_task = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _peer)) => {
                        let s = shared_clone.clone();
                        tokio::spawn(handle_connection(s, stream));
                    }
                    Err(_) => break,
                }
            }
        });

        let handle = DerpServerHandle {
            shared,
            accept_task,
            addr,
        };
        Ok((addr, handle))
    }
}

/// Handle a single TCP connection: parse the HTTP upgrade, run the DERP
/// handshake, then serve the client until disconnect.
async fn handle_connection(shared: Arc<ServerShared>, stream: TcpStream) {
    let _ = stream.set_nodelay(true);

    // Read the HTTP upgrade request using async I/O.
    let (mut read_half, mut write_half) = tokio::io::split(stream);

    let mut buf = vec![0u8; 4096];
    let mut total = 0;
    loop {
        if total >= buf.len() {
            buf.resize(buf.len() * 2, 0);
        }
        match read_half.read(&mut buf[total..]).await {
            Ok(0) => return, // client gone
            Ok(n) => {
                total += n;
                if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => return,
        }
    }

    let request = String::from_utf8_lossy(&buf[..total]);
    let is_derp_upgrade = request
        .lines()
        .take(1)
        .any(|l| l.contains("GET /derp") && l.contains("HTTP/1.1"))
        && request.to_ascii_lowercase().contains("upgrade: derp");

    if !is_derp_upgrade {
        let resp = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = write_half.write_all(resp).await;
        return;
    }

    let has_fast_start = request.contains("Derp-Fast-Start: 1");

    // Preserve any bytes read past the HTTP headers as leftover for the
    // DERP frame parser.
    let header_end = request.find("\r\n\r\n").map_or(total, |p| p + 4);
    let leftover = buf[header_end..total].to_vec();

    // If no fast-start, send HTTP 101 response.
    if !has_fast_start {
        let resp =
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n";
        if write_half.write_all(resp).await.is_err() {
            return;
        }
        let _ = write_half.flush().await;
    }

    // Wrap the read half with leftover bytes (if any).
    let reader = LeftoverReader::new(read_half, leftover);

    serve_client(shared, reader, write_half).await;
}

/// A wrapper that yields leftover bytes first, then reads from the underlying
/// reader.
struct LeftoverReader<R> {
    inner: R,
    leftover: Vec<u8>,
    pos: usize,
}

impl<R> LeftoverReader<R> {
    fn new(inner: R, leftover: Vec<u8>) -> Self {
        Self {
            inner,
            leftover,
            pos: 0,
        }
    }
}

impl<R: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for LeftoverReader<R> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.pos < self.leftover.len() {
            let available = &self.leftover[self.pos..];
            let n = std::cmp::min(available.len(), buf.remaining());
            buf.put_slice(&available[..n]);
            self.pos += n;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

/// Read a DERP frame header from an async reader.
async fn read_frame_header_async<R: tokio::io::AsyncRead + Unpin>(
    r: &mut R,
) -> std::io::Result<(u8, u32)> {
    let mut header = [0u8; frame::FRAME_HEADER_LEN];
    r.read_exact(&mut header).await?;
    Ok(decode_frame_header(&header))
}

/// Read a complete DERP frame body.
async fn read_frame_body_async<R: tokio::io::AsyncRead + Unpin>(
    r: &mut R,
    len: u32,
) -> std::io::Result<Vec<u8>> {
    if len > MAX_FRAME_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame size {len} exceeds max {MAX_FRAME_SIZE}"),
        ));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body).await?;
    Ok(body)
}

/// Write a frame (header + body) to an async writer.
async fn write_frame_async<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut W,
    typ: u8,
    body: &[u8],
) -> std::io::Result<()> {
    let header = frame::encode_frame_header(typ, body.len() as u32);
    w.write_all(&header).await?;
    w.write_all(body).await?;
    w.flush().await
}

/// Serve a single DERP client: handshake, then read loop + send loop.
async fn serve_client(
    shared: Arc<ServerShared>,
    mut read_half: LeftoverReader<tokio::io::ReadHalf<TcpStream>>,
    mut write_half: tokio::io::WriteHalf<TcpStream>,
) {
    // ---- Handshake ----

    // 1. Send ServerKey: MAGIC + server public key.
    {
        let mut body = Vec::with_capacity(MAGIC.len() + KEY_LEN);
        body.extend_from_slice(&MAGIC);
        body.extend_from_slice(&shared.public_key.raw32());
        if write_frame_async(&mut write_half, frame_type::SERVER_KEY, &body)
            .await
            .is_err()
        {
            return;
        }
    }

    // Channel for outbound messages to this client's send loop.
    let (send_tx, mut send_rx) = mpsc::channel::<Outbound>(SEND_QUEUE_DEPTH);

    // 2. Read ClientInfo: 32-byte client pub + sealed ClientInfo JSON.
    let (client_key, _client_info) = match recv_client_key(&mut read_half, &shared).await {
        Some(v) => v,
        None => return,
    };

    // 3. Send ServerInfo (sealed).
    {
        let si = ServerInfo {
            version: PROTOCOL_VERSION,
            ..Default::default()
        };
        let si_json = serde_json::to_vec(&si).unwrap_or_default();
        let si_box = match shared.private_key.seal_to(&client_key, &si_json) {
            Ok(b) => b,
            Err(_) => return,
        };
        if write_frame_async(&mut write_half, frame_type::SERVER_INFO, &si_box)
            .await
            .is_err()
        {
            return;
        }
    }

    // Start the send loop with the writer.
    let send_task = tokio::spawn(async move {
        send_loop(write_half, &mut send_rx).await;
    });

    // 4. Register the client.
    let close_notify = shared
        .register_client(client_key.clone(), send_tx.clone())
        .await;

    // 5. Run the read loop.
    run_read_loop(
        &shared,
        &mut read_half,
        &client_key,
        &send_tx,
        &close_notify,
    )
    .await;

    // 6. Unregister and broadcast PeerGone (only if we're still the active
    //    client for this key — a replacement connection may have taken over).
    let was_current = shared.unregister_client(&client_key, &close_notify).await;
    if was_current {
        shared
            .broadcast_peer_gone(&client_key, peer_gone_reason::DISCONNECTED)
            .await;
    }

    // 7. Signal send loop to finish and wait.
    drop(send_tx);
    let _ = send_task.await;
}

/// Receive and parse the ClientInfo frame.
async fn recv_client_key(
    r: &mut (impl tokio::io::AsyncRead + Unpin),
    shared: &ServerShared,
) -> Option<(NodePublic, ClientInfo)> {
    let (typ, len) = read_frame_header_async(r).await.ok()?;
    if typ != frame_type::CLIENT_INFO {
        return None;
    }
    const MIN_LEN: u32 = (KEY_LEN + NONCE_LEN) as u32;
    if !(MIN_LEN..=256 << 10).contains(&len) {
        return None;
    }
    let body = read_frame_body_async(r, len).await.ok()?;
    if body.len() < KEY_LEN {
        return None;
    }
    let mut key_bytes = [0u8; KEY_LEN];
    key_bytes.copy_from_slice(&body[..KEY_LEN]);
    let client_key = NodePublic::from_raw32(key_bytes);

    let msgbox = &body[KEY_LEN..];
    let plaintext = shared.private_key.open_from(&client_key, msgbox)?;
    let info: ClientInfo = serde_json::from_slice(&plaintext).ok()?;
    Some((client_key, info))
}

/// The per-client read loop: reads frames and dispatches them.
async fn run_read_loop(
    shared: &ServerShared,
    r: &mut (impl tokio::io::AsyncRead + Unpin),
    client_key: &NodePublic,
    send_tx: &mpsc::Sender<Outbound>,
    close_notify: &Arc<Notify>,
) {
    // interval_at with a delayed start so the first keepalive doesn't fire
    // immediately (tokio::time::interval's first tick completes instantly).
    let start = tokio::time::Instant::now() + KEEPALIVE_INTERVAL;
    let mut keepalive = tokio::time::interval_at(start, KEEPALIVE_INTERVAL);
    keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            // Keepalive tick: enqueue a KeepAlive frame.
            _ = keepalive.tick() => {
                if send_tx.send(Outbound::KeepAlive).await.is_err() {
                    return;
                }
            }
            // Last-writer-wins: another connection replaced us.
            () = close_notify.notified() => {
                return;
            }
            result = read_frame_header_async(r) => {
                let (typ, len) = match result {
                    Ok(v) => v,
                    Err(_) => return,
                };
                match typ {
                    frame_type::SEND_PACKET => {
                        if handle_send_packet(shared, r, len, client_key, send_tx).await.is_err() {
                            return;
                        }
                    }
                    frame_type::PING => {
                        if handle_ping(r, len, send_tx).await.is_err() {
                            return;
                        }
                    }
                    frame_type::NOTE_PREFERRED => {
                        // Read and discard the 1-byte body.
                        if len > 0 {
                            let mut buf = vec![0u8; len as usize];
                            if r.read_exact(&mut buf).await.is_err() {
                                return;
                            }
                        }
                    }
                    frame_type::WATCH_CONNS => {
                        // Not mesh; discard body (should be 0-length).
                        if len > 0 {
                            let mut buf = vec![0u8; len as usize];
                            if r.read_exact(&mut buf).await.is_err() {
                                return;
                            }
                        }
                    }
                    frame_type::CLOSE_PEER => {
                        // Not mesh; discard the 32-byte body.
                        if len > 0 {
                            let mut buf = vec![0u8; len as usize];
                            if r.read_exact(&mut buf).await.is_err() {
                                return;
                            }
                        }
                    }
                    frame_type::FORWARD_PACKET => {
                        // Not mesh; discard body.
                        if len > 0 {
                            let mut buf = vec![0u8; len as usize];
                            if r.read_exact(&mut buf).await.is_err() {
                                return;
                            }
                        }
                    }
                    _ => {
                        // Unknown frame: discard the body.
                        if len > 0 {
                            let mut buf = vec![0u8; len as usize];
                            if r.read_exact(&mut buf).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Handle a SendPacket frame: read dst key + packet data, relay to dst client.
async fn handle_send_packet(
    shared: &ServerShared,
    r: &mut (impl tokio::io::AsyncRead + Unpin),
    len: u32,
    src: &NodePublic,
    _send_tx: &mpsc::Sender<Outbound>,
) -> std::io::Result<()> {
    if (len as usize) < KEY_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "short send packet frame",
        ));
    }
    let body = read_frame_body_async(r, len).await?;
    let mut dst_bytes = [0u8; KEY_LEN];
    dst_bytes.copy_from_slice(&body[..KEY_LEN]);
    let dst = NodePublic::from_raw32(dst_bytes);
    let data = body[KEY_LEN..].to_vec();

    if data.len() > MAX_PACKET_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "packet too large",
        ));
    }

    // Look up destination client and enqueue the packet.
    if let Some(dst_tx) = shared.lookup_dst(&dst).await {
        let _ = dst_tx
            .send(Outbound::RecvPacket {
                src: src.clone(),
                data,
            })
            .await;
    }
    // If dst not found: silently drop (Go sends PeerGone for disco packets,
    // but for the test server a simple drop is sufficient).

    Ok(())
}

/// Handle a Ping frame: read 8-byte payload, enqueue Pong.
async fn handle_ping(
    r: &mut (impl tokio::io::AsyncRead + Unpin),
    len: u32,
    send_tx: &mpsc::Sender<Outbound>,
) -> std::io::Result<()> {
    if (len as usize) < 8 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "short ping",
        ));
    }
    let body = read_frame_body_async(r, len).await?;
    let mut payload = [0u8; 8];
    payload.copy_from_slice(&body[..8]);
    let _ = send_tx.send(Outbound::Pong(payload)).await;
    Ok(())
}

/// The per-client send loop: drains the outbound channel and writes frames.
async fn send_loop(mut writer: tokio::io::WriteHalf<TcpStream>, rx: &mut mpsc::Receiver<Outbound>) {
    while let Some(msg) = rx.recv().await {
        let result = match msg {
            Outbound::RecvPacket { src, data } => {
                let mut body = Vec::with_capacity(KEY_LEN + data.len());
                body.extend_from_slice(&src.raw32());
                body.extend_from_slice(&data);
                write_frame_async(&mut writer, frame_type::RECV_PACKET, &body).await
            }
            Outbound::PeerGone { peer, reason } => {
                let mut body = Vec::with_capacity(KEY_LEN + 1);
                body.extend_from_slice(&peer.raw32());
                body.push(reason);
                write_frame_async(&mut writer, frame_type::PEER_GONE, &body).await
            }
            Outbound::Pong(data) => write_frame_async(&mut writer, frame_type::PONG, &data).await,
            Outbound::KeepAlive => {
                write_frame_async(&mut writer, frame_type::KEEP_ALIVE, &[]).await
            }
        };
        if result.is_err() {
            break;
        }
    }
}

// ---- Test helpers ----

/// Build a `tailcfg::DERPMap` with a single region pointing at the given
/// local address. The node has `InsecureForTests: true` so the client
/// skips TLS verification, and `IPv4` is set to the address's IP so the
/// dial path resolves without DNS.
#[cfg(any(test, feature = "test-utils"))]
pub fn make_derp_map(addr: SocketAddr) -> rustscale_tailcfg::DERPMap {
    use rustscale_tailcfg::{DERPMap, DERPNode, DERPRegion};
    use std::collections::BTreeMap;

    let mut regions = BTreeMap::new();
    regions.insert(
        1,
        DERPRegion {
            RegionID: 1,
            RegionCode: "test".into(),
            RegionName: "Test DERP".into(),
            Nodes: Some(vec![DERPNode {
                Name: "1a".into(),
                RegionID: 1,
                HostName: format!("127.0.0.1:{}", addr.port()),
                IPv4: "127.0.0.1".into(),
                DERPPort: i32::from(addr.port()),
                InsecureForTests: true,
                ..Default::default()
            }]),
            ..Default::default()
        },
    );
    DERPMap {
        Regions: regions,
        OmitDefaultRegions: true,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::DerpClient;
    use crate::protocol::Received;
    use rustscale_key::NodePrivate;

    /// Wait for a client to receive a specific message type, with a timeout.
    async fn recv_with_timeout(client: &mut DerpClient, timeout: std::time::Duration) -> Received {
        tokio::time::timeout(timeout, client.recv())
            .await
            .expect("recv timeout")
            .expect("recv error")
    }

    /// Two clients connect to the local server and exchange packets both
    /// directions.
    #[tokio::test]
    async fn two_clients_exchange_packets() {
        let server = DerpServer::with_random_key();
        let (addr, handle) = server.spawn_local().await.unwrap();
        let server_pub = handle.public_key();

        // Client A
        let priv_a = NodePrivate::generate();
        let mut client_a = DerpClient::connect_with_upgrade_dial(
            "127.0.0.1",
            "127.0.0.1",
            addr.port(),
            false, // no TLS
            priv_a.clone(),
            Some(server_pub.clone()),
        )
        .await
        .expect("client A connect");
        let pub_a = client_a.public_key();

        // Client B
        let priv_b = NodePrivate::generate();
        let mut client_b = DerpClient::connect_with_upgrade_dial(
            "127.0.0.1",
            "127.0.0.1",
            addr.port(),
            false,
            priv_b.clone(),
            Some(server_pub.clone()),
        )
        .await
        .expect("client B connect");
        let pub_b = client_b.public_key();

        // A sends to B
        let msg_a_to_b = b"hello from A";
        client_a
            .send_packet(pub_b.clone(), msg_a_to_b)
            .await
            .unwrap();

        // B receives
        let received = recv_with_timeout(&mut client_b, std::time::Duration::from_secs(5)).await;
        match received {
            Received::ReceivedPacket { source, data } => {
                assert_eq!(source, pub_a);
                assert_eq!(data, msg_a_to_b);
            }
            other => panic!("expected ReceivedPacket, got {other:?}"),
        }

        // B sends to A
        let msg_b_to_a = b"hello from B";
        client_b.send_packet(pub_a, msg_b_to_a).await.unwrap();

        let received = recv_with_timeout(&mut client_a, std::time::Duration::from_secs(5)).await;
        match received {
            Received::ReceivedPacket { source, data } => {
                assert_eq!(source, pub_b);
                assert_eq!(data, msg_b_to_a);
            }
            other => panic!("expected ReceivedPacket, got {other:?}"),
        }

        handle.shutdown();
    }

    /// Ping/Pong keepalive works.
    #[tokio::test]
    async fn ping_pong_works() {
        let server = DerpServer::with_random_key();
        let (addr, handle) = server.spawn_local().await.unwrap();
        let server_pub = handle.public_key();

        let priv_c = NodePrivate::generate();
        let mut client = DerpClient::connect_with_upgrade_dial(
            "127.0.0.1",
            "127.0.0.1",
            addr.port(),
            false,
            priv_c,
            Some(server_pub),
        )
        .await
        .expect("client connect");

        let ping_data = [42u8; 8];
        client.send_ping(ping_data).await.unwrap();

        let received = recv_with_timeout(&mut client, std::time::Duration::from_secs(5)).await;
        match received {
            Received::Pong(data) => assert_eq!(data, ping_data),
            other => panic!("expected Pong, got {other:?}"),
        }

        handle.shutdown();
    }

    /// PeerGone is observed when a peer disconnects.
    #[tokio::test]
    async fn peer_gone_on_disconnect() {
        let server = DerpServer::with_random_key();
        let (addr, handle) = server.spawn_local().await.unwrap();
        let server_pub = handle.public_key();

        // Client A
        let priv_a = NodePrivate::generate();
        let mut client_a = DerpClient::connect_with_upgrade_dial(
            "127.0.0.1",
            "127.0.0.1",
            addr.port(),
            false,
            priv_a,
            Some(server_pub.clone()),
        )
        .await
        .expect("client A connect");
        let pub_a = client_a.public_key();

        // Client B
        let priv_b = NodePrivate::generate();
        let mut client_b = DerpClient::connect_with_upgrade_dial(
            "127.0.0.1",
            "127.0.0.1",
            addr.port(),
            false,
            priv_b,
            Some(server_pub.clone()),
        )
        .await
        .expect("client B connect");
        let pub_b = client_b.public_key();

        // A sends a packet to B so the server records A as a sender to B's
        // peer-gone watcher set. Then B disconnects and A should see
        // PeerGone for B.
        client_a.send_packet(pub_b.clone(), b"ping").await.unwrap();

        // B receives the packet (ensures the relay path is established).
        let _ = recv_with_timeout(&mut client_b, std::time::Duration::from_secs(5)).await;

        // B sends to A so the server records B in A's sawSrc set.
        client_b.send_packet(pub_a, b"pong").await.unwrap();
        let _ = recv_with_timeout(&mut client_a, std::time::Duration::from_secs(5)).await;

        // Disconnect client B by dropping it.
        drop(client_b);

        // A should receive a PeerGone for B.
        // We need to poll with a longer timeout since disconnect detection
        // takes a moment.
        let received = recv_with_timeout(&mut client_a, std::time::Duration::from_secs(10)).await;
        match received {
            Received::PeerGone { peer, reason } => {
                assert_eq!(peer, pub_b);
                assert_eq!(reason, peer_gone_reason::DISCONNECTED);
            }
            other => panic!("expected PeerGone, got {other:?}"),
        }

        handle.shutdown();
    }

    /// Last-writer-wins: a new connection for the same key closes the old.
    #[tokio::test]
    async fn last_writer_wins() {
        let server = DerpServer::with_random_key();
        let (addr, handle) = server.spawn_local().await.unwrap();
        let server_pub = handle.public_key();

        let priv_k = NodePrivate::generate();
        let pub_k = priv_k.public();

        // First connection with this key.
        let mut client1 = DerpClient::connect_with_upgrade_dial(
            "127.0.0.1",
            "127.0.0.1",
            addr.port(),
            false,
            priv_k.clone(),
            Some(server_pub.clone()),
        )
        .await
        .expect("client1 connect");

        // A separate client (C) that will send to pub_k.
        let priv_c = NodePrivate::generate();
        let mut client_c = DerpClient::connect_with_upgrade_dial(
            "127.0.0.1",
            "127.0.0.1",
            addr.port(),
            false,
            priv_c,
            Some(server_pub.clone()),
        )
        .await
        .expect("client C connect");
        let pub_c = client_c.public_key();

        // Second connection with the same key — should replace client1.
        let mut client2 = DerpClient::connect_with_upgrade_dial(
            "127.0.0.1",
            "127.0.0.1",
            addr.port(),
            false,
            priv_k,
            Some(server_pub.clone()),
        )
        .await
        .expect("client2 connect");

        // Give the server a moment to process the replacement.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // C sends to pub_k — the packet should go to client2, not client1.
        let msg = b"to the new connection";
        client_c.send_packet(pub_k, msg).await.unwrap();

        let received = recv_with_timeout(&mut client2, std::time::Duration::from_secs(5)).await;
        match received {
            Received::ReceivedPacket { source, data } => {
                assert_eq!(source, pub_c);
                assert_eq!(data, msg);
            }
            other => panic!("expected ReceivedPacket on client2, got {other:?}"),
        }

        // client1 should have been disconnected (its read should fail or
        // return EOF). We verify by attempting a recv with a short timeout.
        let result =
            tokio::time::timeout(std::time::Duration::from_millis(500), client1.recv()).await;
        assert!(
            result.is_err() || result.unwrap().is_err(),
            "client1 should have been disconnected"
        );

        handle.shutdown();
    }

    /// The server handles both fast-start and non-fast-start upgrade paths.
    #[tokio::test]
    async fn non_fast_start_upgrade() {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

        let server = DerpServer::with_random_key();
        let (addr, handle) = server.spawn_local().await.unwrap();
        let server_pub = handle.public_key();

        // Manually connect and send a non-fast-start upgrade.
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (reader, mut writer) = tokio::io::split(tcp);

        let req =
            "GET /derp HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n";
        writer.write_all(req.as_bytes()).await.unwrap();
        writer.flush().await.unwrap();

        // Read the HTTP 101 response using a BufReader so we don't consume
        // bytes belonging to the DERP frame that follows.
        let mut buf_reader = BufReader::new(reader);

        // Read the status line.
        let mut status_line = String::new();
        buf_reader.read_line(&mut status_line).await.unwrap();
        assert!(
            status_line.contains("101 Switching Protocols"),
            "got: {status_line}"
        );

        // Read remaining headers until empty line.
        loop {
            let mut line = String::new();
            buf_reader.read_line(&mut line).await.unwrap();
            if line.trim().is_empty() {
                break;
            }
        }

        // Now the DERP protocol begins: read ServerKey frame.
        let mut header = [0u8; frame::FRAME_HEADER_LEN];
        buf_reader.read_exact(&mut header).await.unwrap();
        let (typ, len) = decode_frame_header(&header);
        assert_eq!(typ, frame_type::SERVER_KEY);
        let mut key_body = vec![0u8; len as usize];
        buf_reader.read_exact(&mut key_body).await.unwrap();
        assert_eq!(&key_body[..MAGIC.len()], &MAGIC);
        let mut sk = [0u8; 32];
        sk.copy_from_slice(&key_body[MAGIC.len()..MAGIC.len() + 32]);
        assert_eq!(NodePublic::from_raw32(sk), server_pub);

        handle.shutdown();
    }

    /// Verify make_derp_map produces a valid DERPMap.
    #[tokio::test]
    async fn make_derp_map_valid() {
        let server = DerpServer::with_random_key();
        let (addr, handle) = server.spawn_local().await.unwrap();
        let map = make_derp_map(addr);
        assert_eq!(map.Regions.len(), 1);
        let region = &map.Regions[&1];
        assert_eq!(region.RegionID, 1);
        let nodes = region.Nodes.as_ref().unwrap();
        assert_eq!(nodes.len(), 1);
        assert!(nodes[0].InsecureForTests);
        assert_eq!(nodes[0].IPv4, "127.0.0.1");
        assert_eq!(nodes[0].DERPPort, i32::from(addr.port()));
        handle.shutdown();
    }
}
