//! Async DERP client over tokio + rustls.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use rustscale_key::{NodePrivate, NodePublic};

use crate::frame::{self, decode_frame_header, encode_frame_header, frame_type, MAX_PACKET_SIZE};
use crate::protocol::{parse_received, ClientInfo, Received};
use crate::DerpError;

/// Trait alias for a combined async read+write stream.
pub trait DerpStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> DerpStream for T {}

/// Read a complete DERP frame from an async reader.
async fn read_frame_async<R: AsyncRead + Unpin>(
    r: &mut R,
    max_size: u32,
) -> Result<(u8, Vec<u8>), DerpError> {
    let mut header = [0u8; frame::FRAME_HEADER_LEN];
    r.read_exact(&mut header).await?;
    let (typ, len) = decode_frame_header(&header);
    if len > max_size {
        return Err(DerpError::BadFrame(format!(
            "frame size {len} exceeds max {max_size}"
        )));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body).await?;
    Ok((typ, body))
}

/// Write a complete DERP frame to an async writer.
async fn write_frame_async<W: AsyncWrite + Unpin>(
    w: &mut W,
    typ: u8,
    body: &[u8],
) -> Result<(), DerpError> {
    let header = encode_frame_header(typ, body.len() as u32);
    w.write_all(&header).await?;
    w.write_all(body).await?;
    w.flush().await?;
    Ok(())
}

/// Build a rustls ClientConfig with webpki roots.
fn tls_config() -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .roots
        .extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// An async DERP client connected to a DERP server.
pub struct DerpClient {
    stream: Box<dyn DerpStream>,
    server_key: NodePublic,
    private_key: NodePrivate,
    public_key: NodePublic,
}

impl DerpClient {
    /// Create a DerpClient from an already-connected stream.
    ///
    /// Performs the DERP handshake (recvServerKey + sendClientKey) and
    /// optionally reads the first ServerInfo frame.
    pub async fn from_stream(
        stream: Box<dyn DerpStream>,
        private_key: NodePrivate,
    ) -> Result<Self, DerpError> {
        let public_key = private_key.public();
        let mut client = DerpClient {
            stream,
            server_key: NodePublic::from_raw32([0u8; 32]),
            private_key,
            public_key,
        };
        client.recv_server_key().await?;
        client.send_client_key().await?;
        Ok(client)
    }

    /// Connect to a DERP server over TCP (optionally TLS) and perform the
    /// DERP handshake directly (no HTTP upgrade).
    pub async fn connect(
        host: &str,
        port: u16,
        use_tls: bool,
        private_key: NodePrivate,
    ) -> Result<Self, DerpError> {
        let addr = format!("{host}:{port}");
        let tcp = TcpStream::connect(&addr).await?;
        tcp.set_nodelay(true).ok();

        if use_tls {
            let config = tls_config();
            let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
            let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
                .map_err(|e| DerpError::BadFrame(format!("invalid server name: {e}")))?;
            let tls = connector.connect(server_name, tcp).await?;
            Self::from_stream(Box::new(tls), private_key).await
        } else {
            Self::from_stream(Box::new(tcp), private_key).await
        }
    }

    /// Connect with an HTTP upgrade request (for servers that expect it).
    ///
    /// Uses the `Derp-Fast-Start: 1` header to suppress the HTTP 101 response,
    /// allowing the DERP protocol to begin immediately after the request.
    pub async fn connect_with_upgrade(
        host: &str,
        port: u16,
        use_tls: bool,
        private_key: NodePrivate,
    ) -> Result<Self, DerpError> {
        let addr = format!("{host}:{port}");
        let tcp = TcpStream::connect(&addr).await?;
        tcp.set_nodelay(true).ok();

        let mut stream: Box<dyn DerpStream> = if use_tls {
            let config = tls_config();
            let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
            let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
                .map_err(|e| DerpError::BadFrame(format!("invalid server name: {e}")))?;
            let tls = connector.connect(server_name, tcp).await?;
            Box::new(tls)
        } else {
            Box::new(tcp)
        };

        // Send HTTP upgrade with fast-start.
        let req = format!(
            "GET /derp HTTP/1.1\r\n\
             Host: {host}\r\n\
             Upgrade: DERP\r\n\
             Connection: Upgrade\r\n\
             {}: 1\r\n\
             \r\n",
            frame::headers::FAST_START
        );
        stream.write_all(req.as_bytes()).await?;
        stream.flush().await?;

        Self::from_stream(stream, private_key).await
    }

    /// The server's public key (learned during handshake).
    pub fn server_public_key(&self) -> NodePublic {
        self.server_key.clone()
    }

    /// Our own public key.
    pub fn public_key(&self) -> NodePublic {
        self.public_key.clone()
    }

    // ---- handshake ----

    async fn recv_server_key(&mut self) -> Result<(), DerpError> {
        let (typ, body) = read_frame_async(&mut self.stream, 4096).await?;
        if typ != frame_type::SERVER_KEY {
            return Err(DerpError::BadFrame("expected FrameServerKey".into()));
        }
        if body.len() < frame::MAGIC.len() + 32 {
            return Err(DerpError::BadMagic);
        }
        if body[..frame::MAGIC.len()] != frame::MAGIC {
            return Err(DerpError::BadMagic);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&body[frame::MAGIC.len()..frame::MAGIC.len() + 32]);
        self.server_key = NodePublic::from_raw32(key);
        Ok(())
    }

    async fn send_client_key(&mut self) -> Result<(), DerpError> {
        let info = ClientInfo {
            version: frame::PROTOCOL_VERSION,
            ..Default::default()
        };
        let json = serde_json::to_vec(&info)?;
        let msgbox = self.private_key.seal_to(&self.server_key, &json)?;

        let mut body = Vec::with_capacity(32 + msgbox.len());
        body.extend_from_slice(&self.public_key.raw32());
        body.extend_from_slice(&msgbox);

        write_frame_async(&mut self.stream, frame_type::CLIENT_INFO, &body).await?;
        Ok(())
    }

    // ---- recv ----

    /// Read the next message from the server.
    pub async fn recv(&mut self) -> Result<Received, DerpError> {
        loop {
            let (typ, body) =
                read_frame_async(&mut self.stream, MAX_PACKET_SIZE as u32 * 2).await?;

            if let Some(msg) = parse_received(typ, &body, &self.private_key, &self.server_key) {
                return Ok(msg);
            }
        }
    }

    // ---- send methods ----

    /// Send a packet to `dst`.
    pub async fn send_packet(
        &mut self,
        dst: NodePublic,
        pkt: &[u8],
    ) -> Result<(), DerpError> {
        if pkt.len() > MAX_PACKET_SIZE {
            return Err(DerpError::PacketTooLarge(pkt.len()));
        }
        let mut body = Vec::with_capacity(32 + pkt.len());
        body.extend_from_slice(&dst.raw32());
        body.extend_from_slice(pkt);
        write_frame_async(&mut self.stream, frame_type::SEND_PACKET, &body).await
    }

    /// Forward a packet (mesh use): `src` -> `dst`.
    pub async fn forward_packet(
        &mut self,
        src: NodePublic,
        dst: NodePublic,
        pkt: &[u8],
    ) -> Result<(), DerpError> {
        if pkt.len() > MAX_PACKET_SIZE {
            return Err(DerpError::PacketTooLarge(pkt.len()));
        }
        let mut body = Vec::with_capacity(64 + pkt.len());
        body.extend_from_slice(&src.raw32());
        body.extend_from_slice(&dst.raw32());
        body.extend_from_slice(pkt);
        write_frame_async(&mut self.stream, frame_type::FORWARD_PACKET, &body).await
    }

    /// Tell the server whether this is the client's preferred (home) node.
    pub async fn note_preferred(&mut self, preferred: bool) -> Result<(), DerpError> {
        let body = [u8::from(preferred)];
        write_frame_async(&mut self.stream, frame_type::NOTE_PREFERRED, &body).await
    }

    /// Send a ping (8-byte payload to be echoed in a pong).
    pub async fn send_ping(&mut self, data: [u8; 8]) -> Result<(), DerpError> {
        write_frame_async(&mut self.stream, frame_type::PING, &data).await
    }

    /// Send a pong (echo of a ping's 8-byte payload).
    pub async fn send_pong(&mut self, data: [u8; 8]) -> Result<(), DerpError> {
        write_frame_async(&mut self.stream, frame_type::PONG, &data).await
    }

    /// Subscribe to peer connection changes (requires mesh key).
    pub async fn watch_conns(&mut self) -> Result<(), DerpError> {
        write_frame_async(&mut self.stream, frame_type::WATCH_CONNS, &[]).await
    }

    /// Ask the server to close a peer's connection (requires mesh key).
    pub async fn close_peer(&mut self, target: NodePublic) -> Result<(), DerpError> {
        write_frame_async(&mut self.stream, frame_type::CLOSE_PEER, &target.raw32()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ServerInfo;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use rustscale_key::NodePrivate;
    use tokio::io::duplex;
    use tokio::sync::oneshot;

    /// Fake DERP server for integration testing.
    /// Speaks the real wire protocol over a tokio duplex stream.
    struct FakeServer {
        server_priv: NodePrivate,
        server_pub: NodePublic,
    }

    impl FakeServer {
        fn new() -> Self {
            let privk = NodePrivate::generate();
            let pubk = privk.public();
            Self {
                server_priv: privk,
                server_pub: pubk,
            }
        }

        async fn run(
            self,
            stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
            client_pub_out: oneshot::Sender<NodePublic>,
            done: oneshot::Receiver<()>,
        ) {
            let mut s = stream;

            // 1. Send FrameServerKey: 8 magic + 32 server pub.
            let mut sk_body = Vec::with_capacity(40);
            sk_body.extend_from_slice(&frame::MAGIC);
            sk_body.extend_from_slice(&self.server_pub.raw32());
            write_frame_async(&mut s, frame_type::SERVER_KEY, &sk_body)
                .await
                .unwrap();

            // 2. Read FrameClientInfo: 32 pub + nonce(24)+box.
            let (typ, body) = read_frame_async(&mut s, 65536).await.unwrap();
            assert_eq!(typ, frame_type::CLIENT_INFO);
            assert!(body.len() >= 32 + frame::NONCE_LEN);
            let mut cp = [0u8; 32];
            cp.copy_from_slice(&body[..32]);
            let client_pub = NodePublic::from_raw32(cp);

            // Open the box with server's private key from client's public key.
            let box_ct = &body[32..];
            let plaintext = self
                .server_priv
                .open_from(&client_pub, box_ct)
                .expect("open client info box");
            let info: ClientInfo = serde_json::from_slice(&plaintext).unwrap();
            assert_eq!(info.version, frame::PROTOCOL_VERSION);

            // 3. Send FrameServerInfo (sealed).
            let si = ServerInfo {
                version: frame::PROTOCOL_VERSION,
                ..Default::default()
            };
            let si_json = serde_json::to_vec(&si).unwrap();
            let si_box = self
                .server_priv
                .seal_to(&client_pub, &si_json)
                .unwrap();
            write_frame_async(&mut s, frame_type::SERVER_INFO, &si_box)
                .await
                .unwrap();

            // Notify the test of the client's public key.
            let _ = client_pub_out.send(client_pub.clone());

            // 4. Echo loop: read frames and respond.
            let mut done = done;
            loop {
                tokio::select! {
                    result = read_frame_async(&mut s, 65536) => {
                        match result {
                            Ok((typ, body)) => {
                                if typ == frame_type::SEND_PACKET && body.len() >= 32 {
                                    let data = &body[32..];
                                    let mut echo = Vec::with_capacity(32 + data.len());
                                    echo.extend_from_slice(&client_pub.raw32());
                                    echo.extend_from_slice(data);
                                    write_frame_async(&mut s, frame_type::RECV_PACKET, &echo)
                                        .await
                                        .unwrap();
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    _ = &mut done => break,
                }
            }
        }
    }

    #[tokio::test]
    async fn handshake_and_echo() {
        let (client_stream, server_stream) = duplex(8192);
        let server = FakeServer::new();
        let server_pub = server.server_pub.clone();

        let (tx, rx) = oneshot::channel();
        let (done_tx, done_rx) = oneshot::channel();
        let server_handle = tokio::spawn(server.run(server_stream, tx, done_rx));

        let client_priv = NodePrivate::generate();
        let mut client = DerpClient::from_stream(Box::new(client_stream), client_priv)
            .await
            .unwrap();

        assert_eq!(client.server_public_key(), server_pub);

        let client_pub = rx.await.unwrap();
        assert_eq!(client.public_key(), client_pub);

        // Read the ServerInfo.
        let msg = client.recv().await.unwrap();
        match msg {
            Received::ServerInfo(si) => assert_eq!(si.version, frame::PROTOCOL_VERSION),
            other => panic!("expected ServerInfo, got {other:?}"),
        }

        // Send a packet and expect it echoed back.
        let data = b"hello derp echo";
        client
            .send_packet(server_pub, data)
            .await
            .unwrap();

        let msg = client.recv().await.unwrap();
        match msg {
            Received::ReceivedPacket { source, data: got } => {
                assert_eq!(source, client_pub);
                assert_eq!(got, data);
            }
            other => panic!("expected ReceivedPacket, got {other:?}"),
        }

        let _ = done_tx.send(());
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn server_sends_ping_and_health() {
        let (client_stream, server_stream) = duplex(8192);

        let server_priv = NodePrivate::generate();
        let server_pub = server_priv.public();
        let server_pub_clone = server_pub.clone();

        let server_task = tokio::spawn(async move {
            let mut s = server_stream;

            // Send FrameServerKey.
            let mut sk_body = Vec::with_capacity(40);
            sk_body.extend_from_slice(&frame::MAGIC);
            sk_body.extend_from_slice(&server_pub.raw32());
            write_frame_async(&mut s, frame_type::SERVER_KEY, &sk_body)
                .await
                .unwrap();

            // Read FrameClientInfo.
            let (_, body) = read_frame_async(&mut s, 65536).await.unwrap();
            let mut cp = [0u8; 32];
            cp.copy_from_slice(&body[..32]);
            let client_pub = NodePublic::from_raw32(cp);

            // Send FrameServerInfo.
            let si = ServerInfo {
                version: frame::PROTOCOL_VERSION,
                ..Default::default()
            };
            let si_json = serde_json::to_vec(&si).unwrap();
            let si_box = server_priv.seal_to(&client_pub, &si_json).unwrap();
            write_frame_async(&mut s, frame_type::SERVER_INFO, &si_box)
                .await
                .unwrap();

            // Send a PeerGone (32 peer + 1 reason).
            let mut pg = Vec::with_capacity(33);
            pg.extend_from_slice(&client_pub.raw32());
            pg.push(frame::peer_gone_reason::NOT_HERE);
            write_frame_async(&mut s, frame_type::PEER_GONE, &pg)
                .await
                .unwrap();

            // Send a Ping (8 bytes).
            let ping_data = [1u8, 2, 3, 4, 5, 6, 7, 42];
            write_frame_async(&mut s, frame_type::PING, &ping_data)
                .await
                .unwrap();

            // Send Health.
            write_frame_async(&mut s, frame_type::HEALTH, b"dup")
                .await
                .unwrap();

            // Send Restarting.
            let mut restart = Vec::with_capacity(8);
            restart.extend_from_slice(&1000u32.to_be_bytes());
            restart.extend_from_slice(&5000u32.to_be_bytes());
            write_frame_async(&mut s, frame_type::RESTARTING, &restart)
                .await
                .unwrap();

            // Send KeepAlive.
            write_frame_async(&mut s, frame_type::KEEP_ALIVE, &[])
                .await
                .unwrap();

            // Send PeerPresent (32 key + 18 ip:port + 1 flags).
            let mut pp = Vec::with_capacity(51);
            pp.extend_from_slice(&client_pub.raw32());
            let mut ip16 = [0u8; 16];
            ip16[10] = 0xff;
            ip16[11] = 0xff;
            ip16[12] = 1;
            ip16[13] = 2;
            ip16[14] = 3;
            ip16[15] = 4;
            pp.extend_from_slice(&ip16);
            pp.extend_from_slice(&567u16.to_be_bytes());
            pp.push(0x01);
            write_frame_async(&mut s, frame_type::PEER_PRESENT, &pp)
                .await
                .unwrap();

            tokio::time::sleep(Duration::from_millis(100)).await;
        });

        let client_priv = NodePrivate::generate();
        let mut client = DerpClient::from_stream(Box::new(client_stream), client_priv)
            .await
            .unwrap();

        assert_eq!(client.server_public_key(), server_pub_clone);

        // ServerInfo
        let _ = client.recv().await.unwrap();

        // PeerGone
        match client.recv().await.unwrap() {
            Received::PeerGone { peer, reason } => {
                assert_eq!(peer, client.public_key());
                assert_eq!(reason, frame::peer_gone_reason::NOT_HERE);
            }
            other => panic!("expected PeerGone, got {other:?}"),
        }

        // Ping
        match client.recv().await.unwrap() {
            Received::Ping(data) => assert_eq!(data, [1, 2, 3, 4, 5, 6, 7, 42]),
            other => panic!("expected Ping, got {other:?}"),
        }

        // Health
        match client.recv().await.unwrap() {
            Received::Health { problem } => assert_eq!(problem, "dup"),
            other => panic!("expected Health, got {other:?}"),
        }

        // Restarting
        match client.recv().await.unwrap() {
            Received::Restarting {
                reconnect_in,
                try_for,
            } => {
                assert_eq!(reconnect_in, Duration::from_secs(1));
                assert_eq!(try_for, Duration::from_secs(5));
            }
            other => panic!("expected Restarting, got {other:?}"),
        }

        // KeepAlive
        match client.recv().await.unwrap() {
            Received::KeepAlive => {}
            other => panic!("expected KeepAlive, got {other:?}"),
        }

        // PeerPresent
        match client.recv().await.unwrap() {
            Received::PeerPresent {
                key,
                ip_port,
                flags,
            } => {
                assert_eq!(key, client.public_key());
                let expected = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 567);
                assert_eq!(ip_port, Some(expected));
                assert_eq!(flags, 0x01);
            }
            other => panic!("expected PeerPresent, got {other:?}"),
        }

        let _ = server_task.await;
    }

    #[tokio::test]
    async fn send_packet_rejects_oversize() {
        let (client_stream, server_stream) = duplex(8192);

        let server_priv = NodePrivate::generate();
        let server_pub = server_priv.public();
        let server_pub_clone = server_pub.clone();
        let s2 = server_stream;

        let server_task = tokio::spawn(async move {
            let mut s = s2;
            // Send server key.
            let mut sk = Vec::with_capacity(40);
            sk.extend_from_slice(&frame::MAGIC);
            sk.extend_from_slice(&server_pub.raw32());
            write_frame_async(&mut s, frame_type::SERVER_KEY, &sk)
                .await
                .unwrap();
            // Read client info.
            let (_, body) = read_frame_async(&mut s, 65536).await.unwrap();
            // Send server info.
            let si = ServerInfo {
                version: frame::PROTOCOL_VERSION,
                ..Default::default()
            };
            let si_json = serde_json::to_vec(&si).unwrap();
            let mut cp = [0u8; 32];
            cp.copy_from_slice(&body[..32]);
            let si_box = server_priv
                .seal_to(&NodePublic::from_raw32(cp), &si_json)
                .unwrap();
            write_frame_async(&mut s, frame_type::SERVER_INFO, &si_box)
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let client_priv = NodePrivate::generate();
        let mut client = DerpClient::from_stream(Box::new(client_stream), client_priv)
            .await
            .unwrap();

        let big = vec![0u8; MAX_PACKET_SIZE + 1];
        let result = client.send_packet(server_pub_clone, &big).await;
        assert!(matches!(result, Err(DerpError::PacketTooLarge(_))));

        let _ = server_task.await;
    }
}
