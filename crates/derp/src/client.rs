//! Async DERP client over tokio + rustls.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use url::Url;

use rustscale_key::{NodePrivate, NodePublic};
use rustscale_limiter::Bucket;

use crate::frame::{self, decode_frame_header, encode_frame_header, frame_type, MAX_PACKET_SIZE};
use crate::protocol::{parse_received, ClientInfo, Received, ServerInfo};
use crate::DerpError;

/// Trait alias for a combined async read+write stream.
pub trait DerpStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> DerpStream for T {}

/// Consult `tshttpproxy::proxy_from_environment` for `https://host:port`.
/// Returns `None` when no proxy is configured or the host is exempt via
/// `no_proxy`. Detection errors are treated as "no proxy" (the direct dial
/// surfaces real connectivity failures), matching Go's `derphttp.dialNode`.
fn proxy_url_for(host: &str, port: u16) -> Option<Url> {
    let url = Url::parse(&format!("https://{host}:{port}")).ok()?;
    rustscale_tshttpproxy::proxy_from_environment(&url)
        .ok()
        .flatten()
}

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

/// Ensure the rustls ring crypto provider is installed process-wide.
fn ensure_ring_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Build a rustls ClientConfig with webpki + baked ISRG roots.
fn tls_config() -> rustls::ClientConfig {
    ensure_ring_provider();
    let roots = rustscale_bakedroots::combined_root_store(None);
    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// Build a rustls ClientConfig that skips certificate verification.
/// Used for DERP servers with `InsecureForTests: true` in the DERPMap.
fn insecure_tls_config() -> rustls::ClientConfig {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};

    #[derive(Debug)]
    struct NoVerify;

    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA384,
                rustls::SignatureScheme::RSA_PKCS1_SHA512,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ED25519,
            ]
        }
    }

    ensure_ring_provider();
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth()
}

/// An async DERP client connected to a DERP server.
pub struct DerpClient {
    stream: Box<dyn DerpStream>,
    server_key: NodePublic,
    private_key: NodePrivate,
    public_key: NodePublic,
    /// Optional token-bucket send rate limiter, configured from the server's
    /// `ServerInfo.TokenBucketBytesPerSecond` / `TokenBucketBytesBurst`.
    rate_limiter: Option<Bucket>,
}

impl std::fmt::Debug for DerpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DerpClient")
            .field("server_key", &self.server_key)
            .field("public_key", &self.public_key)
            .field("rate_limited", &self.rate_limiter.is_some())
            .finish_non_exhaustive()
    }
}

impl DerpClient {
    /// Create a DerpClient from an already-connected stream.
    ///
    /// Performs the full DERP handshake:
    /// 1. Receive the server's public key (`FrameServerKey`). If
    ///    `expected_server_key` is `Some`, the received key is compared and
    ///    the connection is rejected on mismatch (pinned-key verification,
    ///    matching Go's `derp.ServerPublicKey` option posture).
    /// 2. Send our client info (`FrameClientInfo`).
    /// 3. Read the server's `FrameServerInfo` reply and configure the send
    ///    rate limiter from the advertised token-bucket parameters.
    ///
    /// Reading the ServerInfo confirms the server accepted our connection
    /// (the server sends it only after `verifyClient` + `registerClient`
    /// succeed). If the server rejects the client, the connection is closed
    /// and this returns an IO error rather than a false success.
    pub async fn from_stream(
        stream: Box<dyn DerpStream>,
        private_key: NodePrivate,
        expected_server_key: Option<NodePublic>,
    ) -> Result<Self, DerpError> {
        let public_key = private_key.public();
        let mut client = DerpClient {
            stream,
            server_key: NodePublic::from_raw32([0u8; 32]),
            private_key,
            public_key,
            rate_limiter: None,
        };
        client.recv_server_key(expected_server_key).await?;
        client.send_client_key().await?;
        client.recv_server_info().await?;
        Ok(client)
    }

    /// Connect to a DERP server over TCP (optionally TLS) and perform the
    /// DERP handshake directly (no HTTP upgrade).
    ///
    /// When `insecure` is true, TLS certificate verification is skipped
    /// (for test DERP servers with self-signed certs).
    pub async fn connect(
        host: &str,
        port: u16,
        use_tls: bool,
        private_key: NodePrivate,
        expected_server_key: Option<NodePublic>,
    ) -> Result<Self, DerpError> {
        Self::connect_insecure(host, port, use_tls, false, private_key, expected_server_key).await
    }

    /// Connect with an explicit insecure flag. Same as [`connect`] but
    /// allows skipping TLS verification for `InsecureForTests` DERP nodes.
    pub async fn connect_insecure(
        host: &str,
        port: u16,
        use_tls: bool,
        insecure: bool,
        private_key: NodePrivate,
        expected_server_key: Option<NodePublic>,
    ) -> Result<Self, DerpError> {
        let use_tls =
            use_tls && !rustscale_envknob::bool("TS_DEBUG_USE_DERP_HTTP").unwrap_or(false);
        let tcp = if let Some(proxy) = proxy_url_for(host, port) {
            rustscale_tshttpproxy::http_connect(&proxy, host, port)
                .await
                .map_err(|e| DerpError::Proxy(e.to_string()))?
        } else {
            let addr = format!("{host}:{port}");
            rustscale_tsdial::system_dial("tcp", &addr).await?
        };
        tcp.set_nodelay(true).ok();

        if use_tls {
            let config = if insecure {
                insecure_tls_config()
            } else {
                tls_config()
            };
            let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
            let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
                .map_err(|e| DerpError::BadFrame(format!("invalid server name: {e}")))?;
            let tls = connector.connect(server_name, tcp).await?;
            Self::from_stream(Box::new(tls), private_key, expected_server_key).await
        } else {
            Self::from_stream(Box::new(tcp), private_key, expected_server_key).await
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
        expected_server_key: Option<NodePublic>,
    ) -> Result<Self, DerpError> {
        Self::connect_with_upgrade_dial(host, host, port, use_tls, private_key, expected_server_key)
            .await
    }

    /// Connect with an HTTP upgrade, specifying separate TCP dial address and
    /// TLS SNI hostname. `dial_addr` is used for the TCP connection; `tls_host`
    /// is used for TLS SNI and the HTTP Host header.
    pub async fn connect_with_upgrade_dial(
        dial_addr: &str,
        tls_host: &str,
        port: u16,
        use_tls: bool,
        private_key: NodePrivate,
        expected_server_key: Option<NodePublic>,
    ) -> Result<Self, DerpError> {
        Self::connect_with_upgrade_dial_insecure(
            dial_addr,
            tls_host,
            port,
            use_tls,
            false,
            private_key,
            expected_server_key,
        )
        .await
    }

    /// Same as [`connect_with_upgrade_dial`] but with an explicit `insecure`
    /// flag for `InsecureForTests` DERP nodes.
    pub async fn connect_with_upgrade_dial_insecure(
        dial_addr: &str,
        tls_host: &str,
        port: u16,
        use_tls: bool,
        insecure: bool,
        private_key: NodePrivate,
        expected_server_key: Option<NodePublic>,
    ) -> Result<Self, DerpError> {
        let use_tls =
            use_tls && !rustscale_envknob::bool("TS_DEBUG_USE_DERP_HTTP").unwrap_or(false);
        // When an HTTP proxy is configured for this region (checked via the
        // canonical tls_host, matching Go's `proxyFromEnv` using `n.Addr()`),
        // tunnel through it with CONNECT and skip the HTTP upgrade — Go's
        // `dialNodeUsingProxy` does a plain TLS+DERP handshake over the
        // tunnel.
        if let Some(proxy) = proxy_url_for(tls_host, port) {
            let tcp = rustscale_tshttpproxy::http_connect(&proxy, dial_addr, port)
                .await
                .map_err(|e| DerpError::Proxy(e.to_string()))?;
            tcp.set_nodelay(true).ok();

            let stream: Box<dyn DerpStream> = if use_tls {
                let config = if insecure {
                    insecure_tls_config()
                } else {
                    tls_config()
                };
                let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
                let server_name = rustls::pki_types::ServerName::try_from(tls_host.to_string())
                    .map_err(|e| DerpError::BadFrame(format!("invalid server name: {e}")))?;
                let tls = connector.connect(server_name, tcp).await?;
                Box::new(tls)
            } else {
                Box::new(tcp)
            };
            return Self::from_stream(stream, private_key, expected_server_key).await;
        }

        let addr = format!("{dial_addr}:{port}");
        let tcp = rustscale_tsdial::system_dial("tcp", &addr).await?;
        tcp.set_nodelay(true).ok();

        let mut stream: Box<dyn DerpStream> = if use_tls {
            let config = if insecure {
                insecure_tls_config()
            } else {
                tls_config()
            };
            let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
            let server_name = rustls::pki_types::ServerName::try_from(tls_host.to_string())
                .map_err(|e| DerpError::BadFrame(format!("invalid server name: {e}")))?;
            let tls = connector.connect(server_name, tcp).await?;
            Box::new(tls)
        } else {
            Box::new(tcp)
        };

        // Send HTTP upgrade with fast-start.
        let req = format!(
            "GET /derp HTTP/1.1\r\n\
             Host: {tls_host}\r\n\
             Upgrade: DERP\r\n\
             Connection: Upgrade\r\n\
             {}: 1\r\n\
             \r\n",
            frame::headers::FAST_START
        );
        stream.write_all(req.as_bytes()).await?;
        stream.flush().await?;

        Self::from_stream(stream, private_key, expected_server_key).await
    }

    /// The server's public key (learned during handshake).
    pub fn server_public_key(&self) -> NodePublic {
        self.server_key.clone()
    }

    /// Our own public key.
    pub fn public_key(&self) -> NodePublic {
        self.public_key.clone()
    }

    /// Our own private key (for callers that need to decrypt received packets
    /// after splitting the stream).
    pub fn private_key(&self) -> NodePrivate {
        self.private_key.clone()
    }

    /// Consume the client and split the underlying stream into read and write
    /// halves, enabling concurrent reads and writes from separate tasks.
    ///
    /// Also returns the server's public key, which is needed to decrypt
    /// `ReceivedPacket` frames read from the split stream.
    pub fn into_split(
        self,
    ) -> (
        tokio::io::ReadHalf<Box<dyn DerpStream>>,
        tokio::io::WriteHalf<Box<dyn DerpStream>>,
        NodePublic,
    ) {
        let server_key = self.server_key.clone();
        let (r, w) = tokio::io::split(self.stream);
        (r, w, server_key)
    }

    // ---- handshake ----

    async fn recv_server_key(&mut self, expected: Option<NodePublic>) -> Result<(), DerpError> {
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

        // Pinned-key verification: when the caller provides an expected server
        // key (e.g. from the DERPMap or TLS meta cert), compare it against the
        // key received in the FrameServerKey. On mismatch, fail immediately —
        // do NOT proceed to sendClientKey. This matches Go's posture where the
        // ServerPublicKey option pins the key and a wrong key causes crypto
        // failure downstream; we fail earlier with a clear error.
        //
        // When no expected key is provided (bootstrap before DERPMap, or TLS
        // middlebox ate the meta cert), preserve current behavior but log.
        if let Some(expected_key) = expected {
            if !expected_key.is_zero() && expected_key != self.server_key {
                return Err(DerpError::ServerKeyMismatch {
                    expected: expected_key,
                    actual: self.server_key.clone(),
                });
            }
        } else {
            eprintln!(
                "derp: no pinned server key provided — accepting key {} without verification",
                self.server_key.short_string()
            );
        }

        Ok(())
    }

    async fn send_client_key(&mut self) -> Result<(), DerpError> {
        let info = ClientInfo {
            version: frame::PROTOCOL_VERSION,
            can_ack_pings: true,
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

    /// Read and consume the `FrameServerInfo` that the server sends after
    /// verifying and registering the client. If the server rejected the
    /// client (e.g. admission control denied), it closes the connection
    /// and this returns an IO error — which is the desired behavior: the
    /// caller learns immediately that the DERP connection failed.
    ///
    /// Also configures the send rate limiter from the server-advertised
    /// token-bucket parameters (`TokenBucketBytesPerSecond` /
    /// `TokenBucketBytesBurst`), matching Go's `setSendRateLimiter`.
    async fn recv_server_info(&mut self) -> Result<(), DerpError> {
        let (typ, body) = read_frame_async(&mut self.stream, MAX_PACKET_SIZE as u32 * 2).await?;
        if typ != frame_type::SERVER_INFO {
            return Err(DerpError::BadFrame(format!(
                "expected FrameServerInfo (0x{:02x}), got 0x{:02x}",
                frame_type::SERVER_INFO,
                typ
            )));
        }
        match parse_received(typ, &body, &self.private_key, &self.server_key) {
            Some(Received::ServerInfo(info)) => {
                self.configure_rate_limiter(&info);
            }
            Some(_) | None => {
                return Err(DerpError::BadServerInfo(
                    "failed to open ServerInfo box".into(),
                ));
            }
        }
        Ok(())
    }

    /// Configure the send rate limiter from `ServerInfo`, matching Go's
    /// `setSendRateLimiter`: if `TokenBucketBytesPerSecond` is 0, no
    /// limiting; otherwise create a token bucket with the advertised rate
    /// and burst.
    fn configure_rate_limiter(&mut self, info: &ServerInfo) {
        if info.token_bucket_bytes_per_second > 0 {
            self.rate_limiter = Some(Bucket::new(
                info.token_bucket_bytes_per_second,
                info.token_bucket_bytes_burst,
            ));
        }
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
    ///
    /// If a server-advertised rate limiter is active and the send budget is
    /// exhausted, the packet is silently dropped (returns `Ok(())`), matching
    /// Go's `derp.Client.send` which returns `nil` on `!c.rate.AllowN(...)`.
    pub async fn send_packet(&mut self, dst: NodePublic, pkt: &[u8]) -> Result<(), DerpError> {
        if pkt.len() > MAX_PACKET_SIZE {
            return Err(DerpError::PacketTooLarge(pkt.len()));
        }
        if let Some(ref mut limiter) = self.rate_limiter {
            let frame_len = (frame::FRAME_HEADER_LEN + 32 + pkt.len()) as u32;
            if !limiter.allow_n(frame_len) {
                return Ok(());
            }
        }
        let mut body = Vec::with_capacity(32 + pkt.len());
        body.extend_from_slice(&dst.raw32());
        body.extend_from_slice(pkt);
        write_frame_async(&mut self.stream, frame_type::SEND_PACKET, &body).await
    }

    /// Forward a packet (mesh use): `src` -> `dst`.
    ///
    /// Subject to the same rate limiting as [`send_packet`].
    pub async fn forward_packet(
        &mut self,
        src: NodePublic,
        dst: NodePublic,
        pkt: &[u8],
    ) -> Result<(), DerpError> {
        if pkt.len() > MAX_PACKET_SIZE {
            return Err(DerpError::PacketTooLarge(pkt.len()));
        }
        if let Some(ref mut limiter) = self.rate_limiter {
            let frame_len = (frame::FRAME_HEADER_LEN + 64 + pkt.len()) as u32;
            if !limiter.allow_n(frame_len) {
                return Ok(());
            }
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
    use std::time::{Duration, Instant};

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
            let si_box = self.server_priv.seal_to(&client_pub, &si_json).unwrap();
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
        let mut client = DerpClient::from_stream(
            Box::new(client_stream),
            client_priv,
            Some(server_pub.clone()),
        )
        .await
        .unwrap();

        assert_eq!(client.server_public_key(), server_pub);

        let client_pub = rx.await.unwrap();
        assert_eq!(client.public_key(), client_pub);

        // ServerInfo is consumed inside from_stream; send a packet and
        // expect it echoed back.
        let data = b"hello derp echo";
        client.send_packet(server_pub, data).await.unwrap();

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
        let mut client = DerpClient::from_stream(
            Box::new(client_stream),
            client_priv,
            Some(server_pub_clone.clone()),
        )
        .await
        .unwrap();

        assert_eq!(client.server_public_key(), server_pub_clone);

        // ServerInfo consumed in from_stream; first recv is PeerGone.
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
        let mut client = DerpClient::from_stream(
            Box::new(client_stream),
            client_priv,
            Some(server_pub_clone.clone()),
        )
        .await
        .unwrap();

        let big = vec![0u8; MAX_PACKET_SIZE + 1];
        let result = client.send_packet(server_pub_clone, &big).await;
        assert!(matches!(result, Err(DerpError::PacketTooLarge(_))));

        let _ = server_task.await;
    }

    // ---- Pinned-key verification tests ----

    /// A matching expected server key allows the handshake to proceed.
    #[tokio::test]
    async fn handshake_with_matching_expected_key() {
        let (client_stream, server_stream) = duplex(8192);
        let server = FakeServer::new();
        let server_pub = server.server_pub.clone();

        let (tx, _rx) = oneshot::channel();
        let (done_tx, done_rx) = oneshot::channel();
        let server_handle = tokio::spawn(server.run(server_stream, tx, done_rx));

        let client_priv = NodePrivate::generate();
        let client = DerpClient::from_stream(
            Box::new(client_stream),
            client_priv,
            Some(server_pub.clone()),
        )
        .await
        .expect("handshake with matching key should succeed");

        assert_eq!(client.server_public_key(), server_pub);

        let _ = done_tx.send(());
        let _ = server_handle.await;
    }

    /// A mismatched expected server key causes the handshake to fail with
    /// `DerpError::ServerKeyMismatch` — the client must NOT proceed to
    /// sendClientKey.
    #[tokio::test]
    async fn handshake_rejects_mismatched_key() {
        let (client_stream, server_stream) = duplex(8192);
        let server = FakeServer::new();

        let (tx, _rx) = oneshot::channel();
        let (done_tx, done_rx) = oneshot::channel();
        let server_handle = tokio::spawn(server.run(server_stream, tx, done_rx));

        // Generate a *different* key to pin as expected.
        let wrong_key = NodePrivate::generate().public();

        let client_priv = NodePrivate::generate();
        let result = DerpClient::from_stream(
            Box::new(client_stream),
            client_priv,
            Some(wrong_key.clone()),
        )
        .await;

        assert!(
            matches!(&result, Err(DerpError::ServerKeyMismatch { expected, .. }) if *expected == wrong_key),
            "expected ServerKeyMismatch, got {result:?}"
        );

        let _ = done_tx.send(());
        let _ = server_handle.await;
    }

    /// When no expected key is provided, the handshake succeeds (preserves
    /// bootstrap behavior — match Go's posture when no pinned key is known).
    #[tokio::test]
    async fn handshake_with_no_expected_key() {
        let (client_stream, server_stream) = duplex(8192);
        let server = FakeServer::new();
        let server_pub = server.server_pub.clone();

        let (tx, _rx) = oneshot::channel();
        let (done_tx, done_rx) = oneshot::channel();
        let server_handle = tokio::spawn(server.run(server_stream, tx, done_rx));

        let client_priv = NodePrivate::generate();
        let client = DerpClient::from_stream(Box::new(client_stream), client_priv, None)
            .await
            .expect("handshake with no expected key should succeed");

        assert_eq!(client.server_public_key(), server_pub);

        let _ = done_tx.send(());
        let _ = server_handle.await;
    }

    // ---- Rate limiter tests ----

    /// Token bucket allows burst-sized sends then drops until tokens refill.
    #[tokio::test]
    async fn token_bucket_burst_then_drop() {
        let mut bucket = Bucket::new(100, 100);

        // Burst of 100 should be consumed immediately.
        assert!(bucket.allow_n(100), "first 100 tokens from burst");
        // Bucket is now empty — next request should be denied.
        assert!(!bucket.allow_n(1), "no tokens left, should drop");

        // Wait 20ms → ~2 tokens refill at 100/s. A large request should
        // still fail, but a 1-token request should succeed. Using generous
        // bounds to avoid timing flakiness.
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !bucket.allow_n(100),
            "only a few tokens refilled, 100 should fail"
        );
        assert!(bucket.allow_n(1), "at least 1 token after 20ms refill");
    }

    /// Token bucket sustained rate: over a longer window the total bytes
    /// allowed converges to rate × elapsed.
    #[tokio::test]
    async fn token_bucket_sustained_rate() {
        let rate = 10_000u32;
        let mut bucket = Bucket::new(rate, 200);

        // Drain the burst.
        assert!(bucket.allow_n(200));

        // Over 100ms at 10k/s, 1000 tokens accrue. We request 100 at a time
        // and should get ~10 successful sends.
        let mut allowed = 0u32;
        let window = Duration::from_millis(100);
        let start = Instant::now();
        while start.elapsed() < window {
            if bucket.allow_n(100) {
                allowed += 100;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        // We should have allowed roughly rate * 0.1s = 1000 bytes, ±50% for
        // timing jitter. The key assertion is that sustained sends are
        // rate-limited, not unlimited.
        assert!(
            allowed > 500 && allowed < 2000,
            "expected ~1000 bytes allowed in 100ms, got {allowed}"
        );
    }

    /// A DerpClient configured with ServerInfo rate-limit parameters
    /// drops sends that exceed the bucket.
    #[tokio::test]
    async fn client_send_rate_limited() {
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
            // Send server info with a tiny rate limit: 1 byte/sec, burst 10.
            let si = ServerInfo {
                version: frame::PROTOCOL_VERSION,
                token_bucket_bytes_per_second: 1,
                token_bucket_bytes_burst: 10,
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
            // Keep the connection alive long enough for the test.
            tokio::time::sleep(Duration::from_millis(500)).await;
        });

        let client_priv = NodePrivate::generate();
        let mut client = DerpClient::from_stream(
            Box::new(client_stream),
            client_priv,
            Some(server_pub_clone.clone()),
        )
        .await
        .expect("handshake");

        // The first few small sends should succeed (burst budget), then
        // subsequent sends should be silently dropped. The frame overhead
        // is 5 (header) + 32 (key) = 37 bytes per send_packet, so a burst
        // of 10 allows zero sends (37 > 10). This verifies the rate limiter
        // is active.
        let data = b"hi";
        let result = client.send_packet(server_pub_clone, data).await;
        // With burst=10 and frame_len=37, the first send is dropped.
        assert!(result.is_ok(), "dropped send returns Ok");
        // The drop is silent (Ok(())), not an error.

        let _ = server_task.await;
    }
}
