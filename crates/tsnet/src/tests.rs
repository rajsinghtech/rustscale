//! Unit tests and e2e integration tests for tsnet.
//!
//! E2e tests are `#[ignore]`d — they require `TS_E2E_AUTHKEY` and
//! `TS_E2E_TAILNET` env vars (provisioned by `tools/e2e.sh`).

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::Mutex;

use rustscale_key::NodePrivate;
use rustscale_tailcfg::Node;
use rustscale_wg::WgTunn;

use super::*;

// ---------------------------------------------------------------------------
// Builder validation tests (not ignored)
// ---------------------------------------------------------------------------

#[test]
fn builder_rejects_empty_hostname() {
    let result = ServerBuilder::default()
        .hostname("")
        .auth_key("tskey-xxx")
        .build();
    assert!(result.is_err());
    match result {
        Err(TsnetError::Builder(msg)) => assert!(msg.contains("hostname")),
        _ => panic!("expected Builder error"),
    }
}

#[test]
fn builder_accepts_valid_config() {
    let result = ServerBuilder::default()
        .hostname("my-node")
        .auth_key("tskey-xxx")
        .ephemeral(true)
        .build();
    assert!(result.is_ok());
}

#[test]
fn builder_defaults_control_url() {
    let server = Server::builder()
        .hostname("x")
        .auth_key("k")
        .build()
        .unwrap();
    assert_eq!(server.config.control_url, DEFAULT_CONTROL_URL);
}

#[test]
fn builder_sets_ephemeral_flag() {
    let server = ServerBuilder::default()
        .hostname("x")
        .auth_key("k")
        .ephemeral(true)
        .build()
        .unwrap();
    assert!(server.config.ephemeral);
}

// ---------------------------------------------------------------------------
// Hostname resolution tests (not ignored)
// ---------------------------------------------------------------------------

fn fake_node(name: &str, ip: &str, key: NodePrivate) -> Node {
    Node {
        ID: 1,
        Name: name.to_string(),
        Key: key.public(),
        Addresses: vec![format!("{ip}/32")],
        ..Default::default()
    }
}

#[test]
fn resolve_hostname_from_fake_netmap() {
    let peer_key = NodePrivate::generate();
    let peer_node = fake_node("alice.tailnet.ts.net.", "100.64.0.5", peer_key);

    // We can't construct a full RunningState easily, so test the
    // hostname matching logic directly.
    let peers = vec![peer_node.clone()];
    let host_lower = "alice.tailnet.ts.net".to_lowercase();
    let host_trimmed = host_lower.trim_end_matches('.');

    let mut found = None;
    for peer in &peers {
        let name = peer.Name.to_lowercase();
        let name_trimmed = name.trim_end_matches('.');
        if name_trimmed == host_trimmed {
            found = extract_node_ips(peer).first().copied();
            break;
        }
    }

    assert!(found.is_some());
    let ip = found.unwrap();
    assert_eq!(ip, std::net::IpAddr::V4(Ipv4Addr::new(100, 64, 0, 5)));
}

#[test]
fn resolve_hostname_case_insensitive() {
    let peer_key = NodePrivate::generate();
    let peer_node = fake_node("Bob.tailnet.ts.net.", "100.64.0.6", peer_key);
    let peers = vec![peer_node];

    let host = "BOB.tailnet.ts.net";
    let host_lower = host.to_lowercase();
    let host_trimmed = host_lower.trim_end_matches('.');

    let mut found = None;
    for peer in &peers {
        let name = peer.Name.to_lowercase();
        let name_trimmed = name.trim_end_matches('.');
        if name_trimmed == host_trimmed {
            found = extract_node_ips(peer).first().copied();
            break;
        }
    }
    assert!(found.is_some());
}

#[test]
fn resolve_unknown_hostname_returns_none() {
    let peer_key = NodePrivate::generate();
    let peer_node = fake_node("alice.tailnet.ts.net.", "100.64.0.5", peer_key);
    let peers = vec![peer_node];

    let host = "nonexistent.tailnet.ts.net";
    let host_lower = host.to_lowercase();
    let host_trimmed = host_lower.trim_end_matches('.');

    let mut found = None;
    for peer in &peers {
        let name = peer.Name.to_lowercase();
        let name_trimmed = name.trim_end_matches('.');
        if name_trimmed == host_trimmed {
            found = extract_node_ips(peer).first().copied();
            break;
        }
    }
    assert!(found.is_none());
}

// ---------------------------------------------------------------------------
// RouteTable longest-prefix tests
// ---------------------------------------------------------------------------

#[test]
fn route_table_exact_match() {
    let key = NodePrivate::generate();
    let peers = vec![Node {
        ID: 1,
        Name: "p".into(),
        Key: key.public(),
        Addresses: vec!["100.64.0.5/32".into()],
        ..Default::default()
    }];
    let rt = RouteTable::from_peers(&peers);
    assert_eq!(
        rt.lookup(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 5))),
        Some(key.public())
    );
    assert!(rt
        .lookup(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 6)))
        .is_none());
}

#[test]
fn route_table_longest_prefix() {
    let broad = NodePrivate::generate();
    let narrow = NodePrivate::generate();
    let peers = vec![
        Node {
            ID: 1,
            Name: "broad".into(),
            Key: broad.public(),
            Addresses: vec!["100.64.0.0/24".into()],
            ..Default::default()
        },
        Node {
            ID: 2,
            Name: "narrow".into(),
            Key: narrow.public(),
            Addresses: vec!["100.64.0.9/32".into()],
            ..Default::default()
        },
    ];
    let rt = RouteTable::from_peers(&peers);
    // /32 wins for its own address.
    assert_eq!(
        rt.lookup(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 9))),
        Some(narrow.public())
    );
    // /24 covers the rest.
    assert_eq!(
        rt.lookup(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 10))),
        Some(broad.public())
    );
}

// ---------------------------------------------------------------------------
// Netmap -> routes plumbing + builder advertise/accept routes
// ---------------------------------------------------------------------------

/// Simulate the netmap→RouteTable plumbing: peers with mixed /32 tailnet
/// addresses and /24 subnet routes, verify the route table reflects both
/// when accept_routes=true and only tailnet when false.
#[test]
fn netmap_to_routes_plumbing() {
    let router_key = NodePrivate::generate().public();
    let host_key = NodePrivate::generate().public();

    // Simulate what control sends: router peer has its tailnet /32 + the
    // approved subnet route in AllowedIPs; host has just its /32.
    let peers = vec![
        Node {
            ID: 1,
            Name: "router.tailnet.ts.net.".into(),
            Key: router_key.clone(),
            Addresses: vec!["100.64.0.1/32".into()],
            AllowedIPs: vec!["100.64.0.1/32".into(), "192.0.2.0/24".into()],
            ..Default::default()
        },
        Node {
            ID: 2,
            Name: "host.tailnet.ts.net.".into(),
            Key: host_key.clone(),
            Addresses: vec!["100.64.0.2/32".into()],
            AllowedIPs: vec!["100.64.0.2/32".into()],
            ..Default::default()
        },
    ];

    // accept_routes=true: both tailnet + subnet routes installed.
    let rt = RouteTable::from_peers_with_opts(&peers, true);
    assert_eq!(
        rt.lookup(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))),
        Some(router_key.clone()),
        "router tailnet IP should route to router"
    );
    assert_eq!(
        rt.lookup(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2))),
        Some(host_key.clone()),
        "host tailnet IP should route to host"
    );
    assert_eq!(
        rt.lookup(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42))),
        Some(router_key.clone()),
        "subnet route 192.0.2.0/24 should route to router"
    );

    // accept_routes=false: subnet route is NOT installed.
    let rt_no = RouteTable::from_peers_with_opts(&peers, false);
    assert_eq!(
        rt_no.lookup(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))),
        Some(router_key.clone()),
        "tailnet IP still routes without accept_routes"
    );
    assert!(
        rt_no
            .lookup(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42)))
            .is_none(),
        "subnet route should NOT be installed without accept_routes"
    );
}

/// Builder stores advertise_routes and accept_routes.
#[test]
fn builder_stores_advertise_and_accept_routes() {
    let server = ServerBuilder::default()
        .hostname("router")
        .auth_key("tskey-x")
        .advertise_routes(vec!["192.0.2.0/24".into(), "10.0.0.0/16".into()])
        .accept_routes(true)
        .build()
        .unwrap();
    assert_eq!(
        server.config.advertise_routes,
        vec!["192.0.2.0/24", "10.0.0.0/16"]
    );
    assert!(server.config.accept_routes);
}

/// Builder defaults: no advertised routes, accept_routes=false.
#[test]
fn builder_defaults_no_routes() {
    let server = ServerBuilder::default()
        .hostname("x")
        .auth_key("k")
        .build()
        .unwrap();
    assert!(server.config.advertise_routes.is_empty());
    assert!(!server.config.accept_routes);
}

// ---------------------------------------------------------------------------
// State file roundtrip (tested in state.rs, but also verify via Server)
// ---------------------------------------------------------------------------

#[test]
fn server_state_save_load_via_server() {
    let tmp = std::env::temp_dir().join("tsnet-server-state-test");
    let _ = std::fs::remove_dir_all(&tmp);

    let server = ServerBuilder::default()
        .hostname("test")
        .auth_key("tskey-x")
        .state_dir(tmp.clone())
        .build()
        .unwrap();

    // Generate state and save.
    let state = PersistedState::generate();
    server.save_state(&state).expect("save");

    // Load it back.
    let loaded = server.load_or_create_state().expect("load");
    assert_eq!(loaded.node_key.raw32(), state.node_key.raw32());
    assert_eq!(loaded.machine_key.raw32(), state.machine_key.raw32());
    assert_eq!(loaded.disco_key.raw32(), state.disco_key.raw32());

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn server_loads_existing_state_from_disk() {
    let tmp = std::env::temp_dir().join("tsnet-server-load-test");
    let _ = std::fs::remove_dir_all(&tmp);

    // First server generates and saves.
    let s1 = ServerBuilder::default()
        .hostname("test")
        .auth_key("tskey-x")
        .state_dir(tmp.clone())
        .build()
        .unwrap();
    let state = PersistedState::generate();
    s1.save_state(&state).expect("save");

    // Second server loads from the same dir.
    let s2 = ServerBuilder::default()
        .hostname("test")
        .auth_key("tskey-x")
        .state_dir(tmp.clone())
        .build()
        .unwrap();
    let loaded = s2.load_or_create_state().expect("load");
    assert_eq!(loaded.node_key.raw32(), state.node_key.raw32());

    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// Status on a non-up server
// ---------------------------------------------------------------------------

#[test]
fn status_before_up_returns_down() {
    let server = ServerBuilder::default()
        .hostname("test")
        .auth_key("tskey-x")
        .build()
        .unwrap();
    let status = server.status();
    assert!(!status.up);
    assert_eq!(status.peer_count, 0);
}

// ---------------------------------------------------------------------------
// Back-to-back netstack rig: HTTP roundtrip (plain TCP) + TLS handshake
// ---------------------------------------------------------------------------
//
// Two netstacks wired through in-memory WG tunnels (same rig as
// netstack/tests.rs). We listen on B, dial from A, and run a minimal HTTP/1.1
// exchange over the resulting stream — both plain TCP and TLS (self-signed).

use rustscale_netstack::{Netstack, DEFAULT_MTU};
use std::net::SocketAddr;

/// Cross-feed a WG datagram from src to dst, recursively handling replies.
fn cross_feed(
    datagram: &[u8],
    dst_tunn: &Mutex<WgTunn>,
    src_tunn: &Mutex<WgTunn>,
    dst_net: &Netstack,
    src_net: &Netstack,
) {
    let decap = dst_tunn
        .lock()
        .expect("dst lock")
        .decapsulate(datagram)
        .unwrap_or_default();
    if let Some(pt) = decap.plaintext {
        dst_net.push_rx(pt);
    }
    for reply in decap.replies {
        let src_decap = src_tunn
            .lock()
            .expect("src lock")
            .decapsulate(&reply)
            .unwrap_or_default();
        if let Some(pt) = src_decap.plaintext {
            src_net.push_rx(pt);
        }
        for r2 in src_decap.replies {
            cross_feed(&r2, dst_tunn, src_tunn, dst_net, src_net);
        }
    }
}

/// One pump cycle: drain outgoing from both netstacks, encapsulate, cross-feed,
/// tick timers, cross-feed timer output. Returns true if any work was done.
fn pump_cycle(
    a_tunn: &Mutex<WgTunn>,
    b_tunn: &Mutex<WgTunn>,
    a_net: &Netstack,
    b_net: &Netstack,
) -> bool {
    let mut did_work = false;
    while let Some(pkt) = a_net.pop_tx() {
        did_work = true;
        let dgs = a_tunn
            .lock()
            .expect("a")
            .encapsulate(&pkt)
            .unwrap_or_default();
        for dg in dgs {
            cross_feed(&dg, b_tunn, a_tunn, b_net, a_net);
        }
    }
    while let Some(pkt) = b_net.pop_tx() {
        did_work = true;
        let dgs = b_tunn
            .lock()
            .expect("b")
            .encapsulate(&pkt)
            .unwrap_or_default();
        for dg in dgs {
            cross_feed(&dg, a_tunn, b_tunn, a_net, b_net);
        }
    }
    for dg in a_tunn.lock().expect("a timers").tick_timers() {
        did_work = true;
        cross_feed(&dg, b_tunn, a_tunn, b_net, a_net);
    }
    for dg in b_tunn.lock().expect("b timers").tick_timers() {
        did_work = true;
        cross_feed(&dg, a_tunn, b_tunn, a_net, b_net);
    }
    did_work
}

/// Set up a back-to-back rig: two netstacks + WG tunnels + a pump task.
/// Returns (a_net, b_net, pump_handle).
fn make_rig() -> (Arc<Netstack>, Arc<Netstack>, tokio::task::JoinHandle<()>) {
    let a_priv = NodePrivate::generate();
    let b_priv = NodePrivate::generate();
    let a_pub = a_priv.public();
    let b_pub = b_priv.public();

    let a_net = Arc::new(Netstack::new(Ipv4Addr::new(100, 64, 0, 1), DEFAULT_MTU));
    let b_net = Arc::new(Netstack::new(Ipv4Addr::new(100, 64, 0, 2), DEFAULT_MTU));

    let a_tunn = Arc::new(Mutex::new(
        WgTunn::new(&a_priv, &b_pub, 1).expect("A tunnel"),
    ));
    let b_tunn = Arc::new(Mutex::new(
        WgTunn::new(&b_priv, &a_pub, 2).expect("B tunnel"),
    ));

    let a_t = a_tunn.clone();
    let b_t = b_tunn.clone();
    let a_n = a_net.clone();
    let b_n = b_net.clone();
    let pump = tokio::spawn(async move {
        loop {
            let did = pump_cycle(&a_t, &b_t, &a_n, &b_n);
            if !did {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        }
    });
    (a_net, b_net, pump)
}

/// Minimal HTTP/1.1 server: read request line, respond with a fixed body.
async fn http_serve_once(stream: &mut NetstackStream) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(std::time::Duration::from_secs(10), stream.read(&mut buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "read"))??;
    let req = String::from_utf8_lossy(&buf[..n]);
    let path = req.split(' ').nth(1).unwrap_or("/");
    let body = if path == "/bench" {
        "BENCH:ok".repeat(128)
    } else {
        "hello from rustscale tsnet serve".to_string()
    };
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(resp.as_bytes()).await?;
    Ok(())
}

/// Plain TCP HTTP roundtrip over the back-to-back netstack rig.
#[tokio::test]
async fn http_roundtrip_plain_tcp() {
    let (a_net, b_net, pump) = make_rig();

    // B listens on port 8080.
    let mut listener = b_net.listen(8080).await.expect("listen");

    // Spawn the HTTP server on B (accept one connection, serve, close).
    let b_net_s = b_net.clone();
    let server_task = tokio::spawn(async move {
        let mut stream =
            tokio::time::timeout(std::time::Duration::from_secs(10), listener.accept())
                .await
                .expect("accept timeout")
                .expect("accept");
        http_serve_once(&mut stream).await.expect("serve");
        tokio::io::AsyncWriteExt::shutdown(&mut stream).await.ok();
        drop(b_net_s);
    });

    // A dials B.
    let dial_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)), 8080);
    let mut client =
        tokio::time::timeout(std::time::Duration::from_secs(10), a_net.dial(dial_addr))
            .await
            .expect("dial timeout")
            .expect("dial failed");

    // Send a GET / request.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write");

    // Read the response.
    let mut resp = vec![0u8; 4096];
    let n = tokio::time::timeout(std::time::Duration::from_secs(10), client.read(&mut resp))
        .await
        .expect("read timeout")
        .expect("read");
    let resp_str = String::from_utf8_lossy(&resp[..n]);
    assert!(
        resp_str.starts_with("HTTP/1.1 200 OK"),
        "bad response: {resp_str}"
    );
    assert!(
        resp_str.contains("hello from rustscale tsnet serve"),
        "missing body: {resp_str}"
    );

    server_task.await.ok();
    pump.abort();
}

/// TLS handshake + HTTP roundtrip over the back-to-back rig using a
/// self-signed cert (client skips verification).
#[tokio::test]
async fn http_roundtrip_tls_self_signed() {
    ensure_ring_provider();
    let (a_net, b_net, pump) = make_rig();

    // B listens plain TCP on 8443; we wrap with a TlsListener using a
    // self-signed cert provider.
    let provider: Arc<dyn CertProvider> =
        Arc::new(SelfSignedCertProvider::new(vec!["localhost".into()]).expect("cert"));
    let plain_listener = b_net.listen(8443).await.expect("listen");
    let mut tls_listener = TlsListener::new(plain_listener, provider).expect("tls listener");

    // Spawn the TLS HTTP server on B.
    let server_task = tokio::spawn(async move {
        let mut tls_stream =
            tokio::time::timeout(std::time::Duration::from_secs(15), tls_listener.accept())
                .await
                .expect("tls accept timeout")
                .expect("tls accept");

        // Read HTTP request over TLS.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut buf = vec![0u8; 4096];
        let n = tls_stream.read(&mut buf).await.expect("tls read");
        let req = String::from_utf8_lossy(&buf[..n]);
        let path = req.split(' ').nth(1).unwrap_or("/");
        let body = if path == "/bench" {
            "BENCH:ok".repeat(64)
        } else {
            "hello over TLS".to_string()
        };
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        tls_stream
            .write_all(resp.as_bytes())
            .await
            .expect("tls write");
        tls_stream.shutdown().await.ok();
    });

    // A dials B (plain TCP), then wraps with a TLS client that skips
    // certificate verification (the cert is self-signed).
    let dial_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)), 8443);
    let raw = tokio::time::timeout(std::time::Duration::from_secs(10), a_net.dial(dial_addr))
        .await
        .expect("dial timeout")
        .expect("dial failed");

    // Build a rustls client config with a danger verifier that accepts any
    // server certificate (self-signed cert, no CA).
    let client_config = dangerous_client_config();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let domain = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls_client = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        connector.connect(domain, raw),
    )
    .await
    .expect("tls handshake timeout")
    .expect("tls handshake failed");

    // HTTP GET over TLS.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tls_client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("tls write");

    let mut resp = vec![0u8; 4096];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tls_client.read(&mut resp),
    )
    .await
    .expect("tls read timeout")
    .expect("tls read");
    let resp_str = String::from_utf8_lossy(&resp[..n]);
    assert!(
        resp_str.starts_with("HTTP/1.1 200 OK"),
        "bad tls response: {resp_str}"
    );
    assert!(
        resp_str.contains("hello over TLS"),
        "missing tls body: {resp_str}"
    );

    server_task.await.ok();
    pump.abort();
}

/// Build a rustls client config that skips server certificate verification.
/// **DANGEROUS — test only.** The self-signed certs used by listen_tls have
/// no CA chain, so the client must accept any cert.
fn dangerous_client_config() -> rustls::ClientConfig {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    #[derive(Debug)]
    struct NoVerify;

    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
            ]
        }
    }

    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth()
}

// ---------------------------------------------------------------------------
// E2E tests (#[ignore] — require TS_E2E_AUTHKEY + TS_E2E_TAILNET)
// ---------------------------------------------------------------------------

/// Single-node e2e: up() + status() sanity check.
#[tokio::test]
#[ignore]
async fn e2e_register_only() {
    let authkey = std::env::var("TS_E2E_AUTHKEY").expect("TS_E2E_AUTHKEY not set");
    let _tailnet = std::env::var("TS_E2E_TAILNET").expect("TS_E2E_TAILNET not set");

    let mut server = Server::builder()
        .hostname(format!("rustscale-e2e-register-{}", std::process::id()))
        .auth_key(authkey)
        .ephemeral(true)
        .build()
        .expect("build");

    server.up().await.expect("up");

    let status = server.status();
    assert!(status.up, "server should be up");
    assert!(
        !status.tailscale_ips.is_empty(),
        "should have at least one tailscale IP"
    );

    // Clean up.
    server.close().await;
}

/// Helper: wait for a specific peer IP to appear in a server's netmap.
/// Hard deadline 90s. On timeout, panics with the full peer list.
async fn wait_for_peer(server: &Server, target_ip: std::net::IpAddr, label: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    loop {
        let st = server.status();
        if st.peers.iter().any(|p| p.ips.contains(&target_ip)) {
            return;
        }
        if std::time::Instant::now() >= deadline {
            let peers: Vec<String> = st
                .peers
                .iter()
                .map(|p| format!("  {} ips={:?} path={:?}", p.name, p.ips, p.path_class))
                .collect();
            let elapsed = 90;
            panic!(
                "{label}: peer {target_ip} never appeared in netmap after {elapsed}s\n\
                 current peers ({}):\n{}",
                peers.len(),
                peers.join("\n")
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

/// Two-node e2e: spin up two tsnet servers, dial A->B, echo bytes.
/// Every operation has a hard timeout; no unbounded waits.
#[tokio::test]
#[ignore]
async fn e2e_two_nodes() {
    let authkey = std::env::var("TS_E2E_AUTHKEY").expect("TS_E2E_AUTHKEY not set");
    let _tailnet = std::env::var("TS_E2E_TAILNET").expect("TS_E2E_TAILNET not set");

    // Unique hostname suffix to avoid collisions with stale nodes from
    // other test suites running in the same ephemeral tailnet.
    let uid = std::process::id();

    // Start server A.
    let mut server_a = Server::builder()
        .hostname(format!("rustscale-e2e-a-{uid}"))
        .auth_key(authkey.clone())
        .ephemeral(true)
        .build()
        .expect("build A");
    server_a.up().await.expect("up A");
    let status_a = server_a.status();
    let ip_a = status_a
        .tailscale_ips
        .iter()
        .find_map(|ip| match ip {
            std::net::IpAddr::V4(v4) => Some(*v4),
            _ => None,
        })
        .expect("A should have an IPv4");

    // Start server B.
    let mut server_b = Server::builder()
        .hostname(format!("rustscale-e2e-b-{uid}"))
        .auth_key(authkey)
        .ephemeral(true)
        .build()
        .expect("build B");
    server_b.up().await.expect("up B");
    let status_b = server_b.status();
    let ip_b = status_b
        .tailscale_ips
        .iter()
        .find_map(|ip| match ip {
            std::net::IpAddr::V4(v4) => Some(*v4),
            _ => None,
        })
        .expect("B should have an IPv4");

    // B listens on a port.
    let mut listener = server_b.listen(4242).await.expect("listen");

    // Wait for B's specific IP to appear in A's netmap (hard 90s deadline).
    wait_for_peer(&server_a, ip_b.into(), "e2e_two_nodes").await;

    // Give the WG handshake a moment to complete after the peer appeared.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // A dials B. Retry up to 3 times — the WG handshake may not have
    // completed when the peer first appears in the netmap, causing the
    // first dial to time out. Each attempt gives the handshake more time.
    let dial_addr = format!("{}:4242", ip_b);
    let mut stream_a = None;
    for attempt in 1..=3 {
        eprintln!("dial attempt {attempt} to {dial_addr}");
        let dial_result = tokio::time::timeout(
            std::time::Duration::from_secs(45),
            server_a.dial(&dial_addr),
        )
        .await;
        match dial_result {
            Ok(Ok(s)) => {
                stream_a = Some(s);
                break;
            }
            Ok(Err(e)) => {
                eprintln!("dial attempt {attempt} failed: {e}");
            }
            Err(_) => {
                let st = server_a.status();
                let peers: Vec<String> = st
                    .peers
                    .iter()
                    .map(|p| format!("  {} ips={:?} path={:?}", p.name, p.ips, p.path_class))
                    .collect();
                eprintln!(
                    "dial attempt {attempt} timed out (45s)\nA peers ({}):\n{}",
                    peers.len(),
                    peers.join("\n")
                );
            }
        }
        if attempt < 3 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    }
    let mut stream_a = stream_a.expect("all 3 dial attempts failed");

    // B accepts (hard 30s timeout).
    let accept_result =
        tokio::time::timeout(std::time::Duration::from_secs(30), listener.accept()).await;
    let mut stream_b = accept_result
        .expect("accept timed out (30s)")
        .expect("accept failed");

    // A sends, B reads and echoes. Every I/O has a hard 30s timeout.
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio::io::AsyncWriteExt::write_all(&mut stream_a, b"hello e2e"),
    )
    .await
    .expect("A write timed out (30s)")
    .expect("A write failed");

    let mut buf = [0u8; 32];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio::io::AsyncReadExt::read(&mut stream_b, &mut buf),
    )
    .await
    .expect("B read timed out (30s)")
    .expect("B read failed");
    assert_eq!(&buf[..n], b"hello e2e");

    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio::io::AsyncWriteExt::write_all(&mut stream_b, b"world e2e"),
    )
    .await
    .expect("B write timed out (30s)")
    .expect("B write failed");

    let n = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio::io::AsyncReadExt::read(&mut stream_a, &mut buf),
    )
    .await
    .expect("A read timed out (30s)")
    .expect("A read failed");
    assert_eq!(&buf[..n], b"world e2e");

    // Check path (any of derp/direct ok).
    let _ = ip_a;
    let status_a = server_a.status();
    assert!(
        !status_a.peers.is_empty(),
        "A should have at least one peer"
    );

    // Clean up.
    tokio::io::AsyncWriteExt::shutdown(&mut stream_a).await.ok();
    server_a.close().await;
    server_b.close().await;
}

// ---------------------------------------------------------------------------
// E2E: subnet route advertisement + acceptance
// ---------------------------------------------------------------------------

/// Call the Tailscale API via curl (the test harness sets TS_E2E_API_TOKEN
/// and TS_E2E_TAILNET). Returns stdout as a String.
fn api_get(path: &str) -> Result<String, String> {
    let token = std::env::var("TS_E2E_API_TOKEN").map_err(|_| "TS_E2E_API_TOKEN not set")?;
    let url = format!("https://api.tailscale.com{path}");
    let out = std::process::Command::new("curl")
        .args([
            "-fsS",
            "-H",
            &format!("Authorization: Bearer {token}"),
            &url,
        ])
        .output()
        .map_err(|e| format!("curl: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "curl {url} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Approve advertised routes for a device via the API.
fn api_approve_routes(device_id: &str, routes: &[&str]) -> Result<(), String> {
    let token = std::env::var("TS_E2E_API_TOKEN").map_err(|_| "TS_E2E_API_TOKEN not set")?;
    let url = format!("https://api.tailscale.com/api/v2/device/{device_id}/routes");
    let body = format!("{{\"routes\":{}}}", serde_json::to_string(routes).unwrap());
    let out = std::process::Command::new("curl")
        .args([
            "-fsS",
            "-X",
            "POST",
            "-H",
            &format!("Authorization: Bearer {token}"),
            "-H",
            "Content-Type: application/json",
            "-d",
            &body,
            &url,
        ])
        .output()
        .map_err(|e| format!("curl: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "approve routes failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

/// Find a device ID by hostname prefix in the tailnet's device list.
fn find_device_id(hostname_prefix: &str) -> Result<String, String> {
    let tailnet = std::env::var("TS_E2E_TAILNET").map_err(|_| "TS_E2E_TAILNET not set")?;
    let resp = api_get(&format!("/api/v2/tailnet/{tailnet}/devices"))?;
    let devices: serde_json::Value =
        serde_json::from_str(&resp).map_err(|e| format!("json: {e}"))?;
    let arr = devices
        .get("devices")
        .and_then(|d| d.as_array())
        .ok_or("no devices array")?;
    for dev in arr {
        let name = dev.get("name").and_then(|n| n.as_str()).unwrap_or("");
        if name.contains(hostname_prefix) {
            return dev
                .get("id")
                .and_then(|i| i.as_str())
                .map(String::from)
                .ok_or_else(|| "device id not a string".to_string());
        }
    }
    Err(format!("no device matching '{hostname_prefix}'"))
}

/// E2e subnet routes: node A advertises 192.0.2.0/24 (TEST-NET), the test
/// approves it via the API, node B accepts routes, and B's route table must
/// contain 192.0.2.0/24 -> A.
#[tokio::test]
#[ignore]
async fn e2e_subnet_routes() {
    let authkey = std::env::var("TS_E2E_AUTHKEY").expect("TS_E2E_AUTHKEY not set");
    let _tailnet = std::env::var("TS_E2E_TAILNET").expect("TS_E2E_TAILNET not set");
    let uid = std::process::id();
    let subnet = "192.0.2.0/24";

    // Start node A — the subnet router (advertises 192.0.2.0/24).
    let mut server_a = Server::builder()
        .hostname(format!("rustscale-e2e-router-{uid}"))
        .auth_key(authkey.clone())
        .ephemeral(true)
        .advertise_routes(vec![subnet.into()])
        .build()
        .expect("build A");
    server_a.up().await.expect("up A");
    let status_a = server_a.status();
    assert!(!status_a.tailscale_ips.is_empty(), "A should have IPs");
    let ip_a = status_a.tailscale_ips[0];
    eprintln!("A up: ip={ip_a}, advertising {subnet}");

    // Wait for A to appear in the device list, then approve its routes.
    // The device may take a few seconds to show up in the API after up().
    let device_id = {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let mut found = None;
        let hostname_prefix = format!("rustscale-e2e-router-{uid}");
        while std::time::Instant::now() < deadline {
            match find_device_id(&hostname_prefix) {
                Ok(id) => {
                    found = Some(id);
                    break;
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_secs(2)).await,
            }
        }
        found.expect("A never appeared in device list (30s)")
    };
    eprintln!("A device_id={device_id}, approving routes...");
    api_approve_routes(&device_id, &[subnet]).expect("approve routes");
    eprintln!("routes approved");

    // Start node B — accepts routes.
    let mut server_b = Server::builder()
        .hostname(format!("rustscale-e2e-client-{uid}"))
        .auth_key(authkey)
        .ephemeral(true)
        .accept_routes(true)
        .build()
        .expect("build B");
    server_b.up().await.expect("up B");

    // Wait for A to appear in B's netmap, then check B's route table for the
    // subnet route. The route may take a few map updates to propagate after
    // approval (control pushes the updated AllowedIPs).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    loop {
        let st = server_b.status();
        if st.peers.iter().any(|p| p.ips.contains(&ip_a)) {
            // Peer is visible — check the route table.
            if let Some(peer_key) = server_b.route_lookup(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42)))
            {
                eprintln!("B route for 192.0.2.42 -> {peer_key:?}");
                let routes = server_b.routes();
                let has_subnet = routes.iter().any(|(cidr, _)| cidr == subnet);
                assert!(
                    has_subnet,
                    "B's route table should contain {subnet}, got: {routes:?}"
                );
                eprintln!("SUCCESS: B has route {subnet} -> peer");
                break;
            }
        }
        if std::time::Instant::now() >= deadline {
            let routes = server_b.routes();
            panic!(
                "subnet route {subnet} never appeared in B's route table (90s)\n\
                 B routes: {routes:?}\n\
                 B peers: {}",
                st.peers
                    .iter()
                    .map(|p| format!("{} ips={:?}", p.name, p.ips))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    server_a.close().await;
    server_b.close().await;
}
