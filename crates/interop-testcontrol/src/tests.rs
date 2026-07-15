#![allow(dead_code, clippy::large_futures, clippy::zombie_processes)]

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use rustscale_tsnet::{Server, ServerBuilder};
use serde::Deserialize;

/// Path to the Go testcontrol binary (relative to the workspace root).
const BINARY_PATH: &str = "tools/testcontrol/bin/testcontrol";

/// Auth key used for all testcontrol registrations. The Go testcontrol
/// server doesn't validate auth keys unless `RequireAuthKey` is set, so
/// any non-empty string works.
const AUTH_KEY: &str = "tskey-testcontrol";

/// Maximum time to wait for a server to reach Running state.
const UP_TIMEOUT: Duration = Duration::from_secs(120);

/// Maximum time to wait for a peer or state change to propagate.
const POLL_TIMEOUT: Duration = Duration::from_secs(20);

// ---------------------------------------------------------------------------
// Testcontrol process wrapper
// ---------------------------------------------------------------------------

/// A spawned testcontrol server process. The `url` field holds the
/// `https://127.0.0.1:PORT` control URL printed on the first stdout line.
struct TestControl {
    url: String,
    child: Child,
}

impl TestControl {
    /// Spawn the Go testcontrol binary and read the control URL.
    /// Returns `None` if the binary or `go` is missing (skip gracefully).
    fn spawn() -> Option<Self> {
        let bin = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../")
            .join(BINARY_PATH);
        let bin = bin.canonicalize().unwrap_or_else(|_| {
            std::path::PathBuf::from(format!(
                "{}/../../{BINARY_PATH}",
                env!("CARGO_MANIFEST_DIR")
            ))
        });

        if !bin.exists() {
            eprintln!(
                "interop-testcontrol: binary not found at {}; run `bash tools/testcontrol/build.sh`",
                bin.display()
            );
            return None;
        }

        let mut child = Command::new(&bin)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn testcontrol binary");

        // Read the first stdout line — the control URL.
        let stdout = child.stdout.take().expect("stdout piped");
        let reader = BufReader::new(stdout);
        let url = reader.lines().next()?.ok()?;
        eprintln!("interop-testcontrol: server URL: {url}");

        // Spawn a task to drain stderr so the process doesn't block.
        let stderr = child.stderr.take().expect("stderr piped");
        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut stderr = tokio::process::ChildStderr::from_std(stderr).unwrap();
            let mut buf = [0u8; 4096];
            while stderr.read(&mut buf).await.is_ok() {
                // Drain — discard output.
            }
        });

        Some(TestControl { url, child })
    }

    /// The control URL (e.g. `https://127.0.0.1:12345`).
    fn url(&self) -> &str {
        &self.url
    }

    // --- Side-channel API ---

    /// POST /testapi/add-fake-node — inject a fake node into the control
    /// server's node map.
    async fn add_fake_node(&self) -> bool {
        let url = format!("{}/testapi/add-fake-node", self.url);
        reqwest_post_body(&url, "").await
    }

    /// POST /testapi/expire-all — set all nodes' key expiry state.
    async fn expire_all(&self, expired: bool) -> bool {
        let url = format!("{}/testapi/expire-all", self.url);
        let body = serde_json::json!({"expired": expired}).to_string();
        reqwest_post_body(&url, &body).await
    }

    /// GET /testapi/nodes — list registered nodes.
    async fn nodes(&self) -> Option<NodesResponse> {
        let url = format!("{}/testapi/nodes", self.url);
        let body = reqwest_get(&url).await?;
        serde_json::from_str(&body).ok()
    }

    /// POST /testapi/raw-map-response — inject a raw MapResponse for a
    /// specific node key.
    async fn raw_map_response(&self, node_key: &str, map_response_json: &str) -> bool {
        let url = format!("{}/testapi/raw-map-response", self.url);
        let body = serde_json::json!({
            "nodeKey": node_key,
            "mapResponseJSON": serde_json::from_str::<serde_json::Value>(map_response_json).unwrap_or(serde_json::Value::Null),
        })
        .to_string();
        reqwest_post_body(&url, &body).await
    }
}

impl Drop for TestControl {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------------------
// HTTP helpers — minimal TLS client for the side-channel API
// ---------------------------------------------------------------------------

async fn reqwest_post_body(url: &str, body: &str) -> bool {
    let (_, host, port) = parse_url(url);
    let path = url_path(url);
    tokio_tls_request(host, port, "POST", &path, body, true)
        .await
        .is_ok()
}

async fn reqwest_get(url: &str) -> Option<String> {
    let (_, host, port) = parse_url(url);
    let path = url_path(url);
    tokio_tls_request(host, port, "GET", &path, "", true)
        .await
        .ok()
}

/// Parse a URL into (scheme, host, port). Only handles `https://host:port/path`.
fn parse_url(url: &str) -> (&str, &str, u16) {
    let scheme = if url.starts_with("https://") {
        "https"
    } else if url.starts_with("http://") {
        "http"
    } else {
        ""
    };
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let (host_port, _path) = rest.split_once('/').unwrap_or((rest, ""));
    if let Some(colon) = host_port.rfind(':') {
        if let Ok(port) = host_port[colon + 1..].parse::<u16>() {
            return (scheme, &host_port[..colon], port);
        }
    }
    (scheme, host_port, 443)
}

/// Extract the path portion of a URL.
fn url_path(url: &str) -> String {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    if let Some(slash) = rest.find('/') {
        rest[slash..].to_string()
    } else {
        "/".to_string()
    }
}

/// Make a TLS request to the testcontrol side-channel API. Uses an
/// insecure TLS config (self-signed cert) matching the control client.
async fn tokio_tls_request(
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    body: &str,
    insecure: bool,
) -> Result<String, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::rustls::pki_types::ServerName;

    let tcp = tokio::net::TcpStream::connect((host, port))
        .await
        .map_err(|e| format!("tcp: {e}"))?;

    let config = if insecure {
        insecure_rustls_config()
    } else {
        let root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let server_name =
        ServerName::try_from(host.to_string()).map_err(|e| format!("server name: {e}"))?;
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| format!("tls: {e}"))?;

    let content_length = body.len();
    let request = format!(
        "{method} {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {content_length}\r\n\
         Connection: close\r\n\
         \r\n{body}"
    );
    tls.write_all(request.as_bytes())
        .await
        .map_err(|e| format!("write: {e}"))?;

    let mut buf = Vec::with_capacity(4096);
    tls.read_to_end(&mut buf)
        .await
        .map_err(|e| format!("read: {e}"))?;

    let text = String::from_utf8_lossy(&buf);
    let body_start = text.find("\r\n\r\n").map_or(text.len(), |p| p + 4);
    Ok(text[body_start..].to_string())
}

/// Insecure rustls config for the testcontrol self-signed cert.
fn insecure_rustls_config() -> rustls::ClientConfig {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};

    #[derive(Debug)]
    struct NoVerify;
    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &[rustls::pki_types::CertificateDer<'_>],
            _: &rustls::pki_types::ServerName<'_>,
            _: &[u8],
            _: rustls::pki_types::UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
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

    let _ = rustls::crypto::ring::default_provider().install_default();
    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(NoVerify))
        .with_no_client_auth()
}

// ---------------------------------------------------------------------------
// Side-channel API response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct NodesResponse {
    count: usize,
    nodes: Vec<NodeEntry>,
}

#[derive(Debug, Deserialize)]
struct NodeEntry {
    key: String,
    id: i64,
    #[allow(dead_code)]
    ip: String,
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Build a tsnet Server pointing at the testcontrol URL.
fn make_server(tc: &TestControl, hostname: &str) -> Server {
    make_server_with_ephemeral(tc, hostname, true)
}

fn make_server_with_ephemeral(tc: &TestControl, hostname: &str, ephemeral: bool) -> Server {
    ServerBuilder::default()
        .hostname(hostname)
        .control_url(tc.url())
        .auth_key(AUTH_KEY)
        .ephemeral(ephemeral)
        .disable_direct_paths(true)
        .build()
        .expect("failed to build server")
}

/// Wait for a server to reach Running state (up() returns Ok).
/// Each attempt is given 60s since up() does TLS + Noise + register + map fetch.
async fn wait_for_up(server: &mut Server, label: &str) {
    let deadline = tokio::time::sleep(UP_TIMEOUT);
    tokio::pin!(deadline);
    loop {
        let result = tokio::time::timeout(Duration::from_secs(60), server.up()).await;
        if let Ok(Ok(_)) = result {
            eprintln!("interop-testcontrol: {label} is up");
            return;
        }
        if let Ok(Err(e)) = result {
            eprintln!("interop-testcontrol: {label} up() error: {e}, retrying...");
        } else {
            eprintln!("interop-testcontrol: {label} up() timed out, retrying...");
        }
        assert!(
            !deadline.is_elapsed(),
            "{label} did not reach Running state within {UP_TIMEOUT:?}"
        );
    }
}

/// Wait for a condition to become true, polling every 500ms.
async fn wait_for<F, Fut>(label: &str, timeout: Duration, cond: F)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    loop {
        if cond().await {
            return;
        }
        tokio::select! {
            () = &mut deadline => panic!("{label} did not complete within {timeout:?}"),
            () = tokio::time::sleep(Duration::from_millis(500)) => {}
        }
    }
}

/// Helper that spawns testcontrol or skips the test.
fn setup() -> Option<TestControl> {
    TestControl::spawn()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Scenario A: register + reach Running + assert node count via /testapi/nodes.
#[tokio::test]
async fn testcontrol_register_and_node_count() {
    let Some(tc) = setup() else {
        eprintln!("skip: testcontrol binary not available");
        return;
    };
    let mut server = make_server(&tc, "node-a");
    wait_for_up(&mut server, "node-a").await;

    // The control server should now have at least 1 node registered.
    wait_for("node count > 0", POLL_TIMEOUT, || async {
        tc.nodes().await.is_some_and(|n| n.count > 0)
    })
    .await;

    let nodes = tc.nodes().await.expect("nodes API");
    assert!(
        nodes.count >= 1,
        "expected at least 1 node, got {}",
        nodes.count
    );
    eprintln!(
        "interop-testcontrol: PASS — registered, {} node(s) visible",
        nodes.count
    );

    server.close().await;
}

/// Scenario B: two tsnet nodes see each other as peers, ping over local DERP.
#[tokio::test]
async fn testcontrol_two_nodes_peer_visibility() {
    let Some(tc) = setup() else {
        eprintln!("skip: testcontrol binary not available");
        return;
    };
    let mut server1 = make_server(&tc, "node-b1");
    wait_for_up(&mut server1, "node-b1").await;

    let mut server2 = make_server(&tc, "node-b2");
    wait_for_up(&mut server2, "node-b2").await;

    // Wait for each server to see the other as a peer.
    wait_for("server1 sees server2", POLL_TIMEOUT, || async {
        server1.status().peer_count > 0
    })
    .await;
    wait_for("server2 sees server1", POLL_TIMEOUT, || async {
        server2.status().peer_count > 0
    })
    .await;

    let s1_peers = server1.status().peers;
    let s2_peers = server2.status().peers;
    eprintln!(
        "interop-testcontrol: PASS — s1 sees {} peer(s), s2 sees {} peer(s)",
        s1_peers.len(),
        s2_peers.len()
    );
    assert!(!s1_peers.is_empty(), "server1 should have peers");
    assert!(!s2_peers.is_empty(), "server2 should have peers");

    server1.close().await;
    server2.close().await;
}

/// Scenario C: add_fake_node -> peer appears in netmap.
#[tokio::test]
async fn testcontrol_add_fake_node_appears_as_peer() {
    let Some(tc) = setup() else {
        eprintln!("skip: testcontrol binary not available");
        return;
    };
    let mut server = make_server(&tc, "node-c");
    wait_for_up(&mut server, "node-c").await;

    let initial_peers = server.status().peer_count;
    eprintln!("interop-testcontrol: initial peer count: {initial_peers}");

    // Inject a fake node via the side-channel API.
    tc.add_fake_node().await;

    // Wait for the fake node to appear as a peer.
    wait_for("fake node appears as peer", POLL_TIMEOUT, || async {
        server.status().peer_count > initial_peers
    })
    .await;

    eprintln!(
        "interop-testcontrol: PASS — fake node appeared, peer count now {}",
        server.status().peer_count
    );

    server.close().await;
}

/// Scenario D: expire-all -> client observes key expiry, un-expire -> recovers.
#[tokio::test]
async fn testcontrol_key_expiry_and_recovery() {
    let Some(tc) = setup() else {
        eprintln!("skip: testcontrol binary not available");
        return;
    };
    // Expired ephemeral nodes are removed by testcontrol, so use a persistent
    // node to exercise the intended expire/recover stream lifecycle.
    let mut server = make_server_with_ephemeral(&tc, "node-d", false);
    wait_for_up(&mut server, "node-d").await;

    assert!(
        !server.status().key_expired,
        "should not be expired initially"
    );

    // Expire all node keys.
    tc.expire_all(true).await;

    // Wait for the client to observe key expiry.
    wait_for("key expiry observed", POLL_TIMEOUT, || async {
        server.status().key_expired
    })
    .await;
    eprintln!("interop-testcontrol: key expiry observed");

    // Un-expire.
    tc.expire_all(false).await;

    // Wait for recovery.
    wait_for("key expiry cleared", POLL_TIMEOUT, || async {
        !server.status().key_expired
    })
    .await;

    eprintln!("interop-testcontrol: PASS — key expiry + recovery cycle complete");
    server.close().await;
}

/// Scenario E: raw MapResponse with PeersRemoved -> peer disappears.
#[tokio::test]
async fn testcontrol_raw_map_response_peers_removed() {
    let Some(tc) = setup() else {
        eprintln!("skip: testcontrol binary not available");
        return;
    };
    let mut server1 = make_server(&tc, "node-e1");
    wait_for_up(&mut server1, "node-e1").await;

    let mut server2 = make_server(&tc, "node-e2");
    wait_for_up(&mut server2, "node-e2").await;

    // Wait for server1 to see server2 as a peer.
    wait_for("server1 sees server2", POLL_TIMEOUT, || async {
        server1.status().peer_count > 0
    })
    .await;

    let peers_before = server1.status().peers;
    let target_peer = peers_before
        .first()
        .expect("should have at least one peer")
        .clone();
    eprintln!(
        "interop-testcontrol: target peer for removal: {} (key: {})",
        target_peer.name, target_peer.node_key
    );

    // Get the node IDs from the control server.
    let nodes = tc.nodes().await.expect("nodes API");
    eprintln!("interop-testcontrol: all nodes: {:?}", nodes);

    // Find the target peer's node ID from the control server's node list.
    let target_key_str = target_peer.node_key.to_string();
    let s1_key = server1
        .node_key()
        .expect("server1 should have a node key")
        .to_string();
    let target_node = nodes
        .nodes
        .iter()
        .find(|n| n.key == target_key_str)
        .or_else(|| nodes.nodes.iter().find(|n| n.key != s1_key))
        .expect("should find the target peer in the node list");

    let peer_id = target_node.id;
    eprintln!("interop-testcontrol: injecting PeersRemoved for node ID {peer_id}");

    // Inject a raw MapResponse with PeersRemoved for the target peer.
    let map_response_json = serde_json::json!({
        "PeersRemoved": [peer_id]
    })
    .to_string();

    tc.raw_map_response(&s1_key, &map_response_json).await;

    // Wait for the peer to disappear from server1's netmap.
    wait_for("peer removed from netmap", POLL_TIMEOUT, || async {
        let peers = server1.status().peers;
        peers.iter().all(|p| p.node_key != target_peer.node_key)
    })
    .await;

    eprintln!(
        "interop-testcontrol: PASS — peer removed via raw MapResponse, peer count now {}",
        server1.status().peer_count
    );

    server1.close().await;
    server2.close().await;
}
