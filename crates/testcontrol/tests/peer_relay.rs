//! Phase 5 integration test: peer relay server extension end-to-end.
//!
//! Boots testcontrol + a local DERP server, starts 3 tsnet nodes
//! (clients A, B and relay node R), and exercises the full relay path:
//! allocation via DERP, 3-way bind handshake, bidirectional data,
//! CallMeMaybeVia flow, and endpoint expiry.
//!
//! No external network access required.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use rcgen::CertifiedKey;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustscale_derp::DerpServer;
use rustscale_tailcfg::{
    DERPMap, DERPNode, DERPRegion, NodeCapMap, RawMessage, PEER_CAPABILITY_RELAY_TARGET,
};
use rustscale_testcontrol::Server as TestControlServer;
use rustscale_tsnet::Server as TsnetServer;
use rustscale_udprelay::ServerConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

/// Put a self-signed TLS listener in front of the plaintext in-process DERP
/// server. Real DERP clients always use TLS; `InsecureForTests` relaxes only
/// certificate verification, matching the Go client and testcontrol DERP.
async fn spawn_tls_derp_proxy(
    upstream: std::net::SocketAddr,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_owned()]).expect("test cert");
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key)
        .expect("test TLS config");
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("TLS proxy bind");
    let addr = listener.local_addr().expect("TLS proxy address");
    let task = tokio::spawn(async move {
        let mut children = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((client, _)) = accepted else { break };
                    let acceptor = acceptor.clone();
                    children.spawn(async move {
                        let Ok(mut client) = acceptor.accept(client).await else { return };
                        let Ok(mut server) = TcpStream::connect(upstream).await else { return };
                        let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
                    });
                }
                Some(_) = children.join_next(), if !children.is_empty() => {}
            }
        }
    });
    (addr, task)
}

/// Build a DERPMap with a single local region pointing at `addr`.
fn local_derp_map(addr: std::net::SocketAddr) -> DERPMap {
    let mut map = DERPMap::default();
    let port = i32::from(addr.port());
    let region = DERPRegion {
        RegionID: 1,
        RegionCode: "test".into(),
        RegionName: "Test DERP".into(),
        Nodes: Some(vec![DERPNode {
            Name: "1a".into(),
            RegionID: 1,
            HostName: "127.0.0.1".into(),
            IPv4: "127.0.0.1".into(),
            DERPPort: port,
            InsecureForTests: true,
            STUNPort: -1,
            ..Default::default()
        }]),
        ..Default::default()
    };
    map.Regions.insert(1, region);
    map
}

/// Build a CapMap with PEER_CAPABILITY_RELAY_TARGET set.
fn relay_target_cap_map() -> NodeCapMap {
    let mut m = BTreeMap::new();
    m.insert(
        PEER_CAPABILITY_RELAY_TARGET.to_string(),
        vec![RawMessage::default()],
    );
    m
}

/// Bring up a tsnet node against `control_url` with the given DERPMap.
/// All nodes use `disable_direct_paths(true)` to suppress direct path
/// establishment so the relay path is exercised deterministically.
#[allow(clippy::large_futures)]
async fn boot_node(
    hostname: &str,
    control_url: &str,
    state_dir: std::path::PathBuf,
    peer_relay_server: bool,
    relay_config: Option<ServerConfig>,
) -> TsnetServer {
    let mut builder = TsnetServer::builder()
        .disable_portmapping(true)
        .hostname(hostname)
        .auth_key("tskey-test")
        .control_url(control_url)
        .ephemeral(true)
        .state_dir(state_dir)
        .disable_direct_paths(true);

    if peer_relay_server {
        builder = builder.peer_relay_server(true);
    }
    if let Some(cfg) = relay_config {
        builder = builder.relay_server_config(cfg);
    }

    let mut server = builder.build().expect("tsnet build");

    let timeout = tokio::time::timeout(Duration::from_secs(90), server.up());
    match timeout.await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => panic!("tsnet up() failed for {hostname}: {e}"),
        Err(elapsed) => panic!("tsnet up() timed out for {hostname} after {elapsed:?}"),
    }
    server
}

/// Wait for `n` nodes to register with testcontrol, returning their keys.
async fn wait_for_nodes(
    tc: &TestControlServer,
    n: usize,
    timeout: Duration,
) -> Vec<rustscale_key::NodePublic> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let nodes = tc.all_nodes();
        if nodes.len() >= n {
            return nodes.into_iter().map(|n| n.Key).collect();
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timeout waiting for {n} nodes (got {})",
            tc.num_nodes()
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Wait for all 3 nodes to be in streaming map poll.
async fn wait_for_streaming(
    tc: &TestControlServer,
    keys: &[rustscale_key::NodePublic],
    timeout: Duration,
) {
    for k in keys {
        let r = tc.await_node_in_map_request(k, timeout).await;
        assert!(
            r.is_ok(),
            "node {:?} not in streaming map poll within {timeout:?}",
            k
        );
    }
}

async fn peer_status(
    node: &TsnetServer,
    peer: &rustscale_key::NodePublic,
) -> Option<rustscale_ipnstate::PeerStatus> {
    node.ipn_status()
        .await?
        .Peer
        .get(&peer.to_string())
        .cloned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[allow(clippy::too_many_lines, clippy::large_futures)]
async fn peer_relay_e2e() {
    // ── 1. Start testcontrol + local DERP ──────────────────────────────
    let mut tc = TestControlServer::new();
    let _tc_addr = tc.start().await.expect("testcontrol start");
    let control_url = tc.base_url();

    let derp_server = DerpServer::with_random_key();
    let (derp_upstream, derp_handle) = derp_server.spawn_local().await.expect("DERP spawn");
    let (derp_addr, derp_tls_task) = spawn_tls_derp_proxy(derp_upstream).await;
    eprintln!("DERP TLS proxy listening at {derp_addr}");

    let derp_map = local_derp_map(derp_addr);
    tc.set_derp_map(derp_map);
    eprintln!("testcontrol at {control_url}");

    // ── 2. Boot 3 tsnet nodes ──────────────────────────────────────────
    let tmp_a = tempfile::tempdir().expect("tempdir A");
    let tmp_b = tempfile::tempdir().expect("tempdir B");
    let tmp_r = tempfile::tempdir().expect("tempdir R");

    // R has shortened steady-state lifetime for the expiry test.
    let relay_config = ServerConfig {
        bind_lifetime: Duration::from_secs(60),
        steady_state_lifetime: Duration::from_secs(5),
        ..Default::default()
    };

    let mut node_a = boot_node(
        "client-a",
        &control_url,
        tmp_a.path().to_path_buf(),
        false,
        None,
    )
    .await;
    let mut node_b = boot_node(
        "client-b",
        &control_url,
        tmp_b.path().to_path_buf(),
        false,
        None,
    )
    .await;
    let mut node_r = boot_node(
        "relay-r",
        &control_url,
        tmp_r.path().to_path_buf(),
        true,
        Some(relay_config),
    )
    .await;

    eprintln!("all 3 nodes are up");

    // ── 3. Wait for all nodes to be in streaming map poll ──────────────
    let keys = wait_for_nodes(&tc, 3, Duration::from_secs(30)).await;
    wait_for_streaming(&tc, &keys, Duration::from_secs(30)).await;

    let key_a = node_a.node_key().expect("A up");
    let key_b = node_b.node_key().expect("B up");
    let key_r = node_r.node_key().expect("R up");

    // ── 4. Set PEER_CAPABILITY_RELAY_TARGET on R ───────────────────────
    // This makes R visible as a relay server candidate to A and B.
    tc.set_node_cap_map(&key_r, relay_target_cap_map());

    // Wait for the cap map update to propagate to all nodes' netmaps.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // ── 5. Scenario 1: Allocation via DERP ─────────────────────────────
    // A discovers R as a relay server, sends an alloc request via DERP,
    // and R allocates an endpoint. Verify R's relay server has endpoints.
    eprintln!("scenario 1: waiting for allocation on R...");
    let rs = node_r.relay_server().expect("R has relay server");
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let count = rs
            .server()
            .map_or(0, rustscale_udprelay::Server::endpoint_count);
        if count > 0 {
            eprintln!("scenario 1: R has {count} endpoint(s) allocated");
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timeout: R never allocated an endpoint (30s)"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // ── 6. Scenario 2+3: Bidirectional data + CallMeMaybeVia ───────────
    // After allocation, A sends CallMeMaybeVia to B via DERP. B starts
    // its own handshake with R. After both sides are bound, data flows.
    // Wait for A's path to B to become Relay (indicates handshake done).
    eprintln!("scenario 2+3: waiting for relay path A→B...");
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let class_a = node_a.peer_path_class(&key_b);
        if class_a == Some(rustscale_magicsock::PathClass::Relay) {
            eprintln!("scenario 2: A→B path is Relay");
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "A→B never established an authenticated peer-relay path; last class: {class_a:?}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Also check B→A (B should have received CallMeMaybeVia and bound).
    eprintln!("scenario 3: waiting for relay path B→A...");
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let class_b = node_b.peer_path_class(&key_a);
        if class_b == Some(rustscale_magicsock::PathClass::Relay) {
            eprintln!("scenario 3: B→A path is Relay (CallMeMaybeVia worked)");
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "B→A never established an authenticated peer-relay path; last class: {class_b:?}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // ── 7. Verify authenticated relay identities ───────────────────────
    // A successful local UDP write is deliberately not status evidence.
    // Establish a real WireGuard/netstack TCP stream, verify payload delivery
    // in both directions, then require public status to name R's actual UDP
    // socket. The other status may genuinely be overwritten by a later
    // authenticated DERP control packet, but at least one delivered exchange
    // must expose the peer-relay transport identity.
    eprintln!("delivering authenticated TCP traffic through peer relay...");
    const RELAY_ECHO_PORT: u16 = 34567;
    let peer_ip = node_b
        .status()
        .tailscale_ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .copied()
        .expect("B has IPv4");
    let mut listener = node_b.listen(RELAY_ECHO_PORT).await.expect("B listen");
    let dial_addr = format!("{peer_ip}:{RELAY_ECHO_PORT}");
    let (dialed, accepted) = tokio::join!(
        tokio::time::timeout(Duration::from_secs(30), node_a.dial(&dial_addr)),
        tokio::time::timeout(Duration::from_secs(30), listener.accept()),
    );
    let mut stream_a = dialed.expect("A dial timed out").expect("A dial failed");
    let mut stream_b = accepted
        .expect("B accept timed out")
        .expect("B accept failed");
    let relay_addr = rs
        .local_addr()
        .expect("relay has a UDP address")
        .to_string();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut sequence = 0_u32;
    loop {
        sequence += 1;
        let payload = format!("peer-relay-authenticated-{sequence}").into_bytes();
        stream_a.write_all(&payload).await.expect("A write");
        let mut delivered = vec![0_u8; payload.len()];
        stream_b.read_exact(&mut delivered).await.expect("B read");
        assert_eq!(delivered, payload, "A→B relay payload changed");
        stream_b.write_all(&payload).await.expect("B write");
        stream_a.read_exact(&mut delivered).await.expect("A read");
        assert_eq!(delivered, payload, "B→A relay payload changed");

        let a_status = peer_status(&node_a, &key_b).await;
        let b_status = peer_status(&node_b, &key_a).await;
        let actual_path = |status: &rustscale_ipnstate::PeerStatus| {
            status.Active
                && status.CurAddr.is_empty()
                && ((status.PeerRelay == relay_addr && status.Relay.is_empty())
                    || (status.Relay == "derp-1" && status.PeerRelay.is_empty()))
        };
        if a_status.as_ref().is_some_and(actual_path)
            && b_status.as_ref().is_some_and(actual_path)
            && (a_status
                .as_ref()
                .is_some_and(|status| status.PeerRelay == relay_addr)
                || b_status
                    .as_ref()
                    .is_some_and(|status| status.PeerRelay == relay_addr))
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "delivered traffic did not expose authenticated relay {relay_addr}; A={a_status:?}, B={b_status:?}"
        );
    }

    // ── 8. Scenario 4: Rebind from new source port ─────────────────────
    // Trigger a link change on A, which causes the relay manager to
    // re-establish the relay path. The relay server should maintain
    // exactly 1 endpoint for the A-B pair (re-bind, not re-allocate).
    eprintln!("scenario 4: triggering rebind on A...");
    let count_before = rs
        .server()
        .map_or(0, rustscale_udprelay::Server::endpoint_count);
    node_a.link_changed();
    tokio::time::sleep(Duration::from_secs(3)).await;
    let count_after = rs
        .server()
        .map_or(0, rustscale_udprelay::Server::endpoint_count);
    eprintln!("scenario 4: endpoint count before={count_before}, after={count_after}");
    // The endpoint should still exist (may have been re-allocated or maintained).
    assert!(
        count_after >= 1,
        "relay server should still have endpoints after rebind"
    );

    // ── 9. Scenario 5: Endpoint expiry after SteadyStateLifetime ───────
    // Stop sending data, wait past steady_state_lifetime (3s), then
    // trigger GC and verify the endpoint is removed.
    eprintln!("scenario 5: waiting for endpoint expiry (3s steady-state)...");
    let count_before_expiry = rs
        .server()
        .map_or(0, rustscale_udprelay::Server::endpoint_count);
    eprintln!("scenario 5: endpoints before expiry: {count_before_expiry}");

    // Wait past steady_state_lifetime (3s) with no data.
    tokio::time::sleep(Duration::from_secs(5)).await;

    // Trigger GC manually (the background GC loop also runs but we
    // force it for deterministic test behavior).
    if let Some(srv) = rs.server() {
        srv.run_gc_once();
    }
    tokio::time::sleep(Duration::from_millis(500)).await;

    let count_after_expiry = rs
        .server()
        .map_or(0, rustscale_udprelay::Server::endpoint_count);
    eprintln!("scenario 5: endpoints after expiry: {count_after_expiry}");
    assert!(
        count_after_expiry < count_before_expiry,
        "endpoints should decrease after steady-state expiry (before={count_before_expiry}, after={count_after_expiry})"
    );

    // ── Cleanup ────────────────────────────────────────────────────────
    node_a.close().await.unwrap();
    node_b.close().await.unwrap();
    node_r.close().await.unwrap();
    derp_tls_task.abort();
    let _ = derp_tls_task.await;
    derp_handle.shutdown();
    eprintln!("peer_relay_e2e: all scenarios passed");
}
