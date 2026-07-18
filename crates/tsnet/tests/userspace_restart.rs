#![allow(clippy::large_futures)]

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use rustscale_key::NodePublic;
use rustscale_magicsock::PathClass;
use rustscale_netstack::Listener;
use rustscale_tailcfg::MapResponse;
use rustscale_testcontrol::Server as TestControlServer;
use rustscale_tsnet::Server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ECHO_PORT: u16 = 4611;
const STEP_TIMEOUT: Duration = Duration::from_secs(20);

fn find_file(root: &std::path::Path, name: &str) -> std::path::PathBuf {
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory).expect("read state directory") {
            let path = entry.expect("state entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.file_name().is_some_and(|candidate| candidate == name) {
                return path;
            }
        }
    }
    panic!("{name} not found under {}", root.display());
}

fn v4(server: &Server) -> Ipv4Addr {
    server
        .status()
        .tailscale_ips
        .iter()
        .find_map(|ip| match ip {
            IpAddr::V4(ip) => Some(*ip),
            IpAddr::V6(_) => None,
        })
        .expect("server has a tailnet IPv4 address")
}

async fn wait_for_peer(server: &Server, peer: &NodePublic) {
    let deadline = Instant::now() + STEP_TIMEOUT;
    while server
        .status()
        .peers
        .iter()
        .all(|candidate| &candidate.node_key != peer)
    {
        assert!(
            Instant::now() < deadline,
            "peer did not reach the fresh netmap"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_no_peer(server: &Server, peer: &NodePublic) {
    let deadline = Instant::now() + STEP_TIMEOUT;
    while server
        .status()
        .peers
        .iter()
        .any(|candidate| &candidate.node_key == peer)
    {
        assert!(Instant::now() < deadline, "peer delta was not applied");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn exchange_once(
    client: &mut Server,
    listener: &mut Listener,
    target: Ipv4Addr,
    payload: &[u8],
) {
    let target = format!("{target}:{ECHO_PORT}");
    let dial = tokio::time::timeout(STEP_TIMEOUT, client.dial(&target));
    let accept = tokio::time::timeout(STEP_TIMEOUT, listener.accept());
    let (dial, accept) = tokio::join!(dial, accept);
    let mut outgoing = dial.expect("dial deadline").expect("dial");
    let mut incoming = accept.expect("accept deadline").expect("accept");

    outgoing.write_all(payload).await.expect("write payload");
    let mut received = vec![0; payload.len()];
    incoming
        .read_exact(&mut received)
        .await
        .expect("read payload");
    assert_eq!(received, payload);
    incoming.write_all(&received).await.expect("write echo");
    let mut echoed = vec![0; payload.len()];
    outgoing.read_exact(&mut echoed).await.expect("read echo");
    assert_eq!(echoed, payload);
    outgoing.shutdown().await.expect("shutdown stream");
}

async fn wait_for_direct(server: &Server, peer: &NodePublic) {
    let deadline = Instant::now() + STEP_TIMEOUT;
    while server.peer_path_class(peer) != Some(PathClass::Direct) {
        assert!(Instant::now() < deadline, "peer path did not become direct");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_control_connections(control: &TestControlServer, expected: usize) {
    let deadline = Instant::now() + STEP_TIMEOUT;
    while control.active_noise_connection_count() != expected {
        assert!(
            Instant::now() < deadline,
            "control workers did not drain to {expected}; active={}",
            control.active_noise_connection_count()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn durable_identity_rotates_disco_and_reestablishes_direct_after_restart() {
    let mut control = TestControlServer::new();
    control.start().await.expect("start test control");
    let server_state = tempfile::tempdir().expect("server state");
    let client_state = tempfile::tempdir().expect("client state");

    let mut service = Server::builder()
        .hostname("restart-service")
        .auth_key("tskey-test")
        .ephemeral(false)
        .disable_portmapping(true)
        .control_url(control.base_url())
        .state_dir(server_state.path())
        .build()
        .expect("build service");
    tokio::time::timeout(STEP_TIMEOUT, service.up())
        .await
        .expect("service startup deadline")
        .expect("service startup");
    let service_key = service.node_key().expect("service node key");
    let service_endpoints = service
        .magicsock()
        .expect("service magicsock")
        .local_endpoints();
    let service_ip = v4(&service);
    let mut listener = service.listen(ECHO_PORT).await.expect("listen");

    let mut first = Server::builder()
        .hostname("restart-client")
        .auth_key("tskey-test")
        .ephemeral(false)
        .disable_portmapping(true)
        .control_url(control.base_url())
        .state_dir(client_state.path())
        .build()
        .expect("build first client");
    tokio::time::timeout(STEP_TIMEOUT, first.up())
        .await
        .expect("first startup deadline")
        .expect("first startup");
    let node_key = first.node_key().expect("first node key");
    let first_control_node = control.node(&node_key).expect("first control node");
    let first_magicsock = first.magicsock().expect("first magicsock");
    let first_disco = first_magicsock.disco_public();
    control.set_node_endpoints(&service_key, service_endpoints.clone());
    control.set_node_endpoints(&node_key, first_magicsock.local_endpoints());
    wait_for_peer(&first, &service_key).await;
    wait_for_direct(&first, &service_key).await;
    exchange_once(&mut first, &mut listener, service_ip, b"first").await;

    // Even a streaming response that happens to carry Node, Peers, and Domain
    // is not a complete bootstrap snapshot: its other optional fields remain
    // deltas. Prove it is applied live but cannot replace the normalized
    // one-shot restart cache.
    let cache_path = find_file(client_state.path(), "netmap-cache.json");
    let cached_before_stream: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&cache_path).expect("read initial netmap cache"))
            .expect("parse initial netmap cache");
    assert!(cached_before_stream["map_response"]["DERPMap"].is_object());
    assert!(cached_before_stream["map_response"]["PacketFilter"].is_array());
    assert!(control.add_raw_map_response(
        &node_key,
        MapResponse {
            Node: Some(control.node(&node_key).expect("stream self node")),
            Peers: Some(Vec::new()),
            Domain: "fake-control.example.net".into(),
            ..Default::default()
        },
    ));
    wait_for_no_peer(&first, &service_key).await;
    // A following delta is an explicit processing barrier: map responses are
    // applied serially, so observing this peer proves the preceding full-looking
    // response reached the end of the old cache-write location.
    assert!(control.add_raw_map_response(
        &node_key,
        MapResponse {
            PeersChanged: vec![control.node(&service_key).expect("stream peer node")],
            ..Default::default()
        },
    ));
    wait_for_peer(&first, &service_key).await;
    let cached_after_stream: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&cache_path).expect("reread netmap cache"))
            .expect("reparse netmap cache");
    assert_eq!(
        cached_after_stream, cached_before_stream,
        "incomplete streaming map replaced the restart snapshot"
    );
    control.resume_auto_map(&node_key);
    control.set_node_endpoints(&service_key, service_endpoints.clone());
    wait_for_peer(&first, &service_key).await;
    wait_for_direct(&first, &service_key).await;

    tokio::time::timeout(STEP_TIMEOUT, first.close())
        .await
        .expect("first close deadline")
        .expect("first close");
    wait_for_control_connections(&control, 1).await;

    // The one-shot map is cached as a materialized full snapshot, never as a
    // raw PeersChanged delta. Poison its peer list to prove online restart
    // still prefers fresh control state over otherwise valid stale cache.
    let mut cached: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&cache_path).expect("read netmap cache"))
            .expect("parse netmap cache");
    assert!(cached["map_response"]["Peers"].is_array());
    assert!(cached["map_response"]["PeersChanged"].is_null());
    cached["map_response"]["Peers"] = serde_json::json!([]);
    std::fs::write(
        &cache_path,
        serde_json::to_vec(&cached).expect("serialize poisoned cache"),
    )
    .expect("poison cached peers");

    let mut second = Server::builder()
        .hostname("restart-client")
        .auth_key("tskey-test")
        .ephemeral(false)
        .disable_portmapping(true)
        .control_url(control.base_url())
        .state_dir(client_state.path())
        .build()
        .expect("build restarted client");
    tokio::time::timeout(STEP_TIMEOUT, second.up())
        .await
        .expect("restart startup deadline")
        .expect("restart startup");
    assert_eq!(
        second.node_key(),
        Some(node_key.clone()),
        "durable node identity changed"
    );
    let second_disco = second.magicsock().expect("second magicsock").disco_public();
    assert_ne!(
        second_disco, first_disco,
        "process-local disco identity was reused"
    );
    assert_eq!(
        control.num_nodes(),
        2,
        "restart registered a stale extra node"
    );
    let second_control_node = control.node(&node_key).expect("restarted control node");
    assert_eq!(second_control_node.ID, first_control_node.ID);
    assert_eq!(second_control_node.StableID, first_control_node.StableID);
    assert_eq!(second_control_node.Machine, first_control_node.Machine);

    control.set_node_endpoints(&service_key, service_endpoints);
    control.set_node_endpoints(
        &node_key,
        second
            .magicsock()
            .expect("second magicsock")
            .local_endpoints(),
    );
    wait_for_peer(&second, &service_key).await;
    wait_for_direct(&second, &service_key).await;
    exchange_once(&mut second, &mut listener, service_ip, b"second").await;
    tokio::time::timeout(STEP_TIMEOUT, second.close())
        .await
        .expect("second close deadline")
        .expect("second close");
    wait_for_control_connections(&control, 1).await;
    tokio::time::timeout(STEP_TIMEOUT, service.close())
        .await
        .expect("service close deadline")
        .expect("service close");
    wait_for_control_connections(&control, 0).await;
}
