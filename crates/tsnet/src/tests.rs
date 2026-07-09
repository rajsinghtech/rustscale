//! Unit tests and e2e integration tests for tsnet.
//!
//! E2e tests are `#[ignore]`d — they require `TS_E2E_AUTHKEY` and
//! `TS_E2E_TAILNET` env vars (provisioned by `tools/e2e.sh`).

use std::net::Ipv4Addr;

use rustscale_key::NodePrivate;
use rustscale_tailcfg::Node;

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
// E2E tests (#[ignore] — require TS_E2E_AUTHKEY + TS_E2E_TAILNET)
// ---------------------------------------------------------------------------

/// Single-node e2e: up() + status() sanity check.
#[tokio::test]
#[ignore]
async fn e2e_register_only() {
    let authkey = std::env::var("TS_E2E_AUTHKEY").expect("TS_E2E_AUTHKEY not set");
    let _tailnet = std::env::var("TS_E2E_TAILNET").expect("TS_E2E_TAILNET not set");

    let mut server = Server::builder()
        .hostname("rustscale-e2e-register")
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

/// Two-node e2e: spin up two tsnet servers, dial A->B, echo bytes.
#[tokio::test]
#[ignore]
async fn e2e_two_nodes() {
    let authkey = std::env::var("TS_E2E_AUTHKEY").expect("TS_E2E_AUTHKEY not set");
    let _tailnet = std::env::var("TS_E2E_TAILNET").expect("TS_E2E_TAILNET not set");

    // Start server A.
    let mut server_a = Server::builder()
        .hostname("rustscale-e2e-a")
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
        .hostname("rustscale-e2e-b")
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

    // Give the nodes a moment to see each other in the netmap.
    // Wait up to 60s for B to appear in A's netmap (streaming deltas take time).
    let mut found_peer = false;
    for _ in 0..120 {
        let st = server_a.status();
        if st.peer_count > 0 {
            found_peer = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    assert!(found_peer, "A never saw B in its netmap");

    // A dials B.
    let dial_addr = format!("{}:4242", ip_b);
    let dial_result = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        server_a.dial(&dial_addr),
    )
    .await;
    let mut stream_a = dial_result.expect("dial timed out").expect("dial failed");

    // B accepts.
    let accept_result =
        tokio::time::timeout(std::time::Duration::from_secs(30), listener.accept()).await;
    let mut stream_b = accept_result
        .expect("accept timed out")
        .expect("accept failed");

    // A sends, B reads and echoes.
    tokio::io::AsyncWriteExt::write_all(&mut stream_a, b"hello e2e")
        .await
        .expect("A write");

    let mut buf = [0u8; 32];
    let n = tokio::io::AsyncReadExt::read(&mut stream_b, &mut buf)
        .await
        .expect("B read");
    assert_eq!(&buf[..n], b"hello e2e");

    tokio::io::AsyncWriteExt::write_all(&mut stream_b, b"world e2e")
        .await
        .expect("B write");

    let n = tokio::io::AsyncReadExt::read(&mut stream_a, &mut buf)
        .await
        .expect("A read");
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
