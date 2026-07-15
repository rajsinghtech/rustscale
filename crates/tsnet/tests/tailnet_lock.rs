//! Hermetic end-to-end Tailnet Lock control, persistence, filtering, and
//! recovery tests against the in-process Noise testcontrol server.

use std::time::{Duration, Instant};

use rustscale_key::{NLPublic, NodePrivate, NodePublic};
use rustscale_localclient::LocalClient;
use rustscale_tailcfg::{MapResponse, PeerChange};
use rustscale_testcontrol::Server as TestControlServer;
use rustscale_tka::{disablement_kdf, Key, KeyKind};
use rustscale_tsnet::Server;

async fn wait_until(mut condition: impl FnMut() -> bool, message: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out: {message}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lock_init_filters_unsigned_recovers_and_disables() {
    let mut control = TestControlServer::new();
    control.start().await.unwrap();
    control.add_fake_node();

    let state = tempfile::tempdir().unwrap();
    let sockets = tempfile::tempdir().unwrap();
    let socket = sockets.path().join("lock.sock");
    let mut server = Server::builder()
        .disable_portmapping(true)
        .hostname("lock-e2e")
        .auth_key("tskey-test")
        .control_url(control.base_url())
        .state_dir(state.path())
        .localapi_path(&socket)
        .build()
        .unwrap();
    Box::pin(tokio::time::timeout(Duration::from_secs(60), server.up()))
        .await
        .expect("startup deadline")
        .expect("startup");

    let client = LocalClient::new(&socket);
    let initial = client.tailnet_lock_status().await.unwrap();
    assert!(!initial["Enabled"].as_bool().unwrap());
    let public: NLPublic = initial["PublicKey"].as_str().unwrap().parse().unwrap();
    let secret = vec![0x5a; 32];
    let tka_requests_before_init = control.tka_request_connections().len();
    let request = serde_json::json!({
        "Keys": [Key {
            kind: KeyKind::Key25519,
            votes: 1,
            public: public.raw32().to_vec(),
            meta: None,
        }],
        "DisablementValues": [disablement_kdf(&secret)],
        "DisablementSecrets": [secret.clone()],
        "SupportDisablement": [],
        "Resume": false,
    });
    let initialized = client.tailnet_lock_init(&request).await.unwrap();
    let init_request_snapshot = control.tka_request_connections();
    let init_requests = &init_request_snapshot[tka_requests_before_init..];
    assert_eq!(
        init_requests
            .iter()
            .map(|(path, _)| path.as_str())
            .collect::<Vec<_>>(),
        vec!["/machine/tka/init/begin", "/machine/tka/init/finish"]
    );
    assert_eq!(
        init_requests[0].1, init_requests[1].1,
        "init phases must share one authenticated Noise session"
    );
    assert!(initialized["Enabled"].as_bool().unwrap());
    let authority_root = find_dir(state.path(), "tailnet-lock").expect("authority root");
    assert!(authority_root.is_dir());

    // The node present during init was signed atomically. A node introduced
    // later has no signature and must never reach magicsock/routes/status.
    wait_until(
        || server.status().peer_count == 1,
        "initial signed peer visible",
    )
    .await;
    control.add_fake_node();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        server.status().peer_count,
        1,
        "unsigned peer must be filtered"
    );
    let filtered = client.tailnet_lock_status().await.unwrap();
    assert_eq!(filtered["FilteredPeers"].as_array().unwrap().len(), 1);

    // A trusted signer can publish the missing node signature, after which a
    // map update makes the peer visible.
    let unsigned = control
        .all_nodes()
        .into_iter()
        .find(|node| node.Name.is_empty() && node.KeySignature.is_none())
        .expect("new unsigned fake node");
    client
        .tailnet_lock_sign(&serde_json::json!({
            "NodeKey": unsigned.Key,
            "RotationPublic": [],
        }))
        .await
        .unwrap();
    wait_until(|| server.status().peer_count == 2, "signed peer visible").await;

    // A partial delta that rotates only the peer's node key cannot reuse the
    // old signature. Reconstructing then filtering the peer set must drop it.
    let self_node: NodePublic = initialized["NodeKey"].as_str().unwrap().parse().unwrap();
    assert!(control.add_raw_map_response(
        &self_node,
        MapResponse {
            PeersChangedPatch: Some(vec![PeerChange {
                NodeID: unsigned.ID,
                Key: Some(NodePrivate::generate().public()),
                ..Default::default()
            }]),
            ..Default::default()
        },
    ));
    wait_until(
        || server.status().peer_count == 1,
        "partial key/signature delta rejected",
    )
    .await;

    // Restoring the signed key in a second patch makes the peer visible
    // without a full peer resend. The update loop must retain control's raw
    // peer state separately from the fail-closed enforced view.
    assert!(control.add_raw_map_response(
        &self_node,
        MapResponse {
            PeersChangedPatch: Some(vec![PeerChange {
                NodeID: unsigned.ID,
                Key: Some(unsigned.Key.clone()),
                ..Default::default()
            }]),
            ..Default::default()
        },
    ));
    wait_until(
        || server.status().peer_count == 2,
        "matching key patch restores signed peer",
    )
    .await;

    // Remove only the local authority directory and restart. The initial
    // locked netmap must trigger authenticated bootstrap+sync before peers are
    // accepted, rebuilding durable state from canonical CBOR.
    control.resume_auto_map(&self_node);
    server.close().await.unwrap();
    if let Some(cache) = find_file(state.path(), "netmap-cache.json") {
        std::fs::remove_file(cache).unwrap();
    }
    std::fs::remove_dir_all(&authority_root).unwrap();
    let tka_requests_before_recovery = control.tka_request_connections().len();
    let mut recovered = Server::builder()
        .disable_portmapping(true)
        .hostname("lock-e2e")
        .control_url(control.base_url())
        .state_dir(state.path())
        .localapi_path(&socket)
        .build()
        .unwrap();
    Box::pin(tokio::time::timeout(
        Duration::from_secs(60),
        recovered.up(),
    ))
    .await
    .expect("recovery startup deadline")
    .expect("recovery startup");
    let recovery_request_snapshot = control.tka_request_connections();
    let recovery_requests = &recovery_request_snapshot[tka_requests_before_recovery..];
    assert!(recovery_requests
        .iter()
        .any(|(path, _)| path == "/machine/tka/bootstrap"));
    assert!(recovery_requests
        .iter()
        .any(|(path, _)| path == "/machine/tka/sync/offer"));
    assert!(
        recovery_requests
            .iter()
            .all(|(_, connection)| *connection == recovery_requests[0].1),
        "bootstrap and sync must share one authenticated Noise session"
    );
    let recovered_client = LocalClient::new(&socket);
    let deadline = Instant::now() + Duration::from_secs(10);
    let recovered_status = loop {
        let status = recovered_client.tailnet_lock_status().await.unwrap();
        if status["StateConsistent"].as_bool().unwrap_or(false) {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "timed out synchronizing recovered authority"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert!(recovered_status["Enabled"].as_bool().unwrap());
    let recovered_authority_root =
        find_dir(state.path(), "tailnet-lock").expect("recovered authority root");
    assert!(recovered_authority_root.is_dir());

    // Disablement is checked locally, sent over Noise, and only removes local
    // durable state after the confirming disabled netmap supplies the proof.
    recovered_client
        .tailnet_lock_disable(&secret)
        .await
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let status = recovered_client.tailnet_lock_status().await.unwrap();
        if !status["Enabled"].as_bool().unwrap_or(true) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "timed out applying disabled netmap"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!recovered_authority_root.exists());
    recovered.close().await.unwrap();
}

fn find_dir(root: &std::path::Path, name: &str) -> Option<std::path::PathBuf> {
    find_entry(root, name, true)
}

fn find_file(root: &std::path::Path, name: &str) -> Option<std::path::PathBuf> {
    find_entry(root, name, false)
}

fn find_entry(root: &std::path::Path, name: &str, directory: bool) -> Option<std::path::PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in std::fs::read_dir(path).ok()?.flatten() {
            let path = entry.path();
            if path.file_name().is_some_and(|candidate| candidate == name)
                && path.is_dir() == directory
            {
                return Some(path);
            }
            if path.is_dir() {
                pending.push(path);
            }
        }
    }
    None
}
