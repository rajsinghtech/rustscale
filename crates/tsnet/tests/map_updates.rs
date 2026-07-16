use std::time::{Duration, Instant};

use rustscale_key::NodePublic;
use rustscale_tailcfg::MapResponse;
use rustscale_testcontrol::Server as TestControlServer;
use rustscale_tsnet::Server;

async fn wait_until(mut condition: impl FnMut() -> bool, message: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !condition() {
        assert!(Instant::now() < deadline, "timed out: {message}");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn present_empty_peer_snapshot_revokes_all_but_omission_does_not_replace_it() {
    let mut control = TestControlServer::new();
    control.start().await.unwrap();
    control.add_fake_node();

    let state = tempfile::tempdir().unwrap();
    let mut server = Server::builder()
        .disable_portmapping(true)
        .hostname("empty-snapshot")
        .auth_key("tskey-test")
        .control_url(control.base_url())
        .state_dir(state.path())
        .build()
        .unwrap();
    Box::pin(tokio::time::timeout(Duration::from_secs(60), server.up()))
        .await
        .expect("startup deadline")
        .expect("startup");
    wait_until(|| server.status().peer_count == 1, "initial peer snapshot").await;

    let self_key: NodePublic = control
        .all_nodes()
        .into_iter()
        .find(|node| !node.Name.is_empty())
        .expect("registered node")
        .Key;
    assert!(control.add_raw_map_response(
        &self_key,
        MapResponse {
            Peers: Some(Vec::new()),
            ..Default::default()
        },
    ));
    wait_until(
        || server.status().peer_count == 0,
        "present-empty snapshot revocation",
    )
    .await;

    assert!(control.add_raw_map_response(&self_key, MapResponse::default()));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        server.status().peer_count,
        0,
        "an omitted Peers field is a delta/keepalive omission, not a replacement"
    );

    server.close().await.unwrap();
}
