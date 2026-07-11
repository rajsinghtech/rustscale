//! Self-test: boot testcontrol + a real tsnet Server, verify registration,
//! netmap delivery, Running state, and peer appearance via add_fake_node.
//!
//! No external network access required.

use std::time::Duration;

use rustscale_testcontrol::Server;

/// Boot testcontrol on a random loopback port, point a tsnet Server at it,
/// verify the node registers, receives a netmap, reaches Running, and then
/// verify that add_fake_node() causes a new peer to appear in the tsnet
/// node's netmap via the streaming map poll.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::large_futures)]
async fn testcontrol_full_flow() {
    // 1. Start testcontrol.
    let mut tc = Server::new();
    let _addr = tc.start().await.expect("testcontrol start");
    let control_url = tc.base_url();
    eprintln!("testcontrol listening at {control_url}");

    // 2. Build a tsnet Server pointing at testcontrol.
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut server = rustscale_tsnet::Server::builder()
        .hostname("testcontrol-selftest")
        .auth_key("tskey-test")
        .control_url(&control_url)
        .ephemeral(true)
        .state_dir(tmp.path().to_path_buf())
        .build()
        .expect("tsnet build");

    // 3. Bring it up (60s hard timeout — no external network needed).
    eprintln!("bringing tsnet node up...");
    let up_result = tokio::time::timeout(Duration::from_secs(60), server.up()).await;
    if let Ok(Ok(())) = &up_result {
        eprintln!("tsnet node is up");
    } else if let Ok(Err(e)) = &up_result {
        panic!("tsnet up() failed: {e}");
    } else {
        panic!("tsnet up() timed out (60s)");
    }
    // 4. Verify status: up, has tailscale IPs.
    let status = server.status();
    assert!(status.up, "server should be up");
    assert!(
        !status.tailscale_ips.is_empty(),
        "should have at least one tailscale IP"
    );
    eprintln!(
        "tsnet node up: IPs={:?}, peers={}",
        status.tailscale_ips, status.peer_count
    );

    // 5. Verify the node registered with testcontrol.
    assert_eq!(tc.num_nodes(), 1, "testcontrol should have 1 registered node");

    // 6. Wait for the streaming map poll to be active.
    let node_key = tc.all_nodes()[0].Key.clone();
    eprintln!("waiting for node {:?} to enter streaming map poll...", node_key);
    tc.await_node_in_map_request(&node_key, Duration::from_secs(30))
        .await
        .expect("node should enter streaming map poll within 30s");
    eprintln!("node is in streaming map poll");

    // 7. Inject a fake node and verify it appears in the tsnet node's netmap.
    eprintln!("adding fake node...");
    tc.add_fake_node();
    assert_eq!(tc.num_nodes(), 2, "testcontrol should now have 2 nodes");

    // 8. Poll tsnet status until the fake peer appears (30s deadline).
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let st = server.status();
        if st.peer_count > 0 {
            eprintln!(
                "fake peer appeared in netmap: {} peers, first={:?}",
                st.peer_count,
                st.peers.first().map(|p| &p.name)
            );
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "fake peer never appeared in tsnet netmap (30s)\n\
             testcontrol nodes: {}, in_serve_map: {}",
            tc.num_nodes(),
            tc.in_serve_map()
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // 9. Clean up.
    server.close().await;
    eprintln!("tsnet node closed; test passed");
}
