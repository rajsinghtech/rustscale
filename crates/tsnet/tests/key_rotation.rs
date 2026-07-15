//! Integration test for key rotation / re-registration.
//!
//! Verifies that when the control server signals key expiry via
//! `Node.KeyExpiry`, the client re-registers with `OldNodeKey` + a
//! fresh `NodeKey`, and the control server transfers the node identity.

use std::path::PathBuf;
use std::time::Duration;

use rustscale_testcontrol::Server as TestControlServer;
use rustscale_tsnet::Server;

/// Register → force expiry → re-register with OldNodeKey → verify new key.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn key_rotation_reregisters_with_old_node_key() {
    let mut tc = TestControlServer::new();
    let _addr = tc.start().await.expect("testcontrol start");
    let control_url = tc.base_url();

    let state_tmp = tempfile::tempdir().expect("state tempdir");

    // Start the server.
    let mut server = Server::builder()
        .hostname("key-rot-test")
        .auth_key("tskey-test")
        .control_url(&control_url)
        .ephemeral(true)
        .state_dir(state_tmp.path().to_path_buf())
        .build()
        .expect("build");

    Box::pin(tokio::time::timeout(Duration::from_secs(60), server.up()))
        .await
        .expect("up timeout")
        .expect("up");

    let initial_key = server.node_key().expect("node key after up");
    assert!(
        !initial_key.is_zero(),
        "initial node key should be non-zero"
    );
    assert_eq!(
        tc.num_nodes(),
        1,
        "testcontrol should have exactly 1 node after registration"
    );

    // Force key expiry on the node. The next MapResponse will carry
    // Node.KeyExpiry in the past, triggering re-registration.
    tc.expire_node_key(&initial_key);

    // Wait for the map_update task to detect expiry and re-register.
    // The key rotation happens asynchronously in the map poll loop.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        assert!(
            std::time::Instant::now() <= deadline,
            "key rotation did not complete within 30s"
        );
        // After key rotation, testcontrol should have 2 nodes: the
        // original (old key, not retired since no followup) and the
        // new key (transferred identity).
        if tc.num_nodes() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    // Verify: testcontrol now has 2 nodes (old + new).
    assert_eq!(
        tc.num_nodes(),
        2,
        "testcontrol should have 2 nodes after key rotation (old + new)"
    );

    // Verify: the new node exists in testcontrol and has the same
    // IP addresses as the old node (identity transferred).
    let all_nodes = tc.all_nodes();
    let old_node = all_nodes
        .iter()
        .find(|n| n.Key == initial_key)
        .expect("old node should still exist in testcontrol");
    let new_node = all_nodes
        .iter()
        .find(|n| n.Key != initial_key && !n.Key.is_zero())
        .expect("new node should exist in testcontrol");

    assert_eq!(
        new_node.Addresses, old_node.Addresses,
        "new node should have same addresses as old node (identity transferred)"
    );

    // Verify: persisted state has old_node_key set.
    let state_path: PathBuf = find_state_file(state_tmp.path()).expect("scoped state file");
    let state_json = std::fs::read_to_string(&state_path).expect("read state file");
    assert!(
        state_json.contains("old_node_key"),
        "persisted state should contain old_node_key: {state_json}"
    );

    server.close().await;
    eprintln!("key rotation integration test passed");
}

fn find_state_file(root: &std::path::Path) -> Option<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in std::fs::read_dir(path).ok()?.flatten() {
            let path = entry.path();
            if path
                .file_name()
                .is_some_and(|name| name == "tsnet-state.json")
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

/// Verify that LoginFlags constants exist and have correct values.
#[test]
fn login_flags_constants() {
    use rustscale_controlclient::{LOGIN_DEFAULT, LOGIN_EPHEMERAL, LOGIN_INTERACTIVE};

    assert_eq!(LOGIN_DEFAULT.0, 0);
    assert_eq!(LOGIN_INTERACTIVE.0, 1);
    assert_eq!(LOGIN_EPHEMERAL.0, 2);
    assert!(LOGIN_INTERACTIVE.is_interactive());
    assert!(!LOGIN_DEFAULT.is_interactive());
    assert!(LOGIN_EPHEMERAL.is_ephemeral());
}

/// Verify that PersistedState serializes/deserializes old_node_key.
#[test]
fn persisted_state_old_node_key_roundtrip() {
    use rustscale_key::NodePrivate;
    use rustscale_tsnet::PersistedState;

    let mut state = PersistedState::generate();
    assert!(
        state.old_node_key.is_none(),
        "fresh state should have no old_node_key"
    );

    state.old_node_key = Some(NodePrivate::generate());

    let json = serde_json::to_string(&state).expect("serialize");
    assert!(
        json.contains("old_node_key"),
        "JSON should contain old_node_key: {json}"
    );

    let back: PersistedState = serde_json::from_str(&json).expect("deserialize");
    assert!(
        back.old_node_key.is_some(),
        "deserialized state should have old_node_key"
    );
    assert_eq!(back, state, "roundtrip should be identity");
}

/// Verify that a PersistedState without old_node_key (old format)
/// still deserializes correctly (backward compat).
#[test]
fn persisted_state_backward_compat_no_old_node_key() {
    use rustscale_tsnet::PersistedState;

    let json = r#"{
        "node_key":"privkey:0000000000000000000000000000000000000000000000000000000000000000",
        "machine_key":"privkey:0000000000000000000000000000000000000000000000000000000000000000",
        "disco_key":"privkey:0000000000000000000000000000000000000000000000000000000000000000",
        "node_id":0,
        "stable_node_id":""
    }"#;
    let state: PersistedState = serde_json::from_str(json).expect("deserialize old format");
    assert!(
        state.old_node_key.is_none(),
        "old format should deserialize with old_node_key=None"
    );
}
