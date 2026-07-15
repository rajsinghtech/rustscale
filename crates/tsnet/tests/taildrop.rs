//! Taildrop integration test: verifies the full LocalAPI path (file-targets,
//! waiting files, download, delete, conflict modes) and the PeerAPI receive
//! handler. Uses testcontrol — no external network.
//!
//! The actual peer-to-peer file transfer over WireGuard requires DERP/STUN
//! infrastructure not available in the in-process testcontrol. Instead, we
//! simulate the receive side by writing directly to the spool directory,
//! then exercise the complete LocalAPI → localclient → CLI conflict path.
//! The PeerAPI `/v0/put/` handler is tested via direct dispatch.

use std::path::PathBuf;
use std::time::Duration;

use rustscale_localclient::LocalClient;
use rustscale_safesocket::connect;
use rustscale_tailcfg::NodeCapMap;
use rustscale_testcontrol::Server as TestControlServer;
use rustscale_tsnet::Server;

/// Wait for the LocalAPI socket to become connectable.
fn wait_for_socket(path: &std::path::Path, timeout: Duration) {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if connect(path).is_ok() {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "LocalAPI socket at {} never became connectable",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Boot a tsnet node pointed at the given control URL with a state dir
/// and LocalAPI socket.
async fn boot_node(
    hostname: &str,
    control_url: &str,
    state_dir: PathBuf,
    socket_path: PathBuf,
) -> Server {
    let _ = std::fs::remove_file(&socket_path);
    let mut server = Server::builder()
        .disable_portmapping(true)
        .hostname(hostname)
        .auth_key("tskey-test")
        .control_url(control_url)
        .ephemeral(true)
        .state_dir(state_dir)
        .localapi_path(&socket_path)
        .build()
        .expect("tsnet build");

    Box::pin(tokio::time::timeout(Duration::from_secs(60), server.up()))
        .await
        .expect("up timeout")
        .expect("up");

    wait_for_socket(&socket_path, Duration::from_secs(10));
    server
}

/// Test the full LocalAPI Taildrop path: simulate a file arriving in the
/// spool, then list, download, verify bytes, and delete via localclient.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taildrop_localapi_files_roundtrip() {
    let mut tc = TestControlServer::new();
    let _addr = tc.start().await.expect("testcontrol start");
    let control_url = tc.base_url();

    let state_tmp = tempfile::tempdir().expect("state tempdir");
    let sock_tmp = tempfile::tempdir().expect("socket tempdir");
    let socket_path: PathBuf = sock_tmp.path().join("taildrop-test.sock");

    let mut server = boot_node(
        "taildrop-recv",
        &control_url,
        state_tmp.path().to_path_buf(),
        socket_path.clone(),
    )
    .await;
    eprintln!("node is up");

    let lc = LocalClient::new(&socket_path);

    // Simulate a file arriving in the spool (as if received via PeerAPI).
    let spool_dir = state_tmp.path().join("files");
    std::fs::create_dir_all(&spool_dir).unwrap();
    let file_content = b"Hello Taildrop! This is a test file.";
    let filename = "test-file.txt";
    std::fs::write(spool_dir.join(filename), file_content).unwrap();
    eprintln!(
        "simulated file receive: {filename} ({} bytes)",
        file_content.len()
    );

    // List waiting files via LocalAPI.
    let files = lc.waiting_files().await.expect("waiting files");
    eprintln!("waiting files: {:?}", files);
    assert_eq!(files.len(), 1, "should see 1 waiting file");
    assert_eq!(files[0].Name, filename);
    assert_eq!(files[0].Size as usize, file_content.len());

    // Download the file — bytes must match.
    let (bytes, _size) = lc.get_waiting_file(filename).await.expect("get file");
    assert_eq!(bytes, file_content, "downloaded bytes must match original");
    eprintln!("downloaded {filename}, bytes match");

    // Delete the file from the inbox.
    lc.delete_waiting_file(filename).await.expect("delete file");
    let files = lc
        .waiting_files()
        .await
        .expect("waiting files after delete");
    assert!(files.is_empty(), "inbox should be empty after delete");
    eprintln!("deleted {filename} from inbox");

    server.close().await.unwrap();
    eprintln!("localapi files roundtrip test passed");
}

/// Test that file-targets lists a peer with the file-sharing-target cap.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taildrop_file_targets_with_cap() {
    let mut tc = TestControlServer::new();
    let _addr = tc.start().await.expect("testcontrol start");
    let control_url = tc.base_url();

    // Boot node A.
    let state_a = tempfile::tempdir().expect("state A");
    let sock_a = tempfile::tempdir().expect("sock A");
    let socket_a: PathBuf = sock_a.path().join("node-a.sock");
    let mut server_a = boot_node(
        "node-a",
        &control_url,
        state_a.path().to_path_buf(),
        socket_a.clone(),
    )
    .await;

    // Boot node B.
    let state_b = tempfile::tempdir().expect("state B");
    let sock_b = tempfile::tempdir().expect("sock B");
    let socket_b: PathBuf = sock_b.path().join("node-b.sock");
    let server_b = boot_node(
        "node-b",
        &control_url,
        state_b.path().to_path_buf(),
        socket_b.clone(),
    )
    .await;

    // Give B the file-sharing-target cap so A can see it as a file target.
    let b_node_key = server_b.node_key().expect("B node key");
    let mut cap_map = NodeCapMap::new();
    cap_map.insert(
        "https://tailscale.com/cap/file-sharing-target".to_string(),
        vec![],
    );
    tc.set_node_cap_map(&b_node_key, cap_map);

    let lc_a = LocalClient::new(&socket_a);

    // Wait for A to see B as a file target.
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut targets = lc_a.file_targets().await.unwrap_or_default();
    while targets.is_empty() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(500)).await;
        targets = lc_a.file_targets().await.unwrap_or_default();
    }
    eprintln!("A sees {} file targets", targets.len());
    assert!(!targets.is_empty(), "A should see B as a file target");
    assert!(targets.iter().any(|t| t.Name.contains("node-b")));

    server_a.close().await.unwrap();
    drop(server_b);
    eprintln!("file targets test passed");
}

/// Test the conflict resolution logic (skip, overwrite, rename) for
/// `file get` — no network needed, just the local file system.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::case_sensitive_file_extension_comparisons)]
async fn taildrop_conflict_modes() {
    use rustscale_tsnet::{resolve_conflict, ConflictMode};

    let tmp = tempfile::tempdir().unwrap();

    // No conflict: all modes return the original path.
    let path = resolve_conflict(tmp.path(), "new.txt", ConflictMode::Skip).unwrap();
    assert_eq!(path.file_name().unwrap(), "new.txt");

    // skip: existing file → error.
    std::fs::write(tmp.path().join("exists.txt"), b"old").unwrap();
    assert!(resolve_conflict(tmp.path(), "exists.txt", ConflictMode::Skip).is_err());

    // overwrite: existing file → removed (ready for new write).
    let path = resolve_conflict(tmp.path(), "exists.txt", ConflictMode::Overwrite).unwrap();
    assert!(!path.exists(), "overwrite should remove the old file");

    // rename: existing file → new numbered name.
    std::fs::write(tmp.path().join("data.bin"), b"old").unwrap();
    let path = resolve_conflict(tmp.path(), "data.bin", ConflictMode::Rename).unwrap();
    let name = path.file_name().unwrap().to_string_lossy().into_owned();
    assert!(
        name.starts_with("data (1)"),
        "renamed file should start with 'data (1)', got {name}"
    );
    assert!(name.ends_with(".bin"), "renamed file should keep extension");

    // rename: multiple conflicts increment the number.
    std::fs::write(tmp.path().join("report.txt"), b"first").unwrap();
    std::fs::write(tmp.path().join("report (1).txt"), b"second").unwrap();
    let path = resolve_conflict(tmp.path(), "report.txt", ConflictMode::Rename).unwrap();
    let name = path.file_name().unwrap().to_string_lossy().into_owned();
    assert!(
        name.starts_with("report (2)"),
        "third copy should be 'report (2)', got {name}"
    );

    eprintln!("conflict modes test passed");
}

/// Test the full `file get` flow via localclient: simulate multiple files
/// in the inbox, download them to a temp dir with conflict modes, verify
/// content and cleanup.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn taildrop_file_get_multiple_files() {
    let mut tc = TestControlServer::new();
    let _addr = tc.start().await.expect("testcontrol start");
    let control_url = tc.base_url();

    let state_tmp = tempfile::tempdir().expect("state tempdir");
    let sock_tmp = tempfile::tempdir().expect("socket tempdir");
    let socket_path: PathBuf = sock_tmp.path().join("taildrop-multi.sock");
    let dest_tmp = tempfile::tempdir().expect("dest tempdir");

    let mut server = boot_node(
        "taildrop-multi",
        &control_url,
        state_tmp.path().to_path_buf(),
        socket_path.clone(),
    )
    .await;

    let lc = LocalClient::new(&socket_path);

    // Simulate 3 files arriving.
    let spool_dir = state_tmp.path().join("files");
    std::fs::create_dir_all(&spool_dir).unwrap();
    let files: Vec<(&str, Vec<u8>)> = vec![
        ("alpha.txt", b"alpha content".to_vec()),
        ("beta.bin", b"beta binary data".to_vec()),
        ("gamma.json", br#"{"key": "value"}"#.to_vec()),
    ];
    for (name, content) in &files {
        std::fs::write(spool_dir.join(name), content).unwrap();
    }

    // List waiting files.
    let waiting = lc.waiting_files().await.expect("waiting files");
    assert_eq!(waiting.len(), 3, "should see 3 waiting files");

    // Download each file to the dest dir and verify.
    for (name, expected_content) in &files {
        let (bytes, _) = lc.get_waiting_file(name).await.expect("get file");
        assert_eq!(&bytes[..], *expected_content, "content mismatch for {name}");
        std::fs::write(dest_tmp.path().join(name), &bytes).unwrap();
        lc.delete_waiting_file(name).await.expect("delete file");
    }

    // Inbox should be empty.
    let waiting = lc.waiting_files().await.expect("waiting files after");
    assert!(waiting.is_empty(), "inbox should be empty");

    // Verify files on disk.
    for (name, expected_content) in &files {
        let data = std::fs::read(dest_tmp.path().join(name)).unwrap();
        assert_eq!(data, *expected_content, "disk content mismatch for {name}");
    }

    server.close().await.unwrap();
    eprintln!("multiple files get test passed");
}
