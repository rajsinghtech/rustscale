//! Integration test: serve config persistence across daemon restart,
//! and profile switch via LocalAPI. Uses testcontrol — no external network.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Duration;

use rustscale_safesocket::connect;
use rustscale_testcontrol::Server as TestControlServer;
use rustscale_tsnet::Server;

fn http_get(socket_path: &std::path::Path, path: &str) -> String {
    let mut conn = connect(socket_path).expect("connect");
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    conn.write_all(req.as_bytes()).expect("write");
    conn.flush().expect("flush");
    let mut buf = Vec::with_capacity(8192);
    conn.read_to_end(&mut buf).expect("read");
    String::from_utf8(buf).unwrap_or_default()
}

fn http_post_body(socket_path: &std::path::Path, path: &str, body: &str) -> String {
    let mut conn = connect(socket_path).expect("connect");
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    conn.write_all(req.as_bytes()).expect("write");
    conn.flush().expect("flush");
    let mut buf = Vec::with_capacity(8192);
    conn.read_to_end(&mut buf).expect("read");
    String::from_utf8(buf).unwrap_or_default()
}

fn http_put(socket_path: &std::path::Path, path: &str) -> String {
    let mut conn = connect(socket_path).expect("connect");
    let req = format!(
        "PUT {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    conn.write_all(req.as_bytes()).expect("write");
    conn.flush().expect("flush");
    let mut buf = Vec::with_capacity(8192);
    conn.read_to_end(&mut buf).expect("read");
    String::from_utf8(buf).unwrap_or_default()
}

fn http_delete(socket_path: &std::path::Path, path: &str) -> String {
    let mut conn = connect(socket_path).expect("connect");
    let req = format!(
        "DELETE {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    conn.write_all(req.as_bytes()).expect("write");
    conn.flush().expect("flush");
    let mut buf = Vec::with_capacity(8192);
    conn.read_to_end(&mut buf).expect("read");
    String::from_utf8(buf).unwrap_or_default()
}

fn status_code(resp: &str) -> u16 {
    let first_line = resp.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    parts
        .get(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0)
}

fn json_body(resp: &str) -> &str {
    match resp.find("\r\n\r\n") {
        Some(pos) => &resp[pos + 4..],
        None => "",
    }
}

fn wait_for_socket(path: &std::path::Path, timeout: Duration) {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if connect(path).is_ok() {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "LocalAPI socket never became connectable"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Serve config persists across daemon restart: POST a config, close the
/// server, restart with the same state dir, GET the config — it should
/// still be there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn serve_config_persists_across_restart() {
    let mut tc = TestControlServer::new();
    let _addr = tc.start().await.expect("testcontrol start");
    let control_url = tc.base_url();

    let state_tmp = tempfile::tempdir().expect("state tempdir");
    let sock_tmp = tempfile::tempdir().expect("socket tempdir");
    let socket_path: PathBuf = sock_tmp.path().join("rustscaled-serve-test.sock");
    let _ = std::fs::remove_file(&socket_path);

    // Start server.
    let mut server = Server::builder()
        .hostname("serve-persist-test")
        .auth_key("tskey-test")
        .control_url(&control_url)
        .ephemeral(true)
        .state_dir(state_tmp.path().to_path_buf())
        .localapi_path(&socket_path)
        .build()
        .expect("build");

    Box::pin(tokio::time::timeout(Duration::from_secs(60), server.up()))
        .await
        .expect("up timeout")
        .expect("up");

    wait_for_socket(&socket_path, Duration::from_secs(10));

    // POST a serve config.
    let config = r#"{"TCP":{"8080":{"HTTP":true}}}"#;
    let resp = http_post_body(&socket_path, "/localapi/v0/serve-config", config);
    eprintln!("POST serve-config response: {resp}");
    assert_eq!(status_code(&resp), 200, "POST should return 200");

    // GET to verify it's there.
    let resp = http_get(&socket_path, "/localapi/v0/serve-config");
    eprintln!("GET serve-config response (before restart): {resp}");
    assert_eq!(status_code(&resp), 200);
    let body = json_body(&resp);
    let cfg: serde_json::Value = serde_json::from_str(body).expect("parse config");
    assert!(
        cfg["TCP"].get("8080").is_some(),
        "config should have port 8080"
    );

    // Close the server.
    server.close().await;
    eprintln!("server closed");

    // Restart with the same state dir.
    let socket_path2: PathBuf = sock_tmp.path().join("rustscaled-serve-test2.sock");
    let _ = std::fs::remove_file(&socket_path2);

    let mut server2 = Server::builder()
        .hostname("serve-persist-test")
        .auth_key("tskey-test")
        .control_url(&control_url)
        .ephemeral(true)
        .state_dir(state_tmp.path().to_path_buf())
        .localapi_path(&socket_path2)
        .build()
        .expect("build 2");

    Box::pin(tokio::time::timeout(Duration::from_secs(60), server2.up()))
        .await
        .expect("up timeout 2")
        .expect("up 2");

    wait_for_socket(&socket_path2, Duration::from_secs(10));

    // GET the config — it should have been loaded from disk.
    let resp = http_get(&socket_path2, "/localapi/v0/serve-config");
    eprintln!("GET serve-config response (after restart): {resp}");
    assert_eq!(
        status_code(&resp),
        200,
        "GET should return 200 after restart"
    );
    let body = json_body(&resp);
    let cfg: serde_json::Value = serde_json::from_str(body).expect("parse config after restart");
    assert!(
        cfg["TCP"].get("8080").is_some(),
        "config should still have port 8080 after restart"
    );

    server2.close().await;
    eprintln!("serve config persistence test passed");
}

/// Profile switch: create two profiles, switch between them, verify current
/// changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn profile_switch_integration() {
    let mut tc = TestControlServer::new();
    let _addr = tc.start().await.expect("testcontrol start");
    let control_url = tc.base_url();

    let state_tmp = tempfile::tempdir().expect("state tempdir");
    let sock_tmp = tempfile::tempdir().expect("socket tempdir");
    let socket_path: PathBuf = sock_tmp.path().join("rustscaled-profile-test.sock");
    let _ = std::fs::remove_file(&socket_path);

    let mut server = Server::builder()
        .hostname("profile-test")
        .auth_key("tskey-test")
        .control_url(&control_url)
        .ephemeral(true)
        .state_dir(state_tmp.path().to_path_buf())
        .localapi_path(&socket_path)
        .build()
        .expect("build");

    Box::pin(tokio::time::timeout(Duration::from_secs(60), server.up()))
        .await
        .expect("up timeout")
        .expect("up");

    wait_for_socket(&socket_path, Duration::from_secs(10));

    // Create profile 1.
    let resp = http_put(&socket_path, "/localapi/v0/profiles");
    eprintln!("PUT profiles (1): {resp}");
    assert_eq!(status_code(&resp), 201, "PUT should create profile 1");

    // Create profile 2.
    let resp = http_put(&socket_path, "/localapi/v0/profiles");
    eprintln!("PUT profiles (2): {resp}");
    assert_eq!(status_code(&resp), 201, "PUT should create profile 2");

    // List profiles — should have 2.
    let resp = http_get(&socket_path, "/localapi/v0/profiles");
    eprintln!("GET profiles: {resp}");
    assert_eq!(status_code(&resp), 200);
    let body = json_body(&resp);
    let profiles: serde_json::Value = serde_json::from_str(body).expect("parse profiles");
    let arr = profiles.as_array().expect("profiles should be an array");
    assert_eq!(arr.len(), 2, "should have 2 profiles");

    let id1 = arr[0]["ID"].as_str().expect("profile 1 ID");
    let id2 = arr[1]["ID"].as_str().expect("profile 2 ID");
    assert_ne!(id1, id2, "IDs should differ");

    // Current should be profile 2 (last created).
    let resp = http_get(&socket_path, "/localapi/v0/profiles/current");
    eprintln!("GET current (should be profile 2): {resp}");
    assert_eq!(status_code(&resp), 200);
    let body = json_body(&resp);
    let current: serde_json::Value = serde_json::from_str(body).expect("parse current");
    assert_eq!(
        current["ID"].as_str(),
        Some(id2),
        "current should be profile 2"
    );

    // Switch to profile 1.
    let resp = http_post_body(&socket_path, &format!("/localapi/v0/profiles/{id1}"), "");
    eprintln!("POST switch to profile 1: {resp}");
    assert_eq!(status_code(&resp), 204, "switch should return 204");

    // Current should now be profile 1.
    let resp = http_get(&socket_path, "/localapi/v0/profiles/current");
    eprintln!("GET current (should be profile 1): {resp}");
    assert_eq!(status_code(&resp), 200);
    let body = json_body(&resp);
    let current: serde_json::Value =
        serde_json::from_str(body).expect("parse current after switch");
    assert_eq!(
        current["ID"].as_str(),
        Some(id1),
        "current should be profile 1 after switch"
    );

    // Delete profile 1.
    let resp = http_delete(&socket_path, &format!("/localapi/v0/profiles/{id2}"));
    eprintln!("DELETE profile 2: {resp}");
    assert_eq!(status_code(&resp), 204, "delete should return 204");

    // List should have 1 profile.
    let resp = http_get(&socket_path, "/localapi/v0/profiles");
    let body = json_body(&resp);
    let profiles: serde_json::Value =
        serde_json::from_str(body).expect("parse profiles after delete");
    assert_eq!(
        profiles.as_array().unwrap().len(),
        1,
        "should have 1 profile after delete"
    );

    server.close().await;
    eprintln!("profile switch integration test passed");
}
