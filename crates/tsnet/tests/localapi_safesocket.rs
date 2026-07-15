//! Integration test: boot an in-process testcontrol fake control server,
//! bring up a tsnet Server with the LocalAPI enabled on a safesocket, then
//! connect via `safesocket::connect` and verify that GET /localapi/v0/status
//! and GET /localapi/v0/health return 200 with valid JSON.
//!
//! No external network access required — everything runs in-process.

use std::path::PathBuf;
use std::time::Duration;

use rustscale_safesocket::connect;
use rustscale_testcontrol::Server as TestControlServer;
use rustscale_tsnet::Server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Build an HTTP/1.1 GET request for the given path.
fn http_get(path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").into_bytes()
}

/// Send an HTTP request over a Unix socket and read the full response.
async fn unix_http_request(socket_path: &std::path::Path, path: &str) -> String {
    let mut conn = connect(socket_path).expect("connect to LocalAPI socket");
    let req = http_get(path);
    conn.write_all(&req)
        .await
        .expect("write HTTP request to socket");
    conn.flush().await.expect("flush");
    let mut buf = Vec::with_capacity(8192);
    conn.read_to_end(&mut buf)
        .await
        .expect("read HTTP response from socket");
    String::from_utf8(buf).unwrap_or_default()
}

/// Extract the HTTP status code from a response.
fn status_code(resp: &str) -> u16 {
    let first_line = resp.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    parts
        .get(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0)
}

/// Extract the JSON body from an HTTP response (everything after \r\n\r\n).
fn json_body(resp: &str) -> &str {
    match resp.find("\r\n\r\n") {
        Some(pos) => &resp[pos + 4..],
        None => "",
    }
}

/// Wait for the LocalAPI socket to become connectable, polling every 200ms
/// up to `timeout`.
fn wait_for_socket(path: &std::path::Path, timeout: Duration) {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if connect(path).is_ok() {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "LocalAPI socket at {} never became connectable within {timeout:?}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn close_prestarted_localapi_allows_immediate_rebind() {
    let state_tmp = tempfile::tempdir().expect("state tempdir");
    let sock_tmp = tempfile::tempdir().expect("socket tempdir");
    let socket_path = sock_tmp.path().join("prestarted.sock");
    let mut server = Server::builder()
        .hostname("prestarted-close-test")
        .state_dir(state_tmp.path().to_path_buf())
        .localapi_path(&socket_path)
        .build()
        .expect("tsnet build");

    let first_commands = server
        .start_localapi_only()
        .await
        .expect("start pre-login LocalAPI");
    let live_connection = connect(&socket_path).expect("connect pre-login LocalAPI");
    drop(first_commands);
    server
        .close()
        .await
        .into_result()
        .expect("close pre-login state");
    drop(live_connection);
    assert!(connect(&socket_path).is_err());

    for attempt in 0..3 {
        let commands = server
            .start_localapi_only()
            .await
            .unwrap_or_else(|error| panic!("NeedsLogin rebind {attempt}: {error}"));
        assert!(connect(&socket_path).is_ok());
        drop(commands);
        server
            .close()
            .await
            .into_result()
            .unwrap_or_else(|error| panic!("NeedsLogin close {attempt}: {error}"));
        assert!(connect(&socket_path).is_err());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn localapi_status_and_health_over_safesocket() {
    // 1. Start testcontrol.
    let mut tc = TestControlServer::new();
    let _addr = tc.start().await.expect("testcontrol start");
    let control_url = tc.base_url();
    eprintln!("testcontrol listening at {control_url}");

    // 2. Prepare temp dirs for state and socket.
    let state_tmp = tempfile::tempdir().expect("state tempdir");
    let sock_tmp = tempfile::tempdir().expect("socket tempdir");
    let socket_path: PathBuf = sock_tmp.path().join("rustscaled-test.sock");
    let _ = std::fs::remove_file(&socket_path);

    // 3. Build a tsnet Server with LocalAPI enabled on the safesocket path.
    let mut server = Server::builder()
        .hostname("localapi-test")
        .auth_key("tskey-test")
        .control_url(&control_url)
        .ephemeral(true)
        .state_dir(state_tmp.path().to_path_buf())
        .localapi_path(&socket_path)
        .build()
        .expect("tsnet build");

    // 4. Bring it up (60s timeout — no external network needed).
    eprintln!("bringing tsnet node up...");
    let up_result = Box::pin(tokio::time::timeout(Duration::from_secs(60), server.up())).await;
    match &up_result {
        Ok(Ok(_)) => eprintln!("tsnet node is up"),
        Ok(Err(e)) => panic!("tsnet up() failed: {e}"),
        Err(elapsed) => panic!("tsnet up() timed out (60s): {elapsed:?}"),
    }

    // Verify the LocalAPI socket path was registered.
    assert_eq!(
        server.localapi_path(),
        Some(&socket_path),
        "server should report the LocalAPI socket path"
    );

    // 5. Wait for the socket to become connectable.
    wait_for_socket(&socket_path, Duration::from_secs(10));
    eprintln!(
        "LocalAPI socket is connectable at {}",
        socket_path.display()
    );

    // 6. GET /localapi/v0/status — expect 200 + valid JSON with BackendState.
    let resp = unix_http_request(&socket_path, "/localapi/v0/status").await;
    eprintln!("status response: {resp}");
    assert_eq!(
        status_code(&resp),
        200,
        "GET /localapi/v0/status should return 200"
    );
    let body = json_body(&resp);
    let json: serde_json::Value =
        serde_json::from_str(body).expect("status response body should be valid JSON");
    assert_eq!(
        json["BackendState"], "Running",
        "BackendState should be Running"
    );
    assert_eq!(json["Version"], "rustscale", "Version should be rustscale");
    assert!(
        json["Self"]["HostName"].is_string(),
        "Self.HostName should be present"
    );
    eprintln!("status JSON validated: BackendState=Running, Self.HostName present");

    // 7. GET /localapi/v0/health — expect 200 + valid JSON array.
    let resp = unix_http_request(&socket_path, "/localapi/v0/health").await;
    eprintln!("health response: {resp}");
    assert_eq!(
        status_code(&resp),
        200,
        "GET /localapi/v0/health should return 200"
    );
    let body = json_body(&resp);
    let json: serde_json::Value =
        serde_json::from_str(body).expect("health response body should be valid JSON");
    assert!(json.is_array(), "health response should be a JSON array");
    eprintln!(
        "health JSON validated: array with {} entries",
        json.as_array().unwrap().len()
    );

    // 8. Clean up.
    server.close().await;
    eprintln!("test passed: LocalAPI status + health over safesocket");
}
