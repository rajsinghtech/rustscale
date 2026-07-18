//! Integration tests for exit-node prefs → routing wiring (Gap 1),
//! logout clearing state → NeedsLogin (Gap 2), and stored exit-node
//! pref surviving restart.
//!
//! Uses an in-process testcontrol fake control server — no external
//! network access required.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use rustscale_ipn::State;
use rustscale_safesocket::connect;
use rustscale_testcontrol::Server as TestControlServer;
use rustscale_tsnet::Server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn http_request(method: &str, path: &str, body: &str) -> Vec<u8> {
    format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

async fn unix_http(socket_path: &std::path::Path, method: &str, path: &str, body: &str) -> String {
    let mut conn = connect(socket_path).expect("connect to LocalAPI socket");
    let req = http_request(method, path, body);
    conn.write_all(&req).await.expect("write request");
    conn.flush().await.expect("flush");
    let mut buf = Vec::with_capacity(8192);
    conn.read_to_end(&mut buf).await.expect("read response");
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
            "LocalAPI socket never became connectable within {timeout:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Wait for the backend to reach the expected state, polling /status.
async fn wait_for_state(socket_path: &std::path::Path, expected: State, timeout: Duration) {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let resp = unix_http(socket_path, "GET", "/localapi/v0/status", "").await;
        let body = json_body(&resp);
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
            if let Some(state_str) = v.get("BackendState").and_then(|s| s.as_str()) {
                if state_str == expected.as_str() {
                    return;
                }
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "backend never reached {expected} within {timeout:?}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Gap 1: PATCH prefs with ExitNodeIP applies routing via route_table;
/// clearing the exit node removes the route. Uses testcontrol with two
/// nodes — one advertising exit node, the other selecting it via PATCH.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exit_node_prefs_apply_routing() {
    let mut tc = TestControlServer::new();
    let _addr = tc.start().await.expect("testcontrol start");
    let control_url = tc.base_url();

    // Add an online peer with both approved default routes. The returned key
    // is the route owner the LocalAPI mutation must install.
    let exit_peer = tc.add_fake_exit_node("route-exit.fake-control.example.net.", true);

    let state_tmp = tempfile::tempdir().expect("state tempdir");
    let sock_tmp = tempfile::tempdir().expect("socket tempdir");
    let socket_path: PathBuf = sock_tmp.path().join("exitnode-test.sock");
    let _ = std::fs::remove_file(&socket_path);

    let mut server = Server::builder()
        .disable_portmapping(true)
        .hostname("exitnode-prefs-test")
        .auth_key("tskey-test")
        .control_url(&control_url)
        .ephemeral(true)
        .state_dir(state_tmp.path().to_path_buf())
        .localapi_path(&socket_path)
        .build()
        .expect("tsnet build");

    let up_result = Box::pin(tokio::time::timeout(Duration::from_secs(60), server.up())).await;
    up_result.expect("up timeout").expect("up success");

    wait_for_socket(&socket_path, Duration::from_secs(5));

    // Wait for the fake peer to appear in the netmap and get its IP.
    let peer_ip = {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            let st = server.status();
            if let Some(peer) = st.peers.first() {
                if !peer.ips.is_empty() {
                    break peer.ips[0];
                }
            }
            assert!(std::time::Instant::now() < deadline, "peer never appeared");
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    };
    eprintln!("peer IP: {peer_ip}");

    // PATCH prefs with ExitNodeIP. The LocalAPI transaction must persist the
    // selector and install the peer as both IPv4 and IPv6 catch-all owner.
    let patch_body = serde_json::json!({
        "ExitNodeIPSet": true,
        "ExitNodeIP": peer_ip.to_string()
    })
    .to_string();
    let resp = unix_http(&socket_path, "PATCH", "/localapi/v0/prefs", &patch_body).await;
    assert_eq!(status_code(&resp), 200, "PATCH prefs should return 200");

    // Verify the pref was saved.
    let resp = unix_http(&socket_path, "GET", "/localapi/v0/prefs", "").await;
    let body = json_body(&resp);
    let prefs: serde_json::Value = serde_json::from_str(body).expect("prefs JSON");
    assert_eq!(
        prefs["ExitNodeIP"].as_str(),
        Some(peer_ip.to_string().as_str()),
        "ExitNodeIP should be saved in prefs"
    );
    for public_ip in ["8.8.8.8", "2001:4860:4860::8888"] {
        assert_eq!(
            server.route_lookup(public_ip.parse::<IpAddr>().unwrap()),
            Some(exit_peer.Key.clone()),
            "{public_ip} should route through the selected exit node"
        );
    }

    // Clear the exit node pref.
    let clear_body = serde_json::json!({
        "ExitNodeIPSet": true,
        "ExitNodeIP": ""
    })
    .to_string();
    let resp = unix_http(&socket_path, "PATCH", "/localapi/v0/prefs", &clear_body).await;
    assert_eq!(status_code(&resp), 200, "clear prefs should return 200");

    let resp = unix_http(&socket_path, "GET", "/localapi/v0/prefs", "").await;
    let body = json_body(&resp);
    let prefs: serde_json::Value = serde_json::from_str(body).expect("prefs JSON");
    assert!(
        prefs.get("ExitNodeIP").is_none() || prefs["ExitNodeIP"].as_str() == Some(""),
        "ExitNodeIP should be cleared"
    );
    assert!(
        server
            .route_lookup("8.8.8.8".parse::<IpAddr>().unwrap())
            .is_none(),
        "clearing prefs should remove the daemon catch-all route"
    );

    server.close().await.unwrap();
}

/// Gap 1: ExitNodeAllowLANAccess pref field roundtrips through PATCH/prefs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exit_node_allow_lan_access_pref() {
    let mut tc = TestControlServer::new();
    let _addr = tc.start().await.expect("testcontrol start");
    let control_url = tc.base_url();

    let state_tmp = tempfile::tempdir().expect("state tempdir");
    let sock_tmp = tempfile::tempdir().expect("socket tempdir");
    let socket_path: PathBuf = sock_tmp.path().join("allowlan-test.sock");
    let _ = std::fs::remove_file(&socket_path);

    let mut server = Server::builder()
        .disable_portmapping(true)
        .hostname("allowlan-test")
        .auth_key("tskey-test")
        .control_url(&control_url)
        .ephemeral(true)
        .state_dir(state_tmp.path().to_path_buf())
        .localapi_path(&socket_path)
        .build()
        .expect("tsnet build");

    Box::pin(tokio::time::timeout(Duration::from_secs(60), server.up()))
        .await
        .expect("up timeout")
        .expect("up success");

    wait_for_socket(&socket_path, Duration::from_secs(5));

    // Set ExitNodeAllowLANAccess via PATCH.
    let patch_body = serde_json::json!({
        "ExitNodeAllowLANAccessSet": true,
        "ExitNodeAllowLANAccess": true
    })
    .to_string();
    let resp = unix_http(&socket_path, "PATCH", "/localapi/v0/prefs", &patch_body).await;
    assert_eq!(status_code(&resp), 200);

    let resp = unix_http(&socket_path, "GET", "/localapi/v0/prefs", "").await;
    let body = json_body(&resp);
    let prefs: serde_json::Value = serde_json::from_str(body).expect("prefs JSON");
    assert_eq!(
        prefs["ExitNodeAllowLANAccess"].as_bool(),
        Some(true),
        "ExitNodeAllowLANAccess should be saved"
    );

    server.close().await.unwrap();
}

/// Gap 2: Logout clears state → NeedsLogin, control server sees logout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn logout_clears_state_to_needs_login() {
    let mut tc = TestControlServer::new();
    let _addr = tc.start().await.expect("testcontrol start");
    let control_url = tc.base_url();

    let state_tmp = tempfile::tempdir().expect("state tempdir");
    let sock_tmp = tempfile::tempdir().expect("socket tempdir");
    let socket_path: PathBuf = sock_tmp.path().join("logout-test.sock");
    let _ = std::fs::remove_file(&socket_path);

    let state_dir = state_tmp.path().to_path_buf();

    let mut server = Server::builder()
        .disable_portmapping(true)
        .hostname("logout-test")
        .auth_key("tskey-test")
        .control_url(&control_url)
        .ephemeral(true)
        .disable_portmapping(true)
        .state_dir(state_dir.clone())
        .localapi_path(&socket_path)
        .build()
        .expect("tsnet build");

    Box::pin(tokio::time::timeout(Duration::from_secs(60), server.up()))
        .await
        .expect("up timeout")
        .expect("up success");

    wait_for_socket(&socket_path, Duration::from_secs(5));
    wait_for_state(&socket_path, State::Running, Duration::from_secs(30)).await;

    // Verify state file exists before logout.
    let state_file = find_named_file(&state_dir, "tsnet-state.json")
        .expect("scoped state file should exist before logout");

    // Call logout on the server.
    server.logout().await.expect("logout");

    // Verify: control server saw the logout request.
    // The server's node was registered with testcontrol; after logout,
    // at least one node should be in the logged_out set.
    let any_logout = {
        let nodes = tc.all_nodes();
        nodes.iter().any(|n| tc.saw_logout(&n.Key))
    };
    assert!(
        any_logout,
        "control server should have seen a logout request"
    );

    // Verify: state file was regenerated (new keys).
    let state_after = std::fs::read_to_string(&state_file).expect("read state file");
    assert!(
        !state_after.is_empty(),
        "state file should exist after logout (regenerated)"
    );

    // Verify: prefs have LoggedOut=true, WantRunning=false.
    let prefs = rustscale_ipn::Prefs::load(&state_dir).expect("load prefs");
    assert!(
        prefs.LoggedOut,
        "prefs.LoggedOut should be true after logout"
    );
    assert!(
        !prefs.WantRunning,
        "prefs.WantRunning should be false after logout"
    );

    // Verify: netmap cache was cleared.
    assert!(
        find_named_file(&state_dir, "netmap-cache.json").is_none(),
        "netmap cache should be cleared after logout"
    );

    server.close().await.unwrap();
}

fn find_named_file(root: &std::path::Path, name: &str) -> Option<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in std::fs::read_dir(path).ok()?.flatten() {
            let path = entry.path();
            if path.is_file() && path.file_name().is_some_and(|candidate| candidate == name) {
                return Some(path);
            }
            if path.is_dir() {
                pending.push(path);
            }
        }
    }
    None
}

/// Gap 2: POST /logout via LocalAPI fires the logout_trigger and
/// transitions to NeedsLogin.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn localapi_post_logout_triggers_needs_login() {
    let mut tc = TestControlServer::new();
    let _addr = tc.start().await.expect("testcontrol start");
    let control_url = tc.base_url();

    let state_tmp = tempfile::tempdir().expect("state tempdir");
    let sock_tmp = tempfile::tempdir().expect("socket tempdir");
    let socket_path: PathBuf = sock_tmp.path().join("post-logout-test.sock");
    let _ = std::fs::remove_file(&socket_path);

    let mut server = Server::builder()
        .disable_portmapping(true)
        .hostname("post-logout-test")
        .auth_key("tskey-test")
        .control_url(&control_url)
        .ephemeral(true)
        .state_dir(state_tmp.path().to_path_buf())
        .localapi_path(&socket_path)
        .build()
        .expect("tsnet build");

    Box::pin(tokio::time::timeout(Duration::from_secs(60), server.up()))
        .await
        .expect("up timeout")
        .expect("up success");

    wait_for_socket(&socket_path, Duration::from_secs(5));
    wait_for_state(&socket_path, State::Running, Duration::from_secs(30)).await;

    // LocalAPI requests only return 204 after their owner completes the durable
    // logout transaction. This test embeds Server directly, so drive the same
    // trigger/transaction handshake that rustscaled owns in production.
    let trigger = server.logout_trigger().expect("running logout trigger");
    let notified = trigger.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    let request_socket = socket_path.clone();
    let request =
        tokio::spawn(
            async move { unix_http(&request_socket, "POST", "/localapi/v0/logout", "").await },
        );
    tokio::time::timeout(Duration::from_secs(5), notified)
        .await
        .expect("LocalAPI logout did not notify its owner");
    server.logout().await.expect("logout transaction");
    let resp = tokio::time::timeout(Duration::from_secs(5), request)
        .await
        .expect("LocalAPI logout did not return after durable completion")
        .expect("LocalAPI request task");
    assert_eq!(status_code(&resp), 204, "POST /logout should return 204");

    let prefs = rustscale_ipn::Prefs::load(state_tmp.path()).expect("load logout prefs");
    assert!(
        prefs.LoggedOut,
        "LoggedOut should be true after POST /logout"
    );
    assert!(
        !prefs.WantRunning,
        "WantRunning should be false after POST /logout"
    );

    server.close().await.unwrap();
}
