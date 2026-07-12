//! Integration test: boot an in-process testcontrol fake control server,
//! bring up a tsnet Server with LocalAPI on a temp safesocket, then exercise
//! the CLI's status path (both via the localclient library and the `rustscale`
//! binary via std::process) against it.
//!
//! No external network access required — everything runs in-process.

use std::path::PathBuf;
use std::time::Duration;

use rustscale_localclient::LocalClient;
use rustscale_safesocket::connect;
use rustscale_testcontrol::Server as TestControlServer;
use rustscale_tsnet::Server;

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

/// Path to the built `rustscale` binary (same target dir as this test).
fn rustscale_bin() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .join("..")
        .join("..")
        .join("target")
        .join("debug")
        .join("rustscale")
}

/// Set up the test environment: start testcontrol, bring up a tsnet server
/// with LocalAPI, and return the socket path. The caller must call
/// `server.close()` when done.
struct TestEnv {
    _tc: TestControlServer,
    server: Server,
    socket_path: PathBuf,
    _state_tmp: tempfile::TempDir,
    _sock_tmp: tempfile::TempDir,
}

async fn setup() -> TestEnv {
    // 1. Start testcontrol.
    let mut tc = TestControlServer::new();
    let _addr = tc.start().await.expect("testcontrol start");
    let control_url = tc.base_url();
    eprintln!("testcontrol listening at {control_url}");

    // 2. Prepare temp dirs.
    let state_tmp = tempfile::tempdir().expect("state tempdir");
    let sock_tmp = tempfile::tempdir().expect("socket tempdir");
    let socket_path: PathBuf = sock_tmp.path().join("rustscale-cli-test.sock");
    let _ = std::fs::remove_file(&socket_path);

    // 3. Build tsnet Server with LocalAPI.
    let server = Server::builder()
        .hostname("cli-test")
        .auth_key("tskey-test")
        .control_url(&control_url)
        .ephemeral(true)
        .state_dir(state_tmp.path().to_path_buf())
        .localapi_path(&socket_path)
        .build()
        .expect("tsnet build");

    let mut server = server;

    // 4. Bring it up.
    eprintln!("bringing tsnet node up...");
    let up_result = Box::pin(tokio::time::timeout(Duration::from_secs(60), server.up())).await;
    match &up_result {
        Ok(Ok(_)) => eprintln!("tsnet node is up"),
        Ok(Err(e)) => panic!("tsnet up() failed: {e}"),
        Err(elapsed) => panic!("tsnet up() timed out (60s): {elapsed:?}"),
    }

    // 5. Wait for socket.
    wait_for_socket(&socket_path, Duration::from_secs(10));
    eprintln!("LocalAPI socket ready at {}", socket_path.display());

    TestEnv {
        _tc: tc,
        server,
        socket_path,
        _state_tmp: state_tmp,
        _sock_tmp: sock_tmp,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cli_status_via_localclient() {
    let mut env = setup().await;

    // Exercise the localclient library (the same library the CLI binary uses).
    let client = LocalClient::new(&env.socket_path);
    let status = client.status().await.expect("status via localclient");

    assert_eq!(status["BackendState"], "Running");
    assert_eq!(status["Version"], "rustscale");
    assert!(
        status["Self"]["HostName"].is_string(),
        "Self.HostName should be present"
    );
    assert!(
        status["Self"]["TailscaleIPs"].is_array(),
        "Self.TailscaleIPs should be present"
    );

    eprintln!("localclient status OK: BackendState=Running");

    env.server.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cli_status_json_via_binary() {
    let mut env = setup().await;

    // Run the `rustscale` binary via std::process with --socket and --json.
    let bin = rustscale_bin();
    assert!(
        bin.exists(),
        "rustscale binary not found at {} — run `cargo build -p rustscale-cli` first",
        bin.display()
    );

    let output = std::process::Command::new(&bin)
        .arg("--socket")
        .arg(&env.socket_path)
        .arg("status")
        .arg("--json")
        .output()
        .expect("failed to spawn rustscale binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "rustscale status --json failed (exit {:?})\nstdout: {stdout}\nstderr: {stderr}",
        output.status.code()
    );

    // The output should be valid JSON with BackendState=Running.
    let json: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("status --json output should be valid JSON");

    assert_eq!(
        json["BackendState"], "Running",
        "BackendState should be Running, got: {stdout}"
    );
    assert_eq!(json["Version"], "rustscale");
    assert!(json["Self"]["HostName"].is_string());

    eprintln!("binary status --json OK: BackendState=Running");

    env.server.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cli_status_table_via_binary() {
    let mut env = setup().await;

    let bin = rustscale_bin();
    assert!(
        bin.exists(),
        "rustscale binary not found at {}",
        bin.display()
    );

    let output = std::process::Command::new(&bin)
        .arg("--socket")
        .arg(&env.socket_path)
        .arg("status")
        .output()
        .expect("failed to spawn rustscale binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "rustscale status failed (exit {:?})\nstdout: {stdout}\nstderr: {stderr}",
        output.status.code()
    );

    // In table mode, the output should NOT be JSON — it should contain the
    // hostname or IP. The backend state is "Running" so no special message.
    // We just verify the output is non-empty and doesn't start with '{'.
    assert!(
        !stdout.trim().is_empty(),
        "status table output should not be empty"
    );
    assert!(
        !stdout.trim().starts_with('{'),
        "status table output should not be JSON when --json is not passed"
    );

    eprintln!("binary status table OK:\n{stdout}");

    env.server.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cli_ip_via_localclient() {
    let mut env = setup().await;

    let client = LocalClient::new(&env.socket_path);
    let status = client.status().await.expect("status");

    let self_ips: Vec<String> = status
        .get("TailscaleIPs")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    assert!(
        !self_ips.is_empty(),
        "should have at least one tailscale IP"
    );

    eprintln!("localclient ip OK: self IPs = {:?}", self_ips);

    env.server.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cli_health_via_localclient() {
    let mut env = setup().await;

    let client = LocalClient::new(&env.socket_path);
    let health = client.health().await.expect("health");

    assert!(health.is_array(), "health response should be a JSON array");

    eprintln!(
        "localclient health OK: {} warnings",
        health.as_array().unwrap().len()
    );

    env.server.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cli_metrics_via_localclient() {
    let mut env = setup().await;

    let client = LocalClient::new(&env.socket_path);
    let metrics = client.metrics().await.expect("metrics");

    assert!(
        metrics.contains("rustscale_packet_drops_total"),
        "metrics should contain rustscale_packet_drops_total"
    );
    assert!(
        metrics.contains("rustscale_peer_count"),
        "metrics should contain rustscale_peer_count"
    );

    eprintln!("localclient metrics OK");

    env.server.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cli_netmap_includes_derp_map() {
    let mut env = setup().await;

    let client = LocalClient::new(&env.socket_path);
    let netmap = client.netmap().await.expect("netmap");

    // The netmap should now include a DERPMap field (added for the netcheck
    // subcommand).
    assert!(
        netmap.get("DERPMap").is_some(),
        "netmap should include a DERPMap field"
    );

    eprintln!("localclient netmap OK: DERPMap present");

    env.server.close().await;
}

// ---------------------------------------------------------------------------
// Interactive auth integration test
// ---------------------------------------------------------------------------

/// Interactive auth flow: daemon starts with no auth key in NeedsLogin →
/// CLI up → testcontrol issues AuthURL → testcontrol completes auth →
/// CLI sees Running.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interactive_auth_flow() {
    use rustscale_ipn::NOTIFY_INITIAL_STATE;
    use rustscale_localclient::LocalClient;

    // 1. Start testcontrol with require_auth.
    let mut tc = TestControlServer::new();
    let _addr = tc.start().await.expect("testcontrol start");
    tc.set_require_auth(true);
    let control_url = tc.base_url();
    eprintln!("testcontrol (require_auth) listening at {control_url}");

    // 2. Prepare temp dirs.
    let state_tmp = tempfile::tempdir().expect("state tempdir");
    let sock_tmp = tempfile::tempdir().expect("socket tempdir");
    let socket_path: PathBuf = sock_tmp.path().join("rustscale-auth-test.sock");
    let _ = std::fs::remove_file(&socket_path);

    // 3. Build tsnet Server WITHOUT auth_key — start_localapi_only().
    let mut server = Server::builder()
        .hostname("auth-test")
        .control_url(&control_url)
        .ephemeral(true)
        .state_dir(state_tmp.path().to_path_buf())
        .localapi_path(&socket_path)
        .build()
        .expect("tsnet build");

    let mut command_rx = server
        .start_localapi_only()
        .await
        .expect("start_localapi_only");

    // 4. Wait for LocalAPI socket.
    wait_for_socket(&socket_path, Duration::from_secs(10));
    eprintln!("LocalAPI socket ready at {}", socket_path.display());

    // 5. Verify the daemon is in NeedsLogin state.
    let lc = LocalClient::new(&socket_path);
    let status = lc.status().await.expect("status");
    let backend_state = status
        .get("BackendState")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown");
    eprintln!("Initial backend state: {backend_state}");
    assert!(
        backend_state == "NeedsLogin" || backend_state == "NoState",
        "expected NeedsLogin or NoState, got {backend_state}"
    );

    // 6. Start a watch-ipn-bus stream to observe BrowseToURL + state changes.
    let mut watch = lc
        .watch_ipn_bus(NOTIFY_INITIAL_STATE)
        .await
        .expect("watch_ipn_bus");

    // 7. Send /start (no auth_key) to trigger bootstrap.
    let start_opts = rustscale_ipn::StartOptions {
        UpdatePrefs: Some(rustscale_ipn::MaskedPrefs {
            Prefs: rustscale_ipn::Prefs {
                WantRunning: true,
                ..Default::default()
            },
            WantRunningSet: true,
            ..Default::default()
        }),
        ..Default::default()
    };
    lc.start(&start_opts).await.expect("start");

    // 8. Receive the Start command and call up() in a background task.
    //    up() will block on login_trigger during the auth flow.
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let up_task = {
        tokio::spawn(async move {
            if let Some(cmd) = command_rx.recv().await {
                match cmd {
                    rustscale_tsnet::localapi::DaemonCommand::Start { auth_key: _ } => {
                        eprintln!("received Start command, calling up()...");
                        let result = Box::pin(server.up()).await;
                        if let Err(e) = &result {
                            eprintln!("up() failed: {e}");
                        }
                        eprintln!("up() completed");
                        let _ = shutdown_rx.await;
                        eprintln!("shutting down server...");
                        server.close().await;
                        eprintln!("server closed");
                    }
                    _ => {
                        eprintln!("unexpected command: {cmd:?}");
                    }
                }
            }
        })
    };

    // 9. Wait for BrowseToURL from the watch-ipn-bus stream.
    let mut auth_url: Option<String> = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while auth_url.is_none() {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let msg = tokio::time::timeout(remaining, watch.next())
            .await
            .expect("timeout waiting for BrowseToURL")
            .expect("connection error")
            .expect("stream closed");
        if let Some(ref url) = msg.BrowseToURL {
            auth_url = Some(url.clone());
            eprintln!("Got BrowseToURL: {url}");
        }
        if let Some(state) = msg.State {
            eprintln!("State: {state}");
        }
    }

    let auth_url = auth_url.expect("should have received BrowseToURL");

    // 10. Trigger login (unblocks bootstrap's login_trigger wait).
    eprintln!("Triggering login-interactive...");
    lc.login_interactive().await.expect("login_interactive");

    // 11. Complete auth on the testcontrol server.
    eprintln!("Completing auth for {auth_url}...");
    assert!(
        tc.complete_auth(&auth_url),
        "complete_auth should succeed for the auth URL"
    );
    eprintln!("Auth completed on testcontrol");

    // 11. Wait for state to reach Running.
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        assert!(!remaining.is_zero(), "timeout waiting for Running state");
        let msg = match tokio::time::timeout(remaining, watch.next()).await {
            Ok(Ok(Some(n))) => n,
            Ok(Ok(None)) => {
                eprintln!("watch-ipn-bus stream closed; reconnecting...");
                // The pre-started LocalAPI may have been replaced by the full one.
                // Reconnect to the new LocalAPI.
                watch = lc
                    .watch_ipn_bus(NOTIFY_INITIAL_STATE)
                    .await
                    .expect("watch_ipn_bus reconnect");
                continue;
            }
            Ok(Err(e)) => {
                eprintln!("watch-ipn-bus error: {e}; reconnecting...");
                tokio::time::sleep(Duration::from_millis(200)).await;
                watch = lc
                    .watch_ipn_bus(NOTIFY_INITIAL_STATE)
                    .await
                    .expect("watch_ipn_bus reconnect");
                continue;
            }
            Err(elapsed) => panic!("timeout waiting for Running state: {elapsed:?}"),
        };

        if let Some(state) = msg.State {
            eprintln!("State: {state}");
            if state == rustscale_ipn::State::Running {
                eprintln!("Interactive auth flow complete: Running!");
                break;
            }
        }
        if let Some(ref err) = msg.ErrMessage {
            eprintln!("Error from daemon: {err}");
        }
    }

    // 12. Verify status via localclient.
    let status = lc.status().await.expect("status after up");
    let backend_state = status
        .get("BackendState")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown");
    assert_eq!(
        backend_state, "Running",
        "expected Running after interactive auth, got {backend_state}"
    );

    // 13. Verify prefs are accessible.
    let prefs = lc.get_prefs().await.expect("get_prefs");
    assert!(prefs.WantRunning, "WantRunning should be true after up");

    eprintln!("Interactive auth integration test passed!");

    // Clean up.
    let _ = shutdown_tx.send(());
    let _ = up_task.await;
}
