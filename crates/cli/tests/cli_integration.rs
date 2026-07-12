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
        Ok(Ok(())) => eprintln!("tsnet node is up"),
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
