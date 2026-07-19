//! Integration test: boot an in-process testcontrol fake control server,
//! bring up a tsnet Server with LocalAPI on a temp safesocket, then exercise
//! the CLI's status path (both via the localclient library and the `rustscale`
//! binary via std::process) against it.
//!
//! No external network access required — everything runs in-process.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

use rustscale_key::NLPublic;
use rustscale_localclient::LocalClient;
use rustscale_safesocket::connect;
use rustscale_testcontrol::Server as TestControlServer;
use rustscale_tka::{disablement_kdf, Key, KeyKind};
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

/// Path to the `rustscale` binary Cargo built for this integration test.
fn rustscale_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rustscale"))
}

fn run_cli(socket: &std::path::Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new(rustscale_bin())
        .arg("--socket")
        .arg(socket)
        .args(args)
        .output()
        .expect("spawn rustscale CLI")
}

/// Set up the test environment: start testcontrol, bring up a tsnet server
/// with LocalAPI, and return the socket path. The caller must call
/// `server.close()` when done.
struct TestEnv {
    tc: TestControlServer,
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
        .disable_portmapping(true)
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
        tc,
        server,
        socket_path,
        _state_tmp: state_tmp,
        _sock_tmp: sock_tmp,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cli_up_applies_preferences_when_already_running() {
    let mut env = setup().await;
    let output = std::process::Command::new(rustscale_bin())
        .arg("--socket")
        .arg(&env.socket_path)
        .args([
            "up",
            "--accept-routes",
            "--advertise-routes=10.23.0.0/16",
            "--hostname=updated-online-node",
        ])
        .output()
        .expect("run rustscale up against an online node");
    assert!(
        output.status.success(),
        "up failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let prefs = LocalClient::new(&env.socket_path)
        .get_prefs()
        .await
        .expect("read updated prefs");
    assert!(prefs.AcceptRoutes);
    assert_eq!(prefs.AdvertiseRoutes, ["10.23.0.0/16"]);
    assert_eq!(prefs.Hostname, "updated-online-node");

    env.server.close().await.expect("close server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cli_id_token_via_noise_control() {
    let mut env = setup().await;
    let audience = "https://service.example/resource?tenant=rustscale";
    let expected_token = "header.payload.signature";
    env.tc.set_id_token(expected_token);

    let client = LocalClient::new(&env.socket_path);
    let response = client
        .id_token(audience)
        .await
        .expect("id-token via localclient");
    assert_eq!(response.IDToken, expected_token);

    let request = env
        .tc
        .last_token_request()
        .expect("testcontrol should receive a token request");
    assert_eq!(request.Audience, audience);
    assert_eq!(request.CapVersion, 141);
    assert!(!request.NodeKey.is_zero());

    let output = std::process::Command::new(rustscale_bin())
        .arg("--socket")
        .arg(&env.socket_path)
        .arg("id-token")
        .arg(audience)
        .output()
        .expect("failed to spawn rustscale id-token");
    assert!(
        output.status.success(),
        "id-token failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        expected_token
    );

    env.server.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cli_local_disable_uses_the_durable_authorized_route() {
    let mut env = setup().await;
    let client = LocalClient::new(&env.socket_path);
    let status = client.tailnet_lock_status().await.unwrap();
    let public: NLPublic = status["PublicKey"].as_str().unwrap().parse().unwrap();
    let secret = vec![0x44; 32];
    client
        .tailnet_lock_init(&serde_json::json!({
            "Keys": [Key {
                kind: KeyKind::Key25519,
                votes: 1,
                public: public.raw32().to_vec(),
                meta: None,
            }],
            "DisablementValues": [disablement_kdf(&secret)],
            "DisablementSecrets": [secret],
            "SupportDisablement": [],
            "Resume": false,
        }))
        .await
        .unwrap();

    let output = run_cli(&env.socket_path, &["lock", "local-disable"]);
    assert!(
        output.status.success(),
        "local-disable failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("this node only"));
    let disabled = client.tailnet_lock_status().await.unwrap();
    assert!(disabled["LocalDisabled"].as_bool().unwrap());
    assert_eq!(disabled["DisallowedStateIDs"].as_array().unwrap().len(), 1);

    env.server.close().await.unwrap();
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

    env.server.close().await.unwrap();
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

    env.server.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cli_get_honors_global_json_before_or_after_subcommand() {
    let mut env = setup().await;
    LocalClient::new(&env.socket_path)
        .edit_prefs(&rustscale_ipn::MaskedPrefs {
            Prefs: rustscale_ipn::Prefs {
                Hostname: "get-json-test".into(),
                ..Default::default()
            },
            HostnameSet: true,
            ..Default::default()
        })
        .await
        .expect("set known get preference");

    for args in [["get", "--json"], ["--json", "get"]] {
        let output = run_cli(&env.socket_path, &args);
        assert!(
            output.status.success(),
            "rustscale {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        let prefs: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("get --json output should be JSON");
        assert_eq!(prefs["Hostname"], "get-json-test");
    }

    let output = run_cli(&env.socket_path, &["get"]);
    assert!(
        output.status.success(),
        "rustscale get failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with("ControlURL: "));
    assert!(!stdout.trim_start().starts_with('{'));

    env.server.close().await.unwrap();
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

    env.server.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cli_set_operator_replaces_and_explicitly_clears_persisted_pref() {
    let mut env = setup().await;
    let bin = rustscale_bin();

    let set_operator = |value: &str| {
        std::process::Command::new(&bin)
            .arg("--socket")
            .arg(&env.socket_path)
            .arg("set")
            .arg("--operator")
            .arg(value)
            .output()
            .expect("spawn rustscale set --operator")
    };
    let first = set_operator("operator-a");
    assert!(
        first.status.success(),
        "set operator failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let client = LocalClient::new(&env.socket_path);
    assert_eq!(client.prefs().await.unwrap()["OperatorUser"], "operator-a");

    // A normal set operation does not include OperatorUser and therefore
    // preserves it; only --operator (including an empty argument) changes it.
    let preserve = std::process::Command::new(&bin)
        .arg("--socket")
        .arg(&env.socket_path)
        .arg("set")
        .arg("--hostname")
        .arg("operator-flow")
        .output()
        .expect("spawn rustscale set --hostname");
    assert!(preserve.status.success());
    assert_eq!(client.prefs().await.unwrap()["OperatorUser"], "operator-a");

    let clear = set_operator("");
    assert!(
        clear.status.success(),
        "clear operator failed: {}",
        String::from_utf8_lossy(&clear.stderr)
    );
    assert_eq!(
        client.prefs().await.unwrap()["OperatorUser"]
            .as_str()
            .unwrap_or_default(),
        ""
    );
    env.server.close().await.unwrap();
}

#[test]
fn cli_set_help_is_successful_without_a_daemon() {
    let temp = tempfile::tempdir().unwrap();
    for spelling in ["--help", "-h", "help"] {
        let output = run_cli(&temp.path().join("missing.sock"), &["set", spelling]);
        assert!(
            output.status.success(),
            "set {spelling} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("Usage: rustscale set [flags]"));
        assert!(stdout.contains("--accept-dns[=true|false]"));
        assert!(stdout.contains("empty clears routes"));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cli_set_can_disable_booleans_and_clear_advertised_lists() {
    let mut env = setup().await;
    let enabled = run_cli(
        &env.socket_path,
        &[
            "set",
            "--accept-routes=true",
            "--accept-dns=true",
            "--shields-up=true",
            "--advertise-exit-node=true",
            "--advertise-routes=10.0.0.0/8",
            "--advertise-tags=tag:test",
        ],
    );
    assert!(
        enabled.status.success(),
        "enable prefs failed: {}",
        String::from_utf8_lossy(&enabled.stderr)
    );

    let disabled = run_cli(
        &env.socket_path,
        &[
            "set",
            "--accept-routes=false",
            "--accept-dns=false",
            "--shields-up=false",
            "--advertise-exit-node=false",
            "--advertise-routes=",
            "--advertise-tags=",
        ],
    );
    assert!(
        disabled.status.success(),
        "disable prefs failed: {}",
        String::from_utf8_lossy(&disabled.stderr)
    );

    let prefs = LocalClient::new(&env.socket_path)
        .get_prefs()
        .await
        .expect("read cleared prefs");
    assert!(!prefs.AcceptRoutes);
    assert!(!prefs.CorpDNS);
    assert!(!prefs.ShieldsUp);
    assert!(!prefs.AdvertiseExitNode);
    assert!(
        prefs.AdvertiseRoutes.is_empty(),
        "{:?}",
        prefs.AdvertiseRoutes
    );
    assert!(prefs.AdvertiseTags.is_empty(), "{:?}", prefs.AdvertiseTags);

    env.server.close().await.unwrap();
}

#[test]
fn cli_exit_node_help_is_successful_without_a_daemon() {
    let temp = tempfile::tempdir().unwrap();
    let output = run_cli(&temp.path().join("missing.sock"), &["exit-node", "--help"]);
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("rustscale exit-node select"));
    assert!(stdout.contains("rustscale exit-node clear"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cli_exit_node_selection_reaches_prefs_and_daemon_routes() {
    let mut env = setup().await;

    // Empty list is an upstream-style command failure, not a successful prose
    // response that scripts could mistake for an available node.
    let empty = run_cli(&env.socket_path, &["exit-node", "list"]);
    assert_eq!(empty.status.code(), Some(1));
    assert!(empty.stdout.is_empty());
    assert_eq!(
        String::from_utf8(empty.stderr).unwrap(),
        "rustscale: no exit nodes found\n"
    );

    let target = env
        .tc
        .add_fake_exit_node("daily-exit.fake-control.example.net.", true);
    let offline = env
        .tc
        .add_fake_exit_node("offline-exit.fake-control.example.net.", false);
    env.tc
        .add_fake_exit_node("ambiguous.fake-control.example.net.", true);
    env.tc
        .add_fake_exit_node("AMBIGUOUS.fake-control.example.net.", true);

    let client = LocalClient::new(&env.socket_path);
    let status = {
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            let status = client.status_bounded().await.unwrap();
            let visible = status
                .get("Peer")
                .and_then(serde_json::Value::as_object)
                .map_or(0, |peers| {
                    peers
                        .values()
                        .filter(|peer| {
                            peer.get("ExitNodeOption")
                                .and_then(serde_json::Value::as_bool)
                                .unwrap_or(false)
                        })
                        .count()
                });
            if visible == 4 {
                break status;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "exit peers did not reach LocalAPI status"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };

    let target_ip = target.Addresses[0]
        .split('/')
        .next()
        .unwrap()
        .parse::<IpAddr>()
        .unwrap();
    let offline_ip = offline.Addresses[0].split('/').next().unwrap();
    assert!(status["Peer"].as_object().unwrap().values().any(|peer| {
        peer.get("ID").and_then(serde_json::Value::as_str) == Some(target.StableID.as_str())
    }));

    let listed = run_cli(&env.socket_path, &["exit-node", "list"]);
    assert!(listed.status.success());
    assert!(listed.stderr.is_empty());
    let table = String::from_utf8(listed.stdout).unwrap();
    assert!(table.starts_with("IP"));
    assert!(table.contains("daily-exit.fake-control.example.net"));
    assert!(table.contains("offline-exit.fake-control.example.net"));
    assert!(table.contains("offline"));

    let listed_json = run_cli(&env.socket_path, &["exit-node", "list", "--json"]);
    assert!(listed_json.status.success());
    let listed_json: serde_json::Value =
        serde_json::from_slice(&listed_json.stdout).expect("exit-node JSON list");
    assert!(listed_json
        .as_array()
        .unwrap()
        .iter()
        .any(|peer| { peer["id"] == target.StableID && peer["ip"] == target_ip.to_string() }));

    let ambiguous = run_cli(&env.socket_path, &["exit-node", "select", "ambiguous"]);
    assert_eq!(ambiguous.status.code(), Some(1));
    assert!(ambiguous.stdout.is_empty());
    assert_eq!(
        String::from_utf8(ambiguous.stderr).unwrap(),
        "rustscale: ambiguous exit node name \"ambiguous\"\n"
    );

    let offline_selection = run_cli(&env.socket_path, &["exit-node", "select", "offline-exit"]);
    assert_eq!(offline_selection.status.code(), Some(1));
    assert!(offline_selection.stdout.is_empty());
    assert_eq!(
        String::from_utf8(offline_selection.stderr).unwrap(),
        "rustscale: exit node \"offline-exit.fake-control.example.net\" is offline\n"
    );
    assert_eq!(
        status["Peer"]
            .as_object()
            .unwrap()
            .values()
            .find(|peer| peer["ID"] == offline.StableID)
            .and_then(|peer| peer["TailscaleIPs"].as_array())
            .and_then(|ips| ips.first())
            .and_then(serde_json::Value::as_str),
        Some(offline_ip)
    );

    let public_ip = "8.8.8.8".parse::<IpAddr>().unwrap();
    let select_name = run_cli(&env.socket_path, &["exit-node", "select", "daily-exit"]);
    assert!(select_name.status.success());
    assert!(select_name.stdout.is_empty() && select_name.stderr.is_empty());
    let prefs = client.get_prefs().await.unwrap();
    assert_eq!(prefs.ExitNodeIP, target_ip.to_string());
    assert!(prefs.ExitNodeID.is_empty());
    assert_eq!(env.server.route_lookup(public_ip), Some(target.Key.clone()));

    let clear = run_cli(&env.socket_path, &["exit-node", "clear"]);
    assert!(clear.status.success());
    assert!(clear.stdout.is_empty() && clear.stderr.is_empty());
    let prefs = client.get_prefs().await.unwrap();
    assert!(prefs.ExitNodeIP.is_empty() && prefs.ExitNodeID.is_empty());
    assert!(env.server.route_lookup(public_ip).is_none());

    let select_id = run_cli(
        &env.socket_path,
        &["exit-node", "select", target.StableID.as_str()],
    );
    assert!(select_id.status.success());
    let prefs = client.get_prefs().await.unwrap();
    assert_eq!(prefs.ExitNodeID, target.StableID);
    assert!(prefs.ExitNodeIP.is_empty());
    assert_eq!(env.server.route_lookup(public_ip), Some(target.Key.clone()));
    assert!(run_cli(&env.socket_path, &["exit-node", "--clear"])
        .status
        .success());

    let select_ip = run_cli(
        &env.socket_path,
        &["exit-node", "--select", &target_ip.to_string()],
    );
    assert!(select_ip.status.success());
    assert_eq!(env.server.route_lookup(public_ip), Some(target.Key.clone()));
    assert!(run_cli(&env.socket_path, &["exit-node", "clear"])
        .status
        .success());
    assert!(env.server.route_lookup(public_ip).is_none());

    env.server.close().await.unwrap();
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

    env.server.close().await.unwrap();
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

    env.server.close().await.unwrap();
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

    env.server.close().await.unwrap();
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

    env.server.close().await.unwrap();
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
        .disable_portmapping(true)
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
                        server.close().await.unwrap();
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
