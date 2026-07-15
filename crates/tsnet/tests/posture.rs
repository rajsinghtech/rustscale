//! Hermetic posture C2N and shared LocalAPI preference integration tests.

use std::time::Duration;

use rustscale_ipn::{MaskedPrefs, Prefs};
use rustscale_tailcfg::{MapResponse, PingRequest};
use rustscale_testcontrol::Server as TestControlServer;
use rustscale_tsnet::Server;

async fn posture_response(control: &TestControlServer, server: &Server) -> serde_json::Value {
    let node_key = server.node_key().expect("node key");
    control
        .await_node_in_map_request(&node_key, Duration::from_secs(10))
        .await
        .expect("active map request");
    let callback = control.c2n_callback_url(&node_key);
    assert!(control.add_raw_map_response(
        &node_key,
        MapResponse {
            PingRequest: Some(PingRequest {
                URL: callback.clone(),
                Types: "c2n".into(),
                Payload: b"GET /posture/identity?hwaddrs=true HTTP/1.1\r\nHost: node\r\n\r\n"
                    .to_vec(),
                ..PingRequest::default()
            }),
            ..MapResponse::default()
        }
    ));

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let reply = loop {
        if let Some(reply) = control.c2n_reply(&callback) {
            break reply;
        }
        assert!(tokio::time::Instant::now() < deadline, "C2N reply deadline");
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    assert_eq!(control.rejected_c2n_callbacks(), 0);
    let split = reply
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("HTTP response terminator");
    assert!(reply.starts_with(b"HTTP/1.1 200 OK\r\n"));
    serde_json::from_slice(&reply[split + 4..]).expect("posture JSON")
}

fn server(control_url: &str, state_dir: &std::path::Path, hostname: &str) -> Server {
    Server::builder()
        .disable_portmapping(true)
        .hostname(hostname)
        .auth_key("tskey-test")
        .control_url(control_url)
        .state_dir(state_dir.to_path_buf())
        .ephemeral(true)
        .build()
        .expect("build server")
}

async fn up(server: &mut Server) {
    Box::pin(tokio::time::timeout(Duration::from_secs(30), server.up()))
        .await
        .expect("up deadline")
        .expect("up server");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sensitive_c2n_has_no_loopback_listener_and_noise_session_works() {
    let mut control = TestControlServer::new();
    control.start().await.expect("start test control");
    let state = tempfile::tempdir().expect("state dir");
    let mut server = server(&control.base_url(), state.path(), "posture-test");
    up(&mut server).await;

    assert_eq!(
        server.c2n_addr(),
        None,
        "posture, netmap, and prefs must not have an unauthenticated loopback listener"
    );
    assert_eq!(
        posture_response(&control, &server).await,
        serde_json::json!({"PostureDisabled": true})
    );

    server.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn in_memory_clients_share_one_transactional_prefs_state() {
    let mut control = TestControlServer::new();
    control.start().await.expect("start test control");
    let control_url = control.base_url();
    let state = tempfile::tempdir().expect("state dir");
    let mut running = server(&control_url, state.path(), "prefs-race-test");
    up(&mut running).await;

    let client_a = running.local_client().await.expect("first local client");
    let client_b = running.local_client().await.expect("second local client");
    client_a
        .edit_prefs(&MaskedPrefs {
            Prefs: Prefs {
                PostureChecking: true,
                ..Prefs::default()
            },
            PostureCheckingSet: true,
            ..MaskedPrefs::default()
        })
        .await
        .expect("enable posture");

    let unrelated = MaskedPrefs {
        Prefs: Prefs {
            Hostname: "ordered-hostname".into(),
            ..Prefs::default()
        },
        HostnameSet: true,
        ..MaskedPrefs::default()
    };
    let opt_out = MaskedPrefs {
        Prefs: Prefs {
            PostureChecking: false,
            ..Prefs::default()
        },
        PostureCheckingSet: true,
        ..MaskedPrefs::default()
    };
    let (unrelated_result, opt_out_result) = tokio::join!(
        client_a.edit_prefs(&unrelated),
        client_b.edit_prefs(&opt_out)
    );
    unrelated_result.expect("unrelated edit");
    opt_out_result.expect("posture opt-out");

    for prefs in [
        client_a.get_prefs().await.expect("client A prefs"),
        client_b.get_prefs().await.expect("client B prefs"),
    ] {
        assert_eq!(prefs.Hostname, "ordered-hostname");
        assert!(!prefs.PostureChecking);
    }
    let disk_bytes = std::fs::read(state.path().join("prefs.json")).expect("on-disk prefs");
    let disk: Prefs = serde_json::from_slice(&disk_bytes).expect("on-disk prefs JSON");
    assert_eq!(disk.Hostname, "ordered-hostname");
    assert!(!disk.PostureChecking);
    let reloaded = Prefs::load(state.path()).expect("reloaded prefs");
    assert_eq!(reloaded.Hostname, "ordered-hostname");
    assert!(!reloaded.PostureChecking);
    assert_eq!(
        posture_response(&control, &running).await,
        serde_json::json!({"PostureDisabled": true}),
        "live posture flag diverged from shared prefs"
    );

    drop((client_a, client_b));
    running.close().await.unwrap();
}
