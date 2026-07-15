//! Hermetic posture C2N control-path integration test.

use std::time::Duration;

use rustscale_tailcfg::{MapResponse, PingRequest};
use rustscale_testcontrol::Server as TestControlServer;
use rustscale_tsnet::Server;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn control_c2n_reports_disabled_posture_on_same_noise_session() {
    let mut control = TestControlServer::new();
    control.start().await.expect("start test control");
    let state = tempfile::tempdir().expect("state dir");
    let mut server = Server::builder()
        .hostname("posture-test")
        .auth_key("tskey-test")
        .control_url(control.base_url())
        .state_dir(state.path().to_path_buf())
        .ephemeral(true)
        .build()
        .expect("build server");

    Box::pin(tokio::time::timeout(Duration::from_secs(30), server.up()))
        .await
        .expect("up deadline")
        .expect("up server");
    let node_key = server.node_key().expect("node key");
    let callback = control.c2n_callback_url(&node_key);
    let payload = b"GET /posture/identity?hwaddrs=true HTTP/1.1\r\nHost: node\r\n\r\n".to_vec();
    assert!(control.add_raw_map_response(
        &node_key,
        MapResponse {
            PingRequest: Some(PingRequest {
                URL: callback.clone(),
                Types: "c2n".into(),
                Payload: payload,
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
    assert_eq!(&reply[split + 4..], br#"{"PostureDisabled":true}"#);

    server.close().await;
}
