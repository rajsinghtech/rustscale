use rustscale_key::NodePrivate;
use rustscale_tailcfg::{MapResponse, RegisterRequest};

use super::*;

/// Decode the 4-byte LE size-prefixed map response framing.
/// Matches Go's `direct.go` read loop: `binary.LittleEndian.Uint32(siz[:])`.
#[test]
fn decode_map_frames_single() {
    let payload = br#"{"KeepAlive":true}"#;
    let frame = encode_map_frame(payload);

    let frames = decode_map_frames(&frame);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0], payload);
}

#[test]
fn decode_map_frames_multiple() {
    let p1 = br#"{"KeepAlive":true}"#;
    let p2 = br#"{"Domain":"example.com"}"#;
    let p3 = br#"{"Seq":42}"#;

    let mut buf = Vec::new();
    buf.extend_from_slice(&encode_map_frame(p1));
    buf.extend_from_slice(&encode_map_frame(p2));
    buf.extend_from_slice(&encode_map_frame(p3));

    let frames = decode_map_frames(&buf);
    assert_eq!(frames.len(), 3);
    assert_eq!(frames[0], p1);
    assert_eq!(frames[1], p2);
    assert_eq!(frames[2], p3);
}

#[test]
fn decode_map_frames_partial_ignored() {
    let payload = br#"{"KeepAlive":true}"#;
    let mut buf = encode_map_frame(payload);
    // Append a partial frame (only 2 bytes of the 4-byte size header).
    buf.extend_from_slice(&[0xAB, 0xCD]);

    let frames = decode_map_frames(&buf);
    assert_eq!(frames.len(), 1, "partial frame at end should be ignored");
    assert_eq!(frames[0], payload);
}

#[test]
fn decode_map_frames_truncated_payload_ignored() {
    let payload = br#"{"KeepAlive":true}"#;
    let mut buf = encode_map_frame(payload);
    // Append a size header claiming 100 bytes but provide only 3.
    buf.extend_from_slice(&100u32.to_le_bytes());
    buf.extend_from_slice(b"abc");

    let frames = decode_map_frames(&buf);
    assert_eq!(frames.len(), 1, "truncated payload should be ignored");
}

/// Decode a canned MapResponse JSON from a size-prefixed frame and verify
/// the fields deserialize correctly.
#[test]
fn map_response_frame_decode() {
    let mr = MapResponse {
        KeepAlive: true,
        Domain: "example.com".into(),
        Seq: 42,
        ..Default::default()
    };
    let json = serde_json::to_vec(&mr).unwrap();
    let frame = encode_map_frame(&json);

    let frames = decode_map_frames(&frame);
    assert_eq!(frames.len(), 1);

    let decoded: MapResponse = serde_json::from_slice(frames[0]).unwrap();
    assert_eq!(decoded, mr);
}

#[tokio::test]
async fn expired_map_latches_callbacks_before_buffered_channel_and_tka_consumers() {
    let node_key = NodePrivate::generate().public();
    let dispatcher = crate::SshCallbackDispatcher::new();
    let _generation = dispatcher.activate(node_key.clone()).unwrap();
    let (updates, mut receiver) = tokio::sync::mpsc::channel(1);
    updates.send(Ok(MapResponse::default())).await.unwrap();

    let forwarding = {
        let dispatcher = dispatcher.clone();
        let node_key = node_key.clone();
        tokio::spawn(async move {
            forward_map_response(
                &updates,
                MapResponse {
                    NodeKeyExpired: true,
                    ..Default::default()
                },
                None,
                Some(&dispatcher),
                &node_key,
            )
            .await
        })
    };
    tokio::task::yield_now().await;

    assert!(dispatcher.activate(node_key.clone()).is_none());
    assert_eq!(
        dispatcher.notifier().enqueue(
            "https://arbitrary.invalid/ssh/notify",
            &rustscale_tailcfg::SSHEventNotifyRequest {
                SrcNode: 1,
                ..Default::default()
            },
        ),
        Err(crate::SshNotifyEnqueueError::NoGeneration)
    );
    // Unblock forwarding only after observing revocation. A downstream TKA
    // consumer cannot run before this channel handoff either.
    assert!(receiver.recv().await.is_some());
    assert!(forwarding.await.unwrap());

    let tka_pause = Arc::new(tokio::sync::Semaphore::new(0));
    let (tka_entered_tx, tka_entered_rx) = tokio::sync::oneshot::channel();
    let tka_consumer = {
        let tka_pause = Arc::clone(&tka_pause);
        tokio::spawn(async move {
            let expired = receiver.recv().await.unwrap().unwrap();
            assert!(expired.NodeKeyExpired);
            let _ = tka_entered_tx.send(());
            let _permit = tka_pause.acquire().await.unwrap();
        })
    };
    tka_entered_rx.await.unwrap();
    assert!(dispatcher.is_key_revoked(&node_key));
    assert!(dispatcher.activate(node_key).is_none());
    tka_pause.add_permits(1);
    tka_consumer.await.unwrap();
}

/// Register request serialization: verify the JSON wire format matches
/// what Go's control server expects (PascalCase field names, nodekey prefix).
#[test]
fn register_request_serialization() {
    let node_key = NodePrivate::generate();
    let req = RegisterRequest {
        Version: 999,
        NodeKey: node_key.public(),
        Ephemeral: true,
        Tailnet: "required:example.com".into(),
        ..Default::default()
    };

    let j = serde_json::to_string(&req).unwrap();
    assert!(j.contains("\"Version\":999"));
    assert!(j.contains("\"NodeKey\":\"nodekey:"));
    assert!(j.contains("\"Ephemeral\":true"));
    assert!(j.contains("\"Tailnet\":\"required:example.com\""));

    // Roundtrip.
    let back: RegisterRequest = serde_json::from_str(&j).unwrap();
    assert_eq!(back, req);
}

/// Register response with AuthURL (interactive login case).
#[test]
fn register_response_auth_url() {
    use rustscale_tailcfg::RegisterResponse;

    let resp = RegisterResponse {
        MachineAuthorized: false,
        AuthURL: "https://login.tailscale.com/a/abc123".into(),
        ..Default::default()
    };

    let j = serde_json::to_string(&resp).unwrap();
    assert!(j.contains("\"AuthURL\":\"https://login.tailscale.com/a/abc123\""));
    assert!(j.contains("\"MachineAuthorized\":false"));

    let back: RegisterResponse = serde_json::from_str(&j).unwrap();
    assert_eq!(back, resp);
}

/// Real-register probe: dial controlplane.tailscale.com, complete the Noise
/// handshake, establish HTTP/2, and send a register request with a bogus
/// auth key. The server should return a structured response (either a
/// RegisterResponse with an error, or an HTTP error status) — NOT a JSON
/// parse failure at column 1 (which would indicate we're not speaking HTTP/2
/// correctly).
///
/// #[ignore] because it requires network access.
#[tokio::test]
#[ignore = "requires network access to controlplane.tailscale.com"]
async fn real_register_gets_structured_response() {
    use crate::controlbase::ProtocolVersion;
    use crate::controlhttp::fetch_server_pub_key;
    use rustscale_key::MachinePrivate;
    use rustscale_tailcfg::{Hostinfo, RegisterRequest};

    let host = "controlplane.tailscale.com";
    let version: ProtocolVersion = 141;

    // Fetch the server's Noise public key.
    let server_key = fetch_server_pub_key(host, version, None)
        .await
        .expect("fetch_server_pub_key should succeed");

    // Generate our machine key.
    let machine_key = MachinePrivate::generate();

    // Create the control client.
    let cc =
        crate::client::ControlClient::new(host, machine_key.clone(), server_key.clone(), version);

    // Send a register request with a bogus node key (no auth key).
    // The server should return a structured response, not a parse error.
    let req = RegisterRequest {
        Version: 141,
        NodeKey: rustscale_key::NodePrivate::generate().public(),
        Hostinfo: Some(Hostinfo {
            OS: "linux".to_string(),
            Hostname: "rustscale-probe".to_string(),
            ..Default::default()
        }),
        Ephemeral: true,
        ..Default::default()
    };

    let result = cc.register(&req).await;

    // The key assertion: we should get a structured error (not a JSON parse
    // failure at column 1). Acceptable outcomes:
    // - Ok(RegisterResponse) with some error/auth fields
    // - Err(RegisterError::HttpStatus(..)) — HTTP error status
    // - Err(RegisterError::Server(..)) — server error in RegisterResponse
    // NOT acceptable: Err(RegisterError::Json(..)) — means we got non-JSON
    match &result {
        Ok(_resp) => {}
        Err(RegisterError::HttpStatus(_code, _msg)) => {}
        Err(RegisterError::Json(e)) => {
            panic!("JSON parse failure (indicates HTTP/2 not working): {e}");
        }
        Err(_e) => {}
    }
}

struct NeverHandler {
    started: Arc<std::sync::atomic::AtomicUsize>,
    cancelled: Arc<std::sync::atomic::AtomicUsize>,
}

struct CancelGuard(Arc<std::sync::atomic::AtomicUsize>);
impl Drop for CancelGuard {
    fn drop(&mut self) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl crate::C2nHandler for NeverHandler {
    async fn handle(&self, _req: crate::C2nRequest) -> crate::C2nResponse {
        self.started
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let _guard = CancelGuard(self.cancelled.clone());
        std::future::pending::<crate::C2nResponse>().await
    }
}

#[derive(Default)]
struct NoopC2nTransport;

#[async_trait::async_trait]
impl crate::C2nReplyTransport for NoopC2nTransport {
    async fn send(
        &self,
        _callback_path: &str,
        _response: Vec<u8>,
    ) -> Result<(), crate::C2nReplyError> {
        Ok(())
    }
}

fn c2n_ping(index: usize) -> rustscale_tailcfg::PingRequest {
    rustscale_tailcfg::PingRequest {
        URL: format!("https://control.invalid/c2n/{index}"),
        Types: "c2n".into(),
        Payload: b"GET /hang HTTP/1.1\r\nHost: node\r\n\r\n".to_vec(),
        ..Default::default()
    }
}

fn never_c2n_tasks(
    started: Arc<std::sync::atomic::AtomicUsize>,
    cancelled: Arc<std::sync::atomic::AtomicUsize>,
) -> C2nTaskSet {
    let mut router = C2nRouter::new();
    router.register("GET /hang", Arc::new(NeverHandler { started, cancelled }));
    C2nTaskSet::new(
        Arc::new(router),
        Arc::new(NoopC2nTransport),
        Arc::new(Mutex::new(String::new())),
    )
}

#[tokio::test]
async fn map_delivery_precedes_never_completing_c2n() {
    let started = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cancelled = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut tasks = never_c2n_tasks(started.clone(), cancelled);
    let (tx, mut rx) = mpsc::channel(1);
    let response = MapResponse {
        Domain: "new-policy.example".into(),
        PacketFilter: Some(Vec::new()), // immediate deny-all ACL update
        PingRequest: Some(c2n_ping(1)),
        ..Default::default()
    };

    let request_key = NodePrivate::generate().public();
    assert!(forward_map_response(&tx, response, Some(&mut tasks), None, &request_key).await);
    let delivered = tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv())
        .await
        .expect("map delivery was blocked by C2N")
        .expect("map channel closed")
        .expect("map response error");
    assert_eq!(delivered.Domain, "new-policy.example");
    assert_eq!(delivered.PacketFilter, Some(Vec::new()));
    tokio::task::yield_now().await;
    assert_eq!(started.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn c2n_session_cap_holds_and_disconnect_cancels_handlers() {
    let started = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cancelled = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut tasks = never_c2n_tasks(started.clone(), cancelled.clone());

    for index in 0..MAX_C2N_IN_FLIGHT {
        assert_eq!(tasks.dispatch(c2n_ping(index)), C2nDispatch::Started);
    }
    assert_eq!(
        tasks.dispatch(c2n_ping(MAX_C2N_IN_FLIGHT)),
        C2nDispatch::AtCapacity
    );
    tokio::task::yield_now().await;
    assert_eq!(
        started.load(std::sync::atomic::Ordering::SeqCst),
        MAX_C2N_IN_FLIGHT
    );

    drop(tasks); // models the Noise map session disconnecting
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(1);
    while cancelled.load(std::sync::atomic::Ordering::SeqCst) != MAX_C2N_IN_FLIGHT {
        assert!(tokio::time::Instant::now() < deadline, "C2N tasks leaked");
        tokio::task::yield_now().await;
    }
}
