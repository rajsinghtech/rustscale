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
    let server_key = fetch_server_pub_key(host, version)
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
