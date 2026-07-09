//! Tailscale disco NAT-traversal message codec.
//!
//! Ports the wire format of Go's `disco` package. A disco packet consists of:
//!
//! ```text
//! magic          [6]byte  // "TS💬" = 0x54 53 f0 9f 92 ac
//! senderDiscoPub [32]byte
//! nonce          [24]byte
//! <box>          ...      // NaCl box ciphertext (sealed with DiscoShared)
//! ```
//!
//! After decryption the inner payload is:
//!
//! ```text
//! messageType     byte
//! messageVersion  byte
//! message-payload [...]byte
//! ```

#![forbid(unsafe_code)]

mod message;
mod wire;

pub use message::{
    AllocateUdpRelayEndpointRequest, AllocateUdpRelayEndpointResponse, BindUdpRelayEndpoint,
    BindUdpRelayEndpointAnswer, BindUdpRelayEndpointChallenge, BindUdpRelayEndpointCommon,
    CallMeMaybe, CallMeMaybeVia, DiscoError, Message, Ping, Pong, UdpRelayEndpoint,
    ALLOCATE_UDP_RELAY_ENDPOINT_REQUEST_LEN, BIND_UDP_RELAY_CHALLENGE_LEN,
    BIND_UDP_RELAY_ENDPOINT_COMMON_LEN, MESSAGE_HEADER_LEN, PING_LEN, PONG_LEN,
    TYPE_ALLOCATE_UDP_RELAY_ENDPOINT_REQUEST, TYPE_ALLOCATE_UDP_RELAY_ENDPOINT_RESPONSE,
    TYPE_BIND_UDP_RELAY_ENDPOINT, TYPE_BIND_UDP_RELAY_ENDPOINT_ANSWER,
    TYPE_BIND_UDP_RELAY_ENDPOINT_CHALLENGE, TYPE_CALL_ME_MAYBE, TYPE_CALL_ME_MAYBE_VIA,
    TYPE_PING, TYPE_PONG, UDP_RELAY_ENDPOINT_LEN_MINUS_ADDRPORTS,
};
pub use wire::AddrPort;

use rustscale_key::{DiscoPrivate, DiscoPublic, KeyError};

/// The 6-byte magic prefix of all disco packets: UTF-8 of "TS💬".
pub const MAGIC: [u8; 6] = [0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac];

/// Length of a Curve25519 public key.
pub const KEY_LEN: usize = 32;

/// Length of the NaCl box nonce.
pub const NONCE_LEN: usize = 24;

/// Report whether `p` looks like a disco wrapper packet.
pub fn looks_like_disco_wrapper(p: &[u8]) -> bool {
    p.len() >= MAGIC.len() + KEY_LEN + NONCE_LEN && p[..MAGIC.len()] == MAGIC
}

/// Extract the 32-byte sender disco public key from a wrapper packet.
///
/// Returns `None` if the packet does not look like a disco wrapper.
pub fn source(p: &[u8]) -> Option<[u8; KEY_LEN]> {
    if !looks_like_disco_wrapper(p) {
        return None;
    }
    let mut src = [0u8; KEY_LEN];
    src.copy_from_slice(&p[MAGIC.len()..MAGIC.len() + KEY_LEN]);
    Some(src)
}

/// Seal a disco payload: `MAGIC || sender_pub(32) || DiscoShared::seal(payload)`.
///
/// The seal output is `nonce(24) || ct`, so the full packet is
/// `6 + 32 + 24 + payload_len + 16` bytes.
pub fn seal_packet(
    sender: &DiscoPrivate,
    peer: &DiscoPublic,
    payload: &[u8],
) -> Result<Vec<u8>, KeyError> {
    if sender.is_zero() || peer.is_zero() {
        return Err(KeyError::ZeroKey);
    }
    let shared = sender.shared(peer);
    let sealed = shared.seal(payload)?;
    let sender_pub = sender.public();
    let mut out = Vec::with_capacity(MAGIC.len() + KEY_LEN + sealed.len());
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&sender_pub.raw32());
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Open a disco wrapper packet, returning the sender's public key and plaintext.
///
/// Returns `None` on bad magic or authentication failure.
pub fn open_packet(receiver: &DiscoPrivate, packet: &[u8]) -> Option<(DiscoPublic, Vec<u8>)> {
    if !looks_like_disco_wrapper(packet) {
        return None;
    }
    let sender_bytes = source(packet)?;
    let sender_pub = DiscoPublic::from_raw32(sender_bytes);
    let shared = receiver.shared(&sender_pub);
    let plaintext = shared.open(&packet[MAGIC.len() + KEY_LEN..])?;
    Some((sender_pub, plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use rustscale_key::{DiscoPrivate, NodePublic};

    // ---- helper to build the test key {1:1, 2:2, 30:30, 31:31} ----
    fn key_1_2_30_31() -> [u8; 32] {
        let mut k = [0u8; 32];
        k[1] = 1;
        k[2] = 2;
        k[30] = 30;
        k[31] = 31;
        k
    }
    fn key_1_2_3_30_31() -> [u8; 32] {
        let mut k = [0u8; 32];
        k[1] = 1;
        k[2] = 2;
        k[3] = 3;
        k[30] = 30;
        k[31] = 31;
        k
    }
    fn key_1_2_4_30_31() -> [u8; 32] {
        let mut k = [0u8; 32];
        k[1] = 1;
        k[2] = 2;
        k[4] = 4;
        k[30] = 30;
        k[31] = 31;
        k
    }

    fn ap(ip: &str, port: u16) -> AddrPort {
        let ip_str = ip.trim_start_matches('[').trim_end_matches(']');
        AddrPort::new(ip_str.parse().unwrap(), port)
    }

    fn strip_hex(s: &str) -> String {
        s.split(' ').collect()
    }

    // ---- Golden byte vectors from disco_test.go TestMarshalAndParse ----

    #[test]
    fn golden_ping() {
        let m = Message::Ping(Ping {
            tx_id: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            node_key: NodePublic::from_raw32([0u8; 32]),
            padding: 0,
        });
        let want = "01 00 01 02 03 04 05 06 07 08 09 0a 0b 0c";
        assert_eq!(hex::encode(m.marshal()), strip_hex(want));
        let back = Message::parse(&m.marshal()).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn golden_ping_with_nodekey_src() {
        let m = Message::Ping(Ping {
            tx_id: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            node_key: NodePublic::from_raw32(key_1_2_30_31()),
            padding: 0,
        });
        let want = "01 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 00 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1e 1f";
        assert_eq!(hex::encode(m.marshal()), strip_hex(want));
        let back = Message::parse(&m.marshal()).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn golden_ping_with_padding() {
        let m = Message::Ping(Ping {
            tx_id: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            node_key: NodePublic::from_raw32([0u8; 32]),
            padding: 3,
        });
        let want = "01 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 00 00 00";
        assert_eq!(hex::encode(m.marshal()), strip_hex(want));
        let back = Message::parse(&m.marshal()).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn golden_ping_with_padding_and_nodekey_src() {
        let m = Message::Ping(Ping {
            tx_id: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            node_key: NodePublic::from_raw32(key_1_2_30_31()),
            padding: 3,
        });
        let want = "01 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 00 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1e 1f 00 00 00";
        assert_eq!(hex::encode(m.marshal()), strip_hex(want));
        let back = Message::parse(&m.marshal()).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn golden_pong() {
        let m = Message::Pong(Pong {
            tx_id: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            src: ap("2.3.4.5", 1234),
        });
        let want = "02 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 00 00 00 00 00 00 00 00 00 00 ff ff 02 03 04 05 04 d2";
        assert_eq!(hex::encode(m.marshal()), strip_hex(want));
        let back = Message::parse(&m.marshal()).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn golden_pongv6() {
        let m = Message::Pong(Pong {
            tx_id: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            src: ap("fed0::12", 6666),
        });
        let want = "02 00 01 02 03 04 05 06 07 08 09 0a 0b 0c fe d0 00 00 00 00 00 00 00 00 00 00 00 00 00 12 1a 0a";
        assert_eq!(hex::encode(m.marshal()), strip_hex(want));
        let back = Message::parse(&m.marshal()).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn golden_call_me_maybe() {
        let m = Message::CallMeMaybe(CallMeMaybe::default());
        let want = "03 00";
        assert_eq!(hex::encode(m.marshal()), strip_hex(want));
        let back = Message::parse(&m.marshal()).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn golden_call_me_maybe_endpoints() {
        let m = Message::CallMeMaybe(CallMeMaybe {
            my_number: vec![ap("1.2.3.4", 567), ap("[2001::3456]", 789)],
        });
        let want = "03 00 00 00 00 00 00 00 00 00 00 00 ff ff 01 02 03 04 02 37 20 01 00 00 00 00 00 00 00 00 00 00 00 00 34 56 03 15";
        assert_eq!(hex::encode(m.marshal()), strip_hex(want));
        let back = Message::parse(&m.marshal()).unwrap();
        assert_eq!(back, m);
    }

    fn relay_handshake_common() -> BindUdpRelayEndpointCommon {
        let challenge: [u8; BIND_UDP_RELAY_CHALLENGE_LEN] = core::array::from_fn(|i| i as u8);
        BindUdpRelayEndpointCommon {
            vni: 1,
            generation: 2,
            remote_key: DiscoPublic::from_raw32(key_1_2_30_31()),
            challenge,
        }
    }

    #[test]
    fn golden_bind_udp_relay_endpoint() {
        let m = Message::BindUdpRelayEndpoint(BindUdpRelayEndpoint {
            common: relay_handshake_common(),
        });
        let want = "04 00 00 00 00 01 00 00 00 02 00 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1e 1f 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f";
        assert_eq!(hex::encode(m.marshal()), strip_hex(want));
        let back = Message::parse(&m.marshal()).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn golden_bind_udp_relay_endpoint_challenge() {
        let m = Message::BindUdpRelayEndpointChallenge(BindUdpRelayEndpointChallenge {
            common: relay_handshake_common(),
        });
        let want = "05 00 00 00 00 01 00 00 00 02 00 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1e 1f 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f";
        assert_eq!(hex::encode(m.marshal()), strip_hex(want));
        let back = Message::parse(&m.marshal()).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn golden_bind_udp_relay_endpoint_answer() {
        let m = Message::BindUdpRelayEndpointAnswer(BindUdpRelayEndpointAnswer {
            common: relay_handshake_common(),
        });
        let want = "06 00 00 00 00 01 00 00 00 02 00 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1e 1f 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f";
        assert_eq!(hex::encode(m.marshal()), strip_hex(want));
        let back = Message::parse(&m.marshal()).unwrap();
        assert_eq!(back, m);
    }

    fn udp_relay_endpoint() -> UdpRelayEndpoint {
        UdpRelayEndpoint {
            server_disco: DiscoPublic::from_raw32(key_1_2_30_31()),
            client_disco: [
                DiscoPublic::from_raw32(key_1_2_3_30_31()),
                DiscoPublic::from_raw32(key_1_2_4_30_31()),
            ],
            lamport_id: 123,
            vni: 456,
            bind_lifetime: Duration::from_secs(1),
            steady_state_lifetime: Duration::from_secs(60),
            addr_ports: vec![ap("1.2.3.4", 567), ap("[2001::3456]", 789)],
        }
    }

    #[test]
    fn golden_call_me_maybe_via() {
        let m = Message::CallMeMaybeVia(CallMeMaybeVia {
            endpoint: udp_relay_endpoint(),
        });
        let want = "07 00 00 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1e 1f 00 01 02 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1e 1f 00 01 02 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1e 1f 00 00 00 00 00 00 00 7b 00 00 01 c8 00 00 00 00 3b 9a ca 00 00 00 00 0d f8 47 58 00 00 00 00 00 00 00 00 00 00 00 ff ff 01 02 03 04 02 37 20 01 00 00 00 00 00 00 00 00 00 00 00 00 34 56 03 15";
        assert_eq!(hex::encode(m.marshal()), strip_hex(want));
        let back = Message::parse(&m.marshal()).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn golden_allocate_udp_relay_endpoint_request() {
        let m = Message::AllocateUdpRelayEndpointRequest(AllocateUdpRelayEndpointRequest {
            client_disco: [
                DiscoPublic::from_raw32(key_1_2_3_30_31()),
                DiscoPublic::from_raw32(key_1_2_4_30_31()),
            ],
            generation: 1,
        });
        let want = "08 00 00 01 02 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1e 1f 00 01 02 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1e 1f 00 00 00 01";
        assert_eq!(hex::encode(m.marshal()), strip_hex(want));
        let back = Message::parse(&m.marshal()).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn golden_allocate_udp_relay_endpoint_response() {
        let m = Message::AllocateUdpRelayEndpointResponse(AllocateUdpRelayEndpointResponse {
            generation: 1,
            endpoint: udp_relay_endpoint(),
        });
        let want = "09 00 00 00 00 01 00 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1e 1f 00 01 02 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1e 1f 00 01 02 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 1e 1f 00 00 00 00 00 00 00 7b 00 00 01 c8 00 00 00 00 3b 9a ca 00 00 00 00 0d f8 47 58 00 00 00 00 00 00 00 00 00 00 00 ff ff 01 02 03 04 02 37 20 01 00 00 00 00 00 00 00 00 00 00 00 00 34 56 03 15";
        assert_eq!(hex::encode(m.marshal()), strip_hex(want));
        let back = Message::parse(&m.marshal()).unwrap();
        assert_eq!(back, m);
    }

    // ---- Error cases ----

    #[test]
    fn parse_short_returns_short_error() {
        assert!(matches!(
            Message::parse(&[0x01]),
            Err(DiscoError::Short)
        ));
        assert!(matches!(
            Message::parse(&[]),
            Err(DiscoError::Short)
        ));
    }

    #[test]
    fn parse_unknown_type_returns_error() {
        let buf = [0xff, 0x00, 0x01, 0x02];
        assert!(matches!(
            Message::parse(&buf),
            Err(DiscoError::UnknownType(0xff))
        ));
    }

    // ---- Envelope seal/open ----

    #[test]
    fn seal_open_packet_roundtrip() {
        let a = DiscoPrivate::generate();
        let b = DiscoPrivate::generate();

        let ping = Message::Ping(Ping {
            tx_id: [0xaa; 12],
            node_key: NodePublic::from_raw32([0u8; 32]),
            padding: 0,
        });
        let payload = ping.marshal();

        let packet = seal_packet(&a, &b.public(), &payload).unwrap();
        assert!(looks_like_disco_wrapper(&packet));
        assert_eq!(source(&packet).unwrap(), a.public().raw32());

        let (sender_pub, plaintext) = open_packet(&b, &packet).unwrap();
        assert_eq!(sender_pub, a.public());
        assert_eq!(Message::parse(&plaintext).unwrap(), ping);
    }

    #[test]
    fn open_packet_wrong_key_fails() {
        let a = DiscoPrivate::generate();
        let b = DiscoPrivate::generate();
        let evil = DiscoPrivate::generate();

        let packet = seal_packet(&a, &b.public(), b"hello").unwrap();
        assert!(open_packet(&evil, &packet).is_none());
    }

    #[test]
    fn looks_like_wrapper_and_source_helpers() {
        let a = DiscoPrivate::generate();
        let b = DiscoPrivate::generate();
        let packet = seal_packet(&a, &b.public(), b"x").unwrap();

        assert!(looks_like_disco_wrapper(&packet));
        assert!(!looks_like_disco_wrapper(&[0u8; 10]));
        assert!(!looks_like_disco_wrapper(b"not a disco packet at all"));

        let src = source(&packet).unwrap();
        assert_eq!(src, a.public().raw32());

        assert!(source(&[0u8; 10]).is_none());
    }

    #[test]
    fn summary_strings() {
        let msg = Message::Ping(Ping {
            tx_id: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            node_key: NodePublic::from_raw32([0u8; 32]),
            padding: 5,
        });
        assert!(msg.summary().starts_with("ping tx="));
        assert!(msg.summary().contains("padding=5"));

        let reply = Message::Pong(Pong {
            tx_id: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            src: AddrPort::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 567),
        });
        assert!(reply.summary().starts_with("pong tx="));

        assert_eq!(
            Message::CallMeMaybe(CallMeMaybe::default()).summary(),
            "call-me-maybe"
        );
        assert_eq!(
            Message::BindUdpRelayEndpoint(BindUdpRelayEndpoint {
                common: BindUdpRelayEndpointCommon {
                    vni: 0,
                    generation: 0,
                    remote_key: DiscoPublic::from_raw32([0u8; 32]),
                    challenge: [0u8; 32],
                }
            })
            .summary(),
            "bind-udp-relay-endpoint"
        );
    }
}
