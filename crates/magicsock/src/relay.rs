//! Peer relay (UDP relay) client: Geneve data framing and bind handshake state.
//!
//! Ports the client-side relay logic from Go's
//! `wgengine/magicsock/relaymanager.go` and `net/udprelay/server.go`.
//! The 3-way handshake is:
//!
//! 1. Client → server: `BindUDPRelayEndpoint` (VNI + generation + remote key + challenge)
//! 2. Server → client: `BindUDPRelayEndpointChallenge` (same common fields)
//! 3. Client → server: `BindUDPRelayEndpointAnswer` (same common fields)
//!
//! After binding, data flows through the relay with a Geneve header (8 bytes)
//! carrying the VNI, matching Go's `net/udprelay` packet framing.

use std::net::SocketAddr;
use std::time::Instant;

use rustscale_disco::{
    BindUdpRelayEndpoint, BindUdpRelayEndpointAnswer, BindUdpRelayEndpointChallenge,
    BindUdpRelayEndpointCommon, Message,
};
use rustscale_key::DiscoPublic;

// Geneve codec lives in the udprelay crate; re-export for backward compat.
pub use rustscale_udprelay::{
    decode_geneve, encode_geneve, GENEVE_FIXED_HEADER_LENGTH as GENEVE_HEADER_LEN,
    GENEVE_PROTOCOL_DISCO, GENEVE_PROTOCOL_WIREGUARD,
};

/// Encode a Geneve disco control frame with the Control bit set.
///
/// Used for relay handshake messages (BindUDPRelayEndpoint,
/// BindUDPRelayEndpointAnswer). The payload is the sealed disco envelope.
pub fn encode_geneve_disco_control(vni: u32, payload: &[u8]) -> Vec<u8> {
    encode_geneve_header(GENEVE_PROTOCOL_DISCO, vni, true, payload)
}

/// Encode a Geneve disco frame without the Control bit (for relayed
/// Ping/Pong). The payload is the sealed disco envelope.
pub fn encode_geneve_disco(vni: u32, payload: &[u8]) -> Vec<u8> {
    encode_geneve_header(GENEVE_PROTOCOL_DISCO, vni, false, payload)
}

/// Encode a Geneve WireGuard data frame with the Control bit clear.
pub fn encode_geneve_wireguard(vni: u32, payload: &[u8]) -> Vec<u8> {
    encode_geneve_header(GENEVE_PROTOCOL_WIREGUARD, vni, false, payload)
}

fn encode_geneve_header(protocol: u16, vni: u32, control: bool, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(GENEVE_HEADER_LEN + payload.len());
    out.push(0x00);
    out.push(if control { 0x80 } else { 0x00 });
    out.extend_from_slice(&protocol.to_be_bytes());
    out.push((vni >> 16) as u8);
    out.push((vni >> 8) as u8);
    out.push(vni as u8);
    out.push(0x00);
    out.extend_from_slice(payload);
    out
}

/// Decode a Geneve header, returning (protocol, vni, control, payload).
pub fn decode_geneve_full(data: &[u8]) -> Option<(u16, u32, bool, &[u8])> {
    if data.len() < GENEVE_HEADER_LEN {
        return None;
    }
    if data[0] & 0xC0 != 0 {
        return None;
    }
    if data[1] & 0x3F != 0 {
        return None;
    }
    if data[7] != 0 {
        return None;
    }
    let protocol = u16::from_be_bytes([data[2], data[3]]);
    let vni = (u32::from(data[4]) << 16) | (u32::from(data[5]) << 8) | u32::from(data[6]);
    let control = data[1] & 0x80 != 0;
    Some((protocol, vni, control, &data[GENEVE_HEADER_LEN..]))
}

/// Check if a raw UDP packet looks like a Geneve-encapsulated disco packet.
pub fn looks_like_geneve_disco(data: &[u8]) -> bool {
    if data.len() < GENEVE_HEADER_LEN {
        return false;
    }
    if data[0] & 0xC0 != 0 || data[1] & 0x3F != 0 || data[7] != 0 {
        return false;
    }
    let protocol = u16::from_be_bytes([data[2], data[3]]);
    if protocol != GENEVE_PROTOCOL_DISCO {
        return false;
    }
    let inner = &data[GENEVE_HEADER_LEN..];
    rustscale_disco::looks_like_disco_wrapper(inner)
}

/// Check if a raw UDP packet looks like a Geneve-encapsulated WireGuard packet.
pub fn looks_like_geneve_wireguard(data: &[u8]) -> bool {
    if data.len() < GENEVE_HEADER_LEN {
        return false;
    }
    if data[0] & 0xC0 != 0 || data[1] & 0x3F != 0 || data[7] != 0 {
        return false;
    }
    let protocol = u16::from_be_bytes([data[2], data[3]]);
    protocol == GENEVE_PROTOCOL_WIREGUARD
}

/// Read-only view of the relay handshake phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RelayPhase {
    #[default]
    None,
    Binding,
    Established,
}

/// Client-side relay bind handshake state for one peer relay.
pub struct RelayHandshake {
    phase: RelayPhase,
    bind_params: Option<(u32, u32, DiscoPublic)>,
    established: Option<(SocketAddr, u32, Instant)>,
}

impl Default for RelayHandshake {
    fn default() -> Self {
        Self {
            phase: RelayPhase::None,
            bind_params: None,
            established: None,
        }
    }
}

impl RelayHandshake {
    /// Start the bind handshake: build the initial `BindUDPRelayEndpoint`.
    pub fn start_bind(
        &mut self,
        vni: u32,
        generation: u32,
        remote_key: DiscoPublic,
        challenge: [u8; 32],
    ) -> Message {
        self.phase = RelayPhase::Binding;
        self.bind_params = Some((vni, generation, remote_key.clone()));
        Message::BindUdpRelayEndpoint(BindUdpRelayEndpoint {
            common: BindUdpRelayEndpointCommon {
                vni,
                generation,
                remote_key,
                challenge,
            },
        })
    }

    /// Handle a Challenge from the server: produce the Answer message.
    pub fn handle_challenge(
        &mut self,
        challenge: &BindUdpRelayEndpointChallenge,
    ) -> Option<Message> {
        let (vni, generation, remote_key) = self.bind_params.as_ref()?;
        if challenge.common.vni != *vni || challenge.common.generation != *generation {
            return None;
        }
        Some(Message::BindUdpRelayEndpointAnswer(
            BindUdpRelayEndpointAnswer {
                common: BindUdpRelayEndpointCommon {
                    vni: *vni,
                    generation: *generation,
                    remote_key: remote_key.clone(),
                    challenge: challenge.common.challenge,
                },
            },
        ))
    }

    /// Mark the relay as established at `addr`.
    pub fn establish(&mut self, addr: SocketAddr, now: Instant) {
        let vni = self.bind_params.as_ref().map_or(0, |(v, _, _)| *v);
        self.phase = RelayPhase::Established;
        self.established = Some((addr, vni, now));
    }

    /// Whether the relay is established.
    pub fn is_established(&self) -> bool {
        self.phase == RelayPhase::Established
    }

    /// The established relay address and VNI, if any.
    pub fn established_addr(&self) -> Option<(SocketAddr, u32)> {
        self.established.map(|(a, v, _)| (a, v))
    }

    /// Current phase (read-only).
    pub fn phase(&self) -> RelayPhase {
        self.phase
    }

    /// Reset to None.
    pub fn reset(&mut self) {
        self.phase = RelayPhase::None;
        self.bind_params = None;
        self.established = None;
    }
}

#[cfg(test)]
mod tests {
use super::*;
use crate::disco_io::DiscoIo;
use rustscale_key::{DiscoPrivate, NodePublic};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn geneve_roundtrip() {
        let payload = b"hello relay";
        let frame = encode_geneve(0x123456, payload);
        assert_eq!(frame.len(), GENEVE_HEADER_LEN + payload.len());
        let (vni, body) = decode_geneve(&frame).expect("decode");
        assert_eq!(vni, 0x123456);
        assert_eq!(body, payload);
    }

    #[test]
    fn geneve_too_short() {
        assert!(decode_geneve(&[0u8; 4]).is_none());
    }

    #[test]
    fn geneve_disco_control_roundtrip() {
        let payload = [0xAA; 32];
        let frame = encode_geneve_disco_control(0x123456, &payload);
        assert_eq!(frame.len(), GENEVE_HEADER_LEN + payload.len());
        let (proto, vni, control, body) = decode_geneve_full(&frame).expect("decode");
        assert_eq!(proto, GENEVE_PROTOCOL_DISCO);
        assert_eq!(vni, 0x123456);
        assert!(control);
        assert_eq!(body, &payload[..]);
    }

    #[test]
    fn geneve_disco_no_control_roundtrip() {
        let payload = [0xBB; 16];
        let frame = encode_geneve_disco(0xFFFFFF, &payload);
        let (proto, vni, control, body) = decode_geneve_full(&frame).expect("decode");
        assert_eq!(proto, GENEVE_PROTOCOL_DISCO);
        assert_eq!(vni, 0xFFFFFF);
        assert!(!control);
        assert_eq!(body, &payload[..]);
    }

    #[test]
    fn geneve_wireguard_roundtrip() {
        let payload = [0xCC; 64];
        let frame = encode_geneve_wireguard(0x001122, &payload);
        let (proto, vni, control, body) = decode_geneve_full(&frame).expect("decode");
        assert_eq!(proto, GENEVE_PROTOCOL_WIREGUARD);
        assert_eq!(vni, 0x001122);
        assert!(!control);
        assert_eq!(body, &payload[..]);
    }

    #[test]
    fn geneve_full_decode_rejects_bad_version() {
        let mut frame = encode_geneve_disco_control(1, &[0u8; 10]);
        frame[0] |= 0x40;
        assert!(decode_geneve_full(&frame).is_none());
    }

    #[test]
    fn geneve_full_decode_rejects_bad_reserved() {
        let mut frame = encode_geneve_disco_control(1, &[0u8; 10]);
        frame[1] |= 0x01;
        assert!(decode_geneve_full(&frame).is_none());
    }

    #[test]
    fn looks_like_geneve_disco_detects_encapsulated() {
        let disco_io = DiscoIo::new(DiscoPrivate::generate());
        let peer = DiscoPrivate::generate().public();
        let msg = Message::Ping(rustscale_disco::Ping {
            tx_id: [1; 12],
            node_key: NodePublic::from_raw32([0u8; 32]),
            padding: 0,
        });
        let sealed = disco_io.seal(&peer, &msg).expect("seal");
        let frame = encode_geneve_disco_control(42, &sealed);
        assert!(looks_like_geneve_disco(&frame));
        assert!(!looks_like_geneve_wireguard(&frame));
    }

    #[test]
    fn looks_like_geneve_disco_rejects_plain_disco() {
        let disco_io = DiscoIo::new(DiscoPrivate::generate());
        let peer = DiscoPrivate::generate().public();
        let msg = Message::Ping(rustscale_disco::Ping {
            tx_id: [1; 12],
            node_key: NodePublic::from_raw32([0u8; 32]),
            padding: 0,
        });
        let sealed = disco_io.seal(&peer, &msg).expect("seal");
        assert!(!looks_like_geneve_disco(&sealed));
    }

    #[test]
    fn relay_handshake_flow() {
        let mut hs = RelayHandshake::default();
        let remote = DiscoPrivate::generate().public();

        let msg = hs.start_bind(100, 1, remote.clone(), [0xaa; 32]);
        assert!(matches!(msg, Message::BindUdpRelayEndpoint(_)));
        assert_eq!(hs.phase(), RelayPhase::Binding);

        let challenge = BindUdpRelayEndpointChallenge {
            common: BindUdpRelayEndpointCommon {
                vni: 100,
                generation: 1,
                remote_key: remote.clone(),
                challenge: [0xbb; 32],
            },
        };
        let answer = hs.handle_challenge(&challenge);
        assert!(matches!(
            answer,
            Some(Message::BindUdpRelayEndpointAnswer(_))
        ));

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 5678);
        hs.establish(addr, Instant::now());
        assert!(hs.is_established());
        assert_eq!(hs.established_addr(), Some((addr, 100)));
        assert_eq!(hs.phase(), RelayPhase::Established);

        hs.reset();
        assert!(!hs.is_established());
        assert_eq!(hs.phase(), RelayPhase::None);
    }

    #[test]
    fn relay_rejects_mismatched_challenge() {
        let mut hs = RelayHandshake::default();
        let remote = DiscoPrivate::generate().public();

        hs.start_bind(100, 1, remote.clone(), [0xaa; 32]);

        let challenge = BindUdpRelayEndpointChallenge {
            common: BindUdpRelayEndpointCommon {
                vni: 999,
                generation: 1,
                remote_key: remote,
                challenge: [0xbb; 32],
            },
        };
        assert!(hs.handle_challenge(&challenge).is_none());
    }
}
