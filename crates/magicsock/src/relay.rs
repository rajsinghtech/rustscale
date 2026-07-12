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
};

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
    use rustscale_key::DiscoPrivate;
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
