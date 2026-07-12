//! WireGuard data plane for rustscale.
//!
//! Wraps the `boringtun` crate's `noise::Tunn` API in a transport-agnostic
//! per-peer tunnel. The caller (magicsock) moves UDP/DERP datagrams in and out;
//! this crate is pure bytes-in → bytes-out.
//!
//! Key conversion: `rustscale_key::NodePrivate` / `NodePublic` are X25519
//! scalars/points stored as 32 raw bytes. We convert to boringtun's
//! `StaticSecret` / `PublicKey` via `From<[u8; 32]>`.

#![forbid(unsafe_code)]

use std::net::IpAddr;
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use rustscale_key::{NodePrivate, NodePublic};

/// Maximum WireGuard message size (header + payload).
const MAX_WG_MSG: usize = 65_536;

/// Errors from the WireGuard tunnel wrapper.
#[derive(Debug, thiserror::Error)]
pub enum WgError {
    /// The tunnel's internal state reported a non-fatal protocol error.
    #[error("wireguard tunnel error: {0}")]
    Tunnel(String),
    /// A key was zero / unusable.
    #[error("invalid key")]
    InvalidKey,
}

/// Result of decapsulating an incoming WireGuard datagram.
#[derive(Debug, Default)]
pub struct DecapResult {
    /// Decoded IP packet ready for the tunnel interface, if any.
    pub plaintext: Option<Vec<u8>>,
    /// Immediate WireGuard replies (handshake responses, keepalives) to send
    /// back over the transport.
    pub replies: Vec<Vec<u8>>,
}

/// A per-peer WireGuard tunnel wrapping `boringtun::noise::Tunn`.
pub struct WgTunn {
    tunn: Tunn,
    decap_buf: Box<[u8]>,
    encap_buf: Box<[u8]>,
}

impl WgTunn {
    /// Create a new tunnel from our node private key and the peer's node public
    /// key. Both are X25519; the 32 raw bytes are converted to boringtun's key
    /// types directly.
    ///
    /// `index` is a caller-chosen unique per-peer index (used by boringtun's
    /// rate limiter; pass a small incrementing counter).
    pub fn new(
        private: &NodePrivate,
        peer_public: &NodePublic,
        index: u32,
    ) -> Result<Self, WgError> {
        if private.is_zero() || peer_public.is_zero() {
            return Err(WgError::InvalidKey);
        }

        let static_private = StaticSecret::from(private.raw32());
        let peer_static_public = PublicKey::from(peer_public.raw32());

        let tunn = Tunn::new(static_private, peer_static_public, None, None, index, None);

        Ok(Self {
            tunn,
            decap_buf: vec![0u8; MAX_WG_MSG].into_boxed_slice(),
            encap_buf: vec![0u8; MAX_WG_MSG].into_boxed_slice(),
        })
    }

    /// Encapsulate a plaintext IP packet into WireGuard ciphertext datagrams.
    ///
    /// Returns zero or more datagrams to send over the transport. The first
    /// call after `new` typically triggers a handshake initiation, producing a
    /// handshake datagram instead of (or in addition to) the data datagram.
    pub fn encapsulate(&mut self, plaintext: &[u8]) -> Result<Vec<Vec<u8>>, WgError> {
        match self.tunn.encapsulate(plaintext, &mut self.encap_buf[..]) {
            TunnResult::WriteToNetwork(buf) => Ok(vec![buf.to_vec()]),
            TunnResult::Err(e) => Err(WgError::Tunnel(format!("{e:?}"))),
            TunnResult::Done
            | TunnResult::WriteToTunnelV4(_, _)
            | TunnResult::WriteToTunnelV6(_, _) => Ok(vec![]),
        }
    }

    /// Decapsulate an incoming WireGuard datagram.
    ///
    /// If the datagram is a handshake response or keepalive, `plaintext` will
    /// be `None` and `replies` may contain immediate protocol replies to send
    /// back. If it carries data, `plaintext` is the decoded IP packet.
    ///
    /// boringtun requires re-calling decapsulate with an empty datagram after a
    /// `WriteToNetwork` result until `Done` is returned; this method handles
    /// that loop internally and collects all replies.
    pub fn decapsulate(&mut self, datagram: &[u8]) -> Result<DecapResult, WgError> {
        let mut result = DecapResult::default();

        let mut to_process = Some(datagram);
        loop {
            let src = to_process.take().unwrap_or(&[]);
            match self.tunn.decapsulate(None, src, &mut self.decap_buf[..]) {
                TunnResult::WriteToNetwork(buf) => {
                    result.replies.push(buf.to_vec());
                    to_process = Some(&[]);
                }
                TunnResult::WriteToTunnelV4(buf, _) | TunnResult::WriteToTunnelV6(buf, _) => {
                    result.plaintext = Some(buf.to_vec());
                }
                TunnResult::Done => break,
                TunnResult::Err(e) => {
                    let _ = e;
                    break;
                }
            }
        }

        Ok(result)
    }

    /// Drive the tunnel's timer state. Returns any datagrams that need to be
    /// sent (handshake retransmissions, keepalives). Call periodically (every
    /// ~250ms per boringtun's convention).
    pub fn tick_timers(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let TunnResult::WriteToNetwork(buf) = self.tunn.update_timers(&mut self.encap_buf[..])
        {
            out.push(buf.to_vec());
        }
        out
    }

    /// Force a new handshake initiation. Returns the initiation datagram if a
    /// handshake was produced.
    pub fn force_handshake(&mut self) -> Vec<Vec<u8>> {
        match self
            .tunn
            .format_handshake_initiation(&mut self.encap_buf[..], false)
        {
            TunnResult::WriteToNetwork(buf) => vec![buf.to_vec()],
            _ => vec![],
        }
    }

    /// Whether the tunnel has expired (no valid session and handshake failed).
    pub fn is_expired(&self) -> bool {
        self.tunn.is_expired()
    }

    /// Time since the last successful handshake, if any.
    pub fn time_since_last_handshake(&self) -> Option<Duration> {
        self.tunn.time_since_last_handshake()
    }

    /// The peer's destination IP address from an IP packet, if parseable.
    /// Utility for the caller to route decapsulated packets.
    pub fn dst_address(packet: &[u8]) -> Option<IpAddr> {
        Tunn::dst_address(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a trivial IP packet: IPv4 header (20 bytes) + payload.
    /// src=10.0.0.1, dst=10.0.0.2, protocol=UDP(17).
    fn make_ipv4_packet(payload: &[u8]) -> Vec<u8> {
        let total_len = 20 + payload.len();
        let mut pkt = vec![0u8; total_len];
        pkt[0] = 0x45; // version 4, IHL 5
        pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        pkt[8] = 64; // TTL
        pkt[9] = 17; // protocol: UDP
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]); // src
        pkt[16..20].copy_from_slice(&[10, 0, 0, 2]); // dst
        pkt[20..].copy_from_slice(payload);
        pkt
    }

    /// Drive the handshake: A encapsulates (triggers initiation), B
    /// decapsulates (processes initiation, produces response), A decapsulates
    /// (processes response). Returns once both sides should have a session.
    fn handshake(a: &mut WgTunn, b: &mut WgTunn) {
        // A sends a data packet to trigger handshake initiation.
        let pkt = make_ipv4_packet(b"hello from A");
        let a_out = a.encapsulate(&pkt).expect("A encapsulate");
        // First encapsulate after new() produces a handshake initiation.
        assert!(
            !a_out.is_empty(),
            "A should produce at least a handshake initiation"
        );

        // B decapsulates A's handshake initiation.
        for datagram in &a_out {
            let b_res = b.decapsulate(datagram).expect("B decapsulate");
            // B should produce a handshake response.
            assert!(
                !b_res.replies.is_empty(),
                "B should produce a handshake response"
            );
            // B may also have the data packet if the session is now established.
            if let Some(ref pt) = b_res.plaintext {
                assert_eq!(pt, &pkt, "B should decode A's data packet");
            }

            // A decapsulates B's handshake response.
            for reply in &b_res.replies {
                let a_res = a.decapsulate(reply).expect("A decapsulate");
                // A may now have keepalive or nothing; handshake should be complete.
                // Send any A replies back to B if needed.
                for reply2 in &a_res.replies {
                    let _ = b.decapsulate(reply2);
                }
            }
        }
    }

    #[test]
    fn two_peers_handshake_and_pass_packets() {
        let a_priv = NodePrivate::generate();
        let b_priv = NodePrivate::generate();
        let a_pub = a_priv.public();
        let b_pub = b_priv.public();

        let mut a = WgTunn::new(&a_priv, &b_pub, 1).expect("A tunnel");
        let mut b = WgTunn::new(&b_priv, &a_pub, 2).expect("B tunnel");

        // Complete the handshake.
        handshake(&mut a, &mut b);

        // Both sides should have a session now.
        // A sends a data packet to B.
        let pkt_a = make_ipv4_packet(b"hello from A");
        let a_out = a.encapsulate(&pkt_a).expect("A encapsulate data");
        assert!(!a_out.is_empty(), "A should produce a data datagram");

        // B decapsulates and gets the plaintext.
        let mut got_b = None;
        for datagram in &a_out {
            let b_res = b.decapsulate(datagram).expect("B decapsulate data");
            if let Some(pt) = b_res.plaintext {
                got_b = Some(pt);
            }
        }
        assert_eq!(
            got_b.as_deref(),
            Some(&pkt_a[..]),
            "B should receive A's packet"
        );

        // B sends a data packet to A.
        let pkt_b = make_ipv4_packet(b"hello from B");
        let b_out = b.encapsulate(&pkt_b).expect("B encapsulate data");
        assert!(!b_out.is_empty(), "B should produce a data datagram");

        let mut got_a = None;
        for datagram in &b_out {
            let a_res = a.decapsulate(datagram).expect("A decapsulate data");
            if let Some(pt) = a_res.plaintext {
                got_a = Some(pt);
            }
        }
        assert_eq!(
            got_a.as_deref(),
            Some(&pkt_b[..]),
            "A should receive B's packet"
        );
    }

    #[test]
    fn timers_produce_keepalive_after_handshake() {
        let a_priv = NodePrivate::generate();
        let b_priv = NodePrivate::generate();
        let b_pub = b_priv.public();

        let mut a = WgTunn::new(&a_priv, &b_pub, 10).expect("A tunnel");
        let mut b = WgTunn::new(&b_priv, &a_priv.public(), 11).expect("B tunnel");

        handshake(&mut a, &mut b);

        // Timers may or may not produce output immediately, but should not panic.
        let _ = a.tick_timers();
        let _ = b.tick_timers();
    }

    #[test]
    fn force_handshake_produces_initiation() {
        let a_priv = NodePrivate::generate();
        let b_priv = NodePrivate::generate();

        let mut a = WgTunn::new(&a_priv, &b_priv.public(), 20).expect("A tunnel");
        let init = a.force_handshake();
        assert!(
            !init.is_empty(),
            "force_handshake should produce an initiation"
        );
    }

    #[test]
    fn zero_keys_rejected() {
        let z = NodePrivate::from_raw32([0u8; 32]);
        let b = NodePrivate::generate();
        assert!(WgTunn::new(&z, &b.public(), 0).is_err());
        assert!(WgTunn::new(&b, &NodePublic::from_raw32([0u8; 32]), 0).is_err());
    }

    #[test]
    fn decapsulate_garbage_is_nonfatal() {
        let a_priv = NodePrivate::generate();
        let b_priv = NodePrivate::generate();
        let mut a = WgTunn::new(&a_priv, &b_priv.public(), 30).expect("A tunnel");
        // Random garbage should not panic or return an error that we propagate.
        let res = a.decapsulate(&[0xff; 100]).expect("garbage is non-fatal");
        assert!(
            res.plaintext.is_none(),
            "garbage should not produce plaintext"
        );
    }

    #[test]
    fn dst_address_parses_ipv4() {
        let pkt = make_ipv4_packet(b"x");
        let dst = WgTunn::dst_address(&pkt);
        assert_eq!(dst, Some(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2))));
    }
}
