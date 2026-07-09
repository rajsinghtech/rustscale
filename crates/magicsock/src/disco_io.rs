//! Disco message encode/decode and send helpers.
//!
//! Wraps the `rustscale_disco` seal/open envelope. The actual transport (UDP
//! socket or DERP client) is provided by the caller — this module is pure
//! codec + addressing.

use rustscale_disco::{self as disco, Message};
use rustscale_key::{DiscoPrivate, DiscoPublic};

/// Owns our disco key pair and provides seal/open for disco envelopes.
pub struct DiscoIo {
    private: DiscoPrivate,
    public: DiscoPublic,
}

impl DiscoIo {
    /// Create from a generated disco private key.
    pub fn new(private: DiscoPrivate) -> Self {
        let public = private.public();
        Self { private, public }
    }

    /// Our disco public key (for sharing with peers via the netmap).
    pub fn public(&self) -> DiscoPublic {
        self.public.clone()
    }

    /// Seal a disco `Message` into a wire packet for `peer_disco`.
    pub fn seal(&self, peer_disco: &DiscoPublic, msg: &Message) -> Option<Vec<u8>> {
        let payload = msg.marshal();
        disco::seal_packet(&self.private, peer_disco, &payload).ok()
    }

    /// Open a disco wire packet and parse the inner `Message`.
    ///
    /// Returns the sender's disco public key and the parsed message, or `None`
    /// on bad magic / auth failure / parse error.
    pub fn open(&self, packet: &[u8]) -> Option<(DiscoPublic, Message)> {
        let (sender, plaintext) = disco::open_packet(&self.private, packet)?;
        let msg = Message::parse(&plaintext).ok()?;
        Some((sender, msg))
    }

    /// Check whether a raw packet looks like a disco envelope.
    pub fn looks_like_disco(packet: &[u8]) -> bool {
        disco::looks_like_disco_wrapper(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustscale_disco::{Message, Ping};
    use rustscale_key::NodePublic;

    #[test]
    fn seal_open_roundtrip() {
        let a = DiscoIo::new(DiscoPrivate::generate());
        let b = DiscoIo::new(DiscoPrivate::generate());

        let ping = Message::Ping(Ping {
            tx_id: [1; 12],
            node_key: NodePublic::from_raw32([0u8; 32]),
            padding: 0,
        });

        let packet = a.seal(&b.public(), &ping).expect("seal");
        assert!(DiscoIo::looks_like_disco(&packet));

        let (sender, msg) = b.open(&packet).expect("open");
        assert_eq!(sender, a.public());
        assert_eq!(msg, ping);
    }

    #[test]
    fn open_wrong_key_fails() {
        let a = DiscoIo::new(DiscoPrivate::generate());
        let evil = DiscoIo::new(DiscoPrivate::generate());

        let ping = Message::Ping(Ping {
            tx_id: [1; 12],
            node_key: NodePublic::from_raw32([0u8; 32]),
            padding: 0,
        });

        let packet = a.seal(&evil.public(), &ping).expect("seal");
        assert!(a.open(&packet).is_none());
    }
}
