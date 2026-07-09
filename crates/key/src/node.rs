//! Node keys: WireGuard tunnel + DERP communication (Curve25519 / NaCl box).

use std::fmt;
use std::str::FromStr;

use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::boxcrypto;
use crate::{
    append_hex_key, clamp25519, debug32, parse_typed_hex, redacted, KeyError, KEY_LEN,
    NODE_PUB_PREFIX, PRIV_PREFIX,
};

/// A node private key, used for WireGuard tunnels and DERP communication.
///
/// Serializes to `privkey:<64 hex>` for persistence but never reveals its raw
/// bytes via [`fmt::Display`] or [`fmt::Debug`].
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct NodePrivate {
    k: [u8; KEY_LEN],
}

impl NodePrivate {
    /// Generate a fresh node private key using the OS RNG, clamped for box use.
    pub fn generate() -> Self {
        let mut k = [0u8; KEY_LEN];
        rand::rngs::OsRng.fill_bytes(&mut k);
        clamp25519(&mut k);
        Self { k }
    }

    /// Construct from an already-clamped (or raw) 32-byte scalar.
    pub fn from_raw32(bytes: [u8; KEY_LEN]) -> Self {
        Self { k: bytes }
    }

    /// The 32 raw bytes (clamped form).
    pub fn raw32(&self) -> [u8; KEY_LEN] {
        self.k
    }

    /// Whether this is the all-zero (uninitialized) key.
    pub fn is_zero(&self) -> bool {
        self.k.iter().all(|&b| b == 0)
    }

    /// Constant-time-ish equality with another private key.
    pub fn equal(&self, other: &Self) -> bool {
        crate::ct_eq(&self.k, &other.k)
    }

    /// Derive the corresponding [`NodePublic`]. Panics if this key is zero.
    pub fn public(&self) -> NodePublic {
        assert!(
            !self.is_zero(),
            "can't take the public key of a zero NodePrivate"
        );
        NodePublic {
            k: boxcrypto::derive_public(&self.k),
        }
    }

    /// The typed hex text form (`privkey:<hex>`), for on-disk persistence.
    pub fn marshal_text(&self) -> String {
        append_hex_key(PRIV_PREFIX, &self.k)
    }

    /// Seal `cleartext` to `peer` from this key, returning `nonce(24) || ct`.
    pub fn seal_to(&self, peer: &NodePublic, cleartext: &[u8]) -> Result<Vec<u8>, KeyError> {
        if self.is_zero() || peer.is_zero() {
            return Err(KeyError::ZeroKey);
        }
        boxcrypto::seal(&self.k, &peer.k, cleartext)
    }

    /// Open a box sealed from `peer` to this key. Returns `None` on failure.
    pub fn open_from(&self, peer: &NodePublic, ciphertext: &[u8]) -> Option<Vec<u8>> {
        if self.is_zero() || peer.is_zero() {
            return None;
        }
        boxcrypto::open(&self.k, &peer.k, ciphertext)
    }
}

impl FromStr for NodePrivate {
    type Err = KeyError;
    fn from_str(s: &str) -> Result<Self, KeyError> {
        let mut k = [0u8; KEY_LEN];
        parse_typed_hex(s, PRIV_PREFIX, &mut k)?;
        Ok(Self { k })
    }
}

impl fmt::Display for NodePrivate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        redacted(f, "NodePrivate")
    }
}

impl fmt::Debug for NodePrivate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        redacted(f, "NodePrivate")
    }
}

impl Serialize for NodePrivate {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        s.serialize_str(&self.marshal_text())
    }
}

impl<'de> Deserialize<'de> for NodePrivate {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw: String = serde::Deserialize::deserialize(d)?;
        Self::from_str(&raw).map_err(serde::de::Error::custom)
    }
}

/// The public portion of a [`NodePrivate`], serialized as `nodekey:<hex>`.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodePublic {
    k: [u8; KEY_LEN],
}

impl NodePublic {
    /// Construct from 32 raw bytes (e.g. a binary protocol field).
    pub fn from_raw32(bytes: [u8; KEY_LEN]) -> Self {
        Self { k: bytes }
    }

    /// The 32 raw bytes.
    pub fn raw32(&self) -> [u8; KEY_LEN] {
        self.k
    }

    /// Whether this is the all-zero key.
    pub fn is_zero(&self) -> bool {
        self.k.iter().all(|&b| b == 0)
    }

    /// Tailscale debug form: first five base64 digits in brackets, e.g. `[abcde]`.
    pub fn short_string(&self) -> String {
        debug32(&self.k)
    }

    /// The typed hex text form (`nodekey:<hex>`).
    pub fn marshal_text(&self) -> String {
        append_hex_key(NODE_PUB_PREFIX, &self.k)
    }
}

impl FromStr for NodePublic {
    type Err = KeyError;
    fn from_str(s: &str) -> Result<Self, KeyError> {
        let mut k = [0u8; KEY_LEN];
        parse_typed_hex(s, NODE_PUB_PREFIX, &mut k)?;
        Ok(Self { k })
    }
}

impl fmt::Display for NodePublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.marshal_text())
    }
}

impl fmt::Debug for NodePublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodePublic({})", self.short_string())
    }
}

impl Serialize for NodePublic {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        s.serialize_str(&self.marshal_text())
    }
}

impl Default for NodePublic {
    fn default() -> Self {
        Self::from_raw32([0u8; KEY_LEN])
    }
}

impl<'de> Deserialize<'de> for NodePublic {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw: String = serde::Deserialize::deserialize(d)?;
        Self::from_str(&raw).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_public_text_form() {
        let privk = NodePrivate::generate();
        let pubk = privk.public();
        let s = pubk.to_string();
        assert!(s.starts_with("nodekey:"));
        assert_eq!(s.len(), "nodekey:".len() + 64);
        let parsed: NodePublic = s.parse().unwrap();
        assert_eq!(parsed, pubk);
    }

    #[test]
    fn node_private_text_form_roundtrips_and_is_redacted() {
        let privk = NodePrivate::generate();
        let s = privk.marshal_text();
        assert!(s.starts_with("privkey:"));
        assert_eq!(s.len(), "privkey:".len() + 64);
        let parsed: NodePrivate = s.parse().unwrap();
        assert_eq!(parsed.raw32(), privk.raw32());
        // Display/Debug must never leak raw bytes.
        assert!(!privk.to_string().contains(&hex::encode(privk.raw32())));
        assert!(!format!("{privk:?}").contains(&hex::encode(privk.raw32())));
    }

    #[test]
    fn node_public_serde_roundtrip() {
        let privk = NodePrivate::generate();
        let pubk = privk.public();
        let json = serde_json::to_string(&pubk).unwrap();
        assert!(json.starts_with("\"nodekey:") && json.ends_with('"'));
        let back: NodePublic = serde_json::from_str(&json).unwrap();
        assert_eq!(back, pubk);
    }

    #[test]
    fn node_private_serde_roundtrip() {
        let privk = NodePrivate::generate();
        let json = serde_json::to_string(&privk).unwrap();
        assert!(json.starts_with("\"privkey:") && json.ends_with('"'));
        let back: NodePrivate = serde_json::from_str(&json).unwrap();
        assert_eq!(back.raw32(), privk.raw32());
    }

    #[test]
    fn node_seal_open_roundtrip() {
        let a = NodePrivate::generate();
        let b = NodePrivate::generate();
        let msg = b"hello tailscale node box";
        let ct = a.seal_to(&b.public(), msg).unwrap();
        assert_eq!(ct.len(), 24 + msg.len() + 16);
        let pt = b.open_from(&a.public(), &ct).expect("open succeeds");
        assert_eq!(pt, msg);
    }

    #[test]
    fn node_open_with_wrong_key_fails() {
        let a = NodePrivate::generate();
        let b = NodePrivate::generate();
        let evil = NodePrivate::generate();
        let ct = a.seal_to(&b.public(), b"secret").unwrap();
        // Wrong sender public key => different shared key => auth failure.
        assert!(b.open_from(&evil.public(), &ct).is_none());
        // NaCl box shared keys are symmetric, so the genuine recipient opens fine.
        assert_eq!(
            b.open_from(&a.public(), &ct).as_deref(),
            Some(&b"secret"[..])
        );
    }

    #[test]
    fn node_open_short_ciphertext_fails() {
        let a = NodePrivate::generate();
        let b = NodePrivate::generate();
        assert!(a.open_from(&b.public(), &[0u8; 10]).is_none());
    }

    #[test]
    fn node_zero_key_is_rejected() {
        let z = NodePrivate::from_raw32([0u8; KEY_LEN]);
        let peer = NodePrivate::generate();
        assert!(z.seal_to(&peer.public(), b"x").is_err());
        assert!(peer
            .open_from(&NodePublic::from_raw32([0u8; KEY_LEN]), &[0u8; 40])
            .is_none());
    }

    #[test]
    #[should_panic(expected = "zero NodePrivate")]
    fn node_zero_private_cannot_derive_public() {
        let z = NodePrivate::from_raw32([0u8; KEY_LEN]);
        let _ = z.public();
    }

    #[test]
    fn node_public_short_string_shape() {
        let pubk = NodePrivate::generate().public();
        let ss = pubk.short_string();
        assert_eq!(ss.len(), 7);
        assert!(ss.starts_with('[') && ss.ends_with(']'));
        assert_eq!(NodePublic::from_raw32([0u8; KEY_LEN]).short_string(), "");
    }

    #[test]
    fn node_private_clamped_on_generation() {
        let privk = NodePrivate::generate();
        let b = privk.raw32();
        assert_eq!(b[0] & 7, 0, "low 3 bits of byte 0 must be clear");
        assert_eq!(b[31] & 0x80, 0, "high bit of byte 31 must be clear");
        assert_eq!(b[31] & 0x40, 0x40, "bit 6 of byte 31 must be set");
    }

    #[test]
    fn node_serde_rejects_bad_prefix() {
        assert!(serde_json::from_str::<NodePublic>("\"mkey:00\"").is_err());
        assert!(serde_json::from_str::<NodePrivate>("\"nodekey:00\"").is_err());
    }
}
