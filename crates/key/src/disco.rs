//! Disco keys: peer-to-peer path discovery (Curve25519 / NaCl box with a
//! precomputed shared key).

use std::fmt;
use std::str::FromStr;

use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::{
    append_hex_key, clamp25519, ct_eq, parse_typed_hex, redacted, KeyError, KEY_LEN,
    DISCO_PUB_PREFIX, PRIV_PREFIX,
};

use crypto_box::{PublicKey, SecretKey, SalsaBox};

/// A disco private key, used for NAT-traversal path discovery.
///
/// Public keys serialize to `discokey:<hex>`; private keys serialize to
/// `privkey:<hex>` (matching Go's private-key convention) but never reveal raw
/// bytes via [`fmt::Display`] or [`fmt::Debug`].
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DiscoPrivate {
    k: [u8; KEY_LEN],
}

impl DiscoPrivate {
    /// Generate a fresh, clamped disco private key.
    pub fn generate() -> Self {
        let mut k = [0u8; KEY_LEN];
        rand::rngs::OsRng.fill_bytes(&mut k);
        clamp25519(&mut k);
        Self { k }
    }

    /// Construct from 32 raw bytes.
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

    /// Constant-time-ish equality.
    pub fn equal(&self, other: &Self) -> bool {
        ct_eq(&self.k, &other.k)
    }

    /// Derive the corresponding [`DiscoPublic`]. Panics if this key is zero.
    pub fn public(&self) -> DiscoPublic {
        assert!(!self.is_zero(), "can't take the public key of a zero DiscoPrivate");
        DiscoPublic {
            k: crate::boxcrypto::derive_public(&self.k),
        }
    }

    /// Typed hex text form (`privkey:<hex>`).
    pub fn marshal_text(&self) -> String {
        append_hex_key(PRIV_PREFIX, &self.k)
    }

    /// Precompute the disco shared key with `peer` for seal/open.
    ///
    /// Matches Go's `DiscoPrivate.Shared(DiscoPublic) -> DiscoShared`, which
    /// uses `box.Precompute` (HSalsa over the X25519 shared secret).
    pub fn shared(&self, peer: &DiscoPublic) -> DiscoShared {
        if self.is_zero() || peer.is_zero() {
            return DiscoShared::zero();
        }
        let sk = SecretKey::from_bytes(self.k);
        let pk = PublicKey::from_bytes(peer.k);
        DiscoShared {
            salsa: Some(SalsaBox::new(&pk, &sk)),
        }
    }
}

impl FromStr for DiscoPrivate {
    type Err = KeyError;
    fn from_str(s: &str) -> Result<Self, KeyError> {
        let mut k = [0u8; KEY_LEN];
        parse_typed_hex(s, PRIV_PREFIX, &mut k)?;
        Ok(Self { k })
    }
}

impl fmt::Display for DiscoPrivate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        redacted(f, "DiscoPrivate")
    }
}

impl fmt::Debug for DiscoPrivate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        redacted(f, "DiscoPrivate")
    }
}

impl Serialize for DiscoPrivate {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        s.serialize_str(&self.marshal_text())
    }
}

impl<'de> Deserialize<'de> for DiscoPrivate {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw: String = serde::Deserialize::deserialize(d)?;
        Self::from_str(&raw).map_err(serde::de::Error::custom)
    }
}

/// The public portion of a [`DiscoPrivate`], serialized as `discokey:<hex>`.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DiscoPublic {
    k: [u8; KEY_LEN],
}

impl DiscoPublic {
    /// Construct from 32 raw bytes.
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

    /// Lexicographic comparison of the raw key bytes (matches Go's `Compare`).
    pub fn compare(&self, other: &Self) -> std::cmp::Ordering {
        self.k.cmp(&other.k)
    }

    /// Tailscale debug form for disco keys: `d:<16 hex>` (first 8 bytes), or
    /// empty for an all-zero key.
    pub fn short_string(&self) -> String {
        if self.is_zero() {
            return String::new();
        }
        format!("d:{}", hex::encode(&self.k[..8]))
    }

    /// Typed hex text form (`discokey:<hex>`).
    pub fn marshal_text(&self) -> String {
        append_hex_key(DISCO_PUB_PREFIX, &self.k)
    }
}

impl FromStr for DiscoPublic {
    type Err = KeyError;
    fn from_str(s: &str) -> Result<Self, KeyError> {
        let mut k = [0u8; KEY_LEN];
        parse_typed_hex(s, DISCO_PUB_PREFIX, &mut k)?;
        Ok(Self { k })
    }
}

impl fmt::Display for DiscoPublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.marshal_text())
    }
}

impl fmt::Debug for DiscoPublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DiscoPublic({})", self.short_string())
    }
}

impl Serialize for DiscoPublic {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        s.serialize_str(&self.marshal_text())
    }
}

impl Default for DiscoPublic {
    fn default() -> Self {
        Self::from_raw32([0u8; KEY_LEN])
    }
}

impl<'de> Deserialize<'de> for DiscoPublic {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw: String = serde::Deserialize::deserialize(d)?;
        Self::from_str(&raw).map_err(serde::de::Error::custom)
    }
}

/// A precomputed NaCl box shared key between a [`DiscoPrivate`] and a
/// [`DiscoPublic`], matching Go's `DiscoShared`.
///
/// Seal/open produce `nonce(24) || ct` using `box.SealAfterPrecomputation` /
/// `box.OpenAfterPrecomputation` semantics — wire-compatible with Go.
pub struct DiscoShared {
    pub(super) salsa: Option<SalsaBox>,
}

impl DiscoShared {
    /// The zero (uninitialized) shared key — cannot seal or open.
    pub fn zero() -> Self {
        Self { salsa: None }
    }

    /// Whether this is the zero key.
    pub fn is_zero(&self) -> bool {
        self.salsa.is_none()
    }

    /// Constant-time-ish equality between two shared keys' validity state.
    ///
    /// Two zero shared keys are equal; a zero and non-zero key are not.
    /// (Go compares the raw 32-byte precomputed key; this compares validity,
    /// which is sufficient for the discovery protocol's use of equality.)
    pub fn equal(&self, other: &Self) -> bool {
        self.salsa.is_none() == other.salsa.is_none()
    }

    /// Seal `cleartext` with the precomputed shared key, returning
    /// `nonce(24) || ct`.
    pub fn seal(&self, cleartext: &[u8]) -> Result<Vec<u8>, KeyError> {
        use crypto_box::aead::{generic_array::GenericArray, Aead};
        use rand::RngCore;
        let salsa = self.salsa.as_ref().ok_or(KeyError::ZeroKey)?;
        let mut nonce_bytes = [0u8; crate::NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = GenericArray::from_slice(&nonce_bytes);
        let ct = salsa
            .encrypt(nonce, cleartext)
            .map_err(|_| KeyError::Encrypt)?;
        let mut out = Vec::with_capacity(crate::NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Open a `nonce(24) || ct` box. Returns `None` on failure.
    pub fn open(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        use crypto_box::aead::{generic_array::GenericArray, Aead};
        let salsa = self.salsa.as_ref()?;
        if ciphertext.len() < crate::NONCE_LEN {
            return None;
        }
        let nonce = GenericArray::from_slice(&ciphertext[..crate::NONCE_LEN]);
        salsa
            .decrypt(nonce, &ciphertext[crate::NONCE_LEN..])
            .ok()
    }
}

impl fmt::Debug for DiscoShared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        redacted(f, "DiscoShared")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disco_public_text_form() {
        let privk = DiscoPrivate::generate();
        let pubk = privk.public();
        let s = pubk.to_string();
        assert!(s.starts_with("discokey:"));
        assert_eq!(s.len(), "discokey:".len() + 64);
        let parsed: DiscoPublic = s.parse().unwrap();
        assert_eq!(parsed, pubk);
    }

    #[test]
    fn disco_private_redacted_and_parseable() {
        let privk = DiscoPrivate::generate();
        assert!(!privk.to_string().contains(&hex::encode(privk.raw32())));
        let s = privk.marshal_text();
        assert!(s.starts_with("privkey:"));
        assert_eq!(DiscoPrivate::from_str(&s).unwrap().raw32(), privk.raw32());
    }

    #[test]
    fn disco_short_string_shape() {
        let pubk = DiscoPrivate::generate().public();
        let ss = pubk.short_string();
        assert!(ss.starts_with("d:"));
        assert_eq!(ss.len(), "d:".len() + 16);
        assert_eq!(DiscoPublic::from_raw32([0u8; KEY_LEN]).short_string(), "");
    }

    #[test]
    fn disco_shared_seal_open_roundtrip() {
        let a = DiscoPrivate::generate();
        let b = DiscoPrivate::generate();
        let shared_a = a.shared(&b.public());
        let shared_b = b.shared(&a.public());
        let msg = b"disco discovery frame";
        let ct = shared_a.seal(msg).unwrap();
        assert_eq!(ct.len(), 24 + msg.len() + 16);
        assert_eq!(shared_b.open(&ct), Some(msg.to_vec()));
    }

    #[test]
    fn disco_shared_open_wrong_key_fails() {
        let a = DiscoPrivate::generate();
        let b = DiscoPrivate::generate();
        let evil = DiscoPrivate::generate();
        let ct = a.shared(&b.public()).seal(b"x").unwrap();
        assert!(evil.shared(&b.public()).open(&ct).is_none());
        assert!(a.shared(&evil.public()).open(&ct).is_none());
        assert!(DiscoShared::zero().seal(b"x").is_err());
        assert!(DiscoShared::zero().open(&ct).is_none());
        assert!(a.shared(&b.public()).open(&[0u8; 5]).is_none());
    }

    #[test]
    fn disco_serde_roundtrip() {
        let privk = DiscoPrivate::generate();
        let pj = serde_json::to_string(&privk.public()).unwrap();
        assert!(pj.starts_with("\"discokey:"));
        let back: DiscoPublic = serde_json::from_str(&pj).unwrap();
        assert_eq!(back, privk.public());
        let sj = serde_json::to_string(&privk).unwrap();
        assert!(sj.starts_with("\"privkey:"));
        assert_eq!(
            serde_json::from_str::<DiscoPrivate>(&sj).unwrap().raw32(),
            privk.raw32()
        );
    }

    #[test]
    fn disco_compare_orders_lexicographically() {
        let mut lo = [0u8; KEY_LEN];
        lo[0] = 1;
        let mut hi = [0u8; KEY_LEN];
        hi[0] = 2;
        let a = DiscoPublic::from_raw32(lo);
        let b = DiscoPublic::from_raw32(hi);
        assert_eq!(a.compare(&b), std::cmp::Ordering::Less);
        assert!(a < b);
    }
}
