//! Machine keys: communication with the Tailscale coordination server
//! (Curve25519 / NaCl box), including precomputed shared keys.

use std::fmt;
use std::str::FromStr;

use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::boxcrypto;
use crate::{
    append_hex_key, clamp25519, ct_eq, debug32, parse_typed_hex, redacted, KeyError, KEY_LEN,
    MACHINE_PUB_PREFIX, PRIV_PREFIX,
};

use crypto_box::{PublicKey, SalsaBox, SecretKey};

/// A machine private key, used for control-plane communication.
///
/// Serializes to `privkey:<64 hex>` (matching Go's on-disk form); public keys
/// serialize to `mkey:<64 hex>`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct MachinePrivate {
    k: [u8; KEY_LEN],
}

impl MachinePrivate {
    /// Generate a fresh, clamped machine private key.
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

    /// Derive the corresponding [`MachinePublic`]. Panics if this key is zero.
    pub fn public(&self) -> MachinePublic {
        assert!(
            !self.is_zero(),
            "can't take the public key of a zero MachinePrivate"
        );
        MachinePublic {
            k: boxcrypto::derive_public(&self.k),
        }
    }

    /// Typed hex text form (`privkey:<hex>`).
    pub fn marshal_text(&self) -> String {
        append_hex_key(PRIV_PREFIX, &self.k)
    }

    /// Seal `cleartext` to `peer`, returning `nonce(24) || ct`.
    pub fn seal_to(&self, peer: &MachinePublic, cleartext: &[u8]) -> Result<Vec<u8>, KeyError> {
        if self.is_zero() || peer.is_zero() {
            return Err(KeyError::ZeroKey);
        }
        boxcrypto::seal(&self.k, &peer.k, cleartext)
    }

    /// Open a box from `peer`. Returns `None` on failure.
    pub fn open_from(&self, peer: &MachinePublic, ciphertext: &[u8]) -> Option<Vec<u8>> {
        if self.is_zero() || peer.is_zero() {
            return None;
        }
        boxcrypto::open(&self.k, &peer.k, ciphertext)
    }

    /// Precompute the NaCl box shared key with `peer` for repeated seal/open.
    pub fn shared_key(&self, peer: &MachinePublic) -> MachinePrecomputedSharedKey {
        if self.is_zero() || peer.is_zero() {
            return MachinePrecomputedSharedKey::zero();
        }
        let sk = SecretKey::from_bytes(self.k);
        let pk = PublicKey::from_bytes(peer.k);
        MachinePrecomputedSharedKey {
            salsa: Some(SalsaBox::new(&pk, &sk)),
        }
    }
}

impl FromStr for MachinePrivate {
    type Err = KeyError;
    fn from_str(s: &str) -> Result<Self, KeyError> {
        let mut k = [0u8; KEY_LEN];
        parse_typed_hex(s, PRIV_PREFIX, &mut k)?;
        Ok(Self { k })
    }
}

impl fmt::Display for MachinePrivate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        redacted(f, "MachinePrivate")
    }
}

impl fmt::Debug for MachinePrivate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        redacted(f, "MachinePrivate")
    }
}

impl Serialize for MachinePrivate {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        s.serialize_str(&self.marshal_text())
    }
}

impl<'de> Deserialize<'de> for MachinePrivate {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw: String = serde::Deserialize::deserialize(d)?;
        Self::from_str(&raw).map_err(serde::de::Error::custom)
    }
}

/// The public portion of a [`MachinePrivate`], serialized as `mkey:<hex>`.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MachinePublic {
    k: [u8; KEY_LEN],
}

impl MachinePublic {
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

    /// Tailscale debug form (`[xxxxx]`).
    pub fn short_string(&self) -> String {
        debug32(&self.k)
    }

    /// Typed hex text form (`mkey:<hex>`).
    pub fn marshal_text(&self) -> String {
        append_hex_key(MACHINE_PUB_PREFIX, &self.k)
    }
}

impl FromStr for MachinePublic {
    type Err = KeyError;
    fn from_str(s: &str) -> Result<Self, KeyError> {
        let mut k = [0u8; KEY_LEN];
        parse_typed_hex(s, MACHINE_PUB_PREFIX, &mut k)?;
        Ok(Self { k })
    }
}

impl fmt::Display for MachinePublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.marshal_text())
    }
}

impl fmt::Debug for MachinePublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MachinePublic({})", self.short_string())
    }
}

impl Serialize for MachinePublic {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        s.serialize_str(&self.marshal_text())
    }
}

impl Default for MachinePublic {
    fn default() -> Self {
        Self::from_raw32([0u8; KEY_LEN])
    }
}

impl<'de> Deserialize<'de> for MachinePublic {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw: String = serde::Deserialize::deserialize(d)?;
        Self::from_str(&raw).map_err(serde::de::Error::custom)
    }
}

/// A precomputed NaCl box shared key between a [`MachinePrivate`] and a
/// [`MachinePublic`], matching Go's `MachinePrecomputedSharedKey`.
///
/// Stores the precomputed cipher; `None` represents the zero (uninitialized)
/// key. Seal/open produce `nonce(24) || ct`, compatible with
/// [`MachinePrivate::seal_to`].
pub struct MachinePrecomputedSharedKey {
    salsa: Option<SalsaBox>,
}

impl MachinePrecomputedSharedKey {
    /// The zero (uninitialized) shared key — cannot seal or open.
    pub fn zero() -> Self {
        Self { salsa: None }
    }

    /// Whether this is the zero key.
    pub fn is_zero(&self) -> bool {
        self.salsa.is_none()
    }

    /// Seal `cleartext` with the precomputed key, returning `nonce(24) || ct`.
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
        salsa.decrypt(nonce, &ciphertext[crate::NONCE_LEN..]).ok()
    }
}

impl fmt::Debug for MachinePrecomputedSharedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        redacted(f, "MachinePrecomputedSharedKey")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_public_text_form() {
        let privk = MachinePrivate::generate();
        let pubk = privk.public();
        let s = pubk.to_string();
        assert!(s.starts_with("mkey:"));
        assert_eq!(s.len(), "mkey:".len() + 64);
        let parsed: MachinePublic = s.parse().unwrap();
        assert_eq!(parsed, pubk);
    }

    #[test]
    fn machine_private_redacted() {
        let privk = MachinePrivate::generate();
        let hex = hex::encode(privk.raw32());
        assert!(!privk.to_string().contains(&hex));
        assert!(!format!("{privk:?}").contains(&hex));
        assert!(privk.marshal_text().starts_with("privkey:"));
    }

    #[test]
    fn machine_seal_open_and_precompute() {
        let a = MachinePrivate::generate();
        let b = MachinePrivate::generate();
        let msg = b"machine box msg";
        let ct = a.seal_to(&b.public(), msg).unwrap();
        assert_eq!(b.open_from(&a.public(), &ct), Some(msg.to_vec()));

        // Precomputed shared key must interoperate with seal_to.
        let shared = b.shared_key(&a.public());
        let ct2 = shared.seal(msg).unwrap();
        assert_eq!(a.open_from(&b.public(), &ct2), Some(msg.to_vec()));

        let shared_a = a.shared_key(&b.public());
        assert_eq!(shared_a.open(&ct), Some(msg.to_vec()));
    }

    #[test]
    fn machine_precompute_open_wrong_key_fails() {
        let a = MachinePrivate::generate();
        let evil = MachinePrivate::generate();
        let shared = a.shared_key(&evil.public());
        assert!(shared.open(&[0u8; 40]).is_none());
        assert!(MachinePrecomputedSharedKey::zero().seal(b"x").is_err());
        assert!(MachinePrecomputedSharedKey::zero()
            .open(&[0u8; 40])
            .is_none());
    }

    #[test]
    fn machine_serde_roundtrip() {
        let privk = MachinePrivate::generate();
        let json = serde_json::to_string(&privk).unwrap();
        assert!(json.starts_with("\"privkey:"));
        assert_eq!(
            serde_json::from_str::<MachinePrivate>(&json)
                .unwrap()
                .raw32(),
            privk.raw32()
        );
        let pubj = serde_json::to_string(&privk.public()).unwrap();
        assert!(pubj.starts_with("\"mkey:"));
    }
}
