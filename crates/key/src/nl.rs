//! Network-lock (Tailnet Lock) Ed25519 keys.
//!
//! Public keys use `nlpub:<hex>` on the wire and accept the CLI spelling
//! `tlpub:<hex>`. Private keys use the existing persistence-only
//! `privkey:<hex>` spelling and are always redacted from Display and Debug.

use std::fmt;
use std::str::FromStr;

use ed25519_dalek::{Signer as _, SigningKey};
use rand::RngCore as _;
use serde::{Deserialize, Serialize};

use crate::{append_hex_key, ct_eq, parse_typed_hex, redacted, KeyError, KEY_LEN, PRIV_PREFIX};

pub(crate) const NL_PUB_PREFIX: &str = "nlpub:";
pub(crate) const NL_PUB_PREFIX_CLI: &str = "tlpub:";

/// An Ed25519 private key used to sign Tailnet Lock AUMs and node keys.
#[derive(Clone, PartialEq, Eq)]
pub struct NLPrivate {
    k: [u8; KEY_LEN],
}

impl NLPrivate {
    /// Generate a fresh key using the operating system RNG.
    pub fn generate() -> Self {
        let mut k = [0u8; KEY_LEN];
        rand::rngs::OsRng.fill_bytes(&mut k);
        Self { k }
    }

    pub fn from_raw32(k: [u8; KEY_LEN]) -> Self {
        Self { k }
    }

    pub fn raw32(&self) -> [u8; KEY_LEN] {
        self.k
    }

    pub fn is_zero(&self) -> bool {
        self.k.iter().all(|byte| *byte == 0)
    }

    /// Derive the corresponding public key.
    pub fn public(&self) -> NLPublic {
        assert!(!self.is_zero(), "can't derive a zero NLPrivate");
        NLPublic::from_raw32(SigningKey::from_bytes(&self.k).verifying_key().to_bytes())
    }

    /// Sign an already-domain-separated 32-byte TKA digest.
    pub fn sign(&self, digest: &[u8; 32]) -> Result<Vec<u8>, KeyError> {
        if self.is_zero() {
            return Err(KeyError::ZeroKey);
        }
        Ok(SigningKey::from_bytes(&self.k)
            .sign(digest)
            .to_bytes()
            .to_vec())
    }

    pub fn marshal_text(&self) -> String {
        append_hex_key(PRIV_PREFIX, &self.k)
    }
}

impl Default for NLPrivate {
    fn default() -> Self {
        Self::from_raw32([0; KEY_LEN])
    }
}

impl FromStr for NLPrivate {
    type Err = KeyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut k = [0u8; KEY_LEN];
        parse_typed_hex(value, PRIV_PREFIX, &mut k)?;
        Ok(Self { k })
    }
}

impl fmt::Display for NLPrivate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        redacted(formatter, "NLPrivate")
    }
}

impl fmt::Debug for NLPrivate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        redacted(formatter, "NLPrivate")
    }
}

impl Serialize for NLPrivate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.marshal_text())
    }
}

impl<'de> Deserialize<'de> for NLPrivate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::from_str(&raw).map_err(serde::de::Error::custom)
    }
}

/// A Tailnet Lock Ed25519 public key.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NLPublic {
    k: [u8; KEY_LEN],
}

impl NLPublic {
    pub fn from_raw32(bytes: [u8; KEY_LEN]) -> Self {
        Self { k: bytes }
    }

    pub fn raw32(&self) -> [u8; KEY_LEN] {
        self.k
    }

    pub fn is_zero(&self) -> bool {
        self.k.iter().all(|&b| b == 0)
    }

    pub fn equal(&self, other: &Self) -> bool {
        ct_eq(&self.k, &other.k)
    }

    pub fn marshal_text(&self) -> String {
        append_hex_key(NL_PUB_PREFIX, &self.k)
    }

    /// User-facing `tlpub:<hex>` spelling used by lock commands.
    pub fn cli_string(&self) -> String {
        append_hex_key(NL_PUB_PREFIX_CLI, &self.k)
    }
}

impl Default for NLPublic {
    fn default() -> Self {
        Self::from_raw32([0u8; KEY_LEN])
    }
}

impl FromStr for NLPublic {
    type Err = KeyError;

    fn from_str(s: &str) -> Result<Self, KeyError> {
        let mut k = [0u8; KEY_LEN];
        if let Some(rest) = s.strip_prefix(NL_PUB_PREFIX) {
            if rest.len() != KEY_LEN * 2 {
                return Err(KeyError::InvalidLength);
            }
            hex::decode_to_slice(rest, &mut k).map_err(|_| KeyError::InvalidHex)?;
            return Ok(Self { k });
        }
        if let Some(rest) = s.strip_prefix(NL_PUB_PREFIX_CLI) {
            if rest.len() != KEY_LEN * 2 {
                return Err(KeyError::InvalidLength);
            }
            hex::decode_to_slice(rest, &mut k).map_err(|_| KeyError::InvalidHex)?;
            return Ok(Self { k });
        }
        Err(KeyError::MissingPrefix("nlpub:"))
    }
}

impl fmt::Display for NLPublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.marshal_text())
    }
}

impl fmt::Debug for NLPublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_zero() {
            return write!(f, "NLPublic(zero)");
        }
        write!(f, "NLPublic(nlpub:{})", hex::encode(&self.k[..8]))
    }
}

impl Serialize for NLPublic {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        s.serialize_str(&self.marshal_text())
    }
}

impl<'de> Deserialize<'de> for NLPublic {
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
    fn private_signs_and_stays_redacted() {
        use ed25519_dalek::{Signature, VerifyingKey};

        let private = NLPrivate::generate();
        let digest = [7; 32];
        let signature = Signature::from_slice(&private.sign(&digest).unwrap()).unwrap();
        VerifyingKey::from_bytes(&private.public().raw32())
            .unwrap()
            .verify_strict(&digest, &signature)
            .unwrap();
        assert!(!private.to_string().contains(&hex::encode(private.raw32())));
        assert!(!format!("{private:?}").contains(&hex::encode(private.raw32())));
        let encoded = serde_json::to_string(&private).unwrap();
        assert_eq!(
            serde_json::from_str::<NLPrivate>(&encoded).unwrap(),
            private
        );
    }

    #[test]
    fn public_wire_and_cli_forms_roundtrip() {
        let key = NLPublic::from_raw32([0xcd; KEY_LEN]);
        assert_eq!(key.to_string().parse::<NLPublic>().unwrap(), key);
        assert_eq!(key.cli_string().parse::<NLPublic>().unwrap(), key);
        let json = serde_json::to_string(&key).unwrap();
        assert_eq!(serde_json::from_str::<NLPublic>(&json).unwrap(), key);
        assert!(NLPublic::default().is_zero());
        assert!("nodekey:ab".parse::<NLPublic>().is_err());
    }
}
