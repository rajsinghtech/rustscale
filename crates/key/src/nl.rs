//! Network-lock (tailnet-lock) public keys — ed25519 keys serialized as
//! `nlpub:<hex>` on the wire, matching Go's `key.NLPublic`.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{append_hex_key, ct_eq, KeyError, KEY_LEN};

/// The public prefix for network-lock public keys (`nlpub:<hex>`).
pub(crate) const NL_PUB_PREFIX: &str = "nlpub:";
/// The CLI prefix for network-lock public keys (`tlpub:<hex>`).
pub(crate) const NL_PUB_PREFIX_CLI: &str = "tlpub:";

/// A network-lock public key (ed25519), serialized as `nlpub:<hex>`.
///
/// Matches Go's `key.NLPublic`. This is an ed25519 public key used for
/// tailnet lock signatures. Only serialization/deserialization is
/// implemented here; verification requires the ed25519 crate and will be
/// added when tailnet-lock support is ported.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct NLPublic {
    k: [u8; KEY_LEN],
}

impl NLPublic {
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

    /// Typed hex text form (`nlpub:<hex>`).
    pub fn marshal_text(&self) -> String {
        append_hex_key(NL_PUB_PREFIX, &self.k)
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
    fn nl_public_text_form() {
        let bytes = [0xab; KEY_LEN];
        let key = NLPublic::from_raw32(bytes);
        let s = key.to_string();
        assert!(s.starts_with("nlpub:"));
        assert_eq!(s.len(), "nlpub:".len() + 64);
        let parsed: NLPublic = s.parse().unwrap();
        assert_eq!(parsed, key);
    }

    #[test]
    fn nl_public_cli_prefix() {
        let bytes = [0xcd; KEY_LEN];
        let key = NLPublic::from_raw32(bytes);
        let cli = format!("tlpub:{}", hex::encode(bytes));
        let parsed: NLPublic = cli.parse().unwrap();
        assert_eq!(parsed, key);
    }

    #[test]
    fn nl_public_zero_default() {
        let z = NLPublic::default();
        assert!(z.is_zero());
        let s = z.to_string();
        assert_eq!(
            s,
            "nlpub:0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn nl_public_serde_roundtrip() {
        let bytes = [0x42; KEY_LEN];
        let key = NLPublic::from_raw32(bytes);
        let j = serde_json::to_string(&key).unwrap();
        assert!(j.starts_with("\"nlpub:"));
        let back: NLPublic = serde_json::from_str(&j).unwrap();
        assert_eq!(back, key);
    }

    #[test]
    fn nl_public_rejects_bad_prefix() {
        let result: Result<NLPublic, _> = "nodekey:ab".parse();
        assert!(result.is_err());
    }
}
