//! Key CBOR wire types.
//!
//! Wire format (from Go `key.go:36-52`):
//! ```text
//! Key {
//!   1: kind (u8: 0=Invalid, 1=Key25519)
//!   2: votes (uint)
//!   3: public ([]byte, ed25519 public key)
//!  12: meta (map<string,string>, omit if empty)
//! }
//! ```

use std::collections::BTreeMap;

use ciborium::value::Value;
use serde::{Deserialize, Serialize};

use crate::aum::{
    canonical_key_cmp, decode_value, encode_value, expect_bytes, expect_key, expect_map,
    expect_text, expect_uint, set_unique, DecodeError,
};

/// Key kind. Wire representation is `u8` in range 0..=1.
///
/// 0 = Invalid, 1 = Key25519.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum KeyKind {
    Invalid = 0,
    Key25519 = 1,
}

impl KeyKind {
    #[inline]
    fn to_u8(self) -> u8 {
        self as u8
    }

    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Invalid),
            1 => Some(Self::Key25519),
            _ => None,
        }
    }
}

/// Public key known to tailnet lock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Key {
    /// Key 1: key kind.
    pub kind: KeyKind,
    /// Key 2: voting weight for fork resolution.
    pub votes: u64,
    /// Key 3: public key bytes (32 bytes for Key25519).
    pub public: Vec<u8>,
    /// Key 12 (omit if empty): arbitrary metadata.
    pub meta: Option<BTreeMap<String, String>>,
}

impl Key {
    /// Encode to CTAP2 canonical CBOR bytes.
    pub fn encode(&self) -> Vec<u8> {
        encode_value(&self.to_value())
    }

    /// Decode from CBOR bytes, rejecting duplicate keys and excessive nesting.
    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let val = decode_value(data)?;
        Self::from_value(val)
    }

    pub(crate) fn to_value(&self) -> Value {
        let mut map: Vec<(Value, Value)> = vec![
            (
                Value::Integer(1.into()),
                Value::Integer(self.kind.to_u8().into()),
            ),
            (Value::Integer(2.into()), Value::Integer(self.votes.into())),
            (Value::Integer(3.into()), Value::Bytes(self.public.clone())),
        ];

        if let Some(meta) = &self.meta {
            if !meta.is_empty() {
                let entries: Vec<(Value, Value)> = meta
                    .iter()
                    .map(|(k, v)| (Value::Text(k.clone()), Value::Text(v.clone())))
                    .collect();
                map.push((Value::Integer(12.into()), Value::Map(entries)));
            }
        }

        map.sort_by(|a, b| canonical_key_cmp(&a.0, &b.0));
        Value::Map(map)
    }

    pub(crate) fn from_value(v: Value) -> Result<Self, DecodeError> {
        let m = expect_map(v)?;
        let mut kind = None;
        let mut votes = None;
        let mut public = None;
        let mut meta = None;

        for (k, v) in m {
            match expect_key(&k)? {
                1 => {
                    let n = expect_uint(v)?;
                    set_unique(
                        &mut kind,
                        KeyKind::from_u8(n as u8).ok_or(DecodeError::InvalidKeyKind(n))?,
                    )?;
                }
                2 => set_unique(&mut votes, expect_uint(v)?)?,
                3 => set_unique(&mut public, expect_bytes(v)?)?,
                12 => {
                    let entries = expect_map(v)?;
                    let mut m = BTreeMap::new();
                    for (mk, mv) in entries {
                        let mk = expect_text(&mk)?;
                        let mv = expect_text(&mv)?;
                        if m.insert(mk, mv).is_some() {
                            return Err(DecodeError::DuplicateKey);
                        }
                    }
                    set_unique(&mut meta, m)?;
                }
                _ => {}
            }
        }

        Ok(Self {
            kind: kind.ok_or(DecodeError::MissingField(1))?,
            votes: votes.ok_or(DecodeError::MissingField(2))?,
            public: public.ok_or(DecodeError::MissingField(3))?,
            meta,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_roundtrip() {
        let key = Key {
            kind: KeyKind::Key25519,
            votes: 1,
            public: vec![0x42; 32],
            meta: None,
        };
        let enc = key.encode();
        let dec = Key::decode(&enc).unwrap();
        assert_eq!(key, dec);
    }

    #[test]
    fn key_with_meta_roundtrip() {
        let mut meta = BTreeMap::new();
        meta.insert("name".into(), "root".into());
        meta.insert("created".into(), "2026-01-01".into());
        let key = Key {
            kind: KeyKind::Key25519,
            votes: 100,
            public: vec![0xAA; 32],
            meta: Some(meta),
        };
        let enc = key.encode();
        let dec = Key::decode(&enc).unwrap();
        assert_eq!(key, dec);
    }

    #[test]
    fn key_omits_empty_meta() {
        let key = Key {
            kind: KeyKind::Key25519,
            votes: 1,
            public: vec![0x42; 32],
            meta: None,
        };
        let enc = key.encode();
        let val: Value = ciborium::from_reader(&enc[..]).unwrap();
        let map = match val {
            Value::Map(m) => m,
            _ => panic!("expected map"),
        };
        // Keys 1, 2, 3 only — key 12 (meta) omitted.
        assert_eq!(map.len(), 3);
    }

    #[test]
    fn key_rejects_duplicate_keys() {
        let map = vec![
            (Value::Integer(1.into()), Value::Integer(1.into())),
            (Value::Integer(1.into()), Value::Integer(0.into())),
        ];
        let data = encode_value(&Value::Map(map));
        assert_eq!(Key::decode(&data).unwrap_err(), DecodeError::DuplicateKey);
    }
}
