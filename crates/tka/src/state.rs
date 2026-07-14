//! State CBOR wire types.
//!
//! Wire format (from Go `state.go:26-53`):
//! ```text
//! State {
//!   1: last_aum_hash ([]byte, null for genesis/initial)
//!   2: disablement_values ([][]byte)
//!   3: keys ([]Key)
//!   4: state_id1 (uint, omit if zero)
//!   5: state_id2 (uint, omit if zero)
//! }
//! ```

use ciborium::value::Value;
use serde::{Deserialize, Serialize};

use crate::aum::{
    canonical_key_cmp, decode_value, encode_value, expect_array, expect_bytes, expect_key,
    expect_map, expect_uint, set_unique, DecodeError,
};
use crate::key::Key;

/// Tailnet Key Authority state at an instant in time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// Key 1: BLAKE2s digest of the last-applied AUM (`None` for new state).
    pub last_aum_hash: Option<Vec<u8>>,
    /// Key 2: KDF-derived disablement verification values.
    pub disablement_values: Vec<Vec<u8>>,
    /// Key 3: trusted public keys.
    pub keys: Vec<Key>,
    /// Key 4 (omit if zero): nonce half 1.
    pub state_id1: u64,
    /// Key 5 (omit if zero): nonce half 2.
    pub state_id2: u64,
}

impl State {
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
        let mut map: Vec<(Value, Value)> = Vec::new();

        // Key 1 — last_aum_hash (null if None, matching Go nil []byte).
        map.push((
            Value::Integer(1.into()),
            match &self.last_aum_hash {
                Some(h) => Value::Bytes(h.clone()),
                None => Value::Null,
            },
        ));

        // Key 2 — disablement_values.
        let dv: Vec<Value> = self
            .disablement_values
            .iter()
            .map(|v| Value::Bytes(v.clone()))
            .collect();
        map.push((Value::Integer(2.into()), Value::Array(dv)));

        // Key 3 — keys.
        let keys: Vec<Value> = self.keys.iter().map(Key::to_value).collect();
        map.push((Value::Integer(3.into()), Value::Array(keys)));

        // Key 4 — state_id1 (omit if zero).
        if self.state_id1 != 0 {
            map.push((
                Value::Integer(4.into()),
                Value::Integer(self.state_id1.into()),
            ));
        }

        // Key 5 — state_id2 (omit if zero).
        if self.state_id2 != 0 {
            map.push((
                Value::Integer(5.into()),
                Value::Integer(self.state_id2.into()),
            ));
        }

        map.sort_by(|a, b| canonical_key_cmp(&a.0, &b.0));
        Value::Map(map)
    }

    pub(crate) fn from_value(v: Value) -> Result<Self, DecodeError> {
        let m = expect_map(v)?;
        let mut last_aum_hash: Option<Option<Vec<u8>>> = None;
        let mut disablement_values = None;
        let mut keys = None;
        let mut state_id1 = None;
        let mut state_id2 = None;

        for (k, v) in m {
            match expect_key(&k)? {
                1 => {
                    set_unique(
                        &mut last_aum_hash,
                        match v {
                            Value::Null => None,
                            Value::Bytes(b) => Some(b),
                            _ => return Err(DecodeError::TypeMismatch(1)),
                        },
                    )?;
                }
                2 => {
                    let arr = expect_array(v)?;
                    let mut out = Vec::with_capacity(arr.len());
                    for item in arr {
                        out.push(expect_bytes(item)?);
                    }
                    set_unique(&mut disablement_values, out)?;
                }
                3 => {
                    let arr = expect_array(v)?;
                    let mut out = Vec::with_capacity(arr.len());
                    for item in arr {
                        out.push(Key::from_value(item)?);
                    }
                    set_unique(&mut keys, out)?;
                }
                4 => set_unique(&mut state_id1, expect_uint(v)?)?,
                5 => set_unique(&mut state_id2, expect_uint(v)?)?,
                _ => {}
            }
        }

        Ok(Self {
            last_aum_hash: last_aum_hash.unwrap_or(None),
            disablement_values: disablement_values.ok_or(DecodeError::MissingField(2))?,
            keys: keys.ok_or(DecodeError::MissingField(3))?,
            state_id1: state_id1.unwrap_or(0),
            state_id2: state_id2.unwrap_or(0),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::KeyKind;

    fn dummy_key() -> Key {
        Key {
            kind: KeyKind::Key25519,
            votes: 1,
            public: vec![0x42; 32],
            meta: None,
        }
    }

    #[test]
    fn state_roundtrip() {
        let state = State {
            last_aum_hash: Some(vec![0x01; 32]),
            disablement_values: vec![vec![0xAA; 32]],
            keys: vec![dummy_key()],
            state_id1: 0xDEAD_BEEF,
            state_id2: 0xCAFE_BABE,
        };
        let enc = state.encode();
        let dec = State::decode(&enc).unwrap();
        assert_eq!(state, dec);
    }

    #[test]
    fn state_null_last_aum_hash_roundtrip() {
        let state = State {
            last_aum_hash: None,
            disablement_values: vec![vec![0xAA; 32]],
            keys: vec![dummy_key()],
            state_id1: 0,
            state_id2: 0,
        };
        let enc = state.encode();
        let dec = State::decode(&enc).unwrap();
        assert_eq!(state, dec);
    }

    #[test]
    fn state_omits_zero_ids() {
        let state = State {
            last_aum_hash: None,
            disablement_values: vec![vec![0xAA; 32]],
            keys: vec![dummy_key()],
            state_id1: 0,
            state_id2: 0,
        };
        let enc = state.encode();
        let val: Value = ciborium::from_reader(&enc[..]).unwrap();
        let map = match val {
            Value::Map(m) => m,
            _ => panic!("expected map"),
        };
        // Keys 1 (last_aum_hash=null), 2 (disablement_values), 3 (keys) only.
        assert_eq!(map.len(), 3);
    }

    #[test]
    fn state_rejects_duplicate_keys() {
        let map = vec![
            (Value::Integer(1.into()), Value::Null),
            (Value::Integer(1.into()), Value::Bytes(vec![1])),
        ];
        let data = encode_value(&Value::Map(map));
        assert_eq!(State::decode(&data).unwrap_err(), DecodeError::DuplicateKey);
    }
}
