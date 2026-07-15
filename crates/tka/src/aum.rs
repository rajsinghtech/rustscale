//! AUM (Authority Update Message) CBOR wire types.
//!
//! Wire format: CTAP2 canonical CBOR with integer-keyed maps, definite
//! lengths, deterministic key order, and omitted-when-empty optional fields.
//!
//! Field keys (from Go `aum.go` / `research-tka.md`):
//! ```text
//! AUM {
//!   1: message_kind (u8)
//!   2: prev_aum_hash ([]byte, nil for genesis)
//!   3: key (Key, omit if empty)
//!   4: key_id ([]byte, omit if empty)
//!   5: state (State, omit if empty)
//!   6: votes (uint, omit if None)
//!   7: meta (map<string,string>, omit if empty)
//!  23: signatures ([]Signature, omit if empty)
//! }
//! Signature {
//!   1: key_id ([]byte)
//!   2: signature ([]byte)
//! }
//! ```

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use blake2::Blake2s256;
use ciborium::value::Value;
use serde::{Deserialize, Serialize};

use crate::key::Key;
use crate::state::State;

/// Maximum CBOR nesting depth (CTAP2 canonical limit).
pub(crate) const MAX_NESTING: usize = 16;
pub(crate) const MAX_CBOR_BYTES: usize = 1024 * 1024;
const MAX_ARRAY_ELEMENTS: usize = 4096;
const MAX_MAP_PAIRS: usize = 1024;

// ---------------------------------------------------------------------------
// AumHash
// ---------------------------------------------------------------------------

/// BLAKE2s-256 digest of an AUM. 32 bytes.
/// Display/FromStr use RFC 4648 base32 without padding (matching Go).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AumHash(pub [u8; 32]);

impl AumHash {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Construct a hash from an exact 32-byte slice.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        let bytes: &[u8; 32] = bytes.try_into().ok()?;
        Some(Self(*bytes))
    }
}

impl fmt::Display for AumHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&base32_nopad().encode(&self.0))
    }
}

impl fmt::Debug for AumHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AumHash({self})")
    }
}

impl FromStr for AumHash {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 52 {
            return Err(format!("expected 52 base32 characters, got {}", s.len()));
        }
        let bytes = base32_nopad()
            .decode(s.to_ascii_uppercase().as_bytes())
            .map_err(|e| format!("invalid base32: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!("expected 32 bytes, got {}", bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl From<[u8; 32]> for AumHash {
    fn from(arr: [u8; 32]) -> Self {
        Self(arr)
    }
}

impl AsRef<[u8]> for AumHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

fn base32_nopad() -> &'static data_encoding::Encoding {
    use std::sync::OnceLock;
    static ENC: OnceLock<data_encoding::Encoding> = OnceLock::new();
    ENC.get_or_init(|| {
        let mut spec = data_encoding::Specification::new();
        spec.symbols.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567");
        spec.encoding().expect("valid base32 specification")
    })
}

fn blake2s256(data: &[u8]) -> [u8; 32] {
    use blake2::Digest;
    let mut h = Blake2s256::new();
    h.update(data);
    let result = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// ---------------------------------------------------------------------------
// AumKind
// ---------------------------------------------------------------------------

/// AUM message kind. Wire representation is a `u8` in range 0..=5.
///
/// 0 = Invalid (genesis sentinel), 1 = AddKey, 2 = RemoveKey,
/// 3 = NoOp, 4 = UpdateKey, 5 = Checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AumKind {
    Invalid = 0,
    AddKey = 1,
    RemoveKey = 2,
    NoOp = 3,
    UpdateKey = 4,
    Checkpoint = 5,
}

impl AumKind {
    #[inline]
    fn to_u8(self) -> u8 {
        self as u8
    }

    fn from_u64(v: u64) -> Option<Self> {
        match v {
            0 => Some(Self::Invalid),
            1 => Some(Self::AddKey),
            2 => Some(Self::RemoveKey),
            3 => Some(Self::NoOp),
            4 => Some(Self::UpdateKey),
            5 => Some(Self::Checkpoint),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Signature
// ---------------------------------------------------------------------------

/// A signature on an AUM. Always present fields (no omission).
///
/// ```text
/// { 1: key_id ([]byte), 2: signature ([]byte) }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    /// 32-byte ed25519 public key of the signer (KeyID).
    pub key_id: Vec<u8>,
    /// 64-byte ed25519 signature.
    pub signature: Vec<u8>,
}

impl Signature {
    /// Encode to CTAP2 canonical CBOR bytes.
    pub fn encode(&self) -> Vec<u8> {
        let map = canonical_map![
            1 => Value::Bytes(self.key_id.clone()),
            2 => Value::Bytes(self.signature.clone()),
        ];
        encode_value(&Value::Map(map))
    }

    /// Decode from CBOR bytes, rejecting duplicate keys and excessive nesting.
    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let val = decode_value(data)?;
        let m = expect_map(val)?;
        let mut key_id = None;
        let mut signature = None;
        for (k, v) in m {
            match expect_key(&k)? {
                1 => set_unique(&mut key_id, expect_bytes(v)?)?,
                2 => set_unique(&mut signature, expect_bytes(v)?)?,
                _ => {}
            }
        }
        Ok(Self {
            key_id: key_id.ok_or(DecodeError::MissingField(1))?,
            signature: signature.ok_or(DecodeError::MissingField(2))?,
        })
    }
}

// ---------------------------------------------------------------------------
// Aum
// ---------------------------------------------------------------------------

/// Authority Update Message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Aum {
    /// Key 1: message kind.
    pub message_kind: AumKind,
    /// Key 2: parent AUM hash. `None` for genesis.
    pub prev_aum_hash: Option<Vec<u8>>,
    /// Key 3 (omit if None): key to add/update.
    pub key: Option<Key>,
    /// Key 4 (omit if None): key ID for remove/update.
    pub key_id: Option<Vec<u8>>,
    /// Key 5 (omit if None): checkpoint state.
    pub state: Option<State>,
    /// Key 6 (omit if None): new vote count for update.
    pub votes: Option<u64>,
    /// Key 7 (omit if empty): metadata for update.
    pub meta: Option<BTreeMap<String, String>>,
    /// Key 23 (omit if empty): signatures.
    pub signatures: Vec<Signature>,
}

impl Aum {
    /// Encode to CTAP2 canonical CBOR bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut map: Vec<(Value, Value)> = Vec::new();

        // Key 1 — always present.
        map.push((
            Value::Integer(1.into()),
            Value::Integer(self.message_kind.to_u8().into()),
        ));

        // Key 2 — prev_aum_hash. Encoded as nil (null) when None (matches Go
        // behaviour: `PrevAUMHash` is `[]byte` with `cbor:"2,keyasint"`, so a
        // nil slice serializes as CBOR null).
        map.push((
            Value::Integer(2.into()),
            match &self.prev_aum_hash {
                Some(h) => Value::Bytes(h.clone()),
                None => Value::Null,
            },
        ));

        // Key 3 — key (omit if None).
        if let Some(k) = &self.key {
            map.push((Value::Integer(3.into()), k.to_value()));
        }

        // Key 4 — key_id (omit if None).
        if let Some(kid) = &self.key_id {
            map.push((Value::Integer(4.into()), Value::Bytes(kid.clone())));
        }

        // Key 5 — state (omit if None).
        if let Some(s) = &self.state {
            map.push((Value::Integer(5.into()), s.to_value()));
        }

        // Key 6 — votes (omit if None).
        if let Some(v) = self.votes {
            map.push((Value::Integer(6.into()), Value::Integer(v.into())));
        }

        // Key 7 — meta (omit if None or empty).
        if let Some(meta) = &self.meta {
            if !meta.is_empty() {
                let mut entries: Vec<(Value, Value)> = meta
                    .iter()
                    .map(|(k, v)| (Value::Text(k.clone()), Value::Text(v.clone())))
                    .collect();
                entries.sort_by(|left, right| canonical_key_cmp(&left.0, &right.0));
                map.push((Value::Integer(7.into()), Value::Map(entries)));
            }
        }

        // Key 23 — signatures (omit if empty).
        if !self.signatures.is_empty() {
            let arr: Vec<Value> = self.signatures.iter().map(Signature::to_value).collect();
            map.push((Value::Integer(23.into()), Value::Array(arr)));
        }

        map.sort_by(|a, b| canonical_key_cmp(&a.0, &b.0));
        encode_value(&Value::Map(map))
    }

    /// Decode from CBOR bytes, rejecting duplicate keys and excessive nesting.
    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let val = decode_value(data)?;
        let m = expect_map(val)?;
        let mut message_kind = None;
        let mut prev_aum_hash: Option<Option<Vec<u8>>> = None;
        let mut key = None;
        let mut key_id = None;
        let mut state = None;
        let mut votes = None;
        let mut meta = None;
        let mut signatures: Option<Vec<Signature>> = None;

        for (k, v) in m {
            match expect_key(&k)? {
                1 => {
                    let n = expect_uint(v)?;
                    set_unique(
                        &mut message_kind,
                        AumKind::from_u64(n).ok_or(DecodeError::InvalidAumKind(n))?,
                    )?;
                }
                2 => {
                    set_unique(
                        &mut prev_aum_hash,
                        match v {
                            Value::Null => None,
                            Value::Bytes(b) => Some(b),
                            _ => return Err(DecodeError::TypeMismatch(2)),
                        },
                    )?;
                }
                3 => set_unique(&mut key, Key::from_value(v)?)?,
                4 => set_unique(&mut key_id, expect_bytes(v)?)?,
                5 => set_unique(&mut state, State::from_value(v)?)?,
                6 => set_unique(&mut votes, expect_uint(v)?)?,
                7 => {
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
                23 => {
                    let arr = expect_array(v)?;
                    let mut sigs = Vec::with_capacity(arr.len());
                    for item in arr {
                        sigs.push(Signature::from_value(item)?);
                    }
                    set_unique(&mut signatures, sigs)?;
                }
                _ => {}
            }
        }

        Ok(Self {
            message_kind: message_kind.ok_or(DecodeError::MissingField(1))?,
            prev_aum_hash: prev_aum_hash.unwrap_or(None),
            key,
            key_id,
            state,
            votes,
            meta,
            signatures: signatures.unwrap_or_default(),
        })
    }

    /// Return the parent hash, if it has the required 32-byte representation.
    pub fn parent(&self) -> Option<AumHash> {
        self.prev_aum_hash.as_deref().and_then(AumHash::from_slice)
    }

    /// Validate the structure and bounded fields of this AUM.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(parent) = &self.prev_aum_hash {
            if parent.len() != 32 {
                return Err(format!("parent hash has length {}, want 32", parent.len()));
            }
        }
        for (index, signature) in self.signatures.iter().enumerate() {
            if signature.key_id.len() != 32 || signature.signature.len() != 64 {
                return Err(format!(
                    "signature {index} has malformed key ID or signature"
                ));
            }
        }
        if let Some(key) = &self.key {
            key.validate()?;
        }
        if let Some(state) = &self.state {
            state.validate_checkpoint()?;
        }

        match self.message_kind {
            AumKind::AddKey => {
                if self.key.is_none() {
                    return Err("AddKey AUM must contain a key".into());
                }
                if self.key_id.is_some()
                    || self.state.is_some()
                    || self.votes.is_some()
                    || self.meta.is_some()
                {
                    return Err("AddKey AUM may only specify a key".into());
                }
            }
            AumKind::RemoveKey => {
                if self.key_id.as_ref().is_none_or(Vec::is_empty) {
                    return Err("RemoveKey AUM must specify a key ID".into());
                }
                if self.key.is_some()
                    || self.state.is_some()
                    || self.votes.is_some()
                    || self.meta.is_some()
                {
                    return Err("RemoveKey AUM may only specify a key ID".into());
                }
            }
            AumKind::UpdateKey => {
                if self.key_id.as_ref().is_none_or(Vec::is_empty) {
                    return Err("UpdateKey AUM must specify a key ID".into());
                }
                if self.meta.as_ref().is_some_and(BTreeMap::is_empty) {
                    return Err("UpdateKey AUM cannot contain empty metadata".into());
                }
                if self.votes.is_none() && self.meta.is_none() {
                    return Err("UpdateKey AUM must update votes or metadata".into());
                }
                if self.key.is_some() || self.state.is_some() {
                    return Err("UpdateKey AUM may only specify key ID, votes, and metadata".into());
                }
            }
            AumKind::Checkpoint => {
                if self.state.is_none() {
                    return Err("Checkpoint AUM must specify state".into());
                }
                if self.key.is_some()
                    || self.key_id.is_some()
                    || self.votes.is_some()
                    || self.meta.is_some()
                {
                    return Err("Checkpoint AUM may only specify state".into());
                }
            }
            AumKind::NoOp => {}
            AumKind::Invalid => return Err("invalid AUM kind".into()),
        }
        Ok(())
    }

    /// BLAKE2s-256 of the full CBOR encoding (all fields including signatures).
    pub fn hash(&self) -> AumHash {
        AumHash(blake2s256(&self.encode()))
    }

    /// BLAKE2s-256 of the CBOR encoding with signatures omitted.
    /// Used for signature verification (avoids circular dependency).
    pub fn sig_hash(&self) -> [u8; 32] {
        let dupe = Aum {
            signatures: Vec::new(),
            ..self.clone()
        };
        blake2s256(&dupe.encode())
    }
}

// ---------------------------------------------------------------------------
// Trait impls for sub-types
// ---------------------------------------------------------------------------

impl Signature {
    fn to_value(&self) -> Value {
        Value::Map(canonical_map![
            1 => Value::Bytes(self.key_id.clone()),
            2 => Value::Bytes(self.signature.clone()),
        ])
    }

    fn from_value(v: Value) -> Result<Self, DecodeError> {
        let m = expect_map(v)?;
        let mut key_id = None;
        let mut signature = None;
        for (k, v) in m {
            match expect_key(&k)? {
                1 => set_unique(&mut key_id, expect_bytes(v)?)?,
                2 => set_unique(&mut signature, expect_bytes(v)?)?,
                _ => {}
            }
        }
        Ok(Self {
            key_id: key_id.ok_or(DecodeError::MissingField(1))?,
            signature: signature.ok_or(DecodeError::MissingField(2))?,
        })
    }
}

// ---------------------------------------------------------------------------
// Decode error + low-level helpers
// ---------------------------------------------------------------------------

/// Error returned by all `decode` functions.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("CBOR deserialization failed: {0}")]
    Cbor(String),
    #[error("CBOR input is too large: {0} bytes")]
    InputTooLarge(usize),
    #[error("CBOR array exceeds {0} elements")]
    TooManyArrayElements(usize),
    #[error("CBOR map exceeds {0} pairs")]
    TooManyMapPairs(usize),
    #[error("expected map")]
    NotAMap,
    #[error("expected array")]
    NotAnArray,
    #[error("expected bytes")]
    NotBytes,
    #[error("expected text")]
    NotText,
    #[error("expected unsigned integer")]
    NotUint,
    #[error("duplicate map key")]
    DuplicateKey,
    #[error("missing required field {0}")]
    MissingField(u64),
    #[error("CBOR nesting exceeds {0} levels")]
    NestingTooDeep(usize),
    #[error("invalid AUM kind: {0}")]
    InvalidAumKind(u64),
    #[error("invalid sig kind: {0}")]
    InvalidSigKind(u64),
    #[error("invalid key kind: {0}")]
    InvalidKeyKind(u64),
    #[error("type mismatch on field {0}")]
    TypeMismatch(u64),
}

/// Decode CBOR bytes into a `Value`, rejecting nesting > `MAX_NESTING`.
pub(crate) fn decode_value(data: &[u8]) -> Result<Value, DecodeError> {
    if data.len() > MAX_CBOR_BYTES {
        return Err(DecodeError::InputTooLarge(data.len()));
    }
    let consumed = scan_cbor_item(data, 0, 0)?;
    if consumed != data.len() {
        return Err(DecodeError::Cbor("trailing data".into()));
    }
    let val: Value = ciborium::from_reader(data).map_err(|e| DecodeError::Cbor(e.to_string()))?;
    check_nesting(&val, 0)?;
    Ok(val)
}

/// Validate definite-length CBOR before handing it to an allocating decoder.
/// This rejects oversized declared lengths, tags, indefinite values, and
/// excessive containers while only indexing the bounded input slice.
fn scan_cbor_item(data: &[u8], start: usize, depth: usize) -> Result<usize, DecodeError> {
    if depth > MAX_NESTING {
        return Err(DecodeError::NestingTooDeep(MAX_NESTING));
    }
    let initial = *data
        .get(start)
        .ok_or_else(|| DecodeError::Cbor("truncated item".into()))?;
    let major = initial >> 5;
    let additional = initial & 0x1f;
    let (argument, mut cursor) = match additional {
        value @ 0..=23 => (u64::from(value), start + 1),
        24 => (u64::from(read_fixed::<1>(data, start + 1)?[0]), start + 2),
        25 => (
            u64::from(u16::from_be_bytes(read_fixed(data, start + 1)?)),
            start + 3,
        ),
        26 => (
            u64::from(u32::from_be_bytes(read_fixed(data, start + 1)?)),
            start + 5,
        ),
        27 => (u64::from_be_bytes(read_fixed(data, start + 1)?), start + 9),
        31 => {
            return Err(DecodeError::Cbor(
                "indefinite-length CBOR is forbidden".into(),
            ))
        }
        _ => return Err(DecodeError::Cbor("invalid additional information".into())),
    };

    match major {
        0 | 1 | 7 => Ok(cursor),
        2 | 3 => {
            let length = usize::try_from(argument)
                .map_err(|_| DecodeError::Cbor("declared string length overflows usize".into()))?;
            cursor
                .checked_add(length)
                .filter(|end| *end <= data.len())
                .ok_or_else(|| DecodeError::Cbor("declared string exceeds input".into()))
        }
        4 => {
            let length = usize::try_from(argument)
                .map_err(|_| DecodeError::TooManyArrayElements(MAX_ARRAY_ELEMENTS))?;
            if length > MAX_ARRAY_ELEMENTS {
                return Err(DecodeError::TooManyArrayElements(MAX_ARRAY_ELEMENTS));
            }
            for _ in 0..length {
                cursor = scan_cbor_item(data, cursor, depth + 1)?;
            }
            Ok(cursor)
        }
        5 => {
            let length = usize::try_from(argument)
                .map_err(|_| DecodeError::TooManyMapPairs(MAX_MAP_PAIRS))?;
            if length > MAX_MAP_PAIRS {
                return Err(DecodeError::TooManyMapPairs(MAX_MAP_PAIRS));
            }
            for _ in 0..length {
                cursor = scan_cbor_item(data, cursor, depth + 1)?;
                cursor = scan_cbor_item(data, cursor, depth + 1)?;
            }
            Ok(cursor)
        }
        6 => Err(DecodeError::Cbor("CBOR tags are forbidden".into())),
        _ => Err(DecodeError::Cbor("invalid CBOR major type".into())),
    }
}

fn read_fixed<const N: usize>(data: &[u8], start: usize) -> Result<[u8; N], DecodeError> {
    let end = start
        .checked_add(N)
        .ok_or_else(|| DecodeError::Cbor("length overflow".into()))?;
    data.get(start..end)
        .ok_or_else(|| DecodeError::Cbor("truncated argument".into()))?
        .try_into()
        .map_err(|_| DecodeError::Cbor("truncated argument".into()))
}

/// Encode a `Value` to CTAP2 canonical CBOR bytes.
pub(crate) fn encode_value(v: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(v, &mut buf).expect("CBOR encoding to Vec<u8> is infallible");
    buf
}

fn check_nesting(v: &Value, depth: usize) -> Result<(), DecodeError> {
    if depth > MAX_NESTING {
        return Err(DecodeError::NestingTooDeep(MAX_NESTING));
    }
    match v {
        Value::Map(m) => {
            for (k, v) in m {
                check_nesting(k, depth + 1)?;
                check_nesting(v, depth + 1)?;
            }
        }
        Value::Array(a) => {
            for item in a {
                check_nesting(item, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn expect_map(v: Value) -> Result<Vec<(Value, Value)>, DecodeError> {
    match v {
        Value::Map(m) => Ok(m),
        _ => Err(DecodeError::NotAMap),
    }
}

pub(crate) fn expect_array(v: Value) -> Result<Vec<Value>, DecodeError> {
    match v {
        Value::Array(a) => Ok(a),
        _ => Err(DecodeError::NotAnArray),
    }
}

pub(crate) fn expect_bytes(v: Value) -> Result<Vec<u8>, DecodeError> {
    match v {
        Value::Bytes(b) => Ok(b),
        _ => Err(DecodeError::NotBytes),
    }
}

pub(crate) fn expect_text(v: &Value) -> Result<String, DecodeError> {
    match v {
        Value::Text(s) => Ok(s.clone()),
        _ => Err(DecodeError::NotText),
    }
}

pub(crate) fn expect_uint(v: Value) -> Result<u64, DecodeError> {
    match v {
        Value::Integer(i) => {
            let n: i128 = i.into();
            u64::try_from(n).map_err(|_| DecodeError::NotUint)
        }
        _ => Err(DecodeError::NotUint),
    }
}

pub(crate) fn expect_key(v: &Value) -> Result<u64, DecodeError> {
    match v {
        Value::Integer(i) => {
            let n: i128 = (*i).into();
            u64::try_from(n).map_err(|_| DecodeError::NotUint)
        }
        _ => Err(DecodeError::NotUint),
    }
}

pub(crate) fn set_unique<T>(slot: &mut Option<T>, val: T) -> Result<(), DecodeError> {
    if slot.is_some() {
        Err(DecodeError::DuplicateKey)
    } else {
        *slot = Some(val);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Macro for building canonical (sorted) CBOR maps.
// ---------------------------------------------------------------------------

/// Build a `Vec<(Value, Value)>` sorted by canonical CBOR key order.
/// Accepts `key => value` pairs where key is `u64`/`&str` and value is `Value`.
macro_rules! canonical_map {
    ($($k:expr => $v:expr),* $(,)?) => {{
        let mut v: Vec<(ciborium::Value, ciborium::Value)> = vec![
            $((ciborium::Value::from($k), $v)),*
        ];
        v.sort_by(|a, b| $crate::aum::canonical_key_cmp(&a.0, &b.0));
        v
    }};
}
pub(crate) use canonical_map;

/// Compare two CBOR values as map keys in CTAP2 canonical order.
pub(crate) fn canonical_key_cmp(a: &Value, b: &Value) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match (a, b) {
        (Value::Integer(a), Value::Integer(b)) => a.canonical_cmp(b),
        (Value::Bytes(a), Value::Bytes(b)) => a.len().cmp(&b.len()).then_with(|| a.cmp(b)),
        (Value::Text(a), Value::Text(b)) => a.len().cmp(&b.len()).then_with(|| a.cmp(b)),
        // Type ordering: integers < byte strings < text strings < arrays < maps
        (Value::Integer(_), _) => Ordering::Less,
        (_, Value::Integer(_)) => Ordering::Greater,
        (Value::Bytes(_), _) => Ordering::Less,
        (_, Value::Bytes(_)) => Ordering::Greater,
        (Value::Text(_), _) => Ordering::Less,
        (_, Value::Text(_)) => Ordering::Greater,
        _ => Ordering::Equal,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{
        decode_value, encode_value, Aum, AumHash, AumKind, DecodeError, Signature,
        MAX_ARRAY_ELEMENTS, MAX_CBOR_BYTES, MAX_MAP_PAIRS,
    };
    use crate::key::{Key, KeyKind};
    use ciborium::value::Value;
    use std::collections::BTreeMap;
    use std::str::FromStr;

    fn dummy_key() -> Key {
        Key {
            kind: KeyKind::Key25519,
            votes: 1,
            public: vec![0x42; 32],
            meta: None,
        }
    }

    fn dummy_sig() -> Signature {
        Signature {
            key_id: vec![0xAA; 32],
            signature: vec![0xBB; 64],
        }
    }

    #[test]
    fn aum_genesis_roundtrip() {
        let aum = Aum {
            message_kind: AumKind::Checkpoint,
            prev_aum_hash: None,
            key: None,
            key_id: None,
            state: None,
            votes: None,
            meta: None,
            signatures: vec![],
        };
        let enc = aum.encode();
        let dec = Aum::decode(&enc).unwrap();
        assert_eq!(aum, dec);
    }

    #[test]
    fn aum_addkey_roundtrip() {
        let aum = Aum {
            message_kind: AumKind::AddKey,
            prev_aum_hash: Some(vec![0x01; 32]),
            key: Some(dummy_key()),
            key_id: None,
            state: None,
            votes: None,
            meta: None,
            signatures: vec![dummy_sig()],
        };
        let enc = aum.encode();
        let dec = Aum::decode(&enc).unwrap();
        assert_eq!(aum, dec);
    }

    #[test]
    fn aum_updatekey_with_meta_roundtrip() {
        let mut meta = BTreeMap::new();
        meta.insert("name".into(), "test-key".into());
        let aum = Aum {
            message_kind: AumKind::UpdateKey,
            prev_aum_hash: Some(vec![0x02; 32]),
            key: None,
            key_id: Some(vec![0xCC; 32]),
            state: None,
            votes: Some(3),
            meta: Some(meta),
            signatures: vec![dummy_sig(), dummy_sig()],
        };
        let enc = aum.encode();
        let dec = Aum::decode(&enc).unwrap();
        assert_eq!(aum, dec);
    }

    #[test]
    fn aum_omits_empty_optionals() {
        // A genesis NoOp AUM with no optionals: only keys 1 and 2 should appear.
        let aum = Aum {
            message_kind: AumKind::NoOp,
            prev_aum_hash: None,
            key: None,
            key_id: None,
            state: None,
            votes: None,
            meta: None,
            signatures: vec![],
        };
        let enc = aum.encode();
        let val: Value = ciborium::from_reader(&enc[..]).unwrap();
        let map = match val {
            Value::Map(m) => m,
            _ => panic!("expected map"),
        };
        // Keys 1 (message_kind) and 2 (prev_aum_hash=null) only.
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn signature_roundtrip() {
        let sig = dummy_sig();
        let enc = sig.encode();
        let dec = Signature::decode(&enc).unwrap();
        assert_eq!(sig, dec);
    }

    #[test]
    fn aum_rejects_duplicate_keys() {
        // Manually craft a map with duplicate key 1.
        let map = vec![
            (Value::Integer(1.into()), Value::Integer(1.into())),
            (Value::Integer(1.into()), Value::Integer(2.into())),
        ];
        let data = encode_value(&Value::Map(map));
        assert_eq!(Aum::decode(&data).unwrap_err(), DecodeError::DuplicateKey);
    }

    #[test]
    fn signature_rejects_duplicate_keys() {
        let map = vec![
            (Value::Integer(1.into()), Value::Bytes(vec![0x01])),
            (Value::Integer(1.into()), Value::Bytes(vec![0x02])),
        ];
        let data = encode_value(&Value::Map(map));
        assert_eq!(
            Signature::decode(&data).unwrap_err(),
            DecodeError::DuplicateKey
        );
    }

    #[test]
    fn aum_hash_changes_on_field_change() {
        let base = Aum {
            message_kind: AumKind::NoOp,
            prev_aum_hash: Some(vec![0x01; 32]),
            key: None,
            key_id: None,
            state: None,
            votes: None,
            meta: None,
            signatures: vec![],
        };
        let h0 = base.hash();

        // Change message_kind.
        let mut other = base.clone();
        other.message_kind = AumKind::AddKey;
        assert_ne!(other.hash(), h0);

        // Change prev_aum_hash.
        let mut other = base.clone();
        other.prev_aum_hash = Some(vec![0x02; 32]);
        assert_ne!(other.hash(), h0);

        // Add a signature.
        let mut other = base.clone();
        other.signatures.push(dummy_sig());
        assert_ne!(other.hash(), h0);
    }

    #[test]
    fn aum_sig_hash_ignores_signatures() {
        let base = Aum {
            message_kind: AumKind::NoOp,
            prev_aum_hash: Some(vec![0x01; 32]),
            key: None,
            key_id: None,
            state: None,
            votes: None,
            meta: None,
            signatures: vec![],
        };
        let sh0 = base.sig_hash();

        let mut with_sigs = base.clone();
        with_sigs.signatures.push(dummy_sig());
        with_sigs.signatures.push(dummy_sig());
        assert_eq!(with_sigs.sig_hash(), sh0);
    }

    #[test]
    fn aum_hash_base32_roundtrip() {
        let hash = AumHash([0xAB; 32]);
        let s = hash.to_string();
        assert_eq!(s.len(), 52); // 32 bytes -> 52 base32 chars (no pad)
        let parsed = AumHash::from_str(&s).unwrap();
        assert_eq!(hash, parsed);
    }

    #[test]
    fn metadata_uses_ctap2_encoded_key_order_and_stable_hash() {
        let aum = Aum {
            message_kind: AumKind::UpdateKey,
            prev_aum_hash: Some(vec![0x11; 32]),
            key: None,
            key_id: Some(vec![0x22; 32]),
            state: None,
            votes: None,
            meta: Some(BTreeMap::from([
                ("aa".into(), "2".into()),
                ("z".into(), "1".into()),
            ])),
            signatures: Vec::new(),
        };
        let expected = data_encoding::HEXLOWER
            .decode(b"a401040258201111111111111111111111111111111111111111111111111111111111111111045820222222222222222222222222222222222222222222222222222222222222222207a2617a61316261616132")
            .unwrap();
        assert_eq!(aum.encode(), expected);
        assert_eq!(
            aum.hash().0,
            [
                0xec, 0x1a, 0x24, 0x23, 0x58, 0xd8, 0x5f, 0x56, 0x03, 0xd3, 0x65, 0x6a, 0x1b, 0x35,
                0x80, 0xa1, 0xe6, 0xf2, 0x38, 0x42, 0xe0, 0xb5, 0x0b, 0x34, 0x38, 0x2a, 0x61, 0x7a,
                0x41, 0x68, 0x54, 0x3c,
            ]
        );
    }

    #[test]
    fn empty_metadata_update_is_rejected_before_omission() {
        let aum = Aum {
            message_kind: AumKind::UpdateKey,
            prev_aum_hash: Some(vec![0x11; 32]),
            key: None,
            key_id: Some(vec![0x22; 32]),
            state: None,
            votes: None,
            meta: Some(BTreeMap::new()),
            signatures: Vec::new(),
        };
        assert!(aum.validate().is_err());
    }

    #[test]
    fn decode_limits_are_enforced_before_allocation() {
        assert_eq!(
            Aum::decode(&vec![0; MAX_CBOR_BYTES + 1]).unwrap_err(),
            DecodeError::InputTooLarge(MAX_CBOR_BYTES + 1)
        );
        assert_eq!(
            decode_value(&[0x99, 0x10, 0x01]).unwrap_err(),
            DecodeError::TooManyArrayElements(MAX_ARRAY_ELEMENTS)
        );
        assert_eq!(
            decode_value(&[0xb9, 0x04, 0x01]).unwrap_err(),
            DecodeError::TooManyMapPairs(MAX_MAP_PAIRS)
        );
        assert!(matches!(
            decode_value(&[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            Err(DecodeError::Cbor(_))
        ));
    }

    #[test]
    fn aum_hash_display_matches_go_uppercase_base32() {
        let hash = AumHash([0xFF; 32]);
        let s = hash.to_string();
        assert!(s
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
    }
}
