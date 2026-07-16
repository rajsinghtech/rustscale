//! NodeKeySignature CBOR wire types.
//!
//! Wire format (from Go `sig.go:74-104` / `research-tka.md`):
//! ```text
//! NodeKeySignature {
//!   1: sig_kind (u8: 0=Invalid, 1=Direct, 2=Rotation, 3=Credential)
//!   2: pubkey ([]byte, omit if empty)      — node key public
//!   3: key_id ([]byte, omit if empty)      — 32-byte ed25519 public
//!   4: signature ([]byte, omit if empty)   — ed25519 (R,S) packed
//!   5: nested (NodeKeySignature, omit if None) — for SigRotation
//!   6: wrapping_pubkey ([]byte, omit if empty)
//! }
//! ```

use base64::Engine as _;
use ciborium::value::Value;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::aum::{
    canonical_key_cmp, decode_value, encode_value, expect_bytes, expect_key, expect_map,
    expect_uint, set_unique, DecodeError,
};

/// Signature kind. Wire representation is `u8` in range 0..=3.
///
/// 0 = Invalid, 1 = SigDirect, 2 = SigRotation, 3 = SigCredential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum SigKind {
    Invalid = 0,
    Direct = 1,
    Rotation = 2,
    Credential = 3,
}

impl SigKind {
    #[inline]
    fn to_u8(self) -> u8 {
        self as u8
    }

    fn from_u64(v: u64) -> Option<Self> {
        match v {
            0 => Some(Self::Invalid),
            1 => Some(Self::Direct),
            2 => Some(Self::Rotation),
            3 => Some(Self::Credential),
            _ => None,
        }
    }
}

/// NodeKeySignature — authorizes a node key under tailnet lock.
///
/// The `nested` field creates a recursive chain for key rotations,
/// capped at `MAX_NESTING` (16) levels on decode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeKeySignature {
    /// Key 1: signature kind.
    pub sig_kind: SigKind,
    /// Key 2 (omit if empty): node key public (32 bytes WireGuard).
    pub pubkey: Option<Vec<u8>>,
    /// Key 3 (omit if empty): TKA key ID (32-byte ed25519 public).
    pub key_id: Option<Vec<u8>>,
    /// Key 4 (omit if empty): ed25519 signature.
    pub signature: Option<Vec<u8>>,
    /// Key 5 (omit if None): nested signature (for SigRotation).
    pub nested: Option<Box<NodeKeySignature>>,
    /// Key 6 (omit if empty): wrapping ed25519 public key.
    pub wrapping_pubkey: Option<Vec<u8>>,
}

impl NodeKeySignature {
    /// Encode to CTAP2 canonical CBOR bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut map: Vec<(Value, Value)> = Vec::new();

        // Key 1 — always present.
        map.push((
            Value::Integer(1.into()),
            Value::Integer(self.sig_kind.to_u8().into()),
        ));

        // Key 2 — pubkey (omit if None or empty).
        if let Some(b) = &self.pubkey {
            if !b.is_empty() {
                map.push((Value::Integer(2.into()), Value::Bytes(b.clone())));
            }
        }

        // Key 3 — key_id (omit if None or empty).
        if let Some(b) = &self.key_id {
            if !b.is_empty() {
                map.push((Value::Integer(3.into()), Value::Bytes(b.clone())));
            }
        }

        // Key 4 — signature (omit if None or empty).
        if let Some(b) = &self.signature {
            if !b.is_empty() {
                map.push((Value::Integer(4.into()), Value::Bytes(b.clone())));
            }
        }

        // Key 5 — nested (omit if None).
        if let Some(n) = &self.nested {
            map.push((Value::Integer(5.into()), n.to_value()));
        }

        // Key 6 — wrapping_pubkey (omit if None or empty).
        if let Some(b) = &self.wrapping_pubkey {
            if !b.is_empty() {
                map.push((Value::Integer(6.into()), Value::Bytes(b.clone())));
            }
        }

        // Sort canonically.
        map.sort_by(|a, b| canonical_key_cmp(&a.0, &b.0));
        encode_value(&Value::Map(map))
    }

    /// Decode from CBOR bytes, rejecting duplicate keys and excessive nesting.
    pub fn decode(data: &[u8]) -> Result<Self, DecodeError> {
        let val = decode_value(data)?;
        Self::from_value(val)
    }

    fn to_value(&self) -> Value {
        let mut map: Vec<(Value, Value)> = Vec::new();
        map.push((
            Value::Integer(1.into()),
            Value::Integer(self.sig_kind.to_u8().into()),
        ));
        if let Some(b) = &self.pubkey {
            if !b.is_empty() {
                map.push((Value::Integer(2.into()), Value::Bytes(b.clone())));
            }
        }
        if let Some(b) = &self.key_id {
            if !b.is_empty() {
                map.push((Value::Integer(3.into()), Value::Bytes(b.clone())));
            }
        }
        if let Some(b) = &self.signature {
            if !b.is_empty() {
                map.push((Value::Integer(4.into()), Value::Bytes(b.clone())));
            }
        }
        if let Some(n) = &self.nested {
            map.push((Value::Integer(5.into()), n.to_value()));
        }
        if let Some(b) = &self.wrapping_pubkey {
            if !b.is_empty() {
                map.push((Value::Integer(6.into()), Value::Bytes(b.clone())));
            }
        }
        map.sort_by(|a, b| canonical_key_cmp(&a.0, &b.0));
        Value::Map(map)
    }

    fn from_value(v: Value) -> Result<Self, DecodeError> {
        let m = expect_map(v)?;
        let mut sig_kind = None;
        let mut pubkey = None;
        let mut key_id = None;
        let mut signature = None;
        let mut nested = None;
        let mut wrapping_pubkey = None;

        for (k, v) in m {
            match expect_key(&k)? {
                1 => {
                    let n = expect_uint(v)?;
                    set_unique(
                        &mut sig_kind,
                        SigKind::from_u64(n).ok_or(DecodeError::InvalidSigKind(n))?,
                    )?;
                }
                2 => set_unique(&mut pubkey, expect_bytes(v)?)?,
                3 => set_unique(&mut key_id, expect_bytes(v)?)?,
                4 => set_unique(&mut signature, expect_bytes(v)?)?,
                5 => set_unique(&mut nested, Box::new(Self::from_value(v)?))?,
                6 => set_unique(&mut wrapping_pubkey, expect_bytes(v)?)?,
                _ => {}
            }
        }

        Ok(Self {
            sig_kind: sig_kind.ok_or(DecodeError::MissingField(1))?,
            pubkey,
            key_id,
            signature,
            nested,
            wrapping_pubkey,
        })
    }

    /// BLAKE2s-256 of the CBOR encoding with the signature field omitted.
    pub fn sig_hash(&self) -> [u8; 32] {
        use blake2::Digest;
        let dupe = NodeKeySignature {
            signature: None,
            ..self.clone()
        };
        let mut h = blake2::Blake2s256::new();
        h.update(dupe.encode());
        let result = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    /// Walk the nested chain to find the leaf KeyID — the trusted TKA key
    /// that authorizes this signature chain.
    pub fn authorizing_key_id(&self) -> Option<&[u8]> {
        match &self.nested {
            Some(nested) => nested.authorizing_key_id(),
            None => self.key_id.as_deref(),
        }
    }

    /// Recursively resolve the wrapping public key: if `wrapping_pubkey`
    /// is set on this signature, use it; otherwise recurse into `nested`.
    fn wrapping_pubkey_recursive(&self) -> Result<&[u8], VerifyError> {
        if let Some(wp) = &self.wrapping_pubkey {
            if !wp.is_empty() {
                return Ok(wp);
            }
        }
        if let Some(nested) = &self.nested {
            return nested.wrapping_pubkey_recursive();
        }
        Err(VerifyError::MissingWrappingPubkey)
    }

    /// Verify this signature chain against a trusted ed25519 verification key.
    ///
    /// - `node_key`: the marshaled node public key (32 bytes).
    /// - `verification_key`: the ed25519 public key bytes from the TKA Key
    ///   resolved via `authorizing_key_id()`.
    ///
    /// Returns `Ok(Some(RotationDetails))` for SigRotation (containing the
    /// list of previous node keys that were rotated away), `Ok(None)` for
    /// SigDirect/SigCredential.
    pub fn verify_signature(
        &self,
        node_key: &[u8],
        verification_key: &[u8],
    ) -> Result<Option<RotationDetails>, VerifyError> {
        self.verify_inner(node_key, verification_key, 0)
    }

    fn verify_inner(
        &self,
        node_key: &[u8],
        verification_key: &[u8],
        depth: usize,
    ) -> Result<Option<RotationDetails>, VerifyError> {
        if depth > MAX_ROTATION_DEPTH {
            return Err(VerifyError::RotationTooDeep);
        }

        // For non-Credential, assert pubkey == node_key.
        if self.sig_kind != SigKind::Credential {
            match &self.pubkey {
                Some(pk) if pk.as_slice() == node_key => {}
                Some(_) => return Err(VerifyError::PubkeyMismatch),
                None => return Err(VerifyError::MissingPubkey),
            }
        }

        let sig_hash = self.sig_hash();

        match self.sig_kind {
            SigKind::Direct | SigKind::Credential => {
                if self.nested.is_some() {
                    return Err(VerifyError::UnexpectedNested);
                }
                let sig_bytes = self
                    .signature
                    .as_deref()
                    .ok_or(VerifyError::MissingSignature)?;
                let vk = parse_verifying_key(verification_key)?;
                let sig = parse_signature(sig_bytes)?;
                // Direct and Credential use strict (consensus) verification.
                vk.verify_strict(&sig_hash, &sig)
                    .map_err(|_| VerifyError::SignatureFailed)?;
                Ok(None)
            }
            SigKind::Rotation => {
                let nested = self.nested.as_deref().ok_or(VerifyError::MissingNested)?;

                // Resolve wrapping pubkey from the nested signature.
                let wrapping_pubkey_bytes = nested.wrapping_pubkey_recursive()?;
                let wrapping_vk = parse_verifying_key(wrapping_pubkey_bytes)?;

                // Verify this level's signature with the wrapping pubkey
                // (plain verify, NOT strict — matches Go ed25519.Verify).
                let sig_bytes = self
                    .signature
                    .as_deref()
                    .ok_or(VerifyError::MissingSignature)?;
                let sig = parse_signature(sig_bytes)?;
                wrapping_vk
                    .verify(&sig_hash, &sig)
                    .map_err(|_| VerifyError::SignatureFailed)?;

                // Credential signatures certify the wrapping key rather than
                // a node key, so they intentionally have no pubkey field.
                let nested_pubkey = if nested.sig_kind == SigKind::Credential {
                    &[][..]
                } else {
                    nested.pubkey.as_deref().ok_or(VerifyError::MissingPubkey)?
                };
                nested.verify_inner(nested_pubkey, verification_key, depth + 1)?;
                Ok(Some(self.rotation_details()))
            }
            SigKind::Invalid => Err(VerifyError::InvalidSigKind),
        }
    }
}

// ---------------------------------------------------------------------------
// RotationDetails + VerifyError
// ---------------------------------------------------------------------------

/// Details extracted from a verified SigRotation chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationDetails {
    /// Previous node keys that were rotated away (newest first).
    pub prev_node_keys: Vec<Vec<u8>>,
    /// The first non-rotation signature that established the chain.
    pub initial_sig: Option<Box<NodeKeySignature>>,
}

impl NodeKeySignature {
    fn rotation_details(&self) -> RotationDetails {
        let mut details = RotationDetails {
            prev_node_keys: Vec::new(),
            initial_sig: None,
        };
        let mut nested = self.nested.as_deref();
        while let Some(signature) = nested {
            if let Some(pubkey) = &signature.pubkey {
                if !pubkey.is_empty() {
                    details.prev_node_keys.push(pubkey.clone());
                }
            }
            if signature.sig_kind != SigKind::Rotation {
                details.initial_sig = Some(Box::new(signature.clone()));
                break;
            }
            nested = signature.nested.as_deref();
        }
        details
    }
}

/// Maximum rotation chain depth (15 prev keys, to stay under CBOR nesting limit of 16).
const MAX_ROTATION_DEPTH: usize = 15;

/// Decode a Tailnet Lock-wrapped pre-auth key.
///
/// Returns `Ok(None)` for an ordinary auth key. Wrapped keys contain a
/// credential signature and an ephemeral ed25519 key after the `--TL` marker.
pub fn decode_wrapped_auth_key(
    wrapped: &str,
) -> Result<Option<(String, NodeKeySignature, SigningKey)>, WrappedAuthKeyError> {
    let Some((auth_key, suffix)) = wrapped.split_once("--TL") else {
        return Ok(None);
    };
    let (signature, private_key) = suffix
        .split_once('-')
        .ok_or(WrappedAuthKeyError::MissingDelimiter)?;
    let signature = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(signature)
        .map_err(|_| WrappedAuthKeyError::InvalidSignatureEncoding)?;
    let private_key = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(private_key)
        .map_err(|_| WrappedAuthKeyError::InvalidPrivateKeyEncoding)?;
    let credential =
        NodeKeySignature::decode(&signature).map_err(|_| WrappedAuthKeyError::InvalidCredential)?;
    if credential.sig_kind != SigKind::Credential {
        return Err(WrappedAuthKeyError::NotCredential);
    }
    let keypair: [u8; 64] = private_key
        .try_into()
        .map_err(|_| WrappedAuthKeyError::InvalidPrivateKeyLength)?;
    let signing_key = SigningKey::from_keypair_bytes(&keypair)
        .map_err(|_| WrappedAuthKeyError::InvalidPrivateKey)?;
    Ok(Some((auth_key.to_owned(), credential, signing_key)))
}

/// Sign a node key using the delegated credential from a wrapped auth key.
pub fn sign_by_credential(
    credential: &NodeKeySignature,
    signing_key: &SigningKey,
    node_key: [u8; 32],
) -> Result<Vec<u8>, WrappedAuthKeyError> {
    if credential.sig_kind != SigKind::Credential {
        return Err(WrappedAuthKeyError::NotCredential);
    }
    let mut signature = NodeKeySignature {
        sig_kind: SigKind::Rotation,
        pubkey: Some(node_key.to_vec()),
        key_id: None,
        signature: None,
        nested: Some(Box::new(credential.clone())),
        wrapping_pubkey: None,
    };
    signature.signature = Some(signing_key.sign(&signature.sig_hash()).to_bytes().to_vec());
    Ok(signature.encode())
}

/// Tailnet Lock wrapped-auth-key failure. Values never include key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WrappedAuthKeyError {
    #[error("wrapped auth key is missing its credential delimiter")]
    MissingDelimiter,
    #[error("wrapped auth key has invalid signature encoding")]
    InvalidSignatureEncoding,
    #[error("wrapped auth key has invalid private-key encoding")]
    InvalidPrivateKeyEncoding,
    #[error("wrapped auth key contains an invalid credential")]
    InvalidCredential,
    #[error("wrapped auth key signature is not a credential")]
    NotCredential,
    #[error("wrapped auth key has an invalid private-key length")]
    InvalidPrivateKeyLength,
    #[error("wrapped auth key contains an invalid private key")]
    InvalidPrivateKey,
}

/// Error returned by signature verification.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("signature verification failed")]
    SignatureFailed,
    #[error("pubkey does not match node key")]
    PubkeyMismatch,
    #[error("missing pubkey")]
    MissingPubkey,
    #[error("missing signature bytes")]
    MissingSignature,
    #[error("missing nested signature for rotation")]
    MissingNested,
    #[error("unexpected nested signature")]
    UnexpectedNested,
    #[error("missing wrapping pubkey")]
    MissingWrappingPubkey,
    #[error("rotation chain exceeds maximum depth")]
    RotationTooDeep,
    #[error("invalid signature kind")]
    InvalidSigKind,
    #[error("invalid key length")]
    InvalidKeyLength,
    #[error("invalid signature length")]
    InvalidSignatureLength,
}

fn parse_verifying_key(bytes: &[u8]) -> Result<VerifyingKey, VerifyError> {
    let arr: &[u8; 32] = bytes
        .try_into()
        .map_err(|_| VerifyError::InvalidKeyLength)?;
    VerifyingKey::from_bytes(arr).map_err(|_| VerifyError::InvalidKeyLength)
}

fn parse_signature(bytes: &[u8]) -> Result<Signature, VerifyError> {
    Signature::from_slice(bytes).map_err(|_| VerifyError::InvalidSignatureLength)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aum::MAX_NESTING;
    use ed25519_dalek::Signer;

    #[test]
    fn sig_direct_roundtrip() {
        let sig = NodeKeySignature {
            sig_kind: SigKind::Direct,
            pubkey: Some(vec![0x11; 32]),
            key_id: Some(vec![0x22; 32]),
            signature: Some(vec![0x33; 64]),
            nested: None,
            wrapping_pubkey: None,
        };
        let enc = sig.encode();
        let dec = NodeKeySignature::decode(&enc).unwrap();
        assert_eq!(sig, dec);
    }

    #[test]
    fn sig_rotation_nested_roundtrip() {
        let inner = NodeKeySignature {
            sig_kind: SigKind::Direct,
            pubkey: Some(vec![0xAA; 32]),
            key_id: Some(vec![0xBB; 32]),
            signature: Some(vec![0xCC; 64]),
            nested: None,
            wrapping_pubkey: None,
        };
        let outer = NodeKeySignature {
            sig_kind: SigKind::Rotation,
            pubkey: Some(vec![0x11; 32]),
            key_id: None,
            signature: Some(vec![0x22; 64]),
            nested: Some(Box::new(inner)),
            wrapping_pubkey: Some(vec![0x33; 32]),
        };
        let enc = outer.encode();
        let dec = NodeKeySignature::decode(&enc).unwrap();
        assert_eq!(outer, dec);
    }

    #[test]
    fn sig_credential_roundtrip() {
        let sig = NodeKeySignature {
            sig_kind: SigKind::Credential,
            pubkey: None,
            key_id: Some(vec![0x44; 32]),
            signature: Some(vec![0x55; 64]),
            nested: None,
            wrapping_pubkey: None,
        };
        let enc = sig.encode();
        let dec = NodeKeySignature::decode(&enc).unwrap();
        assert_eq!(sig, dec);
    }

    #[test]
    fn sig_omits_empty_optionals() {
        // Only key 1 should be present when all optionals are None.
        let sig = NodeKeySignature {
            sig_kind: SigKind::Invalid,
            pubkey: None,
            key_id: None,
            signature: None,
            nested: None,
            wrapping_pubkey: None,
        };
        let enc = sig.encode();
        let val: Value = ciborium::from_reader(&enc[..]).unwrap();
        let map = match val {
            Value::Map(m) => m,
            _ => panic!("expected map"),
        };
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn sig_rejects_duplicate_keys() {
        let map = vec![
            (Value::Integer(1.into()), Value::Integer(1.into())),
            (Value::Integer(1.into()), Value::Integer(2.into())),
        ];
        let data = encode_value(&Value::Map(map));
        assert_eq!(
            NodeKeySignature::decode(&data).unwrap_err(),
            DecodeError::DuplicateKey
        );
    }

    #[test]
    fn sig_rejects_deep_nesting() {
        // Build a chain of nested NodeKeySignatures exceeding MAX_NESTING.
        // We construct raw CBOR with deeply nested maps at key 5.
        fn nested_map(depth: usize) -> Value {
            if depth == 0 {
                Value::Map(vec![(Value::Integer(1.into()), Value::Integer(1.into()))])
            } else {
                Value::Map(vec![
                    (Value::Integer(1.into()), Value::Integer(2.into())),
                    (Value::Integer(5.into()), nested_map(depth - 1)),
                ])
            }
        }

        // MAX_NESTING is 16. Each level adds one map nesting level. Go from
        // depth 0 to 20 to guarantee we exceed 16.
        let deep = nested_map(20);
        let data = encode_value(&deep);
        let err = NodeKeySignature::decode(&data).unwrap_err();
        assert_eq!(err, DecodeError::NestingTooDeep(MAX_NESTING));
    }

    // --- Verification tests ---

    fn make_signing_key(seed: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn verify_direct_succeeds() {
        let tka_key = make_signing_key(0x01);
        let tka_vk = tka_key.verifying_key();
        let node_key = vec![0x55; 32];

        // Build a Direct sig with signature=None first, compute sig_hash, then sign.
        let mut sig = NodeKeySignature {
            sig_kind: SigKind::Direct,
            pubkey: Some(node_key.clone()),
            key_id: Some(tka_vk.to_bytes().to_vec()),
            signature: None,
            nested: None,
            wrapping_pubkey: None,
        };
        let hash = sig.sig_hash();
        let ed_sig = tka_key.sign(&hash);
        sig.signature = Some(ed_sig.to_bytes().to_vec());

        let result = sig.verify_signature(&node_key, &tka_vk.to_bytes());
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn verify_direct_tampered_fails() {
        let tka_key = make_signing_key(0x01);
        let tka_vk = tka_key.verifying_key();
        let node_key = vec![0x55; 32];

        let mut sig = NodeKeySignature {
            sig_kind: SigKind::Direct,
            pubkey: Some(node_key.clone()),
            key_id: Some(tka_vk.to_bytes().to_vec()),
            signature: None,
            nested: None,
            wrapping_pubkey: None,
        };
        let hash = sig.sig_hash();
        let ed_sig = tka_key.sign(&hash);
        sig.signature = Some(ed_sig.to_bytes().to_vec());

        // Tamper: wrong node key.
        let wrong_key = vec![0x99; 32];
        assert_eq!(
            sig.verify_signature(&wrong_key, &tka_vk.to_bytes()),
            Err(VerifyError::PubkeyMismatch)
        );

        // Tamper: wrong verification key.
        let wrong_vk = make_signing_key(0x02).verifying_key();
        assert_eq!(
            sig.verify_signature(&node_key, &wrong_vk.to_bytes()),
            Err(VerifyError::SignatureFailed)
        );

        // Tamper: flip a byte in signature.
        let mut bad_sig = sig.clone();
        bad_sig.signature.as_mut().unwrap()[0] ^= 1;
        assert_eq!(
            bad_sig.verify_signature(&node_key, &tka_vk.to_bytes()),
            Err(VerifyError::SignatureFailed)
        );

        // Tamper: flip a byte in pubkey.
        let mut bad_sig = sig.clone();
        bad_sig.pubkey.as_mut().unwrap()[0] ^= 1;
        assert_eq!(
            bad_sig.verify_signature(&node_key, &tka_vk.to_bytes()),
            Err(VerifyError::PubkeyMismatch)
        );
    }

    #[test]
    fn verify_rotation_chain_succeeds() {
        // TKA trusted key (leaf of the chain).
        let tka_key = make_signing_key(0x01);
        let tka_vk = tka_key.verifying_key();

        // Wrapping key (the node's TL key that signs the rotation).
        let wrapping_key = make_signing_key(0x02);
        let wrapping_vk = wrapping_key.verifying_key();

        let old_node_key = vec![0xAA; 32];
        let new_node_key = vec![0xBB; 32];

        // Build inner SigDirect: pubkey=old_node_key, key_id=tka_vk.
        let mut inner = NodeKeySignature {
            sig_kind: SigKind::Direct,
            pubkey: Some(old_node_key.clone()),
            key_id: Some(tka_vk.to_bytes().to_vec()),
            signature: None,
            nested: None,
            wrapping_pubkey: Some(wrapping_vk.to_bytes().to_vec()),
        };
        let inner_hash = inner.sig_hash();
        let inner_sig = tka_key.sign(&inner_hash);
        inner.signature = Some(inner_sig.to_bytes().to_vec());

        // Build outer SigRotation: pubkey=new_node_key, nested=inner.
        let mut outer = NodeKeySignature {
            sig_kind: SigKind::Rotation,
            pubkey: Some(new_node_key.clone()),
            key_id: None,
            signature: None,
            nested: Some(Box::new(inner)),
            wrapping_pubkey: None,
        };
        let outer_hash = outer.sig_hash();
        let outer_sig = wrapping_key.sign(&outer_hash);
        outer.signature = Some(outer_sig.to_bytes().to_vec());

        let result = outer.verify_signature(&new_node_key, &tka_vk.to_bytes());
        assert!(result.is_ok(), "{result:?}");
        let details = result.unwrap().unwrap();
        assert_eq!(details.prev_node_keys, vec![old_node_key.clone()]);
        assert_eq!(details.initial_sig.as_deref(), outer.nested.as_deref());
    }

    #[test]
    fn verify_rotation_tampered_outer_sig_fails() {
        let tka_key = make_signing_key(0x01);
        let tka_vk = tka_key.verifying_key();
        let wrapping_key = make_signing_key(0x02);
        let wrapping_vk = wrapping_key.verifying_key();

        let old_node_key = vec![0xAA; 32];
        let new_node_key = vec![0xBB; 32];

        let mut inner = NodeKeySignature {
            sig_kind: SigKind::Direct,
            pubkey: Some(old_node_key.clone()),
            key_id: Some(tka_vk.to_bytes().to_vec()),
            signature: None,
            nested: None,
            wrapping_pubkey: Some(wrapping_vk.to_bytes().to_vec()),
        };
        let inner_hash = inner.sig_hash();
        inner.signature = Some(tka_key.sign(&inner_hash).to_bytes().to_vec());

        let mut outer = NodeKeySignature {
            sig_kind: SigKind::Rotation,
            pubkey: Some(new_node_key.clone()),
            key_id: None,
            signature: None,
            nested: Some(Box::new(inner)),
            wrapping_pubkey: None,
        };
        let outer_hash = outer.sig_hash();
        let mut sig_bytes = wrapping_key.sign(&outer_hash).to_bytes();
        sig_bytes[0] ^= 1; // tamper
        outer.signature = Some(sig_bytes.to_vec());

        assert_eq!(
            outer.verify_signature(&new_node_key, &tka_vk.to_bytes()),
            Err(VerifyError::SignatureFailed)
        );
    }

    #[test]
    fn verify_credential_succeeds() {
        let tka_key = make_signing_key(0x03);
        let tka_vk = tka_key.verifying_key();

        let mut sig = NodeKeySignature {
            sig_kind: SigKind::Credential,
            pubkey: None,
            key_id: Some(tka_vk.to_bytes().to_vec()),
            signature: None,
            nested: None,
            wrapping_pubkey: None,
        };
        let hash = sig.sig_hash();
        let ed_sig = tka_key.sign(&hash);
        sig.signature = Some(ed_sig.to_bytes().to_vec());

        // Credential does not check node_key, pass dummy.
        let result = sig.verify_signature(&[0u8; 32], &tka_vk.to_bytes());
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn verify_wrapped_credential_and_rotation_details() {
        let authority_key = make_signing_key(0x03);
        let authority_public = authority_key.verifying_key();
        let delegated_key = make_signing_key(0x04);
        let node_key = vec![0x55; 32];

        let mut credential = NodeKeySignature {
            sig_kind: SigKind::Credential,
            pubkey: None,
            key_id: Some(authority_public.to_bytes().to_vec()),
            signature: None,
            nested: None,
            wrapping_pubkey: Some(delegated_key.verifying_key().to_bytes().to_vec()),
        };
        credential.signature = Some(
            authority_key
                .sign(&credential.sig_hash())
                .to_bytes()
                .to_vec(),
        );

        let mut wrapped = NodeKeySignature {
            sig_kind: SigKind::Rotation,
            pubkey: Some(node_key.clone()),
            key_id: None,
            signature: None,
            nested: Some(Box::new(credential.clone())),
            wrapping_pubkey: None,
        };
        wrapped.signature = Some(delegated_key.sign(&wrapped.sig_hash()).to_bytes().to_vec());

        let details = wrapped
            .verify_signature(&node_key, &authority_public.to_bytes())
            .unwrap()
            .unwrap();
        assert!(details.prev_node_keys.is_empty());
        assert_eq!(details.initial_sig.as_deref(), Some(&credential));

        let mut bad_inner = wrapped.clone();
        bad_inner
            .nested
            .as_mut()
            .unwrap()
            .signature
            .as_mut()
            .unwrap()[0] ^= 1;
        assert_eq!(
            bad_inner.verify_signature(&node_key, &authority_public.to_bytes()),
            Err(VerifyError::SignatureFailed)
        );

        let mut bad_outer = wrapped.clone();
        bad_outer.signature.as_mut().unwrap()[0] ^= 1;
        assert_eq!(
            bad_outer.verify_signature(&node_key, &authority_public.to_bytes()),
            Err(VerifyError::SignatureFailed)
        );
        assert_eq!(
            wrapped.verify_signature(&[0x99; 32], &authority_public.to_bytes()),
            Err(VerifyError::PubkeyMismatch)
        );
    }

    #[test]
    fn wrapped_auth_key_decodes_and_signs_node_key() {
        let authority = make_signing_key(0x31);
        let delegated = make_signing_key(0x32);
        let mut credential = NodeKeySignature {
            sig_kind: SigKind::Credential,
            pubkey: None,
            key_id: Some(authority.verifying_key().to_bytes().to_vec()),
            signature: None,
            nested: None,
            wrapping_pubkey: Some(delegated.verifying_key().to_bytes().to_vec()),
        };
        credential.signature = Some(authority.sign(&credential.sig_hash()).to_bytes().to_vec());
        let wrapped = format!(
            "tskey-auth-test--TL{}-{}",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(credential.encode()),
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(delegated.to_keypair_bytes())
        );

        let (auth_key, decoded, private) = decode_wrapped_auth_key(&wrapped).unwrap().unwrap();
        assert_eq!(auth_key, "tskey-auth-test");
        assert_eq!(decoded, credential);
        let node_key = [0x55; 32];
        let signature =
            NodeKeySignature::decode(&sign_by_credential(&decoded, &private, node_key).unwrap())
                .unwrap();
        assert!(signature
            .verify_signature(&node_key, &authority.verifying_key().to_bytes())
            .is_ok());
        assert_eq!(decode_wrapped_auth_key("tskey-auth-plain").unwrap(), None);
    }

    #[test]
    fn authorizing_key_id_walks_to_leaf() {
        let tka_key_id = vec![0x42; 32];

        // Direct: key_id is the authorizing key.
        let direct = NodeKeySignature {
            sig_kind: SigKind::Direct,
            pubkey: Some(vec![0x11; 32]),
            key_id: Some(tka_key_id.clone()),
            signature: None,
            nested: None,
            wrapping_pubkey: None,
        };
        assert_eq!(direct.authorizing_key_id(), Some(&tka_key_id[..]));

        // Rotation: walks through nested to the leaf's key_id.
        let inner = NodeKeySignature {
            sig_kind: SigKind::Direct,
            pubkey: Some(vec![0x22; 32]),
            key_id: Some(tka_key_id.clone()),
            signature: None,
            nested: None,
            wrapping_pubkey: None,
        };
        let rotation = NodeKeySignature {
            sig_kind: SigKind::Rotation,
            pubkey: Some(vec![0x33; 32]),
            key_id: None,
            signature: None,
            nested: Some(Box::new(inner)),
            wrapping_pubkey: None,
        };
        assert_eq!(rotation.authorizing_key_id(), Some(&tka_key_id[..]));
    }

    #[test]
    fn sig_hash_ignores_signature_field() {
        let base = NodeKeySignature {
            sig_kind: SigKind::Direct,
            pubkey: Some(vec![0x11; 32]),
            key_id: Some(vec![0x22; 32]),
            signature: None,
            nested: None,
            wrapping_pubkey: None,
        };
        let h0 = base.sig_hash();

        let mut with_sig = base.clone();
        with_sig.signature = Some(vec![0xFF; 64]);
        assert_eq!(with_sig.sig_hash(), h0);
    }

    #[test]
    fn verify_rotation_depth_limit() {
        // Build a chain deeper than MAX_ROTATION_DEPTH (15).
        let tka_key = make_signing_key(0x01);
        let tka_vk = tka_key.verifying_key();
        let wrapping_key = make_signing_key(0x02);
        let wrapping_vk = wrapping_key.verifying_key();

        // Build from the leaf up.
        let leaf_node_key = vec![0x00; 32];
        let mut chain = NodeKeySignature {
            sig_kind: SigKind::Direct,
            pubkey: Some(leaf_node_key.clone()),
            key_id: Some(tka_vk.to_bytes().to_vec()),
            signature: None,
            nested: None,
            wrapping_pubkey: Some(wrapping_vk.to_bytes().to_vec()),
        };
        let h = chain.sig_hash();
        chain.signature = Some(tka_key.sign(&h).to_bytes().to_vec());

        // Wrap with 16 rotation levels (exceeds MAX_ROTATION_DEPTH=15).
        for i in 1..=16 {
            let new_key = vec![i; 32];
            let mut outer = NodeKeySignature {
                sig_kind: SigKind::Rotation,
                pubkey: Some(new_key.clone()),
                key_id: None,
                signature: None,
                nested: Some(Box::new(chain)),
                wrapping_pubkey: None,
            };
            let h = outer.sig_hash();
            outer.signature = Some(wrapping_key.sign(&h).to_bytes().to_vec());
            chain = outer;
        }

        // The outermost pubkey is the current node key.
        let node_key = chain.pubkey.clone().unwrap();
        let result = chain.verify_signature(&node_key, &tka_vk.to_bytes());
        assert_eq!(result, Err(VerifyError::RotationTooDeep));
    }
}
