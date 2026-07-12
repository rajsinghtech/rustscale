//! Curve25519 node/machine/disco keys and NaCl `box` seal/open.
//!
//! Ports the semantics of Tailscale's Go `types/key` package. Public keys
//! serialize to a typed hex string (`nodekey:`, `mkey:`, `discokey:`); private
//! keys serialize to `privkey:` for on-disk persistence but never expose their
//! raw bytes via [`fmt::Display`] or [`fmt::Debug`].
//!
//! Box encryption uses XSalsa20-Poly1305 (NaCl `crypto_box`), producing
//! `nonce(24) || ciphertext` — wire-compatible with Go's
//! `key.NodePrivate.SealTo`/`OpenFrom` and `DiscoShared.Seal`/`Open`.

#![forbid(unsafe_code)]

mod boxcrypto;
mod disco;
mod machine;
mod nl;
mod node;

pub use disco::{DiscoPrivate, DiscoPublic, DiscoShared};
pub use machine::{MachinePrecomputedSharedKey, MachinePrivate, MachinePublic};
pub use nl::NLPublic;
pub use node::{NodePrivate, NodePublic};

use std::fmt;

/// Errors produced by key parsing and box encryption.
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// Box encryption failed (only possible on allocation failure in practice).
    #[error("box encryption failed")]
    Encrypt,
    /// Hex decoding of a key failed.
    #[error("invalid hex in key")]
    InvalidHex,
    /// The input was missing the expected typed prefix.
    #[error("missing key type prefix {0}")]
    MissingPrefix(&'static str),
    /// The hex payload had the wrong length for the key type.
    #[error("invalid key length")]
    InvalidLength,
    /// A zero (uninitialized) key was used where a real key is required.
    #[error("zero key cannot be used for crypto operations")]
    ZeroKey,
}

/// Raw length in bytes of every Curve25519 key in this crate.
pub const KEY_LEN: usize = 32;

/// Length of the nonce prepended to a NaCl box ciphertext.
pub const NONCE_LEN: usize = 24;

pub(crate) const NODE_PUB_PREFIX: &str = "nodekey:";
pub(crate) const MACHINE_PUB_PREFIX: &str = "mkey:";
pub(crate) const DISCO_PUB_PREFIX: &str = "discokey:";
pub(crate) const PRIV_PREFIX: &str = "privkey:";

/// Clamp a 32-byte Curve25519 private key the way Go's `clamp25519Private` does.
///
/// This is required for NaCl `box` use; WireGuard would clamp internally, but
/// DERP/box usage demands a clamped scalar. Clamping is idempotent.
pub(crate) fn clamp25519(b: &mut [u8; KEY_LEN]) {
    b[0] &= 0xf8;
    b[31] = (b[31] & 0x7f) | 0x40;
}

/// Encode a key as `<prefix><hex>` — the typed text form used on the wire.
pub(crate) fn append_hex_key(prefix: &str, bytes: &[u8]) -> String {
    let mut s = String::with_capacity(prefix.len() + bytes.len() * 2);
    s.push_str(prefix);
    s.push_str(&hex::encode(bytes));
    s
}

/// Parse `<prefix><hex>` into `out`, validating the prefix and hex length.
///
/// Errors deliberately avoid echoing the input, which may be (part of) a
/// private key.
pub(crate) fn parse_typed_hex(
    input: &str,
    prefix: &'static str,
    out: &mut [u8],
) -> Result<(), KeyError> {
    let rest = input
        .strip_prefix(prefix)
        .ok_or(KeyError::MissingPrefix(prefix))?;
    if rest.len() != out.len() * 2 {
        return Err(KeyError::InvalidLength);
    }
    hex::decode_to_slice(rest, out).map_err(|_| KeyError::InvalidHex)?;
    Ok(())
}

/// Tailscale's conventional debug rendering of a 32-byte public key:
/// `"["` + the first five base64 digits + `"]"`. Empty for an all-zero key.
pub(crate) fn debug32(k: &[u8; KEY_LEN]) -> String {
    use base64::Engine as _;
    if k.iter().all(|&b| b == 0) {
        return String::new();
    }
    let mut buf = [0u8; 8];
    base64::engine::general_purpose::STANDARD
        .encode_slice(&k[..4], &mut buf)
        .expect("8-byte buffer fits 4 input bytes");
    let mut s = String::with_capacity(7);
    s.push('[');
    s.push_str(std::str::from_utf8(&buf[..5]).unwrap_or(""));
    s.push(']');
    s
}

/// Constant-time comparison of two equal-length byte slices.
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Redacted debug/display helper for private keys.
fn redacted(f: &mut fmt::Formatter<'_>, name: &str) -> fmt::Result {
    write!(f, "{name}(<redacted>)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_is_idempotent_and_matches_curve25519() {
        let mut k = [0u8; KEY_LEN];
        k[0] = 0xff;
        k[31] = 0xff;
        clamp25519(&mut k);
        assert_eq!(k[0], 0xf8);
        // (0xff & 0x7f) | 0x40 = 0x7f (bit 6 is already set in 0x7f).
        assert_eq!(k[31], 0x7f);
        let before = k;
        clamp25519(&mut k);
        assert_eq!(before, k, "clamping must be idempotent");
    }

    #[test]
    fn typed_hex_roundtrips() {
        let bytes = [0xab; KEY_LEN];
        let s = append_hex_key(NODE_PUB_PREFIX, &bytes);
        assert_eq!(
            s,
            "nodekey:abababababababababababababababababababababababababababababababab"
        );
        let mut out = [0u8; KEY_LEN];
        parse_typed_hex(&s, NODE_PUB_PREFIX, &mut out).unwrap();
        assert_eq!(out, bytes);
    }

    #[test]
    fn typed_hex_rejects_bad_prefix_and_length() {
        let mut out = [0u8; KEY_LEN];
        assert!(matches!(
            parse_typed_hex("mkey:ab", NODE_PUB_PREFIX, &mut out),
            Err(KeyError::MissingPrefix(NODE_PUB_PREFIX))
        ));
        assert!(matches!(
            parse_typed_hex("nodekey:ab", NODE_PUB_PREFIX, &mut out),
            Err(KeyError::InvalidLength)
        ));
        let bad_hex = format!("nodekey:{}", "z".repeat(KEY_LEN * 2));
        assert!(matches!(
            parse_typed_hex(&bad_hex, NODE_PUB_PREFIX, &mut out),
            Err(KeyError::InvalidHex)
        ));
    }

    #[test]
    fn debug32_matches_expected_shape() {
        let mut k = [0u8; KEY_LEN];
        k[0] = 0;
        k[1] = 0;
        k[2] = 0;
        k[3] = 0;
        assert_eq!(debug32(&k), "");
        k = [0u8; KEY_LEN];
        k[0] = 1;
        assert_eq!(debug32(&k).len(), 7);
        assert!(debug32(&k).starts_with('[') && debug32(&k).ends_with(']'));
    }
}
