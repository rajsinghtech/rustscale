//! Disablement secret verification using Argon2id.
//!
//! Parameters (from Go `state.go:124-130`):
//!   time = 4, memory = 16*1024 KiB (16 MiB), threads = 4, keyLen = 32
//!
//! The salt is fixed: `"tailscale network-lock disablement salt"`.
//! The derived value is safe to store publicly — it cannot be reversed
//! to find the original secret.

use argon2::{Algorithm, Argon2, Params, Version};

/// Fixed salt from the Go implementation.
const DISABLEMENT_SALT: &[u8] = b"tailscale network-lock disablement salt";

/// Output length of the KDF in bytes.
const DISABLEMENT_LENGTH: usize = 32;

/// Derive a public disablement value from a secret.
///
/// Argon2id with time=4, memory=16384 KiB (16 MiB), threads=4, output=32 bytes.
pub fn disablement_kdf(secret: &[u8]) -> Vec<u8> {
    let params =
        Params::new(16 * 1024, 4, 4, Some(DISABLEMENT_LENGTH)).expect("valid argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = vec![0u8; DISABLEMENT_LENGTH];
    argon2
        .hash_password_into(secret, DISABLEMENT_SALT, &mut output)
        .expect("argon2 hashing with valid params should not fail");
    output
}

/// Check whether a secret matches any of the stored disablement values.
///
/// Uses constant-time comparison to avoid timing side-channels.
pub fn check_disablement(secret: &[u8], stored_values: &[Vec<u8>]) -> bool {
    let derived = disablement_kdf(secret);
    stored_values
        .iter()
        .any(|candidate| constant_time_eq(&derived, candidate))
}

/// Constant-time byte comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in a.iter().zip(b.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_produces_32_bytes() {
        let derived = disablement_kdf(b"my-secret");
        assert_eq!(derived.len(), 32);
    }

    #[test]
    fn kdf_is_deterministic() {
        let a = disablement_kdf(b"test-secret");
        let b = disablement_kdf(b"test-secret");
        assert_eq!(a, b);
    }

    #[test]
    fn kdf_different_secrets_produce_different_values() {
        let a = disablement_kdf(b"secret-a");
        let b = disablement_kdf(b"secret-b");
        assert_ne!(a, b);
    }

    #[test]
    fn check_disablement_succeeds_with_correct_secret() {
        let secret = b"correct-disablement-secret";
        let derived = disablement_kdf(secret);
        assert!(check_disablement(secret, &[derived]));
    }

    #[test]
    fn check_disablement_fails_with_wrong_secret() {
        let derived = disablement_kdf(b"correct-secret");
        assert!(!check_disablement(b"wrong-secret", &[derived]));
    }

    #[test]
    fn check_disablement_matches_any_stored_value() {
        let v1 = disablement_kdf(b"secret-one");
        let v2 = disablement_kdf(b"secret-two");
        assert!(check_disablement(b"secret-two", &[v1, v2]));
    }

    #[test]
    fn check_disablement_empty_stored_values() {
        assert!(!check_disablement(b"any-secret", &[]));
    }
}
