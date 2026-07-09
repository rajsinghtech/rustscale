//! NaCl `box` (XSalsa20-Poly1305 over X25519) seal/open, matching Go's
//! `golang.org/x/crypto/nacl/box` wire format: `nonce(24) || ciphertext`.

use crate::{KeyError, NONCE_LEN};

use crypto_box::{
    aead::{generic_array::GenericArray, Aead},
    PublicKey, SalsaBox, SecretKey,
};
use rand::RngCore;

fn salsa(my_sk: &[u8; 32], peer_pk: &[u8; 32]) -> SalsaBox {
    let sk = SecretKey::from_bytes(*my_sk);
    let pk = PublicKey::from_bytes(*peer_pk);
    SalsaBox::new(&pk, &sk)
}

/// Seal `cleartext` from `my_sk` to `peer_pk` with a fresh random nonce.
/// Returns `nonce(24) || ciphertext`.
pub(crate) fn seal(
    my_sk: &[u8; 32],
    peer_pk: &[u8; 32],
    cleartext: &[u8],
) -> Result<Vec<u8>, KeyError> {
    let sb = salsa(my_sk, peer_pk);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = GenericArray::from_slice(&nonce_bytes);
    let ct = sb
        .encrypt(nonce, cleartext)
        .map_err(|_| KeyError::Encrypt)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a `nonce(24) || ciphertext` box addressed to `my_sk` from `peer_pk`.
/// Returns `None` on any authentication or length failure (matching Go's
/// `(cleartext, ok bool)`).
pub(crate) fn open(my_sk: &[u8; 32], peer_pk: &[u8; 32], ciphertext: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.len() < NONCE_LEN {
        return None;
    }
    let sb = salsa(my_sk, peer_pk);
    let nonce = GenericArray::from_slice(&ciphertext[..NONCE_LEN]);
    sb.decrypt(nonce, &ciphertext[NONCE_LEN..]).ok()
}

/// Derive the X25519 public key for `sk`.
pub(crate) fn derive_public(sk: &[u8; 32]) -> [u8; 32] {
    let secret = SecretKey::from_bytes(*sk);
    PublicKey::from(&secret).to_bytes()
}
