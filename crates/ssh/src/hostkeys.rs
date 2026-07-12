//! SSH host key generation — deterministic from the node private key.
//!
//! Ports the logic from Go's `ssh/tailssh/hostkeys.go`. The Go code reads
//! system OpenSSH keys when running as root and generates random keys
//! otherwise, persisting them to `$TAILSCALE_VAR/ssh/`. For rustscale's
//! tsnet embedding model, we generate Ed25519 host keys **deterministically**
//! from the node private key — so every session with the same node key
//! presents the same host key, without needing on-disk persistence.

use russh::keys::ssh_key::{Algorithm, KeypairData, PrivateKey};
use sha2::{Digest, Sha512};

use rustscale_key::NodePrivate;

/// Generate a deterministic Ed25519 SSH host key from the node private key.
///
/// The node private key is a Curve25519 scalar (32 bytes). We derive an
/// Ed25519 seed by hashing the node key bytes with SHA-512 and taking the
/// first 32 bytes as the Ed25519 seed. This produces a stable, unique SSH
/// host key per Tailscale node identity — the same node always presents
/// the same host key to SSH clients, enabling known_hosts verification.
///
/// This is simpler than the Go implementation (which generates separate
/// RSA/ECDSA/Ed25519 keys and persists them to disk) but sufficient for
/// the tsnet embedding model where the node key is the persistent identity.
pub fn host_key_from_node_key(node_key: &NodePrivate) -> PrivateKey {
    let seed = derive_ed25519_seed(node_key);
    let keypair = ed25519_keypair_from_seed(&seed);
    PrivateKey::from(keypair)
}

/// Generate the public key string in OpenSSH authorized_keys format
/// (`ssh-ed25519 AAAA... comment`). Useful for advertising in
/// `Hostinfo.SSH_HostKeys` to the control plane.
pub fn host_key_public_string(key: &PrivateKey) -> String {
    use russh::keys::ssh_key::SshFormat;
    key.public_key()
        .to_openshstring()
        .trim()
        .to_string()
}

/// Derive a 32-byte Ed25519 seed from the node private key.
fn derive_ed25519_seed(node_key: &NodePrivate) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(b"rustscale-ssh-host-key-v1");
    hasher.update(node_key.as_bytes());
    let hash = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hash[..32]);
    seed
}

/// Create an Ed25519 keypair from a 32-byte seed, returning it in the
/// `ssh_key` crate's `KeypairData` format.
fn ed25519_keypair_from_seed(seed: &[u8; 32]) -> russh::keys::ssh_key::private::Ed25519Keypair {
    russh::keys::ssh_key::private::Ed25519Keypair::from_seed(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_key_is_deterministic() {
        let node_key = NodePrivate::generate();
        let k1 = host_key_from_node_key(&node_key);
        let k2 = host_key_from_node_key(&node_key);
        assert_eq!(k1.public_key(), k2.public_key());
    }

    #[test]
    fn different_node_keys_produce_different_host_keys() {
        let k1 = host_key_from_node_key(&NodePrivate::generate());
        let k2 = host_key_from_node_key(&NodePrivate::generate());
        assert_ne!(k1.public_key(), k2.public_key());
    }

    #[test]
    fn host_key_is_ed25519() {
        let key = host_key_from_node_key(&NodePrivate::generate());
        assert_eq!(key.algorithm(), Algorithm::Ed25519);
        assert!(matches!(key.key_data(), KeypairData::Ed25519(_)));
    }

    #[test]
    fn host_key_public_string_starts_with_ssh_ed25519() {
        let key = host_key_from_node_key(&NodePrivate::generate());
        let s = host_key_public_string(&key);
        assert!(s.starts_with("ssh-ed25519 "));
    }
}
