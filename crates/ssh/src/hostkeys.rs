//! SSH host key generation — deterministic from the node private key.

use russh::keys::ssh_key::PrivateKey;
use rustscale_key::NodePrivate;
use sha2::{Digest, Sha512};

pub fn host_key_from_node_key(node_key: &NodePrivate) -> PrivateKey {
    let seed = derive_ed25519_seed(node_key);
    let keypair = russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&seed);
    PrivateKey::from(keypair)
}

pub fn host_key_public_string(key: &PrivateKey) -> String {
    key.public_key()
        .to_openssh()
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn derive_ed25519_seed(node_key: &NodePrivate) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(b"rustscale-ssh-host-key-v1");
    hasher.update(node_key.raw32());
    let hash = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hash[..32]);
    seed
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn host_key_is_deterministic() {
        let nk = NodePrivate::generate();
        assert_eq!(
            host_key_from_node_key(&nk).public_key(),
            host_key_from_node_key(&nk).public_key()
        );
    }
    #[test]
    fn different_node_keys_produce_different_host_keys() {
        assert_ne!(
            host_key_from_node_key(&NodePrivate::generate()).public_key(),
            host_key_from_node_key(&NodePrivate::generate()).public_key()
        );
    }
    #[test]
    fn host_key_is_ed25519() {
        let key = host_key_from_node_key(&NodePrivate::generate());
        assert_eq!(key.algorithm(), russh::keys::ssh_key::Algorithm::Ed25519);
    }
    #[test]
    fn host_key_public_string_format() {
        let key = host_key_from_node_key(&NodePrivate::generate());
        let s = host_key_public_string(&key);
        assert!(s.starts_with("ssh-ed25519 "));
    }
}
