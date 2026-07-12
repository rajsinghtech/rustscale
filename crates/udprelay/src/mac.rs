//! BLAKE2s MAC computation for the 3-way bind handshake.
//!
//! Ports Go's `blakeMACFromBindMsg` from `net/udprelay/server.go`.
//!
//! The MAC is computed over `(VNI, generation, RemoteKey, src AddrPort)` using
//! a keyed BLAKE2s-256 hash. This binds the handshake to the client's source
//! address, preventing replay from a different address.

use std::net::SocketAddr;

use blake2::digest::{FixedOutput, KeyInit, Update};
use blake2::Blake2sMac256;
use rustscale_disco::BindUdpRelayEndpointCommon;
use rustscale_key::DiscoPublic;

/// BLAKE2s-256 output size in bytes.
pub const MAC_SIZE: usize = 32;

/// Compute the BLAKE2s MAC over `(vni, generation, remote_key, src_addr_port)`.
///
/// Matches Go's `blakeMACFromBindMsg`:
/// - `vni`: 4 bytes big-endian
/// - `generation`: 4 bytes big-endian
/// - `remote_key`: 32 bytes raw disco public key
/// - `src`: 18 bytes (16-byte IP as v4-mapped-v6 + 2-byte big-endian port)
///
/// The `key` is the current MAC secret (32 bytes).
pub fn compute_mac(
    key: &[u8; MAC_SIZE],
    vni: u32,
    generation: u32,
    remote_key: &DiscoPublic,
    src: SocketAddr,
) -> [u8; MAC_SIZE] {
    let mut input = Vec::with_capacity(4 + 4 + 32 + 18);
    input.extend_from_slice(&vni.to_be_bytes());
    input.extend_from_slice(&generation.to_be_bytes());
    input.extend_from_slice(&remote_key.raw32());
    encode_addr_port_to(&mut input, src);

    let mut hasher = Blake2sMac256::new_from_slice(key).expect("32-byte key is valid for Blake2s");
    hasher.update(&input);
    let result = hasher.finalize_fixed();
    let mut out = [0u8; MAC_SIZE];
    out.copy_from_slice(&result);
    out
}

/// Compute the MAC directly from a `BindUdpRelayEndpointCommon` and source addr.
pub fn compute_mac_from_bind_msg(
    key: &[u8; MAC_SIZE],
    src: SocketAddr,
    msg: &BindUdpRelayEndpointCommon,
) -> [u8; MAC_SIZE] {
    compute_mac(key, msg.vni, msg.generation, &msg.remote_key, src)
}

/// Verify a MAC against a candidate in constant-ish time (sender is already
/// authenticated via disco, so speed is favored over constant-time).
pub fn verify_mac(expected: &[u8; MAC_SIZE], candidate: &[u8; MAC_SIZE]) -> bool {
    expected == candidate
}

/// Encode a `SocketAddr` as 16-byte IP (v4-mapped-v6 for IPv4) + 2-byte
/// big-endian port, matching Go's `netip.AddrPort.AppendBinary`.
fn encode_addr_port_to(buf: &mut Vec<u8>, addr: SocketAddr) {
    match addr {
        SocketAddr::V4(v4) => {
            buf.extend_from_slice(&v4.ip().to_ipv6_mapped().octets());
        }
        SocketAddr::V6(v6) => {
            buf.extend_from_slice(&v6.ip().octets());
        }
    }
    buf.extend_from_slice(&addr.port().to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn mac_deterministic() {
        let key = [0x42u8; 32];
        let remote = DiscoPublic::from_raw32([0xAB; 32]);
        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 5678));

        let mac1 = compute_mac(&key, 100, 1, &remote, src);
        let mac2 = compute_mac(&key, 100, 1, &remote, src);
        assert_eq!(mac1, mac2);
    }

    #[test]
    fn mac_changes_with_inputs() {
        let key = [0x42u8; 32];
        let remote = DiscoPublic::from_raw32([0xAB; 32]);
        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 5678));

        let base = compute_mac(&key, 100, 1, &remote, src);

        // Different VNI
        assert_ne!(base, compute_mac(&key, 101, 1, &remote, src));
        // Different generation
        assert_ne!(base, compute_mac(&key, 100, 2, &remote, src));
        // Different remote key
        assert_ne!(
            base,
            compute_mac(&key, 100, 1, &DiscoPublic::from_raw32([0xCD; 32]), src)
        );
        // Different source addr
        assert_ne!(
            base,
            compute_mac(
                &key,
                100,
                1,
                &remote,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 9999))
            )
        );
        // Different key
        assert_ne!(base, compute_mac(&[0x99; 32], 100, 1, &remote, src));
    }

    #[test]
    fn mac_verify() {
        let key = [0x42u8; 32];
        let remote = DiscoPublic::from_raw32([0xAB; 32]);
        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 5678));

        let mac = compute_mac(&key, 100, 1, &remote, src);
        assert!(verify_mac(&mac, &mac));

        let mut wrong = mac;
        wrong[0] ^= 1;
        assert!(!verify_mac(&mac, &wrong));
    }

    #[test]
    fn mac_ipv6_source() {
        let key = [0x42u8; 32];
        let remote = DiscoPublic::from_raw32([0xAB; 32]);
        let src_v4 = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 5678));
        let src_v6 = SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 1)),
            5678,
        );

        let mac_v4 = compute_mac(&key, 100, 1, &remote, src_v4);
        let mac_v6 = compute_mac(&key, 100, 1, &remote, src_v6);
        assert_ne!(mac_v4, mac_v6);
    }

    #[test]
    fn mac_from_bind_msg() {
        let key = [0x42u8; 32];
        let remote = DiscoPublic::from_raw32([0xAB; 32]);
        let src = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 5678));

        let common = BindUdpRelayEndpointCommon {
            vni: 100,
            generation: 1,
            remote_key: remote.clone(),
            challenge: [0u8; 32],
        };

        let mac_a = compute_mac_from_bind_msg(&key, src, &common);
        let mac_b = compute_mac(&key, 100, 1, &remote, src);
        assert_eq!(mac_a, mac_b);
    }
}
