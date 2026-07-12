//! PROXY protocol v2 header encoder.
//!
//! Implements the binary header format from the HAProxy PROXY protocol spec
//! (https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt). Only v2
//! binary headers are implemented (no v1 text).
//!
//! When a [`ServiceListener`](crate::ServiceListener) is configured with
//! PROXY protocol enabled, the v2 header is prepended to the accepted
//! connection stream so the backend learns the real client address.
//!
//! # Header layout (v2)
//!
//! ```text
//! Offset  Length  Content
//! 0       12      Signature: \r\n\r\n\0\r\nQUIT\n
//! 12      1       Version (4 bits) | Command (4 bits)
//! 13      1       Address family (4 bits) | Transport (4 bits)
//! 14      2       Length of address info (big-endian u16)
//! 16      var     Address info (src/dst addr + ports)
//! ```
//!
//! For TCP over IPv4 the address info is 12 bytes:
//! `src_ip(4) + dst_ip(4) + src_port(2) + dst_port(2)`.
//!
//! For TCP over IPv6 the address info is 36 bytes:
//! `src_ip(16) + dst_ip(16) + src_port(2) + dst_port(2)`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The 12-byte PROXY protocol v2 signature.
pub const PROXY_V2_SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// PROXY protocol v2 version (high nibble of byte 12).
const PROXY_V2_VERSION: u8 = 0x20;

/// PROXY protocol v2 command: PROXY (relay real client info).
const PROXY_V2_CMD_PROXY: u8 = 0x01;

/// PROXY protocol v2 command: LOCAL (health check, no address info).
const PROXY_V2_CMD_LOCAL: u8 = 0x00;

/// Address family + transport protocol codes (byte 13).
/// High nibble = AF_INET(1) / AF_INET6(2), low nibble = SOCK_STREAM(1).
const AF_INET_TCP: u8 = 0x11;
const AF_INET6_TCP: u8 = 0x21;

/// Address info length for TCP over IPv4.
const ADDR_LEN_V4: u16 = 12;

/// Address info length for TCP over IPv6.
const ADDR_LEN_V6: u16 = 36;

/// Build a PROXY protocol v2 header for a TCP connection from `src` to `dst`.
///
/// Produces the full header bytes that should be written to the backend stream
/// before any application data. The header carries the real client address
/// (`src`) and the service VIP address (`dst`) so the backend can identify
/// the originating peer.
///
/// For `LOCAL` mode (no address info), use [`proxy_v2_local_header`].
pub fn proxy_v2_header(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(src_v4), IpAddr::V4(dst_v4)) => proxy_v4_header(src, src_v4, dst, dst_v4),
        (IpAddr::V6(src_v6), IpAddr::V6(dst_v6)) => proxy_v6_header(src, src_v6, dst, dst_v6),
        _ => {
            // Mixed v4/v6 — should not happen in practice. Fall back to
            // LOCAL (no address info) so the backend at least sees a valid
            // PROXY v2 header.
            proxy_v2_local_header()
        }
    }
}

fn proxy_v4_header(
    src: SocketAddr,
    src_v4: Ipv4Addr,
    dst: SocketAddr,
    dst_v4: Ipv4Addr,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16 + ADDR_LEN_V4 as usize);
    buf.extend_from_slice(&PROXY_V2_SIGNATURE);
    buf.push(PROXY_V2_VERSION | PROXY_V2_CMD_PROXY);
    buf.push(AF_INET_TCP);
    buf.extend_from_slice(&ADDR_LEN_V4.to_be_bytes());
    buf.extend_from_slice(&src_v4.octets());
    buf.extend_from_slice(&dst_v4.octets());
    buf.extend_from_slice(&src.port().to_be_bytes());
    buf.extend_from_slice(&dst.port().to_be_bytes());
    debug_assert_eq!(buf.len(), 16 + ADDR_LEN_V4 as usize);
    let _ = (src, dst); // silence unused warnings in some configs
    buf
}

fn proxy_v6_header(
    src: SocketAddr,
    src_v6: Ipv6Addr,
    dst: SocketAddr,
    dst_v6: Ipv6Addr,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(16 + ADDR_LEN_V6 as usize);
    buf.extend_from_slice(&PROXY_V2_SIGNATURE);
    buf.push(PROXY_V2_VERSION | PROXY_V2_CMD_PROXY);
    buf.push(AF_INET6_TCP);
    buf.extend_from_slice(&ADDR_LEN_V6.to_be_bytes());
    buf.extend_from_slice(&src_v6.octets());
    buf.extend_from_slice(&dst_v6.octets());
    buf.extend_from_slice(&src.port().to_be_bytes());
    buf.extend_from_slice(&dst.port().to_be_bytes());
    debug_assert_eq!(buf.len(), 16 + ADDR_LEN_V6 as usize);
    let _ = (src, dst);
    buf
}

/// Build a PROXY protocol v2 LOCAL header (no address info, used for health
/// checks). This is the minimal valid v2 header: signature + version/command +
/// family/transport (0x00) + length (0).
pub fn proxy_v2_local_header() -> Vec<u8> {
    let mut buf = Vec::with_capacity(16);
    buf.extend_from_slice(&PROXY_V2_SIGNATURE);
    buf.push(PROXY_V2_VERSION | PROXY_V2_CMD_LOCAL);
    buf.push(0x00);
    buf.extend_from_slice(&0u16.to_be_bytes());
    debug_assert_eq!(buf.len(), 16);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_matches_spec() {
        assert_eq!(PROXY_V2_SIGNATURE, *b"\r\n\r\n\0\r\nQUIT\n");
    }

    #[test]
    fn ipv4_header_byte_exact() {
        let src: SocketAddr = "203.0.113.5:42000".parse().unwrap();
        let dst: SocketAddr = "100.102.42.3:443".parse().unwrap();
        let hdr = proxy_v2_header(src, dst);

        assert_eq!(hdr.len(), 28); // 16 header + 12 address info

        // Signature (bytes 0–11).
        assert_eq!(&hdr[0..12], &PROXY_V2_SIGNATURE);

        // Version (2) + command (PROXY=1) → 0x21.
        assert_eq!(hdr[12], 0x21);

        // AF_INET + SOCK_STREAM → 0x11.
        assert_eq!(hdr[13], 0x11);

        // Length = 12 (big-endian).
        assert_eq!(&hdr[14..16], &[0x00, 0x0C]);

        // Source IP (bytes 16–19).
        assert_eq!(&hdr[16..20], &[203, 0, 113, 5]);

        // Destination IP (bytes 20–23).
        assert_eq!(&hdr[20..24], &[100, 102, 42, 3]);

        // Source port (bytes 24–25, big-endian).
        assert_eq!(&hdr[24..26], &(42000u16).to_be_bytes());

        // Destination port (bytes 26–27, big-endian).
        assert_eq!(&hdr[26..28], &(443u16).to_be_bytes());
    }

    #[test]
    fn ipv6_header_byte_exact() {
        let src: SocketAddr = "[fd7a:115c:a1e0::1234]:42000".parse().unwrap();
        let dst: SocketAddr = "[fd7a:115c:a1e0::abcd]:443".parse().unwrap();
        let hdr = proxy_v2_header(src, dst);

        assert_eq!(hdr.len(), 52); // 16 header + 36 address info

        // Signature.
        assert_eq!(&hdr[0..12], &PROXY_V2_SIGNATURE);

        // Version + command.
        assert_eq!(hdr[12], 0x21);

        // AF_INET6 + SOCK_STREAM → 0x21.
        assert_eq!(hdr[13], 0x21);

        // Length = 36 (big-endian).
        assert_eq!(&hdr[14..16], &[0x00, 0x24]);

        // Source IP (16 bytes, bytes 16–31).
        let src_v6 = match src.ip() {
            IpAddr::V6(v6) => v6,
            _ => unreachable!(),
        };
        assert_eq!(&hdr[16..32], &src_v6.octets());

        // Destination IP (16 bytes, bytes 32–47).
        let dst_v6 = match dst.ip() {
            IpAddr::V6(v6) => v6,
            _ => unreachable!(),
        };
        assert_eq!(&hdr[32..48], &dst_v6.octets());

        // Source port (bytes 48–49).
        assert_eq!(&hdr[48..50], &(42000u16).to_be_bytes());

        // Destination port (bytes 50–51).
        assert_eq!(&hdr[50..52], &(443u16).to_be_bytes());
    }

    #[test]
    fn local_header_byte_exact() {
        let hdr = proxy_v2_local_header();

        assert_eq!(hdr.len(), 16);
        assert_eq!(&hdr[0..12], &PROXY_V2_SIGNATURE);
        assert_eq!(hdr[12], 0x20); // v2 + LOCAL
        assert_eq!(hdr[13], 0x00); // UNSPEC
        assert_eq!(&hdr[14..16], &[0x00, 0x00]); // length = 0
    }

    #[test]
    fn mixed_family_falls_back_to_local() {
        let src: SocketAddr = "203.0.113.5:42000".parse().unwrap();
        let dst: SocketAddr = "[fd7a:115c:a1e0::abcd]:443".parse().unwrap();
        let hdr = proxy_v2_header(src, dst);
        // Should be a LOCAL header (no address info).
        assert_eq!(hdr.len(), 16);
        assert_eq!(hdr[12], 0x20);
    }

    #[test]
    fn ipv4_header_specific_byte_pattern() {
        // Verify a known byte pattern from the spec example.
        let src: SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let dst: SocketAddr = "192.168.0.1:80".parse().unwrap();
        let hdr = proxy_v2_header(src, dst);

        let expected: Vec<u8> = vec![
            // Signature
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
            // v2 + PROXY
            0x21, // AF_INET + STREAM
            0x11, // Length = 12
            0x00, 0x0C, // src addr: 10.0.0.1
            0x0A, 0x00, 0x00, 0x01, // dst addr: 192.168.0.1
            0xC0, 0xA8, 0x00, 0x01, // src port: 1234 (0x04D2)
            0x04, 0xD2, // dst port: 80 (0x0050)
            0x00, 0x50,
        ];

        assert_eq!(hdr, expected);
    }
}
