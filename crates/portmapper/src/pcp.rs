//! PCP client (RFC 6887).
//!
//! Implements the ANNOUNCE opcode (probe) and MAP opcode (create/renew/delete
//! a UDP mapping) to the gateway on port 5351. The wire format is a 24-byte
//! common header followed by opcode-specific data. MAP uses a 36-byte
//! option payload (96-bit nonce, protocol, ports, IPs).

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

/// PCP version (always 2).
pub(crate) const PCP_VERSION: u8 = 2;
/// Opcode: ANNOUNCE (probe for PCP availability).
pub(crate) const PCP_OP_ANNOUNCE: u8 = 0;
/// Opcode: MAP.
pub(crate) const PCP_OP_MAP: u8 = 1;
/// Reply flag OR'd into the opcode on responses.
pub(crate) const PCP_OP_REPLY: u8 = 0x80;

/// Protocol number for UDP (IANA).
pub(crate) const PCP_UDP: u8 = 17;

/// Result codes (RFC 6887 §7.4).
#[allow(dead_code)]
pub(crate) const PCP_CODE_OK: u8 = 0;
#[allow(dead_code)]
pub(crate) const PCP_CODE_NOT_AUTHORIZED: u8 = 2;
#[allow(dead_code)]
pub(crate) const PCP_CODE_ADDRESS_MISMATCH: u8 = 12;

/// A parsed PCP common-header response (first 24 bytes).
#[derive(Debug, Clone)]
pub struct PcpResponse {
    pub op_code: u8,
    pub result_code: u8,
    pub lifetime: u32,
    pub epoch: u32,
}

/// A parsed PCP MAP response (full 60 bytes).
#[derive(Debug, Clone)]
pub struct PcpMapResponse {
    pub result_code: u8,
    pub lifetime: u32,
    #[allow(dead_code)]
    pub epoch: u32,
    pub external: SocketAddr,
}

/// Build a 24-byte PCP ANNOUNCE request (probe).
pub(crate) fn build_announce_request(self_ip: Ipv4Addr) -> [u8; 24] {
    let mut pkt = [0u8; 24];
    pkt[0] = PCP_VERSION;
    pkt[1] = PCP_OP_ANNOUNCE;
    // pkt[2..4] = reserved
    // pkt[4..8] = lifetime (0 for announce)
    // pkt[8..24] = PCP client IP address (16-byte IPv4-mapped IPv6)
    write_ip16(&mut pkt[8..24], self_ip);
    pkt
}

/// Build a 60-byte PCP MAP request (24 common + 36 MAP option).
///
/// `self_ip` is our local IPv4. `local_port` is the internal port to map.
/// `prev_port` is the previously assigned external port (0 = any).
/// `lifetime_sec` is the desired lease (0 = delete). `prev_external_ip` is
/// the previous external IP if known (0.0.0.0 if not). A random 96-bit nonce
/// is generated for the request.
pub(crate) fn build_map_request(
    self_ip: Ipv4Addr,
    local_port: u16,
    prev_port: u16,
    lifetime_sec: u32,
    prev_external_ip: Ipv4Addr,
) -> [u8; 60] {
    let mut pkt = [0u8; 60];
    // Common header (24 bytes).
    pkt[0] = PCP_VERSION;
    pkt[1] = PCP_OP_MAP;
    pkt[4..8].copy_from_slice(&lifetime_sec.to_be_bytes());
    write_ip16(&mut pkt[8..24], self_ip);

    // MAP option (36 bytes, starting at offset 24).
    let map_op = &mut pkt[24..60];
    // 96-bit mapping nonce (random).
    {
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut map_op[0..12]);
    }
    // map_op[12] = protocol (UDP)
    map_op[12] = PCP_UDP;
    // map_op[13..16] = reserved
    // map_op[16..18] = internal port
    map_op[16..18].copy_from_slice(&local_port.to_be_bytes());
    // map_op[18..20] = suggested external port
    map_op[18..20].copy_from_slice(&prev_port.to_be_bytes());
    // map_op[20..36] = suggested external IP (16-byte IPv4-mapped IPv6)
    write_ip16(&mut map_op[20..36], prev_external_ip);

    pkt
}

/// Write an IPv4 address as a 16-byte IPv4-mapped IPv6 address into `dst`.
fn write_ip16(dst: &mut [u8], ip: Ipv4Addr) {
    let v6 = ip_to_ipv4_mapped(ip);
    dst.copy_from_slice(&v6.octets());
}

/// Convert an IPv4 address to an IPv4-mapped IPv6 address (::ffff:a.b.c.d).
fn ip_to_ipv4_mapped(ip: Ipv4Addr) -> Ipv6Addr {
    let o = ip.octets();
    Ipv6Addr::new(
        0,
        0,
        0,
        0,
        0,
        0xffff,
        u16::from_be_bytes([o[0], o[1]]),
        u16::from_be_bytes([o[2], o[3]]),
    )
}

/// Convert a 16-byte slice (IPv4-mapped IPv6 or native IPv6) to a SocketAddr
/// with the given port. For IPv4-mapped addresses, extracts the IPv4.
fn ip16_to_socketaddr(bytes: &[u8; 16], port: u16) -> SocketAddr {
    let v6 = Ipv6Addr::from(*bytes);
    // Check for IPv4-mapped (::ffff:0:0/96).
    if (v6.octets()[0..10] == [0; 10]) && (v6.octets()[10..12] == [0xff, 0xff]) {
        let o = v6.octets();
        let v4 = Ipv4Addr::new(o[12], o[13], o[14], o[15]);
        SocketAddr::new(std::net::IpAddr::V4(v4), port)
    } else {
        SocketAddr::new(std::net::IpAddr::V6(v6), port)
    }
}

/// Parse the PCP common header (first 24 bytes).
pub fn parse_common_header(b: &[u8]) -> Option<PcpResponse> {
    if b.len() < 24 || b[0] != PCP_VERSION {
        return None;
    }
    Some(PcpResponse {
        op_code: b[1],
        result_code: b[3],
        lifetime: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
        epoch: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
    })
}

/// Parse a full PCP MAP response (60 bytes).
pub fn parse_map_response(resp: &[u8]) -> Option<PcpMapResponse> {
    if resp.len() < 60 {
        return None;
    }
    let hdr = parse_common_header(&resp[..24])?;
    if hdr.op_code != PCP_OP_REPLY | PCP_OP_MAP {
        return None;
    }
    // MAP option starts at offset 24.
    // nonce: [24..36], protocol: [36], reserved: [37..40],
    // internal port: [40..42], external port: [42..44],
    // external IP: [44..60]
    let external_port = u16::from_be_bytes([resp[42], resp[43]]);
    let mut ext_ip_bytes = [0u8; 16];
    ext_ip_bytes.copy_from_slice(&resp[44..60]);
    let external = ip16_to_socketaddr(&ext_ip_bytes, external_port);

    Some(PcpMapResponse {
        result_code: hdr.result_code,
        lifetime: hdr.lifetime,
        epoch: hdr.epoch,
        external,
    })
}

/// Build a fake PCP ANNOUNCE discovery response (for test IGDs).
#[cfg(test)]
pub(crate) fn build_disco_response(req_op: u8) -> [u8; 24] {
    let mut out = [0u8; 24];
    out[0] = PCP_VERSION;
    out[1] = req_op | PCP_OP_REPLY;
    out[3] = 0; // result OK
    out
}

/// Build a fake PCP MAP response echoing the request's nonce/internal port
/// and assigning external port 4242 on 127.0.0.1 (for test IGDs).
#[cfg(test)]
pub(crate) fn build_map_response(req: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 60];
    out[0] = PCP_VERSION;
    out[1] = req[1] | PCP_OP_REPLY;
    out[3] = 0; // result OK
    out[4..8].copy_from_slice(&req[4..8]); // echo requested lifetime
                                           // Echo nonce + protocol + internal port from the request.
    if req.len() >= 60 {
        out[24..37].copy_from_slice(&req[24..37]); // nonce (12) + protocol (1)
        out[40..42].copy_from_slice(&req[40..42]); // internal port
    }
    // Assign external port 4242.
    out[42..44].copy_from_slice(&4242u16.to_be_bytes());
    // External IP = 127.0.0.1 (IPv4-mapped).
    write_ip16(&mut out[44..60], Ipv4Addr::LOCALHOST);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // This is the exact byte vector from Go's pcp_test.go — the canonical
    // PCP MAP response test vector. Verifies our parser produces the expected
    // external address (135.180.175.246:1234).
    const EXAMPLE_PCP_MAP_RESPONSE: [u8; 60] = [
        2, 129, 0, 0, 0, 0, 28, 32, 0, 2, 155, 237, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 129, 112,
        9, 24, 241, 208, 251, 45, 157, 76, 10, 188, 17, 0, 0, 0, 4, 210, 4, 210, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 255, 255, 135, 180, 175, 246,
    ];

    #[test]
    fn parse_example_pcp_map_response() {
        let m = parse_map_response(&EXAMPLE_PCP_MAP_RESPONSE)
            .expect("should parse canonical PCP MAP response");
        assert_eq!(m.result_code, 0);
        assert_eq!(
            m.external,
            SocketAddr::new(
                std::net::IpAddr::V4(Ipv4Addr::new(135, 180, 175, 246)),
                1234
            )
        );
    }

    #[test]
    fn announce_request_bytes() {
        let pkt = build_announce_request(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(pkt[0], PCP_VERSION);
        assert_eq!(pkt[1], PCP_OP_ANNOUNCE);
        // IP is IPv4-mapped IPv6 at offset 8: 10 zero bytes, then ff:ff, then IP.
        assert_eq!(&pkt[8..18], &[0; 10]);
        assert_eq!(&pkt[18..20], &[0xff, 0xff]);
        assert_eq!(&pkt[20..24], &[1, 2, 3, 4]);
    }

    #[test]
    fn map_request_header_bytes() {
        let pkt = build_map_request(
            Ipv4Addr::new(10, 0, 0, 1),
            12345,
            4242,
            7200,
            Ipv4Addr::UNSPECIFIED,
        );
        assert_eq!(pkt[0], PCP_VERSION);
        assert_eq!(pkt[1], PCP_OP_MAP);
        assert_eq!(u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]), 7200);
        // Self IP at common header offset 8 (IPv4-mapped: 10 zeros, ff:ff, then IP).
        assert_eq!(&pkt[20..24], &[10, 0, 0, 1]);
        // MAP option at 24: protocol at 36, internal port at 40, suggested ext at 42.
        assert_eq!(pkt[36], PCP_UDP);
        assert_eq!(u16::from_be_bytes([pkt[40], pkt[41]]), 12345);
        assert_eq!(u16::from_be_bytes([pkt[42], pkt[43]]), 4242);
    }

    #[test]
    fn parse_common_header_rejects_wrong_version() {
        let pkt = [1u8; 24];
        assert!(parse_common_header(&pkt).is_none());
    }

    #[test]
    fn roundtrip_map_response_via_fake_igd() {
        let req = build_map_request(Ipv4Addr::LOCALHOST, 12345, 0, 7200, Ipv4Addr::UNSPECIFIED);
        let resp = build_map_response(&req);
        let m = parse_map_response(&resp).expect("parse fake map response");
        assert_eq!(m.result_code, 0);
        assert_eq!(m.external.port(), 4242);
    }
}
