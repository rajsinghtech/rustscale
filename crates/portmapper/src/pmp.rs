//! NAT-PMP client (RFC 6886).
//!
//! Implements opcode 0 (external address request) and opcode 1 (UDP mapping
//! request) to the gateway on port 5351. The wire format is a simple
//! big-endian binary layout with no authentication.

use std::net::Ipv4Addr;

/// NAT-PMP version (always 0).
pub(crate) const PMP_VERSION: u8 = 0;
/// Opcode: map public address (external IP query).
pub(crate) const PMP_OP_MAP_PUBLIC_ADDR: u8 = 0;
/// Opcode: map UDP port.
pub(crate) const PMP_OP_MAP_UDP: u8 = 1;
/// Reply flag OR'd into the opcode on responses.
pub(crate) const PMP_OP_REPLY: u8 = 0x80;

/// Delete lifetime (0 seconds = delete the mapping).
pub(crate) const PMP_LIFETIME_DELETE: u32 = 0;

/// A parsed NAT-PMP response.
#[derive(Debug, Clone)]
pub(crate) struct PmpResponse {
    pub op_code: u8,
    pub result_code: u16,
    #[allow(dead_code)]
    pub seconds_since_epoch: u32,
    /// For map-UDP responses: the internal/external ports and lifetime.
    pub mapping_valid_seconds: u32,
    pub internal_port: u16,
    pub external_port: u16,
    /// For public-address responses: the external IPv4 address.
    pub public_addr: Option<Ipv4Addr>,
}

/// Build the 2-byte external-address request packet (opcode 0).
pub(crate) fn build_external_addr_request() -> [u8; 2] {
    [PMP_VERSION, PMP_OP_MAP_PUBLIC_ADDR]
}

/// Build a 12-byte UDP mapping request packet (opcode 1).
///
/// `local_port` is the internal port to map; `prev_port` is the previously
/// assigned external port (0 to request any); `lifetime_sec` is the desired
/// lease in seconds.
pub(crate) fn build_map_request(local_port: u16, prev_port: u16, lifetime_sec: u32) -> [u8; 12] {
    let mut pkt = [0u8; 12];
    pkt[0] = PMP_VERSION;
    pkt[1] = PMP_OP_MAP_UDP;
    // pkt[2..4] = reserved
    pkt[2..4].copy_from_slice(&0u16.to_be_bytes());
    pkt[4..6].copy_from_slice(&local_port.to_be_bytes());
    pkt[6..8].copy_from_slice(&prev_port.to_be_bytes());
    pkt[8..12].copy_from_slice(&lifetime_sec.to_be_bytes());
    pkt
}

/// Build a 12-byte UDP mapping deletion packet (lifetime = 0).
pub(crate) fn build_delete_request(local_port: u16, external_port: u16) -> [u8; 12] {
    build_map_request(local_port, external_port, PMP_LIFETIME_DELETE)
}

/// Parse a NAT-PMP response packet.
///
/// Returns `None` if the packet is too short, has the wrong version, or has
/// an unexpected length for its opcode.
pub(crate) fn parse_response(pkt: &[u8]) -> Option<PmpResponse> {
    if pkt.len() < 12 {
        return None;
    }
    if pkt[0] != PMP_VERSION {
        return None;
    }
    let op_code = pkt[1];
    let result_code = u16::from_be_bytes([pkt[2], pkt[3]]);
    let seconds_since_epoch = u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);

    let mut resp = PmpResponse {
        op_code,
        result_code,
        seconds_since_epoch,
        mapping_valid_seconds: 0,
        internal_port: 0,
        external_port: 0,
        public_addr: None,
    };

    if op_code == PMP_OP_REPLY | PMP_OP_MAP_UDP {
        if pkt.len() != 16 {
            return None;
        }
        resp.internal_port = u16::from_be_bytes([pkt[8], pkt[9]]);
        resp.external_port = u16::from_be_bytes([pkt[10], pkt[11]]);
        resp.mapping_valid_seconds = u32::from_be_bytes([pkt[12], pkt[13], pkt[14], pkt[15]]);
    } else if op_code == PMP_OP_REPLY | PMP_OP_MAP_PUBLIC_ADDR {
        if pkt.len() != 12 {
            return None;
        }
        let addr = Ipv4Addr::new(pkt[8], pkt[9], pkt[10], pkt[11]);
        if addr.is_unspecified() {
            // Zero it out so it's not used accidentally.
            resp.public_addr = None;
        } else {
            resp.public_addr = Some(addr);
        }
    }

    Some(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_addr_request_bytes() {
        let pkt = build_external_addr_request();
        assert_eq!(pkt, [0, 0]);
    }

    #[test]
    fn map_request_bytes() {
        let pkt = build_map_request(12345, 4242, 7200);
        // version=0, op=1, reserved=0, local=12345, prev=4242, lifetime=7200
        assert_eq!(pkt[0], 0);
        assert_eq!(pkt[1], 1);
        assert_eq!(&pkt[2..4], &[0, 0]);
        assert_eq!(u16::from_be_bytes([pkt[4], pkt[5]]), 12345);
        assert_eq!(u16::from_be_bytes([pkt[6], pkt[7]]), 4242);
        assert_eq!(u32::from_be_bytes([pkt[8], pkt[9], pkt[10], pkt[11]]), 7200);
    }

    #[test]
    fn parse_map_udp_response() {
        // Construct a valid 16-byte map-UDP reply.
        let mut pkt = [0u8; 16];
        pkt[0] = 0; // version
        pkt[1] = PMP_OP_REPLY | PMP_OP_MAP_UDP; // 0x81
        pkt[2..4].copy_from_slice(&0u16.to_be_bytes()); // result OK
        pkt[4..8].copy_from_slice(&12345u32.to_be_bytes()); // epoch
        pkt[8..10].copy_from_slice(&12345u16.to_be_bytes()); // internal port
        pkt[10..12].copy_from_slice(&4242u16.to_be_bytes()); // external port
        pkt[12..16].copy_from_slice(&7200u32.to_be_bytes()); // lifetime
        let resp = parse_response(&pkt).expect("parse");
        assert_eq!(resp.op_code, 0x81);
        assert_eq!(resp.result_code, 0);
        assert_eq!(resp.seconds_since_epoch, 12345);
        assert_eq!(resp.internal_port, 12345);
        assert_eq!(resp.external_port, 4242);
        assert_eq!(resp.mapping_valid_seconds, 7200);
        assert!(resp.public_addr.is_none());
    }

    #[test]
    fn parse_public_addr_response() {
        let mut pkt = [0u8; 12];
        pkt[0] = 0; // version
        pkt[1] = PMP_OP_REPLY | PMP_OP_MAP_PUBLIC_ADDR; // 0x80
        pkt[2..4].copy_from_slice(&0u16.to_be_bytes()); // result OK
        pkt[4..8].copy_from_slice(&99999u32.to_be_bytes()); // epoch
        pkt[8] = 1;
        pkt[9] = 2;
        pkt[10] = 3;
        pkt[11] = 4;
        let resp = parse_response(&pkt).expect("parse");
        assert_eq!(resp.op_code, 0x80);
        assert_eq!(resp.result_code, 0);
        assert_eq!(resp.public_addr, Some(Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn parse_rejects_wrong_version() {
        let pkt = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(parse_response(&pkt).is_none());
    }

    #[test]
    fn parse_rejects_short_packet() {
        let pkt = [0, 0, 0, 0];
        assert!(parse_response(&pkt).is_none());
    }

    #[test]
    fn parse_public_addr_zero_is_none() {
        let mut pkt = [0u8; 12];
        pkt[1] = PMP_OP_REPLY | PMP_OP_MAP_PUBLIC_ADDR;
        // public addr = 0.0.0.0
        let resp = parse_response(&pkt).expect("parse");
        assert!(resp.public_addr.is_none());
    }
}
