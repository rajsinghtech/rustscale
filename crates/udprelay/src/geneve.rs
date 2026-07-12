//! Geneve header (RFC 8926) fixed-size 8-byte header codec.
//!
//! Ports Go's `net/packet/geneve.go`. Only the fixed header is supported
//! (no TLV options).
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |        Virtual Network Identifier (VNI)       |    Reserved   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Tailscale repurposes the O bit (0x80 in byte 1) as the Control flag.

use std::io;

/// Fixed length of the Geneve header in bytes.
pub const GENEVE_FIXED_HEADER_LENGTH: usize = 8;

/// IEEE 802 Ethertype for Tailscale Disco protocol in a Geneve header.
pub const GENEVE_PROTOCOL_DISCO: u16 = 0x7A11;

/// IEEE 802 Ethertype for WireGuard protocol in a Geneve header.
pub const GENEVE_PROTOCOL_WIREGUARD: u16 = 0x7A12;

/// Minimum VNI value (0 is reserved/invalid).
pub const MIN_VNI: u32 = 1;

/// Maximum VNI value (24-bit space).
pub const MAX_VNI: u32 = 0x00FF_FFFF;

/// Geneve fixed-size header (RFC 8926).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GeneveHeader {
    /// Geneve version (2 bits, currently 0).
    pub version: u8,
    /// Control packet flag (O bit in RFC, repurposed by Tailscale).
    pub control: bool,
    /// Protocol type (Ethertype).
    pub protocol: u16,
    /// 24-bit Virtual Network Identifier.
    pub vni: u32,
}

impl GeneveHeader {
    /// Create a new Geneve header with the given VNI, protocol, and control flag.
    pub const fn new(vni: u32, protocol: u16, control: bool) -> Self {
        Self {
            version: 0,
            control,
            protocol,
            vni,
        }
    }

    /// Encode the header into the first 8 bytes of `buf`.
    pub fn encode_to(&self, buf: &mut [u8]) -> Result<(), io::Error> {
        if buf.len() < GENEVE_FIXED_HEADER_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "buffer too short",
            ));
        }
        if self.vni > MAX_VNI {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VNI exceeds 24-bit range",
            ));
        }
        buf[0] = self.version << 6;
        buf[1] = if self.control { 0x80 } else { 0x00 };
        buf[2..4].copy_from_slice(&self.protocol.to_be_bytes());
        let vni_shifted = self.vni << 8;
        buf[4..8].copy_from_slice(&vni_shifted.to_be_bytes());
        Ok(())
    }

    /// Encode the header as a standalone 8-byte `Vec`.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![0u8; GENEVE_FIXED_HEADER_LENGTH];
        self.encode_to(&mut buf)
            .expect("8-byte buffer is always sufficient");
        buf
    }

    /// Decode a Geneve header from `buf`. Returns the header and the remaining
    /// payload slice.
    pub fn decode(buf: &[u8]) -> Result<(GeneveHeader, &[u8]), io::Error> {
        if buf.len() < GENEVE_FIXED_HEADER_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "buffer too short",
            ));
        }
        let version = buf[0] >> 6;
        let control = buf[1] & 0x80 != 0;
        let protocol = u16::from_be_bytes([buf[2], buf[3]]);
        let vni = u32::from_be_bytes([0, buf[4], buf[5], buf[6]]);
        Ok((
            GeneveHeader {
                version,
                control,
                protocol,
                vni,
            },
            &buf[GENEVE_FIXED_HEADER_LENGTH..],
        ))
    }
}

/// Encode a Geneve data frame: 8-byte header + payload.
///
/// Uses `Control=false, Protocol=GeneveProtocolWireGuard`.
pub fn encode_geneve(vni: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(GENEVE_FIXED_HEADER_LENGTH + payload.len());
    let header = GeneveHeader::new(vni, GENEVE_PROTOCOL_WIREGUARD, false);
    out.extend_from_slice(&header.encode());
    out.extend_from_slice(payload);
    out
}

/// Encode a Geneve control frame: 8-byte header + payload.
///
/// Uses `Control=true, Protocol=GeneveProtocolDisco`.
pub fn encode_geneve_control(vni: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(GENEVE_FIXED_HEADER_LENGTH + payload.len());
    let header = GeneveHeader::new(vni, GENEVE_PROTOCOL_DISCO, true);
    out.extend_from_slice(&header.encode());
    out.extend_from_slice(payload);
    out
}

/// Decode a Geneve frame, returning `(vni, payload)`.
///
/// Works for both data and control packets — only extracts the VNI and payload,
/// ignoring the control flag and protocol type.
pub fn decode_geneve(data: &[u8]) -> Option<(u32, &[u8])> {
    let (header, payload) = GeneveHeader::decode(data).ok()?;
    Some((header.vni, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geneve_header_roundtrip_data() {
        let h = GeneveHeader::new(0x123456, GENEVE_PROTOCOL_WIREGUARD, false);
        let encoded = h.encode();
        assert_eq!(encoded.len(), GENEVE_FIXED_HEADER_LENGTH);
        assert_eq!(encoded[0], 0x00); // version=0, opt_len=0
        assert_eq!(encoded[1], 0x00); // not control
        assert_eq!(&encoded[2..4], &0x7A12u16.to_be_bytes());
        assert_eq!(encoded[4], 0x12);
        assert_eq!(encoded[5], 0x34);
        assert_eq!(encoded[6], 0x56);
        assert_eq!(encoded[7], 0x00); // reserved

        let (decoded, _) = GeneveHeader::decode(&encoded).unwrap();
        assert_eq!(decoded, h);
    }

    #[test]
    fn geneve_header_roundtrip_control() {
        let h = GeneveHeader::new(0xFFFFFF, GENEVE_PROTOCOL_DISCO, true);
        let encoded = h.encode();
        assert_eq!(encoded[1], 0x80); // control bit
        assert_eq!(&encoded[2..4], &0x7A11u16.to_be_bytes());
        assert_eq!(encoded[4], 0xFF);
        assert_eq!(encoded[5], 0xFF);
        assert_eq!(encoded[6], 0xFF);

        let (decoded, _) = GeneveHeader::decode(&encoded).unwrap();
        assert_eq!(decoded, h);
        assert!(decoded.control);
    }

    #[test]
    fn geneve_header_decode_short_buffer() {
        assert!(GeneveHeader::decode(&[0u8; 4]).is_err());
    }

    #[test]
    fn geneve_encode_decode_payload_roundtrip() {
        let payload = b"hello relay world";
        let frame = encode_geneve(0xABCDEF, payload);
        assert_eq!(frame.len(), GENEVE_FIXED_HEADER_LENGTH + payload.len());
        let (vni, body) = decode_geneve(&frame).unwrap();
        assert_eq!(vni, 0xABCDEF);
        assert_eq!(body, payload);
    }

    #[test]
    fn geneve_encode_control_has_control_bit() {
        let payload = b"disco-payload";
        let frame = encode_geneve_control(42, payload);
        assert_eq!(frame[1], 0x80); // control bit set
        let (header, body) = GeneveHeader::decode(&frame).unwrap();
        assert!(header.control);
        assert_eq!(header.protocol, GENEVE_PROTOCOL_DISCO);
        assert_eq!(header.vni, 42);
        assert_eq!(body, payload);
    }

    #[test]
    fn geneve_decode_too_short() {
        assert!(decode_geneve(&[0u8; 4]).is_none());
    }

    #[test]
    fn geneve_vni_max() {
        let h = GeneveHeader::new(MAX_VNI, GENEVE_PROTOCOL_WIREGUARD, false);
        let encoded = h.encode();
        let (decoded, _) = GeneveHeader::decode(&encoded).unwrap();
        assert_eq!(decoded.vni, MAX_VNI);
    }

    #[test]
    fn geneve_vni_overflow_rejected() {
        let h = GeneveHeader::new(0x01_00_00_00, GENEVE_PROTOCOL_WIREGUARD, false);
        let mut buf = [0u8; 8];
        assert!(h.encode_to(&mut buf).is_err());
    }
}
