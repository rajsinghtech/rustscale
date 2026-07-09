//! Wire helpers for IP address encoding (v4-mapped-v6, matching Go's
//! `netip.Addr.As16` / `AddrFrom16().Unmap()`).

use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

/// Length of a marshalled endpoint: 16-byte IP + 2-byte big-endian port.
pub(crate) const EP_LENGTH: usize = 16 + 2;

/// A network endpoint (IP + port) with wire-compatible encoding.
///
/// IPv4 addresses are encoded as v4-mapped IPv6 (16 bytes with
/// `::ffff:a.b.c.d`), matching Go's `netip.AddrPort` wire format.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AddrPort {
    ip: IpAddr,
    port: u16,
}

impl AddrPort {
    pub fn new(ip: IpAddr, port: u16) -> Self {
        Self { ip, port }
    }

    pub fn ip(&self) -> &IpAddr {
        &self.ip
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    fn as16(&self) -> [u8; 16] {
        match self.ip {
            IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
            IpAddr::V6(v6) => v6.octets(),
        }
    }

    fn from16(bytes: [u8; 16], port: u16) -> Self {
        let ip = map_from_16(bytes);
        Self { ip, port }
    }

    pub(crate) fn encode_to(&self, buf: &mut [u8]) {
        debug_assert_eq!(buf.len(), EP_LENGTH);
        buf[..16].copy_from_slice(&self.as16());
        buf[16..].copy_from_slice(&self.port.to_be_bytes());
    }

    pub(crate) fn decode_from(buf: &[u8]) -> Self {
        debug_assert_eq!(buf.len(), EP_LENGTH);
        let mut ip16 = [0u8; 16];
        ip16.copy_from_slice(&buf[..16]);
        let port = u16::from_be_bytes([buf[16], buf[17]]);
        Self::from16(ip16, port)
    }
}

fn map_from_16(bytes: [u8; 16]) -> IpAddr {
    if let Some(v4) = Ipv6Addr::from(bytes).to_ipv4_mapped() {
        IpAddr::V4(v4)
    } else {
        IpAddr::V6(Ipv6Addr::from(bytes))
    }
}

impl From<SocketAddr> for AddrPort {
    fn from(sa: SocketAddr) -> Self {
        Self {
            ip: sa.ip(),
            port: sa.port(),
        }
    }
}

impl From<AddrPort> for SocketAddr {
    fn from(ap: AddrPort) -> Self {
        SocketAddr::new(ap.ip, ap.port)
    }
}

impl fmt::Display for AddrPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.ip {
            IpAddr::V4(v4) => write!(f, "{v4}:{}", self.port),
            IpAddr::V6(v6) => write!(f, "[{v6}]:{}", self.port),
        }
    }
}

impl fmt::Debug for AddrPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn encode_buf(ap: &AddrPort) -> [u8; EP_LENGTH] {
        let mut buf = [0u8; EP_LENGTH];
        ap.encode_to(&mut buf);
        buf
    }

    #[test]
    fn v4_encodes_as_mapped_v6() {
        let ap = AddrPort::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 567);
        let buf = encode_buf(&ap);
        assert_eq!(buf[..10], [0u8; 10]);
        assert_eq!(buf[10], 0xff);
        assert_eq!(buf[11], 0xff);
        assert_eq!(buf[12..16], [1, 2, 3, 4]);
        assert_eq!(buf[16..], [0x02, 0x37]);
    }

    #[test]
    fn v6_encodes_directly() {
        let ap = AddrPort::new(
            IpAddr::V6(Ipv6Addr::from([
                0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x34, 0x56, 0, 0,
            ])),
            789,
        );
        let buf = encode_buf(&ap);
        assert_eq!(buf[0], 0x20);
        assert_eq!(buf[1], 0x01);
        assert_eq!(buf[12], 0x34);
        assert_eq!(buf[13], 0x56);
        assert_eq!(buf[16..], [0x03, 0x15]);
    }

    #[test]
    fn v4_roundtrips_through_decode() {
        let ap = AddrPort::new(IpAddr::V4(Ipv4Addr::new(2, 3, 4, 5)), 1234);
        let buf = encode_buf(&ap);
        let back = AddrPort::decode_from(&buf);
        assert_eq!(ap, back);
    }

    #[test]
    fn v6_roundtrips_through_decode() {
        let ip = Ipv6Addr::new(0xfed0, 0, 0, 0, 0, 0, 0, 0x12);
        let ap = AddrPort::new(IpAddr::V6(ip), 6666);
        let buf = encode_buf(&ap);
        let back = AddrPort::decode_from(&buf);
        assert_eq!(ap, back);
    }

    #[test]
    fn display_matches_socketaddr_form() {
        let v4 = AddrPort::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 567);
        assert_eq!(v4.to_string(), "1.2.3.4:567");

        let v6 = AddrPort::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0x3456)),
            789,
        );
        assert_eq!(v6.to_string(), "[2001::3456]:789");
    }
}
