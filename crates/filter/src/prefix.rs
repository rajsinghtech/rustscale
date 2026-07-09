//! IP prefix containment and IP-range-to-prefixes — hand-rolled, no
//! external crates.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// An IP prefix: an address + a prefix length.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IpPrefix {
    pub addr: IpAddr,
    pub bits: u8,
}

impl IpPrefix {
    /// Whether `ip` is contained within this prefix.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => v4_contains(a, b, self.bits),
            (IpAddr::V6(a), IpAddr::V6(b)) => v6_contains(a, b, self.bits),
            _ => false,
        }
    }

    /// Whether this prefix covers IPv4 space.
    pub fn is_v4(&self) -> bool {
        matches!(self.addr, IpAddr::V4(_))
    }
}

fn v4_contains(net: Ipv4Addr, ip: Ipv4Addr, bits: u8) -> bool {
    if bits == 0 {
        return true;
    }
    if bits > 32 {
        return false;
    }
    let mask = u32::from_be_bytes(net.octets());
    let val = u32::from_be_bytes(ip.octets());
    let shift = 32u32.saturating_sub(u32::from(bits));
    mask >> shift == val >> shift
}

fn v6_contains(net: Ipv6Addr, ip: Ipv6Addr, bits: u8) -> bool {
    if bits == 0 {
        return true;
    }
    if bits > 128 {
        return false;
    }
    let net_b = net.octets();
    let ip_b = ip.octets();
    let full_bytes = (bits / 8) as usize;
    let rem_bits = bits % 8;
    if full_bytes > 0 && net_b[..full_bytes] != ip_b[..full_bytes] {
        return false;
    }
    if rem_bits == 0 {
        return true;
    }
    let mask = 0xFFu8 << (8 - rem_bits);
    net_b[full_bytes] & mask == ip_b[full_bytes] & mask
}

/// Whether an IP is a multicast address.
pub fn is_multicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.octets()[0] >= 224,
        IpAddr::V6(a) => a.octets()[0] == 0xFF,
    }
}

/// Whether an IP is a link-local unicast address.
pub fn is_link_local_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => a.octets()[0] == 169 && a.octets()[1] == 254,
        IpAddr::V6(a) => {
            let b = a.octets();
            b[0] == 0xFE && (b[1] & 0xC0) == 0x80
        }
    }
}

/// Convert an IPv4 range [start, end] (inclusive) to the minimal set of
/// CIDR prefixes covering it.
pub fn range_to_prefixes_v4(start: Ipv4Addr, end: Ipv4Addr) -> Vec<IpPrefix> {
    let mut out = Vec::new();
    let mut cur = u32::from_be_bytes(start.octets());
    let last = u32::from_be_bytes(end.octets());
    if cur > last {
        return out;
    }
    while cur <= last {
        let max_align = if cur == 0 { 32 } else { cur.trailing_zeros() };
        let remaining = last - cur + 1;
        let max_size = if remaining == 0 { 0 } else { remaining.ilog2() };
        let host_bits = max_align.min(max_size);
        let prefix_len = 32 - host_bits;
        let block_size = if host_bits < 32 {
            1u32 << host_bits
        } else {
            u32::MAX
        };
        let addr = Ipv4Addr::from(cur.to_be_bytes());
        out.push(IpPrefix {
            addr: IpAddr::V4(addr),
            bits: prefix_len as u8,
        });
        if block_size == 0 {
            break;
        }
        let next = cur.saturating_add(block_size);
        if next <= cur {
            break;
        }
        cur = next;
    }
    out
}

/// Convert an IPv6 range [start, end] (inclusive) to the minimal set of
/// CIDR prefixes covering it.
pub fn range_to_prefixes_v6(start: Ipv6Addr, end: Ipv6Addr) -> Vec<IpPrefix> {
    let mut out = Vec::new();
    let mut cur = ipv6_to_u128(start);
    let last = ipv6_to_u128(end);
    if cur > last {
        return out;
    }
    while cur <= last {
        let max_align = if cur == 0 { 128 } else { cur.trailing_zeros() };
        let remaining = last - cur + 1;
        let max_size = if remaining == 0 { 0 } else { remaining.ilog2() };
        let host_bits = max_align.min(max_size).min(128);
        let prefix_len = 128 - host_bits;
        let block_size = if host_bits < 128 {
            1u128 << host_bits
        } else {
            u128::MAX
        };
        let addr = u128_to_ipv6(cur);
        out.push(IpPrefix {
            addr: IpAddr::V6(addr),
            bits: prefix_len as u8,
        });
        if block_size == 0 {
            break;
        }
        let next = cur.saturating_add(block_size);
        if next <= cur {
            break;
        }
        cur = next;
    }
    out
}

fn ipv6_to_u128(a: Ipv6Addr) -> u128 {
    u128::from_be_bytes(a.octets())
}

fn u128_to_ipv6(v: u128) -> Ipv6Addr {
    Ipv6Addr::from(v.to_be_bytes())
}

/// Parse a CIDR string like "192.168.0.0/16" into an [`IpPrefix`].
/// Returns `None` if the string is not a valid CIDR or contains non-network
/// bits.
pub fn parse_cidr(s: &str) -> Result<IpPrefix, ParseError> {
    let (ip_str, bits_str) = s.split_once('/').ok_or(ParseError::InvalidCidr(s.into()))?;
    let ip: IpAddr = ip_str
        .parse()
        .map_err(|_| ParseError::InvalidIp(ip_str.into()))?;
    let bits: u8 = bits_str
        .parse()
        .map_err(|_| ParseError::InvalidPrefixLen(bits_str.into()))?;
    let max_bits = if ip.is_ipv4() { 32 } else { 128 };
    if bits > max_bits {
        return Err(ParseError::InvalidPrefixLen(bits_str.into()));
    }
    let prefix = IpPrefix { addr: ip, bits };
    // Check for non-network bits: mask the address and compare.
    if !is_masked(&prefix) {
        return Err(ParseError::NonNetworkBits(s.into()));
    }
    Ok(prefix)
}

/// Whether the prefix's address is already masked to the prefix length.
fn is_masked(p: &IpPrefix) -> bool {
    match p.addr {
        IpAddr::V4(a) => {
            let mask = if p.bits == 0 {
                0u32
            } else {
                u32::MAX << (32 - p.bits)
            };
            (u32::from_be_bytes(a.octets()) & mask) == u32::from_be_bytes(a.octets())
        }
        IpAddr::V6(a) => {
            let mask = if p.bits == 0 {
                0u128
            } else {
                u128::MAX << (128 - p.bits)
            };
            (ipv6_to_u128(a) & mask) == ipv6_to_u128(a)
        }
    }
}

/// Make a prefix with the address masked to the prefix length.
pub fn masked_prefix(addr: IpAddr, bits: u8) -> IpPrefix {
    match addr {
        IpAddr::V4(a) => {
            let mask = if bits == 0 {
                0u32
            } else {
                u32::MAX << (32 - bits)
            };
            IpPrefix {
                addr: IpAddr::V4(Ipv4Addr::from(
                    (u32::from_be_bytes(a.octets()) & mask).to_be_bytes(),
                )),
                bits,
            }
        }
        IpAddr::V6(a) => {
            let mask = if bits == 0 {
                0u128
            } else {
                u128::MAX << (128 - bits)
            };
            IpPrefix {
                addr: IpAddr::V6(u128_to_ipv6(ipv6_to_u128(a) & mask)),
                bits,
            }
        }
    }
}

/// Create a host prefix (single address): /32 for IPv4, /128 for IPv6.
pub fn host_prefix(addr: IpAddr) -> IpPrefix {
    let bits = if addr.is_ipv4() { 32 } else { 128 };
    IpPrefix { addr, bits }
}

/// The wildcard prefixes: 0.0.0.0/0 and ::/0.
pub fn wildcard_prefixes() -> Vec<IpPrefix> {
    vec![
        IpPrefix {
            addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            bits: 0,
        },
        IpPrefix {
            addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            bits: 0,
        },
    ]
}

/// Errors from CIDR/range parsing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("invalid CIDR: {0}")]
    InvalidCidr(String),
    #[error("invalid IP address: {0}")]
    InvalidIp(String),
    #[error("invalid prefix length: {0}")]
    InvalidPrefixLen(String),
    #[error("CIDR contains non-network bits: {0}")]
    NonNetworkBits(String),
    #[error("invalid IP range: {0}")]
    InvalidRange(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_prefix_contains() {
        let p = IpPrefix {
            addr: IpAddr::V4("192.168.0.0".parse().unwrap()),
            bits: 16,
        };
        assert!(p.contains("192.168.1.1".parse().unwrap()));
        assert!(p.contains("192.168.255.255".parse().unwrap()));
        assert!(!p.contains("192.169.0.0".parse().unwrap()));
        assert!(!p.contains("10.0.0.0".parse().unwrap()));
    }

    #[test]
    fn v6_prefix_contains() {
        let p = IpPrefix {
            addr: IpAddr::V6("2001::".parse().unwrap()),
            bits: 16,
        };
        assert!(p.contains("2001:db8::1".parse().unwrap()));
        assert!(!p.contains("2002::1".parse().unwrap()));
    }

    #[test]
    fn range_to_prefixes_v4_simple() {
        let start: Ipv4Addr = "1.0.0.0".parse().unwrap();
        let end: Ipv4Addr = "1.255.255.255".parse().unwrap();
        let pfxs = range_to_prefixes_v4(start, end);
        assert_eq!(pfxs.len(), 1);
        assert_eq!(pfxs[0].bits, 8);
        assert_eq!(pfxs[0].addr, IpAddr::V4("1.0.0.0".parse().unwrap()));
    }

    #[test]
    fn range_to_prefixes_v4_multi() {
        let start: Ipv4Addr = "1.0.0.0".parse().unwrap();
        let end: Ipv4Addr = "2.1.2.3".parse().unwrap();
        let pfxs = range_to_prefixes_v4(start, end);
        assert_eq!(pfxs.len(), 4);
        assert_eq!(pfxs[0].bits, 8);
        assert_eq!(pfxs[1].bits, 16);
        assert_eq!(pfxs[2].bits, 23);
        assert_eq!(pfxs[3].bits, 30);
    }

    #[test]
    fn parse_cidr_ok() {
        let p = parse_cidr("192.168.0.0/16").unwrap();
        assert_eq!(p.bits, 16);
    }

    #[test]
    fn parse_cidr_non_network_bits() {
        let err = parse_cidr("8.8.8.8/24").unwrap_err();
        assert!(matches!(err, ParseError::NonNetworkBits(_)));
    }
}
