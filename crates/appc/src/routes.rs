//! Route helpers: Prefix type, address comparison, set difference.
//!
//! Ports the helper functions from Go's `appc/appconnector.go`:
//! `routesWithout`, `compareAddr`, and the `netip.Prefix`/`netip.Addr`
//! operations used throughout the AppConnector.

use std::net::IpAddr;

/// An IP prefix (CIDR), matching Go's `netip.Prefix`.
///
/// Stores the network address and prefix length. Used for route
/// advertisement and containment checks.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Prefix {
    /// Network address.
    pub addr: IpAddr,
    /// Prefix length in bits (0–32 for IPv4, 0–128 for IPv6).
    pub bits: u8,
}

impl Default for Prefix {
    fn default() -> Self {
        Self {
            addr: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            bits: 0,
        }
    }
}

impl Prefix {
    /// Create a prefix from an address and bit length.
    pub fn new(addr: IpAddr, bits: u8) -> Self {
        Self { addr, bits }
    }

    /// Create a single-IP prefix (/32 for IPv4, /128 for IPv6).
    pub fn from_addr(addr: IpAddr) -> Self {
        let bits = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        Self { addr, bits }
    }

    /// The network address.
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// The prefix length.
    pub fn bits(&self) -> u8 {
        self.bits
    }

    /// Whether this is a single-IP prefix (/32 or /128).
    pub fn is_single_ip(&self) -> bool {
        match self.addr {
            IpAddr::V4(_) => self.bits == 32,
            IpAddr::V6(_) => self.bits == 128,
        }
    }

    /// Whether `ip` falls within this prefix.
    pub fn contains(&self, ip: IpAddr) -> bool {
        cidr_match(ip, self.addr, self.bits)
    }

    /// Parse a CIDR string like `"192.0.2.0/24"`.
    pub fn parse(s: &str) -> Option<Self> {
        let (addr_str, bits_str) = s.split_once('/')?;
        let addr: IpAddr = addr_str.parse().ok()?;
        let bits: u8 = bits_str.parse().ok()?;
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if bits > max {
            return None;
        }
        Some(Self { addr, bits })
    }
}

impl std::fmt::Display for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.bits)
    }
}

impl PartialOrd for Prefix {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Prefix {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match compare_addr(&self.addr, &other.addr) {
            std::cmp::Ordering::Equal => self.bits.cmp(&other.bits),
            ord => ord,
        }
    }
}

/// Compare two IP addresses, matching Go's `netip.Addr.Compare`.
pub fn compare_addr(a: &IpAddr, b: &IpAddr) -> std::cmp::Ordering {
    match (a, b) {
        (IpAddr::V4(a4), IpAddr::V4(b4)) => {
            let au = u32::from(*a4);
            let bu = u32::from(*b4);
            au.cmp(&bu)
        }
        (IpAddr::V6(a6), IpAddr::V6(b6)) => {
            let au = u128::from(*a6);
            let bu = u128::from(*b6);
            au.cmp(&bu)
        }
        (IpAddr::V4(_), IpAddr::V6(_)) => std::cmp::Ordering::Less,
        (IpAddr::V6(_), IpAddr::V4(_)) => std::cmp::Ordering::Greater,
    }
}

/// Whether `ip` falls within `net`/`bits`. Only matches within the same
/// address family.
pub fn cidr_match(ip: IpAddr, net: IpAddr, bits: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            if bits > 32 {
                return false;
            }
            let mask = if bits == 0 {
                0u32
            } else {
                u32::MAX << (32 - bits)
            };
            (u32::from(ip) & mask) == (u32::from(net) & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            if bits > 128 {
                return false;
            }
            let mask = if bits == 0 {
                0u128
            } else {
                u128::MAX << (128 - bits)
            };
            (u128::from(ip) & mask) == (u128::from(net) & mask)
        }
        _ => false,
    }
}

/// Returns elements of `a` that are not in `b`, matching Go's
/// `routesWithout`.
pub fn routes_without(a: &[Prefix], b: &[Prefix]) -> Vec<Prefix> {
    let bset: std::collections::HashSet<Prefix> = b.iter().cloned().collect();
    a.iter().filter(|p| !bset.contains(p)).cloned().collect()
}

/// Check if `domain` has the given suffix, matching Go's
/// `dnsname.HasSuffix`. Both are lowercased and trailing dots stripped
/// before comparison. `domain` matches `suffix` if they are equal or
/// `domain` ends with `.<suffix>`.
pub fn has_suffix(domain: &str, suffix: &str) -> bool {
    let d = domain.trim_end_matches('.').to_lowercase();
    let s = suffix.trim_end_matches('.').to_lowercase();
    if d == s {
        return true;
    }
    d.ends_with(&format!(".{s}"))
}

use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_parse_and_display() {
        let p = Prefix::parse("192.0.2.0/24").unwrap();
        assert_eq!(p.addr(), IpAddr::V4("192.0.2.0".parse().unwrap()));
        assert_eq!(p.bits(), 24);
        assert!(!p.is_single_ip());
        assert_eq!(p.to_string(), "192.0.2.0/24");
    }

    #[test]
    fn prefix_from_addr() {
        let p = Prefix::from_addr(IpAddr::V4("192.0.2.1".parse().unwrap()));
        assert_eq!(p.bits(), 32);
        assert!(p.is_single_ip());

        let p6 = Prefix::from_addr(IpAddr::V6("2001:db8::1".parse().unwrap()));
        assert_eq!(p6.bits(), 128);
        assert!(p6.is_single_ip());
    }

    #[test]
    fn prefix_contains() {
        let p = Prefix::parse("192.0.2.0/24").unwrap();
        assert!(p.contains(IpAddr::V4("192.0.2.1".parse().unwrap())));
        assert!(p.contains(IpAddr::V4("192.0.2.255".parse().unwrap())));
        assert!(!p.contains(IpAddr::V4("192.0.3.1".parse().unwrap())));
        assert!(!p.contains(IpAddr::V6("2001:db8::1".parse().unwrap())));
    }

    #[test]
    fn routes_without_basic() {
        let a = prefixes(&["1.1.1.1/32", "1.1.1.2/32"]);
        let b = prefixes(&["1.1.1.1/32"]);
        let result = routes_without(&a, &b);
        assert_eq!(result, vec![Prefix::parse("1.1.1.2/32").unwrap()]);
    }

    #[test]
    fn routes_without_empty_b() {
        let a = prefixes(&["1.1.1.1/32", "1.1.1.2/32"]);
        let result = routes_without(&a, &[]);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn routes_without_empty_a() {
        let result = routes_without(&[], &prefixes(&["1.1.1.1/32"]));
        assert!(result.is_empty());
    }

    #[test]
    fn routes_without_no_overlap() {
        let a = prefixes(&["1.1.1.1/32", "1.1.1.2/32"]);
        let b = prefixes(&["1.1.1.3/32", "1.1.1.4/32"]);
        let result = routes_without(&a, &b);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn routes_without_a_has_more() {
        let a = prefixes(&["1.1.1.1/32", "1.1.1.2/32", "1.1.1.3/32", "1.1.1.4/32"]);
        let b = prefixes(&["1.1.1.1/32", "1.1.1.3/32"]);
        let result = routes_without(&a, &b);
        assert_eq!(
            result,
            vec![
                Prefix::parse("1.1.1.2/32").unwrap(),
                Prefix::parse("1.1.1.4/32").unwrap(),
            ]
        );
    }

    #[test]
    fn routes_without_a_has_fewer() {
        let a = prefixes(&["1.1.1.1/32", "1.1.1.2/32"]);
        let b = prefixes(&["1.1.1.1/32", "1.1.1.2/32", "1.1.1.3/32", "1.1.1.4/32"]);
        let result = routes_without(&a, &b);
        assert!(result.is_empty());
    }

    #[test]
    fn has_suffix_checks() {
        assert!(has_suffix("foo.example.com", "example.com"));
        assert!(has_suffix("example.com", "example.com"));
        assert!(!has_suffix("notexample.com", "example.com"));
        assert!(has_suffix("foo.example.com.", "example.com."));
        assert!(has_suffix("FOO.EXAMPLE.COM", "example.com"));
    }

    #[test]
    fn compare_addr_ordering() {
        let a = IpAddr::V4("10.0.0.1".parse().unwrap());
        let b = IpAddr::V4("10.0.0.2".parse().unwrap());
        assert_eq!(compare_addr(&a, &b), std::cmp::Ordering::Less);
        assert_eq!(compare_addr(&b, &a), std::cmp::Ordering::Greater);
        assert_eq!(compare_addr(&a, &a), std::cmp::Ordering::Equal);

        let v4 = IpAddr::V4("10.0.0.1".parse().unwrap());
        let v6 = IpAddr::V6("::1".parse().unwrap());
        assert_eq!(compare_addr(&v4, &v6), std::cmp::Ordering::Less);
        assert_eq!(compare_addr(&v6, &v4), std::cmp::Ordering::Greater);
    }

    #[test]
    fn prefix_ord() {
        let mut ps = [
            Prefix::parse("10.0.0.3/32").unwrap(),
            Prefix::parse("10.0.0.1/32").unwrap(),
            Prefix::parse("10.0.0.2/32").unwrap(),
        ];
        ps.sort();
        assert_eq!(ps[0].addr(), "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(ps[1].addr(), "10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(ps[2].addr(), "10.0.0.3".parse::<IpAddr>().unwrap());
    }

    fn prefixes(ss: &[&str]) -> Vec<Prefix> {
        ss.iter().map(|s| Prefix::parse(s).unwrap()).collect()
    }
}
