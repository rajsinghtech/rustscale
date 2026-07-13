//! Tailscale IP address predicates and ranges.
//!
//! Ports Go's `net/tsaddr/tsaddr.go`. Provides the canonical definitions of
//! all Tailscale-specialised IP ranges (CGNAT, ULA, 4via6, 4to6, ephemeral,
//! service VIPs) and predicate functions over them. Other crates should call
//! these functions instead of duplicating the byte-comparison logic.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// An IP address with a prefix length (CIDR mask bit count).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IpPrefix {
    pub ip: IpAddr,
    pub bits: u8,
}

impl IpPrefix {
    /// Whether `ip` falls within this prefix. Only matches within the same
    /// address family.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.ip, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => v4_contains(net, addr, self.bits),
            (IpAddr::V6(net), IpAddr::V6(addr)) => v6_contains(net, addr, self.bits),
            _ => false,
        }
    }

    /// Parse a `ip/bits` CIDR string (e.g. `"100.64.0.0/10"`).
    pub fn parse(s: &str) -> Option<IpPrefix> {
        let (ip_part, bits_part) = s.split_once('/')?;
        let ip: IpAddr = ip_part.parse().ok()?;
        let bits: u8 = bits_part.parse().ok()?;
        Some(IpPrefix { ip, bits })
    }
}

impl std::fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.ip, self.bits)
    }
}

// ---------------------------------------------------------------------------
// Range constants
// ---------------------------------------------------------------------------

/// ChromeOS VM range: `100.115.92.0/23`.
pub const fn chrome_os_vm_range() -> IpPrefix {
    IpPrefix {
        ip: IpAddr::V4(Ipv4Addr::new(100, 115, 92, 0)),
        bits: 23,
    }
}

/// Tailscale CGNAT range: `100.64.0.0/10`.
pub const fn cgnat_range() -> IpPrefix {
    IpPrefix {
        ip: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)),
        bits: 10,
    }
}

/// Tailscale IPv4 service VIP: `100.100.100.100`.
pub const fn tailscale_service_ipv4() -> Ipv4Addr {
    Ipv4Addr::new(100, 100, 100, 100)
}

/// Tailscale IPv6 service VIP: `fd7a:115c:a1e0::53`.
pub const fn tailscale_service_ipv6_addr() -> Ipv6Addr {
    Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0x53)
}

/// Tailscale service IP as `IpAddr` (`100.100.100.100`).
pub const fn tailscale_service_ip() -> IpAddr {
    IpAddr::V4(tailscale_service_ipv4())
}

/// Tailscale IPv6 service IP as `IpAddr` (`fd7a:115c:a1e0::53`).
pub const fn tailscale_service_ipv6() -> IpAddr {
    IpAddr::V6(tailscale_service_ipv6_addr())
}

/// Tailscale ULA range: `fd7a:115c:a1e0::/48`.
pub const fn tailscale_ula_range() -> IpPrefix {
    IpPrefix {
        ip: IpAddr::V6(Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0)),
        bits: 48,
    }
}

/// Tailscale 4via6 range: `fd7a:115c:a1e0:b1a::/64`.
pub const fn tailscale_via_range() -> IpPrefix {
    IpPrefix {
        ip: IpAddr::V6(Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0x0b1a, 0, 0, 0, 0)),
        bits: 64,
    }
}

/// Tailscale 4to6 range: `fd7a:115c:a1e0:ab12:4843:cd96:6200::/104`.
pub const fn tailscale_4to6_range() -> IpPrefix {
    IpPrefix {
        ip: IpAddr::V6(Ipv6Addr::new(
            0xfd7a, 0x115c, 0xa1e0, 0xab12, 0x4843, 0xcd96, 0x6200, 0,
        )),
        bits: 104,
    }
}

/// Tailscale ephemeral IPv6 range: `fd7a:115c:a1e0:efe3::/64`.
pub const fn tailscale_ephemeral6_range() -> IpPrefix {
    IpPrefix {
        ip: IpAddr::V6(Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0xefe3, 0, 0, 0, 0)),
        bits: 64,
    }
}

/// First address of the 4to6 range (the placeholder).
pub const fn tailscale_4to6_placeholder() -> IpAddr {
    tailscale_4to6_range().ip
}

/// All IPv4 space: `0.0.0.0/0`.
pub const fn all_ipv4() -> IpPrefix {
    IpPrefix {
        ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        bits: 0,
    }
}

/// All IPv6 space: `::/0`.
pub const fn all_ipv6() -> IpPrefix {
    IpPrefix {
        ip: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        bits: 0,
    }
}

/// `[0.0.0.0/0, ::/0]` — the pair of exit-route prefixes.
pub fn exit_routes() -> Vec<IpPrefix> {
    vec![all_ipv4(), all_ipv6()]
}

// ---------------------------------------------------------------------------
// IP predicates
// ---------------------------------------------------------------------------

/// Whether `ip` is a Tailscale IP: IPv4 in CGNAT (excluding ChromeOS VM range)
/// or IPv6 in the Tailscale ULA range.
pub fn is_tailscale_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(_) => is_tailscale_ipv4(ip),
        IpAddr::V6(_) => tailscale_ula_range().contains(ip),
    }
}

/// Whether `ip` is an IPv4 address in the CGNAT range but NOT in the ChromeOS
/// VM subrange.
pub fn is_tailscale_ipv4(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V4(_)) && cgnat_range().contains(ip) && !chrome_os_vm_range().contains(ip)
}

// ---------------------------------------------------------------------------
// 4to6 / 6to4 mapping
// ---------------------------------------------------------------------------

/// Map an IPv4 address to an IPv6 address in the Tailscale 4to6 range.
///
/// Copies octets 2–4 of the v4 address into bytes 13–15 of the 4to6 range
/// base address.
pub fn tailscale_4to6(ipv4: Ipv4Addr) -> Ipv6Addr {
    let base = match tailscale_4to6_range().ip {
        IpAddr::V6(v6) => v6.octets(),
        _ => unreachable!(),
    };
    let mut ret = base;
    let v4_octets = ipv4.octets();
    ret[13..16].copy_from_slice(&v4_octets[1..4]);
    Ipv6Addr::from(ret)
}

/// Reverse the 4to6 mapping: extract the IPv4 address from an IPv6 address
/// in the 4to6 range. Returns `None` if the IPv6 address is not in range.
pub fn tailscale_6to4(ipv6: Ipv6Addr) -> Option<Ipv4Addr> {
    if !tailscale_4to6_range().contains(IpAddr::V6(ipv6)) {
        return None;
    }
    let o = ipv6.octets();
    Some(Ipv4Addr::new(100, o[13], o[14], o[15]))
}

// ---------------------------------------------------------------------------
// Prefix-list helpers
// ---------------------------------------------------------------------------

/// Linear scan: does any prefix in `prefixes` contain `ip`?
pub fn prefixes_contains_ip(prefixes: &[IpPrefix], ip: IpAddr) -> bool {
    prefixes.iter().any(|p| p.contains(ip))
}

/// Whether the prefix is IPv4.
pub fn prefix_is4(p: &IpPrefix) -> bool {
    matches!(p.ip, IpAddr::V4(_))
}

/// Whether the prefix is IPv6.
pub fn prefix_is6(p: &IpPrefix) -> bool {
    matches!(p.ip, IpAddr::V6(_))
}

/// Whether `prefixes` contains both the IPv4 and IPv6 default routes (`/0`).
pub fn contains_exit_routes(prefixes: &[IpPrefix]) -> bool {
    prefixes.iter().any(|p| *p == all_ipv4()) && prefixes.iter().any(|p| *p == all_ipv6())
}

/// Whether `prefixes` contains any exit route (either IPv4 or IPv6 `/0`).
pub fn contains_exit_route(prefixes: &[IpPrefix]) -> bool {
    prefixes.iter().any(is_exit_route)
}

/// Strip all exit routes (both v4 and v6 `/0`) from `prefixes`.
pub fn without_exit_routes(prefixes: &[IpPrefix]) -> Vec<IpPrefix> {
    prefixes
        .iter()
        .filter(|p| !is_exit_route(p))
        .copied()
        .collect()
}

/// Strip any exit route (any `/0`) from `prefixes`.
pub fn without_exit_route(prefixes: &[IpPrefix]) -> Vec<IpPrefix> {
    prefixes
        .iter()
        .filter(|p| !is_exit_route(p))
        .copied()
        .collect()
}

/// Whether `p` is an exit route (`0.0.0.0/0` or `::/0`).
pub fn is_exit_route(p: &IpPrefix) -> bool {
    *p == all_ipv4() || *p == all_ipv6()
}

/// Sort `prefixes` in-place by IP address bytes then by prefix bits, ascending.
/// IPv4 prefixes sort before IPv6 prefixes.
pub fn sort_prefixes(p: &mut [IpPrefix]) {
    p.sort_by(|a, b| {
        let cmp = compare_ip(a.ip, b.ip);
        if cmp != std::cmp::Ordering::Equal {
            return cmp;
        }
        a.bits.cmp(&b.bits)
    });
}

/// Return a filtered copy of `in_` keeping only prefixes where `f` returns true.
pub fn filter_prefixes_copy(in_: &[IpPrefix], f: impl Fn(&IpPrefix) -> bool) -> Vec<IpPrefix> {
    in_.iter().filter(|p| f(p)).copied().collect()
}

// ---------------------------------------------------------------------------
// 4via6 helpers
// ---------------------------------------------------------------------------

/// Whether `p` is a 4via6 prefix — an IPv6 address in the via range with at
/// least 96 bits of prefix (64 via + 32 site-id).
pub fn is_via_prefix(p: &IpPrefix) -> bool {
    prefix_is6(p) && tailscale_via_range().contains(p.ip) && p.bits >= 96
}

/// Extract the embedded IPv4 address from a 4via6 IPv6 address. If `ip` is not
/// in the via range, return it unchanged.
pub fn unmap_via(ip: IpAddr) -> IpAddr {
    if let IpAddr::V6(v6) = ip {
        if tailscale_via_range().contains(ip) {
            let o = v6.octets();
            return IpAddr::V4(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
        }
    }
    ip
}

/// Construct a 4via6 prefix: embed `site_id` and the IPv4 prefix address into
/// the via range. Returns an error if `v4` is not an IPv4 prefix.
pub fn map_via(site_id: u32, v4: IpPrefix) -> Result<IpPrefix, String> {
    let v4_addr = match v4.ip {
        IpAddr::V4(a) => a,
        _ => return Err("map_via: prefix must be IPv4".into()),
    };
    let via = tailscale_via_range();
    let mut a = match via.ip {
        IpAddr::V6(v6) => v6.octets(),
        _ => unreachable!(),
    };
    a[8..12].copy_from_slice(&site_id.to_be_bytes());
    a[12..16].copy_from_slice(&v4_addr.octets());
    let bits = v4.bits + 64 + 32;
    Ok(IpPrefix {
        ip: IpAddr::V6(Ipv6Addr::from(a)),
        bits,
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

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

fn compare_ip(a: IpAddr, b: IpAddr) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => a.octets().cmp(&b.octets()),
        (IpAddr::V6(a), IpAddr::V6(b)) => a.octets().cmp(&b.octets()),
        (IpAddr::V4(_), IpAddr::V6(_)) => Ordering::Less,
        (IpAddr::V6(_), IpAddr::V4(_)) => Ordering::Greater,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cgnat_range() {
        assert!(cgnat_range().contains(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(cgnat_range().contains(IpAddr::V4(Ipv4Addr::new(100, 127, 255, 255))));
        assert!(!cgnat_range().contains(IpAddr::V4(Ipv4Addr::new(100, 63, 255, 255))));
        assert!(!cgnat_range().contains(IpAddr::V4(Ipv4Addr::new(100, 128, 0, 1))));
    }

    #[test]
    fn test_chrome_os_vm_range() {
        assert!(chrome_os_vm_range().contains(IpAddr::V4(Ipv4Addr::new(100, 115, 92, 0))));
        assert!(chrome_os_vm_range().contains(IpAddr::V4(Ipv4Addr::new(100, 115, 93, 255))));
        assert!(!chrome_os_vm_range().contains(IpAddr::V4(Ipv4Addr::new(100, 115, 91, 255))));
        assert!(!chrome_os_vm_range().contains(IpAddr::V4(Ipv4Addr::new(100, 115, 94, 0))));
    }

    #[test]
    fn test_is_tailscale_ip() {
        assert!(is_tailscale_ip(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(is_tailscale_ip(IpAddr::V4(Ipv4Addr::new(
            100, 100, 100, 100
        ))));
        assert!(is_tailscale_ip(IpAddr::V6(
            "fd7a:115c:a1e0::1".parse().unwrap()
        )));
        // ChromeOS VM range is excluded
        assert!(!is_tailscale_ip(IpAddr::V4(Ipv4Addr::new(100, 115, 92, 5))));
        // Non-tailscale
        assert!(!is_tailscale_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_tailscale_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!is_tailscale_ip(IpAddr::V6("2001:db8::1".parse().unwrap())));
    }

    #[test]
    fn test_is_tailscale_ipv4_excludes_chromeos() {
        assert!(is_tailscale_ipv4(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(!is_tailscale_ipv4(IpAddr::V4(Ipv4Addr::new(
            100, 115, 92, 5
        ))));
        assert!(!is_tailscale_ipv4(IpAddr::V6(
            "fd7a:115c:a1e0::1".parse().unwrap()
        )));
    }

    #[test]
    fn test_ula_range() {
        assert!(tailscale_ula_range().contains(IpAddr::V6("fd7a:115c:a1e0::1".parse().unwrap())));
        assert!(
            tailscale_ula_range().contains(IpAddr::V6("fd7a:115c:a1e0:ffff::1".parse().unwrap()))
        );
        assert!(!tailscale_ula_range().contains(IpAddr::V6("fd7a:115c:a1e1::1".parse().unwrap())));
    }

    #[test]
    fn test_service_ips() {
        assert_eq!(
            tailscale_service_ip(),
            IpAddr::V4(Ipv4Addr::new(100, 100, 100, 100))
        );
        assert_eq!(
            tailscale_service_ipv6(),
            IpAddr::V6("fd7a:115c:a1e0::53".parse().unwrap())
        );
    }

    #[test]
    fn test_4to6_roundtrip() {
        let v4 = Ipv4Addr::new(100, 64, 0, 5);
        let v6 = tailscale_4to6(v4);
        assert_eq!(tailscale_6to4(v6), Some(v4));

        let v4 = Ipv4Addr::new(100, 100, 100, 100);
        let v6 = tailscale_4to6(v4);
        assert_eq!(tailscale_6to4(v6), Some(v4));

        // Not in 4to6 range
        let other: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(tailscale_6to4(other), None);
    }

    #[test]
    fn test_4to6_specific_bytes() {
        // 100.64.0.5 → octets [100, 64, 0, 5] → copy [64, 0, 5] at [13..16]
        let v6 = tailscale_4to6(Ipv4Addr::new(100, 64, 0, 5));
        let o = v6.octets();
        assert_eq!(o[0..8], [0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0xab, 0x12]);
        assert_eq!(o[8..12], [0x48, 0x43, 0xcd, 0x96]);
        assert_eq!(o[12], 0x62);
        assert_eq!(o[13..16], [64, 0, 5]);
    }

    #[test]
    fn test_exit_routes() {
        assert!(is_exit_route(&all_ipv4()));
        assert!(is_exit_route(&all_ipv6()));
        assert!(!is_exit_route(&cgnat_range()));

        let prefixes = vec![all_ipv4(), all_ipv6(), cgnat_range()];
        assert!(contains_exit_route(&prefixes));
        assert!(contains_exit_routes(&prefixes));

        let v4_only = vec![all_ipv4(), cgnat_range()];
        assert!(contains_exit_route(&v4_only));
        assert!(!contains_exit_routes(&v4_only));
    }

    #[test]
    fn test_without_exit_routes() {
        let prefixes = vec![all_ipv4(), all_ipv6(), cgnat_range()];
        let filtered = without_exit_routes(&prefixes);
        assert_eq!(filtered, vec![cgnat_range()]);
    }

    #[test]
    fn test_sort_prefixes() {
        let mut prefixes = vec![
            IpPrefix::parse("10.0.0.0/8").unwrap(),
            IpPrefix::parse("100.64.0.0/10").unwrap(),
            IpPrefix::parse("10.0.0.0/16").unwrap(),
        ];
        sort_prefixes(&mut prefixes);
        assert_eq!(prefixes[0], IpPrefix::parse("10.0.0.0/8").unwrap());
        assert_eq!(prefixes[1], IpPrefix::parse("10.0.0.0/16").unwrap());
        assert_eq!(prefixes[2], IpPrefix::parse("100.64.0.0/10").unwrap());
    }

    #[test]
    fn test_prefix_parse_and_display() {
        let p = IpPrefix::parse("100.64.0.0/10").unwrap();
        assert_eq!(p.ip, IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)));
        assert_eq!(p.bits, 10);
        assert_eq!(p.to_string(), "100.64.0.0/10");

        let p6 = IpPrefix::parse("fd7a:115c:a1e0::/48").unwrap();
        assert_eq!(p6.bits, 48);
        assert_eq!(p6.to_string(), "fd7a:115c:a1e0::/48");

        assert!(IpPrefix::parse("not-a-prefix").is_none());
        assert!(IpPrefix::parse("100.64.0.0").is_none());
    }

    #[test]
    fn test_map_via_and_unmap() {
        let v4 = IpPrefix::parse("10.0.0.0/24").unwrap();
        let via = map_via(42, v4).unwrap();
        assert!(is_via_prefix(&via));
        assert_eq!(via.bits, 24 + 64 + 32);

        // unmap_via should extract the v4 address
        let unmapped = unmap_via(via.ip);
        assert_eq!(unmapped, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));

        // Non-via IP passes through
        let plain: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(unmap_via(plain), plain);
    }

    #[test]
    fn test_map_via_rejects_ipv6() {
        let v6 = IpPrefix::parse("fd7a:115c:a1e0::/48").unwrap();
        assert!(map_via(1, v6).is_err());
    }

    #[test]
    fn test_prefixes_contains_ip() {
        let prefixes = vec![cgnat_range(), tailscale_ula_range()];
        assert!(prefixes_contains_ip(
            &prefixes,
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))
        ));
        assert!(prefixes_contains_ip(
            &prefixes,
            IpAddr::V6("fd7a:115c:a1e0::1".parse().unwrap())
        ));
        assert!(!prefixes_contains_ip(
            &prefixes,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
        ));
    }

    #[test]
    fn test_filter_prefixes_copy() {
        let prefixes = vec![all_ipv4(), cgnat_range(), all_ipv6()];
        let filtered = filter_prefixes_copy(&prefixes, |p| !is_exit_route(p));
        assert_eq!(filtered, vec![cgnat_range()]);
    }

    #[test]
    fn test_4to6_placeholder() {
        let placeholder = tailscale_4to6_placeholder();
        assert!(tailscale_4to6_range().contains(placeholder));
    }

    #[test]
    fn test_via_range() {
        let via = tailscale_via_range();
        assert!(via.contains(IpAddr::V6("fd7a:115c:a1e0:b1a::1".parse().unwrap())));
        assert!(!via.contains(IpAddr::V6("fd7a:115c:a1e0:b1b::1".parse().unwrap())));
    }

    #[test]
    fn test_ephemeral6_range() {
        let ephemeral = tailscale_ephemeral6_range();
        assert!(ephemeral.contains(IpAddr::V6("fd7a:115c:a1e0:efe3::1".parse().unwrap())));
        assert!(!ephemeral.contains(IpAddr::V6("fd7a:115c:a1e0:efe4::1".parse().unwrap())));
    }
}
