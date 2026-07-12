//! Pure parsing logic for BSD/macOS route messages.
//!
//! This module is platform-independent: it operates on raw byte slices and
//! can be unit-tested on any platform. The macOS-specific sysctl fetch lives
//! in [`crate::darwin`]; this module only handles the binary parsing of
//! `rt_msghdr`/`rt_msghdr2` records and their trailing sockaddrs.
//!
//! Ports the Go `route.ParseRIB` + `routetable.routeEntryFromMsg` logic.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{RouteDestination, RouteEntry};

// ---------------------------------------------------------------------------
// Constants — BSD/macOS route message constants.
//
// Defined here (rather than using `libc::` constants) so the parser is
// testable on non-BSD platforms. Values match macOS (xnu) kernel headers.
// ---------------------------------------------------------------------------

// Address families (macOS values).
const AF_INET: u8 = 2;
const AF_INET6: u8 = 30;
const AF_LINK: u8 = 18;

// Route message types.
const RTM_GET: u8 = 0x4;
const RTM_GET2: u8 = 0x14;

// RTA bitmask values (which sockaddrs are present in the message).
const RTA_DST: i32 = 0x1;
const RTA_GATEWAY: i32 = 0x2;
const RTA_NETMASK: i32 = 0x4;
const RTA_GENMASK: i32 = 0x8;
const RTA_IFP: i32 = 0x10;
const RTA_IFA: i32 = 0x20;
const RTA_AUTHOR: i32 = 0x40;
const RTA_BRD: i32 = 0x80;

// RTAX indices (order of sockaddrs after the header).
const RTAX_DST: usize = 0;
const RTAX_GATEWAY: usize = 1;
const RTAX_NETMASK: usize = 2;
#[allow(dead_code)]
const RTAX_GENMASK: usize = 3;
#[allow(dead_code)]
const RTAX_IFP: usize = 4;
#[allow(dead_code)]
const RTAX_IFA: usize = 5;
#[allow(dead_code)]
const RTAX_AUTHOR: usize = 6;
#[allow(dead_code)]
const RTAX_BRD: usize = 7;
const RTAX_MAX: usize = 8;

// Route flags (BSD/macOS).
const RTF_UP: i32 = 0x1;
const RTF_GATEWAY: i32 = 0x2;
const RTF_HOST: i32 = 0x4;
const RTF_REJECT: i32 = 0x8;
const RTF_STATIC: i32 = 0x800;
const RTF_BLACKHOLE: i32 = 0x1000;
const RTF_CLONING: i32 = 0x100;
#[allow(dead_code)]
const RTF_XRESOLVE: i32 = 0x200;
const RTF_LLINFO: i32 = 0x400;
const RTF_PRCLONING: i32 = 0x10000;
const RTF_WASCLONED: i32 = 0x20000;
const RTF_LOCAL: i32 = 0x200000;
const RTF_BROADCAST: i32 = 0x400000;
const RTF_MULTICAST: i32 = 0x800000;
const RTF_IFSCOPE: i32 = 0x1000000;
const RTF_ROUTER: i32 = 0x10000000;
const RTF_GLOBAL: i32 = 0x40000000;

/// `sizeof(struct rt_msghdr)` on 64-bit macOS.
///
/// Both `rt_msghdr` and `rt_msghdr2` are 92 bytes on 64-bit Darwin:
/// 6 bytes (msglen+version+type+index) + 2 pad + 28 bytes of int fields +
/// 56 bytes (`rt_metrics`).
const RT_MSGHDR_SIZE: usize = 92;
const RT_MSGHDR2_SIZE: usize = 92;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// The type of a route.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RouteType {
    /// Unspecified.
    #[default]
    Unspecified,
    /// The destination is an address belonging to this system.
    Local,
    /// The destination is a "regular" unicast address.
    Unicast,
    /// The destination is a broadcast address.
    Broadcast,
    /// The destination is a multicast address.
    Multicast,
    /// The route is of some other valid type; see `raw_flags` for details.
    Other,
}

impl std::fmt::Display for RouteType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unspecified => write!(f, "unspecified"),
            Self::Local => write!(f, "local"),
            Self::Unicast => write!(f, "unicast"),
            Self::Broadcast => write!(f, "broadcast"),
            Self::Multicast => write!(f, "multicast"),
            Self::Other => write!(f, "other"),
        }
    }
}

/// A parsed sockaddr from a route message.
#[derive(Clone, Debug, PartialEq)]
enum ParsedSockaddr {
    Inet4(Ipv4Addr),
    Inet6 {
        addr: Ipv6Addr,
        zone_id: u32,
    },
    Link {
        index: u16,
        name: String,
        addr: Vec<u8>,
    },
    /// A zero-length sockaddr (`sa_len = 0`). On BSD, these represent
    /// "default" addresses (all zeros). For netmasks, this means /0.
    Default,
    Unknown,
}

// ---------------------------------------------------------------------------
// Sockaddr alignment
// ---------------------------------------------------------------------------

/// Align a sockaddr length to the kernel's alignment boundary.
///
/// On 64-bit macOS, the kernel aligns sockaddrs in `NET_RT_DUMP2` output
/// to 4-byte boundaries (not 8-byte as the `RT_ROUNDUP` macro suggests).
/// When `sa_len = 0`, the sockaddr occupies 4 bytes for most families
/// and 8 bytes for `AF_LINK`. This matches the Go `x/net/route` package's
/// `rsaAlignOf` behavior on Darwin.
fn sa_align(len: usize, family: u8) -> usize {
    if len == 0 {
        return if family == AF_LINK { 8 } else { 4 };
    }
    (len + 3) & !3
}

// ---------------------------------------------------------------------------
// Sockaddr parsing
// ---------------------------------------------------------------------------

/// Parse a single sockaddr from a byte slice.
///
/// `sa_family` is the second byte of the sockaddr. The actual bytes
/// available are `buf[..buf.len()]`, which may be larger than the
/// sockaddr's `sa_len` due to alignment padding.
///
/// On BSD/macOS, netmask sockaddrs often carry `sa_len = 0` and
/// `sa_family = AF_UNSPEC` (0). This represents a "default" address
/// (all zeros); for netmasks it means prefix length 0. When `sa_len`
/// is non-zero but `sa_family` is 0, we infer the family from `sa_len`:
/// 16 → IPv4, 28 → IPv6.
fn parse_sockaddr(buf: &[u8], sa_len: u8, sa_family: u8) -> ParsedSockaddr {
    if sa_len == 0 {
        return ParsedSockaddr::Default;
    }

    let family = if sa_family == 0 {
        match sa_len {
            16 => AF_INET,
            28 => AF_INET6,
            _ => sa_family,
        }
    } else {
        sa_family
    };

    match family {
        AF_INET if buf.len() >= 8 => {
            let ip = [buf[4], buf[5], buf[6], buf[7]];
            ParsedSockaddr::Inet4(Ipv4Addr::from(ip))
        }
        AF_INET6 if buf.len() >= 24 => {
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&buf[8..24]);
            let zone_id = if buf.len() >= 28 {
                u32::from_ne_bytes([buf[24], buf[25], buf[26], buf[27]])
            } else {
                0
            };
            ParsedSockaddr::Inet6 {
                addr: Ipv6Addr::from(ip),
                zone_id,
            }
        }
        AF_LINK => {
            if buf.len() < 8 {
                return ParsedSockaddr::Unknown;
            }
            let index = u16::from_ne_bytes([buf[2], buf[3]]);
            let nlen = buf[5] as usize;
            let alen = buf[6] as usize;
            let name = if nlen > 0 && 8 + nlen <= buf.len() {
                String::from_utf8_lossy(&buf[8..8 + nlen]).into_owned()
            } else {
                String::new()
            };
            let addr = if alen > 0 && 8 + nlen + alen <= buf.len() {
                buf[8 + nlen..8 + nlen + alen].to_vec()
            } else {
                Vec::new()
            };
            ParsedSockaddr::Link { index, name, addr }
        }
        _ => ParsedSockaddr::Unknown,
    }
}

// ---------------------------------------------------------------------------
// Sockaddr extraction from a route message
// ---------------------------------------------------------------------------

/// Extract all sockaddrs from a route message.
///
/// Returns an array indexed by RTAX_* constants. Each entry is `Some` if the
/// corresponding bit is set in `rtm_addrs` and the sockaddr could be parsed.
fn extract_sockaddrs(
    msg: &[u8],
    header_size: usize,
    rtm_addrs: i32,
) -> [Option<ParsedSockaddr>; RTAX_MAX] {
    let mut addrs: [Option<ParsedSockaddr>; RTAX_MAX] = [const { None }; RTAX_MAX];
    let mut pos = header_size;

    // RTA bitmask values in RTAX order.
    let rta_bits: [i32; RTAX_MAX] = [
        RTA_DST,
        RTA_GATEWAY,
        RTA_NETMASK,
        RTA_GENMASK,
        RTA_IFP,
        RTA_IFA,
        RTA_AUTHOR,
        RTA_BRD,
    ];

    for i in 0..RTAX_MAX {
        if (rtm_addrs & rta_bits[i]) == 0 {
            continue;
        }
        if pos + 2 > msg.len() {
            break;
        }
        let sa_len = msg[pos];
        let sa_family = msg[pos + 1];
        let actual_len = sa_len as usize;
        let aligned = sa_align(actual_len, sa_family);
        if pos + aligned > msg.len() {
            break;
        }
        let sa_bytes = &msg[pos..pos + aligned];
        addrs[i] = Some(parse_sockaddr(sa_bytes, sa_len, sa_family));
        pos += aligned;
    }

    addrs
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Count the number of leading 1-bits in an IPv4 netmask.
fn prefix_len_v4(mask: Ipv4Addr) -> u8 {
    let bits = u32::from(mask);
    if bits == 0 {
        0
    } else {
        (32 - bits.trailing_zeros()) as u8
    }
}

/// Count the number of leading 1-bits in an IPv6 netmask.
fn prefix_len_v6(mask: &Ipv6Addr) -> u8 {
    let octets = mask.octets();
    let mut len = 0u8;
    for &b in &octets {
        if b == 0xFF {
            len += 8;
        } else if b != 0 {
            len += 8 - b.trailing_zeros() as u8;
            break;
        } else {
            break;
        }
    }
    len
}

/// Determine the route type from the raw flags.
fn route_type_from_flags(flags: i32) -> RouteType {
    if (flags & RTF_LOCAL) != 0 {
        RouteType::Local
    } else if (flags & RTF_BROADCAST) != 0 {
        RouteType::Broadcast
    } else if (flags & RTF_MULTICAST) != 0 {
        RouteType::Multicast
    } else if (flags & RTF_HOST) == 0 {
        // From the manpage: "host entry (net otherwise)"
        RouteType::Unicast
    } else {
        RouteType::Other
    }
}

/// Build a sorted list of flag name strings from the raw flags.
///
/// Mirrors the `flags` map in Go's `routetable_darwin.go`.
fn flag_names(flags: i32) -> Vec<String> {
    let flag_defs: &[(i32, &str)] = &[
        (RTF_BLACKHOLE, "blackhole"),
        (RTF_BROADCAST, "broadcast"),
        (RTF_GATEWAY, "gateway"),
        (RTF_GLOBAL, "global"),
        (RTF_HOST, "host"),
        (RTF_IFSCOPE, "ifscope"),
        (RTF_LOCAL, "local"),
        (RTF_MULTICAST, "multicast"),
        (RTF_REJECT, "reject"),
        (RTF_ROUTER, "router"),
        (RTF_STATIC, "static"),
        (RTF_UP, "up"),
        (RTF_LLINFO, "{RTF_LLINFO}"),
        (RTF_PRCLONING, "{RTF_PRCLONING}"),
        (RTF_CLONING, "{RTF_CLONING}"),
    ];

    let mut names: Vec<String> = flag_defs
        .iter()
        .filter(|(bit, _)| (flags & bit) == *bit)
        .map(|(_, name)| (*name).to_string())
        .collect();
    names.sort();
    names
}

/// Format a MAC address as a colon-separated hex string.
fn format_mac(addr: &[u8]) -> String {
    addr.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

// ---------------------------------------------------------------------------
// Route entry construction from a raw message
// ---------------------------------------------------------------------------

/// Configuration for parsing — mirrors the platform-specific constants.
#[derive(Clone, Copy)]
pub(crate) struct ParseConfig {
    /// The expected message type (`RTM_GET2` on macOS, `RTM_GET` on FreeBSD/OpenBSD).
    pub expected_type: u8,
    /// Flags that cause a message to be skipped (`RTF_WASCLONED` on macOS, 0 on others).
    pub skip_flags: i32,
}

/// Parse a single route message (header + trailing sockaddrs) into a
/// `RouteEntry`.
///
/// Returns `Ok(Some(entry))` if the message should be included, `Ok(None)`
/// if it should be skipped (bad version, wrong type, skip flags, no
/// addresses), or `Err` on a parse error.
///
/// `iface_name_by_index` resolves an interface index to a name (e.g. via
/// `if_indextoname`). It receives the index and returns the name if known.
pub(crate) fn parse_route_entry(
    msg: &[u8],
    cfg: ParseConfig,
    iface_name_by_index: impl Fn(u32) -> Option<String>,
) -> std::io::Result<Option<RouteEntry>> {
    if msg.len() < 16 {
        return Ok(None);
    }

    let version = msg[2];
    let msg_type = msg[3];

    // Ignore messages with unexpected version or type.
    if !(3..=5).contains(&version) {
        return Ok(None);
    }
    if msg_type != cfg.expected_type {
        return Ok(None);
    }

    let rtm_index = u32::from(u16::from_ne_bytes([msg[4], msg[5]]));
    let rtm_flags = i32::from_ne_bytes([msg[8], msg[9], msg[10], msg[11]]);
    let rtm_addrs = i32::from_ne_bytes([msg[12], msg[13], msg[14], msg[15]]);

    // Skip routes with skip flags set (e.g. RTF_WASCLONED on macOS).
    if (rtm_flags & cfg.skip_flags) != 0 {
        return Ok(None);
    }

    // Determine header size based on message type.
    let header_size = if msg_type == RTM_GET2 {
        RT_MSGHDR2_SIZE
    } else {
        RT_MSGHDR_SIZE
    };

    // Parse trailing sockaddrs.
    let addrs = extract_sockaddrs(msg, header_size, rtm_addrs);

    // Skip messages with no addresses at all (mirrors Go's
    // `len(rm.Addrs) < RTAX_GATEWAY` check).
    let has_any_addr = addrs.iter().any(Option::is_some);
    if !has_any_addr {
        return Ok(None);
    }

    let flags_list = flag_names(rtm_flags);
    let route_type = route_type_from_flags(rtm_flags);

    // Populate destination.
    let mut family = 0u8;
    let mut dst = RouteDestination {
        addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        bits: 0,
        zone: String::new(),
    };

    if let Some(ref sa) = addrs[RTAX_DST] {
        match sa {
            ParsedSockaddr::Inet4(addr) => {
                family = 4;
                dst.addr = IpAddr::V4(*addr);
                dst.bits = 32; // default for host routes
            }
            ParsedSockaddr::Inet6 { addr, zone_id } => {
                family = 6;
                dst.addr = IpAddr::V6(*addr);
                dst.bits = 128;
                if *zone_id > 0 {
                    dst.zone = iface_name_by_index(*zone_id).unwrap_or_else(|| zone_id.to_string());
                }
            }
            _ => {}
        }
    }

    // Apply netmask if not a host route.
    if (rtm_flags & RTF_HOST) == 0 {
        if let Some(ref sa) = addrs[RTAX_NETMASK] {
            match sa {
                ParsedSockaddr::Inet4(mask) => {
                    dst.bits = prefix_len_v4(*mask);
                }
                ParsedSockaddr::Inet6 { addr: mask, .. } => {
                    let mut ones = prefix_len_v6(mask);
                    // macOS-specific: for multicast IPv6 routes, the kernel
                    // returns a netmask with 32 extra bits. Subtract to match
                    // netstat output (routetable_darwin.go / Go test
                    // "NetmaskAdjust").
                    if family == 6 && dst.addr.is_multicast() && ones > 32 {
                        ones -= 32;
                    }
                    dst.bits = ones;
                }
                ParsedSockaddr::Default => {
                    // sa_len=0 netmask = all zeros = /0
                    dst.bits = 0;
                }
                _ => {}
            }
        }
    }

    // Populate gateway.
    let mut gateway: Option<IpAddr> = None;
    let mut gateway_iface: Option<String> = None;

    if let Some(ref sa) = addrs[RTAX_GATEWAY] {
        match sa {
            ParsedSockaddr::Inet4(addr) => {
                gateway = Some(IpAddr::V4(*addr));
            }
            ParsedSockaddr::Inet6 { addr, zone_id } => {
                gateway = Some(IpAddr::V6(*addr));
                if *zone_id > 0 {
                    if let Some(name) = iface_name_by_index(*zone_id) {
                        gateway_iface = Some(name);
                    }
                }
            }
            ParsedSockaddr::Link { index, name, addr } => {
                if *index > 0 {
                    gateway_iface = if name.is_empty() {
                        iface_name_by_index(u32::from(*index))
                    } else {
                        Some(name.clone())
                    };
                }
                let _ = format_mac(addr); // stored in Go's GatewayAddr; not exposed here
            }
            ParsedSockaddr::Unknown => {}
            ParsedSockaddr::Default => {}
        }
    }

    // Resolve output interface name from index.
    let iface = if rtm_index > 0 {
        iface_name_by_index(rtm_index).unwrap_or_default()
    } else {
        String::new()
    };

    Ok(Some(RouteEntry {
        family,
        route_type,
        dst,
        gateway,
        gateway_iface,
        iface,
        flags: flags_list,
        raw_flags: rtm_flags,
    }))
}

/// Default parse config for macOS.
pub(crate) const DARWIN_CONFIG: ParseConfig = ParseConfig {
    expected_type: RTM_GET2,
    skip_flags: RTF_WASCLONED,
};

/// Default parse config for FreeBSD/OpenBSD.
#[allow(dead_code)]
pub(crate) const BSD_CONFIG: ParseConfig = ParseConfig {
    expected_type: RTM_GET,
    skip_flags: 0,
};

// ---------------------------------------------------------------------------
// Unit tests — platform-independent (test against synthetic byte buffers)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock interface name lookup: 1→"iface0", 2→"tailscale0".
    fn mock_iface(idx: u32) -> Option<String> {
        match idx {
            1 => Some("iface0".to_string()),
            2 => Some("tailscale0".to_string()),
            _ => None,
        }
    }

    // --- Synthetic sockaddr builders ---

    fn sa_in4(ip: [u8; 4]) -> Vec<u8> {
        let mut sa = vec![0u8; 16];
        sa[0] = 16; // sin_len
        sa[1] = AF_INET;
        sa[4..8].copy_from_slice(&ip);
        sa
    }

    fn sa_in6(ip: [u8; 16], zone_id: u32) -> Vec<u8> {
        let mut sa = vec![0u8; 28];
        sa[0] = 28; // sin6_len
        sa[1] = AF_INET6;
        sa[8..24].copy_from_slice(&ip);
        sa[24..28].copy_from_slice(&zone_id.to_ne_bytes());
        sa
    }

    fn sa_link(index: u16, name: &str, mac: &[u8]) -> Vec<u8> {
        let nlen = name.len();
        let alen = mac.len();
        let total = 8 + nlen + alen;
        let mut sa = vec![0u8; total];
        sa[0] = total as u8;
        sa[1] = AF_LINK;
        sa[2..4].copy_from_slice(&index.to_ne_bytes());
        sa[5] = nlen as u8;
        sa[6] = alen as u8;
        sa[8..8 + nlen].copy_from_slice(name.as_bytes());
        if alen > 0 {
            sa[8 + nlen..8 + nlen + alen].copy_from_slice(mac);
        }
        sa
    }

    // --- Synthetic rt_msghdr2 message builder ---

    fn build_msg(
        version: u8,
        msg_type: u8,
        index: u16,
        flags: i32,
        // sockaddrs in RTAX order; None = absent
        socks: &[Option<Vec<u8>>],
    ) -> Vec<u8> {
        let header_size = RT_MSGHDR2_SIZE;

        let mut rtm_addrs: i32 = 0;
        for (i, s) in socks.iter().enumerate() {
            if s.is_some() {
                rtm_addrs |= 1 << i;
            }
        }

        let mut msg = vec![0u8; header_size];
        msg[2] = version;
        msg[3] = msg_type;
        msg[4..6].copy_from_slice(&index.to_ne_bytes());
        msg[8..12].copy_from_slice(&flags.to_ne_bytes());
        msg[12..16].copy_from_slice(&rtm_addrs.to_ne_bytes());

        for s in socks.iter().flatten() {
            let fam = if s.len() > 1 { s[1] } else { 0 };
            let aligned = sa_align(s.len(), fam);
            msg.extend_from_slice(s);
            let pad = aligned - s.len();
            msg.extend(std::iter::repeat_n(0u8, pad));
        }

        let total = msg.len();
        msg[0..2].copy_from_slice(&(total as u16).to_ne_bytes());
        msg
    }

    // --- Helpers for expected values ---

    fn dst4(ip: &str, bits: u8) -> RouteDestination {
        RouteDestination {
            addr: IpAddr::V4(ip.parse().unwrap()),
            bits,
            zone: String::new(),
        }
    }

    fn dst6(ip: &str, bits: u8, zone: &str) -> RouteDestination {
        RouteDestination {
            addr: IpAddr::V6(ip.parse().unwrap()),
            bits,
            zone: zone.to_string(),
        }
    }

    fn entry(
        family: u8,
        route_type: RouteType,
        dst: RouteDestination,
        gateway: Option<IpAddr>,
        gateway_iface: Option<&str>,
        iface: &str,
        flags: &[&str],
        raw_flags: i32,
    ) -> RouteEntry {
        RouteEntry {
            family,
            route_type,
            dst,
            gateway,
            gateway_iface: gateway_iface.map(str::to_owned),
            iface: iface.to_string(),
            flags: flags.iter().map(ToString::to_string).collect(),
            raw_flags,
        }
    }

    // --- Test cases mirroring routetable_bsd_test.go ---

    #[test]
    fn test_basic_ipv4() {
        let msg = build_msg(
            3,
            RTM_GET2,
            0,
            0,
            &[
                Some(sa_in4([1, 2, 3, 4])),       // dst
                Some(sa_in4([1, 2, 3, 1])),       // gateway
                Some(sa_in4([255, 255, 255, 0])), // netmask
            ],
        );
        let got = parse_route_entry(&msg, DARWIN_CONFIG, mock_iface)
            .unwrap()
            .unwrap();
        let want = entry(
            4,
            RouteType::Unicast,
            dst4("1.2.3.4", 24),
            Some("1.2.3.1".parse().unwrap()),
            None,
            "",
            &[],
            0,
        );
        assert_eq!(got.family, want.family);
        assert_eq!(got.route_type, want.route_type);
        assert_eq!(got.dst, want.dst);
        assert_eq!(got.gateway, want.gateway);
        assert_eq!(got.gateway_iface, want.gateway_iface);
        assert_eq!(got.iface, want.iface);
        assert_eq!(got.flags, want.flags);
    }

    #[test]
    fn test_basic_ipv6() {
        let dst_ip = [
            0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let gw_ip = [0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        // ffff:ffff:ffff:: → 48 bits
        let nm_ip = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let msg = build_msg(
            3,
            RTM_GET2,
            0,
            0,
            &[
                Some(sa_in6(dst_ip, 0)),
                Some(sa_in6(gw_ip, 0)),
                Some(sa_in6(nm_ip, 0)),
            ],
        );
        let got = parse_route_entry(&msg, DARWIN_CONFIG, mock_iface)
            .unwrap()
            .unwrap();
        assert_eq!(got.family, 6);
        assert_eq!(got.route_type, RouteType::Unicast);
        assert_eq!(got.dst, dst6("fd7a:115c:a1e0::", 48, ""));
        assert_eq!(got.gateway, Some(IpAddr::V6("1234::".parse().unwrap())));
    }

    #[test]
    fn test_ipv6_with_zone() {
        let dst_ip = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let gw_ip = [0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let nm_ip = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let msg = build_msg(
            3,
            RTM_GET2,
            0,
            0,
            &[
                Some(sa_in6(dst_ip, 2)), // zone = interface 2
                Some(sa_in6(gw_ip, 0)),
                Some(sa_in6(nm_ip, 0)),
            ],
        );
        let got = parse_route_entry(&msg, DARWIN_CONFIG, mock_iface)
            .unwrap()
            .unwrap();
        assert_eq!(got.family, 6);
        assert_eq!(got.dst, dst6("fe80::", 64, "tailscale0"));
        assert_eq!(got.gateway, Some(IpAddr::V6("1234::".parse().unwrap())));
    }

    #[test]
    fn test_ipv6_with_unknown_zone() {
        let dst_ip = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let gw_ip = [0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let nm_ip = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let msg = build_msg(
            3,
            RTM_GET2,
            0,
            0,
            &[
                Some(sa_in6(dst_ip, 4)), // zone = interface 4 (not in mock)
                Some(sa_in6(gw_ip, 0)),
                Some(sa_in6(nm_ip, 0)),
            ],
        );
        let got = parse_route_entry(&msg, DARWIN_CONFIG, mock_iface)
            .unwrap()
            .unwrap();
        assert_eq!(got.dst, dst6("fe80::", 64, "4"));
    }

    #[test]
    fn test_default_ipv4() {
        let msg = build_msg(
            3,
            RTM_GET2,
            0,
            0,
            &[
                Some(sa_in4([0, 0, 0, 0])),
                Some(sa_in4([1, 2, 3, 4])),
                Some(sa_in4([0, 0, 0, 0])),
            ],
        );
        let got = parse_route_entry(&msg, DARWIN_CONFIG, mock_iface)
            .unwrap()
            .unwrap();
        assert_eq!(got.family, 4);
        assert_eq!(got.dst, dst4("0.0.0.0", 0));
        assert_eq!(got.gateway, Some("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn test_default_ipv6() {
        let zero16 = [0u8; 16];
        let gw_ip = [0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let msg = build_msg(
            3,
            RTM_GET2,
            0,
            0,
            &[
                Some(sa_in6(zero16, 0)),
                Some(sa_in6(gw_ip, 0)),
                Some(sa_in6(zero16, 0)),
            ],
        );
        let got = parse_route_entry(&msg, DARWIN_CONFIG, mock_iface)
            .unwrap()
            .unwrap();
        assert_eq!(got.family, 6);
        assert_eq!(got.dst, dst6("::", 0, ""));
        assert_eq!(got.gateway, Some(IpAddr::V6("1234::".parse().unwrap())));
    }

    #[test]
    fn test_short_addrs() {
        let msg = build_msg(
            3,
            RTM_GET2,
            0,
            0,
            &[
                Some(sa_in4([1, 2, 3, 4])), // dst only
            ],
        );
        let got = parse_route_entry(&msg, DARWIN_CONFIG, mock_iface)
            .unwrap()
            .unwrap();
        assert_eq!(got.family, 4);
        assert_eq!(got.dst, dst4("1.2.3.4", 32));
        assert_eq!(got.gateway, None);
    }

    #[test]
    fn test_tailscale_ipv4() {
        let msg = build_msg(
            3,
            RTM_GET2,
            0,
            0,
            &[
                Some(sa_in4([100, 64, 0, 0])),
                Some(sa_link(2, "tailscale0", &[])), // gateway = link, index 2
                Some(sa_in4([255, 192, 0, 0])),
            ],
        );
        let got = parse_route_entry(&msg, DARWIN_CONFIG, mock_iface)
            .unwrap()
            .unwrap();
        assert_eq!(got.family, 4);
        assert_eq!(got.dst, dst4("100.64.0.0", 10));
        assert_eq!(got.gateway, None);
        assert_eq!(got.gateway_iface.as_deref(), Some("tailscale0"));
    }

    #[test]
    fn test_flags() {
        let flags = RTF_STATIC | RTF_GATEWAY | RTF_UP;
        let msg = build_msg(
            3,
            RTM_GET2,
            0,
            flags,
            &[
                Some(sa_in4([1, 2, 3, 4])),
                Some(sa_in4([1, 2, 3, 1])),
                Some(sa_in4([255, 255, 255, 0])),
            ],
        );
        let got = parse_route_entry(&msg, DARWIN_CONFIG, mock_iface)
            .unwrap()
            .unwrap();
        assert_eq!(got.flags, vec!["gateway", "static", "up"]);
        assert_eq!(got.raw_flags, flags);
    }

    #[test]
    fn test_skip_no_addrs() {
        let msg = build_msg(3, RTM_GET2, 0, 0, &[]);
        let got = parse_route_entry(&msg, DARWIN_CONFIG, mock_iface).unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn test_skip_bad_version() {
        let mut msg = build_msg(1, RTM_GET2, 0, 0, &[Some(sa_in4([1, 2, 3, 4]))]);
        msg[2] = 1; // version 1
        let got = parse_route_entry(&msg, DARWIN_CONFIG, mock_iface).unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn test_skip_bad_type() {
        let mut msg = build_msg(3, RTM_GET2, 0, 0, &[Some(sa_in4([1, 2, 3, 4]))]);
        msg[3] = RTM_GET2 + 1; // wrong type
        let got = parse_route_entry(&msg, DARWIN_CONFIG, mock_iface).unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn test_output_iface() {
        let msg = build_msg(3, RTM_GET2, 1, 0, &[Some(sa_in4([1, 2, 3, 4]))]);
        let got = parse_route_entry(&msg, DARWIN_CONFIG, mock_iface)
            .unwrap()
            .unwrap();
        assert_eq!(got.iface, "iface0");
    }

    #[test]
    fn test_gateway_mac() {
        let mac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let msg = build_msg(
            3,
            RTM_GET2,
            0,
            0,
            &[
                Some(sa_in4([100, 64, 0, 0])),
                Some(sa_link(1, "iface0", &mac)),
                Some(sa_in4([255, 192, 0, 0])),
            ],
        );
        let got = parse_route_entry(&msg, DARWIN_CONFIG, mock_iface)
            .unwrap()
            .unwrap();
        assert_eq!(got.dst, dst4("100.64.0.0", 10));
        assert_eq!(got.gateway_iface.as_deref(), Some("iface0"));
    }

    #[test]
    fn test_skip_flags_darwin() {
        let flags = RTF_UP | RTF_WASCLONED;
        let msg = build_msg(
            3,
            RTM_GET2,
            0,
            flags,
            &[
                Some(sa_in4([1, 2, 3, 4])),
                Some(sa_in4([1, 2, 3, 1])),
                Some(sa_in4([255, 255, 255, 0])),
            ],
        );
        let got = parse_route_entry(&msg, DARWIN_CONFIG, mock_iface).unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn test_netmask_adjust() {
        let dst_ip = [0xff, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let gw_ip = [0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        // netmask ffff:ffff:ff00:: → 40 bits, but multicast → subtract 32 → 8
        let nm_ip = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let msg = build_msg(
            3,
            RTM_GET2,
            0,
            RTF_MULTICAST,
            &[
                Some(sa_in6(dst_ip, 0)),
                Some(sa_in6(gw_ip, 0)),
                Some(sa_in6(nm_ip, 0)),
            ],
        );
        let got = parse_route_entry(&msg, DARWIN_CONFIG, mock_iface)
            .unwrap()
            .unwrap();
        assert_eq!(got.route_type, RouteType::Multicast);
        assert_eq!(got.dst, dst6("ff00::", 8, ""));
        assert_eq!(got.gateway, Some(IpAddr::V6("1234::".parse().unwrap())));
        assert_eq!(got.flags, vec!["multicast"]);
        assert_eq!(got.raw_flags, RTF_MULTICAST);
    }

    // --- Low-level parser tests ---

    #[test]
    fn test_sa_align() {
        // sa_len=0, non-AF_LINK: 4 bytes
        assert_eq!(sa_align(0, 0), 4);
        assert_eq!(sa_align(0, AF_INET), 4);
        assert_eq!(sa_align(0, AF_INET6), 4);
        // sa_len=0, AF_LINK: 8 bytes
        assert_eq!(sa_align(0, AF_LINK), 8);
        // Round up to 4-byte boundary
        assert_eq!(sa_align(1, 0), 4);
        assert_eq!(sa_align(4, 0), 4);
        assert_eq!(sa_align(7, 0), 8);
        assert_eq!(sa_align(8, 0), 8);
        assert_eq!(sa_align(9, 0), 12);
        assert_eq!(sa_align(16, 0), 16);
        assert_eq!(sa_align(17, 0), 20);
        assert_eq!(sa_align(20, 0), 20);
        assert_eq!(sa_align(24, 0), 24);
        assert_eq!(sa_align(28, 0), 28);
        assert_eq!(sa_align(32, 0), 32);
    }

    #[test]
    fn test_prefix_len_v4() {
        assert_eq!(prefix_len_v4(Ipv4Addr::UNSPECIFIED), 0);
        assert_eq!(prefix_len_v4(Ipv4Addr::new(255, 255, 255, 0)), 24);
        assert_eq!(prefix_len_v4(Ipv4Addr::BROADCAST), 32);
        assert_eq!(prefix_len_v4(Ipv4Addr::new(255, 192, 0, 0)), 10);
        assert_eq!(prefix_len_v4(Ipv4Addr::new(255, 255, 255, 128)), 25);
    }

    #[test]
    fn test_prefix_len_v6() {
        assert_eq!(prefix_len_v6(&Ipv6Addr::UNSPECIFIED), 0);
        assert_eq!(
            prefix_len_v6(&"ffff:ffff:ffff::".parse::<Ipv6Addr>().unwrap()),
            48
        );
        assert_eq!(
            prefix_len_v6(&"ffff:ffff:ffff:ffff::".parse::<Ipv6Addr>().unwrap()),
            64
        );
        assert_eq!(prefix_len_v6(&Ipv6Addr::from(u128::MAX)), 128);
    }

    #[test]
    fn test_route_type_from_flags() {
        assert_eq!(route_type_from_flags(RTF_LOCAL), RouteType::Local);
        assert_eq!(route_type_from_flags(RTF_BROADCAST), RouteType::Broadcast);
        assert_eq!(route_type_from_flags(RTF_MULTICAST), RouteType::Multicast);
        // No HOST flag → unicast (net route)
        assert_eq!(route_type_from_flags(0), RouteType::Unicast);
        assert_eq!(route_type_from_flags(RTF_UP), RouteType::Unicast);
        // HOST flag set, none of the above → other
        assert_eq!(route_type_from_flags(RTF_HOST), RouteType::Other);
        assert_eq!(
            route_type_from_flags(RTF_HOST | RTF_UP | RTF_GATEWAY),
            RouteType::Other
        );
    }

    #[test]
    fn test_flag_names() {
        assert!(flag_names(0).is_empty());
        assert_eq!(
            flag_names(RTF_UP | RTF_STATIC | RTF_GATEWAY),
            vec!["gateway", "static", "up"]
        );
        assert_eq!(flag_names(RTF_MULTICAST), vec!["multicast"]);
    }

    #[test]
    fn test_parse_sockaddr_in4() {
        let sa = sa_in4([10, 0, 0, 1]);
        let parsed = parse_sockaddr(&sa, 16, AF_INET);
        assert_eq!(parsed, ParsedSockaddr::Inet4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn test_parse_sockaddr_in6() {
        let ip = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let sa = sa_in6(ip, 5);
        let parsed = parse_sockaddr(&sa, 28, AF_INET6);
        match parsed {
            ParsedSockaddr::Inet6 { addr, zone_id } => {
                assert_eq!(addr, Ipv6Addr::from(ip));
                assert_eq!(zone_id, 5);
            }
            _ => panic!("expected Inet6"),
        }
    }

    #[test]
    fn test_parse_sockaddr_dl() {
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let sa = sa_link(3, "en0", &mac);
        let parsed = parse_sockaddr(&sa, sa[0], AF_LINK);
        match parsed {
            ParsedSockaddr::Link { index, name, addr } => {
                assert_eq!(index, 3);
                assert_eq!(name, "en0");
                assert_eq!(addr, mac);
            }
            _ => panic!("expected Link"),
        }
    }

    #[test]
    fn test_extract_sockaddrs() {
        let dst = sa_in4([10, 0, 0, 1]);
        let gw = sa_in4([10, 0, 0, 254]);
        let nm = sa_in4([255, 255, 255, 0]);

        let mut msg = vec![0u8; RT_MSGHDR2_SIZE];
        let rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
        msg[12..16].copy_from_slice(&rtm_addrs.to_ne_bytes());

        for sa in [&dst, &gw, &nm] {
            let aligned = sa_align(sa.len(), sa[1]);
            msg.extend_from_slice(sa);
            msg.extend(std::iter::repeat_n(0u8, aligned - sa.len()));
        }

        let addrs = extract_sockaddrs(&msg, RT_MSGHDR2_SIZE, rtm_addrs);
        match &addrs[RTAX_DST] {
            Some(ParsedSockaddr::Inet4(addr)) => assert_eq!(*addr, Ipv4Addr::new(10, 0, 0, 1)),
            other => panic!("expected Inet4(10.0.0.1), got {other:?}"),
        }
        match &addrs[RTAX_GATEWAY] {
            Some(ParsedSockaddr::Inet4(addr)) => assert_eq!(*addr, Ipv4Addr::new(10, 0, 0, 254)),
            other => panic!("expected Inet4(10.0.0.254), got {other:?}"),
        }
        match &addrs[RTAX_NETMASK] {
            Some(ParsedSockaddr::Inet4(addr)) => {
                assert_eq!(*addr, Ipv4Addr::new(255, 255, 255, 0));
            }
            other => panic!("expected Inet4(255.255.255.0), got {other:?}"),
        }
        assert!(addrs[RTAX_GENMASK].is_none());
        assert!(addrs[RTAX_IFP].is_none());
    }
}
