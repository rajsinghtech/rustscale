//! Default-route detection via the BSD routing table.
//!
//! Ports Go's `net/netmon/interfaces_bsd.go` (`DefaultRouteInterfaceIndex`)
//! and `net/netmon/interfaces_darwin.go` (`getDelegatedInterface`).
//!
//! On macOS, fetches the kernel routing table via `sysctl(NET_RT_DUMP2)`,
//! parses `rt_msghdr` entries, and finds the first default-gateway route
//! (`RTF_GATEWAY` set, `RTF_IFSCOPE` not set, destination `0.0.0.0/0` or
//! `::/0`). For `utun` interfaces, follows the `SIOCGIFDELEGATE` ioctl to
//! the underlying physical interface so we never report our own tunnel as
//! the default route.

#![allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]

use std::io;
use std::net::IpAddr;
#[cfg(target_os = "macos")]
use std::net::{Ipv4Addr, Ipv6Addr};

/// `NET_RT_DUMP2` sysctl mib value — not in the `libc` crate.
/// Defined in macOS `<sys/socket.h>` as 7.
#[cfg(target_os = "macos")]
const NET_RT_DUMP2: libc::c_int = 7;

/// `SIOCGIFDELEGATE` ioctl value — not in public macOS headers.
/// Generated from `_IOWR('i', 157, struct ifreq)` = `0xc020699d`.
/// Used by `ifconfig` to discover the underlying physical interface for
/// tunnel interfaces (`utun`).
#[cfg(target_os = "macos")]
const SIOCGIFDELEGATE: libc::c_ulong = 0xc020699d;

/// `RTF_IFSCOPE` — route is scoped to a specific interface. Already in
/// the `libc` crate on macOS but declared here for documentation.
#[cfg(target_os = "macos")]
const RTF_IFSCOPE: libc::c_int = 0x1000000;

/// Size of `rt_msghdr` / `rt_msghdr2` on darwin (from Go's `route` package:
/// `sizeofRtMsghdrDarwin15 = 0x5c`).
#[cfg(target_os = "macos")]
const RT_MSGHDR_SIZE: usize = 0x5c;

/// `sizeof(struct sockaddr_in)` on darwin.
#[cfg(all(test, target_os = "macos"))]
const SOCKADDR_IN_SIZE: u8 = 16;

/// `sizeof(struct sockaddr_in6)` on darwin.
#[cfg(all(test, target_os = "macos"))]
const SOCKADDR_IN6_SIZE: u8 = 28;

/// RTAX slot indices in the `rtm_addrs` bitmask.
#[cfg(target_os = "macos")]
const RTAX_DST: usize = 0;
#[cfg(target_os = "macos")]
const RTAX_GATEWAY: usize = 1;
#[cfg(target_os = "macos")]
const RTAX_NETMASK: usize = 2;
#[cfg(target_os = "macos")]
const RTAX_MAX: usize = 8;

/// Address families used in sockaddr parsing (darwin routing table).
#[cfg(target_os = "macos")]
const AF_INET: u8 = libc::AF_INET as u8;
#[cfg(target_os = "macos")]
const AF_INET6: u8 = libc::AF_INET6 as u8;
#[cfg(target_os = "macos")]
const AF_LINK: u8 = libc::AF_LINK as u8;

/// Look up the interface index owning the default route.
///
/// On macOS, fetches the routing table via `sysctl(NET_RT_DUMP2)` and
/// scans for the first default-gateway route. For `utun` interfaces,
/// follows `SIOCGIFDELEGATE` to the underlying physical interface.
///
/// Returns `Err` if no default route is found or the sysctl/ioctl fails.
pub fn default_route_interface_index() -> io::Result<u32> {
    let (idx, _gw) = default_route_from_sysctl()?;
    if idx == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no gateway index found",
        ));
    }
    Ok(idx)
}

/// Look up the default route interface index and gateway IP via sysctl.
///
/// Returns `(interface_index, gateway_ip)`. The gateway may be `None`
/// if the route message doesn't include a gateway sockaddr. The interface
/// index is already resolved through `SIOCGIFDELEGATE` for `utun` tunnels.
pub(crate) fn default_route_from_sysctl() -> io::Result<(u32, Option<IpAddr>)> {
    let rib = fetch_routing_table()?;
    let route = parse_default_gateway(&rib)?;
    let idx = route.interface_index;
    if idx == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no gateway index found",
        ));
    }
    // Follow utun delegation to the underlying physical interface.
    if let Ok(delegated) = get_delegated_interface(idx) {
        if delegated != 0 {
            return Ok((delegated, route.gateway));
        }
    }
    Ok((idx, route.gateway))
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/// A parsed route message from the sysctl RIB dump.
struct ParsedRoute {
    interface_index: u32,
    #[allow(dead_code)]
    flags: i32,
    gateway: Option<IpAddr>,
}

/// A parsed sockaddr from a route message.
#[derive(Clone, Copy, Debug)]
#[cfg(target_os = "macos")]
enum SockAddr {
    Inet4(Ipv4Addr),
    Inet6(Ipv6Addr),
    Link,
    Unspec,
}

// ---------------------------------------------------------------------------
// macOS sysctl + parsing
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn fetch_routing_table() -> io::Result<Vec<u8>> {
    let mut mib: [libc::c_int; 6] = [
        libc::CTL_NET,
        libc::PF_ROUTE,
        0,
        libc::AF_UNSPEC,
        NET_RT_DUMP2,
        0,
    ];

    // First call: get the needed size.
    let mut needed: libc::size_t = 0;
    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            std::ptr::null_mut(),
            std::ptr::addr_of_mut!(needed),
            std::ptr::null_mut(),
            0,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    if needed == 0 {
        return Ok(Vec::new());
    }

    // Second call: get the data. Retry a few times if the table grows
    // between calls (matches Go's FetchRIB retry logic).
    for _ in 0..3 {
        let mut buf = vec![0u8; needed];
        let mut len = needed;
        let ret = unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as libc::c_uint,
                buf.as_mut_ptr().cast::<libc::c_void>(),
                std::ptr::addr_of_mut!(len),
                std::ptr::null_mut(),
                0,
            )
        };
        if ret == 0 {
            buf.truncate(len);
            return Ok(buf);
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ENOMEM) {
            return Err(err);
        }
        // Table grew between calls; retry with the new size hint.
        needed = len;
    }
    Err(io::Error::last_os_error())
}

#[cfg(target_os = "macos")]
fn parse_default_gateway(buf: &[u8]) -> io::Result<ParsedRoute> {
    let mut offset = 0;
    while offset + 4 <= buf.len() {
        let msg_len = u16::from_le_bytes([buf[offset], buf[offset + 1]]) as usize;
        if msg_len == 0 || offset + msg_len > buf.len() {
            break;
        }
        let msg = &buf[offset..offset + msg_len];
        offset += msg_len;

        // Byte 2 is rtm_version — skip mismatched versions.
        if msg[2] != libc::RTM_VERSION as u8 {
            continue;
        }
        if msg.len() < RT_MSGHDR_SIZE {
            continue;
        }

        let rtm_index = u32::from(u16::from_le_bytes([msg[4], msg[5]]));
        let rtm_flags = i32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]);
        let rtm_addrs = i32::from_le_bytes([msg[12], msg[13], msg[14], msg[15]]);

        let body = &msg[RT_MSGHDR_SIZE..];
        let addrs = parse_sockaddrs(body, rtm_addrs);

        if is_default_gateway(rtm_flags, &addrs) {
            let gateway = match addrs.get(RTAX_GATEWAY) {
                Some(Some(SockAddr::Inet4(ip))) => Some(IpAddr::V4(*ip)),
                Some(Some(SockAddr::Inet6(ip))) => Some(IpAddr::V6(*ip)),
                _ => None,
            };
            return Ok(ParsedRoute {
                interface_index: rtm_index,
                flags: rtm_flags,
                gateway,
            });
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "no gateway index found",
    ))
}

// ---------------------------------------------------------------------------
// Non-macOS stubs
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "macos"))]
fn fetch_routing_table() -> io::Result<Vec<u8>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "sysctl NET_RT_DUMP2 is darwin-only",
    ))
}

#[cfg(not(target_os = "macos"))]
fn parse_default_gateway(_buf: &[u8]) -> io::Result<ParsedRoute> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "route table parsing is darwin-only",
    ))
}

// ---------------------------------------------------------------------------
// Sockaddr parsing (darwin only — used by parse_default_gateway and tests)
// ---------------------------------------------------------------------------

/// Parse the sockaddr array following the `rtm_addrs` bitmask.
///
/// Each bit `i` in `rtm_addrs` indicates whether the address at `RTAX_*`
/// slot `i` is present. Present addresses are packed sequentially in
/// `buf`, each aligned to 4 bytes on darwin (`kernelAlign = 4`).
#[cfg(target_os = "macos")]
fn parse_sockaddrs(buf: &[u8], rtm_addrs: i32) -> Vec<Option<SockAddr>> {
    let mut result = vec![None; RTAX_MAX];
    let mut offset = 0;
    let mut last_inet_family: Option<u8> = None;

    for (i, slot) in result.iter_mut().enumerate().take(RTAX_MAX) {
        let bit = 1 << i;
        if (rtm_addrs & bit) == 0 {
            continue;
        }
        if offset + 2 > buf.len() {
            break;
        }
        let remaining = &buf[offset..];
        let sa_len = remaining[0];
        let sa_family = remaining[1];

        let addr = parse_sockaddr(remaining, sa_len, sa_family, i, last_inet_family);
        if let Some(SockAddr::Inet4(_) | SockAddr::Inet6(_)) = &addr {
            last_inet_family = Some(sa_family);
        }
        *slot = addr;

        // Advance by roundup(sa_len, 4). On darwin, kernelAlign = 4.
        // When sa_len = 0, the kernel writes 4 bytes of filler.
        let advance = if sa_len == 0 {
            4
        } else {
            ((sa_len as usize) + 3) & !3
        };
        offset += advance;
    }
    result
}

/// Parse a single sockaddr from the buffer.
#[cfg(target_os = "macos")]
fn parse_sockaddr(
    buf: &[u8],
    sa_len: u8,
    sa_family: u8,
    rtax_index: usize,
    last_inet_family: Option<u8>,
) -> Option<SockAddr> {
    match sa_family {
        AF_LINK => Some(SockAddr::Link),
        AF_INET => parse_inet4(buf, sa_len),
        AF_INET6 => parse_inet6(buf, sa_len),
        _ => {
            // Netmask in kernel form may have family=0 (AF_UNSPEC).
            // If this is a mask slot and we've seen an inet family
            // before, parse as that family (matches Go's parseAddrs).
            if rtax_index == RTAX_NETMASK || rtax_index == 3
            // RTAX_GENMASK
            {
                if let Some(fam) = last_inet_family {
                    return match fam {
                        AF_INET => parse_inet4(buf, sa_len),
                        AF_INET6 => parse_inet6(buf, sa_len),
                        _ => None,
                    };
                }
            }
            Some(SockAddr::Unspec)
        }
    }
}

/// Parse an IPv4 sockaddr. The IP address is at bytes 4-7.
/// If `sa_len` is 0 or < 5, the IP is all-zeros (kernel filler for
/// default mask).
#[cfg(target_os = "macos")]
fn parse_inet4(buf: &[u8], sa_len: u8) -> Option<SockAddr> {
    if sa_len == 0 {
        return Some(SockAddr::Inet4(Ipv4Addr::UNSPECIFIED));
    }
    if (sa_len as usize) <= 4 || buf.len() < 8 {
        return Some(SockAddr::Inet4(Ipv4Addr::UNSPECIFIED));
    }
    Some(SockAddr::Inet4(Ipv4Addr::new(
        buf[4], buf[5], buf[6], buf[7],
    )))
}

/// Parse an IPv6 sockaddr. The IP address is at bytes 8-23.
/// If `sa_len` is 0 or < 9, the IP is all-zeros.
#[cfg(target_os = "macos")]
fn parse_inet6(buf: &[u8], sa_len: u8) -> Option<SockAddr> {
    if sa_len == 0 {
        return Some(SockAddr::Inet6(Ipv6Addr::UNSPECIFIED));
    }
    if (sa_len as usize) <= 8 || buf.len() < 24 {
        return Some(SockAddr::Inet6(Ipv6Addr::UNSPECIFIED));
    }
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&buf[8..24]);
    Some(SockAddr::Inet6(Ipv6Addr::from(octets)))
}

/// Check whether a route message represents a default gateway.
///
/// Mirrors Go's `isDefaultGateway`: `RTF_GATEWAY` set, `RTF_IFSCOPE` not
/// set, destination is `0.0.0.0/0` (v4) or `::/0` (v6).
#[cfg(target_os = "macos")]
fn is_default_gateway(flags: i32, addrs: &[Option<SockAddr>]) -> bool {
    if (flags & libc::RTF_GATEWAY) == 0 {
        return false;
    }
    if (flags & RTF_IFSCOPE) != 0 {
        return false;
    }
    if addrs.len() <= RTAX_NETMASK {
        return false;
    }
    let dst = addrs[RTAX_DST];
    let netmask = addrs[RTAX_NETMASK];
    match (dst, netmask) {
        (Some(SockAddr::Inet4(d)), Some(SockAddr::Inet4(nm))) => {
            d.is_unspecified() && nm.is_unspecified()
        }
        (Some(SockAddr::Inet6(d)), Some(SockAddr::Inet6(nm))) => {
            d.is_unspecified() && nm.is_unspecified()
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// utun / delegated-interface handling (darwin only)
// ---------------------------------------------------------------------------

/// Whether an interface name is a `utun` (tunnel) interface.
///
/// Matches Go's `strings.HasPrefix(ifName, "utun")` from
/// `interfaces_darwin.go`.
#[cfg(target_os = "macos")]
fn is_utun_name(name: &str) -> bool {
    name.starts_with("utun")
}

/// Get the delegated (underlying) interface index for a utun interface.
///
/// On macOS, tunnel interfaces (`utun`) have a delegated physical
/// interface. Uses the `SIOCGIFDELEGATE` ioctl (same mechanism as
/// `ifconfig`). Returns `Ok(0)` if the interface is not `utun` or has no
/// delegation.
#[cfg(target_os = "macos")]
fn get_delegated_interface(if_index: u32) -> io::Result<u32> {
    let name = interface_name_by_index(if_index)?;
    if !is_utun_name(&name) {
        return Ok(0);
    }

    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // ifreq layout: ifr_name[IFNAMSIZ=16] + ifr_delegated(u32) = 20 bytes.
    let mut ifr_buf = [0u8; 20];
    let name_bytes = name.as_bytes();
    let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
    ifr_buf[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    let ret = unsafe {
        libc::ioctl(
            fd,
            SIOCGIFDELEGATE,
            ifr_buf.as_mut_ptr().cast::<libc::c_void>(),
        )
    };
    let delegated = u32::from_le_bytes([ifr_buf[16], ifr_buf[17], ifr_buf[18], ifr_buf[19]]);
    unsafe {
        libc::close(fd);
    }

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(delegated)
}

/// Look up an interface name by index using `if_indextoname`.
#[cfg(target_os = "macos")]
fn interface_name_by_index(index: u32) -> io::Result<String> {
    let mut buf = [0i8; libc::IF_NAMESIZE];
    let ret = unsafe { libc::if_indextoname(index as libc::c_uint, buf.as_mut_ptr()) };
    if ret.is_null() {
        return Err(io::Error::last_os_error());
    }
    let name = unsafe { std::ffi::CStr::from_ptr(ret) }
        .to_string_lossy()
        .to_string();
    Ok(name)
}

#[cfg(not(target_os = "macos"))]
fn get_delegated_interface(_if_index: u32) -> io::Result<u32> {
    Ok(0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, target_os = "macos"))]
mod tests;
