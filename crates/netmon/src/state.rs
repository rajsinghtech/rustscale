//! Network interface state snapshot: enumeration, filtering, and comparison.
//!
//! Ports the semantics of Go's `net/netmon/state.go` in simplified form.
//! [`gather_state`] enumerates all interfaces via `if_addrs`, records their
//! names, IPs, prefix lengths, and up/loopback flags, then computes
//! `have_v4`/`have_v6` over interesting, up, non-Tailscale interfaces with
//! routable IPs.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// An IP address with a prefix length (subnet mask bit count).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct IpPrefix {
    /// The interface IP address.
    pub ip: IpAddr,
    /// The prefix length (number of leading 1-bits in the netmask).
    pub bits: u8,
}

/// Lightweight interface metadata used for change detection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterfaceMeta {
    /// Whether the interface is operationally up.
    pub is_up: bool,
    /// Whether the interface is a loopback interface.
    pub is_loopback: bool,
}

/// A snapshot of the machine's network interface state.
///
/// Mirrors Go's `netmon.State`. `interface_ips` and `interface_meta` record
/// ALL interfaces (including loopback/down) so that [`State::equal`] can
/// detect any change. `have_v4`/`have_v6` are computed only over interesting,
/// up, non-Tailscale interfaces with routable IPs.
#[derive(Clone, Debug)]
pub struct State {
    /// Interface name -> list of IP prefixes configured on it.
    pub interface_ips: BTreeMap<String, Vec<IpPrefix>>,
    /// Interface name -> up/loopback metadata.
    pub interface_meta: BTreeMap<String, InterfaceMeta>,
    /// Whether a usable IPv4 address exists on an interesting, up,
    /// non-Tailscale interface.
    pub have_v4: bool,
    /// Whether a usable IPv6 address exists on an interesting, up,
    /// non-Tailscale interface.
    pub have_v6: bool,
    /// The interface name owning the default route (empty if unknown).
    pub default_route_interface: String,
}

/// Gather a snapshot of the current network interface state.
///
/// Returns `None` if interface enumeration fails entirely.
pub fn gather_state() -> Option<State> {
    let ifaces = if_addrs::get_if_addrs().ok()?;

    let mut interface_ips: BTreeMap<String, Vec<IpPrefix>> = BTreeMap::new();
    let mut interface_meta: BTreeMap<String, InterfaceMeta> = BTreeMap::new();
    let mut have_v4 = false;
    let mut have_v6 = false;

    for iface in &ifaces {
        let name = iface.name.clone();
        let is_up = iface.is_oper_up();
        let is_loopback = iface.is_loopback();

        let prefix = prefix_from_iface(iface);
        interface_ips.entry(name.clone()).or_default().push(prefix);
        interface_meta.insert(name.clone(), InterfaceMeta { is_up, is_loopback });

        if !is_up || !is_interesting_interface(&name) || is_tailscale_interface(&name, &[prefix]) {
            continue;
        }

        let ip = prefix.ip;
        if ip.is_loopback() {
            continue;
        }
        if is_usable_v4(ip) {
            have_v4 = true;
        }
        if is_usable_v6(ip) {
            have_v6 = true;
        }
    }

    let default_route_interface = default_route_interface();

    Some(State {
        interface_ips,
        interface_meta,
        have_v4,
        have_v6,
        default_route_interface,
    })
}

/// Derive an [`IpPrefix`] from an `if_addrs::Interface`, computing the prefix
/// length from the netmask. Falls back to /32 (v4) or /128 (v6) when no
/// netmask is available.
fn prefix_from_iface(iface: &if_addrs::Interface) -> IpPrefix {
    match iface.addr {
        if_addrs::IfAddr::V4(ref a) => IpPrefix {
            ip: IpAddr::V4(a.ip),
            bits: prefix_len_v4(a.netmask),
        },
        if_addrs::IfAddr::V6(ref a) => IpPrefix {
            ip: IpAddr::V6(a.ip),
            bits: prefix_len_v6(a.netmask),
        },
    }
}

/// Count the number of leading 1-bits in an IPv4 netmask.
fn prefix_len_v4(mask: Ipv4Addr) -> u8 {
    let bits = u32::from(mask);
    if bits == 0 {
        return 0;
    }
    (32 - bits.trailing_zeros()) as u8
}

/// Count the number of leading 1-bits in an IPv6 netmask.
fn prefix_len_v6(mask: Ipv6Addr) -> u8 {
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

/// Whether an IPv4 address is usable for Internet connectivity (not loopback,
/// not link-local unless in a special environment — simplified to just exclude
/// loopback and link-local).
fn is_usable_v4(ip: IpAddr) -> bool {
    let v4 = match ip {
        IpAddr::V4(v) => v,
        _ => return false,
    };
    if v4.is_loopback() {
        return false;
    }
    !is_link_local_v4(v4)
}

/// Whether an IPv6 address is usable for Internet connectivity (global
/// unicast 2000::/3, or private ULA excluding Tailscale's ULA range).
fn is_usable_v6(ip: IpAddr) -> bool {
    let v6 = match ip {
        IpAddr::V6(v) => v,
        _ => return false,
    };
    if v6.is_loopback() {
        return false;
    }
    let octets = v6.octets();
    if (octets[0] & 0xE0) == 0x20 {
        return true;
    }
    if (octets[0] & 0xFE) == 0xFC && !is_tailscale_ula(&octets) {
        return true;
    }
    false
}

/// Whether an IPv4 address is link-local (169.254.0.0/16).
fn is_link_local_v4(addr: Ipv4Addr) -> bool {
    let o = addr.octets();
    o[0] == 169 && o[1] == 254
}

/// Whether an IPv6 address is in Tailscale's ULA range (fd7a:115c:a1e0::/48).
fn is_tailscale_ula(octets: &[u8; 16]) -> bool {
    octets[0] == 0xfd
        && octets[1] == 0x7a
        && octets[2] == 0x11
        && octets[3] == 0x5c
        && octets[4] == 0xa1
        && octets[5] == 0xe0
}

/// Whether an IPv4 address is in the Tailscale CGNAT range (100.64.0.0/10).
fn is_cgnat_v4(addr: Ipv4Addr) -> bool {
    let o = addr.octets();
    o[0] == 100 && (o[1] & 0xC0) == 0x40
}

/// Filter out non-routable IPs: loopback, link-local, multicast, Tailscale
/// CGNAT (100.64.0.0/10), and Tailscale ULA (fd7a:115c:a1e0::/48).
pub(crate) fn filter_routable_ips(ips: &[IpPrefix]) -> Vec<IpPrefix> {
    ips.iter()
        .filter(|p| {
            let ip = p.ip;
            if ip.is_loopback() || ip.is_multicast() {
                return false;
            }
            match ip {
                IpAddr::V4(v4) => {
                    if is_link_local_v4(v4) || is_cgnat_v4(v4) {
                        return false;
                    }
                    true
                }
                IpAddr::V6(v6) => {
                    let octets = v6.octets();
                    if is_link_local_v6(&octets) || is_tailscale_ula(&octets) {
                        return false;
                    }
                    true
                }
            }
        })
        .copied()
        .collect()
}

/// Whether an IPv6 address is link-local (fe80::/10).
fn is_link_local_v6(octets: &[u8; 16]) -> bool {
    octets[0] == 0xfe && (octets[1] & 0xC0) == 0x80
}

/// Whether an interface name is "interesting" for network change monitoring.
///
/// Strips trailing ASCII digits from the name, then returns false if the base
/// name is one of the known uninteresting prefixes (mirrors Go's darwin
/// `isInterestingInterface`). Applied on all platforms as the default filter.
pub(crate) fn is_interesting_interface(name: &str) -> bool {
    let base: String = name
        .chars()
        .rev()
        .skip_while(char::is_ascii_digit)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    !matches!(
        base.as_str(),
        "llw" | "awdl" | "ipsec" | "gif" | "XHC" | "anpi" | "lo" | "utun"
    )
}

/// Heuristic Tailscale interface detection: true if the name starts with
/// `utun`, equals `Tailscale`, or starts with `tailscale`.
pub(crate) fn is_tailscale_interface(name: &str, _ips: &[IpPrefix]) -> bool {
    name.starts_with("utun") || name == "Tailscale" || name.starts_with("tailscale")
}

/// Look up the default route interface name. Best-effort; returns an empty
/// string on any failure.
pub fn default_route_interface() -> String {
    default_route_interface_impl()
}

#[cfg(target_os = "macos")]
fn default_route_interface_impl() -> String {
    let output = match std::process::Command::new("/sbin/route")
        .args(["-n", "get", "default"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return String::new(),
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("interface:") {
            let name = rest.trim();
            if !name.is_empty() {
                return name.to_string();
            }
        }
    }
    String::new()
}

#[cfg(target_os = "linux")]
fn default_route_interface_impl() -> String {
    let contents = match std::fs::read_to_string("/proc/net/route") {
        Ok(c) => c,
        Err(_) => return String::new(),
    };
    for line in contents.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 8 && fields[1] == "00000000" && fields[7] == "00000000" {
            return fields[0].to_string();
        }
    }
    String::new()
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn default_route_interface_impl() -> String {
    String::new()
}

impl State {
    /// Whether two states are exactly equal (all fields compared).
    pub fn equal(&self, other: &State) -> bool {
        self.have_v4 == other.have_v4
            && self.have_v6 == other.have_v6
            && self.default_route_interface == other.default_route_interface
            && self.interface_ips == other.interface_ips
            && self.interface_meta == other.interface_meta
    }

    /// Whether `self` (the new state) is a "major" change from `old`.
    ///
    /// Mirrors Go's `isInterestingInterfaceChange`: for each interface present
    /// in one state but not the other (excluding Tailscale interfaces), if it
    /// has routable IPs in the state where it's up, that's major. For
    /// interfaces present in both, an up/down transition or a routable-IP
    /// set change is major. Default-route-only changes are NOT major.
    pub fn is_major_change_from(&self, old: &State) -> bool {
        direction_major(old, self) || direction_major(self, old)
    }

    /// Whether any usable interface is up (we have v4 or v6 connectivity).
    pub fn any_interface_up(&self) -> bool {
        self.have_v4 || self.have_v6
    }
}

/// One direction of the major-change comparison: iterate `from`'s interfaces
/// and compare against `to`'s. Returns true on the first interesting
/// difference (interface removed, up/down transition, or routable IP set
/// changed).
fn direction_major(from: &State, to: &State) -> bool {
    for name in from.interface_meta.keys() {
        if is_tailscale_interface(name, &[]) {
            continue;
        }
        let from_ips = filter_routable_ips(from.interface_ips.get(name).unwrap_or(&Vec::new()));
        if from_ips.is_empty() {
            continue;
        }
        let Some(to_meta) = to.interface_meta.get(name) else {
            return true;
        };
        let to_ips = filter_routable_ips(to.interface_ips.get(name).unwrap_or(&Vec::new()));
        let from_up = from.interface_meta.get(name).is_some_and(|m| m.is_up);
        if from_up != to_meta.is_up || sorted_ne(&from_ips, &to_ips) {
            return true;
        }
    }
    false
}

/// Whether two unsorted IP prefix lists differ (order-independent).
fn sorted_ne(a: &[IpPrefix], b: &[IpPrefix]) -> bool {
    if a.len() != b.len() {
        return true;
    }
    let mut a_sorted: Vec<&IpPrefix> = a.iter().collect();
    let mut b_sorted: Vec<&IpPrefix> = b.iter().collect();
    a_sorted.sort();
    b_sorted.sort();
    a_sorted != b_sorted
}
