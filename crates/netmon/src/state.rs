//! Network interface state snapshot: enumeration, filtering, and comparison.
//!
//! Ports the semantics of Go's `net/netmon/state.go` in simplified form.
//! [`gather_state`] enumerates all interfaces via `if_addrs`, records their
//! names, IPs, prefix lengths, and up/loopback flags, then computes
//! `have_v4`/`have_v6` over interesting, up, non-Tailscale interfaces with
//! routable IPs.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::interfaces::gather_interface_details;

/// An IP address with a prefix length (subnet mask bit count).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct IpPrefix {
    /// The interface IP address.
    pub ip: IpAddr,
    /// The prefix length (number of leading 1-bits in the netmask).
    pub bits: u8,
}

/// Classification of an interface's link type, based on name heuristics.
///
/// Mirrors Go's interface name-based classification (e.g. `utun` → tunnel,
/// `wlan`/`wl` → wifi, `eth`/`en` → wired, `ppp`/`rmnet` → mobile).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub enum LinkType {
    /// Unclassified.
    #[default]
    Unknown,
    /// Ethernet / wired (en0, eth0, etc.)
    Wired,
    /// Wi-Fi (wlan0, wl0, etc.)
    Wifi,
    /// Cellular / mobile broadband (ppp0, rmnet0, etc.)
    Mobile,
    /// Loopback (lo0, lo, etc.)
    Loopback,
    /// Tunnel (utun, tun, tailscale, etc.)
    Tunnel,
}

/// Lightweight interface metadata used for change detection.
///
/// Mirrors Go's `netmon.Interface` fields: Index, MTU, Flags, HardwareAddr,
/// plus the IsUp/IsLoopback booleans used by the change-detection logic.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterfaceMeta {
    /// Whether the interface is operationally up.
    pub is_up: bool,
    /// Whether the interface is a loopback interface.
    pub is_loopback: bool,
    /// Interface index (from `getifaddrs` / `if_nametoindex`). Zero if
    /// unavailable.
    pub index: u32,
    /// Maximum transmission unit (from `ioctl(SIOCGIFMTU)`). Zero if
    /// unavailable.
    pub mtu: u32,
    /// Interface flags (from `getifaddrs` `ifa_flags`).
    pub flags: u32,
    /// Hardware (MAC) address, if available.
    pub hw_addr: Option<[u8; 6]>,
    /// Classified link type based on interface name heuristics.
    pub link_type: LinkType,
}

impl Default for InterfaceMeta {
    fn default() -> Self {
        Self {
            is_up: false,
            is_loopback: false,
            index: 0,
            mtu: 0,
            flags: 0,
            hw_addr: None,
            link_type: LinkType::Unknown,
        }
    }
}

/// Details about the default route, mirroring Go's `DefaultRouteDetails`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Route {
    /// Interface name owning the default route (e.g. "en0", "eth0").
    pub interface_name: String,
    /// Interface index (zero if not populated).
    pub interface_index: u32,
    /// Gateway IP address, if known.
    pub gateway: Option<IpAddr>,
}

/// A single interface entry, combining metadata and configured IP prefixes.
#[derive(Clone, Debug)]
pub struct InterfaceEntry {
    /// Interface name.
    pub name: String,
    /// Interface metadata.
    pub meta: InterfaceMeta,
    /// IP prefixes configured on this interface.
    pub prefixes: Vec<IpPrefix>,
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
    /// Interface name -> metadata.
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
    let details = gather_interface_details();

    let mut interface_ips: BTreeMap<String, Vec<IpPrefix>> = BTreeMap::new();
    let mut interface_meta: BTreeMap<String, InterfaceMeta> = BTreeMap::new();
    let mut have_v4 = false;
    let mut have_v6 = false;

    for iface in &ifaces {
        let name = iface.name.clone();
        let is_up = iface.is_oper_up();
        let is_loopback = iface.is_loopback();

        let det = details.get(&name);
        let prefix = prefix_from_iface(iface);
        interface_ips.entry(name.clone()).or_default().push(prefix);

        let link_type = link_type_from_name(&name, is_loopback);
        let meta = InterfaceMeta {
            is_up,
            is_loopback,
            index: det.map_or(0, |d| d.index),
            mtu: det.map_or(0, |d| d.mtu),
            flags: det.map_or(0, |d| d.flags),
            hw_addr: det.and_then(|d| d.hw_addr),
            link_type,
        };
        interface_meta.insert(name.clone(), meta);

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

    let route = default_route();
    let default_route_interface = route.interface_name.clone();

    Some(State {
        interface_ips,
        interface_meta,
        have_v4,
        have_v6,
        default_route_interface,
    })
}

/// Enumerate all interfaces with their metadata and IP prefixes.
///
/// Equivalent to Go's `GetInterfaceList()` + `ForeachInterface`.
pub fn get_interface_list() -> Vec<InterfaceEntry> {
    let ifaces = match if_addrs::get_if_addrs() {
        Ok(i) => i,
        Err(_) => return Vec::new(),
    };
    let details = gather_interface_details();

    let mut by_name: BTreeMap<String, (InterfaceMeta, Vec<IpPrefix>)> = BTreeMap::new();

    for iface in &ifaces {
        let name = iface.name.clone();
        let is_up = iface.is_oper_up();
        let is_loopback = iface.is_loopback();
        let det = details.get(&name);
        let prefix = prefix_from_iface(iface);

        let entry = by_name.entry(name.clone()).or_insert_with(|| {
            let link_type = link_type_from_name(&name, is_loopback);
            (
                InterfaceMeta {
                    is_up,
                    is_loopback,
                    index: det.map_or(0, |d| d.index),
                    mtu: det.map_or(0, |d| d.mtu),
                    flags: det.map_or(0, |d| d.flags),
                    hw_addr: det.and_then(|d| d.hw_addr),
                    link_type,
                },
                Vec::new(),
            )
        });
        entry.1.push(prefix);
    }

    by_name
        .into_iter()
        .map(|(name, (meta, prefixes))| InterfaceEntry {
            name,
            meta,
            prefixes,
        })
        .collect()
}

/// Detect whether any non-Tailscale, up interface has an address in the
/// Tailscale CGNAT range (100.64.0.0/10).
///
/// Mirrors Go's `Monitor.HasCGNATInterface`.
pub fn has_cgnat_interface(state: &State) -> bool {
    for (name, prefixes) in &state.interface_ips {
        if is_tailscale_interface(name, &[]) {
            continue;
        }
        let meta = match state.interface_meta.get(name) {
            Some(m) => m,
            None => continue,
        };
        if !meta.is_up {
            continue;
        }
        for pfx in prefixes {
            if let IpAddr::V4(v4) = pfx.ip {
                if is_cgnat_v4(v4) {
                    return true;
                }
            }
        }
    }
    false
}

/// Classify an interface's link type based on its name.
pub fn link_type_from_name(name: &str, is_loopback: bool) -> LinkType {
    if is_loopback {
        return LinkType::Loopback;
    }
    let base = strip_trailing_digits(name);
    if base.starts_with("wl") || base == "wlan" || base.starts_with("wifi") {
        return LinkType::Wifi;
    }
    if base.starts_with("en") || base.starts_with("eth") {
        return LinkType::Wired;
    }
    if base.starts_with("ppp")
        || base.starts_with("rmnet")
        || base.starts_with("ccmni")
        || base.starts_with("usb")
        || base.starts_with("ww")
    {
        return LinkType::Mobile;
    }
    if base.starts_with("utun")
        || base.starts_with("tun")
        || base.starts_with("tailscale")
        || base.starts_with("wg")
    {
        return LinkType::Tunnel;
    }
    LinkType::Unknown
}

/// Strip trailing ASCII digits from an interface name to get the base name.
fn strip_trailing_digits(name: &str) -> String {
    let trimmed: &str = name.trim_end_matches(|c: char| c.is_ascii_digit());
    trimmed.to_string()
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
    let base = strip_trailing_digits(name);
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
    default_route().interface_name
}

/// Look up the default route details (interface name, index, gateway IP).
/// Best-effort; returns a `Route` with empty interface name on failure.
///
/// Mirrors Go's `DefaultRoute()` returning `DefaultRouteDetails`.
pub fn default_route() -> Route {
    default_route_impl()
}

/// Parse the default route gateway IP and self IP on that interface.
///
/// Mirrors Go's `LikelyHomeRouterIP()`. Returns `(gateway, self_ip)`.
pub(crate) fn likely_home_router_ip() -> Option<(IpAddr, IpAddr)> {
    likely_home_router_ip_impl()
}

#[cfg(target_os = "macos")]
fn default_route_impl() -> Route {
    // Prefer the sysctl NET_RT_DUMP2 approach (matches Go's
    // DefaultRouteInterfaceIndex). Falls back to /sbin/route if the
    // sysctl approach fails or yields no interface name.
    if let Ok((idx, gw)) = crate::defaultroute::default_route_from_sysctl() {
        if idx > 0 {
            if let Some(iface_name) = index_to_name(idx) {
                return Route {
                    interface_name: iface_name,
                    interface_index: idx,
                    gateway: gw.or_else(gateway_from_route_command),
                };
            }
        }
    }
    // Fallback: shell out to /sbin/route.
    route_from_command()
}

/// Resolve an interface index to a name via `if_indextoname`.
#[cfg(target_os = "macos")]
fn index_to_name(idx: u32) -> Option<String> {
    let mut buf = [0i8; libc::IF_NAMESIZE];
    let ptr = unsafe { libc::if_indextoname(idx as libc::c_uint, buf.as_mut_ptr()) };
    if ptr.is_null() {
        return None;
    }
    Some(
        unsafe { std::ffi::CStr::from_ptr(ptr) }
            .to_string_lossy()
            .to_string(),
    )
}

/// Run `/sbin/route -n get default` and parse the interface name, index,
/// and gateway. Best-effort; returns a default `Route` on any failure.
#[cfg(target_os = "macos")]
fn route_from_command() -> Route {
    let output = match std::process::Command::new("/sbin/route")
        .args(["-n", "get", "default"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return Route::default(),
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut iface_name = String::new();
    let mut gateway: Option<IpAddr> = None;
    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("interface:") {
            let name = rest.trim();
            if !name.is_empty() {
                iface_name = name.to_string();
            }
        }
        if let Some(rest) = trimmed.strip_prefix("gateway:") {
            let gw_str = rest.trim();
            if let Ok(ip) = gw_str.parse::<IpAddr>() {
                gateway = Some(ip);
            }
        }
    }
    let interface_index = if iface_name.is_empty() {
        0
    } else {
        std::ffi::CString::new(iface_name.as_str())
            .ok()
            .and_then(|c| {
                let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
                if idx != 0 {
                    Some(idx)
                } else {
                    None
                }
            })
            .unwrap_or(0)
    };
    Route {
        interface_name: iface_name,
        interface_index,
        gateway,
    }
}

/// Extract just the gateway IP from `/sbin/route -n get default`.
#[cfg(target_os = "macos")]
fn gateway_from_route_command() -> Option<IpAddr> {
    route_from_command().gateway
}

#[cfg(target_os = "linux")]
fn default_route_impl() -> Route {
    let contents = match std::fs::read_to_string("/proc/net/route") {
        Ok(c) => c,
        Err(_) => return Route::default(),
    };
    for line in contents.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        if fields[0].starts_with("tailscale") || fields[0].starts_with("wg") {
            continue;
        }
        if fields[1] == "00000000" && fields.len() >= 8 && fields[7] == "00000000" {
            let iface_name = fields[0].to_string();
            let gateway = u32::from_str_radix(fields[2], 16)
                .ok()
                .map(|v| IpAddr::V4(Ipv4Addr::from(v.to_be())));
            let interface_index = std::ffi::CString::new(iface_name.as_str())
                .ok()
                .and_then(|c| {
                    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
                    if idx != 0 {
                        Some(idx)
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            return Route {
                interface_name: iface_name,
                interface_index,
                gateway,
            };
        }
    }
    Route::default()
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn default_route_impl() -> Route {
    Route::default()
}

#[cfg(target_os = "macos")]
fn likely_home_router_ip_impl() -> Option<(IpAddr, IpAddr)> {
    let route = default_route_impl();
    let gw = route.gateway?;
    let ifname = &route.interface_name;
    if ifname.is_empty() {
        return None;
    }
    let self_ip = find_self_ip_on_interface(ifname, &gw)?;
    Some((gw, self_ip))
}

#[cfg(target_os = "linux")]
fn likely_home_router_ip_impl() -> Option<(IpAddr, IpAddr)> {
    let route = default_route_impl();
    let gw = route.gateway?;
    let ifname = &route.interface_name;
    if ifname.is_empty() {
        return None;
    }
    let self_ip = find_self_ip_on_interface(ifname, &gw)?;
    Some((gw, self_ip))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn likely_home_router_ip_impl() -> Option<(IpAddr, IpAddr)> {
    None
}

/// Find the first private IPv4 address on `ifname` that is in the same subnet
/// as `gateway`.
fn find_self_ip_on_interface(ifname: &str, gateway: &IpAddr) -> Option<IpAddr> {
    let ifaces = if_addrs::get_if_addrs().ok()?;
    let gw_v4 = match gateway {
        IpAddr::V4(v) => *v,
        _ => return None,
    };
    for iface in &ifaces {
        if iface.name != ifname {
            continue;
        }
        if let if_addrs::IfAddr::V4(ref a) = iface.addr {
            let ip = a.ip;
            let mask = a.netmask;
            let net = u32::from(ip) & u32::from(mask);
            let gw_net = u32::from(gw_v4) & u32::from(mask);
            if net == gw_net && !ip.is_loopback() && !is_link_local_v4(ip) {
                return Some(IpAddr::V4(ip));
            }
        }
    }
    None
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
