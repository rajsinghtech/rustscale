//! Gateway and self-IP discovery for the port mapper.
//!
//! Finds the default gateway IPv4 address and our local IPv4 address toward
//! it. On macOS this parses `route -n get default` output (which gives both
//! the interface and the gateway); on Linux it reads `/proc/net/route` for
//! the gateway and then looks up the interface IP via `if_addrs`.
//!
//! The lookup is pluggable: [`Client::set_gateway_lookup`] can inject a
//! synthetic [`GatewayInfo`] for testing so no real LAN is required.

use std::net::Ipv4Addr;

use rustscale_deephash::{DeepHash, Hasher};

/// The gateway IP and our local IP toward it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GatewayInfo {
    /// The default gateway IPv4 address.
    pub gateway: Ipv4Addr,
    /// Our local IPv4 address on the interface facing the gateway.
    pub self_ip: Ipv4Addr,
}

impl DeepHash for GatewayInfo {
    fn deep_hash(&self, hasher: &mut Hasher) {
        self.gateway.deep_hash(hasher);
        self.self_ip.deep_hash(hasher);
    }
}

impl GatewayInfo {
    /// A test gateway on loopback with a synthetic self IP.
    #[cfg(test)]
    pub(crate) fn test_default() -> Self {
        Self {
            gateway: Ipv4Addr::LOCALHOST,
            self_ip: Ipv4Addr::new(1, 2, 3, 4),
        }
    }
}

/// Discover the default gateway IPv4 and our local IPv4 toward it.
///
/// Returns `None` if the gateway can't be determined (no default route, not
/// IPv4, or the platform lookup fails). Mirrors Go's
/// `netmon.LikelyHomeRouterIP`.
#[must_use]
pub fn likely_home_router_ip() -> Option<GatewayInfo> {
    likely_home_router_ip_impl()
}

#[cfg(target_os = "macos")]
fn likely_home_router_ip_impl() -> Option<GatewayInfo> {
    let output = std::process::Command::new("/sbin/route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut gateway: Option<Ipv4Addr> = None;
    let mut interface: Option<String> = None;
    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("gateway:") {
            gateway = rest.trim().parse().ok();
        } else if let Some(rest) = trimmed.strip_prefix("interface:") {
            interface = Some(rest.trim().to_string());
        }
    }
    let gateway = gateway?;
    let interface = interface?;
    let self_ip = ip_for_interface(&interface)?;
    Some(GatewayInfo { gateway, self_ip })
}

#[cfg(target_os = "linux")]
fn likely_home_router_ip_impl() -> Option<GatewayInfo> {
    let contents = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in contents.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 4 && fields[1] == "00000000" {
            // Gateway is field[2] in little-endian hex.
            let gw_hex = fields[2];
            if gw_hex == "00000000" {
                continue;
            }
            let gateway = parse_le_hex_ipv4(gw_hex)?;
            let interface = fields[0];
            let self_ip = ip_for_interface(interface)?;
            return Some(GatewayInfo { gateway, self_ip });
        }
    }
    None
}

/// Parse a little-endian hex IPv4 address from `/proc/net/route` (e.g.
/// "0100A8C0" -> 192.168.0.1).
#[cfg(target_os = "linux")]
fn parse_le_hex_ipv4(hex: &str) -> Option<Ipv4Addr> {
    let val = u32::from_str_radix(hex, 16).ok()?;
    // /proc/net/route stores the address in network byte order as a
    // little-endian u32, so we need to swap bytes.
    let bytes = val.to_le_bytes();
    Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn likely_home_router_ip_impl() -> Option<GatewayInfo> {
    None
}

/// Find the first non-loopback, non-link-local IPv4 address on the named
/// interface. Falls back to loopback if nothing else is present.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn ip_for_interface(name: &str) -> Option<Ipv4Addr> {
    let ifaces = if_addrs::get_if_addrs().ok()?;
    let mut loopback_fallback: Option<Ipv4Addr> = None;
    for iface in &ifaces {
        if iface.name != name {
            continue;
        }
        if let std::net::IpAddr::V4(v4) = iface.ip() {
            if v4.is_loopback() {
                if loopback_fallback.is_none() {
                    loopback_fallback = Some(v4);
                }
                continue;
            }
            if is_link_local(v4) || v4.is_unspecified() {
                continue;
            }
            return Some(v4);
        }
    }
    loopback_fallback
}

/// Whether an IPv4 address is link-local (169.254.0.0/16).
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn is_link_local(addr: Ipv4Addr) -> bool {
    let o = addr.octets();
    o[0] == 169 && o[1] == 254
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_gateway_info() {
        let gi = GatewayInfo::test_default();
        assert_eq!(gi.gateway, Ipv4Addr::LOCALHOST);
        assert_eq!(gi.self_ip, Ipv4Addr::new(1, 2, 3, 4));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_le_hex_ipv4_works() {
        assert_eq!(
            parse_le_hex_ipv4("0100A8C0"),
            Some(Ipv4Addr::new(192, 168, 0, 1))
        );
        assert_eq!(
            parse_le_hex_ipv4("0100FEA9"),
            Some(Ipv4Addr::new(169, 254, 0, 1))
        );
    }
}
