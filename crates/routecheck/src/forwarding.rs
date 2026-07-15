//! Best-effort IP forwarding validation.

#[cfg(target_os = "linux")]
use std::net::IpAddr;

use rustscale_tsaddr::IpPrefix;

use crate::types::Conflict;
#[cfg(target_os = "linux")]
use crate::types::{ConflictKind, Severity};

/// Check that IP forwarding is enabled for the protocols required by `routes`.
///
/// Linux reads the relevant procfs sysctls. Other platforms have no portable
/// equivalent, so this best-effort check returns no conflicts there.
pub fn check_ip_forwarding(routes: &[IpPrefix]) -> Vec<Conflict> {
    #[cfg(target_os = "linux")]
    {
        check_ip_forwarding_from_reader(routes, |path| std::fs::read_to_string(path).ok())
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = routes;
        Vec::new()
    }
}

#[cfg(target_os = "linux")]
fn check_ip_forwarding_from_reader(
    routes: &[IpPrefix],
    read_sysctl: impl Fn(&str) -> Option<String>,
) -> Vec<Conflict> {
    let mut conflicts = Vec::new();
    if let Some(route) = routes.iter().copied().find(is_ipv4) {
        if !sysctl_enabled(read_sysctl("/proc/sys/net/ipv4/ip_forward").as_deref()) {
            conflicts.push(forwarding_disabled(route, "IPv4"));
        }
    }
    if let Some(route) = routes.iter().copied().find(is_ipv6) {
        if !sysctl_enabled(read_sysctl("/proc/sys/net/ipv6/conf/all/forwarding").as_deref()) {
            conflicts.push(forwarding_disabled(route, "IPv6"));
        }
    }
    conflicts
}

#[cfg(target_os = "linux")]
fn sysctl_enabled(value: Option<&str>) -> bool {
    value.is_some_and(|value| value.trim() == "1")
}

#[cfg(target_os = "linux")]
fn forwarding_disabled(route: IpPrefix, protocol: &'static str) -> Conflict {
    Conflict {
        route,
        severity: Severity::Warning,
        kind: ConflictKind::IPForwardingDisabled { protocol },
        message: format!("{protocol} forwarding is disabled"),
    }
}

#[cfg(target_os = "linux")]
fn is_ipv4(route: &IpPrefix) -> bool {
    matches!(route.ip, IpAddr::V4(_))
}

#[cfg(target_os = "linux")]
fn is_ipv6(route: &IpPrefix) -> bool {
    matches!(route.ip, IpAddr::V6(_))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn disabled_sysctls_report_required_protocols() {
        let routes = [
            IpPrefix::parse("192.0.2.0/24").expect("valid IPv4 prefix"),
            IpPrefix::parse("2001:db8::/32").expect("valid IPv6 prefix"),
        ];
        let conflicts = check_ip_forwarding_from_reader(&routes, |_| Some("0\n".to_owned()));
        assert_eq!(conflicts.len(), 2);
        assert!(matches!(
            conflicts[0].kind,
            ConflictKind::IPForwardingDisabled { protocol: "IPv4" }
        ));
        assert!(matches!(
            conflicts[1].kind,
            ConflictKind::IPForwardingDisabled { protocol: "IPv6" }
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn enabled_sysctls_are_not_reported() {
        let routes = [IpPrefix::parse("192.0.2.0/24").expect("valid IPv4 prefix")];
        assert!(check_ip_forwarding_from_reader(&routes, |_| Some("1\n".to_owned())).is_empty());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn forwarding_check_is_noop() {
        let routes = [IpPrefix::parse("192.0.2.0/24").expect("valid IPv4 prefix")];
        assert!(check_ip_forwarding(&routes).is_empty());
    }
}
