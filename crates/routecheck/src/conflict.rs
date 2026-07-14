//! Route conflict detection against local interfaces and routing entries.

use std::net::IpAddr;

use rustscale_netmon::State as NetState;
use rustscale_routetable::RouteEntry;
use rustscale_tsaddr::{all_ipv4, all_ipv6, cgnat_range, tailscale_ula_range, IpPrefix};

use crate::types::{Conflict, ConflictKind, Severity};

/// Detect conflicts between candidate routes and local network state.
pub(crate) fn check_conflicts(
    candidate_routes: &[IpPrefix],
    net_state: &NetState,
    route_table: &[RouteEntry],
    tailscale_iface_name: Option<&str>,
) -> Vec<Conflict> {
    let mut conflicts = Vec::new();
    let has_v4_default = candidate_routes.iter().any(|route| *route == all_ipv4());
    let has_v6_default = candidate_routes.iter().any(|route| *route == all_ipv6());

    for &route in candidate_routes {
        if prefixes_overlap(route, cgnat_range()) || prefixes_overlap(route, tailscale_ula_range())
        {
            conflicts.push(Conflict {
                route,
                severity: Severity::Error,
                kind: ConflictKind::OverlapsTailscaleRange,
                message: "advertised route overlaps Tailscale's internal address range".to_owned(),
            });
        }

        for (interface, prefixes) in &net_state.interface_ips {
            if is_tailscale_interface(interface, tailscale_iface_name)
                || !net_state
                    .interface_meta
                    .get(interface)
                    .is_some_and(|meta| meta.is_up)
            {
                continue;
            }

            for local_prefix in prefixes {
                let local_route = IpPrefix {
                    ip: local_prefix.ip,
                    bits: local_prefix.bits,
                };
                if prefixes_overlap(route, local_route) {
                    conflicts.push(local_interface_conflict(route, interface));
                }
                if is_single_ip(route) && route.ip == local_prefix.ip {
                    conflicts.push(Conflict {
                        route,
                        severity: Severity::Warning,
                        kind: ConflictKind::OverlapsLocalAddress {
                            interface: interface.clone(),
                        },
                        message: format!(
                            "advertised route is this machine's address on interface {interface}"
                        ),
                    });
                }
            }
        }

        for entry in route_table {
            if is_tailscale_interface(&entry.iface, tailscale_iface_name) {
                continue;
            }
            let table_route = IpPrefix {
                ip: entry.dst.addr,
                bits: entry.dst.bits,
            };
            if prefixes_overlap(route, table_route) {
                conflicts.push(local_interface_conflict(route, &entry.iface));
            }
        }

        if route == all_ipv4() && !has_v6_default {
            conflicts.push(missing_dual_stack_conflict(route, "IPv6 (::/0)"));
        }
        if route == all_ipv6() && !has_v4_default {
            conflicts.push(missing_dual_stack_conflict(route, "IPv4 (0.0.0.0/0)"));
        }
    }

    conflicts
}

fn local_interface_conflict(route: IpPrefix, interface: &str) -> Conflict {
    Conflict {
        route,
        severity: Severity::Warning,
        kind: ConflictKind::OverlapsLocalInterface {
            interface: interface.to_owned(),
        },
        message: format!(
            "advertised route overlaps a local route on interface {interface}; traffic may not arrive as expected"
        ),
    }
}

fn missing_dual_stack_conflict(route: IpPrefix, missing: &'static str) -> Conflict {
    Conflict {
        route,
        severity: Severity::Error,
        kind: ConflictKind::ExitNodeMissingDualStack { missing },
        message: format!("exit-node advertisement is missing the {missing} route"),
    }
}

fn is_tailscale_interface(interface: &str, tailscale_iface_name: Option<&str>) -> bool {
    tailscale_iface_name.is_some_and(|name| name == interface)
}

fn is_single_ip(prefix: IpPrefix) -> bool {
    matches!(prefix.ip, IpAddr::V4(_)) && prefix.bits == 32
        || matches!(prefix.ip, IpAddr::V6(_)) && prefix.bits == 128
}

/// Return whether two valid CIDR prefixes overlap.
fn prefixes_overlap(left: IpPrefix, right: IpPrefix) -> bool {
    same_family(left.ip, right.ip) && (left.contains(right.ip) || right.contains(left.ip))
}

fn same_family(left: IpAddr, right: IpAddr) -> bool {
    matches!(
        (left, right),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use rustscale_netmon::{InterfaceMeta, IpPrefix as NetPrefix};
    use rustscale_routetable::{RouteDestination, RouteType};

    use super::*;
    use crate::{check_routes, RouteCheckReport};

    fn prefix(value: &str) -> IpPrefix {
        IpPrefix::parse(value).expect("valid test prefix")
    }

    fn state(interfaces: &[(&str, &str)]) -> NetState {
        let mut interface_ips = BTreeMap::new();
        let mut interface_meta = BTreeMap::new();
        for &(name, address) in interfaces {
            let address = prefix(address);
            interface_ips.insert(
                name.to_owned(),
                vec![NetPrefix {
                    ip: address.ip,
                    bits: address.bits,
                }],
            );
            interface_meta.insert(
                name.to_owned(),
                InterfaceMeta {
                    is_up: true,
                    ..InterfaceMeta::default()
                },
            );
        }
        NetState {
            interface_ips,
            interface_meta,
            have_v4: false,
            have_v6: false,
            default_route_interface: String::new(),
        }
    }

    fn report(routes: &[&str], interfaces: &[(&str, &str)]) -> RouteCheckReport {
        let routes: Vec<_> = routes.iter().map(|route| prefix(route)).collect();
        check_routes(&routes, &state(interfaces), &[], Some("tailscale0"))
    }

    fn has_conflict(report: &RouteCheckReport, severity: Severity, kind: ConflictKind) -> bool {
        report
            .conflicts
            .iter()
            .any(|conflict| conflict.severity == severity && conflict.kind == kind)
    }

    #[test]
    fn tailscale_range_rejected() {
        let report = report(&["100.64.0.0/10"], &[]);
        assert!(has_conflict(
            &report,
            Severity::Error,
            ConflictKind::OverlapsTailscaleRange
        ));
    }

    #[test]
    fn tailscale_ula_rejected() {
        let report = report(&["fd7a:115c:a1e0::/48"], &[]);
        assert!(has_conflict(
            &report,
            Severity::Error,
            ConflictKind::OverlapsTailscaleRange
        ));
    }

    #[test]
    fn overlaps_local_interface() {
        let report = report(&["192.168.1.0/24"], &[("en0", "192.168.1.0/24")]);
        assert!(has_conflict(
            &report,
            Severity::Warning,
            ConflictKind::OverlapsLocalInterface {
                interface: "en0".to_owned()
            }
        ));
    }

    #[test]
    fn subrange_of_local_interface() {
        let report = report(&["10.0.0.0/16"], &[("en0", "10.0.0.0/8")]);
        assert!(has_conflict(
            &report,
            Severity::Warning,
            ConflictKind::OverlapsLocalInterface {
                interface: "en0".to_owned()
            }
        ));
    }

    #[test]
    fn superset_of_local_interface() {
        let report = report(&["10.0.0.0/8"], &[("en0", "10.0.0.0/16")]);
        assert!(has_conflict(
            &report,
            Severity::Warning,
            ConflictKind::OverlapsLocalInterface {
                interface: "en0".to_owned()
            }
        ));
    }

    #[test]
    fn single_ip_local_addr() {
        let report = report(&["10.0.0.1/32"], &[("en0", "10.0.0.1/24")]);
        assert!(has_conflict(
            &report,
            Severity::Warning,
            ConflictKind::OverlapsLocalAddress {
                interface: "en0".to_owned()
            }
        ));
    }

    #[test]
    fn exit_node_missing_v6() {
        let report = report(&["0.0.0.0/0"], &[]);
        assert!(has_conflict(
            &report,
            Severity::Error,
            ConflictKind::ExitNodeMissingDualStack {
                missing: "IPv6 (::/0)"
            }
        ));
    }

    #[test]
    fn exit_node_missing_v4() {
        let report = report(&["::/0"], &[]);
        assert!(has_conflict(
            &report,
            Severity::Error,
            ConflictKind::ExitNodeMissingDualStack {
                missing: "IPv4 (0.0.0.0/0)"
            }
        ));
    }

    #[test]
    fn exit_node_dual_stack_ok() {
        let report = report(&["0.0.0.0/0", "::/0"], &[]);
        assert!(!report.conflicts.iter().any(|conflict| {
            matches!(conflict.kind, ConflictKind::ExitNodeMissingDualStack { .. })
        }));
    }

    #[test]
    fn no_conflicts() {
        assert!(report(&["10.99.0.0/24"], &[]).conflicts.is_empty());
    }

    #[test]
    fn tailscale_iface_excluded() {
        let report = report(&["100.100.0.0/16"], &[("tailscale0", "100.64.0.1/10")]);
        assert!(!report.conflicts.iter().any(|conflict| {
            matches!(
                &conflict.kind,
                ConflictKind::OverlapsLocalInterface { interface } if interface == "tailscale0"
            )
        }));
        assert!(has_conflict(
            &report,
            Severity::Error,
            ConflictKind::OverlapsTailscaleRange
        ));
    }

    #[test]
    fn route_table_conflict_is_reported() {
        let routes = [prefix("172.16.0.0/16")];
        let table = [RouteEntry {
            family: 4,
            route_type: RouteType::Unicast,
            dst: RouteDestination {
                addr: prefix("172.16.0.0/12").ip,
                bits: 12,
                zone: String::new(),
            },
            gateway: None,
            gateway_iface: None,
            iface: "en0".to_owned(),
            flags: Vec::new(),
            raw_flags: 0,
        }];
        let report = check_routes(&routes, &state(&[]), &table, Some("tailscale0"));
        assert!(has_conflict(
            &report,
            Severity::Warning,
            ConflictKind::OverlapsLocalInterface {
                interface: "en0".to_owned()
            }
        ));
    }
}
