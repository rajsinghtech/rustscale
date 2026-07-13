//! Traffic classification logic — port of Go's `addNewVirtConnLocked` +
//! `withinRoutesLocked` in `netlog.go`.
//!
//! Classifies a virtual (tun) connection into one of four buckets:
//! - [`ConnectionType::Virtual`]: src is self, dst is a known tailnet peer
//! - [`ConnectionType::Subnet`]: src is self, dst is within subnet routes
//! - [`ConnectionType::Exit`]: src is self, dst is external (not tailnet, not subnet)
//! - [`ConnectionType::Unknown`]: neither endpoint resolves to a known node
//!
//! When the local node is acting as a subnet router or exit node, the
//! classification is reversed: dst is the known tailnet peer and src is
//! the route/exit address.

use std::collections::HashMap;
use std::net::IpAddr;

use rustscale_netlogtype::Node;
use rustscale_tsaddr::IpPrefix;

use crate::record::ConnectionType;

/// Classify a virtual (tun) connection based on the self node, known
/// peer nodes, and configured routes.
///
/// Mirrors Go's `addNewVirtConnLocked` classification switch.
///
/// # Arguments
/// * `src_is_self` — whether the source address resolves to the self node
/// * `dst_node_valid` — whether the destination address resolves to a known node
/// * `src` / `dst` — the connection endpoints (for route membership checks)
/// * `route_addrs` — set of single-IP route addresses (Tailscale IPs + subnet single-IPs)
/// * `route_prefixes` — CIDR route prefixes (subnet routes)
#[allow(clippy::implicit_hasher)]
pub fn classify_virtual_traffic(
    src_is_self: bool,
    dst_node_valid: bool,
    src: IpAddr,
    dst: IpAddr,
    route_addrs: &std::collections::HashSet<IpAddr>,
    route_prefixes: &[IpPrefix],
) -> ConnectionType {
    match (src_is_self, dst_node_valid) {
        (true, true) => ConnectionType::Virtual,
        (true, false) => {
            // src is self, dst is not a known peer.
            if within_routes(dst, route_addrs, route_prefixes) {
                ConnectionType::Subnet // a client using another subnet router
            } else {
                ConnectionType::Exit // a client using an exit node
            }
        }
        (false, true) => {
            // dst is a known peer, src is not self — we're acting as
            // a subnet router or exit node for the dst peer.
            if within_routes(src, route_addrs, route_prefixes) {
                ConnectionType::Subnet // serving as a subnet router
            } else {
                ConnectionType::Exit // serving as an exit node
            }
        }
        (false, false) => ConnectionType::Unknown,
    }
}

/// Whether `addr` is within the configured routes. Mirrors Go's
/// `withinRoutesLocked`.
///
/// Matches single-IP routes (in `route_addrs`) and CIDR prefixes
/// (in `route_prefixes`). A prefix with `bits == 0` is rejected (it
/// would match everything, which is the exit-node default route, not a
/// subnet route).
#[allow(clippy::implicit_hasher)]
pub fn within_routes(
    addr: IpAddr,
    route_addrs: &std::collections::HashSet<IpAddr>,
    route_prefixes: &[IpPrefix],
) -> bool {
    if route_addrs.contains(&addr) {
        return true;
    }
    for p in route_prefixes {
        if p.bits > 0 && p.contains(addr) {
            return true;
        }
    }
    false
}

/// Determine whether `addr` resolves to the self node.
///
/// In Go, this is `srcNode.Valid() && srcNode.ID() == selfNode.ID()`.
/// Here we check whether `node_by_addr(addr)` returned a node whose
/// `node_id` matches `self_node_id`.
#[allow(clippy::implicit_hasher)]
pub fn is_self_node(addr: IpAddr, self_node_id: &str, seen_nodes: &HashMap<IpAddr, Node>) -> bool {
    if self_node_id.is_empty() {
        return false;
    }
    seen_nodes
        .get(&addr)
        .is_some_and(|n| n.node_id == self_node_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn test_classify_virtual_self_to_peer() {
        let t = classify_virtual_traffic(
            true,
            true,
            ip("100.64.0.1"),
            ip("100.64.0.2"),
            &HashSet::new(),
            &[],
        );
        assert_eq!(t, ConnectionType::Virtual);
    }

    #[test]
    fn test_classify_virtual_self_to_subnet() {
        let mut addrs = HashSet::new();
        addrs.insert(ip("10.0.0.0"));
        let prefixes = vec![IpPrefix {
            ip: ip("10.0.0.0"),
            bits: 24,
        }];
        // src is self, dst is 10.0.0.5 (within 10.0.0.0/24) → Subnet
        let t = classify_virtual_traffic(
            true,
            false,
            ip("100.64.0.1"),
            ip("10.0.0.5"),
            &addrs,
            &prefixes,
        );
        assert_eq!(t, ConnectionType::Subnet);
    }

    #[test]
    fn test_classify_virtual_self_to_exit() {
        // src is self, dst is 8.8.8.8 (not in routes, not a known peer) → Exit
        let t = classify_virtual_traffic(
            true,
            false,
            ip("100.64.0.1"),
            ip("8.8.8.8"),
            &HashSet::new(),
            &[],
        );
        assert_eq!(t, ConnectionType::Exit);
    }

    #[test]
    fn test_classify_virtual_subnet_router() {
        // We're acting as a subnet router: dst is a known peer, src is within routes.
        let prefixes = vec![IpPrefix {
            ip: ip("10.0.0.0"),
            bits: 24,
        }];
        let t = classify_virtual_traffic(
            false,
            true,
            ip("10.0.0.5"),
            ip("100.64.0.2"),
            &HashSet::new(),
            &prefixes,
        );
        assert_eq!(t, ConnectionType::Subnet);
    }

    #[test]
    fn test_classify_virtual_exit_node() {
        // We're acting as an exit node: dst is a known peer, src is external.
        let t = classify_virtual_traffic(
            false,
            true,
            ip("8.8.8.8"),
            ip("100.64.0.2"),
            &HashSet::new(),
            &[],
        );
        assert_eq!(t, ConnectionType::Exit);
    }

    #[test]
    fn test_classify_virtual_unknown() {
        let t = classify_virtual_traffic(
            false,
            false,
            ip("8.8.8.8"),
            ip("1.1.1.1"),
            &HashSet::new(),
            &[],
        );
        assert_eq!(t, ConnectionType::Unknown);
    }

    #[test]
    fn test_within_routes_single_addr() {
        let mut addrs = HashSet::new();
        addrs.insert(ip("10.0.0.1"));
        assert!(within_routes(ip("10.0.0.1"), &addrs, &[]));
        assert!(!within_routes(ip("10.0.0.2"), &addrs, &[]));
    }

    #[test]
    fn test_within_routes_prefix() {
        let prefixes = vec![IpPrefix {
            ip: ip("10.0.0.0"),
            bits: 24,
        }];
        assert!(within_routes(ip("10.0.0.5"), &HashSet::new(), &prefixes));
        assert!(!within_routes(ip("10.0.1.5"), &HashSet::new(), &prefixes));
    }

    #[test]
    fn test_within_routes_rejects_default_route() {
        // A /0 prefix would match everything; Go rejects it (bits > 0 check).
        let prefixes = vec![IpPrefix {
            ip: ip("0.0.0.0"),
            bits: 0,
        }];
        assert!(!within_routes(ip("8.8.8.8"), &HashSet::new(), &prefixes));
    }

    #[test]
    fn test_is_self_node_match() {
        let mut seen = HashMap::new();
        seen.insert(
            ip("100.64.0.1"),
            Node {
                node_id: "nABC".to_string(),
                ..Default::default()
            },
        );
        assert!(is_self_node(ip("100.64.0.1"), "nABC", &seen));
        assert!(!is_self_node(ip("100.64.0.1"), "nXYZ", &seen));
        assert!(!is_self_node(ip("100.64.0.2"), "nABC", &seen));
    }

    #[test]
    fn test_is_self_node_empty_id() {
        assert!(!is_self_node(ip("100.64.0.1"), "", &HashMap::new()));
    }

    #[test]
    fn test_within_routes_ipv6() {
        let prefixes = vec![IpPrefix {
            ip: ip("fd00::"),
            bits: 64,
        }];
        assert!(within_routes(ip("fd00::1"), &HashSet::new(), &prefixes));
        assert!(!within_routes(
            ip("2001:db8::1"),
            &HashSet::new(),
            &prefixes
        ));
    }

    #[test]
    fn test_within_routes_mixed_family() {
        // IPv4 address should not match an IPv6 prefix.
        let prefixes = vec![IpPrefix {
            ip: ip("fd00::"),
            bits: 64,
        }];
        assert!(!within_routes(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            &HashSet::new(),
            &prefixes
        ));
    }
}
