//! macOS integration test: calls `get_route_table` and asserts that the
//! system has at least one route and a default route.
//!
//! Ports `TestGetRouteTable` from `routetable_bsd_test.go`.

#![cfg(target_os = "macos")]

use rustscale_routetable::{get_route_table, RouteDestination, RouteType};

#[test]
fn test_get_route_table() {
    let routes = get_route_table(1000).expect("get_route_table should succeed on macOS");

    assert!(
        !routes.is_empty(),
        "expected at least one route entry; got empty list"
    );

    // Basic assertion: we have at least one default route (0.0.0.0/0 or ::/0).
    let has_default = routes.iter().any(is_default_route);
    assert!(
        has_default,
        "expected at least one default route; routes={routes:?}"
    );
}

fn is_default_route(entry: &rustscale_routetable::RouteEntry) -> bool {
    is_default_v4(&entry.dst) || is_default_v6(&entry.dst)
}

fn is_default_v4(dst: &RouteDestination) -> bool {
    let std::net::IpAddr::V4(ip) = dst.addr else {
        return false;
    };
    ip.is_unspecified() && dst.bits == 0
}

fn is_default_v6(dst: &RouteDestination) -> bool {
    let std::net::IpAddr::V6(ip) = dst.addr else {
        return false;
    };
    ip.is_unspecified() && dst.bits == 0
}

#[test]
fn test_route_entries_well_formed() {
    let routes = get_route_table(1000).expect("get_route_table should succeed");

    for entry in &routes {
        // Family should be 4 or 6.
        assert!(
            entry.family == 4 || entry.family == 6,
            "unexpected family {}",
            entry.family
        );
        // Family should match the destination IP type.
        match entry.dst.addr {
            std::net::IpAddr::V4(_) => assert_eq!(entry.family, 4),
            std::net::IpAddr::V6(_) => assert_eq!(entry.family, 6),
        }
        // Route type should not be unspecified for real entries.
        assert_ne!(
            entry.route_type,
            RouteType::Unspecified,
            "route type should not be unspecified"
        );
        // Prefix bits should be within range.
        match entry.dst.addr {
            std::net::IpAddr::V4(_) => assert!(entry.dst.bits <= 32),
            std::net::IpAddr::V6(_) => assert!(entry.dst.bits <= 128),
        }
    }
}
