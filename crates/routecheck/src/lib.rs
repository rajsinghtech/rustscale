//! Local subnet-route conflict detection for advertised Tailscale routes.
//!
//! The crate accepts caller-provided snapshots rather than querying the live
//! network, making route validation deterministic and straightforward to test.

mod conflict;
pub mod forwarding;
mod types;

pub use types::{Conflict, ConflictKind, RouteCheckReport, Severity};

use rustscale_netmon::State as NetState;
use rustscale_routetable::RouteEntry;
use rustscale_tsaddr::IpPrefix;

/// Check candidate advertised routes for local conflicts and forwarding setup.
///
/// `net_state` and `route_table` are snapshots supplied by the caller; pass an
/// empty route table when route-table checks are unavailable. The named
/// Tailscale interface is excluded from local-conflict detection.
pub fn check_routes(
    candidate_routes: &[IpPrefix],
    net_state: &NetState,
    route_table: &[RouteEntry],
    tailscale_iface_name: Option<&str>,
) -> RouteCheckReport {
    let mut conflicts = conflict::check_conflicts(
        candidate_routes,
        net_state,
        route_table,
        tailscale_iface_name,
    );
    conflicts.extend(forwarding::check_ip_forwarding(candidate_routes));
    RouteCheckReport { conflicts }
}
