//! Public types returned by route validation.

use rustscale_tsaddr::IpPrefix;

/// Severity of a detected route issue.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Severity {
    /// Route is impossible and must be removed.
    Error,
    /// Route may not work as expected.
    Warning,
}

/// The kind of route conflict detected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConflictKind {
    /// Advertised prefix overlaps a non-Tailscale local interface subnet.
    OverlapsLocalInterface { interface: String },
    /// Advertised prefix overlaps Tailscale's internal IP range (CGNAT or ULA).
    OverlapsTailscaleRange,
    /// Advertised prefix is a single IP that is one of the machine's own addresses.
    OverlapsLocalAddress { interface: String },
    /// Exit node advertised without one of v4/v6.
    ExitNodeMissingDualStack { missing: &'static str },
    /// IP forwarding sysctl is disabled (Linux only).
    IPForwardingDisabled { protocol: &'static str },
}

/// A single route conflict or warning.
#[derive(Clone, Debug)]
pub struct Conflict {
    /// The advertised route associated with this issue.
    pub route: IpPrefix,
    /// Whether the route must be removed or merely warrants attention.
    pub severity: Severity,
    /// The category of detected problem.
    pub kind: ConflictKind,
    /// A human-readable explanation of the issue.
    pub message: String,
}

/// The full routecheck report.
#[derive(Clone, Debug, Default)]
pub struct RouteCheckReport {
    /// Every detected issue, in candidate-route order.
    pub conflicts: Vec<Conflict>,
}
