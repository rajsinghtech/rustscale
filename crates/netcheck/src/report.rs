//! The `Report` produced by a netcheck — mirrors Go's `netcheck.Report`.
//!
//! This is an in-memory result type (not a wire type), so it uses idiomatic
//! `snake_case` Rust fields rather than Go's PascalCase. `MappingVariesByDestIP`
//! and the other tri-state booleans are `Option<bool>`: `None` is unset and
//! `Some(true)`/`Some(false)` is explicit.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

/// The result of a single netcheck run, describing the host's UDP/IPv4/IPv6
/// connectivity, per-DERP-region latencies, the discovered reflexive
/// (`XOR-MAPPED-ADDRESS`) endpoints, and the chosen preferred DERP region.
#[derive(Debug, Clone, Default)]
pub struct Report {
    /// When the report was produced.
    pub now: Option<SystemTime>,

    /// A UDP STUN round trip completed (any family).
    pub udp: bool,
    /// An IPv4 STUN round trip completed.
    pub ipv4: bool,
    /// An IPv6 STUN round trip completed.
    pub ipv6: bool,
    /// An IPv6 packet was able to be sent.
    pub ipv6_can_send: bool,
    /// An IPv4 packet was able to be sent.
    pub ipv4_can_send: bool,
    /// The OS could bind a socket to `::1`.
    pub os_has_ipv6: bool,
    /// An ICMPv4 round trip completed (not implemented yet; always false).
    pub icmpv4: bool,

    /// Whether the reflexive IPv4 address differs across STUN servers.
    /// `None` = not enough samples; `Some(true)` = NAT mapping varies by
    /// destination; `Some(false)` = same mapping observed for all destinations.
    pub mapping_varies_by_dest_ip: Option<bool>,

    /// The preferred (home) DERP region ID, or `0` for unknown.
    pub preferred_derp: i32,

    /// Lowest observed latency per DERP region (keyed by region ID).
    pub region_latency: BTreeMap<i32, Duration>,
    /// Lowest observed IPv4 latency per DERP region.
    pub region_v4_latency: BTreeMap<i32, Duration>,
    /// Lowest observed IPv6 latency per DERP region.
    pub region_v6_latency: BTreeMap<i32, Duration>,

    /// The best (lowest-latency) reflexive IPv4 endpoint observed.
    pub global_v4: Option<SocketAddr>,
    /// The best (lowest-latency) reflexive IPv6 endpoint observed.
    pub global_v6: Option<SocketAddr>,

    /// Port-mapping service availability (populated by the caller from a
    /// separate portmapper probe, not by the STUN prober itself). Mirrors
    /// Go's `Report.PortMapperProbe*` fields.
    pub port_mapper_pmp: bool,
    pub port_mapper_pcp: bool,
    pub port_mapper_upnp: bool,

    /// Whether a captive portal was detected during the netcheck. `None` =
    /// detection was not run or was inconclusive; `Some(true)` = a captive
    /// portal is intercepting HTTP traffic; `Some(false)` = no captive portal
    /// detected. Mirrors Go's `Report.CaptivePortal opt.Bool`.
    pub captive_portal: Option<bool>,
}

impl Report {
    /// Record `latency` for `region_id` in the per-family and aggregate maps,
    /// keeping the minimum observed value in each.
    pub(crate) fn update_latencies(
        &mut self,
        region_id: i32,
        proto: ProbeProto,
        latency: Duration,
    ) {
        update_latency(&mut self.region_latency, region_id, latency);
        match proto {
            ProbeProto::V4 => {
                update_latency(&mut self.region_v4_latency, region_id, latency);
                self.ipv4 = true;
            }
            ProbeProto::V6 => {
                update_latency(&mut self.region_v6_latency, region_id, latency);
                self.ipv6 = true;
            }
        }
    }
}

/// Insert/keep the minimum latency for `region_id` in `m`.
fn update_latency(m: &mut BTreeMap<i32, Duration>, region_id: i32, latency: Duration) {
    m.entry(region_id)
        .and_modify(|prev| {
            if latency < *prev {
                *prev = latency;
            }
        })
        .or_insert(latency);
}

/// The transport a probe used to time a node's latency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeProto {
    /// STUN over IPv4.
    V4,
    /// STUN over IPv6.
    V6,
}

impl ProbeProto {
    pub(crate) fn matches_ip(self, ip: std::net::IpAddr) -> bool {
        match self {
            ProbeProto::V4 => ip.is_ipv4(),
            ProbeProto::V6 => ip.is_ipv6(),
        }
    }
}

/// Choose the preferred DERP region: the one with the lowest latency in
/// `region_latency`, or `0` if there are no samples.
///
/// This is the simple selection rule (no hysteresis). The prober keeps the
/// structure in [`crate::prober`] so full `preferredDERPFrameTime`-style
/// stickiness can be layered in later.
#[must_use]
pub fn pick_preferred(region_latency: &BTreeMap<i32, Duration>) -> i32 {
    region_latency
        .iter()
        .min_by_key(|(_, d)| *d)
        .map_or(0, |(rid, _)| *rid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_preferred_returns_lowest_latency() {
        let mut m = BTreeMap::new();
        m.insert(1, Duration::from_millis(50));
        m.insert(2, Duration::from_millis(20));
        m.insert(3, Duration::from_millis(80));
        assert_eq!(pick_preferred(&m), 2);
    }

    #[test]
    fn pick_preferred_empty_returns_zero() {
        let m = BTreeMap::new();
        assert_eq!(pick_preferred(&m), 0);
    }

    #[test]
    fn pick_preferred_ties_pick_lowest_region_id() {
        // BTreeMap iteration is ordered by key; min_by_key returns the first
        // minimum it sees, so ties resolve to the lowest region ID.
        let mut m = BTreeMap::new();
        m.insert(7, Duration::from_millis(30));
        m.insert(3, Duration::from_millis(30));
        m.insert(11, Duration::from_millis(30));
        assert_eq!(pick_preferred(&m), 3);
    }

    #[test]
    fn update_latencies_keeps_minimum_per_family() {
        let mut r = Report::default();
        r.update_latencies(1, ProbeProto::V4, Duration::from_millis(40));
        r.update_latencies(1, ProbeProto::V4, Duration::from_millis(25));
        r.update_latencies(1, ProbeProto::V6, Duration::from_millis(60));
        assert_eq!(r.region_latency[&1], Duration::from_millis(25));
        assert_eq!(r.region_v4_latency[&1], Duration::from_millis(25));
        assert_eq!(r.region_v6_latency[&1], Duration::from_millis(60));
        assert!(r.ipv4);
        assert!(r.ipv6);
        assert!(!r.udp, "udp is set by the prober, not update_latencies");
    }
}
