//! The netcheck prober: given a `DERPMap`, probe each region's nodes over UDP
//! STUN, measure latency, detect NAT mapping variation, and pick a preferred
//! DERP region.
//!
//! Ports the runtime behaviour of Go's `net/netcheck` package, simplified:
//! - one probe per region (the first non-`STUNOnly` node, or the first node
//!   if all are STUN-only), retried a few times with backoff;
//! - latency measured from send to first matching response;
//! - `MappingVariesByDestIP` set once we have two IPv4 reflexive endpoints that
//!   disagree (or `Some(false)` once we have two that agree);
//! - preferred region = lowest latency, with a small absolute-diff hysteresis
//!   to avoid flapping (structure kept simple so full `preferredDERPFrameTime`
//!   stickiness can be added later).
//!
//! Each probe binds its own ephemeral UDP socket on the matching family, sends
//! a STUN binding request, and waits for a response on the same socket. This
//! keeps the implementation self-contained and testable against an in-process
//! fake STUN server (see `tests`).

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use rustscale_tailcfg::{DERPMap, DERPNode};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::captivedetection::Detector;
use crate::report::{pick_preferred, ProbeProto, Report};
use crate::stun::{new_tx_id, parse_response, request};
use rustscale_health::{Tracker, WARN_CAPTIVE_PORTAL};

/// Maximum time a single [`Prober::run`] will spend gathering a report.
pub const REPORT_TIMEOUT: Duration = Duration::from_secs(5);

/// Per-probe receive timeout. If a STUN reply doesn't arrive within this
/// window, we retry (up to `max_retries`).
const PROBE_TIMEOUT: Duration = Duration::from_millis(500);

/// How many times to retry a probe against a single region before giving up.
const MAX_PROBE_RETRIES: usize = 3;

/// Initial retransmit interval for the first probe of an unknown region.
const INITIAL_RETRANSMIT: Duration = Duration::from_millis(100);

/// Minimum absolute latency difference that will cause a preferred-DERP switch.
/// Mirrors Go's `preferredDERPAbsoluteDiff` — keeps nearby regions from
/// flip-flopping under jitter.
const PREFERRED_DERP_ABSOLUTE_DIFF: Duration = Duration::from_millis(10);

/// Errors produced by a netcheck run.
#[derive(Debug, thiserror::Error)]
pub enum NetcheckError {
    #[error("netcheck: DERP map has no regions to probe")]
    NoRegions,
    #[error("netcheck: could not bind a UDP socket: {0}")]
    Bind(std::io::Error),
}

/// Configuration for a netcheck prober.
#[derive(Debug, Clone)]
pub struct ProberOpts {
    /// Overall report timeout (default [`REPORT_TIMEOUT`]).
    pub report_timeout: Duration,
    /// Per-probe timeout (default [`PROBE_TIMEOUT`]).
    pub probe_timeout: Duration,
    /// Max retries per region (default [`MAX_PROBE_RETRIES`]).
    pub max_retries: usize,
    /// Previous preferred DERP region, for hysteresis. `0` means unknown.
    pub previous_preferred_derp: i32,
    /// Optional health tracker. When set, captive portal detection results
    /// are forwarded here: `Some(true)` → `set_unhealthy(WARN_CAPTIVE_PORTAL)`,
    /// `Some(false)` → `set_healthy(WARN_CAPTIVE_PORTAL)`.
    pub health: Option<Tracker>,
    /// Skip the ICMP latency fallback (used by tests that point at
    /// unreachable localhost ports where ICMP would still succeed).
    /// Default: `false` (ICMP is tried when UDP fails).
    pub skip_icmp: bool,
}

impl Default for ProberOpts {
    fn default() -> Self {
        Self {
            report_timeout: REPORT_TIMEOUT,
            probe_timeout: PROBE_TIMEOUT,
            max_retries: MAX_PROBE_RETRIES,
            previous_preferred_derp: 0,
            health: None,
            skip_icmp: false,
        }
    }
}

/// A netcheck prober. Cheap to construct and reuse.
#[derive(Debug, Default)]
pub struct Prober;

/// A single probe attempt against one node, over one transport.
#[derive(Debug, Clone)]
struct Probe {
    region_id: i32,
    addr: SocketAddr,
    proto: ProbeProto,
}

/// The outcome of probing one region.
struct ProbeOutcome {
    region_id: i32,
    proto: ProbeProto,
    latency: Duration,
    reflexive: SocketAddr,
}

impl Prober {
    /// Run a full netcheck against `dm` and return the resulting [`Report`].
    ///
    /// For each probeable region, sends a STUN binding request and waits for a
    /// matching response within the configured timeouts. Regions that don't
    /// respond are simply absent from the report's latency maps.
    pub async fn run(&self, dm: &DERPMap, opts: &ProberOpts) -> Result<Report, NetcheckError> {
        let probes = build_probe_plan(dm).await;
        if probes.is_empty() {
            return Err(NetcheckError::NoRegions);
        }

        // Pre-check OSHasIPv6: if we could bind a v6 socket to ::1, the OS
        // supports IPv6.
        let os_has_ipv6 = UdpSocket::bind("[::1]:0").await.is_ok();

        let mut report = Report {
            os_has_ipv6,
            ..Report::default()
        };

        // Drive all probes concurrently, bounded by the report timeout.
        let deadline = Instant::now() + opts.report_timeout;
        let mut handles = Vec::with_capacity(probes.len());
        for probe in probes {
            let probe_timeout = opts.probe_timeout;
            let max_retries = opts.max_retries;
            handles.push(tokio::spawn(async move {
                run_probe(probe, probe_timeout, max_retries).await
            }));
        }

        let mut outcomes = Vec::with_capacity(handles.len());
        for h in handles {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if let Ok(Ok(Some(o))) = timeout(remaining, h).await {
                outcomes.push(o);
            }
        }

        apply_outcomes(&mut report, &outcomes);

        // If all STUN probes failed (UDP is blocked), fall back to ICMP
        // latency probing — mirrors Go's `measureAllICMPLatency`. ICMP is
        // best-effort: if the socket can't be opened (no root, no
        // ping_group_range), this is silently skipped.
        if !report.udp && !opts.skip_icmp {
            let icmp_results = run_icmp_probes(dm, opts).await;
            for (region_id, latency) in icmp_results {
                report.update_latencies(region_id, ProbeProto::V4, latency);
                report.icmpv4 = true;
            }
        }

        report.preferred_derp =
            pick_with_hysteresis(&report.region_latency, opts.previous_preferred_derp);

        // Run captive portal detection when we have no UDP connectivity (the
        // Go netcheck runs it on every full report via a delayed timer; we
        // gate it on `!report.udp` since if UDP works, there's no captive
        // portal intercepting traffic). The detection runs concurrently with
        // a short delay — matching Go's `captivePortalDelay` of 200ms — so it
        // doesn't block the report if endpoints are unreachable.
        if !report.udp {
            let dm_clone = dm.clone();
            let preferred = report.preferred_derp;
            let captive = tokio::spawn(async move {
                // Small delay so the detection doesn't race ahead of the
                // just-finished STUN probes' cleanup.
                tokio::time::sleep(Duration::from_millis(200)).await;
                Detector.detect_bool(Some(&dm_clone), preferred).await
            })
            .await
            .ok()
            .flatten();
            report.captive_portal = captive;

            // Forward captive portal result to the health tracker.
            if let Some(ref health) = opts.health {
                match report.captive_portal {
                    Some(true) => {
                        health.set_unhealthy(WARN_CAPTIVE_PORTAL, "captive portal detected");
                    }
                    Some(false) => {
                        health.set_healthy(WARN_CAPTIVE_PORTAL);
                    }
                    None => {}
                }
            }
        }

        Ok(report)
    }
}

/// Build the probe plan: for each measurable region, one v4 probe and (if the
/// node speaks IPv6) one v6 probe, targeting the resolved address. DNS
/// resolution is performed here for nodes that carry only a hostname.
async fn build_probe_plan(dm: &DERPMap) -> Vec<Probe> {
    let mut probes = Vec::new();
    for region in dm.Regions.values() {
        if region.NoMeasureNoHome {
            continue;
        }
        let Some(nodes) = region.Nodes.as_ref() else {
            continue;
        };
        if nodes.is_empty() {
            continue;
        }
        // Prefer a non-STUNOnly node (it definitely speaks STUN on :3478), but
        // fall back to the first node if all are STUNOnly (they still speak STUN).
        let node = nodes
            .iter()
            .find(|n| !n.STUNOnly)
            .unwrap_or_else(|| &nodes[0]);
        if let Some(addr) = node_addr_port(node, ProbeProto::V4).await {
            probes.push(Probe {
                region_id: region.RegionID,
                addr,
                proto: ProbeProto::V4,
            });
        }
        if let Some(addr) = node_addr_port(node, ProbeProto::V6).await {
            probes.push(Probe {
                region_id: region.RegionID,
                addr,
                proto: ProbeProto::V6,
            });
        }
    }
    probes
}

/// Resolve the probe target address for `node` over `proto`, mirroring Go's
/// `nodeAddrPort`. When the node has an explicit IP (`IPv4`/`IPv6` or
/// `STUNTestIP`), it is parsed directly. When only a `HostName` is available,
/// it is resolved via DNS (`tokio::net::lookup_host`), and the first address
/// matching the requested family is used. Returns `None` if the field is
/// `"none"`, the IP doesn't match the family, or DNS resolution fails.
async fn node_addr_port(node: &DERPNode, proto: ProbeProto) -> Option<SocketAddr> {
    let port = stun_port(node);
    if port == 0 {
        return None;
    }
    // STUNTestIP overrides everything (used by tests).
    if !node.STUNTestIP.is_empty() {
        if let Ok(ip) = node.STUNTestIP.parse::<IpAddr>() {
            if proto.matches_ip(ip) {
                return Some(SocketAddr::new(ip, port));
            }
            return None;
        }
    }
    let field = match proto {
        ProbeProto::V4 => &node.IPv4,
        ProbeProto::V6 => &node.IPv6,
    };
    if field.is_empty() || field == "none" {
        // No explicit IP — DNS-resolve the HostName, matching Go's
        // `nodeAddrPort` fallback to `net.DefaultResolver.LookupIPAddr`.
        if node.HostName.is_empty() {
            return None;
        }
        let host = node.HostName.as_str();
        return tokio::net::lookup_host((host, port))
            .await
            .ok()?
            .find(|sa| proto.matches_ip(sa.ip()));
    }
    let ip: IpAddr = field.parse().ok()?;
    if !proto.matches_ip(ip) {
        return None;
    }
    Some(SocketAddr::new(ip, port))
}

/// The UDP port to send STUN queries to, per Go's `nodeAddrPort`. Returns 0
/// (meaning "skip") if STUN is disabled (`STUNPort < 0`), and `3478` if
/// unset (`STUNPort == 0`).
fn stun_port(node: &DERPNode) -> u16 {
    match node.STUNPort {
        p if p < 0 => 0,
        0 => 3478,
        p => p as u16,
    }
}

/// Run a single probe with retries. Binds an ephemeral UDP socket on the
/// probe's family, sends a STUN binding request, and waits for a matching
/// response. Returns the outcome if a response was received, or `None` on
/// timeout.
async fn run_probe(
    probe: Probe,
    probe_timeout: Duration,
    max_retries: usize,
) -> Option<ProbeOutcome> {
    let bind = match probe.proto {
        ProbeProto::V4 => "0.0.0.0:0",
        ProbeProto::V6 => "[::]:0",
    };
    let sock = UdpSocket::bind(bind).await.ok()?;
    let mut buf = [0u8; 1500];
    let mut backoff = INITIAL_RETRANSMIT;

    for _ in 0..max_retries {
        let tx_id = new_tx_id();
        let req = request(&tx_id);
        let started = Instant::now();
        if sock.send_to(&req, probe.addr).await.is_err() {
            break;
        }

        // Wait for a response matching this TxID. Ignore mismatched/invalid
        // packets and keep reading until the per-probe timeout expires.
        let deadline = Instant::now() + probe_timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match timeout(remaining, sock.recv_from(&mut buf)).await {
                Ok(Ok((n, _src))) => {
                    if let Ok((rx_tx, reflexive)) = parse_response(&buf[..n]) {
                        if rx_tx == tx_id {
                            return Some(ProbeOutcome {
                                region_id: probe.region_id,
                                proto: probe.proto,
                                latency: started.elapsed(),
                                reflexive,
                            });
                        }
                    }
                    // Mismatched TxID or non-STUN: keep waiting.
                    continue;
                }
                _ => break, // timeout or error
            }
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_millis(400));
    }
    None
}

/// Apply probe outcomes to the report: set UDP/IPv4/IPv6 flags, record
/// latencies, and detect NAT mapping variation.
fn apply_outcomes(report: &mut Report, outcomes: &[ProbeOutcome]) {
    let mut first_v4: Option<SocketAddr> = None;
    for o in outcomes {
        report.udp = true;
        report.update_latencies(o.region_id, o.proto, o.latency);

        match o.reflexive {
            SocketAddr::V4(_) => {
                if o.proto == ProbeProto::V4 {
                    match first_v4 {
                        None => {
                            first_v4 = Some(o.reflexive);
                            report.global_v4 = Some(o.reflexive);
                        }
                        Some(prev) => {
                            if prev != o.reflexive {
                                report.mapping_varies_by_dest_ip = Some(true);
                            } else if report.mapping_varies_by_dest_ip.is_none() {
                                report.mapping_varies_by_dest_ip = Some(false);
                            }
                        }
                    }
                }
            }
            SocketAddr::V6(_) => {
                if o.proto == ProbeProto::V6 && report.global_v6.is_none() {
                    report.global_v6 = Some(o.reflexive);
                }
            }
        }
    }
}

/// Run ICMP echo probes against each measurable DERP region's first node,
/// returning `(region_id, rtt)` pairs for successful probes. Mirrors Go's
/// `measureAllICMPLatency`. Best-effort: if the ICMP socket can't be opened,
/// returns an empty vec.
async fn run_icmp_probes(dm: &DERPMap, opts: &ProberOpts) -> Vec<(i32, Duration)> {
    // Build the list of (region_id, ipv4) targets, resolving DNS as needed.
    let mut targets = Vec::new();
    for region in dm.Regions.values() {
        if region.NoMeasureNoHome {
            continue;
        }
        let Some(nodes) = region.Nodes.as_ref() else {
            continue;
        };
        if nodes.is_empty() {
            continue;
        }
        let node = &nodes[0];
        if node.STUNPort < 0 {
            continue;
        }
        if let Some(addr) = node_addr_port(node, ProbeProto::V4).await {
            targets.push((region.RegionID, addr.ip()));
        }
    }
    if targets.is_empty() {
        return Vec::new();
    }

    let deadline = Instant::now() + opts.report_timeout;
    let mut handles = Vec::with_capacity(targets.len());
    for (region_id, ip) in targets {
        handles.push(tokio::spawn(async move {
            // Each task opens its own ICMP socket — unprivileged datagram
            // ICMP allows multiple sockets; raw ICMP might fail for the 2nd.
            let mut pinger = crate::icmp::Pinger::new_v4()?;
            let rtt = pinger.ping(ip, b"rustscale-netcheck").await?;
            Some((region_id, rtt))
        }));
    }

    let mut results = Vec::new();
    for h in handles {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if let Ok(Ok(Some((rid, rtt)))) = timeout(remaining, h).await {
            results.push((rid, rtt));
        }
    }
    results
}

/// Choose the preferred DERP region with hysteresis: if the previous preferred
/// region is still reachable and the new best is only slightly faster (within
/// `PREFERRED_DERP_ABSOLUTE_DIFF`), keep the old one.
fn pick_with_hysteresis(region_latency: &BTreeMap<i32, Duration>, previous: i32) -> i32 {
    let best = pick_preferred(region_latency);
    if best == 0 {
        return previous;
    }
    if previous == 0 || best == previous {
        return best;
    }
    let Some(&best_d) = region_latency.get(&best) else {
        return best;
    };
    let Some(&prev_d) = region_latency.get(&previous) else {
        return best;
    };
    // Keep the old region if it's still reachable and the improvement is small.
    if prev_d <= best_d + PREFERRED_DERP_ABSOLUTE_DIFF {
        previous
    } else {
        best
    }
}

#[cfg(test)]
mod tests;
