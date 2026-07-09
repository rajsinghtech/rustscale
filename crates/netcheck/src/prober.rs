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

use crate::report::{pick_preferred, ProbeProto, Report};
use crate::stun::{new_tx_id, parse_response, request};

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
}

impl Default for ProberOpts {
    fn default() -> Self {
        Self {
            report_timeout: REPORT_TIMEOUT,
            probe_timeout: PROBE_TIMEOUT,
            max_retries: MAX_PROBE_RETRIES,
            previous_preferred_derp: 0,
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
        let probes = build_probe_plan(dm);
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
        report.preferred_derp =
            pick_with_hysteresis(&report.region_latency, opts.previous_preferred_derp);

        Ok(report)
    }
}

/// Build the probe plan: for each measurable region, one v4 probe and (if the
/// node speaks IPv6) one v6 probe, targeting the resolved address.
fn build_probe_plan(dm: &DERPMap) -> Vec<Probe> {
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
        if let Some(addr) = node_addr_port(node, ProbeProto::V4) {
            probes.push(Probe {
                region_id: region.RegionID,
                addr,
                proto: ProbeProto::V4,
            });
        }
        if let Some(addr) = node_addr_port(node, ProbeProto::V6) {
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
/// `nodeAddrPort` for the explicit-IP cases. DNS resolution is not performed
/// here (Tailscale-provided DERPs always carry explicit IPs); nodes with only
/// a hostname and no IP are skipped.
fn node_addr_port(node: &DERPNode, proto: ProbeProto) -> Option<SocketAddr> {
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
        // No explicit IP; a real client would DNS-resolve HostName. Skip for
        // now — the prober is tested against explicit-IP DERP maps and fake
        // servers, and real control-plane integration will add DNS later.
        return None;
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
