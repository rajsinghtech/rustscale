//! Stateful packet filter — port of Tailscale's `wgengine/filter`.
//!
//! Enforces MapResponse packet-filter rules on inbound IP packets and
//! records outbound UDP/SCTP flow state so return traffic is admitted.

#![forbid(unsafe_code)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

pub mod r#match;
pub mod packet;
pub mod parse;
pub mod prefix;
pub mod state;
#[cfg(test)]
mod tests;

pub use packet::{parse_packet, PacketInfo};
pub use r#match::{CapMatch, Match, Matches, NetPortRange, PortRange};
pub use state::{reversed_tuple, FlowState, FlowTuple};

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;

use r#match::Matches as MatchList;
use rustscale_tailcfg::{FilterRule, PeerCapMap};

/// Callback for counting packets on a connection.
///
/// Signature: `fn(proto, src, dst, packets, bytes, recv)`.
/// `recv=true` = received (Rx), `false` = transmitted (Tx).
///
/// This is structurally identical to `rustscale_netlog::ConnectionCounter`
/// — the same `Arc<dyn Fn(...)>` type — so a counter created by the
/// netlog logger can be installed directly without conversion.
pub type ConnectionCounter =
    Arc<dyn Fn(u8, (IpAddr, u16), (IpAddr, u16), u64, u64, bool) + Send + Sync>;

/// Filter verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Response {
    Accept,
    Drop,
    DropSilently,
}

impl Response {
    pub fn is_drop(&self) -> bool {
        matches!(self, Response::Drop | Response::DropSilently)
    }
}

/// Errors from filter construction.
#[derive(Debug, Clone, thiserror::Error)]
pub enum FilterError {
    #[error("filter rule parse error: {0}")]
    Parse(String),
}

/// A stateful packet filter.
pub struct Filter {
    matches4: MatchList,
    matches6: MatchList,
    local4: Vec<prefix::IpPrefix>,
    local6: Vec<prefix::IpPrefix>,
    state: FlowState,
    /// When true, deny all *new* inbound flows. Established traffic
    /// (non-SYN TCP, cached UDP/SCTP flows, ICMP echo replies/errors,
    /// TSMP) is still admitted. Mirrors Go's `NewShieldsUpFilter`.
    shields_up: bool,
    /// Map from peer tailnet IP → that peer node's capability set
    /// (the keys of `Node.CapMap`). Used to evaluate `cap:<name>`
    /// source predicates in filter rules — the Rust equivalent of
    /// Go's `LocalBackend.srcIPHasCapForFilter` closure passed as
    /// `capTest` to `filter.New`.
    cap_holders: BTreeMap<IpAddr, BTreeSet<String>>,
    /// Capability-grant matches partitioned by source address family,
    /// for `caps_with_values`. Mirrors Go's `Filter.cap4`/`cap6` built
    /// by `capMatchesFunc`. Unlike `matches4`/`matches6`, these include
    /// `CapGrant`-only rules (which have no `DstPorts`).
    cap4: MatchList,
    cap6: MatchList,
    /// Optional connection counter for network flow logging. When set,
    /// the filter calls it for each outbound packet that is parsed,
    /// providing the 5-tuple, packet count (1), and byte count (packet
    /// length). Mirrors Go's `netlogfunc.ConnectionCounter` registration
    /// in the tun device.
    connection_counter: Option<ConnectionCounter>,
}

impl Filter {
    /// Build a filter from control-plane rules, local IPs, and the
    /// peer capability map.
    ///
    /// `cap_holders` maps each peer's tailnet IP to the set of capability
    /// names that peer holds (the keys of its `Node.CapMap`). It is
    /// consulted when a rule's `SrcIPs` contains a `cap:<name>` entry.
    pub fn new(
        rules: &[FilterRule],
        local_ips: &[IpAddr],
        cap_holders: &BTreeMap<IpAddr, BTreeSet<String>>,
    ) -> Result<Self, FilterError> {
        let all_matches = parse::matches_from_filter_rules(rules)
            .map_err(|e| FilterError::Parse(e.to_string()))?;
        let matches = MatchList(all_matches);
        let (m4, m6) = matches.partition_by_family();
        let (cap4, cap6) = matches.partition_caps_by_family();

        let (local4, local6) = partition_local_ips(local_ips);

        Ok(Self {
            matches4: m4,
            matches6: m6,
            local4,
            local6,
            state: FlowState::new(),
            shields_up: false,
            cap_holders: cap_holders.clone(),
            cap4,
            cap6,
            connection_counter: None,
        })
    }

    /// Accept everything (tests / no rules). Uses wildcard localNets so
    /// any destination IP is accepted (mirrors Go's `NewAllowAllForTest`).
    pub fn allow_all() -> Self {
        let rules = rustscale_tailcfg::filter_allow_all();
        // Use wildcard prefixes as localNets (0.0.0.0/0 and ::/0).
        let local: Vec<IpAddr> = vec![
            std::net::Ipv4Addr::UNSPECIFIED.into(),
            std::net::Ipv6Addr::UNSPECIFIED.into(),
        ];
        let empty_caps = BTreeMap::new();
        let f = Self::new(&rules, &local, &empty_caps).unwrap_or_else(|_| Self {
            matches4: MatchList::default(),
            matches6: MatchList::default(),
            local4: vec![prefix::IpPrefix {
                addr: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                bits: 0,
            }],
            local6: vec![prefix::IpPrefix {
                addr: IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                bits: 0,
            }],
            state: FlowState::new(),
            shields_up: false,
            cap_holders: BTreeMap::new(),
            cap4: MatchList::default(),
            cap6: MatchList::default(),
            connection_counter: None,
        });
        // Override local4/local6 with wildcard prefixes (host_prefix would
        // give /32 and /128, but we need /0).
        let mut f = f;
        f.local4 = vec![prefix::IpPrefix {
            addr: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            bits: 0,
        }];
        f.local6 = vec![prefix::IpPrefix {
            addr: IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            bits: 0,
        }];
        f
    }

    /// Reject everything.
    pub fn allow_none() -> Self {
        Self {
            matches4: MatchList::default(),
            matches6: MatchList::default(),
            local4: vec![],
            local6: vec![],
            state: FlowState::new(),
            shields_up: false,
            cap_holders: BTreeMap::new(),
            cap4: MatchList::default(),
            cap6: MatchList::default(),
            connection_counter: None,
        }
    }

    /// Enable or disable shields-up mode. When enabled, all *new* inbound
    /// flows are denied; established flows (non-SYN TCP, cached UDP/SCTP,
    /// ICMP echo replies/errors, TSMP) continue to be admitted. Outbound
    /// traffic is unaffected. Mirrors Go's `Filter.shieldsUp`.
    pub fn set_shields_up(&mut self, on: bool) {
        self.shields_up = on;
    }

    /// Whether shields-up mode is currently active.
    pub fn shields_up(&self) -> bool {
        self.shields_up
    }

    /// Look up the capabilities a peer holds when talking to `dst`, per the
    /// `CapGrant` entries in the compiled filter rules. Mirrors Go's
    /// `Filter.CapsWithValues`.
    ///
    /// Returns a `PeerCapMap` (capability → values) collecting every
    /// `CapMatch` whose source prefix contains `src` and whose destination
    /// prefix contains `dst`.
    pub fn caps_with_values(&self, src: IpAddr, dst: IpAddr) -> PeerCapMap {
        let fam = if src.is_ipv4() {
            &self.cap4
        } else {
            &self.cap6
        };
        let mut out: PeerCapMap = PeerCapMap::new();
        for m in &fam.0 {
            if !m.srcs.iter().any(|p| p.contains(src)) {
                continue;
            }
            for cm in &m.caps {
                if cm.cap.is_empty() {
                    continue;
                }
                if cm.dst.contains(dst) {
                    match out.get_mut(&cm.cap) {
                        Some(prev) => prev.extend(cm.values.iter().cloned()),
                        None => {
                            out.insert(cm.cap.clone(), cm.values.clone());
                        }
                    }
                }
            }
        }
        out
    }

    /// Add extra local CIDR prefixes (e.g. advertised subnet routes) to the
    /// localNets prefilter. Packets destined to these prefixes are treated as
    /// "local" and admitted through the normal rule-matching path — needed by
    /// subnet routers, which receive packets whose dst is not the node's own
    /// tailnet IP but an advertised subnet address.
    ///
    /// Each entry is a `"ip/prefix"` CIDR string; unparseable entries are
    /// silently skipped (matching Go's tolerant parsing).
    pub fn add_local_cidrs(&mut self, cidrs: &[String]) {
        for cidr in cidrs {
            if let Some(pfx) = parse_cidr_prefix(cidr) {
                if pfx.is_v4() {
                    self.local4.push(pfx);
                } else {
                    self.local6.push(pfx);
                }
            }
        }
    }

    /// Check an inbound raw IP packet.
    pub fn check_in(&mut self, buf: &[u8]) -> Response {
        if buf.is_empty() {
            return Response::Accept;
        }
        let Some(info) = packet::parse_packet(buf) else {
            return Response::Drop;
        };
        self.check_in_info(&info)
    }

    /// Check a pre-parsed inbound packet.
    pub fn check_in_info(&mut self, q: &PacketInfo) -> Response {
        match pre(q) {
            PreResult::Accept => return Response::Accept,
            PreResult::Drop => return Response::Drop,
            PreResult::Continue => {}
        }

        let r = if q.version == 4 {
            self.run_in4(q)
        } else {
            self.run_in6(q)
        };

        match r {
            Verdict::Accept => Response::Accept,
            Verdict::NoVerdict => Response::Drop,
        }
    }

    /// Record outbound flow state from a raw IP packet (for UDP/SCTP return
    /// traffic). Also invokes the connection counter (if installed) with
    /// the parsed 5-tuple and packet size — this is the netlog integration
    /// point for virtual (tun) traffic.
    pub fn update_outbound(&mut self, buf: &[u8]) {
        if let Some(info) = packet::parse_packet(buf) {
            self.update_outbound_info(&info);
            if let Some(ref counter) = self.connection_counter {
                counter(
                    info.proto,
                    (info.src, info.src_port),
                    (info.dst, info.dst_port),
                    1,
                    buf.len() as u64,
                    false, // outbound = transmitted (Tx)
                );
            }
        }
    }

    /// Record outbound flow state from a pre-parsed packet.
    pub fn update_outbound_info(&mut self, q: &PacketInfo) {
        match q.proto {
            packet::UDP | packet::SCTP => {
                let tuple = reversed_tuple(q.proto, q.src, q.src_port, q.dst, q.dst_port);
                self.state.add(tuple);
            }
            _ => {}
        }
    }

    /// Install or remove a connection counter for network flow logging.
    ///
    /// When set, the counter is called from [`Filter::update_outbound`]
    /// for each parsed outbound packet. Pass `None` to disable counting.
    /// The counter type is structurally identical to
    /// `rustscale_netlog::ConnectionCounter`.
    pub fn set_connection_counter(&mut self, counter: Option<ConnectionCounter>) {
        self.connection_counter = counter;
    }

    /// Low-level check: is traffic from `src` to `dst`:`dst_port` using
    /// `proto` allowed? Equivalent to Go's `Filter.Check`.
    pub fn check(&mut self, src: IpAddr, dst: IpAddr, proto: u8, dst_port: u16) -> Response {
        let info = PacketInfo {
            version: if src.is_ipv4() { 4 } else { 6 },
            proto,
            src,
            dst,
            src_port: 0,
            dst_port,
            tcp_flags: if proto == packet::TCP { 0x02 } else { 0 },
            is_tcp_syn: proto == packet::TCP,
            is_icmp_echo_reply: false,
            is_icmp_error: false,
        };
        self.check_in_info(&info)
    }

    fn run_in4(&mut self, q: &PacketInfo) -> Verdict {
        if !local_contains(&self.local4, q.dst) {
            return Verdict::NoVerdict;
        }
        let caps = &self.cap_holders;
        let shielded = self.shields_up;
        match q.proto {
            packet::ICMP_V4 => {
                if q.is_echo_response() || q.is_error() {
                    return Verdict::Accept;
                }
                if !shielded
                    && self
                        .matches4
                        .matches_ips_only(q, |s, c| has_cap(caps, s, c))
                {
                    return Verdict::Accept;
                }
            }
            packet::TCP => {
                if !q.is_tcp_syn() {
                    return Verdict::Accept;
                }
                if !shielded && self.matches4.matches(q, |s, c| has_cap(caps, s, c)) {
                    return Verdict::Accept;
                }
            }
            packet::UDP | packet::SCTP => {
                let t = FlowTuple {
                    proto: q.proto,
                    src: q.src,
                    src_port: q.src_port,
                    dst: q.dst,
                    dst_port: q.dst_port,
                };
                if self.state.get(&t) {
                    return Verdict::Accept;
                }
                if !shielded && self.matches4.matches(q, |s, c| has_cap(caps, s, c)) {
                    return Verdict::Accept;
                }
            }
            packet::TSMP => return Verdict::Accept,
            _ => {
                if !shielded && self.matches4.matches_proto_and_ips_only_if_all_ports(q) {
                    return Verdict::Accept;
                }
                return Verdict::NoVerdict;
            }
        }
        Verdict::NoVerdict
    }

    fn run_in6(&mut self, q: &PacketInfo) -> Verdict {
        if !local_contains(&self.local6, q.dst) {
            return Verdict::NoVerdict;
        }
        let caps = &self.cap_holders;
        let shielded = self.shields_up;
        match q.proto {
            packet::ICMP_V6 => {
                if q.is_echo_response() || q.is_error() {
                    return Verdict::Accept;
                }
                if !shielded
                    && self
                        .matches6
                        .matches_ips_only(q, |s, c| has_cap(caps, s, c))
                {
                    return Verdict::Accept;
                }
            }
            packet::TCP => {
                if !q.is_tcp_syn() {
                    return Verdict::Accept;
                }
                if !shielded && self.matches6.matches(q, |s, c| has_cap(caps, s, c)) {
                    return Verdict::Accept;
                }
            }
            packet::UDP | packet::SCTP => {
                let t = FlowTuple {
                    proto: q.proto,
                    src: q.src,
                    src_port: q.src_port,
                    dst: q.dst,
                    dst_port: q.dst_port,
                };
                if self.state.get(&t) {
                    return Verdict::Accept;
                }
                if !shielded && self.matches6.matches(q, |s, c| has_cap(caps, s, c)) {
                    return Verdict::Accept;
                }
            }
            packet::TSMP => return Verdict::Accept,
            _ => {
                if !shielded && self.matches6.matches_proto_and_ips_only_if_all_ports(q) {
                    return Verdict::Accept;
                }
                return Verdict::NoVerdict;
            }
        }
        Verdict::NoVerdict
    }
}

/// Look up whether `src` holds capability `cap` in the peer capability map.
/// Mirrors Go's `LocalBackend.srcIPHasCapForFilter` — resolve the peer node
/// by address, then check its `NodeCapMap` for the capability key.
fn has_cap(cap_holders: &BTreeMap<IpAddr, BTreeSet<String>>, src: &IpAddr, cap: &str) -> bool {
    if cap.is_empty() {
        return false;
    }
    cap_holders.get(src).is_some_and(|caps| caps.contains(cap))
}

fn local_contains(local: &[prefix::IpPrefix], ip: IpAddr) -> bool {
    local.iter().any(|p| p.contains(ip))
}

fn partition_local_ips(ips: &[IpAddr]) -> (Vec<prefix::IpPrefix>, Vec<prefix::IpPrefix>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for ip in ips {
        let pfx = prefix::host_prefix(*ip);
        if pfx.is_v4() {
            v4.push(pfx);
        } else {
            v6.push(pfx);
        }
    }
    (v4, v6)
}

enum Verdict {
    Accept,
    NoVerdict,
}

enum PreResult {
    Accept,
    Drop,
    Continue,
}

/// Direction-agnostic pre-checks (Go's `filter.pre()`).
fn pre(q: &PacketInfo) -> PreResult {
    // Note: the empty-buffer check is handled by the caller (check_in returns
    // Drop for unparseable packets; Go accepts empty buffers as keepalives,
    // but those never reach check_in_info because parse_packet returns None).
    if q.proto == packet::UNKNOWN {
        return PreResult::Drop;
    }
    if prefix::is_multicast(q.dst) {
        return PreResult::Drop;
    }
    if prefix::is_link_local_unicast(q.dst) {
        return PreResult::Drop;
    }
    if q.proto == packet::FRAGMENT {
        return PreResult::Accept;
    }
    PreResult::Continue
}

/// Helper to check an empty buffer (WireGuard keepalive).
pub fn is_keepalive(buf: &[u8]) -> bool {
    buf.is_empty()
}

/// Parse a `"ip/prefix"` CIDR string into an [`prefix::IpPrefix`].
fn parse_cidr_prefix(cidr: &str) -> Option<prefix::IpPrefix> {
    let (net_str, bits_str) = cidr.split_once('/')?;
    let addr: IpAddr = net_str.parse().ok()?;
    let bits: u8 = bits_str.parse().ok()?;
    let max = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if bits > max {
        return None;
    }
    Some(prefix::IpPrefix { addr, bits })
}
