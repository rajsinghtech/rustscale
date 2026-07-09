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

use std::net::IpAddr;

use r#match::Matches as MatchList;
use rustscale_tailcfg::FilterRule;

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
}

impl Filter {
    /// Build a filter from control-plane rules and local IPs.
    pub fn new(rules: &[FilterRule], local_ips: &[IpAddr]) -> Result<Self, FilterError> {
        let all_matches = parse::matches_from_filter_rules(rules)
            .map_err(|e| FilterError::Parse(e.to_string()))?;
        let matches = MatchList(all_matches);
        let (m4, m6) = matches.partition_by_family();

        let (local4, local6) = partition_local_ips(local_ips);

        Ok(Self {
            matches4: m4,
            matches6: m6,
            local4,
            local6,
            state: FlowState::new(),
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
        let f = Self::new(&rules, &local).unwrap_or_else(|_| Self {
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
        }
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
    /// traffic).
    pub fn update_outbound(&mut self, buf: &[u8]) {
        if let Some(info) = packet::parse_packet(buf) {
            self.update_outbound_info(&info);
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
        match q.proto {
            packet::ICMP_V4 => {
                if q.is_echo_response() || q.is_error() {
                    return Verdict::Accept;
                }
                if self.matches4.matches_ips_only(q, no_cap) {
                    return Verdict::Accept;
                }
            }
            packet::TCP => {
                if !q.is_tcp_syn() {
                    return Verdict::Accept;
                }
                if self.matches4.matches(q, no_cap) {
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
                if self.matches4.matches(q, no_cap) {
                    return Verdict::Accept;
                }
            }
            packet::TSMP => return Verdict::Accept,
            _ => {
                if self.matches4.matches_proto_and_ips_only_if_all_ports(q) {
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
        match q.proto {
            packet::ICMP_V6 => {
                if q.is_echo_response() || q.is_error() {
                    return Verdict::Accept;
                }
                if self.matches6.matches_ips_only(q, no_cap) {
                    return Verdict::Accept;
                }
            }
            packet::TCP => {
                if !q.is_tcp_syn() {
                    return Verdict::Accept;
                }
                if self.matches6.matches(q, no_cap) {
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
                if self.matches6.matches(q, no_cap) {
                    return Verdict::Accept;
                }
            }
            packet::TSMP => return Verdict::Accept,
            _ => {
                if self.matches6.matches_proto_and_ips_only_if_all_ports(q) {
                    return Verdict::Accept;
                }
                return Verdict::NoVerdict;
            }
        }
        Verdict::NoVerdict
    }
}

fn no_cap(_: &IpAddr, _: &str) -> bool {
    false
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
