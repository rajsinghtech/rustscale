//! Compiled match rules — the internal representation after parsing
//! [`FilterRule`](rustscale_tailcfg::FilterRule)s.

use crate::packet::PacketInfo;
use crate::prefix::IpPrefix;

/// An inclusive port range.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PortRange {
    pub first: u16,
    pub last: u16,
}

impl PortRange {
    /// All ports (0–65535).
    pub const ALL: Self = Self {
        first: 0,
        last: 65535,
    };

    pub fn contains(&self, port: u16) -> bool {
        port >= self.first && port <= self.last
    }
}

/// An IP prefix + port range — the destination match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetPortRange {
    pub net: IpPrefix,
    pub ports: PortRange,
}

/// A capability grant match (kept but not fully implemented).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapMatch {
    pub dst: IpPrefix,
    pub cap: String,
    pub values: Vec<rustscale_tailcfg::RawMessage>,
}

/// A compiled filter rule.
///
/// A packet matches if `proto` is in `ip_proto`, `src` is in any `srcs`
/// prefix, and there exists a `dst` whose prefix contains `dst_ip` and
/// whose port range contains `dst_port`.
#[derive(Clone, Debug, Default)]
pub struct Match {
    pub ip_proto: Vec<u8>,
    pub srcs: Vec<IpPrefix>,
    pub src_caps: Vec<String>,
    pub dsts: Vec<NetPortRange>,
    pub caps: Vec<CapMatch>,
}

impl Match {
    /// Whether `src` is in any of `self.srcs`.
    fn srcs_contains(&self, src: std::net::IpAddr) -> bool {
        self.srcs.iter().any(|p| p.contains(src))
    }
}

/// A list of compiled matches.
#[derive(Clone, Debug, Default)]
pub struct Matches(pub Vec<Match>);

impl Matches {
    /// Full match: proto in IPProto, src in Srcs, dst IP + dst port in Dsts.
    pub fn matches(
        &self,
        q: &PacketInfo,
        has_cap: impl Fn(&std::net::IpAddr, &str) -> bool,
    ) -> bool {
        for m in &self.0 {
            if !m.ip_proto.contains(&q.proto) {
                continue;
            }
            if !m.srcs_contains(q.src) && !m.src_caps.iter().any(|c| has_cap(&q.src, c)) {
                continue;
            }
            for dst in &m.dsts {
                if dst.net.contains(q.dst) && dst.ports.contains(q.dst_port) {
                    return true;
                }
            }
        }
        false
    }

    /// Match IPs only — ignore proto and ports. Used for ICMP.
    pub fn matches_ips_only(
        &self,
        q: &PacketInfo,
        has_cap: impl Fn(&std::net::IpAddr, &str) -> bool,
    ) -> bool {
        for m in &self.0 {
            if m.srcs_contains(q.src) {
                for dst in &m.dsts {
                    if dst.net.contains(q.dst) {
                        return true;
                    }
                }
            }
        }
        self.0
            .iter()
            .any(|m| m.src_caps.iter().any(|c| has_cap(&q.src, c)))
    }

    /// Match proto + IPs only when the dst entry has all ports (0-65535).
    pub fn matches_proto_and_ips_only_if_all_ports(&self, q: &PacketInfo) -> bool {
        for m in &self.0 {
            if !m.ip_proto.contains(&q.proto) {
                continue;
            }
            if !m.srcs_contains(q.src) {
                continue;
            }
            for dst in &m.dsts {
                if dst.ports == PortRange::ALL && dst.net.contains(q.dst) {
                    return true;
                }
            }
        }
        false
    }

    /// Partition into v4-only and v6-only matches.
    pub fn partition_by_family(&self) -> (Matches, Matches) {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for m in &self.0 {
            let mut m4 = Match {
                ip_proto: m.ip_proto.clone(),
                src_caps: m.src_caps.clone(),
                ..Default::default()
            };
            let mut m6 = Match {
                ip_proto: m.ip_proto.clone(),
                src_caps: m.src_caps.clone(),
                ..Default::default()
            };
            for s in &m.srcs {
                if s.is_v4() {
                    m4.srcs.push(*s);
                } else {
                    m6.srcs.push(*s);
                }
            }
            for d in &m.dsts {
                if d.net.is_v4() {
                    m4.dsts.push(d.clone());
                } else {
                    m6.dsts.push(d.clone());
                }
            }
            if (!m4.srcs.is_empty() || !m4.src_caps.is_empty()) && !m4.dsts.is_empty() {
                v4.push(m4);
            }
            if (!m6.srcs.is_empty() || !m6.src_caps.is_empty()) && !m6.dsts.is_empty() {
                v6.push(m6);
            }
        }
        (Matches(v4), Matches(v6))
    }
}
