//! Parse [`FilterRule`](rustscale_tailcfg::FilterRule)s into compiled
//! [`Match`](crate::match::Match)es.

use std::net::IpAddr;

use rustscale_tailcfg::{CapGrant, FilterRule};

use crate::prefix::{
    host_prefix, parse_cidr, range_to_prefixes_v4, range_to_prefixes_v6, wildcard_prefixes,
    IpPrefix, ParseError,
};
use crate::r#match::{CapMatch, Match, NetPortRange, PortRange};

/// Default protocols when IPProto is empty: TCP, UDP, ICMP_V4, ICMP_V6.
const DEFAULT_PROTOS: [u8; 4] = [
    crate::packet::TCP,
    crate::packet::UDP,
    crate::packet::ICMP_V4,
    crate::packet::ICMP_V6,
];

/// Result of [`parse_ip_set`]: either prefixes, or a capability string.
pub enum IpSetResult {
    Prefixes(Vec<IpPrefix>),
    Cap(String),
}

/// Parse an IP-set string: wildcard, capability, CIDR, range, or bare IP.
pub fn parse_ip_set(arg: &str) -> Result<IpSetResult, ParseError> {
    if arg == "*" {
        return Ok(IpSetResult::Prefixes(wildcard_prefixes()));
    }
    if let Some(cap) = arg.strip_prefix("cap:") {
        return Ok(IpSetResult::Cap(cap.to_string()));
    }
    if arg.contains('/') {
        let p = parse_cidr(arg)?;
        return Ok(IpSetResult::Prefixes(vec![p]));
    }
    if arg.matches('-').count() == 1 {
        let (a, b) = arg.split_once('-').unwrap();
        let ip1: IpAddr = a.parse().map_err(|_| ParseError::InvalidIp(a.into()))?;
        let ip2: IpAddr = b.parse().map_err(|_| ParseError::InvalidIp(b.into()))?;
        if ip1.is_ipv4() != ip2.is_ipv4() {
            return Err(ParseError::InvalidRange(arg.into()));
        }
        match (ip1, ip2) {
            (IpAddr::V4(s), IpAddr::V4(e)) => {
                let start = u32::from_be_bytes(s.octets());
                let end = u32::from_be_bytes(e.octets());
                if start > end {
                    return Err(ParseError::InvalidRange(arg.into()));
                }
                let pfxs = range_to_prefixes_v4(s, e);
                if pfxs.is_empty() {
                    return Err(ParseError::InvalidRange(arg.into()));
                }
                return Ok(IpSetResult::Prefixes(pfxs));
            }
            (IpAddr::V6(s), IpAddr::V6(e)) => {
                let start = u128::from_be_bytes(s.octets());
                let end = u128::from_be_bytes(e.octets());
                if start > end {
                    return Err(ParseError::InvalidRange(arg.into()));
                }
                let pfxs = range_to_prefixes_v6(s, e);
                if pfxs.is_empty() {
                    return Err(ParseError::InvalidRange(arg.into()));
                }
                return Ok(IpSetResult::Prefixes(pfxs));
            }
            _ => unreachable!(),
        }
    }
    // Bare IP.
    let ip: IpAddr = arg
        .parse()
        .map_err(|_| ParseError::InvalidIp(arg.to_string()))?;
    Ok(IpSetResult::Prefixes(vec![host_prefix(ip)]))
}

/// Compile a list of [`FilterRule`]s into [`Match`]es.
///
/// Errors are accumulated (non-fatal) — the returned matches contain all
/// successfully-parsed rules. If any rule had an error, it is returned.
pub fn matches_from_filter_rules(rules: &[FilterRule]) -> Result<Vec<Match>, ParseError> {
    let mut matches = Vec::with_capacity(rules.len());
    let mut first_err: Option<ParseError> = None;

    for r in rules {
        if !r.SrcBits.is_empty() {
            return Err(ParseError::InvalidCidr(
                "unexpected SrcBits; control plane should not send this to this client version"
                    .into(),
            ));
        }

        let mut m = Match {
            ip_proto: if r.IPProto.is_empty() {
                DEFAULT_PROTOS.to_vec()
            } else {
                r.IPProto
                    .iter()
                    .filter(|n| **n >= 0 && **n <= 255)
                    .map(|n| *n as u8)
                    .collect()
            },
            srcs: Vec::with_capacity(r.SrcIPs.len()),
            src_caps: Vec::new(),
            dsts: Vec::with_capacity(r.DstPorts.len() * 2),
            caps: Vec::new(),
        };

        for s in &r.SrcIPs {
            match parse_ip_set(s) {
                Ok(IpSetResult::Prefixes(pfxs)) => m.srcs.extend(pfxs),
                Ok(IpSetResult::Cap(cap)) => m.src_caps.push(cap),
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }

        for d in &r.DstPorts {
            if d.Bits.is_some() {
                return Err(ParseError::InvalidCidr(
                    "unexpected DstBits; control plane should not send this to this client version"
                        .into(),
                ));
            }
            match parse_ip_set(&d.IP) {
                Ok(IpSetResult::Prefixes(pfxs)) => {
                    for pfx in pfxs {
                        m.dsts.push(NetPortRange {
                            net: pfx,
                            ports: PortRange {
                                first: d.Ports.First,
                                last: d.Ports.Last,
                            },
                        });
                    }
                }
                Ok(IpSetResult::Cap(_)) => {
                    if first_err.is_none() {
                        first_err = Some(ParseError::InvalidIp(format!(
                            "unexpected capability in DstPorts: {d:?}"
                        )));
                    }
                }
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }

        for grant in &r.CapGrant {
            for cap_match in parse_cap_grant(grant) {
                m.caps.push(cap_match);
            }
        }

        matches.push(m);
    }

    if let Some(e) = first_err {
        return Err(e);
    }
    Ok(matches)
}

/// Parse a [`CapGrant`] into [`CapMatch`]es.
fn parse_cap_grant(grant: &CapGrant) -> Vec<CapMatch> {
    let mut out = Vec::new();
    for dst_str in &grant.Dsts {
        let pfxs = match parse_ip_set(dst_str) {
            Ok(IpSetResult::Prefixes(p)) => p,
            _ => continue,
        };
        for pfx in pfxs {
            for cap in &grant.Caps {
                out.push(CapMatch {
                    dst: pfx,
                    cap: cap.clone(),
                    values: Vec::new(),
                });
            }
            for (cap, vals) in &grant.CapMap {
                out.push(CapMatch {
                    dst: pfx,
                    cap: cap.clone(),
                    values: vals.clone(),
                });
            }
        }
    }
    out
}
