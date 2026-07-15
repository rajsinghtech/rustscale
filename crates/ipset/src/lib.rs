//! Efficient, in-process IP-in-prefix-set predicates.
//!
//! This mirrors Tailscale's `net/ipset` package. It selects specialized
//! representations for empty sets, one or two host addresses, small prefix
//! lists, larger prefix tables, and host-address hash sets. This package does
//! not manage Linux kernel ipsets.

#![forbid(unsafe_code)]

use std::{collections::HashSet, net::IpAddr};

pub use rustscale_art::IpPrefix;
use rustscale_art::Table;

/// An immutable IP membership predicate produced by
/// [`new_contains_ip_func`].
///
/// Prefixes match only addresses from the same family. Host bits in a prefix
/// are ignored, matching `netip.Prefix.Contains` behavior.
pub struct ContainsIpFunc {
    strategy: Strategy,
}

impl ContainsIpFunc {
    /// Reports whether `ip` is contained by any configured prefix.
    #[must_use]
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.strategy.contains(ip)
    }
}

/// Returns a predicate that rejects every IP address.
#[must_use]
pub fn false_contains_ip_func() -> ContainsIpFunc {
    ContainsIpFunc {
        strategy: Strategy::Empty,
    }
}

/// Returns an immutable predicate that reports whether an IP is in `prefixes`.
///
/// The selected representation follows upstream `net/ipset`:
///
/// - empty, one-host, and two-host sets use direct comparisons;
/// - three or more host-only prefixes use a hash set;
/// - one non-host prefix uses direct prefix containment;
/// - up to six prefixes containing any non-host prefix use a linear scan;
/// - larger prefix sets use an IPv4/IPv6 prefix table.
#[must_use]
pub fn new_contains_ip_func(prefixes: &[IpPrefix]) -> ContainsIpFunc {
    let strategy = if prefixes.is_empty() {
        Strategy::Empty
    } else if prefixes.iter().any(|prefix| !is_single_ip(*prefix)) {
        match prefixes {
            [prefix] => Strategy::OnePrefix(*prefix),
            prefixes if prefixes.len() <= 6 => Strategy::Linear(prefixes.to_vec()),
            prefixes => {
                let mut table = Table::new();
                for prefix in prefixes {
                    table.insert(*prefix, ());
                }
                Strategy::Table(Box::new(table))
            }
        }
    } else {
        match prefixes {
            [prefix] => Strategy::OneIp(prefix.addr()),
            [first, second] => Strategy::TwoIp(first.addr(), second.addr()),
            prefixes => Strategy::IpMap(prefixes.iter().map(|prefix| prefix.addr()).collect()),
        }
    };
    ContainsIpFunc { strategy }
}

fn is_single_ip(prefix: IpPrefix) -> bool {
    prefix.bits() == if prefix.addr().is_ipv4() { 32 } else { 128 }
}

enum Strategy {
    Empty,
    OnePrefix(IpPrefix),
    Linear(Vec<IpPrefix>),
    Table(Box<Table<()>>),
    OneIp(IpAddr),
    TwoIp(IpAddr, IpAddr),
    IpMap(HashSet<IpAddr>),
}

impl Strategy {
    fn contains(&self, ip: IpAddr) -> bool {
        match self {
            Self::Empty => false,
            Self::OnePrefix(prefix) => prefix.contains(ip),
            Self::Linear(prefixes) => prefixes.iter().any(|prefix| prefix.contains(ip)),
            Self::Table(table) => table.get(ip).is_some(),
            Self::OneIp(first) => ip == *first,
            Self::TwoIp(first, second) => ip == *first || ip == *second,
            Self::IpMap(ips) => ips.contains(&ip),
        }
    }

    #[cfg(test)]
    fn name(&self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::OnePrefix(_) => "one-prefix",
            Self::Linear(_) => "linear-contains",
            Self::Table(_) => "bart",
            Self::OneIp(_) => "one-ip",
            Self::TwoIp(_, _) => "two-ip",
            Self::IpMap(_) => "ip-map",
        }
    }
}

#[cfg(test)]
mod tests;
