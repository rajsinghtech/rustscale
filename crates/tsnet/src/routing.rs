//! Longest-prefix-match routing over the tailnet peer map.
//!
//! Given the netmap peers (each advertising `AllowedIPs` and/or `Addresses` as
//! `ip/prefix` CIDRs), [`RouteTable`] resolves a destination `IpAddr` to the
//! owning peer's [`NodePublic`] via longest-prefix match within the matching
//! address family. This mirrors how the kernel routes packets to the right
//! WireGuard peer, and is used by both the netstack and TUN data-plane pumps.

use std::net::IpAddr;

use rustscale_key::NodePublic;
use rustscale_tailcfg::Node;

/// One route entry: a CIDR network owned by a peer.
#[derive(Clone)]
struct RouteEntry {
    net: IpAddr,
    prefix: u8,
    peer: NodePublic,
}

/// A routing table mapping destination IPs to peers by longest-prefix match.
#[derive(Clone, Default)]
pub struct RouteTable {
    entries: Vec<RouteEntry>,
}

impl RouteTable {
    /// Build a table from a peer list. Each peer's `AllowedIPs` are used, or
    /// `Addresses` as a fallback when `AllowedIPs` is empty. Peers with a zero
    /// node key are skipped.
    pub fn from_peers(peers: &[Node]) -> Self {
        let mut entries = Vec::new();
        for peer in peers {
            if peer.Key.is_zero() {
                continue;
            }
            let cidrs: &[String] = if peer.AllowedIPs.is_empty() {
                &peer.Addresses
            } else {
                &peer.AllowedIPs
            };
            for cidr in cidrs {
                if let Some((net, prefix)) = parse_cidr(cidr) {
                    entries.push(RouteEntry {
                        net,
                        prefix,
                        peer: peer.Key.clone(),
                    });
                }
            }
        }
        // Sort by prefix descending so the first match in `lookup` is the
        // longest prefix (avoids a max-scan each call).
        entries.sort_by(|a, b| b.prefix.cmp(&a.prefix));
        Self { entries }
    }

    /// Look up the peer for a destination IP via longest-prefix match. Returns
    /// `None` if no route matches (the IP is not in any peer's allowed range).
    pub fn lookup(&self, ip: IpAddr) -> Option<NodePublic> {
        // Entries are sorted by descending prefix, so the first containing
        // entry is the longest-prefix match.
        for entry in &self.entries {
            if cidr_match(ip, entry.net, entry.prefix) {
                return Some(entry.peer.clone());
            }
        }
        None
    }

    /// Rebuild the table from a new peer list (e.g. on a map-stream delta).
    pub fn rebuild(&mut self, peers: &[Node]) {
        *self = Self::from_peers(peers);
    }

    /// Number of route entries (for diagnostics/testing).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Parse a `"ip/prefix"` CIDR string into its network address and prefix len.
fn parse_cidr(cidr: &str) -> Option<(IpAddr, u8)> {
    let (net_str, prefix_str) = cidr.split_once('/')?;
    let net: IpAddr = net_str.parse().ok()?;
    let prefix: u8 = prefix_str.parse().ok()?;
    let max = match net {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if prefix > max {
        return None;
    }
    Some((net, prefix))
}

/// Whether `ip` falls within `net`/`prefix`. Only matches within the same
/// address family.
fn cidr_match(ip: IpAddr, net: IpAddr, prefix: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            if prefix > 32 {
                return false;
            }
            let mask = if prefix == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(ip) & mask) == (u32::from(net) & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            if prefix > 128 {
                return false;
            }
            let mask = if prefix == 0 {
                0u128
            } else {
                u128::MAX << (128 - prefix)
            };
            (u128::from(ip) & mask) == (u128::from(net) & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustscale_key::NodePrivate;
    use std::net::Ipv4Addr;

    fn peer(name: &str, cidrs: &[&str]) -> Node {
        let key = NodePrivate::generate();
        Node {
            ID: 1,
            Name: name.into(),
            Key: key.public(),
            Addresses: cidrs.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    fn peer_with_key(cidrs: &[&str], key: NodePublic) -> Node {
        Node {
            ID: 1,
            Name: "p".into(),
            Key: key,
            Addresses: cidrs.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn exact_match_v4() {
        let peers = vec![peer("a", &["100.64.0.5/32"])];
        let rt = RouteTable::from_peers(&peers);
        assert_eq!(
            rt.lookup(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 5))),
            Some(peers[0].Key.clone())
        );
        assert!(rt
            .lookup(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 6)))
            .is_none());
    }

    #[test]
    fn subnet_match_v4() {
        let peers = vec![peer("a", &["100.64.0.0/24"])];
        let rt = RouteTable::from_peers(&peers);
        assert!(rt
            .lookup(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)))
            .is_some());
        assert!(rt
            .lookup(IpAddr::V4(Ipv4Addr::new(100, 64, 1, 1)))
            .is_none());
    }

    #[test]
    fn longest_prefix_wins() {
        // Two peers: one owns /24, another owns a more specific /32 within it.
        let broad = NodePrivate::generate().public();
        let narrow = NodePrivate::generate().public();
        let peers = vec![
            peer_with_key(&["100.64.0.0/24"], broad.clone()),
            peer_with_key(&["100.64.0.9/32"], narrow.clone()),
        ];
        let rt = RouteTable::from_peers(&peers);

        // The /32 should win for its exact address.
        assert_eq!(
            rt.lookup(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 9))),
            Some(narrow)
        );
        // Other addresses in /24 go to the broad peer.
        assert_eq!(
            rt.lookup(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 10))),
            Some(broad)
        );
    }

    #[test]
    fn default_route_matches_everything() {
        let peers = vec![peer("a", &["0.0.0.0/0"])];
        let rt = RouteTable::from_peers(&peers);
        assert!(rt.lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))).is_some());
        assert_eq!(rt.len(), 1);
    }

    #[test]
    fn v6_match() {
        let peers = vec![peer("a", &["fd7a:115c:a1e0::1/128"])];
        let rt = RouteTable::from_peers(&peers);
        let ip: IpAddr = "fd7a:115c:a1e0::1".parse().unwrap();
        assert_eq!(rt.lookup(ip), Some(peers[0].Key.clone()));
        let other: IpAddr = "fd7a:115c:a1e0::2".parse().unwrap();
        assert!(rt.lookup(other).is_none());
    }

    #[test]
    fn v6_subnet_longest_prefix() {
        let broad = NodePrivate::generate().public();
        let narrow = NodePrivate::generate().public();
        let peers = vec![
            peer_with_key(&["fd7a:115c:a1e0::/48"], broad.clone()),
            peer_with_key(&["fd7a:115c:a1e0:ab::/64"], narrow.clone()),
        ];
        let rt = RouteTable::from_peers(&peers);
        let in64: IpAddr = "fd7a:115c:a1e0:ab::1".parse().unwrap();
        let in48: IpAddr = "fd7a:115c:a1e0:cd::1".parse().unwrap();
        assert_eq!(rt.lookup(in64), Some(narrow));
        assert_eq!(rt.lookup(in48), Some(broad));
    }

    #[test]
    fn v4_and_v6_do_not_cross_match() {
        let peers = vec![peer("a", &["100.64.0.0/24"])];
        let rt = RouteTable::from_peers(&peers);
        let v6: IpAddr = "fd7a:115c:a1e0::1".parse().unwrap();
        assert!(rt.lookup(v6).is_none());
    }

    #[test]
    fn allowedips_preferred_over_addresses() {
        let key = NodePrivate::generate().public();
        let mut node = peer_with_key(&["100.64.0.5/32"], key.clone());
        node.AllowedIPs = vec!["100.64.0.9/32".into()];
        let rt = RouteTable::from_peers(&[node]);
        // AllowedIPs (100.64.0.9) should be used, not Addresses (100.64.0.5).
        assert_eq!(
            rt.lookup(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 9))),
            Some(key)
        );
        assert!(rt
            .lookup(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 5)))
            .is_none());
    }

    #[test]
    fn zero_key_peers_skipped() {
        let mut node = peer("a", &["100.64.0.5/32"]);
        node.Key = NodePublic::from_raw32([0u8; 32]);
        let rt = RouteTable::from_peers(&[node]);
        assert!(rt.is_empty());
    }

    #[test]
    fn rebuild_replaces_entries() {
        let mut rt = RouteTable::from_peers(&[peer("a", &["100.64.0.5/32"])]);
        assert_eq!(rt.len(), 1);
        rt.rebuild(&[peer("b", &["100.64.0.6/32", "100.64.0.7/32"])]);
        assert_eq!(rt.len(), 2);
    }

    #[test]
    fn bad_cidrs_ignored() {
        let peers = vec![peer("a", &["not-a-cidr", "100.64.0.5/32", "100.64.0.6/99"])];
        let rt = RouteTable::from_peers(&peers);
        // Only the valid /32 survives.
        assert_eq!(rt.len(), 1);
    }
}
