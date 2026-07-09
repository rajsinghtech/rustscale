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
    accept_routes: bool,
}

impl RouteTable {
    /// Build a table from a peer list. Each peer's `AllowedIPs` are used, or
    /// `Addresses` as a fallback when `AllowedIPs` is empty. Peers with a zero
    /// node key are skipped. All prefixes are installed (equivalent to
    /// `accept_routes = true`).
    pub fn from_peers(peers: &[Node]) -> Self {
        Self::from_peers_with_opts(peers, true)
    }

    /// Build a table from a peer list with an `accept_routes` flag.
    ///
    /// When `accept_routes` is true, every `AllowedIPs`/`Addresses` prefix is
    /// installed (tailnet IPs + peer-advertised subnet routes). When false,
    /// only prefixes within the tailnet ranges (100.64.0.0/10 for IPv4,
    /// fd7a:115c:a1e0::/48 for IPv6) are installed — peer subnet routes are
    /// ignored, matching Go's `--accept-routes=false` behavior.
    pub fn from_peers_with_opts(peers: &[Node], accept_routes: bool) -> Self {
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
                let Some((net, prefix)) = parse_cidr(cidr) else {
                    continue;
                };
                if !accept_routes && !is_tailnet_prefix(net, prefix) {
                    continue;
                }
                entries.push(RouteEntry {
                    net,
                    prefix,
                    peer: peer.Key.clone(),
                });
            }
        }
        // Sort by prefix descending so the first match in `lookup` is the
        // longest prefix (avoids a max-scan each call).
        entries.sort_by(|a, b| b.prefix.cmp(&a.prefix));
        Self {
            entries,
            accept_routes,
        }
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
    /// Preserves the `accept_routes` setting of the previous table.
    pub fn rebuild(&mut self, peers: &[Node]) {
        let accept = self.accept_routes;
        *self = Self::from_peers_with_opts(peers, accept);
    }

    /// Rebuild the table from a new peer list with an explicit `accept_routes`
    /// flag.
    pub fn rebuild_with_opts(&mut self, peers: &[Node], accept_routes: bool) {
        *self = Self::from_peers_with_opts(peers, accept_routes);
    }

    /// Number of route entries (for diagnostics/testing).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over all route entries as `(network_ip, prefix, peer_key)`. Used
    /// by TUN mode to install accepted subnet routes as OS routes.
    pub fn entries(&self) -> impl Iterator<Item = (IpAddr, u8, &NodePublic)> {
        self.entries.iter().map(|e| (e.net, e.prefix, &e.peer))
    }

    /// Whether `accept_routes` is enabled for this table.
    pub fn accept_routes(&self) -> bool {
        self.accept_routes
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

/// Whether a `net`/`prefix` falls within the Tailscale tailnet ranges:
/// IPv4 100.64.0.0/10 (CGNAT) or IPv6 fd7a:115c:a1e0::/48 (ULA). These are
/// the "self" IPs that are always installed regardless of `accept_routes`.
fn is_tailnet_prefix(net: IpAddr, prefix: u8) -> bool {
    match net {
        IpAddr::V4(v4) => {
            if prefix > 32 {
                return false;
            }
            // 100.64.0.0/10 — the Tailscale CGNAT range.
            cidr_match(
                IpAddr::V4(v4),
                IpAddr::V4(std::net::Ipv4Addr::new(100, 64, 0, 0)),
                10,
            )
        }
        IpAddr::V6(v6) => {
            if prefix > 128 {
                return false;
            }
            // fd7a:115c:a1e0::/48 — the Tailscale ULA range.
            cidr_match(
                IpAddr::V6(v6),
                IpAddr::V6("fd7a:115c:a1e0::".parse().unwrap()),
                48,
            )
        }
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
            Addresses: cidrs.iter().map(std::string::ToString::to_string).collect(),
            ..Default::default()
        }
    }

    fn peer_with_key(cidrs: &[&str], key: NodePublic) -> Node {
        Node {
            ID: 1,
            Name: "p".into(),
            Key: key,
            Addresses: cidrs.iter().map(std::string::ToString::to_string).collect(),
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

    #[test]
    fn accept_routes_false_ignores_subnet_routes() {
        let key = NodePrivate::generate().public();
        let node = Node {
            ID: 1,
            Name: "router".into(),
            Key: key.clone(),
            AllowedIPs: vec![
                "100.64.0.5/32".into(),
                "192.0.2.0/24".into(),
                "fd7a:115c:a1e0::5/128".into(),
            ],
            ..Default::default()
        };
        // accept_routes=false: only the tailnet /32 and /128 are installed.
        let rt = RouteTable::from_peers_with_opts(&[node], false);
        assert_eq!(rt.len(), 2);
        assert_eq!(
            rt.lookup(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 5))),
            Some(key.clone())
        );
        assert!(rt.lookup(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))).is_none());
    }

    #[test]
    fn accept_routes_true_installs_subnet_routes() {
        let key = NodePrivate::generate().public();
        let node = Node {
            ID: 1,
            Name: "router".into(),
            Key: key.clone(),
            AllowedIPs: vec!["100.64.0.5/32".into(), "192.0.2.0/24".into()],
            ..Default::default()
        };
        let rt = RouteTable::from_peers_with_opts(&[node], true);
        assert_eq!(rt.len(), 2);
        // Subnet route is now reachable.
        assert_eq!(
            rt.lookup(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42))),
            Some(key)
        );
    }

    #[test]
    fn accept_routes_mixed_32_and_cidr_longest_prefix() {
        let router = NodePrivate::generate().public();
        let host = NodePrivate::generate().public();
        let peers = vec![
            Node {
                ID: 1,
                Name: "router".into(),
                Key: router.clone(),
                AllowedIPs: vec!["100.64.0.1/32".into(), "192.0.2.0/24".into()],
                ..Default::default()
            },
            Node {
                ID: 2,
                Name: "host".into(),
                Key: host.clone(),
                AllowedIPs: vec!["192.0.2.9/32".into()],
                ..Default::default()
            },
        ];
        let rt = RouteTable::from_peers_with_opts(&peers, true);
        // The host's /32 within the router's /24 should win.
        assert_eq!(
            rt.lookup(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))),
            Some(host)
        );
        // Other addresses in /24 go to the router.
        assert_eq!(
            rt.lookup(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
            Some(router)
        );
    }

    #[test]
    fn rebuild_preserves_accept_routes() {
        let key = NodePrivate::generate().public();
        let node = Node {
            ID: 1,
            Name: "r".into(),
            Key: key,
            AllowedIPs: vec!["100.64.0.5/32".into(), "192.0.2.0/24".into()],
            ..Default::default()
        };
        let mut rt = RouteTable::from_peers_with_opts(&[node.clone()], false);
        assert_eq!(rt.len(), 1); // only tailnet /32
        rt.rebuild(&[node]);
        assert_eq!(rt.len(), 1); // accept_routes still false
    }

    #[test]
    fn tailnet_range_check() {
        // 100.64.0.0/10 is tailnet; 100.128.0.0 is outside it.
        assert!(is_tailnet_prefix(
            IpAddr::V4(Ipv4Addr::new(100, 64, 5, 5)),
            32
        ));
        assert!(!is_tailnet_prefix(
            IpAddr::V4(Ipv4Addr::new(100, 128, 0, 1)),
            32
        ));
        assert!(is_tailnet_prefix(
            "fd7a:115c:a1e0:abcd::1".parse().unwrap(),
            128
        ));
        assert!(!is_tailnet_prefix(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
            24
        ));
    }
}
