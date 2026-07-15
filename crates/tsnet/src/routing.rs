//! Longest-prefix-match routing over the tailnet peer map.
//!
//! Given the netmap peers (each advertising `AllowedIPs` and/or `Addresses` as
//! `ip/prefix` CIDRs), [`RouteTable`] resolves a destination `IpAddr` to the
//! owning peer's [`NodePublic`] via longest-prefix match within the matching
//! address family. This mirrors how the kernel routes packets to the right
//! WireGuard peer, and is used by both the netstack and TUN data-plane pumps.

use std::net::IpAddr;

use rustscale_art::{IpPrefix as ArtPrefix, Table as ArtTable};
use rustscale_key::NodePublic;
use rustscale_tailcfg::Node;

/// One route entry: a CIDR network owned by a peer.
#[derive(Clone)]
struct RouteEntry {
    prefix: ArtPrefix,
    peer: NodePublic,
}

/// A routing table mapping destination IPs to peers by longest-prefix match.
///
/// When an exit node is selected ([`RouteTable::set_exit_node`]), any
/// destination that does not match a more-specific entry falls through to the
/// exit node peer — mirroring how the Go client installs `0.0.0.0/0` and
/// `::/0` from the exit node's `AllowedIPs` regardless of `accept_routes`.
#[derive(Clone, Default)]
pub struct RouteTable {
    entries: Vec<RouteEntry>,
    index: ArtTable<NodePublic>,
    accept_routes: bool,
    /// The selected exit node peer, if any. Acts as a catch-all fallback for
    /// destinations not matched by a more-specific entry. Independent of
    /// `accept_routes`: the exit node's default routes are installed even when
    /// `accept_routes` is false.
    exit_node: Option<NodePublic>,
    /// Whether ordinary traffic must remain captured even while the requested
    /// exit peer is unresolved. With no `exit_node`, lookup deliberately drops
    /// the captured packet instead of permitting direct physical routing.
    exit_capture: bool,
    /// Emergency data-plane block entered when security-critical OS route
    /// refresh fails. The selected peer is retained for retry, but ordinary
    /// fallback traffic is dropped until the refresh succeeds.
    exit_blocked: bool,
}

#[derive(Clone)]
pub(crate) struct ExitRouteState {
    peer: Option<NodePublic>,
    requested: bool,
    blocked: bool,
}

impl RouteTable {
    /// Build a table from a peer list. Each peer's `AllowedIPs` are used, or
    /// `Addresses` as a fallback when `AllowedIPs` is empty. Peers with a zero
    /// node key are skipped. All non-default prefixes are installed
    /// (equivalent to `accept_routes = true`); advertised defaults require an
    /// explicit exit-node selection.
    pub fn from_peers(peers: &[Node]) -> Self {
        Self::from_peers_with_opts(peers, true)
    }

    /// Build a table from a peer list with an `accept_routes` flag.
    ///
    /// When `accept_routes` is true, host and non-default subnet prefixes are
    /// installed. When false, only IPv4 `/32` and IPv6 `/128` host prefixes
    /// are installed. Peer-advertised default routes are never ordinary table
    /// entries; defaults are enabled only by [`Self::set_exit_node`].
    pub fn from_peers_with_opts(peers: &[Node], accept_routes: bool) -> Self {
        let mut entries = Vec::new();
        let mut index = ArtTable::new();
        for peer in peers {
            if peer.Key.is_zero() {
                continue;
            }
            for cidr in peer_routes(peer) {
                let Some(prefix) = parse_cidr(cidr) else {
                    continue;
                };
                if prefix.bits() == 0
                    || (!accept_routes && !is_host_prefix(prefix))
                    || index.get_prefix(prefix).is_some()
                {
                    continue;
                }
                let _ = index.insert(prefix, peer.Key.clone());
                entries.push(RouteEntry {
                    prefix,
                    peer: peer.Key.clone(),
                });
            }
        }
        // Keep the diagnostic/OS-routing view longest-prefix first. Equal
        // normalized prefixes were already deduplicated while walking peers,
        // so every view retains the first owner in netmap order.
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.prefix.bits()));
        Self {
            entries,
            index,
            accept_routes,
            exit_node: None,
            exit_capture: false,
            exit_blocked: false,
        }
    }

    /// Look up the peer for a destination IP via longest-prefix match. Returns
    /// `None` if no route matches (the IP is not in any peer's allowed range).
    ///
    /// If an exit node is set, it acts as a catch-all: any destination that
    /// does not match a more-specific entry routes to the exit node. Tailnet
    /// IPs and accepted subnet routes (more specific than `0.0.0.0/0`) always
    /// win over the exit fallback.
    pub fn lookup(&self, ip: IpAddr) -> Option<NodePublic> {
        let peer = self.index.get(ip).cloned();
        if self.exit_blocked {
            peer
        } else {
            peer.or_else(|| self.exit_node.clone())
        }
    }

    /// Rebuild the table from a new peer list (e.g. on a map-stream delta).
    /// Preserves the `accept_routes` setting and the selected exit node of the
    /// previous table.
    pub fn rebuild(&mut self, peers: &[Node]) {
        let accept = self.accept_routes;
        let exit = self.exit_node.clone();
        let capture = self.exit_capture;
        let blocked = self.exit_blocked;
        *self = Self::from_peers_with_opts(peers, accept);
        self.exit_node = exit;
        self.exit_capture = capture;
        self.exit_blocked = blocked;
    }

    /// Rebuild the table from a new peer list with an explicit `accept_routes`
    /// flag. Preserves the selected exit node of the previous table.
    pub fn rebuild_with_opts(&mut self, peers: &[Node], accept_routes: bool) {
        let exit = self.exit_node.clone();
        let capture = self.exit_capture;
        let blocked = self.exit_blocked;
        *self = Self::from_peers_with_opts(peers, accept_routes);
        self.exit_node = exit;
        self.exit_capture = capture;
        self.exit_blocked = blocked;
    }

    /// Number of distinct normalized route entries (for diagnostics/testing).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty and no exit node is set.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && !self.exit_node_requested()
    }

    /// Iterate over distinct normalized routes as `(network_ip, prefix,
    /// peer_key)`. Used by TUN mode to install accepted subnet routes as OS
    /// routes.
    pub fn entries(&self) -> impl Iterator<Item = (IpAddr, u8, &NodePublic)> {
        self.entries
            .iter()
            .map(|entry| (entry.prefix.addr(), entry.prefix.bits(), &entry.peer))
    }

    /// Whether `accept_routes` is enabled for this table.
    pub fn accept_routes(&self) -> bool {
        self.accept_routes
    }

    pub(crate) fn exit_route_state(&self) -> ExitRouteState {
        ExitRouteState {
            peer: self.exit_node.clone(),
            requested: self.exit_capture,
            blocked: self.exit_blocked,
        }
    }

    pub(crate) fn restore_exit_route_state(&mut self, state: ExitRouteState) {
        self.exit_node = state.peer;
        self.exit_capture = state.requested;
        self.exit_blocked = state.blocked;
    }

    /// Select an exit node peer. After this, any destination not matched by a
    /// more-specific entry routes to `peer`. This is independent of
    /// `accept_routes`: the exit node's default routes apply even when
    /// `accept_routes` is false.
    pub fn set_exit_node(&mut self, peer: NodePublic) {
        self.exit_node = Some(peer);
        self.exit_capture = true;
        self.exit_blocked = false;
    }

    /// Capture default traffic without forwarding it to any peer. This is the
    /// fail-closed state for an unresolved requested exit selection.
    pub fn capture_exit_node(&mut self) {
        self.exit_node = None;
        self.exit_capture = true;
        self.exit_blocked = false;
    }

    /// Clear the selected exit node. After this, destinations not matched by
    /// any entry return `None` from [`lookup`](Self::lookup).
    pub fn clear_exit_node(&mut self) {
        self.exit_node = None;
        self.exit_capture = false;
        self.exit_blocked = false;
    }

    /// The currently selected exit node peer, if any.
    pub fn exit_node(&self) -> Option<&NodePublic> {
        self.exit_node.as_ref()
    }

    /// Whether OS catch-all routes must remain installed, either for a working
    /// exit peer or for unresolved-selection capture.
    pub fn exit_node_requested(&self) -> bool {
        self.exit_capture
    }

    pub(crate) fn block_exit_traffic(&mut self) {
        if self.exit_capture {
            self.exit_blocked = true;
        }
    }

    pub(crate) fn unblock_exit_traffic(&mut self) {
        self.exit_blocked = false;
    }

    #[cfg(test)]
    pub(crate) fn exit_traffic_blocked(&self) -> bool {
        self.exit_blocked
    }
}

fn peer_routes(peer: &Node) -> &[String] {
    if peer.AllowedIPs.is_empty() {
        &peer.Addresses
    } else {
        &peer.AllowedIPs
    }
}

/// Parse and normalize an `"ip/prefix"` CIDR string.
fn parse_cidr(cidr: &str) -> Option<ArtPrefix> {
    ArtPrefix::parse(cidr).map(ArtPrefix::masked)
}

fn is_host_prefix(prefix: ArtPrefix) -> bool {
    prefix.bits() == if prefix.addr().is_ipv4() { 32 } else { 128 }
}

/// Whether a peer advertises both normalized IPv4 and IPv6 default routes.
///
/// The same exact predicate is used by all exit-node selection paths. A
/// single-family default is insufficient. `AllowedIPs` is authoritative when
/// present; `Addresses` is used only as the existing empty-`AllowedIPs`
/// fallback.
pub fn peer_is_exit_capable(peer: &Node) -> bool {
    let mut has_v4_default = false;
    let mut has_v6_default = false;
    for prefix in peer_routes(peer).iter().filter_map(|cidr| parse_cidr(cidr)) {
        if prefix.bits() != 0 {
            continue;
        }
        if prefix.addr().is_ipv4() {
            has_v4_default = true;
        } else {
            has_v6_default = true;
        }
    }
    has_v4_default && has_v6_default
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
    fn equal_normalized_prefix_is_deduplicated_across_views() {
        let first = NodePrivate::generate().public();
        let second = NodePrivate::generate().public();
        let peers = vec![
            peer_with_key(&["192.0.2.99/24"], first.clone()),
            peer_with_key(&["192.0.2.0/24"], second),
        ];
        let rt = RouteTable::from_peers(&peers);
        assert_eq!(
            rt.lookup(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            Some(first.clone())
        );
        assert_eq!(rt.len(), 1);
        let entries: Vec<_> = rt.entries().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0],
            (IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24, &first)
        );
    }

    #[test]
    fn advertised_defaults_are_not_ordinary_routes() {
        let peers = vec![peer("a", &["192.0.2.99/0", "2001:db8::1/0"])];
        let rt = RouteTable::from_peers(&peers);
        assert!(rt.lookup("8.8.8.8".parse().unwrap()).is_none());
        assert!(rt.lookup("2001:4860:4860::8888".parse().unwrap()).is_none());
        assert_eq!(rt.len(), 0);
        assert_eq!(rt.entries().count(), 0);
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
    fn accept_routes_false_keeps_only_host_prefixes() {
        let key = NodePrivate::generate().public();
        let node = Node {
            ID: 1,
            Name: "router".into(),
            Key: key.clone(),
            AllowedIPs: vec![
                "100.64.0.5/32".into(),
                "fd7a:115c:a1e0::5/128".into(),
                // The supplied addresses are Tailscale IPs, but filtering is
                // based on the normalized prefix length, not the host bits.
                "100.64.99.99/10".into(),
                "fd7a:115c:a1e0:abcd::5/48".into(),
                "192.0.2.9/24".into(),
            ],
            ..Default::default()
        };
        let rt = RouteTable::from_peers_with_opts(&[node], false);
        assert_eq!(rt.len(), 2);
        assert_eq!(rt.lookup("100.64.0.5".parse().unwrap()), Some(key.clone()));
        assert_eq!(rt.lookup("fd7a:115c:a1e0::5".parse().unwrap()), Some(key));
        assert!(rt.lookup("100.64.0.6".parse().unwrap()).is_none());
        assert!(rt.lookup("fd7a:115c:a1e0::6".parse().unwrap()).is_none());
        assert!(rt.lookup("192.0.2.9".parse().unwrap()).is_none());
        assert!(rt.entries().all(|(net, bits, _)| matches!(
            (net, bits),
            (IpAddr::V4(_), 32) | (IpAddr::V6(_), 128)
        )));
    }

    #[test]
    fn accept_routes_true_installs_subnet_routes() {
        let key = NodePrivate::generate().public();
        let node = Node {
            ID: 1,
            Name: "router".into(),
            Key: key.clone(),
            AllowedIPs: vec![
                "100.64.0.5/32".into(),
                "192.0.2.99/24".into(),
                "0.0.0.0/0".into(),
                "::/0".into(),
            ],
            ..Default::default()
        };
        let rt = RouteTable::from_peers_with_opts(&[node], true);
        assert_eq!(rt.len(), 2);
        // The normalized subnet route is reachable, but advertised defaults
        // remain inactive until the peer is explicitly selected.
        assert_eq!(
            rt.lookup(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42))),
            Some(key)
        );
        assert!(rt.lookup("8.8.8.8".parse().unwrap()).is_none());
        assert!(rt.lookup("2001:4860:4860::8888".parse().unwrap()).is_none());
        assert!(rt
            .entries()
            .any(|(net, bits, _)| net == IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)) && bits == 24));
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
        assert!(rustscale_tsaddr::is_tailscale_ip(IpAddr::V4(
            Ipv4Addr::new(100, 64, 5, 5)
        )));
        assert!(!rustscale_tsaddr::is_tailscale_ip(IpAddr::V4(
            Ipv4Addr::new(100, 128, 0, 1)
        )));
        assert!(rustscale_tsaddr::is_tailscale_ip(
            "fd7a:115c:a1e0:abcd::1".parse().unwrap()
        ));
        assert!(!rustscale_tsaddr::is_tailscale_ip(IpAddr::V4(
            Ipv4Addr::new(192, 0, 2, 0)
        )));
    }

    // -----------------------------------------------------------------------
    // Exit node tests
    // -----------------------------------------------------------------------

    #[test]
    fn exit_node_catch_all_routes_non_tailnet() {
        let exit_key = NodePrivate::generate().public();
        let host_key = NodePrivate::generate().public();
        let peers = vec![
            Node {
                ID: 1,
                Name: "exit".into(),
                Key: exit_key.clone(),
                Addresses: vec!["100.64.0.1/32".into()],
                AllowedIPs: vec!["100.64.0.1/32".into(), "0.0.0.0/0".into(), "::/0".into()],
                ..Default::default()
            },
            Node {
                ID: 2,
                Name: "host".into(),
                Key: host_key.clone(),
                Addresses: vec!["100.64.0.2/32".into()],
                AllowedIPs: vec!["100.64.0.2/32".into()],
                ..Default::default()
            },
        ];
        let mut rt = RouteTable::from_peers_with_opts(&peers, false);
        // Advertised defaults remain inactive before explicit selection.
        assert!(rt.lookup("8.8.8.8".parse().unwrap()).is_none());
        assert!(rt.lookup("2001:4860:4860::8888".parse().unwrap()).is_none());

        rt.set_exit_node(exit_key.clone());
        // One explicit selection supplies defaults for both families.
        assert_eq!(
            rt.lookup("8.8.8.8".parse().unwrap()),
            Some(exit_key.clone())
        );
        assert_eq!(
            rt.lookup("2001:4860:4860::8888".parse().unwrap()),
            Some(exit_key.clone())
        );
        // Tailnet IPs still route to their owning peers (more specific).
        assert_eq!(
            rt.lookup(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))),
            Some(exit_key.clone())
        );
        assert_eq!(
            rt.lookup(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2))),
            Some(host_key)
        );
    }

    #[test]
    fn unresolved_exit_capture_keeps_defaults_installed_but_drops_ordinary_traffic() {
        let mut rt = RouteTable::default();
        rt.capture_exit_node();
        assert!(rt.exit_node_requested());
        assert!(rt.exit_node().is_none());
        assert!(rt.lookup("8.8.8.8".parse().unwrap()).is_none());
        rt.rebuild(&[]);
        assert!(rt.exit_node_requested());
    }

    #[test]
    fn emergency_block_retains_selected_exit_for_retry_but_drops_fallback() {
        let exit = NodePrivate::generate().public();
        let mut rt = RouteTable::default();
        rt.set_exit_node(exit.clone());
        rt.block_exit_traffic();
        assert_eq!(rt.exit_node(), Some(&exit));
        assert!(rt.exit_traffic_blocked());
        assert!(rt.lookup("8.8.8.8".parse().unwrap()).is_none());
        rt.unblock_exit_traffic();
        assert_eq!(rt.lookup("8.8.8.8".parse().unwrap()), Some(exit));
    }

    #[test]
    fn exit_node_clear_restores_no_default() {
        let exit_key = NodePrivate::generate().public();
        let peers = vec![Node {
            ID: 1,
            Name: "exit".into(),
            Key: exit_key.clone(),
            Addresses: vec!["100.64.0.1/32".into()],
            AllowedIPs: vec!["100.64.0.1/32".into(), "0.0.0.0/0".into(), "::/0".into()],
            ..Default::default()
        }];
        let mut rt = RouteTable::from_peers_with_opts(&peers, false);
        rt.set_exit_node(exit_key);
        assert!(rt.lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))).is_some());
        rt.clear_exit_node();
        assert!(rt.lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))).is_none());
        // Tailnet IP still routes.
        assert!(rt
            .lookup(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)))
            .is_some());
    }

    #[test]
    fn exit_node_survives_rebuild() {
        let exit_key = NodePrivate::generate().public();
        let peers = vec![Node {
            ID: 1,
            Name: "exit".into(),
            Key: exit_key.clone(),
            Addresses: vec!["100.64.0.1/32".into()],
            AllowedIPs: vec!["100.64.0.1/32".into(), "0.0.0.0/0".into(), "::/0".into()],
            ..Default::default()
        }];
        let mut rt = RouteTable::from_peers_with_opts(&peers, false);
        rt.set_exit_node(exit_key.clone());
        // Simulate a map-stream delta: rebuild with a slightly different peer
        // list. The exit node selection must survive.
        let new_peers = vec![Node {
            ID: 1,
            Name: "exit".into(),
            Key: exit_key.clone(),
            Addresses: vec!["100.64.0.1/32".into(), "100.64.0.3/32".into()],
            AllowedIPs: vec![
                "100.64.0.1/32".into(),
                "100.64.0.3/32".into(),
                "0.0.0.0/0".into(),
                "::/0".into(),
            ],
            ..Default::default()
        }];
        rt.rebuild(&new_peers);
        assert_eq!(rt.exit_node(), Some(&exit_key));
        assert_eq!(
            rt.lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            Some(exit_key)
        );
    }

    #[test]
    fn accept_routes_true_still_requires_exit_selection() {
        let exit_key = NodePrivate::generate().public();
        let peers = vec![Node {
            ID: 1,
            Name: "exit".into(),
            Key: exit_key.clone(),
            Addresses: vec!["100.64.0.1/32".into()],
            AllowedIPs: vec!["100.64.0.1/32".into(), "0.0.0.0/0".into(), "::/0".into()],
            ..Default::default()
        }];
        let mut rt = RouteTable::from_peers_with_opts(&peers, true);
        assert_eq!(rt.len(), 1);
        assert!(rt.lookup("8.8.8.8".parse().unwrap()).is_none());
        assert!(rt.lookup("2001:4860:4860::8888".parse().unwrap()).is_none());

        rt.set_exit_node(exit_key.clone());
        assert_eq!(
            rt.lookup("8.8.8.8".parse().unwrap()),
            Some(exit_key.clone())
        );
        assert_eq!(
            rt.lookup("2001:4860:4860::8888".parse().unwrap()),
            Some(exit_key)
        );
    }

    #[test]
    fn exit_node_v6_fallback() {
        let exit_key = NodePrivate::generate().public();
        let peers = vec![Node {
            ID: 1,
            Name: "exit".into(),
            Key: exit_key.clone(),
            Addresses: vec!["100.64.0.1/32".into()],
            AllowedIPs: vec!["0.0.0.0/0".into(), "::/0".into()],
            ..Default::default()
        }];
        let mut rt = RouteTable::from_peers_with_opts(&peers, false);
        rt.set_exit_node(exit_key.clone());
        let v6: IpAddr = "2001:4860:4860::8888".parse().unwrap();
        assert_eq!(rt.lookup(v6), Some(exit_key));
    }

    #[test]
    fn peer_is_exit_capable_requires_both_normalized_defaults() {
        let mut peer = Node {
            ID: 1,
            Name: "exit".into(),
            Key: NodePrivate::generate().public(),
            Addresses: vec!["100.64.0.1/32".into()],
            AllowedIPs: vec!["192.0.2.99/0".into()],
            ..Default::default()
        };
        assert!(!peer_is_exit_capable(&peer), "IPv4-only default");

        peer.AllowedIPs = vec!["2001:db8::1/0".into()];
        assert!(!peer_is_exit_capable(&peer), "IPv6-only default");

        peer.AllowedIPs = vec!["192.0.2.99/0".into(), "2001:db8::1/0".into()];
        assert!(peer_is_exit_capable(&peer), "normalized dual defaults");

        peer.AllowedIPs = vec!["0.0.0.0/1".into(), "::/1".into()];
        assert!(!peer_is_exit_capable(&peer), "non-default prefixes");
    }
}
