//! MagicDNS name→IP resolution — ports Go's `net/tsdial/dns.go`.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use rustscale_tailcfg::{MapResponse, Node};

/// Errors from [`DnsMap`] resolution.
#[derive(Clone, Debug, thiserror::Error)]
pub enum DnsMapError {
    /// The address string could not be parsed as `host:port`.
    #[error("bad address: {0}")]
    BadAddr(String),
    /// The hostname did not resolve via MagicDNS.
    #[error("unresolved: {0}")]
    Unresolved(String),
}

/// Maps lowercased MagicDNS hostnames to tailnet IP addresses.
///
/// Built from a [`MapResponse`] on each netmap update. This is a *different*
/// cache from [`rustscale_dnscache::Resolver`] (which handles system DNS);
/// this one resolves peer names to tailnet IPs using the network map.
#[derive(Clone, Debug, Default)]
pub struct DnsMap(HashMap<String, IpAddr>);

impl DnsMap {
    /// Build a `DnsMap` from a [`MapResponse`].
    ///
    /// For the self node and each peer with a non-empty `Name`, add both the
    /// full name and the shortname (first label) → first tailnet IP. For each
    /// `DNSConfig.ExtraRecord` with empty `Type`, add `Name` → `Value`.
    pub fn from_network_map(nm: &MapResponse) -> Self {
        let mut map = HashMap::new();
        let domain = canon_map_key(&nm.Domain);

        if let Some(ref node) = nm.Node {
            add_node(&mut map, node, &domain);
        }
        for peer in &nm.Peers {
            add_node(&mut map, peer, &domain);
        }
        if let Some(ref dns) = nm.DNSConfig {
            for rec in &dns.ExtraRecords {
                if rec.Type.is_empty() {
                    if let Ok(ip) = rec.Value.parse::<IpAddr>() {
                        map.insert(canon_map_key(&rec.Name), ip);
                    }
                }
            }
        }
        Self(map)
    }

    /// Resolve `host:port` to a [`SocketAddr`] using the MagicDNS map.
    ///
    /// If `host` is a literal IP address it is returned directly. If the
    /// canonicalized host is in the map, the mapped IP is returned. Otherwise
    /// `None`.
    pub fn resolve(&self, host: &str, port: u16) -> Option<SocketAddr> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Some(SocketAddr::new(ip, port));
        }
        let key = canon_map_key(host);
        self.0.get(&key).map(|ip| SocketAddr::new(*ip, port))
    }

    /// Resolve a `network:addr` pair (e.g. `"tcp:100.64.0.1:443"`) to a
    /// [`SocketAddr`]. The `network` argument is accepted for Go parity but
    /// only TCP-style addresses are meaningful.
    pub fn resolve_memory(&self, network: &str, addr: &str) -> Result<SocketAddr, DnsMapError> {
        let _ = network;
        let (host, port) =
            split_host_port(addr).ok_or_else(|| DnsMapError::BadAddr(addr.into()))?;
        self.resolve(&host, port)
            .ok_or(DnsMapError::Unresolved(host))
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Add a node's name + shortname → first IP to the map.
fn add_node(map: &mut HashMap<String, IpAddr>, node: &Node, domain: &str) {
    let name = node.Name.trim_end_matches('.');
    if name.is_empty() {
        return;
    }
    let Some(ip) = first_node_ip(node) else {
        return;
    };
    let canon = name.to_lowercase();
    map.insert(canon.clone(), ip);
    // Shortname: first label before the tailnet domain suffix.
    if let Some(short) = shortname(&canon, domain) {
        map.insert(short, ip);
    }
}

/// Extract the first usable IP from a node's `Addresses` (CIDR strings).
fn first_node_ip(node: &Node) -> Option<IpAddr> {
    for addr in &node.Addresses {
        if let Some(ip_str) = addr.split('/').next() {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }
    None
}

/// Compute the shortname: strip the tailnet domain suffix, leaving the first
/// label. E.g. `"alice.example.ts.net"` with domain `"example.ts.net"` →
/// `"alice"`. If the name doesn't end with the domain, returns `None`.
fn shortname(name: &str, domain: &str) -> Option<String> {
    if domain.is_empty() {
        return None;
    }
    let suffix = format!(".{domain}");
    name.strip_suffix(&suffix)
        .map(std::string::ToString::to_string)
        .filter(|s| !s.is_empty() && !s.contains('.'))
}

/// Canonicalize a hostname for map lookup: lowercase + trim trailing dot.
pub fn canon_map_key(s: &str) -> String {
    s.trim_end_matches('.').to_lowercase()
}

/// Parse `host:port` or `[host]:port` into `(host, port)`.
pub fn split_host_port(addr: &str) -> Option<(String, u16)> {
    // IPv6 bracketed: [::1]:443
    if let Some(rest) = addr.strip_prefix('[') {
        let close = rest.find(']')?;
        let host = &rest[..close];
        let after = &rest[close + 1..];
        let port_str = after.strip_prefix(':')?;
        let port = port_str.parse::<u16>().ok()?;
        return Some((host.to_string(), port));
    }
    // IPv4 or hostname: host:port
    let idx = addr.rfind(':')?;
    let host = &addr[..idx];
    let port = addr[idx + 1..].parse::<u16>().ok()?;
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canon_map_key_basic() {
        assert_eq!(canon_map_key("Alice."), "alice");
        assert_eq!(canon_map_key("BOB.example.ts.net."), "bob.example.ts.net");
        assert_eq!(canon_map_key("charlie"), "charlie");
    }

    #[test]
    fn split_host_port_ipv4() {
        assert_eq!(
            split_host_port("example.com:443"),
            Some(("example.com".into(), 443))
        );
        assert_eq!(
            split_host_port("100.64.0.1:22"),
            Some(("100.64.0.1".into(), 22))
        );
    }

    #[test]
    fn split_host_port_ipv6() {
        assert_eq!(split_host_port("[::1]:443"), Some(("::1".into(), 443)));
        assert_eq!(
            split_host_port("[fe80::1]:8080"),
            Some(("fe80::1".into(), 8080))
        );
    }

    #[test]
    fn split_host_port_bad() {
        assert_eq!(split_host_port("noport"), None);
        assert_eq!(split_host_port(":443"), None);
        assert_eq!(split_host_port("host:abc"), None);
    }

    #[test]
    fn resolve_literal_ip() {
        let map = DnsMap::default();
        let sa = map.resolve("100.64.0.1", 443);
        assert_eq!(sa, Some(SocketAddr::from(([100, 64, 0, 1], 443))));
    }

    #[test]
    fn resolve_mapped_name() {
        let mut inner = HashMap::new();
        inner.insert("alice".into(), "100.64.0.2".parse().unwrap());
        let map = DnsMap(inner);
        let sa = map.resolve("alice", 22);
        assert_eq!(sa, Some(SocketAddr::from(([100, 64, 0, 2], 22))));
        // Case-insensitive + trailing dot
        let sa2 = map.resolve("ALICE.", 22);
        assert_eq!(sa2, Some(SocketAddr::from(([100, 64, 0, 2], 22))));
    }

    #[test]
    fn resolve_unmapped_returns_none() {
        let map = DnsMap::default();
        assert_eq!(map.resolve("unknown.host", 80), None);
    }

    #[test]
    fn resolve_memory_ok() {
        let mut inner = HashMap::new();
        inner.insert("bob".into(), "100.64.0.3".parse().unwrap());
        let map = DnsMap(inner);
        let r = map.resolve_memory("tcp", "bob:443");
        assert!(r.is_ok());
        assert_eq!(r.unwrap().port(), 443);
    }

    #[test]
    fn resolve_memory_bad_addr() {
        let map = DnsMap::default();
        assert!(matches!(
            map.resolve_memory("tcp", "noport"),
            Err(DnsMapError::BadAddr(_))
        ));
    }

    #[test]
    fn resolve_memory_unresolved() {
        let map = DnsMap::default();
        assert!(matches!(
            map.resolve_memory("tcp", "ghost:443"),
            Err(DnsMapError::Unresolved(_))
        ));
    }

    #[test]
    fn from_network_map_basic() {
        use rustscale_tailcfg::{MapResponse, Node};

        let node = Node {
            ID: 1,
            Name: "alice.example.ts.net".into(),
            Addresses: vec!["100.64.0.1/32".into()],
            ..Default::default()
        };

        let peer = Node {
            ID: 2,
            Name: "bob.example.ts.net".into(),
            Addresses: vec!["100.64.0.2/32".into()],
            ..Default::default()
        };

        let nm = MapResponse {
            Node: Some(node),
            Peers: vec![peer],
            Domain: "example.ts.net".into(),
            ..Default::default()
        };

        let map = DnsMap::from_network_map(&nm);

        // Full names
        assert_eq!(
            map.resolve("alice.example.ts.net", 443),
            Some(SocketAddr::from(([100, 64, 0, 1], 443)))
        );
        assert_eq!(
            map.resolve("bob.example.ts.net", 22),
            Some(SocketAddr::from(([100, 64, 0, 2], 22)))
        );
        // Shortnames
        assert_eq!(
            map.resolve("alice", 443),
            Some(SocketAddr::from(([100, 64, 0, 1], 443)))
        );
        assert_eq!(
            map.resolve("BOB.", 22),
            Some(SocketAddr::from(([100, 64, 0, 2], 22)))
        );
    }

    #[test]
    fn from_network_map_extra_records() {
        use rustscale_tailcfg::{DNSConfig, DNSRecord, MapResponse, Node};

        let node = Node {
            ID: 1,
            Name: "self.example.ts.net".into(),
            Addresses: vec!["100.64.0.1/32".into()],
            ..Default::default()
        };

        let nm = MapResponse {
            Node: Some(node),
            Domain: "example.ts.net".into(),
            DNSConfig: Some(DNSConfig {
                ExtraRecords: vec![DNSRecord {
                    Name: "custom.example.ts.net".into(),
                    Type: String::new(),
                    Value: "100.64.0.99".into(),
                }],
                ..Default::default()
            }),
            ..Default::default()
        };

        let map = DnsMap::from_network_map(&nm);
        assert_eq!(
            map.resolve("custom.example.ts.net", 80),
            Some(SocketAddr::from(([100, 64, 0, 99], 80)))
        );
    }

    #[test]
    fn from_network_map_skips_unnamed() {
        use rustscale_tailcfg::{MapResponse, Node};

        let peer = Node {
            ID: 2,
            Name: String::new(), // unnamed
            Addresses: vec!["100.64.0.2/32".into()],
            ..Default::default()
        };

        let nm = MapResponse {
            Peers: vec![peer],
            ..Default::default()
        };

        let map = DnsMap::from_network_map(&nm);
        assert!(map.is_empty());
    }

    #[test]
    fn shortname_logic() {
        assert_eq!(
            shortname("alice.example.ts.net", "example.ts.net"),
            Some("alice".into())
        );
        // Multi-label prefix not treated as shortname
        assert_eq!(shortname("a.b.example.ts.net", "example.ts.net"), None);
        // No domain set
        assert_eq!(shortname("alice", ""), None);
    }
}
