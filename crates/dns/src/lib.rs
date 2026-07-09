//! MagicDNS resolver and in-process DNS responder for rustscale.
//!
//! [`MagicDnsResolver`] answers `A`/`AAAA` queries for peer FQDNs and short
//! hostnames from the network map (the same logic Go's `dns/resolver` uses
//! for MagicDNS). [`DnsResponder`] is a minimal UDP DNS server bound to the
//! MagicDNS VIP `100.100.100.100:53` that serves those answers, returns
//! `NXDOMAIN` for unknown names within the tailnet domain, and forwards
//! everything else to an upstream system resolver.
//!
//! Both the DNS responder and tsnet's `dial("hostname:port")` path share
//! [`MagicDnsResolver`] so resolution is unified.

#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use rustscale_tailcfg::{DNSConfig, Node};

pub mod wire;

pub use wire::{build_a_response, build_aaaa_response, build_nxdomain, parse_question};

/// The MagicDNS VIP that OS resolvers point at (`100.100.100.100`).
pub const MAGICDNS_VIP: Ipv4Addr = Ipv4Addr::new(100, 100, 100, 100);

/// Outcome of resolving a name against the netmap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolveOutcome {
    /// The name is a tailnet name and resolved to these addresses (A/AAAA).
    Answer(Vec<IpAddr>),
    /// The name is a tailnet name but no peer matched.
    NxDomain,
    /// The name is not a tailnet name; forward it upstream.
    NotTailnet,
}

/// A MagicDNS resolver backed by the network map.
///
/// Cheap to clone (it owns a `Vec<Node>` snapshot). For live updates, wrap it
/// in an `Arc<RwLock<MagicDnsResolver>>` and replace the snapshot on netmap
/// changes.
#[derive(Clone, Debug)]
pub struct MagicDnsResolver {
    peers: Vec<Node>,
    /// Tailnet domain (e.g. `"tailnet.ts.net"`), no trailing dot.
    domain: String,
    proxied: bool,
}

impl Default for MagicDnsResolver {
    fn default() -> Self {
        Self {
            peers: Vec::new(),
            domain: String::new(),
            proxied: true,
        }
    }
}

impl MagicDnsResolver {
    /// Build a resolver from a peer snapshot, the tailnet domain (from
    /// `MapResponse.Domain`), and the DNS config (for `Proxied`).
    pub fn new(
        peers: Vec<Node>,
        domain: impl Into<String>,
        dns_config: Option<&DNSConfig>,
    ) -> Self {
        let proxied = match dns_config {
            Some(c) => c.Proxied,
            None => true,
        };
        Self {
            peers,
            domain: domain.into().trim_end_matches('.').to_lowercase(),
            proxied,
        }
    }

    /// Build a resolver from a peer slice with MagicDNS enabled by default.
    pub fn from_peers(peers: &[Node], domain: &str) -> Self {
        Self::new(peers.to_vec(), domain, None)
    }

    /// Replace the peer snapshot (called on netmap updates).
    pub fn set_peers(&mut self, peers: Vec<Node>) {
        self.peers = peers;
    }

    /// Whether `name` is a name MagicDNS should answer authoritatively:
    /// the apex domain, a name ending in `.<domain>`, or a single-label
    /// short name (when MagicDNS is proxied/enabled).
    pub fn is_tailnet_name(&self, name: &str) -> bool {
        if !self.proxied {
            return false;
        }
        let n = name.trim_end_matches('.').to_lowercase();
        if n.is_empty() {
            return false;
        }
        // Apex domain itself.
        if !self.domain.is_empty() && n == self.domain {
            return true;
        }
        // Fully-qualified within the tailnet domain.
        if !self.domain.is_empty() && n.ends_with(&format!(".{}", self.domain)) {
            return true;
        }
        // Single-label short name (no dots) — MagicDNS resolves these.
        !n.contains('.')
    }

    /// Resolve `A` records for `name` from the netmap.
    pub fn resolve_a(&self, name: &str) -> Vec<Ipv4Addr> {
        self.resolve(name)
            .into_iter()
            .filter_map(|ip| match ip {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            })
            .collect()
    }

    /// Resolve `AAAA` records for `name` from the netmap.
    pub fn resolve_aaaa(&self, name: &str) -> Vec<Ipv6Addr> {
        self.resolve(name)
            .into_iter()
            .filter_map(|ip| match ip {
                IpAddr::V6(v6) => Some(v6),
                IpAddr::V4(_) => None,
            })
            .collect()
    }

    /// Resolve `name` to all matching peer IPs (v4 + v6).
    pub fn resolve(&self, name: &str) -> Vec<IpAddr> {
        let n = name.trim_end_matches('.').to_lowercase();
        for peer in &self.peers {
            if peer.Key.is_zero() {
                continue;
            }
            if peer_matches(peer, &n, &self.domain) {
                return node_ips(peer);
            }
        }
        Vec::new()
    }

    /// Full resolution decision: answer, NXDOMAIN, or forward upstream.
    pub fn lookup(&self, name: &str) -> ResolveOutcome {
        if !self.is_tailnet_name(name) {
            return ResolveOutcome::NotTailnet;
        }
        let addrs = self.resolve(name);
        if addrs.is_empty() {
            ResolveOutcome::NxDomain
        } else {
            ResolveOutcome::Answer(addrs)
        }
    }

    /// Convenience for dial: the first IP (v4 preferred) for a name, or
    /// `None` if the name is unknown *within the tailnet*. Names outside the
    /// tailnet domain also return `None` (the dial path only resolves
    /// tailnet names; non-tailnet dialing goes through the netstack's IP
    /// path).
    pub fn resolve_first(&self, name: &str) -> Option<IpAddr> {
        let addrs = self.resolve(name);
        addrs
            .iter()
            .find(|ip| matches!(ip, IpAddr::V4(_)))
            .or(addrs.first())
            .copied()
    }

    /// The configured search domains (from `DNSConfig.Domains`).
    pub fn domain(&self) -> &str {
        &self.domain
    }
}

/// Whether a peer's MagicDNS name matches `name` (lowercased, no trailing dot).
fn peer_matches(peer: &Node, name: &str, domain: &str) -> bool {
    let peer_name = peer.Name.to_lowercase();
    let peer_name = peer_name.trim_end_matches('.');
    if peer_name == name {
        return true;
    }
    // Short-name match: the first label of the peer's FQDN equals `name`
    // (only meaningful for single-label `name`).
    if !name.contains('.') {
        if let Some(first_label) = peer_name.split('.').next() {
            if first_label == name {
                return true;
            }
        }
    }
    // Suffix match: `name` is `host` and peer is `host.<domain>` handled
    // above by short-name; also allow `name` without the domain suffix to
    // match a peer whose FQDN is `name.<domain>`.
    if !domain.is_empty() && !name.ends_with(&format!(".{domain}")) {
        let full = format!("{name}.{domain}");
        if peer_name == full {
            return true;
        }
    }
    false
}

/// Extract all IPs (v4 + v6) from a peer's `Addresses` CIDR list.
fn node_ips(peer: &Node) -> Vec<IpAddr> {
    peer.Addresses
        .iter()
        .filter_map(|s| s.split('/').next().and_then(|ip| ip.parse::<IpAddr>().ok()))
        .collect()
}

/// Read system nameserver addresses from `/etc/resolv.conf`. Returns the
/// first usable set, falling back to `1.1.1.1:53` / `8.8.8.8:53`.
pub fn system_nameservers() -> Vec<SocketAddr> {
    let mut servers: Vec<SocketAddr> = Vec::new();
    if let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in text.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("nameserver ") {
                let ip = rest.trim();
                if let Ok(addr) = ip.parse::<IpAddr>() {
                    servers.push(SocketAddr::new(addr, 53));
                }
            }
        }
    }
    if servers.is_empty() {
        servers.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53));
        servers.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53));
    }
    servers
}

/// Build the upstream resolver list from `DNSConfig.Resolvers` (preferring
/// plain-IP classic resolvers), falling back to system nameservers.
pub fn upstream_nameservers(dns_config: Option<&DNSConfig>) -> Vec<SocketAddr> {
    let mut servers: Vec<SocketAddr> = Vec::new();
    if let Some(cfg) = dns_config {
        for r in &cfg.Resolvers {
            // Only classic UDP resolvers (plain IP or IP:port) for forwarding.
            if r.Addr.is_empty() {
                continue;
            }
            if r.Addr.starts_with('h') || r.Addr.starts_with('t') {
                continue; // DoH/DoT — not supported by the UDP forwarder.
            }
            if let Ok(ip) = r.Addr.parse::<IpAddr>() {
                servers.push(SocketAddr::new(ip, 53));
            } else if let Ok(sa) = r.Addr.parse::<SocketAddr>() {
                servers.push(sa);
            }
        }
    }
    if servers.is_empty() {
        servers = system_nameservers();
    }
    servers
}

/// A minimal UDP DNS responder serving MagicDNS answers and forwarding the
/// rest upstream.
pub struct DnsResponder {
    resolver: std::sync::Arc<tokio::sync::RwLock<MagicDnsResolver>>,
    upstream: Vec<SocketAddr>,
    bind: SocketAddr,
}

impl DnsResponder {
    /// Create a new responder. `bind` is typically `100.100.100.100:53`.
    pub fn new(
        resolver: std::sync::Arc<tokio::sync::RwLock<MagicDnsResolver>>,
        upstream: Vec<SocketAddr>,
        bind: SocketAddr,
    ) -> Self {
        Self {
            resolver,
            upstream,
            bind,
        }
    }

    /// Bind the UDP socket and spawn the query loop. Returns the task handle
    /// on success. Binding to `:53` typically requires root; failure is
    /// non-fatal and logged by the caller.
    pub async fn spawn(self) -> std::io::Result<tokio::task::JoinHandle<()>> {
        let sock = std::sync::Arc::new(tokio::net::UdpSocket::bind(self.bind).await?);
        let upstream = self.upstream;
        let resolver = self.resolver;
        Ok(tokio::spawn(async move {
            let mut buf = vec![0u8; 1500];
            loop {
                let Ok((n, src)) = sock.recv_from(&mut buf).await else {
                    continue;
                };
                let query = buf[..n].to_vec();
                let resolver = resolver.clone();
                let upstream = upstream.clone();
                let sock = sock.clone();
                tokio::spawn(async move {
                    if let Some(resp) = handle_query(&query, &resolver, &upstream).await {
                        let _ = sock.send_to(&resp, src).await;
                    }
                });
            }
        }))
    }
}

/// Handle a single DNS query: answer from MagicDNS, NXDOMAIN for unknown
/// tailnet names, or forward to upstream. Returns the response bytes (or
/// `None` if the query is unparseable and should be dropped).
async fn handle_query(
    query: &[u8],
    resolver: &tokio::sync::RwLock<MagicDnsResolver>,
    upstream: &[SocketAddr],
) -> Option<Vec<u8>> {
    // Only A (1) and AAAA (28) are answered from the netmap.
    const TYPE_A: u16 = 1;
    const TYPE_AAAA: u16 = 28;

    let (name, qtype, _qclass) = parse_question(query)?;

    let r = resolver.read().await;
    if !r.is_tailnet_name(&name) {
        drop(r);
        return forward_upstream(query, upstream).await;
    }

    match r.lookup(&name) {
        ResolveOutcome::Answer(ips) => {
            if qtype == TYPE_A {
                let v4: Vec<Ipv4Addr> = ips
                    .iter()
                    .filter_map(|ip| match ip {
                        IpAddr::V4(v4) => Some(*v4),
                        IpAddr::V6(_) => None,
                    })
                    .collect();
                if v4.is_empty() {
                    return build_nxdomain(query);
                }
                build_a_response(query, &v4)
            } else if qtype == TYPE_AAAA {
                let v6: Vec<Ipv6Addr> = ips
                    .iter()
                    .filter_map(|ip| match ip {
                        IpAddr::V6(v6) => Some(*v6),
                        IpAddr::V4(_) => None,
                    })
                    .collect();
                if v6.is_empty() {
                    return build_nxdomain(query);
                }
                build_aaaa_response(query, &v6)
            } else {
                // Known peer but unsupported qtype: NOERROR with 0 answers.
                Some(build_nxdomain_noerror(query))
            }
        }
        ResolveOutcome::NxDomain => build_nxdomain(query),
        ResolveOutcome::NotTailnet => {
            drop(r);
            forward_upstream(query, upstream).await
        }
    }
}

/// Forward a raw DNS query to the first reachable upstream resolver and
/// return its response verbatim.
async fn forward_upstream(query: &[u8], upstream: &[SocketAddr]) -> Option<Vec<u8>> {
    for server in upstream {
        let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
        if sock.send_to(query, server).await.is_err() {
            continue;
        }
        let mut buf = vec![0u8; 1500];
        let fut = tokio::time::timeout(std::time::Duration::from_secs(2), sock.recv(&mut buf));
        if let Ok(Ok(n)) = fut.await {
            return Some(buf[..n].to_vec());
        }
    }
    None
}

/// Build a NOERROR response with 0 answers (for known peer, unsupported qtype).
fn build_nxdomain_noerror(query: &[u8]) -> Vec<u8> {
    // Same as NXDOMAIN but RCODE=0.
    let mut resp = query.to_vec();
    if resp.len() < 12 {
        return query.to_vec();
    }
    // Flags at bytes 2..4. Set QR=1, clear all RCODE, keep RD/Opcode.
    let flags = u16::from_be_bytes([resp[2], resp[3]]);
    let opcode = (flags >> 11) & 0b1111;
    let rd = (flags >> 8) & 0b1;
    let new_flags = 0b1000_0000_0000_0000 // QR
        | (opcode << 11)
        | (rd << 8)
        | 0b1000_0000; // RA
    resp[2..4].copy_from_slice(&new_flags.to_be_bytes());
    // ANCOUNT/NSCOUNT/ARCOUNT = 0 (already 0 in query).
    resp
}

#[cfg(test)]
mod tests;
