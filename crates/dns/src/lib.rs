//! MagicDNS resolver and in-process DNS responder for rustscale.
//!
//! [`MagicDnsResolver`] answers `A`/`AAAA`/`PTR` queries for peer FQDNs and
//! short hostnames from the network map (the same logic Go's `dns/resolver`
//! uses for MagicDNS). It also handles split-DNS routing, ExtraRecords hosts,
//! `.onion` NXDOMAIN, 4via6 address synthesis, and TC truncation.
//!
//! [`DnsResponder`] serves UDP and length-prefixed TCP DNS on the MagicDNS VIP
//! `100.100.100.100:53`. It returns `NXDOMAIN` for unknown names within local
//! suffixes and forwards other queries through the longest matching split-DNS
//! route.

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use rustscale_tailcfg::{DNSConfig, Node};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

pub mod forwarder;
pub mod osconfig;
#[cfg(target_os = "macos")]
pub mod osconfig_darwin;
pub mod wire;

pub use forwarder::{Forwarder, UpstreamResolver};
pub use osconfig::{
    build_os_dns_config, new_os_configurator, NoopConfigurator, OsConfig, OsConfigurator,
};
#[cfg(target_os = "macos")]
pub use osconfig_darwin::DarwinConfigurator;
pub use wire::{
    build_a_response, build_aaaa_response, build_format_error_response, build_nxdomain,
    build_ptr_response, build_rcode_response, check_response_size_and_set_tc, parse_question,
    qtype, rcode,
};

/// The MagicDNS VIP that OS resolvers point at (`100.100.100.100`).
pub const MAGICDNS_VIP: Ipv4Addr = rustscale_tsaddr::tailscale_service_ipv4();

/// The MagicDNS IPv6 service VIP (`fd7a:115c:a1e0::53`).
pub const MAGICDNS_VIP_V6: Ipv6Addr = rustscale_tsaddr::tailscale_service_ipv6_addr();

/// The symbolic FQDN that resolves to the MagicDNS VIP.
const DNS_SYMBOLIC_FQDN: &str = "magicdns.localhost-tailscale-daemon.";

/// Default TTL for all MagicDNS responses (600 seconds, matching Go).
/// Used in wire.rs response builders.
#[allow(dead_code)]
const DEFAULT_TTL: u32 = 600;

/// The IPv4 suffix for reverse DNS lookups.
const RDNS_V4_SUFFIX: &str = ".in-addr.arpa.";

/// The IPv6 suffix for reverse DNS lookups.
const RDNS_V6_SUFFIX: &str = ".ip6.arpa.";

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

/// Resolver configuration, matching Go's `resolver.Config`.
///
/// Queries are resolved in the following order:
/// 1. If the query is an exact match for an entry in `hosts`, return that.
/// 2. Else if the query suffix matches an entry in `local_domains`, return NXDOMAIN.
/// 3. Else forward the query to the most specific matching entry in `routes`.
/// 4. Else return SERVFAIL.
#[derive(Clone, Debug, Default)]
pub struct Config {
    /// Whether DNS is accepted (from `Prefs.CorpDNS` / `--accept-dns`).
    pub accept_dns: bool,
    /// Split-DNS routes: FQDN suffix → upstream resolvers.
    /// The key `"."` is the default route.
    pub routes: HashMap<String, Vec<UpstreamResolver>>,
    /// Local hosts map: FQDN → IPs (from `DNSConfig.ExtraRecords` + peers).
    pub hosts: HashMap<String, Vec<IpAddr>>,
    /// Domains that should not be routed to upstream resolvers.
    pub local_domains: Vec<String>,
    /// Search domains (from `DNSConfig.Domains`).
    pub search_domains: Vec<String>,
    /// FQDNs from `hosts` that should also resolve subdomain queries.
    pub subdomain_hosts: HashSet<String>,
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
    /// Full resolver config (routes, hosts, local_domains, etc.)
    config: Config,
    /// Reverse map: IP → FQDN (built from hosts + peers).
    ip_to_host: HashMap<IpAddr, String>,
}

impl Default for MagicDnsResolver {
    fn default() -> Self {
        Self {
            peers: Vec::new(),
            domain: String::new(),
            proxied: true,
            config: Config::default(),
            ip_to_host: HashMap::new(),
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
        let domain = domain.into().trim_end_matches('.').to_lowercase();
        let config = build_config(dns_config, &domain, &peers);
        let ip_to_host = build_reverse_map(&config.hosts, &peers);
        Self {
            peers,
            domain,
            proxied,
            config,
            ip_to_host,
        }
    }

    /// Build a resolver from a peer slice with MagicDNS enabled by default.
    pub fn from_peers(peers: &[Node], domain: &str) -> Self {
        Self::new(peers.to_vec(), domain, None)
    }

    /// Replace the peer snapshot (called on netmap updates).
    pub fn set_peers(&mut self, peers: Vec<Node>) {
        self.peers = peers;
        // Rebuild hosts + ip_to_host from the new peer list.
        rebuild_config_from_peers(&mut self.config, &self.domain, &self.peers);
        self.ip_to_host = build_reverse_map(&self.config.hosts, &self.peers);
    }

    /// Atomically swap the resolver config (like Go's `Resolver.SetConfig`).
    /// Builds the reverse map from the new hosts and updates the forwarder.
    pub fn set_config(&mut self, cfg: Config) {
        self.ip_to_host = build_reverse_map(&cfg.hosts, &self.peers);
        self.config = cfg;
    }

    /// Get a reference to the current config.
    pub fn config(&self) -> &Config {
        &self.config
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
        !self.domain.is_empty() && !n.contains('.')
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
        // Check hosts map first (ExtraRecords + peer names).
        if let Some(addrs) = self.config.hosts.get(&n) {
            return addrs.clone();
        }
        // Check subdomain hosts.
        if let Some(addrs) = self.resolve_subdomain(&n) {
            return addrs;
        }
        // Check peers.
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

    /// Check if `name` matches a subdomain host (parent FQDN in subdomain_hosts).
    fn resolve_subdomain(&self, name: &str) -> Option<Vec<IpAddr>> {
        if self.config.subdomain_hosts.is_empty() {
            return None;
        }
        let mut current = name.to_string();
        loop {
            if let Some(idx) = current.find('.') {
                current = current[idx + 1..].to_string();
                if current.is_empty() {
                    break;
                }
                if self.config.subdomain_hosts.contains(&current) {
                    if let Some(addrs) = self.config.hosts.get(&current) {
                        return Some(addrs.clone());
                    }
                }
            } else {
                break;
            }
        }
        None
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
    /// `None` if the name is unknown *within the tailnet*.
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

    /// Resolve a local name and return the IP + RCODE (matching Go's
    /// `resolveLocal`). Returns `(None, RCODE)` for various rcode cases.
    pub fn resolve_local(&self, name: &str, qt: u16) -> (Option<IpAddr>, u8) {
        let n = name.trim_end_matches('.').to_lowercase();

        // Reject .onion domains per RFC 7686.
        if has_suffix(&n, ".onion") {
            return (None, rcode::NAME_ERROR);
        }

        // Symbolic domain: magicdns.localhost-tailscale-daemon.
        if n == DNS_SYMBOLIC_FQDN.trim_end_matches('.') {
            match qt {
                qtype::A => return (Some(IpAddr::V4(MAGICDNS_VIP)), rcode::SUCCESS),
                qtype::AAAA => return (Some(IpAddr::V6(MAGICDNS_VIP_V6)), rcode::SUCCESS),
                _ => {}
            }
        }

        // 4via6 DNS names: <ip>-via-<siteid>
        let (ip, ok) = Self::resolve_via_domain(&n, qt);
        if ok {
            if let Some(ip) = ip {
                return (Some(ip), rcode::SUCCESS);
            }
            return (None, rcode::SUCCESS);
        }

        // Check hosts map.
        let addrs = {
            let mut found = self.config.hosts.get(&n).cloned();
            if found.is_none() {
                found = self.resolve_subdomain(&n);
            }
            found
        };

        let found = match addrs {
            Some(a) if !a.is_empty() => a,
            _ => {
                // Not in hosts; check if it's a peer name.
                let peer_addrs = self.resolve(name);
                if peer_addrs.is_empty() {
                    // Check local_domains suffix.
                    for suffix in &self.config.local_domains {
                        if suffix_matches(suffix, &n) {
                            return (None, rcode::NAME_ERROR);
                        }
                    }
                    return (None, rcode::REFUSED);
                }
                peer_addrs
            }
        };

        match qt {
            qtype::A => {
                for ip in &found {
                    if let IpAddr::V4(v4) = ip {
                        return (Some(IpAddr::V4(*v4)), rcode::SUCCESS);
                    }
                }
                (None, rcode::SUCCESS)
            }
            qtype::AAAA => {
                for ip in &found {
                    if let IpAddr::V6(v6) = ip {
                        return (Some(IpAddr::V6(*v6)), rcode::SUCCESS);
                    }
                }
                (None, rcode::SUCCESS)
            }
            qtype::ALL => {
                if found.is_empty() {
                    (None, rcode::SUCCESS)
                } else {
                    (Some(found[0]), rcode::SUCCESS)
                }
            }
            qtype::NS | qtype::SOA | qtype::AXFR | qtype::HINFO => (None, rcode::NOT_IMPLEMENTED),
            _ => (None, rcode::SUCCESS),
        }
    }

    /// Synthesize an IP address for 4via6 DNS names of the form
    /// `<IPv4-with-hyphens>-via-<siteid>[.domain]`.
    /// Returns `(ip, true)` on success. If the name is a valid 4via6 domain
    /// but the qtype is A, returns `(None, true)` (name exists, no A record).
    /// Returns `(None, false)` if not a 4via6 domain.
    /// Ports Go's `resolveViaDomain` (tsdns.go:774-824).
    fn resolve_via_domain(dns_name: &str, qt: u16) -> (Option<IpAddr>, bool) {
        match qt {
            qtype::A | qtype::AAAA | qtype::ALL => {}
            _ => return (None, false),
        }

        if dns_name.len() < "0-0-0-0-via-0".len() {
            return (None, false);
        }
        if !dns_name.contains("-via-") {
            return (None, false);
        }

        let (first_label, domain) = match dns_name.split_once('.') {
            Some((a, b)) => (a, b),
            None => (dns_name, ""),
        };

        if !domain.is_empty()
            && !has_suffix(domain, "ts.net")
            && !has_suffix(domain, "tailscale.net")
        {
            return (None, false);
        }

        let (v4hyphens, suffix) = match first_label.split_once("-via-") {
            Some((a, b)) => (a, b),
            None => return (None, false),
        };

        let ip4_str = v4hyphens.replace('-', ".");
        let ip4: Ipv4Addr = match ip4_str.parse() {
            Ok(ip) => ip,
            Err(_) => return (None, false),
        };

        let site_id: u32 = match suffix.parse() {
            Ok(id) => id,
            Err(_) => return (None, false),
        };

        if qt == qtype::A {
            // The name exists, but cannot be resolved to an IPv4 address.
            return (None, true);
        }

        // Map the IPv4 address into the 4via6 range.
        let via_ip = map_via(site_id, ip4);
        (Some(IpAddr::V6(via_ip)), true)
    }

    /// Resolve a reverse DNS (PTR) query. Returns the FQDN and RCODE.
    /// Ports Go's `resolveLocalReverse` (tsdns.go:827-855).
    pub fn resolve_local_reverse(&self, name: &str) -> (String, u8) {
        let n = name.to_lowercase();

        let (ip, ok) = if n.ends_with(RDNS_V4_SUFFIX) {
            rdns_name_to_ipv4(&n)
        } else if n.ends_with(RDNS_V6_SUFFIX) {
            rdns_name_to_ipv6(&n)
        } else {
            (None, false)
        };

        if !ok {
            // Not a well-formed .arpa name; forward upstream.
            return (String::new(), rcode::REFUSED);
        }

        let ip = match ip {
            Some(ip) => ip,
            None => return (String::new(), rcode::REFUSED),
        };

        // If the IP is in the 4to6 range, try the corresponding IPv4.
        if let IpAddr::V6(v6) = ip {
            if let Some(v4) = tailscale_6to4(v6) {
                let (fqdn, code) = self.fqdn_for_ip(IpAddr::V4(v4), &n);
                if code == rcode::SUCCESS {
                    return (fqdn, code);
                }
            }
        }

        self.fqdn_for_ip(ip, &n)
    }

    /// Look up the FQDN for an IP. Must check ip_to_host and local_domains.
    fn fqdn_for_ip(&self, ip: IpAddr, name: &str) -> (String, u8) {
        // If it's the MagicDNS service IP, return the symbolic FQDN.
        if ip == IpAddr::V4(MAGICDNS_VIP) || ip == IpAddr::V6(MAGICDNS_VIP_V6) {
            return (DNS_SYMBOLIC_FQDN.to_string(), rcode::SUCCESS);
        }

        if let Some(fqdn) = self.ip_to_host.get(&ip) {
            return (fqdn.clone(), rcode::SUCCESS);
        }

        // Check local_domains.
        for suffix in &self.config.local_domains {
            if suffix_matches(suffix, name) {
                return (String::new(), rcode::NAME_ERROR);
            }
        }

        (String::new(), rcode::REFUSED)
    }

    /// Get the upstream resolvers for a given domain name, based on routes.
    /// Most-specific suffix match wins. Returns an empty vector for either an
    /// explicitly local route or no matching route; [`Self::upstream_route_for`]
    /// preserves that distinction for forwarding callers.
    pub fn upstream_resolvers_for(&self, name: &str) -> Vec<UpstreamResolver> {
        self.upstream_route_for(name).unwrap_or_default()
    }

    /// Return the longest matching split-DNS route.
    ///
    /// `Some([])` is an explicit local-only route and must not fall through to
    /// system DNS. `None` means no configured route matched, so the responder
    /// may use its base/system resolver fallback.
    pub fn upstream_route_for(&self, name: &str) -> Option<Vec<UpstreamResolver>> {
        let n = name.trim_end_matches('.').to_lowercase();
        self.config
            .routes
            .iter()
            .filter(|(suffix, _)| suffix.as_str() == "." || suffix_matches(suffix, &n))
            .max_by_key(|(suffix, _)| suffix_specificity(suffix))
            .map(|(_, resolvers)| resolvers.clone())
    }
}

/// Build the resolver [`Config`] from a `DNSConfig` + peers.
fn build_config(dns_config: Option<&DNSConfig>, domain: &str, peers: &[Node]) -> Config {
    let mut cfg = Config::default();

    if let Some(dc) = dns_config {
        cfg.accept_dns = true;
        cfg.search_domains.clone_from(&dc.Domains);

        // Build routes from DNSConfig.Routes. As in the pinned Go manager,
        // an empty resolver set is authoritative/local and is moved into
        // local_domains rather than being allowed to leak to a fallback.
        for (suffix, resolvers) in &dc.Routes {
            let suffix = normalize_suffix(suffix);
            if resolvers.is_empty() {
                if !cfg.local_domains.iter().any(|domain| domain == &suffix) {
                    cfg.local_domains.push(suffix);
                }
                continue;
            }
            let up: Vec<_> = resolvers
                .iter()
                .filter(|resolver| !resolver.Addr.is_empty())
                .map(|resolver| UpstreamResolver::from_addr(&resolver.Addr))
                .collect();
            if up.is_empty() {
                if !cfg.local_domains.iter().any(|domain| domain == &suffix) {
                    cfg.local_domains.push(suffix);
                }
            } else {
                cfg.routes.insert(suffix, up);
            }
        }

        // Add a default route from Resolvers, then FallbackResolvers, unless
        // DNSConfig.Routes explicitly supplied the root route (including an
        // empty local-only root route).
        let has_root_route = dc
            .Routes
            .keys()
            .any(|suffix| normalize_suffix(suffix) == ".");
        if !has_root_route && !cfg.routes.contains_key(".") {
            let source = if dc.Resolvers.is_empty() {
                &dc.FallbackResolvers
            } else {
                &dc.Resolvers
            };
            let default: Vec<UpstreamResolver> = source
                .iter()
                .filter(|resolver| !resolver.Addr.is_empty())
                .map(|resolver| UpstreamResolver::from_addr(&resolver.Addr))
                .collect();
            if !default.is_empty() {
                cfg.routes.insert(".".to_string(), default);
            }
        }

        // Build hosts from ExtraRecords.
        for rec in &dc.ExtraRecords {
            let name = rec.Name.trim_end_matches('.').to_lowercase();
            if let Ok(ip) = rec.Value.parse::<IpAddr>() {
                cfg.hosts.entry(name).or_default().push(ip);
            }
        }

        // Local domains: the tailnet domain + search domains + .arpa zones.
        if !domain.is_empty() {
            if !cfg.local_domains.iter().any(|local| local == domain) {
                cfg.local_domains.push(domain.to_string());
            }
            // Add reverse DNS zones for tailnet ranges.
            cfg.local_domains
                .push(format!("{}.in-addr.arpa.", rustscale_tsaddr::cgnat_range()));
            cfg.local_domains.push(format!(
                "{}.ip6.arpa.",
                rustscale_tsaddr::tailscale_ula_range()
            ));
        }
        for domain in &dc.Domains {
            let domain = normalize_suffix(domain);
            if !cfg.local_domains.iter().any(|local| local == &domain) {
                cfg.local_domains.push(domain);
            }
        }
    }

    // Add peer names to hosts.
    for peer in peers {
        if peer.Key.is_zero() {
            continue;
        }
        let peer_name = peer.Name.trim_end_matches('.').to_lowercase();
        if peer_name.is_empty() {
            continue;
        }
        let ips = node_ips(peer);
        if !ips.is_empty() {
            cfg.hosts.entry(peer_name).or_default().extend(ips);
        }
    }

    cfg
}

/// Rebuild the hosts and local_domains in config when peers change.
fn rebuild_config_from_peers(cfg: &mut Config, domain: &str, peers: &[Node]) {
    // Remove old peer entries (those that are FQDNs in the tailnet domain).
    cfg.hosts.retain(|name, _| {
        (domain.is_empty() || !name.ends_with(&format!(".{domain}"))) && name != domain
    });

    // Add current peer names.
    for peer in peers {
        if peer.Key.is_zero() {
            continue;
        }
        let peer_name = peer.Name.trim_end_matches('.').to_lowercase();
        if peer_name.is_empty() {
            continue;
        }
        let ips = node_ips(peer);
        if !ips.is_empty() {
            cfg.hosts.entry(peer_name).or_default().extend(ips);
        }
    }
}

/// Build the reverse IP → hostname map from hosts + peers.
fn build_reverse_map(
    hosts: &HashMap<String, Vec<IpAddr>>,
    peers: &[Node],
) -> HashMap<IpAddr, String> {
    let mut map = HashMap::new();
    for (host, ips) in hosts {
        for ip in ips {
            map.insert(*ip, host.clone());
        }
    }
    for peer in peers {
        if peer.Key.is_zero() {
            continue;
        }
        let peer_name = peer.Name.trim_end_matches('.').to_lowercase();
        if peer_name.is_empty() {
            continue;
        }
        for ip in node_ips(peer) {
            map.entry(ip).or_insert_with(|| peer_name.clone());
        }
    }
    map
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
    if !name.contains('.') && rustscale_dnsname::first_label(peer_name) == name {
        return true;
    }
    // Suffix match: `name` is `host` and peer is `host.<domain>` handled
    // above by short-name; also allow `name` without the domain suffix to
    // match a peer whose FQDN is `name.<domain>`.
    if domain.is_empty() || !name.ends_with(&format!(".{domain}")) {
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

/// Normalize a route/local suffix while preserving `.` as the DNS root.
fn normalize_suffix(suffix: &str) -> String {
    let suffix = suffix.trim_end_matches('.').to_lowercase();
    if suffix.is_empty() {
        ".".to_string()
    } else {
        suffix
    }
}

/// Rank a matching suffix by label count, as the pinned Go resolver does.
fn suffix_specificity(suffix: &str) -> usize {
    let suffix = suffix.trim_end_matches('.');
    if suffix.is_empty() {
        0
    } else {
        suffix.split('.').count()
    }
}

/// Check if `name` ends with `suffix` (case-insensitive, dot-aware).
/// A suffix of "." matches everything.
fn suffix_matches(suffix: &str, name: &str) -> bool {
    let suffix = suffix.trim_end_matches('.').to_lowercase();
    let name = name.trim_end_matches('.').to_lowercase();
    if suffix.is_empty() {
        return true;
    }
    if name == suffix {
        return true;
    }
    name.ends_with(&format!(".{suffix}"))
}

/// Check if `s` has the given suffix (case-insensitive).
fn has_suffix(s: &str, suffix: &str) -> bool {
    s.to_lowercase().ends_with(suffix)
}

/// Parse a `.in-addr.arpa` PTR name to an IPv4 address.
/// Ports Go's `rdnsNameToIPv4` (tsdns.go:1210-1221).
fn rdns_name_to_ipv4(name: &str) -> (Option<IpAddr>, bool) {
    let s = name.trim_end_matches(RDNS_V4_SUFFIX);
    let ip: Ipv4Addr = match s.parse() {
        Ok(ip) => ip,
        Err(_) => return (None, false),
    };
    let oct = ip.octets();
    // Reverse the octets.
    (
        Some(IpAddr::V4(Ipv4Addr::new(oct[3], oct[2], oct[1], oct[0]))),
        true,
    )
}

/// Parse a `.ip6.arpa` PTR name to an IPv6 address.
/// Ports Go's `rdnsNameToIPv6` (tsdns.go:1232-1266).
fn rdns_name_to_ipv6(name: &str) -> (Option<IpAddr>, bool) {
    let s = name.trim_end_matches(RDNS_V6_SUFFIX);
    // 32 nibbles and 31 dots between them = 63 chars.
    if s.len() != 63 {
        return (None, false);
    }

    let mut nibbles = [0u8; 32];
    let mut prev_dot = true;
    let mut j = 0;

    for i in (0..s.len()).rev() {
        let this_dot = s.as_bytes()[i] == b'.';
        if prev_dot == this_dot {
            return (None, false);
        }
        prev_dot = this_dot;

        if !this_dot {
            if j >= 32 {
                return (None, false);
            }
            nibbles[j] = s.as_bytes()[i];
            j += 1;
        }
    }

    if j != 32 {
        return (None, false);
    }

    // Decode hex nibbles into 16 bytes.
    let mut ipb = [0u8; 16];
    for i in 0..16 {
        let hi = match hex_val(nibbles[i * 2]) {
            Some(v) => v,
            None => return (None, false),
        };
        let lo = match hex_val(nibbles[i * 2 + 1]) {
            Some(v) => v,
            None => return (None, false),
        };
        ipb[i] = (hi << 4) | lo;
    }

    (Some(IpAddr::V6(Ipv6Addr::from(ipb))), true)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Map an IPv4 address + siteID into the Tailscale 4via6 range.
/// Delegates to `rustscale_tsaddr::map_via`.
fn map_via(site_id: u32, ip4: Ipv4Addr) -> Ipv6Addr {
    let p = rustscale_tsaddr::map_via(
        site_id,
        rustscale_tsaddr::IpPrefix {
            ip: IpAddr::V4(ip4),
            bits: 32,
        },
    )
    .expect("map_via: must be IPv4");
    match p.ip {
        IpAddr::V6(v6) => v6,
        _ => unreachable!(),
    }
}

/// Convert a Tailscale 4to6 IPv6 address back to IPv4.
/// Delegates to `rustscale_tsaddr::tailscale_6to4`.
fn tailscale_6to4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    rustscale_tsaddr::tailscale_6to4(v6)
}

/// Check if a name has a Bonjour mDNS service prefix.
/// Ports Go's `hasRDNSBonjourPrefix` (tsdns.go:1171-1184).
fn has_rdns_bonjour_prefix(name: &str) -> bool {
    let (base, rest) = match name.split_once('.') {
        Some((a, b)) => (a, b),
        None => return false,
    };
    match base {
        "b" | "db" | "r" | "dr" | "lb" => rest.starts_with("_dns-sd._udp."),
        _ => false,
    }
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
            if r.Addr.is_empty() {
                continue;
            }
            // Skip DoH/DoT — they're handled by the forwarder, not here.
            if r.Addr.starts_with("https://") || r.Addr.starts_with("tls://") {
                continue;
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

/// A callback invoked when a DNS response is served. The AppConnector
/// registers one to observe DNS responses for configured domains and
/// dynamically advertise routes.
pub type DnsResponseObserver = Arc<dyn Fn(&[u8]) + Send + Sync>;

/// Maximum inbound DNS-over-TCP query size, matching
/// `tailscale.com@v1.100.0/net/dns/manager.go`.
pub const MAX_TCP_REQUEST_SIZE: usize = 4096;

/// Upper bound on one local resolver query, matching Go's `dnsQueryTimeout`.
const DNS_QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Idle bound for each TCP frame read or write, matching Go's manager.
const TCP_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45);

/// A UDP and DNS-over-TCP responder serving MagicDNS answers and forwarding
/// non-local names through the longest matching suffix route.
pub struct DnsResponder {
    resolver: Arc<RwLock<MagicDnsResolver>>,
    bind: SocketAddr,
    forwarder: Arc<Forwarder>,
    observer: Option<DnsResponseObserver>,
}

impl DnsResponder {
    /// Create a new responder. `bind` is typically `100.100.100.100:53`.
    pub fn new(
        resolver: Arc<RwLock<MagicDnsResolver>>,
        upstream: Vec<SocketAddr>,
        bind: SocketAddr,
    ) -> Self {
        let defaults = upstream
            .iter()
            .map(|server| UpstreamResolver::from_addr(&server.to_string()))
            .collect();
        Self {
            resolver,
            bind,
            forwarder: Arc::new(Forwarder::new(defaults)),
            observer: None,
        }
    }

    /// Create a new responder with a forwarder for split-DNS + DoH support.
    pub fn with_forwarder(
        resolver: Arc<RwLock<MagicDnsResolver>>,
        bind: SocketAddr,
        forwarder: Arc<Forwarder>,
    ) -> Self {
        Self {
            resolver,
            bind,
            forwarder,
            observer: None,
        }
    }

    /// Set a DNS response observer callback. The observer is called with
    /// the raw DNS response bytes whenever the responder serves a response.
    /// Used by the AppConnector to observe DNS responses for configured
    /// domains and dynamically advertise routes.
    pub fn with_observer(mut self, observer: DnsResponseObserver) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Bind UDP and TCP to the same address and spawn the supervised query
    /// loops. Dropping or shutting down the returned handle cancels active
    /// queries and releases both listeners.
    pub async fn spawn(self) -> std::io::Result<DnsResponderHandle> {
        let (udp, tcp, local_addr) = bind_dns_sockets(self.bind).await?;
        if local_addr != self.bind {
            eprintln!(
                "DNS responder: bound to {local_addr} instead of {}",
                self.bind
            );
        }

        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let context = ResponderContext {
            resolver: self.resolver,
            forwarder: self.forwarder,
            observer: self.observer,
        };
        let task = tokio::spawn(async move {
            run_responder(udp, tcp, context, task_cancel).await;
        });
        Ok(DnsResponderHandle {
            local_addr,
            cancel,
            task: Some(task),
        })
    }
}

/// Lifecycle handle for a running [`DnsResponder`].
pub struct DnsResponderHandle {
    local_addr: SocketAddr,
    cancel: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl DnsResponderHandle {
    /// The shared UDP/TCP address selected by the responder.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Request cancellation, join all listener/session work, and release the
    /// shared UDP/TCP port before returning.
    pub async fn shutdown(mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }

    /// Transfer task ownership to an outer supervisor. Aborting the returned
    /// task drops both listeners and aborts every child query/session.
    pub fn into_join_handle(mut self) -> JoinHandle<()> {
        self.task
            .take()
            .expect("DNS responder task already transferred")
    }
}

impl Drop for DnsResponderHandle {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[derive(Clone)]
struct ResponderContext {
    resolver: Arc<RwLock<MagicDnsResolver>>,
    forwarder: Arc<Forwarder>,
    observer: Option<DnsResponseObserver>,
}

async fn bind_dns_sockets(
    requested: SocketAddr,
) -> std::io::Result<(tokio::net::UdpSocket, tokio::net::TcpListener, SocketAddr)> {
    let mut candidates = vec![
        requested,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    ];
    candidates.dedup();

    let mut last_error = None;
    for candidate in candidates {
        let tcp = match tokio::net::TcpListener::bind(candidate).await {
            Ok(listener) => listener,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let local_addr = tcp.local_addr()?;
        match tokio::net::UdpSocket::bind(local_addr).await {
            Ok(udp) => return Ok((udp, tcp, local_addr)),
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| std::io::Error::other("all DNS bind addresses failed")))
}

async fn run_responder(
    udp: tokio::net::UdpSocket,
    tcp: tokio::net::TcpListener,
    context: ResponderContext,
    cancel: CancellationToken,
) {
    let udp = Arc::new(udp);
    let mut children = JoinSet::new();
    let mut buf = vec![0u8; MAX_TCP_REQUEST_SIZE];

    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            received = udp.recv_from(&mut buf) => {
                let Ok((length, source)) = received else {
                    break;
                };
                let query = buf[..length].to_vec();
                let socket = Arc::clone(&udp);
                let child_context = context.clone();
                let child_cancel = cancel.clone();
                children.spawn(async move {
                    if let Some(response) = resolve_query(
                        &query,
                        &child_context,
                        "udp",
                        &child_cancel,
                    )
                    .await
                    {
                        observe_response(&child_context, &response);
                        let _ = socket.send_to(&response, source).await;
                    }
                });
            }
            accepted = tcp.accept() => {
                let Ok((stream, _source)) = accepted else {
                    break;
                };
                let child_context = context.clone();
                let child_cancel = cancel.clone();
                children.spawn(async move {
                    serve_tcp_connection(stream, child_context, child_cancel).await;
                });
            }
            Some(_) = children.join_next(), if !children.is_empty() => {}
        }
    }

    children.abort_all();
    while children.join_next().await.is_some() {}
}

async fn serve_tcp_connection(
    mut stream: tokio::net::TcpStream,
    context: ResponderContext,
    cancel: CancellationToken,
) {
    let _ = stream.set_nodelay(true);
    loop {
        let mut length_bytes = [0u8; 2];
        let read_length = tokio::select! {
            () = cancel.cancelled() => return,
            result = tokio::time::timeout(
                TCP_IDLE_TIMEOUT,
                stream.read_exact(&mut length_bytes),
            ) => result,
        };
        if !matches!(read_length, Ok(Ok(_))) {
            return;
        }

        let request_len = usize::from(u16::from_be_bytes(length_bytes));
        if request_len > MAX_TCP_REQUEST_SIZE {
            return;
        }
        let mut query = vec![0u8; request_len];
        let read_query = tokio::select! {
            () = cancel.cancelled() => return,
            result = tokio::time::timeout(
                TCP_IDLE_TIMEOUT,
                stream.read_exact(&mut query),
            ) => result,
        };
        if !matches!(read_query, Ok(Ok(_))) {
            return;
        }

        let Some(response) = resolve_query(&query, &context, "tcp", &cancel).await else {
            return;
        };
        let Ok(response_len) = u16::try_from(response.len()) else {
            return;
        };
        observe_response(&context, &response);
        let write_response = async {
            stream.write_all(&response_len.to_be_bytes()).await?;
            stream.write_all(&response).await
        };
        let written = tokio::select! {
            () = cancel.cancelled() => return,
            result = tokio::time::timeout(TCP_IDLE_TIMEOUT, write_response) => result,
        };
        if !matches!(written, Ok(Ok(()))) {
            return;
        }
    }
}

async fn resolve_query(
    query: &[u8],
    context: &ResponderContext,
    family: &str,
    cancel: &CancellationToken,
) -> Option<Vec<u8>> {
    tokio::select! {
        () = cancel.cancelled() => None,
        result = tokio::time::timeout(
            DNS_QUERY_TIMEOUT,
            handle_query(query, &context.resolver, &context.forwarder, family),
        ) => result.ok().flatten(),
    }
}

fn observe_response(context: &ResponderContext, response: &[u8]) {
    if let Some(observer) = &context.observer {
        observer(response);
    }
}

/// Handle a single DNS query: answer from MagicDNS, NXDOMAIN for unknown
/// tailnet names, or forward to upstream.
async fn handle_query(
    query: &[u8],
    resolver: &RwLock<MagicDnsResolver>,
    forwarder: &Forwarder,
    family: &str,
) -> Option<Vec<u8>> {
    let Some((name, qtype, _qclass)) = parse_question(query) else {
        return Some(build_format_error_response(query));
    };

    let r = resolver.read().await;

    // PTR queries: always try reverse lookup first.
    if qtype == qtype::PTR {
        // Check for Bonjour prefix — skip and forward.
        if has_rdns_bonjour_prefix(&name) {
            let route = r.upstream_route_for(&name);
            drop(r);
            return forward(query, forwarder, family, route.as_deref()).await;
        }

        let (fqdn, code) = r.resolve_local_reverse(&name);
        if code == rcode::REFUSED {
            // Not our name; forward upstream.
            let route = r.upstream_route_for(&name);
            drop(r);
            return forward(query, forwarder, family, route.as_deref()).await;
        }
        let response = if code == rcode::SUCCESS && !fqdn.is_empty() {
            build_ptr_response(query, &fqdn)
        } else {
            build_rcode_response(query, code)
        }?;
        return Some(finish_local_response(response, query, family));
    }

    // .onion rejection (RFC 7686).
    if name
        .trim_end_matches('.')
        .to_lowercase()
        .ends_with(".onion")
    {
        let response = build_rcode_response(query, rcode::NAME_ERROR)?;
        return Some(finish_local_response(response, query, family));
    }

    // Check if this is a local name (hosts, peers, 4via6, symbolic).
    let (ip, code) = r.resolve_local(&name, qtype);

    if code == rcode::REFUSED {
        // Not authoritative; route against the same resolver snapshot used for
        // the local decision, then release the lock before network I/O.
        let route = r.upstream_route_for(&name);
        drop(r);
        return forward(query, forwarder, family, route.as_deref()).await;
    }

    if code != rcode::SUCCESS {
        let response = build_rcode_response(query, code)?;
        return Some(finish_local_response(response, query, family));
    }

    // Build the response based on the resolved IP.
    let response = match ip {
        Some(IpAddr::V4(v4)) if qtype == qtype::A || qtype == qtype::ALL => {
            build_a_response(query, &[v4])?
        }
        Some(IpAddr::V6(v6)) if qtype == qtype::AAAA || qtype == qtype::ALL => {
            build_aaaa_response(query, &[v6])?
        }
        Some(IpAddr::V4(_)) if qtype == qtype::AAAA => {
            // Name exists but no AAAA record.
            build_rcode_response(query, rcode::SUCCESS)?
        }
        Some(IpAddr::V6(_)) if qtype == qtype::A => build_rcode_response(query, rcode::SUCCESS)?,
        _ => {
            // NOERROR with 0 answers (name exists, no records of this type).
            build_rcode_response(query, rcode::SUCCESS)?
        }
    };
    Some(finish_local_response(response, query, family))
}

fn finish_local_response(mut response: Vec<u8>, query: &[u8], family: &str) -> Vec<u8> {
    check_response_size_and_set_tc(&mut response, query, family);
    response
}

/// Forward a query through an already-selected live route.
async fn forward(
    query: &[u8],
    forwarder: &Forwarder,
    family: &str,
    route: Option<&[UpstreamResolver]>,
) -> Option<Vec<u8>> {
    forwarder.forward_with_resolvers(query, family, route).await
}

/// Build a config from a DNSConfig for use with `set_config`.
pub fn config_from_dns(dns_config: &DNSConfig, domain: &str, peers: &[Node]) -> Config {
    build_config(Some(dns_config), domain, peers)
}

#[cfg(test)]
mod tests;
