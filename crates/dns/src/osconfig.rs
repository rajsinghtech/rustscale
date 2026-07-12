//! OS-level DNS configuration types and platform configurator trait.
//!
//! Ports `OSConfig` and the `OSConfigurator` interface from Go's
//! `net/dns/osconfig.go` and `net/dns/manager*.go`.

use std::net::IpAddr;

use rustscale_tailcfg::DNSConfig;

/// OS-level DNS configuration, matching Go's `OSConfig`.
///
/// `nameservers` are the IP addresses of the nameservers to use.
/// `search_domains` are suffixes for expanding single-label queries.
/// `match_domains` are the suffixes for which `nameservers` should be used
/// (split DNS). If empty, `nameservers` is installed as the primary resolver.
#[derive(Clone, Debug, Default)]
pub struct OsConfig {
    /// IP addresses of the nameservers to use.
    pub nameservers: Vec<IpAddr>,
    /// Domain suffixes for single-label name expansion.
    pub search_domains: Vec<String>,
    /// DNS suffixes for which `nameservers` should be used (split DNS).
    pub match_domains: Vec<String>,
}

/// An OS configurator applies DNS settings to the operating system.
///
/// Ports Go's `OSConfigurator` interface.
pub trait OsConfigurator {
    /// Update the OS's DNS configuration to match `cfg`. If `cfg` is the
    /// zero value, all Tailscale-related DNS configuration is removed.
    fn set_dns(&mut self, cfg: &OsConfig) -> std::io::Result<()>;

    /// Remove all Tailscale-related DNS configuration from the OS.
    fn close(&mut self) -> std::io::Result<()>;

    /// Whether the configurator supports split DNS (per-suffix resolvers).
    fn supports_split_dns(&self) -> bool;
}

/// A no-op configurator for platforms without a dedicated implementation.
pub struct NoopConfigurator;

impl OsConfigurator for NoopConfigurator {
    fn set_dns(&mut self, _cfg: &OsConfig) -> std::io::Result<()> {
        Ok(())
    }

    fn close(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    fn supports_split_dns(&self) -> bool {
        false
    }
}

/// Build an [`OsConfig`] from the control-plane [`DNSConfig`] and the
/// tailnet MagicDNS suffix (from `MapResponse.Domain`).
///
/// This mirrors the minimal subset of Go's
/// `dns.Manager.compileConfig` that applies on macOS (split-DNS capable):
///
/// - `nameservers` is always `100.100.100.100` (the MagicDNS VIP) — the
///   in-process DNS responder handles resolution and forwards upstream.
/// - `search_domains` are `DNSConfig.Domains` (single-label expansion).
/// - `match_domains` are the MagicDNS suffix (when `Proxied` is true) plus
///   any split-DNS route suffixes from `DNSConfig.Routes`. When non-empty,
///   the OS installs a split-DNS resolver for those suffixes pointing at
///   `100.100.100.100`. When empty, `nameservers` becomes the primary
///   resolver.
///
/// Pure function — does not touch the filesystem. Safe to call in tests.
pub fn build_os_dns_config(dns_config: &DNSConfig, magic_dns_suffix: &str) -> OsConfig {
    let nameservers = vec![IpAddr::V4(crate::MAGICDNS_VIP)];

    let search_domains = dns_config
        .Domains
        .iter()
        .map(|d| d.trim_end_matches('.').to_string())
        .collect();

    let mut match_domains: Vec<String> = Vec::new();

    if dns_config.Proxied {
        let suffix = magic_dns_suffix.trim_end_matches('.');
        if !suffix.is_empty() {
            match_domains.push(suffix.to_string());
        }
    }

    for suffix in dns_config.Routes.keys() {
        let s = suffix.trim_end_matches('.');
        if !s.is_empty() && !match_domains.iter().any(|d| d == s) {
            match_domains.push(s.to_string());
        }
    }

    OsConfig {
        nameservers,
        search_domains,
        match_domains,
    }
}

/// Create the platform-appropriate OS DNS configurator.
#[cfg(target_os = "macos")]
pub fn new_os_configurator() -> crate::osconfig_darwin::DarwinConfigurator {
    crate::osconfig_darwin::DarwinConfigurator::default()
}

/// Create the platform-appropriate OS DNS configurator.
#[cfg(not(target_os = "macos"))]
pub fn new_os_configurator() -> NoopConfigurator {
    NoopConfigurator
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    fn resolver(addr: &str) -> rustscale_tailcfg::Resolver {
        rustscale_tailcfg::Resolver { Addr: addr.into() }
    }

    #[test]
    fn build_os_dns_config_proxied() {
        let cfg = DNSConfig {
            Domains: vec!["tailnet.ts.net".into(), "corp.example".into()],
            Proxied: true,
            ..Default::default()
        };
        let os = build_os_dns_config(&cfg, "tailnet.ts.net");
        assert_eq!(
            os.nameservers,
            vec![IpAddr::V4(Ipv4Addr::new(100, 100, 100, 100))]
        );
        assert_eq!(os.search_domains, vec!["tailnet.ts.net", "corp.example"]);
        assert_eq!(os.match_domains, vec!["tailnet.ts.net"]);
    }

    #[test]
    fn build_os_dns_config_with_split_routes() {
        let mut routes = HashMap::new();
        routes.insert("corp.example.com.".to_string(), vec![resolver("10.0.0.53")]);
        routes.insert(
            "internal.example.com".to_string(),
            vec![resolver("10.0.0.54")],
        );
        let cfg = DNSConfig {
            Domains: vec!["tailnet.ts.net".into()],
            Proxied: true,
            Routes: routes,
            ..Default::default()
        };
        let os = build_os_dns_config(&cfg, "tailnet.ts.net");
        assert_eq!(os.match_domains.len(), 3);
        assert!(os.match_domains.contains(&"tailnet.ts.net".to_string()));
        assert!(os.match_domains.contains(&"corp.example.com".to_string()));
        assert!(os
            .match_domains
            .contains(&"internal.example.com".to_string()));
    }

    #[test]
    fn build_os_dns_config_not_proxied() {
        let cfg = DNSConfig {
            Domains: vec!["tailnet.ts.net".into()],
            Proxied: false,
            ..Default::default()
        };
        let os = build_os_dns_config(&cfg, "tailnet.ts.net");
        assert!(os.match_domains.is_empty());
        assert_eq!(os.search_domains, vec!["tailnet.ts.net"]);
    }

    #[test]
    fn build_os_dns_config_trailing_dots_stripped() {
        let cfg = DNSConfig {
            Domains: vec!["tailnet.ts.net.".into()],
            Proxied: true,
            ..Default::default()
        };
        let os = build_os_dns_config(&cfg, "tailnet.ts.net.");
        assert_eq!(os.search_domains, vec!["tailnet.ts.net"]);
        assert_eq!(os.match_domains, vec!["tailnet.ts.net"]);
    }

    #[test]
    fn build_os_dns_config_dedup_match_domains() {
        let mut routes = HashMap::new();
        routes.insert("tailnet.ts.net".to_string(), vec![resolver("10.0.0.53")]);
        let cfg = DNSConfig {
            Proxied: true,
            Routes: routes,
            ..Default::default()
        };
        let os = build_os_dns_config(&cfg, "tailnet.ts.net");
        assert_eq!(os.match_domains, vec!["tailnet.ts.net"]);
    }

    #[test]
    fn build_os_dns_config_empty() {
        let cfg = DNSConfig::default();
        let os = build_os_dns_config(&cfg, "");
        assert_eq!(
            os.nameservers,
            vec![IpAddr::V4(Ipv4Addr::new(100, 100, 100, 100))]
        );
        assert!(os.search_domains.is_empty());
        assert!(os.match_domains.is_empty());
    }
}
