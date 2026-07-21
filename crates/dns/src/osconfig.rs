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
#[derive(Clone, Debug, Default, PartialEq, Eq)]
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
/// - `nameservers` is the MagicDNS VIP only when this plan has an explicit
///   route. Empty control DNS does not capture host DNS.
/// - `search_domains` are de-duplicated `DNSConfig.Domains`.
/// - `match_domains` are the MagicDNS suffix (when `Proxied` is true) plus
///   control route suffixes. The root route is retained as `"."`: Linux maps
///   that to resolved's `~.` and enables the link default route.
///
/// Pure function — does not touch the filesystem. Safe to call in tests.
pub fn build_os_dns_config(dns_config: &DNSConfig, magic_dns_suffix: &str) -> OsConfig {
    let mut search_domains = Vec::new();
    for domain in &dns_config.Domains {
        let domain = domain.trim_end_matches('.');
        if !domain.is_empty()
            && !search_domains
                .iter()
                .any(|existing: &String| existing.eq_ignore_ascii_case(domain))
        {
            search_domains.push(domain.to_string());
        }
    }

    let mut match_domains: Vec<String> = Vec::new();
    if dns_config.Proxied {
        let suffix = magic_dns_suffix.trim_end_matches('.');
        // A proxied configuration without a tailnet suffix is necessarily a
        // global plan. Keep that explicit rather than relying on an implicit
        // DefaultRoute selection.
        match_domains.push(if suffix.is_empty() {
            ".".into()
        } else {
            suffix.into()
        });
    }
    for suffix in dns_config.Routes.keys() {
        let suffix = suffix.trim_end_matches('.');
        let suffix = if suffix.is_empty() { "." } else { suffix };
        if !match_domains
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(suffix))
        {
            match_domains.push(suffix.to_string());
        }
    }
    // Resolvers/FallbackResolvers compile to the responder's root route even
    // when Routes does not spell one out. The OS plan must select the same VIP
    // globally or those control-selected upstreams are unreachable.
    let has_default_resolvers = dns_config
        .Resolvers
        .iter()
        .chain(&dns_config.FallbackResolvers)
        .any(|resolver| !resolver.Addr.is_empty());
    if has_default_resolvers
        && !match_domains
            .iter()
            .any(|domain| domain.trim_end_matches('.').is_empty())
    {
        match_domains.push(".".into());
    }

    // Search-only config must not turn the VIP into a global resolver.
    let nameservers = if match_domains.is_empty() {
        Vec::new()
    } else {
        vec![rustscale_tsaddr::tailscale_service_ip()]
    };
    OsConfig {
        nameservers,
        search_domains,
        match_domains,
    }
}

/// Create the platform-appropriate OS DNS configurator.
///
/// Linux is deliberately explicit: MagicDNS in TUN mode requires a real
/// systemd-resolved per-link configurator, not a successful no-op. Other
/// unsupported platforms keep the no-op implementation for embedding callers.
#[cfg(target_os = "linux")]
pub fn new_os_configurator(
    interface: Option<&str>,
) -> std::io::Result<Box<dyn OsConfigurator + Send>> {
    let interface = interface.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Linux DNS configuration requires a TUN interface",
        )
    })?;
    Ok(Box::new(
        crate::osconfig_linux::LinuxResolvedConfigurator::new(interface)?,
    ))
}

/// Create the platform-appropriate OS DNS configurator.
#[cfg(target_os = "macos")]
pub fn new_os_configurator(
    _interface: Option<&str>,
) -> std::io::Result<Box<dyn OsConfigurator + Send>> {
    Ok(Box::new(
        crate::osconfig_darwin::DarwinConfigurator::default(),
    ))
}

/// Create the platform-appropriate OS DNS configurator.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn new_os_configurator(
    _interface: Option<&str>,
) -> std::io::Result<Box<dyn OsConfigurator + Send>> {
    Ok(Box::new(NoopConfigurator))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

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
            vec![rustscale_tsaddr::tailscale_service_ip()]
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
    fn build_os_dns_config_default_resolvers_install_root_route() {
        let cfg = DNSConfig {
            Resolvers: vec![resolver("9.9.9.9")],
            ..Default::default()
        };
        let os = build_os_dns_config(&cfg, "tailnet.ts.net");
        assert_eq!(
            os.nameservers,
            vec![rustscale_tsaddr::tailscale_service_ip()]
        );
        assert_eq!(os.match_domains, vec!["."]);
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
        assert!(
            os.nameservers.is_empty(),
            "search domains must not capture global DNS"
        );
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
    fn build_os_dns_config_empty_does_not_capture_global_dns() {
        let cfg = DNSConfig::default();
        let os = build_os_dns_config(&cfg, "");
        assert!(os.nameservers.is_empty());
        assert!(os.search_domains.is_empty());
        assert!(os.match_domains.is_empty());
    }

    #[test]
    fn build_os_dns_config_preserves_global_root_route() {
        let mut routes = HashMap::new();
        routes.insert(".".to_string(), vec![resolver("10.0.0.53")]);
        let os = build_os_dns_config(
            &DNSConfig {
                Routes: routes,
                ..Default::default()
            },
            "",
        );
        assert_eq!(os.match_domains, vec!["."]);
        assert_eq!(
            os.nameservers,
            vec![rustscale_tsaddr::tailscale_service_ip()]
        );
    }
}
