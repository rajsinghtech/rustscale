//! OS-level DNS configuration types and platform configurator trait.
//!
//! Ports `OSConfig` and the `OSConfigurator` interface from Go's
//! `net/dns/osconfig.go` and `net/dns/manager*.go`.

use std::net::IpAddr;

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
