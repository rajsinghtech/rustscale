//! macOS DNS OS configurator.
//!
//! Ports Go's `net/dns/manager_darwin.go`. Maintains split-DNS nameserver
//! entries in `/etc/resolver/$SUFFIX` files, pointing MagicDNS suffixes at
//! the Tailscale resolver (100.100.100.100). Each file starts with a header
//! marker so we can distinguish our files from foreign ones during cleanup.

use std::fs;
use std::io;
use std::path::Path;

use crate::osconfig::{OsConfig, OsConfigurator};

/// Header marker written into every resolver file we own, so we can
/// recognize our files during cleanup and leave foreign files alone.
const MAC_RESOLVER_FILE_HEADER: &str = "# Added by tailscaled\n";

/// Fake DNS suffix used as the filename for the search-domains directive.
const SEARCH_FILE: &str = "search.tailscale";

/// macOS DNS configurator that writes `/etc/resolver/$SUFFIX` files.
///
/// `resolver_dir` and `resolv_conf_path` are struct fields so tests can
/// point them at temp dirs.
pub struct DarwinConfigurator {
    /// Directory for resolver files (default `/etc/resolver`).
    resolver_dir: String,
    /// Path to resolv.conf (default `/etc/resolv.conf`); used by GetBaseConfig
    /// which is not yet ported.
    #[allow(dead_code)]
    resolv_conf_path: String,
}

impl Default for DarwinConfigurator {
    fn default() -> Self {
        Self {
            resolver_dir: "/etc/resolver".to_string(),
            resolv_conf_path: "/etc/resolv.conf".to_string(),
        }
    }
}

impl DarwinConfigurator {
    /// Create a configurator with custom paths (for testing).
    pub fn new(resolver_dir: impl Into<String>, resolv_conf_path: impl Into<String>) -> Self {
        Self {
            resolver_dir: resolver_dir.into(),
            resolv_conf_path: resolv_conf_path.into(),
        }
    }

    /// Delete all regular files in the resolver dir for which `should_delete`
    /// returns true AND that contain our header marker. Foreign files are
    /// never touched.
    fn remove_resolver_files<F>(&self, should_delete: F) -> io::Result<()>
    where
        F: Fn(&str) -> bool,
    {
        let dir = Path::new(&self.resolver_dir);
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };

        for entry in entries {
            let entry = entry?;
            let ft = entry.file_type()?;
            if !ft.is_file() {
                continue;
            }
            let file_name = entry.file_name();
            let name = match file_name.to_str() {
                Some(s) => s,
                None => continue,
            };
            if !should_delete(name) {
                continue;
            }
            let contents = match fs::read_to_string(entry.path()) {
                Ok(c) => c,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            if !contents.starts_with(MAC_RESOLVER_FILE_HEADER) {
                continue;
            }
            fs::remove_file(entry.path())?;
        }
        Ok(())
    }
}

impl OsConfigurator for DarwinConfigurator {
    fn set_dns(&mut self, cfg: &OsConfig) -> io::Result<()> {
        // Build the shared resolver file content: header + nameserver lines.
        let mut buf = String::from(MAC_RESOLVER_FILE_HEADER);
        for ip in &cfg.nameservers {
            buf.push_str("nameserver ");
            buf.push_str(&ip.to_string());
            buf.push('\n');
        }

        let dir = Path::new(&self.resolver_dir);
        fs::create_dir_all(dir)?;

        let mut keep: Vec<String> = Vec::new();

        // Search domains: write a single "search.tailscale" file with a
        // "search ..." directive.
        if !cfg.search_domains.is_empty() {
            keep.push(SEARCH_FILE.to_string());
            let mut sbuf = String::from(MAC_RESOLVER_FILE_HEADER);
            sbuf.push_str("search");
            for d in &cfg.search_domains {
                sbuf.push(' ');
                sbuf.push_str(d.trim_end_matches('.'));
            }
            sbuf.push('\n');
            fs::write(dir.join(SEARCH_FILE), sbuf)?;
        }

        // Match domains: one resolver file per domain, each containing the
        // shared nameserver content.
        for d in &cfg.match_domains {
            let file_base = d.trim_end_matches('.');
            keep.push(file_base.to_string());

            if !is_valid_resolver_file_name(file_base) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "invalid resolver domain {:?}: must not contain slashes or colons",
                        file_base
                    ),
                ));
            }

            fs::write(dir.join(file_base), &buf)?;
        }

        // Remove stale resolver files we own that are no longer in keep.
        self.remove_resolver_files(|name| !keep.iter().any(|k| k == name))
    }

    fn close(&mut self) -> io::Result<()> {
        self.remove_resolver_files(|_| true)
    }

    fn supports_split_dns(&self) -> bool {
        true
    }
}

/// Verify that the filename doesn't contain characters that might cause
/// issues when used as a filename (slashes, backslashes, colons). These
/// aren't valid in domain names anyway.
fn is_valid_resolver_file_name(name: &str) -> bool {
    !(name.contains('/') || name.contains('\\') || name.contains(':'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use tempfile::TempDir;

    fn cfg(nameservers: &[IpAddr], search: &[&str], match_domains: &[&str]) -> OsConfig {
        OsConfig {
            nameservers: nameservers.to_vec(),
            search_domains: search.iter().copied().map(String::from).collect(),
            match_domains: match_domains.iter().copied().map(String::from).collect(),
        }
    }

    #[test]
    fn supports_split_dns_is_true() {
        let dir = TempDir::new().unwrap();
        let c = DarwinConfigurator::new(dir.path().to_str().unwrap(), "/dev/null");
        assert!(c.supports_split_dns());
    }

    #[test]
    fn set_dns_writes_expected_content_per_domain() {
        let dir = TempDir::new().unwrap();
        let mut c = DarwinConfigurator::new(dir.path().to_str().unwrap(), "/dev/null");

        c.set_dns(&cfg(
            &[rustscale_tsaddr::tailscale_service_ip()],
            &[],
            &["example.com", "ts.net"],
        ))
        .unwrap();

        let expected = format!(
            "# Added by tailscaled\nnameserver {}\n",
            rustscale_tsaddr::tailscale_service_ip()
        );
        let content1 = fs::read_to_string(dir.path().join("example.com")).unwrap();
        assert_eq!(content1, expected);
        let content2 = fs::read_to_string(dir.path().join("ts.net")).unwrap();
        assert_eq!(content2, expected);
    }

    #[test]
    fn set_dns_writes_search_file() {
        let dir = TempDir::new().unwrap();
        let mut c = DarwinConfigurator::new(dir.path().to_str().unwrap(), "/dev/null");

        c.set_dns(&cfg(
            &[rustscale_tsaddr::tailscale_service_ip()],
            &["tailnet.ts.net", "corp.example"],
            &["example.com"],
        ))
        .unwrap();

        let search_content = fs::read_to_string(dir.path().join("search.tailscale")).unwrap();
        assert_eq!(
            search_content,
            "# Added by tailscaled\nsearch tailnet.ts.net corp.example\n"
        );
    }

    #[test]
    fn second_set_dns_removes_stale_files() {
        let dir = TempDir::new().unwrap();
        let mut c = DarwinConfigurator::new(dir.path().to_str().unwrap(), "/dev/null");

        c.set_dns(&cfg(
            &[rustscale_tsaddr::tailscale_service_ip()],
            &[],
            &["a.example", "b.example"],
        ))
        .unwrap();
        assert!(dir.path().join("a.example").exists());
        assert!(dir.path().join("b.example").exists());

        c.set_dns(&cfg(
            &[rustscale_tsaddr::tailscale_service_ip()],
            &[],
            &["a.example"],
        ))
        .unwrap();
        assert!(dir.path().join("a.example").exists());
        assert!(!dir.path().join("b.example").exists());
    }

    #[test]
    fn close_removes_only_files_with_our_marker() {
        let dir = TempDir::new().unwrap();

        // Pre-existing foreign file without our header marker.
        fs::write(dir.path().join("foreign"), "nameserver 8.8.8.8\n").unwrap();

        let mut c = DarwinConfigurator::new(dir.path().to_str().unwrap(), "/dev/null");
        c.set_dns(&cfg(
            &[rustscale_tsaddr::tailscale_service_ip()],
            &[],
            &["a.example", "b.example"],
        ))
        .unwrap();
        assert!(dir.path().join("a.example").exists());
        assert!(dir.path().join("b.example").exists());

        c.close().unwrap();
        assert!(!dir.path().join("a.example").exists());
        assert!(!dir.path().join("b.example").exists());
        assert!(
            dir.path().join("foreign").exists(),
            "foreign file should survive close"
        );
    }

    #[test]
    fn close_with_nonexistent_dir_is_ok() {
        let dir = TempDir::new().unwrap();
        let nonexistent = dir.path().join("does-not-exist");
        let mut c = DarwinConfigurator::new(nonexistent.to_str().unwrap(), "/dev/null");
        assert!(c.close().is_ok());
    }

    #[test]
    fn set_dns_with_empty_config_clears_our_files() {
        let dir = TempDir::new().unwrap();
        let mut c = DarwinConfigurator::new(dir.path().to_str().unwrap(), "/dev/null");

        c.set_dns(&cfg(
            &[rustscale_tsaddr::tailscale_service_ip()],
            &[],
            &["a.example"],
        ))
        .unwrap();
        assert!(dir.path().join("a.example").exists());

        // Zero config should remove all our files.
        c.set_dns(&OsConfig::default()).unwrap();
        assert!(!dir.path().join("a.example").exists());
    }

    #[test]
    fn set_dns_rejects_invalid_domain_name() {
        let dir = TempDir::new().unwrap();
        let mut c = DarwinConfigurator::new(dir.path().to_str().unwrap(), "/dev/null");

        let err = c
            .set_dns(&cfg(
                &[rustscale_tsaddr::tailscale_service_ip()],
                &[],
                &["ev/il.com"],
            ))
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
