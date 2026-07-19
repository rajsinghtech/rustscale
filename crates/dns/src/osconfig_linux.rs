//! Linux systemd-resolved DNS configurator.
//!
//! Every mutation is scoped to the RustScale TUN link. `revert` maps to
//! resolved's `RevertLink`, so we never overwrite resolver state owned by a
//! different link. Updates retain the last committed configuration and restore
//! it on a failed replacement; an unsuccessful restore deliberately retains
//! the cleanup owner for a later `close` retry.

use std::io;
use std::process::Command;

use crate::osconfig::{OsConfig, OsConfigurator};

trait ResolvectlRunner: Send {
    fn run(&mut self, args: &[String]) -> io::Result<()>;
}

struct ProcessResolvectl;

impl ResolvectlRunner for ProcessResolvectl {
    fn run(&mut self, args: &[String]) -> io::Result<()> {
        let output = Command::new("resolvectl").args(args).output()?;
        if output.status.success() {
            return Ok(());
        }
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(io::Error::other(if detail.is_empty() {
            format!(
                "resolvectl {} exited with {}",
                args.join(" "),
                output.status
            )
        } else {
            format!("resolvectl {}: {detail}", args.join(" "))
        }))
    }
}

/// A per-link systemd-resolved configurator.
///
/// `owned` becomes true before the first successful mutation. This is
/// intentional: even a failed call may have changed resolved, and dropping
/// that ownership would leave per-link state behind.
pub struct LinuxResolvedConfigurator {
    interface: String,
    runner: Box<dyn ResolvectlRunner>,
    owned: bool,
    applied: Option<OsConfig>,
}

impl LinuxResolvedConfigurator {
    pub fn new(interface: impl Into<String>) -> io::Result<Self> {
        Self::with_runner(interface, Box::new(ProcessResolvectl))
    }

    fn with_runner(
        interface: impl Into<String>,
        runner: Box<dyn ResolvectlRunner>,
    ) -> io::Result<Self> {
        let interface = interface.into();
        if interface.is_empty()
            || interface.len() > 15
            || interface
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid Linux DNS interface name",
            ));
        }
        Ok(Self {
            interface,
            runner,
            owned: false,
            applied: None,
        })
    }

    fn run(&mut self, args: impl IntoIterator<Item = String>) -> io::Result<()> {
        self.runner.run(&args.into_iter().collect::<Vec<_>>())
    }

    fn revert(&mut self) -> io::Result<()> {
        self.run(["revert".into(), self.interface.clone()])
    }

    /// Apply a non-empty configuration without changing transaction metadata.
    fn program(&mut self, cfg: &OsConfig) -> io::Result<()> {
        let mut dns = vec!["dns".into(), self.interface.clone()];
        dns.extend(cfg.nameservers.iter().map(ToString::to_string));
        self.run(dns)?;

        // Search domains take precedence over equivalent routing domains.
        // This matches resolved's domain selection and prevents duplicate
        // `foo.example`/`~foo.example` arguments on the same link.
        let mut domains = vec!["domain".into(), self.interface.clone()];
        let mut seen = std::collections::BTreeSet::new();
        for domain in &cfg.search_domains {
            let domain = domain.trim_end_matches('.');
            if !domain.is_empty() && seen.insert(domain.to_ascii_lowercase()) {
                domains.push(domain.to_string());
            }
        }
        for domain in &cfg.match_domains {
            let domain = domain.trim_end_matches('.');
            let route = if domain.is_empty() {
                "~.".to_string()
            } else {
                format!("~{domain}")
            };
            if domain.is_empty() || seen.insert(domain.to_ascii_lowercase()) {
                domains.push(route);
            }
        }
        self.run(domains)?;

        // A routing-only root domain is the explicit global-DNS plan. Merely
        // setting DefaultRoute is insufficient: resolved otherwise has no
        // domain route that selects this link.
        let global = cfg
            .match_domains
            .iter()
            .any(|domain| domain.trim_end_matches('.').is_empty());
        self.run([
            "default-route".into(),
            self.interface.clone(),
            if global { "yes" } else { "no" }.into(),
        ])
    }

    fn restore_after_failure(
        &mut self,
        original: io::Error,
        previous: Option<OsConfig>,
    ) -> io::Result<()> {
        let restore = match previous.as_ref() {
            Some(cfg) => self.program(cfg),
            None => self.revert(),
        };
        match restore {
            Ok(()) => {
                self.applied = previous;
                self.owned = self.applied.is_some();
                Err(original)
            }
            Err(restore_error) => {
                // A final RevertLink can still make an uncertain partial
                // replacement safe. If it too fails, retain the sole owner.
                match self.revert() {
                    Ok(()) => {
                        self.applied = None;
                        self.owned = false;
                        Err(io::Error::other(format!(
                            "{original}; restoring previous DNS configuration failed: {restore_error}; reverted link"
                        )))
                    }
                    Err(revert_error) => {
                        self.owned = true;
                        Err(io::Error::other(format!(
                            "{original}; restoring previous DNS configuration failed: {restore_error}; RevertLink for {} also failed: {revert_error}",
                            self.interface
                        )))
                    }
                }
            }
        }
    }
}

impl OsConfigurator for LinuxResolvedConfigurator {
    fn set_dns(&mut self, cfg: &OsConfig) -> io::Result<()> {
        if cfg.nameservers.is_empty() {
            return self.close();
        }
        let previous = self.applied.clone();
        self.owned = true;
        match self.program(cfg) {
            Ok(()) => {
                self.applied = Some(cfg.clone());
                Ok(())
            }
            Err(error) => self.restore_after_failure(error, previous),
        }
    }

    fn close(&mut self) -> io::Result<()> {
        if !self.owned {
            return Ok(());
        }
        self.revert()?;
        self.owned = false;
        self.applied = None;
        Ok(())
    }

    fn supports_split_dns(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Arc, Mutex};

    use super::*;

    struct RecordingRunner {
        calls: Arc<Mutex<Vec<Vec<String>>>>,
        fail_calls: Vec<usize>,
    }

    impl ResolvectlRunner for RecordingRunner {
        fn run(&mut self, args: &[String]) -> io::Result<()> {
            let mut calls = self.calls.lock().unwrap();
            calls.push(args.to_vec());
            if self.fail_calls.contains(&calls.len()) {
                return Err(io::Error::other("injected resolvectl failure"));
            }
            Ok(())
        }
    }

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).into()).collect()
    }

    fn config() -> OsConfig {
        OsConfig {
            nameservers: vec![IpAddr::V4(Ipv4Addr::new(100, 100, 100, 100))],
            search_domains: vec!["tailnet.ts.net".into()],
            match_domains: vec!["tailnet.ts.net".into(), "corp.example".into()],
        }
    }

    #[test]
    fn programs_only_the_tun_link_and_reverts_it() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut c = LinuxResolvedConfigurator::with_runner(
            "rustscale0",
            Box::new(RecordingRunner {
                calls: calls.clone(),
                fail_calls: vec![],
            }),
        )
        .unwrap();
        c.set_dns(&config()).unwrap();
        c.close().unwrap();
        assert_eq!(
            *calls.lock().unwrap(),
            vec![
                args(&["dns", "rustscale0", "100.100.100.100"]),
                args(&["domain", "rustscale0", "tailnet.ts.net", "~corp.example"]),
                args(&["default-route", "rustscale0", "no"]),
                args(&["revert", "rustscale0"]),
            ]
        );
    }

    #[test]
    fn global_dns_installs_explicit_root_route() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut c = LinuxResolvedConfigurator::with_runner(
            "rustscale0",
            Box::new(RecordingRunner {
                calls: calls.clone(),
                fail_calls: vec![],
            }),
        )
        .unwrap();
        let mut global = config();
        global.search_domains.clear();
        global.match_domains = vec![".".into()];
        c.set_dns(&global).unwrap();
        assert_eq!(
            *calls.lock().unwrap(),
            vec![
                args(&["dns", "rustscale0", "100.100.100.100"]),
                args(&["domain", "rustscale0", "~."]),
                args(&["default-route", "rustscale0", "yes"]),
            ]
        );
    }

    #[test]
    fn failed_update_restores_previous_plan() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut c = LinuxResolvedConfigurator::with_runner(
            "rustscale0",
            Box::new(RecordingRunner {
                calls: calls.clone(),
                fail_calls: vec![5],
            }),
        )
        .unwrap();
        c.set_dns(&config()).unwrap();
        let mut replacement = config();
        replacement.match_domains = vec!["new.example".into()];
        assert!(c.set_dns(&replacement).is_err());
        assert_eq!(
            &calls.lock().unwrap()[5..],
            [
                args(&["dns", "rustscale0", "100.100.100.100"]),
                args(&["domain", "rustscale0", "tailnet.ts.net", "~corp.example"]),
                args(&["default-route", "rustscale0", "no"]),
            ]
        );
        c.close().unwrap();
    }

    #[test]
    fn failed_restore_and_revert_retains_cleanup_ownership() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut c = LinuxResolvedConfigurator::with_runner(
            "rustscale0",
            Box::new(RecordingRunner {
                calls: calls.clone(),
                fail_calls: vec![5, 6, 7],
            }),
        )
        .unwrap();
        c.set_dns(&config()).unwrap();
        assert!(c
            .set_dns(&OsConfig {
                match_domains: vec!["new.example".into()],
                ..config()
            })
            .is_err());
        c.close().expect("close retries retained RevertLink");
        assert_eq!(
            calls.lock().unwrap().last().unwrap(),
            &args(&["revert", "rustscale0"])
        );
    }

    #[test]
    fn rejects_unsafe_interface_names() {
        assert!(LinuxResolvedConfigurator::new("bad/interface").is_err());
        assert!(LinuxResolvedConfigurator::new("").is_err());
    }
}
