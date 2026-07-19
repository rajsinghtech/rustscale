//! Linux systemd-resolved DNS configurator.
//!
//! This uses the `resolvectl` client for systemd-resolved's per-link D-Bus
//! interface.  It never edits `/etc/resolv.conf`: every mutation is scoped to
//! the RustScale TUN link and `revert` maps to resolved's `RevertLink`, so
//! foreign resolver state is left untouched.

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
/// `owned` becomes true as soon as this instance has changed the link.  A
/// failed rollback deliberately keeps it true, which makes a later `close`
/// retry `RevertLink` instead of forgetting partially-installed state.
pub struct LinuxResolvedConfigurator {
    interface: String,
    runner: Box<dyn ResolvectlRunner>,
    owned: bool,
}

impl LinuxResolvedConfigurator {
    /// Build a configurator for a real TUN interface.
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
        })
    }

    fn run(&mut self, args: impl IntoIterator<Item = String>) -> io::Result<()> {
        self.runner.run(&args.into_iter().collect::<Vec<_>>())
    }

    fn revert(&mut self) -> io::Result<()> {
        self.run(["revert".into(), self.interface.clone()])
    }

    fn rollback_after_failure(&mut self, original: io::Error) -> io::Result<()> {
        match self.revert() {
            Ok(()) => {
                self.owned = false;
                Err(original)
            }
            Err(rollback) => {
                self.owned = true;
                Err(io::Error::other(format!(
                    "{original}; RevertLink for {} also failed: {rollback}",
                    self.interface
                )))
            }
        }
    }
}

impl OsConfigurator for LinuxResolvedConfigurator {
    fn set_dns(&mut self, cfg: &OsConfig) -> io::Result<()> {
        if cfg.nameservers.is_empty() {
            return self.close();
        }

        let mut dns = vec!["dns".into(), self.interface.clone()];
        dns.extend(cfg.nameservers.iter().map(ToString::to_string));
        if let Err(error) = self.run(dns) {
            return self.rollback_after_failure(error);
        }
        self.owned = true;

        // A leading `~` is systemd-resolved's routing-only (split DNS)
        // notation. Search domains remain ordinary domains on the same link.
        let mut domains = vec!["domain".into(), self.interface.clone()];
        domains.extend(cfg.match_domains.iter().map(|domain| format!("~{domain}")));
        domains.extend(cfg.search_domains.iter().cloned());
        if let Err(error) = self.run(domains) {
            return self.rollback_after_failure(error);
        }

        // Match resolved's route selection semantics: split-DNS links are not
        // the default route, while a configuration with no match domains must
        // receive otherwise-unmatched DNS traffic.
        let default_route = if cfg.match_domains.is_empty() {
            "yes"
        } else {
            "no"
        };
        if let Err(error) = self.run([
            "default-route".into(),
            self.interface.clone(),
            default_route.into(),
        ]) {
            return self.rollback_after_failure(error);
        }
        Ok(())
    }

    fn close(&mut self) -> io::Result<()> {
        if !self.owned {
            return Ok(());
        }
        self.revert()?;
        self.owned = false;
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
                args(&[
                    "domain",
                    "rustscale0",
                    "~tailnet.ts.net",
                    "~corp.example",
                    "tailnet.ts.net",
                ]),
                args(&["default-route", "rustscale0", "no"]),
                args(&["revert", "rustscale0"]),
            ]
        );
    }

    #[test]
    fn global_dns_without_match_domains_uses_link_as_default_route() {
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
        global.match_domains.clear();

        c.set_dns(&global).unwrap();

        assert_eq!(
            calls.lock().unwrap().last().unwrap(),
            &args(&["default-route", "rustscale0", "yes"])
        );
    }

    #[test]
    fn failure_reverts_partial_link_configuration() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut c = LinuxResolvedConfigurator::with_runner(
            "rustscale0",
            Box::new(RecordingRunner {
                calls: calls.clone(),
                fail_calls: vec![2],
            }),
        )
        .unwrap();

        assert!(c.set_dns(&config()).is_err());
        assert_eq!(
            calls.lock().unwrap().last().unwrap(),
            &args(&["revert", "rustscale0"])
        );
        assert!(c.close().is_ok(), "successful rollback releases ownership");
    }

    #[test]
    fn failed_rollback_keeps_cleanup_ownership_for_retry() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut c = LinuxResolvedConfigurator::with_runner(
            "rustscale0",
            Box::new(RecordingRunner {
                calls: calls.clone(),
                // Domain setup fails, then the compensating RevertLink fails.
                fail_calls: vec![2, 3],
            }),
        )
        .unwrap();

        assert!(c.set_dns(&config()).is_err());
        c.close().expect("close retries the failed RevertLink");
        assert_eq!(calls.lock().unwrap().len(), 4);
    }

    #[test]
    fn rejects_unsafe_interface_names() {
        assert!(LinuxResolvedConfigurator::new("bad/interface").is_err());
        assert!(LinuxResolvedConfigurator::new("").is_err());
    }
}
