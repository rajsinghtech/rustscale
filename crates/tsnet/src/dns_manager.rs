use std::sync::Arc;

use rustscale_dns::{build_os_dns_config, config_from_dns, MagicDnsResolver, OsConfigurator};
use rustscale_tailcfg::{DNSConfig, Node};
use tokio::sync::{Mutex, RwLock};

/// Serialized owner for one TUN generation's resolver, forwarder plan, and OS
/// DNS state. Control updates and preference changes commit through this gate,
/// so callers never publish a resolver plan that the host resolver failed to
/// install.
pub(crate) struct DnsManager {
    resolver: Arc<RwLock<MagicDnsResolver>>,
    dns_config: Arc<RwLock<Option<DNSConfig>>>,
    peers: Arc<RwLock<Vec<Node>>>,
    domain: String,
    health: rustscale_health::Tracker,
    responder_ready: bool,
    state: Mutex<State>,
}

struct State {
    accept_dns: bool,
    desired: Option<DNSConfig>,
    configurator: Option<Box<dyn OsConfigurator + Send>>,
}

impl DnsManager {
    pub(crate) fn new(
        resolver: Arc<RwLock<MagicDnsResolver>>,
        dns_config: Arc<RwLock<Option<DNSConfig>>>,
        peers: Arc<RwLock<Vec<Node>>>,
        domain: String,
        health: rustscale_health::Tracker,
        responder_ready: bool,
        accept_dns: bool,
        desired: Option<DNSConfig>,
    ) -> Arc<Self> {
        Arc::new(Self {
            resolver,
            dns_config,
            peers,
            domain,
            health,
            responder_ready,
            state: Mutex::new(State {
                accept_dns,
                desired,
                configurator: None,
            }),
        })
    }

    fn os_config(&self, config: Option<&DNSConfig>) -> rustscale_dns::OsConfig {
        config
            .map(|config| build_os_dns_config(config, &self.domain))
            .unwrap_or_default()
    }

    fn failed(&self, error: impl Into<String>) -> String {
        let error = error.into();
        self.health.set_unhealthy("subsystem-dns", error.clone());
        error
    }

    fn succeeded(&self) {
        self.health.set_healthy("subsystem-dns");
    }

    /// Attach the sole OS owner and reconcile the latest desired generation.
    pub(crate) async fn attach(
        &self,
        mut configurator: Box<dyn OsConfigurator + Send>,
    ) -> Result<(), String> {
        let mut state = self.state.lock().await;
        let result = if state.accept_dns && !self.responder_ready {
            configurator
                .close()
                .and_then(|()| Err(std::io::Error::other("MagicDNS responder is not ready")))
        } else if state.accept_dns {
            configurator.set_dns(&self.os_config(state.desired.as_ref()))
        } else {
            configurator.close()
        };
        state.configurator = Some(configurator);
        match result {
            Ok(()) => {
                self.succeeded();
                Ok(())
            }
            Err(error) => Err(self.failed(error.to_string())),
        }
    }

    /// Atomically replace the live control DNS generation. Failed OS updates
    /// leave both the published resolver and shared DNSConfig unchanged.
    pub(crate) async fn update_control(&self, config: DNSConfig) -> Result<(), String> {
        let mut state = self.state.lock().await;
        if state.accept_dns {
            if !self.responder_ready {
                return Err(self.failed("MagicDNS responder is not ready"));
            }
            if let Some(configurator) = state.configurator.as_mut() {
                if let Err(error) = configurator.set_dns(&self.os_config(Some(&config))) {
                    return Err(self.failed(error.to_string()));
                }
            }
        }
        let peers = self.peers.read().await.clone();
        self.resolver
            .write()
            .await
            .set_config(config_from_dns(&config, &self.domain, &peers));
        *self.dns_config.write().await = Some(config.clone());
        state.desired = Some(config);
        self.succeeded();
        Ok(())
    }

    /// Confirm host DNS clear/re-enable before making the preference effective.
    pub(crate) async fn set_accept_dns(&self, enabled: bool) -> Result<(), String> {
        let mut state = self.state.lock().await;
        if state.accept_dns == enabled {
            return Ok(());
        }
        if enabled && !self.responder_ready {
            return Err(self.failed("MagicDNS responder is not ready"));
        }
        let desired_os = self.os_config(state.desired.as_ref());
        if let Some(configurator) = state.configurator.as_mut() {
            if enabled {
                configurator.set_dns(&desired_os)
            } else {
                configurator.close()
            }
            .map_err(|error| self.failed(error.to_string()))?;
        }
        state.accept_dns = enabled;
        self.succeeded();
        Ok(())
    }

    /// Confirm RevertLink while retaining the owner on failure.
    pub(crate) async fn close(&self) -> Result<(), String> {
        let mut state = self.state.lock().await;
        let Some(configurator) = state.configurator.as_mut() else {
            return Ok(());
        };
        configurator.close().map_err(|error| error.to_string())?;
        state.configurator.take();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::{Arc, Mutex as StdMutex};

    use rustscale_dns::{OsConfig, OsConfigurator};
    use rustscale_tailcfg::{DNSConfig, DNSRecord};

    use super::*;

    struct RecordingDns {
        calls: Arc<StdMutex<Vec<Option<OsConfig>>>>,
        fail_next: Arc<std::sync::atomic::AtomicBool>,
    }

    impl OsConfigurator for RecordingDns {
        fn set_dns(&mut self, config: &OsConfig) -> io::Result<()> {
            if self
                .fail_next
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(io::Error::other("injected DNS replacement failure"));
            }
            self.calls.lock().unwrap().push(Some(config.clone()));
            Ok(())
        }

        fn close(&mut self) -> io::Result<()> {
            if self
                .fail_next
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(io::Error::other("injected DNS cleanup failure"));
            }
            self.calls.lock().unwrap().push(None);
            Ok(())
        }

        fn supports_split_dns(&self) -> bool {
            true
        }
    }

    fn manager(
        config: DNSConfig,
    ) -> (
        Arc<DnsManager>,
        Arc<StdMutex<Vec<Option<OsConfig>>>>,
        Arc<std::sync::atomic::AtomicBool>,
    ) {
        let resolver = Arc::new(RwLock::new(MagicDnsResolver::default()));
        let shared = Arc::new(RwLock::new(Some(config.clone())));
        let manager = DnsManager::new(
            resolver,
            shared,
            Arc::new(RwLock::new(Vec::new())),
            "tailnet.ts.net".into(),
            rustscale_health::Tracker::new(),
            true,
            true,
            Some(config),
        );
        let calls = Arc::new(StdMutex::new(Vec::new()));
        let fail_next = Arc::new(std::sync::atomic::AtomicBool::new(false));
        (manager, calls, fail_next)
    }

    #[tokio::test]
    async fn preference_clear_and_reenable_are_confirmed_transactions() {
        let config = DNSConfig {
            Proxied: true,
            ..Default::default()
        };
        let (manager, calls, fail_next) = manager(config);
        manager
            .attach(Box::new(RecordingDns {
                calls: calls.clone(),
                fail_next,
            }))
            .await
            .unwrap();
        manager.set_accept_dns(false).await.unwrap();
        manager.set_accept_dns(true).await.unwrap();
        let calls = calls.lock().unwrap();
        assert!(calls[0].is_some());
        assert!(calls[1].is_none());
        assert!(calls[2].is_some());
    }

    #[tokio::test]
    async fn failed_map_replacement_does_not_publish_resolver_generation() {
        let original = DNSConfig {
            Proxied: true,
            ..Default::default()
        };
        let (manager, calls, fail_next) = manager(original.clone());
        manager
            .attach(Box::new(RecordingDns {
                calls,
                fail_next: fail_next.clone(),
            }))
            .await
            .unwrap();
        fail_next.store(true, std::sync::atomic::Ordering::SeqCst);
        let replacement = DNSConfig {
            ExtraRecords: vec![DNSRecord {
                Name: "new.tailnet.ts.net".into(),
                Type: "A".into(),
                Value: "100.64.0.9".into(),
            }],
            Proxied: true,
            ..Default::default()
        };
        assert!(manager.update_control(replacement).await.is_err());
        assert_eq!(*manager.dns_config.read().await, Some(original));
    }

    #[tokio::test]
    async fn failed_clear_retains_owner_for_retry() {
        let (manager, calls, fail_next) = manager(DNSConfig::default());
        manager
            .attach(Box::new(RecordingDns {
                calls: calls.clone(),
                fail_next: fail_next.clone(),
            }))
            .await
            .unwrap();
        fail_next.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(manager.set_accept_dns(false).await.is_err());
        manager.set_accept_dns(false).await.unwrap();
        assert_eq!(
            calls
                .lock()
                .unwrap()
                .iter()
                .filter(|call| call.is_none())
                .count(),
            1
        );
    }
}
