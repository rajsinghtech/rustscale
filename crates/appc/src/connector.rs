//! AppConnector — DNS-domain-oriented dynamic route advertisement.
//!
//! Ports Go's `appc/appconnector.go`. An AppConnector watches DNS responses
//! for configured domains and dynamically advertises routes so traffic to
//! those domains is routed through the connector node.
//!
//! # Architecture
//!
//! The connector maintains three pieces of state:
//! - `domains`: exact-match domain names → resolved IP addresses
//! - `wildcards`: wildcard domain suffixes (e.g. `example.com` for `*.example.com`)
//! - `control_routes`: routes supplied by the control plane
//!
//! When a DNS response is observed ([`AppConnector::observe_dns_response`]),
//! the connector checks if any answered domain (or its CNAME chain) matches
//! a configured domain or wildcard. If so, and the resolved IP is not already
//! known, a route advertisement is scheduled via [`RouteAdvertiser`].
//!
//! # Concurrency
//!
//! State is protected by a [`std::sync::Mutex`]. Route advertiser calls are
//! made **outside** the mutex lock to prevent deadlocks when the advertiser
//! calls back into the connector (e.g. `domain_routes()`). This mirrors the
//! Go code's `execqueue` pattern where route advertiser tasks run in a
//! separate queued context.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rustscale_deephash::{update as deephash_update, Sum};
use rustscale_tailcfg::RouteInfo;

use crate::ratelog::RateLogger;
use crate::routes::{compare_addr, has_suffix, routes_without, Prefix};

/// Error type for AppConnector operations.
#[derive(Debug, thiserror::Error)]
pub enum AppcError {
    /// A route advertiser returned an error.
    #[error("route advertiser error: {0}")]
    Advertiser(String),
    /// A DNS message could not be parsed.
    #[error("DNS parse error: {0}")]
    DnsParse(String),
}

/// An interface that allows the AppConnector to advertise newly discovered
/// routes. Ports Go's `appc.RouteAdvertiser`.
pub trait RouteAdvertiser: Send + Sync {
    /// Advertise one or more route prefixes, skipping any already advertised.
    fn advertise_route(&self, prefixes: &[Prefix]) -> Result<(), AppcError>;

    /// Unadvertise one or more route prefixes.
    fn unadvertise_route(&self, prefixes: &[Prefix]) -> Result<(), AppcError>;
}

/// Blanket implementation for `Arc<T>` so shared route advertisers can be
/// used interchangeably with owned ones.
impl<T: RouteAdvertiser + ?Sized> RouteAdvertiser for std::sync::Arc<T> {
    fn advertise_route(&self, prefixes: &[Prefix]) -> Result<(), AppcError> {
        (**self).advertise_route(prefixes)
    }

    fn unadvertise_route(&self, prefixes: &[Prefix]) -> Result<(), AppcError> {
        (**self).unadvertise_route(prefixes)
    }
}

/// Configuration for creating an [`AppConnector`]. Ports Go's
/// `appc.Config`.
pub struct AppConnectorConfig {
    /// Logger callback (receives a pre-formatted message string).
    pub logf: Box<dyn Fn(&str) + Send + Sync>,
    /// Route advertiser for dynamic route updates.
    pub route_advertiser: Option<Box<dyn RouteAdvertiser>>,
    /// Initial persisted route state, if available.
    pub route_info: Option<RouteInfo>,
    /// Whether the connector should assume stored routes (control knob).
    pub has_stored_routes: bool,
}

/// Internal state behind the mutex.
pub(crate) struct AppConnectorState {
    /// Lower-case domain names (no trailing dot) → sorted resolved IPs.
    domains: BTreeMap<String, Vec<IpAddr>>,
    /// Routes last supplied by control.
    control_routes: Vec<Prefix>,
    /// Hash of the routes last supplied by control.
    control_routes_hash: Sum,
    /// Wildcard domain suffixes (e.g. `example.com` for `*.example.com`).
    wildcards: Vec<String>,
}

/// An App Connector that observes DNS responses for configured domains and
/// dynamically advertises routes. Ports Go's `appc.AppConnector`.
pub struct AppConnector {
    pub(crate) logf: std::sync::Arc<dyn Fn(&str) + Send + Sync>,
    pub(crate) route_advertiser: Option<Box<dyn RouteAdvertiser>>,
    pub(crate) has_stored_routes: bool,
    pub(crate) state: Mutex<AppConnectorState>,
    write_rate_minute: RateLogger,
    write_rate_day: RateLogger,
}

impl AppConnector {
    /// Create a new AppConnector from the given config.
    pub fn new(config: AppConnectorConfig) -> Self {
        let (domains, wildcards, control_routes) = match &config.route_info {
            Some(ri) => {
                let domains: BTreeMap<String, Vec<IpAddr>> = ri
                    .Domains
                    .iter()
                    .map(|(k, v)| {
                        let addrs: Vec<IpAddr> =
                            v.iter().filter_map(|s| s.parse::<IpAddr>().ok()).collect();
                        (k.clone(), addrs)
                    })
                    .collect();
                let control_routes: Vec<Prefix> =
                    ri.Control.iter().filter_map(|s| Prefix::parse(s)).collect();
                (domains, ri.Wildcards.clone(), control_routes)
            }
            None => (BTreeMap::new(), Vec::new(), Vec::new()),
        };

        // Use an Arc to share the logf between the two rate loggers and the
        // connector itself.
        let logf_arc: std::sync::Arc<dyn Fn(&str) + Send + Sync> =
            std::sync::Arc::from(config.logf);

        let logf_min = logf_arc.clone();
        let write_rate_minute = RateLogger::new(
            Instant::now,
            Duration::from_secs(60),
            move |count, _start, n| {
                logf_min(&format!(
                    "routeInfo write rate: {count} in minute ({n} routes)"
                ));
            },
        );

        let logf_day = logf_arc.clone();
        let write_rate_day = RateLogger::new(
            Instant::now,
            Duration::from_secs(86_400),
            move |count, _start, n| {
                logf_day(&format!(
                    "routeInfo write rate: {count} in 24 hours ({n} routes)"
                ));
            },
        );

        Self {
            logf: logf_arc,
            route_advertiser: config.route_advertiser,
            has_stored_routes: config.has_stored_routes,
            state: Mutex::new(AppConnectorState {
                domains,
                control_routes,
                control_routes_hash: Sum::default(),
                wildcards,
            }),
            write_rate_minute,
            write_rate_day,
        }
    }

    /// Whether the connector was created with the control knob and is storing
    /// its discovered routes persistently.
    pub fn should_store_routes(&self) -> bool {
        self.has_stored_routes
    }

    /// Remove all route state from the AppConnector.
    pub fn clear_routes(&self) -> Result<(), AppcError> {
        {
            let mut state = self.state.lock().unwrap();
            state.control_routes.clear();
            state.control_routes_hash = Sum::default();
            state.domains.clear();
            state.wildcards.clear();
        }
        self.store_routes();
        Ok(())
    }

    /// Update both domains and routes atomically. Ports Go's
    /// `UpdateDomainsAndRoutes`.
    pub fn update_domains_and_routes(&self, domains: Vec<String>, routes: Vec<Prefix>) {
        self.update_routes(&routes);
        self.update_domains(domains);
    }

    /// Replace the current set of configured domains. Domains must not
    /// contain a trailing dot and should be lower case. A leading `*.`
    /// label matches all subdomains. Ports Go's `UpdateDomains`.
    pub fn update_domains(&self, domains: Vec<String>) {
        let to_unadvertise = self.update_domains_inner(domains);

        if !to_unadvertise.is_empty() {
            if let Some(ra) = &self.route_advertiser {
                if let Err(e) = ra.unadvertise_route(&to_unadvertise) {
                    (self.logf)(&format!(
                        "failed to unadvertise routes on domain removal: {to_unadvertise:?}: {e}"
                    ));
                }
            }
        }
    }

    fn update_domains_inner(&self, domains: Vec<String>) -> Vec<Prefix> {
        let mut state = self.state.lock().unwrap();

        let mut old_domains = std::mem::take(&mut state.domains);
        state.wildcards.clear();

        for d in &domains {
            let d = d.to_lowercase();
            if d.is_empty() {
                continue;
            }
            if let Some(stripped) = d.strip_prefix("*.") {
                state.wildcards.push(stripped.to_string());
                continue;
            }
            let addrs = old_domains.remove(&d).unwrap_or_default();
            state.domains.insert(d, addrs);
        }

        // Preserve still-live wildcard-matching domains from the old set.
        let wildcards = state.wildcards.clone();
        let mut removed_domains = BTreeMap::new();
        for (d, addrs) in old_domains {
            let still_wild = wildcards.iter().any(|wc| has_suffix(&d, wc));
            if still_wild {
                state.domains.insert(d, addrs);
            } else {
                removed_domains.insert(d, addrs);
            }
        }

        let domain_keys: Vec<String> = state.domains.keys().cloned().collect();
        (self.logf)(&format!(
            "handling domains: {domain_keys:?} and wildcards: {:?}",
            state.wildcards
        ));

        // Collect routes to unadvertise for removed domains.
        if self.has_stored_routes {
            let mut to_remove = Vec::new();
            for addrs in removed_domains.values() {
                for a in addrs {
                    to_remove.push(Prefix::from_addr(*a));
                }
            }
            to_remove
        } else {
            Vec::new()
        }
    }

    /// Merge the supplied routes into the currently configured routes.
    /// Routes from control are supplemental to DNS-discovered routes, but
    /// are often whole ranges. Single-address routes covered by new ranges
    /// are removed. Ports Go's `updateRoutes`.
    pub fn update_routes(&self, routes: &[Prefix]) {
        let (to_advertise, to_remove) = {
            let mut state = self.state.lock().unwrap();

            if !deephash_update(&mut state.control_routes_hash, routes) {
                return;
            }

            let mut to_remove = Vec::new();

            if self.has_stored_routes {
                to_remove = routes_without(&state.control_routes, routes);
            }

            // Find single-IP domain routes covered by new ranges (but not
            // exactly equal to the new range).
            'next_route: for r in routes {
                for addrs in state.domains.values() {
                    for a in addrs {
                        if r.contains(*a) && Prefix::from_addr(*a) != *r {
                            to_remove.push(Prefix::from_addr(*a));
                            continue 'next_route;
                        }
                    }
                }
            }

            state.control_routes = routes.to_vec();
            (routes.to_vec(), to_remove)
        };

        // Call route advertiser outside the lock.
        if let Some(ra) = &self.route_advertiser {
            if let Err(e) = ra.advertise_route(&to_advertise) {
                (self.logf)(&format!(
                    "failed to advertise routes: {to_advertise:?}: {e}"
                ));
            }
            if !to_remove.is_empty() {
                if let Err(e) = ra.unadvertise_route(&to_remove) {
                    (self.logf)(&format!("failed to unadvertise routes: {to_remove:?}: {e}"));
                }
            }
        }

        self.store_routes();
    }

    /// The currently configured domain list.
    pub fn domains(&self) -> Vec<String> {
        let state = self.state.lock().unwrap();
        state.domains.keys().cloned().collect()
    }

    /// A map of domains to resolved IP addresses (cloned snapshot).
    pub fn domain_routes(&self) -> BTreeMap<String, Vec<IpAddr>> {
        let state = self.state.lock().unwrap();
        state.domains.clone()
    }

    /// Wait for currently scheduled operations to complete. In this
    /// synchronous implementation, all operations complete before returning,
    /// so this is a no-op. Ports Go's `Wait`.
    pub fn wait(&self) {
        // No-op: all operations are synchronous.
    }

    /// Close the connector and clean up resources. Safe to call on a
    /// finished connector. Ports Go's `Close`.
    pub fn close(&self) {
        // No-op: no background tasks to clean up.
    }

    // -----------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------

    /// Find the routed domain for `domain`, following the CNAME chain.
    /// Returns `(routed_domain, is_routed)`. Must be called with the mutex
    /// held. Ports Go's `findRoutedDomainLocked`.
    pub(crate) fn find_routed_domain_locked(
        state: &AppConnectorState,
        mut domain: String,
        cname_chain: &BTreeMap<String, String>,
    ) -> (String, bool) {
        loop {
            if state.domains.contains_key(&domain) {
                return (domain, true);
            }

            // Match wildcard domains.
            for wc in &state.wildcards {
                if has_suffix(&domain, wc) {
                    return (domain, true);
                }
            }

            match cname_chain.get(&domain) {
                Some(next) => domain = next.clone(),
                None => break,
            }
        }
        (domain, false)
    }

    /// Whether `addr` is known for `domain` (either directly or via a
    /// control route). If known via a control route, the domain table is
    /// updated for faster future matching. Must be called with the mutex
    /// held. Ports Go's `isAddrKnownLocked`.
    pub(crate) fn is_addr_known_locked(
        state: &mut AppConnectorState,
        domain: &str,
        addr: IpAddr,
    ) -> bool {
        if has_domain_addr_locked(state, domain, &addr) {
            return true;
        }
        for route in &state.control_routes {
            if route.contains(addr) {
                add_domain_addr_locked(state, domain, addr);
                return true;
            }
        }
        false
    }

    /// Schedule advertisement of the given addresses for the given domain.
    /// Calls the route advertiser, then updates the domain table. Ports
    /// Go's `scheduleAdvertisement`.
    pub(crate) fn schedule_advertisement(&self, domain: &str, routes: &[Prefix]) {
        // Call route advertiser first (outside the lock).
        if let Some(ra) = &self.route_advertiser {
            if let Err(e) = ra.advertise_route(routes) {
                (self.logf)(&format!(
                    "failed to advertise routes for {domain}: {routes:?}: {e}"
                ));
                return;
            }
        }

        // Update state under the lock.
        {
            let mut state = self.state.lock().unwrap();
            for route in routes {
                if !route.is_single_ip() {
                    continue;
                }
                let addr = route.addr();
                if !has_domain_addr_locked(&state, domain, &addr) {
                    add_domain_addr_locked(&mut state, domain, addr);
                    (self.logf)(&format!("advertised route for {domain}: {addr}"));
                }
            }
        }
        self.store_routes();
    }

    /// Persist the current state. In this implementation, invokes the rate
    /// loggers. A real implementation would also publish RouteInfo via the
    /// event bus. Ports Go's `storeRoutesLocked`.
    fn store_routes(&self) {
        let num_routes = {
            let state = self.state.lock().unwrap();
            let mut n = state.control_routes.len() as i64;
            for addrs in state.domains.values() {
                n += addrs.len() as i64;
            }
            n
        };
        self.write_rate_minute.update(num_routes);
        self.write_rate_day.update(num_routes);
    }
}

/// Whether `addr` has been observed in a resolution of `domain`. Must be
/// called with the mutex held. Ports Go's `hasDomainAddrLocked`.
fn has_domain_addr_locked(state: &AppConnectorState, domain: &str, addr: &IpAddr) -> bool {
    match state.domains.get(domain) {
        Some(addrs) => addrs.binary_search_by(|a| compare_addr(a, addr)).is_ok(),
        None => false,
    }
}

/// Add `addr` to the list of addresses resolved for `domain`, keeping the
/// list sorted. Does not deduplicate. Must be called with the mutex held.
/// Ports Go's `addDomainAddrLocked`.
fn add_domain_addr_locked(state: &mut AppConnectorState, domain: &str, addr: IpAddr) {
    let addrs = state.domains.entry(domain.to_string()).or_default();
    addrs.push(addr);
    addrs.sort_by(compare_addr);
}

/// A test helper that collects advertised and unadvertised routes. Ports
/// Go's `appctest.RouteCollector`.
#[cfg(test)]
pub(crate) struct RouteCollector {
    pub routes: Mutex<Vec<Prefix>>,
    pub removed_routes: Mutex<Vec<Prefix>>,
    pub advertise_callback: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
    pub unadvertise_callback: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
}

#[cfg(test)]
impl RouteCollector {
    pub(crate) fn new() -> Self {
        Self {
            routes: Mutex::new(Vec::new()),
            removed_routes: Mutex::new(Vec::new()),
            advertise_callback: Mutex::new(None),
            unadvertise_callback: Mutex::new(None),
        }
    }

    pub(crate) fn routes(&self) -> Vec<Prefix> {
        self.routes.lock().unwrap().clone()
    }

    pub(crate) fn removed_routes(&self) -> Vec<Prefix> {
        self.removed_routes.lock().unwrap().clone()
    }

    #[allow(dead_code)]
    pub(crate) fn set_routes(&self, routes: Vec<Prefix>) {
        *self.routes.lock().unwrap() = routes;
    }
}

#[cfg(test)]
impl RouteAdvertiser for RouteCollector {
    fn advertise_route(&self, prefixes: &[Prefix]) -> Result<(), AppcError> {
        self.routes.lock().unwrap().extend_from_slice(prefixes);
        if let Some(cb) = self.advertise_callback.lock().unwrap().as_ref() {
            cb();
        }
        Ok(())
    }

    fn unadvertise_route(&self, to_remove: &[Prefix]) -> Result<(), AppcError> {
        let mut routes = self.routes.lock().unwrap();
        let to_remove_set: std::collections::HashSet<Prefix> = to_remove.iter().cloned().collect();
        let mut kept = Vec::new();
        for r in routes.drain(..) {
            if to_remove_set.contains(&r) {
                self.removed_routes.lock().unwrap().push(r);
            } else {
                kept.push(r);
            }
        }
        *routes = kept;
        if let Some(cb) = self.unadvertise_callback.lock().unwrap().as_ref() {
            cb();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn noop_logf() -> Box<dyn Fn(&str) + Send + Sync> {
        Box::new(|_| {})
    }

    fn make_connector(has_stored: bool) -> AppConnector {
        AppConnector::new(AppConnectorConfig {
            logf: noop_logf(),
            route_advertiser: None,
            route_info: None,
            has_stored_routes: has_stored,
        })
    }

    fn make_connector_with_ra(has_stored: bool) -> (AppConnector, std::sync::Arc<RouteCollector>) {
        let rc = std::sync::Arc::new(RouteCollector::new());
        let ac = AppConnector::new(AppConnectorConfig {
            logf: noop_logf(),
            route_advertiser: Some(Box::new(rc.clone())),
            route_info: None,
            has_stored_routes: has_stored,
        });
        (ac, rc)
    }

    #[test]
    fn update_domains_basic() {
        for should_store in [false, true] {
            let a = make_connector(should_store);
            a.update_domains(vec!["example.com".into()]);
            a.wait();
            assert_eq!(a.domains(), vec!["example.com"]);
        }
    }

    #[test]
    fn update_domains_preserves_addresses() {
        for should_store in [false, true] {
            let a = make_connector(should_store);
            a.update_domains(vec!["example.com".into()]);
            a.wait();

            {
                let mut state = a.state.lock().unwrap();
                add_domain_addr_locked(&mut state, "example.com", "192.0.0.8".parse().unwrap());
            }

            a.update_domains(vec!["example.com".into()]);
            a.wait();

            let state = a.state.lock().unwrap();
            assert_eq!(
                state.domains.get("example.com"),
                Some(&vec!["192.0.0.8".parse::<IpAddr>().unwrap()])
            );
        }
    }

    #[test]
    fn update_domains_downcases() {
        for should_store in [false, true] {
            let a = make_connector(should_store);
            a.update_domains(vec!["UP.EXAMPLE.COM".into()]);
            a.wait();
            assert_eq!(a.domains(), vec!["up.example.com"]);
        }
    }

    #[test]
    fn update_domains_wildcard() {
        for should_store in [false, true] {
            let a = make_connector(should_store);
            a.update_domains(vec!["*.example.com".into()]);
            a.wait();

            let state = a.state.lock().unwrap();
            assert_eq!(state.wildcards, vec!["example.com"]);
            assert!(state.domains.is_empty());
        }
    }

    #[test]
    fn update_domains_wildcard_preserves_subdomain() {
        for should_store in [false, true] {
            let a = make_connector(should_store);
            a.update_domains(vec!["*.example.com".into()]);
            a.wait();

            {
                let mut state = a.state.lock().unwrap();
                add_domain_addr_locked(&mut state, "foo.example.com", "192.0.0.8".parse().unwrap());
            }

            a.update_domains(vec!["*.example.com".into(), "example.com".into()]);
            a.wait();

            let state = a.state.lock().unwrap();
            assert!(state.domains.contains_key("foo.example.com"));
            assert!(state.domains.contains_key("example.com"));
        }
    }

    #[test]
    fn update_domains_wildcard_no_duplicate() {
        for should_store in [false, true] {
            let a = make_connector(should_store);
            a.update_domains(vec!["*.example.com".into(), "example.com".into()]);
            a.wait();
            a.update_domains(vec!["*.example.com".into(), "example.com".into()]);
            a.wait();

            let state = a.state.lock().unwrap();
            assert_eq!(state.wildcards.len(), 1, "expected only one wildcard");
        }
    }

    #[test]
    fn update_domains_and_routes_advertises() {
        for should_store in [false, true] {
            let (a, rc) = make_connector_with_ra(should_store);
            a.update_domains_and_routes(vec![], prefixes(&["1.2.3.1/32", "1.2.3.2/32"]));
            a.wait();

            assert_eq!(rc.routes().len(), 2);
        }
    }

    #[test]
    fn update_routes_removes_old_when_stored() {
        let (a, rc) = make_connector_with_ra(true);
        a.update_domains_and_routes(vec![], prefixes(&["1.2.3.1/32", "1.2.3.2/32"]));
        a.wait();
        a.update_domains_and_routes(vec![], prefixes(&["1.2.3.1/32", "1.2.3.3/32"]));
        a.wait();

        let removed = rc.removed_routes();
        assert_eq!(removed, vec![Prefix::parse("1.2.3.2/32").unwrap()]);
    }

    #[test]
    fn update_routes_does_not_remove_when_not_stored() {
        let (a, rc) = make_connector_with_ra(false);
        a.update_domains_and_routes(vec![], prefixes(&["1.2.3.1/32", "1.2.3.2/32"]));
        a.wait();
        a.update_domains_and_routes(vec![], prefixes(&["1.2.3.1/32", "1.2.3.3/32"]));
        a.wait();

        assert!(rc.removed_routes().is_empty());
    }

    #[test]
    fn update_routes_collapses_covered_singles() {
        let (a, rc) = make_connector_with_ra(false);

        a.update_domains(vec!["*.example.com".into()]);
        a.wait();

        let resp = crate::observe::test_helpers::dns_response("a.example.com.", "192.0.2.1");
        a.observe_dns_response(&resp).unwrap();
        a.wait();

        assert_eq!(rc.routes(), vec![Prefix::parse("192.0.2.1/32").unwrap()]);

        a.update_routes(&prefixes(&["192.0.2.0/24", "192.0.0.1/32"]));
        a.wait();

        let removed = rc.removed_routes();
        assert_eq!(removed, vec![Prefix::parse("192.0.2.1/32").unwrap()]);
    }

    #[test]
    fn domain_routes_returns_snapshot() {
        let (a, _rc) = make_connector_with_ra(false);
        a.update_domains(vec!["example.com".into()]);
        a.wait();

        let resp = crate::observe::test_helpers::dns_response("example.com.", "192.0.0.8");
        a.observe_dns_response(&resp).unwrap();
        a.wait();

        let dr = a.domain_routes();
        assert_eq!(
            dr.get("example.com"),
            Some(&vec!["192.0.0.8".parse::<IpAddr>().unwrap()])
        );
    }

    #[test]
    fn clear_routes_resets_state() {
        let (a, _rc) = make_connector_with_ra(false);
        a.update_domains(vec!["example.com".into()]);
        a.update_routes(&prefixes(&["10.0.0.0/8"]));
        a.wait();

        a.clear_routes().unwrap();

        let state = a.state.lock().unwrap();
        assert!(state.domains.is_empty());
        assert!(state.control_routes.is_empty());
        assert!(state.wildcards.is_empty());
    }

    #[test]
    fn update_domain_route_removal() {
        for should_store in [false, true] {
            let (a, rc) = make_connector_with_ra(should_store);
            a.update_domains_and_routes(
                vec!["a.example.com".into(), "b.example.com".into()],
                vec![],
            );
            a.wait();

            for res in [
                crate::observe::test_helpers::dns_response("a.example.com.", "1.2.3.1"),
                crate::observe::test_helpers::dns_response("a.example.com.", "1.2.3.2"),
                crate::observe::test_helpers::dns_response("b.example.com.", "1.2.3.3"),
                crate::observe::test_helpers::dns_response("b.example.com.", "1.2.3.4"),
            ] {
                a.observe_dns_response(&res).unwrap();
            }
            a.wait();

            assert_eq!(
                rc.routes(),
                prefixes(&["1.2.3.1/32", "1.2.3.2/32", "1.2.3.3/32", "1.2.3.4/32"])
            );

            a.update_domains_and_routes(vec!["a.example.com".into()], vec![]);
            a.wait();

            if should_store {
                assert_eq!(rc.routes(), prefixes(&["1.2.3.1/32", "1.2.3.2/32"]));
                assert_eq!(rc.removed_routes(), prefixes(&["1.2.3.3/32", "1.2.3.4/32"]));
            } else {
                assert_eq!(
                    rc.routes(),
                    prefixes(&["1.2.3.1/32", "1.2.3.2/32", "1.2.3.3/32", "1.2.3.4/32"])
                );
            }
        }
    }

    #[test]
    fn update_wildcard_route_removal() {
        for should_store in [false, true] {
            let (a, rc) = make_connector_with_ra(should_store);
            a.update_domains_and_routes(
                vec!["a.example.com".into(), "*.b.example.com".into()],
                vec![],
            );
            a.wait();

            for res in [
                crate::observe::test_helpers::dns_response("a.example.com.", "1.2.3.1"),
                crate::observe::test_helpers::dns_response("a.example.com.", "1.2.3.2"),
                crate::observe::test_helpers::dns_response("1.b.example.com.", "1.2.3.3"),
                crate::observe::test_helpers::dns_response("2.b.example.com.", "1.2.3.4"),
            ] {
                a.observe_dns_response(&res).unwrap();
            }
            a.wait();

            assert_eq!(
                rc.routes(),
                prefixes(&["1.2.3.1/32", "1.2.3.2/32", "1.2.3.3/32", "1.2.3.4/32"])
            );

            a.update_domains_and_routes(vec!["a.example.com".into()], vec![]);
            a.wait();

            if should_store {
                assert_eq!(rc.routes(), prefixes(&["1.2.3.1/32", "1.2.3.2/32"]));
                assert_eq!(rc.removed_routes(), prefixes(&["1.2.3.3/32", "1.2.3.4/32"]));
            } else {
                assert_eq!(
                    rc.routes(),
                    prefixes(&["1.2.3.1/32", "1.2.3.2/32", "1.2.3.3/32", "1.2.3.4/32"])
                );
            }
        }
    }

    #[test]
    fn update_routes_deadlock_regression() {
        // Regression test: the route advertiser calling domain_routes() must
        // not deadlock. In this synchronous implementation, the route
        // advertiser is called outside the mutex lock, so this is safe.
        let rc = std::sync::Arc::new(RouteCollector::new());

        let a = AppConnector::new(AppConnectorConfig {
            logf: noop_logf(),
            route_advertiser: Some(Box::new(rc.clone())),
            route_info: None,
            has_stored_routes: true,
        });

        a.update_domains(vec!["example.com".into()]);
        a.wait();

        a.update_routes(&prefixes(&["127.0.0.1/32", "127.0.0.2/32"]));
        a.wait();

        a.update_routes(&prefixes(&["127.0.0.1/32"]));
        a.wait();

        assert!(!rc.routes().is_empty());
    }

    #[test]
    fn update_routes_no_change_is_noop() {
        let (a, rc) = make_connector_with_ra(false);
        let routes = prefixes(&["10.0.0.0/8"]);
        a.update_routes(&routes);
        a.wait();
        assert_eq!(rc.routes().len(), 1);

        // Same routes again — should not re-advertise.
        a.update_routes(&routes);
        a.wait();
        assert_eq!(rc.routes().len(), 1);
    }

    #[test]
    fn update_routes_deephash_detects_changes() {
        let (a, rc) = make_connector_with_ra(false);
        let routes = prefixes(&["10.0.0.0/8"]);

        a.update_routes(&routes);
        let first_hash = a.state.lock().unwrap().control_routes_hash;
        assert_ne!(first_hash, Sum::default());

        a.update_routes(&routes);
        assert_eq!(a.state.lock().unwrap().control_routes_hash, first_hash);
        assert_eq!(rc.routes().len(), 1, "unchanged routes are not advertised");

        a.update_routes(&prefixes(&["10.0.0.0/16"]));
        let changed_hash = a.state.lock().unwrap().control_routes_hash;
        assert_ne!(changed_hash, first_hash);
        assert_eq!(rc.routes().len(), 2, "changed routes are advertised");
    }

    fn prefixes(ss: &[&str]) -> Vec<Prefix> {
        ss.iter().map(|s| Prefix::parse(s).unwrap()).collect()
    }
}
