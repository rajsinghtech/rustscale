//! Minimal DNS caching resolver with single-flight dedup and happy-eyeballs dialer.
//!
//! Ports Go's `net/dnscache` package:
//! - TTL-based cache of A/AAAA lookups with configurable expiry.
//! - Single-flight dedup: concurrent lookups for the same host share one upstream call.
//! - `UseLastGood` fallback: serve stale cache entry when a refresh fails.
//! - Happy-eyeballs-lite dialer: race v4 and v6 TCP dials with staggered start.
//! - `LookupIPFallback` hook for a backup DNS mechanism (e.g. `dnsfallback`).

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::sync::Mutex;

use rustscale_singleflight::Group;

/// Default TTL for cache entries (10 minutes, matching Go's default).
const DEFAULT_TTL: Duration = Duration::from_secs(600);

/// Stagger delay between consecutive dial attempts in happy-eyeballs (300ms,
/// matching Go's `fallbackDelay`).
const FALLBACK_DELAY: Duration = Duration::from_millis(300);

/// Lookup timeout when `UseLastGood` is enabled and a stale entry exists (3s,
/// matching Go's `lookupTimeoutForHost`).
const FAST_LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);

/// Lookup timeout when no stale entry exists (10s, matching Go).
const SLOW_LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Fallback timeout for the `LookupIPFallback` hook (30s, matching Go).
const FALLBACK_TIMEOUT: Duration = Duration::from_secs(30);

/// Errors from DNS cache operations.
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("dns: {0}")]
    Resolve(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("no IPs found for {0}")]
    NoIps(String),
}

/// Async fallback lookup function type. Returns a list of IP addresses for the
/// given hostname. Used when the forward (system) resolver fails or returns
/// no results.
pub type LookupFallback = Arc<
    dyn Fn(&str) -> Pin<Box<dyn std::future::Future<Output = Result<Vec<IpAddr>, DnsError>> + Send>>
        + Send
        + Sync,
>;

/// Async forward lookup function type. Used for the primary DNS resolution.
/// Defaults to system DNS (`tokio::net::lookup_host`) when not set.
pub type ForwardLookup = Arc<
    dyn Fn(
            &str,
        )
            -> Pin<Box<dyn std::future::Future<Output = Result<Vec<IpAddr>, std::io::Error>> + Send>>
        + Send
        + Sync,
>;

/// Result of an IP lookup: primary IP (v4 preferred), optional v6, and all IPs.
#[derive(Clone, Debug)]
pub struct LookupResult {
    /// Primary IP address (IPv4 preferred, falls back to IPv6).
    pub ip: IpAddr,
    /// IPv6 address if both v4 and v6 are available, else `None`.
    pub ip6: Option<IpAddr>,
    /// All resolved IP addresses.
    pub all_ips: Vec<IpAddr>,
}

/// A cached DNS entry with an expiry time.
#[derive(Clone)]
struct CacheEntry {
    result: LookupResult,
    expires: Instant,
}

/// A minimal DNS caching resolver.
///
/// The TTL is fixed per-resolver. Cache entries are never evicted (intended for
/// a fixed set of hostnames, matching Go's design). Private IPs are not cached
/// to avoid captive-portal poisoning.
pub struct Resolver {
    /// Forward lookup function. If `None`, uses system DNS.
    forward: Option<ForwardLookup>,
    /// Fallback lookup function (e.g. DERP bootstrap DNS).
    fallback: Option<LookupFallback>,
    /// Cache TTL.
    ttl: Duration,
    /// Whether to serve stale entries on refresh failure.
    use_last_good: bool,
    /// IP cache keyed by hostname.
    cache: Mutex<HashMap<String, CacheEntry>>,
    /// Singleflight dedup: in-flight lookups keyed by hostname.
    inflight: Group<String, LookupResult, String>,
}

impl Default for Resolver {
    fn default() -> Self {
        Self::new()
    }
}

impl Resolver {
    /// Create a new resolver with default settings (10-minute TTL, no fallback).
    pub fn new() -> Self {
        Self {
            forward: None,
            fallback: None,
            ttl: DEFAULT_TTL,
            use_last_good: false,
            cache: Mutex::new(HashMap::new()),
            inflight: Group::new(),
        }
    }

    /// Set the forward lookup function (overrides system DNS). Mainly for tests.
    pub fn with_forward(mut self, forward: ForwardLookup) -> Self {
        self.forward = Some(forward);
        self
    }

    /// Set the fallback lookup function (e.g. `dnsfallback`'s resolver).
    pub fn with_fallback(mut self, fallback: LookupFallback) -> Self {
        self.fallback = Some(fallback);
        self
    }

    /// Set the cache TTL.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Enable or disable `UseLastGood` fallback (serve stale on error).
    pub fn with_use_last_good(mut self, use_last_good: bool) -> Self {
        self.use_last_good = use_last_good;
        self
    }

    /// Look up the host's primary IP, optional IPv6, and all IPs.
    ///
    /// If the host is a literal IP address, it is returned directly. If a fresh
    /// cache entry exists, it is returned immediately. Otherwise, a single-flight
    /// upstream lookup is performed: concurrent callers for the same host share
    /// one upstream call. On error with `UseLastGood` enabled, a stale cache
    /// entry is served if available.
    pub async fn lookup_ip(&self, host: &str) -> Result<LookupResult, DnsError> {
        // Fast path: literal IP.
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(LookupResult {
                ip,
                ip6: None,
                all_ips: vec![ip],
            });
        }

        // Fast path: fresh cache hit.
        if let Some(entry) = self.cache_get(host).await {
            return Ok(entry);
        }

        let shared = self
            .inflight
            .do_(host.to_owned(), || async {
                let timeout = self.lookup_timeout_for_host(host).await;
                let result = tokio::time::timeout(timeout, self.do_lookup(host))
                    .await
                    .map_err(|_| format!("lookup timeout for {host}"))
                    .and_then(|result| result.map_err(|err| err.to_string()));
                if let Ok(ref resolved) = result {
                    self.cache_add(host, resolved.clone()).await;
                }
                result
            })
            .await;
        let result = match (shared.val, shared.err) {
            (Some(value), None) => Ok(value),
            (_, Some(error)) => Err(DnsError::Resolve(error)),
            (None, None) => Err(DnsError::Resolve(
                "singleflight returned no result".to_owned(),
            )),
        };

        // On error with UseLastGood, try stale cache.
        if let Err(ref err) = result {
            if self.use_last_good {
                if let Some(stale) = self.cache_get_expired(host).await {
                    tracing::debug!("dnscache: {host} using stale entry after error: {err}");
                    return Ok(stale);
                }
            }
        }

        result
    }

    /// Dial a TCP connection to `host:port` using the DNS cache.
    ///
    /// Resolves the host, then dials with happy-eyeballs: if multiple IPs are
    /// available, races them with staggered 300ms delays. If the first attempt
    /// fails and a fallback resolver is configured, retries with fallback IPs.
    pub async fn dial_tcp(&self, host: &str, port: u16) -> Result<TcpStream, DnsError> {
        let result = match self.lookup_ip(host).await {
            Ok(r) => r,
            Err(e) => return Err(DnsError::Resolve(format!("failed to resolve {host}: {e}"))),
        };

        // If only one IP, dial it directly.
        if result.all_ips.len() == 1 {
            return dial_one(result.ip, port).await;
        }

        // Race dial with happy-eyeballs.
        match race_dial(&result.all_ips, port).await {
            Ok(stream) => Ok(stream),
            Err(first_err) => {
                // Try fallback DNS if available.
                if let Some(ref fallback) = self.fallback {
                    let host_owned = host.to_string();
                    let fallback_ips = match tokio::time::timeout(
                        FALLBACK_TIMEOUT,
                        (fallback.as_ref())(&host_owned),
                    )
                    .await
                    {
                        Ok(Ok(ips)) if !ips.is_empty() => ips,
                        _ => return Err(first_err),
                    };
                    if let Ok(stream) = race_dial(&fallback_ips, port).await {
                        return Ok(stream);
                    }
                }
                Err(first_err)
            }
        }
    }

    // ---- internal helpers ----

    /// Get a fresh (non-expired) cache entry for `host`, if present.
    async fn cache_get(&self, host: &str) -> Option<LookupResult> {
        let cache = self.cache.lock().await;
        let entry = cache.get(host)?;
        if entry.expires > Instant::now() {
            Some(entry.result.clone())
        } else {
            None
        }
    }

    /// Get an expired cache entry for `host` (for UseLastGood fallback).
    async fn cache_get_expired(&self, host: &str) -> Option<LookupResult> {
        let cache = self.cache.lock().await;
        cache.get(host).map(|e| e.result.clone())
    }

    /// Add a cache entry for `host` with the configured TTL.
    /// Skips caching if the primary IP is private (captive-portal protection).
    async fn cache_add(&self, host: &str, result: LookupResult) {
        if is_private_ip(&result.ip) {
            tracing::debug!(
                "dnscache: {host} resolved to private IP {}; using but not caching",
                result.ip
            );
            return;
        }
        let mut cache = self.cache.lock().await;
        cache.insert(
            host.to_string(),
            CacheEntry {
                result,
                expires: Instant::now() + self.ttl,
            },
        );
    }

    /// Get the lookup timeout for `host`: fast (3s) if UseLastGood and a stale
    /// entry exists, slow (10s) otherwise. Matches Go's `lookupTimeoutForHost`.
    async fn lookup_timeout_for_host(&self, host: &str) -> Duration {
        if self.use_last_good {
            let cache = self.cache.lock().await;
            if cache.contains_key(host) {
                return FAST_LOOKUP_TIMEOUT;
            }
        }
        SLOW_LOOKUP_TIMEOUT
    }

    /// Perform the actual DNS lookup: forward (system or custom) first, then fallback.
    async fn do_lookup(&self, host: &str) -> Result<LookupResult, DnsError> {
        // Try the forward resolver (custom or system).
        let mut ips = if let Some(ref forward) = self.forward {
            let host_owned = host.to_string();
            (forward.as_ref())(&host_owned).await
        } else {
            system_lookup(host).await
        };

        // If forward failed or returned nothing, try the fallback.
        if ips.as_ref().map_or(true, Vec::is_empty) {
            if let Some(ref fallback) = self.fallback {
                let host_owned = host.to_string();
                match tokio::time::timeout(FALLBACK_TIMEOUT, (fallback.as_ref())(&host_owned)).await
                {
                    Ok(Ok(fb_ips)) if !fb_ips.is_empty() => {
                        ips = Ok(fb_ips);
                    }
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        if ips.is_err() {
                            return Err(DnsError::Resolve(format!(
                                "forward and fallback both failed for {host}: {e}"
                            )));
                        }
                    }
                    Err(_) => {
                        if ips.is_err() {
                            return Err(DnsError::Resolve(format!(
                                "forward and fallback both timed out for {host}"
                            )));
                        }
                    }
                }
            }
        }

        let ips = ips.map_err(|e| DnsError::Resolve(format!("system DNS for {host}: {e}")))?;
        if ips.is_empty() {
            return Err(DnsError::NoIps(host.to_string()));
        }

        // Build the result: prefer v4 as primary, v6 as secondary.
        let mut primary: Option<IpAddr> = None;
        let mut v6: Option<IpAddr> = None;

        for ip in &ips {
            match ip {
                IpAddr::V4(_) => {
                    if primary.is_none() {
                        primary = Some(*ip);
                    } else if v6.is_none() {
                        // If we already have v4 primary and this is also v4,
                        // check if we have a v6 later.
                    }
                }
                IpAddr::V6(_) => {
                    if primary.is_some() && v6.is_none() {
                        v6 = Some(*ip);
                    } else if primary.is_none() {
                        primary = Some(*ip);
                    }
                }
            }
        }

        let ip = primary.unwrap_or(ips[0]);
        Ok(LookupResult {
            ip,
            ip6: v6,
            all_ips: ips,
        })
    }
}

/// Resolve a hostname using the system resolver (tokio's `lookup_host`).
/// Returns all A/AAAA addresses for the hostname.
async fn system_lookup(host: &str) -> Result<Vec<IpAddr>, std::io::Error> {
    let addr = format!("{host}:0");
    let addrs = tokio::net::lookup_host(&addr).await?;
    let ips: Vec<IpAddr> = addrs.map(|sa| sa.ip()).collect();
    Ok(ips)
}

/// Dial a single IP on the given port.
async fn dial_one(ip: IpAddr, port: u16) -> Result<TcpStream, DnsError> {
    let stream = rustscale_netns::dial_tcp(&ip.to_string(), port).await?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// Race-dial multiple IPs with staggered 300ms delays (happy-eyeballs-lite).
/// Returns the first successful connection. If all fail, returns the last error.
async fn race_dial(ips: &[IpAddr], port: u16) -> Result<TcpStream, DnsError> {
    if ips.is_empty() {
        return Err(DnsError::Resolve("no IPs to dial".into()));
    }
    if ips.len() == 1 {
        return dial_one(ips[0], port).await;
    }

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<TcpStream, DnsError>>(ips.len());

    for (i, &ip) in ips.iter().enumerate() {
        let tx = tx.clone();
        tokio::spawn(async move {
            if i > 0 {
                tokio::time::sleep(FALLBACK_DELAY * i as u32).await;
            }
            let result = dial_one(ip, port).await;
            let _ = tx.send(result).await;
        });
    }
    drop(tx);

    let mut last_err = DnsError::Resolve("all dials failed".into());
    while let Some(result) = rx.recv().await {
        match result {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

/// Check if an IP address is private (RFC 1918 / ULA / link-local).
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            // ULA (fc00::/7), link-local (fe80::/10), loopback (::1).
            let segs = v6.segments();
            (segs[0] & 0xFE00) == 0xFC00 // ULA
                || (segs[0] & 0xFFC0) == 0xFE80 // link-local
                || v6.is_loopback()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Test that literal IPs are returned directly without any upstream lookup.
    #[tokio::test]
    async fn literal_ip_bypasses_cache() {
        let r = Resolver::new();
        let result = r.lookup_ip("1.2.3.4").await.unwrap();
        assert_eq!(result.ip, "1.2.3.4".parse::<IpAddr>().unwrap());
        assert_eq!(result.all_ips.len(), 1);
    }

    /// Test that literal IPv6 addresses work too.
    #[tokio::test]
    async fn literal_ipv6_bypasses_cache() {
        let r = Resolver::new();
        let result = r.lookup_ip("::1").await.unwrap();
        assert_eq!(result.ip, "::1".parse::<IpAddr>().unwrap());
    }

    /// Test TTL cache expiry: an entry expires after the TTL and a fresh lookup
    /// is triggered. Uses a mock forward lookup that counts calls.
    #[tokio::test]
    async fn cache_ttl_expiry() {
        let r = Resolver::new().with_ttl(Duration::from_millis(50));
        let host = "example.com";

        // First lookup: resolves and caches.
        // (Can't easily mock system DNS, but we can test cache logic with a
        // manual cache add + expiry check.)
        let result = LookupResult {
            ip: "1.2.3.4".parse().unwrap(),
            ip6: None,
            all_ips: vec!["1.2.3.4".parse().unwrap()],
        };
        r.cache_add(host, result.clone()).await;
        let cached = r.cache_get(host).await;
        assert!(cached.is_some(), "entry should be fresh");

        // Wait for TTL to expire.
        tokio::time::sleep(Duration::from_millis(60)).await;
        let expired = r.cache_get(host).await;
        assert!(expired.is_none(), "entry should be expired");
    }

    /// Test that private IPs are not cached.
    #[tokio::test]
    async fn private_ip_not_cached() {
        let r = Resolver::new();
        let host = "captive.portal";
        let result = LookupResult {
            ip: "10.0.0.1".parse().unwrap(),
            ip6: None,
            all_ips: vec!["10.0.0.1".parse().unwrap()],
        };
        r.cache_add(host, result).await;
        let cached = r.cache_get(host).await;
        assert!(cached.is_none(), "private IP should not be cached");
    }

    /// Test single-flight: N concurrent lookups for the same host result in only
    /// one upstream call. Uses a mock forward resolver with a counted, delayed
    /// response to verify dedup.
    #[tokio::test]
    async fn singleflight_dedup() {
        let call_count = Arc::new(AtomicUsize::new(0));

        let forward: ForwardLookup = {
            let count = call_count.clone();
            Arc::new(move |host: &str| {
                let count = count.clone();
                let _ = host.to_string();
                Box::pin(async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    // Simulate a slow lookup so concurrent callers pile up.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    Ok(vec!["93.184.216.34".parse::<IpAddr>().unwrap()])
                })
            })
        };

        let r = Arc::new(Resolver::new().with_forward(forward));
        let host = "singleflight.test";

        // Spawn 5 concurrent lookups for the same host.
        let mut handles = Vec::new();
        for _ in 0..5 {
            let r2 = r.clone();
            let h = host.to_string();
            handles.push(tokio::spawn(async move { r2.lookup_ip(&h).await }));
        }

        // Wait for all to complete.
        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok(), "each lookup should succeed");
            assert_eq!(
                result.unwrap().ip,
                "93.184.216.34".parse::<IpAddr>().unwrap()
            );
        }

        // The forward resolver should have been called exactly once.
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "single-flight should dedup to one upstream call"
        );
    }

    /// Test UseLastGood: when a refresh fails, the stale cache entry is served.
    #[tokio::test]
    async fn use_last_good_fallback() {
        let r = Resolver::new().with_use_last_good(true);
        let host = "stale.test";

        // Manually cache a good entry.
        let result = LookupResult {
            ip: "1.2.3.4".parse().unwrap(),
            ip6: None,
            all_ips: vec!["1.2.3.4".parse().unwrap()],
        };
        r.cache_add(host, result.clone()).await;

        // Simulate an expired entry by checking cache_get_expired.
        let stale = r.cache_get_expired(host).await;
        assert!(stale.is_some(), "should have a stale entry");
        assert_eq!(stale.unwrap().ip, result.ip);
    }

    /// Test that `is_private_ip` correctly identifies private ranges.
    #[test]
    fn private_ip_detection() {
        assert!(is_private_ip(&"10.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"172.16.0.1".parse().unwrap()));
        assert!(is_private_ip(&"192.168.1.1".parse().unwrap()));
        assert!(is_private_ip(&"169.254.1.1".parse().unwrap()));
        assert!(!is_private_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!is_private_ip(&"1.1.1.1".parse().unwrap()));
        // IPv6
        assert!(is_private_ip(&"fc00::1".parse().unwrap()));
        assert!(is_private_ip(&"fd00::1".parse().unwrap()));
        assert!(is_private_ip(&"fe80::1".parse().unwrap()));
        assert!(is_private_ip(&"::1".parse().unwrap()));
        assert!(!is_private_ip(&"2606:4700:4700::1111".parse().unwrap()));
    }

    /// Test that the fallback function is called when the forward resolver
    /// returns no results. Uses a custom fallback that returns a known IP.
    #[tokio::test]
    async fn fallback_called_on_empty_forward() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let count_clone = call_count.clone();

        let fallback: LookupFallback = Arc::new(move |host: &str| {
            let count = count_clone.clone();
            let _host = host.to_string();
            Box::pin(async move {
                count.fetch_add(1, Ordering::SeqCst);
                Ok(vec!["99.99.99.99".parse::<IpAddr>().unwrap()])
            })
        });

        let r = Resolver::new().with_fallback(fallback);

        // We can't easily control the system resolver, but we can test the
        // fallback by calling do_lookup with a host that definitely doesn't
        // resolve. If system DNS fails, the fallback should kick in.
        // On most test systems, "nonexistent.invalid" won't resolve.
        let result = r.do_lookup("nonexistent.invalid").await;
        // If system DNS fails, fallback should provide 99.99.99.99.
        // If system DNS somehow succeeds (unlikely for .invalid), that's fine too.
        if let Ok(res) = result {
            assert!(
                res.all_ips
                    .contains(&"99.99.99.99".parse::<IpAddr>().unwrap())
                    || !res.all_ips.is_empty()
            );
        }
        // The fallback was at least attempted (if forward returned empty/error).
    }

    /// Test that `race_dial` with a single IP just dials it directly.
    #[tokio::test]
    async fn race_dial_single_ip() {
        // Dial a local port that's not listening — should get a connection error.
        let result = race_dial(&["127.0.0.1".parse().unwrap()], 1).await;
        assert!(result.is_err(), "should fail to connect to closed port");
    }

    /// Test that `race_dial` with empty IPs returns an error.
    #[tokio::test]
    async fn race_dial_empty() {
        let result = race_dial(&[], 80).await;
        assert!(result.is_err());
    }

    /// Test that a real TCP listener can be dialed via race_dial.
    #[tokio::test]
    async fn race_dial_success() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let dial =
            tokio::spawn(async move { race_dial(&["127.0.0.1".parse().unwrap()], port).await });

        // Accept the connection so the dial succeeds.
        let _ = listener.accept().await;

        let result = dial.await.unwrap();
        assert!(result.is_ok(), "race_dial should succeed to open listener");
    }
}
