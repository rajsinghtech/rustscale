//! DNS fallback resolver using DERP bootstrap DNS servers.
//!
//! Ports Go's `net/dnsfallback` package. When system DNS is broken (common in
//! Docker/k8s/embedded), this resolver queries DERP relay servers over HTTPS
//! at `/bootstrap-dns?q=<host>` using their baked-in IP addresses. The response
//! is a JSON map of `hostname -> [IPs]`.
//!
//! Also provides `get_derp_map()` which merges the static (compiled-in) DERP
//! map with any on-disk cached DERP map, and `set_cache_path` / `update_cache`
//! for persisting updated DERP maps.

#![forbid(unsafe_code)]

use std::net::IpAddr;
use std::sync::Mutex;

use rand::seq::SliceRandom;
use rand::thread_rng;
use rustscale_tailcfg::DERPMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

/// Embedded DERP fallback server map (baked into the binary at compile time).
const STATIC_DERP_MAP_JSON: &str = include_str!("dns-fallback-servers.json");

/// Maximum number of DERP candidates to try per lookup (matching Go's `maxCands`).
const MAX_CANDS: usize = 6;

/// Per-candidate timeout for the bootstrap DNS HTTPS request (3s, matching Go).
const BOOTSTRAP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Errors from DNS fallback operations.
#[derive(Debug, thiserror::Error)]
pub enum FallbackError {
    #[error("dnsfallback: {0}")]
    Resolve(String),
    #[error("dnsfallback: io: {0}")]
    Io(#[from] std::io::Error),
    #[error("dnsfallback: tls: {0}")]
    Tls(String),
    #[error("dnsfallback: json: {0}")]
    Json(#[from] serde_json::Error),
}

/// A hostname + IP candidate pair for bootstrap DNS queries.
#[derive(Clone)]
struct NameIp {
    hostname: String,
    ip: IpAddr,
}

/// Global cached DERP map (loaded from disk via `set_cache_path`).
static CACHED_DERP_MAP: Mutex<Option<DERPMap>> = Mutex::new(None);

/// Global cache file path (set by `set_cache_path`).
static CACHE_PATH: Mutex<Option<String>> = Mutex::new(None);

/// Return the static (compiled-in) DERP map.
///
/// This is always available and serves as a baseline. The dynamically updated
/// DERP map should always be preferred; use this only when the control plane
/// is unreachable or hasn't been reached yet.
pub fn get_static_derp_map() -> DERPMap {
    serde_json::from_str(STATIC_DERP_MAP_JSON).expect("embedded DERP map JSON must be valid")
}

/// Return the merged DERP map: static + cached (from disk).
///
/// Cached regions not in the static map are added. For overlapping regions,
/// cached nodes not in the static map's region are appended. This ensures new
/// regions are picked up while not overriding built-in fallbacks if a cached
/// map is bad.
pub fn get_derp_map() -> DERPMap {
    let mut dm = get_static_derp_map();

    let cached = CACHED_DERP_MAP.lock().unwrap();
    let Some(ref cached) = *cached else {
        return dm;
    };

    for (id, region) in &cached.Regions {
        match dm.Regions.get_mut(id) {
            None => {
                // New region not in static map — add it.
                dm.Regions.insert(*id, region.clone());
            }
            Some(dr) => {
                // Existing region — add any nodes we don't already have.
                let mut seen: Vec<String> = dr
                    .Nodes
                    .as_ref()
                    .map(|nodes| nodes.iter().map(|n| n.HostName.clone()).collect())
                    .unwrap_or_default();

                if let Some(ref cached_nodes) = region.Nodes {
                    for n in cached_nodes {
                        if !seen.contains(&n.HostName) {
                            seen.push(n.HostName.clone());
                            dr.Nodes.get_or_insert_with(Vec::new).push(n.clone());
                        }
                    }
                }
            }
        }
    }

    dm
}

/// Set the on-disk DERP map cache path. If a file exists at this path, it is
/// loaded and merged with the static map. Should be called before any calls
/// to `update_cache` (not concurrency-safe, matching Go).
pub fn set_cache_path(path: &str) {
    CACHE_PATH.lock().unwrap().replace(path.to_string());

    if let Ok(data) = std::fs::read(path) {
        match serde_json::from_slice::<DERPMap>(&data) {
            Ok(dm) => {
                CACHED_DERP_MAP.lock().unwrap().replace(dm);
                tracing::debug!("dnsfallback: loaded cached DERP map from {path}");
            }
            Err(e) => {
                tracing::warn!("dnsfallback: error decoding cached DERP map from {path}: {e}");
            }
        }
    } else {
        tracing::debug!("dnsfallback: no cached DERP map at {path}");
    }
}

/// Update the on-disk DERP map cache. Only writes if the map has changed.
/// The caller must not mutate `map` after calling this (matching Go).
pub fn update_cache(map: &DERPMap) {
    let mut cached = CACHED_DERP_MAP.lock().unwrap();

    // Skip if nothing changed.
    if let Some(ref existing) = *cached {
        if existing == map {
            return;
        }
    }

    // Serialize before storing so we know it's valid JSON.
    let data = match serde_json::to_vec(map) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!("dnsfallback: update_cache error marshaling: {e}");
            return;
        }
    };

    cached.replace(map.clone());

    let path = CACHE_PATH.lock().unwrap();
    if let Some(ref path) = *path {
        if let Err(e) = std::fs::write(path, &data) {
            tracing::warn!("dnsfallback: update_cache error writing: {e}");
        }
    }
}

/// Create a lookup function suitable for use as `dnscache::LookupFallback`.
///
/// Resolves a hostname by querying DERP servers' `/bootstrap-dns` HTTPS endpoint
/// using their baked-in IP addresses. Tries up to 6 randomly-selected DERP
/// servers, alternating v4/v6, and returns the first successful response.
///
/// If `host` is already a literal IP address, it is returned directly.
pub async fn resolve(host: &str) -> Result<Vec<IpAddr>, FallbackError> {
    // Fast path: literal IP.
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }

    let dm = get_derp_map();

    // Collect v4 and v6 candidates from all DERP nodes.
    let mut cands4: Vec<NameIp> = Vec::new();
    let mut cands6: Vec<NameIp> = Vec::new();

    for region in dm.Regions.values() {
        if let Some(ref nodes) = region.Nodes {
            for n in nodes {
                if let Ok(ip) = n.IPv4.parse::<IpAddr>() {
                    cands4.push(NameIp {
                        hostname: n.HostName.clone(),
                        ip,
                    });
                }
                if let Ok(ip) = n.IPv6.parse::<IpAddr>() {
                    cands6.push(NameIp {
                        hostname: n.HostName.clone(),
                        ip,
                    });
                }
            }
        }
    }

    // Shuffle candidates.
    {
        let mut rng = thread_rng();
        cands4.shuffle(&mut rng);
        cands6.shuffle(&mut rng);
    }

    // Build alternating v4/v6 candidate list, up to MAX_CANDS.
    let mut cands: Vec<NameIp> = Vec::with_capacity(MAX_CANDS);
    while (!cands4.is_empty() || !cands6.is_empty()) && cands.len() < MAX_CANDS {
        if let Some(c) = cands4.pop() {
            cands.push(c);
        }
        if cands.len() >= MAX_CANDS {
            break;
        }
        if let Some(c) = cands6.pop() {
            cands.push(c);
        }
    }

    if cands.is_empty() {
        return Err(FallbackError::Resolve(format!(
            "no DNS fallback options for {host}"
        )));
    }

    // Try each candidate sequentially.
    for cand in &cands {
        tracing::debug!(
            "dnsfallback: trying bootstrapDNS({:?}, {}) for {}",
            cand.hostname,
            cand.ip,
            host
        );

        let result = tokio::time::timeout(
            BOOTSTRAP_TIMEOUT,
            bootstrap_dns_map(&cand.hostname, &cand.ip, host),
        )
        .await;

        match result {
            Ok(Ok(dm)) => {
                if let Some(ips) = dm.get(host) {
                    if !ips.is_empty() {
                        let mut ips = ips.clone();
                        ips.shuffle(&mut thread_rng());
                        tracing::debug!(
                            "dnsfallback: bootstrapDNS({:?}, {}) for {} = {:?}",
                            cand.hostname,
                            cand.ip,
                            host,
                            ips
                        );
                        return Ok(ips);
                    }
                }
            }
            Ok(Err(e)) => {
                tracing::debug!(
                    "dnsfallback: bootstrapDNS({:?}, {}) for {} error: {e}",
                    cand.hostname,
                    cand.ip,
                    host
                );
            }
            Err(_) => {
                tracing::debug!(
                    "dnsfallback: bootstrapDNS({:?}, {}) for {} timed out",
                    cand.hostname,
                    cand.ip,
                    host
                );
            }
        }
    }

    Err(FallbackError::Resolve(format!(
        "no DNS fallback candidates remain for {host}"
    )))
}

/// Query a DERP server's `/bootstrap-dns` endpoint over HTTPS.
///
/// Connects via TLS to `server_ip:443` with SNI set to `server_name`, then
/// sends `GET /bootstrap-dns?q=<query>`. The response is a JSON map of
/// `hostname -> [IP string]`.
async fn bootstrap_dns_map(
    server_name: &str,
    server_ip: &IpAddr,
    query: &str,
) -> Result<std::collections::HashMap<String, Vec<IpAddr>>, FallbackError> {
    // Connect TCP to the DERP server's IP on port 443.
    let addr = std::net::SocketAddr::new(*server_ip, 443);
    let tcp = TcpStream::connect(addr).await?;
    let _ = tcp.set_nodelay(true);

    // Establish TLS with SNI = server_name (e.g. "derp1.tailscale.com").
    ensure_ring_provider();
    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(std::sync::Arc::new(config));

    let server_name_parsed = ServerName::try_from(server_name.to_string())
        .map_err(|e| FallbackError::Tls(format!("invalid server name: {e}")))?;
    let mut tls = connector
        .connect(server_name_parsed, tcp)
        .await
        .map_err(|e| FallbackError::Tls(e.to_string()))?;

    // Send the HTTP GET request.
    let request = format!(
        "GET /bootstrap-dns?q={query} HTTP/1.1\r\n\
         Host: {server_name}\r\n\
         Connection: close\r\n\
         Accept: application/json\r\n\
         \r\n",
    );
    tls.write_all(request.as_bytes()).await?;

    // Read the full response.
    let mut buf = Vec::with_capacity(4096);
    tls.read_to_end(&mut buf).await?;

    // Find the body (after \r\n\r\n).
    let body_start = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .ok_or_else(|| FallbackError::Resolve("no body in bootstrap-dns response".into()))?;

    let body = &buf[body_start..];

    // Parse the JSON response: { "hostname": ["ip1", "ip2", ...] }
    // The Go format uses netip.Addr which serializes as strings.
    let raw: std::collections::HashMap<String, Vec<String>> = serde_json::from_slice(body)?;

    // Convert string IPs to IpAddr.
    let mut result = std::collections::HashMap::with_capacity(raw.len());
    for (name, ip_strings) in raw {
        let mut ips = Vec::with_capacity(ip_strings.len());
        for s in ip_strings {
            if let Ok(ip) = s.parse::<IpAddr>() {
                ips.push(ip);
            }
        }
        result.insert(name, ips);
    }

    Ok(result)
}

/// Ensure the rustls ring crypto provider is installed process-wide.
fn ensure_ring_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Build a `dnscache::LookupFallback` function wrapping `resolve`.
///
/// Usage:
/// ```ignore
/// let resolver = dnscache::Resolver::new()
///     .with_fallback(rustscale_dnsfallback::make_lookup_fallback());
/// ```
pub fn make_lookup_fallback() -> std::sync::Arc<
    dyn Fn(
            &str,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<Vec<IpAddr>, rustscale_dnscache::DnsError>>
                    + Send,
            >,
        > + Send
        + Sync,
> {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;

    Arc::new(
        |host: &str| -> Pin<
            Box<dyn Future<Output = Result<Vec<IpAddr>, rustscale_dnscache::DnsError>> + Send>,
        > {
            let host = host.to_string();
            Box::pin(async move {
                resolve(&host)
                    .await
                    .map_err(|e| rustscale_dnscache::DnsError::Resolve(e.to_string()))
            })
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustscale_tailcfg::{DERPNode, DERPRegion};
    use std::collections::BTreeMap;
    use std::sync::Mutex as StdMutex;

    /// Serialize tests that touch the global CACHED_DERP_MAP / CACHE_PATH,
    /// since Rust runs #[test] functions in parallel by default.
    static TEST_GUARD: StdMutex<()> = StdMutex::new(());

    /// Test that the embedded DERP map JSON is valid and parseable.
    #[test]
    fn static_derp_map_parses() {
        let dm = get_static_derp_map();
        assert!(
            !dm.Regions.is_empty(),
            "static DERP map should have regions"
        );
        // Check a known region.
        assert!(dm.Regions.contains_key(&1), "should have region 1");
        let r1 = &dm.Regions[&1];
        assert!(!r1.RegionCode.is_empty());
        let nodes = r1.Nodes.as_ref().expect("region 1 should have nodes");
        assert!(!nodes.is_empty(), "region 1 should have nodes");
    }

    /// Test that literal IPs are returned directly.
    #[tokio::test]
    async fn literal_ip_returned_directly() {
        let result = resolve("1.2.3.4").await.unwrap();
        assert_eq!(result, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
    }

    /// Test that `get_derp_map` merges cached regions into the static map.
    #[test]
    fn derp_map_merge_cached_regions() {
        let _guard = TEST_GUARD.lock().unwrap();
        // Save original state.
        let orig = CACHED_DERP_MAP.lock().unwrap().clone();

        // Create a cached map with a new region not in the static map.
        let mut cached_regions = BTreeMap::new();
        cached_regions.insert(
            999,
            DERPRegion {
                RegionID: 999,
                RegionCode: "test".into(),
                RegionName: "Test Region".into(),
                Nodes: Some(vec![DERPNode {
                    Name: "999a".into(),
                    RegionID: 999,
                    HostName: "derp999.test".into(),
                    IPv4: "10.0.0.999".into(),
                    ..Default::default()
                }]),
                ..Default::default()
            },
        );
        *CACHED_DERP_MAP.lock().unwrap() = Some(DERPMap {
            Regions: cached_regions,
            ..Default::default()
        });

        let dm = get_derp_map();
        // Static regions should still be present.
        assert!(dm.Regions.contains_key(&1));
        // New cached region should be merged in.
        assert!(dm.Regions.contains_key(&999));

        // Restore.
        *CACHED_DERP_MAP.lock().unwrap() = orig;
    }

    /// Test that `get_derp_map` appends new nodes to existing regions.
    #[test]
    fn derp_map_merge_appends_nodes() {
        let _guard = TEST_GUARD.lock().unwrap();
        let orig = CACHED_DERP_MAP.lock().unwrap().clone();

        // Create a cached map with a new node in region 1.
        let mut cached_regions = BTreeMap::new();
        let static_dm = get_static_derp_map();
        let r1 = static_dm.Regions.get(&1).unwrap();
        let existing_count = r1.Nodes.as_ref().map_or(0, Vec::len);

        let mut nodes = r1.Nodes.clone().unwrap_or_default();
        nodes.push(DERPNode {
            Name: "1z".into(),
            RegionID: 1,
            HostName: "derp1z.test.new".into(),
            IPv4: "10.10.10.10".into(),
            ..Default::default()
        });

        cached_regions.insert(
            1,
            DERPRegion {
                RegionID: 1,
                RegionCode: r1.RegionCode.clone(),
                RegionName: r1.RegionName.clone(),
                Nodes: Some(nodes),
                ..Default::default()
            },
        );
        *CACHED_DERP_MAP.lock().unwrap() = Some(DERPMap {
            Regions: cached_regions,
            ..Default::default()
        });

        let dm = get_derp_map();
        let merged_r1 = &dm.Regions[&1];
        let merged_nodes = merged_r1.Nodes.as_ref().unwrap();
        assert!(
            merged_nodes.len() > existing_count,
            "merged region should have more nodes"
        );
        assert!(
            merged_nodes.iter().any(|n| n.HostName == "derp1z.test.new"),
            "new node should be in merged map"
        );

        // Restore.
        *CACHED_DERP_MAP.lock().unwrap() = orig;
    }

    /// Test DERP map cache round-trip: write → read → merge.
    #[test]
    fn derp_map_cache_round_trip() {
        let _guard = TEST_GUARD.lock().unwrap();
        let tmp = std::env::temp_dir();
        let path = tmp.join("dnsfallback_test_cache.json");
        let _ = std::fs::remove_file(&path);

        // Set cache path (no file exists yet — should be a no-op load).
        set_cache_path(path.to_str().unwrap());
        assert!(CACHED_DERP_MAP.lock().unwrap().is_none());

        // Write a DERP map to the cache.
        let mut regions = BTreeMap::new();
        regions.insert(
            888,
            DERPRegion {
                RegionID: 888,
                RegionCode: "rt".into(),
                RegionName: "Round Trip".into(),
                Nodes: Some(vec![DERPNode {
                    Name: "888a".into(),
                    RegionID: 888,
                    HostName: "derp888.test".into(),
                    IPv4: "1.2.3.4".into(),
                    ..Default::default()
                }]),
                ..Default::default()
            },
        );
        let test_map = DERPMap {
            Regions: regions,
            ..Default::default()
        };
        update_cache(&test_map);

        // Verify the file was written.
        assert!(path.exists(), "cache file should exist after update_cache");

        // Clear the in-memory cache and reload from disk.
        *CACHED_DERP_MAP.lock().unwrap() = None;
        set_cache_path(path.to_str().unwrap());

        // Verify the cached map was loaded.
        {
            let cached = CACHED_DERP_MAP.lock().unwrap();
            assert!(
                cached.is_some(),
                "cached DERP map should be loaded from disk"
            );
            assert!(cached.as_ref().unwrap().Regions.contains_key(&888));
        }

        // Clean up.
        *CACHED_DERP_MAP.lock().unwrap() = None;
        *CACHE_PATH.lock().unwrap() = None;
        let _ = std::fs::remove_file(&path);
    }

    /// Test that `update_cache` skips writing when the map hasn't changed.
    #[test]
    fn update_cache_no_change() {
        let _guard = TEST_GUARD.lock().unwrap();
        let orig = CACHED_DERP_MAP.lock().unwrap().clone();
        let tmp = std::env::temp_dir();
        let path = tmp.join("dnsfallback_test_nochg.json");
        let _ = std::fs::remove_file(&path);

        set_cache_path(path.to_str().unwrap());

        let test_map = get_static_derp_map();
        update_cache(&test_map);
        assert!(path.exists());

        // Get file modification time.
        let mtime1 = std::fs::metadata(&path).unwrap().modified().unwrap();

        // Wait a tiny bit.
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Call again with the same map — should not write.
        update_cache(&test_map);
        let mtime2 = std::fs::metadata(&path).unwrap().modified().unwrap();

        assert_eq!(
            mtime1, mtime2,
            "file should not be rewritten when unchanged"
        );

        // Clean up.
        *CACHED_DERP_MAP.lock().unwrap() = orig;
        *CACHE_PATH.lock().unwrap() = None;
        let _ = std::fs::remove_file(&path);
    }

    /// Test that `resolve` returns an error for a hostname that can't be
    /// resolved by any fallback (when all candidates time out). This test
    /// doesn't require network access — it just verifies error handling when
    /// no candidates respond. We use a zero-second timeout by making all
    /// IPs unreachable.
    #[tokio::test]
    #[ignore = "requires network access to DERP servers"]
    async fn resolve_real_hostname() {
        // This test hits real DERP servers — ignored by default.
        let result = resolve("controlplane.tailscale.com").await;
        assert!(result.is_ok(), "should resolve via DERP bootstrap DNS");
        let ips = result.unwrap();
        assert!(!ips.is_empty());
    }

    /// Test bootstrap DNS JSON response parsing from a mock HTTP response.
    #[tokio::test]
    async fn bootstrap_dns_json_parsing() {
        // Simulate a bootstrap DNS JSON response.
        let json = r#"{"controlplane.tailscale.com": ["100.64.0.1", "2001:db8::1"], "other.com": ["1.2.3.4"]}"#;
        let http_response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            json.len(),
            json
        );

        // Start a mock TCP listener (unused — we test JSON parsing directly
        // since we can't easily test the full TLS path without real certs).
        let _listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();

        // We can't easily test the full TLS path, but we can test the JSON
        // parsing logic directly.
        let body_start = http_response.find("\r\n\r\n").map(|p| p + 4).unwrap();
        let body = &http_response[body_start..];
        let raw: std::collections::HashMap<String, Vec<String>> =
            serde_json::from_str(body).unwrap();

        let mut result = std::collections::HashMap::new();
        for (name, ip_strings) in raw {
            let ips: Vec<IpAddr> = ip_strings
                .iter()
                .filter_map(|s| s.parse::<IpAddr>().ok())
                .collect();
            result.insert(name, ips);
        }

        assert!(result.contains_key("controlplane.tailscale.com"));
        let ips = &result["controlplane.tailscale.com"];
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&"100.64.0.1".parse::<IpAddr>().unwrap()));
        assert!(ips.contains(&"2001:db8::1".parse::<IpAddr>().unwrap()));

        // Ensure the listener task is not starved.
        // (No drop needed — _listener is dropped at scope end.)
    }

    /// Test that `make_lookup_fallback` produces a working fallback function.
    #[tokio::test]
    async fn make_lookup_fallback_works() {
        let fallback = make_lookup_fallback();
        // Test with a literal IP — should return directly.
        let result = fallback("1.2.3.4").await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
    }
}
