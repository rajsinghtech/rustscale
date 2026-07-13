//! Ephemeral `(protocol, localhost IP:port) -> Tailscale IP` registry.
//!
//! Used by netstack's TCP handler to register proxied connections so that
//! WhoIs can attribute them. Mirrors Go's `net/proxymap/` package.
//!
//! The retry-with-sleep pattern in [`Mapper::whois_ipport`] works around a
//! registration race (Go issue #1616) where the goroutine that registers the
//! mapping may not have completed before the lookup arrives.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;

/// Key for the internal map: `(protocol, localhost IP:port)`.
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
struct MappingKey {
    proto: String,
    addr: SocketAddr,
}

/// Maps localhost `(proto, ip:port)` pairs to Tailscale IPs.
/// Thread-safe via internal `Mutex`.
///
/// Mirrors Go's `proxymap.Mapper`.
pub struct Mapper {
    inner: Mutex<HashMap<MappingKey, IpAddr>>,
}

impl Default for Mapper {
    fn default() -> Self {
        Self::new()
    }
}

impl Mapper {
    /// Create an empty mapper.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Register a mapping: `(proto, localhost ipport) -> ts_ip`.
    ///
    /// Returns an error if the key is already registered with a different IP.
    /// Re-registering the same key with the same IP is a no-op.
    pub fn register(&self, proto: &str, ipport: SocketAddr, ts_ip: IpAddr) -> Result<(), String> {
        let key = MappingKey {
            proto: proto.to_string(),
            addr: ipport,
        };
        let mut map = self.inner.lock().unwrap();
        if let Some(&existing) = map.get(&key) {
            if existing == ts_ip {
                return Ok(());
            }
            return Err(format!(
                "proxymap: key ({proto}, {ipport}) already registered to {existing}"
            ));
        }
        map.insert(key, ts_ip);
        Ok(())
    }

    /// Unregister a mapping. Safe to call on a non-existent key.
    pub fn unregister(&self, proto: &str, ipport: SocketAddr) {
        let key = MappingKey {
            proto: proto.to_string(),
            addr: ipport,
        };
        self.inner.lock().unwrap().remove(&key);
    }

    /// Look up a localhost `(proto, ipport) -> Tailscale IP`.
    ///
    /// Retries with 0/10/20/50/100ms sleeps to work around the registration
    /// race (issue #1616 pattern). The total worst-case latency is ~180ms.
    pub async fn whois_ipport(&self, proto: &str, ipport: SocketAddr) -> Option<IpAddr> {
        let key = MappingKey {
            proto: proto.to_string(),
            addr: ipport,
        };

        let delays = [
            std::time::Duration::from_millis(0),
            std::time::Duration::from_millis(10),
            std::time::Duration::from_millis(20),
            std::time::Duration::from_millis(50),
            std::time::Duration::from_millis(100),
        ];

        for delay in delays {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            if let Some(&ip) = self.inner.lock().unwrap().get(&key) {
                return Some(ip);
            }
        }
        None
    }

    /// Synchronous lookup without retry — for cases where the caller already
    /// holds the runtime context and doesn't need the race workaround.
    pub fn whois_ipport_no_retry(&self, proto: &str, ipport: SocketAddr) -> Option<IpAddr> {
        let key = MappingKey {
            proto: proto.to_string(),
            addr: ipport,
        };
        self.inner.lock().unwrap().get(&key).copied()
    }

    /// Reverse lookup: find the `(proto, localhost addr)` that maps to the
    /// given Tailscale IP. Returns the first match.
    pub fn whois_by_ip(&self, ts_ip: IpAddr) -> Option<(String, SocketAddr)> {
        let map = self.inner.lock().unwrap();
        map.iter()
            .find(|(_, &ip)| ip == ts_ip)
            .map(|(k, _)| (k.proto.clone(), k.addr))
    }

    /// Current number of registered mappings.
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    /// Whether the mapper is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_register_and_lookup() {
        let m = Mapper::new();
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        let ts_ip = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1));

        assert!(m.register("tcp", local, ts_ip).is_ok());
        assert_eq!(m.whois_ipport_no_retry("tcp", local), Some(ts_ip));
    }

    #[test]
    fn test_register_duplicate_same_ip() {
        let m = Mapper::new();
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9090);
        let ts_ip = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2));

        assert!(m.register("tcp", local, ts_ip).is_ok());
        assert!(m.register("tcp", local, ts_ip).is_ok());
    }

    #[test]
    fn test_register_duplicate_different_ip() {
        let m = Mapper::new();
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9090);
        let ip1 = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2));

        assert!(m.register("tcp", local, ip1).is_ok());
        assert!(m.register("tcp", local, ip2).is_err());
    }

    #[test]
    fn test_unregister() {
        let m = Mapper::new();
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7070);
        let ts_ip = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 3));

        m.register("tcp", local, ts_ip).unwrap();
        assert_eq!(m.whois_ipport_no_retry("tcp", local), Some(ts_ip));
        m.unregister("tcp", local);
        assert_eq!(m.whois_ipport_no_retry("tcp", local), None);
    }

    #[test]
    fn test_unregister_nonexistent() {
        let m = Mapper::new();
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234);
        m.unregister("tcp", local);
    }

    #[test]
    fn test_different_proto_same_port() {
        let m = Mapper::new();
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4040);
        let ip_tcp = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 10));
        let ip_udp = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 11));

        m.register("tcp", local, ip_tcp).unwrap();
        m.register("udp", local, ip_udp).unwrap();
        assert_eq!(m.whois_ipport_no_retry("tcp", local), Some(ip_tcp));
        assert_eq!(m.whois_ipport_no_retry("udp", local), Some(ip_udp));
    }

    #[tokio::test]
    async fn test_whois_retry_immediate_hit() {
        let m = Mapper::new();
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3030);
        let ts_ip = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 20));

        m.register("tcp", local, ts_ip).unwrap();
        let result = m.whois_ipport("tcp", local).await;
        assert_eq!(result, Some(ts_ip));
    }

    #[tokio::test]
    async fn test_whois_retry_miss() {
        let m = Mapper::new();
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5050);
        let result = m.whois_ipport("tcp", local).await;
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_whois_retry_concurrent_register() {
        let m = std::sync::Arc::new(Mapper::new());
        let local = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 6060);
        let ts_ip = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 30));

        let m2 = m.clone();
        let local2 = local;
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(15)).await;
            m2.register("tcp", local2, ts_ip).unwrap();
        });

        let result = m.whois_ipport("tcp", local).await;
        assert_eq!(result, Some(ts_ip));
    }
}
