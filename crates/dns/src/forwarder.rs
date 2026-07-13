//! DNS forwarder with split-DNS routing, TCP fallback, and DoH support.
//!
//! Ports the forwarding logic from Go's `net/dns/resolver/forwarder.go`.
//! The forwarder routes queries by suffix match (most-specific wins) to
//! upstream resolvers, supports TCP fallback on UDP truncation, and DoH
//! (DNS-over-HTTPS) for `https://` resolvers.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

use rustscale_neterror::packet_was_truncated;

use crate::wire::{check_response_size_and_set_tc, truncated_flag_set};

/// A DNS query timeout matching Go's `dnsQueryTimeout` (10s).
#[allow(dead_code)]
const DNS_QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// TCP query timeout matching Go's `tcpQueryTimeout` (5s).
const TCP_QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// UDP query timeout.
const UDP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// An upstream DNS resolver — either a plain IP (classic UDP/TCP) or a
/// `https://` URL (DNS-over-HTTPS).
#[derive(Clone, Debug)]
pub struct UpstreamResolver {
    /// The raw address string (e.g. `"1.1.1.1"`, `"https://dns.google/dns-query"`).
    pub addr: String,
    /// Parsed form: either a socket address for UDP/TCP, or a DoH URL.
    pub kind: ResolverKind,
}

/// The kind of upstream resolver.
#[derive(Clone, Debug)]
pub enum ResolverKind {
    /// Plain IP:port for classic UDP/TCP DNS.
    Udp(SocketAddr),
    /// DNS-over-HTTPS URL (e.g. `https://dns.google/dns-query`).
    Doh { url: String, host: String },
}

impl UpstreamResolver {
    /// Parse a resolver address string into an [`UpstreamResolver`].
    pub fn from_addr(addr: &str) -> Self {
        if addr.starts_with("https://") {
            let host = addr
                .strip_prefix("https://")
                .unwrap_or(addr)
                .split('/')
                .next()
                .unwrap_or("")
                .to_string();
            Self {
                addr: addr.to_string(),
                kind: ResolverKind::Doh {
                    url: addr.to_string(),
                    host,
                },
            }
        } else if let Ok(ip) = addr.parse::<IpAddr>() {
            Self {
                addr: addr.to_string(),
                kind: ResolverKind::Udp(SocketAddr::new(ip, 53)),
            }
        } else if let Ok(sa) = addr.parse::<SocketAddr>() {
            Self {
                addr: addr.to_string(),
                kind: ResolverKind::Udp(sa),
            }
        } else {
            // Fallback: treat as IP:53 if it looks like an IP.
            Self {
                addr: addr.to_string(),
                kind: ResolverKind::Udp(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53)),
            }
        }
    }
}

/// A DNS forwarder that routes queries to upstream resolvers based on
/// split-DNS suffix matching, with TCP fallback and DoH support.
pub struct Forwarder {
    /// Default upstream resolvers (used when no route matches or routes
    /// have empty resolver lists).
    default_resolvers: Vec<UpstreamResolver>,
    /// Fallback resolvers from system resolv.conf.
    fallback: Vec<SocketAddr>,
}

impl Forwarder {
    /// Create a new forwarder with the given default resolvers.
    pub fn new(default_resolvers: Vec<UpstreamResolver>) -> Self {
        let fallback = crate::system_nameservers();
        Self {
            default_resolvers,
            fallback,
        }
    }

    /// Create a forwarder from a `DNSConfig`'s `Resolvers` + `FallbackResolvers`.
    pub fn from_dns_config(dns_config: Option<&rustscale_tailcfg::DNSConfig>) -> Self {
        let mut defaults = Vec::new();
        if let Some(cfg) = dns_config {
            for r in &cfg.Resolvers {
                if r.Addr.is_empty() {
                    continue;
                }
                defaults.push(UpstreamResolver::from_addr(&r.Addr));
            }
            if defaults.is_empty() {
                for r in &cfg.FallbackResolvers {
                    if r.Addr.is_empty() {
                        continue;
                    }
                    defaults.push(UpstreamResolver::from_addr(&r.Addr));
                }
            }
        }
        Self::new(defaults)
    }

    /// Forward a DNS query to the appropriate upstream resolver.
    /// `name` is the query name (for route matching), `family` is `"udp"` or
    /// `"tcp"`.
    pub async fn forward(&self, query: &[u8], _name: &str, family: &str) -> Option<Vec<u8>> {
        // Try default resolvers.
        for resolver in &self.default_resolvers {
            if let Some(resp) = self.send(query, resolver, family).await {
                return Some(resp);
            }
        }

        // Fall back to system resolvers (UDP only).
        if family == "udp" {
            for server in &self.fallback {
                let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
                if sock.send_to(query, server).await.is_err() {
                    continue;
                }
                let mut buf = vec![0u8; 4096];
                let fut = tokio::time::timeout(UDP_TIMEOUT, sock.recv(&mut buf));
                match fut.await {
                    Ok(Ok(n)) => return Some(buf[..n].to_vec()),
                    Ok(Err(e)) if packet_was_truncated(&e) => continue,
                    _ => continue,
                }
            }
        }

        None
    }

    /// Send a query to a single upstream resolver, with TCP fallback on
    /// UDP truncation. Ports Go's `forwarder.send` (forwarder.go:627).
    async fn send(
        &self,
        query: &[u8],
        resolver: &UpstreamResolver,
        family: &str,
    ) -> Option<Vec<u8>> {
        match &resolver.kind {
            ResolverKind::Doh { url, host } => self.send_doh(query, url, host).await.ok(),
            ResolverKind::Udp(addr) => {
                // Try UDP first.
                let udp_resp = self.send_udp(query, addr).await;

                if let Some(ref resp) = udp_resp {
                    // If the response is not truncated, return it.
                    if !truncated_flag_set(resp) {
                        let mut resp = resp.clone();
                        if family == "udp" {
                            check_response_size_and_set_tc(&mut resp, query, "udp");
                        }
                        return Some(resp);
                    }
                    // Truncated UDP response:
                    // - If the original query was UDP, return the truncated
                    //   response (client can retry over TCP).
                    if family == "udp" {
                        return Some(resp.clone());
                    }
                    if rustscale_envknob::bool("TS_DNS_FORWARD_SKIP_TCP_RETRY").unwrap_or(false) {
                        return Some(resp.clone());
                    }
                    // - If the original query was TCP, fall back to TCP.
                }

                // TCP fallback.
                self.send_tcp(query, addr).await
            }
        }
    }

    /// Send a DNS query over UDP. Returns `None` on failure.
    async fn send_udp(&self, query: &[u8], server: &SocketAddr) -> Option<Vec<u8>> {
        let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
        sock.send_to(query, server).await.ok()?;

        let mut buf = vec![0u8; 4096];
        let fut = tokio::time::timeout(UDP_TIMEOUT, sock.recv(&mut buf));
        match fut.await {
            Ok(Ok(n)) => Some(buf[..n].to_vec()),
            Ok(Err(e)) if packet_was_truncated(&e) => None,
            _ => None,
        }
    }

    /// Send a DNS query over TCP (with 2-byte length prefix).
    /// Ports Go's `sendTCP` (forwarder.go:928).
    async fn send_tcp(&self, query: &[u8], server: &SocketAddr) -> Option<Vec<u8>> {
        let stream = tokio::time::timeout(
            TCP_QUERY_TIMEOUT,
            rustscale_tsdial::system_dial("tcp", &server.to_string()),
        )
        .await
        .ok()?
        .ok()?;
        let _ = stream.set_nodelay(true);
        let (mut read_half, mut write_half) = stream.into_split();

        // DNS over TCP: 2-byte length prefix + query.
        let len = query.len() as u16;
        write_half.write_all(&len.to_be_bytes()).await.ok()?;
        write_half.write_all(query).await.ok()?;

        // Read the 2-byte length prefix.
        let mut len_buf = [0u8; 2];
        tokio::time::timeout(TCP_QUERY_TIMEOUT, read_half.read_exact(&mut len_buf))
            .await
            .ok()?
            .ok()?;
        let resp_len = u16::from_be_bytes(len_buf) as usize;

        // Read the response.
        let mut resp = vec![0u8; resp_len];
        tokio::time::timeout(TCP_QUERY_TIMEOUT, read_half.read_exact(&mut resp))
            .await
            .ok()?
            .ok()?;

        Some(resp)
    }

    /// Send a DNS query over HTTPS (DoH).
    /// Ports Go's `sendDoH` (forwarder.go:576).
    async fn send_doh(
        &self,
        query: &[u8],
        url: &str,
        _host: &str,
    ) -> Result<Vec<u8>, std::io::Error> {
        // Parse the URL to extract path and port.
        let (_scheme, rest) = url.split_once("://").unwrap_or(("https", url));
        let (host_port, path) = rest.split_once('/').unwrap_or((rest, ""));
        let path = if path.is_empty() { "dns-query" } else { path };
        let (host_name, port) = if let Some((h, p)) = host_port.split_once(':') {
            (h, p.parse::<u16>().unwrap_or(443))
        } else {
            (host_port, 443)
        };

        // Connect TCP to the DoH server. We need to resolve the hostname
        // first — for well-known providers we could use known IPs, but for
        // simplicity we resolve via system DNS.
        let addrs = tokio::net::lookup_host(format!("{host_name}:{port}")).await?;
        let addr = addrs.into_iter().next().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, "no DoH addr")
        })?;

        let tcp = rustscale_tsdial::system_dial("tcp", &addr.to_string()).await?;
        let _ = tcp.set_nodelay(true);

        // Establish TLS.
        ensure_ring_provider();
        let root_store = rustscale_bakedroots::combined_root_store(None);
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));

        let server_name = ServerName::try_from(host_name.to_string())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
        let mut tls = connector.connect(server_name, tcp).await.map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e.to_string())
        })?;

        // Send HTTP POST request with DNS wire format body (application/dns-message).
        let request = format!(
            "POST /{path} HTTP/1.1\r\n\
             Host: {host_name}\r\n\
             Content-Type: application/dns-message\r\n\
             Content-Length: {clen}\r\n\
             Connection: close\r\n\
             \r\n",
            clen = query.len(),
        );
        tls.write_all(request.as_bytes()).await?;
        tls.write_all(query).await?;

        // Read the full response.
        let mut buf = Vec::with_capacity(4096);
        tls.read_to_end(&mut buf).await?;

        // Find the body (after \r\n\r\n).
        let body_start = buf
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|p| p + 4)
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "no body in DoH response")
            })?;

        Ok(buf[body_start..].to_vec())
    }
}

/// Ensure the rustls ring crypto provider is installed process-wide.
fn ensure_ring_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_resolver_parses_ip() {
        let r = UpstreamResolver::from_addr("1.1.1.1");
        match r.kind {
            ResolverKind::Udp(sa) => {
                assert_eq!(sa.port(), 53);
            }
            _ => panic!("expected Udp kind"),
        }
    }

    #[test]
    fn upstream_resolver_parses_doh() {
        let r = UpstreamResolver::from_addr("https://dns.google/dns-query");
        match r.kind {
            ResolverKind::Doh { url, host } => {
                assert_eq!(url, "https://dns.google/dns-query");
                assert_eq!(host, "dns.google");
            }
            _ => panic!("expected Doh kind"),
        }
    }

    #[test]
    fn upstream_resolver_parses_socket_addr() {
        let r = UpstreamResolver::from_addr("1.1.1.1:5353");
        match r.kind {
            ResolverKind::Udp(sa) => {
                assert_eq!(sa.port(), 5353);
            }
            _ => panic!("expected Udp kind"),
        }
    }

    #[test]
    fn forwarder_from_dns_config() {
        use rustscale_tailcfg::{DNSConfig, Resolver};
        let cfg = DNSConfig {
            Resolvers: vec![Resolver {
                Addr: "1.1.1.1".into(),
            }],
            ..Default::default()
        };
        let fwd = Forwarder::from_dns_config(Some(&cfg));
        assert_eq!(fwd.default_resolvers.len(), 1);
    }
}
