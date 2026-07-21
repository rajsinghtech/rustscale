//! DNS forwarder with split-DNS routing, TCP fallback, and DoH support.
//!
//! Ports the forwarding logic from Go's `net/dns/resolver/forwarder.go`.
//! The forwarder routes queries by suffix match (most-specific wins) to
//! upstream resolvers, supports TCP fallback on UDP truncation, and DoH
//! (DNS-over-HTTPS) for `https://` resolvers.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

use rustscale_neterror::packet_was_truncated;

use crate::wire::{check_response_size_and_set_tc, set_tc_flag, truncated_flag_set, HEADER_BYTES};

/// TCP query timeout matching Go's `tcpQueryTimeout` (5s).
const TCP_QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// UDP query timeout.
const UDP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Maximum classic UDP response retained by the pinned Go resolver. One extra
/// byte is read to detect kernel/socket truncation and set TC deterministically.
const MAX_RESPONSE_BYTES: usize = 4095;

/// Hard cap for the complete HTTP response around a DoH DNS message.
const MAX_DOH_HTTP_BYTES: u64 = 128 * 1024;

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
    /// Malformed or unsupported resolver address. It is retained for
    /// diagnostics but never redirected to an unrelated public resolver.
    Invalid,
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
            Self {
                addr: addr.to_string(),
                kind: ResolverKind::Invalid,
            }
        }
    }
}

/// A DNS forwarder that routes queries to upstream resolvers based on
/// split-DNS suffix matching, with TCP fallback and DoH support.
pub struct Forwarder {
    /// Default upstream resolvers used only when no suffix route matches.
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

    /// Create a forwarder whose control-selected routes come exclusively from
    /// the resolver's live config snapshot. Capturing control defaults here
    /// would resurrect a removed root route after a later map update.
    pub fn from_dns_config(_dns_config: Option<&rustscale_tailcfg::DNSConfig>) -> Self {
        Self::new(Vec::new())
    }

    /// Forward using the configured default resolvers, followed by the base
    /// system resolvers. `family` is the transport used by the local client,
    /// either `"udp"` or `"tcp"`.
    pub async fn forward(&self, query: &[u8], _name: &str, family: &str) -> Option<Vec<u8>> {
        self.forward_with_resolvers(query, family, None).await
    }

    /// Forward using a route selected from the responder's live resolver
    /// snapshot.
    ///
    /// `Some(resolvers)` is authoritative: failures (and an explicitly empty
    /// route) do not leak to less-specific or system resolvers. `None` means
    /// that no route matched and enables the configured/system fallback.
    pub async fn forward_with_resolvers(
        &self,
        query: &[u8],
        family: &str,
        resolvers: Option<&[UpstreamResolver]>,
    ) -> Option<Vec<u8>> {
        let selected = resolvers.unwrap_or(&self.default_resolvers);
        for resolver in selected {
            if let Some(resp) = self.send(query, resolver, family).await {
                return Some(resp);
            }
        }

        if resolvers.is_some() {
            return None;
        }

        for server in &self.fallback {
            let resolver = UpstreamResolver {
                addr: server.to_string(),
                kind: ResolverKind::Udp(*server),
            };
            if let Some(resp) = self.send(query, &resolver, family).await {
                return Some(resp);
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
        let response = match &resolver.kind {
            ResolverKind::Doh { url, host } => self.send_doh(query, url, host).await.ok(),
            ResolverKind::Udp(addr) => self.send_classic(query, addr, family).await,
            ResolverKind::Invalid => None,
        }?;
        finish_response(query, response, family)
    }

    async fn send_classic(
        &self,
        query: &[u8],
        server: &SocketAddr,
        family: &str,
    ) -> Option<Vec<u8>> {
        let skip_tcp = rustscale_envknob::bool("TS_DNS_FORWARD_SKIP_TCP_RETRY").unwrap_or(false);

        // A TCP client can consume a full response, so match the upstream
        // resolver's immediate UDP/TCP race. A non-truncated UDP response may
        // still win; a truncated one waits for TCP and is retained only as a
        // last resort.
        if family == "tcp" && !skip_tcp {
            let udp = self.send_udp(query, server);
            let tcp = self.send_tcp(query, server);
            tokio::pin!(udp);
            tokio::pin!(tcp);
            return tokio::select! {
                udp_response = &mut udp => match udp_response {
                    Some(response) if !truncated_flag_set(&response) => Some(response),
                    Some(truncated) => tcp.await.or(Some(truncated)),
                    None => tcp.await,
                },
                tcp_response = &mut tcp => match tcp_response {
                    Some(response) => Some(response),
                    None => udp.await,
                },
            };
        }

        let udp_response = self.send_udp(query, server).await;
        if let Some(response) = udp_response {
            // UDP clients must receive TC and retry through the local TCP
            // listener rather than hiding an upstream truncation.
            if family == "udp" || !truncated_flag_set(&response) || skip_tcp {
                return Some(response);
            }
        }
        if skip_tcp {
            return None;
        }
        self.send_tcp(query, server).await
    }

    /// Send a DNS query over UDP. Returns `None` on failure.
    async fn send_udp(&self, query: &[u8], server: &SocketAddr) -> Option<Vec<u8>> {
        let bind = if server.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let sock = tokio::net::UdpSocket::bind(bind).await.ok()?;
        rustscale_netns::configure_udp_socket(&sock).ok()?;
        sock.connect(server).await.ok()?;
        sock.send(query).await.ok()?;

        let mut buf = vec![0u8; MAX_RESPONSE_BYTES + 1];
        let fut = tokio::time::timeout(UDP_TIMEOUT, sock.recv(&mut buf));
        match fut.await {
            Ok(Ok(n)) => {
                let truncated = n > MAX_RESPONSE_BYTES;
                let mut response = buf[..n.min(MAX_RESPONSE_BYTES)].to_vec();
                if truncated {
                    set_tc_flag(&mut response);
                }
                Some(response)
            }
            Ok(Err(error)) if packet_was_truncated(&error) => None,
            _ => None,
        }
    }

    /// Send a DNS query over TCP (with 2-byte length prefix).
    /// Ports Go's `sendTCP` (forwarder.go:928).
    async fn send_tcp(&self, query: &[u8], server: &SocketAddr) -> Option<Vec<u8>> {
        let query_len = u16::try_from(query.len()).ok()?;
        tokio::time::timeout(TCP_QUERY_TIMEOUT, async {
            let mut stream = rustscale_tsdial::system_dial("tcp", &server.to_string())
                .await
                .ok()?;
            let _ = stream.set_nodelay(true);

            // DNS over TCP: one 2-byte length prefix and one complete query.
            stream.write_all(&query_len.to_be_bytes()).await.ok()?;
            stream.write_all(query).await.ok()?;

            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await.ok()?;
            let response_len = usize::from(u16::from_be_bytes(len_buf));
            if response_len < HEADER_BYTES {
                return None;
            }

            let mut response = vec![0u8; response_len];
            stream.read_exact(&mut response).await.ok()?;
            Some(response)
        })
        .await
        .ok()?
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

        // Read a bounded HTTP response. A DNS/TCP message is at most 65535
        // bytes; the additional allowance covers ordinary HTTP headers.
        let mut buf = Vec::with_capacity(4096);
        let mut limited = tls.take(MAX_DOH_HTTP_BYTES + 1);
        limited.read_to_end(&mut buf).await?;
        if buf.len() as u64 > MAX_DOH_HTTP_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "DoH response exceeds limit",
            ));
        }

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
fn finish_response(query: &[u8], mut response: Vec<u8>, family: &str) -> Option<Vec<u8>> {
    if query.len() < 2 || response.len() < HEADER_BYTES || response.get(..2) != query.get(..2) {
        return None;
    }
    check_response_size_and_set_tc(&mut response, query, family);
    Some(response)
}

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
    fn malformed_resolver_does_not_redirect_to_public_dns() {
        let resolver = UpstreamResolver::from_addr("not a resolver");
        assert!(matches!(resolver.kind, ResolverKind::Invalid));
        assert_eq!(resolver.addr, "not a resolver");
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
        assert!(
            fwd.default_resolvers.is_empty(),
            "control defaults are selected from the live resolver snapshot"
        );
    }
}
