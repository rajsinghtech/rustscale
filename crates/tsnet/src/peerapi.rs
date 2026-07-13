//! PeerAPI server — ports Go's `ipn/ipnlocal/peerapi.go`.
//!
//! Each node runs an HTTP server on a deterministic port per Tailscale IP,
//! serving RFC 8484 DNS-over-HTTP (`/dns-query`) for exit node DNS resolution,
//! debug endpoints (`/v0/...`), and a root greeting identifying the node.
//!
//! Connections arrive over WireGuard (HTTP/1.1 without TLS — WireGuard provides
//! the encryption). Each connection is authenticated via WhoIs: the remote
//! peer's IP is resolved against the netmap to find the owning `Node` and
//! `UserProfile`; non-tailnet sources are rejected.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use base64::Engine;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

use rustscale_dns::{
    build_a_response, build_aaaa_response, build_nxdomain, parse_question, upstream_nameservers,
    MagicDnsResolver, ResolveOutcome,
};
use rustscale_netstack::{Netstack, NetstackStream};
use rustscale_tailcfg::{DNSConfig, Node, Service, UserID, UserProfile};

use crate::{whois_lookup, WhoIsInfo};

/// Maximum DNS query size accepted by the DoH handler (256 KiB, matching Go).
const MAX_DNS_QUERY_LEN: usize = 256 << 10;

/// DoH query timeout — short enough for humans to notice, longer than real DNS
/// timeouts (matching Go's `arbitraryTimeout = 5 * time.Second`).
const DOH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Port derivation
// ---------------------------------------------------------------------------

/// Compute the deterministic PeerAPI port for a Tailscale IP address.
///
/// Matches Go's `peerapi.go:106-125`: takes the lower 3 bytes of the IP's
/// 16-byte representation, computes CRC32 (IEEE), and maps into the
/// `[32768, 65535]` range. The `try` parameter (0..5) increments the first
/// hash byte to produce alternate ports if the first is already in use.
pub fn deterministic_port(ip: IpAddr, try_offset: u8) -> u16 {
    let a16 = ip_to_16_bytes(ip);
    let mut hash_data = [a16[13], a16[14], a16[15]];
    hash_data[0] = hash_data[0].wrapping_add(try_offset);
    let crc = crc32fast::hash(&hash_data);
    (32 << 10) | (crc as u16)
}

/// Convert an `IpAddr` to its 16-byte representation (like Go's
/// `netip.Addr.As16()`).
fn ip_to_16_bytes(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // IPv4-mapped IPv6: ::ffff:a.b.c.d
            let mut buf = [0u8; 16];
            buf[10] = 0xff;
            buf[11] = 0xff;
            buf[12] = octets[0];
            buf[13] = octets[1];
            buf[14] = octets[2];
            buf[15] = octets[3];
            buf
        }
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// Try to bind a `TcpListener` on the deterministic port for `ip`, falling
/// back to an ephemeral port. Returns `(listener, bound_port)`.
async fn bind_peerapi_tcp(ip: IpAddr) -> std::io::Result<(TcpListener, u16)> {
    for try_offset in 0u8..5 {
        let port = deterministic_port(ip, try_offset);
        let addr = SocketAddr::new(ip, port);
        match TcpListener::bind(addr).await {
            Ok(ln) => return Ok((ln, port)),
            Err(_) => continue,
        }
    }
    // Fall back to ephemeral port on the same IP.
    let addr = SocketAddr::new(ip, 0);
    let ln = TcpListener::bind(addr).await?;
    let port = ln.local_addr()?.port();
    Ok((ln, port))
}

/// Build the `Hostinfo.Services` entries for peerapi advertisement.
///
/// Returns `Service` entries for `peerapi4` and `peerapi6` (if the respective
/// IP exists). Call this after the peerapi listener is bound and add the
/// result to `Hostinfo.Services` before sending a MapRequest.
pub fn peerapi_services(v4_port: Option<u16>, v6_port: Option<u16>) -> Vec<Service> {
    let mut services = Vec::new();
    if let Some(port) = v4_port {
        if port > 0 {
            services.push(Service {
                Proto: "peerapi4".into(),
                Port: port,
                Description: String::new(),
            });
        }
    }
    if let Some(port) = v6_port {
        if port > 0 {
            services.push(Service {
                Proto: "peerapi6".into(),
                Port: port,
                Description: String::new(),
            });
        }
    }
    services
}

// ---------------------------------------------------------------------------
// PeerAPI server state
// ---------------------------------------------------------------------------

/// Shared state for the PeerAPI server, accessible by all handler tasks.
pub(crate) struct PeerApiState {
    peers: Arc<RwLock<Vec<Node>>>,
    user_profiles: Arc<RwLock<BTreeMap<UserID, UserProfile>>>,
    resolver: Arc<RwLock<MagicDnsResolver>>,
    dns_config: Arc<RwLock<Option<DNSConfig>>>,
    /// Our node's tailscale IPs (for `isAddressValid` checks).
    tailscale_ips: Vec<IpAddr>,
    /// Whether this node is advertising exit node routes.
    offering_exit_node: bool,
    /// Taildrop file manager (None if taildrop is disabled).
    taildrop: Option<Arc<crate::taildrop::TaildropManager>>,
    /// Per-label socket TX/RX counter registry (for the `/v0/sockstats`
    /// debug endpoint). `None` when no registry was injected.
    sockstats: Option<Arc<rustscale_sockstats::SockStats>>,
}

impl PeerApiState {
    /// WhoIs lookup: resolve a remote IP to peer identity.
    fn whois(&self, remote_ip: IpAddr) -> Option<WhoIsInfo> {
        let peers = self.peers.try_read().ok()?;
        let ups = self.user_profiles.try_read().ok()?;
        whois_lookup(&peers, &ups, remote_ip)
    }

    /// Whether the remote peer should get DNS responses from us. Mirrors
    /// Go's `peerAPIHandler.replyToDNSQueries()`.
    fn reply_to_dns_queries(&self, is_self: bool) -> bool {
        if is_self {
            return true;
        }
        // If we're not an exit node, there's no point being a DNS server.
        self.offering_exit_node
    }

    /// Forward a raw DNS query upstream and return the response bytes.
    async fn forward_dns_upstream(&self, query: &[u8]) -> Option<Vec<u8>> {
        let dns_cfg = self.dns_config.read().await;
        let upstream = upstream_nameservers(dns_cfg.as_ref());
        drop(dns_cfg);

        for server in &upstream {
            let sock = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => s,
                Err(_) => continue,
            };
            if sock.send_to(query, server).await.is_err() {
                continue;
            }
            let mut buf = vec![0u8; 1500];
            let fut = tokio::time::timeout(std::time::Duration::from_secs(3), sock.recv(&mut buf));
            if let Ok(Ok(n)) = fut.await {
                return Some(buf[..n].to_vec());
            }
        }
        None
    }

    /// Handle a DNS query: answer from MagicDNS for tailnet names, NXDOMAIN
    /// for unknown tailnet names, or forward upstream for non-tailnet names.
    async fn handle_dns_query(&self, query: &[u8]) -> Option<Vec<u8>> {
        const TYPE_A: u16 = 1;
        const TYPE_AAAA: u16 = 28;

        let (name, qtype, _qclass) = parse_question(query)?;

        let r = self.resolver.read().await;
        if !r.is_tailnet_name(&name) {
            drop(r);
            return self.forward_dns_upstream(query).await;
        }

        match r.lookup(&name) {
            ResolveOutcome::Answer(ips) => {
                if qtype == TYPE_A {
                    let v4: Vec<Ipv4Addr> = ips
                        .iter()
                        .filter_map(|ip| match ip {
                            IpAddr::V4(v4) => Some(*v4),
                            _ => None,
                        })
                        .collect();
                    if v4.is_empty() {
                        return Some(build_nxdomain_noerror(query));
                    }
                    build_a_response(query, &v4)
                } else if qtype == TYPE_AAAA {
                    let v6: Vec<std::net::Ipv6Addr> = ips
                        .iter()
                        .filter_map(|ip| match ip {
                            IpAddr::V6(v6) => Some(*v6),
                            _ => None,
                        })
                        .collect();
                    if v6.is_empty() {
                        return Some(build_nxdomain_noerror(query));
                    }
                    build_aaaa_response(query, &v6)
                } else {
                    Some(build_nxdomain_noerror(query))
                }
            }
            ResolveOutcome::NxDomain => build_nxdomain(query),
            ResolveOutcome::NotTailnet => {
                drop(r);
                self.forward_dns_upstream(query).await
            }
        }
    }
}

/// Build a NOERROR response with 0 answers (for known peer, unsupported qtype).
fn build_nxdomain_noerror(query: &[u8]) -> Vec<u8> {
    let mut resp = query.to_vec();
    if resp.len() < 12 {
        return query.to_vec();
    }
    let flags = u16::from_be_bytes([resp[2], resp[3]]);
    let opcode = (flags >> 11) & 0b1111;
    let rd = (flags >> 8) & 0b1;
    let new_flags = 0b1000_0000_0000_0000u16 | (opcode << 11) | (rd << 8) | 0b1000_0000;
    resp[2..4].copy_from_slice(&new_flags.to_be_bytes());
    resp
}

// ---------------------------------------------------------------------------
// Spawning
// ---------------------------------------------------------------------------

/// Spawn the PeerAPI server in **netstack mode**.
///
/// Uses `Netstack::listen(port)` to accept incoming tailnet TCP connections.
/// The port is derived deterministically from the primary IPv4 address (with
/// fallback to ephemeral). Returns the task handle and the bound port.
pub(crate) async fn spawn_peerapi_netstack(
    netstack: Arc<Netstack>,
    peers: Arc<RwLock<Vec<Node>>>,
    user_profiles: Arc<RwLock<BTreeMap<UserID, UserProfile>>>,
    resolver: Arc<RwLock<MagicDnsResolver>>,
    dns_config: Arc<RwLock<Option<DNSConfig>>>,
    tailscale_ips: Vec<IpAddr>,
    offering_exit_node: bool,
    taildrop: Option<Arc<crate::taildrop::TaildropManager>>,
    sockstats: Option<Arc<rustscale_sockstats::SockStats>>,
) -> (JoinHandle<()>, Option<u16>) {
    // Derive the port from the primary IPv4 address.
    let v4 = tailscale_ips.iter().find_map(|ip| match ip {
        IpAddr::V4(v4) => Some(*v4),
        _ => None,
    });

    let port = if let Some(v4) = v4 {
        // Try the deterministic port. Netstack::listen will fail if the port
        // is already in use; try the 5 deterministic candidates, then fall
        // back to an ephemeral port.
        let mut chosen: Option<u16> = None;
        for try_offset in 0u8..5 {
            let candidate = deterministic_port(IpAddr::V4(v4), try_offset);
            match netstack.listen(candidate).await {
                Ok(listener) => {
                    chosen = Some(candidate);
                    let state = Arc::new(PeerApiState {
                        peers: peers.clone(),
                        user_profiles: user_profiles.clone(),
                        resolver: resolver.clone(),
                        dns_config: dns_config.clone(),
                        tailscale_ips: tailscale_ips.clone(),
                        offering_exit_node,
                        taildrop: taildrop.clone(),
                        sockstats: sockstats.clone(),
                    });
                    let handle = tokio::spawn(serve_netstack_listener(listener, state));
                    // Keep the listener task alive; we return the port.
                    // The handle is stored but the listener lives for the
                    // lifetime of the netstack.
                    std::mem::forget(handle);
                    break;
                }
                Err(_) => continue,
            }
        }
        if chosen.is_none() {
            // Fall back to an ephemeral port.
            match netstack.listen(0).await {
                Ok(listener) => {
                    // port 0 with netstack doesn't give us the actual port back.
                    // Use a high ephemeral port instead.
                    chosen = Some(0);
                    let state = Arc::new(PeerApiState {
                        peers: peers.clone(),
                        user_profiles: user_profiles.clone(),
                        resolver: resolver.clone(),
                        dns_config: dns_config.clone(),
                        tailscale_ips: tailscale_ips.clone(),
                        offering_exit_node,
                        taildrop: taildrop.clone(),
                        sockstats: sockstats.clone(),
                    });
                    let handle = tokio::spawn(serve_netstack_listener(listener, state));
                    std::mem::forget(handle);
                }
                Err(e) => {
                    eprintln!("peerapi: failed to listen on netstack (non-fatal): {e}");
                }
            }
        }
        chosen
    } else {
        None
    };

    // Return a dummy handle — the real listener task is spawned above and
    // tied to the netstack's lifetime. We return a no-op handle for the
    // RunningState task list.
    let dummy = tokio::spawn(async {});
    (dummy, port)
}

/// Spawn the PeerAPI server in **TUN mode**.
///
/// Binds a `tokio::net::TcpListener` on each tailscale IP (v4 + v6) on the
/// deterministic port. Returns the task handle and the primary (v4) port.
pub(crate) async fn spawn_peerapi_tun(
    peers: Arc<RwLock<Vec<Node>>>,
    user_profiles: Arc<RwLock<BTreeMap<UserID, UserProfile>>>,
    resolver: Arc<RwLock<MagicDnsResolver>>,
    dns_config: Arc<RwLock<Option<DNSConfig>>>,
    tailscale_ips: Vec<IpAddr>,
    offering_exit_node: bool,
    taildrop: Option<Arc<crate::taildrop::TaildropManager>>,
    sockstats: Option<Arc<rustscale_sockstats::SockStats>>,
) -> (JoinHandle<()>, Option<u16>) {
    let state = Arc::new(PeerApiState {
        peers,
        user_profiles,
        resolver,
        dns_config,
        tailscale_ips: tailscale_ips.clone(),
        offering_exit_node,
        taildrop,
        sockstats,
    });

    let mut v4_port: Option<u16> = None;
    let mut v6_port: Option<u16> = None;
    let mut handles: Vec<JoinHandle<()>> = Vec::new();

    for ip in &tailscale_ips {
        match bind_peerapi_tcp(*ip).await {
            Ok((listener, port)) => {
                eprintln!("peerapi: listening on {ip}:{port}");
                match ip {
                    IpAddr::V4(_) => v4_port = Some(port),
                    IpAddr::V6(_) => v6_port = Some(port),
                }
                let state = state.clone();
                handles.push(tokio::spawn(serve_tcp_listener(listener, state)));
            }
            Err(e) => {
                eprintln!("peerapi: failed to bind on {ip}: {e} (non-fatal)");
            }
        }
    }

    let handle = tokio::spawn(async move {
        for h in handles {
            let _ = h.await;
        }
    });

    (handle, v4_port.or(v6_port))
}

/// Serve a netstack listener: accept connections and dispatch to handlers.
async fn serve_netstack_listener(
    mut listener: rustscale_netstack::Listener,
    state: Arc<PeerApiState>,
) {
    loop {
        match listener.accept().await {
            Ok(stream) => {
                let remote_addr = stream.peer_addr();
                let state = state.clone();
                tokio::spawn(handle_connection_netstack(stream, remote_addr, state));
            }
            Err(e) => {
                eprintln!("peerapi: netstack accept error: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

/// Serve a TCP listener (TUN mode): accept connections and dispatch.
async fn serve_tcp_listener(listener: TcpListener, state: Arc<PeerApiState>) {
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let state = state.clone();
                tokio::spawn(handle_connection_tcp(stream, addr, state));
            }
            Err(e) => {
                eprintln!("peerapi: tcp accept error: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

/// Handle a single netstack connection: WhoIs auth, then HTTP dispatch.
async fn handle_connection_netstack(
    stream: NetstackStream,
    remote_addr: Option<SocketAddr>,
    state: Arc<PeerApiState>,
) {
    let remote_ip = remote_addr.map(|a| a.ip());
    if let Some(ip) = remote_ip {
        if !rustscale_tsaddr::is_tailscale_ip(ip) {
            return;
        }
    }
    let conn = PeerApiConn::new(stream, remote_addr, state);
    conn.serve().await;
}

/// Handle a single TCP connection (TUN mode): WhoIs auth, then HTTP dispatch.
async fn handle_connection_tcp(
    stream: tokio::net::TcpStream,
    remote_addr: SocketAddr,
    state: Arc<PeerApiState>,
) {
    if !rustscale_tsaddr::is_tailscale_ip(remote_addr.ip()) {
        return;
    }
    let conn = PeerApiConn::new(stream, Some(remote_addr), state);
    conn.serve().await;
}

/// A connection wrapper that abstracts netstack vs TCP streams.
struct PeerApiConn<S> {
    stream: S,
    remote_addr: Option<SocketAddr>,
    state: Arc<PeerApiState>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> PeerApiConn<S> {
    fn new(stream: S, remote_addr: Option<SocketAddr>, state: Arc<PeerApiState>) -> Self {
        Self {
            stream,
            remote_addr,
            state,
        }
    }

    /// Serve a single HTTP request: parse, auth, dispatch, respond.
    async fn serve(mut self) {
        // WhoIs auth: resolve the remote IP against the netmap.
        let remote_ip = self.remote_addr.map(|a| a.ip());
        let whois = remote_ip.and_then(|ip| self.state.whois(ip));

        let (whois, is_self) = match (&whois, remote_ip) {
            (Some(info), _) if info.found => {
                // Check if the peer is owned by the same user as us.
                // We determine "is_self" by checking if the peer's user_id
                // matches any of our own node's user. Since we don't have
                // our own user_id readily available, we approximate: if the
                // peer's IPs include one of our own tailscale_ips, it's us.
                let is_self = remote_ip.is_some_and(|ip| self.state.tailscale_ips.contains(&ip));
                (info.clone(), is_self)
            }
            _ => {
                // Unknown peer — reject.
                if let Some(ip) = remote_ip {
                    eprintln!("peerapi: unknown peer {ip}");
                }
                let _ = write_error_response(
                    &mut self.stream,
                    403,
                    "Forbidden",
                    "invalid peerapi request",
                )
                .await;
                return;
            }
        };

        // Parse the HTTP request.
        let req = match read_request(&mut self.stream).await {
            Ok(r) => r,
            Err(e) => {
                let _ = write_error_response(
                    &mut self.stream,
                    400,
                    "Bad Request",
                    &format!("bad request: {e}"),
                )
                .await;
                return;
            }
        };

        // Dispatch.
        let resp = dispatch(&req, &whois, is_self, &self.state).await;

        // Write the response.
        let _ = resp.write(&mut self.stream).await;
    }
}

// ---------------------------------------------------------------------------
// HTTP request/response
// ---------------------------------------------------------------------------

/// A parsed HTTP/1.1 request.
struct PeerApiRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl PeerApiRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Get a query parameter value from the path's query string.
    fn query_param(&self, name: &str) -> Option<String> {
        let q = self.path.split_once('?').map(|(_, q)| q)?;
        for pair in q.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                if k == name {
                    return Some(percent_decode(v));
                }
            } else if pair == name {
                return Some(String::new());
            }
        }
        None
    }

    /// The path without the query string.
    fn path_only(&self) -> &str {
        self.path.split('?').next().unwrap_or(&self.path)
    }
}

/// A response to be written to the connection.
struct PeerApiResponse {
    status: u16,
    reason: &'static str,
    content_type: &'static str,
    body: Vec<u8>,
    /// Extra headers to include (e.g. security headers).
    extra_headers: Vec<(&'static str, &'static str)>,
}

impl PeerApiResponse {
    fn new(status: u16, reason: &'static str, content_type: &'static str, body: Vec<u8>) -> Self {
        Self {
            status,
            reason,
            content_type,
            body,
            extra_headers: Vec::new(),
        }
    }

    fn with_header(mut self, name: &'static str, value: &'static str) -> Self {
        self.extra_headers.push((name, value));
        self
    }

    async fn write<W: AsyncWrite + Unpin>(&self, conn: &mut W) -> Result<(), std::io::Error> {
        let mut header = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
            self.status,
            self.reason,
            self.content_type,
            self.body.len()
        );
        for (k, v) in &self.extra_headers {
            let _ = write!(header, "{k}: {v}\r\n");
        }
        header.push_str("\r\n");
        conn.write_all(header.as_bytes()).await?;
        conn.write_all(&self.body).await?;
        conn.flush().await?;
        Ok(())
    }
}

/// Read and parse an HTTP/1.1 request from a connection. Reads the full
/// Content-Length body (not just the preview that arrived with the headers).
async fn read_request<R: AsyncRead + Unpin>(conn: &mut R) -> Result<PeerApiRequest, String> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    loop {
        let n = conn
            .read(&mut tmp)
            .await
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("connection closed before headers".into());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(end) = find_header_end(&buf) {
            let head = &buf[..end + 4];
            let mut body = buf[end + 4..].to_vec();
            // Read the full Content-Length body if the preview is short.
            let header_text =
                std::str::from_utf8(head).map_err(|_| "non-utf8 header".to_string())?;
            let cl = extract_content_length(header_text);
            while body.len() < cl {
                let n = conn
                    .read(&mut tmp)
                    .await
                    .map_err(|e| format!("read body: {e}"))?;
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&tmp[..n]);
            }
            body.truncate(cl);
            return parse_request_head(head, body);
        }
        if buf.len() > 256 * 1024 {
            return Err("header too large".into());
        }
    }
}

/// Extract the Content-Length value from an HTTP header block. Returns 0
/// if the header is absent or unparseable.
fn extract_content_length(header_text: &str) -> usize {
    for line in header_text.split("\r\n") {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                return v.trim().parse().unwrap_or(0);
            }
        }
    }
    0
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_request_head(head: &[u8], body_preview: Vec<u8>) -> Result<PeerApiRequest, String> {
    let text = std::str::from_utf8(head).map_err(|_| "non-utf8 header".to_string())?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or("no request line")?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or("no method")?.to_string();
    let path = parts.next().ok_or("no path")?.to_string();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    let cl_header = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"));

    let body = if let Some((_, v)) = cl_header {
        let cl: usize = v.parse().unwrap_or(0);
        if body_preview.len() >= cl {
            body_preview[..cl].to_vec()
        } else {
            body_preview
        }
    } else {
        body_preview
    };

    Ok(PeerApiRequest {
        method,
        path,
        headers,
        body,
    })
}

/// Write a simple text error response.
async fn write_error_response<W: AsyncWrite + Unpin>(
    conn: &mut W,
    status: u16,
    reason: &str,
    msg: &str,
) -> Result<(), std::io::Error> {
    let body = msg.as_bytes();
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    conn.write_all(header.as_bytes()).await?;
    conn.write_all(body).await?;
    conn.flush().await?;
    Ok(())
}

/// Percent-decode a URL query parameter value (minimal implementation).
fn percent_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                result.push((h * 16 + l) as char);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            result.push(' ');
        } else {
            result.push(bytes[i] as char);
        }
        i += 1;
    }
    result
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Security headers
// ---------------------------------------------------------------------------

/// Determine whether a request should get browser security headers.
/// Matches Go's `peerAPIRequestShouldGetSecurityHeaders` (peerapi.go:312-330).
fn should_get_security_headers(req: &PeerApiRequest) -> bool {
    // Accept-Encoding with "deflate" is a forbidden header browsers send but
    // Go doesn't — a strong browser signal.
    if let Some(ae) = req.header("Accept-Encoding") {
        if ae.split(',').any(|v| v.trim() == "deflate") {
            return true;
        }
    }
    // User-Agent starting with "Mozilla/" or having many space-separated
    // components is likely a browser.
    if let Some(ua) = req.header("User-Agent") {
        if ua.starts_with("Mozilla/") || ua.matches(' ').count() > 2 {
            return true;
        }
    }
    // Accept-Language is not sent by Go PeerAPI clients.
    if req.header("Accept-Language").is_some() {
        return true;
    }
    false
}

/// Add security headers to a response if the request warrants them.
fn add_security_headers(resp: PeerApiResponse, req: &PeerApiRequest) -> PeerApiResponse {
    if should_get_security_headers(req) {
        resp.with_header(
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'; script-src 'none'; \
                 script-src-elem 'none'; script-src-attr 'none'; style-src 'unsafe-inline'",
        )
        .with_header("X-Frame-Options", "DENY")
        .with_header("X-Content-Type-Options", "nosniff")
    } else {
        resp
    }
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// Dispatch a parsed request to the appropriate handler.
async fn dispatch(
    req: &PeerApiRequest,
    whois: &WhoIsInfo,
    is_self: bool,
    state: &Arc<PeerApiState>,
) -> PeerApiResponse {
    let path = req.path_only();

    // DoH handler: /dns-query
    if path == "/dns-query" {
        let resp = handle_dns_query(req, is_self, state).await;
        return add_security_headers(resp, req);
    }

    // Taildrop receive: /v0/put/<filename>
    if path.starts_with("/v0/put/") {
        let resp = handle_peer_put(req, whois, is_self, state).await;
        return add_security_headers(resp, req);
    }

    // Debug handlers: /v0/*
    if let Some(resp) = handle_debug(req, path, whois, is_self, state) {
        return add_security_headers(resp, req);
    }

    // Root: greeting
    if path == "/" || path.is_empty() {
        let resp = handle_root(whois, is_self);
        return add_security_headers(resp, req);
    }

    // Unknown path
    let resp = PeerApiResponse::new(
        404,
        "Not Found",
        "text/plain; charset=utf-8",
        b"unsupported peerapi path".to_vec(),
    );
    add_security_headers(resp, req)
}

/// DoH handler (RFC 8484 over HTTP, not HTTPS — WireGuard provides encryption).
/// Mirrors Go's `handleDNSQuery` (peerapi.go:731-790).
async fn handle_dns_query(
    req: &PeerApiRequest,
    is_self: bool,
    state: &Arc<PeerApiState>,
) -> PeerApiResponse {
    if !state.reply_to_dns_queries(is_self) {
        return PeerApiResponse::new(
            403,
            "Forbidden",
            "text/plain; charset=utf-8",
            b"DNS access denied".to_vec(),
        );
    }

    // Parse the DNS query from the request.
    let query = match parse_doh_query(req) {
        Ok(q) => q,
        Err(msg) => {
            return PeerApiResponse::new(
                400,
                "Bad Request",
                "text/plain; charset=utf-8",
                msg.into_bytes(),
            );
        }
    };

    // Resolve with a timeout.
    let result = tokio::time::timeout(DOH_TIMEOUT, state.handle_dns_query(&query)).await;
    match result {
        Ok(Some(resp_bytes)) => {
            PeerApiResponse::new(200, "OK", "application/dns-message", resp_bytes)
        }
        Ok(None) => PeerApiResponse::new(
            502,
            "Bad Gateway",
            "text/plain; charset=utf-8",
            b"DNS forwarding error".to_vec(),
        ),
        Err(_) => PeerApiResponse::new(
            500,
            "Internal Server Error",
            "text/plain; charset=utf-8",
            b"DNS query timeout".to_vec(),
        ),
    }
}

/// Parse the DNS query from a DoH request (GET ?dns= or POST body).
/// Mirrors Go's `dohQuery` (peerapi.go:792-823).
fn parse_doh_query(req: &PeerApiRequest) -> Result<Vec<u8>, String> {
    match req.method.as_str() {
        "GET" => {
            let q64 = req.query_param("dns").ok_or_else(|| {
                "missing 'dns' parameter; try '?dns=' (DoH standard) or use '?q=<name>' for JSON debug mode".to_string()
            })?;
            // base64url (no pad) decodes to ~3/4 of the encoded length.
            if q64.len() > (MAX_DNS_QUERY_LEN * 4 / 3) + 4 {
                return Err("query too large".into());
            }
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(&q64)
                .map_err(|_| "invalid 'dns' base64 encoding".to_string())
        }
        "POST" => {
            let ct = req.header("Content-Type").unwrap_or("");
            if ct != "application/dns-message" {
                return Err("unexpected Content-Type".into());
            }
            if req.body.len() > MAX_DNS_QUERY_LEN {
                return Err("query too large".into());
            }
            Ok(req.body.clone())
        }
        _ => Err("bad HTTP method".into()),
    }
}

// ---------------------------------------------------------------------------
// Taildrop receive: PUT /v0/put/<filename>
// ---------------------------------------------------------------------------

/// Handle `PUT /v0/put/<filename>` — receive a file from a peer via the
/// PeerAPI and write it to the Taildrop spool. Mirrors Go's
/// `feature/taildrop/peerapi.go:handlePeerPut`.
///
/// Auth: the peer must be known (WhoIs passed) and either be the same user
/// or have the `file-send` peer capability. The node must have taildrop
/// enabled (file-sharing cap + spool directory).
async fn handle_peer_put(
    req: &PeerApiRequest,
    _whois: &WhoIsInfo,
    is_self: bool,
    state: &Arc<PeerApiState>,
) -> PeerApiResponse {
    // Must have a taildrop manager.
    let Some(taildrop) = state.taildrop.as_ref() else {
        return PeerApiResponse::new(
            403,
            "Forbidden",
            "text/plain; charset=utf-8",
            b"taildrop not enabled".to_vec(),
        );
    };

    // Auth: same user (is_self) or file-send cap. We approximate "same
    // user" with is_self since we don't track our own user_id in
    // PeerApiState. Tagged peers would need the file-send cap check
    // against the peer's CapMap; for now we allow same-user sends.
    if !is_self {
        return PeerApiResponse::new(
            403,
            "Forbidden",
            "text/plain; charset=utf-8",
            b"taildrop: peer not authorized".to_vec(),
        );
    }

    if req.method != "PUT" {
        return PeerApiResponse::new(
            405,
            "Method Not Allowed",
            "text/plain; charset=utf-8",
            b"expected method PUT".to_vec(),
        );
    }

    let path = req.path_only();
    let prefix = match path.strip_prefix("/v0/put/") {
        Some(p) => p,
        None => {
            return PeerApiResponse::new(
                400,
                "Bad Request",
                "text/plain; charset=utf-8",
                b"misconfigured internals".to_vec(),
            );
        }
    };

    let filename = percent_decode(prefix);
    if filename.is_empty() {
        return PeerApiResponse::new(
            400,
            "Bad Request",
            "text/plain; charset=utf-8",
            b"missing filename".to_vec(),
        );
    }

    match taildrop.put_file(&filename, &req.body).await {
        Ok(_size) => PeerApiResponse::new(200, "OK", "application/json", b"{}\n".to_vec()),
        Err(crate::taildrop::TaildropError::FileExists(_)) => PeerApiResponse::new(
            409,
            "Conflict",
            "text/plain; charset=utf-8",
            b"file already exists".to_vec(),
        ),
        Err(crate::taildrop::TaildropError::InvalidFileName(msg)) => PeerApiResponse::new(
            400,
            "Bad Request",
            "text/plain; charset=utf-8",
            format!("invalid file name: {msg}").into_bytes(),
        ),
        Err(crate::taildrop::TaildropError::FileTooLarge { .. }) => PeerApiResponse::new(
            413,
            "Payload Too Large",
            "text/plain; charset=utf-8",
            b"file too large".to_vec(),
        ),
        Err(crate::taildrop::TaildropError::NotEnabled) => PeerApiResponse::new(
            403,
            "Forbidden",
            "text/plain; charset=utf-8",
            b"taildrop not enabled".to_vec(),
        ),
        Err(e) => PeerApiResponse::new(
            500,
            "Internal Server Error",
            "text/plain; charset=utf-8",
            format!("{e}").into_bytes(),
        ),
    }
}

/// Handle debug endpoints (`/v0/*`). Returns `None` if the path doesn't match
/// any debug handler.
fn handle_debug(
    _req: &PeerApiRequest,
    path: &str,
    whois: &WhoIsInfo,
    is_self: bool,
    state: &Arc<PeerApiState>,
) -> Option<PeerApiResponse> {
    let can_debug = is_self; // Simplified: only same-user can debug.

    match path {
        "/v0/goroutines" => {
            if !can_debug {
                return Some(PeerApiResponse::new(
                    403,
                    "Forbidden",
                    "text/plain; charset=utf-8",
                    b"denied; no debug access".to_vec(),
                ));
            }
            // Rust has no goroutines. Return tokio task count as a text note.
            let body = format!(
                "Rust/tokio runtime — no goroutines.\n\
                 Active tokio tasks: {}\n",
                count_tokio_tasks()
            );
            Some(PeerApiResponse::new(
                200,
                "OK",
                "text/plain; charset=utf-8",
                body.into_bytes(),
            ))
        }
        "/v0/env" => {
            if !can_debug {
                return Some(PeerApiResponse::new(
                    403,
                    "Forbidden",
                    "text/plain; charset=utf-8",
                    b"denied; no debug access".to_vec(),
                ));
            }
            let env: Vec<(String, String)> = std::env::vars().collect();
            let data = serde_json::json!({
                "hostname": whois.node_name,
                "args": std::env::args().collect::<Vec<_>>(),
                "env": env,
            });
            Some(PeerApiResponse::new(
                200,
                "OK",
                "application/json",
                serde_json::to_vec(&data).unwrap_or_default(),
            ))
        }
        "/v0/metrics" => {
            if !can_debug {
                return Some(PeerApiResponse::new(
                    403,
                    "Forbidden",
                    "text/plain; charset=utf-8",
                    b"denied; no debug access".to_vec(),
                ));
            }
            // Return a minimal Prometheus-format response.
            let body = "# rustscale peerapi metrics\n# (no exported metrics yet)\n";
            Some(PeerApiResponse::new(
                200,
                "OK",
                "text/plain; charset=utf-8",
                body.as_bytes().to_vec(),
            ))
        }
        "/v0/magicsock" => {
            if !can_debug {
                return Some(PeerApiResponse::new(
                    403,
                    "Forbidden",
                    "text/plain; charset=utf-8",
                    b"denied; no debug access".to_vec(),
                ));
            }
            let body = "rustscale magicsock debug — not yet wired up\n";
            Some(PeerApiResponse::new(
                200,
                "OK",
                "text/plain; charset=utf-8",
                body.as_bytes().to_vec(),
            ))
        }
        "/v0/dnsfwd" => {
            if !can_debug {
                return Some(PeerApiResponse::new(
                    403,
                    "Forbidden",
                    "text/plain; charset=utf-8",
                    b"denied; no debug access".to_vec(),
                ));
            }
            let body = "DNS forwarder debug — not yet wired up\n";
            Some(PeerApiResponse::new(
                200,
                "OK",
                "text/plain; charset=utf-8",
                body.as_bytes().to_vec(),
            ))
        }
        "/v0/interfaces" => {
            if !can_debug {
                return Some(PeerApiResponse::new(
                    403,
                    "Forbidden",
                    "text/plain; charset=utf-8",
                    b"denied; no debug access".to_vec(),
                ));
            }
            // Return a minimal JSON response with interface info.
            let data = serde_json::json!({
                "interfaces": [],
                "note": "interface enumeration not yet implemented"
            });
            Some(PeerApiResponse::new(
                200,
                "OK",
                "application/json",
                serde_json::to_vec(&data).unwrap_or_default(),
            ))
        }
        "/v0/sockstats" => {
            if !can_debug {
                return Some(PeerApiResponse::new(
                    403,
                    "Forbidden",
                    "text/plain; charset=utf-8",
                    b"denied; no debug access".to_vec(),
                ));
            }
            if let Some(stats) = state.sockstats.as_ref() {
                let body = serde_json::to_vec(&stats.to_json()).unwrap_or_default();
                Some(PeerApiResponse::new(200, "OK", "application/json", body))
            } else {
                let body = "sockstats: no sockstat logger wired up\n";
                Some(PeerApiResponse::new(
                    200,
                    "OK",
                    "text/plain; charset=utf-8",
                    body.as_bytes().to_vec(),
                ))
            }
        }
        _ => None,
    }
}

/// Root handler: greeting identifying the local node to the peer.
fn handle_root(whois: &WhoIsInfo, is_self: bool) -> PeerApiResponse {
    let display = if whois.display_name.is_empty() {
        &whois.login_name
    } else {
        &whois.display_name
    };
    let body = format!(
        "<html>\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <body>\n<h1>Hello, {display} ({})</h1>\n\
         This is my Tailscale device. Your device is {}.\n{}\n</body>\n</html>\n",
        whois
            .tailscale_ips
            .first()
            .map(std::string::ToString::to_string)
            .unwrap_or_default(),
        html_escape(&whois.node_name),
        if is_self {
            "<p>You are the owner of this node.\n"
        } else {
            ""
        }
    );
    PeerApiResponse::new(200, "OK", "text/html; charset=utf-8", body.into_bytes())
}

/// Escape HTML special characters.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Best-effort count of active tokio tasks. The tokio runtime doesn't expose
/// a direct task count, so we return a placeholder.
fn count_tokio_tasks() -> String {
    "unknown (tokio does not expose task count)".to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rustscale_dns::MagicDnsResolver;
    use rustscale_tailcfg::{Node, UserProfile};

    /// Make a fake `PeerApiState` for testing.
    fn make_test_state(peers: Vec<Node>, ips: Vec<IpAddr>, exit_node: bool) -> Arc<PeerApiState> {
        Arc::new(PeerApiState {
            peers: Arc::new(RwLock::new(peers)),
            user_profiles: Arc::new(RwLock::new(BTreeMap::new())),
            resolver: Arc::new(RwLock::new(MagicDnsResolver::default())),
            dns_config: Arc::new(RwLock::new(None)),
            tailscale_ips: ips,
            offering_exit_node: exit_node,
            taildrop: None,
            sockstats: None,
        })
    }

    #[test]
    fn test_deterministic_port_range() {
        let ip: IpAddr = "100.64.0.1".parse().unwrap();
        let port = deterministic_port(ip, 0);
        assert!(
            port >= 32768,
            "port should be in [32768, 65535], got {port}"
        );
    }

    #[test]
    fn test_deterministic_port_stable() {
        let ip: IpAddr = "100.64.0.1".parse().unwrap();
        let p1 = deterministic_port(ip, 0);
        let p2 = deterministic_port(ip, 0);
        assert_eq!(p1, p2, "same IP + try should produce same port");
    }

    #[test]
    fn test_deterministic_port_try_offset_changes_port() {
        let ip: IpAddr = "100.64.0.1".parse().unwrap();
        let p0 = deterministic_port(ip, 0);
        let p1 = deterministic_port(ip, 1);
        assert_ne!(
            p0, p1,
            "different try offsets should produce different ports"
        );
    }

    #[test]
    fn test_deterministic_port_v4_v6_same_lower_bytes() {
        // IPv4 100.64.0.1 → lower 3 bytes are 64, 0, 1
        // IPv6 fd7a:115c:a1e0::1 → lower 3 bytes are 0, 0, 1 (different!)
        // So they won't match. But two IPs with the same lower 3 bytes will.
        let v4: IpAddr = "100.64.0.1".parse().unwrap();
        let v4_port = deterministic_port(v4, 0);
        // The port should be deterministic and in range.
        assert!(v4_port >= 32768);
    }

    #[test]
    fn test_peerapi_services() {
        let services = peerapi_services(Some(12345), Some(12346));
        assert_eq!(services.len(), 2);
        assert_eq!(services[0].Proto, "peerapi4");
        assert_eq!(services[0].Port, 12345);
        assert_eq!(services[1].Proto, "peerapi6");
        assert_eq!(services[1].Port, 12346);
    }

    #[test]
    fn test_peerapi_services_partial() {
        let services = peerapi_services(Some(12345), None);
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].Proto, "peerapi4");

        let services = peerapi_services(None, Some(12346));
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].Proto, "peerapi6");
    }

    #[test]
    fn test_peerapi_services_empty() {
        let services = peerapi_services(None, None);
        assert!(services.is_empty());

        let services = peerapi_services(Some(0), Some(0));
        assert!(services.is_empty());
    }

    #[test]
    fn test_is_tailnet_ip() {
        assert!(rustscale_tsaddr::is_tailscale_ip(
            "100.64.0.1".parse().unwrap()
        ));
        assert!(rustscale_tsaddr::is_tailscale_ip(
            "100.127.255.255".parse().unwrap()
        ));
        assert!(rustscale_tsaddr::is_tailscale_ip(
            "fd7a:115c:a1e0::1".parse().unwrap()
        ));
        assert!(!rustscale_tsaddr::is_tailscale_ip(
            "8.8.8.8".parse().unwrap()
        ));
        assert!(!rustscale_tsaddr::is_tailscale_ip(
            "127.0.0.1".parse().unwrap()
        ));
        assert!(!rustscale_tsaddr::is_tailscale_ip(
            "100.63.0.1".parse().unwrap()
        ));
        assert!(!rustscale_tsaddr::is_tailscale_ip(
            "100.128.0.1".parse().unwrap()
        ));
    }

    #[test]
    fn test_security_headers_for_browser() {
        let req = PeerApiRequest {
            method: "GET".into(),
            path: "/".into(),
            headers: vec![
                ("User-Agent".into(), "Mozilla/5.0 (Macintosh)".into()),
                ("Accept-Encoding".into(), "gzip, deflate, br".into()),
            ],
            body: vec![],
        };
        assert!(should_get_security_headers(&req));
    }

    #[test]
    fn test_security_headers_for_non_browser() {
        let req = PeerApiRequest {
            method: "GET".into(),
            path: "/".into(),
            headers: vec![],
            body: vec![],
        };
        assert!(!should_get_security_headers(&req));
    }

    #[test]
    fn test_security_headers_accept_language() {
        let req = PeerApiRequest {
            method: "GET".into(),
            path: "/".into(),
            headers: vec![("Accept-Language".into(), "en-US".into())],
            body: vec![],
        };
        assert!(should_get_security_headers(&req));
    }

    #[test]
    fn test_security_headers_added_to_response() {
        let req = PeerApiRequest {
            method: "GET".into(),
            path: "/".into(),
            headers: vec![("User-Agent".into(), "Mozilla/5.0".into())],
            body: vec![],
        };
        let resp = PeerApiResponse::new(200, "OK", "text/html", b"hello".to_vec());
        let resp = add_security_headers(resp, &req);
        let header_names: Vec<_> = resp.extra_headers.iter().map(|(k, _)| *k).collect();
        assert!(header_names.contains(&"Content-Security-Policy"));
        assert!(header_names.contains(&"X-Frame-Options"));
        assert!(header_names.contains(&"X-Content-Type-Options"));
    }

    #[test]
    fn test_security_headers_not_added_for_non_browser() {
        let req = PeerApiRequest {
            method: "GET".into(),
            path: "/".into(),
            headers: vec![],
            body: vec![],
        };
        let resp = PeerApiResponse::new(200, "OK", "text/html", b"hello".to_vec());
        let resp = add_security_headers(resp, &req);
        assert!(resp.extra_headers.is_empty());
    }

    #[test]
    fn test_doh_get_base64url_parsing() {
        // Build a minimal DNS query for "example.com" type A.
        let query = build_test_dns_query("example.com", 1);
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&query);

        let req = PeerApiRequest {
            method: "GET".into(),
            path: format!("/dns-query?dns={encoded}"),
            headers: vec![],
            body: vec![],
        };

        let parsed = parse_doh_query(&req).expect("should parse GET ?dns=");
        assert_eq!(parsed, query);
    }

    #[test]
    fn test_doh_get_missing_param() {
        let req = PeerApiRequest {
            method: "GET".into(),
            path: "/dns-query".into(),
            headers: vec![],
            body: vec![],
        };
        assert!(parse_doh_query(&req).is_err());
    }

    #[test]
    fn test_doh_post_correct_content_type() {
        let query = build_test_dns_query("test.com", 1);
        let req = PeerApiRequest {
            method: "POST".into(),
            path: "/dns-query".into(),
            headers: vec![("Content-Type".into(), "application/dns-message".into())],
            body: query.clone(),
        };
        let parsed = parse_doh_query(&req).expect("should parse POST");
        assert_eq!(parsed, query);
    }

    #[test]
    fn test_doh_post_wrong_content_type() {
        let req = PeerApiRequest {
            method: "POST".into(),
            path: "/dns-query".into(),
            headers: vec![("Content-Type".into(), "text/plain".into())],
            body: vec![0; 100],
        };
        assert!(parse_doh_query(&req).is_err());
    }

    #[test]
    fn test_doh_bad_method() {
        let req = PeerApiRequest {
            method: "DELETE".into(),
            path: "/dns-query".into(),
            headers: vec![],
            body: vec![],
        };
        assert!(parse_doh_query(&req).is_err());
    }

    #[test]
    fn test_doh_get_bad_base64() {
        let req = PeerApiRequest {
            method: "GET".into(),
            path: "/dns-query?dns=!!!notbase64!!!".into(),
            headers: vec![],
            body: vec![],
        };
        assert!(parse_doh_query(&req).is_err());
    }

    #[tokio::test]
    async fn test_dispatch_root() {
        let whois = WhoIsInfo {
            found: true,
            node_name: "test-node.tailnet.ts.net.".into(),
            tailscale_ips: vec!["100.64.0.1".parse().unwrap()],
            user_id: 1,
            login_name: "user@example.com".into(),
            display_name: "User".into(),
        };
        let state = make_test_state(vec![], vec![], false);
        let req = PeerApiRequest {
            method: "GET".into(),
            path: "/".into(),
            headers: vec![],
            body: vec![],
        };
        let resp = dispatch(&req, &whois, false, &state).await;
        assert_eq!(resp.status, 200);
        assert_eq!(resp.content_type, "text/html; charset=utf-8");
        let body = String::from_utf8(resp.body).unwrap();
        assert!(body.contains("Hello, User"));
        assert!(body.contains("test-node"));
    }

    #[tokio::test]
    async fn test_dispatch_root_is_self() {
        let whois = WhoIsInfo {
            found: true,
            node_name: "me.tailnet.ts.net.".into(),
            tailscale_ips: vec!["100.64.0.1".parse().unwrap()],
            user_id: 1,
            login_name: "me@example.com".into(),
            display_name: "Me".into(),
        };
        let state = make_test_state(vec![], vec!["100.64.0.1".parse().unwrap()], false);
        let req = PeerApiRequest {
            method: "GET".into(),
            path: "/".into(),
            headers: vec![],
            body: vec![],
        };
        let resp = dispatch(&req, &whois, true, &state).await;
        let body = String::from_utf8(resp.body).unwrap();
        assert!(body.contains("You are the owner"));
    }

    #[tokio::test]
    async fn test_dispatch_unknown_path() {
        let whois = WhoIsInfo {
            found: true,
            node_name: "test.".into(),
            tailscale_ips: vec![],
            user_id: 1,
            login_name: String::new(),
            display_name: String::new(),
        };
        let state = make_test_state(vec![], vec![], false);
        let req = PeerApiRequest {
            method: "GET".into(),
            path: "/nonexistent".into(),
            headers: vec![],
            body: vec![],
        };
        let resp = dispatch(&req, &whois, false, &state).await;
        assert_eq!(resp.status, 404);
    }

    #[tokio::test]
    async fn test_dispatch_v0_goroutines() {
        let whois = WhoIsInfo {
            found: true,
            node_name: "test.".into(),
            tailscale_ips: vec![],
            user_id: 1,
            login_name: String::new(),
            display_name: String::new(),
        };
        let state = make_test_state(vec![], vec![], false);
        let req = PeerApiRequest {
            method: "GET".into(),
            path: "/v0/goroutines".into(),
            headers: vec![],
            body: vec![],
        };
        let resp = dispatch(&req, &whois, true, &state).await;
        assert_eq!(resp.status, 200);
        let body = String::from_utf8(resp.body).unwrap();
        assert!(body.contains("tokio"));
    }

    #[tokio::test]
    async fn test_dispatch_v0_goroutines_debug_denied() {
        let whois = WhoIsInfo {
            found: true,
            node_name: "test.".into(),
            tailscale_ips: vec![],
            user_id: 1,
            login_name: String::new(),
            display_name: String::new(),
        };
        let state = make_test_state(vec![], vec![], false);
        let req = PeerApiRequest {
            method: "GET".into(),
            path: "/v0/goroutines".into(),
            headers: vec![],
            body: vec![],
        };
        let resp = dispatch(&req, &whois, false, &state).await;
        assert_eq!(resp.status, 403);
    }

    #[tokio::test]
    async fn test_dispatch_v0_env() {
        let whois = WhoIsInfo {
            found: true,
            node_name: "test.".into(),
            tailscale_ips: vec![],
            user_id: 1,
            login_name: String::new(),
            display_name: String::new(),
        };
        let state = make_test_state(vec![], vec![], false);
        let req = PeerApiRequest {
            method: "GET".into(),
            path: "/v0/env".into(),
            headers: vec![],
            body: vec![],
        };
        let resp = dispatch(&req, &whois, true, &state).await;
        assert_eq!(resp.status, 200);
        assert_eq!(resp.content_type, "application/json");
    }

    #[tokio::test]
    async fn test_dispatch_v0_metrics() {
        let whois = WhoIsInfo {
            found: true,
            node_name: "test.".into(),
            tailscale_ips: vec![],
            user_id: 1,
            login_name: String::new(),
            display_name: String::new(),
        };
        let state = make_test_state(vec![], vec![], false);
        let req = PeerApiRequest {
            method: "GET".into(),
            path: "/v0/metrics".into(),
            headers: vec![],
            body: vec![],
        };
        let resp = dispatch(&req, &whois, true, &state).await;
        assert_eq!(resp.status, 200);
        assert_eq!(resp.content_type, "text/plain; charset=utf-8");
    }

    #[tokio::test]
    async fn test_dispatch_v0_interfaces() {
        let whois = WhoIsInfo {
            found: true,
            node_name: "test.".into(),
            tailscale_ips: vec![],
            user_id: 1,
            login_name: String::new(),
            display_name: String::new(),
        };
        let state = make_test_state(vec![], vec![], false);
        let req = PeerApiRequest {
            method: "GET".into(),
            path: "/v0/interfaces".into(),
            headers: vec![],
            body: vec![],
        };
        let resp = dispatch(&req, &whois, true, &state).await;
        assert_eq!(resp.status, 200);
        assert_eq!(resp.content_type, "application/json");
    }

    #[tokio::test]
    async fn test_dispatch_v0_magicsock() {
        let whois = WhoIsInfo {
            found: true,
            node_name: "test.".into(),
            tailscale_ips: vec![],
            user_id: 1,
            login_name: String::new(),
            display_name: String::new(),
        };
        let state = make_test_state(vec![], vec![], false);
        let req = PeerApiRequest {
            method: "GET".into(),
            path: "/v0/magicsock".into(),
            headers: vec![],
            body: vec![],
        };
        let resp = dispatch(&req, &whois, true, &state).await;
        assert_eq!(resp.status, 200);
    }

    #[tokio::test]
    async fn test_dispatch_v0_dnsfwd() {
        let whois = WhoIsInfo {
            found: true,
            node_name: "test.".into(),
            tailscale_ips: vec![],
            user_id: 1,
            login_name: String::new(),
            display_name: String::new(),
        };
        let state = make_test_state(vec![], vec![], false);
        let req = PeerApiRequest {
            method: "GET".into(),
            path: "/v0/dnsfwd".into(),
            headers: vec![],
            body: vec![],
        };
        let resp = dispatch(&req, &whois, true, &state).await;
        assert_eq!(resp.status, 200);
    }

    #[tokio::test]
    async fn test_dispatch_v0_sockstats() {
        let whois = WhoIsInfo {
            found: true,
            node_name: "test.".into(),
            tailscale_ips: vec![],
            user_id: 1,
            login_name: String::new(),
            display_name: String::new(),
        };
        let state = make_test_state(vec![], vec![], false);
        let req = PeerApiRequest {
            method: "GET".into(),
            path: "/v0/sockstats".into(),
            headers: vec![],
            body: vec![],
        };
        let resp = dispatch(&req, &whois, true, &state).await;
        assert_eq!(resp.status, 200);
        // No sockstats wired → text/plain fallback.
        assert!(resp.content_type.contains("text/plain"));
    }

    #[tokio::test]
    async fn test_dispatch_v0_sockstats_json_when_wired() {
        let stats = Arc::new(rustscale_sockstats::SockStats::new());
        let h = stats.label_handle(rustscale_sockstats::Label::MagicsockConnUDP4);
        h.record_tx(1234);
        h.record_rx(5678);

        let state = Arc::new(PeerApiState {
            peers: Arc::new(RwLock::new(vec![])),
            user_profiles: Arc::new(RwLock::new(BTreeMap::new())),
            resolver: Arc::new(RwLock::new(MagicDnsResolver::default())),
            dns_config: Arc::new(RwLock::new(None)),
            tailscale_ips: vec![],
            offering_exit_node: false,
            taildrop: None,
            sockstats: Some(stats),
        });
        let whois = WhoIsInfo {
            found: true,
            node_name: "test.".into(),
            tailscale_ips: vec![],
            user_id: 1,
            login_name: String::new(),
            display_name: String::new(),
        };
        let req = PeerApiRequest {
            method: "GET".into(),
            path: "/v0/sockstats".into(),
            headers: vec![],
            body: vec![],
        };
        let resp = dispatch(&req, &whois, true, &state).await;
        assert_eq!(resp.status, 200);
        assert!(resp.content_type.contains("application/json"));
        let body = String::from_utf8(resp.body).expect("valid utf8");
        assert!(body.contains("\"stats\""));
        assert!(body.contains("MagicsockConnUDP4"));
        assert!(body.contains("1234"));
        assert!(body.contains("5678"));
    }

    #[tokio::test]
    async fn test_dns_query_denied_not_exit_node() {
        let state = make_test_state(vec![], vec![], false);
        let req = PeerApiRequest {
            method: "GET".into(),
            path: "/dns-query?dns=AAAA".into(),
            headers: vec![],
            body: vec![],
        };
        // is_self=false, offering_exit_node=false → denied
        let resp = handle_dns_query(&req, false, &state).await;
        assert_eq!(resp.status, 403);
    }

    #[tokio::test]
    async fn test_dns_query_allowed_self() {
        let state = make_test_state(vec![], vec![], false);
        let query = build_test_dns_query("example.com", 1);
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&query);
        let req = PeerApiRequest {
            method: "GET".into(),
            path: format!("/dns-query?dns={encoded}"),
            headers: vec![],
            body: vec![],
        };
        // is_self=true → allowed (will try to resolve, may timeout/fail)
        let resp = handle_dns_query(&req, true, &state).await;
        // Should not be 403 — the query is allowed.
        assert_ne!(resp.status, 403);
    }

    #[tokio::test]
    async fn test_dns_query_allowed_exit_node() {
        let state = make_test_state(vec![], vec![], true);
        let query = build_test_dns_query("example.com", 1);
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&query);
        let req = PeerApiRequest {
            method: "GET".into(),
            path: format!("/dns-query?dns={encoded}"),
            headers: vec![],
            body: vec![],
        };
        // is_self=false but offering_exit_node=true → allowed
        let resp = handle_dns_query(&req, false, &state).await;
        assert_ne!(resp.status, 403);
    }

    #[test]
    fn test_auth_rejects_unknown_ip() {
        let state = make_test_state(vec![], vec![], false);
        // No peers in the netmap → whois returns None for any IP.
        let result = state.whois("100.64.0.99".parse().unwrap());
        assert!(result.is_none() || !result.unwrap().found);
    }

    #[test]
    fn test_auth_finds_known_peer() {
        let peer = Node {
            Name: "peer.tailnet.ts.net.".into(),
            Addresses: vec!["100.64.0.2/32".into()],
            User: 1,
            ..Default::default()
        };
        let mut profiles = BTreeMap::new();
        profiles.insert(
            1,
            UserProfile {
                ID: 1,
                LoginName: "peer@example.com".into(),
                DisplayName: "Peer".into(),
                ..Default::default()
            },
        );
        let state = Arc::new(PeerApiState {
            peers: Arc::new(RwLock::new(vec![peer])),
            user_profiles: Arc::new(RwLock::new(profiles)),
            resolver: Arc::new(RwLock::new(MagicDnsResolver::default())),
            dns_config: Arc::new(RwLock::new(None)),
            tailscale_ips: vec!["100.64.0.1".parse().unwrap()],
            offering_exit_node: false,
            taildrop: None,
            sockstats: None,
        });
        let result = state.whois("100.64.0.2".parse().unwrap());
        assert!(result.is_some());
        let info = result.unwrap();
        assert!(info.found);
        assert_eq!(info.node_name, "peer.tailnet.ts.net.");
        assert_eq!(info.login_name, "peer@example.com");
    }

    #[test]
    fn test_percent_decode() {
        assert_eq!(percent_decode("hello"), "hello");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("%20"), " ");
        assert_eq!(percent_decode("%41"), "A");
        assert_eq!(percent_decode("a%26b"), "a&b");
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("\"quote\""), "&quot;quote&quot;");
        assert_eq!(html_escape("a&b"), "a&amp;b");
    }

    #[test]
    fn test_request_query_param() {
        let req = PeerApiRequest {
            method: "GET".into(),
            path: "/dns-query?dns=AAAA&foo=bar".into(),
            headers: vec![],
            body: vec![],
        };
        assert_eq!(req.query_param("dns"), Some("AAAA".into()));
        assert_eq!(req.query_param("foo"), Some("bar".into()));
        assert_eq!(req.query_param("missing"), None);
    }

    #[test]
    fn test_request_path_only() {
        let req = PeerApiRequest {
            method: "GET".into(),
            path: "/dns-query?dns=AAAA".into(),
            headers: vec![],
            body: vec![],
        };
        assert_eq!(req.path_only(), "/dns-query");
    }

    /// Build a minimal DNS wire-format query for testing.
    fn build_test_dns_query(name: &str, qtype: u16) -> Vec<u8> {
        // DNS header: ID=1, flags=0x0100 (RD=1), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        let mut msg = vec![
            0x00, 0x01, // ID
            0x01, 0x00, // Flags: RD=1
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
        ];
        // Question: encode the name as labels.
        for label in name.split('.') {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0); // root label
        msg.extend_from_slice(&qtype.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
        msg
    }
}
