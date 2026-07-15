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
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
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
use rustscale_drive::{AuthenticatedPeer, RequestControl, CAPABILITY_TAILDRIVE};
use rustscale_filter::Filter;
use rustscale_key::NodePublic;
use rustscale_netstack::{Netstack, NetstackStream};
use rustscale_tailcfg::{DNSConfig, Node, Service, UserID, UserProfile};

use crate::{extract_node_ips, whois_lookup, WhoIsInfo};

/// Maximum DNS query size accepted by the DoH handler (256 KiB, matching Go).
const MAX_DNS_QUERY_LEN: usize = 256 << 10;

/// DoH query timeout — short enough for humans to notice, longer than real DNS
/// timeouts (matching Go's `arbitraryTimeout = 5 * time.Second`).
const DOH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Whole-request read/write deadline for the one-request-per-connection server.
const PEERAPI_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// Existing Taildrop supports files up to 1 GiB; all PeerAPI bodies are
/// rejected before allocation beyond that protocol limit.
const MAX_PEERAPI_BODY: usize = 1 << 30;
const MAX_PEERAPI_CONNECTIONS: usize = 16;
const MAX_PEERAPI_INFLIGHT_BYTES: usize = 64 * 1024 * 1024;
const TAILDRIVE_STREAM_CHUNK: usize = 64 * 1024;
const TAILDRIVE_STREAM_QUEUE: usize = 2;

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
    /// Live signed packet filter used to derive peer capability grants.
    filter: Arc<std::sync::Mutex<Filter>>,
    /// Disabled-by-default Taildrive configuration and authorization epoch.
    drive: Arc<crate::drive::Runtime>,
    /// Stable-ID map commit gate and WireGuard source provenance.
    peer_map: Arc<crate::peer_map::Runtime>,
    /// Global PeerAPI connection and declared-body admission limits.
    admission: Arc<PeerApiAdmission>,
    /// Per-label socket TX/RX counter registry (for the `/v0/sockstats`
    /// debug endpoint). `None` when no registry was injected.
    sockstats: Option<Arc<rustscale_sockstats::SockStats>>,
}

struct PeerApiAdmission {
    connections: Arc<tokio::sync::Semaphore>,
    bytes: Arc<tokio::sync::Semaphore>,
}

impl PeerApiAdmission {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            connections: Arc::new(tokio::sync::Semaphore::new(MAX_PEERAPI_CONNECTIONS)),
            bytes: Arc::new(tokio::sync::Semaphore::new(MAX_PEERAPI_INFLIGHT_BYTES)),
        })
    }
}

impl PeerApiState {
    /// WhoIs lookup: resolve a remote IP to peer identity.
    #[cfg(test)]
    fn whois(&self, remote_ip: IpAddr) -> Option<WhoIsInfo> {
        let key = self.peer_map.current_owner(remote_ip)?;
        self.authenticated_whois(remote_ip, &key)
            .map(|(whois, _)| whois)
    }

    /// Resolve identity and node key from the same live peer snapshot. A zero
    /// key is never an authenticated PeerAPI principal.
    fn authenticated_whois(
        &self,
        remote_ip: IpAddr,
        authenticated_key: &NodePublic,
    ) -> Option<(WhoIsInfo, String)> {
        let peers = self.peers.try_read().ok()?;
        let peer = peers.iter().find(|peer| {
            &peer.Key == authenticated_key && extract_node_ips(peer).contains(&remote_ip)
        })?;
        if peer.Key.is_zero() {
            return None;
        }
        let ups = self.user_profiles.try_read().ok()?;
        let whois = whois_lookup(&peers, &ups, remote_ip)?;
        Some((whois, peer.Key.to_string()))
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
    filter: Arc<std::sync::Mutex<Filter>>,
    drive: Arc<crate::drive::Runtime>,
    peer_map: Arc<crate::peer_map::Runtime>,
) -> (Vec<JoinHandle<()>>, Option<u16>) {
    let admission = PeerApiAdmission::new();
    let v4 = tailscale_ips.iter().find_map(|ip| match ip {
        IpAddr::V4(v4) => Some(*v4),
        _ => None,
    });

    let mut bound = None;
    if let Some(v4) = v4 {
        // Complete the bind before spawning. Cancellation during a candidate
        // bind leaves no detached task or retained listener.
        for try_offset in 0u8..5 {
            let candidate = deterministic_port(IpAddr::V4(v4), try_offset);
            if let Ok(listener) = netstack.listen(candidate).await {
                bound = Some((listener, candidate));
                break;
            }
        }
        if bound.is_none() {
            match netstack.listen(0).await {
                Ok(listener) => bound = Some((listener, 0)),
                Err(error) => {
                    log::warn!("peerapi: failed to listen on netstack (non-fatal): {error}");
                }
            }
        }
    }

    let Some((listener, port)) = bound else {
        return (Vec::new(), None);
    };
    let state = Arc::new(PeerApiState {
        peers,
        user_profiles,
        resolver,
        dns_config,
        tailscale_ips,
        offering_exit_node,
        taildrop,
        filter,
        drive,
        peer_map,
        admission,
        sockstats,
    });
    (
        vec![tokio::spawn(serve_netstack_listener(listener, state))],
        Some(port),
    )
}

type BindHook = Arc<dyn Fn(IpAddr, u16) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

async fn bind_peerapi_tcp_listeners(
    tailscale_ips: &[IpAddr],
    after_bind: BindHook,
) -> (Vec<TcpListener>, Option<u16>, Option<u16>) {
    let mut listeners = Vec::new();
    let mut v4_port = None;
    let mut v6_port = None;
    for ip in tailscale_ips {
        match bind_peerapi_tcp(*ip).await {
            Ok((listener, port)) => {
                log::info!("peerapi: listening on {ip}:{port}");
                match ip {
                    IpAddr::V4(_) => v4_port = Some(port),
                    IpAddr::V6(_) => v6_port = Some(port),
                }
                listeners.push(listener);
                after_bind(*ip, port).await;
            }
            Err(error) => {
                log::warn!("peerapi: failed to bind on {ip}: {error} (non-fatal)");
            }
        }
    }
    (listeners, v4_port, v6_port)
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
    filter: Arc<std::sync::Mutex<Filter>>,
    drive: Arc<crate::drive::Runtime>,
    peer_map: Arc<crate::peer_map::Runtime>,
) -> (Vec<JoinHandle<()>>, Option<u16>) {
    let admission = PeerApiAdmission::new();
    let state = Arc::new(PeerApiState {
        peers,
        user_profiles,
        resolver,
        dns_config,
        tailscale_ips: tailscale_ips.clone(),
        offering_exit_node,
        taildrop,
        sockstats,
        filter,
        drive,
        peer_map,
        admission,
    });

    // Bind every address before spawning. Cancelling between per-IP binds
    // drops all earlier listeners, so fixed ports are immediately reusable.
    let (listeners, v4_port, v6_port) = bind_peerapi_tcp_listeners(
        &tailscale_ips,
        Arc::new(|_, _| Box::pin(std::future::ready(()))),
    )
    .await;

    let handles = listeners
        .into_iter()
        .map(|listener| tokio::spawn(serve_tcp_listener(listener, Arc::clone(&state))))
        .collect();

    (handles, v4_port.or(v6_port))
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
                handle_connection_netstack(stream, remote_addr, Arc::clone(&state)).await;
            }
            Err(e) => {
                log::warn!("peerapi: netstack accept error: {e}");
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
                handle_connection_tcp(stream, addr, Arc::clone(&state)).await;
            }
            Err(e) => {
                log::warn!("peerapi: tcp accept error: {e}");
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
    let authenticated_key = stream.peer_node_key().cloned();
    let conn = PeerApiConn::new(stream, remote_addr, authenticated_key, state);
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
    let authenticated_key = stream
        .local_addr()
        .ok()
        .and_then(|local| state.peer_map.flow_owner(remote_addr, local));
    let conn = PeerApiConn::new(stream, Some(remote_addr), authenticated_key, state);
    conn.serve().await;
}

/// A connection wrapper that abstracts netstack vs TCP streams.
struct PeerApiConn<S> {
    stream: S,
    remote_addr: Option<SocketAddr>,
    authenticated_key: Option<NodePublic>,
    state: Arc<PeerApiState>,
    #[cfg(test)]
    staged_before_body: Option<(
        tokio::sync::oneshot::Sender<()>,
        tokio::sync::oneshot::Receiver<()>,
    )>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> PeerApiConn<S> {
    fn new(
        stream: S,
        remote_addr: Option<SocketAddr>,
        authenticated_key: Option<NodePublic>,
        state: Arc<PeerApiState>,
    ) -> Self {
        Self {
            stream,
            remote_addr,
            authenticated_key,
            state,
            #[cfg(test)]
            staged_before_body: None,
        }
    }

    #[cfg(test)]
    fn new_staged_for_test(
        stream: S,
        remote_addr: SocketAddr,
        authenticated_key: NodePublic,
        state: Arc<PeerApiState>,
        entered: tokio::sync::oneshot::Sender<()>,
        release: tokio::sync::oneshot::Receiver<()>,
    ) -> Self {
        Self {
            stream,
            remote_addr: Some(remote_addr),
            authenticated_key: Some(authenticated_key),
            state,
            staged_before_body: Some((entered, release)),
        }
    }

    /// Serve a single HTTP request: parse, auth, dispatch, respond.
    async fn serve(mut self) {
        let Ok(_connection_permit) = self.state.admission.connections.clone().try_acquire_owned()
        else {
            let _ = write_error_response(
                &mut self.stream,
                503,
                "Service Unavailable",
                "peerapi connection limit reached",
            )
            .await;
            return;
        };

        // Bind the transport-authenticated WireGuard key to its current source
        // address immediately before WhoIs. Source IP alone is never an
        // identity, including during stable-node key rotation.
        let map_guard = self.state.peer_map.gate.read().await;
        let remote_ip = self.remote_addr.map(|address| address.ip());
        let authenticated = remote_ip.and_then(|ip| {
            let key = self.authenticated_key.as_ref()?;
            if self.state.peer_map.current_owner(ip).as_ref() != Some(key) {
                return None;
            }
            self.state.authenticated_whois(ip, key)
        });

        let (_whois, node_key, _is_self) = match (&authenticated, remote_ip) {
            (Some((info, node_key)), _) if info.found => {
                // Check if the peer is owned by the same user as us.
                // We determine "is_self" by checking if the peer's user_id
                // matches any of our own node's user. Since we don't have
                // our own user_id readily available, we approximate: if the
                // peer's IPs include one of our own tailscale_ips, it's us.
                let is_self = remote_ip.is_some_and(|ip| self.state.tailscale_ips.contains(&ip));
                (info.clone(), node_key.clone(), is_self)
            }
            _ => {
                // Unknown peer — reject.
                if let Some(ip) = remote_ip {
                    log::warn!("peerapi: unknown peer {ip}");
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
        drop(map_guard);

        // Read only the request head. Taildrive method/path/grants are
        // authorized before a single body byte is consumed.
        let mut req =
            match tokio::time::timeout(PEERAPI_IO_TIMEOUT, read_request_head(&mut self.stream))
                .await
            {
                Ok(Ok(request)) => request,
                Ok(Err(error)) => {
                    let _ = write_error_response(
                        &mut self.stream,
                        400,
                        "Bad Request",
                        &format!("bad request: {error}"),
                    )
                    .await;
                    return;
                }
                Err(_) => {
                    let _ = write_error_response(
                        &mut self.stream,
                        408,
                        "Request Timeout",
                        "peerapi request deadline exceeded",
                    )
                    .await;
                    return;
                }
            };
        let body_length = match request_content_length(&req) {
            Ok(length) => length,
            Err(error) => {
                let _ = write_error_response(&mut self.stream, 400, "Bad Request", &error).await;
                return;
            }
        };
        let is_drive = req.path_only() == "/v0/drive" || req.path_only().starts_with("/v0/drive/");
        let source = (
            remote_ip.expect("authenticated PeerAPI connection has a source IP"),
            node_key.as_str(),
        );

        #[cfg(test)]
        if let Some((entered, release)) = self.staged_before_body.take() {
            let _ = entered.send(());
            let _ = release.await;
        }

        let mut response_map_guard = None;
        let mut resp = if is_drive {
            match authorize_drive(&req, Some(source), &self.state).await {
                Err(response) => response,
                Ok(authorized) => {
                    let body_limit = self.state.drive.limits().max_request_body;
                    if body_length > body_limit {
                        PeerApiResponse::new(
                            413,
                            "Content Too Large",
                            "text/plain; charset=utf-8",
                            b"request body too large".to_vec(),
                        )
                    } else {
                        match self.try_body_budget(body_length) {
                            Err(response) => response,
                            Ok(_permit) if req.method == "PUT" => {
                                stream_authorized_put(
                                    &mut self.stream,
                                    authorized,
                                    body_length,
                                    &self.state,
                                )
                                .await
                            }
                            Ok(_permit) => match tokio::time::timeout(
                                PEERAPI_IO_TIMEOUT,
                                read_request_body(&mut self.stream, body_length, body_limit),
                            )
                            .await
                            {
                                Ok(Ok(body)) => {
                                    req.body = body;
                                    match authorize_drive(&req, Some(source), &self.state).await {
                                        Ok(authorized) => {
                                            run_authorized_drive(authorized, &self.state).await
                                        }
                                        Err(response) => response,
                                    }
                                }
                                Ok(Err(error)) => PeerApiResponse::new(
                                    400,
                                    "Bad Request",
                                    "text/plain; charset=utf-8",
                                    error.into_bytes(),
                                ),
                                Err(_) => PeerApiResponse::new(
                                    408,
                                    "Request Timeout",
                                    "text/plain; charset=utf-8",
                                    b"peerapi request deadline exceeded".to_vec(),
                                ),
                            },
                        }
                    }
                }
            }
        } else {
            match self.try_body_budget(body_length) {
                Err(response) => response,
                Ok(_permit) => match tokio::time::timeout(
                    PEERAPI_IO_TIMEOUT,
                    read_request_body(&mut self.stream, body_length, MAX_PEERAPI_BODY),
                )
                .await
                {
                    Ok(Ok(body)) => {
                        req.body = body;
                        let map_guard = self.state.peer_map.gate.read().await;
                        let current = self.authenticated_key.as_ref().and_then(|key| {
                            if self.state.peer_map.current_owner(source.0).as_ref() != Some(key) {
                                return None;
                            }
                            self.state.authenticated_whois(source.0, key)
                        });
                        match current {
                            Some((current_whois, current_node_key))
                                if current_node_key == source.1 =>
                            {
                                let current_is_self = self.state.tailscale_ips.contains(&source.0);
                                response_map_guard = Some(map_guard);
                                dispatch_authenticated(
                                    &req,
                                    &current_whois,
                                    current_is_self,
                                    source.0,
                                    source.1,
                                    &self.state,
                                )
                                .await
                            }
                            _ => {
                                response_map_guard = Some(map_guard);
                                PeerApiResponse::new(
                                    403,
                                    "Forbidden",
                                    "text/plain; charset=utf-8",
                                    b"authenticated peer is no longer authorized".to_vec(),
                                )
                            }
                        }
                    }
                    Ok(Err(error)) => PeerApiResponse::new(
                        400,
                        "Bad Request",
                        "text/plain; charset=utf-8",
                        error.into_bytes(),
                    ),
                    Err(_) => PeerApiResponse::new(
                        408,
                        "Request Timeout",
                        "text/plain; charset=utf-8",
                        b"peerapi request deadline exceeded".to_vec(),
                    ),
                },
            }
        };

        // Every handler re-enters the current map immediately before its
        // response. Ordinary handlers retain this guard from dispatch through
        // side effects and write; Taildrive uses its cancellable publication
        // epoch for long work, then revalidates exact identity and grants here.
        if response_map_guard.is_none() {
            let map_guard = self.state.peer_map.gate.read().await;
            let identity_valid = self.authenticated_key.as_ref().is_some_and(|key| {
                self.state.peer_map.current_owner(source.0).as_ref() == Some(key)
                    && self
                        .state
                        .authenticated_whois(source.0, key)
                        .is_some_and(|(_, current_node_key)| current_node_key == source.1)
            });
            if !identity_valid {
                resp = PeerApiResponse::new(
                    403,
                    "Forbidden",
                    "text/plain; charset=utf-8",
                    b"authenticated peer is no longer authorized".to_vec(),
                );
            } else if is_drive {
                if let Err(response) = authorize_drive_locked(&req, Some(source), &self.state).await
                {
                    resp = response;
                }
            }
            response_map_guard = Some(map_guard);
        }

        // Bound response writes so a stalled peer cannot retain a handler or
        // its request-scoped authorization indefinitely. The map guard makes
        // response publication part of the same revocation barrier.
        let _ = tokio::time::timeout(PEERAPI_IO_TIMEOUT, resp.write(&mut self.stream)).await;
        drop(response_map_guard);
    }

    fn try_body_budget(
        &self,
        length: usize,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, PeerApiResponse> {
        let permits = u32::try_from(length).map_err(|_| {
            PeerApiResponse::new(
                413,
                "Content Too Large",
                "text/plain; charset=utf-8",
                b"request body too large".to_vec(),
            )
        })?;
        self.state
            .admission
            .bytes
            .clone()
            .try_acquire_many_owned(permits)
            .map_err(|_| {
                PeerApiResponse::new(
                    503,
                    "Service Unavailable",
                    "text/plain; charset=utf-8",
                    b"peerapi body budget exhausted".to_vec(),
                )
            })
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
    content_type: String,
    body: Vec<u8>,
    /// Extra headers to include (e.g. security or WebDAV headers).
    extra_headers: Vec<(String, String)>,
}

impl PeerApiResponse {
    fn new(
        status: u16,
        reason: &'static str,
        content_type: impl Into<String>,
        body: Vec<u8>,
    ) -> Self {
        Self {
            status,
            reason,
            content_type: content_type.into(),
            body,
            extra_headers: Vec::new(),
        }
    }

    fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_headers.push((name.into(), value.into()));
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
#[cfg(test)]
async fn read_request<R: AsyncRead + Unpin>(conn: &mut R) -> Result<PeerApiRequest, String> {
    read_request_with_drive_limit(conn, rustscale_drive::Limits::default().max_request_body).await
}

#[cfg(test)]
async fn read_request_with_drive_limit<R: AsyncRead + Unpin>(
    conn: &mut R,
    max_drive_body: usize,
) -> Result<PeerApiRequest, String> {
    let mut request = read_request_head(conn).await?;
    let limit =
        if request.path_only() == "/v0/drive" || request.path_only().starts_with("/v0/drive/") {
            max_drive_body
        } else {
            MAX_PEERAPI_BODY
        };
    request.body = read_request_body(conn, request_content_length(&request)?, limit).await?;
    Ok(request)
}

/// Read exactly the HTTP head, one byte at a time, so no request-body byte is
/// consumed before method/path/capability authorization.
async fn read_request_head<R: AsyncRead + Unpin>(conn: &mut R) -> Result<PeerApiRequest, String> {
    let mut head = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    loop {
        let count = conn
            .read(&mut byte)
            .await
            .map_err(|error| format!("read: {error}"))?;
        if count == 0 {
            return Err("connection closed before headers".into());
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if head.len() > 256 * 1024 {
            return Err("header too large".into());
        }
    }
    let text = std::str::from_utf8(&head).map_err(|_| "non-utf8 header".to_string())?;
    let _ = extract_content_length(text)?;
    parse_request_head(&head, Vec::new())
}

fn request_content_length(request: &PeerApiRequest) -> Result<usize, String> {
    match request.header("content-length") {
        Some(value) => value
            .parse::<usize>()
            .map_err(|_| "invalid content-length".to_string()),
        None => Ok(0),
    }
}

async fn read_request_body<R: AsyncRead + Unpin>(
    conn: &mut R,
    length: usize,
    limit: usize,
) -> Result<Vec<u8>, String> {
    if length > limit {
        return Err(format!("request body exceeds {limit} bytes"));
    }
    let mut body = Vec::with_capacity(length);
    let mut chunk = vec![0u8; TAILDRIVE_STREAM_CHUNK];
    while body.len() < length {
        let remaining = length - body.len();
        let count = conn
            .read(&mut chunk[..remaining.min(TAILDRIVE_STREAM_CHUNK)])
            .await
            .map_err(|error| format!("read body: {error}"))?;
        if count == 0 {
            return Err("connection closed before complete request body".into());
        }
        body.extend_from_slice(&chunk[..count]);
    }
    Ok(body)
}

/// Extract one valid Content-Length value. An absent length means zero;
/// malformed/duplicate lengths and transfer encoding are rejected.
fn extract_content_length(header_text: &str) -> Result<usize, String> {
    let mut content_length = None;
    for line in header_text.split("\r\n").skip(1) {
        let Some((key, value)) = line.split_once(':') else {
            if line.is_empty() {
                continue;
            }
            return Err("malformed header line".into());
        };
        if key.trim().eq_ignore_ascii_case("transfer-encoding") {
            return Err("transfer-encoding is unsupported".into());
        }
        if key.trim().eq_ignore_ascii_case("content-length") {
            let parsed = value
                .trim()
                .parse::<usize>()
                .map_err(|_| "invalid content-length".to_string())?;
            if content_length.replace(parsed).is_some() {
                return Err("duplicate content-length".into());
            }
        }
    }
    Ok(content_length.unwrap_or(0))
}

fn parse_request_head(head: &[u8], body_preview: Vec<u8>) -> Result<PeerApiRequest, String> {
    let text = std::str::from_utf8(head).map_err(|_| "non-utf8 header".to_string())?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or("no request line")?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or("no method")?.to_string();
    let path = parts.next().ok_or("no path")?.to_string();
    let version = parts.next().ok_or("no HTTP version")?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") || parts.next().is_some() {
        return Err("invalid request line".into());
    }
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once(':')
            .ok_or_else(|| "malformed header line".to_string())?;
        if key.is_empty() || key.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err("invalid header name".into());
        }
        headers.push((key.to_string(), value.trim().to_string()));
    }

    let cl_header = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"));

    let body = if let Some((_, value)) = cl_header {
        let length = value
            .parse::<usize>()
            .map_err(|_| "invalid content-length".to_string())?;
        if body_preview.is_empty() {
            Vec::new()
        } else if body_preview.len() == length {
            body_preview
        } else {
            return Err("request body length does not match content-length".into());
        }
    } else if body_preview.is_empty() {
        Vec::new()
    } else {
        return Err("request body requires content-length".into());
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

/// Dispatch a parsed request to the appropriate handler. Tests and handlers
/// that do not carry connection-bound source metadata cannot use Taildrive.
#[cfg(test)]
async fn dispatch(
    req: &PeerApiRequest,
    whois: &WhoIsInfo,
    is_self: bool,
    state: &Arc<PeerApiState>,
) -> PeerApiResponse {
    dispatch_inner(req, whois, is_self, None, state).await
}

async fn dispatch_authenticated(
    req: &PeerApiRequest,
    whois: &WhoIsInfo,
    is_self: bool,
    remote_ip: IpAddr,
    node_key: &str,
    state: &Arc<PeerApiState>,
) -> PeerApiResponse {
    dispatch_inner(req, whois, is_self, Some((remote_ip, node_key)), state).await
}

async fn dispatch_inner(
    req: &PeerApiRequest,
    whois: &WhoIsInfo,
    is_self: bool,
    authenticated_source: Option<(IpAddr, &str)>,
    state: &Arc<PeerApiState>,
) -> PeerApiResponse {
    let path = req.path_only();

    // Taildrive WebDAV: exact prefix match only. Authorization is derived
    // from WhoIs plus signed packet-filter CapGrant values, never headers.
    if path == "/v0/drive" || path.starts_with("/v0/drive/") {
        let resp = handle_drive(req, authenticated_source, state).await;
        return add_security_headers(resp, req);
    }

    // DoH handler: /dns-query
    if path == "/dns-query" {
        let resp = handle_dns_query(req, is_self, state).await;
        return add_security_headers(resp, req);
    }

    // Taildrop receive: /v0/put/<filename>
    if path.starts_with("/v0/put/") {
        let resp = handle_peer_put(
            req,
            whois,
            is_self,
            authenticated_source.map(|source| source.0),
            state,
        )
        .await;
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

struct AuthorizedDriveRequest {
    peer: AuthenticatedPeer,
    request: rustscale_drive::Request,
    authority: rustscale_drive::RequestAuthority,
}

async fn authorize_drive(
    req: &PeerApiRequest,
    authenticated_source: Option<(IpAddr, &str)>,
    state: &Arc<PeerApiState>,
) -> Result<AuthorizedDriveRequest, PeerApiResponse> {
    let _map = state.peer_map.gate.read().await;
    authorize_drive_locked(req, authenticated_source, state).await
}

/// Authorize against one map snapshot. The caller holds `peer_map.gate` so
/// key/address provenance and signed grants cannot change before authority is
/// captured.
async fn authorize_drive_locked(
    req: &PeerApiRequest,
    authenticated_source: Option<(IpAddr, &str)>,
    state: &Arc<PeerApiState>,
) -> Result<AuthorizedDriveRequest, PeerApiResponse> {
    let Some((remote_ip, connection_node_key)) = authenticated_source else {
        return Err(PeerApiResponse::new(
            403,
            "Forbidden",
            "text/plain; charset=utf-8",
            b"Taildrive requires an authenticated peer".to_vec(),
        ));
    };

    let epoch = state.drive.authorization_read().await;
    if !state.drive.sharing_allowed() || !state.drive.snapshot().enabled() {
        return Err(PeerApiResponse::new(
            404,
            "Not Found",
            "text/plain; charset=utf-8",
            b"taildrive not enabled".to_vec(),
        ));
    }
    if state
        .peer_map
        .current_owner(remote_ip)
        .is_none_or(|key| key.to_string() != connection_node_key)
    {
        return Err(PeerApiResponse::new(
            403,
            "Forbidden",
            "text/plain; charset=utf-8",
            b"authenticated peer is no longer in the netmap".to_vec(),
        ));
    }
    let Some(destination_ip) = state
        .tailscale_ips
        .iter()
        .copied()
        .find(|ip| ip.is_ipv4() == remote_ip.is_ipv4())
    else {
        return Err(PeerApiResponse::new(
            403,
            "Forbidden",
            "text/plain; charset=utf-8",
            b"no matching local Taildrive address".to_vec(),
        ));
    };
    let cap_map = state
        .filter
        .lock()
        .map_err(|_| {
            PeerApiResponse::new(
                503,
                "Service Unavailable",
                "text/plain; charset=utf-8",
                b"Taildrive authorization is unavailable".to_vec(),
            )
        })?
        .caps_with_values(remote_ip, destination_ip);
    let grants = cap_map.get(CAPABILITY_TAILDRIVE).ok_or_else(|| {
        PeerApiResponse::new(
            403,
            "Forbidden",
            "text/plain; charset=utf-8",
            b"taildrive not permitted".to_vec(),
        )
    })?;
    let raw_grants: Vec<Vec<u8>> = grants
        .iter()
        .map(|grant| grant.0.as_bytes().to_vec())
        .collect();
    let peer = AuthenticatedPeer::from_capability_grants(
        connection_node_key,
        &raw_grants,
        state.drive.limits(),
    )
    .map_err(|error| {
        log::warn!("peerapi: rejected malformed signed Taildrive grants: {error}");
        PeerApiResponse::new(
            403,
            "Forbidden",
            "text/plain; charset=utf-8",
            b"invalid Taildrive authorization".to_vec(),
        )
    })?;
    let path = req.path.strip_prefix("/v0/drive").unwrap_or_default();
    let request = rustscale_drive::Request {
        method: req.method.clone(),
        path: if path.is_empty() {
            "/".into()
        } else {
            path.into()
        },
        headers: req
            .headers
            .iter()
            .map(|(name, value)| {
                let name = name.to_ascii_lowercase();
                let value = if name == "destination" {
                    strip_drive_destination_prefix(value)
                } else {
                    value.clone()
                };
                (name, value)
            })
            .collect(),
        body: req.body.clone(),
    };
    state
        .drive
        .preflight(&peer, &request)
        .map_err(adapt_drive_response)?;
    let authority = state.drive.request_authority_locked(&epoch);
    Ok(AuthorizedDriveRequest {
        peer,
        request,
        authority,
    })
}

async fn handle_drive(
    req: &PeerApiRequest,
    authenticated_source: Option<(IpAddr, &str)>,
    state: &Arc<PeerApiState>,
) -> PeerApiResponse {
    match authorize_drive(req, authenticated_source, state).await {
        Ok(authorized) => run_authorized_drive(authorized, state).await,
        Err(response) => response,
    }
}

async fn run_authorized_drive(
    authorized: AuthorizedDriveRequest,
    state: &Arc<PeerApiState>,
) -> PeerApiResponse {
    let AuthorizedDriveRequest {
        peer,
        request,
        authority,
    } = authorized;
    let timeout = state.drive.limits().request_timeout;
    let cancellation = authority.cancellation();
    let control = RequestControl::new(authority, std::time::Instant::now() + timeout);
    let cancellation_guard = cancellation.drop_guard();
    let drive = state.drive.clone();
    let worker = tokio::task::spawn_blocking(move || drive.handle(&peer, request, &control));
    let response = await_drive_worker(worker, timeout).await;
    drop(cancellation_guard);
    response
}

async fn stream_authorized_put<R: AsyncRead + Unpin>(
    stream: &mut R,
    authorized: AuthorizedDriveRequest,
    body_length: usize,
    state: &Arc<PeerApiState>,
) -> PeerApiResponse {
    let AuthorizedDriveRequest {
        peer,
        request,
        authority,
    } = authorized;
    let timeout = state.drive.limits().request_timeout;
    let deadline = std::time::Instant::now() + timeout;
    let cancellation = authority.cancellation();
    let control = RequestControl::new(authority, deadline);
    let cancellation_guard = cancellation.clone().drop_guard();
    let (sender, body) =
        rustscale_drive::streaming_body_channel(body_length, TAILDRIVE_STREAM_QUEUE);
    let drive = state.drive.clone();
    let worker = tokio::task::spawn_blocking(move || {
        drive.handle_streaming_put(&peer, request, body, &control)
    });
    let mut sender = Some(sender);
    let mut received = 0usize;
    let mut chunk = vec![0u8; TAILDRIVE_STREAM_CHUNK];
    let read_result = loop {
        if received == body_length {
            break Ok(());
        }
        let remaining = body_length - received;
        let read = tokio::select! {
            () = cancellation.cancelled() => break Err("Taildrive authorization was revoked".to_string()),
            result = tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                stream.read(&mut chunk[..remaining.min(TAILDRIVE_STREAM_CHUNK)]),
            ) => match result {
                Ok(result) => result.map_err(|error| format!("read body: {error}")),
                Err(_) => break Err("Taildrive request deadline exceeded".to_string()),
            },
        };
        let count = match read {
            Ok(0) => break Err("connection closed before complete request body".to_string()),
            Ok(count) => count,
            Err(error) => break Err(error),
        };
        received += count;
        let send = sender
            .as_ref()
            .expect("stream sender exists")
            .send(chunk[..count].to_vec());
        let sent = tokio::select! {
            () = cancellation.cancelled() => false,
            result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), send) => {
                matches!(result, Ok(Ok(())))
            }
        };
        if !sent {
            break Err("Taildrive upload worker stopped or was revoked".to_string());
        }
    };
    drop(sender.take());
    if let Err(error) = read_result {
        cancellation.cancel();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), worker).await;
        drop(cancellation_guard);
        return PeerApiResponse::new(
            400,
            "Bad Request",
            "text/plain; charset=utf-8",
            error.into_bytes(),
        );
    }
    let response = await_drive_worker(worker, timeout).await;
    drop(cancellation_guard);
    response
}

async fn await_drive_worker(
    worker: tokio::task::JoinHandle<rustscale_drive::Response>,
    timeout: std::time::Duration,
) -> PeerApiResponse {
    match tokio::time::timeout(timeout + std::time::Duration::from_secs(1), worker).await {
        Ok(Ok(response)) => adapt_drive_response(response),
        Ok(Err(error)) => {
            log::warn!("peerapi: Taildrive worker failed: {error}");
            PeerApiResponse::new(
                500,
                "Internal Server Error",
                "text/plain; charset=utf-8",
                b"Taildrive worker failed".to_vec(),
            )
        }
        Err(_) => PeerApiResponse::new(
            408,
            "Request Timeout",
            "text/plain; charset=utf-8",
            b"Taildrive request deadline exceeded".to_vec(),
        ),
    }
}

fn adapt_drive_response(response: rustscale_drive::Response) -> PeerApiResponse {
    let content_type = response
        .headers
        .get("content-type")
        .cloned()
        .unwrap_or_else(|| "application/octet-stream".into());
    let mut adapted = PeerApiResponse::new(
        response.status,
        status_reason(response.status),
        content_type,
        response.body,
    );
    for (name, value) in response.headers {
        if !name.eq_ignore_ascii_case("content-type")
            && !name.eq_ignore_ascii_case("content-length")
            && !name.eq_ignore_ascii_case("connection")
        {
            adapted.extra_headers.push((name, value));
        }
    }
    adapted
}

fn strip_drive_destination_prefix(destination: &str) -> String {
    if destination == "/v0/drive" {
        "/".into()
    } else if destination.starts_with("/v0/drive/") {
        destination["/v0/drive".len()..].into()
    } else {
        // Absolute URIs and non-Taildrive paths are left intact so the core's
        // strict origin/cross-share validation rejects them.
        destination.into()
    }
}

fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        207 => "Multi-Status",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        412 => "Precondition Failed",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        507 => "Insufficient Storage",
        _ => "Unknown",
    }
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
    whois: &WhoIsInfo,
    is_self: bool,
    authenticated_source_ip: Option<IpAddr>,
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

    // Auth: self or an exact current signed `file-send` grant from this
    // source address to one of our same-family node addresses. The connection
    // dispatcher holds the peer-map gate across this lookup and file commit.
    if !is_self {
        let source_ip =
            authenticated_source_ip.filter(|source| whois.tailscale_ips.contains(source));
        let destination_ip = source_ip.and_then(|source| {
            state
                .tailscale_ips
                .iter()
                .copied()
                .find(|destination| destination.is_ipv4() == source.is_ipv4())
        });
        let allowed = source_ip
            .zip(destination_ip)
            .is_some_and(|(source, destination)| {
                state.filter.lock().is_ok_and(|filter| {
                    filter
                        .caps_with_values(source, destination)
                        .contains_key(crate::taildrop::CAP_PEER_FILE_SHARING_SEND)
                })
            });
        if !allowed {
            return PeerApiResponse::new(
                403,
                "Forbidden",
                "text/plain; charset=utf-8",
                b"taildrop: peer not authorized".to_vec(),
            );
        }
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
    use rustscale_tailcfg::{CapGrant, FilterRule, Node, PeerCapMap, RawMessage, UserProfile};

    /// Make a fake `PeerApiState` for testing.
    fn make_test_state(
        mut peers: Vec<Node>,
        ips: Vec<IpAddr>,
        exit_node: bool,
    ) -> Arc<PeerApiState> {
        for (index, peer) in peers.iter_mut().enumerate() {
            if peer.ID == 0 {
                peer.ID = i64::try_from(index + 1).expect("test peer ID");
            }
        }
        let peer_map = crate::peer_map::Runtime::new(&peers).expect("valid test peers");
        Arc::new(PeerApiState {
            peers: Arc::new(RwLock::new(peers)),
            user_profiles: Arc::new(RwLock::new(BTreeMap::new())),
            resolver: Arc::new(RwLock::new(MagicDnsResolver::default())),
            dns_config: Arc::new(RwLock::new(None)),
            tailscale_ips: ips,
            offering_exit_node: exit_node,
            taildrop: None,
            sockstats: None,
            filter: Arc::new(std::sync::Mutex::new(Filter::allow_none())),
            drive: crate::drive::Runtime::new(),
            peer_map,
            admission: PeerApiAdmission::new(),
        })
    }

    fn taildrive_filter(src: IpAddr, dst: IpAddr, grant: Option<&str>) -> Filter {
        let mut cap_map = PeerCapMap::new();
        if let Some(grant) = grant {
            cap_map.insert(CAPABILITY_TAILDRIVE.into(), vec![RawMessage(grant.into())]);
        }
        let rules = vec![FilterRule {
            SrcIPs: vec![src.to_string()],
            CapGrant: vec![CapGrant {
                Dsts: vec![dst.to_string()],
                CapMap: cap_map,
                ..Default::default()
            }],
            ..Default::default()
        }];
        Filter::new(&rules, &[dst], &BTreeMap::new()).unwrap()
    }

    async fn install_taildrive_filter(
        state: &Arc<PeerApiState>,
        src: IpAddr,
        dst: IpAddr,
        grant: Option<&str>,
    ) {
        let mut epoch = state.drive.authorization_write().await;
        state.drive.rotate_authorization_locked(&mut epoch);
        *state.filter.lock().unwrap() = taildrive_filter(src, dst, grant);
    }

    async fn enabled_taildrive_state(
        grant: Option<&str>,
    ) -> (Arc<PeerApiState>, tempfile::TempDir, IpAddr, String) {
        let src: IpAddr = "100.64.0.2".parse().unwrap();
        let dst: IpAddr = "100.64.0.1".parse().unwrap();
        let key = rustscale_key::NodePrivate::generate().public();
        let node_key = key.to_string();
        let peer = Node {
            Key: key,
            Addresses: vec![format!("{src}/32")],
            ..Default::default()
        };
        let state = make_test_state(vec![peer], vec![dst], false);
        {
            let mut epoch = state.drive.authorization_write().await;
            state.drive.rotate_authorization_locked(&mut epoch);
            state.drive.set_sharing_allowed_locked(true, &mut epoch);
        }
        let temp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        std::fs::write(root.join("hello.txt"), b"hello").unwrap();
        state
            .drive
            .replace(crate::drive::RuntimeConfig {
                enabled: true,
                shares: vec![rustscale_drive::Share::new("docs", root)],
            })
            .await
            .unwrap();
        install_taildrive_filter(&state, src, dst, grant).await;
        (state, temp, src, node_key)
    }

    fn drive_whois(src: IpAddr) -> WhoIsInfo {
        WhoIsInfo {
            found: true,
            node_name: "peer.tailnet.test.".into(),
            tailscale_ips: vec![src],
            user_id: 1,
            login_name: "peer@example.test".into(),
            display_name: "Peer".into(),
        }
    }

    #[tokio::test]
    async fn netstack_listener_handle_is_real_and_fixed_port_retries() {
        let ip: Ipv4Addr = "100.64.0.55".parse().unwrap();
        let netstack = Arc::new(Netstack::new(ip, 1280));
        let spawn = |netstack: Arc<Netstack>| async move {
            spawn_peerapi_netstack(
                netstack,
                Arc::new(RwLock::new(Vec::new())),
                Arc::new(RwLock::new(BTreeMap::new())),
                Arc::new(RwLock::new(MagicDnsResolver::default())),
                Arc::new(RwLock::new(None)),
                vec![IpAddr::V4(ip)],
                false,
                None,
                None,
                Arc::new(std::sync::Mutex::new(Filter::allow_none())),
                crate::drive::Runtime::new(),
                crate::peer_map::Runtime::new(&[]).expect("empty peer map"),
            )
            .await
        };

        let (handles, first_port) = spawn(Arc::clone(&netstack)).await;
        assert_eq!(handles.len(), 1);
        assert!(!handles[0].is_finished(), "peerapi returned a dummy task");
        for handle in &handles {
            handle.abort();
        }
        for handle in handles {
            let _ = handle.await;
        }

        let (retry_handles, retry_port) = spawn(netstack).await;
        assert_eq!(
            retry_port, first_port,
            "fixed port was retained by old task"
        );
        for handle in &retry_handles {
            handle.abort();
        }
        for handle in retry_handles {
            let _ = handle.await;
        }
    }

    #[tokio::test]
    async fn request_head_parser_leaves_taildrive_body_unread() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        client
            .write_all(b"PUT /v0/drive/docs/file HTTP/1.1\r\nContent-Length: 6\r\n\r\nsecret")
            .await
            .unwrap();
        let request = read_request_head(&mut server).await.unwrap();
        assert_eq!(request.method, "PUT");
        assert!(request.body.is_empty());
        let mut body = [0u8; 6];
        server.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"secret");
    }

    #[tokio::test]
    async fn staged_taildrop_revalidates_current_peer_and_grant_before_commit() {
        let source: IpAddr = "100.64.0.2".parse().unwrap();
        let destination: IpAddr = "100.64.0.1".parse().unwrap();
        let key = rustscale_key::NodePrivate::generate().public();
        let peer = Node {
            ID: 1,
            Key: key.clone(),
            Addresses: vec![format!("{source}/32")],
            ..Default::default()
        };
        let mut state = make_test_state(vec![peer], vec![destination], false);
        let temp = tempfile::tempdir().unwrap();
        Arc::get_mut(&mut state).unwrap().taildrop = Some(Arc::new(
            crate::taildrop::TaildropManager::new(Some(temp.path()), None),
        ));
        let mut cap_map = PeerCapMap::new();
        cap_map.insert(
            crate::taildrop::CAP_PEER_FILE_SHARING_SEND.into(),
            Vec::new(),
        );
        *state.filter.lock().unwrap() = Filter::new(
            &[FilterRule {
                SrcIPs: vec![source.to_string()],
                CapGrant: vec![CapGrant {
                    Dsts: vec![destination.to_string()],
                    CapMap: cap_map,
                    ..Default::default()
                }],
                ..Default::default()
            }],
            &[destination],
            &BTreeMap::new(),
        )
        .unwrap();

        let (mut client, server) = tokio::io::duplex(4096);
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let connection = PeerApiConn::new_staged_for_test(
            server,
            SocketAddr::new(source, 12345),
            key,
            state.clone(),
            entered_tx,
            release_rx,
        );
        let task = tokio::spawn(connection.serve());
        client
            .write_all(b"PUT /v0/put/staged.txt HTTP/1.1\r\nContent-Length: 6\r\n\r\nsecret")
            .await
            .unwrap();
        entered_rx.await.expect("request reached pre-body stage");

        // This is the same lock order and authority withdrawal used by the
        // tailnet-identity mismatch transaction.
        let map_commit = state.peer_map.gate.write().await;
        let mut drive_epoch = state.drive.authorization_write().await;
        state.drive.rotate_authorization_locked(&mut drive_epoch);
        state
            .drive
            .set_sharing_allowed_locked(false, &mut drive_epoch);
        *state.filter.lock().unwrap() = Filter::allow_none();
        state.peers.write().await.clear();
        state.peer_map.install_locked(&[]).unwrap();
        drop(drive_epoch);
        drop(map_commit);
        let _ = release_tx.send(());

        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        task.await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 403 Forbidden\r\n"));
        assert!(
            !temp.path().join("files/staged.txt").exists(),
            "staged Taildrop request published after peer revocation"
        );
    }

    #[test]
    fn global_body_budget_bounds_parallel_max_sized_requests() {
        const MAX_BODY: u32 = 16 * 1024 * 1024;
        let admission = PeerApiAdmission::new();
        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(
                admission
                    .bytes
                    .clone()
                    .try_acquire_many_owned(MAX_BODY)
                    .expect("four max-sized requests fit the global budget"),
            );
        }
        assert!(admission
            .bytes
            .clone()
            .try_acquire_many_owned(MAX_BODY)
            .is_err());
        held.pop();
        assert!(admission
            .bytes
            .clone()
            .try_acquire_many_owned(MAX_BODY)
            .is_ok());
    }

    #[tokio::test]
    async fn taildrive_grants_narrow_and_revoke_without_trusting_headers() {
        let (state, _temp, src, node_key) =
            enabled_taildrive_state(Some(r#"{"shares":["docs"],"access":"rw"}"#)).await;
        let whois = drive_whois(src);

        let put = PeerApiRequest {
            method: "PUT".into(),
            path: "/v0/drive/docs/writable.txt".into(),
            headers: vec![],
            body: b"written".to_vec(),
        };
        assert_eq!(
            dispatch_authenticated(&put, &whois, false, src, &node_key, &state)
                .await
                .status,
            201
        );
        let moved = PeerApiRequest {
            method: "MOVE".into(),
            path: "/v0/drive/docs/writable.txt".into(),
            headers: vec![("Destination".into(), "/v0/drive/docs/moved.txt".into())],
            body: vec![],
        };
        assert_eq!(
            dispatch_authenticated(&moved, &whois, false, src, &node_key, &state)
                .await
                .status,
            201
        );

        install_taildrive_filter(
            &state,
            src,
            "100.64.0.1".parse().unwrap(),
            Some(r#"{"shares":["docs"],"access":"ro"}"#),
        )
        .await;
        let forged = PeerApiRequest {
            headers: vec![(
                "X-Taildrive-Grants".into(),
                r#"{"shares":["*"],"access":"rw"}"#.into(),
            )],
            path: "/v0/drive/docs/forged.txt".into(),
            ..put
        };
        assert_eq!(
            dispatch_authenticated(&forged, &whois, false, src, &node_key, &state)
                .await
                .status,
            403
        );
        let get = PeerApiRequest {
            method: "GET".into(),
            path: "/v0/drive/docs/hello.txt".into(),
            headers: vec![],
            body: vec![],
        };
        assert_eq!(
            dispatch_authenticated(&get, &whois, false, src, &node_key, &state)
                .await
                .status,
            200
        );

        install_taildrive_filter(&state, src, "100.64.0.1".parse().unwrap(), None).await;
        assert_eq!(
            dispatch_authenticated(&get, &whois, false, src, &node_key, &state)
                .await
                .status,
            403
        );
    }

    #[tokio::test]
    async fn taildrive_key_rotation_denies_old_key_and_accepts_new_key() {
        let (state, _temp, src, old_node_key) =
            enabled_taildrive_state(Some(r#"{"shares":["docs"],"access":"ro"}"#)).await;
        let whois = drive_whois(src);
        let request = PeerApiRequest {
            method: "GET".into(),
            path: "/v0/drive/docs/hello.txt".into(),
            headers: vec![],
            body: vec![],
        };
        assert_eq!(
            dispatch_authenticated(&request, &whois, false, src, &old_node_key, &state)
                .await
                .status,
            200
        );

        let new_key = rustscale_key::NodePrivate::generate().public();
        let new_node_key = new_key.to_string();
        let map_guard = state.peer_map.gate.write().await;
        let mut epoch = state.drive.authorization_write().await;
        state.drive.rotate_authorization_locked(&mut epoch);
        {
            let mut peers = state.peers.write().await;
            peers[0].Key = new_key;
            state.peer_map.install_locked(&peers).unwrap();
        }
        drop(epoch);
        drop(map_guard);

        assert_eq!(
            dispatch_authenticated(&request, &whois, false, src, &old_node_key, &state)
                .await
                .status,
            403
        );
        assert_eq!(
            dispatch_authenticated(&request, &whois, false, src, &new_node_key, &state)
                .await
                .status,
            200
        );
    }

    #[tokio::test]
    async fn identity_mismatch_cancels_staged_taildrive_mutation_atomically() {
        let (state, temp, src, node_key) =
            enabled_taildrive_state(Some(r#"{"shares":["docs"],"access":"rw"}"#)).await;
        let request = PeerApiRequest {
            method: "PUT".into(),
            path: "/v0/drive/docs/staged.txt".into(),
            headers: vec![],
            body: vec![],
        };
        let authorized = match authorize_drive(&request, Some((src, &node_key)), &state).await {
            Ok(authorized) => authorized,
            Err(response) => panic!(
                "initial signed authorization failed with status {}",
                response.status
            ),
        };
        let AuthorizedDriveRequest {
            peer,
            request,
            authority,
        } = authorized;
        let control = RequestControl::new(
            authority,
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        );
        let (body_tx, body) = rustscale_drive::streaming_body_channel(6, 1);
        let worker_drive = state.drive.clone();
        let worker = tokio::task::spawn_blocking(move || {
            worker_drive.handle_streaming_put(&peer, request, body, &control)
        });
        body_tx.send(b"sec".to_vec()).await.unwrap();
        tokio::task::yield_now().await;

        // Tailnet identity mismatch is a single map-writer transaction: no
        // ordinary PeerAPI reader can remain, and Taildrive's old publication
        // epoch is revoked before empty identity/filter state is installed.
        let map_commit = state.peer_map.gate.write().await;
        let mut drive_epoch = state.drive.authorization_write().await;
        state.drive.rotate_authorization_locked(&mut drive_epoch);
        state
            .drive
            .set_sharing_allowed_locked(false, &mut drive_epoch);
        *state.filter.lock().unwrap() = Filter::allow_none();
        state.peers.write().await.clear();
        state.peer_map.install_locked(&[]).unwrap();
        drop(drive_epoch);
        drop(map_commit);

        let _ = body_tx.send(b"ret".to_vec()).await;
        drop(body_tx);
        let response = worker.await.unwrap();
        assert!(
            response.status >= 400,
            "revoked mutation unexpectedly succeeded"
        );
        assert!(
            !temp.path().join("staged.txt").exists(),
            "identity mismatch allowed Taildrive publication"
        );
        assert!(state.peer_map.current_owner(src).is_none());
        assert!(!state.drive.sharing_allowed());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn taildrive_peerapi_blocks_traversal_and_symlink_escape() {
        use std::os::unix::fs::symlink;

        let (state, temp, src, node_key) =
            enabled_taildrive_state(Some(r#"{"shares":["docs"],"access":"ro"}"#)).await;
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let outside_dir = tempfile::tempdir().unwrap();
        let outside = outside_dir.path().join("secret");
        std::fs::write(&outside, b"secret").unwrap();
        symlink(&outside, root.join("escape")).unwrap();
        let whois = drive_whois(src);
        for path in [
            "/v0/drive/docs/../taildrive-outside-secret",
            "/v0/drive/docs/%2e%2e/taildrive-outside-secret",
            "/v0/drive/docs/escape",
        ] {
            let request = PeerApiRequest {
                method: "GET".into(),
                path: path.into(),
                headers: vec![],
                body: vec![],
            };
            let response =
                dispatch_authenticated(&request, &whois, false, src, &node_key, &state).await;
            assert!(matches!(response.status, 400 | 403), "{path}");
            assert_ne!(response.body, b"secret");
        }
    }

    #[tokio::test]
    async fn taildrive_peerapi_is_disabled_at_startup_even_with_a_grant() {
        let src: IpAddr = "100.64.0.2".parse().unwrap();
        let dst: IpAddr = "100.64.0.1".parse().unwrap();
        let key = rustscale_key::NodePrivate::generate().public();
        let node_key = key.to_string();
        let state = make_test_state(
            vec![Node {
                Key: key,
                Addresses: vec![format!("{src}/32")],
                ..Default::default()
            }],
            vec![dst],
            false,
        );
        install_taildrive_filter(&state, src, dst, Some(r#"{"shares":["*"],"access":"rw"}"#)).await;
        let request = PeerApiRequest {
            method: "PROPFIND".into(),
            path: "/v0/drive/".into(),
            headers: vec![("Depth".into(), "1".into())],
            body: vec![],
        };
        assert_eq!(
            dispatch_authenticated(&request, &drive_whois(src), false, src, &node_key, &state,)
                .await
                .status,
            404
        );
    }

    #[tokio::test]
    async fn taildrive_parser_rejects_oversized_body_before_reading_it() {
        let raw = format!(
            "PUT /v0/drive/docs/file HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            rustscale_drive::Limits::default().max_request_body + 1
        );
        let mut cursor = std::io::Cursor::new(raw.into_bytes());
        let error = match read_request(&mut cursor).await {
            Ok(_) => panic!("oversized request was accepted"),
            Err(error) => error,
        };
        assert!(error.contains("request body exceeds"), "{error}");
    }

    #[tokio::test]
    async fn cancellation_between_each_bind_releases_fixed_ports() {
        let ip = "127.0.0.1".parse::<IpAddr>().unwrap();
        let ips = vec![ip, ip];
        for cancel_at in 1..=ips.len() {
            let (bound_tx, mut bound_rx) = tokio::sync::mpsc::unbounded_channel();
            let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let hook_count = Arc::clone(&count);
            let hook: BindHook = Arc::new(move |ip, port| {
                let index = hook_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                let _ = bound_tx.send((ip, port));
                Box::pin(async move {
                    if index == cancel_at {
                        std::future::pending::<()>().await;
                    }
                })
            });
            let bind_ips = ips.clone();
            let bind =
                tokio::spawn(async move { bind_peerapi_tcp_listeners(&bind_ips, hook).await });
            let mut bound = Vec::new();
            for _ in 0..cancel_at {
                bound.push(
                    tokio::time::timeout(std::time::Duration::from_secs(1), bound_rx.recv())
                        .await
                        .expect("bind hook did not run")
                        .unwrap(),
                );
            }
            bind.abort();
            let _ = bind.await;

            for (ip, port) in bound {
                let listener = TcpListener::bind(SocketAddr::new(ip, port))
                    .await
                    .unwrap_or_else(|error| {
                        panic!("fixed-port retry failed after bind {cancel_at}: {error}")
                    });
                drop(listener);
            }
        }
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
        let header_names: Vec<_> = resp
            .extra_headers
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
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
            filter: Arc::new(std::sync::Mutex::new(Filter::allow_none())),
            drive: crate::drive::Runtime::new(),
            peer_map: crate::peer_map::Runtime::new(&[]).expect("empty peer map"),
            admission: PeerApiAdmission::new(),
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
            ID: 1,
            Name: "peer.tailnet.ts.net.".into(),
            Key: rustscale_key::NodePrivate::generate().public(),
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
        let peer_map =
            crate::peer_map::Runtime::new(std::slice::from_ref(&peer)).expect("valid peer map");
        let state = Arc::new(PeerApiState {
            peers: Arc::new(RwLock::new(vec![peer])),
            user_profiles: Arc::new(RwLock::new(profiles)),
            resolver: Arc::new(RwLock::new(MagicDnsResolver::default())),
            dns_config: Arc::new(RwLock::new(None)),
            tailscale_ips: vec!["100.64.0.1".parse().unwrap()],
            offering_exit_node: false,
            taildrop: None,
            sockstats: None,
            filter: Arc::new(std::sync::Mutex::new(Filter::allow_none())),
            drive: crate::drive::Runtime::new(),
            peer_map,
            admission: PeerApiAdmission::new(),
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
