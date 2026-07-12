//! Tailscale Serve + Funnel support for rustscale.
//!
//! Ports the serve/funnel feature from Go's `ipn/serve.go` and
//! `ipn/ipnlocal/serve.go`. [`ServeConfig`] is a plain serde-serializable
//! struct settable via [`Server::set_serve_config`](crate::Server::set_serve_config);
//! the runner starts netstack listeners on the configured tailnet ports and
//! dispatches each accepted connection to the matching handler.
//!
//! # Handler kinds
//!
//! - **TCP forward** ([`TCPPortHandler::TCPForward`]): raw TCP proxy to a local
//!   backend address, optionally TLS-terminated first ([`TCPPortHandler::TerminateTLS`]).
//! - **HTTP/HTTPS web** ([`TCPPortHandler::HTTP`] / [`TCPPortHandler::HTTPS`]):
//!   dispatches to [`WebServerConfig`] handlers keyed by mount path. Each
//!   [`HTTPHandler`] is either a reverse proxy ([`HTTPHandler::Proxy`]) or
//!   static text ([`HTTPHandler::Text`]). The reverse proxy sets `Host`,
//!   `X-Forwarded-For`, and `Tailscale-User-Login`/`Tailscale-User-Name`
//!   headers (from WhoIs) mirroring Go's `addTailscaleIdentityHeaders`.
//!
//! # Funnel
//!
//! [`Server::listen_funnel`](crate::Server::listen_funnel) validates the port
//! (443/8443/10000) and the node's funnel capability from the netmap, returning
//! a typed [`FunnelError::NotEnabled`] when control has not granted the
//! `funnel` node attribute — the expected state on API-only tailnets.

// Field names match Go's `ipn.ServeConfig` JSON output exactly for wire
// compatibility (serde serializes PascalCase field names verbatim).
#![allow(non_snake_case)]

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;

use rustscale_netstack::{Listener, Netstack, NetstackStream};
use rustscale_tailcfg::{Node, NodeCapMap, UserID, UserProfile};

use crate::tls::CertProvider;

/// An SNI name and port joined by a colon, e.g. `"node.tailnet.ts.net:443"`.
/// Matches Go's `ipn.HostPort`. There is no implicit port 443.
pub type HostPort = String;

/// The set of TCP ports Tailscale Funnel supports (mirrors Go's
/// `CapabilityFunnelPorts` default set).
pub const FUNNEL_PORTS: &[u16] = &[443, 8443, 10000];

/// The `https` node capability (Go's `tailcfg.CapabilityHTTPS`).
const CAP_HTTPS: &str = "https";
/// The `funnel` node attribute (Go's `tailcfg.NodeAttrFunnel`).
const NODE_ATTR_FUNNEL: &str = "funnel";
/// The funnel-ports capability URL prefix (Go's `tailcfg.CapabilityFunnelPorts`).
const CAP_FUNNEL_PORTS: &str = "https://tailscale.com/cap/funnel-ports";

// ---------------------------------------------------------------------------
// ServeConfig model
// ---------------------------------------------------------------------------

/// The serve configuration — a plain serde-serializable struct mirroring Go's
/// `ipn.ServeConfig`. Set via [`Server::set_serve_config`](crate::Server::set_serve_config).
///
/// No file watching or LocalAPI persistence; the config lives in memory for
/// the life of the server.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ServeConfig {
    /// TCP port handlers keyed by port number.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub TCP: BTreeMap<u16, TCPPortHandler>,
    /// Web server configs keyed by `"fqdn:port"`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub Web: BTreeMap<HostPort, WebServerConfig>,
    /// Per-service configs keyed by service name (`svc:dns-label`).
    /// Mirrors Go's `ServeConfig.Services`. Not yet fully wired — present
    /// for config compatibility and future VIP-service serve dispatch.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub Services: BTreeMap<String, ServiceConfig>,
    /// Set of `"fqdn:port"` values for which funnel (public internet) traffic
    /// is allowed from trusted ingress peers.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub AllowFunnel: BTreeMap<HostPort, bool>,
    /// Foreground serve configs keyed by IPN watch session ID. Mirrors Go's
    /// `ServeConfig.Foreground`. Each entry is an alternate ephemeral config
    /// valid for the life of that watch session (CLI `--foreground` mode).
    /// Not yet fully wired — present for config compatibility.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub Foreground: BTreeMap<String, ServeConfig>,
}

/// Per-service serve configuration. Mirrors Go's `ipn.ServiceConfig`.
/// Not yet fully wired — present for config compatibility.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// TCP port handlers for this service.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub TCP: BTreeMap<u16, TCPPortHandler>,
    /// Web server configs for this service.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub Web: BTreeMap<HostPort, WebServerConfig>,
    /// Whether the service uses L3 (TUN) forwarding.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub Tun: bool,
}

/// Describes what to do when handling a TCP connection on a serve port.
/// Mirrors Go's `ipn.TCPPortHandler`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TCPPortHandler {
    /// If true, handle this connection as HTTPS using [`ServeConfig::Web`].
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub HTTPS: bool,
    /// If true, handle this connection as HTTP using [`ServeConfig::Web`].
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub HTTP: bool,
    /// The `ip:port` to forward raw TCP connections to. Mutually exclusive
    /// with `HTTPS`/`HTTP`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub TCPForward: String,
    /// If non-empty, terminate TLS before forwarding to `TCPForward`,
    /// permitting only this SNI name.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub TerminateTLS: String,
}

/// Describes a web server's configuration (mount-point → handler).
/// Mirrors Go's `ipn.WebServerConfig`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WebServerConfig {
    /// HTTP handlers keyed by mount point (`"/"`, `"/foo"`, ...).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub Handlers: BTreeMap<String, HTTPHandler>,
}

/// An HTTP handler — exactly one of `Proxy`, `Text`, `Path`, or `Redirect`
/// should be set. Mirrors Go's `ipn.HTTPHandler`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HTTPHandler {
    /// Reverse-proxy target URL (e.g. `"http://127.0.0.1:3000"`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub Proxy: String,
    /// Plaintext body to serve (primarily for testing).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub Text: String,
    /// Absolute path to a file/directory to serve (not yet implemented in
    /// rustscale; present for config compatibility).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub Path: String,
    /// Redirect target URL. If non-empty, the handler issues an HTTP redirect
    /// instead of proxying. May optionally start with `"<3xx>:"` to set the
    /// status code (default 302 Found). Supports `${HOST}` and
    /// `${REQUEST_URI}` expansion variables. Mirrors Go's
    /// `HTTPHandler.Redirect`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub Redirect: String,
}

impl ServeConfig {
    /// Returns the TCP handler for `port`, if any.
    pub fn tcp_handler(&self, port: u16) -> Option<&TCPPortHandler> {
        self.TCP.get(&port)
    }

    /// Whether funnel is enabled for any host:port.
    pub fn is_funnel_on(&self) -> bool {
        self.AllowFunnel.values().any(|b| *b)
    }

    /// Whether this config maps the given port to a TCP listener.
    pub fn ports(&self) -> Vec<u16> {
        self.TCP.keys().copied().collect()
    }

    /// Find the [`WebServerConfig`] for a given destination port, matching
    /// the HostPort key by its port suffix. Falls back to the node FQDN key.
    pub fn web_for_port(&self, port: u16, fqdn: &str) -> Option<&WebServerConfig> {
        let fqdn_key = format!("{}:{}", fqdn.trim_end_matches('.'), port);
        if let Some(w) = self.Web.get(&fqdn_key) {
            return Some(w);
        }
        let suffix = format!(":{port}");
        self.Web
            .iter()
            .find(|(hp, _)| hp.ends_with(&suffix))
            .map(|(_, w)| w)
    }

    /// Find the [`WebServerConfig`] for an exact `"host:port"` key (as used
    /// by the `Tailscale-Ingress-Target` header in Funnel dispatch).
    pub fn web_for_host_port(&self, host_port: &str) -> Option<&WebServerConfig> {
        self.Web.get(host_port)
    }

    /// Compute the ETag for this config — the hex-encoded SHA-256 of the
    /// canonical JSON serialization. Mirrors Go's `generateServeConfigETag`.
    pub fn etag(&self) -> String {
        let j = serde_json::to_vec(self).unwrap_or_default();
        let sum = sha256(&j);
        hex::encode(sum)
    }

    /// Whether this config has any handlers configured.
    pub fn is_empty(&self) -> bool {
        self.TCP.is_empty()
            && self.Web.is_empty()
            && self.Services.is_empty()
            && self.AllowFunnel.is_empty()
            && self.Foreground.is_empty()
    }

    /// Load serve config from `<dir>/serve-config.json`. Returns
    /// `ServeConfig::default()` if the file does not exist.
    pub fn load(dir: &Path) -> Result<Self, std::io::Error> {
        let path = dir.join("serve-config.json");
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = std::fs::read_to_string(&path)?;
        let cfg: Self = serde_json::from_str(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(cfg)
    }

    /// Save serve config to `<dir>/serve-config.json` atomically.
    pub fn save(&self, dir: &Path) -> Result<(), std::io::Error> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join("serve-config.json");
        let tmp = dir.join(format!("serve-config.json.tmp.{}", std::process::id()));
        let data = serde_json::to_vec_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&tmp, &data)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }
}

/// Compute SHA-256 digest of `data`.
fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// Funnel validation
// ---------------------------------------------------------------------------

/// Errors from Funnel access checks. Mirrors Go's `ipn.CheckFunnelAccess` /
/// `NodeCanFunnel` / `CheckFunnelPort` error conditions.
#[derive(Debug, thiserror::Error)]
pub enum FunnelError {
    /// HTTPS is not enabled on the tailnet (the node lacks the `https`
    /// capability, i.e. `DNSConfig.CertDomains` is empty). This is the
    /// expected state on API-only tailnets where funnel cannot be granted.
    #[error("Funnel not available; HTTPS must be enabled. See https://tailscale.com/s/https")]
    HttpsNotEnabled,
    /// The node does not have the `funnel` node attribute. On API-only
    /// tailnets control never grants this, so callers get this clean typed
    /// error rather than a generic failure.
    #[error("Funnel not available; \"funnel\" node attribute not set. See https://tailscale.com/s/no-funnel")]
    NotEnabled,
    /// The requested port is not in the allowed funnel ports set.
    #[error("port {0} is not allowed for funnel; allowed ports are: 443, 8443, 10000")]
    PortNotAllowed(u16),
}

/// Check whether Funnel access is allowed for the given port and self node.
/// Mirrors Go's `ipn.CheckFunnelAccess(port, node)`.
///
/// Checks:
/// 1. The node has the `https` capability.
/// 2. The node has the `funnel` node attribute.
/// 3. The port is in the allowed funnel ports set (443/8443/10000).
pub fn check_funnel_access(port: u16, self_node: &Node) -> Result<(), FunnelError> {
    if !node_has_cap(self_node, CAP_HTTPS) {
        return Err(FunnelError::HttpsNotEnabled);
    }
    if !node_has_cap(self_node, NODE_ATTR_FUNNEL) {
        return Err(FunnelError::NotEnabled);
    }
    check_funnel_port(port, self_node)
}

/// Check the port against the funnel-ports capability. If the capability is
/// absent, fall back to the default set [`FUNNEL_PORTS`].
pub fn check_funnel_port(port: u16, self_node: &Node) -> Result<(), FunnelError> {
    if let Some(allowed) = funnel_ports_from_capmap(&self_node.CapMap) {
        if allowed.contains(&port) {
            return Ok(());
        }
        return Err(FunnelError::PortNotAllowed(port));
    }
    if FUNNEL_PORTS.contains(&port) {
        Ok(())
    } else {
        Err(FunnelError::PortNotAllowed(port))
    }
}

/// Whether `node` has the given capability in `Capabilities` or `CapMap`.
fn node_has_cap(node: &Node, cap: &str) -> bool {
    if node.Capabilities.iter().any(|c| c == cap) {
        return true;
    }
    node.CapMap.contains_key(cap)
}

/// Parse the allowed funnel ports from the `https://tailscale.com/cap/funnel-ports`
/// capability in `CapMap`. The capability value is a JSON object with a
/// `ports` query-string-style field, e.g. `{"ports":"443,8443,10000"}`.
fn funnel_ports_from_capmap(capmap: &NodeCapMap) -> Option<Vec<u16>> {
    let raw = capmap.get(CAP_FUNNEL_PORTS)?;
    let first = raw.first()?;
    let obj: serde_json::Value = serde_json::from_str(&first.0).ok()?;
    let ports_str = obj.get("ports")?.as_str()?;
    Some(
        ports_str
            .split(',')
            .filter_map(|s| s.trim().parse::<u16>().ok())
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// Serve runner — manages netstack listeners per configured port
// ---------------------------------------------------------------------------

/// A running serve configuration: one netstack listener task per configured
/// port, plus the shared config + identity data needed for dispatch.
pub(crate) struct ServeRunner {
    config: Arc<RwLock<ServeConfig>>,
    cert_provider: std::sync::Mutex<Option<Arc<dyn CertProvider>>>,
    peers: Arc<RwLock<Vec<Node>>>,
    user_profiles: Arc<RwLock<BTreeMap<UserID, UserProfile>>>,
    our_fqdn: String,
    netstack: Arc<Netstack>,
    /// The active generation's cancel token. Replaced on each `set_config`.
    cancel: std::sync::Mutex<Arc<CancelToken>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

/// Simple cancellation token (mirrors the one in lib.rs but local to serve).
pub(crate) struct CancelToken {
    cancelled: std::sync::atomic::AtomicBool,
}

impl CancelToken {
    fn new() -> Self {
        Self {
            cancelled: std::sync::atomic::AtomicBool::new(false),
        }
    }
    fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl ServeRunner {
    /// Build a new runner. The cert provider is installed later via
    /// [`set_config`](Self::set_config) when the config requires TLS.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        netstack: Arc<Netstack>,
        peers: Arc<RwLock<Vec<Node>>>,
        user_profiles: Arc<RwLock<BTreeMap<UserID, UserProfile>>>,
        our_fqdn: String,
    ) -> Self {
        Self {
            config: Arc::new(RwLock::new(ServeConfig::default())),
            cert_provider: std::sync::Mutex::new(None),
            peers,
            user_profiles,
            our_fqdn,
            netstack,
            cancel: std::sync::Mutex::new(Arc::new(CancelToken::new())),
            tasks: Mutex::new(vec![]),
        }
    }

    /// Whether any funnel (public internet) endpoint is currently active.
    /// Used by the Hostinfo update loop to set `IngressEnabled`.
    pub(crate) async fn is_funnel_on(&self) -> bool {
        self.config.read().await.is_funnel_on()
    }

    /// Replace the serve config, stopping old listeners and starting new ones
    /// for the configured ports. `cert_provider` is installed for TLS handlers
    /// (HTTPS / TLS-terminated TCP forward); pass `None` to clear it. Returns
    /// the list of ports now being served.
    pub(crate) async fn set_config(
        &self,
        cfg: ServeConfig,
        cert_provider: Option<Arc<dyn CertProvider>>,
    ) -> Result<Vec<u16>, ServeError> {
        // Install the cert provider (if provided; None keeps the existing one).
        if let Some(cp) = cert_provider {
            *self.cert_provider.lock().expect("cert mutex") = Some(cp);
        }

        // Cancel the old generation and abort its tasks.
        {
            let old = self.cancel.lock().expect("cancel mutex").clone();
            old.cancel();
        }
        {
            let mut tasks = self.tasks.lock().await;
            for t in tasks.drain(..) {
                t.abort();
            }
        }

        // Install a fresh cancel token for the new generation.
        let new_cancel = Arc::new(CancelToken::new());
        *self.cancel.lock().expect("cancel mutex") = new_cancel.clone();

        // Store the new config.
        *self.config.write().await = cfg.clone();

        // Start listeners for each configured port.
        let mut started = Vec::new();
        let mut new_tasks = Vec::new();
        for port in cfg.ports() {
            let handler = cfg.tcp_handler(port).cloned();
            let Some(handler) = handler else { continue };
            let listener = match self.netstack.listen(port).await {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("tsnet: serve listener on port {port} failed: {e}");
                    continue;
                }
            };
            started.push(port);
            let cfg_arc = self.config.clone();
            let cert = self.cert_provider.lock().expect("cert mutex").clone();
            let peers = self.peers.clone();
            let ups = self.user_profiles.clone();
            let fqdn = self.our_fqdn.clone();
            new_tasks.push(tokio::spawn(serve_listener_loop(
                listener,
                port,
                handler,
                cfg_arc,
                cert,
                peers,
                ups,
                fqdn,
                new_cancel.clone(),
            )));
        }
        {
            let mut tasks = self.tasks.lock().await;
            *tasks = new_tasks;
        }
        Ok(started)
    }

    /// Stop all serve listeners.
    pub(crate) async fn stop(&self) {
        {
            let cancel = self.cancel.lock().expect("cancel mutex").clone();
            cancel.cancel();
        }
        let mut tasks = self.tasks.lock().await;
        for t in tasks.drain(..) {
            t.abort();
        }
    }
}

/// The per-port listener loop: accepts connections and dispatches each to the
/// appropriate handler based on the [`TCPPortHandler`] config.
async fn serve_listener_loop(
    mut listener: Listener,
    port: u16,
    handler: TCPPortHandler,
    cfg: Arc<RwLock<ServeConfig>>,
    cert: Option<Arc<dyn CertProvider>>,
    peers: Arc<RwLock<Vec<Node>>>,
    ups: Arc<RwLock<BTreeMap<UserID, UserProfile>>>,
    fqdn: String,
    cancel: Arc<CancelToken>,
) {
    loop {
        if cancel.is_cancelled() {
            break;
        }
        let accept =
            tokio::time::timeout(std::time::Duration::from_millis(500), listener.accept()).await;
        let stream = match accept {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                eprintln!("tsnet: serve accept on port {port} failed: {e}");
                continue;
            }
            Err(_) => continue, // periodic cancel check
        };
        let cfg = cfg.clone();
        let cert = cert.clone();
        let peers = peers.clone();
        let ups = ups.clone();
        let fqdn = fqdn.clone();
        let handler = handler.clone();
        tokio::spawn(async move {
            if let Err(e) =
                dispatch_serve(stream, port, &handler, &cfg, cert, &peers, &ups, &fqdn).await
            {
                eprintln!("tsnet: serve dispatch on port {port} failed: {e}");
            }
        });
    }
}

/// Dispatch a single accepted connection to the configured handler.
async fn dispatch_serve(
    stream: NetstackStream,
    port: u16,
    handler: &TCPPortHandler,
    cfg: &Arc<RwLock<ServeConfig>>,
    cert: Option<Arc<dyn CertProvider>>,
    peers: &Arc<RwLock<Vec<Node>>>,
    ups: &Arc<RwLock<BTreeMap<UserID, UserProfile>>>,
    fqdn: &str,
) -> Result<(), ServeError> {
    let src_ip = peer_ip_from_stream(&stream);

    if handler.HTTPS || handler.HTTP {
        // Web handler (HTTP or HTTPS).
        if handler.HTTPS {
            let Some(cert) = cert else {
                return Err(ServeError::NoCertProvider);
            };
            // Peek at the first byte to detect plain HTTP vs TLS ClientHello.
            // A TLS ClientHello starts with 0x16 (Handshake); an HTTP request
            // starts with an ASCII method letter (GET, POST, etc.).
            let mut first = [0u8; 1];
            use tokio::io::AsyncReadExt;
            let mut rd_stream = stream;
            let n = rd_stream.read(&mut first).await.unwrap_or(0);
            if n == 0 {
                return Ok(());
            }
            if first[0] != 0x16 {
                // Plain HTTP on an HTTPS port — redirect to HTTPS.
                let cfg_snap = cfg.read().await;
                let host = cfg_snap
                    .web_for_port(port, fqdn)
                    .and_then(|_| {
                        cfg_snap
                            .Web
                            .keys()
                            .find(|hp| hp.ends_with(&format!(":{port}")))
                            .cloned()
                    })
                    .and_then(|hp| hp.split(':').next().map(std::string::ToString::to_string))
                    .unwrap_or_else(|| fqdn.to_string());
                let mut http_stream = PrefixedNetstackStream::new(first[0], rd_stream);
                let _ = write_https_redirect(&mut http_stream, &host, port).await;
                return Ok(());
            }
            // It's TLS — prepend the consumed byte and accept.
            let chained = PrefixedNetstackStream::new(first[0], rd_stream);
            let acceptor = build_tls_acceptor(cert)?;
            let tls = acceptor.accept(chained).await?;
            handle_http(tls, port, cfg, fqdn, src_ip, peers, ups).await?;
        } else {
            handle_http(stream, port, cfg, fqdn, src_ip, peers, ups).await?;
        }
        return Ok(());
    }

    if !handler.TCPForward.is_empty() {
        if handler.TerminateTLS.is_empty() {
            tcp_forward(stream, &handler.TCPForward).await?;
        } else {
            let Some(cert) = cert else {
                return Err(ServeError::NoCertProvider);
            };
            let acceptor = build_tls_acceptor(cert)?;
            let tls = acceptor.accept(stream).await?;
            tcp_forward(tls, &handler.TCPForward).await?;
        }
        return Ok(());
    }

    Err(ServeError::EmptyHandler)
}

/// A wrapper around [`NetstackStream`] that yields a single prepended byte
/// before delegating to the inner stream. Used to re-inject a byte consumed
/// during TLS-vs-HTTP sniffing.
struct PrefixedNetstackStream {
    prefix: Option<u8>,
    inner: NetstackStream,
}

impl PrefixedNetstackStream {
    fn new(first_byte: u8, inner: NetstackStream) -> Self {
        Self {
            prefix: Some(first_byte),
            inner,
        }
    }
}

impl AsyncRead for PrefixedNetstackStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if let Some(byte) = this.prefix.take() {
            if buf.remaining() > 0 {
                buf.put_slice(&[byte]);
                return std::task::Poll::Ready(Ok(()));
            }
        }
        std::pin::Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedNetstackStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Write an HTTP 301 redirect to `https://<host>:<port>/...` for a plain-HTTP
/// request on an HTTPS serve port. Mirrors Go's implicit HTTP→HTTPS redirect
/// when a funnel/HTTPS port receives a non-TLS connection.
async fn write_https_redirect<W: AsyncWrite + Unpin>(
    conn: &mut W,
    host: &str,
    https_port: u16,
) -> Result<(), ServeError> {
    let location = if https_port == 443 {
        format!("https://{host}/")
    } else {
        format!("https://{host}:{https_port}/")
    };
    let body = format!("Redirecting to <a href=\"{location}\">{location}</a>\n");
    let resp = format!(
        "HTTP/1.1 301 Moved Permanently\r\n\
         Location: {location}\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        body.len(),
        body
    );
    conn.write_all(resp.as_bytes()).await?;
    conn.flush().await?;
    Ok(())
}

/// Extract the remote peer IP from a netstack stream (best-effort; may be
/// zero if unavailable).
fn peer_ip_from_stream(_stream: &NetstackStream) -> Option<IpAddr> {
    // NetstackStream does not currently expose the remote address. In a future
    // revision the netstack will carry the peer endpoint through the accept
    // channel; for now we return None and the HTTP proxy omits the
    // Tailscale-User headers (matching Go's behavior for non-tailnet traffic).
    None
}

/// Build a TLS acceptor from a cert provider.
fn build_tls_acceptor(
    provider: Arc<dyn CertProvider>,
) -> Result<tokio_rustls::TlsAcceptor, ServeError> {
    let cert_chain = provider.cert_chain();
    let key = provider.private_key();
    let server_config = rustls::server::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|e| ServeError::Tls(e.to_string()))?;
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(server_config)))
}

// ---------------------------------------------------------------------------
// TCP forward (raw proxy)
// ---------------------------------------------------------------------------

/// Forward a connection to `backend` (an `ip:port` or `host:port` string),
/// bridging bytes bidirectionally until either side closes. Hostnames are
/// resolved via the system resolver (matching Go's `net.Dial`).
pub(crate) async fn tcp_forward<S>(mut conn: S, backend: &str) -> Result<(), ServeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut back = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::TcpStream::connect(backend),
    )
    .await
    .map_err(|_| ServeError::BackendConnectTimeout)?
    .map_err(|e| ServeError::BackendConnect(e.to_string()))?;
    tokio::io::copy_bidirectional(&mut conn, &mut back).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// HTTP dispatch (web handlers)
// ---------------------------------------------------------------------------

/// Handle an HTTP/1.1 connection: parse the request, find the matching web
/// handler, and dispatch (text / proxy / 404).
pub(crate) async fn handle_http<S>(
    mut conn: S,
    port: u16,
    cfg: &Arc<RwLock<ServeConfig>>,
    fqdn: &str,
    src_ip: Option<IpAddr>,
    peers: &Arc<RwLock<Vec<Node>>>,
    ups: &Arc<RwLock<BTreeMap<UserID, UserProfile>>>,
) -> Result<(), ServeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let req = match read_request(&mut conn).await {
        Ok(r) => r,
        Err(e) => {
            let _ = write_simple_response(&mut conn, 400, "Bad Request", &e).await;
            return Ok(());
        }
    };

    let cfg_snap = cfg.read().await;
    let web = cfg_snap.web_for_port(port, fqdn);

    let Some(web) = web else {
        let _ = write_simple_response(&mut conn, 404, "Not Found", "no web handler").await;
        return Ok(());
    };

    // Longest-prefix mount match (mirrors Go's getServeHandler loop).
    let handler = match_mount(&web.Handlers, &req.path);
    let Some(handler) = handler else {
        let _ = write_simple_response(&mut conn, 404, "Not Found", "no handler for path").await;
        return Ok(());
    };

    // Funnel Ingress-Target dispatch: when a request carries the
    // `Tailscale-Ingress-Target` header (set by Tailscale's ingress servers
    // for Funnel), the target is the `host:port` to route to. If it matches a
    // web handler in the config, dispatch to that handler instead. Mirrors
    // Go's `handleServeIngress` → `HandleIngressTCPConn` path.
    if let Some(target) = req_header(&req.headers, "tailscale-ingress-target") {
        if let Some(ingress_web) = cfg_snap.web_for_host_port(&target) {
            if let Some(ingress_handler) = match_mount(&ingress_web.Handlers, &req.path) {
                return dispatch_handler(
                    &mut conn,
                    &req,
                    ingress_handler,
                    port,
                    fqdn,
                    src_ip,
                    peers,
                    ups,
                )
                .await;
            }
        }
    }

    dispatch_handler(&mut conn, &req, handler, port, fqdn, src_ip, peers, ups).await
}

/// Dispatch a matched handler: text, redirect, proxy, or 500.
async fn dispatch_handler<S>(
    conn: &mut S,
    req: &HttpRequest,
    handler: &HTTPHandler,
    _port: u16,
    _fqdn: &str,
    src_ip: Option<IpAddr>,
    peers: &Arc<RwLock<Vec<Node>>>,
    ups: &Arc<RwLock<BTreeMap<UserID, UserProfile>>>,
) -> Result<(), ServeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if !handler.Text.is_empty() {
        write_simple_response(conn, 200, "OK", &handler.Text).await?;
        return Ok(());
    }

    if !handler.Redirect.is_empty() {
        let (code, url) = parse_redirect_with_code(&handler.Redirect);
        let host = req_header(&req.headers, "host").unwrap_or_default();
        let request_uri = &req.path;
        let expanded = url
            .replace("${HOST}", &host)
            .replace("${REQUEST_URI}", request_uri);
        write_redirect_response(conn, code, &expanded).await?;
        return Ok(());
    }

    if !handler.Proxy.is_empty() {
        let whois = src_ip.and_then(|ip| {
            let p = peers.try_read().ok()?;
            let u = ups.try_read().ok()?;
            crate::whois_lookup(&p, &u, ip)
        });
        proxy_request(conn, req, &handler.Proxy, src_ip, whois.as_ref()).await?;
        return Ok(());
    }

    write_simple_response(conn, 500, "Internal Server Error", "empty handler").await?;
    Ok(())
}

/// Parse a redirect string that may optionally start with a 3xx status code
/// prefix (`"3xx:url"`). Returns `(status_code, url)`. Defaults to 302 Found.
/// Mirrors Go's `parseRedirectWithCode`.
fn parse_redirect_with_code(redirect: &str) -> (u16, String) {
    if redirect.len() >= 4 && redirect.as_bytes()[3] == b':' {
        if let Ok(code) = redirect[..3].parse::<u16>() {
            if (300..=399).contains(&code) {
                return (code, redirect[4..].to_string());
            }
        }
    }
    (302, redirect.to_string())
}

/// Write an HTTP redirect response.
async fn write_redirect_response<W: AsyncWrite + Unpin>(
    conn: &mut W,
    code: u16,
    location: &str,
) -> Result<(), ServeError> {
    let reason = match code {
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        _ => "Found",
    };
    let body = format!("Redirecting to <a href=\"{location}\">{location}</a>\n");
    let resp = format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Location: {location}\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        body.len(),
        body
    );
    conn.write_all(resp.as_bytes()).await?;
    conn.flush().await?;
    Ok(())
}

/// Case-insensitive header lookup.
fn req_header(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

/// Find the handler for a request path using longest-prefix mount matching.
/// Mirrors Go's `getServeHandler` directory-walk: try exact path, then
/// `path + "/"`, then walk up with `path.Dir`.
fn match_mount<'a>(
    handlers: &'a BTreeMap<String, HTTPHandler>,
    raw_path: &str,
) -> Option<&'a HTTPHandler> {
    if let Some(h) = handlers.get(raw_path) {
        return Some(h);
    }
    let mut cur = clean_path(raw_path);
    loop {
        let with_slash = format!("{cur}/");
        if let Some(h) = handlers.get(&with_slash) {
            return Some(h);
        }
        if let Some(h) = handlers.get(&cur) {
            return Some(h);
        }
        if cur == "/" || cur.is_empty() {
            return None;
        }
        match cur.rsplit_once('/') {
            Some((p, _)) => {
                let parent = if p.is_empty() {
                    "/".to_string()
                } else {
                    p.to_string()
                };
                if parent == cur {
                    return None;
                }
                cur = parent;
            }
            None => return None,
        }
    }
}

/// Simplified `path.Clean` for HTTP paths: resolve `.` and `..` segments.
fn clean_path(p: &str) -> String {
    if p.is_empty() {
        return "/".to_string();
    }
    let mut parts: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    let cleaned = parts.join("/");
    if cleaned.is_empty() {
        "/".to_string()
    } else if p.starts_with('/') {
        format!("/{cleaned}")
    } else {
        cleaned
    }
}

/// A minimal HTTP/1.1 request: method, path, and headers.
pub(crate) struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    /// Bytes read past the header end (body preview).
    pub body_preview: Vec<u8>,
}

/// Read an HTTP/1.1 request head from `conn`. Returns the parsed request plus
/// any body bytes already buffered.
pub(crate) async fn read_request<R: AsyncRead + Unpin>(
    conn: &mut R,
) -> Result<HttpRequest, String> {
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
            let body_preview = buf[end + 4..].to_vec();
            return parse_request_head(head, body_preview);
        }
        if buf.len() > 256 * 1024 {
            return Err("header too large".into());
        }
    }
}

/// Find the `\r\n\r\n` that terminates the HTTP head.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Parse the request line + headers from `head` bytes.
fn parse_request_head(head: &[u8], body_preview: Vec<u8>) -> Result<HttpRequest, String> {
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
    Ok(HttpRequest {
        method,
        path,
        headers,
        body_preview,
    })
}

/// Write a minimal HTTP/1.1 response with a text body.
pub(crate) async fn write_simple_response<W: AsyncWrite + Unpin>(
    conn: &mut W,
    status: u16,
    reason: &str,
    body: &str,
) -> Result<(), ServeError> {
    let body_bytes = body.as_bytes();
    let resp = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body_bytes.len()
    );
    conn.write_all(resp.as_bytes()).await?;
    conn.write_all(body_bytes).await?;
    conn.flush().await?;
    Ok(())
}

/// Reverse-proxy a request to `backend_url`, adding `Host`, `X-Forwarded-For`,
/// and `Tailscale-User-Login`/`Tailscale-User-Name` headers (from WhoIs).
pub(crate) async fn proxy_request<W: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut W,
    req: &HttpRequest,
    backend_url: &str,
    src_ip: Option<IpAddr>,
    whois: Option<&crate::WhoIsInfo>,
) -> Result<(), ServeError> {
    let (host, port, path) = parse_proxy_url(backend_url)?;
    // Build the outbound request from the raw head, rewriting the request
    // line path and injecting proxy headers.
    use std::fmt::Write as _;
    let mut out = String::new();
    write!(out, "{} {} HTTP/1.1\r\n", req.method, path).unwrap();
    for (k, v) in &req.headers {
        let kl = k.to_lowercase();
        if matches!(
            kl.as_str(),
            "host"
                | "x-forwarded-for"
                | "x-forwarded-host"
                | "x-forwarded-proto"
                | "tailscale-user-login"
                | "tailscale-user-name"
                | "tailscale-user-profile-pic"
                | "tailscale-headers-info"
                | "connection"
        ) {
            continue;
        }
        write!(out, "{k}: {v}\r\n").unwrap();
    }
    write!(out, "Host: {host}:{port}\r\n").unwrap();
    if let Some(ip) = src_ip {
        write!(out, "X-Forwarded-For: {ip}\r\n").unwrap();
    }
    let orig_host = req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    if !orig_host.is_empty() {
        write!(out, "X-Forwarded-Host: {orig_host}\r\n").unwrap();
        out.push_str("X-Forwarded-Proto: https\r\n");
    }
    if let Some(w) = whois {
        if !w.login_name.is_empty() {
            write!(out, "Tailscale-User-Login: {}\r\n", w.login_name).unwrap();
        }
        if !w.display_name.is_empty() {
            write!(out, "Tailscale-User-Name: {}\r\n", w.display_name).unwrap();
        }
        out.push_str("Tailscale-Headers-Info: https://tailscale.com/s/serve-headers\r\n");
    }
    out.push_str("Connection: close\r\n\r\n");

    // Connect to the backend.
    let mut back = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::TcpStream::connect((host.as_str(), port)),
    )
    .await
    .map_err(|_| ServeError::BackendConnectTimeout)?
    .map_err(|e| ServeError::BackendConnect(e.to_string()))?;

    back.write_all(out.as_bytes()).await?;
    // Write any body bytes that were already read with the header.
    if !req.body_preview.is_empty() {
        back.write_all(&req.body_preview).await?;
    }
    back.flush().await?;

    // Bridge the remaining bytes in both directions. `conn` still has unread
    // body bytes (for streaming/chunked requests) and `back` will produce the
    // response. copy_bidirectional handles both until EOF.
    tokio::io::copy_bidirectional(conn, &mut back).await?;
    Ok(())
}

/// Parse a proxy target URL into (host, port, path). Accepts:
/// `http://host:port/path`, `host:port`, `port` (→ 127.0.0.1:port).
fn parse_proxy_url(url: &str) -> Result<(String, u16, String), ServeError> {
    let url = url.trim();
    if url.is_empty() {
        return Err(ServeError::BadBackend("empty proxy url".into()));
    }
    // Strip scheme.
    let (scheme, rest) = if let Some(r) = url.strip_prefix("http://") {
        ("http", r)
    } else if let Some(r) = url.strip_prefix("https://") {
        ("https", r)
    } else {
        ("http", url)
    };
    let _ = scheme;
    // Split path.
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    // If the whole thing is a port number, default to 127.0.0.1.
    if authority.parse::<u16>().is_ok() && !url.contains("://") && !url.contains(':') {
        let port: u16 = authority.parse().unwrap();
        return Ok(("127.0.0.1".into(), port, path.into()));
    }
    let (host, port) = match authority.rfind(':') {
        Some(i) => (&authority[..i], authority[i + 1..].parse().unwrap_or(80)),
        None => (authority, 80),
    };
    Ok((host.into(), port, path.into()))
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from serve operations.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error("serve handler is empty (no TCPForward/HTTP/HTTPS)")]
    EmptyHandler,
    #[error("bad backend address: {0}")]
    BadBackend(String),
    #[error("backend connect timeout")]
    BackendConnectTimeout,
    #[error("backend connect failed: {0}")]
    BackendConnect(String),
    #[error("no cert provider available for HTTPS handler")]
    NoCertProvider,
    #[error("tls error: {0}")]
    Tls(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("netstack error: {0}")]
    Netstack(#[from] rustscale_netstack::NetstackError),
}

// ---------------------------------------------------------------------------
// Re-exports for the public API
// ---------------------------------------------------------------------------

#[cfg(test)]
#[path = "serve_tests.rs"]
mod serve_tests;
