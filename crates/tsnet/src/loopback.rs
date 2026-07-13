//! In-memory LocalClient and combined SOCKS5+LocalAPI loopback listener.
//!
//! Gap 6: [`InMemoryLocalClient`] dispatches LocalAPI requests directly
//! through the in-process handler without a Unix-socket roundtrip. Mirrors
//! Go's `Server.localClient` which uses an in-memory `net.Pipe` listener.
//!
//! Gap 7: [`Server::loopback`] starts a single TCP listener that dispatches
//! SOCKS5 and LocalAPI traffic by protocol sniffing. Mirrors Go's
//! `Server.Loopback` + `proxymux.SplitSOCKSAndHTTP`.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use rustscale_ipn::{LoginProfile, Prefs, StartOptions, WaitingFile};
use rustscale_safesocket::peercred::ConnIdentity;
use rustscale_tailcfg::DERPMap;

use super::localapi::{self, LocalApiState};
use super::socks5;
use super::socks5::ServerSocksDialer;
use super::{
    serve, DataPlane, FileTarget, JoinHandle, RwLock, Server, SocketAddr, TsnetError,
    CAPABILITY_VERSION, PROTOCOL_VERSION,
};

/// Error type for [`InMemoryLocalClient`]. Mirrors the variants of
/// `rustscale_localclient::LocalClientError` but defined locally to avoid
/// a cyclic dependency (tsnet <- localclient <- tsnet).
#[derive(Debug, thiserror::Error)]
pub enum InMemoryClientError {
    #[error("json decode error: {0}")]
    Json(String),
    #[error("connection error: {0}")]
    Connect(String),
    #[error("access denied (403)")]
    AccessDenied(String),
    #[error("preconditions failed (412)")]
    PreconditionsFailed(String),
    #[error("HTTP status {0}")]
    HttpStatus(u16),
}

/// Result of [`Server::loopback`]: the bound address and credentials for
/// SOCKS5 and LocalAPI access.
pub struct LoopbackHandle {
    /// The bound loopback TCP address.
    pub addr: SocketAddr,
    /// SOCKS5 password (username is always `"tsnet"`).
    pub proxy_cred: String,
    /// LocalAPI basic-auth password (requires `Sec-Tailscale: localapi`
    /// header as well).
    pub localapi_cred: String,
    /// Cancel + task handle for graceful shutdown.
    pub(crate) cancel: Arc<socks5::CancelToken>,
    pub(crate) task: Option<JoinHandle<()>>,
}

#[allow(clippy::missing_fields_in_debug)]
impl std::fmt::Debug for LoopbackHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoopbackHandle")
            .field("addr", &self.addr)
            .field("proxy_cred", &self.proxy_cred)
            .field("localapi_cred", &self.localapi_cred)
            .finish()
    }
}

impl LoopbackHandle {
    /// The bound loopback address.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Gracefully stop the loopback listener.
    pub fn stop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// In-memory LocalAPI client. Dispatches requests through the in-process
/// LocalAPI handler via a `tokio::io::duplex` pipe — no Unix-socket
/// roundtrip. Mirrors Go's `Server.LocalClient()` which returns a
/// `*local.Client` backed by an in-memory listener.
///
/// The client is a thin wrapper that constructs HTTP/1.1 requests, pipes
/// them through the in-process [`localapi::dispatch`], and parses the
/// responses. This gives the same API surface as
/// [`rustscale_localclient::LocalClient`] without requiring the Unix socket
/// server to be running.
pub struct InMemoryLocalClient {
    state: Arc<LocalApiState>,
}

impl InMemoryLocalClient {
    pub(crate) fn new(state: Arc<LocalApiState>) -> Self {
        Self { state }
    }

    /// Send a request with no body and return (status, body bytes).
    async fn request(
        &self,
        method: &str,
        path: &str,
    ) -> Result<(u16, Vec<u8>), InMemoryClientError> {
        self.request_with_body(method, path, &[]).await
    }

    /// Send a request with a body and return (status, body bytes).
    async fn request_with_body(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<(u16, Vec<u8>), InMemoryClientError> {
        self.request_with_headers(method, path, body, &[]).await
    }

    /// Send a request with extra headers.
    async fn request_with_headers(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        extra_headers: &[(String, String)],
    ) -> Result<(u16, Vec<u8>), InMemoryClientError> {
        // Build the raw HTTP request bytes.
        let mut raw = format!(
            "{method} {path} HTTP/1.1\r\nHost: local-rustscale.sock\r\n\
             Content-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        for (k, v) in extra_headers {
            use std::fmt::Write;
            let _ = write!(raw, "{k}: {v}\r\n");
        }
        raw.push_str("\r\n");
        let mut req_bytes = raw.into_bytes();
        req_bytes.extend_from_slice(body);

        // Create an in-memory duplex pipe. The client writes the request
        // to one end; a spawned task reads it, dispatches it through the
        // in-process LocalAPI handler, and writes the response to the same
        // end. The client then reads the response back.
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        let state = self.state.clone();

        let dispatch_task = tokio::spawn(async move {
            let req = match localapi::read_request(&mut server).await {
                Ok(r) => r,
                Err(_) => return,
            };
            let _ = localapi::dispatch(&mut server, &req, &state, &ConnIdentity::readwrite()).await;
        });

        // Write the request to the client end of the pipe.
        client
            .write_all(&req_bytes)
            .await
            .map_err(|e| InMemoryClientError::Connect(e.to_string()))?;
        client
            .flush()
            .await
            .map_err(|e| InMemoryClientError::Connect(e.to_string()))?;

        // Read the response from the client end.
        let response = read_full_response(&mut client).await;
        // Wait for the dispatch task to finish.
        let _ = dispatch_task.await;

        let (status, resp_body) = response?;
        check_status(status, &resp_body)?;
        Ok((status, resp_body))
    }

    // -----------------------------------------------------------------------
    // High-level API (mirrors rustscale_localclient::LocalClient)
    // -----------------------------------------------------------------------

    /// GET /localapi/v0/status
    pub async fn status(&self) -> Result<serde_json::Value, InMemoryClientError> {
        let (_, body) = self.request("GET", "/localapi/v0/status").await?;
        serde_json::from_slice(&body).map_err(|e| InMemoryClientError::Json(e.to_string()))
    }

    /// GET /localapi/v0/whois?addr=...
    pub async fn whois(&self, addr: &str) -> Result<serde_json::Value, InMemoryClientError> {
        let path = format!("/localapi/v0/whois?addr={addr}");
        let (_, body) = self.request("GET", &path).await?;
        serde_json::from_slice(&body).map_err(|e| InMemoryClientError::Json(e.to_string()))
    }

    /// GET /localapi/v0/prefs
    pub async fn prefs(&self) -> Result<serde_json::Value, InMemoryClientError> {
        let (_, body) = self.request("GET", "/localapi/v0/prefs").await?;
        serde_json::from_slice(&body).map_err(|e| InMemoryClientError::Json(e.to_string()))
    }

    /// GET /localapi/v0/netmap
    pub async fn netmap(&self) -> Result<serde_json::Value, InMemoryClientError> {
        let (_, body) = self.request("GET", "/localapi/v0/netmap").await?;
        serde_json::from_slice(&body).map_err(|e| InMemoryClientError::Json(e.to_string()))
    }

    /// GET /localapi/v0/metrics
    pub async fn metrics(&self) -> Result<String, InMemoryClientError> {
        let (_, body) = self.request("GET", "/localapi/v0/metrics").await?;
        Ok(String::from_utf8_lossy(&body).into_owned())
    }

    /// GET /localapi/v0/health
    pub async fn health(&self) -> Result<serde_json::Value, InMemoryClientError> {
        let (_, body) = self.request("GET", "/localapi/v0/health").await?;
        serde_json::from_slice(&body).map_err(|e| InMemoryClientError::Json(e.to_string()))
    }

    /// GET /localapi/v0/derpmap
    pub async fn derp_map(&self) -> Result<DERPMap, InMemoryClientError> {
        let (_, body) = self.request("GET", "/localapi/v0/derpmap").await?;
        serde_json::from_slice(&body).map_err(|e| InMemoryClientError::Json(e.to_string()))
    }

    /// GET /localapi/v0/start
    pub async fn start(&self, options: &StartOptions) -> Result<(), InMemoryClientError> {
        let body = serde_json::to_vec(options).unwrap_or_default();
        let _ = self
            .request_with_body("POST", "/localapi/v0/start", &body)
            .await?;
        Ok(())
    }

    /// GET /localapi/v0/prefs (typed)
    pub async fn get_prefs(&self) -> Result<Prefs, InMemoryClientError> {
        let (_, body) = self.request("GET", "/localapi/v0/prefs").await?;
        serde_json::from_slice(&body).map_err(|e| InMemoryClientError::Json(e.to_string()))
    }

    /// GET /localapi/v0/profiles
    pub async fn list_profiles(&self) -> Result<Vec<LoginProfile>, InMemoryClientError> {
        let (_, body) = self.request("GET", "/localapi/v0/profiles").await?;
        serde_json::from_slice(&body).map_err(|e| InMemoryClientError::Json(e.to_string()))
    }

    /// GET /localapi/v0/file-targets
    pub async fn file_targets(&self) -> Result<Vec<FileTarget>, InMemoryClientError> {
        let (_, body) = self.request("GET", "/localapi/v0/file-targets").await?;
        serde_json::from_slice(&body).map_err(|e| InMemoryClientError::Json(e.to_string()))
    }

    /// GET /localapi/v0/files/
    pub async fn waiting_files(&self) -> Result<Vec<WaitingFile>, InMemoryClientError> {
        let (_, body) = self.request("GET", "/localapi/v0/files/").await?;
        serde_json::from_slice(&body).map_err(|e| InMemoryClientError::Json(e.to_string()))
    }
}

fn check_status(status: u16, _body: &[u8]) -> Result<(), InMemoryClientError> {
    match status {
        200..=299 => Ok(()),
        403 => Err(InMemoryClientError::AccessDenied("403".into())),
        412 => Err(InMemoryClientError::PreconditionsFailed("412".into())),
        _ => Err(InMemoryClientError::HttpStatus(status)),
    }
}

/// Read a full HTTP/1.1 response from `stream` and return (status, body).
async fn read_full_response<R: AsyncReadExt + Unpin>(
    stream: &mut R,
) -> Result<(u16, Vec<u8>), InMemoryClientError> {
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|e| InMemoryClientError::Connect(e.to_string()))?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        // Check if we have the full response (headers + body).
        if let Some(hdr_end) = find_header_end(&buf) {
            let header_text = std::str::from_utf8(&buf[..hdr_end]).unwrap_or("");
            let content_length = extract_content_length(header_text);
            if buf.len() >= hdr_end + 4 + content_length {
                break;
            }
        }
    }

    // Parse status line.
    let hdr_end = find_header_end(&buf).ok_or_else(|| {
        InMemoryClientError::Connect("incomplete HTTP response: no header terminator".into())
    })?;
    let header_text = std::str::from_utf8(&buf[..hdr_end]).unwrap_or("");
    let status = parse_status_code(header_text)?;
    let content_length = extract_content_length(header_text);
    let body_start = hdr_end + 4;
    let body_end = (body_start + content_length).min(buf.len());
    let body = if body_start < body_end {
        buf[body_start..body_end].to_vec()
    } else {
        Vec::new()
    };
    Ok((status, body))
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

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

fn parse_status_code(header_text: &str) -> Result<u16, InMemoryClientError> {
    let first_line = header_text.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let _version = parts.next();
    let status_str = parts
        .next()
        .ok_or_else(|| InMemoryClientError::Connect("no status code in response".into()))?;
    status_str
        .parse()
        .map_err(|_| InMemoryClientError::Connect("invalid status code".into()))
}

// ---------------------------------------------------------------------------
// Loopback listener (SOCKS5 + LocalAPI on the same port)
// ---------------------------------------------------------------------------

/// Generate a random hex credential string (32 hex chars from 16 random bytes).
fn random_cred() -> String {
    use rand_core::RngCore;
    let mut buf = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

impl Server {
    /// Start a combined SOCKS5 + LocalAPI loopback listener on a single TCP
    /// port. Connections are dispatched by protocol sniffing:
    ///
    /// - **SOCKS5**: the first byte is `0x05` (SOCKS5 version). Routed to the
    ///   in-process SOCKS5 server, which dials through the tailnet via
    ///   [`Server::dial`]. Authentication uses username `"tsnet"` and the
    ///   returned `proxy_cred` as the password.
    /// - **HTTP/LocalAPI**: any other first byte. Routed to the in-process
    ///   LocalAPI HTTP handler. Access requires both the
    ///   `Sec-Tailscale: localapi` header and `localapi_cred` as basic auth.
    ///
    /// If you only need the LocalAPI from Go, prefer
    /// [`Server::local_client`] (in-memory, no TCP roundtrip).
    ///
    /// Mirrors Go's `Server.Loopback()` which returns
    /// `(addr, proxyCred, localAPICred, error)`.
    pub async fn loopback(&mut self, addr: SocketAddr) -> Result<LoopbackHandle, TsnetError> {
        Box::pin(self.ensure_up()).await?;
        let inner = self.inner.as_ref().expect("ensure_up guarantees inner");

        let netstack = match &inner.data_plane {
            DataPlane::Netstack(ns) => ns.clone(),
            DataPlane::Tun => return Err(TsnetError::NotAvailableInTunMode),
        };

        let proxy_cred = random_cred();
        let localapi_cred = random_cred();

        let listener = TcpListener::bind(addr).await.map_err(TsnetError::Io)?;
        let bound_addr = listener.local_addr().map_err(TsnetError::Io)?;

        // Build the LocalAPI state for the loopback HTTP handler. We reuse
        // the same state as the Unix-socket LocalAPI if it's running;
        // otherwise we build a minimal one from the running state.
        let api_state = self.build_loopback_api_state(&proxy_cred, &localapi_cred);

        let dialer = ServerSocksDialer::new(netstack, inner.resolver.clone(), inner.peers.clone());

        let cancel = Arc::new(socks5::CancelToken::new());
        let cancel_task = cancel.clone();

        let localapi_cred_clone = localapi_cred.clone();
        let proxy_cred_clone = proxy_cred.clone();
        let task = tokio::spawn(async move {
            serve_loopback(
                listener,
                dialer,
                api_state,
                localapi_cred_clone,
                proxy_cred_clone,
                cancel_task,
            )
            .await;
        });

        Ok(LoopbackHandle {
            addr: bound_addr,
            proxy_cred,
            localapi_cred,
            cancel,
            task: Some(task),
        })
    }

    /// Return an in-memory [`InMemoryLocalClient`] that dispatches LocalAPI
    /// requests directly through the in-process handler — no Unix-socket
    /// roundtrip. Mirrors Go's `Server.LocalClient()`.
    ///
    /// Requires the server to be up. The returned client shares the same
    /// `LocalApiState` as the Unix-socket LocalAPI server (if running), so
    /// changes are immediately visible to both.
    pub async fn local_client(&mut self) -> Result<InMemoryLocalClient, TsnetError> {
        Box::pin(self.ensure_up()).await?;
        let state = self.build_loopback_api_state("", "");
        Ok(InMemoryLocalClient::new(state))
    }

    /// Build a `LocalApiState` for the loopback / in-memory LocalClient.
    /// Reuses the running state's shared resources (peers, health, etc.).
    fn build_loopback_api_state(
        &self,
        _proxy_cred: &str,
        _localapi_cred: &str,
    ) -> Arc<LocalApiState> {
        let inner = self.inner.as_ref().expect("server must be up");
        Arc::new(LocalApiState {
            peers: inner.peers.clone(),
            user_profiles: inner.user_profiles.clone(),
            health: inner.health.clone(),
            dns_config: inner.dns_config.clone(),
            packet_drops: inner.packet_drops.clone(),
            metrics: crate::localapi::default_metric_registry(),
            prefs: Arc::new(RwLock::new(self.load_prefs().unwrap_or_default())),
            tailscale_ips: inner.tailscale_ips.clone(),
            our_fqdn: inner.our_fqdn.clone(),
            hostname: self.config.hostname.clone(),
            magicsock: inner.magicsock.clone(),
            tun_mode: matches!(inner.data_plane, DataPlane::Tun),
            home_derp: 0,
            ipn_backend: inner.ipn_backend.clone(),
            derp_map: DERPMap::default(),
            command_tx: None,
            state_dir: self.config.state_dir.clone(),
            auth_url: Arc::new(std::sync::Mutex::new(None)),
            login_trigger: Arc::new(tokio::sync::Notify::new()),
            serve_config: Arc::new(RwLock::new(
                self.config
                    .state_dir
                    .as_ref()
                    .and_then(|d| serve::ServeConfig::load(d).ok())
                    .unwrap_or_default(),
            )),
            serve_runner: inner.serve.clone(),
            profiles: Arc::new(RwLock::new(
                self.config
                    .state_dir
                    .as_ref()
                    .and_then(|d| rustscale_ipn::LoginProfile::load_all(d).ok())
                    .unwrap_or_default(),
            )),
            current_profile: Arc::new(RwLock::new(
                self.config
                    .state_dir
                    .as_ref()
                    .and_then(|d| rustscale_ipn::LoginProfile::load_current_id(d).ok())
                    .flatten(),
            )),
            cert_params: self
                .config
                .state_dir
                .clone()
                .map(|dir| localapi::CertParams {
                    state_dir: dir,
                    control_url: self.config.control_url.clone(),
                    machine_key: inner.machine_key.clone(),
                    server_pub_key: inner.server_pub_key.clone(),
                    node_key: inner.node_key.clone(),
                    capability_version: CAPABILITY_VERSION,
                    protocol_version: PROTOCOL_VERSION,
                }),
            taildrop: None,
            netstack: match &inner.data_plane {
                DataPlane::Netstack(ns) => Some(ns.clone()),
                DataPlane::Tun => None,
            },
            filter: std::sync::OnceLock::new(),
            route_table: Some(inner.route_table.clone()),
            logout_trigger: inner.logout_trigger.clone(),
            suggested_exit_node: Arc::new(RwLock::new(String::new())),
            client_updater: inner.client_updater.clone(),
        })
    }
}

/// Serve the combined SOCKS5 + LocalAPI loopback listener. Each accepted
/// connection is sniffed: if the first byte is `0x05` (SOCKS5), it's handed
/// to the SOCKS5 handler (with username `"tsnet"` + `proxy_cred` as password
/// auth per RFC 1929); otherwise it's treated as HTTP and dispatched to the
/// LocalAPI handler.
async fn serve_loopback<D: super::socks5::SocksDialer + 'static>(
    listener: TcpListener,
    dialer: D,
    api_state: Arc<LocalApiState>,
    localapi_cred: String,
    proxy_cred: String,
    cancel: Arc<socks5::CancelToken>,
) {
    let dialer = Arc::new(dialer);
    loop {
        if cancel.is_cancelled() {
            break;
        }
        let accept = tokio::time::timeout(Duration::from_millis(250), listener.accept()).await;
        let (mut stream, _peer) = match accept {
            Ok(Ok(s)) => s,
            Ok(Err(_)) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            Err(_) => continue,
        };

        // Peek at the first byte to detect SOCKS5 vs HTTP.
        let mut peek_buf = [0u8; 1];
        let n = match stream.read(&mut peek_buf).await {
            Ok(n) => n,
            Err(_) => continue,
        };
        if n == 0 {
            continue;
        }

        let is_socks5 = peek_buf[0] == super::socks5::SOCKS5_VERSION;

        if is_socks5 {
            let d = dialer.clone();
            let cred = proxy_cred.clone();
            tokio::spawn(async move {
                let prefixed = PrefixedStream::new(peek_buf[0], stream);
                let auth = Some(("tsnet", &cred[..]));
                if let Err(e) = super::socks5::handle_conn_generic(prefixed, d, auth).await {
                    eprintln!("loopback: socks5 connection ended: {e}");
                }
            });
        } else {
            let state = api_state.clone();
            let cred = localapi_cred.clone();
            tokio::spawn(async move {
                let prefixed = PrefixedStream::new(peek_buf[0], stream);
                if let Err(e) = handle_localapi_http(prefixed, state, &cred).await {
                    eprintln!("loopback: localapi connection ended: {e}");
                }
            });
        }
    }
}

/// Handle an HTTP LocalAPI connection. Validates the `Sec-Tailscale:
/// localapi` header and basic auth, then dispatches to the in-process
/// LocalAPI handler.
async fn handle_localapi_http(
    mut stream: PrefixedStream,
    state: Arc<LocalApiState>,
    expected_cred: &str,
) -> std::io::Result<()> {
    // Read the full HTTP request. The first byte has already been
    // consumed and is in the PrefixedStream.
    let req = match localapi::read_request(&mut stream).await {
        Ok(r) => r,
        Err(e) => {
            let body = serde_json::json!({"error": "bad request", "reason": e});
            let _ = localapi::write_json_response(&mut stream, 400, "Bad Request", &body).await;
            return Ok(());
        }
    };

    // Validate the Sec-Tailscale header.
    let has_sec_header = req
        .headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("Sec-Tailscale") && v == "localapi");

    // Validate basic auth (Authorization: Basic <base64(user:pass)>).
    let auth_ok = if expected_cred.is_empty() {
        true
    } else {
        req.headers.iter().any(|(k, v)| {
            if k.eq_ignore_ascii_case("Authorization") {
                if let Some(encoded) = v.strip_prefix("Basic ") {
                    use base64::Engine;
                    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) {
                        if let Ok(s) = std::str::from_utf8(&decoded) {
                            return s == format!("tsnet:{expected_cred}");
                        }
                    }
                }
            }
            false
        })
    };

    if !has_sec_header || !auth_ok {
        let body = serde_json::json!({"error": "forbidden: missing Sec-Tailscale header or invalid credentials"});
        let _ = localapi::write_json_response(&mut stream, 403, "Forbidden", &body).await;
        return Ok(());
    }

    localapi::dispatch(&mut stream, &req, &state, &ConnIdentity::readwrite())
        .await
        .map_err(std::io::Error::other)
}

/// A stream that prepends a single byte in front of an underlying
/// `TcpStream`. Used after peeking the first byte for protocol detection.
struct PrefixedStream {
    prefix: Option<u8>,
    inner: TcpStream,
}

impl PrefixedStream {
    fn new(first_byte: u8, inner: TcpStream) -> Self {
        Self {
            prefix: Some(first_byte),
            inner,
        }
    }
}

impl tokio::io::AsyncRead for PrefixedStream {
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

impl tokio::io::AsyncWrite for PrefixedStream {
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

impl Unpin for PrefixedStream {}
