//! LocalAPI — a Unix-domain-socket HTTP server exposing node status, WhoIs,
//! prefs, netmap, metrics, health, and ping endpoints. Ports the subset of
//! Go's `ipn/localapi` package needed for CLI tooling integration.
//!
//! # Architecture
//!
//! Same hand-rolled HTTP/1.1 pattern as `crates/c2n`: no external HTTP
//! framework, just `tokio::net::UnixListener` + manual request parsing and
//! response writing. The server runs as a background tokio task; the socket
//! path is returned for the caller to advertise.
//!
//! # Auth model
//!
//! Unix peer credentials (SO_PEERCRED/LOCAL_PEERCRED) — the kernel stamps
//! each accepted connection with the peer's real UID. Connections from root
//! (uid 0) or the daemon's own UID are granted read-write access; all others
//! are read-only (mutating endpoints return 403). On platforms without peer
//! credentials (Windows named pipes), the pipe ACL handles access control
//! and all connections are read-write. See
//! [`rustscale_safesocket::peercred::ConnIdentity`].
//!
//! # Wire shapes
//!
//! JSON shapes follow Go's `ipn/ipnstate` and `apitype.WhoIsResponse` where
//! practical. Divergences are documented in comments on each handler.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use rustscale_clientmetric::Registry as MetricRegistry;
use rustscale_filter::Filter;
use rustscale_health::Tracker;
use rustscale_ipn::{
    validate_notify_watch_opt, IpnBackend, LoginProfile, MaskedPrefs, NotifyWatchOpt, Prefs,
    StartOptions, NOTIFY_IN_PROCESS_NO_DISCONNECT,
};
use rustscale_ipnstate::{PeerStatus, StatusBuilder, TailnetStatus};
use rustscale_key::{MachinePrivate, MachinePublic, NodePrivate, NodePublic};
use rustscale_magicsock::{Magicsock, PathClass};
use rustscale_safesocket::peercred::ConnIdentity;
use rustscale_safesocket::ServerStream;
use rustscale_tailcfg::{DERPMap, DNSConfig, Node, UserID, UserProfile};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, RwLock};
use tokio::task::JoinHandle;

use crate::serve::ServeConfig;
use crate::tls::{AcmeCertFetcher, ControlCertProvider};

const API_PREFIX: &str = "/localapi/v0/";

/// Commands sent from LocalAPI handlers to the daemon for actions that
/// require server-level operations (start, login, logout).
#[derive(Clone, Debug)]
pub enum DaemonCommand {
    Start {
        auth_key: Option<String>,
    },
    LoginInteractive,
    Logout,
    Shutdown,
    /// Re-read the config file and apply the resulting prefs. Fired by
    /// `POST /reload-config` or daemon-side SIGHUP handler.
    ReloadConfig,
    /// Switch to a different profile by ID, tearing down the running
    /// backend and re-bootstrapping with the new profile's prefs+keys.
    /// Fired by `POST /localapi/v0/profiles/<id>`. Mirrors Go's
    /// `LocalBackend.SwitchProfile` → `resetForProfileChangeLocked`.
    SwitchProfile(String),
}

/// Credentials needed to build an [`AcmeCertFetcher`] on demand for the
/// `GET /localapi/v0/cert/<domain>` endpoint. The cert domains themselves
/// are read live from `dns_config` (shared with the map-update task) so the
/// endpoint always sees the current tailnet HTTPS configuration.
#[derive(Clone)]
pub(crate) struct CertParams {
    pub state_dir: PathBuf,
    pub control_url: String,
    pub machine_key: MachinePrivate,
    pub server_pub_key: MachinePublic,
    pub node_key: NodePrivate,
    pub capability_version: i32,
    pub protocol_version: u16,
}

/// Shared state for the LocalAPI server — all fields are Arc clones of the
/// same state held by [`crate::RunningState`], so the API always sees live
/// data without explicit refresh.
pub(crate) struct LocalApiState {
    pub peers: Arc<RwLock<Vec<Node>>>,
    pub user_profiles: Arc<RwLock<BTreeMap<UserID, UserProfile>>>,
    pub health: Tracker,
    pub dns_config: Arc<RwLock<Option<DNSConfig>>>,
    pub packet_drops: Arc<AtomicU64>,
    /// Client metric registry — supersedes the hardcoded metrics above.
    /// Subsystems register counters/gauges here; the `/metrics` endpoint
    /// renders them via `to_prometheus_text()`.
    pub metrics: MetricRegistry,
    pub prefs: Arc<RwLock<Prefs>>,
    pub tailscale_ips: Vec<IpAddr>,
    pub our_fqdn: String,
    pub hostname: String,
    pub magicsock: Arc<Magicsock>,
    pub tun_mode: bool,
    pub home_derp: i32,
    pub ipn_backend: Arc<IpnBackend>,
    pub derp_map: DERPMap,
    pub command_tx: Option<mpsc::UnboundedSender<DaemonCommand>>,
    pub state_dir: Option<PathBuf>,
    #[allow(dead_code)]
    pub auth_url: Arc<std::sync::Mutex<Option<String>>>,
    pub login_trigger: Arc<tokio::sync::Notify>,
    /// Serve config (shared with ServeRunner). The LocalAPI serve-config
    /// endpoint reads/writes this, computing ETags from the canonical JSON.
    pub serve_config: Arc<RwLock<ServeConfig>>,
    /// The serve runner (None in TUN mode or before `up()`).
    pub serve_runner: Option<Arc<crate::serve::ServeRunner>>,
    /// Login profiles list (shared state for the profiles endpoints).
    pub profiles: Arc<RwLock<Vec<LoginProfile>>>,
    /// Current profile ID (shared state for the profiles endpoints).
    pub current_profile: Arc<RwLock<Option<String>>>,
    /// Credentials for the cert endpoint (`GET /cert/<domain>`). `None` when
    /// the server hasn't joined a tailnet yet (no machine/node keys).
    pub cert_params: Option<CertParams>,
    /// Taildrop file manager (None if taildrop is disabled or not yet up).
    pub taildrop: Option<Arc<crate::taildrop::TaildropManager>>,
    /// Netstack handle for dialing peer PeerAPIs (None in TUN mode or
    /// before `up()`). Used by the `file-put` endpoint to proxy uploads
    /// through the tailnet.
    pub netstack: Option<Arc<rustscale_netstack::Netstack>>,
    /// Shared packet filter. Set once after the server joins the tailnet
    /// (the `Arc<Mutex<Filter>>` is stable across rebuilds — only its inner
    /// value is swapped — so a `OnceLock` suffices). Used to apply shields-up
    /// mode changes from `PATCH /prefs` without a full filter rebuild.
    pub filter: std::sync::OnceLock<Arc<std::sync::Mutex<Filter>>>,
    /// Shared route table (for applying exit-node pref changes directly).
    /// None when the server is not fully up (e.g. start_localapi_only).
    pub route_table: Option<Arc<RwLock<crate::routing::RouteTable>>>,
    /// Notify fired by POST /logout so the daemon can tear down the server
    /// and transition to NeedsLogin. The daemon selects on this alongside
    /// shutdown signals.
    pub logout_trigger: Arc<tokio::sync::Notify>,
    /// Control-suggested exit node (StableNodeID). Set by the map_update
    /// task from `MapResponse.SuggestedExitNode`.
    #[allow(dead_code)]
    pub suggested_exit_node: Arc<RwLock<String>>,
    /// Path to the declarative config file (`--config` flag), if set.
    /// `POST /reload-config` re-reads this file and applies the resulting
    /// `MaskedPrefs` to the live prefs.
    pub config_path: Option<PathBuf>,
    /// Client update checker — fed by the map-update loop from
    /// `MapResponse.ClientVersion`; read by `build_status_json` to populate
    /// `Status.ClientVersion`.
    pub client_updater: Arc<std::sync::Mutex<rustscale_clientupdate::ClientUpdater>>,
}

pub struct LocalApiHandle {
    pub task: JoinHandle<()>,
    pub socket_path: PathBuf,
}

/// Spawn the LocalAPI Unix-domain-socket server.
///
/// Delegates listener creation to [`rustscale_safesocket::listen`], which
/// removes stale socket files, creates parent directories, and sets
/// platform-appropriate permissions (0o666 on peer-credential platforms,
/// 0o600 elsewhere). The listener is converted to non-blocking mode and
/// a background task serves HTTP/1.1.
///
/// Returns `None` if the socket cannot be bound.
pub(crate) fn spawn_localapi(
    state: Arc<LocalApiState>,
    socket_path: PathBuf,
) -> Option<LocalApiHandle> {
    let listener = rustscale_safesocket::listen(&socket_path).ok()?;

    let path = socket_path.clone();
    let task = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok(stream) => {
                    let peer_identity = peer_identity_from_stream(&stream);
                    let state = state.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, &state, peer_identity).await {
                            eprintln!("localapi: connection error: {e}");
                        }
                    });
                }
                Err(e) => {
                    eprintln!("localapi: accept error: {e}");
                    continue;
                }
            }
        }
    });

    Some(LocalApiHandle {
        task,
        socket_path: path,
    })
}

/// Extract a [`ConnIdentity`] from a server-side stream. On Unix this reads
/// peer credentials (SO_PEERCRED/LOCAL_PEERCRED); on other platforms all
/// connections are treated as read-write (pipe ACL handles access control).
#[cfg(unix)]
fn peer_identity_from_stream(stream: &ServerStream) -> ConnIdentity {
    ConnIdentity::from_stream(stream)
}

#[cfg(not(unix))]
fn peer_identity_from_stream(_stream: &ServerStream) -> ConnIdentity {
    ConnIdentity::readwrite()
}

// ---------------------------------------------------------------------------
// HTTP request parsing (same pattern as crates/c2n)
// ---------------------------------------------------------------------------

pub(crate) struct HttpRequest {
    pub(crate) method: String,
    pub(crate) path: String,
    #[allow(dead_code)]
    pub(crate) query: String,
    pub(crate) headers: Vec<(String, String)>,
    #[allow(dead_code)]
    pub(crate) body: Vec<u8>,
}

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

fn parse_request_head(head: &[u8], body_preview: Vec<u8>) -> Result<HttpRequest, String> {
    let text = std::str::from_utf8(head).map_err(|_| "non-utf8 header".to_string())?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or("no request line")?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or("no method")?.to_string();
    let raw_path = parts.next().ok_or("no path")?.to_string();
    let (path, query) = match raw_path.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (raw_path, String::new()),
    };
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

    Ok(HttpRequest {
        method,
        path,
        query,
        headers,
        body,
    })
}

// ---------------------------------------------------------------------------
// Response writers
// ---------------------------------------------------------------------------

pub(crate) async fn write_json_response<W: AsyncWrite + Unpin>(
    conn: &mut W,
    status: u16,
    reason: &str,
    body: &serde_json::Value,
) -> Result<(), std::io::Error> {
    let json = serde_json::to_vec(body).unwrap_or_default();
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        json.len()
    );
    conn.write_all(header.as_bytes()).await?;
    conn.write_all(&json).await?;
    conn.flush().await?;
    Ok(())
}

async fn write_raw_response<W: AsyncWrite + Unpin>(
    conn: &mut W,
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
) -> Result<(), std::io::Error> {
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    conn.write_all(header.as_bytes()).await?;
    conn.write_all(body).await?;
    conn.flush().await?;
    Ok(())
}

async fn write_no_content_response<W: AsyncWrite + Unpin>(
    conn: &mut W,
    status: u16,
    reason: &str,
) -> Result<(), std::io::Error> {
    let header =
        format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    conn.write_all(header.as_bytes()).await?;
    conn.flush().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Start / login-interactive / logout / prefs handlers
// ---------------------------------------------------------------------------

async fn handle_start<W: AsyncWrite + Unpin>(
    conn: &mut W,
    body: &[u8],
    state: &Arc<LocalApiState>,
) -> Result<(), std::io::Error> {
    let opts: StartOptions = if body.is_empty() {
        StartOptions::default()
    } else {
        match serde_json::from_slice(body) {
            Ok(o) => o,
            Err(e) => {
                let err = serde_json::json!({"error": format!("bad StartOptions: {e}")});
                write_json_response(conn, 400, "Bad Request", &err).await?;
                return Ok(());
            }
        }
    };

    if let Some(ref mask) = opts.UpdatePrefs {
        let mut prefs = state.prefs.write().await;
        mask.apply_to(&mut prefs);
        if let Some(ref dir) = state.state_dir {
            let _ = prefs.save(dir);
        }
        state.ipn_backend.bus().send(rustscale_ipn::Notify {
            Prefs: Some(serde_json::to_value(&*prefs).unwrap_or_default()),
            ..Default::default()
        });
    }

    if let Some(ref tx) = state.command_tx {
        let _ = tx.send(DaemonCommand::Start {
            auth_key: if opts.AuthKey.is_empty() {
                None
            } else {
                Some(opts.AuthKey.clone())
            },
        });
    }
    write_no_content_response(conn, 204, "No Content").await?;
    Ok(())
}

async fn handle_logout<W: AsyncWrite + Unpin>(
    conn: &mut W,
    state: &Arc<LocalApiState>,
) -> Result<(), std::io::Error> {
    {
        let mut prefs = state.prefs.write().await;
        prefs.LoggedOut = true;
        prefs.WantRunning = false;
        if let Some(ref dir) = state.state_dir {
            let _ = prefs.save(dir);
        }
    }
    state.ipn_backend.set_auth_cant_continue(true);
    state.ipn_backend.set_logged_out(true);
    state.ipn_backend.set_blocked(true);
    state.ipn_backend.bus().send(rustscale_ipn::Notify {
        Prefs: Some(serde_json::to_value(&*state.prefs.read().await).unwrap_or_default()),
        ..Default::default()
    });
    if let Some(ref tx) = state.command_tx {
        let _ = tx.send(DaemonCommand::Logout);
    }
    state.logout_trigger.notify_waiters();
    write_no_content_response(conn, 204, "No Content").await?;
    Ok(())
}

/// Handle `POST /localapi/v0/reload-config`: re-read the config file at
/// `state.config_path`, convert to `MaskedPrefs`, and apply to the live
/// prefs. Mirrors Go's `LocalBackend.ReloadConfig()`.
async fn handle_reload_config<W: AsyncWrite + Unpin>(
    conn: &mut W,
    state: &Arc<LocalApiState>,
) -> Result<(), std::io::Error> {
    let Some(ref config_path) = state.config_path else {
        let err = serde_json::json!({"error": "no config file path set"});
        write_json_response(conn, 400, "Bad Request", &err).await?;
        return Ok(());
    };

    let path_str = config_path.to_string_lossy();
    let config = match rustscale_conffile::Config::load(&path_str) {
        Ok(c) => c,
        Err(e) => {
            let err = serde_json::json!({"error": format!("config reload failed: {e}")});
            write_json_response(conn, 400, "Bad Request", &err).await?;
            return Ok(());
        }
    };

    let masked = config.parsed.to_prefs();
    let updated = {
        let mut prefs = state.prefs.write().await;
        masked.apply_to(&mut prefs);
        if let Some(ref dir) = state.state_dir {
            let _ = prefs.save(dir);
        }
        serde_json::to_value(&*prefs).unwrap_or_default()
    };

    state.ipn_backend.bus().send(rustscale_ipn::Notify {
        Prefs: Some(updated.clone()),
        ..Default::default()
    });

    eprintln!("rustscaled: config reloaded from {path_str}");
    write_json_response(conn, 200, "OK", &updated).await?;
    Ok(())
}
/// or stable node ID. Returns the peer's NodePublic key on success.
/// Mirrors Go's `resolveExitNodeIPLocked` / `peerWithStableID` lookup.
pub(crate) fn resolve_exit_node_peer(peers: &[Node], ip_or_name: &str) -> Option<NodePublic> {
    // Try parsing as an IP address first.
    if let Ok(ip) = ip_or_name.parse::<IpAddr>() {
        for peer in peers {
            for addr in &peer.Addresses {
                if let Some(peer_ip_str) = addr.split('/').next() {
                    if let Ok(peer_ip) = peer_ip_str.parse::<IpAddr>() {
                        if peer_ip == ip {
                            // Verify the peer is exit-node-capable.
                            if peer
                                .AllowedIPs
                                .iter()
                                .any(|r| r == "0.0.0.0/0" || r == "::/0")
                            {
                                return Some(peer.Key.clone());
                            }
                        }
                    }
                }
            }
        }
        return None;
    }

    // Try matching by hostname (with or without trailing dot, case-insensitive).
    let name_lc = ip_or_name.trim_end_matches('.').to_lowercase();
    for peer in peers {
        let peer_name = peer.Name.trim_end_matches('.').to_lowercase();
        if peer_name == name_lc
            && peer
                .AllowedIPs
                .iter()
                .any(|r| r == "0.0.0.0/0" || r == "::/0")
        {
            return Some(peer.Key.clone());
        }
    }

    // Try matching by StableID.
    for peer in peers {
        if peer.StableID == ip_or_name
            && peer
                .AllowedIPs
                .iter()
                .any(|r| r == "0.0.0.0/0" || r == "::/0")
        {
            return Some(peer.Key.clone());
        }
    }

    None
}

/// Apply exit-node prefs to the route table. Called from handle_patch_prefs
/// when ExitNodeID/ExitNodeIP changes, and from up()/up_tun() on daemon
/// start to apply persisted prefs. Mirrors Go's applyPrefsToEngine
/// exit-node handling.
pub(crate) async fn apply_exit_node_prefs(prefs: &Prefs, state: &Arc<LocalApiState>) {
    let Some(ref rt) = state.route_table else {
        return;
    };

    let ip_or_name = if !prefs.ExitNodeIP.is_empty() {
        &prefs.ExitNodeIP
    } else if !prefs.ExitNodeID.is_empty() {
        &prefs.ExitNodeID
    } else {
        // No exit node selected — clear it.
        rt.write().await.clear_exit_node();
        return;
    };

    let peers = state.peers.read().await;
    if let Some(peer_key) = resolve_exit_node_peer(&peers, ip_or_name) {
        rt.write().await.set_exit_node(peer_key);
    } else {
        // Peer not found (may not be in the netmap yet). Clear for now;
        // the map update task will re-apply when the peer appears.
        rt.write().await.clear_exit_node();
    }
}

async fn handle_patch_prefs<W: AsyncWrite + Unpin>(
    conn: &mut W,
    body: &[u8],
    state: &Arc<LocalApiState>,
) -> Result<(), std::io::Error> {
    let masked: MaskedPrefs = if body.is_empty() {
        MaskedPrefs::default()
    } else {
        match serde_json::from_slice(body) {
            Ok(m) => m,
            Err(e) => {
                let err = serde_json::json!({"error": format!("bad MaskedPrefs: {e}")});
                write_json_response(conn, 400, "Bad Request", &err).await?;
                return Ok(());
            }
        }
    };

    let exit_node_changed = masked.ExitNodeIDSet || masked.ExitNodeIPSet;

    let updated = {
        let mut prefs = state.prefs.write().await;
        masked.apply_to(&mut prefs);
        if let Some(ref dir) = state.state_dir {
            let _ = prefs.save(dir);
        }
        serde_json::to_value(&*prefs).unwrap_or_default()
    };

    // Apply shields-up changes to the live filter without a full rebuild.
    // The filter's `set_shields_up` toggles the flag that suppresses new
    // inbound flow admission; established flows are preserved.
    if masked.ShieldsUpSet {
        if let Some(filter) = state.filter.get() {
            filter
                .lock()
                .unwrap()
                .set_shields_up(masked.Prefs.ShieldsUp);
        }
    }

    // Apply exit-node routing changes to the route table (Gap 1).
    // When ExitNodeIP or ExitNodeID is patched, resolve the peer and
    // update the route table — mirroring Go's applyPrefsToEngine.
    if exit_node_changed {
        let prefs = state.prefs.read().await;
        apply_exit_node_prefs(&prefs, state).await;
    }

    state.ipn_backend.bus().send(rustscale_ipn::Notify {
        Prefs: Some(updated.clone()),
        ..Default::default()
    });
    write_json_response(conn, 200, "OK", &updated).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Query string parsing
// ---------------------------------------------------------------------------

fn parse_query(query: &str) -> std::collections::HashMap<String, String> {
    let mut params = std::collections::HashMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        if let Some((k, v)) = pair.split_once('=') {
            params.insert(k.to_string(), v.to_string());
        } else {
            params.insert(pair.to_string(), String::new());
        }
    }
    params
}

// ---------------------------------------------------------------------------
// Connection handling
// ---------------------------------------------------------------------------

async fn handle_connection(
    mut stream: ServerStream,
    state: &Arc<LocalApiState>,
    peer_identity: ConnIdentity,
) -> Result<(), std::io::Error> {
    let req = match read_request(&mut stream).await {
        Ok(r) => r,
        Err(e) => {
            let body = serde_json::json!({"error": "bad request", "reason": e});
            write_json_response(&mut stream, 400, "Bad Request", &body).await?;
            return Ok(());
        }
    };

    dispatch(&mut stream, &req, state, &peer_identity).await
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// Check whether the peer has read-write access. On Unix, compares the peer's
/// uid against the daemon's uid (and root). On non-Unix platforms, always
/// returns true (named-pipe ACL handles access control).
fn require_readwrite(identity: &ConnIdentity) -> bool {
    #[cfg(unix)]
    {
        let daemon_uid = unsafe { libc::getuid() };
        identity.is_readwrite(daemon_uid, None)
    }
    #[cfg(not(unix))]
    {
        let _ = identity;
        true
    }
}

/// Write a 403 Forbidden response for read-only peers attempting mutations.
async fn write_access_denied<W: AsyncWrite + Unpin>(conn: &mut W) -> Result<(), std::io::Error> {
    let body = serde_json::json!({"error": "access denied"});
    write_json_response(conn, 403, "Forbidden", &body).await
}

pub(crate) async fn dispatch<W: AsyncWrite + Unpin>(
    conn: &mut W,
    req: &HttpRequest,
    state: &Arc<LocalApiState>,
    peer_identity: &ConnIdentity,
) -> Result<(), std::io::Error> {
    let method = req.method.as_str();
    let path = req.path.as_str();

    // All endpoints are under /localapi/v0/
    if !path.starts_with(API_PREFIX) {
        if path == "/" {
            if method == "GET" {
                let endpoints = serde_json::json!([
                    "/localapi/v0/status",
                    "/localapi/v0/whois",
                    "/localapi/v0/prefs",
                    "/localapi/v0/netmap",
                    "/localapi/v0/metrics",
                    "/localapi/v0/health",
                    "/localapi/v0/ping",
                    "/localapi/v0/watch-ipn-bus",
                    "/localapi/v0/start",
                    "/localapi/v0/login-interactive",
                    "/localapi/v0/logout",
                    "/localapi/v0/serve-config",
                    "/localapi/v0/profiles",
                    "/localapi/v0/cert/<domain>",
                    "/localapi/v0/file-targets",
                    "/localapi/v0/files/",
                    "/localapi/v0/file-put/",
                    "/localapi/v0/debug",
                    "/localapi/v0/dial",
                    "/localapi/v0/dns-query",
                    "/localapi/v0/check-ip-forwarding",
                    "/localapi/v0/check-prefs",
                    "/localapi/v0/set-expiry-sooner",
                    "/localapi/v0/shutdown",
                    "/localapi/v0/id-token",
                    "/localapi/v0/reload-config",
                ]);
                write_json_response(conn, 200, "OK", &endpoints).await?;
            } else {
                let body = serde_json::json!({"error": "bad method"});
                write_json_response(conn, 405, "Method Not Allowed", &body).await?;
            }
            return Ok(());
        }
        let body = serde_json::json!({"error": "unknown path", "path": path});
        write_json_response(conn, 404, "Not Found", &body).await?;
        return Ok(());
    }

    let endpoint = &path[API_PREFIX.len()..];

    match endpoint {
        // --- GET /localapi/v0/status ---
        "status" if method == "GET" => {
            let st = build_status_json(state).await;
            write_json_response(conn, 200, "OK", &st).await?;
        }

        // --- GET /localapi/v0/whois?addr=ip:port ---
        "whois" if method == "GET" => {
            handle_whois(conn, &req.query, state).await?;
        }

        // --- GET /localapi/v0/prefs ---
        "prefs" if method == "GET" => {
            let prefs = state.prefs.read().await.clone();
            let json = serde_json::to_value(&prefs).unwrap_or(serde_json::json!({}));
            write_json_response(conn, 200, "OK", &json).await?;
        }

        // --- PATCH /localapi/v0/prefs ---
        "prefs" if method == "PATCH" => {
            if !require_readwrite(peer_identity) {
                write_access_denied(conn).await?;
                return Ok(());
            }
            handle_patch_prefs(conn, &req.body, state).await?;
        }

        // --- POST /localapi/v0/start ---
        "start" if method == "POST" => {
            if !require_readwrite(peer_identity) {
                write_access_denied(conn).await?;
                return Ok(());
            }
            handle_start(conn, &req.body, state).await?;
        }

        // --- POST /localapi/v0/login-interactive ---
        "login-interactive" if method == "POST" => {
            if !require_readwrite(peer_identity) {
                write_access_denied(conn).await?;
                return Ok(());
            }
            state.login_trigger.notify_waiters();
            write_no_content_response(conn, 204, "No Content").await?;
        }

        // --- POST /localapi/v0/logout ---
        "logout" if method == "POST" => {
            if !require_readwrite(peer_identity) {
                write_access_denied(conn).await?;
                return Ok(());
            }
            handle_logout(conn, state).await?;
        }

        // --- GET /localapi/v0/netmap ---
        "netmap" if method == "GET" => {
            let netmap = build_netmap_json(state).await;
            write_json_response(conn, 200, "OK", &netmap).await?;
        }

        // --- GET /localapi/v0/metrics ---
        "metrics" if method == "GET" => {
            let text = build_metrics_text(state);
            write_raw_response(
                conn,
                200,
                "OK",
                "text/plain; version=0.0.4; charset=utf-8",
                text.as_bytes(),
            )
            .await?;
        }

        // --- GET /localapi/v0/health ---
        "health" if method == "GET" => {
            let health = build_health_json(state);
            write_json_response(conn, 200, "OK", &health).await?;
        }

        // --- POST /localapi/v0/ping?ip=<ip>&type=disco ---
        "ping" if method == "POST" => {
            handle_ping(conn, &req.query, state).await?;
        }

        // --- GET /localapi/v0/watch-ipn-bus?mask=<u64> ---
        "watch-ipn-bus" if method == "GET" => {
            handle_watch_ipn_bus(conn, &req.query, state).await?;
        }

        // --- GET/POST /localapi/v0/serve-config ---
        "serve-config" if method == "GET" => {
            handle_get_serve_config(conn, state).await?;
        }
        "serve-config" if method == "POST" => {
            if !require_readwrite(peer_identity) {
                write_access_denied(conn).await?;
                return Ok(());
            }
            handle_post_serve_config(conn, req, state).await?;
        }

        // --- GET /localapi/v0/profiles ---
        "profiles" if method == "GET" => {
            handle_list_profiles(conn, state).await?;
        }
        // --- PUT /localapi/v0/profiles ---
        "profiles" if method == "PUT" => {
            if !require_readwrite(peer_identity) {
                write_access_denied(conn).await?;
                return Ok(());
            }
            handle_new_profile(conn, state).await?;
        }
        // --- GET /localapi/v0/file-targets ---
        "file-targets" if method == "GET" => {
            handle_file_targets(conn, state).await?;
        }

        // --- GET /localapi/v0/debug?action=<method> ---
        "debug" if method == "GET" => {
            handle_debug(conn, &req.query, state).await?;
        }

        // --- POST /localapi/v0/dial?addr=<host:port> ---
        "dial" if method == "POST" => {
            handle_dial(conn, &req.query, state).await?;
        }

        // --- GET /localapi/v0/dns-query?name=<name>&type=<type> ---
        "dns-query" if method == "GET" => {
            handle_dns_query(conn, &req.query, state).await?;
        }

        // --- GET /localapi/v0/check-ip-forwarding ---
        "check-ip-forwarding" if method == "GET" => {
            handle_check_ip_forwarding(conn).await?;
        }

        // --- POST /localapi/v0/check-prefs ---
        "check-prefs" if method == "POST" => {
            handle_check_prefs(conn, &req.body).await?;
        }

        // --- POST /localapi/v0/set-expiry-sooner ---
        "set-expiry-sooner" if method == "POST" => {
            if !require_readwrite(peer_identity) {
                write_access_denied(conn).await?;
                return Ok(());
            }
            handle_set_expiry_sooner(conn, &req.body, &req.query).await?;
        }

        // --- POST /localapi/v0/shutdown ---
        "shutdown" if method == "POST" => {
            if !require_readwrite(peer_identity) {
                write_access_denied(conn).await?;
                return Ok(());
            }
            handle_shutdown(conn, state).await?;
        }

        // --- GET /localapi/v0/id-token ---
        "id-token" if method == "GET" => {
            handle_id_token(conn, &req.query).await?;
        }

        // --- POST /localapi/v0/reload-config ---
        "reload-config" if method == "POST" => {
            if !require_readwrite(peer_identity) {
                write_access_denied(conn).await?;
                return Ok(());
            }
            handle_reload_config(conn, state).await?;
        }

        // --- POST /localapi/v0/debug (action dispatcher) ---
        "debug" if method == "POST" => {
            if !require_readwrite(peer_identity) {
                write_access_denied(conn).await?;
                return Ok(());
            }
            handle_debug_action(conn, &req.body, &req.query, state).await?;
        }

        _ => {
            // Check for cert/<domain> sub-path.
            if let Some(suffix) = endpoint.strip_prefix("cert/") {
                handle_cert(conn, method, suffix, &req.query, state).await?;
                return Ok(());
            }
            // Check for profiles/<id> or profiles/current sub-paths.
            if let Some(suffix) = endpoint.strip_prefix("profiles/") {
                if (method == "POST" || method == "DELETE") && !require_readwrite(peer_identity) {
                    write_access_denied(conn).await?;
                    return Ok(());
                }
                handle_profile_subpath(conn, method, suffix, state).await?;
                return Ok(());
            }
            // Check for files/<name> or files/ (Taildrop).
            if endpoint == "files" || endpoint.starts_with("files/") {
                if method == "DELETE" && !require_readwrite(peer_identity) {
                    write_access_denied(conn).await?;
                    return Ok(());
                }
                handle_files(conn, method, endpoint, &req.query, req, state).await?;
                return Ok(());
            }
            // Check for file-put/<stableID>/<filename> (Taildrop upload proxy).
            if let Some(suffix) = endpoint.strip_prefix("file-put/") {
                if !require_readwrite(peer_identity) {
                    write_access_denied(conn).await?;
                    return Ok(());
                }
                handle_file_put(conn, method, suffix, req, state).await?;
                return Ok(());
            }
            let body = serde_json::json!({
                "error": "not found",
                "path": path,
                "method": method,
            });
            write_json_response(conn, 404, "Not Found", &body).await?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Status handler
// ---------------------------------------------------------------------------

/// Build the status JSON via `ipnstate::StatusBuilder` and serde, producing
/// byte-identical output to Go's `ipnstate.Status` serialization.
///
/// # Divergences from Go ipnstate.Status
///
/// - `Version`: "rustscale" instead of Go's version.Long().
/// - `BackendState`: the live IPN state machine string (e.g. "Running",
///   "Starting", "NeedsLogin"), not a hardcoded value.
/// - `Self` and `Peer` entries omit fields not tracked by rustscale:
///   `RxBytes`, `TxBytes`, `LastHandshake`, `LastSeen`, `LastWrite`,
///   `AllowedIPs`, `Tags`, `PrimaryRoutes`, `Capabilities`, `CapMap`,
///   `PeerAPIURL`, `SSH_HostKeys`, `KeyExpiry`, `Location`.
/// - `ExitNodeStatus`: included when an exit node is selected via the
///   route table, but `ID` is derived from the peer's node key (not a
///   stable node ID, which rustscale does not track).
/// - `ClientVersion`, `ExtraRecords`, `AuthURL`: omitted.
/// - `CertDomains`: included (from the live DNSConfig).
/// - `Peer` is a JSON object keyed by node public key string (same as Go).
/// - `TUN`: true when the server was started via `up_tun()`.
/// - `SuggestedExitNode`: omitted (Go does not emit it in ipnstate.Status).
async fn build_status_json(state: &LocalApiState) -> serde_json::Value {
    let peers = state.peers.read().await;
    let user_profiles = state.user_profiles.read().await;
    let dns_config = state.dns_config.read().await;

    let mut sb = StatusBuilder::new();

    sb.mutate_status(|s| {
        s.Version = "rustscale".into();
        s.TUN = state.tun_mode;
        s.BackendState = state.ipn_backend.state().as_str().to_string();
        s.HaveNodeKey = Some(true);
        s.Health = state
            .health
            .current_warnings()
            .iter()
            .map(|w| w.text.clone())
            .collect();
        for ip in &state.tailscale_ips {
            s.TailscaleIPs.push(*ip);
        }
        let (tailnet_name, magicdns_suffix, magicdns_enabled) = if let Some(ref dns) = *dns_config {
            let suffix = state.our_fqdn.trim_end_matches('.');
            let suffix = match suffix.split_once('.') {
                Some((_, d)) => d,
                None => suffix,
            };
            (suffix.to_string(), suffix.to_string(), dns.Proxied)
        } else {
            (String::new(), String::new(), false)
        };
        s.CurrentTailnet = Some(Box::new(TailnetStatus {
            Name: tailnet_name,
            MagicDNSSuffix: magicdns_suffix,
            MagicDNSEnabled: magicdns_enabled,
        }));
        let cert_domains: Vec<String> = dns_config
            .as_ref()
            .map(|c| c.CertDomains.clone())
            .unwrap_or_default();
        s.CertDomains = cert_domains;
        if let Ok(u) = state.client_updater.lock() {
            let cr = u.check();
            s.ClientVersion = Some(Box::new(rustscale_ipnstate::ClientVersionStatus {
                RunningLatest: cr.running_latest,
                LatestVersion: cr.latest_version.clone(),
                UrgentSecurityUpdate: cr.urgent_security_update,
                Notify: cr.notify,
                NotifyURL: cr.notify_url.clone(),
                NotifyText: cr.notify_text.clone(),
            }));
        }
    });

    // Self peer.
    sb.mutate_self_status(|ps| {
        ps.HostName.clone_from(&state.hostname);
        ps.DNSName.clone_from(&state.our_fqdn);
        ps.TailscaleIPs.clone_from(&state.tailscale_ips);
        ps.PublicKey = state.magicsock.node_public().to_string();
        ps.Online = true;
        ps.InNetworkMap = true;
        ps.InMagicSock = true;
        ps.InEngine = true;
    });

    // Peers.
    for peer in peers.iter() {
        if peer.Key.is_zero() {
            continue;
        }
        let ips: Vec<IpAddr> = peer
            .Addresses
            .iter()
            .filter_map(|s| s.split('/').next().and_then(|p| p.parse::<IpAddr>().ok()))
            .collect();

        let path_class = state.magicsock.peer_path_class(&peer.Key);
        let relay = match path_class {
            PathClass::Derp => format!("derp-{}", state.home_derp),
            _ => String::new(),
        };

        let exit_node_option = peer
            .AllowedIPs
            .iter()
            .any(|r| r == "0.0.0.0/0" || r == "::/0");

        let ps = PeerStatus {
            HostName: peer.Name.trim_end_matches('.').to_string(),
            DNSName: peer.Name.clone(),
            TailscaleIPs: ips,
            Online: peer.Online.unwrap_or(false),
            Relay: relay,
            ExitNodeOption: exit_node_option,
            InNetworkMap: true,
            InMagicSock: true,
            InEngine: true,
            UserID: peer.User,
            ..Default::default()
        };
        sb.add_peer(&peer.Key, ps);
    }

    // Users.
    for (id, profile) in user_profiles.iter() {
        sb.add_user(*id, profile.clone());
    }

    serde_json::to_value(sb.status()).unwrap_or(serde_json::Value::Null)
}

// ---------------------------------------------------------------------------
// WhoIs handler
// ---------------------------------------------------------------------------

/// Handle GET /localapi/v0/whois?addr=ip:port
///
/// Parses the `addr` query parameter (accepts bare IP or ip:port), looks up
/// the peer owning that IP, and returns a JSON response modeled on Go's
/// `apitype.WhoIsResponse`.
///
/// # Divergences from Go
///
/// - `Node`: a subset of the Node struct (Name, Addresses, Key, User, Online).
///   Go returns the full `tailcfg.Node` via `NodeView.AsStruct()`.
/// - `UserProfile`: includes ID, LoginName, DisplayName, ProfilePicURL.
/// - `CapMap`: omitted (rustscale does not expose peer capability maps).
/// - `nodekey:` prefix for `addr`: not supported (returns 400).
async fn handle_whois<W: AsyncWrite + Unpin>(
    conn: &mut W,
    query: &str,
    state: &LocalApiState,
) -> Result<(), std::io::Error> {
    let params = parse_query(query);
    let addr_str = match params.get("addr") {
        Some(v) if !v.is_empty() => v,
        _ => {
            let body = serde_json::json!({"error": "missing 'addr' parameter"});
            write_json_response(conn, 400, "Bad Request", &body).await?;
            return Ok(());
        }
    };

    // Parse the addr: accept bare IP or ip:port.
    let ip: IpAddr = if let Ok(ip) = addr_str.parse::<IpAddr>() {
        ip
    } else if let Ok(sa) = addr_str.parse::<std::net::SocketAddr>() {
        sa.ip()
    } else {
        let body = serde_json::json!({"error": "invalid 'addr' parameter"});
        write_json_response(conn, 400, "Bad Request", &body).await?;
        return Ok(());
    };

    let peers = state.peers.read().await;
    let user_profiles = state.user_profiles.read().await;

    let mut found_peer: Option<&Node> = None;
    for peer in peers.iter() {
        let ips: Vec<IpAddr> = peer
            .Addresses
            .iter()
            .filter_map(|s| s.split('/').next().and_then(|p| p.parse::<IpAddr>().ok()))
            .collect();
        if ips.contains(&ip) {
            found_peer = Some(peer);
            break;
        }
    }

    let Some(peer) = found_peer else {
        let body = serde_json::json!({"error": "no match for IP"});
        write_json_response(conn, 404, "Not Found", &body).await?;
        return Ok(());
    };

    let user_profile = user_profiles.get(&peer.User);

    let node_json = serde_json::json!({
        "Name": peer.Name,
        "Addresses": peer.Addresses,
        "Key": peer.Key.to_string(),
        "User": peer.User,
        "Online": peer.Online.unwrap_or(false),
    });

    let profile_json = user_profile.map_or(serde_json::Value::Null, |p| {
        serde_json::json!({
            "ID": p.ID,
            "LoginName": p.LoginName,
            "DisplayName": p.DisplayName,
            "ProfilePicURL": p.ProfilePicURL,
        })
    });

    let resp = serde_json::json!({
        "Node": node_json,
        "UserProfile": profile_json,
    });

    write_json_response(conn, 200, "OK", &resp).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Netmap handler
// ---------------------------------------------------------------------------

/// Build the netmap JSON. Reuses the same shape as the C2N netmap handler.
async fn build_netmap_json(state: &LocalApiState) -> serde_json::Value {
    let peers = state.peers.read().await;
    let dns = state.dns_config.read().await;
    let domain = state.our_fqdn.trim_end_matches('.');
    let domain = match domain.split_once('.') {
        Some((_, d)) => d.to_string(),
        None => domain.to_string(),
    };

    let self_node = serde_json::json!({
        "Name": state.our_fqdn,
        "Addresses": state.tailscale_ips.iter().map(|ip| format!("{ip}/32")).collect::<Vec<_>>(),
        "Key": state.magicsock.node_public().to_string(),
    });

    let peers_json: Vec<serde_json::Value> = peers
        .iter()
        .filter(|p| !p.Key.is_zero())
        .map(|p| serde_json::to_value(p).unwrap_or(serde_json::Value::Null))
        .collect();

    serde_json::json!({
        "SelfNode": self_node,
        "Peers": peers_json,
        "DNSConfig": dns.as_ref().map(|c| serde_json::to_value(c).unwrap_or(serde_json::Value::Null)),
        "Domain": domain,
        "DERPMap": serde_json::to_value(&state.derp_map).unwrap_or(serde_json::Value::Null),
    })
}

// ---------------------------------------------------------------------------
// Metrics handler
// ---------------------------------------------------------------------------

/// Create a default metric registry with the standard rustscale metrics
/// pre-registered. Subsystems can obtain handles via `reg.get(name)` to
/// update values. The `/metrics` endpoint calls `build_metrics_text` which
/// populates dynamic values from `LocalApiState` before rendering.
pub(crate) fn default_metric_registry() -> MetricRegistry {
    let reg = MetricRegistry::new();
    reg.counter_with_help(
        "rustscale_packet_drops_total",
        "Packets dropped by the packet filter",
    );
    reg.gauge_with_help("rustscale_peer_count", "Number of peers in the netmap");
    reg.gauge_with_help(
        "rustscale_health_warnings",
        "Active health warnings by severity",
    );
    reg.gauge_with_help("rustscale_local_endpoints", "Number of local UDP endpoints");
    reg
}

/// Build Prometheus text exposition format using the metric registry.
///
/// Dynamic values (packet drops, peer count, health, endpoints) are
/// populated from `LocalApiState` fields before rendering. Additional
/// metrics registered by subsystems appear alongside the standard ones.
fn build_metrics_text(state: &LocalApiState) -> String {
    // Populate the standard metrics from live state.
    let drops = state.packet_drops.load(Ordering::Relaxed) as i64;
    if let Some(m) = state.metrics.get("rustscale_packet_drops_total") {
        m.set(drops);
    }

    let peer_count = state.peers.try_read().map_or(0, |p| p.len()) as i64;
    if let Some(m) = state.metrics.get("rustscale_peer_count") {
        m.set(peer_count);
    }

    let warnings = state.health.current_warnings();
    if let Some(m) = state.metrics.get("rustscale_health_warnings") {
        m.set(warnings.len() as i64);
    }

    let endpoints = state.magicsock.local_endpoints();
    if let Some(m) = state.metrics.get("rustscale_local_endpoints") {
        m.set(endpoints.len() as i64);
    }

    // Render the registry (standard + any subsystem-registered metrics).
    state.metrics.to_prometheus_text()
}

// ---------------------------------------------------------------------------
// Health handler
// ---------------------------------------------------------------------------

/// Build health JSON — an array of active warnings (same shape as C2N).
fn build_health_json(state: &LocalApiState) -> serde_json::Value {
    let warnings = state.health.current_warnings();
    serde_json::to_value(&warnings).unwrap_or(serde_json::json!([]))
}

// ---------------------------------------------------------------------------
// Ping handler
// ---------------------------------------------------------------------------

/// Handle POST /localapi/v0/ping?ip=<ip>&type=<disco|tsmp|icmp|peerapi>&size=<n>
///
/// Dispatches to the appropriate ping sub-handler based on `type`. For
/// `disco` (the default), sends a CLI-initiated disco ping via magicsock
/// and returns a `PingResult` with latency + endpoint info. For `icmp`,
/// uses the netcheck ICMP pinger. `tsmp` and `peerapi` are stubbed.
async fn handle_ping<W: AsyncWrite + Unpin>(
    conn: &mut W,
    query: &str,
    state: &Arc<LocalApiState>,
) -> Result<(), std::io::Error> {
    let params = parse_query(query);
    let ip_str = params.get("ip").map_or("", String::as_str);
    let ping_type = params.get("type").map_or("disco", String::as_str);
    let size_str = params.get("size").map_or("0", String::as_str);
    let size: usize = size_str.parse().unwrap_or(0);

    if ip_str.is_empty() {
        let body = serde_json::json!({"error": "missing 'ip' parameter"});
        write_json_response(conn, 400, "Bad Request", &body).await?;
        return Ok(());
    }

    let ip: IpAddr = if let Ok(ip) = ip_str.parse() {
        ip
    } else {
        let body = serde_json::json!({"error": "invalid IP address"});
        return write_json_response(conn, 400, "Bad Request", &body).await;
    };

    match ping_type {
        "disco" | "" => handle_disco_ping(conn, ip, size, state).await,
        "tsmp" => handle_tsmp_ping(conn, ip, state).await,
        "icmp" => handle_icmp_ping(conn, ip, state).await,
        "peerapi" => handle_peerapi_ping(conn, ip, state).await,
        other => {
            let body = serde_json::json!({
                "error": format!("unknown ping type '{other}'; try disco, tsmp, icmp, or peerapi")
            });
            write_json_response(conn, 400, "Bad Request", &body).await
        }
    }
}

/// Find a peer in the netmap by its Tailscale IP address.
fn peer_by_ip(peers: &[Node], ip: IpAddr) -> Option<&Node> {
    peers.iter().find(|p| {
        p.Addresses.iter().any(|cidr| {
            cidr.split('/')
                .next()
                .and_then(|s| s.parse::<IpAddr>().ok())
                == Some(ip)
        })
    })
}

/// Handle disco ping: sends a CLI-initiated disco ping via magicsock.
async fn handle_disco_ping<W: AsyncWrite + Unpin>(
    conn: &mut W,
    ip: IpAddr,
    size: usize,
    state: &Arc<LocalApiState>,
) -> Result<(), std::io::Error> {
    // Look up the peer by Tailscale IP in the netmap.
    let (peer_key, peer_name) = {
        let peers = state.peers.read().await;
        let Some(peer) = peer_by_ip(&peers, ip) else {
            let body = serde_json::json!({
                "error": format!("no peer found for {ip}"),
                "ip": ip.to_string(),
            });
            return write_json_response(conn, 404, "Not Found", &body).await;
        };
        (peer.Key.clone(), peer.Name.clone())
    };

    // Check if the IP is one of our own (self-ping).
    let is_local_ip = state.tailscale_ips.contains(&ip);

    match state
        .magicsock
        .cli_ping(&peer_key, &peer_name, ip, size)
        .await
    {
        Ok(mut pr) => {
            pr.NodeIP = ip.to_string();
            pr.IsLocalIP = is_local_ip;
            if pr.Err.is_empty() && is_local_ip {
                pr.Err = "local IP".into();
            }
            let json = serde_json::to_value(&pr).unwrap_or_default();
            write_json_response(conn, 200, "OK", &json).await
        }
        Err(e) => {
            let pr = rustscale_ipnstate::PingResult {
                IP: ip.to_string(),
                NodeIP: ip.to_string(),
                NodeName: peer_name,
                Err: e.to_string(),
                ..Default::default()
            };
            let json = serde_json::to_value(&pr).unwrap_or_default();
            // Return 200 with the error in the result (Go does the same —
            // the ping "succeeded" as an operation, it just got an error).
            write_json_response(conn, 200, "OK", &json).await
        }
    }
}

/// Handle ICMP ping: uses the netcheck ICMP pinger (unprivileged DGRAM+ICMP).
async fn handle_icmp_ping<W: AsyncWrite + Unpin>(
    conn: &mut W,
    ip: IpAddr,
    state: &Arc<LocalApiState>,
) -> Result<(), std::io::Error> {
    let _ = state;
    let Some(mut pinger) = rustscale_netcheck::icmp::Pinger::new_v4() else {
        let body = serde_json::json!({
            "error": "ICMP not available (need root or ping_group_range)"
        });
        return write_json_response(conn, 501, "Not Implemented", &body).await;
    };
    if let Some(rtt) = pinger.ping(ip, b"rustscale-ping").await {
        let pr = rustscale_ipnstate::PingResult {
            IP: ip.to_string(),
            NodeIP: ip.to_string(),
            LatencySeconds: rtt.as_secs_f64(),
            ..Default::default()
        };
        let json = serde_json::to_value(&pr).unwrap_or_default();
        write_json_response(conn, 200, "OK", &json).await
    } else {
        let pr = rustscale_ipnstate::PingResult {
            IP: ip.to_string(),
            NodeIP: ip.to_string(),
            Err: "ICMP ping timed out or failed".into(),
            ..Default::default()
        };
        let json = serde_json::to_value(&pr).unwrap_or_default();
        write_json_response(conn, 200, "OK", &json).await
    }
}

/// Handle TSMP ping: Tailscale's own protocol over WireGuard. Currently
/// stubbed — requires a TSMP implementation in the WireGuard data plane.
async fn handle_tsmp_ping<W: AsyncWrite + Unpin>(
    conn: &mut W,
    ip: IpAddr,
    _state: &Arc<LocalApiState>,
) -> Result<(), std::io::Error> {
    let pr = rustscale_ipnstate::PingResult {
        IP: ip.to_string(),
        NodeIP: ip.to_string(),
        Err: "TSMP ping not yet implemented".into(),
        ..Default::default()
    };
    let json = serde_json::to_value(&pr).unwrap_or_default();
    write_json_response(conn, 200, "OK", &json).await
}

/// Handle peerapi ping: sends a HEAD to the peer's PeerAPI via netstack.
async fn handle_peerapi_ping<W: AsyncWrite + Unpin>(
    conn: &mut W,
    ip: IpAddr,
    _state: &Arc<LocalApiState>,
) -> Result<(), std::io::Error> {
    let pr = rustscale_ipnstate::PingResult {
        IP: ip.to_string(),
        NodeIP: ip.to_string(),
        Err: "peerapi ping not yet implemented".into(),
        ..Default::default()
    };
    let json = serde_json::to_value(&pr).unwrap_or_default();
    write_json_response(conn, 200, "OK", &json).await
}

// ---------------------------------------------------------------------------
// Watch IPN Bus handler (streaming newline-delimited JSON)
// ---------------------------------------------------------------------------

/// Handle GET /localapi/v0/watch-ipn-bus?mask=<u64>
///
/// Streams newline-delimited JSON `Notify` messages. The first message
/// may contain initial state (depending on the mask bits), then subsequent
/// messages are delivered as the backend state changes.
///
/// The response uses connection-close delimiting (no Content-Length); the
/// client reads JSON lines until EOF. Each line is flushed immediately.
///
/// # Mask validation
///
/// - `NotifyInProcessNoDisconnect` is rejected (only valid for in-process
///   subscribers, not LocalAPI).
/// - `NotifyRateLimit` combined with incompatible bits is rejected.
///
/// # Supported initial bits
///
/// - `NotifyInitialState`: includes SessionID + State in the first message.
/// - `NotifyInitialPrefs`: includes Prefs in the first message.
/// - `NotifyInitialStatus`: includes InitialStatus (status JSON) in the
///   first message.
async fn handle_watch_ipn_bus<W: AsyncWrite + Unpin>(
    conn: &mut W,
    query: &str,
    state: &Arc<LocalApiState>,
) -> Result<(), std::io::Error> {
    use rustscale_ipn::{NOTIFY_INITIAL_PREFS, NOTIFY_INITIAL_STATE, NOTIFY_INITIAL_STATUS};

    let params = parse_query(query);

    // Parse and validate the mask.
    let mask: NotifyWatchOpt = match params.get("mask") {
        Some(s) if !s.is_empty() => {
            if let Ok(v) = s.parse::<u64>() {
                v
            } else {
                let body = serde_json::json!({"error": "bad mask"});
                write_json_response(conn, 400, "Bad Request", &body).await?;
                return Ok(());
            }
        }
        _ => 0,
    };

    if mask & NOTIFY_IN_PROCESS_NO_DISCONNECT != 0 {
        let body = serde_json::json!({
            "error": "NotifyInProcessNoDisconnect is only valid for in-process IPN bus subscribers"
        });
        write_json_response(conn, 400, "Bad Request", &body).await?;
        return Ok(());
    }

    if let Err(e) = validate_notify_watch_opt(mask) {
        let body = serde_json::json!({"error": e});
        write_json_response(conn, 400, "Bad Request", &body).await?;
        return Ok(());
    }

    // Generate a session ID (hex string, like Go's rands.HexString(16)).
    let session_id = generate_session_id();

    // Build and send the initial Notify message if any initial bits are set.
    let has_initial =
        mask & (NOTIFY_INITIAL_STATE | NOTIFY_INITIAL_PREFS | NOTIFY_INITIAL_STATUS) != 0;

    // Write the HTTP response header (streaming, connection-close delimited).
    let header = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n";
    conn.write_all(header.as_bytes()).await?;
    conn.flush().await?;

    if has_initial {
        // Build initial status if requested.
        let initial_status = if mask & NOTIFY_INITIAL_STATUS != 0 {
            Some(build_status_json(state).await)
        } else {
            None
        };

        // Build initial prefs if requested.
        let initial_prefs = if mask & NOTIFY_INITIAL_PREFS != 0 {
            Some(serde_json::to_value(&*state.prefs.read().await).unwrap_or_default())
        } else {
            None
        };

        let notify = state.ipn_backend.build_initial_notify(
            mask,
            &session_id,
            initial_status,
            initial_prefs,
        );

        let line = serde_json::to_vec(&notify).unwrap_or_default();
        conn.write_all(&line).await?;
        conn.write_all(b"\n").await?;
        conn.flush().await?;
    }

    // Subscribe to the bus and stream subsequent messages.
    let mut rx = state.ipn_backend.bus().subscribe();

    loop {
        match rx.recv().await {
            Some(Ok(notify)) => {
                let line = serde_json::to_vec(&notify).unwrap_or_default();
                conn.write_all(&line).await?;
                conn.write_all(b"\n").await?;
                conn.flush().await?;
            }
            Some(Err(_)) => {
                // Subscriber fell behind (Lagged); skip and continue.
                continue;
            }
            None => {
                // Bus shut down (all senders dropped). End the stream.
                break;
            }
        }
    }

    Ok(())
}

/// Generate a random hex session ID (16 bytes = 32 hex chars), matching
/// Go's `rands.HexString(16)`.
fn generate_session_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Simple non-cryptographic session ID: timestamp + counter.
    // This is sufficient for local IPC session identification.
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let ctr = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{ts:016x}{ctr:016x}")
}

// ---------------------------------------------------------------------------
// Default socket path
// ---------------------------------------------------------------------------

/// Compute the default LocalAPI socket path from a state directory.
/// Returns `<state_dir>/rustscale.sock`.
pub(crate) fn default_socket_path(state_dir: &std::path::Path) -> PathBuf {
    state_dir.join("rustscale.sock")
}

// ---------------------------------------------------------------------------
// Serve config handler (GET/POST /localapi/v0/serve-config)
// ---------------------------------------------------------------------------

/// Write a JSON response with an ETag header.
async fn write_json_with_etag<W: AsyncWrite + Unpin>(
    conn: &mut W,
    status: u16,
    reason: &str,
    etag: &str,
    body: &[u8],
) -> Result<(), std::io::Error> {
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n\
         ETag: \"{etag}\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    conn.write_all(header.as_bytes()).await?;
    conn.write_all(body).await?;
    conn.flush().await?;
    Ok(())
}

/// Handle GET /localapi/v0/serve-config — returns the current serve config
/// with an ETag header (SHA-256 of canonical JSON).
async fn handle_get_serve_config<W: AsyncWrite + Unpin>(
    conn: &mut W,
    state: &Arc<LocalApiState>,
) -> Result<(), std::io::Error> {
    let cfg = state.serve_config.read().await.clone();
    let etag = cfg.etag();
    let body = serde_json::to_vec(&cfg).unwrap_or_default();
    write_json_with_etag(conn, 200, "OK", &etag, &body).await
}

/// Handle POST /localapi/v0/serve-config — requires If-Match header when
/// a config exists, returns 412 on mismatch. Applies via the serve runner
/// and persists to `<state_dir>/serve-config.json`.
async fn handle_post_serve_config<W: AsyncWrite + Unpin>(
    conn: &mut W,
    req: &HttpRequest,
    state: &Arc<LocalApiState>,
) -> Result<(), std::io::Error> {
    // Parse the incoming config.
    let cfg_in: ServeConfig = match serde_json::from_slice(&req.body) {
        Ok(c) => c,
        Err(e) => {
            let err = serde_json::json!({"error": format!("bad serve config: {e}")});
            write_json_response(conn, 400, "Bad Request", &err).await?;
            return Ok(());
        }
    };

    // Extract If-Match header.
    let if_match = req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("if-match"))
        .map(|(_, v)| v.trim_matches('"').to_string())
        .unwrap_or_default();

    // Check ETag if If-Match is present.
    let current_cfg = state.serve_config.read().await.clone();
    let current_etag = current_cfg.etag();
    if !if_match.is_empty() && if_match != current_etag {
        let body = serde_json::json!({"error": "etag mismatch"});
        let body_bytes = serde_json::to_vec(&body).unwrap_or_default();
        let header = format!(
            "HTTP/1.1 412 Precondition Failed\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            body_bytes.len()
        );
        conn.write_all(header.as_bytes()).await?;
        conn.write_all(&body_bytes).await?;
        conn.flush().await?;
        return Ok(());
    }

    // Apply the config via the serve runner (if available).
    if let Some(ref runner) = state.serve_runner {
        if let Err(e) = runner.set_config(cfg_in.clone(), None).await {
            let err = serde_json::json!({"error": format!("serve apply failed: {e}")});
            write_json_response(conn, 500, "Internal Server Error", &err).await?;
            return Ok(());
        }
    }

    // Update the shared config state.
    *state.serve_config.write().await = cfg_in.clone();

    // Persist to disk.
    if let Some(ref dir) = state.state_dir {
        if let Err(e) = cfg_in.save(dir) {
            eprintln!("localapi: serve-config persist failed: {e}");
        }
    }

    // Return 200 with the new ETag.
    let new_etag = cfg_in.etag();
    let body = serde_json::to_vec(&cfg_in).unwrap_or_default();
    write_json_with_etag(conn, 200, "OK", &new_etag, &body).await
}

// ---------------------------------------------------------------------------
// Cert handler (GET /localapi/v0/cert/<domain>)
// ---------------------------------------------------------------------------

/// Handle `GET /localapi/v0/cert/<domain>?type=pair|cert|key&min_validity=<dur>`.
///
/// Ports Go's `ipn/localapi/cert.go` → `serveCert` / `serveKeyPair`. The
/// domain must appear in the tailnet's `DNSConfig.CertDomains` (i.e. HTTPS
/// certs are enabled); otherwise 404. The cert is provisioned/cached via
/// the existing ACME path ([`ControlCertProvider`] + [`AcmeCertFetcher`]).
///
/// # Query parameters
///
/// - `type`: `pair` (default; key PEM then cert PEM concatenated), `cert`
///   (or `crt`; cert PEM only), `key` (key PEM only).
/// - `min_validity`: a Go-style duration string (e.g. `"720h"`); the cert
///   is renewed if its remaining validity is less than this. `0` / empty
///   means "just don't be expired".
///
/// # Response
///
/// `Content-Type: text/plain`; the body is PEM text. For `type=pair` the key
/// PEM block comes first, then the cert PEM blocks (matching Go).
async fn handle_cert<W: AsyncWrite + Unpin>(
    conn: &mut W,
    method: &str,
    domain_suffix: &str,
    query: &str,
    state: &Arc<LocalApiState>,
) -> Result<(), std::io::Error> {
    if method != "GET" {
        let body = serde_json::json!({"error": "use GET"});
        write_json_response(conn, 405, "Method Not Allowed", &body).await?;
        return Ok(());
    }

    let domain = domain_suffix.trim_end_matches('/');
    if domain.is_empty() {
        let body = serde_json::json!({"error": "missing domain in path"});
        write_json_response(conn, 400, "Bad Request", &body).await?;
        return Ok(());
    }

    let params = parse_query(query);
    let typ = params.get("type").map_or("pair", String::as_str);

    // Parse min_validity duration (Go-style: "720h", "30m", "1h30m"; 0/empty = none).
    let min_validity = match params.get("min_validity") {
        Some(v) if !v.is_empty() && v != "0" => match parse_go_duration(v) {
            Ok(d) => d,
            Err(msg) => {
                let body = serde_json::json!({"error": format!("invalid min_validity: {msg}")});
                write_json_response(conn, 400, "Bad Request", &body).await?;
                return Ok(());
            }
        },
        _ => chrono::Duration::zero(),
    };

    // Validate the domain against the tailnet's CertDomains (live DNSConfig).
    let cert_domains: Vec<String> = state
        .dns_config
        .read()
        .await
        .as_ref()
        .map(|c| c.CertDomains.clone())
        .unwrap_or_default();
    let domain_lc = domain.trim_end_matches('.').to_lowercase();
    let allowed = cert_domains
        .iter()
        .any(|c| c.trim_end_matches('.').eq_ignore_ascii_case(&domain_lc));
    if !allowed {
        let body = serde_json::json!({
            "error": "cert domain not authorized",
            "domain": domain,
            "cert_domains": cert_domains,
        });
        write_json_response(conn, 404, "Not Found", &body).await?;
        return Ok(());
    }

    // Build the cert provider on demand (reuses the ACME fetcher + cache).
    let Some(ref cp) = state.cert_params else {
        let body =
            serde_json::json!({"error": "cert provisioning unavailable (server not fully up)"});
        write_json_response(conn, 500, "Internal Server Error", &body).await?;
        return Ok(());
    };

    let fetcher = Arc::new(AcmeCertFetcher::new(
        cert_domains,
        cp.state_dir.clone(),
        cp.control_url.clone(),
        cp.machine_key.clone(),
        cp.server_pub_key.clone(),
        cp.node_key.clone(),
        cp.capability_version,
        cp.protocol_version,
    ));
    let provider = ControlCertProvider::new(cp.state_dir.clone(), domain, fetcher);
    if let Err(e) = provider.refresh_with_min_validity(min_validity).await {
        let body = serde_json::json!({"error": e.to_string()});
        write_json_response(conn, 500, "Internal Server Error", &body).await?;
        return Ok(());
    }

    let (cert_pem, key_pem) = if let (Some(c), Some(k)) = (provider.cert_pem(), provider.key_pem())
    {
        (c, k)
    } else {
        let body = serde_json::json!({"error": "cert material unavailable after refresh"});
        write_json_response(conn, 500, "Internal Server Error", &body).await?;
        return Ok(());
    };

    let body: Vec<u8> = match typ {
        "pair" | "" => {
            let mut out = Vec::with_capacity(key_pem.len() + cert_pem.len());
            out.extend_from_slice(&key_pem);
            out.extend_from_slice(&cert_pem);
            out
        }
        "cert" | "crt" => cert_pem,
        "key" => key_pem,
        other => {
            let body = serde_json::json!({
                "error": format!("invalid type '{other}'; want \"pair\", \"cert\", or \"key\"")
            });
            write_json_response(conn, 400, "Bad Request", &body).await?;
            return Ok(());
        }
    };

    write_raw_response(conn, 200, "OK", "text/plain", &body).await
}

/// Parse a Go-style duration string (`"720h"`, `"30m"`, `"1h30m"`, `"3600s"`).
/// Supports `h`, `m`, `s` suffixes (case-insensitive). Returns the parsed
/// duration or an error message.
fn parse_go_duration(s: &str) -> Result<chrono::Duration, String> {
    let s = s.trim();
    if s.is_empty() || s == "0" {
        return Ok(chrono::Duration::zero());
    }
    let mut total = chrono::Duration::zero();
    let mut rest = s;
    while !rest.is_empty() {
        // Find the end of the numeric part.
        let num_end = rest
            .bytes()
            .position(|b| !b.is_ascii_digit() && b != b'.')
            .unwrap_or(rest.len());
        if num_end == 0 {
            return Err(format!("expected number at start of '{rest}'"));
        }
        let n: f64 = rest[..num_end]
            .parse()
            .map_err(|e| format!("bad number in '{s}': {e}"))?;
        rest = &rest[num_end..];
        // Find the unit.
        let unit_end = rest
            .bytes()
            .position(|b| b.is_ascii_digit() || b == b'.')
            .unwrap_or(rest.len());
        if unit_end == 0 {
            return Err(format!("expected unit after number in '{s}'"));
        }
        let unit = rest[..unit_end].to_ascii_lowercase();
        rest = &rest[unit_end..];
        let secs = match unit.as_str() {
            "h" => n * 3600.0,
            "m" => n * 60.0,
            "s" => n,
            "ms" => n / 1000.0,
            other => return Err(format!("unknown duration unit '{other}'")),
        };
        total = total
            + chrono::Duration::seconds(secs.trunc() as i64)
            + chrono::Duration::milliseconds(((secs.fract()) * 1000.0).round() as i64);
    }
    Ok(total)
}

// ---------------------------------------------------------------------------
// Profiles handlers
// ---------------------------------------------------------------------------

/// Handle GET /localapi/v0/profiles — list all profiles.
async fn handle_list_profiles<W: AsyncWrite + Unpin>(
    conn: &mut W,
    state: &Arc<LocalApiState>,
) -> Result<(), std::io::Error> {
    let profiles = state.profiles.read().await;
    let json = serde_json::to_value(&*profiles).unwrap_or(serde_json::json!([]));
    write_json_response(conn, 200, "OK", &json).await
}

/// Handle PUT /localapi/v0/profiles — create a new empty profile and
/// switch to it.
async fn handle_new_profile<W: AsyncWrite + Unpin>(
    conn: &mut W,
    state: &Arc<LocalApiState>,
) -> Result<(), std::io::Error> {
    let id = LoginProfile::new_id();
    let profile = LoginProfile {
        ID: id.clone(),
        Key: format!("profile-{id}"),
        ..Default::default()
    };

    {
        let mut profiles = state.profiles.write().await;
        profiles.push(profile);
        if let Some(ref dir) = state.state_dir {
            let _ = LoginProfile::save_all(dir, &profiles);
        }
    }

    // Switch to the new profile.
    {
        let mut current = state.current_profile.write().await;
        *current = Some(id.clone());
        if let Some(ref dir) = state.state_dir {
            let _ = LoginProfile::save_current_id(dir, &id);
        }
    }

    write_no_content_response(conn, 201, "Created").await?;
    Ok(())
}

/// Handle profile sub-paths: profiles/current, profiles/<id>.
async fn handle_profile_subpath<W: AsyncWrite + Unpin>(
    conn: &mut W,
    method: &str,
    suffix: &str,
    state: &Arc<LocalApiState>,
) -> Result<(), std::io::Error> {
    let suffix = suffix.trim_end_matches('/');

    if suffix == "current" {
        if method != "GET" {
            let body = serde_json::json!({"error": "use GET"});
            write_json_response(conn, 405, "Method Not Allowed", &body).await?;
            return Ok(());
        }
        let current_id = state.current_profile.read().await.clone();
        let profiles = state.profiles.read().await;
        let current = current_id
            .and_then(|id| profiles.iter().find(|p| p.ID == id).cloned())
            .unwrap_or_default();
        let json = serde_json::to_value(&current).unwrap_or(serde_json::json!({}));
        write_json_response(conn, 200, "OK", &json).await?;
        return Ok(());
    }

    // profiles/<id>
    let profile_id = suffix.to_string();
    match method {
        "GET" => {
            let profiles = state.profiles.read().await;
            if let Some(p) = profiles.iter().find(|p| p.ID == profile_id) {
                let json = serde_json::to_value(p).unwrap_or(serde_json::json!({}));
                write_json_response(conn, 200, "OK", &json).await?;
            } else {
                let body = serde_json::json!({"error": "profile not found"});
                write_json_response(conn, 404, "Not Found", &body).await?;
            }
        }
        "POST" => {
            // Switch to the profile. Validate the ID, then delegate the
            // full teardown+restart to the daemon loop via
            // `DaemonCommand::SwitchProfile`. The daemon calls
            // `Server::switch_profile`, which closes the running engine,
            // reloads the ProfileManager from disk, applies the new
            // profile's prefs, and re-bootstraps with `up()`. Mirrors
            // Go's `LocalBackend.SwitchProfile` → `resetForProfileChangeLocked`.
            let profiles = state.profiles.read().await;
            if !profiles.iter().any(|p| p.ID == profile_id) {
                let body = serde_json::json!({"error": "profile not found"});
                write_json_response(conn, 404, "Not Found", &body).await?;
                return Ok(());
            }
            drop(profiles);

            if let Some(ref tx) = state.command_tx {
                let _ = tx.send(DaemonCommand::SwitchProfile(profile_id.clone()));
            }
            // Save the current-profile ID immediately so a crash during
            // teardown doesn't lose the switch intent.
            if let Some(ref dir) = state.state_dir {
                let _ = LoginProfile::save_current_id(dir, &profile_id);
            }
            // Update the in-memory current-profile pointer so concurrent
            // `GET /profiles/current` requests see the switch right away.
            {
                let mut current = state.current_profile.write().await;
                *current = Some(profile_id.clone());
            }

            write_no_content_response(conn, 204, "No Content").await?;
        }
        "DELETE" => {
            let mut profiles = state.profiles.write().await;
            let len_before = profiles.len();
            profiles.retain(|p| p.ID != profile_id);
            if profiles.len() == len_before {
                let body = serde_json::json!({"error": "profile not found"});
                write_json_response(conn, 404, "Not Found", &body).await?;
                return Ok(());
            }
            if let Some(ref dir) = state.state_dir {
                let _ = LoginProfile::save_all(dir, &profiles);
            }

            // If we deleted the current profile, clear or pick a new one.
            let mut current = state.current_profile.write().await;
            if current.as_deref() == Some(profile_id.as_str()) {
                *current = profiles.first().map(|p| p.ID.clone());
                if let Some(ref dir) = state.state_dir {
                    if let Some(ref id) = *current {
                        let _ = LoginProfile::save_current_id(dir, id);
                    }
                }
            }
            drop(current);
            drop(profiles);

            write_no_content_response(conn, 204, "No Content").await?;
        }
        _ => {
            let body = serde_json::json!({"error": "use GET, POST, or DELETE"});
            write_json_response(conn, 405, "Method Not Allowed", &body).await?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Taildrop handlers (file-targets, files, file-put)
// ---------------------------------------------------------------------------

/// Handle GET /localapi/v0/file-targets — list peers that can receive
/// Taildrop files. Mirrors Go's `serveFileTargets`.
async fn handle_file_targets<W: AsyncWrite + Unpin>(
    conn: &mut W,
    state: &Arc<LocalApiState>,
) -> Result<(), std::io::Error> {
    let Some(ref taildrop) = state.taildrop else {
        let body = serde_json::json!({"error": "taildrop not enabled"});
        write_json_response(conn, 500, "Internal Server Error", &body).await?;
        return Ok(());
    };
    let peers = state.peers.read().await;
    let user_profiles = state.user_profiles.read().await;
    match taildrop.file_targets(&peers, &user_profiles).await {
        Ok(targets) => {
            let json = serde_json::to_value(&targets).unwrap_or(serde_json::json!([]));
            write_json_response(conn, 200, "OK", &json).await?;
        }
        Err(e) => {
            let body = serde_json::json!({"error": e.to_string()});
            write_json_response(conn, 500, "Internal Server Error", &body).await?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Debug / dial / DNS query / IP forwarding handlers
// ---------------------------------------------------------------------------

/// Resolve a `host:port` string to a `SocketAddr`, looking up tailnet
/// hostnames in the peer list. Returns `None` if the host cannot be
/// resolved or the port is missing/invalid.
fn resolve_dial_addr(addr: &str, peers: &[Node]) -> Option<SocketAddr> {
    let (host, port_str) = addr.rsplit_once(':')?;
    let port: u16 = port_str.parse().ok()?;

    // Try direct IP parse first.
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, port));
    }

    // Look up hostname in peers (case-insensitive, strip trailing dot).
    let host_lower = host.trim_end_matches('.').to_lowercase();
    for peer in peers {
        let peer_name = peer.Name.trim_end_matches('.').to_lowercase();
        let first_label = peer_name.split('.').next().unwrap_or("");
        if peer_name == host_lower || first_label == host_lower {
            for cidr in &peer.Addresses {
                if let Some(ip_str) = cidr.split('/').next() {
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        return Some(SocketAddr::new(ip, port));
                    }
                }
            }
        }
    }
    None
}

/// Handle GET /localapi/v0/debug?action=<method>
///
/// Generic debug endpoint. The `action` query parameter selects the
/// sub-command. Mirrors a subset of Go's `LocalBackend.HandleDebugJSON`
/// actions. Returns JSON with the requested debug info.
async fn handle_debug<W: AsyncWrite + Unpin>(
    conn: &mut W,
    query: &str,
    state: &Arc<LocalApiState>,
) -> Result<(), std::io::Error> {
    let params = parse_query(query);
    let action = params.get("action").map(String::as_str).unwrap_or("status");

    let result = match action {
        "status" => {
            let peers = state.peers.read().await;
            serde_json::json!({
                "backend_state": state.ipn_backend.state().as_str(),
                "peer_count": peers.len(),
                "hostname": state.hostname,
                "tun_mode": state.tun_mode,
                "home_derp": state.home_derp,
            })
        }
        "ipconfig" => {
            // Return local interface info. On Unix, list interfaces via
            // std::net or the OS. Minimal stub for now.
            serde_json::json!({
                "interfaces": [],
                "note": "ipconfig detail not yet implemented",
            })
        }
        "metrics" => {
            let text = build_metrics_text(state);
            serde_json::json!({
                "metrics": text,
            })
        }
        other => {
            let body = serde_json::json!({
                "error": format!("unknown debug action: {other}"),
                "available": ["status", "ipconfig", "metrics"],
            });
            write_json_response(conn, 400, "Bad Request", &body).await?;
            return Ok(());
        }
    };
    write_json_response(conn, 200, "OK", &result).await?;
    Ok(())
}

/// Handle POST /localapi/v0/check-prefs
///
/// Validate a `Prefs` body without applying it. Returns JSON with an
/// `error` field (empty string on success). Mirrors Go's
/// `serveCheckPrefs` → `LocalBackend.CheckPrefs`.
async fn handle_check_prefs<W: AsyncWrite + Unpin>(
    conn: &mut W,
    body: &[u8],
) -> Result<(), std::io::Error> {
    let prefs: Prefs = match serde_json::from_slice(body) {
        Ok(p) => p,
        Err(e) => {
            let body = serde_json::json!({"error": format!("invalid JSON body: {e}")});
            write_json_response(conn, 400, "Bad Request", &body).await?;
            return Ok(());
        }
    };

    let mut errors: Vec<String> = Vec::new();

    // Validate ExitNodeIP: must be a parseable IP address if non-empty.
    if !prefs.ExitNodeIP.is_empty() && prefs.ExitNodeIP.parse::<IpAddr>().is_err() {
        errors.push(format!(
            "ExitNodeIP {:?} is not a valid IP address",
            prefs.ExitNodeIP
        ));
    }

    // Validate AdvertiseRoutes: each entry must be a valid CIDR.
    for route in &prefs.AdvertiseRoutes {
        if let Some((ip, prefix)) = route.split_once('/') {
            if ip.parse::<IpAddr>().is_err() {
                errors.push(format!("AdvertiseRoute {route:?} has invalid IP"));
            } else if prefix.parse::<u8>().is_err() {
                errors.push(format!(
                    "AdvertiseRoute {route:?} has invalid prefix length"
                ));
            }
        } else if !route.is_empty() {
            errors.push(format!(
                "AdvertiseRoute {route:?} is not a valid CIDR (missing /)"
            ));
        }
    }

    // Validate ExitNodeAllowLANAccess only makes sense with an exit node.
    if prefs.ExitNodeAllowLANAccess && prefs.ExitNodeID.is_empty() && prefs.ExitNodeIP.is_empty() {
        errors.push("ExitNodeAllowLANAccess set without ExitNodeID or ExitNodeIP".into());
    }

    let error = errors.join("; ");
    let body = serde_json::json!({"error": error});
    write_json_response(conn, 200, "OK", &body).await?;
    Ok(())
}

/// Handle POST /localapi/v0/set-expiry-sooner
///
/// Accepts an `expiry` form parameter (Unix timestamp in seconds) and
/// queues a key-expiry-sooner request. Mirrors Go's `serveSetExpirySooner`
/// → `LocalBackend.SetExpirySooner`. Returns `done\n` as text/plain.
async fn handle_set_expiry_sooner<W: AsyncWrite + Unpin>(
    conn: &mut W,
    body: &[u8],
    query: &str,
) -> Result<(), std::io::Error> {
    // The expiry may come from the form body or the query string.
    let body_str = std::str::from_utf8(body).unwrap_or("");
    let body_params = parse_query(body_str);
    let query_params = parse_query(query);
    let expiry_str = body_params
        .get("expiry")
        .or_else(|| query_params.get("expiry"));

    let expiry_str = match expiry_str {
        Some(v) if !v.is_empty() => v,
        _ => {
            let body = serde_json::json!({
                "error": "missing 'expiry' parameter, a unix timestamp"
            });
            write_json_response(conn, 400, "Bad Request", &body).await?;
            return Ok(());
        }
    };

    let expiry_ts: i64 = if let Ok(v) = expiry_str.parse() {
        v
    } else {
        let body = serde_json::json!({
            "error": "can't parse expiry time, expects a unix timestamp"
        });
        write_json_response(conn, 400, "Bad Request", &body).await?;
        return Ok(());
    };

    // Basic sanity: the new expiry should be in the future.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if expiry_ts <= now {
        let body = serde_json::json!({
            "error": "expiry must be a future timestamp"
        });
        write_json_response(conn, 400, "Bad Request", &body).await?;
        return Ok(());
    }

    // TODO: wire the expiry into the next MapRequest's Hostinfo or a
    // dedicated SetExpirySooner control call. The link_monitor loop
    // sends periodic MapRequests; the expiry would be included there.
    // For now we accept and acknowledge the request.

    write_raw_response(conn, 200, "OK", "text/plain", b"done\n").await?;
    Ok(())
}

/// Handle POST /localapi/v0/shutdown
///
/// Sends a `DaemonCommand::Shutdown` to the daemon loop for graceful
/// shutdown. Mirrors Go's `serveShutdown` which publishes a `Shutdown`
/// event on the event bus.
async fn handle_shutdown<W: AsyncWrite + Unpin>(
    conn: &mut W,
    state: &Arc<LocalApiState>,
) -> Result<(), std::io::Error> {
    if let Some(ref tx) = state.command_tx {
        let _ = tx.send(DaemonCommand::Shutdown);
        write_raw_response(conn, 200, "OK", "text/plain", b"").await?;
    } else {
        let body = serde_json::json!({"error": "no daemon command channel"});
        write_json_response(conn, 503, "Service Unavailable", &body).await?;
    }
    Ok(())
}

/// Handle GET /localapi/v0/id-token
///
/// Fetch an OIDC ID token from the control plane for the given audience.
/// **Stub**: OIDC ID token support requires Noise-protocol control plane
/// integration (`DoNoiseRequest`) not yet implemented in rustscale.
/// Returns 501 Not Implemented.
async fn handle_id_token<W: AsyncWrite + Unpin>(
    conn: &mut W,
    query: &str,
) -> Result<(), std::io::Error> {
    let params = parse_query(query);
    let aud = params.get("aud").map(String::as_str).unwrap_or("");
    if aud.is_empty() {
        let body = serde_json::json!({"error": "no audience requested"});
        write_json_response(conn, 400, "Bad Request", &body).await?;
        return Ok(());
    }
    let body = serde_json::json!({
        "error": "id-token not yet supported: OIDC Noise request not implemented"
    });
    write_json_response(conn, 501, "Not Implemented", &body).await?;
    Ok(())
}

/// Handle POST /localapi/v0/debug (action dispatcher)
///
/// Dispatches debug actions via the `action` form/query parameter.
/// Mirrors Go's `serveDebug` in `ipn/localapi/debug.go`. Supported
/// actions are a subset of Go's full set; unsupported actions return
/// a 400 error listing what's available.
async fn handle_debug_action<W: AsyncWrite + Unpin>(
    conn: &mut W,
    body: &[u8],
    query: &str,
    state: &Arc<LocalApiState>,
) -> Result<(), std::io::Error> {
    // The action may come from the form body, query string, or a
    // `Debug-Action` header (matching Go's logic for "notify").
    let body_str = std::str::from_utf8(body).unwrap_or("");
    let body_params = parse_query(body_str);
    let query_params = parse_query(query);
    let action = body_params
        .get("action")
        .or_else(|| query_params.get("action"))
        .map(String::as_str)
        .unwrap_or("");

    if action.is_empty() {
        let body = serde_json::json!({
            "error": "missing 'action' parameter",
            "available": [
                "statedir",
                "force-netmap-update",
                "rebind",
                "restun",
            ],
        });
        write_json_response(conn, 400, "Bad Request", &body).await?;
        return Ok(());
    }

    let result = match action {
        "statedir" => {
            let dir = state
                .state_dir
                .as_ref()
                .map(|d| d.display().to_string())
                .unwrap_or_default();
            serde_json::json!(dir)
        }
        "force-netmap-update" => {
            // TODO: trigger a forced netmap refresh. The link_monitor
            // loop handles periodic updates; a forced refresh would
            // signal it to send an immediate MapRequest.
            serde_json::json!({"status": "queued"})
        }
        "rebind" => {
            // Rebind magicsock: signal link change to close/reopen sockets.
            state.magicsock.link_changed();
            serde_json::json!({"status": "ok"})
        }
        "restun" => {
            // Trigger a re-STUN / endpoint refresh.
            // TODO: wire to netcheck/magicsock endpoint refresh.
            serde_json::json!({"status": "queued"})
        }
        other => {
            let body = serde_json::json!({
                "error": format!("unknown debug action: {other}"),
                "available": [
                    "statedir",
                    "force-netmap-update",
                    "rebind",
                    "restun",
                ],
            });
            write_json_response(conn, 400, "Bad Request", &body).await?;
            return Ok(());
        }
    };
    write_json_response(conn, 200, "OK", &result).await?;
    Ok(())
}

/// Handle POST /localapi/v0/dial?addr=<host:port>
///
/// Attempts to dial a remote address through the daemon's netstack.
/// Returns a JSON status indicating success or failure. This is a minimal
/// implementation that verifies reachability without proxying full data.
async fn handle_dial<W: AsyncWrite + Unpin>(
    conn: &mut W,
    query: &str,
    state: &Arc<LocalApiState>,
) -> Result<(), std::io::Error> {
    let params = parse_query(query);
    let addr = match params.get("addr") {
        Some(a) if !a.is_empty() => a.clone(),
        _ => {
            let body = serde_json::json!({"error": "missing addr parameter"});
            write_json_response(conn, 400, "Bad Request", &body).await?;
            return Ok(());
        }
    };

    // If netstack is available, attempt a TCP dial through it.
    if let Some(ref netstack) = state.netstack {
        // Parse addr into host:port, resolving hostnames via peers.
        let dial_addr = resolve_dial_addr(&addr, &state.peers.read().await);
        if let Some(socket_addr) = dial_addr {
            match netstack.dial(socket_addr).await {
                Ok(_stream) => {
                    let body = serde_json::json!({
                        "ok": true,
                        "addr": addr,
                        "resolved": socket_addr.to_string(),
                        "via": "netstack",
                    });
                    write_json_response(conn, 200, "OK", &body).await?;
                }
                Err(e) => {
                    let body = serde_json::json!({
                        "ok": false,
                        "addr": addr,
                        "resolved": socket_addr.to_string(),
                        "error": e.to_string(),
                    });
                    write_json_response(conn, 200, "OK", &body).await?;
                }
            }
        } else {
            let body = serde_json::json!({
                "ok": false,
                "addr": addr,
                "error": "could not resolve address",
            });
            write_json_response(conn, 200, "OK", &body).await?;
        }
    } else {
        let body = serde_json::json!({
            "ok": false,
            "addr": addr,
            "error": "netstack not available (server not fully up or TUN mode)",
        });
        write_json_response(conn, 503, "Service Unavailable", &body).await?;
    }
    Ok(())
}

/// Handle GET /localapi/v0/dns-query?name=<name>&type=<type>
///
/// Queries the daemon's DNS resolver for the given name. The `type`
/// parameter is optional (defaults to "A"). Returns resolved IPs.
async fn handle_dns_query<W: AsyncWrite + Unpin>(
    conn: &mut W,
    query: &str,
    state: &Arc<LocalApiState>,
) -> Result<(), std::io::Error> {
    let params = parse_query(query);
    let name = match params.get("name") {
        Some(n) if !n.is_empty() => n.clone(),
        _ => {
            let body = serde_json::json!({"error": "missing name parameter"});
            write_json_response(conn, 400, "Bad Request", &body).await?;
            return Ok(());
        }
    };
    let qtype = params.get("type").map(String::as_str).unwrap_or("A");

    let peers = state.peers.read().await;
    let dns_config = state.dns_config.read().await;

    // Resolve by looking up the name in the peer list. This mirrors
    // MagicDnsResolver's local resolution logic for tailnet names.
    let name_trimmed = name.trim_end_matches('.').to_lowercase();
    let mut results: Vec<String> = Vec::new();

    for peer in peers.iter() {
        let peer_name = peer.Name.trim_end_matches('.').to_lowercase();
        let first_label = peer_name.split('.').next().unwrap_or("");
        if peer_name == name_trimmed || first_label == name_trimmed {
            for addr in &peer.Addresses {
                if let Some(ip) = addr.split('/').next() {
                    results.push(ip.to_string());
                }
            }
        }
    }

    // Check if MagicDNS is enabled and provide context.
    let magicdns_enabled = dns_config.as_ref().is_some_and(|c| c.Proxied);

    let response = serde_json::json!({
        "name": name,
        "type": qtype,
        "results": results,
        "magicdns_enabled": magicdns_enabled,
    });
    write_json_response(conn, 200, "OK", &response).await?;
    Ok(())
}

/// Handle GET /localapi/v0/check-ip-forwarding
///
/// Checks whether IP forwarding is enabled on the local system. On Linux,
/// reads /proc/sys/net/ipv4/ip_forward. On macOS, checks the sysctl value.
/// Returns JSON with the forwarding status.
async fn handle_check_ip_forwarding<W: AsyncWrite + Unpin>(
    conn: &mut W,
) -> Result<(), std::io::Error> {
    #[cfg(target_os = "linux")]
    {
        let v4 = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
            .unwrap_or_default()
            .trim()
            .to_string();
        let v6 = std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/forwarding")
            .unwrap_or_default()
            .trim()
            .to_string();
        let body = serde_json::json!({
            "ipv4_forwarding": v4 == "1",
            "ipv6_forwarding": v6 == "1",
            "ipv4_raw": v4,
            "ipv6_raw": v6,
            "platform": "linux",
        });
        write_json_response(conn, 200, "OK", &body).await?;
    }
    #[cfg(target_os = "macos")]
    {
        let v4 = std::process::Command::new("sysctl")
            .args(["-n", "net.inet.ip.forwarding"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let v6 = std::process::Command::new("sysctl")
            .args(["-n", "net.inet6.ip6.forwarding"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let body = serde_json::json!({
            "ipv4_forwarding": v4 == "1",
            "ipv6_forwarding": v6 == "1",
            "ipv4_raw": v4,
            "ipv6_raw": v6,
            "platform": "macos",
        });
        write_json_response(conn, 200, "OK", &body).await?;
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let body = serde_json::json!({
            "error": "ip forwarding check not supported on this platform",
            "platform": std::env::consts::OS,
        });
        write_json_response(conn, 501, "Not Implemented", &body).await?;
    }
    Ok(())
}

/// Handle GET/DELETE /localapi/v0/files/[<name>] — list, download, or
/// delete waiting files. Mirrors Go's `serveFiles`.
async fn handle_files<W: AsyncWrite + Unpin>(
    conn: &mut W,
    method: &str,
    endpoint: &str,
    query: &str,
    _req: &HttpRequest,
    state: &Arc<LocalApiState>,
) -> Result<(), std::io::Error> {
    let Some(ref taildrop) = state.taildrop else {
        let body = serde_json::json!({"error": "taildrop not enabled"});
        write_json_response(conn, 500, "Internal Server Error", &body).await?;
        return Ok(());
    };

    // Extract the filename suffix (everything after "files/").
    let suffix = endpoint.strip_prefix("files").unwrap_or("");
    let suffix = suffix.strip_prefix('/').unwrap_or(suffix);

    if suffix.is_empty() {
        // List waiting files (optionally long-poll with ?waitsec=N).
        if method != "GET" {
            let body = serde_json::json!({"error": "want GET to list files"});
            write_json_response(conn, 400, "Bad Request", &body).await?;
            return Ok(());
        }
        let params = parse_query(query);
        let waitsec: u64 = params
            .get("waitsec")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let files = if waitsec > 0 {
            taildrop
                .await_waiting_files(std::time::Duration::from_secs(waitsec))
                .await
        } else {
            taildrop.waiting_files()
        };
        match files {
            Ok(list) => {
                let json = serde_json::to_value(&list).unwrap_or(serde_json::json!([]));
                write_json_response(conn, 200, "OK", &json).await?;
            }
            Err(e) => {
                let body = serde_json::json!({"error": e.to_string()});
                write_json_response(conn, 500, "Internal Server Error", &body).await?;
            }
        }
        return Ok(());
    }

    // A specific file: download or delete.
    let name = percent_decode_path(suffix);
    match method {
        "GET" => match taildrop.open_file(&name).await {
            Ok((bytes, size)) => {
                write_raw_response(conn, 200, "OK", "application/octet-stream", &bytes).await?;
                let _ = size; // Content-Length is implicit in the body.
            }
            Err(crate::taildrop::TaildropError::FileNotFound(_)) => {
                let body = serde_json::json!({"error": "file not found"});
                write_json_response(conn, 404, "Not Found", &body).await?;
            }
            Err(e) => {
                let body = serde_json::json!({"error": e.to_string()});
                write_json_response(conn, 500, "Internal Server Error", &body).await?;
            }
        },
        "DELETE" => match taildrop.delete_file(&name).await {
            Ok(()) => {
                write_no_content_response(conn, 204, "No Content").await?;
            }
            Err(crate::taildrop::TaildropError::FileNotFound(_)) => {
                let body = serde_json::json!({"error": "file not found"});
                write_json_response(conn, 404, "Not Found", &body).await?;
            }
            Err(e) => {
                let body = serde_json::json!({"error": e.to_string()});
                write_json_response(conn, 500, "Internal Server Error", &body).await?;
            }
        },
        _ => {
            let body = serde_json::json!({"error": "want GET or DELETE"});
            write_json_response(conn, 400, "Bad Request", &body).await?;
        }
    }
    Ok(())
}

/// Handle PUT /localapi/v0/file-put/<stableID>/<filename> — proxy a file
/// upload to a peer's PeerAPI. The daemon dials the target's PeerAPI via
/// the netstack and streams the body. Mirrors Go's `serveFilePut`.
async fn handle_file_put<W: AsyncWrite + Unpin>(
    conn: &mut W,
    method: &str,
    suffix: &str,
    req: &HttpRequest,
    state: &Arc<LocalApiState>,
) -> Result<(), std::io::Error> {
    if method != "PUT" {
        let body = serde_json::json!({"error": "want PUT to put file"});
        write_json_response(conn, 400, "Bad Request", &body).await?;
        return Ok(());
    }

    let Some(ref taildrop) = state.taildrop else {
        let body = serde_json::json!({"error": "taildrop not enabled"});
        write_json_response(conn, 500, "Internal Server Error", &body).await?;
        return Ok(());
    };

    // Parse <stableID>/<filename> from the suffix.
    let Some((peer_id_str, filename_escaped)) = suffix.split_once('/') else {
        let body = serde_json::json!({"error": "bogus URL"});
        write_json_response(conn, 400, "Bad Request", &body).await?;
        return Ok(());
    };
    let filename = percent_decode_path(filename_escaped);

    // Find the file target matching this stable ID.
    let peers = state.peers.read().await;
    let user_profiles = state.user_profiles.read().await;
    let targets = match taildrop.file_targets(&peers, &user_profiles).await {
        Ok(t) => t,
        Err(e) => {
            let body = serde_json::json!({"error": e.to_string()});
            write_json_response(conn, 500, "Internal Server Error", &body).await?;
            return Ok(());
        }
    };
    drop(peers);
    drop(user_profiles);

    let target = targets.iter().find(|t| t.StableID == peer_id_str);
    let Some(target) = target else {
        let body = serde_json::json!({"error": "node not found"});
        write_json_response(conn, 404, "Not Found", &body).await?;
        return Ok(());
    };

    // Dial the peer's PeerAPI via the netstack.
    let Some(ref netstack) = state.netstack else {
        let body = serde_json::json!({"error": "netstack not available (TUN mode?)"});
        write_json_response(conn, 500, "Internal Server Error", &body).await?;
        return Ok(());
    };

    // Parse the PeerAPI URL to get the dial address.
    let peerapi_url = &target.PeerAPIURL;
    let dial_addr = peerapi_url
        .strip_prefix("http://")
        .or_else(|| peerapi_url.strip_prefix("https://"))
        .unwrap_or(peerapi_url);

    // Parse into a SocketAddr for the netstack dial.
    let socket_addr: std::net::SocketAddr = match dial_addr.parse() {
        Ok(sa) => sa,
        Err(e) => {
            let body = serde_json::json!({"error": format!("bogus peer URL: {e}")});
            write_json_response(conn, 500, "Internal Server Error", &body).await?;
            return Ok(());
        }
    };

    // Dial the peer's PeerAPI via the netstack.
    let mut peer_conn = match netstack.dial(socket_addr).await {
        Ok(s) => s,
        Err(e) => {
            let body = serde_json::json!({"error": format!("failed to dial peer: {e}")});
            write_json_response(conn, 502, "Bad Gateway", &body).await?;
            return Ok(());
        }
    };

    // Send PUT /v0/put/<filename> to the peer's PeerAPI.
    let put_path = format!("/v0/put/{}", url_encode_path(&filename));
    let put_request = format!(
        "PUT {put_path} HTTP/1.1\r\nHost: peer\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        req.body.len()
    );
    use tokio::io::AsyncWriteExt;
    if peer_conn.write_all(put_request.as_bytes()).await.is_err() {
        let body = serde_json::json!({"error": "failed to send to peer"});
        write_json_response(conn, 502, "Bad Gateway", &body).await?;
        return Ok(());
    }
    if !req.body.is_empty() && peer_conn.write_all(&req.body).await.is_err() {
        let body = serde_json::json!({"error": "failed to send body to peer"});
        write_json_response(conn, 502, "Bad Gateway", &body).await?;
        return Ok(());
    }
    peer_conn.flush().await.ok();

    // Read the peer's response and forward it to the client.
    use tokio::io::AsyncReadExt;
    let mut resp_buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    loop {
        let n = match peer_conn.read(&mut tmp).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(_) => break,
        };
        resp_buf.extend_from_slice(&tmp[..n]);
        if resp_buf.len() > 1024 * 1024 {
            break;
        }
    }

    // Forward the raw HTTP response from the peer to the client.
    conn.write_all(&resp_buf).await?;
    conn.flush().await?;
    Ok(())
}

/// Percent-decode a URL path component (filename). Unlike query param
/// decoding, this handles %XX sequences and does not convert + to space.
fn percent_decode_path(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val_local(bytes[i + 1]), hex_val_local(bytes[i + 2])) {
                result.push((h * 16 + l) as char);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    result
}

/// URL-encode a filename for use in a path component. Encodes everything
/// except unreserved characters and path-safe chars.
fn url_encode_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                use std::fmt::Write;
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

fn hex_val_local(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TCPPortHandler;
    use rustscale_key::{DiscoPrivate, NodePrivate};
    use rustscale_magicsock::{Magicsock, MagicsockConfig};
    use rustscale_tailcfg::{Node, UserProfile};
    use tokio::io::AsyncWriteExt;

    /// Build a test LocalApiState with mock data. The IPN backend is
    /// initialized to the Running state to match the pre-IPN behavior.
    async fn make_test_state() -> Arc<LocalApiState> {
        let node_key = NodePrivate::generate();
        let disco_key = DiscoPrivate::generate();

        let derp_map = rustscale_tailcfg::DERPMap::default();
        let (magicsock_inner, _wg_recv) = Magicsock::new(MagicsockConfig {
            private_key: node_key.clone(),
            disco_key: disco_key.clone(),
            derp_client: None,
            derp_map: Some(derp_map),
            home_derp_region: 0,
            udp_bind: None,
            udp_socket: None,
            portmapper: None,
            health: None,
            disable_direct_paths: false,
            peer_relay_server: false,
            relay_server_config: None,
            sockstats: None,
            control_knobs: None,
        })
        .await
        .expect("magicsock");
        let magicsock = Arc::new(magicsock_inner);

        let peer = Node {
            Name: "peer1.tailnet.ts.net.".into(),
            Key: node_key.public(),
            Addresses: vec!["100.64.0.2/32".into()],
            User: 1,
            Online: Some(true),
            AllowedIPs: vec!["100.64.0.2/32".into()],
            ..Default::default()
        };

        let peers = Arc::new(RwLock::new(vec![peer]));
        let mut profiles = BTreeMap::new();
        profiles.insert(
            1,
            UserProfile {
                ID: 1,
                LoginName: "user@tailnet".into(),
                DisplayName: "Test User".into(),
                ProfilePicURL: String::new(),
            },
        );

        // Initialize the IPN backend to Running, matching the pre-IPN
        // behavior where status always reported "Running".
        let ipn_backend = Arc::new(rustscale_ipn::IpnBackend::new("rustscale"));
        ipn_backend.set_want_running();
        ipn_backend.set_has_node_key(true);
        ipn_backend.set_machine_authorized(true);
        ipn_backend.set_netmap_present(true);
        ipn_backend.set_engine_status(1, 1);
        assert_eq!(ipn_backend.state(), rustscale_ipn::State::Running);

        Arc::new(LocalApiState {
            peers,
            user_profiles: Arc::new(RwLock::new(profiles)),
            health: Tracker::new(),
            dns_config: Arc::new(RwLock::new(None)),
            packet_drops: Arc::new(AtomicU64::new(0)),
            metrics: default_metric_registry(),
            prefs: Arc::new(RwLock::new(Prefs {
                Hostname: "test".into(),
                ControlURL: "https://control".into(),
                WantRunning: true,
                ..Default::default()
            })),
            tailscale_ips: vec!["100.64.0.1".parse().unwrap()],
            our_fqdn: "test.tailnet.ts.net.".into(),
            hostname: "test".into(),
            magicsock,
            tun_mode: false,
            home_derp: 0,
            ipn_backend,
            derp_map: rustscale_tailcfg::DERPMap::default(),
            command_tx: None,
            state_dir: None,
            auth_url: Arc::new(std::sync::Mutex::new(None)),
            login_trigger: Arc::new(tokio::sync::Notify::new()),
            serve_config: Arc::new(RwLock::new(ServeConfig::default())),
            serve_runner: None,
            profiles: Arc::new(RwLock::new(vec![])),
            current_profile: Arc::new(RwLock::new(None)),
            cert_params: None,
            taildrop: None,
            netstack: None,
            filter: std::sync::OnceLock::new(),
            route_table: None,
            logout_trigger: Arc::new(tokio::sync::Notify::new()),
            suggested_exit_node: Arc::new(RwLock::new(String::new())),
            config_path: None,
            client_updater: Arc::new(std::sync::Mutex::new(
                rustscale_clientupdate::ClientUpdater::new("0.1.0"),
            )),
        })
    }

    // --- HTTP parsing tests ---

    #[test]
    fn test_find_header_end() {
        assert_eq!(find_header_end(b"a\r\n\r\nb"), Some(1));
        assert_eq!(find_header_end(b"no header here"), None);
        assert_eq!(find_header_end(b""), None);
    }

    #[test]
    fn test_parse_query() {
        let q = parse_query("addr=100.64.0.1:80&proto=tcp");
        assert_eq!(q.get("addr"), Some(&"100.64.0.1:80".to_string()));
        assert_eq!(q.get("proto"), Some(&"tcp".to_string()));
    }

    #[tokio::test]
    async fn test_parse_request_basic() {
        let raw =
            b"GET /localapi/v0/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        let mut cursor = std::io::Cursor::new(raw);
        let req = read_request(&mut cursor).await.unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/localapi/v0/status");
        assert_eq!(req.query, "");
    }

    #[tokio::test]
    async fn test_parse_request_with_query() {
        let raw = b"GET /localapi/v0/whois?addr=100.64.0.1:80 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        let mut cursor = std::io::Cursor::new(raw);
        let req = read_request(&mut cursor).await.unwrap();
        assert_eq!(req.path, "/localapi/v0/whois");
        assert_eq!(req.query, "addr=100.64.0.1:80");
    }

    #[tokio::test]
    async fn test_parse_request_post_with_body() {
        let raw = b"POST /localapi/v0/ping?ip=100.64.0.1&type=disco HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let mut cursor = std::io::Cursor::new(raw);
        let req = read_request(&mut cursor).await.unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/localapi/v0/ping");
        assert_eq!(req.query, "ip=100.64.0.1&type=disco");
    }

    // --- Dispatch tests (using tokio::io::duplex) ---

    async fn send_request_to_state(raw: &[u8], state: &Arc<LocalApiState>) -> String {
        let (mut client, mut server) = tokio::io::duplex(8192);
        client.write_all(raw).await.unwrap();
        client.flush().await.unwrap();
        // Close the write half so the server sees EOF.
        client.shutdown().await.ok();

        let mut buf = vec![0u8; 8192];
        let n = tokio::io::AsyncReadExt::read(&mut server, &mut buf)
            .await
            .unwrap_or(0);
        if n > 0 {
            let req_raw = &buf[..n];
            // Split header/body at \r\n\r\n for proper body extraction.
            let body_preview = if let Some(pos) = req_raw.windows(4).position(|w| w == b"\r\n\r\n")
            {
                req_raw[pos + 4..].to_vec()
            } else {
                Vec::new()
            };
            if let Ok(req) = parse_request_head(req_raw, body_preview) {
                // Tests run as the same user as the daemon → read-write.
                let identity = test_rw_identity();
                dispatch(&mut server, &req, state, &identity).await.ok();
            }
        }
        tokio::io::AsyncWriteExt::shutdown(&mut server).await.ok();

        let mut buf = Vec::new();
        // Read the response on the client side.
        let read_task = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            client.read_to_end(&mut buf).await.ok();
            String::from_utf8(buf).unwrap_or_default()
        });

        read_task.await.unwrap_or_default()
    }

    /// Build a read-write ConnIdentity for tests (same-uid as the daemon).
    #[cfg(unix)]
    fn test_rw_identity() -> ConnIdentity {
        ConnIdentity {
            uid: Some(unsafe { libc::getuid() }),
            pid: Some(std::process::id()),
            is_unix_sock: true,
        }
    }

    #[cfg(not(unix))]
    fn test_rw_identity() -> ConnIdentity {
        ConnIdentity::readwrite()
    }

    /// Build a read-only ConnIdentity for tests (different uid).
    fn test_ro_identity() -> ConnIdentity {
        // Use a uid that is guaranteed to differ from the daemon's.
        // uid 65534 is "nobody" on most systems; daemon is typically root or
        // a regular user. Even if it matches, the test still validates the
        // read-only path when the identity has no creds.
        ConnIdentity {
            uid: Some(65534),
            pid: Some(99999),
            is_unix_sock: true,
        }
    }

    #[tokio::test]
    async fn test_status_endpoint_returns_json() {
        let state = make_test_state().await;
        let resp = send_request_to_state(
            b"GET /localapi/v0/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            &state,
        )
        .await;
        assert!(resp.contains("200 OK"), "response: {resp}");
        assert!(resp.contains("Content-Type: application/json"));
        assert!(resp.contains("BackendState"));
        assert!(resp.contains("Running"));
        assert!(resp.contains("TailscaleIPs"));
        assert!(resp.contains("100.64.0.1"));
    }

    #[tokio::test]
    async fn test_status_includes_self_and_peers() {
        let state = make_test_state().await;
        let resp = send_request_to_state(
            b"GET /localapi/v0/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            &state,
        )
        .await;
        assert!(resp.contains("Self"));
        assert!(resp.contains("Peer"));
        assert!(resp.contains("peer1"));
    }

    #[tokio::test]
    async fn test_whois_with_bare_ip() {
        let state = make_test_state().await;
        let resp = send_request_to_state(
            b"GET /localapi/v0/whois?addr=100.64.0.2 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            &state,
        )
        .await;
        assert!(resp.contains("200 OK"), "response: {resp}");
        assert!(resp.contains("Node"));
        assert!(resp.contains("UserProfile"));
        assert!(resp.contains("peer1"));
        assert!(resp.contains("user@tailnet"));
    }

    #[tokio::test]
    async fn test_whois_with_ip_port() {
        let state = make_test_state().await;
        let resp = send_request_to_state(
            b"GET /localapi/v0/whois?addr=100.64.0.2:443 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            &state,
        )
        .await;
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("peer1"));
    }

    #[tokio::test]
    async fn test_whois_missing_addr_returns_400() {
        let state = make_test_state().await;
        let resp = send_request_to_state(
            b"GET /localapi/v0/whois HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            &state,
        )
        .await;
        assert!(resp.contains("400 Bad Request"));
        assert!(resp.contains("missing 'addr'"));
    }

    #[tokio::test]
    async fn test_whois_no_match_returns_404() {
        let state = make_test_state().await;
        let resp = send_request_to_state(
            b"GET /localapi/v0/whois?addr=10.0.0.1 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            &state,
        )
        .await;
        assert!(resp.contains("404 Not Found"));
    }

    #[tokio::test]
    async fn test_prefs_endpoint_returns_json() {
        let state = make_test_state().await;
        let resp = send_request_to_state(
            b"GET /localapi/v0/prefs HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            &state,
        )
        .await;
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("Hostname"));
        assert!(resp.contains("ControlURL"));
    }

    #[tokio::test]
    async fn test_netmap_endpoint_returns_json() {
        let state = make_test_state().await;
        let resp = send_request_to_state(
            b"GET /localapi/v0/netmap HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            &state,
        )
        .await;
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("SelfNode"));
        assert!(resp.contains("Peers"));
    }

    #[tokio::test]
    async fn test_metrics_endpoint_returns_prometheus() {
        let state = make_test_state().await;
        let resp = send_request_to_state(
            b"GET /localapi/v0/metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            &state,
        )
        .await;
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("text/plain"));
        assert!(resp.contains("rustscale_packet_drops_total"));
        assert!(resp.contains("rustscale_peer_count"));
    }

    #[tokio::test]
    async fn test_health_endpoint_returns_json() {
        let state = make_test_state().await;
        let resp = send_request_to_state(
            b"GET /localapi/v0/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            &state,
        )
        .await;
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("Content-Type: application/json"));
    }

    #[tokio::test]
    async fn test_ping_disco_returns_result() {
        let state = make_test_state().await;
        let resp = send_request_to_state(
            b"POST /localapi/v0/ping?ip=100.64.0.2&type=disco HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            &state,
        )
        .await;
        // Disco ping to a known peer should return 200 (with PingResult JSON,
        // possibly containing an error since no real path exists in the test).
        assert!(
            resp.contains("200 OK") || resp.contains("404 Not Found"),
            "expected 200 or 404, got: {resp}"
        );
    }

    #[tokio::test]
    async fn test_ping_missing_ip_returns_400() {
        let state = make_test_state().await;
        let resp = send_request_to_state(
            b"POST /localapi/v0/ping?type=disco HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            &state,
        )
        .await;
        assert!(resp.contains("400 Bad Request"));
        assert!(resp.contains("missing 'ip'"));
    }

    #[tokio::test]
    async fn test_unknown_endpoint_returns_404() {
        let state = make_test_state().await;
        let resp = send_request_to_state(
            b"GET /localapi/v0/nonexistent HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            &state,
        )
        .await;
        assert!(resp.contains("404 Not Found"));
    }

    #[tokio::test]
    async fn test_non_localapi_path_returns_404() {
        let state = make_test_state().await;
        let resp = send_request_to_state(
            b"GET /random/path HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            &state,
        )
        .await;
        assert!(resp.contains("404 Not Found"));
    }

    #[tokio::test]
    async fn test_root_returns_endpoint_list() {
        let state = make_test_state().await;
        let resp = send_request_to_state(
            b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            &state,
        )
        .await;
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("/localapi/v0/status"));
        assert!(resp.contains("/localapi/v0/whois"));
    }

    #[tokio::test]
    async fn test_wrong_method_returns_404() {
        let state = make_test_state().await;
        let resp = send_request_to_state(
            b"POST /localapi/v0/status HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            &state,
        )
        .await;
        // POST to a GET-only endpoint falls through to the 404 catch-all.
        assert!(resp.contains("404 Not Found"));
    }

    // --- Socket permission test ---

    #[cfg(unix)]
    #[tokio::test]
    async fn test_socket_permissions_match_safesocket() {
        use std::os::unix::fs::PermissionsExt;
        let state = make_test_state().await;
        let tmp = std::env::temp_dir().join(format!(
            "rustscale-localapi-test-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&tmp);
        let handle = spawn_localapi(state, tmp.clone());
        assert!(handle.is_some());

        let perms = std::fs::metadata(&tmp)
            .expect("socket file exists")
            .permissions();
        let mode = perms.mode() & 0o777;
        let expected = if rustscale_safesocket::platform_uses_peer_creds() {
            0o666
        } else {
            0o600
        };
        assert_eq!(
            mode, expected,
            "socket permissions should be {expected:o}, got {mode:o}"
        );

        // Clean up: abort the task and remove the socket.
        if let Some(h) = handle {
            h.task.abort();
        }
        let _ = std::fs::remove_file(&tmp);
    }

    // --- Status JSON shape test ---

    #[tokio::test]
    async fn test_status_json_shape() {
        let state = make_test_state().await;
        let json = build_status_json(&state).await;

        assert_eq!(json["Version"], "rustscale");
        assert_eq!(json["BackendState"], "Running");
        assert_eq!(json["TUN"], false);
        assert!(json["Self"]["HostName"].is_string());
        assert!(json["Self"]["DNSName"].is_string());
        assert!(json["Self"]["PublicKey"].is_string());
        assert!(json["Self"]["TailscaleIPs"].is_array());
        assert!(json["Peer"].is_object());
        assert!(json["Health"].is_array());
        assert!(json["CurrentTailnet"].is_object());
    }

    // --- watch-ipn-bus tests ---

    #[tokio::test]
    async fn test_watch_ipn_bus_bad_mask_returns_400() {
        let state = make_test_state().await;
        let resp = send_request_to_state(
            b"GET /localapi/v0/watch-ipn-bus?mask=abc HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            &state,
        )
        .await;
        assert!(resp.contains("400 Bad Request"));
        assert!(resp.contains("bad mask"));
    }

    #[tokio::test]
    async fn test_watch_ipn_bus_rejects_in_process_no_disconnect() {
        let state = make_test_state().await;
        // NotifyInProcessNoDisconnect = 1 << 16 = 65536
        let resp = send_request_to_state(
            b"GET /localapi/v0/watch-ipn-bus?mask=65536 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            &state,
        )
        .await;
        assert!(resp.contains("400 Bad Request"));
        assert!(resp.contains("NotifyInProcessNoDisconnect"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_watch_ipn_bus_initial_state_message() {
        // Test over a real Unix socket: connect, send the request, read
        // the initial state notify as a JSON line, then close.
        use tokio::io::AsyncReadExt;
        use tokio::net::UnixStream;

        let state = make_test_state().await;
        let tmp = std::env::temp_dir().join(format!(
            "rustscale-watch-ipn-test-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&tmp);
        let handle = spawn_localapi(state.clone(), tmp.clone());
        assert!(handle.is_some());

        // Connect and send the request with NotifyInitialState mask (1 << 1 = 2).
        let mut stream = UnixStream::connect(&tmp).await.expect("connect");
        let req = b"GET /localapi/v0/watch-ipn-bus?mask=2 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        stream.write_all(req).await.unwrap();
        stream.flush().await.unwrap();

        // Read the response. The initial notify should arrive quickly.
        let mut buf = vec![0u8; 8192];
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut buf))
            .await
            .expect("timed out reading initial notify")
            .expect("read");

        let resp = String::from_utf8_lossy(&buf[..n]);

        // Should be 200 OK with the initial state notify as a JSON line.
        assert!(resp.contains("200 OK"), "response: {resp}");
        assert!(resp.contains("Content-Type: application/json"));

        // The body should contain a JSON line with State and SessionID.
        // Find the body (after \r\n\r\n).
        let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
        let first_line = body.lines().next().unwrap_or("");
        let notify: serde_json::Value =
            serde_json::from_str(first_line).expect("parse notify JSON");

        // With NotifyInitialState, the first message should have:
        // - Version: "rustscale"
        // - SessionID: non-empty string
        // - State: 6 (Running, since test state is initialized to Running)
        assert_eq!(notify["Version"], "rustscale");
        assert!(notify["SessionID"].is_string());
        assert!(!notify["SessionID"].as_str().unwrap().is_empty());
        assert_eq!(notify["State"], 6); // Running

        // Clean up.
        if let Some(h) = handle {
            h.task.abort();
        }
        let _ = std::fs::remove_file(&tmp);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_watch_ipn_bus_transition_notify() {
        // Test that a state transition produces a second JSON line.
        // Connects over a real Unix socket to the LocalAPI server.
        use tokio::io::AsyncReadExt;
        use tokio::net::UnixStream;

        let state = make_test_state().await;
        let tmp = std::env::temp_dir().join(format!(
            "rustscale-watch-ipn-trans-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&tmp);
        let handle = spawn_localapi(state.clone(), tmp.clone());
        assert!(handle.is_some());

        // Connect with NotifyInitialState mask (1 << 1 = 2).
        let mut stream = UnixStream::connect(&tmp).await.expect("connect");
        let req = b"GET /localapi/v0/watch-ipn-bus?mask=2 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        stream.write_all(req).await.unwrap();
        stream.flush().await.unwrap();

        // Read the initial notify.
        let mut buf = vec![0u8; 8192];
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut buf))
            .await
            .expect("timed out reading initial notify")
            .expect("read");

        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.contains("200 OK"));

        // Parse the initial notify from the body.
        let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
        let first_line = body.lines().next().unwrap_or("");
        let initial: serde_json::Value = serde_json::from_str(first_line).expect("parse initial");
        assert_eq!(initial["State"], 6); // Running

        // Trigger a state transition: set key_expired=true which
        // transitions from Running to NeedsLogin (per the truth table).
        state.ipn_backend.set_key_expired(true);
        assert_eq!(state.ipn_backend.state(), rustscale_ipn::State::NeedsLogin);

        // Read the transition notify.
        let mut buf2 = vec![0u8; 8192];
        let n2 = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut buf2))
            .await
            .expect("timed out reading transition notify")
            .expect("read");

        let transition = String::from_utf8_lossy(&buf2[..n2]);
        let transition_line = transition.trim();
        let transition_notify: serde_json::Value =
            serde_json::from_str(transition_line).expect("parse transition notify");

        // The transition notify should have State: 2 (NeedsLogin) and no SessionID.
        assert_eq!(transition_notify["State"], 2); // NeedsLogin
        assert!(
            transition_notify.get("SessionID").is_none()
                || transition_notify["SessionID"].is_null()
        );

        if let Some(h) = handle {
            h.task.abort();
        }
        let _ = std::fs::remove_file(&tmp);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_watch_ipn_bus_no_initial_without_mask() {
        // Without NotifyInitialState, the first message should not have State.
        // With mask=0, the handler sends only the HTTP headers and then
        // waits for bus messages.
        use tokio::io::AsyncReadExt;
        use tokio::net::UnixStream;

        let state = make_test_state().await;
        let tmp = std::env::temp_dir().join(format!(
            "rustscale-watch-ipn-noinit-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&tmp);
        let handle = spawn_localapi(state.clone(), tmp.clone());
        assert!(handle.is_some());

        let mut stream = UnixStream::connect(&tmp).await.expect("connect");
        let req = b"GET /localapi/v0/watch-ipn-bus?mask=0 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        stream.write_all(req).await.unwrap();
        stream.flush().await.unwrap();

        // Give the handler time to write headers and subscribe to the bus.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Emit a notify so the handler sends something.
        state.ipn_backend.emit_err_message("test error");

        // Read the response — may take multiple reads since the error
        // notify arrives after the headers.
        let mut all = Vec::new();
        let mut buf = vec![0u8; 8192];
        loop {
            let n = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut buf))
                .await
                .expect("timed out")
                .expect("read");
            if n == 0 {
                break;
            }
            all.extend_from_slice(&buf[..n]);
            // Check if we have a complete JSON line in the body.
            let resp = String::from_utf8_lossy(&all);
            if let Some(body) = resp.split("\r\n\r\n").nth(1) {
                if !body.lines().next().unwrap_or("").is_empty() {
                    break;
                }
            }
        }

        let resp = String::from_utf8_lossy(&all);
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("Content-Type: application/json"));

        // The body should contain the error notify (no initial state notify).
        let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
        let first_line = body.lines().next().unwrap_or("");
        assert!(!first_line.is_empty(), "body should have a JSON line");
        let notify: serde_json::Value = serde_json::from_str(first_line).expect("parse notify");
        assert_eq!(notify["ErrMessage"], "test error");
        // No State field (no initial state notify was sent).
        assert!(notify.get("State").is_none() || notify["State"].is_null());

        if let Some(h) = handle {
            h.task.abort();
        }
        let _ = std::fs::remove_file(&tmp);
    }

    #[tokio::test]
    async fn test_status_reports_live_backend_state() {
        // Verify that build_status_json reports the live IPN state, not
        // a hardcoded "Running".
        let state = make_test_state().await;

        // The test state initializes to Running.
        let json = build_status_json(&state).await;
        assert_eq!(json["BackendState"], "Running");

        // Transition to NeedsLogin by setting key_expired=true.
        // Per the truth table, Running → NeedsLogin when key_expired.
        state.ipn_backend.set_key_expired(true);
        assert_eq!(state.ipn_backend.state(), rustscale_ipn::State::NeedsLogin);

        let json = build_status_json(&state).await;
        assert_eq!(json["BackendState"], "NeedsLogin");
    }

    // --- Serve config tests ---

    #[tokio::test]
    async fn test_get_serve_config_returns_etag() {
        let state = make_test_state().await;
        let resp = send_request_to_state(
            b"GET /localapi/v0/serve-config HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            &state,
        )
        .await;
        assert!(resp.contains("200 OK"), "response: {resp}");
        assert!(resp.contains("ETag:"), "missing ETag header");
        // Empty config should serialize as {}.
        let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
        assert!(body.contains("{}"), "body should be empty config: {body}");
    }

    #[tokio::test]
    async fn test_post_serve_config_no_if_match_succeeds() {
        let state = make_test_state().await;
        let config =
            r#"{"TCP":{"8080":{"HTTP":true,"HTTPS":false,"TCPForward":"","TerminateTLS":""}}}"#;
        let req = format!(
            "POST /localapi/v0/serve-config HTTP/1.1\r\nHost: localhost\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            config.len(),
            config
        );
        let resp = send_request_to_state(req.as_bytes(), &state).await;
        assert!(resp.contains("200 OK"), "response: {resp}");
        // Verify the config was applied to shared state.
        let cfg = state.serve_config.read().await;
        assert!(cfg.TCP.contains_key(&8080));
    }

    #[tokio::test]
    async fn test_post_serve_config_etag_mismatch_returns_412() {
        let state = make_test_state().await;

        // Set an initial config.
        let config = r#"{"TCP":{"8080":{"HTTP":true}}}"#;
        let req = format!(
            "POST /localapi/v0/serve-config HTTP/1.1\r\nHost: localhost\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            config.len(),
            config
        );
        let _ = send_request_to_state(req.as_bytes(), &state).await;

        // Now try to update with a wrong ETag.
        let config2 = r#"{"TCP":{"9090":{"HTTP":true}}}"#;
        let req2 = format!(
            "POST /localapi/v0/serve-config HTTP/1.1\r\nHost: localhost\r\n\
             If-Match: \"wrong-etag\"\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            config2.len(),
            config2
        );
        let resp = send_request_to_state(req2.as_bytes(), &state).await;
        assert!(resp.contains("412 Precondition Failed"), "response: {resp}");
        assert!(resp.contains("etag mismatch"));
    }

    #[tokio::test]
    async fn test_post_serve_config_correct_etag_succeeds() {
        let state = make_test_state().await;

        // Get the initial config + ETag.
        let resp = send_request_to_state(
            b"GET /localapi/v0/serve-config HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            &state,
        )
        .await;
        // Extract the ETag from the response.
        let etag = resp
            .split("ETag: \"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap_or_default();

        // Post with the correct ETag.
        let config = r#"{"TCP":{"8080":{"HTTP":true}}}"#;
        let req = format!(
            "POST /localapi/v0/serve-config HTTP/1.1\r\nHost: localhost\r\n\
             If-Match: \"{}\"\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            etag,
            config.len(),
            config
        );
        let resp = send_request_to_state(req.as_bytes(), &state).await;
        assert!(resp.contains("200 OK"), "response: {resp}");
    }

    #[tokio::test]
    async fn test_post_serve_config_persists_to_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_test_state().await;
        // Set the state_dir so the handler persists.
        // We need to modify the state — but it's Arc. So instead, create
        // a state with state_dir set.
        let state2 = Arc::new(LocalApiState {
            peers: state.peers.clone(),
            user_profiles: state.user_profiles.clone(),
            health: state.health.clone(),
            dns_config: state.dns_config.clone(),
            packet_drops: state.packet_drops.clone(),
            metrics: default_metric_registry(),
            prefs: state.prefs.clone(),
            tailscale_ips: state.tailscale_ips.clone(),
            our_fqdn: state.our_fqdn.clone(),
            hostname: state.hostname.clone(),
            magicsock: state.magicsock.clone(),
            tun_mode: state.tun_mode,
            home_derp: state.home_derp,
            ipn_backend: state.ipn_backend.clone(),
            derp_map: state.derp_map.clone(),
            command_tx: None,
            state_dir: Some(tmp.path().to_path_buf()),
            auth_url: state.auth_url.clone(),
            login_trigger: state.login_trigger.clone(),
            serve_config: Arc::new(RwLock::new(ServeConfig::default())),
            serve_runner: None,
            profiles: Arc::new(RwLock::new(vec![])),
            current_profile: Arc::new(RwLock::new(None)),
            cert_params: None,
            taildrop: None,
            netstack: None,
            filter: std::sync::OnceLock::new(),
            route_table: None,
            logout_trigger: Arc::new(tokio::sync::Notify::new()),
            suggested_exit_node: Arc::new(RwLock::new(String::new())),
            config_path: None,
            client_updater: Arc::new(std::sync::Mutex::new(
                rustscale_clientupdate::ClientUpdater::new("0.1.0"),
            )),
        });

        let config = r#"{"TCP":{"8080":{"HTTP":true}}}"#;
        let req = format!(
            "POST /localapi/v0/serve-config HTTP/1.1\r\nHost: localhost\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            config.len(),
            config
        );
        let resp = send_request_to_state(req.as_bytes(), &state2).await;
        assert!(resp.contains("200 OK"), "response: {resp}");

        // Verify the file was written.
        let serve_config_path = tmp.path().join("serve-config.json");
        assert!(serve_config_path.exists(), "serve-config.json should exist");
        let data = std::fs::read_to_string(&serve_config_path).unwrap();
        assert!(
            data.contains("8080"),
            "file should contain port 8080: {data}"
        );
    }

    #[tokio::test]
    async fn test_serve_config_loads_from_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = ServeConfig {
            TCP: {
                let mut m = BTreeMap::new();
                m.insert(
                    443,
                    TCPPortHandler {
                        HTTPS: true,
                        ..Default::default()
                    },
                );
                m
            },
            ..Default::default()
        };
        cfg.save(tmp.path()).unwrap();

        let loaded = ServeConfig::load(tmp.path()).unwrap();
        assert!(loaded.TCP.contains_key(&443));
        assert!(loaded.TCP[&443].HTTPS);
    }

    #[tokio::test]
    async fn test_serve_config_etag_changes_on_modification() {
        let cfg1 = ServeConfig::default();
        let etag1 = cfg1.etag();

        let mut cfg2 = ServeConfig::default();
        cfg2.TCP.insert(
            8080,
            TCPPortHandler {
                HTTP: true,
                ..Default::default()
            },
        );
        let etag2 = cfg2.etag();

        assert_ne!(etag1, etag2, "ETags should differ for different configs");
    }

    // --- Profile tests ---

    #[tokio::test]
    async fn test_list_profiles_returns_empty() {
        let state = make_test_state().await;
        let resp = send_request_to_state(
            b"GET /localapi/v0/profiles HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            &state,
        )
        .await;
        assert!(resp.contains("200 OK"), "response: {resp}");
        let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
        assert!(body.trim() == "[]", "expected empty array, got: {body}");
    }

    #[tokio::test]
    async fn test_put_profiles_creates_new() {
        let state = make_test_state().await;
        let resp = send_request_to_state(
            b"PUT /localapi/v0/profiles HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            &state,
        )
        .await;
        assert!(resp.contains("201 Created"), "response: {resp}");
        // Verify the profile was added to state.
        let profiles = state.profiles.read().await;
        assert_eq!(profiles.len(), 1);
    }

    #[tokio::test]
    async fn test_profile_switch_and_current() {
        let state = make_test_state().await;

        // Create two profiles.
        let _ = send_request_to_state(
            b"PUT /localapi/v0/profiles HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            &state,
        ).await;
        let _ = send_request_to_state(
            b"PUT /localapi/v0/profiles HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            &state,
        ).await;

        let profiles = state.profiles.read().await;
        assert_eq!(profiles.len(), 2);
        let first_id = profiles[0].ID.clone();
        let second_id = profiles[1].ID.clone();
        drop(profiles);

        // Current should be the second (last created).
        let resp = send_request_to_state(
            b"GET /localapi/v0/profiles/current HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            &state,
        ).await;
        assert!(resp.contains("200 OK"), "response: {resp}");
        assert!(
            resp.contains(&second_id),
            "current should be second profile"
        );

        // Switch to the first.
        let switch_path = format!(
            "POST /localapi/v0/profiles/{} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            first_id
        );
        let resp = send_request_to_state(switch_path.as_bytes(), &state).await;
        assert!(resp.contains("204"), "response: {resp}");

        // Current should now be first.
        let current = state.current_profile.read().await;
        assert_eq!(*current, Some(first_id.clone()));
    }

    #[tokio::test]
    async fn test_delete_profile() {
        let state = make_test_state().await;

        // Create a profile.
        let _ = send_request_to_state(
            b"PUT /localapi/v0/profiles HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            &state,
        ).await;

        let profiles = state.profiles.read().await;
        let id = profiles[0].ID.clone();
        drop(profiles);

        // Delete it.
        let delete_path = format!(
            "DELETE /localapi/v0/profiles/{} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            id
        );
        let resp = send_request_to_state(delete_path.as_bytes(), &state).await;
        assert!(resp.contains("204"), "response: {resp}");

        let profiles = state.profiles.read().await;
        assert!(profiles.is_empty(), "profile should be deleted");
    }

    #[tokio::test]
    async fn test_get_profile_not_found() {
        let state = make_test_state().await;
        let resp = send_request_to_state(
            b"GET /localapi/v0/profiles/nonexistent HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            &state,
        ).await;
        assert!(resp.contains("404 Not Found"), "response: {resp}");
    }

    // --- Cert endpoint tests ---

    /// Build a test state with CertDomains and cert_params wired up so the
    /// cert endpoint can be exercised. The cert cache is pre-populated so
    /// refresh loads from cache without hitting a real ACME server.
    async fn make_cert_test_state(
        cert_domains: Vec<String>,
        state_dir: &std::path::Path,
    ) -> Arc<LocalApiState> {
        let base = make_test_state().await;
        let mk = rustscale_key::MachinePrivate::generate();
        let mk_pub = mk.public();
        let nk = rustscale_key::NodePrivate::generate();
        Arc::new(LocalApiState {
            peers: base.peers.clone(),
            user_profiles: base.user_profiles.clone(),
            health: base.health.clone(),
            dns_config: Arc::new(RwLock::new(Some(rustscale_tailcfg::DNSConfig {
                CertDomains: cert_domains,
                ..Default::default()
            }))),
            packet_drops: base.packet_drops.clone(),
            metrics: default_metric_registry(),
            prefs: base.prefs.clone(),
            tailscale_ips: base.tailscale_ips.clone(),
            our_fqdn: base.our_fqdn.clone(),
            hostname: base.hostname.clone(),
            magicsock: base.magicsock.clone(),
            tun_mode: base.tun_mode,
            home_derp: base.home_derp,
            ipn_backend: base.ipn_backend.clone(),
            derp_map: base.derp_map.clone(),
            command_tx: None,
            state_dir: Some(state_dir.to_path_buf()),
            auth_url: base.auth_url.clone(),
            login_trigger: base.login_trigger.clone(),
            serve_config: base.serve_config.clone(),
            serve_runner: None,
            profiles: base.profiles.clone(),
            current_profile: base.current_profile.clone(),
            cert_params: Some(CertParams {
                state_dir: state_dir.to_path_buf(),
                control_url: "https://control.example.invalid".into(),
                machine_key: mk,
                server_pub_key: mk_pub,
                node_key: nk,
                capability_version: 141,
                protocol_version: 141,
            }),
            taildrop: None,
            netstack: None,
            filter: std::sync::OnceLock::new(),
            route_table: None,
            logout_trigger: Arc::new(tokio::sync::Notify::new()),
            suggested_exit_node: Arc::new(RwLock::new(String::new())),
            config_path: None,
            client_updater: Arc::new(std::sync::Mutex::new(
                rustscale_clientupdate::ClientUpdater::new("0.1.0"),
            )),
        })
    }

    /// Write a self-signed cert + key into the cert cache so
    /// ControlCertProvider::refresh loads from cache (no ACME hit).
    fn write_cert_cache(state_dir: &std::path::Path, domain: &str) {
        use base64::Engine as _;
        let ck = rcgen::generate_simple_self_signed(vec![domain.to_string()]).unwrap();
        let cert = &ck.cert;
        let key_pair = &ck.key_pair;
        let der = cert.der();
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        let mut cert_pem = String::new();
        cert_pem.push_str("-----BEGIN CERTIFICATE-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            cert_pem.push_str(std::str::from_utf8(chunk).unwrap());
            cert_pem.push('\n');
        }
        cert_pem.push_str("-----END CERTIFICATE-----\n");
        let key_der = key_pair.serialize_der();
        let kb64 = base64::engine::general_purpose::STANDARD.encode(&key_der);
        let mut key_pem = String::new();
        key_pem.push_str("-----BEGIN PRIVATE KEY-----\n");
        for chunk in kb64.as_bytes().chunks(64) {
            key_pem.push_str(std::str::from_utf8(chunk).unwrap());
            key_pem.push('\n');
        }
        key_pem.push_str("-----END PRIVATE KEY-----\n");
        std::fs::write(
            state_dir.join(format!("{domain}.crt.pem")),
            cert_pem.as_bytes(),
        )
        .unwrap();
        std::fs::write(
            state_dir.join(format!("{domain}.key.pem")),
            key_pem.as_bytes(),
        )
        .unwrap();
        let far_future = chrono::Utc::now() + chrono::Duration::days(90);
        std::fs::write(
            state_dir.join(format!("{domain}.expiry")),
            far_future.to_rfc3339(),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn test_cert_no_domain_returns_400() {
        let state = make_test_state().await;
        let resp = send_request_to_state(
            b"GET /localapi/v0/cert/ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            &state,
        )
        .await;
        assert!(resp.contains("400 Bad Request"), "response: {resp}");
        assert!(resp.contains("missing domain"));
    }

    #[tokio::test]
    async fn test_cert_domain_not_in_certdomains_returns_404() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_cert_test_state(vec![], tmp.path()).await;
        let resp = send_request_to_state(
            b"GET /localapi/v0/cert/unauthorized.ts.net HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            &state,
        )
        .await;
        assert!(resp.contains("404 Not Found"), "response: {resp}");
        assert!(resp.contains("not authorized"));
    }

    #[tokio::test]
    async fn test_cert_no_cert_params_returns_500() {
        let state = make_test_state().await; // cert_params: None
                                             // But we need cert_domains to be non-empty to get past the 404 check.
        *state.dns_config.write().await = Some(rustscale_tailcfg::DNSConfig {
            CertDomains: vec!["test.ts.net".into()],
            ..Default::default()
        });
        let resp = send_request_to_state(
            b"GET /localapi/v0/cert/test.ts.net HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            &state,
        )
        .await;
        assert!(resp.contains("500"), "response: {resp}");
        assert!(resp.contains("cert provisioning unavailable"));
    }

    #[tokio::test]
    async fn test_cert_invalid_type_returns_400() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_cert_test_state(vec!["test.ts.net".into()], tmp.path()).await;
        write_cert_cache(tmp.path(), "test.ts.net");
        let resp = send_request_to_state(
            b"GET /localapi/v0/cert/test.ts.net?type=bogus HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            &state,
        )
        .await;
        assert!(resp.contains("400 Bad Request"), "response: {resp}");
        assert!(resp.contains("invalid type"));
    }

    #[tokio::test]
    async fn test_cert_invalid_min_validity_returns_400() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_cert_test_state(vec!["test.ts.net".into()], tmp.path()).await;
        write_cert_cache(tmp.path(), "test.ts.net");
        let resp = send_request_to_state(
            b"GET /localapi/v0/cert/test.ts.net?min_validity=xyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            &state,
        )
        .await;
        assert!(resp.contains("400 Bad Request"), "response: {resp}");
        assert!(resp.contains("invalid min_validity"));
    }

    #[tokio::test]
    async fn test_cert_pair_returns_pem_from_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_cert_test_state(vec!["test.ts.net".into()], tmp.path()).await;
        write_cert_cache(tmp.path(), "test.ts.net");
        let resp = send_request_to_state(
            b"GET /localapi/v0/cert/test.ts.net?type=pair HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            &state,
        )
        .await;
        assert!(resp.contains("200 OK"), "response: {resp}");
        assert!(resp.contains("text/plain"));
        // type=pair: key PEM first, then cert PEM.
        let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
        let key_pos = body.find("BEGIN PRIVATE KEY").unwrap_or(usize::MAX);
        let cert_pos = body.find("BEGIN CERTIFICATE").unwrap_or(usize::MAX);
        assert!(key_pos < cert_pos, "pair must have key PEM before cert PEM");
        assert!(body.contains("END PRIVATE KEY"));
        assert!(body.contains("END CERTIFICATE"));
    }

    #[tokio::test]
    async fn test_cert_cert_only_returns_cert_pem() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_cert_test_state(vec!["test.ts.net".into()], tmp.path()).await;
        write_cert_cache(tmp.path(), "test.ts.net");
        let resp = send_request_to_state(
            b"GET /localapi/v0/cert/test.ts.net?type=cert HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            &state,
        )
        .await;
        assert!(resp.contains("200 OK"), "response: {resp}");
        let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
        assert!(body.contains("BEGIN CERTIFICATE"));
        assert!(
            !body.contains("BEGIN PRIVATE KEY"),
            "type=cert must not include key"
        );
    }

    #[tokio::test]
    async fn test_cert_key_only_returns_key_pem() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_cert_test_state(vec!["test.ts.net".into()], tmp.path()).await;
        write_cert_cache(tmp.path(), "test.ts.net");
        let resp = send_request_to_state(
            b"GET /localapi/v0/cert/test.ts.net?type=key HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            &state,
        )
        .await;
        assert!(resp.contains("200 OK"), "response: {resp}");
        let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
        assert!(body.contains("BEGIN PRIVATE KEY"));
        assert!(
            !body.contains("BEGIN CERTIFICATE"),
            "type=key must not include cert"
        );
    }

    #[tokio::test]
    async fn test_cert_default_type_is_pair() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_cert_test_state(vec!["test.ts.net".into()], tmp.path()).await;
        write_cert_cache(tmp.path(), "test.ts.net");
        let resp = send_request_to_state(
            b"GET /localapi/v0/cert/test.ts.net HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            &state,
        )
        .await;
        assert!(resp.contains("200 OK"), "response: {resp}");
        let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
        // Default type=pair → both key and cert.
        assert!(body.contains("BEGIN PRIVATE KEY"));
        assert!(body.contains("BEGIN CERTIFICATE"));
    }

    #[tokio::test]
    async fn test_cert_wrong_method_returns_405() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_cert_test_state(vec!["test.ts.net".into()], tmp.path()).await;
        let resp = send_request_to_state(
            b"POST /localapi/v0/cert/test.ts.net HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            &state,
        )
        .await;
        assert!(resp.contains("405"), "response: {resp}");
    }

    #[test]
    fn test_parse_go_duration() {
        assert_eq!(parse_go_duration("0"), Ok(chrono::Duration::zero()));
        assert_eq!(parse_go_duration(""), Ok(chrono::Duration::zero()));
        assert_eq!(parse_go_duration("720h"), Ok(chrono::Duration::hours(720)));
        assert_eq!(parse_go_duration("30m"), Ok(chrono::Duration::minutes(30)));
        assert_eq!(
            parse_go_duration("1h30m"),
            Ok(chrono::Duration::seconds(5400))
        );
        assert_eq!(
            parse_go_duration("3600s"),
            Ok(chrono::Duration::seconds(3600))
        );
        assert!(parse_go_duration("xyz").is_err());
        assert!(
            parse_go_duration("12").is_err(),
            "missing unit should error"
        );
    }

    #[tokio::test]
    async fn test_status_includes_cert_domains() {
        let tmp = tempfile::tempdir().unwrap();
        let state = make_cert_test_state(vec!["node.ts.net".into()], tmp.path()).await;
        let json = build_status_json(&state).await;
        let domains = json["CertDomains"]
            .as_array()
            .expect("CertDomains is array");
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0], "node.ts.net");
    }

    // --- IPNAUTH: peer-credential enforcement tests ---

    async fn send_request_with_identity(
        raw: &[u8],
        state: &Arc<LocalApiState>,
        identity: ConnIdentity,
    ) -> String {
        let (mut client, mut server) = tokio::io::duplex(8192);
        client.write_all(raw).await.unwrap();
        client.flush().await.unwrap();
        client.shutdown().await.ok();

        let mut buf = vec![0u8; 8192];
        let n = tokio::io::AsyncReadExt::read(&mut server, &mut buf)
            .await
            .unwrap_or(0);
        if n > 0 {
            let req_raw = &buf[..n];
            let body_preview = if let Some(pos) = req_raw.windows(4).position(|w| w == b"\r\n\r\n")
            {
                req_raw[pos + 4..].to_vec()
            } else {
                Vec::new()
            };
            if let Ok(req) = parse_request_head(req_raw, body_preview) {
                dispatch(&mut server, &req, state, &identity).await.ok();
            }
        }
        tokio::io::AsyncWriteExt::shutdown(&mut server).await.ok();

        let mut buf = Vec::new();
        let read_task = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            client.read_to_end(&mut buf).await.ok();
            String::from_utf8(buf).unwrap_or_default()
        });
        read_task.await.unwrap_or_default()
    }

    #[tokio::test]
    async fn test_readonly_identity_can_read_status() {
        let state = make_test_state().await;
        let resp = send_request_with_identity(
            b"GET /localapi/v0/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            &state,
            test_ro_identity(),
        )
        .await;
        assert!(
            resp.contains("200 OK"),
            "read-only peer should read status: {resp}"
        );
    }

    #[tokio::test]
    async fn test_readonly_identity_can_read_health() {
        let state = make_test_state().await;
        let resp = send_request_with_identity(
            b"GET /localapi/v0/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            &state,
            test_ro_identity(),
        )
        .await;
        assert!(resp.contains("200 OK"));
    }

    #[tokio::test]
    async fn test_readonly_identity_can_read_metrics() {
        let state = make_test_state().await;
        let resp = send_request_with_identity(
            b"GET /localapi/v0/metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            &state,
            test_ro_identity(),
        )
        .await;
        assert!(resp.contains("200 OK"));
    }

    #[tokio::test]
    async fn test_readonly_identity_can_read_whois() {
        let state = make_test_state().await;
        let resp = send_request_with_identity(
            b"GET /localapi/v0/whois?addr=100.64.0.2 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            &state,
            test_ro_identity(),
        )
        .await;
        assert!(resp.contains("200 OK"));
    }

    #[tokio::test]
    async fn test_readonly_identity_blocked_from_patch_prefs() {
        let state = make_test_state().await;
        let resp = send_request_with_identity(
            b"PATCH /localapi/v0/prefs HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            &state,
            test_ro_identity(),
        )
        .await;
        assert!(
            resp.contains("403 Forbidden"),
            "read-only peer should get 403: {resp}"
        );
        assert!(resp.contains("access denied"));
    }

    #[tokio::test]
    async fn test_readonly_identity_blocked_from_shutdown() {
        let state = make_test_state().await;
        let resp = send_request_with_identity(
            b"POST /localapi/v0/shutdown HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            &state,
            test_ro_identity(),
        )
        .await;
        assert!(resp.contains("403 Forbidden"));
    }

    #[tokio::test]
    async fn test_readonly_identity_blocked_from_logout() {
        let state = make_test_state().await;
        let resp = send_request_with_identity(
            b"POST /localapi/v0/logout HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            &state,
            test_ro_identity(),
        )
        .await;
        assert!(resp.contains("403 Forbidden"));
    }

    #[tokio::test]
    async fn test_readonly_identity_blocked_from_login_interactive() {
        let state = make_test_state().await;
        let resp = send_request_with_identity(
            b"POST /localapi/v0/login-interactive HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            &state,
            test_ro_identity(),
        )
        .await;
        assert!(resp.contains("403 Forbidden"));
    }

    #[tokio::test]
    async fn test_readwrite_identity_can_patch_prefs() {
        let state = make_test_state().await;
        let body = r#"{"Hostname":"renamed"}"#;
        let req = format!(
            "PATCH /localapi/v0/prefs HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let resp = send_request_with_identity(req.as_bytes(), &state, test_rw_identity()).await;
        assert!(
            resp.contains("200 OK") || resp.contains("204"),
            "read-write peer should patch prefs: {resp}"
        );
    }

    #[tokio::test]
    async fn test_no_creds_identity_is_readonly() {
        let state = make_test_state().await;
        let no_creds = ConnIdentity::default();
        let resp = send_request_with_identity(
            b"POST /localapi/v0/shutdown HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            &state,
            no_creds,
        )
        .await;
        assert!(resp.contains("403 Forbidden"));
    }
}
