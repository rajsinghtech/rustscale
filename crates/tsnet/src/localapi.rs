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
//! Socket filesystem permissions (0600) — matching tailscaled's default
//! local root/user model. No password or token. Only the same UID that
//! created the socket (or root) can connect.
//!
//! # Wire shapes
//!
//! JSON shapes follow Go's `ipn/ipnstate` and `apitype.WhoIsResponse` where
//! practical. Divergences are documented in comments on each handler.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use rustscale_health::{Severity, Tracker};
use rustscale_magicsock::{Magicsock, PathClass};
use rustscale_tailcfg::{DNSConfig, Node, UserID, UserProfile};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;

const API_PREFIX: &str = "/localapi/v0/";

/// Shared state for the LocalAPI server — all fields are Arc clones of the
/// same state held by [`crate::RunningState`], so the API always sees live
/// data without explicit refresh.
pub(crate) struct LocalApiState {
    pub peers: Arc<RwLock<Vec<Node>>>,
    pub user_profiles: Arc<RwLock<BTreeMap<UserID, UserProfile>>>,
    pub health: Tracker,
    pub dns_config: Arc<RwLock<Option<DNSConfig>>>,
    pub packet_drops: Arc<AtomicU64>,
    pub prefs: serde_json::Value,
    pub tailscale_ips: Vec<IpAddr>,
    pub our_fqdn: String,
    pub hostname: String,
    pub magicsock: Arc<Magicsock>,
    pub tun_mode: bool,
    pub home_derp: i32,
}

/// Result of spawning the LocalAPI server: the background task handle and
/// the resolved socket path.
pub(crate) struct LocalApiHandle {
    pub task: JoinHandle<()>,
    pub socket_path: PathBuf,
}

/// Spawn the LocalAPI Unix-domain-socket server.
///
/// Removes any stale socket file at `socket_path`, binds a fresh one, sets
/// permissions to 0600, and spawns a background task serving HTTP/1.1.
/// Returns `None` if the socket cannot be bound.
pub(crate) fn spawn_localapi(
    state: Arc<LocalApiState>,
    socket_path: PathBuf,
) -> Option<LocalApiHandle> {
    // Remove stale socket from a previous run.
    let _ = std::fs::remove_file(&socket_path);

    // Ensure parent directory exists.
    if let Some(parent) = socket_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let listener = UnixListener::bind(&socket_path).ok()?;

    // Set socket permissions to 0600 — only the owning user (or root) can
    // connect. This is the sole auth mechanism, matching tailscaled's
    // default local root/user model.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = std::fs::set_permissions(&socket_path, perms);
    }

    let path = socket_path.clone();
    let task = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _peer_addr)) => {
                    let state = state.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, &state).await {
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

// ---------------------------------------------------------------------------
// HTTP request parsing (same pattern as crates/c2n)
// ---------------------------------------------------------------------------

struct HttpRequest {
    method: String,
    path: String,
    query: String,
    #[allow(dead_code)]
    headers: Vec<(String, String)>,
    #[allow(dead_code)]
    body: Vec<u8>,
}

async fn read_request<R: AsyncRead + Unpin>(conn: &mut R) -> Result<HttpRequest, String> {
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

async fn write_json_response<W: AsyncWrite + Unpin>(
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
    mut stream: tokio::net::UnixStream,
    state: &Arc<LocalApiState>,
) -> Result<(), std::io::Error> {
    let req = match read_request(&mut stream).await {
        Ok(r) => r,
        Err(e) => {
            let body = serde_json::json!({"error": "bad request", "reason": e});
            write_json_response(&mut stream, 400, "Bad Request", &body).await?;
            return Ok(());
        }
    };

    dispatch(&mut stream, &req, state).await
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

async fn dispatch<W: AsyncWrite + Unpin>(
    conn: &mut W,
    req: &HttpRequest,
    state: &Arc<LocalApiState>,
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
            write_json_response(conn, 200, "OK", &state.prefs).await?;
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
            handle_ping(conn, &req.query).await?;
        }

        _ => {
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

/// Build the status JSON, modeled on Go's `ipnstate.Status`.
///
/// # Divergences from Go ipnstate.Status
///
/// - `Version`: "rustscale" instead of Go's version.Long().
/// - `BackendState`: always "Running" when the server is up (rustscale does
///   not implement the full IPN state machine with NoState/NeedsLogin/etc.).
/// - `Self` and `Peer` entries omit fields not tracked by rustscale:
///   `RxBytes`, `TxBytes`, `LastHandshake`, `LastSeen`, `LastWrite`,
///   `AllowedIPs`, `Tags`, `PrimaryRoutes`, `Capabilities`, `CapMap`,
///   `PeerAPIURL`, `SSH_HostKeys`, `KeyExpiry`, `Location`.
/// - `ExitNodeStatus`: included when an exit node is selected via the
///   route table, but `ID` is derived from the peer's node key (not a
///   stable node ID, which rustscale does not track).
/// - `ClientVersion`, `CertDomains`, `ExtraRecords`, `AuthURL`: omitted.
/// - `Peer` is a JSON object keyed by node public key string (same as Go).
/// - `TUN`: true when the server was started via `up_tun()`.
async fn build_status_json(state: &LocalApiState) -> serde_json::Value {
    let peers = state.peers.read().await;
    let user_profiles = state.user_profiles.read().await;
    let dns_config = state.dns_config.read().await;

    let node_key = state.magicsock.node_public().to_string();

    // Build self node.
    let self_node = serde_json::json!({
        "HostName": state.hostname,
        "DNSName": state.our_fqdn,
        "TailscaleIPs": state.tailscale_ips.iter().map(std::string::ToString::to_string).collect::<Vec<_>>(),
        "PublicKey": node_key,
        "Online": true,
        "InNetworkMap": true,
        "InMagicSock": true,
        "InEngine": true,
    });

    // Build peers map keyed by node public key.
    let mut peers_map = serde_json::Map::new();
    for peer in peers.iter() {
        if peer.Key.is_zero() {
            continue;
        }
        let key_str = peer.Key.to_string();
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

        // Check if this peer is exit-node-capable.
        let exit_node_option = peer
            .AllowedIPs
            .iter()
            .any(|r| r == "0.0.0.0/0" || r == "::/0");

        peers_map.insert(
            key_str,
            serde_json::json!({
                "HostName": peer.Name.trim_end_matches('.'),
                "DNSName": peer.Name,
                "TailscaleIPs": ips.iter().map(std::string::ToString::to_string).collect::<Vec<_>>(),
                "PublicKey": peer.Key.to_string(),
                "Online": peer.Online.unwrap_or(false),
                "Relay": relay,
                "ExitNode": false,
                "ExitNodeOption": exit_node_option,
                "InNetworkMap": true,
                "InMagicSock": true,
                "InEngine": true,
                "UserID": peer.User,
            }),
        );
    }

    // Health: list of warning text strings (Go uses []string).
    let health_warnings: Vec<String> = state
        .health
        .current_warnings()
        .iter()
        .map(|w| w.text.clone())
        .collect();

    // Current tailnet info.
    let (tailnet_name, magicdns_suffix, magicdns_enabled) = {
        if let Some(ref dns) = *dns_config {
            let suffix = state.our_fqdn.trim_end_matches('.');
            let suffix = match suffix.split_once('.') {
                Some((_, d)) => d,
                None => suffix,
            };
            (suffix.to_string(), suffix.to_string(), dns.Proxied)
        } else {
            (String::new(), String::new(), false)
        }
    };

    serde_json::json!({
        "Version": "rustscale",
        "TUN": state.tun_mode,
        "BackendState": "Running",
        "HaveNodeKey": true,
        "TailscaleIPs": state.tailscale_ips.iter().map(std::string::ToString::to_string).collect::<Vec<_>>(),
        "Self": self_node,
        "Peer": peers_map,
        "User": user_profiles_to_json(&user_profiles),
        "Health": health_warnings,
        "CurrentTailnet": {
            "Name": tailnet_name,
            "MagicDNSSuffix": magicdns_suffix,
            "MagicDNSEnabled": magicdns_enabled,
        },
    })
}

fn user_profiles_to_json(profiles: &BTreeMap<UserID, UserProfile>) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (id, profile) in profiles {
        map.insert(
            id.to_string(),
            serde_json::json!({
                "ID": profile.ID,
                "LoginName": profile.LoginName,
                "DisplayName": profile.DisplayName,
                "ProfilePicURL": profile.ProfilePicURL,
            }),
        );
    }
    serde_json::Value::Object(map)
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
    })
}

// ---------------------------------------------------------------------------
// Metrics handler
// ---------------------------------------------------------------------------

/// Build Prometheus text exposition format. Same metrics as the C2N handler.
fn build_metrics_text(state: &LocalApiState) -> String {
    use std::fmt::Write;

    let drops = state.packet_drops.load(Ordering::Relaxed);
    let peer_count = state.peers.try_read().map(|p| p.len()).unwrap_or(0);
    let warnings = state.health.current_warnings();
    let high = warnings
        .iter()
        .filter(|w| w.severity == Severity::High)
        .count();
    let medium = warnings
        .iter()
        .filter(|w| w.severity == Severity::Medium)
        .count();
    let low = warnings
        .iter()
        .filter(|w| w.severity == Severity::Low)
        .count();
    let endpoints = state.magicsock.local_endpoints();

    let mut out = String::new();
    let _ = writeln!(
        out,
        "# HELP rustscale_packet_drops_total Packets dropped by the packet filter"
    );
    let _ = writeln!(out, "# TYPE rustscale_packet_drops_total counter");
    let _ = writeln!(out, "rustscale_packet_drops_total {drops}");
    let _ = writeln!(
        out,
        "# HELP rustscale_peer_count Number of peers in the netmap"
    );
    let _ = writeln!(out, "# TYPE rustscale_peer_count gauge");
    let _ = writeln!(out, "rustscale_peer_count {peer_count}");
    let _ = writeln!(
        out,
        "# HELP rustscale_health_warnings Active health warnings by severity"
    );
    let _ = writeln!(out, "# TYPE rustscale_health_warnings gauge");
    let _ = writeln!(out, "rustscale_health_warnings{{severity=\"high\"}} {high}");
    let _ = writeln!(
        out,
        "rustscale_health_warnings{{severity=\"medium\"}} {medium}"
    );
    let _ = writeln!(out, "rustscale_health_warnings{{severity=\"low\"}} {low}");
    let _ = writeln!(
        out,
        "# HELP rustscale_local_endpoints Number of local UDP endpoints"
    );
    let _ = writeln!(out, "# TYPE rustscale_local_endpoints gauge");
    let _ = writeln!(out, "rustscale_local_endpoints {}", endpoints.len());
    out
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

/// Handle POST /localapi/v0/ping?ip=<ip>&type=disco
///
/// Returns 501 because magicsock does not expose a standalone disco-ping
/// API that returns latency. The disco ping/pong mechanism is internal to
/// path establishment and not callable as a one-shot latency probe from
/// outside the crate. This is a known gap to be addressed in a future phase.
async fn handle_ping<W: AsyncWrite + Unpin>(
    conn: &mut W,
    query: &str,
) -> Result<(), std::io::Error> {
    let params = parse_query(query);
    let ip_str = params.get("ip").map_or("", String::as_str);
    let ping_type = params.get("type").map_or("", String::as_str);

    if ip_str.is_empty() {
        let body = serde_json::json!({"error": "missing 'ip' parameter"});
        write_json_response(conn, 400, "Bad Request", &body).await?;
        return Ok(());
    }
    if ping_type.is_empty() {
        let body = serde_json::json!({"error": "missing 'type' parameter"});
        write_json_response(conn, 400, "Bad Request", &body).await?;
        return Ok(());
    }

    let body = serde_json::json!({
        "error": "ping not implemented",
        "reason": "magicsock does not expose a standalone disco-ping API; \
                   the ping/pong mechanism is internal to path establishment",
        "ip": ip_str,
        "type": ping_type,
    });
    write_json_response(conn, 501, "Not Implemented", &body).await?;
    Ok(())
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rustscale_key::{DiscoPrivate, NodePrivate};
    use rustscale_magicsock::{Magicsock, MagicsockConfig};
    use rustscale_tailcfg::{Node, UserProfile};
    use tokio::io::AsyncWriteExt;

    /// Build a test LocalApiState with mock data.
    async fn make_test_state() -> Arc<LocalApiState> {
        let node_key = NodePrivate::generate();
        let disco_key = DiscoPrivate::generate();

        let derp_map = rustscale_tailcfg::DERPMap::default();
        let magicsock = Arc::new(
            Magicsock::new(MagicsockConfig {
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
            })
            .await
            .expect("magicsock"),
        );

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

        Arc::new(LocalApiState {
            peers,
            user_profiles: Arc::new(RwLock::new(profiles)),
            health: Tracker::new(),
            dns_config: Arc::new(RwLock::new(None)),
            packet_drops: Arc::new(AtomicU64::new(0)),
            prefs: serde_json::json!({"hostname": "test", "control_url": "https://control"}),
            tailscale_ips: vec!["100.64.0.1".parse().unwrap()],
            our_fqdn: "test.tailnet.ts.net.".into(),
            hostname: "test".into(),
            magicsock,
            tun_mode: false,
            home_derp: 0,
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

        let mut buf = Vec::new();
        // Read the response on the client side.
        let read_task = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            client.read_to_end(&mut buf).await.ok();
            String::from_utf8(buf).unwrap_or_default()
        });

        // Handle the request on the server side.
        // We need to parse the request from the server side of the duplex.
        let mut server_buf = vec![0u8; 8192];
        let n = tokio::io::AsyncReadExt::read(&mut server, &mut server_buf)
            .await
            .unwrap_or(0);
        if n > 0 {
            let req_raw = &server_buf[..n];
            // Parse and dispatch.
            if let Ok(req) = parse_request_head(req_raw, Vec::new()) {
                dispatch(&mut server, &req, state).await.ok();
            }
        }
        tokio::io::AsyncWriteExt::shutdown(&mut server).await.ok();

        read_task.await.unwrap_or_default()
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
        assert!(resp.contains("hostname"));
        assert!(resp.contains("control_url"));
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
    async fn test_ping_returns_501() {
        let state = make_test_state().await;
        let resp = send_request_to_state(
            b"POST /localapi/v0/ping?ip=100.64.0.2&type=disco HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            &state,
        )
        .await;
        assert!(resp.contains("501 Not Implemented"));
        assert!(resp.contains("ping not implemented"));
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
    async fn test_socket_permissions_are_0600() {
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
        assert_eq!(
            mode, 0o600,
            "socket permissions should be 0600, got {mode:o}"
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
}
