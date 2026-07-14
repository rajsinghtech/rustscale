#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use async_trait::async_trait;
use rustscale_tailcfg::C2NPostureIdentityResponse;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Debug, Clone, serde::Serialize)]
pub struct WhoIsResult {
    pub found: bool,
    pub node_name: String,
    pub user_id: i64,
    pub login_name: String,
}

// ---------------------------------------------------------------------------
// Per-component verbose logging state with expiry
// ---------------------------------------------------------------------------

/// Shared state for per-component verbose logging.
///
/// Maps component names to expiry timestamps. A component is verbose if it
/// has an entry whose expiry hasn't passed. Expired entries are cleaned up
/// on access. Mirrors Go's `LocalBackend.SetComponentDebugLogging`.
#[derive(Clone, Default)]
pub struct LogLevelState {
    inner: Arc<Mutex<HashMap<String, SystemTime>>>,
}

impl LogLevelState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable verbose logging for `component` until `until`.
    pub fn set(&self, component: &str, until: SystemTime) {
        let mut g = self.inner.lock().expect("LogLevelState mutex poisoned");
        g.insert(component.to_string(), until);
    }

    /// Whether `component` currently has verbose logging enabled.
    pub fn is_verbose(&self, component: &str) -> bool {
        let mut g = self.inner.lock().expect("LogLevelState mutex poisoned");
        let now = SystemTime::now();
        g.retain(|_, until| *until > now);
        g.contains_key(component)
    }

    /// Remove expired entries.
    pub fn cleanup_expired(&self) {
        let mut g = self.inner.lock().expect("LogLevelState mutex poisoned");
        let now = SystemTime::now();
        g.retain(|_, until| *until > now);
    }

    /// Snapshot of currently-verbose components and their expiry timestamps.
    pub fn active(&self) -> Vec<(String, SystemTime)> {
        let mut g = self.inner.lock().expect("LogLevelState mutex poisoned");
        let now = SystemTime::now();
        g.retain(|_, until| *until > now);
        g.iter().map(|(k, v)| (k.clone(), *v)).collect()
    }
}

impl std::fmt::Debug for LogLevelState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogLevelState").finish()
    }
}

// ---------------------------------------------------------------------------
// C2N backend trait
// ---------------------------------------------------------------------------

#[async_trait]
pub trait C2nBackend: Send + Sync {
    async fn whois(&self, ip: IpAddr) -> Option<WhoIsResult>;

    /// Current server config/prefs as JSON. None if not available.
    async fn prefs_json(&self) -> Option<serde_json::Value> {
        None
    }

    /// Current netmap as JSON. `omit_fields` names top-level keys to remove.
    async fn netmap_json(&self, _omit_fields: &[String]) -> Option<serde_json::Value> {
        None
    }

    /// Current health state as JSON (array of active warnings).
    async fn health_json(&self) -> Option<serde_json::Value> {
        None
    }

    /// Metrics in Prometheus text exposition format.
    async fn metrics_text(&self) -> Option<String> {
        None
    }

    /// Current DNS config as JSON.
    async fn dns_config_json(&self) -> Option<serde_json::Value> {
        None
    }

    /// Flush logs. Returns `true` if a flush was attempted (even a no-op).
    async fn try_flush_logs(&self) -> bool {
        false
    }

    /// Set per-component debug logging until `until`.
    async fn set_component_debug_logging(
        &self,
        _component: &str,
        _until: SystemTime,
    ) -> Result<(), String> {
        Err("not implemented".into())
    }

    /// TLS certificate status for `domain`. Returns a JSON object mirroring
    /// Go's `tailcfg.C2NTLSCertInfo`:
    /// `{ "Valid": bool, "Error": str, "Missing": bool, "Expired": bool,
    ///    "NotBefore": str, "NotAfter": str }`.
    /// `None` if cert management is not available.
    async fn tls_cert_status(&self, _domain: &str) -> Option<serde_json::Value> {
        None
    }

    /// Per-label socket TX/RX byte counters as JSON (the body for
    /// `POST /sockstats`). `None` if no sockstats registry is wired up.
    async fn sockstats_json(&self) -> Option<serde_json::Value> {
        None
    }

    /// Serial numbers and hardware addresses for device posture.
    ///
    /// A `None` response means the backend does not support posture identity.
    async fn posture_identity(&self) -> Option<C2NPostureIdentityResponse> {
        None
    }
}

#[derive(Debug, thiserror::Error)]
pub enum C2nError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("bind error: {0}")]
    Bind(String),
}

pub struct C2NServer {
    backend: Arc<dyn C2nBackend>,
    log_id: String,
    log_level_state: LogLevelState,
}

impl C2NServer {
    pub fn new(backend: Arc<dyn C2nBackend>, log_id: String) -> Self {
        Self {
            backend,
            log_id,
            log_level_state: LogLevelState::new(),
        }
    }

    /// Like [`new`](Self::new) but with a shared [`LogLevelState`] so callers
    /// can query per-component verbose flags from outside the server.
    pub fn new_with_log_level(
        backend: Arc<dyn C2nBackend>,
        log_id: String,
        log_level_state: LogLevelState,
    ) -> Self {
        Self {
            backend,
            log_id,
            log_level_state,
        }
    }

    /// Shared log-level state (for external query of verbose components).
    pub fn log_level_state(&self) -> LogLevelState {
        self.log_level_state.clone()
    }

    pub async fn bind() -> Result<(TcpListener, SocketAddr), C2nError> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        Ok((listener, addr))
    }

    pub async fn serve(self, listener: TcpListener) -> Result<(), C2nError> {
        loop {
            let (mut stream, peer_addr) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("c2n[{}]: accept error: {e}", self.log_id);
                    continue;
                }
            };

            let backend = self.backend.clone();
            let log_id = self.log_id.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(&mut stream, peer_addr, &backend, &log_id).await {
                    eprintln!("c2n[{log_id}]: connection error: {e}");
                }
            });
        }
    }
}

async fn handle_connection(
    stream: &mut tokio::net::TcpStream,
    peer_addr: SocketAddr,
    backend: &Arc<dyn C2nBackend>,
    log_id: &str,
) -> Result<(), std::io::Error> {
    let req = match read_request(stream).await {
        Ok(r) => r,
        Err(e) => {
            let body = serde_json::json!({"error": "bad request", "reason": e});
            write_json_response(stream, 400, "Bad Request", &body).await?;
            return Ok(());
        }
    };

    if !check_auth(peer_addr.ip(), backend).await {
        let body = serde_json::json!({
            "error": "unauthorized",
            "reason": "non-tailnet connection",
        });
        write_json_response(stream, 401, "Unauthorized", &body).await?;
        return Ok(());
    }

    let _ = log_id;
    dispatch(stream, &req, backend).await
}

async fn check_auth(ip: IpAddr, backend: &Arc<dyn C2nBackend>) -> bool {
    if is_loopback(ip) {
        return true;
    }
    if rustscale_tsaddr::is_tailscale_ip(ip) {
        return backend.whois(ip).await.is_some();
    }
    false
}

fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

struct HttpRequest {
    method: String,
    path: String,
    query: String,
    #[allow(dead_code)]
    headers: Vec<(String, String)>,
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

async fn write_text_response<W: AsyncWrite + Unpin>(
    conn: &mut W,
    status: u16,
    reason: &str,
    body: &str,
) -> Result<(), std::io::Error> {
    let body_bytes = body.as_bytes();
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body_bytes.len()
    );
    conn.write_all(header.as_bytes()).await?;
    conn.write_all(body_bytes).await?;
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

async fn write_no_content<W: AsyncWrite + Unpin>(conn: &mut W) -> Result<(), std::io::Error> {
    conn.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await?;
    conn.flush().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Query string parsing
// ---------------------------------------------------------------------------

fn parse_query(query: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
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

fn parse_omit_fields(query: &str) -> Vec<String> {
    let params = parse_query(query);
    params
        .get("omit_fields")
        .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Known paths
// ---------------------------------------------------------------------------

const KNOWN_PATHS: &[&str] = &[
    "/",
    "/echo",
    "/debug/goroutines",
    "/debug/pprof/",
    "/debug/pprof/profile",
    "/debug/pprof/heap",
    "/debug/pprof/allocs",
    "/debug/metrics",
    "/debug/netmap",
    "/debug/prefs",
    "/debug/health",
    "/debug/component-logging",
    "/debug/logheap",
    "/netmap",
    "/prefs",
    "/dns",
    "/logtail/flush",
    "/sockstats",
    "/tls-cert-status",
    "/posture/identity",
];

fn known_paths() -> serde_json::Value {
    serde_json::json!(KNOWN_PATHS)
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

async fn dispatch<W: AsyncWrite + Unpin>(
    conn: &mut W,
    req: &HttpRequest,
    backend: &Arc<dyn C2nBackend>,
) -> Result<(), std::io::Error> {
    let method = req.method.as_str();
    let path = req.path.as_str();

    if path == "/" {
        if method == "GET" {
            write_json_response(conn, 200, "OK", &known_paths()).await?;
        } else {
            let body = serde_json::json!({"error": "bad method", "path": path});
            write_json_response(conn, 405, "Method Not Allowed", &body).await?;
        }
        return Ok(());
    }

    if path == "/echo" {
        if method == "GET" {
            write_raw_response(conn, 200, "OK", "application/octet-stream", &req.body).await?;
        } else {
            let body = serde_json::json!({"error": "bad method", "path": path});
            write_json_response(conn, 405, "Method Not Allowed", &body).await?;
        }
        return Ok(());
    }

    if path.starts_with("/local/") {
        if method == "POST" {
            let body = serde_json::json!({"error": "not implemented", "path": path});
            write_json_response(conn, 501, "Not Implemented", &body).await?;
        } else {
            let body = serde_json::json!({"error": "bad method", "path": path});
            write_json_response(conn, 405, "Method Not Allowed", &body).await?;
        }
        return Ok(());
    }

    // --- POST /logtail/flush → 204 when a flusher is wired ---
    if method == "POST" && path == "/logtail/flush" {
        if backend.try_flush_logs().await {
            write_no_content(conn).await?;
        } else {
            let body = serde_json::json!({"error": "no log flusher wired up"});
            write_json_response(conn, 500, "Internal Server Error", &body).await?;
        }
        return Ok(());
    }

    // --- POST /sockstats → 200 with per-label TX/RX JSON ---
    if method == "POST" && path == "/sockstats" {
        match backend.sockstats_json().await {
            Some(v) => write_json_response(conn, 200, "OK", &v).await?,
            None => {
                write_text_response(conn, 200, "OK", "sockstats: no sockstat logger wired up\n")
                    .await?;
            }
        }
        return Ok(());
    }

    // --- GET /posture/identity → device posture identity JSON ---
    if method == "GET" && path == "/posture/identity" {
        if let Some(response) = backend.posture_identity().await {
            let body = serde_json::to_value(response).unwrap_or(serde_json::Value::Null);
            write_json_response(conn, 200, "OK", &body).await?;
        } else {
            let body = serde_json::json!({"error": "posture identity not available"});
            write_json_response(conn, 501, "Not Implemented", &body).await?;
        }
        return Ok(());
    }

    // --- GET /debug/goroutines ---
    if method == "GET" && path == "/debug/goroutines" {
        let body = "Rust has no goroutine dump. Tokio task introspection is not available.\n";
        write_text_response(conn, 200, "OK", body).await?;
        return Ok(());
    }

    // --- GET /debug/pprof/* → 501 with clear message ---
    if method == "GET" && path.starts_with("/debug/pprof/") {
        let body = serde_json::json!({
            "error": "pprof not available in rustscale (no Rust pprof implementation)",
            "path": path,
        });
        write_json_response(conn, 501, "Not Implemented", &body).await?;
        return Ok(());
    }

    // --- GET /debug/component-logging ---
    if method == "GET" && path == "/debug/component-logging" {
        let params = parse_query(&req.query);
        let component = params.get("component").map_or("", String::as_str);
        let secs: i64 = params.get("secs").and_then(|s| s.parse().ok()).unwrap_or(0);
        // Go: if secs == 0, secs -= 1 (negative → immediate expiry).
        let secs = if secs == 0 { -1 } else { secs };
        let now = SystemTime::now();
        let until = if secs >= 0 {
            now + std::time::Duration::from_secs(secs as u64)
        } else {
            // Negative: already expired (1 ns before now)
            now - std::time::Duration::from_nanos(1)
        };
        let result = backend.set_component_debug_logging(component, until).await;
        let resp = match result {
            Ok(()) => serde_json::json!({}),
            Err(e) => serde_json::json!({"error": e}),
        };
        write_json_response(conn, 200, "OK", &resp).await?;
        return Ok(());
    }

    // --- GET /debug/logheap → 200 with note ---
    if method == "GET" && path == "/debug/logheap" {
        write_text_response(
            conn,
            200,
            "OK",
            "logheap: no heap profiler available in rustscale\n",
        )
        .await?;
        return Ok(());
    }

    // --- GET /debug/metrics → Prometheus text ---
    if method == "GET" && path == "/debug/metrics" {
        let text = backend
            .metrics_text()
            .await
            .unwrap_or_else(|| "# rustscale metrics: no backend metrics available\n".to_string());
        write_raw_response(
            conn,
            200,
            "OK",
            "text/plain; version=0.0.4; charset=utf-8",
            text.as_bytes(),
        )
        .await?;
        return Ok(());
    }

    // --- GET /debug/prefs (and alias /prefs) ---
    if method == "GET" && (path == "/debug/prefs" || path == "/prefs") {
        if let Some(v) = backend.prefs_json().await {
            write_json_response(conn, 200, "OK", &v).await?;
        } else {
            let body = serde_json::json!({"error": "prefs not available"});
            write_json_response(conn, 501, "Not Implemented", &body).await?;
        }
        return Ok(());
    }

    // --- GET /debug/health ---
    if method == "GET" && path == "/debug/health" {
        if let Some(v) = backend.health_json().await {
            write_json_response(conn, 200, "OK", &v).await?;
        } else {
            let body = serde_json::json!({"error": "health not available"});
            write_json_response(conn, 501, "Not Implemented", &body).await?;
        }
        return Ok(());
    }

    // --- GET/POST /debug/netmap (and alias /netmap) ---
    if (method == "GET" || method == "POST") && (path == "/debug/netmap" || path == "/netmap") {
        let omit_fields = if method == "POST" {
            serde_json::from_slice::<NetmapOmitRequest>(&req.body)
                .map(|r| r.OmitFields)
                .unwrap_or_default()
        } else {
            parse_omit_fields(&req.query)
        };
        if let Some(v) = backend.netmap_json(&omit_fields).await {
            let mut v = v;
            if let Some(obj) = v.as_object_mut() {
                for f in &omit_fields {
                    obj.remove(f);
                }
            }
            write_json_response(conn, 200, "OK", &v).await?;
        } else {
            let body = serde_json::json!({"error": "netmap not available"});
            write_json_response(conn, 501, "Not Implemented", &body).await?;
        }
        return Ok(());
    }

    // --- GET /dns → DNS config JSON ---
    if method == "GET" && path == "/dns" {
        if let Some(v) = backend.dns_config_json().await {
            write_json_response(conn, 200, "OK", &v).await?;
        } else {
            let body = serde_json::json!({"error": "dns config not available"});
            write_json_response(conn, 501, "Not Implemented", &body).await?;
        }
        return Ok(());
    }

    // --- GET /tls-cert-status → TLS certificate info for a domain ---
    // Mirrors Go's `handleC2NTLSCertStatus` in ipnlocal/cert.go. Returns
    // a `C2NTLSCertInfo`-shaped JSON object: Valid, Error, Missing, Expired,
    // NotBefore, NotAfter. The `domain` query parameter is required.
    if method == "GET" && path == "/tls-cert-status" {
        let params = parse_query(&req.query);
        let domain = params.get("domain").map_or("", String::as_str);
        if domain.is_empty() {
            let body = serde_json::json!({"error": "no 'domain'"});
            write_json_response(conn, 400, "Bad Request", &body).await?;
            return Ok(());
        }
        if let Some(v) = backend.tls_cert_status(domain).await {
            write_json_response(conn, 200, "OK", &v).await?;
        } else {
            let body = serde_json::json!({
                "Valid": false,
                "Error": "no certificate",
                "Missing": true,
            });
            write_json_response(conn, 200, "OK", &body).await?;
        }
        return Ok(());
    }

    // --- Unknown path ---
    let is_known = KNOWN_PATHS.contains(&path)
        || path.starts_with("/debug/pprof/")
        || path.starts_with("/local/");

    if is_known {
        let body = serde_json::json!({"error": "bad method", "path": path});
        write_json_response(conn, 405, "Method Not Allowed", &body).await
    } else {
        let body = serde_json::json!({"error": "unknown c2n path", "path": path});
        write_json_response(conn, 400, "Bad Request", &body).await
    }
}

/// POST body for /debug/netmap (matches Go's C2NDebugNetmapRequest).
#[derive(serde::Deserialize)]
#[allow(non_snake_case)]
struct NetmapOmitRequest {
    #[serde(default)]
    OmitFields: Vec<String>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    struct FakeBackend;
    #[async_trait]
    impl C2nBackend for FakeBackend {
        async fn whois(&self, _ip: IpAddr) -> Option<WhoIsResult> {
            Some(WhoIsResult {
                found: true,
                node_name: "test.".into(),
                user_id: 1,
                login_name: "test@tailnet".into(),
            })
        }

        async fn try_flush_logs(&self) -> bool {
            true
        }
    }

    /// Mock backend that returns data for all trait methods.
    struct MockBackend {
        log_level: LogLevelState,
    }
    #[async_trait]
    impl C2nBackend for MockBackend {
        async fn whois(&self, _ip: IpAddr) -> Option<WhoIsResult> {
            Some(WhoIsResult {
                found: true,
                node_name: "mock.".into(),
                user_id: 1,
                login_name: "mock@tailnet".into(),
            })
        }
        async fn prefs_json(&self) -> Option<serde_json::Value> {
            Some(serde_json::json!({"hostname": "mock", "control_url": "https://control"}))
        }
        async fn netmap_json(&self, _omit_fields: &[String]) -> Option<serde_json::Value> {
            Some(serde_json::json!({
                "SelfNode": {"Name": "mock.tailnet.ts.net."},
                "Peers": [{"Name": "peer1.tailnet.ts.net."}],
                "DNSConfig": {"Proxied": true},
                "Domain": "tailnet.ts.net",
            }))
        }
        async fn health_json(&self) -> Option<serde_json::Value> {
            Some(serde_json::json!([]))
        }
        async fn metrics_text(&self) -> Option<String> {
            Some("# HELP rustscale_test A test metric\n# TYPE rustscale_test counter\nrustscale_test 1\n".into())
        }
        async fn dns_config_json(&self) -> Option<serde_json::Value> {
            Some(serde_json::json!({"Proxied": true, "Domains": ["tailnet.ts.net"]}))
        }
        async fn try_flush_logs(&self) -> bool {
            true
        }
        async fn set_component_debug_logging(
            &self,
            component: &str,
            until: SystemTime,
        ) -> Result<(), String> {
            self.log_level.set(component, until);
            Ok(())
        }
        async fn tls_cert_status(&self, domain: &str) -> Option<serde_json::Value> {
            Some(serde_json::json!({
                "Valid": true,
                "Error": "",
                "Missing": false,
                "Expired": false,
                "NotBefore": "2026-01-01T00:00:00Z",
                "NotAfter": "2027-01-01T00:00:00Z",
                "Domain": domain,
            }))
        }
        async fn sockstats_json(&self) -> Option<serde_json::Value> {
            Some(serde_json::json!({
                "stats": {
                    "MagicsockConnUDP4": { "tx_bytes": 100, "rx_bytes": 200 }
                },
                "current_interface_cellular": false
            }))
        }
    }

    #[test]
    fn test_is_loopback() {
        assert!(is_loopback("127.0.0.1".parse().unwrap()));
        assert!(is_loopback("::1".parse().unwrap()));
        assert!(!is_loopback("100.64.0.1".parse().unwrap()));
        assert!(!is_loopback("8.8.8.8".parse().unwrap()));
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
            "99.64.0.1".parse().unwrap()
        ));
        assert!(!rustscale_tsaddr::is_tailscale_ip(
            "100.63.0.1".parse().unwrap()
        ));
        assert!(!rustscale_tsaddr::is_tailscale_ip(
            "100.128.0.1".parse().unwrap()
        ));
    }

    #[test]
    fn test_find_header_end() {
        assert_eq!(find_header_end(b"a\r\n\r\nb"), Some(1));
        assert_eq!(find_header_end(b"no header here"), None);
        assert_eq!(find_header_end(b""), None);
    }

    #[test]
    fn test_parse_query() {
        let q = parse_query("component=magicsock&secs=30");
        assert_eq!(q.get("component"), Some(&"magicsock".to_string()));
        assert_eq!(q.get("secs"), Some(&"30".to_string()));
    }

    #[test]
    fn test_parse_omit_fields() {
        assert_eq!(
            parse_omit_fields("omit_fields=Peers,Node"),
            vec!["Peers", "Node"]
        );
        assert!(parse_omit_fields("").is_empty());
        assert!(parse_omit_fields("other=foo").is_empty());
    }

    #[test]
    fn test_log_level_state_set_and_check() {
        let state = LogLevelState::new();
        assert!(!state.is_verbose("magicsock"));
        let until = SystemTime::now() + std::time::Duration::from_secs(60);
        state.set("magicsock", until);
        assert!(state.is_verbose("magicsock"));
        assert!(!state.is_verbose("control"));
    }

    #[test]
    fn test_log_level_state_expiry() {
        let state = LogLevelState::new();
        // Set with already-passed expiry → immediately expired.
        let past = SystemTime::now() - std::time::Duration::from_secs(10);
        state.set("expired-component", past);
        // is_verbose cleans up expired entries.
        assert!(!state.is_verbose("expired-component"));
        assert!(state.active().is_empty());
    }

    #[test]
    fn test_log_level_state_cleanup() {
        let state = LogLevelState::new();
        let future = SystemTime::now() + std::time::Duration::from_secs(60);
        let past = SystemTime::now() - std::time::Duration::from_secs(10);
        state.set("active-comp", future);
        state.set("expired-comp", past);
        state.cleanup_expired();
        assert!(state.is_verbose("active-comp"));
        assert!(!state.is_verbose("expired-comp"));
    }

    #[tokio::test]
    async fn test_parse_request_basic() {
        let raw = b"GET /netmap HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        let mut cursor = std::io::Cursor::new(raw);
        let req = read_request(&mut cursor).await.unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/netmap");
        assert_eq!(req.query, "");
        assert_eq!(req.headers.len(), 2);
        assert_eq!(req.headers[0].0, "Host");
        assert_eq!(req.headers[0].1, "localhost");
        assert!(req.body.is_empty());
    }

    #[tokio::test]
    async fn test_parse_request_with_query() {
        let raw = b"GET /debug/netmap?omit_fields=Peers,Node HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        let mut cursor = std::io::Cursor::new(raw);
        let req = read_request(&mut cursor).await.unwrap();
        assert_eq!(req.path, "/debug/netmap");
        assert_eq!(req.query, "omit_fields=Peers,Node");
    }

    #[tokio::test]
    async fn test_parse_request_with_body() {
        let raw = b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhello";
        let mut cursor = std::io::Cursor::new(raw);
        let req = read_request(&mut cursor).await.unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/echo");
        assert_eq!(req.body, b"hello");
    }

    async fn send_request(addr: SocketAddr, raw: &[u8]) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(raw).await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        String::from_utf8(buf).unwrap()
    }

    async fn start_server() -> SocketAddr {
        let backend: Arc<dyn C2nBackend> = Arc::new(FakeBackend);
        let server = C2NServer::new(backend, "test".into());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(server.serve(listener));
        addr
    }

    async fn start_mock_server() -> (SocketAddr, LogLevelState) {
        let log_level = LogLevelState::new();
        let backend: Arc<dyn C2nBackend> = Arc::new(MockBackend {
            log_level: log_level.clone(),
        });
        let server = C2NServer::new_with_log_level(backend, "test".into(), log_level.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(server.serve(listener));
        (addr, log_level)
    }

    struct PostureBackend {
        posture_disabled: bool,
    }

    #[async_trait]
    impl C2nBackend for PostureBackend {
        async fn whois(&self, _ip: IpAddr) -> Option<WhoIsResult> {
            Some(WhoIsResult {
                found: true,
                node_name: "posture.".into(),
                user_id: 1,
                login_name: "posture@tailnet".into(),
            })
        }

        async fn posture_identity(&self) -> Option<C2NPostureIdentityResponse> {
            Some(C2NPostureIdentityResponse {
                serial_numbers: vec!["serial-1".into()],
                iface_hardware_addrs: vec!["00:11:22:33:44:55".into()],
                posture_disabled: self.posture_disabled,
            })
        }
    }

    async fn start_posture_server(posture_disabled: bool) -> SocketAddr {
        let backend: Arc<dyn C2nBackend> = Arc::new(PostureBackend { posture_disabled });
        let server = C2NServer::new(backend, "test".into());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(server.serve(listener));
        addr
    }

    // --- Handler status + content-type tests ---

    #[tokio::test]
    async fn logtail_flush_returns_204() {
        let addr = start_server().await;
        let resp = send_request(
            addr,
            b"POST /logtail/flush HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("204 No Content"));
        assert!(!resp.contains("Content-Type"));
    }

    #[tokio::test]
    async fn debug_prefs_returns_json() {
        let (addr, _) = start_mock_server().await;
        let resp = send_request(
            addr,
            b"GET /debug/prefs HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("Content-Type: application/json"));
        assert!(resp.contains("hostname"));
    }

    #[tokio::test]
    async fn prefs_alias_returns_json() {
        let (addr, _) = start_mock_server().await;
        let resp = send_request(
            addr,
            b"GET /prefs HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("Content-Type: application/json"));
    }

    #[tokio::test]
    async fn debug_metrics_returns_prometheus() {
        let (addr, _) = start_mock_server().await;
        let resp = send_request(
            addr,
            b"GET /debug/metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("text/plain"));
        assert!(resp.contains("rustscale_test"));
    }

    #[tokio::test]
    async fn debug_metrics_minimal_without_backend() {
        let addr = start_server().await;
        let resp = send_request(
            addr,
            b"GET /debug/metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("text/plain"));
    }

    #[tokio::test]
    async fn debug_health_returns_json() {
        let (addr, _) = start_mock_server().await;
        let resp = send_request(
            addr,
            b"GET /debug/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("Content-Type: application/json"));
    }

    #[tokio::test]
    async fn debug_netmap_returns_json() {
        let (addr, _) = start_mock_server().await;
        let resp = send_request(
            addr,
            b"GET /debug/netmap HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("Content-Type: application/json"));
        assert!(resp.contains("SelfNode"));
    }

    #[tokio::test]
    async fn netmap_alias_returns_json() {
        let (addr, _) = start_mock_server().await;
        let resp = send_request(
            addr,
            b"GET /netmap HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("Content-Type: application/json"));
    }

    #[tokio::test]
    async fn debug_netmap_omit_fields() {
        let (addr, _) = start_mock_server().await;
        let resp = send_request(
            addr,
            b"GET /debug/netmap?omit_fields=Peers HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("200 OK"));
        assert!(!resp.contains("peer1"));
        assert!(resp.contains("SelfNode"));
    }

    #[tokio::test]
    async fn debug_netmap_post_omit_fields() {
        let (addr, _) = start_mock_server().await;
        let body = r#"{"OmitFields":["DNSConfig"]}"#;
        let req = format!(
            "POST /debug/netmap HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let resp = send_request(addr, req.as_bytes()).await;
        assert!(resp.contains("200 OK"));
        assert!(!resp.contains("Proxied"));
        assert!(resp.contains("Peers"));
    }

    #[tokio::test]
    async fn debug_goroutines_returns_text() {
        let addr = start_server().await;
        let resp = send_request(
            addr,
            b"GET /debug/goroutines HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("text/plain"));
        assert!(resp.contains("goroutine"));
    }

    #[tokio::test]
    async fn debug_pprof_returns_501_with_message() {
        let addr = start_server().await;
        let resp = send_request(
            addr,
            b"GET /debug/pprof/heap HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("501 Not Implemented"));
        assert!(resp.contains("pprof not available"));
    }

    #[tokio::test]
    async fn debug_pprof_allocs_returns_501() {
        let addr = start_server().await;
        let resp = send_request(
            addr,
            b"GET /debug/pprof/allocs HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("501 Not Implemented"));
    }

    #[tokio::test]
    async fn debug_component_logging_sets_state() {
        let (addr, log_level) = start_mock_server().await;
        let resp = send_request(
            addr,
            b"GET /debug/component-logging?component=magicsock&secs=60 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("Content-Type: application/json"));
        assert!(log_level.is_verbose("magicsock"));
    }

    #[tokio::test]
    async fn debug_component_logging_secs_zero_immediate_expiry() {
        let (addr, log_level) = start_mock_server().await;
        let resp = send_request(
            addr,
            b"GET /debug/component-logging?component=foo&secs=0 HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("200 OK"));
        // secs=0 → secs=-1 → already expired → not verbose.
        assert!(!log_level.is_verbose("foo"));
    }

    #[tokio::test]
    async fn debug_logheap_returns_200() {
        let addr = start_server().await;
        let resp = send_request(
            addr,
            b"GET /debug/logheap HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("text/plain"));
    }

    #[tokio::test]
    async fn sockstats_returns_200() {
        let addr = start_server().await;
        let resp = send_request(
            addr,
            b"POST /sockstats HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("text/plain"));
    }

    #[tokio::test]
    async fn sockstats_returns_json_when_wired() {
        let (addr, _log_level) = start_mock_server().await;
        let resp = send_request(
            addr,
            b"POST /sockstats HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("application/json"));
        assert!(resp.contains("\"stats\""));
        assert!(resp.contains("MagicsockConnUDP4"));
        assert!(resp.contains("\"tx_bytes\""));
        assert!(resp.contains("current_interface_cellular"));
    }

    #[tokio::test]
    async fn dns_returns_json() {
        let (addr, _) = start_mock_server().await;
        let resp = send_request(
            addr,
            b"GET /dns HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("Content-Type: application/json"));
        assert!(resp.contains("Proxied"));
    }

    #[tokio::test]
    async fn tls_cert_status_returns_json() {
        let (addr, _) = start_mock_server().await;
        let resp = send_request(
            addr,
            b"GET /tls-cert-status?domain=example.ts.net HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("Content-Type: application/json"));
        assert!(resp.contains("\"Valid\":true"));
        assert!(resp.contains("NotBefore"));
        assert!(resp.contains("NotAfter"));
        assert!(resp.contains("example.ts.net"));
    }

    #[tokio::test]
    async fn tls_cert_status_no_domain_returns_400() {
        let (addr, _) = start_mock_server().await;
        let resp = send_request(
            addr,
            b"GET /tls-cert-status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("400 Bad Request"));
        assert!(resp.contains("no 'domain'"));
    }

    #[tokio::test]
    async fn tls_cert_status_no_backend_returns_missing() {
        let addr = start_server().await;
        let resp = send_request(
            addr,
            b"GET /tls-cert-status?domain=foo.ts.net HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("\"Missing\":true"));
        assert!(resp.contains("\"Valid\":false"));
    }

    #[tokio::test]
    async fn echo_handler_returns_body() {
        let addr = start_server().await;
        let resp = send_request(
            addr,
            b"GET /echo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\nhello-echo",
        )
        .await;
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("hello-echo"));
    }

    #[tokio::test]
    async fn root_returns_endpoint_list_200() {
        let addr = start_server().await;
        let resp = send_request(
            addr,
            b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("/echo"));
        assert!(resp.contains("/netmap"));
        assert!(resp.contains("/prefs"));
        assert!(resp.contains("/debug/component-logging"));
        assert!(resp.contains("/debug/logheap"));
        assert!(resp.contains("/sockstats"));
    }

    #[tokio::test]
    async fn unknown_path_returns_400() {
        let addr = start_server().await;
        let resp = send_request(
            addr,
            b"GET /nonexistent HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("400 Bad Request"));
        assert!(resp.contains("unknown c2n path"));
    }

    #[tokio::test]
    async fn wrong_method_returns_405() {
        let addr = start_server().await;
        let resp = send_request(
            addr,
            b"POST /debug/goroutines HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("405 Method Not Allowed"));
        assert!(resp.contains("bad method"));
    }

    #[tokio::test]
    async fn local_command_returns_501() {
        let addr = start_server().await;
        let resp = send_request(
            addr,
            b"POST /local/ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("501 Not Implemented"));
    }

    #[tokio::test]
    async fn c2n_posture_identity_dispatch() {
        let addr = start_posture_server(false).await;
        let resp = send_request(
            addr,
            b"GET /posture/identity HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("\"serialNumbers\":[\"serial-1\"]"));
        assert!(resp.contains("\"ifaceHardwareAddrs\":[\"00:11:22:33:44:55\"]"));
    }

    #[tokio::test]
    async fn c2n_posture_disabled() {
        let addr = start_posture_server(true).await;
        let resp = send_request(
            addr,
            b"GET /posture/identity HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("\"postureDisabled\":true"));
    }

    #[tokio::test]
    async fn auth_allows_loopback() {
        let backend: Arc<dyn C2nBackend> = Arc::new(FakeBackend);
        assert!(check_auth("127.0.0.1".parse().unwrap(), &backend).await);
        assert!(check_auth("::1".parse().unwrap(), &backend).await);
    }

    #[tokio::test]
    async fn auth_allows_tailnet_ip() {
        let backend: Arc<dyn C2nBackend> = Arc::new(FakeBackend);
        assert!(check_auth("100.64.0.1".parse().unwrap(), &backend).await);
    }

    #[tokio::test]
    async fn auth_rejects_non_tailnet() {
        let backend: Arc<dyn C2nBackend> = Arc::new(FakeBackend);
        assert!(!check_auth("8.8.8.8".parse().unwrap(), &backend).await);
    }

    struct NotFoundBackend;
    #[async_trait]
    impl C2nBackend for NotFoundBackend {
        async fn whois(&self, _ip: IpAddr) -> Option<WhoIsResult> {
            None
        }
    }

    #[tokio::test]
    async fn auth_rejects_tailnet_ip_not_found() {
        let backend: Arc<dyn C2nBackend> = Arc::new(NotFoundBackend);
        assert!(!check_auth("100.64.0.1".parse().unwrap(), &backend).await);
    }
}
