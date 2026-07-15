//! `rustscale web` — minimal management web UI.
//!
//! Ports Go's `cmd/tailscale/cli/web.go` (but NOT the React app from
//! `client/web/`). Serves a self-contained single-file HTML page with inline
//! vanilla JS that talks to handlers in this process, which proxy to the
//! daemon over LocalAPI (safesocket).
//!
//! # Endpoints
//!
//!   GET  /             — embedded HTML status page
//!   GET  /api/status   — daemon status JSON (passthrough)
//!   POST /api/up       — set WantRunning=true  (disabled in --readonly)
//!   POST /api/down     — set WantRunning=false (disabled in --readonly)
//!   POST /api/logout   — logout               (disabled in --readonly)
//!
//! # Security
//!
//! Binds to localhost only by default. Use `--unsafe-any-addr` to bind to a
//! non-loopback address (the web UI has no authentication — anyone who can
//! reach it can toggle your Tailscale state).

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use rustscale_ipn::{MaskedPrefs, Prefs};
use rustscale_localclient::LocalClient;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::flags::{parse_bool_flag, parse_str_flag};
use crate::CliError;

/// Trait abstracting the LocalAPI calls the web UI needs.
/// Implemented for [`LocalClient`] (production) and test stubs.
#[async_trait]
trait LocalApi: Send + Sync {
    async fn status(&self) -> Result<Value, String>;
    async fn set_want_running(&self, want: bool) -> Result<(), String>;
    async fn logout(&self) -> Result<(), String>;
}

#[async_trait]
impl LocalApi for LocalClient {
    async fn status(&self) -> Result<Value, String> {
        LocalClient::status(self).await.map_err(|e| e.to_string())
    }

    async fn set_want_running(&self, want: bool) -> Result<(), String> {
        let mask = MaskedPrefs {
            Prefs: Prefs {
                WantRunning: want,
                ..Default::default()
            },
            WantRunningSet: true,
            ..Default::default()
        };
        self.edit_prefs(&mask)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    async fn logout(&self) -> Result<(), String> {
        LocalClient::logout(self).await.map_err(|e| e.to_string())
    }
}

pub async fn run(args: Vec<String>, socket: &Path) -> Result<(), CliError> {
    let listen = parse_str_flag(&args, "listen").unwrap_or_else(|| "localhost:8088".to_string());
    let readonly = parse_bool_flag(&args, "readonly").unwrap_or(false);
    let unsafe_any_addr = parse_bool_flag(&args, "unsafe-any-addr").unwrap_or(false);
    let open_browser = parse_bool_flag(&args, "browser").unwrap_or(true);

    if !unsafe_any_addr && !is_loopback_addr(&listen) {
        return Err(CliError(format!(
            "refusing to bind to non-loopback address '{listen}'. \
             Use --unsafe-any-addr to override (WARNING: no authentication)."
        )));
    }

    let client = Arc::new(LocalClient::new(socket));
    let listener = TcpListener::bind(&listen)
        .await
        .map_err(|e| CliError(format!("failed to bind {listen}: {e}")))?;

    let addr = listener
        .local_addr()
        .map_err(|e| CliError(format!("local_addr: {e}")))?;
    let url = format!("http://{addr}/");
    eprintln!(
        "rustscale web listening on {url} ({}readonly)",
        if readonly { "" } else { "read-write, " }
    );

    // Match upstream's local web-status behavior narrowly: only try to open a
    // browser for a loopback listener, and never make desktop integration a
    // prerequisite for serving. The command transport enforces its own short
    // deadline and rejects non-HTTP(S) URLs.
    if cfg!(target_os = "linux") && open_browser && addr.ip().is_loopback() {
        tokio::task::spawn_blocking(move || {
            use rustscale_freedesktop::{
                DesktopSession, DesktopTransport, Freedesktop, IntegrationError,
            };

            let integration = Freedesktop::default();
            let session = DesktopSession::detect();
            if let Err(error) = integration.open_url(&session, &url) {
                if !matches!(
                    error,
                    IntegrationError::NoGraphicalSession | IntegrationError::NoSessionBus
                ) {
                    eprintln!("web: could not open browser: {error}");
                }
            }
        });
    }

    serve(listener, client, readonly).await
}

/// Run the HTTP server loop.
async fn serve(
    listener: TcpListener,
    client: Arc<LocalClient>,
    readonly: bool,
) -> Result<(), CliError> {
    loop {
        let (mut stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("web: accept error: {e}");
                continue;
            }
        };
        let client = client.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(&mut stream, &*client, readonly).await {
                eprintln!("web: connection error: {e}");
            }
        });
    }
}

/// Handle a single HTTP connection.
async fn handle_connection(
    stream: &mut tokio::net::TcpStream,
    client: &dyn LocalApi,
    readonly: bool,
) -> Result<(), std::io::Error> {
    let req = match read_request(stream).await {
        Ok(r) => r,
        Err(e) => {
            let body = format!(r#"{{"error":"bad request","reason":"{e}"}}"#);
            write_response(
                stream,
                400,
                "Bad Request",
                "application/json",
                body.as_bytes(),
            )
            .await?;
            return Ok(());
        }
    };

    let resp = handle_request(&req, client, readonly).await;
    write_response(
        stream,
        resp.status,
        resp.reason,
        resp.content_type,
        &resp.body,
    )
    .await
}

/// Parsed HTTP request.
struct HttpRequest {
    method: String,
    path: String,
    #[allow(dead_code)]
    body: Vec<u8>,
}

/// HTTP response.
struct HttpResponse {
    status: u16,
    reason: &'static str,
    content_type: &'static str,
    body: Vec<u8>,
}

impl HttpResponse {
    fn json(status: u16, reason: &'static str, body: &Value) -> Self {
        let body = serde_json::to_vec(body).unwrap_or_default();
        HttpResponse {
            status,
            reason,
            content_type: "application/json",
            body,
        }
    }

    fn text(status: u16, reason: &'static str, body: &[u8]) -> Self {
        HttpResponse {
            status,
            reason,
            content_type: "text/html; charset=utf-8",
            body: body.to_vec(),
        }
    }

    fn empty(status: u16, reason: &'static str) -> Self {
        HttpResponse {
            status,
            reason,
            content_type: "application/json",
            body: Vec::new(),
        }
    }
}

/// Dispatch a parsed HTTP request to the appropriate handler.
/// This is the core logic, separated from the TCP layer for testability.
async fn handle_request(req: &HttpRequest, client: &dyn LocalApi, readonly: bool) -> HttpResponse {
    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") => HttpResponse::text(200, "OK", HTML_PAGE.as_bytes()),
        ("GET", "/api/status") => match client.status().await {
            Ok(status) => HttpResponse::json(200, "OK", &status),
            Err(e) => {
                let body = serde_json::json!({"error": e});
                HttpResponse::json(500, "Internal Server Error", &body)
            }
        },
        ("POST", "/api/up") => {
            if readonly {
                let body = serde_json::json!({"error": "server is in read-only mode"});
                return HttpResponse::json(403, "Forbidden", &body);
            }
            match client.set_want_running(true).await {
                Ok(()) => HttpResponse::empty(200, "OK"),
                Err(e) => {
                    let body = serde_json::json!({"error": e});
                    HttpResponse::json(500, "Internal Server Error", &body)
                }
            }
        }
        ("POST", "/api/down") => {
            if readonly {
                let body = serde_json::json!({"error": "server is in read-only mode"});
                return HttpResponse::json(403, "Forbidden", &body);
            }
            match client.set_want_running(false).await {
                Ok(()) => HttpResponse::empty(200, "OK"),
                Err(e) => {
                    let body = serde_json::json!({"error": e});
                    HttpResponse::json(500, "Internal Server Error", &body)
                }
            }
        }
        ("POST", "/api/logout") => {
            if readonly {
                let body = serde_json::json!({"error": "server is in read-only mode"});
                return HttpResponse::json(403, "Forbidden", &body);
            }
            match client.logout().await {
                Ok(()) => HttpResponse::empty(200, "OK"),
                Err(e) => {
                    let body = serde_json::json!({"error": e});
                    HttpResponse::json(500, "Internal Server Error", &body)
                }
            }
        }
        _ => {
            let body = serde_json::json!({"error": "not found"});
            HttpResponse::json(404, "Not Found", &body)
        }
    }
}

/// Read a complete HTTP/1.1 request from the stream.
async fn read_request(stream: &mut tokio::net::TcpStream) -> Result<HttpRequest, String> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream
            .read(&mut tmp)
            .await
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("connection closed before headers".into());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(end) = find_header_end(&buf) {
            let head = &buf[..end + 4];
            let body_start = end + 4;
            let body_preview = buf[body_start..].to_vec();
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

    let mut content_length: Option<usize> = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().ok();
            }
        }
    }

    let body = match content_length {
        Some(cl) if body_preview.len() >= cl => body_preview[..cl].to_vec(),
        _ => body_preview,
    };

    Ok(HttpRequest {
        method,
        path: raw_path,
        body,
    })
}

/// Write an HTTP response to the stream.
async fn write_response(
    stream: &mut tokio::net::TcpStream,
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
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

/// Check if a listen address binds to a loopback interface.
/// Accepts `host:port` or `[ipv6]:port` format.
fn is_loopback_addr(addr: &str) -> bool {
    let host = parse_host(addr);
    if host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]" {
        return true;
    }
    host.split('.').next().is_some_and(|first_octet| {
        first_octet == "127" && host.parse::<std::net::Ipv4Addr>().is_ok()
    })
}

/// Extract the host part from a `host:port` or `[host]:port` address.
fn parse_host(addr: &str) -> String {
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            return format!("[{}]", &rest[..end]);
        }
    }
    match addr.rsplit_once(':') {
        Some((host, _port)) => host.to_string(),
        None => addr.to_string(),
    }
}

// -----------------------------------------------------------------------
// Embedded HTML page
// -----------------------------------------------------------------------

const HTML_PAGE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>rustscale</title>
<style>
:root { color-scheme: light dark; }
body { font-family: system-ui, sans-serif; max-width: 920px; margin: 2rem auto; padding: 0 1rem; }
h1 { font-size: 1.5rem; }
h2 { font-size: 1.1rem; margin-top: 2rem; border-bottom: 1px solid #888; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 0.3rem 0.5rem; border-bottom: 1px solid #444; }
th { font-size: 0.8rem; text-transform: uppercase; opacity: 0.7; }
.status-ok { color: #2e7d32; }
.status-warn { color: #f57f17; }
.status-err { color: #c62828; }
.actions { display: flex; gap: 0.5rem; margin: 1rem 0; }
button { padding: 0.4rem 1rem; font-size: 0.9rem; cursor: pointer; border-radius: 4px; border: 1px solid #666; background: var(--btn-bg, #f0f0f0); color: inherit; }
button:hover { background: #e0e0e0; }
button.danger { border-color: #c62828; color: #c62828; }
.muted { opacity: 0.6; font-size: 0.85rem; }
pre { white-space: pre-wrap; }
</style>
</head>
<body>
<h1>rustscale</h1>
<div id="status" class="muted">Loading…</div>
<div id="actions" class="actions" style="display:none">
  <button id="btn-up" onclick="doAction('up')">Up</button>
  <button id="btn-down" onclick="doAction('down')">Down</button>
  <button id="btn-logout" class="danger" onclick="doAction('logout')">Logout</button>
</div>
<h2>Peers</h2>
<table id="peers">
<thead><tr><th>Name</th><th>IP</th><th>OS</th><th>Online</th><th>Path</th></tr></thead>
<tbody></tbody>
</table>
<script>
async function fetchStatus() {
  try {
    const r = await fetch('/api/status');
    const st = await r.json();
    renderStatus(st);
    renderPeers(st);
  } catch (e) {
    document.getElementById('status').textContent = 'Error: ' + e;
  }
}
function renderStatus(st) {
  const self = st.Self || {};
  const ips = (self.TailscaleIPs || []).join(', ') || '-';
  const state = st.BackendState || 'Unknown';
  const hostname = self.HostName || self.DNSName || '-';
  const health = (st.Health || []).join('; ');
  const version = st.Version || '-';
  const cls = state === 'Running' ? 'status-ok' : state === 'NeedsLogin' ? 'status-err' : 'status-warn';
  let html = '<p><strong>State:</strong> <span class="' + cls + '">' + state + '</span></p>';
  html += '<p><strong>Hostname:</strong> ' + esc(hostname) + '</p>';
  html += '<p><strong>IPs:</strong> ' + esc(ips) + '</p>';
  html += '<p><strong>Version:</strong> ' + esc(version) + '</p>';
  if (health) html += '<p><strong>Health:</strong> ' + esc(health) + '</p>';
  document.getElementById('status').innerHTML = html;
  const running = state === 'Running';
  document.getElementById('actions').style.display = '';
  document.getElementById('btn-up').disabled = running;
  document.getElementById('btn-down').disabled = !running;
}
function renderPeers(st) {
  const tbody = document.querySelector('#peers tbody');
  tbody.innerHTML = '';
  const peers = st.Peer || {};
  const rows = Object.values(peers).sort(function(a, b) {
    return ((a.TailscaleIPs||[])[0]||'').localeCompare((b.TailscaleIPs||[])[0]||'');
  });
  for (const p of rows) {
    const tr = document.createElement('tr');
    const name = (p.DNSName || p.HostName || '-').replace(/\.$/, '');
    const ip = (p.TailscaleIPs || [])[0] || '-';
    const os = p.OS || '-';
    const online = p.Online ? 'yes' : 'no';
    const path = p.Relay ? 'relay ' + p.Relay : (p.Online ? 'direct' : '-');
    tr.innerHTML = '<td>' + esc(name) + '</td><td>' + esc(ip) + '</td><td>' + esc(os) +
      '</td><td>' + online + '</td><td>' + esc(path) + '</td>';
    tbody.appendChild(tr);
  }
  if (rows.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="muted">No peers</td></tr>';
  }
}
function esc(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}
async function doAction(action) {
  try {
    await fetch('/api/' + action, { method: 'POST' });
    await fetchStatus();
  } catch (e) {
    alert('Action failed: ' + e);
  }
}
fetchStatus();
setInterval(fetchStatus, 5000);
</script>
</body>
</html>"#;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    /// Stub client for testing handlers. Records method calls.
    struct StubClient {
        status_json: Value,
        calls: Mutex<Vec<String>>,
        fail: bool,
    }

    impl StubClient {
        fn new(status_json: Value) -> Self {
            StubClient {
                status_json,
                calls: Mutex::new(Vec::new()),
                fail: false,
            }
        }

        fn failing() -> Self {
            StubClient {
                status_json: json!({}),
                calls: Mutex::new(Vec::new()),
                fail: true,
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl LocalApi for StubClient {
        async fn status(&self) -> Result<Value, String> {
            if self.fail {
                return Err("daemon unavailable".into());
            }
            Ok(self.status_json.clone())
        }

        async fn set_want_running(&self, want: bool) -> Result<(), String> {
            if self.fail {
                return Err("daemon unavailable".into());
            }
            self.calls
                .lock()
                .unwrap()
                .push(format!("set_want_running({want})"));
            Ok(())
        }

        async fn logout(&self) -> Result<(), String> {
            if self.fail {
                return Err("daemon unavailable".into());
            }
            self.calls.lock().unwrap().push("logout".into());
            Ok(())
        }
    }

    fn make_status() -> Value {
        let mut peers = serde_json::Map::new();
        peers.insert(
            "node1".into(),
            json!({
                "DNSName": "alpha.tailnet.ts.net",
                "HostName": "alpha",
                "TailscaleIPs": ["100.64.0.2"],
                "OS": "linux",
                "Online": true,
                "Relay": "",
            }),
        );
        peers.insert(
            "node2".into(),
            json!({
                "DNSName": "beta.tailnet.ts.net",
                "HostName": "beta",
                "TailscaleIPs": ["100.64.0.3"],
                "OS": "macOS",
                "Online": false,
                "Relay": "derp1",
            }),
        );
        json!({
            "BackendState": "Running",
            "Version": "0.1.0",
            "Health": [],
            "Self": {
                "HostName": "myhost",
                "DNSName": "myhost.tailnet.ts.net",
                "TailscaleIPs": ["100.64.0.1"],
            },
            "Peer": peers,
        })
    }

    fn make_req(method: &str, path: &str) -> HttpRequest {
        HttpRequest {
            method: method.into(),
            path: path.into(),
            body: Vec::new(),
        }
    }

    #[tokio::test]
    async fn get_root_returns_html() {
        let stub = StubClient::new(json!({}));
        let resp = handle_request(&make_req("GET", "/"), &stub, false).await;
        assert_eq!(resp.status, 200);
        assert!(resp.content_type.contains("text/html"));
        let html = std::str::from_utf8(&resp.body).unwrap();
        assert!(html.contains("<title>rustscale</title>"));
        assert!(html.contains("/api/status"));
    }

    #[tokio::test]
    async fn get_status_returns_peers() {
        let stub = StubClient::new(make_status());
        let resp = handle_request(&make_req("GET", "/api/status"), &stub, false).await;
        assert_eq!(resp.status, 200);
        assert_eq!(resp.content_type, "application/json");
        let body: Value = serde_json::from_slice(&resp.body).unwrap();
        let peers = body.get("Peer").unwrap().as_object().unwrap();
        assert_eq!(peers.len(), 2);
        assert!(peers.contains_key("node1"));
        assert!(peers.contains_key("node2"));
    }

    #[tokio::test]
    async fn post_up_toggles_want_running() {
        let stub = StubClient::new(make_status());
        let resp = handle_request(&make_req("POST", "/api/up"), &stub, false).await;
        assert_eq!(resp.status, 200);
        assert_eq!(stub.calls(), vec!["set_want_running(true)"]);
    }

    #[tokio::test]
    async fn post_down_toggles_want_running() {
        let stub = StubClient::new(make_status());
        let resp = handle_request(&make_req("POST", "/api/down"), &stub, false).await;
        assert_eq!(resp.status, 200);
        assert_eq!(stub.calls(), vec!["set_want_running(false)"]);
    }

    #[tokio::test]
    async fn post_logout_calls_logout() {
        let stub = StubClient::new(make_status());
        let resp = handle_request(&make_req("POST", "/api/logout"), &stub, false).await;
        assert_eq!(resp.status, 200);
        assert_eq!(stub.calls(), vec!["logout"]);
    }

    #[tokio::test]
    async fn readonly_blocks_actions() {
        let stub = StubClient::new(make_status());
        let resp = handle_request(&make_req("POST", "/api/up"), &stub, true).await;
        assert_eq!(resp.status, 403);
        assert!(stub.calls().is_empty());
    }

    #[tokio::test]
    async fn readonly_blocks_down() {
        let stub = StubClient::new(make_status());
        let resp = handle_request(&make_req("POST", "/api/down"), &stub, true).await;
        assert_eq!(resp.status, 403);
        assert!(stub.calls().is_empty());
    }

    #[tokio::test]
    async fn readonly_blocks_logout() {
        let stub = StubClient::new(make_status());
        let resp = handle_request(&make_req("POST", "/api/logout"), &stub, true).await;
        assert_eq!(resp.status, 403);
        assert!(stub.calls().is_empty());
    }

    #[tokio::test]
    async fn readonly_allows_status() {
        let stub = StubClient::new(make_status());
        let resp = handle_request(&make_req("GET", "/api/status"), &stub, true).await;
        assert_eq!(resp.status, 200);
    }

    #[tokio::test]
    async fn status_error_returns_500() {
        let stub = StubClient::failing();
        let resp = handle_request(&make_req("GET", "/api/status"), &stub, false).await;
        assert_eq!(resp.status, 500);
        let body: Value = serde_json::from_slice(&resp.body).unwrap();
        assert!(body
            .get("error")
            .unwrap()
            .as_str()
            .unwrap()
            .contains("daemon unavailable"));
    }

    #[tokio::test]
    async fn up_error_returns_500() {
        let stub = StubClient::failing();
        let resp = handle_request(&make_req("POST", "/api/up"), &stub, false).await;
        assert_eq!(resp.status, 500);
    }

    #[tokio::test]
    async fn unknown_path_returns_404() {
        let stub = StubClient::new(json!({}));
        let resp = handle_request(&make_req("GET", "/nonexistent"), &stub, false).await;
        assert_eq!(resp.status, 404);
    }

    #[tokio::test]
    async fn wrong_method_returns_404() {
        let stub = StubClient::new(json!({}));
        let resp = handle_request(&make_req("DELETE", "/api/status"), &stub, false).await;
        assert_eq!(resp.status, 404);
    }

    #[test]
    fn is_loopback_localhost() {
        assert!(is_loopback_addr("localhost:8088"));
        assert!(is_loopback_addr("localhost:0"));
    }

    #[test]
    fn is_loopback_127_ipv4() {
        assert!(is_loopback_addr("127.0.0.1:8088"));
        assert!(is_loopback_addr("127.0.0.1:0"));
    }

    #[test]
    fn is_loopback_ipv6() {
        assert!(is_loopback_addr("[::1]:8088"));
        assert!(is_loopback_addr("[::1]:0"));
    }

    #[test]
    fn is_not_loopback_wildcard() {
        assert!(!is_loopback_addr("0.0.0.0:8088"));
        assert!(!is_loopback_addr("[::]:8088"));
    }

    #[test]
    fn is_not_loopback_external() {
        assert!(!is_loopback_addr("192.168.1.1:8088"));
        assert!(!is_loopback_addr("10.0.0.1:8088"));
        assert!(!is_loopback_addr("100.64.0.1:8088"));
    }

    #[test]
    fn parse_host_simple() {
        assert_eq!(parse_host("localhost:8088"), "localhost");
        assert_eq!(parse_host("127.0.0.1:8088"), "127.0.0.1");
    }

    #[test]
    fn parse_host_ipv6() {
        assert_eq!(parse_host("[::1]:8088"), "[::1]");
    }

    #[test]
    fn parse_host_no_port() {
        assert_eq!(parse_host("localhost"), "localhost");
    }
}
