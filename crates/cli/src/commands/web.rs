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
//! The default listener is an explicit loopback address. The address is checked
//! again after binding so a hostile resolver cannot turn a loopback-looking
//! hostname into a non-loopback listener. Every run has a fresh CSRF token;
//! API requests also require an exact Host and same-origin Origin header.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use rand::RngCore;
use rustscale_ipn::{MaskedPrefs, Prefs};
use rustscale_localclient::LocalClient;
use serde_json::Value;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const DEFAULT_LISTEN: &str = "127.0.0.1:8088";
const MAX_HEADER_BYTES: usize = 32 * 1024;
const MAX_BODY_BYTES: usize = 64 * 1024;
const CSRF_HEADER: &str = "x-rustscale-csrf-token";
const CSRF_FIELD: &str = "csrf_token";

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
    let listen = parse_str_flag(&args, "listen").unwrap_or_else(|| DEFAULT_LISTEN.to_owned());
    let readonly = parse_bool_flag(&args, "readonly").unwrap_or(false);
    let unsafe_any_addr = parse_bool_flag(&args, "unsafe-any-addr").unwrap_or(false);
    let open_browser = parse_bool_flag(&args, "browser").unwrap_or(true);

    // Do not pre-classify hostnames: only the kernel-selected address is an
    // authoritative answer after resolution and bind.
    let listener = TcpListener::bind(&listen)
        .await
        .map_err(|error| CliError(format!("failed to bind {listen}: {error}")))?;
    let addr = listener
        .local_addr()
        .map_err(|error| CliError(format!("local_addr: {error}")))?;
    verify_bound_addr(&listen, addr, unsafe_any_addr)?;

    let security = Arc::new(RequestSecurity::new(addr)?);
    let client = Arc::new(LocalClient::new(socket));
    let url = format!("http://{addr}/");
    eprintln!("{}", startup_message(&url, readonly));

    // Match upstream's local web-status behavior narrowly. The clean URL does
    // not contain the CSRF token; the loopback HTML response receives it only
    // after Host validation and applies a no-referrer/no-store policy.
    if should_open_browser(open_browser, addr) {
        let browser_url = url.clone();
        tokio::task::spawn_blocking(move || {
            use rustscale_freedesktop::{
                DesktopSession, DesktopTransport, Freedesktop, IntegrationError,
            };

            let integration = Freedesktop::default();
            let session = DesktopSession::detect();
            if let Err(error) = integration.open_url(&session, &browser_url) {
                if !matches!(
                    error,
                    IntegrationError::NoGraphicalSession | IntegrationError::NoSessionBus
                ) {
                    eprintln!("web: could not open browser: {error}");
                }
            }
        });
    }

    serve(listener, client, security, readonly).await
}

/// Run the HTTP server loop.
async fn serve(
    listener: TcpListener,
    client: Arc<LocalClient>,
    security: Arc<RequestSecurity>,
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
        let security = security.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(&mut stream, &*client, &security, readonly).await {
                eprintln!("web: connection error: {e}");
            }
        });
    }
}

/// Handle a single HTTP connection.
async fn handle_connection(
    stream: &mut tokio::net::TcpStream,
    client: &dyn LocalApi,
    security: &RequestSecurity,
    readonly: bool,
) -> Result<(), std::io::Error> {
    let Ok(req) = read_request(stream).await else {
        let body =
            serde_json::to_vec(&serde_json::json!({"error": "bad request"})).unwrap_or_default();
        write_response(stream, 400, "Bad Request", "application/json", &body).await?;
        return Ok(());
    };

    let resp = handle_request(&req, client, security, readonly).await;
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
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl HttpRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

/// Per-process request policy. Deliberately does not implement `Debug`, so the
/// token cannot be included accidentally in diagnostics.
struct RequestSecurity {
    authority: String,
    origin: String,
    csrf_token: String,
}

impl RequestSecurity {
    fn new(addr: SocketAddr) -> Result<Self, CliError> {
        let mut random = [0u8; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut random)
            .map_err(|error| CliError(format!("failed to generate web security token: {error}")))?;
        Ok(Self::from_token(
            addr,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random),
        ))
    }

    fn from_token(addr: SocketAddr, csrf_token: String) -> Self {
        let authority = addr.to_string();
        Self {
            origin: format!("http://{authority}"),
            authority,
            csrf_token,
        }
    }

    fn authorize(&self, request: &HttpRequest) -> Result<(), SecurityError> {
        let host = request.header("host").ok_or(SecurityError)?;
        if !host.eq_ignore_ascii_case(&self.authority) {
            return Err(SecurityError);
        }

        match request.header("origin") {
            Some(origin) if origin == self.origin => {}
            // A browser navigation does not send Origin. This one bootstrap
            // exception returns no token or state, only a same-origin POST
            // transition. Every response containing UI data requires Origin.
            None if request.method == "GET" && request.path == "/" => {}
            _ => return Err(SecurityError),
        }

        if is_state_changing(request) && !self.valid_csrf(request) {
            return Err(SecurityError);
        }
        Ok(())
    }

    fn valid_csrf(&self, request: &HttpRequest) -> bool {
        let candidate = request
            .header(CSRF_HEADER)
            .map(str::to_owned)
            .or_else(|| csrf_from_body(request));
        candidate.is_some_and(|candidate| {
            candidate.len() == self.csrf_token.len()
                && bool::from(candidate.as_bytes().ct_eq(self.csrf_token.as_bytes()))
        })
    }
}

#[derive(Clone, Copy)]
struct SecurityError;

fn is_state_changing(request: &HttpRequest) -> bool {
    !(matches!(request.method.as_str(), "GET" | "HEAD")
        || request.method == "POST" && matches!(request.path.as_str(), "/" | "/api/status"))
}

fn csrf_from_body(request: &HttpRequest) -> Option<String> {
    let content_type = request
        .header("content-type")?
        .split(';')
        .next()?
        .trim()
        .to_ascii_lowercase();
    match content_type.as_str() {
        "application/x-www-form-urlencoded" => {
            let mut values = url::form_urlencoded::parse(&request.body)
                .filter(|(name, _)| name == CSRF_FIELD)
                .map(|(_, value)| value.into_owned());
            let value = values.next()?;
            values.next().is_none().then_some(value)
        }
        "application/json" => {
            let value: Value = serde_json::from_slice(&request.body).ok()?;
            value
                .as_object()?
                .get(CSRF_FIELD)?
                .as_str()
                .map(str::to_owned)
        }
        _ => None,
    }
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

    fn rejected() -> Self {
        Self::json(
            403,
            "Forbidden",
            &serde_json::json!({"error": "request rejected"}),
        )
    }
}

/// Dispatch a parsed HTTP request to the appropriate handler.
/// This is the core logic, separated from the TCP layer for testability.
async fn handle_request(
    req: &HttpRequest,
    client: &dyn LocalApi,
    security: &RequestSecurity,
    readonly: bool,
) -> HttpResponse {
    // This must remain before route dispatch and before any action body is
    // interpreted. Rejected requests cannot reach LocalAPI.
    if security.authorize(req).is_err() {
        return HttpResponse::rejected();
    }

    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/") => HttpResponse::text(200, "OK", BOOTSTRAP_PAGE.as_bytes()),
        ("POST", "/") => HttpResponse::text(200, "OK", &render_html(&security.csrf_token)),
        ("GET" | "POST", "/api/status") => match client.status().await {
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

/// Read one bounded HTTP/1.1 request from the stream.
async fn read_request(stream: &mut tokio::net::TcpStream) -> Result<HttpRequest, String> {
    let mut bytes = Vec::with_capacity(4096);
    let mut temporary = [0u8; 4096];
    let header_end = loop {
        let count = stream
            .read(&mut temporary)
            .await
            .map_err(|error| format!("read: {error}"))?;
        if count == 0 {
            return Err("connection closed before headers".into());
        }
        bytes.extend_from_slice(&temporary[..count]);
        if let Some(end) = find_header_end(&bytes) {
            break end;
        }
        if bytes.len() > MAX_HEADER_BYTES {
            return Err("header too large".into());
        }
    };
    if header_end + 4 > MAX_HEADER_BYTES {
        return Err("header too large".into());
    }

    let (mut request, content_length) = parse_request_head(&bytes[..header_end + 4])?;
    request.body.extend_from_slice(&bytes[header_end + 4..]);
    if request.body.len() > content_length {
        request.body.truncate(content_length);
    }
    while request.body.len() < content_length {
        let remaining = content_length - request.body.len();
        let read_length = remaining.min(temporary.len());
        let count = stream
            .read(&mut temporary[..read_length])
            .await
            .map_err(|error| format!("read body: {error}"))?;
        if count == 0 {
            return Err("connection closed before body".into());
        }
        request.body.extend_from_slice(&temporary[..count]);
    }
    Ok(request)
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_request_head(head: &[u8]) -> Result<(HttpRequest, usize), String> {
    let text = std::str::from_utf8(head).map_err(|_| "non-utf8 header".to_string())?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or("no request line")?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or("no method")?;
    let path = parts.next().ok_or("no path")?;
    let version = parts.next().ok_or("no HTTP version")?;
    if parts.next().is_some() || version != "HTTP/1.1" {
        return Err("invalid request line".into());
    }
    if !method.bytes().all(|byte| byte.is_ascii_uppercase())
        || !path.starts_with('/')
        || path.len() > 2048
        || path.chars().any(char::is_control)
    {
        return Err("invalid request target".into());
    }

    let mut headers = BTreeMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':').ok_or("malformed header")?;
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || value.chars().any(char::is_control)
            || headers.insert(name, value.to_owned()).is_some()
        {
            return Err("invalid or duplicate header".into());
        }
    }
    if headers.contains_key("transfer-encoding") {
        return Err("transfer encoding is unsupported".into());
    }
    let content_length = match headers.get("content-length") {
        Some(value) => value
            .parse::<usize>()
            .map_err(|_| "invalid content length")?,
        None => 0,
    };
    if content_length > MAX_BODY_BYTES {
        return Err("body too large".into());
    }

    Ok((
        HttpRequest {
            method: method.to_owned(),
            path: path.to_owned(),
            headers,
            body: Vec::with_capacity(content_length),
        },
        content_length,
    ))
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
         Content-Length: {}\r\nCache-Control: no-store\r\nPragma: no-cache\r\n\
         Referrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\n\
         Cross-Origin-Opener-Policy: same-origin\r\nContent-Security-Policy: default-src 'self'; style-src 'unsafe-inline'; \
         script-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; \
         base-uri 'none'; form-action 'self'\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

fn verify_bound_addr(
    requested: &str,
    bound: SocketAddr,
    unsafe_any_addr: bool,
) -> Result<(), CliError> {
    if unsafe_any_addr || bound.ip().is_loopback() {
        return Ok(());
    }
    Err(CliError(format!(
        "refusing resolved non-loopback address {bound} for {requested:?}; \
         use --unsafe-any-addr to override"
    )))
}

fn should_open_browser(open_browser: bool, addr: SocketAddr) -> bool {
    cfg!(target_os = "linux") && open_browser && addr.ip().is_loopback()
}

fn startup_message(url: &str, readonly: bool) -> String {
    format!(
        "rustscale web listening on {url} ({}readonly)",
        if readonly { "" } else { "read-write, " }
    )
}

// -----------------------------------------------------------------------
// Embedded HTML page
// -----------------------------------------------------------------------

fn render_html(csrf_token: &str) -> Vec<u8> {
    HTML_PAGE.replace("__CSRF_TOKEN__", csrf_token).into_bytes()
}

// Top-level browser navigations omit Origin. Return no state or secret until a
// form POST from this loopback document supplies a browser-controlled Origin.
const BOOTSTRAP_PAGE: &str = r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer">
<title>rustscale</title></head><body>
<form method="post" action="/" id="bootstrap"><noscript><button type="submit">Open rustscale</button></noscript></form>
<script>document.getElementById('bootstrap').submit();</script>
</body></html>"#;

const HTML_PAGE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="rustscale-csrf-token" content="__CSRF_TOKEN__">
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
const csrfToken = document.querySelector('meta[name="rustscale-csrf-token"]').content;
const requestHeaders = { 'X-RustScale-CSRF-Token': csrfToken };
async function fetchStatus() {
  try {
    const r = await fetch('/api/status', {
      method: 'POST', headers: requestHeaders, credentials: 'same-origin',
      cache: 'no-store', referrerPolicy: 'no-referrer'
    });
    if (!r.ok) throw new Error('status request rejected');
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
function validEndpoint(value) {
  // LocalAPI serializes SocketAddr, so require either IPv4/hostname:port or
  // bracketed IPv6:port. A status page must fail closed on malformed data.
  return /^(?:[^:\\s]+|\\[[0-9A-Fa-f:.]+\\]):[1-9][0-9]*$/.test(value || '');
}
function validDerp(value) {
  return /^derp-[1-9][0-9]*$/.test(value || '');
}
function peerPath(p) {
  const paths = [
    validEndpoint(p.CurAddr) ? ['direct ', p.CurAddr] : null,
    validDerp(p.Relay) ? ['relay ', p.Relay] : null,
    validEndpoint(p.PeerRelay) ? ['peer-relay ', p.PeerRelay] : null
  ].filter(Boolean);
  if (!p.Online) return '-';
  if (!p.Active || paths.length !== 1) return 'idle';
  return paths[0][0] + paths[0][1];
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
    const path = peerPath(p);
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
    const r = await fetch('/api/' + action, {
      method: 'POST', headers: requestHeaders, credentials: 'same-origin',
      cache: 'no-store', referrerPolicy: 'no-referrer'
    });
    if (!r.ok) throw new Error('action request rejected');
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

    const TEST_TOKEN: &str = "test-token-that-is-not-logged";

    fn test_addr() -> SocketAddr {
        "127.0.0.1:8088".parse().unwrap()
    }

    fn test_security() -> RequestSecurity {
        RequestSecurity::from_token(test_addr(), TEST_TOKEN.to_owned())
    }

    fn make_req(method: &str, path: &str) -> HttpRequest {
        let mut headers = BTreeMap::from([
            ("host".to_owned(), "127.0.0.1:8088".to_owned()),
            ("origin".to_owned(), "http://127.0.0.1:8088".to_owned()),
        ]);
        if !(matches!(method, "GET" | "HEAD")
            || method == "POST" && matches!(path, "/" | "/api/status"))
        {
            headers.insert(CSRF_HEADER.to_owned(), TEST_TOKEN.to_owned());
        }
        HttpRequest {
            method: method.into(),
            path: path.into(),
            headers,
            body: Vec::new(),
        }
    }

    // Preserve concise functional-handler tests while making every request go
    // through the same production request policy.
    async fn handle_request(
        request: &HttpRequest,
        client: &dyn LocalApi,
        readonly: bool,
    ) -> HttpResponse {
        super::handle_request(request, client, &test_security(), readonly).await
    }

    #[tokio::test]
    async fn get_root_returns_token_free_bootstrap_then_origin_checked_ui() {
        let stub = StubClient::new(json!({}));
        let bootstrap = handle_request(&make_req("GET", "/"), &stub, false).await;
        assert_eq!(bootstrap.status, 200);
        assert!(bootstrap.content_type.contains("text/html"));
        let bootstrap_html = std::str::from_utf8(&bootstrap.body).unwrap();
        assert!(bootstrap_html.contains("method=\"post\""));
        assert!(!bootstrap_html.contains(TEST_TOKEN));

        let response = handle_request(&make_req("POST", "/"), &stub, false).await;
        assert_eq!(response.status, 200);
        let html = std::str::from_utf8(&response.body).unwrap();
        assert!(html.contains("<title>rustscale</title>"));
        assert!(html.contains("/api/status"));
        assert!(html.contains(TEST_TOKEN));
        assert!(!html.contains("__CSRF_TOKEN__"));
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

    async fn assert_security_rejection(request: HttpRequest, stub: &StubClient) {
        let response = super::handle_request(&request, stub, &test_security(), false).await;
        assert_eq!(response.status, 403);
        assert_eq!(response.content_type, "application/json");
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body, json!({"error": "request rejected"}));
        assert!(!String::from_utf8_lossy(&response.body).contains(TEST_TOKEN));
        assert!(stub.calls().is_empty());
    }

    #[tokio::test]
    async fn absent_null_and_cross_origin_reads_are_rejected() {
        let stub = StubClient::new(make_status());
        for origin in [None, Some("null"), Some("https://attacker.example")] {
            let mut request = make_req("GET", "/api/status");
            match origin {
                Some(origin) => {
                    request.headers.insert("origin".into(), origin.into());
                }
                None => {
                    request.headers.remove("origin");
                }
            }
            assert_security_rejection(request, &stub).await;
        }
    }

    #[tokio::test]
    async fn hostile_host_and_dns_rebinding_host_are_rejected_before_reads() {
        let stub = StubClient::new(make_status());
        for host in ["attacker.example", "localhost:8088", "127.0.0.1:9999"] {
            let mut request = make_req("GET", "/api/status");
            request.headers.insert("host".into(), host.into());
            assert_security_rejection(request, &stub).await;
        }

        let mut bootstrap = make_req("GET", "/");
        bootstrap.headers.remove("origin");
        bootstrap
            .headers
            .insert("host".into(), "rebind.attacker".into());
        assert_security_rejection(bootstrap, &stub).await;
    }

    #[tokio::test]
    async fn bootstrap_allows_only_absent_or_same_origin_after_host_check() {
        let stub = StubClient::new(json!({}));
        let mut request = make_req("GET", "/");
        request.headers.remove("origin");
        let response = super::handle_request(&request, &stub, &test_security(), false).await;
        assert_eq!(response.status, 200);
        assert!(!String::from_utf8_lossy(&response.body).contains(TEST_TOKEN));

        request.headers.insert("origin".into(), "null".into());
        assert_security_rejection(request, &stub).await;
    }

    #[tokio::test]
    async fn malicious_form_posts_cannot_reach_actions() {
        let stub = StubClient::new(make_status());
        let mut request = make_req("POST", "/api/up");
        request.headers.remove(CSRF_HEADER);
        request.headers.insert(
            "content-type".into(),
            "application/x-www-form-urlencoded".into(),
        );
        request.body = b"action=up&csrf_token=guessed".to_vec();
        assert_security_rejection(request, &stub).await;

        let mut cross_origin = make_req("POST", "/api/logout");
        cross_origin
            .headers
            .insert("origin".into(), "https://attacker.example".into());
        assert_security_rejection(cross_origin, &stub).await;
    }

    #[tokio::test]
    async fn csrf_token_is_required_for_every_action() {
        let stub = StubClient::new(make_status());
        for path in ["/api/up", "/api/down", "/api/logout", "/unknown"] {
            let mut request = make_req("POST", path);
            request.headers.remove(CSRF_HEADER);
            assert_security_rejection(request, &stub).await;
        }
    }

    #[tokio::test]
    async fn csrf_token_can_be_supplied_in_bounded_form_or_json_body() {
        let stub = StubClient::new(make_status());
        let mut form = make_req("POST", "/api/up");
        form.headers.remove(CSRF_HEADER);
        form.headers.insert(
            "content-type".into(),
            "application/x-www-form-urlencoded".into(),
        );
        form.body = format!("csrf_token={TEST_TOKEN}").into_bytes();
        let response = super::handle_request(&form, &stub, &test_security(), false).await;
        assert_eq!(response.status, 200);

        let mut json_request = make_req("POST", "/api/down");
        json_request.headers.remove(CSRF_HEADER);
        json_request
            .headers
            .insert("content-type".into(), "application/json".into());
        json_request.body = serde_json::to_vec(&json!({CSRF_FIELD: TEST_TOKEN})).unwrap();
        let response = super::handle_request(&json_request, &stub, &test_security(), false).await;
        assert_eq!(response.status, 200);
        assert_eq!(
            stub.calls(),
            ["set_want_running(true)", "set_want_running(false)"]
        );
    }

    #[test]
    fn csrf_tokens_are_per_run_cryptographic_values() {
        let first = RequestSecurity::new(test_addr()).unwrap();
        let second = RequestSecurity::new(test_addr()).unwrap();
        assert_eq!(first.csrf_token.len(), 43);
        assert_eq!(second.csrf_token.len(), 43);
        assert_ne!(first.csrf_token, second.csrf_token);
        assert!(first
            .csrf_token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')));
    }

    #[test]
    fn default_and_post_bind_checks_do_not_trust_hostname_resolution() {
        assert_eq!(DEFAULT_LISTEN, "127.0.0.1:8088");
        let rebound: SocketAddr = "192.0.2.44:8088".parse().unwrap();
        assert!(verify_bound_addr("localhost:8088", rebound, false).is_err());
        assert!(verify_bound_addr("localhost:8088", rebound, true).is_ok());
    }

    #[test]
    fn post_bind_check_accepts_ipv4_and_ipv6_loopback_only() {
        for address in ["127.0.0.1:8088", "127.99.1.2:0", "[::1]:8088"] {
            assert!(verify_bound_addr(address, address.parse().unwrap(), false).is_ok());
        }
        for address in ["0.0.0.0:8088", "[::]:8088", "100.64.0.1:8088"] {
            assert!(verify_bound_addr(address, address.parse().unwrap(), false).is_err());
        }
    }

    #[test]
    fn ipv4_and_ipv6_authorities_are_origin_checked_exactly() {
        for address in ["127.0.0.1:8088", "[::1]:8088"] {
            let addr: SocketAddr = address.parse().unwrap();
            let security = RequestSecurity::from_token(addr, TEST_TOKEN.to_owned());
            let request = HttpRequest {
                method: "GET".into(),
                path: "/api/status".into(),
                headers: BTreeMap::from([
                    ("host".into(), address.into()),
                    ("origin".into(), format!("http://{address}")),
                ]),
                body: Vec::new(),
            };
            assert!(security.authorize(&request).is_ok());
        }
    }

    #[test]
    fn web_peer_table_requires_one_valid_active_path_identity() {
        // Browser rendering is intentionally driven from the same LocalAPI
        // fields as `status`; preserve the fail-closed checks in the emitted
        // public page rather than relying on its Rust-side producer alone.
        assert!(HTML_PAGE.contains("function peerPath(p)"));
        assert!(HTML_PAGE.contains("!p.Active || paths.length !== 1"));
        assert!(HTML_PAGE.contains("validEndpoint(p.CurAddr)"));
        assert!(HTML_PAGE.contains("validDerp(p.Relay)"));
        assert!(HTML_PAGE.contains("validEndpoint(p.PeerRelay)"));
    }

    #[test]
    fn browser_false_and_startup_output_never_expose_token() {
        let args = ["--browser=false".to_owned()];
        let browser = parse_bool_flag(&args, "browser").unwrap_or(true);
        assert!(!should_open_browser(browser, test_addr()));

        let url = "http://127.0.0.1:8088/";
        let message = startup_message(url, false);
        assert!(message.contains(url));
        assert!(!message.contains(TEST_TOKEN));
        assert!(!url.contains(TEST_TOKEN));
        assert!(
            !message.starts_with('{'),
            "startup diagnostics stay off JSON stdout"
        );
    }

    #[test]
    fn parser_rejects_duplicate_host_origin_and_csrf_headers() {
        for duplicate in ["Host", "Origin", "X-RustScale-CSRF-Token"] {
            let request = format!(
                "POST /api/up HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n\
                 Origin: http://127.0.0.1:8088\r\n\
                 X-RustScale-CSRF-Token: {TEST_TOKEN}\r\n{duplicate}: duplicate\r\n\r\n"
            );
            assert!(parse_request_head(request.as_bytes()).is_err());
        }
    }

    #[test]
    fn parser_rejects_oversized_bodies_and_absolute_targets() {
        let oversized = format!(
            "POST /api/up HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n\
             Content-Length: {}\r\n\r\n",
            MAX_BODY_BYTES + 1
        );
        assert!(parse_request_head(oversized.as_bytes()).is_err());
        assert!(parse_request_head(
            b"GET http://attacker.example/ HTTP/1.1\r\nHost: 127.0.0.1:8088\r\n\r\n"
        )
        .is_err());
    }
}
