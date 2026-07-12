//! LocalAPI HTTP client for rustscale — a Rust equivalent of Go's
//! `client/local` package. Communicates with `rustscaled` over a Unix domain
//! socket via [`rustscale_safesocket::connect`], speaking hand-rolled HTTP/1.1.
//!
//! # Architecture
//!
//! No external HTTP client library: requests are built as raw HTTP/1.1 bytes
//! and responses are parsed manually, matching the minimalist style of the
//! daemon's LocalAPI server (`crates/tsnet/src/localapi.rs`). The fake Host
//! header is `local-rustscaled.sock` (analogous to Go's `local-tailscaled.sock`).
//!
//! # Error mapping
//!
//! HTTP status codes are mapped to typed errors matching Go's
//! `client/local`:
//! - 403 → [`LocalClientError::AccessDenied`]
//! - 412 → [`LocalClientError::PreconditionsFailed`]
//! - other non-200 → [`LocalClientError::HttpStatus`]
//! - connection failures → [`LocalClientError::Connect`]
//! - JSON decode failures → [`LocalClientError::Json`]

#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]

mod error;
mod stream;

pub use error::LocalClientError;
pub use stream::WatchIpnBus;

use std::path::PathBuf;

use rustscale_ipn::{MaskedPrefs, NotifyWatchOpt, Prefs, StartOptions};
use rustscale_tailcfg::DERPMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// The fake Host header value, analogous to Go's `apitype.LocalAPIHost`.
const LOCAL_API_HOST: &str = "local-rustscaled.sock";

/// A client for the rustscale daemon's LocalAPI over a Unix domain socket.
///
/// Its zero value is invalid — use [`LocalClient::new`] or
/// [`LocalClient::with_socket`].
#[derive(Clone, Debug)]
pub struct LocalClient {
    socket_path: PathBuf,
}

impl LocalClient {
    /// Create a client pointing at the given socket path.
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    /// The socket path this client connects to.
    pub fn socket_path(&self) -> &std::path::Path {
        &self.socket_path
    }

    // -----------------------------------------------------------------------
    // High-level API methods
    // -----------------------------------------------------------------------

    /// GET /localapi/v0/status — returns the raw status JSON.
    pub async fn status(&self) -> Result<serde_json::Value, LocalClientError> {
        let body = self.get_json("/localapi/v0/status").await?;
        Ok(body)
    }

    /// GET /localapi/v0/whois?addr=<addr> — returns the whois JSON.
    pub async fn whois(&self, addr: &str) -> Result<serde_json::Value, LocalClientError> {
        let path = format!("/localapi/v0/whois?addr={}", url_encode(addr));
        let body = self.get_json(&path).await?;
        Ok(body)
    }

    /// GET /localapi/v0/prefs — returns the prefs JSON.
    pub async fn prefs(&self) -> Result<serde_json::Value, LocalClientError> {
        self.get_json("/localapi/v0/prefs").await
    }

    /// GET /localapi/v0/netmap — returns the netmap JSON (including DERPMap).
    pub async fn netmap(&self) -> Result<serde_json::Value, LocalClientError> {
        self.get_json("/localapi/v0/netmap").await
    }

    /// GET /localapi/v0/metrics — returns raw Prometheus text.
    pub async fn metrics(&self) -> Result<String, LocalClientError> {
        let body = self.get_raw("/localapi/v0/metrics").await?;
        Ok(body)
    }

    /// GET /localapi/v0/health — returns the health JSON array.
    pub async fn health(&self) -> Result<serde_json::Value, LocalClientError> {
        self.get_json("/localapi/v0/health").await
    }

    /// POST /localapi/v0/ping?ip=<ip>&type=<ping_type> — returns the ping
    /// result JSON. The daemon currently returns 501; this surfaces the error.
    pub async fn ping(
        &self,
        ip: &str,
        ping_type: &str,
    ) -> Result<serde_json::Value, LocalClientError> {
        let path = format!(
            "/localapi/v0/ping?ip={}&type={}",
            url_encode(ip),
            url_encode(ping_type)
        );
        // The ping endpoint uses POST.
        let (_status, body) = self.send_request("POST", &path, &[]).await?;
        // ping returns 501 which maps to HttpStatus error; but if it succeeds,
        // parse the JSON.
        let json: serde_json::Value =
            serde_json::from_slice(&body).map_err(|e| LocalClientError::Json(e.to_string()))?;
        Ok(json)
    }

    /// GET /localapi/v0/netmap, extracting just the DERPMap. Convenience
    /// wrapper for the `netcheck` subcommand.
    pub async fn derp_map(&self) -> Result<DERPMap, LocalClientError> {
        let netmap = self.netmap().await?;
        if let Some(derp) = netmap.get("DERPMap") {
            if !derp.is_null() {
                return serde_json::from_value(derp.clone())
                    .map_err(|e| LocalClientError::Json(e.to_string()));
            }
        }
        Ok(DERPMap::default())
    }

    /// GET /localapi/v0/watch-ipn-bus?mask=<mask> — returns a streaming
    /// reader that yields newline-delimited JSON [`Notify`] messages.
    ///
    /// The connection is long-lived; the caller reads messages until EOF
    /// (daemon shutdown) or drops the [`WatchIpnBus`].
    pub async fn watch_ipn_bus(
        &self,
        mask: NotifyWatchOpt,
    ) -> Result<WatchIpnBus, LocalClientError> {
        let path = format!("/localapi/v0/watch-ipn-bus?mask={mask}");
        let stream = self.connect_and_send("GET", &path).await?;
        Ok(WatchIpnBus::new(stream))
    }

    /// POST /localapi/v0/start — applies prefs and triggers bootstrap.
    pub async fn start(&self, options: &StartOptions) -> Result<(), LocalClientError> {
        let body =
            serde_json::to_vec(options).map_err(|e| LocalClientError::Json(e.to_string()))?;
        let (_status, _) = self
            .send_request_with_body("POST", "/localapi/v0/start", &body)
            .await?;
        Ok(())
    }

    /// POST /localapi/v0/login-interactive — triggers interactive login.
    pub async fn login_interactive(&self) -> Result<(), LocalClientError> {
        let (_status, _) = self
            .send_request_with_body("POST", "/localapi/v0/login-interactive", &[])
            .await?;
        Ok(())
    }

    /// POST /localapi/v0/logout — logs out and disconnects.
    pub async fn logout(&self) -> Result<(), LocalClientError> {
        let (_status, _) = self
            .send_request_with_body("POST", "/localapi/v0/logout", &[])
            .await?;
        Ok(())
    }

    /// PATCH /localapi/v0/prefs — applies masked prefs and returns the
    /// updated prefs JSON.
    pub async fn edit_prefs(
        &self,
        masked: &MaskedPrefs,
    ) -> Result<serde_json::Value, LocalClientError> {
        let body = serde_json::to_vec(masked).map_err(|e| LocalClientError::Json(e.to_string()))?;
        let (_status, resp_body) = self
            .send_request_with_body("PATCH", "/localapi/v0/prefs", &body)
            .await?;
        let json: serde_json::Value = serde_json::from_slice(&resp_body)
            .map_err(|e| LocalClientError::Json(e.to_string()))?;
        Ok(json)
    }

    /// GET /localapi/v0/prefs — returns typed prefs.
    pub async fn get_prefs(&self) -> Result<Prefs, LocalClientError> {
        let (_status, body) = self.send_request("GET", "/localapi/v0/prefs", &[]).await?;
        let prefs: Prefs =
            serde_json::from_slice(&body).map_err(|e| LocalClientError::Json(e.to_string()))?;
        Ok(prefs)
    }

    // -----------------------------------------------------------------------
    // Internal HTTP plumbing
    // -----------------------------------------------------------------------

    /// Send an HTTP request with a body, read the full response, check the
    /// status code, and return (status_code, body_bytes).
    async fn send_request_with_body(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<(u16, Vec<u8>), LocalClientError> {
        let std_conn = rustscale_safesocket::connect(&self.socket_path)
            .map_err(|e| LocalClientError::Connect(e.to_string()))?;
        let _ = std_conn.set_nonblocking(true);
        let mut stream =
            UnixStream::from_std(std_conn).map_err(|e| LocalClientError::Connect(e.to_string()))?;

        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {LOCAL_API_HOST}\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(request.as_bytes()).await?;
        if !body.is_empty() {
            stream.write_all(body).await?;
        }
        stream.flush().await?;

        let response = read_full_response(&mut stream).await?;
        drop(stream);

        check_status(response.status, &response.body)?;
        Ok((response.status, response.body))
    }

    /// Send a GET request and return the response body as a JSON value.
    /// Maps non-200 status codes to typed errors.
    async fn get_json(&self, path: &str) -> Result<serde_json::Value, LocalClientError> {
        let (_, body) = self.send_request("GET", path, &[]).await?;
        let json: serde_json::Value =
            serde_json::from_slice(&body).map_err(|e| LocalClientError::Json(e.to_string()))?;
        Ok(json)
    }

    /// Send a GET request and return the response body as a string.
    async fn get_raw(&self, path: &str) -> Result<String, LocalClientError> {
        let (_status, body) = self.send_request("GET", path, &[]).await?;
        Ok(String::from_utf8_lossy(&body).into_owned())
    }

    /// Send an HTTP request, read the full response, check the status code,
    /// and return (status_code, body_bytes).
    async fn send_request(
        &self,
        method: &str,
        path: &str,
        _body: &[u8],
    ) -> Result<(u16, Vec<u8>), LocalClientError> {
        let mut stream = self.connect_and_send(method, path).await?;

        // Read the full response (headers + body). The daemon sends
        // Connection: close + Content-Length, so we read until we have the
        // full body.
        let response = read_full_response(&mut stream).await?;
        drop(stream);

        check_status(response.status, &response.body)?;
        Ok((response.status, response.body))
    }

    /// Connect to the socket, send the HTTP request line + headers, and
    /// return the stream for further reading. Used by both the one-shot
    /// methods and the streaming watch-ipn-bus.
    async fn connect_and_send(
        &self,
        method: &str,
        path: &str,
    ) -> Result<UnixStream, LocalClientError> {
        let std_conn = rustscale_safesocket::connect(&self.socket_path)
            .map_err(|e| LocalClientError::Connect(e.to_string()))?;
        let _ = std_conn.set_nonblocking(true);
        let mut stream =
            UnixStream::from_std(std_conn).map_err(|e| LocalClientError::Connect(e.to_string()))?;

        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {LOCAL_API_HOST}\r\n\
             Content-Length: 0\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;
        Ok(stream)
    }
}

// ---------------------------------------------------------------------------
// Response parsing
// ---------------------------------------------------------------------------

struct RawResponse {
    status: u16,
    body: Vec<u8>,
}

/// Read a complete HTTP/1.1 response from the stream. Parses the status line
/// and headers, then reads the body based on Content-Length (or until EOF for
/// streaming responses with Connection: close and no Content-Length).
async fn read_full_response(stream: &mut UnixStream) -> Result<RawResponse, LocalClientError> {
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];

    // Read until we find the end of headers.
    let header_end_pos;
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            return Err(LocalClientError::Io(
                "connection closed before headers".into(),
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_header_end(&buf) {
            header_end_pos = pos;
            break;
        }
        if buf.len() > 256 * 1024 {
            return Err(LocalClientError::Io("header too large".into()));
        }
    }

    let header_bytes = &buf[..header_end_pos];
    let header_text = std::str::from_utf8(header_bytes)
        .map_err(|_| LocalClientError::Io("non-utf8 header".into()))?;

    let mut lines = header_text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| LocalClientError::Io("no status line".into()))?;
    let mut parts = status_line.split_whitespace();
    let _version = parts.next();
    let status: u16 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);

    // Parse headers.
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

    // Read the body.
    let body_start = header_end_pos + 4;
    let body = if let Some(cl) = content_length {
        // Read exactly cl bytes.
        let mut body = buf[body_start..].to_vec();
        while body.len() < cl {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&tmp[..n]);
        }
        body.truncate(cl);
        body
    } else {
        // No Content-Length: read until EOF (streaming / connection-close).
        let mut body = buf[body_start..].to_vec();
        loop {
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&tmp[..n]);
        }
        body
    };

    Ok(RawResponse { status, body })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Map an HTTP status code to a typed error if it's not 200.
fn check_status(status: u16, body: &[u8]) -> Result<(), LocalClientError> {
    if status == 200 || (200..300).contains(&status) {
        return Ok(());
    }
    let msg = extract_error_message(body);
    match status {
        403 => Err(LocalClientError::AccessDenied(msg)),
        412 => Err(LocalClientError::PreconditionsFailed(msg)),
        _ => Err(LocalClientError::HttpStatus {
            status,
            message: msg,
        }),
    }
}

/// Try to extract an error message from a JSON body `{"error": "..."}`,
/// falling back to the raw body text.
fn extract_error_message(body: &[u8]) -> String {
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) {
        if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
            return err.to_string();
        }
    }
    String::from_utf8_lossy(body).trim().to_string()
}

/// Minimal URL-encoding for query parameter values (encodes characters that
/// are not safe in a query string).
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                use std::fmt::Write;
                out.push('%');
                let _ = write!(out, "{b:02X}");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_url_encode() {
        assert_eq!(url_encode("100.64.0.1"), "100.64.0.1");
        assert_eq!(url_encode("100.64.0.1:443"), "100.64.0.1%3A443");
        assert_eq!(url_encode("hello world"), "hello%20world");
    }

    #[test]
    fn test_find_header_end() {
        assert_eq!(find_header_end(b"HTTP/1.1 200 OK\r\n\r\nbody"), Some(15));
        assert_eq!(find_header_end(b"no headers here"), None);
    }

    #[test]
    fn test_extract_error_message_json() {
        let body = br#"{"error": "missing 'addr' parameter"}"#;
        assert_eq!(extract_error_message(body), "missing 'addr' parameter");
    }

    #[test]
    fn test_extract_error_message_plain() {
        let body = b"not found";
        assert_eq!(extract_error_message(body), "not found");
    }

    #[test]
    fn test_check_status_ok() {
        assert!(check_status(200, b"").is_ok());
        assert!(check_status(204, b"").is_ok());
    }

    #[test]
    fn test_check_status_403() {
        let err = check_status(403, br#"{"error": "denied"}"#).unwrap_err();
        assert!(matches!(err, LocalClientError::AccessDenied(_)));
    }

    #[test]
    fn test_check_status_412() {
        let err = check_status(412, br#"{"error": "precondition"}"#).unwrap_err();
        assert!(matches!(err, LocalClientError::PreconditionsFailed(_)));
    }

    #[test]
    fn test_check_status_501() {
        let err = check_status(501, br#"{"error": "not implemented"}"#).unwrap_err();
        assert!(matches!(
            err,
            LocalClientError::HttpStatus { status: 501, .. }
        ));
    }

    #[test]
    fn test_local_client_construction() {
        let lc = LocalClient::new("/tmp/test.sock");
        assert_eq!(lc.socket_path(), std::path::Path::new("/tmp/test.sock"));
    }
}
