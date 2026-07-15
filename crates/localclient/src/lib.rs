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
pub use stream::{DebugCapture, WatchIpnBus};

use std::path::PathBuf;

use rustscale_ipn::{LoginProfile, MaskedPrefs, NotifyWatchOpt, Prefs, StartOptions, WaitingFile};
use rustscale_ipnstate::PingResult;
use rustscale_tailcfg::{DERPMap, TokenResponse};
use rustscale_tsnet::{FileTarget, ServeConfig};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use rustscale_safesocket::Connection;

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

    /// GET /localapi/v0/id-token?aud=<audience> — request an OIDC ID token.
    pub async fn id_token(&self, audience: &str) -> Result<TokenResponse, LocalClientError> {
        let path = format!("/localapi/v0/id-token?aud={}", url_encode(audience));
        let body = self.get_json(&path).await?;
        serde_json::from_value(body).map_err(|e| LocalClientError::Json(e.to_string()))
    }

    /// GET /localapi/v0/netmap — returns the netmap JSON (including DERPMap).
    pub async fn netmap(&self) -> Result<serde_json::Value, LocalClientError> {
        self.get_json("/localapi/v0/netmap").await
    }

    /// GET /localapi/v0/metrics — returns raw Prometheus text.
    pub async fn metrics(&self) -> Result<String, LocalClientError> {
        let body = self.get_raw_str("/localapi/v0/metrics").await?;
        Ok(body)
    }

    /// GET /localapi/v0/health — returns the health JSON array.
    pub async fn health(&self) -> Result<serde_json::Value, LocalClientError> {
        self.get_json("/localapi/v0/health").await
    }

    /// POST /localapi/v0/ping?ip=<ip>&type=<ping_type>&size=<size> — returns
    /// a typed [`PingResult`] with latency, endpoint, and path info.
    pub async fn ping(
        &self,
        ip: &str,
        ping_type: &str,
        size: usize,
    ) -> Result<PingResult, LocalClientError> {
        let path = format!(
            "/localapi/v0/ping?ip={}&type={}&size={}",
            url_encode(ip),
            url_encode(ping_type),
            size,
        );
        let (_status, body) = self.send_request("POST", &path, &[]).await?;
        let result: PingResult =
            serde_json::from_slice(&body).map_err(|e| LocalClientError::Json(e.to_string()))?;
        Ok(result)
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

    /// POST /localapi/v0/debug-capture — returns a long-lived raw pcap stream.
    pub async fn debug_capture(&self) -> Result<DebugCapture, LocalClientError> {
        let stream = self
            .connect_and_send("POST", "/localapi/v0/debug-capture")
            .await?;
        Ok(DebugCapture::new(stream))
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
    // Serve config API
    // -----------------------------------------------------------------------

    /// GET /localapi/v0/serve-config — returns the current serve config
    /// and its ETag. If no config is set, returns an empty ServeConfig.
    pub async fn get_serve_config(&self) -> Result<(ServeConfig, String), LocalClientError> {
        let raw_resp = self
            .send_request_raw("GET", "/localapi/v0/serve-config", &[], &[])
            .await?;
        let cfg: ServeConfig = serde_json::from_slice(&raw_resp.body)
            .map_err(|e| LocalClientError::Json(e.to_string()))?;
        Ok((cfg, raw_resp.etag))
    }

    /// POST /localapi/v0/serve-config — sets the serve config. If `etag`
    /// is non-empty, sends it as the If-Match header for optimistic
    /// concurrency control. Returns `PreconditionsFailed` on 412.
    pub async fn set_serve_config(
        &self,
        config: &ServeConfig,
        etag: &str,
    ) -> Result<(), LocalClientError> {
        let body = serde_json::to_vec(config).map_err(|e| LocalClientError::Json(e.to_string()))?;
        let extra_headers = if etag.is_empty() {
            vec![]
        } else {
            vec![("If-Match".to_string(), format!("\"{etag}\""))]
        };
        let (_status, _) = self
            .send_request_with_headers("POST", "/localapi/v0/serve-config", &body, &extra_headers)
            .await?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Profiles API
    // -----------------------------------------------------------------------

    /// GET /localapi/v0/profiles — returns all login profiles.
    pub async fn list_profiles(&self) -> Result<Vec<LoginProfile>, LocalClientError> {
        let (_status, body) = self
            .send_request("GET", "/localapi/v0/profiles", &[])
            .await?;
        let profiles: Vec<LoginProfile> =
            serde_json::from_slice(&body).map_err(|e| LocalClientError::Json(e.to_string()))?;
        Ok(profiles)
    }

    /// GET /localapi/v0/profiles/current — returns the current profile.
    pub async fn current_profile(&self) -> Result<LoginProfile, LocalClientError> {
        let (_status, body) = self
            .send_request("GET", "/localapi/v0/profiles/current", &[])
            .await?;
        let profile: LoginProfile =
            serde_json::from_slice(&body).map_err(|e| LocalClientError::Json(e.to_string()))?;
        Ok(profile)
    }

    /// PUT /localapi/v0/profiles — creates a new empty profile and
    /// switches to it.
    pub async fn new_profile(&self) -> Result<(), LocalClientError> {
        let (_status, _) = self
            .send_request_with_body("PUT", "/localapi/v0/profiles", &[])
            .await?;
        Ok(())
    }

    /// POST /localapi/v0/profiles/<id> — switches to the given profile.
    pub async fn switch_profile(&self, profile_id: &str) -> Result<(), LocalClientError> {
        let path = format!("/localapi/v0/profiles/{}", url_encode(profile_id));
        let (_status, _) = self.send_request_with_body("POST", &path, &[]).await?;
        Ok(())
    }

    /// DELETE /localapi/v0/profiles/<id> — deletes the given profile.
    pub async fn delete_profile(&self, profile_id: &str) -> Result<(), LocalClientError> {
        let path = format!("/localapi/v0/profiles/{}", url_encode(profile_id));
        let (_status, _) = self.send_request_with_body("DELETE", &path, &[]).await?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Cert API
    // -----------------------------------------------------------------------

    /// `GET /localapi/v0/cert/<domain>?type=pair&min_validity=<dur>` — returns
    /// the raw response body (key PEM then cert PEM, concatenated). This is
    /// the low-level method behind [`cert_pair`](Self::cert_pair).
    pub async fn cert_raw(
        &self,
        domain: &str,
        typ: &str,
        min_validity: &str,
    ) -> Result<Vec<u8>, LocalClientError> {
        let path = format!(
            "/localapi/v0/cert/{}?type={}&min_validity={}",
            url_encode(domain),
            url_encode(typ),
            url_encode(min_validity),
        );
        let (_status, body) = self.send_request("GET", &path, &[]).await?;
        Ok(body)
    }

    /// Fetch a cert+key pair for `domain`. Returns `(cert_pem, key_pem)` —
    /// the PEM-encoded cert chain and private key, split from the `type=pair`
    /// response (key first, then cert, matching Go's wire format).
    ///
    /// `min_validity_secs` of 0 means "just don't be expired".
    pub async fn cert_pair(
        &self,
        domain: &str,
        min_validity_secs: u64,
    ) -> Result<(Vec<u8>, Vec<u8>), LocalClientError> {
        let mv = if min_validity_secs == 0 {
            String::from("0")
        } else {
            format!("{}s", min_validity_secs)
        };
        let body = self.cert_raw(domain, "pair", &mv).await?;
        split_pair_pem(&body).ok_or_else(|| {
            LocalClientError::Io("unexpected cert pair: no key/cert delimiter".into())
        })
    }

    /// Fetch the cert PEM only for `domain` (`type=cert`).
    pub async fn cert(
        &self,
        domain: &str,
        min_validity_secs: u64,
    ) -> Result<Vec<u8>, LocalClientError> {
        let mv = if min_validity_secs == 0 {
            String::from("0")
        } else {
            format!("{}s", min_validity_secs)
        };
        self.cert_raw(domain, "cert", &mv).await
    }

    /// Fetch the private key PEM only for `domain` (`type=key`).
    pub async fn cert_key(
        &self,
        domain: &str,
        min_validity_secs: u64,
    ) -> Result<Vec<u8>, LocalClientError> {
        let mv = if min_validity_secs == 0 {
            String::from("0")
        } else {
            format!("{}s", min_validity_secs)
        };
        self.cert_raw(domain, "key", &mv).await
    }

    // -----------------------------------------------------------------------
    // Taildrop file API
    // -----------------------------------------------------------------------

    /// GET /localapi/v0/file-targets — list peers that can receive files.
    pub async fn file_targets(&self) -> Result<Vec<FileTarget>, LocalClientError> {
        let (_status, body) = self
            .send_request("GET", "/localapi/v0/file-targets", &[])
            .await?;
        let targets: Vec<FileTarget> =
            serde_json::from_slice(&body).map_err(|e| LocalClientError::Json(e.to_string()))?;
        Ok(targets)
    }

    /// GET /localapi/v0/files/ — list waiting files in the inbox.
    pub async fn waiting_files(&self) -> Result<Vec<WaitingFile>, LocalClientError> {
        let (_status, body) = self.send_request("GET", "/localapi/v0/files/", &[]).await?;
        let files: Vec<WaitingFile> =
            serde_json::from_slice(&body).map_err(|e| LocalClientError::Json(e.to_string()))?;
        Ok(files)
    }

    /// GET /localapi/v0/files/<name> — download a file from the inbox.
    /// Returns `(bytes, size)`.
    pub async fn get_waiting_file(&self, name: &str) -> Result<(Vec<u8>, i64), LocalClientError> {
        let path = format!("/localapi/v0/files/{}", url_encode(name));
        let (_status, body) = self.send_request("GET", &path, &[]).await?;
        let size = body.len() as i64;
        Ok((body, size))
    }

    /// DELETE /localapi/v0/files/<name> — delete a file from the inbox.
    pub async fn delete_waiting_file(&self, name: &str) -> Result<(), LocalClientError> {
        let path = format!("/localapi/v0/files/{}", url_encode(name));
        let (_status, _) = self.send_request_with_body("DELETE", &path, &[]).await?;
        Ok(())
    }

    /// PUT /localapi/v0/file-put/<stableID>/<filename> — upload a file to a
    /// peer via the daemon (which dials the peer's PeerAPI). The daemon
    /// proxies the upload through the tailnet.
    pub async fn push_file(
        &self,
        stable_id: &str,
        filename: &str,
        body: &[u8],
    ) -> Result<(), LocalClientError> {
        let path = format!(
            "/localapi/v0/file-put/{}/{}",
            url_encode(stable_id),
            url_encode(filename)
        );
        let (_status, _) = self.send_request_with_body("PUT", &path, body).await?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Debug / dial / DNS / IP forwarding API
    // -----------------------------------------------------------------------

    /// GET /localapi/v0/debug?action=<method> — generic debug endpoint
    /// caller. Returns the raw JSON response from the debug sub-command.
    pub async fn debug(&self, method: &str) -> Result<serde_json::Value, LocalClientError> {
        let path = format!("/localapi/v0/debug?action={}", url_encode(method));
        self.get_json(&path).await
    }

    /// POST /localapi/v0/dial?addr=<host:port> — dial a remote address via
    /// the daemon's netstack. Returns JSON with `ok`, `addr`, and either
    /// `resolved`+`via` on success or `error` on failure.
    pub async fn dial(&self, addr: &str) -> Result<serde_json::Value, LocalClientError> {
        let path = format!("/localapi/v0/dial?addr={}", url_encode(addr));
        let (_status, body) = self.send_request("POST", &path, &[]).await?;
        let json: serde_json::Value =
            serde_json::from_slice(&body).map_err(|e| LocalClientError::Json(e.to_string()))?;
        Ok(json)
    }

    /// POST /localapi/v0/dial with `Upgrade: ts-dial`, returning the raw
    /// LocalAPI connection after the daemon has connected it to `host:port`
    /// through the tailnet.
    pub async fn dial_tcp_stream(
        &self,
        host: &str,
        port: u16,
    ) -> Result<Connection, LocalClientError> {
        if host.is_empty() || host.contains(['\r', '\n']) {
            return Err(LocalClientError::Io("invalid dial host".into()));
        }

        let mut stream = rustscale_safesocket::connect(&self.socket_path)
            .map_err(|e| LocalClientError::Connect(e.to_string()))?;
        let request = format!(
            "POST /localapi/v0/dial HTTP/1.1\r\nHost: {LOCAL_API_HOST}\r\n\
             Upgrade: ts-dial\r\nConnection: upgrade\r\nDial-Host: {host}\r\n\
             Dial-Port: {port}\r\nDial-Network: tcp\r\nContent-Length: 0\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await?;
        stream.flush().await?;

        let header = read_upgrade_response_header(&mut stream).await?;
        let header_text = std::str::from_utf8(&header)
            .map_err(|_| LocalClientError::Io("non-utf8 response header".into()))?;
        let mut lines = header_text.split("\r\n");
        let status_line = lines
            .next()
            .ok_or_else(|| LocalClientError::Io("missing response status".into()))?;
        let status = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(0);
        let upgraded = lines
            .filter_map(|line| line.split_once(':'))
            .any(|(name, value)| {
                name.trim().eq_ignore_ascii_case("upgrade")
                    && value.trim().eq_ignore_ascii_case("ts-dial")
            });
        if status != 101 || !upgraded {
            return Err(LocalClientError::HttpStatus {
                status,
                message: format!("unexpected dial upgrade response: {status_line}"),
            });
        }
        Ok(stream)
    }

    /// GET /localapi/v0/dns-query?name=<name>&type=<type> — query the
    /// daemon's DNS resolver. Returns JSON with `name`, `type`, `results`,
    /// and `magicdns_enabled`.
    pub async fn dns_query(
        &self,
        name: &str,
        qtype: &str,
    ) -> Result<serde_json::Value, LocalClientError> {
        let path = format!(
            "/localapi/v0/dns-query?name={}&type={}",
            url_encode(name),
            url_encode(qtype)
        );
        self.get_json(&path).await
    }

    /// GET /localapi/v0/check-ip-forwarding — check if IP forwarding is
    /// enabled on the daemon's host. Returns JSON with `ipv4_forwarding`,
    /// `ipv6_forwarding`, and `platform`.
    pub async fn check_ip_forwarding(&self) -> Result<serde_json::Value, LocalClientError> {
        self.get_json("/localapi/v0/check-ip-forwarding").await
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
        self.send_request_with_headers(method, path, body, &[])
            .await
    }

    /// Send an HTTP request with a body and extra headers, read the full
    /// response, check the status code, and return (status_code, body_bytes).
    async fn send_request_with_headers(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        extra_headers: &[(String, String)],
    ) -> Result<(u16, Vec<u8>), LocalClientError> {
        let raw = self
            .send_request_raw(method, path, body, extra_headers)
            .await?;
        Ok((raw.status, raw.body))
    }

    /// Send an HTTP request with a body and extra headers, read the full
    /// response (including parsed ETag header), without checking the status
    /// code (the caller handles status checking).
    async fn send_request_raw(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        extra_headers: &[(String, String)],
    ) -> Result<RawResponseWithHeaders, LocalClientError> {
        let mut stream = rustscale_safesocket::connect(&self.socket_path)
            .map_err(|e| LocalClientError::Connect(e.to_string()))?;

        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {LOCAL_API_HOST}\r\n\
             Content-Length: {}\r\nConnection: close\r\n",
            body.len()
        );
        for (k, v) in extra_headers {
            use std::fmt::Write;
            let _ = write!(request, "{k}: {v}\r\n");
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await?;
        if !body.is_empty() {
            stream.write_all(body).await?;
        }
        stream.flush().await?;

        let response = read_full_response_with_headers(&mut stream).await?;
        drop(stream);

        check_status(response.status, &response.body)?;
        Ok(response)
    }

    /// Send an HTTP request, read the full response, check the status code,
    /// and return (status_code, body_bytes).
    async fn send_request(
        &self,
        method: &str,
        path: &str,
        _body: &[u8],
    ) -> Result<(u16, Vec<u8>), LocalClientError> {
        let raw = self.send_request_raw(method, path, &[], &[]).await?;
        Ok((raw.status, raw.body))
    }

    /// Send a GET request and return the response body as a JSON value.
    async fn get_json(&self, path: &str) -> Result<serde_json::Value, LocalClientError> {
        let (_, body) = self.send_request("GET", path, &[]).await?;
        let json: serde_json::Value =
            serde_json::from_slice(&body).map_err(|e| LocalClientError::Json(e.to_string()))?;
        Ok(json)
    }

    /// Send a GET request and return the response body as a string.
    async fn get_raw_str(&self, path: &str) -> Result<String, LocalClientError> {
        let (_status, body) = self.send_request("GET", path, &[]).await?;
        Ok(String::from_utf8_lossy(&body).into_owned())
    }

    /// Connect to the socket, send the HTTP request line + headers, and
    /// return the stream for further reading. Used by both the one-shot
    /// methods and the streaming watch-ipn-bus.
    async fn connect_and_send(
        &self,
        method: &str,
        path: &str,
    ) -> Result<Connection, LocalClientError> {
        let mut stream = rustscale_safesocket::connect(&self.socket_path)
            .map_err(|e| LocalClientError::Connect(e.to_string()))?;

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

/// Response with parsed ETag header (used by serve-config endpoint).
struct RawResponseWithHeaders {
    status: u16,
    body: Vec<u8>,
    etag: String,
}

/// Read a complete HTTP/1.1 response including the ETag header.
async fn read_full_response_with_headers(
    stream: &mut Connection,
) -> Result<RawResponseWithHeaders, LocalClientError> {
    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];

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

    let mut content_length: Option<usize> = None;
    let mut etag = String::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().ok();
            } else if k.trim().eq_ignore_ascii_case("etag") {
                etag = v.trim().trim_matches('"').to_string();
            }
        }
    }

    let body_start = header_end_pos + 4;
    let body = if let Some(cl) = content_length {
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

    Ok(RawResponseWithHeaders { status, body, etag })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Read an upgrade response one byte at a time so no raw proxied bytes are
/// consumed along with the HTTP headers. After this returns, `stream` starts
/// exactly at the dialed TCP stream.
async fn read_upgrade_response_header(
    stream: &mut (impl AsyncRead + Unpin),
) -> Result<Vec<u8>, LocalClientError> {
    let mut header = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while !header.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await?;
        header.push(byte[0]);
        if header.len() > 256 * 1024 {
            return Err(LocalClientError::Io("header too large".into()));
        }
    }
    Ok(header)
}

/// Split a `type=pair` PEM blob into `(cert_pem, key_pem)`. The wire format
/// (matching Go's `serveKeyPair`) is key PEM first, then cert PEM. We split
/// at the boundary between the first PEM block end and the second begin.
fn split_pair_pem(pair: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    // Find the end of the first PEM block (key).
    let end_marker = b"-----END PRIVATE KEY-----";
    let end_pos = pair
        .windows(end_marker.len())
        .position(|w| w == end_marker)?;
    let after_end = end_pos + end_marker.len();
    // Skip trailing whitespace (newline) after the key block.
    let rest = &pair[after_end..];
    let cert_start_offset = rest.iter().position(|b| !b.is_ascii_whitespace())?;
    let cert_start = after_end + cert_start_offset;
    let key_pem = pair[..cert_start].to_vec();
    let cert_pem = pair[cert_start..].to_vec();
    // Sanity: the second block should be a cert, not another key.
    let needle = b"PRIVATE KEY-----";
    if cert_pem.windows(needle.len()).any(|w| w == needle) {
        return None;
    }
    Some((cert_pem, key_pem))
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

    #[tokio::test]
    async fn upgrade_header_reader_does_not_consume_proxied_bytes() {
        let (mut reader, mut writer) = tokio::io::duplex(1024);
        let server = tokio::spawn(async move {
            writer
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: ts-dial\r\n\r\nhello")
                .await
                .unwrap();
        });

        let header = read_upgrade_response_header(&mut reader).await.unwrap();
        assert_eq!(
            header,
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: ts-dial\r\n\r\n"
        );
        let mut proxied = [0u8; 5];
        reader.read_exact(&mut proxied).await.unwrap();
        assert_eq!(&proxied, b"hello");
        server.await.unwrap();
    }

    #[test]
    fn test_split_pair_pem() {
        let key = b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
        let cert = b"-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n";
        let mut pair = Vec::new();
        pair.extend_from_slice(key);
        pair.extend_from_slice(cert);
        let (c, k) = split_pair_pem(&pair).expect("split");
        assert_eq!(k, key);
        assert_eq!(c, cert);
    }

    #[test]
    fn test_split_pair_pem_rejects_key_in_cert() {
        let key1 = b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
        let key2 = b"-----BEGIN PRIVATE KEY-----\nBBBB\n-----END PRIVATE KEY-----\n";
        let mut pair = Vec::new();
        pair.extend_from_slice(key1);
        pair.extend_from_slice(key2);
        assert!(split_pair_pem(&pair).is_none());
    }

    #[test]
    fn test_split_pair_pem_missing_end_returns_none() {
        assert!(split_pair_pem(b"not pem at all").is_none());
    }
}
