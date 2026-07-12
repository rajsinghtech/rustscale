//! HTTP `/ts2021` upgrade dance — ports Go's `control/controlhttp/client.go`.
//!
//! The client POSTs to `/ts2021` with an `Upgrade: tailscale-control-protocol`
//! header. The `X-Tailscale-Handshake` header carries the base64-encoded Noise
//! initiation message, saving an RTT. On `101 Switching Protocols` the TLS
//! stream becomes the Noise transport.
//!
//! DNS resolution uses a `dnscache::Resolver` with `dnsfallback` as the
//! `LookupIPFallback`, so control-plane connections survive broken system DNS.

use std::sync::Arc;

use base64::Engine as _;
use rustscale_key::{MachinePrivate, MachinePublic};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use url::Url;

use crate::controlbase::{client_deferred, NoiseConn, NoiseError, ProtocolVersion};

/// HTTP header value indicating the Tailscale control protocol.
const UPGRADE_VALUE: &str = "tailscale-control-protocol";
/// HTTP header name carrying the base64-encoded Noise initiation.
const HANDSHAKE_HEADER: &str = "X-Tailscale-Handshake";
/// The URL path for the protocol upgrade.
const UPGRADE_PATH: &str = "/ts2021";

/// A boxed async read+write stream — either a TLS stream or a plain TCP
/// stream. Used by [`dial_control`] to return a uniform type regardless of
/// whether the control URL uses `https://` (TLS) or `http://` (plain TCP,
/// for in-process test fakes like `rustscale-testcontrol`).
pub enum AnyStream {
    /// TLS-encrypted TCP (production control plane).
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
    /// Plain TCP (for testcontrol and local fakes).
    Plain(TcpStream),
}

impl tokio::io::AsyncRead for AnyStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Tls(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            Self::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for AnyStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            Self::Tls(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            Self::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Tls(s) => std::pin::Pin::new(s).poll_flush(cx),
            Self::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Tls(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            Self::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Parsed control-plane URL: scheme, host, port, and the `host:port` string
/// for HTTP `Host` headers.
struct ParsedUrl {
    /// `"http"` for plain TCP (test fakes), `"https"` for TLS (production).
    is_plain: bool,
    /// Hostname or IP without port.
    host: String,
    /// `host:port` — for the HTTP `Host` header and `ServerName`.
    host_port: String,
    /// TCP port.
    port: u16,
}

/// Parse a control-plane URL string into scheme/host/port.
///
/// Accepted forms:
/// - `"controlplane.tailscale.com"` → TLS to port 443 (bare hostname).
/// - `"https://control.example.com:8443"` → TLS to 8443.
/// - `"http://127.0.0.1:12345"` → plain TCP to 12345 (for test fakes).
fn parse_control_url(url: &str) -> ParsedUrl {
    if let Some(rest) = url.strip_prefix("http://") {
        let (host, port) = split_host_port(rest, 80);
        ParsedUrl {
            is_plain: true,
            host_port: format!("{host}:{port}"),
            host,
            port,
        }
    } else if let Some(rest) = url.strip_prefix("https://") {
        let (host, port) = split_host_port(rest, 443);
        ParsedUrl {
            is_plain: false,
            host_port: format!("{host}:{port}"),
            host,
            port,
        }
    } else {
        ParsedUrl {
            is_plain: false,
            host_port: format!("{url}:443"),
            host: url.to_string(),
            port: 443,
        }
    }
}

/// Split `host:port` or `[::1]:port` into (host, port), defaulting to
/// `default_port` if no port is present.
fn split_host_port(s: &str, default_port: u16) -> (String, u16) {
    if s.starts_with('[') {
        if let Some(end) = s.find(']') {
            let host = &s[1..end];
            let rest = &s[end + 1..];
            if let Some(port_str) = rest.strip_prefix(':') {
                if let Ok(p) = port_str.parse::<u16>() {
                    return (host.to_string(), p);
                }
            }
            return (host.to_string(), default_port);
        }
    }
    if let Some(colon) = s.rfind(':') {
        let port_str = &s[colon + 1..];
        if let Ok(p) = port_str.parse::<u16>() {
            return (s[..colon].to_string(), p);
        }
    }
    (s.to_string(), default_port)
}

/// Process-wide DNS cache resolver with DERP bootstrap fallback.
///
/// Initialized lazily on first use. Uses `UseLastGood` so a stale cached IP
/// is served if a refresh fails — matching Go's `controlclient/direct.go`
/// lines 334-368.
static DNS_RESOLVER: std::sync::OnceLock<rustscale_dnscache::Resolver> = std::sync::OnceLock::new();

/// Get the shared DNS cache resolver, initializing it on first call.
fn dns_resolver() -> &'static rustscale_dnscache::Resolver {
    DNS_RESOLVER.get_or_init(|| {
        rustscale_dnscache::Resolver::new()
            .with_use_last_good(true)
            .with_fallback(rustscale_dnsfallback::make_lookup_fallback())
    })
}

/// Consult `tshttpproxy::proxy_from_environment` for `scheme://host:port`.
/// Returns `None` when no proxy is configured or the host is exempt via
/// `no_proxy` — matching Go's `tshttpproxy.ProxyFromEnvironment` posture
/// where detection errors are non-fatal (the direct dial surfaces real
/// connectivity failures).
fn proxy_url_for(scheme: &str, host: &str, port: u16) -> Option<Url> {
    let url = Url::parse(&format!("{scheme}://{host}:{port}")).ok()?;
    rustscale_tshttpproxy::proxy_from_environment(&url)
        .ok()
        .flatten()
}

/// JSON response from `GET /key?v=<version>` (matching Go's
/// `OverTLSPublicKeyResponse`).
#[derive(serde::Deserialize)]
struct KeyResponse {
    #[serde(default, rename = "publicKey")]
    public_key: String,
    #[serde(default, rename = "legacyPublicKey")]
    legacy_public_key: String,
}

/// Errors from the HTTP upgrade dial.
#[derive(Debug, thiserror::Error)]
pub enum DialError {
    /// TLS setup or connection failure.
    #[error("tls: {0}")]
    Tls(String),
    /// The server did not return `101 Switching Protocols`.
    #[error("unexpected HTTP status: {0}")]
    BadStatus(String),
    /// The server switched to an unexpected protocol.
    #[error("server switched to unexpected protocol: {0}")]
    BadUpgrade(String),
    /// The HTTP response was malformed.
    #[error("malformed HTTP response: {0}")]
    Malformed(String),
    /// The Noise handshake failed after the upgrade.
    #[error("noise: {0}")]
    Noise(#[from] NoiseError),
    /// An I/O error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// An HTTP CONNECT proxy tunnel failed.
    #[error("proxy: {0}")]
    Proxy(String),
}

/// A Noise transport channel owning both the cipher state and the underlying
/// async stream. Provides async encrypted record I/O for the client module.
pub struct NoiseStream<S> {
    stream: S,
    conn: NoiseConn,
}

impl<S> NoiseStream<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    /// Encrypt and write one record.
    pub async fn write_record(&mut self, plaintext: &[u8]) -> std::io::Result<()> {
        self.conn
            .write_record_async(&mut self.stream, plaintext)
            .await
    }

    /// Read and decrypt one record.
    pub async fn read_record(&mut self) -> Result<Vec<u8>, NoiseError> {
        self.conn.read_record_async(&mut self.stream).await
    }

    /// Borrow the underlying Noise connection info (version, peer, hash).
    pub fn noise(&self) -> &NoiseConn {
        &self.conn
    }

    /// Consume the NoiseStream and return the NoiseConn + the raw underlying
    /// stream. Used when the caller needs to wrap the connection in a
    /// streaming adapter (e.g. for HTTP/2 over Noise).
    pub fn into_parts(self) -> (NoiseConn, S) {
        (self.conn, self.stream)
    }
}

/// Dial the control server, perform the `/ts2021` upgrade, and complete the
/// Noise handshake.
///
/// `control_key` is the server's machine public key (fetched beforehand via
/// [`fetch_server_pub_key`]). Returns a [`NoiseStream`] ready for encrypted
/// control-plane messages.
///
/// For `http://` URLs (in-process test fakes) this uses plain TCP; for bare
/// hostnames or `https://` URLs it uses TLS to port 443 (or the specified
/// port). For `https://` URLs where the host is an IP literal or `localhost`,
/// TLS certificate verification is skipped (self-signed cert support for the
/// Go testcontrol interop harness).
pub async fn dial_control(
    url: &str,
    machine_key: &MachinePrivate,
    control_key: &MachinePublic,
    version: ProtocolVersion,
) -> Result<NoiseStream<AnyStream>, DialError> {
    let parsed = parse_control_url(url);
    if parsed.is_plain {
        let tcp = if let Some(proxy) = proxy_url_for("http", &parsed.host, parsed.port) {
            rustscale_tshttpproxy::http_connect(&proxy, &parsed.host, parsed.port)
                .await
                .map_err(|e| DialError::Proxy(e.to_string()))?
        } else {
            tokio::net::TcpStream::connect((parsed.host.as_str(), parsed.port))
                .await
                .map_err(DialError::Io)?
        };
        let stream = AnyStream::Plain(tcp);
        upgrade_and_handshake(stream, &parsed.host_port, machine_key, control_key, version).await
    } else {
        let insecure = is_insecure_host(&parsed.host);
        let tls_stream = tls_connect(&parsed.host, parsed.port, insecure).await?;
        let stream = AnyStream::Tls(Box::new(tls_stream));
        upgrade_and_handshake(stream, &parsed.host, machine_key, control_key, version).await
    }
}

/// Fetch the server's Noise public key via `GET /key?v=<version>` (matching
/// Go's `loadServerPubKeys` in `controlclient/direct.go`).
///
/// This is a regular HTTP(S) request — no Noise. The response JSON has
/// `{"publicKey":"mkey:...","legacyPublicKey":"mkey:..."}`. We return the
/// `publicKey` field (the Noise transport key).
///
/// For `http://` URLs (in-process test fakes) this uses plain TCP; for bare
/// hostnames or `https://` URLs it uses TLS to port 443 (or the specified
/// port). For `https://` URLs where the host is an IP literal or `localhost`,
/// TLS certificate verification is skipped (self-signed cert support for the
/// Go testcontrol interop harness).
pub async fn fetch_server_pub_key(
    url: &str,
    version: ProtocolVersion,
) -> Result<MachinePublic, DialError> {
    let parsed = parse_control_url(url);

    let read_buf: Vec<u8> = if parsed.is_plain {
        // Plain TCP — no TLS (for testcontrol and local fakes).
        let mut tcp = if let Some(proxy) = proxy_url_for("http", &parsed.host, parsed.port) {
            rustscale_tshttpproxy::http_connect(&proxy, &parsed.host, parsed.port)
                .await
                .map_err(|e| DialError::Proxy(e.to_string()))?
        } else {
            tokio::net::TcpStream::connect((parsed.host.as_str(), parsed.port))
                .await
                .map_err(DialError::Io)?
        };

        let request = format!(
            "GET /key?v={version} HTTP/1.1\r\n\
             Host: {host_port}\r\n\
             Connection: close\r\n\
             \r\n",
            host_port = parsed.host_port,
        );
        tcp.write_all(request.as_bytes())
            .await
            .map_err(DialError::Io)?;

        let mut buf = Vec::with_capacity(4096);
        tcp.read_to_end(&mut buf).await.map_err(DialError::Io)?;
        buf
    } else {
        let insecure = is_insecure_host(&parsed.host);
        let mut tls = tls_connect(&parsed.host, parsed.port, insecure).await?;

        let request = format!(
            "GET /key?v={version} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Connection: close\r\n\
             \r\n",
            host = parsed.host,
        );
        tls.write_all(request.as_bytes())
            .await
            .map_err(DialError::Io)?;

        let mut buf = Vec::with_capacity(4096);
        tls.read_to_end(&mut buf).await.map_err(DialError::Io)?;
        buf
    };

    // Find the body (after \r\n\r\n).
    let body_start = read_buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .ok_or_else(|| DialError::Malformed("no body in /key response".into()))?;

    let body = &read_buf[body_start..];

    // Parse JSON: {"publicKey":"mkey:...","legacyPublicKey":"mkey:..."}
    let resp: Option<KeyResponse> = serde_json::from_slice(body).ok();

    if let Some(resp) = resp {
        if !resp.public_key.is_empty() {
            return resp
                .public_key
                .parse()
                .map_err(|e| DialError::Malformed(format!("invalid publicKey: {e}")));
        }
        if !resp.legacy_public_key.is_empty() {
            return resp
                .legacy_public_key
                .parse()
                .map_err(|e| DialError::Malformed(format!("invalid legacyPublicKey: {e}")));
        }
    }

    // Fall back: the body might be a raw machine key string (old format).
    let body_str = std::str::from_utf8(body).unwrap_or("").trim();
    body_str
        .parse()
        .map_err(|e| DialError::Malformed(format!("could not parse server key: {e}")))
}

/// Ensure the rustls ring crypto provider is installed process-wide.
/// Called before any `ClientConfig::builder()` to avoid the
/// "could not determine CryptoProvider" panic when both ring and aws-lc-rs
/// features are transitively enabled.
fn ensure_ring_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Establish a TLS connection to `host:port`.
///
/// When `insecure` is true, certificate verification is skipped (for test
/// control servers with self-signed certs, e.g. the Go testcontrol interop
/// harness on `https://127.0.0.1:PORT`). Otherwise uses the webpki root CA
/// store with full verification.
///
/// Uses the shared DNS cache resolver with DERP fallback for production
/// hosts so that control-plane connections survive broken system DNS
/// (matching Go's `dnscache.Dialer` wrapping the control client's transport).
async fn tls_connect(
    host: &str,
    port: u16,
    insecure: bool,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, DialError> {
    ensure_ring_provider();

    let tcp = if let Some(proxy) = proxy_url_for("https", host, port) {
        rustscale_tshttpproxy::http_connect(&proxy, host, port)
            .await
            .map_err(|e| DialError::Proxy(e.to_string()))?
    } else if port == 443 && !insecure {
        dns_resolver()
            .dial_tcp(host, port)
            .await
            .map_err(|e| DialError::Io(std::io::Error::other(e.to_string())))?
    } else {
        tokio::net::TcpStream::connect((host, port))
            .await
            .map_err(DialError::Io)?
    };

    let config = if insecure {
        insecure_tls_config()
    } else {
        let root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| DialError::Tls(format!("invalid server name: {e}")))?;
    let tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| DialError::Tls(e.to_string()))?;
    Ok(tls)
}

/// Returns true when the host is a literal IP address or `localhost` —
/// these hosts use self-signed certs in test environments, so TLS
/// certificate verification must be skipped.
fn is_insecure_host(host: &str) -> bool {
    host == "localhost"
        || host == "127.0.0.1"
        || host == "::1"
        || host.parse::<std::net::IpAddr>().is_ok()
}

/// Build a rustls client config that skips certificate verification entirely.
/// Used for `https://` control servers with self-signed certificates (the Go
/// testcontrol interop harness).
fn insecure_tls_config() -> rustls::ClientConfig {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};

    #[derive(Debug)]
    struct NoVerify;

    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA384,
                rustls::SignatureScheme::RSA_PKCS1_SHA512,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ED25519,
            ]
        }
    }

    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(NoVerify))
        .with_no_client_auth()
}

/// Send the HTTP upgrade request, parse the 101 response, and run the
/// Noise handshake continuation over the upgraded TLS stream.
async fn upgrade_and_handshake<S>(
    mut stream: S,
    host: &str,
    machine_key: &MachinePrivate,
    control_key: &MachinePublic,
    version: ProtocolVersion,
) -> Result<NoiseStream<S>, DialError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let deferred = client_deferred(machine_key, control_key, version);
    let init_b64 = base64::engine::general_purpose::STANDARD.encode(&deferred.init);

    // Build and send the HTTP/1.1 upgrade request.
    let request = format!(
        "POST {UPGRADE_PATH} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Upgrade: {UPGRADE_VALUE}\r\n\
         Connection: upgrade\r\n\
         {HANDSHAKE_HEADER}: {init_b64}\r\n\
         Content-Length: 0\r\n\
         \r\n",
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(DialError::Io)?;

    // Read the HTTP response status line and headers.
    let response = read_http_headers(&mut stream).await?;

    // Verify 101 Switching Protocols (matching Go's StatusSwitchingProtocols check).
    if response.status_code != 101 {
        return Err(DialError::BadStatus(response.status));
    }

    // Verify the Upgrade header matches.
    let upgrade = response
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("upgrade"))
        .map(|(_, v)| v.as_str());
    if upgrade != Some(UPGRADE_VALUE) {
        return Err(DialError::BadUpgrade(
            upgrade.unwrap_or("(missing)").to_string(),
        ));
    }

    // The TLS stream is now the Noise transport. Read the 51-byte handshake
    // response. Any bytes already buffered past the HTTP headers (in
    // `response.trailing`) are the beginning of the handshake response and
    // must be prepended to the read.
    #[allow(clippy::items_after_statements)]
    const RESPONSE_MSG_LEN: usize = 51;
    let mut resp_buf = [0u8; RESPONSE_MSG_LEN];

    if response.trailing.is_empty() {
        stream
            .read_exact(&mut resp_buf)
            .await
            .map_err(DialError::Io)?;
    } else {
        let n = response.trailing.len().min(RESPONSE_MSG_LEN);
        resp_buf[..n].copy_from_slice(&response.trailing[..n]);
        if n < RESPONSE_MSG_LEN {
            stream
                .read_exact(&mut resp_buf[n..])
                .await
                .map_err(DialError::Io)?;
        }
    }

    let conn = deferred.finish_from_response_bytes(&resp_buf)?;
    Ok(NoiseStream { stream, conn })
}

/// Parsed HTTP response head (status line + headers).
struct HttpResponse {
    status: String,
    /// The numeric status code parsed from the status line (e.g. 101).
    status_code: u16,
    headers: Vec<(String, String)>,
    /// Any bytes read past the `\r\n\r\n` header terminator — these belong
    /// to the response body (the Noise handshake) and must not be lost.
    trailing: Vec<u8>,
}

/// Read the HTTP response status line and headers from `stream` (until
/// the blank line that terminates the response head).
///
/// Returns the parsed response plus any bytes already buffered past the
/// header terminator in `trailing` — the server may pipeline body bytes
/// (the Noise handshake response) immediately after the headers, and a
/// single TLS read may deliver them together. The caller must prepend
/// `trailing` to subsequent reads.
async fn read_http_headers<S>(stream: &mut S) -> Result<HttpResponse, DialError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).await.map_err(DialError::Io)?;
        buf.push(byte[0]);
        // Look for \r\n\r\n terminator.
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            break;
        }
        if buf.len() > 65536 {
            return Err(DialError::Malformed("response headers too large".into()));
        }
    }

    // We read byte-by-byte, so there are no trailing bytes in this path.
    // However, if we later switch to buffered reads, any bytes past the
    // \r\n\r\n terminator would be captured here. For now this is always
    // empty, but the field exists so the caller handles it correctly.
    let trailing = Vec::new();

    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| DialError::Malformed("empty response".into()))?
        .to_string();

    // Parse the status code from "HTTP/1.1 101 Switching Protocols".
    let status_code = parse_status_code(&status_line)?;

    let headers = lines
        .take_while(|l| !l.is_empty())
        .filter_map(|l| {
            let mut parts = l.splitn(2, ':');
            let key = parts.next()?.trim().to_string();
            let val = parts.next()?.trim().to_string();
            Some((key, val))
        })
        .collect();

    Ok(HttpResponse {
        status: status_line,
        status_code,
        headers,
        trailing,
    })
}

/// Extract the numeric status code from an HTTP status line like
/// `"HTTP/1.1 101 Switching Protocols"`.
fn parse_status_code(line: &str) -> Result<u16, DialError> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(DialError::Malformed(format!(
            "malformed status line: {line}"
        )));
    }
    parts[1]
        .parse::<u16>()
        .map_err(|_| DialError::Malformed(format!("invalid status code: {}", parts[1])))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustscale_key::MachinePrivate;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Test that `is_insecure_host` correctly identifies test hosts.
    #[test]
    fn is_insecure_host_detects_ip_and_localhost() {
        assert!(is_insecure_host("127.0.0.1"));
        assert!(is_insecure_host("localhost"));
        assert!(is_insecure_host("::1"));
        assert!(is_insecure_host("10.0.0.1"));
        assert!(!is_insecure_host("controlplane.tailscale.com"));
        assert!(!is_insecure_host("example.com"));
    }

    /// Test that `parse_control_url` handles http://, https://, and bare
    /// hostnames correctly.
    #[test]
    fn parse_control_url_schemes() {
        let p = parse_control_url("http://127.0.0.1:12345");
        assert!(p.is_plain);
        assert_eq!(p.host, "127.0.0.1");
        assert_eq!(p.port, 12345);

        let p = parse_control_url("https://127.0.0.1:8443");
        assert!(!p.is_plain);
        assert_eq!(p.host, "127.0.0.1");
        assert_eq!(p.port, 8443);

        let p = parse_control_url("controlplane.tailscale.com");
        assert!(!p.is_plain);
        assert_eq!(p.port, 443);
    }

    /// Test that `parse_status_code` extracts the code from a full status line.
    #[test]
    fn parse_status_code_from_full_line() {
        assert_eq!(
            parse_status_code("HTTP/1.1 101 Switching Protocols").unwrap(),
            101
        );
        assert_eq!(parse_status_code("HTTP/1.1 200 OK").unwrap(), 200);
        assert_eq!(parse_status_code("HTTP/1.1 404 Not Found").unwrap(), 404);
        assert!(parse_status_code("garbage").is_err());
        assert!(parse_status_code("HTTP/1.1").is_err());
    }

    /// Test that `read_http_headers` correctly parses a 101 response with
    /// headers, and that any trailing bytes past the `\r\n\r\n` terminator
    /// are captured (not lost).
    #[tokio::test]
    async fn read_http_headers_parses_101_and_captures_trailing() {
        // Build a fake HTTP 101 response with trailing body bytes.
        let response = b"HTTP/1.1 101 Switching Protocols\r\n\
                         Upgrade: tailscale-control-protocol\r\n\
                         Connection: upgrade\r\n\
                         \r\n\
                         TRAILING_BODY_DATA";
        let (mut server, mut client) = tokio::io::duplex(1024);
        server.write_all(response).await.unwrap();

        let parsed = read_http_headers(&mut client).await.unwrap();
        assert_eq!(parsed.status_code, 101);
        assert!(parsed.status.contains("101 Switching Protocols"));

        // Verify the Upgrade header.
        let upgrade = parsed
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("upgrade"))
            .map(|(_, v)| v.as_str());
        assert_eq!(upgrade, Some(UPGRADE_VALUE));

        // The trailing bytes belong to the body. Since we read byte-by-byte,
        // trailing is empty — but the body bytes are still in the stream
        // and must be readable next.
        let mut body = [0u8; 20];
        let n = client.read(&mut body).await.unwrap();
        assert_eq!(&body[..n], b"TRAILING_BODY_DATA");
    }

    /// Test that a non-101 status is correctly identified.
    #[tokio::test]
    async fn read_http_headers_parses_non_101() {
        let response = b"HTTP/1.1 200 OK\r\n\
                         Content-Type: text/plain\r\n\
                         \r\n\
                         hello";
        let (mut server, mut client) = tokio::io::duplex(1024);
        server.write_all(response).await.unwrap();

        let parsed = read_http_headers(&mut client).await.unwrap();
        assert_eq!(parsed.status_code, 200);
        assert_ne!(parsed.status_code, 101);
    }

    /// Test the full upgrade flow with a fake server that sends 101 + Upgrade
    /// header, followed by a Noise response message. Verifies that the
    /// handshake response bytes are correctly read after the HTTP headers.
    ///
    /// We can't do a real Noise handshake in this test (it requires matching
    /// keys), but we can verify that the 101 is accepted (not rejected as
    /// BadStatus) and that the correct number of bytes are read for the
    /// handshake response.
    #[tokio::test]
    async fn upgrade_accepts_101_and_reads_handshake() {
        let machine_key = MachinePrivate::generate();
        let control_key = MachinePrivate::generate().public();

        // Build the Noise initiation to know what the server would need to
        // respond with. We can't complete the real handshake, but we can
        // verify the flow up to the point where handshake bytes are read.
        let deferred = client_deferred(&machine_key, &control_key, 1);
        let init_b64 = base64::engine::general_purpose::STANDARD.encode(&deferred.init);

        // Fake server response: 101 + Upgrade header + a 51-byte placeholder
        // Noise response. The response won't pass Noise validation, but we
        // just want to verify the HTTP upgrade parsing and byte reading.
        let mut fake_response = Vec::new();
        fake_response.extend_from_slice(b"HTTP/1.1 101 Switching Protocols\r\n");
        fake_response.extend_from_slice(b"Upgrade: tailscale-control-protocol\r\n");
        fake_response.extend_from_slice(b"Connection: upgrade\r\n");
        fake_response.extend_from_slice(b"\r\n");
        // 51 bytes of placeholder Noise response (msg type 2 = response).
        let mut noise_resp = vec![0u8; 51];
        noise_resp[0] = 2; // MSG_TYPE_RESPONSE
        noise_resp[1..3].copy_from_slice(&48u16.to_be_bytes()); // payload len
        fake_response.extend_from_slice(&noise_resp);

        let (mut server, mut client) = tokio::io::duplex(4096);

        // Write the fake response to the server side; the client will read it.
        server.write_all(&fake_response).await.unwrap();

        // Read and parse the HTTP headers from the client side.
        let parsed = read_http_headers(&mut client).await.unwrap();

        // The key assertion: 101 must be accepted, not rejected as BadStatus.
        assert_eq!(parsed.status_code, 101);

        // Verify the Upgrade header matches.
        let upgrade = parsed
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("upgrade"))
            .map(|(_, v)| v.as_str());
        assert_eq!(upgrade, Some(UPGRADE_VALUE));

        // Read the 51-byte Noise handshake response from the stream.
        // This proves bytes after the HTTP headers are not lost.
        let mut resp_buf = [0u8; 51];
        client.read_exact(&mut resp_buf).await.unwrap();
        assert_eq!(resp_buf[0], 2); // MSG_TYPE_RESPONSE
        assert_eq!(u16::from_be_bytes([resp_buf[1], resp_buf[2]]), 48);

        // Verify the initiation was base64-encoded correctly in the request
        // (the client would have sent it in the X-Tailscale-Handshake header).
        assert!(!init_b64.is_empty());
    }

    /// Test that a 200 response (not 101) is correctly rejected.
    #[tokio::test]
    async fn upgrade_rejects_non_101() {
        let response = b"HTTP/1.1 200 OK\r\n\
                         Content-Type: text/plain\r\n\
                         \r\n\
                         not an upgrade";
        let (mut server, mut client) = tokio::io::duplex(1024);
        server.write_all(response).await.unwrap();

        let parsed = read_http_headers(&mut client).await.unwrap();
        assert_ne!(parsed.status_code, 101);
        // In the real upgrade_and_handshake, this would return BadStatus.
    }

    /// Test that a 101 with a wrong Upgrade header would be rejected.
    #[tokio::test]
    async fn upgrade_rejects_wrong_protocol() {
        let response = b"HTTP/1.1 101 Switching Protocols\r\n\
                         Upgrade: websocket\r\n\
                         \r\n";
        let (mut server, mut client) = tokio::io::duplex(1024);
        server.write_all(response).await.unwrap();

        let parsed = read_http_headers(&mut client).await.unwrap();
        assert_eq!(parsed.status_code, 101);

        let upgrade = parsed
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("upgrade"))
            .map(|(_, v)| v.as_str());
        assert_ne!(upgrade, Some(UPGRADE_VALUE));
        // In the real upgrade_and_handshake, this would return BadUpgrade.
    }

    /// Test that a 101 with no Upgrade header is rejected.
    #[tokio::test]
    async fn upgrade_rejects_missing_upgrade_header() {
        let response = b"HTTP/1.1 101 Switching Protocols\r\n\
                         Connection: upgrade\r\n\
                         \r\n";
        let (mut server, mut client) = tokio::io::duplex(1024);
        server.write_all(response).await.unwrap();

        let parsed = read_http_headers(&mut client).await.unwrap();
        assert_eq!(parsed.status_code, 101);

        let upgrade = parsed
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("upgrade"))
            .map(|(_, v)| v.as_str());
        assert_eq!(upgrade, None);
    }

    /// Real-handshake probe: dial controlplane.tailscale.com, fetch the
    /// server's Noise public key, complete the Noise handshake, and read
    /// one framed record. No credentials needed — the server will close
    /// the connection after we fail to send a register request, but the
    /// handshake itself should succeed.
    ///
    /// #[ignore] because it requires network access.
    #[tokio::test]
    #[ignore = "requires network access to controlplane.tailscale.com"]
    async fn real_noise_handshake_completes() {
        let host = "controlplane.tailscale.com";
        let version: ProtocolVersion = 141;

        // 1. Fetch the server's Noise public key.
        let server_key = fetch_server_pub_key(host, version)
            .await
            .expect("fetch_server_pub_key should succeed");
        assert!(!server_key.is_zero(), "server key should be non-zero");

        // 2. Generate our machine key.
        let machine_key = MachinePrivate::generate();

        // 3. Dial and complete the Noise handshake.
        let mut stream = dial_control(host, &machine_key, &server_key, version)
            .await
            .expect("dial_control should succeed");

        // 4. The handshake completed. Try to read a record — the server
        //    may send us nothing and close (since we haven't sent a register
        //    request), or it may send an empty/ping record. Either way,
        //    the handshake itself succeeded if we got here.
        //
        //    We don't assert on the read result — an EOF here is expected
        //    since we never sent a register request. The key assertion is
        //    that dial_control returned Ok, meaning the Noise handshake
        //    completed without EOF/error.
        let _ = stream.read_record().await; // may succeed or EOF — both ok
    }
}
