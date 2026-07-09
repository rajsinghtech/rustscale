//! HTTP `/ts2021` upgrade dance — ports Go's `control/controlhttp/client.go`.
//!
//! The client POSTs to `/ts2021` with an `Upgrade: tailscale-control-protocol`
//! header. The `X-Tailscale-Handshake` header carries the base64-encoded Noise
//! initiation message, saving an RTT. On `101 Switching Protocols` the TLS
//! stream becomes the Noise transport.
//!
//! This implementation is deliberately simple: single `host:443` over TLS,
//! no port-80 plaintext fallback, no DNS fallback tricks.

use std::sync::Arc;

use base64::Engine as _;
use rustscale_key::{MachinePrivate, MachinePublic};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;

use crate::controlbase::{client_deferred, NoiseConn, NoiseError, ProtocolVersion};

/// HTTP header value indicating the Tailscale control protocol.
const UPGRADE_VALUE: &str = "tailscale-control-protocol";
/// HTTP header name carrying the base64-encoded Noise initiation.
const HANDSHAKE_HEADER: &str = "X-Tailscale-Handshake";
/// The URL path for the protocol upgrade.
const UPGRADE_PATH: &str = "/ts2021";

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
}

/// Dial the control server at `host:443` over TLS, perform the `/ts2021`
/// upgrade, and complete the Noise handshake.
///
/// Returns a [`NoiseStream`] ready for encrypted control-plane messages.
pub async fn dial_control(
    host: &str,
    machine_key: &MachinePrivate,
    control_key: &MachinePublic,
    version: ProtocolVersion,
) -> Result<NoiseStream<tokio_rustls::client::TlsStream<TcpStream>>, DialError> {
    let tls_stream = tls_connect(host).await?;
    upgrade_and_handshake(tls_stream, host, machine_key, control_key, version).await
}

/// Establish a TLS connection to `host:443`.
async fn tls_connect(host: &str) -> Result<tokio_rustls::client::TlsStream<TcpStream>, DialError> {
    let addr = format!("{host}:443");
    let tcp = TcpStream::connect(&addr).await.map_err(DialError::Io)?;

    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| DialError::Tls(format!("invalid server name: {e}")))?;
    let tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| DialError::Tls(e.to_string()))?;
    Ok(tls)
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

    // Verify 101 Switching Protocols.
    if !response.status.starts_with("101") {
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
    // response and finalize the Noise session.
    let mut resp_buf = [0u8; 51]; // RESPONSE_MSG_LEN
    stream
        .read_exact(&mut resp_buf)
        .await
        .map_err(DialError::Io)?;
    let conn = deferred.finish_from_response_bytes(&resp_buf)?;
    Ok(NoiseStream { stream, conn })
}

/// Parsed HTTP response head (status line + headers).
struct HttpResponse {
    status: String,
    headers: Vec<(String, String)>,
}

/// Read the HTTP response status line and headers from `stream` (until
/// the blank line that terminates the response head).
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

    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.split("\r\n");
    let status = lines
        .next()
        .ok_or_else(|| DialError::Malformed("empty response".into()))?
        .to_string();
    let headers = lines
        .take_while(|l| !l.is_empty())
        .filter_map(|l| {
            let mut parts = l.splitn(2, ':');
            let key = parts.next()?.trim().to_string();
            let val = parts.next()?.trim().to_string();
            Some((key, val))
        })
        .collect();

    Ok(HttpResponse { status, headers })
}
