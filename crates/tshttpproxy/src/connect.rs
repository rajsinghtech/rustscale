//! HTTP CONNECT tunnel client — establishes a TCP tunnel through an HTTP
//! proxy and returns the raw `TcpStream` ready for TLS or plain-protocol
//! framing. Mirrors Go's `derphttp.dialNodeUsingProxy()` CONNECT sequence.

use std::fmt::Write as _;
use std::time::Duration;

use base64::Engine as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use url::Url;

use crate::TsHttpProxyError;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Establish a TCP tunnel to `target_host:target_port` via `proxy_url` using
/// HTTP/1.1 `CONNECT`.
///
/// The proxy address is taken from `proxy_url` (host + port, defaulting to
/// 8080 when no port is given). If `proxy_url` carries userinfo
/// (`user:pass@host`), a `Proxy-Authorization: Basic ...` header is sent,
/// matching Go's `tshttpproxy.GetAuthHeader`.
///
/// Returns the tunneled `TcpStream` on a `200` response. The caller wraps it
/// in TLS or uses it directly as the base transport.
///
/// Reads the proxy response one byte at a time so that no tunneled-protocol
/// bytes are accidentally consumed past the `\\r\\n\\r\\n` terminator (a
/// CONNECT response has no body; well-behaved proxies send nothing after the
/// blank line, but byte-at-a-time reads guarantee correctness regardless).
pub async fn http_connect(
    proxy_url: &Url,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream, TsHttpProxyError> {
    let proxy_host = proxy_url.host_str().ok_or_else(|| {
        TsHttpProxyError::ConnectFailed(format!("proxy URL missing host: {proxy_url}"))
    })?;
    let proxy_port = proxy_url.port().unwrap_or(8080);

    let tcp = tokio::time::timeout(
        CONNECT_TIMEOUT,
        rustscale_netns::dial_tcp(proxy_host, proxy_port),
    )
    .await
    .map_err(|_| {
        TsHttpProxyError::ConnectFailed(format!(
            "timed out connecting to proxy {proxy_host}:{proxy_port}"
        ))
    })??;
    tcp.set_nodelay(true).ok();

    let target = format!("{target_host}:{target_port}");
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some(auth) = proxy_auth_header(proxy_url) {
        let _ = write!(req, "Proxy-Authorization: Basic {auth}\r\n");
    }
    req.push_str("\r\n");

    let mut stream = tcp;
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    let status = read_connect_status(&mut stream).await?;
    if status != 200 {
        return Err(TsHttpProxyError::ConnectFailed(format!(
            "proxy returned HTTP {status} for CONNECT {target}"
        )));
    }
    Ok(stream)
}

/// Build the `Proxy-Authorization: Basic <b64>` value from a proxy URL's
/// userinfo, or `None` when no credentials are present. Matches Go's
/// `tshttpproxy.GetAuthHeader`.
fn proxy_auth_header(proxy_url: &Url) -> Option<String> {
    let username = proxy_url.username();
    let password = proxy_url.password().unwrap_or("");
    if username.is_empty() && password.is_empty() {
        return None;
    }
    let creds = if password.is_empty() {
        username.to_string()
    } else {
        format!("{username}:{password}")
    };
    Some(base64::engine::general_purpose::STANDARD.encode(creds.as_bytes()))
}

/// Read the proxy's CONNECT response status line + headers, returning the
/// HTTP status code. Reads one byte at a time so no bytes past the header
/// terminator are consumed from the socket.
async fn read_connect_status(stream: &mut TcpStream) -> Result<u16, TsHttpProxyError> {
    let mut buf = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        let n = tokio::time::timeout(CONNECT_TIMEOUT, stream.read(&mut byte))
            .await
            .map_err(|_| {
                TsHttpProxyError::ConnectFailed("timed out reading proxy response".into())
            })??;
        if n == 0 {
            return Err(TsHttpProxyError::ConnectFailed(
                "proxy closed before sending CONNECT response".into(),
            ));
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 8192 {
            return Err(TsHttpProxyError::ConnectFailed(
                "proxy CONNECT response too large".into(),
            ));
        }
    }
    parse_status_code(&buf)
}

fn parse_status_code(buf: &[u8]) -> Result<u16, TsHttpProxyError> {
    let line_end = buf
        .iter()
        .position(|&b| b == b'\n')
        .ok_or_else(|| TsHttpProxyError::ConnectFailed("malformed status line".into()))?;
    let line = std::str::from_utf8(&buf[..line_end])
        .map_err(|_| TsHttpProxyError::ConnectFailed("non-utf8 status line".into()))?;
    let mut parts = line.split_whitespace();
    let _version = parts.next();
    let code = parts
        .next()
        .ok_or_else(|| TsHttpProxyError::ConnectFailed(format!("missing status code: {line}")))?;
    code.parse::<u16>()
        .map_err(|_| TsHttpProxyError::ConnectFailed(format!("invalid status code: {code}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_header_without_credentials() {
        let url = Url::parse("http://proxy.local:8080").unwrap();
        assert!(proxy_auth_header(&url).is_none());
    }

    #[test]
    fn auth_header_with_credentials() {
        let url = Url::parse("http://user:pass@proxy.local:8080").unwrap();
        let auth = proxy_auth_header(&url).unwrap();
        assert_eq!(
            auth,
            base64::engine::general_purpose::STANDARD.encode(b"user:pass")
        );
    }

    #[test]
    fn auth_header_username_only() {
        let url = Url::parse("http://token@proxy.local:8080").unwrap();
        let auth = proxy_auth_header(&url).unwrap();
        assert_eq!(
            auth,
            base64::engine::general_purpose::STANDARD.encode(b"token")
        );
    }

    #[test]
    fn parse_status_ok() {
        let resp = b"HTTP/1.1 200 Connection established\r\n\r\n";
        assert_eq!(parse_status_code(resp).unwrap(), 200);
    }

    #[test]
    fn parse_status_failure() {
        let resp = b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n";
        assert_eq!(parse_status_code(resp).unwrap(), 407);
    }

    #[test]
    fn parse_status_malformed() {
        assert!(parse_status_code(b"garbage\r\n\r\n").is_err());
    }
}
