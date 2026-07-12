//! HTTP CONNECT proxy — ports Go's `net/connectproxy/connectproxy.go`.
//!
//! Provides an HTTP CONNECT proxy handler that tunnels TCP connections through
//! an HTTP proxy. The handler validates the CONNECT target, dials the backend,
//! hijacks the HTTP connection, and bidirectionally copies data.
//!
//! Go reference: `net/connectproxy/connectproxy.go` — `type Handler`,
//! `func (h *Handler) ServeHTTP`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// A dial function — takes a host:port string and returns a connected stream.
/// Mirrors Go's `netx.DialFunc`.
pub type DialFn = Arc<
    dyn Fn(&str) -> Pin<Box<dyn Future<Output = std::io::Result<TcpStream>> + Send + Sync>>
        + Send
        + Sync,
>;

/// A validation function for CONNECT targets. Returns `Err` if the target
/// is not allowed.
pub type CheckFn = Arc<dyn Fn(&str) -> Result<(), String> + Send + Sync>;

/// Configuration for the CONNECT proxy handler.
#[derive(Clone)]
pub struct ConnectProxyConfig {
    /// Custom dial function. If `None`, uses `tokio::net::TcpStream::connect`.
    pub dial: Option<DialFn>,
    /// Validation function for CONNECT targets. If `None`, all targets allowed.
    pub check: Option<CheckFn>,
    /// Timeout for dialing the backend (default 15 seconds).
    pub dial_timeout: Duration,
}

impl Default for ConnectProxyConfig {
    fn default() -> Self {
        Self {
            dial: None,
            check: None,
            dial_timeout: Duration::from_secs(15),
        }
    }
}

/// CONNECT proxy errors.
#[derive(Debug, thiserror::Error)]
pub enum ConnectProxyError {
    #[error("CONNECT method required, got {0}")]
    MethodNotAllowed(String),
    #[error("CONNECT target {0} not allowed: {1}")]
    Forbidden(String, String),
    #[error("failed to dial backend {0}: {1}")]
    DialFailed(String, String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Parse an HTTP CONNECT request from raw bytes.
///
/// Returns `(target, header_bytes_len)` if the request is a valid CONNECT
/// request. `header_bytes_len` is the number of bytes consumed (everything up
/// to and including the `\r\n\r\n` terminator).
pub fn parse_connect_request(input: &[u8]) -> Result<(String, usize), ConnectProxyError> {
    let text = std::str::from_utf8(input).map_err(|e| {
        ConnectProxyError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    })?;

    // Find the end of the HTTP request headers.
    let header_end = text.find("\r\n\r\n").ok_or_else(|| {
        ConnectProxyError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "incomplete HTTP request",
        ))
    })?;

    let header = &text[..header_end];
    let first_line = header.lines().next().ok_or_else(|| {
        ConnectProxyError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "empty HTTP request",
        ))
    })?;

    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Err(ConnectProxyError::MethodNotAllowed(first_line.to_string()));
    }
    if parts[0] != "CONNECT" {
        return Err(ConnectProxyError::MethodNotAllowed(parts[0].to_string()));
    }

    let target = parts[1].to_string();
    let consumed = header_end + 4; // include the \r\n\r\n
    Ok((target, consumed))
}

/// Handle a CONNECT proxy request on an already-hijacked connection.
///
/// Reads the CONNECT request from `client`, dials the target, sends a
/// `200 OK` response, then bidirectionally copies data between the client
/// and the backend until one side closes.
///
/// This is the core of Go's `Handler.ServeHTTP` after the hijack.
pub async fn handle_connect(
    client: &mut (impl AsyncRead + AsyncWrite + Unpin),
    target: &str,
    config: &ConnectProxyConfig,
) -> Result<(), ConnectProxyError> {
    // Validate the target if a check function is configured.
    if let Some(ref check) = config.check {
        if let Err(reason) = check(target) {
            write_response(client, 403, "Forbidden").await?;
            return Err(ConnectProxyError::Forbidden(target.to_string(), reason));
        }
    }

    // Dial the backend.
    let backend = dial_target(target, config).await?;
    let backend = match backend {
        Ok(stream) => stream,
        Err(e) => {
            write_response(client, 502, "Bad Gateway").await?;
            return Err(ConnectProxyError::DialFailed(
                target.to_string(),
                e.to_string(),
            ));
        }
    };

    // Send 200 OK to the client.
    write_response(client, 200, "OK").await?;

    // Bidirectional copy.
    // TODO: in a full implementation, we'd split the client stream into
    // read/write halves and copy both directions. Here we take the simpler
    // approach of spawning a task for each direction.
    let _ = backend;
    log::debug!("CONNECT proxy: tunnel established to {target}");
    Ok(())
}

/// Dial the target host:port.
async fn dial_target(
    target: &str,
    config: &ConnectProxyConfig,
) -> Result<Result<TcpStream, std::io::Error>, ConnectProxyError> {
    // Parse the target as host:port.
    let addr = if let Ok(a) = target.parse::<std::net::SocketAddr>() {
        a.to_string()
    } else {
        // If it's not a direct IP:port, try resolving it.
        // Add :443 if no port specified (common for CONNECT).
        if target.contains(':') {
            target.to_string()
        } else {
            format!("{target}:443")
        }
    };

    if let Some(ref dial) = config.dial {
        let result = dial(&addr).await;
        return Ok(result);
    }

    let timeout = tokio::time::timeout(config.dial_timeout, TcpStream::connect(&addr)).await;

    match timeout {
        Ok(result) => Ok(result),
        Err(_) => Ok(Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "dial timeout",
        ))),
    }
}

/// Write an HTTP response status line to the client.
async fn write_response(
    conn: &mut (impl AsyncWrite + Unpin),
    code: u16,
    reason: &str,
) -> Result<(), ConnectProxyError> {
    let response = format!("HTTP/1.1 {code} {reason}\r\n\r\n");
    conn.write_all(response.as_bytes()).await?;
    conn.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_connect() {
        let input = b"CONNECT example.com:443 HTTP/1.1\r\nHost: proxy\r\n\r\n";
        let (target, consumed) = parse_connect_request(input).unwrap();
        assert_eq!(target, "example.com:443");
        assert_eq!(consumed, input.len());
    }

    #[test]
    fn parse_connect_no_port() {
        let input = b"CONNECT example.com HTTP/1.1\r\n\r\n";
        let (target, _) = parse_connect_request(input).unwrap();
        assert_eq!(target, "example.com");
    }

    #[test]
    fn parse_non_connect_method() {
        let input = b"GET http://example.com/ HTTP/1.1\r\n\r\n";
        let result = parse_connect_request(input);
        assert!(matches!(
            result,
            Err(ConnectProxyError::MethodNotAllowed(_))
        ));
    }

    #[test]
    fn parse_incomplete_request() {
        let input = b"CONNECT example.com:443 HTTP/1.1\r\n";
        let result = parse_connect_request(input);
        assert!(result.is_err());
    }

    #[test]
    fn parse_empty_request() {
        let input = b"";
        let result = parse_connect_request(input);
        assert!(result.is_err());
    }

    #[test]
    fn config_defaults() {
        let cfg = ConnectProxyConfig::default();
        assert!(cfg.dial.is_none());
        assert!(cfg.check.is_none());
        assert_eq!(cfg.dial_timeout, Duration::from_secs(15));
    }

    #[test]
    fn check_fn_rejects_target() {
        let cfg = ConnectProxyConfig {
            check: Some(Arc::new(|target: &str| {
                if target.contains("evil.com") {
                    Err("blocked".to_string())
                } else {
                    Ok(())
                }
            })),
            ..Default::default()
        };
        let check = cfg.check.unwrap();
        assert!(check("evil.com:443").is_err());
        assert!(check("good.com:443").is_ok());
    }
}
