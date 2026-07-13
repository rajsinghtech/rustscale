//! Minimal HTTP/1.1 client for UPnP IGD.
//!
//! UPnP runs over plain HTTP (not HTTPS) on the LAN. The requests are simple
//! GETs (root-desc XML) and POSTs (SOAP). We hand-roll a minimal client over
//! `tokio::net::TcpStream` to avoid adding a heavyweight HTTP dependency,
//! mirroring Go's pragmatic approach.

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

/// Maximum response body size we'll accept (root-desc XML + SOAP responses
/// are small; 256 KiB is generous).
const MAX_BODY: usize = 256 * 1024;

/// Fetch a URL via HTTP/1.1 GET and return the response body as a string.
pub(crate) async fn http_get(url: &str, deadline: Duration) -> Result<String, std::io::Error> {
    let (host, port, path) = parse_url(url)?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n");
    let body = do_request(&host, port, &req, deadline).await?;
    String::from_utf8(body).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// POST a SOAP envelope to a UPnP control URL and return the response body.
pub(crate) async fn http_post_soap(
    url: &str,
    soap_action: &str,
    content_type: &str,
    body: &str,
    deadline: Duration,
) -> Result<(u16, String), std::io::Error> {
    let (host, port, path) = parse_url(url)?;
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: {content_type}\r\nSOAPAction: \"{soap_action}\"\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let resp = do_request(&host, port, &req, deadline).await?;
    let (status, body_text) = split_response(&resp);
    Ok((
        status,
        String::from_utf8(body_text)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
    ))
}

/// Parse a `http://host:port/path` URL into its components.
fn parse_url(url: &str) -> Result<(String, u16, String), std::io::Error> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "not http://"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rfind(':') {
        Some(i) => (&authority[..i], authority[i + 1..].parse().unwrap_or(80)),
        None => (authority, 80),
    };
    Ok((host.to_string(), port, path.to_string()))
}

/// Send an HTTP request, read the full response, and return the raw bytes
/// (headers + body). Uses `Connection: close` so the server closes after
/// sending the full response, which lets us read until EOF.
async fn do_request(
    host: &str,
    port: u16,
    req: &str,
    deadline: Duration,
) -> Result<Vec<u8>, std::io::Error> {
    let mut stream = timeout(
        deadline,
        rustscale_tsdial::system_dial("tcp", &format!("{host}:{port}")),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"))??;
    stream.write_all(req.as_bytes()).await?;
    let mut buf = Vec::with_capacity(4096);
    let mut limited = stream.take(MAX_BODY as u64);
    timeout(deadline, limited.read_to_end(&mut buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "read timeout"))??;
    if buf.len() > MAX_BODY {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "response too large",
        ));
    }
    Ok(buf)
}

/// Split a raw HTTP response into (status_code, body_bytes).
fn split_response(raw: &[u8]) -> (u16, Vec<u8>) {
    // Find the end of headers (\r\n\r\n).
    let header_end = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(0);
    let header_str = String::from_utf8_lossy(&raw[..header_end]);
    let status = header_str
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(500);
    let body = if header_end > 0 {
        raw[header_end + 4..].to_vec()
    } else {
        Vec::new()
    };
    (status, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_url_basic() {
        let (h, p, path) = parse_url("http://127.0.0.1:5000/rootDesc.xml").unwrap();
        assert_eq!(h, "127.0.0.1");
        assert_eq!(p, 5000);
        assert_eq!(path, "/rootDesc.xml");
    }

    #[test]
    fn parse_url_default_port() {
        let (h, p, path) = parse_url("http://192.168.1.1/foo").unwrap();
        assert_eq!(h, "192.168.1.1");
        assert_eq!(p, 80);
        assert_eq!(path, "/foo");
    }

    #[test]
    fn parse_url_no_path() {
        let (h, p, path) = parse_url("http://10.0.0.1:8080").unwrap();
        assert_eq!(h, "10.0.0.1");
        assert_eq!(p, 8080);
        assert_eq!(path, "/");
    }

    #[test]
    fn split_response_extracts_status_and_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let (status, body) = split_response(raw);
        assert_eq!(status, 200);
        assert_eq!(&body, b"hello");
    }
}
