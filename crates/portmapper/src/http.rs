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
    let response = do_request(&host, port, &req, deadline).await?;
    let (status, body) = split_response(&response)?;
    if status != 200 {
        return Err(std::io::Error::other(format!(
            "HTTP GET failed (status={status})"
        )));
    }
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
    let (status, body_text) = split_response(&resp)?;
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
    let mut limited = stream.take((MAX_BODY + 1) as u64);
    timeout(deadline, limited.read_to_end(&mut buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "read timeout"))??;
    if buf.len() > MAX_BODY {
        return Err(std::io::Error::new(
            std::io::ErrorKind::FileTooLarge,
            "HTTP response exceeds size limit",
        ));
    }
    Ok(buf)
}

/// Strictly split a raw HTTP/1.x response into status and body.
fn split_response(raw: &[u8]) -> Result<(u16, Vec<u8>), std::io::Error> {
    let invalid =
        |message: &'static str| std::io::Error::new(std::io::ErrorKind::InvalidData, message);
    let header_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| invalid("missing HTTP header terminator"))?;
    let header = std::str::from_utf8(&raw[..header_end])
        .map_err(|_| invalid("HTTP headers are not UTF-8"))?;
    let mut lines = header.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| invalid("missing HTTP status line"))?;
    let mut status_parts = status_line.splitn(3, ' ');
    let version = status_parts.next().unwrap_or_default();
    let code = status_parts.next().unwrap_or_default();
    let reason = status_parts
        .next()
        .ok_or_else(|| invalid("malformed HTTP status line"))?;
    let version_bytes = version.as_bytes();
    if version_bytes.len() != 8
        || &version_bytes[..7] != b"HTTP/1."
        || !version_bytes[7].is_ascii_digit()
        || code.len() != 3
        || !code.bytes().all(|byte| byte.is_ascii_digit())
        || code.starts_with('0')
        || !reason
            .bytes()
            .all(|byte| byte == b'\t' || (byte >= b' ' && byte != 0x7f))
    {
        return Err(invalid("malformed HTTP status line"));
    }
    let status = code
        .parse::<u16>()
        .map_err(|_| invalid("invalid HTTP status code"))?;

    let mut content_length = None;
    for line in lines {
        if line.is_empty() || line.starts_with([' ', '\t']) {
            return Err(invalid("malformed HTTP header"));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| invalid("malformed HTTP header"))?;
        if name.is_empty() || !name.bytes().all(is_http_token_byte) {
            return Err(invalid("invalid HTTP header name"));
        }
        if !value
            .bytes()
            .all(|byte| byte == b'\t' || (byte >= b' ' && byte != 0x7f))
        {
            return Err(invalid("invalid HTTP header value"));
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(invalid("unsupported Transfer-Encoding"));
        }
        if name.eq_ignore_ascii_case("content-length") {
            let value = value.trim();
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(invalid("invalid Content-Length"));
            }
            let length = value
                .parse::<usize>()
                .map_err(|_| invalid("invalid Content-Length"))?;
            if content_length.replace(length).is_some() {
                return Err(invalid("duplicate Content-Length"));
            }
        }
    }
    let body = raw[header_end + 4..].to_vec();
    if body.len() > MAX_BODY {
        return Err(std::io::Error::new(
            std::io::ErrorKind::FileTooLarge,
            "HTTP response body exceeds size limit",
        ));
    }
    if content_length.is_some_and(|length| length != body.len()) {
        return Err(invalid("Content-Length mismatch"));
    }
    if ((100..200).contains(&status) || matches!(status, 204 | 304)) && !body.is_empty() {
        return Err(invalid("HTTP status forbids a response body"));
    }
    Ok((status, body))
}

fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
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
        let (status, body) = split_response(raw).unwrap();
        assert_eq!(status, 200);
        assert_eq!(&body, b"hello");
    }

    #[tokio::test]
    async fn reader_detects_oversized_close_framed_response() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await;
            let mut response = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n<s:Envelope>".to_vec();
            response.resize(MAX_BODY + 1, b'x');
            stream.write_all(&response).await.unwrap();
        });
        let error = http_post_soap(
            &format!("http://{address}/control"),
            "urn:test#AddPortMapping",
            "text/xml",
            "<request/>",
            Duration::from_secs(2),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::FileTooLarge);
        server.await.unwrap();
    }

    #[test]
    fn split_response_enforces_body_framing_and_limits() {
        let visible_fault_prefix = b"<s:Envelope><s:Body><s:Fault>";
        let mut oversized = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        oversized.extend_from_slice(visible_fault_prefix);
        oversized.resize(oversized.len() + MAX_BODY, b'x');
        assert_eq!(
            split_response(&oversized).unwrap_err().kind(),
            std::io::ErrorKind::FileTooLarge
        );

        assert!(split_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhell").is_err());
        assert!(
            split_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello-trailing").is_err()
        );
        for raw in [
            &b"HTTP/1.1 100 Continue\r\n\r\nx"[..],
            &b"HTTP/1.1 204 No Content\r\n\r\nx"[..],
            &b"HTTP/1.1 304 Not Modified\r\nContent-Length: 1\r\n\r\nx"[..],
        ] {
            assert!(split_response(raw).is_err(), "accepted {raw:?}");
        }
        assert!(split_response(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n").is_ok());
    }

    #[test]
    fn split_response_rejects_malformed_status_and_headers() {
        for raw in [
            &b"BROKEN 200 OK\r\nContent-Length: 0\r\n\r\n"[..],
            &b"HTTP/2 200 OK\r\nContent-Length: 0\r\n\r\n"[..],
            &b"HTTP/1.1 20 OK\r\nContent-Length: 0\r\n\r\n"[..],
            &b"HTTP/1.1 abc OK\r\nContent-Length: 0\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\nContent-Length: 0\n\n"[..],
            &b"HTTP/1.1 200 OK\r\nBad Header: x\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\n folded: x\r\n\r\n"[..],
            &b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n"[..],
        ] {
            assert!(split_response(raw).is_err(), "accepted {raw:?}");
        }
    }
}
