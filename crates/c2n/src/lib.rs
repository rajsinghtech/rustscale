#![forbid(unsafe_code)]

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Debug, Clone, serde::Serialize)]
pub struct WhoIsResult {
    pub found: bool,
    pub node_name: String,
    pub user_id: i64,
    pub login_name: String,
}

#[async_trait]
pub trait C2nBackend: Send + Sync {
    async fn whois(&self, ip: IpAddr) -> Option<WhoIsResult>;
}

#[derive(Debug, thiserror::Error)]
pub enum C2nError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("bind error: {0}")]
    Bind(String),
}

pub struct C2NServer {
    backend: Arc<dyn C2nBackend>,
    log_id: String,
}

impl C2NServer {
    pub fn new(backend: Arc<dyn C2nBackend>, log_id: String) -> Self {
        Self { backend, log_id }
    }

    pub async fn bind() -> Result<(TcpListener, SocketAddr), C2nError> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        Ok((listener, addr))
    }

    pub async fn serve(self, listener: TcpListener) -> Result<(), C2nError> {
        loop {
            let (mut stream, peer_addr) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("c2n[{}]: accept error: {e}", self.log_id);
                    continue;
                }
            };

            let backend = self.backend.clone();
            let log_id = self.log_id.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(&mut stream, peer_addr, &backend, &log_id).await {
                    eprintln!("c2n[{log_id}]: connection error: {e}");
                }
            });
        }
    }
}

async fn handle_connection(
    stream: &mut tokio::net::TcpStream,
    peer_addr: SocketAddr,
    backend: &Arc<dyn C2nBackend>,
    log_id: &str,
) -> Result<(), std::io::Error> {
    let req = match read_request(stream).await {
        Ok(r) => r,
        Err(e) => {
            let body = serde_json::json!({"error": "bad request", "reason": e});
            write_json_response(stream, 400, "Bad Request", &body).await?;
            return Ok(());
        }
    };

    if !check_auth(peer_addr.ip(), backend).await {
        let body = serde_json::json!({
            "error": "unauthorized",
            "reason": "non-tailnet connection",
        });
        write_json_response(stream, 401, "Unauthorized", &body).await?;
        return Ok(());
    }

    let _ = log_id;
    dispatch(stream, &req).await
}

async fn check_auth(ip: IpAddr, backend: &Arc<dyn C2nBackend>) -> bool {
    if is_loopback(ip) {
        return true;
    }
    if is_tailnet_ip(ip) {
        return backend.whois(ip).await.is_some();
    }
    false
}

fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

fn is_tailnet_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            octets[0] == 100 && (octets[1] >= 64 && octets[1] <= 127)
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            segs[0] == 0xfd7a && segs[1] == 0x115c && segs[2] == 0xa1e0
        }
    }
}

struct HttpRequest {
    method: String,
    path: String,
    #[allow(dead_code)]
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

async fn read_request<R: AsyncRead + Unpin>(conn: &mut R) -> Result<HttpRequest, String> {
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    loop {
        let n = conn
            .read(&mut tmp)
            .await
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("connection closed before headers".into());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(end) = find_header_end(&buf) {
            let head = &buf[..end + 4];
            let body_preview = buf[end + 4..].to_vec();
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
    let path = parts.next().ok_or("no path")?.to_string();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    let cl_header = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"));

    let body = if let Some((_, v)) = cl_header {
        let cl: usize = v.parse().unwrap_or(0);
        if body_preview.len() >= cl {
            body_preview[..cl].to_vec()
        } else {
            body_preview
        }
    } else {
        body_preview
    };

    Ok(HttpRequest {
        method,
        path,
        headers,
        body,
    })
}

async fn write_json_response<W: AsyncWrite + Unpin>(
    conn: &mut W,
    status: u16,
    reason: &str,
    body: &serde_json::Value,
) -> Result<(), std::io::Error> {
    let json = serde_json::to_vec(body).unwrap_or_default();
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        json.len()
    );
    conn.write_all(header.as_bytes()).await?;
    conn.write_all(&json).await?;
    conn.flush().await?;
    Ok(())
}

#[allow(dead_code)]
async fn write_text_response<W: AsyncWrite + Unpin>(
    conn: &mut W,
    status: u16,
    reason: &str,
    body: &str,
) -> Result<(), std::io::Error> {
    let body_bytes = body.as_bytes();
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body_bytes.len()
    );
    conn.write_all(header.as_bytes()).await?;
    conn.write_all(body_bytes).await?;
    conn.flush().await?;
    Ok(())
}

async fn write_raw_response<W: AsyncWrite + Unpin>(
    conn: &mut W,
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
    conn.write_all(header.as_bytes()).await?;
    conn.write_all(body).await?;
    conn.flush().await?;
    Ok(())
}

const KNOWN_PATHS: &[&str] = &[
    "/",
    "/echo",
    "/debug/goroutines",
    "/debug/pprof/",
    "/debug/pprof/profile",
    "/debug/pprof/heap",
    "/debug/metrics",
    "/debug/netmap",
    "/debug/prefs",
    "/debug/health",
    "/netmap",
    "/prefs",
    "/dns",
    "/logtail/logs",
    "/logtail/flush",
];

fn known_paths() -> serde_json::Value {
    serde_json::json!(KNOWN_PATHS)
}

async fn dispatch<W: AsyncWrite + Unpin>(
    conn: &mut W,
    req: &HttpRequest,
) -> Result<(), std::io::Error> {
    let method = req.method.as_str();
    let path = req.path.as_str();

    if path == "/" {
        if method == "GET" {
            write_json_response(conn, 200, "OK", &known_paths()).await?;
        } else {
            let body = serde_json::json!({"error": "bad method", "path": path});
            write_json_response(conn, 405, "Method Not Allowed", &body).await?;
        }
        return Ok(());
    }

    if path == "/echo" {
        if method == "GET" {
            write_raw_response(conn, 200, "OK", "application/octet-stream", &req.body).await?;
        } else {
            let body = serde_json::json!({"error": "bad method", "path": path});
            write_json_response(conn, 405, "Method Not Allowed", &body).await?;
        }
        return Ok(());
    }

    if path.starts_with("/local/") {
        if method == "POST" {
            let body = serde_json::json!({"error": "not implemented", "path": path});
            write_json_response(conn, 501, "Not Implemented", &body).await?;
        } else {
            let body = serde_json::json!({"error": "bad method", "path": path});
            write_json_response(conn, 405, "Method Not Allowed", &body).await?;
        }
        return Ok(());
    }

    let is_known = KNOWN_PATHS.contains(&path)
        || path == "/logtail/flush"
        || path == "/logtail/logs";

    match (method, path) {
        ("GET", "/debug/goroutines") => stub_501(conn, path).await,
        ("GET", "/debug/pprof/") => stub_501(conn, path).await,
        ("GET", "/debug/pprof/profile") => stub_501(conn, path).await,
        ("GET", "/debug/pprof/heap") => stub_501(conn, path).await,
        ("GET", "/debug/metrics") => stub_501(conn, path).await,
        ("GET", "/debug/netmap") => stub_501(conn, path).await,
        ("GET", "/debug/prefs") => stub_501(conn, path).await,
        ("GET", "/debug/health") => stub_501(conn, path).await,
        ("GET", "/netmap") => stub_501(conn, path).await,
        ("GET", "/prefs") => stub_501(conn, path).await,
        ("GET", "/dns") => stub_501(conn, path).await,
        ("GET", "/logtail/logs") => stub_501(conn, path).await,
        ("POST", "/logtail/flush") => stub_501(conn, path).await,
        _ => {
            if is_known {
                let body = serde_json::json!({"error": "bad method", "path": path});
                write_json_response(conn, 405, "Method Not Allowed", &body).await
            } else {
                let body = serde_json::json!({"error": "unknown c2n path", "path": path});
                write_json_response(conn, 400, "Bad Request", &body).await
            }
        }
    }
}

async fn stub_501<W: AsyncWrite + Unpin>(
    conn: &mut W,
    path: &str,
) -> Result<(), std::io::Error> {
    let body = serde_json::json!({"error": "not implemented", "path": path});
    write_json_response(conn, 501, "Not Implemented", &body).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    struct FakeBackend;
    #[async_trait]
    impl C2nBackend for FakeBackend {
        async fn whois(&self, _ip: IpAddr) -> Option<WhoIsResult> {
            Some(WhoIsResult {
                found: true,
                node_name: "test.".into(),
                user_id: 1,
                login_name: "test@tailnet".into(),
            })
        }
    }

    #[test]
    fn test_is_loopback() {
        assert!(is_loopback("127.0.0.1".parse().unwrap()));
        assert!(is_loopback("::1".parse().unwrap()));
        assert!(!is_loopback("100.64.0.1".parse().unwrap()));
        assert!(!is_loopback("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_is_tailnet_ip() {
        assert!(is_tailnet_ip("100.64.0.1".parse().unwrap()));
        assert!(is_tailnet_ip("100.127.255.255".parse().unwrap()));
        assert!(is_tailnet_ip("fd7a:115c:a1e0::1".parse().unwrap()));
        assert!(!is_tailnet_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_tailnet_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_tailnet_ip("99.64.0.1".parse().unwrap()));
        assert!(!is_tailnet_ip("100.63.0.1".parse().unwrap()));
        assert!(!is_tailnet_ip("100.128.0.1".parse().unwrap()));
    }

    #[test]
    fn test_find_header_end() {
        assert_eq!(find_header_end(b"a\r\n\r\nb"), Some(1));
        assert_eq!(find_header_end(b"no header here"), None);
        assert_eq!(find_header_end(b""), None);
    }

    #[tokio::test]
    async fn test_parse_request_basic() {
        let raw = b"GET /netmap HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        let mut cursor = std::io::Cursor::new(raw);
        let req = read_request(&mut cursor).await.unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/netmap");
        assert_eq!(req.headers.len(), 2);
        assert_eq!(req.headers[0].0, "Host");
        assert_eq!(req.headers[0].1, "localhost");
        assert!(req.body.is_empty());
    }

    #[tokio::test]
    async fn test_parse_request_with_body() {
        let raw =
            b"POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhello";
        let mut cursor = std::io::Cursor::new(raw);
        let req = read_request(&mut cursor).await.unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/echo");
        assert_eq!(req.body, b"hello");
    }

    async fn send_request(
        addr: SocketAddr,
        raw: &[u8],
    ) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(raw).await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        String::from_utf8(buf).unwrap()
    }

    async fn start_server() -> SocketAddr {
        let backend: Arc<dyn C2nBackend> = Arc::new(FakeBackend);
        let server = C2NServer::new(backend, "test".into());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(server.serve(listener));
        addr
    }

    #[tokio::test]
    async fn handler_returns_501_for_netmap() {
        let addr = start_server().await;
        let resp = send_request(
            addr,
            b"GET /netmap HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("501 Not Implemented"));
        assert!(resp.contains("not implemented"));
    }

    #[tokio::test]
    async fn handler_returns_501_for_prefs() {
        let addr = start_server().await;
        let resp = send_request(
            addr,
            b"GET /prefs HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("501 Not Implemented"));
    }

    #[tokio::test]
    async fn handler_returns_501_for_dns() {
        let addr = start_server().await;
        let resp = send_request(
            addr,
            b"GET /dns HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("501 Not Implemented"));
    }

    #[tokio::test]
    async fn handler_returns_501_for_debug_netmap() {
        let addr = start_server().await;
        let resp = send_request(
            addr,
            b"GET /debug/netmap HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("501 Not Implemented"));
    }

    #[tokio::test]
    async fn handler_returns_501_for_debug_health() {
        let addr = start_server().await;
        let resp = send_request(
            addr,
            b"GET /debug/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("501 Not Implemented"));
    }

    #[tokio::test]
    async fn handler_returns_501_for_logtail_flush() {
        let addr = start_server().await;
        let resp = send_request(
            addr,
            b"POST /logtail/flush HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("501 Not Implemented"));
    }

    #[tokio::test]
    async fn echo_handler_returns_body() {
        let addr = start_server().await;
        let resp = send_request(
            addr,
            b"GET /echo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\nhello-echo",
        )
        .await;
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("hello-echo"));
    }

    #[tokio::test]
    async fn root_returns_endpoint_list_200() {
        let addr = start_server().await;
        let resp = send_request(
            addr,
            b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("200 OK"));
        assert!(resp.contains("/echo"));
        assert!(resp.contains("/netmap"));
        assert!(resp.contains("/prefs"));
    }

    #[tokio::test]
    async fn unknown_path_returns_400() {
        let addr = start_server().await;
        let resp = send_request(
            addr,
            b"GET /nonexistent HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("400 Bad Request"));
        assert!(resp.contains("unknown c2n path"));
    }

    #[tokio::test]
    async fn wrong_method_returns_405() {
        let addr = start_server().await;
        let resp = send_request(
            addr,
            b"POST /netmap HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("405 Method Not Allowed"));
        assert!(resp.contains("bad method"));
    }

    #[tokio::test]
    async fn local_command_returns_501() {
        let addr = start_server().await;
        let resp = send_request(
            addr,
            b"POST /local/ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.contains("501 Not Implemented"));
    }

    #[tokio::test]
    async fn auth_allows_loopback() {
        let backend: Arc<dyn C2nBackend> = Arc::new(FakeBackend);
        assert!(check_auth("127.0.0.1".parse().unwrap(), &backend).await);
        assert!(check_auth("::1".parse().unwrap(), &backend).await);
    }

    #[tokio::test]
    async fn auth_allows_tailnet_ip() {
        let backend: Arc<dyn C2nBackend> = Arc::new(FakeBackend);
        assert!(check_auth("100.64.0.1".parse().unwrap(), &backend).await);
    }

    #[tokio::test]
    async fn auth_rejects_non_tailnet() {
        let backend: Arc<dyn C2nBackend> = Arc::new(FakeBackend);
        assert!(!check_auth("8.8.8.8".parse().unwrap(), &backend).await);
    }

    struct NotFoundBackend;
    #[async_trait]
    impl C2nBackend for NotFoundBackend {
        async fn whois(&self, _ip: IpAddr) -> Option<WhoIsResult> {
            None
        }
    }

    #[tokio::test]
    async fn auth_rejects_tailnet_ip_not_found() {
        let backend: Arc<dyn C2nBackend> = Arc::new(NotFoundBackend);
        assert!(!check_auth("100.64.0.1".parse().unwrap(), &backend).await);
    }
}
