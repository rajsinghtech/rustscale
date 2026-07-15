//! Control-to-Node (C2N) request routing and bounded callback handling.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rustscale_tailcfg::PingRequest;

/// Maximum HTTP-formatted C2N request payload accepted from control.
pub const MAX_C2N_REQUEST_BYTES: usize = 256 * 1024;
/// Maximum C2N response sent back to control.
pub const MAX_C2N_RESPONSE_BYTES: usize = 512 * 1024;
const MAX_REQUEST_TARGET_BYTES: usize = 8 * 1024;
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_HEADERS: usize = 100;
const DEFAULT_HANDLER_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_HANDLER_TIMEOUT: Duration = Duration::from_secs(60);
const REPLY_TIMEOUT: Duration = Duration::from_secs(30);

/// A single C2N request. `path` contains the origin-form request target,
/// including its query string when present.
#[derive(Debug, Clone)]
pub struct C2nRequest {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
}

/// A C2N response sent back over the Noise control channel.
#[derive(Debug, Clone)]
pub struct C2nResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

impl C2nResponse {
    pub fn ok(body: Vec<u8>) -> Self {
        Self { status: 200, body }
    }

    pub fn error(status: u16, msg: impl Into<String>) -> Self {
        Self {
            status,
            body: msg.into().into_bytes(),
        }
    }

    pub fn no_content() -> Self {
        Self {
            status: 204,
            body: vec![],
        }
    }

    pub fn text(status: u16, msg: impl Into<String>) -> Self {
        Self {
            status,
            body: msg.into().into_bytes(),
        }
    }

    pub fn json(status: u16, value: &serde_json::Value) -> Self {
        Self {
            status,
            body: serde_json::to_vec(value).unwrap_or_default(),
        }
    }
}

/// A C2N handler processes a single request and returns a response.
#[async_trait]
pub trait C2nHandler: Send + Sync {
    async fn handle(&self, req: C2nRequest) -> C2nResponse;
}

/// Routes incoming C2N requests to registered handlers by URL path.
#[derive(Default)]
pub struct C2nRouter {
    exact: HashMap<(String, String), Arc<dyn C2nHandler>>,
    fallback: HashMap<String, Arc<dyn C2nHandler>>,
}

impl C2nRouter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, pattern: &str, handler: Arc<dyn C2nHandler>) {
        if let Some((method, path)) = pattern.split_once(' ') {
            self.exact
                .insert((method.to_string(), path.to_string()), handler);
        } else {
            self.fallback.insert(pattern.to_string(), handler);
        }
    }

    pub async fn route(&self, req: C2nRequest) -> C2nResponse {
        let route_path = req.path.split_once('?').map_or(req.path.as_str(), |v| v.0);
        if let Some(handler) = self
            .exact
            .get(&(req.method.clone(), route_path.to_string()))
        {
            return handler.handle(req).await;
        }
        if let Some(handler) = self.fallback.get(route_path) {
            return handler.handle(req).await;
        }
        let known = self.exact.keys().any(|(_, path)| path == route_path)
            || self.fallback.contains_key(route_path);
        if known {
            C2nResponse::error(405, "bad method")
        } else {
            C2nResponse::error(400, "unknown c2n path")
        }
    }
}

/// Injectable same-session transport for a serialized C2N HTTP response.
#[async_trait]
pub trait C2nReplyTransport: Send + Sync {
    async fn send(&self, callback_path: &str, response: Vec<u8>) -> Result<(), C2nReplyError>;
}

/// Privacy-safe C2N handling failures. Values supplied by control and posture
/// identity data are intentionally absent from Display output.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum C2nReplyError {
    #[error("C2N request is invalid")]
    InvalidRequest,
    #[error("C2N request exceeds a size limit")]
    RequestTooLarge,
    #[error("C2N handler timed out")]
    HandlerTimeout,
    #[error("C2N response exceeds a size limit")]
    ResponseTooLarge,
    #[error("C2N callback URL is invalid")]
    InvalidCallback,
    #[error("C2N callback transport failed")]
    Transport,
    #[error("C2N callback timed out")]
    ReplyTimeout,
}

/// Parse, route, and return one `Types == "c2n"` ping request.
///
/// Dropping this future cancels handler or transport work. Independent hard
/// deadlines bound both phases.
pub async fn answer_c2n_ping(
    router: &C2nRouter,
    transport: &dyn C2nReplyTransport,
    ping: &PingRequest,
) -> Result<(), C2nReplyError> {
    if ping.Types != "c2n" || ping.URL.is_empty() {
        return Err(C2nReplyError::InvalidRequest);
    }
    let callback_path = callback_path(&ping.URL)?;
    let parsed = parse_http_request(&ping.Payload)?;
    let response = tokio::time::timeout(parsed.timeout, router.route(parsed.request))
        .await
        .map_err(|_| C2nReplyError::HandlerTimeout)?;
    let response = serialize_http_response(response)?;
    tokio::time::timeout(REPLY_TIMEOUT, transport.send(&callback_path, response))
        .await
        .map_err(|_| C2nReplyError::ReplyTimeout)??;
    Ok(())
}

struct ParsedRequest {
    request: C2nRequest,
    timeout: Duration,
}

fn parse_http_request(payload: &[u8]) -> Result<ParsedRequest, C2nReplyError> {
    if payload.len() > MAX_C2N_REQUEST_BYTES {
        return Err(C2nReplyError::RequestTooLarge);
    }
    let header_end = payload
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(C2nReplyError::InvalidRequest)?;
    if header_end > MAX_HEADER_BYTES {
        return Err(C2nReplyError::RequestTooLarge);
    }
    let header =
        std::str::from_utf8(&payload[..header_end]).map_err(|_| C2nReplyError::InvalidRequest)?;
    let mut lines = header.split("\r\n");
    let request_line = lines.next().ok_or(C2nReplyError::InvalidRequest)?;
    let mut request_parts = request_line.split(' ');
    let method = request_parts.next().ok_or(C2nReplyError::InvalidRequest)?;
    let target = request_parts.next().ok_or(C2nReplyError::InvalidRequest)?;
    let version = request_parts.next().ok_or(C2nReplyError::InvalidRequest)?;
    if request_parts.next().is_some()
        || method.is_empty()
        || !method.bytes().all(is_token_byte)
        || target.len() > MAX_REQUEST_TARGET_BYTES
        || !target.starts_with('/')
        || target.starts_with("//")
        || target
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
    {
        return Err(C2nReplyError::InvalidRequest);
    }

    let mut content_length = None;
    let mut timeout = DEFAULT_HANDLER_TIMEOUT;
    let mut count = 0;
    for line in lines {
        count += 1;
        if count > MAX_HEADERS || line.starts_with([' ', '\t']) {
            return Err(C2nReplyError::InvalidRequest);
        }
        let (name, value) = line.split_once(':').ok_or(C2nReplyError::InvalidRequest)?;
        if name.is_empty() || !name.bytes().all(is_token_byte) {
            return Err(C2nReplyError::InvalidRequest);
        }
        let value = value.trim();
        if value.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(C2nReplyError::InvalidRequest);
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(C2nReplyError::InvalidRequest);
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(C2nReplyError::InvalidRequest);
            }
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| C2nReplyError::InvalidRequest)?,
            );
        }
        if name.eq_ignore_ascii_case("c2n-handler-timeout") {
            timeout = parse_timeout(value)?;
        }
    }

    let body = &payload[header_end + 4..];
    if content_length.unwrap_or(0) != body.len() {
        return Err(C2nReplyError::InvalidRequest);
    }
    Ok(ParsedRequest {
        request: C2nRequest {
            method: method.to_owned(),
            path: target.to_owned(),
            body: body.to_vec(),
        },
        timeout,
    })
}

fn parse_timeout(value: &str) -> Result<Duration, C2nReplyError> {
    let duration = if let Some(value) = value.strip_suffix("ms") {
        Duration::from_millis(value.parse().map_err(|_| C2nReplyError::InvalidRequest)?)
    } else if let Some(value) = value.strip_suffix('s') {
        Duration::from_secs(value.parse().map_err(|_| C2nReplyError::InvalidRequest)?)
    } else if let Some(value) = value.strip_suffix('m') {
        Duration::from_secs(
            value
                .parse::<u64>()
                .map_err(|_| C2nReplyError::InvalidRequest)?
                .checked_mul(60)
                .ok_or(C2nReplyError::InvalidRequest)?,
        )
    } else {
        return Err(C2nReplyError::InvalidRequest);
    };
    if duration.is_zero() || duration > MAX_HANDLER_TIMEOUT {
        return Err(C2nReplyError::InvalidRequest);
    }
    Ok(duration)
}

fn callback_path(value: &str) -> Result<String, C2nReplyError> {
    if value.len() > MAX_REQUEST_TARGET_BYTES {
        return Err(C2nReplyError::InvalidCallback);
    }
    let uri: http::Uri = value.parse().map_err(|_| C2nReplyError::InvalidCallback)?;
    if uri
        .scheme()
        .is_some_and(|scheme| scheme != "http" && scheme != "https")
    {
        return Err(C2nReplyError::InvalidCallback);
    }
    let path = uri
        .path_and_query()
        .map_or("/", http::uri::PathAndQuery::as_str);
    if !path.starts_with('/') || path.starts_with("//") {
        return Err(C2nReplyError::InvalidCallback);
    }
    Ok(path.to_owned())
}

fn serialize_http_response(response: C2nResponse) -> Result<Vec<u8>, C2nReplyError> {
    if response.body.len() > MAX_C2N_RESPONSE_BYTES {
        return Err(C2nReplyError::ResponseTooLarge);
    }
    let reason = http::StatusCode::from_u16(response.status)
        .ok()
        .and_then(|status| status.canonical_reason())
        .unwrap_or("Unknown");
    let mut bytes = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\n",
        response.status,
        reason,
        response.body.len()
    )
    .into_bytes();
    bytes.extend_from_slice(b"Connection: close\r\n\r\n");
    bytes.extend_from_slice(&response.body);
    if bytes.len() > MAX_C2N_RESPONSE_BYTES {
        return Err(C2nReplyError::ResponseTooLarge);
    }
    Ok(bytes)
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    struct EchoHandler;
    #[async_trait]
    impl C2nHandler for EchoHandler {
        async fn handle(&self, req: C2nRequest) -> C2nResponse {
            C2nResponse::ok(req.body)
        }
    }

    #[derive(Default)]
    struct FakeTransport(Mutex<Vec<(String, Vec<u8>)>>);
    #[async_trait]
    impl C2nReplyTransport for FakeTransport {
        async fn send(&self, path: &str, response: Vec<u8>) -> Result<(), C2nReplyError> {
            self.0.lock().unwrap().push((path.to_owned(), response));
            Ok(())
        }
    }

    fn request(path: &str, body: &[u8]) -> Vec<u8> {
        format!(
            "POST {path} HTTP/1.1\r\nHost: node\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes()
        .into_iter()
        .chain(body.iter().copied())
        .collect()
    }

    #[tokio::test]
    async fn route_ignores_query_for_dispatch() {
        let mut router = C2nRouter::new();
        router.register("POST /echo", Arc::new(EchoHandler));
        let response = router
            .route(C2nRequest {
                method: "POST".into(),
                path: "/echo?x=1".into(),
                body: b"hello".to_vec(),
            })
            .await;
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"hello");
    }

    #[tokio::test]
    async fn answers_c2n_over_injected_transport() {
        let mut router = C2nRouter::new();
        router.register("POST /echo", Arc::new(EchoHandler));
        let transport = FakeTransport::default();
        let ping = PingRequest {
            URL: "https://control.example/callback?id=1".into(),
            Types: "c2n".into(),
            Payload: request("/echo", b"secret"),
            ..PingRequest::default()
        };
        answer_c2n_ping(&router, &transport, &ping).await.unwrap();
        let sent = transport.0.lock().unwrap();
        assert_eq!(sent[0].0, "/callback?id=1");
        assert!(sent[0].1.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(sent[0].1.ends_with(b"\r\n\r\nsecret"));
    }

    #[test]
    fn parser_rejects_oversize_smuggling_and_bad_lengths() {
        assert_eq!(
            parse_http_request(&vec![b'x'; MAX_C2N_REQUEST_BYTES + 1]).err(),
            Some(C2nReplyError::RequestTooLarge)
        );
        assert_eq!(
            parse_http_request(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
                .err(),
            Some(C2nReplyError::InvalidRequest)
        );
        assert_eq!(
            parse_http_request(b"POST / HTTP/1.1\r\nContent-Length: 9\r\n\r\nshort").err(),
            Some(C2nReplyError::InvalidRequest)
        );
    }

    #[test]
    fn callback_and_timeout_are_bounded() {
        assert_eq!(
            callback_path("file:///tmp/no"),
            Err(C2nReplyError::InvalidCallback)
        );
        assert_eq!(parse_timeout("61s"), Err(C2nReplyError::InvalidRequest));
        assert_eq!(parse_timeout("500ms"), Ok(Duration::from_millis(500)));
    }

    #[tokio::test]
    async fn router_reports_unknown_and_bad_method() {
        let mut router = C2nRouter::new();
        router.register("POST /echo", Arc::new(EchoHandler));
        let bad_method = router
            .route(C2nRequest {
                method: "GET".into(),
                path: "/echo".into(),
                body: vec![],
            })
            .await;
        assert_eq!(bad_method.status, 405);
        let unknown = router
            .route(C2nRequest {
                method: "GET".into(),
                path: "/nope".into(),
                body: vec![],
            })
            .await;
        assert_eq!(unknown.status, 400);
    }
}
