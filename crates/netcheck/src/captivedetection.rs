//! Captive portal detection — ports Go's `net/captivedetection` package.
//!
//! Makes concurrent HTTP GET requests to known detection endpoints (DERP nodes
//! with `CanPort80` plus Tailscale coordination servers) and checks whether the
//! responses look like a captive portal intercepting traffic. An endpoint is
//! considered "captive" if the status code doesn't match the expected value,
//! the `X-Tailscale-Response` challenge header is missing/wrong, or the body
//! doesn't contain the expected token.
//!
//! The HTTP client is a minimal HTTP/1.1 implementation over `tokio::TcpStream`
//! (no redirects, short timeout, no keep-alive) — matching the Go client's
//! configuration without pulling in a heavy HTTP dependency.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustscale_tailcfg::DERPMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Per-request and overall detection timeout. Captive portals are usually
/// on the LAN, so this is short. Mirrors Go's `Timeout`.
pub const DETECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Maximum endpoints to probe in a single detection run.
const MAX_ENDPOINTS: usize = 5;

/// Maximum response body bytes to read for content checking.
const MAX_BODY_READ: usize = 4096;

// ---------------------------------------------------------------------------
// Endpoint types
// ---------------------------------------------------------------------------

/// The source of a captive-portal detection endpoint, used for prioritization.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EndpointProvider {
    /// A DERP node in the current preferred DERP region.
    DerpMapPreferred,
    /// A DERP node in a non-preferred DERP region.
    DerpMapOther,
    /// A Tailscale-run endpoint (controlplane / login).
    Tailscale,
}

impl fmt::Display for EndpointProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DerpMapPreferred => f.write_str("DERPMapPreferred"),
            Self::DerpMapOther => f.write_str("DERPMapOther"),
            Self::Tailscale => f.write_str("Tailscale"),
        }
    }
}

/// A URL to probe for captive-portal detection, plus the expected response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    /// The full URL to GET (e.g. `http://1.2.3.4/generate_204`).
    pub url: String,
    /// The host portion of the URL, extracted for challenge header matching.
    pub host: String,
    /// Expected HTTP status code (e.g. 204).
    pub expected_status: u16,
    /// If non-empty, the response body must contain this substring.
    pub expected_content: String,
    /// Whether the endpoint supports the `X-Tailscale-Challenge` header.
    pub supports_tailscale_challenge: bool,
    /// Source/priority of this endpoint.
    pub provider: EndpointProvider,
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Endpoint{{url={:?}, status={}, content={:?}, challenge={}, provider={}}}",
            self.url,
            self.expected_status,
            self.expected_content,
            self.supports_tailscale_challenge,
            self.provider
        )
    }
}

/// Build the list of captive-portal detection endpoints from a DERPMap and the
/// preferred DERP region ID. Endpoints are sorted by provider priority:
/// preferred-region DERP nodes first, then other DERP nodes, then Tailscale
/// endpoints.
///
/// Ports Go's `availableEndpoints`. When `derp_map` is empty/None, returns
/// only the built-in Tailscale endpoints (Go falls back to dnsfallback's
/// static DERPMap; we include the Tailscale endpoints unconditionally since
/// they're always present).
#[must_use]
pub fn available_endpoints(
    derp_map: Option<&DERPMap>,
    preferred_derp_region: i32,
) -> Vec<Endpoint> {
    let mut endpoints = Vec::new();

    if let Some(dm) = derp_map {
        for region in dm.Regions.values() {
            if region.Avoid || region.NoMeasureNoHome {
                continue;
            }
            let Some(nodes) = region.Nodes.as_ref() else {
                continue;
            };
            for node in nodes {
                if node.IPv4.is_empty() || !node.CanPort80 {
                    continue;
                }
                let provider = if region.RegionID == preferred_derp_region {
                    EndpointProvider::DerpMapPreferred
                } else {
                    EndpointProvider::DerpMapOther
                };
                endpoints.push(Endpoint {
                    url: format!("http://{}/generate_204", node.IPv4),
                    host: node.IPv4.clone(),
                    expected_status: 204,
                    expected_content: String::new(),
                    supports_tailscale_challenge: true,
                    provider,
                });
            }
        }
    }

    // Built-in Tailscale endpoints — always present.
    for host in &["controlplane.tailscale.com", "login.tailscale.com"] {
        endpoints.push(Endpoint {
            url: format!("http://{host}/generate_204"),
            host: (*host).to_string(),
            expected_status: 204,
            expected_content: String::new(),
            supports_tailscale_challenge: false,
            provider: EndpointProvider::Tailscale,
        });
    }

    // Sort by provider priority (DerpMapPreferred < DerpMapOther < Tailscale).
    endpoints.sort_by_key(|e| e.provider);
    endpoints
}

/// Built-in endpoints with no DERPMap (just the Tailscale coordination servers).
#[must_use]
pub fn builtin_endpoints() -> Vec<Endpoint> {
    available_endpoints(None, 0)
}

// ---------------------------------------------------------------------------
// Response validation
// ---------------------------------------------------------------------------

/// Parsed HTTP response (just the parts we need).
#[derive(Debug)]
struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Check whether an HTTP response looks like a captive portal intercepting
/// traffic. Returns `true` if the response does NOT match the expected
/// endpoint semantics (i.e. a captive portal is likely present).
///
/// Ports Go's `Endpoint.responseLooksLikeCaptive`:
/// 1. Status code mismatch → captive.
/// 2. If the endpoint supports the Tailscale challenge, the
///    `X-Tailscale-Response` header must match `response ts_<host>`.
/// 3. If `expected_content` is non-empty, the body must contain it.
fn response_looks_like_captive(resp: &HttpResponse, ep: &Endpoint) -> bool {
    if resp.status != ep.expected_status {
        return true;
    }

    if ep.supports_tailscale_challenge {
        let expected = format!("response ts_{}", ep.host);
        if resp.header("X-Tailscale-Response") != Some(&expected) {
            return true;
        }
    }

    if !ep.expected_content.is_empty() && !memcontains(&resp.body, ep.expected_content.as_bytes()) {
        return true;
    }

    false
}

/// Check if `haystack` contains `needle` (case-sensitive byte substring).
fn memcontains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------------------
// Minimal HTTP/1.1 client
// ---------------------------------------------------------------------------

/// Perform a single HTTP GET to `url`, returning the parsed response.
/// No redirects are followed. Fails on connection errors or response parse
/// errors. The `?t=<timestamp>` query parameter is appended to bust caches,
/// matching Go's behavior.
async fn http_get(url: &str, ep: &Endpoint) -> Result<HttpResponse, std::io::Error> {
    // Parse the URL manually (it's always http://host[:port]/path?query).
    let (host_port, path) = parse_http_url(url)?;

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    // Build the request.
    let mut req = format!(
        "GET {path}?t={now_secs} HTTP/1.1\r\n\
         Host: {host_port}\r\n\
         Cache-Control: no-cache, no-store, must-revalidate, no-transform, max-age=0\r\n\
         Connection: close\r\n"
    );
    if ep.supports_tailscale_challenge {
        req.push_str("X-Tailscale-Challenge: ts_");
        req.push_str(&ep.host);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");

    let stream = TcpStream::connect(&host_port).await?;
    // Set a read/write timeout via tokio's timeout wrapper instead.
    let mut stream = stream;

    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    // Read the full response. Since we send Connection: close, the server
    // closes after sending, so we can read to EOF.
    let mut raw = Vec::with_capacity(1024);
    loop {
        let mut buf = [0u8; 4096];
        match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
    }

    parse_http_response(&raw)
}

/// Parse `http://host[:port]/path` into `(host_port, path)`.
fn parse_http_url(url: &str) -> Result<(String, String), std::io::Error> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "not http:// URL"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    Ok((authority.to_string(), path.to_string()))
}

/// Parse a raw HTTP/1.1 response into [`HttpResponse`].
fn parse_http_response(raw: &[u8]) -> Result<HttpResponse, std::io::Error> {
    // Find the header/body boundary (\r\n\r\n).
    let boundary = find_subsequence(raw, b"\r\n\r\n").ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "no header/body boundary")
    })?;

    let header_bytes = &raw[..boundary];
    let body = &raw[boundary + 4..];

    let header_str = std::str::from_utf8(header_bytes)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "non-UTF-8 headers"))?;

    let mut lines = header_str.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "empty response"))?;

    // Parse "HTTP/1.1 204 No Content"
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad status line"))?;

    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(": ") {
            headers.push((k.to_string(), v.trim().to_string()));
        }
    }

    // Truncate body to MAX_BODY_READ for the content check.
    let body = if body.len() > MAX_BODY_READ {
        body[..MAX_BODY_READ].to_vec()
    } else {
        body.to_vec()
    };

    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

// ---------------------------------------------------------------------------
// Detector
// ---------------------------------------------------------------------------

/// Detects whether the system is behind a captive portal by making HTTP
/// requests to known detection endpoints. Cheap to construct; stateless.
///
/// Ports Go's `captivedetection.Detector`. Interface binding is not implemented
/// in this first pass — requests go out via the default route, which is
/// sufficient for most cases (the Go code's per-interface logic is mainly
/// needed for macOS before the user accepts the portal alert).
#[derive(Debug, Clone)]
pub struct Detector;

/// The outcome of a detection run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectResult {
    /// A captive portal was detected.
    CaptivePortal,
    /// No captive portal was detected.
    NoCaptivePortal,
    /// Detection was inconclusive (all requests failed or no endpoints).
    Inconclusive,
}

impl Detector {
    /// Run captive portal detection. Probes up to [`MAX_ENDPOINTS`] endpoints
    /// concurrently; if any returns a response that looks like a captive
    /// portal, returns `CaptivePortal`. If any returns a clean response and
    /// none look captive, returns `NoCaptivePortal`. If all requests fail,
    /// returns `Inconclusive`.
    ///
    /// Use [`Detector::detect_bool`] for the `Option<bool>` form
    /// (`Some(true)` = captive, `Some(false)` = not captive, `None` =
    /// inconclusive).
    pub async fn detect(
        &self,
        derp_map: Option<&DERPMap>,
        preferred_derp_region: i32,
    ) -> DetectResult {
        let endpoints = available_endpoints(derp_map, preferred_derp_region);
        self.detect_with_endpoints(&endpoints).await
    }

    /// Run detection against an explicit endpoint list (useful for tests).
    pub async fn detect_with_endpoints(&self, endpoints: &[Endpoint]) -> DetectResult {
        if endpoints.is_empty() {
            return DetectResult::Inconclusive;
        }

        let use_count = endpoints.len().min(MAX_ENDPOINTS);
        let endpoints = &endpoints[..use_count];

        let mut tasks = Vec::with_capacity(endpoints.len());
        for ep in endpoints {
            let ep = ep.clone();
            tasks.push(tokio::spawn(async move {
                match timeout(DETECT_TIMEOUT, http_get(&ep.url, &ep)).await {
                    Ok(Ok(resp)) => {
                        let captive = response_looks_like_captive(&resp, &ep);
                        Some(captive)
                    }
                    Ok(Err(_)) | Err(_) => None,
                }
            }));
        }

        let mut any_clean = false;
        for task in tasks {
            if let Ok(Some(captive)) = task.await {
                if captive {
                    return DetectResult::CaptivePortal;
                }
                any_clean = true;
            }
        }

        if any_clean {
            DetectResult::NoCaptivePortal
        } else {
            DetectResult::Inconclusive
        }
    }

    /// Convenience wrapper returning `Option<bool>`:
    /// - `Some(true)` = captive portal detected
    /// - `Some(false)` = no captive portal
    /// - `None` = inconclusive
    pub async fn detect_bool(
        &self,
        derp_map: Option<&DERPMap>,
        preferred_derp_region: i32,
    ) -> Option<bool> {
        match self.detect(derp_map, preferred_derp_region).await {
            DetectResult::CaptivePortal => Some(true),
            DetectResult::NoCaptivePortal => Some(false),
            DetectResult::Inconclusive => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
