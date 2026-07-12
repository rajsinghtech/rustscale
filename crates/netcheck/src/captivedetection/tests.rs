//! Captive portal detection tests: endpoint generation from a fake DERPMap,
//! response validation table tests, and end-to-end detection against a local
//! HTTP test server simulating clean (204) and captive (redirect / body
//! mismatch) responses.

use std::collections::BTreeMap;
use std::time::Duration;

use rustscale_tailcfg::{DERPMap, DERPNode, DERPRegion};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;

// ---------------------------------------------------------------------------
// Endpoint generation tests
// ---------------------------------------------------------------------------

fn fake_derp_map() -> DERPMap {
    let mut regions = BTreeMap::new();
    // Region 1 — preferred, has a CanPort80 node and a non-CanPort80 node.
    regions.insert(
        1,
        DERPRegion {
            RegionID: 1,
            RegionCode: "nyc".into(),
            RegionName: "New York".into(),
            Nodes: Some(vec![
                DERPNode {
                    Name: "1a".into(),
                    RegionID: 1,
                    HostName: "derp1.tailscale.com".into(),
                    IPv4: "10.0.0.1".into(),
                    CanPort80: true,
                    ..Default::default()
                },
                DERPNode {
                    Name: "1b".into(),
                    RegionID: 1,
                    HostName: "derp2.tailscale.com".into(),
                    IPv4: "10.0.0.2".into(),
                    CanPort80: false,
                    ..Default::default()
                },
            ]),
            ..Default::default()
        },
    );
    // Region 2 — non-preferred, CanPort80 node.
    regions.insert(
        2,
        DERPRegion {
            RegionID: 2,
            RegionCode: "sf".into(),
            RegionName: "San Francisco".into(),
            Nodes: Some(vec![DERPNode {
                Name: "2a".into(),
                RegionID: 2,
                HostName: "derp3.tailscale.com".into(),
                IPv4: "10.0.0.3".into(),
                CanPort80: true,
                ..Default::default()
            }]),
            ..Default::default()
        },
    );
    // Region 3 — Avoid, should be skipped even if CanPort80.
    regions.insert(
        3,
        DERPRegion {
            RegionID: 3,
            RegionCode: "tok".into(),
            RegionName: "Tokyo".into(),
            Avoid: true,
            Nodes: Some(vec![DERPNode {
                Name: "3a".into(),
                RegionID: 3,
                HostName: "derp4.tailscale.com".into(),
                IPv4: "10.0.0.4".into(),
                CanPort80: true,
                ..Default::default()
            }]),
            ..Default::default()
        },
    );
    // Region 4 — NoMeasureNoHome, should be skipped.
    regions.insert(
        4,
        DERPRegion {
            RegionID: 4,
            RegionCode: "sin".into(),
            RegionName: "Singapore".into(),
            NoMeasureNoHome: true,
            Nodes: Some(vec![DERPNode {
                Name: "4a".into(),
                RegionID: 4,
                HostName: "derp5.tailscale.com".into(),
                IPv4: "10.0.0.5".into(),
                CanPort80: true,
                ..Default::default()
            }]),
            ..Default::default()
        },
    );
    // Region 5 — node with no IPv4, should be skipped.
    regions.insert(
        5,
        DERPRegion {
            RegionID: 5,
            RegionCode: "lon".into(),
            RegionName: "London".into(),
            Nodes: Some(vec![DERPNode {
                Name: "5a".into(),
                RegionID: 5,
                HostName: "derp6.tailscale.com".into(),
                IPv4: String::new(),
                CanPort80: true,
                ..Default::default()
            }]),
            ..Default::default()
        },
    );
    DERPMap {
        Regions: regions,
        ..Default::default()
    }
}

#[test]
fn endpoint_generation_from_derp_map() {
    let dm = fake_derp_map();
    let eps = available_endpoints(Some(&dm), 1);

    // Region 1 node 1a (CanPort80, preferred), Region 2 node 2a (CanPort80,
    // non-preferred), plus 2 Tailscale endpoints = 4 total.
    assert_eq!(eps.len(), 4, "expected 4 endpoints, got {eps:?}");

    // Preferred DERP region endpoint comes first.
    assert_eq!(eps[0].provider, EndpointProvider::DerpMapPreferred);
    assert_eq!(eps[0].url, "http://10.0.0.1/generate_204");
    assert_eq!(eps[0].expected_status, 204);
    assert!(eps[0].supports_tailscale_challenge);

    // Then other DERP region.
    assert_eq!(eps[1].provider, EndpointProvider::DerpMapOther);
    assert_eq!(eps[1].url, "http://10.0.0.3/generate_204");

    // Then Tailscale endpoints.
    assert_eq!(eps[2].provider, EndpointProvider::Tailscale);
    assert_eq!(eps[2].url, "http://controlplane.tailscale.com/generate_204");
    assert!(!eps[2].supports_tailscale_challenge);
    assert_eq!(eps[3].provider, EndpointProvider::Tailscale);
    assert_eq!(eps[3].url, "http://login.tailscale.com/generate_204");
}

#[test]
fn endpoint_generation_no_derp_map() {
    let eps = available_endpoints(None, 0);
    assert_eq!(eps.len(), 2);
    assert!(eps
        .iter()
        .all(|e| e.provider == EndpointProvider::Tailscale));
}

#[test]
fn endpoint_generation_empty_derp_map() {
    let dm = DERPMap::default();
    let eps = available_endpoints(Some(&dm), 0);
    assert_eq!(
        eps.len(),
        2,
        "empty DERPMap should yield only Tailscale endpoints"
    );
}

#[test]
fn endpoint_generation_skips_avoid_and_no_measure() {
    let dm = fake_derp_map();
    let eps = available_endpoints(Some(&dm), 1);
    // No endpoint from region 3 (Avoid) or region 4 (NoMeasureNoHome).
    assert!(
        !eps.iter().any(|e| e.url.contains("10.0.0.4")),
        "Avoid region should be skipped"
    );
    assert!(
        !eps.iter().any(|e| e.url.contains("10.0.0.5")),
        "NoMeasureNoHome region should be skipped"
    );
    assert!(
        !eps.iter().any(|e| e.url.contains("10.0.0.2")),
        "CanPort80=false node should be skipped"
    );
}

#[test]
fn builtin_endpoints_are_tailscale() {
    let eps = builtin_endpoints();
    assert_eq!(eps.len(), 2);
    assert!(eps
        .iter()
        .all(|e| e.provider == EndpointProvider::Tailscale));
}

// ---------------------------------------------------------------------------
// Response validation table tests
// ---------------------------------------------------------------------------

fn make_response(status: u16, headers: &[(&str, &str)], body: &[u8]) -> HttpResponse {
    HttpResponse {
        status,
        headers: headers
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect(),
        body: body.to_vec(),
    }
}

fn derp_endpoint(host: &str) -> Endpoint {
    Endpoint {
        url: format!("http://{host}/generate_204"),
        host: host.to_string(),
        expected_status: 204,
        expected_content: String::new(),
        supports_tailscale_challenge: true,
        provider: EndpointProvider::DerpMapPreferred,
    }
}

fn tailscale_endpoint(host: &str) -> Endpoint {
    Endpoint {
        url: format!("http://{host}/generate_204"),
        host: host.to_string(),
        expected_status: 204,
        expected_content: String::new(),
        supports_tailscale_challenge: false,
        provider: EndpointProvider::Tailscale,
    }
}

fn endpoint_with_content(host: &str, content: &str) -> Endpoint {
    Endpoint {
        url: format!("http://{host}/check"),
        host: host.to_string(),
        expected_status: 200,
        expected_content: content.to_string(),
        supports_tailscale_challenge: false,
        provider: EndpointProvider::Tailscale,
    }
}

#[test]
fn validation_table() {
    let cases: &[(&str, HttpResponse, Endpoint, bool)] = &[
        // 1. Clean 204, DERP endpoint with correct challenge response → not captive.
        (
            "clean 204 with challenge",
            make_response(
                204,
                &[("X-Tailscale-Response", "response ts_10.0.0.1")],
                &[],
            ),
            derp_endpoint("10.0.0.1"),
            false,
        ),
        // 2. Clean 204, Tailscale endpoint (no challenge) → not captive.
        (
            "clean 204 no challenge",
            make_response(204, &[], &[]),
            tailscale_endpoint("controlplane.tailscale.com"),
            false,
        ),
        // 3. Status code mismatch (302 redirect) → captive.
        (
            "302 redirect",
            make_response(302, &[("Location", "http://portal.example.com/")], &[]),
            derp_endpoint("10.0.0.1"),
            true,
        ),
        // 4. 200 instead of 204 → captive.
        (
            "200 instead of 204",
            make_response(200, &[], b"OK"),
            derp_endpoint("10.0.0.1"),
            true,
        ),
        // 5. Missing X-Tailscale-Response header → captive.
        (
            "missing challenge response",
            make_response(204, &[], &[]),
            derp_endpoint("10.0.0.1"),
            true,
        ),
        // 6. Wrong X-Tailscale-Response header → captive.
        (
            "wrong challenge response",
            make_response(204, &[("X-Tailscale-Response", "bogus")], &[]),
            derp_endpoint("10.0.0.1"),
            true,
        ),
        // 7. Body content mismatch → captive.
        (
            "body mismatch",
            make_response(200, &[], b"<html>captive portal</html>"),
            endpoint_with_content("example.com", "expected-token"),
            true,
        ),
        // 8. Body content match → not captive.
        (
            "body match",
            make_response(200, &[], b"hello expected-token world"),
            endpoint_with_content("example.com", "expected-token"),
            false,
        ),
        // 9. 500 error → captive (status mismatch).
        (
            "500 error",
            make_response(500, &[], b"Internal Server Error"),
            tailscale_endpoint("controlplane.tailscale.com"),
            true,
        ),
        // 10. Empty body with no expected content → not captive (204 case).
        (
            "empty body no expectation",
            make_response(204, &[("X-Tailscale-Response", "response ts_1.2.3.4")], &[]),
            derp_endpoint("1.2.3.4"),
            false,
        ),
    ];

    for (name, resp, ep, expected_captive) in cases {
        let actual = response_looks_like_captive(resp, ep);
        assert_eq!(
            actual, *expected_captive,
            "test case {name:?}: expected captive={expected_captive}, got {actual}"
        );
    }
}

#[test]
fn memcontains_basic() {
    assert!(memcontains(b"hello world", b"world"));
    assert!(memcontains(b"hello world", b"hello"));
    assert!(memcontains(b"hello", b""));
    assert!(!memcontains(b"hello", b"world"));
    assert!(!memcontains(b"hi", b"hello"));
}

// ---------------------------------------------------------------------------
// URL parsing tests
// ---------------------------------------------------------------------------

#[test]
fn parse_http_url_basic() {
    let (authority, path) = parse_http_url("http://10.0.0.1/generate_204").unwrap();
    assert_eq!(authority, "10.0.0.1");
    assert_eq!(path, "/generate_204");
}

#[test]
fn parse_http_url_with_port() {
    let (authority, path) = parse_http_url("http://example.com:8080/check").unwrap();
    assert_eq!(authority, "example.com:8080");
    assert_eq!(path, "/check");
}

#[test]
fn parse_http_url_no_path() {
    let (authority, path) = parse_http_url("http://example.com").unwrap();
    assert_eq!(authority, "example.com");
    assert_eq!(path, "/");
}

#[test]
fn parse_http_url_rejects_https() {
    assert!(parse_http_url("https://example.com/").is_err());
}

// ---------------------------------------------------------------------------
// HTTP response parsing tests
// ---------------------------------------------------------------------------

#[test]
fn parse_simple_204() {
    let raw = b"HTTP/1.1 204 No Content\r\n\
                X-Tailscale-Response: response ts_10.0.0.1\r\n\
                Content-Length: 0\r\n\
                \r\n";
    let resp = parse_http_response(raw).unwrap();
    assert_eq!(resp.status, 204);
    assert_eq!(
        resp.header("X-Tailscale-Response"),
        Some("response ts_10.0.0.1")
    );
    assert!(resp.body.is_empty());
}

#[test]
fn parse_response_with_body() {
    let raw = b"HTTP/1.1 200 OK\r\n\
                Content-Length: 13\r\n\
                \r\n\
                hello, world!";
    let resp = parse_http_response(raw).unwrap();
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"hello, world!");
}

#[test]
fn parse_response_case_insensitive_headers() {
    let raw = b"HTTP/1.1 204 No Content\r\n\
                x-tailscale-response: response ts_1.2.3.4\r\n\
                \r\n";
    let resp = parse_http_response(raw).unwrap();
    assert_eq!(
        resp.header("X-Tailscale-Response"),
        Some("response ts_1.2.3.4")
    );
}

// ---------------------------------------------------------------------------
// End-to-end detection tests against a local HTTP test server
// ---------------------------------------------------------------------------

/// A minimal HTTP test server that responds to all requests with a fixed
/// status code, optional headers, and optional body. Simulates what a
/// hyper/axum test server would do for our detection probes.
struct TestHttpServer {
    addr: std::net::SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl TestHttpServer {
    async fn start(
        status: u16,
        extra_headers: Vec<(String, String)>,
        body: Vec<u8>,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            let mut shutdown_rx = std::pin::pin!(shutdown_rx);
            loop {
                let accept = tokio::select! {
                    biased;
                    _ = &mut shutdown_rx => break,
                    r = listener.accept() => r,
                };
                let (mut sock, _) = match accept {
                    Ok(c) => c,
                    Err(_) => break,
                };

                let status_line = format!("HTTP/1.1 {status} OK\r\n");
                let mut header_lines = String::new();
                for (k, v) in &extra_headers {
                    header_lines.push_str(k);
                    header_lines.push_str(": ");
                    header_lines.push_str(v);
                    header_lines.push_str("\r\n");
                }
                header_lines.push_str("Content-Length: ");
                header_lines.push_str(&body.len().to_string());
                header_lines.push_str("\r\n");
                header_lines.push_str("Connection: close\r\n");

                let response = format!("{status_line}{header_lines}\r\n");
                let _ = sock.write_all(response.as_bytes()).await;
                if !body.is_empty() {
                    let _ = sock.write_all(&body).await;
                }
                let _ = sock.flush().await;

                // Drain the incoming request (client sends then we respond).
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf).await;
            }
        });

        Ok(Self {
            addr,
            shutdown: Some(shutdown_tx),
        })
    }
}

impl Drop for TestHttpServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

#[tokio::test]
async fn detect_clean_204_no_captive() {
    // Server returns 204 with the correct X-Tailscale-Response header.
    // The challenge response must match "response ts_<host:port>".
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let host = format!("127.0.0.1:{port}");
    let challenge_resp = format!("response ts_{host}");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let mut shutdown_rx = std::pin::pin!(shutdown_rx);
        loop {
            let accept = tokio::select! {
                biased;
                _ = &mut shutdown_rx => break,
                r = listener.accept() => r,
            };
            let (mut sock, _) = match accept {
                Ok(c) => c,
                Err(_) => break,
            };
            let resp = format!(
                "HTTP/1.1 204 No Content\r\n\
                 X-Tailscale-Response: {challenge_resp}\r\n\
                 Content-Length: 0\r\n\
                 Connection: close\r\n\
                 \r\n"
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.flush().await;
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).await;
        }
    });

    let ep = Endpoint {
        url: format!("http://{host}/generate_204"),
        host: host.clone(),
        expected_status: 204,
        expected_content: String::new(),
        supports_tailscale_challenge: true,
        provider: EndpointProvider::DerpMapPreferred,
    };

    let detector = Detector;
    let result = detector.detect_with_endpoints(&[ep]).await;
    assert_eq!(
        result,
        DetectResult::NoCaptivePortal,
        "clean 204 should not be captive"
    );

    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn detect_captive_redirect() {
    // Server returns a 302 redirect — typical captive portal behavior.
    let server = TestHttpServer::start(
        302,
        vec![("Location".into(), "http://portal.example.com/login".into())],
        b"<html>Redirecting...</html>".to_vec(),
    )
    .await
    .unwrap();

    let ep = Endpoint {
        url: format!("http://127.0.0.1:{}/generate_204", server.addr.port()),
        host: format!("127.0.0.1:{}", server.addr.port()),
        expected_status: 204,
        expected_content: String::new(),
        supports_tailscale_challenge: true,
        provider: EndpointProvider::DerpMapPreferred,
    };

    let detector = Detector;
    let result = detector.detect_with_endpoints(&[ep]).await;
    assert_eq!(
        result,
        DetectResult::CaptivePortal,
        "302 redirect should be captive"
    );
}

#[tokio::test]
async fn detect_captive_body_mismatch() {
    // Server returns 200 with HTML body instead of 204 with no content.
    let server = TestHttpServer::start(
        200,
        vec![],
        b"<html><body>Please log in to continue</body></html>".to_vec(),
    )
    .await
    .unwrap();

    let ep = Endpoint {
        url: format!("http://127.0.0.1:{}/check", server.addr.port()),
        host: format!("127.0.0.1:{}", server.addr.port()),
        expected_status: 200,
        expected_content: "expected-token".into(),
        supports_tailscale_challenge: false,
        provider: EndpointProvider::Tailscale,
    };

    let detector = Detector;
    let result = detector.detect_with_endpoints(&[ep]).await;
    assert_eq!(
        result,
        DetectResult::CaptivePortal,
        "body mismatch should be captive"
    );
}

#[tokio::test]
async fn detect_captive_missing_challenge_header() {
    // Server returns 204 but doesn't echo the X-Tailscale-Response header.
    let server = TestHttpServer::start(204, vec![], vec![]).await.unwrap();

    let ep = Endpoint {
        url: format!("http://127.0.0.1:{}/generate_204", server.addr.port()),
        host: format!("127.0.0.1:{}", server.addr.port()),
        expected_status: 204,
        expected_content: String::new(),
        supports_tailscale_challenge: true,
        provider: EndpointProvider::DerpMapPreferred,
    };

    let detector = Detector;
    let result = detector.detect_with_endpoints(&[ep]).await;
    assert_eq!(
        result,
        DetectResult::CaptivePortal,
        "missing challenge header should be captive"
    );
}

#[tokio::test]
async fn detect_body_match_not_captive() {
    let server = TestHttpServer::start(200, vec![], b"hello expected-token".to_vec())
        .await
        .unwrap();

    let ep = Endpoint {
        url: format!("http://127.0.0.1:{}/check", server.addr.port()),
        host: format!("127.0.0.1:{}", server.addr.port()),
        expected_status: 200,
        expected_content: "expected-token".into(),
        supports_tailscale_challenge: false,
        provider: EndpointProvider::Tailscale,
    };

    let detector = Detector;
    let result = detector.detect_with_endpoints(&[ep]).await;
    assert_eq!(
        result,
        DetectResult::NoCaptivePortal,
        "body match should not be captive"
    );
}

#[tokio::test]
async fn detect_inconclusive_on_connection_failure() {
    // Endpoint pointing at a port that's definitely not listening.
    let ep = Endpoint {
        url: "http://127.0.0.1:1/generate_204".into(),
        host: "127.0.0.1:1".into(),
        expected_status: 204,
        expected_content: String::new(),
        supports_tailscale_challenge: true,
        provider: EndpointProvider::DerpMapPreferred,
    };

    let detector = Detector;
    let result = detector.detect_with_endpoints(&[ep]).await;
    assert_eq!(
        result,
        DetectResult::Inconclusive,
        "connection failure should be inconclusive"
    );
}

#[tokio::test]
async fn detect_empty_endpoints_inconclusive() {
    let detector = Detector;
    let result = detector.detect_with_endpoints(&[]).await;
    assert_eq!(result, DetectResult::Inconclusive);
}

#[tokio::test]
async fn detect_any_clean_overrides_failures() {
    // One endpoint fails (port 1), one is clean → not captive.
    let clean_server = TestHttpServer::start(204, vec![], vec![]).await.unwrap();
    let clean_ep = Endpoint {
        url: format!("http://127.0.0.1:{}/generate_204", clean_server.addr.port()),
        host: format!("127.0.0.1:{}", clean_server.addr.port()),
        expected_status: 204,
        expected_content: String::new(),
        supports_tailscale_challenge: false,
        provider: EndpointProvider::Tailscale,
    };
    let dead_ep = Endpoint {
        url: "http://127.0.0.1:1/generate_204".into(),
        host: "127.0.0.1:1".into(),
        expected_status: 204,
        expected_content: String::new(),
        supports_tailscale_challenge: false,
        provider: EndpointProvider::Tailscale,
    };

    let detector = Detector;
    let result = detector.detect_with_endpoints(&[dead_ep, clean_ep]).await;
    assert_eq!(
        result,
        DetectResult::NoCaptivePortal,
        "one clean endpoint should override a failed one"
    );
}

#[tokio::test]
async fn detect_captive_wins_over_clean() {
    // One captive endpoint, one clean → captive (any match wins).
    let captive_server = TestHttpServer::start(302, vec![], vec![]).await.unwrap();
    let clean_server = TestHttpServer::start(204, vec![], vec![]).await.unwrap();
    let captive_ep = Endpoint {
        url: format!(
            "http://127.0.0.1:{}/generate_204",
            captive_server.addr.port()
        ),
        host: format!("127.0.0.1:{}", captive_server.addr.port()),
        expected_status: 204,
        expected_content: String::new(),
        supports_tailscale_challenge: false,
        provider: EndpointProvider::DerpMapPreferred,
    };
    let clean_ep = Endpoint {
        url: format!("http://127.0.0.1:{}/generate_204", clean_server.addr.port()),
        host: format!("127.0.0.1:{}", clean_server.addr.port()),
        expected_status: 204,
        expected_content: String::new(),
        supports_tailscale_challenge: false,
        provider: EndpointProvider::Tailscale,
    };

    let detector = Detector;
    let result = detector
        .detect_with_endpoints(&[clean_ep, captive_ep])
        .await;
    assert_eq!(
        result,
        DetectResult::CaptivePortal,
        "captive detection should win over clean"
    );
}

#[tokio::test]
async fn detect_with_timeout() {
    // Server that accepts but never responds → should time out → inconclusive.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        // Accept the connection but never write a response.
        let _ = listener.accept().await;
        // Hold the connection open until the test ends.
        tokio::time::sleep(Duration::from_secs(10)).await;
    });

    let ep = Endpoint {
        url: format!("http://127.0.0.1:{}/generate_204", addr.port()),
        host: format!("127.0.0.1:{}", addr.port()),
        expected_status: 204,
        expected_content: String::new(),
        supports_tailscale_challenge: false,
        provider: EndpointProvider::Tailscale,
    };

    let detector = Detector;
    let start = std::time::Instant::now();
    let result = detector.detect_with_endpoints(&[ep]).await;
    let elapsed = start.elapsed();

    assert_eq!(result, DetectResult::Inconclusive);
    assert!(
        elapsed <= DETECT_TIMEOUT + Duration::from_secs(2),
        "detection should respect the timeout, took {elapsed:?}"
    );
}
