//! Unit tests for the serve module.

use super::*;

use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// ServeConfig serde
// ---------------------------------------------------------------------------

#[test]
fn serve_config_serde_roundtrip() {
    let mut cfg = ServeConfig::default();
    cfg.TCP.insert(
        443,
        TCPPortHandler {
            HTTPS: true,
            ..Default::default()
        },
    );
    cfg.TCP.insert(
        8080,
        TCPPortHandler {
            TCPForward: "127.0.0.1:3000".into(),
            ..Default::default()
        },
    );
    let hp = "node.tailnet.ts.net:443".to_string();
    let mut web = WebServerConfig::default();
    web.Handlers.insert(
        "/".into(),
        HTTPHandler {
            Text: "hello".into(),
            ..Default::default()
        },
    );
    web.Handlers.insert(
        "/api".into(),
        HTTPHandler {
            Proxy: "http://127.0.0.1:8080".into(),
            ..Default::default()
        },
    );
    cfg.Web.insert(hp, web);
    cfg.AllowFunnel
        .insert("node.tailnet.ts.net:443".into(), true);

    let json = serde_json::to_string(&cfg).unwrap();
    let back: ServeConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back.TCP.len(), 2);
    assert!(back.TCP[&443].HTTPS);
    assert_eq!(back.TCP[&8080].TCPForward, "127.0.0.1:3000");
    assert_eq!(back.Web.len(), 1);
    assert_eq!(
        back.Web["node.tailnet.ts.net:443"].Handlers["/"].Text,
        "hello"
    );
    assert!(back.AllowFunnel["node.tailnet.ts.net:443"]);
}

#[test]
fn serve_config_omits_empty_fields() {
    let cfg = ServeConfig::default();
    let json = serde_json::to_string(&cfg).unwrap();
    assert_eq!(json, "{}");
}

#[test]
fn tcp_port_handler_serde() {
    let h = TCPPortHandler {
        TCPForward: "127.0.0.1:9090".into(),
        TerminateTLS: "node.ts.net".into(),
        ..Default::default()
    };
    let json = serde_json::to_string(&h).unwrap();
    let back: TCPPortHandler = serde_json::from_str(&json).unwrap();
    assert_eq!(back.TCPForward, "127.0.0.1:9090");
    assert_eq!(back.TerminateTLS, "node.ts.net");
    assert!(!back.HTTPS);
    assert!(!back.HTTP);
}

// ---------------------------------------------------------------------------
// Funnel validation
// ---------------------------------------------------------------------------

#[test]
fn funnel_port_not_allowed() {
    let node = Node::default();
    let err = check_funnel_port(9999, &node).unwrap_err();
    assert!(matches!(err, FunnelError::PortNotAllowed(9999)));
}

#[test]
fn funnel_default_ports_allowed() {
    let node = Node::default();
    for port in FUNNEL_PORTS {
        assert!(check_funnel_port(*port, &node).is_ok(), "port {port}");
    }
}

#[test]
fn funnel_access_https_not_enabled() {
    let node = Node::default();
    let err = check_funnel_access(443, &node).unwrap_err();
    assert!(matches!(err, FunnelError::HttpsNotEnabled));
}

#[test]
fn funnel_access_not_enabled_when_no_funnel_attr() {
    let mut node = Node::default();
    node.Capabilities.push("https".into());
    let err = check_funnel_access(443, &node).unwrap_err();
    assert!(matches!(err, FunnelError::NotEnabled));
}

#[test]
fn funnel_access_ok_when_both_caps_present() {
    let mut node = Node::default();
    node.Capabilities.push("https".into());
    node.Capabilities.push("funnel".into());
    assert!(check_funnel_access(443, &node).is_ok());
}

#[test]
fn funnel_access_ok_via_capmap() {
    let mut node = Node::default();
    node.Capabilities.push("https".into());
    node.CapMap.insert(
        "funnel".into(),
        vec![rustscale_tailcfg::RawMessage("true".into())],
    );
    assert!(check_funnel_access(8443, &node).is_ok());
}

#[test]
fn funnel_ports_from_capmap_parses() {
    let mut capmap = NodeCapMap::new();
    capmap.insert(
        CAP_FUNNEL_PORTS.into(),
        vec![rustscale_tailcfg::RawMessage(
            r#"{"ports":"443,8443,10000"}"#.into(),
        )],
    );
    let ports = funnel_ports_from_capmap(&capmap).unwrap();
    assert_eq!(ports, vec![443, 8443, 10000]);
}

// ---------------------------------------------------------------------------
// Mount matching
// ---------------------------------------------------------------------------

#[test]
fn match_mount_exact() {
    let mut handlers = BTreeMap::new();
    handlers.insert(
        "/".into(),
        HTTPHandler {
            Text: "root".into(),
            ..Default::default()
        },
    );
    handlers.insert(
        "/api".into(),
        HTTPHandler {
            Text: "api".into(),
            ..Default::default()
        },
    );
    let h = match_mount(&handlers, "/api").unwrap();
    assert_eq!(h.Text, "api");
}

#[test]
fn match_mount_longest_prefix() {
    let mut handlers = BTreeMap::new();
    handlers.insert(
        "/".into(),
        HTTPHandler {
            Text: "root".into(),
            ..Default::default()
        },
    );
    handlers.insert(
        "/api".into(),
        HTTPHandler {
            Text: "api".into(),
            ..Default::default()
        },
    );
    // /api/users should match /api (longest prefix), not /
    let h = match_mount(&handlers, "/api/users").unwrap();
    assert_eq!(h.Text, "api");
}

#[test]
fn match_mount_trailing_slash() {
    let mut handlers = BTreeMap::new();
    handlers.insert(
        "/api/".into(),
        HTTPHandler {
            Text: "api-dir".into(),
            ..Default::default()
        },
    );
    let h = match_mount(&handlers, "/api/users").unwrap();
    assert_eq!(h.Text, "api-dir");
}

#[test]
fn match_mount_no_match() {
    let handlers = BTreeMap::new();
    assert!(match_mount(&handlers, "/whatever").is_none());
}

// ---------------------------------------------------------------------------
// URL parsing
// ---------------------------------------------------------------------------

#[test]
fn parse_proxy_url_full() {
    let (host, port, path) = parse_proxy_url("http://127.0.0.1:3000/api").unwrap();
    assert_eq!(host, "127.0.0.1");
    assert_eq!(port, 3000);
    assert_eq!(path, "/api");
}

#[test]
fn parse_proxy_url_no_scheme() {
    let (host, port, path) = parse_proxy_url("localhost:8080").unwrap();
    assert_eq!(host, "localhost");
    assert_eq!(port, 8080);
    assert_eq!(path, "/");
}

#[test]
fn parse_proxy_url_port_only() {
    let (host, port, path) = parse_proxy_url("3000").unwrap();
    assert_eq!(host, "127.0.0.1");
    assert_eq!(port, 3000);
    assert_eq!(path, "/");
}

#[test]
fn parse_proxy_url_https() {
    let (host, port, _path) = parse_proxy_url("https://backend.example.com:443/").unwrap();
    assert_eq!(host, "backend.example.com");
    assert_eq!(port, 443);
}

// ---------------------------------------------------------------------------
// TCP forward dispatch (in-process, using tokio TCP)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tcp_forward_proxies_bytes() {
    // Start a backend echo server on a real TCP socket.
    let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend.local_addr().unwrap();
    let backend_str = backend_addr.to_string();

    // Backend: echo everything back.
    tokio::spawn(async move {
        loop {
            if let Ok((mut sock, _)) = backend.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    loop {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if sock.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        }
    });

    // Simulate a "client" stream using a tokio TCP pair.
    // We use an in-memory pipe: write to one end, tcp_forward bridges to backend.
    let (mut client, server_side) = tokio::io::duplex(4096);

    // Run tcp_forward on the server_side, bridging to the backend.
    let forward_task = tokio::spawn(async move { tcp_forward(server_side, &backend_str).await });

    // Client writes data and reads it back (echoed via the forward → backend).
    client.write_all(b"hello world").await.unwrap();
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut buf))
        .await
        .expect("read timeout")
        .expect("read err");
    assert_eq!(&buf[..n], b"hello world");

    // Close the client side to end the forward.
    drop(client);
    let _ = forward_task.await;
}

// ---------------------------------------------------------------------------
// HTTP dispatch: static text handler
// ---------------------------------------------------------------------------

#[tokio::test]
async fn http_static_text_handler() {
    let mut cfg = ServeConfig::default();
    cfg.TCP.insert(
        8080,
        TCPPortHandler {
            HTTP: true,
            ..Default::default()
        },
    );
    let hp = "node.ts.net:8080".to_string();
    let mut web = WebServerConfig::default();
    web.Handlers.insert(
        "/".into(),
        HTTPHandler {
            Text: "hello from serve".into(),
            ..Default::default()
        },
    );
    cfg.Web.insert(hp, web);

    let cfg_arc = std::sync::Arc::new(tokio::sync::RwLock::new(cfg));
    let peers = std::sync::Arc::new(tokio::sync::RwLock::new(vec![]));
    let ups = std::sync::Arc::new(tokio::sync::RwLock::new(BTreeMap::new()));

    let (mut client, mut server_side) = tokio::io::duplex(4096);

    // Send an HTTP request.
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: node.ts.net:8080\r\n\r\n")
        .await
        .unwrap();

    let handler_task = tokio::spawn(async move {
        handle_http(
            &mut server_side,
            8080,
            &cfg_arc,
            "node.ts.net",
            None,
            &peers,
            &ups,
        )
        .await
    });

    // Read the response.
    let mut resp = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => resp.extend_from_slice(&buf[..n]),
            Ok(Err(e)) => panic!("read error: {e}"),
            Err(e) => panic!("read timeout: {e}"),
        }
        if resp.windows(7).any(|w| w == b"hello f") && resp.contains(&b'\n') {
            break;
        }
    }
    let resp_str = String::from_utf8_lossy(&resp);
    assert!(resp_str.contains("200 OK"), "response: {resp_str}");
    assert!(
        resp_str.contains("hello from serve"),
        "response: {resp_str}"
    );
    drop(client);
    let _ = handler_task.await;
}

// ---------------------------------------------------------------------------
// HTTP dispatch: redirect handler
// ---------------------------------------------------------------------------

#[tokio::test]
async fn http_redirect_handler() {
    let mut cfg = ServeConfig::default();
    cfg.TCP.insert(
        8080,
        TCPPortHandler {
            HTTP: true,
            ..Default::default()
        },
    );
    let hp = "node.ts.net:8080".to_string();
    let mut web = WebServerConfig::default();
    web.Handlers.insert(
        "/".into(),
        HTTPHandler {
            Redirect: "https://example.com/".into(),
            ..Default::default()
        },
    );
    cfg.Web.insert(hp, web);

    let cfg_arc = std::sync::Arc::new(tokio::sync::RwLock::new(cfg));
    let peers = std::sync::Arc::new(tokio::sync::RwLock::new(vec![]));
    let ups = std::sync::Arc::new(tokio::sync::RwLock::new(BTreeMap::new()));

    let (mut client, mut server_side) = tokio::io::duplex(4096);
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: node.ts.net:8080\r\n\r\n")
        .await
        .unwrap();

    let handler_task = tokio::spawn(async move {
        handle_http(
            &mut server_side,
            8080,
            &cfg_arc,
            "node.ts.net",
            None,
            &peers,
            &ups,
        )
        .await
    });

    let mut resp = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => resp.extend_from_slice(&buf[..n]),
            Ok(Err(_)) => break,
            Err(_) => break,
        }
        if resp.contains(&b'\n') {
            break;
        }
    }
    drop(client);
    let _ = handler_task.await;
    let resp_str = String::from_utf8_lossy(&resp);
    assert!(
        resp_str.contains("302 Found"),
        "expected 302, got: {resp_str}"
    );
    assert!(
        resp_str.contains("Location: https://example.com/"),
        "expected Location header, got: {resp_str}"
    );
}

#[tokio::test]
async fn http_redirect_with_code_prefix() {
    let mut cfg = ServeConfig::default();
    cfg.TCP.insert(
        8080,
        TCPPortHandler {
            HTTP: true,
            ..Default::default()
        },
    );
    let hp = "node.ts.net:8080".to_string();
    let mut web = WebServerConfig::default();
    web.Handlers.insert(
        "/".into(),
        HTTPHandler {
            Redirect: "301:https://example.com/new".into(),
            ..Default::default()
        },
    );
    cfg.Web.insert(hp, web);

    let cfg_arc = std::sync::Arc::new(tokio::sync::RwLock::new(cfg));
    let peers = std::sync::Arc::new(tokio::sync::RwLock::new(vec![]));
    let ups = std::sync::Arc::new(tokio::sync::RwLock::new(BTreeMap::new()));

    let (mut client, mut server_side) = tokio::io::duplex(4096);
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: node.ts.net:8080\r\n\r\n")
        .await
        .unwrap();

    let handler_task = tokio::spawn(async move {
        handle_http(
            &mut server_side,
            8080,
            &cfg_arc,
            "node.ts.net",
            None,
            &peers,
            &ups,
        )
        .await
    });

    let mut resp = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => resp.extend_from_slice(&buf[..n]),
            Ok(Err(_)) => break,
            Err(_) => break,
        }
        if resp.contains(&b'\n') {
            break;
        }
    }
    drop(client);
    let _ = handler_task.await;
    let resp_str = String::from_utf8_lossy(&resp);
    assert!(
        resp_str.contains("301 Moved Permanently"),
        "expected 301, got: {resp_str}"
    );
    assert!(
        resp_str.contains("Location: https://example.com/new"),
        "expected Location header, got: {resp_str}"
    );
}

// ---------------------------------------------------------------------------
// HTTP dispatch: reverse proxy with headers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn http_reverse_proxy_sets_headers() {
    // Start a backend that echoes received headers as the response body.
    let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend.local_addr().unwrap();
    let backend_port = backend_addr.port();

    tokio::spawn(async move {
        loop {
            if let Ok((mut sock, _)) = backend.accept().await {
                tokio::spawn(async move {
                    // Read the full request.
                    let mut buf = vec![0u8; 8192];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req_text = String::from_utf8_lossy(&buf[..n]);
                    // Echo the request headers back as the body.
                    let body = req_text.to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        }
    });

    // Build a serve config with a reverse-proxy handler.
    let mut cfg = ServeConfig::default();
    cfg.TCP.insert(
        80,
        TCPPortHandler {
            HTTP: true,
            ..Default::default()
        },
    );
    let hp = "node.ts.net:80".to_string();
    let mut web = WebServerConfig::default();
    web.Handlers.insert(
        "/".into(),
        HTTPHandler {
            Proxy: format!("http://127.0.0.1:{backend_port}"),
            ..Default::default()
        },
    );
    cfg.Web.insert(hp, web);

    let cfg_arc = std::sync::Arc::new(tokio::sync::RwLock::new(cfg));

    // Set up fake peer for WhoIs.
    let peer_key = rustscale_key::NodePrivate::generate();
    let peer_node = Node {
        ID: 1,
        Name: "alice.ts.net.".into(),
        Key: peer_key.public(),
        Addresses: vec!["100.64.0.5/32".into()],
        User: 7,
        ..Default::default()
    };
    let peers = std::sync::Arc::new(tokio::sync::RwLock::new(vec![peer_node]));
    let mut ups = BTreeMap::new();
    ups.insert(
        7,
        UserProfile {
            ID: 7,
            LoginName: "alice@example.com".into(),
            DisplayName: "Alice".into(),
            ..Default::default()
        },
    );
    let ups = std::sync::Arc::new(tokio::sync::RwLock::new(ups));

    let (mut client, mut server_side) = tokio::io::duplex(4096);

    // Send an HTTP request through the proxy.
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: node.ts.net:80\r\n\r\n")
        .await
        .unwrap();

    let cfg_clone = cfg_arc.clone();
    let peers_clone = peers.clone();
    let ups_clone = ups.clone();
    let handler_task = tokio::spawn(async move {
        handle_http(
            &mut server_side,
            80,
            &cfg_clone,
            "node.ts.net",
            Some("100.64.0.5".parse().unwrap()),
            &peers_clone,
            &ups_clone,
        )
        .await
    });

    // Read the response (which echoes the proxied request headers).
    let mut resp = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => resp.extend_from_slice(&buf[..n]),
            Ok(Err(_)) => break,
            Err(_) => break,
        }
    }
    drop(client);
    let _ = handler_task.await;

    let resp_str = String::from_utf8_lossy(&resp);
    // The backend echoes the request it received. Check the proxy injected
    // the expected headers.
    assert!(
        resp_str.contains("X-Forwarded-For: 100.64.0.5"),
        "missing X-Forwarded-For, response: {resp_str}"
    );
    assert!(
        resp_str.contains("Tailscale-User-Login: alice@example.com"),
        "missing Tailscale-User-Login, response: {resp_str}"
    );
    assert!(
        resp_str.contains("Tailscale-User-Name: Alice"),
        "missing Tailscale-User-Name, response: {resp_str}"
    );
}

// ---------------------------------------------------------------------------
// HTTP 404 when no handler
// ---------------------------------------------------------------------------

#[tokio::test]
async fn http_returns_404_when_no_web_config() {
    let mut cfg = ServeConfig::default();
    cfg.TCP.insert(
        9090,
        TCPPortHandler {
            HTTP: true,
            ..Default::default()
        },
    );
    // No Web entry for port 9090.

    let cfg_arc = std::sync::Arc::new(tokio::sync::RwLock::new(cfg));
    let peers = std::sync::Arc::new(tokio::sync::RwLock::new(vec![]));
    let ups = std::sync::Arc::new(tokio::sync::RwLock::new(BTreeMap::new()));

    let (mut client, mut server_side) = tokio::io::duplex(4096);
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: node.ts.net:9090\r\n\r\n")
        .await
        .unwrap();

    let handler_task = tokio::spawn(async move {
        handle_http(
            &mut server_side,
            9090,
            &cfg_arc,
            "node.ts.net",
            None,
            &peers,
            &ups,
        )
        .await
    });

    let mut resp = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => resp.extend_from_slice(&buf[..n]),
            Ok(Err(e)) => panic!("read error: {e}"),
            Err(e) => panic!("timeout: {e}"),
        }
        if resp.contains(&b'\n') {
            break;
        }
    }
    drop(client);
    let _ = handler_task.await;
    let resp_str = String::from_utf8_lossy(&resp);
    assert!(resp_str.contains("404"), "expected 404, got: {resp_str}");
}

// ---------------------------------------------------------------------------
// web_for_port lookup
// ---------------------------------------------------------------------------

#[test]
fn web_for_port_fqdn_match() {
    let mut cfg = ServeConfig::default();
    let hp = "node.ts.net:443".to_string();
    cfg.Web.insert(
        hp,
        WebServerConfig {
            Handlers: BTreeMap::new(),
        },
    );
    assert!(cfg.web_for_port(443, "node.ts.net").is_some());
    assert!(cfg.web_for_port(443, "node.ts.net.").is_some()); // trailing dot
    assert!(cfg.web_for_port(443, "other.ts.net").is_some()); // fallback by port suffix
    assert!(cfg.web_for_port(8443, "node.ts.net").is_none());
}

// ---------------------------------------------------------------------------
// clean_path
// ---------------------------------------------------------------------------

#[test]
fn clean_path_resolves_dots() {
    assert_eq!(clean_path("/a/b/../c"), "/a/c");
    assert_eq!(clean_path("/a/./b"), "/a/b");
    assert_eq!(clean_path("/"), "/");
    assert_eq!(clean_path(""), "/");
    assert_eq!(clean_path("/foo/bar/"), "/foo/bar");
}

// ---------------------------------------------------------------------------
// ETag and persistence
// ---------------------------------------------------------------------------

#[test]
fn serve_config_etag_is_deterministic() {
    let cfg = ServeConfig::default();
    let etag1 = cfg.etag();
    let etag2 = cfg.etag();
    assert_eq!(etag1, etag2, "ETag should be deterministic for same config");
    assert!(!etag1.is_empty(), "ETag should not be empty");
    assert_eq!(etag1.len(), 64, "ETag should be 32-byte hex (64 chars)");
}

#[test]
fn serve_config_etag_differs_for_different_configs() {
    let cfg1 = ServeConfig::default();
    let mut cfg2 = ServeConfig::default();
    cfg2.TCP.insert(
        443,
        TCPPortHandler {
            HTTPS: true,
            ..Default::default()
        },
    );
    assert_ne!(cfg1.etag(), cfg2.etag());
}

#[test]
fn serve_config_persist_and_reload() {
    let tmp = tempfile::tempdir().unwrap();
    let mut cfg = ServeConfig::default();
    cfg.TCP.insert(
        8080,
        TCPPortHandler {
            TCPForward: "127.0.0.1:3000".into(),
            ..Default::default()
        },
    );
    cfg.save(tmp.path()).unwrap();
    let loaded = ServeConfig::load(tmp.path()).unwrap();
    assert_eq!(loaded.TCP.len(), 1);
    assert_eq!(loaded.TCP[&8080].TCPForward, "127.0.0.1:3000");
}

#[test]
fn serve_config_load_returns_default_when_no_file() {
    let tmp = tempfile::tempdir().unwrap();
    let loaded = ServeConfig::load(tmp.path()).unwrap();
    assert!(loaded.is_empty());
}

#[test]
fn serve_config_is_empty_check() {
    assert!(ServeConfig::default().is_empty());
    let mut cfg = ServeConfig::default();
    cfg.TCP.insert(
        80,
        TCPPortHandler {
            HTTP: true,
            ..Default::default()
        },
    );
    assert!(!cfg.is_empty());
}

// ---------------------------------------------------------------------------
// HTTPHandler.Redirect
// ---------------------------------------------------------------------------

#[test]
fn http_handler_redirect_serde() {
    let h = HTTPHandler {
        Redirect: "https://example.com/".into(),
        ..Default::default()
    };
    let json = serde_json::to_string(&h).unwrap();
    let back: HTTPHandler = serde_json::from_str(&json).unwrap();
    assert_eq!(back.Redirect, "https://example.com/");
}

#[test]
fn parse_redirect_default_302() {
    let (code, url) = parse_redirect_with_code("https://example.com/");
    assert_eq!(code, 302);
    assert_eq!(url, "https://example.com/");
}

#[test]
fn parse_redirect_with_code_prefix() {
    let (code, url) = parse_redirect_with_code("301:https://example.com/new");
    assert_eq!(code, 301);
    assert_eq!(url, "https://example.com/new");
}

#[test]
fn parse_redirect_307() {
    let (code, url) = parse_redirect_with_code("307:https://example.com/temp");
    assert_eq!(code, 307);
    assert_eq!(url, "https://example.com/temp");
}

#[test]
fn parse_redirect_invalid_code_defaults_302() {
    let (code, url) = parse_redirect_with_code("499:https://example.com/");
    assert_eq!(code, 302);
    assert_eq!(url, "499:https://example.com/");
}

// ---------------------------------------------------------------------------
// ServeConfig Foreground + Services
// ---------------------------------------------------------------------------

#[test]
fn serve_config_foreground_serde() {
    let mut cfg = ServeConfig::default();
    let mut fg = ServeConfig::default();
    fg.TCP.insert(
        8080,
        TCPPortHandler {
            HTTP: true,
            ..Default::default()
        },
    );
    cfg.Foreground.insert("session-1".into(), fg);
    let json = serde_json::to_string(&cfg).unwrap();
    let back: ServeConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back.Foreground.len(), 1);
    assert!(back.Foreground["session-1"].TCP[&8080].HTTP);
    assert!(!back.is_empty());
}

#[test]
fn serve_config_services_serde() {
    let mut cfg = ServeConfig::default();
    let mut svc = ServiceConfig::default();
    svc.TCP.insert(
        443,
        TCPPortHandler {
            HTTPS: true,
            ..Default::default()
        },
    );
    svc.Tun = true;
    cfg.Services.insert("svc:my-app".into(), svc);
    let json = serde_json::to_string(&cfg).unwrap();
    let back: ServeConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back.Services.len(), 1);
    assert!(back.Services["svc:my-app"].TCP[&443].HTTPS);
    assert!(back.Services["svc:my-app"].Tun);
}

// ---------------------------------------------------------------------------
// web_for_host_port (Ingress-Target lookup)
// ---------------------------------------------------------------------------

#[test]
fn web_for_host_port_exact_match() {
    let mut cfg = ServeConfig::default();
    cfg.Web.insert(
        "node.ts.net:443".into(),
        WebServerConfig {
            Handlers: BTreeMap::new(),
        },
    );
    assert!(cfg.web_for_host_port("node.ts.net:443").is_some());
    assert!(cfg.web_for_host_port("other.ts.net:443").is_none());
}
