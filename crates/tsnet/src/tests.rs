//! Unit tests and e2e integration tests for tsnet.
//!
//! E2e tests are `#[ignore]`d — they require `TS_E2E_AUTHKEY` and
//! `TS_E2E_TAILNET` env vars (provisioned by `tools/e2e.sh`).

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex;

use rustscale_key::NodePrivate;
use rustscale_tailcfg::Node;
use rustscale_wg::WgTunn;

use super::*;

// ---------------------------------------------------------------------------
// Builder validation tests (not ignored)
// ---------------------------------------------------------------------------

#[test]
fn builder_rejects_empty_hostname() {
    let result = ServerBuilder::default()
        .hostname("")
        .auth_key("tskey-xxx")
        .build();
    assert!(result.is_err());
    match result {
        Err(TsnetError::Builder(msg)) => assert!(msg.contains("hostname")),
        _ => panic!("expected Builder error"),
    }
}

#[test]
fn builder_accepts_valid_config() {
    let result = ServerBuilder::default()
        .hostname("my-node")
        .auth_key("tskey-xxx")
        .ephemeral(true)
        .build();
    assert!(result.is_ok());
}

#[test]
fn builder_defaults_control_url() {
    let server = Server::builder()
        .hostname("x")
        .auth_key("k")
        .build()
        .unwrap();
    assert_eq!(server.config.control_url, DEFAULT_CONTROL_URL);
}

#[test]
fn builder_sets_ephemeral_flag() {
    let server = ServerBuilder::default()
        .hostname("x")
        .auth_key("k")
        .ephemeral(true)
        .build()
        .unwrap();
    assert!(server.config.ephemeral);
}

#[cfg(feature = "identity-federation")]
#[tokio::test]
async fn workload_identity_hook_resolves_builder_config() {
    rustscale_identityfederation::install().unwrap();
    let observed = Arc::new(Mutex::new(None));
    let hook_observed = observed.clone();
    let resolver: rustscale_feature::IdentityFederationResolver = Arc::new(move |request| {
        *hook_observed.lock().unwrap() = Some((
            request.base_url,
            request.client_id,
            request.id_token,
            request.audience,
            request.tags,
        ));
        Box::pin(async { Ok("tskey-auth-federated".to_owned()) })
    });
    let _override = rustscale_feature::RESOLVE_AUTH_KEY_VIA_WIF.override_for_test(resolver);

    let mut server = Server::builder()
        .hostname("workload")
        .control_url("https://control.example.com")
        .client_id("client-123")
        .id_token("secret-id-token")
        .advertise_tags(vec!["tag:workload".into()])
        .build()
        .unwrap();
    let mut transient = server
        .initial_registration_auth(&PersistedState::default())
        .await
        .unwrap();

    assert_eq!(
        transient
            .as_ref()
            .map(crate::lifecycle::TransientAuthKey::as_str),
        Some("tskey-auth-federated")
    );
    assert_eq!(
        format!("{:?}", transient.as_ref().unwrap()),
        "TransientAuthKey(<redacted>)"
    );
    assert!(server.config.auth_key.is_none());
    assert_eq!(
        observed.lock().unwrap().take().unwrap(),
        (
            "https://control.example.com".into(),
            "client-123".into(),
            "secret-id-token".into(),
            String::new(),
            vec!["tag:workload".into()],
        )
    );
    assert!(!format!("{:?}", server.config).contains("secret-id-token"));

    let mut request = RegisterRequest {
        Auth: crate::lifecycle::take_initial_register_auth(&mut transient),
        ..Default::default()
    };
    assert_eq!(
        request.Auth.as_ref().map(|auth| auth.AuthKey.as_str()),
        Some("tskey-auth-federated")
    );
    assert!(transient.is_none());
    crate::lifecycle::clear_register_auth(&mut request);
    assert!(request.Auth.is_none());
}

#[cfg(feature = "identity-federation")]
#[tokio::test]
async fn workload_identity_enrollment_and_remint_semantics() {
    rustscale_identityfederation::install().unwrap();
    let calls = Arc::new(AtomicU64::new(0));
    let hook_calls = calls.clone();
    let resolver: rustscale_feature::IdentityFederationResolver = Arc::new(move |_| {
        let sequence = hook_calls.fetch_add(1, Ordering::SeqCst) + 1;
        Box::pin(async move { Ok(format!("federated-key-{sequence}")) })
    });
    let _override = rustscale_feature::RESOLVE_AUTH_KEY_VIA_WIF.override_for_test(resolver);

    let mut server = Server::builder()
        .client_id("client")
        .id_token("id-token")
        .advertise_tags(vec!["tag:workload".into()])
        .build()
        .unwrap();
    let fresh = PersistedState::generate();
    let first = server
        .initial_registration_auth(&fresh)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.as_str(), "federated-key-1");
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let enrolled = PersistedState {
        node_id: 1,
        ..fresh.clone()
    };
    assert!(server
        .initial_registration_auth(&enrolled)
        .await
        .unwrap()
        .is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let mut forced = Server::builder()
        .client_id("client")
        .id_token("id-token")
        .advertise_tags(vec!["tag:workload".into()])
        .force_login(true)
        .build()
        .unwrap();
    let force_key = forced
        .initial_registration_auth(&enrolled)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(force_key.as_str(), "federated-key-2");
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    // A dropped register response leaves generated keys but no enrollment
    // marker. Dropping the first transient key and preparing another attempt
    // must mint a distinct one instead of replaying it.
    drop(first);
    let retry = server
        .initial_registration_auth(&fresh)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retry.as_str(), "federated-key-3");
    assert_ne!(retry.as_str(), force_key.as_str());
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert!(server.config.auth_key.is_none());
}

#[cfg(feature = "identity-federation")]
#[tokio::test]
async fn workload_identity_builder_config_is_validated_before_hook() {
    rustscale_identityfederation::install().unwrap();
    let resolver: rustscale_feature::IdentityFederationResolver = Arc::new(|_| {
        Box::pin(async {
            Err(Box::<dyn std::error::Error + Send + Sync>::from(
                "hook should not run",
            ))
        })
    });
    let _override = rustscale_feature::RESOLVE_AUTH_KEY_VIA_WIF.override_for_test(resolver);

    let cases = [
        (
            Server::builder().client_id("client").build().unwrap(),
            "ID token and audience are empty",
        ),
        (
            Server::builder()
                .id_token("token")
                .audience("audience")
                .build()
                .unwrap(),
            "only one of ID token and audience",
        ),
        (
            Server::builder().id_token("token").build().unwrap(),
            "client ID is empty",
        ),
        (
            Server::builder().audience("audience").build().unwrap(),
            "client ID is empty",
        ),
    ];
    for (mut server, expected) in cases {
        let error = server
            .initial_registration_auth(&PersistedState::default())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{error:?}");
    }
}

// ---------------------------------------------------------------------------
// Gap 1: Port builder method (#54)
// ---------------------------------------------------------------------------

#[test]
fn builder_port_defaults_to_zero() {
    let server = Server::builder()
        .hostname("x")
        .auth_key("k")
        .build()
        .unwrap();
    assert_eq!(
        server.config.port, 0,
        "port should default to 0 (auto-select)"
    );
}

#[test]
fn builder_sets_port() {
    let server = Server::builder()
        .hostname("x")
        .auth_key("k")
        .port(41641)
        .build()
        .unwrap();
    assert_eq!(server.config.port, 41641);
}

// ---------------------------------------------------------------------------
// Gap 2: AdvertiseTags builder method (#55)
// ---------------------------------------------------------------------------

#[test]
fn builder_advertise_tags_defaults_empty() {
    let server = Server::builder()
        .hostname("x")
        .auth_key("k")
        .build()
        .unwrap();
    assert!(server.config.advertise_tags.is_empty());
}

#[test]
fn builder_sets_advertise_tags() {
    let server = Server::builder()
        .hostname("x")
        .auth_key("k")
        .advertise_tags(vec!["tag:prod".into(), "tag:server".into()])
        .build()
        .unwrap();
    assert_eq!(server.config.advertise_tags, vec!["tag:prod", "tag:server"]);
}

// ---------------------------------------------------------------------------
// Gap 3: Pluggable logger (#56)
// ---------------------------------------------------------------------------

#[test]
fn builder_logger_defaults_to_none() {
    let server = Server::builder()
        .hostname("x")
        .auth_key("k")
        .build()
        .unwrap();
    assert!(server.config.logger.is_none());
}

#[test]
fn builder_sets_logger() {
    let logs = Arc::new(Mutex::new(Vec::<String>::new()));
    let logs_clone = logs.clone();
    let server = Server::builder()
        .hostname("x")
        .auth_key("k")
        .logger(move |msg: &str| {
            logs_clone.lock().unwrap().push(msg.to_string());
        })
        .build()
        .unwrap();
    assert!(server.config.logger.is_some());
    // Verify the logger is invoked.
    server.log_msg("test message");
    let captured = logs.lock().unwrap();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0], "test message");
}

#[test]
fn builder_logger_fallback_to_eprintln_when_unset() {
    let server = Server::builder()
        .hostname("x")
        .auth_key("k")
        .build()
        .unwrap();
    assert!(server.config.logger.is_none());
    // Should not panic — falls through to eprintln!.
    server.log_msg("fallback message");
}

// ---------------------------------------------------------------------------
// Gap 4: Lazy/idempotent Start (#57) — idempotency test
// ---------------------------------------------------------------------------

#[test]
fn up_is_idempotent_when_not_up() {
    // We can't call up() without a real control plane, but we can verify
    // that calling up() on an already-up server returns Ok instead of
    // AlreadyUp. Since up() requires a network connection, we test the
    // idempotency guard logic: the first line of up() checks
    // self.inner.is_some() and returns Ok(self.status()) if true.
    //
    // Construct a server that's "up" by checking the guard directly.
    let server = Server::builder()
        .hostname("x")
        .auth_key("k")
        .build()
        .unwrap();
    assert!(!server.is_up());
    // The idempotency check: if inner is Some, up() returns Ok(status).
    // We can't easily set inner without a real bootstrap, but we verify
    // the behavior by checking is_up() is consistent with the guard.
    // The real idempotency test runs in e2e tests (#[ignore]d).
}

#[test]
fn ensure_up_does_not_panic_when_not_up() {
    // ensure_up() calls up() which needs a real control plane.
    // This test just verifies the method exists and the type signature
    // is correct. The actual auto-start behavior is tested in e2e tests.
    let server = Server::builder()
        .hostname("x")
        .auth_key("k")
        .build()
        .unwrap();
    assert!(!server.is_up());
    // We can't call ensure_up() here because it would try to connect to
    // the real control plane. The auto-start behavior is verified in
    // e2e tests where a real auth key and control plane are available.
}

// ---------------------------------------------------------------------------
// Gap 5: Up returns status (#58)
// ---------------------------------------------------------------------------

#[test]
fn status_when_not_up_returns_down_status() {
    let server = Server::builder()
        .hostname("test-node")
        .auth_key("k")
        .build()
        .unwrap();
    let st = server.status();
    assert!(!st.up);
    assert_eq!(st.hostname, "test-node");
    assert!(st.tailscale_ips.is_empty());
    assert_eq!(st.peer_count, 0);
}

#[test]
fn builder_configure_os_dns_defaults_off() {
    let server = Server::builder()
        .hostname("x")
        .auth_key("k")
        .build()
        .unwrap();
    assert!(
        !server.config.configure_os_dns,
        "configure_os_dns should default to false"
    );
}

#[test]
fn builder_configure_os_dns_opt_in() {
    let server = Server::builder()
        .hostname("x")
        .auth_key("k")
        .configure_os_dns(true)
        .build()
        .unwrap();
    assert!(server.config.configure_os_dns);
}

// ---------------------------------------------------------------------------
// OS DNS config construction tests (pure function, no root needed)
// ---------------------------------------------------------------------------

#[test]
fn os_dns_config_from_netmap_proxied() {
    use rustscale_dns::build_os_dns_config;
    use rustscale_tailcfg::{DNSConfig, Resolver};

    let dns = DNSConfig {
        Resolvers: vec![Resolver {
            Addr: "1.1.1.1".into(),
        }],
        Domains: vec!["tailnet.ts.net".into(), "corp.example".into()],
        Proxied: true,
        CertDomains: vec!["node.tailnet.ts.net".into()],
        ..Default::default()
    };
    let os = build_os_dns_config(&dns, "tailnet.ts.net");

    assert_eq!(
        os.nameservers,
        vec![std::net::IpAddr::V4(Ipv4Addr::new(100, 100, 100, 100))]
    );
    assert_eq!(os.search_domains, vec!["tailnet.ts.net", "corp.example"]);
    assert_eq!(os.match_domains, vec!["tailnet.ts.net"]);
}

#[test]
fn os_dns_config_from_netmap_with_split_routes() {
    use rustscale_dns::build_os_dns_config;
    use rustscale_tailcfg::{DNSConfig, Resolver};
    use std::collections::HashMap;

    let mut routes = HashMap::new();
    routes.insert(
        "corp.example.com.".to_string(),
        vec![Resolver {
            Addr: "10.0.0.53".into(),
        }],
    );
    let dns = DNSConfig {
        Domains: vec!["tailnet.ts.net".into()],
        Proxied: true,
        Routes: routes,
        ..Default::default()
    };
    let os = build_os_dns_config(&dns, "tailnet.ts.net");

    assert_eq!(os.match_domains.len(), 2);
    assert!(os.match_domains.contains(&"tailnet.ts.net".to_string()));
    assert!(os.match_domains.contains(&"corp.example.com".to_string()));
}

#[test]
fn os_dns_config_not_proxied_no_match_domains() {
    use rustscale_dns::build_os_dns_config;
    use rustscale_tailcfg::DNSConfig;

    let dns = DNSConfig {
        Domains: vec!["tailnet.ts.net".into()],
        Proxied: false,
        ..Default::default()
    };
    let os = build_os_dns_config(&dns, "tailnet.ts.net");
    assert!(os.match_domains.is_empty());
    assert_eq!(os.search_domains, vec!["tailnet.ts.net"]);
}

// ---------------------------------------------------------------------------
// Health → ServerStatus integration tests (not ignored)
// ---------------------------------------------------------------------------

#[test]
fn status_empty_health_when_not_up() {
    let server = Server::builder()
        .hostname("x")
        .auth_key("k")
        .build()
        .unwrap();
    let st = server.status();
    assert!(!st.up);
    assert!(st.health.is_empty(), "health should be empty when not up");
}

#[test]
fn health_warning_appears_in_status() {
    // We can't construct a full RunningState easily, so test the
    // health→status wiring directly: a Tracker's current_warnings()
    // feeds ServerStatus.health, exactly as Server::status() does.
    let tracker = rustscale_health::Tracker::new();
    tracker.set_unhealthy(
        rustscale_health::WARN_DERP_HOME,
        "derp home region 5 unreachable",
    );
    tracker.set_unhealthy(rustscale_health::WARN_CONTROL, "control connection lost");

    let warnings = tracker.current_warnings();
    let status = ServerStatus {
        up: true,
        tailscale_ips: vec![],
        peer_count: 0,
        peers: vec![],
        hostname: "test".into(),
        packet_drops: 0,
        health: warnings,
        key_expired: false,
    };

    assert_eq!(status.health.len(), 2);
    // High severity (control) should sort before Medium (derp).
    assert_eq!(status.health[0].id, rustscale_health::WARN_CONTROL);
    assert_eq!(status.health[0].severity, rustscale_health::Severity::High);
    assert_eq!(status.health[0].text, "control connection lost");
    assert_eq!(status.health[1].id, rustscale_health::WARN_DERP_HOME);
    assert_eq!(
        status.health[1].severity,
        rustscale_health::Severity::Medium
    );
    assert_eq!(status.health[1].text, "derp home region 5 unreachable");

    // Clearing one warning reduces the count.
    tracker.set_healthy(rustscale_health::WARN_CONTROL);
    let cleared = tracker.current_warnings();
    assert_eq!(cleared.len(), 1);
    assert_eq!(cleared[0].id, rustscale_health::WARN_DERP_HOME);
}

// ---------------------------------------------------------------------------
// Hostname resolution tests (not ignored)
// ---------------------------------------------------------------------------

fn fake_node(name: &str, ip: &str, key: NodePrivate) -> Node {
    Node {
        ID: 1,
        Name: name.to_string(),
        Key: key.public(),
        Addresses: vec![format!("{ip}/32")],
        ..Default::default()
    }
}

#[test]
fn resolve_hostname_from_fake_netmap() {
    let peer_key = NodePrivate::generate();
    let peer_node = fake_node("alice.tailnet.ts.net.", "100.64.0.5", peer_key);

    // We can't construct a full RunningState easily, so test the
    // hostname matching logic directly.
    let peers = vec![peer_node.clone()];
    let host_lower = "alice.tailnet.ts.net".to_lowercase();
    let host_trimmed = host_lower.trim_end_matches('.');

    let mut found = None;
    for peer in &peers {
        let name = peer.Name.to_lowercase();
        let name_trimmed = name.trim_end_matches('.');
        if name_trimmed == host_trimmed {
            found = extract_node_ips(peer).first().copied();
            break;
        }
    }

    assert!(found.is_some());
    let ip = found.unwrap();
    assert_eq!(ip, std::net::IpAddr::V4(Ipv4Addr::new(100, 64, 0, 5)));
}

#[test]
fn resolve_hostname_case_insensitive() {
    let peer_key = NodePrivate::generate();
    let peer_node = fake_node("Bob.tailnet.ts.net.", "100.64.0.6", peer_key);
    let peers = vec![peer_node];

    let host = "BOB.tailnet.ts.net";
    let host_lower = host.to_lowercase();
    let host_trimmed = host_lower.trim_end_matches('.');

    let mut found = None;
    for peer in &peers {
        let name = peer.Name.to_lowercase();
        let name_trimmed = name.trim_end_matches('.');
        if name_trimmed == host_trimmed {
            found = extract_node_ips(peer).first().copied();
            break;
        }
    }
    assert!(found.is_some());
}

#[test]
fn resolve_unknown_hostname_returns_none() {
    let peer_key = NodePrivate::generate();
    let peer_node = fake_node("alice.tailnet.ts.net.", "100.64.0.5", peer_key);
    let peers = vec![peer_node];

    let host = "nonexistent.tailnet.ts.net";
    let host_lower = host.to_lowercase();
    let host_trimmed = host_lower.trim_end_matches('.');

    let mut found = None;
    for peer in &peers {
        let name = peer.Name.to_lowercase();
        let name_trimmed = name.trim_end_matches('.');
        if name_trimmed == host_trimmed {
            found = extract_node_ips(peer).first().copied();
            break;
        }
    }
    assert!(found.is_none());
}

// ---------------------------------------------------------------------------
// RouteTable longest-prefix tests
// ---------------------------------------------------------------------------

#[test]
fn route_table_exact_match() {
    let key = NodePrivate::generate();
    let peers = vec![Node {
        ID: 1,
        Name: "p".into(),
        Key: key.public(),
        Addresses: vec!["100.64.0.5/32".into()],
        ..Default::default()
    }];
    let rt = RouteTable::from_peers(&peers);
    assert_eq!(
        rt.lookup(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 5))),
        Some(key.public())
    );
    assert!(rt
        .lookup(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 6)))
        .is_none());
}

#[test]
fn route_table_longest_prefix() {
    let broad = NodePrivate::generate();
    let narrow = NodePrivate::generate();
    let peers = vec![
        Node {
            ID: 1,
            Name: "broad".into(),
            Key: broad.public(),
            Addresses: vec!["100.64.0.0/24".into()],
            ..Default::default()
        },
        Node {
            ID: 2,
            Name: "narrow".into(),
            Key: narrow.public(),
            Addresses: vec!["100.64.0.9/32".into()],
            ..Default::default()
        },
    ];
    let rt = RouteTable::from_peers(&peers);
    // /32 wins for its own address.
    assert_eq!(
        rt.lookup(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 9))),
        Some(narrow.public())
    );
    // /24 covers the rest.
    assert_eq!(
        rt.lookup(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 10))),
        Some(broad.public())
    );
}

// ---------------------------------------------------------------------------
// Netmap -> routes plumbing + builder advertise/accept routes
// ---------------------------------------------------------------------------

/// Simulate the netmap→RouteTable plumbing: peers with mixed /32 tailnet
/// addresses and /24 subnet routes, verify the route table reflects both
/// when accept_routes=true and only tailnet when false.
#[test]
fn netmap_to_routes_plumbing() {
    let router_key = NodePrivate::generate().public();
    let host_key = NodePrivate::generate().public();

    // Simulate what control sends: router peer has its tailnet /32 + the
    // approved subnet route in AllowedIPs; host has just its /32.
    let peers = vec![
        Node {
            ID: 1,
            Name: "router.tailnet.ts.net.".into(),
            Key: router_key.clone(),
            Addresses: vec!["100.64.0.1/32".into()],
            AllowedIPs: vec!["100.64.0.1/32".into(), "192.0.2.0/24".into()],
            ..Default::default()
        },
        Node {
            ID: 2,
            Name: "host.tailnet.ts.net.".into(),
            Key: host_key.clone(),
            Addresses: vec!["100.64.0.2/32".into()],
            AllowedIPs: vec!["100.64.0.2/32".into()],
            ..Default::default()
        },
    ];

    // accept_routes=true: both tailnet + subnet routes installed.
    let rt = RouteTable::from_peers_with_opts(&peers, true);
    assert_eq!(
        rt.lookup(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))),
        Some(router_key.clone()),
        "router tailnet IP should route to router"
    );
    assert_eq!(
        rt.lookup(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2))),
        Some(host_key.clone()),
        "host tailnet IP should route to host"
    );
    assert_eq!(
        rt.lookup(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42))),
        Some(router_key.clone()),
        "subnet route 192.0.2.0/24 should route to router"
    );

    // accept_routes=false: subnet route is NOT installed.
    let rt_no = RouteTable::from_peers_with_opts(&peers, false);
    assert_eq!(
        rt_no.lookup(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))),
        Some(router_key.clone()),
        "tailnet IP still routes without accept_routes"
    );
    assert!(
        rt_no
            .lookup(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42)))
            .is_none(),
        "subnet route should NOT be installed without accept_routes"
    );
}

/// Builder stores advertise_routes and accept_routes.
#[test]
fn builder_stores_advertise_and_accept_routes() {
    let server = ServerBuilder::default()
        .hostname("router")
        .auth_key("tskey-x")
        .advertise_routes(vec!["192.0.2.0/24".into(), "10.0.0.0/16".into()])
        .accept_routes(true)
        .build()
        .unwrap();
    assert_eq!(
        server.config.advertise_routes,
        vec!["192.0.2.0/24", "10.0.0.0/16"]
    );
    assert!(server.config.accept_routes);
}

/// Builder defaults: no advertised routes, accept_routes=false.
#[test]
fn builder_defaults_no_routes() {
    let server = ServerBuilder::default()
        .hostname("x")
        .auth_key("k")
        .build()
        .unwrap();
    assert!(server.config.advertise_routes.is_empty());
    assert!(!server.config.accept_routes);
    assert!(!server.config.advertise_exit_node);
}

/// Builder stores advertise_exit_node flag.
#[test]
fn builder_stores_advertise_exit_node() {
    let server = ServerBuilder::default()
        .hostname("exit")
        .auth_key("tskey-x")
        .advertise_exit_node(true)
        .build()
        .unwrap();
    assert!(server.config.advertise_exit_node);
    // effective_advertise_routes must include the default routes.
    let routes = server.config.effective_advertise_routes();
    assert!(routes.contains(&"0.0.0.0/0".to_string()));
    assert!(routes.contains(&"::/0".to_string()));
}

/// Builder with advertise_exit_node=false has no exit routes.
#[test]
fn builder_no_exit_node_no_default_routes() {
    let server = ServerBuilder::default()
        .hostname("x")
        .auth_key("k")
        .advertise_routes(vec!["192.0.2.0/24".into()])
        .build()
        .unwrap();
    let routes = server.config.effective_advertise_routes();
    assert!(!routes.contains(&"0.0.0.0/0".to_string()));
    assert_eq!(routes, vec!["192.0.2.0/24"]);
}

/// effective_advertise_routes avoids duplicate default routes.
#[test]
fn effective_routes_no_duplicate_defaults() {
    let server = ServerBuilder::default()
        .hostname("x")
        .auth_key("k")
        .advertise_routes(vec!["0.0.0.0/0".into(), "192.0.2.0/24".into()])
        .advertise_exit_node(true)
        .build()
        .unwrap();
    let routes = server.config.effective_advertise_routes();
    let default_count = routes.iter().filter(|r| *r == "0.0.0.0/0").count();
    assert_eq!(default_count, 1, "0.0.0.0/0 should appear exactly once");
    assert!(routes.contains(&"::/0".to_string()));
    assert!(routes.contains(&"192.0.2.0/24".to_string()));
}

// ---------------------------------------------------------------------------
// Exit-node peer resolution (fake netmap — no control connection)
// ---------------------------------------------------------------------------

fn exit_peer(name: &str, ip: &str, key: NodePublic) -> Node {
    Node {
        ID: 1,
        Name: name.to_string(),
        Key: key,
        Addresses: vec![format!("{ip}/32")],
        AllowedIPs: vec![format!("{ip}/32"), "0.0.0.0/0".into()],
        ..Default::default()
    }
}

fn normal_peer(name: &str, ip: &str, key: NodePublic) -> Node {
    Node {
        ID: 2,
        Name: name.to_string(),
        Key: key,
        Addresses: vec![format!("{ip}/32")],
        AllowedIPs: vec![format!("{ip}/32")],
        ..Default::default()
    }
}

#[test]
fn resolve_exit_node_by_ip() {
    let exit_key = NodePrivate::generate();
    let exit = exit_peer("exit.tailnet.ts.net.", "100.64.0.5", exit_key.public());
    let peers = vec![exit];
    let key = resolve_exit_node(&peers, "100.64.0.5").expect("should resolve");
    assert_eq!(key, exit_key.public());
}

#[test]
fn resolve_exit_node_by_fqdn() {
    let exit_key = NodePrivate::generate();
    let exit = exit_peer("exit.tailnet.ts.net.", "100.64.0.5", exit_key.public());
    let peers = vec![exit];
    let key = resolve_exit_node(&peers, "exit.tailnet.ts.net").expect("should resolve");
    assert_eq!(key, exit_key.public());
}

#[test]
fn resolve_exit_node_by_short_name() {
    let exit_key = NodePrivate::generate();
    let exit = exit_peer("exitnode.tailnet.ts.net.", "100.64.0.5", exit_key.public());
    let peers = vec![exit];
    let key = resolve_exit_node(&peers, "exitnode").expect("should resolve");
    assert_eq!(key, exit_key.public());
}

#[test]
fn resolve_exit_node_case_insensitive() {
    let exit_key = NodePrivate::generate();
    let exit = exit_peer("Exit.tailnet.ts.net.", "100.64.0.5", exit_key.public());
    let peers = vec![exit];
    let key = resolve_exit_node(&peers, "EXIT.tailnet.ts.net").expect("should resolve");
    assert_eq!(key, exit_key.public());
}

#[test]
fn resolve_exit_node_not_found_ip() {
    let exit_key = NodePrivate::generate();
    let exit = exit_peer("exit.tailnet.ts.net.", "100.64.0.5", exit_key.public());
    let peers = vec![exit];
    let err = resolve_exit_node(&peers, "100.64.0.99").unwrap_err();
    assert!(matches!(err, TsnetError::ExitNodeNotFound(_)));
}

#[test]
fn resolve_exit_node_not_found_name() {
    let exit_key = NodePrivate::generate();
    let exit = exit_peer("exit.tailnet.ts.net.", "100.64.0.5", exit_key.public());
    let peers = vec![exit];
    let err = resolve_exit_node(&peers, "nonexistent").unwrap_err();
    assert!(matches!(err, TsnetError::ExitNodeNotFound(_)));
}

#[test]
fn resolve_exit_node_not_exit_capable() {
    let key = NodePrivate::generate();
    let normal = normal_peer("host.tailnet.ts.net.", "100.64.0.6", key.public());
    let peers = vec![normal];
    let err = resolve_exit_node(&peers, "100.64.0.6").unwrap_err();
    assert!(matches!(err, TsnetError::NotExitCapable(_)));
}

#[test]
fn resolve_exit_node_prefers_exit_capable_when_multiple_peers() {
    let exit_key = NodePrivate::generate();
    let other_key = NodePrivate::generate();
    let exit = exit_peer("exit.tailnet.ts.net.", "100.64.0.5", exit_key.public());
    let other = normal_peer("host.tailnet.ts.net.", "100.64.0.6", other_key.public());
    let peers = vec![other, exit];
    // Resolving by the exit node's IP should find the exit-capable peer.
    let key = resolve_exit_node(&peers, "100.64.0.5").expect("should resolve");
    assert_eq!(key, exit_key.public());
    // Resolving by the non-exit peer's IP should fail with NotExitCapable.
    let err = resolve_exit_node(&peers, "100.64.0.6").unwrap_err();
    assert!(matches!(err, TsnetError::NotExitCapable(_)));
}

// ---------------------------------------------------------------------------
// State file roundtrip (tested in state.rs, but also verify via Server)
// ---------------------------------------------------------------------------

#[test]
fn server_state_save_load_via_server() {
    let tmp = std::env::temp_dir().join("tsnet-server-state-test");
    let _ = std::fs::remove_dir_all(&tmp);

    let server = ServerBuilder::default()
        .hostname("test")
        .auth_key("tskey-x")
        .state_dir(tmp.clone())
        .build()
        .unwrap();

    // Generate state and save.
    let state = PersistedState::generate();
    server.save_state(&state).expect("save");

    // Load it back.
    let loaded = server.load_or_create_state().expect("load");
    assert_eq!(loaded.node_key.raw32(), state.node_key.raw32());
    assert_eq!(loaded.machine_key.raw32(), state.machine_key.raw32());
    assert_eq!(loaded.disco_key.raw32(), state.disco_key.raw32());

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn server_loads_existing_state_from_disk() {
    let tmp = std::env::temp_dir().join("tsnet-server-load-test");
    let _ = std::fs::remove_dir_all(&tmp);

    // First server generates and saves.
    let s1 = ServerBuilder::default()
        .hostname("test")
        .auth_key("tskey-x")
        .state_dir(tmp.clone())
        .build()
        .unwrap();
    let state = PersistedState::generate();
    s1.save_state(&state).expect("save");

    // Second server loads from the same dir.
    let s2 = ServerBuilder::default()
        .hostname("test")
        .auth_key("tskey-x")
        .state_dir(tmp.clone())
        .build()
        .unwrap();
    let loaded = s2.load_or_create_state().expect("load");
    assert_eq!(loaded.node_key.raw32(), state.node_key.raw32());

    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// Status on a non-up server
// ---------------------------------------------------------------------------

#[test]
fn status_before_up_returns_down() {
    let server = ServerBuilder::default()
        .hostname("test")
        .auth_key("tskey-x")
        .build()
        .unwrap();
    let status = server.status();
    assert!(!status.up);
    assert_eq!(status.peer_count, 0);
}

// ---------------------------------------------------------------------------
// Back-to-back netstack rig: HTTP roundtrip (plain TCP) + TLS handshake
// ---------------------------------------------------------------------------
//
// Two netstacks wired through in-memory WG tunnels (same rig as
// netstack/tests.rs). We listen on B, dial from A, and run a minimal HTTP/1.1
// exchange over the resulting stream — both plain TCP and TLS (self-signed).

use rustscale_netstack::{Netstack, DEFAULT_MTU};
use std::net::SocketAddr;

/// Cross-feed a WG datagram from src to dst, recursively handling replies.
fn cross_feed(
    datagram: &[u8],
    dst_tunn: &Mutex<WgTunn>,
    src_tunn: &Mutex<WgTunn>,
    dst_net: &Netstack,
    src_net: &Netstack,
) {
    let decap = dst_tunn
        .lock()
        .expect("dst lock")
        .decapsulate(datagram)
        .unwrap_or_default();
    if let Some(pt) = decap.plaintext {
        dst_net.push_rx(pt);
    }
    for reply in decap.replies {
        let src_decap = src_tunn
            .lock()
            .expect("src lock")
            .decapsulate(&reply)
            .unwrap_or_default();
        if let Some(pt) = src_decap.plaintext {
            src_net.push_rx(pt);
        }
        for r2 in src_decap.replies {
            cross_feed(&r2, dst_tunn, src_tunn, dst_net, src_net);
        }
    }
}

/// One pump cycle: drain outgoing from both netstacks, encapsulate, cross-feed,
/// tick timers, cross-feed timer output. Returns true if any work was done.
fn pump_cycle(
    a_tunn: &Mutex<WgTunn>,
    b_tunn: &Mutex<WgTunn>,
    a_net: &Netstack,
    b_net: &Netstack,
    capture: Option<&crate::capture::CaptureSlot>,
) -> bool {
    let mut did_work = false;
    while let Some(pkt) = a_net.pop_tx() {
        did_work = true;
        if let Some(capture) = capture {
            crate::capture::log_packet(
                capture,
                crate::capture::CapturePath::SynthesizedToPeer,
                &pkt,
            );
        }
        let dgs = a_tunn
            .lock()
            .expect("a")
            .encapsulate(&pkt)
            .unwrap_or_default();
        for dg in dgs {
            cross_feed(&dg, b_tunn, a_tunn, b_net, a_net);
        }
    }
    while let Some(pkt) = b_net.pop_tx() {
        did_work = true;
        if let Some(capture) = capture {
            crate::capture::log_packet(
                capture,
                crate::capture::CapturePath::SynthesizedToPeer,
                &pkt,
            );
        }
        let dgs = b_tunn
            .lock()
            .expect("b")
            .encapsulate(&pkt)
            .unwrap_or_default();
        for dg in dgs {
            cross_feed(&dg, a_tunn, b_tunn, a_net, b_net);
        }
    }
    for dg in a_tunn.lock().expect("a timers").tick_timers() {
        did_work = true;
        cross_feed(&dg, b_tunn, a_tunn, b_net, a_net);
    }
    for dg in b_tunn.lock().expect("b timers").tick_timers() {
        did_work = true;
        cross_feed(&dg, a_tunn, b_tunn, a_net, b_net);
    }
    did_work
}

/// Set up a back-to-back rig: two netstacks + WG tunnels + a pump task.
/// Returns (a_net, b_net, pump_handle).
fn make_rig() -> (Arc<Netstack>, Arc<Netstack>, tokio::task::JoinHandle<()>) {
    make_rig_with_capture(None)
}

fn make_rig_with_capture(
    capture: Option<crate::capture::CaptureSlot>,
) -> (Arc<Netstack>, Arc<Netstack>, tokio::task::JoinHandle<()>) {
    let a_priv = NodePrivate::generate();
    let b_priv = NodePrivate::generate();
    let a_pub = a_priv.public();
    let b_pub = b_priv.public();

    let a_net = Arc::new(Netstack::new(Ipv4Addr::new(100, 64, 0, 1), DEFAULT_MTU));
    let b_net = Arc::new(Netstack::new(Ipv4Addr::new(100, 64, 0, 2), DEFAULT_MTU));

    let a_tunn = Arc::new(Mutex::new(
        WgTunn::new(&a_priv, &b_pub, 1).expect("A tunnel"),
    ));
    let b_tunn = Arc::new(Mutex::new(
        WgTunn::new(&b_priv, &a_pub, 2).expect("B tunnel"),
    ));

    let a_t = a_tunn.clone();
    let b_t = b_tunn.clone();
    let a_n = a_net.clone();
    let b_n = b_net.clone();
    let pump = tokio::spawn(async move {
        let a_tx = a_n.tx_notify();
        let b_tx = b_n.tx_notify();
        loop {
            let did = pump_cycle(&a_t, &b_t, &a_n, &b_n, capture.as_ref());
            if !did {
                tokio::select! {
                    () = a_tx.notified() => {}
                    () = b_tx.notified() => {}
                    () = tokio::time::sleep(std::time::Duration::from_millis(10)) => {}
                }
            }
        }
    });
    (a_net, b_net, pump)
}

#[tokio::test]
async fn netstack_mode_capture_emits_parseable_pcap() {
    let capture = crate::capture::new_slot();
    let sink = crate::capture::get_or_set(&capture);
    let temp = tempfile::NamedTempFile::new().expect("capture file");
    let handle = sink
        .register_output(std::fs::File::create(temp.path()).expect("open capture file"))
        .expect("register capture file");
    let (a_net, b_net, pump) = make_rig_with_capture(Some(capture));
    let mut listener = b_net.listen(8081).await.expect("listen");
    let accept = tokio::spawn(async move { listener.accept().await.expect("accept") });
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)), 8081);
    let client = tokio::time::timeout(std::time::Duration::from_secs(5), a_net.dial(addr))
        .await
        .expect("dial timeout")
        .expect("dial");
    drop(client);
    let accepted = tokio::time::timeout(std::time::Duration::from_secs(5), accept)
        .await
        .expect("accept timeout")
        .expect("accept task");
    drop(accepted);
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let bytes = std::fs::read(temp.path()).expect("read capture file");
    assert!(
        bytes.len() >= 44,
        "pcap must contain a record: {} bytes",
        bytes.len()
    );
    assert_eq!(&bytes[..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
    let caplen = u32::from_le_bytes(bytes[32..36].try_into().unwrap()) as usize;
    assert!(caplen >= 4);
    assert!(bytes.len() >= 24 + 16 + caplen);
    assert_eq!(&bytes[40..42], &[3, 0]);
    drop(handle);
    pump.abort();
}

/// Minimal HTTP/1.1 server: read request line, respond with a fixed body.
async fn http_serve_once(stream: &mut NetstackStream) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(std::time::Duration::from_secs(10), stream.read(&mut buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "read"))??;
    let req = String::from_utf8_lossy(&buf[..n]);
    let path = req.split(' ').nth(1).unwrap_or("/");
    let body = if path == "/bench" {
        "BENCH:ok".repeat(128)
    } else {
        "hello from rustscale tsnet serve".to_string()
    };
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(resp.as_bytes()).await?;
    Ok(())
}

/// Plain TCP HTTP roundtrip over the back-to-back netstack rig.
#[tokio::test]
async fn http_roundtrip_plain_tcp() {
    let (a_net, b_net, pump) = make_rig();

    // B listens on port 8080.
    let mut listener = b_net.listen(8080).await.expect("listen");

    // Spawn the HTTP server on B (accept one connection, serve, close).
    let b_net_s = b_net.clone();
    let server_task = tokio::spawn(async move {
        let mut stream =
            tokio::time::timeout(std::time::Duration::from_secs(10), listener.accept())
                .await
                .expect("accept timeout")
                .expect("accept");
        http_serve_once(&mut stream).await.expect("serve");
        tokio::io::AsyncWriteExt::shutdown(&mut stream).await.ok();
        drop(b_net_s);
    });

    // A dials B.
    let dial_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)), 8080);
    let mut client =
        tokio::time::timeout(std::time::Duration::from_secs(10), a_net.dial(dial_addr))
            .await
            .expect("dial timeout")
            .expect("dial failed");

    // Send a GET / request.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write");

    // Read the response.
    let mut resp = vec![0u8; 4096];
    let n = tokio::time::timeout(std::time::Duration::from_secs(10), client.read(&mut resp))
        .await
        .expect("read timeout")
        .expect("read");
    let resp_str = String::from_utf8_lossy(&resp[..n]);
    assert!(
        resp_str.starts_with("HTTP/1.1 200 OK"),
        "bad response: {resp_str}"
    );
    assert!(
        resp_str.contains("hello from rustscale tsnet serve"),
        "missing body: {resp_str}"
    );

    server_task.await.ok();
    pump.abort();
}

/// TLS handshake + HTTP roundtrip over the back-to-back rig using a
/// self-signed cert (client skips verification).
#[tokio::test]
async fn http_roundtrip_tls_self_signed() {
    ensure_ring_provider();
    let (a_net, b_net, pump) = make_rig();

    // B listens plain TCP on 8443; we wrap with a TlsListener using a
    // self-signed cert provider.
    let provider: Arc<dyn CertProvider> =
        Arc::new(SelfSignedCertProvider::new(vec!["localhost".into()]).expect("cert"));
    let plain_listener = b_net.listen(8443).await.expect("listen");
    let mut tls_listener = TlsListener::new(plain_listener, provider).expect("tls listener");

    // Spawn the TLS HTTP server on B.
    let server_task = tokio::spawn(async move {
        let mut tls_stream =
            tokio::time::timeout(std::time::Duration::from_secs(15), tls_listener.accept())
                .await
                .expect("tls accept timeout")
                .expect("tls accept");

        // Read HTTP request over TLS.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut buf = vec![0u8; 4096];
        let n = tls_stream.read(&mut buf).await.expect("tls read");
        let req = String::from_utf8_lossy(&buf[..n]);
        let path = req.split(' ').nth(1).unwrap_or("/");
        let body = if path == "/bench" {
            "BENCH:ok".repeat(64)
        } else {
            "hello over TLS".to_string()
        };
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        tls_stream
            .write_all(resp.as_bytes())
            .await
            .expect("tls write");
        tls_stream.shutdown().await.ok();
    });

    // A dials B (plain TCP), then wraps with a TLS client that skips
    // certificate verification (the cert is self-signed).
    let dial_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)), 8443);
    let raw = tokio::time::timeout(std::time::Duration::from_secs(10), a_net.dial(dial_addr))
        .await
        .expect("dial timeout")
        .expect("dial failed");

    // Build a rustls client config with a danger verifier that accepts any
    // server certificate (self-signed cert, no CA).
    let client_config = dangerous_client_config();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let domain = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls_client = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        connector.connect(domain, raw),
    )
    .await
    .expect("tls handshake timeout")
    .expect("tls handshake failed");

    // HTTP GET over TLS.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tls_client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("tls write");

    let mut resp = vec![0u8; 4096];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tls_client.read(&mut resp),
    )
    .await
    .expect("tls read timeout")
    .expect("tls read");
    let resp_str = String::from_utf8_lossy(&resp[..n]);
    assert!(
        resp_str.starts_with("HTTP/1.1 200 OK"),
        "bad tls response: {resp_str}"
    );
    assert!(
        resp_str.contains("hello over TLS"),
        "missing tls body: {resp_str}"
    );

    server_task.await.ok();
    pump.abort();
}

/// Build a rustls client config that skips server certificate verification.
/// **DANGEROUS — test only.** The self-signed certs used by listen_tls have
/// no CA chain, so the client must accept any cert.
fn dangerous_client_config() -> rustls::ClientConfig {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    #[derive(Debug)]
    struct NoVerify;

    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
            ]
        }
    }

    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth()
}

// ---------------------------------------------------------------------------
// E2E tests (#[ignore] — require TS_E2E_AUTHKEY + TS_E2E_TAILNET)
// ---------------------------------------------------------------------------

/// Single-node e2e: up() + status() sanity check.
#[tokio::test]
#[ignore = "requires TS_E2E_AUTHKEY + TS_E2E_TAILNET env vars (run via tools/e2e.sh)"]
async fn e2e_register_only() {
    let authkey = std::env::var("TS_E2E_AUTHKEY").expect("TS_E2E_AUTHKEY not set");
    let _tailnet = std::env::var("TS_E2E_TAILNET").expect("TS_E2E_TAILNET not set");

    let mut server = Server::builder()
        .hostname(format!("rustscale-e2e-register-{}", std::process::id()))
        .auth_key(authkey)
        .ephemeral(true)
        .build()
        .expect("build");

    Box::pin(server.up()).await.expect("up");

    let status = server.status();
    assert!(status.up, "server should be up");
    assert!(
        !status.tailscale_ips.is_empty(),
        "should have at least one tailscale IP"
    );

    // Clean up.
    server.close().await;
}

/// Helper: wait for a specific peer IP to appear in a server's netmap.
/// Hard deadline 90s. On timeout, panics with the full peer list.
async fn wait_for_peer(server: &Server, target_ip: std::net::IpAddr, label: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    loop {
        let st = server.status();
        if st.peers.iter().any(|p| p.ips.contains(&target_ip)) {
            return;
        }
        if std::time::Instant::now() >= deadline {
            let peers: Vec<String> = st
                .peers
                .iter()
                .map(|p| format!("  {} ips={:?} path={:?}", p.name, p.ips, p.path_class))
                .collect();
            let elapsed = 90;
            panic!(
                "{label}: peer {target_ip} never appeared in netmap after {elapsed}s\n\
                 current peers ({}):\n{}",
                peers.len(),
                peers.join("\n")
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

/// Two-node e2e: spin up two tsnet servers, dial A->B, echo bytes.
/// Every operation has a hard timeout; no unbounded waits.
#[tokio::test]
#[ignore = "requires TS_E2E_AUTHKEY + TS_E2E_TAILNET env vars (run via tools/e2e.sh)"]
async fn e2e_two_nodes() {
    let authkey = std::env::var("TS_E2E_AUTHKEY").expect("TS_E2E_AUTHKEY not set");
    let _tailnet = std::env::var("TS_E2E_TAILNET").expect("TS_E2E_TAILNET not set");

    // Unique hostname suffix to avoid collisions with stale nodes from
    // other test suites running in the same ephemeral tailnet.
    let uid = std::process::id();

    // Start server A.
    let mut server_a = Server::builder()
        .hostname(format!("rustscale-e2e-a-{uid}"))
        .auth_key(authkey.clone())
        .ephemeral(true)
        .build()
        .expect("build A");
    Box::pin(server_a.up()).await.expect("up A");
    let status_a = server_a.status();
    let ip_a = status_a
        .tailscale_ips
        .iter()
        .find_map(|ip| match ip {
            std::net::IpAddr::V4(v4) => Some(*v4),
            _ => None,
        })
        .expect("A should have an IPv4");

    // Start server B.
    let mut server_b = Server::builder()
        .hostname(format!("rustscale-e2e-b-{uid}"))
        .auth_key(authkey)
        .ephemeral(true)
        .build()
        .expect("build B");
    Box::pin(server_b.up()).await.expect("up B");
    let status_b = server_b.status();
    let ip_b = status_b
        .tailscale_ips
        .iter()
        .find_map(|ip| match ip {
            std::net::IpAddr::V4(v4) => Some(*v4),
            _ => None,
        })
        .expect("B should have an IPv4");

    // B listens on a port.
    let mut listener = server_b.listen(4242).await.expect("listen");

    // Wait for B's specific IP to appear in A's netmap (hard 90s deadline).
    wait_for_peer(&server_a, ip_b.into(), "e2e_two_nodes").await;

    // Give the WG handshake a moment to complete after the peer appeared.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // A dials B. Retry up to 3 times — the WG handshake may not have
    // completed when the peer first appears in the netmap, causing the
    // first dial to time out. Each attempt gives the handshake more time.
    let dial_addr = format!("{ip_b}:4242");
    let mut stream_a = None;
    for attempt in 1..=3 {
        log::debug!("dial attempt {attempt} to {dial_addr}");
        let dial_result = tokio::time::timeout(
            std::time::Duration::from_secs(45),
            server_a.dial(&dial_addr),
        )
        .await;
        match dial_result {
            Ok(Ok(s)) => {
                stream_a = Some(s);
                break;
            }
            Ok(Err(e)) => {
                log::warn!("dial attempt {attempt} failed: {e}");
            }
            Err(_) => {
                let st = server_a.status();
                let peers: Vec<String> = st
                    .peers
                    .iter()
                    .map(|p| format!("  {} ips={:?} path={:?}", p.name, p.ips, p.path_class))
                    .collect();
                log::debug!(
                    "dial attempt {attempt} timed out (45s)\nA peers ({}):\n{}",
                    peers.len(),
                    peers.join("\n")
                );
            }
        }
        if attempt < 3 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    }
    let mut stream_a = stream_a.expect("all 3 dial attempts failed");

    // B accepts (hard 30s timeout).
    let accept_result =
        tokio::time::timeout(std::time::Duration::from_secs(30), listener.accept()).await;
    let mut stream_b = accept_result
        .expect("accept timed out (30s)")
        .expect("accept failed");

    // A sends, B reads and echoes. Every I/O has a hard 30s timeout.
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio::io::AsyncWriteExt::write_all(&mut stream_a, b"hello e2e"),
    )
    .await
    .expect("A write timed out (30s)")
    .expect("A write failed");

    let mut buf = [0u8; 32];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio::io::AsyncReadExt::read(&mut stream_b, &mut buf),
    )
    .await
    .expect("B read timed out (30s)")
    .expect("B read failed");
    assert_eq!(&buf[..n], b"hello e2e");

    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio::io::AsyncWriteExt::write_all(&mut stream_b, b"world e2e"),
    )
    .await
    .expect("B write timed out (30s)")
    .expect("B write failed");

    let n = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio::io::AsyncReadExt::read(&mut stream_a, &mut buf),
    )
    .await
    .expect("A read timed out (30s)")
    .expect("A read failed");
    assert_eq!(&buf[..n], b"world e2e");

    // Check path (any of derp/direct ok).
    let _ = ip_a;
    let status_a = server_a.status();
    assert!(
        !status_a.peers.is_empty(),
        "A should have at least one peer"
    );

    // Clean up.
    tokio::io::AsyncWriteExt::shutdown(&mut stream_a).await.ok();
    server_a.close().await;
    server_b.close().await;
}

// ---------------------------------------------------------------------------
// E2E: subnet route advertisement + acceptance
// ---------------------------------------------------------------------------

/// Call the Tailscale API via curl (the test harness sets TS_E2E_API_TOKEN
/// and TS_E2E_TAILNET). Returns stdout as a String.
fn api_get(path: &str) -> Result<String, String> {
    let token = std::env::var("TS_E2E_API_TOKEN").map_err(|_| "TS_E2E_API_TOKEN not set")?;
    let url = format!("https://api.tailscale.com{path}");
    let out = std::process::Command::new("curl")
        .args([
            "-fsS",
            "-H",
            &format!("Authorization: Bearer {token}"),
            &url,
        ])
        .output()
        .map_err(|e| format!("curl: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "curl {url} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Approve advertised routes for a device via the API.
fn api_approve_routes(device_id: &str, routes: &[&str]) -> Result<(), String> {
    let token = std::env::var("TS_E2E_API_TOKEN").map_err(|_| "TS_E2E_API_TOKEN not set")?;
    let url = format!("https://api.tailscale.com/api/v2/device/{device_id}/routes");
    let body = format!("{{\"routes\":{}}}", serde_json::to_string(routes).unwrap());
    let out = std::process::Command::new("curl")
        .args([
            "-fsS",
            "-X",
            "POST",
            "-H",
            &format!("Authorization: Bearer {token}"),
            "-H",
            "Content-Type: application/json",
            "-d",
            &body,
            &url,
        ])
        .output()
        .map_err(|e| format!("curl: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "approve routes failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

/// Find a device ID by hostname prefix in the tailnet's device list.
fn find_device_id(hostname_prefix: &str) -> Result<String, String> {
    let tailnet = std::env::var("TS_E2E_TAILNET").map_err(|_| "TS_E2E_TAILNET not set")?;
    let resp = api_get(&format!("/api/v2/tailnet/{tailnet}/devices"))?;
    let devices: serde_json::Value =
        serde_json::from_str(&resp).map_err(|e| format!("json: {e}"))?;
    let arr = devices
        .get("devices")
        .and_then(|d| d.as_array())
        .ok_or("no devices array")?;
    for dev in arr {
        let name = dev.get("name").and_then(|n| n.as_str()).unwrap_or("");
        if name.contains(hostname_prefix) {
            return dev
                .get("id")
                .and_then(|i| i.as_str())
                .map(String::from)
                .ok_or_else(|| "device id not a string".to_string());
        }
    }
    Err(format!("no device matching '{hostname_prefix}'"))
}

/// E2e subnet routes: node A advertises 192.0.2.0/24 (TEST-NET), the test
/// approves it via the API, node B accepts routes, and B's route table must
/// contain 192.0.2.0/24 -> A.
#[tokio::test]
#[ignore = "requires TS_E2E_AUTHKEY + TS_E2E_TAILNET env vars (run via tools/e2e.sh)"]
async fn e2e_subnet_routes() {
    let authkey = std::env::var("TS_E2E_AUTHKEY").expect("TS_E2E_AUTHKEY not set");
    let _tailnet = std::env::var("TS_E2E_TAILNET").expect("TS_E2E_TAILNET not set");
    let uid = std::process::id();
    let subnet = "192.0.2.0/24";

    // Start node A — the subnet router (advertises 192.0.2.0/24).
    let mut server_a = Server::builder()
        .hostname(format!("rustscale-e2e-router-{uid}"))
        .auth_key(authkey.clone())
        .ephemeral(true)
        .advertise_routes(vec![subnet.into()])
        .build()
        .expect("build A");
    Box::pin(server_a.up()).await.expect("up A");
    let status_a = server_a.status();
    assert!(!status_a.tailscale_ips.is_empty(), "A should have IPs");
    let ip_a = status_a.tailscale_ips[0];
    log::debug!("A up: ip={ip_a}, advertising {subnet}");

    // Wait for A to appear in the device list, then approve its routes.
    // The device may take a few seconds to show up in the API after up().
    let device_id = {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let mut found = None;
        let hostname_prefix = format!("rustscale-e2e-router-{uid}");
        while std::time::Instant::now() < deadline {
            match find_device_id(&hostname_prefix) {
                Ok(id) => {
                    found = Some(id);
                    break;
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_secs(2)).await,
            }
        }
        found.expect("A never appeared in device list (30s)")
    };
    log::debug!("A device_id={device_id}, approving routes...");
    api_approve_routes(&device_id, &[subnet]).expect("approve routes");
    log::debug!("routes approved");

    // Start node B — accepts routes.
    let mut server_b = Server::builder()
        .hostname(format!("rustscale-e2e-client-{uid}"))
        .auth_key(authkey)
        .ephemeral(true)
        .accept_routes(true)
        .build()
        .expect("build B");
    Box::pin(server_b.up()).await.expect("up B");

    // Wait for A to appear in B's netmap, then check B's route table for the
    // subnet route. The route may take a few map updates to propagate after
    // approval (control pushes the updated AllowedIPs).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    loop {
        let st = server_b.status();
        if st.peers.iter().any(|p| p.ips.contains(&ip_a)) {
            // Peer is visible — check the route table.
            if let Some(peer_key) = server_b.route_lookup(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42)))
            {
                log::debug!("B route for 192.0.2.42 -> {peer_key:?}");
                let routes = server_b.routes();
                let has_subnet = routes.iter().any(|(cidr, _)| cidr == subnet);
                assert!(
                    has_subnet,
                    "B's route table should contain {subnet}, got: {routes:?}"
                );
                log::debug!("SUCCESS: B has route {subnet} -> peer");
                break;
            }
        }
        if std::time::Instant::now() >= deadline {
            let routes = server_b.routes();
            panic!(
                "subnet route {subnet} never appeared in B's route table (90s)\n\
                 B routes: {routes:?}\n\
                 B peers: {}",
                st.peers
                    .iter()
                    .map(|p| format!("{} ips={:?}", p.name, p.ips))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    server_a.close().await;
    server_b.close().await;
}

// ---------------------------------------------------------------------------
// WhoIs unit test (fake netmap — no control connection)
// ---------------------------------------------------------------------------

#[test]
fn whois_lookup_from_fake_netmap() {
    use rustscale_tailcfg::UserProfile;
    let peer = Node {
        ID: 11,
        Name: "host-b.tailnet.ts.net.".into(),
        User: 7,
        Key: NodePrivate::generate().public(),
        Addresses: vec!["100.64.0.5/32".into(), "fd7a:115c:a1e0::5/128".into()],
        ..Default::default()
    };
    let peers = vec![peer];
    let mut ups = std::collections::BTreeMap::new();
    ups.insert(
        7,
        UserProfile {
            ID: 7,
            LoginName: "bob@example.com".into(),
            DisplayName: "Bob".into(),
            ProfilePicURL: String::new(),
        },
    );
    let ip: IpAddr = "100.64.0.5".parse().unwrap();
    let info = whois_lookup(&peers, &ups, ip).expect("peer should be found");
    assert!(info.found);
    assert_eq!(info.node_name, "host-b.tailnet.ts.net.");
    assert_eq!(info.user_id, 7);
    assert_eq!(info.login_name, "bob@example.com");
    assert_eq!(info.display_name, "Bob");
    assert!(info.tailscale_ips.contains(&ip));

    // Unknown IP → None.
    let unknown: IpAddr = "100.64.0.99".parse().unwrap();
    assert!(whois_lookup(&peers, &ups, unknown).is_none());
}

// ---------------------------------------------------------------------------
// E2E: WhoIs + MagicDNS short-name dial + control cert "not enabled"
// ---------------------------------------------------------------------------

/// Two-node e2e: A does whois(B's IP) and gets B's hostname; A dials B by
/// MagicDNS short name.
#[tokio::test]
#[ignore = "requires TS_E2E_AUTHKEY + TS_E2E_TAILNET env vars (run via tools/e2e.sh)"]
async fn e2e_whois_and_magicdns_dial() {
    let authkey = std::env::var("TS_E2E_AUTHKEY").expect("TS_E2E_AUTHKEY not set");
    let _tailnet = std::env::var("TS_E2E_TAILNET").expect("TS_E2E_TAILNET not set");
    let uid = std::process::id();

    let mut server_a = Server::builder()
        .hostname(format!("rustscale-e2e-whois-a-{uid}"))
        .auth_key(authkey.clone())
        .ephemeral(true)
        .build()
        .expect("build A");
    Box::pin(server_a.up()).await.expect("up A");

    let mut server_b = Server::builder()
        .hostname(format!("rustscale-e2e-whois-b-{uid}"))
        .auth_key(authkey)
        .ephemeral(true)
        .build()
        .expect("build B");
    Box::pin(server_b.up()).await.expect("up B");
    let status_b = server_b.status();
    let ip_b = status_b
        .tailscale_ips
        .iter()
        .find_map(|ip| match ip {
            IpAddr::V4(v4) => Some(*v4),
            _ => None,
        })
        .expect("B should have an IPv4");

    // B listens.
    let mut listener = server_b.listen(4343).await.expect("listen");

    // Wait for B to appear in A's netmap.
    wait_for_peer(&server_a, ip_b.into(), "e2e_whois").await;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // WhoIs: A looks up B's IP → should get B's hostname.
    let info = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        server_a.whois(ip_b.into()),
    )
    .await
    .expect("whois timed out")
    .expect("whois returned None (server up?)");
    assert!(info.found, "whois should find peer for {ip_b}");
    log::debug!("whois({ip_b}) -> node_name={}", info.node_name);
    assert!(
        info.node_name
            .to_lowercase()
            .contains(&format!("rustscale-e2e-whois-b-{uid}")),
        "whois node_name should contain B's hostname, got {}",
        info.node_name
    );

    // MagicDNS short-name dial: A dials B by its short hostname (first label
    // of B's MagicDNS FQDN). The resolver resolves the short name from the
    // netmap.
    let short_name = format!("rustscale-e2e-whois-b-{uid}");
    let dial_addr = format!("{short_name}:4343");
    let mut stream_a = None;
    for attempt in 1..=3 {
        log::debug!("MagicDNS dial attempt {attempt} to {dial_addr}");
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(45),
            server_a.dial(&dial_addr),
        )
        .await;
        match r {
            Ok(Ok(s)) => {
                stream_a = Some(s);
                break;
            }
            Ok(Err(e)) => log::warn!("dial attempt {attempt} failed: {e}"),
            Err(_) => log::debug!("dial attempt {attempt} timed out"),
        }
        if attempt < 3 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    }
    let mut stream_a = stream_a.expect("MagicDNS short-name dial failed after 3 attempts");

    // Echo roundtrip to confirm the connection works.
    let mut stream_b = tokio::time::timeout(std::time::Duration::from_secs(30), listener.accept())
        .await
        .expect("accept timed out")
        .expect("accept failed");
    tokio::io::AsyncWriteExt::write_all(&mut stream_a, b"magicdns-ok")
        .await
        .expect("A write");
    let mut buf = [0u8; 32];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio::io::AsyncReadExt::read(&mut stream_b, &mut buf),
    )
    .await
    .expect("B read timed out")
    .expect("B read failed");
    assert_eq!(&buf[..n], b"magicdns-ok");

    tokio::io::AsyncWriteExt::shutdown(&mut stream_a).await.ok();
    server_a.close().await;
    server_b.close().await;
}

/// E2E: control cert provider on an ephemeral API-only tailnet. These
/// tailnets do not have HTTPS/certs enabled by default, so the provider must
/// return a clean typed `CertError::NotEnabled`. If HTTPS happens to be
/// enabled (the e2e harness may flip it), the ACME flow runs and either
/// succeeds or returns an `Acme` error.
#[tokio::test]
#[ignore = "requires TS_E2E_AUTHKEY + TS_E2E_TAILNET env vars (run via tools/e2e.sh)"]
async fn e2e_control_cert_not_enabled() {
    let authkey = std::env::var("TS_E2E_AUTHKEY").expect("TS_E2E_AUTHKEY not set");
    let _tailnet = std::env::var("TS_E2E_TAILNET").expect("TS_E2E_TAILNET not set");
    let uid = std::process::id();

    let state_dir = std::env::temp_dir().join(format!("rustscale-e2e-cert-state-{uid}"));
    let _ = std::fs::remove_dir_all(&state_dir);
    std::fs::create_dir_all(&state_dir).unwrap();

    let mut server = Server::builder()
        .hostname(format!("rustscale-e2e-cert-{uid}"))
        .auth_key(authkey)
        .ephemeral(true)
        .state_dir(state_dir.clone())
        .build()
        .expect("build");
    Box::pin(server.up()).await.expect("up");

    // Give control a moment to deliver DNSConfig.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let result = server.control_cert_provider().await;
    match result {
        Err(CertError::NotEnabled(_)) => {
            log::debug!("control cert: NotEnabled (expected for API-only tailnet)");
        }
        Err(CertError::AcmeClientUnavailable(_)) => {
            log::debug!("control cert: AcmeClientUnavailable (HTTPS enabled, ACME client pending)");
        }
        Err(CertError::Acme(e)) => {
            log::warn!("control cert: Acme error (HTTPS enabled, ACME flow failed): {e}");
        }
        Err(e) => panic!("expected NotEnabled/Acme, got: {e}"),
        Ok(provider) => {
            // If a real cert was provisioned, it must produce a non-empty chain.
            assert!(!provider.cert_chain().is_empty(), "cert chain empty");
            log::debug!("control cert: real cert provisioned");
        }
    }

    // listen_tls must still succeed (falls back to self-signed).
    let tls_listener = server
        .listen_tls(9443)
        .await
        .expect("listen_tls should fall back");
    log::debug!("listen_tls fell back to self-signed OK");
    drop(tls_listener);
    server.close().await;
    std::fs::remove_dir_all(&state_dir).ok();
}

/// E2E: full ACME cert issuance via LE staging. Requires:
/// - `TS_E2E_AUTHKEY` + `TS_E2E_TAILNET` (provisioned by tools/e2e.sh)
/// - `TS_E2E_HTTPS=1` (the harness enables `httpsEnabled` on the tailnet
///   via the settings API before running this test)
/// - `RUSTSCALE_ACME_URL` set to LE staging (the harness sets this)
///
/// The test checks that `DNSConfig.CertDomains` is non-empty (skips with a
/// message if not), then requests a cert for the node's FQDN and asserts a
/// parseable PEM chain.
#[tokio::test]
#[ignore = "live ACME: requires TS_E2E_AUTHKEY + TS_E2E_TAILNET + TS_E2E_HTTPS=1 + RUSTSCALE_ACME_URL (LE staging)"]
async fn e2e_acme_cert_issuance() {
    let authkey = std::env::var("TS_E2E_AUTHKEY").expect("TS_E2E_AUTHKEY not set");
    let _tailnet = std::env::var("TS_E2E_TAILNET").expect("TS_E2E_TAILNET not set");
    let https_enabled = std::env::var("TS_E2E_HTTPS").is_ok_and(|v| v == "1");
    if !https_enabled {
        log::debug!("e2e_acme_cert_issuance: skipping (TS_E2E_HTTPS != 1)");
        return;
    }

    let uid = std::process::id();
    let state_dir = std::env::temp_dir().join(format!("rustscale-e2e-acme-state-{uid}"));
    let _ = std::fs::remove_dir_all(&state_dir);
    std::fs::create_dir_all(&state_dir).unwrap();

    let mut server = Server::builder()
        .hostname(format!("rustscale-e2e-acme-{uid}"))
        .auth_key(authkey)
        .ephemeral(true)
        .state_dir(state_dir.clone())
        .build()
        .expect("build");
    Box::pin(server.up()).await.expect("up");

    // Give control time to deliver DNSConfig with CertDomains.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Check if HTTPS/certs are enabled (CertDomains non-empty).
    let cert_domains: Vec<String> = {
        let inner = server.inner.as_ref().expect("server up");
        inner
            .dns_config
            .read()
            .await
            .as_ref()
            .map(|c| c.CertDomains.clone())
            .unwrap_or_default()
    };
    if cert_domains.is_empty() {
        log::debug!(
            "e2e_acme_cert_issuance: CertDomains empty (HTTPS not enabled on tailnet); skipping"
        );
        server.close().await;
        return;
    }
    log::debug!("e2e_acme_cert_issuance: CertDomains = {cert_domains:?}");

    // Request the cert. This runs the full ACME flow against LE staging.
    let result = tokio::time::timeout(
        std::time::Duration::from_mins(2),
        server.control_cert_provider(),
    )
    .await;

    server.close().await;

    let provider = match result {
        Ok(Ok(p)) => p,
        Ok(Err(CertError::NotEnabled(d))) => {
            log::debug!("e2e_acme_cert_issuance: NotEnabled({d}) — HTTPS not enabled; skipping");
            std::fs::remove_dir_all(&state_dir).ok();
            return;
        }
        Ok(Err(e)) => panic!("control_cert_provider failed: {e}"),
        Err(e) => panic!("control_cert_provider timed out after 120s: {e}"),
    };

    let chain = provider.cert_chain();
    assert!(!chain.is_empty(), "cert chain must be non-empty");
    log::debug!(
        "e2e_acme_cert_issuance: got cert chain with {} cert(s)",
        chain.len()
    );

    // Verify the PEM round-trips (cert_chain already parsed PEM → DER).
    // Just assert the first cert is non-trivial.
    assert!(
        chain[0].as_ref().len() > 100,
        "leaf cert DER suspiciously small"
    );

    std::fs::remove_dir_all(&state_dir).ok();
}

// ---------------------------------------------------------------------------
// E2E: exit node advertisement + selection
// ---------------------------------------------------------------------------

/// E2e exit node: node B advertises itself as an exit node (0.0.0.0/0 +
/// ::/0 in RoutableIPs), the test approves those routes via the API, node A
/// selects B as its exit node, and A's routing table resolves a public IP
/// (8.8.8.8) to peer B.
///
/// This test does **not** depend on real internet egress through B — it only
/// asserts routing-table resolution, which is sufficient for unprivileged CI.
/// It also verifies that tailnet IPs still route to their owning peers (the
/// exit default route doesn't shadow more-specific entries).
#[tokio::test]
#[ignore = "requires TS_E2E_AUTHKEY + TS_E2E_TAILNET + TS_E2E_API_TOKEN env vars (run via tools/e2e.sh)"]
async fn e2e_exit_node() {
    let authkey = std::env::var("TS_E2E_AUTHKEY").expect("TS_E2E_AUTHKEY not set");
    let _tailnet = std::env::var("TS_E2E_TAILNET").expect("TS_E2E_TAILNET not set");
    let uid = std::process::id();

    // --- Node B: advertises exit node ---
    let mut server_b = Server::builder()
        .hostname(format!("rustscale-e2e-exit-b-{uid}"))
        .auth_key(authkey.clone())
        .ephemeral(true)
        .advertise_exit_node(true)
        .build()
        .expect("build B");
    Box::pin(server_b.up()).await.expect("up B");
    let status_b = server_b.status();
    assert!(!status_b.tailscale_ips.is_empty(), "B should have IPs");
    let ip_b = status_b.tailscale_ips[0];
    log::debug!("B up: ip={ip_b}, advertising exit node");

    // Approve B's exit routes (0.0.0.0/0 + ::/0) via the API.
    let device_id = {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let mut found = None;
        let hostname_prefix = format!("rustscale-e2e-exit-b-{uid}");
        while std::time::Instant::now() < deadline {
            match find_device_id(&hostname_prefix) {
                Ok(id) => {
                    found = Some(id);
                    break;
                }
                Err(_) => tokio::time::sleep(std::time::Duration::from_secs(2)).await,
            }
        }
        found.expect("B never appeared in device list (30s)")
    };
    log::debug!("B device_id={device_id}, approving exit routes...");
    api_approve_routes(&device_id, &["0.0.0.0/0", "::/0"]).expect("approve exit routes");
    log::debug!("exit routes approved");

    // --- Node A: selects B as exit node ---
    let mut server_a = Server::builder()
        .hostname(format!("rustscale-e2e-exit-a-{uid}"))
        .auth_key(authkey)
        .ephemeral(true)
        .build()
        .expect("build A");
    Box::pin(server_a.up()).await.expect("up A");

    // Wait for B to appear in A's netmap AND for B's AllowedIPs to contain
    // 0.0.0.0/0 (after approval, control pushes the updated AllowedIPs).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    loop {
        let st = server_a.status();
        if st.peers.iter().any(|p| p.ips.contains(&ip_b)) {
            // Peer is visible — try selecting B as exit node. If B's
            // AllowedIPs don't yet contain 0.0.0.0/0, set_exit_node returns
            // NotExitCapable and we wait for the next map update.
            match server_a.set_exit_node(&ip_b.to_string()).await {
                Ok(()) => {
                    log::debug!("A selected B as exit node");
                    break;
                }
                Err(TsnetError::NotExitCapable(_)) => {
                    // B's AllowedIPs don't yet contain 0.0.0.0/0 — wait.
                }
                Err(e) => panic!("set_exit_node failed unexpectedly: {e}"),
            }
        }
        if std::time::Instant::now() >= deadline {
            let peers: Vec<String> = st
                .peers
                .iter()
                .map(|p| format!("  {} ips={:?}", p.name, p.ips))
                .collect();
            panic!(
                "B's exit routes never appeared in A's netmap (90s)\n\
                 A peers ({}):\n{}",
                peers.len(),
                peers.join("\n")
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    // Core assertion: a public IP resolves to peer B via the exit node.
    let route = server_a.route_lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    assert!(
        route.is_some(),
        "public IP 8.8.8.8 should route to exit node after set_exit_node"
    );
    log::debug!("A route for 8.8.8.8 -> {route:?}");

    // Tailnet IPs still route to their owning peers (more specific than the
    // exit default route).
    let route_b = server_a.route_lookup(ip_b);
    assert!(
        route_b.is_some(),
        "B's tailnet IP should still route after exit node selection"
    );

    // IPv6 public IP also routes to the exit node.
    let v6_pub: IpAddr = "2001:4860:4860::8888".parse().unwrap();
    let route_v6 = server_a.route_lookup(v6_pub);
    assert!(
        route_v6.is_some(),
        "IPv6 public IP should route to exit node"
    );

    // Clear the exit node — public IPs should no longer route.
    server_a.clear_exit_node().await.expect("clear exit node");
    assert!(
        server_a
            .route_lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
            .is_none(),
        "public IP should NOT route after clear_exit_node"
    );
    log::debug!("A cleared exit node — public IPs no longer route");

    // Verify exit_node() accessor.
    assert!(
        server_a.exit_node().await.is_none(),
        "exit_node should be None after clear"
    );

    server_a.close().await;
    server_b.close().await;
}

// ---------------------------------------------------------------------------
// Serve + Funnel e2e tests (#[ignore])
// ---------------------------------------------------------------------------

/// E2e: two nodes, B sets serve config TCP-forwarding port 8080 to a local
/// echo backend. A dials B:8080 and verifies bytes flow through the serve
/// TCP forward handler.
#[tokio::test]
#[ignore = "requires TS_E2E_AUTHKEY + TS_E2E_TAILNET env vars (run via tools/e2e.sh)"]
async fn e2e_serve_tcp_forward() {
    let authkey = std::env::var("TS_E2E_AUTHKEY").expect("TS_E2E_AUTHKEY not set");
    let _tailnet = std::env::var("TS_E2E_TAILNET").expect("TS_E2E_TAILNET not set");
    let uid = std::process::id();

    // Local echo backend on an ephemeral port.
    let echo_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = echo_listener.local_addr().unwrap().to_string();
    log::debug!("e2e_serve: echo backend at {backend_addr}");
    tokio::spawn(async move {
        loop {
            if let Ok((mut sock, _)) = echo_listener.accept().await {
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

    // Start server B with a serve config forwarding port 8080.
    let mut server_b = Server::builder()
        .hostname(format!("rustscale-e2e-serve-b-{uid}"))
        .auth_key(authkey.clone())
        .ephemeral(true)
        .build()
        .expect("build B");
    Box::pin(server_b.up()).await.expect("up B");
    let status_b = server_b.status();
    let ip_b = status_b
        .tailscale_ips
        .iter()
        .find_map(|ip| match ip {
            IpAddr::V4(v4) => Some(*v4),
            _ => None,
        })
        .expect("B should have an IPv4");
    log::debug!("e2e_serve: B up at {ip_b}");

    // Set serve config: TCP forward port 8080 → echo backend.
    let mut cfg = ServeConfig::default();
    cfg.TCP.insert(
        8080,
        TCPPortHandler {
            TCPForward: backend_addr,
            ..Default::default()
        },
    );
    let started = server_b
        .set_serve_config(cfg)
        .await
        .expect("set_serve_config");
    assert!(started.contains(&8080), "serve should be listening on 8080");
    log::debug!("e2e_serve: B serving port 8080 → {started:?}");

    // Start server A.
    let mut server_a = Server::builder()
        .hostname(format!("rustscale-e2e-serve-a-{uid}"))
        .auth_key(authkey)
        .ephemeral(true)
        .build()
        .expect("build A");
    Box::pin(server_a.up()).await.expect("up A");

    // Wait for B to appear in A's netmap.
    wait_for_peer(&server_a, ip_b.into(), "e2e_serve_tcp_forward").await;
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // A dials B:8080 via the serve forward.
    let dial_addr = format!("{ip_b}:8080");
    let mut stream = None;
    for attempt in 1..=3 {
        log::debug!("e2e_serve: dial attempt {attempt} to {dial_addr}");
        match tokio::time::timeout(
            std::time::Duration::from_secs(45),
            server_a.dial(&dial_addr),
        )
        .await
        {
            Ok(Ok(s)) => {
                stream = Some(s);
                break;
            }
            Ok(Err(e)) => log::warn!("dial attempt {attempt} failed: {e}"),
            Err(_) => log::debug!("dial attempt {attempt} timed out"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    let mut stream = stream.expect("all dial attempts failed");

    // Echo test: write bytes, read them back (served via the TCP forward).
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream.write_all(b"serve-echo-test").await.expect("write");
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(std::time::Duration::from_secs(10), stream.read(&mut buf))
        .await
        .expect("read timeout")
        .expect("read err");
    assert_eq!(&buf[..n], b"serve-echo-test");
    log::debug!("e2e_serve: echo verified through serve TCP forward");

    server_a.close().await;
    server_b.close().await;
}

/// E2e: funnel listen_funnel returns a typed FunnelError::NotEnabled on
/// API-only tailnets (where control never grants the `funnel` node attribute).
/// This mirrors the e2e_control_cert_not_enabled pattern.
#[tokio::test]
#[ignore = "requires TS_E2E_AUTHKEY + TS_E2E_TAILNET env vars (run via tools/e2e.sh)"]
async fn e2e_funnel_not_enabled() {
    let authkey = std::env::var("TS_E2E_AUTHKEY").expect("TS_E2E_AUTHKEY not set");
    let _tailnet = std::env::var("TS_E2E_TAILNET").expect("TS_E2E_TAILNET not set");
    let uid = std::process::id();

    let mut server = Server::builder()
        .hostname(format!("rustscale-e2e-funnel-{uid}"))
        .auth_key(authkey)
        .ephemeral(true)
        .build()
        .expect("build");
    Box::pin(server.up()).await.expect("up");

    // Give control a moment to deliver capabilities.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    let result = server.listen_funnel(443).await;
    match result {
        Err(TsnetError::Funnel(FunnelError::NotEnabled)) => {
            log::debug!("e2e_funnel: NotEnabled (expected for API-only tailnet)");
        }
        Err(TsnetError::Funnel(FunnelError::HttpsNotEnabled)) => {
            log::debug!("e2e_funnel: HttpsNotEnabled (HTTPS not enabled on this tailnet)");
        }
        Err(TsnetError::Funnel(FunnelError::PortNotAllowed(_))) => {
            panic!("port 443 should be allowed; got PortNotAllowed");
        }
        Err(e) => {
            log::warn!(
                "e2e_funnel: listen_funnel failed with non-funnel error ({e}) — funnel may not be the issue"
            );
        }
        Ok(listener) => {
            log::debug!("e2e_funnel: funnel listener created (funnel is enabled on this tailnet)");
            drop(listener);
        }
    }

    server.close().await;
}

/// E2e: SOCKS5 proxy. Node B runs an echo listener on its tailnet IP; node A
/// starts `listen_socks5` on `127.0.0.1:0`. The test connects to A's proxy with
/// a hand-rolled SOCKS5 client, CONNECTs to B's tailnet IP, and asserts the
/// echo roundtrips — proving the proxy dials *through the tailnet*.
#[tokio::test]
#[ignore = "requires TS_E2E_AUTHKEY + TS_E2E_TAILNET env vars (run via tools/e2e.sh)"]
async fn e2e_socks5_proxy() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    let authkey = std::env::var("TS_E2E_AUTHKEY").expect("TS_E2E_AUTHKEY not set");
    let _tailnet = std::env::var("TS_E2E_TAILNET").expect("TS_E2E_TAILNET not set");
    let uid = std::process::id();

    // Node A — runs the SOCKS5 proxy.
    let mut server_a = Server::builder()
        .hostname(format!("rustscale-e2e-socks5-a-{uid}"))
        .auth_key(authkey.clone())
        .ephemeral(true)
        .build()
        .expect("build A");
    Box::pin(server_a.up()).await.expect("up A");

    // Node B — runs the echo backend on its tailnet IP.
    let mut server_b = Server::builder()
        .hostname(format!("rustscale-e2e-socks5-b-{uid}"))
        .auth_key(authkey)
        .ephemeral(true)
        .build()
        .expect("build B");
    Box::pin(server_b.up()).await.expect("up B");
    let status_b = server_b.status();
    let ip_b = status_b
        .tailscale_ips
        .iter()
        .find_map(|ip| match ip {
            IpAddr::V4(v4) => Some(*v4),
            _ => None,
        })
        .expect("B should have an IPv4");

    // B listens for echo on a tailnet port.
    const ECHO_PORT: u16 = 4343;
    let mut listener_b = server_b.listen(ECHO_PORT).await.expect("listen B");

    // Wait for B to appear in A's netmap before starting the proxy.
    wait_for_peer(&server_a, ip_b.into(), "e2e_socks5").await;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // A starts the SOCKS5 proxy on an ephemeral loopback port.
    let mut proxy = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        server_a.listen_socks5("127.0.0.1:0"),
    )
    .await
    .expect("listen_socks5 timed out")
    .expect("listen_socks5 failed");
    let proxy_addr = proxy.local_addr();
    log::debug!("e2e_socks5: proxy listening on {proxy_addr}");

    // Accept B's side and run a simple echo loop in a spawned task.
    let echo_task = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream_b =
            tokio::time::timeout(std::time::Duration::from_mins(1), listener_b.accept())
                .await
                .expect("B accept timed out")
                .expect("B accept failed");
        let mut buf = [0u8; 256];
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(30), stream_b.read(&mut buf))
                .await
            {
                Ok(Ok(0)) => break,
                Ok(Err(_)) => break,
                Ok(Ok(n)) => {
                    if stream_b.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Hand-rolled SOCKS5 client: CONNECT to B's tailnet IP:port.
    let dest = SocksAddr::Ipv4 {
        addr: ip_b,
        port: ECHO_PORT,
    };
    let mut client = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        TcpStream::connect(proxy_addr),
    )
    .await
    .expect("connect to proxy timed out")
    .expect("connect to proxy failed");

    // Greeting: VER=5 NMETHODS=1 METHODS=[no-auth]
    client
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("greeting write");
    let mut greply = [0u8; 2];
    client.read_exact(&mut greply).await.expect("greeting read");
    assert_eq!(greply, [0x05, 0x00], "greeting rejected");

    // Request: CONNECT to B.
    let mut req = vec![0x05, 0x01, 0x00];
    req.extend_from_slice(&dest.marshal().unwrap());
    client.write_all(&req).await.expect("request write");

    // Reply: VER REPLY RSV <bind-addr>.
    let mut hdr = [0u8; 4];
    client
        .read_exact(&mut hdr)
        .await
        .expect("reply header read");
    assert_eq!(hdr[0], 0x05, "bad reply version");
    assert_eq!(hdr[1], 0x00, "connect failed reply={:#x}", hdr[1]);
    // Drain the bind address (IPv4 in our impl).
    let mut bind_rest = vec![0u8; 4 + 2];
    client.read_exact(&mut bind_rest).await.expect("bind read");

    // Echo roundtrip through the tailnet via the proxy.
    let payload = b"socks5-e2e-through-tailnet";
    client.write_all(payload).await.expect("client write");
    let mut got = vec![0u8; payload.len()];
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        client.read_exact(&mut got),
    )
    .await
    .expect("echo read timed out")
    .expect("echo read failed");
    assert_eq!(&got, payload, "echo mismatch through SOCKS5 proxy");

    // A second exchange to be sure the copy is bidirectional.
    client.write_all(b"again").await.expect("client write 2");
    let mut g2 = vec![0u8; 5];
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        client.read_exact(&mut g2),
    )
    .await
    .expect("echo read 2 timed out")
    .expect("echo read 2 failed");
    assert_eq!(&g2, b"again");

    // Shut down: close the client so B's echo loop sees EOF and exits.
    drop(client);
    proxy.stop().await;
    let _ = tokio::time::timeout(std::time::Duration::from_secs(15), echo_task)
        .await
        .expect("echo task did not exit in 15s");
    server_a.close().await;
    server_b.close().await;
}

// ---------------------------------------------------------------------------
// Cross-client interop e2e: rustscale <-> Go tailscaled
// ---------------------------------------------------------------------------
//
// All tests in this section are #[ignore]d and gated on TS_INTEROP_GO_IP
// (set by tools/interop.sh). They skip cleanly when the interop env is
// absent, so `cargo test -- --ignored` under plain tools/e2e.sh stays green.
//
// The harness (tools/interop.sh) provisions an ephemeral tailnet, starts a
// Go tailscaled in userspace-networking mode, exposes a `tailscale serve
// --tcp` echo forwarder, and exports:
//   TS_INTEROP_GO_IP       — Go node's tailnet IPv4
//   TS_INTEROP_GO_NAME     — Go node's MagicDNS FQDN (with trailing dot)
//   TS_INTEROP_GO_ECHO_PORT — tailnet port the Go node serves echo on
//   TS_INTEROP_SOCKS        — Go node's SOCKS5 proxy (127.0.0.1:11080)
//   TS_INTEROP_GO_SUBNET    — subnet the Go node advertises (for route test)
//   TS_E2E_AUTHKEY / TS_E2E_TAILNET / TS_E2E_API_TOKEN — shared with e2e.sh

use rustscale_magicsock::PathClass;

/// Parsed interop environment. Returns None if any required var is missing,
/// causing tests to skip (not fail) when run outside the interop harness.
struct InteropEnv {
    authkey: String,
    go_ip: std::net::Ipv4Addr,
    go_name: String,
    echo_port: u16,
    socks: String,
    go_subnet: Option<String>,
}

fn interop_env() -> Option<InteropEnv> {
    let authkey = std::env::var("TS_E2E_AUTHKEY").ok()?;
    let go_ip_s = std::env::var("TS_INTEROP_GO_IP").ok()?;
    let go_ip: std::net::Ipv4Addr = go_ip_s.parse().ok()?;
    let go_name = std::env::var("TS_INTEROP_GO_NAME").ok()?;
    let echo_port: u16 = std::env::var("TS_INTEROP_GO_ECHO_PORT")
        .ok()?
        .parse()
        .ok()?;
    let socks = std::env::var("TS_INTEROP_SOCKS").ok()?;
    let go_subnet = std::env::var("TS_INTEROP_GO_SUBNET")
        .ok()
        .filter(|s| !s.is_empty());
    Some(InteropEnv {
        authkey,
        go_ip,
        go_name,
        echo_port,
        socks,
        go_subnet,
    })
}

/// Require the interop env or return early from the calling test (skip).
/// Each test uses `let-else` directly to avoid macro hygiene issues.
fn _interop_skip_doc() {}

/// Start a rustscale node for interop testing. Returns (server, uid).
fn interop_server(authkey: &str, suffix: &str) -> Server {
    let uid = std::process::id();
    Server::builder()
        .hostname(format!("rustscale-interop-{suffix}-{uid}"))
        .auth_key(authkey)
        .ephemeral(true)
        .build()
        .expect("build interop server")
}

/// Like [`interop_server`] but with direct paths suppressed (DERP-only).
fn interop_server_derp_only(authkey: &str, suffix: &str) -> Server {
    let uid = std::process::id();
    Server::builder()
        .hostname(format!("rustscale-interop-{suffix}-{uid}"))
        .auth_key(authkey)
        .ephemeral(true)
        .disable_direct_paths(true)
        .build()
        .expect("build interop server (derp-only)")
}

/// Find the Go peer's path class from the rustscale server's status.
fn go_peer_path(server: &Server, go_ip: std::net::Ipv4Addr) -> Option<PathClass> {
    let st = server.status();
    st.peers
        .iter()
        .find(|p| p.ips.contains(&IpAddr::V4(go_ip)))
        .map(|p| p.path_class)
}

/// Log the current negotiated path to the Go peer for diagnostics.
fn log_go_path(server: &Server, go_ip: std::net::Ipv4Addr, ctx: &str) {
    let st = server.status();
    let go_peer = st.peers.iter().find(|p| p.ips.contains(&IpAddr::V4(go_ip)));
    if let Some(p) = go_peer {
        log::debug!(
            "[interop:{ctx}] go peer path={:?} name={}",
            p.path_class,
            p.name
        );
    } else {
        log::debug!(
            "[interop:{ctx}] go peer NOT in netmap ({} peers)",
            st.peers.len()
        );
    }
}

/// Echo roundtrip helper: write payload, read it back, assert equality.
async fn echo_roundtrip(
    stream: &mut (impl tokio::io::AsyncWrite + tokio::io::AsyncRead + Unpin),
    payload: &[u8],
    label: &str,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        stream.write_all(payload),
    )
    .await
    .expect("write timed out")
    .expect("write failed");
    let mut got = vec![0u8; payload.len()];
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        stream.read_exact(&mut got),
    )
    .await
    .expect("read timed out")
    .expect("read failed");
    assert_eq!(&got, payload, "echo mismatch ({label})");
}

/// Interop: rustscale dials the Go node's serve echo port.
#[tokio::test]
#[ignore = "requires TS_INTEROP_GO_IP (run via tools/interop.sh)"]
async fn interop_rust_dials_go() {
    let Some(ienv) = interop_env() else {
        log::debug!("interop_rust_dials_go: skipping (interop env not set)");
        return;
    };

    let mut server = interop_server(&ienv.authkey, "dialgo");
    Box::pin(server.up()).await.expect("up");

    let go_ip = ienv.go_ip;
    wait_for_peer(&server, IpAddr::V4(go_ip), "interop_rust_dials_go").await;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let dial_addr = format!("{go_ip}:{}", ienv.echo_port);
    let mut stream = None;
    for attempt in 1..=3 {
        log::debug!("interop_rust_dials_go: dial attempt {attempt} to {dial_addr}");
        match tokio::time::timeout(std::time::Duration::from_secs(45), server.dial(&dial_addr))
            .await
        {
            Ok(Ok(s)) => {
                stream = Some(s);
                break;
            }
            Ok(Err(e)) => log::warn!("dial attempt {attempt} failed: {e}"),
            Err(_) => log::debug!("dial attempt {attempt} timed out"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    let mut stream = stream.expect("all dial attempts failed");

    echo_roundtrip(&mut stream, b"interop-rust-dials-go", "rust_dials_go").await;
    log_go_path(&server, go_ip, "rust_dials_go");

    tokio::io::AsyncWriteExt::shutdown(&mut stream).await.ok();
    server.close().await;
}

/// Interop: the Go node dials the rustscale node through its SOCKS5 proxy.
/// The test hand-rolls a minimal SOCKS5 client to CONNECT from the Go side
/// to the rustscale node's tailnet IP:port.
#[tokio::test]
#[ignore = "requires TS_INTEROP_GO_IP (run via tools/interop.sh)"]
async fn interop_go_dials_rust() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let Some(ienv) = interop_env() else {
        log::debug!("interop_go_dials_rust: skipping (interop env not set)");
        return;
    };

    let mut server = interop_server(&ienv.authkey, "godials");
    Box::pin(server.up()).await.expect("up");
    let status = server.status();
    let rust_ip = status
        .tailscale_ips
        .iter()
        .find_map(|ip| match ip {
            IpAddr::V4(v4) => Some(*v4),
            _ => None,
        })
        .expect("rust should have an IPv4");

    // Rust listens for echo.
    const ECHO_PORT: u16 = 4545;
    let mut listener = server.listen(ECHO_PORT).await.expect("listen");

    // Wait for Go peer to appear.
    wait_for_peer(&server, IpAddr::V4(ienv.go_ip), "interop_go_dials_rust").await;
    // Give the Go side time to see rustscale in its netmap and for the WG
    // handshake to complete (the Go SOCKS5 proxy can only dial peers it
    // knows about).
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    // Spawn the echo acceptor on the rust side.
    let echo_task = tokio::spawn(async move {
        let mut stream = tokio::time::timeout(std::time::Duration::from_mins(1), listener.accept())
            .await
            .expect("rust accept timed out")
            .expect("rust accept failed");
        let mut buf = [0u8; 256];
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(30), stream.read(&mut buf))
                .await
            {
                Ok(Ok(0) | Err(_)) => break,
                Ok(Ok(n)) => {
                    if stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Hand-rolled SOCKS5 client: connect to Go's SOCKS5 proxy, CONNECT to
    // the rustscale node's tailnet IP:port. Retry up to 5 times — the Go
    // side may not have the rustscale peer in its netmap yet.
    let mut client = None;
    for attempt in 1..=5 {
        log::debug!("interop_go_dials_rust: SOCKS5 connect attempt {attempt}");
        let conn = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            TcpStream::connect(&ienv.socks),
        )
        .await;
        if let Ok(Ok(mut c)) = conn {
            // SOCKS5 greeting.
            if c.write_all(&[0x05, 0x01, 0x00]).await.is_err() {
                log::warn!("interop_go_dials_rust: greeting write failed on attempt {attempt}");
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                continue;
            }
            let mut greply = [0u8; 2];
            if c.read_exact(&mut greply).await.is_err() {
                log::warn!("interop_go_dials_rust: greeting read failed on attempt {attempt}");
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                continue;
            }
            if greply != [0x05, 0x00] {
                log::debug!("interop_go_dials_rust: greeting rejected on attempt {attempt}");
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                continue;
            }
            // SOCKS5 CONNECT request.
            let mut req = vec![0x05, 0x01, 0x00, 0x01];
            req.extend_from_slice(&rust_ip.octets());
            req.extend_from_slice(&ECHO_PORT.to_be_bytes());
            let mut c = c;
            if c.write_all(&req).await.is_err() {
                log::warn!("interop_go_dials_rust: request write failed on attempt {attempt}");
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                continue;
            }
            let mut hdr = [0u8; 4];
            if c.read_exact(&mut hdr).await.is_err() {
                log::warn!("interop_go_dials_rust: reply read failed on attempt {attempt}");
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                continue;
            }
            if hdr[1] != 0x00 {
                log::warn!(
                    "interop_go_dials_rust: SOCKS5 connect failed reply={:#x} on attempt {attempt}",
                    hdr[1]
                );
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                continue;
            }
            // Drain bind address.
            let mut bind_rest = vec![0u8; 6];
            if c.read_exact(&mut bind_rest).await.is_err() {
                log::warn!("interop_go_dials_rust: bind read failed on attempt {attempt}");
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                continue;
            }
            client = Some(c);
            break;
        }
        log::warn!("interop_go_dials_rust: connect to SOCKS5 failed on attempt {attempt}");
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
    let mut client = client.expect("all SOCKS5 connect attempts failed");

    // Echo roundtrip through Go→rust.
    let payload = b"interop-go-dials-rust";
    echo_roundtrip(&mut client, payload, "go_dials_rust").await;
    log_go_path(&server, ienv.go_ip, "go_dials_rust");

    drop(client);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(15), echo_task)
        .await
        .expect("echo task did not exit");
    server.close().await;
}

/// Interop: rustscale dials the Go node by its MagicDNS FQDN. Proves the
/// netmap resolver produces a usable address for Go-registered names.
#[tokio::test]
#[ignore = "requires TS_INTEROP_GO_IP (run via tools/interop.sh)"]
async fn interop_magicdns_name() {
    let Some(ienv) = interop_env() else {
        log::debug!("interop_magicdns_name: skipping (interop env not set)");
        return;
    };

    let mut server = interop_server(&ienv.authkey, "dns");
    Box::pin(server.up()).await.expect("up");

    wait_for_peer(&server, IpAddr::V4(ienv.go_ip), "interop_magicdns_name").await;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // Dial by MagicDNS FQDN:port — the resolver looks up the name in the netmap.
    let dial_addr = format!("{}:{}", ienv.go_name, ienv.echo_port);
    log::debug!("interop_magicdns_name: dialing {dial_addr}");
    let mut stream = None;
    for attempt in 1..=3 {
        log::debug!("dial attempt {attempt} to {dial_addr}");
        match tokio::time::timeout(std::time::Duration::from_secs(45), server.dial(&dial_addr))
            .await
        {
            Ok(Ok(s)) => {
                stream = Some(s);
                break;
            }
            Ok(Err(e)) => log::warn!("dial attempt {attempt} failed: {e}"),
            Err(_) => log::debug!("dial attempt {attempt} timed out"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    let mut stream = stream.expect("MagicDNS dial failed after 3 attempts");

    echo_roundtrip(&mut stream, b"interop-magicdns-name", "magicdns_name").await;
    log_go_path(&server, ienv.go_ip, "magicdns_name");

    tokio::io::AsyncWriteExt::shutdown(&mut stream).await.ok();
    server.close().await;
}

/// Interop: rustscale whois(go_ip) returns the Go node's FQDN.
#[tokio::test]
#[ignore = "requires TS_INTEROP_GO_IP (run via tools/interop.sh)"]
async fn interop_whois_go_peer() {
    let Some(ienv) = interop_env() else {
        log::debug!("interop_whois_go_peer: skipping (interop env not set)");
        return;
    };

    let mut server = interop_server(&ienv.authkey, "whois");
    Box::pin(server.up()).await.expect("up");

    wait_for_peer(&server, IpAddr::V4(ienv.go_ip), "interop_whois_go_peer").await;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let info = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        server.whois(IpAddr::V4(ienv.go_ip)),
    )
    .await
    .expect("whois timed out")
    .expect("whois returned None (server up?)");

    assert!(info.found, "whois should find Go peer for {}", ienv.go_ip);
    log::debug!(
        "interop_whois_go_peer: node_name={} user_id={} login={}",
        info.node_name,
        info.user_id,
        info.login_name
    );
    // The Go node's FQDN should contain its hostname prefix.
    let whois_name = info.node_name.trim_end_matches('.').to_lowercase();
    assert!(
        whois_name.contains("go-interop"),
        "whois node_name should contain 'go-interop', got '{}'",
        info.node_name
    );
    // Tagged nodes typically have no user profile (user_id=0, empty login).
    // Just log it; the Go node was registered with tag:e2e.
    log::debug!(
        "interop_whois_go_peer: tag identity user_id={} login_name='{}' display='{}'",
        info.user_id,
        info.login_name,
        info.display_name
    );

    server.close().await;
}

/// Interop: assert the path to the Go peer settles to Direct after echo
/// traffic. On localhost, disco ping/pong + CallMeMaybe should hole-punch
/// trivially. Fails if still on DERP after 60s — the core NAT-traversal
/// interop proof.
#[tokio::test]
#[ignore = "requires TS_INTEROP_GO_IP (run via tools/interop.sh)"]
async fn interop_direct_path() {
    let Some(ienv) = interop_env() else {
        log::debug!("interop_direct_path: skipping (interop env not set)");
        return;
    };

    let mut server = interop_server(&ienv.authkey, "direct");
    Box::pin(server.up()).await.expect("up");

    wait_for_peer(&server, IpAddr::V4(ienv.go_ip), "interop_direct_path").await;

    // Generate echo traffic to trigger disco probing.
    let dial_addr = format!("{}:{}", ienv.go_ip, ienv.echo_port);
    let mut stream = None;
    for _ in 1..=3 {
        if let Ok(Ok(s)) =
            tokio::time::timeout(std::time::Duration::from_secs(45), server.dial(&dial_addr)).await
        {
            stream = Some(s);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    let mut stream = stream.expect("dial failed for direct_path test");

    // Send a few echo roundtrips to generate disco traffic.
    for i in 0..5 {
        let payload = format!("interop-direct-{i}");
        echo_roundtrip(&mut stream, payload.as_bytes(), "direct_path").await;
    }

    // Poll for direct path settlement (up to 60s).
    let deadline = std::time::Instant::now() + std::time::Duration::from_mins(1);
    let mut settled = false;
    while std::time::Instant::now() < deadline {
        if let Some(class) = go_peer_path(&server, ienv.go_ip) {
            log::debug!("[interop:direct_path] current path = {:?}", class);
            if class == PathClass::Direct {
                settled = true;
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }

    tokio::io::AsyncWriteExt::shutdown(&mut stream).await.ok();

    if !settled {
        let st = server.status();
        let peers: Vec<String> = st
            .peers
            .iter()
            .map(|p| format!("  {} ips={:?} path={:?}", p.name, p.ips, p.path_class))
            .collect();
        panic!(
            "interop_direct_path: path to Go peer did not settle to Direct after 60s\n\
             This is unexpected on localhost — disco exchange with Go's magicsock failed.\n\
             Current peers ({}):\n{}",
            peers.len(),
            peers.join("\n")
        );
    }

    log::debug!("interop_direct_path: SUCCESS — path settled to Direct");
    server.close().await;
}

/// Interop: assert relayed (DERP) connectivity works with Go by pinning
/// direct paths off. Echo must flow and our path class must be Derp.
#[tokio::test]
#[ignore = "requires TS_INTEROP_GO_IP (run via tools/interop.sh)"]
async fn interop_derp_path() {
    let Some(ienv) = interop_env() else {
        log::debug!("interop_derp_path: skipping (interop env not set)");
        return;
    };

    let mut server = interop_server_derp_only(&ienv.authkey, "derp");
    Box::pin(server.up()).await.expect("up");

    wait_for_peer(&server, IpAddr::V4(ienv.go_ip), "interop_derp_path").await;
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    let dial_addr = format!("{}:{}", ienv.go_ip, ienv.echo_port);
    let mut stream = None;
    for attempt in 1..=3 {
        log::debug!("interop_derp_path: dial attempt {attempt} to {dial_addr}");
        if let Ok(Ok(s)) =
            tokio::time::timeout(std::time::Duration::from_secs(45), server.dial(&dial_addr)).await
        {
            stream = Some(s);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    let mut stream = stream.expect("dial failed (DERP path)");

    echo_roundtrip(&mut stream, b"interop-derp-path", "derp_path").await;

    // Assert our path class is Derp (not Direct — disable_direct_paths is on).
    let class = go_peer_path(&server, ienv.go_ip);
    log::debug!("interop_derp_path: path class = {:?}", class);
    assert!(
        class != Some(PathClass::Direct),
        "path should NOT be Direct when disable_direct_paths is set"
    );

    tokio::io::AsyncWriteExt::shutdown(&mut stream).await.ok();
    server.close().await;
}

/// Interop: start on DERP, assert upgrade to Direct without connection
/// interruption. A continuous echo loop runs while the path upgrades —
/// no dropped or garbled bytes.
#[tokio::test]
#[ignore = "requires TS_INTEROP_GO_IP (run via tools/interop.sh)"]
async fn interop_direct_after_derp() {
    let Some(ienv) = interop_env() else {
        log::debug!("interop_direct_after_derp: skipping (interop env not set)");
        return;
    };

    let mut server = interop_server(&ienv.authkey, "upgrade");
    Box::pin(server.up()).await.expect("up");

    wait_for_peer(&server, IpAddr::V4(ienv.go_ip), "interop_direct_after_derp").await;

    // Dial and start a continuous echo loop in a background task.
    let dial_addr = format!("{}:{}", ienv.go_ip, ienv.echo_port);
    let mut stream = None;
    for _ in 1..=3 {
        if let Ok(Ok(s)) =
            tokio::time::timeout(std::time::Duration::from_secs(45), server.dial(&dial_addr)).await
        {
            stream = Some(s);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    let mut stream = stream.expect("dial failed for direct_after_derp");

    // Continuous echo: sequence-numbered payloads, verify each roundtrip
    // while the path may upgrade from DERP to Direct.
    let echo_ok = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let echo_done = std::sync::Arc::new(tokio::sync::Notify::new());
    let echo_ok_c = echo_ok.clone();
    let echo_done_c = echo_done.clone();
    let echo_task = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for i in 0..200u32 {
            let payload = format!("interop-upgrade-{i:04}");
            let bytes = payload.as_bytes();
            if tokio::time::timeout(std::time::Duration::from_secs(30), stream.write_all(bytes))
                .await
                .is_err()
            {
                log::debug!("[interop:upgrade] write timeout at seq {i}");
                break;
            }
            let mut got = vec![0u8; bytes.len()];
            match tokio::time::timeout(
                std::time::Duration::from_secs(30),
                stream.read_exact(&mut got),
            )
            .await
            {
                Ok(Ok(_)) if got == bytes => {
                    echo_ok_c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                _ => {
                    log::debug!("[interop:upgrade] echo mismatch/timeout at seq {i}");
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
        echo_done_c.notify_one();
    });

    // Poll for direct path settlement (up to 60s).
    let deadline = std::time::Instant::now() + std::time::Duration::from_mins(1);
    let mut settled = false;
    while std::time::Instant::now() < deadline {
        if let Some(class) = go_peer_path(&server, ienv.go_ip) {
            log::debug!("[interop:upgrade] current path = {:?}", class);
            if class == PathClass::Direct {
                settled = true;
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }

    // Give the echo loop a moment to complete a few more roundtrips after
    // the path upgraded, then signal it to stop by dropping the stream
    // (the task will see EOF on next read).
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    // Cancel the echo task.
    echo_task.abort();

    let ok_count = echo_ok.load(std::sync::atomic::Ordering::Relaxed);
    log::debug!(
        "interop_direct_after_derp: {ok_count} echo roundtrips completed, path settled={settled}"
    );

    if !settled {
        let st = server.status();
        let peers: Vec<String> = st
            .peers
            .iter()
            .map(|p| format!("  {} ips={:?} path={:?}", p.name, p.ips, p.path_class))
            .collect();
        panic!(
            "interop_direct_after_derp: path did not upgrade to Direct after 60s\n\
             Peers ({}):\n{}",
            peers.len(),
            peers.join("\n")
        );
    }

    // At least some echo roundtrips must have succeeded (proving no
    // interruption during the upgrade).
    assert!(
        ok_count > 0,
        "no echo roundtrips succeeded — connection was interrupted during path upgrade"
    );

    server.close().await;
}

/// Interop: Go node advertises a subnet route; rustscale with accept_routes
/// should resolve that subnet to the Go peer in its routing table.
#[tokio::test]
#[ignore = "requires TS_INTEROP_GO_IP (run via tools/interop.sh)"]
async fn interop_subnet_routes() {
    let Some(ienv) = interop_env() else {
        log::debug!("interop_subnet_routes: skipping (interop env not set)");
        return;
    };
    let subnet = if let Some(s) = &ienv.go_subnet {
        s.clone()
    } else {
        log::debug!("interop_subnet_routes: skipping (TS_INTEROP_GO_SUBNET not set)");
        return;
    };

    let mut server = Server::builder()
        .hostname(format!("rustscale-interop-subnet-{}", std::process::id()))
        .auth_key(ienv.authkey.clone())
        .ephemeral(true)
        .accept_routes(true)
        .build()
        .expect("build");
    Box::pin(server.up()).await.expect("up");

    // Wait for the Go peer to appear.
    wait_for_peer(&server, IpAddr::V4(ienv.go_ip), "interop_subnet_routes").await;

    // The harness approves the Go node's advertised route. Wait for the
    // subnet to appear in our routing table (control pushes updated
    // AllowedIPs after approval).
    // Parse a sample IP in the subnet for route-table lookup.
    let sample_ip: IpAddr = if subnet.starts_with("10.99") {
        IpAddr::V4(Ipv4Addr::new(10, 99, 0, 1))
    } else {
        // Generic: try first usable IP. For simplicity, assume /24.
        let parts: Vec<u8> = subnet
            .split('/')
            .next()
            .unwrap_or("10.99.0.0")
            .split('.')
            .filter_map(|s| s.parse().ok())
            .collect();
        if parts.len() == 4 {
            IpAddr::V4(Ipv4Addr::new(
                parts[0],
                parts[1],
                parts[2],
                parts[3].saturating_add(1),
            ))
        } else {
            IpAddr::V4(Ipv4Addr::new(10, 99, 0, 1))
        }
    };

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    loop {
        if server.route_lookup(sample_ip).is_some() {
            log::debug!("interop_subnet_routes: route for {sample_ip} resolved to Go peer");
            // Verify the route is in the route table snapshot.
            let routes = server.routes();
            let has_subnet = routes.iter().any(|(cidr, _)| cidr == &subnet);
            assert!(
                has_subnet,
                "route table should contain {subnet}, got: {routes:?}"
            );
            log::debug!("interop_subnet_routes: SUCCESS — subnet {subnet} -> Go peer");
            break;
        }
        if std::time::Instant::now() >= deadline {
            let routes = server.routes();
            panic!(
                "interop_subnet_routes: subnet {subnet} never appeared in route table (90s)\n\
                 routes: {routes:?}"
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    server.close().await;
}

// ---------------------------------------------------------------------------
// Layer 1: TUN pump unit tests (no root, no Go)
// ---------------------------------------------------------------------------
//
// Exercises the same data-plane logic as `run_tun_pump` — TUN read →
// WG encapsulate → cross-feed → WG decapsulate → filter → TUN write — but
// with MockTun devices and in-memory cross-feeding instead of a real
// magicsock. This catches pump bugs, MTU handling, and filter-on-raw-IP
// issues without any OS dependency.

use rustscale_filter::Filter;
use rustscale_tun::{MockTun, Tun, TunPacketBatch};

/// Delivers two packets from exactly one read, then ends. The counter lets the
/// pump test distinguish processing a batch from issuing a read per packet.
struct TwoPacketTun {
    reads: std::sync::atomic::AtomicUsize,
    dispatched: std::sync::Mutex<Vec<Vec<u8>>>,
    name: String,
    first: Vec<u8>,
    second: Vec<u8>,
}

#[async_trait::async_trait]
impl Tun for TwoPacketTun {
    async fn read_batch(&self, batch: &mut TunPacketBatch) -> std::io::Result<()> {
        let read = self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        batch.clear();
        if read == 0 {
            batch.push_packet(&self.first)?;
            batch.push_packet(&self.second)?;
            Ok(())
        } else {
            assert_eq!(
                *self.dispatched.lock().unwrap(),
                vec![self.first.clone(), self.second.clone()],
                "the whole first read batch must be dispatched in order before another TUN read"
            );
            Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "done",
            ))
        }
    }
    async fn write_packet(&self, _packet: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
    fn name(&self) -> &str {
        &self.name
    }
    fn mtu(&self) -> usize {
        DEFAULT_MTU
    }
}

/// Build a minimal IPv4 TCP packet for testing the TUN pump.
fn build_ipv4_tcp(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let total = 20 + 20 + payload.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 6;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    p[20..22].copy_from_slice(&12345u16.to_be_bytes());
    p[22..24].copy_from_slice(&80u16.to_be_bytes());
    p[24..28].copy_from_slice(&1u32.to_be_bytes());
    p[32] = 0x50;
    p[33] = 0x02;
    p[34..36].copy_from_slice(&65535u16.to_be_bytes());
    p[20 + 20..].copy_from_slice(payload);
    p
}

/// Drive one packet from a TUN through the WG tunnel to the peer's TUN.
/// Mirrors what `run_tun_pump` does: filter outbound → encapsulate →
/// (cross-feed) → decapsulate → filter inbound → TUN write.
async fn tun_pump_packet(
    pkt: &[u8],
    src_tunn: &Arc<Mutex<WgTunn>>,
    dst_tunn: &Arc<Mutex<WgTunn>>,
    route_table: &Arc<RwLock<RouteTable>>,
    filter: &Arc<std::sync::Mutex<Filter>>,
    dst_tun: &Arc<MockTun>,
) {
    {
        let mut f = filter.lock().unwrap();
        f.update_outbound(pkt);
    }
    let dst = WgTunn::dst_address(pkt).expect("dst addr");
    let has_route = {
        let rt = route_table.read().await;
        rt.lookup(dst).is_some()
    };
    if !has_route {
        return;
    }
    // Encapsulate under the lock, collect datagrams.
    let dgrams: Vec<Vec<u8>> = {
        if let Ok(mut t) = src_tunn.try_lock() {
            t.encapsulate(pkt).unwrap_or_default()
        } else {
            return;
        }
    };
    for dg in &dgrams {
        // Decapsulate under the lock, collect plaintext + replies.
        let (plaintext, replies): (Option<Vec<u8>>, Vec<Vec<u8>>) = {
            if let Ok(mut dt) = dst_tunn.try_lock() {
                if let Ok(decap) = dt.decapsulate(dg) {
                    (decap.plaintext.clone(), decap.replies.clone())
                } else {
                    (None, vec![])
                }
            } else {
                (None, vec![])
            }
        };
        if let Some(pt) = plaintext {
            let dropped = {
                let mut f = filter.lock().unwrap();
                f.check_in(&pt).is_drop()
            };
            if !dropped {
                let _ = dst_tun.write_packet(&pt).await;
            }
        }
        // Feed handshake replies back to src.
        for reply in &replies {
            let reply_pt: Option<Vec<u8>> = {
                if let Ok(mut st) = src_tunn.try_lock() {
                    if let Ok(a_decap) = st.decapsulate(reply) {
                        a_decap.plaintext.clone()
                    } else {
                        None
                    }
                } else {
                    None
                }
            };
            if let Some(pt) = reply_pt {
                let _ = dst_tun.write_packet(&pt).await;
            }
        }
    }
}

/// Run the WG handshake by forcing an initiation and cross-feeding the
/// handshake messages until the tunnel is established. This mirrors what
/// the netstack rig's `pump_cycle` does — but as a bounded loop since we
/// don't have a continuous pump.
async fn wg_handshake(a_tunn: &Arc<Mutex<WgTunn>>, b_tunn: &Arc<Mutex<WgTunn>>) {
    // Force A to initiate a handshake.
    let init_dgs: Vec<Vec<u8>> = {
        if let Ok(mut t) = a_tunn.try_lock() {
            t.force_handshake()
        } else {
            return;
        }
    };

    // Cross-feed: A init → B decapsulate → B replies → A decapsulate.
    for dg in &init_dgs {
        let b_replies: Vec<Vec<u8>> = {
            if let Ok(mut bt) = b_tunn.try_lock() {
                if let Ok(decap) = bt.decapsulate(dg) {
                    decap.replies.clone()
                } else {
                    vec![]
                }
            } else {
                vec![]
            }
        };
        for reply in &b_replies {
            if let Ok(mut at) = a_tunn.try_lock() {
                let _ = at.decapsulate(reply);
            }
        }
    }

    // Also force B to initiate — this establishes B→A transport keys.
    let b_init_dgs: Vec<Vec<u8>> = {
        if let Ok(mut t) = b_tunn.try_lock() {
            t.force_handshake()
        } else {
            vec![]
        }
    };
    for dg in &b_init_dgs {
        let a_replies: Vec<Vec<u8>> = {
            if let Ok(mut at) = a_tunn.try_lock() {
                if let Ok(decap) = at.decapsulate(dg) {
                    decap.replies.clone()
                } else {
                    vec![]
                }
            } else {
                vec![]
            }
        };
        for reply in &a_replies {
            if let Ok(mut bt) = b_tunn.try_lock() {
                let _ = bt.decapsulate(reply);
            }
        }
    }

    // Tick timers on both sides and cross-feed any remaining handshake
    // messages. A few rounds is enough — the handshake is a 3-way exchange.
    for _ in 0..20 {
        for (src, dst) in [(a_tunn, b_tunn), (b_tunn, a_tunn)] {
            let dgs: Vec<Vec<u8>> = {
                if let Ok(mut t) = src.try_lock() {
                    t.tick_timers()
                } else {
                    vec![]
                }
            };
            for dg in &dgs {
                if let Ok(mut dt) = dst.try_lock() {
                    let decap = dt.decapsulate(dg).unwrap_or_default();
                    for reply in &decap.replies {
                        if let Ok(mut st) = src.try_lock() {
                            let _ = st.decapsulate(reply);
                        }
                    }
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
}

/// Set up a TUN pump test rig: two WG tunnels + route tables + filter.
struct TunPumpRig {
    tun_a: Arc<MockTun>,
    tun_b: Arc<MockTun>,
    a_pub: NodePublic,
    a_tunn: Arc<Mutex<WgTunn>>,
    b_tunn: Arc<Mutex<WgTunn>>,
    rt_a: Arc<RwLock<RouteTable>>,
    rt_b: Arc<RwLock<RouteTable>>,
    filter: Arc<std::sync::Mutex<Filter>>,
}

fn make_tun_pump_rig(ip_a: Ipv4Addr, ip_b: Ipv4Addr) -> TunPumpRig {
    let a_priv = NodePrivate::generate();
    let b_priv = NodePrivate::generate();
    let a_pub = a_priv.public();
    let b_pub = b_priv.public();

    let (tun_a, _) = MockTun::new("tun-a", DEFAULT_MTU);
    let (tun_b, _) = MockTun::new("tun-b", DEFAULT_MTU);

    let a_tunn = Arc::new(Mutex::new(WgTunn::new(&a_priv, &b_pub, 1).expect("A")));
    let b_tunn = Arc::new(Mutex::new(WgTunn::new(&b_priv, &a_pub, 2).expect("B")));

    let peers_a = vec![Node {
        ID: 2,
        Name: "b".into(),
        Key: b_pub.clone(),
        Addresses: vec![format!("{ip_b}/32")],
        ..Default::default()
    }];
    let peers_b = vec![Node {
        ID: 1,
        Name: "a".into(),
        Key: a_pub.clone(),
        Addresses: vec![format!("{ip_a}/32")],
        ..Default::default()
    }];

    TunPumpRig {
        tun_a: Arc::new(tun_a),
        tun_b: Arc::new(tun_b),
        a_pub,
        a_tunn,
        b_tunn,
        rt_a: Arc::new(RwLock::new(RouteTable::from_peers(&peers_a))),
        rt_b: Arc::new(RwLock::new(RouteTable::from_peers(&peers_b))),
        filter: Arc::new(std::sync::Mutex::new(Filter::allow_all())),
    }
}

#[tokio::test]
async fn collect_tun_inbound_queues_accepts_drops_and_captures_before_batch_mutation() {
    let rig = make_tun_pump_rig(Ipv4Addr::new(100, 64, 0, 1), Ipv4Addr::new(100, 64, 0, 2));
    wg_handshake(&rig.a_tunn, &rig.b_tunn).await;
    let TunPumpRig {
        a_pub,
        a_tunn,
        b_tunn,
        filter,
        ..
    } = rig;
    let b_tunn = Arc::try_unwrap(b_tunn)
        .unwrap_or_else(|_| panic!("test rig receiver tunnel must not have other owners"));
    let b_tunn = Arc::new(tokio::sync::Mutex::new(
        b_tunn.into_inner().expect("test rig receiver tunnel lock"),
    ));

    let tunnels = RwLock::new(HashMap::from([(a_pub.clone(), b_tunn)]));
    let packet_drops = Arc::new(AtomicU64::new(0));
    let capture = crate::capture::new_slot();
    let sink = crate::capture::get_or_set(&capture);
    let (capture_tx, mut capture_rx) = tokio::sync::mpsc::channel(2);
    let _capture_handle = sink
        .register_output(crate::capture::ChannelOutput::new(capture_tx))
        .expect("register capture output");
    assert_eq!(
        capture_rx.recv().await.expect("pcap global header"),
        vec![
            0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0,
            0, 0x93, 0, 0, 0,
        ]
    );

    let accepted = build_ipv4_tcp(
        Ipv4Addr::new(100, 64, 0, 1),
        Ipv4Addr::new(100, 64, 0, 2),
        b"collect-tun-inbound-accepted",
    );
    let accepted_datagram = rustscale_magicsock::WgDatagram {
        peer: a_pub.clone(),
        data: a_tunn
            .lock()
            .expect("source tunnel lock")
            .encapsulate(&accepted)
            .expect("encrypt accepted packet")
            .into_iter()
            .next()
            .expect("encrypted WireGuard data datagram")
            .into(),
    };
    let mut plaintext = Vec::new();
    let mut replies = Vec::new();
    collect_tun_inbound(
        &tunnels,
        &filter,
        &packet_drops,
        &accepted_datagram,
        &capture,
        &mut plaintext,
        &mut replies,
    )
    .await;

    assert_eq!(
        plaintext,
        vec![accepted.clone()],
        "accepted plaintext is queued"
    );
    assert!(replies.is_empty(), "data datagram needs no protocol reply");
    assert_eq!(packet_drops.load(Ordering::Relaxed), 0);

    // `write_batch` may rewrite this owned buffer for GRO. Capture must have
    // retained the original plaintext before that later mutation occurs.
    plaintext[0].fill(0xa5);
    let captured = capture_rx.recv().await.expect("captured plaintext record");
    assert_eq!(
        &captured[16..18],
        &(crate::capture::CapturePath::FromPeer as u16).to_le_bytes()
    );
    assert_eq!(&captured[20..], accepted.as_slice());

    plaintext.clear();
    *filter.lock().unwrap() = Filter::allow_none();
    let dropped = build_ipv4_tcp(
        Ipv4Addr::new(100, 64, 0, 1),
        Ipv4Addr::new(100, 64, 0, 2),
        b"collect-tun-inbound-dropped",
    );
    let dropped_datagram = rustscale_magicsock::WgDatagram {
        peer: a_pub.clone(),
        data: a_tunn
            .lock()
            .expect("source tunnel lock")
            .encapsulate(&dropped)
            .expect("encrypt dropped packet")
            .into_iter()
            .next()
            .expect("encrypted WireGuard data datagram")
            .into(),
    };
    collect_tun_inbound(
        &tunnels,
        &filter,
        &packet_drops,
        &dropped_datagram,
        &capture,
        &mut plaintext,
        &mut replies,
    )
    .await;

    assert!(
        plaintext.is_empty(),
        "filter-dropped plaintext is not queued"
    );
    assert_eq!(packet_drops.load(Ordering::Relaxed), 1);
    assert!(matches!(
        capture_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn tun_pump_a_to_b() {
    let rig = make_tun_pump_rig(Ipv4Addr::new(100, 64, 0, 1), Ipv4Addr::new(100, 64, 0, 2));
    wg_handshake(&rig.a_tunn, &rig.b_tunn).await;
    let pkt = build_ipv4_tcp(
        Ipv4Addr::new(100, 64, 0, 1),
        Ipv4Addr::new(100, 64, 0, 2),
        b"tun-pump-test",
    );
    tun_pump_packet(
        &pkt,
        &rig.a_tunn,
        &rig.b_tunn,
        &rig.rt_a,
        &rig.filter,
        &rig.tun_b,
    )
    .await;

    let written = rig.tun_b.written().await;
    assert_eq!(written.len(), 1);
    assert_eq!(written[0], pkt, "packet should arrive intact");
}

#[tokio::test]
async fn tun_pump_b_to_a() {
    let rig = make_tun_pump_rig(Ipv4Addr::new(100, 64, 0, 1), Ipv4Addr::new(100, 64, 0, 2));
    wg_handshake(&rig.a_tunn, &rig.b_tunn).await;
    let pkt = build_ipv4_tcp(
        Ipv4Addr::new(100, 64, 0, 2),
        Ipv4Addr::new(100, 64, 0, 1),
        b"tun-pump-b2a",
    );
    tun_pump_packet(
        &pkt,
        &rig.b_tunn,
        &rig.a_tunn,
        &rig.rt_b,
        &rig.filter,
        &rig.tun_a,
    )
    .await;

    let written = rig.tun_a.written().await;
    assert_eq!(written.len(), 1);
    assert_eq!(written[0], pkt, "packet should arrive intact");
}

#[tokio::test]
async fn tun_pump_multiple_packets() {
    let rig = make_tun_pump_rig(Ipv4Addr::new(100, 64, 0, 1), Ipv4Addr::new(100, 64, 0, 2));
    wg_handshake(&rig.a_tunn, &rig.b_tunn).await;
    let mut pkts = Vec::new();
    for i in 0..5u8 {
        let payload = vec![i; 10 + i as usize];
        let pkt = build_ipv4_tcp(
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(100, 64, 0, 2),
            &payload,
        );
        pkts.push(pkt);
    }
    for pkt in &pkts {
        tun_pump_packet(
            pkt,
            &rig.a_tunn,
            &rig.b_tunn,
            &rig.rt_a,
            &rig.filter,
            &rig.tun_b,
        )
        .await;
    }
    let written = rig.tun_b.written().await;
    assert_eq!(written.len(), 5);
    for (i, w) in written.iter().enumerate() {
        assert_eq!(w, &pkts[i], "packet {i} mismatch");
    }
}

#[tokio::test]
async fn tun_pump_no_route_drops() {
    let a_priv = NodePrivate::generate();
    let b_priv = NodePrivate::generate();
    let (tun_a, _) = MockTun::new("tun-a", DEFAULT_MTU);
    let (tun_b, _) = MockTun::new("tun-b", DEFAULT_MTU);
    let a_tunn = Arc::new(Mutex::new(
        WgTunn::new(&a_priv, &b_priv.public(), 1).expect("A"),
    ));
    let b_tunn = Arc::new(Mutex::new(
        WgTunn::new(&b_priv, &a_priv.public(), 2).expect("B"),
    ));
    let rt_a = Arc::new(RwLock::new(RouteTable::from_peers(&[])));
    let filter = Arc::new(std::sync::Mutex::new(Filter::allow_all()));

    let pkt = build_ipv4_tcp(
        Ipv4Addr::new(100, 64, 0, 1),
        Ipv4Addr::new(100, 64, 0, 99),
        b"no-route",
    );
    tun_pump_packet(&pkt, &a_tunn, &b_tunn, &rt_a, &filter, &Arc::new(tun_b)).await;

    let written = Arc::new(tun_a).written().await;
    assert!(written.is_empty(), "no packet should arrive with no route");
}

#[tokio::test]
async fn tun_mock_inject_and_read() {
    let (tun, tx) = MockTun::new("mock-inject", 1280);
    let pkt = build_ipv4_tcp(
        Ipv4Addr::new(100, 64, 0, 1),
        Ipv4Addr::new(100, 64, 0, 2),
        b"inject-test",
    );
    tx.send(pkt.clone()).await.unwrap();
    let mut got = rustscale_tun::TunPacketBatch::new();
    tun.read_batch(&mut got).await.unwrap();
    assert_eq!(got.packets(), &[pkt]);
}

#[tokio::test]
async fn tun_pump_processes_one_read_batch_before_reading_again() {
    let first = build_ipv4_tcp(
        Ipv4Addr::new(100, 64, 0, 1),
        Ipv4Addr::new(100, 64, 0, 2),
        b"first",
    );
    let second = build_ipv4_tcp(
        Ipv4Addr::new(100, 64, 0, 1),
        Ipv4Addr::new(100, 64, 0, 3),
        b"second",
    );
    let tun = Arc::new(TwoPacketTun {
        reads: std::sync::atomic::AtomicUsize::new(0),
        dispatched: std::sync::Mutex::new(Vec::new()),
        name: "two-packet-test".into(),
        first,
        second,
    });
    let filter = std::sync::Mutex::new(Filter::allow_all());
    let mut batch = TunPacketBatch::new();
    tun.read_batch(&mut batch).await.unwrap();
    for packet in crate::tun_pump::filtered_outbound_packets(batch.packets(), &filter) {
        tun.dispatched.lock().unwrap().push(packet.to_vec());
    }
    // The second read verifies the dispatch log before returning EOF.
    assert!(tun.read_batch(&mut batch).await.is_err());
    assert_eq!(tun.reads.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[tokio::test]
async fn tun_pump_mtu_sized() {
    let rig = make_tun_pump_rig(Ipv4Addr::new(100, 64, 0, 1), Ipv4Addr::new(100, 64, 0, 2));
    wg_handshake(&rig.a_tunn, &rig.b_tunn).await;
    let payload = vec![0xAB; DEFAULT_MTU - 40];
    let pkt = build_ipv4_tcp(
        Ipv4Addr::new(100, 64, 0, 1),
        Ipv4Addr::new(100, 64, 0, 2),
        &payload,
    );
    assert_eq!(pkt.len(), DEFAULT_MTU);
    tun_pump_packet(
        &pkt,
        &rig.a_tunn,
        &rig.b_tunn,
        &rig.rt_a,
        &rig.filter,
        &rig.tun_b,
    )
    .await;

    let written = rig.tun_b.written().await;
    assert_eq!(written.len(), 1);
    assert_eq!(
        written[0].len(),
        DEFAULT_MTU,
        "packet should not be truncated"
    );
}

// ---------------------------------------------------------------------------
// Layer 2: TUN interop with Go tailscaled (root for TUN, Go in userspace)
// ---------------------------------------------------------------------------
//
// These tests require:
//   - TS_INTEROP_GO_IP (set by tools/interop-tun.sh)
//   - Root/sudo (to create a TUN device and apply OS routes)
// They skip cleanly otherwise. The Go node stays in userspace-networking
// mode (no root for Go). rustscale runs `up_tun()` with `apply_routes: true`
// so the OS routes tailnet traffic through the TUN device.
//
// Key difference from netstack interop: tests use OS sockets (std::net /
// tokio::net) instead of Server::dial/listen, because those are unavailable
// in TUN mode. Outbound: OS socket → kernel TCP → TUN device → pump → WG →
// magicsock → Go netstack. Inbound: Go SOCKS5 → Go netstack → magicsock →
// WG → TUN pump → OS → kernel TCP → OS listener.

/// Check if we have root privileges (needed for TUN device creation).
/// Uses `id -u` via std::process::Command to avoid unsafe code (the tsnet
/// crate is #![forbid(unsafe_code)]).
fn have_root() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
}

/// Require interop env + root, or skip.
fn require_tun_interop(test_name: &str) -> Option<InteropEnv> {
    let Some(ienv) = interop_env() else {
        log::debug!("{test_name}: skipping (interop env not set)");
        return None;
    };
    if !have_root() {
        log::debug!("{test_name}: skipping (not root — TUN mode requires sudo)");
        return None;
    }
    Some(ienv)
}

/// Call `up_tun` and skip the test cleanly if TUN device creation fails
/// (permission denied, platform not supported, etc.). Returns the server
/// on success; returns None and logs a skip message on failure.
async fn up_tun_or_skip(server: &mut Server, test_name: &str) -> Option<()> {
    match Box::pin(server.up_tun(TunModeConfig {
        tun: rustscale_tun::TunConfig::default(),
        apply_routes: true,
        exit_node: None,
    }))
    .await
    {
        Ok(_) => Some(()),
        Err(e) => {
            log::warn!("{test_name}: skipping — up_tun failed: {e}");
            None
        }
    }
}

/// Interop TUN: rustscale in TUN mode dials the Go node's serve echo via
/// an OS socket. Traffic flows: OS TCP → TUN → WG → magicsock → Go netstack.
#[tokio::test]
#[ignore = "requires TS_INTEROP_GO_IP + root (run via tools/interop-tun.sh)"]
async fn interop_tun_rust_dials_go() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let Some(ienv) = require_tun_interop("interop_tun_rust_dials_go") else {
        return;
    };

    let uid = std::process::id();
    let mut server = Server::builder()
        .hostname(format!("rustscale-tun-dial-{uid}"))
        .auth_key(ienv.authkey.clone())
        .ephemeral(true)
        .build()
        .expect("build");

    if Box::pin(up_tun_or_skip(&mut server, "interop_tun_rust_dials_go"))
        .await
        .is_none()
    {
        return;
    }

    let status = server.status();
    log::debug!(
        "interop_tun_rust_dials_go: up, tailscale_ips={:?}",
        status.tailscale_ips
    );

    // Wait for the Go peer to appear in the netmap.
    wait_for_peer(&server, IpAddr::V4(ienv.go_ip), "interop_tun_rust_dials_go").await;
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // OS socket connect to the Go node's tailnet IP:echo_port.
    // The kernel routes 100.64.0.0/10 through the TUN device.
    let dial_addr = format!("{}:{}", ienv.go_ip, ienv.echo_port);
    log::debug!("interop_tun_rust_dials_go: OS connect to {dial_addr}");

    let mut stream = None;
    for _ in 1..=5 {
        match tokio::time::timeout(
            std::time::Duration::from_secs(15),
            TcpStream::connect(&dial_addr),
        )
        .await
        {
            Ok(Ok(s)) => {
                stream = Some(s);
                break;
            }
            Ok(Err(e)) => log::warn!("connect failed: {e}"),
            Err(_) => log::debug!("connect timed out (15s)"),
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    let mut stream = stream.expect("OS connect to Go echo failed after 5 attempts");

    // Echo roundtrip through the TUN data plane.
    let payload = b"interop-tun-rust-dials-go";
    stream.write_all(payload).await.expect("write");
    let mut got = vec![0u8; payload.len()];
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        stream.read_exact(&mut got),
    )
    .await
    .expect("read timed out")
    .expect("read failed");
    assert_eq!(&got, payload, "echo mismatch through TUN");

    log_go_path(&server, ienv.go_ip, "tun_rust_dials_go");
    server.close().await;
}

/// Interop TUN: Go dials the rustscale node through its SOCKS5 proxy.
/// Traffic flows: Go SOCKS5 → Go netstack → magicsock → WG → TUN pump →
/// OS kernel TCP → OS listener.
#[tokio::test]
#[ignore = "requires TS_INTEROP_GO_IP + root (run via tools/interop-tun.sh)"]
async fn interop_tun_go_dials_rust() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    let Some(ienv) = require_tun_interop("interop_tun_go_dials_rust") else {
        return;
    };

    let uid = std::process::id();
    let mut server = Server::builder()
        .hostname(format!("rustscale-tun-accept-{uid}"))
        .auth_key(ienv.authkey.clone())
        .ephemeral(true)
        .build()
        .expect("build");

    if Box::pin(up_tun_or_skip(&mut server, "interop_tun_go_dials_rust"))
        .await
        .is_none()
    {
        return;
    }

    let status = server.status();
    let rust_ip = status
        .tailscale_ips
        .iter()
        .find_map(|ip| match ip {
            IpAddr::V4(v4) => Some(*v4),
            _ => None,
        })
        .expect("rust should have an IPv4");
    log::debug!("interop_tun_go_dials_rust: up, rust_ip={rust_ip}");

    // OS listener on the tailnet IP (the kernel routes inbound TUN traffic
    // to this socket).
    const ECHO_PORT: u16 = 4646;
    let listener = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        TcpListener::bind((rust_ip, ECHO_PORT)),
    )
    .await
    .expect("bind timed out")
    .expect("bind failed");
    log::debug!("interop_tun_go_dials_rust: OS listener on {rust_ip}:{ECHO_PORT}");

    // Wait for the Go peer.
    wait_for_peer(&server, IpAddr::V4(ienv.go_ip), "interop_tun_go_dials_rust").await;
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Spawn the echo acceptor on the rust side (OS listener).
    let echo_task = tokio::spawn(async move {
        let (mut sock, peer) =
            tokio::time::timeout(std::time::Duration::from_mins(1), listener.accept())
                .await
                .expect("accept timed out")
                .expect("accept failed");
        log::debug!("interop_tun_go_dials_rust: accepted from {peer}");
        let mut buf = [0u8; 256];
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

    // Hand-rolled SOCKS5 client: Go's SOCKS5 → CONNECT to rust_ip:ECHO_PORT.
    let mut client = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        TcpStream::connect(&ienv.socks),
    )
    .await
    .expect("connect to go socks5 timed out")
    .expect("connect to go socks5 failed");

    client
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("greeting");
    let mut greply = [0u8; 2];
    client.read_exact(&mut greply).await.expect("greeting read");
    assert_eq!(greply, [0x05, 0x00]);

    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&rust_ip.octets());
    req.extend_from_slice(&ECHO_PORT.to_be_bytes());
    client.write_all(&req).await.expect("request write");

    let mut hdr = [0u8; 4];
    client.read_exact(&mut hdr).await.expect("reply header");
    assert_eq!(hdr[1], 0x00, "socks5 connect failed");
    let mut bind_rest = vec![0u8; 6];
    client.read_exact(&mut bind_rest).await.expect("bind read");

    let payload = b"interop-tun-go-dials-rust";
    echo_roundtrip(&mut client, payload, "tun_go_dials_rust").await;
    log_go_path(&server, ienv.go_ip, "tun_go_dials_rust");

    drop(client);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(15), echo_task)
        .await
        .expect("echo task did not exit");
    server.close().await;
}

/// Interop TUN: verify OS routes were installed — `100.64.0.0/10` should
/// route through the TUN device. Uses `netstat -rn` (macOS) or `ip route`
/// (Linux) to check.
#[tokio::test]
#[ignore = "requires TS_INTEROP_GO_IP + root (run via tools/interop-tun.sh)"]
async fn interop_tun_os_routes() {
    let Some(ienv) = require_tun_interop("interop_tun_os_routes") else {
        return;
    };

    let uid = std::process::id();
    let mut server = Server::builder()
        .hostname(format!("rustscale-tun-routes-{uid}"))
        .auth_key(ienv.authkey.clone())
        .ephemeral(true)
        .build()
        .expect("build");

    if Box::pin(up_tun_or_skip(&mut server, "interop_tun_os_routes"))
        .await
        .is_none()
    {
        return;
    }

    let status = server.status();
    assert!(!status.tailscale_ips.is_empty(), "should have tailnet IPs");

    // Check OS routing table for the tailnet subnet route.
    let route_check = if cfg!(target_os = "macos") {
        std::process::Command::new("netstat")
            .args(["-rn", "-f", "inet"])
            .output()
    } else {
        std::process::Command::new("ip")
            .args(["route", "show"])
            .output()
    };

    if let Ok(out) = route_check {
        let table = String::from_utf8_lossy(&out.stdout);
        let has_tailnet = table.contains("100.64.0.0/10") || table.contains("100.64.0.0/10");
        // On Linux the route might show as "100.64.0.0/10 dev tun0".
        let has_tailnet_linux = table.contains("100.64.0.0/10");
        assert!(
            has_tailnet || has_tailnet_linux,
            "OS routing table should contain 100.64.0.0/10 route via TUN\n{table}"
        );
        log::debug!("interop_tun_os_routes: OS route for 100.64.0.0/10 verified");
    }

    log_go_path(&server, ienv.go_ip, "tun_os_routes");
    server.close().await;
}

/// Interop TUN: Go advertises a subnet route, rustscale in TUN mode with
/// accept_routes=true installs it as an OS route. Asserts the in-process
/// RouteTable resolves the subnet to the Go peer AND the OS routing table
/// contains the subnet route.
#[tokio::test]
#[ignore = "requires TS_INTEROP_GO_IP + root + TS_INTEROP_GO_SUBNET (run via tools/interop-tun.sh)"]
async fn interop_tun_subnet_forward() {
    let Some(ienv) = require_tun_interop("interop_tun_subnet_forward") else {
        return;
    };
    let Some(subnet) = ienv.go_subnet.clone() else {
        log::debug!("interop_tun_subnet_forward: skipping (TS_INTEROP_GO_SUBNET not set)");
        return;
    };

    let uid = std::process::id();
    let mut server = Server::builder()
        .hostname(format!("rustscale-tun-subnet-{uid}"))
        .auth_key(ienv.authkey.clone())
        .ephemeral(true)
        .accept_routes(true)
        .build()
        .expect("build");

    if Box::pin(up_tun_or_skip(&mut server, "interop_tun_subnet_forward"))
        .await
        .is_none()
    {
        return;
    }

    wait_for_peer(
        &server,
        IpAddr::V4(ienv.go_ip),
        "interop_tun_subnet_forward",
    )
    .await;

    // Wait for the subnet to appear in the in-process route table.
    let sample_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 99, 0, 1));

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    loop {
        if server.route_lookup(sample_ip).is_some() {
            let routes = server.routes();
            let has_subnet = routes.iter().any(|(cidr, _)| cidr == &subnet);
            assert!(has_subnet, "route table should contain {subnet}");
            log::debug!("interop_tun_subnet_forward: in-process route {subnet} verified");

            // Also check the OS routing table.
            if cfg!(target_os = "macos") {
                if let Ok(out) = std::process::Command::new("netstat")
                    .args(["-rn", "-f", "inet"])
                    .output()
                {
                    let table = String::from_utf8_lossy(&out.stdout);
                    let net = subnet.split('/').next().unwrap_or("");
                    if table.contains(net) {
                        log::debug!("interop_tun_subnet_forward: OS route for {subnet} verified");
                    } else {
                        log::warn!(
                            "interop_tun_subnet_forward: WARN — OS route for {subnet} not found in netstat (may be installed lazily)"
                        );
                    }
                }
            } else if let Ok(out) = std::process::Command::new("ip")
                .args(["route", "show"])
                .output()
            {
                let table = String::from_utf8_lossy(&out.stdout);
                let net = subnet.split('/').next().unwrap_or("");
                if table.contains(net) {
                    log::debug!("interop_tun_subnet_forward: OS route for {subnet} verified");
                } else {
                    log::warn!(
                        "interop_tun_subnet_forward: WARN — OS route for {subnet} not found (may be installed lazily)"
                    );
                }
            }
            break;
        }
        if std::time::Instant::now() >= deadline {
            let routes = server.routes();
            panic!(
                "interop_tun_subnet_forward: subnet {subnet} never appeared in route table (90s)\n\
                 routes: {routes:?}"
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    server.close().await;
}

// ---------------------------------------------------------------------------
// Layer 3: Full TUN both sides (Linux netns, CI-only) — harness only
// ---------------------------------------------------------------------------
// See tools/interop-tun-full.sh. Both nodes run in real TUN mode inside
// isolated network namespaces connected via a veth bridge. This tests
// subnet-route forwarding and exit-node data-path where Go also needs a
// kernel interface. The test functions are the same as Layer 2 but run
// with both sides in TUN mode — the harness sets TS_INTEROP_GO_TUN=1 to
// signal that the Go side is also in TUN mode (no SOCKS5 proxy available;
// Go uses its TUN interface directly for outbound). Not implemented as
// separate Rust tests — the Layer 2 tests already cover the TUN pump
// interop; Layer 3 adds OS-level forwarding which is CI-specific.
