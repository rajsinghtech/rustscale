use super::*;
use rustscale_key::{DiscoPrivate, MachinePrivate, NodePrivate};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

fn make_query(id: u16, name: &str, query_type: u16) -> Vec<u8> {
    let mut query = Vec::new();
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    query.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    query.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    query.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    query.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    for label in name.trim_end_matches('.').split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&query_type.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes()); // IN
    query
}

fn response_v4(response: &[u8]) -> Ipv4Addr {
    let bytes: [u8; 4] = response[response.len() - 4..]
        .try_into()
        .expect("A response rdata");
    Ipv4Addr::from(bytes)
}

async fn udp_round_trip(server: SocketAddr, query: &[u8]) -> Vec<u8> {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind UDP client");
    socket.send_to(query, server).await.expect("send UDP query");
    let mut response = vec![0u8; 8192];
    let (length, source) =
        tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut response))
            .await
            .expect("UDP response timeout")
            .expect("receive UDP response");
    assert_eq!(source, server);
    response.truncate(length);
    response
}

async fn write_tcp_frame(stream: &mut tokio::net::TcpStream, query: &[u8]) {
    let length = u16::try_from(query.len()).expect("test query fits DNS/TCP frame");
    tokio::time::timeout(Duration::from_secs(2), async {
        stream.write_all(&length.to_be_bytes()).await?;
        stream.write_all(query).await
    })
    .await
    .expect("TCP query write timeout")
    .expect("write TCP query");
}

async fn read_tcp_frame(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut length = [0u8; 2];
        stream.read_exact(&mut length).await?;
        let mut response = vec![0u8; usize::from(u16::from_be_bytes(length))];
        stream.read_exact(&mut response).await?;
        std::io::Result::Ok(response)
    })
    .await
    .expect("TCP response timeout")
    .expect("read TCP response")
}

async fn spawn_udp_answer(
    answer: Ipv4Addr,
    wrong_transaction_id: bool,
) -> (
    SocketAddr,
    mpsc::UnboundedReceiver<String>,
    tokio::task::JoinHandle<()>,
) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind fake upstream");
    let address = socket.local_addr().expect("fake upstream address");
    let (seen_tx, seen_rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((length, source)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let query = &buf[..length];
            let Some((name, _, _)) = parse_question(query) else {
                continue;
            };
            let _ = seen_tx.send(name);
            let Some(mut response) = build_a_response(query, &[answer]) else {
                continue;
            };
            if wrong_transaction_id {
                response[1] ^= 0xff;
            }
            let _ = socket.send_to(&response, source).await;
        }
    });
    (address, seen_rx, task)
}

fn local_resolver(name: &str, address: Ipv4Addr) -> Arc<RwLock<MagicDnsResolver>> {
    let mut config = Config::default();
    config
        .hosts
        .insert(name.to_string(), vec![IpAddr::V4(address)]);
    let mut resolver = MagicDnsResolver::default();
    resolver.set_config(config);
    Arc::new(RwLock::new(resolver))
}

fn peer(name: &str, v4: &str, v6: &str) -> Node {
    Node {
        ID: 1,
        Name: name.into(),
        Key: NodePrivate::generate().public(),
        Machine: MachinePrivate::generate().public(),
        DiscoKey: DiscoPrivate::generate().public(),
        Addresses: vec![format!("{v4}/32"), format!("{v6}/128")],
        ..Default::default()
    }
}

#[test]
fn resolves_fqdn_a_and_aaaa() {
    let peers = vec![peer(
        "host.tailnet.ts.net.",
        "100.64.0.5",
        "fd7a:115c:a1e0::5",
    )];
    let r = MagicDnsResolver::from_peers(&peers, "tailnet.ts.net");
    assert_eq!(
        r.resolve_a("host.tailnet.ts.net"),
        vec!["100.64.0.5".parse::<Ipv4Addr>().unwrap()]
    );
    assert_eq!(
        r.resolve_aaaa("host.tailnet.ts.net"),
        vec!["fd7a:115c:a1e0::5".parse::<Ipv6Addr>().unwrap()]
    );
}

#[test]
fn resolves_short_name() {
    let peers = vec![peer(
        "host.tailnet.ts.net.",
        "100.64.0.5",
        "fd7a:115c:a1e0::5",
    )];
    let r = MagicDnsResolver::from_peers(&peers, "tailnet.ts.net");
    assert!(r.is_tailnet_name("host"));
    assert_eq!(
        r.resolve_a("host"),
        vec!["100.64.0.5".parse::<Ipv4Addr>().unwrap()]
    );
    assert_eq!(
        r.resolve_first("host"),
        Some(std::net::IpAddr::V4(
            "100.64.0.5".parse::<Ipv4Addr>().unwrap()
        ))
    );
}

#[test]
fn short_name_without_dot_is_tailnet() {
    let r = MagicDnsResolver::from_peers(&[], "tailnet.ts.net");
    assert!(
        r.is_tailnet_name("host"),
        "single-label short name is tailnet"
    );
    assert!(
        !r.is_tailnet_name("google.com"),
        "dotted non-tailnet name is NOT tailnet"
    );
    assert!(r.is_tailnet_name("host.tailnet.ts.net"));
    assert!(r.is_tailnet_name("host.tailnet.ts.net."));
    assert!(r.is_tailnet_name("tailnet.ts.net"));
}

#[test]
fn nxdomain_for_unknown_tailnet_name() {
    let peers = vec![peer(
        "host.tailnet.ts.net.",
        "100.64.0.5",
        "fd7a:115c:a1e0::5",
    )];
    let r = MagicDnsResolver::from_peers(&peers, "tailnet.ts.net");
    assert_eq!(r.lookup("nope.tailnet.ts.net"), ResolveOutcome::NxDomain);
    assert_eq!(r.lookup("nope"), ResolveOutcome::NxDomain);
}

#[test]
fn forward_decision_for_non_tailnet() {
    let r = MagicDnsResolver::from_peers(&[], "tailnet.ts.net");
    assert_eq!(r.lookup("google.com"), ResolveOutcome::NotTailnet);
}

#[test]
fn proxied_off_disables_tailnet_authoritative() {
    let peers = vec![peer(
        "host.tailnet.ts.net.",
        "100.64.0.5",
        "fd7a:115c:a1e0::5",
    )];
    let cfg = DNSConfig {
        Proxied: false,
        ..Default::default()
    };
    let r = MagicDnsResolver::new(peers, "tailnet.ts.net", Some(&cfg));
    assert!(
        !r.is_tailnet_name("host"),
        "proxied off => not authoritative"
    );
    assert!(!r.is_tailnet_name("host.tailnet.ts.net"));
}

#[test]
fn resolve_first_prefers_v4() {
    let peers = vec![peer(
        "host.tailnet.ts.net.",
        "100.64.0.5",
        "fd7a:115c:a1e0::5",
    )];
    let r = MagicDnsResolver::from_peers(&peers, "tailnet.ts.net");
    let first = r.resolve_first("host.tailnet.ts.net").unwrap();
    assert!(matches!(first, std::net::IpAddr::V4(_)));
}

#[test]
fn upstream_nameservers_falls_back_to_system() {
    let servers = upstream_nameservers(None);
    assert!(!servers.is_empty(), "must have a fallback resolver");
}

#[test]
fn upstream_nameservers_from_config() {
    use rustscale_tailcfg::Resolver;
    let cfg = DNSConfig {
        Resolvers: vec![Resolver {
            Addr: "9.9.9.9".into(),
        }],
        ..Default::default()
    };
    let servers = upstream_nameservers(Some(&cfg));
    assert_eq!(
        servers[0],
        "9.9.9.9:53".parse::<std::net::SocketAddr>().unwrap()
    );
}

// === New tests for Phase 20 ===

#[test]
fn extra_records_hosts_answer() {
    use rustscale_tailcfg::{DNSConfig, DNSRecord, Resolver};
    let cfg = DNSConfig {
        Resolvers: vec![Resolver {
            Addr: "1.1.1.1".into(),
        }],
        ExtraRecords: vec![DNSRecord {
            Name: "app.corp.ts.net.".into(),
            Type: "A".into(),
            Value: "100.64.0.10".into(),
        }],
        Proxied: true,
        ..Default::default()
    };
    let r = MagicDnsResolver::new(vec![], "tailnet.ts.net", Some(&cfg));
    // The ExtraRecord should be in the hosts map.
    let addrs = r.resolve("app.corp.ts.net");
    assert_eq!(addrs.len(), 1);
    assert_eq!(addrs[0], "100.64.0.10".parse::<IpAddr>().unwrap());
}

#[test]
fn onion_nxdomain() {
    let r = MagicDnsResolver::from_peers(&[], "tailnet.ts.net");
    let (ip, code) = r.resolve_local("something.onion", qtype::A);
    assert_eq!(code, rcode::NAME_ERROR, ".onion must return NXDOMAIN");
    assert!(ip.is_none());
}

#[test]
fn onion_nxdomain_with_subdomain() {
    let r = MagicDnsResolver::from_peers(&[], "tailnet.ts.net");
    let (_ip, code) = r.resolve_local("foo.bar.onion", qtype::A);
    assert_eq!(code, rcode::NAME_ERROR, ".onion subdomain must NXDOMAIN");
}

#[test]
fn ptr_reverse_ipv4() {
    let peers = vec![peer(
        "host.tailnet.ts.net.",
        "100.64.0.5",
        "fd7a:115c:a1e0::5",
    )];
    let r = MagicDnsResolver::from_peers(&peers, "tailnet.ts.net");
    // 100.64.0.5 → 5.0.64.100.in-addr.arpa.
    let (fqdn, code) = r.resolve_local_reverse("5.0.64.100.in-addr.arpa.");
    assert_eq!(code, rcode::SUCCESS, "PTR should succeed");
    assert_eq!(fqdn, "host.tailnet.ts.net");
}

#[test]
fn ptr_reverse_ipv6() {
    let peers = vec![peer(
        "host.tailnet.ts.net.",
        "100.64.0.5",
        "fd7a:115c:a1e0::5",
    )];
    let r = MagicDnsResolver::from_peers(&peers, "tailnet.ts.net");
    // fd7a:115c:a1e0::5 → reverse nibble format
    // Expanded: fd7a115ca1e00000000000000000005 (32 nibbles)
    // Reversed: 500000000000000000000e1ac511a7df
    // PTR: 5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.
    let ptr_name = "5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.";
    let (fqdn, code) = r.resolve_local_reverse(ptr_name);
    assert_eq!(code, rcode::SUCCESS, "IPv6 PTR should succeed");
    assert_eq!(fqdn, "host.tailnet.ts.net");
}

#[test]
fn ptr_reverse_unknown_returns_refused() {
    let r = MagicDnsResolver::from_peers(&[], "tailnet.ts.net");
    // 8.8.8.8 is not a tailnet IP.
    let (_, code) = r.resolve_local_reverse("8.8.8.8.in-addr.arpa.");
    assert_eq!(code, rcode::REFUSED, "non-tailnet PTR should be refused");
}

#[test]
fn ptr_reverse_service_ip_returns_symbolic() {
    let r = MagicDnsResolver::from_peers(&[], "tailnet.ts.net");
    // 100.100.100.100 → 100.100.100.100.in-addr.arpa.
    let (fqdn, code) = r.resolve_local_reverse("100.100.100.100.in-addr.arpa.");
    assert_eq!(code, rcode::SUCCESS);
    assert_eq!(fqdn, "magicdns.localhost-tailscale-daemon.");
}

#[test]
fn ptr_reverse_malformed_returns_refused() {
    let r = MagicDnsResolver::from_peers(&[], "tailnet.ts.net");
    let (_, code) = r.resolve_local_reverse("not-valid.arpa.");
    assert_eq!(code, rcode::REFUSED);
}

#[test]
fn via_domain_resolves_aaaa() {
    let r = MagicDnsResolver::from_peers(&[], "tailnet.ts.net");
    // 192-168-1-2-via-7 → should synthesize a 4via6 address.
    let (ip, code) = r.resolve_local("192-168-1-2-via-7", qtype::AAAA);
    assert_eq!(code, rcode::SUCCESS, "4via6 AAAA should succeed");
    assert!(ip.is_some(), "should have an IPv6 address");
    let ip6 = match ip.unwrap() {
        IpAddr::V6(v6) => v6,
        _ => panic!("expected IPv6"),
    };
    // Verify the site ID is embedded in the address.
    let oct = ip6.octets();
    assert_eq!(
        &oct[0..8],
        &[0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0x0b, 0x1a]
    );
    assert_eq!(&oct[8..12], &7u32.to_be_bytes());
    assert_eq!(&oct[12..16], &[192, 168, 1, 2]);
}

#[test]
fn via_domain_a_returns_noerror_empty() {
    // For A queries, 4via6 returns (None, true) → NOERROR with empty answer.
    let (ip, ok) = MagicDnsResolver::resolve_via_domain("192-168-1-2-via-7", qtype::A);
    assert!(ok, "should be a valid 4via6 domain");
    assert!(ip.is_none(), "A query should not return an IP");
}

#[test]
fn via_domain_with_ts_net_suffix() {
    let r = MagicDnsResolver::from_peers(&[], "tailnet.ts.net");
    let (ip, code) = r.resolve_local("10-0-0-1-via-3.foo.ts.net", qtype::AAAA);
    assert_eq!(code, rcode::SUCCESS);
    assert!(ip.is_some());
}

#[test]
fn via_domain_invalid_returns_false() {
    let (_, ok) = MagicDnsResolver::resolve_via_domain("not-a-via-domain", qtype::AAAA);
    assert!(!ok, "non-via domain should return false");
}

#[test]
fn via_domain_bad_ip_returns_false() {
    let (_, ok) = MagicDnsResolver::resolve_via_domain("999-999-999-999-via-1", qtype::AAAA);
    assert!(!ok, "invalid IP in via domain should return false");
}

#[test]
fn symbolic_fqdn_resolves_to_service_ip() {
    let r = MagicDnsResolver::from_peers(&[], "tailnet.ts.net");
    let (ip, code) = r.resolve_local("magicdns.localhost-tailscale-daemon", qtype::A);
    assert_eq!(code, rcode::SUCCESS);
    assert_eq!(ip, Some(IpAddr::V4(MAGICDNS_VIP)));

    let (ip6, code6) = r.resolve_local("magicdns.localhost-tailscale-daemon", qtype::AAAA);
    assert_eq!(code6, rcode::SUCCESS);
    assert_eq!(ip6, Some(IpAddr::V6(MAGICDNS_VIP_V6)));
}

#[test]
fn all_qtype_returns_first_addr() {
    use rustscale_tailcfg::{DNSConfig, DNSRecord};
    let cfg = DNSConfig {
        ExtraRecords: vec![DNSRecord {
            Name: "dual.corp.ts.net.".into(),
            Type: "A".into(),
            Value: "100.64.0.10".into(),
        }],
        Proxied: true,
        ..Default::default()
    };
    let r = MagicDnsResolver::new(vec![], "tailnet.ts.net", Some(&cfg));
    let (ip, code) = r.resolve_local("dual.corp.ts.net", qtype::ALL);
    assert_eq!(code, rcode::SUCCESS);
    assert!(ip.is_some());
}

#[test]
fn ns_qtype_returns_notimpl() {
    let _r = MagicDnsResolver::from_peers(&[], "tailnet.ts.net");
    let peers = vec![peer(
        "host.tailnet.ts.net.",
        "100.64.0.5",
        "fd7a:115c:a1e0::5",
    )];
    let mut r = MagicDnsResolver::from_peers(&peers, "tailnet.ts.net");
    r.set_peers(peers);
    let (_, code) = r.resolve_local("host.tailnet.ts.net", qtype::NS);
    assert_eq!(code, rcode::NOT_IMPLEMENTED);
}

#[test]
fn unknown_qtype_returns_noerror() {
    let peers = vec![peer(
        "host.tailnet.ts.net.",
        "100.64.0.5",
        "fd7a:115c:a1e0::5",
    )];
    let r = MagicDnsResolver::from_peers(&peers, "tailnet.ts.net");
    // Unknown record type → NOERROR with 0 answers (name exists).
    let (_, code) = r.resolve_local("host.tailnet.ts.net", 9999);
    assert_eq!(code, rcode::SUCCESS);
}

#[test]
fn set_config_swaps_atomically() {
    let r = MagicDnsResolver::from_peers(&[], "tailnet.ts.net");
    let mut cfg = Config::default();
    cfg.hosts.insert(
        "newhost.ts.net".to_string(),
        vec!["100.64.0.99".parse::<IpAddr>().unwrap()],
    );
    let mut r = r;
    r.set_config(cfg);
    assert_eq!(
        r.resolve("newhost.ts.net"),
        vec!["100.64.0.99".parse::<IpAddr>().unwrap()]
    );
}

#[test]
fn set_config_under_concurrent_queries() {
    use std::sync::Arc;
    use std::thread;

    let r = Arc::new(std::sync::RwLock::new(MagicDnsResolver::from_peers(
        &[],
        "tailnet.ts.net",
    )));

    // Spawn a thread that rapidly swaps config.
    let r2 = r.clone();
    let swap_thread = thread::spawn(move || {
        for i in 0..100 {
            let mut cfg = Config::default();
            cfg.hosts.insert(
                format!("host{i}.ts.net"),
                vec![format!("100.64.0.{i}").parse::<IpAddr>().unwrap()],
            );
            r2.write().unwrap().set_config(cfg);
        }
    });

    // Concurrently query the resolver.
    let r3 = r.clone();
    let query_thread = thread::spawn(move || {
        for i in 0..100 {
            let _ = r3.read().unwrap().resolve(&format!("host{i}.ts.net"));
        }
    });

    swap_thread.join().unwrap();
    query_thread.join().unwrap();
}

#[test]
fn routes_suffix_matching_most_specific_wins() {
    let mut cfg = Config::default();
    cfg.routes.insert(
        ".".to_string(),
        vec![UpstreamResolver::from_addr("8.8.8.8")],
    );
    cfg.routes.insert(
        "corp.example.com".to_string(),
        vec![UpstreamResolver::from_addr("10.0.0.53")],
    );
    cfg.routes.insert(
        "internal.corp.example.com".to_string(),
        vec![UpstreamResolver::from_addr("10.0.0.54")],
    );

    let r = MagicDnsResolver {
        peers: vec![],
        domain: "ts.net".into(),
        proxied: true,
        config: cfg,
        ip_to_host: HashMap::new(),
    };

    // Most specific match.
    let resolvers = r.upstream_resolvers_for("host.internal.corp.example.com");
    assert_eq!(resolvers.len(), 1);
    assert_eq!(resolvers[0].addr, "10.0.0.54");

    // Less specific match.
    let resolvers = r.upstream_resolvers_for("host.corp.example.com");
    assert_eq!(resolvers[0].addr, "10.0.0.53");

    // Default route.
    let resolvers = r.upstream_resolvers_for("google.com");
    assert_eq!(resolvers[0].addr, "8.8.8.8");
}

#[test]
fn routes_empty_resolver_list_means_local() {
    let mut cfg = Config::default();
    cfg.routes.insert(".".to_string(), vec![]);
    cfg.hosts.insert(
        "local.ts.net".to_string(),
        vec!["100.64.0.1".parse::<IpAddr>().unwrap()],
    );

    let r = MagicDnsResolver {
        peers: vec![],
        domain: "ts.net".into(),
        proxied: true,
        config: cfg,
        ip_to_host: HashMap::new(),
    };

    // Empty route means local handling.
    let resolvers = r.upstream_resolvers_for("local.ts.net");
    assert!(resolvers.is_empty(), "empty route = local handling");
}

#[test]
fn subdomain_hosts_resolution() {
    let mut cfg = Config::default();
    cfg.hosts.insert(
        "node.tailnet.ts.net".to_string(),
        vec!["100.64.0.5".parse::<IpAddr>().unwrap()],
    );
    cfg.subdomain_hosts
        .insert("node.tailnet.ts.net".to_string());

    let r = MagicDnsResolver {
        peers: vec![],
        domain: "tailnet.ts.net".into(),
        proxied: true,
        config: cfg,
        ip_to_host: HashMap::new(),
    };

    // sub.node.tailnet.ts.net should resolve to node.tailnet.ts.net's IPs.
    let addrs = r.resolve("sub.node.tailnet.ts.net");
    assert_eq!(addrs.len(), 1);
    assert_eq!(addrs[0], "100.64.0.5".parse::<IpAddr>().unwrap());
}

#[test]
fn config_from_dns_builds_routes() {
    use rustscale_tailcfg::{DNSConfig, Resolver};
    let cfg = DNSConfig {
        Resolvers: vec![Resolver {
            Addr: "1.1.1.1".into(),
        }],
        Routes: HashMap::from([(
            "corp.example.com.".to_string(),
            vec![Resolver {
                Addr: "10.0.0.53".into(),
            }],
        )]),
        Proxied: true,
        ..Default::default()
    };
    let config = config_from_dns(&cfg, "tailnet.ts.net", &[]);
    assert!(config.routes.contains_key("."));
    assert!(config.routes.contains_key("corp.example.com"));
    assert_eq!(config.routes["."].len(), 1);
}

#[test]
fn config_from_dns_preserves_root_and_local_routes() {
    use rustscale_tailcfg::Resolver;

    let explicit_root = DNSConfig {
        Resolvers: vec![Resolver {
            Addr: "1.1.1.1".into(),
        }],
        Routes: HashMap::from([(
            ".".to_string(),
            vec![Resolver {
                Addr: "9.9.9.9".into(),
            }],
        )]),
        ..Default::default()
    };
    let config = config_from_dns(&explicit_root, "", &[]);
    assert_eq!(config.routes.len(), 1);
    assert_eq!(config.routes["."][0].addr, "9.9.9.9");

    let local = DNSConfig {
        Resolvers: vec![Resolver {
            Addr: "1.1.1.1".into(),
        }],
        Routes: HashMap::from([("private.example.".to_string(), vec![])]),
        ..Default::default()
    };
    let config = config_from_dns(&local, "", &[]);
    assert!(!config.routes.contains_key("private.example"));
    assert!(config
        .local_domains
        .contains(&"private.example".to_string()));

    let fallback = DNSConfig {
        FallbackResolvers: vec![Resolver {
            Addr: "8.8.4.4".into(),
        }],
        ..Default::default()
    };
    let config = config_from_dns(&fallback, "", &[]);
    assert_eq!(config.routes["."][0].addr, "8.8.4.4");
}

#[test]
fn bonjour_prefix_detection() {
    assert!(has_rdns_bonjour_prefix("b._dns-sd._udp.example.com."));
    assert!(has_rdns_bonjour_prefix("db._dns-sd._udp.example.com."));
    assert!(has_rdns_bonjour_prefix("lb._dns-sd._udp.example.com."));
    assert!(!has_rdns_bonjour_prefix("host.tailnet.ts.net."));
    assert!(!has_rdns_bonjour_prefix("example.com."));
}

#[test]
fn rdns_name_to_ipv4_roundtrip() {
    let (ip, ok) = rdns_name_to_ipv4("5.0.64.100.in-addr.arpa.");
    assert!(ok);
    assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 5))));
}

#[test]
fn rdns_name_to_ipv6_roundtrip() {
    // fd7a:115c:a1e0::5
    let ptr = "5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.";
    let (ip, ok) = rdns_name_to_ipv6(ptr);
    assert!(ok);
    assert_eq!(
        ip,
        Some(IpAddr::V6("fd7a:115c:a1e0::5".parse::<Ipv6Addr>().unwrap()))
    );
}

#[test]
fn map_via_produces_correct_address() {
    let ip4 = Ipv4Addr::new(192, 168, 1, 2);
    let v6 = map_via(7, ip4);
    let oct = v6.octets();
    assert_eq!(
        &oct[0..8],
        &[0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0x0b, 0x1a]
    );
    assert_eq!(&oct[8..12], &7u32.to_be_bytes());
    assert_eq!(&oct[12..16], &[192, 168, 1, 2]);
}

#[test]
fn tailscale_6to4_roundtrip() {
    // 100.64.0.5 → 4to6 → fd7a:115c:a1e0:ab12:4843:cd96:6264:0005
    let v4 = Ipv4Addr::new(100, 64, 0, 5);
    let v6 = rustscale_tsaddr::tailscale_4to6(v4);

    let back = tailscale_6to4(v6);
    assert_eq!(back, Some(v4));
}

#[test]
fn suffix_matches_dot_matches_all() {
    assert!(suffix_matches(".", "anything.com"));
    assert!(suffix_matches("", "anything.com"));
}

#[test]
fn suffix_matches_domain() {
    assert!(suffix_matches("ts.net", "host.ts.net"));
    assert!(suffix_matches("ts.net", "ts.net"));
    assert!(!suffix_matches("ts.net", "google.com"));
    assert!(!suffix_matches("ts.net", "notts.net"));
}

/// End-to-end route vectors derived from the route ordering/fallback contracts
/// in tailscale.com@v1.100.0 net/dns/resolver/forwarder.go.
#[tokio::test]
async fn responder_uses_longest_suffix_failover_and_live_reconfiguration() {
    use rustscale_tailcfg::Resolver;

    let (wrong_addr, mut wrong_seen, wrong_task) =
        spawn_udp_answer(Ipv4Addr::new(192, 0, 2, 1), true).await;
    let (corp_addr, mut corp_seen, corp_task) =
        spawn_udp_answer(Ipv4Addr::new(10, 0, 0, 53), false).await;
    let (internal_addr, mut internal_seen, internal_task) =
        spawn_udp_answer(Ipv4Addr::new(10, 0, 0, 54), false).await;
    let (default_addr, mut default_seen, default_task) =
        spawn_udp_answer(Ipv4Addr::new(8, 8, 8, 8), false).await;

    let dns_config = DNSConfig {
        Resolvers: vec![Resolver {
            Addr: default_addr.to_string(),
        }],
        Routes: HashMap::from([
            (
                "corp.example.".to_string(),
                vec![
                    Resolver {
                        Addr: wrong_addr.to_string(),
                    },
                    Resolver {
                        Addr: corp_addr.to_string(),
                    },
                ],
            ),
            (
                "internal.corp.example.".to_string(),
                vec![Resolver {
                    Addr: internal_addr.to_string(),
                }],
            ),
            ("blocked.example.".to_string(), vec![]),
        ]),
        Proxied: true,
        ..Default::default()
    };
    let resolver = Arc::new(RwLock::new(MagicDnsResolver::new(
        vec![],
        "tailnet.ts.net",
        Some(&dns_config),
    )));
    let responder = DnsResponder::with_forwarder(
        Arc::clone(&resolver),
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(Forwarder::from_dns_config(Some(&dns_config))),
    )
    .spawn()
    .await
    .expect("start DNS responder");
    let responder_addr = responder.local_addr();

    let internal_query = make_query(0x1001, "host.internal.corp.example", qtype::A);
    let internal_response = udp_round_trip(responder_addr, &internal_query).await;
    assert_eq!(response_v4(&internal_response), Ipv4Addr::new(10, 0, 0, 54));
    assert_eq!(
        internal_seen.recv().await.as_deref(),
        Some("host.internal.corp.example")
    );
    assert!(wrong_seen.try_recv().is_err());
    assert!(corp_seen.try_recv().is_err());

    // The first resolver returns a mismatched transaction ID, so the same
    // matched route fails over to its second resolver without using root DNS.
    let corp_query = make_query(0x1002, "host.corp.example", qtype::A);
    let corp_response = udp_round_trip(responder_addr, &corp_query).await;
    assert_eq!(response_v4(&corp_response), Ipv4Addr::new(10, 0, 0, 53));
    assert_eq!(
        wrong_seen.recv().await.as_deref(),
        Some("host.corp.example")
    );
    assert_eq!(corp_seen.recv().await.as_deref(), Some("host.corp.example"));

    let default_query = make_query(0x1003, "public.example.net", qtype::A);
    let default_response = udp_round_trip(responder_addr, &default_query).await;
    assert_eq!(response_v4(&default_response), Ipv4Addr::new(8, 8, 8, 8));
    assert_eq!(
        default_seen.recv().await.as_deref(),
        Some("public.example.net")
    );

    // An empty route is local/authoritative and must not leak to root DNS.
    let blocked_query = make_query(0x1004, "host.blocked.example", qtype::A);
    let blocked_response = udp_round_trip(responder_addr, &blocked_query).await;
    assert_eq!(blocked_response[3] & 0x0f, rcode::NAME_ERROR);
    tokio::task::yield_now().await;
    assert!(default_seen.try_recv().is_err());

    // Reconfigure the same live responder and prove that its next query uses
    // the new route rather than Forwarder's startup snapshot.
    let updated_dns = DNSConfig {
        Routes: HashMap::from([(
            "corp.example.".to_string(),
            vec![Resolver {
                Addr: internal_addr.to_string(),
            }],
        )]),
        Proxied: true,
        ..Default::default()
    };
    resolver
        .write()
        .await
        .set_config(config_from_dns(&updated_dns, "tailnet.ts.net", &[]));
    let reconfigured_query = make_query(0x1005, "host.corp.example", qtype::A);
    let reconfigured_response = udp_round_trip(responder_addr, &reconfigured_query).await;
    assert_eq!(
        response_v4(&reconfigured_response),
        Ipv4Addr::new(10, 0, 0, 54)
    );
    assert_eq!(
        internal_seen.recv().await.as_deref(),
        Some("host.corp.example")
    );

    responder.shutdown().await;
    wrong_task.abort();
    corp_task.abort();
    internal_task.abort();
    default_task.abort();
}

/// The production TUN lifecycle transfers responder task ownership to its
/// outer supervisor. The transfer itself must not cancel the live listeners.
#[tokio::test]
async fn transferred_responder_task_serves_udp_and_tcp() {
    let handle = DnsResponder::with_forwarder(
        local_resolver("handoff.test", Ipv4Addr::new(100, 64, 0, 42)),
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(Forwarder::new(vec![])),
    )
    .spawn()
    .await
    .expect("start DNS responder");
    let address = handle.local_addr();

    // Mirror StartupRollback ownership in the TUN lifecycle.
    let task = handle.into_join_handle();
    let query = make_query(0x5001, "handoff.test", qtype::A);
    assert_eq!(
        response_v4(&udp_round_trip(address, &query).await),
        Ipv4Addr::new(100, 64, 0, 42)
    );

    let mut stream = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect DNS/TCP after task transfer");
    write_tcp_frame(&mut stream, &query).await;
    let response = read_tcp_frame(&mut stream).await;
    assert_eq!(response_v4(&response), Ipv4Addr::new(100, 64, 0, 42));

    task.abort();
    let _ = task.await;
}

/// Framing and same-session reconfiguration vectors ported from
/// tailscale.com@v1.100.0 net/dns/manager_tcp_test.go::TestDNSOverTCP.
#[tokio::test]
async fn inbound_tcp_frames_multiple_queries_and_reconfigures() {
    let resolver = local_resolver("one.test", Ipv4Addr::new(100, 64, 0, 1));
    {
        let mut config = resolver.read().await.config().clone();
        config.hosts.insert(
            "two.test".to_string(),
            vec![IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2))],
        );
        resolver.write().await.set_config(config);
    }
    let responder = DnsResponder::with_forwarder(
        Arc::clone(&resolver),
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(Forwarder::new(vec![])),
    )
    .spawn()
    .await
    .expect("start DNS responder");

    let mut stream = tokio::net::TcpStream::connect(responder.local_addr())
        .await
        .expect("connect DNS/TCP");
    let query_one = make_query(0x2001, "one.test", qtype::A);
    let query_two = make_query(0x2002, "two.test", qtype::A);
    // Write both frames before reading either response, exercising persistent
    // connection framing and query pipelining.
    write_tcp_frame(&mut stream, &query_one).await;
    write_tcp_frame(&mut stream, &query_two).await;
    let response_one = read_tcp_frame(&mut stream).await;
    let response_two = read_tcp_frame(&mut stream).await;
    assert_eq!(&response_one[..2], &0x2001u16.to_be_bytes());
    assert_eq!(&response_two[..2], &0x2002u16.to_be_bytes());
    assert_eq!(response_v4(&response_one), Ipv4Addr::new(100, 64, 0, 1));
    assert_eq!(response_v4(&response_two), Ipv4Addr::new(100, 64, 0, 2));
    assert!(!wire::truncated_flag_set(&response_one));
    assert!(!wire::truncated_flag_set(&response_two));

    let mut replacement = Config::default();
    replacement.hosts.insert(
        "one.test".to_string(),
        vec![IpAddr::V4(Ipv4Addr::new(100, 64, 0, 99))],
    );
    resolver.write().await.set_config(replacement);
    let reconfigured = make_query(0x2003, "one.test", qtype::A);
    write_tcp_frame(&mut stream, &reconfigured).await;
    let response = read_tcp_frame(&mut stream).await;
    assert_eq!(response_v4(&response), Ipv4Addr::new(100, 64, 0, 99));

    responder.shutdown().await;
}

async fn spawn_truncating_dual_upstream() -> (
    SocketAddr,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
    tokio::task::JoinHandle<()>,
) {
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake upstream TCP");
    let address = tcp.local_addr().unwrap();
    let udp = tokio::net::UdpSocket::bind(address)
        .await
        .expect("bind fake upstream UDP");
    let udp_count = Arc::new(AtomicUsize::new(0));
    let tcp_count = Arc::new(AtomicUsize::new(0));

    let udp_counter = Arc::clone(&udp_count);
    let udp_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((length, source)) = udp.recv_from(&mut buf).await else {
                return;
            };
            udp_counter.fetch_add(1, Ordering::SeqCst);
            let query = &buf[..length];
            let addresses = vec![Ipv4Addr::LOCALHOST; 40];
            let Some(mut response) = build_a_response(query, &addresses) else {
                continue;
            };
            wire::set_tc_flag(&mut response);
            let _ = udp.send_to(&response, source).await;
        }
    });

    let tcp_counter = Arc::clone(&tcp_count);
    let tcp_task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = tcp.accept().await else {
                return;
            };
            tcp_counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut length = [0u8; 2];
                if stream.read_exact(&mut length).await.is_err() {
                    return;
                }
                let mut query = vec![0u8; usize::from(u16::from_be_bytes(length))];
                if stream.read_exact(&mut query).await.is_err() {
                    return;
                }
                let addresses = vec![Ipv4Addr::LOCALHOST; 40];
                let Some(response) = build_a_response(&query, &addresses) else {
                    return;
                };
                let Ok(response_len) = u16::try_from(response.len()) else {
                    return;
                };
                let _ = stream.write_all(&response_len.to_be_bytes()).await;
                let _ = stream.write_all(&response).await;
            });
        }
    });

    (address, udp_count, tcp_count, udp_task, tcp_task)
}

/// TCP retry and TC vectors derived from
/// tailscale.com@v1.100.0 net/dns/resolver/forwarder_test.go::TestForwarderTCPFallback.
#[tokio::test]
async fn inbound_transport_preserves_udp_tc_and_returns_full_tcp_response() {
    let (upstream, udp_count, tcp_count, udp_task, tcp_task) =
        spawn_truncating_dual_upstream().await;
    let mut config = Config::default();
    config.routes.insert(
        ".".to_string(),
        vec![UpstreamResolver::from_addr(&upstream.to_string())],
    );
    let mut magic = MagicDnsResolver::default();
    magic.set_config(config);
    let resolver = Arc::new(RwLock::new(magic));
    let responder = DnsResponder::with_forwarder(
        resolver,
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(Forwarder::new(vec![])),
    )
    .spawn()
    .await
    .expect("start DNS responder");
    let query = make_query(0x3001, "large.example", qtype::A);

    let udp_response = udp_round_trip(responder.local_addr(), &query).await;
    assert!(wire::truncated_flag_set(&udp_response));
    assert_eq!(tcp_count.load(Ordering::SeqCst), 0);

    let mut stream = tokio::net::TcpStream::connect(responder.local_addr())
        .await
        .expect("connect DNS/TCP");
    write_tcp_frame(&mut stream, &query).await;
    let tcp_response = read_tcp_frame(&mut stream).await;
    assert!(tcp_response.len() > 512);
    assert!(!wire::truncated_flag_set(&tcp_response));
    assert!(udp_count.load(Ordering::SeqCst) >= 1);
    assert!(tcp_count.load(Ordering::SeqCst) >= 1);

    responder.shutdown().await;
    udp_task.abort();
    tcp_task.abort();
}

async fn spawn_hanging_dual_upstream() -> (
    SocketAddr,
    mpsc::UnboundedReceiver<()>,
    tokio::task::JoinHandle<()>,
    tokio::task::JoinHandle<()>,
) {
    // Binding one protocol to port zero does not reserve the same port for the
    // other protocol. Another test or process can claim the UDP port between
    // these calls, particularly on macOS, so retry the complete pair.
    let (tcp, udp, address) = {
        let mut pair = None;
        for _ in 0..32 {
            let tcp = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind hanging upstream TCP");
            let address = tcp.local_addr().unwrap();
            match tokio::net::UdpSocket::bind(address).await {
                Ok(udp) => {
                    pair = Some((tcp, udp, address));
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                    drop(tcp);
                    tokio::task::yield_now().await;
                }
                Err(error) => panic!("bind hanging upstream UDP: {error}"),
            }
        }
        pair.expect("bind hanging upstream TCP/UDP pair after retries")
    };
    let (started_tx, started_rx) = mpsc::unbounded_channel();
    let udp_started = started_tx.clone();
    let udp_task = tokio::spawn(async move {
        let mut query = vec![0u8; 4096];
        if udp.recv(&mut query).await.is_ok() {
            let _ = udp_started.send(());
            std::future::pending::<()>().await;
        }
    });
    let tcp_task = tokio::spawn(async move {
        let Ok((mut stream, _)) = tcp.accept().await else {
            return;
        };
        let mut length = [0u8; 2];
        if stream.read_exact(&mut length).await.is_err() {
            return;
        }
        let mut query = vec![0u8; usize::from(u16::from_be_bytes(length))];
        if stream.read_exact(&mut query).await.is_ok() {
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        }
    });
    (address, started_rx, udp_task, tcp_task)
}

#[tokio::test]
async fn shutdown_cancels_inflight_forwarding() {
    let (upstream, mut started, udp_task, tcp_task) = spawn_hanging_dual_upstream().await;
    let mut config = Config::default();
    config.routes.insert(
        ".".to_string(),
        vec![UpstreamResolver::from_addr(&upstream.to_string())],
    );
    let mut magic = MagicDnsResolver::default();
    magic.set_config(config);
    let responder = DnsResponder::with_forwarder(
        Arc::new(RwLock::new(magic)),
        "127.0.0.1:0".parse().unwrap(),
        Arc::new(Forwarder::new(vec![])),
    )
    .spawn()
    .await
    .expect("start DNS responder");
    let mut stream = tokio::net::TcpStream::connect(responder.local_addr())
        .await
        .expect("connect DNS/TCP");
    write_tcp_frame(
        &mut stream,
        &make_query(0x3fff, "hanging.example", qtype::A),
    )
    .await;
    tokio::time::timeout(Duration::from_secs(2), started.recv())
        .await
        .expect("forwarding did not start")
        .expect("hanging upstream stopped");

    tokio::time::timeout(Duration::from_secs(2), responder.shutdown())
        .await
        .expect("in-flight forwarding ignored cancellation");
    assert_tcp_closed(&mut stream).await;
    udp_task.abort();
    tcp_task.abort();
}

async fn assert_tcp_closed(stream: &mut tokio::net::TcpStream) {
    let mut byte = [0u8; 1];
    match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte)).await {
        Ok(Ok(0) | Err(_)) => {}
        Ok(Ok(length)) => panic!("unexpected {length} response byte(s) before close"),
        Err(error) => panic!("DNS/TCP connection did not close: {error}"),
    }
}

/// Malformed-size and shutdown/restart vectors ported from
/// tailscale.com@v1.100.0 net/dns/manager_tcp_test.go::TestDNSOverTCP_TooLarge.
#[tokio::test]
async fn inbound_tcp_limits_cancellation_and_restart_release_port() {
    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let first = DnsResponder::with_forwarder(
        local_resolver("restart.test", Ipv4Addr::new(100, 64, 0, 7)),
        bind,
        Arc::new(Forwarder::new(vec![])),
    )
    .spawn()
    .await
    .expect("start first responder");
    let address = first.local_addr();

    // Cancellation must wake a session blocked in a partial length prefix.
    let mut partial = tokio::net::TcpStream::connect(address).await.unwrap();
    partial.write_all(&[0]).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), first.shutdown())
        .await
        .expect("responder shutdown blocked");
    assert_tcp_closed(&mut partial).await;

    // Both protocols must be immediately restartable on the exact old port.
    let second = DnsResponder::with_forwarder(
        local_resolver("restart.test", Ipv4Addr::new(100, 64, 0, 8)),
        address,
        Arc::new(Forwarder::new(vec![])),
    )
    .spawn()
    .await
    .expect("restart responder on released UDP/TCP port");
    assert_eq!(second.local_addr(), address);
    let query = make_query(0x4001, "restart.test", qtype::A);
    assert_eq!(
        response_v4(&udp_round_trip(address, &query).await),
        Ipv4Addr::new(100, 64, 0, 8)
    );

    // The exact pinned boundary is accepted.
    let mut maximum = tokio::net::TcpStream::connect(address).await.unwrap();
    let mut maximum_query = query.clone();
    maximum_query.resize(MAX_TCP_REQUEST_SIZE, 0);
    write_tcp_frame(&mut maximum, &maximum_query).await;
    let maximum_response = read_tcp_frame(&mut maximum).await;
    assert_eq!(response_v4(&maximum_response), Ipv4Addr::new(100, 64, 0, 8));

    // A frame above the pinned 4096-byte cap closes only that connection.
    let mut oversized = tokio::net::TcpStream::connect(address).await.unwrap();
    oversized
        .write_all(
            &u16::try_from(MAX_TCP_REQUEST_SIZE + 1)
                .unwrap()
                .to_be_bytes(),
        )
        .await
        .unwrap();
    assert_tcp_closed(&mut oversized).await;

    // Zero-length and structurally malformed frames receive bounded FORMERR
    // responses, and the persistent session remains usable afterward.
    let mut malformed = tokio::net::TcpStream::connect(address).await.unwrap();
    write_tcp_frame(&mut malformed, &[]).await;
    let empty_response = read_tcp_frame(&mut malformed).await;
    assert_eq!(empty_response[3] & 0x0f, rcode::FORMAT_ERROR);

    let mut bad_question_count = vec![0u8; 12];
    bad_question_count[..2].copy_from_slice(&0x4002u16.to_be_bytes());
    bad_question_count[4..6].copy_from_slice(&2u16.to_be_bytes());
    write_tcp_frame(&mut malformed, &bad_question_count).await;
    let malformed_response = read_tcp_frame(&mut malformed).await;
    assert_eq!(&malformed_response[..2], &0x4002u16.to_be_bytes());
    assert_eq!(malformed_response[3] & 0x0f, rcode::FORMAT_ERROR);

    write_tcp_frame(&mut malformed, &query).await;
    let valid_response = read_tcp_frame(&mut malformed).await;
    assert_eq!(response_v4(&valid_response), Ipv4Addr::new(100, 64, 0, 8));

    second.shutdown().await;
}
