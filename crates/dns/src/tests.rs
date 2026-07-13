use super::*;
use rustscale_key::{DiscoPrivate, MachinePrivate, NodePrivate};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

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
