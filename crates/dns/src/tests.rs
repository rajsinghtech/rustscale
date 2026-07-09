use super::*;
use rustscale_key::{DiscoPrivate, MachinePrivate, NodePrivate};
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
