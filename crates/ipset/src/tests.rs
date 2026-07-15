use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rand::{rngs::StdRng, Rng, SeedableRng};

use super::*;

fn prefix(value: &str) -> IpPrefix {
    let (address, bits) = value.split_once('/').expect("prefix has slash");
    IpPrefix::new(
        address.parse().expect("valid IP"),
        bits.parse().expect("valid bits"),
    )
    .expect("valid prefix")
}

fn ip(value: &str) -> IpAddr {
    value.parse().expect("valid IP")
}

struct UpstreamCase {
    name: &'static str,
    prefixes: Vec<IpPrefix>,
    strategy: &'static str,
    want_in: Vec<IpAddr>,
    want_out: Vec<IpAddr>,
}

fn upstream_cases() -> Vec<UpstreamCase> {
    vec![
        UpstreamCase {
            name: "empty",
            prefixes: vec![],
            strategy: "empty",
            want_in: vec![],
            want_out: vec![ip("8.8.8.8")],
        },
        UpstreamCase {
            name: "cidr-list-1",
            prefixes: vec![prefix("10.0.0.0/8")],
            strategy: "one-prefix",
            want_in: vec![ip("10.0.0.1"), ip("10.2.3.4")],
            want_out: vec![ip("8.8.8.8")],
        },
        UpstreamCase {
            name: "cidr-list-2",
            prefixes: vec![prefix("1.0.0.0/8"), prefix("3.0.0.0/8")],
            strategy: "linear-contains",
            want_in: vec![ip("1.0.0.1"), ip("3.0.0.1")],
            want_out: vec![ip("2.0.0.1")],
        },
        UpstreamCase {
            name: "cidr-list-3",
            prefixes: vec![
                prefix("1.0.0.0/8"),
                prefix("3.0.0.0/8"),
                prefix("5.0.0.0/8"),
            ],
            strategy: "linear-contains",
            want_in: vec![ip("1.0.0.1"), ip("5.0.0.1")],
            want_out: vec![ip("2.0.0.1")],
        },
        UpstreamCase {
            name: "cidr-list-4",
            prefixes: vec![
                prefix("1.0.0.0/8"),
                prefix("3.0.0.0/8"),
                prefix("5.0.0.0/8"),
                prefix("7.0.0.0/8"),
            ],
            strategy: "linear-contains",
            want_in: vec![ip("1.0.0.1"), ip("7.0.0.1")],
            want_out: vec![ip("2.0.0.1")],
        },
        UpstreamCase {
            name: "cidr-list-5",
            prefixes: vec![
                prefix("1.0.0.0/8"),
                prefix("3.0.0.0/8"),
                prefix("5.0.0.0/8"),
                prefix("7.0.0.0/8"),
                prefix("9.0.0.0/8"),
            ],
            strategy: "linear-contains",
            want_in: vec![ip("1.0.0.1"), ip("9.0.0.1")],
            want_out: vec![ip("2.0.0.1")],
        },
        UpstreamCase {
            name: "cidr-list-10",
            prefixes: [1_u8, 3, 5, 7, 9, 11, 13, 15, 17, 19]
                .into_iter()
                .map(|first| IpPrefix::new(IpAddr::V4(Ipv4Addr::new(first, 0, 0, 0)), 8).unwrap())
                .collect(),
            strategy: "bart",
            want_in: vec![ip("1.0.0.1"), ip("19.0.0.1")],
            want_out: vec![ip("2.0.0.1")],
        },
        UpstreamCase {
            name: "one-ip",
            prefixes: vec![prefix("10.1.0.0/32")],
            strategy: "one-ip",
            want_in: vec![ip("10.1.0.0")],
            want_out: vec![ip("10.0.0.9")],
        },
        UpstreamCase {
            name: "two-ip",
            prefixes: vec![prefix("10.1.0.0/32"), prefix("10.2.0.0/32")],
            strategy: "two-ip",
            want_in: vec![ip("10.1.0.0"), ip("10.2.0.0")],
            want_out: vec![ip("8.8.8.8")],
        },
        UpstreamCase {
            name: "three-ip",
            prefixes: vec![
                prefix("10.1.0.0/32"),
                prefix("10.2.0.0/32"),
                prefix("10.3.0.0/32"),
            ],
            strategy: "ip-map",
            want_in: vec![ip("10.1.0.0"), ip("10.2.0.0")],
            want_out: vec![ip("8.8.8.8")],
        },
    ]
}

#[test]
fn full_upstream_vectors_and_strategy_selection() {
    for case in upstream_cases() {
        let matcher = new_contains_ip_func(&case.prefixes);
        assert_eq!(matcher.strategy.name(), case.strategy, "{}", case.name);
        for address in case.want_in {
            assert!(matcher.contains(address), "{}: {address}", case.name);
        }
        for address in case.want_out {
            assert!(!matcher.contains(address), "{}: {address}", case.name);
        }
    }
}

#[test]
fn false_predicate_rejects_both_families() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ContainsIpFunc>();

    let matcher = false_contains_ip_func();
    assert!(!matcher.contains(ip("192.0.2.1")));
    assert!(!matcher.contains(ip("2001:db8::1")));
}

#[test]
fn mixed_families_and_host_bits_match_netip_prefix_contains() {
    let prefixes = [prefix("10.20.30.40/8"), prefix("2001:db8:1234:5678::1/32")];
    let matcher = new_contains_ip_func(&prefixes);

    assert!(matcher.contains(ip("10.255.0.1")));
    assert!(!matcher.contains(ip("11.0.0.1")));
    assert!(matcher.contains(ip("2001:db8:ffff::1")));
    assert!(!matcher.contains(ip("2001:db9::1")));
    assert!(!matcher.contains(ip("::ffff:10.20.30.40")));
}

#[test]
fn matcher_is_immutable_after_construction() {
    let mut prefixes = vec![prefix("192.0.2.0/24"), prefix("2001:db8::/32")];
    let matcher = new_contains_ip_func(&prefixes);
    prefixes.clear();
    prefixes.push(prefix("198.51.100.0/24"));

    assert!(matcher.contains(ip("192.0.2.44")));
    assert!(matcher.contains(ip("2001:db8::44")));
    assert!(!matcher.contains(ip("198.51.100.44")));
}

fn random_prefix(rng: &mut StdRng) -> IpPrefix {
    if rng.gen_bool(0.5) {
        IpPrefix::new(
            IpAddr::V4(Ipv4Addr::from(rng.gen::<u32>())),
            rng.gen_range(0..=32),
        )
        .unwrap()
    } else {
        IpPrefix::new(
            IpAddr::V6(Ipv6Addr::from(rng.gen::<u128>())),
            rng.gen_range(0..=128),
        )
        .unwrap()
    }
}

fn random_ip(rng: &mut StdRng) -> IpAddr {
    if rng.gen_bool(0.5) {
        IpAddr::V4(Ipv4Addr::from(rng.gen::<u32>()))
    } else {
        IpAddr::V6(Ipv6Addr::from(rng.gen::<u128>()))
    }
}

#[test]
fn randomized_differential_against_linear_prefix_contains() {
    let mut rng = StdRng::seed_from_u64(0x4950_5345_545f_4449);
    for len in 0..=24 {
        for case in 0..100 {
            let prefixes: Vec<_> = (0..len).map(|_| random_prefix(&mut rng)).collect();
            let matcher = new_contains_ip_func(&prefixes);
            for query in 0..200 {
                let address = random_ip(&mut rng);
                let want = prefixes.iter().any(|prefix| prefix.contains(address));
                assert_eq!(
                    matcher.contains(address),
                    want,
                    "len={len} case={case} query={query} address={address} prefixes={prefixes:?}"
                );
            }
        }
    }
}
