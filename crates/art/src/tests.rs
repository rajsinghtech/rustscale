use std::{collections::BTreeMap, net::IpAddr};

use rand::{rngs::StdRng, Rng, SeedableRng};

use crate::{compute_prefix_split, stride_table, IpPrefix, Table};

fn prefix(value: &str) -> IpPrefix {
    value.parse().expect("valid test prefix")
}

fn naive_get(routes: &BTreeMap<IpPrefix, usize>, addr: IpAddr) -> Option<usize> {
    routes
        .iter()
        .filter(|(route, _)| route.contains(addr))
        .max_by_key(|(route, _)| route.bits())
        .map(|(_, value)| *value)
}

fn random_addr(rng: &mut StdRng, is_v6: bool) -> IpAddr {
    if is_v6 {
        IpAddr::V6(rng.gen::<u128>().into())
    } else {
        IpAddr::V4(rng.gen::<u32>().into())
    }
}

fn random_prefix(rng: &mut StdRng, is_v6: bool) -> IpPrefix {
    let max_bits = if is_v6 { 128 } else { 32 };
    IpPrefix::new(random_addr(rng, is_v6), rng.gen_range(0..=max_bits))
        .expect("generated prefix length is valid")
}

fn assert_routes(table: &Table<i32>, probes: &[&str], expected: &[i32]) {
    assert_eq!(probes.len(), expected.len());
    for (&probe, &want) in probes.iter().zip(expected) {
        let addr = probe.parse().expect("valid probe address");
        assert_eq!(
            table.get(addr).copied(),
            (want >= 0).then_some(want),
            "lookup {probe}"
        );
    }
}

#[test]
fn prefix_index_roundtrip() {
    for addr in 0_u16..256 {
        for bits in 0_u8..=8 {
            let byte = if bits == 0 {
                0
            } else {
                addr as u8 & (u8::MAX << (8 - bits))
            };
            let index = stride_table::prefix_index(byte, bits);
            let recovered_bits = (usize::BITS - 1 - index.leading_zeros()) as u8;
            let recovered_addr = if recovered_bits == 0 {
                0
            } else {
                ((index - (1 << recovered_bits)) as u8) << (8 - recovered_bits)
            };
            assert_eq!((recovered_addr, recovered_bits), (byte, bits));
            assert_eq!(
                stride_table::host_index(byte),
                stride_table::prefix_index(byte, 8)
            );
        }
    }
}

#[test]
fn upstream_compute_prefix_split_vectors() {
    let vectors = [
        ("192.168.1.0/24", "192.168.5.5/32", "192.168.0.0/16", 1, 5),
        (
            "192.168.129.0/24",
            "192.168.128.0/17",
            "192.168.0.0/16",
            129,
            128,
        ),
        ("192.168.5.0/24", "192.168.0.0/16", "192.0.0.0/8", 168, 168),
        ("192.168.0.0/16", "192.168.0.0/16", "192.0.0.0/8", 168, 168),
        (
            "ff:aaaa:aaaa::1/128",
            "ff:aaaa::/120",
            "ff:aaaa::/32",
            170,
            0,
        ),
    ];

    for (a, b, common, a_stride, b_stride) in vectors {
        assert_eq!(
            compute_prefix_split(prefix(a), prefix(b)),
            (prefix(common), a_stride, b_stride),
            "split {a} and {b}"
        );
    }
}

#[test]
fn upstream_insert_vectors_ipv4_and_ipv6() {
    let mut table = Table::new();
    let probes4 = [
        "192.168.0.1",
        "192.168.0.2",
        "192.168.0.3",
        "192.168.0.255",
        "192.168.1.1",
        "192.170.1.1",
        "192.180.0.1",
        "192.180.3.5",
        "10.0.0.5",
        "10.0.0.15",
    ];
    let operations4 = [
        ("192.168.0.1/32", 1, [1, -1, -1, -1, -1, -1, -1, -1, -1, -1]),
        ("192.168.0.2/32", 2, [1, 2, -1, -1, -1, -1, -1, -1, -1, -1]),
        ("192.168.0.0/26", 7, [1, 2, 7, -1, -1, -1, -1, -1, -1, -1]),
        ("10.0.0.0/27", 3, [1, 2, 7, -1, -1, -1, -1, -1, 3, 3]),
        ("192.168.1.1/32", 4, [1, 2, 7, -1, 4, -1, -1, -1, 3, 3]),
        ("192.170.0.0/16", 5, [1, 2, 7, -1, 4, 5, -1, -1, 3, 3]),
        ("192.180.0.1/32", 8, [1, 2, 7, -1, 4, 5, 8, -1, 3, 3]),
        ("192.180.0.0/21", 9, [1, 2, 7, -1, 4, 5, 8, 9, 3, 3]),
        ("123.45.67.89/0", 6, [1, 2, 7, 6, 4, 5, 8, 9, 3, 3]),
    ];
    for (route, value, expected) in operations4 {
        assert_eq!(table.insert(prefix(route), value), None);
        assert_routes(&table, &probes4, &expected);
    }

    let probes6 = [
        "ff:aaaa::1",
        "ff:aaaa::2",
        "ff:aaaa::3",
        "ff:aaaa::255",
        "ff:aaaa:aaaa::1",
        "ff:aaaa:aaaa:bbbb::1",
        "ff:cccc::1",
        "ff:cccc::ff",
        "ffff:bbbb::5",
        "ffff:bbbb::15",
    ];
    let operations6 = [
        ("ff:aaaa::1/128", 1, [1, -1, -1, -1, -1, -1, -1, -1, -1, -1]),
        ("ff:aaaa::2/128", 2, [1, 2, -1, -1, -1, -1, -1, -1, -1, -1]),
        ("ff:aaaa::/125", 7, [1, 2, 7, -1, -1, -1, -1, -1, -1, -1]),
        ("ffff:bbbb::/120", 3, [1, 2, 7, -1, -1, -1, -1, -1, 3, 3]),
        ("ff:aaaa:aaaa::1/128", 4, [1, 2, 7, -1, 4, -1, -1, -1, 3, 3]),
        (
            "ff:aaaa:aaaa:bb00::/56",
            5,
            [1, 2, 7, -1, 4, 5, -1, -1, 3, 3],
        ),
        ("ff:cccc::1/128", 8, [1, 2, 7, -1, 4, 5, 8, -1, 3, 3]),
        ("ff:cccc::/37", 9, [1, 2, 7, -1, 4, 5, 8, 9, 3, 3]),
        ("feed::1/0", 6, [1, 2, 7, 6, 4, 5, 8, 9, 3, 3]),
    ];
    for (route, value, expected) in operations6 {
        assert_eq!(table.insert(prefix(route), value), None);
        assert_routes(&table, &probes6, &expected);
    }
}

#[test]
fn replacement_exact_delete_and_boundaries() {
    let mut table = Table::new();
    assert!(table.is_empty());
    assert_eq!(table.insert(prefix("10.1.200.9/16"), 2), None);
    assert_eq!(table.insert(prefix("10.1.99.8/16"), 7), Some(2));
    assert_eq!(table.len(), 1);
    assert_eq!(table.get_prefix(prefix("10.1.255.255/16")), Some(&7));

    assert_eq!(table.insert(prefix("0.0.0.0/0"), 4), None);
    assert_eq!(table.insert(prefix("255.255.255.255/32"), 32), None);
    assert_eq!(table.insert(prefix("::/0"), 6), None);
    assert_eq!(
        table.insert(prefix("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"), 128),
        None
    );
    assert_eq!(table.get("255.255.255.255".parse().unwrap()), Some(&32));
    assert_eq!(table.get("255.255.255.254".parse().unwrap()), Some(&4));
    assert_eq!(
        table.get("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()),
        Some(&128)
    );
    assert_eq!(
        table.get("ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe".parse().unwrap()),
        Some(&6)
    );

    assert_eq!(table.delete(prefix("10.1.42.42/16")), Some(7));
    assert_eq!(table.delete(prefix("10.1.0.0/16")), None);
    assert_eq!(table.get("10.1.2.3".parse().unwrap()), Some(&4));
}

#[test]
fn mapped_ipv6_is_distinct_from_ipv4() {
    let mut table = Table::new();
    assert_eq!(table.insert(prefix("192.0.2.0/24"), "v4"), None);
    assert_eq!(
        table.insert(prefix("::ffff:192.0.2.0/120"), "mapped-v6"),
        None
    );
    assert_eq!(table.insert(prefix("0.0.0.0/0"), "default-v4"), None);
    assert_eq!(table.insert(prefix("::/0"), "default-v6"), None);

    assert_eq!(table.get("192.0.2.9".parse().unwrap()), Some(&"v4"));
    assert_eq!(
        table.get("::ffff:192.0.2.9".parse().unwrap()),
        Some(&"mapped-v6")
    );
    assert_eq!(
        table.get("198.51.100.9".parse().unwrap()),
        Some(&"default-v4")
    );
    assert_eq!(
        table.get("2001:db8::9".parse().unwrap()),
        Some(&"default-v6")
    );
}

#[test]
fn delete_compacts_compressed_paths() {
    let mut table = Table::new();
    assert_eq!(table.num_strides(), 2);
    assert_eq!(table.insert(prefix("192.168.0.1/32"), 1), None);
    assert_eq!(table.insert(prefix("192.180.0.1/32"), 2), None);
    assert_eq!(table.num_strides(), 5);

    assert_eq!(table.delete(prefix("192.180.0.1/32")), Some(2));
    assert_eq!(table.num_strides(), 3);
    assert_eq!(table.get("192.168.0.1".parse().unwrap()), Some(&1));
    assert_eq!(table.get("192.180.0.1".parse().unwrap()), None);

    assert_eq!(table.insert(prefix("192.168.0.0/22"), 3), None);
    assert_eq!(table.num_strides(), 4);
    assert_eq!(table.delete(prefix("192.168.0.0/22")), Some(3));
    assert_eq!(table.num_strides(), 3);
    assert_eq!(table.delete(prefix("192.168.0.1/32")), Some(1));
    assert_eq!(table.num_strides(), 2);

    // A compressed child can be deeper than a missing prefix. This must be a
    // miss rather than an unsigned prefix-length underflow.
    assert_eq!(table.insert(prefix("2001:db8:1:2::1/128"), 9), None);
    assert_eq!(table.delete(prefix("2001:db8::/32")), None);
}

#[test]
fn iteration_is_normalized_and_canonical() {
    let mut table = Table::new();
    for (route, value) in [
        ("2001:db8::/32", 5),
        ("192.168.1.99/24", 4),
        ("10.0.0.1/8", 2),
        ("192.168.0.0/16", 3),
        ("10.0.0.0/16", 1),
        ("::/0", 6),
        ("0.0.0.0/0", 0),
    ] {
        assert_eq!(table.insert(prefix(route), value), None);
    }

    let first: Vec<_> = table
        .iter()
        .map(|(route, value)| (route.to_string(), *value))
        .collect();
    let second: Vec<_> = table
        .iter()
        .map(|(route, value)| (route.to_string(), *value))
        .collect();
    assert_eq!(first, second);
    assert_eq!(
        first,
        [
            ("0.0.0.0/0".into(), 0),
            ("10.0.0.0/8".into(), 2),
            ("10.0.0.0/16".into(), 1),
            ("192.168.0.0/16".into(), 3),
            ("192.168.1.0/24".into(), 4),
            ("::/0".into(), 6),
            ("2001:db8::/32".into(), 5),
        ]
    );
}

#[test]
fn clone_and_snapshot_are_independent() {
    let mut original = Table::new();
    assert_eq!(
        original.insert(prefix("10.0.0.0/8"), String::from("original")),
        None
    );
    assert_eq!(
        original.insert(prefix("2001:db8::/32"), String::from("v6")),
        None
    );

    let mut cloned = original.clone();
    let snapshot = original.snapshot();
    assert_eq!(
        cloned.insert(prefix("10.0.0.0/8"), String::from("changed")),
        Some(String::from("original"))
    );
    assert_eq!(
        cloned.delete(prefix("2001:db8::/32")),
        Some(String::from("v6"))
    );
    assert_eq!(
        cloned.insert(prefix("192.0.2.0/24"), String::from("new")),
        None
    );

    for stable in [&original, &snapshot] {
        assert_eq!(
            stable.get("10.1.2.3".parse().unwrap()).map(String::as_str),
            Some("original")
        );
        assert_eq!(
            stable
                .get("2001:db8::1".parse().unwrap())
                .map(String::as_str),
            Some("v6")
        );
        assert_eq!(stable.get("192.0.2.1".parse().unwrap()), None);
    }
}

#[test]
fn route_value_storage_is_bounded_by_peak_live_routes() {
    let mut table = Table::new();
    let host = prefix("192.0.2.1/32");
    assert_eq!(table.insert(host, 0), None);
    for value in 1..10_000 {
        assert_eq!(table.insert(host, value), Some(value - 1));
    }
    assert_eq!(table.values.len(), 1);

    let routes: Vec<_> = (0..128)
        .map(|last| {
            IpPrefix::new(
                IpAddr::V4(u32::from_be_bytes([198, 51, 100, last]).into()),
                32,
            )
            .unwrap()
        })
        .collect();
    for (value, route) in routes.iter().copied().enumerate() {
        assert_eq!(table.insert(route, value), None);
    }
    let peak = table.len();
    for route in routes.iter().step_by(2) {
        assert!(table.delete(*route).is_some());
    }
    for (value, route) in routes.iter().step_by(2).copied().enumerate() {
        assert_eq!(table.insert(route, value), None);
    }
    assert_eq!(table.values.len(), peak);

    table.clear();
    assert!(table.is_empty());
    assert!(table.values.is_empty());
    assert_eq!(table.num_strides(), 2);
}

#[test]
fn randomized_mutations_match_reference_map() {
    let mut rng = StdRng::seed_from_u64(0xa47_d1ff_2026);
    let mut table = Table::new();
    let mut reference = BTreeMap::new();
    let mut peak_live = 0;

    for step in 0..8_000_usize {
        match rng.gen_range(0..100) {
            0..=54 => {
                let is_v6 = rng.gen();
                let route = random_prefix(&mut rng, is_v6).masked();
                let value = rng.gen();
                assert_eq!(table.insert(route, value), reference.insert(route, value));
            }
            55..=84 => {
                let route = if !reference.is_empty() && rng.gen_bool(0.8) {
                    *reference
                        .keys()
                        .nth(rng.gen_range(0..reference.len()))
                        .expect("chosen route exists")
                } else {
                    let is_v6 = rng.gen();
                    random_prefix(&mut rng, is_v6)
                };
                assert_eq!(table.delete(route), reference.remove(&route.masked()));
            }
            _ => {
                let is_v6 = rng.gen();
                let addr = random_addr(&mut rng, is_v6);
                assert_eq!(table.get(addr).copied(), naive_get(&reference, addr));
            }
        }
        peak_live = peak_live.max(reference.len());
        assert_eq!(table.len(), reference.len());
        assert!(table.values.len() <= peak_live);

        if step % 40 == 0 {
            for is_v6 in [false, true] {
                for _ in 0..8 {
                    let addr = random_addr(&mut rng, is_v6);
                    assert_eq!(
                        table.get(addr).copied(),
                        naive_get(&reference, addr),
                        "step={step}, addr={addr}"
                    );
                }
            }
            let actual: Vec<_> = table.iter().map(|(route, value)| (route, *value)).collect();
            let expected: Vec<_> = reference
                .iter()
                .map(|(&route, &value)| (route, value))
                .collect();
            assert_eq!(actual, expected, "iteration at step={step}");
        }
    }
}

#[test]
fn prefix_parsing_validates_family_lengths() {
    assert_eq!(prefix("192.0.2.99/24").masked().to_string(), "192.0.2.0/24");
    assert!(IpPrefix::parse("192.0.2.1/33").is_none());
    assert!(IpPrefix::parse("2001:db8::1/129").is_none());
    assert!(IpPrefix::parse("192.0.2.1").is_none());
}
