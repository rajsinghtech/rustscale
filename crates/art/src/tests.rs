use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rand::{rngs::StdRng, Rng, SeedableRng};

use crate::{stride_table, IpPrefix, Table};

#[derive(Clone)]
struct Route {
    prefix: IpPrefix,
    value: usize,
}

fn prefix(addr: IpAddr, bits: u8) -> IpPrefix {
    IpPrefix::new(addr, bits).expect("valid test prefix")
}

fn naive_get(routes: &[Route], addr: IpAddr) -> Option<usize> {
    routes
        .iter()
        .filter(|route| route.prefix.contains(addr))
        .max_by_key(|route| route.prefix.bits())
        .map(|route| route.value)
}

fn replace(routes: &mut Vec<Route>, prefix: IpPrefix, value: usize) {
    let prefix = prefix.masked();
    if let Some(route) = routes.iter_mut().find(|route| route.prefix == prefix) {
        route.value = value;
    } else {
        routes.push(Route { prefix, value });
    }
}

fn remove(routes: &mut Vec<Route>, prefix: IpPrefix) {
    let prefix = prefix.masked();
    routes.retain(|route| route.prefix != prefix);
}

fn random_addr(rng: &mut StdRng, is_v6: bool) -> IpAddr {
    if is_v6 {
        IpAddr::V6(Ipv6Addr::from(rng.gen::<u128>()))
    } else {
        IpAddr::V4(Ipv4Addr::from(rng.gen::<u32>()))
    }
}

fn random_prefix(rng: &mut StdRng, is_v6: bool) -> IpPrefix {
    let max_bits = if is_v6 { 128 } else { 32 };
    prefix(random_addr(rng, is_v6), rng.gen_range(0..=max_bits))
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
fn insert_delete_overwrite_and_default_route() {
    let mut table = Table::new();
    let default = prefix(IpAddr::V4(Ipv4Addr::new(123, 99, 8, 7)), 0);
    let default_v6 = prefix(IpAddr::V6(Ipv6Addr::from(0xfeed_u128)), 0);
    let subnet = prefix(IpAddr::V4(Ipv4Addr::new(10, 1, 200, 9)), 16);
    let host = prefix(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)), 32);

    table.insert(default, 1);
    table.insert(default_v6, 9);
    table.insert(subnet, 2);
    table.insert(host, 3);
    assert_eq!(table.get(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))), Some(&3));
    assert_eq!(
        table.lookup(IpAddr::V4(Ipv4Addr::new(10, 1, 9, 9))),
        Some(&2)
    );
    assert_eq!(table.get(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))), Some(&1));
    assert_eq!(table.get(IpAddr::V6(Ipv6Addr::LOCALHOST)), Some(&9));

    table.insert(host, 4);
    assert_eq!(table.get(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))), Some(&4));
    table.delete(host);
    assert_eq!(table.get(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))), Some(&2));
    table.delete(subnet);
    assert_eq!(table.get(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))), Some(&1));
    table.delete(default);
    table.delete(default_v6);
    assert_eq!(table.get(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))), None);
    assert_eq!(table.get(IpAddr::V6(Ipv6Addr::LOCALHOST)), None);
    assert_eq!(table.num_strides(), 2);
}

#[test]
fn regression_stride_boundary_prefixes() {
    let mut table = Table::new();
    table.insert(prefix(IpAddr::V4(Ipv4Addr::new(226, 205, 197, 0)), 24), 1);
    table.insert(prefix(IpAddr::V4(Ipv4Addr::new(226, 205, 0, 0)), 16), 2);
    assert_eq!(
        table.get(IpAddr::V4(Ipv4Addr::new(226, 205, 121, 152))),
        Some(&2)
    );

    let mut reverse = Table::new();
    reverse.insert(prefix(IpAddr::V4(Ipv4Addr::new(136, 20, 201, 62)), 32), 2);
    reverse.insert(prefix(IpAddr::V4(Ipv4Addr::new(136, 20, 0, 0)), 16), 1);
    assert_eq!(
        reverse.get(IpAddr::V4(Ipv4Addr::new(136, 20, 54, 139))),
        Some(&1)
    );
}

#[test]
fn random_lpm_matches_naive_for_ipv4_and_ipv6() {
    let mut rng = StdRng::seed_from_u64(0x5eed_1234);
    let mut table = Table::new();
    let mut routes = Vec::new();
    for value in 0..2_000 {
        let route = random_prefix(&mut rng, value % 2 == 0);
        table.insert(route, value);
        replace(&mut routes, route, value);
    }

    for _ in 0..5_000 {
        for is_v6 in [false, true] {
            let addr = random_addr(&mut rng, is_v6);
            assert_eq!(
                table.get(addr).copied(),
                naive_get(&routes, addr),
                "addr={addr}"
            );
        }
    }
}

#[test]
fn random_deletes_match_naive_for_ipv4_and_ipv6() {
    let mut rng = StdRng::seed_from_u64(0xd311_e7e5);
    let mut table = Table::new();
    let mut routes = Vec::new();
    let mut inserted = Vec::new();
    for value in 0..1_200 {
        let route = random_prefix(&mut rng, value % 2 == 0);
        table.insert(route, value);
        replace(&mut routes, route, value);
        inserted.push(route);
    }
    for route in inserted.iter().step_by(2) {
        table.delete(*route);
        remove(&mut routes, *route);
    }

    for _ in 0..3_000 {
        for is_v6 in [false, true] {
            let addr = random_addr(&mut rng, is_v6);
            assert_eq!(
                table.get(addr).copied(),
                naive_get(&routes, addr),
                "addr={addr}"
            );
        }
    }
}
