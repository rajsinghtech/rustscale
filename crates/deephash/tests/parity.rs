use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;

use proptest::collection::btree_map;
use proptest::prelude::*;
use rustscale_deephash::{hash, update, DeepHash, Hasher, Sum};
use rustscale_tailcfg::{
    ClientVersion, DERPMap, MapResponse, PingRequest, SSHPolicy, SSHRule, UserProfile,
};

fn structural_sum<T: DeepHash + ?Sized>(value: &T) -> Sum {
    let mut hasher = Hasher::new();
    value.deep_hash(&mut hasher);
    hasher.finalize()
}

#[test]
fn upstream_structural_vectors() {
    // These are SHA-256 sums of the byte streams asserted by upstream's
    // TestGetTypeHasher. The process seed and top-level Rust type tag used by
    // hash() are intentionally excluded.
    let cases = [
        (
            structural_sum(&1_i64),
            "7c9fa136d4413fa6173637e883b6998d32e1d675f88cddff9dcbcf331820f4b8",
        ),
        (
            structural_sum(&1.0_f64),
            "6c3c396ed6b5c36dcae172271f462051b1266b851e92df3deea8ac65478fd712",
        ),
        (
            structural_sum("foo"),
            "6139f36b7e4e7dadbd1391967339c7673629e4750c02b0545f8dbd6090cbff1e",
        ),
        (
            structural_sum(&["foo", "bar"][..]),
            "96ef2ac67567c334b0c0a79b0a286f986ca723ce1a2d5cd2fc58e44136b764e1",
        ),
        (
            structural_sum(&vec![1_u8, 2, 3, 4]),
            "a14f2d187b846b96d2f0e8998a1d704fc3c59bdd38da3639cced5e87f20ff16b",
        ),
        (
            structural_sum(&[1_u8, 2, 3, 4]),
            "9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a",
        ),
        (
            structural_sum(&Ipv4Addr::new(1, 2, 3, 4)),
            "1a340e8c7828b9421a2d8b54f746ae6e6d0702a32f37f6aa602392054a62f509",
        ),
        (
            structural_sum(&"fe80::123".parse::<Ipv6Addr>().unwrap()),
            "6a6d9bc8d68d9d38a0e409b96be53fc5bb57f8282dcfb63f3d5c784427b6b837",
        ),
    ];

    for (got, want) in cases {
        assert_eq!(got.to_string(), want);
    }
}

#[test]
fn option_slice_and_array_framing_are_distinct() {
    assert_ne!(
        structural_sum(&Option::<Vec<u8>>::None),
        structural_sum(&Some(Vec::<u8>::new()))
    );
    assert_ne!(hash(&Vec::<u8>::new()), hash(&vec![0_u8]));
    assert_ne!(hash(&vec![1_u8, 2, 3, 4]), hash(&[1_u8, 2, 3, 4]));
    assert_ne!(hash(&["a", "bc"]), hash(&["ab", "c"]));
}

#[test]
fn floats_hash_raw_bits() {
    assert_ne!(hash(&0.0_f32), hash(&-0.0_f32));
    assert_ne!(hash(&0.0_f64), hash(&-0.0_f64));

    let nan = f64::from_bits(0x7ff8_0000_0000_0042);
    let same_nan = f64::from_bits(0x7ff8_0000_0000_0042);
    let other_nan = f64::from_bits(0x7ff8_0000_0000_0043);
    assert_eq!(hash(&nan), hash(&same_nan));
    assert_ne!(hash(&nan), hash(&other_nan));
}

#[derive(Clone, Copy)]
enum ExampleEnum {
    Unit,
    Value(u16),
}

impl DeepHash for ExampleEnum {
    fn deep_hash(&self, hasher: &mut Hasher) {
        match self {
            Self::Unit => hasher.hash_uint8(0),
            Self::Value(value) => {
                hasher.hash_uint8(1);
                value.deep_hash(hasher);
            }
        }
    }
}

#[test]
fn enums_use_explicit_discriminants() {
    assert_ne!(hash(&ExampleEnum::Unit), hash(&ExampleEnum::Value(0)));
    assert_ne!(hash(&ExampleEnum::Value(0)), hash(&ExampleEnum::Value(1)));
}

#[test]
fn smart_pointer_addresses_do_not_affect_hashes() {
    let first = Box::new(String::from("same value"));
    let second = Box::new(String::from("same value"));
    assert_ne!(std::ptr::from_ref(&*first), std::ptr::from_ref(&*second));
    assert_eq!(hash(&first), hash(&second));

    let first = Arc::new(vec![1_u64, 2, 3]);
    let second = Arc::new(vec![1_u64, 2, 3]);
    assert!(!Arc::ptr_eq(&first, &second));
    assert_eq!(hash(&first), hash(&second));
}

#[test]
fn network_variants_and_fields_affect_hashes() {
    let v4 = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    let v6 = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
    assert_ne!(hash(&v4), hash(&v6));

    let scoped = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 1, 2));
    let other_scope = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 1, 3));
    assert_ne!(hash(&scoped), hash(&other_scope));
}

#[test]
fn map_and_set_order_is_irrelevant_but_content_is_not() {
    let first = HashMap::from([("one", 1_u64), ("two", 2)]);
    let second = HashMap::from([("two", 2_u64), ("one", 1)]);
    assert_eq!(hash(&first), hash(&second));

    let changed = HashMap::from([("one", 1_u64), ("two", 3)]);
    assert_ne!(hash(&first), hash(&changed));

    let first = HashSet::from(["one", "two"]);
    let second = HashSet::from(["two", "one"]);
    assert_eq!(hash(&first), hash(&second));
}

#[test]
fn all_map_response_change_fields_are_structural() {
    let baseline = MapResponse::default();

    let mut ping = baseline.clone();
    ping.PingRequest = Some(PingRequest {
        URL: "http://127.0.0.1/".into(),
        ..Default::default()
    });
    assert_ne!(hash(&baseline), hash(&ping));

    let mut derp = baseline.clone();
    derp.DERPMap = Some(DERPMap {
        OmitDefaultRegions: true,
        ..Default::default()
    });
    assert_ne!(hash(&baseline), hash(&derp));

    let mut profiles = baseline.clone();
    profiles.UserProfiles.push(UserProfile {
        ID: 1,
        LoginName: "user@example.com".into(),
        ..Default::default()
    });
    assert_ne!(hash(&baseline), hash(&profiles));

    let mut ssh = baseline.clone();
    ssh.SSHPolicy = Some(SSHPolicy {
        Rules: vec![SSHRule {
            AcceptEnv: vec!["LANG".into()],
            ..Default::default()
        }],
    });
    assert_ne!(hash(&baseline), hash(&ssh));

    let mut version = baseline.clone();
    version.ClientVersion = Some(ClientVersion {
        LatestVersion: "9.9.9".into(),
        ..Default::default()
    });
    assert_ne!(hash(&baseline), hash(&version));
}

proptest! {
    #[test]
    fn hash_map_insertion_order_does_not_matter(
        entries in btree_map(any::<u16>(), any::<Vec<u8>>(), 0..64)
    ) {
        let forward: HashMap<_, _> = entries.iter().map(|(k, v)| (*k, v.clone())).collect();
        let reverse: HashMap<_, _> = entries.iter().rev().map(|(k, v)| (*k, v.clone())).collect();
        prop_assert_eq!(hash(&forward), hash(&reverse));
    }

    #[test]
    fn map_update_detects_content_changes(
        entries in btree_map(any::<u16>(), any::<Vec<u8>>(), 0..64)
    ) {
        let mut map: BTreeMap<_, _> = entries;
        let mut last = Sum::default();
        prop_assert!(update(&mut last, &map));
        prop_assert!(!update(&mut last, &map));

        if let Some(value) = map.values_mut().next() {
            value.push(0x5a);
        } else {
            map.insert(0, vec![0x5a]);
        }
        prop_assert!(update(&mut last, &map));
        prop_assert!(!update(&mut last, &map));
    }
}
