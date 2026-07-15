//! Process-local structural SHA-256 hashes for inexpensive change detection.
//!
//! Values are hashed by logical content: maps and sets do not depend on
//! iteration order, and smart pointers are dereferenced rather than hashing
//! their addresses. [`Sum`] values are deliberately seeded per process and
//! include Rust type names, so they must not be persisted or sent on the wire.

#![forbid(unsafe_code)]

mod hash_impls;
mod hasher;
mod sum;

use std::any::type_name;
use std::sync::OnceLock;

pub use hasher::Hasher;
pub use sum::Sum;

/// Types that can write their logical structure into a [`Hasher`].
///
/// Implementations must write fields in a deterministic, stable order and
/// must frame variable-length data. Enums must hash an explicit discriminant
/// before variant data. Implementations for pointers hash the pointee, never
/// its address.
///
/// Unsupported types fail at compile time because they do not implement this
/// trait. Safe owning Rust values cannot normally contain a cycle; custom
/// implementations for interior-mutable cyclic graphs must detect cycles
/// themselves rather than recursively calling `deep_hash` without a bound.
pub trait DeepHash {
    /// Feed this value's logical representation to `hasher`.
    fn deep_hash(&self, hasher: &mut Hasher);
}

/// Hash `value` for change detection.
#[must_use]
pub fn hash<T: DeepHash + ?Sized + 'static>(value: &T) -> Sum {
    let mut hasher = Hasher::new();
    hasher.hash_uint64(*process_seed());
    let type_name = type_name::<T>();
    hasher.hash_uint64(type_name.len() as u64);
    hasher.hash_string(type_name);
    value.deep_hash(&mut hasher);
    hasher.finalize()
}

/// Replace `last` with the hash of `value` and report whether it changed.
pub fn update<T: DeepHash + ?Sized + 'static>(last: &mut Sum, value: &T) -> bool {
    let current = hash(value);
    let changed = *last != current;
    if changed {
        *last = current;
    }
    changed
}

fn process_seed() -> &'static u64 {
    static SEED: OnceLock<u64> = OnceLock::new();
    SEED.get_or_init(rand::random)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use rustscale_ipn::{MaskedPrefs, Prefs};
    use rustscale_tailcfg::{FilterRule, Node};

    use super::{hash, update, Sum};

    #[test]
    fn stability() {
        for value in [
            hash(&Node::default()),
            hash(&FilterRule::default()),
            hash(&Prefs::default()),
        ] {
            assert_eq!(value, value);
        }
        assert_eq!(hash(&Node::default()), hash(&Node::default()));
        assert_eq!(hash(&FilterRule::default()), hash(&FilterRule::default()));
        assert_eq!(hash(&Prefs::default()), hash(&Prefs::default()));
    }

    #[test]
    fn sensitivity() {
        let mut node = Node::default();
        let original = hash(&node);
        node.Name = "node.example.test.".into();
        assert_ne!(original, hash(&node));
        node.Endpoints.push("192.0.2.1:41641".into());
        assert_ne!(original, hash(&node));

        let mut rule = FilterRule::default();
        let original = hash(&rule);
        rule.SrcIPs.push("192.0.2.0/24".into());
        assert_ne!(original, hash(&rule));
        rule.IPProto.push(6);
        assert_ne!(original, hash(&rule));

        let mut prefs = Prefs::default();
        let original = hash(&prefs);
        prefs.WantRunning = true;
        assert_ne!(original, hash(&prefs));
        prefs.Hostname = "example".into();
        assert_ne!(original, hash(&prefs));
        prefs.AdvertiseRoutes.push("192.0.2.0/24".into());
        assert_ne!(original, hash(&prefs));
    }

    #[test]
    fn masked_prefs_mask_bits_affect_hash() {
        let cases: [(&str, fn(&mut MaskedPrefs)); 25] = [
            ("ControlURLSet", |p| p.ControlURLSet = true),
            ("WantRunningSet", |p| p.WantRunningSet = true),
            ("LoggedOutSet", |p| p.LoggedOutSet = true),
            ("RouteAllSet", |p| p.RouteAllSet = true),
            ("ExitNodeIDSet", |p| p.ExitNodeIDSet = true),
            ("ExitNodeIPSet", |p| p.ExitNodeIPSet = true),
            ("CorpDNSSet", |p| p.CorpDNSSet = true),
            ("ShieldsUpSet", |p| p.ShieldsUpSet = true),
            ("HostnameSet", |p| p.HostnameSet = true),
            ("AdvertiseRoutesSet", |p| p.AdvertiseRoutesSet = true),
            ("AdvertiseTagsSet", |p| p.AdvertiseTagsSet = true),
            ("OperatorUserSet", |p| p.OperatorUserSet = true),
            ("EphemeralSet", |p| p.EphemeralSet = true),
            ("AcceptRoutesSet", |p| p.AcceptRoutesSet = true),
            ("AdvertiseExitNodeSet", |p| p.AdvertiseExitNodeSet = true),
            ("ExitNodeAllowLANAccessSet", |p| {
                p.ExitNodeAllowLANAccessSet = true;
            }),
            ("AutoUpdateSet", |p| p.AutoUpdateSet = true),
            ("NetfilterModeSet", |p| p.NetfilterModeSet = true),
            ("NoSNATSet", |p| p.NoSNATSet = true),
            ("PostureCheckingSet", |p| p.PostureCheckingSet = true),
            ("AppConnectorSet", |p| p.AppConnectorSet = true),
            ("RunWebClientSet", |p| p.RunWebClientSet = true),
            ("RunSSHSet", |p| p.RunSSHSet = true),
            ("NoStatefulFilteringSet", |p| {
                p.NoStatefulFilteringSet = true;
            }),
            ("NoLogsNoSupportSet", |p| p.NoLogsNoSupportSet = true),
        ];
        let baseline = MaskedPrefs::default();
        for (name, toggle) in cases {
            let mut changed = MaskedPrefs::default();
            toggle(&mut changed);
            assert_ne!(hash(&baseline), hash(&changed), "mask bit {name}");
            assert_eq!(hash(&changed), hash(&changed), "mask bit {name}");
        }
    }

    #[test]
    fn nil_vs_empty() {
        assert_ne!(
            hash(&Option::<Vec<u8>>::None),
            hash(&Some(Vec::<u8>::new()))
        );
        assert_ne!(hash(&Option::<String>::None), hash(&Some(String::new())));
        assert_ne!(
            hash(&Option::<HashMap<String, u8>>::None),
            hash(&Some(HashMap::<String, u8>::new()))
        );
        assert_eq!(hash(&Vec::<u8>::new()), hash(&Vec::<u8>::new()));
    }

    #[test]
    fn map_order_independence() {
        let mut first = HashMap::new();
        first.insert("one", 1_u64);
        first.insert("two", 2_u64);
        let mut second = HashMap::new();
        second.insert("two", 2_u64);
        second.insert("one", 1_u64);
        assert_eq!(hash(&first), hash(&second));
    }

    #[test]
    fn bool_true_false() {
        assert_ne!(hash(&true), hash(&false));
    }

    #[test]
    fn float_zero() {
        assert_ne!(hash(&0.0_f64), hash(&-0.0_f64));
    }

    #[test]
    fn float_nan() {
        assert_eq!(hash(&f64::NAN), hash(&f64::NAN));
    }

    #[test]
    fn exhaustive_no_collision() {
        let mut sums = HashMap::new();
        for value in 0_u32..100_000 {
            assert!(
                sums.insert(hash(&value), value).is_none(),
                "collision at {value}"
            );
        }
    }

    #[test]
    fn update_reports_changes() {
        let mut last = Sum([0; 32]);
        assert!(update(&mut last, &"first"));
        assert!(!update(&mut last, &"first"));
        assert!(update(&mut last, &"second"));
    }
}
