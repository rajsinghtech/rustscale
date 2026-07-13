//! IP flow tuples and an LRU cache for tracking them.
//!
//! Ports Tailscale's `net/flowtrack`. The cache is deliberately not safe for
//! concurrent access; callers that share one must synchronize access.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A packed IP protocol, source address/port, and destination address/port.
///
/// IPv4 addresses are stored as IPv4-mapped IPv6 addresses so each address
/// occupies 16 bytes. The address accessors return mapped addresses as IPv4.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Tuple {
    src: [u8; 16],
    dst: [u8; 16],
    src_port: u16,
    dst_port: u16,
    proto: u8,
}

impl Tuple {
    /// Builds a tuple from protocol and source/destination socket addresses.
    #[must_use]
    pub fn new(proto: u8, src: SocketAddr, dst: SocketAddr) -> Self {
        Self {
            src: mapped_octets(src.ip()),
            dst: mapped_octets(dst.ip()),
            src_port: src.port(),
            dst_port: dst.port(),
            proto,
        }
    }

    /// Returns the source IP address, unmapping an IPv4-mapped IPv6 address.
    #[must_use]
    pub fn src_addr(self) -> IpAddr {
        unmapped_addr(self.src)
    }

    /// Returns the destination IP address, unmapping an IPv4-mapped IPv6 address.
    #[must_use]
    pub fn dst_addr(self) -> IpAddr {
        unmapped_addr(self.dst)
    }

    /// Returns the source port.
    #[must_use]
    pub const fn src_port(self) -> u16 {
        self.src_port
    }

    /// Returns the destination port.
    #[must_use]
    pub const fn dst_port(self) -> u16 {
        self.dst_port
    }

    /// Returns the IP protocol number.
    #[must_use]
    pub const fn proto(self) -> u8 {
        self.proto
    }
}

impl fmt::Display for Tuple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "({} {} => {})",
            display_proto(self.proto),
            SocketAddr::new(self.src_addr(), self.src_port),
            SocketAddr::new(self.dst_addr(), self.dst_port)
        )
    }
}

/// The legacy JSON representation retained for Go wire compatibility.
#[derive(Serialize)]
struct TupleOld<'a> {
    proto: u8,
    src: &'a str,
    dst: &'a str,
}

impl Serialize for Tuple {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let src = SocketAddr::new(self.src_addr(), self.src_port).to_string();
        let dst = SocketAddr::new(self.dst_addr(), self.dst_port).to_string();
        TupleOld {
            proto: self.proto,
            src: &src,
            dst: &dst,
        }
        .serialize(serializer)
    }
}

/// The legacy JSON representation retained for Go wire compatibility.
#[derive(Deserialize)]
struct TupleOldOwned {
    proto: u8,
    src: String,
    dst: String,
}

impl<'de> Deserialize<'de> for Tuple {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let old = TupleOldOwned::deserialize(deserializer)?;
        let src = old.src.parse().map_err(D::Error::custom)?;
        let dst = old.dst.parse().map_err(D::Error::custom)?;
        Ok(Self::new(old.proto, src, dst))
    }
}

fn mapped_octets(addr: IpAddr) -> [u8; 16] {
    match addr {
        IpAddr::V4(addr) => addr.to_ipv6_mapped().octets(),
        IpAddr::V6(addr) => addr.octets(),
    }
}

fn unmapped_addr(octets: [u8; 16]) -> IpAddr {
    let addr = Ipv6Addr::from(octets);
    match addr.to_ipv4_mapped() {
        Some(addr) => IpAddr::V4(addr),
        None => IpAddr::V6(addr),
    }
}

fn display_proto(proto: u8) -> String {
    match proto {
        0 => "Unknown".to_owned(),
        1 => "ICMPv4".to_owned(),
        2 => "IGMP".to_owned(),
        6 => "TCP".to_owned(),
        17 => "UDP".to_owned(),
        33 => "DCCP".to_owned(),
        47 => "GRE".to_owned(),
        58 => "ICMPv6".to_owned(),
        99 => "TSMP".to_owned(),
        132 => "SCTP".to_owned(),
        255 => "Frag".to_owned(),
        _ => format!("IPProto-{proto}"),
    }
}

/// An LRU cache keyed by [`Tuple`].
///
/// `max_entries` is the maximum number of retained entries; zero means no
/// limit. The zero value is ready to use. This type is not thread-safe.
pub struct Cache<V> {
    /// Maximum entries retained by the cache; zero means unlimited.
    pub max_entries: usize,
    entries: HashMap<Tuple, usize>,
    nodes: Vec<Option<Node<V>>>,
    free: Vec<usize>,
    front: Option<usize>,
    back: Option<usize>,
}

struct Node<V> {
    key: Tuple,
    value: V,
    prev: Option<usize>,
    next: Option<usize>,
}

impl<V> Cache<V> {
    /// Adds or updates a value, making its key most recently used.
    pub fn add(&mut self, key: Tuple, value: V) {
        if let Some(&index) = self.entries.get(&key) {
            self.nodes[index]
                .as_mut()
                .expect("cache index must be valid")
                .value = value;
            self.move_to_front(index);
            return;
        }

        let index = self.allocate_node(key, value);
        self.entries.insert(key, index);
        self.push_front(index);
        if self.max_entries != 0 && self.len() > self.max_entries {
            self.remove_oldest();
        }
    }

    /// Gets a value and makes its key most recently used.
    pub fn get(&mut self, key: &Tuple) -> Option<&V> {
        let index = *self.entries.get(key)?;
        self.move_to_front(index);
        Some(
            &self.nodes[index]
                .as_ref()
                .expect("cache index must be valid")
                .value,
        )
    }

    /// Gets a mutable value and makes its key most recently used.
    pub fn get_mut(&mut self, key: &Tuple) -> Option<&mut V> {
        let index = *self.entries.get(key)?;
        self.move_to_front(index);
        Some(
            &mut self.nodes[index]
                .as_mut()
                .expect("cache index must be valid")
                .value,
        )
    }

    /// Removes a key if it is present.
    pub fn remove(&mut self, key: &Tuple) {
        if let Some(index) = self.entries.get(key).copied() {
            self.remove_index(index);
        }
    }

    /// Removes the least recently used entry, if any.
    pub fn remove_oldest(&mut self) {
        if let Some(index) = self.back {
            self.remove_index(index);
        }
    }

    /// Returns the number of entries currently retained.
    #[must_use]
    #[allow(clippy::len_without_is_empty)] // Match the Go cache API exactly.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    fn allocate_node(&mut self, key: Tuple, value: V) -> usize {
        let node = Node {
            key,
            value,
            prev: None,
            next: None,
        };
        if let Some(index) = self.free.pop() {
            self.nodes[index] = Some(node);
            index
        } else {
            self.nodes.push(Some(node));
            self.nodes.len() - 1
        }
    }

    fn move_to_front(&mut self, index: usize) {
        if self.front == Some(index) {
            return;
        }
        self.unlink(index);
        self.push_front(index);
    }

    fn push_front(&mut self, index: usize) {
        let old_front = self.front;
        {
            let node = self.nodes[index]
                .as_mut()
                .expect("cache index must be valid");
            node.prev = None;
            node.next = old_front;
        }
        if let Some(old_front) = old_front {
            self.nodes[old_front]
                .as_mut()
                .expect("cache index must be valid")
                .prev = Some(index);
        } else {
            self.back = Some(index);
        }
        self.front = Some(index);
    }

    fn unlink(&mut self, index: usize) {
        let (prev, next) = {
            let node = self.nodes[index]
                .as_ref()
                .expect("cache index must be valid");
            (node.prev, node.next)
        };
        if let Some(prev) = prev {
            self.nodes[prev]
                .as_mut()
                .expect("cache index must be valid")
                .next = next;
        } else {
            self.front = next;
        }
        if let Some(next) = next {
            self.nodes[next]
                .as_mut()
                .expect("cache index must be valid")
                .prev = prev;
        } else {
            self.back = prev;
        }
    }

    fn remove_index(&mut self, index: usize) {
        let key = self.nodes[index]
            .as_ref()
            .expect("cache index must be valid")
            .key;
        self.unlink(index);
        self.entries.remove(&key);
        self.nodes[index] = None;
        self.free.push(index);
    }
}

impl<V> Default for Cache<V> {
    fn default() -> Self {
        Self {
            max_entries: 0,
            entries: HashMap::new(),
            nodes: Vec::new(),
            free: Vec::new(),
            front: None,
            back: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn tuple(dst: &str) -> Tuple {
        Tuple::new(0, "1.1.1.1:1".parse().unwrap(), dst.parse().unwrap())
    }

    #[test]
    fn cache_add_get_evict_and_update() {
        let mut cache = Cache {
            max_entries: 2,
            ..Cache::default()
        };
        let k1 = tuple("1.1.1.1:1");
        let k2 = tuple("2.2.2.2:2");
        let k3 = tuple("3.3.3.3:3");
        let k4 = tuple("4.4.4.4:4");

        cache.remove_oldest();
        cache.remove(&k4);
        cache.add(k1, 1);
        cache.add(k2, 2);
        cache.add(k3, 3);
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get(&k1), None);
        assert_eq!(cache.get(&k3), Some(&3));
        assert_eq!(cache.get(&k2), Some(&2));
        cache.remove(&k2);
        assert_eq!(cache.len(), 1);
        cache.add(k3, 30);
        assert_eq!(cache.get(&k3), Some(&30));
    }

    #[test]
    fn cache_hit_and_update_move_to_front() {
        let mut cache = Cache {
            max_entries: 2,
            ..Cache::default()
        };
        let k1 = tuple("1.1.1.1:1");
        let k2 = tuple("2.2.2.2:2");
        let k3 = tuple("3.3.3.3:3");
        cache.add(k1, 1);
        cache.add(k2, 2);
        assert_eq!(cache.get(&k1), Some(&1));
        cache.add(k3, 3);
        assert_eq!(cache.get(&k1), Some(&1));
        assert_eq!(cache.get(&k2), None);
        cache.add(k1, 10);
        cache.add(k2, 2);
        assert_eq!(cache.get(&k1), Some(&10));
        assert_eq!(cache.get(&k3), None);
    }

    #[test]
    fn cache_mutable_hit_moves_to_front() {
        let mut cache = Cache {
            max_entries: 2,
            ..Cache::default()
        };
        let k1 = tuple("1.1.1.1:1");
        let k2 = tuple("2.2.2.2:2");
        let k3 = tuple("3.3.3.3:3");
        cache.add(k1, 1);
        cache.add(k2, 2);
        *cache.get_mut(&k1).unwrap() = 10;
        cache.add(k3, 3);
        assert_eq!(cache.get(&k1), Some(&10));
        assert_eq!(cache.get(&k2), None);
    }

    #[test]
    fn tuple_v4_storage_is_mapped_and_accessors_unmap() {
        let tuple = Tuple::new(
            17,
            "1.2.3.4:5".parse().unwrap(),
            "[2001:db8::1]:6".parse().unwrap(),
        );
        assert_eq!(tuple.src_addr(), IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(tuple.dst_addr(), "2001:db8::1".parse::<IpAddr>().unwrap());
        assert_eq!(tuple.src_port(), 5);
        assert_eq!(tuple.dst_port(), 6);
        assert_eq!(
            tuple,
            Tuple::new(
                17,
                "[::ffff:1.2.3.4]:5".parse().unwrap(),
                "[2001:db8::1]:6".parse().unwrap(),
            )
        );
    }

    #[test]
    fn tuple_display_and_old_json_round_trip() {
        let tuple = Tuple::new(
            123,
            "1.2.3.4:5".parse().unwrap(),
            "6.7.8.9:10".parse().unwrap(),
        );
        assert_eq!(tuple.to_string(), "(IPProto-123 1.2.3.4:5 => 6.7.8.9:10)");
        let json = serde_json::to_string(&tuple).unwrap();
        assert_eq!(
            json,
            r#"{"proto":123,"src":"1.2.3.4:5","dst":"6.7.8.9:10"}"#
        );
        assert_eq!(serde_json::from_str::<Tuple>(&json).unwrap(), tuple);
    }

    #[test]
    fn tuple_json_uses_bracketed_ipv6_address_ports() {
        let tuple = Tuple::new(
            17,
            "[::1]:80".parse().unwrap(),
            "[2001:db8::1]:443".parse().unwrap(),
        );
        assert_eq!(
            serde_json::to_string(&tuple).unwrap(),
            r#"{"proto":17,"src":"[::1]:80","dst":"[2001:db8::1]:443"}"#
        );
    }
}
