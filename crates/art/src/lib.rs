//! A fast IPv4 and IPv6 longest-prefix-match routing table.
//!
//! This crate ports Tailscale's Go implementation of the Allotment Routing
//! Table (ART). Each node is an 8-bit stride table whose flattened binary tree
//! stores the matching route directly at every host entry, making the work
//! within a stride constant-time.

#![forbid(unsafe_code)]

mod stride_table;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use stride_table::RouteId;

pub use stride_table::StrideTable;

/// An IP network prefix.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct IpPrefix {
    addr: IpAddr,
    bits: u8,
}

impl IpPrefix {
    /// Creates a prefix when `bits` is valid for the address family.
    #[must_use]
    pub fn new(addr: IpAddr, bits: u8) -> Option<Self> {
        if bits <= bit_len(addr) {
            Some(Self { addr, bits })
        } else {
            None
        }
    }

    /// Returns the prefix address as originally supplied.
    #[must_use]
    pub const fn addr(self) -> IpAddr {
        self.addr
    }

    /// Returns the number of significant leading bits.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.bits
    }

    /// Returns this prefix with all host bits cleared.
    #[must_use]
    pub fn masked(self) -> Self {
        let mut octets = self.octets();
        let byte_len = usize::from(bit_len(self.addr) / 8);
        let full_bytes = usize::from(self.bits / 8);
        let partial_bits = self.bits % 8;
        if full_bytes < byte_len {
            if partial_bits != 0 {
                octets[full_bytes] &= u8::MAX << (8 - partial_bits);
                octets[(full_bytes + 1)..byte_len].fill(0);
            } else {
                octets[full_bytes..byte_len].fill(0);
            }
        }
        Self::from_octets(octets, self.is_ipv6(), self.bits)
    }

    /// Reports whether this prefix contains `addr`.
    #[must_use]
    pub fn contains(self, addr: IpAddr) -> bool {
        if self.addr.is_ipv6() != addr.is_ipv6() {
            return false;
        }
        let normalized = self.masked();
        let candidate = IpPrefix {
            addr,
            bits: bit_len(addr),
        };
        common_bits(normalized, candidate, self.bits) == self.bits
    }

    pub(crate) const fn is_ipv6(self) -> bool {
        self.addr.is_ipv6()
    }

    pub(crate) fn octets(self) -> [u8; 16] {
        match self.addr {
            IpAddr::V4(addr) => {
                let mut octets = [0; 16];
                octets[..4].copy_from_slice(&addr.octets());
                octets
            }
            IpAddr::V6(addr) => addr.octets(),
        }
    }

    pub(crate) fn byte_at(self, index: usize) -> u8 {
        self.octets()[index]
    }

    pub(crate) fn from_octets(octets: [u8; 16], is_ipv6: bool, bits: u8) -> Self {
        let addr = if is_ipv6 {
            IpAddr::V6(Ipv6Addr::from(octets))
        } else {
            IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
        };
        Self { addr, bits }
    }
}

/// Compatibility alias for [`IpPrefix`].
pub type Prefix = IpPrefix;

/// An Allotment Routing Table supporting IPv4 and IPv6 longest-prefix-match
/// lookups.
pub struct Table<V> {
    v4: StrideTable<V>,
    v6: StrideTable<V>,
    values: Vec<Option<Box<V>>>,
}

impl<V> Default for Table<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V> Table<V> {
    /// Creates an empty routing table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            v4: StrideTable::new(
                IpPrefix::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).expect("valid IPv4 default"),
            ),
            v6: StrideTable::new(
                IpPrefix::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0).expect("valid IPv6 default"),
            ),
            values: Vec::new(),
        }
    }

    /// Inserts `prefix -> value`, replacing the value of an existing prefix.
    ///
    /// Host bits in `prefix` are ignored.
    pub fn insert(&mut self, prefix: IpPrefix, value: V) {
        let prefix = prefix.masked();
        let route = self.allocate(value);
        let replaced = if prefix.is_ipv6() {
            Self::insert_into(&mut self.v6, prefix, route)
        } else {
            Self::insert_into(&mut self.v4, prefix, route)
        };
        if let Some(route) = replaced {
            self.values[route] = None;
        }
    }

    /// Returns the value associated with the most-specific prefix containing
    /// `addr`, or `None` when no prefix matches.
    #[must_use]
    pub fn get(&self, addr: IpAddr) -> Option<&V> {
        let root = if addr.is_ipv6() { &self.v6 } else { &self.v4 };
        let mut stride = root;
        let mut byte_index = 0;
        let mut matches = Vec::with_capacity(16);

        loop {
            let (route, child) = stride.get_val_and_child(addr_byte_at(addr, byte_index));
            if let Some(route) = route {
                matches.push((stride.prefix, route));
            }
            let Some(child) = child else {
                break;
            };
            stride = child;
            byte_index = usize::from(stride.prefix.bits() / 8);
        }

        matches.into_iter().rev().find_map(|(prefix, route)| {
            prefix
                .contains(addr)
                .then(|| self.values[route].as_deref().expect("live route entry"))
        })
    }

    /// Alias for [`Self::get`].
    #[must_use]
    pub fn lookup(&self, addr: IpAddr) -> Option<&V> {
        self.get(addr)
    }

    /// Removes `prefix`, if it exists. Host bits in `prefix` are ignored.
    pub fn delete(&mut self, prefix: IpPrefix) {
        let prefix = prefix.masked();
        let removed = if prefix.is_ipv6() {
            Self::delete_from(&mut self.v6, prefix)
        } else {
            Self::delete_from(&mut self.v4, prefix)
        };
        if let Some(route) = removed {
            self.values[route] = None;
        }
    }

    /// Returns the number of allocated stride tables across both families.
    #[must_use]
    pub fn num_strides(&self) -> usize {
        self.v4.num_strides() + self.v6.num_strides()
    }

    fn allocate(&mut self, value: V) -> RouteId {
        self.values.push(Some(Box::new(value)));
        self.values.len() - 1
    }

    fn insert_into(
        stride: &mut StrideTable<V>,
        prefix: IpPrefix,
        route: RouteId,
    ) -> Option<RouteId> {
        if prefix.bits() == 0 {
            return stride.insert(0, 0, route);
        }

        let final_byte = (prefix.bits() - 1) / 8;
        let final_bits = prefix.bits() - (final_byte * 8);
        let final_stride_prefix = prefix_at_byte_boundary(prefix, final_byte * 8);
        let mut byte_index = 0_u8;
        let mut bits_remaining = prefix.bits();
        let mut current: &mut StrideTable<V> = &mut *stride;

        loop {
            if bits_remaining <= 8 {
                return current.insert(prefix.byte_at(usize::from(final_byte)), final_bits, route);
            }

            let addr = prefix.byte_at(usize::from(byte_index));
            let child_exists = current.children[usize::from(addr)].is_some();
            if !child_exists {
                let (child, created) = current.get_or_create_child(addr);
                debug_assert!(created);
                child.prefix = final_stride_prefix;
                return child.insert(prefix.byte_at(usize::from(final_byte)), final_bits, route);
            }
            let child_prefix = current.children[usize::from(addr)]
                .as_deref()
                .expect("existing child")
                .prefix;
            if !prefix_strictly_contains(child_prefix, prefix) {
                let (intermediate_prefix, existing_stride, new_stride) =
                    compute_prefix_split(child_prefix, prefix);
                let old_child = current.children[usize::from(addr)]
                    .take()
                    .expect("existing child");
                let mut intermediate = Box::new(StrideTable::new(intermediate_prefix));
                intermediate.set_child(existing_stride, old_child);

                let result = if prefix.bits() - intermediate.prefix.bits() <= 8 {
                    intermediate.insert(prefix.byte_at(usize::from(final_byte)), final_bits, route)
                } else {
                    let (new_child, was_created) = intermediate.get_or_create_child(new_stride);
                    debug_assert!(was_created);
                    new_child.prefix = final_stride_prefix;
                    new_child.insert(prefix.byte_at(usize::from(final_byte)), final_bits, route)
                };
                current.children[usize::from(addr)] = Some(intermediate);
                return result;
            }

            let child = current.children[usize::from(addr)]
                .as_deref_mut()
                .expect("existing child");
            byte_index = child.prefix.bits() / 8;
            bits_remaining = prefix.bits() - child.prefix.bits();
            current = child;
        }
    }

    fn delete_from(stride: &mut StrideTable<V>, prefix: IpPrefix) -> Option<RouteId> {
        if prefix.bits() == 0 {
            return stride.delete(0, 0);
        }

        let mut path = Vec::with_capacity(16);
        let mut byte_index = 0_u8;
        let mut bits_remaining = prefix.bits();
        let mut current: &mut StrideTable<V> = &mut *stride;
        while bits_remaining > 8 {
            let addr = prefix.byte_at(usize::from(byte_index));
            let child = current.children[usize::from(addr)].as_deref_mut()?;
            path.push(addr);
            byte_index = child.prefix.bits() / 8;
            bits_remaining = prefix.bits() - child.prefix.bits();
            current = child;
        }

        if !prefix_strictly_contains(current.prefix, prefix) {
            return None;
        }
        let removed = current.delete(prefix.byte_at(usize::from(byte_index)), bits_remaining)?;
        Self::clean_empty_strides(stride, &path);
        Some(removed)
    }

    fn clean_empty_strides(stride: &mut StrideTable<V>, path: &[u8]) {
        let Some((&addr, rest)) = path.split_first() else {
            return;
        };
        let child = stride.children[usize::from(addr)]
            .as_deref_mut()
            .expect("recorded path exists");
        Self::clean_empty_strides(child, rest);

        let child = stride.children[usize::from(addr)]
            .as_deref_mut()
            .expect("recorded path exists");
        if child.route_refs != 0 || child.child_refs > 1 {
            return;
        }
        if child.child_refs == 0 {
            stride.delete_child(addr);
        } else {
            let replacement = stride.children[usize::from(addr)]
                .as_deref_mut()
                .expect("child exists")
                .take_first_child();
            stride.set_child(addr, replacement);
        }
    }
}

fn bit_len(addr: IpAddr) -> u8 {
    if addr.is_ipv6() {
        128
    } else {
        32
    }
}

fn addr_byte_at(addr: IpAddr, index: usize) -> u8 {
    match addr {
        IpAddr::V4(addr) => addr.octets()[index],
        IpAddr::V6(addr) => addr.octets()[index],
    }
}

fn prefix_at_byte_boundary(prefix: IpPrefix, bits: u8) -> IpPrefix {
    IpPrefix::from_octets(prefix.masked().octets(), prefix.is_ipv6(), bits)
}

fn prefix_strictly_contains(parent: IpPrefix, child: IpPrefix) -> bool {
    parent.bits() < child.bits() && parent.contains(child.addr())
}

fn compute_prefix_split(a: IpPrefix, b: IpPrefix) -> (IpPrefix, u8, u8) {
    debug_assert_ne!(a.bits(), 0);
    debug_assert_ne!(b.bits(), 0);
    debug_assert_eq!(a.is_ipv6(), b.is_ipv6());
    let min_bits = a.bits().min(b.bits());
    let mut shared = common_bits(a.masked(), b.masked(), min_bits);
    if shared == min_bits {
        shared -= 1;
    }
    let common_strides = shared / 8;
    (
        prefix_at_byte_boundary(a, common_strides * 8),
        a.byte_at(usize::from(common_strides)),
        b.byte_at(usize::from(common_strides)),
    )
}

fn common_bits(a: IpPrefix, b: IpPrefix, max_bits: u8) -> u8 {
    debug_assert_eq!(a.is_ipv6(), b.is_ipv6());
    let a = a.octets();
    let b = b.octets();
    let length = usize::from(max_bits.div_ceil(8));
    let mut shared = 0_u8;
    for index in 0..length {
        let different = a[index] ^ b[index];
        if different == 0 {
            shared += 8;
        } else {
            shared += different.leading_zeros() as u8;
            break;
        }
    }
    shared.min(max_bits)
}

#[cfg(test)]
mod tests;
