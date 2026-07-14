//! The 8-bit stride table used by the Allotment Routing Table.

use std::marker::PhantomData;

use crate::IpPrefix;

pub(crate) const FIRST_HOST_INDEX: usize = 1 << 8;
const LAST_HOST_INDEX: usize = (1 << 9) - 1;
const ENTRY_COUNT: usize = LAST_HOST_INDEX + 1;
const CHILD_COUNT: usize = 256;

pub(crate) type RouteId = usize;

/// An 8-bit binary-tree routing table used as a node of [`crate::Table`].
///
/// A stride table is exported to make the ART implementation inspectable, but
/// route insertion and lookup are intentionally exposed through [`crate::Table`].
pub struct StrideTable<V> {
    pub(crate) prefix: IpPrefix,
    entries: [Option<RouteId>; ENTRY_COUNT],
    pub(crate) children: [Option<Box<Self>>; CHILD_COUNT],
    pub(crate) route_refs: u16,
    pub(crate) child_refs: u16,
    marker: PhantomData<fn() -> V>,
}

impl<V> StrideTable<V> {
    pub(crate) fn new(prefix: IpPrefix) -> Self {
        Self {
            prefix,
            entries: [None; ENTRY_COUNT],
            children: std::array::from_fn(|_| None),
            route_refs: 0,
            child_refs: 0,
            marker: PhantomData,
        }
    }

    pub(crate) fn get_or_create_child(&mut self, addr: u8) -> (&mut Self, bool) {
        let index = usize::from(addr);
        let created = self.children[index].is_none();
        if created {
            self.children[index] = Some(Box::new(Self::new(child_prefix_of(self.prefix, addr))));
            self.child_refs += 1;
        }
        (
            self.children[index]
                .as_deref_mut()
                .expect("child was just created"),
            created,
        )
    }

    pub(crate) fn set_child(&mut self, addr: u8, child: Box<Self>) {
        let index = usize::from(addr);
        if self.children[index].is_none() {
            self.child_refs += 1;
        }
        self.children[index] = Some(child);
    }

    pub(crate) fn delete_child(&mut self, addr: u8) {
        let child = &mut self.children[usize::from(addr)];
        if child.take().is_some() {
            self.child_refs -= 1;
        }
    }

    pub(crate) fn take_first_child(&mut self) -> Box<Self> {
        self.children
            .iter_mut()
            .find_map(Option::take)
            .expect("stride table with one child has a child")
    }

    pub(crate) fn insert(&mut self, addr: u8, prefix_len: u8, route: RouteId) -> Option<RouteId> {
        let index = prefix_index(addr, prefix_len);
        let previous = self
            .has_prefix_rooted_at(index)
            .then_some(self.entries[index])
            .flatten();
        if previous.is_none() {
            self.route_refs += 1;
        }
        let old = self.entries[index];
        self.allot(index, old, Some(route));
        previous
    }

    pub(crate) fn delete(&mut self, addr: u8, prefix_len: u8) -> Option<RouteId> {
        let index = prefix_index(addr, prefix_len);
        if !self.has_prefix_rooted_at(index) {
            return None;
        }
        let old = self.entries[index].expect("rooted prefix has a value");
        let parent = parent_index(index).and_then(|parent| self.entries[parent]);
        self.allot(index, Some(old), parent);
        self.route_refs -= 1;
        Some(old)
    }

    pub(crate) fn get_val_and_child(&self, addr: u8) -> (Option<RouteId>, Option<&Self>) {
        (
            self.entries[host_index(addr)],
            self.children[usize::from(addr)].as_deref(),
        )
    }

    pub(crate) fn num_strides(&self) -> usize {
        1 + self
            .children
            .iter()
            .flatten()
            .map(|child| child.num_strides())
            .sum::<usize>()
    }

    fn has_prefix_rooted_at(&self, index: usize) -> bool {
        let Some(value) = self.entries[index] else {
            return false;
        };
        parent_index(index).is_none_or(|parent| self.entries[parent] != Some(value))
    }

    fn allot(&mut self, index: usize, old: Option<RouteId>, new: Option<RouteId>) {
        if self.entries[index] != old {
            return;
        }
        self.entries[index] = new;
        if index >= FIRST_HOST_INDEX {
            return;
        }
        self.allot(index << 1, old, new);
        self.allot((index << 1) + 1, old, new);
    }
}

pub(crate) fn prefix_index(addr: u8, prefix_len: u8) -> usize {
    (usize::from(addr) >> (8 - prefix_len)) + (1 << prefix_len)
}

pub(crate) fn host_index(addr: u8) -> usize {
    usize::from(addr) + FIRST_HOST_INDEX
}

fn parent_index(index: usize) -> Option<usize> {
    if index == 1 {
        None
    } else {
        Some(index >> 1)
    }
}

fn child_prefix_of(parent: IpPrefix, stride: u8) -> IpPrefix {
    let bits = parent.bits();
    debug_assert_eq!(bits % 8, 0);
    let mut octets = parent.octets();
    octets[usize::from(bits / 8)] = stride;
    IpPrefix::from_octets(octets, parent.is_ipv6(), bits + 8)
}
