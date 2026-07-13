//! UDP/SCTP flow tracking LRU cache.
//!
//! Mirrors Go's `filterState` + `flowtrack.Cache` (size-based eviction,
//! no time-based timeout). Max 512 entries.

use std::net::{IpAddr, SocketAddr};

use rustscale_flowtrack::{Cache, Tuple};

/// A 5-tuple identifying a UDP/SCTP flow.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FlowTuple {
    pub proto: u8,
    pub src: IpAddr,
    pub src_port: u16,
    pub dst: IpAddr,
    pub dst_port: u16,
}

/// Build a reversed tuple: swap src and dst (addr + port), keep proto.
pub fn reversed_tuple(
    proto: u8,
    src: IpAddr,
    src_port: u16,
    dst: IpAddr,
    dst_port: u16,
) -> FlowTuple {
    FlowTuple {
        proto,
        src: dst,
        src_port: dst_port,
        dst: src,
        dst_port: src_port,
    }
}

/// Size-based LRU cache for flow state. Max 512 entries.
pub struct FlowState {
    cache: Cache<()>,
}

impl FlowState {
    pub fn new() -> Self {
        let mut cache = Cache::default();
        // Go's wgengine/filter uses `lruMax = 512`.
        cache.max_entries = 512;
        Self { cache }
    }

    /// Look up `tuple`; if found, make it most recently used.
    pub fn get(&mut self, tuple: &FlowTuple) -> bool {
        self.cache.get(&tuple.as_tuple()).is_some()
    }

    /// Insert `tuple`; evict the least recently used entry if over capacity.
    pub fn add(&mut self, tuple: FlowTuple) {
        self.cache.add(tuple.as_tuple(), ());
    }

    /// Current number of cached flows.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cache.len() == 0
    }
}

impl FlowTuple {
    fn as_tuple(&self) -> Tuple {
        Tuple::new(
            self.proto,
            SocketAddr::new(self.src, self.src_port),
            SocketAddr::new(self.dst, self.dst_port),
        )
    }
}

impl Default for FlowState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn lru_eviction() {
        let mut s = FlowState::new();
        for i in 0..600u16 {
            s.add(FlowTuple {
                proto: 17,
                src: IpAddr::V4(Ipv4Addr::new(1, (i / 256) as u8, (i % 256) as u8, 1)),
                src_port: 1,
                dst: IpAddr::V4(Ipv4Addr::new(2, 0, 0, 0)),
                dst_port: 1,
            });
        }
        assert_eq!(s.len(), 512);
    }

    #[test]
    fn reversed_tuple_swaps() {
        let t = reversed_tuple(
            17,
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            1000,
            IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            80,
        );
        assert_eq!(t.src, IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)));
        assert_eq!(t.src_port, 80);
        assert_eq!(t.dst, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(t.dst_port, 1000);
    }
}
