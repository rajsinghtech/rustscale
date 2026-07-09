//! Per-peer endpoint state machine: candidate paths, trust-on-pong, ranking.
//!
//! Ports the semantics of Go's `wgengine/magicsock/endpoint.go` in simplified
//! form. Each peer has a set of candidate UDP endpoints (from the netmap), a
//! best confirmed direct path with a trust expiry, an optional peer-relay path,
//! and a DERP fallback (the peer's home region).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// How long to trust a direct path after receiving a pong (simplified from
/// Go's variable trust windows; the task specifies ~15s).
pub const TRUST_BEST_ADDR_DURATION: Duration = Duration::from_secs(15);

/// Path class ranking — lower ordinal = better.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum PathClass {
    /// No usable path.
    #[default]
    None,
    /// DERP relay fallback.
    Derp,
    /// Peer relay (UDP relay) path.
    Relay,
    /// Direct UDP path confirmed by pong.
    Direct,
}

/// The current best transport path for a peer, evaluated at a point in time.
#[derive(Debug, Clone, Default)]
pub enum BestPath {
    /// No known working path.
    #[default]
    None,
    /// DERP relay via the given region.
    Derp { region: i32 },
    /// Direct UDP path, trusted until `trusted_until`.
    Direct {
        addr: SocketAddr,
        trusted_until: Instant,
    },
    /// Peer relay path via a UDP relay server.
    Relay { addr: SocketAddr, vni: u32 },
}

impl BestPath {
    /// The ranking class of this path.
    pub fn class(&self) -> PathClass {
        match self {
            Self::None => PathClass::None,
            Self::Derp { .. } => PathClass::Derp,
            Self::Relay { .. } => PathClass::Relay,
            Self::Direct { .. } => PathClass::Direct,
        }
    }

    /// The destination address, if applicable (direct or relay).
    pub fn addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Direct { addr, .. } | Self::Relay { addr, .. } => Some(*addr),
            _ => None,
        }
    }
}

/// Per-peer endpoint state.
pub struct Endpoint {
    peer_node_key: rustscale_key::NodePublic,
    peer_disco_key: rustscale_key::DiscoPublic,
    candidates: Vec<SocketAddr>,
    best_addr: Option<(SocketAddr, Instant)>,
    relay: Option<(SocketAddr, u32)>,
    home_derp: i32,
    /// The DERP region from which the most recent packet from this peer
    /// arrived. Used for reply routing when HomeDERP is 0 or stale.
    /// Mirrors Go's `derpRoute` / `setDerpRoute` caching.
    last_recv_derp_region: i32,
    pending_pings: HashMap<[u8; 12], (Instant, SocketAddr)>,
    call_me_maybe_sent: bool,
}

impl Endpoint {
    /// Create a new endpoint for a peer.
    pub fn new(
        peer_node_key: rustscale_key::NodePublic,
        peer_disco_key: rustscale_key::DiscoPublic,
        home_derp: i32,
    ) -> Self {
        Self {
            peer_node_key,
            peer_disco_key,
            candidates: Vec::new(),
            best_addr: None,
            relay: None,
            home_derp,
            last_recv_derp_region: 0,
            pending_pings: HashMap::new(),
            call_me_maybe_sent: false,
        }
    }

    /// The peer's WireGuard public key.
    pub fn peer_node_key(&self) -> &rustscale_key::NodePublic {
        &self.peer_node_key
    }

    /// The peer's disco public key.
    pub fn peer_disco_key(&self) -> &rustscale_key::DiscoPublic {
        &self.peer_disco_key
    }

    /// Set candidate UDP endpoints (from `tailcfg::Node.Endpoints`).
    pub fn set_candidates(&mut self, addrs: Vec<SocketAddr>) {
        self.candidates = addrs;
    }

    /// Candidate UDP endpoints to probe.
    pub fn candidates(&self) -> &[SocketAddr] {
        &self.candidates
    }

    /// The peer's home DERP region.
    pub fn home_derp(&self) -> i32 {
        self.home_derp
    }

    /// Update the peer's home DERP region (e.g. on a netmap delta).
    pub fn set_home_derp(&mut self, region: i32) {
        self.home_derp = region;
    }

    /// Record the DERP region from which a packet from this peer arrived.
    /// Used for reply routing (Go's derpRoute caching).
    pub fn set_last_recv_derp_region(&mut self, region: i32) {
        self.last_recv_derp_region = region;
    }

    /// Pick the DERP region to use for sending to this peer.
    /// Priority: last-received-region (most reliable) > HomeDERP (netmap) > 0.
    /// This mirrors Go magicsock's derpRoute: the region a packet arrived on
    /// is the one we reply on, since the peer is demonstrably listening there.
    pub fn derp_send_region(&self) -> i32 {
        if self.last_recv_derp_region > 0 {
            return self.last_recv_derp_region;
        }
        self.home_derp
    }

    /// Debug accessor for the last-recv DERP region.
    pub fn last_recv_derp_region_for_debug(&self) -> i32 {
        self.last_recv_derp_region
    }

    /// Evaluate the best path at time `now`.
    pub fn best_path(&self, now: Instant) -> BestPath {
        if let Some((addr, trusted_until)) = self.best_addr {
            if now < trusted_until {
                return BestPath::Direct {
                    addr,
                    trusted_until,
                };
            }
        }
        if let Some((addr, vni)) = self.relay {
            return BestPath::Relay { addr, vni };
        }
        if self.home_derp > 0 || self.last_recv_derp_region > 0 {
            return BestPath::Derp {
                region: self.derp_send_region(),
            };
        }
        BestPath::None
    }

    /// Confirm a direct path after receiving a pong from `addr`.
    pub fn confirm_direct(&mut self, addr: SocketAddr, now: Instant) {
        self.best_addr = Some((addr, now + TRUST_BEST_ADDR_DURATION));
    }

    /// Record a peer relay path.
    pub fn set_relay(&mut self, addr: SocketAddr, vni: u32) {
        self.relay = Some((addr, vni));
    }

    /// Clear the relay path.
    pub fn clear_relay(&mut self) {
        self.relay = None;
    }

    /// Whether the direct path has expired at `now`.
    pub fn direct_expired(&self, now: Instant) -> bool {
        match self.best_addr {
            Some((_, until)) => now >= until,
            None => true,
        }
    }

    /// The trusted direct address, if still valid at `now`.
    pub fn trusted_direct_addr(&self, now: Instant) -> Option<SocketAddr> {
        self.best_addr
            .filter(|(_, until)| now < *until)
            .map(|(addr, _)| addr)
    }

    /// Record a pending disco ping.
    pub fn add_pending_ping(&mut self, tx_id: [u8; 12], addr: SocketAddr, now: Instant) {
        self.pending_pings.insert(tx_id, (now, addr));
    }

    /// Match a pong's tx_id to a pending ping; returns the target addr.
    pub fn match_pong(&mut self, tx_id: &[u8; 12]) -> Option<SocketAddr> {
        self.pending_pings.remove(tx_id).map(|(_, addr)| addr)
    }

    /// Whether we should send a CallMeMaybe to this peer (once per netmap set).
    pub fn should_send_call_me_maybe(&mut self) -> bool {
        if self.call_me_maybe_sent {
            return false;
        }
        self.call_me_maybe_sent = true;
        true
    }

    /// Reset the CallMeMaybe flag (e.g. on a new netmap).
    pub fn reset_call_me_maybe(&mut self) {
        self.call_me_maybe_sent = false;
    }

    /// Remove expired pending pings (housekeeping).
    pub fn expire_pending_pings(&mut self, now: Instant, max_age: Duration) {
        self.pending_pings
            .retain(|_, (sent, _)| now.duration_since(*sent) < max_age);
    }

    /// Reset transient direct-path state after a major link change so disco
    /// re-probes. Keeps candidates and `home_derp` (from the netmap).
    pub fn reset_for_link_change(&mut self) {
        self.best_addr = None;
        self.pending_pings.clear();
        self.last_recv_derp_region = 0;
        self.call_me_maybe_sent = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustscale_key::{DiscoPrivate, NodePrivate};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn sa(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    fn ep() -> Endpoint {
        let nk = NodePrivate::generate().public();
        let dk = DiscoPrivate::generate().public();
        Endpoint::new(nk, dk, 1)
    }

    #[test]
    fn derp_fallback_when_no_direct() {
        let e = ep();
        let now = Instant::now();
        assert_eq!(e.best_path(now).class(), PathClass::Derp);
    }

    #[test]
    fn direct_beats_relay_beats_derp() {
        let mut e = ep();
        let now = Instant::now();

        e.set_relay(sa(4000), 42);
        assert_eq!(e.best_path(now).class(), PathClass::Relay);

        e.confirm_direct(sa(5000), now);
        assert_eq!(e.best_path(now).class(), PathClass::Direct);
    }

    #[test]
    fn trust_expires_to_relay() {
        let mut e = ep();
        let now = Instant::now();
        e.set_relay(sa(4000), 42);
        e.confirm_direct(sa(5000), now);

        assert_eq!(e.best_path(now).class(), PathClass::Direct);

        let later = now + TRUST_BEST_ADDR_DURATION + Duration::from_millis(1);
        assert_eq!(e.best_path(later).class(), PathClass::Relay);
        assert!(e.direct_expired(later));
    }

    #[test]
    fn trust_expires_to_derp_when_no_relay() {
        let mut e = ep();
        let now = Instant::now();
        e.confirm_direct(sa(5000), now);

        let later = now + TRUST_BEST_ADDR_DURATION + Duration::from_millis(1);
        assert_eq!(e.best_path(later).class(), PathClass::Derp);
    }

    #[test]
    fn pending_ping_match() {
        let mut e = ep();
        let now = Instant::now();
        let tx = [0xaa; 12];
        let addr = sa(1234);
        e.add_pending_ping(tx, addr, now);
        assert_eq!(e.match_pong(&tx), Some(addr));
        // Second match returns None.
        assert_eq!(e.match_pong(&tx), None);
    }

    #[test]
    fn call_me_maybe_sent_once() {
        let mut e = ep();
        assert!(e.should_send_call_me_maybe());
        assert!(!e.should_send_call_me_maybe());
        e.reset_call_me_maybe();
        assert!(e.should_send_call_me_maybe());
    }

    #[test]
    fn none_path_when_no_derp() {
        let nk = NodePrivate::generate().public();
        let dk = DiscoPrivate::generate().public();
        let e = Endpoint::new(nk, dk, 0);
        assert_eq!(e.best_path(Instant::now()).class(), PathClass::None);
    }
}
