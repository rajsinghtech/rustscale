//! Per-peer endpoint state machine: candidate paths, trust-on-pong, ranking.
//!
//! Ports the semantics of Go's `wgengine/magicsock/endpoint.go` in simplified
//! form. Each peer has a set of candidate UDP endpoints (from the netmap), a
//! best confirmed direct path with a trust expiry, an optional peer-relay path,
//! and a DERP fallback (the peer's home region).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// How long to trust a direct path after receiving a pong.
/// Mirrors Go's `trustUDPAddrDuration` (magicsock.go:4036).
pub const TRUST_BEST_ADDR_DURATION: Duration = Duration::from_millis(6500);

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

/// Why a discovery ping was sent. Mirrors Go's `discoPingPurpose`
/// (endpoint.go:1282-1301).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoPingPurpose {
    /// Path validity discovery (initial probing).
    Discovery,
    /// Keep-alive heartbeat to the best UDP path.
    Heartbeat,
    /// User-initiated `tailscale ping`.
    CLI,
    /// UDP path lifetime probe at a NAT timeout cliff.
    HeartbeatForUDPLifetime,
}

/// A pending disco ping awaiting a pong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingPing {
    pub sent_at: Instant,
    pub addr: SocketAddr,
    pub purpose: DiscoPingPurpose,
    /// Probe size for PMTUD (0 for non-PMTUD pings).
    pub size: usize,
}

/// UDP path lifetime probing state. Mirrors Go's `probeUDPLifetime`
/// (endpoint.go:178-204).
///
/// A probe "cycle" pings the UDP path at ascending timeout cliffs
/// (10s, 30s, 60s). A cycle completes when all cliffs receive a pong
/// or a ping times out. Only the node with the lexicographically
/// smaller disco public key probes, to avoid duplicate work.
pub struct ProbeUDPLifetime {
    cliffs: Vec<Duration>,
    cycle_can_start_every: Duration,
    current_cliff: usize,
    cycle_active: bool,
    cycle_started_at: Option<Instant>,
    best_addr: Option<SocketAddr>,
    last_tx_id: [u8; 12],
}

impl ProbeUDPLifetime {
    /// Default config matching Go's `defaultProbeUDPLifetimeConfig`
    /// (endpoint.go:269-276).
    pub fn default_config() -> Self {
        Self {
            cliffs: vec![
                Duration::from_secs(10),
                Duration::from_secs(30),
                Duration::from_secs(60),
            ],
            cycle_can_start_every: Duration::from_secs(86400),
            current_cliff: 0,
            cycle_active: false,
            cycle_started_at: None,
            best_addr: None,
            last_tx_id: [0u8; 12],
        }
    }

    /// The duration of the current cliff being probed.
    pub fn current_cliff_duration(&self) -> Duration {
        self.cliffs[self.current_cliff]
    }

    /// Whether a probing cycle is active.
    pub fn cycle_active(&self) -> bool {
        self.cycle_active
    }

    /// The `best_addr` recorded when the cycle was scheduled.
    pub fn best_addr(&self) -> Option<SocketAddr> {
        self.best_addr
    }

    /// The last ping tx_id sent for this probe.
    pub fn last_tx_id(&self) -> [u8; 12] {
        self.last_tx_id
    }

    /// Reset cycle state to inactive (mirrors `resetCycleEndpointLocked`).
    pub fn reset_cycle(&mut self) {
        self.cycle_active = false;
        self.current_cliff = 0;
        self.best_addr = None;
    }

    /// Begin a new cycle at cliff 0, recording `best_addr`.
    pub fn start_cycle(&mut self, best_addr: SocketAddr, now: Instant) {
        self.current_cliff = 0;
        self.cycle_active = true;
        self.cycle_started_at = Some(now);
        self.best_addr = Some(best_addr);
    }

    /// Record the tx_id of the ping sent for the current cliff.
    pub fn set_last_tx_id(&mut self, tx_id: [u8; 12]) {
        self.last_tx_id = tx_id;
    }

    /// Advance to the next cliff. Returns `true` if there are more cliffs,
    /// `false` if the cycle is complete.
    pub fn advance_cliff(&mut self) -> bool {
        if self.current_cliff >= self.cliffs.len() - 1 {
            self.reset_cycle();
            false
        } else {
            self.current_cliff += 1;
            true
        }
    }

    /// Whether enough time has passed since the last cycle to start a new one.
    pub fn can_start_cycle(&self, now: Instant) -> bool {
        if self.cycle_active {
            return false;
        }
        match self.cycle_started_at {
            Some(t) => now.duration_since(t) >= self.cycle_can_start_every,
            None => true,
        }
    }

    /// Number of cliffs in the config.
    pub fn num_cliffs(&self) -> usize {
        self.cliffs.len()
    }

    /// Current cliff index.
    pub fn current_cliff_index(&self) -> usize {
        self.current_cliff
    }
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
    pending_pings: HashMap<[u8; 12], PendingPing>,
    call_me_maybe_sent: bool,
    /// Last external TX activity (e.g. wireguard send). Drives the heartbeat
    /// timer: heartbeats fire every `HEARTBEAT_INTERVAL` while recent, and
    /// stop after `SESSION_ACTIVE_TIMEOUT` of inactivity.
    /// Mirrors Go's `lastSendExt` (endpoint.go:84).
    last_send_ext: Option<Instant>,
    /// Last UDP packet received from this peer (any kind). Used by the
    /// UDP lifetime probe to measure inactivity.
    /// Mirrors Go's `lastRecvUDPAny` (endpoint.go:88).
    last_recv_udp: Option<Instant>,
    /// UDP path lifetime probing state. `None` when probing is disabled.
    probe_udp_lifetime: Option<ProbeUDPLifetime>,
    /// Largest PMTUD probe size that received a pong (0 = not probed).
    peer_mtu: usize,
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
            last_send_ext: None,
            last_recv_udp: None,
            probe_udp_lifetime: Some(ProbeUDPLifetime::default_config()),
            peer_mtu: 0,
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
    pub fn add_pending_ping(
        &mut self,
        tx_id: [u8; 12],
        addr: SocketAddr,
        now: Instant,
        purpose: DiscoPingPurpose,
        size: usize,
    ) {
        self.pending_pings.insert(
            tx_id,
            PendingPing {
                sent_at: now,
                addr,
                purpose,
                size,
            },
        );
    }

    /// Match a pong's tx_id to a pending ping; returns the full record.
    pub fn match_pong(&mut self, tx_id: &[u8; 12]) -> Option<PendingPing> {
        self.pending_pings.remove(tx_id)
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
            .retain(|_, pp| now.duration_since(pp.sent_at) < max_age);
    }

    /// Reset transient direct-path state after a major link change so disco
    /// re-probes. Keeps candidates and `home_derp` (from the netmap).
    pub fn reset_for_link_change(&mut self) {
        self.best_addr = None;
        self.pending_pings.clear();
        self.last_recv_derp_region = 0;
        self.call_me_maybe_sent = false;
        self.last_send_ext = None;
        self.last_recv_udp = None;
        if let Some(ref mut p) = self.probe_udp_lifetime {
            p.reset_cycle();
        }
    }

    /// Note external TX activity (e.g. a WG send). Arms the heartbeat timer
    /// on first activity. Mirrors Go's `noteTxActivityExtTriggerLocked`
    /// (endpoint.go:974-979).
    pub fn note_tx_activity(&mut self, now: Instant) {
        self.last_send_ext = Some(now);
    }

    /// Last external TX activity time.
    pub fn last_send_ext(&self) -> Option<Instant> {
        self.last_send_ext
    }

    /// Note a UDP packet received from this peer. Mirrors Go's
    /// `lastRecvUDPAny` updates.
    pub fn note_recv_udp(&mut self, now: Instant) {
        self.last_recv_udp = Some(now);
    }

    /// Last UDP recv time from this peer.
    pub fn last_recv_udp(&self) -> Option<Instant> {
        self.last_recv_udp
    }

    /// Whether the session is still active (TX within `session_active_timeout`).
    pub fn session_active(&self, now: Instant, session_active_timeout: Duration) -> bool {
        match self.last_send_ext {
            Some(t) => now.duration_since(t) < session_active_timeout,
            None => false,
        }
    }

    /// The inactivity duration: time since the most recent of last TX or
    /// last UDP recv. Mirrors Go's
    /// `now.Sub(max(de.lastSendAny, de.lastRecvUDPAny.LoadAtomic()))`.
    pub fn inactivity_duration(&self, now: Instant) -> Duration {
        let last = match (self.last_send_ext, self.last_recv_udp) {
            (Some(t1), Some(t2)) => t1.max(t2),
            (Some(t), None) | (None, Some(t)) => t,
            (None, None) => return Duration::from_secs(u64::MAX / 2),
        };
        now.duration_since(last)
    }

    /// Clear the best direct path (demote to DERP/relay). Mirrors Go's
    /// `clearBestAddrLocked`.
    pub fn clear_best_addr(&mut self) {
        self.best_addr = None;
    }

    /// Whether this endpoint is a candidate for UDP lifetime probing.
    /// Returns the inactivity threshold after which to probe, and whether
    /// probing is eligible. Mirrors Go's `maybeProbeUDPLifetimeLocked`
    /// (endpoint.go:706-742).
    ///
    /// `our_disco` is our disco public key (for lexicographic comparison).
    /// `cliff_slack` is subtracted from the cliff duration.
    pub fn maybe_probe_udp_lifetime(
        &self,
        now: Instant,
        our_disco: &rustscale_key::DiscoPublic,
        cliff_slack: Duration,
    ) -> Option<Duration> {
        let p = self.probe_udp_lifetime.as_ref()?;
        self.best_addr?;
        if self.peer_disco_key.is_zero() {
            return None;
        }
        // Lower disco pub key probes higher (avoid duplicate work).
        if our_disco.raw32() >= self.peer_disco_key.raw32() {
            return None;
        }
        if !p.can_start_cycle(now) {
            return None;
        }
        let after_inactivity = p.current_cliff_duration().checked_sub(cliff_slack)?;
        Some(after_inactivity)
    }

    /// Start a UDP lifetime probe cycle. Records the current best_addr
    /// and marks the cycle as active.
    pub fn start_udp_lifetime_cycle(&mut self, now: Instant) {
        if let Some(ref mut p) = self.probe_udp_lifetime {
            if let Some((addr, _)) = self.best_addr {
                p.start_cycle(addr, now);
            }
        }
    }

    /// Record the tx_id of a UDP lifetime probe ping.
    pub fn set_udp_lifetime_tx_id(&mut self, tx_id: [u8; 12]) {
        if let Some(ref mut p) = self.probe_udp_lifetime {
            p.set_last_tx_id(tx_id);
        }
    }

    /// Advance the UDP lifetime probe to the next cliff on pong.
    /// Returns `true` if there are more cliffs to probe.
    pub fn advance_udp_lifetime_cliff(&mut self) -> bool {
        match self.probe_udp_lifetime.as_mut() {
            Some(p) => p.advance_cliff(),
            None => false,
        }
    }

    /// Complete the UDP lifetime probe cycle (reset state).
    pub fn complete_udp_lifetime_cycle(&mut self) {
        if let Some(ref mut p) = self.probe_udp_lifetime {
            p.reset_cycle();
        }
    }

    /// Whether a UDP lifetime probe cycle is currently active.
    pub fn udp_lifetime_cycle_active(&self) -> bool {
        self.probe_udp_lifetime
            .as_ref()
            .is_some_and(ProbeUDPLifetime::cycle_active)
    }

    /// Whether the best_addr matches the probe's recorded best_addr.
    pub fn udp_lifetime_best_addr_matches(&self) -> bool {
        match (self.best_addr, self.probe_udp_lifetime.as_ref()) {
            (Some((addr, _)), Some(p)) => p.best_addr() == Some(addr),
            _ => false,
        }
    }

    /// The current cliff index in the UDP lifetime probe.
    pub fn udp_lifetime_current_cliff(&self) -> Option<usize> {
        self.probe_udp_lifetime
            .as_ref()
            .map(ProbeUDPLifetime::current_cliff_index)
    }

    /// The current cliff duration in the UDP lifetime probe.
    pub fn udp_lifetime_current_cliff_duration(&self) -> Option<Duration> {
        self.probe_udp_lifetime
            .as_ref()
            .map(ProbeUDPLifetime::current_cliff_duration)
    }

    /// Record the largest PMTUD probe size that succeeded.
    pub fn set_peer_mtu(&mut self, size: usize) {
        if size > self.peer_mtu {
            self.peer_mtu = size;
        }
    }

    /// The largest PMTUD probe size that succeeded (0 = not probed).
    pub fn peer_mtu(&self) -> usize {
        self.peer_mtu
    }

    /// Enable or disable UDP lifetime probing on this endpoint.
    pub fn set_probe_udp_lifetime(&mut self, enabled: bool) {
        if enabled {
            if self.probe_udp_lifetime.is_none() {
                self.probe_udp_lifetime = Some(ProbeUDPLifetime::default_config());
            }
        } else {
            if let Some(ref mut p) = self.probe_udp_lifetime {
                p.reset_cycle();
            }
            self.probe_udp_lifetime = None;
        }
    }

    /// Check whether the last UDP lifetime probe ping was answered (pong
    /// received and removed from pending_pings). Returns `true` if the
    /// probe's `last_tx_id` is no longer in `pending_pings`.
    pub fn is_last_udp_lifetime_ping_answered(&self) -> bool {
        match self.probe_udp_lifetime.as_ref() {
            Some(p) => !self.pending_pings.contains_key(&p.last_tx_id()),
            None => true,
        }
    }

    /// Number of pending disco pings (for testing PMTUD burst).
    pub fn pending_pings_count(&self) -> usize {
        self.pending_pings.len()
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
        e.add_pending_ping(tx, addr, now, DiscoPingPurpose::Discovery, 0);
        let pp = e.match_pong(&tx).expect("should match");
        assert_eq!(pp.addr, addr);
        assert_eq!(pp.purpose, DiscoPingPurpose::Discovery);
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

    // ---- Heartbeat tests ----

    #[test]
    fn heartbeat_arms_on_tx_activity() {
        let mut e = ep();
        let now = Instant::now();
        // Before TX activity, session is not active.
        assert!(!e.session_active(now, Duration::from_secs(45)));
        // Note TX activity.
        e.note_tx_activity(now);
        // Session should be active immediately after.
        assert!(e.session_active(now, Duration::from_secs(45)));
        // And still active just under the timeout.
        let almost_idle = now + Duration::from_secs(44);
        assert!(e.session_active(almost_idle, Duration::from_secs(45)));
    }

    #[test]
    fn heartbeat_cancels_after_idle() {
        let mut e = ep();
        let now = Instant::now();
        e.note_tx_activity(now);
        assert!(e.session_active(now, Duration::from_secs(45)));
        // After 45s of inactivity, session should be idle.
        let idle = now + Duration::from_secs(46);
        assert!(!e.session_active(idle, Duration::from_secs(45)));
        // Inactivity duration should be ~46s.
        let inact = e.inactivity_duration(idle);
        assert!(inact >= Duration::from_secs(46));
    }

    // ---- UDP lifetime probe tests ----

    #[test]
    fn udp_lifetime_cliff_scheduling() {
        let mut e = ep();
        let now = Instant::now();
        e.confirm_direct(sa(5000), now);

        // Create a disco key that is HIGHER than ours so we probe.
        // Our disco key is e.peer_disco_key(). We need a key that is lower.
        // For this test, use the endpoint's own disco key and compare.
        // maybe_probe_udp_lifetime returns None if our key >= peer's key.
        // So we need our_disco < peer_disco.
        // Since we can't control the keys, test both branches:
        let our_disco = e.peer_disco_key().clone();
        let result = e.maybe_probe_udp_lifetime(now, &our_disco, Duration::from_secs(2));
        // our_disco == peer_disco, so our_disco >= peer_disco → None.
        assert!(result.is_none());

        // Now use a lower disco key for "ours" to simulate being the
        // lower-key node. We create a key with first byte = 0.
        let mut lower_raw = [0u8; 32];
        lower_raw[0] = 0;
        let lower_disco = rustscale_key::DiscoPublic::from_raw32(lower_raw);
        let result = e.maybe_probe_udp_lifetime(now, &lower_disco, Duration::from_secs(2));
        // First cliff is 10s, slack is 2s → 8s after inactivity.
        assert_eq!(result, Some(Duration::from_secs(8)));
    }

    #[test]
    fn udp_lifetime_timeout_demotes_direct() {
        let mut e = ep();
        let now = Instant::now();
        e.confirm_direct(sa(5000), now);
        assert_eq!(e.best_path(now).class(), PathClass::Direct);

        // Start a UDP lifetime cycle.
        e.start_udp_lifetime_cycle(now);
        assert!(e.udp_lifetime_cycle_active());
        assert_eq!(e.udp_lifetime_current_cliff(), Some(0));

        // Simulate a timeout: the ping was not answered.
        // First, record a pending ping with the probe tx_id.
        let tx_id = [0xbb; 12];
        e.set_udp_lifetime_tx_id(tx_id);
        e.add_pending_ping(
            tx_id,
            sa(5000),
            now,
            DiscoPingPurpose::HeartbeatForUDPLifetime,
            0,
        );
        // The ping is still pending → not answered.
        assert!(!e.is_last_udp_lifetime_ping_answered());

        // On timeout: clear best_addr and complete cycle.
        e.clear_best_addr();
        e.complete_udp_lifetime_cycle();
        assert!(!e.udp_lifetime_cycle_active());
        assert_eq!(e.best_path(now).class(), PathClass::Derp);
    }

    #[test]
    fn udp_lifetime_pong_advances_cliff() {
        let mut e = ep();
        let now = Instant::now();
        e.confirm_direct(sa(5000), now);
        e.start_udp_lifetime_cycle(now);
        assert_eq!(e.udp_lifetime_current_cliff(), Some(0));

        // Simulate a pong: remove the pending ping.
        let tx_id = [0xcc; 12];
        e.set_udp_lifetime_tx_id(tx_id);
        e.add_pending_ping(
            tx_id,
            sa(5000),
            now,
            DiscoPingPurpose::HeartbeatForUDPLifetime,
            0,
        );
        // Pong received → match_pong removes it.
        e.match_pong(&tx_id);
        assert!(e.is_last_udp_lifetime_ping_answered());

        // Advance cliff.
        let has_more = e.advance_udp_lifetime_cliff();
        assert!(has_more);
        assert_eq!(e.udp_lifetime_current_cliff(), Some(1));

        // Advance to last cliff and beyond.
        let has_more = e.advance_udp_lifetime_cliff();
        assert!(has_more);
        assert_eq!(e.udp_lifetime_current_cliff(), Some(2));

        // Past the last cliff → cycle completes.
        let has_more = e.advance_udp_lifetime_cliff();
        assert!(!has_more);
        assert!(!e.udp_lifetime_cycle_active());
    }

    // ---- PMTUD tests ----

    #[test]
    fn pmtud_records_largest_succeeding_size() {
        let mut e = ep();
        assert_eq!(e.peer_mtu(), 0);

        e.set_peer_mtu(1280);
        assert_eq!(e.peer_mtu(), 1280);

        e.set_peer_mtu(1400);
        assert_eq!(e.peer_mtu(), 1400);

        // Smaller size doesn't reduce.
        e.set_peer_mtu(1280);
        assert_eq!(e.peer_mtu(), 1400);
    }

    #[test]
    fn pmtud_disabled_by_default() {
        let e = ep();
        // Endpoint starts with probe_udp_lifetime enabled (matching Go's
        // default config), but PMTUD is on Inner, not Endpoint.
        // Here we just verify the endpoint has no peer_mtu set.
        assert_eq!(e.peer_mtu(), 0);
    }

    #[test]
    fn probe_udp_lifetime_can_be_disabled() {
        let mut e = ep();
        assert!(!e.udp_lifetime_cycle_active());
        e.set_probe_udp_lifetime(false);
        // After disabling, maybe_probe_udp_lifetime returns None.
        let now = Instant::now();
        e.confirm_direct(sa(5000), now);
        let lower_disco = rustscale_key::DiscoPublic::from_raw32([0u8; 32]);
        assert!(e
            .maybe_probe_udp_lifetime(now, &lower_disco, Duration::from_secs(2))
            .is_none());

        // Re-enable.
        e.set_probe_udp_lifetime(true);
        assert!(e
            .maybe_probe_udp_lifetime(now, &lower_disco, Duration::from_secs(2))
            .is_some());
    }
}
