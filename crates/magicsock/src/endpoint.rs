//! Per-peer endpoint state machine: candidate paths, trust-on-pong, ranking.
//!
//! Ports the semantics of Go's `wgengine/magicsock/endpoint.go` in simplified
//! form. Each peer has a set of candidate UDP endpoints (from the netmap), a
//! best confirmed direct path with a trust expiry, an optional peer-relay path,
//! and a DERP fallback (the peer's home region).

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// How long to trust a direct path after receiving a pong.
/// Mirrors Go's `trustUDPAddrDuration` (magicsock.go:4036).
pub const TRUST_BEST_ADDR_DURATION: Duration = Duration::from_millis(6500);

/// How long after the last DERP packet from a peer before we consider the
/// DERP route stale and clear it. Mirrors Go's derpRoute inactivity
/// semantics — the route is cleaned up after this timeout.
pub const DERP_ROUTE_CLEANUP_TIMEOUT: Duration = Duration::from_secs(300);

/// Maximum current/recent relay addresses retained per exact server
/// generation for revocation cleanup.
pub(crate) const MAX_RELAY_PATH_HISTORY_PER_SERVER: usize = 8;

/// Endpoint type, mirroring Go's `tailcfg.EndpointType` (tailcfg.go:1332).
/// Used for ranking candidate paths: higher-ranked types are preferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum EndpointType {
    /// Unknown / unspecified.
    #[default]
    Unknown,
    /// Explicitly configured by the user.
    ExplicitConf,
    /// STUN-resolved public address.
    Stun,
    /// Port-mapped (NAT-PMP/PCP/UPnP).
    Portmapped,
    /// Hard NAT: STUN'ed IPv4 + local fixed port.
    Stun4LocalPort,
    /// Local interface address.
    Local,
}

impl EndpointType {
    /// Ranking priority — higher is better. Mirrors Go's path preference:
    /// local > portmapped > stun4localport > stun > explicit > unknown.
    pub fn rank(self) -> u8 {
        match self {
            Self::Local => 5,
            Self::Portmapped => 4,
            Self::Stun4LocalPort => 3,
            Self::Stun => 2,
            Self::ExplicitConf => 1,
            Self::Unknown => 0,
        }
    }
}

impl From<rustscale_tailcfg::EndpointType> for EndpointType {
    fn from(t: rustscale_tailcfg::EndpointType) -> Self {
        match t {
            rustscale_tailcfg::EndpointType::LOCAL => Self::Local,
            rustscale_tailcfg::EndpointType::STUN => Self::Stun,
            rustscale_tailcfg::EndpointType::PORTMAPPED => Self::Portmapped,
            rustscale_tailcfg::EndpointType::STUN4_LOCAL_PORT => Self::Stun4LocalPort,
            rustscale_tailcfg::EndpointType::EXPLICIT_CONF => Self::ExplicitConf,
            _ => Self::Unknown,
        }
    }
}

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
    /// The CLI request that owns this ping, when it was user initiated.
    /// This prevents an older ping's pong from completing a newer request.
    pub cli_request_id: Option<u64>,
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
#[derive(Clone)]
struct RelayPath {
    addr: SocketAddr,
    vni: u32,
    server_key: rustscale_key::NodePublic,
    server_generation: u64,
}

pub struct Endpoint {
    peer_node_key: rustscale_key::NodePublic,
    /// The peer's first Tailscale address, used as the source of physical
    /// netlog tuples, matching upstream magicsock's `nodeAddr`.
    node_addr: Option<IpAddr>,
    peer_disco_key: rustscale_key::DiscoPublic,
    candidates: Vec<(SocketAddr, EndpointType)>,
    best_addr: Option<(SocketAddr, Instant)>,
    relay: Option<RelayPath>,
    relay_history: HashMap<(rustscale_key::NodePublic, u64), VecDeque<SocketAddr>>,
    home_derp: i32,
    /// The DERP region from which the most recent packet from this peer
    /// arrived. Used for reply routing when HomeDERP is 0 or stale.
    /// Mirrors Go's `derpRoute` / `setDerpRoute` caching.
    last_recv_derp_region: i32,
    /// When `last_recv_derp_region` was last set. Used for timer-based
    /// expiry — after `DERP_ROUTE_CLEANUP_TIMEOUT` of inactivity, the
    /// route is considered stale and cleared.
    last_recv_derp_at: Option<Instant>,
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
    /// Last time a full candidate discovery round was started.
    last_full_ping: Option<Instant>,
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
            node_addr: None,
            peer_disco_key,
            candidates: Vec::new(),
            best_addr: None,
            relay: None,
            relay_history: HashMap::new(),
            home_derp,
            last_recv_derp_region: 0,
            last_recv_derp_at: None,
            pending_pings: HashMap::new(),
            call_me_maybe_sent: false,
            last_send_ext: None,
            last_recv_udp: None,
            probe_udp_lifetime: Some(ProbeUDPLifetime::default_config()),
            peer_mtu: 0,
            last_full_ping: None,
        }
    }

    /// The peer's WireGuard public key.
    pub fn peer_node_key(&self) -> &rustscale_key::NodePublic {
        &self.peer_node_key
    }

    /// The peer's first Tailscale address.
    pub fn node_addr(&self) -> Option<IpAddr> {
        self.node_addr
    }

    /// Refresh the peer's first Tailscale address.
    pub fn set_node_addr(&mut self, node_addr: Option<IpAddr>) {
        self.node_addr = node_addr;
    }

    /// The peer's disco public key.
    pub fn peer_disco_key(&self) -> &rustscale_key::DiscoPublic {
        &self.peer_disco_key
    }

    /// Refresh the peer's disco public key.
    ///
    /// Returns the previous key when it changed, or `None` when it was
    /// already current. This deliberately preserves all other endpoint state.
    pub fn update_peer_disco_key(
        &mut self,
        peer_disco_key: rustscale_key::DiscoPublic,
    ) -> Option<rustscale_key::DiscoPublic> {
        if self.peer_disco_key == peer_disco_key {
            return None;
        }
        Some(std::mem::replace(&mut self.peer_disco_key, peer_disco_key))
    }

    /// Set candidate UDP endpoints (from `tailcfg::Node.Endpoints`).
    pub fn set_candidates(&mut self, addrs: Vec<SocketAddr>) {
        self.candidates = addrs
            .into_iter()
            .map(|a| (a, EndpointType::Unknown))
            .collect();
    }

    /// Learn an authenticated source address from an incoming disco Ping.
    /// Keep the candidate set bounded, as Go does for discovered endpoints.
    pub fn learn_candidate(&mut self, addr: SocketAddr) -> bool {
        const MAX_CANDIDATES: usize = 100;
        if self
            .candidates
            .iter()
            .any(|(candidate, _)| *candidate == addr)
            || self.candidates.len() >= MAX_CANDIDATES
        {
            return false;
        }
        self.candidates.push((addr, EndpointType::Unknown));
        true
    }

    /// Rate-limit full direct discovery rounds started by WireGuard sends.
    pub fn should_start_discovery(&mut self, now: Instant, interval: Duration) -> bool {
        if self
            .last_full_ping
            .is_some_and(|last| now.duration_since(last) < interval)
        {
            return false;
        }
        self.last_full_ping = Some(now);
        true
    }

    /// Set candidate UDP endpoints with their endpoint types (from
    /// `tailcfg::Node.Endpoints` + `EndpointTypes`).
    pub fn set_candidates_typed(&mut self, addrs: Vec<(SocketAddr, EndpointType)>) {
        self.candidates = addrs;
    }

    /// Candidate UDP endpoints to probe (address only).
    pub fn candidates(&self) -> Vec<SocketAddr> {
        self.candidates.iter().map(|(a, _)| *a).collect()
    }

    /// Candidate UDP endpoints with their types.
    pub fn candidates_typed(&self) -> &[(SocketAddr, EndpointType)] {
        &self.candidates
    }

    /// Candidates sorted by endpoint type rank (highest first), so
    /// higher-quality paths are probed before lower-quality ones.
    /// Mirrors Go's endpoint type preference for path ranking.
    pub fn ranked_candidates(&self) -> Vec<(SocketAddr, EndpointType)> {
        let mut sorted = self.candidates.clone();
        sorted.sort_by_key(|b| std::cmp::Reverse(b.1.rank()));
        sorted
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
    /// Used for reply routing (Go's derpRoute caching). Also records the
    /// arrival time for timer-based expiry.
    pub fn set_last_recv_derp_region(&mut self, region: i32) {
        self.last_recv_derp_region = region;
        self.last_recv_derp_at = Some(Instant::now());
    }

    /// Pick the DERP region to use for sending to this peer.
    /// Priority: last-received-region (if still valid) > HomeDERP (netmap) > 0.
    /// This mirrors Go magicsock's derpRoute: the region a packet arrived on
    /// is the one we reply on, since the peer is demonstrably listening there.
    /// Does not mutate — call `expire_derp_route_if_stale` from housekeeping
    /// to actually clear stale routes.
    pub fn derp_send_region(&self) -> i32 {
        if self.last_recv_derp_region > 0 && self.derp_route_valid() {
            return self.last_recv_derp_region;
        }
        self.home_derp
    }

    /// Debug accessor for the last-recv DERP region.
    pub fn last_recv_derp_region_for_debug(&self) -> i32 {
        self.last_recv_derp_region
    }

    /// Check whether the DERP route has expired and clear it if so.
    /// Called automatically by `derp_send_region` and usable from
    /// housekeeping loops.
    pub fn expire_derp_route_if_stale(&mut self) {
        if let Some(at) = self.last_recv_derp_at {
            if Instant::now().duration_since(at) >= DERP_ROUTE_CLEANUP_TIMEOUT {
                self.last_recv_derp_region = 0;
                self.last_recv_derp_at = None;
            }
        }
    }

    /// Whether the DERP route is currently valid (not expired).
    pub fn derp_route_valid(&self) -> bool {
        match self.last_recv_derp_at {
            Some(at) => Instant::now().duration_since(at) < DERP_ROUTE_CLEANUP_TIMEOUT,
            None => false,
        }
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
        if let Some(relay) = self.relay.as_ref() {
            return BestPath::Relay {
                addr: relay.addr,
                vni: relay.vni,
            };
        }
        // Check derp route validity without mutating (best_path is &self).
        let derp_region = if self.derp_route_valid() {
            self.last_recv_derp_region
        } else {
            self.home_derp
        };
        if derp_region > 0 {
            return BestPath::Derp {
                region: derp_region,
            };
        }
        BestPath::None
    }

    /// Confirm a direct path after receiving a pong from `addr`.
    pub fn confirm_direct(&mut self, addr: SocketAddr, now: Instant) {
        self.best_addr = Some((addr, now + TRUST_BEST_ADDR_DURATION));
    }

    /// Record a peer relay path.
    pub fn set_relay(
        &mut self,
        addr: SocketAddr,
        vni: u32,
        server_key: rustscale_key::NodePublic,
        server_generation: u64,
    ) -> Vec<SocketAddr> {
        let history = self
            .relay_history
            .entry((server_key.clone(), server_generation))
            .or_default();
        if let Some(existing) = history.iter().position(|existing| *existing == addr) {
            history.remove(existing);
        }
        history.push_back(addr);
        let mut evicted = Vec::new();
        while history.len() > MAX_RELAY_PATH_HISTORY_PER_SERVER {
            if let Some(oldest) = history.pop_front() {
                debug_assert_ne!(oldest, addr, "current relay address must not be evicted");
                evicted.push(oldest);
            }
        }
        self.relay = Some(RelayPath {
            addr,
            vni,
            server_key,
            server_generation,
        });
        evicted
    }

    /// Return the current relay path and its server identity.
    pub fn current_relay(&self) -> Option<(SocketAddr, u32, &rustscale_key::NodePublic, u64)> {
        self.relay.as_ref().map(|relay| {
            (
                relay.addr,
                relay.vni,
                &relay.server_key,
                relay.server_generation,
            )
        })
    }

    /// Clear the relay path and its retained reverse-map history.
    pub fn clear_relay(&mut self) {
        self.relay = None;
        self.relay_history.clear();
    }

    /// Clear and return every relay address associated with this exact server
    /// identity, including addresses replaced by newer relay paths.
    pub fn clear_relay_server(
        &mut self,
        server_key: &rustscale_key::NodePublic,
        server_generation: u64,
    ) -> Vec<SocketAddr> {
        let identity = (server_key.clone(), server_generation);
        let mut addresses = self
            .relay_history
            .remove(&identity)
            .unwrap_or_default()
            .into_iter()
            .collect::<Vec<_>>();
        let matches_current = self.relay.as_ref().is_some_and(|relay| {
            &relay.server_key == server_key && relay.server_generation == server_generation
        });
        if matches_current {
            if let Some(relay) = self.relay.take() {
                if !addresses.contains(&relay.addr) {
                    addresses.push(relay.addr);
                }
            }
        } else if let Some(current) = self.relay.as_ref() {
            // An address can be reused by a newer server identity. Its single
            // reverse-map slot now belongs to the current path, not history.
            addresses.retain(|address| *address != current.addr);
        }
        addresses
    }

    #[cfg(test)]
    pub fn relay_history_len(
        &self,
        server_key: &rustscale_key::NodePublic,
        server_generation: u64,
    ) -> usize {
        self.relay_history
            .get(&(server_key.clone(), server_generation))
            .map_or(0, VecDeque::len)
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
        cli_request_id: Option<u64>,
    ) {
        self.pending_pings.insert(
            tx_id,
            PendingPing {
                sent_at: now,
                addr,
                purpose,
                size,
                cli_request_id,
            },
        );
    }

    /// Match a pong's tx_id to a pending ping; returns the full record.
    pub fn match_pong(&mut self, tx_id: &[u8; 12]) -> Option<PendingPing> {
        self.pending_pings.remove(tx_id)
    }

    /// Check whether a tx_id has a pending ping without consuming it.
    pub fn has_pending_ping(&self, tx_id: &[u8; 12]) -> bool {
        self.pending_pings.contains_key(tx_id)
    }

    /// Remove every pending transaction owned by one CLI ping request.
    /// Called by the request's drop guard so cancellation cannot leak state.
    pub fn remove_cli_request_pings(&mut self, request_id: u64) {
        self.pending_pings
            .retain(|_, ping| ping.cli_request_id != Some(request_id));
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

    /// Check whether the best-addr trust has expired and, if so, reset the
    /// CallMeMaybe flag so it can be retriggered on the next disco ping
    /// cycle. Mirrors Go's behavior where `trustBestAddrUntil` expiring
    /// causes `sendDiscoPingsLocked` to re-send CallMeMaybe
    /// (endpoint.go:1375-1407).
    ///
    /// Returns `true` if CallMeMaybe was retriggered (trust expired).
    pub fn maybe_retrigger_call_me_maybe(&mut self, now: Instant) -> bool {
        match self.best_addr {
            Some((_, until)) if now >= until => {
                if self.call_me_maybe_sent {
                    self.call_me_maybe_sent = false;
                    return true;
                }
                false
            }
            _ => false,
        }
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
        self.last_recv_derp_at = None;
        self.call_me_maybe_sent = false;
        self.last_send_ext = None;
        self.last_recv_udp = None;
        if let Some(ref mut p) = self.probe_udp_lifetime {
            p.reset_cycle();
        }
    }

    /// Note external TX activity (e.g. a WG send). Mirrors Go's
    /// `noteTxActivityExtTriggerLocked` (endpoint.go:974-979).
    pub fn note_tx_activity(&mut self, now: Instant) {
        self.last_send_ext = Some(now);
    }

    /// Note external TX activity and report an inactive-to-active session
    /// transition. Kept crate-private so the public TX accounting API remains
    /// stable.
    pub(crate) fn note_tx_activity_transition(
        &mut self,
        now: Instant,
        session_active_timeout: Duration,
    ) -> bool {
        let was_inactive = !self.session_active(now, session_active_timeout);
        self.note_tx_activity(now);
        was_inactive
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

    /// Reset the PMTUD state to 0 so the next discovery ping burst re-probes
    /// all sizes. Mirrors Go's `resetEndpointStates` clearing per-endpoint
    /// PMTU values.
    pub fn reset_peer_mtu(&mut self) {
        self.peer_mtu = 0;
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

    /// Clear the DERP route for this peer (e.g. on PeerGone).
    /// Mirrors Go's `removeDerpPeerRoute`
    /// (derp.go:52-59).
    pub fn remove_derp_route(&mut self) {
        self.last_recv_derp_region = 0;
        self.last_recv_derp_at = None;
    }

    /// Number of pending disco pings (for testing PMTUD burst).
    pub fn pending_pings_count(&self) -> usize {
        self.pending_pings.len()
    }

    #[cfg(test)]
    pub fn pending_cli_pings_count(&self) -> usize {
        self.pending_pings
            .values()
            .filter(|ping| ping.cli_request_id.is_some())
            .count()
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
    fn peer_disco_key_update_reports_only_changes() {
        let mut e = ep();
        let original = e.peer_disco_key().clone();
        let now = Instant::now();
        let candidate = sa(1234);
        e.set_candidates(vec![candidate]);
        e.confirm_direct(sa(5678), now);
        e.add_pending_ping(
            [0xaa; 12],
            candidate,
            now,
            DiscoPingPurpose::Discovery,
            0,
            None,
        );

        assert_eq!(e.update_peer_disco_key(original.clone()), None);
        assert_eq!(e.peer_disco_key(), &original);

        let replacement = DiscoPrivate::generate().public();
        assert_eq!(e.update_peer_disco_key(replacement.clone()), Some(original));
        assert_eq!(e.peer_disco_key(), &replacement);
        assert_eq!(e.candidates(), vec![candidate]);
        assert_eq!(e.best_path(now).class(), PathClass::Direct);
        assert_eq!(e.pending_pings_count(), 1);
    }

    #[test]
    fn direct_beats_relay_beats_derp() {
        let mut e = ep();
        let now = Instant::now();

        e.set_relay(sa(4000), 42, NodePrivate::generate().public(), 1);
        assert_eq!(e.best_path(now).class(), PathClass::Relay);

        e.confirm_direct(sa(5000), now);
        assert_eq!(e.best_path(now).class(), PathClass::Direct);
    }

    #[test]
    fn trust_expires_to_relay() {
        let mut e = ep();
        let now = Instant::now();
        e.set_relay(sa(4000), 42, NodePrivate::generate().public(), 1);
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
        e.add_pending_ping(tx, addr, now, DiscoPingPurpose::Discovery, 0, None);
        let pp = e.match_pong(&tx).expect("should match");
        assert_eq!(pp.addr, addr);
        assert_eq!(pp.purpose, DiscoPingPurpose::Discovery);
        // Second match returns None.
        assert_eq!(e.match_pong(&tx), None);
    }

    #[test]
    fn recording_new_pings_can_expire_stale_transactions() {
        let mut e = ep();
        let now = Instant::now();
        e.add_pending_ping(
            [0xaa; 12],
            sa(1234),
            now,
            DiscoPingPurpose::Discovery,
            0,
            None,
        );
        e.expire_pending_pings(now + Duration::from_secs(5), Duration::from_secs(5));
        assert_eq!(e.pending_pings_count(), 0);
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
    fn learned_candidate_is_deduplicated_and_bounded() {
        let mut e = ep();
        let learned = sa(4242);
        assert!(e.learn_candidate(learned));
        assert!(!e.learn_candidate(learned));
        assert_eq!(e.candidates(), vec![learned]);

        for port in 10_000..10_099 {
            assert!(e.learn_candidate(sa(port)));
        }
        assert_eq!(e.candidates().len(), 100);
        assert!(!e.learn_candidate(sa(20_000)));
    }

    #[test]
    fn full_discovery_is_rate_limited() {
        let mut e = ep();
        let now = Instant::now();
        let interval = Duration::from_secs(5);
        assert!(e.should_start_discovery(now, interval));
        assert!(!e.should_start_discovery(now + Duration::from_secs(1), interval));
        assert!(e.should_start_discovery(now + interval, interval));
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
    fn tx_activity_reports_inactive_to_active_transition_and_refreshes_timestamp() {
        let mut e = ep();
        let now = Instant::now();
        let timeout = Duration::from_secs(45);

        // No prior TX is inactive and starts a session.
        assert!(e.note_tx_activity_transition(now, timeout));
        assert_eq!(e.last_send_ext(), Some(now));

        // Recent TX remains active, but every send refreshes the timestamp.
        let recent = now + Duration::from_secs(1);
        assert!(!e.note_tx_activity_transition(recent, timeout));
        assert_eq!(e.last_send_ext(), Some(recent));

        // The timeout boundary is inactive because activity is strictly less
        // than the timeout, and therefore starts a new session.
        let boundary = recent + timeout;
        assert!(e.note_tx_activity_transition(boundary, timeout));
        assert_eq!(e.last_send_ext(), Some(boundary));

        // A stale timestamp likewise starts a new session and is refreshed.
        let stale = boundary + timeout + Duration::from_nanos(1);
        assert!(e.note_tx_activity_transition(stale, timeout));
        assert_eq!(e.last_send_ext(), Some(stale));
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

    #[test]
    fn link_reset_makes_next_tx_inactive_to_active() {
        let mut e = ep();
        let now = Instant::now();
        let timeout = Duration::from_secs(45);

        assert!(e.note_tx_activity_transition(now, timeout));
        e.reset_for_link_change();
        assert_eq!(e.last_send_ext(), None);
        assert!(e.note_tx_activity_transition(now + Duration::from_secs(1), timeout));
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
            None,
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
            None,
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

    // ---- EndpointType ranking tests ----

    #[test]
    fn endpoint_type_ranking_order() {
        assert!(EndpointType::Local.rank() > EndpointType::Portmapped.rank());
        assert!(EndpointType::Portmapped.rank() > EndpointType::Stun4LocalPort.rank());
        assert!(EndpointType::Stun4LocalPort.rank() > EndpointType::Stun.rank());
        assert!(EndpointType::Stun.rank() > EndpointType::ExplicitConf.rank());
        assert!(EndpointType::ExplicitConf.rank() > EndpointType::Unknown.rank());
    }

    #[test]
    fn ranked_candidates_sorts_by_type() {
        let mut e = ep();
        e.set_candidates_typed(vec![
            (sa(1000), EndpointType::Stun),
            (sa(2000), EndpointType::Local),
            (sa(3000), EndpointType::Portmapped),
            (sa(4000), EndpointType::Unknown),
        ]);

        let ranked = e.ranked_candidates();
        assert_eq!(ranked[0].0, sa(2000)); // Local
        assert_eq!(ranked[0].1, EndpointType::Local);
        assert_eq!(ranked[1].0, sa(3000)); // Portmapped
        assert_eq!(ranked[1].1, EndpointType::Portmapped);
        assert_eq!(ranked[2].0, sa(1000)); // Stun
        assert_eq!(ranked[2].1, EndpointType::Stun);
        assert_eq!(ranked[3].0, sa(4000)); // Unknown
        assert_eq!(ranked[3].1, EndpointType::Unknown);
    }

    #[test]
    fn candidates_typed_preserves_types() {
        let mut e = ep();
        e.set_candidates_typed(vec![
            (sa(1000), EndpointType::Stun),
            (sa(2000), EndpointType::Local),
        ]);
        let typed = e.candidates_typed();
        assert_eq!(typed.len(), 2);
        assert_eq!(typed[0].1, EndpointType::Stun);
        assert_eq!(typed[1].1, EndpointType::Local);

        // candidates() still returns just addresses.
        let addrs = e.candidates();
        assert_eq!(addrs, vec![sa(1000), sa(2000)]);
    }

    // ---- DerpRoute timer expiry tests ----

    #[test]
    fn derp_route_expires_after_timeout() {
        let mut e = ep();
        // Set a DERP route.
        e.set_last_recv_derp_region(5);
        assert!(e.derp_route_valid());
        assert_eq!(e.derp_send_region(), 5);

        // Simulate expiry: manually set the timestamp to the past.
        let stale = Instant::now()
            .checked_sub(DERP_ROUTE_CLEANUP_TIMEOUT)
            .unwrap()
            .checked_sub(Duration::from_secs(1))
            .unwrap();
        e.last_recv_derp_at = Some(stale);

        // Now the route is no longer valid.
        assert!(!e.derp_route_valid());

        // derp_send_region falls back to home_derp (which is 1).
        assert_eq!(e.derp_send_region(), 1);

        // expire_derp_route_if_stale clears it.
        e.expire_derp_route_if_stale();
        assert_eq!(e.last_recv_derp_region_for_debug(), 0);
    }

    #[test]
    fn derp_route_remove_clears_state() {
        let mut e = ep();
        e.set_last_recv_derp_region(7);
        assert!(e.derp_route_valid());
        assert_eq!(e.derp_send_region(), 7);

        e.remove_derp_route();
        assert!(!e.derp_route_valid());
        assert_eq!(e.last_recv_derp_region_for_debug(), 0);
        // Falls back to home_derp.
        assert_eq!(e.derp_send_region(), 1);
    }

    #[test]
    fn derp_route_reset_on_link_change() {
        let mut e = ep();
        e.set_last_recv_derp_region(3);
        assert!(e.derp_route_valid());

        e.reset_for_link_change();
        assert!(!e.derp_route_valid());
        assert_eq!(e.last_recv_derp_region_for_debug(), 0);
    }

    // ---- CallMeMaybe retriggering tests ----

    #[test]
    fn call_me_maybe_retriggers_on_trust_expiry() {
        let mut e = ep();
        let now = Instant::now();

        // Simulate having sent CallMeMaybe and confirmed a direct path.
        assert!(e.should_send_call_me_maybe());
        e.confirm_direct(sa(5000), now);

        // Trust still valid — no retrigger.
        assert!(!e.maybe_retrigger_call_me_maybe(now));

        // After trust expires — retrigger.
        let later = now + TRUST_BEST_ADDR_DURATION + Duration::from_millis(1);
        assert!(e.maybe_retrigger_call_me_maybe(later));

        // Now should_send_call_me_maybe returns true again.
        assert!(e.should_send_call_me_maybe());
    }

    #[test]
    fn call_me_maybe_no_retrigger_when_not_sent() {
        let mut e = ep();
        let now = Instant::now();
        e.confirm_direct(sa(5000), now);

        // CallMeMaybe was never sent, so even after trust expiry
        // there's nothing to retrigger.
        let later = now + TRUST_BEST_ADDR_DURATION + Duration::from_millis(1);
        assert!(!e.maybe_retrigger_call_me_maybe(later));
    }
}
