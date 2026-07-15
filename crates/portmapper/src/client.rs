//! The port mapping [`Client`] facade.
//!
//! Mirrors Go's `portmapper.Client`: [`Client::probe`] detects which
//! protocols the gateway supports (PMP/PCP/UPnP), and
//! [`Client::get_cached_mapping_or_start_creating_one`] returns a cached
//! mapping or kicks off background creation. [`Client::create_or_get_mapping`]
//! does the synchronous create/renew work. The last working method is
//! cached and renewed at half-lifetime.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::time::timeout;

use rustscale_deephash::{update as deephash_update, Sum};
use rustscale_neterror::treat_as_lost_udp;

use crate::gateway::{likely_home_router_ip, GatewayInfo};
use crate::pcp;
use crate::pmp;
use crate::upnp;

/// Which kind of port mapping was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingKind {
    /// NAT-PMP (RFC 6886).
    Pmp,
    /// PCP (RFC 6887).
    Pcp,
    /// UPnP IGD.
    Upnp,
}

impl std::fmt::Display for MappingKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pmp => write!(f, "pmp"),
            Self::Pcp => write!(f, "pcp"),
            Self::Upnp => write!(f, "upnp"),
        }
    }
}

/// An active port mapping: the external `ip:port` and its lease timing.
#[derive(Debug, Clone)]
pub struct Mapping {
    /// The external endpoint reachable from the internet.
    pub external: SocketAddr,
    /// Which protocol produced this mapping.
    pub kind: MappingKind,
    /// When the mapping expires and must be renewed or recreated.
    pub good_until: Instant,
    /// The earliest time we should try to renew (half-lifetime).
    pub renew_after: Instant,
}

impl Mapping {
    /// Whether this mapping is still valid (hasn't expired).
    pub fn is_valid(&self) -> bool {
        Instant::now() < self.good_until
    }

    /// Whether this mapping should be renewed now (past renew_after).
    pub fn needs_renewal(&self) -> bool {
        Instant::now() >= self.renew_after
    }
}

/// Result of probing the gateway for supported port-mapping protocols.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProbeResult {
    /// NAT-PMP is available.
    pub pmp: bool,
    /// PCP is available.
    pub pcp: bool,
    /// UPnP IGD is available.
    pub upnp: bool,
}

impl ProbeResult {
    /// Whether any port-mapping service was detected.
    pub fn any(&self) -> bool {
        self.pmp || self.pcp || self.upnp
    }
}

/// Configuration for constructing a [`Client`].
#[derive(Default)]
pub struct ClientConfig {
    /// Optional gateway lookup override (for testing). If `None`, the real
    /// `likely_home_router_ip` is used.
    pub gateway_lookup: Option<Box<dyn Fn() -> Option<GatewayInfo> + Send + Sync>>,
}

/// A port mapping client. Cheap to clone (all state is behind `Arc`).
#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

struct ClientInner {
    gateway_lookup: RwLock<Box<dyn Fn() -> Option<GatewayInfo> + Send + Sync>>,
    local_port: RwLock<u16>,
    /// Test override for the PMP/PCP port (0 = use default 5351).
    test_pxp_port: AtomicU16,
    /// Test override for the UPnP port (0 = use default 1900).
    test_upnp_port: AtomicU16,
    state: Mutex<ClientState>,
    next_gateway_observation: AtomicU64,
    running_create: AtomicBool,
    closed: AtomicBool,
}

#[derive(Default)]
struct ClientState {
    /// The current active mapping, if any.
    mapping: Option<Mapping>,
    /// When we last probed.
    last_probe: Option<Instant>,
    /// PMP: the external IP learned from the public-addr response.
    pmp_pub_ip: Option<Ipv4Addr>,
    /// PMP: when the pub IP was last verified.
    pmp_pub_ip_time: Option<Instant>,
    /// PCP: when we last saw PCP was available.
    pcp_saw_time: Option<Instant>,
    /// UPnP: when we last saw UPnP was available.
    upnp_saw_time: Option<Instant>,
    /// UPnP: cached discovery responses (Location -> UpnpService).
    upnp_services: HashMap<String, upnp::UpnpService>,
    /// Hash and identity of the last gateway/self-IP observation.
    gw_hash: Sum,
    gateway: Option<GatewayInfo>,
    /// Monotonic epoch for gateway changes and mapping invalidations. Async
    /// work may only commit results captured in the current generation.
    gateway_generation: u64,
    /// Sequence of the latest gateway lookup to finish. This prevents an
    /// older, slow lookup from overwriting a newer observation.
    gateway_observation: u64,
    /// Whether this gateway generation still needs a full protocol probe.
    needs_probe: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GatewaySnapshot {
    info: Option<GatewayInfo>,
    generation: u64,
}

impl Client {
    /// Create a new port mapping client with default gateway detection.
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(ClientConfig::default())
    }

    /// Create a client with custom configuration.
    #[must_use]
    pub fn with_config(config: ClientConfig) -> Self {
        let gateway_lookup: Box<dyn Fn() -> Option<GatewayInfo> + Send + Sync> = config
            .gateway_lookup
            .unwrap_or_else(|| Box::new(likely_home_router_ip));
        Self {
            inner: Arc::new(ClientInner {
                gateway_lookup: RwLock::new(gateway_lookup),
                local_port: RwLock::new(0),
                test_pxp_port: AtomicU16::new(0),
                test_upnp_port: AtomicU16::new(0),
                state: Mutex::new(ClientState::default()),
                next_gateway_observation: AtomicU64::new(0),
                running_create: AtomicBool::new(false),
                closed: AtomicBool::new(false),
            }),
        }
    }

    /// Override the gateway lookup function (for testing).
    pub fn set_gateway_lookup(&self, f: Box<dyn Fn() -> Option<GatewayInfo> + Send + Sync>) {
        *self.inner.gateway_lookup.write().expect("gw lock") = f;
    }

    /// Set the local UDP port to map.
    pub fn set_local_port(&self, port: u16) {
        let mut p = self.inner.local_port.write().expect("port lock");
        if *p != port {
            *p = port;
            self.invalidate_mappings(true);
        }
    }

    /// Override the PMP/PCP port (for testing).
    #[cfg(test)]
    pub(crate) fn set_test_pxp_port(&self, port: u16) {
        self.inner.test_pxp_port.store(port, Ordering::Relaxed);
    }

    /// Override the UPnP port (for testing).
    #[cfg(test)]
    pub(crate) fn set_test_upnp_port(&self, port: u16) {
        self.inner.test_upnp_port.store(port, Ordering::Relaxed);
    }

    fn pxp_port(&self) -> u16 {
        let p = self.inner.test_pxp_port.load(Ordering::Relaxed);
        if p != 0 {
            p
        } else {
            crate::PXP_PORT
        }
    }

    fn upnp_port(&self) -> u16 {
        let p = self.inner.test_upnp_port.load(Ordering::Relaxed);
        if p != 0 {
            p
        } else {
            crate::UPNP_PORT
        }
    }

    fn observe_gateway(&self) -> GatewaySnapshot {
        // Number the lookup before running it. If this lookup stalls while a
        // newer one completes, its stale result is discarded below.
        let observation = self
            .inner
            .next_gateway_observation
            .fetch_add(1, Ordering::SeqCst)
            .checked_add(1)
            .expect("gateway observation counter overflow");
        let info = (self.inner.gateway_lookup.read().expect("gw lock"))();

        let (snapshot, old_mapping) = {
            let mut state = self.inner.state.lock().expect("state lock");
            if observation <= state.gateway_observation {
                (
                    GatewaySnapshot {
                        info: state.gateway,
                        generation: state.gateway_generation,
                    },
                    None,
                )
            } else {
                state.gateway_observation = observation;
                let identity_changed = state.gateway != info;
                let hash_changed = deephash_update(&mut state.gw_hash, &info);
                let old_mapping = if identity_changed || hash_changed {
                    state.gateway_generation = state
                        .gateway_generation
                        .checked_add(1)
                        .expect("gateway generation overflow");
                    state.gateway = info;
                    state.needs_probe = info.is_some();
                    Self::reset_mapping_state(&mut state)
                } else {
                    None
                };
                (
                    GatewaySnapshot {
                        info: state.gateway,
                        generation: state.gateway_generation,
                    },
                    old_mapping,
                )
            }
        };

        if let Some(mapping) = old_mapping {
            self.release_mapping(&mapping);
        }
        snapshot
    }

    fn gateway_and_self_ip(&self) -> Option<GatewayInfo> {
        self.observe_gateway().info
    }

    fn invalidate_mappings(&self, release: bool) {
        let old_mapping = {
            let mut state = self.inner.state.lock().expect("state lock");
            state.gateway_generation = state
                .gateway_generation
                .checked_add(1)
                .expect("gateway generation overflow");
            state.needs_probe = state.gateway.is_some();
            Self::reset_mapping_state(&mut state)
        };
        if release {
            if let Some(mapping) = old_mapping {
                self.release_mapping(&mapping);
            }
        }
    }

    fn reset_mapping_state(state: &mut ClientState) -> Option<Mapping> {
        let old_mapping = state.mapping.take();
        state.last_probe = None;
        state.pmp_pub_ip = None;
        state.pmp_pub_ip_time = None;
        state.pcp_saw_time = None;
        state.upnp_saw_time = None;
        state.upnp_services.clear();
        old_mapping
    }

    fn with_current_gateway<R>(
        &self,
        snapshot: GatewaySnapshot,
        f: impl FnOnce(&mut ClientState) -> R,
    ) -> Option<R> {
        let mut state = self.inner.state.lock().expect("state lock");
        if state.gateway_generation != snapshot.generation || state.gateway != snapshot.info {
            return None;
        }
        Some(f(&mut state))
    }

    fn release_mapping(&self, mapping: &Mapping) {
        let client = self.clone();
        let m = mapping.clone();
        tokio::spawn(async move {
            client.do_release(&m).await;
        });
    }

    async fn do_release(&self, mapping: &Mapping) {
        let gi = match self.gateway_and_self_ip() {
            Some(gi) => gi,
            None => return,
        };
        match mapping.kind {
            MappingKind::Pmp | MappingKind::Pcp => {
                let sock = match UdpSocket::bind("0.0.0.0:0").await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let dst = SocketAddr::V4(SocketAddrV4::new(gi.gateway, self.pxp_port()));
                let pkt =
                    pmp::build_delete_request(mapping.external.port(), mapping.external.port());
                let _ = sock.send_to(&pkt, dst).await;
            }
            MappingKind::Upnp => {
                // Clone the service out of the lock before awaiting.
                let svc = {
                    let state = self.inner.state.lock().expect("state lock");
                    state.upnp_services.values().next().cloned()
                };
                if let Some(svc) = svc {
                    upnp::delete_port_mapping(
                        &svc,
                        mapping.external.port(),
                        Duration::from_secs(1),
                    )
                    .await;
                }
            }
        }
    }

    /// Close the client and release any active mapping.
    pub fn close(&self) {
        if self.inner.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.invalidate_mappings(true);
    }

    /// Whether we have a valid (non-expired) cached mapping.
    pub fn have_mapping(&self) -> bool {
        let snapshot = self.observe_gateway();
        if snapshot.info.is_none() {
            return false;
        }
        self.with_current_gateway(snapshot, |state| {
            state.mapping.as_ref().is_some_and(Mapping::is_valid)
        })
        .unwrap_or(false)
    }

    /// Get the cached mapping if it's still valid, or start creating one in
    /// the background. Returns `(Some(external), true)` if a valid cached
    /// mapping exists, `(None, false)` otherwise.
    ///
    /// Mirrors Go's `GetCachedMappingOrStartCreatingOne`.
    pub fn get_cached_mapping_or_start_creating_one(&self) -> (Option<SocketAddr>, bool) {
        // Validate the gateway before returning an external address. This is
        // the path magicsock uses while gathering advertised endpoints, so a
        // lost default route must hide and invalidate the old mapping at once.
        let snapshot = self.observe_gateway();
        if snapshot.info.is_none() {
            return (None, false);
        }

        let Some(cached) = self.with_current_gateway(snapshot, |state| {
            state
                .mapping
                .as_ref()
                .filter(|m| m.is_valid())
                .map(|m| (m.external, m.needs_renewal()))
        }) else {
            return (None, false);
        };
        if let Some((external, needs_renewal)) = cached {
            if needs_renewal {
                self.maybe_start_create();
            }
            return (Some(external), true);
        }
        self.maybe_start_create();
        (None, false)
    }

    fn maybe_start_create(&self) {
        if self.inner.running_create.swap(true, Ordering::SeqCst) {
            return;
        }
        let client = self.clone();
        tokio::spawn(async move {
            let started_generation = client.current_gateway_state().0;
            let _ = client.create_or_get_mapping().await;
            client.inner.running_create.store(false, Ordering::SeqCst);

            // If this worker crossed a gateway invalidation, a cache read may
            // have seen running_create=true and declined to launch the fresh
            // worker. Close that handoff race after publishing false.
            let (current_generation, gateway_available) = client.current_gateway_state();
            if gateway_available
                && current_generation != started_generation
                && !client.inner.closed.load(Ordering::Relaxed)
            {
                client.maybe_start_create();
            }
        });
    }

    fn current_gateway_state(&self) -> (u64, bool) {
        let state = self.inner.state.lock().expect("state lock");
        (state.gateway_generation, state.gateway.is_some())
    }

    /// Probe the gateway for supported port-mapping protocols. Sends PMP,
    /// PCP, and UPnP probes in parallel on a shared socket and collects
    /// responses within `probe_timeout` (250 ms by default).
    pub async fn probe(&self) -> Result<ProbeResult, crate::PortMapError> {
        if self.inner.closed.load(Ordering::Relaxed) {
            return Err(crate::PortMapError::Disabled);
        }
        let snapshot = self.observe_gateway();
        snapshot.info.ok_or(crate::PortMapError::GatewayRange)?;
        self.probe_with_snapshot(snapshot).await
    }

    async fn probe_with_snapshot(
        &self,
        snapshot: GatewaySnapshot,
    ) -> Result<ProbeResult, crate::PortMapError> {
        let gi = snapshot.info.ok_or(crate::PortMapError::GatewayRange)?;
        if self.with_current_gateway(snapshot, |_| ()).is_none() {
            return Err(crate::PortMapError::GatewayRange);
        }
        let pxp_port = self.pxp_port();
        let upnp_port = self.upnp_port();

        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        let pxp_addr = SocketAddr::V4(SocketAddrV4::new(gi.gateway, pxp_port));
        let upnp_unicast = SocketAddr::V4(SocketAddrV4::new(gi.gateway, upnp_port));
        let upnp_multicast = SocketAddr::V4(SocketAddrV4::new(crate::SSDP_MULTICAST, upnp_port));

        // Send all probes.
        let pmp_pkt = pmp::build_external_addr_request();
        let _ = sock.send_to(&pmp_pkt, pxp_addr).await;
        let pcp_pkt = pcp::build_announce_request(gi.self_ip);
        let _ = sock.send_to(&pcp_pkt, pxp_addr).await;
        let upnp_all = upnp::ssdp_packet();
        let upnp_igd = upnp::ssdp_igd_packet();
        let _ = sock.send_to(&upnp_all, upnp_unicast).await;
        let _ = sock.send_to(&upnp_all, upnp_multicast).await;
        let _ = sock.send_to(&upnp_igd, upnp_multicast).await;

        // Collect responses in a single loop.
        let deadline = Instant::now() + crate::PROBE_TIMEOUT;
        let mut buf = [0u8; 1500];
        let mut result = ProbeResult::default();
        let mut upnp_disco_responses: Vec<upnp::UpnpDiscoResponse> = Vec::new();

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match timeout(remaining, sock.recv_from(&mut buf)).await {
                Ok(Ok((n, src))) => {
                    let pkt = &buf[..n];
                    if src.port() == upnp_port || upnp::looks_like_igd_response(pkt) {
                        if let Some(resp) = upnp::parse_ssdp_response(pkt) {
                            upnp_disco_responses.push(resp);
                        }
                        continue;
                    }
                    if src.port() == pxp_port {
                        if let Some(pcp_resp) = pcp::parse_common_header(pkt) {
                            if pcp_resp.op_code == pcp::PCP_OP_REPLY | pcp::PCP_OP_ANNOUNCE {
                                result.pcp = true;
                                if self
                                    .with_current_gateway(snapshot, |state| {
                                        state.pcp_saw_time = Some(Instant::now());
                                    })
                                    .is_none()
                                {
                                    return Err(crate::PortMapError::GatewayRange);
                                }
                                continue;
                            }
                        }
                        if let Some(pmp_resp) = pmp::parse_response(pkt) {
                            if pmp_resp.op_code == pmp::PMP_OP_REPLY | pmp::PMP_OP_MAP_PUBLIC_ADDR
                                && pmp_resp.result_code == 0
                            {
                                result.pmp = true;
                                if self
                                    .with_current_gateway(snapshot, |state| {
                                        state.pmp_pub_ip = pmp_resp.public_addr;
                                        state.pmp_pub_ip_time = Some(Instant::now());
                                    })
                                    .is_none()
                                {
                                    return Err(crate::PortMapError::GatewayRange);
                                }
                                continue;
                            }
                        }
                    }
                }
                _ => break,
            }
        }

        // Process UPnP discovery responses: fetch root-desc and cache services.
        if !upnp_disco_responses.is_empty() {
            let deduped = upnp::process_responses(upnp_disco_responses);
            for resp in &deduped {
                if let Some(svc) =
                    upnp::fetch_and_select_service(&resp.location, Duration::from_secs(1)).await
                {
                    if self
                        .with_current_gateway(snapshot, |state| {
                            state.upnp_services.insert(resp.location.clone(), svc);
                            state.upnp_saw_time = Some(Instant::now());
                        })
                        .is_none()
                    {
                        return Err(crate::PortMapError::GatewayRange);
                    }
                    result.upnp = true;
                    break;
                }
            }
        }

        if self
            .with_current_gateway(snapshot, |state| {
                state.last_probe = Some(Instant::now());
                state.needs_probe = false;
            })
            .is_none()
        {
            return Err(crate::PortMapError::GatewayRange);
        }

        Ok(result)
    }

    /// Create or renew a port mapping. Returns the external endpoint if
    /// successful.
    pub async fn create_or_get_mapping(&self) -> Result<Mapping, crate::PortMapError> {
        if self.inner.closed.load(Ordering::Relaxed) {
            return Err(crate::PortMapError::Disabled);
        }

        // Check the gateway before the cache fast path. Otherwise a mapping
        // from a disappeared network can be returned until its lease expires.
        let snapshot = self.observe_gateway();
        let gi = snapshot.info.ok_or(crate::PortMapError::GatewayRange)?;
        let needs_probe = self
            .with_current_gateway(snapshot, |state| state.needs_probe)
            .ok_or(crate::PortMapError::GatewayRange)?;
        if needs_probe {
            // A new or reappeared gateway has no trustworthy protocol cache.
            // Probe PMP, PCP, and UPnP before selecting a mapping method.
            self.probe_with_snapshot(snapshot).await?;
        }

        // Fast path: return cached mapping if valid and not needing renewal.
        if let Some(mapping) = self
            .with_current_gateway(snapshot, |state| {
                state
                    .mapping
                    .as_ref()
                    .filter(|mapping| mapping.is_valid() && !mapping.needs_renewal())
                    .cloned()
            })
            .ok_or(crate::PortMapError::GatewayRange)?
        {
            return Ok(mapping);
        }

        let local_port = *self.inner.local_port.read().expect("port lock");
        if local_port == 0 {
            return Err(crate::PortMapError::NoServices);
        }

        let internal_addr = SocketAddr::V4(SocketAddrV4::new(gi.self_ip, local_port));
        let pxp_port = self.pxp_port();
        let prev_port = self
            .with_current_gateway(snapshot, |state| {
                state.mapping.as_ref().map_or(0, |m| m.external.port())
            })
            .ok_or(crate::PortMapError::GatewayRange)?;

        let (have_recent_pmp, have_recent_pcp, have_recent_upnp) = self
            .with_current_gateway(snapshot, |state| {
                let now = Instant::now();
                (
                    state
                        .pmp_pub_ip_time
                        .is_some_and(|t| now.duration_since(t) < crate::TRUST_DURATION),
                    state
                        .pcp_saw_time
                        .is_some_and(|t| now.duration_since(t) < crate::TRUST_DURATION),
                    state
                        .upnp_saw_time
                        .is_some_and(|t| now.duration_since(t) < crate::TRUST_DURATION),
                )
            })
            .ok_or(crate::PortMapError::GatewayRange)?;

        // Try PMP/PCP first (faster, share port 5351).
        if have_recent_pmp || have_recent_pcp || !have_recent_upnp {
            match self
                .try_pxp_mapping(
                    snapshot,
                    internal_addr,
                    local_port,
                    prev_port,
                    pxp_port,
                    have_recent_pmp,
                    have_recent_pcp,
                )
                .await
            {
                Ok(Some(m)) => return Ok(m),
                Ok(None) => {}
                Err(e) => return Err(e),
            }
        }

        // Fallback to UPnP.
        if have_recent_upnp {
            if let Some(m) = self.try_upnp_mapping(snapshot, local_port, prev_port).await {
                return Ok(m);
            }
        }

        Err(crate::PortMapError::NoServices)
    }

    /// Try to create a mapping via PMP or PCP (they share port 5351).
    #[allow(clippy::too_many_arguments)]
    async fn try_pxp_mapping(
        &self,
        snapshot: GatewaySnapshot,
        _internal_addr: SocketAddr,
        local_port: u16,
        prev_port: u16,
        pxp_port: u16,
        have_recent_pmp: bool,
        have_recent_pcp: bool,
    ) -> Result<Option<Mapping>, crate::PortMapError> {
        let gi = snapshot.info.ok_or(crate::PortMapError::GatewayRange)?;
        if self.with_current_gateway(snapshot, |_| ()).is_none() {
            return Ok(None);
        }
        let sock = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(crate::PortMapError::Io)?;
        let pxp_addr = SocketAddr::V4(SocketAddrV4::new(gi.gateway, pxp_port));

        let prefer_pcp = have_recent_pcp && !have_recent_pmp;

        // Get the cached PMP pub IP (if any) so we don't need to re-request it.
        let cached_pub_ip = match self.with_current_gateway(snapshot, |state| state.pmp_pub_ip) {
            Some(ip) => ip,
            None => return Ok(None),
        };

        if prefer_pcp {
            let pkt = pcp::build_map_request(
                gi.self_ip,
                local_port,
                prev_port,
                crate::MAP_LIFETIME_SECS,
                Ipv4Addr::UNSPECIFIED,
            );
            if let Err(e) = sock.send_to(&pkt, pxp_addr).await {
                if treat_as_lost_udp(&e) {
                    return Err(crate::PortMapError::NoServices);
                }
                return Err(crate::PortMapError::Io(e));
            }
        } else {
            // PMP: request external address first if not cached.
            if cached_pub_ip.is_none() {
                let req = pmp::build_external_addr_request();
                if let Err(e) = sock.send_to(&req, pxp_addr).await {
                    if treat_as_lost_udp(&e) {
                        return Err(crate::PortMapError::NoServices);
                    }
                    return Err(crate::PortMapError::Io(e));
                }
            }
            let pkt = pmp::build_map_request(local_port, prev_port, crate::MAP_LIFETIME_SECS);
            if let Err(e) = sock.send_to(&pkt, pxp_addr).await {
                if treat_as_lost_udp(&e) {
                    return Err(crate::PortMapError::NoServices);
                }
                return Err(crate::PortMapError::Io(e));
            }
        }

        let deadline = Instant::now() + crate::PROBE_TIMEOUT * 4;
        let mut buf = [0u8; 1500];
        let mut pmp_pub_ip = cached_pub_ip;
        let mut pmp_external_port: Option<u16> = None;
        let mut pmp_lifetime_secs: u32 = crate::MAP_LIFETIME_SECS;

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match timeout(remaining, sock.recv_from(&mut buf)).await {
                Ok(Ok((n, src))) => {
                    if src.port() != pxp_port {
                        continue;
                    }
                    let pkt = &buf[..n];

                    // PCP MAP response (60 bytes).
                    if let Some(pcp_resp) = pcp::parse_map_response(pkt) {
                        if pcp_resp.result_code == 0 {
                            let lifetime = Duration::from_secs(u64::from(pcp_resp.lifetime));
                            let now = Instant::now();
                            let mapping = Mapping {
                                external: pcp_resp.external,
                                kind: MappingKind::Pcp,
                                good_until: now + lifetime,
                                renew_after: now + lifetime / 2,
                            };
                            if self
                                .with_current_gateway(snapshot, |state| {
                                    state.mapping = Some(mapping.clone());
                                })
                                .is_none()
                            {
                                return Ok(None);
                            }
                            return Ok(Some(mapping));
                        }
                        return Ok(None);
                    }

                    // PMP response.
                    if let Some(pmp_resp) = pmp::parse_response(pkt) {
                        if pmp_resp.result_code != 0 {
                            return Ok(None);
                        }
                        if pmp_resp.op_code == pmp::PMP_OP_REPLY | pmp::PMP_OP_MAP_PUBLIC_ADDR {
                            pmp_pub_ip = pmp_resp.public_addr;
                        }
                        if pmp_resp.op_code == pmp::PMP_OP_REPLY | pmp::PMP_OP_MAP_UDP {
                            pmp_external_port = Some(pmp_resp.external_port);
                            pmp_lifetime_secs = pmp_resp.mapping_valid_seconds;
                        }
                    }

                    // If we have both pub IP and external port, construct mapping.
                    if let (Some(pub_ip), Some(ext_port)) = (pmp_pub_ip, pmp_external_port) {
                        let lifetime = Duration::from_secs(u64::from(pmp_lifetime_secs));
                        let now = Instant::now();
                        let external = SocketAddr::V4(SocketAddrV4::new(pub_ip, ext_port));
                        let mapping = Mapping {
                            external,
                            kind: MappingKind::Pmp,
                            good_until: now + lifetime,
                            renew_after: now + lifetime / 2,
                        };
                        if self
                            .with_current_gateway(snapshot, |state| {
                                state.pmp_pub_ip = Some(pub_ip);
                                state.pmp_pub_ip_time = Some(now);
                                state.mapping = Some(mapping.clone());
                            })
                            .is_none()
                        {
                            return Ok(None);
                        }
                        return Ok(Some(mapping));
                    }
                }
                _ => break,
            }
        }
        Ok(None)
    }

    /// Try to create a mapping via UPnP.
    async fn try_upnp_mapping(
        &self,
        snapshot: GatewaySnapshot,
        local_port: u16,
        prev_port: u16,
    ) -> Option<Mapping> {
        let gi = snapshot.info?;
        let services: Vec<upnp::UpnpService> = self.with_current_gateway(snapshot, |state| {
            state.upnp_services.values().cloned().collect()
        })?;
        if services.is_empty() {
            return None;
        }

        let internal_client = gi.self_ip.to_string();
        let deadline = Duration::from_secs(2);

        for svc in &services {
            let ext_port = match upnp::add_port_mapping(
                svc,
                &internal_client,
                local_port,
                prev_port,
                crate::MAP_LIFETIME_SECS,
                deadline,
            )
            .await
            {
                Ok(p) => p,
                Err(_) => continue,
            };

            let ext_ip = match upnp::get_external_ip(svc, deadline).await {
                Ok(ip) => ip,
                Err(_) => continue,
            };

            let now = Instant::now();
            let lifetime = Duration::from_secs(u64::from(crate::MAP_LIFETIME_SECS));
            let mapping = Mapping {
                external: SocketAddr::V4(SocketAddrV4::new(ext_ip, ext_port)),
                kind: MappingKind::Upnp,
                good_until: now + lifetime,
                renew_after: now + lifetime / 2,
            };
            self.with_current_gateway(snapshot, |state| {
                state.mapping = Some(mapping.clone());
            })?;
            return Some(mapping);
        }
        None
    }

    /// Get the cached mapping, if any (without starting creation).
    pub fn cached_mapping(&self) -> Option<Mapping> {
        let snapshot = self.observe_gateway();
        snapshot.info?;
        self.with_current_gateway(snapshot, |state| state.mapping.clone())
            .flatten()
    }
}

#[allow(clippy::derivable_impls)]
impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}
// ClientInner contains a Box<dyn Fn()> which doesn't implement Default, so
// a manual impl is required even though clippy thinks it can be derived.

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc, Mutex};
    use std::time::{Duration, Instant};

    use super::{Client, ClientConfig, GatewayInfo, Mapping, MappingKind};
    use crate::upnp::UpnpService;

    fn test_mapping(external: SocketAddr) -> Mapping {
        let now = Instant::now();
        Mapping {
            external,
            kind: MappingKind::Pcp,
            good_until: now + Duration::from_secs(3600),
            renew_after: now + Duration::from_secs(1800),
        }
    }

    fn seed_mapping_state(client: &Client, external: SocketAddr) {
        let now = Instant::now();
        let mut state = client.inner.state.lock().unwrap();
        state.mapping = Some(test_mapping(external));
        state.last_probe = Some(now);
        state.pmp_pub_ip = Some(Ipv4Addr::new(198, 51, 100, 10));
        state.pmp_pub_ip_time = Some(now);
        state.pcp_saw_time = Some(now);
        state.upnp_saw_time = Some(now);
        state.upnp_services.insert(
            "router".into(),
            UpnpService {
                control_url: "http://192.168.1.1/control".into(),
                kind: 0,
            },
        );
    }

    fn assert_mapping_state_empty(client: &Client) {
        let state = client.inner.state.lock().unwrap();
        assert!(state.mapping.is_none());
        assert!(state.last_probe.is_none());
        assert!(state.pmp_pub_ip.is_none());
        assert!(state.pmp_pub_ip_time.is_none());
        assert!(state.pcp_saw_time.is_none());
        assert!(state.upnp_saw_time.is_none());
        assert!(state.upnp_services.is_empty());
    }

    #[test]
    fn gateway_deephash_detects_changes() {
        let first_gateway = GatewayInfo {
            gateway: Ipv4Addr::new(192, 168, 1, 1),
            self_ip: Ipv4Addr::new(192, 168, 1, 2),
        };
        let client = Client::with_config(ClientConfig {
            gateway_lookup: Some(Box::new(move || Some(first_gateway))),
        });

        client.gateway_and_self_ip();
        let first_hash = client.inner.state.lock().unwrap().gw_hash;

        client.gateway_and_self_ip();
        assert_eq!(client.inner.state.lock().unwrap().gw_hash, first_hash);

        client.set_gateway_lookup(Box::new(|| {
            Some(GatewayInfo {
                gateway: Ipv4Addr::new(10, 0, 0, 1),
                self_ip: Ipv4Addr::new(10, 0, 0, 2),
            })
        }));
        client.gateway_and_self_ip();
        assert_ne!(client.inner.state.lock().unwrap().gw_hash, first_hash);
    }

    #[tokio::test]
    async fn missing_gateway_clears_mapping_and_is_stable() {
        let gateway = GatewayInfo {
            gateway: Ipv4Addr::new(192, 168, 1, 1),
            self_ip: Ipv4Addr::new(192, 168, 1, 2),
        };
        let client = Client::with_config(ClientConfig {
            gateway_lookup: Some(Box::new(move || Some(gateway))),
        });
        assert_eq!(client.gateway_and_self_ip(), Some(gateway));

        let external = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 10), 41641));
        seed_mapping_state(&client, external);

        client.set_gateway_lookup(Box::new(|| None));

        // This is the cache API used by magicsock endpoint advertisement.
        // It must never return the old external endpoint after route loss.
        assert_eq!(
            client.get_cached_mapping_or_start_creating_one(),
            (None, false)
        );
        assert_mapping_state_empty(&client);
        let (none_hash, none_generation) = {
            let state = client.inner.state.lock().unwrap();
            (state.gw_hash, state.gateway_generation)
        };
        assert!(!client.inner.running_create.load(Ordering::SeqCst));

        // Repeated route-loss observations are hash-stable, do not launch a
        // futile creation task, and still cannot expose a cached endpoint.
        assert_eq!(
            client.get_cached_mapping_or_start_creating_one(),
            (None, false)
        );
        let state = client.inner.state.lock().unwrap();
        assert_eq!(state.gw_hash, none_hash);
        assert_eq!(state.gateway_generation, none_generation);
        drop(state);
        assert!(!client.inner.running_create.load(Ordering::SeqCst));
        assert!(client.cached_mapping().is_none());
    }

    #[tokio::test]
    async fn stale_async_completion_cannot_repopulate_invalidated_generation() {
        let gateway = GatewayInfo {
            gateway: Ipv4Addr::new(192, 168, 1, 1),
            self_ip: Ipv4Addr::new(192, 168, 1, 2),
        };
        let client = Client::with_config(ClientConfig {
            gateway_lookup: Some(Box::new(move || Some(gateway))),
        });
        let stale_snapshot = client.observe_gateway();
        assert_eq!(stale_snapshot.info, Some(gateway));

        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (resume_tx, resume_rx) = tokio::sync::oneshot::channel();
        let stale_client = client.clone();
        let stale_commit = tokio::spawn(async move {
            ready_tx.send(()).unwrap();
            resume_rx.await.unwrap();
            stale_client.with_current_gateway(stale_snapshot, |state| {
                let now = Instant::now();
                state.mapping = Some(test_mapping(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(203, 0, 113, 9),
                    41641,
                ))));
                state.last_probe = Some(now);
                state.pmp_pub_ip = Some(Ipv4Addr::new(203, 0, 113, 9));
                state.pmp_pub_ip_time = Some(now);
                state.pcp_saw_time = Some(now);
                state.upnp_saw_time = Some(now);
                state.upnp_services.insert(
                    "stale-router".into(),
                    UpnpService {
                        control_url: "http://192.168.1.1/stale".into(),
                        kind: 0,
                    },
                );
            })
        });

        ready_rx.await.unwrap();
        client.set_gateway_lookup(Box::new(|| None));
        let missing = client.observe_gateway();
        assert!(missing.info.is_none());
        assert!(missing.generation > stale_snapshot.generation);
        assert_mapping_state_empty(&client);

        let new_gateway = GatewayInfo {
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            self_ip: Ipv4Addr::new(10, 0, 0, 2),
        };
        client.set_gateway_lookup(Box::new(move || Some(new_gateway)));
        let current = client.observe_gateway();
        assert_eq!(current.info, Some(new_gateway));
        assert!(current.generation > missing.generation);

        resume_tx.send(()).unwrap();
        assert!(stale_commit.await.unwrap().is_none());
        assert_mapping_state_empty(&client);
        let state = client.inner.state.lock().unwrap();
        assert_eq!(state.gateway, Some(new_gateway));
        assert!(state.needs_probe);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn newer_gateway_observation_closes_cache_read_gap() {
        let gateway = GatewayInfo {
            gateway: Ipv4Addr::new(192, 168, 1, 1),
            self_ip: Ipv4Addr::new(192, 168, 1, 2),
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let (lookup_started_tx, lookup_started_rx) = mpsc::sync_channel(1);
        let (resume_lookup_tx, resume_lookup_rx) = mpsc::sync_channel(1);
        let resume_lookup_rx = Arc::new(Mutex::new(resume_lookup_rx));
        let client = Client::with_config(ClientConfig {
            gateway_lookup: Some(Box::new({
                let calls = calls.clone();
                let resume_lookup_rx = resume_lookup_rx.clone();
                move || match calls.fetch_add(1, Ordering::SeqCst) {
                    0 => Some(gateway),
                    1 => {
                        lookup_started_tx.send(()).unwrap();
                        resume_lookup_rx.lock().unwrap().recv().unwrap();
                        Some(gateway)
                    }
                    _ => None,
                }
            })),
        });
        let initial = client.observe_gateway();
        assert_eq!(initial.info, Some(gateway));
        let external = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 41641));
        seed_mapping_state(&client, external);

        let reader_client = client.clone();
        let reader =
            std::thread::spawn(move || reader_client.get_cached_mapping_or_start_creating_one());
        lookup_started_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap();

        // A newer lookup observes route loss and atomically advances the
        // generation plus clears state while the older lookup is paused.
        let missing = client.observe_gateway();
        assert!(missing.info.is_none());
        assert!(missing.generation > initial.generation);
        assert_mapping_state_empty(&client);

        resume_lookup_tx.send(()).unwrap();
        assert_eq!(reader.join().unwrap(), (None, false));
        let state = client.inner.state.lock().unwrap();
        assert!(state.gateway.is_none());
        assert_eq!(state.gateway_generation, missing.generation);
        assert!(state.mapping.is_none());
    }
}
