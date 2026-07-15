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
use tokio::task::JoinSet;
use tokio::time::timeout;

use rustscale_deephash::{update as deephash_update, Sum};
use rustscale_neterror::treat_as_lost_udp;

use crate::gateway::{likely_home_router_ip, GatewayInfo};
use crate::pcp;
use crate::pmp;
use crate::upnp;

async fn bind_underlay_udp() -> std::io::Result<UdpSocket> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    rustscale_netns::configure_udp_socket(&socket)?;
    Ok(socket)
}

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
        self.is_valid_at(Instant::now())
    }

    /// Whether this mapping should be renewed now (past renew_after).
    pub fn needs_renewal(&self) -> bool {
        self.needs_renewal_at(Instant::now())
    }

    fn is_valid_at(&self, now: Instant) -> bool {
        now < self.good_until
    }

    fn needs_renewal_at(&self, now: Instant) -> bool {
        now >= self.renew_after
    }
}

#[derive(Clone)]
struct CachedMapping {
    ownership_id: u64,
    mapping: Mapping,
    #[cfg_attr(not(test), allow(dead_code))]
    generation: u64,
    release: ReleaseIdentity,
    lease_expires: Option<Instant>,
}

#[derive(Clone)]
enum ReleaseIdentity {
    Pmp {
        destination: SocketAddr,
        internal_port: u16,
    },
    Pcp {
        destination: SocketAddr,
        self_ip: Ipv4Addr,
        internal_port: u16,
        nonce: pcp::PcpNonce,
    },
    Upnp {
        service: upnp::UpnpService,
    },
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

#[cfg(test)]
pub(crate) struct ReleaseTestGate {
    reached: tokio::sync::Barrier,
    resume: tokio::sync::Barrier,
}

#[cfg(test)]
impl ReleaseTestGate {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            reached: tokio::sync::Barrier::new(2),
            resume: tokio::sync::Barrier::new(2),
        })
    }

    pub(crate) async fn wait_reached(&self) {
        self.reached.wait().await;
    }

    pub(crate) async fn resume(&self) {
        self.resume.wait().await;
    }
}

#[cfg(test)]
pub(crate) type SendTestGate = ReleaseTestGate;

struct ClientInner {
    gateway_lookup: RwLock<Box<dyn Fn() -> Option<GatewayInfo> + Send + Sync>>,
    local_port: RwLock<u16>,
    /// Test override for the PMP/PCP port (0 = use default 5351).
    test_pxp_port: AtomicU16,
    /// Test override for the UPnP port (0 = use default 1900).
    test_upnp_port: AtomicU16,
    state: Mutex<ClientState>,
    clock: RwLock<Box<dyn Fn() -> Instant + Send + Sync>>,
    next_gateway_observation: AtomicU64,
    next_ownership_id: AtomicU64,
    running_create: AtomicBool,
    work: Mutex<WorkGate>,
    release_progress_tx: tokio::sync::watch::Sender<ReleaseProgress>,
    send_progress_tx: tokio::sync::watch::Sender<u64>,
    #[cfg(test)]
    release_test_gate: Mutex<Option<Arc<ReleaseTestGate>>>,
    #[cfg(test)]
    pre_send_test_gate: Mutex<Option<Arc<SendTestGate>>>,
    #[cfg(test)]
    send_test_gate: Mutex<Option<Arc<SendTestGate>>>,
    #[cfg(test)]
    test_send_error: AtomicBool,
    closed: AtomicBool,
}

struct WorkGate {
    closing: bool,
    pending_releases: u64,
    generation: u64,
    allocation: Option<AllocationFlight>,
    shutdown: Option<ShutdownFlight>,
    send_in_flight: u64,
    send_terminal: bool,
    allocation_tasks: JoinSet<()>,
    probe_tasks: JoinSet<()>,
    release_tasks: JoinSet<()>,
    launcher_tasks: JoinSet<()>,
    shutdown_tasks: JoinSet<()>,
}

struct AllocationFlight {
    generation: u64,
    result: tokio::sync::watch::Sender<Option<Result<Mapping, crate::PortMapError>>>,
}

struct ShutdownFlight {
    result: tokio::sync::watch::Sender<Option<Result<(), crate::PortMapError>>>,
}

impl Default for WorkGate {
    fn default() -> Self {
        Self {
            closing: false,
            pending_releases: 0,
            generation: 0,
            allocation: None,
            shutdown: None,
            send_in_flight: 0,
            send_terminal: false,
            allocation_tasks: JoinSet::new(),
            probe_tasks: JoinSet::new(),
            release_tasks: JoinSet::new(),
            launcher_tasks: JoinSet::new(),
            shutdown_tasks: JoinSet::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ReleaseProgress {
    pending: u64,
    generation: u64,
}

struct SendPermit(Client);

impl Drop for SendPermit {
    fn drop(&mut self) {
        let mut work = self.0.inner.work.lock().expect("work gate lock");
        work.send_in_flight = work.send_in_flight.checked_sub(1).expect("send underflow");
        self.0
            .inner
            .send_progress_tx
            .send_replace(work.send_in_flight);
    }
}

struct PendingReleaseGuard(Client);

impl Drop for PendingReleaseGuard {
    fn drop(&mut self) {
        self.0.complete_release();
    }
}

#[derive(Default)]
struct ClientState {
    /// The current active mapping, if any.
    mapping: Option<CachedMapping>,
    /// Unconfirmed deletions that still gate reuse of their mapping key.
    uncertain_releases: Vec<CachedMapping>,
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
        let (release_progress_tx, _) = tokio::sync::watch::channel(ReleaseProgress::default());
        let (send_progress_tx, _) = tokio::sync::watch::channel(0);
        Self {
            inner: Arc::new(ClientInner {
                gateway_lookup: RwLock::new(gateway_lookup),
                local_port: RwLock::new(0),
                test_pxp_port: AtomicU16::new(0),
                test_upnp_port: AtomicU16::new(0),
                state: Mutex::new(ClientState::default()),
                clock: RwLock::new(Box::new(Instant::now)),
                next_gateway_observation: AtomicU64::new(0),
                next_ownership_id: AtomicU64::new(1),
                running_create: AtomicBool::new(false),
                work: Mutex::new(WorkGate::default()),
                release_progress_tx,
                send_progress_tx,
                #[cfg(test)]
                release_test_gate: Mutex::new(None),
                #[cfg(test)]
                pre_send_test_gate: Mutex::new(None),
                #[cfg(test)]
                send_test_gate: Mutex::new(None),
                #[cfg(test)]
                test_send_error: AtomicBool::new(false),
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
        if self.inner.closed.load(Ordering::SeqCst) {
            return;
        }
        let mut p = self.inner.local_port.write().expect("port lock");
        if *p != port {
            *p = port;
            self.invalidate_mappings(true);
        }
    }

    /// Override the monotonic clock (for testing lease and trust expiry).
    #[cfg(test)]
    pub(crate) fn set_test_clock(&self, clock: Box<dyn Fn() -> Instant + Send + Sync>) {
        *self.inner.clock.write().expect("clock lock") = clock;
    }

    #[cfg(test)]
    pub(crate) fn set_test_release_gate(&self, gate: Option<Arc<ReleaseTestGate>>) {
        *self
            .inner
            .release_test_gate
            .lock()
            .expect("release gate lock") = gate;
    }

    #[cfg(test)]
    pub(crate) fn set_test_send_gate(&self, gate: Option<Arc<SendTestGate>>) {
        *self.inner.send_test_gate.lock().expect("send gate lock") = gate;
    }

    #[cfg(test)]
    pub(crate) fn set_test_pre_send_gate(&self, gate: Option<Arc<SendTestGate>>) {
        *self
            .inner
            .pre_send_test_gate
            .lock()
            .expect("pre-send gate lock") = gate;
    }

    #[cfg(test)]
    pub(crate) fn set_test_send_error(&self, enabled: bool) {
        self.inner.test_send_error.store(enabled, Ordering::SeqCst);
    }

    fn now(&self) -> Instant {
        (self.inner.clock.read().expect("clock lock"))()
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
                    let old_mapping = Self::reset_mapping_state(&mut state);
                    if let Some(mapping) = old_mapping.as_ref() {
                        self.reserve_release(&mut state, mapping);
                    }
                    old_mapping
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

        let _ = old_mapping;
        snapshot
    }

    fn invalidate_mappings(&self, release: bool) {
        let old_mapping = {
            let mut state = self.inner.state.lock().expect("state lock");
            state.gateway_generation = state
                .gateway_generation
                .checked_add(1)
                .expect("gateway generation overflow");
            state.needs_probe = state.gateway.is_some();
            let old_mapping = Self::reset_mapping_state(&mut state);
            if let (true, Some(mapping)) = (release, old_mapping.as_ref()) {
                // The cleanup ledger and pending-operation count become visible
                // before invalidation unlocks. Shutdown takes this same state
                // lock after closing the work gate, so it cannot miss the
                // task-registration gap below.
                self.reserve_release(&mut state, mapping);
            }
            old_mapping
        };
        let _ = old_mapping;
    }

    fn reset_mapping_state(state: &mut ClientState) -> Option<CachedMapping> {
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
        if self.inner.closed.load(Ordering::SeqCst)
            || state.gateway_generation != snapshot.generation
            || state.gateway != snapshot.info
        {
            return None;
        }
        Some(f(&mut state))
    }

    fn acquire_send_permit(
        &self,
        snapshot: Option<GatewaySnapshot>,
        cleanup: bool,
    ) -> Result<SendPermit, crate::PortMapError> {
        let state = self.inner.state.lock().expect("state lock");
        if snapshot.is_some_and(|snapshot| {
            state.gateway_generation != snapshot.generation || state.gateway != snapshot.info
        }) {
            return Err(crate::PortMapError::GatewayRange);
        }
        let mut work = self.inner.work.lock().expect("work gate lock");
        if work.send_terminal || (work.closing && !cleanup) {
            return Err(crate::PortMapError::Disabled);
        }
        work.send_in_flight = work
            .send_in_flight
            .checked_add(1)
            .expect("send permit overflow");
        self.inner
            .send_progress_tx
            .send_replace(work.send_in_flight);
        drop(work);
        drop(state);
        Ok(SendPermit(self.clone()))
    }

    async fn send_udp(
        &self,
        socket: &UdpSocket,
        packet: &[u8],
        destination: SocketAddr,
        snapshot: Option<GatewaySnapshot>,
        cleanup: bool,
    ) -> Result<usize, crate::PortMapError> {
        #[cfg(test)]
        {
            let gate = self
                .inner
                .pre_send_test_gate
                .lock()
                .expect("pre-send gate lock")
                .clone();
            if let Some(gate) = gate {
                gate.reached.wait().await;
                gate.resume.wait().await;
            }
        }
        let _permit = self.acquire_send_permit(snapshot, cleanup)?;
        #[cfg(test)]
        {
            let gate = self
                .inner
                .send_test_gate
                .lock()
                .expect("send gate lock")
                .clone();
            if let Some(gate) = gate {
                gate.reached.wait().await;
                gate.resume.wait().await;
            }
        }
        #[cfg(test)]
        if self.inner.test_send_error.load(Ordering::SeqCst) {
            return Err(crate::PortMapError::Io(std::io::Error::other(
                "injected UDP send failure",
            )));
        }
        socket
            .send_to(packet, destination)
            .await
            .map_err(crate::PortMapError::Io)
    }

    fn reserve_release(&self, state: &mut ClientState, cached: &CachedMapping) {
        if !state
            .uncertain_releases
            .iter()
            .any(|pending| pending.ownership_id == cached.ownership_id)
        {
            state.uncertain_releases.push(cached.clone());
        }
        let mut work = self.inner.work.lock().expect("work gate lock");
        work.pending_releases = work
            .pending_releases
            .checked_add(1)
            .expect("pending release overflow");
        work.generation = work
            .generation
            .checked_add(1)
            .expect("release generation overflow");
        self.inner
            .release_progress_tx
            .send_replace(ReleaseProgress {
                pending: work.pending_releases,
                generation: work.generation,
            });
        // Spawn while the invalidating state lock is still held. This closes
        // the reservation/registration gap for shutdown.
        let client = self.clone();
        let captured = cached.clone();
        Self::reap_join_set(&mut work.release_tasks);
        work.release_tasks.spawn(async move {
            let _completion = PendingReleaseGuard(client.clone());
            if client.do_release(captured.clone()).await {
                client.clear_uncertain_release(&captured);
            }
        });
    }

    #[cfg(test)]
    fn register_release(&self) {
        let mut work = self.inner.work.lock().expect("work gate lock");
        work.pending_releases += 1;
        work.generation += 1;
        self.inner
            .release_progress_tx
            .send_replace(ReleaseProgress {
                pending: work.pending_releases,
                generation: work.generation,
            });
    }

    fn complete_release(&self) {
        let mut work = self.inner.work.lock().expect("work gate lock");
        work.pending_releases = work
            .pending_releases
            .checked_sub(1)
            .expect("release underflow");
        work.generation = work
            .generation
            .checked_add(1)
            .expect("release generation overflow");
        self.inner
            .release_progress_tx
            .send_replace(ReleaseProgress {
                pending: work.pending_releases,
                generation: work.generation,
            });
    }

    async fn wait_for_pending_releases(&self) {
        let mut progress = self.inner.release_progress_tx.subscribe();
        loop {
            if progress.borrow_and_update().pending == 0 {
                return;
            }
            if progress.changed().await.is_err() {
                return;
            }
        }
    }

    fn clear_uncertain_release(&self, released: &CachedMapping) {
        let mut state = self.inner.state.lock().expect("state lock");
        state
            .uncertain_releases
            .retain(|cached| cached.ownership_id != released.ownership_id);
    }

    async fn do_release(&self, cached: CachedMapping) -> bool {
        #[cfg(test)]
        {
            let gate = self
                .inner
                .release_test_gate
                .lock()
                .expect("release gate lock")
                .clone();
            if let Some(gate) = gate {
                gate.reached.wait().await;
                gate.resume.wait().await;
            }
        }

        // A release is fully self-contained. In particular, never look up the
        // current gateway or UPnP cache: they may now describe a replacement
        // mapping in a newer generation.
        let socket = match &cached.release {
            ReleaseIdentity::Pmp { .. } | ReleaseIdentity::Pcp { .. } => {
                match bind_underlay_udp().await {
                    Ok(socket) => Some(socket),
                    Err(_) => return false,
                }
            }
            ReleaseIdentity::Upnp { .. } => None,
        };

        let confirmed = match cached.release {
            ReleaseIdentity::Pmp {
                destination,
                internal_port,
            } => {
                let socket = socket.expect("PMP release socket");
                let external_port = cached.mapping.external.port();
                let packet = pmp::build_delete_request(internal_port, external_port);
                if self
                    .send_udp(&socket, &packet, destination, None, true)
                    .await
                    .is_err()
                {
                    false
                } else {
                    let mut response = [0_u8; 64];
                    matches!(
                        timeout(crate::PROBE_TIMEOUT, socket.recv_from(&mut response)).await,
                        Ok(Ok((size, source))) if source == destination
                            && pmp::parse_response(&response[..size]).is_some_and(|reply|
                                reply.op_code == pmp::PMP_OP_REPLY | pmp::PMP_OP_MAP_UDP
                                    && reply.result_code == 0
                                    && reply.internal_port == internal_port
                                    && (external_port == 0
                                        || reply.external_port == external_port)
                                    && reply.mapping_valid_seconds == 0)
                    )
                }
            }
            ReleaseIdentity::Pcp {
                destination,
                self_ip,
                internal_port,
                nonce,
            } => {
                let socket = socket.expect("PCP release socket");
                let external_port = cached.mapping.external.port();
                let requested_ip = match cached.mapping.external.ip() {
                    std::net::IpAddr::V4(ip) => ip,
                    std::net::IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
                };
                let packet = pcp::build_map_request(
                    self_ip,
                    internal_port,
                    external_port,
                    0,
                    requested_ip,
                    nonce,
                );
                if self
                    .send_udp(&socket, &packet, destination, None, true)
                    .await
                    .is_err()
                {
                    false
                } else {
                    let mut response = [0_u8; 128];
                    matches!(
                        timeout(crate::PROBE_TIMEOUT, socket.recv_from(&mut response)).await,
                        Ok(Ok((size, source))) if source == destination
                            && pcp::parse_map_response(&response[..size]).is_some_and(|reply|
                                reply.result_code == 0
                                    && reply.lifetime == 0
                                    && reply.nonce == nonce
                                    && reply.protocol == pcp::PCP_UDP
                                    && reply.internal_port == internal_port
                                    && (external_port == 0
                                        || reply.external.port() == external_port))
                    )
                }
            }
            ReleaseIdentity::Upnp { service } => {
                let Ok(_permit) = self.acquire_send_permit(None, true) else {
                    return false;
                };
                upnp::delete_port_mapping(
                    &service,
                    cached.mapping.external.port(),
                    Duration::from_secs(1),
                )
                .await
                .is_ok()
            }
        };

        confirmed
    }

    /// Close the client and release any active mapping.
    pub fn close(&self) {
        {
            let mut work = self.inner.work.lock().expect("work gate lock");
            if work.closing {
                return;
            }
            work.closing = true;
            self.inner.closed.store(true, Ordering::SeqCst);
        }
        self.invalidate_mappings(true);
    }

    /// Stop new mapping work and await active allocation/release supervisors.
    pub async fn shutdown(&self, deadline: Duration) -> Result<(), crate::PortMapError> {
        let mut result = {
            let mut work = self.inner.work.lock().expect("work gate lock");
            Self::reap_join_set(&mut work.shutdown_tasks);
            let completed = work
                .shutdown
                .as_ref()
                .is_some_and(|flight| flight.result.borrow().is_some())
                && work.shutdown_tasks.is_empty();
            if completed {
                work.shutdown = None;
            }
            if let Some(flight) = &work.shutdown {
                flight.result.subscribe()
            } else {
                work.closing = true;
                self.inner.closed.store(true, Ordering::SeqCst);
                let (result_tx, result_rx) = tokio::sync::watch::channel(None);
                work.shutdown = Some(ShutdownFlight {
                    result: result_tx.clone(),
                });
                let client = self.clone();
                work.shutdown_tasks.spawn(async move {
                    let outcome = client.shutdown_owner(deadline).await;
                    result_tx.send_replace(Some(outcome));
                });
                result_rx
            }
        };
        loop {
            if let Some(outcome) = result.borrow_and_update().clone() {
                return outcome;
            }
            result.changed().await.map_err(|_| {
                crate::PortMapError::Protocol("portmapper shutdown supervisor terminated".into())
            })?;
        }
    }

    async fn shutdown_owner(&self, deadline: Duration) -> Result<(), crate::PortMapError> {
        // Taking the state lock after closing is the invalidation barrier: any
        // earlier invalidator has already reserved its cleanup operation while
        // holding this lock, and later public work is rejected by the gate.
        self.invalidate_mappings(true);

        let (allocations, probes, launchers) = {
            let mut work = self.inner.work.lock().expect("work gate lock");
            work.allocation = None;
            (
                std::mem::take(&mut work.allocation_tasks),
                std::mem::take(&mut work.probe_tasks),
                std::mem::take(&mut work.launcher_tasks),
            )
        };
        let deadline = tokio::time::Instant::now() + deadline;
        let mut shutdown_error = self.await_join_set(allocations, deadline).await.err();
        if let Err(error) = self.await_join_set(probes, deadline).await {
            shutdown_error.get_or_insert(error);
        }
        if let Err(error) = self.await_join_set(launchers, deadline).await {
            shutdown_error.get_or_insert(error);
        }

        // Allocation supervisors are gone, so no new release can now be
        // reserved. Every prior reservation was synchronously registered
        // before its invalidation lock was released.
        let releases = {
            let mut work = self.inner.work.lock().expect("work gate lock");
            std::mem::take(&mut work.release_tasks)
        };
        if let Err(error) = self.await_join_set(releases, deadline).await {
            shutdown_error.get_or_insert(error);
        }
        if tokio::time::timeout_at(deadline, self.wait_for_pending_releases())
            .await
            .is_err()
        {
            shutdown_error.get_or_insert_with(|| {
                crate::PortMapError::Protocol("portmapper shutdown deadline".into())
            });
        }
        if let Some(error) = shutdown_error {
            return Err(error);
        }

        let uncertain = self
            .inner
            .state
            .lock()
            .expect("state lock")
            .uncertain_releases
            .clone();
        for cached in uncertain {
            let confirmed = tokio::time::timeout_at(deadline, self.do_release(cached.clone()))
                .await
                .map_err(|_| {
                    crate::PortMapError::Protocol("portmapper shutdown deadline".into())
                })?;
            if confirmed {
                self.clear_uncertain_release(&cached);
            }
        }
        if !self
            .inner
            .state
            .lock()
            .expect("state lock")
            .uncertain_releases
            .is_empty()
        {
            return Err(crate::PortMapError::Protocol(
                "portmapper cleanup remains uncertain".into(),
            ));
        }
        self.finish_send_gate(deadline).await?;
        Ok(())
    }

    async fn finish_send_gate(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<(), crate::PortMapError> {
        let mut progress = self.inner.send_progress_tx.subscribe();
        loop {
            {
                let mut work = self.inner.work.lock().expect("work gate lock");
                if work.send_in_flight == 0 {
                    work.send_terminal = true;
                    return Ok(());
                }
            }
            tokio::time::timeout_at(deadline, progress.changed())
                .await
                .map_err(|_| crate::PortMapError::Protocol("portmapper shutdown deadline".into()))?
                .map_err(|_| {
                    crate::PortMapError::Protocol("send progress channel closed".into())
                })?;
        }
    }

    fn reap_join_set(tasks: &mut JoinSet<()>) {
        while tasks.try_join_next().is_some() {}
    }

    fn reap_completed_tasks(&self) {
        let mut work = self.inner.work.lock().expect("work gate lock");
        Self::reap_join_set(&mut work.allocation_tasks);
        Self::reap_join_set(&mut work.probe_tasks);
        Self::reap_join_set(&mut work.release_tasks);
        Self::reap_join_set(&mut work.launcher_tasks);
        Self::reap_join_set(&mut work.shutdown_tasks);
    }

    #[cfg(test)]
    pub(crate) fn owned_task_counts(&self) -> (usize, usize, usize) {
        self.reap_completed_tasks();
        let work = self.inner.work.lock().expect("work gate lock");
        (
            work.allocation_tasks.len(),
            work.release_tasks.len(),
            work.launcher_tasks.len(),
        )
    }

    async fn await_join_set(
        &self,
        mut tasks: JoinSet<()>,
        deadline: tokio::time::Instant,
    ) -> Result<(), crate::PortMapError> {
        loop {
            match tokio::time::timeout_at(deadline, tasks.join_next()).await {
                Ok(Some(_)) => {}
                Ok(None) => return Ok(()),
                Err(_) => {
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                    return Err(crate::PortMapError::Protocol(
                        "portmapper shutdown deadline".into(),
                    ));
                }
            }
        }
    }

    /// Whether we have a valid (non-expired) cached mapping.
    pub fn have_mapping(&self) -> bool {
        self.reap_completed_tasks();
        if self.inner.closed.load(Ordering::SeqCst) {
            return false;
        }
        let snapshot = self.observe_gateway();
        if snapshot.info.is_none() {
            return false;
        }
        let now = self.now();
        self.with_current_gateway(snapshot, |state| {
            state
                .mapping
                .as_ref()
                .is_some_and(|cached| cached.mapping.is_valid_at(now))
        })
        .unwrap_or(false)
    }

    /// Get the cached mapping if it's still valid, or start creating one in
    /// the background. Returns `(Some(external), true)` if a valid cached
    /// mapping exists, `(None, false)` otherwise.
    ///
    /// Mirrors Go's `GetCachedMappingOrStartCreatingOne`.
    pub fn get_cached_mapping_or_start_creating_one(&self) -> (Option<SocketAddr>, bool) {
        self.reap_completed_tasks();
        if self.inner.closed.load(Ordering::SeqCst) {
            return (None, false);
        }
        // Validate the gateway before returning an external address. This is
        // the path magicsock uses while gathering advertised endpoints, so a
        // lost default route must hide and invalidate the old mapping at once.
        let snapshot = self.observe_gateway();
        if snapshot.info.is_none() {
            return (None, false);
        }

        let now = self.now();
        let Some(cached) = self.with_current_gateway(snapshot, |state| {
            state
                .mapping
                .as_ref()
                .filter(|cached| cached.mapping.is_valid_at(now))
                .map(|cached| {
                    (
                        cached.mapping.external,
                        cached.mapping.needs_renewal_at(now),
                    )
                })
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
        let mut work = self.inner.work.lock().expect("work gate lock");
        Self::reap_join_set(&mut work.launcher_tasks);
        Self::reap_join_set(&mut work.allocation_tasks);
        if work.closing || self.inner.running_create.swap(true, Ordering::SeqCst) {
            return;
        }
        let client = self.clone();
        work.launcher_tasks.spawn(async move {
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
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        let client = self.clone();
        {
            let mut work = self.inner.work.lock().expect("work gate lock");
            Self::reap_join_set(&mut work.probe_tasks);
            if work.closing {
                return Err(crate::PortMapError::Disabled);
            }
            work.probe_tasks.spawn(async move {
                let snapshot = client.observe_gateway();
                let result = if snapshot.info.is_none() {
                    Err(crate::PortMapError::GatewayRange)
                } else {
                    client.probe_with_snapshot(snapshot).await
                };
                let _ = result_tx.send(result);
            });
        }
        result_rx.await.unwrap_or_else(|_| {
            Err(crate::PortMapError::Protocol(
                "probe supervisor terminated".into(),
            ))
        })
    }

    async fn probe_with_snapshot(
        &self,
        snapshot: GatewaySnapshot,
    ) -> Result<ProbeResult, crate::PortMapError> {
        let gi = snapshot.info.ok_or(crate::PortMapError::GatewayRange)?;
        if self
            .with_current_gateway(snapshot, |state| {
                // A full probe replaces, rather than merges, protocol
                // observations. The active mapping retains its own release
                // identity independently of these discovery caches.
                state.pmp_pub_ip = None;
                state.pmp_pub_ip_time = None;
                state.pcp_saw_time = None;
                state.upnp_saw_time = None;
                state.upnp_services.clear();
            })
            .is_none()
        {
            return Err(crate::PortMapError::GatewayRange);
        }
        let pxp_port = self.pxp_port();
        let upnp_port = self.upnp_port();

        let sock = bind_underlay_udp().await?;
        let pxp_addr = SocketAddr::V4(SocketAddrV4::new(gi.gateway, pxp_port));
        let upnp_unicast = SocketAddr::V4(SocketAddrV4::new(gi.gateway, upnp_port));
        let upnp_multicast = SocketAddr::V4(SocketAddrV4::new(crate::SSDP_MULTICAST, upnp_port));

        // Send all probes.
        let pmp_pkt = pmp::build_external_addr_request();
        let _ = self
            .send_udp(&sock, &pmp_pkt, pxp_addr, Some(snapshot), false)
            .await;
        let pcp_pkt = pcp::build_announce_request(gi.self_ip);
        let _ = self
            .send_udp(&sock, &pcp_pkt, pxp_addr, Some(snapshot), false)
            .await;
        let upnp_all = upnp::ssdp_packet();
        let upnp_igd = upnp::ssdp_igd_packet();
        let _ = self
            .send_udp(&sock, &upnp_all, upnp_unicast, Some(snapshot), false)
            .await;
        let _ = self
            .send_udp(&sock, &upnp_all, upnp_multicast, Some(snapshot), false)
            .await;
        let _ = self
            .send_udp(&sock, &upnp_igd, upnp_multicast, Some(snapshot), false)
            .await;

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
                                let now = self.now();
                                if self
                                    .with_current_gateway(snapshot, |state| {
                                        state.pcp_saw_time = Some(now);
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
                                let now = self.now();
                                if self
                                    .with_current_gateway(snapshot, |state| {
                                        state.pmp_pub_ip = pmp_resp.public_addr;
                                        state.pmp_pub_ip_time = Some(now);
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
                let Ok(_permit) = self.acquire_send_permit(Some(snapshot), false) else {
                    return Err(crate::PortMapError::Disabled);
                };
                if let Some(svc) =
                    upnp::fetch_and_select_service(&resp.location, Duration::from_secs(1)).await
                {
                    let now = self.now();
                    if self
                        .with_current_gateway(snapshot, |state| {
                            state.upnp_services.insert(resp.location.clone(), svc);
                            state.upnp_saw_time = Some(now);
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

        let now = self.now();
        if self
            .with_current_gateway(snapshot, |state| {
                state.last_probe = Some(now);
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
        // Register or join the one allocation flight while holding the state
        // generation and work gate together. Caller cancellation only drops
        // this receiver; the owned supervisor and all cleanup identity remain.
        let mut result = {
            let state = self.inner.state.lock().expect("state lock");
            let generation = state.gateway_generation;
            let mut work = self.inner.work.lock().expect("work gate lock");
            Self::reap_join_set(&mut work.allocation_tasks);
            if work.closing {
                return Err(crate::PortMapError::Disabled);
            }
            let completed = work
                .allocation
                .as_ref()
                .is_some_and(|flight| flight.result.borrow().is_some())
                && work.allocation_tasks.is_empty();
            if completed {
                work.allocation = None;
            }
            if let Some(flight) = &work.allocation {
                // A stale-generation flight still owns router work and must
                // finish before a replacement generation can start.
                debug_assert!(flight.generation <= generation);
                flight.result.subscribe()
            } else {
                let (result_tx, result_rx) = tokio::sync::watch::channel(None);
                work.allocation = Some(AllocationFlight {
                    generation,
                    result: result_tx.clone(),
                });
                let client = self.clone();
                work.allocation_tasks.spawn(async move {
                    let outcome = client.create_or_get_mapping_serialized().await;
                    result_tx.send_replace(Some(outcome));
                });
                result_rx
            }
        };
        loop {
            if let Some(outcome) = result.borrow_and_update().clone() {
                return outcome;
            }
            result.changed().await.map_err(|_| {
                crate::PortMapError::Protocol("mapping supervisor terminated".into())
            })?;
        }
    }

    async fn create_or_get_mapping_serialized(&self) -> Result<Mapping, crate::PortMapError> {
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
        let now = self.now();
        if let Some(mapping) = self
            .with_current_gateway(snapshot, |state| {
                state.mapping.as_ref().and_then(|cached| {
                    let mapping = &cached.mapping;
                    (mapping.is_valid_at(now) && !mapping.needs_renewal_at(now))
                        .then(|| mapping.clone())
                })
            })
            .ok_or(crate::PortMapError::GatewayRange)?
        {
            return Ok(mapping);
        }

        let local_port = *self.inner.local_port.read().expect("port lock");
        if local_port == 0 {
            return Err(crate::PortMapError::NoServices);
        }

        // Protocol observations are only trusted for TRUST_DURATION. A lease
        // can outlive that window by hours, so renewals must refresh all
        // protocol observations instead of falling through to default PMP.
        let now = self.now();
        let trust_expired = self
            .with_current_gateway(snapshot, |state| {
                let last_probe_expired = !Self::observation_is_recent(state.last_probe, now);
                let mapped_protocol_expired = state.mapping.as_ref().is_some_and(|cached| {
                    let observed = match cached.mapping.kind {
                        MappingKind::Pmp => state.pmp_pub_ip_time,
                        MappingKind::Pcp => state.pcp_saw_time,
                        MappingKind::Upnp => state.upnp_saw_time,
                    };
                    !Self::observation_is_recent(observed, now)
                });
                last_probe_expired || mapped_protocol_expired
            })
            .ok_or(crate::PortMapError::GatewayRange)?;
        if trust_expired {
            self.probe_with_snapshot(snapshot).await?;
        }

        // Invalidation registers its release synchronously. Never allocate a
        // replacement until all older releases have completed, including when
        // the gateway and external mapping key reappear identically.
        self.wait_for_pending_releases().await;
        if self.with_current_gateway(snapshot, |_| ()).is_none() {
            return Err(crate::PortMapError::GatewayRange);
        }

        let internal_addr = SocketAddr::V4(SocketAddrV4::new(gi.self_ip, local_port));
        let pxp_port = self.pxp_port();
        let prev_port = self
            .with_current_gateway(snapshot, |state| {
                state
                    .mapping
                    .as_ref()
                    .map_or(0, |cached| cached.mapping.external.port())
            })
            .ok_or(crate::PortMapError::GatewayRange)?;

        let now = self.now();
        let (have_recent_pmp, have_recent_pcp, have_recent_upnp) = self
            .with_current_gateway(snapshot, |state| {
                (
                    Self::observation_is_recent(state.pmp_pub_ip_time, now),
                    Self::observation_is_recent(state.pcp_saw_time, now),
                    Self::observation_is_recent(state.upnp_saw_time, now),
                )
            })
            .ok_or(crate::PortMapError::GatewayRange)?;

        // Try PMP/PCP first (faster, share port 5351).
        if have_recent_pmp || have_recent_pcp || !have_recent_upnp {
            let desired_kind = if have_recent_pcp && !have_recent_pmp {
                MappingKind::Pcp
            } else {
                MappingKind::Pmp
            };
            self.release_incompatible_mapping(snapshot, prev_port, |identity| {
                matches!(
                    (desired_kind, identity),
                    (MappingKind::Pmp, ReleaseIdentity::Pmp { .. })
                        | (MappingKind::Pcp, ReleaseIdentity::Pcp { .. })
                )
            })
            .await?;
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

    fn observation_is_recent(observed: Option<Instant>, now: Instant) -> bool {
        observed.is_some_and(|time| now.saturating_duration_since(time) < crate::TRUST_DURATION)
    }

    async fn release_incompatible_mapping(
        &self,
        snapshot: GatewaySnapshot,
        desired_external_port: u16,
        compatible: impl Fn(&ReleaseIdentity) -> bool,
    ) -> Result<(), crate::PortMapError> {
        let old_mapping = {
            let mut state = self.inner.state.lock().expect("state lock");
            if state.gateway_generation != snapshot.generation || state.gateway != snapshot.info {
                return Err(crate::PortMapError::GatewayRange);
            }
            if state
                .mapping
                .as_ref()
                .is_some_and(|cached| !compatible(&cached.release))
            {
                let old = state.mapping.take();
                if let Some(mapping) = old.as_ref() {
                    self.reserve_release(&mut state, mapping);
                }
                old
            } else {
                None
            }
        };
        if old_mapping.is_some() {
            self.wait_for_pending_releases().await;
            if self.with_current_gateway(snapshot, |_| ()).is_none() {
                return Err(crate::PortMapError::GatewayRange);
            }
        }
        let now = self.now();
        let blocked = self
            .with_current_gateway(snapshot, |state| {
                state
                    .uncertain_releases
                    .retain(|cached| cached.lease_expires.is_none_or(|expiry| now < expiry));
                state.uncertain_releases.iter().any(|cached| {
                    desired_external_port == 0
                        || cached.mapping.external.port() == desired_external_port
                })
            })
            .ok_or(crate::PortMapError::GatewayRange)?;
        if blocked {
            return Err(crate::PortMapError::NoServices);
        }
        Ok(())
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
        let sock = bind_underlay_udp().await.map_err(crate::PortMapError::Io)?;
        let pxp_addr = SocketAddr::V4(SocketAddrV4::new(gi.gateway, pxp_port));

        let prefer_pcp = have_recent_pcp && !have_recent_pmp;

        // Get protocol identity from the cached mapping. PCP's nonce names the
        // mapping and must remain constant across create, renewal, and delete.
        let (cached_pub_ip, cached_pcp_nonce) = match self.with_current_gateway(snapshot, |state| {
            let nonce = state
                .mapping
                .as_ref()
                .and_then(|cached| match &cached.release {
                    ReleaseIdentity::Pcp { nonce, .. } => Some(*nonce),
                    _ => None,
                });
            (state.pmp_pub_ip, nonce)
        }) {
            Some(values) => values,
            None => return Ok(None),
        };

        let pcp_nonce = cached_pcp_nonce.unwrap_or_else(|| {
            use rand::RngCore;
            let mut nonce = [0_u8; 12];
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            nonce
        });
        let ownership_id = self.next_ownership_id();
        let provisional_now = self.now();
        let provisional_mapping = Mapping {
            external: SocketAddr::V4(SocketAddrV4::new(
                cached_pub_ip.unwrap_or(Ipv4Addr::UNSPECIFIED),
                prev_port,
            )),
            kind: if prefer_pcp {
                MappingKind::Pcp
            } else {
                MappingKind::Pmp
            },
            good_until: provisional_now + Duration::from_secs(u64::from(crate::MAP_LIFETIME_SECS)),
            renew_after: provisional_now,
        };
        let provisional = CachedMapping {
            ownership_id,
            mapping: provisional_mapping.clone(),
            generation: snapshot.generation,
            release: if prefer_pcp {
                ReleaseIdentity::Pcp {
                    destination: pxp_addr,
                    self_ip: gi.self_ip,
                    internal_port: local_port,
                    nonce: pcp_nonce,
                }
            } else {
                ReleaseIdentity::Pmp {
                    destination: pxp_addr,
                    internal_port: local_port,
                }
            },
            // Until a response arrives, the granted lifetime is unknown.
            // Never age an ambiguous pre-send ownership record out.
            lease_expires: None,
        };

        if prefer_pcp {
            let pkt = pcp::build_map_request(
                gi.self_ip,
                local_port,
                prev_port,
                crate::MAP_LIFETIME_SECS,
                Ipv4Addr::UNSPECIFIED,
                pcp_nonce,
            );
            self.inner
                .state
                .lock()
                .expect("state lock")
                .uncertain_releases
                .push(provisional.clone());
            if let Err(error) = self
                .send_udp(&sock, &pkt, pxp_addr, Some(snapshot), false)
                .await
            {
                // The send future returned an error before accepting a
                // datagram, so this request cannot have created a mapping.
                self.clear_uncertain_ownership(ownership_id);
                if matches!(&error, crate::PortMapError::Io(io) if treat_as_lost_udp(io)) {
                    return Err(crate::PortMapError::NoServices);
                }
                return Err(error);
            }
        } else {
            // PMP: request external address first if not cached.
            if cached_pub_ip.is_none() {
                let req = pmp::build_external_addr_request();
                if let Err(error) = self
                    .send_udp(&sock, &req, pxp_addr, Some(snapshot), false)
                    .await
                {
                    if matches!(&error, crate::PortMapError::Io(io) if treat_as_lost_udp(io)) {
                        return Err(crate::PortMapError::NoServices);
                    }
                    return Err(error);
                }
            }
            let pkt = pmp::build_map_request(local_port, prev_port, crate::MAP_LIFETIME_SECS);
            self.inner
                .state
                .lock()
                .expect("state lock")
                .uncertain_releases
                .push(provisional.clone());
            if let Err(error) = self
                .send_udp(&sock, &pkt, pxp_addr, Some(snapshot), false)
                .await
            {
                // No PMP mapping request was accepted by the socket.
                self.clear_uncertain_ownership(ownership_id);
                if matches!(&error, crate::PortMapError::Io(io) if treat_as_lost_udp(io)) {
                    return Err(crate::PortMapError::NoServices);
                }
                return Err(error);
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
                    if src != pxp_addr {
                        continue;
                    }
                    let pkt = &buf[..n];

                    // PCP MAP response (60 bytes).
                    if let Some(pcp_resp) = pcp::parse_map_response(pkt) {
                        if pcp_resp.nonce != pcp_nonce
                            || pcp_resp.protocol != pcp::PCP_UDP
                            || pcp_resp.internal_port != local_port
                        {
                            return Ok(None);
                        }
                        if pcp_resp.result_code == 0 {
                            let lifetime = Duration::from_secs(u64::from(pcp_resp.lifetime));
                            let now = self.now();
                            let mapping = Mapping {
                                external: pcp_resp.external,
                                kind: MappingKind::Pcp,
                                good_until: now + lifetime,
                                renew_after: now + lifetime / 2,
                            };
                            let cached = CachedMapping {
                                ownership_id,
                                mapping: mapping.clone(),
                                generation: snapshot.generation,
                                release: ReleaseIdentity::Pcp {
                                    destination: pxp_addr,
                                    self_ip: gi.self_ip,
                                    internal_port: local_port,
                                    nonce: pcp_nonce,
                                },
                                lease_expires: Some(mapping.good_until),
                            };
                            {
                                let mut state = self.inner.state.lock().expect("state lock");
                                if let Some(pending) = state
                                    .uncertain_releases
                                    .iter_mut()
                                    .find(|pending| pending.ownership_id == ownership_id)
                                {
                                    *pending = cached.clone();
                                }
                            }
                            if self.retained_port_conflicts(
                                mapping.external.port(),
                                Some(ownership_id),
                            ) {
                                if self.do_release(cached.clone()).await {
                                    self.clear_uncertain_release(&cached);
                                }
                                return Ok(None);
                            }
                            if self
                                .with_current_gateway(snapshot, |state| {
                                    state
                                        .uncertain_releases
                                        .retain(|pending| pending.ownership_id != ownership_id);
                                    state.mapping = Some(cached.clone());
                                })
                                .is_none()
                            {
                                if self.do_release(cached.clone()).await {
                                    self.clear_uncertain_release(&cached);
                                }
                                return Ok(None);
                            }
                            return Ok(Some(mapping));
                        }
                        self.clear_uncertain_ownership(ownership_id);
                        return Ok(None);
                    }

                    // PMP response. MAP replies are correlated by the
                    // requested internal port; another client's valid reply
                    // is unrelated and must not resolve our ownership.
                    if let Some(pmp_resp) = pmp::parse_response(pkt) {
                        if pmp_resp.op_code == pmp::PMP_OP_REPLY | pmp::PMP_OP_MAP_UDP
                            && pmp_resp.internal_port != local_port
                        {
                            continue;
                        }
                        if pmp_resp.result_code != 0 {
                            if pmp_resp.op_code == pmp::PMP_OP_REPLY | pmp::PMP_OP_MAP_UDP {
                                self.clear_uncertain_ownership(ownership_id);
                            }
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
                        let now = self.now();
                        let external = SocketAddr::V4(SocketAddrV4::new(pub_ip, ext_port));
                        let mapping = Mapping {
                            external,
                            kind: MappingKind::Pmp,
                            good_until: now + lifetime,
                            renew_after: now + lifetime / 2,
                        };
                        let cached = CachedMapping {
                            ownership_id,
                            mapping: mapping.clone(),
                            generation: snapshot.generation,
                            release: ReleaseIdentity::Pmp {
                                destination: pxp_addr,
                                internal_port: local_port,
                            },
                            lease_expires: Some(mapping.good_until),
                        };
                        {
                            let mut state = self.inner.state.lock().expect("state lock");
                            if let Some(pending) = state
                                .uncertain_releases
                                .iter_mut()
                                .find(|pending| pending.ownership_id == ownership_id)
                            {
                                *pending = cached.clone();
                            }
                        }
                        if self.retained_port_conflicts(mapping.external.port(), Some(ownership_id))
                        {
                            if self.do_release(cached.clone()).await {
                                self.clear_uncertain_release(&cached);
                            }
                            return Ok(None);
                        }
                        if self
                            .with_current_gateway(snapshot, |state| {
                                state
                                    .uncertain_releases
                                    .retain(|pending| pending.ownership_id != ownership_id);
                                state.pmp_pub_ip = Some(pub_ip);
                                state.pmp_pub_ip_time = Some(now);
                                state.mapping = Some(cached.clone());
                            })
                            .is_none()
                        {
                            if self.do_release(cached.clone()).await {
                                self.clear_uncertain_release(&cached);
                            }
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

    fn retained_port_conflicts(&self, port: u16, except_ownership: Option<u64>) -> bool {
        self.inner
            .state
            .lock()
            .expect("state lock")
            .uncertain_releases
            .iter()
            .any(|cached| {
                except_ownership != Some(cached.ownership_id)
                    && cached.mapping.external.port() == port
            })
    }

    fn retained_key_conflicts(
        &self,
        service: &upnp::UpnpService,
        port: u16,
        except_ownership: Option<u64>,
    ) -> bool {
        self.inner
            .state
            .lock()
            .expect("state lock")
            .uncertain_releases
            .iter()
            .any(|cached| {
                except_ownership != Some(cached.ownership_id)
                    && cached.mapping.external.port() == port
                    && match &cached.release {
                        ReleaseIdentity::Upnp { service: old } => {
                            old.control_url == service.control_url && old.kind == service.kind
                        }
                        // PMP/PCP and UPnP can address the same UDP mapping;
                        // without positive router identity equivalence, fail closed.
                        ReleaseIdentity::Pmp { .. } | ReleaseIdentity::Pcp { .. } => true,
                    }
            })
    }

    fn next_ownership_id(&self) -> u64 {
        self.inner.next_ownership_id.fetch_add(1, Ordering::Relaxed)
    }

    fn track_uncertain_upnp(
        &self,
        ownership_id: u64,
        snapshot: GatewaySnapshot,
        service: &upnp::UpnpService,
        port: u16,
        permanent: bool,
    ) {
        let now = self.now();
        let mapping = Mapping {
            external: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)),
            kind: MappingKind::Upnp,
            good_until: now + Duration::from_secs(u64::from(crate::MAP_LIFETIME_SECS)),
            renew_after: now,
        };
        let uncertain = CachedMapping {
            ownership_id,
            mapping: mapping.clone(),
            generation: snapshot.generation,
            release: ReleaseIdentity::Upnp {
                service: service.clone(),
            },
            lease_expires: (!permanent).then_some(mapping.good_until),
        };
        // Ownership transfers to the client-wide cleanup ledger even if the
        // originating gateway generation became stale while Add was in flight.
        self.inner
            .state
            .lock()
            .expect("state lock")
            .uncertain_releases
            .push(uncertain);
    }

    fn clear_uncertain_ownership(&self, ownership_id: u64) {
        self.inner
            .state
            .lock()
            .expect("state lock")
            .uncertain_releases
            .retain(|cached| cached.ownership_id != ownership_id);
    }

    fn uncertain_ownership(&self, ownership_id: u64) -> Option<CachedMapping> {
        self.inner
            .state
            .lock()
            .expect("state lock")
            .uncertain_releases
            .iter()
            .find(|cached| cached.ownership_id == ownership_id)
            .cloned()
    }

    async fn retry_uncertain_upnp(
        &self,
        snapshot: GatewaySnapshot,
        service: &upnp::UpnpService,
        deadline: Duration,
    ) -> bool {
        let now = self.now();
        let candidates = self
            .with_current_gateway(snapshot, |state| {
                state
                    .uncertain_releases
                    .iter()
                    .filter(|cached| {
                        matches!(&cached.release, ReleaseIdentity::Upnp { service: old }
                        if old.control_url == service.control_url && old.kind == service.kind)
                    })
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for candidate in candidates {
            let expired = candidate.lease_expires.is_some_and(|expiry| now >= expiry);
            let confirmed = if expired {
                true
            } else if let Ok(_permit) = self.acquire_send_permit(None, true) {
                upnp::delete_port_mapping(service, candidate.mapping.external.port(), deadline)
                    .await
                    .is_ok()
            } else {
                false
            };
            if confirmed {
                let _ = self.with_current_gateway(snapshot, |state| {
                    state
                        .uncertain_releases
                        .retain(|cached| cached.ownership_id != candidate.ownership_id);
                });
            }
        }
        self.with_current_gateway(snapshot, |state| {
            !state.uncertain_releases.iter().any(|cached| {
                matches!(&cached.release,
                ReleaseIdentity::Upnp { service: old }
                    if old.control_url == service.control_url && old.kind == service.kind)
            })
        })
        .unwrap_or(false)
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
            if self
                .release_incompatible_mapping(snapshot, prev_port, |identity| {
                    matches!(identity, ReleaseIdentity::Upnp { service }
                        if service.control_url == svc.control_url && service.kind == svc.kind)
                })
                .await
                .is_err()
            {
                return None;
            }
            if !self.retry_uncertain_upnp(snapshot, svc, deadline).await {
                continue;
            }
            let pending_ownership = AtomicU64::new(0);
            let allocation = match upnp::add_port_mapping(
                svc,
                &internal_client,
                local_port,
                prev_port,
                crate::MAP_LIFETIME_SECS,
                deadline,
                |port, permanent| {
                    let permit = self
                        .acquire_send_permit(Some(snapshot), false)
                        .map_err(|error| std::io::Error::other(error.to_string()))?;
                    let ownership_id = self.next_ownership_id();
                    self.track_uncertain_upnp(ownership_id, snapshot, svc, port, permanent);
                    pending_ownership.store(ownership_id, Ordering::SeqCst);
                    Ok(permit)
                },
                |_port, _permanent| {
                    let ownership_id = pending_ownership.swap(0, Ordering::SeqCst);
                    if ownership_id != 0 {
                        self.clear_uncertain_ownership(ownership_id);
                    }
                },
            )
            .await
            {
                Ok(allocation) => allocation,
                Err(error) => {
                    let _ = (&error.source, error.port, error.permanent);
                    let ownership_id = pending_ownership.load(Ordering::SeqCst);
                    if ownership_id != 0 {
                        if let Some(cached) = self.uncertain_ownership(ownership_id) {
                            if self.do_release(cached.clone()).await {
                                self.clear_uncertain_release(&cached);
                            }
                        }
                    }
                    continue;
                }
            };
            let ext_port = allocation.port;
            let ownership_id = pending_ownership.load(Ordering::SeqCst);
            assert_ne!(
                ownership_id, 0,
                "successful UPnP Add owns a cleanup ledger entry"
            );
            if self.retained_key_conflicts(svc, ext_port, Some(ownership_id)) {
                if let Some(cached) = self.uncertain_ownership(ownership_id) {
                    if self.do_release(cached.clone()).await {
                        self.clear_uncertain_release(&cached);
                    }
                }
                continue;
            }

            let external_ip = if let Ok(_permit) = self.acquire_send_permit(Some(snapshot), false) {
                upnp::get_external_ip(svc, deadline).await
            } else {
                Err(std::io::Error::other("portmapper closed"))
            };
            let ext_ip = if let Ok(ip) = external_ip {
                ip
            } else {
                if let Some(cached) = self.uncertain_ownership(ownership_id) {
                    if self.do_release(cached.clone()).await {
                        self.clear_uncertain_release(&cached);
                    }
                }
                continue;
            };

            let now = self.now();
            let lifetime = Duration::from_secs(u64::from(crate::MAP_LIFETIME_SECS));
            let mapping = Mapping {
                external: SocketAddr::V4(SocketAddrV4::new(ext_ip, ext_port)),
                kind: MappingKind::Upnp,
                good_until: now + lifetime,
                renew_after: now + lifetime / 2,
            };
            let cached = CachedMapping {
                ownership_id,
                mapping: mapping.clone(),
                generation: snapshot.generation,
                release: ReleaseIdentity::Upnp {
                    service: svc.clone(),
                },
                lease_expires: (!allocation.permanent).then_some(mapping.good_until),
            };
            if self
                .with_current_gateway(snapshot, |state| {
                    state.mapping = Some(cached.clone());
                    state
                        .uncertain_releases
                        .retain(|uncertain| uncertain.ownership_id != ownership_id);
                })
                .is_none()
            {
                if self.do_release(cached.clone()).await {
                    self.clear_uncertain_release(&cached);
                }
                return None;
            }
            return Some(mapping);
        }
        None
    }

    /// Get the cached mapping, if any (without starting creation).
    pub fn cached_mapping(&self) -> Option<Mapping> {
        self.reap_completed_tasks();
        if self.inner.closed.load(Ordering::SeqCst) {
            return None;
        }
        let snapshot = self.observe_gateway();
        snapshot.info?;
        self.with_current_gateway(snapshot, |state| {
            state.mapping.as_ref().map(|cached| cached.mapping.clone())
        })
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

    use super::{
        CachedMapping, Client, ClientConfig, GatewayInfo, Mapping, MappingKind, ReleaseIdentity,
        ReleaseTestGate, SendTestGate,
    };
    use crate::upnp::UpnpService;
    use crate::{pcp, pmp};
    use tokio::net::UdpSocket;

    fn prepare_pcp_client(router_port: u16, self_ip: Ipv4Addr) -> Client {
        let gateway = GatewayInfo {
            gateway: Ipv4Addr::LOCALHOST,
            self_ip,
        };
        let client = Client::with_config(ClientConfig {
            gateway_lookup: Some(Box::new(move || Some(gateway))),
        });
        client.set_test_pxp_port(router_port);
        client.set_local_port(41641);
        client.observe_gateway();
        {
            let mut state = client.inner.state.lock().unwrap();
            state.needs_probe = false;
            state.last_probe = Some(client.now());
            state.pcp_saw_time = Some(client.now());
        }
        client
    }

    fn prepare_pmp_client(router_port: u16) -> Client {
        let gateway = GatewayInfo {
            gateway: Ipv4Addr::LOCALHOST,
            self_ip: Ipv4Addr::new(192, 0, 2, 2),
        };
        let client = Client::with_config(ClientConfig {
            gateway_lookup: Some(Box::new(move || Some(gateway))),
        });
        client.set_test_pxp_port(router_port);
        client.set_local_port(41641);
        client.observe_gateway();
        {
            let mut state = client.inner.state.lock().unwrap();
            state.needs_probe = false;
            state.last_probe = Some(client.now());
            state.pmp_pub_ip = Some(Ipv4Addr::new(198, 51, 100, 7));
            state.pmp_pub_ip_time = Some(client.now());
        }
        client
    }

    async fn complete_pcp_request(
        router: &UdpSocket,
        operation: tokio::task::JoinHandle<Result<Mapping, crate::PortMapError>>,
    ) -> Mapping {
        let mut request = [0_u8; 128];
        let (size, source) = router.recv_from(&mut request).await.unwrap();
        assert_eq!(size, 60);
        let response = pcp::build_map_response(&request[..size]);
        router.send_to(&response, source).await.unwrap();
        operation.await.unwrap().unwrap()
    }

    fn pmp_map_response(result_code: u16, internal_port: u16, external_port: u16) -> [u8; 16] {
        let mut response = [0_u8; 16];
        response[1] = pmp::PMP_OP_REPLY | pmp::PMP_OP_MAP_UDP;
        response[2..4].copy_from_slice(&result_code.to_be_bytes());
        response[8..10].copy_from_slice(&internal_port.to_be_bytes());
        response[10..12].copy_from_slice(&external_port.to_be_bytes());
        response[12..16].copy_from_slice(&crate::MAP_LIFETIME_SECS.to_be_bytes());
        response
    }

    fn test_mapping(external: SocketAddr) -> Mapping {
        test_mapping_at(external, Instant::now())
    }

    fn test_mapping_at(external: SocketAddr, now: Instant) -> Mapping {
        Mapping {
            external,
            kind: MappingKind::Pcp,
            good_until: now + Duration::from_secs(3600),
            renew_after: now + Duration::from_secs(1800),
        }
    }

    fn seed_mapping_state(client: &Client, external: SocketAddr) {
        let now = client.now();
        let pxp_port = client.pxp_port();
        let mut state = client.inner.state.lock().unwrap();
        let gateway = state.gateway.expect("test gateway");
        state.mapping = Some(CachedMapping {
            ownership_id: client.next_ownership_id(),
            mapping: test_mapping_at(external, now),
            generation: state.gateway_generation,
            release: ReleaseIdentity::Pcp {
                destination: SocketAddr::V4(SocketAddrV4::new(gateway.gateway, pxp_port)),
                self_ip: gateway.self_ip,
                internal_port: 41641,
                nonce: [1; 12],
            },
            lease_expires: None,
        });
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

        client.observe_gateway();
        let first_hash = client.inner.state.lock().unwrap().gw_hash;

        client.observe_gateway();
        assert_eq!(client.inner.state.lock().unwrap().gw_hash, first_hash);

        client.set_gateway_lookup(Box::new(|| {
            Some(GatewayInfo {
                gateway: Ipv4Addr::new(10, 0, 0, 1),
                self_ip: Ipv4Addr::new(10, 0, 0, 2),
            })
        }));
        client.observe_gateway();
        assert_ne!(client.inner.state.lock().unwrap().gw_hash, first_hash);
    }

    #[tokio::test]
    async fn owned_task_sets_stay_bounded_under_cache_and_allocation_churn() {
        let gateway = GatewayInfo {
            gateway: Ipv4Addr::LOCALHOST,
            self_ip: Ipv4Addr::new(192, 0, 2, 2),
        };
        let client = Client::with_config(ClientConfig {
            gateway_lookup: Some(Box::new(move || Some(gateway))),
        });
        let snapshot = client.observe_gateway();
        {
            let mut state = client.inner.state.lock().unwrap();
            assert_eq!(state.gateway_generation, snapshot.generation);
            state.needs_probe = false;
            state.last_probe = Some(client.now());
        }

        for iteration in 0..2_000 {
            let _ = client.create_or_get_mapping().await;
            let (allocations, releases, launchers) = client.owned_task_counts();
            assert!(allocations <= 1, "allocation handles grew at {iteration}");
            assert!(releases <= 1, "release handles grew at {iteration}");
            assert!(launchers <= 1, "launcher handles grew at {iteration}");
        }
        for iteration in 0..5_000 {
            let _ = client.get_cached_mapping_or_start_creating_one();
            if iteration % 32 == 0 {
                tokio::task::yield_now().await;
            }
            let (allocations, releases, launchers) = client.owned_task_counts();
            assert!(allocations <= 1, "allocation handles grew at {iteration}");
            assert!(releases <= 1, "release handles grew at {iteration}");
            assert!(launchers <= 1, "launcher handles grew at {iteration}");
        }
        for iteration in 0..2_000 {
            client
                .inner
                .work
                .lock()
                .unwrap()
                .release_tasks
                .spawn(async {});
            tokio::task::yield_now().await;
            let (_, releases, _) = client.owned_task_counts();
            assert!(releases <= 1, "release handles grew at {iteration}");
        }
        client.shutdown(Duration::from_secs(2)).await.unwrap();
        assert_eq!(client.owned_task_counts(), (0, 0, 0));
    }

    #[tokio::test]
    async fn release_watch_cannot_miss_terminal_transition() {
        let client = Client::new();
        client.register_release();
        let waiter_client = client.clone();
        let waiter = tokio::spawn(async move {
            waiter_client.wait_for_pending_releases().await;
        });
        tokio::task::yield_now().await;
        client.complete_release();
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("watch waiter missed terminal state")
            .unwrap();
    }

    #[tokio::test]
    async fn shutdown_waits_for_check_to_send_permit_and_closes_gate() {
        let router = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let gateway = GatewayInfo {
            gateway: Ipv4Addr::LOCALHOST,
            self_ip: Ipv4Addr::new(192, 0, 2, 2),
        };
        let client = Client::with_config(ClientConfig {
            gateway_lookup: Some(Box::new(move || Some(gateway))),
        });
        client.set_test_pxp_port(router.local_addr().unwrap().port());
        client.set_test_upnp_port(router.local_addr().unwrap().port());
        let gate = SendTestGate::new();
        client.set_test_send_gate(Some(gate.clone()));

        let probe_client = client.clone();
        let probe = tokio::spawn(async move { probe_client.probe().await });
        gate.wait_reached().await;
        let shutdown_client = client.clone();
        let shutdown =
            tokio::spawn(async move { shutdown_client.shutdown(Duration::from_secs(2)).await });
        tokio::task::yield_now().await;
        assert!(!shutdown.is_finished(), "shutdown skipped an acquired send");

        gate.resume().await;
        let mut packet = [0_u8; 64];
        tokio::time::timeout(Duration::from_secs(1), router.recv_from(&mut packet))
            .await
            .expect("permitted packet was not sent")
            .unwrap();
        let _ = probe.await;
        shutdown.await.unwrap().unwrap();
        client.set_test_send_gate(None);

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert!(matches!(
            client
                .send_udp(&socket, &[0], router.local_addr().unwrap(), None, false,)
                .await,
            Err(crate::PortMapError::Disabled)
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), router.recv_from(&mut packet))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn closed_before_pcp_send_clears_provisional_ownership() {
        let router = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = prepare_pcp_client(
            router.local_addr().unwrap().port(),
            Ipv4Addr::new(192, 0, 2, 2),
        );
        let gate = SendTestGate::new();
        client.set_test_pre_send_gate(Some(gate.clone()));
        let operation_client = client.clone();
        let operation = tokio::spawn(async move { operation_client.create_or_get_mapping().await });
        gate.wait_reached().await;
        client.close();
        gate.resume().await;
        assert!(operation.await.unwrap().is_err());
        assert!(client
            .inner
            .state
            .lock()
            .unwrap()
            .uncertain_releases
            .is_empty());
        assert!(tokio::time::timeout(
            Duration::from_millis(50),
            router.recv_from(&mut [0_u8; 128])
        )
        .await
        .is_err());

        let retry = prepare_pcp_client(
            router.local_addr().unwrap().port(),
            Ipv4Addr::new(192, 0, 2, 3),
        );
        let retry_client = retry.clone();
        let retry_operation =
            tokio::spawn(async move { retry_client.create_or_get_mapping().await });
        assert_eq!(
            complete_pcp_request(&router, retry_operation).await.kind,
            MappingKind::Pcp
        );
    }

    #[tokio::test]
    async fn stale_generation_before_pcp_send_clears_and_retries() {
        let router = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = prepare_pcp_client(
            router.local_addr().unwrap().port(),
            Ipv4Addr::new(192, 0, 2, 2),
        );
        let gate = SendTestGate::new();
        client.set_test_pre_send_gate(Some(gate.clone()));
        let operation_client = client.clone();
        let operation = tokio::spawn(async move { operation_client.create_or_get_mapping().await });
        gate.wait_reached().await;
        client.set_gateway_lookup(Box::new(|| {
            Some(GatewayInfo {
                gateway: Ipv4Addr::LOCALHOST,
                self_ip: Ipv4Addr::new(192, 0, 2, 9),
            })
        }));
        client.observe_gateway();
        gate.resume().await;
        assert!(operation.await.unwrap().is_err());
        assert!(client
            .inner
            .state
            .lock()
            .unwrap()
            .uncertain_releases
            .is_empty());
        client.set_test_pre_send_gate(None);
        {
            let mut state = client.inner.state.lock().unwrap();
            state.needs_probe = false;
            state.last_probe = Some(client.now());
            state.pcp_saw_time = Some(client.now());
        }
        let retry_client = client.clone();
        let retry_operation =
            tokio::spawn(async move { retry_client.create_or_get_mapping().await });
        assert_eq!(
            complete_pcp_request(&router, retry_operation).await.kind,
            MappingKind::Pcp
        );
    }

    #[tokio::test]
    async fn synchronous_pcp_send_error_clears_and_retries_without_cleanup() {
        let router = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = prepare_pcp_client(
            router.local_addr().unwrap().port(),
            Ipv4Addr::new(192, 0, 2, 2),
        );
        client.set_test_send_error(true);
        assert!(client.create_or_get_mapping().await.is_err());
        assert!(client
            .inner
            .state
            .lock()
            .unwrap()
            .uncertain_releases
            .is_empty());
        assert!(tokio::time::timeout(
            Duration::from_millis(50),
            router.recv_from(&mut [0_u8; 128])
        )
        .await
        .is_err());

        client.set_test_send_error(false);
        let retry_client = client.clone();
        let retry_operation =
            tokio::spawn(async move { retry_client.create_or_get_mapping().await });
        assert_eq!(
            complete_pcp_request(&router, retry_operation).await.kind,
            MappingKind::Pcp
        );
    }

    #[tokio::test]
    async fn synchronous_pmp_send_error_clears_provisional_ownership() {
        let router = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = prepare_pmp_client(router.local_addr().unwrap().port());
        client.set_test_send_error(true);
        assert!(client.create_or_get_mapping().await.is_err());
        assert!(client
            .inner
            .state
            .lock()
            .unwrap()
            .uncertain_releases
            .is_empty());
        assert!(tokio::time::timeout(
            Duration::from_millis(50),
            router.recv_from(&mut [0_u8; 128])
        )
        .await
        .is_err());

        client.set_test_send_error(false);
        let retry_client = client.clone();
        let retry = tokio::spawn(async move { retry_client.create_or_get_mapping().await });
        let mut request = [0_u8; 64];
        let (size, source) = router.recv_from(&mut request).await.unwrap();
        assert_eq!(size, 12);
        let mut response = [0_u8; 16];
        response[1] = pmp::PMP_OP_REPLY | pmp::PMP_OP_MAP_UDP;
        response[8..10].copy_from_slice(&41641_u16.to_be_bytes());
        response[10..12].copy_from_slice(&4242_u16.to_be_bytes());
        response[12..16].copy_from_slice(&crate::MAP_LIFETIME_SECS.to_be_bytes());
        router.send_to(&response, source).await.unwrap();
        assert_eq!(retry.await.unwrap().unwrap().kind, MappingKind::Pmp);
    }

    #[tokio::test]
    async fn pmp_ignores_mismatched_reject_before_matching_success() {
        let router = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = prepare_pmp_client(router.local_addr().unwrap().port());
        let operation_client = client.clone();
        let operation = tokio::spawn(async move { operation_client.create_or_get_mapping().await });
        let mut request = [0_u8; 64];
        let (size, source) = router.recv_from(&mut request).await.unwrap();
        assert_eq!(size, 12);

        router
            .send_to(&pmp_map_response(2, 41642, 0), source)
            .await
            .unwrap();
        tokio::task::yield_now().await;
        assert!(!operation.is_finished());
        assert_eq!(
            client.inner.state.lock().unwrap().uncertain_releases.len(),
            1
        );

        router
            .send_to(&pmp_map_response(0, 41641, 4242), source)
            .await
            .unwrap();
        let mapping = operation.await.unwrap().unwrap();
        assert_eq!(mapping.kind, MappingKind::Pmp);
        assert_eq!(mapping.external.port(), 4242);
        assert!(client.inner.state.lock().unwrap().mapping.is_some());
    }

    #[tokio::test]
    async fn pmp_mismatched_success_never_commits() {
        let router = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = prepare_pmp_client(router.local_addr().unwrap().port());
        let operation_client = client.clone();
        let operation = tokio::spawn(async move { operation_client.create_or_get_mapping().await });
        let mut request = [0_u8; 64];
        let (size, source) = router.recv_from(&mut request).await.unwrap();
        assert_eq!(size, 12);
        router
            .send_to(&pmp_map_response(0, 41642, 4242), source)
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!operation.is_finished());
        assert!(client.inner.state.lock().unwrap().mapping.is_none());
        assert_eq!(
            client.inner.state.lock().unwrap().uncertain_releases.len(),
            1
        );
        operation.abort();
        let _ = operation.await;
        assert!(client.inner.state.lock().unwrap().mapping.is_none());
    }

    #[tokio::test]
    async fn pmp_request_owns_key_before_response() {
        let router = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let gateway = GatewayInfo {
            gateway: Ipv4Addr::LOCALHOST,
            self_ip: Ipv4Addr::new(192, 0, 2, 2),
        };
        let client = Client::with_config(ClientConfig {
            gateway_lookup: Some(Box::new(move || Some(gateway))),
        });
        client.set_test_pxp_port(router.local_addr().unwrap().port());
        client.set_local_port(41641);
        client.observe_gateway();
        {
            let mut state = client.inner.state.lock().unwrap();
            state.needs_probe = false;
            state.last_probe = Some(client.now());
            state.pmp_pub_ip = Some(Ipv4Addr::new(198, 51, 100, 7));
            state.pmp_pub_ip_time = Some(client.now());
        }

        let operation_client = client.clone();
        let operation = tokio::spawn(async move { operation_client.create_or_get_mapping().await });
        let mut request = [0_u8; 64];
        let (size, source) = router.recv_from(&mut request).await.unwrap();
        assert_eq!(size, 12);
        {
            let state = client.inner.state.lock().unwrap();
            let pending = state
                .uncertain_releases
                .iter()
                .find(|cached| matches!(cached.release, ReleaseIdentity::Pmp { .. }))
                .expect("PMP ownership must precede send completion");
            assert_eq!(pending.mapping.external.port(), 0);
            assert!(matches!(
                pending.release,
                ReleaseIdentity::Pmp {
                    internal_port: 41641,
                    ..
                }
            ));
        }

        let mut response = [0_u8; 16];
        response[1] = pmp::PMP_OP_REPLY | pmp::PMP_OP_MAP_UDP;
        response[8..10].copy_from_slice(&41641_u16.to_be_bytes());
        response[10..12].copy_from_slice(&4242_u16.to_be_bytes());
        response[12..16].copy_from_slice(&crate::MAP_LIFETIME_SECS.to_be_bytes());
        router.send_to(&response, source).await.unwrap();
        let mapping = operation.await.unwrap().unwrap();
        assert_eq!(mapping.kind, MappingKind::Pmp);
        assert!(client
            .inner
            .state
            .lock()
            .unwrap()
            .uncertain_releases
            .is_empty());
    }

    #[tokio::test]
    async fn pcp_request_owns_nonce_and_key_before_response() {
        let router = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let gateway = GatewayInfo {
            gateway: Ipv4Addr::LOCALHOST,
            self_ip: Ipv4Addr::new(192, 0, 2, 2),
        };
        let client = Client::with_config(ClientConfig {
            gateway_lookup: Some(Box::new(move || Some(gateway))),
        });
        client.set_test_pxp_port(router.local_addr().unwrap().port());
        client.set_local_port(41641);
        let snapshot = client.observe_gateway();
        {
            let mut state = client.inner.state.lock().unwrap();
            state.needs_probe = false;
            state.last_probe = Some(client.now());
            state.pcp_saw_time = Some(client.now());
        }

        let operation_client = client.clone();
        let operation = tokio::spawn(async move { operation_client.create_or_get_mapping().await });
        let mut request = [0_u8; 128];
        let (size, source) = router.recv_from(&mut request).await.unwrap();
        assert_eq!(size, 60);
        let mut nonce = [0_u8; 12];
        nonce.copy_from_slice(&request[24..36]);
        {
            let state = client.inner.state.lock().unwrap();
            let pending = state
                .uncertain_releases
                .iter()
                .find(|cached| matches!(cached.release, ReleaseIdentity::Pcp { .. }))
                .expect("PCP ownership must precede send completion");
            assert_eq!(pending.generation, snapshot.generation);
            assert_eq!(pending.mapping.external.port(), 0);
            match pending.release {
                ReleaseIdentity::Pcp {
                    internal_port,
                    nonce: pending_nonce,
                    ..
                } => {
                    assert_eq!(internal_port, 41641);
                    assert_eq!(pending_nonce, nonce);
                }
                _ => unreachable!(),
            }
        }

        let response = pcp::build_map_response(&request[..size]);
        router.send_to(&response, source).await.unwrap();
        let mapping = operation.await.unwrap().unwrap();
        assert_eq!(mapping.kind, MappingKind::Pcp);
        assert!(client
            .inner
            .state
            .lock()
            .unwrap()
            .uncertain_releases
            .is_empty());
    }

    #[tokio::test]
    async fn invalidation_registers_cleanup_task_before_unlock() {
        let gateway = GatewayInfo {
            gateway: Ipv4Addr::LOCALHOST,
            self_ip: Ipv4Addr::new(192, 168, 1, 2),
        };
        let client = Client::with_config(ClientConfig {
            gateway_lookup: Some(Box::new(move || Some(gateway))),
        });
        client.observe_gateway();
        seed_mapping_state(&client, "198.51.100.9:45000".parse().unwrap());
        let gate = ReleaseTestGate::new();
        client.set_test_release_gate(Some(gate.clone()));

        client.invalidate_mappings(true);
        {
            let work = client.inner.work.lock().unwrap();
            assert_eq!(work.pending_releases, 1);
            assert_eq!(work.release_tasks.len(), 1);
        }
        gate.wait_reached().await;
        gate.resume().await;
        client.wait_for_pending_releases().await;
        client.reap_completed_tasks();
        assert_eq!(client.owned_task_counts().1, 0);
        client.set_test_release_gate(None);
    }

    #[tokio::test]
    async fn shutdown_deadline_retains_blocked_permanent_upnp_cleanup() {
        let gateway = GatewayInfo {
            gateway: Ipv4Addr::LOCALHOST,
            self_ip: Ipv4Addr::new(192, 168, 1, 2),
        };
        let client = Client::with_config(ClientConfig {
            gateway_lookup: Some(Box::new(move || Some(gateway))),
        });
        let snapshot = client.observe_gateway();
        let gate = ReleaseTestGate::new();
        client.set_test_release_gate(Some(gate.clone()));
        {
            let mut state = client.inner.state.lock().unwrap();
            state.mapping = Some(CachedMapping {
                ownership_id: client.next_ownership_id(),
                mapping: Mapping {
                    external: "198.51.100.9:45000".parse().unwrap(),
                    kind: MappingKind::Upnp,
                    good_until: Instant::now() + Duration::from_secs(3600),
                    renew_after: Instant::now(),
                },
                generation: snapshot.generation,
                release: ReleaseIdentity::Upnp {
                    service: UpnpService {
                        control_url: "http://127.0.0.1:9/control".into(),
                        kind: 0,
                    },
                },
                lease_expires: None,
            });
        }

        let shutdown_client = client.clone();
        let shutdown =
            tokio::spawn(async move { shutdown_client.shutdown(Duration::from_millis(50)).await });
        gate.wait_reached().await;
        assert!(shutdown.await.unwrap().is_err());
        assert!(client
            .inner
            .state
            .lock()
            .unwrap()
            .uncertain_releases
            .iter()
            .any(|cached| cached.lease_expires.is_none()));
        gate.resume().await;
        client.set_test_release_gate(None);
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
        assert_eq!(client.observe_gateway().info, Some(gateway));

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
    async fn delayed_a_release_uses_captured_identity_and_cannot_delete_b() {
        let a_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a_destination = a_socket.local_addr().unwrap();
        let b_destination = b_socket.local_addr().unwrap();
        let gateway_a = GatewayInfo {
            gateway: Ipv4Addr::LOCALHOST,
            self_ip: Ipv4Addr::new(192, 168, 1, 2),
        };
        let lookup_calls = Arc::new(AtomicUsize::new(0));
        let client = Client::with_config(ClientConfig {
            gateway_lookup: Some(Box::new({
                let lookup_calls = lookup_calls.clone();
                move || {
                    assert_eq!(lookup_calls.fetch_add(1, Ordering::SeqCst), 0);
                    Some(gateway_a)
                }
            })),
        });
        let snapshot_a = client.observe_gateway();
        let mapping_a = test_mapping(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(198, 51, 100, 1),
            41001,
        )));
        let mapping_b = test_mapping(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(198, 51, 100, 2),
            41002,
        )));
        let gateway_b = GatewayInfo {
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            self_ip: Ipv4Addr::new(10, 0, 0, 2),
        };

        let captured_a = {
            let mut state = client.inner.state.lock().unwrap();
            state.mapping = Some(CachedMapping {
                ownership_id: client.next_ownership_id(),
                mapping: mapping_a,
                generation: snapshot_a.generation,
                release: ReleaseIdentity::Pcp {
                    destination: a_destination,
                    self_ip: gateway_a.self_ip,
                    internal_port: 41641,
                    nonce: [2; 12],
                },
                lease_expires: None,
            });
            let captured = Client::reset_mapping_state(&mut state).unwrap();
            state.gateway_generation += 1;
            state.gateway = Some(gateway_b);
            state.mapping = Some(CachedMapping {
                ownership_id: client.next_ownership_id(),
                mapping: mapping_b.clone(),
                generation: state.gateway_generation,
                release: ReleaseIdentity::Pcp {
                    destination: b_destination,
                    self_ip: gateway_b.self_ip,
                    internal_port: 41641,
                    nonce: [3; 12],
                },
                lease_expires: None,
            });
            captured
        };
        assert_eq!(captured_a.generation, snapshot_a.generation);

        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (resume_tx, resume_rx) = tokio::sync::oneshot::channel();
        let release_client = client.clone();
        let delayed_release = tokio::spawn(async move {
            ready_tx.send(()).unwrap();
            resume_rx.await.unwrap();
            release_client.do_release(captured_a).await;
        });
        ready_rx.await.unwrap();
        resume_tx.send(()).unwrap();

        let mut packet = [0_u8; 64];
        let (size, _) =
            tokio::time::timeout(Duration::from_secs(1), a_socket.recv_from(&mut packet))
                .await
                .expect("A must receive its release")
                .unwrap();
        assert_eq!(&packet[..2], &[2, 1]);
        assert_eq!(&packet[4..8], &[0, 0, 0, 0]);
        assert_eq!(size, 60);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), b_socket.recv_from(&mut packet))
                .await
                .is_err(),
            "delayed A release must not be sent to B"
        );
        delayed_release.await.unwrap();
        assert_eq!(lookup_calls.load(Ordering::SeqCst), 1);

        let state = client.inner.state.lock().unwrap();
        let cached_b = state.mapping.as_ref().expect("B mapping remains cached");
        assert_eq!(cached_b.mapping.external, mapping_b.external);
        assert_eq!(cached_b.generation, state.gateway_generation);
    }

    #[test]
    fn invalidation_captures_upnp_service_before_clearing_discovery() {
        let client = Client::new();
        let service = UpnpService {
            control_url: "http://192.168.1.1/old-control".into(),
            kind: 1,
        };
        let mut state = client.inner.state.lock().unwrap();
        state.gateway_generation = 7;
        state.upnp_services.insert("old".into(), service.clone());
        state.mapping = Some(CachedMapping {
            ownership_id: client.next_ownership_id(),
            mapping: Mapping {
                external: "198.51.100.3:42000".parse().unwrap(),
                kind: MappingKind::Upnp,
                good_until: Instant::now() + Duration::from_secs(3600),
                renew_after: Instant::now() + Duration::from_secs(1800),
            },
            generation: 7,
            release: ReleaseIdentity::Upnp {
                service: service.clone(),
            },
            lease_expires: None,
        });

        let captured = Client::reset_mapping_state(&mut state).unwrap();
        assert!(state.upnp_services.is_empty());
        assert_eq!(captured.generation, 7);
        match captured.release {
            ReleaseIdentity::Upnp { service: captured } => {
                assert_eq!(captured.control_url, service.control_url);
                assert_eq!(captured.kind, service.kind);
            }
            _ => panic!("expected captured UPnP release"),
        }
    }

    #[test]
    fn remapped_external_port_is_checked_against_retained_cleanup_key() {
        let client = Client::new();
        client
            .inner
            .state
            .lock()
            .unwrap()
            .uncertain_releases
            .push(CachedMapping {
                ownership_id: client.next_ownership_id(),
                mapping: Mapping {
                    external: "198.51.100.10:4242".parse().unwrap(),
                    kind: MappingKind::Pcp,
                    good_until: Instant::now() + Duration::from_secs(3600),
                    renew_after: Instant::now(),
                },
                generation: 1,
                release: ReleaseIdentity::Pcp {
                    destination: "192.0.2.1:5351".parse().unwrap(),
                    self_ip: Ipv4Addr::new(192, 0, 2, 2),
                    internal_port: 41641,
                    nonce: [8; 12],
                },
                lease_expires: Some(Instant::now() + Duration::from_secs(3600)),
            });
        assert!(client.retained_port_conflicts(4242, None));
        assert!(!client.retained_port_conflicts(4243, None));
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
                state.mapping = Some(CachedMapping {
                    ownership_id: stale_client.next_ownership_id(),
                    mapping: test_mapping(SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::new(203, 0, 113, 9),
                        41641,
                    ))),
                    generation: stale_snapshot.generation,
                    release: ReleaseIdentity::Pcp {
                        destination: SocketAddr::V4(SocketAddrV4::new(gateway.gateway, 5351)),
                        self_ip: gateway.self_ip,
                        internal_port: 41641,
                        nonce: [4; 12],
                    },
                    lease_expires: None,
                });
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
