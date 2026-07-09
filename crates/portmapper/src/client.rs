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
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::time::timeout;

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
    /// The last gateway/self_ip we saw (to detect changes).
    last_gw: Option<GatewayInfo>,
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

    fn gateway_and_self_ip(&self) -> Option<GatewayInfo> {
        let gi = (self.inner.gateway_lookup.read().expect("gw lock"))()?;
        let changed = {
            let mut state = self.inner.state.lock().expect("state lock");
            let changed = state.last_gw != Some(gi);
            if changed {
                state.last_gw = Some(gi);
            }
            changed
        };
        if changed {
            self.invalidate_mappings(true);
        }
        Some(gi)
    }

    fn invalidate_mappings(&self, release: bool) {
        let old_mapping = {
            let mut state = self.inner.state.lock().expect("state lock");
            let old = state.mapping.take();
            state.pmp_pub_ip = None;
            state.pmp_pub_ip_time = None;
            state.pcp_saw_time = None;
            state.upnp_saw_time = None;
            state.upnp_services.clear();
            old
        };
        if release {
            if let Some(m) = old_mapping {
                self.release_mapping(&m);
            }
        }
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
        let state = self.inner.state.lock().expect("state lock");
        state.mapping.as_ref().is_some_and(Mapping::is_valid)
    }

    /// Get the cached mapping if it's still valid, or start creating one in
    /// the background. Returns `(Some(external), true)` if a valid cached
    /// mapping exists, `(None, false)` otherwise.
    ///
    /// Mirrors Go's `GetCachedMappingOrStartCreatingOne`.
    pub fn get_cached_mapping_or_start_creating_one(&self) -> (Option<SocketAddr>, bool) {
        let cached = {
            let state = self.inner.state.lock().expect("state lock");
            state
                .mapping
                .as_ref()
                .filter(|m| m.is_valid())
                .map(|m| (m.external, m.needs_renewal()))
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
            let _ = client.create_or_get_mapping().await;
            client.inner.running_create.store(false, Ordering::SeqCst);
        });
    }

    /// Probe the gateway for supported port-mapping protocols. Sends PMP,
    /// PCP, and UPnP probes in parallel on a shared socket and collects
    /// responses within `probe_timeout` (250 ms by default).
    pub async fn probe(&self) -> Result<ProbeResult, crate::PortMapError> {
        if self.inner.closed.load(Ordering::Relaxed) {
            return Err(crate::PortMapError::Disabled);
        }
        let gi = self
            .gateway_and_self_ip()
            .ok_or(crate::PortMapError::GatewayRange)?;
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
                                let mut state = self.inner.state.lock().expect("state lock");
                                state.pcp_saw_time = Some(Instant::now());
                                continue;
                            }
                        }
                        if let Some(pmp_resp) = pmp::parse_response(pkt) {
                            if pmp_resp.op_code == pmp::PMP_OP_REPLY | pmp::PMP_OP_MAP_PUBLIC_ADDR
                                && pmp_resp.result_code == 0
                            {
                                result.pmp = true;
                                let mut state = self.inner.state.lock().expect("state lock");
                                state.pmp_pub_ip = pmp_resp.public_addr;
                                state.pmp_pub_ip_time = Some(Instant::now());
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
                    let mut state = self.inner.state.lock().expect("state lock");
                    state.upnp_services.insert(resp.location.clone(), svc);
                    result.upnp = true;
                    state.upnp_saw_time = Some(Instant::now());
                    break;
                }
            }
        }

        {
            let mut state = self.inner.state.lock().expect("state lock");
            state.last_probe = Some(Instant::now());
        }

        Ok(result)
    }

    /// Create or renew a port mapping. Returns the external endpoint if
    /// successful.
    pub async fn create_or_get_mapping(&self) -> Result<Mapping, crate::PortMapError> {
        if self.inner.closed.load(Ordering::Relaxed) {
            return Err(crate::PortMapError::Disabled);
        }

        // Fast path: return cached mapping if valid and not needing renewal.
        {
            let state = self.inner.state.lock().expect("state lock");
            if let Some(ref m) = state.mapping {
                if m.is_valid() && !m.needs_renewal() {
                    return Ok(m.clone());
                }
            }
        }

        let local_port = *self.inner.local_port.read().expect("port lock");
        if local_port == 0 {
            return Err(crate::PortMapError::NoServices);
        }

        let gi = self
            .gateway_and_self_ip()
            .ok_or(crate::PortMapError::GatewayRange)?;
        let internal_addr = SocketAddr::V4(SocketAddrV4::new(gi.self_ip, local_port));
        let pxp_port = self.pxp_port();
        let prev_port = {
            let state = self.inner.state.lock().expect("state lock");
            state.mapping.as_ref().map_or(0, |m| m.external.port())
        };

        let (have_recent_pmp, have_recent_pcp, have_recent_upnp) = {
            let state = self.inner.state.lock().expect("state lock");
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
        };

        // Try PMP/PCP first (faster, share port 5351).
        if have_recent_pmp || have_recent_pcp || !have_recent_upnp {
            if let Some(m) = self
                .try_pxp_mapping(
                    &gi,
                    internal_addr,
                    local_port,
                    prev_port,
                    pxp_port,
                    have_recent_pmp,
                    have_recent_pcp,
                )
                .await
            {
                return Ok(m);
            }
        }

        // Fallback to UPnP.
        if have_recent_upnp {
            if let Some(m) = self.try_upnp_mapping(&gi, local_port, prev_port).await {
                return Ok(m);
            }
        }

        Err(crate::PortMapError::NoServices)
    }

    /// Try to create a mapping via PMP or PCP (they share port 5351).
    #[allow(clippy::too_many_arguments)]
    async fn try_pxp_mapping(
        &self,
        gi: &GatewayInfo,
        _internal_addr: SocketAddr,
        local_port: u16,
        prev_port: u16,
        pxp_port: u16,
        have_recent_pmp: bool,
        have_recent_pcp: bool,
    ) -> Option<Mapping> {
        let sock = UdpSocket::bind("0.0.0.0:0").await.ok()?;
        let pxp_addr = SocketAddr::V4(SocketAddrV4::new(gi.gateway, pxp_port));

        let prefer_pcp = have_recent_pcp && !have_recent_pmp;

        // Get the cached PMP pub IP (if any) so we don't need to re-request it.
        let cached_pub_ip = {
            let state = self.inner.state.lock().expect("state lock");
            state.pmp_pub_ip
        };

        if prefer_pcp {
            let pkt = pcp::build_map_request(
                gi.self_ip,
                local_port,
                prev_port,
                crate::MAP_LIFETIME_SECS,
                Ipv4Addr::UNSPECIFIED,
            );
            let _ = sock.send_to(&pkt, pxp_addr).await;
        } else {
            // PMP: request external address first if not cached.
            if cached_pub_ip.is_none() {
                let req = pmp::build_external_addr_request();
                let _ = sock.send_to(&req, pxp_addr).await;
            }
            let pkt = pmp::build_map_request(local_port, prev_port, crate::MAP_LIFETIME_SECS);
            let _ = sock.send_to(&pkt, pxp_addr).await;
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
                            let mut state = self.inner.state.lock().expect("state lock");
                            state.mapping = Some(mapping.clone());
                            return Some(mapping);
                        }
                        return None;
                    }

                    // PMP response.
                    if let Some(pmp_resp) = pmp::parse_response(pkt) {
                        if pmp_resp.result_code != 0 {
                            return None;
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
                        let mut state = self.inner.state.lock().expect("state lock");
                        state.pmp_pub_ip = Some(pub_ip);
                        state.pmp_pub_ip_time = Some(now);
                        state.mapping = Some(mapping.clone());
                        return Some(mapping);
                    }
                }
                _ => break,
            }
        }
        None
    }

    /// Try to create a mapping via UPnP.
    async fn try_upnp_mapping(
        &self,
        gi: &GatewayInfo,
        local_port: u16,
        prev_port: u16,
    ) -> Option<Mapping> {
        let services: Vec<upnp::UpnpService> = {
            let state = self.inner.state.lock().expect("state lock");
            state.upnp_services.values().cloned().collect()
        };
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
            let mut state = self.inner.state.lock().expect("state lock");
            state.mapping = Some(mapping.clone());
            return Some(mapping);
        }
        None
    }

    /// Get the cached mapping, if any (without starting creation).
    pub fn cached_mapping(&self) -> Option<Mapping> {
        let state = self.inner.state.lock().expect("state lock");
        state.mapping.clone()
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
