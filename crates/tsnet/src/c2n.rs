use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;
use rustscale_c2n::{C2nBackend, LogLevelState, WhoIsResult};
use rustscale_controlclient::c2n::{
    C2nHandler, C2nPublicationValidator, C2nReplyError, C2nRequest, C2nResponse, C2nRouter,
};
use rustscale_health::{Severity, Tracker};
use rustscale_magicsock::Magicsock;
use rustscale_tailcfg::{C2NPostureIdentityResponse, DNSConfig, Node, UserID, UserProfile};
use tokio::sync::RwLock;

pub struct EchoHandler;

#[async_trait]
impl C2nHandler for EchoHandler {
    async fn handle(&self, req: C2nRequest) -> C2nResponse {
        C2nResponse::ok(req.body)
    }
}

/// Data needed to construct a [`TsnetC2nBackend`].
///
/// All fields are `Arc` clones of the same shared state held by
/// [`crate::RunningState`], so the C2N server always sees live data.
pub(crate) struct C2nBackendData {
    pub peers: Arc<RwLock<Vec<Node>>>,
    pub user_profiles: Arc<RwLock<BTreeMap<UserID, UserProfile>>>,
    pub health: Tracker,
    pub dns_config: Arc<RwLock<Option<DNSConfig>>>,
    pub packet_drops: Arc<AtomicU64>,
    pub prefs: serde_json::Value,
    pub tailscale_ips: Vec<IpAddr>,
    pub our_fqdn: String,
    pub magicsock: Arc<Magicsock>,
    pub sockstats: Arc<rustscale_sockstats::SockStats>,
    pub logtail: Option<rustscale_logtail::LogTail>,
    pub posture_checking: Arc<crate::LivePosturePreference>,
    pub posture_service: Arc<rustscale_posture::IdentityService>,
}

struct CollectedPosture {
    response: C2NPostureIdentityResponse,
    preference_generation: u64,
    include_hardware_addrs: bool,
}

struct PosturePublicationValidator {
    preference: Arc<crate::LivePosturePreference>,
    posture_service: Arc<rustscale_posture::IdentityService>,
    expected_generation: u64,
    include_hardware_addrs: bool,
    response_has_hardware_addrs: bool,
}

impl C2nPublicationValidator for PosturePublicationValidator {
    fn validate_and_publish(
        &self,
        publish: &mut dyn FnMut() -> Result<(), C2nReplyError>,
    ) -> Result<(), C2nReplyError> {
        self.preference
            .with_generation(self.expected_generation, |user_enabled| {
                if (self.response_has_hardware_addrs && !self.include_hardware_addrs)
                    || !self.posture_service.publication_allowed(user_enabled)
                {
                    return Err(C2nReplyError::PublicationRevoked);
                }
                publish()
            })
            .ok_or(C2nReplyError::PublicationRevoked)?
    }
}

pub struct TsnetC2nBackend {
    peers: Arc<RwLock<Vec<Node>>>,
    user_profiles: Arc<RwLock<BTreeMap<UserID, UserProfile>>>,
    health: Tracker,
    dns_config: Arc<RwLock<Option<DNSConfig>>>,
    packet_drops: Arc<AtomicU64>,
    prefs: serde_json::Value,
    tailscale_ips: Vec<IpAddr>,
    our_fqdn: String,
    magicsock: Arc<Magicsock>,
    sockstats: Arc<rustscale_sockstats::SockStats>,
    logtail: Option<rustscale_logtail::LogTail>,
    posture_checking: Arc<crate::LivePosturePreference>,
    posture_service: Arc<rustscale_posture::IdentityService>,
    log_level: LogLevelState,
}

impl TsnetC2nBackend {
    pub(crate) fn new(data: C2nBackendData, log_level: LogLevelState) -> Self {
        Self {
            peers: data.peers,
            user_profiles: data.user_profiles,
            health: data.health,
            dns_config: data.dns_config,
            packet_drops: data.packet_drops,
            prefs: data.prefs,
            tailscale_ips: data.tailscale_ips,
            our_fqdn: data.our_fqdn,
            magicsock: data.magicsock,
            sockstats: data.sockstats,
            logtail: data.logtail,
            posture_checking: data.posture_checking,
            posture_service: data.posture_service,
            log_level,
        }
    }

    async fn collect_posture(
        &self,
        include_hardware_addrs: bool,
        session_cancellation: tokio_util::sync::CancellationToken,
    ) -> Option<CollectedPosture> {
        const POSTURE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

        let (_, preference_generation) = self.posture_checking.snapshot();
        let service = self.posture_service.clone();
        let worker_service = service.clone();
        let preference = self.posture_checking.clone();
        let worker_preference = preference.clone();
        let cancellation = session_cancellation.child_token();
        let worker_cancellation = cancellation.clone();
        let deadline = std::time::Instant::now() + POSTURE_DEADLINE;
        let collection = tokio::task::spawn_blocking(move || {
            let context =
                rustscale_posture::CollectionContext::new(Some(deadline), worker_cancellation);
            worker_service.collect_cancellable(
                || worker_preference.load(Ordering::Acquire),
                include_hardware_addrs,
                &context,
            )
        });
        let collection = tokio::select! {
            result = collection => match result {
                Ok(Ok(collection)) => collection,
                Ok(Err(rustscale_posture::PostureError::Cancelled)) => return None,
                Ok(Err(rustscale_posture::PostureError::Timeout)) => {
                    log::warn!("posture: collection deadline exceeded");
                    return None;
                }
                Ok(Err(error)) => {
                    log::warn!("posture: collection failed: {error}");
                    return None;
                }
                Err(_) => {
                    log::warn!("posture: collector task failed");
                    return None;
                }
            },
            () = session_cancellation.cancelled() => {
                cancellation.cancel();
                return None;
            }
            () = tokio::time::sleep(POSTURE_DEADLINE) => {
                cancellation.cancel();
                log::warn!("posture: collection deadline exceeded");
                return None;
            }
        };
        if session_cancellation.is_cancelled() {
            return None;
        }
        let revalidation_service = service.clone();
        let revalidation_preference = preference.clone();
        let revalidation = tokio::task::spawn_blocking(move || {
            revalidation_service.revalidate_for_publication(
                revalidation_preference.load(Ordering::Acquire),
                collection,
            )
        });
        let collection = tokio::select! {
            result = revalidation => {
                let Ok(collection) = result else {
                    log::warn!("posture: policy revalidation task failed");
                    return None;
                };
                collection
            },
            () = session_cancellation.cancelled() => {
                cancellation.cancel();
                return None;
            }
            () = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                cancellation.cancel();
                log::warn!("posture: policy revalidation deadline exceeded");
                return None;
            }
        };
        if session_cancellation.is_cancelled() {
            return None;
        }
        if let Some(error) = collection.policy_error {
            log::warn!("posture: policy lookup failed: {error}");
        }
        if let Some(error) = collection.serial_error {
            log::warn!("posture: serial collection failed: {error}");
        }
        if let Some(error) = collection.hardware_addr_error {
            log::warn!("posture: hardware address collection failed: {error}");
        }
        let identity = collection.identity;
        log::debug!(
            "posture: disabled={} serials={} hardware_addrs={}",
            identity.posture_disabled,
            identity.serial_numbers.len(),
            identity.iface_hardware_addrs.len()
        );
        Some(CollectedPosture {
            response: C2NPostureIdentityResponse {
                serial_numbers: identity.serial_numbers,
                iface_hardware_addrs: identity.iface_hardware_addrs,
                posture_disabled: identity.posture_disabled,
            },
            preference_generation,
            include_hardware_addrs,
        })
    }
}

#[async_trait]
impl C2nBackend for TsnetC2nBackend {
    async fn whois(&self, ip: IpAddr) -> Option<WhoIsResult> {
        let peers = self.peers.try_read().ok()?;
        let user_profiles = self.user_profiles.try_read().ok()?;

        for peer in peers.iter() {
            let ips: Vec<IpAddr> = peer
                .Addresses
                .iter()
                .filter_map(|s| s.split('/').next().and_then(|p| p.parse::<IpAddr>().ok()))
                .collect();
            if ips.contains(&ip) {
                let up = user_profiles.get(&peer.User);
                return Some(WhoIsResult {
                    found: true,
                    node_name: peer.Name.clone(),
                    user_id: peer.User,
                    login_name: up.map(|p| p.LoginName.clone()).unwrap_or_default(),
                });
            }
        }
        None
    }

    async fn prefs_json(&self) -> Option<serde_json::Value> {
        Some(self.prefs.clone())
    }

    async fn netmap_json(&self, _omit_fields: &[String]) -> Option<serde_json::Value> {
        let peers = self.peers.read().await;
        let dns = self.dns_config.read().await;
        let domain = self.our_fqdn.trim_end_matches('.');
        let domain = match domain.split_once('.') {
            Some((_, d)) => d.to_string(),
            None => domain.to_string(),
        };

        let self_node = serde_json::json!({
            "Name": self.our_fqdn,
            "Addresses": self.tailscale_ips.iter().map(|ip| format!("{ip}/32")).collect::<Vec<_>>(),
            "Key": self.magicsock.node_public().to_string(),
        });

        let peers_json: Vec<serde_json::Value> = peers
            .iter()
            .filter(|p| !p.Key.is_zero())
            .map(|p| serde_json::to_value(p).unwrap_or(serde_json::Value::Null))
            .collect();

        Some(serde_json::json!({
            "SelfNode": self_node,
            "Peers": peers_json,
            "DNSConfig": dns.as_ref().map(|c| serde_json::to_value(c).unwrap_or(serde_json::Value::Null)),
            "Domain": domain,
        }))
    }

    async fn health_json(&self) -> Option<serde_json::Value> {
        let warnings = self.health.current_warnings();
        serde_json::to_value(&warnings).ok()
    }

    async fn metrics_text(&self) -> Option<String> {
        use std::fmt::Write;
        let drops = self.packet_drops.load(Ordering::Relaxed);
        let peer_count = self.peers.try_read().map_or(0, |p| p.len());
        let warnings = self.health.current_warnings();
        let high = warnings
            .iter()
            .filter(|w| w.severity == Severity::High)
            .count();
        let medium = warnings
            .iter()
            .filter(|w| w.severity == Severity::Medium)
            .count();
        let low = warnings
            .iter()
            .filter(|w| w.severity == Severity::Low)
            .count();
        let endpoints = self.magicsock.local_endpoints();

        let mut out = String::new();
        let _ = writeln!(
            out,
            "# HELP rustscale_packet_drops_total Packets dropped by the packet filter"
        );
        let _ = writeln!(out, "# TYPE rustscale_packet_drops_total counter");
        let _ = writeln!(out, "rustscale_packet_drops_total {drops}");
        let _ = writeln!(
            out,
            "# HELP rustscale_peer_count Number of peers in the netmap"
        );
        let _ = writeln!(out, "# TYPE rustscale_peer_count gauge");
        let _ = writeln!(out, "rustscale_peer_count {peer_count}");
        let _ = writeln!(
            out,
            "# HELP rustscale_health_warnings Active health warnings by severity"
        );
        let _ = writeln!(out, "# TYPE rustscale_health_warnings gauge");
        let _ = writeln!(out, "rustscale_health_warnings{{severity=\"high\"}} {high}");
        let _ = writeln!(
            out,
            "rustscale_health_warnings{{severity=\"medium\"}} {medium}"
        );
        let _ = writeln!(out, "rustscale_health_warnings{{severity=\"low\"}} {low}");
        let _ = writeln!(
            out,
            "# HELP rustscale_local_endpoints Number of local UDP endpoints"
        );
        let _ = writeln!(out, "# TYPE rustscale_local_endpoints gauge");
        let _ = writeln!(out, "rustscale_local_endpoints {}", endpoints.len());
        Some(out)
    }

    async fn dns_config_json(&self) -> Option<serde_json::Value> {
        let dns = self.dns_config.read().await;
        dns.as_ref()
            .map(|c| serde_json::to_value(c).unwrap_or(serde_json::Value::Null))
    }

    async fn try_flush_logs(&self) -> bool {
        if let Some(logtail) = &self.logtail {
            logtail.flush();
            true
        } else {
            false
        }
    }

    async fn set_component_debug_logging(
        &self,
        component: &str,
        until: SystemTime,
    ) -> Result<(), String> {
        if component.is_empty() {
            return Err("component is required".into());
        }
        self.log_level.set(component, until);
        Ok(())
    }

    async fn sockstats_json(&self) -> Option<serde_json::Value> {
        Some(self.sockstats.to_json())
    }

    async fn posture_identity(&self) -> Option<C2NPostureIdentityResponse> {
        self.collect_posture(false, tokio_util::sync::CancellationToken::new())
            .await
            .map(|collected| collected.response)
    }
}

// ---------------------------------------------------------------------------
// Noise-channel C2N handlers (C2nRouter)
// ---------------------------------------------------------------------------

struct BackendPrefsHandler {
    backend: Arc<TsnetC2nBackend>,
}
#[async_trait]
impl C2nHandler for BackendPrefsHandler {
    async fn handle(&self, _req: C2nRequest) -> C2nResponse {
        match self.backend.prefs_json().await {
            Some(v) => C2nResponse::json(200, &v),
            None => C2nResponse::error(501, "prefs not available"),
        }
    }
}

struct BackendNetmapHandler {
    backend: Arc<TsnetC2nBackend>,
}
#[async_trait]
impl C2nHandler for BackendNetmapHandler {
    async fn handle(&self, req: C2nRequest) -> C2nResponse {
        let omit_fields: Vec<String> = if req.method == "POST" {
            serde_json::from_slice::<NetmapOmitWire>(&req.body)
                .map(|r| r.OmitFields)
                .unwrap_or_default()
        } else if let Some((_, query)) = req.path.split_once('?') {
            parse_omit_fields(query)
        } else {
            vec![]
        };
        match self.backend.netmap_json(&omit_fields).await {
            Some(v) => {
                let mut v = v;
                if let Some(obj) = v.as_object_mut() {
                    for f in &omit_fields {
                        obj.remove(f);
                    }
                }
                C2nResponse::json(200, &v)
            }
            None => C2nResponse::error(501, "netmap not available"),
        }
    }
}

#[derive(serde::Deserialize)]
#[allow(non_snake_case)]
struct NetmapOmitWire {
    #[serde(default)]
    OmitFields: Vec<String>,
}

struct BackendHealthHandler {
    backend: Arc<TsnetC2nBackend>,
}
#[async_trait]
impl C2nHandler for BackendHealthHandler {
    async fn handle(&self, _req: C2nRequest) -> C2nResponse {
        match self.backend.health_json().await {
            Some(v) => C2nResponse::json(200, &v),
            None => C2nResponse::error(501, "health not available"),
        }
    }
}

struct BackendDnsHandler {
    backend: Arc<TsnetC2nBackend>,
}
#[async_trait]
impl C2nHandler for BackendDnsHandler {
    async fn handle(&self, _req: C2nRequest) -> C2nResponse {
        match self.backend.dns_config_json().await {
            Some(v) => C2nResponse::json(200, &v),
            None => C2nResponse::error(501, "dns config not available"),
        }
    }
}

struct LogtailFlushHandler {
    backend: Arc<TsnetC2nBackend>,
}
#[async_trait]
impl C2nHandler for LogtailFlushHandler {
    async fn handle(&self, _req: C2nRequest) -> C2nResponse {
        if self.backend.try_flush_logs().await {
            C2nResponse::no_content()
        } else {
            C2nResponse::error(500, "no log flusher wired up")
        }
    }
}

struct GoroutinesHandler;
#[async_trait]
impl C2nHandler for GoroutinesHandler {
    async fn handle(&self, _req: C2nRequest) -> C2nResponse {
        C2nResponse::text(
            200,
            "Rust has no goroutine dump. Tokio task introspection is not available.\n",
        )
    }
}

struct PprofHandler;
#[async_trait]
impl C2nHandler for PprofHandler {
    async fn handle(&self, _req: C2nRequest) -> C2nResponse {
        C2nResponse::error(501, "pprof not available in rustscale")
    }
}

struct LogheapHandler;
#[async_trait]
impl C2nHandler for LogheapHandler {
    async fn handle(&self, _req: C2nRequest) -> C2nResponse {
        C2nResponse::text(200, "logheap: no heap profiler available in rustscale\n")
    }
}

struct SockStatsHandler {
    backend: Arc<TsnetC2nBackend>,
}

struct PostureIdentityHandler {
    backend: Arc<TsnetC2nBackend>,
}

#[async_trait]
impl C2nHandler for PostureIdentityHandler {
    async fn handle(&self, req: C2nRequest) -> C2nResponse {
        self.handle_cancellable(req, tokio_util::sync::CancellationToken::new())
            .await
    }

    async fn handle_cancellable(
        &self,
        req: C2nRequest,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> C2nResponse {
        let include_hardware_addrs = req
            .path
            .split_once('?')
            .map(|(_, query)| {
                query
                    .split('&')
                    .filter_map(|part| part.split_once('='))
                    .any(|(key, value)| key == "hwaddrs" && value == "true")
            })
            .unwrap_or(false);
        match self
            .backend
            .collect_posture(include_hardware_addrs, cancellation)
            .await
        {
            Some(collected) => {
                let response_has_hardware_addrs =
                    !collected.response.iface_hardware_addrs.is_empty();
                let response_is_sensitive =
                    response_has_hardware_addrs || !collected.response.serial_numbers.is_empty();
                let body =
                    serde_json::to_value(&collected.response).unwrap_or(serde_json::Value::Null);
                let response = C2nResponse::json(200, &body);
                if response_is_sensitive {
                    response.with_publication_validator(Arc::new(PosturePublicationValidator {
                        preference: self.backend.posture_checking.clone(),
                        posture_service: self.backend.posture_service.clone(),
                        expected_generation: collected.preference_generation,
                        include_hardware_addrs: collected.include_hardware_addrs,
                        response_has_hardware_addrs,
                    }))
                } else {
                    response
                }
            }
            None => C2nResponse::error(501, "posture identity not available"),
        }
    }
}
#[async_trait]
impl C2nHandler for SockStatsHandler {
    async fn handle(&self, _req: C2nRequest) -> C2nResponse {
        match self.backend.sockstats_json().await {
            Some(v) => C2nResponse::json(200, &v),
            None => C2nResponse::text(200, "sockstats: no sockstat logger wired up\n"),
        }
    }
}

struct ComponentLoggingHandler {
    backend: Arc<TsnetC2nBackend>,
}
#[async_trait]
impl C2nHandler for ComponentLoggingHandler {
    async fn handle(&self, req: C2nRequest) -> C2nResponse {
        let query = req.path.split_once('?').map_or("", |(_, q)| q);
        let params = parse_query_map(query);
        let component = params.get("component").map_or("", String::as_str);
        let secs: i64 = params.get("secs").and_then(|s| s.parse().ok()).unwrap_or(0);
        let secs = if secs == 0 { -1 } else { secs };
        let now = SystemTime::now();
        let until = if secs >= 0 {
            now + std::time::Duration::from_secs(secs as u64)
        } else {
            now - std::time::Duration::from_nanos(1)
        };
        match self
            .backend
            .set_component_debug_logging(component, until)
            .await
        {
            Ok(()) => C2nResponse::json(200, &serde_json::json!({})),
            Err(e) => C2nResponse::json(200, &serde_json::json!({"error": e})),
        }
    }
}

// ---------------------------------------------------------------------------
// Query string helpers
// ---------------------------------------------------------------------------

fn parse_omit_fields(query: &str) -> Vec<String> {
    let params = parse_query_map(query);
    params
        .get("omit_fields")
        .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default()
}

fn parse_query_map(query: &str) -> std::collections::HashMap<String, String> {
    let mut params = std::collections::HashMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        if let Some((k, v)) = pair.split_once('=') {
            params.insert(k.to_string(), v.to_string());
        } else {
            params.insert(pair.to_string(), String::new());
        }
    }
    params
}

// ---------------------------------------------------------------------------
// Router registration + server spawn
// ---------------------------------------------------------------------------

/// Register all C2N handlers on the given router.
///
/// Mirrors Go's `init()` registration in `c2n.go`.
pub(crate) fn register_c2n_handlers(router: &mut C2nRouter, backend: Arc<TsnetC2nBackend>) {
    router.register("/echo", Arc::new(EchoHandler));
    router.register(
        "POST /logtail/flush",
        Arc::new(LogtailFlushHandler {
            backend: backend.clone(),
        }),
    );
    router.register("/debug/goroutines", Arc::new(GoroutinesHandler));
    router.register("/debug/pprof/heap", Arc::new(PprofHandler));
    router.register("/debug/pprof/allocs", Arc::new(PprofHandler));
    router.register(
        "/debug/prefs",
        Arc::new(BackendPrefsHandler {
            backend: backend.clone(),
        }),
    );
    router.register("/debug/logheap", Arc::new(LogheapHandler));
    router.register(
        "POST /sockstats",
        Arc::new(SockStatsHandler {
            backend: backend.clone(),
        }),
    );
    router.register(
        "GET /posture/identity",
        Arc::new(PostureIdentityHandler {
            backend: backend.clone(),
        }),
    );
    // Handlers that need the backend:
    router.register(
        "/debug/netmap",
        Arc::new(BackendNetmapHandler {
            backend: backend.clone(),
        }),
    );
    router.register(
        "/debug/health",
        Arc::new(BackendHealthHandler {
            backend: backend.clone(),
        }),
    );
    router.register(
        "/debug/component-logging",
        Arc::new(ComponentLoggingHandler {
            backend: backend.clone(),
        }),
    );
    router.register(
        "/dns",
        Arc::new(BackendDnsHandler {
            backend: backend.clone(),
        }),
    );
    // Rust-specific aliases
    router.register(
        "/netmap",
        Arc::new(BackendNetmapHandler {
            backend: backend.clone(),
        }),
    );
    router.register(
        "/prefs",
        Arc::new(BackendPrefsHandler {
            backend: backend.clone(),
        }),
    );
}
