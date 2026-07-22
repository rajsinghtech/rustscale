#[allow(clippy::wildcard_imports)]
use super::*;
use rand_core::{OsRng, RngCore as _};

const PERIODIC_ENDPOINT_UPDATE_MIN: std::time::Duration = std::time::Duration::from_secs(270);
const PERIODIC_ENDPOINT_UPDATE_JITTER_SECS: u64 = 60;

fn periodic_endpoint_update_delay(random: u64) -> std::time::Duration {
    PERIODIC_ENDPOINT_UPDATE_MIN
        + std::time::Duration::from_secs(random % (PERIODIC_ENDPOINT_UPDATE_JITTER_SECS + 1))
}

#[derive(Clone)]
pub(crate) struct LinkRouteSync {
    pub exit_map_gate: crate::ExitMapGate,
    pub peer_map: Arc<crate::peer_map::Runtime>,
    pub router: SharedRouter,
    pub route_table: Arc<RwLock<RouteTable>>,
    pub tailscale_ips: Vec<IpAddr>,
    pub prefs: Arc<RwLock<rustscale_ipn::Prefs>>,
}

fn block_and_report_exit_route_failure(
    routes: &mut RouteTable,
    health: &Tracker,
    error: impl std::fmt::Display,
) {
    routes.block_exit_traffic();
    health.set_unhealthy(
        WARN_EXIT_ROUTE_SECURITY,
        format!("exit-route security refresh failed: {error}"),
    );
}

#[derive(Clone, Default)]
pub(crate) struct InterfaceRouteSnapshot {
    pub addrs: Vec<IpAddr>,
    pub prefixes: Vec<rustscale_tsaddr::IpPrefix>,
}

/// Snapshot every non-TUN interface address plus prefixes connected on active
/// interfaces. Exact addresses are denied even when an interface is down;
/// connected prefixes describe routes the kernel can preserve directly.
pub(crate) fn connected_prefixes_from_state(
    state: &rustscale_netmon::State,
    rustscale_tun_name: &str,
) -> Result<InterfaceRouteSnapshot, String> {
    let mut addrs = Vec::new();
    let mut prefixes = Vec::new();
    for (name, addresses) in &state.interface_ips {
        let Some(meta) = state.interface_meta.get(name) else {
            return Err(format!("missing metadata for connected interface {name}"));
        };
        if meta.is_loopback || name == rustscale_tun_name {
            continue;
        }
        for prefix in addresses {
            if prefix.bits == 0 {
                continue;
            }
            addrs.push(prefix.ip);
            if !meta.is_up {
                continue;
            }
            let ip = match prefix.ip {
                IpAddr::V4(ip) if prefix.bits <= 32 => {
                    let mask = u32::MAX
                        .checked_shl(u32::from(32 - prefix.bits))
                        .unwrap_or(0);
                    IpAddr::V4((u32::from(ip) & mask).into())
                }
                IpAddr::V6(ip) if prefix.bits <= 128 => {
                    let mask = u128::MAX
                        .checked_shl(u32::from(128 - prefix.bits))
                        .unwrap_or(0);
                    IpAddr::V6((u128::from(ip) & mask).into())
                }
                _ => {
                    return Err(format!(
                        "invalid connected prefix {}/{}",
                        prefix.ip, prefix.bits
                    ))
                }
            };
            prefixes.push(rustscale_tsaddr::IpPrefix {
                ip,
                bits: prefix.bits,
            });
        }
    }
    addrs.sort();
    addrs.dedup();
    rustscale_tsaddr::sort_prefixes(&mut prefixes);
    prefixes.dedup();
    Ok(InterfaceRouteSnapshot { addrs, prefixes })
}

#[cfg(target_os = "macos")]
fn append_darwin_route_prefixes(
    prefixes: &mut Vec<rustscale_tsaddr::IpPrefix>,
    routes: Vec<rustscale_routetable::RouteEntry>,
    rustscale_tun_name: &str,
) {
    for route in routes {
        if route.iface.is_empty()
            || route.iface == rustscale_tun_name
            || route.dst.bits == 0
            || matches!(
                route.route_type,
                rustscale_routetable::RouteType::Local
                    | rustscale_routetable::RouteType::Broadcast
                    | rustscale_routetable::RouteType::Multicast
            )
        {
            continue;
        }
        prefixes.push(rustscale_tsaddr::IpPrefix {
            ip: route.dst.addr,
            bits: route.dst.bits,
        });
    }
}

fn security_prefixes_from_state(
    state: &rustscale_netmon::State,
    rustscale_tun_name: &str,
) -> Result<InterfaceRouteSnapshot, String> {
    #[cfg_attr(not(target_os = "macos"), allow(unused_mut))]
    let mut snapshot = connected_prefixes_from_state(state, rustscale_tun_name)?;
    #[cfg(target_os = "macos")]
    {
        let routes = rustscale_routetable::get_route_table(100_000)
            .map_err(|error| format!("Darwin route-table enumeration failed: {error}"))?;
        append_darwin_route_prefixes(&mut snapshot.prefixes, routes, rustscale_tun_name);
        rustscale_tsaddr::sort_prefixes(&mut snapshot.prefixes);
        snapshot.prefixes.dedup();
    }
    Ok(snapshot)
}

/// Spawn the network change monitor. On a major link change (interface IP
/// change, up/down transition, or wall-clock time jump), re-gathers local
/// endpoints, resets peer direct paths, closes DERP connections, re-STUNs,
/// and pushes a lightweight non-streaming MapRequest to the control plane.
pub(crate) async fn spawn_link_monitor(
    magicsock: Arc<Magicsock>,
    cancel: Arc<CancelToken>,
    control_url: String,
    machine_key: MachinePrivate,
    server_pub_key: MachinePublic,
    node_key: NodePrivate,
    disco_key: DiscoPrivate,
    udp_port: u16,
    hostname: String,
    advertise_routes: Vec<String>,
    derp_map: DERPMap,
    home_derp: i32,
    health: Tracker,
    route_sync: Option<LinkRouteSync>,
) -> Option<rustscale_netmon::MonitorHandle> {
    let (monitor, initial_enumeration_failed) = rustscale_netmon::Monitor::new_fail_closed();
    if initial_enumeration_failed {
        if let Some(route_sync) = route_sync.as_ref() {
            let _exit_map_guard = route_sync.exit_map_gate.lock().await;
            let _peer_gate = route_sync.peer_map.gate.write().await;
            let allow_lan = route_sync.prefs.read().await.ExitNodeAllowLANAccess;
            let security_required =
                route_sync.route_table.read().await.exit_node_requested() && !allow_lan;
            if security_required {
                let kernel_error = engage_kernel_security_block(
                    &route_sync.router,
                    SecurityBlockReason::Enumeration,
                )
                .err()
                .map(|error| format!("; kernel block: {error}"))
                .unwrap_or_default();
                route_sync.route_table.write().await.block_exit_traffic();
                route_sync.peer_map.advance_dial_epoch_locked();
                health.set_unhealthy(
                    WARN_EXIT_ROUTE_SECURITY,
                    format!("initial connected-interface enumeration failed{kernel_error}"),
                );
            }
        }
    }

    let handle = monitor.start().ok()?;
    handle.register_owned_change_callback(move |delta| {
        let magicsock = magicsock.clone();
        let cancel = cancel.clone();
        let control_url = control_url.clone();
        let machine_key = machine_key.clone();
        let server_pub_key = server_pub_key.clone();
        let node_key = node_key.clone();
        let disco_key = disco_key.clone();
        let hostname = hostname.clone();
        let advertise_routes = advertise_routes.clone();
        let derp_map = derp_map.clone();
        let health = health.clone();
        let route_sync = route_sync.clone();
        let home_derp = home_derp;
        async move {
            // Shutdown may race task scheduling; no callback may enter router
            // synchronization after owner cancellation.
            if cancel.is_cancelled() {
                return;
            }
            // Route notifications include default-interface-only changes that
            // are intentionally classified as minor. The netmon delta already
            // contains the successfully enumerated connected-prefix snapshot,
            // so security refresh does not perform a second fallible scan.
            if let Some(route_sync) = route_sync {
                // Global lock order: exit_map_gate -> peer gate -> prefs ->
                // route table -> router. Hold both gates through the complete
                // link-route commit so plans cannot invert peer/route locks.
                let _exit_map_guard = route_sync.exit_map_gate.lock().await;
                let tun_name = {
                    match route_sync.router.lock() {
                        Ok(router) => Some(router.tun_name.clone()),
                        Err(_) => None,
                    }
                };
                let Some(tun_name) = tun_name else {
                    let _peer_gate = route_sync.peer_map.gate.write().await;
                    let allow_lan = route_sync.prefs.read().await.ExitNodeAllowLANAccess;
                    let mut routes = route_sync.route_table.write().await;
                    if routes.exit_node_requested() && !allow_lan {
                        block_and_report_exit_route_failure(
                            &mut routes,
                            &health,
                            "router lock poisoned",
                        );
                    }
                    route_sync.peer_map.advance_dial_epoch_locked();
                    return;
                };
                let mut prefix_snapshot = if delta.enumeration_failed {
                    Err("connected-interface enumeration failed".to_string())
                } else {
                    security_prefixes_from_state(&delta.new, &tun_name)
                };
                loop {
                    if cancel.is_cancelled() {
                        return;
                    }
                    let peer_gate = route_sync.peer_map.gate.write().await;
                    let exit_node_allow_lan_access =
                        route_sync.prefs.read().await.ExitNodeAllowLANAccess;
                    let mut routes = route_sync.route_table.write().await;
                    let security_critical =
                        routes.exit_node_requested() && !exit_node_allow_lan_access;
                    let interface_routes = match &prefix_snapshot {
                        Ok(snapshot) => snapshot.clone(),
                        Err(error) if security_critical => {
                            let kernel_error = engage_kernel_security_block(
                                &route_sync.router,
                                SecurityBlockReason::Enumeration,
                            )
                            .err()
                                .map(|failure| format!("{error}; {failure}"))
                                .unwrap_or_else(|| error.clone());
                            block_and_report_exit_route_failure(
                                &mut routes,
                                &health,
                                kernel_error,
                            );
                            route_sync.peer_map.advance_dial_epoch_locked();
                            drop(routes);
                            drop(peer_gate);
                            tokio::select! {
                                () = cancel.cancelled() => return,
                                () = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
                            }
                            prefix_snapshot = rustscale_netmon::gather_state()
                                .ok_or_else(|| "connected-interface enumeration failed".to_string())
                                .and_then(|state| security_prefixes_from_state(&state, &tun_name));
                            continue;
                        }
                        Err(error) => {
                            log::warn!("tsnet: interface route snapshot invalid: {error}");
                            break;
                        }
                    };
                    if security_critical {
                        // Block fallback forwarding and install a kernel-level
                        // direct-traffic block before touching OS routes;
                        // successful sync is the only operation that reopens it.
                        routes.block_exit_traffic();
                        if let Err(error) = engage_kernel_security_block(
                            &route_sync.router,
                            SecurityBlockReason::LinkRefresh,
                        ) {
                            block_and_report_exit_route_failure(&mut routes, &health, error);
                            route_sync.peer_map.advance_dial_epoch_locked();
                            drop(routes);
                            drop(peer_gate);
                            tokio::select! {
                                () = cancel.cancelled() => return,
                                () = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
                            }
                            continue;
                        }
                    }
                    // Locks above can yield; check cancellation immediately
                    // before every possible sync_router call.
                    if cancel.is_cancelled() {
                        return;
                    }
                    match sync_router_with_connected_prefixes(
                        &route_sync.router,
                        &route_sync.tailscale_ips,
                        &mut routes,
                        &magicsock,
                        &control_url,
                        exit_node_allow_lan_access,
                        interface_routes.prefixes.clone(),
                    ) {
                        Ok(()) => {
                            let mut local_addrs = interface_routes.addrs;
                            local_addrs.extend_from_slice(&route_sync.tailscale_ips);
                            routes.set_local_interface_routes(
                                local_addrs,
                                interface_routes.prefixes,
                                exit_node_allow_lan_access,
                            );
                            let enumeration_latched = clear_kernel_security_block_reason(
                                &route_sync.router,
                                SecurityBlockReason::Enumeration,
                            )
                            .unwrap_or(true);
                            let link_latched = clear_kernel_security_block_reason(
                                &route_sync.router,
                                SecurityBlockReason::LinkRefresh,
                            )
                            .unwrap_or(true);
                            if enumeration_latched
                                || link_latched
                                || kernel_security_block_latched(&route_sync.router)
                            {
                                routes.block_exit_traffic();
                            } else {
                                routes.unblock_exit_traffic();
                                health.set_healthy(WARN_EXIT_ROUTE_SECURITY);
                            }
                            route_sync.peer_map.advance_dial_epoch_locked();
                            break;
                        }
                        Err(error) if security_critical => {
                            route_sync.peer_map.advance_dial_epoch_locked();
                            block_and_report_exit_route_failure(&mut routes, &health, error);
                            drop(routes);
                            drop(peer_gate);
                            tokio::select! {
                                () = cancel.cancelled() => return,
                                () = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
                            }
                            prefix_snapshot = rustscale_netmon::gather_state()
                                .ok_or_else(|| "connected-interface enumeration failed".to_string())
                                .and_then(|state| security_prefixes_from_state(&state, &tun_name));
                        }
                        Err(error) => {
                            route_sync.peer_map.advance_dial_epoch_locked();
                            log::warn!("tsnet: interface route refresh failed: {error}");
                            break;
                        }
                    }
                }
            }
            if !delta.major {
                return;
            }
            if cancel.is_cancelled() {
                return;
            }
            log::debug!(
                "tsnet: major link change detected; re-gathering endpoints + re-STUN (udp_port={udp_port})"
            );

            // Transient health warning while re-probing.
            health.set_unhealthy(WARN_NETMON_CHANGE, "network changed, re-probing");

            magicsock.link_changed();

            let mut eps = magicsock.all_endpoints();
            if !derp_map.Regions.is_empty() {
                if let Ok(report) = rustscale_netcheck::Prober
                    .run(
                        &derp_map,
                        &rustscale_netcheck::ProberOpts {
                            health: Some(health.clone()),
                            ..Default::default()
                        },
                    )
                    .await
                {
                    if let Some(g) = report.global_v4 {
                        eps.push(g.to_string());
                    }
                }
            }

            let node_pub = node_key.public();
            let disco_pub = disco_key.public();
            let req = MapRequest {
                Version: CAPABILITY_VERSION,
                KeepAlive: false,
                NodeKey: node_pub,
                DiscoKey: disco_pub,
                Stream: false,
                OmitPeers: true,
                Endpoints: eps,
                Hostinfo: Some(Hostinfo {
                    OS: std::env::consts::OS.into(),
                    Hostname: hostname,
                    RoutableIPs: advertise_routes,
                    NetInfo: Some(NetInfo {
                        PreferredDERP: home_derp,
                        WorkingUDP: OptBool::True,
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let cc = ControlClient::new(&control_url, machine_key, server_pub_key, PROTOCOL_VERSION);
            match cc.send_map_request(&req).await {
                Ok(()) => {
                    log::debug!("tsnet: link-change endpoint update sent");
                    // Endpoints re-published: clear the transient warning.
                    health.set_healthy(WARN_NETMON_CHANGE);
                }
                Err(e) => log::warn!("tsnet: link-change endpoint update failed (non-fatal): {e}"),
            }
        }
    });

    Some(handle)
}

/// Periodic endpoint update task (Bug 4).
///
/// Sends a non-streaming MapRequest with `OmitPeers=true` every 4.5–5.5 minutes
/// so the control server always has fresh endpoint data (local IPs, STUN
/// results, port-mapped endpoints). The maintenance probe is limited to the
/// current home DERP because endpoint publication consumes one reflexive
/// address; explicit diagnostic netchecks still measure every region.
/// Randomizing every interval mirrors Go's periodic re-STUN
/// anti-synchronization and prevents peers started together from phase-locking
/// their maintenance work. Go's controlclient publishes via `setEndpoints`;
/// rustscale previously sent endpoints only at startup and on link-change
/// (netmon), which could leave them stale in long-lived sessions.
///
/// The task is self-contained: it creates its own `ControlClient` per
/// update (to avoid sharing the streaming map-poll client) and respects
/// the shared `CancelToken`.
#[derive(Clone)]
struct PeriodicEndpointUpdate {
    magicsock: Arc<Magicsock>,
    control_url: String,
    machine_key: MachinePrivate,
    server_pub_key: MachinePublic,
    node_key: NodePrivate,
    disco_key: DiscoPrivate,
    hostname: String,
    advertise_routes: Vec<String>,
    derp_map: DERPMap,
    home_derp: i32,
    peer_relay_server: bool,
}

impl PeriodicEndpointUpdate {
    async fn run(&self) {
        let mut eps = self.magicsock.all_endpoints();
        if !self.derp_map.Regions.is_empty() {
            if let Ok(report) = rustscale_netcheck::Prober
                .run_endpoint_refresh(
                    &self.derp_map,
                    &rustscale_netcheck::ProberOpts {
                        previous_preferred_derp: self.home_derp,
                        ..Default::default()
                    },
                )
                .await
            {
                if let Some(g) = report.global_v4 {
                    eps.push(g.to_string());
                }
            }
        }

        let req = MapRequest {
            Version: CAPABILITY_VERSION,
            KeepAlive: false,
            NodeKey: self.node_key.public(),
            DiscoKey: self.disco_key.public(),
            Stream: false,
            OmitPeers: true,
            Endpoints: eps,
            Hostinfo: Some(Hostinfo {
                OS: std::env::consts::OS.into(),
                Hostname: self.hostname.clone(),
                RoutableIPs: self.advertise_routes.clone(),
                NetInfo: Some(NetInfo {
                    PreferredDERP: self.home_derp,
                    WorkingUDP: OptBool::True,
                    ..Default::default()
                }),
                PeerRelay: self.peer_relay_server,
                ..Default::default()
            }),
            ..Default::default()
        };
        let cc = ControlClient::new(
            &self.control_url,
            self.machine_key.clone(),
            self.server_pub_key.clone(),
            PROTOCOL_VERSION,
        );
        match cc.send_map_request(&req).await {
            Ok(()) => log::debug!("tsnet: periodic endpoint update sent"),
            Err(e) => log::warn!("tsnet: periodic endpoint update failed (non-fatal): {e}"),
        }
    }
}

async fn run_periodic_maintenance_isolated<F, Fut>(make_future: F) -> Result<(), String>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + 'static,
{
    tokio::task::spawn_blocking(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| format!("isolated endpoint runtime: {error}"))?;
        runtime.block_on(make_future());
        Ok(())
    })
    .await
    .map_err(|error| format!("isolated endpoint worker: {error}"))?
}

pub(crate) fn spawn_periodic_endpoint_updates(
    magicsock: Arc<Magicsock>,
    cancel: Arc<CancelToken>,
    control_url: String,
    machine_key: MachinePrivate,
    server_pub_key: MachinePublic,
    node_key: NodePrivate,
    disco_key: DiscoPrivate,
    hostname: String,
    advertise_routes: Vec<String>,
    derp_map: DERPMap,
    home_derp: i32,
    peer_relay_server: bool,
) -> JoinHandle<()> {
    let update = PeriodicEndpointUpdate {
        magicsock,
        control_url,
        machine_key,
        server_pub_key,
        node_key,
        disco_key,
        hostname,
        advertise_routes,
        derp_map,
        home_derp,
        peer_relay_server,
    };
    tokio::spawn(async move {
        loop {
            let delay = periodic_endpoint_update_delay(OsRng.next_u64());
            tokio::select! {
                () = tokio::time::sleep(delay) => {}
                () = cancel.cancelled() => break,
            }

            let maintenance = update.clone();
            let maintenance_cancel = Arc::clone(&cancel);
            if let Err(error) = run_periodic_maintenance_isolated(move || async move {
                tokio::select! {
                    () = maintenance_cancel.cancelled() => {}
                    () = maintenance.run() => {}
                }
            })
            .await
            {
                log::warn!("tsnet: periodic endpoint isolation failed (non-fatal): {error}");
            }
            if cancel.is_cancelled() {
                break;
            }
        }
    })
}

/// Periodic Hostinfo refresh loop (mirrors Go's
/// `controlclient.Direct.hostinfoUpdateLoop`).
///
/// Recollects `Hostinfo` every 10 minutes. If the content hash differs from
/// the last-sent hash, sends a lightweight non-streaming `MapRequest` with
/// `OmitPeers=true` carrying the new `Hostinfo`. An initial collection is
/// performed at startup so the control server has the full platform-detected
/// Hostinfo (the bootstrap sends a minimal one); the dedup hash prevents a
/// redundant send if the content matches.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_hostinfo_update_loop(
    cancel: Arc<CancelToken>,
    control_url: String,
    machine_key: MachinePrivate,
    server_pub_key: MachinePublic,
    node_key: NodePrivate,
    disco_key: DiscoPrivate,
    hostname: String,
    advertise_routes: Vec<String>,
    home_derp: i32,
    peers: Arc<RwLock<Vec<Node>>>,
    route_table: Arc<RwLock<RouteTable>>,
    serve: Option<Arc<serve::ServeRunner>>,
    overrides: SharedOverrides,
    state_dir: Option<PathBuf>,
    backend_log_id: String,
    ssh_host_keys: Arc<RwLock<Vec<String>>>,
    posture_checking: bool,
    preference_policy: Option<Arc<dyn crate::PreferencePolicy>>,
) -> JoinHandle<()> {
    let policy_changed = Arc::new(tokio::sync::Notify::new());
    let policy_subscription = preference_policy.as_ref().map(|policy| {
        let policy_changed = policy_changed.clone();
        policy.subscribe(Arc::new(move || policy_changed.notify_one()))
    });
    tokio::spawn(async move {
        let _policy_subscription = policy_subscription;
        let node_pub = node_key.public();
        let disco_pub = disco_key.public();

        // Initial collection: build the full Hostinfo and send it so control
        // has platform-detected fields. The bootstrap already sent a minimal
        // Hostinfo; this updates it to the full set. Dedup by content hash
        // prevents redundant sends on subsequent ticks.
        let mut last_hash: u64 = 0;

        loop {
            if cancel.is_cancelled() {
                break;
            }

            // Determine the exit node's StableNodeID (if any).
            let exit_node_id: Option<rustscale_tailcfg::StableNodeID> = {
                let exit_key = {
                    let rt = route_table.read().await;
                    rt.exit_node().cloned()
                };
                if let Some(key) = exit_key {
                    let peers_guard = peers.read().await;
                    peers_guard
                        .iter()
                        .find(|p| p.Key == key)
                        .map(|p| p.StableID.clone())
                        .filter(|id| !id.is_empty())
                } else {
                    None
                }
            };

            // Check whether funnel is active and whether it's configured but
            // inactive. Mirrors Go's hasIngressEnabledLocked / wantIngressLocked /
            // shouldWireInactiveIngressLocked in ipn/ipnlocal/serve.go.
            let (ingress_enabled, wire_ingress) = if let Some(ref runner) = serve {
                let on = runner.is_funnel_on().await;
                let configured = runner.has_allow_funnel().await;
                (on, !on && configured)
            } else {
                (false, false)
            };

            // Build the base Hostinfo with fields the bootstrap sets.
            let base = Hostinfo {
                OS: std::env::consts::OS.to_string(),
                Hostname: hostname.clone(),
                RoutableIPs: advertise_routes.clone(),
                NetInfo: Some(NetInfo {
                    PreferredDERP: home_derp,
                    WorkingUDP: OptBool::True,
                    ..Default::default()
                }),
                ..Default::default()
            };

            // Apply overrides + platform detection + runtime fields.
            // Read prefs so the control plane knows about ShieldsUp,
            // AppConnector, tags, and other pref-driven hostinfo fields.
            // Mirrors Go's hostinfo building in ipn/ipnlocal/local.go.
            let prefs = state_dir
                .as_ref()
                .and_then(|d| rustscale_ipn::Prefs::load(d).ok())
                .unwrap_or_default();
            let lower_precedence_allows_update = prefs.AutoUpdate.unwrap_or(false)
                || rustscale_envknob::bool("TS_ALLOW_ADMIN_CONSOLE_REMOTE_UPDATE").unwrap_or(false);
            let allows_update = preference_policy.as_ref().map_or_else(
                || lower_precedence_allows_update,
                |policy| {
                    policy
                        .allows_update(lower_precedence_allows_update)
                        .unwrap_or(false)
                },
            );
            let rt = RuntimeHostinfo {
                posture_checking,
                backend_log_id: backend_log_id.clone(),
                exit_node_id: exit_node_id.clone(),
                ingress_enabled,
                wire_ingress,
                shields_up: prefs.ShieldsUp,
                app_connector: prefs.AppConnector.Advertise,
                request_tags: prefs.AdvertiseTags.clone(),
                no_logs_no_support: prefs.NoLogsNoSupport,
                allows_update,
                sharee_node: false,
                ssh_host_keys: ssh_host_keys.read().await.clone(),
                wol_macs: hostinfo::wol_macs(),
                state_encrypted: OptBool::False,
                userspace: true,
                userspace_router: true,
                peer_relay: false,
            };
            let ov = overrides.read().await.clone();
            let hi = collect_hostinfo(base, &ov, &rt);

            let hash = hostinfo_hash(&hi);
            if hash != last_hash {
                let req = MapRequest {
                    Version: CAPABILITY_VERSION,
                    KeepAlive: false,
                    NodeKey: node_pub.clone(),
                    DiscoKey: disco_pub.clone(),
                    Stream: false,
                    OmitPeers: true,
                    Hostinfo: Some(hi),
                    ..Default::default()
                };
                let cc = ControlClient::new(
                    &control_url,
                    machine_key.clone(),
                    server_pub_key.clone(),
                    PROTOCOL_VERSION,
                );
                match cc.send_map_request(&req).await {
                    Ok(()) => {
                        last_hash = hash;
                    }
                    Err(e) => {
                        log::warn!("tsnet: hostinfo update send failed (non-fatal): {e}");
                    }
                }
            }

            tokio::select! {
                () = tokio::time::sleep(std::time::Duration::from_mins(10)) => {}
                () = policy_changed.notified(), if preference_policy.is_some() => {}
            }
        }
    })
}

pub(crate) async fn connect_home_derp(
    derp_map: &DERPMap,
    home_region: i32,
    node_key: &NodePrivate,
) -> Result<DerpClient, rustscale_derp::DerpError> {
    let region = derp_map
        .Regions
        .get(&home_region)
        .ok_or_else(|| rustscale_derp::DerpError::BadFrame("unknown DERP region".into()))?;
    let nodes = region
        .Nodes
        .as_ref()
        .ok_or_else(|| rustscale_derp::DerpError::BadFrame("no DERP nodes".into()))?;
    let node = nodes
        .iter()
        .find(|n| !n.STUNOnly)
        .or_else(|| nodes.first())
        .ok_or_else(|| rustscale_derp::DerpError::BadFrame("no DERP node".into()))?;
    let port = if node.DERPPort > 0 {
        node.DERPPort as u16
    } else {
        443
    };

    // Use the explicit IPv4 for TCP dialing if available, but always use
    // the hostname for TLS SNI (DERP servers reject IP-based SNI).
    let tls_host = node.HostName.clone();
    let dial_addr = if !node.IPv4.is_empty() && node.IPv4 != "none" {
        node.IPv4.clone()
    } else {
        node.HostName.clone()
    };

    let certificate_policy =
        rustscale_derp::CertificatePolicy::from_derp_cert_name(&node.CertName)?;
    let (use_tls, insecure) = derp_tls_options(node.InsecureForTests);
    DerpClient::connect_with_upgrade_dial_policy(
        &dial_addr,
        &tls_host,
        port,
        use_tls,
        insecure,
        certificate_policy,
        node_key.clone(),
        None,
    )
    .await
}

/// `InsecureForTests` permits an untrusted test certificate; it does not
/// change a DERP endpoint into plaintext HTTP. Testcontrol deliberately uses
/// a self-signed TLS listener, just like an ordinary DERP endpoint.
fn derp_tls_options(insecure_for_tests: bool) -> (bool, bool) {
    (true, insecure_for_tests)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tun_pump::ManagedRouter;
    use rustscale_key::NodePrivate;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn insecure_test_derp_keeps_tls_and_only_relaxes_certificate_validation() {
        assert_eq!(derp_tls_options(false), (true, false));
        assert_eq!(derp_tls_options(true), (true, true));
    }

    #[test]
    fn periodic_endpoint_update_delay_is_bounded_and_dephased() {
        assert_eq!(
            periodic_endpoint_update_delay(0),
            std::time::Duration::from_secs(270)
        );
        assert_eq!(
            periodic_endpoint_update_delay(60),
            std::time::Duration::from_secs(330)
        );
        assert_eq!(
            periodic_endpoint_update_delay(61),
            std::time::Duration::from_secs(270)
        );
        assert!((0..=60).all(|sample| {
            let delay = periodic_endpoint_update_delay(sample);
            (std::time::Duration::from_secs(270)..=std::time::Duration::from_secs(330))
                .contains(&delay)
        }));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn periodic_endpoint_work_runs_off_the_data_plane_runtime_thread() {
        let caller = std::thread::current().id();
        let observed = Arc::new(std::sync::Mutex::new(None));
        let worker_observed = Arc::clone(&observed);

        run_periodic_maintenance_isolated(move || async move {
            *worker_observed.lock().unwrap() = Some(std::thread::current().id());
        })
        .await
        .unwrap();

        assert_ne!(*observed.lock().unwrap(), Some(caller));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn periodic_endpoint_worker_honors_cross_runtime_cancellation() {
        let cancel = Arc::new(CancelToken::new());
        let worker_cancel = Arc::clone(&cancel);
        let work = tokio::spawn(run_periodic_maintenance_isolated(move || async move {
            worker_cancel.cancelled().await;
        }));

        tokio::task::yield_now().await;
        cancel.cancel();

        tokio::time::timeout(std::time::Duration::from_secs(1), work)
            .await
            .expect("isolated endpoint worker did not stop after cancellation")
            .expect("isolated endpoint worker task panicked")
            .expect("isolated endpoint worker failed");
    }

    struct BlockCountingRouter(Arc<AtomicUsize>);

    impl rustscale_router::Router for BlockCountingRouter {
        fn up(&mut self) -> Result<(), rustscale_router::RouterError> {
            Ok(())
        }
        fn set(
            &mut self,
            _config: &rustscale_router::RouterConfig,
        ) -> Result<(), rustscale_router::RouterError> {
            Ok(())
        }
        fn block_direct(&mut self) -> Result<(), rustscale_router::RouterError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn unblock_direct(&mut self) -> Result<(), rustscale_router::RouterError> {
            Ok(())
        }
        fn close(&mut self) -> Result<(), rustscale_router::RouterError> {
            Ok(())
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_interface_scoped_kernel_routes_are_captured() {
        let route = |iface: &str, cidr: &str| {
            let prefix = rustscale_tsaddr::IpPrefix::parse(cidr).unwrap();
            rustscale_routetable::RouteEntry {
                family: if prefix.ip.is_ipv4() { 4 } else { 6 },
                route_type: rustscale_routetable::RouteType::Unicast,
                dst: rustscale_routetable::RouteDestination {
                    addr: prefix.ip,
                    bits: prefix.bits,
                    zone: String::new(),
                },
                gateway: None,
                gateway_iface: Some(iface.into()),
                iface: iface.into(),
                flags: vec!["INTERFACE".into()],
                raw_flags: 0,
            }
        };
        let mut prefixes = Vec::new();
        append_darwin_route_prefixes(
            &mut prefixes,
            vec![
                route("en7", "198.51.100.0/24"),
                route("rustscale0", "203.0.113.0/24"),
            ],
            "rustscale0",
        );
        assert_eq!(
            prefixes,
            [rustscale_tsaddr::IpPrefix::parse("198.51.100.0/24").unwrap()]
        );
    }

    #[tokio::test]
    async fn link_route_sync_cannot_commit_after_newer_api_mutation() {
        let gate = Arc::new(tokio::sync::Mutex::new(()));
        let prefs = Arc::new(RwLock::new(rustscale_ipn::Prefs {
            ExitNodeAllowLANAccess: true,
            ..Default::default()
        }));
        let applied = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let link = {
            let gate = gate.clone();
            let prefs = prefs.clone();
            let applied = applied.clone();
            let barrier = barrier.clone();
            tokio::spawn(async move {
                let _guard = gate.lock().await;
                let snapshot = prefs.read().await.ExitNodeAllowLANAccess;
                barrier.wait().await;
                applied.lock().await.push(("link", snapshot));
            })
        };
        barrier.wait().await;
        let api = {
            let gate = gate.clone();
            let prefs = prefs.clone();
            let applied = applied.clone();
            tokio::spawn(async move {
                let _guard = gate.lock().await;
                prefs.write().await.ExitNodeAllowLANAccess = false;
                applied.lock().await.push(("api", false));
            })
        };
        link.await.unwrap();
        api.await.unwrap();
        assert_eq!(*applied.lock().await, [("link", true), ("api", false)]);
        assert!(!prefs.read().await.ExitNodeAllowLANAccess);
    }

    #[test]
    fn churn_snapshot_prevents_enumeration_failure_lan_leak() {
        let mut interface_ips = BTreeMap::new();
        interface_ips.insert(
            "corp-vpn0".into(),
            vec![rustscale_netmon::IpPrefix {
                ip: "100.100.2.99".parse().unwrap(),
                bits: 24,
            }],
        );
        interface_ips.insert(
            "rustscale0".into(),
            vec![rustscale_netmon::IpPrefix {
                ip: "100.64.0.1".parse().unwrap(),
                bits: 32,
            }],
        );
        let mut interface_meta = BTreeMap::new();
        interface_meta.insert(
            "corp-vpn0".into(),
            rustscale_netmon::InterfaceMeta {
                is_up: true,
                ..Default::default()
            },
        );
        interface_meta.insert(
            "rustscale0".into(),
            rustscale_netmon::InterfaceMeta {
                is_up: true,
                ..Default::default()
            },
        );
        let state = rustscale_netmon::State {
            interface_ips,
            interface_meta,
            have_v4: true,
            have_v6: false,
            default_route_interface: "corp-vpn0".into(),
        };

        // A second system scan can fail during churn; security refresh uses
        // the already-successful netmon snapshot instead.
        let injected_enumeration: Result<Vec<rustscale_tsaddr::IpPrefix>, _> =
            Err(std::io::Error::other("injected enumeration failure"));
        assert!(injected_enumeration.is_err());
        let connected = connected_prefixes_from_state(&state, "rustscale0").unwrap();
        assert_eq!(connected.addrs, ["100.100.2.99".parse::<IpAddr>().unwrap()]);
        assert_eq!(
            connected.prefixes,
            [rustscale_tsaddr::IpPrefix::parse("100.100.2.0/24").unwrap()]
        );

        let mut routes = RouteTable::default();
        routes.set_exit_node(NodePrivate::generate().public());
        let config = crate::tun_pump::build_router_config_with_local_routes(
            &[],
            &routes,
            false,
            connected.prefixes,
        );
        assert!(config
            .routes
            .contains(&rustscale_tsaddr::IpPrefix::parse("100.100.2.0/25").unwrap()));
        assert!(config
            .routes
            .contains(&rustscale_tsaddr::IpPrefix::parse("100.100.2.128/25").unwrap()));

        let blocks = Arc::new(AtomicUsize::new(0));
        let router = Arc::new(std::sync::Mutex::new(ManagedRouter {
            router: Box::new(BlockCountingRouter(blocks.clone())),
            tun_name: "rustscale0".into(),
            exit_node: true,
            security_block_attempted: false,
            security_block_verified: false,
            security_block_reasons: 0,
        }));
        engage_kernel_security_block(&router, SecurityBlockReason::Enumeration).unwrap();
        assert_eq!(blocks.load(Ordering::SeqCst), 1);
        let health = Tracker::new();
        block_and_report_exit_route_failure(&mut routes, &health, "injected route failure");
        assert!(routes.exit_traffic_blocked());
        assert!(routes.lookup("8.8.8.8".parse().unwrap()).is_none());
        assert!(health
            .current_warnings()
            .iter()
            .any(|warning| warning.id == WARN_EXIT_ROUTE_SECURITY));
    }
}
