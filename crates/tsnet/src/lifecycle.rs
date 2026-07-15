#[allow(clippy::wildcard_imports)]
use super::*;
use zeroize::{Zeroize, Zeroizing};

/// One-attempt auth material. It cannot be cloned and its formatting is always
/// redacted; dropping it zeroizes the allocation.
pub(crate) struct TransientAuthKey(Zeroizing<String>);

impl TransientAuthKey {
    fn new(secret: String) -> Self {
        Self(Zeroizing::new(secret))
    }

    fn take(&mut self) -> String {
        std::mem::take(&mut *self.0)
    }

    #[cfg(all(test, feature = "identity-federation"))]
    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl std::fmt::Debug for TransientAuthKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TransientAuthKey(<redacted>)")
    }
}

pub(crate) fn take_initial_register_auth(
    auth: &mut Option<TransientAuthKey>,
) -> Option<rustscale_tailcfg::RegisterResponseAuth> {
    let mut secret = auth.take()?;
    if secret.0.is_empty() {
        return None;
    }
    Some(rustscale_tailcfg::RegisterResponseAuth {
        AuthKey: secret.take(),
    })
}

pub(crate) fn clear_register_auth(request: &mut RegisterRequest) {
    if let Some(auth) = request.Auth.as_mut() {
        auth.AuthKey.zeroize();
    }
    request.Auth = None;
}

/// Nonblocking node lookup view used by the netlog aggregation task.
struct TsnetNetlogNodeSource {
    self_node: Option<Node>,
    peers: Arc<RwLock<Vec<Node>>>,
}

impl rustscale_netlog::NodeSource for TsnetNetlogNodeSource {
    fn self_node(&self) -> Option<rustscale_netlogtype::Node> {
        self.self_node.as_ref().map(netlog_node)
    }

    fn node_by_addr(&self, addr: IpAddr) -> Option<rustscale_netlogtype::Node> {
        if let Some(node) = self
            .self_node
            .as_ref()
            .filter(|node| node_has_addr(node, addr))
        {
            return Some(netlog_node(node));
        }
        // NodeSource is synchronous by design. Avoid blocking a runtime worker
        // if a map update briefly owns the peer list.
        self.peers
            .try_read()
            .ok()?
            .iter()
            .find(|node| node_has_addr(node, addr))
            .map(netlog_node)
    }
}

fn node_has_addr(node: &Node, addr: IpAddr) -> bool {
    node.Addresses.iter().any(|prefix| {
        prefix
            .split_once('/')
            .map_or(prefix.as_str(), |(ip, _)| ip)
            .parse::<IpAddr>()
            .is_ok_and(|node_addr| node_addr == addr)
    })
}

fn netlog_node(node: &Node) -> rustscale_netlogtype::Node {
    rustscale_netlogtype::Node {
        node_id: node.StableID.clone(),
        name: node.Name.trim_end_matches('.').to_string(),
        addresses: node
            .Addresses
            .iter()
            .filter_map(|prefix| {
                prefix
                    .split_once('/')
                    .map_or(prefix.as_str(), |(ip, _)| ip)
                    .parse::<IpAddr>()
                    .ok()
                    .map(|ip| ip.to_string())
            })
            .collect(),
        os: node
            .Hostinfo
            .as_ref()
            .map(|hostinfo| hostinfo.OS.clone())
            .unwrap_or_default(),
        tags: node.Tags.clone(),
        ..Default::default()
    }
}

impl Server {
    /// Bring the server online in userspace netstack mode (tsnet listen/dial).
    ///
    /// This is the classic tsnet embedding path: an in-process smoltcp netstack
    /// backs `listen`/`dial`. For a full-client TUN device instead, use
    /// [`Server::up_tun`].
    #[allow(clippy::large_futures)]
    ///
    /// **Idempotent**: calling `up()` on an already-running server returns
    /// `Ok(ServerStatus)` immediately without re-starting. Mirrors Go's
    /// `sync.Once`-guarded `Start()`.
    ///
    /// Returns the current [`ServerStatus`] after startup (or the existing
    /// status if already up). Mirrors Go's `Up()` which returns
    /// `(*ipnstate.Status, error)`.
    #[allow(clippy::large_futures)]
    pub async fn up(&mut self) -> Result<ServerStatus, TsnetError> {
        if self.inner.is_some() {
            return Ok(self.status());
        }

        ensure_ring_provider();
        let state = self.load_or_create_state()?;
        let initial_auth = self.initial_registration_auth(&state).await?;

        let b = self.bootstrap(state, initial_auth).await?;
        let prefs = Arc::new(RwLock::new(self.load_prefs().unwrap_or_default()));
        let exit_node_selection = Arc::new(RwLock::new(ExitNodeSelection::from_prefs(
            &*prefs.read().await,
        )));
        let audit_logger = Self::start_audit_logger(
            self.config.state_dir.clone(),
            self.config.control_url.clone(),
            b.machine_key.clone(),
            b.server_pub_key.clone(),
            b.node_key.clone(),
        )
        .await;

        let monitor = spawn_link_monitor(
            b.magicsock.clone(),
            b.cancel.clone(),
            b.control_url.clone(),
            b.machine_key.clone(),
            b.server_pub_key.clone(),
            b.node_key.clone(),
            b.disco_key.clone(),
            b.udp_port,
            b.hostname.clone(),
            b.advertise_routes.clone(),
            b.derp_map.clone(),
            b.home_derp,
            b.health.clone(),
        );

        // Userspace netstack bound to our tailnet IPv4.
        let netstack = Arc::new(Netstack::new(b.our_v4, DEFAULT_MTU));

        // Periodic endpoint update (Bug 4): pushes a non-streaming
        // MapRequest with OmitPeers=true every 5 minutes so the control
        // server always has fresh endpoint data.
        let periodic_ep = spawn_periodic_endpoint_updates(
            b.magicsock.clone(),
            b.cancel.clone(),
            b.control_url.clone(),
            b.machine_key.clone(),
            b.server_pub_key.clone(),
            b.node_key.clone(),
            b.disco_key.clone(),
            b.hostname.clone(),
            b.advertise_routes.clone(),
            b.derp_map.clone(),
            b.home_derp,
            self.config.peer_relay_server,
        );

        let capture = crate::capture::new_slot();

        // Netstack data-plane pump: netstack <-> WG <-> magicsock.
        let pump = tokio::spawn(run_netstack_pump(
            b.magicsock.clone(),
            b.wg_recv,
            netstack.clone(),
            b.wg_tunnels.clone(),
            b.route_table.clone(),
            b.filter.clone(),
            b.packet_drops.clone(),
            b.cancel.clone(),
            capture.clone(),
        ));

        // Map-stream update task (peer/route deltas).
        let suggested_exit_node: Arc<RwLock<String>> = Arc::new(RwLock::new(String::new()));
        let client_updater = Arc::new(std::sync::Mutex::new(
            rustscale_clientupdate::ClientUpdater::new(env!("CARGO_PKG_VERSION")),
        ));
        let key_rotation_ctx = KeyRotationCtx {
            control_url: b.control_url.clone(),
            machine_key: b.machine_key.clone(),
            server_pub_key: b.server_pub_key.clone(),
            hostname: self.config.hostname.clone(),
            ephemeral: self.config.ephemeral,
            advertise_routes: b.advertise_routes.clone(),
            peer_relay_server: self.config.peer_relay_server,
            disco_key: b.disco_key.clone(),
            capability_version: CAPABILITY_VERSION,
            protocol_version: PROTOCOL_VERSION,
            shields_up: prefs.read().await.ShieldsUp,
        };
        let map_update = spawn_map_update_task(
            b.map_rx,
            b.magicsock.clone(),
            b.wg_tunnels.clone(),
            b.peers.clone(),
            b.route_table.clone(),
            None,
            prefs.clone(),
            exit_node_selection.clone(),
            b.node_key.clone(),
            b.filter.clone(),
            b.tailscale_ips.clone(),
            b.control_url.clone(),
            self.config.accept_routes,
            b.advertise_routes.clone(),
            b.resolver.clone(),
            b.dns_config.clone(),
            b.user_profiles.clone(),
            b.ssh_policy.clone(),
            b.cancel.clone(),
            b.health.clone(),
            b.health_watchdog.clone(),
            self.config.state_dir.clone(),
            b.node_key.public(),
            b.control_knobs.clone(),
            b.key_expired.clone(),
            b.ipn_backend.clone(),
            Some(key_rotation_ctx),
            b.map_session.clone(),
            suggested_exit_node.clone(),
            client_updater.clone(),
        );

        // MagicDNS responder: best-effort UDP server at 100.100.100.100:53.
        // Binding to :53 typically requires root and the MagicDNS VIP to be
        // assigned to an interface; failure is non-fatal (dial still resolves
        // via the shared resolver). The responder serves A/AAAA/PTR for peer
        // hostnames, handles split-DNS routes, ExtraRecords, .onion NXDOMAIN,
        // 4via6 synthesis, and forwards the rest upstream (with TCP fallback
        // and DoH support).
        let mut tasks = vec![b.map_task, pump, map_update, periodic_ep];
        let dns_cfg_snapshot = b.dns_config.read().await.clone();
        let forwarder = Arc::new(Forwarder::from_dns_config(dns_cfg_snapshot.as_ref()));
        let responder = DnsResponder::with_forwarder(
            b.resolver.clone(),
            SocketAddr::new(IpAddr::V4(MAGICDNS_VIP), 53),
            forwarder,
        );
        match responder.spawn().await {
            Ok(handle) => tasks.push(handle),
            Err(e) => log::warn!(
                "tsnet: MagicDNS responder not started ({e}); dial still resolves via netmap"
            ),
        }

        // Serve/Funnel runner (netstack mode only).
        let serve = Some(Arc::new(serve::ServeRunner::new(
            netstack.clone(),
            b.peers.clone(),
            b.user_profiles.clone(),
            b.our_fqdn.clone(),
            b.magicsock.self_cap_map_arc(),
        )));

        let (c2n_task, c2n_addr) =
            c2n::spawn_c2n_server(b.c2n_backend.clone(), "rustscale".into()).await;
        tasks.push(c2n_task);

        // Taildrop file manager (shared between PeerAPI receive handler
        // and LocalAPI endpoints). Created from the state directory; if
        // no state dir, taildrop is disabled.
        let taildrop = Arc::new(taildrop::TaildropManager::new(
            self.config.state_dir.as_deref(),
            Some(b.ipn_backend.clone()),
        ));

        // PeerAPI server (netstack mode): listens on a deterministic port on
        // the node's tailnet IP, serving DoH DNS + debug endpoints to peers.
        let offering_exit_node = self.config.advertise_exit_node;
        let (peerapi_task, peerapi_port) = peerapi::spawn_peerapi_netstack(
            netstack.clone(),
            b.peers.clone(),
            b.user_profiles.clone(),
            b.resolver.clone(),
            b.dns_config.clone(),
            b.tailscale_ips.clone(),
            offering_exit_node,
            Some(taildrop.clone()),
            Some(b.sockstats.clone()),
        )
        .await;
        tasks.push(peerapi_task);

        // Advertise peerapi4/peerapi6 services to the control plane so peers
        // can discover our PeerAPI port.
        if let Some(port) = peerapi_port {
            let has_v6 = b.tailscale_ips.iter().any(|ip| matches!(ip, IpAddr::V6(_)));
            let services =
                peerapi::peerapi_services(Some(port), if has_v6 { Some(port) } else { None });
            if !services.is_empty() {
                let cc_ep = ControlClient::new(
                    &b.control_url,
                    b.machine_key.clone(),
                    b.server_pub_key.clone(),
                    PROTOCOL_VERSION,
                );
                let node_pub = b.node_key.public();
                let disco_pub = b.disco_key.public();
                let svc_req = MapRequest {
                    Version: CAPABILITY_VERSION,
                    KeepAlive: false,
                    NodeKey: node_pub,
                    DiscoKey: disco_pub,
                    Stream: false,
                    OmitPeers: true,
                    Hostinfo: Some(Hostinfo {
                        OS: std::env::consts::OS.to_string(),
                        Hostname: b.hostname.clone(),
                        RoutableIPs: b.advertise_routes.clone(),
                        Services: services,
                        PeerRelay: self.config.peer_relay_server,
                        ..Default::default()
                    }),
                    ..Default::default()
                };
                match cc_ep.send_map_request(&svc_req).await {
                    Ok(()) => log::info!("tsnet: peerapi services advertised (port {port})"),
                    Err(e) => {
                        log::warn!("tsnet: peerapi service advertisement failed (non-fatal): {e}");
                    }
                }
            }
        }

        // Portlist: shared state for the background port-scanning task and
        // the hostinfo hook. The hook adds portlist services to
        // Hostinfo.Services; the background task polls every N seconds and
        // updates the shared list. Mirrors Go's portlist EventBus extension.
        let portlist_ports: Arc<std::sync::Mutex<Vec<rustscale_portlist::Port>>> =
            Arc::new(std::sync::Mutex::new(vec![]));
        let proxy_mapper = Arc::new(rustscale_proxymap::Mapper::new());

        // Register a hostinfo hook that adds portlist + peerapi services to
        // Hostinfo.Services before it is sent to control.
        let pl_ports_hook = portlist_ports.clone();
        let hp_port = peerapi_port;
        let has_v6_hook = b.tailscale_ips.iter().any(|ip| matches!(ip, IpAddr::V6(_)));
        hostinfo::register_hostinfo_hook(move |hi| {
            let mut services = Vec::new();
            if let Some(port) = hp_port {
                if port > 0 {
                    services.push(rustscale_tailcfg::Service {
                        Proto: "peerapi4".into(),
                        Port: port,
                        Description: String::new(),
                    });
                    if has_v6_hook {
                        services.push(rustscale_tailcfg::Service {
                            Proto: "peerapi6".into(),
                            Port: port,
                            Description: String::new(),
                        });
                    }
                }
            }
            if let Ok(ports) = pl_ports_hook.lock() {
                services.extend(rustscale_portlist::to_services(&ports));
            }
            if !services.is_empty() {
                hi.Services = services;
            }
        });

        // Spawn the portlist poller background task.
        let pl_ports_task = portlist_ports.clone();
        let pl_cancel = b.cancel.clone();
        let pl_interval = rustscale_portlist::Poller::new(false).interval();
        let portlist_task = tokio::spawn(async move {
            let mut poller = rustscale_portlist::Poller::new(false);
            loop {
                if pl_cancel.is_cancelled() {
                    break;
                }
                let (ports, changed) = poller.poll().await;
                if changed {
                    if let Ok(mut guard) = pl_ports_task.lock() {
                        *guard = ports;
                    }
                }
                tokio::time::sleep(pl_interval).await;
            }
        });
        tasks.push(portlist_task);

        // Periodic Hostinfo refresh (every 10 min, dedup by content hash).
        let hostinfo_loop = spawn_hostinfo_update_loop(
            b.cancel.clone(),
            b.control_url.clone(),
            b.machine_key.clone(),
            b.server_pub_key.clone(),
            b.node_key.clone(),
            b.disco_key.clone(),
            b.hostname.clone(),
            b.advertise_routes.clone(),
            b.home_derp,
            b.peers.clone(),
            b.route_table.clone(),
            serve.clone(),
            b.overrides.clone(),
            self.config.state_dir.clone(),
            b.backend_log_id.clone(),
            b.ssh_host_keys.clone(),
            self.config.posture_checking,
        );
        tasks.push(hostinfo_loop);

        // LocalAPI Unix-domain-socket server (optional, default OFF).
        let localapi_socket = if self.config.localapi {
            let path = self.config.localapi_path.clone().unwrap_or_else(|| {
                let dir = self
                    .config
                    .state_dir
                    .clone()
                    .unwrap_or_else(|| std::env::temp_dir().join("rustscale"));
                localapi::default_socket_path(&dir)
            });
            let state = localapi::LocalApiState {
                peers: b.peers.clone(),
                user_profiles: b.user_profiles.clone(),
                health: b.health.clone(),
                dns_config: b.dns_config.clone(),
                packet_drops: b.packet_drops.clone(),
                capture: capture.clone(),
                metrics: localapi::default_metric_registry(),
                prefs: prefs.clone(),
                exit_node_selection: exit_node_selection.clone(),
                tailscale_ips: b.tailscale_ips.clone(),
                our_fqdn: b.our_fqdn.clone(),
                hostname: self.config.hostname.clone(),
                magicsock: b.magicsock.clone(),
                tun_mode: false,
                routecheck: Some(b.routecheck.clone()),
                home_derp: b.home_derp,
                ipn_backend: b.ipn_backend.clone(),
                derp_map: b.derp_map.clone(),
                command_tx: self
                    .pre_started
                    .as_ref()
                    .and_then(|ps| ps.command_tx.clone()),
                state_dir: self.config.state_dir.clone(),
                auth_url: Arc::new(std::sync::Mutex::new(None)),
                login_trigger: self
                    .pre_started
                    .as_ref()
                    .map(|ps| ps.login_trigger.clone())
                    .unwrap_or_else(|| Arc::new(tokio::sync::Notify::new())),
                serve_config: Arc::new(RwLock::new(
                    self.config
                        .state_dir
                        .as_ref()
                        .and_then(|d| serve::ServeConfig::load(d).ok())
                        .unwrap_or_default(),
                )),
                serve_runner: serve.clone(),
                profiles: Arc::new(RwLock::new(
                    self.config
                        .state_dir
                        .as_ref()
                        .and_then(|d| rustscale_ipn::LoginProfile::load_all(d).ok())
                        .unwrap_or_default(),
                )),
                current_profile: Arc::new(RwLock::new(
                    self.config
                        .state_dir
                        .as_ref()
                        .and_then(|d| rustscale_ipn::LoginProfile::load_current_id(d).ok())
                        .flatten(),
                )),
                cert_params: self
                    .config
                    .state_dir
                    .clone()
                    .map(|dir| localapi::CertParams {
                        state_dir: dir,
                        control_url: self.config.control_url.clone(),
                        machine_key: b.machine_key.clone(),
                        server_pub_key: b.server_pub_key.clone(),
                        node_key: b.node_key.clone(),
                        capability_version: CAPABILITY_VERSION,
                        protocol_version: PROTOCOL_VERSION,
                    }),
                control_params: Some(localapi::ControlParams {
                    control_url: self.config.control_url.clone(),
                    machine_key: b.machine_key.clone(),
                    server_pub_key: b.server_pub_key.clone(),
                    node_key: b.node_key.clone(),
                    capability_version: CAPABILITY_VERSION,
                    protocol_version: PROTOCOL_VERSION,
                }),
                taildrop: Some(taildrop.clone()),
                netstack: Some(netstack.clone()),
                filter: std::sync::OnceLock::new(),
                route_table: Some(b.route_table.clone()),
                router: None,
                logout_trigger: self
                    .pre_started
                    .as_ref()
                    .map(|ps| ps.logout_trigger.clone())
                    .unwrap_or_else(|| Arc::new(tokio::sync::Notify::new())),
                suggested_exit_node: suggested_exit_node.clone(),
                config_path: self.config.config_path.clone(),
                client_updater: client_updater.clone(),
                audit_logger: Some(audit_logger.clone()),
            };
            // Publish the live filter so `PATCH /prefs` can toggle
            // shields-up mode without a full rebuild.
            let _ = state.filter.set(b.filter.clone());
            if let Some(h) = localapi::spawn_localapi(Arc::new(state), path.clone()) {
                tasks.push(h.task);
                if let Some(ref ps) = self.pre_started {
                    if let Some(ref handle) = ps.handle {
                        handle.task.abort();
                    }
                }
                log::info!("tsnet: LocalAPI listening at {}", path.display());
                Some(h.socket_path)
            } else {
                log::warn!(
                    "tsnet: LocalAPI failed to bind socket at {}",
                    path.display()
                );
                None
            }
        } else {
            None
        };

        self.inner = Some(RunningState {
            tailscale_ips: b.tailscale_ips,
            magicsock: b.magicsock,
            netlog: b.netlog,
            data_plane: DataPlane::Netstack(netstack),
            peers: b.peers,
            routecheck: b.routecheck,
            route_table: b.route_table,
            router: None,
            cancel: b.cancel,
            tasks: Mutex::new(tasks),
            packet_drops: b.packet_drops,
            capture,
            capture_handles: std::sync::Mutex::new(vec![]),
            resolver: b.resolver,
            our_fqdn: b.our_fqdn,
            domain: b.domain.clone(),
            dns_config: b.dns_config,
            user_profiles: b.user_profiles,
            ssh_policy: b.ssh_policy,
            ssh_host_keys: b.ssh_host_keys,
            monitor,
            machine_key: b.machine_key,
            server_pub_key: b.server_pub_key,
            node_key: b.node_key,
            serve,
            health: b.health,
            health_watchdog: b.health_watchdog,
            c2n_router: b.c2n_router,
            c2n_addr: Some(c2n_addr),
            control_knobs: b.control_knobs,
            peerapi_port,
            overrides: b.overrides,
            localapi_socket,
            key_expired: b.key_expired,
            os_dns_configurator: None,
            ipn_backend: b.ipn_backend,
            logout_trigger: self
                .pre_started
                .as_ref()
                .map(|ps| ps.logout_trigger.clone())
                .unwrap_or_else(|| Arc::new(tokio::sync::Notify::new())),
            fallback_tcp_handlers: Arc::new(std::sync::Mutex::new(vec![])),
            fallback_next_id: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            prefs: prefs.clone(),
            exit_node_selection: exit_node_selection.clone(),
            proxy_mapper,
            portlist_ports,
            client_updater: client_updater.clone(),
            audit_logger,
        });

        // A persisted selection retries only while it is unresolved. Once it
        // resolves, later map rebuilds retain the route-table owner.
        let (peers, route_table) = match self.inner.as_ref() {
            Some(inner) => (inner.peers.clone(), inner.route_table.clone()),
            None => return Ok(self.status()),
        };
        let peers = peers.read().await;
        let mut routes = route_table.write().await;
        exit_node_selection.write().await.retry(&peers, &mut routes);

        Ok(self.status())
    }

    /// Bring the server online in **TUN mode**: route plaintext IP packets
    /// between a real OS TUN device and the WireGuard/magicsock data plane,
    /// instead of an in-process netstack.
    ///
    /// `listen`/`dial` are unavailable in TUN mode. Creating the TUN device
    /// requires root on both macOS (`utun`) and Linux (`/dev/net/tun`). If
    /// `config.apply_routes` is true, the interface is brought up and tailnet
    /// routes are added via `ifconfig`/`route` (macOS) or `ip` (Linux) — also
    /// requiring root.
    #[allow(clippy::large_futures)]
    pub async fn up_tun(&mut self, config: TunModeConfig) -> Result<ServerStatus, TsnetError> {
        if self.inner.is_some() {
            return Ok(self.status());
        }

        ensure_ring_provider();
        let state = self.load_or_create_state()?;
        let initial_auth = self.initial_registration_auth(&state).await?;

        let b = self.bootstrap(state, initial_auth).await?;
        let prefs = Arc::new(RwLock::new(self.load_prefs().unwrap_or_default()));
        let exit_node_selection = Arc::new(RwLock::new(ExitNodeSelection::from_prefs(
            &*prefs.read().await,
        )));
        let audit_logger = Self::start_audit_logger(
            self.config.state_dir.clone(),
            self.config.control_url.clone(),
            b.machine_key.clone(),
            b.server_pub_key.clone(),
            b.node_key.clone(),
        )
        .await;

        // Resolve and apply the exit node selection from TunModeConfig, if
        // set. This sets the in-process RouteTable's exit node so the data
        // pump routes non-tailnet traffic to the exit peer. OS-level
        // default-route overrides are installed after the TUN is created.
        if let Some(ref exit) = config.exit_node {
            let peers = b.peers.read().await;
            let peer_key = resolve_exit_node(&peers, exit)?;
            drop(peers);
            b.route_table.write().await.set_exit_node(peer_key);
            exit_node_selection.write().await.clear_pending();
            let mut live_prefs = prefs.write().await;
            set_exit_node_pref(&mut live_prefs, exit);
            if let Some(ref dir) = self.config.state_dir {
                let _ = live_prefs.save(dir);
            }
        }

        let monitor = spawn_link_monitor(
            b.magicsock.clone(),
            b.cancel.clone(),
            b.control_url.clone(),
            b.machine_key.clone(),
            b.server_pub_key.clone(),
            b.node_key.clone(),
            b.disco_key.clone(),
            b.udp_port,
            b.hostname.clone(),
            b.advertise_routes.clone(),
            b.derp_map.clone(),
            b.home_derp,
            b.health.clone(),
        );

        // Real TUN device (macOS/Linux only; on other platforms
        // `create_tun_device` returns an error and `?` propagates it).
        let exit_node_allow_lan_access = prefs.read().await.ExitNodeAllowLANAccess;
        let (tun, router) = create_tun_device(
            &config,
            &b,
            self.config.accept_routes,
            exit_node_allow_lan_access,
        )
        .await?;

        let capture = crate::capture::new_slot();

        // TUN data-plane pump: TUN <-> WG <-> magicsock.
        let pump = tokio::spawn(run_tun_pump(
            b.magicsock.clone(),
            b.wg_recv,
            tun.clone(),
            b.wg_tunnels.clone(),
            b.route_table.clone(),
            b.filter.clone(),
            b.packet_drops.clone(),
            b.cancel.clone(),
            capture.clone(),
        ));

        // Periodic endpoint update (Bug 4).
        let periodic_ep = spawn_periodic_endpoint_updates(
            b.magicsock.clone(),
            b.cancel.clone(),
            b.control_url.clone(),
            b.machine_key.clone(),
            b.server_pub_key.clone(),
            b.node_key.clone(),
            b.disco_key.clone(),
            b.hostname.clone(),
            b.advertise_routes.clone(),
            b.derp_map.clone(),
            b.home_derp,
            self.config.peer_relay_server,
        );

        let suggested_exit_node: Arc<RwLock<String>> = Arc::new(RwLock::new(String::new()));
        let client_updater = Arc::new(std::sync::Mutex::new(
            rustscale_clientupdate::ClientUpdater::new(env!("CARGO_PKG_VERSION")),
        ));
        let key_rotation_ctx = KeyRotationCtx {
            control_url: b.control_url.clone(),
            machine_key: b.machine_key.clone(),
            server_pub_key: b.server_pub_key.clone(),
            hostname: self.config.hostname.clone(),
            ephemeral: self.config.ephemeral,
            advertise_routes: b.advertise_routes.clone(),
            peer_relay_server: self.config.peer_relay_server,
            disco_key: b.disco_key.clone(),
            capability_version: CAPABILITY_VERSION,
            protocol_version: PROTOCOL_VERSION,
            shields_up: prefs.read().await.ShieldsUp,
        };
        let map_update = spawn_map_update_task(
            b.map_rx,
            b.magicsock.clone(),
            b.wg_tunnels.clone(),
            b.peers.clone(),
            b.route_table.clone(),
            router.clone(),
            prefs.clone(),
            exit_node_selection.clone(),
            b.node_key.clone(),
            b.filter.clone(),
            b.tailscale_ips.clone(),
            b.control_url.clone(),
            self.config.accept_routes,
            b.advertise_routes.clone(),
            b.resolver.clone(),
            b.dns_config.clone(),
            b.user_profiles.clone(),
            b.ssh_policy.clone(),
            b.cancel.clone(),
            b.health.clone(),
            b.health_watchdog.clone(),
            self.config.state_dir.clone(),
            b.node_key.public(),
            b.control_knobs.clone(),
            b.key_expired.clone(),
            b.ipn_backend.clone(),
            Some(key_rotation_ctx),
            b.map_session.clone(),
            suggested_exit_node.clone(),
            client_updater.clone(),
        );

        let (c2n_task, c2n_addr) =
            c2n::spawn_c2n_server(b.c2n_backend.clone(), "rustscale".into()).await;

        // Taildrop file manager (shared between PeerAPI receive handler
        // and LocalAPI endpoints). Created from the state directory.
        let taildrop = Arc::new(taildrop::TaildropManager::new(
            self.config.state_dir.as_deref(),
            Some(b.ipn_backend.clone()),
        ));

        // PeerAPI server (TUN mode): binds TCP listeners on the node's
        // tailnet IPs (v4 + v6) on the deterministic port.
        let offering_exit_node = self.config.advertise_exit_node;
        let (peerapi_task, peerapi_port) = peerapi::spawn_peerapi_tun(
            b.peers.clone(),
            b.user_profiles.clone(),
            b.resolver.clone(),
            b.dns_config.clone(),
            b.tailscale_ips.clone(),
            offering_exit_node,
            Some(taildrop.clone()),
            Some(b.sockstats.clone()),
        )
        .await;

        // Advertise peerapi4/peerapi6 services to the control plane.
        if let Some(port) = peerapi_port {
            let has_v6 = b.tailscale_ips.iter().any(|ip| matches!(ip, IpAddr::V6(_)));
            let services =
                peerapi::peerapi_services(Some(port), if has_v6 { Some(port) } else { None });
            if !services.is_empty() {
                let cc_ep = ControlClient::new(
                    &b.control_url,
                    b.machine_key.clone(),
                    b.server_pub_key.clone(),
                    PROTOCOL_VERSION,
                );
                let node_pub = b.node_key.public();
                let disco_pub = b.disco_key.public();
                let svc_req = MapRequest {
                    Version: CAPABILITY_VERSION,
                    KeepAlive: false,
                    NodeKey: node_pub,
                    DiscoKey: disco_pub,
                    Stream: false,
                    OmitPeers: true,
                    Hostinfo: Some(Hostinfo {
                        OS: std::env::consts::OS.to_string(),
                        Hostname: b.hostname.clone(),
                        RoutableIPs: b.advertise_routes.clone(),
                        Services: services,
                        PeerRelay: self.config.peer_relay_server,
                        ..Default::default()
                    }),
                    ..Default::default()
                };
                match cc_ep.send_map_request(&svc_req).await {
                    Ok(()) => log::info!("tsnet: peerapi services advertised (port {port})"),
                    Err(e) => {
                        log::warn!("tsnet: peerapi service advertisement failed (non-fatal): {e}");
                    }
                }
            }
        }

        // Portlist: shared state for the background port-scanning task and
        // the hostinfo hook (TUN mode).
        let portlist_ports: Arc<std::sync::Mutex<Vec<rustscale_portlist::Port>>> =
            Arc::new(std::sync::Mutex::new(vec![]));
        let proxy_mapper = Arc::new(rustscale_proxymap::Mapper::new());

        let pl_ports_hook = portlist_ports.clone();
        let hp_port = peerapi_port;
        let has_v6_hook = b.tailscale_ips.iter().any(|ip| matches!(ip, IpAddr::V6(_)));
        hostinfo::register_hostinfo_hook(move |hi| {
            let mut services = Vec::new();
            if let Some(port) = hp_port {
                if port > 0 {
                    services.push(rustscale_tailcfg::Service {
                        Proto: "peerapi4".into(),
                        Port: port,
                        Description: String::new(),
                    });
                    if has_v6_hook {
                        services.push(rustscale_tailcfg::Service {
                            Proto: "peerapi6".into(),
                            Port: port,
                            Description: String::new(),
                        });
                    }
                }
            }
            if let Ok(ports) = pl_ports_hook.lock() {
                services.extend(rustscale_portlist::to_services(&ports));
            }
            if !services.is_empty() {
                hi.Services = services;
            }
        });

        let pl_ports_task = portlist_ports.clone();
        let pl_cancel = b.cancel.clone();
        let pl_interval = rustscale_portlist::Poller::new(false).interval();
        let portlist_task = tokio::spawn(async move {
            let mut poller = rustscale_portlist::Poller::new(false);
            loop {
                if pl_cancel.is_cancelled() {
                    break;
                }
                let (ports, changed) = poller.poll().await;
                if changed {
                    if let Ok(mut guard) = pl_ports_task.lock() {
                        *guard = ports;
                    }
                }
                tokio::time::sleep(pl_interval).await;
            }
        });

        // Periodic Hostinfo refresh (every 10 min, dedup by content hash).
        // In TUN mode, serve/funnel is not available so pass None.
        let hostinfo_loop = spawn_hostinfo_update_loop(
            b.cancel.clone(),
            b.control_url.clone(),
            b.machine_key.clone(),
            b.server_pub_key.clone(),
            b.node_key.clone(),
            b.disco_key.clone(),
            b.hostname.clone(),
            b.advertise_routes.clone(),
            b.home_derp,
            b.peers.clone(),
            b.route_table.clone(),
            None,
            b.overrides.clone(),
            self.config.state_dir.clone(),
            b.backend_log_id.clone(),
            b.ssh_host_keys.clone(),
            self.config.posture_checking,
        );

        let mut tasks = vec![
            b.map_task,
            pump,
            map_update,
            periodic_ep,
            c2n_task,
            peerapi_task,
            hostinfo_loop,
            portlist_task,
        ];

        // LocalAPI Unix-domain-socket server (optional, default OFF).
        let localapi_socket = if self.config.localapi {
            let path = self.config.localapi_path.clone().unwrap_or_else(|| {
                let dir = self
                    .config
                    .state_dir
                    .clone()
                    .unwrap_or_else(|| std::env::temp_dir().join("rustscale"));
                localapi::default_socket_path(&dir)
            });
            let state = localapi::LocalApiState {
                peers: b.peers.clone(),
                user_profiles: b.user_profiles.clone(),
                health: b.health.clone(),
                dns_config: b.dns_config.clone(),
                packet_drops: b.packet_drops.clone(),
                capture: capture.clone(),
                metrics: localapi::default_metric_registry(),
                prefs: prefs.clone(),
                exit_node_selection: exit_node_selection.clone(),
                tailscale_ips: b.tailscale_ips.clone(),
                our_fqdn: b.our_fqdn.clone(),
                hostname: self.config.hostname.clone(),
                magicsock: b.magicsock.clone(),
                tun_mode: true,
                routecheck: Some(b.routecheck.clone()),
                home_derp: b.home_derp,
                ipn_backend: b.ipn_backend.clone(),
                derp_map: b.derp_map.clone(),
                command_tx: self
                    .pre_started
                    .as_ref()
                    .and_then(|ps| ps.command_tx.clone()),
                state_dir: self.config.state_dir.clone(),
                auth_url: Arc::new(std::sync::Mutex::new(None)),
                login_trigger: self
                    .pre_started
                    .as_ref()
                    .map(|ps| ps.login_trigger.clone())
                    .unwrap_or_else(|| Arc::new(tokio::sync::Notify::new())),
                serve_config: Arc::new(RwLock::new(
                    self.config
                        .state_dir
                        .as_ref()
                        .and_then(|d| serve::ServeConfig::load(d).ok())
                        .unwrap_or_default(),
                )),
                serve_runner: None, // TUN mode has no serve runner
                profiles: Arc::new(RwLock::new(
                    self.config
                        .state_dir
                        .as_ref()
                        .and_then(|d| rustscale_ipn::LoginProfile::load_all(d).ok())
                        .unwrap_or_default(),
                )),
                current_profile: Arc::new(RwLock::new(
                    self.config
                        .state_dir
                        .as_ref()
                        .and_then(|d| rustscale_ipn::LoginProfile::load_current_id(d).ok())
                        .flatten(),
                )),
                cert_params: self
                    .config
                    .state_dir
                    .clone()
                    .map(|dir| localapi::CertParams {
                        state_dir: dir,
                        control_url: self.config.control_url.clone(),
                        machine_key: b.machine_key.clone(),
                        server_pub_key: b.server_pub_key.clone(),
                        node_key: b.node_key.clone(),
                        capability_version: CAPABILITY_VERSION,
                        protocol_version: PROTOCOL_VERSION,
                    }),
                control_params: Some(localapi::ControlParams {
                    control_url: self.config.control_url.clone(),
                    machine_key: b.machine_key.clone(),
                    server_pub_key: b.server_pub_key.clone(),
                    node_key: b.node_key.clone(),
                    capability_version: CAPABILITY_VERSION,
                    protocol_version: PROTOCOL_VERSION,
                }),
                taildrop: Some(taildrop.clone()),
                netstack: None, // TUN mode has no netstack
                filter: std::sync::OnceLock::new(),
                route_table: Some(b.route_table.clone()),
                router: router.clone(),
                logout_trigger: self
                    .pre_started
                    .as_ref()
                    .map(|ps| ps.logout_trigger.clone())
                    .unwrap_or_else(|| Arc::new(tokio::sync::Notify::new())),
                suggested_exit_node: suggested_exit_node.clone(),
                config_path: self.config.config_path.clone(),
                client_updater: client_updater.clone(),
                audit_logger: Some(audit_logger.clone()),
            };
            // Publish the live filter so `PATCH /prefs` can toggle
            // shields-up mode without a full rebuild.
            let _ = state.filter.set(b.filter.clone());
            if let Some(h) = localapi::spawn_localapi(Arc::new(state), path.clone()) {
                tasks.push(h.task);
                if let Some(ref ps) = self.pre_started {
                    if let Some(ref handle) = ps.handle {
                        handle.task.abort();
                    }
                }
                log::info!("tsnet: LocalAPI listening at {}", path.display());
                Some(h.socket_path)
            } else {
                log::warn!(
                    "tsnet: LocalAPI failed to bind socket at {}",
                    path.display()
                );
                None
            }
        } else {
            None
        };

        // OS DNS configuration (macOS: /etc/resolver entries pointing at
        // 100.100.100.100). Opt-in via `configure_os_dns(true)` — requires
        // root. Best-effort: permission errors are logged and do not prevent
        // up_tun from completing.
        let os_dns_configurator = if self.config.configure_os_dns {
            let dns_cfg_snapshot = b.dns_config.read().await.clone();
            let os_cfg = if let Some(ref dc) = dns_cfg_snapshot {
                build_os_dns_config(dc, &b.domain)
            } else {
                OsConfig {
                    nameservers: vec![IpAddr::V4(MAGICDNS_VIP)],
                    ..Default::default()
                }
            };
            let mut configurator: Box<dyn OsConfigurator + Send> = Box::new(new_os_configurator());
            match configurator.set_dns(&os_cfg) {
                Ok(()) => {
                    log::info!(
                        "tsnet: OS DNS configured ({} match domains, {} search domains)",
                        os_cfg.match_domains.len(),
                        os_cfg.search_domains.len()
                    );
                    Some(configurator)
                }
                Err(e) => {
                    log::warn!("tsnet: OS DNS configuration failed (non-fatal, needs root?): {e}");
                    None
                }
            }
        } else {
            None
        };

        self.inner = Some(RunningState {
            tailscale_ips: b.tailscale_ips,
            magicsock: b.magicsock,
            netlog: b.netlog,
            data_plane: DataPlane::Tun,
            peers: b.peers,
            routecheck: b.routecheck,
            route_table: b.route_table,
            router,
            cancel: b.cancel,
            tasks: Mutex::new(tasks),
            packet_drops: b.packet_drops,
            capture,
            capture_handles: std::sync::Mutex::new(vec![]),
            resolver: b.resolver,
            our_fqdn: b.our_fqdn,
            domain: b.domain.clone(),
            dns_config: b.dns_config,
            user_profiles: b.user_profiles,
            ssh_policy: b.ssh_policy,
            ssh_host_keys: b.ssh_host_keys,
            monitor,
            machine_key: b.machine_key,
            server_pub_key: b.server_pub_key,
            node_key: b.node_key,
            serve: None,
            health: b.health,
            health_watchdog: b.health_watchdog,
            c2n_router: b.c2n_router,
            c2n_addr: Some(c2n_addr),
            control_knobs: b.control_knobs,
            peerapi_port,
            overrides: b.overrides,
            localapi_socket,
            key_expired: b.key_expired,
            os_dns_configurator,
            ipn_backend: b.ipn_backend,
            logout_trigger: self
                .pre_started
                .as_ref()
                .map(|ps| ps.logout_trigger.clone())
                .unwrap_or_else(|| Arc::new(tokio::sync::Notify::new())),
            fallback_tcp_handlers: Arc::new(std::sync::Mutex::new(vec![])),
            fallback_next_id: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            prefs: prefs.clone(),
            exit_node_selection: exit_node_selection.clone(),
            proxy_mapper,
            portlist_ports,
            client_updater: client_updater.clone(),
            audit_logger,
        });

        // TUN config owns a selection made above; otherwise retry only an
        // unresolved persisted selection.
        let (peers, route_table, router, tailscale_ips, magicsock, live_prefs) =
            match self.inner.as_ref() {
                Some(inner) => (
                    inner.peers.clone(),
                    inner.route_table.clone(),
                    inner.router.clone(),
                    inner.tailscale_ips.clone(),
                    inner.magicsock.clone(),
                    inner.prefs.clone(),
                ),
                None => return Ok(self.status()),
            };
        let peers = peers.read().await;
        let mut routes = route_table.write().await;
        if exit_node_selection.write().await.retry(&peers, &mut routes) {
            if let Some(router) = router.as_ref() {
                let derp_map = magicsock.get_derp_map();
                let exit_node_allow_lan_access = live_prefs.read().await.ExitNodeAllowLANAccess;
                sync_router(
                    router,
                    &tailscale_ips,
                    &routes,
                    derp_map.as_ref(),
                    &self.config.control_url,
                    exit_node_allow_lan_access,
                )?;
            }
        }

        Ok(self.status())
    }

    // --- shared control-plane bootstrap ---

    /// Ensure the server is up, starting it if needed. Called by `listen()`
    /// and `dial()` for lazy auto-start. Mirrors Go's `Server.Start()` being
    /// called by `Dial`/`Listen`. If the server is already up, this is a
    /// no-op (idempotent).
    pub async fn ensure_up(&mut self) -> Result<ServerStatus, TsnetError> {
        if self.inner.is_none() {
            Box::pin(self.up()).await?;
        }
        Ok(self.status())
    }

    /// Load prefs from the state directory, or return default if not found.
    pub(crate) fn load_prefs(&self) -> Result<rustscale_ipn::Prefs, TsnetError> {
        if let Some(ref dir) = self.config.state_dir {
            rustscale_ipn::Prefs::load(dir).map_err(|e| TsnetError::Builder(e.to_string()))
        } else {
            Ok(rustscale_ipn::Prefs::default())
        }
    }

    /// Set the auth key after construction (used by the daemon when the CLI
    /// provides it via `POST /start`).
    pub fn set_auth_key(&mut self, key: impl Into<String>) {
        self.config.auth_key = Some(key.into());
    }

    /// Start only the LocalAPI server without full bootstrap. Used by the
    /// daemon when no auth key is available — the server enters NeedsLogin
    /// state and waits for CLI-driven `up()` via `POST /start` or
    /// `POST /login-interactive`.
    ///
    /// Returns a command receiver for the daemon to listen on, and the
    /// login trigger Notify (used by `/login-interactive` to unblock
    /// bootstrap's auth wait).
    pub async fn start_localapi_only(
        &mut self,
    ) -> Result<mpsc::UnboundedReceiver<localapi::DaemonCommand>, TsnetError> {
        let ipn_backend = Arc::new(IpnBackend::new("rustscale"));
        ipn_backend.set_want_running();
        ipn_backend.set_auth_cant_continue(true);
        // Block engine updates while waiting for auth — mirrors Go's
        // blockEngineUpdatesLocked(true) on NeedsLogin enter.
        ipn_backend.set_blocked(true);

        let state = self.load_or_create_state()?;
        let was_fresh = state.is_zero();
        let state = if was_fresh {
            let s = PersistedState::generate();
            self.save_state(&s)?;
            s
        } else {
            state
        };
        ipn_backend.set_has_node_key(!state.is_zero());

        let prefs = self.load_prefs().unwrap_or_default();
        let prefs = Arc::new(RwLock::new(prefs));

        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let command_tx_clone = command_tx.clone();
        let login_trigger = Arc::new(tokio::sync::Notify::new());
        let auth_url = Arc::new(std::sync::Mutex::new(None));
        let logout_trigger = Arc::new(tokio::sync::Notify::new());

        let (magicsock, _wg_rx) = Magicsock::new(MagicsockConfig {
            private_key: state.node_key.clone(),
            disco_key: state.disco_key.clone(),
            derp_client: None,
            derp_map: Some(DERPMap::default()),
            home_derp_region: 0,
            udp_bind: None,
            udp_socket: None,
            portmapper: None,
            health: None,
            disable_direct_paths: false,
            peer_relay_server: false,
            relay_server_config: None,
            sockstats: None,
            control_knobs: Some(Arc::new(ControlKnobs::new())),
        })
        .await
        .map_err(TsnetError::Magicsock)?;
        let magicsock = Arc::new(magicsock);

        let socket_path = if let Some(ref p) = self.config.localapi_path {
            p.clone()
        } else if let Some(ref dir) = self.config.state_dir {
            localapi::default_socket_path(dir)
        } else {
            localapi::default_socket_path(&std::env::temp_dir().join("rustscale"))
        };

        let api_state = Arc::new(localapi::LocalApiState {
            peers: Arc::new(RwLock::new(vec![])),
            routecheck: None,
            user_profiles: Arc::new(RwLock::new(BTreeMap::new())),
            health: Tracker::new(),
            dns_config: Arc::new(RwLock::new(None)),
            packet_drops: Arc::new(AtomicU64::new(0)),
            capture: crate::capture::new_slot(),
            metrics: localapi::default_metric_registry(),
            prefs: prefs.clone(),
            exit_node_selection: Arc::new(RwLock::new(ExitNodeSelection::from_prefs(
                &*prefs.read().await,
            ))),
            tailscale_ips: vec![],
            our_fqdn: String::new(),
            hostname: self.config.hostname.clone(),
            magicsock: magicsock.clone(),
            tun_mode: false,
            home_derp: 0,
            ipn_backend: ipn_backend.clone(),
            derp_map: DERPMap::default(),
            command_tx: Some(command_tx),
            state_dir: self.config.state_dir.clone(),
            auth_url: auth_url.clone(),
            login_trigger: login_trigger.clone(),
            serve_config: Arc::new(RwLock::new(
                self.config
                    .state_dir
                    .as_ref()
                    .and_then(|d| serve::ServeConfig::load(d).ok())
                    .unwrap_or_default(),
            )),
            serve_runner: None,
            profiles: Arc::new(RwLock::new(
                self.config
                    .state_dir
                    .as_ref()
                    .and_then(|d| rustscale_ipn::LoginProfile::load_all(d).ok())
                    .unwrap_or_default(),
            )),
            current_profile: Arc::new(RwLock::new(
                self.config
                    .state_dir
                    .as_ref()
                    .and_then(|d| rustscale_ipn::LoginProfile::load_current_id(d).ok())
                    .flatten(),
            )),
            cert_params: None,
            control_params: None,
            taildrop: None,
            netstack: None,
            filter: std::sync::OnceLock::new(),
            route_table: None,
            router: None,
            logout_trigger: logout_trigger.clone(),
            suggested_exit_node: Arc::new(RwLock::new(String::new())),
            config_path: self.config.config_path.clone(),
            client_updater: Arc::new(std::sync::Mutex::new(
                rustscale_clientupdate::ClientUpdater::new(env!("CARGO_PKG_VERSION")),
            )),
            audit_logger: None,
        });

        let handle = localapi::spawn_localapi(api_state.clone(), socket_path.clone());
        if handle.is_some() {
            log::info!(
                "tsnet: LocalAPI (needs-login) listening at {}",
                socket_path.display()
            );
        } else {
            log::warn!("tsnet: LocalAPI failed to bind {}", socket_path.display());
        }

        self.pre_started = Some(PreStartedLocalApi {
            backend: ipn_backend,
            handle,
            login_trigger,
            auth_url,
            command_rx: Some(command_rx),
            command_tx: Some(command_tx_clone),
            logout_trigger,
            socket_path,
        });

        Ok(self
            .pre_started
            .as_mut()
            .unwrap()
            .command_rx
            .take()
            .unwrap())
    }

    /// Select transient credentials for the initial register request.
    /// Persisted enrollments authenticate by node identity unless force-login
    /// was explicitly requested.
    pub(crate) async fn initial_registration_auth(
        &mut self,
        state: &PersistedState,
    ) -> Result<Option<TransientAuthKey>, TsnetError> {
        if state.is_enrolled() && !self.config.force_login {
            return Ok(None);
        }
        if self
            .config
            .auth_key
            .as_deref()
            .is_some_and(|key| !key.is_empty())
        {
            return Ok(self.config.auth_key.clone().map(TransientAuthKey::new));
        }

        #[cfg(feature = "identity-federation")]
        rustscale_identityfederation::install()
            .map_err(|error| TsnetError::IdentityFederation(error.to_string()))?;

        let Some(resolve) = rustscale_feature::RESOLVE_AUTH_KEY_VIA_WIF.try_get() else {
            return Ok(None);
        };
        let client_id = &self.config.client_id;
        let id_token = &self.config.id_token;
        let audience = &self.config.audience;
        if client_id.is_empty() && id_token.is_empty() && audience.is_empty() {
            return Ok(None);
        }
        if !client_id.is_empty() && id_token.is_empty() && audience.is_empty() {
            return Err(TsnetError::IdentityFederation(
                "client ID for workload identity federation found, but ID token and audience are empty"
                    .into(),
            ));
        }
        if !id_token.is_empty() && !audience.is_empty() {
            return Err(TsnetError::IdentityFederation(
                "only one of ID token and audience should be for workload identity federation"
                    .into(),
            ));
        }
        if client_id.is_empty() {
            if !id_token.is_empty() {
                return Err(TsnetError::IdentityFederation(
                    "ID token for workload identity federation found, but client ID is empty"
                        .into(),
                ));
            }
            if !audience.is_empty() {
                return Err(TsnetError::IdentityFederation(
                    "audience for workload identity federation found, but client ID is empty"
                        .into(),
                ));
            }
        }

        let auth_key = resolve(rustscale_feature::IdentityFederationRequest {
            base_url: self.config.control_url.clone(),
            client_id: client_id.clone(),
            id_token: id_token.clone(),
            audience: audience.clone(),
            tags: self.config.advertise_tags.clone(),
        })
        .await
        .map_err(|error| TsnetError::IdentityFederation(error.to_string()))?;
        if auth_key.is_empty() {
            Ok(None)
        } else {
            Ok(Some(TransientAuthKey::new(auth_key)))
        }
    }

    /// Shared bootstrapping for `up()` and `up_tun()`: load state, register
    /// with control, start the map long-poll, wait for the first `MapResponse`,
    /// netcheck for a home DERP, connect it, build magicsock + per-peer WG
    /// tunnels + the routing table. Returns the shared handles plus the
    /// still-open map receiver for the update task.
    async fn bootstrap(
        &mut self,
        mut state: PersistedState,
        mut initial_auth: Option<TransientAuthKey>,
    ) -> Result<Bootstrap, TsnetError> {
        // Effective advertised routes: user-specified subnet routes plus the
        // exit-node default routes (0.0.0.0/0, ::/0) when advertise_exit_node
        // is enabled. Used for Hostinfo.RoutableIPs, the filter's localNets,
        // and link-change endpoint updates.
        let advertise = self.config.effective_advertise_routes();

        // Health tracker + map-poll staleness watchdog (fires if no
        // MapResponse for more than 3 minutes).
        let health = Tracker::new();
        let health_watchdog = Watchdog::new(
            health.clone(),
            WARN_CONTROL,
            "Control connection",
            Severity::High,
            "control connection lost: no map activity for over 3 minutes",
            std::time::Duration::from_mins(3),
        );

        // Socket-statistics registry (per-label TX/RX byte counters).
        // Shared across magicsock, DERP, DNS, and the C2N/PeerAPI debug
        // endpoints. Best-effort: instrumentation is fire-and-forget atomic
        // increments with no error paths.
        let sockstats = Arc::new(rustscale_sockstats::SockStats::new());

        // IPN state machine backend. Created early so state transitions
        // are tracked from the start. Want_running is set immediately;
        // other inputs are set as bootstrap progresses.
        let ipn_backend = if let Some(ref ps) = self.pre_started {
            ps.backend.clone()
        } else {
            Arc::new(IpnBackend::new("rustscale"))
        };
        ipn_backend.set_want_running();

        // 1. Generate persistent key material when no state was loaded.
        let was_fresh = state.is_zero();
        if was_fresh {
            state = PersistedState::generate();
            self.save_state(&state)?;
        }

        let private_log_id = if let Some(dir) = self.config.state_dir.as_ref() {
            rustscale_logid::PrivateID::load_or_create(&dir.join("logid-private"))?
        } else {
            rustscale_logid::PrivateID::new()
        };
        let backend_log_id = private_log_id.public().to_string();

        let node_pub = state.node_key.public();
        let disco_pub = state.disco_key.public();

        // We have a node key (generated or loaded from state).
        ipn_backend.set_has_node_key(!state.is_zero());

        // Try to load a cached netmap from the state directory. On a restart
        // with an existing state dir, this lets us skip the blocking first
        // MapResponse fetch (2-5s) and use the cached peers immediately —
        // the streaming long-poll delivers fresh updates in the background.
        let cached_netmap = self
            .config
            .state_dir
            .as_ref()
            .and_then(|dir| PersistedState::load_netmap(dir, &node_pub));

        // 2. Fetch the server's Noise public key (GET /key?v=<version>).
        let server_pub_key = controlhttp::fetch_server_pub_key(
            &self.config.control_url,
            PROTOCOL_VERSION,
            self.config.extra_root_certs.as_deref(),
        )
        .await
        .map_err(|e| TsnetError::Register(rustscale_controlclient::RegisterError::Dial(e)))?;

        // 3. Register with the control plane. Authentication is consumed by
        // this one request and omitted from followups and all later refreshes.
        let mut cc = ControlClient::new(
            self.config.control_url.clone(),
            state.machine_key.clone(),
            server_pub_key.clone(),
            PROTOCOL_VERSION,
        );
        if let Some(certs) = self.config.extra_root_certs.clone() {
            cc.set_extra_root_certs(certs);
        }

        let mut reg_req = RegisterRequest {
            Version: CAPABILITY_VERSION,
            NodeKey: node_pub.clone(),
            Auth: take_initial_register_auth(&mut initial_auth),
            Hostinfo: Some(Hostinfo {
                OS: std::env::consts::OS.to_string(),
                Hostname: self.config.hostname.clone(),
                RoutableIPs: advertise.clone(),
                RequestTags: self.config.advertise_tags.clone(),
                PeerRelay: self.config.peer_relay_server,
                ..Default::default()
            }),
            Ephemeral: self.config.ephemeral,
            ..Default::default()
        };

        drop(initial_auth);
        let register_result = cc.register(&reg_req).await;
        clear_register_auth(&mut reg_req);
        let reg_resp = register_result.map_err(|e| {
            // Auth/network failure is ambiguous. The key is not retained, so
            // a fresh WIF key is minted if the caller starts again.
            if let Some(ref dir) = self.config.state_dir {
                PersistedState::clear_netmap(dir);
                log::warn!("tsnet: cleared netmap cache after register error: {e}");
            }
            ipn_backend.emit_err_message(e.to_string());
            TsnetError::Register(e)
        })?;

        // Server-side error string (e.g. "invalid auth key", "node key revoked").
        if !reg_resp.Error.is_empty() {
            if let Some(ref dir) = self.config.state_dir {
                PersistedState::clear_netmap(dir);
                log::warn!(
                    "tsnet: cleared netmap cache after register error: {}",
                    reg_resp.Error
                );
            }
            ipn_backend.emit_err_message(&reg_resp.Error);
            return Err(TsnetError::Builder(format!(
                "control register rejected: {}",
                reg_resp.Error
            )));
        }

        // Node key expired — the server says our key is no longer valid.
        // Clear the cache so we don't reuse a netmap bound to the old key.
        if reg_resp.NodeKeyExpired {
            if let Some(ref dir) = self.config.state_dir {
                PersistedState::clear_netmap(dir);
                log::info!("tsnet: cleared netmap cache: node key expired");
            }
            ipn_backend.set_key_expired(true);
        }

        if reg_resp.AuthURL.is_empty() {
            ipn_backend.set_machine_authorized(reg_resp.MachineAuthorized);
            ipn_backend.set_blocked(false);
            ipn_backend.emit_login_finished();
            state.node_id = reg_resp.User.ID;
            state.enrolled = true;
            self.save_state(&state)?;
        } else {
            ipn_backend.set_auth_cant_continue(true);
            // Block engine updates while waiting for interactive auth.
            ipn_backend.set_blocked(true);
            ipn_backend.emit_browse_to_url(&reg_resp.AuthURL);

            if let Some(ref ps) = self.pre_started {
                {
                    let mut au = ps.auth_url.lock().unwrap();
                    *au = Some(reg_resp.AuthURL.clone());
                }
                ps.login_trigger.notified().await;
                {
                    let mut au = ps.auth_url.lock().unwrap();
                    *au = None;
                }
                ipn_backend.set_auth_cant_continue(false);

                let followup_req = RegisterRequest {
                    Version: CAPABILITY_VERSION,
                    NodeKey: node_pub.clone(),
                    Followup: reg_resp.AuthURL.clone(),
                    Hostinfo: Some(Hostinfo {
                        OS: std::env::consts::OS.to_string(),
                        Hostname: self.config.hostname.clone(),
                        RoutableIPs: advertise.clone(),
                        RequestTags: self.config.advertise_tags.clone(),
                        PeerRelay: self.config.peer_relay_server,
                        ..Default::default()
                    }),
                    Ephemeral: self.config.ephemeral,
                    ..Default::default()
                };
                let followup_resp = cc.register(&followup_req).await.map_err(|e| {
                    if let Some(ref dir) = self.config.state_dir {
                        PersistedState::clear_netmap(dir);
                    }
                    ipn_backend.emit_err_message(e.to_string());
                    TsnetError::Register(e)
                })?;

                if followup_resp.Error.is_empty() {
                    ipn_backend.set_machine_authorized(followup_resp.MachineAuthorized);
                    ipn_backend.set_blocked(false);
                    ipn_backend.emit_login_finished();
                    state.node_id = followup_resp.User.ID;
                    state.enrolled = true;
                    self.save_state(&state)?;
                } else {
                    ipn_backend.emit_err_message(&followup_resp.Error);
                    return Err(TsnetError::Builder(format!(
                        "control register (followup) rejected: {}",
                        followup_resp.Error
                    )));
                }
            } else {
                return Err(TsnetError::AuthRequired(reg_resp.AuthURL));
            }
        }

        // 3b. Bind the UDP socket early so we can gather local interface
        // endpoints (interface IP + bound port) and advertise them in the
        // MapRequest. Magicsock takes ownership of this socket later, once
        // the DERPMap/home-DERP are known from the first MapResponse.
        // Without advertised endpoints, peers only learn our addresses via
        // CallMeMaybe (one-shot, racy) and two nodes on the same machine
        // never establish a direct UDP path — they stay on DERP.
        let udp_socket = Arc::new(
            tokio::net::UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], self.config.port)))
                .await
                .map_err(TsnetError::Io)?,
        );
        let udp_port = udp_socket.local_addr().map_err(TsnetError::Io)?.port();
        let local_endpoints = rustscale_magicsock::gather_local_endpoints(udp_port);
        self.log_msg(format!("tsnet: local UDP endpoints: {local_endpoints:?}"));

        // Create a port-mapping client (NAT-PMP/PCP/UPnP) so magicsock can
        // publish a port-mapped external endpoint alongside local/STUN
        // endpoints. Best-effort: if the gateway doesn't support any
        // port-mapping protocol, this silently produces no endpoint.
        let portmapper = rustscale_portmapper::Client::new();
        portmapper.set_local_port(udp_port);

        // 3c. Send a lightweight non-streaming MapRequest to push our
        // DiscoKey + Endpoints to the control server BEFORE starting the
        // streaming long-poll. The control server processes the MapRequest
        // body asynchronously and the first streaming MapResponse is
        // generated from registration data (which lacks DiscoKey/Endpoints).
        // Without this pre-update, peers see DiscoKey=zero and Endpoints=[]
        // and can never initiate disco probing for a direct path.
        let endpoint_update_req = MapRequest {
            Version: CAPABILITY_VERSION,
            KeepAlive: false,
            NodeKey: node_pub.clone(),
            DiscoKey: disco_pub.clone(),
            Stream: false,
            OmitPeers: true,
            Endpoints: local_endpoints.clone(),
            Hostinfo: Some(Hostinfo {
                OS: std::env::consts::OS.to_string(),
                Hostname: self.config.hostname.clone(),
                RoutableIPs: advertise.clone(),
                PeerRelay: self.config.peer_relay_server,
                ..Default::default()
            }),
            ..Default::default()
        };
        let cc_ep = ControlClient::new(
            self.config.control_url.clone(),
            state.machine_key.clone(),
            server_pub_key.clone(),
            PROTOCOL_VERSION,
        );
        match cc_ep.send_map_request(&endpoint_update_req).await {
            Ok(()) => log::debug!("tsnet: endpoint update sent (DiscoKey + {local_endpoints:?})"),
            Err(e) => log::warn!("tsnet: endpoint update failed (non-fatal): {e}"),
        }

        // 4. Fetch the first MapResponse. If we have a cached netmap, skip
        // the blocking fetch and use the cached data — the streaming
        // long-poll (started below) will deliver fresh updates in the
        // background. This eliminates the 2-5s startup delay on restarts.
        let map_resp: MapResponse = if let Some(ref cached) = cached_netmap {
            let peer_count = cached.Peers.len();
            log::debug!(
                "tsnet: using cached netmap ({peer_count} peers); streaming poll will refresh in background"
            );
            cached.clone()
        } else {
            let fetch_req = MapRequest {
                Version: CAPABILITY_VERSION,
                KeepAlive: false,
                NodeKey: node_pub.clone(),
                DiscoKey: disco_pub.clone(),
                Stream: false,
                Endpoints: local_endpoints.clone(),
                Hostinfo: Some(Hostinfo {
                    OS: std::env::consts::OS.to_string(),
                    Hostname: self.config.hostname.clone(),
                    RoutableIPs: advertise.clone(),
                    PeerRelay: self.config.peer_relay_server,
                    ..Default::default()
                }),
                ..Default::default()
            };
            tokio::time::timeout(
                std::time::Duration::from_secs(30),
                cc_ep.fetch_map(&fetch_req),
            )
            .await
            .map_err(|_| TsnetError::MapTimeout)??
        };

        let tailscale_ips = extract_tailscale_ips(&map_resp);
        if tailscale_ips.is_empty() {
            return Err(TsnetError::Builder("no tailscale IPs assigned".into()));
        }
        let our_v4 = first_v4(&tailscale_ips)?;

        // We have a netmap — update the IPN state machine. Set netmap_present
        // and engine status (peer count + DERP home as a proxy for live
        // connections). This may transition the state from Starting to Running.
        let peer_count = map_resp.Peers.iter().filter(|p| !p.Key.is_zero()).count() as i32;
        let has_derp_home = map_resp.Node.as_ref().is_some_and(|n| n.HomeDERP > 0);
        ipn_backend.set_netmap_present(true);
        ipn_backend.set_engine_status(peer_count, i32::from(has_derp_home));

        // 6. Pick home DERP. Prefer the control-assigned HomeDERP from our
        // own node in the MapResponse — this ensures both nodes in the same
        // tailnet use the same DERP region. Fall back to netcheck, then to
        // the first available region.
        let derp_map = map_resp.DERPMap.clone().unwrap_or_default();
        let home_derp = if derp_map.Regions.is_empty() {
            0
        } else {
            // Try control-assigned HomeDERP first.
            let assigned = map_resp
                .Node
                .as_ref()
                .map(|n| n.HomeDERP)
                .filter(|&d| d > 0);
            if let Some(d) = assigned {
                log::info!("tsnet: using control-assigned home DERP region {d}");
                d
            } else {
                // Fall back to netcheck.
                match rustscale_netcheck::Prober
                    .run(&derp_map, &rustscale_netcheck::ProberOpts::default())
                    .await
                {
                    Ok(r) if r.preferred_derp > 0 => r.preferred_derp,
                    _ => derp_map
                        .Regions
                        .values()
                        .find(|r| !r.Avoid)
                        .or_else(|| derp_map.Regions.values().next())
                        .map_or(0, |r| r.RegionID),
                }
            }
        };

        // The IPN backend normally owns only state-machine data. At this
        // point bootstrap has the shared health tracker and current DERP
        // selection, so install its captive-portal watcher with the real
        // runtime dependencies.
        let (_captive_derp_map_tx, captive_derp_map_rx) =
            tokio::sync::watch::channel(Some(derp_map.clone()));
        let (_captive_preferred_derp_tx, captive_preferred_derp_rx) =
            tokio::sync::watch::channel(home_derp);
        ipn_backend.start_captive_portal_watcher(
            health.clone(),
            rustscale_netcheck::Detector::default(),
            captive_derp_map_rx,
            captive_preferred_derp_rx,
        );

        // 7. Connect home DERP.
        log::info!("tsnet: home DERP region = {home_derp}");
        let derp_client = match connect_home_derp(&derp_map, home_derp, &state.node_key).await {
            Ok(mut c) => {
                // Tell the DERP server this is our preferred (home) node.
                // Go's derphttp.Client sets preferred=true after connecting
                // to the home DERP and calls NotePreferred(true). This lets
                // the DERP server track home-client metrics and is part of
                // the expected handshake.
                if let Err(e) = c.note_preferred(true).await {
                    log::warn!("tsnet: DERP note_preferred failed (non-fatal): {e}");
                }
                log::info!("tsnet: DERP connected to region {home_derp}");
                health.set_healthy(WARN_DERP_HOME);
                Some(c)
            }
            Err(e) => {
                log::warn!("tsnet: DERP connection to region {home_derp} failed: {e}");
                health.set_unhealthy(
                    WARN_DERP_HOME,
                    format!("derp home region {home_derp} unreachable: {e}"),
                );
                None
            }
        };

        let netinfo = NetInfo {
            PreferredDERP: home_derp,
            WorkingUDP: OptBool::True,
            ..Default::default()
        };
        let netinfo_req = MapRequest {
            Version: CAPABILITY_VERSION,
            KeepAlive: false,
            NodeKey: node_pub.clone(),
            DiscoKey: disco_pub.clone(),
            Stream: false,
            OmitPeers: true,
            Hostinfo: Some(Hostinfo {
                OS: std::env::consts::OS.to_string(),
                Hostname: self.config.hostname.clone(),
                RoutableIPs: advertise.clone(),
                NetInfo: Some(netinfo.clone()),
                PeerRelay: self.config.peer_relay_server,
                ..Default::default()
            }),
            ..Default::default()
        };
        match cc_ep.send_map_request(&netinfo_req).await {
            Ok(()) => log::debug!("tsnet: NetInfo (PreferredDERP={home_derp}) sent to control"),
            Err(e) => log::warn!("tsnet: NetInfo update failed (non-fatal): {e}"),
        }

        // 7b. Run a STUN probe now that DERPMap is known, to discover our
        // external (NAT-mapped) IP:port and include it in the endpoint list.
        // This is critical for peers on different networks — without STUN
        // endpoints they can never establish a direct UDP connection.
        let stun_ep: Option<String> = if derp_map.Regions.is_empty() {
            None
        } else {
            // Run STUN probe to discover external IP:port
            match rustscale_netcheck::Prober
                .run(&derp_map, &rustscale_netcheck::ProberOpts::default())
                .await
            {
                Ok(report) => {
                    if let Some(g) = report.global_v4 {
                        log::debug!("tsnet: STUN endpoint: {g}");
                        Some(g.to_string())
                    } else {
                        log::warn!("tsnet: STUN probe returned no global_v4");
                        None
                    }
                }
                Err(e) => {
                    log::warn!("tsnet: STUN probe failed (non-fatal): {e}");
                    None
                }
            }
        };

        // Build the enhanced endpoint list: filtered local endpoints + STUN.
        let mut all_endpoints = local_endpoints.clone();
        if let Some(ref stun) = stun_ep {
            all_endpoints.push(stun.clone());
        }
        // Re-send endpoint update with STUN results included.
        let stun_ep_req = MapRequest {
            Version: CAPABILITY_VERSION,
            KeepAlive: false,
            NodeKey: node_pub.clone(),
            DiscoKey: disco_pub.clone(),
            Stream: false,
            OmitPeers: true,
            Endpoints: all_endpoints,
            Hostinfo: Some(Hostinfo {
                OS: std::env::consts::OS.to_string(),
                Hostname: self.config.hostname.clone(),
                RoutableIPs: advertise.clone(),
                NetInfo: Some(netinfo.clone()),
                PeerRelay: self.config.peer_relay_server,
                ..Default::default()
            }),
            ..Default::default()
        };
        match cc_ep.send_map_request(&stun_ep_req).await {
            Ok(()) => log::debug!("tsnet: STUN endpoint update sent ({stun_ep:?})"),
            Err(e) => log::warn!("tsnet: STUN endpoint update failed (non-fatal): {e}"),
        }

        // Start the streaming map long-poll with NetInfo included. This is
        // done after the home DERP is known and connected so the streaming
        // MapRequest carries NetInfo.PreferredDERP from the start.
        // stream_map_loop reconnects automatically when the stream ends.
        let map_req = MapRequest {
            Version: CAPABILITY_VERSION,
            KeepAlive: true,
            NodeKey: node_pub.clone(),
            DiscoKey: disco_pub.clone(),
            Stream: true,
            Endpoints: local_endpoints.clone(),
            Hostinfo: Some(Hostinfo {
                OS: std::env::consts::OS.to_string(),
                Hostname: self.config.hostname.clone(),
                RoutableIPs: advertise.clone(),
                NetInfo: Some(netinfo.clone()),
                PeerRelay: self.config.peer_relay_server,
                ..Default::default()
            }),
            ..Default::default()
        };

        let (map_tx, map_rx) = mpsc::channel(32);
        let map_session = Arc::new(MapSessionState::new());
        let cc2 = ControlClient::new(
            self.config.control_url.clone(),
            state.machine_key.clone(),
            server_pub_key.clone(),
            PROTOCOL_VERSION,
        );
        let map_task = tokio::spawn({
            let ss = map_session.clone();
            async move {
                cc2.stream_map_loop(&map_req, map_tx, Some(ss)).await;
            }
        });

        // Control knobs: shared feature-flag store updated from each netmap.
        // Created here (before magicsock) so PMTUD can read PeerMTUEnable at
        // construction time.
        let control_knobs = Arc::new(ControlKnobs::new());
        let initial_knobs = extract_knobs_from_map_response(&map_resp);
        if !initial_knobs.is_empty() {
            control_knobs.apply(initial_knobs);
        }

        // 8. Create magicsock, reusing the UDP socket bound in step 3b so
        // the local endpoints advertised in the MapRequest match the socket
        // magicsock actually owns and reads from.
        let (magicsock_inner, wg_recv) = Magicsock::new(MagicsockConfig {
            private_key: state.node_key.clone(),
            disco_key: state.disco_key.clone(),
            derp_client,
            derp_map: Some(derp_map.clone()),
            home_derp_region: home_derp,
            udp_bind: None,
            udp_socket: Some(udp_socket),
            portmapper: Some(portmapper),
            health: Some(health.clone()),
            disable_direct_paths: self.config.disable_direct_paths,
            peer_relay_server: self.config.peer_relay_server,
            relay_server_config: self.config.relay_server_config.clone(),
            sockstats: Some(sockstats.clone()),
            control_knobs: Some(control_knobs.clone()),
        })
        .await?;
        let magicsock = Arc::new(magicsock_inner);

        // Start a background port-mapping probe + creation (best-effort, 2s
        // timeout). The cached mapping will be picked up by subsequent
        // `all_endpoints()` calls and published to the control plane.
        magicsock.start_portmap();

        // The server may send peers via Peers (full list) or PeersChanged
        // (delta). The first response often uses PeersChanged.
        let mut peers = map_resp.Peers.clone();
        if peers.is_empty() && !map_resp.PeersChanged.is_empty() {
            peers = map_resp.PeersChanged.clone();
        }
        // Update the self node's CapMap from the first MapResponse so the
        // relay server extension can check NODE_ATTR_DISABLE_RELAY_SERVER.
        if let Some(ref node) = map_resp.Node {
            magicsock.set_self_cap_map(node.CapMap.clone());
        }
        magicsock.set_netmap(peers.clone()).await?;

        // 9. Per-peer WG tunnels + routing table.
        let wg_tunnels = Arc::new(RwLock::new(HashMap::new()));
        {
            let mut tunnels = wg_tunnels.write().await;
            for peer in &peers {
                if peer.Key.is_zero() {
                    continue;
                }
                let tunn = WgTunn::new(&state.node_key, &peer.Key, rand_index())?;
                tunnels.insert(peer.Key.clone(), Arc::new(Mutex::new(tunn)));
            }
        }

        let peers_arc = Arc::new(RwLock::new(peers.clone()));
        let routecheck = localapi::new_routecheck_client(
            map_resp.Node.clone(),
            peers_arc.clone(),
            magicsock.clone(),
        );
        let route_table = Arc::new(RwLock::new(RouteTable::from_peers_with_opts(
            &peers,
            self.config.accept_routes,
        )));
        let cancel = Arc::new(CancelToken::new());

        // Build the initial packet filter from the first MapResponse. Add our
        // advertised subnet routes to the filter's localNets so packets
        // destined to those subnets are admitted (needed by subnet routers).
        // The peer list supplies the capability map for `cap:<name>` source
        // predicates, and the ShieldsUp pref enables shields-up mode.
        let shields_up = self.load_prefs().unwrap_or_default().ShieldsUp;
        let (mut filter, _named_filters) =
            build_filter_from_map_response(&map_resp, &tailscale_ips, &peers, shields_up);
        if !advertise.is_empty() {
            filter.add_local_cidrs(&advertise);
        }
        let filter = Arc::new(std::sync::Mutex::new(filter));
        let packet_drops = Arc::new(AtomicU64::new(0));

        // Netlog is opt-in with the embedding's tailtraffic configuration. Keep
        // the existing virtual filter counter and add the physical magicsock
        // counter from the same logger so their traffic remains in distinct
        // aggregation maps.
        let netlog = if let Some(logtail) = self.config.netlog.clone() {
            let logger = Arc::new(rustscale_netlog::Logger::new());
            let source: Arc<dyn rustscale_netlog::NodeSource> = Arc::new(TsnetNetlogNodeSource {
                self_node: map_resp.Node.clone(),
                peers: peers_arc.clone(),
            });
            logger.start(source, logtail).await?;
            let virtual_counter = logger.make_counter(true).await;
            if let Ok(mut filter) = filter.lock() {
                filter.set_connection_counter(Some(virtual_counter));
            }
            magicsock.set_connection_counter(Some(logger.make_counter(false).await));
            Some(logger)
        } else {
            None
        };

        // MagicDNS: build the shared resolver from the first map response.
        // `Domain` is the tailnet domain (e.g. "tailnet.ts.net"); `DNSConfig`
        // carries `Proxied` and `CertDomains`; peer `Name`s are FQDNs.
        let domain = map_resp.Domain.clone();
        let our_fqdn = map_resp
            .Node
            .as_ref()
            .map(|n| n.Name.clone())
            .unwrap_or_default();
        let dns_config = Arc::new(RwLock::new(map_resp.DNSConfig.clone()));
        let user_profiles = Arc::new(RwLock::new(
            map_resp
                .UserProfiles
                .iter()
                .map(|p| (p.ID, p.clone()))
                .collect(),
        ));
        // SSH policy from the first MapResponse. `None` means the control
        // server hasn't sent a policy yet (SSH server rejects all connections
        // until one arrives). Updated on each subsequent map response.
        let ssh_policy = Arc::new(RwLock::new(map_resp.SSHPolicy.clone()));
        let ssh_host_keys = Arc::new(RwLock::new(Vec::new()));
        let resolver = Arc::new(RwLock::new(MagicDnsResolver::new(
            peers.clone(),
            &domain,
            map_resp.DNSConfig.as_ref(),
        )));

        let c2n_prefs = serde_json::json!({
            "hostname": self.config.hostname,
            "control_url": self.config.control_url,
            "ephemeral": self.config.ephemeral,
            "advertise_routes": self.config.advertise_routes,
            "accept_routes": self.config.accept_routes,
            "advertise_exit_node": self.config.advertise_exit_node,
        });
        let c2n_log_level = rustscale_c2n::LogLevelState::new();
        let c2n_backend = Arc::new(c2n::TsnetC2nBackend::new(
            c2n::C2nBackendData {
                peers: peers_arc.clone(),
                user_profiles: user_profiles.clone(),
                health: health.clone(),
                dns_config: dns_config.clone(),
                packet_drops: packet_drops.clone(),
                prefs: c2n_prefs,
                tailscale_ips: tailscale_ips.clone(),
                our_fqdn: our_fqdn.clone(),
                magicsock: magicsock.clone(),
                sockstats: sockstats.clone(),
                logtail: self.config.logtail.clone(),
                posture_checking: self.config.posture_checking,
            },
            c2n_log_level,
        ));
        let c2n_router = {
            let mut r = C2nRouter::new();
            c2n::register_c2n_handlers(&mut r, c2n_backend.clone());
            Arc::new(r)
        };

        // Control knobs created earlier (before magicsock construction).

        Ok(Bootstrap {
            tailscale_ips: tailscale_ips.clone(),
            our_v4,
            magicsock,
            netlog,
            wg_recv,
            wg_tunnels,
            peers: peers_arc,
            routecheck,
            route_table,
            cancel,
            map_rx,
            map_task,
            node_key: state.node_key.clone(),
            filter,
            packet_drops,
            resolver,
            our_fqdn,
            domain,
            dns_config,
            user_profiles,
            ssh_policy,
            ssh_host_keys,
            machine_key: state.machine_key.clone(),
            server_pub_key,
            disco_key: state.disco_key.clone(),
            control_url: self.config.control_url.clone(),
            hostname: self.config.hostname.clone(),
            advertise_routes: advertise,
            udp_port,
            derp_map,
            home_derp,
            health,
            health_watchdog,
            c2n_router,
            c2n_backend,
            control_knobs,
            overrides: self.config.overrides.clone(),
            key_expired: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            ipn_backend,
            map_session,
            sockstats,
            backend_log_id,
            private_log_id,
        })
    }

    /// Shut down the server.
    pub async fn close(&mut self) {
        if let Some(mut inner) = self.inner.take() {
            if let Some(router) = inner.router.take() {
                match router.lock() {
                    Ok(mut router) => {
                        if let Err(error) = router.close() {
                            eprintln!("tsnet: route cleanup failed (non-fatal): {error}");
                        }
                    }
                    Err(_) => eprintln!("tsnet: route cleanup skipped (router lock poisoned)"),
                }
            }
            crate::capture::clear(&inner.capture);
            inner
                .capture_handles
                .lock()
                .expect("capture handles lock poisoned")
                .clear();
            inner
                .audit_logger
                .flush_and_stop(std::time::Duration::from_secs(5))
                .await;
            // Stop serve listeners first (graceful).
            if let Some(serve) = inner.serve.take() {
                serve.stop().await;
            }
            inner.cancel.cancel();
            inner.health_watchdog.stop();
            if let Some(m) = inner.monitor.take() {
                m.shutdown();
            }
            let mut tasks = inner.tasks.lock().await;
            for task in tasks.drain(..) {
                task.abort();
            }
            drop(tasks);
            inner.magicsock.set_connection_counter(None);
            if let Some(netlog) = inner.netlog.take() {
                if let Err(error) = netlog.stop().await {
                    log::warn!("tsnet: netlog shutdown failed (non-fatal): {error}");
                }
            }
            // Clean up the LocalAPI socket file if it was created.
            if let Some(ref path) = inner.localapi_socket {
                let _ = std::fs::remove_file(path);
            }
            // Remove OS DNS configuration (e.g. /etc/resolver entries) if
            // we installed it. Best-effort: log on error.
            if let Some(mut cfg) = inner.os_dns_configurator.take() {
                if let Err(e) = cfg.close() {
                    log::warn!("tsnet: OS DNS cleanup failed (non-fatal): {e}");
                }
            }
        }
    }

    /// Returns the logout trigger Notify, if the server is running.
    /// The daemon selects on this alongside shutdown signals to handle
    /// POST /logout after the server is up.
    pub fn logout_trigger(&self) -> Option<Arc<tokio::sync::Notify>> {
        self.inner
            .as_ref()
            .map(|inner| inner.logout_trigger.clone())
            .or_else(|| {
                self.pre_started
                    .as_ref()
                    .map(|ps| ps.logout_trigger.clone())
            })
    }

    /// Log out: send a logout register request to the control plane
    /// (expiring the node key), clear persisted state, transition the IPN
    /// backend to NeedsLogin, and tear down the running state.
    ///
    /// Mirrors Go's `LocalBackend.Logout` → `controlclient.TryLogout`:
    /// a RegisterRequest with `Expiry` set to the far past (1970-01-01)
    /// tells the control server to expire the node. After that, persisted
    /// keys and netmap cache are cleared so a restart starts fresh.
    ///
    /// After logout, the server is in a `NeedsLogin` state. The daemon
    /// should call `start_localapi_only()` again to accept a new login.
    pub async fn logout(&mut self) -> Result<(), TsnetError> {
        let mut inner = match self.inner.take() {
            Some(inner) => inner,
            None => return Ok(()), // already down
        };

        if let Some(router) = inner.router.take() {
            match router.lock() {
                Ok(mut router) => {
                    if let Err(error) = router.close() {
                        eprintln!("tsnet: route cleanup failed (non-fatal): {error}");
                    }
                }
                Err(_) => eprintln!("tsnet: route cleanup skipped (router lock poisoned)"),
            }
        }

        if let Err(error) = inner
            .audit_logger
            .enqueue(rustscale_tailcfg::AuditNodeDisconnect, "logout")
        {
            log::warn!("tsnet: failed to persist audit log (non-fatal): {error}");
        }
        inner
            .audit_logger
            .flush_and_stop(std::time::Duration::from_secs(5))
            .await;

        // 1. Send a logout register request (Expiry = far past) to expire
        //    the node key on the control server. Best-effort: network
        //    errors don't prevent local cleanup.
        let cc = ControlClient::new(
            &self.config.control_url,
            inner.machine_key.clone(),
            inner.server_pub_key.clone(),
            PROTOCOL_VERSION,
        );
        let node_pub = inner.node_key.public();
        let logout_req = RegisterRequest {
            Version: CAPABILITY_VERSION,
            NodeKey: node_pub,
            Expiry: Some(
                chrono::DateTime::parse_from_rfc3339("1970-01-01T00:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
            Hostinfo: Some(Hostinfo {
                OS: std::env::consts::OS.to_string(),
                Hostname: self.config.hostname.clone(),
                ..Default::default()
            }),
            ..Default::default()
        };
        if let Err(e) = cc.register(&logout_req).await {
            log::warn!("tsnet: logout register failed (non-fatal): {e}");
        }

        // 2. Clear persisted state: regenerate keys, clear netmap cache.
        if let Some(ref dir) = self.config.state_dir {
            let fresh = PersistedState::generate();
            if let Err(e) = self.save_state(&fresh) {
                log::warn!("tsnet: failed to clear state on logout: {e}");
            }
            PersistedState::clear_netmap(dir);
        }

        // 3. Set prefs LoggedOut=true, WantRunning=false.
        let mut prefs = self.load_prefs().unwrap_or_default();
        prefs.LoggedOut = true;
        prefs.WantRunning = false;
        if let Some(ref dir) = self.config.state_dir {
            let _ = prefs.save(dir);
        }

        // 4. Transition IPN backend to NeedsLogin.
        inner.ipn_backend.set_logged_out(true);
        inner.ipn_backend.set_blocked(true);
        inner.ipn_backend.update_inputs(|i| {
            i.want_running = false;
            i.has_node_key = false;
            i.auth_cant_continue = true;
            i.netmap_present = false;
        });
        inner.ipn_backend.bus().send(rustscale_ipn::Notify {
            State: Some(rustscale_ipn::State::NeedsLogin),
            Prefs: Some(serde_json::to_value(&prefs).unwrap_or_default()),
            ..Default::default()
        });

        // 5. Tear down the running state (stop tasks, cancel, close sockets).
        if let Some(serve) = inner.serve.take() {
            serve.stop().await;
        }
        inner.cancel.cancel();
        inner.health_watchdog.stop();
        if let Some(m) = inner.monitor.take() {
            m.shutdown();
        }
        let mut tasks = inner.tasks.lock().await;
        for task in tasks.drain(..) {
            task.abort();
        }
        drop(tasks);
        inner.magicsock.set_connection_counter(None);
        if let Some(netlog) = inner.netlog.take() {
            if let Err(error) = netlog.stop().await {
                log::warn!("tsnet: netlog shutdown failed (non-fatal): {error}");
            }
        }
        if let Some(ref path) = inner.localapi_socket {
            let _ = std::fs::remove_file(path);
        }
        if let Some(mut cfg) = inner.os_dns_configurator.take() {
            if let Err(e) = cfg.close() {
                log::warn!("tsnet: OS DNS cleanup failed (non-fatal): {e}");
            }
        }

        Ok(())
    }

    /// Switch to profile `profile_id`, tearing down the running backend and
    /// restarting with the new profile's prefs. Mirrors Go's
    /// `resetForProfileChangeLocked`.
    ///
    /// Sequence:
    /// 1. `close()` — stop serve listeners, cancel tasks, drop magicsock
    ///    and the control client (like Go's `currentNode` shutdown).
    /// 2. Reload the `ProfileManager` from disk, switch to the target
    ///    profile, and apply its prefs (`ControlURL`, `Hostname`) to
    ///    `self.config` so `up()` bootstraps against the right control
    ///    plane.
    /// 3. If ephemeral, regenerate persisted state so bootstrap creates
    ///    fresh node keys.
    /// 4. `up()` — re-bootstrap the engine, control client, and netstack.
    pub async fn switch_profile(&mut self, profile_id: &str) -> Result<(), TsnetError> {
        // 1. Stop the running engine (like close() but keep the config).
        self.close().await;

        // 2. Update current profile + prefs from the ProfileManager.
        //    (ProfileManager lives in state_dir on disk; reload it.)
        if let Some(ref dir) = self.config.state_dir {
            let mut pm = rustscale_ipn::ProfileManager::new(dir)
                .map_err(|e| TsnetError::Builder(e.to_string()))?;
            pm.switch_profile(profile_id)
                .map_err(|e| TsnetError::Builder(e.to_string()))?;
            // Apply the profile's prefs to self.config.
            let new_prefs = pm.current_prefs().clone();
            if !new_prefs.ControlURL.is_empty() {
                self.config.control_url.clone_from(&new_prefs.ControlURL);
            }
            if !new_prefs.Hostname.is_empty() {
                self.config.hostname.clone_from(&new_prefs.Hostname);
            }
            // Save prefs to disk so bootstrap picks them up.
            if let Err(e) = new_prefs.save(dir) {
                log::warn!("tsnet: failed to save prefs on profile switch: {e}");
            }
        }

        // 3. Restart the engine. Ephemeral nodes regenerate keys on
        //    restart — clear persisted state so bootstrap generates fresh
        //    keys. (Mirrors Go clearing the node key on profile switch for
        //    ephemeral nodes.)
        if self.config.ephemeral {
            if let Some(ref _dir) = self.config.state_dir {
                let fresh = PersistedState::generate();
                let _ = self.save_state(&fresh);
            }
        }
        Box::pin(self.up()).await?;
        Ok(())
    }

    // --- internal helpers ---

    async fn start_audit_logger(
        state_dir: Option<PathBuf>,
        control_url: String,
        machine_key: MachinePrivate,
        server_pub_key: MachinePublic,
        node_key: NodePrivate,
    ) -> Arc<rustscale_auditlog::Logger> {
        let store: Arc<dyn rustscale_ipn::store::Store> = match &state_dir {
            Some(dir) => Arc::new(rustscale_ipn::store::FileStore::new(dir)),
            None => Arc::new(rustscale_ipn::store::MemStore::new()),
        };
        let log_store = Arc::new(rustscale_auditlog::LogStore::new(store));
        let logger = rustscale_auditlog::Logger::new(rustscale_auditlog::LoggerOptions {
            retry_limit: 10,
            store: log_store,
        });
        let profile_id = state_dir
            .as_ref()
            .and_then(|dir| {
                rustscale_ipn::LoginProfile::load_current_id(dir)
                    .ok()
                    .flatten()
            })
            .unwrap_or_else(|| "default".to_string());
        if let Err(error) = logger.set_profile_id(profile_id) {
            log::warn!("tsnet: failed to configure audit log profile (non-fatal): {error}");
        }

        let mut control_client =
            ControlClient::new(control_url, machine_key, server_pub_key, PROTOCOL_VERSION);
        control_client.set_audit_node_key(node_key.public());
        if let Err(error) = logger.start(Arc::new(control_client)).await {
            log::warn!("tsnet: failed to start audit logger (non-fatal): {error}");
        }
        logger
    }

    pub(crate) fn load_or_create_state(&self) -> Result<PersistedState, TsnetError> {
        if let Some(ref dir) = self.config.state_dir {
            let path = dir.join("tsnet-state.json");
            if path.exists() {
                return Ok(PersistedState::load(&path)?);
            }
        }
        Ok(PersistedState::default())
    }

    pub(crate) fn save_state(&self, state: &PersistedState) -> Result<(), TsnetError> {
        if let Some(ref dir) = self.config.state_dir {
            let path = dir.join("tsnet-state.json");
            state.save(&path)?;
        }
        Ok(())
    }
}
