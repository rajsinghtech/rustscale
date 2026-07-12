#[allow(clippy::wildcard_imports)]
use super::*;

impl Server {
    /// Bring the server online in userspace netstack mode (tsnet listen/dial).
    ///
    /// This is the classic tsnet embedding path: an in-process smoltcp netstack
    /// backs `listen`/`dial`. For a full-client TUN device instead, use
    /// [`Server::up_tun`].
    #[allow(clippy::large_futures)]
    pub async fn up(&mut self) -> Result<(), TsnetError> {
        if self.inner.is_some() {
            return Err(TsnetError::AlreadyUp);
        }

        ensure_ring_provider();

        let b = self.bootstrap().await?;

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
        ));

        // Map-stream update task (peer/route deltas).
        let key_rotation_ctx = KeyRotationCtx {
            control_url: b.control_url.clone(),
            machine_key: b.machine_key.clone(),
            server_pub_key: b.server_pub_key.clone(),
            hostname: self.config.hostname.clone(),
            auth_key: self.config.auth_key.clone().unwrap_or_default(),
            ephemeral: self.config.ephemeral,
            advertise_routes: b.advertise_routes.clone(),
            peer_relay_server: self.config.peer_relay_server,
            disco_key: b.disco_key.clone(),
            capability_version: CAPABILITY_VERSION,
            protocol_version: PROTOCOL_VERSION,
        };
        let map_update = spawn_map_update_task(
            b.map_rx,
            b.magicsock.clone(),
            b.wg_tunnels.clone(),
            b.peers.clone(),
            b.route_table.clone(),
            b.node_key.clone(),
            b.filter.clone(),
            b.tailscale_ips.clone(),
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
            Err(e) => eprintln!(
                "tsnet: MagicDNS responder not started ({e}); dial still resolves via netmap"
            ),
        }

        // Serve/Funnel runner (netstack mode only).
        let serve = Some(Arc::new(serve::ServeRunner::new(
            netstack.clone(),
            b.peers.clone(),
            b.user_profiles.clone(),
            b.our_fqdn.clone(),
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
                    Ok(()) => eprintln!("tsnet: peerapi services advertised (port {port})"),
                    Err(e) => {
                        eprintln!("tsnet: peerapi service advertisement failed (non-fatal): {e}");
                    }
                }
            }
        }

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
                prefs: Arc::new(RwLock::new(self.load_prefs().unwrap_or_default())),
                tailscale_ips: b.tailscale_ips.clone(),
                our_fqdn: b.our_fqdn.clone(),
                hostname: self.config.hostname.clone(),
                magicsock: b.magicsock.clone(),
                tun_mode: false,
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
                taildrop: Some(taildrop.clone()),
                netstack: Some(netstack.clone()),
                filter: std::sync::OnceLock::new(),
                route_table: Some(b.route_table.clone()),
                logout_trigger: self
                    .pre_started
                    .as_ref()
                    .map(|ps| ps.logout_trigger.clone())
                    .unwrap_or_else(|| Arc::new(tokio::sync::Notify::new())),
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
                eprintln!("tsnet: LocalAPI listening at {}", path.display());
                Some(h.socket_path)
            } else {
                eprintln!(
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
            data_plane: DataPlane::Netstack(netstack),
            peers: b.peers,
            route_table: b.route_table,
            cancel: b.cancel,
            tasks: Mutex::new(tasks),
            packet_drops: b.packet_drops,
            resolver: b.resolver,
            our_fqdn: b.our_fqdn,
            domain: b.domain.clone(),
            dns_config: b.dns_config,
            user_profiles: b.user_profiles,
            ssh_policy: b.ssh_policy,
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
        });

        // Apply stored exit-node pref on start (survives restart).
        // The peer list is populated from the first MapResponse, so we
        // can resolve the exit node immediately.
        let stored_prefs = self.load_prefs().unwrap_or_default();
        if !stored_prefs.ExitNodeIP.is_empty() || !stored_prefs.ExitNodeID.is_empty() {
            // Extract Arcs before awaiting — RunningState is !Sync due to
            // os_dns_configurator, so &RunningState can't cross await points.
            let (peers, route_table) = match self.inner.as_ref() {
                Some(inner) => (inner.peers.clone(), inner.route_table.clone()),
                None => return Ok(()),
            };
            let ip_or_name = if stored_prefs.ExitNodeIP.is_empty() {
                &stored_prefs.ExitNodeID
            } else {
                &stored_prefs.ExitNodeIP
            };
            let peers_guard = peers.read().await;
            if let Some(peer_key) = localapi::resolve_exit_node_peer(&peers_guard, ip_or_name) {
                drop(peers_guard);
                route_table.write().await.set_exit_node(peer_key);
                eprintln!("tsnet: applied stored exit-node pref: {ip_or_name}");
            } else {
                eprintln!(
                    "tsnet: stored exit-node pref unresolved (peer not in netmap): {ip_or_name}"
                );
            }
        }

        Ok(())
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
    pub async fn up_tun(&mut self, config: TunModeConfig) -> Result<(), TsnetError> {
        if self.inner.is_some() {
            return Err(TsnetError::AlreadyUp);
        }

        ensure_ring_provider();

        let b = self.bootstrap().await?;

        // Resolve and apply the exit node selection from TunModeConfig, if
        // set. This sets the in-process RouteTable's exit node so the data
        // pump routes non-tailnet traffic to the exit peer. OS-level
        // default-route overrides are installed after the TUN is created.
        if let Some(ref exit) = config.exit_node {
            let peers = b.peers.read().await;
            let peer_key = resolve_exit_node(&peers, exit)?;
            drop(peers);
            b.route_table.write().await.set_exit_node(peer_key);
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
        let tun: Arc<dyn Tun> = create_tun_device(&config, &b, self.config.accept_routes).await?;

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

        let key_rotation_ctx = KeyRotationCtx {
            control_url: b.control_url.clone(),
            machine_key: b.machine_key.clone(),
            server_pub_key: b.server_pub_key.clone(),
            hostname: self.config.hostname.clone(),
            auth_key: self.config.auth_key.clone().unwrap_or_default(),
            ephemeral: self.config.ephemeral,
            advertise_routes: b.advertise_routes.clone(),
            peer_relay_server: self.config.peer_relay_server,
            disco_key: b.disco_key.clone(),
            capability_version: CAPABILITY_VERSION,
            protocol_version: PROTOCOL_VERSION,
        };
        let map_update = spawn_map_update_task(
            b.map_rx,
            b.magicsock.clone(),
            b.wg_tunnels.clone(),
            b.peers.clone(),
            b.route_table.clone(),
            b.node_key.clone(),
            b.filter.clone(),
            b.tailscale_ips.clone(),
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
                    Ok(()) => eprintln!("tsnet: peerapi services advertised (port {port})"),
                    Err(e) => {
                        eprintln!("tsnet: peerapi service advertisement failed (non-fatal): {e}");
                    }
                }
            }
        }

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
        );

        let mut tasks = vec![
            b.map_task,
            pump,
            map_update,
            periodic_ep,
            c2n_task,
            peerapi_task,
            hostinfo_loop,
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
                prefs: Arc::new(RwLock::new(self.load_prefs().unwrap_or_default())),
                tailscale_ips: b.tailscale_ips.clone(),
                our_fqdn: b.our_fqdn.clone(),
                hostname: self.config.hostname.clone(),
                magicsock: b.magicsock.clone(),
                tun_mode: true,
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
                taildrop: Some(taildrop.clone()),
                netstack: None, // TUN mode has no netstack
                filter: std::sync::OnceLock::new(),
                route_table: Some(b.route_table.clone()),
                logout_trigger: self
                    .pre_started
                    .as_ref()
                    .map(|ps| ps.logout_trigger.clone())
                    .unwrap_or_else(|| Arc::new(tokio::sync::Notify::new())),
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
                eprintln!("tsnet: LocalAPI listening at {}", path.display());
                Some(h.socket_path)
            } else {
                eprintln!(
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
                    eprintln!(
                        "tsnet: OS DNS configured ({} match domains, {} search domains)",
                        os_cfg.match_domains.len(),
                        os_cfg.search_domains.len()
                    );
                    Some(configurator)
                }
                Err(e) => {
                    eprintln!("tsnet: OS DNS configuration failed (non-fatal, needs root?): {e}");
                    None
                }
            }
        } else {
            None
        };

        self.inner = Some(RunningState {
            tailscale_ips: b.tailscale_ips,
            magicsock: b.magicsock,
            data_plane: DataPlane::Tun,
            peers: b.peers,
            route_table: b.route_table,
            cancel: b.cancel,
            tasks: Mutex::new(tasks),
            packet_drops: b.packet_drops,
            resolver: b.resolver,
            our_fqdn: b.our_fqdn,
            domain: b.domain.clone(),
            dns_config: b.dns_config,
            user_profiles: b.user_profiles,
            ssh_policy: b.ssh_policy,
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
        });

        // Apply stored exit-node pref on start (survives restart).
        let stored_prefs = self.load_prefs().unwrap_or_default();
        if !stored_prefs.ExitNodeIP.is_empty() || !stored_prefs.ExitNodeID.is_empty() {
            let (peers, route_table) = match self.inner.as_ref() {
                Some(inner) => (inner.peers.clone(), inner.route_table.clone()),
                None => return Ok(()),
            };
            let ip_or_name = if stored_prefs.ExitNodeIP.is_empty() {
                &stored_prefs.ExitNodeID
            } else {
                &stored_prefs.ExitNodeIP
            };
            let peers_guard = peers.read().await;
            if let Some(peer_key) = localapi::resolve_exit_node_peer(&peers_guard, ip_or_name) {
                drop(peers_guard);
                route_table.write().await.set_exit_node(peer_key);
                eprintln!("tsnet: applied stored exit-node pref: {ip_or_name}");
            } else {
                eprintln!(
                    "tsnet: stored exit-node pref unresolved (peer not in netmap): {ip_or_name}"
                );
            }
        }

        Ok(())
    }

    // --- shared control-plane bootstrap ---

    /// Load prefs from the state directory, or return default if not found.
    fn load_prefs(&self) -> Result<rustscale_ipn::Prefs, TsnetError> {
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
            user_profiles: Arc::new(RwLock::new(BTreeMap::new())),
            health: Tracker::new(),
            dns_config: Arc::new(RwLock::new(None)),
            packet_drops: Arc::new(AtomicU64::new(0)),
            prefs: prefs.clone(),
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
            taildrop: None,
            netstack: None,
            filter: std::sync::OnceLock::new(),
            route_table: None,
            logout_trigger: logout_trigger.clone(),
        });

        let handle = localapi::spawn_localapi(api_state.clone(), socket_path.clone());
        if handle.is_some() {
            eprintln!(
                "tsnet: LocalAPI (needs-login) listening at {}",
                socket_path.display()
            );
        } else {
            eprintln!("tsnet: LocalAPI failed to bind {}", socket_path.display());
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

    /// Shared bootstrapping for `up()` and `up_tun()`: load state, register
    /// with control, start the map long-poll, wait for the first `MapResponse`,
    /// netcheck for a home DERP, connect it, build magicsock + per-peer WG
    /// tunnels + the routing table. Returns the shared handles plus the
    /// still-open map receiver for the update task.
    async fn bootstrap(&mut self) -> Result<Bootstrap, TsnetError> {
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

        // IPN state machine backend. Created early so state transitions
        // are tracked from the start. Want_running is set immediately;
        // other inputs are set as bootstrap progresses.
        let ipn_backend = if let Some(ref ps) = self.pre_started {
            ps.backend.clone()
        } else {
            Arc::new(IpnBackend::new("rustscale"))
        };
        ipn_backend.set_want_running();

        // 1. Load or generate persistent state.
        let mut state = self.load_or_create_state()?;
        let was_fresh = state.is_zero();
        if was_fresh {
            state = PersistedState::generate();
            self.save_state(&state)?;
        }

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
        let server_pub_key =
            controlhttp::fetch_server_pub_key(&self.config.control_url, PROTOCOL_VERSION)
                .await
                .map_err(|e| {
                    TsnetError::Register(rustscale_controlclient::RegisterError::Dial(e))
                })?;

        // 3. Register with the control plane.
        let auth_key = self.config.auth_key.clone().unwrap_or_default();

        let cc = ControlClient::new(
            self.config.control_url.clone(),
            state.machine_key.clone(),
            server_pub_key.clone(),
            PROTOCOL_VERSION,
        );

        let reg_req = RegisterRequest {
            Version: CAPABILITY_VERSION,
            NodeKey: node_pub.clone(),
            Auth: if auth_key.is_empty() {
                None
            } else {
                Some(rustscale_tailcfg::RegisterResponseAuth {
                    AuthKey: auth_key.clone(),
                })
            },
            Hostinfo: Some(Hostinfo {
                OS: std::env::consts::OS.to_string(),
                Hostname: self.config.hostname.clone(),
                RoutableIPs: advertise.clone(),
                PeerRelay: self.config.peer_relay_server,
                ..Default::default()
            }),
            Ephemeral: self.config.ephemeral,
            ..Default::default()
        };

        let reg_resp = cc.register(&reg_req).await.map_err(|e| {
            // Auth/network failure: the cached netmap may be stale or the
            // node key may have been revoked. Clear it so a restart doesn't
            // boot from a stale cache. Mirrors Go's discardDiskCacheLocked
            // call on register failures (ipn/ipnlocal/local.go:7415).
            if let Some(ref dir) = self.config.state_dir {
                PersistedState::clear_netmap(dir);
                eprintln!("tsnet: cleared netmap cache after register error: {e}");
            }
            ipn_backend.emit_err_message(e.to_string());
            TsnetError::Register(e)
        })?;

        // Server-side error string (e.g. "invalid auth key", "node key revoked").
        if !reg_resp.Error.is_empty() {
            if let Some(ref dir) = self.config.state_dir {
                PersistedState::clear_netmap(dir);
                eprintln!(
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
                eprintln!("tsnet: cleared netmap cache: node key expired");
            }
            ipn_backend.set_key_expired(true);
        }

        if reg_resp.AuthURL.is_empty() {
            ipn_backend.set_machine_authorized(reg_resp.MachineAuthorized);
            ipn_backend.set_blocked(false);
            ipn_backend.emit_login_finished();
            state.node_id = reg_resp.User.ID;
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
            tokio::net::UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0u16)))
                .await
                .map_err(TsnetError::Io)?,
        );
        let udp_port = udp_socket.local_addr().map_err(TsnetError::Io)?.port();
        let local_endpoints = rustscale_magicsock::gather_local_endpoints(udp_port);
        eprintln!("tsnet: local UDP endpoints: {local_endpoints:?}");

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
            Ok(()) => eprintln!("tsnet: endpoint update sent (DiscoKey + {local_endpoints:?})"),
            Err(e) => eprintln!("tsnet: endpoint update failed (non-fatal): {e}"),
        }

        // 4. Fetch the first MapResponse. If we have a cached netmap, skip
        // the blocking fetch and use the cached data — the streaming
        // long-poll (started below) will deliver fresh updates in the
        // background. This eliminates the 2-5s startup delay on restarts.
        let map_resp: MapResponse = if let Some(ref cached) = cached_netmap {
            let peer_count = cached.Peers.len();
            eprintln!(
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
                eprintln!("tsnet: using control-assigned home DERP region {d}");
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

        // 7. Connect home DERP.
        eprintln!("tsnet: home DERP region = {home_derp}");
        let derp_client = match connect_home_derp(&derp_map, home_derp, &state.node_key).await {
            Ok(mut c) => {
                // Tell the DERP server this is our preferred (home) node.
                // Go's derphttp.Client sets preferred=true after connecting
                // to the home DERP and calls NotePreferred(true). This lets
                // the DERP server track home-client metrics and is part of
                // the expected handshake.
                if let Err(e) = c.note_preferred(true).await {
                    eprintln!("tsnet: DERP note_preferred failed (non-fatal): {e}");
                }
                eprintln!("tsnet: DERP connected to region {home_derp}");
                health.set_healthy(WARN_DERP_HOME);
                Some(c)
            }
            Err(e) => {
                eprintln!("tsnet: DERP connection to region {home_derp} failed: {e}");
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
            Ok(()) => eprintln!("tsnet: NetInfo (PreferredDERP={home_derp}) sent to control"),
            Err(e) => eprintln!("tsnet: NetInfo update failed (non-fatal): {e}"),
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
                        eprintln!("tsnet: STUN endpoint: {g}");
                        Some(g.to_string())
                    } else {
                        eprintln!("tsnet: STUN probe returned no global_v4");
                        None
                    }
                }
                Err(e) => {
                    eprintln!("tsnet: STUN probe failed (non-fatal): {e}");
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
            Ok(()) => eprintln!("tsnet: STUN endpoint update sent ({stun_ep:?})"),
            Err(e) => eprintln!("tsnet: STUN endpoint update failed (non-fatal): {e}"),
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
            },
            c2n_log_level,
        ));
        let c2n_router = {
            let mut r = C2nRouter::new();
            c2n::register_c2n_handlers(&mut r, c2n_backend.clone());
            Arc::new(r)
        };

        // Control knobs: shared feature-flag store updated from each netmap.
        let control_knobs = Arc::new(ControlKnobs::new());
        let initial_knobs = extract_knobs_from_map_response(&map_resp);
        if !initial_knobs.is_empty() {
            control_knobs.apply(initial_knobs);
        }

        Ok(Bootstrap {
            tailscale_ips: tailscale_ips.clone(),
            our_v4,
            magicsock,
            wg_recv,
            wg_tunnels,
            peers: peers_arc,
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
        })
    }

    /// Shut down the server.
    pub async fn close(&mut self) {
        if let Some(mut inner) = self.inner.take() {
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
            // Clean up the LocalAPI socket file if it was created.
            if let Some(ref path) = inner.localapi_socket {
                let _ = std::fs::remove_file(path);
            }
            // Remove OS DNS configuration (e.g. /etc/resolver entries) if
            // we installed it. Best-effort: log on error.
            if let Some(mut cfg) = inner.os_dns_configurator.take() {
                if let Err(e) = cfg.close() {
                    eprintln!("tsnet: OS DNS cleanup failed (non-fatal): {e}");
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
            eprintln!("tsnet: logout register failed (non-fatal): {e}");
        }

        // 2. Clear persisted state: regenerate keys, clear netmap cache.
        if let Some(ref dir) = self.config.state_dir {
            let fresh = PersistedState::generate();
            if let Err(e) = self.save_state(&fresh) {
                eprintln!("tsnet: failed to clear state on logout: {e}");
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
        if let Some(ref path) = inner.localapi_socket {
            let _ = std::fs::remove_file(path);
        }
        if let Some(mut cfg) = inner.os_dns_configurator.take() {
            if let Err(e) = cfg.close() {
                eprintln!("tsnet: OS DNS cleanup failed (non-fatal): {e}");
            }
        }

        Ok(())
    }

    // --- internal helpers ---

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
