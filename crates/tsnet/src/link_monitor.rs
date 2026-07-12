#[allow(clippy::wildcard_imports)]
use super::*;

/// Spawn the network change monitor. On a major link change (interface IP
/// change, up/down transition, or wall-clock time jump), re-gathers local
/// endpoints, resets peer direct paths, closes DERP connections, re-STUNs,
/// and pushes a lightweight non-streaming MapRequest to the control plane.
pub(crate) fn spawn_link_monitor(
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
) -> Option<rustscale_netmon::MonitorHandle> {
    let monitor = rustscale_netmon::Monitor::new().ok()?;

    let handle = monitor.start();
    handle.register_change_callback(move |delta| {
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
        let home_derp = home_derp;
        async move {
            if !delta.major {
                return;
            }
            if cancel.is_cancelled() {
                return;
            }
            eprintln!(
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
                    eprintln!("tsnet: link-change endpoint update sent");
                    // Endpoints re-published: clear the transient warning.
                    health.set_healthy(WARN_NETMON_CHANGE);
                }
                Err(e) => eprintln!("tsnet: link-change endpoint update failed (non-fatal): {e}"),
            }
        }
    });

    Some(handle)
}

/// Periodic endpoint update task (Bug 4).
///
/// Sends a non-streaming MapRequest with `OmitPeers=true` every 5 minutes
/// so the control server always has fresh endpoint data (local IPs, STUN
/// results, port-mapped endpoints). Go's controlclient does this via
/// `setEndpoints` on a timer; rustscale only sent endpoints once at startup
/// and on link-change (netmon), which could leave the control server with
/// stale data for the lifetime of a long-lived session.
///
/// The task is self-contained: it creates its own `ControlClient` per
/// update (to avoid sharing the streaming map-poll client) and respects
/// the shared `CancelToken`.
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
    tokio::spawn(async move {
        let node_pub = node_key.public();
        let disco_pub = disco_key.public();
        loop {
            tokio::time::sleep(std::time::Duration::from_mins(5)).await;
            if cancel.is_cancelled() {
                break;
            }

            let mut eps = magicsock.all_endpoints();
            if !derp_map.Regions.is_empty() {
                if let Ok(report) = rustscale_netcheck::Prober
                    .run(&derp_map, &rustscale_netcheck::ProberOpts::default())
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
                NodeKey: node_pub.clone(),
                DiscoKey: disco_pub.clone(),
                Stream: false,
                OmitPeers: true,
                Endpoints: eps,
                Hostinfo: Some(Hostinfo {
                    OS: std::env::consts::OS.into(),
                    Hostname: hostname.clone(),
                    RoutableIPs: advertise_routes.clone(),
                    NetInfo: Some(NetInfo {
                        PreferredDERP: home_derp,
                        WorkingUDP: OptBool::True,
                        ..Default::default()
                    }),
                    PeerRelay: peer_relay_server,
                    ..Default::default()
                }),
                ..Default::default()
            };
            let cc = ControlClient::new(
                &control_url,
                machine_key.clone(),
                server_pub_key.clone(),
                PROTOCOL_VERSION,
            );
            match cc.send_map_request(&req).await {
                Ok(()) => eprintln!("tsnet: periodic endpoint update sent"),
                Err(e) => eprintln!("tsnet: periodic endpoint update failed (non-fatal): {e}"),
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
) -> JoinHandle<()> {
    tokio::spawn(async move {
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

            // Check whether funnel is active.
            let ingress_enabled = if let Some(ref runner) = serve {
                runner.is_funnel_on().await
            } else {
                false
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
            // Read ShieldsUp from prefs so the control plane knows whether
            // to block inbound connections. Mirrors Go's hostinfo building
            // in ipn/ipnlocal/local.go.
            let shields_up = state_dir
                .as_ref()
                .and_then(|d| rustscale_ipn::Prefs::load(d).ok())
                .map(|p| p.ShieldsUp)
                .unwrap_or(false);
            let ov = overrides.read().await.clone();
            let hi = collect_hostinfo(
                base,
                &ov,
                exit_node_id.as_ref(),
                ingress_enabled,
                shields_up,
            );

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
                        eprintln!("tsnet: hostinfo update send failed (non-fatal): {e}");
                    }
                }
            }

            tokio::time::sleep(std::time::Duration::from_mins(10)).await;
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

    DerpClient::connect_with_upgrade_dial_insecure(
        &dial_addr,
        &tls_host,
        port,
        !node.InsecureForTests,
        node.InsecureForTests,
        node_key.clone(),
        None,
    )
    .await
}
