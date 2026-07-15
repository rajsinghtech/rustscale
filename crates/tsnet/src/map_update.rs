#[allow(clippy::wildcard_imports)]
use super::*;

/// Context needed to re-register with the control server after a key
/// expiry. Passed to [`spawn_map_update_task`] so the map update loop
/// can detect expiry and perform key rotation in-place.
pub(crate) struct KeyRotationCtx {
    pub control_url: String,
    pub machine_key: MachinePrivate,
    pub server_pub_key: MachinePublic,
    pub hostname: String,
    pub ephemeral: bool,
    pub advertise_routes: Vec<String>,
    pub peer_relay_server: bool,
    pub disco_key: DiscoPrivate,
    pub capability_version: i32,
    pub protocol_version: u16,
    pub shields_up: bool,
}

/// The only exit-node preference that a map update may apply. Once it
/// resolves, or an explicit API/config selection supersedes it, route-table
/// rebuilds preserve their existing selection without consulting prefs again.
#[derive(Clone, Debug, Default)]
pub(crate) struct ExitNodeSelection {
    pending_persisted: Option<String>,
}

impl ExitNodeSelection {
    pub(crate) fn from_prefs(prefs: &rustscale_ipn::Prefs) -> Self {
        let mut selection = Self::default();
        selection.replace_from_prefs(prefs);
        selection
    }

    pub(crate) fn replace_from_prefs(&mut self, prefs: &rustscale_ipn::Prefs) {
        self.pending_persisted = exit_node_pref(prefs);
    }

    pub(crate) fn clear_pending(&mut self) {
        self.pending_persisted = None;
    }

    /// Retry an unresolved persisted selection. This deliberately does not
    /// clear the route table when the peer is absent: an explicit selection
    /// owns the table once it has superseded the persisted preference.
    pub(crate) fn retry(&mut self, peers: &[Node], routes: &mut RouteTable) -> bool {
        let Some(selector) = self.pending_persisted.as_deref() else {
            return false;
        };
        if let Some(peer) = crate::localapi::resolve_exit_node_peer(peers, selector) {
            routes.set_exit_node(peer);
            self.pending_persisted = None;
            true
        } else {
            false
        }
    }
}

pub(crate) fn exit_node_pref(prefs: &rustscale_ipn::Prefs) -> Option<String> {
    if !prefs.ExitNodeIP.is_empty() {
        Some(prefs.ExitNodeIP.clone())
    } else if !prefs.ExitNodeID.is_empty() {
        Some(prefs.ExitNodeID.clone())
    } else {
        None
    }
}

pub(crate) fn set_exit_node_pref(prefs: &mut rustscale_ipn::Prefs, selector: &str) {
    if selector.parse::<std::net::IpAddr>().is_ok() {
        prefs.ExitNodeIP = selector.into();
        prefs.ExitNodeID.clear();
    } else {
        // ExitNodeID is also the prefs field LocalAPI uses for a hostname.
        prefs.ExitNodeID = selector.into();
        prefs.ExitNodeIP.clear();
    }
}

/// Spawn the map-stream delta update task. Shared by `up()` and `up_tun()`:
/// processes Peers/PeersChanged/PeersRemoved, feeds the new peer list to
/// magicsock, rebuilds the route table, and creates WG tunnels for new peers.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_map_update_task(
    mut map_rx: mpsc::Receiver<Result<MapResponse, StreamMapError>>,
    magicsock: Arc<Magicsock>,
    wg_tunnels: Arc<RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>>,
    mut raw_peers: Vec<Node>,
    peers_arc: Arc<RwLock<Vec<Node>>>,
    route_table: Arc<RwLock<RouteTable>>,
    router: Option<SharedRouter>,
    prefs: Arc<RwLock<rustscale_ipn::Prefs>>,
    exit_node_selection: Arc<RwLock<ExitNodeSelection>>,
    mut node_key: NodePrivate,
    filter_arc: Arc<std::sync::Mutex<Filter>>,
    mut named_filters: BTreeMap<String, Vec<FilterRule>>,
    drive: Arc<crate::drive::Runtime>,
    peer_map: Arc<crate::peer_map::Runtime>,
    tailscale_ips: Vec<IpAddr>,
    control_url: String,
    accept_routes: bool,
    advertise_routes: Vec<String>,
    resolver: Arc<RwLock<MagicDnsResolver>>,
    dns_config: Arc<RwLock<Option<DNSConfig>>>,
    user_profiles: Arc<RwLock<BTreeMap<UserID, UserProfile>>>,
    ssh_policy: Arc<RwLock<Option<SSHPolicy>>>,
    cancel: Arc<CancelToken>,
    health: Tracker,
    health_watchdog: Watchdog,
    state_scope: Option<crate::state::StateScope>,
    mut node_pub: NodePublic,
    control_knobs: Arc<ControlKnobs>,
    key_expired: Arc<std::sync::atomic::AtomicBool>,
    ipn_backend: Arc<IpnBackend>,
    key_rotation_ctx: Option<KeyRotationCtx>,
    map_session: Arc<MapSessionState>,
    c2n_router: Arc<C2nRouter>,
    suggested_exit_node: Arc<RwLock<String>>,
    client_updater: Arc<std::sync::Mutex<rustscale_clientupdate::ClientUpdater>>,
    tailnet_lock: Arc<crate::tailnet_lock::TailnetLock>,
    tailnet_identity: String,
) -> JoinHandle<()> {
    // Create the netmap cache helper once so that save_if_changed can
    // dedup identical writes via the in-memory SHA-256 hash.
    let netmap_cache = state_scope
        .as_ref()
        .map(|scope| NetMapCache::new_scoped(scope, ""));
    // Watchdog for map-response timeout: fires if no MapResponse for >2m5s
    // (matching Go's MapResponseTimeout duration). Fed on each response.
    let map_timeout_watchdog = Watchdog::new(
        health.clone(),
        WARN_MAP_RESPONSE_TIMEOUT,
        "Network map response timeout",
        Severity::Medium,
        "no map response for over 2 minutes",
        std::time::Duration::from_secs(125),
    );
    tokio::spawn(async move {
        let mut first_non_keepalive = true;
        loop {
            if cancel.is_cancelled() {
                break;
            }
            match map_rx.recv().await {
                Some(Ok(resp)) => {
                    // Map activity: feed the staleness watchdogs + mark
                    // control healthy. Even keep-alive messages count.
                    health_watchdog.feed();
                    map_timeout_watchdog.feed();
                    health.set_healthy(WARN_CONTROL);
                    health.set_healthy(WARN_NOT_IN_MAP_POLL);
                    send_health_notify(&health, &ipn_backend);

                    if let Some(derp_map) = resp.DERPMap.as_ref() {
                        magicsock.set_derp_map(derp_map);
                    }

                    if resp.KeepAlive {
                        if let Some(router) = router.as_ref() {
                            let routes = route_table.read().await;
                            if routes.exit_node().is_some() {
                                let derp_map = magicsock.get_derp_map();
                                let exit_node_allow_lan_access =
                                    prefs.read().await.ExitNodeAllowLANAccess;
                                if let Err(error) = sync_router(
                                    router,
                                    &tailscale_ips,
                                    &routes,
                                    derp_map.as_ref(),
                                    &control_url,
                                    exit_node_allow_lan_access,
                                ) {
                                    eprintln!(
                                        "tsnet: bypass-route update failed (non-fatal): {error}"
                                    );
                                }
                            }
                        }
                        continue;
                    }

                    if !resp.Domain.is_empty() && resp.Domain != tailnet_identity {
                        log::error!(
                            "tsnet: control changed tailnet identity for the active profile; failing closed"
                        );
                        tailnet_lock.require_fresh_control_state();
                        raw_peers.clear();
                        peers_arc.write().await.clear();
                        wg_tunnels.write().await.clear();
                        route_table
                            .write()
                            .await
                            .rebuild_with_opts(&[], accept_routes);
                        let _ = magicsock.set_netmap(Vec::new()).await;
                        ipn_backend.set_blocked(true);
                        break;
                    }

                    let tka_state_may_change = first_non_keepalive || resp.TKAInfo.is_some();
                    let tka_sync =
                        tailnet_lock.apply_control_info(resp.TKAInfo.as_ref(), first_non_keepalive);
                    tokio::select! {
                        () = cancel.cancelled() => break,
                        result = tka_sync => {
                            if let Err(error) = result {
                                // The verifier remains in its fail-closed state;
                                // do not retain peers using stale/partial state.
                                log::warn!("tsnet: Tailnet Lock synchronization failed closed: {error}");
                            }
                        }
                    }
                    first_non_keepalive = false;
                    map_session.set_tka_head(tailnet_lock.head());
                    if resp.Node.is_some() {
                        tailnet_lock.set_self_node(resp.Node.clone());
                    }

                    // Track map session handle + seq for delta resumption.
                    // The server sends MapSessionHandle on the first message
                    // of a session; Seq increments on each subsequent message.
                    // On reconnection, stream_map_loop reads these to resume
                    // from the last-processed sequence.
                    if !resp.MapSessionHandle.is_empty() || resp.Seq > 0 {
                        map_session.set(resp.MapSessionHandle.clone(), resp.Seq);
                    }

                    // Handle key expiry from the control server. The
                    // testcontrol server signals expiry by setting
                    // Node.KeyExpiry to a past time in MapResponse. The
                    // real control server may also set NodeKeyExpired on
                    // the RegisterResponse. We check both sources.
                    let expired = resp.NodeKeyExpired
                        || resp
                            .Node
                            .as_ref()
                            .and_then(|n| n.KeyExpiry)
                            .is_some_and(|expiry| expiry < chrono::Utc::now());
                    key_expired.store(expired, std::sync::atomic::Ordering::Relaxed);
                    ipn_backend.set_key_expired(expired);
                    if expired {
                        log::info!("tsnet: node key expired (signalled by control)");
                        if let Some(scope) = state_scope.as_ref() {
                            NetMapCache::new_scoped(scope, "").clear();
                        }

                        // Attempt key rotation: re-register with
                        // OldNodeKey + fresh NodeKey. On success, promote
                        // the new key, restart the map poll, and continue.
                        if let Some(ctx) = key_rotation_ctx.as_ref() {
                            match perform_key_rotation(
                                ctx,
                                &node_key,
                                &magicsock,
                                &wg_tunnels,
                                state_scope.as_ref().map(|scope| scope.dir.as_path()),
                                &ipn_backend,
                            )
                            .await
                            {
                                Ok(Some(new_key)) => {
                                    node_key = new_key.clone();
                                    node_pub = new_key.public();
                                    tailnet_lock.set_node_key(new_key);
                                    key_expired.store(false, std::sync::atomic::Ordering::Relaxed);
                                    ipn_backend.set_key_expired(false);
                                    ipn_backend.set_blocked(false);
                                    ipn_backend.emit_login_finished();

                                    // Restart the map poll with the new
                                    // key. Dropping the old map_rx closes
                                    // the channel, which stops the old
                                    // stream_map_loop. The new map task
                                    // feeds into the new receiver.
                                    let (new_tx, new_rx) = mpsc::channel(32);
                                    let cc_new = ControlClient::new(
                                        ctx.control_url.clone(),
                                        ctx.machine_key.clone(),
                                        ctx.server_pub_key.clone(),
                                        ctx.protocol_version,
                                    );
                                    let new_map_req = MapRequest {
                                        Version: ctx.capability_version,
                                        KeepAlive: true,
                                        NodeKey: node_pub.clone(),
                                        DiscoKey: ctx.disco_key.public(),
                                        Stream: true,
                                        Endpoints: magicsock.local_udp_addrs(),
                                        Hostinfo: Some(Hostinfo {
                                            OS: std::env::consts::OS.to_string(),
                                            Hostname: ctx.hostname.clone(),
                                            RoutableIPs: ctx.advertise_routes.clone(),
                                            PeerRelay: ctx.peer_relay_server,
                                            ShieldsUp: ctx.shields_up,
                                            ..Default::default()
                                        }),
                                        ..Default::default()
                                    };
                                    let ss = map_session.clone();
                                    let router = c2n_router.clone();
                                    tokio::spawn(async move {
                                        cc_new
                                            .stream_map_loop_with_c2n(
                                                &new_map_req,
                                                new_tx,
                                                Some(ss),
                                                router,
                                            )
                                            .await;
                                    });
                                    map_rx = new_rx;
                                    log::info!(
                                        "tsnet: key rotation complete, map poll restarted with new node key"
                                    );
                                }
                                Ok(None) => {
                                    log::info!(
                                        "tsnet: current key remains globally expired; waiting for control update"
                                    );
                                }
                                Err(e) => {
                                    log::warn!("tsnet: key rotation failed: {e}");
                                    ipn_backend
                                        .emit_err_message(format!("key rotation failed: {e}"));
                                }
                            }
                        }
                    }

                    // Extract control knobs from the self-node's CapMap and
                    // apply them. Mirrors Go's
                    // `controlKnobs.UpdateFromNodeAttributes(resp.Node.CapMap)`
                    // (controlclient/map.go:302).
                    let knobs = extract_knobs_from_map_response(&resp);
                    if !knobs.is_empty() {
                        control_knobs.apply(knobs);
                    }

                    // Update the self node's CapMap in magicsock so the relay
                    // server extension can check NODE_ATTR_DISABLE_RELAY_SERVER.
                    if let Some(ref node) = resp.Node {
                        magicsock.set_self_cap_map(node.CapMap.clone());
                    }

                    // Wire NetInfo from control to magicsock. Control may push
                    // updated network probe results (PreferredDERP, connectivity)
                    // that supersede the client's local netcheck. Also check
                    // the self-node's Hostinfo for NetInfo (sent back by some
                    // control servers).
                    if let Some(ref ni) = resp.NetInfo {
                        magicsock.set_net_info(ni);
                    } else if let Some(ref node) = resp.Node {
                        if let Some(ref hi) = node.Hostinfo {
                            if let Some(ref ni) = hi.NetInfo {
                                magicsock.set_net_info(ni);
                            }
                        }
                    }

                    // Reconcile the raw control view by stable Node.ID before
                    // intersecting it with TKA authorization. Invalid identity
                    // or address ownership withdraws all peers and grants.
                    let current_peers = peers_arc.read().await.clone();
                    let (next_raw_peers, invalid_peer_map) =
                        match crate::peer_map::reconcile(&raw_peers, &resp) {
                            Ok(peers) => (peers, false),
                            Err(error) => {
                                log::warn!("tsnet: rejecting invalid peer map update: {error}");
                                (Vec::new(), true)
                            }
                        };
                    raw_peers = next_raw_peers;
                    let mut next_peers = raw_peers.clone();
                    tailnet_lock.filter_peers(&mut next_peers);
                    let peers_changed =
                        tka_state_may_change || invalid_peer_map || next_peers != current_peers;

                    // Construct replacement tunnels and routes before the
                    // commit gate. Unchanged verified keys keep WG state;
                    // stable-ID rotations and TKA withdrawals cannot.
                    let old_tunnels = wg_tunnels.read().await;
                    let next_tunnels = build_peer_tunnels(&node_key, &next_peers, &old_tunnels);
                    drop(old_tunnels);
                    let mut next_routes =
                        RouteTable::from_peers_with_opts(&next_peers, accept_routes);
                    if let Some(selected) = route_table.read().await.exit_node().cloned() {
                        if let Some(replacement) =
                            rotated_peer_key(&current_peers, &next_peers, &selected)
                        {
                            next_routes.set_exit_node(replacement);
                        }
                    }
                    exit_node_selection
                        .write()
                        .await
                        .retry(&next_peers, &mut next_routes);

                    // One writer commit replaces every peer-derived authority:
                    // authenticated source ownership, tunnels, magicsock and
                    // relay generations, ACL capability grants, routes, and
                    // Taildrive publication epochs all use the TKA-verified
                    // stable-ID intersection.
                    let map_commit = peer_map.gate.write().await;
                    let mut drive_epoch = drive.authorization_write().await;
                    drive.rotate_authorization_locked(&mut drive_epoch);
                    if invalid_peer_map {
                        drive.set_sharing_allowed_locked(false, &mut drive_epoch);
                    } else if let Some(ref node) = resp.Node {
                        let sharing_allowed = node
                            .Capabilities
                            .iter()
                            .any(|cap| cap == rustscale_drive::NODE_CAPABILITY_TAILDRIVE_SHARE)
                            || node
                                .CapMap
                                .contains_key(rustscale_drive::NODE_CAPABILITY_TAILDRIVE_SHARE);
                        drive.set_sharing_allowed_locked(sharing_allowed, &mut drive_epoch);
                    }

                    let filter_changed = process_filter_deltas(&resp, &mut named_filters);
                    if invalid_peer_map {
                        named_filters.clear();
                        *filter_arc.lock().unwrap() = Filter::allow_none();
                    } else if filter_changed || peers_changed {
                        let shields_up = filter_arc.lock().unwrap().shields_up();
                        rebuild_filter(
                            &filter_arc,
                            &named_filters,
                            &tailscale_ips,
                            &advertise_routes,
                            &next_peers,
                            shields_up,
                        );
                    }
                    if let Err(error) = magicsock.set_netmap(next_peers.clone()).await {
                        log::warn!("tsnet: magicsock peer-map update failed: {error}");
                    }
                    peers_arc.write().await.clone_from(&next_peers);
                    *wg_tunnels.write().await = next_tunnels;
                    *route_table.write().await = next_routes;
                    peer_map
                        .install_locked(&next_peers)
                        .expect("validated verified peer map installs");
                    drop(drive_epoch);
                    drop(map_commit);
                    let peers = next_peers;

                    // Forward peer deltas to the IPN notify bus so
                    // watch-ipn-bus subscribers receive PeersChanged /
                    // PeersRemoved / NetMap. Mirrors Go's `ipnlocal.send`
                    // in the full-netmap and delta notify paths.
                    if !resp.PeersChanged.is_empty() || !resp.Peers.is_empty() {
                        let changed_nodes: Vec<serde_json::Value> = peers
                            .iter()
                            .filter_map(|peer| serde_json::to_value(peer).ok())
                            .collect();
                        if !changed_nodes.is_empty() {
                            ipn_backend.bus().send(rustscale_ipn::Notify {
                                PeersChanged: Some(changed_nodes),
                                ..Default::default()
                            });
                        }
                    }
                    // On a full peer list (Peers non-empty), also send a
                    // NetMap notify with a summary JSON. This mirrors Go's
                    // full-netmap notify path for legacy/initial-netmap
                    // watchers.
                    if !resp.Peers.is_empty() {
                        let peers_json: Vec<serde_json::Value> = peers
                            .iter()
                            .filter_map(|peer| serde_json::to_value(peer).ok())
                            .collect();
                        let netmap_json = serde_json::json!({
                            "Peers": peers_json,
                            "Self": resp.Node.as_ref().and_then(|n| serde_json::to_value(n).ok()),
                        });
                        ipn_backend.bus().send(rustscale_ipn::Notify {
                            NetMap: Some(netmap_json),
                            ..Default::default()
                        });
                    }
                    if !resp.PeersRemoved.is_empty() {
                        let removed_ids: Vec<i64> = resp.PeersRemoved.clone();
                        ipn_backend.bus().send(rustscale_ipn::Notify {
                            PeersRemoved: Some(removed_ids),
                            ..Default::default()
                        });
                    }
                    // Note: PeerChangedPatch on Notify is populated from
                    // NodeMutation delta events (Go's UpdateNetmapDelta),
                    // not from MapResponse. The MapResponse struct has no
                    // PeerChangedPatch field. That path will be wired when
                    // the netmap delta subscription system is ported.

                    // Peer-derived in-process state was committed above.
                    // Apply the already-built route snapshot to the OS after
                    // releasing the packet gate so shell/native router work
                    // cannot stall data-plane readers.
                    let live_prefs = prefs.read().await.clone();
                    if let Some(router) = router.as_ref() {
                        let derp_map = magicsock.get_derp_map();
                        let routes = route_table.read().await;
                        if let Err(error) = sync_router(
                            router,
                            &tailscale_ips,
                            &routes,
                            derp_map.as_ref(),
                            &control_url,
                            live_prefs.ExitNodeAllowLANAccess,
                        ) {
                            eprintln!("tsnet: route update failed (non-fatal): {error}");
                        }
                    }

                    // Update IPN engine status: peer count as NumLive, DERP
                    // home connection as LiveDERPs. This may transition the
                    // state machine from Starting to Running.
                    let live_count = peers.iter().filter(|p| !p.Key.is_zero()).count() as i32;
                    ipn_backend.set_engine_status(live_count, 1);

                    // Refresh the shared MagicDNS resolver with the new peers.
                    resolver.write().await.set_peers(peers.clone());

                    // Apply DNSConfig delta (None means unchanged).
                    if let Some(cfg) = &resp.DNSConfig {
                        dns_config.write().await.clone_from(&resp.DNSConfig);
                        // Rebuild the resolver config from the new DNSConfig,
                        // preserving the current peers and domain. This wires
                        // split-DNS Routes, ExtraRecords hosts, and local
                        // domains from the control plane.
                        let mut r = resolver.write().await;
                        let domain = r.domain().to_string();
                        let new_config = config_from_dns(cfg, &domain, &peers);
                        r.set_config(new_config);
                    }

                    // Merge UserProfiles delta (add/update; never removed).
                    if !resp.UserProfiles.is_empty() {
                        let mut ups = user_profiles.write().await;
                        for up in &resp.UserProfiles {
                            ups.insert(up.ID, up.clone());
                        }
                    }

                    // Apply SSHPolicy delta (None = unchanged; Some = replace).
                    // Mirrors Go's `ipn/ipnlocal/local.go` feeding
                    // `netMap.SSHPolicy` into the SSH server on each netmap
                    // update.
                    if resp.SSHPolicy.is_some() {
                        ssh_policy.write().await.clone_from(&resp.SSHPolicy);
                    }

                    // Extract control-suggested exit node (Go's
                    // MapResponse.SuggestedExitNode). Stored for LocalAPI
                    // /status to surface to the CLI `exit-node` subcommand.
                    if !resp.SuggestedExitNode.is_empty() {
                        suggested_exit_node
                            .write()
                            .await
                            .clone_from(&resp.SuggestedExitNode);
                    }

                    // Process ClientVersion from the control server (Go's
                    // `LocalBackend.onClientVersion`). Feed it to the
                    // ClientUpdater and fire a Notify so CLI status can show
                    // update availability.
                    if let Some(ref cv) = resp.ClientVersion {
                        if let Ok(mut u) = client_updater.lock() {
                            u.set_client_version(cv.clone());
                        }
                        ipn_backend.bus().send(rustscale_ipn::Notify {
                            ClientVersion: serde_json::to_value(cv).ok(),
                            ..Default::default()
                        });
                    }

                    // Save the updated netmap to disk (best-effort) so a
                    // restart can skip the blocking first fetch. Dedup via
                    // SHA-256 skips the write if the content is unchanged
                    // since the last successful save.
                    if let Some(ref cache) = netmap_cache {
                        if let Err(e) = cache.save_if_changed(&node_pub, &resp) {
                            log::warn!("tsnet: netmap cache save failed (non-fatal): {e}");
                        }
                    }
                }
                Some(Err(e)) => {
                    health.set_unhealthy(WARN_CONTROL, format!("control connection lost: {e}"));
                    health.set_unhealthy(
                        WARN_NOT_IN_MAP_POLL,
                        "map poll stream error: not receiving updates",
                    );
                    send_health_notify(&health, &ipn_backend);
                    break;
                }
                None => {
                    health.set_unhealthy(WARN_CONTROL, "control connection lost: stream closed");
                    health.set_unhealthy(
                        WARN_NOT_IN_MAP_POLL,
                        "map poll stream closed: not receiving updates",
                    );
                    send_health_notify(&health, &ipn_backend);
                    break;
                }
            }
        }
    })
}

fn rotation_register_request(
    ctx: &KeyRotationCtx,
    node_key: NodePublic,
    old_node_key: Option<NodePublic>,
) -> RegisterRequest {
    RegisterRequest {
        Version: ctx.capability_version,
        NodeKey: node_key,
        OldNodeKey: old_node_key.unwrap_or_default(),
        // Auth keys are initial-login credentials. Refresh and replacement
        // registrations prove continuity with node keys and must never replay
        // a one-use federated key.
        Auth: None,
        Hostinfo: Some(Hostinfo {
            OS: std::env::consts::OS.to_string(),
            Hostname: ctx.hostname.clone(),
            RoutableIPs: ctx.advertise_routes.clone(),
            PeerRelay: ctx.peer_relay_server,
            ShieldsUp: ctx.shields_up,
            ..Default::default()
        }),
        Ephemeral: ctx.ephemeral,
        ..Default::default()
    }
}

/// Re-register with the control server after a key expiry.
///
/// Mirrors Go's `doLogin` with `regen=true` (`direct.go:739-926`):
/// 1. Refresh the current key. If control reports it expired, regenerate it.
/// 2. Save current key as `OldPrivateNodeKey` and generate a fresh node key.
/// 3. Send `RegisterRequest` with `OldNodeKey` + `NodeKey`.
/// 4. If `resp.AuthURL` is non-empty, send a followup and block until
///    interactive auth completes.
/// 5. On success, persist the new key, re-key magicsock, and clear WG
///    tunnels so they are recreated with the new key.
///
/// `Ok(None)` means control also rejected the fresh replacement key, which
/// indicates a global expiry policy. The current map stream remains active so
/// an un-expire update can recover.
async fn perform_key_rotation(
    ctx: &KeyRotationCtx,
    current_key: &NodePrivate,
    magicsock: &Magicsock,
    wg_tunnels: &Arc<RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>>,
    state_dir: Option<&std::path::Path>,
    ipn_backend: &Arc<IpnBackend>,
) -> Result<Option<NodePrivate>, String> {
    let old_key = current_key.clone();
    let old_pub = old_key.public();

    // Match the upstream client's refresh-before-regenerate behavior. An
    // expired current key requires regeneration; a replacement that is also
    // expired indicates a global expiry policy and must not be promoted.
    let refresh_req = rotation_register_request(ctx, old_pub.clone(), None);
    let refresh = ControlClient::new(
        ctx.control_url.clone(),
        ctx.machine_key.clone(),
        ctx.server_pub_key.clone(),
        ctx.protocol_version,
    )
    .register(&refresh_req)
    .await
    .map_err(|e| format!("refresh register: {e}"))?;
    if !refresh.Error.is_empty() {
        return Err(format!(
            "control rejected refresh registration: {}",
            refresh.Error
        ));
    }
    if !refresh.NodeKeyExpired {
        // The expiry was cleared between the map update and registration.
        // Keep the current identity and let the caller restart its map poll.
        return Ok(Some(old_key));
    }
    let trying_key = NodePrivate::generate();
    let old_node_key = old_pub.clone();

    {
        let new_pub = trying_key.public();

        let reg_req = rotation_register_request(ctx, new_pub.clone(), Some(old_node_key.clone()));

        let cc = ControlClient::new(
            ctx.control_url.clone(),
            ctx.machine_key.clone(),
            ctx.server_pub_key.clone(),
            ctx.protocol_version,
        );

        let resp = cc
            .register(&reg_req)
            .await
            .map_err(|e| format!("register: {e}"))?;

        if !resp.Error.is_empty() {
            return Err(format!("control rejected re-registration: {}", resp.Error));
        }

        if resp.NodeKeyExpired {
            log::info!("tsnet: replacement key is also expired; retaining current map stream");

            // Some control implementations transfer the node record to
            // OldNodeKey's replacement before reporting global expiry. Roll
            // that tentative transfer back so the current map stream can
            // reconnect after the global policy is cleared.
            let mut rollback_req = reg_req.clone();
            rollback_req.NodeKey = old_pub.clone();
            rollback_req.OldNodeKey = new_pub;
            match cc.register(&rollback_req).await {
                Ok(rollback) if !rollback.Error.is_empty() => {
                    log::warn!(
                        "tsnet: control rejected expired-key rollback: {}",
                        rollback.Error
                    );
                }
                Err(error) => {
                    log::warn!("tsnet: expired-key rollback failed: {error}");
                }
                _ => {}
            }
            return Ok(None);
        }

        // If interactive auth is required, emit BrowseToURL and block on
        // the followup poll until the user completes auth.
        if !resp.AuthURL.is_empty() {
            log::info!(
                "tsnet: key rotation requires interactive auth: {}",
                resp.AuthURL
            );
            ipn_backend.emit_browse_to_url(&resp.AuthURL);

            let followup_req = RegisterRequest {
                Version: ctx.capability_version,
                NodeKey: new_pub.clone(),
                OldNodeKey: old_node_key.clone(),
                Followup: resp.AuthURL.clone(),
                Hostinfo: Some(Hostinfo {
                    OS: std::env::consts::OS.to_string(),
                    Hostname: ctx.hostname.clone(),
                    RoutableIPs: ctx.advertise_routes.clone(),
                    PeerRelay: ctx.peer_relay_server,
                    ShieldsUp: ctx.shields_up,
                    ..Default::default()
                }),
                Ephemeral: ctx.ephemeral,
                ..Default::default()
            };
            let cc2 = ControlClient::new(
                ctx.control_url.clone(),
                ctx.machine_key.clone(),
                ctx.server_pub_key.clone(),
                ctx.protocol_version,
            );
            let followup_resp = cc2
                .register(&followup_req)
                .await
                .map_err(|e| format!("followup register: {e}"))?;

            if !followup_resp.Error.is_empty() {
                return Err(format!(
                    "control rejected followup: {}",
                    followup_resp.Error
                ));
            }
            if followup_resp.NodeKeyExpired {
                log::info!(
                    "tsnet: authenticated replacement key is expired; retaining current map stream"
                );
                return Ok(None);
            }
        }

        // Success — promote the new key.
        // Persist: save new node_key + old_node_key to disk.
        if let Some(dir) = state_dir {
            let path = dir.join("tsnet-state.json");
            if let Ok(mut state) = PersistedState::load(&path) {
                state.old_node_key = Some(old_key.clone());
                state.node_key = trying_key.clone();
                if let Err(e) = state.save(&path) {
                    log::warn!("tsnet: failed to save rotated key state: {e}");
                }
            }
        }

        // Re-key magicsock so disco/relay use the new identity.
        magicsock.set_node_key(&trying_key);

        // Clear all WG tunnels — they were created with the old private
        // key and must be recreated with the new one.
        wg_tunnels.write().await.clear();

        log::info!(
            "tsnet: key rotation succeeded (old={}, new={})",
            old_pub,
            trying_key.public()
        );
        Ok(Some(trying_key))
    }
}

/// Send a Notify with the current health warnings so frontend consumers
/// can surface health state changes. Mirrors Go's `LocalBackend.sendHealthNotify`.
fn rotated_peer_key(current: &[Node], next: &[Node], selected: &NodePublic) -> Option<NodePublic> {
    let stable_id = current.iter().find(|peer| &peer.Key == selected)?.ID;
    next.iter()
        .find(|peer| peer.ID == stable_id)
        .map(|peer| peer.Key.clone())
}

fn build_peer_tunnels(
    node_key: &NodePrivate,
    peers: &[Node],
    current: &HashMap<NodePublic, Arc<Mutex<WgTunn>>>,
) -> HashMap<NodePublic, Arc<Mutex<WgTunn>>> {
    peers
        .iter()
        .filter_map(|peer| {
            current
                .get(&peer.Key)
                .cloned()
                .or_else(|| {
                    WgTunn::new(node_key, &peer.Key, rand_index())
                        .ok()
                        .map(|tunnel| Arc::new(Mutex::new(tunnel)))
                })
                .map(|tunnel| (peer.Key.clone(), tunnel))
        })
        .collect()
}

fn send_health_notify(health: &Tracker, ipn_backend: &IpnBackend) {
    let warnings: Vec<String> = health
        .current_warnings()
        .iter()
        .map(|w| w.text.clone())
        .collect();
    ipn_backend
        .bus()
        .send(rustscale_ipn::Notify::health(warnings));
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustscale_ipn::Prefs;
    use rustscale_key::{DiscoPrivate, NodePrivate};
    use rustscale_tailcfg::PeerChange;

    fn sample_peer() -> Node {
        Node {
            ID: 10,
            Key: NodePrivate::generate().public(),
            DiscoKey: DiscoPrivate::generate().public(),
            HomeDERP: 3,
            Online: Some(true),
            Endpoints: vec!["1.2.3.4:5".into()],
            Cap: 50,
            ..Default::default()
        }
    }

    #[test]
    fn peer_key_rotation_preserves_exit_selection_by_stable_id() {
        let old_key = NodePrivate::generate().public();
        let new_key = NodePrivate::generate().public();
        let old_peer = Node {
            ID: 10,
            Key: old_key.clone(),
            ..Default::default()
        };
        let new_peer = Node {
            ID: 10,
            Key: new_key.clone(),
            ..Default::default()
        };
        assert_eq!(
            rotated_peer_key(&[old_peer], &[new_peer], &old_key),
            Some(new_key)
        );
    }

    #[test]
    fn peer_key_rotation_removes_old_decryption_tunnel() {
        let local = NodePrivate::generate();
        let old_key = NodePrivate::generate().public();
        let new_key = NodePrivate::generate().public();
        let old_tunnel = Arc::new(Mutex::new(
            WgTunn::new(&local, &old_key, 1).expect("old tunnel"),
        ));
        let current = HashMap::from([(old_key.clone(), old_tunnel)]);
        let rotated = build_peer_tunnels(
            &local,
            &[Node {
                ID: 10,
                Key: new_key.clone(),
                Addresses: vec!["100.64.0.2/32".into()],
                ..Default::default()
            }],
            &current,
        );
        assert!(!rotated.contains_key(&old_key));
        assert!(rotated.contains_key(&new_key));
    }

    #[test]
    fn key_rotation_refresh_and_replacement_omit_auth() {
        let ctx = KeyRotationCtx {
            control_url: "https://control.example".into(),
            machine_key: MachinePrivate::generate(),
            server_pub_key: MachinePrivate::generate().public(),
            hostname: "node".into(),
            ephemeral: true,
            advertise_routes: vec![],
            peer_relay_server: false,
            disco_key: DiscoPrivate::generate(),
            capability_version: 141,
            protocol_version: 141,
            shields_up: false,
        };
        let current = NodePrivate::generate().public();
        let replacement = NodePrivate::generate().public();

        let refresh = rotation_register_request(&ctx, current.clone(), None);
        assert!(refresh.Auth.is_none());
        assert!(refresh.OldNodeKey.is_zero());

        let replace = rotation_register_request(&ctx, replacement, Some(current.clone()));
        assert!(replace.Auth.is_none());
        assert_eq!(replace.OldNodeKey, current);
    }

    #[test]
    fn unresolved_persisted_exit_node_is_retried_when_peer_arrives() {
        let exit_key = NodePrivate::generate().public();
        let prefs = Prefs {
            ExitNodeIP: "100.64.0.9".into(),
            ..Default::default()
        };
        let mut routes = RouteTable::default();
        let mut selection = ExitNodeSelection::from_prefs(&prefs);
        selection.retry(&[], &mut routes);
        assert!(routes.exit_node().is_none());

        let mut peer = Node {
            Key: exit_key.clone(),
            Addresses: vec!["100.64.0.9/32".into()],
            AllowedIPs: vec!["0.0.0.0/0".into()],
            ..Default::default()
        };
        assert!(!selection.retry(std::slice::from_ref(&peer), &mut routes));
        assert!(routes.exit_node().is_none());

        peer.AllowedIPs.push("::/0".into());
        assert!(selection.retry(&[peer], &mut routes));
        assert_eq!(routes.exit_node(), Some(&exit_key));
    }

    #[test]
    fn persisted_exit_node_does_not_overwrite_explicit_set() {
        let persisted = NodePrivate::generate().public();
        let explicit = NodePrivate::generate().public();
        let prefs = Prefs {
            ExitNodeIP: "100.64.0.9".into(),
            ..Default::default()
        };
        let peer = Node {
            Key: persisted,
            Addresses: vec!["100.64.0.9/32".into()],
            AllowedIPs: vec!["0.0.0.0/0".into(), "::/0".into()],
            ..Default::default()
        };
        let mut selection = ExitNodeSelection::from_prefs(&prefs);
        let mut routes = RouteTable::default();
        selection.retry(&[peer], &mut routes);

        routes.set_exit_node(explicit.clone());
        routes.rebuild_with_opts(&[], false);
        selection.retry(&[], &mut routes);
        assert_eq!(routes.exit_node(), Some(&explicit));
    }

    #[test]
    fn persisted_exit_node_does_not_overwrite_explicit_clear() {
        let persisted = NodePrivate::generate().public();
        let prefs = Prefs {
            ExitNodeIP: "100.64.0.9".into(),
            ..Default::default()
        };
        let peer = Node {
            Key: persisted,
            Addresses: vec!["100.64.0.9/32".into()],
            AllowedIPs: vec!["0.0.0.0/0".into(), "::/0".into()],
            ..Default::default()
        };
        let mut selection = ExitNodeSelection::from_prefs(&prefs);
        let mut routes = RouteTable::default();
        selection.retry(&[peer], &mut routes);
        routes.clear_exit_node();
        routes.rebuild_with_opts(&[], false);
        selection.retry(&[], &mut routes);
        assert!(routes.exit_node().is_none());
    }

    #[test]
    fn config_exit_node_survives_map_rebuild() {
        let config_exit = NodePrivate::generate().public();
        let mut routes = RouteTable::default();
        routes.set_exit_node(config_exit.clone());
        routes.rebuild_with_opts(&[], false);
        let mut selection = ExitNodeSelection::default();
        selection.retry(&[], &mut routes);
        assert_eq!(routes.exit_node(), Some(&config_exit));
    }

    #[test]
    fn peer_change_patch_derp_and_online() {
        let mut peer = sample_peer();
        let patch = PeerChange {
            NodeID: 10,
            DERPRegion: 7,
            Online: Some(false),
            ..Default::default()
        };
        crate::peer_map::apply_patch(&mut peer, &patch);
        assert_eq!(peer.HomeDERP, 7);
        assert_eq!(peer.Online, Some(false));
        // Unchanged fields stay the same.
        assert_eq!(peer.Cap, 50);
        assert!(!peer.Endpoints.is_empty());
    }

    #[test]
    fn peer_change_patch_endpoints_and_key() {
        let mut peer = sample_peer();
        let new_key = NodePrivate::generate().public();
        let patch = PeerChange {
            NodeID: 10,
            Endpoints: vec!["5.6.7.8:9".into(), "[::1]:10".into()],
            Key: Some(new_key.clone()),
            ..Default::default()
        };
        crate::peer_map::apply_patch(&mut peer, &patch);
        assert_eq!(peer.Endpoints, vec!["5.6.7.8:9", "[::1]:10"]);
        assert_eq!(peer.Key, new_key);
        // DERPRegion 0 means unchanged.
        assert_eq!(peer.HomeDERP, 3);
    }

    #[test]
    fn peer_change_patch_last_seen_and_key_expiry() {
        let mut peer = sample_peer();
        let ts = chrono::DateTime::parse_from_rfc3339("2025-07-12T10:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let patch = PeerChange {
            NodeID: 10,
            LastSeen: Some(ts),
            KeyExpiry: Some(ts),
            ..Default::default()
        };
        crate::peer_map::apply_patch(&mut peer, &patch);
        assert_eq!(peer.LastSeen, Some(ts));
        assert_eq!(peer.KeyExpiry, Some(ts));
    }

    #[test]
    fn peer_change_patch_unknown_node_is_noop() {
        let mut peer = sample_peer();
        let original = peer.clone();
        // Patch for a different NodeID — should not be applied by the caller,
        // but the patch helper itself doesn't check NodeID.
        let patch = PeerChange {
            NodeID: 999,
            DERPRegion: 42,
            ..Default::default()
        };
        // Reconciliation checks NodeID before calling the patch helper.
        crate::peer_map::apply_patch(&mut peer, &patch);
        assert_eq!(peer.HomeDERP, 42);
        // Verify the original is different
        assert_ne!(peer.HomeDERP, original.HomeDERP);
    }
}
