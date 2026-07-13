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
    pub auth_key: String,
    pub ephemeral: bool,
    pub advertise_routes: Vec<String>,
    pub peer_relay_server: bool,
    pub disco_key: DiscoPrivate,
    pub capability_version: i32,
    pub protocol_version: u16,
    pub shields_up: bool,
}

/// Spawn the map-stream delta update task. Shared by `up()` and `up_tun()`:
/// processes Peers/PeersChanged/PeersRemoved, feeds the new peer list to
/// magicsock, rebuilds the route table, and creates WG tunnels for new peers.
#[allow(clippy::too_many_arguments)]
pub(crate) fn spawn_map_update_task(
    mut map_rx: mpsc::Receiver<Result<MapResponse, StreamMapError>>,
    magicsock: Arc<Magicsock>,
    wg_tunnels: Arc<RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>>,
    peers_arc: Arc<RwLock<Vec<Node>>>,
    route_table: Arc<RwLock<RouteTable>>,
    router: Option<SharedRouter>,
    mut node_key: NodePrivate,
    filter_arc: Arc<std::sync::Mutex<Filter>>,
    tailscale_ips: Vec<IpAddr>,
    accept_routes: bool,
    advertise_routes: Vec<String>,
    resolver: Arc<RwLock<MagicDnsResolver>>,
    dns_config: Arc<RwLock<Option<DNSConfig>>>,
    user_profiles: Arc<RwLock<BTreeMap<UserID, UserProfile>>>,
    ssh_policy: Arc<RwLock<Option<SSHPolicy>>>,
    cancel: Arc<CancelToken>,
    health: Tracker,
    health_watchdog: Watchdog,
    state_dir: Option<PathBuf>,
    mut node_pub: NodePublic,
    control_knobs: Arc<ControlKnobs>,
    key_expired: Arc<std::sync::atomic::AtomicBool>,
    ipn_backend: Arc<IpnBackend>,
    key_rotation_ctx: Option<KeyRotationCtx>,
    map_session: Arc<MapSessionState>,
    suggested_exit_node: Arc<RwLock<String>>,
    client_updater: Arc<std::sync::Mutex<rustscale_clientupdate::ClientUpdater>>,
) -> JoinHandle<()> {
    let mut named_filters: BTreeMap<String, Vec<FilterRule>> = BTreeMap::new();
    // Create the netmap cache helper once so that save_if_changed can
    // dedup identical writes via the in-memory SHA-256 hash.
    let netmap_cache = state_dir.as_ref().map(|dir| NetMapCache::new(dir));
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

                    if resp.KeepAlive {
                        continue;
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
                        eprintln!("tsnet: node key expired (signalled by control)");
                        if let Some(ref dir) = state_dir {
                            PersistedState::clear_netmap(dir);
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
                                state_dir.as_deref(),
                                &ipn_backend,
                            )
                            .await
                            {
                                Ok(new_key) => {
                                    node_key = new_key.clone();
                                    node_pub = new_key.public();
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
                                    tokio::spawn(async move {
                                        cc_new
                                            .stream_map_loop(&new_map_req, new_tx, Some(ss))
                                            .await;
                                    });
                                    map_rx = new_rx;
                                    eprintln!(
                                        "tsnet: key rotation complete, map poll restarted with new node key"
                                    );
                                }
                                Err(e) => {
                                    eprintln!("tsnet: key rotation failed: {e}");
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

                    // Merge peer deltas. Track whether the peer set changed
                    // so the filter's capability map can be refreshed.
                    let peers_changed = !resp.Peers.is_empty()
                        || !resp.PeersChanged.is_empty()
                        || !resp.PeersRemoved.is_empty()
                        || resp
                            .PeersChangedPatch
                            .as_ref()
                            .is_some_and(|p| !p.is_empty());
                    {
                        let mut peers = peers_arc.write().await;
                        if !resp.Peers.is_empty() {
                            peers.clone_from(&resp.Peers);
                        }
                        if !resp.PeersChanged.is_empty() {
                            for changed in &resp.PeersChanged {
                                if let Some(existing) =
                                    peers.iter_mut().find(|p| p.Key == changed.Key)
                                {
                                    *existing = changed.clone();
                                } else {
                                    peers.push(changed.clone());
                                }
                            }
                        }
                        if !resp.PeersRemoved.is_empty() {
                            peers.retain(|p| !resp.PeersRemoved.contains(&p.ID));
                        }
                        // Apply incremental peer patches (PeersChangedPatch).
                        // These are lighter-weight updates that only modify
                        // individual fields (Online, LastSeen, DERPRegion,
                        // Endpoints, Key, DiscoKey, KeyExpiry, Cap, CapMap).
                        if let Some(ref patches) = resp.PeersChangedPatch {
                            for patch in patches {
                                if let Some(existing) =
                                    peers.iter_mut().find(|p| p.ID == patch.NodeID)
                                {
                                    apply_peer_change(existing, patch);
                                }
                            }
                        }
                    }

                    // Forward peer deltas to the IPN notify bus so
                    // watch-ipn-bus subscribers receive PeersChanged /
                    // PeersRemoved / NetMap. Mirrors Go's `ipnlocal.send`
                    // in the full-netmap and delta notify paths.
                    if !resp.PeersChanged.is_empty() || !resp.Peers.is_empty() {
                        let changed_nodes: Vec<serde_json::Value> = if resp.Peers.is_empty() {
                            resp.PeersChanged
                                .iter()
                                .filter_map(|p| serde_json::to_value(p).ok())
                                .collect()
                        } else {
                            resp.Peers
                                .iter()
                                .filter_map(|p| serde_json::to_value(p).ok())
                                .collect()
                        };
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
                        let peers_json: Vec<serde_json::Value> = resp
                            .Peers
                            .iter()
                            .filter_map(|p| serde_json::to_value(p).ok())
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

                    // Feed the updated peer list to magicsock + rebuild routes.
                    let peers = peers_arc.read().await.clone();
                    let _ = magicsock.set_netmap(peers.clone()).await;
                    let mut routes = route_table.write().await;
                    routes.rebuild_with_opts(&peers, accept_routes);
                    if let Some(router) = router.as_ref() {
                        if let Err(error) = sync_router(router, &tailscale_ips, &routes) {
                            eprintln!("tsnet: route update failed (non-fatal): {error}");
                        }
                    }
                    drop(routes);

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

                    // Create WG tunnels for new peers.
                    let mut tunnels = wg_tunnels.write().await;
                    for peer in &peers {
                        if peer.Key.is_zero() {
                            continue;
                        }
                        if !tunnels.contains_key(&peer.Key) {
                            if let Ok(t) = WgTunn::new(&node_key, &peer.Key, rand_index()) {
                                tunnels.insert(peer.Key.clone(), Arc::new(Mutex::new(t)));
                            }
                        }
                    }
                    drop(tunnels);

                    // Process PacketFilter / PacketFilters deltas and rebuild
                    // the filter if anything changed. The peer list supplies
                    // the capability map; the existing shields-up state is
                    // preserved across the rebuild (mirrors Go passing
                    // `oldFilter` to `filter.New`). A peer-set change also
                    // triggers a rebuild so `cap:<name>` source predicates
                    // see the latest peer `CapMap`s.
                    let filter_changed = process_filter_deltas(&resp, &mut named_filters);
                    if filter_changed || peers_changed {
                        let shields_up = filter_arc.lock().unwrap().shields_up();
                        let peers_snapshot = peers_arc.read().await.clone();
                        rebuild_filter(
                            &filter_arc,
                            &named_filters,
                            &tailscale_ips,
                            &advertise_routes,
                            &peers_snapshot,
                            shields_up,
                        );
                    }

                    // Save the updated netmap to disk (best-effort) so a
                    // restart can skip the blocking first fetch. Dedup via
                    // SHA-256 skips the write if the content is unchanged
                    // since the last successful save.
                    if let Some(ref cache) = netmap_cache {
                        if let Err(e) = cache.save_if_changed(&node_pub, &resp) {
                            eprintln!("tsnet: netmap cache save failed (non-fatal): {e}");
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

/// Re-register with the control server after a key expiry, using
/// `OldNodeKey` (public of the old key) and a fresh `NodeKey`.
///
/// Mirrors Go's `doLogin` with `regen=true` (`direct.go:739-926`):
/// 1. Save current key as `OldPrivateNodeKey`.
/// 2. Generate a fresh node key.
/// 3. Send `RegisterRequest` with `OldNodeKey` + `NodeKey`.
/// 4. If `resp.NodeKeyExpired`, retry with another fresh key (max 2).
/// 5. If `resp.AuthURL` is non-empty, send a followup and block until
///    interactive auth completes.
/// 6. On success, persist the new key, re-key magicsock, and clear WG
///    tunnels so they are recreated with the new key.
async fn perform_key_rotation(
    ctx: &KeyRotationCtx,
    current_key: &NodePrivate,
    magicsock: &Magicsock,
    wg_tunnels: &Arc<RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>>,
    state_dir: Option<&std::path::Path>,
    ipn_backend: &Arc<IpnBackend>,
) -> Result<NodePrivate, String> {
    let old_key = current_key.clone();
    let old_pub = old_key.public();

    let mut trying_key = NodePrivate::generate();
    let mut old_node_key = old_pub.clone();

    for attempt in 0..=2u32 {
        let new_pub = trying_key.public();

        let reg_req = RegisterRequest {
            Version: ctx.capability_version,
            NodeKey: new_pub.clone(),
            OldNodeKey: old_node_key.clone(),
            Auth: if ctx.auth_key.is_empty() {
                None
            } else {
                Some(rustscale_tailcfg::RegisterResponseAuth {
                    AuthKey: ctx.auth_key.clone(),
                })
            },
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
            eprintln!(
                "tsnet: key rotation attempt {attempt}: server says NodeKeyExpired, regenerating"
            );
            old_node_key = new_pub;
            trying_key = NodePrivate::generate();
            continue;
        }

        // If interactive auth is required, emit BrowseToURL and block on
        // the followup poll until the user completes auth.
        if !resp.AuthURL.is_empty() {
            eprintln!(
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
                eprintln!("tsnet: followup returned NodeKeyExpired, regenerating");
                old_node_key = new_pub;
                trying_key = NodePrivate::generate();
                continue;
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
                    eprintln!("tsnet: failed to save rotated key state: {e}");
                }
            }
        }

        // Re-key magicsock so disco/relay use the new identity.
        magicsock.set_node_key(&trying_key);

        // Clear all WG tunnels — they were created with the old private
        // key and must be recreated with the new one.
        wg_tunnels.write().await.clear();

        eprintln!(
            "tsnet: key rotation succeeded (old={}, new={})",
            old_pub,
            trying_key.public()
        );
        return Ok(trying_key);
    }

    Err("key rotation exhausted retries (max 2)".into())
}

/// Apply an incremental [`PeerChange`] patch to an existing [`Node`].
/// Only fields that are `Some` / non-default are applied; the rest are left
/// unchanged. Mirrors Go's `(*Node).ApplyPatch` in `tailcfg/tailcfg.go`.
fn apply_peer_change(node: &mut Node, patch: &PeerChange) {
    if patch.DERPRegion != 0 {
        node.HomeDERP = patch.DERPRegion;
    }
    if patch.Cap != 0 {
        node.Cap = patch.Cap;
    }
    if !patch.CapMap.is_empty() {
        node.CapMap = patch.CapMap.clone();
    }
    if !patch.Endpoints.is_empty() {
        node.Endpoints.clone_from(&patch.Endpoints);
    }
    if let Some(ref key) = patch.Key {
        node.Key = key.clone();
    }
    if let Some(ref sig) = patch.KeySignature {
        node.KeySignature = Some(sig.clone());
    }
    if let Some(ref disco) = patch.DiscoKey {
        node.DiscoKey = disco.clone();
    }
    if let Some(online) = patch.Online {
        node.Online = Some(online);
    }
    if let Some(last_seen) = patch.LastSeen {
        node.LastSeen = Some(last_seen);
    }
    if let Some(key_expiry) = patch.KeyExpiry {
        node.KeyExpiry = Some(key_expiry);
    }
}

/// Send a Notify with the current health warnings so frontend consumers
/// can surface health state changes. Mirrors Go's `LocalBackend.sendHealthNotify`.
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
    fn peer_change_patch_derp_and_online() {
        let mut peer = sample_peer();
        let patch = PeerChange {
            NodeID: 10,
            DERPRegion: 7,
            Online: Some(false),
            ..Default::default()
        };
        apply_peer_change(&mut peer, &patch);
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
        apply_peer_change(&mut peer, &patch);
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
        apply_peer_change(&mut peer, &patch);
        assert_eq!(peer.LastSeen, Some(ts));
        assert_eq!(peer.KeyExpiry, Some(ts));
    }

    #[test]
    fn peer_change_patch_unknown_node_is_noop() {
        let mut peer = sample_peer();
        let original = peer.clone();
        // Patch for a different NodeID — should not be applied by the caller,
        // but apply_peer_change itself doesn't check NodeID.
        let patch = PeerChange {
            NodeID: 999,
            DERPRegion: 42,
            ..Default::default()
        };
        // In the map_update task, the caller checks NodeID before calling
        // apply_peer_change. Here we just verify the helper is correct.
        apply_peer_change(&mut peer, &patch);
        assert_eq!(peer.HomeDERP, 42);
        // Verify the original is different
        assert_ne!(peer.HomeDERP, original.HomeDERP);
    }
}
