#[allow(clippy::wildcard_imports)]
use super::*;

/// Spawn the map-stream delta update task. Shared by `up()` and `up_tun()`:
/// processes Peers/PeersChanged/PeersRemoved, feeds the new peer list to
/// magicsock, rebuilds the route table, and creates WG tunnels for new peers.
pub(crate) fn spawn_map_update_task(
    mut map_rx: mpsc::Receiver<Result<MapResponse, StreamMapError>>,
    magicsock: Arc<Magicsock>,
    wg_tunnels: Arc<RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>>,
    peers_arc: Arc<RwLock<Vec<Node>>>,
    route_table: Arc<RwLock<RouteTable>>,
    node_key: NodePrivate,
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
    node_pub: NodePublic,
    control_knobs: Arc<ControlKnobs>,
    key_expired: Arc<std::sync::atomic::AtomicBool>,
    ipn_backend: Arc<IpnBackend>,
) -> JoinHandle<()> {
    let mut named_filters: BTreeMap<String, Vec<FilterRule>> = BTreeMap::new();
    // Create the netmap cache helper once so that save_if_changed can
    // dedup identical writes via the in-memory SHA-256 hash.
    let netmap_cache = state_dir.as_ref().map(|dir| NetMapCache::new(dir));
    tokio::spawn(async move {
        loop {
            if cancel.is_cancelled() {
                break;
            }
            match map_rx.recv().await {
                Some(Ok(resp)) => {
                    // Map activity: feed the staleness watchdog + mark control
                    // healthy. Even keep-alive messages count as activity.
                    health_watchdog.feed();
                    health.set_healthy(WARN_CONTROL);

                    if resp.KeepAlive {
                        continue;
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
                        // TODO(key-rotation): When the node key expires, the
                        // client should re-register with OldNodeKey set to the
                        // previous key, generate a fresh node key, and send a
                        // new RegisterRequest. If interactive auth is required,
                        // emit BrowseToURL via ipn_backend. After successful
                        // re-registration, restart the map poll with the new
                        // key and transition back to Running.
                        //
                        // Go ref: control/controlclient/direct.go doLogin with
                        // OldNodeKey, ipn/ipnlocal/local.go key-expiry handling.
                        // The RegisterRequest struct already has OldNodeKey;
                        // the bootstrap() flow would need refactoring to support
                        // re-registration without tearing down the whole stack.
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

                    // Merge peer deltas. Track whether the peer set changed
                    // so the filter's capability map can be refreshed.
                    let peers_changed = !resp.Peers.is_empty()
                        || !resp.PeersChanged.is_empty()
                        || !resp.PeersRemoved.is_empty();
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
                    route_table
                        .write()
                        .await
                        .rebuild_with_opts(&peers, accept_routes);

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
                    break;
                }
                None => {
                    health.set_unhealthy(WARN_CONTROL, "control connection lost: stream closed");
                    break;
                }
            }
        }
    })
}
