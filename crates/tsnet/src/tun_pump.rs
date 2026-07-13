#[allow(clippy::wildcard_imports)]
use super::*;

/// TUN data-plane pump: TUN device <-> WG <-> magicsock.
///
/// Inbound (from network): magicsock recv -> WG decapsulate -> TUN write.
/// Outbound (from OS): TUN read -> route lookup -> WG encapsulate -> magicsock send.
/// WG timer ticks run on a 250ms interval.
pub(crate) async fn run_tun_pump(
    magicsock: Arc<Magicsock>,
    mut wg_recv: mpsc::Receiver<rustscale_magicsock::WgDatagram>,
    tun: Arc<dyn Tun>,
    wg_tunnels: Arc<RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>>,
    route_table: Arc<RwLock<RouteTable>>,
    filter: Arc<std::sync::Mutex<Filter>>,
    packet_drops: Arc<AtomicU64>,
    cancel: Arc<CancelToken>,
    capture: crate::capture::CaptureSlot,
) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_millis(250));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut batch = rustscale_tun::TunPacketBatch::new();
    let mut outbound = OutboundBatchScratch::default();

    loop {
        if cancel.is_cancelled() {
            break;
        }

        tokio::select! {
            // TUN read -> route -> WG encapsulate -> magicsock send.
            result = tun.read_batch(&mut batch) => {
                match result {
                    Ok(()) => {
                        send_tun_batch(
                            &magicsock, &wg_tunnels, &route_table, &filter,
                            batch.packets(), &mut outbound, &capture,
                        ).await;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => {
                        log::warn!("tun read error: {e}");
                        break;
                    }
                }
            }
            // magicsock recv -> WG decapsulate -> filter -> TUN write.
            result = wg_recv.recv() => {
                if let Some(dgram) = result {
                    process_tun_inbound(
                        &magicsock, &wg_tunnels, &filter, &packet_drops, &tun, &dgram, &capture,
                    ).await;

                    // Drain any additional immediately-available datagrams
                    // to batch a burst of packets into a single scheduler turn.
                    while let Ok(more) = wg_recv.try_recv() {
                        process_tun_inbound(
                            &magicsock, &wg_tunnels, &filter, &packet_drops, &tun, &more, &capture,
                        ).await;
                    }
                } else {
                    log::warn!("tsnet: magicsock wg channel closed (tun)");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
            _ = ticker.tick() => {
                tick_wg_timers(&magicsock, &wg_tunnels).await;
            }
        }
    }
}

/// Reused state for one outbound kernel-TUN read.
#[derive(Default)]
struct OutboundBatchScratch {
    routes: Vec<Option<NodePublic>>,
    runs: Vec<BatchRun>,
    datagrams: rustscale_wg::WgDatagramBatch,
}

struct OutboundRun {
    peer: NodePublic,
    tunnel: Arc<Mutex<WgTunn>>,
    start: usize,
    end: usize,
}

enum BatchRun {
    Skip { start: usize, end: usize },
    Routed(OutboundRun),
}

/// Build maximal contiguous route runs from one tunnels-map snapshot.
fn build_batch_runs(
    routes: &[Option<NodePublic>],
    tunnels: &HashMap<NodePublic, Arc<Mutex<WgTunn>>>,
    runs: &mut Vec<BatchRun>,
) {
    runs.clear();
    let mut start = 0;
    while start < routes.len() {
        let route = routes[start].clone();
        let mut end = start + 1;
        while end < routes.len() && routes[end] == route {
            end += 1;
        }
        match route.and_then(|peer| tunnels.get(&peer).cloned().map(|tunnel| (peer, tunnel))) {
            Some((peer, tunnel)) => runs.push(BatchRun::Routed(OutboundRun {
                peer,
                tunnel,
                start,
                end,
            })),
            None => runs.push(BatchRun::Skip { start, end }),
        }
        start = end;
    }
}

/// Filter, route, and send one ordered TUN read as contiguous peer runs.
async fn send_tun_batch(
    magicsock: &Magicsock,
    wg_tunnels: &RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>,
    route_table: &RwLock<RouteTable>,
    filter: &std::sync::Mutex<Filter>,
    packets: &[Vec<u8>],
    scratch: &mut OutboundBatchScratch,
    capture: &crate::capture::CaptureSlot,
) {
    scratch.routes.clear();
    scratch.runs.clear();
    scratch.datagrams.clear();

    // Keep filtering and route lookup in input order under one acquisition of
    // each guard. Invalid packets deliberately get filtered before routing.
    {
        let routes = route_table.read().await;
        let mut filt = filter.lock().unwrap();
        for packet in packets {
            filt.update_outbound(packet);
            crate::capture::log_packet(capture, crate::capture::CapturePath::FromLocal, packet);
            scratch
                .routes
                .push(WgTunn::dst_address(packet).and_then(|dst| routes.lookup(dst)));
        }
    }

    // Form maximal equal-route runs using a single map snapshot. `None` and a
    // missing tunnel are boundaries, so they cannot merge routed runs.
    let tunnels = wg_tunnels.read().await;
    build_batch_runs(&scratch.routes, &tunnels, &mut scratch.runs);
    drop(tunnels);

    for run in scratch.runs.drain(..) {
        let run = match run {
            BatchRun::Skip { start, end } => {
                debug_assert!(start <= end && end <= packets.len());
                continue;
            }
            BatchRun::Routed(run) => run,
        };
        scratch.datagrams.clear();
        {
            let mut tunnel = run.tunnel.lock().await;
            for packet in &packets[run.start..run.end] {
                let _ = tunnel.encapsulate_into(packet, &mut scratch.datagrams);
            }
        }
        let _ = magicsock
            .send_batch(run.peer.clone(), scratch.datagrams.packets())
            .await;
    }
}

/// Lazily filter the packets from one TUN read in read order.
///
/// The filter is applied once, immediately before each packet is dispatched.
#[cfg(test)]
pub(crate) fn filtered_outbound_packets<'a>(
    packets: &'a [Vec<u8>],
    filter: &'a std::sync::Mutex<Filter>,
) -> impl Iterator<Item = &'a [u8]> + 'a {
    packets.iter().map(Vec::as_slice).inspect(move |packet| {
        let mut filt = filter.lock().unwrap();
        filt.update_outbound(packet);
    })
}

/// A router shared by the TUN lifecycle, API calls, and map-update task.
pub(crate) type SharedRouter = Arc<std::sync::Mutex<Box<dyn rustscale_router::Router>>>;

/// Build the one OS-level routing configuration from current TUN state.
pub(crate) fn build_router_config(
    local_addrs: &[IpAddr],
    route_table: &RouteTable,
) -> rustscale_router::RouterConfig {
    let mut routes = vec![rustscale_tsaddr::cgnat_range()];
    for (net, bits, _) in route_table.entries() {
        // Exit-node defaults are controlled solely by `exit_node`; accepting
        // an exit-capable peer's advertised /0 must not enable it implicitly.
        if bits != 0 && !rustscale_tsaddr::is_tailscale_ip(net) {
            routes.push(rustscale_tsaddr::IpPrefix { ip: net, bits });
        }
    }
    rustscale_router::RouterConfig {
        local_addrs: local_addrs.to_vec(),
        routes,
        local_routes: vec![],
        exit_node: route_table.exit_node().is_some(),
    }
}

/// Synchronize a shared router after a route-table change.
pub(crate) fn sync_router(
    router: &SharedRouter,
    local_addrs: &[IpAddr],
    route_table: &RouteTable,
) -> Result<(), TsnetError> {
    let config = build_router_config(local_addrs, route_table);
    router
        .lock()
        .map_err(|_| TsnetError::Builder("router lock poisoned".into()))?
        .set(&config)
        .map_err(|error| TsnetError::Builder(format!("route configuration failed: {error}")))
}

/// Create a TUN device and optionally apply OS routes.
/// On macOS/Linux this creates the real device and installs routes when
/// `config.apply_routes` is true. On other platforms it returns an error.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) async fn create_tun_device(
    config: &TunModeConfig,
    b: &Bootstrap,
    _accept_routes: bool,
) -> Result<(Arc<dyn Tun>, Option<SharedRouter>), TsnetError> {
    let dev = rustscale_tun::create(&config.tun)?;
    let router = if config.apply_routes {
        let mut router = rustscale_router::new(dev.name());
        router
            .up()
            .map_err(|error| TsnetError::Builder(format!("bring TUN interface up: {error}")))?;
        let route_config = {
            let route_table = b.route_table.read().await;
            build_router_config(&b.tailscale_ips, &route_table)
        };
        if let Err(error) = router.set(&route_config) {
            let _ = router.close();
            return Err(TsnetError::Builder(format!("install TUN routes: {error}")));
        }
        Some(Arc::new(std::sync::Mutex::new(router)))
    } else {
        None
    };
    Ok((Arc::new(dev), router))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
#[allow(clippy::unused_async)]
pub(crate) async fn create_tun_device(
    _config: &TunModeConfig,
    _b: &Bootstrap,
    _accept_routes: bool,
) -> Result<(Arc<dyn Tun>, Option<SharedRouter>), TsnetError> {
    Err(TsnetError::Builder(
        "TUN mode not supported on this platform".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustscale_key::NodePrivate;

    fn tunnel_for(peer: &NodePublic) -> Arc<Mutex<WgTunn>> {
        Arc::new(Mutex::new(
            WgTunn::new(&NodePrivate::generate(), peer, 1).expect("tunnel"),
        ))
    }

    fn shapes(runs: &[BatchRun]) -> Vec<(Option<NodePublic>, usize, usize)> {
        runs.iter()
            .map(|run| match run {
                BatchRun::Skip { start, end } => (None, *start, *end),
                BatchRun::Routed(run) => (Some(run.peer.clone()), run.start, run.end),
            })
            .collect()
    }

    #[test]
    fn build_batch_runs_preserves_contiguous_route_boundaries() {
        let a = NodePrivate::generate().public();
        let b = NodePrivate::generate().public();
        let mut tunnels = HashMap::new();
        tunnels.insert(a.clone(), tunnel_for(&a));
        tunnels.insert(b.clone(), tunnel_for(&b));
        let mut runs = Vec::new();

        build_batch_runs(&[], &tunnels, &mut runs);
        assert!(runs.is_empty());

        build_batch_runs(&[Some(a.clone())], &tunnels, &mut runs);
        assert_eq!(shapes(&runs), vec![(Some(a.clone()), 0, 1)]);

        build_batch_runs(
            &[Some(a.clone()), Some(a.clone()), Some(a.clone())],
            &tunnels,
            &mut runs,
        );
        assert_eq!(shapes(&runs), vec![(Some(a.clone()), 0, 3)]);

        build_batch_runs(
            &[Some(a.clone()), Some(b.clone()), Some(a.clone())],
            &tunnels,
            &mut runs,
        );
        assert_eq!(
            shapes(&runs),
            vec![
                (Some(a.clone()), 0, 1),
                (Some(b.clone()), 1, 2),
                (Some(a.clone()), 2, 3)
            ]
        );

        build_batch_runs(
            &[Some(a.clone()), None, Some(a.clone())],
            &tunnels,
            &mut runs,
        );
        assert_eq!(
            shapes(&runs),
            vec![
                (Some(a.clone()), 0, 1),
                (None, 1, 2),
                (Some(a.clone()), 2, 3)
            ]
        );
    }

    #[test]
    fn build_batch_runs_keeps_missing_tunnel_as_a_boundary() {
        let a = NodePrivate::generate().public();
        let missing = NodePrivate::generate().public();
        let mut tunnels = HashMap::new();
        tunnels.insert(a.clone(), tunnel_for(&a));
        let mut runs = Vec::new();
        build_batch_runs(
            &[Some(a.clone()), Some(missing.clone()), Some(a.clone())],
            &tunnels,
            &mut runs,
        );
        assert_eq!(
            shapes(&runs),
            vec![(Some(a.clone()), 0, 1), (None, 1, 2), (Some(a), 2, 3)]
        );
    }
}
