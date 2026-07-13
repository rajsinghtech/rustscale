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
    let mut inbound = InboundBatchScratch::default();

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
                    inbound.clear();
                    take_immediate_burst(dgram, &mut wg_recv, &mut inbound.datagrams);
                    collect_tun_inbound_batch(
                        &wg_tunnels,
                        &filter,
                        &packet_drops,
                        &capture,
                        &mut inbound,
                    )
                    .await;
                    // Datagrams are ciphertext ownership; release their
                    // nested buffers before reply I/O or a blocked TUN write.
                    inbound.datagrams.clear();
                    let reply_socket = magicsock.clone();
                    flush_inbound_burst(tun.as_ref(), &mut inbound, move |peer, reply| {
                        let magicsock = reply_socket.clone();
                        async move {
                            let _ = magicsock.send(peer, &reply).await;
                        }
                    })
                    .await;
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

/// Take the triggering datagram plus at most 127 immediately-ready entries.
fn take_immediate_burst<T>(first: T, receiver: &mut mpsc::Receiver<T>, output: &mut Vec<T>) {
    output.push(first);
    while output.len() < rustscale_tun::TunPacketBatch::MAX_PACKETS {
        let Ok(next) = receiver.try_recv() else { break };
        output.push(next);
    }
}

/// Send replies before the one batch write. Draining drops completed reply
/// buffers; `Vec::clear` only retains the outer allocation and must not be
/// mistaken for retaining boringtun plaintext allocations.
async fn flush_inbound_burst<F, Fut>(
    tun: &dyn Tun,
    inbound: &mut InboundBatchScratch,
    mut send_reply: F,
) where
    F: FnMut(NodePublic, Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    for (peer, reply) in inbound.replies.drain(..) {
        send_reply(peer, reply).await;
    }
    if !inbound.plaintext.is_empty() {
        if let Err(error) = tun.write_batch(&mut inbound.plaintext).await {
            log::warn!("tun batch write error: {error}");
        }
        // Retain only the outer Vec allocation while idle; plaintext buffers
        // are consume-on-write and must not remain resident after return.
        inbound.plaintext.clear();
    }
}

/// Reused outer storage for one bounded inbound WireGuard burst. Clearing it
/// does not retain the individual decrypted plaintext buffers.
#[derive(Default)]
struct InboundBatchScratch {
    datagrams: Vec<rustscale_magicsock::WgDatagram>,
    runs: Vec<InboundBatchRun>,
    decaps: Vec<rustscale_wg::DecapResult>,
    plaintext: Vec<Vec<u8>>,
    replies: Vec<(NodePublic, Vec<u8>)>,
}

impl InboundBatchScratch {
    fn clear(&mut self) {
        self.datagrams.clear();
        self.runs.clear();
        self.decaps.clear();
        self.plaintext.clear();
        self.replies.clear();
    }
}

struct InboundRun {
    peer: NodePublic,
    tunnel: Arc<Mutex<WgTunn>>,
    start: usize,
    end: usize,
}

enum InboundBatchRun {
    Drop { start: usize, end: usize },
    Routed(InboundRun),
}

/// Build maximal contiguous same-peer receive runs using a single tunnel-map
/// snapshot. A missing map entry remains an explicit drop boundary, so later
/// packets for the same peer are never merged across it.
fn build_inbound_runs(
    datagrams: &[rustscale_magicsock::WgDatagram],
    tunnels: &HashMap<NodePublic, Arc<Mutex<WgTunn>>>,
    runs: &mut Vec<InboundBatchRun>,
) {
    runs.clear();
    let mut start = 0;
    while start < datagrams.len() {
        let peer = datagrams[start].peer.clone();
        let mut end = start + 1;
        while end < datagrams.len() && datagrams[end].peer == peer {
            end += 1;
        }
        if let Some(tunnel) = tunnels.get(&peer).cloned() {
            runs.push(InboundBatchRun::Routed(InboundRun {
                peer,
                tunnel,
                start,
                end,
            }));
        } else {
            runs.push(InboundBatchRun::Drop { start, end });
        }
        start = end;
    }
}

/// Decapsulate a capped immediate receive burst in peer runs. Map and tunnel
/// locks are released before the filter, capture, reply transport, or TUN I/O
/// stages; only synchronous boringtun work occurs while a tunnel is locked.
async fn collect_tun_inbound_batch(
    wg_tunnels: &RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>,
    filter: &Arc<std::sync::Mutex<Filter>>,
    packet_drops: &Arc<AtomicU64>,
    capture: &crate::capture::CaptureSlot,
    inbound: &mut InboundBatchScratch,
) {
    let tunnels = wg_tunnels.read().await;
    build_inbound_runs(&inbound.datagrams, &tunnels, &mut inbound.runs);
    drop(tunnels);

    for run in inbound.runs.drain(..) {
        let run = match run {
            InboundBatchRun::Drop { start, end } => {
                debug_assert!(start < end && end <= inbound.datagrams.len());
                continue;
            }
            InboundBatchRun::Routed(run) => run,
        };
        inbound.decaps.clear();
        {
            let mut tunnel = run.tunnel.lock().await;
            for datagram in &inbound.datagrams[run.start..run.end] {
                if let Ok(decap) = tunnel.decapsulate(&datagram.data) {
                    inbound.decaps.push(decap);
                }
            }
        }
        for decap in inbound.decaps.drain(..) {
            enqueue_tun_inbound_result(
                filter,
                packet_drops,
                &run.peer,
                decap,
                capture,
                &mut inbound.plaintext,
                &mut inbound.replies,
            );
        }
    }
}

fn enqueue_tun_inbound_result(
    filter: &Arc<std::sync::Mutex<Filter>>,
    packet_drops: &Arc<AtomicU64>,
    peer: &NodePublic,
    decap: rustscale_wg::DecapResult,
    capture: &crate::capture::CaptureSlot,
    plaintext: &mut Vec<Vec<u8>>,
    replies: &mut Vec<(NodePublic, Vec<u8>)>,
) {
    if let Some(pt) = decap.plaintext {
        let dropped = {
            let mut filt = filter.lock().unwrap();
            filt.check_in(&pt).is_drop()
        };
        if dropped {
            packet_drops.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            // Capture before Linux write-side GRO is allowed to rewrite the
            // packet's offload and transport headers.
            crate::capture::log_packet(capture, crate::capture::CapturePath::FromPeer, &pt);
            plaintext.push(pt);
        }
    }
    replies.extend(decap.replies.into_iter().map(|reply| (peer.clone(), reply)));
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

    struct BatchProbe {
        events: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>,
    }

    struct PendingProbe {
        replies_seen: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        polled: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<usize>>>,
    }

    #[async_trait::async_trait]
    impl Tun for PendingProbe {
        async fn read_batch(
            &self,
            _batch: &mut rustscale_tun::TunPacketBatch,
        ) -> std::io::Result<()> {
            unreachable!("write-only TUN probe")
        }
        async fn write_packet(&self, _packet: &[u8]) -> std::io::Result<()> {
            unreachable!("write_batch must be used")
        }
        async fn write_batch(&self, _packets: &mut [Vec<u8>]) -> std::io::Result<()> {
            if let Some(polled) = self.polled.lock().unwrap().take() {
                let _ = polled.send(self.replies_seen.load(std::sync::atomic::Ordering::SeqCst));
            }
            std::future::pending().await
        }
        fn name(&self) -> &'static str {
            "pending-probe"
        }
        fn mtu(&self) -> usize {
            1280
        }
    }

    #[async_trait::async_trait]
    impl Tun for BatchProbe {
        async fn read_batch(
            &self,
            _batch: &mut rustscale_tun::TunPacketBatch,
        ) -> std::io::Result<()> {
            unreachable!("write-only TUN probe")
        }

        async fn write_packet(&self, _packet: &[u8]) -> std::io::Result<()> {
            unreachable!("write_batch must be used")
        }

        async fn write_batch(&self, packets: &mut [Vec<u8>]) -> std::io::Result<()> {
            assert_eq!(packets.len(), 2);
            self.events.lock().unwrap().push("write");
            Err(std::io::Error::other("intentional write failure"))
        }

        fn name(&self) -> &'static str {
            "batch-probe"
        }

        fn mtu(&self) -> usize {
            1280
        }
    }

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

    fn inbound_shapes(runs: &[InboundBatchRun]) -> Vec<(Option<NodePublic>, usize, usize)> {
        runs.iter()
            .map(|run| match run {
                InboundBatchRun::Drop { start, end } => (None, *start, *end),
                InboundBatchRun::Routed(run) => (Some(run.peer.clone()), run.start, run.end),
            })
            .collect()
    }

    async fn establish_tunnels(a: &Arc<Mutex<WgTunn>>, b: &Arc<Mutex<WgTunn>>) {
        let a_init = { a.lock().await.force_handshake() };
        for packet in &a_init {
            let replies = { b.lock().await.decapsulate(packet).unwrap().replies };
            for reply in &replies {
                let _ = a.lock().await.decapsulate(reply);
            }
        }
        let b_init = { b.lock().await.force_handshake() };
        for packet in &b_init {
            let replies = { a.lock().await.decapsulate(packet).unwrap().replies };
            for reply in &replies {
                let _ = b.lock().await.decapsulate(reply);
            }
        }
        for _ in 0..4 {
            for (source, destination) in [(a, b), (b, a)] {
                let pending = { source.lock().await.tick_timers() };
                for packet in pending {
                    let replies = {
                        destination
                            .lock()
                            .await
                            .decapsulate(&packet)
                            .unwrap()
                            .replies
                    };
                    for reply in replies {
                        let _ = source.lock().await.decapsulate(&reply);
                    }
                }
            }
        }
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

    #[test]
    fn build_inbound_runs_keeps_peer_and_missing_boundaries() {
        let a = NodePrivate::generate().public();
        let b = NodePrivate::generate().public();
        let missing = NodePrivate::generate().public();
        let mut tunnels = HashMap::new();
        tunnels.insert(a.clone(), tunnel_for(&a));
        tunnels.insert(b.clone(), tunnel_for(&b));
        let datagrams = [
            a.clone(),
            a.clone(),
            b.clone(),
            a.clone(),
            missing,
            a.clone(),
        ]
        .into_iter()
        .enumerate()
        .map(|(index, peer)| rustscale_magicsock::WgDatagram {
            peer,
            data: vec![index as u8],
        })
        .collect::<Vec<_>>();
        let mut runs = Vec::new();
        build_inbound_runs(&datagrams, &tunnels, &mut runs);
        assert_eq!(
            inbound_shapes(&runs),
            vec![
                (Some(a.clone()), 0, 2),
                (Some(b), 2, 3),
                (Some(a.clone()), 3, 4),
                (None, 4, 5),
                (Some(a), 5, 6),
            ]
        );
    }

    #[tokio::test]
    async fn inbound_batch_matches_scalar_plaintext_order_then_releases_lock() {
        let a_private = NodePrivate::generate();
        let b_private = NodePrivate::generate();
        let a_public = a_private.public();
        let b_public = b_private.public();
        let sender = Arc::new(Mutex::new(
            WgTunn::new(&a_private, &b_public, 1).expect("source tunnel"),
        ));
        let receiver = Arc::new(Mutex::new(
            WgTunn::new(&b_private, &a_public, 2).expect("receiver tunnel"),
        ));
        establish_tunnels(&sender, &receiver).await;

        let packets = vec![
            vec![
                0x45, 0, 0, 20, 0, 1, 0, 0, 64, 17, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2,
            ],
            vec![
                0x45, 0, 0, 20, 0, 2, 0, 0, 64, 17, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2,
            ],
        ];
        let mut inbound = InboundBatchScratch::default();
        for packet in &packets {
            let ciphertext = sender
                .lock()
                .await
                .encapsulate(packet)
                .expect("encrypt packet")
                .into_iter()
                .next()
                .expect("one wireguard data packet");
            inbound.datagrams.push(rustscale_magicsock::WgDatagram {
                peer: a_public.clone(),
                data: ciphertext,
            });
        }
        let tunnels = RwLock::new(HashMap::from([(a_public, receiver.clone())]));
        let filter = Arc::new(std::sync::Mutex::new(Filter::allow_all()));
        let packet_drops = Arc::new(AtomicU64::new(0));
        let capture = crate::capture::new_slot();

        collect_tun_inbound_batch(&tunnels, &filter, &packet_drops, &capture, &mut inbound).await;

        assert_eq!(inbound.plaintext, packets);
        assert!(inbound.replies.is_empty());
        assert_eq!(packet_drops.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert!(
            receiver.try_lock().is_ok(),
            "filtering and flush are lock-free"
        );
    }

    #[tokio::test]
    async fn inbound_batch_filter_drops_are_counted() {
        let a_private = NodePrivate::generate();
        let b_private = NodePrivate::generate();
        let a_public = a_private.public();
        let b_public = b_private.public();
        let sender = Arc::new(Mutex::new(
            WgTunn::new(&a_private, &b_public, 1).expect("source tunnel"),
        ));
        let receiver = Arc::new(Mutex::new(
            WgTunn::new(&b_private, &a_public, 2).expect("receiver tunnel"),
        ));
        establish_tunnels(&sender, &receiver).await;

        let packets = [
            vec![
                0x45, 0, 0, 20, 0, 1, 0, 0, 64, 17, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2,
            ],
            vec![
                0x45, 0, 0, 20, 0, 2, 0, 0, 64, 17, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2,
            ],
        ];
        let mut inbound = InboundBatchScratch::default();
        for packet in packets {
            inbound.datagrams.push(rustscale_magicsock::WgDatagram {
                peer: a_public.clone(),
                data: sender
                    .lock()
                    .await
                    .encapsulate(&packet)
                    .expect("encrypt packet")
                    .into_iter()
                    .next()
                    .expect("one wireguard data packet"),
            });
        }

        let tunnels = RwLock::new(HashMap::from([(a_public, receiver)]));
        let filter = Arc::new(std::sync::Mutex::new(Filter::allow_none()));
        let packet_drops = Arc::new(AtomicU64::new(0));
        let capture = crate::capture::new_slot();
        collect_tun_inbound_batch(&tunnels, &filter, &packet_drops, &capture, &mut inbound).await;

        assert!(
            inbound.plaintext.is_empty(),
            "dropped packets are not queued"
        );
        assert_eq!(packet_drops.load(std::sync::atomic::Ordering::Relaxed), 2);
    }

    #[test]
    fn immediate_burst_is_capped_at_tun_batch_capacity() {
        let (tx, mut rx) = mpsc::channel(256);
        for value in 1_u16..=130 {
            tx.try_send(value).unwrap();
        }
        let mut burst = Vec::new();
        take_immediate_burst(0, &mut rx, &mut burst);
        assert_eq!(burst.len(), rustscale_tun::TunPacketBatch::MAX_PACKETS);
        assert_eq!(burst[0], 0);
        assert_eq!(burst.last(), Some(&127));
        assert_eq!(rx.try_recv().unwrap(), 128);
    }

    #[tokio::test]
    async fn replies_complete_before_one_failed_batch_write() {
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let tun = BatchProbe {
            events: events.clone(),
        };
        let peer = NodePrivate::generate().public();
        let mut inbound = InboundBatchScratch {
            datagrams: Vec::new(),
            plaintext: vec![vec![1], vec![2]],
            replies: vec![(peer.clone(), vec![3]), (peer, vec![4])],
            ..Default::default()
        };
        let reply_events = events.clone();
        flush_inbound_burst(&tun, &mut inbound, move |_peer, _reply| {
            let events = reply_events.clone();
            async move { events.lock().unwrap().push("reply") }
        })
        .await;
        assert_eq!(*events.lock().unwrap(), vec!["reply", "reply", "write"]);
        assert!(inbound.replies.is_empty());
        assert!(inbound.plaintext.is_empty());
    }

    #[tokio::test]
    async fn replies_finish_before_a_pending_batch_write_is_polled() {
        let seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (polled_tx, polled_rx) = tokio::sync::oneshot::channel();
        let tun = PendingProbe {
            replies_seen: seen.clone(),
            polled: std::sync::Mutex::new(Some(polled_tx)),
        };
        let peer = NodePrivate::generate().public();
        let mut inbound = InboundBatchScratch {
            datagrams: Vec::new(),
            plaintext: vec![vec![1]],
            replies: vec![(peer.clone(), vec![2]), (peer, vec![3])],
            ..Default::default()
        };
        let task = tokio::spawn(async move {
            flush_inbound_burst(&tun, &mut inbound, move |_peer, _reply| {
                let seen = seen.clone();
                async move {
                    seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            })
            .await;
        });
        let replies_at_write =
            tokio::time::timeout(std::time::Duration::from_millis(100), polled_rx)
                .await
                .expect("write_batch was polled")
                .unwrap();
        assert_eq!(replies_at_write, 2);
        task.abort();
    }
}
