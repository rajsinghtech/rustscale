#[allow(clippy::wildcard_imports)]
use super::*;
use crate::routing::resolve_control_server_ips;

fn tun_outbound_send_pipeline_enabled() -> bool {
    tun_outbound_send_pipeline_enabled_for(
        std::env::var_os("RUSTSCALE_TUN_OUTBOUND_SEND_PIPELINE").is_some(),
    )
}

fn tun_outbound_send_pipeline_enabled_for(env_present: bool) -> bool {
    cfg!(target_os = "linux") && env_present
}

/// TUN data-plane pump: TUN device <-> WG <-> magicsock.
///
/// Inbound (from network): magicsock recv -> WG decapsulate -> TUN write.
/// Outbound (from OS): TUN read -> route lookup -> WG encapsulate -> magicsock send.
/// WG timer ticks run on a 250ms interval.
pub(crate) async fn run_tun_pump(
    magicsock: Arc<Magicsock>,
    mut wg_recv: mpsc::Receiver<rustscale_magicsock::WgReceiveBatch>,
    tun: Arc<dyn Tun>,
    wg_tunnels: Arc<RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>>,
    route_table: Arc<RwLock<RouteTable>>,
    filter: Arc<std::sync::Mutex<Filter>>,
    packet_drops: Arc<AtomicU64>,
    cancel: Arc<CancelToken>,
    capture: crate::capture::CaptureSlot,
    peer_map: Arc<crate::peer_map::Runtime>,
) {
    // Read once so a running pump cannot change scheduling or buffer
    // ownership mid-flight.  Presence is deliberately the opt-in contract.
    let outbound_send_pipeline = tun_outbound_send_pipeline_enabled();
    // This is deliberately read once.  The scalar scheduler below is kept
    // byte-for-byte independent while the spike is opt-in.
    if std::env::var_os("RUSTSCALE_TUN_INBOUND_PIPELINE").is_some() {
        run_tun_pump_pipeline(
            magicsock,
            wg_recv,
            tun,
            wg_tunnels,
            route_table,
            filter,
            packet_drops,
            cancel,
            capture,
            peer_map,
            outbound_send_pipeline,
        )
        .await;
        return;
    }
    let mut ticker = tokio::time::interval(std::time::Duration::from_millis(250));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut batch = rustscale_tun::TunPacketBatch::new();
    let mut outbound = OutboundBatchScratch::default();
    let mut outbound_sender = outbound_send_pipeline
        .then(|| OutboundSendPipeline::start(magicsock.clone(), cancel.clone()));
    let mut inbound = InboundBatchScratch::default();
    // A whole receive item that did not fit after a smaller item. Keeping it
    // here instead of splitting it preserves both batch ordering and the
    // packet-credit permit until its next turn.
    let mut deferred_wg_batch = None;

    loop {
        if cancel.is_cancelled() {
            break;
        }

        // Process a whole batch deferred by the previous opportunistic drain
        // before accepting later channel items. This is the only way a batch
        // can be kept out of the current TUN write, so it cannot be overtaken.
        if let Some(first) = deferred_wg_batch.take() {
            inbound.clear();
            deferred_wg_batch =
                take_immediate_receive_batches(first, &mut wg_recv, &mut inbound.datagrams);
            if !process_tun_inbound_batch(
                &magicsock,
                tun.as_ref(),
                &wg_tunnels,
                &filter,
                &packet_drops,
                &capture,
                &cancel,
                &peer_map,
                &mut inbound,
                outbound_sender.as_mut(),
            )
            .await
            {
                break;
            }
            continue;
        }

        tokio::select! {
            // TUN read -> route -> WG encapsulate -> magicsock send.
            result = tun.read_batch(&mut batch) => {
                match result {
                    Ok(()) => {
                        send_tun_batch_maybe_pipelined(
                            &magicsock, &wg_tunnels, &route_table, &filter,
                            batch.packets(), &mut outbound, &capture, &peer_map, outbound_sender.as_mut(),
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
                if let Some(first) = result {
                    inbound.clear();
                    deferred_wg_batch = take_immediate_receive_batches(
                        first,
                        &mut wg_recv,
                        &mut inbound.datagrams,
                    );
                    if !process_tun_inbound_batch(
                        &magicsock,
                        tun.as_ref(),
                        &wg_tunnels,
                        &filter,
                        &packet_drops,
                        &capture,
                        &cancel,
                        &peer_map,
                        &mut inbound,
                        outbound_sender.as_mut(),
                    )
                    .await {
                        break;
                    }
                } else {
                    log::warn!("tsnet: magicsock wg channel closed (tun)");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
            _ = ticker.tick() => {
                if !flush_outbound_before_competing_send(outbound_sender.as_mut()).await {
                    break;
                }
                let _map = peer_map.gate.read().await;
                tick_wg_timers(&magicsock, &wg_tunnels).await;
            }
        }
    }
    if let Some(sender) = outbound_sender {
        sender.shutdown().await;
    }
}

/// Move one received item and every immediately-ready whole item that fits
/// into the TUN's 128-packet write. A too-large next item is returned without
/// consuming it, so no batch is split or reordered.
fn take_immediate_receive_batches(
    first: rustscale_magicsock::WgReceiveBatch,
    receiver: &mut mpsc::Receiver<rustscale_magicsock::WgReceiveBatch>,
    output: &mut Vec<rustscale_magicsock::WgDatagram>,
) -> Option<rustscale_magicsock::WgReceiveBatch> {
    debug_assert!(output.is_empty());
    *output = first.into_datagrams();
    while output.len() < rustscale_tun::TunPacketBatch::MAX_PACKETS {
        let Ok(next) = receiver.try_recv() else { break };
        if next.len() > rustscale_tun::TunPacketBatch::MAX_PACKETS - output.len() {
            return Some(next);
        }
        output.append(&mut next.into_datagrams());
    }
    None
}

async fn process_tun_inbound_batch(
    magicsock: &Arc<Magicsock>,
    tun: &dyn Tun,
    wg_tunnels: &RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>,
    filter: &Arc<std::sync::Mutex<Filter>>,
    packet_drops: &Arc<AtomicU64>,
    capture: &crate::capture::CaptureSlot,
    cancel: &CancelToken,
    peer_map: &crate::peer_map::Runtime,
    inbound: &mut InboundBatchScratch,
    outbound_sender: Option<&mut OutboundSendPipeline>,
) -> bool {
    let map_guard = peer_map.gate.read().await;
    inbound.datagrams.retain(|datagram| {
        magicsock.is_authorization_current(&datagram.peer, datagram.authorization_generation())
    });
    if !collect_tun_inbound_batch(wg_tunnels, inbound, cancel).await {
        return false;
    }
    authorize_tun_inbound_batch(peer_map, packet_drops, inbound);
    filter_tun_inbound_batch(filter, packet_drops, capture, inbound);
    drop(map_guard);
    // Normal transport data only writes the TUN and must not serialize the
    // outbound pipeline. Fence precisely before a generated reply could
    // bypass the sender task.
    if !flush_outbound_before_replies(outbound_sender, inbound).await {
        return false;
    }
    // Datagrams are ciphertext ownership; release their nested buffers before
    // reply I/O or a blocked TUN write.
    inbound.datagrams.clear();
    let reply_socket = magicsock.clone();
    flush_inbound_burst_authorized(tun, inbound, magicsock.as_ref(), move |peer, reply| {
        let magicsock = reply_socket.clone();
        async move {
            let _ = magicsock.send(peer, &reply).await;
        }
    })
    .await;
    true
}

/// The opt-in ordered two-buffer receive pipeline.  The worker owns only
/// mutation-free preflight/open; this task retains ordering, arbitration,
/// commit, filtering, replies, and TUN writes.
async fn run_tun_pump_pipeline(
    magicsock: Arc<Magicsock>,
    wg_recv: mpsc::Receiver<rustscale_magicsock::WgReceiveBatch>,
    tun: Arc<dyn Tun>,
    wg_tunnels: Arc<RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>>,
    route_table: Arc<RwLock<RouteTable>>,
    filter: Arc<std::sync::Mutex<Filter>>,
    packet_drops: Arc<AtomicU64>,
    cancel: Arc<CancelToken>,
    capture: crate::capture::CaptureSlot,
    peer_map: Arc<crate::peer_map::Runtime>,
    outbound_send_pipeline: bool,
) {
    run_tun_pump_pipeline_inner(
        magicsock,
        wg_recv,
        tun,
        wg_tunnels,
        route_table,
        filter,
        packet_drops,
        cancel,
        capture,
        peer_map,
        outbound_send_pipeline,
        #[cfg(test)]
        None,
        #[cfg(test)]
        None,
    )
    .await;
}

/// Pipeline implementation with test-only production-boundary observers.
async fn run_tun_pump_pipeline_inner(
    magicsock: Arc<Magicsock>,
    mut wg_recv: mpsc::Receiver<rustscale_magicsock::WgReceiveBatch>,
    tun: Arc<dyn Tun>,
    wg_tunnels: Arc<RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>>,
    route_table: Arc<RwLock<RouteTable>>,
    filter: Arc<std::sync::Mutex<Filter>>,
    packet_drops: Arc<AtomicU64>,
    cancel: Arc<CancelToken>,
    capture: crate::capture::CaptureSlot,
    peer_map: Arc<crate::peer_map::Runtime>,
    outbound_send_pipeline: bool,
    #[cfg(test)] opened_observer: Option<mpsc::UnboundedSender<()>>,
    #[cfg(test)] timer_entered_observer: Option<mpsc::UnboundedSender<()>>,
) {
    let (job_tx, job_rx) = mpsc::channel(1);
    let (opened_tx, mut opened_rx) = mpsc::channel(1);
    let (recycle_tx, recycle_rx) = mpsc::channel(1);
    let (available_tx, mut available_rx) = mpsc::channel(1);
    let worker_tunnels = wg_tunnels.clone();
    let worker_cancel = cancel.clone();
    let worker = tokio::spawn(async move {
        tun_inbound_open_worker(
            worker_tunnels,
            job_rx,
            opened_tx,
            recycle_rx,
            available_tx,
            worker_cancel,
            #[cfg(test)]
            opened_observer,
        )
        .await;
    });

    let mut ticker = tokio::time::interval(std::time::Duration::from_millis(250));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Consume interval's immediate first tick before entering the pipeline
    // scheduler. Subsequent ticks represent real overdue timer work.
    let _ = ticker.tick().await;
    let mut batch = rustscale_tun::TunPacketBatch::new();
    let mut outbound = OutboundBatchScratch::default();
    let mut outbound_sender = outbound_send_pipeline
        .then(|| OutboundSendPipeline::start(magicsock.clone(), cancel.clone()));
    // These are the only inbound scratch objects.  They circulate as whole
    // values through job/opened/recycle/available capacity-one channels.
    let mut free = Some(InboundBatchScratch::default());
    let mut first_seed = Some(InboundBatchScratch::default());
    let mut deferred_wg_batch = None;

    'pump: loop {
        if cancel.is_cancelled() {
            break;
        }
        let first = if let Some(first) = deferred_wg_batch.take() {
            first
        } else {
            tokio::select! {
                result = tun.read_batch(&mut batch) => match result {
                    Ok(()) => {
                        send_tun_batch_maybe_pipelined(&magicsock, &wg_tunnels, &route_table, &filter,
                            batch.packets(), &mut outbound, &capture, &peer_map, outbound_sender.as_mut()).await;
                        continue;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(e) => { log::warn!("tun read error: {e}"); break 'pump; }
                },
                result = wg_recv.recv() => if let Some(batch) = result {
                    batch
                } else {
                    log::warn!("tsnet: magicsock wg channel closed (tun)");
                    break 'pump;
                },
                _ = ticker.tick() => {
                    if !flush_outbound_before_competing_send(outbound_sender.as_mut()).await {
                        break 'pump;
                    }
                    let _map = peer_map.gate.read().await;
                    if !tick_wg_timers_pipeline_inner(&magicsock, &wg_tunnels, &cancel,
                        #[cfg(test)] timer_entered_observer.as_ref()).await {
                        break 'pump;
                    }
                    continue;
                }
            }
        };

        let mut seed = if let Some(seed) = first_seed.take() {
            seed
        } else if let Some(free) = free.take() {
            free
        } else if let Some(recycled) = pipeline_recv(&mut available_rx, &cancel).await {
            recycled
        } else {
            break;
        };
        seed.clear();
        deferred_wg_batch =
            take_immediate_receive_batches(first, &mut wg_recv, &mut seed.datagrams);
        if !pipeline_send(&job_tx, seed, &cancel).await {
            break;
        }
        let Some(mut current) = pipeline_recv(&mut opened_rx, &cancel).await else {
            break;
        };
        if free.is_none() {
            free = pipeline_recv(&mut available_rx, &cancel).await;
            if free.is_none() {
                break;
            }
        }

        loop {
            // Consume an already-ready N+1 first, preserving a deferred whole
            // batch ahead of later channel items.
            let next = deferred_wg_batch.take().or_else(|| wg_recv.try_recv().ok());
            let mut has_next = if let Some(next) = next {
                let Some(mut next_scratch) = free.take() else {
                    break 'pump;
                };
                next_scratch.clear();
                deferred_wg_batch =
                    take_immediate_receive_batches(next, &mut wg_recv, &mut next_scratch.datagrams);
                if !pipeline_send(&job_tx, next_scratch, &cancel).await {
                    break 'pump;
                }
                true
            } else {
                false
            };

            let map_guard = peer_map.gate.read().await;
            if current.datagrams.iter().any(|datagram| {
                !magicsock
                    .is_authorization_current(&datagram.peer, datagram.authorization_generation())
            }) {
                current.clear();
            } else if !commit_or_scalar_tun_inbound_batch(&wg_tunnels, &mut current, &cancel).await
            {
                break 'pump;
            }
            authorize_tun_inbound_batch(&peer_map, &packet_drops, &mut current);
            filter_tun_inbound_batch(&filter, &packet_drops, &capture, &mut current);
            drop(map_guard);
            current.datagrams.clear();
            if !flush_outbound_before_replies(outbound_sender.as_mut(), &current).await {
                break 'pump;
            }
            let flushed = {
                let flush = flush_inbound_burst_pipeline_authorized(
                    tun.as_ref(),
                    &mut current,
                    magicsock.as_ref(),
                    |peer, reply| {
                        let magicsock = magicsock.clone();
                        async move {
                            let _ = magicsock.send(peer, &reply).await;
                        }
                    },
                    &cancel,
                );
                tokio::pin!(flush);

                // If N+1 was not ready at commit time, wait for either N's
                // post-open work or exactly one next channel item. This is what
                // permits AEAD opening N+1 while a fake/real TUN write blocks N.
                if has_next || free.is_none() {
                    flush.await
                } else {
                    tokio::select! {
                        done = &mut flush => done,
                        next = wg_recv.recv() => {
                            let Some(next) = next else { break 'pump; };
                            let Some(mut next_scratch) = free.take() else {
                                break 'pump;
                            };
                            next_scratch.clear();
                            deferred_wg_batch = take_immediate_receive_batches(
                                next, &mut wg_recv, &mut next_scratch.datagrams,
                            );
                            if !pipeline_send(&job_tx, next_scratch, &cancel).await {
                                break 'pump;
                            }
                            has_next = true;
                            flush.await
                        }
                        () = cancel.cancelled() => break 'pump,
                    }
                }
            };
            if !flushed {
                break 'pump;
            }

            // A batch can arrive while the write future becomes ready. Drain
            // that one item before deciding whether N+1 exists, so it cannot
            // bypass the mandatory post-EMPTY arbitration through the outer
            // scheduler.
            if !has_next {
                let next = deferred_wg_batch.take().or_else(|| wg_recv.try_recv().ok());
                if let Some(next) = next {
                    let Some(mut next_scratch) = free.take() else {
                        break 'pump;
                    };
                    next_scratch.clear();
                    deferred_wg_batch = take_immediate_receive_batches(
                        next,
                        &mut wg_recv,
                        &mut next_scratch.datagrams,
                    );
                    if !pipeline_send(&job_tx, next_scratch, &cancel).await {
                        break 'pump;
                    }
                    has_next = true;
                }
            }

            // N reaches EMPTY only after its write future returns.  Recycling
            // it wakes the worker's bounded recycle wait; it then becomes the
            // only free scratch for a later burst.
            if !pipeline_send(&recycle_tx, current, &cancel).await {
                break 'pump;
            }
            if has_next {
                let Some(recycled) = pipeline_recv(&mut available_rx, &cancel).await else {
                    break 'pump;
                };
                free = Some(recycled);
            }
            // N is EMPTY. Give the owner one bounded arbitration turn before
            // N+1 can commit, so sustained inbound cannot starve a ready TUN
            // read or timer.
            match select_post_empty_ready(tun.read_batch(&mut batch), ticker.tick(), &cancel).await
            {
                PostEmptyReady::Read(Ok(())) => {
                    tokio::select! {
                        () = send_tun_batch_maybe_pipelined(&magicsock, &wg_tunnels, &route_table, &filter,
                            batch.packets(), &mut outbound, &capture, &peer_map, outbound_sender.as_mut()) => {}
                        () = cancel.cancelled() => break 'pump,
                    }
                }
                PostEmptyReady::Read(Err(error))
                    if error.kind() == std::io::ErrorKind::WouldBlock => {}
                PostEmptyReady::Read(Err(error)) => {
                    log::warn!("tun read error: {error}");
                    break 'pump;
                }
                PostEmptyReady::Timer => {
                    if !flush_outbound_before_competing_send(outbound_sender.as_mut()).await {
                        break 'pump;
                    }
                    let _map = peer_map.gate.read().await;
                    if !tick_wg_timers_pipeline_inner(
                        &magicsock,
                        &wg_tunnels,
                        &cancel,
                        #[cfg(test)]
                        timer_entered_observer.as_ref(),
                    )
                    .await
                    {
                        break 'pump;
                    }
                }
                PostEmptyReady::Cancelled => break 'pump,
                PostEmptyReady::NoReady => {}
            }
            if !has_next {
                // The other scratch is now circulating through the worker's
                // recycle/available leg; no third scratch is created.
                break;
            }
            let Some(next_opened) = pipeline_recv(&mut opened_rx, &cancel).await else {
                break 'pump;
            };
            current = next_opened;
        }
    }

    drop(job_tx);
    drop(recycle_tx);
    worker.abort();
    let _ = worker.await;
    if let Some(sender) = outbound_sender {
        sender.shutdown().await;
    }
}

/// Persistent worker: exactly one whole burst is opened at a time.  The
/// recycle leg keeps two owned scratch values bounded even if output is full.
async fn tun_inbound_open_worker(
    wg_tunnels: Arc<RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>>,
    mut jobs: mpsc::Receiver<InboundBatchScratch>,
    opened: mpsc::Sender<InboundBatchScratch>,
    mut recycle: mpsc::Receiver<InboundBatchScratch>,
    available: mpsc::Sender<InboundBatchScratch>,
    cancel: Arc<CancelToken>,
    #[cfg(test)] opened_observer: Option<mpsc::UnboundedSender<()>>,
) {
    let mut waiting_recycle = false;
    loop {
        if !waiting_recycle {
            let Some(mut scratch) = pipeline_recv(&mut jobs, &cancel).await else {
                return;
            };
            if !open_tun_inbound_batch(&wg_tunnels, &mut scratch, &cancel).await {
                return;
            }
            #[cfg(test)]
            if let Some(observer) = &opened_observer {
                let _ = observer.send(());
            }
            if !pipeline_send(&opened, scratch, &cancel).await {
                return;
            }
            waiting_recycle = true;
            continue;
        }
        tokio::select! {
            scratch = pipeline_recv(&mut jobs, &cancel) => {
                let Some(mut scratch) = scratch else { return; };
                // This is the sole permitted look-ahead job. The pump owns no
                // further scratch until it has completed and recycled N.
                if !open_tun_inbound_batch(&wg_tunnels, &mut scratch, &cancel).await { return; }
                #[cfg(test)]
                if let Some(observer) = &opened_observer {
                    let _ = observer.send(());
                }
                if !pipeline_send(&opened, scratch, &cancel).await { return; }
            }
            recycled = pipeline_recv(&mut recycle, &cancel) => {
                let Some(recycled) = recycled else { return; };
                if !pipeline_send(&available, recycled, &cancel).await { return; }
                waiting_recycle = false;
            }
            () = cancel.cancelled() => return,
        }
    }
}

async fn pipeline_recv(
    receiver: &mut mpsc::Receiver<InboundBatchScratch>,
    cancel: &CancelToken,
) -> Option<InboundBatchScratch> {
    tokio::select! {
        scratch = receiver.recv() => scratch,
        () = cancel.cancelled() => None,
    }
}

async fn pipeline_send(
    sender: &mpsc::Sender<InboundBatchScratch>,
    scratch: InboundBatchScratch,
    cancel: &CancelToken,
) -> bool {
    tokio::select! {
        result = sender.send(scratch) => result.is_ok(),
        () = cancel.cancelled() => false,
    }
}

/// One bounded post-EMPTY readiness turn. The selected read/tick is complete;
/// its stateful service is deliberately performed by the caller afterwards.
enum PostEmptyReady<R> {
    Read(R),
    Timer,
    Cancelled,
    NoReady,
}

async fn select_post_empty_ready<R, T>(
    read: impl std::future::Future<Output = R>,
    timer: impl std::future::Future<Output = T>,
    cancel: &CancelToken,
) -> PostEmptyReady<R> {
    tokio::select! {
        biased;
        _ = timer => PostEmptyReady::Timer,
        result = read => PostEmptyReady::Read(result),
        () = cancel.cancelled() => PostEmptyReady::Cancelled,
        () = tokio::task::yield_now() => PostEmptyReady::NoReady,
    }
}

/// Pipeline-only timer service. Every wait that can block is cancellation
/// aware; netstack continues to use its existing timer helper unchanged.
#[cfg(test)]
async fn tick_wg_timers_pipeline(
    magicsock: &Magicsock,
    wg_tunnels: &RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>,
    cancel: &CancelToken,
) -> bool {
    tick_wg_timers_pipeline_inner(
        magicsock,
        wg_tunnels,
        cancel,
        #[cfg(test)]
        None,
    )
    .await
}

async fn tick_wg_timers_pipeline_inner(
    magicsock: &Magicsock,
    wg_tunnels: &RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>,
    cancel: &CancelToken,
    #[cfg(test)] timer_entered_observer: Option<&mpsc::UnboundedSender<()>>,
) -> bool {
    let tunnels: Vec<(NodePublic, Arc<Mutex<WgTunn>>)> = tokio::select! {
        tunnels = wg_tunnels.read() => tunnels.iter().map(|(peer, tunnel)| (peer.clone(), tunnel.clone())).collect(),
        () = cancel.cancelled() => return false,
    };
    #[cfg(test)]
    if let Some(observer) = timer_entered_observer {
        let _ = observer.send(());
    }
    let mut pending = Vec::new();
    for (peer, tunnel) in tunnels {
        let mut tunnel = tokio::select! {
            tunnel = tunnel.lock() => tunnel,
            () = cancel.cancelled() => return false,
        };
        for datagram in tunnel.tick_timers() {
            pending.push((peer.clone(), datagram));
        }
    }
    for (peer, datagram) in pending {
        tokio::select! {
            _ = magicsock.send(peer, &datagram) => {}
            () = cancel.cancelled() => return false,
        }
    }
    true
}

/// Send replies before the one batch write, then reset the logical plaintext
/// length. The owned plaintext slots remain available for the next burst.
async fn flush_inbound_burst_authorized<F, Fut>(
    tun: &dyn Tun,
    inbound: &mut InboundBatchScratch,
    magicsock: &Magicsock,
    mut send_reply: F,
) where
    F: FnMut(NodePublic, Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    for (peer, generation, reply) in inbound.replies.drain(..) {
        if magicsock.is_authorization_current(&peer, generation) {
            send_reply(peer, reply).await;
        }
    }
    let _delivery = magicsock.authorization_delivery_guard().await;
    retain_current_authorization(magicsock, inbound);
    if !inbound.plaintext.is_empty() {
        if let Err(error) = tun.write_batch(inbound.plaintext.packets_mut()).await {
            log::warn!("tun batch write error: {error}");
        }
    }
    // TUN write-side GRO may have rewritten these buffers even on error.
    // Clear only after the write completed, then release scalar jumbo fallback
    // allocations before this scratch can be recycled.
    inbound.plaintext.clear();
    inbound.plaintext.release_oversized_slots();
    inbound.plaintext_peers.clear();
    inbound.plaintext_generations.clear();
}

/// Cancellation-aware pipeline flush. Dropping the in-flight reply/write
/// future on cancellation releases the scratch rather than leaving the pump
/// parked behind a device or transport operation.
async fn flush_inbound_burst_pipeline_authorized<F, Fut>(
    tun: &dyn Tun,
    inbound: &mut InboundBatchScratch,
    magicsock: &Magicsock,
    mut send_reply: F,
    cancel: &CancelToken,
) -> bool
where
    F: FnMut(NodePublic, Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    for (peer, generation, reply) in inbound.replies.drain(..) {
        if magicsock.is_authorization_current(&peer, generation) {
            tokio::select! {
                () = send_reply(peer, reply) => {}
                () = cancel.cancelled() => return false,
            }
        }
    }
    let _delivery = magicsock.authorization_delivery_guard().await;
    retain_current_authorization(magicsock, inbound);
    if !inbound.plaintext.is_empty() {
        let result = {
            let packets = inbound.plaintext.packets_mut();
            tokio::select! {
                result = tun.write_batch(packets) => Some(result),
                () = cancel.cancelled() => None,
            }
        };
        let Some(result) = result else {
            return false;
        };
        if let Err(error) = result {
            log::warn!("tun batch write error: {error}");
        }
    }
    inbound.plaintext.clear();
    inbound.plaintext.release_oversized_slots();
    inbound.plaintext_peers.clear();
    inbound.plaintext_generations.clear();
    true
}

#[cfg(test)]
async fn flush_inbound_burst<F, Fut>(
    tun: &dyn Tun,
    inbound: &mut InboundBatchScratch,
    mut send_reply: F,
) where
    F: FnMut(NodePublic, Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    for (peer, _, reply) in inbound.replies.drain(..) {
        send_reply(peer, reply).await;
    }
    if !inbound.plaintext.is_empty() {
        let _ = tun.write_batch(inbound.plaintext.packets_mut()).await;
    }
    inbound.plaintext.clear();
    inbound.plaintext.release_oversized_slots();
    inbound.plaintext_peers.clear();
    inbound.plaintext_generations.clear();
}

#[cfg(test)]
async fn flush_inbound_burst_pipeline<F, Fut>(
    tun: &dyn Tun,
    inbound: &mut InboundBatchScratch,
    mut send_reply: F,
    cancel: &CancelToken,
) -> bool
where
    F: FnMut(NodePublic, Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    for (peer, _, reply) in inbound.replies.drain(..) {
        tokio::select! {
            () = send_reply(peer, reply) => {}
            () = cancel.cancelled() => return false,
        }
    }
    if !inbound.plaintext.is_empty() {
        let result = tokio::select! {
            result = tun.write_batch(inbound.plaintext.packets_mut()) => result,
            () = cancel.cancelled() => return false,
        };
        let _ = result;
    }
    inbound.plaintext.clear();
    inbound.plaintext.release_oversized_slots();
    inbound.plaintext_peers.clear();
    inbound.plaintext_generations.clear();
    true
}

fn retain_current_authorization(magicsock: &Magicsock, inbound: &mut InboundBatchScratch) {
    debug_assert_eq!(inbound.plaintext.len(), inbound.plaintext_peers.len());
    debug_assert_eq!(inbound.plaintext.len(), inbound.plaintext_generations.len());
    let mut source = 0;
    let mut retained = 0;
    inbound.plaintext.retain_mut(|_| {
        let keep = magicsock.is_authorization_current(
            &inbound.plaintext_peers[source],
            inbound.plaintext_generations[source],
        );
        if keep {
            if retained != source {
                inbound.plaintext_peers[retained] = inbound.plaintext_peers[source].clone();
                inbound.plaintext_generations[retained] = inbound.plaintext_generations[source];
            }
            retained += 1;
        }
        source += 1;
        keep
    });
    inbound.plaintext_peers.truncate(retained);
    inbound.plaintext_generations.truncate(retained);
}

/// Reused state for one bounded inbound WireGuard burst.
#[derive(Default)]
struct InboundBatchScratch {
    datagrams: Vec<rustscale_magicsock::WgDatagram>,
    runs: Vec<InboundBatchRun>,
    plaintext: rustscale_wg::WgPlaintextBatch,
    /// Identity and authorization generation aligned with each initialized
    /// `plaintext` slot.
    plaintext_peers: Vec<NodePublic>,
    plaintext_generations: Vec<u64>,
    replies: Vec<(NodePublic, u64, Vec<u8>)>,
    /// One opaque entry per ciphertext datagram while this scratch is OPENED.
    opened: Vec<Option<rustscale_wg::WgOpenedPacket>>,
    /// Reused only by the ordered pump commit; always empty before this owned
    /// scratch crosses a worker channel.
    locked: Vec<(Arc<Mutex<WgTunn>>, tokio::sync::OwnedMutexGuard<WgTunn>)>,
}

impl InboundBatchScratch {
    /// Recover every slot owned by a speculative vendor token before resetting
    /// this scratch.  A scalar fallback is allowed only after this completes:
    /// otherwise a corrupt tail packet would silently discard the warmed
    /// allocations opened for its valid predecessors.
    fn abort_opened(&mut self) {
        let (opened, plaintext) = (&mut self.opened, &mut self.plaintext);
        for opened in opened.iter_mut().flatten() {
            rustscale_wg::WgTunn::abort_opened(opened, plaintext);
        }
        opened.clear();
    }

    fn clear(&mut self) {
        debug_assert!(self.locked.is_empty());
        self.abort_opened();
        self.datagrams.clear();
        self.runs.clear();
        self.plaintext.clear();
        self.plaintext_peers.clear();
        self.plaintext_generations.clear();
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

/// Decapsulate a capped immediate receive burst in peer runs. Only synchronous
/// boringtun work and owned-result collection occur while a tunnel is locked.
async fn collect_tun_inbound_batch(
    wg_tunnels: &RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>,
    inbound: &mut InboundBatchScratch,
    cancel: &CancelToken,
) -> bool {
    let tunnels = tokio::select! {
        tunnels = wg_tunnels.read() => tunnels,
        () = cancel.cancelled() => return false,
    };
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
        {
            let mut tunnel = tokio::select! {
                tunnel = run.tunnel.lock() => tunnel,
                () = cancel.cancelled() => return false,
            };
            for datagram in &inbound.datagrams[run.start..run.end] {
                let plaintext_start = inbound.plaintext.len();
                if let Ok(replies) = tunnel.decapsulate_into(&datagram.data, &mut inbound.plaintext)
                {
                    for _ in plaintext_start..inbound.plaintext.len() {
                        inbound.plaintext_peers.push(run.peer.clone());
                        inbound
                            .plaintext_generations
                            .push(datagram.authorization_generation());
                    }
                    inbound.replies.extend(replies.into_iter().map(|reply| {
                        (run.peer.clone(), datagram.authorization_generation(), reply)
                    }));
                }
            }
        }
    }
    !cancel.is_cancelled()
}

/// Worker half of the pipeline. A failed whole-burst preflight or open leaves
/// the retained ciphertext untouched and marks the whole scratch scalar-only.
async fn open_tun_inbound_batch(
    wg_tunnels: &RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>,
    inbound: &mut InboundBatchScratch,
    cancel: &CancelToken,
) -> bool {
    let tunnels = tokio::select! {
        tunnels = wg_tunnels.read() => tunnels,
        () = cancel.cancelled() => return false,
    };
    build_inbound_runs(&inbound.datagrams, &tunnels, &mut inbound.runs);
    drop(tunnels);

    // Do not open even an earlier packet if a tail item is scalar-only.
    let mut scalar_only = false;
    for run in &inbound.runs {
        let InboundBatchRun::Routed(run) = run else {
            scalar_only = true;
            break;
        };
        let tunnel = tokio::select! { guard = run.tunnel.lock() => guard, () = cancel.cancelled() => return false };
        if inbound.datagrams[run.start..run.end]
            .iter()
            .any(|datagram| {
                datagram.data.len().saturating_sub(16) > rustscale_wg::MAX_PIPELINED_ENCRYPTED_BODY
                    || tunnel.preflight_data(&datagram.data).is_err()
            })
        {
            scalar_only = true;
            break;
        }
    }
    if scalar_only {
        inbound.abort_opened();
        return true;
    }

    inbound.opened.resize_with(inbound.datagrams.len(), || None);
    let mut open_failed = false;
    for run in &inbound.runs {
        let InboundBatchRun::Routed(run) = run else {
            open_failed = true;
            break;
        };
        let tunnel = tokio::select! { guard = run.tunnel.lock() => guard, () = cancel.cancelled() => return false };
        for index in run.start..run.end {
            let datagram = &inbound.datagrams[index];
            let opened = tunnel.preflight_data(&datagram.data).and_then(|prepared| {
                tunnel.open_prepared_into(&datagram.data, &prepared, &mut inbound.plaintext)
            });
            if let Ok(opened) = opened {
                inbound.opened[index] = Some(opened);
            } else {
                open_failed = true;
                break;
            }
        }
        if open_failed {
            break;
        }
    }
    if open_failed {
        inbound.abort_opened();
        inbound.plaintext.clear();
    }
    true
}

/// Pump half of the pipeline. It revalidates every token while all relevant
/// guards are held, then commits synchronously in FIFO order. Any stale token
/// falls back before the first mutation, never after a partial replay commit.
async fn commit_or_scalar_tun_inbound_batch(
    wg_tunnels: &RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>,
    inbound: &mut InboundBatchScratch,
    cancel: &CancelToken,
) -> bool {
    if inbound.opened.len() != inbound.datagrams.len() {
        return collect_tun_inbound_batch(wg_tunnels, inbound, cancel).await;
    }

    debug_assert!(inbound.locked.is_empty());
    for run in &inbound.runs {
        let InboundBatchRun::Routed(run) = run else {
            inbound.locked.clear();
            inbound.abort_opened();
            inbound.plaintext.clear();
            return collect_tun_inbound_batch(wg_tunnels, inbound, cancel).await;
        };
        if !inbound
            .locked
            .iter()
            .any(|(tunnel, _)| Arc::ptr_eq(tunnel, &run.tunnel))
        {
            let tunnel = run.tunnel.clone();
            let guard = tokio::select! {
                guard = tunnel.clone().lock_owned() => guard,
                () = cancel.cancelled() => { inbound.locked.clear(); return false; }
            };
            inbound.locked.push((tunnel, guard));
        }
    }

    let valid = inbound.runs.iter().all(|run| {
        let InboundBatchRun::Routed(run) = run else {
            return false;
        };
        let Some((_, tunnel)) = inbound
            .locked
            .iter()
            .find(|(tunnel, _)| Arc::ptr_eq(tunnel, &run.tunnel))
        else {
            return false;
        };
        (run.start..run.end).all(|index| {
            inbound.opened[index]
                .as_ref()
                .is_some_and(|opened| tunnel.preflight_opened(opened, &inbound.plaintext))
        })
    });
    if !valid {
        inbound.locked.clear();
        inbound.abort_opened();
        inbound.plaintext.clear();
        return collect_tun_inbound_batch(wg_tunnels, inbound, cancel).await;
    }

    for run in &inbound.runs {
        let InboundBatchRun::Routed(run) = run else {
            continue;
        };
        let Some((_, tunnel)) = inbound
            .locked
            .iter_mut()
            .find(|(tunnel, _)| Arc::ptr_eq(tunnel, &run.tunnel))
        else {
            continue;
        };
        for index in run.start..run.end {
            let Some(opened) = inbound.opened.get_mut(index).and_then(Option::as_mut) else {
                continue;
            };
            match tunnel.commit_opened(opened, &mut inbound.plaintext) {
                Ok(rustscale_wg::WgCommitResult::Accepted) => {
                    inbound.plaintext_peers.push(run.peer.clone());
                    inbound
                        .plaintext_generations
                        .push(inbound.datagrams[index].authorization_generation());
                }
                Ok(rustscale_wg::WgCommitResult::Dropped) => {}
                // A complete prevalidation makes this structurally
                // impossible. Do not silently turn it into a post-commit
                // drop: ordered state may already have changed.
                Ok(rustscale_wg::WgCommitResult::Stale) | Err(_) => return false,
            }
        }
    }
    inbound.locked.clear();
    inbound.runs.clear();
    // Successful commits have consumed every vendor token. Clear the now-empty
    // capability slots without touching the initialized plaintext prefix.
    inbound.opened.clear();
    !cancel.is_cancelled()
}

/// Enforce that each decrypted packet's source address is currently owned by
/// the exact WireGuard key that opened it, then retain TCP SYN provenance for
/// TUN PeerAPI accepts. This runs immediately before the packet filter.
fn authorize_tun_inbound_batch(
    peer_map: &crate::peer_map::Runtime,
    packet_drops: &Arc<AtomicU64>,
    inbound: &mut InboundBatchScratch,
) {
    debug_assert_eq!(inbound.plaintext.len(), inbound.plaintext_peers.len());
    debug_assert_eq!(inbound.plaintext.len(), inbound.plaintext_generations.len());
    let mut source = 0;
    let mut retained = 0;
    inbound.plaintext.retain_mut(|packet| {
        let peer = &inbound.plaintext_peers[source];
        let keep = peer_map.packet_source_matches(peer, packet);
        if keep {
            peer_map.record_packet(peer, packet);
            if retained != source {
                inbound.plaintext_peers[retained] = peer.clone();
                inbound.plaintext_generations[retained] = inbound.plaintext_generations[source];
            }
            retained += 1;
        } else {
            packet_drops.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        source += 1;
        keep
    });
    inbound.plaintext_peers.truncate(retained);
    inbound.plaintext_generations.truncate(retained);
}

/// Filter and stably compact plaintext after every tunnel lock has been
/// released. Capture sees each accepted packet before a Linux GRO write can
/// mutate it; the parallel peer vector is compacted in the same stable order.
fn filter_tun_inbound_batch(
    filter: &Arc<std::sync::Mutex<Filter>>,
    packet_drops: &Arc<AtomicU64>,
    capture: &crate::capture::CaptureSlot,
    inbound: &mut InboundBatchScratch,
) {
    #[cfg(test)]
    if inbound.plaintext_generations.is_empty() && !inbound.plaintext.is_empty() {
        // Filter-only unit tests construct post-decryption scratch directly.
        inbound
            .plaintext_generations
            .resize(inbound.plaintext.len(), 0);
    }
    debug_assert_eq!(inbound.plaintext.len(), inbound.plaintext_peers.len());
    debug_assert_eq!(inbound.plaintext.len(), inbound.plaintext_generations.len());
    let mut source = 0;
    let mut retained = 0;
    let mut filt = filter.lock().unwrap();
    inbound.plaintext.retain_mut(|packet| {
        let keep = !filt.check_in(packet).is_drop();
        if keep {
            // Capture before Linux write-side GRO is allowed to rewrite the
            // packet's offload and transport headers.
            crate::capture::log_packet(capture, crate::capture::CapturePath::FromPeer, packet);
            if retained != source {
                inbound.plaintext_peers[retained] = inbound.plaintext_peers[source].clone();
                inbound.plaintext_generations[retained] = inbound.plaintext_generations[source];
            }
            retained += 1;
        } else {
            packet_drops.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        source += 1;
        keep
    });
    drop(filt);
    inbound.plaintext_peers.truncate(retained);
    inbound.plaintext_generations.truncate(retained);
}

/// Reused state for one outbound kernel-TUN read.
#[derive(Default)]
struct OutboundBatchScratch {
    routes: Vec<Option<NodePublic>>,
    runs: Vec<BatchRun>,
    // Created only by the scalar path. The opt-in sender owns exactly its two
    // ciphertext batches and never retains a hidden third batch in the pump.
    scalar_datagrams: Option<rustscale_wg::WgDatagramBatch>,
}

/// One owned, completely encrypted peer run. These are the only objects that
/// may cross from the ordered pump into the transport task.
struct OutboundDatagramRun {
    peer: Option<NodePublic>,
    datagrams: rustscale_wg::WgDatagramBatch,
}

enum OutboundSendJob {
    Run(OutboundDatagramRun),
    /// A FIFO fence for a pump-originated send that would otherwise bypass
    /// this task (inbound WG replies and timer packets).
    Barrier(tokio::sync::oneshot::Sender<()>),
}

/// Default-off, depth-one queued outbound sender. The pump begins with two
/// reusable ciphertext batches: one can be in `send_batch` while it encrypts
/// the next run into the other. No packet task or per-packet channel exists.
struct OutboundSendPipeline {
    jobs: Option<mpsc::Sender<OutboundSendJob>>,
    available: mpsc::Receiver<OutboundDatagramRun>,
    local: Vec<OutboundDatagramRun>,
    cancel: Arc<CancelToken>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl OutboundSendPipeline {
    fn start(magicsock: Arc<Magicsock>, cancel: Arc<CancelToken>) -> Self {
        Self::start_with(cancel, move |run| {
            let magicsock = magicsock.clone();
            Box::pin(async move {
                let _ = magicsock
                    .send_batch(
                        run.peer.clone().expect("queued outbound run has a peer"),
                        run.datagrams.packets(),
                    )
                    .await;
            })
        })
    }

    fn start_with<F>(cancel: Arc<CancelToken>, send: F) -> Self
    where
        F: for<'a> FnMut(&'a OutboundDatagramRun) -> OutboundSendFuture<'a> + Send + 'static,
    {
        let (jobs, job_rx) = mpsc::channel(1);
        let (available_tx, available) = mpsc::channel(2);
        let worker_cancel = cancel.clone();
        let task = tokio::spawn(outbound_send_worker(
            job_rx,
            available_tx,
            worker_cancel,
            send,
        ));
        Self {
            jobs: Some(jobs),
            available,
            local: vec![
                OutboundDatagramRun {
                    peer: None,
                    datagrams: rustscale_wg::WgDatagramBatch::new(),
                },
                OutboundDatagramRun {
                    peer: None,
                    datagrams: rustscale_wg::WgDatagramBatch::new(),
                },
            ],
            cancel,
            task: Some(task),
        }
    }

    async fn acquire(&mut self) -> Option<OutboundDatagramRun> {
        if let Some(run) = self.local.pop() {
            return Some(run);
        }
        tokio::select! {
            run = self.available.recv() => run,
            () = self.cancel.cancelled() => None,
        }
    }

    async fn queue(&mut self, run: OutboundDatagramRun) -> bool {
        let Some(jobs) = self.jobs.as_ref() else {
            return false;
        };
        tokio::select! {
            result = jobs.send(OutboundSendJob::Run(run)) => result.is_ok(),
            () = self.cancel.cancelled() => false,
        }
    }

    /// Wait for all previously queued outbound TUN ciphertext to reach
    /// Magicsock before a reply/timer send bypasses this sender. This is not
    /// used between ordinary TUN batches, which retain the intended overlap.
    async fn flush(&mut self) -> bool {
        let Some(jobs) = self.jobs.as_ref() else {
            return false;
        };
        let (complete_tx, complete_rx) = tokio::sync::oneshot::channel();
        tokio::select! {
            result = jobs.send(OutboundSendJob::Barrier(complete_tx)) => {
                if result.is_err() { return false; }
            }
            () = self.cancel.cancelled() => return false,
        }
        tokio::select! {
            result = complete_rx => result.is_ok(),
            () = self.cancel.cancelled() => false,
        }
    }

    async fn shutdown(mut self) {
        drop(self.jobs.take());
        // Do not cancel the shared lifecycle token here: a fatal TUN error is
        // local to this pump. Give queued sends a small orderly-drain window,
        // then deterministically abort a transport operation that cannot be
        // cancelled by dropping its future.
        const OUTBOUND_SENDER_SHUTDOWN_DRAIN: std::time::Duration =
            std::time::Duration::from_secs(1);
        let Some(task) = self.task.as_mut() else {
            return;
        };
        if tokio::time::timeout(OUTBOUND_SENDER_SHUTDOWN_DRAIN, task)
            .await
            .is_err()
        {
            // Keep the handle in `self` until this join completes. If this
            // shutdown future itself is aborted at either await point, Drop
            // still sees the handle and aborts the blocked sender.
            if let Some(task) = self.task.as_ref() {
                task.abort();
            }
            if let Some(task) = self.task.as_mut() {
                let _ = task.await;
            }
        }
        self.task.take();
        // Keep the recycle receiver alive during the bounded drain. Once the
        // sender is joined (or aborted), this value drops its remaining
        // channel and local batch owners immediately on return.
    }
}

impl Drop for OutboundSendPipeline {
    fn drop(&mut self) {
        // An aborted pump cannot await orderly shutdown. Aborting the one
        // sender releases a blocked Magicsock future and its owned batches;
        // this deliberately does not touch the shared lifecycle token.
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

type OutboundSendFuture<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>>;

/// The sole sender-side transport loop. FIFO channel order plus one sender
/// preserves input run, peer, and packet order across direct and DERP paths.
async fn outbound_send_worker<F>(
    mut jobs: mpsc::Receiver<OutboundSendJob>,
    available: mpsc::Sender<OutboundDatagramRun>,
    cancel: Arc<CancelToken>,
    mut send: F,
) where
    F: for<'a> FnMut(&'a OutboundDatagramRun) -> OutboundSendFuture<'a> + Send + 'static,
{
    loop {
        let Some(job) = (tokio::select! {
            job = jobs.recv() => job,
            () = cancel.cancelled() => None,
        }) else {
            return;
        };
        let mut run = match job {
            OutboundSendJob::Run(run) => run,
            OutboundSendJob::Barrier(complete) => {
                let _ = complete.send(());
                continue;
            }
        };
        tokio::select! {
            () = send(&run) => {}
            () = cancel.cancelled() => return,
        }
        run.datagrams.clear();
        if !pipeline_send_outbound(&available, run, &cancel).await {
            return;
        }
    }
}

async fn pipeline_send_outbound(
    sender: &mpsc::Sender<OutboundDatagramRun>,
    run: OutboundDatagramRun,
    cancel: &CancelToken,
) -> bool {
    tokio::select! {
        result = sender.send(run) => result.is_ok(),
        () = cancel.cancelled() => false,
    }
}

/// Scalar sends were awaited inline, so a pump reply or timer packet could
/// never overtake earlier TUN ciphertext. Preserve that ordering scope when
/// the sender is enabled. It intentionally says nothing about sends made by
/// other Magicsock tasks; it fences only this pump's ordered protocol work.
async fn flush_outbound_before_competing_send(sender: Option<&mut OutboundSendPipeline>) -> bool {
    match sender {
        Some(sender) => sender.flush().await,
        None => true,
    }
}

async fn flush_outbound_before_replies(
    sender: Option<&mut OutboundSendPipeline>,
    inbound: &InboundBatchScratch,
) -> bool {
    if inbound.replies.is_empty() {
        true
    } else {
        flush_outbound_before_competing_send(sender).await
    }
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
    prepare_outbound_batch(wg_tunnels, route_table, filter, packets, scratch, capture).await;
    let mut datagrams = scratch.scalar_datagrams.take().unwrap_or_default();

    for run in scratch.runs.drain(..) {
        let run = match run {
            BatchRun::Skip { start, end } => {
                debug_assert!(start <= end && end <= packets.len());
                continue;
            }
            BatchRun::Routed(run) => run,
        };
        datagrams.clear();
        {
            let mut tunnel = run.tunnel.lock().await;
            for packet in &packets[run.start..run.end] {
                let _ = tunnel.encapsulate_into(packet, &mut datagrams);
            }
        }
        let _ = magicsock
            .send_batch(run.peer.clone(), datagrams.packets())
            .await;
    }
    scratch.scalar_datagrams = Some(datagrams);
}

/// Shared ordered protocol work for scalar and pipelined outbound sends.
async fn prepare_outbound_batch(
    wg_tunnels: &RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>,
    route_table: &RwLock<RouteTable>,
    filter: &std::sync::Mutex<Filter>,
    packets: &[Vec<u8>],
    scratch: &mut OutboundBatchScratch,
    capture: &crate::capture::CaptureSlot,
) {
    scratch.routes.clear();
    scratch.runs.clear();

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
}

/// Encrypt in pump order but hand completed owned peer runs to the persistent
/// sender. At most one run waits in the FIFO while another is in transport.
async fn send_tun_batch_pipeline(
    wg_tunnels: &RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>,
    route_table: &RwLock<RouteTable>,
    filter: &std::sync::Mutex<Filter>,
    packets: &[Vec<u8>],
    scratch: &mut OutboundBatchScratch,
    capture: &crate::capture::CaptureSlot,
    sender: &mut OutboundSendPipeline,
) {
    prepare_outbound_batch(wg_tunnels, route_table, filter, packets, scratch, capture).await;

    for run in scratch.runs.drain(..) {
        let run = match run {
            BatchRun::Skip { start, end } => {
                debug_assert!(start <= end && end <= packets.len());
                continue;
            }
            BatchRun::Routed(run) => run,
        };
        let Some(mut datagram_run) = sender.acquire().await else {
            return;
        };
        datagram_run.peer = Some(run.peer);
        datagram_run.datagrams.clear();
        {
            let mut tunnel = run.tunnel.lock().await;
            for packet in &packets[run.start..run.end] {
                let _ = tunnel.encapsulate_into(packet, &mut datagram_run.datagrams);
            }
        }
        if !sender.queue(datagram_run).await {
            return;
        }
    }
}

async fn send_tun_batch_maybe_pipelined(
    magicsock: &Magicsock,
    wg_tunnels: &RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>,
    route_table: &RwLock<RouteTable>,
    filter: &std::sync::Mutex<Filter>,
    packets: &[Vec<u8>],
    scratch: &mut OutboundBatchScratch,
    capture: &crate::capture::CaptureSlot,
    peer_map: &crate::peer_map::Runtime,
    sender: Option<&mut OutboundSendPipeline>,
) {
    let _map = peer_map.gate.read().await;
    if let Some(sender) = sender {
        send_tun_batch_pipeline(
            wg_tunnels,
            route_table,
            filter,
            packets,
            scratch,
            capture,
            sender,
        )
        .await;
    } else {
        send_tun_batch(
            magicsock,
            wg_tunnels,
            route_table,
            filter,
            packets,
            scratch,
            capture,
        )
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
    derp_map: Option<&DERPMap>,
    control_url: &str,
    exit_node_allow_lan_access: bool,
) -> rustscale_router::RouterConfig {
    build_router_config_with_local_routes(
        local_addrs,
        route_table,
        derp_map,
        control_url,
        exit_node_allow_lan_access,
        rustscale_tsaddr::local_interface_prefixes(),
    )
}

fn build_router_config_with_local_routes(
    local_addrs: &[IpAddr],
    route_table: &RouteTable,
    derp_map: Option<&DERPMap>,
    control_url: &str,
    exit_node_allow_lan_access: bool,
    local_interface_prefixes: Vec<rustscale_tsaddr::IpPrefix>,
) -> rustscale_router::RouterConfig {
    let mut local_routes = Vec::new();
    if route_table.exit_node().is_some() {
        if let Some(derp_map) = derp_map {
            for region in derp_map.Regions.values() {
                for node in region.Nodes.iter().flatten() {
                    if node.STUNOnly {
                        continue;
                    }
                    for address in [&node.IPv4, &node.IPv6] {
                        if let Ok(ip) = address.parse::<IpAddr>() {
                            if !ip.is_unspecified() {
                                local_routes.push(rustscale_tsaddr::IpPrefix {
                                    ip,
                                    bits: if ip.is_ipv4() { 32 } else { 128 },
                                });
                            }
                        }
                    }
                }
            }
        }
        local_routes.extend(
            resolve_control_server_ips(control_url)
                .into_iter()
                .map(|ip| rustscale_tsaddr::IpPrefix {
                    ip,
                    bits: if ip.is_ipv4() { 32 } else { 128 },
                }),
        );
        if exit_node_allow_lan_access {
            local_routes.extend(local_interface_prefixes);
        }
        local_routes.extend([
            rustscale_tsaddr::IpPrefix {
                ip: "127.0.0.0".parse().expect("valid IPv4 loopback prefix"),
                bits: 8,
            },
            rustscale_tsaddr::IpPrefix {
                ip: "::1".parse().expect("valid IPv6 loopback address"),
                bits: 128,
            },
        ]);
        local_routes.sort_by_key(|prefix| (prefix.ip, prefix.bits));
        local_routes.dedup();
    }

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
        local_routes,
        exit_node: route_table.exit_node().is_some(),
    }
}

/// Synchronize a shared router after a route-table change.
pub(crate) fn sync_router(
    router: &SharedRouter,
    local_addrs: &[IpAddr],
    route_table: &RouteTable,
    derp_map: Option<&DERPMap>,
    control_url: &str,
    exit_node_allow_lan_access: bool,
) -> Result<(), TsnetError> {
    let config = build_router_config(
        local_addrs,
        route_table,
        derp_map,
        control_url,
        exit_node_allow_lan_access,
    );
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
    exit_node_allow_lan_access: bool,
) -> Result<(Arc<dyn Tun>, Option<SharedRouter>), TsnetError> {
    let dev = rustscale_tun::create(&config.tun)?;
    let router = if config.apply_routes {
        let mut router = rustscale_router::new(dev.name());
        router
            .up()
            .map_err(|error| TsnetError::Builder(format!("bring TUN interface up: {error}")))?;
        let route_config = {
            let route_table = b.route_table.read().await;
            build_router_config(
                &b.tailscale_ips,
                &route_table,
                b.magicsock.get_derp_map().as_ref(),
                &b.control_url,
                exit_node_allow_lan_access,
            )
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
    _exit_node_allow_lan_access: bool,
) -> Result<(Arc<dyn Tun>, Option<SharedRouter>), TsnetError> {
    Err(TsnetError::Builder(
        "TUN mode not supported on this platform".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustscale_key::{DiscoPrivate, NodePrivate};
    use rustscale_tailcfg::{DERPNode, DERPRegion};

    struct BatchProbe {
        events: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>,
    }

    struct PendingProbe {
        replies_seen: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        polled: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<usize>>>,
    }

    struct BlockingPipelineTun {
        entered: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        release: tokio::sync::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    }

    /// A TUN whose outbound read is deliberately held pending until the test
    /// reaches N's blocked write. This exercises the real pipeline scheduler
    /// rather than manually driving its worker channels.
    struct PostEmptyArbitrationTun {
        allow_read: std::sync::atomic::AtomicBool,
        read_ready: tokio::sync::Notify,
        read_seen: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        read_release: tokio::sync::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
        write_entered: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        release: tokio::sync::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
        replay_tunnel: Arc<Mutex<WgTunn>>,
        next_ciphertext: Vec<u8>,
        read_must_be_eligible: bool,
        outbound_packet: Vec<u8>,
    }

    /// Lets a test observe that aborting the sender dropped the *transport
    /// future*, rather than merely dropping its join handle.
    struct DropNotify(Option<tokio::sync::oneshot::Sender<()>>);

    impl Drop for DropNotify {
        fn drop(&mut self) {
            if let Some(notify) = self.0.take() {
                let _ = notify.send(());
            }
        }
    }

    #[test]
    fn exit_node_router_config_respects_lan_access_preference() {
        let exit_key = NodePrivate::generate().public();
        let mut routes = RouteTable::default();
        routes.set_exit_node(exit_key);
        let mut derp_map = DERPMap::default();
        derp_map.Regions.insert(
            1,
            DERPRegion {
                Nodes: Some(vec![DERPNode {
                    IPv4: "192.0.2.10".into(),
                    IPv6: "2001:db8::10".into(),
                    ..Default::default()
                }]),
                ..Default::default()
            },
        );

        let lan_prefix = rustscale_tsaddr::IpPrefix::parse("192.168.0.0/16").unwrap();
        let config = build_router_config_with_local_routes(
            &[],
            &routes,
            Some(&derp_map),
            "https://127.0.0.1",
            false,
            vec![lan_prefix],
        );
        for prefix in [
            "192.0.2.10/32",
            "2001:db8::10/128",
            "127.0.0.1/32",
            "127.0.0.0/8",
            "::1/128",
        ] {
            assert!(
                config
                    .local_routes
                    .contains(&rustscale_tsaddr::IpPrefix::parse(prefix).unwrap()),
                "missing bypass route {prefix}",
            );
        }
        assert!(
            !config.local_routes.contains(&lan_prefix),
            "LAN route {lan_prefix} must not bypass the exit node by default"
        );

        let config = build_router_config_with_local_routes(
            &[],
            &routes,
            Some(&derp_map),
            "https://127.0.0.1",
            true,
            vec![lan_prefix],
        );
        assert!(config.local_routes.contains(&lan_prefix));
        for prefix in [
            "192.0.2.10/32",
            "2001:db8::10/128",
            "127.0.0.1/32",
            "127.0.0.0/8",
            "::1/128",
        ] {
            assert!(
                config
                    .local_routes
                    .contains(&rustscale_tsaddr::IpPrefix::parse(prefix).unwrap()),
                "missing bypass route {prefix}",
            );
        }
    }

    #[test]
    fn control_server_resolution_returns_host_prefixes() {
        assert_eq!(
            resolve_control_server_ips("https://127.0.0.1:8443"),
            vec!["127.0.0.1".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn outbound_send_pipeline_activation_is_linux_only() {
        assert!(!tun_outbound_send_pipeline_enabled_for(false));
        assert_eq!(
            tun_outbound_send_pipeline_enabled_for(true),
            cfg!(target_os = "linux"),
            "an environment opt-in must retain the scalar path off Linux"
        );
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
    impl Tun for BlockingPipelineTun {
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
            if let Some(entered) = self.entered.lock().unwrap().take() {
                let _ = entered.send(());
            }
            if let Some(release) = self.release.lock().await.take() {
                let _ = release.await;
            }
            Ok(())
        }

        fn name(&self) -> &'static str {
            "blocking-pipeline"
        }

        fn mtu(&self) -> usize {
            1280
        }
    }

    #[async_trait::async_trait]
    impl Tun for PostEmptyArbitrationTun {
        async fn read_batch(
            &self,
            batch: &mut rustscale_tun::TunPacketBatch,
        ) -> std::io::Result<()> {
            while !self.allow_read.load(std::sync::atomic::Ordering::SeqCst) {
                self.read_ready.notified().await;
            }
            let read_seen = { self.read_seen.lock().unwrap().take() };
            if let Some(read_seen) = read_seen {
                // This is deliberately before the signal/return: a regression
                // that commits N+1 before servicing this selected read fails
                // here deterministically instead of after an observer races.
                let tunnel = self
                    .replay_tunnel
                    .try_lock()
                    .expect("post-N read must not race a tunnel commit");
                let eligibility = tunnel.preflight_data(&self.next_ciphertext);
                if self.read_must_be_eligible {
                    assert!(
                        eligibility.is_ok(),
                        "N+1 committed before the selected outbound read: {eligibility:?}"
                    );
                }
                drop(tunnel);
                let _ = read_seen.send(());
                if let Some(release) = self.read_release.lock().await.take() {
                    let _ = release.await;
                }
                batch.clear();
                batch.push_packet(&self.outbound_packet)?;
                return Ok(());
            }
            std::future::pending().await
        }

        async fn write_packet(&self, _packet: &[u8]) -> std::io::Result<()> {
            unreachable!("write_batch must be used")
        }

        async fn write_batch(&self, _packets: &mut [Vec<u8>]) -> std::io::Result<()> {
            if let Some(entered) = self.write_entered.lock().unwrap().take() {
                let _ = entered.send(());
            }
            if let Some(release) = self.release.lock().await.take() {
                let _ = release.await;
            }
            Ok(())
        }

        fn name(&self) -> &'static str {
            "post-empty-arbitration"
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
            for packet in packets {
                packet.fill(0xa5);
            }
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
            data: vec![index as u8].into(),
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
                data: ciphertext.into(),
            });
        }
        let tunnels = RwLock::new(HashMap::from([(a_public.clone(), receiver.clone())]));
        let filter = Arc::new(std::sync::Mutex::new(Filter::allow_all()));
        let packet_drops = Arc::new(AtomicU64::new(0));
        let capture = crate::capture::new_slot();

        assert!(collect_tun_inbound_batch(&tunnels, &mut inbound, &CancelToken::new()).await);
        filter_tun_inbound_batch(&filter, &packet_drops, &capture, &mut inbound);

        assert_eq!(inbound.plaintext.packets(), packets.as_slice());
        assert_eq!(inbound.plaintext_peers, vec![a_public.clone(), a_public]);
        assert!(inbound.replies.is_empty());
        assert_eq!(packet_drops.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert!(
            receiver.try_lock().is_ok(),
            "filtering and flush are lock-free"
        );
    }

    #[tokio::test]
    async fn pipeline_open_defers_replay_and_plaintext_publication_until_commit() {
        let source_private = NodePrivate::generate();
        let target_private = NodePrivate::generate();
        let source_public = source_private.public();
        let target_public = target_private.public();
        let sender = Arc::new(Mutex::new(
            WgTunn::new(&source_private, &target_public, 21).expect("source tunnel"),
        ));
        let receiver = Arc::new(Mutex::new(
            WgTunn::new(&target_private, &source_public, 22).expect("target tunnel"),
        ));
        establish_tunnels(&sender, &receiver).await;
        let packet = vec![
            0x45, 0, 0, 20, 0, 1, 0, 0, 64, 17, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2,
        ];
        let ciphertext = sender
            .lock()
            .await
            .encapsulate(&packet)
            .unwrap()
            .pop()
            .unwrap();
        let mut inbound = InboundBatchScratch::default();
        inbound.datagrams.push(rustscale_magicsock::WgDatagram {
            peer: source_public.clone(),
            data: ciphertext.into(),
        });
        let tunnels = RwLock::new(HashMap::from([(source_public, receiver.clone())]));

        let cancel = CancelToken::new();
        assert!(open_tun_inbound_batch(&tunnels, &mut inbound, &cancel).await);
        assert_eq!(inbound.plaintext.len(), 0, "OPENED is not published");
        assert_eq!(inbound.opened.len(), 1);
        assert!(receiver
            .lock()
            .await
            .preflight_data(&inbound.datagrams[0].data)
            .is_ok());

        let run_capacity = inbound.runs.capacity();
        assert!(commit_or_scalar_tun_inbound_batch(&tunnels, &mut inbound, &cancel).await);
        assert_eq!(inbound.plaintext.packets(), [packet]);
        assert!(
            inbound.runs.capacity() >= run_capacity && inbound.runs.is_empty(),
            "ordered commit must clear rather than replace reusable run storage"
        );
        assert!(receiver
            .lock()
            .await
            .preflight_data(&inbound.datagrams[0].data)
            .is_err());
    }

    #[tokio::test]
    async fn pipeline_tail_capability_stale_falls_back_before_any_speculative_commit() {
        let source_private = NodePrivate::generate();
        let target_private = NodePrivate::generate();
        let source_public = source_private.public();
        let target_public = target_private.public();
        let sender = Arc::new(Mutex::new(
            WgTunn::new(&source_private, &target_public, 23).expect("source tunnel"),
        ));
        let receiver = Arc::new(Mutex::new(
            WgTunn::new(&target_private, &source_public, 24).expect("target tunnel"),
        ));
        establish_tunnels(&sender, &receiver).await;
        let first_packet = vec![
            0x45, 0, 0, 20, 0, 1, 0, 0, 64, 17, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2,
        ];
        let second_packet = vec![
            0x45, 0, 0, 20, 0, 2, 0, 0, 64, 17, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2,
        ];
        let mut scratch = InboundBatchScratch::default();
        for packet in [&first_packet, &second_packet] {
            scratch.datagrams.push(rustscale_magicsock::WgDatagram {
                peer: source_public.clone(),
                data: sender
                    .lock()
                    .await
                    .encapsulate(packet)
                    .unwrap()
                    .pop()
                    .unwrap()
                    .into(),
            });
        }
        let tunnels = RwLock::new(HashMap::from([(source_public, receiver.clone())]));
        let cancel = CancelToken::new();
        assert!(open_tun_inbound_batch(&tunnels, &mut scratch, &cancel).await);
        // Simulates a substituted/tampered opaque tail capability. Complete
        // prevalidation must reject the burst before packet 1 can commit.
        scratch.opened[1] = None;
        assert!(commit_or_scalar_tun_inbound_batch(&tunnels, &mut scratch, &cancel).await);
        assert_eq!(scratch.plaintext.packets(), [first_packet, second_packet]);
        assert!(scratch.opened.is_empty());
    }

    #[tokio::test]
    async fn pipeline_mixed_corrupt_tail_scalar_fallback_retains_opened_slots() {
        let source_private = NodePrivate::generate();
        let target_private = NodePrivate::generate();
        let source_public = source_private.public();
        let target_public = target_private.public();
        let sender = Arc::new(Mutex::new(
            WgTunn::new(&source_private, &target_public, 25).expect("source tunnel"),
        ));
        let receiver = Arc::new(Mutex::new(
            WgTunn::new(&target_private, &source_public, 26).expect("target tunnel"),
        ));
        establish_tunnels(&sender, &receiver).await;
        let tunnels = RwLock::new(HashMap::from([(source_public.clone(), receiver.clone())]));
        let cancel = CancelToken::new();
        let mut scratch = InboundBatchScratch::default();
        let mut warmed_slots = None;

        for iteration in 0..4_u8 {
            scratch.clear();
            let valid_packet = vec![
                0x45, 0, 0, 20, 0, iteration, 0, 0, 64, 17, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2,
            ];
            let tail_packet = vec![
                0x45, 0, 0, 20, 1, iteration, 0, 0, 64, 17, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2,
            ];
            let valid = sender
                .lock()
                .await
                .encapsulate(&valid_packet)
                .expect("encrypt valid")
                .pop()
                .expect("valid data packet");
            let mut corrupt = sender
                .lock()
                .await
                .encapsulate(&tail_packet)
                .expect("encrypt tail")
                .pop()
                .expect("tail data packet");
            *corrupt.last_mut().expect("AEAD tag") ^= 1;
            scratch.datagrams.extend([
                rustscale_magicsock::WgDatagram {
                    peer: source_public.clone(),
                    data: valid.into(),
                },
                rustscale_magicsock::WgDatagram {
                    peer: source_public.clone(),
                    data: corrupt.into(),
                },
            ]);

            assert!(open_tun_inbound_batch(&tunnels, &mut scratch, &cancel).await);
            assert!(
                scratch.opened.is_empty(),
                "bad tag must select scalar fallback"
            );
            assert!(commit_or_scalar_tun_inbound_batch(&tunnels, &mut scratch, &cancel).await);
            assert_eq!(scratch.plaintext.packets(), [valid_packet]);
            assert_eq!(scratch.plaintext.reserved_len(), 0);
            let slots = scratch
                .plaintext
                .packets()
                .iter()
                .map(|packet| (packet.as_ptr(), packet.capacity()))
                .collect::<Vec<_>>();
            if let Some(warmed_slots) = &warmed_slots {
                assert_eq!(
                    &slots, warmed_slots,
                    "iteration {iteration} lost a warmed slot"
                );
            } else {
                warmed_slots = Some(slots);
            }
        }
    }

    #[tokio::test]
    async fn worker_opens_next_burst_while_current_tun_write_is_blocked() {
        let source_private = NodePrivate::generate();
        let target_private = NodePrivate::generate();
        let source_public = source_private.public();
        let target_public = target_private.public();
        let sender = Arc::new(Mutex::new(
            WgTunn::new(&source_private, &target_public, 31).expect("source tunnel"),
        ));
        let receiver = Arc::new(Mutex::new(
            WgTunn::new(&target_private, &source_public, 32).expect("target tunnel"),
        ));
        establish_tunnels(&sender, &receiver).await;
        let first_ciphertext = sender
            .lock()
            .await
            .encapsulate(&[
                0x45, 0, 0, 20, 0, 1, 0, 0, 64, 17, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2,
            ])
            .unwrap()
            .pop()
            .unwrap();
        let second_ciphertext = sender
            .lock()
            .await
            .encapsulate(&[
                0x45, 0, 0, 20, 0, 2, 0, 0, 64, 17, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2,
            ])
            .unwrap()
            .pop()
            .unwrap();
        let mut first_scratch = InboundBatchScratch::default();
        first_scratch
            .datagrams
            .push(rustscale_magicsock::WgDatagram {
                peer: source_public.clone(),
                data: first_ciphertext.into(),
            });
        let mut second_scratch = InboundBatchScratch::default();
        second_scratch
            .datagrams
            .push(rustscale_magicsock::WgDatagram {
                peer: source_public.clone(),
                data: second_ciphertext.into(),
            });
        let tunnels = Arc::new(RwLock::new(HashMap::from([(
            source_public.clone(),
            receiver.clone(),
        )])));
        let cancel = Arc::new(CancelToken::new());
        let (job_tx, job_rx) = mpsc::channel(1);
        let (opened_tx, mut opened_rx) = mpsc::channel(1);
        let (recycle_tx, recycle_rx) = mpsc::channel(1);
        let (available_tx, _available_rx) = mpsc::channel(1);
        let worker = tokio::spawn(tun_inbound_open_worker(
            tunnels.clone(),
            job_rx,
            opened_tx,
            recycle_rx,
            available_tx,
            cancel.clone(),
            None,
        ));

        job_tx.send(first_scratch).await.unwrap();
        let mut current = opened_rx.recv().await.unwrap();
        assert!(commit_or_scalar_tun_inbound_batch(&tunnels, &mut current, &cancel).await);
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let tun = BlockingPipelineTun {
            entered: std::sync::Mutex::new(Some(entered_tx)),
            release: tokio::sync::Mutex::new(Some(release_rx)),
        };
        {
            let flush = flush_inbound_burst_pipeline(&tun, &mut current, |_, _| async {}, &cancel);
            tokio::pin!(flush);
            tokio::select! {
                result = &mut flush => panic!("write unexpectedly completed: {result}"),
                _ = entered_rx => {}
            }

            // This is the scheduler's critical overlap: OPENED for N+1 arrives
            // while N still owns plaintext in a blocked write future.
            job_tx.send(second_scratch).await.unwrap();
            let next =
                tokio::time::timeout(std::time::Duration::from_millis(100), opened_rx.recv())
                    .await
                    .expect("worker did not open N+1 while N write was blocked")
                    .expect("worker output closed");
            assert_eq!(next.plaintext.len(), 0, "OPENED must not publish plaintext");
            assert!(
                receiver
                    .lock()
                    .await
                    .preflight_data(&next.datagrams[0].data)
                    .is_ok(),
                "N+1 replay state changed before ordered commit"
            );

            let _ = release_tx.send(());
            assert!(flush.await);
        }
        recycle_tx.send(current).await.unwrap();
        cancel.cancel();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), worker)
                .await
                .expect("worker did not wake on cancellation")
                .is_ok()
        );
    }

    #[tokio::test]
    async fn pipeline_scheduler_services_ready_outbound_before_committing_prefetched_next() {
        let source_private = NodePrivate::generate();
        let target_private = NodePrivate::generate();
        let source_public = source_private.public();
        let target_public = target_private.public();
        let sender = Arc::new(Mutex::new(
            WgTunn::new(&source_private, &target_public, 41).expect("source tunnel"),
        ));
        let receiver = Arc::new(Mutex::new(
            WgTunn::new(&target_private, &source_public, 42).expect("target tunnel"),
        ));
        establish_tunnels(&sender, &receiver).await;
        let first = sender
            .lock()
            .await
            .encapsulate(&[
                0x45, 0, 0, 20, 0, 1, 0, 0, 64, 17, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2,
            ])
            .expect("encrypt first")
            .pop()
            .expect("first data");
        let second = sender
            .lock()
            .await
            .encapsulate(&[
                0x45, 0, 0, 20, 0, 2, 0, 0, 64, 17, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2,
            ])
            .expect("encrypt second")
            .pop()
            .expect("second data");
        assert_ne!(
            &first[8..16],
            &second[8..16],
            "test requires distinct replay counters"
        );
        let (write_entered_tx, write_entered_rx) = tokio::sync::oneshot::channel();
        let (read_seen_tx, read_seen_rx) = tokio::sync::oneshot::channel();
        let (read_release_tx, read_release_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let tun = Arc::new(PostEmptyArbitrationTun {
            allow_read: std::sync::atomic::AtomicBool::new(false),
            read_ready: tokio::sync::Notify::new(),
            read_seen: std::sync::Mutex::new(Some(read_seen_tx)),
            read_release: tokio::sync::Mutex::new(Some(read_release_rx)),
            write_entered: std::sync::Mutex::new(Some(write_entered_tx)),
            release: tokio::sync::Mutex::new(Some(release_rx)),
            replay_tunnel: receiver.clone(),
            next_ciphertext: second.clone(),
            read_must_be_eligible: false,
            // A valid IPv4 packet whose destination is routed below to the
            // established peer. The selected service therefore performs a
            // nonempty WireGuard encapsulation rather than an empty read.
            outbound_packet: vec![
                0x45, 0, 0, 20, 0, 3, 0, 0, 64, 17, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2,
            ],
        });
        let (magicsock, _unused_rx) = Magicsock::new(MagicsockConfig {
            private_key: NodePrivate::generate(),
            disco_key: DiscoPrivate::generate(),
            derp_client: None,
            derp_map: None,
            home_derp_region: 0,
            udp_bind: None,
            udp_socket: None,
            portmapper: None,
            health: None,
            disable_direct_paths: false,
            peer_relay_server: false,
            relay_server_config: None,
            sockstats: None,
            control_knobs: None,
        })
        .await
        .expect("magicsock");
        magicsock
            .set_netmap(vec![Node {
                Key: source_public.clone(),
                ..Default::default()
            }])
            .await
            .unwrap();
        let first_datagram = magicsock
            .authorized_wg_datagram(source_public.clone(), first)
            .unwrap();
        let second_datagram = magicsock
            .authorized_wg_datagram(source_public.clone(), second.clone())
            .unwrap();
        let (wg_tx, wg_rx) = mpsc::channel(2);
        let tunnels = Arc::new(RwLock::new(HashMap::from([(
            source_public.clone(),
            receiver.clone(),
        )])));
        let cancel = Arc::new(CancelToken::new());
        let task = tokio::spawn(run_tun_pump_pipeline(
            Arc::new(magicsock),
            wg_rx,
            tun.clone(),
            tunnels,
            Arc::new(RwLock::new({
                let mut routes = RouteTable::default();
                routes.set_exit_node(source_public.clone());
                routes
            })),
            Arc::new(std::sync::Mutex::new(Filter::allow_all())),
            Arc::new(AtomicU64::new(0)),
            cancel.clone(),
            crate::capture::new_slot(),
            crate::peer_map::Runtime::new(&[rustscale_tailcfg::Node {
                ID: 1,
                Key: source_public.clone(),
                Addresses: vec!["100.64.0.1/32".into()],
                ..Default::default()
            }])
            .expect("peer map"),
            false,
        ));
        tokio::task::yield_now().await;
        wg_tx
            .send(
                rustscale_magicsock::WgReceiveBatch::from_datagrams_for_test(vec![first_datagram]),
            )
            .await
            .expect("first batch");
        tokio::time::timeout(std::time::Duration::from_millis(250), write_entered_rx)
            .await
            .expect("N write did not block")
            .expect("N write signal closed");
        wg_tx
            .send(
                rustscale_magicsock::WgReceiveBatch::from_datagrams_for_test(vec![second_datagram]),
            )
            .await
            .expect("second batch");
        assert!(
            receiver.lock().await.preflight_data(&second).is_ok(),
            "N+1 committed while N's TUN write was still blocked"
        );

        tun.allow_read
            .store(true, std::sync::atomic::Ordering::SeqCst);
        tun.read_ready.notify_waiters();
        let _ = release_tx.send(());
        tokio::time::timeout(std::time::Duration::from_millis(250), read_seen_rx)
            .await
            .expect("post-N ready outbound read was starved")
            .expect("outbound read signal closed");
        // The readiness future was selected, but it has not returned to the
        // scheduler yet. Hold the outbound tunnel before allowing it to do
        // so; this makes the selected nonempty encrypt/send service itself
        // observably block, not merely the fake read notification.
        let service_lock = receiver.lock().await;
        let _ = read_release_tx.send(());
        tokio::task::yield_now().await;
        assert!(
            service_lock.preflight_data(&second).is_ok(),
            "N+1 committed before the selected outbound service completed"
        );
        drop(service_lock);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            if receiver.lock().await.preflight_data(&second).is_err() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "N+1 did not commit after service"
            );
            tokio::task::yield_now().await;
        }
        cancel.cancel();
        drop(wg_tx);
        tokio::time::timeout(std::time::Duration::from_millis(250), task)
            .await
            .expect("pipeline did not stop after cancellation")
            .expect("pipeline task panicked");
    }

    #[tokio::test]
    async fn pipeline_timer_ready_arbitration_precedes_next_commit() {
        let source_private = NodePrivate::generate();
        let target_private = NodePrivate::generate();
        let source_public = source_private.public();
        let target_public = target_private.public();
        let sender = Arc::new(Mutex::new(
            WgTunn::new(&source_private, &target_public, 43).expect("sender"),
        ));
        let receiver = Arc::new(Mutex::new(
            WgTunn::new(&target_private, &source_public, 44).expect("receiver"),
        ));
        establish_tunnels(&sender, &receiver).await;
        let n = sender
            .lock()
            .await
            .encapsulate(&[
                0x45, 0, 0, 20, 0, 1, 0, 0, 64, 17, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2,
            ])
            .unwrap()
            .pop()
            .unwrap();
        let n_plus_one = sender
            .lock()
            .await
            .encapsulate(&[
                0x45, 0, 0, 20, 0, 2, 0, 0, 64, 17, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2,
            ])
            .unwrap()
            .pop()
            .unwrap();
        let dummy_key = NodePrivate::generate().public();
        let dummy = Arc::new(Mutex::new(
            WgTunn::new(&NodePrivate::generate(), &dummy_key, 45).expect("dummy tunnel"),
        ));
        let (write_entered_tx, write_entered_rx) = tokio::sync::oneshot::channel();
        let (read_seen_tx, mut read_seen_rx) = tokio::sync::oneshot::channel();
        let (read_release_tx, read_release_rx) = tokio::sync::oneshot::channel();
        let (write_release_tx, write_release_rx) = tokio::sync::oneshot::channel();
        let tun = Arc::new(PostEmptyArbitrationTun {
            allow_read: std::sync::atomic::AtomicBool::new(false),
            read_ready: tokio::sync::Notify::new(),
            read_seen: std::sync::Mutex::new(Some(read_seen_tx)),
            read_release: tokio::sync::Mutex::new(Some(read_release_rx)),
            write_entered: std::sync::Mutex::new(Some(write_entered_tx)),
            release: tokio::sync::Mutex::new(Some(write_release_rx)),
            replay_tunnel: receiver.clone(),
            next_ciphertext: n_plus_one.clone(),
            read_must_be_eligible: false,
            outbound_packet: vec![
                0x45, 0, 0, 20, 0, 3, 0, 0, 64, 17, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2,
            ],
        });
        let (magicsock, _unused_rx) = Magicsock::new(MagicsockConfig {
            private_key: NodePrivate::generate(),
            disco_key: DiscoPrivate::generate(),
            derp_client: None,
            derp_map: None,
            home_derp_region: 0,
            udp_bind: None,
            udp_socket: None,
            portmapper: None,
            health: None,
            disable_direct_paths: false,
            peer_relay_server: false,
            relay_server_config: None,
            sockstats: None,
            control_knobs: None,
        })
        .await
        .expect("magicsock");
        magicsock
            .set_netmap(vec![
                Node {
                    Key: source_public.clone(),
                    ..Default::default()
                },
                Node {
                    Key: dummy_key.clone(),
                    ..Default::default()
                },
            ])
            .await
            .unwrap();
        let n_datagram = magicsock
            .authorized_wg_datagram(source_public.clone(), n)
            .unwrap();
        let n_plus_one_datagram = magicsock
            .authorized_wg_datagram(source_public.clone(), n_plus_one.clone())
            .unwrap();
        let (wg_tx, wg_rx) = mpsc::channel(2);
        let tunnels = Arc::new(RwLock::new(HashMap::from([
            (source_public.clone(), receiver.clone()),
            (dummy_key, dummy.clone()),
        ])));
        let cancel = Arc::new(CancelToken::new());
        let (opened_tx, mut opened_rx) = mpsc::unbounded_channel();
        let (timer_tx, mut timer_rx) = mpsc::unbounded_channel();
        let task = tokio::spawn(run_tun_pump_pipeline_inner(
            Arc::new(magicsock),
            wg_rx,
            tun.clone(),
            tunnels,
            Arc::new(RwLock::new(RouteTable::default())),
            Arc::new(std::sync::Mutex::new(Filter::allow_all())),
            Arc::new(AtomicU64::new(0)),
            cancel.clone(),
            crate::capture::new_slot(),
            crate::peer_map::Runtime::new(&[rustscale_tailcfg::Node {
                ID: 1,
                Key: source_public.clone(),
                Addresses: vec!["100.64.0.1/32".into()],
                ..Default::default()
            }])
            .expect("peer map"),
            false,
            Some(opened_tx),
            Some(timer_tx),
        ));
        wg_tx
            .send(rustscale_magicsock::WgReceiveBatch::from_datagrams_for_test(vec![n_datagram]))
            .await
            .unwrap();
        opened_rx.recv().await.expect("N opened");
        tokio::time::timeout(std::time::Duration::from_millis(250), write_entered_rx)
            .await
            .expect("N write")
            .expect("write signal");
        wg_tx
            .send(
                rustscale_magicsock::WgReceiveBatch::from_datagrams_for_test(vec![
                    n_plus_one_datagram,
                ]),
            )
            .await
            .unwrap();
        opened_rx.recv().await.expect("N+1 opened");
        let dummy_lock = dummy.lock().await;
        tokio::time::sleep(std::time::Duration::from_millis(275)).await;
        tun.allow_read
            .store(true, std::sync::atomic::Ordering::SeqCst);
        tun.read_ready.notify_waiters();
        let _ = write_release_tx.send(());
        timer_rx.recv().await.expect("timer snapshot entered");
        assert!(
            read_seen_rx.try_recv().is_err(),
            "ready read ran before timer service"
        );
        assert!(
            receiver.lock().await.preflight_data(&n_plus_one).is_ok(),
            "N+1 committed while timer blocked"
        );
        drop(dummy_lock);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while receiver.lock().await.preflight_data(&n_plus_one).is_ok() {
            assert!(
                std::time::Instant::now() < deadline,
                "N+1 did not commit after timer"
            );
            tokio::task::yield_now().await;
        }
        let _ = read_release_tx.send(());
        cancel.cancel();
        drop(wg_tx);
        tokio::time::timeout(std::time::Duration::from_millis(250), task)
            .await
            .expect("pipeline join")
            .expect("pipeline panic");
    }

    #[tokio::test]
    async fn pipeline_worker_wakes_when_channels_close_or_cancel() {
        let tunnels = Arc::new(RwLock::new(HashMap::new()));
        let cancel = Arc::new(CancelToken::new());
        let (job_tx, job_rx) = mpsc::channel(1);
        let (opened_tx, _opened_rx) = mpsc::channel(1);
        let (_recycle_tx, recycle_rx) = mpsc::channel(1);
        let (available_tx, _available_rx) = mpsc::channel(1);
        let worker = tokio::spawn(tun_inbound_open_worker(
            tunnels,
            job_rx,
            opened_tx,
            recycle_rx,
            available_tx,
            cancel.clone(),
            None,
        ));
        drop(job_tx);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), worker)
                .await
                .expect("worker did not wake for closed input")
                .is_ok()
        );
        cancel.cancel();
    }

    #[tokio::test]
    async fn pipeline_worker_cancels_while_waiting_for_tunnel_lock() {
        let source_private = NodePrivate::generate();
        let target_private = NodePrivate::generate();
        let source_public = source_private.public();
        let target_public = target_private.public();
        let sender = Arc::new(Mutex::new(
            WgTunn::new(&source_private, &target_public, 51).expect("source tunnel"),
        ));
        let receiver = Arc::new(Mutex::new(
            WgTunn::new(&target_private, &source_public, 52).expect("target tunnel"),
        ));
        establish_tunnels(&sender, &receiver).await;
        let ciphertext = sender
            .lock()
            .await
            .encapsulate(&[
                0x45, 0, 0, 20, 0, 3, 0, 0, 64, 17, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2,
            ])
            .expect("encrypt")
            .pop()
            .expect("data");
        let mut scratch = InboundBatchScratch::default();
        scratch.datagrams.push(rustscale_magicsock::WgDatagram {
            peer: source_public.clone(),
            data: ciphertext.into(),
        });
        let tunnels = Arc::new(RwLock::new(HashMap::from([(
            source_public,
            receiver.clone(),
        )])));
        let cancel = Arc::new(CancelToken::new());
        let held = receiver.lock().await;
        let task = tokio::spawn({
            let tunnels = tunnels.clone();
            let cancel = cancel.clone();
            async move { open_tun_inbound_batch(&tunnels, &mut scratch, &cancel).await }
        });
        tokio::task::yield_now().await;
        cancel.cancel();
        assert!(
            !tokio::time::timeout(std::time::Duration::from_millis(250), task)
                .await
                .expect("worker lock wait did not wake")
                .expect("worker task panicked")
        );
        drop(held);
    }

    #[tokio::test]
    async fn pipeline_open_cancels_while_waiting_for_tunnel_map_lock() {
        let tunnels = Arc::new(RwLock::new(HashMap::new()));
        let cancel = Arc::new(CancelToken::new());
        let held = tunnels.write().await;
        let task = tokio::spawn({
            let tunnels = tunnels.clone();
            let cancel = cancel.clone();
            async move {
                let mut scratch = InboundBatchScratch::default();
                open_tun_inbound_batch(&tunnels, &mut scratch, &cancel).await
            }
        });
        tokio::task::yield_now().await;
        cancel.cancel();
        assert!(
            !tokio::time::timeout(std::time::Duration::from_millis(250), task)
                .await
                .expect("map lock wait did not wake")
                .expect("map lock task panicked")
        );
        drop(held);
    }

    #[tokio::test]
    async fn pipeline_scalar_fallback_cancels_while_waiting_for_tunnel_lock() {
        let source_private = NodePrivate::generate();
        let target_private = NodePrivate::generate();
        let source_public = source_private.public();
        let target_public = target_private.public();
        let sender = Arc::new(Mutex::new(
            WgTunn::new(&source_private, &target_public, 55).expect("source tunnel"),
        ));
        let receiver = Arc::new(Mutex::new(
            WgTunn::new(&target_private, &source_public, 56).expect("target tunnel"),
        ));
        establish_tunnels(&sender, &receiver).await;
        let ciphertext = sender
            .lock()
            .await
            .encapsulate(&[
                0x45, 0, 0, 20, 0, 5, 0, 0, 64, 17, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2,
            ])
            .expect("encrypt")
            .pop()
            .expect("data");
        let mut scratch = InboundBatchScratch::default();
        scratch.datagrams.push(rustscale_magicsock::WgDatagram {
            peer: source_public.clone(),
            data: ciphertext.into(),
        });
        let tunnels = Arc::new(RwLock::new(HashMap::from([(
            source_public,
            receiver.clone(),
        )])));
        let cancel = Arc::new(CancelToken::new());
        let held = receiver.lock().await;
        let task = tokio::spawn({
            let tunnels = tunnels.clone();
            let cancel = cancel.clone();
            async move {
                let completed =
                    commit_or_scalar_tun_inbound_batch(&tunnels, &mut scratch, &cancel).await;
                (completed, scratch)
            }
        });
        tokio::task::yield_now().await;
        cancel.cancel();
        let (completed, scratch) =
            tokio::time::timeout(std::time::Duration::from_millis(250), task)
                .await
                .expect("scalar fallback lock wait did not wake")
                .expect("scalar fallback task panicked");
        assert!(!completed);
        assert!(
            scratch.plaintext.is_empty(),
            "cancellation must not filter or write"
        );
        drop(held);
    }

    #[tokio::test]
    async fn pipeline_timer_cancels_while_waiting_for_tunnel_lock() {
        let private = NodePrivate::generate();
        let peer = NodePrivate::generate().public();
        let tunnel = Arc::new(Mutex::new(
            WgTunn::new(&private, &peer, 57).expect("tunnel"),
        ));
        let tunnels = RwLock::new(HashMap::from([(peer, tunnel.clone())]));
        let (magicsock, _unused_rx) = Magicsock::new(MagicsockConfig {
            private_key: NodePrivate::generate(),
            disco_key: DiscoPrivate::generate(),
            derp_client: None,
            derp_map: None,
            home_derp_region: 0,
            udp_bind: None,
            udp_socket: None,
            portmapper: None,
            health: None,
            disable_direct_paths: false,
            peer_relay_server: false,
            relay_server_config: None,
            sockstats: None,
            control_knobs: None,
        })
        .await
        .expect("magicsock");
        let cancel = Arc::new(CancelToken::new());
        let held = tunnel.lock().await;
        let task = tokio::spawn({
            let cancel = cancel.clone();
            async move { tick_wg_timers_pipeline(&magicsock, &tunnels, &cancel).await }
        });
        tokio::task::yield_now().await;
        cancel.cancel();
        assert!(
            !tokio::time::timeout(std::time::Duration::from_millis(250), task)
                .await
                .expect("timer lock wait did not wake")
                .expect("timer task panicked")
        );
        drop(held);
    }

    #[tokio::test]
    async fn pipeline_commit_cancels_while_waiting_for_tunnel_lock() {
        let source_private = NodePrivate::generate();
        let target_private = NodePrivate::generate();
        let source_public = source_private.public();
        let target_public = target_private.public();
        let sender = Arc::new(Mutex::new(
            WgTunn::new(&source_private, &target_public, 53).expect("source tunnel"),
        ));
        let receiver = Arc::new(Mutex::new(
            WgTunn::new(&target_private, &source_public, 54).expect("target tunnel"),
        ));
        establish_tunnels(&sender, &receiver).await;
        let ciphertext = sender
            .lock()
            .await
            .encapsulate(&[
                0x45, 0, 0, 20, 0, 4, 0, 0, 64, 17, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2,
            ])
            .expect("encrypt")
            .pop()
            .expect("data");
        let ciphertext_for_check = ciphertext.clone();
        let mut scratch = InboundBatchScratch::default();
        scratch.datagrams.push(rustscale_magicsock::WgDatagram {
            peer: source_public.clone(),
            data: ciphertext.into(),
        });
        let tunnels = Arc::new(RwLock::new(HashMap::from([(
            source_public,
            receiver.clone(),
        )])));
        let cancel = Arc::new(CancelToken::new());
        assert!(open_tun_inbound_batch(&tunnels, &mut scratch, &cancel).await);
        let held = receiver.lock().await;
        let task = tokio::spawn({
            let tunnels = tunnels.clone();
            let cancel = cancel.clone();
            async move {
                let _ = commit_or_scalar_tun_inbound_batch(&tunnels, &mut scratch, &cancel).await;
                scratch
            }
        });
        tokio::task::yield_now().await;
        cancel.cancel();
        let scratch = tokio::time::timeout(std::time::Duration::from_millis(250), task)
            .await
            .expect("commit lock wait did not wake")
            .expect("commit task panicked");
        assert!(
            scratch.locked.is_empty(),
            "cancel must release held guards once"
        );
        drop(held);
        assert!(
            receiver
                .lock()
                .await
                .preflight_data(&ciphertext_for_check)
                .is_ok(),
            "cancelled commit mutated replay state"
        );
    }

    #[tokio::test]
    async fn tun_wg_receive_batch_consumer_matches_scalar_delivery_order() {
        let batch_source_private = NodePrivate::generate();
        let batch_target_private = NodePrivate::generate();
        let batch_source_public = batch_source_private.public();
        let batch_target_public = batch_target_private.public();
        let batch_sender = Arc::new(Mutex::new(
            WgTunn::new(&batch_source_private, &batch_target_public, 11).expect("batch sender"),
        ));
        let batch_receiver = Arc::new(Mutex::new(
            WgTunn::new(&batch_target_private, &batch_source_public, 12).expect("batch receiver"),
        ));
        establish_tunnels(&batch_sender, &batch_receiver).await;

        let scalar_source_private = NodePrivate::generate();
        let scalar_target_private = NodePrivate::generate();
        let scalar_source_public = scalar_source_private.public();
        let scalar_target_public = scalar_target_private.public();
        let scalar_sender = Arc::new(Mutex::new(
            WgTunn::new(&scalar_source_private, &scalar_target_public, 13).expect("scalar sender"),
        ));
        let scalar_receiver = Arc::new(Mutex::new(
            WgTunn::new(&scalar_target_private, &scalar_source_public, 14)
                .expect("scalar receiver"),
        ));
        establish_tunnels(&scalar_sender, &scalar_receiver).await;

        let plaintext = vec![
            vec![
                0x45, 0, 0, 20, 0, 1, 0, 0, 64, 17, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2,
            ],
            vec![
                0x45, 0, 0, 20, 0, 2, 0, 0, 64, 17, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2,
            ],
            vec![
                0x45, 0, 0, 20, 0, 3, 0, 0, 64, 17, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2,
            ],
        ];
        let mut batch_datagrams = Vec::new();
        for packet in &plaintext {
            batch_datagrams.push(rustscale_magicsock::WgDatagram {
                peer: batch_source_public.clone(),
                data: batch_sender
                    .lock()
                    .await
                    .encapsulate(packet)
                    .expect("batch encrypt")
                    .into_iter()
                    .next()
                    .expect("one batch data datagram")
                    .into(),
            });
        }
        let second = batch_datagrams.split_off(1);
        let (send, mut recv) = mpsc::channel(2);
        send.try_send(
            rustscale_magicsock::WgReceiveBatch::from_datagrams_for_test(batch_datagrams),
        )
        .unwrap();
        send.try_send(rustscale_magicsock::WgReceiveBatch::from_datagrams_for_test(second))
            .unwrap();
        let first = recv.recv().await.expect("first receive batch");
        let mut batch_inbound = InboundBatchScratch::default();
        assert!(
            take_immediate_receive_batches(first, &mut recv, &mut batch_inbound.datagrams)
                .is_none()
        );
        assert_eq!(batch_inbound.datagrams.len(), plaintext.len());

        let batch_tunnels = RwLock::new(HashMap::from([(batch_source_public, batch_receiver)]));
        assert!(
            collect_tun_inbound_batch(&batch_tunnels, &mut batch_inbound, &CancelToken::new())
                .await
        );

        let scalar_tunnels = RwLock::new(HashMap::from([(
            scalar_source_public.clone(),
            scalar_receiver,
        )]));
        let mut scalar_inbound = InboundBatchScratch::default();
        for packet in &plaintext {
            scalar_inbound.datagrams = vec![rustscale_magicsock::WgDatagram {
                peer: scalar_source_public.clone(),
                data: scalar_sender
                    .lock()
                    .await
                    .encapsulate(packet)
                    .expect("scalar encrypt")
                    .into_iter()
                    .next()
                    .expect("one scalar data datagram")
                    .into(),
            }];
            assert!(
                collect_tun_inbound_batch(
                    &scalar_tunnels,
                    &mut scalar_inbound,
                    &CancelToken::new()
                )
                .await
            );
        }

        assert_eq!(batch_inbound.plaintext.packets(), plaintext.as_slice());
        assert_eq!(scalar_inbound.plaintext.packets(), plaintext.as_slice());
    }

    #[test]
    fn tun_receive_coalescing_defers_a_whole_nonfitting_batch() {
        let peer = NodePrivate::generate().public();
        let datagrams = |start, count| {
            (start..start + count)
                .map(|byte| rustscale_magicsock::WgDatagram {
                    peer: peer.clone(),
                    data: vec![byte as u8].into(),
                })
                .collect::<Vec<_>>()
        };
        let (send, mut recv) = mpsc::channel(2);
        send.try_send(
            rustscale_magicsock::WgReceiveBatch::from_datagrams_for_test(datagrams(0, 3)),
        )
        .unwrap();
        send.try_send(
            rustscale_magicsock::WgReceiveBatch::from_datagrams_for_test(datagrams(3, 126)),
        )
        .unwrap();
        let mut output = Vec::new();
        let deferred = take_immediate_receive_batches(
            recv.try_recv().expect("first batch"),
            &mut recv,
            &mut output,
        )
        .expect("126-packet batch must not be split");

        assert_eq!(
            output.iter().map(|d| d.data[0]).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert_eq!(deferred.len(), 126);
        let deferred = deferred.into_datagrams();
        assert_eq!(deferred[0].data, vec![3]);
    }

    #[tokio::test]
    async fn inbound_batch_collects_all_128_plaintext_slots_in_order() {
        let first_source_private = NodePrivate::generate();
        let first_target_private = NodePrivate::generate();
        let first_source_public = first_source_private.public();
        let first_target_public = first_target_private.public();
        let first_sender = Arc::new(Mutex::new(
            WgTunn::new(&first_source_private, &first_target_public, 1).expect("first sender"),
        ));
        let first_receiver = Arc::new(Mutex::new(
            WgTunn::new(&first_target_private, &first_source_public, 2).expect("first receiver"),
        ));
        let second_source_private = NodePrivate::generate();
        let second_target_private = NodePrivate::generate();
        let second_source_public = second_source_private.public();
        let second_target_public = second_target_private.public();
        let second_sender = Arc::new(Mutex::new(
            WgTunn::new(&second_source_private, &second_target_public, 3).expect("second sender"),
        ));
        let second_receiver = Arc::new(Mutex::new(
            WgTunn::new(&second_target_private, &second_source_public, 4).expect("second receiver"),
        ));
        establish_tunnels(&first_sender, &first_receiver).await;
        establish_tunnels(&second_sender, &second_receiver).await;

        let packets = (0..rustscale_wg::WgPlaintextBatch::MAX_PACKETS)
            .map(|sequence| {
                let mut packet = vec![0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0];
                packet.extend_from_slice(&[100, 64, 0, 1, 100, 64, 0, 2]);
                packet[4..6].copy_from_slice(&(sequence as u16).to_be_bytes());
                packet
            })
            .collect::<Vec<_>>();
        let mut inbound = InboundBatchScratch::default();
        let mut expected_peers = Vec::with_capacity(packets.len());
        for (sequence, packet) in packets.iter().enumerate() {
            let (sender, peer) = if sequence % 2 == 0 {
                (&first_sender, &first_source_public)
            } else {
                (&second_sender, &second_source_public)
            };
            let ciphertext = sender
                .lock()
                .await
                .encapsulate(packet)
                .expect("encrypt packet")
                .into_iter()
                .next()
                .expect("one wireguard data packet");
            inbound.datagrams.push(rustscale_magicsock::WgDatagram {
                peer: peer.clone(),
                data: ciphertext.into(),
            });
            expected_peers.push(peer.clone());
        }
        assert_eq!(
            inbound.datagrams.len(),
            rustscale_wg::WgPlaintextBatch::MAX_PACKETS
        );

        let tunnels = RwLock::new(HashMap::from([
            (first_source_public, first_receiver),
            (second_source_public, second_receiver),
        ]));
        assert!(collect_tun_inbound_batch(&tunnels, &mut inbound, &CancelToken::new()).await);

        // Reaching the exact batch capacity proves collection did not fail
        // with PlaintextBatchFull; each sequence number makes reordering
        // observable, and every plaintext slot keeps its sender identity.
        assert_eq!(
            inbound.plaintext.len(),
            rustscale_wg::WgPlaintextBatch::MAX_PACKETS
        );
        assert_eq!(inbound.plaintext.packets(), packets.as_slice());
        assert_eq!(inbound.plaintext_peers, expected_peers);
        assert!(inbound.replies.is_empty());
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
                    .expect("one wireguard data packet")
                    .into(),
            });
        }

        let tunnels = RwLock::new(HashMap::from([(a_public, receiver)]));
        let filter = Arc::new(std::sync::Mutex::new(Filter::allow_none()));
        let packet_drops = Arc::new(AtomicU64::new(0));
        let capture = crate::capture::new_slot();
        assert!(collect_tun_inbound_batch(&tunnels, &mut inbound, &CancelToken::new()).await);
        filter_tun_inbound_batch(&filter, &packet_drops, &capture, &mut inbound);

        assert!(
            inbound.plaintext.is_empty(),
            "dropped packets are not queued"
        );
        assert_eq!(packet_drops.load(std::sync::atomic::Ordering::Relaxed), 2);
    }

    #[test]
    fn inbound_filter_compacts_mixed_packets_and_aligned_peers_stably() {
        let first_peer = NodePrivate::generate().public();
        let dropped_peer = NodePrivate::generate().public();
        let last_peer = NodePrivate::generate().public();
        let first = vec![
            0x45, 0, 0, 20, 0, 1, 0, 0, 64, 17, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2,
        ];
        let last = vec![
            0x45, 0, 0, 20, 0, 3, 0, 0, 64, 17, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2,
        ];
        let mut inbound = InboundBatchScratch::default();
        for packet in [&first[..], &[0x10][..], &last[..]] {
            inbound.plaintext.push_copy(packet).unwrap();
        }
        inbound.plaintext_peers = vec![first_peer.clone(), dropped_peer, last_peer.clone()];
        let filter = Arc::new(std::sync::Mutex::new(Filter::allow_all()));
        let packet_drops = Arc::new(AtomicU64::new(0));
        filter_tun_inbound_batch(
            &filter,
            &packet_drops,
            &crate::capture::new_slot(),
            &mut inbound,
        );

        assert_eq!(inbound.plaintext.packets(), &[first, last]);
        assert_eq!(inbound.plaintext_peers, vec![first_peer, last_peer]);
        assert_eq!(packet_drops.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[test]
    fn receive_batch_is_capped_at_tun_batch_capacity() {
        assert_eq!(
            rustscale_wg::WgPlaintextBatch::MAX_PACKETS,
            rustscale_tun::TunPacketBatch::MAX_PACKETS
        );
        assert_eq!(
            rustscale_magicsock::WG_RECEIVE_BATCH_MAX_PACKETS,
            rustscale_tun::TunPacketBatch::MAX_PACKETS
        );
    }

    #[tokio::test]
    async fn replies_complete_before_one_failed_batch_write() {
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let tun = BatchProbe {
            events: events.clone(),
        };
        let peer = NodePrivate::generate().public();
        let mut inbound = InboundBatchScratch::default();
        inbound.plaintext.push_copy(&[1]).unwrap();
        inbound.plaintext.push_copy(&[2]).unwrap();
        inbound.replies = vec![(peer.clone(), 0, vec![3]), (peer, 0, vec![4])];
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
    async fn inbound_capture_precedes_mutating_write_and_reuses_slots_after_error() {
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let tun = BatchProbe {
            events: events.clone(),
        };
        let first = vec![
            0x45, 0, 0, 20, 0, 1, 0, 0, 64, 17, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2,
        ];
        let second = vec![
            0x45, 0, 0, 20, 0, 2, 0, 0, 64, 17, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2,
        ];
        let mut inbound = InboundBatchScratch::default();
        inbound.plaintext.push_copy(&first).unwrap();
        inbound.plaintext.push_copy(&second).unwrap();
        let first_slot = inbound.plaintext.packets()[0].as_ptr();
        let first_capacity = inbound.plaintext.packets()[0].capacity();
        let filter = Arc::new(std::sync::Mutex::new(Filter::allow_all()));
        let packet_drops = Arc::new(AtomicU64::new(0));
        let capture = crate::capture::new_slot();
        let sink = crate::capture::get_or_set(&capture);
        let (capture_tx, mut capture_rx) = mpsc::channel(4);
        let _handle = sink
            .register_output(crate::capture::ChannelOutput::new(capture_tx))
            .expect("register capture output");
        let _header = capture_rx.recv().await.expect("pcap header");
        inbound.plaintext_peers = vec![
            NodePrivate::generate().public(),
            NodePrivate::generate().public(),
        ];
        filter_tun_inbound_batch(&filter, &packet_drops, &capture, &mut inbound);
        flush_inbound_burst(&tun, &mut inbound, |_peer, _reply| async {}).await;

        let captured = capture_rx.recv().await.expect("first captured packet");
        assert_eq!(&captured[20..], first.as_slice());
        assert!(inbound.plaintext.is_empty());
        inbound.plaintext.push_copy(&first).unwrap();
        assert_eq!(inbound.plaintext.packets()[0], first);
        assert_eq!(inbound.plaintext.packets()[0].as_ptr(), first_slot);
        assert_eq!(inbound.plaintext.packets()[0].capacity(), first_capacity);
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
        let mut inbound = InboundBatchScratch::default();
        inbound.plaintext.push_copy(&[1]).unwrap();
        inbound.replies = vec![(peer.clone(), 0, vec![2]), (peer, 0, vec![3])];
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

    fn outbound_test_run(peer: NodePublic, packet: &[u8]) -> OutboundDatagramRun {
        let mut datagrams = rustscale_wg::WgDatagramBatch::new();
        datagrams.push_copy(packet);
        OutboundDatagramRun {
            peer: Some(peer),
            datagrams,
        }
    }

    #[tokio::test]
    async fn outbound_sender_overlaps_next_encryption_without_reordering_or_extra_ownership() {
        let source_private = NodePrivate::generate();
        let target_private = NodePrivate::generate();
        let peer = target_private.public();
        let source = Arc::new(Mutex::new(
            WgTunn::new(&source_private, &peer, 61).expect("source tunnel"),
        ));
        let target = Arc::new(Mutex::new(
            WgTunn::new(&target_private, &source_private.public(), 62).expect("target tunnel"),
        ));
        establish_tunnels(&source, &target).await;
        let first_packet = [
            0x45, 0, 0, 20, 0, 1, 0, 0, 64, 17, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2,
        ];
        let second_packet = [
            0x45, 0, 0, 20, 0, 2, 0, 0, 64, 17, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2,
        ];
        let tunnels = RwLock::new(HashMap::from([(peer.clone(), source.clone())]));
        let mut routes = RouteTable::default();
        routes.set_exit_node(peer.clone());
        let routes = RwLock::new(routes);
        let filter = std::sync::Mutex::new(Filter::allow_all());
        let capture = crate::capture::new_slot();
        let mut scratch = OutboundBatchScratch::default();
        let cancel = Arc::new(CancelToken::new());
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let release = Arc::new(tokio::sync::Notify::new());
        let transmitted = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
        let (completed_tx, mut completed_rx) = tokio::sync::mpsc::unbounded_channel();
        let first_send = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let mut pipeline = OutboundSendPipeline::start_with(cancel.clone(), {
            let release = release.clone();
            let transmitted = transmitted.clone();
            let first_send = first_send.clone();
            let completed_tx = completed_tx.clone();
            let mut entered = Some(entered_tx);
            move |run| {
                let release = release.clone();
                let transmitted = transmitted.clone();
                let completed_tx = completed_tx.clone();
                let block = first_send.swap(false, std::sync::atomic::Ordering::SeqCst);
                let entered = if block { entered.take() } else { None };
                Box::pin(async move {
                    if let Some(entered) = entered {
                        let _ = entered.send(());
                        release.notified().await;
                    }
                    transmitted
                        .lock()
                        .unwrap()
                        .extend(run.datagrams.packets().iter().cloned());
                    let _ = completed_tx.send(());
                })
            }
        });

        send_tun_batch_pipeline(
            &tunnels,
            &routes,
            &filter,
            &[first_packet.to_vec()],
            &mut scratch,
            &capture,
            &mut pipeline,
        )
        .await;
        entered_rx.await.expect("first send did not block");
        // N+1 returns only after the production route/filter/encapsulate path
        // has assigned its WG counter and handed the second owned batch to the
        // FIFO while N remains blocked in transport.
        send_tun_batch_pipeline(
            &tunnels,
            &routes,
            &filter,
            &[second_packet.to_vec()],
            &mut scratch,
            &capture,
            &mut pipeline,
        )
        .await;
        assert_eq!(
            pipeline.jobs.as_ref().expect("live sender").capacity(),
            0,
            "N+1 was not queued behind N"
        );
        assert!(
            transmitted.lock().unwrap().is_empty(),
            "N+1 transmitted before N"
        );
        assert!(
            pipeline.local.is_empty()
                && matches!(
                    pipeline.available.try_recv(),
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty)
                ),
            "a third owned WgDatagramBatch bypassed the two-buffer bound"
        );

        release.notify_one();
        // Completion notifications, rather than a short scheduling timeout,
        // prove that both FIFO sends reached transport before recycling.
        tokio::time::timeout(std::time::Duration::from_secs(2), completed_rx.recv())
            .await
            .expect("first transport send hung")
            .expect("first transport completion observer closed");
        tokio::time::timeout(std::time::Duration::from_secs(2), completed_rx.recv())
            .await
            .expect("second transport send hung")
            .expect("second transport completion observer closed");
        let first_recycled =
            tokio::time::timeout(std::time::Duration::from_secs(2), pipeline.acquire())
                .await
                .expect("first owned batch was not recycled")
                .expect("sender closed before recycle");
        let second_recycled =
            tokio::time::timeout(std::time::Duration::from_secs(2), pipeline.acquire())
                .await
                .expect("second owned batch was not recycled")
                .expect("sender closed before second recycle");
        assert!(first_recycled.datagrams.packets().is_empty());
        assert!(second_recycled.datagrams.packets().is_empty());
        assert_eq!(
            transmitted.lock().unwrap().len(),
            2,
            "both production-pipeline ciphertext runs were not transmitted"
        );
        let transmitted = transmitted.lock().unwrap().clone();
        assert_ne!(
            transmitted[0], transmitted[1],
            "distinct packets reused ciphertext"
        );
        assert_eq!(
            transmitted[0][..4],
            transmitted[1][..4],
            "WireGuard data packet framing changed"
        );
        assert!(
            u64::from_le_bytes(transmitted[0][8..16].try_into().unwrap())
                < u64::from_le_bytes(transmitted[1][8..16].try_into().unwrap()),
            "ciphertext and assigned counter order changed"
        );
        drop(first_recycled);
        drop(second_recycled);
        tokio::time::timeout(std::time::Duration::from_secs(2), pipeline.shutdown())
            .await
            .expect("sender leaked after its input closed");
    }

    #[tokio::test]
    async fn outbound_sender_cancels_while_transport_is_blocked() {
        let cancel = Arc::new(CancelToken::new());
        let (jobs_tx, jobs_rx) = mpsc::channel(1);
        let (available_tx, _available_rx) = mpsc::channel(2);
        let worker = tokio::spawn(outbound_send_worker(
            jobs_rx,
            available_tx,
            cancel.clone(),
            |_run| Box::pin(std::future::pending()),
        ));
        jobs_tx
            .send(OutboundSendJob::Run(outbound_test_run(
                NodePrivate::generate().public(),
                &[1],
            )))
            .await
            .unwrap();
        tokio::task::yield_now().await;
        cancel.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(2), worker)
            .await
            .expect("blocked outbound sender ignored cancellation")
            .expect("sender panicked");
    }

    #[tokio::test]
    async fn outbound_pipeline_shutdown_aborts_blocked_transport_without_shared_cancel() {
        let cancel = Arc::new(CancelToken::new());
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let mut entered = Some(entered_tx);
        let mut pipeline = OutboundSendPipeline::start_with(cancel.clone(), move |_run| {
            let entered = entered.take();
            Box::pin(async move {
                if let Some(entered) = entered {
                    let _ = entered.send(());
                }
                std::future::pending::<()>().await;
            })
        });
        let mut run = pipeline.acquire().await.expect("owned batch");
        run.peer = Some(NodePrivate::generate().public());
        run.datagrams.push_copy(&[1]);
        assert!(pipeline.queue(run).await);
        entered_rx.await.expect("blocked transport was not entered");
        tokio::time::timeout(std::time::Duration::from_secs(2), pipeline.shutdown())
            .await
            .expect("shutdown waited forever for blocked transport");
        assert!(
            !cancel.is_cancelled(),
            "pump shutdown must not cancel the shared lifecycle token"
        );
    }

    #[tokio::test]
    async fn outbound_pipeline_drop_aborts_blocked_transport_without_shared_cancel() {
        let cancel = Arc::new(CancelToken::new());
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
        let mut entered = Some(entered_tx);
        let mut dropped = Some(dropped_tx);
        let mut pipeline = OutboundSendPipeline::start_with(cancel.clone(), move |_run| {
            let entered = entered.take();
            let future_drop = DropNotify(dropped.take());
            Box::pin(async move {
                let _future_drop = future_drop;
                if let Some(entered) = entered {
                    let _ = entered.send(());
                }
                std::future::pending::<()>().await;
            })
        });
        let mut run = pipeline.acquire().await.expect("owned batch");
        run.peer = Some(NodePrivate::generate().public());
        run.datagrams.push_copy(&[1]);
        assert!(pipeline.queue(run).await);
        entered_rx.await.expect("blocked transport was not entered");

        drop(pipeline);
        tokio::time::timeout(std::time::Duration::from_secs(2), dropped_rx)
            .await
            .expect("dropping the pump leaked its blocked transport future")
            .expect("transport future drop observer was lost");
        assert!(
            !cancel.is_cancelled(),
            "pump drop must not cancel the shared lifecycle token"
        );
    }

    #[tokio::test]
    async fn outbound_pipeline_barrier_prevents_reply_or_timer_overtake() {
        let cancel = Arc::new(CancelToken::new());
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let release = Arc::new(tokio::sync::Notify::new());
        let sent = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut pipeline = OutboundSendPipeline::start_with(cancel, {
            let release = release.clone();
            let sent = sent.clone();
            let mut entered = Some(entered_tx);
            move |_run| {
                let release = release.clone();
                let sent = sent.clone();
                let entered = entered.take();
                Box::pin(async move {
                    sent.lock().unwrap().push("tun");
                    if let Some(entered) = entered {
                        let _ = entered.send(());
                        release.notified().await;
                    }
                })
            }
        });
        let mut run = pipeline.acquire().await.expect("owned batch");
        run.peer = Some(NodePrivate::generate().public());
        run.datagrams.push_copy(&[1]);
        assert!(pipeline.queue(run).await);
        entered_rx.await.expect("TUN send did not block");
        let no_reply = InboundBatchScratch::default();
        assert!(
            flush_outbound_before_replies(Some(&mut pipeline), &no_reply).await,
            "ordinary inbound data must not fence the outbound sender"
        );
        let mut reply = InboundBatchScratch::default();
        reply
            .replies
            .push((NodePrivate::generate().public(), 0, vec![1]));
        {
            let barrier = flush_outbound_before_replies(Some(&mut pipeline), &reply);
            tokio::pin!(barrier);
            tokio::select! {
                _ = &mut barrier => panic!("actual inbound reply passed a blocked TUN send"),
                () = tokio::task::yield_now() => {}
            }
            release.notify_one();
            assert!(barrier.await);
        }
        sent.lock().unwrap().push("reply-or-timer");
        assert_eq!(*sent.lock().unwrap(), ["tun", "reply-or-timer"]);
        pipeline.shutdown().await;
    }
}
