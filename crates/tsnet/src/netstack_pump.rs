#[allow(clippy::wildcard_imports)]
use super::*;

// ---------------------------------------------------------------------------
// Data-plane pumps
// ---------------------------------------------------------------------------

type TcpSegmentSignature = ([u8; 4], [u8; 4], u16, u16, u32, u8, u16);

// Match Magicsock's Linux sendmmsg/GSO ceiling so one route/filter/tunnel
// snapshot feeds one physical UDP submission without creating a second
// scheduler handoff inside the transport.
const NETSTACK_OUTBOUND_BATCH: usize = 128;
// Pure ACK bursts are intentionally below this threshold. A full batch with
// at least 64 KiB of plaintext represents bulk data worth dephasing from the
// next physical submission.
const NETSTACK_OUTBOUND_BULK_YIELD_BYTES: usize = 64 << 10;
const WG_TIMER_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);
const MAX_FORCED_NETSTACK_RX_GRO_SEGMENTS: usize = 128;

struct NetstackOutboundRun {
    peer: NodePublic,
    tunnel: Arc<Mutex<WgTunn>>,
    start: usize,
    end: usize,
}

#[derive(Default)]
struct NetstackInboundScratch {
    opened: rustscale_wg::WgPlaintextBatch,
    opened_peers: Vec<NodePublic>,
    keep: Vec<bool>,
    accepted: Vec<(NodePublic, rustscale_packet::PacketInfo)>,
    decrypted: Vec<Vec<u8>>,
    packets: Vec<Vec<u8>>,
    recycled: Vec<Vec<u8>>,
    peer: Option<NodePublic>,
    gro: rustscale_tun::TcpGroCoalescer,
}

#[derive(Default)]
struct NetstackOutboundScratch {
    packets: Vec<Vec<u8>>,
    routes: Vec<Option<NodePublic>>,
    runs: Vec<NetstackOutboundRun>,
    datagrams: rustscale_wg::WgDatagramBatch,
}

fn take_wg_timer_due(now: tokio::time::Instant, next_tick: &mut tokio::time::Instant) -> bool {
    if now < *next_tick {
        return false;
    }
    // Skip missed intervals. Timer work is maintenance, not a backlog that
    // should displace data-plane work after a delayed scheduler turn.
    *next_tick = now + WG_TIMER_INTERVAL;
    true
}

const fn should_yield_after_outbound_burst(
    packets: usize,
    bytes: usize,
    live_connections: usize,
    force_high_fanout: bool,
) -> bool {
    packets == NETSTACK_OUTBOUND_BATCH
        && bytes >= NETSTACK_OUTBOUND_BULK_YIELD_BYTES
        && live_connections > 0
        && (live_connections <= NETSTACK_OUTBOUND_BATCH || force_high_fanout)
}

#[derive(Default)]
struct NetstackPumpStats {
    lane: &'static str,
    enabled: bool,
    track_retransmits: bool,
    inbound_batches: u64,
    inbound_packets: u64,
    outbound_packets: u64,
    tcp_syn: u64,
    tcp_syn_ack: u64,
    tcp_ack: u64,
    tcp_fin: u64,
    tcp_rst: u64,
    tcp_retransmit: u64,
    rx_queue_high_water: usize,
    tx_queue_high_water: usize,
    live_connections: usize,
    pending_closes: usize,
    close_requests: usize,
    close_completions: usize,
    duplicate_close_requests: usize,
    next_snapshot_packets: u64,
    seen_segments: std::collections::HashSet<TcpSegmentSignature>,
    segment_order: std::collections::VecDeque<TcpSegmentSignature>,
}

impl NetstackPumpStats {
    fn new(lane: &'static str) -> Self {
        let track_retransmits =
            std::env::var_os("RUSTSCALE_NETSTACK_RETRANSMIT_DIAGNOSTICS").is_some();
        let enabled =
            track_retransmits || std::env::var_os("RUSTSCALE_NETSTACK_PUMP_DIAGNOSTICS").is_some();
        Self::with_options(lane, enabled, track_retransmits)
    }

    #[cfg(test)]
    fn with_retransmit_tracking(lane: &'static str, track_retransmits: bool) -> Self {
        Self::with_options(lane, true, track_retransmits)
    }

    fn with_options(lane: &'static str, enabled: bool, track_retransmits: bool) -> Self {
        Self {
            lane,
            enabled,
            track_retransmits,
            next_snapshot_packets: if enabled { 256 } else { 0 },
            ..Self::default()
        }
    }

    fn note_batches(&mut self, count: usize) {
        if !self.enabled {
            return;
        }
        self.inbound_batches = self.inbound_batches.saturating_add(count as u64);
    }

    fn note_connections(&mut self, stats: rustscale_netstack::ConnectionStats) {
        self.live_connections = stats.live_connections;
        if !self.enabled {
            return;
        }
        self.pending_closes = stats.pending_closes;
        self.close_requests = stats.close_requests;
        self.close_completions = stats.close_completions;
        self.duplicate_close_requests = stats.duplicate_close_requests;
    }

    fn note_packet(&mut self, inbound: bool, packet: &[u8]) {
        if !self.enabled {
            return;
        }
        let info = rustscale_packet::parse_packet(packet);
        self.note_packet_parsed(inbound, packet, info.as_ref());
    }

    fn note_packet_info(
        &mut self,
        inbound: bool,
        packet: &[u8],
        info: &rustscale_packet::PacketInfo,
    ) {
        if !self.enabled {
            return;
        }
        self.note_packet_parsed(inbound, packet, Some(info));
    }

    fn note_packet_parsed(
        &mut self,
        inbound: bool,
        packet: &[u8],
        info: Option<&rustscale_packet::PacketInfo>,
    ) {
        debug_assert!(self.enabled);
        if inbound {
            self.inbound_packets = self.inbound_packets.saturating_add(1);
        } else {
            self.outbound_packets = self.outbound_packets.saturating_add(1);
        }
        if let Some(info) = info {
            self.note_tcp(packet, info);
        }
        let total = self.inbound_packets.saturating_add(self.outbound_packets);
        if self.next_snapshot_packets != 0 && total >= self.next_snapshot_packets {
            self.emit("periodic");
            self.next_snapshot_packets = self.next_snapshot_packets.checked_mul(2).unwrap_or(0);
        }
    }

    fn note_queues(&mut self, queues: (usize, usize)) {
        if !self.enabled {
            return;
        }
        self.rx_queue_high_water = self.rx_queue_high_water.max(queues.0);
        self.tx_queue_high_water = self.tx_queue_high_water.max(queues.1);
    }

    fn note_tcp(&mut self, packet: &[u8], info: &rustscale_packet::PacketInfo) {
        if packet.len() < 40 || info.version != 4 || info.proto != rustscale_packet::TCP {
            return;
        }
        let ip_header = usize::from(packet[0] & 0x0f) * 4;
        if ip_header < 20 || packet.len() < ip_header + 20 {
            return;
        }
        let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]])).min(packet.len());
        let tcp = &packet[ip_header..];
        let tcp_header = usize::from(tcp[12] >> 4) * 4;
        if tcp_header < 20 || total_len < ip_header + tcp_header {
            return;
        }
        let flags = info.tcp_flags;
        let syn = flags & 0x02 != 0;
        let ack = flags & 0x10 != 0;
        if syn && ack {
            self.tcp_syn_ack = self.tcp_syn_ack.saturating_add(1);
        } else if syn {
            self.tcp_syn = self.tcp_syn.saturating_add(1);
        }
        if ack {
            self.tcp_ack = self.tcp_ack.saturating_add(1);
        }
        if flags & 0x01 != 0 {
            self.tcp_fin = self.tcp_fin.saturating_add(1);
        }
        if flags & 0x04 != 0 {
            self.tcp_rst = self.tcp_rst.saturating_add(1);
        }
        if !self.track_retransmits {
            return;
        }
        let payload_len = total_len - ip_header - tcp_header;
        if syn || flags & 0x01 != 0 || payload_len != 0 {
            let signature = (
                packet[12..16].try_into().unwrap(),
                packet[16..20].try_into().unwrap(),
                info.src_port,
                info.dst_port,
                u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
                flags,
                u16::try_from(payload_len).unwrap_or(u16::MAX),
            );
            if self.seen_segments.insert(signature) {
                self.segment_order.push_back(signature);
                if self.segment_order.len() > 32_768 {
                    if let Some(expired) = self.segment_order.pop_front() {
                        self.seen_segments.remove(&expired);
                    }
                }
            } else {
                self.tcp_retransmit = self.tcp_retransmit.saturating_add(1);
            }
        }
    }

    fn emit(&self, event: &str) {
        eprintln!(
            "rustscale: netstack_pump_stats event={event} lane={} inbound_batches={} inbound_packets={} outbound_packets={} tcp_syn={} tcp_syn_ack={} tcp_ack={} tcp_retransmit={} tcp_retransmit_tracking={} tcp_fin={} tcp_rst={} rx_queue_high_water={} tx_queue_high_water={} live_connections={} pending_closes={} close_requests={} close_completions={} duplicate_close_requests={}",
            self.lane,
            self.inbound_batches,
            self.inbound_packets,
            self.outbound_packets,
            self.tcp_syn,
            self.tcp_syn_ack,
            self.tcp_ack,
            self.tcp_retransmit,
            if self.track_retransmits { "on" } else { "off" },
            self.tcp_fin,
            self.tcp_rst,
            self.rx_queue_high_water,
            self.tx_queue_high_water,
            self.live_connections,
            self.pending_closes,
            self.close_requests,
            self.close_completions,
            self.duplicate_close_requests,
        );
    }
}

/// Netstack data-plane pump supervisor: netstack <-> WG <-> magicsock.
///
/// Receive/decrypt and ACK/encrypt run as separately scheduled tasks so their
/// CPU work can overlap. The supervisor retains the single lifecycle owner and
/// joins both lanes after cancellation. `JoinSet` also aborts both children if
/// the supervisor itself is aborted during shutdown or startup rollback.
pub(crate) async fn run_netstack_pump(
    magicsock: Arc<Magicsock>,
    wg_recv: mpsc::Receiver<rustscale_magicsock::WgReceiveBatch>,
    netstack: Arc<Netstack>,
    wg_tunnels: Arc<RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>>,
    route_table: Arc<RwLock<RouteTable>>,
    filter: Arc<std::sync::Mutex<Filter>>,
    packet_drops: Arc<AtomicU64>,
    cancel: Arc<CancelToken>,
    capture: crate::capture::CaptureSlot,
    peer_map: Arc<crate::peer_map::Runtime>,
) {
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(run_netstack_inbound_pump(
        magicsock.clone(),
        wg_recv,
        netstack.clone(),
        wg_tunnels.clone(),
        filter.clone(),
        packet_drops,
        cancel.clone(),
        capture.clone(),
        peer_map.clone(),
    ));
    tasks.spawn(run_netstack_outbound_pump(
        magicsock,
        netstack,
        wg_tunnels,
        route_table,
        filter,
        cancel.clone(),
        capture,
        peer_map,
    ));

    if let Some(Err(error)) = tasks.join_next().await {
        if !error.is_cancelled() {
            log::warn!("tsnet: netstack pump lane failed: {error}");
        }
    }
    cancel.cancel();
    while let Some(result) = tasks.join_next().await {
        if let Err(error) = result {
            if !error.is_cancelled() {
                log::warn!("tsnet: netstack pump lane failed during shutdown: {error}");
            }
        }
    }
}

/// Dedicated receive lane. Keeping this in its own Tokio task prevents
/// outbound encryption and socket submission from delaying kernel draining.
async fn run_netstack_inbound_pump(
    magicsock: Arc<Magicsock>,
    mut wg_recv: mpsc::Receiver<rustscale_magicsock::WgReceiveBatch>,
    netstack: Arc<Netstack>,
    wg_tunnels: Arc<RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>>,
    filter: Arc<std::sync::Mutex<Filter>>,
    packet_drops: Arc<AtomicU64>,
    cancel: Arc<CancelToken>,
    capture: crate::capture::CaptureSlot,
    peer_map: Arc<crate::peer_map::Runtime>,
) {
    let mut pump_stats = NetstackPumpStats::new("inbound");
    let mut inbound = NetstackInboundScratch::default();
    if let Ok(raw_segments) = std::env::var("RUSTSCALE_FORCE_NETSTACK_RX_GRO_SEGMENTS") {
        match raw_segments.parse::<usize>() {
            Ok(segments @ 1..=MAX_FORCED_NETSTACK_RX_GRO_SEGMENTS) => {
                inbound.gro.set_max_segments(segments);
                eprintln!(
                    "rustscale: netstack receive GRO forced to at most {segments} TCP segments by \
                     RUSTSCALE_FORCE_NETSTACK_RX_GRO_SEGMENTS"
                );
            }
            _ => eprintln!(
                "rustscale: ignoring invalid RUSTSCALE_FORCE_NETSTACK_RX_GRO_SEGMENTS={raw_segments:?}; \
                 expected 1..={MAX_FORCED_NETSTACK_RX_GRO_SEGMENTS}"
            ),
        }
    }
    let mut datagrams = Vec::with_capacity(rustscale_magicsock::WG_RECEIVE_BATCH_MAX_PACKETS);
    let mut deferred = None;
    loop {
        if cancel.is_cancelled() {
            break;
        }
        let batch = if let Some(batch) = deferred.take() {
            Some(batch)
        } else {
            tokio::select! {
                () = cancel.cancelled() => break,
                batch = wg_recv.recv() => batch,
            }
        };
        let Some(batch) = batch else {
            log::warn!("tsnet: magicsock wg channel closed");
            tokio::select! {
                () = cancel.cancelled() => break,
                () = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
            }
            continue;
        };
        let (next, received_batches) =
            take_immediate_netstack_receive_batches(batch, &mut wg_recv, &mut datagrams);
        deferred = next;
        if pump_stats.enabled {
            pump_stats.note_connections(netstack.connection_stats());
        }
        handle_inbound_wg_batch(
            &magicsock,
            &wg_tunnels,
            &datagrams,
            received_batches,
            &netstack,
            &filter,
            &packet_drops,
            &capture,
            &peer_map,
            &mut pump_stats,
            &mut inbound,
        )
        .await;
        datagrams.clear();
    }
}

/// Combine immediately-ready whole handoff items into one bounded decrypt
/// turn. Linux UDP GRO can expand one kernel message to a full 128-packet
/// item, while uncoalesced peers commonly publish one or two packets at a
/// time. Draining those small items here releases their packet credits and
/// amortizes authorization and tunnel locking without splitting or reordering
/// a publisher-owned batch.
fn take_immediate_netstack_receive_batches(
    first: rustscale_magicsock::WgReceiveBatch,
    receiver: &mut mpsc::Receiver<rustscale_magicsock::WgReceiveBatch>,
    output: &mut Vec<rustscale_magicsock::WgDatagram>,
) -> (Option<rustscale_magicsock::WgReceiveBatch>, usize) {
    debug_assert!(output.is_empty());
    output.extend(first.into_datagrams());
    let mut received_batches = 1;
    while output.len() < rustscale_magicsock::WG_RECEIVE_BATCH_MAX_PACKETS {
        let Ok(next) = receiver.try_recv() else {
            break;
        };
        if next.len() > rustscale_magicsock::WG_RECEIVE_BATCH_MAX_PACKETS - output.len() {
            return (Some(next), received_batches);
        }
        output.extend(next.into_datagrams());
        received_batches += 1;
    }
    (None, received_batches)
}

/// Dedicated outbound/timer lane. A retained Notify permit plus the explicit
/// queue check prevent missed wakeups after a bounded drain.
async fn run_netstack_outbound_pump(
    magicsock: Arc<Magicsock>,
    netstack: Arc<Netstack>,
    wg_tunnels: Arc<RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>>,
    route_table: Arc<RwLock<RouteTable>>,
    filter: Arc<std::sync::Mutex<Filter>>,
    cancel: Arc<CancelToken>,
    capture: crate::capture::CaptureSlot,
    peer_map: Arc<crate::peer_map::Runtime>,
) {
    let tx_notify = netstack.tx_notify();
    let mut next_wg_tick = tokio::time::Instant::now() + WG_TIMER_INTERVAL;
    let mut pump_stats = NetstackPumpStats::new("outbound");
    let mut outbound = NetstackOutboundScratch::default();
    let force_high_fanout_yield =
        std::env::var_os("RUSTSCALE_FORCE_HIGH_FANOUT_OUTBOUND_YIELD").is_some();
    if force_high_fanout_yield {
        eprintln!(
            "rustscale: high-fanout outbound batch yielding forced by \
             RUSTSCALE_FORCE_HIGH_FANOUT_OUTBOUND_YIELD"
        );
    }

    loop {
        if cancel.is_cancelled() {
            break;
        }
        pump_stats.note_connections(netstack.connection_stats());
        let mut timer_due = take_wg_timer_due(tokio::time::Instant::now(), &mut next_wg_tick);

        // A Notify retains at most one permit. After a bounded outbound
        // drain, more than one packet can remain even though its notification
        // was consumed, so do not sleep while the queue is still non-empty.
        if !netstack.has_tx_packets() && !timer_due {
            tokio::select! {
                () = cancel.cancelled() => break,
                () = tx_notify.notified() => {}
                () = tokio::time::sleep_until(next_wg_tick) => {}
            }
            timer_due = take_wg_timer_due(tokio::time::Instant::now(), &mut next_wg_tick);
        }

        // Drain one bounded burst, then route, encrypt, and submit it by
        // contiguous peer run. This preserves packet order and fairness while
        // avoiding four async lock acquisitions plus one socket submission per
        // packet on the embedded firehose path.
        outbound.packets.clear();
        let mut outbound_bytes = 0usize;
        if pump_stats.enabled {
            pump_stats.note_queues(netstack.data_plane_queue_depths());
        }
        while outbound.packets.len() < NETSTACK_OUTBOUND_BATCH {
            let Some(packet) = netstack.pop_tx() else {
                break;
            };
            outbound_bytes = outbound_bytes.saturating_add(packet.len());
            pump_stats.note_packet(false, &packet);
            outbound.packets.push(packet);
        }
        if !outbound.packets.is_empty() {
            let _map = peer_map.gate.read().await;
            send_netstack_outbound_batch(
                &magicsock,
                &wg_tunnels,
                &route_table,
                &filter,
                &capture,
                &mut outbound,
            )
            .await;

            // sendmmsg can remain immediately writable across consecutive
            // payload-heavy batches. Dephase those submissions without
            // delaying the small pure-ACK batches that sustain TCP progress.
            // Above one connection per batch, fanout already rotates work
            // across multiple submissions and an extra yield costs bulk rate.
            if should_yield_after_outbound_burst(
                outbound.packets.len(),
                outbound_bytes,
                pump_stats.live_connections,
                force_high_fanout_yield,
            ) {
                tokio::task::yield_now().await;
            }
        }

        if timer_due {
            let _map = peer_map.gate.read().await;
            tick_wg_timers(&magicsock, &wg_tunnels).await;
        }
    }
}

fn build_netstack_outbound_runs(
    routes: &[Option<NodePublic>],
    tunnels: &HashMap<NodePublic, Arc<Mutex<WgTunn>>>,
    runs: &mut Vec<NetstackOutboundRun>,
) {
    runs.clear();
    let mut start = 0;
    while start < routes.len() {
        let route = routes[start].clone();
        let mut end = start + 1;
        while end < routes.len() && routes[end] == route {
            end += 1;
        }
        if let Some((peer, tunnel)) =
            route.and_then(|peer| tunnels.get(&peer).cloned().map(|tunnel| (peer, tunnel)))
        {
            runs.push(NetstackOutboundRun {
                peer,
                tunnel,
                start,
                end,
            });
        }
        start = end;
    }
}

async fn send_netstack_outbound_batch(
    magicsock: &Magicsock,
    wg_tunnels: &RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>,
    route_table: &RwLock<RouteTable>,
    filter: &std::sync::Mutex<Filter>,
    capture: &crate::capture::CaptureSlot,
    scratch: &mut NetstackOutboundScratch,
) {
    scratch.routes.clear();
    {
        let routes = route_table.read().await;
        let mut filter = filter.lock().unwrap();
        for packet in &scratch.packets {
            filter.update_outbound(packet);
            crate::capture::log_packet(
                capture,
                crate::capture::CapturePath::SynthesizedToPeer,
                packet,
            );
            scratch
                .routes
                .push(WgTunn::dst_address(packet).and_then(|dst| routes.lookup(dst)));
        }
    }

    {
        let tunnels = wg_tunnels.read().await;
        build_netstack_outbound_runs(&scratch.routes, &tunnels, &mut scratch.runs);
    }
    for run in scratch.runs.drain(..) {
        scratch.datagrams.clear();
        {
            let mut tunnel = run.tunnel.lock().await;
            let _ = tunnel.encapsulate_batch_into(
                &scratch.packets[run.start..run.end],
                &mut scratch.datagrams,
            );
        }
        let _ = magicsock
            .send_batch(run.peer, scratch.datagrams.packets())
            .await;
    }
}

/// Process one bounded ordered receive burst with the same per-datagram
/// semantics as the former scalar channel consumer.
async fn handle_inbound_wg_batch(
    magicsock: &Magicsock,
    wg_tunnels: &RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>,
    datagrams: &[rustscale_magicsock::WgDatagram],
    received_batches: usize,
    netstack: &Netstack,
    filter: &std::sync::Mutex<Filter>,
    packet_drops: &AtomicU64,
    capture: &crate::capture::CaptureSlot,
    peer_map: &crate::peer_map::Runtime,
    pump_stats: &mut NetstackPumpStats,
    scratch: &mut NetstackInboundScratch,
) {
    let _map = peer_map.gate.read().await;
    pump_stats.note_batches(received_batches);
    debug_assert!(scratch.opened.is_empty());
    debug_assert!(scratch.opened_peers.is_empty());
    debug_assert!(scratch.decrypted.is_empty());
    debug_assert!(scratch.recycled.is_empty());
    netstack.take_recycled_rx_buffers(
        &mut scratch.recycled,
        rustscale_wg::WgPlaintextBatch::MAX_PACKETS,
    );
    scratch.opened.refill_from(&mut scratch.recycled);
    scratch.accepted.clear();
    collect_inbound_wg_datagrams(
        magicsock,
        wg_tunnels,
        datagrams,
        &mut scratch.opened,
        &mut scratch.opened_peers,
    )
    .await;

    if !scratch.opened.is_empty() {
        debug_assert_eq!(scratch.opened.len(), scratch.opened_peers.len());
        let ownership = peer_map.packet_source_snapshot();
        let mut filt = filter.lock().unwrap();
        scratch.keep.clear();
        for (peer, pt) in scratch.opened_peers.drain(..).zip(scratch.opened.packets()) {
            let Some(info) = rustscale_packet::parse_packet(pt) else {
                packet_drops.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                scratch.keep.push(false);
                continue;
            };
            if !ownership.matches(&peer, info.src) || filt.check_in_info(&info).is_drop() {
                packet_drops.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                scratch.keep.push(false);
                continue;
            }
            scratch.keep.push(true);
            scratch.accepted.push((peer, info));
        }
        let mut index = 0;
        scratch.opened.retain_mut(|_| {
            let keep = scratch.keep[index];
            index += 1;
            keep
        });
        debug_assert_eq!(scratch.opened.len(), scratch.accepted.len());
    }
    scratch.opened_peers.clear();
    scratch.opened.drain_into(&mut scratch.decrypted);

    let mut accepted = std::mem::take(&mut scratch.accepted);
    let mut decrypted = std::mem::take(&mut scratch.decrypted);
    for ((peer, info), pt) in accepted.drain(..).zip(decrypted.drain(..)) {
        crate::capture::log_packet(
            capture,
            crate::capture::CapturePath::SynthesizedToLocal,
            &pt,
        );
        pump_stats.note_packet_info(true, &pt, &info);
        if scratch
            .peer
            .as_ref()
            .is_some_and(|current| current != &peer)
        {
            flush_netstack_inbound(netstack, scratch);
        }
        if scratch.peer.is_none() {
            scratch.peer = Some(peer);
        }
        scratch.packets.push(pt);
    }
    flush_netstack_inbound(netstack, scratch);
    scratch.accepted = accepted;
    scratch.decrypted = decrypted;
    if pump_stats.enabled {
        pump_stats.note_queues(netstack.data_plane_queue_depths());
    }
}

fn flush_netstack_inbound(netstack: &Netstack, scratch: &mut NetstackInboundScratch) {
    let Some(peer) = scratch.peer.take() else {
        debug_assert!(scratch.packets.is_empty());
        return;
    };
    scratch
        .gro
        .coalesce_recycling(&mut scratch.packets, &mut scratch.recycled);
    scratch.opened.refill_from(&mut scratch.recycled);
    netstack.push_rx_batch_from(&mut scratch.packets, peer);
}

/// Decapsulate contiguous same-peer/same-generation runs while acquiring the
/// tunnel map, tunnel mutex, and authorization delivery guard once per run.
/// Per-packet authorization and delivery decisions remain ordered. Protocol
/// replies are sent only after all guards have been dropped.
async fn collect_inbound_wg_datagrams(
    magicsock: &Magicsock,
    wg_tunnels: &RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>,
    datagrams: &[rustscale_magicsock::WgDatagram],
    plaintext: &mut rustscale_wg::WgPlaintextBatch,
    plaintext_peers: &mut Vec<NodePublic>,
) {
    let mut start = 0;
    while start < datagrams.len() {
        let peer = datagrams[start].peer.clone();
        let generation = datagrams[start].authorization_generation();
        let end = contiguous_receive_run_end(datagrams, start);

        if magicsock.is_authorization_current(&peer, generation) {
            let tunnel = {
                let tunnels = wg_tunnels.read().await;
                tunnels.get(&peer).cloned()
            };
            if let Some(tunnel) = tunnel {
                let mut replies = Vec::new();
                let mut authenticated = Vec::new();
                {
                    // The caller holds peer_map.gate. This second guard keeps
                    // magicsock's generation stable through the entire ordered
                    // plaintext handoff for this same-peer/same-generation run,
                    // so one revalidation covers every datagram below. Acquire
                    // it before the peer tunnel mutex so no mutex is held across
                    // this await.
                    let _delivery = magicsock.authorization_delivery_guard().await;
                    if magicsock.is_authorization_current(&peer, generation) {
                        let mut tunnel = tunnel.lock().await;
                        for (offset, datagram) in datagrams[start..end].iter().enumerate() {
                            let before = plaintext.len();
                            if let Ok(protocol_replies) =
                                tunnel.decapsulate_into(&datagram.data, plaintext)
                            {
                                authenticated.push(start + offset);
                                for _ in before..plaintext.len() {
                                    plaintext_peers.push(peer.clone());
                                }
                                replies.extend(protocol_replies);
                            }
                        }
                    }
                }
                magicsock.note_authenticated_wg_transports(datagrams, &authenticated);
                for reply in replies {
                    if !magicsock.is_authorization_current(&peer, generation) {
                        break;
                    }
                    let _ = magicsock.send(peer.clone(), &reply).await;
                }
            }
        }
        start = end;
    }
}

#[cfg(test)]
async fn handle_inbound_wg_datagrams(
    magicsock: &Magicsock,
    wg_tunnels: &RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>,
    datagrams: &[rustscale_magicsock::WgDatagram],
    mut deliver: impl FnMut(NodePublic, Vec<u8>),
) {
    let mut plaintext = rustscale_wg::WgPlaintextBatch::new();
    let mut peers = Vec::new();
    collect_inbound_wg_datagrams(magicsock, wg_tunnels, datagrams, &mut plaintext, &mut peers)
        .await;
    let mut packets = Vec::new();
    plaintext.drain_into(&mut packets);
    for (peer, packet) in peers.into_iter().zip(packets) {
        deliver(peer, packet);
    }
}

fn contiguous_receive_run_end(
    datagrams: &[rustscale_magicsock::WgDatagram],
    start: usize,
) -> usize {
    let peer = &datagrams[start].peer;
    let generation = datagrams[start].authorization_generation();
    let mut end = start + 1;
    while end < datagrams.len()
        && datagrams[end].peer == *peer
        && datagrams[end].authorization_generation() == generation
    {
        end += 1;
    }
    end
}

/// Handle one datagram through the same grouped implementation.
#[cfg(test)]
async fn handle_inbound_wg(
    magicsock: &Magicsock,
    wg_tunnels: &RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>,
    dgram: &rustscale_magicsock::WgDatagram,
    deliver: impl FnMut(NodePublic, Vec<u8>),
) {
    handle_inbound_wg_datagrams(magicsock, wg_tunnels, std::slice::from_ref(dgram), deliver).await;
}

/// Decapsulate one TUN-bound datagram and retain accepted plaintext and
/// protocol replies for the caller's batch boundary. No async device or
/// magicsock I/O occurs here, so tunnel and filter guards are always dropped
/// before those operations.
#[cfg(test)]
pub(crate) async fn collect_tun_inbound(
    wg_tunnels: &RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>,
    filter: &Arc<std::sync::Mutex<Filter>>,
    packet_drops: &Arc<AtomicU64>,
    dgram: &rustscale_magicsock::WgDatagram,
    capture: &crate::capture::CaptureSlot,
    plaintext: &mut Vec<Vec<u8>>,
    replies: &mut Vec<(NodePublic, Vec<u8>)>,
) {
    let tunn = {
        let tunnels = wg_tunnels.read().await;
        tunnels.get(&dgram.peer).cloned()
    };
    if let Some(tunn) = tunn {
        let decap_result = {
            let mut t = tunn.lock().await;
            t.decapsulate(&dgram.data)
        };
        if let Ok(decap) = decap_result {
            if let Some(pt) = decap.plaintext {
                let dropped = {
                    let mut filt = filter.lock().unwrap();
                    filt.check_in(&pt).is_drop()
                };
                if dropped {
                    packet_drops.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                } else {
                    // Capture before Linux write-side GRO is allowed to
                    // rewrite the packet's offload and transport headers.
                    crate::capture::log_packet(capture, crate::capture::CapturePath::FromPeer, &pt);
                    plaintext.push(pt);
                }
            }
            for reply in decap.replies {
                replies.push((dgram.peer.clone(), reply));
            }
        }
    }
}

/// Tick WG timers for all peers and send any resulting datagrams.
///
/// Collects all timer-generated datagrams while holding the read lock, then
/// releases the lock before sending. This prevents blocking `spawn_map_update_task`
/// (which needs a write lock to add new peers) during the potentially many
/// `magicsock.send().await` calls.
pub(crate) async fn tick_wg_timers(
    magicsock: &Magicsock,
    wg_tunnels: &RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>,
) {
    let pending: Vec<(NodePublic, Vec<u8>)> = {
        let tunnels = wg_tunnels.read().await;
        let mut out = Vec::new();
        for (peer_key, tunn) in tunnels.iter() {
            let mut t = tunn.lock().await;
            for dg in t.tick_timers() {
                out.push((peer_key.clone(), dg));
            }
        }
        out
    };
    for (peer_key, dg) in pending {
        let _ = magicsock.send(peer_key, &dg).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustscale_key::{DiscoPrivate, NodePrivate};

    #[test]
    fn wireguard_timer_skips_missed_intervals_without_replaying_backlog() {
        let start = tokio::time::Instant::now();
        let mut next = start + WG_TIMER_INTERVAL;

        assert!(!take_wg_timer_due(
            start + WG_TIMER_INTERVAL - std::time::Duration::from_nanos(1),
            &mut next
        ));
        assert!(take_wg_timer_due(start + WG_TIMER_INTERVAL, &mut next));
        assert_eq!(next, start + WG_TIMER_INTERVAL * 2);
        assert!(!take_wg_timer_due(
            start + WG_TIMER_INTERVAL + std::time::Duration::from_nanos(1),
            &mut next
        ));

        let delayed = start + WG_TIMER_INTERVAL * 8;
        assert!(take_wg_timer_due(delayed, &mut next));
        assert_eq!(next, delayed + WG_TIMER_INTERVAL);
        assert!(!take_wg_timer_due(delayed, &mut next));
    }

    #[test]
    fn outbound_burst_yield_requires_a_full_payload_heavy_batch() {
        assert!(!should_yield_after_outbound_burst(
            NETSTACK_OUTBOUND_BATCH - 1,
            NETSTACK_OUTBOUND_BULK_YIELD_BYTES,
            100,
            false
        ));
        assert!(!should_yield_after_outbound_burst(
            NETSTACK_OUTBOUND_BATCH,
            NETSTACK_OUTBOUND_BATCH * 80,
            100,
            false
        ));
        assert!(!should_yield_after_outbound_burst(
            NETSTACK_OUTBOUND_BATCH,
            NETSTACK_OUTBOUND_BULK_YIELD_BYTES - 1,
            100,
            false
        ));
        assert!(should_yield_after_outbound_burst(
            NETSTACK_OUTBOUND_BATCH,
            NETSTACK_OUTBOUND_BULK_YIELD_BYTES,
            100,
            false
        ));
        assert!(!should_yield_after_outbound_burst(
            NETSTACK_OUTBOUND_BATCH,
            NETSTACK_OUTBOUND_BULK_YIELD_BYTES,
            0,
            false
        ));
        assert!(!should_yield_after_outbound_burst(
            NETSTACK_OUTBOUND_BATCH,
            NETSTACK_OUTBOUND_BULK_YIELD_BYTES,
            NETSTACK_OUTBOUND_BATCH + 1,
            false
        ));
        assert!(should_yield_after_outbound_burst(
            NETSTACK_OUTBOUND_BATCH,
            NETSTACK_OUTBOUND_BULK_YIELD_BYTES,
            NETSTACK_OUTBOUND_BATCH + 1,
            true
        ));
    }

    #[test]
    fn netstack_outbound_runs_preserve_route_order_and_missing_boundaries() {
        let local = NodePrivate::generate();
        let first_private = NodePrivate::generate();
        let second_private = NodePrivate::generate();
        let first = first_private.public();
        let second = second_private.public();
        let first_tunnel = Arc::new(Mutex::new(
            WgTunn::new(&local, &first, 1).expect("first tunnel"),
        ));
        let second_tunnel = Arc::new(Mutex::new(
            WgTunn::new(&local, &second, 2).expect("second tunnel"),
        ));
        let tunnels = HashMap::from([
            (first.clone(), first_tunnel.clone()),
            (second.clone(), second_tunnel.clone()),
        ]);
        let missing = NodePrivate::generate().public();
        let routes = vec![
            Some(first.clone()),
            Some(first.clone()),
            None,
            Some(first.clone()),
            Some(missing),
            Some(second.clone()),
            Some(second.clone()),
        ];
        let mut runs = Vec::new();

        build_netstack_outbound_runs(&routes, &tunnels, &mut runs);

        assert_eq!(runs.len(), 3);
        assert_eq!((runs[0].start, runs[0].end), (0, 2));
        assert_eq!(runs[0].peer, first);
        assert!(Arc::ptr_eq(&runs[0].tunnel, &first_tunnel));
        assert_eq!((runs[1].start, runs[1].end), (3, 4));
        assert_eq!(runs[1].peer, first);
        assert_eq!((runs[2].start, runs[2].end), (5, 7));
        assert_eq!(runs[2].peer, second);
        assert!(Arc::ptr_eq(&runs[2].tunnel, &second_tunnel));
    }

    #[test]
    fn pump_diagnostics_classify_duplicate_tcp_control_segments() {
        let mut syn = vec![0u8; 40];
        syn[0] = 0x45;
        syn[2..4].copy_from_slice(&40u16.to_be_bytes());
        syn[9] = 6;
        syn[12..16].copy_from_slice(&[100, 64, 0, 1]);
        syn[16..20].copy_from_slice(&[100, 64, 0, 2]);
        syn[20..22].copy_from_slice(&49152u16.to_be_bytes());
        syn[22..24].copy_from_slice(&5201u16.to_be_bytes());
        syn[24..28].copy_from_slice(&7u32.to_be_bytes());
        syn[32] = 5 << 4;
        syn[33] = 0x02;

        let mut stats = NetstackPumpStats::with_retransmit_tracking("test", true);
        stats.note_packet(true, &syn);
        stats.note_queues((1, 0));
        stats.note_packet(true, &syn);
        stats.note_queues((2, 0));
        assert_eq!(stats.tcp_syn, 2);
        assert_eq!(stats.tcp_retransmit, 1);
        assert_eq!(stats.rx_queue_high_water, 2);
    }

    #[test]
    fn pump_retransmit_history_is_opt_in() {
        let mut packet = vec![0u8; 41];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&41u16.to_be_bytes());
        packet[9] = 6;
        packet[20..22].copy_from_slice(&1u16.to_be_bytes());
        packet[22..24].copy_from_slice(&2u16.to_be_bytes());
        packet[32] = 5 << 4;
        packet[33] = 0x10;

        let mut disabled = NetstackPumpStats::with_retransmit_tracking("test", false);
        disabled.note_packet(true, &packet);
        disabled.note_packet(true, &packet);
        assert_eq!(disabled.tcp_retransmit, 0);
        assert!(disabled.seen_segments.is_empty());
        assert!(disabled.segment_order.is_empty());

        let mut enabled = NetstackPumpStats::with_retransmit_tracking("test", true);
        enabled.note_packet(true, &packet);
        enabled.note_packet(true, &packet);
        assert_eq!(enabled.tcp_retransmit, 1);
        assert_eq!(enabled.seen_segments.len(), 1);
        assert_eq!(enabled.segment_order.len(), 1);
    }

    #[test]
    fn pump_packet_diagnostics_are_inert_when_disabled() {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40u16.to_be_bytes());
        packet[9] = 6;
        packet[32] = 5 << 4;
        packet[33] = 0x10;

        let mut disabled = NetstackPumpStats::with_options("test", false, false);
        disabled.note_batches(3);
        disabled.note_packet(true, &packet);
        disabled.note_queues((7, 9));

        assert_eq!(disabled.inbound_batches, 0);
        assert_eq!(disabled.inbound_packets, 0);
        assert_eq!(disabled.tcp_ack, 0);
        assert_eq!(disabled.rx_queue_high_water, 0);
        assert_eq!(disabled.tx_queue_high_water, 0);
        assert_eq!(disabled.next_snapshot_packets, 0);
    }

    #[test]
    fn immediate_netstack_receive_batches_preserve_order_and_defer_whole_item() {
        fn batch(
            peer: &NodePublic,
            ids: std::ops::Range<usize>,
        ) -> rustscale_magicsock::WgReceiveBatch {
            rustscale_magicsock::WgReceiveBatch::from_datagrams_for_test(
                ids.map(|id| rustscale_magicsock::WgDatagram {
                    peer: peer.clone(),
                    data: u16::try_from(id).unwrap().to_be_bytes().to_vec().into(),
                })
                .collect(),
            )
        }

        fn ids(datagrams: &[rustscale_magicsock::WgDatagram]) -> Vec<u16> {
            datagrams
                .iter()
                .map(|datagram| {
                    let bytes = datagram.data.as_ref();
                    u16::from_be_bytes(bytes.try_into().unwrap())
                })
                .collect()
        }

        let peer = NodePrivate::generate().public();
        let first = batch(&peer, 0..3);
        let (send, mut receive) = mpsc::channel(3);
        send.try_send(batch(&peer, 3..127)).unwrap();
        send.try_send(batch(&peer, 127..129)).unwrap();
        send.try_send(batch(&peer, 129..130)).unwrap();

        let mut output = Vec::new();
        let (deferred, received_batches) =
            take_immediate_netstack_receive_batches(first, &mut receive, &mut output);
        assert_eq!(received_batches, 2);
        assert_eq!(ids(&output), (0..127).collect::<Vec<_>>());

        output.clear();
        let (deferred, received_batches) = take_immediate_netstack_receive_batches(
            deferred.expect("nonfitting item is deferred whole"),
            &mut receive,
            &mut output,
        );
        assert!(deferred.is_none());
        assert_eq!(received_batches, 2);
        assert_eq!(ids(&output), (127..130).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn userspace_gro_packet_larger_than_mtu_reaches_tcp_stream() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let a_ip = std::net::Ipv4Addr::new(100, 64, 0, 1);
        let b_ip = std::net::Ipv4Addr::new(100, 64, 0, 2);
        let a_net = Arc::new(Netstack::new(a_ip, DEFAULT_MTU).unwrap());
        let b_net = Arc::new(Netstack::new(b_ip, DEFAULT_MTU).unwrap());
        let a_pump = Arc::clone(&a_net);
        let b_pump = Arc::clone(&b_net);
        let pump = tokio::spawn(async move {
            let a_tx = a_pump.tx_notify();
            let b_tx = b_pump.tx_notify();
            loop {
                let mut did_work = false;
                while let Some(packet) = a_pump.pop_tx() {
                    did_work = true;
                    b_pump.push_rx(packet);
                }
                while let Some(packet) = b_pump.pop_tx() {
                    did_work = true;
                    a_pump.push_rx(packet);
                }
                if !did_work {
                    tokio::select! {
                        () = a_tx.notified() => {}
                        () = b_tx.notified() => {}
                    }
                }
            }
        });

        let mut listener = b_net.listen(41002).await.unwrap();
        let dial_net = Arc::clone(&a_net);
        let dial = tokio::spawn(async move {
            dial_net
                .dial(std::net::SocketAddr::new(b_ip.into(), 41002))
                .await
                .unwrap()
        });
        let mut server = tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
            .await
            .expect("accept timed out")
            .unwrap();
        let mut client = dial.await.unwrap();
        pump.abort();
        let _ = pump.await;
        // The dial future completes when A receives SYN-ACK; finish forwarding
        // its final ACK before isolating the A -> B data packets below.
        loop {
            let mut did_work = false;
            while let Some(packet) = a_net.pop_tx() {
                did_work = true;
                b_net.push_rx(packet);
            }
            while let Some(packet) = b_net.pop_tx() {
                did_work = true;
                a_net.push_rx(packet);
            }
            if !did_work {
                tokio::task::yield_now().await;
                if !a_net.has_tx_packets() && !b_net.has_tx_packets() {
                    break;
                }
            }
        }

        let payload = vec![0xA5; (DEFAULT_MTU - 40) * 6];
        client.write_all(&payload).await.unwrap();
        let mut packets = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                a_net.tx_notify().notified().await;
                while let Some(packet) = a_net.pop_tx() {
                    packets.push(packet);
                }
                let tcp_payload: usize = packets
                    .iter()
                    .map(|packet| {
                        let ip_len = usize::from(packet[0] & 0x0f) * 4;
                        let tcp_len = usize::from(packet[ip_len + 12] >> 4) * 4;
                        packet.len() - ip_len - tcp_len
                    })
                    .sum();
                if tcp_payload >= payload.len() {
                    break;
                }
            }
        })
        .await
        .expect("sender did not emit the full payload");

        let mut gro = rustscale_tun::TcpGroCoalescer::new();
        gro.coalesce(&mut packets);
        assert!(
            packets.iter().any(|packet| packet.len() > DEFAULT_MTU),
            "GRO did not materialize a packet larger than the device MTU"
        );
        for packet in packets {
            b_net.push_rx(packet);
        }

        let mut received = vec![0; payload.len()];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            server.read_exact(&mut received),
        )
        .await
        .expect("GRO packet was not accepted by smoltcp")
        .unwrap();
        assert_eq!(received, payload);
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
    }

    async fn encrypt(sender: &Arc<Mutex<WgTunn>>, packet: &[u8]) -> Vec<u8> {
        sender
            .lock()
            .await
            .encapsulate(packet)
            .expect("encrypt packet")
            .into_iter()
            .next()
            .expect("one WireGuard data packet")
    }

    #[tokio::test]
    async fn netstack_batch_delivery_matches_scalar_order() {
        let source_private = NodePrivate::generate();
        let target_private = NodePrivate::generate();
        let source_public = source_private.public();
        let target_public = target_private.public();
        let sender = Arc::new(Mutex::new(
            WgTunn::new(&source_private, &target_public, 1).expect("source tunnel"),
        ));
        let receiver = Arc::new(Mutex::new(
            WgTunn::new(&target_private, &source_public, 2).expect("target tunnel"),
        ));
        establish_tunnels(&sender, &receiver).await;

        let plaintext: Vec<Vec<u8>> = (0..rustscale_magicsock::WG_RECEIVE_BATCH_MAX_PACKETS)
            .map(|id| {
                vec![
                    0x45,
                    0,
                    0,
                    20,
                    (id >> 8) as u8,
                    id as u8,
                    0,
                    0,
                    64,
                    17,
                    0,
                    0,
                    100,
                    64,
                    0,
                    1,
                    100,
                    64,
                    0,
                    2,
                ]
            })
            .collect();
        let mut batch = Vec::new();
        let mut scalar = Vec::new();
        for packet in &plaintext {
            batch.push(rustscale_magicsock::WgDatagram {
                peer: source_public.clone(),
                data: encrypt(&sender, packet).await.into(),
            });
        }
        for packet in &plaintext {
            scalar.push(rustscale_magicsock::WgDatagram {
                peer: source_public.clone(),
                data: encrypt(&sender, packet).await.into(),
            });
        }

        let (magicsock, _receive) = Magicsock::new(rustscale_magicsock::MagicsockConfig {
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
        .expect("magicsock without network I/O");
        magicsock
            .set_netmap(vec![rustscale_tailcfg::Node {
                Key: source_public.clone(),
                ..Default::default()
            }])
            .await
            .unwrap();
        batch = batch
            .into_iter()
            .map(|datagram| {
                magicsock
                    .authorized_wg_datagram(datagram.peer, datagram.data.as_ref().to_vec())
                    .unwrap()
            })
            .collect();
        scalar = scalar
            .into_iter()
            .map(|datagram| {
                magicsock
                    .authorized_wg_datagram(datagram.peer, datagram.data.as_ref().to_vec())
                    .unwrap()
            })
            .collect();
        assert_eq!(contiguous_receive_run_end(&batch, 0), batch.len());
        let tunnels = RwLock::new(HashMap::from([(source_public, receiver)]));
        let batched_plaintext = Arc::new(std::sync::Mutex::new(Vec::new()));
        let batched_delivery = batched_plaintext.clone();
        handle_inbound_wg_datagrams(&magicsock, &tunnels, &batch, move |_node_key, packet| {
            batched_delivery.lock().unwrap().push(packet);
        })
        .await;

        let scalar_plaintext = Arc::new(std::sync::Mutex::new(Vec::new()));
        for datagram in scalar {
            let scalar_delivery = scalar_plaintext.clone();
            handle_inbound_wg_datagrams(
                &magicsock,
                &tunnels,
                &[datagram],
                move |_node_key, packet| {
                    scalar_delivery.lock().unwrap().push(packet);
                },
            )
            .await;
        }

        assert_eq!(*batched_plaintext.lock().unwrap(), plaintext);
        assert_eq!(*scalar_plaintext.lock().unwrap(), plaintext);
    }

    /// Exercise the production direct-UDP handoff end to end at the benchmark
    /// scale. Unlike the netstack-only rig, this owns real loopback UDP
    /// sockets, Magicsock receive credits, authenticated WG batches, route
    /// lookup, and the production netstack pump.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn direct_udp_wg_netstack_retains_p1000_connections() {
        const STREAMS: usize = 1000;
        let a_private = NodePrivate::generate();
        let b_private = NodePrivate::generate();
        let a_ip = Ipv4Addr::new(100, 64, 0, 1);
        let b_ip = Ipv4Addr::new(100, 64, 0, 2);
        let config = |private_key| MagicsockConfig {
            private_key,
            disco_key: DiscoPrivate::generate(),
            derp_client: None,
            derp_map: None,
            home_derp_region: 0,
            udp_bind: Some("127.0.0.1:0".parse().unwrap()),
            udp_socket: None,
            portmapper: None,
            health: None,
            disable_direct_paths: false,
            peer_relay_server: false,
            relay_server_config: None,
            sockstats: None,
            control_knobs: None,
        };
        let (a_magic, a_recv) = Magicsock::new(config(a_private.clone())).await.unwrap();
        let (b_magic, b_recv) = Magicsock::new(config(b_private.clone())).await.unwrap();
        let a_magic = Arc::new(a_magic);
        let b_magic = Arc::new(b_magic);
        let a_udp_addr = a_magic.bound_udp_addr().unwrap();
        let b_udp_addr = b_magic.bound_udp_addr().unwrap();
        let a_node = Node {
            ID: 1,
            Key: a_magic.node_public(),
            DiscoKey: a_magic.disco_public(),
            Addresses: vec![format!("{a_ip}/32")],
            Endpoints: vec![a_udp_addr.to_string()],
            ..Default::default()
        };
        let b_node = Node {
            ID: 2,
            Key: b_magic.node_public(),
            DiscoKey: b_magic.disco_public(),
            Addresses: vec![format!("{b_ip}/32")],
            Endpoints: vec![b_udp_addr.to_string()],
            ..Default::default()
        };
        a_magic.set_netmap(vec![b_node.clone()]).await.unwrap();
        b_magic.set_netmap(vec![a_node.clone()]).await.unwrap();
        // The first A→B probe can precede B's initial map installation.
        // Reapplying the unchanged map is the production refresh path and
        // gives both peers an authenticated direct pong.
        a_magic.set_netmap(vec![b_node.clone()]).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                if a_magic.peer_direct_trusted(&b_node.Key)
                    && b_magic.peer_direct_trusted(&a_node.Key)
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("loopback UDP direct paths were not authenticated");

        let a_net = Arc::new(Netstack::new(a_ip, DEFAULT_MTU).unwrap());
        let b_net = Arc::new(Netstack::new(b_ip, DEFAULT_MTU).unwrap());
        let a_tunnels = Arc::new(RwLock::new(HashMap::from([(
            b_node.Key.clone(),
            Arc::new(Mutex::new(WgTunn::new(&a_private, &b_node.Key, 1).unwrap())),
        )])));
        let b_tunnels = Arc::new(RwLock::new(HashMap::from([(
            a_node.Key.clone(),
            Arc::new(Mutex::new(WgTunn::new(&b_private, &a_node.Key, 2).unwrap())),
        )])));
        let a_cancel = Arc::new(CancelToken::new());
        let b_cancel = Arc::new(CancelToken::new());
        let a_pump = tokio::spawn(run_netstack_pump(
            a_magic.clone(),
            a_recv,
            a_net.clone(),
            a_tunnels,
            Arc::new(RwLock::new(RouteTable::from_peers(&[b_node.clone()]))),
            Arc::new(std::sync::Mutex::new(Filter::allow_all())),
            Arc::new(AtomicU64::new(0)),
            a_cancel.clone(),
            crate::capture::new_slot(),
            crate::peer_map::Runtime::new(&[b_node.clone()]).unwrap(),
        ));
        let b_pump = tokio::spawn(run_netstack_pump(
            b_magic.clone(),
            b_recv,
            b_net.clone(),
            b_tunnels,
            Arc::new(RwLock::new(RouteTable::from_peers(&[a_node.clone()]))),
            Arc::new(std::sync::Mutex::new(Filter::allow_all())),
            Arc::new(AtomicU64::new(0)),
            b_cancel.clone(),
            crate::capture::new_slot(),
            crate::peer_map::Runtime::new(&[a_node.clone()]).unwrap(),
        ));

        let mut listener = b_net.listen(41001).await.unwrap();
        let accept = tokio::spawn(async move {
            let mut streams = Vec::with_capacity(STREAMS);
            for _ in 0..STREAMS {
                streams.push(listener.accept().await.unwrap());
            }
            streams
        });
        let clients = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            a_net.dial_many(
                SocketAddr::new(b_ip.into(), 41001),
                STREAMS,
                tokio::time::Instant::now() + std::time::Duration::from_secs(25),
            ),
        )
        .await
        .expect("P1000 direct-UDP setup deadline")
        .expect("P1000 direct-UDP setup");
        let servers = accept.await.unwrap();
        assert_eq!(clients.len(), STREAMS);
        assert_eq!(servers.len(), STREAMS);
        assert!(a_magic.peer_direct_trusted(&b_node.Key));
        assert!(b_magic.peer_direct_trusted(&a_node.Key));
        assert!(a_net.dial_stats().pending_dials <= rustscale_netstack::TCP_DIAL_WINDOW);

        // Cross the saturated queue boundary several times with every stream
        // active. Connection retention alone cannot catch smoltcp restarting
        // each partial egress refill at socket zero and starving later flows.
        let bytes_per_stream = std::env::var("RUSTSCALE_P1000_BYTES_PER_STREAM")
            .ok()
            .and_then(|value| value.parse().ok())
            .filter(|bytes| *bytes > 0)
            .unwrap_or(16 * 1024);
        let payload = Arc::new(vec![0xa5; bytes_per_stream]);
        let transfer_started = std::time::Instant::now();
        let mut writers = tokio::task::JoinSet::new();
        for mut server in servers {
            let payload = payload.clone();
            writers.spawn(async move {
                use tokio::io::AsyncWriteExt;
                server.write_all(&payload).await.unwrap();
                server
            });
        }
        let mut readers = tokio::task::JoinSet::new();
        for mut client in clients {
            readers.spawn(async move {
                use tokio::io::AsyncReadExt;
                let mut received = vec![0; bytes_per_stream];
                client.read_exact(&mut received).await.unwrap();
                assert!(received.iter().all(|byte| *byte == 0xa5));
                client
            });
        }
        let (clients, servers) = tokio::time::timeout(std::time::Duration::from_secs(30), async {
            let mut clients = Vec::with_capacity(STREAMS);
            let mut servers = Vec::with_capacity(STREAMS);
            while let Some(client) = readers.join_next().await {
                clients.push(client.unwrap());
            }
            while let Some(server) = writers.join_next().await {
                servers.push(server.unwrap());
            }
            (clients, servers)
        })
        .await
        .expect("P1000 direct-UDP data transfer starved a connection");
        eprintln!(
            "P1000 direct-UDP transferred {} bytes across all streams in {:?}",
            bytes_per_stream * STREAMS,
            transfer_started.elapsed()
        );

        drop(clients);
        drop(servers);
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let a = a_net.connection_stats();
                let b = b_net.connection_stats();
                if a.live_connections == 0
                    && b.live_connections == 0
                    && a.pending_closes == 0
                    && b.pending_closes == 0
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("P1000 direct-UDP teardown leaked connection ownership");
        a_cancel.cancel();
        b_cancel.cancel();
        a_pump.abort();
        b_pump.abort();
        let _ = a_pump.await;
        let _ = b_pump.await;
        drop(a_magic);
        drop(b_magic);
    }

    #[tokio::test]
    async fn wireguard_rotation_drops_old_ciphertext_and_opens_new_key() {
        let local_private = NodePrivate::generate();
        let old_private = NodePrivate::generate();
        let old_public = old_private.public();
        let local_public = local_private.public();
        let old_sender = Arc::new(Mutex::new(
            WgTunn::new(&old_private, &local_public, 10).expect("old sender"),
        ));
        let old_receiver = Arc::new(Mutex::new(
            WgTunn::new(&local_private, &old_public, 11).expect("old receiver"),
        ));
        establish_tunnels(&old_sender, &old_receiver).await;
        let packet = vec![
            0x45, 0, 0, 20, 0, 1, 0, 0, 64, 17, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2,
        ];
        let stale_data = encrypt(&old_sender, &packet).await;

        let new_private = NodePrivate::generate();
        let new_public = new_private.public();
        let new_sender = Arc::new(Mutex::new(
            WgTunn::new(&new_private, &local_public, 12).expect("new sender"),
        ));
        let new_receiver = Arc::new(Mutex::new(
            WgTunn::new(&local_private, &new_public, 13).expect("new receiver"),
        ));
        establish_tunnels(&new_sender, &new_receiver).await;
        let fresh_data = encrypt(&new_sender, &packet).await;

        let (magicsock, _receive) = Magicsock::new(rustscale_magicsock::MagicsockConfig {
            private_key: local_private,
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
        .expect("magicsock without network I/O");
        magicsock
            .set_netmap(vec![
                rustscale_tailcfg::Node {
                    Key: old_public.clone(),
                    ..Default::default()
                },
                rustscale_tailcfg::Node {
                    Key: new_public.clone(),
                    ..Default::default()
                },
            ])
            .await
            .unwrap();
        let stale = magicsock
            .authorized_wg_datagram(old_public.clone(), stale_data)
            .unwrap();
        let fresh = magicsock
            .authorized_wg_datagram(new_public.clone(), fresh_data)
            .unwrap();
        let tunnels = RwLock::new(HashMap::from([(new_public, new_receiver)]));
        let delivered = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = delivered.clone();
        handle_inbound_wg_datagrams(&magicsock, &tunnels, &[stale, fresh], move |key, body| {
            sink.lock().unwrap().push((key, body));
        })
        .await;
        let delivered = delivered.lock().unwrap();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].1, packet);
        assert_ne!(delivered[0].0, old_public);
    }

    #[tokio::test]
    async fn queued_ciphertext_is_dropped_after_revocation_commit() {
        let source_private = NodePrivate::generate();
        let target_private = NodePrivate::generate();
        let source_public = source_private.public();
        let sender = Arc::new(Mutex::new(
            WgTunn::new(&source_private, &target_private.public(), 11).unwrap(),
        ));
        let receiver = Arc::new(Mutex::new(
            WgTunn::new(&target_private, &source_public, 12).unwrap(),
        ));
        establish_tunnels(&sender, &receiver).await;
        let (magicsock, _receive) = Magicsock::new(rustscale_magicsock::MagicsockConfig {
            private_key: target_private,
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
        .unwrap();
        let node = rustscale_tailcfg::Node {
            Key: source_public.clone(),
            ..Default::default()
        };
        magicsock.set_netmap(vec![node.clone()]).await.unwrap();
        let old_generation = magicsock.authorization_generation(&source_public).unwrap();
        let plaintext = vec![
            0x45, 0, 0, 20, 0, 9, 0, 0, 64, 17, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2,
        ];
        let queued = magicsock
            .authorized_wg_datagram(source_public.clone(), encrypt(&sender, &plaintext).await)
            .unwrap();
        magicsock.set_netmap(Vec::new()).await.unwrap();

        let tunnels = RwLock::new(HashMap::from([(source_public.clone(), receiver)]));
        let delivered = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = delivered.clone();
        handle_inbound_wg(&magicsock, &tunnels, &queued, move |_peer, _plaintext| {
            observed.store(true, std::sync::atomic::Ordering::SeqCst);
        })
        .await;
        assert!(!delivered.load(std::sync::atomic::Ordering::SeqCst));

        magicsock.set_netmap(vec![node]).await.unwrap();
        assert_ne!(
            magicsock.authorization_generation(&source_public),
            Some(old_generation),
            "reauthorization must use a fresh generation"
        );
    }
}
