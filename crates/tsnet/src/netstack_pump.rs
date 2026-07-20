#[allow(clippy::wildcard_imports)]
use super::*;

// ---------------------------------------------------------------------------
// Data-plane pumps
// ---------------------------------------------------------------------------

type TcpSegmentSignature = ([u8; 4], [u8; 4], u16, u16, u32, u8, u16);

#[derive(Default)]
struct NetstackPumpStats {
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
    fn new() -> Self {
        Self {
            next_snapshot_packets: 256,
            ..Self::default()
        }
    }

    fn note_batch(&mut self) {
        self.inbound_batches = self.inbound_batches.saturating_add(1);
    }

    fn note_connections(&mut self, stats: rustscale_netstack::ConnectionStats) {
        self.live_connections = stats.live_connections;
        self.pending_closes = stats.pending_closes;
        self.close_requests = stats.close_requests;
        self.close_completions = stats.close_completions;
        self.duplicate_close_requests = stats.duplicate_close_requests;
    }

    fn note_packet(&mut self, inbound: bool, packet: &[u8], queues: (usize, usize)) {
        if inbound {
            self.inbound_packets = self.inbound_packets.saturating_add(1);
        } else {
            self.outbound_packets = self.outbound_packets.saturating_add(1);
        }
        self.rx_queue_high_water = self.rx_queue_high_water.max(queues.0);
        self.tx_queue_high_water = self.tx_queue_high_water.max(queues.1);
        self.note_tcp(packet);
        let total = self.inbound_packets.saturating_add(self.outbound_packets);
        if self.next_snapshot_packets != 0 && total >= self.next_snapshot_packets {
            self.emit("periodic");
            self.next_snapshot_packets = self.next_snapshot_packets.checked_mul(2).unwrap_or(0);
        }
    }

    fn note_tcp(&mut self, packet: &[u8]) {
        if packet.len() < 40 || packet[0] >> 4 != 4 || packet[9] != 6 {
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
        let flags = tcp[13];
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
        let payload_len = total_len - ip_header - tcp_header;
        if syn || flags & 0x01 != 0 || payload_len != 0 {
            let signature = (
                packet[12..16].try_into().unwrap(),
                packet[16..20].try_into().unwrap(),
                u16::from_be_bytes([tcp[0], tcp[1]]),
                u16::from_be_bytes([tcp[2], tcp[3]]),
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
            "rustscale: netstack_pump_stats event={event} inbound_batches={} inbound_packets={} outbound_packets={} tcp_syn={} tcp_syn_ack={} tcp_ack={} tcp_retransmit={} tcp_fin={} tcp_rst={} rx_queue_high_water={} tx_queue_high_water={} live_connections={} pending_closes={} close_requests={} close_completions={} duplicate_close_requests={}",
            self.inbound_batches,
            self.inbound_packets,
            self.outbound_packets,
            self.tcp_syn,
            self.tcp_syn_ack,
            self.tcp_ack,
            self.tcp_retransmit,
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

/// Netstack data-plane pump: netstack <-> WG <-> magicsock.
///
/// Inbound: magicsock recv → WG decapsulate → netstack.push_rx.
/// Outbound: netstack.pop_tx → route lookup → WG encapsulate → magicsock send.
/// Also ticks WG timers every loop iteration.
pub(crate) async fn run_netstack_pump(
    magicsock: Arc<Magicsock>,
    mut wg_recv: mpsc::Receiver<rustscale_magicsock::WgReceiveBatch>,
    netstack: Arc<Netstack>,
    wg_tunnels: Arc<RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>>,
    route_table: Arc<RwLock<RouteTable>>,
    filter: Arc<std::sync::Mutex<Filter>>,
    packet_drops: Arc<AtomicU64>,
    cancel: Arc<CancelToken>,
    capture: crate::capture::CaptureSlot,
    peer_map: Arc<crate::peer_map::Runtime>,
) {
    let tx_notify = netstack.tx_notify();
    let mut wg_timer = tokio::time::interval(std::time::Duration::from_millis(250));
    wg_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut pump_stats = NetstackPumpStats::new();

    loop {
        if cancel.is_cancelled() {
            break;
        }
        pump_stats.note_connections(netstack.connection_stats());

        let mut handled_inbound = false;
        // A Notify retains at most one permit. After a bounded outbound
        // drain, more than one packet can remain even though its notification
        // was consumed, so do not sleep while the queue is still non-empty.
        if netstack.has_tx_packets() {
            if let Some(batch) = take_one_ready_receive_batch(&mut wg_recv) {
                handle_inbound_wg_batch(
                    &magicsock,
                    &wg_tunnels,
                    batch,
                    &netstack,
                    &filter,
                    &packet_drops,
                    &capture,
                    &peer_map,
                    &mut pump_stats,
                )
                .await;
                handled_inbound = true;
            }
        } else {
            tokio::select! {
                () = tx_notify.notified() => {}
                _ = wg_timer.tick() => {}
                result = wg_recv.recv() => {
                    if let Some(batch) = result {
                        handle_inbound_wg_batch(
                            &magicsock, &wg_tunnels, batch, &netstack, &filter,
                            &packet_drops, &capture, &peer_map, &mut pump_stats,
                        ).await;
                        handled_inbound = true;
                    } else {
                        log::warn!("tsnet: magicsock wg channel closed");
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                }
            }
        }

        // push_rx_from only queues plaintext and notifies smoltcp. Give that
        // task one scheduler handoff after exactly one receive batch so TCP
        // ACK/SYN output can become visible before admitting another burst.
        if handled_inbound {
            tokio::task::yield_now().await;
        }

        // Drain outbound IP packets from netstack → route → WG → magicsock.
        // Cap the batch size so inbound packets aren't starved under heavy
        // outbound load (e.g. bulk TCP transfer). A full drain can take long
        // enough for the magicsock receive buffer to fill and drop inbound.
        const DRAIN_BATCH: usize = 64;
        let mut drained = 0;
        while drained < DRAIN_BATCH {
            let Some(pkt) = netstack.pop_tx() else { break };
            pump_stats.note_packet(false, &pkt, netstack.data_plane_queue_depths());
            {
                let mut filt = filter.lock().unwrap();
                filt.update_outbound(&pkt);
            }
            crate::capture::log_packet(
                &capture,
                crate::capture::CapturePath::SynthesizedToPeer,
                &pkt,
            );
            let _map = peer_map.gate.read().await;
            encapsulate_and_send(&magicsock, &wg_tunnels, &route_table, &pkt).await;
            drained += 1;
        }

        let _map = peer_map.gate.read().await;
        tick_wg_timers(&magicsock, &wg_tunnels).await;
    }
}

/// Take at most one immediately-ready receive batch for this scheduler turn.
fn take_one_ready_receive_batch(
    receiver: &mut mpsc::Receiver<rustscale_magicsock::WgReceiveBatch>,
) -> Option<rustscale_magicsock::WgReceiveBatch> {
    receiver.try_recv().ok()
}

/// Process one ordered receive-batch with the same per-datagram semantics as
/// the former scalar channel consumer.
async fn handle_inbound_wg_batch(
    magicsock: &Magicsock,
    wg_tunnels: &RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>,
    batch: rustscale_magicsock::WgReceiveBatch,
    netstack: &Netstack,
    filter: &std::sync::Mutex<Filter>,
    packet_drops: &AtomicU64,
    capture: &crate::capture::CaptureSlot,
    peer_map: &crate::peer_map::Runtime,
    pump_stats: &mut NetstackPumpStats,
) {
    let _map = peer_map.gate.read().await;
    let datagrams = batch.into_datagrams();
    pump_stats.note_batch();
    handle_inbound_wg_datagrams(magicsock, wg_tunnels, &datagrams, |peer, pt| {
        if !peer_map.packet_source_matches(&peer, &pt) {
            packet_drops.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return;
        }
        let dropped = {
            let mut filt = filter.lock().unwrap();
            filt.check_in(&pt).is_drop()
        };
        if dropped {
            packet_drops.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return;
        }
        crate::capture::log_packet(
            capture,
            crate::capture::CapturePath::SynthesizedToLocal,
            &pt,
        );
        let (rx_depth, tx_depth) = netstack.data_plane_queue_depths();
        pump_stats.note_packet(true, &pt, (rx_depth.saturating_add(1), tx_depth));
        netstack.push_rx_from(pt, peer);
    })
    .await;
}

/// Decapsulate contiguous same-peer/same-generation runs while acquiring the
/// tunnel map, tunnel mutex, and authorization delivery guard once per run.
/// Per-packet authorization and delivery decisions remain ordered. Protocol
/// replies are sent only after all guards have been dropped.
async fn handle_inbound_wg_datagrams(
    magicsock: &Magicsock,
    wg_tunnels: &RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>,
    datagrams: &[rustscale_magicsock::WgDatagram],
    mut deliver: impl FnMut(NodePublic, Vec<u8>),
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
                    // plaintext handoff for this run. Acquire it before the
                    // peer tunnel mutex so no mutex is held across this await.
                    let _delivery = magicsock.authorization_delivery_guard().await;
                    if magicsock.is_authorization_current(&peer, generation) {
                        let mut tunnel = tunnel.lock().await;
                        for (offset, datagram) in datagrams[start..end].iter().enumerate() {
                            if !magicsock.is_authorization_current(&peer, generation) {
                                break;
                            }
                            if let Ok(decap) = tunnel.decapsulate(&datagram.data) {
                                authenticated.push(start + offset);
                                if let Some(plaintext) = decap.plaintext {
                                    deliver(peer.clone(), plaintext);
                                }
                                replies.extend(decap.replies);
                            }
                        }
                    }
                }
                for index in authenticated {
                    magicsock.note_authenticated_wg_transport(&datagrams[index]);
                }
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

/// Route a plaintext IP packet to the right peer, encapsulate it via WG, and
/// send the resulting datagrams over magicsock.
pub(crate) async fn encapsulate_and_send(
    magicsock: &Magicsock,
    wg_tunnels: &RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>,
    route_table: &RwLock<RouteTable>,
    pkt: &[u8],
) {
    let Some(dst) = WgTunn::dst_address(pkt) else {
        return;
    };
    let peer_key = {
        let rt = route_table.read().await;
        rt.lookup(dst)
    };
    let Some(peer_key) = peer_key else {
        return;
    };
    let tunn = {
        let tunnels = wg_tunnels.read().await;
        tunnels.get(&peer_key).cloned()
    };
    if let Some(tunn) = tunn {
        // Lock the tunnel, encapsulate (synchronous), then drop the lock
        // before async magicsock.send to avoid holding it across .await.
        let dgrams = {
            let mut t = tunn.lock().await;
            t.encapsulate(pkt)
        };
        if let Ok(dgrams) = dgrams {
            for dg in dgrams {
                let _ = magicsock.send(peer_key.clone(), &dg).await;
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

        let mut stats = NetstackPumpStats::new();
        stats.note_packet(true, &syn, (1, 0));
        stats.note_packet(true, &syn, (2, 0));
        assert_eq!(stats.tcp_syn, 2);
        assert_eq!(stats.tcp_retransmit, 1);
        assert_eq!(stats.rx_queue_high_water, 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn receive_turn_services_ready_outbound_before_second_batch() {
        let (send, mut receive) = mpsc::channel(2);
        send.try_send(rustscale_magicsock::WgReceiveBatch::from_datagrams_for_test(Vec::new()))
            .unwrap();
        send.try_send(rustscale_magicsock::WgReceiveBatch::from_datagrams_for_test(Vec::new()))
            .unwrap();
        let (outbound_send, mut outbound_receive) = mpsc::channel(1);
        let mut order = Vec::new();

        let _first = take_one_ready_receive_batch(&mut receive).expect("first receive batch");
        order.push("inbound-1");
        outbound_send.try_send(vec![1]).unwrap();
        tokio::task::yield_now().await;
        assert_eq!(
            receive.len(),
            1,
            "one receive turn must leave the second batch queued"
        );
        assert_eq!(outbound_receive.try_recv(), Ok(vec![1]));
        order.push("outbound");
        let _second = take_one_ready_receive_batch(&mut receive).expect("second receive batch");
        order.push("inbound-2");

        assert_eq!(order, ["inbound-1", "outbound", "inbound-2"]);
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
