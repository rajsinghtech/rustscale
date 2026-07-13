#[allow(clippy::wildcard_imports)]
use super::*;

// ---------------------------------------------------------------------------
// Data-plane pumps
// ---------------------------------------------------------------------------

/// Netstack data-plane pump: netstack <-> WG <-> magicsock.
///
/// Inbound: magicsock recv → WG decapsulate → netstack.push_rx.
/// Outbound: netstack.pop_tx → route lookup → WG encapsulate → magicsock send.
/// Also ticks WG timers every loop iteration.
pub(crate) async fn run_netstack_pump(
    magicsock: Arc<Magicsock>,
    mut wg_recv: mpsc::Receiver<rustscale_magicsock::WgDatagram>,
    netstack: Arc<Netstack>,
    wg_tunnels: Arc<RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>>,
    route_table: Arc<RwLock<RouteTable>>,
    filter: Arc<std::sync::Mutex<Filter>>,
    packet_drops: Arc<AtomicU64>,
    cancel: Arc<CancelToken>,
    capture: crate::capture::CaptureSlot,
) {
    let tx_notify = netstack.tx_notify();
    let mut wg_timer = tokio::time::interval(std::time::Duration::from_millis(250));
    wg_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        if cancel.is_cancelled() {
            break;
        }

        tokio::select! {
            () = tx_notify.notified() => {}
            _ = wg_timer.tick() => {}
            result = wg_recv.recv() => {
                if let Some(dgram) = result {
                    let f = filter.clone();
                    let drops = packet_drops.clone();
                    let ns = netstack.clone();
                    let inbound_capture = capture.clone();
                    handle_inbound_wg(&magicsock, &wg_tunnels, &dgram, move |pt| {
                        let dropped = {
                            let mut filt = f.lock().unwrap();
                            filt.check_in(&pt).is_drop()
                        };
                        if dropped {
                            drops.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            return;
                        }
                        crate::capture::log_packet(
                            &inbound_capture,
                            crate::capture::CapturePath::SynthesizedToLocal,
                            &pt,
                        );
                        ns.push_rx(pt);
                    }).await;

                    // Drain any additional immediately-available datagrams
                    // to batch a burst of packets (e.g. TCP handshake +
                    // data) into a single scheduler turn.
                    while let Ok(more) = wg_recv.try_recv() {
                        let f = filter.clone();
                        let drops = packet_drops.clone();
                        let ns = netstack.clone();
                        let capture = capture.clone();
                        handle_inbound_wg(&magicsock, &wg_tunnels, &more, move |pt| {
                            let dropped = {
                                let mut filt = f.lock().unwrap();
                                filt.check_in(&pt).is_drop()
                            };
                            if dropped {
                                drops.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                return;
                            }
                            crate::capture::log_packet(
                                &capture,
                                crate::capture::CapturePath::SynthesizedToLocal,
                                &pt,
                            );
                            ns.push_rx(pt);
                        }).await;
                    }
                } else {
                    log::warn!("tsnet: magicsock wg channel closed");
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }

        // Drain outbound IP packets from netstack → route → WG → magicsock.
        // Cap the batch size so inbound packets aren't starved under heavy
        // outbound load (e.g. bulk TCP transfer). A full drain can take long
        // enough for the magicsock receive buffer to fill and drop inbound.
        const DRAIN_BATCH: usize = 64;
        let mut drained = 0;
        while drained < DRAIN_BATCH {
            let Some(pkt) = netstack.pop_tx() else { break };
            {
                let mut filt = filter.lock().unwrap();
                filt.update_outbound(&pkt);
            }
            crate::capture::log_packet(
                &capture,
                crate::capture::CapturePath::SynthesizedToPeer,
                &pkt,
            );
            encapsulate_and_send(&magicsock, &wg_tunnels, &route_table, &pkt).await;
            drained += 1;
        }

        tick_wg_timers(&magicsock, &wg_tunnels).await;
    }
}
/// Handle an inbound WG datagram: decapsulate, deliver plaintext via `deliver`,
/// and send any WG protocol replies back over magicsock.
async fn handle_inbound_wg(
    magicsock: &Magicsock,
    wg_tunnels: &RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>,
    dgram: &rustscale_magicsock::WgDatagram,
    deliver: impl Fn(Vec<u8>),
) {
    let tunn = {
        let tunnels = wg_tunnels.read().await;
        tunnels.get(&dgram.peer).cloned()
    };
    if let Some(tunn) = tunn {
        // Lock the tunnel, decapsulate (synchronous), then drop the lock
        // before any async I/O (magicsock.send). This prevents packet drops
        // from try_lock failures and avoids holding the lock across .await.
        let decap_result = {
            let mut t = tunn.lock().await;
            t.decapsulate(&dgram.data)
        };
        if let Ok(decap) = decap_result {
            if let Some(pt) = decap.plaintext {
                deliver(pt);
            }
            for reply in decap.replies {
                let _ = magicsock.send(dgram.peer.clone(), &reply).await;
            }
        }
    }
}

/// Decapsulate one TUN-bound datagram and retain accepted plaintext and
/// protocol replies for the caller's batch boundary. No async device or
/// magicsock I/O occurs here, so tunnel and filter guards are always dropped
/// before those operations.
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
