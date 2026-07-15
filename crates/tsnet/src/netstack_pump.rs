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

    loop {
        if cancel.is_cancelled() {
            break;
        }

        tokio::select! {
            () = tx_notify.notified() => {}
            _ = wg_timer.tick() => {}
            result = wg_recv.recv() => {
                if let Some(batch) = result {
                    handle_inbound_wg_batch(
                        &magicsock, &wg_tunnels, batch, &netstack, &filter,
                        &packet_drops, &capture, &peer_map,
                    ).await;

                    // Preserve the former scheduler-turn burst drain, now in
                    // receive-batch units. Each batch retains scalar packet
                    // handling and ordering internally.
                    while let Ok(more) = wg_recv.try_recv() {
                        handle_inbound_wg_batch(
                            &magicsock, &wg_tunnels, more, &netstack, &filter,
                            &packet_drops, &capture, &peer_map,
                        ).await;
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
            let _map = peer_map.gate.read().await;
            encapsulate_and_send(&magicsock, &wg_tunnels, &route_table, &pkt).await;
            drained += 1;
        }

        let _map = peer_map.gate.read().await;
        tick_wg_timers(&magicsock, &wg_tunnels).await;
    }
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
) {
    let _map = peer_map.gate.read().await;
    let datagrams = batch.into_datagrams();
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
        netstack.push_rx_from(pt, peer);
    })
    .await;
}

/// Run the scalar decapsulation semantics over one ordered receive burst.
/// Keeping this seam independent from the delivery target lets the batch path
/// remain exactly equivalent to delivering every item from the old channel.
async fn handle_inbound_wg_datagrams(
    magicsock: &Magicsock,
    wg_tunnels: &RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>,
    datagrams: &[rustscale_magicsock::WgDatagram],
    deliver: impl Fn(NodePublic, Vec<u8>),
) {
    for dgram in datagrams {
        handle_inbound_wg(magicsock, wg_tunnels, dgram, |peer, pt| {
            deliver(peer, pt);
        })
        .await;
    }
}
/// Handle an inbound WG datagram: decapsulate, deliver plaintext via `deliver`,
/// and send any WG protocol replies back over magicsock.
async fn handle_inbound_wg(
    magicsock: &Magicsock,
    wg_tunnels: &RwLock<HashMap<NodePublic, Arc<Mutex<WgTunn>>>>,
    dgram: &rustscale_magicsock::WgDatagram,
    deliver: impl Fn(NodePublic, Vec<u8>),
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
                deliver(dgram.peer.clone(), pt);
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

        let plaintext = vec![
            vec![
                0x45, 0, 0, 20, 0, 1, 0, 0, 64, 17, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2,
            ],
            vec![
                0x45, 0, 0, 20, 0, 2, 0, 0, 64, 17, 0, 0, 100, 64, 0, 1, 100, 64, 0, 2,
            ],
        ];
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
        let stale = rustscale_magicsock::WgDatagram {
            peer: old_public.clone(),
            data: encrypt(&old_sender, &packet).await.into(),
        };

        let new_private = NodePrivate::generate();
        let new_public = new_private.public();
        let new_sender = Arc::new(Mutex::new(
            WgTunn::new(&new_private, &local_public, 12).expect("new sender"),
        ));
        let new_receiver = Arc::new(Mutex::new(
            WgTunn::new(&local_private, &new_public, 13).expect("new receiver"),
        ));
        establish_tunnels(&new_sender, &new_receiver).await;
        let fresh = rustscale_magicsock::WgDatagram {
            peer: new_public.clone(),
            data: encrypt(&new_sender, &packet).await.into(),
        };

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
}
