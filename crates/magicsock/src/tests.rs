//! Integration and unit tests for magicsock.
//!
//! Test scenarios:
//! (a) Two Magicsock instances through a fake in-process DERP server,
//!     exchanging disco pings and falling back to DERP data path.
//! (b) Loopback UDP sockets achieving a direct path upgrade after ping/pong.
//! Plus unit tests for endpoint ranking and trust expiry (in endpoint.rs).

use super::*;
use rustscale_derp::{
    decode_frame_header, encode_frame_header, frame_type, DerpClient, FRAME_HEADER_LEN, MAGIC,
    PROTOCOL_VERSION,
};
use rustscale_key::{DiscoPrivate, NodePrivate, NodePublic};
use rustscale_tailcfg::{DERPMap, DERPNode, DERPRegion};
use std::cell::Cell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex, Notify};

#[test]
fn post_selection_configures_some_socket_from_udp_socket_and_udp_bind() {
    // `Magicsock::new` resolves both constructor alternatives before this
    // hook, so each selected `Some` must receive the same configuration.
    for constructor in ["udp_socket", "udp_bind"] {
        let calls = Cell::new(0);

        configure_selected_udp_socket(Some(constructor), |configured| {
            assert_eq!(configured, constructor);
            calls.set(calls.get() + 1);
        });

        assert_eq!(calls.get(), 1, "{constructor} selected socket");
    }
}

#[test]
fn post_selection_skips_configuration_without_a_selected_socket() {
    let calls = Cell::new(0);

    configure_selected_udp_socket(None::<()>, |()| calls.set(calls.get() + 1));

    assert_eq!(calls.get(), 0);
}

/// Minimal ServerInfo JSON for the handshake (just the version field).
async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    typ: u8,
    body: &[u8],
) -> std::io::Result<()> {
    let header = encode_frame_header(typ, body.len() as u32);
    w.write_all(&header).await?;
    w.write_all(body).await?;
    w.flush().await?;
    Ok(())
}

/// Read a DERP frame from an async reader.
async fn read_frame<R: AsyncRead + Unpin>(
    r: &mut R,
    max_size: u32,
) -> std::io::Result<(u8, Vec<u8>)> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    r.read_exact(&mut header).await?;
    let (typ, len) = decode_frame_header(&header);
    if len > max_size {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body).await?;
    Ok((typ, body))
}

/// Minimal ServerInfo JSON for the handshake (just the version field).
fn server_info_json() -> Vec<u8> {
    format!(r#"{{"version":{PROTOCOL_VERSION}}}"#).into_bytes()
}

/// Write a DERP frame to an async writer.

/// Fake DERP relay server that connects multiple clients and relays packets
/// between them. Speaks the real DERP wire protocol over tokio duplex streams.
struct FakeRelay {
    server_priv: NodePrivate,
    server_pub: NodePublic,
    senders: Arc<Mutex<HashMap<NodePublic, mpsc::UnboundedSender<(NodePublic, Vec<u8>)>>>>,
    clients_registered: Arc<Notify>,
    drop_next_packets: Arc<Mutex<usize>>,
    dropped_packets: Arc<AtomicUsize>,
    forwarded_packets: Arc<AtomicUsize>,
    packet_event: Arc<Notify>,
}

impl FakeRelay {
    fn new() -> Self {
        let privk = NodePrivate::generate();
        Self {
            server_pub: privk.public(),
            server_priv: privk,
            senders: Arc::new(Mutex::new(HashMap::new())),
            clients_registered: Arc::new(Notify::new()),
            drop_next_packets: Arc::new(Mutex::new(0)),
            dropped_packets: Arc::new(AtomicUsize::new(0)),
            forwarded_packets: Arc::new(AtomicUsize::new(0)),
            packet_event: Arc::new(Notify::new()),
        }
    }

    async fn wait_for_clients(&self, count: usize) {
        loop {
            let notified = self.clients_registered.notified();
            if self.senders.lock().await.len() >= count {
                return;
            }
            notified.await;
        }
    }

    async fn drop_next_packets(&self, count: usize) {
        *self.drop_next_packets.lock().await = count;
    }

    async fn wait_for_dropped_packets(&self, count: usize) {
        loop {
            let notified = self.packet_event.notified();
            if self.dropped_packets.load(Ordering::SeqCst) >= count {
                return;
            }
            notified.await;
        }
    }

    fn dropped_packets(&self) -> usize {
        self.dropped_packets.load(Ordering::SeqCst)
    }

    fn forwarded_packets(&self) -> usize {
        self.forwarded_packets.load(Ordering::SeqCst)
    }

    async fn wait_for_forwarded_packets(&self, count: usize) {
        loop {
            let notified = self.packet_event.notified();
            if self.forwarded_packets() >= count {
                return;
            }
            notified.await;
        }
    }

    /// Accept a new client connection and spawn per-client reader/writer tasks.
    fn accept(self: &Arc<Self>, stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static) {
        let server_priv = self.server_priv.clone();
        let server_pub = self.server_pub.clone();
        let senders = self.senders.clone();
        let clients_registered = self.clients_registered.clone();
        let drop_next_packets = self.drop_next_packets.clone();
        let dropped_packets = self.dropped_packets.clone();
        let forwarded_packets = self.forwarded_packets.clone();
        let packet_event = self.packet_event.clone();

        tokio::spawn(async move {
            let mut s = stream;

            // 1. Send FrameServerKey.
            let mut sk = Vec::with_capacity(40);
            sk.extend_from_slice(&MAGIC);
            sk.extend_from_slice(&server_pub.raw32());
            write_frame(&mut s, frame_type::SERVER_KEY, &sk)
                .await
                .unwrap();

            // 2. Read FrameClientInfo.
            let (_, body) = read_frame(&mut s, 65536).await.unwrap();
            let mut cp = [0u8; 32];
            cp.copy_from_slice(&body[..32]);
            let client_pub = NodePublic::from_raw32(cp);

            // 3. Send FrameServerInfo (sealed).
            let si_json = server_info_json();
            let si_box = server_priv.seal_to(&client_pub, &si_json).unwrap();
            write_frame(&mut s, frame_type::SERVER_INFO, &si_box)
                .await
                .unwrap();

            // 4. Register this client BEFORE splitting (so it's reachable immediately).
            let (relay_tx, mut relay_rx) = mpsc::unbounded_channel::<(NodePublic, Vec<u8>)>();
            senders.lock().await.insert(client_pub.clone(), relay_tx);
            clients_registered.notify_waiters();

            // 5. Split the stream for concurrent read + write.
            let (read_half, mut write_half) = tokio::io::split(s);

            // Reader task: reads SEND_PACKET frames and relays to other clients.
            let senders_r = senders.clone();
            let client_pub_r = client_pub.clone();
            let drop_next_packets_r = drop_next_packets.clone();
            let dropped_packets_r = dropped_packets.clone();
            let forwarded_packets_r = forwarded_packets.clone();
            let packet_event_r = packet_event.clone();
            tokio::spawn(async move {
                let mut reader = read_half;
                loop {
                    match read_frame(&mut reader, 65536).await {
                        Ok((typ, body)) => {
                            if typ == frame_type::SEND_PACKET && body.len() >= 32 {
                                let mut dst = [0u8; 32];
                                dst.copy_from_slice(&body[..32]);
                                let dst_pub = NodePublic::from_raw32(dst);
                                let data = body[32..].to_vec();
                                let drop_packet = {
                                    let mut remaining = drop_next_packets_r.lock().await;
                                    if *remaining == 0 {
                                        false
                                    } else {
                                        *remaining -= 1;
                                        true
                                    }
                                };
                                if drop_packet {
                                    dropped_packets_r.fetch_add(1, Ordering::SeqCst);
                                    packet_event_r.notify_waiters();
                                    continue;
                                }
                                let senders = senders_r.lock().await;
                                if let Some(tx) = senders.get(&dst_pub) {
                                    let _ = tx.send((client_pub_r.clone(), data));
                                    forwarded_packets_r.fetch_add(1, Ordering::SeqCst);
                                    packet_event_r.notify_waiters();
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
            });

            // Writer task: reads from relay channel and sends RECV_PACKET to client.
            tokio::spawn(async move {
                while let Some((sender_pub, data)) = relay_rx.recv().await {
                    let mut pkt = Vec::with_capacity(32 + data.len());
                    pkt.extend_from_slice(&sender_pub.raw32());
                    pkt.extend_from_slice(&data);
                    if write_frame(&mut write_half, frame_type::RECV_PACKET, &pkt)
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                // Clean up when the relay channel closes.
                senders.lock().await.remove(&client_pub);
            });
        });
    }
}

/// Create a DerpClient connected to the fake relay via a duplex stream.
/// The `private_key` must match the Magicsock's node private key so that the
/// relay registers the client under the same public key that peers address.
async fn connect_to_relay(relay: &Arc<FakeRelay>, private_key: NodePrivate) -> DerpClient {
    let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
    relay.accept(server_stream);
    DerpClient::from_stream(Box::new(client_stream), private_key, None)
        .await
        .expect("derp handshake")
}

/// Build a tailcfg::Node for a peer.
fn make_peer(
    node_key: NodePublic,
    disco_key: rustscale_key::DiscoPublic,
    endpoints: Vec<String>,
    home_derp: i32,
) -> Node {
    Node {
        Key: node_key,
        DiscoKey: disco_key,
        Endpoints: endpoints,
        HomeDERP: home_derp,
        ..Default::default()
    }
}

async fn magicsock_with_idle_peer() -> (Magicsock, NodePublic) {
    let private_key = NodePrivate::generate();
    let peer_key = NodePrivate::generate().public();
    let (magicsock, _rx) = Magicsock::new(MagicsockConfig {
        private_key,
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
        .set_netmap(vec![make_peer(
            peer_key.clone(),
            DiscoPrivate::generate().public(),
            vec![],
            0,
        )])
        .await
        .expect("netmap");
    (magicsock, peer_key)
}

#[tokio::test]
async fn active_tx_keeps_one_heartbeat_task_and_idle_tx_rearms_it() {
    let (magicsock, peer_key) = magicsock_with_idle_peer().await;

    assert!(magicsock
        .send_batch(
            peer_key.clone(),
            &[
                b"first".as_slice(),
                b"second".as_slice(),
                b"third".as_slice()
            ],
        )
        .await
        .is_err());
    assert_eq!(
        magicsock
            .inner
            .heartbeat_task_generations
            .load(Ordering::Relaxed),
        1
    );

    for _ in 0..4 {
        assert!(magicsock.send(peer_key.clone(), b"active").await.is_err());
    }
    assert_eq!(
        magicsock
            .inner
            .heartbeat_task_generations
            .load(Ordering::Relaxed),
        1,
        "active sends must not replace the heartbeat task"
    );
    assert_eq!(magicsock.inner.background_tasks.read().unwrap().len(), 1);

    // Make the session stale as if the task had entered its UDP-lifetime
    // phase. The next TX must replace that task with a heartbeat task.
    let now = std::time::Instant::now();
    magicsock
        .inner
        .endpoints
        .write()
        .unwrap()
        .get_mut(&peer_key)
        .unwrap()
        .note_tx_activity(
            now.checked_sub(SESSION_ACTIVE_TIMEOUT)
                .expect("monotonic clock predates timeout"),
        );
    assert!(magicsock
        .send(peer_key.clone(), b"after idle")
        .await
        .is_err());
    assert_eq!(
        magicsock
            .inner
            .heartbeat_task_generations
            .load(Ordering::Relaxed),
        2,
        "TX after idle must replace the lifetime-phase task"
    );
    assert_eq!(magicsock.inner.background_tasks.read().unwrap().len(), 1);
}

#[tokio::test]
async fn link_change_makes_next_tx_rearm_heartbeat() {
    let (magicsock, peer_key) = magicsock_with_idle_peer().await;

    assert!(magicsock
        .send(peer_key.clone(), b"before link change")
        .await
        .is_err());
    magicsock.link_changed();
    assert!(magicsock
        .send(peer_key, b"after link change")
        .await
        .is_err());
    assert_eq!(
        magicsock
            .inner
            .heartbeat_task_generations
            .load(Ordering::Relaxed),
        2
    );
}

#[tokio::test]
async fn abort_background_tasks_drains_all_peer_records() {
    let (magicsock, first_peer) = magicsock_with_idle_peer().await;
    let second_peer = NodePrivate::generate().public();
    magicsock
        .set_netmap(vec![
            make_peer(
                first_peer.clone(),
                DiscoPrivate::generate().public(),
                vec![],
                0,
            ),
            make_peer(
                second_peer.clone(),
                DiscoPrivate::generate().public(),
                vec![],
                0,
            ),
        ])
        .await
        .expect("netmap");

    assert!(magicsock.send(first_peer, b"first").await.is_err());
    assert!(magicsock.send(second_peer, b"second").await.is_err());
    assert_eq!(magicsock.inner.background_tasks.read().unwrap().len(), 2);

    magicsock.abort_background_tasks();
    assert!(magicsock.inner.background_tasks.read().unwrap().is_empty());
}

#[tokio::test]
async fn netmap_refreshes_peer_disco_key_and_reverse_map() {
    let private_key = NodePrivate::generate();
    let peer_key = NodePrivate::generate().public();
    let other_peer = NodePrivate::generate().public();
    let zero_disco = rustscale_key::DiscoPublic::from_raw32([0; 32]);
    let first_disco = DiscoPrivate::generate().public();
    let rotated_disco = DiscoPrivate::generate().public();
    let (magicsock, _rx) = Magicsock::new(MagicsockConfig {
        private_key,
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
        .set_netmap(vec![make_peer(
            peer_key.clone(),
            zero_disco.clone(),
            vec![],
            0,
        )])
        .await
        .unwrap();
    assert_eq!(magicsock.inner.peer_disco_key(&peer_key), Some(zero_disco));

    magicsock
        .set_netmap(vec![make_peer(
            peer_key.clone(),
            first_disco.clone(),
            vec![],
            0,
        )])
        .await
        .unwrap();
    assert_eq!(
        magicsock.inner.peer_disco_key(&peer_key),
        Some(first_disco.clone())
    );
    assert_eq!(
        magicsock
            .inner
            .disco_to_peer
            .read()
            .unwrap()
            .get(&first_disco),
        Some(&peer_key)
    );

    magicsock
        .set_netmap(vec![make_peer(
            peer_key.clone(),
            rotated_disco.clone(),
            vec![],
            0,
        )])
        .await
        .unwrap();
    {
        let d2p = magicsock.inner.disco_to_peer.read().unwrap();
        assert!(!d2p.contains_key(&first_disco));
        assert_eq!(d2p.get(&rotated_disco), Some(&peer_key));
    }

    // A stale mapping must not be removed if another peer now owns the key.
    magicsock
        .inner
        .disco_to_peer
        .write()
        .unwrap()
        .insert(rotated_disco.clone(), other_peer.clone());
    magicsock
        .set_netmap(vec![make_peer(
            peer_key.clone(),
            rustscale_key::DiscoPublic::from_raw32([0; 32]),
            vec![],
            0,
        )])
        .await
        .unwrap();
    assert_eq!(
        magicsock.inner.peer_disco_key(&peer_key),
        Some(rustscale_key::DiscoPublic::from_raw32([0; 32]))
    );
    assert_eq!(
        magicsock
            .inner
            .disco_to_peer
            .read()
            .unwrap()
            .get(&rotated_disco),
        Some(&other_peer)
    );
}

// ---- Test (a): DERP data path fallback ----

#[tokio::test]
async fn derp_data_path_fallback() {
    let relay = Arc::new(FakeRelay::new());

    let a_priv = NodePrivate::generate();
    let b_priv = NodePrivate::generate();

    let a_derp = connect_to_relay(&relay, a_priv.clone()).await;
    let (a, mut a_rx) = Magicsock::new(MagicsockConfig {
        private_key: a_priv,
        disco_key: DiscoPrivate::generate(),
        derp_client: Some(a_derp),
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
    .expect("A magicsock");

    let b_derp = connect_to_relay(&relay, b_priv.clone()).await;
    let (b, mut b_rx) = Magicsock::new(MagicsockConfig {
        private_key: b_priv,
        disco_key: DiscoPrivate::generate(),
        derp_client: Some(b_derp),
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
    .expect("B magicsock");

    // Each knows about the other via the netmap.
    let b_peer = make_peer(b.node_public(), b.disco_public(), vec![], 1);
    let a_peer = make_peer(a.node_public(), a.disco_public(), vec![], 1);

    // Give relay time to fully register both clients.
    relay.wait_for_clients(2).await;

    a.set_netmap(vec![b_peer]).await.expect("A set_netmap");
    b.set_netmap(vec![a_peer]).await.expect("B set_netmap");

    // A sends a WG datagram to B — no direct path, goes via DERP.
    let wg_datagram = b"\x00\x01\x02\x03 fake wg packet from A";
    a.send(b.node_public(), wg_datagram).await.expect("A send");

    // B may receive disco CallMeMaybe packets first; drain until we get the WG datagram.
    let mut got_wg = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        if let Ok(Some(d)) = tokio::time::timeout(Duration::from_millis(500), b_rx.recv()).await {
            if d.data == wg_datagram {
                got_wg = Some(d);
                break;
            }
        }
    }
    let received = got_wg.expect("B should receive A's WG datagram");
    assert_eq!(received.peer, a.node_public());
    assert_eq!(received.data, wg_datagram);

    // B sends back to A.
    let wg_reply = b"\x00\x04\x05\x06 fake wg packet from B";
    b.send(a.node_public(), wg_reply).await.expect("B send");
    let received = tokio::time::timeout(Duration::from_secs(2), a_rx.recv())
        .await
        .expect("timed out waiting for A recv")
        .expect("A poll_recv");
    assert_eq!(received.peer, b.node_public());
    assert_eq!(received.data, wg_reply);
}

#[tokio::test]
async fn cli_ping_cmm_recovers_direct_path_after_initial_netmap_drop() {
    let relay = Arc::new(FakeRelay::new());
    let a_priv = NodePrivate::generate();
    let b_priv = NodePrivate::generate();
    let a_derp = connect_to_relay(&relay, a_priv.clone()).await;
    let (a, _a_rx) = Magicsock::new(MagicsockConfig {
        private_key: a_priv,
        disco_key: DiscoPrivate::generate(),
        derp_client: Some(a_derp),
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
    })
    .await
    .unwrap();
    let b_derp = connect_to_relay(&relay, b_priv.clone()).await;
    let (b, _b_rx) = Magicsock::new(MagicsockConfig {
        private_key: b_priv,
        disco_key: DiscoPrivate::generate(),
        derp_client: Some(b_derp),
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
    })
    .await
    .unwrap();

    // This test binds loopback sockets, while interface discovery may prefer
    // a non-loopback host address. Advertise the actual bound sockets so the
    // CMM-triggered probes are reachable in this in-process scenario.
    *a.inner.local_udp_addrs.write().unwrap() = vec![a.bound_udp_addr().unwrap().to_string()];
    *b.inner.local_udp_addrs.write().unwrap() = vec![b.bound_udp_addr().unwrap().to_string()];
    relay.wait_for_clients(2).await;

    // Model the startup race: both one-shot netmap CMM packets disappear,
    // leaving neither endpoint with a usable UDP candidate.
    relay.drop_next_packets(2).await;
    a.set_netmap(vec![make_peer(
        b.node_public(),
        b.disco_public(),
        vec![],
        0,
    )])
    .await
    .unwrap();
    b.set_netmap(vec![make_peer(
        a.node_public(),
        a.disco_public(),
        vec![],
        0,
    )])
    .await
    .unwrap();
    relay.wait_for_dropped_packets(2).await;
    assert!(a
        .inner
        .endpoints
        .read()
        .unwrap()
        .get(&b.node_public())
        .unwrap()
        .candidates()
        .is_empty());
    assert!(b
        .inner
        .endpoints
        .read()
        .unwrap()
        .get(&a.node_public())
        .unwrap()
        .candidates()
        .is_empty());

    // This attempt's CMM makes B probe A over UDP. Its existing first-pong
    // contract permits either a DERP or direct result.
    let _first = tokio::time::timeout(
        Duration::from_secs(2),
        a.cli_ping(&b.node_public(), "b", "100.64.0.2".parse().unwrap(), 0),
    )
    .await
    .expect("first CLI ping should not time out")
    .expect("first CLI ping should complete");

    let learned_candidate = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if !a
                .inner
                .endpoints
                .read()
                .unwrap()
                .get(&b.node_public())
                .unwrap()
                .candidates()
                .is_empty()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .is_ok();
    assert!(
        learned_candidate,
        "B's CMM-triggered UDP probe should teach A B's source address"
    );

    // For one attempt, remove the CMM and DERP ping from the fake relay.
    // The learned UDP candidate ping is then the only callback-completing
    // path, proving the CLI path can return Direct without changing its
    // production first-pong behavior.
    let drops_before = relay.dropped_packets();
    relay.drop_next_packets(2).await;
    let direct = tokio::time::timeout(
        Duration::from_secs(2),
        a.cli_ping(&b.node_public(), "b", "100.64.0.2".parse().unwrap(), 0),
    )
    .await
    .expect("CLI ping should return through the learned direct candidate")
    .expect("CLI ping should complete");
    tokio::time::timeout(
        Duration::from_secs(1),
        relay.wait_for_dropped_packets(drops_before + 2),
    )
    .await
    .expect("the attempt's CMM and DERP ping should be dropped");
    assert!(
        !direct.Endpoint.is_empty(),
        "CLI ping should return its direct endpoint when DERP is unavailable"
    );
    assert_eq!(a.peer_path_class(&b.node_public()), PathClass::Direct);
}

#[tokio::test]
async fn cli_ping_fans_out_udp_and_derp() {
    let relay = Arc::new(FakeRelay::new());
    let a_priv = NodePrivate::generate();
    let b_priv = NodePrivate::generate();
    let a_derp = connect_to_relay(&relay, a_priv.clone()).await;
    let (a, _a_rx) = Magicsock::new(MagicsockConfig {
        private_key: a_priv,
        disco_key: DiscoPrivate::generate(),
        derp_client: Some(a_derp),
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
    })
    .await
    .unwrap();
    let b_derp = connect_to_relay(&relay, b_priv.clone()).await;
    let (b, _b_rx) = Magicsock::new(MagicsockConfig {
        private_key: b_priv,
        disco_key: DiscoPrivate::generate(),
        derp_client: Some(b_derp),
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
    relay.wait_for_clients(2).await;

    // Port 9 has no peer listener, so only the independently sent DERP ping
    // can answer. Its pending UDP ping proves both paths were started.
    a.set_netmap(vec![make_peer(
        b.node_public(),
        b.disco_public(),
        vec!["127.0.0.1:9".to_owned()],
        1,
    )])
    .await
    .unwrap();
    b.set_netmap(vec![make_peer(
        a.node_public(),
        a.disco_public(),
        vec![],
        1,
    )])
    .await
    .unwrap();

    let result = a
        .cli_ping(&b.node_public(), "b", "100.64.0.2".parse().unwrap(), 0)
        .await
        .expect("DERP CLI pong");
    assert_eq!(result.DERPRegionID, 1);
    let pending_udp = a
        .inner
        .endpoints
        .read()
        .unwrap()
        .get(&b.node_public())
        .unwrap()
        .pending_pings_count();
    assert!(pending_udp > 0, "UDP candidate ping should also be pending");
}

#[tokio::test]
async fn cli_ping_with_unknown_derp_region_uses_fanout() {
    let relay = Arc::new(FakeRelay::new());
    let a_priv = NodePrivate::generate();
    let b_priv = NodePrivate::generate();
    let a_derp = connect_to_relay(&relay, a_priv.clone()).await;
    let (a, _a_rx) = Magicsock::new(MagicsockConfig {
        private_key: a_priv,
        disco_key: DiscoPrivate::generate(),
        derp_client: Some(a_derp),
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
    let b_derp = connect_to_relay(&relay, b_priv.clone()).await;
    let (b, _b_rx) = Magicsock::new(MagicsockConfig {
        private_key: b_priv,
        disco_key: DiscoPrivate::generate(),
        derp_client: Some(b_derp),
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
    relay.wait_for_clients(2).await;

    // No UDP candidates or known DERP route leaves fanout as the only path.
    a.set_netmap(vec![make_peer(
        b.node_public(),
        b.disco_public(),
        vec![],
        0,
    )])
    .await
    .unwrap();
    b.set_netmap(vec![make_peer(
        a.node_public(),
        a.disco_public(),
        vec![],
        1,
    )])
    .await
    .unwrap();

    let packets_before = relay.forwarded_packets();
    let result = a
        .cli_ping(&b.node_public(), "b", "100.64.0.2".parse().unwrap(), 0)
        .await
        .expect("DERP CLI pong");
    assert_eq!(result.DERPRegionID, 1);
    tokio::time::timeout(
        Duration::from_secs(1),
        relay.wait_for_forwarded_packets(packets_before + 3),
    )
    .await
    .expect("unknown-region CMM, CLI ping, and pong should all reach the relay");
    assert_eq!(
        relay.forwarded_packets() - packets_before,
        3,
        "unknown-region CLI ping must fan out both CallMeMaybe and its DERP ping"
    );
}

#[tokio::test]
async fn derp_or_none_send_starts_rate_limited_direct_discovery() {
    // No UDP socket and no DERP client keeps this deterministic in the test
    // sandbox: send() has no usable data path, but it must still start direct
    // discovery for the advertised candidate exactly once per interval.
    let private_key = NodePrivate::generate();
    let peer_key = NodePrivate::generate().public();
    let peer_disco = DiscoPrivate::generate().public();
    let (magicsock, _rx) = Magicsock::new(MagicsockConfig {
        private_key,
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
    magicsock
        .set_netmap(vec![make_peer(
            peer_key.clone(),
            peer_disco,
            vec!["127.0.0.1:4242".to_owned(), "127.0.0.1:4243".to_owned()],
            0,
        )])
        .await
        .unwrap();

    assert_eq!(magicsock.peer_path_class(&peer_key), PathClass::None);
    assert_eq!(
        magicsock
            .inner
            .endpoints
            .read()
            .unwrap()
            .get(&peer_key)
            .unwrap()
            .pending_pings_count(),
        0
    );

    assert!(magicsock.send(peer_key.clone(), b"first").await.is_err());
    tokio::task::yield_now().await;
    let pending_after_first_send = magicsock
        .inner
        .endpoints
        .read()
        .unwrap()
        .get(&peer_key)
        .unwrap()
        .pending_pings_count();
    assert_eq!(pending_after_first_send, 2, "send should fan out discovery");

    assert!(magicsock.send(peer_key.clone(), b"second").await.is_err());
    tokio::task::yield_now().await;
    let pending_after_second_send = magicsock
        .inner
        .endpoints
        .read()
        .unwrap()
        .get(&peer_key)
        .unwrap()
        .pending_pings_count();
    assert_eq!(
        pending_after_second_send, pending_after_first_send,
        "a second immediate send must not start another discovery round"
    );
}

#[tokio::test]
async fn derp_send_starts_rate_limited_direct_discovery() {
    let relay = Arc::new(FakeRelay::new());
    let private_key = NodePrivate::generate();
    let peer_key = NodePrivate::generate().public();
    let peer_disco = DiscoPrivate::generate().public();
    let derp_client = connect_to_relay(&relay, private_key.clone()).await;
    let (magicsock, _rx) = Magicsock::new(MagicsockConfig {
        private_key,
        disco_key: DiscoPrivate::generate(),
        derp_client: Some(derp_client),
        derp_map: None,
        home_derp_region: 1,
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
    magicsock
        .set_netmap(vec![make_peer(
            peer_key.clone(),
            peer_disco,
            vec!["127.0.0.1:4343".to_owned(), "127.0.0.1:4344".to_owned()],
            1,
        )])
        .await
        .unwrap();

    assert_eq!(magicsock.peer_path_class(&peer_key), PathClass::Derp);
    magicsock.send(peer_key.clone(), b"first").await.unwrap();
    tokio::task::yield_now().await;
    let pending_after_first_send = magicsock
        .inner
        .endpoints
        .read()
        .unwrap()
        .get(&peer_key)
        .unwrap()
        .pending_pings_count();
    assert_eq!(
        pending_after_first_send, 2,
        "DERP send should fan out discovery"
    );

    magicsock.send(peer_key.clone(), b"second").await.unwrap();
    tokio::task::yield_now().await;
    assert_eq!(
        magicsock
            .inner
            .endpoints
            .read()
            .unwrap()
            .get(&peer_key)
            .unwrap()
            .pending_pings_count(),
        pending_after_first_send,
        "a second immediate DERP send must not start another discovery round"
    );
}

// ---- Test (b): Direct path upgrade over loopback UDP ----

#[tokio::test]
async fn direct_path_upgrade_over_udp() {
    let relay = Arc::new(FakeRelay::new());

    let a_priv = NodePrivate::generate();
    let b_priv = NodePrivate::generate();

    let a_derp = connect_to_relay(&relay, a_priv.clone()).await;
    let (a, _a_rx) = Magicsock::new(MagicsockConfig {
        private_key: a_priv,
        disco_key: DiscoPrivate::generate(),
        derp_client: Some(a_derp),
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
    })
    .await
    .expect("A magicsock");

    let b_derp = connect_to_relay(&relay, b_priv.clone()).await;
    let (b, mut b_rx) = Magicsock::new(MagicsockConfig {
        private_key: b_priv,
        disco_key: DiscoPrivate::generate(),
        derp_client: Some(b_derp),
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
    })
    .await
    .expect("B magicsock");

    let a_udp = a.bound_udp_addr().unwrap().to_string();
    let b_udp = b.bound_udp_addr().unwrap().to_string();

    let b_peer = make_peer(b.node_public(), b.disco_public(), vec![b_udp], 1);
    let a_peer = make_peer(a.node_public(), a.disco_public(), vec![a_udp], 1);
    a.set_netmap(vec![b_peer]).await.expect("A set_netmap");
    b.set_netmap(vec![a_peer]).await.expect("B set_netmap");

    // Wait for disco ping/pong to establish direct paths.
    let deadline = Duration::from_secs(3);
    let start = std::time::Instant::now();
    let mut a_direct = false;
    let mut b_direct = false;
    while start.elapsed() < deadline {
        if a.peer_direct_trusted(&b.node_public()) {
            a_direct = true;
        }
        if b.peer_direct_trusted(&a.node_public()) {
            b_direct = true;
        }
        if a_direct && b_direct {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(a_direct, "A should have a trusted direct path to B");
    assert!(b_direct, "B should have a trusted direct path to A");

    assert_eq!(
        a.peer_path_class(&b.node_public()),
        PathClass::Direct,
        "A's path to B should be Direct"
    );
    assert_eq!(
        b.peer_path_class(&a.node_public()),
        PathClass::Direct,
        "B's path to A should be Direct"
    );

    // A direct batch remains ordered and is delivered as one datagram per UDP
    // send, using the already-established direct path snapshot.
    let datagrams = [
        b"\x08\x07\x06\x05 direct wg packet one".as_slice(),
        b"\x08\x07\x06\x05 direct wg packet two".as_slice(),
    ];
    a.send_batch(b.node_public(), &datagrams)
        .await
        .expect("A batch send");
    for datagram in datagrams {
        let received = tokio::time::timeout(Duration::from_secs(2), b_rx.recv())
            .await
            .expect("timed out waiting for B recv")
            .expect("B poll_recv");
        assert_eq!(received.peer, a.node_public());
        assert_eq!(received.data, datagram);
    }
}

// ---- Test: trust expiry downgrades to DERP ----

#[tokio::test]
async fn trust_expiry_downgrades_to_derp() {
    let relay = Arc::new(FakeRelay::new());

    let a_priv = NodePrivate::generate();
    let b_priv = NodePrivate::generate();

    let a_derp = connect_to_relay(&relay, a_priv.clone()).await;
    let (a, _a_rx) = Magicsock::new(MagicsockConfig {
        private_key: a_priv,
        disco_key: DiscoPrivate::generate(),
        derp_client: Some(a_derp),
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
    })
    .await
    .expect("A magicsock");

    let b_derp = connect_to_relay(&relay, b_priv.clone()).await;
    let (b, _b_rx) = Magicsock::new(MagicsockConfig {
        private_key: b_priv,
        disco_key: DiscoPrivate::generate(),
        derp_client: Some(b_derp),
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
    })
    .await
    .expect("B magicsock");

    let a_udp = a.bound_udp_addr().unwrap().to_string();
    let b_udp = b.bound_udp_addr().unwrap().to_string();
    let b_peer = make_peer(b.node_public(), b.disco_public(), vec![b_udp], 1);
    let a_peer = make_peer(a.node_public(), a.disco_public(), vec![a_udp], 1);
    a.set_netmap(vec![b_peer]).await.unwrap();
    b.set_netmap(vec![a_peer]).await.unwrap();

    // Wait for direct path.
    let deadline = Duration::from_secs(3);
    let start = std::time::Instant::now();
    while start.elapsed() < deadline && !a.peer_direct_trusted(&b.node_public()) {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(a.peer_direct_trusted(&b.node_public()));
    assert_eq!(a.peer_path_class(&b.node_public()), PathClass::Direct);

    // Manually expire the trust.
    {
        let mut endpoints = a.inner.endpoints.write().expect("endpoints lock poisoned");
        if let Some(ep) = endpoints.get_mut(&b.node_public()) {
            let past = std::time::Instant::now()
                .checked_sub(Duration::from_secs(100))
                .unwrap();
            ep.confirm_direct(
                std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0),
                past,
            );
        }
    }

    assert_eq!(
        a.peer_path_class(&b.node_public()),
        PathClass::Derp,
        "expired direct should fall back to DERP"
    );
}

// ---- Test: send to unknown peer errors ----

#[tokio::test]
async fn send_unknown_peer_errors() {
    let relay = Arc::new(FakeRelay::new());
    let privk = NodePrivate::generate();
    let derp = connect_to_relay(&relay, privk.clone()).await;
    let (a, _a_rx) = Magicsock::new(MagicsockConfig {
        private_key: privk,
        disco_key: DiscoPrivate::generate(),
        derp_client: Some(derp),
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

    let unknown = NodePrivate::generate().public();
    assert!(a
        .send_batch(unknown.clone(), &[] as &[Vec<u8>])
        .await
        .is_ok());
    assert!(a.send(unknown, b"hello").await.is_err());
}

// ---- Test: multi-region DERP — A lazily connects to B's home region ----

/// Two fake DERP servers in different regions. Node A is homed to region 1,
/// node B is homed to region 2. A must lazily connect to region 2 to send
/// WG data to B, and B must lazily connect to region 1 to reply.
///
/// Since FakeRelay uses in-process duplex streams (not real TCP), we can't
/// test lazy TCP connections here. Instead we pre-connect both relays and
/// pass them as the derp_map with `InsecureForTests`-style config. But
/// `connect_with_upgrade_dial` needs real TCP, so for this test we inject
/// pre-connected DerpClients for BOTH regions and verify routing.
#[tokio::test]
async fn multi_region_derp_routing() {
    let relay1 = Arc::new(FakeRelay::new());
    let relay2 = Arc::new(FakeRelay::new());

    let a_priv = NodePrivate::generate();
    let b_priv = NodePrivate::generate();

    // A connects to relay1 (region 1, home) and relay2 (region 2, peer's home).
    let a_derp_home = connect_to_relay(&relay1, a_priv.clone()).await;
    let a_derp_r2 = connect_to_relay(&relay2, a_priv.clone()).await;

    // B connects to relay2 (region 2, home) and relay1 (region 1, peer's home).
    let b_derp_home = connect_to_relay(&relay2, b_priv.clone()).await;
    let b_derp_r1 = connect_to_relay(&relay1, b_priv.clone()).await;

    // Build a DERPMap with two regions (not used for connecting, just for
    // structural completeness — the connections are pre-injected).
    let _derp_map = DERPMap {
        Regions: [
            (
                1,
                DERPRegion {
                    RegionID: 1,
                    RegionCode: "r1".into(),
                    RegionName: "Region 1".into(),
                    Nodes: Some(vec![DERPNode {
                        Name: "1a".into(),
                        RegionID: 1,
                        HostName: "r1.test".into(),
                        ..Default::default()
                    }]),
                    ..Default::default()
                },
            ),
            (
                2,
                DERPRegion {
                    RegionID: 2,
                    RegionCode: "r2".into(),
                    RegionName: "Region 2".into(),
                    Nodes: Some(vec![DERPNode {
                        Name: "2a".into(),
                        RegionID: 2,
                        HostName: "r2.test".into(),
                        ..Default::default()
                    }]),
                    ..Default::default()
                },
            ),
        ]
        .into_iter()
        .collect(),
        ..Default::default()
    };

    // Create magicsock A with home region 1. We inject BOTH DERP connections
    // by first creating with the home client, then manually inserting the
    // region 2 connection into the DerpManager.
    let (a, mut a_rx) = Magicsock::new(MagicsockConfig {
        private_key: a_priv,
        disco_key: DiscoPrivate::generate(),
        derp_client: Some(a_derp_home),
        derp_map: None,
        home_derp_region: 1,
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
    .expect("A magicsock");

    // Manually inject region 2 connection into A's DerpManager.
    {
        let mut conns = a
            .inner
            .derp
            .connections
            .write()
            .expect("derp connections lock poisoned");
        let io2 = Arc::new(DerpIo::spawn(a_derp_r2));
        // The DerpManager needs to spawn a recv consumer for this connection.
        // We can't do that from here, but the DerpIo's internal reader task
        // feeds a channel. We need to also spawn a consumer.
        // Actually, let's spawn it here — including the reconnect signal.
        let tx = a.inner.derp.derp_recv_tx.clone();
        let reconnect_tx = a.inner.derp.reconnect_tx.clone();
        let io2_clone = io2.clone();
        tokio::spawn(async move {
            while let Some(event) = io2_clone.try_recv().await {
                if tx.send((2, event)).await.is_err() {
                    break;
                }
            }
            let _ = reconnect_tx.send(2);
        });
        conns.insert(2, io2);
    }

    // Create magicsock B with home region 2. Similarly inject region 1.
    let (b, mut b_rx) = Magicsock::new(MagicsockConfig {
        private_key: b_priv,
        disco_key: DiscoPrivate::generate(),
        derp_client: Some(b_derp_home),
        derp_map: None,
        home_derp_region: 2,
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
    .expect("B magicsock");

    {
        let mut conns = b
            .inner
            .derp
            .connections
            .write()
            .expect("derp connections lock poisoned");
        let io1 = Arc::new(DerpIo::spawn(b_derp_r1));
        let tx = b.inner.derp.derp_recv_tx.clone();
        let reconnect_tx = b.inner.derp.reconnect_tx.clone();
        let io1_clone = io1.clone();
        tokio::spawn(async move {
            while let Some(event) = io1_clone.try_recv().await {
                if tx.send((1, event)).await.is_err() {
                    break;
                }
            }
            let _ = reconnect_tx.send(1);
        });
        conns.insert(1, io1);
    }

    // Each knows about the other via the netmap, with DIFFERENT home DERP.
    let b_peer = make_peer(b.node_public(), b.disco_public(), vec![], 2);
    let a_peer = make_peer(a.node_public(), a.disco_public(), vec![], 1);

    // Give relays time to fully register all clients.
    tokio::time::sleep(Duration::from_millis(200)).await;

    a.set_netmap(vec![b_peer]).await.expect("A set_netmap");
    b.set_netmap(vec![a_peer]).await.expect("B set_netmap");

    // A sends a WG datagram to B — A routes to B's home DERP (region 2).
    let wg_datagram = b"\x00\x01\x02\x03 multi-region wg from A";
    a.send(b.node_public(), wg_datagram)
        .await
        .expect("A send to B via region 2");

    // B should receive the WG datagram (via region 2 relay).
    let mut got_wg = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if let Ok(Some(d)) = tokio::time::timeout(Duration::from_millis(500), b_rx.recv()).await {
            if d.data == wg_datagram {
                got_wg = Some(d);
                break;
            }
        }
    }
    let received = got_wg.expect("B should receive A's WG datagram via region 2");
    assert_eq!(received.peer, a.node_public());
    assert_eq!(received.data, wg_datagram);

    // B sends back to A — B routes to A's home DERP (region 1).
    let wg_reply = b"\x00\x04\x05\x06 multi-region wg from B";
    b.send(a.node_public(), wg_reply)
        .await
        .expect("B send to A via region 1");

    let received = tokio::time::timeout(Duration::from_secs(5), a_rx.recv())
        .await
        .expect("timed out waiting for A recv via region 1")
        .expect("A poll_recv");
    assert_eq!(received.peer, b.node_public());
    assert_eq!(received.data, wg_reply);
}

// ---- Test: PMTUD disabled by default ----

#[tokio::test]
async fn pmtud_disabled_by_default() {
    let relay = Arc::new(FakeRelay::new());
    let privk = NodePrivate::generate();
    let derp = connect_to_relay(&relay, privk.clone()).await;
    let (a, _a_rx) = Magicsock::new(MagicsockConfig {
        private_key: privk,
        disco_key: DiscoPrivate::generate(),
        derp_client: Some(derp),
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
    })
    .await
    .expect("magicsock");

    assert!(!a.peer_mtu_enabled(), "PMTUD should be disabled by default");

    a.set_pmtud_enabled(true);
    assert!(a.peer_mtu_enabled(), "PMTUD should be enabled after set");
}

// ---- Test: PMTUD flag -> multi-size ping burst ----

#[tokio::test]
async fn pmtud_flag_multi_size_burst() {
    let relay = Arc::new(FakeRelay::new());

    let a_priv = NodePrivate::generate();
    let b_priv = NodePrivate::generate();

    let a_derp = connect_to_relay(&relay, a_priv.clone()).await;
    let (a, _a_rx) = Magicsock::new(MagicsockConfig {
        private_key: a_priv,
        disco_key: DiscoPrivate::generate(),
        derp_client: Some(a_derp),
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
    })
    .await
    .expect("A magicsock");

    a.set_pmtud_enabled(true);

    let b_derp = connect_to_relay(&relay, b_priv.clone()).await;
    let (b, _b_rx) = Magicsock::new(MagicsockConfig {
        private_key: b_priv,
        disco_key: DiscoPrivate::generate(),
        derp_client: Some(b_derp),
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
    })
    .await
    .expect("B magicsock");

    let b_udp = b.bound_udp_addr().unwrap().to_string();
    let b_peer = make_peer(b.node_public(), b.disco_public(), vec![b_udp], 1);

    a.set_netmap(vec![b_peer]).await.expect("A set_netmap");

    // With PMTUD enabled, each candidate gets 6 pings (WIRE_MTUS_TO_PROBE).
    let pending_count = {
        let endpoints = a.inner.endpoints.read().expect("endpoints lock poisoned");
        endpoints
            .get(&b.node_public())
            .map_or(0, super::endpoint::Endpoint::pending_pings_count)
    };
    assert!(
        pending_count >= 6,
        "expected at least 6 pending pings with PMTUD, got {pending_count}"
    );
}

// ---- Test: PeerGone removes DERP route ----

#[tokio::test]
async fn peer_gone_removes_derp_route() {
    let relay = Arc::new(FakeRelay::new());

    let a_priv = NodePrivate::generate();
    let b_priv = NodePrivate::generate();
    let b_key = b_priv.public();

    let a_derp = connect_to_relay(&relay, a_priv.clone()).await;
    let (a, _a_rx) = Magicsock::new(MagicsockConfig {
        private_key: a_priv,
        disco_key: DiscoPrivate::generate(),
        derp_client: Some(a_derp),
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
    })
    .await
    .expect("A magicsock");

    // Set up peer B in A's netmap with HomeDERP=1.
    let b_peer = make_peer(b_key.clone(), DiscoPrivate::generate().public(), vec![], 1);
    a.set_netmap(vec![b_peer]).await.expect("A set_netmap");

    // Simulate a DERP packet from B arriving on region 3 — this sets
    // last_recv_derp_region to 3.
    {
        let mut endpoints = a.inner.endpoints.write().expect("endpoints lock poisoned");
        if let Some(ep) = endpoints.get_mut(&b_key) {
            ep.set_last_recv_derp_region(3);
            assert_eq!(ep.derp_send_region(), 3);
        }
    }

    // Simulate a PeerGone event for B on region 3.
    a.inner.handle_derp_peer_gone(b_key.clone(), 3, 0);

    // The DERP route should be cleared — derp_send_region falls back to
    // home_derp (1).
    {
        let endpoints = a.inner.endpoints.read().expect("endpoints lock poisoned");
        if let Some(ep) = endpoints.get(&b_key) {
            assert_eq!(
                ep.derp_send_region(),
                1,
                "derp_send_region should fall back to home_derp after PeerGone"
            );
            assert_eq!(
                ep.last_recv_derp_region_for_debug(),
                0,
                "last_recv_derp_region should be 0 after PeerGone"
            );
        }
    }
}

// ---- Test: DERP region health tracking ----

#[tokio::test]
async fn derp_region_health_tracking() {
    use rustscale_health::Tracker;

    let health = Tracker::new();
    let relay = Arc::new(FakeRelay::new());

    let a_priv = NodePrivate::generate();
    let a_derp = connect_to_relay(&relay, a_priv.clone()).await;
    let (a, _a_rx) = Magicsock::new(MagicsockConfig {
        private_key: a_priv,
        disco_key: DiscoPrivate::generate(),
        derp_client: Some(a_derp),
        derp_map: None,
        home_derp_region: 0,
        udp_bind: Some("127.0.0.1:0".parse().unwrap()),
        udp_socket: None,
        portmapper: None,
        health: Some(health.clone()),
        disable_direct_paths: false,
        peer_relay_server: false,
        relay_server_config: None,
        sockstats: None,
        control_knobs: None,
    })
    .await
    .expect("A magicsock");

    // Initially, region 1 has no health record.
    assert!(!health.is_unhealthy("derp-region-1-unreachable"));

    // Mark region 1 unhealthy via a Health event with a non-empty problem.
    a.inner
        .derp
        .health
        .as_ref()
        .unwrap()
        .set_derp_region_health(1, false);
    assert!(health.is_unhealthy("derp-region-1-unreachable"));

    // Mark it healthy again.
    a.inner
        .derp
        .health
        .as_ref()
        .unwrap()
        .set_derp_region_health(1, true);
    assert!(!health.is_unhealthy("derp-region-1-unreachable"));
}
