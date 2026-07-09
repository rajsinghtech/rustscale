//! Integration and unit tests for magicsock.
//!
//! Test scenarios:
//! (a) Two Magicsock instances through a fake in-process DERP server,
//!     exchanging disco pings and falling back to DERP data path.
//! (b) Loopback UDP sockets achieving a direct path upgrade after ping/pong.
//! Plus unit tests for endpoint ranking and trust expiry (in endpoint.rs).

use super::*;
use rustscale_derp::{
    decode_frame_header, encode_frame_header, frame_type, DerpClient, Received, FRAME_HEADER_LEN,
    MAGIC, PROTOCOL_VERSION,
};
use rustscale_key::{DiscoPrivate, NodePrivate, NodePublic};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};

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
    format!(r#"{{"version":{}}}"#, PROTOCOL_VERSION).into_bytes()
}

/// Write a DERP frame to an async writer.

/// Fake DERP relay server that connects multiple clients and relays packets
/// between them. Speaks the real DERP wire protocol over tokio duplex streams.
struct FakeRelay {
    server_priv: NodePrivate,
    server_pub: NodePublic,
    senders: Arc<Mutex<HashMap<NodePublic, mpsc::UnboundedSender<(NodePublic, Vec<u8>)>>>>,
}

impl FakeRelay {
    fn new() -> Self {
        let privk = NodePrivate::generate();
        Self {
            server_pub: privk.public(),
            server_priv: privk,
            senders: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn public_key(&self) -> NodePublic {
        self.server_pub.clone()
    }

    /// Accept a new client connection and spawn per-client reader/writer tasks.
    fn accept(self: &Arc<Self>, stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static) {
        let server_priv = self.server_priv.clone();
        let server_pub = self.server_pub.clone();
        let senders = self.senders.clone();

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

            // 5. Split the stream for concurrent read + write.
            let (read_half, mut write_half) = tokio::io::split(s);

            // Reader task: reads SEND_PACKET frames and relays to other clients.
            let senders_r = senders.clone();
            let client_pub_r = client_pub.clone();
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
                                let senders = senders_r.lock().await;
                                if let Some(tx) = senders.get(&dst_pub) {
                                    let _ = tx.send((client_pub_r.clone(), data));
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
    DerpClient::from_stream(Box::new(client_stream), private_key)
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

// ---- Test (a): DERP data path fallback ----

#[tokio::test]
async fn derp_data_path_fallback() {
    let relay = Arc::new(FakeRelay::new());

    let a_priv = NodePrivate::generate();
    let b_priv = NodePrivate::generate();

    let a_derp = connect_to_relay(&relay, a_priv.clone()).await;
    let a = Magicsock::new(MagicsockConfig {
        private_key: a_priv,
        disco_key: DiscoPrivate::generate(),
        derp_client: Some(a_derp),
        udp_bind: None,
    })
    .await
    .expect("A magicsock");

    let b_derp = connect_to_relay(&relay, b_priv.clone()).await;
    let b = Magicsock::new(MagicsockConfig {
        private_key: b_priv,
        disco_key: DiscoPrivate::generate(),
        derp_client: Some(b_derp),
        udp_bind: None,
    })
    .await
    .expect("B magicsock");

    // Each knows about the other via the netmap.
    let b_peer = make_peer(b.node_public(), b.disco_public(), vec![], 1);
    let a_peer = make_peer(a.node_public(), a.disco_public(), vec![], 1);

    // Give relay time to fully register both clients.
    tokio::time::sleep(Duration::from_millis(100)).await;

    a.set_netmap(vec![b_peer]).await.expect("A set_netmap");
    b.set_netmap(vec![a_peer]).await.expect("B set_netmap");

    // A sends a WG datagram to B — no direct path, goes via DERP.
    let wg_datagram = b"\x00\x01\x02\x03 fake wg packet from A";
    a.send(b.node_public(), wg_datagram).await.expect("A send");

    // B may receive disco CallMeMaybe packets first; drain until we get the WG datagram.
    let mut got_wg = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), b.poll_recv()).await {
            Ok(Ok(d)) => {
                if d.data == wg_datagram {
                    got_wg = Some(d);
                    break;
                }
            }
            _ => {}
        }
    }
    let received = got_wg.expect("B should receive A's WG datagram");
    assert_eq!(received.peer, a.node_public());
    assert_eq!(received.data, wg_datagram);

    // B sends back to A.
    let wg_reply = b"\x00\x04\x05\x06 fake wg packet from B";
    b.send(a.node_public(), wg_reply).await.expect("B send");
    let received = tokio::time::timeout(Duration::from_secs(2), a.poll_recv())
        .await
        .expect("timed out waiting for A recv")
        .expect("A poll_recv");
    assert_eq!(received.peer, b.node_public());
    assert_eq!(received.data, wg_reply);
}

// ---- Test (b): Direct path upgrade over loopback UDP ----

#[tokio::test]
async fn direct_path_upgrade_over_udp() {
    let relay = Arc::new(FakeRelay::new());

    let a_priv = NodePrivate::generate();
    let b_priv = NodePrivate::generate();

    let a_derp = connect_to_relay(&relay, a_priv.clone()).await;
    let a = Magicsock::new(MagicsockConfig {
        private_key: a_priv,
        disco_key: DiscoPrivate::generate(),
        derp_client: Some(a_derp),
        udp_bind: Some("127.0.0.1:0".parse().unwrap()),
    })
    .await
    .expect("A magicsock");

    let b_derp = connect_to_relay(&relay, b_priv.clone()).await;
    let b = Magicsock::new(MagicsockConfig {
        private_key: b_priv,
        disco_key: DiscoPrivate::generate(),
        derp_client: Some(b_derp),
        udp_bind: Some("127.0.0.1:0".parse().unwrap()),
    })
    .await
    .expect("B magicsock");

    let a_udp = a.local_udp_addrs()[0].clone();
    let b_udp = b.local_udp_addrs()[0].clone();

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

    // Send a WG datagram over the direct path.
    let wg_datagram = b"\x08\x07\x06\x05 direct wg packet";
    a.send(b.node_public(), wg_datagram).await.expect("A send");
    let received = tokio::time::timeout(Duration::from_secs(2), b.poll_recv())
        .await
        .expect("timed out waiting for B recv")
        .expect("B poll_recv");
    assert_eq!(received.peer, a.node_public());
    assert_eq!(received.data, wg_datagram);
}

// ---- Test: trust expiry downgrades to DERP ----

#[tokio::test]
async fn trust_expiry_downgrades_to_derp() {
    let relay = Arc::new(FakeRelay::new());

    let a_priv = NodePrivate::generate();
    let b_priv = NodePrivate::generate();

    let a_derp = connect_to_relay(&relay, a_priv.clone()).await;
    let a = Magicsock::new(MagicsockConfig {
        private_key: a_priv,
        disco_key: DiscoPrivate::generate(),
        derp_client: Some(a_derp),
        udp_bind: Some("127.0.0.1:0".parse().unwrap()),
    })
    .await
    .expect("A magicsock");

    let b_derp = connect_to_relay(&relay, b_priv.clone()).await;
    let b = Magicsock::new(MagicsockConfig {
        private_key: b_priv,
        disco_key: DiscoPrivate::generate(),
        derp_client: Some(b_derp),
        udp_bind: Some("127.0.0.1:0".parse().unwrap()),
    })
    .await
    .expect("B magicsock");

    let a_udp = a.local_udp_addrs()[0].clone();
    let b_udp = b.local_udp_addrs()[0].clone();
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
            let past = std::time::Instant::now() - Duration::from_secs(100);
            ep.confirm_direct(
                std::net::SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                    0,
                ),
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
    let a = Magicsock::new(MagicsockConfig {
        private_key: privk,
        disco_key: DiscoPrivate::generate(),
        derp_client: Some(derp),
        udp_bind: None,
    })
    .await
    .expect("magicsock");

    let unknown = NodePrivate::generate().public();
    assert!(a.send(unknown, b"hello").await.is_err());
}
