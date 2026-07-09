//! Back-to-back netstack test: two netstacks wired through in-memory WG tunnels.
//!
//! Exercises the full data path: TCP dial from A to B's listener, bidirectional
//! data exchange, and clean close — all over WireGuard-encapsulated IP packets
//! pumped through in-memory tunnels (no real network).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;

use rustscale_key::NodePrivate;
use rustscale_wg::WgTunn;

use crate::{Netstack, DEFAULT_MTU};

/// Cross-feed a WG datagram from src to dst, recursively handling reply chains.
fn cross_feed(
    datagram: &[u8],
    dst_tunn: &Mutex<WgTunn>,
    src_tunn: &Mutex<WgTunn>,
    dst_net: &Netstack,
    src_net: &Netstack,
) {
    let decap = dst_tunn
        .lock()
        .expect("dst lock")
        .decapsulate(datagram)
        .unwrap_or_default();
    if let Some(pt) = decap.plaintext {
        dst_net.push_rx(pt);
    }
    for reply in decap.replies {
        let src_decap = src_tunn
            .lock()
            .expect("src lock")
            .decapsulate(&reply)
            .unwrap_or_default();
        if let Some(pt) = src_decap.plaintext {
            src_net.push_rx(pt);
        }
        for r2 in src_decap.replies {
            cross_feed(&r2, dst_tunn, src_tunn, dst_net, src_net);
        }
    }
}

/// One pump cycle: drain outgoing from both netstacks, encapsulate, cross-feed,
/// tick timers, cross-feed timer output.
fn pump_cycle(
    a_tunn: &Mutex<WgTunn>,
    b_tunn: &Mutex<WgTunn>,
    a_net: &Netstack,
    b_net: &Netstack,
) -> bool {
    let mut did_work = false;

    // A -> B
    while let Some(pkt) = a_net.pop_tx() {
        did_work = true;
        let dgs = a_tunn
            .lock()
            .expect("a lock")
            .encapsulate(&pkt)
            .unwrap_or_default();
        for dg in dgs {
            cross_feed(&dg, b_tunn, a_tunn, b_net, a_net);
        }
    }

    // B -> A
    while let Some(pkt) = b_net.pop_tx() {
        did_work = true;
        let dgs = b_tunn
            .lock()
            .expect("b lock")
            .encapsulate(&pkt)
            .unwrap_or_default();
        for dg in dgs {
            cross_feed(&dg, a_tunn, b_tunn, a_net, b_net);
        }
    }

    // Tick timers (flush queued data, retransmissions, keepalives).
    for dg in a_tunn.lock().expect("a timers").tick_timers() {
        did_work = true;
        cross_feed(&dg, b_tunn, a_tunn, b_net, a_net);
    }
    for dg in b_tunn.lock().expect("b timers").tick_timers() {
        did_work = true;
        cross_feed(&dg, a_tunn, b_tunn, a_net, b_net);
    }

    did_work
}

#[tokio::test]
async fn back_to_back_dial_and_echo() {
    let a_priv = NodePrivate::generate();
    let b_priv = NodePrivate::generate();
    let a_pub = a_priv.public();
    let b_pub = b_priv.public();

    let a_addr = Ipv4Addr::new(100, 64, 0, 1);
    let b_addr = Ipv4Addr::new(100, 64, 0, 2);

    let a_net = Arc::new(Netstack::new(a_addr, DEFAULT_MTU));
    let b_net = Arc::new(Netstack::new(b_addr, DEFAULT_MTU));

    let a_tunn = Arc::new(Mutex::new(
        WgTunn::new(&a_priv, &b_pub, 1).expect("A tunnel"),
    ));
    let b_tunn = Arc::new(Mutex::new(
        WgTunn::new(&b_priv, &a_pub, 2).expect("B tunnel"),
    ));

    // Spawn the pump loop.
    let a_tunn_p = a_tunn.clone();
    let b_tunn_p = b_tunn.clone();
    let a_net_p = a_net.clone();
    let b_net_p = b_net.clone();
    let pump = tokio::spawn(async move {
        let a_tx = a_net_p.tx_notify();
        let b_tx = b_net_p.tx_notify();
        loop {
            let did_work = pump_cycle(&a_tunn_p, &b_tunn_p, &a_net_p, &b_net_p);
            if !did_work {
                tokio::select! {
                    _ = a_tx.notified() => {}
                    _ = b_tx.notified() => {}
                    _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => {}
                }
            }
        }
    });

    // B listens on port 12345.
    let mut listener = b_net.listen(12345).await.expect("listen");

    // A dials B. Use a timeout — the WG + TCP handshake takes several pump cycles.
    let dial_result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        a_net.dial(SocketAddr::new(b_addr.into(), 12345)),
    )
    .await;
    let mut a_stream = dial_result.expect("dial timed out").expect("dial failed");

    // B accepts.
    let accept_result =
        tokio::time::timeout(std::time::Duration::from_secs(10), listener.accept()).await;
    let mut b_stream = accept_result
        .expect("accept timed out")
        .expect("accept failed");

    // A sends data to B.
    tokio::io::AsyncWriteExt::write_all(&mut a_stream, b"hello from A")
        .await
        .expect("A write");

    // B reads and echoes back.
    let mut buf = [0u8; 32];
    let n = tokio::io::AsyncReadExt::read(&mut b_stream, &mut buf)
        .await
        .expect("B read");
    assert_eq!(&buf[..n], b"hello from A");

    // B sends data to A.
    tokio::io::AsyncWriteExt::write_all(&mut b_stream, b"hello from B")
        .await
        .expect("B write");

    // A reads.
    let n = tokio::io::AsyncReadExt::read(&mut a_stream, &mut buf)
        .await
        .expect("A read");
    assert_eq!(&buf[..n], b"hello from B");

    // Clean close.
    tokio::io::AsyncWriteExt::shutdown(&mut a_stream)
        .await
        .expect("A shutdown");

    pump.abort();
}

#[tokio::test]
async fn listen_rejects_duplicate_port() {
    let addr = Ipv4Addr::new(100, 64, 0, 1);
    let net = Netstack::new(addr, DEFAULT_MTU);

    let _listener1 = net.listen(8080).await.expect("first listen");
    let result = net.listen(8080).await;
    assert!(result.is_err(), "duplicate port should fail");
}

/// Push a payload much larger than the TCP send buffer (65 KB) through the
/// back-to-back rig and verify zero data loss with correct byte ordering.
/// This exercises the backpressure fix in `pump_connection`: when the
/// smoltcp send buffer fills, the unwritten remainder is retained and the
/// app channel is not drained, so `poll_write` returns Pending to the app
/// until ACKs free up send capacity. Without the fix, the surplus was
/// silently dropped.
#[tokio::test]
async fn backpressure_large_transfer_no_loss() {
    let a_priv = NodePrivate::generate();
    let b_priv = NodePrivate::generate();
    let a_pub = a_priv.public();
    let b_pub = b_priv.public();

    let a_addr = Ipv4Addr::new(100, 64, 0, 1);
    let b_addr = Ipv4Addr::new(100, 64, 0, 2);

    let a_net = Arc::new(Netstack::new(a_addr, DEFAULT_MTU));
    let b_net = Arc::new(Netstack::new(b_addr, DEFAULT_MTU));

    let a_tunn = Arc::new(Mutex::new(
        WgTunn::new(&a_priv, &b_pub, 1).expect("A tunnel"),
    ));
    let b_tunn = Arc::new(Mutex::new(
        WgTunn::new(&b_priv, &a_pub, 2).expect("B tunnel"),
    ));

    let a_tunn_p = a_tunn.clone();
    let b_tunn_p = b_tunn.clone();
    let a_net_p = a_net.clone();
    let b_net_p = b_net.clone();
    let pump = tokio::spawn(async move {
        let a_tx = a_net_p.tx_notify();
        let b_tx = b_net_p.tx_notify();
        loop {
            let did_work = pump_cycle(&a_tunn_p, &b_tunn_p, &a_net_p, &b_net_p);
            if !did_work {
                tokio::select! {
                    _ = a_tx.notified() => {}
                    _ = b_tx.notified() => {}
                    _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => {}
                }
            }
        }
    });

    // B listens.
    let mut listener = b_net.listen(20000).await.expect("listen");

    // A dials B.
    let dial_result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        a_net.dial(SocketAddr::new(b_addr.into(), 20000)),
    )
    .await;
    let mut a_stream = dial_result.expect("dial timed out").expect("dial failed");

    let accept_result =
        tokio::time::timeout(std::time::Duration::from_secs(10), listener.accept()).await;
    let mut b_stream = accept_result
        .expect("accept timed out")
        .expect("accept failed");

    // Build a 1 MB payload with a verifiable byte pattern. 1 MB >> the 65 KB
    // TCP send buffer, so the send buffer will fill repeatedly and the
    // backpressure path is exercised on every cycle.
    const PAYLOAD_SIZE: usize = 1 * 1024 * 1024;
    let payload: Vec<u8> = (0..PAYLOAD_SIZE)
        .map(|i| (i % 251) as u8) // prime modulus for a non-trivial pattern
        .collect();

    // A writes the full payload (write_all loops poll_write until done).
    let payload_write = payload.clone();
    let write_task = tokio::spawn(async move {
        tokio::io::AsyncWriteExt::write_all(&mut a_stream, &payload_write)
            .await
            .expect("A write_all");
        // Half-close so B sees EOF after the last byte.
        tokio::io::AsyncWriteExt::shutdown(&mut a_stream)
            .await
            .expect("A shutdown");
    });

    // B reads everything until EOF, verifying count + ordering.
    let mut received = Vec::with_capacity(PAYLOAD_SIZE);
    let mut buf = vec![0u8; 32_768];
    loop {
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            tokio::io::AsyncReadExt::read(&mut b_stream, &mut buf),
        )
        .await
        .expect("B read timed out")
        .expect("B read");
        if n == 0 {
            break;
        }
        received.extend_from_slice(&buf[..n]);
    }

    // Wait for the writer to finish.
    tokio::time::timeout(std::time::Duration::from_secs(10), write_task)
        .await
        .expect("write task timed out")
        .expect("write task panicked");

    pump.abort();

    // Zero loss + correct ordering.
    assert_eq!(
        received.len(),
        PAYLOAD_SIZE,
        "data loss: expected {PAYLOAD_SIZE} bytes, got {}",
        received.len()
    );
    assert_eq!(
        received, payload,
        "byte mismatch: data arrived out of order or corrupted"
    );
}

#[tokio::test]
async fn latency_small_message_round_trip() {
    let a_priv = NodePrivate::generate();
    let b_priv = NodePrivate::generate();
    let a_pub = a_priv.public();
    let b_pub = b_priv.public();

    let a_addr = Ipv4Addr::new(100, 64, 0, 1);
    let b_addr = Ipv4Addr::new(100, 64, 0, 2);

    let a_net = Arc::new(Netstack::new(a_addr, DEFAULT_MTU));
    let b_net = Arc::new(Netstack::new(b_addr, DEFAULT_MTU));

    let a_tunn = Arc::new(Mutex::new(
        WgTunn::new(&a_priv, &b_pub, 1).expect("A tunnel"),
    ));
    let b_tunn = Arc::new(Mutex::new(
        WgTunn::new(&b_priv, &a_pub, 2).expect("B tunnel"),
    ));

    let a_tunn_p = a_tunn.clone();
    let b_tunn_p = b_tunn.clone();
    let a_net_p = a_net.clone();
    let b_net_p = b_net.clone();
    let pump = tokio::spawn(async move {
        let a_tx = a_net_p.tx_notify();
        let b_tx = b_net_p.tx_notify();
        loop {
            let did_work = pump_cycle(&a_tunn_p, &b_tunn_p, &a_net_p, &b_net_p);
            if !did_work {
                tokio::select! {
                    _ = a_tx.notified() => {}
                    _ = b_tx.notified() => {}
                    _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => {}
                }
            }
        }
    });

    let mut listener = b_net.listen(30000).await.expect("listen");

    let dial_result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        a_net.dial(SocketAddr::new(b_addr.into(), 30000)),
    )
    .await;
    let mut a_stream = dial_result.expect("dial timed out").expect("dial failed");

    let accept_result =
        tokio::time::timeout(std::time::Duration::from_secs(10), listener.accept()).await;
    let mut b_stream = accept_result
        .expect("accept timed out")
        .expect("accept failed");

    let echo_task = tokio::spawn(async move {
        let mut buf = [0u8; 8];
        loop {
            let n = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                tokio::io::AsyncReadExt::read(&mut b_stream, &mut buf),
            )
            .await;
            match n {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    tokio::io::AsyncWriteExt::write_all(&mut b_stream, &buf[..n])
                        .await
                        .expect("echo write");
                }
                _ => break,
            }
        }
    });

    const ROUNDS: usize = 100;
    let msg = [0x42u8; 8];
    let mut rtts: Vec<std::time::Duration> = Vec::with_capacity(ROUNDS);

    for _ in 0..ROUNDS {
        let start = std::time::Instant::now();
        tokio::io::AsyncWriteExt::write_all(&mut a_stream, &msg)
            .await
            .expect("A write");
        let mut resp = [0u8; 8];
        tokio::io::AsyncReadExt::read_exact(&mut a_stream, &mut resp)
            .await
            .expect("A read");
        rtts.push(start.elapsed());
    }

    tokio::io::AsyncWriteExt::shutdown(&mut a_stream).await.ok();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), echo_task).await;
    pump.abort();

    rtts.sort();
    let p50 = rtts[ROUNDS / 2];
    let p95 = rtts[ROUNDS * 95 / 100];
    let p99 = rtts[ROUNDS * 99 / 100];

    eprintln!(
        "latency_small_message_round_trip: p50={:?} p95={:?} p99={:?}",
        p50, p95, p99
    );

    assert!(
        p50 < std::time::Duration::from_millis(20),
        "p50 latency too high: {:?} (expected < 20ms)",
        p50
    );
}
