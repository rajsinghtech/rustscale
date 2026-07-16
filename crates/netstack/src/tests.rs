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

use crate::{DialStats, Netstack, DEFAULT_MTU, TCP_BUF, TCP_DIAL_TIMEOUT};

#[test]
fn constructor_without_runtime_is_typed_error() {
    let result = std::panic::catch_unwind(|| Netstack::new(Ipv4Addr::LOCALHOST, DEFAULT_MTU));
    let error = match result.expect("must not panic") {
        Ok(_) => panic!("runtime is required"),
        Err(error) => error,
    };
    assert!(
        matches!(error, crate::NetstackError::Io(ref e) if e.kind() == std::io::ErrorKind::NotConnected)
    );
}

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

    let a_net = Arc::new(Netstack::new(a_addr, DEFAULT_MTU).unwrap());
    let b_net = Arc::new(Netstack::new(b_addr, DEFAULT_MTU).unwrap());

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
                    () = a_tx.notified() => {}
                    () = b_tx.notified() => {}
                    () = tokio::time::sleep(std::time::Duration::from_millis(10)) => {}
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
    let net = Netstack::new(addr, DEFAULT_MTU).unwrap();

    let _listener1 = net.listen(8080).await.expect("first listen");
    let result = net.listen(8080).await;
    assert!(result.is_err(), "duplicate port should fail");
}

#[tokio::test]
async fn tx_backlog_above_drain_batch_remains_observable() {
    let net = Netstack::new(Ipv4Addr::new(100, 64, 0, 1), DEFAULT_MTU).unwrap();
    for i in 0..65 {
        net.push_tx_for_test(vec![i]);
    }

    for _ in 0..64 {
        assert!(net.pop_tx().is_some());
    }
    assert!(
        net.has_tx_packets(),
        "a bounded pump drain must not treat its 65th packet as idle"
    );
    assert_eq!(net.pop_tx(), Some(vec![64]));
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

    let a_net = Arc::new(Netstack::new(a_addr, DEFAULT_MTU).unwrap());
    let b_net = Arc::new(Netstack::new(b_addr, DEFAULT_MTU).unwrap());

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
                    () = a_tx.notified() => {}
                    () = b_tx.notified() => {}
                    () = tokio::time::sleep(std::time::Duration::from_millis(10)) => {}
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
    const PAYLOAD_SIZE: usize = 1024 * 1024;
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

    let a_net = Arc::new(Netstack::new(a_addr, DEFAULT_MTU).unwrap());
    let b_net = Arc::new(Netstack::new(b_addr, DEFAULT_MTU).unwrap());

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
                    () = a_tx.notified() => {}
                    () = b_tx.notified() => {}
                    () = tokio::time::sleep(std::time::Duration::from_millis(10)) => {}
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

    eprintln!("latency_small_message_round_trip: p50={p50:?} p95={p95:?} p99={p99:?}");

    assert!(
        p50 < std::time::Duration::from_millis(20),
        "p50 latency too high: {p50:?} (expected < 20ms)"
    );
}

#[tokio::test]
async fn canceled_pending_dial_releases_socket_and_buffers_promptly() {
    let net = Arc::new(
        Netstack::new(Ipv4Addr::new(100, 64, 0, 1), DEFAULT_MTU).expect("create netstack"),
    );
    let dial_net = Arc::clone(&net);
    let dial = tokio::spawn(async move {
        dial_net
            .dial(SocketAddr::from(([100, 64, 0, 254], 9)))
            .await
    });

    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while net.dial_stats().pending_dials != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("pending dial was not registered");
    assert_eq!(net.dial_stats().pending_buffer_bytes, TCP_BUF * 2);

    dial.abort();
    let _ = dial.await;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while net.dial_stats() != DialStats::default() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("canceled dial retained pending socket buffers");
}

#[tokio::test(start_paused = true)]
async fn pending_dial_has_an_internal_deadline() {
    let net = Arc::new(
        Netstack::new(Ipv4Addr::new(100, 64, 0, 1), DEFAULT_MTU).expect("create netstack"),
    );
    let dial_net = Arc::clone(&net);
    let dial = tokio::spawn(async move {
        dial_net
            .dial(SocketAddr::from(([100, 64, 0, 254], 9)))
            .await
    });
    while net.dial_stats().pending_dials != 1 {
        tokio::task::yield_now().await;
    }
    tokio::time::advance(TCP_DIAL_TIMEOUT + std::time::Duration::from_millis(1)).await;
    let error = match dial.await.unwrap() {
        Ok(_) => panic!("pending dial unexpectedly connected"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("deadline exceeded"));
    assert_eq!(net.dial_stats(), DialStats::default());
}

/// Verify that multiple peers can connect simultaneously. Before the backlog
/// fix, only one listening socket existed per port — the second peer's SYN
/// was dropped because the single socket was mid-handshake. With a backlog
/// pool of 32 listening sockets, all 5 concurrent dials should succeed.
#[tokio::test]
async fn concurrent_connections_all_succeed() {
    let a_priv = NodePrivate::generate();
    let b_priv = NodePrivate::generate();
    let a_pub = a_priv.public();
    let b_pub = b_priv.public();

    let a_addr = Ipv4Addr::new(100, 64, 0, 1);
    let b_addr = Ipv4Addr::new(100, 64, 0, 2);

    let a_net = Arc::new(Netstack::new(a_addr, DEFAULT_MTU).unwrap());
    let b_net = Arc::new(Netstack::new(b_addr, DEFAULT_MTU).unwrap());

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
                    () = a_tx.notified() => {}
                    () = b_tx.notified() => {}
                    () = tokio::time::sleep(std::time::Duration::from_millis(1)) => {}
                }
            }
        }
    });

    // B listens.
    let mut listener = b_net.listen(40000).await.expect("listen");

    // A launches 5 concurrent dials to B.
    const NUM_CONCURRENT: usize = 5;
    let mut dial_handles = Vec::new();
    for _ in 0..NUM_CONCURRENT {
        let net = a_net.clone();
        dial_handles.push(tokio::spawn(async move {
            tokio::time::timeout(
                std::time::Duration::from_secs(15),
                net.dial(SocketAddr::new(b_addr.into(), 40000)),
            )
            .await
        }));
    }

    // B accepts all 5 connections.
    let mut accepted = 0;
    for _ in 0..NUM_CONCURRENT {
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(15), listener.accept()).await;
        match result {
            Ok(Ok(_stream)) => accepted += 1,
            Ok(Err(e)) => eprintln!("accept error: {e}"),
            Err(_) => eprintln!("accept timed out"),
        }
    }

    // All dials should have succeeded too.
    let mut dial_succeeded = 0;
    for handle in dial_handles {
        match handle.await {
            Ok(Ok(Ok(_stream))) => dial_succeeded += 1,
            Ok(Ok(Err(e))) => eprintln!("dial error: {e}"),
            Ok(Err(_)) => eprintln!("dial timed out"),
            Err(e) => eprintln!("dial task panicked: {e}"),
        }
    }

    pump.abort();

    assert_eq!(
        accepted, NUM_CONCURRENT,
        "only {accepted}/{NUM_CONCURRENT} connections were accepted"
    );
    assert_eq!(
        dial_succeeded, NUM_CONCURRENT,
        "only {dial_succeeded}/{NUM_CONCURRENT} dials succeeded"
    );
}

/// Verify that `add_addr` + `listen_on` allows listening on a VIP address
/// distinct from the node's primary tailnet IP. This exercises the service
/// listener path: a netstack with primary IP 100.64.0.2 adds a VIP
/// 100.64.0.10, listens on it, and a peer dials the VIP.
#[tokio::test]
async fn listen_on_vip_addr() {
    use std::net::IpAddr;

    let a_priv = NodePrivate::generate();
    let b_priv = NodePrivate::generate();
    let a_pub = a_priv.public();
    let b_pub = b_priv.public();

    let a_addr = Ipv4Addr::new(100, 64, 0, 1);
    let b_addr = Ipv4Addr::new(100, 64, 0, 2);
    let b_vip = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 10));

    let a_net = Arc::new(Netstack::new(a_addr, DEFAULT_MTU).unwrap());
    let b_net = Arc::new(Netstack::new(b_addr, DEFAULT_MTU).unwrap());

    let a_tunn = Arc::new(Mutex::new(
        WgTunn::new(&a_priv, &b_pub, 1).expect("A tunnel"),
    ));
    let b_tunn = Arc::new(Mutex::new(
        WgTunn::new(&b_priv, &a_pub, 2).expect("B tunnel"),
    ));

    // Add the VIP address to B's netstack interface.
    b_net.add_addr(b_vip).await.expect("add_addr");

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
                    () = a_tx.notified() => {}
                    () = b_tx.notified() => {}
                    () = tokio::time::sleep(std::time::Duration::from_millis(10)) => {}
                }
            }
        }
    });

    // B listens on the VIP address.
    let mut listener = b_net.listen_on(b_vip, 12345).await.expect("listen_on");

    // A dials B's VIP address.
    let dial_result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        a_net.dial(SocketAddr::new(b_vip, 12345)),
    )
    .await;
    let mut a_stream = dial_result.expect("dial timed out").expect("dial failed");

    // B accepts.
    let accept_result =
        tokio::time::timeout(std::time::Duration::from_secs(10), listener.accept()).await;
    let mut b_stream = accept_result
        .expect("accept timed out")
        .expect("accept failed");

    // Verify bidirectional data exchange.
    tokio::io::AsyncWriteExt::write_all(&mut a_stream, b"vip-echo")
        .await
        .expect("A write");

    let mut buf = [0u8; 32];
    let n = tokio::io::AsyncReadExt::read(&mut b_stream, &mut buf)
        .await
        .expect("B read");
    assert_eq!(&buf[..n], b"vip-echo");

    tokio::io::AsyncWriteExt::write_all(&mut b_stream, b"vip-reply")
        .await
        .expect("B write");

    let n = tokio::io::AsyncReadExt::read(&mut a_stream, &mut buf)
        .await
        .expect("A read");
    assert_eq!(&buf[..n], b"vip-reply");

    tokio::io::AsyncWriteExt::shutdown(&mut a_stream)
        .await
        .expect("A shutdown");

    pump.abort();
}

/// Verify that `listen` (on the primary IP) and `listen_on` (on a VIP) can
/// coexist on the same port without conflict.
#[tokio::test]
async fn listen_and_listen_on_same_port() {
    use std::net::IpAddr;

    let addr = Ipv4Addr::new(100, 64, 0, 1);
    let vip = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 50));
    let net = Netstack::new(addr, DEFAULT_MTU).unwrap();

    // Listen on the primary IP.
    let _listener1 = net.listen(8080).await.expect("listen on primary");

    // Add VIP and listen on it — same port, different IP, should succeed.
    net.add_addr(vip).await.expect("add_addr");
    let _listener2 = net.listen_on(vip, 8080).await.expect("listen_on VIP");

    // Listening on the same (primary_ip, port) should still fail.
    let result = net.listen(8080).await;
    assert!(result.is_err(), "duplicate (primary_ip, port) should fail");
}

// ────────────────────────────────────────────────────────────────────
// UDP tests
// ────────────────────────────────────────────────────────────────────

/// Two netstacks wired back-to-back: B listens for UDP, A sends a datagram,
/// B receives it and echoes back. Exercises the full UDP data path through
/// WireGuard-encapsulated IP packets.
#[tokio::test]
async fn udp_recv_and_echo() {
    use std::net::IpAddr;

    let a_priv = NodePrivate::generate();
    let b_priv = NodePrivate::generate();
    let a_pub = a_priv.public();
    let b_pub = b_priv.public();

    let a_addr = Ipv4Addr::new(100, 64, 0, 1);
    let b_addr = Ipv4Addr::new(100, 64, 0, 2);

    let a_net = Arc::new(Netstack::new(a_addr, DEFAULT_MTU).unwrap());
    let b_net = Arc::new(Netstack::new(b_addr, DEFAULT_MTU).unwrap());

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
                    () = a_tx.notified() => {}
                    () = b_tx.notified() => {}
                    () = tokio::time::sleep(std::time::Duration::from_millis(10)) => {}
                }
            }
        }
    });

    // B listens for UDP on its tailnet IP, port 12345.
    let mut b_udp = b_net
        .listen_packet(IpAddr::V4(b_addr), 12345)
        .await
        .expect("listen_packet");
    assert_eq!(
        b_udp.local_addr(),
        SocketAddr::new(IpAddr::V4(b_addr), 12345)
    );

    // A listens on an ephemeral port so it can receive the echo reply.
    let mut a_udp = a_net
        .listen_packet(IpAddr::V4(a_addr), 0)
        .await
        .expect("listen_packet (ephemeral)");
    let a_local = a_udp.local_addr();
    assert!(
        (10002..=19999).contains(&a_local.port()),
        "ephemeral port {} not in 10002-19999",
        a_local.port()
    );

    // A sends a datagram to B.
    a_udp
        .send_to(b"hello udp", SocketAddr::new(IpAddr::V4(b_addr), 12345))
        .await
        .expect("send_to");

    // B receives it.
    let (data, src) = tokio::time::timeout(std::time::Duration::from_secs(10), b_udp.recv_from())
        .await
        .expect("recv_from timed out")
        .expect("recv_from failed");
    assert_eq!(&data[..], b"hello udp");
    assert_eq!(src, a_local);

    // B echoes back to A.
    b_udp
        .send_to(b"echo reply", src)
        .await
        .expect("echo send_to");

    // A receives the echo.
    let (data, _src) = tokio::time::timeout(std::time::Duration::from_secs(10), a_udp.recv_from())
        .await
        .expect("echo recv timed out")
        .expect("echo recv failed");
    assert_eq!(&data[..], b"echo reply");

    pump.abort();
}

/// Verify that listening on an already-bound (addr, port) fails.
#[tokio::test]
async fn udp_listen_rejects_duplicate_port() {
    use std::net::IpAddr;

    let addr = Ipv4Addr::new(100, 64, 0, 1);
    let net = Netstack::new(addr, DEFAULT_MTU).unwrap();

    let _listener1 = net
        .listen_packet(IpAddr::V4(addr), 9090)
        .await
        .expect("first listen_packet");
    let result = net.listen_packet(IpAddr::V4(addr), 9090).await;
    assert!(result.is_err(), "duplicate UDP port should fail");
}

/// Verify that ephemeral port allocation (port 0) produces distinct ports
/// across multiple listeners on the same netstack.
#[tokio::test]
async fn udp_ephemeral_port_allocation() {
    use std::net::IpAddr;

    let addr = Ipv4Addr::new(100, 64, 0, 1);
    let net = Netstack::new(addr, DEFAULT_MTU).unwrap();

    let mut ports = Vec::new();
    for _ in 0..3 {
        let listener = net
            .listen_packet(IpAddr::V4(addr), 0)
            .await
            .expect("ephemeral listen_packet");
        let p = listener.local_addr().port();
        assert!(
            (10002..=19999).contains(&p),
            "ephemeral port {p} not in range 10002-19999"
        );
        assert!(!ports.contains(&p), "duplicate ephemeral port {p}");
        ports.push(p);
    }
}

/// Verify that dropping a UdpListener unregisters the socket so the port
/// can be reused.
#[tokio::test]
async fn udp_drop_releases_port() {
    use std::net::IpAddr;

    let addr = Ipv4Addr::new(100, 64, 0, 1);
    let net = Netstack::new(addr, DEFAULT_MTU).unwrap();

    {
        let _listener = net
            .listen_packet(IpAddr::V4(addr), 7070)
            .await
            .expect("first listen_packet");
    }
    // After drop, the port should be available again — but the poll loop
    // processes the CloseUdp command asynchronously, so retry briefly.
    let mut bound = false;
    for _ in 0..50 {
        if net.listen_packet(IpAddr::V4(addr), 7070).await.is_ok() {
            bound = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(bound, "port 7070 was not released after drop");
}
