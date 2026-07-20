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

#[tokio::test]
async fn full_app_channel_cannot_lose_close_ownership() {
    use tokio::io::AsyncWriteExt;

    let notify = Arc::new(tokio::sync::Notify::new());
    let stats = Arc::new(crate::ConnectionStatsInner::default());
    let (mut stream, mut conn) =
        crate::make_stream_and_conn(notify, Arc::clone(&stats), None, None, None);

    // Fill the exact bounded app->smoltcp channel without running a poll loop.
    // The former in-band empty marker was lost at this boundary.
    for _ in 0..64 {
        stream.write_all(&[7]).await.expect("fill app channel");
    }
    assert_eq!(conn.app_rx.len(), 64);

    stream.shutdown().await.expect("publish durable close");
    assert!(conn
        .lifecycle
        .close_requested
        .load(std::sync::atomic::Ordering::Acquire));
    assert_eq!(
        conn.app_rx.len(),
        64,
        "close must not consume channel capacity"
    );
    assert_eq!(
        stats
            .pending_closes
            .load(std::sync::atomic::Ordering::Acquire),
        1
    );
    assert_eq!(
        stats
            .close_requests
            .load(std::sync::atomic::Ordering::Acquire),
        1
    );
    assert_eq!(
        stream
            .write(&[8])
            .await
            .expect_err("write after shutdown")
            .kind(),
        std::io::ErrorKind::BrokenPipe
    );

    let mut drained = 0;
    while conn.app_rx.try_recv().is_ok() {
        drained += 1;
    }
    assert_eq!(
        drained, 64,
        "all accepted data remains ordered before close"
    );
    conn.lifecycle.complete_close();
    assert_eq!(
        stats
            .pending_closes
            .load(std::sync::atomic::Ordering::Acquire),
        0
    );
    assert_eq!(
        stats
            .close_completions
            .load(std::sync::atomic::Ordering::Acquire),
        1
    );
    conn.lifecycle.complete_close();
    assert_eq!(
        stats
            .close_completions
            .load(std::sync::atomic::Ordering::Acquire),
        1
    );
}

#[test]
fn tcp_ephemeral_allocator_wraps_skips_live_ports_and_exhausts() {
    let mut allocated = std::collections::HashSet::from([u16::MAX, 49152]);
    let mut next = u16::MAX;
    assert_eq!(
        crate::allocate_ephemeral_tcp_port(&mut allocated, &mut next).unwrap(),
        49153
    );
    assert_eq!(next, 49154);

    allocated.extend(49152..=u16::MAX);
    let error = crate::allocate_ephemeral_tcp_port(&mut allocated, &mut next)
        .expect_err("a full client port range must fail closed");
    assert!(error.to_string().contains("port range exhausted"));
}

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
async fn repeated_canceled_dials_release_sockets_and_buffers_promptly() {
    let net = Arc::new(
        Netstack::new(Ipv4Addr::new(100, 64, 0, 1), DEFAULT_MTU).expect("create netstack"),
    );

    for round in 1..=3 {
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
        .unwrap_or_else(|_| panic!("round {round} pending dial was not registered"));
        assert_eq!(net.dial_stats().pending_buffer_bytes, TCP_BUF * 2);

        dial.abort();
        let _ = dial.await;
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while net.dial_stats() != DialStats::default() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("round {round} retained a canceled dial or its buffers"));
    }
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

/// Exercise the production netstack and WireGuard data path at an explicit
/// setup scale. The in-memory link is credential-free; it only replaces the
/// UDP underlay, not dial admission, packet ownership, TCP, or WireGuard.
async fn assert_bounded_bulk_dial_phases(phases: &[usize]) {
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

    let pump = {
        let a_tunn = a_tunn.clone();
        let b_tunn = b_tunn.clone();
        let a_net = a_net.clone();
        let b_net = b_net.clone();
        tokio::spawn(async move {
            let a_tx = a_net.tx_notify();
            let b_tx = b_net.tx_notify();
            loop {
                if !pump_cycle(&a_tunn, &b_tunn, &a_net, &b_net) {
                    tokio::select! {
                        () = a_tx.notified() => {}
                        () = b_tx.notified() => {}
                        () = tokio::time::sleep(std::time::Duration::from_millis(1)) => {}
                    }
                }
            }
        })
    };

    let mut listener = b_net.listen(41000).await.expect("listen");
    let mut expected_closes = 0;
    for &streams in phases {
        let accept = tokio::spawn(async move {
            let mut accepted = Vec::with_capacity(streams);
            for _ in 0..streams {
                accepted.push(listener.accept().await.expect("accept"));
            }
            (accepted, listener)
        });
        let dial = {
            let a_net = a_net.clone();
            tokio::spawn(async move {
                tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    a_net.dial_many(
                        SocketAddr::new(b_addr.into(), 41000),
                        streams,
                        tokio::time::Instant::now() + std::time::Duration::from_secs(25),
                    ),
                )
                .await
            })
        };
        let mut maximum = 0;
        while !dial.is_finished() {
            maximum = maximum.max(a_net.dial_stats().pending_dials);
            tokio::task::yield_now().await;
        }
        let client_streams = dial
            .await
            .expect("dial worker")
            .expect("bulk setup outer deadline")
            .expect("bulk dial");
        let (server_streams, returned_listener) = accept.await.expect("accept worker");
        listener = returned_listener;

        assert_eq!(client_streams.len(), streams);
        assert_eq!(server_streams.len(), streams);
        assert!(
            maximum <= crate::TCP_DIAL_WINDOW,
            "maximum in flight: {maximum}"
        );
        assert_eq!(a_net.dial_stats(), DialStats::default());
        drop(client_streams);
        drop(server_streams);
        expected_closes += streams;
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let a = a_net.connection_stats();
                let b = b_net.connection_stats();
                if a.live_connections == 0
                    && b.live_connections == 0
                    && a.pending_closes == 0
                    && b.pending_closes == 0
                {
                    assert_eq!(a.close_requests, expected_closes);
                    assert_eq!(a.close_completions, expected_closes);
                    assert_eq!(b.close_requests, expected_closes);
                    assert_eq!(b.close_completions, expected_closes);
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("bulk teardown leaked a connection or close request");
    }
    pump.abort();
}

/// Production bulk dialing retains every P500 stream while never exceeding
/// the peer's listener-sized admission window.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bounded_bulk_dial_establishes_and_retains_p500() {
    assert_bounded_bulk_dial_phases(&[500]).await;
}

/// P1000 setup takes the same production bounded path as P500: all streams
/// must remain established without widening the handshake window or deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bounded_bulk_dial_establishes_and_retains_p1000() {
    assert_bounded_bulk_dial_phases(&[1000]).await;
}

/// Reproduce the benchmark's long-lived-server boundary: P500 must retire
/// bilaterally before an unchanged P1000 setup starts on the same stacks,
/// tunnels, listener, channel limits, and four-dial admission window.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p500_teardown_then_p1000_has_no_stale_connections() {
    assert_bounded_bulk_dial_phases(&[500, 1000]).await;
}

/// A P1000 request that cannot connect still owns at most one bounded window,
/// and common-deadline cancellation reclaims every pending socket and buffer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bounded_bulk_dial_p1000_cancels_without_task_pileup() {
    const STREAMS: usize = 1000;
    let net = Arc::new(Netstack::new(Ipv4Addr::new(100, 64, 0, 1), DEFAULT_MTU).unwrap());
    let dial = {
        let net = net.clone();
        tokio::spawn(async move {
            net.dial_many(
                SocketAddr::from(([100, 64, 0, 254], 9)),
                STREAMS,
                tokio::time::Instant::now() + std::time::Duration::from_millis(500),
            )
            .await
        })
    };
    let mut maximum = 0;
    while !dial.is_finished() {
        maximum = maximum.max(net.dial_stats().pending_dials);
        tokio::task::yield_now().await;
    }
    let error = match dial.await.expect("dial worker") {
        Ok(_) => panic!("unreachable P1000 dial must fail closed"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("established 0 of 1000"),
        "{error}"
    );
    assert!(maximum > 0);
    assert!(
        maximum <= crate::TCP_DIAL_WINDOW,
        "maximum in flight: {maximum}"
    );
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while net.dial_stats() != DialStats::default() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cancelled P1000 dials leaked resources");
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

/// Start a WireGuard pump driven only by netstack transmit notifications.
///
/// There is deliberately no periodic fallback here. The old UDP coverage
/// polled this outer pump every 10 ms and allowed 10 seconds for delivery, so
/// it proved eventual delivery but not that an idle application send woke the
/// inner netstack poll loop instead of waiting for its one-second fallback.
fn make_notification_only_udp_rig() -> (
    Arc<Netstack>,
    Arc<Netstack>,
    tokio::task::JoinHandle<()>,
    Ipv4Addr,
    Ipv4Addr,
) {
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

    let a_net_p = Arc::clone(&a_net);
    let b_net_p = Arc::clone(&b_net);
    let pump = tokio::spawn(async move {
        let a_tx = a_net_p.tx_notify();
        let b_tx = b_net_p.tx_notify();
        loop {
            if !pump_cycle(&a_tunn, &b_tunn, &a_net_p, &b_net_p) {
                tokio::select! {
                    () = a_tx.notified() => {}
                    () = b_tx.notified() => {}
                }
            }
        }
    });

    (a_net, b_net, pump, a_addr, b_addr)
}

/// Two netstacks wired back-to-back: B listens for UDP, A sends an idle
/// datagram, B receives it and echoes back. Both application sends must arrive
/// well before the poll loop's one-second safety fallback.
#[tokio::test]
async fn udp_recv_and_echo() {
    use std::net::IpAddr;

    const DELIVERY_DEADLINE: std::time::Duration = std::time::Duration::from_millis(500);

    let (a_net, b_net, pump, a_addr, b_addr) = make_notification_only_udp_rig();

    let mut b_udp = b_net
        .listen_packet(IpAddr::V4(b_addr), 12345)
        .await
        .expect("listen_packet");
    assert_eq!(
        b_udp.local_addr(),
        SocketAddr::new(IpAddr::V4(b_addr), 12345)
    );

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

    // Let both poll loops become idle so a command/listener wake cannot carry
    // this application packet through accidentally.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let sent_at = std::time::Instant::now();
    a_udp
        .send_to(b"hello udp", SocketAddr::new(IpAddr::V4(b_addr), 12345))
        .await
        .expect("send_to");
    let (data, src) = tokio::time::timeout(DELIVERY_DEADLINE, b_udp.recv_from())
        .await
        .unwrap_or_else(|_| {
            panic!(
                "idle application UDP send was not delivered within {DELIVERY_DEADLINE:?}; \
                 the netstack poll fallback is one second"
            )
        })
        .expect("recv_from failed");
    assert_eq!(&data[..], b"hello udp");
    assert_eq!(src, a_local);
    assert!(
        sent_at.elapsed() < DELIVERY_DEADLINE,
        "idle UDP delivery exceeded {DELIVERY_DEADLINE:?}"
    );

    let echoed_at = std::time::Instant::now();
    b_udp
        .send_to(b"echo reply", src)
        .await
        .expect("echo send_to");
    let (data, _src) = tokio::time::timeout(DELIVERY_DEADLINE, a_udp.recv_from())
        .await
        .unwrap_or_else(|_| {
            panic!(
                "idle application UDP echo was not delivered within {DELIVERY_DEADLINE:?}; \
                 the netstack poll fallback is one second"
            )
        })
        .expect("echo recv failed");
    assert_eq!(&data[..], b"echo reply");
    assert!(
        echoed_at.elapsed() < DELIVERY_DEADLINE,
        "idle UDP echo exceeded {DELIVERY_DEADLINE:?}"
    );

    pump.abort();
}

/// A 20 Hz application stream must remain paced rather than accumulating in
/// the send channel until the poll loop's one-second fallback.
#[tokio::test]
async fn udp_application_cadence_is_not_batched() {
    use std::net::IpAddr;

    const PACKET_COUNT: usize = 16;
    const CADENCE_MS: u64 = 50;
    const MAX_ONE_WAY: std::time::Duration = std::time::Duration::from_millis(500);
    const MIN_ARRIVAL_SPAN: std::time::Duration = std::time::Duration::from_millis(400);

    let (a_net, b_net, pump, a_addr, b_addr) = make_notification_only_udp_rig();
    let mut b_udp = b_net
        .listen_packet(IpAddr::V4(b_addr), 12346)
        .await
        .expect("B listen_packet");
    let a_udp = a_net
        .listen_packet(IpAddr::V4(a_addr), 0)
        .await
        .expect("A listen_packet");
    let a_local = a_udp.local_addr();
    let destination = SocketAddr::new(IpAddr::V4(b_addr), 12346);

    // Establish WireGuard before measuring application cadence. This warmup is
    // allowed to hit the old fallback; the measured train starts after the
    // poll loop has returned to a known idle period.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    a_udp
        .send_to(b"warmup", destination)
        .await
        .expect("warmup send_to");
    let (warmup, warmup_src) =
        tokio::time::timeout(std::time::Duration::from_secs(2), b_udp.recv_from())
            .await
            .expect("warmup timed out")
            .expect("warmup receive failed");
    assert_eq!(&warmup[..], b"warmup");
    assert_eq!(warmup_src, a_local);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let receiver = tokio::spawn(async move {
        let mut arrivals = Vec::with_capacity(PACKET_COUNT);
        for expected in 0..PACKET_COUNT {
            let (data, src) =
                tokio::time::timeout(std::time::Duration::from_secs(2), b_udp.recv_from())
                    .await
                    .unwrap_or_else(|_| panic!("timed out waiting for UDP sequence {expected}"))
                    .expect("cadence receive failed");
            let expected_payload = (expected as u32).to_be_bytes();
            assert_eq!(&data[..], &expected_payload, "UDP sequence {expected}");
            assert_eq!(src, a_local, "UDP source for sequence {expected}");
            arrivals.push(std::time::Instant::now());
        }
        arrivals
    });

    let cadence_start = std::time::Instant::now();
    let mut sent_at = Vec::with_capacity(PACKET_COUNT);
    for sequence in 0..PACKET_COUNT {
        let scheduled =
            cadence_start + std::time::Duration::from_millis(CADENCE_MS * sequence as u64);
        tokio::time::sleep_until(tokio::time::Instant::from_std(scheduled)).await;
        sent_at.push(std::time::Instant::now());
        a_udp
            .send_to(&(sequence as u32).to_be_bytes(), destination)
            .await
            .unwrap_or_else(|error| panic!("send sequence {sequence}: {error}"));
    }

    let arrivals = tokio::time::timeout(std::time::Duration::from_secs(3), receiver)
        .await
        .expect("cadence receiver timed out")
        .expect("cadence receiver task failed");
    pump.abort();

    let max_one_way = sent_at
        .iter()
        .zip(&arrivals)
        .map(|(sent, arrived)| arrived.duration_since(*sent))
        .max()
        .expect("at least one latency sample");
    let send_span = sent_at
        .last()
        .expect("last send")
        .duration_since(sent_at[0]);
    let arrival_span = arrivals
        .last()
        .expect("last arrival")
        .duration_since(arrivals[0]);
    let samples = sent_at
        .iter()
        .zip(&arrivals)
        .enumerate()
        .map(|(sequence, (sent, arrived))| {
            format!(
                "{sequence}:send={}ms recv={}ms latency={}ms",
                sent.duration_since(cadence_start).as_millis(),
                arrived.duration_since(cadence_start).as_millis(),
                arrived.duration_since(*sent).as_millis()
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    let diagnostics = format!(
        "send_span={}ms arrival_span={}ms max_one_way={}ms samples=[{samples}]",
        send_span.as_millis(),
        arrival_span.as_millis(),
        max_one_way.as_millis()
    );
    eprintln!("UDP cadence regression: {diagnostics}");

    assert!(
        max_one_way <= MAX_ONE_WAY,
        "20 Hz application UDP exceeded the generous {MAX_ONE_WAY:?} one-way bound; {diagnostics}"
    );
    assert!(
        arrival_span >= MIN_ARRIVAL_SPAN,
        "20 Hz application UDP arrived as a batch instead of a paced stream; {diagnostics}"
    );
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
