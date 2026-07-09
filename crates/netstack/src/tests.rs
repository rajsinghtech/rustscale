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
        loop {
            let did_work = pump_cycle(&a_tunn_p, &b_tunn_p, &a_net_p, &b_net_p);
            if !did_work {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
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
    let mut a_stream = dial_result
        .expect("dial timed out")
        .expect("dial failed");

    // B accepts.
    let accept_result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        listener.accept(),
    )
    .await;
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
