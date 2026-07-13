//! Tests for the tun crate: AF-header framing primitives and the mock device.

use super::*;

fn v4_packet(dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45; // IPv4, IHL 5
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[9] = 17; // UDP
    p[12..16].copy_from_slice(&[10, 0, 0, 1]); // src
    p[16..20].copy_from_slice(&dst);
    p[20..].copy_from_slice(payload);
    p
}

#[test]
fn prepare_read_buffer_clears_grows_and_reuses_capacity() {
    let mut packet = vec![0xaa; 8];
    let read_len = 1280;
    assert!(packet.capacity() < read_len);

    prepare_read_buffer(&mut packet, read_len);
    assert!(packet.is_empty());
    assert!(packet.capacity() >= read_len);
    let capacity = packet.capacity();

    packet.extend_from_slice(&[1, 2, 3]);
    prepare_read_buffer(&mut packet, read_len);
    assert!(packet.is_empty());
    assert_eq!(packet.capacity(), capacity);
}

#[cfg(unix)]
fn v6_packet(payload: &[u8]) -> Vec<u8> {
    let total = 40 + payload.len();
    let mut p = vec![0u8; total];
    p[0] = 0x60; // IPv6, version 6
    p[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    p[6] = 17; // next header: UDP
    p[7] = 64; // hop limit
               // source address [8..24]
    p[8..24].copy_from_slice(&[
        0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ]);
    // destination address [24..40]
    p[24..40].copy_from_slice(&[
        0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
    ]);
    p[40..].copy_from_slice(payload);
    p
}

// --- strip_af_header ---

#[cfg(unix)]
#[test]
fn strip_v4_header() {
    let pkt = v4_packet([100, 64, 0, 2], b"hi");
    let mut framed = Vec::new();
    prepend_af_header(&pkt, &mut framed).unwrap();
    assert_eq!(framed[0], 0x00);
    assert_eq!(framed[1], 0x00);
    assert_eq!(framed[2], 0x00);
    assert_eq!(framed[3], AF_INET);
    let stripped = strip_af_header(&framed).unwrap();
    assert_eq!(stripped, &pkt[..]);
}

#[cfg(unix)]
#[test]
fn strip_v6_header() {
    let pkt = v6_packet(b"v6hi");
    let mut framed = Vec::new();
    prepend_af_header(&pkt, &mut framed).unwrap();
    assert_eq!(framed[3], AF_INET6);
    let stripped = strip_af_header(&framed).unwrap();
    assert_eq!(stripped, &pkt[..]);
}

#[cfg(unix)]
#[test]
fn strip_rejects_short_frame() {
    assert!(strip_af_header(&[0, 0, 0]).is_none());
    assert!(strip_af_header(&[]).is_none());
}

#[cfg(unix)]
#[test]
fn strip_rejects_bad_af() {
    // 4 bytes but AF byte is neither AF_INET nor AF_INET6.
    assert!(strip_af_header(&[0, 0, 0, 99, 0x45, 0]).is_none());
}

// --- prepend_af_header ---

#[cfg(unix)]
#[test]
fn prepend_rejects_empty() {
    let mut out = Vec::new();
    assert!(prepend_af_header(&[], &mut out).is_err());
}

#[cfg(unix)]
#[test]
fn prepend_rejects_unknown_version() {
    let mut out = Vec::new();
    // version nibble 7 (0x70 >> 4 = 7) is invalid
    assert!(prepend_af_header(&[0x70, 0, 0], &mut out).is_err());
}

#[cfg(unix)]
#[test]
fn prepend_v4_sets_af_inet() {
    let mut out = Vec::new();
    prepend_af_header(&v4_packet([1, 2, 3, 4], b"x"), &mut out).unwrap();
    assert_eq!(out[3], AF_INET);
    assert_eq!(out.len(), 4 + 20 + 1);
}

#[cfg(unix)]
#[test]
fn prepend_v6_sets_af_inet6() {
    let mut out = Vec::new();
    prepend_af_header(&v6_packet(b"x"), &mut out).unwrap();
    assert_eq!(out[3], AF_INET6);
}

#[cfg(unix)]
#[test]
fn prepend_clears_out_before_writing() {
    let mut out = vec![0xff; 10];
    prepend_af_header(&v4_packet([1, 2, 3, 4], b"y"), &mut out).unwrap();
    assert_eq!(out.len(), 4 + 21);
    assert_eq!(out[0..4], [0, 0, 0, AF_INET]);
}

// --- round-trip via MockTun (mock device trait) ---

#[tokio::test]
async fn mock_round_trip_framing() {
    let (tun, tx) = MockTun::new("mock0", 1280);

    // Inject a plain IP packet; read_packet should return it verbatim.
    let pkt = v4_packet([100, 64, 0, 5], b"hello");
    tx.send(pkt.clone()).await.unwrap();
    let mut got = Vec::new();
    tun.read_packet(&mut got).await.unwrap();
    assert_eq!(got, pkt);

    // Write a packet out; it should be captured verbatim (no AF header on the
    // public API surface).
    tun.write_packet(&pkt).await.unwrap();
    let written = tun.written().await;
    assert_eq!(written, vec![pkt.clone()]);
}

#[tokio::test]
async fn mock_name_and_mtu() {
    let (tun, _tx) = MockTun::new("mock9", 1400);
    assert_eq!(tun.name(), "mock9");
    assert_eq!(tun.mtu(), 1400);
}

#[tokio::test]
async fn mock_read_after_close_returns_eof() {
    let (tun, tx) = MockTun::new("mock0", 1280);
    drop(tx);
    let mut packet = vec![1, 2, 3];
    let res = tun.read_packet(&mut packet).await;
    assert!(res.is_err());
    assert_eq!(res.unwrap_err().kind(), std::io::ErrorKind::UnexpectedEof);
    assert!(packet.is_empty());
}

#[tokio::test]
async fn mock_successive_reads_reuse_caller_capacity() {
    let (tun, tx) = MockTun::new("mock0", 1280);
    let first = v4_packet([100, 64, 0, 5], b"first");
    let second = v4_packet([100, 64, 0, 6], b"second");
    tx.send(first.clone()).await.unwrap();
    tx.send(second.clone()).await.unwrap();

    let mut packet = Vec::with_capacity(1280);
    let capacity = packet.capacity();
    tun.read_packet(&mut packet).await.unwrap();
    assert_eq!(packet, first);
    assert_eq!(packet.capacity(), capacity);
    tun.read_packet(&mut packet).await.unwrap();
    assert_eq!(packet, second);
    assert_eq!(packet.capacity(), capacity);
}

// --- real utun creation (needs root) ---

#[cfg(target_os = "macos")]
#[tokio::test]
#[ignore = "requires root to create a utun device"]
async fn real_utun_create() {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("real_utun_create: skipped (not root)");
        return;
    }
    let dev = create(&TunConfig::default()).expect("create utun");
    assert!(dev.name().starts_with("utun"));
    assert_eq!(dev.mtu(), 1280);
}
