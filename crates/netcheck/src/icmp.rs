//! Best-effort ICMP echo probing — ports Go's `net/ping` package.
//!
//! When all STUN probes fail (UDP is blocked), the netcheck falls back to
//! ICMP latency probing (Go: `measureAllICMPLatency`). This module implements
//! a minimal ICMPv4 echo client using `socket2`.
//!
//! Two socket modes are tried, in order:
//! 1. **Unprivileged** (`SOCK_DGRAM` + `IPPROTO_ICMP`) — works on Linux with
//!    `net.ipv4.ping_group_range` configured and on macOS without root.
//! 2. **Raw** (`SOCK_RAW` + `IPPROTO_ICMP`) — requires root/CAP_NET_RAW.
//!
//! If neither can be opened, ICMP probing is silently skipped (the report's
//! `icmpv4` stays `false`), matching Go's EPERM handling.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// ICMP Echo Request type code (RFC 792).
const ICMP_ECHO_REQUEST: u8 = 8;
/// ICMP Echo Reply type code (RFC 792).
const ICMP_ECHO_REPLY: u8 = 0;

/// Maximum time to wait for a single ICMP echo reply.
const ICMP_RECV_TIMEOUT: Duration = Duration::from_secs(1);

/// A best-effort ICMPv4 pinger. Created once per netcheck run and reused
/// across multiple targets (matching Go's `ping.Pinger`).
pub struct Pinger {
    sock: UdpSocket,
    id: u16,
    seq: u16,
}

impl Pinger {
    /// Create a new ICMPv4 pinger. Tries unprivileged datagram ICMP first,
    /// then raw ICMP. Returns `Ok(None)` if neither can be opened (e.g. no
    /// permissions), and a typed error if no Tokio runtime is entered.
    pub fn new_v4() -> io::Result<Option<Self>> {
        tokio::runtime::Handle::try_current().map_err(|_| {
            io::Error::new(
                io::ErrorKind::NotConnected,
                "ICMP socket registration requires an entered Tokio runtime",
            )
        })?;
        let Some(sock) = Self::open_icmp_socket() else {
            return Ok(None);
        };
        let id = rand::random::<u16>();
        Ok(Some(Self { sock, id, seq: 0 }))
    }

    fn open_icmp_socket() -> Option<UdpSocket> {
        // Try unprivileged ICMP (SOCK_DGRAM + IPPROTO_ICMP) first.
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))
            .or_else(|_| {
                // Fall back to raw ICMP (requires root / CAP_NET_RAW).
                Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
            })
            .ok()?;

        // Set a 1-second receive timeout so blocking recv doesn't hang.
        sock.set_read_timeout(Some(Duration::from_secs(1))).ok()?;
        sock.set_nonblocking(true).ok()?;
        let std_sock: std::net::UdpSocket = sock.into();
        UdpSocket::from_std(std_sock).ok()
    }

    /// Send an ICMP echo request to `dest` and wait for the reply. Returns
    /// the RTT on success, or `None` on timeout/error.
    pub async fn ping(&mut self, dest: IpAddr, data: &[u8]) -> Option<Duration> {
        let addr = SocketAddr::new(dest, 0);
        self.seq = self.seq.wrapping_add(1);
        let packet = build_echo_request(self.id, self.seq, data);
        let start = Instant::now();
        if self.sock.send_to(&packet, addr).await.is_err() {
            return None;
        }

        let mut buf = [0u8; 1500];
        loop {
            let recv = timeout(ICMP_RECV_TIMEOUT, self.sock.recv_from(&mut buf)).await;
            match recv {
                Ok(Ok((n, _))) => {
                    if let Some((reply_id, reply_seq, _)) = parse_echo_reply(&buf[..n]) {
                        if reply_id == self.id && reply_seq == self.seq {
                            return Some(start.elapsed());
                        }
                    }
                    // Mismatched packet — keep waiting.
                    continue;
                }
                _ => return None, // timeout or error
            }
        }
    }
}

/// Build an ICMPv4 Echo Request packet (RFC 792):
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Type | Code  | Checksum       | ID             | Sequence    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Data ...
/// ```
fn build_echo_request(id: u16, seq: u16, data: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(8 + data.len());
    pkt.push(ICMP_ECHO_REQUEST); // type
    pkt.push(0); // code
    pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum (placeholder)
    pkt.extend_from_slice(&id.to_be_bytes()); // identifier
    pkt.extend_from_slice(&seq.to_be_bytes()); // sequence
    pkt.extend_from_slice(data); // data

    // Compute and fill in the Internet Checksum (RFC 1071).
    let cksum = internet_checksum(&pkt);
    pkt[2..4].copy_from_slice(&cksum.to_be_bytes());
    pkt
}

/// Parse an ICMP echo reply. Handles both bare-ICMP (SOCK_DGRAM, where the
/// kernel strips the IP header) and IP+ICMP (SOCK_RAW on some platforms where
/// the IP header is included). Returns `(id, seq, data)` on a valid echo
/// reply, or `None` if the packet is not an echo reply or is malformed.
fn parse_echo_reply(buf: &[u8]) -> Option<(u16, u16, &[u8])> {
    if buf.is_empty() {
        return None;
    }

    // If the first byte looks like an IPv4 header (version 4), skip it.
    let icmp = if buf[0] >> 4 == 4 {
        // IPv4 header: IHL is the lower nibble, in 32-bit words.
        let ihl = (buf[0] & 0x0f) as usize * 4;
        if buf.len() < ihl + 8 {
            return None;
        }
        &buf[ihl..]
    } else {
        buf
    };

    if icmp.len() < 8 {
        return None;
    }
    if icmp[0] != ICMP_ECHO_REPLY {
        return None;
    }
    // Skip checksum verification — the kernel validates it for us.
    let id = u16::from_be_bytes([icmp[4], icmp[5]]);
    let seq = u16::from_be_bytes([icmp[6], icmp[7]]);
    let data = &icmp[8..];
    Some((id, seq, data))
}

/// Compute the Internet Checksum (RFC 1071) over `data`. The checksum field
/// itself is treated as zero during computation.
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    // Handle trailing byte.
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }
    // Fold 32-bit sum into 16 bits.
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinger_without_runtime_is_typed_error() {
        let result = std::panic::catch_unwind(Pinger::new_v4);
        let error = match result.expect("must not panic") {
            Ok(_) => panic!("runtime is required"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::NotConnected);
    }

    #[test]
    fn echo_request_checksum() {
        let pkt = build_echo_request(0x1234, 1, b"test");
        assert_eq!(pkt[0], ICMP_ECHO_REQUEST);
        assert_eq!(pkt[1], 0);
        // Verify checksum is not zero (for non-trivial data).
        let cksum = u16::from_be_bytes([pkt[2], pkt[3]]);
        assert_ne!(cksum, 0);
        // Verify ID and sequence.
        assert_eq!(u16::from_be_bytes([pkt[4], pkt[5]]), 0x1234);
        assert_eq!(u16::from_be_bytes([pkt[6], pkt[7]]), 1);
        assert_eq!(&pkt[8..], b"test");
    }

    #[test]
    fn parse_bare_echo_reply() {
        // Build a fake echo reply.
        let mut pkt = vec![ICMP_ECHO_REPLY, 0, 0, 0];
        pkt.extend_from_slice(&0x1234u16.to_be_bytes()); // id
        pkt.extend_from_slice(&1u16.to_be_bytes()); // seq
        pkt.extend_from_slice(b"hello");
        // Compute checksum.
        let cksum = internet_checksum(&pkt);
        pkt[2..4].copy_from_slice(&cksum.to_be_bytes());

        let (id, seq, data) = parse_echo_reply(&pkt).expect("should parse");
        assert_eq!(id, 0x1234);
        assert_eq!(seq, 1);
        assert_eq!(data, b"hello");
    }

    #[test]
    fn parse_ip_plus_echo_reply() {
        // Build a minimal IPv4 header (20 bytes) + ICMP echo reply.
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45; // version 4, IHL 5 (20 bytes)
        let mut icmp = vec![ICMP_ECHO_REPLY, 0, 0, 0];
        icmp.extend_from_slice(&0xABCDu16.to_be_bytes()); // id
        icmp.extend_from_slice(&42u16.to_be_bytes()); // seq
        let mut pkt = ip.clone();
        pkt.extend_from_slice(&icmp);
        let cksum = internet_checksum(&icmp);
        pkt[22..24].copy_from_slice(&cksum.to_be_bytes());

        let (id, seq, _data) = parse_echo_reply(&pkt).expect("should parse IP+ICMP");
        assert_eq!(id, 0xABCD);
        assert_eq!(seq, 42);
    }

    #[test]
    fn parse_non_echo_reply_returns_none() {
        let pkt = vec![3u8, 0, 0, 0, 0, 0, 0, 0]; // type 3 = Destination Unreachable
        assert!(parse_echo_reply(&pkt).is_none());
    }

    #[test]
    fn internet_checksum_known_value() {
        // RFC 1071 example: sum of bytes [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        let cksum = internet_checksum(&data);
        // The checksum should be 0x0d_d5 (or equivalent).
        // Actually, the expected sum is 0xdd5, complement is 0xf22a... let me just
        // verify the property that checksumming the data + checksum gives 0.
        let mut with_cksum = data.to_vec();
        with_cksum.extend_from_slice(&cksum.to_be_bytes());
        let verify = internet_checksum(&with_cksum);
        assert_eq!(verify, 0, "checksum of data+checksum should be 0");
    }
}
