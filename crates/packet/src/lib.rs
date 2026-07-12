//! IP packet header parsing — port of Tailscale's `net/packet` package.
//!
//! Provides zero-alloc decoding of IPv4/IPv6 packets into typed header
//! structs and a [`Parsed`] view suitable for filter inspection.

#![forbid(unsafe_code)]
#![allow(non_upper_case_globals)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// ---------------------------------------------------------------------------
// Protocol number constants (IANA IP protocol numbers)
// ---------------------------------------------------------------------------

pub const UNKNOWN: u8 = 0;
pub const ICMP_V4: u8 = 1;
pub const IGMP: u8 = 2;
pub const TCP: u8 = 6;
pub const UDP: u8 = 17;
pub const FRAGMENT: u8 = 44;
pub const ICMP_V6: u8 = 58;
pub const SCTP: u8 = 132;
pub const TSMP: u8 = 99;

// ---------------------------------------------------------------------------
// TCP flags
// ---------------------------------------------------------------------------

/// TCP flag bits as defined in RFC 793 (plus ECN extensions).
///
/// Modelled as a newtype around `u8` with associated constants, mirroring
/// Go's `packet.TCPFlag`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct TCPFlag(pub u8);

impl TCPFlag {
    pub const FIN: TCPFlag = TCPFlag(0x01);
    pub const SYN: TCPFlag = TCPFlag(0x02);
    pub const RST: TCPFlag = TCPFlag(0x04);
    pub const PSH: TCPFlag = TCPFlag(0x08);
    pub const ACK: TCPFlag = TCPFlag(0x10);
    pub const URG: TCPFlag = TCPFlag(0x20);
    pub const ECE: TCPFlag = TCPFlag(0x40);
    pub const CWR: TCPFlag = TCPFlag(0x80);
    pub const SYN_ACK: TCPFlag = TCPFlag(Self::SYN.0 | Self::ACK.0);

    pub fn contains(self, other: TCPFlag) -> bool {
        (self.0 & other.0) == other.0
    }

    pub fn is_set(self, flag: TCPFlag) -> bool {
        (self.0 & flag.0) != 0
    }
}

impl std::ops::BitOr for TCPFlag {
    type Output = TCPFlag;
    fn bitor(self, rhs: TCPFlag) -> TCPFlag {
        TCPFlag(self.0 | rhs.0)
    }
}

impl std::ops::BitAnd for TCPFlag {
    type Output = TCPFlag;
    fn bitand(self, rhs: TCPFlag) -> TCPFlag {
        TCPFlag(self.0 & rhs.0)
    }
}

impl From<u8> for TCPFlag {
    fn from(v: u8) -> TCPFlag {
        TCPFlag(v)
    }
}

impl From<TCPFlag> for u8 {
    fn from(f: TCPFlag) -> u8 {
        f.0
    }
}

// ---------------------------------------------------------------------------
// Typed header structs
// ---------------------------------------------------------------------------

/// IPv4 header fields (decoded from a raw packet).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IPv4Header {
    pub version: u8,
    pub ihl: u8,
    pub tos: u8,
    pub total_len: u16,
    pub id: u16,
    pub flags_frag: u16,
    pub ttl: u8,
    pub proto: u8,
    pub checksum: u16,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
}

/// IPv6 header fields (decoded from a raw packet).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IPv6Header {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_len: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
}

/// ICMP header (common first 4 bytes for both ICMPv4 and ICMPv6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ICMPHeader {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    /// The 4-byte "rest of header" (unused for most messages, or
    /// identifier+sequence for echo).
    pub rest_of_header: u32,
}

/// UDP header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UDPHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub len: u16,
    pub checksum: u16,
}

// ---------------------------------------------------------------------------
// PacketInfo — the flat summary struct used by the filter crate.
// Kept for backward compatibility; new code should prefer Parsed.
// ---------------------------------------------------------------------------

/// ICMP_V4 types that are considered "errors".
const ICMP_V4_ERROR_TYPES: [u8; 4] = [3, 4, 11, 12];
/// ICMP_V6 types that are considered "errors".
const ICMP_V6_ERROR_TYPES: [u8; 4] = [1, 2, 3, 4];

/// Parsed packet info — everything the filter needs to make a verdict.
#[derive(Clone, Debug)]
pub struct PacketInfo {
    pub version: u8,
    pub proto: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub tcp_flags: u8,
    pub is_tcp_syn: bool,
    pub is_icmp_echo_reply: bool,
    pub is_icmp_error: bool,
}

impl Default for PacketInfo {
    fn default() -> Self {
        Self {
            version: 0,
            proto: 0,
            src: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            dst: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: 0,
            dst_port: 0,
            tcp_flags: 0,
            is_tcp_syn: false,
            is_icmp_echo_reply: false,
            is_icmp_error: false,
        }
    }
}

impl PacketInfo {
    /// Whether this is a TCP SYN (SYN set, ACK not set).
    pub fn is_tcp_syn(&self) -> bool {
        self.is_tcp_syn
    }

    /// Whether this is an ICMP echo reply (type 0) or ICMP_V6 echo reply
    /// (type 129).
    pub fn is_echo_response(&self) -> bool {
        self.is_icmp_echo_reply
    }

    /// Whether this is an ICMP error (dest-unreachable, source-quench,
    /// time-exceeded, param-problem).
    pub fn is_error(&self) -> bool {
        self.is_icmp_error
    }
}

// ---------------------------------------------------------------------------
// Parsed — rich decoded view (mirrors Go's packet.Parsed)
// ---------------------------------------------------------------------------

/// A decoded IP packet view, modelled after Go's `packet.Parsed`.
///
/// Holds a reference to the raw buffer plus offsets for extracting the
/// transport header and payload slices without allocation.
#[derive(Debug, Clone)]
pub struct Parsed<'a> {
    buf: &'a [u8],
    /// Offset of the IP subprotocol (transport) header within `buf`.
    subofs: usize,
    /// Offset of the transport payload within `buf`.
    dataofs: usize,
    /// Total length of the packet (may be < `buf.len()` if the buffer
    /// has trailing zeros).
    length: usize,
    /// IP version (4 or 6), or 0 if unparseable.
    pub ip_version: u8,
    /// IP protocol number of the transport layer.
    pub ip_proto: u8,
    /// Source IP address.
    pub src: IpAddr,
    /// Destination IP address.
    pub dst: IpAddr,
    /// Source port (valid for TCP / UDP / SCTP).
    pub src_port: u16,
    /// Destination port (valid for TCP / UDP / SCTP).
    pub dst_port: u16,
    /// TCP flags (valid for TCP).
    pub tcp_flags: TCPFlag,
}

impl<'a> Parsed<'a> {
    /// Decode a raw IP packet buffer into a [`Parsed`] view.
    ///
    /// Performs minimal, allocation-free parsing of IPv4 and IPv6 headers,
    /// following extension headers for IPv6. Extracts protocol, addresses,
    /// ports, and TCP flags.
    pub fn decode(buf: &'a [u8]) -> Self {
        let mut q = Self {
            buf,
            subofs: 0,
            dataofs: 0,
            length: buf.len(),
            ip_version: 0,
            ip_proto: UNKNOWN,
            src: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            dst: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: 0,
            dst_port: 0,
            tcp_flags: TCPFlag(0),
        };
        if buf.is_empty() {
            return q;
        }
        q.ip_version = buf[0] >> 4;
        match q.ip_version {
            4 => q.decode4(buf),
            6 => q.decode6(buf),
            _ => {
                q.ip_version = 0;
                q.ip_proto = UNKNOWN;
            }
        }
        q
    }

    /// The full raw packet buffer.
    pub fn buffer(&self) -> &'a [u8] {
        self.buf
    }

    /// The transport header and payload (everything from the IP subprotocol
    /// onward).
    pub fn transport(&self) -> &'a [u8] {
        if self.subofs > self.buf.len() {
            &[]
        } else {
            &self.buf[self.subofs..]
        }
    }

    /// The transport-layer payload (e.g. TCP payload after the TCP header,
    /// UDP datagram payload after the UDP header). Returns an empty slice
    /// if the packet is truncated.
    pub fn payload(&self) -> &'a [u8] {
        if self.length > self.buf.len() || self.dataofs > self.buf.len() {
            return &[];
        }
        &self.buf[self.dataofs..self.length]
    }

    /// Whether this is a TCP SYN (SYN set, ACK not set).
    pub fn is_tcp_syn(&self) -> bool {
        (self.tcp_flags & TCPFlag::SYN_ACK) == TCPFlag::SYN
    }

    /// Whether this is an ICMP echo request (type 8 for ICMPv4, type 128
    /// for ICMPv6).
    pub fn is_echo_request(&self) -> bool {
        match self.ip_proto {
            ICMP_V4 => {
                self.buf.len() >= self.subofs + 8
                    && self.buf[self.subofs] == 8
                    && self.buf[self.subofs + 1] == 0
            }
            ICMP_V6 => {
                self.buf.len() >= self.subofs + 8
                    && self.buf[self.subofs] == 128
                    && self.buf[self.subofs + 1] == 0
            }
            _ => false,
        }
    }

    /// Whether this is an ICMP echo response (type 0 for ICMPv4, type 129
    /// for ICMPv6).
    pub fn is_echo_response(&self) -> bool {
        match self.ip_proto {
            ICMP_V4 => {
                self.buf.len() >= self.subofs + 8
                    && self.buf[self.subofs] == 0
                    && self.buf[self.subofs + 1] == 0
            }
            ICMP_V6 => {
                self.buf.len() >= self.subofs + 8
                    && self.buf[self.subofs] == 129
                    && self.buf[self.subofs + 1] == 0
            }
            _ => false,
        }
    }

    /// Whether this is an ICMP error packet (destination unreachable, time
    /// exceeded, parameter problem, etc.).
    pub fn is_error(&self) -> bool {
        match self.ip_proto {
            ICMP_V4 => {
                self.buf.len() > self.subofs && ICMP_V4_ERROR_TYPES.contains(&self.buf[self.subofs])
            }
            ICMP_V6 => {
                self.buf.len() > self.subofs && ICMP_V6_ERROR_TYPES.contains(&self.buf[self.subofs])
            }
            _ => false,
        }
    }

    /// Extract the decoded IPv4 header. Panics if this is not an IPv4 packet.
    pub fn ip4_header(&self) -> IPv4Header {
        assert_eq!(self.ip_version, 4, "ip4_header called on non-IPv4 Parsed");
        let b = self.buf;
        IPv4Header {
            version: 4,
            ihl: b[0] & 0x0F,
            tos: b[1],
            total_len: u16::from_be_bytes([b[2], b[3]]),
            id: u16::from_be_bytes([b[4], b[5]]),
            flags_frag: u16::from_be_bytes([b[6], b[7]]),
            ttl: b[8],
            proto: b[9],
            checksum: u16::from_be_bytes([b[10], b[11]]),
            src: Ipv4Addr::new(b[12], b[13], b[14], b[15]),
            dst: Ipv4Addr::new(b[16], b[17], b[18], b[19]),
        }
    }

    /// Extract the decoded IPv6 header. Panics if this is not an IPv6 packet.
    pub fn ip6_header(&self) -> IPv6Header {
        assert_eq!(self.ip_version, 6, "ip6_header called on non-IPv6 Parsed");
        let b = self.buf;
        let vtc_fl = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        IPv6Header {
            version: (vtc_fl >> 28) as u8,
            traffic_class: ((vtc_fl >> 20) & 0xFF) as u8,
            flow_label: vtc_fl & 0xFFFFF,
            payload_len: u16::from_be_bytes([b[4], b[5]]),
            next_header: b[6],
            hop_limit: b[7],
            src: Ipv6Addr::from([
                b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15], b[16], b[17], b[18], b[19],
                b[20], b[21], b[22], b[23],
            ]),
            dst: Ipv6Addr::from([
                b[24], b[25], b[26], b[27], b[28], b[29], b[30], b[31], b[32], b[33], b[34], b[35],
                b[36], b[37], b[38], b[39],
            ]),
        }
    }

    /// Extract the ICMP header (common 8-byte format: type, code, checksum,
    /// rest-of-header).
    pub fn icmp_header(&self) -> ICMPHeader {
        let b = &self.buf[self.subofs..];
        ICMPHeader {
            icmp_type: b[0],
            code: b[1],
            checksum: u16::from_be_bytes([b[2], b[3]]),
            rest_of_header: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
        }
    }

    /// Extract the UDP header.
    pub fn udp_header(&self) -> UDPHeader {
        let b = &self.buf[self.subofs..];
        UDPHeader {
            src_port: u16::from_be_bytes([b[0], b[1]]),
            dst_port: u16::from_be_bytes([b[2], b[3]]),
            len: u16::from_be_bytes([b[4], b[5]]),
            checksum: u16::from_be_bytes([b[6], b[7]]),
        }
    }

    fn decode4(&mut self, b: &[u8]) {
        if b.len() < 20 {
            self.ip_proto = UNKNOWN;
            return;
        }
        let ihl = (b[0] & 0x0F) as usize * 4;
        if ihl < 20 || b.len() < ihl {
            self.ip_proto = UNKNOWN;
            return;
        }
        self.ip_proto = b[9];
        self.src = IpAddr::V4(Ipv4Addr::new(b[12], b[13], b[14], b[15]));
        self.dst = IpAddr::V4(Ipv4Addr::new(b[16], b[17], b[18], b[19]));
        self.subofs = ihl;
        self.fill_transport(&b[ihl..]);
        self.dataofs = self.compute_dataofs(&b[ihl..]);
    }

    fn decode6(&mut self, b: &[u8]) {
        if b.len() < 40 {
            self.ip_proto = UNKNOWN;
            return;
        }
        let mut next_header = b[6];
        self.src = IpAddr::V6(Ipv6Addr::from([
            b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15], b[16], b[17], b[18], b[19],
            b[20], b[21], b[22], b[23],
        ]));
        self.dst = IpAddr::V6(Ipv6Addr::from([
            b[24], b[25], b[26], b[27], b[28], b[29], b[30], b[31], b[32], b[33], b[34], b[35],
            b[36], b[37], b[38], b[39],
        ]));

        let mut offset = 40usize;

        // Follow extension headers until we reach a transport protocol or
        // run out of buffer.
        loop {
            match next_header {
                0 | 43 | 60 | 51 => {
                    // Hop-by-Hop, Routing, Destination Options, AH
                    if offset + 2 > b.len() {
                        break;
                    }
                    let new_nh = b[offset];
                    let hdr_len = if next_header == 51 {
                        (b[offset + 1] as usize + 2) * 4
                    } else {
                        (b[offset + 1] as usize + 1) * 8
                    };
                    next_header = new_nh;
                    offset += hdr_len;
                }
                FRAGMENT => {
                    if offset + 8 > b.len() {
                        break;
                    }
                    let frag_offset =
                        (u16::from(b[offset + 2]) << 5) | (u16::from(b[offset + 3]) >> 3);
                    if frag_offset != 0 {
                        break;
                    }
                    next_header = b[offset];
                    offset += 8;
                }
                _ => break,
            }
        }

        self.ip_proto = next_header;
        self.subofs = offset;
        if offset < b.len() {
            let transport = &b[offset..];
            self.fill_transport(transport);
            self.dataofs = self.compute_dataofs(transport);
        }
    }

    /// Fill in transport-layer fields (ports, TCP flags) from the transport
    /// header bytes.
    fn fill_transport(&mut self, transport: &[u8]) {
        match self.ip_proto {
            TCP => {
                if transport.len() >= 14 {
                    self.src_port = u16::from_be_bytes([transport[0], transport[1]]);
                    self.dst_port = u16::from_be_bytes([transport[2], transport[3]]);
                    self.tcp_flags = TCPFlag(transport[13]);
                }
            }
            UDP | SCTP if transport.len() >= 4 => {
                self.src_port = u16::from_be_bytes([transport[0], transport[1]]);
                self.dst_port = u16::from_be_bytes([transport[2], transport[3]]);
            }
            _ => {}
        }
    }

    /// Compute the offset of the transport payload relative to the start
    /// of the transport header.
    fn compute_dataofs(&self, transport: &[u8]) -> usize {
        let dofs = match self.ip_proto {
            TCP => {
                if transport.len() >= 14 {
                    ((transport[12] >> 4) as usize) * 4
                } else {
                    return self.subofs;
                }
            }
            UDP => 8,
            SCTP => 12,
            ICMP_V4 | ICMP_V6 => 8,
            _ => return self.subofs,
        };
        self.subofs + dofs
    }
}

// ---------------------------------------------------------------------------
// parse_packet — the legacy free function (returns Option<PacketInfo>).
// Delegates to Parsed::decode and maps to the flat PacketInfo struct.
// ---------------------------------------------------------------------------

/// Parse a raw IP packet into [`PacketInfo`]. Returns `None` if the packet
/// is too short or not a valid IP packet.
pub fn parse_packet(buf: &[u8]) -> Option<PacketInfo> {
    if buf.is_empty() {
        return None;
    }
    let version = buf[0] >> 4;
    match version {
        4 => parse_v4(buf),
        6 => parse_v6(buf),
        _ => None,
    }
}

fn parse_v4(buf: &[u8]) -> Option<PacketInfo> {
    if buf.len() < 20 {
        return None;
    }
    let ihl = (buf[0] & 0x0F) as usize * 4;
    if ihl < 20 || buf.len() < ihl {
        return None;
    }
    let proto = buf[9];
    let src = IpAddr::V4(Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]));

    let mut info = PacketInfo {
        version: 4,
        proto,
        src,
        dst,
        ..Default::default()
    };

    let transport = &buf[ihl..];
    fill_transport_info(&mut info, proto, transport);
    Some(info)
}

fn parse_v6(buf: &[u8]) -> Option<PacketInfo> {
    if buf.len() < 40 {
        return None;
    }
    let mut next_header = buf[6];
    let src = IpAddr::V6(Ipv6Addr::from([
        buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15], buf[16], buf[17],
        buf[18], buf[19], buf[20], buf[21], buf[22], buf[23],
    ]));
    let dst = IpAddr::V6(Ipv6Addr::from([
        buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31], buf[32], buf[33],
        buf[34], buf[35], buf[36], buf[37], buf[38], buf[39],
    ]));

    let mut offset = 40usize;

    loop {
        match next_header {
            0 | 43 | 60 | 51 => {
                if offset + 2 > buf.len() {
                    break;
                }
                let new_nh = buf[offset];
                let hdr_len = if next_header == 51 {
                    (buf[offset + 1] as usize + 2) * 4
                } else {
                    (buf[offset + 1] as usize + 1) * 8
                };
                next_header = new_nh;
                offset += hdr_len;
            }
            FRAGMENT => {
                if offset + 8 > buf.len() {
                    break;
                }
                let frag_offset =
                    (u16::from(buf[offset + 2]) << 5) | (u16::from(buf[offset + 3]) >> 3);
                if frag_offset != 0 {
                    break;
                }
                next_header = buf[offset];
                offset += 8;
            }
            _ => break,
        }
    }

    let proto = next_header;
    let mut info = PacketInfo {
        version: 6,
        proto,
        src,
        dst,
        ..Default::default()
    };

    if offset < buf.len() {
        fill_transport_info(&mut info, proto, &buf[offset..]);
    }
    Some(info)
}

/// Fill in transport-layer fields (ports, TCP flags, ICMP type) from the
/// transport header bytes.
fn fill_transport_info(info: &mut PacketInfo, proto: u8, transport: &[u8]) {
    match proto {
        TCP => {
            if transport.len() >= 14 {
                info.src_port = u16::from_be_bytes([transport[0], transport[1]]);
                info.dst_port = u16::from_be_bytes([transport[2], transport[3]]);
                info.tcp_flags = transport[13];
                info.is_tcp_syn =
                    (info.tcp_flags & (TCPFlag::SYN.0 | TCPFlag::ACK.0)) == TCPFlag::SYN.0;
            }
        }
        UDP | SCTP => {
            if transport.len() >= 4 {
                info.src_port = u16::from_be_bytes([transport[0], transport[1]]);
                info.dst_port = u16::from_be_bytes([transport[2], transport[3]]);
            }
        }
        ICMP_V4 if !transport.is_empty() => {
            let icmp_type = transport[0];
            info.is_icmp_echo_reply = icmp_type == 0;
            info.is_icmp_error = ICMP_V4_ERROR_TYPES.contains(&icmp_type);
        }
        ICMP_V6 if !transport.is_empty() => {
            let icmp_type = transport[0];
            info.is_icmp_echo_reply = icmp_type == 129;
            info.is_icmp_error = ICMP_V6_ERROR_TYPES.contains(&icmp_type);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4_tcp_syn() -> Vec<u8> {
        // Minimal IPv4 TCP SYN packet
        let mut p = vec![0u8; 40];
        p[0] = 0x45; // version 4, ihl 5
        p[9] = TCP; // protocol
        p[12..16].copy_from_slice(&[192, 168, 1, 1]); // src
        p[16..20].copy_from_slice(&[192, 168, 1, 2]); // dst
        p[20..22].copy_from_slice(&12345u16.to_be_bytes()); // src port
        p[22..24].copy_from_slice(&443u16.to_be_bytes()); // dst port
        p[33] = 0x02; // SYN flag
        p
    }

    #[test]
    fn parsed_decode_v4_tcp() {
        let buf = v4_tcp_syn();
        let q = Parsed::decode(&buf);
        assert_eq!(q.ip_version, 4);
        assert_eq!(q.ip_proto, TCP);
        assert_eq!(q.src, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(q.dst, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)));
        assert_eq!(q.src_port, 12345);
        assert_eq!(q.dst_port, 443);
        assert!(q.is_tcp_syn());
    }

    #[test]
    fn parsed_ip4_header() {
        let buf = v4_tcp_syn();
        let q = Parsed::decode(&buf);
        let h = q.ip4_header();
        assert_eq!(h.version, 4);
        assert_eq!(h.ihl, 5);
        assert_eq!(h.proto, TCP);
        assert_eq!(h.ttl, 0);
        assert_eq!(h.src, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(h.dst, Ipv4Addr::new(192, 168, 1, 2));
    }

    #[test]
    fn parsed_decode_empty() {
        let q = Parsed::decode(&[]);
        assert_eq!(q.ip_version, 0);
        assert_eq!(q.ip_proto, UNKNOWN);
    }

    #[test]
    fn tcp_flag_ops() {
        let syn_ack = TCPFlag::SYN | TCPFlag::ACK;
        assert!(syn_ack.contains(TCPFlag::SYN));
        assert!(syn_ack.contains(TCPFlag::ACK));
        assert!(!TCPFlag::SYN.contains(TCPFlag::ACK));
        assert_eq!(TCPFlag::SYN.0, 0x02);
        assert_eq!(TCPFlag::FIN.0, 0x01);
    }

    #[test]
    fn parse_packet_legacy_compat() {
        let buf = v4_tcp_syn();
        let info = parse_packet(&buf).unwrap();
        assert_eq!(info.version, 4);
        assert_eq!(info.proto, TCP);
        assert!(info.is_tcp_syn());
        assert_eq!(info.src_port, 12345);
        assert_eq!(info.dst_port, 443);
    }

    #[test]
    fn parsed_udp_payload() {
        // IPv4 UDP with 8-byte header + 4-byte payload
        let mut p = vec![0u8; 32];
        p[0] = 0x45; // v4, ihl 5
        p[9] = UDP;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        p[20..22].copy_from_slice(&1234u16.to_be_bytes()); // src port
        p[22..24].copy_from_slice(&5678u16.to_be_bytes()); // dst port
        p[24..26].copy_from_slice(&12u16.to_be_bytes()); // length (8 hdr + 4 payload)
        p[28..32].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let q = Parsed::decode(&p);
        assert_eq!(q.ip_proto, UDP);
        assert_eq!(q.src_port, 1234);
        assert_eq!(q.dst_port, 5678);
        let h = q.udp_header();
        assert_eq!(h.src_port, 1234);
        assert_eq!(h.dst_port, 5678);
        assert_eq!(h.len, 12);
        assert_eq!(q.payload(), &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn parsed_v6_icmp_echo_request() {
        // Minimal IPv6 ICMPv6 Echo Request
        let mut p = vec![0u8; 48];
        p[0] = 0x60; // version 6
        p[6] = ICMP_V6; // next header
        p[7] = 64; // hop limit
                   // src: fd00::1
        p[8] = 0xfd;
        p[23] = 0x01;
        // dst: fd00::2
        p[24] = 0xfd;
        p[39] = 0x02;
        p[40] = 128; // Echo Request
        p[41] = 0; // code
        let q = Parsed::decode(&p);
        assert_eq!(q.ip_version, 6);
        assert_eq!(q.ip_proto, ICMP_V6);
        assert!(q.is_echo_request());
        assert!(!q.is_echo_response());
        let h = q.ip6_header();
        assert_eq!(h.hop_limit, 64);
        assert_eq!(h.next_header, ICMP_V6);
    }
}
