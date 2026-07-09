//! Minimal IP header parser — extracts the fields the filter needs from a
//! raw IP packet (version, proto, addrs, ports, TCP flags, ICMP type).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// IP protocol numbers used by the filter.
pub const UNKNOWN: u8 = 0;
pub const ICMP_V4: u8 = 1;
pub const IGMP: u8 = 2;
pub const TCP: u8 = 6;
pub const UDP: u8 = 17;
pub const FRAGMENT: u8 = 44;
pub const ICMP_V6: u8 = 58;
pub const SCTP: u8 = 132;
pub const TSMP: u8 = 99;

/// TCP flag bits.
const TCP_SYN: u8 = 0x02;
const TCP_ACK: u8 = 0x10;

/// ICMP_V4 types that are considered "errors".
const ICMP_ERROR_TYPES: [u8; 4] = [3, 4, 11, 12];

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
    fill_transport(&mut info, proto, transport);
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

    // Follow extension headers until we reach a transport protocol or
    // run out of buffer. Only Fragment (44) is handled specially: offset 0
    // means first fragment (parse through to real proto); non-zero means
    // Fragment proto (accepted by pre()).
    loop {
        match next_header {
            0 | 43 | 60 | 51 => {
                // Hop-by-Hop, Routing, Destination Options, AH —
                // each has next-header at byte 0 and length in 8-byte units
                // (except AH which is in 4-byte units + 2).
                if offset + 2 > buf.len() {
                    break;
                }
                let new_nh = buf[offset];
                let hdr_len = if next_header == 51 {
                    // AH: length in 4-byte units + 2
                    (buf[offset + 1] as usize + 2) * 4
                } else {
                    // Others: length in 8-byte units + 8
                    (buf[offset + 1] as usize + 1) * 8
                };
                next_header = new_nh;
                offset += hdr_len;
            }
            FRAGMENT => {
                // Fragment header is 8 bytes.
                if offset + 8 > buf.len() {
                    // Can't parse fragment header — treat as Fragment.
                    break;
                }
                let frag_offset = ((buf[offset + 2] as u16) << 5) | (buf[offset + 3] as u16 >> 3);
                if frag_offset != 0 {
                    // Non-first fragment: proto stays as FRAGMENT.
                    break;
                }
                // First fragment: real protocol is in the fragment header's
                // NextHeader field.
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
        fill_transport(&mut info, proto, &buf[offset..]);
    }
    Some(info)
}

/// Fill in transport-layer fields (ports, TCP flags, ICMP type) from the
/// transport header bytes.
fn fill_transport(info: &mut PacketInfo, proto: u8, transport: &[u8]) {
    match proto {
        TCP => {
            if transport.len() >= 14 {
                info.src_port = u16::from_be_bytes([transport[0], transport[1]]);
                info.dst_port = u16::from_be_bytes([transport[2], transport[3]]);
                info.tcp_flags = transport[13];
                info.is_tcp_syn = (info.tcp_flags & (TCP_SYN | TCP_ACK)) == TCP_SYN;
            }
        }
        UDP | SCTP => {
            if transport.len() >= 4 {
                info.src_port = u16::from_be_bytes([transport[0], transport[1]]);
                info.dst_port = u16::from_be_bytes([transport[2], transport[3]]);
            }
        }
        ICMP_V4 => {
            if transport.len() >= 1 {
                let icmp_type = transport[0];
                info.is_icmp_echo_reply = icmp_type == 0;
                info.is_icmp_error = ICMP_ERROR_TYPES.contains(&icmp_type);
            }
        }
        ICMP_V6 => {
            if transport.len() >= 1 {
                let icmp_type = transport[0];
                // Echo reply = 129 for ICMP_V6.
                info.is_icmp_echo_reply = icmp_type == 129;
                info.is_icmp_error =
                    ICMP_ERROR_TYPES.contains(&icmp_type) || icmp_type == 1 || icmp_type == 2;
            }
        }
        _ => {}
    }
}
