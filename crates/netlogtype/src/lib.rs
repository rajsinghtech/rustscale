//! Network logging wire types — port of Go's `types/netlogtype` (157 loc).
//!
//! Defines [`Message`], [`Node`], [`Connection`], [`Counts`], and
//! [`ConnectionCounts`] — the JSON schema for network flow log entries
//! uploaded to the `tailtraffic.log.tailscale.io` logtail collection.
//!
//! The `src`/`dst` fields of [`Connection`] serialize as strings in
//! Go's `netip.AddrPort` format (`"1.2.3.4:443"` for IPv4,
//! `"[2001:db8::1]:443"` for IPv6) so the server-side log pipeline
//! accepts our messages unchanged.

#![forbid(unsafe_code)]
#![allow(non_snake_case)]

use std::fmt;
use std::net::IpAddr;

use rustscale_tailcfg::StableNodeID;
use serde::{Deserialize, Serialize};

/// IP protocol number (mirrors Go's `ipproto.Proto`).
pub type Proto = u8;

/// A `(IpAddr, port)` pair that serializes as Go's `netip.AddrPort`:
/// `"1.2.3.4:443"` for IPv4, `"[::1]:443"` for IPv6.
///
/// Stored as a tuple struct so [`Connection`] can hold the fields
/// directly while still producing the correct JSON shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AddrPort(pub IpAddr, pub u16);

impl AddrPort {
    pub fn addr(&self) -> IpAddr {
        self.0
    }
    pub fn port(&self) -> u16 {
        self.1
    }
}

impl fmt::Display for AddrPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            IpAddr::V4(ip) => write!(f, "{ip}:{}", self.1),
            IpAddr::V6(ip) => write!(f, "[{ip}]:{}", self.1),
        }
    }
}

impl Serialize for AddrPort {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for AddrPort {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        parse_addrport(&s).map_err(serde::de::Error::custom)
    }
}

/// Parse `"host:port"` / `"[host]:port"` into [`AddrPort`], matching
/// Go's `netip.AddrPort.UnmarshalText`.
fn parse_addrport(s: &str) -> Result<AddrPort, String> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        // [ipv6]:port
        let (host, port) = rest
            .split_once(']')
            .ok_or_else(|| "missing ']' in [ipv6]:port".to_string())?;
        let port_part = port.strip_prefix(':').ok_or("missing ':port'")?;
        let ip: IpAddr = host
            .parse()
            .map_err(|e: std::net::AddrParseError| e.to_string())?;
        let port: u16 = port_part
            .parse()
            .map_err(|e: std::num::ParseIntError| e.to_string())?;
        Ok(AddrPort(ip, port))
    } else {
        // ipv4:port  —  the un-bracketed form only accepts IPv4 here,
        // matching Go's `netip.AddrPort.UnmarshalText` behavior.
        let (host, port) = s
            .rsplit_once(':')
            .ok_or_else(|| "missing ':port'".to_string())?;
        let ip: IpAddr = host
            .parse()
            .map_err(|e: std::net::AddrParseError| e.to_string())?;
        let port: u16 = port
            .parse()
            .map_err(|e: std::num::ParseIntError| e.to_string())?;
        Ok(AddrPort(ip, port))
    }
}

/// A 5-tuple identifying a network connection.
///
/// Mirrors Go's `netlogtype.Connection`. `src`/`dst` serialize as
/// `AddrPort` strings so the server sees the same JSON shape as Go.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Connection {
    #[serde(default, skip_serializing_if = "is_zero_u8")]
    pub proto: Proto,
    pub src: AddrPort,
    pub dst: AddrPort,
}

/// Per-connection packet/byte counts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counts {
    #[serde(rename = "txPkts", default, skip_serializing_if = "is_zero_u64")]
    pub tx_packets: u64,
    #[serde(rename = "txBytes", default, skip_serializing_if = "is_zero_u64")]
    pub tx_bytes: u64,
    #[serde(rename = "rxPkts", default, skip_serializing_if = "is_zero_u64")]
    pub rx_packets: u64,
    #[serde(rename = "rxBytes", default, skip_serializing_if = "is_zero_u64")]
    pub rx_bytes: u64,
}

impl Counts {
    pub fn is_zero(&self) -> bool {
        *self == Self::default()
    }

    /// Add `other`'s counts into `self` (mirrors Go's `Counts.Add`).
    pub fn add(&mut self, other: &Counts) {
        self.tx_packets = self.tx_packets.wrapping_add(other.tx_packets);
        self.tx_bytes = self.tx_bytes.wrapping_add(other.tx_bytes);
        self.rx_packets = self.rx_packets.wrapping_add(other.rx_packets);
        self.rx_bytes = self.rx_bytes.wrapping_add(other.rx_bytes);
    }
}

/// A connection with its traffic counts (flattened for JSON).
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct ConnectionCounts {
    #[serde(flatten)]
    pub connection: Connection,
    #[serde(flatten)]
    pub counts: Counts,
}

/// Node metadata for netlog messages. Mirrors Go's `netlogtype.Node`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    #[serde(rename = "nodeId", default)]
    pub node_id: StableNodeID,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub os: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub user: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

impl Node {
    pub fn is_valid(&self) -> bool {
        !self.node_id.is_empty()
    }
}

/// A netlog message — sent to logtail every ~5s.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Message {
    #[serde(rename = "nodeId", default)]
    pub node_id: StableNodeID,
    pub start: String, // RFC3339
    pub end: String,   // RFC3339
    #[serde(rename = "srcNode", default)]
    pub src_node: Node,
    #[serde(rename = "dstNodes", default, skip_serializing_if = "Vec::is_empty")]
    pub dst_nodes: Vec<Node>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub virtual_traffic: Vec<ConnectionCounts>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subnet_traffic: Vec<ConnectionCounts>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exit_traffic: Vec<ConnectionCounts>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub physical_traffic: Vec<ConnectionCounts>,
}

// --- size constants mirroring Go's netlogtype ---
//
// Go computes upper bounds on JSON size to flush records before they
// exceed `maxLogSize` (256 KiB). We port the two constants that callers
// use: `MinMessageJSONSize` (overhead of an empty-ish Message) and
// `MaxConnectionCountsJSONSize` (worst-case per-connection entry).

/// Overhead of a minimally-populated Message JSON blob. Matches Go's
/// `netlogtype.MinMessageJSONSize`.
pub const MIN_MESSAGE_JSON_SIZE: usize = 154;

/// Worst-case JSON size of a single `ConnectionCounts` entry. Matches
/// Go's `netlogtype.MaxConnectionCountsJSONSize`.
pub const MAX_CONNECTION_COUNTS_JSON_SIZE: usize = 135;

// --- serde helpers (omitzero semantics for primitives) ---
// `skip_serializing_if` predicates must take a reference; clippy's
// `trivially_copy_pass_by_ref` is silenced since the signature is forced
// by the serde API.

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero_u8(v: &u8) -> bool {
    *v == 0
}
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_addrport_serde_ipv4() {
        let ap = AddrPort("1.2.3.4".parse().unwrap(), 443);
        let j = serde_json::to_string(&ap).unwrap();
        assert_eq!(j, "\"1.2.3.4:443\"");
        let back: AddrPort = serde_json::from_str(&j).unwrap();
        assert_eq!(ap, back);
    }

    #[test]
    fn test_addrport_serde_ipv6() {
        let ap = AddrPort("2001:db8::1".parse().unwrap(), 443);
        let j = serde_json::to_string(&ap).unwrap();
        assert_eq!(j, "\"[2001:db8::1]:443\"");
        let back: AddrPort = serde_json::from_str(&j).unwrap();
        assert_eq!(ap, back);
    }

    #[test]
    fn test_connection_roundtrip() {
        let c = Connection {
            proto: 6,
            src: AddrPort("100.64.0.1".parse().unwrap(), 1234),
            dst: AddrPort("100.64.0.2".parse().unwrap(), 443),
        };
        let j = serde_json::to_string(&c).unwrap();
        let back: Connection = serde_json::from_str(&j).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn test_counts_serde_keys() {
        let c = Counts {
            tx_packets: 10,
            tx_bytes: 1024,
            rx_packets: 5,
            rx_bytes: 512,
        };
        let j = serde_json::to_string(&c).unwrap();
        assert!(j.contains("\"txPkts\":10"));
        assert!(j.contains("\"txBytes\":1024"));
        assert!(j.contains("\"rxPkts\":5"));
        assert!(j.contains("\"rxBytes\":512"));
    }

    #[test]
    fn test_counts_zero_omitted() {
        let c = Counts::default();
        let j = serde_json::to_string(&c).unwrap();
        assert_eq!(j, "{}");
    }

    #[test]
    fn test_message_roundtrip() {
        let m = Message {
            node_id: "nABC".to_string(),
            start: "2026-07-13T00:00:00Z".to_string(),
            end: "2026-07-13T00:00:05Z".to_string(),
            src_node: Node {
                node_id: "nABC".to_string(),
                name: "self.example.ts.net".to_string(),
                ..Default::default()
            },
            dst_nodes: vec![Node {
                node_id: "nDEF".to_string(),
                ..Default::default()
            }],
            virtual_traffic: vec![ConnectionCounts {
                connection: Connection {
                    proto: 6,
                    src: AddrPort("100.64.0.1".parse().unwrap(), 1234),
                    dst: AddrPort("100.64.0.2".parse().unwrap(), 443),
                },
                counts: Counts {
                    tx_packets: 1,
                    tx_bytes: 100,
                    ..Default::default()
                },
            }],
            ..Default::default()
        };
        let j = serde_json::to_string(&m).unwrap();
        let back: Message = serde_json::from_str(&j).unwrap();
        assert_eq!(back.node_id, m.node_id);
        assert_eq!(back.virtual_traffic.len(), 1);
        assert_eq!(back.virtual_traffic[0].connection.proto, 6);
        assert_eq!(back.virtual_traffic[0].counts.tx_packets, 1);
    }

    #[test]
    fn test_connection_counts_flattened() {
        let cc = ConnectionCounts {
            connection: Connection {
                proto: 17,
                src: AddrPort("10.0.0.1".parse().unwrap(), 53),
                dst: AddrPort("10.0.0.2".parse().unwrap(), 53),
            },
            counts: Counts {
                rx_packets: 2,
                rx_bytes: 200,
                ..Default::default()
            },
        };
        let j = serde_json::to_string(&cc).unwrap();
        // Flattened: proto + src + dst + tx/rx keys all top-level.
        assert!(j.contains("\"proto\":17"));
        assert!(j.contains("\"rxPkts\":2"));
        assert!(!j.contains("\"connection\""));
        assert!(!j.contains("\"counts\""));
    }

    #[test]
    fn test_counts_add() {
        let mut a = Counts {
            tx_packets: 1,
            tx_bytes: 10,
            ..Default::default()
        };
        let b = Counts {
            tx_packets: 2,
            rx_packets: 3,
            rx_bytes: 30,
            ..Default::default()
        };
        a.add(&b);
        assert_eq!(a.tx_packets, 3);
        assert_eq!(a.rx_packets, 3);
        assert_eq!(a.rx_bytes, 30);
    }
}
