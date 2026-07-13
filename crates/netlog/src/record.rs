//! In-memory record aggregation — port of Go's `record.go` (218 loc).
//!
//! A [`Record`] accumulates per-connection packet/byte counts in
//! `HashMap`s. When flushed, [`Record::to_message`] converts it into a
//! [`Message`] suitable for JSON serialization and logtail upload.

use std::collections::HashMap;
use std::net::IpAddr;

use chrono::{DateTime, Utc};

use rustscale_netlogtype::{
    AddrPort, Connection, ConnectionCounts, Counts, Message, Node, MAX_CONNECTION_COUNTS_JSON_SIZE,
};

/// Traffic classification. Mirrors Go's `connType`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ConnectionType {
    #[default]
    Unknown,
    Virtual,
    Subnet,
    Exit,
}

/// Counts with traffic classification. Mirrors Go's `countsType`.
#[derive(Clone, Copy, Debug, Default)]
pub struct CountsAndType {
    pub counts: Counts,
    pub conn_type: ConnectionType,
}

/// An in-memory record of aggregated flows, mirroring Go's `record` struct.
///
/// The record is owned by the logger's background task — no locking is
/// needed because only that task touches it. Events arrive via a channel.
pub struct Record {
    pub self_node: Option<Node>,
    pub start: DateTime<Utc>,
    pub seen_nodes: HashMap<IpAddr, Node>,
    pub virt_conns: HashMap<Connection, CountsAndType>,
    pub phys_conns: HashMap<Connection, Counts>,
    /// Upper-bound estimate of the JSON size, used to flush early when
    /// approaching `MAX_LOG_SIZE`. Mirrors Go's `recordLen`.
    pub json_len_estimate: usize,
}

impl Record {
    /// Create a fresh record starting at `now` with the given self node.
    pub fn new(self_node: Option<Node>, now: DateTime<Utc>) -> Self {
        let mut json_len_estimate = rustscale_netlogtype::MIN_MESSAGE_JSON_SIZE;
        if let Some(ref n) = self_node {
            json_len_estimate += node_json_len(n);
        }
        Self {
            self_node,
            start: now,
            seen_nodes: HashMap::new(),
            virt_conns: HashMap::new(),
            phys_conns: HashMap::new(),
            json_len_estimate,
        }
    }

    /// Whether the record has no connections (mirrors Go's `recordLen == 0`).
    pub fn is_empty(&self) -> bool {
        self.json_len_estimate == 0
    }

    /// Reset the record to the empty state.
    pub fn clear(&mut self) {
        self.self_node = None;
        self.start = DateTime::<Utc>::default();
        self.seen_nodes.clear();
        self.virt_conns.clear();
        self.phys_conns.clear();
        self.json_len_estimate = 0;
    }

    /// Add counts for a virtual (tun) connection.
    ///
    /// `conn_type` is pre-classified by the caller (see [`crate::traffic`]).
    /// `recv=true` means received (Rx), `false` means transmitted (Tx).
    pub fn add_virt(
        &mut self,
        proto: u8,
        src: (IpAddr, u16),
        dst: (IpAddr, u16),
        packets: u64,
        bytes: u64,
        recv: bool,
        conn_type: ConnectionType,
    ) {
        let conn = Connection {
            proto,
            src: AddrPort(src.0, src.1),
            dst: AddrPort(dst.0, dst.1),
        };
        let entry = self.virt_conns.entry(conn).or_insert_with(|| {
            // First insertion — account for the JSON size.
            self.json_len_estimate += MAX_CONNECTION_COUNTS_JSON_SIZE;
            CountsAndType {
                counts: Counts::default(),
                conn_type,
            }
        });
        if recv {
            entry.counts.rx_packets = entry.counts.rx_packets.wrapping_add(packets);
            entry.counts.rx_bytes = entry.counts.rx_bytes.wrapping_add(bytes);
        } else {
            entry.counts.tx_packets = entry.counts.tx_packets.wrapping_add(packets);
            entry.counts.tx_bytes = entry.counts.tx_bytes.wrapping_add(bytes);
        }
    }

    /// Add counts for a physical (magicsock) connection.
    pub fn add_phys(
        &mut self,
        proto: u8,
        src: (IpAddr, u16),
        dst: (IpAddr, u16),
        packets: u64,
        bytes: u64,
        recv: bool,
    ) {
        let conn = Connection {
            proto,
            src: AddrPort(src.0, src.1),
            dst: AddrPort(dst.0, dst.1),
        };
        let entry = self.phys_conns.entry(conn).or_insert_with(|| {
            self.json_len_estimate += MAX_CONNECTION_COUNTS_JSON_SIZE;
            Counts::default()
        });
        if recv {
            entry.rx_packets = entry.rx_packets.wrapping_add(packets);
            entry.rx_bytes = entry.rx_bytes.wrapping_add(bytes);
        } else {
            entry.tx_packets = entry.tx_packets.wrapping_add(packets);
            entry.tx_bytes = entry.tx_bytes.wrapping_add(bytes);
        }
    }

    /// Note a newly-seen node address so it appears in `dstNodes`.
    /// Returns the node if it was newly inserted.
    pub fn note_seen_node(&mut self, addr: IpAddr, node: Node) -> bool {
        if !node.is_valid() {
            return false;
        }
        if self.seen_nodes.contains_key(&addr) {
            return false;
        }
        self.seen_nodes.insert(addr, node.clone());
        self.json_len_estimate += node_json_len(&node);
        true
    }

    /// Whether adding another connection would exceed `max_log_size`.
    /// Mirrors Go's size check in `addNewVirtConnLocked`/`addNewPhysConnLocked`.
    pub fn would_overflow(&self, max_log_size: usize, extra: usize) -> bool {
        self.json_len_estimate + extra > max_log_size
    }

    /// Convert to a [`Message`], consuming the record's traffic maps.
    /// Mirrors Go's `record.toMessage`.
    ///
    /// `anonymize_exit` scrubs port numbers and non-Tailscale source
    /// addresses from exit traffic (privacy mode), matching Go's
    /// `anonymizeExitTraffic` parameter.
    pub fn to_message(&mut self, end: DateTime<Utc>, anonymize_exit: bool) -> Option<Message> {
        let self_node = self.self_node.clone()?;
        let mut m = Message {
            node_id: self_node.node_id.clone(),
            start: self.start.to_rfc3339(),
            end: end.to_rfc3339(),
            src_node: self_node,
            ..Default::default()
        };

        // Collect and sort dst nodes by node_id (deterministic output,
        // matching Go's `slices.SortFunc`).
        let self_id = m.src_node.node_id.clone();
        let mut dst_ids = std::collections::HashSet::new();
        dst_ids.insert(self_id.clone());
        for node in self.seen_nodes.values() {
            if dst_ids.insert(node.node_id.clone()) {
                m.dst_nodes.push(node.clone());
            }
        }
        m.dst_nodes.sort_by(|a, b| a.node_id.cmp(&b.node_id));

        // Classify virtual traffic into the four buckets.
        let mut anonymized_exit: HashMap<Connection, Counts> = HashMap::new();
        for (&conn, cnts) in &self.virt_conns {
            match cnts.conn_type {
                ConnectionType::Virtual => {
                    m.virtual_traffic.push(ConnectionCounts {
                        connection: conn,
                        counts: cnts.counts,
                    });
                }
                ConnectionType::Subnet => {
                    m.subnet_traffic.push(ConnectionCounts {
                        connection: conn,
                        counts: cnts.counts,
                    });
                }
                ConnectionType::Exit => {
                    if anonymize_exit {
                        let scrubbed = Connection {
                            proto: conn.proto,
                            src: AddrPort(conn.src.addr(), 0),
                            dst: AddrPort(conn.dst.addr(), 0),
                        };
                        let src_seen = self.seen_nodes.contains_key(&conn.src.addr());
                        let dst_seen = self.seen_nodes.contains_key(&conn.dst.addr());
                        let key = Connection {
                            proto: scrubbed.proto,
                            src: if src_seen {
                                scrubbed.src
                            } else {
                                AddrPort(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
                            },
                            dst: if dst_seen {
                                scrubbed.dst
                            } else {
                                AddrPort(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
                            },
                        };
                        anonymized_exit
                            .entry(key)
                            .and_modify(|c| c.add(&cnts.counts))
                            .or_insert(cnts.counts);
                    } else {
                        m.exit_traffic.push(ConnectionCounts {
                            connection: conn,
                            counts: cnts.counts,
                        });
                    }
                }
                ConnectionType::Unknown => {
                    // Unknown traffic falls into exit bucket (matching Go's default case).
                    m.exit_traffic.push(ConnectionCounts {
                        connection: conn,
                        counts: cnts.counts,
                    });
                }
            }
        }
        for (conn, cnts) in &anonymized_exit {
            m.exit_traffic.push(ConnectionCounts {
                connection: *conn,
                counts: *cnts,
            });
        }

        for (&conn, &cnts) in &self.phys_conns {
            m.physical_traffic.push(ConnectionCounts {
                connection: conn,
                counts: cnts,
            });
        }

        // Sort connections deterministically (src, then dst, then proto).
        sort_conn_counts(&mut m.virtual_traffic);
        sort_conn_counts(&mut m.subnet_traffic);
        sort_conn_counts(&mut m.exit_traffic);
        sort_conn_counts(&mut m.physical_traffic);

        Some(m)
    }
}

/// Sort `ConnectionCounts` by (src, dst, proto) for deterministic output.
/// Mirrors Go's `compareConnCnts`.
fn sort_conn_counts(v: &mut [ConnectionCounts]) {
    v.sort_by(|a, b| {
        a.connection
            .src
            .to_string()
            .cmp(&b.connection.src.to_string())
            .then_with(|| {
                a.connection
                    .dst
                    .to_string()
                    .cmp(&b.connection.dst.to_string())
            })
            .then_with(|| a.connection.proto.cmp(&b.connection.proto))
    });
}

/// Upper-bound JSON size of a [`Node`]. Mirrors Go's `nodeUser.jsonLen`.
fn node_json_len(n: &Node) -> usize {
    // Base: `{}`
    let mut n_len = 2; // "{}"
                       // "nodeId":"<id>",
    n_len += 8 + n.node_id.len() + 1; // "nodeId": + quoted + comma
    if !n.name.is_empty() {
        n_len += 7 + n.name.len() + 1; // "name": + quoted + comma
    }
    if !n.addresses.is_empty() {
        n_len += 13; // "addresses":[]
        for addr in &n.addresses {
            n_len += addr.len() + 2 + 1; // quoted + comma
        }
    }
    if !n.os.is_empty() {
        n_len += 5 + n.os.len() + 1; // "os": + quoted + comma
    }
    if !n.user.is_empty() {
        n_len += 7 + n.user.len() + 1; // "user": + quoted + comma
    }
    if !n.tags.is_empty() {
        n_len += 8; // "tags":[]
        for tag in &n.tags {
            n_len += tag.len() + 2 + 1; // quoted + comma
        }
    }
    n_len
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn test_record_add_virtual_connection() {
        let now = Utc::now();
        let mut rec = Record::new(
            Some(Node {
                node_id: "nABC".to_string(),
                ..Default::default()
            }),
            now,
        );
        rec.add_virt(
            6,
            (ip("100.64.0.1"), 1234),
            (ip("100.64.0.2"), 443),
            1,
            100,
            false,
            ConnectionType::Virtual,
        );
        rec.add_virt(
            6,
            (ip("100.64.0.1"), 1234),
            (ip("100.64.0.2"), 443),
            2,
            200,
            true,
            ConnectionType::Virtual,
        );
        let conn = Connection {
            proto: 6,
            src: AddrPort(ip("100.64.0.1"), 1234),
            dst: AddrPort(ip("100.64.0.2"), 443),
        };
        let entry = rec.virt_conns.get(&conn).unwrap();
        assert_eq!(entry.counts.tx_packets, 1);
        assert_eq!(entry.counts.tx_bytes, 100);
        assert_eq!(entry.counts.rx_packets, 2);
        assert_eq!(entry.counts.rx_bytes, 200);
        assert_eq!(entry.conn_type, ConnectionType::Virtual);
    }

    #[test]
    fn test_record_to_message_virtual() {
        let now = Utc::now();
        let mut rec = Record::new(
            Some(Node {
                node_id: "nABC".to_string(),
                name: "self.example.ts.net".to_string(),
                ..Default::default()
            }),
            now,
        );
        rec.note_seen_node(
            ip("100.64.0.2"),
            Node {
                node_id: "nDEF".to_string(),
                ..Default::default()
            },
        );
        rec.add_virt(
            6,
            (ip("100.64.0.1"), 1234),
            (ip("100.64.0.2"), 443),
            10,
            1000,
            false,
            ConnectionType::Virtual,
        );
        let end = now + chrono::Duration::seconds(5);
        let msg = rec.to_message(end, false).unwrap();
        assert_eq!(msg.node_id, "nABC");
        assert_eq!(msg.virtual_traffic.len(), 1);
        assert_eq!(msg.virtual_traffic[0].connection.proto, 6);
        assert_eq!(msg.virtual_traffic[0].counts.tx_packets, 10);
        assert_eq!(msg.virtual_traffic[0].counts.tx_bytes, 1000);
        assert_eq!(msg.dst_nodes.len(), 1);
        assert_eq!(msg.dst_nodes[0].node_id, "nDEF");
    }

    #[test]
    fn test_record_to_message_exit_anonymized() {
        let now = Utc::now();
        let mut rec = Record::new(
            Some(Node {
                node_id: "nABC".to_string(),
                ..Default::default()
            }),
            now,
        );
        // Exit traffic to an external IP (not a seen node).
        rec.add_virt(
            6,
            (ip("100.64.0.1"), 1234),
            (ip("8.8.8.8"), 443),
            5,
            500,
            false,
            ConnectionType::Exit,
        );
        let end = now + chrono::Duration::seconds(5);
        let msg = rec.to_message(end, true).unwrap();
        // Exit traffic should have scrubbed ports and scrubbed dst (not a seen node).
        assert_eq!(msg.exit_traffic.len(), 1);
        assert_eq!(msg.exit_traffic[0].connection.dst.port(), 0);
        // dst address should be scrubbed to 0.0.0.0 since 8.8.8.8 is not a seen node.
        assert_eq!(
            msg.exit_traffic[0].connection.dst.addr(),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        );
        assert_eq!(msg.exit_traffic[0].counts.tx_packets, 5);
    }

    #[test]
    fn test_record_to_message_no_self_node() {
        let now = Utc::now();
        let mut rec = Record::new(None, now);
        rec.add_virt(
            6,
            (ip("100.64.0.1"), 1234),
            (ip("100.64.0.2"), 443),
            1,
            100,
            false,
            ConnectionType::Virtual,
        );
        let end = now + chrono::Duration::seconds(5);
        // No self node → to_message returns None (matching Go).
        assert!(rec.to_message(end, false).is_none());
    }

    #[test]
    fn test_record_to_message_json_roundtrip() {
        let now = Utc::now();
        let mut rec = Record::new(
            Some(Node {
                node_id: "nABC".to_string(),
                name: "self.example.ts.net".to_string(),
                os: "linux".to_string(),
                ..Default::default()
            }),
            now,
        );
        rec.note_seen_node(
            ip("100.64.0.2"),
            Node {
                node_id: "nDEF".to_string(),
                name: "peer.example.ts.net".to_string(),
                ..Default::default()
            },
        );
        rec.add_virt(
            6,
            (ip("100.64.0.1"), 1234),
            (ip("100.64.0.2"), 443),
            10,
            1000,
            false,
            ConnectionType::Virtual,
        );
        rec.add_virt(
            6,
            (ip("100.64.0.1"), 1234),
            (ip("100.64.0.2"), 443),
            3,
            300,
            true,
            ConnectionType::Virtual,
        );
        rec.add_phys(
            17,
            (ip("100.64.0.1"), 0),
            (ip("203.0.113.5"), 41641),
            8,
            640,
            false,
        );
        let end = now + chrono::Duration::seconds(5);
        let msg = rec.to_message(end, false).unwrap();
        let json = serde_json::to_string(&msg).unwrap();
        let back: Message = serde_json::from_str(&json).unwrap();
        assert_eq!(back.node_id, "nABC");
        assert_eq!(back.virtual_traffic.len(), 1);
        assert_eq!(back.virtual_traffic[0].counts.tx_packets, 10);
        assert_eq!(back.virtual_traffic[0].counts.rx_packets, 3);
        assert_eq!(back.physical_traffic.len(), 1);
        assert_eq!(back.physical_traffic[0].counts.tx_packets, 8);
    }

    #[test]
    fn test_record_physical_connection() {
        let now = Utc::now();
        let mut rec = Record::new(
            Some(Node {
                node_id: "nABC".to_string(),
                ..Default::default()
            }),
            now,
        );
        rec.add_phys(
            17,
            (ip("100.64.0.1"), 0),
            (ip("203.0.113.5"), 41641),
            1,
            80,
            false,
        );
        rec.add_phys(
            17,
            (ip("100.64.0.1"), 0),
            (ip("203.0.113.5"), 41641),
            2,
            160,
            true,
        );
        let conn = Connection {
            proto: 17,
            src: AddrPort(ip("100.64.0.1"), 0),
            dst: AddrPort(ip("203.0.113.5"), 41641),
        };
        let entry = rec.phys_conns.get(&conn).unwrap();
        assert_eq!(entry.tx_packets, 1);
        assert_eq!(entry.tx_bytes, 80);
        assert_eq!(entry.rx_packets, 2);
        assert_eq!(entry.rx_bytes, 160);
    }

    #[test]
    fn test_record_would_overflow() {
        let now = Utc::now();
        let mut rec = Record::new(None, now);
        rec.json_len_estimate = 200;
        assert!(rec.would_overflow(256, 100));
        assert!(!rec.would_overflow(256, 50));
    }
}
