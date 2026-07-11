//! Packet-filter wire types, ported from Go's `tailcfg.go` (PortRange,
//! NetPortRange, CapGrant, FilterRule) and the MapResponse packet-filter
//! fields.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{deserialize_null_to_default, NodeCapability, RawMessage};

/// Deserialize a `PeerCapMap`, treating `null` values inside the map as empty
/// vectors (Go's nil slices marshal as `null`).
fn deserialize_peercapmap<'de, D>(deserializer: D) -> Result<PeerCapMap, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt: Option<BTreeMap<NodeCapability, Option<Vec<RawMessage>>>> =
        Option::deserialize(deserializer)?;
    match opt {
        None => Ok(PeerCapMap::new()),
        Some(raw) => {
            let mut map = PeerCapMap::new();
            for (k, v) in raw {
                map.insert(k, v.unwrap_or_default());
            }
            Ok(map)
        }
    }
}

/// A range of TCP/UDP/SCTP ports (inclusive). Matches Go's `tailcfg.PortRange`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PortRange {
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub First: u16,
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub Last: u16,
}

impl PortRange {
    /// All ports (0–65535), matching Go's `PortRangeAny`.
    pub const ALL: Self = Self {
        First: 0,
        Last: 65535,
    };

    /// Whether `port` falls within this range.
    pub fn contains(&self, port: u16) -> bool {
        port >= self.First && port <= self.Last
    }
}

/// An IP prefix + port range, matching Go's `tailcfg.NetPortRange`.
///
/// `IP` is a string that may be a bare IP, a CIDR, an IP range
/// (`"1.0.0.0-2.1.2.3"`), or `"*"` for wildcard. It is parsed into prefixes
/// by the filter crate.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NetPortRange {
    /// IP / CIDR / range / wildcard string.
    #[serde(default, skip_serializing_if = "String::is_empty", deserialize_with = "deserialize_null_to_default")]
    pub IP: String,
    /// Deprecated CIDR-bits field. If non-null, the filter rejects it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub Bits: Option<i32>,
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub Ports: PortRange,
}

/// A capability grant in a [`FilterRule`], matching Go's `tailcfg.CapGrant`.
///
/// `Dsts` are destination IP-range strings (parsed by the filter crate).
/// `Caps` is the deprecated flat capability list; `CapMap` is the newer
/// capability→values map.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapGrant {
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Dsts: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Caps: Vec<NodeCapability>,
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "deserialize_peercapmap"
    )]
    pub CapMap: PeerCapMap,
}

/// `map[PeerCapability][]RawMessage`, matching Go's `tailcfg.PeerCapMap`.
pub type PeerCapMap = BTreeMap<NodeCapability, Vec<RawMessage>>;

/// A firewall rule, matching Go's `tailcfg.FilterRule`.
///
/// Wire format: PascalCase JSON with `omitempty` on slices and optional
/// fields.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterRule {
    /// Source IPs/CIDRs/ranges/wildcards.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub SrcIPs: Vec<String>,
    /// Deprecated CIDR bits paired with `SrcIPs`. Rejected by the filter.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub SrcBits: Vec<i32>,
    /// Destination IP+port ranges.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub DstPorts: Vec<NetPortRange>,
    /// IP protocol numbers. Empty → default (TCP, UDP, ICMPv4, ICMPv6).
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub IPProto: Vec<i32>,
    /// Capability grants.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub CapGrant: Vec<CapGrant>,
}

/// The canonical "accept everything" rule list, matching Go's
/// `tailcfg.FilterAllowAll`.
pub fn filter_allow_all() -> Vec<FilterRule> {
    vec![FilterRule {
        SrcIPs: vec!["*".into()],
        DstPorts: vec![NetPortRange {
            IP: "*".into(),
            Bits: None,
            Ports: PortRange::ALL,
        }],
        ..Default::default()
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MapResponse;

    #[test]
    fn filter_rule_roundtrip() {
        let rule = FilterRule {
            SrcIPs: vec!["100.64.0.0/10".into(), "*".into()],
            DstPorts: vec![NetPortRange {
                IP: "1.2.3.4".into(),
                Bits: None,
                Ports: PortRange {
                    First: 22,
                    Last: 22,
                },
            }],
            IPProto: vec![6, 17],
            ..Default::default()
        };
        let j = serde_json::to_string(&rule).unwrap();
        assert!(j.contains("\"SrcIPs\""));
        assert!(j.contains("\"DstPorts\""));
        assert!(j.contains("\"IPProto\":[6,17]"));
        assert!(!j.contains("\"SrcBits\""));
        assert!(!j.contains("\"CapGrant\""));
        let back: FilterRule = serde_json::from_str(&j).unwrap();
        assert_eq!(back, rule);
    }

    #[test]
    fn filter_rule_empty_omits_all() {
        let rule = FilterRule::default();
        let j = serde_json::to_string(&rule).unwrap();
        assert_eq!(j, "{}");
    }

    #[test]
    fn cap_grant_roundtrip() {
        let mut cap_map = PeerCapMap::new();
        cap_map.insert("cap-foo".into(), vec![RawMessage("42".into())]);
        let grant = CapGrant {
            Dsts: vec!["0.0.0.0/0".into()],
            Caps: vec!["is-ipv4".into()],
            CapMap: cap_map,
        };
        let j = serde_json::to_string(&grant).unwrap();
        let back: CapGrant = serde_json::from_str(&j).unwrap();
        assert_eq!(back, grant);
    }

    #[test]
    fn map_response_packet_filter_none_vs_empty() {
        // None = field absent (unchanged)
        let resp = MapResponse::default();
        let j = serde_json::to_string(&resp).unwrap();
        assert!(!j.contains("PacketFilter"));
        assert!(!j.contains("PacketFilters"));

        // Some(vec![]) = block all (field present, empty array)
        let resp = MapResponse {
            PacketFilter: Some(vec![]),
            ..Default::default()
        };
        let j = serde_json::to_string(&resp).unwrap();
        assert!(j.contains("\"PacketFilter\":[]"));

        // Some(vec![rule]) = full replacement
        let resp = MapResponse {
            PacketFilter: Some(filter_allow_all()),
            ..Default::default()
        };
        let j = serde_json::to_string(&resp).unwrap();
        assert!(j.contains("\"PacketFilter\":["));
        let back: MapResponse = serde_json::from_str(&j).unwrap();
        assert_eq!(back.PacketFilter, Some(filter_allow_all()));
    }

    #[test]
    fn map_response_packet_filters_delta() {
        let mut map = BTreeMap::new();
        map.insert("base".into(), Some(vec![]));
        map.insert("*".into(), None);
        let resp = MapResponse {
            PacketFilters: Some(map),
            ..Default::default()
        };
        let j = serde_json::to_string(&resp).unwrap();
        assert!(j.contains("\"PacketFilters\":{"));
        assert!(j.contains("\"base\":[]"));
        assert!(j.contains("\"*\":null"));
        let back: MapResponse = serde_json::from_str(&j).unwrap();
        assert!(back.PacketFilters.is_some());
    }

    #[test]
    fn port_range_serializes_correctly() {
        let pr = PortRange {
            First: 22,
            Last: 22,
        };
        assert_eq!(
            serde_json::to_string(&pr).unwrap(),
            "{\"First\":22,\"Last\":22}"
        );
        let pr_all = PortRange::ALL;
        assert_eq!(
            serde_json::to_string(&pr_all).unwrap(),
            "{\"First\":0,\"Last\":65535}"
        );
    }
}
