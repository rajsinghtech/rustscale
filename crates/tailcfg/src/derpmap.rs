//! DERP relay map types, ported from Go's `tailcfg/derpmap.go`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::{deserialize_null_to_default, int_key, skip_default};

/// The set of DERP packet relay servers available to clients.
///
/// `Regions` is keyed by `DERPRegion::RegionID`; Go marshals `map[int]` with
/// string JSON keys, reproduced here via [`int_key`].
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DERPMap {
    /// Changes in home- DERP selection parameters; nil means unchanged.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub HomeParams: Option<DERPHomeParams>,

    /// Geographic regions, keyed by `RegionID`.
    #[serde(
        default,
        serialize_with = "int_key::serialize",
        deserialize_with = "int_key::deserialize_null_values"
    )]
    pub Regions: BTreeMap<i32, DERPRegion>,

    /// When true, ignore Tailscale's default DERP servers.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub OmitDefaultRegions: bool,
}

/// Server-supplied parameters for selecting a home DERP region.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DERPHomeParams {
    /// Per-region latency scaling factors (1.0 = neutral). A nil map means no
    /// change; an empty map resets all scores to 1.0.
    #[serde(
        default,
        serialize_with = "int_key::serialize",
        deserialize_with = "int_key::deserialize_null_values",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub RegionScore: BTreeMap<i32, f64>,
}

/// A geographic region running one or more DERP relay nodes.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DERPRegion {
    /// Unique, non-zero region integer (900-999 reserved for user-run DERP).
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub RegionID: i32,
    /// Short code, e.g. `"nyc"`, `"sf"`, `"sin"`.
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub RegionCode: String,
    /// Long English name, e.g. `"New York City"`.
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub RegionName: String,
    /// Optional geographical latitude in degrees.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Latitude: f64,
    /// Optional geographical longitude in degrees.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Longitude: f64,
    /// Deprecated: avoid selecting this region as home.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Avoid: bool,
    /// Do not measure this region or select it as home; still usable for peers.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub NoMeasureNoHome: bool,
    /// DERP nodes in this region, in priority order. `None` serializes as
    /// `null` (matching Go's nil `[]*DERPNode`).
    #[serde(default)]
    pub Nodes: Option<Vec<DERPNode>>,
}

/// A single DERP relay node within a [`DERPRegion`].
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DERPNode {
    /// Unique node name across all regions (e.g. `"1b"`).
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub Name: String,
    /// The `RegionID` this node belongs to.
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub RegionID: i32,
    /// The node's hostname (required; need not be unique).
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub HostName: String,
    /// Optional expected TLS cert common name; empty means use `HostName`.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub CertName: String,
    /// Optional forced IPv4 address; `"none"` disables IPv4.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub IPv4: String,
    /// Optional forced IPv6 address; `"none"` disables IPv6.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub IPv6: String,
    /// STUN port; 0 means 3478, -1 disables STUN.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub STUNPort: i32,
    /// Whether this node is STUN-only (not a DERP server).
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub STUNOnly: bool,
    /// Alternate TLS port for the DERP HTTPS server; 0 means 443.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub DERPPort: i32,
    /// Tests-only: disable TLS verification.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub InsecureForTests: bool,
    /// Tests-only: override the STUN server IP.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub STUNTestIP: String,
    /// Whether this node is reachable over HTTP on port 80 (captive-portal checks).
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub CanPort80: bool,
}

impl DERPNode {
    /// Whether this node is a test node (per Go's `IsTestNode`).
    pub fn is_test_node(&self) -> bool {
        !self.STUNTestIP.is_empty() || self.IPv4 == "127.0.0.1"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derpmap_region_ids_sorted() {
        let mut regions = BTreeMap::new();
        regions.insert(
            2,
            DERPRegion {
                RegionID: 2,
                RegionCode: "sf".into(),
                RegionName: "San Francisco".into(),
                Nodes: Some(vec![]),
                ..Default::default()
            },
        );
        regions.insert(
            1,
            DERPRegion {
                RegionID: 1,
                RegionCode: "nyc".into(),
                RegionName: "New York City".into(),
                Nodes: Some(vec![DERPNode {
                    Name: "1a".into(),
                    RegionID: 1,
                    HostName: "derp1.tailscale.com".into(),
                    STUNPort: 3478,
                    ..Default::default()
                }]),
                ..Default::default()
            },
        );
        let m = DERPMap {
            Regions: regions,
            ..Default::default()
        };
        let ids: Vec<i32> = m.Regions.keys().copied().collect();
        assert_eq!(ids, vec![1, 2]);
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn derpmap_realistic_json_roundtrip() {
        // A realistic DERPMap JSON snippet (integer region keys as strings,
        // matching Go's map[int] marshaling).
        let json = r#"{
  "Regions": {
    "1": {
      "RegionID": 1,
      "RegionCode": "nyc",
      "RegionName": "New York City",
      "Latitude": 40.71,
      "Longitude": -74.01,
      "Nodes": [
        {
          "Name": "1a",
          "RegionID": 1,
          "HostName": "derp1.tailscale.com",
          "IPv4": "",
          "STUNPort": 3478,
          "DERPPort": 443
        },
        {
          "Name": "1b",
          "RegionID": 1,
          "HostName": "derp2.tailscale.com",
          "STUNOnly": true
        }
      ]
    },
    "9": {
      "RegionID": 9,
      "RegionCode": "sin",
      "RegionName": "Singapore",
      "Nodes": null
    }
  }
}"#;
        let m: DERPMap = serde_json::from_str(json).expect("parse DERPMap");
        assert_eq!(m.Regions.len(), 2);
        let nyc = &m.Regions[&1];
        assert_eq!(nyc.RegionCode, "nyc");
        assert_eq!(nyc.RegionName, "New York City");
        assert_eq!(nyc.Latitude, 40.71);
        let nodes = nyc.Nodes.as_ref().expect("nyc nodes");
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].Name, "1a");
        assert_eq!(nodes[0].HostName, "derp1.tailscale.com");
        assert_eq!(nodes[0].STUNPort, 3478);
        assert_eq!(nodes[0].DERPPort, 443);
        assert!(nodes[1].STUNOnly);
        let sin = &m.Regions[&9];
        assert_eq!(sin.RegionCode, "sin");
        assert!(sin.Nodes.is_none(), "null Nodes -> None");

        // Round-trip back through serde and re-parse to verify stability.
        let reser = serde_json::to_string(&m).unwrap();
        let back: DERPMap = serde_json::from_str(&reser).unwrap();
        assert_eq!(back.Regions.len(), 2);
        assert_eq!(back.Regions[&1].RegionCode, "nyc");
        assert_eq!(back.Regions[&9].Nodes, None);
    }

    #[test]
    fn derpmap_omits_empty_optionals() {
        let m = DERPMap::default();
        let j = serde_json::to_string(&m).unwrap();
        // Default DERPMap has empty Regions -> "{}" and omitted bools.
        assert!(j.contains("\"Regions\":{}"));
        assert!(!j.contains("OmitDefaultRegions"));
        assert!(!j.contains("HomeParams"));
    }

    #[test]
    fn derp_node_is_test_node() {
        let mut n = DERPNode {
            Name: "t".into(),
            RegionID: 1,
            HostName: "h".into(),
            ..Default::default()
        };
        assert!(!n.is_test_node());
        n.IPv4 = "127.0.0.1".into();
        assert!(n.is_test_node());
        n.IPv4 = String::new();
        n.STUNTestIP = "10.0.0.1".into();
        assert!(n.is_test_node());
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn derp_home_params_int_keyed_scores() {
        let mut scores = BTreeMap::new();
        scores.insert(1, 0.5_f64);
        let hp = DERPHomeParams {
            RegionScore: scores,
        };
        let j = serde_json::to_string(&hp).unwrap();
        assert!(j.contains("\"RegionScore\":{\"1\":0.5}"));
        let back: DERPHomeParams = serde_json::from_str(&j).unwrap();
        assert_eq!(back.RegionScore.get(&1), Some(&0.5));
    }
}
