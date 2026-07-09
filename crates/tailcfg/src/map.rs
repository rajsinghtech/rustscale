//! `MapRequest` / `MapResponse` — the control-plane long-poll protocol
//! (subset of Go's `tailcfg.go`).

use serde::{Deserialize, Serialize};

use rustscale_key::{DiscoPublic, NodePublic};

use crate::{skip_default, skip_zero_disco, CapabilityVersion, DERPMap, Node, NodeID};
use crate::deserialize_null_to_default;

/// Sent by a client to update its state and/or long-poll network-map updates.
///
/// POSTed to `https://<control>/machine/map`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct MapRequest {
    /// Client capability version (negotiates semantics with control).
    pub Version: CapabilityVersion,
    /// Compression mode: `"zstd"` or `""`.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Compress: String,
    /// Whether the server should send keep-alives back.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub KeepAlive: bool,
    /// The client's current node public key.
    pub NodeKey: NodePublic,
    /// The client's disco public key (zero if unset, then default-filled).
    #[serde(default, skip_serializing_if = "skip_zero_disco")]
    pub DiscoKey: DiscoPublic,
    /// magicsock UDP endpoints (IP:port). Ignored when `Stream` and Version>=68.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Endpoints: Vec<String>,
    /// Types of the corresponding `Endpoints`, in order.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub EndpointTypes: Vec<crate::EndpointType>,
    /// Whether the client wants streamed MapResponses over one connection.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Stream: bool,
    /// The client's current host info. `None` serializes as `null`.
    #[serde(default)]
    pub Hostinfo: Option<crate::Hostinfo>,
    /// Whether the client is okay with the peers list being omitted.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub OmitPeers: bool,
    /// Deprecated: always false as of Version 68.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub ReadOnly: bool,
    /// Debug/dev feature flags (no compatibility promise).
    #[serde(default, skip_serializing_if = "skip_default")]
    pub DebugFlags: Vec<String>,
}

/// Returned by the control server, either as a single response or as a stream
/// of delta updates (subset of Go's `tailcfg.MapResponse`).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct MapResponse {
    /// Opaque handle for a stateful map session (first message only).
    #[serde(default, skip_serializing_if = "skip_default")]
    pub MapSessionHandle: String,
    /// Sequence number within a named map session.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Seq: i64,
    /// Empty keep-alive message; other fields are ignored when true.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub KeepAlive: bool,
    /// The node making the map request; `None` means unchanged.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Node: Option<Node>,
    /// DERP servers available; `None` means unchanged.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub DERPMap: Option<DERPMap>,
    /// Complete peer list (first response); sorted by `Node.ID`.
    #[serde(default, skip_serializing_if = "skip_default", deserialize_with = "deserialize_null_to_default")]
    pub Peers: Vec<Node>,
    /// Changed/added peers since the last update; sorted by `Node.ID`.
    #[serde(default, skip_serializing_if = "skip_default", deserialize_with = "deserialize_null_to_default")]
    pub PeersChanged: Vec<Node>,
    /// Node IDs no longer in the peer list.
    #[serde(default, skip_serializing_if = "skip_default", deserialize_with = "deserialize_null_to_default")]
    pub PeersRemoved: Vec<NodeID>,
    /// The tailnet domain name; empty means unchanged.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Domain: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustscale_key::{DiscoPrivate, NodePrivate};

    #[test]
    fn map_request_roundtrip_and_keys() {
        let req = MapRequest {
            Version: 999,
            Compress: "zstd".into(),
            KeepAlive: true,
            NodeKey: NodePrivate::generate().public(),
            DiscoKey: DiscoPrivate::generate().public(),
            Endpoints: vec!["1.2.3.4:5".into()],
            EndpointTypes: vec![crate::EndpointType::STUN],
            Stream: true,
            Hostinfo: None,
            OmitPeers: false,
            ReadOnly: false,
            DebugFlags: vec![],
        };
        let j = serde_json::to_string(&req).unwrap();
        assert!(j.contains("\"NodeKey\":\"nodekey:"));
        assert!(j.contains("\"DiscoKey\":\"discokey:"));
        assert!(j.contains("\"Version\":999"));
        assert!(j.contains("\"Compress\":\"zstd\""));
        let back: MapRequest = serde_json::from_str(&j).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn map_request_omits_zero_disco() {
        let req = MapRequest {
            Version: 1,
            NodeKey: NodePrivate::generate().public(),
            ..Default::default()
        };
        let j = serde_json::to_string(&req).unwrap();
        assert!(!j.contains("\"DiscoKey\""), "zero disco omitted");
    }

    #[test]
    fn map_response_roundtrip() {
        let resp = MapResponse {
            KeepAlive: true,
            Domain: "example.com".into(),
            PeersRemoved: vec![3, 7],
            DERPMap: Some(DERPMap::default()),
            ..Default::default()
        };
        let j = serde_json::to_string(&resp).unwrap();
        assert!(j.contains("\"KeepAlive\":true"));
        assert!(j.contains("\"Domain\":\"example.com\""));
        assert!(j.contains("\"PeersRemoved\":[3,7]"));
        let back: MapResponse = serde_json::from_str(&j).unwrap();
        assert_eq!(back, resp);
    }

    #[test]
    fn map_response_empty_serializes_minimal() {
        let resp = MapResponse::default();
        let j = serde_json::to_string(&resp).unwrap();
        assert_eq!(j, "{}", "all-default MapResponse is empty JSON object");
    }
}
