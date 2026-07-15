//! `MapRequest` / `MapResponse` — the control-plane long-poll protocol
//! (subset of Go's `tailcfg.go`).

use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;

use rustscale_key::{DiscoPublic, NodePublic};

use crate::deserialize_null_to_default;
use crate::{
    skip_default, CapabilityVersion, DERPMap, DNSConfig, FilterRule, NetInfo, Node, NodeCapMap,
    NodeID, StableNodeID, UserProfile,
};

/// Sent by a client to update its state and/or long-poll network-map updates.
///
/// POSTed to `https://<control>/machine/map`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct MapRequest {
    /// Client capability version (negotiates semantics with control).
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub Version: CapabilityVersion,
    /// Compression mode: `"zstd"` or `""`.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Compress: String,
    /// Whether the server should send keep-alives back.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub KeepAlive: bool,
    /// The client's current node public key.
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub NodeKey: NodePublic,
    /// The client's disco public key. Go has no json tag (always present,
    /// even when zero — emits `discokey:0000...0000`).
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub DiscoKey: DiscoPublic,
    /// magicsock UDP endpoints (IP:port). Ignored when `Stream` and Version>=68.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Endpoints: Vec<String>,
    /// Types of the corresponding `Endpoints`, in order.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub EndpointTypes: Vec<crate::EndpointType>,
    /// Whether the client wants streamed MapResponses over one connection.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Stream: bool,
    /// The client's current host info. `None` serializes as `null`.
    #[serde(default)]
    pub Hostinfo: Option<crate::Hostinfo>,
    /// Whether the client is okay with the peers list being omitted.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub OmitPeers: bool,
    /// Deprecated: always false as of Version 68.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub ReadOnly: bool,
    /// Debug/dev feature flags (no compatibility promise).
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub DebugFlags: Vec<String>,
    /// Opaque handle to reattach to a previous map session after an
    /// interruption. When set, `MapSessionSeq` must also be set. The server
    /// may ignore this and start a new session. Only applicable when `Stream`
    /// is true.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub MapSessionHandle: String,
    /// The last-processed sequence number in the session identified by
    /// `MapSessionHandle`. Only applicable when `MapSessionHandle` is set;
    /// the server will return only seq numbers greater than this.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub MapSessionSeq: i64,
    /// Local Tailnet Lock authority head, if enabled.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub TKAHead: String,
}

/// A control-plane ping request, including C2N HTTP callbacks.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PingRequest {
    #[serde(default, skip_serializing_if = "skip_default")]
    pub URL: String,
    #[serde(default, skip_serializing_if = "skip_default")]
    pub URLIsNoise: bool,
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Log: bool,
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Types: String,
    #[serde(default, skip_serializing_if = "skip_default")]
    pub IP: String,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "crate::base64_vec"
    )]
    pub Payload: Vec<u8>,
}

/// Returned by the control server, either as a single response or as a stream
/// of delta updates (subset of Go's `tailcfg.MapResponse`).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct MapResponse {
    /// Opaque handle for a stateful map session (first message only).
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub MapSessionHandle: String,
    /// Sequence number within a named map session.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Seq: i64,
    /// Empty keep-alive message; other fields are ignored when true.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub KeepAlive: bool,
    /// The node making the map request; `None` means unchanged.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Node: Option<Node>,
    /// DERP servers available; `None` means unchanged.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub DERPMap: Option<DERPMap>,
    /// Complete peer list (first response); sorted by `Node.ID`.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Peers: Vec<Node>,
    /// Changed/added peers since the last update; sorted by `Node.ID`.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub PeersChanged: Vec<Node>,
    /// Node IDs no longer in the peer list.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub PeersRemoved: Vec<NodeID>,
    /// The tailnet domain name; empty means unchanged.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Domain: String,
    /// DNS settings for the client. `None` means unchanged from a prior
    /// non-nil value. Carries MagicDNS config (`Proxied`), search domains,
    /// upstream resolvers, and `CertDomains` (non-empty ⇒ HTTPS enabled).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub DNSConfig: Option<DNSConfig>,
    /// New/updated user profiles of nodes in the network (mapver ≥5).
    /// Keyed by `UserProfile.ID` to match `Node.User`.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub UserProfiles: Vec<UserProfile>,
    /// Firewall rules. `None` = unchanged (field absent); `Some([])` = block
    /// all; `Some([…])` = full replacement of the "base" key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub PacketFilter: Option<Vec<FilterRule>>,
    /// Incremental named packet-filter updates. `None` = unchanged. Key `"*"`
    /// with `None` value = clear all named filters. Other key with `None`/
    /// empty = delete; `Some(vec)` = set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub PacketFilters: Option<BTreeMap<String, Option<Vec<FilterRule>>>>,
    /// Whether the client's node key has expired. When true, the client
    /// should transition to a "NeedsLogin" state; when false (un-expire),
    /// it should recover. Matches Go's `MapResponse.NodeKeyExpired`.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub NodeKeyExpired: bool,
    /// Control-to-node ping or C2N callback request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub PingRequest: Option<PingRequest>,
    /// ControlTime from the server (usually only in the first map response).
    #[serde(default, skip_serializing_if = "skip_default")]
    pub ControlTime: Option<chrono::DateTime<chrono::Utc>>,
    /// Whether the server wants the client to collect and report services.
    #[serde(default, skip_serializing_if = "crate::OptBool::is_unset")]
    pub CollectServices: crate::OptBool,
    /// SSH policy for incoming SSH connections. `None` = unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub SSHPolicy: Option<crate::SSHPolicy>,
    /// Incremental peer updates (lighter than `PeersChanged`). Applied after
    /// `Peers`/`PeersChanged`/`PeersRemoved`. In practice the server sends
    /// these on their own, without the full peer fields also set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub PeersChangedPatch: Option<Vec<PeerChange>>,
    /// Network probe results pushed from control to the client. `None` means
    /// unchanged. When present, wired to magicsock for endpoint/DERP tracking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub NetInfo: Option<NetInfo>,
    /// Latest client version info from control. `None` means no change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ClientVersion: Option<ClientVersion>,
    /// Control-suggested exit node (`StableNodeID`). Empty means no
    /// suggestion. Mirrors Go's `MapResponse.SuggestedExitNode`.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub SuggestedExitNode: StableNodeID,
    /// Control's Tailnet Lock state. `None` in a delta means unchanged; on
    /// the initial map it means disabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub TKAInfo: Option<crate::TKAInfo>,
}

/// Incremental update to a single peer (mirrors Go's `tailcfg.PeerChange`).
/// Only fields that are `Some` / non-default are applied; the rest are left
/// unchanged on the existing peer identified by `NodeID`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct PeerChange {
    /// The node ID being mutated.
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub NodeID: NodeID,
    /// New home DERP region ID; 0 means unchanged.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub DERPRegion: i32,
    /// New capability version; 0 means unchanged.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Cap: CapabilityVersion,
    /// New capability map; empty means unchanged.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "crate::node::deserialize_capmap"
    )]
    pub CapMap: NodeCapMap,
    /// New UDP endpoints; empty means unchanged.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Endpoints: Vec<String>,
    /// New WireGuard public key; `None` means unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub Key: Option<NodePublic>,
    /// New signature over the WireGuard public key; `None` means unchanged.
    /// Go marshals `[]byte` as base64.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "crate::base64_bytes"
    )]
    pub KeySignature: Option<Vec<u8>>,
    /// New disco key; `None` means unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub DiscoKey: Option<DiscoPublic>,
    /// New online status; `None` means unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub Online: Option<bool>,
    /// New last-seen timestamp; `None` means unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub LastSeen: Option<chrono::DateTime<chrono::Utc>>,
    /// New key expiry; `None` means unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub KeyExpiry: Option<chrono::DateTime<chrono::Utc>>,
}

/// Latest client version information from control (mirrors Go's
/// `tailcfg.ClientVersion`).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ClientVersion {
    /// Whether the client is running the latest build.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub RunningLatest: bool,
    /// Latest version.Short available for the client's platform. Not
    /// populated if `RunningLatest` is true.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub LatestVersion: String,
    /// Whether the client is missing an important security update.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub UrgentSecurityUpdate: bool,
    /// Whether the client should OS-notify about a new version. Not populated
    /// if `RunningLatest` is true.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Notify: bool,
    /// URL to open when the user clicks the notification.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub NotifyURL: String,
    /// Text to show in the notification.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub NotifyText: String,
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
            MapSessionHandle: String::new(),
            MapSessionSeq: 0,
            TKAHead: String::new(),
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
    fn map_request_emits_zero_disco() {
        let req = MapRequest {
            Version: 1,
            NodeKey: NodePrivate::generate().public(),
            ..Default::default()
        };
        let j = serde_json::to_string(&req).unwrap();
        assert!(
            j.contains("\"DiscoKey\":\"discokey:"),
            "zero DiscoKey is always emitted (matches Go)"
        );
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

    #[test]
    fn peer_change_roundtrip() {
        let pc = PeerChange {
            NodeID: 42,
            DERPRegion: 7,
            Online: Some(false),
            Endpoints: vec!["1.2.3.4:5".into()],
            Key: Some(NodePrivate::generate().public()),
            DiscoKey: Some(DiscoPrivate::generate().public()),
            LastSeen: Some(
                chrono::DateTime::parse_from_rfc3339("2025-07-12T10:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
            ..Default::default()
        };
        let j = serde_json::to_string(&pc).unwrap();
        assert!(j.contains("\"NodeID\":42"));
        assert!(j.contains("\"DERPRegion\":7"));
        assert!(j.contains("\"Online\":false"));
        assert!(j.contains("\"Endpoints\""));
        let back: PeerChange = serde_json::from_str(&j).unwrap();
        assert_eq!(back, pc);
    }

    #[test]
    fn peer_change_default_omits_optionals() {
        let pc = PeerChange {
            NodeID: 1,
            ..Default::default()
        };
        let j = serde_json::to_string(&pc).unwrap();
        assert!(j.contains("\"NodeID\":1"));
        assert!(!j.contains("\"Key\""), "None Key omitted");
        assert!(!j.contains("\"DiscoKey\""), "None DiscoKey omitted");
        assert!(!j.contains("\"Online\""), "None Online omitted");
        assert!(!j.contains("\"LastSeen\""), "None LastSeen omitted");
        assert!(!j.contains("\"DERPRegion\""), "zero DERPRegion omitted");
    }

    #[test]
    fn client_version_roundtrip() {
        let cv = ClientVersion {
            RunningLatest: false,
            LatestVersion: "1.99.0".into(),
            UrgentSecurityUpdate: true,
            Notify: true,
            NotifyURL: "https://tailscale.com/download".into(),
            NotifyText: "Update available".into(),
        };
        let j = serde_json::to_string(&cv).unwrap();
        assert!(j.contains("\"LatestVersion\":\"1.99.0\""));
        assert!(j.contains("\"UrgentSecurityUpdate\":true"));
        assert!(j.contains("\"Notify\":true"));
        let back: ClientVersion = serde_json::from_str(&j).unwrap();
        assert_eq!(back, cv);
    }

    #[test]
    fn map_response_with_peers_changed_patch() {
        let resp = MapResponse {
            PeersChangedPatch: Some(vec![
                PeerChange {
                    NodeID: 10,
                    DERPRegion: 5,
                    ..Default::default()
                },
                PeerChange {
                    NodeID: 20,
                    Online: Some(false),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        };
        let j = serde_json::to_string(&resp).unwrap();
        assert!(j.contains("\"PeersChangedPatch\""));
        assert!(j.contains("\"NodeID\":10"));
        assert!(j.contains("\"DERPRegion\":5"));
        assert!(j.contains("\"NodeID\":20"));
        assert!(j.contains("\"Online\":false"));
        let back: MapResponse = serde_json::from_str(&j).unwrap();
        assert_eq!(back, resp);
    }

    #[test]
    fn map_response_with_client_version() {
        let resp = MapResponse {
            ClientVersion: Some(ClientVersion {
                RunningLatest: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let j = serde_json::to_string(&resp).unwrap();
        assert!(j.contains("\"ClientVersion\""));
        assert!(j.contains("\"RunningLatest\":true"));
        let back: MapResponse = serde_json::from_str(&j).unwrap();
        assert_eq!(back, resp);
    }

    #[test]
    fn c2n_ping_request_payload_uses_go_base64_format() {
        let response = MapResponse {
            PingRequest: Some(PingRequest {
                URL: "https://control.example/c2n/1".into(),
                Types: "c2n".into(),
                Payload: b"GET /echo HTTP/1.1\r\n\r\n".to_vec(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"Payload\":\"R0VUIC9lY2hvIEhUVFAvMS4xDQoNCg==\""));
        assert_eq!(
            serde_json::from_str::<MapResponse>(&json).unwrap(),
            response
        );
    }

    #[test]
    fn map_request_with_session_handle() {
        let req = MapRequest {
            Version: 100,
            NodeKey: NodePrivate::generate().public(),
            Stream: true,
            MapSessionHandle: "session-xyz".into(),
            MapSessionSeq: 42,
            ..Default::default()
        };
        let j = serde_json::to_string(&req).unwrap();
        assert!(j.contains("\"MapSessionHandle\":\"session-xyz\""));
        assert!(j.contains("\"MapSessionSeq\":42"));
        let back: MapRequest = serde_json::from_str(&j).unwrap();
        assert_eq!(back, req);
    }
}
