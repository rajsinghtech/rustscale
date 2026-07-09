//! Node, Hostinfo, NetInfo and related types, ported from Go's `tailcfg.go`.

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use rustscale_key::{DiscoPublic, MachinePublic, NodePublic};

use crate::{
    skip_default, skip_zero_disco, skip_zero_machine, CapabilityVersion, NodeCapability, NodeID,
    OptBool, RawMessage, StableNodeID, UserID,
};

/// A Tailscale device in a tailnet (subset of Go's `tailcfg.Node`).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Node {
    /// Numeric node ID (global within a control plane URL).
    pub ID: NodeID,
    /// Stable, string-form node ID.
    pub StableID: StableNodeID,
    /// FQDN of the node, with trailing dot (MagicDNS name).
    pub Name: String,
    /// The user who created the node.
    pub User: UserID,
    /// The node's WireGuard public key.
    pub Key: NodePublic,
    /// When the node key expires; `None` if it does not expire.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub KeyExpiry: Option<DateTime<Utc>>,
    /// The node's machine key (zero if unset, then omitted).
    #[serde(default, skip_serializing_if = "skip_zero_machine")]
    pub Machine: MachinePublic,
    /// The node's disco public key (zero if unset, then omitted).
    #[serde(default, skip_serializing_if = "skip_zero_disco")]
    pub DiscoKey: DiscoPublic,
    /// Tailscale IP prefixes of this node (e.g. `"100.64.0.1/32"`).
    pub Addresses: Vec<String>,
    /// IP ranges to route to this node. Nil is special (means "same as
    /// Addresses"); an empty non-nil vec means "none".
    #[serde(default, skip_serializing_if = "skip_default")]
    pub AllowedIPs: Vec<String>,
    /// Public UDP endpoints (IP:port) discovered via STUN / LANs.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Endpoints: Vec<String>,
    /// DERP region ID of the node's home DERP; 0 if unknown.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub HomeDERP: i32,
    /// Host information block.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Hostinfo: Option<Hostinfo>,
    /// When the node was created.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Created: Option<DateTime<Utc>>,
    /// Capability version of the node, if non-zero.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Cap: CapabilityVersion,
    /// ACL tags applied to the node (e.g. `tag:prod`).
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Tags: Vec<String>,
    /// Whether the node is currently connected to control; `None` = unknown.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Online: Option<bool>,
    /// Deprecated free-form capability URLs.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Capabilities: Vec<NodeCapability>,
    /// Map of capabilities to optional argument/data values.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub CapMap: NodeCapMap,
}

/// `Node.CapMap` — capabilities to optional `RawMessage` argument lists.
pub type NodeCapMap = BTreeMap<NodeCapability, Vec<RawMessage>>;

/// Host information advertised by a node (subset of Go's `tailcfg.Hostinfo`).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Hostinfo {
    /// Version of this code (in `version.Long` format).
    #[serde(default, skip_serializing_if = "skip_default")]
    pub IPNVersion: String,
    /// Logtail ID of the frontend instance.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub FrontendLogID: String,
    /// Logtail ID of the backend instance.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub BackendLogID: String,
    /// Operating system the client runs on.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub OS: String,
    /// OS version string.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub OSVersion: String,
    /// Name of the host the client runs on.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Hostname: String,
    /// Services advertised by this machine.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Services: Vec<Service>,
}

/// A service running on a node (matches Go's `tailcfg.Service`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Service {
    /// Service protocol (`"tcp"`, `"udp"`, or a meta service like `"peerapi4"`).
    pub Proto: ServiceProto,
    /// Port number.
    pub Port: u16,
    /// Textual description, usually the process name.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Description: String,
}

/// A service protocol string (`"tcp"`, `"udp"`, `"peerapi4"`, ...).
pub type ServiceProto = String;

/// Information about the host's network state (matches Go's `tailcfg.NetInfo`).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct NetInfo {
    /// Whether NAT mappings vary by destination IP.
    #[serde(default, skip_serializing_if = "OptBool::is_unset")]
    pub MappingVariesByDestIP: OptBool,
    /// Whether the host has IPv6 internet connectivity.
    #[serde(default, skip_serializing_if = "OptBool::is_unset")]
    pub WorkingIPv6: OptBool,
    /// Whether the OS supports IPv6 at all.
    #[serde(default, skip_serializing_if = "OptBool::is_unset")]
    pub OSHasIPv6: OptBool,
    /// Whether the host has UDP internet connectivity.
    #[serde(default, skip_serializing_if = "OptBool::is_unset")]
    pub WorkingUDP: OptBool,
    /// Whether ICMPv4 works (empty = not checked).
    #[serde(default, skip_serializing_if = "OptBool::is_unset")]
    pub WorkingICMPv4: OptBool,
    /// Whether an existing portmap (UPnP/PMP/PCP) is open.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub HavePortMap: bool,
    /// Whether UPnP appears present on the LAN.
    #[serde(default, skip_serializing_if = "OptBool::is_unset")]
    pub UPnP: OptBool,
    /// Whether NAT-PMP appears present on the LAN.
    #[serde(default, skip_serializing_if = "OptBool::is_unset")]
    pub PMP: OptBool,
    /// Whether PCP appears present on the LAN.
    #[serde(default, skip_serializing_if = "OptBool::is_unset")]
    pub PCP: OptBool,
    /// Preferred (home) DERP region ID; 0 = disconnected/unknown.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub PreferredDERP: i32,
    /// Current link type: `"wired"`, `"wifi"`, `"mobile"`.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub LinkType: String,
    /// Fastest recent latencies to DERP STUN servers, in seconds, keyed by
    /// `"regionID-v4"` / `"-v6"`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub DERPLatency: BTreeMap<String, f64>,
    /// Linux-specific firewall-mode selector + reason (e.g. `"nft-forced"`).
    #[serde(default, skip_serializing_if = "skip_default")]
    pub FirewallMode: String,
}

/// Optional geographical location data about a host (subset).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Location {
    /// User-friendly country name (`"Canada"`).
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Country: String,
    /// ISO 3166-1 alpha-2 country code, upper case (`"CA"`).
    #[serde(default, skip_serializing_if = "skip_default")]
    pub CountryCode: String,
}

/// Distinguishes sources of endpoint values (matches Go's `tailcfg.EndpointType`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EndpointType(pub i32);

impl EndpointType {
    pub const UNKNOWN: Self = Self(0);
    pub const LOCAL: Self = Self(1);
    pub const STUN: Self = Self(2);
    pub const PORTMAPPED: Self = Self(3);
    pub const STUN4_LOCAL_PORT: Self = Self(4);
    pub const EXPLICIT_CONF: Self = Self(5);
}

impl fmt::Display for EndpointType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            Self::UNKNOWN => "?",
            Self::LOCAL => "local",
            Self::STUN => "stun",
            Self::PORTMAPPED => "portmap",
            Self::STUN4_LOCAL_PORT => "stun4localport",
            Self::EXPLICIT_CONF => "explicitconf",
            _ => "other",
        };
        f.write_str(s)
    }
}

/// An endpoint IPPort and its associated type (matches Go's `tailcfg.Endpoint`).
///
/// This does not go over the wire as-is in the current protocol; it is broken
/// into parallel slices in [`crate::MapRequest`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    /// IP:port endpoint (a `netip.AddrPort` string).
    pub Addr: String,
    /// How the endpoint was discovered.
    pub Type: EndpointType,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustscale_key::{DiscoPrivate, MachinePrivate, NodePrivate};

    fn sample_node() -> Node {
        let np = NodePrivate::generate().public();
        let mp = MachinePrivate::generate().public();
        let dp = DiscoPrivate::generate().public();
        Node {
            ID: 42,
            StableID: "nodeABC".into(),
            Name: "host.tail-scale.ts.net.".into(),
            User: 7,
            Key: np,
            KeyExpiry: Some(
                DateTime::parse_from_rfc3339("2025-12-31T23:59:59Z")
                    .unwrap()
                    .with_timezone(&Utc),
            ),
            Machine: mp,
            DiscoKey: dp,
            Addresses: vec!["100.64.0.1/32".into(), "fd7a:115c::1/128".into()],
            AllowedIPs: vec!["100.64.0.1/32".into()],
            Endpoints: vec!["1.2.3.4:5".into()],
            HomeDERP: 1,
            Hostinfo: Some(Hostinfo {
                OS: "linux".into(),
                Hostname: "host".into(),
                IPNVersion: "1.99.0".into(),
                Services: vec![Service {
                    Proto: "peerapi4".into(),
                    Port: 1234,
                    ..Default::default()
                }],
                ..Default::default()
            }),
            Created: Some(
                DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
            ),
            Cap: 999,
            Tags: vec!["tag:prod".into()],
            Online: Some(true),
            Capabilities: vec!["https://tailscale.com/cap/file-sharing".into()],
            CapMap: BTreeMap::new(),
        }
    }

    #[test]
    fn node_serde_roundtrip() {
        let n = sample_node();
        let j = serde_json::to_string(&n).unwrap();
        let back: Node = serde_json::from_str(&j).unwrap();
        assert_eq!(back, n);
    }

    #[test]
    fn node_key_serializes_as_nodekey_string() {
        let n = sample_node();
        let j = serde_json::to_string(&n).unwrap();
        assert!(j.contains("\"Key\":\"nodekey:"));
        assert!(j.contains("\"Machine\":\"mkey:"));
        assert!(j.contains("\"DiscoKey\":\"discokey:"));
    }

    #[test]
    fn node_omits_zero_machine_and_disco() {
        let mut n = sample_node();
        n.Machine = MachinePublic::default();
        n.DiscoKey = DiscoPublic::default();
        let j = serde_json::to_string(&n).unwrap();
        assert!(!j.contains("\"Machine\""));
        assert!(!j.contains("\"DiscoKey\""));
        // Parse back: zero keys are filled in via default.
        let back: Node = serde_json::from_str(&j).unwrap();
        assert!(back.Machine.is_zero());
        assert!(back.DiscoKey.is_zero());
    }

    #[test]
    fn node_online_tri_state() {
        let mut n = sample_node();
        n.Online = None;
        let j = serde_json::to_string(&n).unwrap();
        assert!(!j.contains("\"Online\""), "None Online is omitted");
        n.Online = Some(false);
        let j = serde_json::to_string(&n).unwrap();
        assert!(j.contains("\"Online\":false"));
    }

    #[test]
    fn netinfo_opt_bool_fields() {
        let ni = NetInfo {
            WorkingUDP: OptBool::True,
            WorkingIPv6: OptBool::False,
            PreferredDERP: 3,
            ..Default::default()
        };
        let j = serde_json::to_string(&ni).unwrap();
        assert!(j.contains("\"WorkingUDP\":true"));
        assert!(j.contains("\"WorkingIPv6\":false"));
        assert!(!j.contains("\"WorkingICMPv4\""), "unset OptBool omitted");
        assert!(j.contains("\"PreferredDERP\":3"));
        let back: NetInfo = serde_json::from_str(&j).unwrap();
        assert_eq!(back, ni);
    }

    #[test]
    fn endpoint_type_display_and_serde() {
        assert_eq!(EndpointType::STUN.to_string(), "stun");
        assert_eq!(serde_json::to_string(&EndpointType::LOCAL).unwrap(), "1");
        let back: EndpointType = serde_json::from_str("2").unwrap();
        assert_eq!(back, EndpointType::STUN);
    }

    #[test]
    fn hostinfo_minimal_omits_empty() {
        let hi = Hostinfo {
            OS: "darwin".into(),
            ..Default::default()
        };
        let j = serde_json::to_string(&hi).unwrap();
        assert!(j.contains("\"OS\":\"darwin\""));
        assert!(!j.contains("\"Hostname\""));
        assert!(!j.contains("\"Services\""));
    }
}
