//! Node, Hostinfo, NetInfo and related types, ported from Go's `tailcfg.go`.

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use rustscale_key::{DiscoPublic, MachinePublic, NodePublic};

use crate::{
    deserialize_null_map_values, deserialize_null_to_default, skip_default, skip_zero_disco,
    skip_zero_machine, CapabilityVersion, NodeCapability, NodeID, OptBool, RawMessage,
    StableNodeID, UserID,
};

/// Deserialize a `NodeCapMap`, treating `null` values inside the map as empty
/// vectors (Go's nil slices marshal as `null`).
fn deserialize_capmap<'de, D>(deserializer: D) -> Result<NodeCapMap, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt: Option<BTreeMap<String, Option<Vec<RawMessage>>>> = Option::deserialize(deserializer)?;
    match opt {
        None => Ok(NodeCapMap::new()),
        Some(raw) => {
            let mut map = NodeCapMap::new();
            for (k, v) in raw {
                map.insert(k, v.unwrap_or_default());
            }
            Ok(map)
        }
    }
}

/// A Tailscale device in a tailnet (subset of Go's `tailcfg.Node`).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Node {
    /// Numeric node ID (global within a control plane URL).
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub ID: NodeID,
    /// Stable, string-form node ID.
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub StableID: StableNodeID,
    /// FQDN of the node, with trailing dot (MagicDNS name).
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub Name: String,
    /// The user who created the node.
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub User: UserID,
    /// The node's WireGuard public key.
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub Key: NodePublic,
    /// When the node key expires; `None` if it does not expire.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub KeyExpiry: Option<DateTime<Utc>>,
    /// The node's machine key (zero if unset, then omitted).
    #[serde(
        default,
        skip_serializing_if = "skip_zero_machine",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Machine: MachinePublic,
    /// The node's disco public key (zero if unset, then omitted).
    #[serde(
        default,
        skip_serializing_if = "skip_zero_disco",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub DiscoKey: DiscoPublic,
    /// Tailscale IP prefixes of this node (e.g. `"100.64.0.1/32"`).
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub Addresses: Vec<String>,
    /// IP ranges to route to this node. Nil is special (means "same as
    /// Addresses"); an empty non-nil vec means "none".
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub AllowedIPs: Vec<String>,
    /// Primary subnet routes this node advertises (subset of `AllowedIPs`
    /// that the node is the primary/sole handler for). Mirrors Go's
    /// `Node.PrimaryRoutes`.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub PrimaryRoutes: Vec<String>,
    /// Public UDP endpoints (IP:port) discovered via STUN / LANs.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Endpoints: Vec<String>,
    /// DERP region ID of the node's home DERP; 0 if unknown.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub HomeDERP: i32,
    /// Host information block.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Hostinfo: Option<Hostinfo>,
    /// When the node was created.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Created: Option<DateTime<Utc>>,
    /// Capability version of the node, if non-zero.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Cap: CapabilityVersion,
    /// ACL tags applied to the node (e.g. `tag:prod`).
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Tags: Vec<String>,
    /// Whether the node is currently connected to control; `None` = unknown.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Online: Option<bool>,
    /// Deprecated free-form capability URLs.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Capabilities: Vec<NodeCapability>,
    /// Map of capabilities to optional argument/data values. Values may be
    /// `null` on the wire (Go nil slices); we treat null as empty.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_capmap"
    )]
    pub CapMap: NodeCapMap,
}

/// `Node.CapMap` — capabilities to optional `RawMessage` argument lists.
/// Values may be `null` on the wire (Go nil slices); we treat null as empty.
pub type NodeCapMap = BTreeMap<NodeCapability, Vec<RawMessage>>;

/// Host information advertised by a node (mirrors Go's `tailcfg.Hostinfo`).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Hostinfo {
    /// Version of this code (in `version.Long` format).
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub IPNVersion: String,
    /// Logtail ID of the frontend instance.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub FrontendLogID: String,
    /// Logtail ID of the backend instance.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub BackendLogID: String,
    /// Operating system the client runs on.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub OS: String,
    /// OS version string (kernel version on Linux, marketing version on
    /// macOS/iOS, build number on Windows).
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub OSVersion: String,
    /// Best-effort whether the client is running in a container.
    #[serde(default, skip_serializing_if = "OptBool::is_unset")]
    pub Container: OptBool,
    /// A hostinfo `EnvType` in string form (`"kn"`, `"k8s"`, ...).
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Env: String,
    /// Linux distro id (`"debian"`, `"ubuntu"`, `"nixos"`, ...).
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Distro: String,
    /// Linux distro version (`"20.04"`, ...).
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub DistroVersion: String,
    /// Linux distro codename (`"jammy"`, `"bullseye"`, ...).
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub DistroCodeName: String,
    /// App identifier for tsnet-based clients (`"tsnet"`, `"golinks"`, ...).
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub App: String,
    /// Whether a desktop was detected on Linux.
    #[serde(default, skip_serializing_if = "OptBool::is_unset")]
    pub Desktop: OptBool,
    /// Tailscale package type (`"tsnet"`, `"snap"`, ...).
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Package: String,
    /// Device model (mobile phone model, Raspberry Pi, Synology, ...).
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub DeviceModel: String,
    /// macOS/iOS APNs device token for notifications (and Android in the
    /// future). Mirrors Go's `Hostinfo.PushDeviceToken`.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub PushDeviceToken: String,
    /// Name of the host the client runs on.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Hostname: String,
    /// Whether the host is blocking incoming connections.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub ShieldsUp: bool,
    /// Indicates this node exists in netmap because it's owned by a
    /// shared-to user. Mirrors Go's `Hostinfo.ShareeNode`.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub ShareeNode: bool,
    /// Whether the node opted out of sending logs and support.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub NoLogsNoSupport: bool,
    /// The node would like to be wired up server-side (DNS, etc) for Funnel,
    /// even if not currently enabled. Only sent when `IngressEnabled` is
    /// false. Mirrors Go's `Hostinfo.WireIngress`.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub WireIngress: bool,
    /// Whether the node has any funnel endpoint enabled.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub IngressEnabled: bool,
    /// Whether the node has opted-in to admin-console-driven remote updates.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub AllowsUpdate: bool,
    /// The current host's machine type (uname -m).
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Machine: String,
    /// Architecture of the built binary (Go's GOARCH equivalent).
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub GoArch: String,
    /// Architecture variant (GOARM, GOAMD64, ...).
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub GoArchVar: String,
    /// Go compiler version the binary was built with (or Rust toolchain).
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub GoVersion: String,
    /// Services advertised by this machine.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Services: Vec<Service>,
    /// IP prefixes this node can route (advertised subnet routes), e.g.
    /// `"192.0.2.0/24"`. Control must approve them before peers see them in
    /// this node's `AllowedIPs`. Mirrors Go's `Hostinfo.RoutableIPs`.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub RoutableIPs: Vec<String>,
    /// ACL tags this node wants to claim.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub RequestTags: Vec<String>,
    /// MAC address(es) to send Wake-on-LAN packets to wake this node
    /// (lowercase hex with colons). Mirrors Go's `Hostinfo.WoLMACs`.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub WoLMACs: Vec<String>,
    /// SSH host keys advertised by this node.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default",
        rename = "sshHostKeys"
    )]
    pub SSH_HostKeys: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub NetInfo: Option<NetInfo>,
    /// Cloud environment (`"aws"`, `"gcp"`, `"azure"`, `"digitalocean"`, ...).
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Cloud: String,
    /// Whether the client is running in userspace (netstack) mode.
    #[serde(default, skip_serializing_if = "OptBool::is_unset")]
    pub Userspace: OptBool,
    /// Whether the client's subnet router is running in userspace mode.
    #[serde(default, skip_serializing_if = "OptBool::is_unset")]
    pub UserspaceRouter: OptBool,
    /// Whether the client is running the app-connector service.
    #[serde(default, skip_serializing_if = "OptBool::is_unset")]
    pub AppConnector: OptBool,
    /// Whether the client is willing to relay traffic for other peers.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub PeerRelay: bool,
    /// Opaque hash of the most recent list of tailnet services. A change in
    /// hash signals config should be fetched via c2n. Mirrors Go's
    /// `Hostinfo.ServicesHash`.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub ServicesHash: String,
    /// The client's selected exit node StableNodeID; empty when unselected.
    /// Mirrors Go's `Hostinfo.ExitNodeID`.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub ExitNodeID: StableNodeID,
    /// Geographical location data about a host. Optional — only set if
    /// explicitly declared by a node. Mirrors Go's `Hostinfo.Location`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub Location: Option<Location>,
    /// TPM 2.0 device metadata, if available. Mirrors Go's
    /// `Hostinfo.TPM`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub TPM: Option<TPMInfo>,
    /// Whether the node state is stored encrypted on disk. The mechanism is
    /// platform-specific (Keychain on Apple, TPM on Linux/Windows,
    /// EncryptedSharedPreferences on Android). Mirrors Go's
    /// `Hostinfo.StateEncrypted`.
    #[serde(default, skip_serializing_if = "OptBool::is_unset")]
    pub StateEncrypted: OptBool,
}

/// A service running on a node (matches Go's `tailcfg.Service`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Service {
    /// Service protocol (`"tcp"`, `"udp"`, or a meta service like `"peerapi4"`).
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub Proto: ServiceProto,
    /// Port number.
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub Port: u16,
    /// Textual description, usually the process name.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
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
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
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
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub PreferredDERP: i32,
    /// Current link type: `"wired"`, `"wifi"`, `"mobile"`.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub LinkType: String,
    /// Fastest recent latencies to DERP STUN servers, in seconds, keyed by
    /// `"regionID-v4"` / `"-v6"`.
    #[serde(
        default,
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "deserialize_null_map_values"
    )]
    pub DERPLatency: BTreeMap<String, f64>,
    /// Linux-specific firewall-mode selector + reason (e.g. `"nft-forced"`).
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub FirewallMode: String,
}

/// Optional geographical location data about a host (subset).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Location {
    /// User-friendly country name (`"Canada"`).
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Country: String,
    /// ISO 3166-1 alpha-2 country code, upper case (`"CA"`).
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub CountryCode: String,
}

/// TPM 2.0 device metadata (mirrors Go's `tailcfg.TPMInfo`).
///
/// All fields are read from `TPM_CAP_TPM_PROPERTIES`; see Part 2, section 6.13
/// of the TPM 2.0 library specification.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TPMInfo {
    /// 4-letter manufacturer code from the TCG vendor-ID registry
    /// (e.g. `"MSFT"`). Read from `TPM_PT_MANUFACTURER`.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Manufacturer: String,
    /// Vendor ID string, up to 16 characters. Read from
    /// `TPM_PT_VENDOR_STRING_*`.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Vendor: String,
    /// Vendor-defined TPM model. Read from `TPM_PT_VENDOR_TPM_TYPE`.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Model: i32,
    /// Firmware version number. Read from `TPM_PT_FIRMWARE_VERSION_*`.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub FirmwareVersion: u64,
    /// TPM 2.0 spec revision encoded as a single number. Read from
    /// `TPM_PT_REVISION`.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub SpecRevision: i32,
    /// TPM spec family, like `"2.0"`. Read from `TPM_PT_FAMILY_INDICATOR`.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub FamilyIndicator: String,
}

impl TPMInfo {
    /// Whether a TPM device is present (non-default).
    pub fn is_present(&self) -> bool {
        *self != Self::default()
    }
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
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub Addr: String,
    /// How the endpoint was discovered.
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
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
            PrimaryRoutes: vec![],
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

    #[test]
    fn hostinfo_new_fields_roundtrip() {
        let hi = Hostinfo {
            PushDeviceToken: "abc123".into(),
            ShareeNode: true,
            WireIngress: true,
            IngressEnabled: true,
            WoLMACs: vec!["aa:bb:cc:dd:ee:ff".into()],
            ServicesHash: "deadbeef".into(),
            ExitNodeID: "nodeXYZ123".into(),
            Location: Some(Location {
                Country: "Canada".into(),
                CountryCode: "CA".into(),
            }),
            TPM: Some(TPMInfo {
                Manufacturer: "MSFT".into(),
                Vendor: "MSFT".into(),
                Model: 42,
                FirmwareVersion: 511,
                SpecRevision: 127,
                FamilyIndicator: "2.0".into(),
            }),
            StateEncrypted: OptBool::True,
            ..Default::default()
        };
        let j = serde_json::to_string(&hi).unwrap();
        // Verify exact Go JSON key names.
        assert!(j.contains("\"PushDeviceToken\":\"abc123\""));
        assert!(j.contains("\"ShareeNode\":true"));
        assert!(j.contains("\"WireIngress\":true"));
        assert!(j.contains("\"IngressEnabled\":true"));
        assert!(j.contains("\"WoLMACs\":[\"aa:bb:cc:dd:ee:ff\"]"));
        assert!(j.contains("\"ServicesHash\":\"deadbeef\""));
        assert!(j.contains("\"ExitNodeID\":\"nodeXYZ123\""));
        assert!(j.contains("\"Location\":{"));
        assert!(j.contains("\"Country\":\"Canada\""));
        assert!(j.contains("\"CountryCode\":\"CA\""));
        assert!(j.contains("\"TPM\":{"));
        assert!(j.contains("\"Manufacturer\":\"MSFT\""));
        assert!(j.contains("\"Vendor\":\"MSFT\""));
        assert!(j.contains("\"Model\":42"));
        assert!(j.contains("\"FirmwareVersion\":511"));
        assert!(j.contains("\"SpecRevision\":127"));
        assert!(j.contains("\"FamilyIndicator\":\"2.0\""));
        assert!(j.contains("\"StateEncrypted\":true"));
        // Round-trip.
        let back: Hostinfo = serde_json::from_str(&j).unwrap();
        assert_eq!(back, hi);
    }

    #[test]
    fn hostinfo_new_fields_omitted_when_default() {
        let hi = Hostinfo {
            OS: "linux".into(),
            ..Default::default()
        };
        let j = serde_json::to_string(&hi).unwrap();
        assert!(!j.contains("\"PushDeviceToken\""));
        assert!(!j.contains("\"ShareeNode\""));
        assert!(!j.contains("\"WireIngress\""));
        assert!(!j.contains("\"IngressEnabled\""));
        assert!(!j.contains("\"WoLMACs\""));
        assert!(!j.contains("\"ServicesHash\""));
        assert!(!j.contains("\"ExitNodeID\""));
        assert!(!j.contains("\"Location\""));
        assert!(!j.contains("\"TPM\""));
        assert!(!j.contains("\"StateEncrypted\""));
    }

    #[test]
    fn tpm_info_present_and_default() {
        let t = TPMInfo::default();
        assert!(!t.is_present());
        let t = TPMInfo {
            Manufacturer: "INTC".into(),
            ..Default::default()
        };
        assert!(t.is_present());
    }

    #[test]
    fn hostinfo_state_encrypted_opt_bool() {
        let hi = Hostinfo {
            StateEncrypted: OptBool::False,
            ..Default::default()
        };
        let j = serde_json::to_string(&hi).unwrap();
        assert!(j.contains("\"StateEncrypted\":false"));
        let back: Hostinfo = serde_json::from_str(&j).unwrap();
        assert_eq!(back.StateEncrypted, OptBool::False);
    }
}
