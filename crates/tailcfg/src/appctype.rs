//! App Connector configuration types, ported from Go's
//! `types/appctype/appconnector.go` and `tailcfg/proto_port_range.go`.
//!
//! These are the wire types that appear in `Node.CapMap` under the
//! `tailscale.com/app-connectors-experimental` capability key, and in
//! persisted route state.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{deserialize_null_to_default, skip_default, PortRange};

/// An opaque identifier for a configuration (matches Go's `appctype.ConfigID`).
pub type ConfigID = String;

/// An IP address range (matches Go's `go4.org/netipx.IPRange`).
///
/// Serialized as `{From, To}` on the wire, matching Go's JSON encoding.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IPRange {
    /// The start of the range (inclusive).
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub From: String,
    /// The end of the range (inclusive).
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub To: String,
}

/// A protocol + port range specification, matching Go's
/// `tailcfg.ProtoPortRange`. Used by DNAT and SNI proxy configs.
///
/// `Proto` is an IP protocol number (0 = TCP+UDP+ICMP). `Ports` is a port
/// range. On the wire, Go uses `TextMarshaler`/`TextUnmarshaler` which
/// encodes as strings like `"tcp:80"`, `"*"`, `"udp:53-90"`. We store the
/// parsed fields and serialize as a string for wire compatibility.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtoPortRange {
    /// IP protocol number (0 means TCP+UDP+ICMP).
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Proto: i32,
    #[serde(default)]
    pub Ports: PortRange,
}

/// The configuration structure for an application connection proxy service
/// (matches Go's `appctype.AppConnectorConfig`).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AppConnectorConfig {
    /// DNAT configurations keyed by config ID.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub DNAT: BTreeMap<ConfigID, DNATConfig>,
    /// SNI proxy configurations keyed by config ID.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub SNIProxy: BTreeMap<ConfigID, SNIProxyConfig>,
    /// Whether the node should advertise routes for service address lists.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub AdvertiseRoutes: bool,
}

/// Destination NAT configuration ("port forward"), matching Go's
/// `appctype.DNATConfig`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DNATConfig {
    /// Addresses to listen on.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub Addrs: Vec<String>,
    /// Destination addresses to forward to (one domain or list of IPs).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub To: Vec<String>,
    /// IP specifications to forward (e.g. `"tcp/80"`). If omitted, all
    /// protocols are forwarded.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub IP: Vec<ProtoPortRange>,
}

/// SNI proxy configuration, forwarding TLS based on SNI hostname, matching
/// Go's `appctype.SNIProxyConfig`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SNIProxyConfig {
    /// Addresses to listen on.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub Addrs: Vec<String>,
    /// IP specifications to forward.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub IP: Vec<ProtoPortRange>,
    /// Domains allowed to be proxied. A leading `.` means any subdomain.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub AllowedDomains: Vec<String>,
}

/// Describes a set of domains serviced by specified app connectors (matches
/// Go's `appctype.AppConnectorAttr`). Appears in `Node.CapMap` under the
/// `tailscale.com/app-connectors-experimental` key.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AppConnectorAttr {
    /// Name of this collection of domains.
    #[serde(default, skip_serializing_if = "skip_default", rename = "name")]
    pub Name: String,
    /// Domains serviced (can be `example.com` or `*.example.com`).
    #[serde(default, skip_serializing_if = "Vec::is_empty", rename = "domains")]
    pub Domains: Vec<String>,
    /// Predetermined routes to be advertised.
    #[serde(default, skip_serializing_if = "Vec::is_empty", rename = "routes")]
    pub Routes: Vec<String>,
    /// App connector tags that service these domains. `"*"` matches any
    /// advertising connector, or `tag:<tag-name>`.
    #[serde(default, skip_serializing_if = "Vec::is_empty", rename = "connectors")]
    pub Connectors: Vec<String>,
}

/// Conn25 domain/connector configuration (matches Go's
/// `appctype.Conn25Attr`).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Conn25Attr {
    /// Name of this collection of domains.
    #[serde(default, skip_serializing_if = "skip_default", rename = "name")]
    pub Name: String,
    /// Domains serviced (can be `example.com` or `*.example.com`).
    #[serde(default, skip_serializing_if = "Vec::is_empty", rename = "domains")]
    pub Domains: Vec<String>,
    /// App connector tags (`"*"` or `tag:<tag-name>`).
    #[serde(default, skip_serializing_if = "Vec::is_empty", rename = "connectors")]
    pub Connectors: Vec<String>,
}

/// Conn25 IP pool configuration (matches Go's `appctype.Conn25PoolsAttr`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Conn25PoolsAttr {
    /// IPv4 magic IP pool ranges.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub V4MagicIPPool: Vec<IPRange>,
    /// IPv4 transit IP pool ranges.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub V4TransitIPPool: Vec<IPRange>,
    /// IPv6 magic IP pool ranges.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub V6MagicIPPool: Vec<IPRange>,
    /// IPv6 transit IP pool ranges.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub V6TransitIPPool: Vec<IPRange>,
}

/// Persisted in-memory state of an AppConnector (matches Go's
/// `appctype.RouteInfo`). Used to survive restarts: which routes came from
/// ACLs (control) and which were learned from DNS observation (domains).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RouteInfo {
    /// Routes from the `routes` section of an app connector ACL.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub Control: Vec<String>,
    /// Routes discovered by observing DNS lookups for configured domains.
    /// Maps domain → resolved IP addresses.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub Domains: BTreeMap<String, Vec<String>>,
    /// Configured DNS lookup domains to observe. When a DNS query matches,
    /// its result is added to `Domains`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub Wildcards: Vec<String>,
}

/// Records routes to advertise and unadvertise (matches Go's
/// `appctype.RouteUpdate`). Published as event bus updates.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteUpdate {
    /// Routes to advertise (CIDR strings).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub Advertise: Vec<String>,
    /// Routes to unadvertise (CIDR strings).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub Unadvertise: Vec<String>,
}

/// The capability attribute name for app connectors (matches Go's
/// `appc.AppConnectorsExperimentalAttrName`).
pub const APP_CONNECTORS_EXPERIMENTAL_ATTR_NAME: &str = "tailscale.com/app-connectors-experimental";

/// The custom URI scheme used for conn25-managed split DNS entries (matches
/// Go's `appc.DNSAddrScheme`).
pub const DNS_ADDR_SCHEME: &str = "tailscale-app";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_connector_attr_roundtrip() {
        let attr = AppConnectorAttr {
            Name: "my-app".into(),
            Domains: vec!["example.com".into(), "*.example.com".into()],
            Routes: vec!["192.0.2.0/24".into()],
            Connectors: vec!["tag:prod".into(), "*".into()],
        };
        let j = serde_json::to_string(&attr).unwrap();
        assert!(j.contains("\"name\":\"my-app\""));
        assert!(j.contains("\"domains\""));
        assert!(j.contains("\"routes\""));
        assert!(j.contains("\"connectors\""));
        let back: AppConnectorAttr = serde_json::from_str(&j).unwrap();
        assert_eq!(back, attr);
    }

    #[test]
    fn app_connector_attr_omits_empty() {
        let attr = AppConnectorAttr::default();
        let j = serde_json::to_string(&attr).unwrap();
        assert_eq!(j, "{}");
    }

    #[test]
    fn conn25_attr_roundtrip() {
        let attr = Conn25Attr {
            Name: "app1".into(),
            Domains: vec!["corp.example.com".into()],
            Connectors: vec!["tag:connector".into()],
        };
        let j = serde_json::to_string(&attr).unwrap();
        let back: Conn25Attr = serde_json::from_str(&j).unwrap();
        assert_eq!(back, attr);
    }

    #[test]
    fn route_info_roundtrip() {
        let mut domains = BTreeMap::new();
        domains.insert(
            "example.com".into(),
            vec!["192.0.0.8".into(), "192.0.0.9".into()],
        );
        let ri = RouteInfo {
            Control: vec!["192.0.2.0/24".into()],
            Domains: domains,
            Wildcards: vec!["example.com".into()],
        };
        let j = serde_json::to_string(&ri).unwrap();
        let back: RouteInfo = serde_json::from_str(&j).unwrap();
        assert_eq!(back, ri);
    }

    #[test]
    fn route_info_omits_empty() {
        let ri = RouteInfo::default();
        let j = serde_json::to_string(&ri).unwrap();
        assert_eq!(j, "{}");
    }

    #[test]
    fn route_update_roundtrip() {
        let ru = RouteUpdate {
            Advertise: vec!["192.0.2.0/24".into()],
            Unadvertise: vec!["192.0.2.1/32".into()],
        };
        let j = serde_json::to_string(&ru).unwrap();
        let back: RouteUpdate = serde_json::from_str(&j).unwrap();
        assert_eq!(back, ru);
    }

    #[test]
    fn app_connector_config_roundtrip() {
        let mut dnat = BTreeMap::new();
        dnat.insert(
            "cfg1".into(),
            DNATConfig {
                Addrs: vec!["10.0.0.1".into()],
                To: vec!["internal.example.com".into()],
                IP: vec![],
            },
        );
        let cfg = AppConnectorConfig {
            DNAT: dnat,
            SNIProxy: BTreeMap::new(),
            AdvertiseRoutes: true,
        };
        let j = serde_json::to_string(&cfg).unwrap();
        let back: AppConnectorConfig = serde_json::from_str(&j).unwrap();
        assert_eq!(back, cfg);
    }

    #[test]
    fn ip_range_roundtrip() {
        let r = IPRange {
            From: "10.0.0.1".into(),
            To: "10.0.0.255".into(),
        };
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("\"From\":\"10.0.0.1\""));
        assert!(j.contains("\"To\":\"10.0.0.255\""));
        let back: IPRange = serde_json::from_str(&j).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn conn25_pools_attr_roundtrip() {
        let pools = Conn25PoolsAttr {
            V4MagicIPPool: vec![IPRange {
                From: "10.0.0.0".into(),
                To: "10.0.255.255".into(),
            }],
            ..Default::default()
        };
        let j = serde_json::to_string(&pools).unwrap();
        let back: Conn25PoolsAttr = serde_json::from_str(&j).unwrap();
        assert_eq!(back, pools);
    }

    #[test]
    fn proto_port_range_roundtrip() {
        let ppr = ProtoPortRange {
            Proto: 6,
            Ports: PortRange {
                First: 80,
                Last: 80,
            },
        };
        let j = serde_json::to_string(&ppr).unwrap();
        let back: ProtoPortRange = serde_json::from_str(&j).unwrap();
        assert_eq!(back, ppr);
    }

    #[test]
    fn constants_match_go() {
        assert_eq!(
            APP_CONNECTORS_EXPERIMENTAL_ATTR_NAME,
            "tailscale.com/app-connectors-experimental"
        );
        assert_eq!(DNS_ADDR_SCHEME, "tailscale-app");
    }
}
