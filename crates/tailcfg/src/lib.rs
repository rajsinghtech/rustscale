//! Tailscale control-plane wire types.
//!
//! Ports the JSON wire format of Go's `tailcfg` package. Field names match
//! Go's `encoding/json` output exactly (Go marshals exported field names
//! verbatim unless a `json:"name,..."` tag says otherwise). `omitempty`/
//! `omitzero` are reproduced with `#[serde(default, skip_serializing_if = ...)]`.

#![forbid(unsafe_code)]
#![allow(non_snake_case)]

mod appctype;
mod caps;
mod derpmap;
mod dns;
mod filter;
mod map;
mod node;
mod register;
mod service;
mod ssh;

pub use appctype::{
    AppConnectorAttr, AppConnectorConfig, ConfigID, Conn25Attr, Conn25PoolsAttr, DNATConfig,
    IPRange, ProtoPortRange, RouteInfo, RouteUpdate, SNIProxyConfig,
    APP_CONNECTORS_EXPERIMENTAL_ATTR_NAME, DNS_ADDR_SCHEME,
};
pub use caps::{
    cap_ver_is_relay_capable, has_capability, relay_client_disabled, relay_server_disabled,
    CAP_VERSION_RELAY, NODE_ATTR_DISABLE_RELAY_CLIENT, NODE_ATTR_DISABLE_RELAY_SERVER,
    PEER_CAPABILITY_RELAY, PEER_CAPABILITY_RELAY_TARGET,
};
pub use derpmap::{DERPHomeParams, DERPMap, DERPNode, DERPRegion};
pub use dns::{DNSConfig, DNSRecord, Resolver, SetDNSRequest, SetDNSResponse, UserProfile};
pub use filter::{filter_allow_all, CapGrant, FilterRule, NetPortRange, PeerCapMap, PortRange};
pub use map::{ClientVersion, MapRequest, MapResponse, PeerChange};
pub use node::{
    Endpoint, EndpointType, Hostinfo, Location, NetInfo, Node, NodeCapMap, Service, ServiceProto,
    TPMInfo,
};
pub use register::{Login, LoginID, RegisterRequest, RegisterResponse, RegisterResponseAuth, User};
pub use service::{
    service_ip_mappings_from_capmap, service_vip_addrs, ServiceIPMappings, ServiceName,
    ServiceNameError, VIPService, NODE_ATTR_SERVICE_HOST,
};
pub use ssh::{SSHAction, SSHPolicy, SSHPrincipal, SSHRecorderFailureAction, SSHRule};

pub use rustscale_key::{
    DiscoPublic as DiscoKey, MachinePublic as MachineKey, NodePublic as NodeKey,
};

use serde::{Deserialize, Serialize};

/// A tri-state optional boolean matching Go's `opt.Bool` JSON encoding:
/// `true`, `false`, or `null` (unset). In struct fields it is omitted when
/// unset, mirroring Go's `omitempty`/`omitzero`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum OptBool {
    /// The unset/unknown state — serializes to `null` and is omitted in
    /// `skip_serializing_if` contexts.
    #[default]
    Unset,
    /// An explicit `true`.
    True,
    /// An explicit `false`.
    False,
}

impl OptBool {
    /// Construct from a plain `bool`.
    pub fn new(v: bool) -> Self {
        if v {
            Self::True
        } else {
            Self::False
        }
    }

    /// The underlying `bool` if set, else `None`.
    pub fn get(self) -> Option<bool> {
        match self {
            Self::True => Some(true),
            Self::False => Some(false),
            Self::Unset => None,
        }
    }

    /// Whether this is the unset state (used by `skip_serializing_if`).
    pub fn is_unset(&self) -> bool {
        matches!(*self, Self::Unset)
    }
}

impl Serialize for OptBool {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::True => s.serialize_bool(true),
            Self::False => s.serialize_bool(false),
            Self::Unset => s.serialize_none(),
        }
    }
}

impl<'de> Deserialize<'de> for OptBool {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Vis;
        impl serde::de::Visitor<'_> for Vis {
            type Value = OptBool;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a boolean or null")
            }
            fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(OptBool::new(v))
            }
            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(OptBool::Unset)
            }
            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(OptBool::Unset)
            }
        }
        d.deserialize_any(Vis)
    }
}

/// A 64-bit control-plane identifier (matches Go's `tailcfg.ID`).
pub type ID = i64;

/// Identifier for a [`User`].
pub type UserID = ID;
/// Identifier for a [`Node`].
pub type NodeID = ID;

/// A stable, string-form node identifier (matches Go's `tailcfg.StableNodeID`).
pub type StableNodeID = String;

/// A capability-version integer the client sends to negotiate semantics with
/// the control plane (matches Go's `tailcfg.CapabilityVersion`).
pub type CapabilityVersion = i32;

/// A free-form node capability string, typically a URL like
/// `https://tailscale.com/cap/is-admin` (matches Go's `tailcfg.NodeCapability`).
pub type NodeCapability = String;

/// A raw encoded JSON value, like Go's `json.RawMessage`.
///
/// Captures the raw JSON text of any value (string, number, boolean, object,
/// array, null) without interpreting it. This is needed because Go's
/// `json.RawMessage` is `[]byte` that delays deserialization, and the
/// `NodeCapMap` values can be any JSON type.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct RawMessage(pub String);

impl Serialize for RawMessage {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.0.is_empty() {
            return s.serialize_none();
        }
        // The inner string contains valid JSON text; parse and re-serialize
        // to embed as raw JSON content.
        let value: serde_json::Value =
            serde_json::from_str(&self.0).map_err(serde::ser::Error::custom)?;
        value.serialize(s)
    }
}

impl<'de> Deserialize<'de> for RawMessage {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(d)?;
        if value.is_null() {
            Ok(Self::default())
        } else {
            Ok(Self(value.to_string()))
        }
    }
}

/// Serde helper: skip a field whose value equals its `Default` (mirrors Go's
/// `omitempty`/`omitzero` for scalars, strings, Vecs, and Options).
pub(crate) fn skip_default<T>(v: &T) -> bool
where
    T: Default + PartialEq,
{
    *v == T::default()
}

/// Serde helper: deserialize `null` as `Default` (Go nil slices marshal as `null`).
pub(crate) fn deserialize_null_to_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    let opt: Option<T> = Option::deserialize(deserializer)?;
    Ok(opt.unwrap_or_default())
}

/// Serde helper: deserialize a `BTreeMap<String, V>` where the whole map or
/// individual values may be `null` on the wire (Go nil maps marshal as `null`;
/// nil pointers in `map[string]*T` values marshal as `null`). Treats null
/// values as `V::default()`.
pub(crate) fn deserialize_null_map_values<'de, D, V>(
    deserializer: D,
) -> Result<std::collections::BTreeMap<String, V>, D::Error>
where
    D: serde::Deserializer<'de>,
    V: Default + Deserialize<'de>,
{
    let opt: Option<std::collections::BTreeMap<String, Option<V>>> =
        Option::deserialize(deserializer)?;
    match opt {
        None => Ok(std::collections::BTreeMap::new()),
        Some(raw) => {
            let mut map = std::collections::BTreeMap::new();
            for (k, v) in raw {
                map.insert(k, v.unwrap_or_default());
            }
            Ok(map)
        }
    }
}

/// Serde helper: skip a key field when it is the all-zero key.
pub(crate) fn skip_zero_machine(v: &rustscale_key::MachinePublic) -> bool {
    v.is_zero()
}

/// Serde helper: skip a disco key field when it is the all-zero key.
pub(crate) fn skip_zero_disco(v: &rustscale_key::DiscoPublic) -> bool {
    v.is_zero()
}

/// Serde helpers for `BTreeMap<i32, V>`: Go marshals `map[int]V` with string
/// keys, so we serialize/deserialize the integer keys as JSON strings.
pub mod int_key {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::BTreeMap;

    pub fn serialize<S, V>(m: &BTreeMap<i32, V>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        V: Serialize,
    {
        use serde::ser::SerializeMap;
        let mut map = s.serialize_map(Some(m.len()))?;
        for (k, v) in m {
            map.serialize_entry(&k.to_string(), v)?;
        }
        map.end()
    }

    pub fn deserialize<'de, D, V>(d: D) -> Result<BTreeMap<i32, V>, D::Error>
    where
        D: Deserializer<'de>,
        V: Deserialize<'de>,
    {
        let raw: BTreeMap<String, V> = BTreeMap::deserialize(d)?;
        raw.into_iter()
            .map(|(k, v)| {
                k.parse::<i32>()
                    .map(|k| (k, v))
                    .map_err(serde::de::Error::custom)
            })
            .collect()
    }

    /// Deserialize with null-to-default handling (Go nil maps marshal as null).
    pub fn deserialize_null<'de, D, V>(d: D) -> Result<BTreeMap<i32, V>, D::Error>
    where
        D: Deserializer<'de>,
        V: Deserialize<'de>,
    {
        let opt: Option<BTreeMap<String, V>> = Option::deserialize(d)?;
        match opt {
            Some(raw) => raw
                .into_iter()
                .map(|(k, v)| {
                    k.parse::<i32>()
                        .map(|k| (k, v))
                        .map_err(serde::de::Error::custom)
                })
                .collect(),
            None => Ok(BTreeMap::new()),
        }
    }

    /// Deserialize with null-to-default handling for both the whole map and
    /// individual values (Go nil maps marshal as `null`; nil pointers in
    /// `map[int]*T` values marshal as `null`). Null values are treated as
    /// `V::default()`.
    pub fn deserialize_null_values<'de, D, V>(d: D) -> Result<BTreeMap<i32, V>, D::Error>
    where
        D: Deserializer<'de>,
        V: Default + Deserialize<'de>,
    {
        let opt: Option<BTreeMap<String, Option<V>>> = Option::deserialize(d)?;
        match opt {
            None => Ok(BTreeMap::new()),
            Some(raw) => {
                let mut map = BTreeMap::new();
                for (k, v) in raw {
                    let k = k.parse::<i32>().map_err(serde::de::Error::custom)?;
                    map.insert(k, v.unwrap_or_default());
                }
                Ok(map)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opt_bool_encodes_true_false_null() {
        assert_eq!(serde_json::to_string(&OptBool::True).unwrap(), "true");
        assert_eq!(serde_json::to_string(&OptBool::False).unwrap(), "false");
        assert_eq!(serde_json::to_string(&OptBool::Unset).unwrap(), "null");
    }

    #[test]
    fn opt_bool_decodes_true_false_null() {
        assert_eq!(
            serde_json::from_str::<OptBool>("true").unwrap(),
            OptBool::True
        );
        assert_eq!(
            serde_json::from_str::<OptBool>("false").unwrap(),
            OptBool::False
        );
        assert_eq!(
            serde_json::from_str::<OptBool>("null").unwrap(),
            OptBool::Unset
        );
        assert!(serde_json::from_str::<OptBool>("\"true\"").is_err());
    }

    #[test]
    fn opt_bool_skipped_when_unset_in_struct() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct Wrap {
            #[serde(default, skip_serializing_if = "OptBool::is_unset")]
            flag: OptBool,
        }
        let w = Wrap {
            flag: OptBool::Unset,
        };
        assert_eq!(serde_json::to_string(&w).unwrap(), "{}");
        let back: Wrap = serde_json::from_str("{}").unwrap();
        assert_eq!(back.flag, OptBool::Unset);
        let set: Wrap = serde_json::from_str("{\"flag\":true}").unwrap();
        assert_eq!(set.flag, OptBool::True);
    }

    #[test]
    fn int_key_map_roundtrips_with_string_keys() {
        use std::collections::BTreeMap;
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct M {
            #[serde(with = "int_key")]
            vals: BTreeMap<i32, f64>,
        }
        let mut vals = BTreeMap::new();
        vals.insert(1, 0.5);
        vals.insert(900, 1.25);
        let m = M { vals };
        let j = serde_json::to_string(&m).unwrap();
        assert!(j.contains("\"1\":0.5"));
        assert!(j.contains("\"900\":1.25"));
        let back: M = serde_json::from_str(&j).unwrap();
        assert_eq!(back, m);
    }
}
