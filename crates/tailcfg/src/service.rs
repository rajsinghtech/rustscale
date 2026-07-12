//! Tailscale VIP Service wire types — `ServiceName`, `VIPService`, and
//! `ServiceIPMappings`.
//!
//! Ports the Go types from `tailcfg/tailcfg.go`:
//! - `tailcfg.ServiceName` (line 965) — a `svc:dns-label` string newtype
//! - `tailcfg.VIPService` (line 1010) — service descriptor
//! - `tailcfg.ServiceIPMappings` (line 3397) — map carried in `NodeCapMap`
//!   under the `NodeAttrServiceHost` capability key
//! - `tailcfg.NodeAttrServiceHost` (line 2702) — `"service-host"`

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::NodeCapMap;

/// Node capability key indicating the VIP Services for which the client is
/// approved to act as a service host. The value(s) in `NodeCapMap` under this
/// key are JSON-encoded [`ServiceIPMappings`].
///
/// Matches Go's `tailcfg.NodeAttrServiceHost = "service-host"`.
pub const NODE_ATTR_SERVICE_HOST: &str = "service-host";

/// Maximum DNS label length (RFC 1035).
const MAX_LABEL_LENGTH: usize = 63;

/// The name of a Tailscale Service, of the form `svc:dns-label`.
///
/// Matches Go's `tailcfg.ServiceName` (a `string` newtype). The `svc:` prefix
/// is required; the remainder must be a valid RFC 1035 DNS label.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ServiceName(pub String);

impl ServiceName {
    /// Parse and validate a service name from a string.
    ///
    /// Returns `Ok` if the name starts with `svc:` and the remainder is a
    /// valid DNS label (alphanumeric + hyphens, 1–63 bytes, starts/ends
    /// alphanumeric).
    pub fn new(name: impl Into<String>) -> Result<Self, ServiceNameError> {
        let s = name.into();
        Self::validate_inner(&s)?;
        Ok(Self(s))
    }

    /// Construct a `ServiceName` without validation. Caller must ensure the
    /// string is valid.
    pub fn new_unchecked(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// Validate the service name format.
    pub fn validate(&self) -> Result<(), ServiceNameError> {
        Self::validate_inner(&self.0)
    }

    fn validate_inner(s: &str) -> Result<(), ServiceNameError> {
        let bare = s
            .strip_prefix("svc:")
            .ok_or_else(|| ServiceNameError::InvalidPrefix(s.to_string()))?;
        if bare.is_empty() {
            return Err(ServiceNameError::EmptyAfterPrefix);
        }
        validate_dns_label(bare)?;
        Ok(())
    }

    /// The service name without the `svc:` prefix (used for DNS names).
    /// Returns `""` if the prefix is missing.
    pub fn without_prefix(&self) -> &str {
        self.0.strip_prefix("svc:").unwrap_or("")
    }

    /// The full name as a string slice (including `svc:` prefix).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ServiceName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<ServiceName> for String {
    fn from(s: ServiceName) -> String {
        s.0
    }
}

impl AsRef<str> for ServiceName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Serialize for ServiceName {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ServiceName {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        Ok(Self(s))
    }
}

/// Errors from [`ServiceName`] validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ServiceNameError {
    #[error("{0:?} is not a valid service name: must start with 'svc:'")]
    InvalidPrefix(String),
    #[error("service name must not be empty after the 'svc:' prefix")]
    EmptyAfterPrefix,
    #[error("{0:?} is not a valid DNS label: {1}")]
    InvalidLabel(String, String),
}

/// Validate a single DNS label per RFC 1035 (matches Go's
/// `dnsname.ValidLabel`).
fn validate_dns_label(label: &str) -> Result<(), ServiceNameError> {
    if label.is_empty() {
        return Err(ServiceNameError::InvalidLabel(
            label.to_string(),
            "empty DNS label".into(),
        ));
    }
    if label.len() > MAX_LABEL_LENGTH {
        return Err(ServiceNameError::InvalidLabel(
            label.to_string(),
            format!("too long, max length is {MAX_LABEL_LENGTH} bytes"),
        ));
    }
    if !is_alphanum(label.as_bytes()[0]) {
        return Err(ServiceNameError::InvalidLabel(
            label.to_string(),
            "must start with a letter or number".into(),
        ));
    }
    if !is_alphanum(label.as_bytes()[label.len() - 1]) {
        return Err(ServiceNameError::InvalidLabel(
            label.to_string(),
            "must end with a letter or number".into(),
        ));
    }
    if label.len() >= 2 {
        for &c in &label.as_bytes()[1..label.len() - 1] {
            if !is_dns_char(c) {
                return Err(ServiceNameError::InvalidLabel(
                    label.to_string(),
                    format!("contains invalid character '{}'", c as char),
                ));
            }
        }
    }
    Ok(())
}

fn is_alphanum(c: u8) -> bool {
    c.is_ascii_alphanumeric()
}

fn is_dns_char(c: u8) -> bool {
    is_alphanum(c) || c == b'-'
}

/// A VIP Service from the perspective of a node providing that service.
///
/// Matches Go's `tailcfg.VIPService`. Services have a virtual IP (VIP) address
/// pair distinct from the node's own IPs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VIPService {
    /// The name of the service. Uniquely identifies a service on a particular
    /// tailnet and corresponds to its VIP address pair.
    #[serde(default, deserialize_with = "crate::deserialize_null_to_default")]
    pub Name: ServiceName,

    /// Which protocol+ports are made available by this node on the service's
    /// IPs.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "crate::deserialize_null_to_default"
    )]
    pub Ports: Vec<crate::ProtoPortRange>,

    /// Whether new requests for the service should be sent to this node by
    /// control.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub Active: bool,
}

/// Maps `ServiceName` to lists of IP addresses. This is the value of the
/// [`NODE_ATTR_SERVICE_HOST`] capability in `NodeCapMap`, informing service
/// hosts which IP addresses they need to listen on.
///
/// Matches Go's `tailcfg.ServiceIPMappings`.
///
/// # Wire format
///
/// ```json
/// {
///   "svc:samba": ["100.65.32.1", "fd7a:115c:a1e0::1234"],
///   "svc:web": ["100.102.42.3", "fd7a:115c:a1e0::abcd"]
/// }
/// ```
pub type ServiceIPMappings = BTreeMap<ServiceName, Vec<IpAddr>>;

/// Extract [`ServiceIPMappings`] from a node's `NodeCapMap`, decoding the
/// JSON values stored under the [`NODE_ATTR_SERVICE_HOST`] key.
///
/// Mirrors Go's `tailcfg.UnmarshalNodeCapViewJSON[ServiceIPMappings]` call in
/// `ipn/ipnlocal/local.go:3281`. Multiple values under the key are merged in
/// sequence (replace conflicting keys), matching Go's semantics.
pub fn service_ip_mappings_from_capmap(cap_map: &NodeCapMap) -> ServiceIPMappings {
    let mut result = ServiceIPMappings::new();
    let Some(values) = cap_map.get(NODE_ATTR_SERVICE_HOST) else {
        return result;
    };
    for raw in values {
        if raw.0.is_empty() {
            continue;
        }
        match serde_json::from_str::<ServiceIPMappings>(&raw.0) {
            Ok(mappings) => {
                for (k, v) in mappings {
                    result.insert(k, v);
                }
            }
            Err(e) => {
                eprintln!("tailcfg: failed to decode ServiceIPMappings: {e}");
            }
        }
    }
    result
}

/// Resolve the VIP addresses for a named service from a `NodeCapMap`.
///
/// Returns the list of IPs (typically two: one v4, one v6) assigned to the
/// service, or an empty vec if the service is not found.
pub fn service_vip_addrs(cap_map: &NodeCapMap, svc_name: &ServiceName) -> Vec<IpAddr> {
    service_ip_mappings_from_capmap(cap_map)
        .get(svc_name)
        .cloned()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RawMessage;

    #[test]
    fn service_name_valid() {
        assert!(ServiceName::new("svc:my-service").is_ok());
        assert!(ServiceName::new("svc:samba").is_ok());
        assert!(ServiceName::new("svc:web").is_ok());
        assert!(ServiceName::new("svc:a").is_ok());
        assert!(ServiceName::new("svc:a1").is_ok());
        assert!(ServiceName::new("svc:1").is_ok());
        assert!(ServiceName::new("svc:abc-def").is_ok());
    }

    #[test]
    fn service_name_missing_prefix() {
        assert_eq!(
            ServiceName::new("my-service").unwrap_err(),
            ServiceNameError::InvalidPrefix("my-service".into())
        );
        assert_eq!(
            ServiceName::new("").unwrap_err(),
            ServiceNameError::InvalidPrefix(String::new())
        );
    }

    #[test]
    fn service_name_empty_after_prefix() {
        assert_eq!(
            ServiceName::new("svc:").unwrap_err(),
            ServiceNameError::EmptyAfterPrefix
        );
    }

    #[test]
    fn service_name_invalid_label() {
        assert!(ServiceName::new("svc:-bad").is_err());
        assert!(ServiceName::new("svc:bad-").is_err());
        assert!(ServiceName::new("svc:bad label").is_err());
        assert!(ServiceName::new("svc:bad.label").is_err());
        assert!(ServiceName::new("svc:_under").is_err());
    }

    #[test]
    fn service_name_too_long() {
        let long = "a".repeat(64);
        let name = format!("svc:{long}");
        assert!(ServiceName::new(&name).is_err());
    }

    #[test]
    fn service_name_without_prefix() {
        let sn = ServiceName::new_unchecked("svc:my-service");
        assert_eq!(sn.without_prefix(), "my-service");
        assert_eq!(sn.as_str(), "svc:my-service");
        assert_eq!(sn.to_string(), "svc:my-service");
    }

    #[test]
    fn service_name_serde_roundtrip() {
        let sn = ServiceName::new_unchecked("svc:web");
        let j = serde_json::to_string(&sn).unwrap();
        assert_eq!(j, "\"svc:web\"");
        let back: ServiceName = serde_json::from_str(&j).unwrap();
        assert_eq!(back, sn);
    }

    #[test]
    fn vip_service_serde() {
        let svc = VIPService {
            Name: ServiceName::new_unchecked("svc:samba"),
            Ports: vec![],
            Active: true,
        };
        let j = serde_json::to_string(&svc).unwrap();
        assert!(j.contains("\"Name\":\"svc:samba\""));
        assert!(j.contains("\"Active\":true"));
        let back: VIPService = serde_json::from_str(&j).unwrap();
        assert_eq!(back, svc);
    }

    #[test]
    fn service_ip_mappings_from_capmap_empty() {
        let map = NodeCapMap::new();
        let mappings = service_ip_mappings_from_capmap(&map);
        assert!(mappings.is_empty());
    }

    #[test]
    fn service_ip_mappings_from_capmap_decodes() {
        let json = r#"{"svc:web":["100.102.42.3","fd7a:115c:a1e0::abcd"]}"#;
        let mut map = NodeCapMap::new();
        map.insert(
            NODE_ATTR_SERVICE_HOST.to_string(),
            vec![RawMessage(json.to_string())],
        );
        let mappings = service_ip_mappings_from_capmap(&map);
        let addrs = mappings
            .get(&ServiceName::new_unchecked("svc:web"))
            .unwrap();
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0], "100.102.42.3".parse::<IpAddr>().unwrap());
        assert_eq!(addrs[1], "fd7a:115c:a1e0::abcd".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn service_ip_mappings_merges_multiple_values() {
        let j1 = r#"{"svc:a":["100.64.0.1"]}"#;
        let j2 = r#"{"svc:b":["100.64.0.2"]}"#;
        let mut map = NodeCapMap::new();
        map.insert(
            NODE_ATTR_SERVICE_HOST.to_string(),
            vec![RawMessage(j1.to_string()), RawMessage(j2.to_string())],
        );
        let mappings = service_ip_mappings_from_capmap(&map);
        assert!(mappings.contains_key(&ServiceName::new_unchecked("svc:a")));
        assert!(mappings.contains_key(&ServiceName::new_unchecked("svc:b")));
    }

    #[test]
    fn service_vip_addrs_lookup() {
        let json = r#"{"svc:web":["100.102.42.3","fd7a:115c:a1e0::abcd"]}"#;
        let mut map = NodeCapMap::new();
        map.insert(
            NODE_ATTR_SERVICE_HOST.to_string(),
            vec![RawMessage(json.to_string())],
        );
        let addrs = service_vip_addrs(&map, &ServiceName::new_unchecked("svc:web"));
        assert_eq!(addrs.len(), 2);
        let missing = service_vip_addrs(&map, &ServiceName::new_unchecked("svc:nonexistent"));
        assert!(missing.is_empty());
    }

    #[test]
    fn service_ip_mappings_serde_roundtrip() {
        let mut mappings = ServiceIPMappings::new();
        mappings.insert(
            ServiceName::new_unchecked("svc:web"),
            vec![
                "100.102.42.3".parse().unwrap(),
                "fd7a:115c:a1e0::abcd".parse().unwrap(),
            ],
        );
        let j = serde_json::to_string(&mappings).unwrap();
        let back: ServiceIPMappings = serde_json::from_str(&j).unwrap();
        assert_eq!(back, mappings);
    }
}
