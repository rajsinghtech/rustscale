//! DNS configuration + SetDNS request types, ported from Go's `tailcfg.go`
//! and `types/dnstype/dnstype.go`.
//!
//! These carry the MagicDNS configuration the control plane sends in
//! [`crate::MapResponse`] and the request a node posts at `/machine/set-dns`
//! (used to publish ACME DNS-01 challenge TXT records; see
//! `DNSConfig.CertDomains`).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{deserialize_null_to_default, skip_default, CapabilityVersion, NodeKey, UserID};

/// Deserialize a `HashMap<String, Vec<Resolver>>` where individual route values
/// may be `null` on the wire (Go's nil slices marshal as `null`). Treats null
/// values as empty vectors.
fn deserialize_null_routes<'de, D>(
    deserializer: D,
) -> Result<HashMap<String, Vec<Resolver>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt: Option<HashMap<String, Option<Vec<Resolver>>>> = Option::deserialize(deserializer)?;
    match opt {
        None => Ok(HashMap::new()),
        Some(raw) => {
            let mut map = HashMap::with_capacity(raw.len());
            for (k, v) in raw {
                map.insert(k, v.unwrap_or_default());
            }
            Ok(map)
        }
    }
}

/// Configuration for one DNS resolver (subset of Go's `dnstype.Resolver`).
///
/// `Addr` is the workhorse field: a plain IP for classic UDP/TCP DNS, or a
/// `https://`/`http://` URL for DNS-over-HTTPS. Bootstrap addresses and the
/// exit-node-use flag are omitted for now (minimal port).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resolver {
    /// Resolver address: a plain IP, `IP:port`, or a DoH URL.
    #[serde(default, skip_serializing_if = "skip_default", deserialize_with = "deserialize_null_to_default")]
    pub Addr: String,
}

/// The DNS configuration the control plane sends in `MapResponse.DNSConfig`
/// (subset of Go's `tailcfg.DNSConfig`).
///
/// `Proxied` enables MagicDNS — automatic resolution of peer hostnames from
/// the network map. `CertDomains` lists the DNS names for which control will
/// assist with TLS certificate provisioning (via `SetDNSRequest` answering
/// ACME DNS-01 challenges); a non-empty `CertDomains` means the tailnet has
/// HTTPS/certs enabled.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DNSConfig {
    /// Global DNS resolvers to use, in preference order.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Resolvers: Vec<Resolver>,
    /// Split-DNS routes: maps FQDN suffix → upstream resolvers.
    /// Keys are fully-qualified DNS name suffixes (may optionally contain
    /// a trailing dot but no leading dot). An empty resolver slice means
    /// the suffix is handled by Tailscale's built-in resolver (for
    /// ExtraRecords support).
    #[serde(
        default,
        skip_serializing_if = "HashMap::is_empty",
        deserialize_with = "deserialize_null_routes"
    )]
    pub Routes: HashMap<String, Vec<Resolver>>,
    /// Fallback resolvers (like `Resolvers` but only used when split DNS
    /// is configured without explicit default resolvers).
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub FallbackResolvers: Vec<Resolver>,
    /// Search domains (FQDNs without trailing dot).
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Domains: Vec<String>,
    /// Whether MagicDNS (peer-name resolution from the netmap) is on.
    #[serde(default, skip_serializing_if = "skip_default", deserialize_with = "deserialize_null_to_default")]
    pub Proxied: bool,
    /// DNS names for which control assists with LE cert provisioning. A
    /// non-empty list signals the tailnet has HTTPS enabled.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub CertDomains: Vec<String>,
    /// Extra DNS records to add to MagicDNS.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub ExtraRecords: Vec<DNSRecord>,
    /// Deprecated global nameserver IPs (MapRequest.Version <14). Kept for
    /// wire compatibility.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Nameservers: Vec<String>,
}

/// An extra DNS record to add to MagicDNS (matches Go's `tailcfg.DNSRecord`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DNSRecord {
    /// FQDN of the record (trailing dot optional).
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub Name: String,
    /// DNS record type; empty means A or AAAA depending on `Value`.
    #[serde(default, skip_serializing_if = "skip_default", deserialize_with = "deserialize_null_to_default")]
    #[allow(non_snake_case)]
    pub Type: String,
    /// IP address in string form.
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub Value: String,
}

/// A request to add a DNS record, POSTed to `/machine/set-dns`.
///
/// For ACME DNS-01 challenges, `Name` is `_acme-challenge.<cert-domain>`,
/// `Type` is `"TXT"`, and `Value` is the challenge record. Control owns the
/// tailnet DNS zone (e.g. `ts.net`) and publishes the TXT record that
/// Let's Encrypt then validates.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SetDNSRequest {
    /// Client capability version.
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub Version: CapabilityVersion,
    /// The client's current node public key.
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub NodeKey: NodeKey,
    /// Domain name to create a record for.
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub Name: String,
    /// DNS record type (e.g. `"TXT"`).
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    #[allow(non_snake_case)]
    pub Type: String,
    /// Value to add.
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub Value: String,
}

/// The response to a [`SetDNSRequest`] (empty in Go).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetDNSResponse {}

/// Display-friendly data for a [`crate::User`] (matches Go's
/// `tailcfg.UserProfile`). Used by WhoIs to report the login owning a node.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserProfile {
    /// User ID (matches `Node.User`).
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub ID: UserID,
    /// Login name, e.g. `"alice@example.com"` (provider not listed).
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub LoginName: String,
    /// Display name, e.g. `"Alice Smith"`.
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub DisplayName: String,
    /// Profile picture URL.
    #[serde(default, skip_serializing_if = "skip_default", deserialize_with = "deserialize_null_to_default")]
    pub ProfilePicURL: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_config_roundtrip() {
        let cfg = DNSConfig {
            Resolvers: vec![Resolver {
                Addr: "1.1.1.1".into(),
            }],
            Routes: HashMap::from([(
                "corp.example.com.".to_string(),
                vec![Resolver {
                    Addr: "10.0.0.53".into(),
                }],
            )]),
            FallbackResolvers: vec![],
            Domains: vec!["ts.net".into()],
            Proxied: true,
            CertDomains: vec!["node.ts.net".into()],
            ExtraRecords: vec![DNSRecord {
                Name: "app.ts.net".into(),
                Type: "A".into(),
                Value: "100.64.0.5".into(),
            }],
            Nameservers: vec![],
        };
        let j = serde_json::to_string(&cfg).unwrap();
        let back: DNSConfig = serde_json::from_str(&j).unwrap();
        assert_eq!(back, cfg);
        assert!(j.contains("\"Proxied\":true"));
        assert!(j.contains("\"CertDomains\":[\"node.ts.net\"]"));
        assert!(j.contains("\"corp.example.com.\""));
    }

    #[test]
    fn dns_config_routes_roundtrip() {
        let cfg = DNSConfig {
            Routes: HashMap::from([
                (
                    "corp.example.com.".to_string(),
                    vec![Resolver {
                        Addr: "10.0.0.53".into(),
                    }],
                ),
                (
                    ".".to_string(),
                    vec![Resolver {
                        Addr: "1.1.1.1".into(),
                    }],
                ),
            ]),
            ..Default::default()
        };
        let j = serde_json::to_string(&cfg).unwrap();
        let back: DNSConfig = serde_json::from_str(&j).unwrap();
        assert_eq!(back, cfg);
        assert_eq!(back.Routes.len(), 2);
    }

    #[test]
    fn dns_config_empty_serializes_minimal() {
        let cfg = DNSConfig::default();
        let j = serde_json::to_string(&cfg).unwrap();
        assert_eq!(j, "{}");
    }

    #[test]
    fn set_dns_request_roundtrip() {
        use rustscale_key::NodePrivate;
        let req = SetDNSRequest {
            Version: 141,
            NodeKey: NodePrivate::generate().public(),
            Name: "_acme-challenge.node.ts.net".into(),
            Type: "TXT".into(),
            Value: "abc123".into(),
        };
        let j = serde_json::to_string(&req).unwrap();
        assert!(j.contains("\"Name\":\"_acme-challenge.node.ts.net\""));
        assert!(j.contains("\"Type\":\"TXT\""));
        let back: SetDNSRequest = serde_json::from_str(&j).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn user_profile_roundtrip() {
        let up = UserProfile {
            ID: 7,
            LoginName: "alice@example.com".into(),
            DisplayName: "Alice".into(),
            ProfilePicURL: "https://x/a.png".into(),
        };
        let j = serde_json::to_string(&up).unwrap();
        let back: UserProfile = serde_json::from_str(&j).unwrap();
        assert_eq!(back, up);
        assert!(j.contains("\"LoginName\":\"alice@example.com\""));
    }
}
