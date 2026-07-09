//! Registration protocol types, ported from Go's `tailcfg.go`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use rustscale_key::NodePublic;

use crate::{skip_default, CapabilityVersion, Hostinfo, ID};

/// A request to register a node key (subset of Go's `tailcfg.RegisterRequest`).
///
/// POSTed to `https://<control>/machine/register`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RegisterRequest {
    /// Client capability version (must be 1 on the legacy NaCl transport).
    pub Version: CapabilityVersion,
    /// The node public key being registered.
    pub NodeKey: NodePublic,
    /// The previous node key, if rotating.
    #[serde(default)]
    pub OldNodeKey: NodePublic,
    /// Authentication information returned by a prior registration.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Auth: Option<RegisterResponseAuth>,
    /// Requested key expiry (server policy may override).
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Expiry: Option<DateTime<Utc>>,
    /// If set, the response waits until the auth URL is visited.
    pub Followup: String,
    /// The client's current host info. `None` serializes as `null`.
    #[serde(default)]
    pub Hostinfo: Option<Hostinfo>,
    /// Whether the node is ephemeral (auto-deleted when inactive).
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Ephemeral: bool,
    /// Optional recommended/required tailnet identifier.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Tailnet: String,
}

/// The server's response to a [`RegisterRequest`] (subset of Go's
/// `tailcfg.RegisterResponse`).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RegisterResponse {
    /// The user that owns the node.
    pub User: User,
    /// The login from the identity provider.
    pub Login: Login,
    /// Whether the node key needs to be replaced.
    pub NodeKeyExpired: bool,
    /// Whether the machine is authorized.
    pub MachineAuthorized: bool,
    /// If non-empty, authorization is pending at this URL.
    pub AuthURL: String,
    /// If non-empty, authorization failed and other fields should be ignored.
    pub Error: String,
}

/// Auth information returned by the server (subset of Go's
/// `tailcfg.RegisterResponseAuth`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterResponseAuth {
    /// An auth key (the deprecated Android OAuth2 token path is omitted).
    #[serde(default, skip_serializing_if = "skip_default")]
    pub AuthKey: String,
}

/// A Tailscale user (matches Go's `tailcfg.User`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    /// User ID.
    pub ID: UserID,
    /// Display name (overrides the login field if non-empty).
    pub DisplayName: String,
    /// Profile picture URL.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub ProfilePicURL: String,
    /// When the user was created.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Created: Option<DateTime<Utc>>,
}

/// A user from a specific identity provider (matches Go's `tailcfg.Login`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Login {
    /// Login ID (unused in the Tailscale client).
    pub ID: LoginID,
    /// Provider: `"google"`, `"github"`, `"okta_foo"`, ...
    pub Provider: String,
    /// Email-ish login name.
    pub LoginName: String,
    /// Display name from the IdP.
    pub DisplayName: String,
    /// Profile picture URL from the IdP.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub ProfilePicURL: String,
}

/// Identifier for a [`Login`] (matches Go's `tailcfg.LoginID`).
pub type LoginID = ID;
/// Identifier for a [`User`] (matches Go's `tailcfg.UserID`).
pub type UserID = ID;

#[cfg(test)]
mod tests {
    use super::*;
    use rustscale_key::NodePrivate;

    #[test]
    fn register_request_roundtrip() {
        let req = RegisterRequest {
            Version: 999,
            NodeKey: NodePrivate::generate().public(),
            Expiry: Some(
                DateTime::parse_from_rfc3339("2025-12-31T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
            ),
            Ephemeral: true,
            Tailnet: "required:example.com".into(),
            ..Default::default()
        };
        let j = serde_json::to_string(&req).unwrap();
        assert!(j.contains("\"NodeKey\":\"nodekey:"));
        assert!(j.contains("\"Ephemeral\":true"));
        assert!(j.contains("\"Tailnet\":\"required:example.com\""));
        // OldNodeKey defaults to zero and is emitted (no skip) as nodekey:00...
        assert!(j.contains("\"OldNodeKey\":\"nodekey:"));
        // Followup is always present (no tag), empty -> "".
        assert!(j.contains("\"Followup\":\"\""));
        let back: RegisterRequest = serde_json::from_str(&j).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn register_response_roundtrip() {
        let resp = RegisterResponse {
            User: User {
                ID: 5,
                DisplayName: "Alice".into(),
                ..Default::default()
            },
            Login: Login {
                ID: 9,
                Provider: "google".into(),
                LoginName: "alice@example.com".into(),
                ..Default::default()
            },
            NodeKeyExpired: false,
            MachineAuthorized: true,
            AuthURL: String::new(),
            Error: String::new(),
        };
        let j = serde_json::to_string(&resp).unwrap();
        assert!(j.contains("\"MachineAuthorized\":true"));
        assert!(j.contains("\"Provider\":\"google\""));
        let back: RegisterResponse = serde_json::from_str(&j).unwrap();
        assert_eq!(back, resp);
    }

    #[test]
    fn register_response_auth_omits_empty_key() {
        let a = RegisterResponseAuth::default();
        let j = serde_json::to_string(&a).unwrap();
        assert_eq!(j, "{}");
        let keyed = RegisterResponseAuth {
            AuthKey: "tskey-abc".into(),
        };
        assert!(serde_json::to_string(&keyed).unwrap().contains("\"AuthKey\":\"tskey-abc\""));
    }
}
