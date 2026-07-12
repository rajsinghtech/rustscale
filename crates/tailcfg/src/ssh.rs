//! SSH policy wire types — ported from Go's `tailcfg.go` SSHPolicy/SSHRule/
//! SSHAction/SSHPrincipal/SSHRecorderFailureAction.

use std::collections::BTreeMap;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{deserialize_null_to_default, skip_default, StableNodeID};

/// The policy for how to handle incoming SSH connections over Tailscale.
/// Mirrors Go's `tailcfg.SSHPolicy`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SSHPolicy {
    /// Rules are evaluated in order; the first matching rule's action wins.
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub Rules: Vec<SSHRule>,
}

/// An SSH rule: a match predicate (principals + ssh-users) and an associated
/// action. Mirrors Go's `tailcfg.SSHRule`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SSHRule {
    /// When this rule expires. `None` = never expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub RuleExpires: Option<DateTime<Utc>>,

    /// Principals that match an incoming connection. If any principal matches
    /// AND the SSH user matches `SSHUsers`, the rule's `Action` is applied.
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub Principals: Vec<SSHPrincipal>,

    /// Map from ssh-user (or `"*"`) => local-user. If the value is `"="`, the
    /// requested ssh-user maps directly to the local user. May be empty if
    /// `Action.Reject` is true.
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub SSHUsers: BTreeMap<String, String>,

    /// The outcome when this rule matches. `None`/invalid => deny.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub Action: Option<SSHAction>,

    /// Allowlisted environment variable names the SSH client may set.
    /// Supports `*` and `?` wildcards.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub AcceptEnv: Vec<String>,
}

/// An SSH principal identifies who may connect. Any one of the four fields
/// matching causes a principal match. Mirrors Go's `tailcfg.SSHPrincipal`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SSHPrincipal {
    /// Match by stable node ID.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Node: StableNodeID,

    /// Match by node IP.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub NodeIP: String,

    /// Match by user login name (e.g. `foo@example.com`).
    #[serde(default, skip_serializing_if = "skip_default")]
    pub UserLogin: String,

    /// If true, match any connection.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Any: bool,
}

/// How to handle an incoming SSH connection. At most one field should be
/// non-zero. Mirrors Go's `tailcfg.SSHAction`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SSHAction {
    /// Message shown to the user before the action occurs.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Message: String,

    /// If true, terminate the connection.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Reject: bool,

    /// If true, accept the connection immediately.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Accept: bool,

    /// How long the session may stay open before forced termination.
    #[serde(default, skip_serializing_if = "skip_default", with = "duration_secs")]
    pub SessionDuration: Duration,

    /// Allow SSH agent forwarding.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub AllowAgentForwarding: bool,

    /// If non-empty, a URL to long-poll for an outcome verdict. The connection
    /// is accepted and blocks until the URL serves a new `SSHAction`.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub HoldAndDelegate: String,

    /// Allow local port forwarding.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub AllowLocalPortForwarding: bool,

    /// Allow remote port forwarding.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub AllowRemotePortForwarding: bool,

    /// SSH session recorder destinations (`addr:port`).
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Recorders: Vec<String>,

    /// Action to take if recording fails.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub OnRecordingFailure: Option<SSHRecorderFailureAction>,
}

/// Action when SSH session recording fails. Mirrors Go's
/// `tailcfg.SSHRecorderFailureAction`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SSHRecorderFailureAction {
    /// If non-empty, reject the session when recording fails to start.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub RejectSessionWithMessage: String,

    /// If non-empty, terminate the session when recording fails mid-stream.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub TerminateSessionWithMessage: String,

    /// URL to notify about the recording failure.
    #[serde(default, skip_serializing_if = "skip_default")]
    pub NotifyURL: String,
}

/// Serde module for `Duration` ↔ seconds (Go uses `time.Duration` in
/// nanoseconds with `format:nano`, but for SSH session durations seconds
/// granularity is sufficient and avoids overflow issues).
mod duration_secs {
    use std::time::Duration;

    use serde::Deserialize;

    pub fn serialize<S>(d: &Duration, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if d.is_zero() {
            return s.serialize_none();
        }
        s.serialize_u64(d.as_secs())
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Duration, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let opt: Option<u64> = Option::deserialize(d)?;
        Ok(opt.map(Duration::from_secs).unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_policy_roundtrip() {
        let policy = SSHPolicy {
            Rules: vec![SSHRule {
                Principals: vec![SSHPrincipal {
                    Any: true,
                    ..Default::default()
                }],
                SSHUsers: {
                    let mut m = BTreeMap::new();
                    m.insert("*".into(), "=".into());
                    m
                },
                Action: Some(SSHAction {
                    Accept: true,
                    Message: "Welcome".into(),
                    ..Default::default()
                }),
                AcceptEnv: vec!["TERM".into(), "LANG".into()],
                ..Default::default()
            }],
        };
        let j = serde_json::to_string(&policy).unwrap();
        let back: SSHPolicy = serde_json::from_str(&j).unwrap();
        assert_eq!(back, policy);
    }

    #[test]
    fn ssh_action_reject_roundtrip() {
        let action = SSHAction {
            Reject: true,
            Message: "Access denied".into(),
            ..Default::default()
        };
        let j = serde_json::to_string(&action).unwrap();
        assert!(j.contains("\"Reject\":true"));
        assert!(j.contains("\"Message\":\"Access denied\""));
        let back: SSHAction = serde_json::from_str(&j).unwrap();
        assert_eq!(back, action);
    }

    #[test]
    fn ssh_principal_node_match() {
        let p = SSHPrincipal {
            Node: "nodeABC".into(),
            ..Default::default()
        };
        let j = serde_json::to_string(&p).unwrap();
        assert!(j.contains("\"Node\":\"nodeABC\""));
        let back: SSHPrincipal = serde_json::from_str(&j).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn ssh_policy_empty_serializes_minimal() {
        let p = SSHPolicy::default();
        let j = serde_json::to_string(&p).unwrap();
        assert_eq!(j, "{\"Rules\":[]}");
    }
}
