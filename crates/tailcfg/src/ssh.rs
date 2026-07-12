//! SSH policy wire types — ported from Go's `tailcfg.go`.

use std::collections::BTreeMap;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{deserialize_null_to_default, skip_default, StableNodeID};

/// The policy for how to handle incoming SSH connections over Tailscale.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SSHPolicy {
    #[serde(
        default,
        rename = "rules",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Rules: Vec<SSHRule>,
}

/// An SSH rule: match predicate + action.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SSHRule {
    #[serde(
        default,
        rename = "ruleExpires",
        skip_serializing_if = "Option::is_none"
    )]
    pub RuleExpires: Option<DateTime<Utc>>,
    #[serde(
        default,
        rename = "principals",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Principals: Vec<SSHPrincipal>,
    #[serde(
        default,
        rename = "sshUsers",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub SSHUsers: BTreeMap<String, String>,
    #[serde(default, rename = "action", skip_serializing_if = "Option::is_none")]
    pub Action: Option<SSHAction>,
    #[serde(default, rename = "acceptEnv", skip_serializing_if = "skip_default")]
    pub AcceptEnv: Vec<String>,
}

/// An SSH principal identifies who may connect.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SSHPrincipal {
    #[serde(default, rename = "node", skip_serializing_if = "skip_default")]
    pub Node: StableNodeID,
    #[serde(default, rename = "nodeIP", skip_serializing_if = "skip_default")]
    pub NodeIP: String,
    #[serde(default, rename = "userLogin", skip_serializing_if = "skip_default")]
    pub UserLogin: String,
    #[serde(default, rename = "any", skip_serializing_if = "skip_default")]
    pub Any: bool,
}

/// How to handle an incoming SSH connection.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SSHAction {
    #[serde(default, rename = "message", skip_serializing_if = "skip_default")]
    pub Message: String,
    #[serde(default, rename = "reject", skip_serializing_if = "skip_default")]
    pub Reject: bool,
    #[serde(default, rename = "accept", skip_serializing_if = "skip_default")]
    pub Accept: bool,
    #[serde(
        default,
        rename = "sessionDuration",
        skip_serializing_if = "skip_default",
        with = "duration_nanos"
    )]
    pub SessionDuration: Duration,
    #[serde(
        default,
        rename = "allowAgentForwarding",
        skip_serializing_if = "skip_default"
    )]
    pub AllowAgentForwarding: bool,
    #[serde(
        default,
        rename = "holdAndDelegate",
        skip_serializing_if = "skip_default"
    )]
    pub HoldAndDelegate: String,
    #[serde(
        default,
        rename = "allowLocalPortForwarding",
        skip_serializing_if = "skip_default"
    )]
    pub AllowLocalPortForwarding: bool,
    #[serde(
        default,
        rename = "allowRemotePortForwarding",
        skip_serializing_if = "skip_default"
    )]
    pub AllowRemotePortForwarding: bool,
    #[serde(default, rename = "recorders", skip_serializing_if = "skip_default")]
    pub Recorders: Vec<String>,
    #[serde(
        default,
        rename = "onRecordingFailure",
        skip_serializing_if = "Option::is_none"
    )]
    pub OnRecordingFailure: Option<SSHRecorderFailureAction>,
}

/// Action when SSH session recording fails.
///
/// Go uses `json:",omitempty"` (no field-name override) for all fields,
/// so the JSON keys are the Go struct field names (PascalCase).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SSHRecorderFailureAction {
    #[serde(default, skip_serializing_if = "skip_default")]
    pub RejectSessionWithMessage: String,
    #[serde(default, skip_serializing_if = "skip_default")]
    pub TerminateSessionWithMessage: String,
    #[serde(default, skip_serializing_if = "skip_default")]
    pub NotifyURL: String,
}

/// Serde helper for Go's `time.Duration` which marshals as int64 nanoseconds.
/// Zero duration serializes as `null` (omitted via `skip_serializing_if`).
mod duration_nanos {
    use super::{Deserialize, Duration};
    use serde::Deserializer;

    pub fn serialize<S>(d: &Duration, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if d.is_zero() {
            return s.serialize_none();
        }
        s.serialize_i64(d.as_nanos() as i64)
    }

    pub fn deserialize<'de, D>(d: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<i64> = Option::deserialize(d)?;
        Ok(opt
            .filter(|n| *n > 0)
            .map(|n| Duration::from_nanos(n as u64))
            .unwrap_or_default())
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
        assert!(j.contains("\"reject\":true"));
        let back: SSHAction = serde_json::from_str(&j).unwrap();
        assert_eq!(back, action);
    }
    #[test]
    fn ssh_policy_empty_serializes_minimal() {
        let p = SSHPolicy::default();
        let j = serde_json::to_string(&p).unwrap();
        assert_eq!(j, "{\"rules\":[]}");
    }
}
