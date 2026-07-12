//! SSH policy wire types — ported from Go's `tailcfg.go`.

use std::collections::BTreeMap;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{deserialize_null_to_default, skip_default, StableNodeID};

/// The policy for how to handle incoming SSH connections over Tailscale.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SSHPolicy {
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub Rules: Vec<SSHRule>,
}

/// An SSH rule: match predicate + action.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SSHRule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub RuleExpires: Option<DateTime<Utc>>,
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub Principals: Vec<SSHPrincipal>,
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub SSHUsers: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub Action: Option<SSHAction>,
    #[serde(default, skip_serializing_if = "skip_default")]
    pub AcceptEnv: Vec<String>,
}

/// An SSH principal identifies who may connect.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SSHPrincipal {
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Node: StableNodeID,
    #[serde(default, skip_serializing_if = "skip_default")]
    pub NodeIP: String,
    #[serde(default, skip_serializing_if = "skip_default")]
    pub UserLogin: String,
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Any: bool,
}

/// How to handle an incoming SSH connection.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SSHAction {
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Message: String,
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Reject: bool,
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Accept: bool,
    #[serde(default, skip_serializing_if = "skip_default", with = "duration_secs")]
    pub SessionDuration: Duration,
    #[serde(default, skip_serializing_if = "skip_default")]
    pub AllowAgentForwarding: bool,
    #[serde(default, skip_serializing_if = "skip_default")]
    pub HoldAndDelegate: String,
    #[serde(default, skip_serializing_if = "skip_default")]
    pub AllowLocalPortForwarding: bool,
    #[serde(default, skip_serializing_if = "skip_default")]
    pub AllowRemotePortForwarding: bool,
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Recorders: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub OnRecordingFailure: Option<SSHRecorderFailureAction>,
}

/// Action when SSH session recording fails.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SSHRecorderFailureAction {
    #[serde(default, skip_serializing_if = "skip_default")]
    pub RejectSessionWithMessage: String,
    #[serde(default, skip_serializing_if = "skip_default")]
    pub TerminateSessionWithMessage: String,
    #[serde(default, skip_serializing_if = "skip_default")]
    pub NotifyURL: String,
}

mod duration_secs {
    use super::{Deserialize, Duration};
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
        let back: SSHAction = serde_json::from_str(&j).unwrap();
        assert_eq!(back, action);
    }
    #[test]
    fn ssh_policy_empty_serializes_minimal() {
        let p = SSHPolicy::default();
        let j = serde_json::to_string(&p).unwrap();
        assert_eq!(j, "{\"Rules\":[]}");
    }
}
