//! Client audit-log wire types, ported from Go's `tailcfg.go`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{deserialize_null_to_default, skip_default, CapabilityVersion, NodeKey};

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_epoch_time(v: &DateTime<Utc>) -> bool {
    *v == DateTime::UNIX_EPOCH
}

/// An auditable client action recognized by the control plane.
pub type ClientAuditAction = String;

/// Audit action emitted when a node intentionally disconnects.
#[allow(non_upper_case_globals)]
pub const AuditNodeDisconnect: &str = "DISCONNECT_NODE";

/// Uppercase alias following Rust's usual constant naming convention.
pub const AUDIT_NODE_DISCONNECT: &str = AuditNodeDisconnect;

/// An audit event delivered to `POST /machine/audit-log` over the Noise
/// control connection.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditLogRequest {
    /// Client capability version.
    #[serde(
        default,
        skip_serializing_if = "skip_default",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Version: CapabilityVersion,
    /// Current client node key.
    #[serde(
        default,
        skip_serializing_if = "NodeKey::is_zero",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub NodeKey: NodeKey,
    /// The auditable action.
    #[serde(
        default,
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Action: ClientAuditAction,
    /// Action-specific opaque details.
    #[serde(
        default,
        skip_serializing_if = "String::is_empty",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Details: String,
    /// Time at which the client generated the event.
    #[serde(
        default,
        skip_serializing_if = "is_epoch_time",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub Timestamp: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use rustscale_key::NodePublic;

    use super::{AuditLogRequest, AUDIT_NODE_DISCONNECT};

    #[test]
    fn audit_log_request_json_uses_go_field_names() {
        let request = AuditLogRequest {
            Version: 141,
            NodeKey: NodePublic::from_raw32([7; 32]),
            Action: AUDIT_NODE_DISCONNECT.to_string(),
            Details: "cli".to_string(),
            Timestamp: Utc.with_ymd_and_hms(2026, 7, 13, 12, 34, 56).unwrap(),
        };

        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            concat!(
                r#"{"Version":141,"NodeKey":"nodekey:"#,
                "0707070707070707070707070707070707070707070707070707070707070707",
                r#"","Action":"DISCONNECT_NODE","Details":"cli","Timestamp":"2026-07-13T12:34:56Z"}"#
            )
        );
    }

    #[test]
    fn audit_log_request_accepts_go_compatible_omitted_timestamp() {
        let request: AuditLogRequest = serde_json::from_str(concat!(
            r#"{"Version":141,"NodeKey":"nodekey:"#,
            "0808080808080808080808080808080808080808080808080808080808080808",
            r#"","Action":"DISCONNECT_NODE","Details":"cli"}"#,
        ))
        .unwrap();

        assert_eq!(request.Timestamp, chrono::DateTime::UNIX_EPOCH);
        assert!(!serde_json::to_string(&request)
            .unwrap()
            .contains("Timestamp"));
    }
}
