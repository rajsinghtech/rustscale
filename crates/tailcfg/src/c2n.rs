use serde::{Deserialize, Serialize};

/// Device identity information returned by `GET /posture/identity`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct C2NPostureIdentityResponse {
    /// Serial numbers reported by the local platform.
    #[serde(
        rename = "SerialNumbers",
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "crate::deserialize_null_to_default"
    )]
    pub serial_numbers: Vec<String>,
    /// MAC addresses from non-loopback local interfaces.
    #[serde(
        rename = "IfaceHardwareAddrs",
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "crate::deserialize_null_to_default"
    )]
    pub iface_hardware_addrs: Vec<String>,
    /// Whether the node has opted out of device posture collection.
    #[serde(
        rename = "PostureDisabled",
        default,
        skip_serializing_if = "is_false",
        deserialize_with = "crate::deserialize_null_to_default"
    )]
    pub posture_disabled: bool,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(value: &bool) -> bool {
    !value
}

#[cfg(test)]
mod tests {
    use super::C2NPostureIdentityResponse;

    #[test]
    fn c2n_posture_identity_response_roundtrip() {
        let response = C2NPostureIdentityResponse {
            serial_numbers: vec!["serial-1".into()],
            iface_hardware_addrs: vec!["00:11:22:33:44:55".into()],
            posture_disabled: false,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert_eq!(
            json,
            r#"{"SerialNumbers":["serial-1"],"IfaceHardwareAddrs":["00:11:22:33:44:55"]}"#
        );
        assert_eq!(
            serde_json::from_str::<C2NPostureIdentityResponse>(&json).unwrap(),
            response
        );
        assert_eq!(
            serde_json::from_str::<C2NPostureIdentityResponse>(
                r#"{"SerialNumbers":null,"IfaceHardwareAddrs":null,"PostureDisabled":null}"#
            )
            .unwrap(),
            C2NPostureIdentityResponse::default()
        );
    }
}
