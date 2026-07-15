//! Tailnet Lock control-plane JSON wire types.
//!
//! Binary CBOR signatures and AUMs are base64 strings in JSON, matching Go's
//! `tkatype.MarshaledSignature` and `tkatype.MarshaledAUM` aliases.

use std::collections::BTreeMap;

use rustscale_key::NodePublic;
use serde::{Deserialize, Serialize};

use crate::{deserialize_null_to_default, skip_default, CapabilityVersion, NodeID};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TKAInfo {
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Head: String,
    #[serde(default, skip_serializing_if = "skip_default")]
    pub Disabled: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TKAInitBeginRequest {
    pub Version: CapabilityVersion,
    pub NodeKey: NodePublic,
    #[serde(with = "crate::base64_vec")]
    pub GenesisAUM: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TKASignInfo {
    pub NodeID: NodeID,
    pub NodePublic: NodePublic,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "crate::base64_vec"
    )]
    pub RotationPubkey: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TKAInitBeginResponse {
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub NeedSignatures: Vec<TKASignInfo>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TKAInitFinishRequest {
    pub Version: CapabilityVersion,
    pub NodeKey: NodePublic,
    #[serde(with = "signature_map")]
    pub Signatures: BTreeMap<NodeID, Vec<u8>>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "crate::base64_vec"
    )]
    pub SupportDisablement: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TKAInitFinishResponse {}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TKABootstrapRequest {
    pub Version: CapabilityVersion,
    pub NodeKey: NodePublic,
    #[serde(default)]
    pub Head: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TKABootstrapResponse {
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "crate::base64_vec"
    )]
    pub GenesisAUM: Vec<u8>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "crate::base64_vec"
    )]
    pub DisablementSecret: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TKASyncOfferRequest {
    pub Version: CapabilityVersion,
    pub NodeKey: NodePublic,
    pub Head: String,
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub Ancestors: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TKASyncOfferResponse {
    pub Head: String,
    #[serde(default, deserialize_with = "deserialize_null_to_default")]
    pub Ancestors: Vec<String>,
    #[serde(default, with = "base64_vec_vec")]
    pub MissingAUMs: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TKASyncSendRequest {
    pub Version: CapabilityVersion,
    pub NodeKey: NodePublic,
    pub Head: String,
    #[serde(default, with = "base64_vec_vec")]
    pub MissingAUMs: Vec<Vec<u8>>,
    #[serde(default)]
    pub Interactive: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TKASyncSendResponse {
    pub Head: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TKADisableRequest {
    pub Version: CapabilityVersion,
    pub NodeKey: NodePublic,
    pub Head: String,
    #[serde(with = "crate::base64_vec")]
    pub DisablementSecret: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TKADisableResponse {}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TKASubmitSignatureRequest {
    pub Version: CapabilityVersion,
    pub NodeKey: NodePublic,
    #[serde(with = "crate::base64_vec")]
    pub Signature: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TKASubmitSignatureResponse {}

mod base64_vec_vec {
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(values: &[Vec<u8>], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded: Vec<String> = values
            .iter()
            .map(|value| base64::engine::general_purpose::STANDARD.encode(value))
            .collect();
        encoded.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = Option::<Vec<String>>::deserialize(deserializer)?.unwrap_or_default();
        values
            .into_iter()
            .map(|value| {
                base64::engine::general_purpose::STANDARD
                    .decode(value)
                    .map_err(serde::de::Error::custom)
            })
            .collect()
    }
}

mod signature_map {
    use std::collections::BTreeMap;

    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::NodeID;

    pub fn serialize<S>(
        values: &BTreeMap<NodeID, Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded: BTreeMap<NodeID, String> = values
            .iter()
            .map(|(id, value)| (*id, base64::engine::general_purpose::STANDARD.encode(value)))
            .collect();
        encoded.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BTreeMap<NodeID, Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = BTreeMap::<NodeID, String>::deserialize(deserializer)?;
        values
            .into_iter()
            .map(|(id, value)| {
                base64::engine::general_purpose::STANDARD
                    .decode(value)
                    .map(|decoded| (id, decoded))
                    .map_err(serde::de::Error::custom)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_fields_are_go_base64_strings() {
        let request = TKAInitBeginRequest {
            Version: 141,
            NodeKey: NodePublic::from_raw32([1; 32]),
            GenesisAUM: vec![0xde, 0xad],
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"GenesisAUM\":\"3q0=\""));
        assert_eq!(
            serde_json::from_str::<TKAInitBeginRequest>(&json).unwrap(),
            request
        );
    }

    #[test]
    fn tka_info_null_tolerant_collections() {
        let response: TKASyncOfferResponse =
            serde_json::from_str(r#"{"Head":"h","Ancestors":null,"MissingAUMs":null}"#).unwrap();
        assert!(response.Ancestors.is_empty());
        assert!(response.MissingAUMs.is_empty());
    }
}
