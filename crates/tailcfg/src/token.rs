//! OIDC identity-token request and response wire types.
//!
//! These are JSON encoded over the Noise control channel at
//! `POST /machine/id-token`.

use serde::{Deserialize, Serialize};

use crate::CapabilityVersion;
use rustscale_key::NodePublic;

/// A request for an OIDC ID token scoped to `Audience`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRequest {
    /// Client capability version.
    pub CapVersion: CapabilityVersion,
    /// Public key of the requesting node.
    pub NodeKey: NodePublic,
    /// Resource-provider audience for the token.
    pub Audience: String,
}

/// The control plane's response to a [`TokenRequest`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenResponse {
    /// Signed OIDC JWT.
    #[serde(rename = "id_token")]
    pub IDToken: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustscale_key::NodePrivate;

    #[test]
    fn wire_shape_matches_go() {
        let node_key = NodePrivate::generate().public();
        let request = TokenRequest {
            CapVersion: 141,
            NodeKey: node_key.clone(),
            Audience: "https://service.example".into(),
        };
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(value["CapVersion"], 141);
        assert_eq!(value["NodeKey"], node_key.to_string());
        assert_eq!(value["Audience"], "https://service.example");

        let response = TokenResponse {
            IDToken: "header.payload.signature".into(),
        };
        assert_eq!(
            serde_json::to_value(&response).unwrap(),
            serde_json::json!({"id_token": "header.payload.signature"})
        );
    }
}
