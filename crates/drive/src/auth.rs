use std::collections::BTreeMap;

use serde::Deserialize;

use crate::{config::Limits, path::normalize_share_name};

/// Effective access to one share.
#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub enum Permission {
    #[default]
    None,
    ReadOnly,
    ReadWrite,
}

/// Taildrive permissions derived from authenticated peer capability grants.
#[derive(Clone, Debug, Default)]
pub struct Permissions(BTreeMap<String, Permission>);

impl Permissions {
    pub fn for_share(&self, share: &str) -> Permission {
        self.0
            .get(share)
            .copied()
            .unwrap_or_default()
            .max(self.0.get("*").copied().unwrap_or_default())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    shares: Vec<String>,
    access: String,
}

/// Identity and authorization material supplied by a trusted PeerAPI adapter.
///
/// This type can only be constructed by parsing the capability values attached
/// to an authenticated peer. HTTP headers, query parameters, and paths are not
/// consulted, preventing a WebDAV client from selecting another principal.
#[derive(Clone, Debug)]
pub struct AuthenticatedPeer {
    node_key: String,
    permissions: Permissions,
}

impl AuthenticatedPeer {
    /// Parse `tailscale.com/cap/drive` values for an authenticated netmap peer.
    pub fn from_capability_grants(
        node_key: impl Into<String>,
        raw_grants: &[Vec<u8>],
        limits: &Limits,
    ) -> Result<Self, AuthError> {
        let node_key = node_key.into();
        if node_key.trim().is_empty() {
            return Err(AuthError::Unauthenticated);
        }
        if raw_grants.len() > limits.max_grants {
            return Err(AuthError::TooManyGrants);
        }

        let mut total = 0usize;
        let mut permissions = Permissions::default();
        for raw in raw_grants {
            total = total
                .checked_add(raw.len())
                .ok_or(AuthError::GrantsTooLarge)?;
            if total > limits.max_grant_bytes {
                return Err(AuthError::GrantsTooLarge);
            }
            let grant: Grant = serde_json::from_slice(raw).map_err(AuthError::MalformedGrant)?;
            if grant.shares.len() > limits.max_shares {
                return Err(AuthError::TooManyShares);
            }
            let permission = match grant.access.as_str() {
                "ro" => Permission::ReadOnly,
                "rw" => Permission::ReadWrite,
                _ => return Err(AuthError::InvalidAccess(grant.access)),
            };
            for share in grant.shares {
                let share = if share == "*" {
                    share
                } else {
                    let canonical = normalize_share_name(&share)
                        .map_err(|_| AuthError::InvalidShare(share.clone()))?;
                    if canonical != share {
                        return Err(AuthError::NonCanonicalShare(share));
                    }
                    share
                };
                permissions
                    .0
                    .entry(share)
                    .and_modify(|current| *current = (*current).max(permission))
                    .or_insert(permission);
            }
        }

        Ok(Self {
            node_key,
            permissions,
        })
    }

    pub fn node_key(&self) -> &str {
        &self.node_key
    }

    pub fn permissions(&self) -> &Permissions {
        &self.permissions
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("peer identity is not authenticated")]
    Unauthenticated,
    #[error("too many Taildrive grants")]
    TooManyGrants,
    #[error("Taildrive grants exceed the configured byte limit")]
    GrantsTooLarge,
    #[error("Taildrive grant contains too many shares")]
    TooManyShares,
    #[error("malformed Taildrive grant: {0}")]
    MalformedGrant(serde_json::Error),
    #[error("invalid Taildrive access value {0:?}")]
    InvalidAccess(String),
    #[error("invalid share name in Taildrive grant: {0:?}")]
    InvalidShare(String),
    #[error("Taildrive grant selector is not canonical: {0:?}")]
    NonCanonicalShare(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permissions_merge_specific_and_wildcard() {
        let limits = Limits::default();
        let peer = AuthenticatedPeer::from_capability_grants(
            "nodekey:peer",
            &[
                br#"{"shares":["*"],"access":"ro"}"#.to_vec(),
                br#"{"shares":["docs"],"access":"rw"}"#.to_vec(),
            ],
            &limits,
        )
        .unwrap();
        assert_eq!(peer.permissions().for_share("docs"), Permission::ReadWrite);
        assert_eq!(peer.permissions().for_share("other"), Permission::ReadOnly);
    }

    #[test]
    fn noncanonical_selectors_never_broaden_authority() {
        for selector in ["Docs", " docs", "docs ", "DOCS"] {
            let raw = format!(r#"{{"shares":["{selector}"],"access":"rw"}}"#);
            assert!(matches!(
                AuthenticatedPeer::from_capability_grants(
                    "nodekey:peer",
                    &[raw.into_bytes()],
                    &Limits::default(),
                ),
                Err(AuthError::NonCanonicalShare(_))
            ));
        }
        assert!(AuthenticatedPeer::from_capability_grants(
            "nodekey:peer",
            &[br#"{"shares":["*"],"access":"ro"}"#.to_vec()],
            &Limits::default(),
        )
        .is_ok());
    }

    #[test]
    fn malformed_or_oversized_grants_fail_closed() {
        let limits = Limits {
            max_grant_bytes: 8,
            ..Limits::default()
        };
        assert!(AuthenticatedPeer::from_capability_grants(
            "nodekey:peer",
            &[br#"{"shares":["*"],"access":"rw"}"#.to_vec()],
            &limits,
        )
        .is_err());
        assert!(AuthenticatedPeer::from_capability_grants(
            "",
            &[br#"{"shares":["*"],"access":"rw"}"#.to_vec()],
            &Limits::default(),
        )
        .is_err());
        assert!(AuthenticatedPeer::from_capability_grants(
            "nodekey:peer",
            &[br#"{"shares":["*"],"access":"owner"}"#.to_vec()],
            &Limits::default(),
        )
        .is_err());
    }
}
