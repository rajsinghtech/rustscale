//! Taildrive runtime wiring shared by PeerAPI, LocalAPI, and netmap updates.
//!
//! The runtime starts disabled. Local share configuration is replaced as one
//! validated snapshot, while a separate authorization epoch lets a netmap
//! update cancel every request authorized against the previous map.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use rustscale_drive::{
    AuthenticatedPeer, ConfigError, ConfigStore, Limits, Request, RequestAuthority, RequestControl,
    Response, Server, Share, Snapshot, StreamingBody,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Maximum encoded LocalAPI configuration body.
pub(crate) const MAX_CONFIG_BODY: usize = 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimeConfig {
    pub(crate) enabled: bool,
    #[serde(default)]
    pub(crate) shares: Vec<Share>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RuntimeStatus {
    pub(crate) enabled: bool,
    pub(crate) sharing_allowed: bool,
    pub(crate) generation: u64,
    pub(crate) shares: Vec<Share>,
}

/// Live Taildrive state. There is one instance for the full `Server` lifetime,
/// including the needs-login LocalAPI phase.
pub(crate) struct Runtime {
    config: Arc<ConfigStore>,
    server: Server,
    sharing_allowed: AtomicBool,
    /// Serializes signed grant derivation with map/config replacement. The
    /// synchronous server commit barrier separately linearizes filesystem
    /// publication without holding this async lock during staging work.
    authorization: RwLock<()>,
}

impl Runtime {
    pub(crate) fn new() -> Arc<Self> {
        let config = Arc::new(ConfigStore::new(Limits::default()));
        Arc::new(Self {
            server: Server::new(config.clone()),
            config,
            sharing_allowed: AtomicBool::new(false),
            authorization: RwLock::new(()),
        })
    }

    pub(crate) fn limits(&self) -> &Limits {
        self.config.limits()
    }

    pub(crate) fn snapshot(&self) -> Arc<Snapshot> {
        self.config.snapshot()
    }

    pub(crate) fn sharing_allowed(&self) -> bool {
        self.sharing_allowed.load(Ordering::Acquire)
    }

    pub(crate) fn status(&self) -> RuntimeStatus {
        let snapshot = self.snapshot();
        RuntimeStatus {
            enabled: snapshot.enabled(),
            sharing_allowed: self.sharing_allowed(),
            generation: snapshot.generation(),
            shares: snapshot.shares().cloned().collect(),
        }
    }

    pub(crate) async fn authorization_read(&self) -> RwLockReadGuard<'_, ()> {
        self.authorization.read().await
    }

    pub(crate) async fn authorization_write(&self) -> RwLockWriteGuard<'_, ()> {
        self.authorization.write().await
    }

    /// Capture one request authority while the caller holds the authorization
    /// read lock used for signed map/grant derivation.
    pub(crate) fn request_authority_locked(
        &self,
        _guard: &RwLockReadGuard<'_, ()>,
    ) -> RequestAuthority {
        self.server.request_authority()
    }

    /// Apply the self-node `drive:share` attribute while a map-update writer
    /// guard is held. Revocation also drops every configured root immediately.
    pub(crate) fn set_sharing_allowed_locked(
        &self,
        allowed: bool,
        _guard: &mut RwLockWriteGuard<'_, ()>,
    ) {
        self.sharing_allowed.store(allowed, Ordering::Release);
        if !allowed {
            self.config.disable();
        }
    }

    /// Cancel old staging work, drain old publication critical sections, and
    /// start a fresh commit epoch. The caller holds the authorization writer
    /// across this call and the following map/config state replacement, so new
    /// request authority cannot observe a partially installed epoch.
    pub(crate) fn rotate_authorization_locked(&self, _guard: &mut RwLockWriteGuard<'_, ()>) {
        self.server.revoke_authority();
    }

    /// Replace the complete runtime configuration. Validation and root opening
    /// happen before ConfigStore's atomic commit. The authorization writer lock
    /// serializes this with map revocation and prevents a request from being
    /// authorized between the commit and cancellation of the old snapshot.
    pub(crate) async fn replace(
        self: &Arc<Self>,
        config: RuntimeConfig,
    ) -> Result<u64, ReplaceError> {
        let store = self.config.clone();
        let enabled = config.enabled;
        let prepared = tokio::task::spawn_blocking(move || store.prepare(enabled, config.shares))
            .await
            .map_err(|error| ReplaceError::Worker(error.to_string()))??;

        let mut epoch = self.authorization.write().await;
        if enabled && !self.sharing_allowed() {
            return Err(ReplaceError::SharingNotAllowed);
        }
        self.rotate_authorization_locked(&mut epoch);
        Ok(self.config.commit(prepared))
    }

    /// Synchronously revoke all request authority for terminal Drop cleanup.
    /// This deliberately bypasses the async serialization gate: Drop has
    /// already removed the owning Server generation and must fail closed even
    /// if a stale request is holding that gate forever.
    pub(crate) fn disable_terminal(&self) {
        self.server.revoke_authority();
        self.sharing_allowed.store(false, Ordering::Release);
        self.config.disable();
    }

    /// Disable sharing and cancel every active Taildrive request.
    pub(crate) async fn disable(&self) {
        let mut epoch = self.authorization.write().await;
        self.rotate_authorization_locked(&mut epoch);
        self.sharing_allowed.store(false, Ordering::Release);
        self.config.disable();
    }

    pub(crate) fn preflight(
        &self,
        peer: &AuthenticatedPeer,
        request: &Request,
    ) -> Result<(), Response> {
        self.server.preflight(peer, request)
    }

    pub(crate) fn handle(
        &self,
        peer: &AuthenticatedPeer,
        request: Request,
        control: &RequestControl,
    ) -> Response {
        self.server.handle(peer, request, control)
    }

    pub(crate) fn handle_streaming_put(
        &self,
        peer: &AuthenticatedPeer,
        request: Request,
        body: StreamingBody,
        control: &RequestControl,
    ) -> Response {
        self.server
            .handle_streaming_put(peer, request, body, control)
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ReplaceError {
    #[error("the signed netmap does not allow this node to share Taildrive folders")]
    SharingNotAllowed,
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("Taildrive configuration worker failed: {0}")]
    Worker(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn disabled_by_default_and_epoch_rotation_revokes_children() {
        let runtime = Runtime::new();
        let status = runtime.status();
        assert!(!status.enabled);
        assert!(!status.sharing_allowed);
        assert!(status.shares.is_empty());

        let old = {
            let epoch = runtime.authorization_read().await;
            runtime.request_authority_locked(&epoch).cancellation()
        };
        let mut epoch = runtime.authorization_write().await;
        runtime.rotate_authorization_locked(&mut epoch);
        drop(epoch);
        assert!(old.is_cancelled());

        let current = {
            let epoch = runtime.authorization_read().await;
            runtime.request_authority_locked(&epoch).cancellation()
        };
        assert!(!current.is_cancelled());
    }

    #[tokio::test]
    async fn self_capability_revocation_clears_roots_and_active_epoch() {
        let runtime = Runtime::new();
        {
            let mut epoch = runtime.authorization_write().await;
            runtime.rotate_authorization_locked(&mut epoch);
            runtime.set_sharing_allowed_locked(true, &mut epoch);
        }
        let temp = tempfile::tempdir().unwrap();
        runtime
            .replace(RuntimeConfig {
                enabled: true,
                shares: vec![Share::new(
                    "docs",
                    std::fs::canonicalize(temp.path()).unwrap(),
                )],
            })
            .await
            .unwrap();
        let active = {
            let epoch = runtime.authorization_read().await;
            runtime.request_authority_locked(&epoch).cancellation()
        };

        let mut epoch = runtime.authorization_write().await;
        runtime.rotate_authorization_locked(&mut epoch);
        runtime.set_sharing_allowed_locked(false, &mut epoch);
        drop(epoch);

        assert!(active.is_cancelled());
        let status = runtime.status();
        assert!(!status.sharing_allowed);
        assert!(!status.enabled);
        assert!(status.shares.is_empty());
    }
}
