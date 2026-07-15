//! Taildrive runtime wiring shared by PeerAPI, LocalAPI, and netmap updates.
//!
//! The runtime starts disabled. Local share configuration is replaced as one
//! validated snapshot, while a separate authorization epoch lets a netmap
//! update cancel every request authorized against the previous map.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use rustscale_drive::{
    AuthenticatedPeer, ConfigError, ConfigStore, Limits, Request, RequestControl, Response, Server,
    Share, Snapshot,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use tokio_util::sync::CancellationToken;

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
    /// Requests hold a child of the token protected by this lock. A map update
    /// takes the write lock while replacing peer/filter state, then cancels and
    /// replaces the token before allowing new authorization decisions.
    authorization: RwLock<CancellationToken>,
}

impl Runtime {
    pub(crate) fn new() -> Arc<Self> {
        let config = Arc::new(ConfigStore::new(Limits::default()));
        Arc::new(Self {
            server: Server::new(config.clone()),
            config,
            sharing_allowed: AtomicBool::new(false),
            authorization: RwLock::new(CancellationToken::new()),
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

    pub(crate) async fn authorization_read(&self) -> RwLockReadGuard<'_, CancellationToken> {
        self.authorization.read().await
    }

    pub(crate) async fn authorization_write(&self) -> RwLockWriteGuard<'_, CancellationToken> {
        self.authorization.write().await
    }

    pub(crate) fn child_cancellation(epoch: &CancellationToken) -> CancellationToken {
        epoch.child_token()
    }

    /// Apply the self-node `drive:share` attribute while a map-update writer
    /// guard is held. Revocation also drops every configured root immediately.
    pub(crate) fn set_sharing_allowed_locked(
        &self,
        allowed: bool,
        _guard: &mut RwLockWriteGuard<'_, CancellationToken>,
    ) {
        self.sharing_allowed.store(allowed, Ordering::Release);
        if !allowed {
            self.config.disable();
        }
    }

    /// Cancel all requests authorized under the old map and start a fresh
    /// epoch. The caller must already have atomically installed the new map
    /// authorization state while holding `guard`.
    pub(crate) fn rotate_authorization_locked(guard: &mut RwLockWriteGuard<'_, CancellationToken>) {
        guard.cancel();
        **guard = CancellationToken::new();
    }

    /// Replace the complete runtime configuration. Validation and root opening
    /// happen before ConfigStore's atomic commit. The authorization writer lock
    /// serializes this with map revocation and prevents a request from being
    /// authorized between the commit and cancellation of the old snapshot.
    pub(crate) async fn replace(
        self: &Arc<Self>,
        config: RuntimeConfig,
    ) -> Result<u64, ReplaceError> {
        let mut epoch = self.authorization.write().await;
        if config.enabled && !self.sharing_allowed() {
            return Err(ReplaceError::SharingNotAllowed);
        }
        let store = self.config.clone();
        let result =
            tokio::task::spawn_blocking(move || store.replace(config.enabled, config.shares))
                .await
                .map_err(|error| ReplaceError::Worker(error.to_string()))?;
        let generation = result?;
        Self::rotate_authorization_locked(&mut epoch);
        Ok(generation)
    }

    /// Disable sharing and cancel every active Taildrive request.
    pub(crate) async fn disable(&self) {
        let mut epoch = self.authorization.write().await;
        self.sharing_allowed.store(false, Ordering::Release);
        self.config.disable();
        Self::rotate_authorization_locked(&mut epoch);
    }

    pub(crate) fn handle(
        &self,
        peer: &AuthenticatedPeer,
        request: Request,
        control: &RequestControl,
    ) -> Response {
        self.server.handle(peer, request, control)
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
            Runtime::child_cancellation(&epoch)
        };
        let mut epoch = runtime.authorization_write().await;
        Runtime::rotate_authorization_locked(&mut epoch);
        drop(epoch);
        assert!(old.is_cancelled());

        let current = {
            let epoch = runtime.authorization_read().await;
            Runtime::child_cancellation(&epoch)
        };
        assert!(!current.is_cancelled());
    }

    #[tokio::test]
    async fn self_capability_revocation_clears_roots_and_active_epoch() {
        let runtime = Runtime::new();
        {
            let mut epoch = runtime.authorization_write().await;
            runtime.set_sharing_allowed_locked(true, &mut epoch);
            Runtime::rotate_authorization_locked(&mut epoch);
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
            Runtime::child_cancellation(&epoch)
        };

        let mut epoch = runtime.authorization_write().await;
        runtime.set_sharing_allowed_locked(false, &mut epoch);
        Runtime::rotate_authorization_locked(&mut epoch);
        drop(epoch);

        assert!(active.is_cancelled());
        let status = runtime.status();
        assert!(!status.sharing_allowed);
        assert!(!status.enabled);
        assert!(status.shares.is_empty());
    }
}
