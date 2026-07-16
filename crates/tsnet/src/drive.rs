//! Taildrive runtime wiring shared by PeerAPI, LocalAPI, and netmap updates.
//!
//! The runtime starts disabled. Local share configuration is replaced as one
//! validated snapshot, while a separate authorization epoch lets a netmap
//! update cancel every request authorized against the previous map.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use rand_core::{OsRng, RngCore};
use rustscale_drive::{
    AuthenticatedPeer, ConfigError, ConfigStore, Limits, Request, RequestAuthority, RequestControl,
    Response, Server, Share, Snapshot, StreamingBody,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
    /// Fresh for every process/runtime instance, so an ETag cannot be replayed
    /// after restart even when generation and configuration repeat.
    etag_nonce: [u8; 32],
    /// Serializes signed grant derivation with map/config replacement. The
    /// synchronous server commit barrier separately linearizes filesystem
    /// publication without holding this async lock during staging work.
    authorization: RwLock<()>,
}

impl Runtime {
    pub(crate) fn new() -> Arc<Self> {
        let config = Arc::new(ConfigStore::new(Limits::default()));
        let mut etag_nonce = [0u8; 32];
        OsRng.fill_bytes(&mut etag_nonce);
        Arc::new(Self {
            server: Server::new(config.clone()),
            config,
            sharing_allowed: AtomicBool::new(false),
            etag_nonce,
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
        self.status_and_etag().0
    }

    /// Return status and a strong opaque ETag derived from exactly the same
    /// immutable snapshot. The nonce is random public domain separation, not
    /// persisted state or key material.
    pub(crate) fn status_and_etag(&self) -> (RuntimeStatus, String) {
        let snapshot = self.snapshot();
        let status = RuntimeStatus {
            enabled: snapshot.enabled(),
            sharing_allowed: self.sharing_allowed(),
            generation: snapshot.generation(),
            shares: snapshot.shares().cloned().collect(),
        };
        let mut digest = Sha256::new();
        digest.update(b"rustscale-taildrive-config-etag-v1\0");
        digest.update(self.etag_nonce);
        digest.update(status.generation.to_be_bytes());
        digest.update([u8::from(status.enabled)]);
        digest.update((status.shares.len() as u64).to_be_bytes());
        for share in &status.shares {
            hash_etag_bytes(&mut digest, share.name.as_bytes());
            hash_etag_path(&mut digest, &share.path);
            hash_etag_bytes(&mut digest, share.as_user.as_bytes());
            hash_etag_bytes(&mut digest, &share.bookmark_data);
        }
        (status, hex::encode(digest.finalize()))
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

    /// Compare-and-swap the complete runtime configuration for a LocalAPI
    /// read/modify/write client. Root validation remains outside the short
    /// authorization barrier. The writer lock serializes publication with map
    /// revocation, and the opaque ETag comparison prevents lost updates and
    /// restart ABA.
    pub(crate) async fn replace_if_etag(
        self: &Arc<Self>,
        config: RuntimeConfig,
        expected_etag: &str,
    ) -> Result<u64, ReplaceError> {
        let (initial, actual_etag) = self.status_and_etag();
        if actual_etag != expected_etag {
            return Err(ReplaceError::EtagMismatch);
        }
        let expected_generation = initial.generation;
        let store = self.config.clone();
        let enabled = config.enabled;
        let prepared = tokio::task::spawn_blocking(move || store.prepare(enabled, config.shares))
            .await
            .map_err(|error| ReplaceError::Worker(error.to_string()))??;

        let mut epoch = self.authorization.write().await;
        if enabled && !self.sharing_allowed() {
            return Err(ReplaceError::SharingNotAllowed);
        }
        let (current, actual_etag) = self.status_and_etag();
        if actual_etag != expected_etag || current.generation != expected_generation {
            return Err(ReplaceError::EtagMismatch);
        }
        self.rotate_authorization_locked(&mut epoch);
        self.config
            .commit_if_generation(prepared, expected_generation)
            .map_err(ReplaceError::from)
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

fn hash_etag_bytes(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}

#[cfg(unix)]
fn hash_etag_path(digest: &mut Sha256, path: &std::path::Path) {
    use std::os::unix::ffi::OsStrExt;
    hash_etag_bytes(digest, path.as_os_str().as_bytes());
}

#[cfg(windows)]
fn hash_etag_path(digest: &mut Sha256, path: &std::path::Path) {
    use std::os::windows::ffi::OsStrExt;
    let units = path.as_os_str().encode_wide().collect::<Vec<_>>();
    digest.update((units.len() as u64).to_be_bytes());
    for unit in units {
        digest.update(unit.to_be_bytes());
    }
}

#[cfg(not(any(unix, windows)))]
fn hash_etag_path(digest: &mut Sha256, path: &std::path::Path) {
    hash_etag_bytes(digest, path.to_string_lossy().as_bytes());
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ReplaceError {
    #[error("the signed netmap does not allow this node to share Taildrive folders")]
    SharingNotAllowed,
    #[error("Taildrive configuration ETag is stale")]
    EtagMismatch,
    #[error(transparent)]
    Config(ConfigError),
    #[error("Taildrive configuration worker failed: {0}")]
    Worker(String),
}

impl From<ConfigError> for ReplaceError {
    fn from(error: ConfigError) -> Self {
        match error {
            ConfigError::GenerationMismatch { .. } => Self::EtagMismatch,
            other => Self::Config(other),
        }
    }
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
    async fn etags_are_unpredictable_across_runtime_restart() {
        let first = Runtime::new();
        let second = Runtime::new();
        let (_, first_etag) = first.status_and_etag();
        let (_, second_etag) = second.status_and_etag();
        assert_eq!(first.status().generation, second.status().generation);
        assert_ne!(first_etag, second_etag);
        assert_eq!(first_etag.len(), 64);
        assert!(first_etag.bytes().all(|byte| byte.is_ascii_hexdigit()));
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
        let before_etag = runtime.status_and_etag().1;
        runtime
            .replace_if_etag(
                RuntimeConfig {
                    enabled: true,
                    shares: vec![Share::new(
                        "docs",
                        std::fs::canonicalize(temp.path()).unwrap(),
                    )],
                },
                &before_etag,
            )
            .await
            .unwrap();
        assert_ne!(runtime.status_and_etag().1, before_etag);
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
