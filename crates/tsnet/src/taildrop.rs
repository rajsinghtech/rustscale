//! Taildrop — file transfer between tailnet nodes via the PeerAPI.
//!
//! Ports Go's `feature/taildrop/` package:
//! - `peerapi.go`: `PUT /v0/put/<filename>` receive handler (runs on the
//!   PeerAPI server, writes incoming files to a spool directory).
//! - `localapi.go`: `GET /localapi/v0/files/` (list), `GET /localapi/v0/files/<name>`
//!   (download), `DELETE /localapi/v0/files/<name>`, `GET /localapi/v0/file-targets`
//!   (peers that can receive files), `PUT /localapi/v0/file-put/<stableID>/<filename>`
//!   (daemon dials the target's PeerAPI and proxies the upload).
//! - `ext.go`: `FileTargets()` — peers with the file-sharing capability that
//!   are online and owned by the same user (or explicitly tagged as targets).
//!
//! # Spool directory
//!
//! Received files are stored in `<state_dir>/files/`. Each file is written
//! atomically (temp file → rename on completion). The spool is scanned on
//! demand to list waiting files.
//!
//! # Conflict modes (file get)
//!
//! When downloading a file that would overwrite an existing local file:
//! - `skip`: leave it in the inbox, report an error.
//! - `overwrite`: replace the local file.
//! - `rename`: write to a number-suffixed filename (e.g. `foo (1).txt`).

#![allow(non_snake_case)]

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustscale_ipn::{Notify, WaitingFile};
use rustscale_tailcfg::{Node, UserID, UserProfile};

use tokio::sync::Notify as TokioNotify;
use tokio::sync::RwLock;

/// The file-sharing node capability (Go's `tailcfg.CapabilityFileSharing`).
#[allow(dead_code)]
pub const CAP_FILE_SHARING: &str = "https://tailscale.com/cap/file-sharing";

/// The peer capability that grants the current node the ability to send
/// files to a target (Go's `tailcfg.PeerCapabilityFileSharingTarget`).
pub const CAP_PEER_FILE_SHARING_TARGET: &str = "https://tailscale.com/cap/file-sharing-target";

/// The peer capability that grants the ability to receive files from a
/// peer (Go's `tailcfg.PeerCapabilityFileSharingSend`).
#[allow(dead_code)]
pub const CAP_PEER_FILE_SHARING_SEND: &str = "https://tailscale.com/cap/file-send";

/// Maximum file size accepted by the Taildrop receive handler (1 GiB,
/// matching Go's default `maxFileSize`).
pub const MAX_FILE_SIZE: u64 = 1 << 30;

/// Default conflict behavior when a downloaded file would overwrite an
/// existing local file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConflictMode {
    Skip,
    Overwrite,
    Rename,
}

impl ConflictMode {
    /// Parse a conflict mode from a string flag value.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "" | "skip" => Ok(Self::Skip),
            "overwrite" => Ok(Self::Overwrite),
            "rename" => Ok(Self::Rename),
            other => Err(format!("{other:?} is not one of (skip|overwrite|rename)")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Skip => "skip",
            Self::Overwrite => "overwrite",
            Self::Rename => "rename",
        }
    }
}

/// A peer that can receive Taildrop files, mirroring Go's
/// `apitype.FileTarget`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FileTarget {
    /// The peer's node name (FQDN with trailing dot).
    pub Name: String,
    /// The peer's stable node ID (used in the file-put URL path).
    pub StableID: String,
    /// The peer's tailscale IP addresses.
    pub TailscaleIPs: Vec<IpAddr>,
    /// The PeerAPI base URL for dialing the peer (e.g.
    /// `http://100.64.0.2:40123`).
    pub PeerAPIURL: String,
    /// Whether the peer is currently online.
    pub Online: bool,
}

/// Error from Taildrop operations.
#[derive(Debug, thiserror::Error)]
pub enum TaildropError {
    #[error("taildrop not enabled")]
    NotEnabled,
    #[error("invalid file name: {0}")]
    InvalidFileName(String),
    #[error("file already exists: {0}")]
    FileExists(String),
    #[error("file not found: {0}")]
    FileNotFound(String),
    #[error("file too large: {size} bytes (max {max})")]
    FileTooLarge { size: u64, max: u64 },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Manages the Taildrop file spool and provides file-target enumeration.
///
/// Shared between the PeerAPI receive handler (which writes files into the
/// spool) and the LocalAPI endpoints (which list/download/delete files and
/// proxy uploads to peer PeerAPIs).
pub struct TaildropManager {
    /// The spool directory (`<state_dir>/files/`). None if taildrop is
    /// disabled (no state dir).
    spool_dir: Option<PathBuf>,
    /// Notify signal fired when a new file arrives in the spool. The
    /// `await-waiting-files` LocalAPI endpoint waits on this.
    file_arrived: Arc<TokioNotify>,
    /// Whether this node has the file-sharing capability. Set from the
    /// netmap self-node's Capabilities list.
    has_file_sharing_cap: RwLock<bool>,
    /// Our own user ID (for same-user file-target filtering).
    self_user_id: RwLock<UserID>,
    /// IPN backend bus (for emitting FilesWaiting notifies). None if not
    /// wired.
    ipn_backend: Option<Arc<rustscale_ipn::IpnBackend>>,
}

impl TaildropManager {
    /// Create a new manager. If `state_dir` is None, taildrop is disabled
    /// (all operations return `NotEnabled`).
    pub fn new(
        state_dir: Option<&Path>,
        ipn_backend: Option<Arc<rustscale_ipn::IpnBackend>>,
    ) -> Self {
        let spool_dir = state_dir.map(|d| d.join("files"));
        if let Some(ref dir) = spool_dir {
            let _ = std::fs::create_dir_all(dir);
        }
        Self {
            spool_dir,
            file_arrived: Arc::new(TokioNotify::new()),
            has_file_sharing_cap: RwLock::new(true),
            self_user_id: RwLock::new(0),
            ipn_backend,
        }
    }

    /// Whether taildrop is enabled (has a spool directory).
    pub fn enabled(&self) -> bool {
        self.spool_dir.is_some()
    }

    /// Update the file-sharing capability flag and self user ID from the
    /// netmap. Called by the map-update task when the self-node changes.
    pub async fn update_caps(&self, has_cap: bool, self_user_id: UserID) {
        *self.has_file_sharing_cap.write().await = has_cap;
        *self.self_user_id.write().await = self_user_id;
    }

    // -----------------------------------------------------------------------
    // Receiving files (PeerAPI side)
    // -----------------------------------------------------------------------

    /// Write an incoming file to the spool directory. Called by the
    /// PeerAPI `PUT /v0/put/<filename>` handler.
    ///
    /// Mirrors Go's `manager.PutFile`. If the file already exists in the
    /// spool, returns `FileExists` (409 Conflict).
    pub async fn put_file(&self, filename: &str, body: &[u8]) -> Result<u64, TaildropError> {
        let dir = self.spool_dir.as_ref().ok_or(TaildropError::NotEnabled)?;

        validate_filename(filename)?;
        if body.len() as u64 > MAX_FILE_SIZE {
            return Err(TaildropError::FileTooLarge {
                size: body.len() as u64,
                max: MAX_FILE_SIZE,
            });
        }

        let target = dir.join(filename);
        if target.exists() {
            return Err(TaildropError::FileExists(filename.to_string()));
        }

        // Write to a temp file then rename for atomicity.
        let tmp = dir.join(format!(".{filename}.partial.{}", std::process::id()));
        tokio::fs::write(&tmp, body).await?;
        tokio::fs::rename(&tmp, &target).await?;

        let size = body.len() as u64;

        // Notify watchers and emit an IPN bus message.
        self.file_arrived.notify_waiters();
        if let Some(ref backend) = self.ipn_backend {
            let files = scan_waiting_files(dir);
            backend.bus().send(Notify {
                FilesWaiting: Some(files),
                ..Default::default()
            });
        }

        Ok(size)
    }

    // -----------------------------------------------------------------------
    // Listing / reading / deleting files (LocalAPI side)
    // -----------------------------------------------------------------------

    /// List all waiting files in the spool, with their sizes.
    pub fn waiting_files(&self) -> Result<Vec<WaitingFile>, TaildropError> {
        let dir = self.spool_dir.as_ref().ok_or(TaildropError::NotEnabled)?;
        Ok(scan_waiting_files(dir))
    }

    /// Open a file from the spool for reading. Returns `(bytes, size)`.
    pub async fn open_file(&self, name: &str) -> Result<(Vec<u8>, i64), TaildropError> {
        let dir = self.spool_dir.as_ref().ok_or(TaildropError::NotEnabled)?;
        validate_filename(name)?;
        let path = dir.join(name);
        if !path.exists() {
            return Err(TaildropError::FileNotFound(name.to_string()));
        }
        let metadata = tokio::fs::metadata(&path).await?;
        let size = metadata.len() as i64;
        let bytes = tokio::fs::read(&path).await?;
        Ok((bytes, size))
    }

    /// Delete a file from the spool.
    pub async fn delete_file(&self, name: &str) -> Result<(), TaildropError> {
        let dir = self.spool_dir.as_ref().ok_or(TaildropError::NotEnabled)?;
        validate_filename(name)?;
        let path = dir.join(name);
        if !path.exists() {
            return Err(TaildropError::FileNotFound(name.to_string()));
        }
        tokio::fs::remove_file(&path).await?;
        Ok(())
    }

    /// Wait for up to `timeout` for at least one file to appear in the
    /// spool. Returns the current file list (possibly empty if the timeout
    /// elapsed). Mirrors Go's `AwaitWaitingFiles`.
    pub async fn await_waiting_files(
        &self,
        timeout: std::time::Duration,
    ) -> Result<Vec<WaitingFile>, TaildropError> {
        let files = self.waiting_files()?;
        if !files.is_empty() {
            return Ok(files);
        }
        let _ = tokio::time::timeout(timeout, self.file_arrived.notified()).await;
        self.waiting_files()
    }

    /// Get a handle to the file-arrived notify (for the long-poll endpoint).
    pub fn file_arrived_notify(&self) -> &Arc<TokioNotify> {
        &self.file_arrived
    }

    // -----------------------------------------------------------------------
    // File targets (LocalAPI side)
    // -----------------------------------------------------------------------

    /// List peers that can receive Taildrop files. Mirrors Go's
    /// `Extension.FileTargets()`.
    ///
    /// A peer is a valid target if:
    /// - It has a valid node key.
    /// - It is online.
    /// - It is owned by the same user OR has the
    ///   `PeerCapabilityFileSharingTarget` capability in its CapMap.
    /// - It advertises a PeerAPI service (or we fall back to the
    ///   deterministic port).
    pub async fn file_targets(
        &self,
        peers: &[Node],
        _user_profiles: &BTreeMap<UserID, UserProfile>,
    ) -> Result<Vec<FileTarget>, TaildropError> {
        if !*self.has_file_sharing_cap.read().await {
            return Err(TaildropError::NotEnabled);
        }

        let self_user = *self.self_user_id.read().await;
        let mut targets = Vec::new();

        for peer in peers {
            if peer.Key.is_zero() {
                continue;
            }
            // Must be online (None = unknown, treat as potentially online;
            // only skip peers explicitly marked offline).
            if peer.Online == Some(false) {
                continue;
            }

            // Same user, or explicitly tagged as a file-sharing target.
            let same_user = peer.User == self_user;
            let has_target_cap = peer_has_cap(peer, CAP_PEER_FILE_SHARING_TARGET);
            if !same_user && !has_target_cap {
                continue;
            }

            // Find the peer's primary tailscale IP (prefer v4).
            let ips: Vec<IpAddr> = peer
                .Addresses
                .iter()
                .filter_map(|s| s.split('/').next().and_then(|p| p.parse::<IpAddr>().ok()))
                .collect();
            let primary_ip = ips.iter().find(|ip| matches!(ip, IpAddr::V4(_)));
            let Some(primary_ip) = primary_ip else {
                continue;
            };

            // Derive the PeerAPI port. Check Hostinfo.Services first, then
            // fall back to the deterministic port derived from the IP.
            let port = peerapi_port_for_peer(peer, *primary_ip);
            let peerapi_url = format!("http://{primary_ip}:{port}");

            targets.push(FileTarget {
                Name: peer.Name.clone(),
                StableID: peer.StableID.clone(),
                TailscaleIPs: ips,
                PeerAPIURL: peerapi_url,
                Online: peer.Online.unwrap_or(false),
            });
        }

        targets.sort_by(|a, b| a.Name.cmp(&b.Name));
        Ok(targets)
    }
}

/// Check whether a peer's CapMap contains the given capability key.
/// Mirrors Go's `PeerCapMap.HasCapability`.
/// Scan a spool directory for waiting files. Skips hidden (temp/partial)
/// files and sorts by name.
fn scan_waiting_files(dir: &Path) -> Vec<WaitingFile> {
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') {
                continue;
            }
            let size = entry.metadata().map(|m| m.len() as i64).unwrap_or(0);
            files.push(WaitingFile {
                Name: name,
                Size: size,
            });
        }
    }
    files.sort_by(|a, b| a.Name.cmp(&b.Name));
    files
}

fn peer_has_cap(peer: &Node, cap: &str) -> bool {
    peer.CapMap.contains_key(cap)
}

/// Derive the PeerAPI port for a peer. Checks `Hostinfo.Services` for
/// `peerapi4`/`peerapi6` entries; falls back to the deterministic port
/// derived from the primary IP.
fn peerapi_port_for_peer(peer: &Node, primary_ip: IpAddr) -> u16 {
    if let Some(ref hostinfo) = peer.Hostinfo {
        let want_proto = if primary_ip.is_ipv4() {
            "peerapi4"
        } else {
            "peerapi6"
        };
        for svc in &hostinfo.Services {
            if svc.Proto == want_proto && svc.Port > 0 {
                return svc.Port;
            }
        }
    }
    // Fallback: deterministic port from the IP.
    crate::peerapi::deterministic_port(primary_ip, 0)
}

/// Validate a filename for Taildrop. Rejects:
/// - Empty names.
/// - Names containing path separators (`/`, `\`).
/// - Names containing `..` (path traversal).
/// - Names starting with `.` (hidden files).
/// - Names containing null bytes or control characters.
fn validate_filename(name: &str) -> Result<(), TaildropError> {
    if name.is_empty() {
        return Err(TaildropError::InvalidFileName("empty name".into()));
    }
    if name.starts_with('.') {
        return Err(TaildropError::InvalidFileName("starts with '.'".into()));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(TaildropError::InvalidFileName(
            "contains path separator".into(),
        ));
    }
    if name.contains("..") {
        return Err(TaildropError::InvalidFileName("contains '..'".into()));
    }
    if name.bytes().any(|b| b == 0 || b < 0x20) {
        return Err(TaildropError::InvalidFileName(
            "contains control characters".into(),
        ));
    }
    Ok(())
}

/// Resolve a filename conflict in the target directory, returning the
/// final path to write to. Mirrors Go's `openFileOrSubstitute`.
pub fn resolve_conflict(dir: &Path, name: &str, mode: ConflictMode) -> Result<PathBuf, String> {
    let target = dir.join(name);
    if !target.exists() {
        return Ok(target);
    }
    match mode {
        ConflictMode::Skip => Err(format!("refusing to overwrite file: {}", target.display())),
        ConflictMode::Overwrite => {
            std::fs::remove_file(&target)
                .map_err(|e| format!("unable to remove target file: {e}"))?;
            Ok(target)
        }
        ConflictMode::Rename => {
            let ext = Path::new(name)
                .extension()
                .map(|e| format!(".{}", e.to_string_lossy()))
                .unwrap_or_default();
            let stem = Path::new(name)
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| name.to_string());
            for i in 1..100 {
                let candidate = dir.join(format!("{stem} ({i}){ext}"));
                if !candidate.exists() {
                    return Ok(candidate);
                }
            }
            Err(format!("unable to find a name for writing {name}"))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conflict_mode_parse() {
        assert_eq!(ConflictMode::parse("skip").unwrap(), ConflictMode::Skip);
        assert_eq!(
            ConflictMode::parse("overwrite").unwrap(),
            ConflictMode::Overwrite
        );
        assert_eq!(ConflictMode::parse("rename").unwrap(), ConflictMode::Rename);
        assert_eq!(ConflictMode::parse("").unwrap(), ConflictMode::Skip);
        assert!(ConflictMode::parse("bogus").is_err());
    }

    #[test]
    fn test_validate_filename_rejects_traversal() {
        assert!(validate_filename("").is_err());
        assert!(validate_filename(".hidden").is_err());
        assert!(validate_filename("../etc/passwd").is_err());
        assert!(validate_filename("foo/bar").is_err());
        assert!(validate_filename("foo\\bar").is_err());
        assert!(validate_filename("foo\x00bar").is_err());
        assert!(validate_filename("ok-file.txt").is_ok());
        assert!(validate_filename("data.bin").is_ok());
    }

    #[tokio::test]
    async fn test_put_and_list_and_delete() {
        let tmp = tempfile::tempdir().unwrap();
        let mgr = TaildropManager::new(Some(tmp.path()), None);
        assert!(mgr.enabled());

        mgr.put_file("hello.txt", b"hello world").await.unwrap();
        let files = mgr.waiting_files().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].Name, "hello.txt");
        assert_eq!(files[0].Size, 11);

        let (bytes, size) = mgr.open_file("hello.txt").await.unwrap();
        assert_eq!(bytes, b"hello world");
        assert_eq!(size, 11);

        mgr.delete_file("hello.txt").await.unwrap();
        let files = mgr.waiting_files().unwrap();
        assert!(files.is_empty());
    }

    #[tokio::test]
    async fn test_put_file_exists_conflict() {
        let tmp = tempfile::tempdir().unwrap();
        let mgr = TaildropManager::new(Some(tmp.path()), None);
        mgr.put_file("dup.txt", b"first").await.unwrap();
        let err = mgr.put_file("dup.txt", b"second").await.unwrap_err();
        assert!(matches!(err, TaildropError::FileExists(_)));
    }

    #[tokio::test]
    async fn test_put_rejects_bad_filename() {
        let tmp = tempfile::tempdir().unwrap();
        let mgr = TaildropManager::new(Some(tmp.path()), None);
        assert!(mgr.put_file("../escape", b"x").await.is_err());
        assert!(mgr.put_file(".hidden", b"x").await.is_err());
        assert!(mgr.put_file("a/b", b"x").await.is_err());
    }

    #[tokio::test]
    async fn test_disabled_returns_not_enabled() {
        let mgr = TaildropManager::new(None, None);
        assert!(!mgr.enabled());
        let err = mgr.waiting_files().unwrap_err();
        assert!(matches!(err, TaildropError::NotEnabled));
    }

    #[tokio::test]
    async fn test_await_waiting_files_returns_immediately_if_nonempty() {
        let tmp = tempfile::tempdir().unwrap();
        let mgr = TaildropManager::new(Some(tmp.path()), None);
        mgr.put_file("f.txt", b"x").await.unwrap();
        let files = mgr
            .await_waiting_files(std::time::Duration::from_millis(10))
            .await
            .unwrap();
        assert!(!files.is_empty());
    }

    #[tokio::test]
    async fn test_await_waiting_files_times_out_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let mgr = TaildropManager::new(Some(tmp.path()), None);
        let files = mgr
            .await_waiting_files(std::time::Duration::from_millis(50))
            .await
            .unwrap();
        assert!(files.is_empty());
    }

    #[tokio::test]
    async fn test_file_targets_same_user() {
        let mgr = TaildropManager::new(None, None);
        mgr.update_caps(true, 1).await;

        let peer = Node {
            Name: "peer.tailnet.".into(),
            StableID: "NODE02".into(),
            User: 1,
            Key: rustscale_key::NodePrivate::generate().public(),
            Addresses: vec!["100.64.0.2/32".into()],
            Online: Some(true),
            ..Default::default()
        };
        let targets = mgr.file_targets(&[peer], &BTreeMap::new()).await.unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].StableID, "NODE02");
        assert!(targets[0].PeerAPIURL.starts_with("http://100.64.0.2:"));
    }

    #[tokio::test]
    async fn test_file_targets_other_user_without_cap_excluded() {
        let mgr = TaildropManager::new(None, None);
        mgr.update_caps(true, 1).await;

        let peer = Node {
            Name: "other.tailnet.".into(),
            StableID: "NODE03".into(),
            User: 2,
            Key: rustscale_key::NodePrivate::generate().public(),
            Addresses: vec!["100.64.0.3/32".into()],
            Online: Some(true),
            ..Default::default()
        };
        let targets = mgr.file_targets(&[peer], &BTreeMap::new()).await.unwrap();
        assert!(targets.is_empty());
    }

    #[tokio::test]
    async fn test_file_targets_offline_excluded() {
        let mgr = TaildropManager::new(None, None);
        mgr.update_caps(true, 1).await;

        let peer = Node {
            Name: "offline.tailnet.".into(),
            StableID: "NODE04".into(),
            User: 1,
            Key: rustscale_key::NodePrivate::generate().public(),
            Addresses: vec!["100.64.0.4/32".into()],
            Online: Some(false),
            ..Default::default()
        };
        let targets = mgr.file_targets(&[peer], &BTreeMap::new()).await.unwrap();
        assert!(targets.is_empty());
    }

    #[test]
    fn test_resolve_conflict_no_existing() {
        let tmp = tempfile::tempdir().unwrap();
        let path = resolve_conflict(tmp.path(), "new.txt", ConflictMode::Skip).unwrap();
        assert_eq!(path.file_name().unwrap(), "new.txt");
    }

    #[test]
    fn test_resolve_conflict_skip_fails() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("exists.txt"), b"x").unwrap();
        assert!(resolve_conflict(tmp.path(), "exists.txt", ConflictMode::Skip).is_err());
    }

    #[test]
    fn test_resolve_conflict_overwrite() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("exists.txt"), b"old").unwrap();
        let path = resolve_conflict(tmp.path(), "exists.txt", ConflictMode::Overwrite).unwrap();
        assert!(!path.exists());
    }

    #[test]
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    fn test_resolve_conflict_rename() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("file.txt"), b"old").unwrap();
        let path = resolve_conflict(tmp.path(), "file.txt", ConflictMode::Rename).unwrap();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with("file (1)"));
        assert!(name.ends_with(".txt"), "renamed file should keep extension");
        assert!(!path.exists());
    }
}
