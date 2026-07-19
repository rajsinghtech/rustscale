//! Persistent server state — keys and node ID saved as JSON.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rustscale_key::{
    DiscoPrivate, MachinePrivate, MachinePublic, NLPrivate, NodePrivate, NodePublic,
};
use rustscale_tailcfg::MapResponse;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Cache file format version. Bumped on breaking changes to the envelope
/// structure; mismatched versions are rejected on load so a stale cache
/// from an older format is discarded cleanly rather than partially parsed.
const NETMAP_CACHE_VERSION: u32 = 3;

/// Durable profile/control namespace for identity, netmap, and TKA state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StateScope {
    pub profile_id: String,
    pub control_identity: String,
    pub dir: PathBuf,
}

impl StateScope {
    pub(crate) fn new(root: &Path, control_url: &str) -> Self {
        let profile_id = rustscale_ipn::LoginProfile::load_current_id(root)
            .ok()
            .flatten()
            .unwrap_or_else(|| "default".to_string());
        let control_identity = hex::encode(sha256(control_url.as_bytes()));
        let mut binding = Sha256::new();
        binding.update(profile_id.as_bytes());
        binding.update([0]);
        binding.update(control_identity.as_bytes());
        let namespace = hex::encode(binding.finalize());
        Self {
            profile_id,
            control_identity,
            dir: root.join("profile-state").join(namespace),
        }
    }

    pub(crate) fn bind(&self, state: &mut PersistedState) {
        state.profile_id.clone_from(&self.profile_id);
        state.control_identity.clone_from(&self.control_identity);
    }

    pub(crate) fn matches(&self, state: &PersistedState) -> bool {
        state.profile_id == self.profile_id && state.control_identity == self.control_identity
    }
}

/// Errors from state file operations.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

/// The persistent state of a tsnet server.
///
/// Node and machine keys are durable identity. The serialized disco key is
/// retained for state-file compatibility but is replaced before every engine
/// start; discovery identity is process-local, matching upstream magicsock.
/// Serialized as JSON in `state_dir/tsnet-state.json`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistedState {
    /// Durable profile and exact control namespace this identity belongs to.
    #[serde(default)]
    pub profile_id: String,
    #[serde(default)]
    pub control_identity: String,
    /// Tailnet identity learned from the netmap. It is informational until
    /// registration, but once set prevents accepting a cache for another
    /// tailnet served by the same control URL.
    #[serde(default)]
    pub tailnet_identity: String,
    /// The WireGuard node private key (serialized as `privkey:<hex>`).
    pub node_key: NodePrivate,
    /// The machine private key (control plane).
    pub machine_key: MachinePrivate,
    /// The last disco private key. Lifecycle startup always replaces it before
    /// use so a restarted UDP socket cannot inherit peer path trust.
    pub disco_key: DiscoPrivate,
    /// The node ID assigned by the control plane (0 until registered).
    #[serde(default)]
    pub node_id: i64,
    /// The stable node ID (string form, empty until registered).
    #[serde(default)]
    pub stable_node_id: String,
    /// Whether a register response completed enrollment. Older state files
    /// infer this from their existing ID fields.
    #[serde(default)]
    pub enrolled: bool,
    /// The previous node private key, saved during key rotation so
    /// `OldNodeKey` can be sent in the next `RegisterRequest`. Matches
    /// Go's `persist.OldPrivateNodeKey` (`types/persist/persist.go:25`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_node_key: Option<NodePrivate>,
    /// Persisted-identity Ed25519 signing key for Tailnet Lock. Older state files
    /// receive a fresh key on the next successful state save.
    #[serde(default)]
    pub network_lock_key: NLPrivate,
}

impl Default for PersistedState {
    fn default() -> Self {
        Self {
            profile_id: String::new(),
            control_identity: String::new(),
            tailnet_identity: String::new(),
            node_key: NodePrivate::from_raw32([0u8; 32]),
            machine_key: MachinePrivate::from_raw32([0u8; 32]),
            disco_key: DiscoPrivate::from_raw32([0u8; 32]),
            node_id: 0,
            stable_node_id: String::new(),
            enrolled: false,
            old_node_key: None,
            network_lock_key: NLPrivate::default(),
        }
    }
}

impl PersistedState {
    /// Generate fresh keys for a new server.
    pub fn generate() -> Self {
        Self {
            profile_id: String::new(),
            control_identity: String::new(),
            tailnet_identity: String::new(),
            node_key: NodePrivate::generate(),
            machine_key: MachinePrivate::generate(),
            disco_key: DiscoPrivate::generate(),
            node_id: 0,
            stable_node_id: String::new(),
            enrolled: false,
            old_node_key: None,
            network_lock_key: NLPrivate::generate(),
        }
    }

    /// Rotate enrollment identity for logout while preserving the durable
    /// profile/control/tailnet binding and Tailnet Lock signing identity.
    pub(crate) fn rotated_for_logout(&self) -> Self {
        let mut rotated = Self::generate();
        rotated.profile_id.clone_from(&self.profile_id);
        rotated.control_identity.clone_from(&self.control_identity);
        rotated.tailnet_identity.clone_from(&self.tailnet_identity);
        rotated.network_lock_key.clone_from(&self.network_lock_key);
        rotated
    }

    /// Whether all keys are zero (uninitialized).
    pub fn is_zero(&self) -> bool {
        self.node_key.is_zero() && self.machine_key.is_zero() && self.disco_key.is_zero()
    }

    /// Whether control has completed enrollment for this persisted identity.
    /// Generated keys alone are not enrollment: a register response can be
    /// lost, leaving non-zero keys that must still authenticate on retry.
    pub fn is_enrolled(&self) -> bool {
        self.enrolled || self.node_id != 0 || !self.stable_node_id.is_empty()
    }

    /// Load state from a JSON file.
    pub fn load(path: &Path) -> Result<Self, StateError> {
        let data = rustscale_atomicfile::read_private(path)?;
        Ok(serde_json::from_slice(&data)?)
    }

    /// Save state using an owner-only atomic replacement with durable parent
    /// fsync. Symlink and non-regular targets are rejected.
    pub fn save(&self, path: &Path) -> Result<(), StateError> {
        let data = serde_json::to_vec_pretty(self)?;
        rustscale_atomicfile::write_private(path, &data)?;
        Ok(())
    }

    /// Load a cached netmap from `<dir>/netmap-cache.json`.
    ///
    /// Returns `None` if no cache exists, the file is corrupt, the cache
    /// version doesn't match [`NETMAP_CACHE_VERSION`], or the cached node
    /// key does not match `expected_node_key` (indicating the node was
    /// re-keyed and the cache is stale).
    pub fn load_netmap(dir: &Path, expected_node_key: &NodePublic) -> Option<MapResponse> {
        let cache = NetMapCache::new(dir).load()?;
        if &cache.node_key != expected_node_key {
            log::warn!("tsnet: netmap cache stale (node key mismatch); discarding");
            return None;
        }
        Some(cache.map_response)
    }

    /// Save a netmap to `<dir>/netmap-cache.json`, tagged with the current
    /// node public key and cache version for later validation on load.
    ///
    /// This is a one-shot save (no dedup). Use [`NetMapCache::save_if_changed`]
    /// from a long-lived [`NetMapCache`] instance for deduplicated writes.
    pub fn save_netmap(
        dir: &Path,
        node_key: &NodePublic,
        resp: &MapResponse,
    ) -> Result<(), StateError> {
        NetMapCache::new(dir)
            .save_if_changed(node_key, resp)
            .map_err(StateError::Io)
    }

    /// Remove the cached netmap file (best-effort).
    pub fn clear_netmap(dir: &Path) {
        NetMapCache::new(dir).clear();
    }
}

/// On-disk netmap cache: a `MapResponse` tagged with the node public key
/// and a version header so stale caches from a re-keyed node or an
/// incompatible format are rejected on load.
#[derive(Clone, Serialize, Deserialize)]
pub struct NetMapCacheData {
    /// Envelope version — must match [`NETMAP_CACHE_VERSION`].
    #[serde(default)]
    pub version: u32,
    pub node_key: NodePublic,
    #[serde(default)]
    pub profile_id: String,
    #[serde(default)]
    pub control_identity: String,
    #[serde(default)]
    pub tailnet_identity: String,
    pub map_response: MapResponse,
}

/// Helper for reading/writing the netmap cache file at `<dir>/netmap-cache.json`.
///
/// Holds an in-memory SHA-256 digest of the last successfully written
/// serialized payload so that repeated saves of an identical netmap are
/// skipped (dedup), avoiding unnecessary disk I/O on every MapResponse.
pub struct NetMapCache {
    path: PathBuf,
    control_key_path: PathBuf,
    profile_id: String,
    control_identity: String,
    expected_tailnet_identity: String,
    last_hash: Mutex<Option<[u8; 32]>>,
}

impl NetMapCache {
    /// Create a new cache helper for `<dir>/netmap-cache.json`.
    pub fn new(dir: &Path) -> Self {
        Self {
            path: dir.join("netmap-cache.json"),
            control_key_path: dir.join("control-server-key.json"),
            profile_id: String::new(),
            control_identity: String::new(),
            expected_tailnet_identity: String::new(),
            last_hash: Mutex::new(None),
        }
    }

    pub(crate) fn new_scoped(scope: &StateScope, expected_tailnet_identity: &str) -> Self {
        Self {
            path: scope.dir.join("netmap-cache.json"),
            control_key_path: scope.dir.join("control-server-key.json"),
            profile_id: scope.profile_id.clone(),
            control_identity: scope.control_identity.clone(),
            expected_tailnet_identity: expected_tailnet_identity.to_string(),
            last_hash: Mutex::new(None),
        }
    }

    /// Load and deserialize the cache file. Returns `None` if the file
    /// doesn't exist or is corrupt (corrupt files are removed).
    pub fn load(&self) -> Option<NetMapCacheData> {
        let data = std::fs::read(&self.path).ok()?;
        match serde_json::from_slice::<NetMapCacheData>(&data) {
            Ok(c) if c.version != NETMAP_CACHE_VERSION => {
                log::debug!(
                    "tsnet: netmap cache version mismatch ({} != {}); discarding",
                    c.version,
                    NETMAP_CACHE_VERSION
                );
                self.clear();
                None
            }
            Ok(c)
                if (self.profile_id.is_empty() || c.profile_id == self.profile_id)
                    && (self.control_identity.is_empty()
                        || c.control_identity == self.control_identity)
                    && (self.expected_tailnet_identity.is_empty()
                        || c.tailnet_identity == self.expected_tailnet_identity) =>
            {
                // Seed the in-memory hash so a subsequent save_if_changed
                // of the same content is deduped.
                let digest = sha256(&data);
                *self.last_hash.lock().unwrap() = Some(digest);
                Some(c)
            }
            Ok(_) => {
                log::warn!("tsnet: netmap cache identity binding mismatch; discarding");
                self.clear();
                None
            }
            Err(e) => {
                log::warn!("tsnet: netmap cache corrupt ({e}); discarding");
                self.clear();
                None
            }
        }
    }

    /// Load the authenticated control Noise key retained with this scoped
    /// cache. It is useful only alongside a separately validated netmap.
    pub(crate) fn load_control_server_key(&self) -> Option<MachinePublic> {
        let data = std::fs::read(&self.control_key_path).ok()?;
        match serde_json::from_slice::<MachinePublic>(&data) {
            Ok(key) if !key.is_zero() => Some(key),
            Ok(_) | Err(_) => {
                log::warn!("tsnet: control server key cache is invalid; discarding");
                let _ = std::fs::remove_file(&self.control_key_path);
                None
            }
        }
    }

    /// Persist the authenticated control Noise key for a later validated
    /// offline restart. The path is profile/control scoped with the netmap.
    pub(crate) fn save_control_server_key(
        &self,
        key: &MachinePublic,
    ) -> Result<(), std::io::Error> {
        if key.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "refusing to cache zero control server key",
            ));
        }
        if let Some(parent) = self.control_key_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_vec(key).map_err(std::io::Error::other)?;
        rustscale_atomicfile::write(&self.control_key_path, &data)
    }

    /// Serialize, compute SHA-256, and skip the write if the digest
    /// matches the last successful write (or the content loaded by
    /// [`load`](Self::load)). Otherwise write atomically and update
    /// the in-memory hash.
    pub fn save_if_changed(
        &self,
        node_key: &NodePublic,
        resp: &MapResponse,
    ) -> Result<(), std::io::Error> {
        let data = serde_json::to_vec(&NetMapCacheData {
            version: NETMAP_CACHE_VERSION,
            node_key: node_key.clone(),
            profile_id: self.profile_id.clone(),
            control_identity: self.control_identity.clone(),
            tailnet_identity: resp.Domain.clone(),
            map_response: resp.clone(),
        })
        .map_err(std::io::Error::other)?;

        let digest = sha256(&data);
        if let Some(ref prev) = *self.last_hash.lock().unwrap() {
            if prev == &digest {
                return Ok(());
            }
        }

        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        rustscale_atomicfile::write(&self.path, &data)?;

        *self.last_hash.lock().unwrap() = Some(digest);
        Ok(())
    }

    /// Remove cache authority (best-effort) and reset the in-memory hash.
    /// The control key is useful only with this exact validated netmap, so it
    /// must never survive cache invalidation, logout, or identity rotation.
    pub fn clear(&self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_file(&self.control_key_path);
        *self.last_hash.lock().unwrap() = None;
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_and_control_scopes_do_not_share_identity_or_cache() {
        let root = tempfile::tempdir().unwrap();
        rustscale_ipn::LoginProfile::save_current_id(root.path(), "a").unwrap();
        let a = StateScope::new(root.path(), "https://control-a.example");
        rustscale_ipn::LoginProfile::save_current_id(root.path(), "b").unwrap();
        let b = StateScope::new(root.path(), "https://control-a.example");
        let other_control = StateScope::new(root.path(), "https://control-b.example");
        assert_ne!(a.dir, b.dir);
        assert_ne!(b.dir, other_control.dir);

        let mut a_state = PersistedState::generate();
        a.bind(&mut a_state);
        a_state.tailnet_identity = "tailnet-a".into();
        a_state.save(&a.dir.join("tsnet-state.json")).unwrap();
        assert!(PersistedState::load(&b.dir.join("tsnet-state.json")).is_err());

        let response = MapResponse {
            Domain: "tailnet-a".into(),
            ..Default::default()
        };
        NetMapCache::new_scoped(&a, "tailnet-a")
            .save_if_changed(&a_state.node_key.public(), &response)
            .unwrap();
        assert!(NetMapCache::new_scoped(&a, "tailnet-b").load().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn state_load_repairs_legacy_owner_modes_and_rejects_symlink() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let root = tempfile::tempdir().unwrap();
        let private = root.path().join("scope");
        std::fs::create_dir(&private).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = private.join("tsnet-state.json");
        let state = PersistedState::generate();
        std::fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        PersistedState::load(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&private).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        std::fs::remove_file(&path).unwrap();
        let target = private.join("target");
        std::fs::write(&target, serde_json::to_vec(&state).unwrap()).unwrap();
        symlink(target, &path).unwrap();
        assert!(PersistedState::load(&path).is_err());
    }

    #[test]
    fn state_save_load_roundtrip() {
        let root = tempfile::tempdir().unwrap();
        let tmp = root.path().join("tsnet-state-roundtrip.json");

        let state = PersistedState::generate();
        state.save(&tmp).expect("save");
        let loaded = PersistedState::load(&tmp).expect("load");
        assert_eq!(loaded.node_key.raw32(), state.node_key.raw32());
        assert_eq!(loaded.machine_key.raw32(), state.machine_key.raw32());
        assert_eq!(loaded.disco_key.raw32(), state.disco_key.raw32());
    }

    #[test]
    fn state_with_node_id_roundtrips() {
        let root = tempfile::tempdir().unwrap();
        let tmp = root.path().join("tsnet-state-nodeid.json");

        let state = PersistedState {
            node_id: 12345,
            stable_node_id: "nodeABC".into(),
            ..PersistedState::generate()
        };
        state.save(&tmp).expect("save");
        let loaded = PersistedState::load(&tmp).expect("load");
        assert_eq!(loaded.node_id, 12345);
        assert_eq!(loaded.stable_node_id, "nodeABC");
        assert!(loaded.is_enrolled());
    }

    #[test]
    fn logout_rotates_enrollment_but_preserves_lock_identity_and_binding() {
        let state = PersistedState {
            profile_id: "profile".into(),
            control_identity: "control".into(),
            tailnet_identity: "tailnet".into(),
            node_id: 42,
            stable_node_id: "stable".into(),
            enrolled: true,
            old_node_key: Some(NodePrivate::generate()),
            ..PersistedState::generate()
        };
        let rotated = state.rotated_for_logout();

        assert_ne!(rotated.node_key, state.node_key);
        assert_ne!(rotated.machine_key, state.machine_key);
        assert_ne!(rotated.disco_key, state.disco_key);
        assert_eq!(rotated.network_lock_key, state.network_lock_key);
        assert_eq!(rotated.profile_id, state.profile_id);
        assert_eq!(rotated.control_identity, state.control_identity);
        assert_eq!(rotated.tailnet_identity, state.tailnet_identity);
        assert_eq!(rotated.node_id, 0);
        assert!(rotated.stable_node_id.is_empty());
        assert!(!rotated.enrolled);
        assert!(rotated.old_node_key.is_none());
    }

    #[test]
    fn default_state_is_zero() {
        let state = PersistedState::default();
        assert!(state.is_zero());
        assert!(state.node_key.is_zero());
        assert!(state.machine_key.is_zero());
        assert!(state.disco_key.is_zero());
    }

    #[test]
    fn generated_state_is_not_zero() {
        let state = PersistedState::generate();
        assert!(!state.is_zero());
        assert!(!state.is_enrolled());
        assert!(!state.node_key.is_zero());
        assert!(!state.machine_key.is_zero());
        assert!(!state.disco_key.is_zero());

        let enrolled = PersistedState {
            enrolled: true,
            ..state
        };
        assert!(enrolled.is_enrolled());
    }

    #[test]
    fn state_json_contains_privkey_prefix() {
        let state = PersistedState::generate();
        let json = serde_json::to_string(&state).expect("serialize");
        assert!(
            json.contains("\"node_key\":\"privkey:"),
            "node_key should serialize as privkey: prefix"
        );
        assert!(
            json.contains("\"machine_key\":\"privkey:"),
            "machine_key should serialize as privkey: prefix"
        );
        assert!(
            json.contains("\"disco_key\":\"privkey:"),
            "disco_key should serialize as privkey: prefix"
        );
    }

    #[test]
    fn netmap_cache_save_load_roundtrip() {
        let dir = std::env::temp_dir().join("tsnet-netmap-cache-roundtrip");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let node_key = rustscale_key::NodePrivate::generate();
        let node_pub = node_key.public();
        let resp = MapResponse {
            Domain: "test.tailnet.ts.net".into(),
            Peers: Some(vec![rustscale_tailcfg::Node {
                ID: 42,
                Name: "peer.test.tailnet.ts.net.".into(),
                ..Default::default()
            }]),
            ..Default::default()
        };

        PersistedState::save_netmap(&dir, &node_pub, &resp).expect("save_netmap");
        let loaded = PersistedState::load_netmap(&dir, &node_pub).expect("load_netmap");
        assert_eq!(loaded.Domain, "test.tailnet.ts.net");
        assert_eq!(loaded.Peers.as_ref().unwrap().len(), 1);
        assert_eq!(loaded.Peers.as_ref().unwrap()[0].ID, 42);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn netmap_cache_rejects_wrong_node_key() {
        let dir = std::env::temp_dir().join("tsnet-netmap-cache-wrongkey");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let key_a = rustscale_key::NodePrivate::generate();
        let key_b = rustscale_key::NodePrivate::generate();
        let resp = MapResponse {
            Domain: "test.tailnet.ts.net".into(),
            ..Default::default()
        };

        PersistedState::save_netmap(&dir, &key_a.public(), &resp).expect("save_netmap");
        assert!(PersistedState::load_netmap(&dir, &key_b.public()).is_none());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn netmap_cache_clear_removes_file() {
        let dir = std::env::temp_dir().join("tsnet-netmap-cache-clear");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let key = rustscale_key::NodePrivate::generate();
        let resp = MapResponse::default();

        PersistedState::save_netmap(&dir, &key.public(), &resp).expect("save_netmap");
        assert!(dir.join("netmap-cache.json").exists());

        PersistedState::clear_netmap(&dir);
        assert!(!dir.join("netmap-cache.json").exists());

        PersistedState::clear_netmap(&dir);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn netmap_cache_load_missing_returns_none() {
        let dir = std::env::temp_dir().join("tsnet-netmap-cache-missing");
        let _ = std::fs::remove_dir_all(&dir);
        let key = rustscale_key::NodePrivate::generate();
        assert!(PersistedState::load_netmap(&dir, &key.public()).is_none());
    }

    #[test]
    fn netmap_cache_dedup_skips_identical_writes() {
        let dir = std::env::temp_dir().join("tsnet-netmap-cache-dedup");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let node_key = rustscale_key::NodePrivate::generate();
        let node_pub = node_key.public();
        let resp = MapResponse {
            Domain: "dedup.tailnet.ts.net".into(),
            ..Default::default()
        };

        // First write creates the file.
        let cache = NetMapCache::new(&dir);
        cache.save_if_changed(&node_pub, &resp).expect("first save");
        let mtime1 = std::fs::metadata(dir.join("netmap-cache.json"))
            .expect("file exists")
            .modified()
            .expect("modified");

        // Sleep briefly so a real write would produce a different mtime.
        std::thread::sleep(std::time::Duration::from_millis(20));

        // Second save of identical content should be deduped (no disk I/O).
        cache.save_if_changed(&node_pub, &resp).expect("dedup save");
        let mtime2 = std::fs::metadata(dir.join("netmap-cache.json"))
            .expect("file exists")
            .modified()
            .expect("modified");
        assert_eq!(mtime1, mtime2, "identical save should not touch the file");

        // A different MapResponse should produce a real write.
        let resp2 = MapResponse {
            Domain: "changed.tailnet.ts.net".into(),
            ..Default::default()
        };
        std::thread::sleep(std::time::Duration::from_millis(20));
        cache
            .save_if_changed(&node_pub, &resp2)
            .expect("changed save");
        let mtime3 = std::fs::metadata(dir.join("netmap-cache.json"))
            .expect("file exists")
            .modified()
            .expect("modified");
        assert_ne!(
            mtime2, mtime3,
            "changed content should produce a real write"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn legacy_full_looking_stream_cache_is_rejected() {
        let dir = std::env::temp_dir().join("tsnet-netmap-cache-legacy-stream");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let node_key = rustscale_key::NodePrivate::generate();
        let node_pub = node_key.public();
        let resp = MapResponse {
            Node: Some(rustscale_tailcfg::Node::default()),
            Peers: Some(Vec::new()),
            Domain: "version.tailnet.ts.net".into(),
            // Version 2 could persist a streaming response with this shape
            // while omitting independently optional bootstrap state.
            ..Default::default()
        };

        let legacy = NetMapCacheData {
            version: 2,
            node_key: node_pub.clone(),
            profile_id: String::new(),
            control_identity: String::new(),
            tailnet_identity: resp.Domain.clone(),
            map_response: resp,
        };
        let data = serde_json::to_vec(&legacy).expect("serialize");
        std::fs::write(dir.join("netmap-cache.json"), data).expect("write");

        assert!(
            PersistedState::load_netmap(&dir, &node_pub).is_none(),
            "pre-normalization cache version should be rejected"
        );
        assert!(
            !dir.join("netmap-cache.json").exists(),
            "legacy cache file should be removed on version mismatch"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn netmap_cache_clear_resets_dedup_hash() {
        let dir = std::env::temp_dir().join("tsnet-netmap-cache-clear-dedup");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let node_key = rustscale_key::NodePrivate::generate();
        let node_pub = node_key.public();
        let resp = MapResponse {
            Domain: "clear-dedup.tailnet.ts.net".into(),
            ..Default::default()
        };

        let cache = NetMapCache::new(&dir);
        cache.save_if_changed(&node_pub, &resp).expect("save");
        assert!(dir.join("netmap-cache.json").exists());

        // Clear removes the file and resets the hash.
        cache.clear();
        assert!(!dir.join("netmap-cache.json").exists());

        // After clear, saving the same content should write again
        // (hash was reset), recreating the file.
        cache
            .save_if_changed(&node_pub, &resp)
            .expect("save after clear");
        assert!(
            dir.join("netmap-cache.json").exists(),
            "save after clear should write the file"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn netmap_cache_load_seeds_dedup_hash() {
        let dir = std::env::temp_dir().join("tsnet-netmap-cache-load-dedup");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let node_key = rustscale_key::NodePrivate::generate();
        let node_pub = node_key.public();
        let resp = MapResponse {
            Domain: "load-dedup.tailnet.ts.net".into(),
            ..Default::default()
        };

        // Write via one cache instance, then load via another to seed hash.
        let writer = NetMapCache::new(&dir);
        writer.save_if_changed(&node_pub, &resp).expect("save");
        let mtime1 = std::fs::metadata(dir.join("netmap-cache.json"))
            .expect("file exists")
            .modified()
            .expect("modified");

        // A fresh cache instance that loads first should dedup the next
        // identical save (load seeds the hash).
        let cache = NetMapCache::new(&dir);
        let loaded = cache.load().expect("load");
        assert_eq!(loaded.map_response.Domain, "load-dedup.tailnet.ts.net");

        std::thread::sleep(std::time::Duration::from_millis(20));
        cache
            .save_if_changed(&node_pub, &resp)
            .expect("save after load");
        let mtime2 = std::fs::metadata(dir.join("netmap-cache.json"))
            .expect("file exists")
            .modified()
            .expect("modified");
        assert_eq!(
            mtime1, mtime2,
            "identical save after load should be deduped"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
