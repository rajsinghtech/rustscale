//! Persistent server state — keys and node ID saved as JSON.

use std::path::{Path, PathBuf};

use rustscale_key::{DiscoPrivate, MachinePrivate, NodePrivate, NodePublic};
use rustscale_tailcfg::MapResponse;
use serde::{Deserialize, Serialize};

/// Errors from state file operations.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

/// The persistent state of a tsnet server: node, machine, and disco keys.
///
/// Serialized as JSON in `state_dir/tsnet-state.json`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistedState {
    /// The WireGuard node private key (serialized as `privkey:<hex>`).
    pub node_key: NodePrivate,
    /// The machine private key (control plane).
    pub machine_key: MachinePrivate,
    /// The disco private key (NAT traversal).
    pub disco_key: DiscoPrivate,
    /// The node ID assigned by the control plane (0 until registered).
    #[serde(default)]
    pub node_id: i64,
    /// The stable node ID (string form, empty until registered).
    #[serde(default)]
    pub stable_node_id: String,
}

impl Default for PersistedState {
    fn default() -> Self {
        Self {
            node_key: NodePrivate::from_raw32([0u8; 32]),
            machine_key: MachinePrivate::from_raw32([0u8; 32]),
            disco_key: DiscoPrivate::from_raw32([0u8; 32]),
            node_id: 0,
            stable_node_id: String::new(),
        }
    }
}

impl PersistedState {
    /// Generate fresh keys for a new server.
    pub fn generate() -> Self {
        Self {
            node_key: NodePrivate::generate(),
            machine_key: MachinePrivate::generate(),
            disco_key: DiscoPrivate::generate(),
            node_id: 0,
            stable_node_id: String::new(),
        }
    }

    /// Whether all keys are zero (uninitialized).
    pub fn is_zero(&self) -> bool {
        self.node_key.is_zero() && self.machine_key.is_zero() && self.disco_key.is_zero()
    }

    /// Load state from a JSON file.
    pub fn load(path: &Path) -> Result<Self, StateError> {
        let data = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&data)?)
    }

    /// Save state to a JSON file (atomic: write to tmp + rename).
    pub fn save(&self, path: &Path) -> Result<(), StateError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_string_pretty(self)?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, data)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Load a cached netmap from `<dir>/netmap-cache.json`.
    ///
    /// Returns `None` if no cache exists, the file is corrupt, or the
    /// cached node key does not match `expected_node_key` (indicating
    /// the node was re-keyed and the cache is stale).
    pub fn load_netmap(dir: &Path, expected_node_key: &NodePublic) -> Option<MapResponse> {
        let cache = NetMapCache::new(dir).load()?;
        if &cache.node_key != expected_node_key {
            eprintln!("tsnet: netmap cache stale (node key mismatch); discarding");
            return None;
        }
        Some(cache.map_response)
    }

    /// Save a netmap to `<dir>/netmap-cache.json`, tagged with the current
    /// node public key for later validation on load.
    pub fn save_netmap(
        dir: &Path,
        node_key: &NodePublic,
        resp: &MapResponse,
    ) -> Result<(), StateError> {
        NetMapCache::new(dir)
            .save(node_key, resp)
            .map_err(StateError::Io)
    }

    /// Remove the cached netmap file (best-effort).
    pub fn clear_netmap(dir: &Path) {
        NetMapCache::new(dir).clear();
    }
}

/// On-disk netmap cache: a `MapResponse` tagged with the node public key
/// so stale caches from a re-keyed node are rejected on load.
#[derive(Serialize, Deserialize)]
struct NetMapCacheData {
    node_key: NodePublic,
    map_response: MapResponse,
}

/// Helper for reading/writing the netmap cache file at `<dir>/netmap-cache.json`.
struct NetMapCache {
    path: PathBuf,
}

impl NetMapCache {
    fn new(dir: &Path) -> Self {
        Self {
            path: dir.join("netmap-cache.json"),
        }
    }

    fn load(&self) -> Option<NetMapCacheData> {
        let data = std::fs::read(&self.path).ok()?;
        match serde_json::from_slice::<NetMapCacheData>(&data) {
            Ok(c) => Some(c),
            Err(e) => {
                eprintln!("tsnet: netmap cache corrupt ({e}); discarding");
                let _ = std::fs::remove_file(&self.path);
                None
            }
        }
    }

    fn save(&self, node_key: &NodePublic, resp: &MapResponse) -> Result<(), std::io::Error> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_vec(&NetMapCacheData {
            node_key: node_key.clone(),
            map_response: resp.clone(),
        })
        .map_err(std::io::Error::other)?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, data)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    fn clear(&self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_save_load_roundtrip() {
        let tmp = std::env::temp_dir().join("tsnet-state-roundtrip.json");
        let _ = std::fs::remove_file(&tmp);

        let state = PersistedState::generate();
        state.save(&tmp).expect("save");
        let loaded = PersistedState::load(&tmp).expect("load");
        assert_eq!(loaded.node_key.raw32(), state.node_key.raw32());
        assert_eq!(loaded.machine_key.raw32(), state.machine_key.raw32());
        assert_eq!(loaded.disco_key.raw32(), state.disco_key.raw32());

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn state_with_node_id_roundtrips() {
        let tmp = std::env::temp_dir().join("tsnet-state-nodeid.json");
        let _ = std::fs::remove_file(&tmp);

        let state = PersistedState {
            node_id: 12345,
            stable_node_id: "nodeABC".into(),
            ..PersistedState::generate()
        };
        state.save(&tmp).expect("save");
        let loaded = PersistedState::load(&tmp).expect("load");
        assert_eq!(loaded.node_id, 12345);
        assert_eq!(loaded.stable_node_id, "nodeABC");

        let _ = std::fs::remove_file(&tmp);
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
        assert!(!state.node_key.is_zero());
        assert!(!state.machine_key.is_zero());
        assert!(!state.disco_key.is_zero());
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
            Peers: vec![rustscale_tailcfg::Node {
                ID: 42,
                Name: "peer.test.tailnet.ts.net.".into(),
                ..Default::default()
            }],
            ..Default::default()
        };

        PersistedState::save_netmap(&dir, &node_pub, &resp).expect("save_netmap");
        let loaded = PersistedState::load_netmap(&dir, &node_pub).expect("load_netmap");
        assert_eq!(loaded.Domain, "test.tailnet.ts.net");
        assert_eq!(loaded.Peers.len(), 1);
        assert_eq!(loaded.Peers[0].ID, 42);

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
}
