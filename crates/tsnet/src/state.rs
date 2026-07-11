//! Persistent server state — keys and node ID saved as JSON.

use std::path::Path;

use rustscale_key::{DiscoPrivate, MachinePrivate, NodePrivate};
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
}
