//! Persisted logtail policy for the rustscale daemon.
//!
//! The logtail private ID is deliberately shared with tsnet's persisted
//! `logid-private` file. Its derived public ID is therefore the same ID sent
//! to control as `Hostinfo.BackendLogID`.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use rustscale_logid::{PrivateID, PublicID};
use rustscale_logtail::{Config as LogtailConfig, LogTail, UploadHandle};

/// Log collection used for daemon logs.
pub const DEFAULT_COLLECTION: &str = "tailnode.log.tailscale.io";
const CONFIG_NAME: &str = "rustscaled.log.conf";

/// Persisted Go-compatible log policy configuration.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Config {
    pub collection: String,
    pub private_id: PrivateID,
    pub public_id: PublicID,
}

impl Config {
    fn new(collection: &str, private_id: PrivateID) -> Self {
        let public_id = private_id.public();
        Self {
            collection: collection.to_string(),
            private_id,
            public_id,
        }
    }

    fn is_valid_for(&self, collection: &str, private_id: &PrivateID) -> bool {
        self.collection == collection
            && &self.private_id == private_id
            && self.public_id == private_id.public()
    }
}

/// Errors loading or persisting log policy configuration.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("log ID error: {0}")]
    LogId(#[from] rustscale_logid::LogIdError),
    #[error("log policy I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid log policy JSON: {0}")]
    Json(#[from] serde_json::Error),
}

/// Logtail configuration and uploader for one daemon instance.
pub struct Policy {
    config: Config,
    logtail: LogTail,
}

impl Policy {
    /// Load or create the policy configuration for `state_dir`.
    ///
    /// The configuration location can be overridden by `TS_LOGS_DIR`, but the
    /// private ID always remains in `state_dir/logid-private` so tsnet and
    /// logtail share the exact same identity.
    pub fn new(collection: &str, state_dir: &Path) -> Result<Self, Error> {
        let private_id = PrivateID::load_or_create(&state_dir.join("logid-private"))?;
        let config_path = config_path(state_dir);
        let config = load_or_create_config(&config_path, collection, private_id)?;
        let base_url = rustscale_envknob::string("TS_LOG_TARGET").unwrap_or_default();
        let logtail = LogTail::new(LogtailConfig {
            collection: config.collection.clone(),
            private_id: config.private_id.to_string(),
            base_url,
            ..Default::default()
        });

        Ok(Self { config, logtail })
    }

    /// Persisted policy configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// The logtail client used by the daemon.
    pub fn logtail(&self) -> &LogTail {
        &self.logtail
    }

    /// Enable or disable log buffering and uploads for this policy.
    pub fn set_enabled(&self, enabled: bool) {
        self.logtail.set_enabled(enabled);
    }

    /// Start the background upload task.
    pub fn start_upload(&self) -> UploadHandle {
        self.logtail.start_upload()
    }
}

/// Effective directory used for the policy JSON file.
pub fn logs_dir(state_dir: &Path) -> PathBuf {
    rustscale_envknob::string("TS_LOGS_DIR").map_or_else(|| state_dir.to_path_buf(), PathBuf::from)
}

/// Path of the persisted policy configuration.
pub fn config_path(state_dir: &Path) -> PathBuf {
    logs_dir(state_dir).join(CONFIG_NAME)
}

fn load_or_create_config(
    path: &Path,
    collection: &str,
    private_id: PrivateID,
) -> Result<Config, Error> {
    let loaded = match std::fs::read_to_string(path) {
        Ok(data) => Some(serde_json::from_str::<Config>(&data)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };

    if let Some(config) = loaded {
        if config.is_valid_for(collection, &private_id) {
            return Ok(config);
        }
    }

    let config = Config::new(collection, private_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_vec_pretty(&config)?;
    std::fs::write(path, json)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_and_roundtrips_config() {
        let dir = tempfile::tempdir().unwrap();
        let first = Policy::new(DEFAULT_COLLECTION, dir.path()).unwrap();
        let saved: Config =
            serde_json::from_str(&std::fs::read_to_string(config_path(dir.path())).unwrap())
                .unwrap();
        assert_eq!(saved, *first.config());

        let second = Policy::new(DEFAULT_COLLECTION, dir.path()).unwrap();
        assert_eq!(first.config(), second.config());
    }

    #[test]
    fn reuses_preseeded_logid_private() {
        let dir = tempfile::tempdir().unwrap();
        let private: PrivateID = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            .parse()
            .unwrap();
        std::fs::write(dir.path().join("logid-private"), private.to_string()).unwrap();

        let policy = Policy::new(DEFAULT_COLLECTION, dir.path()).unwrap();
        assert_eq!(policy.config().private_id, private);
        assert_eq!(policy.config().public_id, private.public());
        assert!(policy
            .logtail()
            .upload_url()
            .ends_with(&private.to_string()));
    }

    #[test]
    fn replaces_config_with_a_different_private_id() {
        let dir = tempfile::tempdir().unwrap();
        let private: PrivateID = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            .parse()
            .unwrap();
        std::fs::write(dir.path().join("logid-private"), private.to_string()).unwrap();
        let stale = Config::new(DEFAULT_COLLECTION, PrivateID::new());
        std::fs::write(config_path(dir.path()), serde_json::to_vec(&stale).unwrap()).unwrap();

        let policy = Policy::new(DEFAULT_COLLECTION, dir.path()).unwrap();
        assert_eq!(policy.config().private_id, private);
    }
}
