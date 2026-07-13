//! Declarative config file for rustscaled. Mirrors Go's `ipn/conffile/` +
//! `ipn/conf.go`.
//!
//! A config file is a JSON object with a `"Version"` field set to `"alpha0"`
//! and zero or more preference fields. The file is loaded at daemon startup
//! and converted to [`MaskedPrefs`] via [`ConfigVAlpha::to_prefs`]. Reload
//! is triggered by `POST /localapi/v0/reload-config` or `SIGHUP`.
//!
//! # Example
//! ```json
//! {
//!     "Version": "alpha0",
//!     "Hostname": "my-node",
//!     "AuthKey": "tskey-auth-xxxx",
//!     "AcceptDNS": true,
//!     "AcceptRoutes": true,
//!     "AdvertiseRoutes": ["10.0.0.0/24"],
//!     "RunSSHServer": true,
//!     "ShieldsUp": false
//! }
//! ```

use std::net::IpAddr;

use rustscale_ipn::prefs::MaskedPrefs;
use thiserror::Error;

/// Errors returned by config file loading.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    Read {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to parse config file {path}: {source}")]
    Parse {
        path: String,
        source: serde_json::Error,
    },
    #[error("config file {path} is missing required \"Version\" field")]
    MissingVersion { path: String },
    #[error("config file {path} has unsupported version {version:?}; only \"alpha0\" is accepted")]
    UnsupportedVersion { path: String, version: String },
    #[error("\"vm:user-data\" config source is not implemented; use an explicit file path")]
    VmUserDataNotImplemented,
}

/// Deserialized config from a config file. Mirrors Go's `ipn.ConfigVAlpha`.
///
/// Boolean fields use `serde_json::Value` to represent Go's `opt_bool` —
/// a tri-state type that distinguishes "absent" (`Value::Null`) from
/// explicitly `true` or `false`. Only fields that are explicitly present
/// (non-null) produce a `*Set = true` in [`to_prefs`](Self::to_prefs).
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
#[allow(non_snake_case)]
pub struct ConfigVAlpha {
    #[serde(default)]
    pub Version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ServerURL: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub AuthKey: Option<String>,
    #[serde(default)]
    pub Enabled: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub OperatorUser: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub Hostname: Option<String>,
    #[serde(default)]
    pub AcceptDNS: serde_json::Value,
    #[serde(default)]
    pub AcceptRoutes: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ExitNode: Option<String>,
    #[serde(default)]
    pub AllowLANWhileUsingExitNode: serde_json::Value,
    #[serde(default)]
    pub AdvertiseRoutes: Vec<String>,
    #[serde(default)]
    pub DisableSNAT: serde_json::Value,
    #[serde(default)]
    pub RunSSHServer: serde_json::Value,
    #[serde(default)]
    pub ShieldsUp: serde_json::Value,
    #[serde(default)]
    pub NoStatefulFiltering: serde_json::Value,
    #[serde(default)]
    pub PostureChecking: serde_json::Value,
}

/// A loaded config file, keeping the raw file contents plus the parsed config.
/// Mirrors Go's `conffile.Config`.
#[derive(Clone, Debug)]
pub struct Config {
    pub path: String,
    pub raw: Vec<u8>,
    pub parsed: ConfigVAlpha,
}

impl Config {
    /// Load and parse a config file from `path`.
    ///
    /// The sentinel `"vm:user-data"` is recognized but returns
    /// [`ConfigError::VmUserDataNotImplemented`] (AWS EC2 user-data fetch
    /// is deferred). Only version `"alpha0"` is accepted. Unknown fields
    /// are rejected (`deny_unknown_fields`).
    pub fn load(path: &str) -> Result<Self, ConfigError> {
        if path == "vm:user-data" {
            return Err(ConfigError::VmUserDataNotImplemented);
        }

        let raw = std::fs::read(path).map_err(|e| ConfigError::Read {
            path: path.to_string(),
            source: e,
        })?;

        let parsed: ConfigVAlpha =
            serde_json::from_slice(&raw).map_err(|e| ConfigError::Parse {
                path: path.to_string(),
                source: e,
            })?;

        if parsed.Version.is_empty() {
            return Err(ConfigError::MissingVersion {
                path: path.to_string(),
            });
        }
        if parsed.Version != "alpha0" {
            return Err(ConfigError::UnsupportedVersion {
                path: path.to_string(),
                version: parsed.Version.clone(),
            });
        }

        Ok(Config {
            path: path.to_string(),
            raw,
            parsed,
        })
    }

    /// Returns `true` if the config's `Enabled` is not explicitly `false`.
    /// Mirrors Go's `Config.WantRunning()`.
    pub fn want_running(&self) -> bool {
        !matches!(self.parsed.Enabled, serde_json::Value::Bool(false))
    }
}

impl ConfigVAlpha {
    /// Convert this config into `MaskedPrefs` for application to the running
    /// prefs. Mirrors Go's `ConfigVAlpha.ToPrefs()` in `ipn/conf.go`.
    ///
    /// Each explicitly-present field maps to a `Prefs` field + its `*Set`
    /// flag. `Value::Null` fields are treated as absent (not set).
    #[allow(non_snake_case)]
    pub fn to_prefs(&self) -> MaskedPrefs {
        let mut mp = MaskedPrefs::default();

        // Enabled → WantRunning
        if let Some(b) = opt_bool(&self.Enabled) {
            mp.Prefs.WantRunning = b;
            mp.WantRunningSet = true;
        }

        // ServerURL → ControlURL
        if let Some(ref url) = self.ServerURL {
            if !url.is_empty() {
                mp.Prefs.ControlURL.clone_from(url);
                mp.ControlURLSet = true;
            }
        }

        // AuthKey (non-empty) → LoggedOut = false
        if let Some(ref key) = self.AuthKey {
            if !key.is_empty() {
                mp.Prefs.LoggedOut = false;
                mp.LoggedOutSet = true;
            }
        }

        // OperatorUser → OperatorUser
        if let Some(ref op) = self.OperatorUser {
            mp.Prefs.OperatorUser.clone_from(op);
            mp.OperatorUserSet = true;
        }

        // Hostname → Hostname
        if let Some(ref hn) = self.Hostname {
            mp.Prefs.Hostname.clone_from(hn);
            mp.HostnameSet = true;
        }

        // AcceptDNS → CorpDNS
        if let Some(b) = opt_bool(&self.AcceptDNS) {
            mp.Prefs.CorpDNS = b;
            mp.CorpDNSSet = true;
        }

        // AcceptRoutes → RouteAll
        if let Some(b) = opt_bool(&self.AcceptRoutes) {
            mp.Prefs.RouteAll = b;
            mp.RouteAllSet = true;
        }

        // ExitNode → ExitNodeIP (if IP) or ExitNodeID (if StableNodeID)
        if let Some(ref exit) = self.ExitNode {
            if !exit.is_empty() {
                if exit.parse::<IpAddr>().is_ok() {
                    mp.Prefs.ExitNodeIP.clone_from(exit);
                    mp.ExitNodeIPSet = true;
                } else {
                    mp.Prefs.ExitNodeID.clone_from(exit);
                    mp.ExitNodeIDSet = true;
                }
            }
        }

        // AllowLANWhileUsingExitNode → ExitNodeAllowLANAccess
        if let Some(b) = opt_bool(&self.AllowLANWhileUsingExitNode) {
            mp.Prefs.ExitNodeAllowLANAccess = b;
            mp.ExitNodeAllowLANAccessSet = true;
        }

        // AdvertiseRoutes → AdvertiseRoutes
        if !self.AdvertiseRoutes.is_empty() {
            mp.Prefs.AdvertiseRoutes.clone_from(&self.AdvertiseRoutes);
            mp.AdvertiseRoutesSet = true;
        }

        // DisableSNAT → NoSNAT
        if let Some(b) = opt_bool(&self.DisableSNAT) {
            mp.Prefs.NoSNAT = b;
            mp.NoSNATSet = true;
        }

        // RunSSHServer → RunSSH
        if let Some(b) = opt_bool(&self.RunSSHServer) {
            mp.Prefs.RunSSH = b;
            mp.RunSSHSet = true;
        }

        // ShieldsUp → ShieldsUp
        if let Some(b) = opt_bool(&self.ShieldsUp) {
            mp.Prefs.ShieldsUp = b;
            mp.ShieldsUpSet = true;
        }

        // NoStatefulFiltering → NoStatefulFiltering
        if let Some(b) = opt_bool(&self.NoStatefulFiltering) {
            mp.Prefs.NoStatefulFiltering = b;
            mp.NoStatefulFilteringSet = true;
        }

        // PostureChecking → PostureChecking
        if let Some(b) = opt_bool(&self.PostureChecking) {
            mp.Prefs.PostureChecking = b;
            mp.PostureCheckingSet = true;
        }

        mp
    }
}

/// Extract a `bool` from a `serde_json::Value`, returning `None` for
/// `Value::Null` (absent) or non-bool values. This mirrors Go's
/// `opt_bool` semantics: only explicit `true`/`false` count as "set".
fn opt_bool(v: &serde_json::Value) -> Option<bool> {
    match v {
        serde_json::Value::Bool(b) => Some(*b),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustscale_ipn::prefs::Prefs;

    fn load_str(json: &str) -> Result<Config, ConfigError> {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("test.conf");
        std::fs::write(&path, json).unwrap();
        Config::load(path.to_str().unwrap())
    }

    #[test]
    fn load_valid_minimal_config() {
        let config = load_str(r#"{"Version": "alpha0"}"#).unwrap();
        assert_eq!(config.parsed.Version, "alpha0");
        assert!(config.want_running());
    }

    #[test]
    fn load_full_config() {
        let json = r#"{
            "Version": "alpha0",
            "Hostname": "my-node",
            "AuthKey": "tskey-auth-xxxx",
            "AcceptDNS": true,
            "AcceptRoutes": true,
            "AdvertiseRoutes": ["10.0.0.0/24"],
            "RunSSHServer": true,
            "ShieldsUp": false
        }"#;
        let config = load_str(json).unwrap();
        assert_eq!(config.parsed.Hostname.as_deref(), Some("my-node"));
        assert_eq!(config.parsed.AuthKey.as_deref(), Some("tskey-auth-xxxx"));
        assert_eq!(config.parsed.AdvertiseRoutes, vec!["10.0.0.0/24"]);
        assert!(config.want_running());
    }

    #[test]
    fn load_missing_version_errors() {
        let err = load_str(r#"{"Hostname": "test"}"#).unwrap_err();
        assert!(matches!(err, ConfigError::MissingVersion { .. }));
    }

    #[test]
    fn load_unknown_version_errors() {
        let err = load_str(r#"{"Version": "beta1"}"#).unwrap_err();
        assert!(matches!(err, ConfigError::UnsupportedVersion { .. }));
    }

    #[test]
    fn load_unknown_fields_errors() {
        let err = load_str(r#"{"Version": "alpha0", "BogusField": true}"#).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    #[test]
    fn want_running_true_when_enabled_absent() {
        let config = load_str(r#"{"Version": "alpha0"}"#).unwrap();
        assert!(config.want_running());
    }

    #[test]
    fn want_running_false_when_enabled_false() {
        let config = load_str(r#"{"Version": "alpha0", "Enabled": false}"#).unwrap();
        assert!(!config.want_running());
    }

    #[test]
    fn want_running_true_when_enabled_true() {
        let config = load_str(r#"{"Version": "alpha0", "Enabled": true}"#).unwrap();
        assert!(config.want_running());
    }

    #[test]
    fn to_prefs_enabled_absent_no_set() {
        let config = load_str(r#"{"Version": "alpha0"}"#).unwrap();
        let mp = config.parsed.to_prefs();
        assert!(!mp.WantRunningSet);
    }

    #[test]
    fn to_prefs_enabled_false_sets_want_running_false() {
        let config = load_str(r#"{"Version": "alpha0", "Enabled": false}"#).unwrap();
        let mp = config.parsed.to_prefs();
        assert!(mp.WantRunningSet);
        assert!(!mp.Prefs.WantRunning);
    }

    #[test]
    fn to_prefs_enabled_true_sets_want_running_true() {
        let config = load_str(r#"{"Version": "alpha0", "Enabled": true}"#).unwrap();
        let mp = config.parsed.to_prefs();
        assert!(mp.WantRunningSet);
        assert!(mp.Prefs.WantRunning);
    }

    #[test]
    fn to_prefs_all_fields_mapped() {
        let json = r#"{
            "Version": "alpha0",
            "ServerURL": "https://control.example.com",
            "AuthKey": "tskey-auth-xxxx",
            "OperatorUser": "admin",
            "Hostname": "my-node",
            "AcceptDNS": true,
            "AcceptRoutes": true,
            "ExitNode": "100.64.0.5",
            "AllowLANWhileUsingExitNode": true,
            "AdvertiseRoutes": ["10.0.0.0/24"],
            "DisableSNAT": true,
            "RunSSHServer": true,
            "ShieldsUp": true,
            "NoStatefulFiltering": false,
            "PostureChecking": true
        }"#;
        let config = load_str(json).unwrap();
        let mp = config.parsed.to_prefs();

        assert!(mp.ControlURLSet);
        assert_eq!(mp.Prefs.ControlURL, "https://control.example.com");

        assert!(mp.LoggedOutSet);
        assert!(!mp.Prefs.LoggedOut);

        assert!(mp.OperatorUserSet);
        assert_eq!(mp.Prefs.OperatorUser, "admin");

        assert!(mp.HostnameSet);
        assert_eq!(mp.Prefs.Hostname, "my-node");

        assert!(mp.CorpDNSSet);
        assert!(mp.Prefs.CorpDNS);

        assert!(mp.RouteAllSet);
        assert!(mp.Prefs.RouteAll);

        assert!(mp.ExitNodeIPSet);
        assert_eq!(mp.Prefs.ExitNodeIP, "100.64.0.5");
        assert!(!mp.ExitNodeIDSet);

        assert!(mp.ExitNodeAllowLANAccessSet);
        assert!(mp.Prefs.ExitNodeAllowLANAccess);

        assert!(mp.AdvertiseRoutesSet);
        assert_eq!(mp.Prefs.AdvertiseRoutes, vec!["10.0.0.0/24"]);

        assert!(mp.NoSNATSet);
        assert!(mp.Prefs.NoSNAT);

        assert!(mp.RunSSHSet);
        assert!(mp.Prefs.RunSSH);

        assert!(mp.ShieldsUpSet);
        assert!(mp.Prefs.ShieldsUp);

        assert!(mp.NoStatefulFilteringSet);
        assert!(!mp.Prefs.NoStatefulFiltering);

        assert!(mp.PostureCheckingSet);
        assert!(mp.Prefs.PostureChecking);
    }

    #[test]
    fn to_prefs_exit_node_as_stable_id() {
        let json = r#"{"Version": "alpha0", "ExitNode": "nodeABCDEFG"}"#;
        let config = load_str(json).unwrap();
        let mp = config.parsed.to_prefs();
        assert!(mp.ExitNodeIDSet);
        assert_eq!(mp.Prefs.ExitNodeID, "nodeABCDEFG");
        assert!(!mp.ExitNodeIPSet);
    }

    #[test]
    fn to_prefs_auth_key_empty_does_not_set() {
        let json = r#"{"Version": "alpha0", "AuthKey": ""}"#;
        let config = load_str(json).unwrap();
        let mp = config.parsed.to_prefs();
        assert!(!mp.LoggedOutSet);
    }

    #[test]
    fn to_prefs_apply_roundtrip() {
        let json = r#"{
            "Version": "alpha0",
            "Hostname": "config-host",
            "AcceptDNS": false,
            "ShieldsUp": true
        }"#;
        let config = load_str(json).unwrap();
        let mp = config.parsed.to_prefs();
        let mut prefs = Prefs::default();
        mp.apply_to(&mut prefs);
        assert_eq!(prefs.Hostname, "config-host");
        assert!(!prefs.CorpDNS);
        assert!(prefs.ShieldsUp);
    }

    #[test]
    fn vm_user_data_not_implemented() {
        let err = Config::load("vm:user-data").unwrap_err();
        assert!(matches!(err, ConfigError::VmUserDataNotImplemented));
    }
}
