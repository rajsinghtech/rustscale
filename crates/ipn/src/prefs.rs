//! User preferences — a Rust port of Go's `ipn.Prefs` and `ipn.MaskedPrefs`.
//!
//! [`Prefs`] is the full set of user-tunable preferences, serialized as
//! PascalCase JSON for wire compatibility with Go. [`MaskedPrefs`] wraps a
//! `Prefs` with per-field `*Set` bools for PATCH-style partial updates.

use std::path::Path;

use serde::{Deserialize, Serialize};

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(v: &bool) -> bool {
    !*v
}
fn is_empty_string(v: &str) -> bool {
    v.is_empty()
}
fn is_empty_vec(v: &[String]) -> bool {
    v.is_empty()
}
fn is_app_connector_default(v: &AppConnectorPrefs) -> bool {
    !v.Advertise
}

/// App connector preferences, mirroring Go's `ipn.AppConnectorPrefs`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct AppConnectorPrefs {
    #[serde(default, skip_serializing_if = "is_false")]
    pub Advertise: bool,
}

/// User preferences, mirroring Go's `ipn.Prefs`.
///
/// All fields serialize as PascalCase with `omitempty`-style skipping for
/// zero values, matching Go's `encoding/json` output.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Prefs {
    #[serde(default, skip_serializing_if = "is_empty_string")]
    pub ControlURL: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub WantRunning: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub LoggedOut: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub RouteAll: bool,
    #[serde(default, skip_serializing_if = "is_empty_string")]
    pub ExitNodeID: String,
    #[serde(default, skip_serializing_if = "is_empty_string")]
    pub ExitNodeIP: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub CorpDNS: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub ShieldsUp: bool,
    #[serde(default, skip_serializing_if = "is_empty_string")]
    pub Hostname: String,
    #[serde(default, skip_serializing_if = "is_empty_vec")]
    pub AdvertiseRoutes: Vec<String>,
    #[serde(default, skip_serializing_if = "is_empty_vec")]
    pub AdvertiseTags: Vec<String>,
    #[serde(default, skip_serializing_if = "is_empty_string")]
    pub OperatorUser: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub Ephemeral: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub AcceptRoutes: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub AdvertiseExitNode: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub ExitNodeAllowLANAccess: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub AutoUpdate: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub NetfilterMode: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub NoSNAT: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub PostureChecking: bool,
    #[serde(default, skip_serializing_if = "is_app_connector_default")]
    pub AppConnector: AppConnectorPrefs,
    #[serde(default, skip_serializing_if = "is_false")]
    pub RunWebClient: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub RunSSH: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub NoStatefulFiltering: bool,
}

impl Prefs {
    /// Load prefs from `<dir>/prefs.json`. Returns `Prefs::default()` if the
    /// file does not exist (first run). Returns an error only on read/parse
    /// failures.
    pub fn load(dir: &Path) -> Result<Self, std::io::Error> {
        let path = dir.join("prefs.json");
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = std::fs::read_to_string(&path)?;
        let prefs: Self = serde_json::from_str(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(prefs)
    }

    /// Save prefs to `<dir>/prefs.json` atomically (write to temp file, then
    /// rename). Creates the directory if it does not exist.
    pub fn save(&self, dir: &Path) -> Result<(), std::io::Error> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join("prefs.json");
        let tmp = dir.join(format!("prefs.json.tmp.{}", std::process::id()));
        let data = serde_json::to_vec_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&tmp, &data)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }
}

/// Masked preferences for PATCH-style partial updates, mirroring Go's
/// `ipn.MaskedPrefs`.
///
/// Each `<Field>Set` bool indicates whether the corresponding field in
/// `Prefs` should be applied. Only fields with `*Set == true` are copied
/// by [`apply_to`](Self::apply_to).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct MaskedPrefs {
    #[serde(flatten)]
    pub Prefs: Prefs,
    #[serde(default, skip_serializing_if = "is_false")]
    pub ControlURLSet: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub WantRunningSet: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub LoggedOutSet: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub RouteAllSet: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub ExitNodeIDSet: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub ExitNodeIPSet: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub CorpDNSSet: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub ShieldsUpSet: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub HostnameSet: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub AdvertiseRoutesSet: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub AdvertiseTagsSet: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub OperatorUserSet: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub EphemeralSet: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub AcceptRoutesSet: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub AdvertiseExitNodeSet: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub ExitNodeAllowLANAccessSet: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub AutoUpdateSet: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub NetfilterModeSet: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub NoSNATSet: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub PostureCheckingSet: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub AppConnectorSet: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub RunWebClientSet: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub RunSSHSet: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub NoStatefulFilteringSet: bool,
}

impl MaskedPrefs {
    /// Apply the masked fields to `target`. Only fields whose `*Set` bool is
    /// `true` are copied.
    pub fn apply_to(&self, target: &mut Prefs) {
        if self.ControlURLSet {
            target.ControlURL.clone_from(&self.Prefs.ControlURL);
        }
        if self.WantRunningSet {
            target.WantRunning = self.Prefs.WantRunning;
        }
        if self.LoggedOutSet {
            target.LoggedOut = self.Prefs.LoggedOut;
        }
        if self.RouteAllSet {
            target.RouteAll = self.Prefs.RouteAll;
        }
        if self.ExitNodeIDSet {
            target.ExitNodeID.clone_from(&self.Prefs.ExitNodeID);
        }
        if self.ExitNodeIPSet {
            target.ExitNodeIP.clone_from(&self.Prefs.ExitNodeIP);
        }
        if self.CorpDNSSet {
            target.CorpDNS = self.Prefs.CorpDNS;
        }
        if self.ShieldsUpSet {
            target.ShieldsUp = self.Prefs.ShieldsUp;
        }
        if self.HostnameSet {
            target.Hostname.clone_from(&self.Prefs.Hostname);
        }
        if self.AdvertiseRoutesSet {
            target
                .AdvertiseRoutes
                .clone_from(&self.Prefs.AdvertiseRoutes);
        }
        if self.AdvertiseTagsSet {
            target.AdvertiseTags.clone_from(&self.Prefs.AdvertiseTags);
        }
        if self.OperatorUserSet {
            target.OperatorUser.clone_from(&self.Prefs.OperatorUser);
        }
        if self.EphemeralSet {
            target.Ephemeral = self.Prefs.Ephemeral;
        }
        if self.AcceptRoutesSet {
            target.AcceptRoutes = self.Prefs.AcceptRoutes;
        }
        if self.AdvertiseExitNodeSet {
            target.AdvertiseExitNode = self.Prefs.AdvertiseExitNode;
        }
        if self.ExitNodeAllowLANAccessSet {
            target.ExitNodeAllowLANAccess = self.Prefs.ExitNodeAllowLANAccess;
        }
        if self.AutoUpdateSet {
            target.AutoUpdate = self.Prefs.AutoUpdate;
        }
        if self.NetfilterModeSet {
            target.NetfilterMode.clone_from(&self.Prefs.NetfilterMode);
        }
        if self.NoSNATSet {
            target.NoSNAT = self.Prefs.NoSNAT;
        }
        if self.PostureCheckingSet {
            target.PostureChecking = self.Prefs.PostureChecking;
        }
        if self.AppConnectorSet {
            target.AppConnector = self.Prefs.AppConnector.clone();
        }
        if self.RunWebClientSet {
            target.RunWebClient = self.Prefs.RunWebClient;
        }
        if self.RunSSHSet {
            target.RunSSH = self.Prefs.RunSSH;
        }
        if self.NoStatefulFilteringSet {
            target.NoStatefulFiltering = self.Prefs.NoStatefulFiltering;
        }
    }

    /// Returns `true` if no fields are set (no `*Set` bool is `true`).
    pub fn is_empty(&self) -> bool {
        !(self.ControlURLSet
            || self.WantRunningSet
            || self.LoggedOutSet
            || self.RouteAllSet
            || self.ExitNodeIDSet
            || self.ExitNodeIPSet
            || self.CorpDNSSet
            || self.ShieldsUpSet
            || self.HostnameSet
            || self.AdvertiseRoutesSet
            || self.AdvertiseTagsSet
            || self.OperatorUserSet
            || self.EphemeralSet
            || self.AcceptRoutesSet
            || self.AdvertiseExitNodeSet
            || self.ExitNodeAllowLANAccessSet
            || self.AutoUpdateSet
            || self.NetfilterModeSet
            || self.NoSNATSet
            || self.PostureCheckingSet
            || self.AppConnectorSet
            || self.RunWebClientSet
            || self.RunSSHSet
            || self.NoStatefulFilteringSet)
    }
}

/// Options for `POST /localapi/v0/start`, mirroring Go's `ipn.Options`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct StartOptions {
    #[serde(default, skip_serializing_if = "is_empty_string")]
    pub AuthKey: String,
    #[serde(default, skip_serializing_if = "is_empty_string")]
    pub UpdUserID: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub UpdatePrefs: Option<MaskedPrefs>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefs_default_serializes_as_empty_object() {
        let p = Prefs::default();
        let j = serde_json::to_string(&p).unwrap();
        assert_eq!(j, "{}");
    }

    #[test]
    fn prefs_round_trip() {
        let p = Prefs {
            ControlURL: "https://control.example.com".into(),
            WantRunning: true,
            Hostname: "my-node".into(),
            AdvertiseRoutes: vec!["10.0.0.0/24".into()],
            AdvertiseExitNode: true,
            Ephemeral: true,
            ..Default::default()
        };
        let j = serde_json::to_string(&p).unwrap();
        let p2: Prefs = serde_json::from_str(&j).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn prefs_omits_zero_values() {
        let p = Prefs {
            WantRunning: true,
            ..Default::default()
        };
        let j = serde_json::to_string(&p).unwrap();
        assert!(j.contains("\"WantRunning\":true"));
        assert!(!j.contains("ControlURL"));
        assert!(!j.contains("Hostname"));
        assert!(!j.contains("RouteAll"));
    }

    #[test]
    fn masked_prefs_apply_only_set_fields() {
        let mut target = Prefs {
            ControlURL: "https://old".into(),
            WantRunning: false,
            Hostname: "old-host".into(),
            ..Default::default()
        };
        let mask = MaskedPrefs {
            Prefs: Prefs {
                ControlURL: "https://new".into(),
                WantRunning: true,
                Hostname: "should-not-apply".into(),
                ..Default::default()
            },
            ControlURLSet: true,
            WantRunningSet: true,
            ..Default::default()
        };
        mask.apply_to(&mut target);
        assert_eq!(target.ControlURL, "https://new");
        assert!(target.WantRunning);
        assert_eq!(target.Hostname, "old-host");
    }

    #[test]
    fn masked_prefs_is_empty() {
        let m = MaskedPrefs::default();
        assert!(m.is_empty());

        let m = MaskedPrefs {
            WantRunningSet: true,
            ..Default::default()
        };
        assert!(!m.is_empty());
    }

    #[test]
    fn masked_prefs_round_trip() {
        let m = MaskedPrefs {
            Prefs: Prefs {
                WantRunning: true,
                Hostname: "test".into(),
                ..Default::default()
            },
            WantRunningSet: true,
            HostnameSet: true,
            ..Default::default()
        };
        let j = serde_json::to_string(&m).unwrap();
        let m2: MaskedPrefs = serde_json::from_str(&j).unwrap();
        assert_eq!(m, m2);
    }

    #[test]
    fn prefs_load_returns_default_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let p = Prefs::load(tmp.path()).unwrap();
        assert_eq!(p, Prefs::default());
    }

    #[test]
    fn prefs_save_and_load_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let p = Prefs {
            ControlURL: "https://ctrl".into(),
            WantRunning: true,
            Hostname: "host1".into(),
            AdvertiseRoutes: vec!["10.0.0.0/24".into()],
            ..Default::default()
        };
        p.save(tmp.path()).unwrap();
        let loaded = Prefs::load(tmp.path()).unwrap();
        assert_eq!(p, loaded);
    }

    #[test]
    fn start_options_serializes_with_omitempty() {
        let opts = StartOptions {
            AuthKey: "tskey-abc".into(),
            ..Default::default()
        };
        let j = serde_json::to_string(&opts).unwrap();
        assert!(j.contains("\"AuthKey\":\"tskey-abc\""));
        assert!(!j.contains("UpdUserID"));
        assert!(!j.contains("UpdatePrefs"));
    }

    #[test]
    fn prefs_new_fields_round_trip() {
        let p = Prefs {
            AutoUpdate: Some(true),
            NetfilterMode: Some("on".into()),
            NoSNAT: true,
            PostureChecking: true,
            AppConnector: AppConnectorPrefs { Advertise: true },
            RunWebClient: true,
            ..Default::default()
        };
        let j = serde_json::to_string(&p).unwrap();
        let p2: Prefs = serde_json::from_str(&j).unwrap();
        assert_eq!(p, p2);
        assert_eq!(p2.AutoUpdate, Some(true));
        assert_eq!(p2.NetfilterMode.as_deref(), Some("on"));
        assert!(p2.NoSNAT);
        assert!(p2.PostureChecking);
        assert!(p2.AppConnector.Advertise);
        assert!(p2.RunWebClient);
    }

    #[test]
    fn prefs_new_fields_omitted_when_default() {
        let p = Prefs::default();
        let j = serde_json::to_string(&p).unwrap();
        assert_eq!(j, "{}");
        assert!(!j.contains("AutoUpdate"));
        assert!(!j.contains("NetfilterMode"));
        assert!(!j.contains("NoSNAT"));
        assert!(!j.contains("PostureChecking"));
        assert!(!j.contains("AppConnector"));
        assert!(!j.contains("RunWebClient"));
    }

    #[test]
    fn masked_prefs_new_fields_apply() {
        let mut target = Prefs::default();
        let mask = MaskedPrefs {
            Prefs: Prefs {
                NoSNAT: true,
                PostureChecking: true,
                RunWebClient: true,
                AppConnector: AppConnectorPrefs { Advertise: true },
                ..Default::default()
            },
            NoSNATSet: true,
            PostureCheckingSet: true,
            RunWebClientSet: true,
            AppConnectorSet: true,
            ..Default::default()
        };
        mask.apply_to(&mut target);
        assert!(target.NoSNAT);
        assert!(target.PostureChecking);
        assert!(target.RunWebClient);
        assert!(target.AppConnector.Advertise);
        // Fields not set in mask should remain default.
        assert_eq!(target.AutoUpdate, None);
        assert_eq!(target.NetfilterMode, None);
    }

    #[test]
    fn masked_prefs_new_fields_is_empty() {
        let m = MaskedPrefs {
            AutoUpdateSet: true,
            ..Default::default()
        };
        assert!(!m.is_empty());

        let m = MaskedPrefs {
            AppConnectorSet: true,
            ..Default::default()
        };
        assert!(!m.is_empty());
    }
}
