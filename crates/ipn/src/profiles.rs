//! Login profiles — a Rust port of Go's `ipn.LoginProfile` and related
//! profile management types.
//!
//! A [`LoginProfile`] represents one saved tailnet identity on this machine.
//! Multiple profiles can coexist (e.g. work + personal), and the user
//! switches between them via `rustscale switch`.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// A unique identifier for a profile. Assigned at creation, never changes.
pub type ProfileID = String;

/// A state store key under which a profile's persisted state lives.
pub type StateKey = String;

/// A subset of netmap information stored to remember which tailnet this
/// profile was logged in with. Mirrors Go's `ipn.NetworkProfile`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct NetworkProfile {
    /// The tailnet's domain name (e.g. "example.com.ts.net").
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub DomainName: String,
    /// A display name for the tailnet (e.g. "Example Corp").
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub DisplayName: String,
}

impl NetworkProfile {
    /// Returns the display name if set, otherwise the domain name.
    pub fn display_name_or_default(&self) -> &str {
        if self.DisplayName.is_empty() {
            &self.DomainName
        } else {
            &self.DisplayName
        }
    }
}

/// A saved tailnet login identity. Mirrors Go's `ipn.LoginProfile`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct LoginProfile {
    /// Unique identifier for this profile.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ID: ProfileID,
    /// User-visible name (filled from `UserProfile.LoginName`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub Name: String,
    /// Tailnet network info.
    #[serde(default, skip_serializing_if = "is_network_profile_empty")]
    pub NetworkProfile: NetworkProfile,
    /// The state key under which the profile's state is stored.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub Key: StateKey,
    /// The server-provided user profile.
    #[serde(default, skip_serializing_if = "is_user_profile_empty")]
    pub UserProfile: UserProfile,
    /// The node ID this profile is logged into.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub NodeID: String,
    /// The control server URL.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ControlURL: String,
}

/// A minimal user profile, mirroring the subset of `tailcfg.UserProfile`
/// that the profile manager needs. The full UserProfile is in
/// `rustscale-tailcfg`, but we include a copy here to avoid a circular
/// dependency.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct UserProfile {
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub ID: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub LoginName: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub DisplayName: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ProfilePicURL: String,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}
fn is_network_profile_empty(v: &NetworkProfile) -> bool {
    v.DomainName.is_empty() && v.DisplayName.is_empty()
}
fn is_user_profile_empty(v: &UserProfile) -> bool {
    v.ID == 0 && v.LoginName.is_empty() && v.DisplayName.is_empty() && v.ProfilePicURL.is_empty()
}

impl LoginProfile {
    /// Load all profiles from `<dir>/profiles.json`. Returns an empty vec
    /// if the file does not exist.
    pub fn load_all(dir: &Path) -> Result<Vec<Self>, std::io::Error> {
        let path = dir.join("profiles.json");
        if !path.exists() {
            return Ok(Vec::new());
        }
        let data = std::fs::read_to_string(&path)?;
        let profiles: Vec<Self> = serde_json::from_str(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(profiles)
    }

    /// Save all profiles to `<dir>/profiles.json` atomically.
    pub fn save_all(dir: &Path, profiles: &[Self]) -> Result<(), std::io::Error> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join("profiles.json");
        let tmp = dir.join(format!("profiles.json.tmp.{}", std::process::id()));
        let data = serde_json::to_vec_pretty(profiles)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&tmp, &data)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// Load the current profile ID from `<dir>/current-profile`. Returns
    /// `None` if the file does not exist.
    pub fn load_current_id(dir: &Path) -> Result<Option<ProfileID>, std::io::Error> {
        let path = dir.join("current-profile");
        if !path.exists() {
            return Ok(None);
        }
        let id = std::fs::read_to_string(&path)?;
        Ok(Some(id.trim().to_string()))
    }

    /// Save the current profile ID to `<dir>/current-profile`.
    pub fn save_current_id(dir: &Path, id: &str) -> Result<(), std::io::Error> {
        std::fs::create_dir_all(dir)?;
        std::fs::write(dir.join("current-profile"), id)?;
        Ok(())
    }

    /// Generate a new profile ID (timestamp + random suffix).
    pub fn new_id() -> ProfileID {
        use std::time::{SystemTime, UNIX_EPOCH};
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let ctr = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!("{ts:016x}{ctr:016x}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_profile_serde_roundtrip() {
        let p = LoginProfile {
            ID: "abc123".into(),
            Name: "user@example.com".into(),
            NetworkProfile: NetworkProfile {
                DomainName: "example.com.ts.net".into(),
                DisplayName: "Example Corp".into(),
            },
            Key: "profile-abc123".into(),
            UserProfile: UserProfile {
                ID: 42,
                LoginName: "user@example.com".into(),
                DisplayName: "User Name".into(),
                ProfilePicURL: String::new(),
            },
            NodeID: "nodeXYZ".into(),
            ControlURL: "https://control.example.com".into(),
        };
        let j = serde_json::to_string(&p).unwrap();
        let back: LoginProfile = serde_json::from_str(&j).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn login_profile_omits_empty_fields() {
        let p = LoginProfile::default();
        let j = serde_json::to_string(&p).unwrap();
        assert_eq!(j, "{}");
    }

    #[test]
    fn profiles_persist_and_reload() {
        let tmp = tempfile::tempdir().unwrap();
        let profiles = vec![
            LoginProfile {
                ID: "p1".into(),
                Name: "user1@work.com".into(),
                ControlURL: "https://control.work.com".into(),
                ..Default::default()
            },
            LoginProfile {
                ID: "p2".into(),
                Name: "user2@home.com".into(),
                ControlURL: "https://control.home.com".into(),
                ..Default::default()
            },
        ];
        LoginProfile::save_all(tmp.path(), &profiles).unwrap();
        LoginProfile::save_current_id(tmp.path(), "p1").unwrap();

        let loaded = LoginProfile::load_all(tmp.path()).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].ID, "p1");
        assert_eq!(loaded[1].Name, "user2@home.com");

        let current = LoginProfile::load_current_id(tmp.path()).unwrap();
        assert_eq!(current.as_deref(), Some("p1"));
    }

    #[test]
    fn load_all_returns_empty_when_no_file() {
        let tmp = tempfile::tempdir().unwrap();
        let loaded = LoginProfile::load_all(tmp.path()).unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn load_current_id_returns_none_when_no_file() {
        let tmp = tempfile::tempdir().unwrap();
        let current = LoginProfile::load_current_id(tmp.path()).unwrap();
        assert!(current.is_none());
    }

    #[test]
    fn new_id_is_unique() {
        let id1 = LoginProfile::new_id();
        let id2 = LoginProfile::new_id();
        assert_ne!(id1, id2);
    }

    #[test]
    fn network_profile_display_name_or_default() {
        let np = NetworkProfile {
            DomainName: "tailnet.ts.net".into(),
            DisplayName: "My Tailnet".into(),
        };
        assert_eq!(np.display_name_or_default(), "My Tailnet");

        let np = NetworkProfile {
            DomainName: "tailnet.ts.net".into(),
            DisplayName: String::new(),
        };
        assert_eq!(np.display_name_or_default(), "tailnet.ts.net");
    }
}
