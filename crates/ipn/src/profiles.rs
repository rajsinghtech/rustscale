//! Login profiles — a Rust port of Go's `ipn.LoginProfile` and related
//! profile management types, plus a [`ProfileManager`] for profile
//! switching, auto-detection, and key-expiry tracking.
//!
//! A [`LoginProfile`] represents one saved tailnet identity on this machine.
//! Multiple profiles can coexist (e.g. work + personal), and the user
//! switches between them via `rustscale switch`.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::prefs::Prefs;

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

// ─── ProfileManager ───────────────────────────────────────────────────

/// A callback invoked when the current profile changes, receiving the
/// new profile and its loaded prefs. The backend uses this to apply prefs
/// to the engine (netmap reset, route table update, etc.). Mirrors Go's
/// `profileManager.StateChangeHook`.
pub type StateChangeCallback = Box<dyn Fn(&LoginProfile, &Prefs) + Send + Sync>;

/// Key-expiry information tracked per profile so the manager can flag
/// expiring keys and trigger re-registration. Mirrors the subset of
/// Go's `LocalBackend.keyExpired` logic that applies to profile switching.
#[derive(Clone, Debug, Default)]
pub struct KeyExpiryState {
    /// Unix timestamp (seconds) at which the node key expires. Zero if
    /// unknown or no expiry set.
    pub expiry_unix: i64,
    /// Whether the key was flagged as expired on the last check.
    pub is_expired: bool,
}

/// Result of a profile switch operation.
#[derive(Debug)]
pub struct SwitchResult {
    /// The profile that is now current.
    pub profile: LoginProfile,
    /// Whether the switch actually changed the active profile (false = same).
    pub changed: bool,
}

/// Manages a collection of login profiles, the currently active profile,
/// and per-profile key-expiry state. Mirrors Go's `profileManager`
/// (ipn/ipnlocal/profiles.go) at the API level — the full backend
/// integration (netmap reset, engine reconfig) is wired via the
/// [`StateChangeCallback`].
///
/// Not safe for concurrent use without external synchronization — callers
/// typically hold the `LocalBackend` lock while mutating.
pub struct ProfileManager {
    state_dir: PathBuf,
    known: Vec<LoginProfile>,
    current_id: Option<ProfileID>,
    prefs: Prefs,
    key_expiry: KeyExpiryState,
    state_change_hook: Option<StateChangeCallback>,
}

impl ProfileManager {
    /// Create a new ProfileManager, auto-detecting available profiles from
    /// `<state_dir>/profiles.json` and loading the current profile ID from
    /// `<state_dir>/current-profile`. Mirrors Go's `newProfileManager`.
    pub fn new(state_dir: &Path) -> Result<Self, std::io::Error> {
        let known = LoginProfile::load_all(state_dir)?;
        let current_id = LoginProfile::load_current_id(state_dir)?;
        let prefs = Prefs::load(state_dir)?;
        Ok(Self {
            state_dir: state_dir.to_path_buf(),
            known,
            current_id,
            prefs,
            key_expiry: KeyExpiryState::default(),
            state_change_hook: None,
        })
    }

    /// Set the state-change callback invoked after a successful profile
    /// switch. The callback receives the new profile and its loaded prefs
    /// so the backend can apply them to the engine.
    pub fn set_state_change_hook(&mut self, hook: StateChangeCallback) {
        self.state_change_hook = Some(hook);
    }

    /// Returns all known profiles.
    pub fn profiles(&self) -> &[LoginProfile] {
        &self.known
    }

    /// Returns the currently active profile, or `None` if no profile is
    /// selected.
    pub fn current_profile(&self) -> Option<&LoginProfile> {
        self.current_id
            .as_ref()
            .and_then(|id| self.known.iter().find(|p| &p.ID == id))
    }

    /// Returns the current prefs (the prefs of the active profile, or
    /// defaults if none selected).
    pub fn current_prefs(&self) -> &Prefs {
        &self.prefs
    }

    /// Returns the current key-expiry state.
    pub fn key_expiry(&self) -> &KeyExpiryState {
        &self.key_expiry
    }

    /// Find a profile by ID.
    pub fn profile_by_id(&self, id: &str) -> Option<&LoginProfile> {
        self.known.iter().find(|p| p.ID == id)
    }

    /// Switch to the profile with the given ID. Loads the profile's prefs
    /// from disk, sets it as current, persists the current-profile marker,
    /// and fires the state-change callback. Returns an error if the profile
    /// ID is not found. Mirrors Go's `profileManager.SwitchProfileByID`.
    pub fn switch_profile(&mut self, id: &str) -> Result<SwitchResult, ProfileError> {
        if let Some(ref cid) = self.current_id {
            if cid == id {
                let profile = self.profile_by_id(id).cloned().unwrap_or_default();
                return Ok(SwitchResult {
                    profile,
                    changed: false,
                });
            }
        }

        let profile = self
            .profile_by_id(id)
            .ok_or_else(|| ProfileError::NotFound(id.to_string()))?
            .clone();

        let prefs = Prefs::load(&self.state_dir).unwrap_or_default();

        self.current_id = Some(id.to_string());
        self.prefs = prefs.clone();
        LoginProfile::save_current_id(&self.state_dir, id)?;

        if let Some(ref hook) = self.state_change_hook {
            hook(&profile, &prefs);
        }

        Ok(SwitchResult {
            profile,
            changed: true,
        })
    }

    /// Create and switch to a new empty profile. The profile is assigned a
    /// fresh ID and added to the known list. Mirrors Go's
    /// `profileManager.NewProfileForUser` + `SwitchToProfile`.
    pub fn new_profile(&mut self, name: &str) -> Result<SwitchResult, std::io::Error> {
        let id = LoginProfile::new_id();
        let profile = LoginProfile {
            ID: id.clone(),
            Name: name.to_string(),
            ControlURL: "https://controlplane.tailscale.com".to_string(),
            ..Default::default()
        };
        self.known.push(profile.clone());
        LoginProfile::save_all(&self.state_dir, &self.known)?;
        LoginProfile::save_current_id(&self.state_dir, &id)?;

        self.current_id = Some(id.clone());
        self.prefs = Prefs::default();

        if let Some(ref hook) = self.state_change_hook {
            hook(&profile, &self.prefs);
        }

        Ok(SwitchResult {
            profile,
            changed: true,
        })
    }

    /// Delete a profile by ID. If the deleted profile was current, the
    /// current profile is cleared. Persists the updated profile list.
    pub fn delete_profile(&mut self, id: &str) -> Result<(), std::io::Error> {
        self.known.retain(|p| p.ID != id);
        if self.current_id.as_deref() == Some(id) {
            self.current_id = None;
        }
        LoginProfile::save_all(&self.state_dir, &self.known)?;
        Ok(())
    }

    /// Update the key-expiry state for the current profile. When the key
    /// is expired or nearing expiry (within `threshold_secs`), returns
    /// `true` to signal the caller that re-registration should be
    /// triggered. Mirrors Go's `LocalBackend` key-expiry check in
    /// `onNewDataPlaneState` / `setNodeKeyExpired`.
    pub fn check_key_expiry(&mut self, now_unix: i64, threshold_secs: i64) -> bool {
        if self.key_expiry.expiry_unix == 0 {
            return false;
        }
        let was_expired = self.key_expiry.is_expired;
        let remaining = self.key_expiry.expiry_unix - now_unix;
        self.key_expiry.is_expired = remaining <= 0;
        let just_expired = self.key_expiry.is_expired && !was_expired;
        // Trigger re-registration only on the expired transition, or when
        // nearing expiry within the threshold (but not yet expired).
        just_expired || (remaining > 0 && remaining <= threshold_secs)
    }

    /// Set the key-expiry timestamp for the current profile (e.g. from a
    /// netmap update). This does not trigger re-registration — call
    /// `check_key_expiry` afterward.
    pub fn set_key_expiry(&mut self, expiry_unix: i64) {
        self.key_expiry.expiry_unix = expiry_unix;
    }

    /// Persist the current prefs to disk.
    pub fn save_prefs(&self) -> Result<(), std::io::Error> {
        self.prefs.save(&self.state_dir)
    }

    /// Update the in-memory prefs and persist them. Used by `PATCH /prefs`
    /// and `SetExpirySooner` paths.
    pub fn set_prefs(&mut self, prefs: Prefs) -> Result<(), std::io::Error> {
        self.prefs = prefs;
        self.prefs.save(&self.state_dir)?;
        if let Some(profile) = self.current_profile() {
            if let Some(ref hook) = self.state_change_hook {
                hook(profile, &self.prefs);
            }
        }
        Ok(())
    }
}

/// Errors from profile operations.
#[derive(Debug)]
pub enum ProfileError {
    /// Profile ID not found in the known list.
    NotFound(String),
    /// I/O error during persistence.
    Io(std::io::Error),
}

impl From<std::io::Error> for ProfileError {
    fn from(e: std::io::Error) -> Self {
        ProfileError::Io(e)
    }
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProfileError::NotFound(id) => write!(f, "profile not found: {id}"),
            ProfileError::Io(e) => write!(f, "profile I/O error: {e}"),
        }
    }
}

impl std::error::Error for ProfileError {}

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

    // ─── ProfileManager tests ───────────────────────────────────────

    #[test]
    fn profile_manager_autodetects_profiles() {
        let tmp = tempfile::tempdir().unwrap();
        let profiles = vec![
            LoginProfile {
                ID: "p1".into(),
                Name: "user1@work.com".into(),
                ..Default::default()
            },
            LoginProfile {
                ID: "p2".into(),
                Name: "user2@home.com".into(),
                ..Default::default()
            },
        ];
        LoginProfile::save_all(tmp.path(), &profiles).unwrap();
        LoginProfile::save_current_id(tmp.path(), "p2").unwrap();

        let pm = ProfileManager::new(tmp.path()).unwrap();
        assert_eq!(pm.profiles().len(), 2);
        assert_eq!(pm.current_id.as_deref(), Some("p2"));
        assert_eq!(pm.current_profile().unwrap().Name, "user2@home.com");
    }

    #[test]
    fn profile_manager_switch_profile() {
        let tmp = tempfile::tempdir().unwrap();
        let profiles = vec![
            LoginProfile {
                ID: "p1".into(),
                Name: "user1@work.com".into(),
                ..Default::default()
            },
            LoginProfile {
                ID: "p2".into(),
                Name: "user2@home.com".into(),
                ..Default::default()
            },
        ];
        LoginProfile::save_all(tmp.path(), &profiles).unwrap();
        LoginProfile::save_current_id(tmp.path(), "p1").unwrap();

        let mut pm = ProfileManager::new(tmp.path()).unwrap();
        assert_eq!(pm.current_id.as_deref(), Some("p1"));

        let result = pm.switch_profile("p2").unwrap();
        assert!(result.changed);
        assert_eq!(result.profile.ID, "p2");
        assert_eq!(pm.current_id.as_deref(), Some("p2"));

        // Switching to same profile is a no-op.
        let result2 = pm.switch_profile("p2").unwrap();
        assert!(!result2.changed);
    }

    #[test]
    fn profile_manager_switch_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let mut pm = ProfileManager::new(tmp.path()).unwrap();
        let err = pm.switch_profile("nonexistent").unwrap_err();
        assert!(matches!(err, ProfileError::NotFound(_)));
    }

    #[test]
    fn profile_manager_new_profile() {
        let tmp = tempfile::tempdir().unwrap();
        let mut pm = ProfileManager::new(tmp.path()).unwrap();
        assert!(pm.profiles().is_empty());

        let result = pm.new_profile("newuser@example.com").unwrap();
        assert!(result.changed);
        assert!(!result.profile.ID.is_empty());
        assert_eq!(pm.profiles().len(), 1);
        assert_eq!(pm.current_id.as_deref(), Some(result.profile.ID.as_str()));
    }

    #[test]
    fn profile_manager_delete_profile() {
        let tmp = tempfile::tempdir().unwrap();
        let profiles = vec![
            LoginProfile {
                ID: "p1".into(),
                Name: "user1@work.com".into(),
                ..Default::default()
            },
            LoginProfile {
                ID: "p2".into(),
                Name: "user2@home.com".into(),
                ..Default::default()
            },
        ];
        LoginProfile::save_all(tmp.path(), &profiles).unwrap();
        LoginProfile::save_current_id(tmp.path(), "p1").unwrap();

        let mut pm = ProfileManager::new(tmp.path()).unwrap();
        pm.delete_profile("p1").unwrap();
        assert_eq!(pm.profiles().len(), 1);
        assert!(pm.current_id.is_none());
    }

    #[test]
    fn profile_manager_key_expiry_check() {
        let tmp = tempfile::tempdir().unwrap();
        let mut pm = ProfileManager::new(tmp.path()).unwrap();

        // No expiry set → no re-registration needed.
        assert!(!pm.check_key_expiry(1000, 3600));

        // Set expiry in the past → expired, triggers re-registration.
        pm.set_key_expiry(500);
        assert!(pm.check_key_expiry(1000, 3600));

        // Already expired flag is set, subsequent check without just-expired
        // transition does not re-trigger.
        assert!(!pm.check_key_expiry(1001, 3600));

        // Set expiry in the near future (within threshold) → triggers.
        pm.set_key_expiry(2000);
        assert!(pm.check_key_expiry(1500, 3600));
    }

    #[test]
    fn profile_manager_state_change_hook() {
        let tmp = tempfile::tempdir().unwrap();
        let profiles = vec![
            LoginProfile {
                ID: "p1".into(),
                Name: "user1@work.com".into(),
                ..Default::default()
            },
            LoginProfile {
                ID: "p2".into(),
                Name: "user2@home.com".into(),
                ..Default::default()
            },
        ];
        LoginProfile::save_all(tmp.path(), &profiles).unwrap();
        LoginProfile::save_current_id(tmp.path(), "p1").unwrap();

        let hook_called = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
        let hook_called_clone = hook_called.clone();
        let mut pm = ProfileManager::new(tmp.path()).unwrap();
        pm.set_state_change_hook(Box::new(move |_profile, _prefs| {
            *hook_called_clone.lock().unwrap() = Some("hook fired".to_string());
        }));

        pm.switch_profile("p2").unwrap();
        assert_eq!(*hook_called.lock().unwrap(), Some("hook fired".to_string()));
    }

    #[test]
    fn profile_manager_set_prefs_fires_hook() {
        let tmp = tempfile::tempdir().unwrap();
        let mut pm = ProfileManager::new(tmp.path()).unwrap();
        let hook_fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hf = hook_fired.clone();
        pm.set_state_change_hook(Box::new(move |_, _| {
            hf.store(true, std::sync::atomic::Ordering::SeqCst);
        }));
        // Create a profile first so current_profile() is Some.
        pm.new_profile("test").unwrap();
        hook_fired.store(false, std::sync::atomic::Ordering::SeqCst);

        let prefs = Prefs {
            WantRunning: true,
            ..Default::default()
        };
        pm.set_prefs(prefs).unwrap();
        assert!(hook_fired.load(std::sync::atomic::Ordering::SeqCst));
    }
}
