//! Client update checker — ports Go's `clientupdate/clientupdate.go`.
//!
//! Periodically checks for client updates based on `ClientVersion` from the
//! control plane `MapResponse`. Provides a `check` method to determine if an
//! update is available, and an `auto_apply` method (stub) to apply it.
//!
//! Go reference: `clientupdate/clientupdate.go` — `type Updater`,
//! `type Arguments`, `func NewUpdater`, `func Update`.

use rustscale_tailcfg::ClientVersion;

/// Release track — mirrors Go's track constants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Track {
    Stable,
    Unstable,
    ReleaseCandidate,
}

impl Track {
    pub fn as_str(self) -> &'static str {
        match self {
            Track::Stable => "stable",
            Track::Unstable => "unstable",
            Track::ReleaseCandidate => "release-candidate",
        }
    }
}

/// Arguments for the update checker — mirrors Go's `Arguments` struct.
#[derive(Clone, Debug, Default)]
pub struct UpdateArguments {
    /// Specific version to install (mutually exclusive with `track`).
    pub version: String,
    /// Release track to use.
    pub track: Option<Track>,
    /// Whether this is for auto-update (vs. manual).
    pub for_auto_update: bool,
}

/// Result of checking for updates.
#[derive(Clone, Debug, Default)]
pub struct CheckResult {
    /// The latest version available for the client's platform.
    pub latest_version: String,
    /// Whether the client is running the latest build.
    pub running_latest: bool,
    /// Whether there's an urgent security update.
    pub urgent_security_update: bool,
    /// Whether the client should notify the user.
    pub notify: bool,
    /// URL to open for the update.
    pub notify_url: String,
    /// Text to show in the notification.
    pub notify_text: String,
}

impl CheckResult {
    /// Whether an update is available.
    pub fn update_available(&self) -> bool {
        !self.running_latest && !self.latest_version.is_empty()
    }
}

/// The client update checker — holds the current version info and tracks
/// whether updates are available.
///
/// In Go, `Updater` handles platform-specific update logic (deb, rpm, macOS,
/// Windows, etc.). Here we provide the check logic; the actual update
/// application is a stub.
pub struct ClientUpdater {
    current_version: String,
    last_check: ClientVersion,
}

impl ClientUpdater {
    /// Create a new updater with the given current version string.
    pub fn new(current_version: &str) -> Self {
        Self {
            current_version: current_version.to_string(),
            last_check: ClientVersion::default(),
        }
    }

    /// Update the `ClientVersion` from the latest `MapResponse`.
    ///
    /// The control plane sends this in the `MapResponse.ClientVersion` field.
    /// Call this whenever a new netmap is received.
    pub fn set_client_version(&mut self, cv: ClientVersion) {
        self.last_check = cv;
    }

    /// Check whether an update is available.
    ///
    /// Returns a `CheckResult` derived from the last `ClientVersion` received
    /// from the control plane. If no `ClientVersion` has been received yet,
    /// returns a default (no update known).
    pub fn check(&self) -> CheckResult {
        let cv = &self.last_check;
        CheckResult {
            latest_version: cv.LatestVersion.clone(),
            running_latest: cv.RunningLatest,
            urgent_security_update: cv.UrgentSecurityUpdate,
            notify: cv.Notify,
            notify_url: cv.NotifyURL.clone(),
            notify_text: cv.NotifyText.clone(),
        }
    }

    /// Auto-apply the update (stub).
    ///
    /// In Go, this calls the platform-specific update function. Here it's a
    /// stub that logs the intent. A full implementation would download and
    /// install the new binary/package.
    pub fn auto_apply(&self, args: UpdateArguments) -> Result<(), UpdateError> {
        let result = self.check();
        if !result.update_available() && args.version.is_empty() {
            log::info!("clientupdate: no update available");
            return Ok(());
        }

        let target = if args.version.is_empty() {
            result.latest_version.clone()
        } else {
            args.version.clone()
        };

        log::info!(
            "clientupdate: auto-apply is a stub; would update to {target} (current: {})",
            self.current_version
        );

        // TODO: platform-specific update logic:
        // - Linux: deb/rpm/apk/nixos package update
        // - macOS: app store or pkg update
        // - Windows: MSI update
        // - FreeBSD: pkg update
        Err(UpdateError::AutoUpdateNotImplemented)
    }

    /// The current client version string.
    pub fn current_version(&self) -> &str {
        &self.current_version
    }

    /// Whether an urgent security update is pending.
    pub fn has_urgent_security_update(&self) -> bool {
        self.last_check.UrgentSecurityUpdate
    }
}

/// Error from the update checker.
#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("auto-update is not yet implemented for this platform")]
    AutoUpdateNotImplemented,
    #[error("update check failed: {0}")]
    CheckFailed(String),
}

/// Determine the track from a version string.
///
/// Mirrors Go's `versionToTrack`: even minor versions are stable, odd are
/// unstable.
pub fn version_to_track(version: &str) -> Option<Track> {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() < 2 {
        return None;
    }
    let minor: u32 = parts[1].parse().ok()?;
    if minor.is_multiple_of(2) {
        Some(Track::Stable)
    } else {
        Some(Track::Unstable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_with_no_client_version() {
        let updater = ClientUpdater::new("0.1.0");
        let result = updater.check();
        assert!(!result.update_available());
        assert!(!result.running_latest);
    }

    #[test]
    fn check_with_update_available() {
        let mut updater = ClientUpdater::new("0.1.0");
        updater.set_client_version(ClientVersion {
            RunningLatest: false,
            LatestVersion: "0.2.0".to_string(),
            UrgentSecurityUpdate: false,
            Notify: true,
            NotifyURL: "https://tailscale.com/download".to_string(),
            NotifyText: "Update available".to_string(),
        });
        let result = updater.check();
        assert!(result.update_available());
        assert!(!result.running_latest);
        assert_eq!(result.latest_version, "0.2.0");
        assert!(result.notify);
    }

    #[test]
    fn check_with_latest() {
        let mut updater = ClientUpdater::new("0.1.0");
        updater.set_client_version(ClientVersion {
            RunningLatest: true,
            ..Default::default()
        });
        let result = updater.check();
        assert!(!result.update_available());
    }

    #[test]
    fn urgent_security_update_flag() {
        let mut updater = ClientUpdater::new("0.1.0");
        updater.set_client_version(ClientVersion {
            UrgentSecurityUpdate: true,
            ..Default::default()
        });
        assert!(updater.has_urgent_security_update());
    }

    #[test]
    fn auto_apply_stub_returns_error() {
        let mut updater = ClientUpdater::new("0.1.0");
        updater.set_client_version(ClientVersion {
            RunningLatest: false,
            LatestVersion: "0.2.0".to_string(),
            ..Default::default()
        });
        let result = updater.auto_apply(UpdateArguments::default());
        assert!(matches!(result, Err(UpdateError::AutoUpdateNotImplemented)));
    }

    #[test]
    fn auto_apply_no_update_returns_ok() {
        let updater = ClientUpdater::new("0.1.0");
        let result = updater.auto_apply(UpdateArguments::default());
        assert!(result.is_ok());
    }

    #[test]
    fn version_to_track_stable() {
        assert_eq!(version_to_track("1.2.3"), Some(Track::Stable));
        assert_eq!(version_to_track("1.10.0"), Some(Track::Stable));
    }

    #[test]
    fn version_to_track_unstable() {
        assert_eq!(version_to_track("1.3.0"), Some(Track::Unstable));
        assert_eq!(version_to_track("1.11.0"), Some(Track::Unstable));
    }

    #[test]
    fn version_to_track_invalid() {
        assert_eq!(version_to_track("invalid"), None);
        assert_eq!(version_to_track("1"), None);
    }
}
