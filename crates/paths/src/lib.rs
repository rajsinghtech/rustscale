//! Platform-specific default paths for rustscale state, logs, and config.
//!
//! Ports Go's `tailscale.com/paths` package, adapted for rustscale's
//! directory naming conventions. Unlike the Go original, which targets the
//! system daemon (tailscaled) and probes `/var/lib` writability, this crate
//! targets the embedded/tsnet use-case: per-user state under XDG directories
//! on Linux and `~/Library` on macOS.

#![forbid(unsafe_code)]

use std::path::PathBuf;

/// Returns the user's home directory.
///
/// On Unix reads `$HOME`; on Windows `%USERPROFILE%`. Falls back to `"."`
/// if neither is set.
fn home_dir() -> PathBuf {
    #[cfg(unix)]
    if let Some(h) = std::env::var_os("HOME") {
        return PathBuf::from(h);
    }
    #[cfg(windows)]
    if let Some(h) = std::env::var_os("USERPROFILE") {
        return PathBuf::from(h);
    }
    PathBuf::from(".")
}

/// Default state directory.
///
/// - macOS: `$HOME/Library/Application Support/rustscale`
/// - Linux: `$XDG_STATE_HOME/rustscale` or `$HOME/.local/state/rustscale`
/// - Windows: `%LOCALAPPDATA%\rustscale`
pub fn default_state_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        home_dir()
            .join("Library")
            .join("Application Support")
            .join("rustscale")
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(p) = std::env::var_os("XDG_STATE_HOME") {
            PathBuf::from(p).join("rustscale")
        } else {
            home_dir().join(".local").join("state").join("rustscale")
        }
    }
    #[cfg(windows)]
    {
        if let Some(p) = std::env::var_os("LOCALAPPDATA") {
            PathBuf::from(p).join("rustscale")
        } else {
            home_dir().join("AppData").join("Local").join("rustscale")
        }
    }
    #[cfg(not(any(target_os = "macos", unix, windows)))]
    {
        home_dir().join(".rustscale")
    }
}

/// Default log directory.
///
/// - macOS: `$HOME/Library/Logs/rustscale`
/// - Linux: `<state_dir>/logs`
/// - Windows: `<state_dir>/logs`
pub fn default_log_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        home_dir().join("Library").join("Logs").join("rustscale")
    }
    #[cfg(not(target_os = "macos"))]
    {
        default_state_dir().join("logs")
    }
}

/// Default config directory.
///
/// - macOS: `$HOME/Library/Application Support/rustscale` (same as state)
/// - Linux: `$XDG_CONFIG_HOME/rustscale` or `$HOME/.config/rustscale`
/// - Windows: `%LOCALAPPDATA%\rustscale` (same as state)
pub fn default_config_dir() -> PathBuf {
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(p) = std::env::var_os("XDG_CONFIG_HOME") {
            PathBuf::from(p).join("rustscale")
        } else {
            home_dir().join(".config").join("rustscale")
        }
    }
    #[cfg(any(target_os = "macos", windows, not(any(unix, windows))))]
    {
        default_state_dir()
    }
}

/// Default daemon socket path.
///
/// - Unix: `/var/run/rustscaled.sock`
/// - Windows: `\\.\pipe\rustscale`
pub fn daemon_socket_path() -> String {
    #[cfg(windows)]
    {
        r"\\.\pipe\rustscale".to_string()
    }
    #[cfg(not(windows))]
    {
        "/var/run/rustscaled.sock".to_string()
    }
}

/// Default path to the tsnet state file (`<state_dir>/tsnet-state.json`).
pub fn tailscaled_state_path() -> PathBuf {
    default_state_dir().join("tsnet-state.json")
}

/// Default path to the daemon log file (`<log_dir>/rustscale.log`).
pub fn tailscaled_log_path() -> PathBuf {
    default_log_dir().join("rustscale.log")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_dir_ends_with_rustscale() {
        let dir = default_state_dir();
        assert!(dir.ends_with("rustscale"), "state dir: {}", dir.display());
    }

    #[test]
    fn config_dir_ends_with_rustscale() {
        let dir = default_config_dir();
        assert!(dir.ends_with("rustscale"), "config dir: {}", dir.display());
    }

    #[test]
    fn tailscaled_state_path_is_json() {
        let p = tailscaled_state_path();
        assert!(p.ends_with("tsnet-state.json"));
    }

    #[test]
    fn tailscaled_log_path_is_sane() {
        let p = tailscaled_log_path();
        assert!(p.ends_with("rustscale.log"));
    }

    #[test]
    fn socket_path_nonempty() {
        let s = daemon_socket_path();
        assert!(!s.is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_paths() {
        let state = default_state_dir();
        assert!(state
            .to_string_lossy()
            .contains("Library/Application Support/rustscale"));
        let logs = default_log_dir();
        assert!(logs.to_string_lossy().contains("Library/Logs/rustscale"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_paths() {
        let state = default_state_dir();
        let logs = default_log_dir();
        assert!(state.ends_with("rustscale"));
        assert!(logs.starts_with(&state));
        assert!(logs.ends_with("logs"));
        let config = default_config_dir();
        assert!(config.ends_with("rustscale"));
    }

    #[cfg(not(windows))]
    #[test]
    fn socket_path_is_unix_socket() {
        let s = daemon_socket_path();
        assert!(s.starts_with('/') || s.starts_with('\\'));
        assert!(s.contains("rustscale"));
    }
}
