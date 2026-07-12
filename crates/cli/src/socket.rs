//! Socket path resolution — mirrors the daemon's `determine_socket_path`
//! logic: try the primary path first, then the state-dir fallback.
//!
//! On Windows the default is a named pipe path
//! (`\\.\pipe\ProtectedPrefix\Administrators\Rustscale\rustscaled`) and there
//! is no state-dir fallback — the pipe path is always the same.

use std::path::PathBuf;

/// Default state directory for the fallback probe (unix only). On macOS the
/// daemon lives in `/var/db/rustscale` (matching Tailscale's
/// `/var/db/tailscale`); on other Unixes `/var/lib/rustscale`.
#[cfg(target_os = "macos")]
const DEFAULT_STATE_DIR: &str = "/var/db/rustscale";
#[cfg(all(unix, not(target_os = "macos")))]
const DEFAULT_STATE_DIR: &str = "/var/lib/rustscale";

/// Resolve the socket path to connect to. If the caller supplied an explicit
/// path via `--socket`, use that. Otherwise, probe the default path(s) for
/// the platform, returning the first that is connectable.
pub fn resolve_socket_path(explicit: Option<PathBuf>) -> PathBuf {
    if let Some(p) = explicit {
        return p;
    }

    let primary = rustscale_safesocket::default_socket_path();

    // Try the primary path.
    if rustscale_safesocket::connect(&primary).is_ok() {
        return primary;
    }

    // On Unix, try the state-dir fallback.
    #[cfg(unix)]
    {
        let fallback = std::path::Path::new(DEFAULT_STATE_DIR).join("rustscaled.sock");
        if rustscale_safesocket::connect(&fallback).is_ok() {
            return fallback;
        }
    }

    // Neither is connectable — return the primary as the default so the
    // error message is informative.
    primary
}
