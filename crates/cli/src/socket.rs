//! Socket path resolution — mirrors the daemon's `determine_socket_path`
//! logic: try the primary path first, then the state-dir fallback.

use std::path::{Path, PathBuf};

/// Primary socket path (requires root or appropriate permissions).
const PRIMARY_SOCKET_PATH: &str = "/var/run/rustscaled.sock";

/// Default state directory for the fallback probe.
const DEFAULT_STATE_DIR: &str = "/var/lib/rustscale";

/// Resolve the socket path to connect to. If the caller supplied an explicit
/// path via `--socket`, use that. Otherwise, probe the primary path and the
/// state-dir fallback, returning the first that is connectable.
pub fn resolve_socket_path(explicit: Option<PathBuf>) -> PathBuf {
    if let Some(p) = explicit {
        return p;
    }

    // Try the primary path.
    let primary = PathBuf::from(PRIMARY_SOCKET_PATH);
    if rustscale_safesocket::connect(&primary).is_ok() {
        return primary;
    }

    // Try the state-dir fallback.
    let fallback = Path::new(DEFAULT_STATE_DIR).join("rustscaled.sock");
    if rustscale_safesocket::connect(&fallback).is_ok() {
        return fallback;
    }

    // Neither is connectable — return the primary as the default so the
    // error message is informative ("can't connect to /var/run/...").
    primary
}
