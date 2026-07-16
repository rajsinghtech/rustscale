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

    #[cfg(unix)]
    {
        let fallback = Some(std::path::Path::new(DEFAULT_STATE_DIR).join("rustscaled.sock"));
        resolve_socket_candidates(primary, fallback)
    }
    #[cfg(not(unix))]
    {
        // Windows has one canonical named-pipe path, so probing cannot change
        // the result and would construct a Tokio pipe before runtime entry.
        primary
    }
}

/// Return the first live candidate. Kept separate so the exact default-socket
/// behavior is testable without binding a machine-global `/var/run` path.
#[cfg(unix)]
fn resolve_socket_candidates(primary: PathBuf, fallback: Option<PathBuf>) -> PathBuf {
    resolve_socket_candidates_with(primary, fallback, socket_is_live)
}

#[cfg(unix)]
fn resolve_socket_candidates_with(
    primary: PathBuf,
    fallback: Option<PathBuf>,
    is_live: impl Fn(&std::path::Path) -> bool,
) -> PathBuf {
    // Try the primary path.
    if is_live(&primary) {
        return primary;
    }

    if let Some(fallback) = fallback {
        if is_live(&fallback) {
            return fallback;
        }
    }

    // Neither is connectable — return the primary as the default so the
    // error message is informative.
    primary
}

/// Check for a Unix socket without connecting to it. A probe connection would
/// be accepted by LocalAPI and then dropped without an HTTP request, producing
/// a misleading `Broken pipe` warning on every CLI invocation.
#[cfg(unix)]
fn socket_is_live(path: &std::path::Path) -> bool {
    use std::os::unix::fs::FileTypeExt;

    std::fs::metadata(path).is_ok_and(|metadata| metadata.file_type().is_socket())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn live_default_candidate_neither_requires_tokio_nor_connects() {
        let temp = tempfile::tempdir().unwrap();
        let primary = temp.path().join("rustscaled.sock");
        let listener = std::os::unix::net::UnixListener::bind(&primary).unwrap();
        listener.set_nonblocking(true).unwrap();
        let fallback = temp.path().join("fallback.sock");

        let resolved = resolve_socket_candidates(primary.clone(), Some(fallback));
        assert_eq!(resolved, primary);
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "socket discovery must not create a throwaway LocalAPI connection"
        );
    }
}
