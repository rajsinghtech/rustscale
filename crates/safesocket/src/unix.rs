//! Unix domain socket listen/connect — ported from Go's
//! `safesocket/unixsocket.go`.
//!
//! `listen` removes stale socket files (nobody listening) before binding and
//! sets filesystem permissions appropriate for the platform:
//! - `0o666` on platforms that use peer credentials (linux, darwin, freebsd,
//!   solaris, illumos) — the kernel authenticates the peer, so the file can
//!   be world-readable.
//! - `0o600` elsewhere (root-only).

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

/// Bind a Unix socket listener at `path`.
///
/// If a socket file already exists and something is listening on it, returns
/// `AddrInUse`. If the file exists but nobody is listening (stale), it is
/// removed and a new listener is bound.
///
/// The parent directory is created if missing. On platforms that use peer
/// credentials, the socket and directory permissions are widened so
/// unprivileged peers can connect.
pub fn listen(path: &Path) -> io::Result<UnixListener> {
    if UnixStream::connect(path).is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            format!("{}: address already in use", path.display()),
        ));
    }

    let _ = fs::remove_file(path);

    let perm = socket_permissions();

    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
            if perm == 0o666 {
                if let Ok(meta) = fs::metadata(parent) {
                    let mode = meta.permissions().mode();
                    if mode.trailing_zeros() >= 6 {
                        let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o755));
                    }
                }
            }
        }
    }

    let listener = UnixListener::bind(path)?;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(perm));

    Ok(listener)
}

/// Dial a Unix socket at `path`.
pub fn connect(path: &Path) -> io::Result<UnixStream> {
    UnixStream::connect(path)
}

/// Dial a Unix socket at `path`, retrying every 250 ms until `timeout` elapses.
///
/// Mirrors Go's `ConnectContext` retry loop for when the daemon is still
/// starting up and hasn't bound the socket yet.
pub fn connect_with_retries(path: &Path, timeout: Duration) -> io::Result<UnixStream> {
    let start = Instant::now();
    loop {
        match UnixStream::connect(path) {
            Ok(conn) => return Ok(conn),
            Err(e) => {
                if start.elapsed() >= timeout {
                    return Err(e);
                }
                thread::sleep(Duration::from_millis(250));
            }
        }
    }
}

/// Reports whether the current platform authenticates Unix socket peers via
/// SO_PEERCRED / LOCAL_PEERCRED. Mirrors Go's `PlatformUsesPeerCreds`.
pub fn platform_uses_peer_creds() -> bool {
    cfg!(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "solaris",
        target_os = "illumos",
    ))
}

fn socket_permissions() -> u32 {
    if platform_uses_peer_creds() {
        0o666
    } else {
        0o600
    }
}
