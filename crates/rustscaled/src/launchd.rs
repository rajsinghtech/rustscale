//! macOS launchd install/uninstall for the rustscaled system daemon.
//!
//! Ports Go's `cmd/tailscaled/install_darwin.go` to Rust with rustscale
//! naming:
//! - plist label: `com.rustscale.rustscaled`
//! - plist path: `/Library/LaunchDaemons/com.rustscale.rustscaled.plist`
//! - target binary: `/usr/local/bin/rustscaled`

use std::io;
use std::path::{Path, PathBuf};

/// launchd service label.
const SERVICE_LABEL: &str = "com.rustscale.rustscaled";
/// Path to the plist file.
const PLIST_PATH: &str = "/Library/LaunchDaemons/com.rustscale.rustscaled.plist";
/// Target binary path.
const TARGET_BIN: &str = "/usr/local/bin/rustscaled";
/// State directory the daemon uses on macOS — matches the `--statedir`
/// argument baked into the plist's `ProgramArguments` and the daemon's
/// `DEFAULT_STATE_DIR` on macOS. Tailscale uses `/var/db/tailscale`.
const STATE_DIR: &str = "/var/db/rustscale";
/// Log directory for launchd's `StandardOutPath`/`StandardErrorPath`
/// redirection.
const LOG_DIR: &str = "/var/log/rustscale";

/// Errors from launchd install/uninstall operations.
#[derive(Debug, thiserror::Error)]
pub enum LaunchdError {
    #[error("must run as root (try sudo)")]
    NotRoot,
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Other(String),
}

/// Generate the launchd plist XML content.
///
/// Mirrors Go's `darwinLaunchdPlist` constant with rustscale naming. The
/// `ProgramArguments` include the `run` subcommand and `--statedir` so
/// launchd starts the daemon the same way an interactive `rustscaled run`
/// would (the binary's `main` requires an explicit subcommand). `KeepAlive`
/// restarts the daemon after a crash, and the standard out/err paths let
/// launchd capture logs for debugging.
pub fn launchd_plist() -> String {
    format!(
        r#"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>

  <key>Label</key>
  <string>{SERVICE_LABEL}</string>

  <key>ProgramArguments</key>
  <array>
    <string>{TARGET_BIN}</string>
    <string>run</string>
    <string>--statedir</string>
    <string>{STATE_DIR}</string>
  </array>

  <key>RunAtLoad</key>
  <true/>

  <key>KeepAlive</key>
  <true/>

  <key>StandardErrorPath</key>
  <string>{LOG_DIR}/rustscaled.log</string>

  <key>StandardOutPath</key>
  <string>{LOG_DIR}/rustscaled.log</string>

</dict>
</plist>
"#
    )
}

/// Check whether the given UID is root (0).
///
/// Takes `uid` as a parameter so it can be unit-tested without changing
/// process privileges. The install/uninstall functions call this with
/// `effective_uid()`.
pub fn check_root(uid: u32) -> Result<(), LaunchdError> {
    if uid != 0 {
        Err(LaunchdError::NotRoot)
    } else {
        Ok(())
    }
}

/// Create the directories the daemon needs at runtime:
/// - `STATE_DIR` (`/var/db/rustscale`, mode `0o700`) — state files.
/// - `LOG_DIR` (`/var/log/rustscale`, mode `0o755`) — log files for launchd's
///   `StandardOutPath`/`StandardErrorPath`.
///
/// The state dir is required (its path is baked into the plist's
/// `ProgramArguments` via `--statedir`). The log dir is created best-effort:
/// a missing log dir just means launchd has nowhere to redirect the daemon's
/// stdout/stderr, which is non-fatal. Must run as root.
fn create_state_and_log_dirs() -> Result<(), LaunchdError> {
    use std::os::unix::fs::PermissionsExt;

    let state_dir = Path::new(STATE_DIR);
    std::fs::create_dir_all(state_dir)?;
    std::fs::set_permissions(state_dir, std::fs::Permissions::from_mode(0o700))?;

    let log_dir = Path::new(LOG_DIR);
    if let Err(e) = std::fs::create_dir_all(log_dir) {
        eprintln!("create {LOG_DIR}: {e} (non-fatal; launchd logs will go nowhere)");
    } else {
        let _ = std::fs::set_permissions(log_dir, std::fs::Permissions::from_mode(0o755));
    }

    Ok(())
}

/// Install the rustscaled system daemon.
///
/// Flow (mirrors Go's `installSystemDaemonDarwin`):
/// 1. Root check.
/// 2. Best-effort uninstall of any existing version.
/// 3. Copy the current binary to `/usr/local/bin/rustscaled` (unless already
///    running from there).
/// 4. Write the plist.
/// 5. `launchctl load` + `launchctl start`.
pub fn install_system_daemon() -> Result<(), LaunchdError> {
    check_root(effective_uid())?;

    // Best effort: uninstall any existing version first.
    let _ = uninstall_system_daemon();

    // Create the state and log directories the daemon expects at runtime.
    // The state dir is required (the plist bakes `--statedir /var/db/rustscale`
    // into ProgramArguments); the log dir is best-effort but lets launchd
    // redirect stdout/stderr to the paths declared in the plist.
    create_state_and_log_dirs()?;

    let exe = std::env::current_exe()
        .map_err(|e| LaunchdError::Other(format!("failed to find our own executable path: {e}")))?;

    let same = same_file(&exe, Path::new(TARGET_BIN))?;
    if !same {
        copy_binary(&exe, Path::new(TARGET_BIN))?;
    }

    std::fs::write(PLIST_PATH, launchd_plist())?;

    run_launchctl(&["load", PLIST_PATH])?;
    run_launchctl(&["start", SERVICE_LABEL])?;

    Ok(())
}

/// Uninstall the rustscaled system daemon.
///
/// Flow (mirrors Go's `uninstallSystemDaemonDarwin`):
/// 1. Root check.
/// 2. If the service is loaded: `launchctl stop` + `launchctl unload`.
/// 3. Remove the plist file.
/// 4. Remove the binary (unless it's a symlink — Homebrew case).
///
/// Tolerates partial state: collects errors and keeps going, returning the
/// first error encountered.
pub fn uninstall_system_daemon() -> Result<(), LaunchdError> {
    check_root(effective_uid())?;

    let mut ret: Result<(), LaunchdError> = Ok(());

    // Check if the service is loaded.
    let running = std::process::Command::new("launchctl")
        .args(["list", SERVICE_LABEL])
        .output()
        .is_ok_and(|o| o.status.success());

    if running {
        if let Err(e) = run_launchctl(&["stop", SERVICE_LABEL]) {
            eprintln!("{e}");
            if ret.is_ok() {
                ret = Err(e);
            }
        }
        if let Err(e) = run_launchctl(&["unload", PLIST_PATH]) {
            eprintln!("{e}");
            if ret.is_ok() {
                ret = Err(e);
            }
        }
    }

    // Remove plist (tolerate not-exist).
    if let Err(e) = std::fs::remove_file(PLIST_PATH) {
        if !is_not_found(&e) {
            eprintln!("remove {PLIST_PATH}: {e}");
            if ret.is_ok() {
                ret = Err(LaunchdError::Io(e));
            }
        }
    }

    // Do not delete the target binary if it's a symlink (Homebrew case).
    if is_symlink(Path::new(TARGET_BIN)) {
        return ret;
    }

    // Remove binary (tolerate not-exist).
    if let Err(e) = std::fs::remove_file(TARGET_BIN) {
        if !is_not_found(&e) {
            eprintln!("remove {TARGET_BIN}: {e}");
            if ret.is_ok() {
                ret = Err(LaunchdError::Io(e));
            }
        }
    }

    ret
}

// --- helpers ---

/// Run a launchctl command, returning an error on non-zero exit.
fn run_launchctl(args: &[&str]) -> Result<(), LaunchdError> {
    let out = std::process::Command::new("launchctl")
        .args(args)
        .output()
        .map_err(|e| LaunchdError::Other(format!("launchctl {}: {e}", args.join(" "))))?;
    if !out.status.success() {
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        return Err(LaunchdError::Other(format!(
            "launchctl {}: {}, {}",
            args.join(" "),
            out.status,
            combined.trim()
        )));
    }
    Ok(())
}

/// Copy a binary file from `src` to `dst`, writing via a temp file and
/// atomically renaming. Removes the old binary before rename to handle the
/// busy-binary case on macOS (where the running daemon may still hold the
/// inode — `remove` succeeds, the old process keeps the inode until exit).
fn copy_binary(src: &Path, dst: &Path) -> io::Result<()> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp_path = PathBuf::from(format!("{}.tmp", dst.display()));
    {
        let mut src_file = std::fs::File::open(src)?;
        let mut dst_file = std::fs::File::create(&tmp_path)?;
        std::io::copy(&mut src_file, &mut dst_file)?;
    }
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o755))?;
    }
    // Remove the old binary before rename (busy-binary safe on Unix).
    let _ = std::fs::remove_file(dst);
    std::fs::rename(&tmp_path, dst)?;
    Ok(())
}

/// Check if `path` is a symlink (mirrors Go's `isSymlink`).
fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
}

/// Check if two paths resolve to the same file (mirrors Go's `sameFile`).
/// Returns `true` if both paths don't exist (matching Go's behavior where
/// `EvalSymlinks` returns "" for `ErrNotExist`).
fn same_file(path1: &Path, path2: &Path) -> Result<bool, LaunchdError> {
    let resolved1 = resolve_symlinks(path1)?;
    let resolved2 = resolve_symlinks(path2)?;
    Ok(resolved1 == resolved2)
}

/// Resolve symlinks, returning `None` for non-existent paths (matching Go's
/// behavior where `EvalSymlinks` returns "" for `ErrNotExist`).
fn resolve_symlinks(path: &Path) -> Result<Option<PathBuf>, LaunchdError> {
    match std::fs::canonicalize(path) {
        Ok(p) => Ok(Some(p)),
        Err(e) if is_not_found(&e) => Ok(None),
        Err(e) => Err(LaunchdError::Other(format!(
            "canonicalize({}): {e}",
            path.display()
        ))),
    }
}

/// Check if an `io::Error` is a "file not found" error.
fn is_not_found(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::NotFound
}

/// Get the effective UID of the current process via the POSIX `id -u`
/// command. This avoids needing `unsafe` to call `geteuid(2)` directly
/// (the workspace forbids `unsafe_code`). If `id` is unavailable (extremely
/// unlikely on any Unix), returns `u32::MAX` so the root check fails safe.
fn effective_uid() -> u32 {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| {
            String::from_utf8(o.stdout)
                .ok()
                .and_then(|s| s.trim().parse().ok())
        })
        .unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plist_content() {
        let plist = launchd_plist();
        let expected = r#"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>

  <key>Label</key>
  <string>com.rustscale.rustscaled</string>

  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/rustscaled</string>
    <string>run</string>
    <string>--statedir</string>
    <string>/var/db/rustscale</string>
  </array>

  <key>RunAtLoad</key>
  <true/>

  <key>KeepAlive</key>
  <true/>

  <key>StandardErrorPath</key>
  <string>/var/log/rustscale/rustscaled.log</string>

  <key>StandardOutPath</key>
  <string>/var/log/rustscale/rustscaled.log</string>

</dict>
</plist>
"#;
        assert_eq!(plist, expected);
    }

    #[test]
    fn test_check_root_refuses_non_root() {
        assert!(check_root(1000).is_err());
        assert!(check_root(501).is_err());
        assert!(check_root(1).is_err());
    }

    #[test]
    fn test_check_root_allows_root() {
        assert!(check_root(0).is_ok());
    }

    #[test]
    fn test_check_root_error_message() {
        let err = check_root(1000).unwrap_err();
        assert_eq!(err.to_string(), "must run as root (try sudo)");
    }

    #[test]
    fn test_is_not_found() {
        assert!(is_not_found(&io::Error::new(
            io::ErrorKind::NotFound,
            "test"
        )));
        assert!(!is_not_found(&io::Error::new(
            io::ErrorKind::PermissionDenied,
            "test"
        )));
    }
}
