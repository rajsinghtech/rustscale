//! macOS "sameuserproof" localhost-TCP fallback — ported from Go's
//! `safesocket/safesocket_darwin.go`.
//!
//! When the daemon runs inside the macOS App Sandbox or as a System Extension,
//! it cannot create a world-accessible Unix socket. Instead it listens on a
//! localhost TCP ephemeral port and writes a "sameuserproof" proof file so an
//! unprivileged CLI of the same user can discover the port and auth token.
//!
//! Two variants:
//!
//! - **macsys** (standalone notarized / System Extension): the daemon runs as
//!   root. A file named `sameuserproof-{port}` *containing* the token is
//!   written to `shared_dir` (e.g. `/Library/Tailscale`) with mode `0o640`,
//!   and a symlink `ipnport -> {port}` is created alongside it.
//!
//! - **macos** (App Store / IPNExtension): the daemon runs as the user. A file
//!   named `sameuserproof-{port}-{token}` (empty content) is written to the
//!   app's container dir. The CLI discovers it via `lsof` (the file is kept
//!   open so lsof can find it by file descriptor).

use std::fs;
use std::io;
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;

use rand::rngs::OsRng;
use rand::RngCore;

/// Number of random bytes in a sameuserproof token. The hex-encoded token
/// string is twice this length (20 chars). Mirrors Go's
/// `sameUserProofTokenLength`.
pub const SAME_USER_PROOF_TOKEN_LENGTH: usize = 10;

/// macOS admin group GID (used for macsys file ownership).
const ADMIN_GID: u32 = 80;

/// A discovered port + token pair for the sameuserproof mechanism.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SameUserProof {
    /// Localhost TCP port the daemon is listening on.
    pub port: u16,
    /// Hex-encoded auth token.
    pub token: String,
}

/// Errors from the darwin sameuserproof mechanism.
#[derive(Debug, thiserror::Error)]
pub enum DarwinError {
    #[error("no token found")]
    TokenNotFound,
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("invalid proof file: {0}")]
    InvalidProof(String),
}

/// Configuration and state for the darwin sameuserproof mechanism.
///
/// Fields are injectable so tests can use tempdirs and toggle variants without
/// touching `/Library/Tailscale` or running `lsof`.
pub struct DarwinSafesocket {
    shared_dir: PathBuf,
    is_mac_sys_ext: bool,
    check_conn: bool,
    explicit_credentials: Mutex<Option<SameUserProof>>,
}

impl DarwinSafesocket {
    /// Create a new instance with the given `shared_dir` and default settings
    /// (non-macsys, connection-checking enabled).
    pub fn new(shared_dir: PathBuf) -> Self {
        Self {
            shared_dir,
            is_mac_sys_ext: false,
            check_conn: true,
            explicit_credentials: Mutex::new(None),
        }
    }

    /// Set whether this instance represents the macOS System Extension
    /// (macsys variant). Default: `false`.
    pub fn with_mac_sys_ext(mut self, v: bool) -> Self {
        self.is_mac_sys_ext = v;
        self
    }

    /// Set whether `port_and_token` verifies the port is connectable before
    /// returning it (guards against stale proof files). Default: `true`.
    pub fn with_check_conn(mut self, v: bool) -> Self {
        self.check_conn = v;
        self
    }

    /// Explicitly set the port and token, overriding the sameuserproof file
    /// lookup. Mirrors Go's `SetCredentials` — used when the CLI is invoked
    /// from the Tailscale.app GUI which already knows the credentials via XPC.
    pub fn set_credentials(&self, port: u16, token: String) {
        let mut guard = self.explicit_credentials.lock().expect("mutex poisoned");
        *guard = Some(SameUserProof { port, token });
    }

    /// Returns the shared directory used for proof files.
    pub fn shared_dir(&self) -> &Path {
        &self.shared_dir
    }

    /// Initialise the daemon-side listener: bind a localhost TCP ephemeral
    /// port, generate a random token, write the sameuserproof proof file(s),
    /// and return the listener + proof.
    ///
    /// Mirrors Go's `InitListenerDarwin`.
    pub fn init_listener(&self) -> io::Result<(TcpListener, SameUserProof)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let token = generate_token();

        if port == 0 || token.is_empty() {
            return Err(io::Error::other("invalid localhost port or token"));
        }

        init_sameuserproof_token(&self.shared_dir, port, &token, self.is_mac_sys_ext)?;

        let proof = SameUserProof {
            port,
            token: token.clone(),
        };

        let mut guard = self.explicit_credentials.lock().expect("mutex poisoned");
        *guard = Some(proof.clone());

        Ok((listener, proof))
    }

    /// Resolve the port and token for connecting to the local daemon.
    ///
    /// Priority: explicit credentials (set via [`set_credentials`] or
    /// [`init_listener`]) take precedence, then the sameuserproof file lookup
    /// is tried (macos variant via lsof, then macsys variant via filesystem).
    ///
    /// Mirrors Go's `localTCPPortAndTokenDarwin`.
    pub fn port_and_token(&self) -> Result<SameUserProof, DarwinError> {
        {
            let guard = self.explicit_credentials.lock().expect("mutex poisoned");
            if let Some(ref creds) = *guard {
                return Ok(creds.clone());
            }
        }
        port_and_token_from_sameuserproof(&self.shared_dir, self.check_conn)
    }
}

/// Generate a cryptographically random hex token of length
/// `2 * SAME_USER_PROOF_TOKEN_LENGTH` (20 chars). Mirrors Go's `getToken`.
pub fn generate_token() -> String {
    let mut buf = [0u8; SAME_USER_PROOF_TOKEN_LENGTH];
    OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Write the sameuserproof proof file(s) to `shared_dir`.
///
/// Removes any existing `sameuserproof-*` files first. The file layout depends
/// on `is_mac_sys_ext`:
///
/// - `true` (macsys): creates `sameuserproof-{port}` containing `"{token}\n"`
///   with mode `0o640`, and a symlink `ipnport -> {port}`. File ownership is
///   set to root:admin (best-effort, requires running as root).
/// - `false` (macos): creates `sameuserproof-{port}-{token}` (empty) with mode
///   `0o666`.
pub fn init_sameuserproof_token(
    shared_dir: &Path,
    port: u16,
    token: &str,
    is_mac_sys_ext: bool,
) -> io::Result<()> {
    if let Ok(entries) = fs::read_dir(shared_dir) {
        for entry in entries.flatten() {
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with("sameuserproof-")
            {
                let _ = fs::remove_file(entry.path());
            }
        }
    }

    if is_mac_sys_ext {
        let base_file = format!("sameuserproof-{port}");
        let path = shared_dir.join(&base_file);

        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o640)
            .open(&path)?;

        use std::io::Write;
        writeln!(file, "{token}")?;

        let port_file = shared_dir.join("ipnport");
        let _ = fs::remove_file(&port_file);
        let _ = std::os::unix::fs::symlink(port.to_string(), &port_file);

        unsafe {
            libc::fchown(file.as_raw_fd(), 0, ADMIN_GID);
        }
    } else {
        let base_file = format!("sameuserproof-{port}-{token}");
        let path = shared_dir.join(&base_file);

        let _ = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o666)
            .open(&path)?;
    }

    Ok(())
}

/// Read the port and token from a macsys-style proof file.
///
/// Reads the `ipnport` symlink for the port, then reads
/// `sameuserproof-{port}` for the token. If `check_conn` is true, also
/// verifies the port is connectable on localhost.
///
/// Mirrors Go's `readMacsysSameUserProof`.
pub fn read_macsys_sameuserproof(
    shared_dir: &Path,
    check_conn: bool,
) -> Result<SameUserProof, DarwinError> {
    let port_file = shared_dir.join("ipnport");
    let port_link = fs::read_link(&port_file)?;
    let port_str = port_link.to_string_lossy().into_owned();
    let port: u16 = port_str
        .parse()
        .map_err(|_| DarwinError::InvalidProof(format!("invalid port: {port_str}")))?;

    let proof_file = shared_dir.join(format!("sameuserproof-{port_str}"));
    let auth_bytes = fs::read(&proof_file)?;
    let auth = String::from_utf8_lossy(&auth_bytes).trim().to_string();

    if auth.is_empty() {
        return Err(DarwinError::InvalidProof("empty auth token".into()));
    }

    if check_conn {
        let addr = format!("127.0.0.1:{port}");
        let sock_addr: std::net::SocketAddr = addr
            .parse()
            .map_err(|_| DarwinError::InvalidProof(format!("invalid address: {addr}")))?;
        let conn = TcpStream::connect_timeout(&sock_addr, Duration::from_secs(1))?;
        drop(conn);
    }

    Ok(SameUserProof { port, token: auth })
}

/// Read the port and token from a macos-style proof file via `lsof`.
///
/// Searches for open files belonging to the current user and the IPNExtension
/// process whose path contains `.tailscale.ipn.macos/sameuserproof-{port}-{token}`.
///
/// Mirrors Go's `readMacosSameUserProof`.
pub fn read_macos_sameuserproof() -> Result<SameUserProof, DarwinError> {
    let uid = unsafe { libc::getuid() };
    let uid_arg = format!("-u{uid}");

    let output = Command::new("lsof")
        .args(["-n", "-a", &uid_arg, "-c", "IPNExtension", "-F"])
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    const SUB_STR: &str = ".tailscale.ipn.macos/sameuserproof-";

    for line in stdout.lines() {
        if let Some(idx) = line.find(SUB_STR) {
            let rest = &line[idx + SUB_STR.len()..];
            let mut parts = rest.splitn(2, '-');
            let Some(port_str) = parts.next() else {
                continue;
            };
            let Some(token) = parts.next() else {
                continue;
            };
            let port: u16 = port_str.parse().map_err(|_| {
                DarwinError::InvalidProof(format!("invalid port in lsof: {port_str}"))
            })?;
            return Ok(SameUserProof {
                port,
                token: token.to_string(),
            });
        }
    }

    Err(DarwinError::TokenNotFound)
}

/// Try the macos (lsof) variant first, then the macsys (filesystem) variant.
///
/// Mirrors Go's `portAndTokenFromSameUserProof`.
pub fn port_and_token_from_sameuserproof(
    shared_dir: &Path,
    check_conn: bool,
) -> Result<SameUserProof, DarwinError> {
    if let Ok(proof) = read_macos_sameuserproof() {
        return Ok(proof);
    }
    if let Ok(proof) = read_macsys_sameuserproof(shared_dir, check_conn) {
        return Ok(proof);
    }
    Err(DarwinError::TokenNotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_token_valid(token: &str) {
        assert_eq!(
            token.len(),
            SAME_USER_PROOF_TOKEN_LENGTH * 2,
            "token length"
        );
        assert!(
            token
                .chars()
                .all(|c: char| c.is_ascii_digit() || ('a'..='f').contains(&c)),
            "token charset: {token}"
        );
    }

    #[test]
    fn test_generate_token_length_and_charset() {
        let token = generate_token();
        assert_token_valid(&token);
    }

    #[test]
    fn test_generate_token_uniqueness() {
        let t1 = generate_token();
        let t2 = generate_token();
        assert_ne!(t1, t2, "tokens should be random");
        assert_token_valid(&t1);
        assert_token_valid(&t2);
    }

    #[test]
    fn test_init_sameuserproof_macsys() {
        let dir = tempfile::tempdir().unwrap();
        const PORT: u16 = 12345;
        const TOKEN: &str = "deadbeefcafe";

        init_sameuserproof_token(dir.path(), PORT, TOKEN, true).unwrap();

        let proof = read_macsys_sameuserproof(dir.path(), false).unwrap();
        assert_eq!(proof.port, PORT);
        assert_eq!(proof.token, TOKEN);
    }

    #[test]
    fn test_init_sameuserproof_macos() {
        let dir = tempfile::tempdir().unwrap();
        const PORT: u16 = 12345;
        const TOKEN: &str = "deadbeefcafe";

        init_sameuserproof_token(dir.path(), PORT, TOKEN, false).unwrap();

        let expected = format!("sameuserproof-{PORT}-{TOKEN}");
        assert!(
            dir.path().join(&expected).exists(),
            "macos proof file should exist: {expected}"
        );
    }

    #[test]
    fn test_init_sameuserproof_no_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        const PORT: u16 = 12345;
        const TOKEN: &str = "deadbeefcafe";

        init_sameuserproof_token(dir.path(), PORT, TOKEN, false).unwrap();
        init_sameuserproof_token(dir.path(), PORT, TOKEN, false).unwrap();

        let count = fs::read_dir(dir.path())
            .unwrap()
            .filter(|e| {
                e.as_ref().is_ok_and(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .starts_with("sameuserproof-")
                })
            })
            .count();
        assert_eq!(count, 1, "should have exactly one proof file");
    }

    #[test]
    fn test_init_sameuserproof_macsys_removes_old_files() {
        let dir = tempfile::tempdir().unwrap();

        init_sameuserproof_token(dir.path(), 11111, "oldtoken", false).unwrap();
        init_sameuserproof_token(dir.path(), 22222, "newtoken", true).unwrap();

        let count = fs::read_dir(dir.path())
            .unwrap()
            .filter(|e| {
                e.as_ref().is_ok_and(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .starts_with("sameuserproof-")
                })
            })
            .count();
        assert_eq!(count, 1, "old proof files should be removed");
    }

    #[test]
    fn test_read_macsys_malformed_port() {
        let dir = tempfile::tempdir().unwrap();

        let port_file = dir.path().join("ipnport");
        std::os::unix::fs::symlink("notaport", &port_file).unwrap();

        let result = read_macsys_sameuserproof(dir.path(), false);
        assert!(matches!(result, Err(DarwinError::InvalidProof(_))));
    }

    #[test]
    fn test_read_macsys_empty_token() {
        let dir = tempfile::tempdir().unwrap();

        let port_file = dir.path().join("ipnport");
        std::os::unix::fs::symlink("12345", &port_file).unwrap();

        let proof_file = dir.path().join("sameuserproof-12345");
        fs::write(&proof_file, "  \n").unwrap();

        let result = read_macsys_sameuserproof(dir.path(), false);
        assert!(matches!(result, Err(DarwinError::InvalidProof(_))));
    }

    #[test]
    fn test_read_macsys_missing_ipnport() {
        let dir = tempfile::tempdir().unwrap();
        let result = read_macsys_sameuserproof(dir.path(), false);
        assert!(result.is_err());
    }

    #[test]
    fn test_darwin_set_credentials_override() {
        let dir = tempfile::tempdir().unwrap();
        let ss = DarwinSafesocket::new(dir.path().to_path_buf());

        ss.set_credentials(123, "mytoken".into());

        let proof = ss.port_and_token().unwrap();
        assert_eq!(proof.port, 123);
        assert_eq!(proof.token, "mytoken");
    }

    #[test]
    fn test_darwin_init_listener() {
        let dir = tempfile::tempdir().unwrap();
        let ss = DarwinSafesocket::new(dir.path().to_path_buf())
            .with_mac_sys_ext(true)
            .with_check_conn(false);

        let (listener, proof) = ss.init_listener().unwrap();
        assert_ne!(proof.port, 0, "port should be non-zero");
        assert!(!proof.token.is_empty(), "token should be non-empty");
        assert_token_valid(&proof.token);

        let resolved = ss.port_and_token().unwrap();
        assert_eq!(resolved, proof);

        drop(listener);
    }

    #[test]
    fn test_darwin_fallback_to_sameuserproof() {
        let dir = tempfile::tempdir().unwrap();
        let ss = DarwinSafesocket::new(dir.path().to_path_buf())
            .with_mac_sys_ext(true)
            .with_check_conn(false);

        init_sameuserproof_token(dir.path(), 12345, "fallofftoken", true).unwrap();

        let proof = ss.port_and_token().unwrap();
        assert_eq!(proof.port, 12345);
        assert_eq!(proof.token, "fallofftoken");
    }

    #[test]
    fn test_darwin_port_and_token_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let ss = DarwinSafesocket::new(dir.path().to_path_buf()).with_check_conn(false);

        let result = ss.port_and_token();
        assert!(matches!(result, Err(DarwinError::TokenNotFound)));
    }
}
