//! Unix peer credential extraction — ports the credential-checking half of
//! Go's `ipn/ipnauth` package (`ConnIdentity`, `SO_PEERCRED`/`LOCAL_PEERCRED`).
//!
//! On Linux/macOS/FreeBSD the kernel stamps each accepted Unix-domain-socket
//! connection with the peer's real UID and PID. [`ConnIdentity`] wraps those
//! credentials and provides [`ConnIdentity::is_readwrite`] mirroring Go's
//! `ConnIdentity.IsReadonlyConn` (inverted).
//!
//! # Auth model
//!
//! Read-write access is granted when the peer's uid is 0 (root), matches the
//! daemon's uid (same user), or matches an optional operator uid. When no
//! credentials are available the connection defaults to read-only.

/// Peer credentials (uid + pid) extracted from a connected Unix socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerCreds {
    pub uid: u32,
    pub pid: u32,
}

/// Identity of a connecting peer. Ports Go's `ipn/ipnauth.ConnIdentity`.
#[derive(Clone, Debug, Default)]
pub struct ConnIdentity {
    pub uid: Option<u32>,
    pub pid: Option<u32>,
    pub is_unix_sock: bool,
    /// True only when `uid` came from trusted kernel peer credentials or the
    /// explicitly trusted in-process transport. Credential-authenticated TCP
    /// must leave this false even when it has ordinary LocalAPI write access.
    pub trusted_os_uid: bool,
}

impl ConnIdentity {
    /// Returns an identity that is always granted ordinary read-write access.
    /// This is for credential-authenticated transports such as loopback TCP;
    /// it deliberately carries no trusted local-system identity.
    pub fn readwrite() -> Self {
        Self {
            uid: Some(0),
            pid: None,
            is_unix_sock: false,
            trusted_os_uid: false,
        }
    }

    /// Trusted authority established by the local system, such as a named-pipe
    /// ACL on Windows. Platforms without numeric UIDs represent it as uid 0.
    pub fn trusted_local_system() -> Self {
        Self {
            uid: Some(0),
            pid: None,
            is_unix_sock: false,
            trusted_os_uid: true,
        }
    }

    /// Trusted authority for calls originating inside the owning process.
    pub fn trusted_in_process() -> Self {
        Self::trusted_local_system()
    }

    pub fn has_trusted_os_uid(&self) -> bool {
        self.trusted_os_uid && self.uid.is_some()
    }

    /// Whether this connection should be granted full read-write access.
    /// Mirrors Go's `ConnIdentity.IsReadonlyConn` (inverted).
    ///
    /// Read-write if the peer's uid is 0 (root), matches `daemon_uid` (same
    /// user), or matches `operator_uid` (if set). Returns `false` when no uid
    /// is available (credentials not extractable -> default read-only).
    pub fn is_readwrite(&self, daemon_uid: u32, operator_uid: Option<u32>) -> bool {
        let Some(uid) = self.uid else {
            return false;
        };
        uid == 0 || uid == daemon_uid || operator_uid.is_some_and(|op| uid == op)
    }
}

/// Resolve a local account name to its numeric uid using the platform's NSS
/// path. A lookup failure is intentionally indistinguishable from an absent
/// user to callers: authorization must fail closed.
///
/// This mirrors Tailscale's `osuser.LookupByUsername` used for
/// `Prefs.OperatorUser`. Callers must run it off async worker threads because
/// NSS modules are allowed to block on network directory services.
#[cfg(unix)]
pub fn lookup_uid_by_username(username: &str) -> Option<u32> {
    use std::ffi::CString;
    use std::ptr;

    let username = CString::new(username).ok()?;
    let mut buffer_len = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    if buffer_len < 0 {
        buffer_len = 16 * 1024;
    }
    let mut buffer_len = usize::try_from(buffer_len).ok()?.max(1024);

    loop {
        let mut passwd = unsafe { std::mem::zeroed::<libc::passwd>() };
        let mut result = ptr::null_mut();
        let mut buffer = vec![0 as libc::c_char; buffer_len];
        let status = unsafe {
            libc::getpwnam_r(
                username.as_ptr(),
                &raw mut passwd,
                buffer.as_mut_ptr(),
                buffer.len(),
                &raw mut result,
            )
        };
        if status == 0 {
            return (!result.is_null()).then_some(passwd.pw_uid);
        }
        if status != libc::ERANGE || buffer_len >= 1024 * 1024 {
            return None;
        }
        buffer_len *= 2;
    }
}

#[cfg(not(unix))]
pub fn lookup_uid_by_username(_username: &str) -> Option<u32> {
    None
}

// ---------------------------------------------------------------------------
// Platform-specific peer-credential extraction (unix only)
// ---------------------------------------------------------------------------

#[cfg(unix)]
impl ConnIdentity {
    /// Extract peer credentials from a connected Unix stream.
    pub fn from_stream(stream: &tokio::net::UnixStream) -> Self {
        let creds = get_peer_creds(stream);
        Self {
            uid: creds.as_ref().map(|c| c.uid),
            pid: creds.as_ref().map(|c| c.pid),
            is_unix_sock: true,
            trusted_os_uid: creds.is_some(),
        }
    }
}

/// Get peer credentials from a connected Unix socket.
///
/// - **Linux**: `SO_PEERCRED` -> `struct ucred` (pid, uid, gid)
/// - **macOS**: `getpeereid()` for uid + `LOCAL_PEERPID` for pid
/// - **FreeBSD**: `LOCAL_PEERCRED` -> `struct xucred`
///
/// Returns `None` when credentials are not available or the platform is
/// unsupported (e.g. Solaris/Illumos — future work).
#[cfg(target_os = "linux")]
pub fn get_peer_creds(stream: &tokio::net::UnixStream) -> Option<PeerCreds> {
    use std::os::unix::io::AsRawFd;

    let fd = stream.as_raw_fd();
    let mut ucred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut ucred).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if ret == 0 {
        Some(PeerCreds {
            uid: ucred.uid,
            pid: ucred.pid as u32,
        })
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
pub fn get_peer_creds(stream: &tokio::net::UnixStream) -> Option<PeerCreds> {
    use std::os::unix::io::AsRawFd;

    let fd = stream.as_raw_fd();
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    if unsafe { libc::getpeereid(fd, &raw mut uid, &raw mut gid) } != 0 {
        return None;
    }
    // LOCAL_PEERPID is not in the libc crate; defined in <sys/un.h> as 0x004.
    const LOCAL_PEERPID: libc::c_int = 0x004;
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    let pid_ok = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            LOCAL_PEERPID,
            (&raw mut pid).cast::<libc::c_void>(),
            &raw mut len,
        )
    } == 0;
    Some(PeerCreds {
        uid,
        pid: if pid_ok && pid > 0 { pid as u32 } else { 0 },
    })
}

#[cfg(target_os = "freebsd")]
pub fn get_peer_creds(stream: &tokio::net::UnixStream) -> Option<PeerCreds> {
    use std::os::unix::io::AsRawFd;

    let fd = stream.as_raw_fd();
    let mut xucred: libc::xucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::xucred>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::LOCAL_PEERCRED,
            (&raw mut xucred).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if ret == 0 && xucred.cr_version != 0 {
        Some(PeerCreds {
            uid: xucred.cr_uid,
            pid: 0,
        })
    } else {
        None
    }
}

/// Fallback for unix platforms without a dedicated implementation
/// (solaris/illumos — future work).
#[cfg(all(
    unix,
    not(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))
))]
pub fn get_peer_creds(_stream: &tokio::net::UnixStream) -> Option<PeerCreds> {
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_readwrite_identity_alows_all() {
        let id = ConnIdentity::readwrite();
        assert!(id.is_readwrite(0, None));
        assert!(id.is_readwrite(1000, None));
        assert!(id.is_readwrite(501, Some(42)));
        assert!(!id.has_trusted_os_uid());
        assert!(ConnIdentity::trusted_in_process().has_trusted_os_uid());
    }

    #[test]
    fn test_is_readwrite_root() {
        let id = ConnIdentity {
            uid: Some(0),
            pid: Some(123),
            is_unix_sock: true,
            trusted_os_uid: true,
        };
        assert!(id.is_readwrite(501, None));
        assert!(id.is_readwrite(1000, None));
        assert!(id.has_trusted_os_uid());
    }

    #[test]
    fn test_is_readwrite_same_uid() {
        let id = ConnIdentity {
            uid: Some(501),
            pid: Some(123),
            is_unix_sock: true,
            trusted_os_uid: true,
        };
        assert!(id.is_readwrite(501, None));
        assert!(!id.is_readwrite(502, None));
        assert!(id.has_trusted_os_uid());
    }

    #[test]
    fn test_is_readwrite_operator_uid() {
        let id = ConnIdentity {
            uid: Some(42),
            pid: None,
            is_unix_sock: true,
            trusted_os_uid: true,
        };
        assert!(id.is_readwrite(501, Some(42)));
        assert!(!id.is_readwrite(501, None));
        assert!(id.has_trusted_os_uid());
    }

    #[test]
    fn test_is_readwrite_no_creds_is_readonly() {
        let id = ConnIdentity::default();
        assert!(!id.is_readwrite(0, None));
        assert!(!id.is_readwrite(501, None));
        assert!(!id.has_trusted_os_uid());
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    #[tokio::test]
    async fn test_get_peer_creds_same_process() {
        use tokio::io::AsyncReadExt;
        use tokio::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("peercred-test.sock");
        let listener = UnixListener::bind(&sock).unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let creds = get_peer_creds(&stream);
            // Drop the stream so the client sees EOF.
            drop(stream);
            creds
        });

        let mut client = tokio::net::UnixStream::connect(&sock).await.unwrap();
        // Keep the client open until the server has read creds.
        let mut buf = [0u8; 1];
        let _ =
            tokio::time::timeout(std::time::Duration::from_secs(2), client.read(&mut buf)).await;
        drop(client);

        let creds = server.await.unwrap();
        assert!(creds.is_some(), "peer creds should be available");
        let creds = creds.unwrap();
        let self_uid = unsafe { libc::getuid() };
        assert_eq!(creds.uid, self_uid);
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    #[tokio::test]
    async fn test_conn_identity_from_stream() {
        use tokio::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("identity-test.sock");
        let listener = UnixListener::bind(&sock).unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let identity = ConnIdentity::from_stream(&stream);
            drop(stream);
            identity
        });

        let _client = tokio::net::UnixStream::connect(&sock).await.unwrap();
        let identity = server.await.unwrap();

        assert!(identity.is_unix_sock);
        assert!(identity.uid.is_some());
        let self_uid = unsafe { libc::getuid() };
        assert_eq!(identity.uid, Some(self_uid));
        assert!(identity.has_trusted_os_uid());
        // Same-uid peer should be read-write.
        assert!(identity.is_readwrite(self_uid, None));
    }
}
