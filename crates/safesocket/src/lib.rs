//! CLI <-> daemon IPC for rustscale, ported from Tailscale's Go `safesocket`
//! package. Provides:
//! - **Unix**: Unix domain socket listen/connect with correct permissions.
//! - **macOS**: "sameuserproof" localhost-TCP fallback for sandboxed daemon
//!   scenarios where a Unix socket is not available (see [`darwin`] module).
//! - **Windows**: Named pipe listen/connect (see `windows` module).
//!
//! # Core API
//!
//! - [`listen`] — bind a listener at `path` (Unix socket or named pipe).
//! - [`connect`] — dial the daemon at `path`.
//! - [`connect_with_retries`] — dial with retry loop (mirrors Go's
//!   `ConnectContext` for when the daemon is still starting).
//! - [`Listener::accept`] — accept an incoming connection (async).
//!
//! All connection types implement `tokio::io::AsyncRead + AsyncWrite + Unpin`.

#![allow(clippy::module_name_repetitions)]

#[cfg(unix)]
mod unix;

#[cfg(windows)]
mod windows;

#[cfg(target_os = "macos")]
pub mod darwin;

// ---------------------------------------------------------------------------
// Platform-agnostic type aliases
// ---------------------------------------------------------------------------

/// Client-side connection type returned by [`connect`].
///
/// On Unix this is `tokio::net::UnixStream`; on Windows a named-pipe client.
/// Both implement `tokio::io::AsyncRead + AsyncWrite + Unpin`.
#[cfg(unix)]
pub type Connection = tokio::net::UnixStream;
#[cfg(windows)]
pub type Connection = tokio::net::windows::named_pipe::NamedPipeClient;

/// Server-side stream type returned by [`Listener::accept`].
///
/// On Unix this is `tokio::net::UnixStream`; on Windows a named-pipe server
/// instance. Both implement `tokio::io::AsyncRead + AsyncWrite + Unpin`.
#[cfg(unix)]
pub type ServerStream = tokio::net::UnixStream;
#[cfg(windows)]
pub type ServerStream = tokio::net::windows::named_pipe::NamedPipeServer;

/// Listener for incoming IPC connections.
#[cfg(unix)]
pub use unix::Listener;
#[cfg(windows)]
pub use windows::Listener;

// ---------------------------------------------------------------------------
// Cross-platform functions
// ---------------------------------------------------------------------------

/// Listen at the given path.
///
/// On Unix, creates a Unix domain socket with appropriate permissions. On
/// Windows, creates a named pipe (path should be `\\.\pipe\...`).
pub fn listen(path: &std::path::Path) -> std::io::Result<Listener> {
    #[cfg(unix)]
    {
        unix::listen(path)
    }
    #[cfg(windows)]
    {
        windows::listen(path)
    }
}

/// Connect to the daemon at the given path.
///
/// On Unix, dials a Unix domain socket. On Windows, opens a named pipe.
pub fn connect(path: &std::path::Path) -> std::io::Result<Connection> {
    #[cfg(unix)]
    {
        unix::connect(path)
    }
    #[cfg(windows)]
    {
        windows::connect(path)
    }
}

/// Connect with retry loop, retrying every 250 ms until `timeout` elapses.
///
/// Mirrors Go's `ConnectContext` for when the daemon is still starting.
pub fn connect_with_retries(
    path: &std::path::Path,
    timeout: std::time::Duration,
) -> std::io::Result<Connection> {
    #[cfg(unix)]
    {
        unix::connect_with_retries(path, timeout)
    }
    #[cfg(windows)]
    {
        windows::connect_with_retries(path, timeout)
    }
}

/// Reports whether the current platform authenticates IPC peers via
/// credentials (SO_PEERCRED / LOCAL_PEERCRED). Always `false` on Windows.
pub fn platform_uses_peer_creds() -> bool {
    #[cfg(unix)]
    {
        unix::platform_uses_peer_creds()
    }
    #[cfg(windows)]
    {
        false
    }
}

/// The platform-default socket/pipe path for the rustscale daemon.
///
/// - **macOS**: `/var/run/rustscaled.sock`
/// - **Linux**: `/var/run/rustscaled.sock` (or `tailscaled.sock` in the
///   state dir as fallback)
/// - **Windows**: `\\.\pipe\ProtectedPrefix\Administrators\Rustscale\rustscaled`
pub fn default_socket_path() -> std::path::PathBuf {
    #[cfg(unix)]
    {
        std::path::PathBuf::from("/var/run/rustscaled.sock")
    }
    #[cfg(windows)]
    {
        std::path::PathBuf::from(windows::DEFAULT_PIPE_PATH)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
