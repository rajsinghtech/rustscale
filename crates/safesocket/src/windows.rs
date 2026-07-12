//! Windows named-pipe listen/connect — ported from Go's
//! `safesocket/pipe_windows.go`.
//!
//! The pipe path uses the `ProtectedPrefix\Administrators` prefix to restrict
//! pipe creation to elevated processes, matching the Tailscale convention.
//! Pipe instances are created with 256 KiB input/output buffers and
//! `reject_remote_clients(true)` for security.

use std::io;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};

/// Default pipe path for the rustscale daemon.
pub const DEFAULT_PIPE_PATH: &str = r"\\.\pipe\ProtectedPrefix\Administrators\Rustscale\rustscaled";

/// A named-pipe listener that mimics the `accept()` pattern of a Unix socket
/// listener. The first pipe instance is created in [`listen`] so the pipe name
/// is registered with the system before any client tries to connect. Each call
/// to [`Listener::accept`] either reuses the pending instance or creates a new
/// one, then waits for a client to connect.
pub struct Listener {
    pipe_name: String,
    pending: Mutex<Option<NamedPipeServer>>,
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listener")
            .field("pipe_name", &self.pipe_name)
            .field("pending", &self.pending.lock().map(|g| g.is_some()))
            .finish()
    }
}

impl Listener {
    /// Wait for a client to connect and return the server-side stream.
    pub async fn accept(&self) -> io::Result<NamedPipeServer> {
        let server = {
            let mut guard = self.pending.lock().expect("mutex poisoned");
            guard.take()
        };
        let server = match server {
            Some(s) => s,
            None => create_pipe_instance(&self.pipe_name)?,
        };
        server.connect().await?;
        Ok(server)
    }
}

/// Create a named-pipe listener at `path`.
///
/// The path should be of the form `\\.\pipe\...`. A first pipe instance is
/// created immediately so the pipe name is visible to clients; the actual
/// client connection waits happen in [`Listener::accept`].
pub fn listen(path: &Path) -> io::Result<Listener> {
    let pipe_name = path_to_pipe_name(path)?;
    let first = create_pipe_instance(&pipe_name)?;
    Ok(Listener {
        pipe_name,
        pending: Mutex::new(Some(first)),
    })
}

/// Connect to a named pipe at `path`.
pub fn connect(path: &Path) -> io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    let pipe_name = path_to_pipe_name(path)?;
    ClientOptions::new()
        .pipe_mode(tokio::net::windows::named_pipe::PipeMode::Byte)
        .open(&pipe_name)
}

/// Connect to a named pipe at `path`, retrying every 250 ms until `timeout`
/// elapses. Mirrors Go's `ConnectContext` retry loop for when the daemon is
/// still starting up.
pub fn connect_with_retries(
    path: &Path,
    timeout: Duration,
) -> io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    let pipe_name = path_to_pipe_name(path)?;
    let start = Instant::now();
    loop {
        match ClientOptions::new()
            .pipe_mode(tokio::net::windows::named_pipe::PipeMode::Byte)
            .open(&pipe_name)
        {
            Ok(conn) => return Ok(conn),
            Err(e) => {
                if start.elapsed() >= timeout {
                    return Err(e);
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        }
    }
}

fn create_pipe_instance(pipe_name: &str) -> io::Result<NamedPipeServer> {
    ServerOptions::new()
        .first_pipe_instance(false)
        .pipe_mode(tokio::net::windows::named_pipe::PipeMode::Byte)
        .in_buffer_size(256 * 1024)
        .out_buffer_size(256 * 1024)
        .reject_remote_clients(true)
        .create(pipe_name)
}

fn path_to_pipe_name(path: &Path) -> io::Result<String> {
    path.as_os_str()
        .to_str()
        .map(|s| s.to_string())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid pipe path (non-UTF-8): {}", path.display()),
            )
        })
}
