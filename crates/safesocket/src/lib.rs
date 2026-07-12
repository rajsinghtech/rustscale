//! CLI <-> daemon IPC for rustscale, ported from Tailscale's Go `safesocket`
//! package. Provides Unix socket listen/connect with correct permissions, and
//! on macOS, the "sameuserproof" localhost-TCP fallback for sandboxed daemon
//! scenarios where a Unix socket is not available.
//!
//! # Core API
//!
//! - [`listen`] — bind a Unix socket listener at `path`, removing any stale
//!   socket file and setting filesystem permissions appropriate for the
//!   platform.
//! - [`connect`] — dial a Unix socket at `path`.
//! - [`connect_with_retries`] — dial with retry loop (mirrors Go's
//!   `ConnectContext` for when the daemon is still starting).
//!
//! # macOS sameuserproof
//!
//! On macOS the daemon may run inside the App Sandbox / System Extension where
//! it cannot create a world-accessible Unix socket. Instead it listens on a
//! localhost TCP ephemeral port and writes a "sameuserproof" proof file so an
//! unprivileged CLI of the same user can discover the port and auth token.
//! See the [`darwin`] module.

#![allow(clippy::module_name_repetitions)]

#[cfg(unix)]
mod unix;

#[cfg(unix)]
pub use unix::{connect, connect_with_retries, listen, platform_uses_peer_creds};

#[cfg(target_os = "macos")]
pub mod darwin;

#[cfg(test)]
mod tests;
