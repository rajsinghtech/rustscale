//! Platform TUN device abstraction for rustscale.
//!
//! Provides an async [`Tun`] trait and a concrete [`TunDevice`] that wraps the
//! OS-level TUN interface:
//! - **macOS**: `utun` via `socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)` +
//!   `CTLIOCGINFO` for `com.apple.net.utun_control`, with the 4-byte address-family
//!   header stripped/prepended on read/write (matching Go's `wireguard-go/tun`).
//! - **Linux**: `/dev/net/tun` with `TUNSETIFF` (`IFF_TUN | IFF_NO_PI`).
//!
//! The public API deals in **plain IP packets** — the macOS AF header and the
//! Linux packet-info byte are never exposed to callers. See [`strip_af_header`]
//! and [`prepend_af_header`] for the framing primitives, which are unit-tested
//! independently of any real device.
//!
//! # Why hand-rolled instead of the `tun` crate?
//!
//! We need exact control over the macOS utun 4-byte AF framing (the `tun` crate
//! on crates.io exposes a sync or Linux-centric API and varies by version), a
//! tokio `AsyncFd`-friendly async surface, and plain-packet semantics with no
//! platform framing leaking. Hand-rolling against `libc` + `tokio::io::AsyncFd`
//! is the most faithful port of `wireguard-go/tun/tun_darwin.go` and keeps the
//! boundary clean. This crate is the only one in the workspace that permits
//! `unsafe` (raw syscalls require it); all other crates keep
//! `unsafe_code = "forbid"`.

use std::io;

use async_trait::async_trait;

#[cfg(target_os = "macos")]
#[path = "darwin.rs"]
mod darwin;
#[cfg(target_os = "linux")]
#[path = "linux.rs"]
mod linux;
mod mock;

#[cfg(target_os = "macos")]
pub use darwin::TunDevice;
#[cfg(target_os = "linux")]
pub use linux::TunDevice;
pub use mock::MockTun;

/// Errors from TUN device operations.
#[derive(Debug, thiserror::Error)]
pub enum TunError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid tun name: {0}")]
    InvalidName(String),
    #[error("tun device creation failed: {0}")]
    Create(String),
}

/// An async TUN device that reads and writes plain IP packets.
///
/// Implementations strip/prepend platform-specific framing internally so callers
/// only ever see raw IPv4/IPv6 packets. `TunDevice` is the real OS-backed
/// implementation; [`MockTun`] is an in-memory implementation for tests.
#[async_trait]
pub trait Tun: Send + Sync {
    /// Read one IP packet from the device into a fresh `Vec`.
    async fn read_packet(&self) -> io::Result<Vec<u8>>;

    /// Write one IP packet to the device.
    async fn write_packet(&self, packet: &[u8]) -> io::Result<()>;

    /// The OS-assigned interface name (e.g. `utun4`).
    fn name(&self) -> &str;

    /// The device MTU in bytes.
    fn mtu(&self) -> usize;
}

/// Configuration for creating a [`TunDevice`].
#[derive(Clone, Debug)]
pub struct TunConfig {
    /// Interface name hint. On macOS use `"utun"` for automatic selection or
    /// `"utunN"` (e.g. `"utun9"`) for a specific unit. On Linux any interface
    /// name ≤ 15 bytes.
    pub name: String,
    /// Desired MTU. Linux applies this to the created interface; Tailscale's
    /// tailnet MTU is 1280.
    pub mtu: usize,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            // "utun" on macOS auto-selects a unit; Linux users should override.
            #[cfg(target_os = "macos")]
            name: "utun".to_string(),
            #[cfg(not(target_os = "macos"))]
            name: "tun0".to_string(),
            mtu: 1280,
        }
    }
}

impl TunConfig {
    /// Build a config with the given name hint and the default tailnet MTU.
    pub fn named(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            mtu: 1280,
        }
    }
}

/// Create a real OS-backed [`TunDevice`] from a [`TunConfig`].
///
/// On macOS this opens a `utun` control socket (requires root). On Linux this
/// opens `/dev/net/tun` (requires the `tun` module and appropriate permissions).
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn create(config: &TunConfig) -> Result<TunDevice, TunError> {
    TunDevice::create(config)
}

// ---------------------------------------------------------------------------
// Address-family framing primitives (macOS utun)
// ---------------------------------------------------------------------------

/// macOS address families used in the utun 4-byte packet header.
#[cfg(unix)]
pub const AF_INET: u8 = libc::AF_INET as u8;
/// IPv6 address family for the utun 4-byte packet header.
#[cfg(unix)]
pub const AF_INET6: u8 = libc::AF_INET6 as u8;

/// Length of the utun 4-byte address-family header prepended to every packet.
pub const AF_HEADER_LEN: usize = 4;

/// Given a raw utun read (4-byte AF header + IP packet), return the plain IP
/// packet bytes. Returns `None` if the frame is too short or the AF byte is
/// neither `AF_INET` nor `AF_INET6`.
#[cfg(unix)]
pub fn strip_af_header(raw: &[u8]) -> Option<&[u8]> {
    if raw.len() < AF_HEADER_LEN {
        return None;
    }
    let af = raw[3];
    if af != AF_INET && af != AF_INET6 {
        return None;
    }
    Some(&raw[AF_HEADER_LEN..])
}

/// Prepend the utun 4-byte AF header to `packet`, writing into `out`. The AF
/// byte is derived from the IP version nibble of `packet[0]`. Returns an error
/// if the packet is empty or has an unknown IP version.
#[cfg(unix)]
pub fn prepend_af_header(packet: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
    if packet.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty packet"));
    }
    let af = match packet[0] >> 4 {
        4 => AF_INET,
        6 => AF_INET6,
        v => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unknown IP version {v}"),
            ));
        }
    };
    out.clear();
    out.push(0x00);
    out.push(0x00);
    out.push(0x00);
    out.push(af);
    out.extend_from_slice(packet);
    Ok(())
}

#[cfg(test)]
mod tests;
