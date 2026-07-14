//! Device posture identity collection.
//!
//! Serial numbers are collected on demand, while hardware addresses are
//! enumerated from the local network interfaces.

#![forbid(unsafe_code)]

mod hwaddr;
mod serial;

#[cfg(target_os = "linux")]
mod serial_linux;
#[cfg(target_os = "macos")]
mod serial_macos;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod serial_stub;

pub use hwaddr::get_hardware_addrs;
pub use serial::{dedup_serials, get_serial_numbers, is_sentinel_serial};

/// Errors returned while collecting device posture identity data.
#[derive(Debug, thiserror::Error)]
pub enum PostureError {
    /// The platform did not expose a serial number.
    #[error("serial number collection failed: {0}")]
    CollectionFailed(String),
    /// Serial-number collection is unavailable on this platform.
    #[error("not supported on this platform")]
    UnsupportedPlatform,
    /// An operating-system I/O operation failed.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}
