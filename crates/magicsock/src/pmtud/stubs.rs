//! Stubs for platforms without PMTUD support.
//! Mirrors Go's peermtu_stubs.go.

use std::os::unix::io::RawFd;

/// Enable/disable DF — always fails on unsupported platforms.
pub(crate) fn set_dont_fragment(
    _fd: RawFd,
    _network: &str,
    _enable: bool,
) -> Result<(), SetDfError> {
    Err(SetDfError::Unsupported)
}

/// Query DF state — always returns false on unsupported platforms.
pub(crate) fn get_dont_fragment(_fd: RawFd, _network: &str) -> Result<bool, SetDfError> {
    Ok(false)
}

/// Error from set/get dont-fragment operations.
#[derive(Debug, thiserror::Error)]
pub enum SetDfError {
    #[error("PMTUD not supported on this platform")]
    Unsupported,
}
