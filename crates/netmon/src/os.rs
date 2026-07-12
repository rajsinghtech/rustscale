//! Platform dispatch for the OS event source.

#[cfg(target_os = "macos")]
pub(crate) use crate::os_darwin::spawn_os_source;

#[cfg(target_os = "linux")]
pub(crate) use crate::os_linux::spawn_os_source;

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(crate) use crate::os_poll::spawn_os_source;
