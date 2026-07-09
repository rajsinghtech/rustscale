//! Platform dispatch for the OS event source.

#[cfg(target_os = "macos")]
pub(crate) use crate::os_darwin::spawn_os_source;

#[cfg(not(target_os = "macos"))]
pub(crate) use crate::os_poll::spawn_os_source;
