//! Stub for unsupported platforms — returns an empty port list.

use crate::Port;

// Keep the same async API as the platform implementations so callers do not
// need target-specific control flow.
#[allow(clippy::unused_async)]
pub async fn scan_ports() -> Vec<Port> {
    Vec::new()
}
