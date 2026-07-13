//! Stub for unsupported platforms — returns an empty port list.

use crate::Port;

pub async fn scan_ports() -> Vec<Port> {
    Vec::new()
}
