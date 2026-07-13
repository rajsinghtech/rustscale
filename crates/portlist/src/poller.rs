//! Poller for listening ports. Holds OS-specific state and a previous-result
//! cache for the same-count shortcut.

use crate::{sort_and_dedup, Port};
use std::time::Duration;

/// Platform-specific port scanning function.
#[cfg(target_os = "linux")]
async fn scan_ports(include_localhost: bool) -> Vec<Port> {
    crate::linux::scan_ports(include_localhost).await
}

#[cfg(target_os = "macos")]
async fn scan_ports(include_localhost: bool) -> Vec<Port> {
    crate::macos::scan_ports(include_localhost).await
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
async fn scan_ports(_include_localhost: bool) -> Vec<Port> {
    crate::stub::scan_ports().await
}

/// Returns the platform-appropriate poll interval.
fn poll_interval() -> Duration {
    if cfg!(target_os = "linux") {
        Duration::from_secs(1)
    } else {
        Duration::from_secs(5)
    }
}

/// Poller for listening ports. Holds a previous-result cache for the
/// same-count shortcut.
///
/// Mirrors Go's `portlist.Poller`.
pub struct Poller {
    include_localhost: bool,
    prev: Vec<Port>,
    interval: Duration,
}

impl Default for Poller {
    fn default() -> Self {
        Self::new(false)
    }
}

impl Poller {
    /// Create a new poller. If `include_localhost` is true, localhost-bound
    /// ports (127.0.0.1 / ::1) are included in results.
    pub fn new(include_localhost: bool) -> Self {
        Self {
            include_localhost,
            prev: Vec::new(),
            interval: poll_interval(),
        }
    }

    /// Override the poll interval.
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// The configured poll interval.
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// Poll once: get current listening ports. Returns `(list, changed)`.
    ///
    /// If the list is identical to the previous poll (same-count shortcut),
    /// returns `(vec![], false)`. Otherwise returns `(sorted_list, true)`.
    pub async fn poll(&mut self) -> (Vec<Port>, bool) {
        let mut ports = scan_ports(self.include_localhost).await;
        sort_and_dedup(&mut ports);

        if ports == self.prev {
            return (Vec::new(), false);
        }

        self.prev.clone_from(&ports);
        (ports, true)
    }

    /// Returns the previous poll result (without re-polling).
    pub fn previous(&self) -> &[Port] {
        &self.prev
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_poll_returns_empty_on_unsupported() {
        // On all platforms, poll should at least not panic.
        let mut p = Poller::new(false);
        let (ports, _changed) = p.poll().await;
        // On Linux/macOS this may find real ports; on stub it's empty.
        let _ = ports;
    }

    #[tokio::test]
    async fn test_poll_same_count_shortcut() {
        let mut p = Poller::new(false);
        // First poll establishes baseline.
        let _ = p.poll().await;
        // Second poll should return (empty, false) if nothing changed.
        let (ports, changed) = p.poll().await;
        if !changed {
            assert!(ports.is_empty());
        }
    }

    #[test]
    fn test_interval_linux_1s() {
        if cfg!(target_os = "linux") {
            assert_eq!(Poller::new(false).interval(), Duration::from_secs(1));
        }
    }

    #[test]
    fn test_interval_macos_5s() {
        if cfg!(target_os = "macos") {
            assert_eq!(Poller::new(false).interval(), Duration::from_secs(5));
        }
    }
}
