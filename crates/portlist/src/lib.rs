//! Periodic enumeration of listening TCP/UDP ports on the host.
//!
//! Mirrors Go's `portlist/` package. Reports results as
//! `Vec<rustscale_tailcfg::Service>` for `Hostinfo.Services`.
//!
//! Platform support:
//! - **Linux**: reads `/proc/net/tcp{,6}` and `/proc/net/udp{,6}`, walks
//!   `/proc/*/fd/` for process names. Poll interval: 1s.
//! - **macOS**: runs `netstat -na` for port discovery, `lsof` for process
//!   names on newly-detected ports. Poll interval: 5s.
//! - **Other**: returns an empty list.

mod policy;
mod poller;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod stub;

pub use poller::Poller;

use rustscale_tailcfg::Service;

/// A listening port entry (mirrors Go's `portlist.Port`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Port {
    /// Protocol: `"tcp"` or `"udp"`.
    pub proto: String,
    /// Port number.
    pub port: u16,
    /// Process name (empty if unknown).
    pub process: String,
    /// Process ID (0 if unknown).
    pub pid: u32,
}

impl Port {
    /// Create a port entry with no process info.
    pub fn new(proto: &str, port: u16) -> Self {
        Self {
            proto: proto.to_string(),
            port,
            process: String::new(),
            pid: 0,
        }
    }
}

/// Sort ports by (port, proto, process) and deduplicate by (proto, port).
pub fn sort_and_dedup(ports: &mut Vec<Port>) {
    ports.sort_by(|a, b| {
        a.port
            .cmp(&b.port)
            .then_with(|| a.proto.cmp(&b.proto))
            .then_with(|| a.process.cmp(&b.process))
    });
    ports.dedup_by(|a, b| a.port == b.port && a.proto == b.proto);
}

/// Convert `Vec<Port>` to `Vec<Service>` for `Hostinfo.Services`.
///
/// Applies the interesting-service policy: peerAPI services are always
/// included; TCP ports are included on non-Windows (all) or Windows (specific
/// ports only); non-TCP services are dropped.
pub fn to_services(ports: &[Port]) -> Vec<Service> {
    ports
        .iter()
        .filter(|p| policy::is_interesting_service(&p.proto, p.port))
        .map(|p| Service {
            Proto: p.proto.clone(),
            Port: p.port,
            Description: p.process.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sort_and_dedup() {
        let mut ports = vec![
            Port::new("tcp", 8080),
            Port::new("udp", 53),
            Port::new("tcp", 22),
            Port::new("tcp", 8080),
        ];
        sort_and_dedup(&mut ports);
        assert_eq!(ports.len(), 3);
        assert_eq!(ports[0].port, 22);
        assert_eq!(ports[1].port, 53);
        assert_eq!(ports[2].port, 8080);
    }

    #[test]
    fn test_to_services_filters() {
        let ports = vec![
            Port::new("tcp", 22),
            Port::new("tcp", 8080),
            Port::new("udp", 53),
        ];
        let services = to_services(&ports);
        assert_eq!(services.len(), 2);
        assert_eq!(services[0].Port, 22);
        assert_eq!(services[1].Port, 8080);
    }
}
