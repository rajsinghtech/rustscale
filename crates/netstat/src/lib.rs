//! Bounded, read-only snapshots of the host TCP connection table.
//!
//! Linux snapshots parse `/proc/net/tcp` and `/proc/net/tcp6` and can perform
//! a bounded, best-effort `/proc/<pid>/fd` symlink walk to associate socket
//! inodes with processes. macOS uses the numeric output of the system
//! `netstat` command with a hard output cap and deadline. Windows is
//! explicitly unsupported until a safe implementation can be provided without
//! weakening this workspace's `unsafe_code` policy.
//!
//! Snapshotting never closes, duplicates, or calls socket operations on a
//! process file descriptor. Process races only make association metadata
//! partial; they do not invalidate connection rows already read from the OS.

#![forbid(unsafe_code)]

mod linux;
mod macos;

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub use linux::{snapshot_linux_with_reader, Directory, LinuxReader, SystemLinuxReader};
pub use macos::{parse_netstat, snapshot_macos_with_reader, NetstatReader};

/// Default whole-snapshot deadline.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);

/// A normalized TCP endpoint.
///
/// IPv4-mapped IPv6 addresses are represented as IPv4. `zone` is retained for
/// scoped addresses reported by macOS; Linux `/proc/net/tcp6` does not expose
/// an interface zone.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Endpoint {
    pub address: IpAddr,
    pub port: u16,
    pub zone: Option<String>,
}

impl Endpoint {
    pub fn new(address: IpAddr, port: u16) -> Self {
        Self {
            address: canonical_ip(address),
            port,
            zone: None,
        }
    }

    fn with_zone(address: IpAddr, port: u16, zone: Option<String>) -> Self {
        let address = canonical_ip(address);
        Self {
            address,
            port,
            zone: address.is_ipv6().then_some(zone).flatten(),
        }
    }

    pub fn is_unspecified(&self) -> bool {
        self.address.is_unspecified()
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.address, self.zone.as_deref()) {
            (IpAddr::V4(address), _) => write!(f, "{address}:{}", self.port),
            (IpAddr::V6(address), Some(zone)) => write!(f, "[{address}%{zone}]:{}", self.port),
            (IpAddr::V6(address), None) => write!(f, "[{address}]:{}", self.port),
        }
    }
}

/// Normalized TCP states used across supported operating systems.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum State {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb,
    NewSynReceived,
    Unknown(u32),
    Other(String),
}

impl State {
    /// Return the canonical spelling used by Tailscale's connection table.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Closed => "CLOSED",
            Self::Listen => "LISTEN",
            Self::SynSent => "SYN-SENT",
            Self::SynReceived => "SYN-RECEIVED",
            Self::Established => "ESTABLISHED",
            Self::FinWait1 => "FIN-WAIT-1",
            Self::FinWait2 => "FIN-WAIT-2",
            Self::CloseWait => "CLOSE-WAIT",
            Self::Closing => "CLOSING",
            Self::LastAck => "LAST-ACK",
            Self::TimeWait => "TIME-WAIT",
            Self::DeleteTcb => "DELETE-TCB",
            Self::NewSynReceived => "NEW-SYN-RECEIVED",
            Self::Unknown(_) => "UNKNOWN",
            Self::Other(value) => value,
        }
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(value) => write!(f, "unknown-state-{value}"),
            _ => f.write_str(self.as_str()),
        }
    }
}

/// Additional information that is meaningful only on the source OS.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OsMetadata {
    Linux { inode: u64, uid: u32 },
    Macos,
}

/// One TCP connection table row.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Entry {
    pub local: Endpoint,
    pub remote: Endpoint,
    pub pid: Option<u32>,
    pub process: Option<String>,
    pub state: State,
    pub os_metadata: OsMetadata,
}

/// Completeness of optional inode-to-process association.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessAssociation {
    NotRequested,
    Complete,
    Partial,
    Unavailable,
}

/// A race-tolerant TCP table snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Table {
    pub entries: Vec<Entry>,
    pub process_association: ProcessAssociation,
}

impl Table {
    /// Iterate over listening sockets, matching the upstream port-list caller's
    /// state semantics.
    pub fn listening(&self) -> impl Iterator<Item = &Entry> {
        self.entries
            .iter()
            .filter(|entry| entry.state == State::Listen)
    }
}

/// Hard resource limits for a snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_table_bytes: usize,
    pub max_netstat_bytes: usize,
    pub max_line_bytes: usize,
    pub max_entries: usize,
    pub max_processes: usize,
    pub max_fds_per_process: usize,
    pub max_total_fds: usize,
    pub max_process_name_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_table_bytes: 8 * 1024 * 1024,
            max_netstat_bytes: 8 * 1024 * 1024,
            max_line_bytes: 4096,
            max_entries: 65_536,
            max_processes: 4096,
            max_fds_per_process: 4096,
            max_total_fds: 262_144,
            max_process_name_bytes: 256,
        }
    }
}

/// Options for one snapshot operation.
#[derive(Clone, Debug)]
pub struct SnapshotOptions {
    pub deadline: Option<Instant>,
    pub limits: Limits,
    pub associate_processes: bool,
}

impl Default for SnapshotOptions {
    fn default() -> Self {
        Self {
            deadline: Some(Instant::now() + DEFAULT_TIMEOUT),
            limits: Limits::default(),
            associate_processes: true,
        }
    }
}

/// Cooperative cancellation shared by readers and parsers.
#[derive(Clone, Debug, Default)]
pub struct CancellationToken(Arc<AtomicBool>);

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Deadline and cancellation state supplied to injectable readers.
#[derive(Clone, Debug)]
pub struct SnapshotContext {
    deadline: Option<Instant>,
    cancellation: CancellationToken,
}

impl SnapshotContext {
    pub fn new(deadline: Option<Instant>, cancellation: CancellationToken) -> Self {
        Self {
            deadline,
            cancellation,
        }
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    pub fn check(&self) -> Result<(), Error> {
        if self.is_cancelled() {
            return Err(Error::Cancelled);
        }
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(Error::DeadlineExceeded);
        }
        Ok(())
    }
}

/// Snapshot failures. Per-process disappearance and permission errors are
/// treated as partial process metadata rather than fatal I/O errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("TCP table snapshots are unsupported on {platform}")]
    Unsupported { platform: &'static str },
    #[error("TCP table snapshot cancelled")]
    Cancelled,
    #[error("TCP table snapshot deadline exceeded")]
    DeadlineExceeded,
    #[error("{resource} exceeded limit {limit}")]
    LimitExceeded {
        resource: &'static str,
        limit: usize,
    },
    #[error("malformed {source_name} line {line}: {reason}")]
    Malformed {
        source_name: &'static str,
        line: usize,
        reason: &'static str,
    },
    #[error("invalid UTF-8 in {source_name}")]
    InvalidUtf8 { source_name: &'static str },
    #[error("I/O error while {operation}: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("netstat exited unsuccessfully: {0}")]
    NetstatFailed(String),
}

impl Error {
    fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }
}

/// Take a host TCP connection table snapshot.
#[cfg(target_os = "linux")]
pub fn get(options: &SnapshotOptions, cancellation: &CancellationToken) -> Result<Table, Error> {
    let context = SnapshotContext::new(options.deadline, cancellation.clone());
    context.check()?;
    snapshot_linux_with_reader(&SystemLinuxReader, options, &context)
}

/// Take a host TCP connection table snapshot.
#[cfg(target_os = "macos")]
pub fn get(options: &SnapshotOptions, cancellation: &CancellationToken) -> Result<Table, Error> {
    let context = SnapshotContext::new(options.deadline, cancellation.clone());
    context.check()?;
    snapshot_macos_with_reader(&macos::SystemNetstatReader, options, &context)
}

/// Return an explicit unsupported error on platforms without a safe reader.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn get(options: &SnapshotOptions, cancellation: &CancellationToken) -> Result<Table, Error> {
    let context = SnapshotContext::new(options.deadline, cancellation.clone());
    context.check()?;
    Err(Error::Unsupported {
        platform: std::env::consts::OS,
    })
}

fn canonical_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
        address => address,
    }
}

fn parse_ipv4_hex(value: &str) -> Option<Ipv4Addr> {
    let bytes = parse_hex_array::<4>(value)?;
    Some(Ipv4Addr::new(bytes[3], bytes[2], bytes[1], bytes[0]))
}

fn parse_ipv6_hex(value: &str) -> Option<Ipv6Addr> {
    let bytes = parse_hex_array::<16>(value)?;
    let mut address = [0_u8; 16];
    for (destination, source) in address.chunks_exact_mut(4).zip(bytes.chunks_exact(4)) {
        destination.copy_from_slice(&[source[3], source[2], source[1], source[0]]);
    }
    Some(Ipv6Addr::from(address))
}

fn parse_hex_array<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 {
        return None;
    }
    let mut result = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        result[index] = hex_nibble(pair[0])? << 4 | hex_nibble(pair[1])?;
    }
    Some(result)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn read_file_limited(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    use std::fs::File;
    use std::io::Read;

    let file = File::open(path)?;
    let take_limit = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
    file.take(take_limit).read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn sorted_directory(path: &Path, limit: usize) -> io::Result<Directory> {
    let mut names = Vec::with_capacity(limit.min(1024));
    let mut truncated = false;
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        if names.len() == limit {
            truncated = true;
            break;
        }
        names.push(entry.file_name());
    }
    names.sort_unstable();
    Ok(Directory { names, truncated })
}

fn path_for_proc(root: &Path, pid: u32, suffix: &str) -> PathBuf {
    root.join(pid.to_string()).join(suffix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_mapped_ipv6() {
        let endpoint = Endpoint::new("::ffff:127.0.0.1".parse().unwrap(), 80);
        assert_eq!(endpoint.address, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(endpoint.to_string(), "127.0.0.1:80");
    }

    #[test]
    fn upstream_state_spellings_are_stable() {
        let states = [
            State::Closed,
            State::Listen,
            State::SynSent,
            State::SynReceived,
            State::Established,
            State::FinWait1,
            State::FinWait2,
            State::CloseWait,
            State::Closing,
            State::LastAck,
            State::DeleteTcb,
        ];
        let actual: Vec<String> = states.iter().map(ToString::to_string).collect();
        assert_eq!(
            actual,
            [
                "CLOSED",
                "LISTEN",
                "SYN-SENT",
                "SYN-RECEIVED",
                "ESTABLISHED",
                "FIN-WAIT-1",
                "FIN-WAIT-2",
                "CLOSE-WAIT",
                "CLOSING",
                "LAST-ACK",
                "DELETE-TCB",
            ]
        );
        assert_eq!(State::Unknown(99).to_string(), "unknown-state-99");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn live_snapshot_uses_normalized_endpoints_and_states() {
        let options = SnapshotOptions {
            deadline: Some(Instant::now() + Duration::from_secs(5)),
            associate_processes: false,
            ..SnapshotOptions::default()
        };
        let table = get(&options, &CancellationToken::new()).unwrap();
        assert_eq!(table.process_association, ProcessAssociation::NotRequested);
        for entry in table.entries {
            assert!(!entry.state.as_str().is_empty());
            if entry.local.address.is_ipv4() {
                assert!(entry.local.zone.is_none());
            }
            if entry.remote.address.is_ipv4() {
                assert!(entry.remote.zone.is_none());
            }
        }
    }

    #[test]
    fn cancelled_before_snapshot() {
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let error = get(&SnapshotOptions::default(), &cancellation).unwrap_err();
        assert!(matches!(error, Error::Cancelled));
    }

    #[test]
    fn expired_deadline_is_rejected() {
        let options = SnapshotOptions {
            deadline: Some(
                Instant::now()
                    .checked_sub(Duration::from_millis(1))
                    .unwrap(),
            ),
            ..SnapshotOptions::default()
        };
        let error = get(&options, &CancellationToken::new()).unwrap_err();
        assert!(matches!(error, Error::DeadlineExceeded));
    }
}
