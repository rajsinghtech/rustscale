//! Bounded, read-only snapshots of the host TCP connection table.
//!
//! Linux snapshots parse `/proc/net/tcp` and `/proc/net/tcp6` and can perform
//! a bounded, best-effort `/proc/<pid>/fd` symlink walk to associate socket
//! inodes with processes. macOS uses the numeric output of the system
//! `netstat` command with a hard output cap and deadline. Windows invokes only
//! `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` and uses an
//! embedded reflection-only P/Invoke wrapper around the fixed system
//! `iphlpapi.dll`. Its child environment is cleared before fixed `SystemRoot`
//! and `WINDIR` values are restored, its working directory is fixed to system32,
//! and it cannot inherit `PATH`, module, CLR profiler, COMPlus, DOTNET startup,
//! profile, or localized-formatting controls. This requires Windows
//! PowerShell 5.1 and deliberately fails closed on installations that do not
//! use the standard `C:\Windows` root or provide that runtime.
//!
//! Snapshotting never closes, duplicates, or calls socket operations on a
//! process file descriptor. PID metadata is observational only and must never
//! be used to select a destructive action. Linux PID metadata is emitted only
//! after validating a stable process start time; Windows PIDs come from the
//! same diagnostic table row but can still race with process exit or PID reuse.

#![forbid(unsafe_code)]

mod linux;
mod macos;
mod windows;

use std::fmt;
use std::io;
use std::net::IpAddr;
#[cfg(test)]
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

pub use linux::{
    snapshot_linux_with_reader, snapshot_linux_with_reader_and_decoder, Directory, LinuxReader,
    ProcAddressDecoder, ProcEndian, SystemLinuxReader,
};
pub use macos::{parse_netstat, snapshot_macos_with_reader, NetstatReader};
pub use windows::{parse_windows_tcp_table, snapshot_windows_with_reader, WindowsTcpTableReader};

/// Default whole-snapshot deadline.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);
const SUPERVISOR_POLL_INTERVAL: Duration = Duration::from_millis(5);
const MAX_SNAPSHOT_WORKERS: usize = 4;

static SNAPSHOT_WORKERS: LazyLock<Arc<WorkerLimiter>> =
    LazyLock::new(|| Arc::new(WorkerLimiter::new(MAX_SNAPSHOT_WORKERS)));

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
    Windows,
}

/// One TCP connection table row.
///
/// `pid` and `process` are race-checked diagnostic observations, not handles or
/// authority for signaling, closing, or otherwise modifying a process/socket.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Entry {
    pub local: Endpoint,
    pub remote: Endpoint,
    pub pid: Option<u32>,
    pub process: Option<String>,
    pub state: State,
    pub os_metadata: OsMetadata,
}

/// Completeness of optional diagnostic process association.
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
    pub max_windows_token_bytes: usize,
    pub max_entries: usize,
    pub max_processes: usize,
    pub max_fds_per_process: usize,
    pub max_total_fds: usize,
    pub max_process_name_bytes: usize,
    pub max_process_stat_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_table_bytes: 8 * 1024 * 1024,
            max_netstat_bytes: 8 * 1024 * 1024,
            max_line_bytes: 4096,
            max_windows_token_bytes: 256,
            max_entries: 65_536,
            max_processes: 4096,
            max_fds_per_process: 4096,
            max_total_fds: 262_144,
            max_process_name_bytes: 256,
            max_process_stat_bytes: 4096,
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
    supervisor_cancellation: CancellationToken,
}

impl SnapshotContext {
    pub fn new(deadline: Option<Instant>, cancellation: CancellationToken) -> Self {
        Self {
            deadline,
            cancellation,
            supervisor_cancellation: CancellationToken::new(),
        }
    }

    fn supervised(
        deadline: Option<Instant>,
        cancellation: CancellationToken,
        supervisor_cancellation: CancellationToken,
    ) -> Self {
        Self {
            deadline,
            cancellation,
            supervisor_cancellation,
        }
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled() || self.supervisor_cancellation.is_cancelled()
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

/// Snapshot failures. Per-process disappearance and permission errors during
/// optional PID association become partial metadata; TCP table read failures
/// other than an explicitly absent family are fatal.
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
    #[error("Windows TCP table command exited unsuccessfully: {0}")]
    WindowsCommandFailed(String),
    #[error("Windows TCP table {family} enumeration failed with code {code}")]
    WindowsFamilyFailed { family: &'static str, code: u32 },
    #[error("TCP table snapshot worker capacity exhausted")]
    WorkerCapacity,
    #[error("TCP table snapshot worker terminated without a result")]
    WorkerTerminated,
}

impl Error {
    fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }
}

struct WorkerLimiter {
    active: AtomicUsize,
    maximum: usize,
}

impl WorkerLimiter {
    const fn new(maximum: usize) -> Self {
        Self {
            active: AtomicUsize::new(0),
            maximum,
        }
    }

    fn acquire(self: &Arc<Self>) -> Result<WorkerPermit, Error> {
        self.active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < self.maximum).then_some(active + 1)
            })
            .map_err(|_| Error::WorkerCapacity)?;
        Ok(WorkerPermit {
            limiter: self.clone(),
        })
    }
}

struct WorkerPermit {
    limiter: Arc<WorkerLimiter>,
}

impl Drop for WorkerPermit {
    fn drop(&mut self) {
        self.limiter.active.fetch_sub(1, Ordering::AcqRel);
    }
}

fn run_supervised<T, F>(
    options: &SnapshotOptions,
    cancellation: &CancellationToken,
    work: F,
) -> Result<T, Error>
where
    T: Send + 'static,
    F: FnOnce(SnapshotContext) -> Result<T, Error> + Send + 'static,
{
    run_supervised_with_limiter(options, cancellation, SNAPSHOT_WORKERS.clone(), work)
}

fn run_supervised_with_limiter<T, F>(
    options: &SnapshotOptions,
    cancellation: &CancellationToken,
    limiter: Arc<WorkerLimiter>,
    work: F,
) -> Result<T, Error>
where
    T: Send + 'static,
    F: FnOnce(SnapshotContext) -> Result<T, Error> + Send + 'static,
{
    let initial_context = SnapshotContext::new(options.deadline, cancellation.clone());
    initial_context.check()?;
    let permit = limiter.acquire()?;
    let supervisor_cancellation = CancellationToken::new();
    let worker_context = SnapshotContext::supervised(
        options.deadline,
        cancellation.clone(),
        supervisor_cancellation.clone(),
    );
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("rustscale-netstat-snapshot".into())
        .spawn(move || {
            let result = work(worker_context);
            drop(permit);
            let _ = sender.send(result);
        })
        .map_err(|error| Error::io("starting TCP table snapshot worker", error))?;

    loop {
        if cancellation.is_cancelled() {
            supervisor_cancellation.cancel();
            return Err(Error::Cancelled);
        }
        let wait = if let Some(deadline) = options.deadline {
            let now = Instant::now();
            if now >= deadline {
                supervisor_cancellation.cancel();
                return Err(Error::DeadlineExceeded);
            }
            SUPERVISOR_POLL_INTERVAL.min(deadline.duration_since(now))
        } else {
            SUPERVISOR_POLL_INTERVAL
        };
        match receiver.recv_timeout(wait) {
            Ok(result) => {
                if cancellation.is_cancelled() {
                    supervisor_cancellation.cancel();
                    return Err(Error::Cancelled);
                }
                if options
                    .deadline
                    .is_some_and(|deadline| Instant::now() >= deadline)
                {
                    supervisor_cancellation.cancel();
                    return Err(Error::DeadlineExceeded);
                }
                return result;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return Err(Error::WorkerTerminated);
            }
        }
    }
}

/// Take a host TCP connection table snapshot.
#[cfg(target_os = "linux")]
pub fn get(options: &SnapshotOptions, cancellation: &CancellationToken) -> Result<Table, Error> {
    let context = SnapshotContext::new(options.deadline, cancellation.clone());
    context.check()?;
    snapshot_linux_with_reader(SystemLinuxReader, options, cancellation)
}

/// Take a host TCP connection table snapshot.
#[cfg(target_os = "macos")]
pub fn get(options: &SnapshotOptions, cancellation: &CancellationToken) -> Result<Table, Error> {
    let context = SnapshotContext::new(options.deadline, cancellation.clone());
    context.check()?;
    snapshot_macos_with_reader(macos::SystemNetstatReader, options, cancellation)
}

/// Take a host TCP connection table snapshot.
#[cfg(target_os = "windows")]
pub fn get(options: &SnapshotOptions, cancellation: &CancellationToken) -> Result<Table, Error> {
    let context = SnapshotContext::new(options.deadline, cancellation.clone());
    context.check()?;
    snapshot_windows_with_reader(windows::SystemWindowsTcpTableReader, options, cancellation)
}

/// Return an explicit unsupported error on platforms without a safe reader.
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
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
        let table = match get(&options, &CancellationToken::new()) {
            Ok(table) => table,
            #[cfg(target_os = "macos")]
            Err(Error::Malformed {
                reason: "invalid local endpoint" | "invalid remote endpoint",
                ..
            }) => {
                // Even wide Darwin netstat output can contain non-standard,
                // ambiguous IPv6 text. Rejecting the snapshot is intentional.
                return;
            }
            Err(error) => panic!("live snapshot failed: {error}"),
        };
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
    fn supervisor_returns_by_deadline_and_caps_abandoned_workers() {
        let limiter = Arc::new(WorkerLimiter::new(1));
        let (release, blocked) = std::sync::mpsc::channel();
        let options = SnapshotOptions {
            deadline: Some(Instant::now() + Duration::from_millis(30)),
            ..SnapshotOptions::default()
        };
        let started = Instant::now();
        let result = run_supervised_with_limiter(
            &options,
            &CancellationToken::new(),
            limiter.clone(),
            move |_| {
                let _ = blocked.recv_timeout(Duration::from_millis(500));
                Ok(())
            },
        );
        assert!(matches!(result, Err(Error::DeadlineExceeded)));
        assert!(started.elapsed() < Duration::from_millis(150));

        let second_options = SnapshotOptions {
            deadline: Some(Instant::now() + Duration::from_millis(100)),
            ..SnapshotOptions::default()
        };
        assert!(matches!(
            run_supervised_with_limiter(
                &second_options,
                &CancellationToken::new(),
                limiter.clone(),
                |_| Ok(())
            ),
            Err(Error::WorkerCapacity)
        ));
        release.send(()).unwrap();
        let cleanup_deadline = Instant::now() + Duration::from_secs(1);
        while limiter.active.load(Ordering::Acquire) != 0 && Instant::now() < cleanup_deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(limiter.active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn supervisor_returns_promptly_on_cancellation() {
        let limiter = Arc::new(WorkerLimiter::new(1));
        let (release, blocked) = std::sync::mpsc::channel();
        let cancellation = CancellationToken::new();
        let canceller = {
            let cancellation = cancellation.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                cancellation.cancel();
            })
        };
        let options = SnapshotOptions {
            deadline: None,
            ..SnapshotOptions::default()
        };
        let started = Instant::now();
        let result = run_supervised_with_limiter(&options, &cancellation, limiter, move |_| {
            let _ = blocked.recv_timeout(Duration::from_secs(2));
            Ok(())
        });
        assert!(matches!(result, Err(Error::Cancelled)));
        assert!(started.elapsed() < Duration::from_secs(1));
        release.send(()).unwrap();
        canceller.join().unwrap();
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
