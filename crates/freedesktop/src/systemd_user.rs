//! Bounded, transactional management of one narrowly generated systemd user unit.
//!
//! The manager intentionally exposes no arbitrary unit directives, environment
//! entries, command programs, or `systemctl` arguments. Filesystem and command
//! transports are injectable so callers can test policy without touching a real
//! user manager.
//!
//! Cooperating RustScale processes serialize through an owner-only advisory
//! lock. A noncooperating process with the same UID can still rename files in
//! the user's configuration directory: Linux has no rename operation
//! conditional on a destination inode. Such interference is detected by exact
//! inode-and-content checks; unvalidated bytes are never sent to daemon-reload.

use std::collections::HashMap;
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::fd::OwnedFd;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use thiserror::Error;
use wait_timeout::ChildExt;

use crate::{Environment, SystemEnvironment};

const MANAGED_HEADER: &str = "# Managed by rustscale-freedesktop. Do not edit.";
const SYSTEMCTL_PROGRAM: &str = "/usr/bin/systemctl";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_OUTPUT_BYTES: usize = 16 * 1024;
const MAX_UNIT_BYTES: usize = 64 * 1024;
const MAX_NAME_BYTES: usize = 48;
const MAX_EXECUTABLE_BYTES: usize = 4096;
const MAX_ARGUMENT_BYTES: usize = 4096;
const MAX_ARGUMENTS: usize = 64;
const POLL_INTERVAL: Duration = Duration::from_millis(20);
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
static UNIT_LOCKS: OnceLock<Mutex<HashMap<String, Arc<Mutex<()>>>>> = OnceLock::new();

fn process_unit_lock(name: &str) -> Arc<Mutex<()>> {
    UNIT_LOCKS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .entry(name.to_owned())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

/// Cooperative cancellation for user-unit operations.
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

/// The only caller-controlled fields accepted by the unit generator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserUnit {
    /// A short identifier used in `rustscale-<name>.service`.
    pub name: String,
    /// Absolute path to the RustScale executable or a dedicated RustScale helper.
    pub executable: PathBuf,
    /// Literal `ExecStart` arguments. They are never interpreted by a shell.
    pub arguments: Vec<String>,
}

impl UserUnit {
    pub fn unit_name(&self) -> Result<String, UserUnitError> {
        validate_name(&self.name)?;
        Ok(format!("rustscale-{}.service", self.name))
    }

    /// Return the deterministic bytes installed by [`UserUnitManager`].
    pub fn render(&self) -> Result<Vec<u8>, UserUnitError> {
        validate_unit(self)?;
        let mut exec = quote_exec_word(
            self.executable
                .to_str()
                .ok_or(UserUnitError::InvalidExecutable("path is not UTF-8"))?,
        );
        for argument in &self.arguments {
            exec.push(' ');
            exec.push_str(&quote_exec_word(argument));
        }
        let unit_name = self.unit_name()?;
        let bytes = format!(
            "{MANAGED_HEADER}\n# Unit: {unit_name}\n[Unit]\nDescription=RustScale user service ({})\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart={exec}\nRestart=on-failure\nRestartSec=5s\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=read-only\n\n[Install]\nWantedBy=default.target\n",
            self.name
        )
        .into_bytes();
        if bytes.len() > MAX_UNIT_BYTES {
            return Err(UserUnitError::InvalidArgument(
                "combined arguments are too long",
            ));
        }
        Ok(bytes)
    }
}

/// Validation failure for a generated unit.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum UserUnitError {
    #[error("invalid RustScale user unit name: {0}")]
    InvalidName(&'static str),
    #[error("invalid RustScale user unit executable: {0}")]
    InvalidExecutable(&'static str),
    #[error("invalid RustScale user unit argument: {0}")]
    InvalidArgument(&'static str),
}

fn validate_name(name: &str) -> Result<(), UserUnitError> {
    if name.is_empty() || name.len() > MAX_NAME_BYTES {
        return Err(UserUnitError::InvalidName("invalid length"));
    }
    let mut bytes = name.bytes();
    let first = bytes.next().expect("non-empty name");
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return Err(UserUnitError::InvalidName(
            "must start with a lowercase ASCII letter or digit",
        ));
    }
    if !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-') {
        return Err(UserUnitError::InvalidName(
            "only lowercase ASCII letters, digits, and hyphens are allowed",
        ));
    }
    Ok(())
}

fn validate_unit(unit: &UserUnit) -> Result<(), UserUnitError> {
    validate_name(&unit.name)?;
    let executable = unit
        .executable
        .to_str()
        .ok_or(UserUnitError::InvalidExecutable("path is not UTF-8"))?;
    if executable.is_empty() || executable.len() > MAX_EXECUTABLE_BYTES {
        return Err(UserUnitError::InvalidExecutable("invalid length"));
    }
    if !unit.executable.is_absolute()
        || unit
            .executable
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(UserUnitError::InvalidExecutable(
            "must be a normalized absolute path",
        ));
    }
    validate_exec_text(executable).map_err(UserUnitError::InvalidExecutable)?;
    if looks_sensitive(executable) {
        return Err(UserUnitError::InvalidExecutable(
            "credential-bearing paths are not accepted",
        ));
    }
    let basename = unit
        .executable
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(UserUnitError::InvalidExecutable(
            "path has no UTF-8 file name",
        ))?;
    if !matches!(basename, "rustscale" | "rustscaled") && !basename.starts_with("rustscale-") {
        return Err(UserUnitError::InvalidExecutable(
            "file name must identify a RustScale executable",
        ));
    }
    if unit.arguments.len() > MAX_ARGUMENTS {
        return Err(UserUnitError::InvalidArgument("too many arguments"));
    }
    for argument in &unit.arguments {
        if argument.len() > MAX_ARGUMENT_BYTES {
            return Err(UserUnitError::InvalidArgument("argument is too long"));
        }
        validate_exec_text(argument).map_err(UserUnitError::InvalidArgument)?;
        if looks_like_environment_assignment(argument) {
            return Err(UserUnitError::InvalidArgument(
                "environment assignments are not accepted",
            ));
        }
        if looks_sensitive(argument) {
            return Err(UserUnitError::InvalidArgument(
                "credential-bearing arguments are not accepted",
            ));
        }
    }
    Ok(())
}

fn validate_exec_text(value: &str) -> Result<(), &'static str> {
    if value.contains('\0') || value.chars().any(char::is_control) {
        return Err("control characters are not accepted");
    }
    // systemd expands both specifiers and manager environment in ExecStart.
    // Reject rather than trying to maintain a second escaping language.
    if value.contains(['%', '$']) {
        return Err("systemd expansion characters are not accepted");
    }
    Ok(())
}

fn looks_like_environment_assignment(argument: &str) -> bool {
    let Some((name, _)) = argument.split_once('=') else {
        return false;
    };
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn looks_sensitive(argument: &str) -> bool {
    let normalized = argument.to_ascii_lowercase().replace('_', "-");
    [
        "auth-key",
        "authkey",
        "password",
        "passwd",
        "secret",
        "token",
        "credential",
        "private-key",
    ]
    .iter()
    .any(|word| normalized.contains(word))
        || (argument.contains("://") && argument.contains('@'))
}

fn quote_exec_word(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for character in value.chars() {
        if matches!(character, '"' | '\\') {
            output.push('\\');
        }
        output.push(character);
    }
    output.push('"');
    output
}

fn is_managed_unit_filename(name: &str) -> bool {
    name.strip_prefix("rustscale-")
        .and_then(|name| name.strip_suffix(".service"))
        .is_some_and(|name| validate_name(name).is_ok())
}

/// Whether the caller is plausibly attached to a Linux systemd user session.
/// A live manager probe remains authoritative.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserSession {
    Supported,
    UnsupportedPlatform,
    MissingRuntimeDirectory,
}

impl UserSession {
    pub fn detect(environment: &dyn Environment) -> Self {
        if !cfg!(target_os = "linux") {
            return Self::UnsupportedPlatform;
        }
        let Some(runtime) = environment.var("XDG_RUNTIME_DIR") else {
            return Self::MissingRuntimeDirectory;
        };
        let path = Path::new(&runtime);
        if runtime.is_empty()
            || !path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
        {
            return Self::MissingRuntimeDirectory;
        }
        Self::Supported
    }
}

/// Outcome from an injected `systemctl` invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemctlOutput {
    pub success: bool,
    pub stdout: Vec<u8>,
}

/// A bounded direct command request. Manager-created requests always use
/// `systemctl` and fixed argument layouts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemctlCommand {
    pub program: String,
    pub arguments: Vec<String>,
    pub timeout: Duration,
    pub max_output: usize,
}

/// Transport failure. Command output is deliberately absent from errors.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SystemctlError {
    #[error("systemctl is unavailable")]
    Unavailable,
    #[error("systemctl operation timed out")]
    TimedOut,
    #[error("systemctl operation was cancelled")]
    Cancelled,
    #[error("systemctl output exceeded its limit")]
    OutputTooLarge,
    #[error("systemctl I/O failed")]
    Io,
}

/// Injectable, shell-free `systemctl` transport.
pub trait SystemctlTransport: Send + Sync {
    fn run(
        &self,
        command: &SystemctlCommand,
        cancellation: &CancellationToken,
    ) -> Result<SystemctlOutput, SystemctlError>;
}

/// Production command transport. Timed-out, cancelled, and overproducing
/// children are killed and reaped before this returns.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemSystemctlTransport;

impl SystemctlTransport for SystemSystemctlTransport {
    fn run(
        &self,
        command: &SystemctlCommand,
        cancellation: &CancellationToken,
    ) -> Result<SystemctlOutput, SystemctlError> {
        run_child(command, cancellation)
    }
}

fn run_child(
    command: &SystemctlCommand,
    cancellation: &CancellationToken,
) -> Result<SystemctlOutput, SystemctlError> {
    if command.program.is_empty() || command.program.contains('\0') {
        return Err(SystemctlError::Unavailable);
    }
    let timeout = command.timeout.min(MAX_TIMEOUT);
    if timeout.is_zero() {
        return Err(SystemctlError::TimedOut);
    }
    if cancellation.is_cancelled() {
        return Err(SystemctlError::Cancelled);
    }
    let child = Command::new(&command.program)
        .args(&command.arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => SystemctlError::Unavailable,
            _ => SystemctlError::Io,
        })?;
    // Install ownership immediately: every subsequent setup/pipe error kills
    // and reaps the child before unwinding.
    let mut child = ChildGuard::new(child);
    let mut stdout = child.child_mut().stdout.take().ok_or(SystemctlError::Io)?;
    set_nonblocking(&stdout)?;
    let limit = command.max_output.min(MAX_OUTPUT_BYTES);
    let mut output = Vec::with_capacity(limit.min(4096));
    let deadline = Instant::now() + timeout;
    let outcome = loop {
        match read_available(&mut stdout, &mut output, limit) {
            Ok(true) => break Err(SystemctlError::OutputTooLarge),
            Ok(false) => {}
            Err(error) => break Err(error),
        }
        if cancellation.is_cancelled() {
            break Err(SystemctlError::Cancelled);
        }
        let now = Instant::now();
        if now >= deadline {
            break Err(SystemctlError::TimedOut);
        }
        let wait = POLL_INTERVAL.min(deadline.saturating_duration_since(now));
        match child.child_mut().wait_timeout(wait) {
            Ok(Some(status)) => {
                let overflow = read_available(&mut stdout, &mut output, limit)?;
                break if overflow {
                    Err(SystemctlError::OutputTooLarge)
                } else {
                    Ok(status.success())
                };
            }
            Ok(None) => {}
            Err(_) => break Err(SystemctlError::Io),
        }
    };
    if outcome.is_err() {
        let _ = child.child_mut().kill();
    }
    // Always reap, including after wait_timeout I/O failures. stdout is
    // nonblocking, so descendants inheriting the pipe cannot extend the bound.
    if child.child_mut().wait().is_err() {
        return Err(SystemctlError::Io);
    }
    child.disarm();
    outcome.map(|success| SystemctlOutput {
        success,
        stdout: output,
    })
}

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self(Some(child))
    }

    fn child_mut(&mut self) -> &mut Child {
        self.0.as_mut().expect("child remains owned until disarm")
    }

    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(unix)]
fn set_nonblocking(stdout: &std::process::ChildStdout) -> Result<(), SystemctlError> {
    let flags = rustix::fs::fcntl_getfl(stdout).map_err(|_| SystemctlError::Io)?;
    rustix::fs::fcntl_setfl(stdout, flags | rustix::fs::OFlags::NONBLOCK)
        .map_err(|_| SystemctlError::Io)
}

#[cfg(not(unix))]
fn set_nonblocking(_stdout: &std::process::ChildStdout) -> Result<(), SystemctlError> {
    // The systemd user API is unsupported on non-Unix targets.
    Err(SystemctlError::Unavailable)
}

fn read_available<R: Read>(
    reader: &mut R,
    retained: &mut Vec<u8>,
    limit: usize,
) -> Result<bool, SystemctlError> {
    let mut buffer = [0_u8; 4096];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(false),
            Ok(count) => {
                let remaining = limit.saturating_sub(retained.len());
                retained.extend_from_slice(&buffer[..count.min(remaining)]);
                if count > remaining {
                    return Ok(true);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(SystemctlError::Io),
        }
    }
}

/// State of the managed path, without following a final symlink.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum StoredUnit {
    #[default]
    Missing,
    Regular(Vec<u8>),
    Symlink,
    Other,
}

/// Filesystem transport failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum UnitStoreError {
    #[error("unit storage is unavailable")]
    Unavailable,
    #[error("unit storage is not owner-only")]
    InsecurePermissions,
    #[error("unit storage ownership is invalid")]
    WrongOwner,
    #[error("unit path changed during the operation")]
    Conflict,
    #[error("operation journal is malformed; explicit precommit repair is required")]
    MalformedJournal,
    #[error("operation state changed during compensation; explicit repair is required")]
    RepairRequired,
    #[error("unit filesystem operation was cancelled")]
    Cancelled,
    #[error("unit mutation committed but its directory sync failed")]
    CommittedNeedsReload,
    #[error("unit filesystem I/O failed")]
    Io,
}

/// Owned advisory lock held for the complete unit transaction.
pub trait UnitOperationGuard: Send {}

impl<T: Send> UnitOperationGuard for T {}

/// Injectable atomic unit-file storage.
pub trait UserUnitStore: Send + Sync {
    fn lock_unit<'a>(
        &'a self,
        unit_name: &str,
        cancellation: &CancellationToken,
        timeout: Duration,
    ) -> Result<Box<dyn UnitOperationGuard + 'a>, UnitStoreError>;

    fn inspect(&self, unit_name: &str) -> Result<StoredUnit, UnitStoreError>;

    fn reload_required(&self, unit_name: &str) -> Result<bool, UnitStoreError>;

    /// Revalidate the exact opened journal snapshot immediately before reload.
    fn revalidate_reload_required(&self, unit_name: &str) -> Result<(), UnitStoreError>;

    fn clear_reload_required(&self, unit_name: &str) -> Result<(), UnitStoreError>;

    /// Remove a malformed final journal only after proving the destination is
    /// still the caller-attested precommit state.
    fn repair_precommit_journal(
        &self,
        unit_name: &str,
        expected: Option<&[u8]>,
    ) -> Result<(), UnitStoreError>;

    /// Atomically replace `expected` with `contents`. `None` means the path must
    /// not exist. Implementations must not follow a final symlink.
    fn atomic_replace(
        &self,
        unit_name: &str,
        expected: Option<&[u8]>,
        contents: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<(), UnitStoreError>;

    fn atomic_remove(
        &self,
        unit_name: &str,
        expected: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<(), UnitStoreError>;
}

/// Filesystem-backed `$XDG_CONFIG_HOME/systemd/user` store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
#[derive(Debug)]
struct ParsedJournal {
    phase: unix_store::JournalPhase,
    kind: String,
    temporary: String,
    before: String,
    after: String,
    before_hash: String,
    after_hash: String,
}

#[cfg(unix)]
#[derive(Debug)]
struct RawSnapshot {
    bytes: Vec<u8>,
    hash: String,
    identity: FileIdentity,
    fd: OwnedFd,
}

#[cfg(unix)]
#[derive(Debug)]
struct JournalSnapshot {
    expected_target_identity: String,
    expected_target_hash: String,
    parsed: ParsedJournal,
    bytes: Vec<u8>,
    hash: String,
    identity: FileIdentity,
    fd: OwnedFd,
}

#[derive(Clone, Debug)]
pub struct SystemUserUnitStore {
    config_home: PathBuf,
    #[cfg(unix)]
    config_directory: Arc<OwnedFd>,
    observed: Arc<Mutex<HashMap<String, (FileIdentity, Vec<u8>)>>>,
    #[cfg(unix)]
    journals: Arc<Mutex<HashMap<String, JournalSnapshot>>>,
}

impl SystemUserUnitStore {
    pub fn new(config_home: impl Into<PathBuf>) -> Result<Self, UnitStoreError> {
        let config_home = config_home.into();
        if !config_home.is_absolute()
            || config_home
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
        {
            return Err(UnitStoreError::Unavailable);
        }
        #[cfg(unix)]
        let config_directory = unix_store::bind_config_directory(&config_home)?;
        Ok(Self {
            config_home,
            #[cfg(unix)]
            config_directory: Arc::new(config_directory),
            observed: Arc::new(Mutex::new(HashMap::new())),
            #[cfg(unix)]
            journals: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn unit_directory(&self) -> PathBuf {
        self.config_home.join("systemd/user")
    }
}

#[cfg(unix)]
mod unix_store {
    use std::fs::File;
    use std::os::unix::fs::FileExt;

    use rustix::fs::{AtFlags, Mode, OFlags};
    use sha2::{Digest, Sha256};

    use super::{
        is_managed_unit_filename, CancellationToken, Component, Duration, FileIdentity, Instant,
        JournalSnapshot, Ordering, OwnedFd, ParsedJournal, Path, RawSnapshot, Read, StoredUnit,
        SystemUserUnitStore, UnitOperationGuard, UnitStoreError, UserUnitStore, Write, MAX_TIMEOUT,
        MAX_UNIT_BYTES, POLL_INTERVAL, TEMP_COUNTER,
    };

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum CasGap {
        AfterValidation,
        AfterMutation,
        BeforeFinalize,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum SnapshotGap {
        AfterInitialStat,
        BeforeFinalStat,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum ClearGap {
        BeforeJournalTombstone,
        AfterJournalTombstone,
        BeforeJournalUnlink,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum RepairGap {
        BeforeJournalTombstone,
        AfterJournalTombstone,
        BeforeJournalUnlink,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TargetValidationStage {
        BeforeTombstone,
        AfterTombstone,
        BeforeUnlink,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum JournalPhase {
        Forward,
        Rollback,
    }

    pub(super) struct JournalMutation {
        pub(super) phase: JournalPhase,
        pub(super) prior: Option<JournalSnapshot>,
    }

    enum ExactTargetSnapshot {
        Missing,
        Regular(RawSnapshot),
    }

    impl JournalPhase {
        fn text(self) -> &'static str {
            match self {
                Self::Forward => "forward",
                Self::Rollback => "rollback",
            }
        }
    }

    fn journal_name(unit_name: &str) -> String {
        format!(".{unit_name}.operation")
    }

    fn journal_phase(bytes: &[u8]) -> Option<JournalPhase> {
        let text = std::str::from_utf8(bytes).ok()?;
        match journal_field(text, "phase")? {
            "forward" => Some(JournalPhase::Forward),
            "rollback" => Some(JournalPhase::Rollback),
            _ => None,
        }
    }

    fn parse_journal(unit_name: &str, bytes: &[u8]) -> Option<ParsedJournal> {
        let text = std::str::from_utf8(bytes).ok()?;
        if !text.starts_with("version=1\n")
            || !text.lines().any(|line| line == format!("unit={unit_name}"))
            || journal_field(text, "operation").is_none()
        {
            return None;
        }
        Some(ParsedJournal {
            phase: journal_phase(bytes)?,
            kind: journal_field(text, "kind")?.to_owned(),
            temporary: journal_field(text, "temporary")?.to_owned(),
            before: journal_field(text, "before")?.to_owned(),
            after: journal_field(text, "after")?.to_owned(),
            before_hash: journal_field(text, "before-hash")?.to_owned(),
            after_hash: journal_field(text, "after-hash")?.to_owned(),
        })
    }

    fn valid_journal(unit_name: &str, bytes: &[u8]) -> bool {
        parse_journal(unit_name, bytes).is_some()
    }

    fn content_hash(bytes: Option<&[u8]>) -> String {
        bytes.map_or_else(
            || "missing".to_owned(),
            |bytes| format!("{:x}", Sha256::digest(bytes)),
        )
    }

    fn journal_field<'a>(text: &'a str, field: &str) -> Option<&'a str> {
        text.lines()
            .find_map(|line| line.strip_prefix(&format!("{field}=")))
    }

    fn snapshot_matches(
        stored: &StoredUnit,
        identity: Option<FileIdentity>,
        expected_identity: &str,
        expected_hash: &str,
    ) -> bool {
        match (stored, identity) {
            (StoredUnit::Missing, None) => {
                expected_identity == "missing" && expected_hash == "missing"
            }
            (StoredUnit::Regular(bytes), Some(identity)) => {
                identity_text(Some(identity)) == expected_identity
                    && content_hash(Some(bytes)) == expected_hash
            }
            _ => false,
        }
    }

    pub(super) fn write_journal_bytes<W: Write>(
        writer: &mut W,
        record: &[u8],
    ) -> std::io::Result<()> {
        writer.write_all(record)
    }

    fn identity_text(identity: Option<FileIdentity>) -> String {
        identity.map_or_else(
            || "missing".to_owned(),
            |identity| format!("{}:{}", identity.device, identity.inode),
        )
    }

    pub(super) fn bind_config_directory(config_home: &Path) -> Result<OwnedFd, UnitStoreError> {
        let basename = config_home
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or(UnitStoreError::Unavailable)?
            .to_os_string();
        let parent = config_home.parent().ok_or(UnitStoreError::Unavailable)?;
        let mut current = rustix::fs::open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| UnitStoreError::Io)?;
        for component in parent.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => {
                    current = rustix::fs::openat(
                        &current,
                        name,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(|_| UnitStoreError::Unavailable)?;
                }
                _ => return Err(UnitStoreError::Unavailable),
            }
        }
        let stat = rustix::fs::fstat(&current).map_err(|_| UnitStoreError::Io)?;
        if stat.st_uid != rustix::process::getuid().as_raw() {
            return Err(UnitStoreError::WrongOwner);
        }
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let open = || rustix::fs::openat(&current, &basename, flags, Mode::empty());
        let config = match open() {
            Ok(config) => config,
            Err(rustix::io::Errno::NOENT) => {
                match rustix::fs::mkdirat(&current, &basename, Mode::RWXU) {
                    Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                    Err(_) => return Err(UnitStoreError::Io),
                }
                open().map_err(|_| UnitStoreError::Unavailable)?
            }
            Err(_) => return Err(UnitStoreError::Unavailable),
        };
        let stat = rustix::fs::fstat(&config).map_err(|_| UnitStoreError::Io)?;
        if stat.st_uid != rustix::process::getuid().as_raw() {
            return Err(UnitStoreError::WrongOwner);
        }
        rustix::fs::fchmod(&config, Mode::RWXU).map_err(|_| UnitStoreError::Io)?;
        Ok(config)
    }

    impl SystemUserUnitStore {
        fn open_owned_dir(
            parent: &OwnedFd,
            name: &str,
            create: bool,
        ) -> Result<Option<OwnedFd>, UnitStoreError> {
            let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            let open = || rustix::fs::openat(parent, name, flags, Mode::empty());
            let directory = match open() {
                Ok(fd) => fd,
                Err(rustix::io::Errno::NOENT) if create => {
                    match rustix::fs::mkdirat(parent, name, Mode::RWXU) {
                        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                        Err(_) => return Err(UnitStoreError::Io),
                    }
                    open().map_err(|_| UnitStoreError::Io)?
                }
                Err(rustix::io::Errno::NOENT) => return Ok(None),
                Err(rustix::io::Errno::LOOP) => return Err(UnitStoreError::Unavailable),
                Err(_) => return Err(UnitStoreError::Io),
            };
            let stat = rustix::fs::fstat(&directory).map_err(|_| UnitStoreError::Io)?;
            if stat.st_uid != rustix::process::getuid().as_raw() {
                return Err(UnitStoreError::WrongOwner);
            }
            rustix::fs::fchmod(&directory, Mode::RWXU).map_err(|_| UnitStoreError::Io)?;
            Ok(Some(directory))
        }

        pub(super) fn open_user_dir(
            &self,
            create: bool,
        ) -> Result<Option<OwnedFd>, UnitStoreError> {
            let Some(systemd) = Self::open_owned_dir(&self.config_directory, "systemd", create)?
            else {
                return Ok(None);
            };
            Self::open_owned_dir(&systemd, "user", create)
        }

        fn has_journal_repair_tombstone(
            directory: &OwnedFd,
            unit_name: &str,
        ) -> Result<bool, UnitStoreError> {
            let prefix = format!("..{unit_name}.operation.");
            let directory =
                rustix::fs::Dir::read_from(directory).map_err(|_| UnitStoreError::Io)?;
            for entry in directory {
                let entry = entry.map_err(|_| UnitStoreError::Io)?;
                if entry.file_name().to_bytes().starts_with(prefix.as_bytes()) {
                    return Ok(true);
                }
            }
            Ok(false)
        }

        pub(super) fn inspect_at(
            directory: &OwnedFd,
            name: &str,
        ) -> Result<(StoredUnit, Option<FileIdentity>), UnitStoreError> {
            let stat = match rustix::fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => stat,
                Err(rustix::io::Errno::NOENT) => return Ok((StoredUnit::Missing, None)),
                Err(_) => return Err(UnitStoreError::Io),
            };
            let file_type = rustix::fs::FileType::from_raw_mode(stat.st_mode);
            if file_type == rustix::fs::FileType::Symlink {
                return Ok((StoredUnit::Symlink, None));
            }
            if file_type != rustix::fs::FileType::RegularFile {
                return Ok((StoredUnit::Other, None));
            }
            if stat.st_uid != rustix::process::getuid().as_raw() {
                return Err(UnitStoreError::WrongOwner);
            }
            if stat.st_mode & 0o077 != 0 {
                return Err(UnitStoreError::InsecurePermissions);
            }
            if stat.st_size < 0 || stat.st_size as usize > MAX_UNIT_BYTES {
                return Ok((StoredUnit::Other, None));
            }
            let fd = rustix::fs::openat(
                directory,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| UnitStoreError::Conflict)?;
            let opened = rustix::fs::fstat(&fd).map_err(|_| UnitStoreError::Io)?;
            if opened.st_dev != stat.st_dev || opened.st_ino != stat.st_ino {
                return Err(UnitStoreError::Conflict);
            }
            let mut bytes = Vec::with_capacity(stat.st_size as usize);
            File::from(fd)
                .take((MAX_UNIT_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|_| UnitStoreError::Io)?;
            if bytes.len() > MAX_UNIT_BYTES {
                return Ok((StoredUnit::Other, None));
            }
            Ok((
                StoredUnit::Regular(bytes),
                Some(FileIdentity {
                    device: opened.st_dev as u64,
                    inode: opened.st_ino as u64,
                }),
            ))
        }

        fn open_raw_snapshot(
            directory: &OwnedFd,
            name: &str,
        ) -> Result<Option<RawSnapshot>, UnitStoreError> {
            let (stored, identity) = Self::inspect_at(directory, name)?;
            let StoredUnit::Regular(bytes) = stored else {
                return match stored {
                    StoredUnit::Missing => Ok(None),
                    _ => Err(UnitStoreError::Conflict),
                };
            };
            let identity = identity.ok_or(UnitStoreError::Conflict)?;
            let fd = rustix::fs::openat(
                directory,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| UnitStoreError::Conflict)?;
            let stat = rustix::fs::fstat(&fd).map_err(|_| UnitStoreError::Io)?;
            if stat.st_dev as u64 != identity.device || stat.st_ino as u64 != identity.inode {
                return Err(UnitStoreError::Conflict);
            }
            Ok(Some(RawSnapshot {
                hash: content_hash(Some(&bytes)),
                bytes,
                identity,
                fd,
            }))
        }

        fn raw_snapshot_still_named(
            directory: &OwnedFd,
            name: &str,
            snapshot: &RawSnapshot,
        ) -> Result<bool, UnitStoreError> {
            let fd_stat = rustix::fs::fstat(&snapshot.fd).map_err(|_| UnitStoreError::Io)?;
            let name_stat = match rustix::fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => stat,
                Err(rustix::io::Errno::NOENT) => return Ok(false),
                Err(_) => return Err(UnitStoreError::Io),
            };
            if fd_stat.st_dev as u64 != snapshot.identity.device
                || fd_stat.st_ino as u64 != snapshot.identity.inode
                || name_stat.st_dev as u64 != snapshot.identity.device
                || name_stat.st_ino as u64 != snapshot.identity.inode
            {
                return Ok(false);
            }
            let duplicate = rustix::io::dup(&snapshot.fd).map_err(|_| UnitStoreError::Io)?;
            let file = File::from(duplicate);
            let mut current = Vec::new();
            let mut buffer = [0_u8; 4096];
            let mut offset = 0_u64;
            loop {
                let count = file
                    .read_at(&mut buffer, offset)
                    .map_err(|_| UnitStoreError::Io)?;
                if count == 0 {
                    break;
                }
                if current.len() + count > MAX_UNIT_BYTES {
                    return Ok(false);
                }
                current.extend_from_slice(&buffer[..count]);
                offset += count as u64;
            }
            let final_fd = rustix::fs::fstat(&snapshot.fd).map_err(|_| UnitStoreError::Io)?;
            let final_name = rustix::fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| UnitStoreError::Conflict)?;
            Ok(current == snapshot.bytes
                && content_hash(Some(&current)) == snapshot.hash
                && final_fd.st_dev as u64 == snapshot.identity.device
                && final_fd.st_ino as u64 == snapshot.identity.inode
                && final_fd.st_size >= 0
                && final_fd.st_size as usize == snapshot.bytes.len()
                && final_name.st_dev as u64 == snapshot.identity.device
                && final_name.st_ino as u64 == snapshot.identity.inode
                && final_name.st_size >= 0
                && final_name.st_size as usize == snapshot.bytes.len())
        }

        fn capture_expected_target(
            directory: &OwnedFd,
            unit_name: &str,
            expected_identity: &str,
            expected_hash: &str,
        ) -> Result<ExactTargetSnapshot, UnitStoreError> {
            if expected_identity == "missing" && expected_hash == "missing" {
                return matches!(
                    Self::inspect_at(directory, unit_name),
                    Ok((StoredUnit::Missing, None))
                )
                .then_some(ExactTargetSnapshot::Missing)
                .ok_or(UnitStoreError::RepairRequired);
            }
            let snapshot = Self::open_raw_snapshot(directory, unit_name)?
                .ok_or(UnitStoreError::RepairRequired)?;
            if identity_text(Some(snapshot.identity)) != expected_identity
                || snapshot.hash != expected_hash
            {
                return Err(UnitStoreError::RepairRequired);
            }
            Ok(ExactTargetSnapshot::Regular(snapshot))
        }

        fn exact_target_still_named(
            directory: &OwnedFd,
            unit_name: &str,
            snapshot: &ExactTargetSnapshot,
        ) -> Result<bool, UnitStoreError> {
            match snapshot {
                ExactTargetSnapshot::Missing => Ok(matches!(
                    Self::inspect_at(directory, unit_name),
                    Ok((StoredUnit::Missing, None))
                )),
                ExactTargetSnapshot::Regular(snapshot) => {
                    Self::raw_snapshot_still_named(directory, unit_name, snapshot)
                }
            }
        }

        pub(super) fn open_journal_snapshot(
            directory: &OwnedFd,
            unit_name: &str,
        ) -> Result<Option<JournalSnapshot>, UnitStoreError> {
            let name = journal_name(unit_name);
            let stat = match rustix::fs::statat(directory, &name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => stat,
                Err(rustix::io::Errno::NOENT) => return Ok(None),
                Err(_) => return Err(UnitStoreError::Io),
            };
            if rustix::fs::FileType::from_raw_mode(stat.st_mode)
                != rustix::fs::FileType::RegularFile
                || stat.st_uid != rustix::process::getuid().as_raw()
                || stat.st_mode & 0o077 != 0
                || stat.st_size < 0
                || stat.st_size as usize > MAX_UNIT_BYTES
            {
                return Err(UnitStoreError::MalformedJournal);
            }
            let fd = rustix::fs::openat(
                directory,
                &name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| UnitStoreError::Conflict)?;
            let opened = rustix::fs::fstat(&fd).map_err(|_| UnitStoreError::Io)?;
            if opened.st_dev != stat.st_dev || opened.st_ino != stat.st_ino {
                return Err(UnitStoreError::Conflict);
            }
            let identity = FileIdentity {
                device: opened.st_dev as u64,
                inode: opened.st_ino as u64,
            };
            let mut file = File::from(fd);
            let mut bytes = Vec::with_capacity(stat.st_size as usize);
            (&mut file)
                .take((MAX_UNIT_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|_| UnitStoreError::Io)?;
            if bytes.len() > MAX_UNIT_BYTES {
                return Err(UnitStoreError::MalformedJournal);
            }
            let fd: OwnedFd = file.into();
            let current = rustix::fs::statat(directory, &name, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| UnitStoreError::Conflict)?;
            if current.st_dev != opened.st_dev || current.st_ino != opened.st_ino {
                return Err(UnitStoreError::Conflict);
            }
            let parsed =
                parse_journal(unit_name, &bytes).ok_or(UnitStoreError::MalformedJournal)?;
            Ok(Some(JournalSnapshot {
                expected_target_identity: parsed.after.clone(),
                expected_target_hash: parsed.after_hash.clone(),
                parsed,
                hash: content_hash(Some(&bytes)),
                bytes,
                identity,
                fd,
            }))
        }

        pub(super) fn snapshot_still_named_with_hook<F>(
            directory: &OwnedFd,
            unit_name: &str,
            snapshot: &JournalSnapshot,
            mut hook: F,
        ) -> Result<bool, UnitStoreError>
        where
            F: FnMut(SnapshotGap, &OwnedFd, &str),
        {
            let initial_fd = rustix::fs::fstat(&snapshot.fd).map_err(|_| UnitStoreError::Io)?;
            let initial_name = match rustix::fs::statat(
                directory,
                journal_name(unit_name),
                AtFlags::SYMLINK_NOFOLLOW,
            ) {
                Ok(stat) => stat,
                Err(rustix::io::Errno::NOENT) => return Ok(false),
                Err(_) => return Err(UnitStoreError::Io),
            };
            if initial_fd.st_dev as u64 != snapshot.identity.device
                || initial_fd.st_ino as u64 != snapshot.identity.inode
                || initial_name.st_dev as u64 != snapshot.identity.device
                || initial_name.st_ino as u64 != snapshot.identity.inode
            {
                return Ok(false);
            }
            hook(SnapshotGap::AfterInitialStat, directory, unit_name);

            let duplicate = rustix::io::dup(&snapshot.fd).map_err(|_| UnitStoreError::Io)?;
            let file = File::from(duplicate);
            let mut current = Vec::with_capacity(snapshot.bytes.len().min(4096));
            let mut buffer = [0_u8; 4096];
            let mut offset = 0_u64;
            loop {
                let count = file
                    .read_at(&mut buffer, offset)
                    .map_err(|_| UnitStoreError::Io)?;
                if count == 0 {
                    break;
                }
                if current.len() + count > MAX_UNIT_BYTES {
                    return Ok(false);
                }
                current.extend_from_slice(&buffer[..count]);
                offset += count as u64;
            }
            if current != snapshot.bytes || content_hash(Some(&current)) != snapshot.hash {
                return Ok(false);
            }
            hook(SnapshotGap::BeforeFinalStat, directory, unit_name);
            let final_fd = rustix::fs::fstat(&snapshot.fd).map_err(|_| UnitStoreError::Io)?;
            let final_name = match rustix::fs::statat(
                directory,
                journal_name(unit_name),
                AtFlags::SYMLINK_NOFOLLOW,
            ) {
                Ok(stat) => stat,
                Err(rustix::io::Errno::NOENT) => return Ok(false),
                Err(_) => return Err(UnitStoreError::Io),
            };
            Ok(final_fd.st_dev as u64 == snapshot.identity.device
                && final_fd.st_ino as u64 == snapshot.identity.inode
                && final_fd.st_size >= 0
                && final_fd.st_size as usize == snapshot.bytes.len()
                && final_name.st_dev as u64 == snapshot.identity.device
                && final_name.st_ino as u64 == snapshot.identity.inode
                && final_name.st_size >= 0
                && final_name.st_size as usize == snapshot.bytes.len())
        }

        fn snapshot_still_named(
            directory: &OwnedFd,
            unit_name: &str,
            snapshot: &JournalSnapshot,
        ) -> Result<bool, UnitStoreError> {
            Self::snapshot_still_named_with_hook(directory, unit_name, snapshot, |_, _, _| {})
        }

        fn exact_regular(
            stored: &StoredUnit,
            identity: Option<FileIdentity>,
            expected: &[u8],
            expected_identity: FileIdentity,
        ) -> bool {
            matches!(
                (stored, identity),
                (StoredUnit::Regular(actual), Some(identity))
                    if actual == expected && identity == expected_identity
            )
        }

        pub(super) fn exchange_exact_with_hook<F>(
            directory: &OwnedFd,
            left: &str,
            left_bytes: &[u8],
            left_identity: FileIdentity,
            right: &str,
            right_bytes: &[u8],
            right_identity: FileIdentity,
            mut hook: F,
        ) -> Result<(), UnitStoreError>
        where
            F: FnMut(CasGap, &OwnedFd, &str, &str),
        {
            let (left_now, left_now_identity) = Self::inspect_at(directory, left)?;
            let (right_now, right_now_identity) = Self::inspect_at(directory, right)?;
            if !Self::exact_regular(&left_now, left_now_identity, left_bytes, left_identity)
                || !Self::exact_regular(&right_now, right_now_identity, right_bytes, right_identity)
            {
                return Err(UnitStoreError::Conflict);
            }
            hook(CasGap::AfterValidation, directory, left, right);
            rustix::fs::renameat_with(
                directory,
                left,
                directory,
                right,
                rustix::fs::RenameFlags::EXCHANGE,
            )
            .map_err(|_| UnitStoreError::Conflict)?;
            hook(CasGap::AfterMutation, directory, left, right);
            let left_after = Self::inspect_at(directory, left);
            let right_after = Self::inspect_at(directory, right);
            let valid = matches!(
                (left_after, right_after),
                (
                    Ok((left_stored, left_observed)),
                    Ok((right_stored, right_observed)),
                ) if Self::exact_regular(
                    &left_stored,
                    left_observed,
                    right_bytes,
                    right_identity,
                ) && Self::exact_regular(
                    &right_stored,
                    right_observed,
                    left_bytes,
                    left_identity,
                )
            );
            if valid {
                return Ok(());
            }
            // At least one name no longer refers to an expected inode. Moving
            // either name could clobber a racer, so preserve both fail-closed.
            Err(UnitStoreError::RepairRequired)
        }

        fn exchange_exact(
            directory: &OwnedFd,
            left: &str,
            left_bytes: &[u8],
            left_identity: FileIdentity,
            right: &str,
            right_bytes: &[u8],
            right_identity: FileIdentity,
        ) -> Result<(), UnitStoreError> {
            Self::exchange_exact_with_hook(
                directory,
                left,
                left_bytes,
                left_identity,
                right,
                right_bytes,
                right_identity,
                |_, _, _, _| {},
            )
        }

        pub(super) fn rename_noreplace_exact_with_hook<F>(
            directory: &OwnedFd,
            source: &str,
            expected: &[u8],
            expected_identity: FileIdentity,
            destination: &str,
            mut hook: F,
        ) -> Result<(), UnitStoreError>
        where
            F: FnMut(CasGap, &OwnedFd, &str, &str),
        {
            let (source_now, source_identity) = Self::inspect_at(directory, source)?;
            let (destination_now, destination_identity) = Self::inspect_at(directory, destination)?;
            if !Self::exact_regular(&source_now, source_identity, expected, expected_identity)
                || !matches!(
                    (destination_now, destination_identity),
                    (StoredUnit::Missing, None)
                )
            {
                return Err(UnitStoreError::Conflict);
            }
            hook(CasGap::AfterValidation, directory, source, destination);
            rustix::fs::renameat_with(
                directory,
                source,
                directory,
                destination,
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .map_err(|_| UnitStoreError::Conflict)?;
            hook(CasGap::AfterMutation, directory, source, destination);
            let (published, published_identity) = Self::inspect_at(directory, destination)?;
            let (source_after, source_after_identity) = Self::inspect_at(directory, source)?;
            if Self::exact_regular(&published, published_identity, expected, expected_identity)
                && matches!(
                    (source_after, source_after_identity),
                    (StoredUnit::Missing, None)
                )
            {
                return Ok(());
            }
            Err(UnitStoreError::RepairRequired)
        }

        fn rename_noreplace_exact(
            directory: &OwnedFd,
            source: &str,
            expected: &[u8],
            expected_identity: FileIdentity,
            destination: &str,
        ) -> Result<(), UnitStoreError> {
            Self::rename_noreplace_exact_with_hook(
                directory,
                source,
                expected,
                expected_identity,
                destination,
                |_, _, _, _| {},
            )
        }

        fn remove_exact_validated_with_hook<F, V>(
            directory: &OwnedFd,
            name: &str,
            expected: &[u8],
            expected_identity: FileIdentity,
            tag: &str,
            mut validate_target: V,
            mut hook: F,
        ) -> Result<(), UnitStoreError>
        where
            F: FnMut(CasGap, &OwnedFd, &str, &str),
            V: FnMut(TargetValidationStage) -> Result<bool, UnitStoreError>,
        {
            let (current, identity) = Self::inspect_at(directory, name)?;
            if !Self::exact_regular(&current, identity, expected, expected_identity) {
                return Err(UnitStoreError::Conflict);
            }
            if !validate_target(TargetValidationStage::BeforeTombstone)? {
                return Err(UnitStoreError::RepairRequired);
            }
            let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let tombstone = format!(".{name}.{tag}.{sequence:x}");
            hook(CasGap::AfterValidation, directory, name, &tombstone);
            rustix::fs::renameat_with(
                directory,
                name,
                directory,
                &tombstone,
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .map_err(|_| UnitStoreError::Conflict)?;
            hook(CasGap::AfterMutation, directory, name, &tombstone);
            let (displaced, displaced_identity) = Self::inspect_at(directory, &tombstone)?;
            if !Self::exact_regular(&displaced, displaced_identity, expected, expected_identity) {
                return Err(UnitStoreError::RepairRequired);
            }
            if !validate_target(TargetValidationStage::AfterTombstone)? {
                // Restore the journal name only if the target raced back to the
                // exact captured state and the tombstone is still exact.
                if validate_target(TargetValidationStage::AfterTombstone)? {
                    let _ = Self::rename_noreplace_exact(
                        directory,
                        &tombstone,
                        expected,
                        expected_identity,
                        name,
                    );
                }
                return Err(UnitStoreError::RepairRequired);
            }
            hook(CasGap::BeforeFinalize, directory, name, &tombstone);
            let (final_file, final_identity) = Self::inspect_at(directory, &tombstone)?;
            if !Self::exact_regular(&final_file, final_identity, expected, expected_identity) {
                return Err(UnitStoreError::RepairRequired);
            }
            if !validate_target(TargetValidationStage::BeforeUnlink)? {
                if validate_target(TargetValidationStage::BeforeUnlink)? {
                    let _ = Self::rename_noreplace_exact(
                        directory,
                        &tombstone,
                        expected,
                        expected_identity,
                        name,
                    );
                }
                return Err(UnitStoreError::RepairRequired);
            }
            rustix::fs::unlinkat(directory, &tombstone, AtFlags::empty())
                .map_err(|_| UnitStoreError::Io)
        }

        pub(super) fn remove_exact_with_hook<F>(
            directory: &OwnedFd,
            name: &str,
            expected: &[u8],
            expected_identity: FileIdentity,
            tag: &str,
            hook: F,
        ) -> Result<(), UnitStoreError>
        where
            F: FnMut(CasGap, &OwnedFd, &str, &str),
        {
            Self::remove_exact_validated_with_hook(
                directory,
                name,
                expected,
                expected_identity,
                tag,
                |_| Ok(true),
                hook,
            )
        }

        fn remove_exact(
            directory: &OwnedFd,
            name: &str,
            expected: &[u8],
            expected_identity: FileIdentity,
            tag: &str,
        ) -> Result<(), UnitStoreError> {
            Self::remove_exact_with_hook(
                directory,
                name,
                expected,
                expected_identity,
                tag,
                |_, _, _, _| {},
            )
        }

        fn journal_phase_for_mutation(
            directory: &OwnedFd,
            unit_name: &str,
        ) -> Result<JournalMutation, UnitStoreError> {
            match Self::open_journal_snapshot(directory, unit_name)? {
                None if !Self::has_journal_repair_tombstone(directory, unit_name)? => {
                    Ok(JournalMutation {
                        phase: JournalPhase::Forward,
                        prior: None,
                    })
                }
                None => Err(UnitStoreError::RepairRequired),
                Some(snapshot) if snapshot.parsed.phase == JournalPhase::Forward => {
                    Ok(JournalMutation {
                        phase: JournalPhase::Rollback,
                        prior: Some(snapshot),
                    })
                }
                Some(_) => Err(UnitStoreError::Conflict),
            }
        }

        pub(super) fn publish_journal(
            directory: &OwnedFd,
            unit_name: &str,
            mutation: JournalMutation,
            record: &[u8],
        ) -> Result<JournalSnapshot, UnitStoreError> {
            let journal = journal_name(unit_name);
            let mut staging = None;
            for _ in 0..16 {
                let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
                let candidate = format!(
                    ".{unit_name}.operation-write.{:x}.{sequence:x}",
                    std::process::id()
                );
                match rustix::fs::openat(
                    directory,
                    &candidate,
                    OFlags::WRONLY
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::RUSR | Mode::WUSR,
                ) {
                    Ok(fd) => {
                        staging = Some((candidate, fd));
                        break;
                    }
                    Err(rustix::io::Errno::EXIST) => {}
                    Err(_) => return Err(UnitStoreError::Io),
                }
            }
            let (temporary, fd) = staging.ok_or(UnitStoreError::Io)?;
            let new_stat = rustix::fs::fstat(&fd).map_err(|_| UnitStoreError::Io)?;
            let new_identity = FileIdentity {
                device: new_stat.st_dev as u64,
                inode: new_stat.st_ino as u64,
            };
            let mut file = File::from(fd);
            let prepared = (|| {
                write_journal_bytes(&mut file, record).map_err(|_| UnitStoreError::Io)?;
                file.sync_all().map_err(|_| UnitStoreError::Io)?;
                drop(file);
                match mutation.phase {
                    JournalPhase::Forward => {
                        rustix::fs::renameat_with(
                            directory,
                            &temporary,
                            directory,
                            &journal,
                            rustix::fs::RenameFlags::NOREPLACE,
                        )
                        .map_err(|error| match error {
                            rustix::io::Errno::EXIST => UnitStoreError::Conflict,
                            _ => UnitStoreError::Io,
                        })?;
                    }
                    JournalPhase::Rollback => {
                        let expected = mutation
                            .prior
                            .as_ref()
                            .ok_or(UnitStoreError::RepairRequired)?;
                        if !Self::snapshot_still_named(directory, unit_name, expected)? {
                            return Err(UnitStoreError::Conflict);
                        }
                        Self::exchange_exact(
                            directory,
                            &temporary,
                            record,
                            new_identity,
                            &journal,
                            &expected.bytes,
                            expected.identity,
                        )?;
                        if let Err(error) = Self::remove_exact(
                            directory,
                            &temporary,
                            &expected.bytes,
                            expected.identity,
                            "journal-displaced",
                        ) {
                            if Self::exchange_exact(
                                directory,
                                &temporary,
                                &expected.bytes,
                                expected.identity,
                                &journal,
                                record,
                                new_identity,
                            )
                            .is_ok()
                            {
                                return Err(error);
                            }
                            return Err(UnitStoreError::CommittedNeedsReload);
                        }
                    }
                }
                rustix::fs::fsync(directory).map_err(|_| UnitStoreError::CommittedNeedsReload)
            })();
            if prepared.is_err() {
                let _ = Self::remove_exact(
                    directory,
                    &temporary,
                    record,
                    new_identity,
                    "journal-abort",
                );
            }
            prepared?;
            let snapshot = Self::open_journal_snapshot(directory, unit_name)?
                .ok_or(UnitStoreError::RepairRequired)?;
            if snapshot.bytes != record || snapshot.identity != new_identity {
                return Err(UnitStoreError::RepairRequired);
            }
            Ok(snapshot)
        }

        fn remember_journal(&self, unit_name: &str, snapshot: JournalSnapshot) {
            self.journals
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(unit_name.to_owned(), snapshot);
        }

        fn set_cached_expected_target(
            &self,
            unit_name: &str,
            identity: &str,
            hash: &str,
        ) -> Result<(), UnitStoreError> {
            let mut snapshots = self
                .journals
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let snapshot = snapshots
                .get_mut(unit_name)
                .ok_or(UnitStoreError::RepairRequired)?;
            identity.clone_into(&mut snapshot.expected_target_identity);
            hash.clone_into(&mut snapshot.expected_target_hash);
            Ok(())
        }

        fn revalidate_cached_journal(
            &self,
            directory: &OwnedFd,
            unit_name: &str,
        ) -> Result<(), UnitStoreError> {
            let snapshots = self
                .journals
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let snapshot = snapshots
                .get(unit_name)
                .ok_or(UnitStoreError::RepairRequired)?;
            Self::snapshot_still_named(directory, unit_name, snapshot)?
                .then_some(())
                .ok_or(UnitStoreError::RepairRequired)
        }

        fn write_at(
            &self,
            directory: &OwnedFd,
            name: &str,
            expected: Option<&[u8]>,
            expected_identity: Option<FileIdentity>,
            contents: &[u8],
            cancellation: &CancellationToken,
        ) -> Result<(), UnitStoreError> {
            if cancellation.is_cancelled() {
                return Err(UnitStoreError::Cancelled);
            }
            let (current, current_identity) = Self::inspect_at(directory, name)?;
            match (expected, expected_identity, current, current_identity) {
                (None, None, StoredUnit::Missing, None) => {}
                (
                    Some(expected),
                    Some(expected_identity),
                    StoredUnit::Regular(actual),
                    Some(actual_identity),
                ) if expected == actual && expected_identity == actual_identity => {}
                _ => return Err(UnitStoreError::Conflict),
            }
            let mut temporary = None;
            for _ in 0..16 {
                let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
                let candidate = format!(".{name}.tmp.{:x}.{sequence:x}", std::process::id());
                match rustix::fs::openat(
                    directory,
                    &candidate,
                    OFlags::WRONLY
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::NOFOLLOW
                        | OFlags::CLOEXEC,
                    Mode::RUSR | Mode::WUSR,
                ) {
                    Ok(fd) => {
                        temporary = Some((candidate, File::from(fd)));
                        break;
                    }
                    Err(rustix::io::Errno::EXIST) => {}
                    Err(_) => return Err(UnitStoreError::Io),
                }
            }
            let Some((temporary_name, mut file)) = temporary else {
                return Err(UnitStoreError::Io);
            };
            let new_stat = rustix::fs::fstat(&file).map_err(|_| UnitStoreError::Io)?;
            let new_identity = FileIdentity {
                device: new_stat.st_dev as u64,
                inode: new_stat.st_ino as u64,
            };
            let mut committed = false;
            let result = (|| {
                file.write_all(contents).map_err(|_| UnitStoreError::Io)?;
                file.sync_all().map_err(|_| UnitStoreError::Io)?;
                drop(file);
                if cancellation.is_cancelled() {
                    return Err(UnitStoreError::Cancelled);
                }
                // Bind the intent to both exact inodes and the unique staging
                // name before the CAS can become visible.
                let phase = Self::journal_phase_for_mutation(directory, name)?;
                let operation = format!(
                    "version=1\nunit={name}\noperation={temporary_name}\nphase={}\nkind=replace\ntemporary={temporary_name}\nbefore={}\nafter={}\nbefore-hash={}\nafter-hash={}\nbefore-bytes={}\nafter-bytes={}\n",
                    phase.phase.text(),
                    identity_text(expected_identity),
                    identity_text(Some(new_identity)),
                    content_hash(expected),
                    content_hash(Some(contents)),
                    expected.map_or(0, <[u8]>::len),
                    contents.len(),
                );
                let journal = Self::publish_journal(directory, name, phase, operation.as_bytes())?;
                self.remember_journal(name, journal);

                // Re-open and validate immediately before publication. This is
                // the last possible check on kernels without conditional rename.
                let (immediate, immediate_identity) = Self::inspect_at(directory, name)?;
                match (expected, expected_identity, immediate, immediate_identity) {
                    (None, None, StoredUnit::Missing, None) => {}
                    (
                        Some(expected),
                        Some(expected_identity),
                        StoredUnit::Regular(actual),
                        Some(actual_identity),
                    ) if actual == expected && actual_identity == expected_identity => {}
                    _ => return Err(UnitStoreError::Conflict),
                }

                match expected {
                    None => {
                        Self::rename_noreplace_exact(
                            directory,
                            &temporary_name,
                            contents,
                            new_identity,
                            name,
                        )?;
                        committed = true;
                    }
                    Some(expected) => {
                        let expected_identity =
                            expected_identity.ok_or(UnitStoreError::Conflict)?;
                        Self::exchange_exact(
                            directory,
                            &temporary_name,
                            contents,
                            new_identity,
                            name,
                            expected,
                            expected_identity,
                        )?;
                        committed = true;
                        if let Err(error) = Self::remove_exact(
                            directory,
                            &temporary_name,
                            expected,
                            expected_identity,
                            "data-displaced",
                        ) {
                            if Self::exchange_exact(
                                directory,
                                &temporary_name,
                                expected,
                                expected_identity,
                                name,
                                contents,
                                new_identity,
                            )
                            .is_ok()
                            {
                                committed = false;
                                return Err(error);
                            }
                            return Err(UnitStoreError::CommittedNeedsReload);
                        }
                    }
                }
                Ok(())
            })();
            if !committed && !matches!(&result, Err(UnitStoreError::CommittedNeedsReload)) {
                let _ = Self::remove_exact(
                    directory,
                    &temporary_name,
                    contents,
                    new_identity,
                    "data-abort",
                );
            }
            match result {
                Ok(()) => {
                    rustix::fs::fsync(directory).map_err(|_| UnitStoreError::CommittedNeedsReload)
                }
                Err(_) if committed => Err(UnitStoreError::CommittedNeedsReload),
                Err(error) => Err(error),
            }
        }

        pub(super) fn clear_reload_required_with_hook<F>(
            &self,
            unit_name: &str,
            mut hook: F,
        ) -> Result<(), UnitStoreError>
        where
            F: FnMut(ClearGap, &OwnedFd, &str),
        {
            if !is_managed_unit_filename(unit_name) {
                return Err(UnitStoreError::Unavailable);
            }
            let Some(directory) = self.open_user_dir(false)? else {
                return Ok(());
            };
            let journal = journal_name(unit_name);
            let mut snapshots = self
                .journals
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let snapshot = snapshots
                .get(unit_name)
                .ok_or(UnitStoreError::RepairRequired)?;
            if !Self::snapshot_still_named(&directory, unit_name, snapshot)?
                || !matches!(
                    Self::inspect_at(&directory, &snapshot.parsed.temporary),
                    Ok((StoredUnit::Missing, None))
                )
            {
                return Err(UnitStoreError::RepairRequired);
            }
            let target = Self::capture_expected_target(
                &directory,
                unit_name,
                &snapshot.expected_target_identity,
                &snapshot.expected_target_hash,
            )?;
            Self::remove_exact_validated_with_hook(
                &directory,
                &journal,
                &snapshot.bytes,
                snapshot.identity,
                "journal-clear",
                |stage| {
                    let gap = match stage {
                        TargetValidationStage::BeforeTombstone => ClearGap::BeforeJournalTombstone,
                        TargetValidationStage::AfterTombstone => ClearGap::AfterJournalTombstone,
                        TargetValidationStage::BeforeUnlink => ClearGap::BeforeJournalUnlink,
                    };
                    hook(gap, &directory, unit_name);
                    if stage == TargetValidationStage::BeforeTombstone
                        && !Self::snapshot_still_named(&directory, unit_name, snapshot)?
                    {
                        return Ok(false);
                    }
                    Self::exact_target_still_named(&directory, unit_name, &target)
                },
                |_, _, _, _| {},
            )
            .map_err(|error| match error {
                UnitStoreError::Conflict | UnitStoreError::RepairRequired => {
                    UnitStoreError::RepairRequired
                }
                _ => UnitStoreError::CommittedNeedsReload,
            })?;
            rustix::fs::fsync(&directory).map_err(|_| UnitStoreError::CommittedNeedsReload)?;
            snapshots.remove(unit_name);
            Ok(())
        }

        pub(super) fn repair_precommit_journal_with_hook<F>(
            &self,
            unit_name: &str,
            expected: Option<&[u8]>,
            mut hook: F,
        ) -> Result<(), UnitStoreError>
        where
            F: FnMut(RepairGap, &OwnedFd, &str),
        {
            if !is_managed_unit_filename(unit_name) {
                return Err(UnitStoreError::Unavailable);
            }
            let directory = self.open_user_dir(false)?.ok_or(UnitStoreError::Conflict)?;
            let journal_name = journal_name(unit_name);
            let journal = Self::open_raw_snapshot(&directory, &journal_name)?
                .ok_or(UnitStoreError::Conflict)?;
            if valid_journal(unit_name, &journal.bytes) {
                return Err(UnitStoreError::Conflict);
            }
            let target = if let Some(expected) = expected {
                let snapshot = Self::open_raw_snapshot(&directory, unit_name)?
                    .ok_or(UnitStoreError::Conflict)?;
                if snapshot.bytes != expected {
                    return Err(UnitStoreError::Conflict);
                }
                ExactTargetSnapshot::Regular(snapshot)
            } else {
                if !matches!(
                    Self::inspect_at(&directory, unit_name),
                    Ok((StoredUnit::Missing, None))
                ) {
                    return Err(UnitStoreError::Conflict);
                }
                ExactTargetSnapshot::Missing
            };
            Self::remove_exact_validated_with_hook(
                &directory,
                &journal_name,
                &journal.bytes,
                journal.identity,
                "malformed-repair",
                |stage| {
                    let gap = match stage {
                        TargetValidationStage::BeforeTombstone => RepairGap::BeforeJournalTombstone,
                        TargetValidationStage::AfterTombstone => RepairGap::AfterJournalTombstone,
                        TargetValidationStage::BeforeUnlink => RepairGap::BeforeJournalUnlink,
                    };
                    hook(gap, &directory, unit_name);
                    if stage == TargetValidationStage::BeforeTombstone
                        && !Self::raw_snapshot_still_named(&directory, &journal_name, &journal)?
                    {
                        return Ok(false);
                    }
                    Self::exact_target_still_named(&directory, unit_name, &target)
                },
                |_, _, _, _| {},
            )?;
            rustix::fs::fsync(&directory).map_err(|_| UnitStoreError::Io)
        }
    }

    impl UserUnitStore for SystemUserUnitStore {
        fn lock_unit<'a>(
            &'a self,
            unit_name: &str,
            cancellation: &CancellationToken,
            timeout: Duration,
        ) -> Result<Box<dyn UnitOperationGuard + 'a>, UnitStoreError> {
            if !is_managed_unit_filename(unit_name) {
                return Err(UnitStoreError::Unavailable);
            }
            let directory = self
                .open_user_dir(true)?
                .ok_or(UnitStoreError::Unavailable)?;
            let lock_name = format!(".{unit_name}.lock");
            let fd = rustix::fs::openat(
                &directory,
                &lock_name,
                OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| UnitStoreError::Conflict)?;
            let stat = rustix::fs::fstat(&fd).map_err(|_| UnitStoreError::Io)?;
            if rustix::fs::FileType::from_raw_mode(stat.st_mode)
                != rustix::fs::FileType::RegularFile
            {
                return Err(UnitStoreError::Conflict);
            }
            if stat.st_uid != rustix::process::getuid().as_raw() {
                return Err(UnitStoreError::WrongOwner);
            }
            if stat.st_mode & 0o077 != 0 {
                return Err(UnitStoreError::InsecurePermissions);
            }
            rustix::fs::fsync(&fd).map_err(|_| UnitStoreError::Io)?;
            rustix::fs::fsync(&directory).map_err(|_| UnitStoreError::Io)?;
            let deadline = Instant::now() + timeout.min(MAX_TIMEOUT);
            loop {
                if cancellation.is_cancelled() {
                    return Err(UnitStoreError::Cancelled);
                }
                match rustix::fs::flock(&fd, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
                    Ok(()) => return Ok(Box::new(fd)),
                    Err(rustix::io::Errno::WOULDBLOCK) if Instant::now() < deadline => {
                        std::thread::sleep(POLL_INTERVAL);
                    }
                    Err(rustix::io::Errno::WOULDBLOCK) => {
                        return Err(UnitStoreError::Conflict);
                    }
                    Err(_) => return Err(UnitStoreError::Io),
                }
            }
        }

        fn inspect(&self, unit_name: &str) -> Result<StoredUnit, UnitStoreError> {
            if !is_managed_unit_filename(unit_name) {
                return Err(UnitStoreError::Unavailable);
            }
            let Some(directory) = self.open_user_dir(false)? else {
                self.observed
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(unit_name);
                return Ok(StoredUnit::Missing);
            };
            let (stored, identity) = Self::inspect_at(&directory, unit_name)?;
            let mut observed = self
                .observed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match (&stored, identity) {
                (StoredUnit::Regular(bytes), Some(identity)) => {
                    observed.insert(unit_name.to_owned(), (identity, bytes.clone()));
                }
                _ => {
                    observed.remove(unit_name);
                }
            }
            Ok(stored)
        }

        fn reload_required(&self, unit_name: &str) -> Result<bool, UnitStoreError> {
            if !is_managed_unit_filename(unit_name) {
                return Err(UnitStoreError::Unavailable);
            }
            let Some(directory) = self.open_user_dir(false)? else {
                return Ok(false);
            };
            let Some(snapshot) = Self::open_journal_snapshot(&directory, unit_name)? else {
                return if Self::has_journal_repair_tombstone(&directory, unit_name)? {
                    Err(UnitStoreError::RepairRequired)
                } else {
                    Ok(false)
                };
            };
            let phase = snapshot.parsed.phase;
            let kind = snapshot.parsed.kind.clone();
            let temporary = snapshot.parsed.temporary.clone();
            let before = snapshot.parsed.before.clone();
            let after = snapshot.parsed.after.clone();
            let before_hash = snapshot.parsed.before_hash.clone();
            let after_hash = snapshot.parsed.after_hash.clone();
            if !temporary.starts_with(&format!(".{unit_name}.")) || temporary.contains(['/', '\0'])
            {
                return Err(UnitStoreError::MalformedJournal);
            }
            self.remember_journal(unit_name, snapshot);
            let temporary = temporary.as_str();
            let before = before.as_str();
            let after = after.as_str();
            let before_hash = before_hash.as_str();
            let after_hash = after_hash.as_str();
            let kind = kind.as_str();
            let (target, target_identity) = Self::inspect_at(&directory, unit_name)
                .map_err(|_| UnitStoreError::CommittedNeedsReload)?;
            let (staged, staged_identity) = Self::inspect_at(&directory, temporary)
                .map_err(|_| UnitStoreError::CommittedNeedsReload)?;
            // The same opened journal FD must still name the final journal
            // before any recovery mutation is attempted.
            self.revalidate_cached_journal(&directory, unit_name)?;

            if snapshot_matches(&target, target_identity, after, after_hash) {
                if !matches!(&staged, StoredUnit::Missing) {
                    if !snapshot_matches(&staged, staged_identity, before, before_hash) {
                        return Err(UnitStoreError::Conflict);
                    }
                    let (StoredUnit::Regular(staged_bytes), Some(staged_identity)) =
                        (&staged, staged_identity)
                    else {
                        return Err(UnitStoreError::Conflict);
                    };
                    Self::remove_exact(
                        &directory,
                        temporary,
                        staged_bytes,
                        staged_identity,
                        "recovery-committed",
                    )?;
                    rustix::fs::fsync(&directory)
                        .map_err(|_| UnitStoreError::CommittedNeedsReload)?;
                }
                return Ok(true);
            }

            if snapshot_matches(&target, target_identity, before, before_hash) {
                if phase == JournalPhase::Forward {
                    self.set_cached_expected_target(unit_name, before, before_hash)?;
                    if !matches!(&staged, StoredUnit::Missing) {
                        if !snapshot_matches(&staged, staged_identity, after, after_hash) {
                            return Err(UnitStoreError::Conflict);
                        }
                        let (StoredUnit::Regular(staged_bytes), Some(staged_identity)) =
                            (&staged, staged_identity)
                        else {
                            return Err(UnitStoreError::Conflict);
                        };
                        Self::remove_exact(
                            &directory,
                            temporary,
                            staged_bytes,
                            staged_identity,
                            "recovery-abort",
                        )?;
                        rustix::fs::fsync(&directory).map_err(|_| UnitStoreError::Io)?;
                    }
                    self.clear_reload_required(unit_name)?;
                    return Ok(false);
                }

                match kind {
                    "replace" => {
                        if !snapshot_matches(&staged, staged_identity, after, after_hash) {
                            return Err(UnitStoreError::CommittedNeedsReload);
                        }
                        let (StoredUnit::Regular(staged_bytes), Some(staged_identity)) =
                            (&staged, staged_identity)
                        else {
                            return Err(UnitStoreError::CommittedNeedsReload);
                        };
                        if before == "missing" {
                            Self::rename_noreplace_exact(
                                &directory,
                                temporary,
                                staged_bytes,
                                staged_identity,
                                unit_name,
                            )?;
                        } else {
                            let (StoredUnit::Regular(target_bytes), Some(target_identity)) =
                                (&target, target_identity)
                            else {
                                return Err(UnitStoreError::Conflict);
                            };
                            Self::exchange_exact(
                                &directory,
                                temporary,
                                staged_bytes,
                                staged_identity,
                                unit_name,
                                target_bytes,
                                target_identity,
                            )?;
                            Self::remove_exact(
                                &directory,
                                temporary,
                                target_bytes,
                                target_identity,
                                "recovery-rollback",
                            )?;
                        }
                    }
                    "remove" => {
                        if !matches!(&staged, StoredUnit::Missing) || after != "missing" {
                            return Err(UnitStoreError::CommittedNeedsReload);
                        }
                        let (StoredUnit::Regular(target_bytes), Some(target_identity)) =
                            (&target, target_identity)
                        else {
                            return Err(UnitStoreError::Conflict);
                        };
                        Self::rename_noreplace_exact(
                            &directory,
                            unit_name,
                            target_bytes,
                            target_identity,
                            temporary,
                        )?;
                        Self::remove_exact(
                            &directory,
                            temporary,
                            target_bytes,
                            target_identity,
                            "recovery-remove",
                        )?;
                    }
                    _ => return Err(UnitStoreError::MalformedJournal),
                }
                rustix::fs::fsync(&directory).map_err(|_| UnitStoreError::CommittedNeedsReload)?;
                return Ok(true);
            }
            Err(UnitStoreError::Conflict)
        }

        fn revalidate_reload_required(&self, unit_name: &str) -> Result<(), UnitStoreError> {
            let directory = self
                .open_user_dir(false)?
                .ok_or(UnitStoreError::RepairRequired)?;
            let snapshots = self
                .journals
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let snapshot = snapshots
                .get(unit_name)
                .ok_or(UnitStoreError::RepairRequired)?;
            if !Self::snapshot_still_named(&directory, unit_name, snapshot)? {
                return Err(UnitStoreError::RepairRequired);
            }
            let (target, target_identity) = Self::inspect_at(&directory, unit_name)?;
            snapshot_matches(
                &target,
                target_identity,
                &snapshot.expected_target_identity,
                &snapshot.expected_target_hash,
            )
            .then_some(())
            .ok_or(UnitStoreError::RepairRequired)
        }

        fn clear_reload_required(&self, unit_name: &str) -> Result<(), UnitStoreError> {
            self.clear_reload_required_with_hook(unit_name, |_, _, _| {})
        }

        fn repair_precommit_journal(
            &self,
            unit_name: &str,
            expected: Option<&[u8]>,
        ) -> Result<(), UnitStoreError> {
            self.repair_precommit_journal_with_hook(unit_name, expected, |_, _, _| {})
        }

        fn atomic_replace(
            &self,
            unit_name: &str,
            expected: Option<&[u8]>,
            contents: &[u8],
            cancellation: &CancellationToken,
        ) -> Result<(), UnitStoreError> {
            if !is_managed_unit_filename(unit_name) || contents.len() > MAX_UNIT_BYTES {
                return Err(UnitStoreError::Unavailable);
            }
            let directory = self
                .open_user_dir(true)?
                .ok_or(UnitStoreError::Unavailable)?;
            let expected_identity = match expected {
                Some(expected) => self
                    .observed
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(unit_name)
                    .filter(|(_, bytes)| bytes == expected)
                    .map(|(identity, _)| *identity)
                    .ok_or(UnitStoreError::Conflict)
                    .map(Some)?,
                None => None,
            };
            let result = self.write_at(
                &directory,
                unit_name,
                expected,
                expected_identity,
                contents,
                cancellation,
            );
            self.observed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(unit_name);
            result
        }

        fn atomic_remove(
            &self,
            unit_name: &str,
            expected: &[u8],
            cancellation: &CancellationToken,
        ) -> Result<(), UnitStoreError> {
            if !is_managed_unit_filename(unit_name) {
                return Err(UnitStoreError::Unavailable);
            }
            if cancellation.is_cancelled() {
                return Err(UnitStoreError::Cancelled);
            }
            let directory = self.open_user_dir(false)?.ok_or(UnitStoreError::Conflict)?;
            let expected_identity = self
                .observed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(unit_name)
                .filter(|(_, bytes)| bytes == expected)
                .map(|(identity, _)| *identity)
                .ok_or(UnitStoreError::Conflict)?;
            let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let tombstone = format!(".{unit_name}.remove.{:x}.{sequence:x}", std::process::id());
            let phase = Self::journal_phase_for_mutation(&directory, unit_name)?;
            let operation = format!(
                "version=1\nunit={unit_name}\noperation={tombstone}\nphase={}\nkind=remove\ntemporary={tombstone}\nbefore={}\nafter=missing\nbefore-hash={}\nafter-hash=missing\nbefore-bytes={}\nafter-bytes=0\n",
                phase.phase.text(),
                identity_text(Some(expected_identity)),
                content_hash(Some(expected)),
                expected.len(),
            );
            let journal =
                Self::publish_journal(&directory, unit_name, phase, operation.as_bytes())?;
            self.remember_journal(unit_name, journal);
            Self::rename_noreplace_exact(
                &directory,
                unit_name,
                expected,
                expected_identity,
                &tombstone,
            )?;
            if Self::remove_exact(
                &directory,
                &tombstone,
                expected,
                expected_identity,
                "remove-committed",
            )
            .is_err()
            {
                return Err(UnitStoreError::CommittedNeedsReload);
            }
            self.observed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(unit_name);
            rustix::fs::fsync(&directory).map_err(|_| UnitStoreError::CommittedNeedsReload)
        }
    }
}

#[cfg(not(unix))]
impl UserUnitStore for SystemUserUnitStore {
    fn lock_unit<'a>(
        &'a self,
        _unit_name: &str,
        _cancellation: &CancellationToken,
        _timeout: Duration,
    ) -> Result<Box<dyn UnitOperationGuard + 'a>, UnitStoreError> {
        Err(UnitStoreError::Unavailable)
    }

    fn inspect(&self, _unit_name: &str) -> Result<StoredUnit, UnitStoreError> {
        Err(UnitStoreError::Unavailable)
    }

    fn reload_required(&self, _unit_name: &str) -> Result<bool, UnitStoreError> {
        Err(UnitStoreError::Unavailable)
    }

    fn revalidate_reload_required(&self, _unit_name: &str) -> Result<(), UnitStoreError> {
        Err(UnitStoreError::Unavailable)
    }

    fn clear_reload_required(&self, _unit_name: &str) -> Result<(), UnitStoreError> {
        Err(UnitStoreError::Unavailable)
    }

    fn repair_precommit_journal(
        &self,
        _unit_name: &str,
        _expected: Option<&[u8]>,
    ) -> Result<(), UnitStoreError> {
        Err(UnitStoreError::Unavailable)
    }

    fn atomic_replace(
        &self,
        _unit_name: &str,
        _expected: Option<&[u8]>,
        _contents: &[u8],
        _cancellation: &CancellationToken,
    ) -> Result<(), UnitStoreError> {
        Err(UnitStoreError::Unavailable)
    }

    fn atomic_remove(
        &self,
        _unit_name: &str,
        _expected: &[u8],
        _cancellation: &CancellationToken,
    ) -> Result<(), UnitStoreError> {
        Err(UnitStoreError::Unavailable)
    }
}

/// Parsed state from `systemctl --user show`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserUnitStatus {
    pub load_state: String,
    pub unit_file_state: String,
    pub active_state: String,
    pub sub_state: String,
    pub fragment_path: Option<PathBuf>,
}

impl UserUnitStatus {
    pub fn is_enabled(&self) -> bool {
        matches!(
            self.unit_file_state.as_str(),
            "enabled" | "enabled-runtime" | "linked" | "linked-runtime" | "alias"
        )
    }
}

/// Transaction result. `Unchanged` means no file or command mutation occurred.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    Changed,
    Unchanged,
}

/// User-unit management failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum UserUnitManagerError {
    #[error(transparent)]
    InvalidUnit(#[from] UserUnitError),
    #[error("systemd user units are unsupported on this platform")]
    UnsupportedPlatform,
    #[error("no systemd user runtime directory is available")]
    UnsupportedSession,
    #[error("no live systemd user manager is available")]
    NotSystemdSession,
    #[error("operation was cancelled")]
    Cancelled,
    #[error("the unit path is a symlink or non-regular file")]
    RefusedPath,
    #[error("the existing unit is not owned by this API")]
    ForeignUnit,
    #[error("the unit already exists")]
    AlreadyExists,
    #[error("the unit is not installed")]
    NotInstalled,
    #[error("the unit changed concurrently; no raced-in file was overwritten")]
    ConcurrentMutation,
    #[error("operation journal is malformed; use the explicit precommit repair API")]
    MalformedJournalNeedsRepair,
    #[error("operation state changed during compensation; explicit repair is required")]
    RepairRequired,
    #[error("unit mutation committed and requires deterministic reload recovery")]
    CommittedNeedsReload,
    #[error("secure unit storage failed")]
    Storage,
    #[error("systemctl failed")]
    Command,
    #[error("systemctl returned malformed status")]
    MalformedStatus,
    #[error("mutation failed and rollback also failed")]
    RollbackFailed,
}

/// Secure systemd `--user` manager with injectable transports.
pub struct UserUnitManager<S = SystemUserUnitStore, C = SystemSystemctlTransport> {
    store: S,
    commands: C,
    session: UserSession,
    timeout: Duration,
}

impl UserUnitManager<SystemUserUnitStore, SystemSystemctlTransport> {
    /// Detect the current Linux user session and XDG configuration directory.
    pub fn detect() -> Result<Self, UserUnitManagerError> {
        Self::detect_with(&SystemEnvironment)
    }

    /// Detect through an injectable environment provider.
    pub fn detect_with(environment: &dyn Environment) -> Result<Self, UserUnitManagerError> {
        let session = UserSession::detect(environment);
        match session {
            UserSession::Supported => {}
            UserSession::UnsupportedPlatform => {
                return Err(UserUnitManagerError::UnsupportedPlatform);
            }
            UserSession::MissingRuntimeDirectory => {
                return Err(UserUnitManagerError::UnsupportedSession);
            }
        }
        let config_home = if let Some(path) = environment.var("XDG_CONFIG_HOME") {
            if path.is_empty() {
                return Err(UserUnitManagerError::UnsupportedSession);
            }
            PathBuf::from(path)
        } else {
            let home = environment
                .var("HOME")
                .filter(|path| !path.is_empty())
                .ok_or(UserUnitManagerError::UnsupportedSession)?;
            PathBuf::from(home).join(".config")
        };
        let store = SystemUserUnitStore::new(config_home)
            .map_err(|_| UserUnitManagerError::UnsupportedSession)?;
        Ok(Self::with_transports(
            store,
            SystemSystemctlTransport,
            session,
            DEFAULT_TIMEOUT,
        ))
    }
}

impl<S: UserUnitStore, C: SystemctlTransport> UserUnitManager<S, C> {
    pub fn with_transports(store: S, commands: C, session: UserSession, timeout: Duration) -> Self {
        Self {
            store,
            commands,
            session,
            timeout: timeout.min(MAX_TIMEOUT),
        }
    }

    pub fn install(
        &self,
        unit: &UserUnit,
        cancellation: &CancellationToken,
    ) -> Result<Change, UserUnitManagerError> {
        let name = unit.unit_name()?;
        let bytes = unit.render()?;
        let unit_lock = process_unit_lock(&name);
        let _unit_guard = unit_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _store_guard = self
            .store
            .lock_unit(&name, cancellation, self.timeout)
            .map_err(map_store_error)?;
        self.ensure_manager(cancellation)?;
        self.recover_pending_reload(&name, cancellation)?;
        match self.checked_unit(&name)? {
            StoredUnit::Missing => self.replace_and_reload(&name, None, &bytes, cancellation),
            StoredUnit::Regular(existing) if existing == bytes => Ok(Change::Unchanged),
            StoredUnit::Regular(_) => Err(UserUnitManagerError::AlreadyExists),
            StoredUnit::Symlink | StoredUnit::Other => Err(UserUnitManagerError::RefusedPath),
        }
    }

    pub fn update(
        &self,
        unit: &UserUnit,
        cancellation: &CancellationToken,
    ) -> Result<Change, UserUnitManagerError> {
        let name = unit.unit_name()?;
        let bytes = unit.render()?;
        let unit_lock = process_unit_lock(&name);
        let _unit_guard = unit_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _store_guard = self
            .store
            .lock_unit(&name, cancellation, self.timeout)
            .map_err(map_store_error)?;
        self.ensure_manager(cancellation)?;
        self.recover_pending_reload(&name, cancellation)?;
        match self.checked_unit(&name)? {
            StoredUnit::Missing => Err(UserUnitManagerError::NotInstalled),
            StoredUnit::Regular(existing) if existing == bytes => Ok(Change::Unchanged),
            StoredUnit::Regular(existing) => {
                self.replace_and_reload(&name, Some(&existing), &bytes, cancellation)
            }
            StoredUnit::Symlink | StoredUnit::Other => Err(UserUnitManagerError::RefusedPath),
        }
    }

    pub fn remove(
        &self,
        name: &str,
        cancellation: &CancellationToken,
    ) -> Result<Change, UserUnitManagerError> {
        validate_name(name)?;
        let unit_name = format!("rustscale-{name}.service");
        let unit_lock = process_unit_lock(&unit_name);
        let _unit_guard = unit_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _store_guard = self
            .store
            .lock_unit(&unit_name, cancellation, self.timeout)
            .map_err(map_store_error)?;
        self.ensure_manager(cancellation)?;
        self.recover_pending_reload(&unit_name, cancellation)?;
        let existing = match self.checked_unit(&unit_name)? {
            StoredUnit::Missing => {
                // Clean stale wants links even when the fragment disappeared.
                self.disable_all(&unit_name, cancellation)?;
                return Ok(Change::Unchanged);
            }
            StoredUnit::Regular(existing) => existing,
            StoredUnit::Symlink | StoredUnit::Other => {
                return Err(UserUnitManagerError::RefusedPath);
            }
        };
        let enablement = self.query_status(&unit_name, cancellation)?;
        let enablement_changed =
            self.set_enabled_locked(&unit_name, &enablement, false, cancellation)?
                == Change::Changed;
        let remove_error = match self
            .store
            .atomic_remove(&unit_name, &existing, cancellation)
        {
            Ok(()) | Err(UnitStoreError::CommittedNeedsReload) => None,
            Err(error) => Some(error),
        };
        if let Some(error) = remove_error {
            if enablement_changed && self.restore_enablement(&unit_name, &enablement).is_err() {
                return Err(UserUnitManagerError::RollbackFailed);
            }
            return Err(map_store_error(error));
        }
        if !matches!(self.checked_unit(&unit_name), Ok(StoredUnit::Missing)) {
            // Preserve the operation journal and do not reload a raced-in file.
            if enablement_changed && self.restore_enablement(&unit_name, &enablement).is_err() {
                return Err(UserUnitManagerError::RollbackFailed);
            }
            return Err(UserUnitManagerError::CommittedNeedsReload);
        }
        let finish = self
            .reload_validated(&unit_name, cancellation)
            .and_then(|()| {
                self.store
                    .clear_reload_required(&unit_name)
                    .map_err(map_store_error)
            });
        if let Err(original) = finish {
            if matches!(
                original,
                UserUnitManagerError::RepairRequired
                    | UserUnitManagerError::MalformedJournalNeedsRepair
            ) {
                return Err(original);
            }
            let rollback = CancellationToken::new();
            let restored = self
                .store
                .atomic_replace(&unit_name, None, &existing, &rollback);
            if !matches!(restored, Ok(()) | Err(UnitStoreError::CommittedNeedsReload))
                || !matches!(
                    self.checked_unit(&unit_name),
                    Ok(StoredUnit::Regular(actual)) if actual == existing
                )
                || self.reload_validated(&unit_name, &rollback).is_err()
                || self.store.clear_reload_required(&unit_name).is_err()
                || (enablement_changed && self.restore_enablement(&unit_name, &enablement).is_err())
            {
                return Err(UserUnitManagerError::RollbackFailed);
            }
            return Err(original);
        }
        Ok(Change::Changed)
    }

    pub fn enable(
        &self,
        name: &str,
        cancellation: &CancellationToken,
    ) -> Result<Change, UserUnitManagerError> {
        self.set_enabled(name, true, cancellation)
    }

    pub fn disable(
        &self,
        name: &str,
        cancellation: &CancellationToken,
    ) -> Result<Change, UserUnitManagerError> {
        self.set_enabled(name, false, cancellation)
    }

    /// Explicitly clear a malformed final journal after attesting the exact
    /// precommit destination. `None` attests that the unit was absent; `Some`
    /// must render to the currently installed unit. No reload is performed.
    pub fn repair_precommit_journal(
        &self,
        name: &str,
        expected: Option<&UserUnit>,
        cancellation: &CancellationToken,
    ) -> Result<(), UserUnitManagerError> {
        validate_name(name)?;
        let unit_name = format!("rustscale-{name}.service");
        let expected_bytes = match expected {
            Some(expected) if expected.unit_name()? == unit_name => Some(expected.render()?),
            Some(_) => return Err(UserUnitError::InvalidName("repair unit name mismatch").into()),
            None => None,
        };
        let unit_lock = process_unit_lock(&unit_name);
        let _unit_guard = unit_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _store_guard = self
            .store
            .lock_unit(&unit_name, cancellation, self.timeout)
            .map_err(map_store_error)?;
        self.ensure_manager(cancellation)?;
        let current = self.store.inspect(&unit_name).map_err(map_store_error)?;
        match (&expected_bytes, current) {
            (None, StoredUnit::Missing) => {}
            (Some(expected), StoredUnit::Regular(actual)) if *expected == actual => {}
            _ => return Err(UserUnitManagerError::ConcurrentMutation),
        }
        self.store
            .repair_precommit_journal(&unit_name, expected_bytes.as_deref())
            .map_err(map_store_error)
    }

    pub fn status(
        &self,
        name: &str,
        cancellation: &CancellationToken,
    ) -> Result<UserUnitStatus, UserUnitManagerError> {
        validate_name(name)?;
        let unit_name = format!("rustscale-{name}.service");
        let unit_lock = process_unit_lock(&unit_name);
        let _unit_guard = unit_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _store_guard = self
            .store
            .lock_unit(&unit_name, cancellation, self.timeout)
            .map_err(map_store_error)?;
        self.status_locked(&unit_name, cancellation)
    }

    fn status_locked(
        &self,
        unit_name: &str,
        cancellation: &CancellationToken,
    ) -> Result<UserUnitStatus, UserUnitManagerError> {
        self.ensure_manager(cancellation)?;
        self.recover_pending_reload(unit_name, cancellation)?;
        match self.checked_unit(unit_name)? {
            StoredUnit::Regular(_) => {}
            StoredUnit::Missing => return Err(UserUnitManagerError::NotInstalled),
            StoredUnit::Symlink | StoredUnit::Other => {
                return Err(UserUnitManagerError::RefusedPath);
            }
        }
        self.query_status(unit_name, cancellation)
    }

    fn query_status(
        &self,
        unit_name: &str,
        cancellation: &CancellationToken,
    ) -> Result<UserUnitStatus, UserUnitManagerError> {
        let output = self.command(
            vec![
                "--user".into(),
                "show".into(),
                "--no-pager".into(),
                "--property=LoadState,UnitFileState,ActiveState,SubState,FragmentPath".into(),
                unit_name.to_owned(),
            ],
            cancellation,
        )?;
        if !output.success {
            return Err(UserUnitManagerError::Command);
        }
        parse_status(&output.stdout)
    }

    fn set_enabled(
        &self,
        name: &str,
        enabled: bool,
        cancellation: &CancellationToken,
    ) -> Result<Change, UserUnitManagerError> {
        validate_name(name)?;
        let unit_name = format!("rustscale-{name}.service");
        let unit_lock = process_unit_lock(&unit_name);
        let _unit_guard = unit_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _store_guard = self
            .store
            .lock_unit(&unit_name, cancellation, self.timeout)
            .map_err(map_store_error)?;
        let status = self.status_locked(&unit_name, cancellation)?;
        self.set_enabled_locked(&unit_name, &status, enabled, cancellation)
    }

    fn set_enabled_locked(
        &self,
        unit_name: &str,
        before: &UserUnitStatus,
        enabled: bool,
        cancellation: &CancellationToken,
    ) -> Result<Change, UserUnitManagerError> {
        let already_desired = if enabled {
            before.is_enabled()
        } else {
            before.unit_file_state == "disabled"
        };
        if already_desired {
            return Ok(Change::Unchanged);
        }
        if !matches!(
            before.unit_file_state.as_str(),
            "disabled"
                | "enabled"
                | "enabled-runtime"
                | "linked"
                | "linked-runtime"
                | "masked"
                | "masked-runtime"
        ) {
            // Alias/static/generated states cannot be recreated by this narrow
            // API, so refuse before mutating them.
            return Err(UserUnitManagerError::Command);
        }
        let mutation = if enabled {
            self.command_success(
                vec![
                    "--user".into(),
                    "enable".into(),
                    "--".into(),
                    unit_name.to_owned(),
                ],
                cancellation,
            )
        } else {
            self.disable_all(unit_name, cancellation)
        };
        let expected_state = if enabled { "enabled" } else { "disabled" };
        let postcondition = mutation.is_ok()
            && self
                .query_status(unit_name, cancellation)
                .is_ok_and(|status| {
                    status.unit_file_state == expected_state
                        && status.fragment_path == before.fragment_path
                });
        if postcondition {
            return Ok(Change::Changed);
        }
        if self.restore_enablement(unit_name, before).is_err() {
            return Err(UserUnitManagerError::RollbackFailed);
        }
        match mutation {
            Err(error) => Err(error),
            Ok(()) => Err(UserUnitManagerError::Command),
        }
    }

    fn restore_enablement(
        &self,
        unit_name: &str,
        snapshot: &UserUnitStatus,
    ) -> Result<(), UserUnitManagerError> {
        let rollback = CancellationToken::new();
        if self
            .query_status(unit_name, &rollback)
            .is_ok_and(|current| enablement_matches(&current, snapshot))
        {
            return Ok(());
        }
        self.disable_all(unit_name, &rollback)?;
        let mut command = vec!["--user".into()];
        match snapshot.unit_file_state.as_str() {
            "disabled" => {}
            "enabled" => command.push("enable".into()),
            "enabled-runtime" => {
                command.push("enable".into());
                command.push("--runtime".into());
            }
            "linked" | "linked-runtime" => {
                command.push("link".into());
                if snapshot.unit_file_state == "linked-runtime" {
                    command.push("--runtime".into());
                }
                let fragment = snapshot
                    .fragment_path
                    .as_ref()
                    .ok_or(UserUnitManagerError::RollbackFailed)?;
                command.push("--".into());
                command.push(fragment.to_string_lossy().into_owned());
            }
            "masked" | "masked-runtime" => {
                command.push("mask".into());
                if snapshot.unit_file_state == "masked-runtime" {
                    command.push("--runtime".into());
                }
            }
            _ => return Err(UserUnitManagerError::RollbackFailed),
        }
        if snapshot.unit_file_state != "disabled" {
            if !matches!(
                snapshot.unit_file_state.as_str(),
                "linked" | "linked-runtime"
            ) {
                command.push("--".into());
                command.push(unit_name.to_owned());
            }
            self.command_success(command, &rollback)?;
        }
        let restored = self.query_status(unit_name, &rollback)?;
        enablement_matches(&restored, snapshot)
            .then_some(())
            .ok_or(UserUnitManagerError::RollbackFailed)
    }

    fn disable_all(
        &self,
        unit_name: &str,
        cancellation: &CancellationToken,
    ) -> Result<(), UserUnitManagerError> {
        self.command_success(
            vec![
                "--user".into(),
                "disable".into(),
                "--".into(),
                unit_name.to_owned(),
            ],
            cancellation,
        )?;
        self.command_success(
            vec![
                "--user".into(),
                "disable".into(),
                "--runtime".into(),
                "--".into(),
                unit_name.to_owned(),
            ],
            cancellation,
        )
    }

    fn command_success(
        &self,
        arguments: Vec<String>,
        cancellation: &CancellationToken,
    ) -> Result<(), UserUnitManagerError> {
        let output = self.command(arguments, cancellation)?;
        output
            .success
            .then_some(())
            .ok_or(UserUnitManagerError::Command)
    }

    fn checked_unit(&self, name: &str) -> Result<StoredUnit, UserUnitManagerError> {
        let stored = self.store.inspect(name).map_err(map_store_error)?;
        if let StoredUnit::Regular(bytes) = &stored {
            if !is_exact_generated_unit(name, bytes) {
                return Err(UserUnitManagerError::ForeignUnit);
            }
        }
        Ok(stored)
    }

    fn replace_and_reload(
        &self,
        name: &str,
        previous: Option<&[u8]>,
        bytes: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<Change, UserUnitManagerError> {
        match self
            .store
            .atomic_replace(name, previous, bytes, cancellation)
        {
            Ok(()) | Err(UnitStoreError::CommittedNeedsReload) => {}
            Err(error) => return Err(map_store_error(error)),
        }
        if !matches!(
            self.checked_unit(name),
            Ok(StoredUnit::Regular(actual)) if actual == bytes
        ) {
            // The committed journal remains for deterministic recovery; never
            // reload a destination that is not exactly what we generated.
            return Err(UserUnitManagerError::CommittedNeedsReload);
        }
        if cancellation.is_cancelled() {
            return self.rollback_file(name, bytes, previous, UserUnitManagerError::Cancelled);
        }
        if let Err(error) = self.reload_validated(name, cancellation) {
            if matches!(
                error,
                UserUnitManagerError::RepairRequired
                    | UserUnitManagerError::MalformedJournalNeedsRepair
            ) {
                return Err(error);
            }
            return self.rollback_file(name, bytes, previous, error);
        }
        self.store
            .clear_reload_required(name)
            .map_err(map_store_error)?;
        Ok(Change::Changed)
    }

    fn rollback_file(
        &self,
        name: &str,
        current: &[u8],
        previous: Option<&[u8]>,
        original: UserUnitManagerError,
    ) -> Result<Change, UserUnitManagerError> {
        let rollback_token = CancellationToken::new();
        if !matches!(
            self.checked_unit(name),
            Ok(StoredUnit::Regular(actual)) if actual == current
        ) {
            return Err(UserUnitManagerError::RollbackFailed);
        }
        let restored = match previous {
            Some(previous) => {
                self.store
                    .atomic_replace(name, Some(current), previous, &rollback_token)
            }
            None => self.store.atomic_remove(name, current, &rollback_token),
        };
        let restored_exactly = match previous {
            Some(previous) => matches!(
                self.checked_unit(name),
                Ok(StoredUnit::Regular(actual)) if actual == previous
            ),
            None => matches!(self.checked_unit(name), Ok(StoredUnit::Missing)),
        };
        if !matches!(restored, Ok(()) | Err(UnitStoreError::CommittedNeedsReload))
            || !restored_exactly
            || self.reload_validated(name, &rollback_token).is_err()
            || self.store.clear_reload_required(name).is_err()
        {
            Err(UserUnitManagerError::RollbackFailed)
        } else {
            Err(original)
        }
    }

    fn recover_pending_reload(
        &self,
        name: &str,
        cancellation: &CancellationToken,
    ) -> Result<(), UserUnitManagerError> {
        match self.store.reload_required(name) {
            Ok(false) => return Ok(()),
            Ok(true) | Err(UnitStoreError::CommittedNeedsReload) => {}
            Err(error) => return Err(map_store_error(error)),
        }
        match self.checked_unit(name)? {
            StoredUnit::Missing | StoredUnit::Regular(_) => {}
            StoredUnit::Symlink | StoredUnit::Other => {
                return Err(UserUnitManagerError::CommittedNeedsReload);
            }
        }
        self.reload_validated(name, cancellation)?;
        self.store
            .clear_reload_required(name)
            .map_err(map_store_error)
    }

    fn reload_validated(
        &self,
        name: &str,
        cancellation: &CancellationToken,
    ) -> Result<(), UserUnitManagerError> {
        self.store
            .revalidate_reload_required(name)
            .map_err(map_store_error)?;
        self.reload(cancellation)
    }

    fn reload(&self, cancellation: &CancellationToken) -> Result<(), UserUnitManagerError> {
        let output = self.command(vec!["--user".into(), "daemon-reload".into()], cancellation)?;
        if output.success {
            Ok(())
        } else {
            Err(UserUnitManagerError::Command)
        }
    }

    fn ensure_manager(&self, cancellation: &CancellationToken) -> Result<(), UserUnitManagerError> {
        match self.session {
            UserSession::Supported => {}
            UserSession::UnsupportedPlatform => {
                return Err(UserUnitManagerError::UnsupportedPlatform);
            }
            UserSession::MissingRuntimeDirectory => {
                return Err(UserUnitManagerError::UnsupportedSession);
            }
        }
        if cancellation.is_cancelled() {
            return Err(UserUnitManagerError::Cancelled);
        }
        let output = self.commands.run(
            &SystemctlCommand {
                program: SYSTEMCTL_PROGRAM.into(),
                arguments: vec![
                    "--user".into(),
                    "show".into(),
                    "--no-pager".into(),
                    "--property=Version".into(),
                    "--value".into(),
                ],
                timeout: self.timeout,
                max_output: 64,
            },
            cancellation,
        );
        match output {
            Ok(output)
                if output.success
                    && !output.stdout.is_empty()
                    && output.stdout.len() <= 64
                    && output.stdout.iter().all(|byte| {
                        byte.is_ascii_digit() || matches!(byte, b'.' | b'~' | b'-' | b'\n')
                    }) =>
            {
                Ok(())
            }
            Ok(_) | Err(SystemctlError::Unavailable) => {
                Err(UserUnitManagerError::NotSystemdSession)
            }
            Err(error) => Err(map_command_error(error)),
        }
    }

    fn command(
        &self,
        arguments: Vec<String>,
        cancellation: &CancellationToken,
    ) -> Result<SystemctlOutput, UserUnitManagerError> {
        if cancellation.is_cancelled() {
            return Err(UserUnitManagerError::Cancelled);
        }
        self.commands
            .run(
                &SystemctlCommand {
                    program: SYSTEMCTL_PROGRAM.into(),
                    arguments,
                    timeout: self.timeout,
                    max_output: MAX_OUTPUT_BYTES,
                },
                cancellation,
            )
            .map_err(map_command_error)
    }
}

fn is_exact_generated_unit(unit_name: &str, bytes: &[u8]) -> bool {
    let Some(name) = unit_name
        .strip_prefix("rustscale-")
        .and_then(|name| name.strip_suffix(".service"))
    else {
        return false;
    };
    let prefix = format!(
        "{MANAGED_HEADER}\n# Unit: {unit_name}\n[Unit]\nDescription=RustScale user service ({name})\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart="
    );
    let suffix = "\nRestart=on-failure\nRestartSec=5s\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=read-only\n\n[Install]\nWantedBy=default.target\n";
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let Some(exec) = text
        .strip_prefix(&prefix)
        .and_then(|text| text.strip_suffix(suffix))
    else {
        return false;
    };
    let Some(words) = decode_generated_exec(exec) else {
        return false;
    };
    let Some((executable, arguments)) = words.split_first() else {
        return false;
    };
    let unit = UserUnit {
        name: name.to_owned(),
        executable: PathBuf::from(executable),
        arguments: arguments.to_vec(),
    };
    unit.render().is_ok_and(|rendered| rendered == bytes)
}

fn decode_generated_exec(mut input: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    while !input.is_empty() {
        input = input.strip_prefix('"')?;
        let mut word = String::new();
        let mut escaped = false;
        let mut closed_at = None;
        for (index, character) in input.char_indices() {
            if escaped {
                if !matches!(character, '"' | '\\') {
                    return None;
                }
                word.push(character);
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                closed_at = Some(index + character.len_utf8());
                break;
            } else {
                word.push(character);
            }
        }
        let closed_at = closed_at?;
        words.push(word);
        input = &input[closed_at..];
        if input.is_empty() {
            break;
        }
        input = input.strip_prefix(' ')?;
        if input.is_empty() {
            return None;
        }
    }
    Some(words)
}

fn enablement_matches(current: &UserUnitStatus, expected: &UserUnitStatus) -> bool {
    current.unit_file_state == expected.unit_file_state
        && current.fragment_path == expected.fragment_path
}

fn map_store_error(error: UnitStoreError) -> UserUnitManagerError {
    match error {
        UnitStoreError::Cancelled => UserUnitManagerError::Cancelled,
        UnitStoreError::CommittedNeedsReload => UserUnitManagerError::CommittedNeedsReload,
        UnitStoreError::Conflict => UserUnitManagerError::ConcurrentMutation,
        UnitStoreError::MalformedJournal => UserUnitManagerError::MalformedJournalNeedsRepair,
        UnitStoreError::RepairRequired => UserUnitManagerError::RepairRequired,
        UnitStoreError::Unavailable
        | UnitStoreError::InsecurePermissions
        | UnitStoreError::WrongOwner
        | UnitStoreError::Io => UserUnitManagerError::Storage,
    }
}

fn map_command_error(error: SystemctlError) -> UserUnitManagerError {
    match error {
        SystemctlError::Cancelled => UserUnitManagerError::Cancelled,
        SystemctlError::Unavailable
        | SystemctlError::TimedOut
        | SystemctlError::OutputTooLarge
        | SystemctlError::Io => UserUnitManagerError::Command,
    }
}

fn parse_status(bytes: &[u8]) -> Result<UserUnitStatus, UserUnitManagerError> {
    if bytes.is_empty() || bytes.len() > MAX_OUTPUT_BYTES {
        return Err(UserUnitManagerError::MalformedStatus);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| UserUnitManagerError::MalformedStatus)?;
    let mut load_state = None;
    let mut unit_file_state = None;
    let mut active_state = None;
    let mut sub_state = None;
    let mut fragment_path = None;
    let mut saw_fragment_path = false;
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err(UserUnitManagerError::MalformedStatus);
        };
        if key == "FragmentPath" {
            if saw_fragment_path || value.len() > MAX_EXECUTABLE_BYTES || value.contains('\0') {
                return Err(UserUnitManagerError::MalformedStatus);
            }
            saw_fragment_path = true;
            if !value.is_empty() {
                let path = PathBuf::from(value);
                if !path.is_absolute()
                    || path
                        .components()
                        .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
                {
                    return Err(UserUnitManagerError::MalformedStatus);
                }
                fragment_path = Some(path);
            }
            continue;
        }
        if value.is_empty()
            || value.len() > 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(UserUnitManagerError::MalformedStatus);
        }
        let slot = match key {
            "LoadState" => &mut load_state,
            "UnitFileState" => &mut unit_file_state,
            "ActiveState" => &mut active_state,
            "SubState" => &mut sub_state,
            _ => return Err(UserUnitManagerError::MalformedStatus),
        };
        if slot.replace(value.to_owned()).is_some() {
            return Err(UserUnitManagerError::MalformedStatus);
        }
    }
    Ok(UserUnitStatus {
        load_state: load_state.ok_or(UserUnitManagerError::MalformedStatus)?,
        unit_file_state: unit_file_state.ok_or(UserUnitManagerError::MalformedStatus)?,
        active_state: active_state.ok_or(UserUnitManagerError::MalformedStatus)?,
        sub_state: sub_state.ok_or(UserUnitManagerError::MalformedStatus)?,
        fragment_path: saw_fragment_path
            .then_some(fragment_path)
            .ok_or(UserUnitManagerError::MalformedStatus)?,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Mutex;
    use std::thread;

    use super::*;

    #[derive(Default)]
    struct MemoryStore {
        value: Mutex<StoredUnit>,
        cancel_after_write: AtomicBool,
        fail_rollback: AtomicBool,
        replace_calls: AtomicUsize,
        reload_required: AtomicBool,
        commit_needs_reload: AtomicBool,
        fail_clear_once: AtomicBool,
        fail_recovery_before_mutation_once: AtomicBool,
        fail_revalidate_once: AtomicBool,
        substitute_clear_once: AtomicBool,
    }

    impl MemoryStore {
        fn with(value: StoredUnit) -> Self {
            Self {
                value: Mutex::new(value),
                ..Self::default()
            }
        }

        fn value(&self) -> StoredUnit {
            self.value.lock().unwrap().clone()
        }
    }

    impl UserUnitStore for &MemoryStore {
        fn lock_unit<'a>(
            &'a self,
            _unit_name: &str,
            _cancellation: &CancellationToken,
            _timeout: Duration,
        ) -> Result<Box<dyn UnitOperationGuard + 'a>, UnitStoreError> {
            Ok(Box::new(()))
        }

        fn inspect(&self, _unit_name: &str) -> Result<StoredUnit, UnitStoreError> {
            Ok(self.value())
        }

        fn reload_required(&self, _unit_name: &str) -> Result<bool, UnitStoreError> {
            if self
                .fail_recovery_before_mutation_once
                .swap(false, Ordering::AcqRel)
            {
                return Err(UnitStoreError::RepairRequired);
            }
            Ok(self.reload_required.load(Ordering::Acquire))
        }

        fn revalidate_reload_required(&self, _unit_name: &str) -> Result<(), UnitStoreError> {
            if self.fail_revalidate_once.swap(false, Ordering::AcqRel) {
                return Err(UnitStoreError::RepairRequired);
            }
            Ok(())
        }

        fn clear_reload_required(&self, _unit_name: &str) -> Result<(), UnitStoreError> {
            if self.substitute_clear_once.swap(false, Ordering::AcqRel) {
                return Err(UnitStoreError::RepairRequired);
            }
            if self.fail_clear_once.swap(false, Ordering::AcqRel) {
                return Err(UnitStoreError::CommittedNeedsReload);
            }
            self.reload_required.store(false, Ordering::Release);
            Ok(())
        }

        fn repair_precommit_journal(
            &self,
            _unit_name: &str,
            _expected: Option<&[u8]>,
        ) -> Result<(), UnitStoreError> {
            self.reload_required.store(false, Ordering::Release);
            Ok(())
        }

        fn atomic_replace(
            &self,
            _unit_name: &str,
            expected: Option<&[u8]>,
            contents: &[u8],
            cancellation: &CancellationToken,
        ) -> Result<(), UnitStoreError> {
            let mut value = self.value.lock().unwrap();
            let matches = match (expected, &*value) {
                (None, StoredUnit::Missing) => true,
                (Some(expected), StoredUnit::Regular(actual)) => expected == actual,
                _ => false,
            };
            if !matches {
                return Err(UnitStoreError::Conflict);
            }
            let call = self.replace_calls.fetch_add(1, Ordering::AcqRel) + 1;
            if self.fail_rollback.load(Ordering::Acquire) && call > 1 {
                return Err(UnitStoreError::Io);
            }
            *value = StoredUnit::Regular(contents.to_vec());
            self.reload_required.store(true, Ordering::Release);
            if self.cancel_after_write.load(Ordering::Acquire) && call == 1 {
                cancellation.cancel();
            }
            if self.commit_needs_reload.load(Ordering::Acquire) {
                Err(UnitStoreError::CommittedNeedsReload)
            } else {
                Ok(())
            }
        }

        fn atomic_remove(
            &self,
            _unit_name: &str,
            expected: &[u8],
            _cancellation: &CancellationToken,
        ) -> Result<(), UnitStoreError> {
            let mut value = self.value.lock().unwrap();
            if !matches!(&*value, StoredUnit::Regular(actual) if actual == expected) {
                return Err(UnitStoreError::Conflict);
            }
            *value = StoredUnit::Missing;
            self.reload_required.store(true, Ordering::Release);
            if self.commit_needs_reload.load(Ordering::Acquire) {
                Err(UnitStoreError::CommittedNeedsReload)
            } else {
                Ok(())
            }
        }
    }

    #[derive(Default)]
    struct FakeCommands {
        commands: Mutex<Vec<SystemctlCommand>>,
        outputs: Mutex<VecDeque<Result<SystemctlOutput, SystemctlError>>>,
    }

    impl FakeCommands {
        fn with(outputs: Vec<Result<SystemctlOutput, SystemctlError>>) -> Self {
            Self {
                commands: Mutex::new(Vec::new()),
                outputs: Mutex::new(outputs.into()),
            }
        }

        fn commands(&self) -> Vec<SystemctlCommand> {
            self.commands.lock().unwrap().clone()
        }
    }

    impl SystemctlTransport for &FakeCommands {
        fn run(
            &self,
            command: &SystemctlCommand,
            _cancellation: &CancellationToken,
        ) -> Result<SystemctlOutput, SystemctlError> {
            self.commands.lock().unwrap().push(command.clone());
            self.outputs.lock().unwrap().pop_front().unwrap_or_else(|| {
                Ok(SystemctlOutput {
                    success: true,
                    stdout: b"252\n".to_vec(),
                })
            })
        }
    }

    #[derive(Default)]
    struct BlockingCommands {
        active: AtomicUsize,
        maximum: AtomicUsize,
    }

    impl SystemctlTransport for &BlockingCommands {
        fn run(
            &self,
            _command: &SystemctlCommand,
            _cancellation: &CancellationToken,
        ) -> Result<SystemctlOutput, SystemctlError> {
            let active = self.active.fetch_add(1, Ordering::AcqRel) + 1;
            self.maximum.fetch_max(active, Ordering::AcqRel);
            thread::sleep(Duration::from_millis(30));
            self.active.fetch_sub(1, Ordering::AcqRel);
            Ok(SystemctlOutput {
                success: true,
                stdout: b"252\n".to_vec(),
            })
        }
    }

    fn ok(stdout: &[u8]) -> Result<SystemctlOutput, SystemctlError> {
        Ok(SystemctlOutput {
            success: true,
            stdout: stdout.to_vec(),
        })
    }

    fn failed() -> Result<SystemctlOutput, SystemctlError> {
        Ok(SystemctlOutput {
            success: false,
            stdout: Vec::new(),
        })
    }

    fn status(state: &str) -> Vec<u8> {
        format!(
            "LoadState=loaded\nUnitFileState={state}\nActiveState=inactive\nSubState=dead\nFragmentPath=/home/user/.config/systemd/user/rustscale-tray.service\n"
        )
        .into_bytes()
    }

    fn unit(arguments: &[&str]) -> UserUnit {
        UserUnit {
            name: "tray".into(),
            executable: "/opt/rustscale/bin/rustscale".into(),
            arguments: arguments.iter().map(|value| (*value).to_owned()).collect(),
        }
    }

    fn manager<'a>(
        store: &'a MemoryStore,
        commands: &'a FakeCommands,
    ) -> UserUnitManager<&'a MemoryStore, &'a FakeCommands> {
        UserUnitManager::with_transports(
            store,
            commands,
            UserSession::Supported,
            Duration::from_secs(2),
        )
    }

    #[test]
    fn unit_bytes_are_deterministic_and_shell_free() {
        let unit = unit(&["tray", "--socket=/home/me/a b;touch-pwned"]);
        let first = unit.render().unwrap();
        assert_eq!(first, unit.render().unwrap());
        assert!(is_exact_generated_unit("rustscale-tray.service", &first));
        let text = String::from_utf8(first).unwrap();
        assert!(text.starts_with(MANAGED_HEADER));
        assert!(text.contains(
            "ExecStart=\"/opt/rustscale/bin/rustscale\" \"tray\" \"--socket=/home/me/a b;touch-pwned\"\n"
        ));
        assert!(!text.contains("Environment="));
        assert!(!text.contains("sh -c"));
    }

    #[test]
    fn rejects_names_expansion_environment_and_credentials() {
        for name in ["", "UPPER", "../x", "x.service", "x@y"] {
            let mut candidate = unit(&[]);
            candidate.name = name.into();
            assert!(candidate.render().is_err(), "accepted name {name:?}");
        }
        for argument in [
            "$HOME",
            "%h",
            "AUTH_KEY=value",
            "--auth-key=secret",
            "--password",
            "https://user:pass@example.test/path",
            "line\nfeed",
        ] {
            assert!(unit(&[argument]).render().is_err(), "accepted {argument:?}");
        }
        let mut relative = unit(&[]);
        relative.executable = "rustscale".into();
        assert!(relative.render().is_err());
        let mut arbitrary = unit(&[]);
        arbitrary.executable = "/bin/echo".into();
        assert!(arbitrary.render().is_err());
        let mut sensitive_path = unit(&[]);
        sensitive_path.executable = "/private/token/rustscale".into();
        assert!(sensitive_path.render().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn journal_write_faults_at_every_byte_leave_only_partial_staging() {
        use std::io::{self, Write};

        struct FailAfter {
            limit: usize,
            bytes: Vec<u8>,
        }

        impl Write for FailAfter {
            fn write(&mut self, input: &[u8]) -> io::Result<usize> {
                if self.bytes.len() == self.limit {
                    return Err(io::Error::other("injected write fault"));
                }
                let count = input.len().min(self.limit - self.bytes.len());
                self.bytes.extend_from_slice(&input[..count]);
                Ok(count)
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let record = b"version=1\nunit=rustscale-tray.service\nphase=forward\n";
        for limit in 0..record.len() {
            let mut writer = FailAfter {
                limit,
                bytes: Vec::new(),
            };
            assert!(unix_store::write_journal_bytes(&mut writer, record).is_err());
            assert_eq!(writer.bytes, record[..limit]);
        }
        let mut complete = FailAfter {
            limit: record.len(),
            bytes: Vec::new(),
        };
        unix_store::write_journal_bytes(&mut complete, record).unwrap();
        assert_eq!(complete.bytes, record);
    }

    #[test]
    fn symlink_and_foreign_files_are_refused_without_commands() {
        for stored in [
            StoredUnit::Symlink,
            StoredUnit::Other,
            StoredUnit::Regular(b"[Service]\nExecStart=/bin/false\n".to_vec()),
            StoredUnit::Regular(
                format!(
                    "{MANAGED_HEADER}\n# Unit: rustscale-tray.service\n[Service]\nExecStart=\"/bin/false\"\n"
                )
                .into_bytes(),
            ),
        ] {
            let store = MemoryStore::with(stored);
            let commands = FakeCommands::default();
            let error = manager(&store, &commands)
                .install(&unit(&[]), &CancellationToken::new())
                .unwrap_err();
            assert!(matches!(
                error,
                UserUnitManagerError::RefusedPath | UserUnitManagerError::ForeignUnit
            ));
            // The support probe occurs before filesystem mutation.
            assert_eq!(commands.commands().len(), 1);
        }
    }

    #[test]
    fn install_and_update_are_idempotent() {
        let store = MemoryStore::default();
        let commands = FakeCommands::default();
        let manager = manager(&store, &commands);
        assert_eq!(
            manager.install(&unit(&["tray"]), &CancellationToken::new()),
            Ok(Change::Changed)
        );
        assert_eq!(
            manager.install(&unit(&["tray"]), &CancellationToken::new()),
            Ok(Change::Unchanged)
        );
        assert_eq!(
            manager.update(&unit(&["tray"]), &CancellationToken::new()),
            Ok(Change::Unchanged)
        );
        assert_eq!(
            manager.update(&unit(&["web"]), &CancellationToken::new()),
            Ok(Change::Changed)
        );
        let reloads = commands
            .commands()
            .iter()
            .filter(|command| command.arguments == ["--user", "daemon-reload"])
            .count();
        assert_eq!(reloads, 2);
    }

    #[test]
    fn managers_serialize_the_same_unit_process_wide() {
        let store = MemoryStore::default();
        let commands = BlockingCommands::default();
        thread::scope(|scope| {
            for _ in 0..2 {
                scope.spawn(|| {
                    UserUnitManager::with_transports(
                        &store,
                        &commands,
                        UserSession::Supported,
                        Duration::from_secs(2),
                    )
                    .install(&unit(&[]), &CancellationToken::new())
                    .unwrap();
                });
            }
        });
        assert_eq!(commands.maximum.load(Ordering::Acquire), 1);
    }

    #[cfg(unix)]
    #[test]
    fn independent_stores_serialize_with_durable_advisory_lock() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
        let config = temporary.path().join("config");
        let first = SystemUserUnitStore::new(&config).unwrap();
        let second = SystemUserUnitStore::new(&config).unwrap();
        let cancellation = CancellationToken::new();
        let held = first
            .lock_unit(
                "rustscale-tray.service",
                &cancellation,
                Duration::from_secs(2),
            )
            .unwrap();
        let acquired = Arc::new(AtomicBool::new(false));
        let acquired_in_thread = acquired.clone();
        let thread = thread::spawn(move || {
            let cancellation = CancellationToken::new();
            let _guard = second
                .lock_unit(
                    "rustscale-tray.service",
                    &cancellation,
                    Duration::from_secs(2),
                )
                .unwrap();
            acquired_in_thread.store(true, Ordering::Release);
        });
        thread::sleep(Duration::from_millis(80));
        assert!(!acquired.load(Ordering::Acquire));
        drop(held);
        thread.join().unwrap();
        assert!(acquired.load(Ordering::Acquire));
        assert_eq!(
            std::fs::metadata(first.unit_directory().join(".rustscale-tray.service.lock"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn interrupted_update_does_not_publish() {
        let old = unit(&["old"]).render().unwrap();
        let store = MemoryStore::with(StoredUnit::Regular(old.clone()));
        store.cancel_after_write.store(true, Ordering::Release);
        let commands = FakeCommands::default();
        let error = manager(&store, &commands)
            .update(&unit(&["new"]), &CancellationToken::new())
            .unwrap_err();
        assert_eq!(error, UserUnitManagerError::Cancelled);
        assert_eq!(store.value(), StoredUnit::Regular(old));
    }

    #[test]
    fn concurrent_foreign_replacement_is_not_clobbered_or_rolled_back() {
        struct RacingStore {
            value: Mutex<StoredUnit>,
            foreign: Vec<u8>,
        }

        impl UserUnitStore for &RacingStore {
            fn lock_unit<'a>(
                &'a self,
                _unit_name: &str,
                _cancellation: &CancellationToken,
                _timeout: Duration,
            ) -> Result<Box<dyn UnitOperationGuard + 'a>, UnitStoreError> {
                Ok(Box::new(()))
            }

            fn inspect(&self, _unit_name: &str) -> Result<StoredUnit, UnitStoreError> {
                Ok(self.value.lock().unwrap().clone())
            }

            fn reload_required(&self, _unit_name: &str) -> Result<bool, UnitStoreError> {
                Ok(false)
            }

            fn revalidate_reload_required(&self, _unit_name: &str) -> Result<(), UnitStoreError> {
                Ok(())
            }

            fn clear_reload_required(&self, _unit_name: &str) -> Result<(), UnitStoreError> {
                Ok(())
            }

            fn repair_precommit_journal(
                &self,
                _unit_name: &str,
                _expected: Option<&[u8]>,
            ) -> Result<(), UnitStoreError> {
                Ok(())
            }

            fn atomic_replace(
                &self,
                _unit_name: &str,
                _expected: Option<&[u8]>,
                _contents: &[u8],
                _cancellation: &CancellationToken,
            ) -> Result<(), UnitStoreError> {
                *self.value.lock().unwrap() = StoredUnit::Regular(self.foreign.clone());
                Err(UnitStoreError::Conflict)
            }

            fn atomic_remove(
                &self,
                _unit_name: &str,
                _expected: &[u8],
                _cancellation: &CancellationToken,
            ) -> Result<(), UnitStoreError> {
                Err(UnitStoreError::Conflict)
            }
        }

        let old = unit(&["old"]).render().unwrap();
        let foreign = b"foreign concurrent replacement".to_vec();
        let store = RacingStore {
            value: Mutex::new(StoredUnit::Regular(old)),
            foreign: foreign.clone(),
        };
        let commands = FakeCommands::default();
        assert_eq!(
            UserUnitManager::with_transports(
                &store,
                &commands,
                UserSession::Supported,
                Duration::from_secs(2),
            )
            .update(&unit(&["new"]), &CancellationToken::new())
            .unwrap_err(),
            UserUnitManagerError::ConcurrentMutation
        );
        assert_eq!(*store.value.lock().unwrap(), StoredUnit::Regular(foreign));
        assert_eq!(commands.commands().len(), 1);
    }

    #[test]
    fn postcommit_inspection_failure_never_reloads_unvalidated_bytes() {
        struct InspectionFaultStore {
            value: Mutex<StoredUnit>,
            pending: AtomicBool,
            fail_inspection: AtomicBool,
        }

        impl UserUnitStore for &InspectionFaultStore {
            fn lock_unit<'a>(
                &'a self,
                _unit_name: &str,
                _cancellation: &CancellationToken,
                _timeout: Duration,
            ) -> Result<Box<dyn UnitOperationGuard + 'a>, UnitStoreError> {
                Ok(Box::new(()))
            }

            fn inspect(&self, _unit_name: &str) -> Result<StoredUnit, UnitStoreError> {
                if self.fail_inspection.swap(false, Ordering::AcqRel) {
                    return Err(UnitStoreError::Io);
                }
                Ok(self.value.lock().unwrap().clone())
            }

            fn reload_required(&self, _unit_name: &str) -> Result<bool, UnitStoreError> {
                Ok(self.pending.load(Ordering::Acquire))
            }

            fn revalidate_reload_required(&self, _unit_name: &str) -> Result<(), UnitStoreError> {
                Ok(())
            }

            fn clear_reload_required(&self, _unit_name: &str) -> Result<(), UnitStoreError> {
                self.pending.store(false, Ordering::Release);
                Ok(())
            }

            fn repair_precommit_journal(
                &self,
                _unit_name: &str,
                _expected: Option<&[u8]>,
            ) -> Result<(), UnitStoreError> {
                self.pending.store(false, Ordering::Release);
                Ok(())
            }

            fn atomic_replace(
                &self,
                _unit_name: &str,
                _expected: Option<&[u8]>,
                contents: &[u8],
                _cancellation: &CancellationToken,
            ) -> Result<(), UnitStoreError> {
                *self.value.lock().unwrap() = StoredUnit::Regular(contents.to_vec());
                self.pending.store(true, Ordering::Release);
                self.fail_inspection.store(true, Ordering::Release);
                Err(UnitStoreError::CommittedNeedsReload)
            }

            fn atomic_remove(
                &self,
                _unit_name: &str,
                _expected: &[u8],
                _cancellation: &CancellationToken,
            ) -> Result<(), UnitStoreError> {
                Err(UnitStoreError::Conflict)
            }
        }

        let store = InspectionFaultStore {
            value: Mutex::new(StoredUnit::Missing),
            pending: AtomicBool::new(false),
            fail_inspection: AtomicBool::new(false),
        };
        let commands = FakeCommands::default();
        assert_eq!(
            UserUnitManager::with_transports(
                &store,
                &commands,
                UserSession::Supported,
                Duration::from_secs(2),
            )
            .install(&unit(&[]), &CancellationToken::new())
            .unwrap_err(),
            UserUnitManagerError::CommittedNeedsReload
        );
        assert!(store.pending.load(Ordering::Acquire));
        assert!(!commands
            .commands()
            .iter()
            .any(|command| command.arguments == ["--user", "daemon-reload"]));

        let retry = FakeCommands::default();
        assert_eq!(
            UserUnitManager::with_transports(
                &store,
                &retry,
                UserSession::Supported,
                Duration::from_secs(2),
            )
            .install(&unit(&[]), &CancellationToken::new()),
            Ok(Change::Unchanged)
        );
        assert!(!store.pending.load(Ordering::Acquire));
    }

    #[test]
    fn reload_failure_restores_previous_bytes_and_reloads_again() {
        let old = unit(&["old"]).render().unwrap();
        let store = MemoryStore::with(StoredUnit::Regular(old.clone()));
        let commands = FakeCommands::with(vec![ok(b"252\n"), failed(), ok(b"")]);
        let error = manager(&store, &commands)
            .update(&unit(&["new"]), &CancellationToken::new())
            .unwrap_err();
        assert_eq!(error, UserUnitManagerError::Command);
        assert_eq!(store.value(), StoredUnit::Regular(old));
        assert_eq!(commands.commands().len(), 3);
    }

    #[test]
    fn rollback_failure_is_reported_without_hiding_partial_state() {
        let old = unit(&["old"]).render().unwrap();
        let new = unit(&["new"]).render().unwrap();
        let store = MemoryStore::with(StoredUnit::Regular(old));
        store.fail_rollback.store(true, Ordering::Release);
        let commands = FakeCommands::with(vec![ok(b"252\n"), failed()]);
        let error = manager(&store, &commands)
            .update(&unit(&["new"]), &CancellationToken::new())
            .unwrap_err();
        assert_eq!(error, UserUnitManagerError::RollbackFailed);
        assert_eq!(store.value(), StoredUnit::Regular(new));
    }

    #[test]
    fn remove_is_idempotent_and_reload_failure_restores_file() {
        let bytes = unit(&[]).render().unwrap();
        let store = MemoryStore::with(StoredUnit::Regular(bytes.clone()));
        let enabled = status("enabled");
        let disabled = status("disabled");
        let commands = FakeCommands::with(vec![
            ok(b"252\n"),
            ok(&enabled),
            ok(b""),
            ok(b""),
            ok(&disabled),
            failed(),
            ok(b""),
            ok(&disabled),
            ok(b""),
            ok(b""),
            ok(b""),
            ok(&enabled),
        ]);
        let unit_manager = manager(&store, &commands);
        assert_eq!(
            unit_manager
                .remove("tray", &CancellationToken::new())
                .unwrap_err(),
            UserUnitManagerError::Command
        );
        assert_eq!(store.value(), StoredUnit::Regular(bytes));

        let commands = FakeCommands::default();
        let empty = MemoryStore::default();
        assert_eq!(
            manager(&empty, &commands).remove("tray", &CancellationToken::new()),
            Ok(Change::Unchanged)
        );
    }

    #[test]
    fn committed_remove_cleanup_failure_reloads_only_validated_absence() {
        let bytes = unit(&[]).render().unwrap();
        let store = MemoryStore::with(StoredUnit::Regular(bytes));
        store.commit_needs_reload.store(true, Ordering::Release);
        let disabled = status("disabled");
        let commands = FakeCommands::with(vec![ok(b"252\n"), ok(&disabled), ok(b"")]);
        assert_eq!(
            manager(&store, &commands).remove("tray", &CancellationToken::new()),
            Ok(Change::Changed)
        );
        assert_eq!(store.value(), StoredUnit::Missing);
        assert!(!store.reload_required.load(Ordering::Acquire));
        assert!(commands
            .commands()
            .iter()
            .any(|command| command.arguments == ["--user", "daemon-reload"]));
    }

    #[test]
    fn committed_sync_failure_reloads_and_clears_durable_journal() {
        let store = MemoryStore::default();
        store.commit_needs_reload.store(true, Ordering::Release);
        let commands = FakeCommands::default();
        assert_eq!(
            manager(&store, &commands).install(&unit(&[]), &CancellationToken::new()),
            Ok(Change::Changed)
        );
        assert!(!store.reload_required.load(Ordering::Acquire));
        assert!(commands
            .commands()
            .iter()
            .any(|command| command.arguments == ["--user", "daemon-reload"]));

        // A journal surviving an interrupted caller is recovered before an
        // idempotent retry inspects or mutates the unit.
        store.reload_required.store(true, Ordering::Release);
        let commands = FakeCommands::default();
        assert_eq!(
            manager(&store, &commands).install(&unit(&[]), &CancellationToken::new()),
            Ok(Change::Unchanged)
        );
        assert!(!store.reload_required.load(Ordering::Acquire));
        assert_eq!(
            commands
                .commands()
                .iter()
                .filter(|command| command.arguments == ["--user", "daemon-reload"])
                .count(),
            1
        );
    }

    #[test]
    fn postcommit_journal_clear_failure_is_retryable() {
        let store = MemoryStore::default();
        store.commit_needs_reload.store(true, Ordering::Release);
        store.fail_clear_once.store(true, Ordering::Release);
        let commands = FakeCommands::default();
        assert_eq!(
            manager(&store, &commands)
                .install(&unit(&[]), &CancellationToken::new())
                .unwrap_err(),
            UserUnitManagerError::CommittedNeedsReload
        );
        assert!(store.reload_required.load(Ordering::Acquire));
        assert_eq!(
            commands
                .commands()
                .iter()
                .filter(|command| command.arguments == ["--user", "daemon-reload"])
                .count(),
            1
        );

        let retry_commands = FakeCommands::default();
        assert_eq!(
            manager(&store, &retry_commands).install(&unit(&[]), &CancellationToken::new()),
            Ok(Change::Unchanged)
        );
        assert!(!store.reload_required.load(Ordering::Acquire));
        assert_eq!(
            retry_commands
                .commands()
                .iter()
                .filter(|command| command.arguments == ["--user", "daemon-reload"])
                .count(),
            1
        );
    }

    #[test]
    fn journal_substitution_before_mutation_reload_or_clear_fails_closed() {
        let old = unit(&["old"]).render().unwrap();
        let store = MemoryStore::with(StoredUnit::Regular(old.clone()));
        store.reload_required.store(true, Ordering::Release);
        store
            .fail_recovery_before_mutation_once
            .store(true, Ordering::Release);
        let commands = FakeCommands::default();
        assert_eq!(
            manager(&store, &commands)
                .update(&unit(&["new"]), &CancellationToken::new())
                .unwrap_err(),
            UserUnitManagerError::RepairRequired
        );
        assert_eq!(store.value(), StoredUnit::Regular(old));
        assert!(!commands
            .commands()
            .iter()
            .any(|command| command.arguments == ["--user", "daemon-reload"]));

        let store = MemoryStore::default();
        store.fail_revalidate_once.store(true, Ordering::Release);
        let commands = FakeCommands::default();
        assert_eq!(
            manager(&store, &commands)
                .install(&unit(&[]), &CancellationToken::new())
                .unwrap_err(),
            UserUnitManagerError::RepairRequired
        );
        assert!(store.reload_required.load(Ordering::Acquire));
        assert!(!commands
            .commands()
            .iter()
            .any(|command| command.arguments == ["--user", "daemon-reload"]));

        let retry = FakeCommands::default();
        assert_eq!(
            manager(&store, &retry).install(&unit(&[]), &CancellationToken::new()),
            Ok(Change::Unchanged)
        );
        assert!(!store.reload_required.load(Ordering::Acquire));

        let store = MemoryStore::default();
        store.substitute_clear_once.store(true, Ordering::Release);
        let commands = FakeCommands::default();
        assert_eq!(
            manager(&store, &commands)
                .install(&unit(&[]), &CancellationToken::new())
                .unwrap_err(),
            UserUnitManagerError::RepairRequired
        );
        assert!(store.reload_required.load(Ordering::Acquire));
        assert_eq!(
            commands
                .commands()
                .iter()
                .filter(|command| command.arguments == ["--user", "daemon-reload"])
                .count(),
            1
        );
    }

    #[test]
    fn failed_enable_is_compensated_with_disable() {
        let bytes = unit(&[]).render().unwrap();
        let store = MemoryStore::with(StoredUnit::Regular(bytes));
        let disabled = status("disabled");
        let enabled = status("enabled");
        let commands = FakeCommands::with(vec![
            ok(b"252\n"),
            ok(&disabled),
            failed(),
            ok(&enabled),
            ok(b""),
            ok(b""),
            ok(&disabled),
        ]);
        let error = manager(&store, &commands)
            .enable("tray", &CancellationToken::new())
            .unwrap_err();
        assert_eq!(error, UserUnitManagerError::Command);
        let commands = commands.commands();
        assert_eq!(commands[2].arguments[1], "enable");
        assert_eq!(commands[4].arguments[1], "disable");
        assert_eq!(commands[5].arguments[2], "--runtime");
    }

    #[test]
    fn enablement_rollback_restores_runtime_state_and_refuses_alias_mutation() {
        let bytes = unit(&[]).render().unwrap();
        let store = MemoryStore::with(StoredUnit::Regular(bytes));
        let runtime = status("enabled-runtime");
        let disabled = status("disabled");
        let commands = FakeCommands::with(vec![
            ok(b"252\n"),
            ok(&runtime),
            failed(),
            ok(&disabled),
            ok(b""),
            ok(b""),
            ok(b""),
            ok(&runtime),
        ]);
        assert_eq!(
            manager(&store, &commands)
                .disable("tray", &CancellationToken::new())
                .unwrap_err(),
            UserUnitManagerError::Command
        );
        let recorded = commands.commands();
        assert!(recorded.iter().any(|command| {
            command
                .arguments
                .get(1)
                .is_some_and(|verb| verb == "enable")
                && command
                    .arguments
                    .iter()
                    .any(|argument| argument == "--runtime")
        }));

        let linked = status("linked");
        let commands = FakeCommands::with(vec![
            ok(b"252\n"),
            ok(&linked),
            failed(),
            ok(&disabled),
            ok(b""),
            ok(b""),
            ok(b""),
            ok(&linked),
        ]);
        assert_eq!(
            manager(&store, &commands)
                .disable("tray", &CancellationToken::new())
                .unwrap_err(),
            UserUnitManagerError::Command
        );
        assert!(commands.commands().iter().any(|command| {
            command.arguments.get(1).is_some_and(|verb| verb == "link")
                && command.arguments.iter().any(|argument| {
                    argument == "/home/user/.config/systemd/user/rustscale-tray.service"
                })
        }));

        let alias = status("alias");
        let commands = FakeCommands::with(vec![ok(b"252\n"), ok(&alias)]);
        assert_eq!(
            manager(&store, &commands)
                .disable("tray", &CancellationToken::new())
                .unwrap_err(),
            UserUnitManagerError::Command
        );
        assert_eq!(commands.commands().len(), 2);
    }

    #[test]
    fn status_is_strict_and_bounded_by_transport() {
        let bytes = unit(&[]).render().unwrap();
        let store = MemoryStore::with(StoredUnit::Regular(bytes));
        let enabled = b"LoadState=loaded\nUnitFileState=enabled\nActiveState=active\nSubState=running\nFragmentPath=/home/user/.config/systemd/user/rustscale-tray.service\n";
        let commands = FakeCommands::with(vec![ok(b"252\n"), ok(enabled)]);
        let status = manager(&store, &commands)
            .status("tray", &CancellationToken::new())
            .unwrap();
        assert!(status.is_enabled());
        assert_eq!(status.sub_state, "running");
        assert_eq!(commands.commands()[1].max_output, MAX_OUTPUT_BYTES);
    }

    #[test]
    fn unsupported_and_non_systemd_sessions_do_not_touch_storage() {
        let store = MemoryStore::default();
        let commands = FakeCommands::default();
        for session in [
            UserSession::UnsupportedPlatform,
            UserSession::MissingRuntimeDirectory,
        ] {
            let manager = UserUnitManager::with_transports(
                &store,
                &commands,
                session,
                Duration::from_secs(1),
            );
            assert!(matches!(
                manager.install(&unit(&[]), &CancellationToken::new()),
                Err(UserUnitManagerError::UnsupportedPlatform
                    | UserUnitManagerError::UnsupportedSession)
            ));
        }
        assert!(commands.commands().is_empty());

        let non_systemd = FakeCommands::with(vec![failed()]);
        assert_eq!(
            manager(&store, &non_systemd)
                .install(&unit(&[]), &CancellationToken::new())
                .unwrap_err(),
            UserUnitManagerError::NotSystemdSession
        );
        assert_eq!(store.value(), StoredUnit::Missing);
    }

    #[cfg(unix)]
    #[test]
    fn command_timeout_cancel_output_limit_and_reap() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let executable = std::env::current_exe().unwrap();
        let sleep_program = temporary.path().join("rustscale-systemd-sleep");
        let output_program = temporary.path().join("rustscale-systemd-output");
        symlink(&executable, &sleep_program).unwrap();
        symlink(&executable, &output_program).unwrap();

        let setup_child = Command::new(&sleep_program)
            .args([
                "--exact",
                "systemd_user::tests::command_child",
                "--nocapture",
            ])
            .spawn()
            .unwrap();
        let started = Instant::now();
        drop(ChildGuard::new(setup_child));
        assert!(started.elapsed() < Duration::from_secs(1));

        let sleeping = SystemctlCommand {
            program: sleep_program.to_string_lossy().into_owned(),
            arguments: vec![
                "--exact".into(),
                "systemd_user::tests::command_child".into(),
                "--nocapture".into(),
            ],
            timeout: Duration::from_millis(80),
            max_output: 1024,
        };
        assert_eq!(
            SystemSystemctlTransport.run(&sleeping, &CancellationToken::new()),
            Err(SystemctlError::TimedOut)
        );

        let cancellation = CancellationToken::new();
        let signal = cancellation.clone();
        let thread = thread::spawn(move || {
            thread::sleep(Duration::from_millis(40));
            signal.cancel();
        });
        let mut cancellable = sleeping.clone();
        cancellable.timeout = Duration::from_secs(3);
        assert_eq!(
            SystemSystemctlTransport.run(&cancellable, &cancellation),
            Err(SystemctlError::Cancelled)
        );
        thread.join().unwrap();

        let mut output = sleeping;
        output.program = output_program.to_string_lossy().into_owned();
        output.timeout = Duration::from_secs(3);
        output.max_output = 32;
        assert_eq!(
            SystemSystemctlTransport.run(&output, &CancellationToken::new()),
            Err(SystemctlError::OutputTooLarge)
        );
    }

    #[test]
    fn command_child() {
        let executable = std::env::args().next().unwrap_or_default();
        if executable.ends_with("rustscale-systemd-sleep") {
            thread::sleep(Duration::from_secs(10));
        } else if executable.ends_with("rustscale-systemd-output") {
            print!("{}", "x".repeat(100_000));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_filesystem_reload_failures_reuse_journal_and_rollback_exactly() {
        let temporary = tempfile::tempdir().unwrap();
        let config = temporary.path().join("config");
        std::fs::create_dir(&config).unwrap();

        let store = SystemUserUnitStore::new(&config).unwrap();
        let commands = FakeCommands::with(vec![ok(b"252\n"), failed(), ok(b"")]);
        assert_eq!(
            UserUnitManager::with_transports(
                store.clone(),
                &commands,
                UserSession::Supported,
                Duration::from_secs(2),
            )
            .install(&unit(&["first"]), &CancellationToken::new())
            .unwrap_err(),
            UserUnitManagerError::Command
        );
        assert_eq!(
            store.inspect("rustscale-tray.service").unwrap(),
            StoredUnit::Missing
        );
        assert!(!store
            .unit_directory()
            .join(".rustscale-tray.service.operation")
            .exists());

        let setup_commands = FakeCommands::default();
        UserUnitManager::with_transports(
            store.clone(),
            &setup_commands,
            UserSession::Supported,
            Duration::from_secs(2),
        )
        .install(&unit(&["old"]), &CancellationToken::new())
        .unwrap();
        let old = unit(&["old"]).render().unwrap();
        let commands = FakeCommands::with(vec![ok(b"252\n"), failed(), ok(b"")]);
        assert_eq!(
            UserUnitManager::with_transports(
                store.clone(),
                &commands,
                UserSession::Supported,
                Duration::from_secs(2),
            )
            .update(&unit(&["new"]), &CancellationToken::new())
            .unwrap_err(),
            UserUnitManagerError::Command
        );
        assert_eq!(
            store.inspect("rustscale-tray.service").unwrap(),
            StoredUnit::Regular(old)
        );
        assert!(!store
            .unit_directory()
            .join(".rustscale-tray.service.operation")
            .exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn noncooperating_races_at_every_cas_gap_preserve_racer_and_avoid_reload() {
        use std::os::unix::fs::PermissionsExt;

        use rustix::fs::{Mode, OFlags};

        fn write_private(path: &Path, bytes: &[u8]) {
            std::fs::write(path, bytes).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let commands = FakeCommands::default();

        fn replace_at(directory: &OwnedFd, name: &str, bytes: &[u8]) {
            let candidate = format!(".{name}.race-injection");
            let fd = rustix::fs::openat(
                directory,
                &candidate,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .unwrap();
            let mut file = std::fs::File::from(fd);
            file.write_all(bytes).unwrap();
            file.sync_all().unwrap();
            drop(file);
            rustix::fs::renameat(directory, &candidate, directory, name).unwrap();
        }

        for gap in [
            unix_store::CasGap::AfterValidation,
            unix_store::CasGap::AfterMutation,
        ] {
            let temporary = tempfile::tempdir().unwrap();
            let config = temporary.path().join("config");
            std::fs::create_dir(&config).unwrap();
            let store = SystemUserUnitStore::new(&config).unwrap();
            let directory = store.open_user_dir(true).unwrap().unwrap();
            let root = store.unit_directory();
            write_private(&root.join("left"), b"owned-left");
            write_private(&root.join("right"), b"owned-right");
            let (_, Some(left_identity)) =
                SystemUserUnitStore::inspect_at(&directory, "left").unwrap()
            else {
                panic!("left identity missing");
            };
            let (_, Some(right_identity)) =
                SystemUserUnitStore::inspect_at(&directory, "right").unwrap()
            else {
                panic!("right identity missing");
            };
            assert_eq!(
                SystemUserUnitStore::exchange_exact_with_hook(
                    &directory,
                    "left",
                    b"owned-left",
                    left_identity,
                    "right",
                    b"owned-right",
                    right_identity,
                    |at, directory, _, right| {
                        if at == gap {
                            replace_at(directory, right, b"same-uid-racer");
                        }
                    },
                ),
                Err(UnitStoreError::RepairRequired)
            );
            let survivors = [
                std::fs::read(root.join("left")).unwrap(),
                std::fs::read(root.join("right")).unwrap(),
            ];
            assert!(survivors.iter().any(|bytes| bytes == b"same-uid-racer"));
            assert!(survivors
                .iter()
                .any(|bytes| bytes == b"owned-left" || bytes == b"owned-right"));

            let source = root.join("source");
            write_private(&source, b"rename-owned");
            let (_, Some(source_identity)) =
                SystemUserUnitStore::inspect_at(&directory, "source").unwrap()
            else {
                panic!("source identity missing");
            };
            let rename_result = SystemUserUnitStore::rename_noreplace_exact_with_hook(
                &directory,
                "source",
                b"rename-owned",
                source_identity,
                "destination",
                |at, directory, _, destination| {
                    if at == gap {
                        replace_at(directory, destination, b"same-uid-racer");
                    }
                },
            );
            assert_eq!(
                rename_result,
                Err(if gap == unix_store::CasGap::AfterValidation {
                    UnitStoreError::Conflict
                } else {
                    UnitStoreError::RepairRequired
                })
            );
            assert!(std::fs::read_dir(&root)
                .unwrap()
                .filter_map(Result::ok)
                .filter_map(|entry| std::fs::read(entry.path()).ok())
                .any(|bytes| bytes == b"same-uid-racer"));

            write_private(&root.join("remove-owned"), b"remove-owned");
            let (_, Some(remove_identity)) =
                SystemUserUnitStore::inspect_at(&directory, "remove-owned").unwrap()
            else {
                panic!("remove identity missing");
            };
            assert_eq!(
                SystemUserUnitStore::remove_exact_with_hook(
                    &directory,
                    "remove-owned",
                    b"remove-owned",
                    remove_identity,
                    "test-remove",
                    |at, directory, name, tombstone| {
                        if at == gap {
                            let raced = if at == unix_store::CasGap::AfterValidation {
                                name
                            } else {
                                tombstone
                            };
                            replace_at(directory, raced, b"same-uid-racer");
                        }
                    },
                ),
                Err(UnitStoreError::RepairRequired)
            );
            assert!(std::fs::read_dir(&root)
                .unwrap()
                .filter_map(Result::ok)
                .filter_map(|entry| std::fs::read(entry.path()).ok())
                .any(|bytes| bytes == b"same-uid-racer"));

            if gap == unix_store::CasGap::AfterMutation {
                write_private(&root.join("remove-finalize"), b"remove-finalize");
                let (_, Some(finalize_identity)) =
                    SystemUserUnitStore::inspect_at(&directory, "remove-finalize").unwrap()
                else {
                    panic!("finalize identity missing");
                };
                assert_eq!(
                    SystemUserUnitStore::remove_exact_with_hook(
                        &directory,
                        "remove-finalize",
                        b"remove-finalize",
                        finalize_identity,
                        "test-finalize",
                        |at, directory, _, tombstone| {
                            if at == unix_store::CasGap::BeforeFinalize {
                                replace_at(directory, tombstone, b"same-uid-final-racer");
                            }
                        },
                    ),
                    Err(UnitStoreError::RepairRequired)
                );
                assert!(std::fs::read_dir(&root)
                    .unwrap()
                    .filter_map(Result::ok)
                    .filter_map(|entry| std::fs::read(entry.path()).ok())
                    .any(|bytes| bytes == b"same-uid-final-racer"));
            }
        }
        assert!(commands.commands().is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn snapshot_append_target_clear_and_repair_races_fail_closed() {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt;

        fn replace_path(path: &Path, bytes: &[u8]) {
            let temporary = path.with_extension("race-new");
            std::fs::write(&temporary, bytes).unwrap();
            std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::rename(temporary, path).unwrap();
        }

        let temporary = tempfile::tempdir().unwrap();
        let config = temporary.path().join("config");
        std::fs::create_dir(&config).unwrap();
        let store = SystemUserUnitStore::new(&config).unwrap();
        let directory = store.open_user_dir(true).unwrap().unwrap();
        let bytes = unit(&[]).render().unwrap();
        store
            .atomic_replace(
                "rustscale-tray.service",
                None,
                &bytes,
                &CancellationToken::new(),
            )
            .unwrap();
        let snapshot =
            SystemUserUnitStore::open_journal_snapshot(&directory, "rustscale-tray.service")
                .unwrap()
                .unwrap();
        let journal_path = store
            .unit_directory()
            .join(".rustscale-tray.service.operation");
        assert!(!SystemUserUnitStore::snapshot_still_named_with_hook(
            &directory,
            "rustscale-tray.service",
            &snapshot,
            |gap, _, _| {
                if gap == unix_store::SnapshotGap::AfterInitialStat {
                    let mut file = std::fs::OpenOptions::new()
                        .append(true)
                        .open(&journal_path)
                        .unwrap();
                    file.write_all(b"appended-after-stat").unwrap();
                    file.sync_all().unwrap();
                }
            },
        )
        .unwrap());

        // Recreate a clean operation and substitute the target immediately
        // before clear's final journal+target validation.
        std::fs::remove_file(&journal_path).unwrap();
        store.journals.lock().unwrap().clear();
        std::fs::remove_file(store.unit_directory().join("rustscale-tray.service")).unwrap();
        store
            .atomic_replace(
                "rustscale-tray.service",
                None,
                &bytes,
                &CancellationToken::new(),
            )
            .unwrap();
        assert_eq!(
            store.clear_reload_required_with_hook("rustscale-tray.service", |gap, _, unit_name| {
                if gap == unix_store::ClearGap::BeforeJournalTombstone {
                    let path = store.unit_directory().join(unit_name);
                    replace_path(&path, b"clear-racer");
                }
            },),
            Err(UnitStoreError::RepairRequired)
        );
        assert!(journal_path.exists());
        assert_eq!(
            std::fs::read(store.unit_directory().join("rustscale-tray.service")).unwrap(),
            b"clear-racer"
        );

        // A malformed-journal repair similarly preserves both the journal and
        // a target raced after the exact target snapshot was opened.
        std::fs::write(&journal_path, b"malformed-repair-journal").unwrap();
        std::fs::set_permissions(&journal_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let target = store.unit_directory().join("rustscale-tray.service");
        std::fs::write(&target, &bytes).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            store.repair_precommit_journal_with_hook(
                "rustscale-tray.service",
                Some(&bytes),
                |gap, _, _| {
                    if gap == unix_store::RepairGap::BeforeJournalTombstone {
                        replace_path(&target, b"repair-racer");
                    }
                },
            ),
            Err(UnitStoreError::RepairRequired)
        );
        assert!(journal_path.exists());
        assert_eq!(std::fs::read(target).unwrap(), b"repair-racer");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn target_races_at_each_journal_removal_stage_preserve_journal_inode() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        fn replace_path(path: &Path, bytes: &[u8]) {
            let temporary = path.with_extension("race-new");
            std::fs::write(&temporary, bytes).unwrap();
            std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::rename(temporary, path).unwrap();
        }

        fn inode_survives(directory: &Path, inode: u64) -> bool {
            std::fs::read_dir(directory)
                .unwrap()
                .filter_map(Result::ok)
                .filter_map(|entry| entry.metadata().ok())
                .any(|metadata| metadata.ino() == inode)
        }

        for raced_gap in [
            unix_store::ClearGap::BeforeJournalTombstone,
            unix_store::ClearGap::AfterJournalTombstone,
            unix_store::ClearGap::BeforeJournalUnlink,
        ] {
            let temporary = tempfile::tempdir().unwrap();
            let config = temporary.path().join("config");
            std::fs::create_dir(&config).unwrap();
            let store = SystemUserUnitStore::new(&config).unwrap();
            let bytes = unit(&[]).render().unwrap();
            store
                .atomic_replace(
                    "rustscale-tray.service",
                    None,
                    &bytes,
                    &CancellationToken::new(),
                )
                .unwrap();
            let root = store.unit_directory();
            let journal = root.join(".rustscale-tray.service.operation");
            let journal_inode = std::fs::metadata(&journal).unwrap().ino();
            assert_eq!(
                store.clear_reload_required_with_hook(
                    "rustscale-tray.service",
                    |gap, _, unit_name| {
                        if gap == raced_gap {
                            replace_path(&root.join(unit_name), b"clear-stage-racer");
                        }
                    },
                ),
                Err(UnitStoreError::RepairRequired)
            );
            assert!(inode_survives(&root, journal_inode));
            if raced_gap != unix_store::ClearGap::BeforeJournalTombstone {
                assert_eq!(
                    store.reload_required("rustscale-tray.service"),
                    Err(UnitStoreError::RepairRequired)
                );
            }
        }

        for raced_gap in [
            unix_store::RepairGap::BeforeJournalTombstone,
            unix_store::RepairGap::AfterJournalTombstone,
            unix_store::RepairGap::BeforeJournalUnlink,
        ] {
            let temporary = tempfile::tempdir().unwrap();
            let config = temporary.path().join("config");
            std::fs::create_dir(&config).unwrap();
            let store = SystemUserUnitStore::new(&config).unwrap();
            let root = store.unit_directory();
            std::fs::create_dir_all(&root).unwrap();
            let target = root.join("rustscale-tray.service");
            let bytes = unit(&[]).render().unwrap();
            std::fs::write(&target, &bytes).unwrap();
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
            let journal = root.join(".rustscale-tray.service.operation");
            std::fs::write(&journal, b"malformed-stage-journal").unwrap();
            std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();
            let journal_inode = std::fs::metadata(&journal).unwrap().ino();
            assert_eq!(
                store.repair_precommit_journal_with_hook(
                    "rustscale-tray.service",
                    Some(&bytes),
                    |gap, _, _| {
                        if gap == raced_gap {
                            replace_path(&target, b"repair-stage-racer");
                        }
                    },
                ),
                Err(UnitStoreError::RepairRequired)
            );
            assert!(inode_survives(&root, journal_inode));
            if raced_gap != unix_store::RepairGap::BeforeJournalTombstone {
                assert_eq!(
                    store.reload_required("rustscale-tray.service"),
                    Err(UnitStoreError::RepairRequired)
                );
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn journal_noreplace_rename_fault_preserves_existing_final() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::tempdir().unwrap();
        let config = temporary.path().join("config");
        std::fs::create_dir(&config).unwrap();
        let store = SystemUserUnitStore::new(&config).unwrap();
        let directory = store.open_user_dir(true).unwrap().unwrap();
        let journal_path = store
            .unit_directory()
            .join(".rustscale-tray.service.operation");
        std::fs::write(&journal_path, b"raced-final").unwrap();
        std::fs::set_permissions(&journal_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let record = b"version=1\nunit=rustscale-tray.service\noperation=test\nphase=forward\nkind=replace\ntemporary=.rustscale-tray.service.tmp.test\nbefore=missing\nafter=missing\nbefore-hash=missing\nafter-hash=missing\n";
        assert!(matches!(
            SystemUserUnitStore::publish_journal(
                &directory,
                "rustscale-tray.service",
                unix_store::JournalMutation {
                    phase: unix_store::JournalPhase::Forward,
                    prior: None,
                },
                record,
            ),
            Err(UnitStoreError::Conflict)
        ));
        assert_eq!(std::fs::read(&journal_path).unwrap(), b"raced-final");
        assert!(!std::fs::read_dir(store.unit_directory())
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| entry
                .file_name()
                .to_string_lossy()
                .contains("operation-write")));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn malformed_final_journal_requires_proven_precommit_repair() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::tempdir().unwrap();
        let config = temporary.path().join("config");
        std::fs::create_dir(&config).unwrap();
        let store = SystemUserUnitStore::new(&config).unwrap();
        let setup = FakeCommands::default();
        UserUnitManager::with_transports(
            store.clone(),
            &setup,
            UserSession::Supported,
            Duration::from_secs(2),
        )
        .install(&unit(&["old"]), &CancellationToken::new())
        .unwrap();

        let journal = store
            .unit_directory()
            .join(".rustscale-tray.service.operation");
        std::fs::write(&journal, b"partial-final").unwrap();
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();
        let commands = FakeCommands::default();
        assert_eq!(
            UserUnitManager::with_transports(
                store.clone(),
                &commands,
                UserSession::Supported,
                Duration::from_secs(2),
            )
            .update(&unit(&["new"]), &CancellationToken::new())
            .unwrap_err(),
            UserUnitManagerError::MalformedJournalNeedsRepair
        );
        assert!(!commands
            .commands()
            .iter()
            .any(|command| command.arguments == ["--user", "daemon-reload"]));

        let repair = FakeCommands::default();
        UserUnitManager::with_transports(
            store.clone(),
            &repair,
            UserSession::Supported,
            Duration::from_secs(2),
        )
        .repair_precommit_journal("tray", Some(&unit(&["old"])), &CancellationToken::new())
        .unwrap();
        assert!(!journal.exists());

        // A crash-partial journal staging file is not a final intent and cannot
        // wedge the next operation.
        let partial = store
            .unit_directory()
            .join(".rustscale-tray.service.operation-write.deadbeef.1");
        std::fs::write(&partial, b"version=1\nunit=").unwrap();
        std::fs::set_permissions(&partial, std::fs::Permissions::from_mode(0o600)).unwrap();
        let update = FakeCommands::default();
        UserUnitManager::with_transports(
            store.clone(),
            &update,
            UserSession::Supported,
            Duration::from_secs(2),
        )
        .update(&unit(&["new"]), &CancellationToken::new())
        .unwrap();
        assert!(partial.exists());

        std::fs::write(&journal, b"corrupt-again").unwrap();
        std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(
            store.unit_directory().join("rustscale-tray.service"),
            b"foreign-racer",
        )
        .unwrap();
        let repair = FakeCommands::default();
        assert_eq!(
            UserUnitManager::with_transports(
                store,
                &repair,
                UserSession::Supported,
                Duration::from_secs(2),
            )
            .repair_precommit_journal("tray", Some(&unit(&["new"])), &CancellationToken::new())
            .unwrap_err(),
            UserUnitManagerError::ConcurrentMutation
        );
        assert!(journal.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_store_refuses_symlink_and_foreign_file_and_uses_private_modes() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let temporary = tempfile::tempdir().unwrap();
        let config = temporary.path().join("config");
        std::fs::create_dir(&config).unwrap();
        let store = SystemUserUnitStore::new(&config).unwrap();
        let token = CancellationToken::new();
        let bytes = unit(&[]).render().unwrap();
        assert_eq!(
            store.inspect("../foreign.service"),
            Err(UnitStoreError::Unavailable)
        );
        store
            .atomic_replace("rustscale-tray.service", None, &bytes, &token)
            .unwrap();
        let journal = std::fs::read_to_string(
            store
                .unit_directory()
                .join(".rustscale-tray.service.operation"),
        )
        .unwrap();
        assert!(journal.contains("version=1\nunit=rustscale-tray.service\n"));
        assert!(journal.contains("operation=.rustscale-tray.service.tmp."));
        assert!(journal.contains("phase=forward\n"));
        assert!(journal.contains("before=missing\n"));
        assert!(journal.contains("after-hash="));
        let directory_mode = std::fs::metadata(store.unit_directory())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let file_mode = std::fs::metadata(store.unit_directory().join("rustscale-tray.service"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(directory_mode, 0o700);
        assert_eq!(file_mode, 0o600);

        let unit_path = store.unit_directory().join("rustscale-tray.service");
        let displaced = store.unit_directory().join("displaced.service");
        assert_eq!(
            store.inspect("rustscale-tray.service").unwrap(),
            StoredUnit::Regular(bytes.clone())
        );
        std::fs::rename(&unit_path, &displaced).unwrap();
        std::fs::write(&unit_path, b"foreign-racer").unwrap();
        std::fs::set_permissions(&unit_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            store.atomic_replace(
                "rustscale-tray.service",
                Some(&bytes),
                &unit(&["new"]).render().unwrap(),
                &token,
            ),
            Err(UnitStoreError::Conflict)
        );
        assert_eq!(std::fs::read(&unit_path).unwrap(), b"foreign-racer");
        std::fs::remove_file(&unit_path).unwrap();
        std::fs::rename(&displaced, &unit_path).unwrap();

        std::fs::remove_file(&unit_path).unwrap();
        symlink(
            temporary.path().join("outside"),
            store.unit_directory().join("rustscale-tray.service"),
        )
        .unwrap();
        assert_eq!(
            store.inspect("rustscale-tray.service").unwrap(),
            StoredUnit::Symlink
        );
        assert_eq!(
            store.atomic_replace("rustscale-tray.service", None, &bytes, &token),
            Err(UnitStoreError::Conflict)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bound_config_fd_does_not_follow_substituted_config_path() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().unwrap();
        let config = temporary.path().join("config");
        std::fs::create_dir(&config).unwrap();
        let store = SystemUserUnitStore::new(&config).unwrap();
        let bound = temporary.path().join("bound-config");
        let outside = temporary.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::fs::rename(&config, &bound).unwrap();
        symlink(&outside, &config).unwrap();

        let bytes = unit(&[]).render().unwrap();
        store
            .atomic_replace(
                "rustscale-tray.service",
                None,
                &bytes,
                &CancellationToken::new(),
            )
            .unwrap();
        assert_eq!(
            store.inspect("rustscale-tray.service").unwrap(),
            StoredUnit::Regular(bytes)
        );
        assert!(!outside.join("systemd/user/rustscale-tray.service").exists());
        assert!(bound.join("systemd/user/rustscale-tray.service").exists());
    }
}
