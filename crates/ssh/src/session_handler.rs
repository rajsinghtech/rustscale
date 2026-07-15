//! SSH session orchestrator — ports Go's `handleSession` (tailssh.go).
//!
//! Takes a [`Session`], resolves the local user, spawns the shell, and pumps
//! I/O bidirectionally between the SSH channel and the shell process. This is
//! the glue that `tsnet::SshListener::accept()` users call in a per-session
//! task.
//!
//! Deferred to later phases: HoldAndDelegate, check/verification URLs, SFTP.

use crate::incubator::IncubatorError;
#[cfg(unix)]
use crate::incubator::{Incubator, IncubatorArgs, ProcessGroup};
use crate::recording::{CastHeader, RecordingConfig, SessionRecorder};
#[cfg(unix)]
use crate::recording::{RecordDir, RecordResult};
use crate::recording_upload::DialFn;
use crate::session::Session;
#[cfg(unix)]
use crate::session::Window;

#[cfg(unix)]
use russh::Sig;
#[cfg(unix)]
use std::ffi::CString;
use std::io;
use std::net::IpAddr;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
#[cfg(unix)]
use std::sync::{Arc, Mutex, OnceLock};
#[cfg(unix)]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Initialize the recording backend before the shell is started.
///
/// Remote recorder failures reject only when the policy supplies a rejection
/// message; otherwise they deliberately fail open. NotifyURL requires the
/// control-plane Noise client and is deferred for now.
pub async fn init_recording(
    config: &RecordingConfig,
    cast_header: CastHeader,
    dial: Option<DialFn>,
) -> Result<Option<SessionRecorder>, String> {
    if config.recorders.is_empty() {
        return match &config.local_path {
            Some(path) => match SessionRecorder::with_file(path, cast_header, config.fail_open) {
                Ok(recorder) => Ok(Some(recorder)),
                Err(_) => recording_connect_failed(config, "local recording could not start"),
            },
            None => Ok(None),
        };
    }
    let Some(dial) = dial else {
        return recording_connect_failed(config, "no recorder dialer configured");
    };
    match crate::recording_upload::connect_to_recorder(&config.recorders, dial).await {
        Ok(connection) => initialize_upload_recording(config, cast_header, connection),
        Err((attempts, error)) => {
            let _ = error;
            log::warn!(
                "SSH recording could not start after {} recorder attempt(s)",
                attempts.len()
            );
            recording_connect_failed(config, "recorder connection failed")
        }
    }
}

fn initialize_upload_recording(
    config: &RecordingConfig,
    cast_header: CastHeader,
    connection: crate::recording_upload::RecordingConnection,
) -> Result<Option<SessionRecorder>, String> {
    let abort = connection.abort.clone();
    if let Ok(recorder) = SessionRecorder::with_upload(
        connection.writer,
        connection.result_rx,
        connection.abort,
        cast_header,
        config.fail_open,
    ) {
        Ok(Some(recorder))
    } else {
        // Header/enqueue initialization can fail after transport connection.
        // Abort the partial upload before applying the same fail-open/
        // fail-closed policy as connect failures.
        abort.abort();
        recording_connect_failed(config, "remote recording could not start")
    }
}

fn recording_connect_failed(
    config: &RecordingConfig,
    error: &str,
) -> Result<Option<SessionRecorder>, String> {
    if let Some(action) = &config.on_failure {
        if !action.NotifyURL.is_empty() {
            log::warn!("SSH recording NotifyURL is not implemented yet");
        }
        if !action.RejectSessionWithMessage.is_empty() {
            return Err(action.RejectSessionWithMessage.clone());
        }
    }
    if config.fail_open {
        let _ = error;
        log::warn!("SSH recording disabled after a recorder transport failure");
        Ok(None)
    } else {
        Err(config
            .on_failure
            .as_ref()
            .map(|action| action.TerminateSessionWithMessage.clone())
            .filter(|message| !message.is_empty())
            .unwrap_or_else(|| "recording required".into()))
    }
}

/// Extended data type code for stderr (RFC 4254 section 5.2).
#[cfg(unix)]
const EXTENDED_DATA_STDERR: u32 = 1;

/// Default PATH when the SSH client doesn't provide one.
const DEFAULT_PATH: &str = "/usr/local/bin:/usr/bin:/bin";
#[cfg(not(test))]
const RECORDING_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
#[cfg(test)]
const RECORDING_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(200);
const OUTPUT_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);
#[cfg(not(test))]
const PROCESS_TERM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
#[cfg(test)]
const PROCESS_TERM_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(100);
#[cfg(not(test))]
const PROCESS_KILL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
#[cfg(test)]
const PROCESS_KILL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);
#[cfg(not(test))]
const BLOCKING_PHASE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
#[cfg(test)]
const BLOCKING_PHASE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// Errors from session handling.
#[derive(Debug, thiserror::Error)]
pub enum SessionHandlerError {
    #[error("local user resolution failed: {0}")]
    LocalUser(String),
    #[error("PTY allocation failed: {0}")]
    Pty(String),
    #[error("incubator error: {0}")]
    Incubator(#[from] IncubatorError),
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("channel closed")]
    ChannelClosed,
}

/// Resolved local user information from `getpwnam_r`.
///
/// Mirrors the fields Go extracts from `user.User` in `lookupUser`.
#[derive(Clone, Debug)]
pub struct LocalUser {
    pub uid: u32,
    pub gid: u32,
    pub gids: Vec<u32>,
    pub name: String,
    pub home_dir: String,
    pub shell: String,
}

/// Resolve a local user by name via `getpwnam_r` (Unix).
///
/// Mirrors Go's `lookupUser` in tailssh.go. Returns the uid, gid,
/// supplementary groups, home directory, and login shell.
#[cfg(unix)]
pub fn get_local_user(username: &str) -> Result<LocalUser, SessionHandlerError> {
    let cname = CString::new(username)
        .map_err(|e| SessionHandlerError::LocalUser(format!("invalid username: {e}")))?;

    let mut buf = vec![0u8; 8192];
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();

    // SAFETY: getpwnam_r is thread-safe and writes into our buffer.
    let ret = unsafe {
        libc::getpwnam_r(
            cname.as_ptr(),
            std::ptr::addr_of_mut!(pwd),
            buf.as_mut_ptr().cast::<libc::c_char>(),
            buf.len(),
            std::ptr::addr_of_mut!(result),
        )
    };

    if ret != 0 {
        return Err(SessionHandlerError::LocalUser(
            io::Error::from_raw_os_error(ret).to_string(),
        ));
    }
    if result.is_null() {
        return Err(SessionHandlerError::LocalUser(format!(
            "user '{username}' not found"
        )));
    }

    // SAFETY: result is non-null and points into pwd/buf which are still alive.
    let name = unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) }
        .to_string_lossy()
        .into_owned();
    let home_dir = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) }
        .to_string_lossy()
        .into_owned();
    let shell = unsafe { std::ffi::CStr::from_ptr(pwd.pw_shell) }
        .to_string_lossy()
        .into_owned();
    let gids = get_group_list(&cname, pwd.pw_gid);

    Ok(LocalUser {
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
        gids,
        name,
        home_dir,
        shell,
    })
}

#[cfg(not(unix))]
pub fn get_local_user(username: &str) -> Result<LocalUser, SessionHandlerError> {
    Err(SessionHandlerError::LocalUser(format!(
        "user lookup not supported on this platform (user '{username}')"
    )))
}

/// Get the supplementary group list for a user via `getgrouplist`.
#[cfg(unix)]
fn get_group_list(cname: &CString, base_gid: libc::gid_t) -> Vec<u32> {
    fn checked_gid<T: TryInto<u32>>(gid: T) -> Option<u32> {
        gid.try_into().ok()
    }

    // On macOS, getgrouplist takes c_int for groups; on Linux it takes gid_t.
    #[cfg(target_os = "macos")]
    type GidT = libc::c_int;
    #[cfg(not(target_os = "macos"))]
    type GidT = libc::gid_t;

    let mut groups: Vec<GidT> = vec![0; 32];
    let mut ngroups: libc::c_int = groups.len() as i32;

    // SAFETY: getgrouplist writes into our buffer and updates ngroups.
    let ret = unsafe {
        libc::getgrouplist(
            cname.as_ptr(),
            base_gid as GidT,
            groups.as_mut_ptr(),
            std::ptr::addr_of_mut!(ngroups),
        )
    };

    if ret < 0 && ngroups > 0 {
        groups = vec![0; ngroups as usize];
        let ret = unsafe {
            libc::getgrouplist(
                cname.as_ptr(),
                base_gid as GidT,
                groups.as_mut_ptr(),
                std::ptr::addr_of_mut!(ngroups),
            )
        };
        if ret < 0 {
            return vec![base_gid];
        }
    }

    groups[..ngroups as usize]
        .iter()
        .copied()
        .filter_map(checked_gid)
        .collect()
}

/// Build the SSH environment variables.
///
/// Mirrors Go's `envForSSH` / `setupEnv` in tailssh.go. Combines the
/// client-provided env vars with the standard SSH_* variables and
/// user-specific vars (HOME, SHELL, USER, LOGNAME, PATH).
#[allow(clippy::too_many_arguments)]
pub fn build_env_vars(
    session_env: &[(String, String)],
    local_user: &LocalUser,
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    tty_name: Option<&str>,
    term: Option<&str>,
) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = session_env.to_vec();

    env.push((
        "SSH_CLIENT".into(),
        format!("{src_ip} {src_port} {dst_port}"),
    ));
    env.push((
        "SSH_CONNECTION".into(),
        format!("{src_ip} {src_port} {dst_ip} {dst_port}"),
    ));
    if let Some(tty) = tty_name {
        env.push(("SSH_TTY".into(), tty.to_string()));
    }
    env.push(("LOGNAME".into(), local_user.name.clone()));
    env.push(("USER".into(), local_user.name.clone()));
    env.push(("HOME".into(), local_user.home_dir.clone()));
    env.push(("SHELL".into(), local_user.shell.clone()));

    let has_path = env.iter().any(|(k, _)| k == "PATH");
    if !has_path {
        env.push(("PATH".into(), DEFAULT_PATH.into()));
    }
    if let Some(t) = term {
        let has_term = env.iter().any(|(k, _)| k == "TERM");
        if !has_term {
            env.push(("TERM".into(), t.to_string()));
        }
    }
    env
}

/// Map a russh signal to a libc signal number.
#[cfg(unix)]
fn sig_to_libc(sig: &Sig) -> libc::c_int {
    match sig {
        Sig::INT => libc::SIGINT,
        Sig::TERM => libc::SIGTERM,
        Sig::HUP => libc::SIGHUP,
        Sig::QUIT => libc::SIGQUIT,
        Sig::KILL => libc::SIGKILL,
        Sig::ABRT => libc::SIGABRT,
        Sig::ALRM => libc::SIGALRM,
        Sig::FPE => libc::SIGFPE,
        Sig::ILL => libc::SIGILL,
        Sig::PIPE => libc::SIGPIPE,
        Sig::SEGV => libc::SIGSEGV,
        Sig::USR1 => libc::SIGUSR1,
        Sig::Custom(_) => libc::SIGTERM,
    }
}

/// Allocate a PTY via `openpty(3)` and set the initial window size.
///
/// Returns `(master_fd, slave_fd, tty_name)`. Mirrors Go's `setupPTY`.
#[cfg(unix)]
fn allocate_pty(
    pty: &crate::session::Pty,
) -> Result<(OwnedFd, OwnedFd, String), SessionHandlerError> {
    let mut master: RawFd = -1;
    let mut slave: RawFd = -1;

    // SAFETY: openpty writes into our stack variables.
    // On macOS, the termp/winp params are *mut; on Linux they're *const.
    // Using null_mut() with a cast works for both.
    let ret = unsafe {
        libc::openpty(
            std::ptr::addr_of_mut!(master),
            std::ptr::addr_of_mut!(slave),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ret != 0 {
        return Err(SessionHandlerError::Pty(
            io::Error::last_os_error().to_string(),
        ));
    }

    // Own both descriptors immediately. Every subsequent `?` now closes both
    // exactly once, including window/name and recorder rejection paths.
    let master = unsafe { OwnedFd::from_raw_fd(master) };
    let slave = unsafe { OwnedFd::from_raw_fd(slave) };

    set_winsize(slave.as_raw_fd(), &pty.window)?;

    let mut name_buf = vec![0u8; 256];
    let ret = unsafe {
        libc::ttyname_r(
            slave.as_raw_fd(),
            name_buf.as_mut_ptr().cast::<libc::c_char>(),
            name_buf.len(),
        )
    };
    if ret != 0 {
        return Err(SessionHandlerError::Pty(
            io::Error::from_raw_os_error(ret).to_string(),
        ));
    }

    let tty_name = unsafe { std::ffi::CStr::from_ptr(name_buf.as_ptr().cast()) }
        .to_string_lossy()
        .into_owned();

    Ok((master, slave, tty_name))
}

/// Set the window size on a fd via `TIOCSWINSZ` ioctl.
#[cfg(unix)]
fn pty_eof_byte(fd: RawFd) -> u8 {
    // SAFETY: termios is initialized before ioctl writes it, and fd is an
    // owned PTY master kept alive by the caller.
    let mut termios: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &raw mut termios) } == 0 {
        termios.c_cc[libc::VEOF]
    } else {
        4 // POSIX default Ctrl-D.
    }
}

#[cfg(unix)]
fn set_winsize(fd: RawFd, win: &Window) -> Result<(), SessionHandlerError> {
    let ws = libc::winsize {
        ws_row: win.height as libc::c_ushort,
        ws_col: win.width as libc::c_ushort,
        ws_xpixel: win.width_pixels as libc::c_ushort,
        ws_ypixel: win.height_pixels as libc::c_ushort,
    };
    // SAFETY: ioctl with TIOCSWINSZ takes a pointer to winsize.
    let ret = unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, std::ptr::addr_of!(ws)) };
    if ret != 0 {
        return Err(SessionHandlerError::Pty(
            io::Error::last_os_error().to_string(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
type BoxRead = Box<dyn AsyncRead + Unpin + Send>;
#[cfg(unix)]
type BoxWrite = Box<dyn AsyncWrite + Unpin + Send>;

/// Injectable process-group control used by the lifecycle state machine.
#[cfg(unix)]
pub(crate) trait ProcessControl: Send + Sync {
    /// Returns true if the process group still existed.
    fn signal_group(&self, signal: libc::c_int) -> io::Result<bool>;
    fn group_exists(&self) -> io::Result<bool>;
}

#[cfg(unix)]
impl ProcessControl for ProcessGroup {
    fn signal_group(&self, signal: libc::c_int) -> io::Result<bool> {
        self.signal(signal)
    }

    fn group_exists(&self) -> io::Result<bool> {
        self.exists()
    }
}

#[cfg(unix)]
type ChildWait = std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<i32>> + Send>>;

#[cfg(unix)]
pub(crate) struct LaunchedSession {
    pub input: Option<BoxWrite>,
    pub output: Option<BoxRead>,
    pub stderr: Option<BoxRead>,
    pub wait: ChildWait,
    pub control: std::sync::Arc<dyn ProcessControl>,
}

#[cfg(unix)]
struct ProcessCleanupCommand {
    control: Arc<dyn ProcessControl>,
    wait: Option<ChildWait>,
    signal_group: bool,
}

#[cfg(unix)]
fn process_cleanup_supervisor() -> &'static tokio::sync::mpsc::UnboundedSender<ProcessCleanupCommand>
{
    static SUPERVISOR: OnceLock<tokio::sync::mpsc::UnboundedSender<ProcessCleanupCommand>> =
        OnceLock::new();
    SUPERVISOR.get_or_init(|| {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ProcessCleanupCommand>();
        std::thread::Builder::new()
            .name("ssh-process-cleanup".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("SSH process cleanup runtime");
                runtime.block_on(async move {
                    while let Some(mut command) = rx.recv().await {
                        tokio::spawn(async move {
                            if command.signal_group {
                                let _ = command.control.signal_group(libc::SIGTERM);
                                tokio::time::sleep(PROCESS_TERM_TIMEOUT).await;
                                let _ = command.control.signal_group(libc::SIGKILL);
                                let disappear = async {
                                    loop {
                                        if matches!(command.control.group_exists(), Ok(false)) {
                                            break;
                                        }
                                        tokio::time::sleep(std::time::Duration::from_millis(25))
                                            .await;
                                    }
                                };
                                let _ = tokio::time::timeout(PROCESS_KILL_TIMEOUT, disappear).await;
                            }
                            if let Some(wait) = command.wait.as_mut() {
                                let _ = tokio::time::timeout(PROCESS_KILL_TIMEOUT, wait).await;
                            }
                        });
                    }
                });
            })
            .expect("SSH process cleanup supervisor");
        tx
    })
}

#[cfg(unix)]
struct ProcessCleanupGuard {
    control: Arc<dyn ProcessControl>,
    wait: Option<ChildWait>,
    armed: bool,
}

#[cfg(unix)]
impl ProcessCleanupGuard {
    fn new(control: Arc<dyn ProcessControl>, wait: Option<ChildWait>) -> Self {
        Self {
            control,
            wait,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
        self.wait = None;
    }
}

#[cfg(unix)]
impl Drop for ProcessCleanupGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = process_cleanup_supervisor().send(ProcessCleanupCommand {
                control: self.control.clone(),
                wait: self.wait.take(),
                signal_group: true,
            });
        }
    }
}

#[cfg(unix)]
#[derive(Default)]
struct LaunchOwnershipState {
    canceled: bool,
    cleanup_signaled: bool,
    control: Option<Arc<dyn ProcessControl>>,
}

#[cfg(unix)]
struct LaunchAbortGuard {
    state: Arc<Mutex<LaunchOwnershipState>>,
    armed: bool,
}

#[cfg(unix)]
impl LaunchAbortGuard {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(LaunchOwnershipState::default())),
            armed: true,
        }
    }

    fn publisher(&self) -> Arc<Mutex<LaunchOwnershipState>> {
        self.state.clone()
    }

    fn disarm(&mut self) {
        self.armed = false;
        self.state.lock().unwrap().control = None;
    }

    fn transfer_to_cleanup(&mut self) -> LaunchCleanupOwner {
        self.armed = false;
        let owner = LaunchCleanupOwner {
            state: self.state.clone(),
        };
        owner.cancel();
        owner
    }
}

#[cfg(unix)]
fn publish_launch_control(
    state: &Arc<Mutex<LaunchOwnershipState>>,
    control: Arc<dyn ProcessControl>,
) {
    let cleanup = {
        let mut state = state.lock().unwrap();
        if state.canceled {
            if state.cleanup_signaled {
                None
            } else {
                state.cleanup_signaled = true;
                Some(control)
            }
        } else if state.control.is_none() {
            state.control = Some(control);
            None
        } else {
            None
        }
    };
    if let Some(control) = cleanup {
        let _ = process_cleanup_supervisor().send(ProcessCleanupCommand {
            control,
            wait: None,
            signal_group: true,
        });
    }
}

#[cfg(unix)]
struct LaunchCleanupOwner {
    state: Arc<Mutex<LaunchOwnershipState>>,
}

#[cfg(unix)]
impl LaunchCleanupOwner {
    fn cancel(&self) {
        let cleanup = {
            let mut state = self.state.lock().unwrap();
            state.canceled = true;
            if state.cleanup_signaled {
                None
            } else {
                let control = state.control.take();
                if control.is_some() {
                    state.cleanup_signaled = true;
                }
                control
            }
        };
        if let Some(control) = cleanup {
            let _ = process_cleanup_supervisor().send(ProcessCleanupCommand {
                control,
                wait: None,
                signal_group: true,
            });
        }
    }

    fn adopt_result(&self, launched: LaunchedSession) {
        let signal_group = {
            let mut state = self.state.lock().unwrap();
            state.control = None;
            if state.cleanup_signaled {
                false
            } else {
                state.cleanup_signaled = true;
                true
            }
        };
        let _ = process_cleanup_supervisor().send(ProcessCleanupCommand {
            control: launched.control,
            wait: Some(launched.wait),
            signal_group,
        });
    }
}

#[cfg(unix)]
impl Drop for LaunchAbortGuard {
    fn drop(&mut self) {
        if self.armed {
            LaunchCleanupOwner {
                state: self.state.clone(),
            }
            .cancel();
        }
    }
}

/// Injectable launcher. Tests can validate identity and lifecycle behavior
/// without changing the test runner's uid.
#[cfg(unix)]
pub(crate) type LaunchStarted = Box<dyn FnOnce(Arc<dyn ProcessControl>) + Send>;

#[cfg(unix)]
pub(crate) trait SessionLauncher: Send + Sync {
    /// Begin launch and publish process-group control immediately after fork,
    /// before child setup/exec can block.
    fn launch(
        &self,
        args: IncubatorArgs,
        started: LaunchStarted,
    ) -> Result<LaunchedSession, SessionHandlerError>;
}

#[cfg(unix)]
pub(crate) type UserResolver =
    dyn Fn(String) -> Result<LocalUser, SessionHandlerError> + Send + Sync;

#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
enum CancellationCause {
    Duration,
    Client,
    Policy,
    BlockerTimeout,
}

#[cfg(unix)]
struct LifecycleWatch {
    duration: std::time::Duration,
    deadline: Option<tokio::time::Instant>,
    cancel_rx: tokio::sync::watch::Receiver<bool>,
    revalidate: Option<crate::session::RevalidateCallback>,
    policy_tick: tokio::time::Interval,
    policy_invalid_checks: u8,
}

#[cfg(unix)]
impl LifecycleWatch {
    fn new(session: &mut Session) -> Self {
        let duration = session.session_duration();
        let deadline = (!duration.is_zero()).then(|| tokio::time::Instant::now() + duration);
        let mut policy_tick = tokio::time::interval(std::time::Duration::from_millis(250));
        policy_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        Self {
            duration,
            deadline,
            cancel_rx: session.take_cancel_rx(),
            revalidate: session.take_revalidate(),
            policy_tick,
            policy_invalid_checks: 0,
        }
    }

    async fn cancellation(&mut self) -> CancellationCause {
        loop {
            tokio::select! {
                () = wait_for_deadline(self.deadline), if self.deadline.is_some() => {
                    self.deadline = None;
                    return CancellationCause::Duration;
                }
                changed = self.cancel_rx.changed() => {
                    if changed.is_err() || *self.cancel_rx.borrow() {
                        return CancellationCause::Client;
                    }
                }
                _ = self.policy_tick.tick(), if self.revalidate.is_some() => {
                    if self.revalidate.as_ref().is_some_and(|check| check()) {
                        self.policy_invalid_checks = 0;
                    } else {
                        self.policy_invalid_checks = self.policy_invalid_checks.saturating_add(1);
                        if self.policy_invalid_checks >= 2 {
                            self.revalidate = None;
                            return CancellationCause::Policy;
                        }
                    }
                }
            }
        }
    }

    async fn supervise<F: std::future::Future>(
        &mut self,
        future: F,
    ) -> Result<F::Output, CancellationCause> {
        tokio::pin!(future);
        tokio::select! {
            output = &mut future => Ok(output),
            cause = self.cancellation() => Err(cause),
        }
    }

    async fn supervise_blocker<F: std::future::Future>(
        &mut self,
        future: F,
    ) -> Result<F::Output, CancellationCause> {
        tokio::pin!(future);
        tokio::select! {
            output = &mut future => Ok(output),
            cause = self.cancellation() => Err(cause),
            () = tokio::time::sleep(BLOCKING_PHASE_TIMEOUT) => Err(CancellationCause::BlockerTimeout),
        }
    }
}

#[cfg(unix)]
fn blocker_limit() -> std::sync::Arc<tokio::sync::Semaphore> {
    static LIMIT: std::sync::OnceLock<std::sync::Arc<tokio::sync::Semaphore>> =
        std::sync::OnceLock::new();
    LIMIT
        .get_or_init(|| std::sync::Arc::new(tokio::sync::Semaphore::new(8)))
        .clone()
}

#[cfg(unix)]
struct IncubatorSessionLauncher;

#[cfg(unix)]
impl SessionLauncher for IncubatorSessionLauncher {
    fn launch(
        &self,
        args: IncubatorArgs,
        started: LaunchStarted,
    ) -> Result<LaunchedSession, SessionHandlerError> {
        let mut process = Incubator::new(args).spawn_with_start_notify(move |group| {
            started(Arc::new(group));
        })?;
        let control: std::sync::Arc<dyn ProcessControl> = std::sync::Arc::new(
            process
                .process_group()
                .ok_or_else(|| io::Error::other("spawned SSH process has no process group"))?,
        );
        let input = process
            .take_stdin()
            .map(|stream| Box::new(stream) as BoxWrite);
        let output = process
            .take_stdout()
            .map(|stream| Box::new(stream) as BoxRead);
        let stderr = process
            .take_stderr()
            .map(|stream| Box::new(stream) as BoxRead);
        let wait = Box::pin(async move { process.wait().await });
        Ok(LaunchedSession {
            input,
            output,
            stderr,
            wait,
            control,
        })
    }
}

/// Run a session to completion using the production user resolver and launcher.
#[cfg(unix)]
pub async fn run_session(
    session: Session,
    rec_config: Option<RecordingConfig>,
) -> Result<i32, SessionHandlerError> {
    run_session_with(
        session,
        rec_config,
        std::sync::Arc::new(|name| get_local_user(&name)),
        std::sync::Arc::new(IncubatorSessionLauncher),
    )
    .await
}

#[cfg(unix)]
pub(crate) async fn run_session_with(
    mut session: Session,
    rec_config: Option<RecordingConfig>,
    resolve_user: std::sync::Arc<UserResolver>,
    launcher: std::sync::Arc<dyn SessionLauncher>,
) -> Result<i32, SessionHandlerError> {
    let mut lifecycle = LifecycleWatch::new(&mut session);
    let local_user_name = session.local_user().to_string();
    let permit = match lifecycle
        .supervise_blocker(blocker_limit().acquire_owned())
        .await
    {
        Ok(Ok(permit)) => permit,
        Ok(Err(_)) => {
            return finish_prelaunch_error(
                &mut session,
                io::Error::other("SSH blocker limit closed").into(),
            )
            .await;
        }
        Err(cause) => return finish_prelaunch_cancellation(&mut session, cause).await,
    };
    let mut resolve_task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        resolve_user(local_user_name)
    });
    let local_user = match lifecycle.supervise_blocker(&mut resolve_task).await {
        Ok(Ok(Ok(user))) => user,
        Ok(Ok(Err(error))) => return finish_prelaunch_error(&mut session, error).await,
        Ok(Err(error)) => {
            return finish_prelaunch_error(
                &mut session,
                io::Error::other(error.to_string()).into(),
            )
            .await;
        }
        Err(cause) => {
            tokio::spawn(async move {
                let _ = resolve_task.await;
            });
            return finish_prelaunch_cancellation(&mut session, cause).await;
        }
    };

    let (src_ip, src_port, dst_ip, dst_port) = session.peer_addr().map_or(
        (
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            0,
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            22,
        ),
        |address| (address.ip(), address.port(), address.ip(), address.port()),
    );

    #[cfg(test)]
    if session.fail_pty_setup() {
        return finish_prelaunch_error(
            &mut session,
            SessionHandlerError::Pty("injected PTY setup failure".into()),
        )
        .await;
    }

    let (pty_master_fd, pty_slave_fd, tty_name, term) = if let Some(pty) = session.pty() {
        let (master, slave, name) = match allocate_pty(pty) {
            Ok(pty) => pty,
            Err(error) => return finish_prelaunch_error(&mut session, error).await,
        };
        (
            Some(master),
            Some(slave),
            Some(name),
            Some(pty.term.clone()),
        )
    } else {
        (None, None, None, None)
    };

    let env = build_env_vars(
        session.environ(),
        &local_user,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        tty_name.as_deref(),
        term.as_deref(),
    );
    let args = IncubatorArgs {
        login_shell: local_user.shell.clone(),
        uid: local_user.uid,
        gid: local_user.gid,
        gids: local_user.gids.clone(),
        local_user: local_user.name.clone(),
        home_dir: local_user.home_dir.clone(),
        remote_user: session.user().to_string(),
        remote_ip: src_ip.to_string(),
        tty_name: tty_name.unwrap_or_default(),
        has_tty: pty_master_fd.is_some(),
        cmd: session.raw_command().to_string(),
        is_shell: session.is_shell(),
        is_sftp: false,
        env: env
            .iter()
            .map(|(key, value)| std::ffi::OsString::from(format!("{key}={value}")))
            .collect(),
        pty_slave_fd,
    };

    let effective_recording_config = rec_config.or_else(|| session.take_recording_config());
    let mut recorder = session.take_recorder();
    if recorder.is_none() {
        if let (Some(config), Some(mut header)) = (
            effective_recording_config.as_ref(),
            session.take_recording_header(),
        ) {
            // Resolve first, then commit the header, so recorder metadata is
            // the exact account/uid selected for process launch.
            header.local_user.clone_from(&local_user.name);
            let initialize = init_recording(config, header, session.take_recording_dial());
            let initialized = match lifecycle.supervise(initialize).await {
                Ok(result) => result,
                Err(cause) => return finish_prelaunch_cancellation(&mut session, cause).await,
            };
            match initialized {
                Ok(initialized) => recorder = initialized,
                Err(message) => {
                    let _ = session.handle().data(session.channel_id(), message).await;
                    session.exit(1).await;
                    return Ok(1);
                }
            }
        }
    }
    let recording_fail_closed = effective_recording_config
        .as_ref()
        .is_some_and(|config| !config.fail_open);
    let terminate_message = effective_recording_config
        .as_ref()
        .and_then(|config| config.on_failure.as_ref())
        .map(|action| action.TerminateSessionWithMessage.clone())
        .filter(|message| !message.is_empty());
    let mut upload_result_rx = recorder.as_ref().and_then(SessionRecorder::take_result_rx);

    // Duplicate all parent PTY roles before launch. Any allocation/duplication
    // error therefore drops every OwnedFd without spawning an orphan process.
    let pty_handles = if let Some(fd) = pty_master_fd {
        let read_fd = match fd.try_clone() {
            Ok(fd) => fd,
            Err(error) => {
                return finish_prelaunch_error(
                    &mut session,
                    SessionHandlerError::Pty(format!("failed to duplicate PTY output: {error}")),
                )
                .await;
            }
        };
        let ioctl_fd = match fd.try_clone() {
            Ok(fd) => fd,
            Err(error) => {
                return finish_prelaunch_error(
                    &mut session,
                    SessionHandlerError::Pty(format!("failed to duplicate PTY control: {error}")),
                )
                .await;
            }
        };
        Some((fd, read_fd, ioctl_fd))
    } else {
        None
    };

    if lifecycle.revalidate.as_ref().is_some_and(|check| !check()) {
        return finish_prelaunch_cancellation(&mut session, CancellationCause::Policy).await;
    }
    if lifecycle
        .deadline
        .is_some_and(|deadline| deadline <= tokio::time::Instant::now())
    {
        return finish_prelaunch_cancellation(&mut session, CancellationCause::Duration).await;
    }

    let permit = match lifecycle
        .supervise_blocker(blocker_limit().acquire_owned())
        .await
    {
        Ok(Ok(permit)) => permit,
        Ok(Err(_)) => {
            return finish_prelaunch_error(
                &mut session,
                io::Error::other("SSH blocker limit closed").into(),
            )
            .await;
        }
        Err(cause) => return finish_prelaunch_cancellation(&mut session, cause).await,
    };
    let runtime = tokio::runtime::Handle::current();
    let (started_tx, mut started_rx) = tokio::sync::oneshot::channel();
    let mut launch_abort = LaunchAbortGuard::new();
    let launch_publisher = launch_abort.publisher();
    let raw_launch_task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let _runtime = runtime.enter();
        launcher.launch(
            args,
            Box::new(move |control| {
                publish_launch_control(&launch_publisher, control.clone());
                let _ = started_tx.send(control);
            }),
        )
    });
    let (launch_result_tx, mut launch_result_rx) = tokio::sync::oneshot::channel();
    let result_cleanup = LaunchCleanupOwner {
        state: launch_abort.publisher(),
    };
    tokio::spawn(async move {
        let result = match raw_launch_task.await {
            Ok(result) => result,
            Err(error) => Err(io::Error::other(error.to_string()).into()),
        };
        if let Err(Ok(launched)) = launch_result_tx.send(result) {
            result_cleanup.adopt_result(launched);
        }
    });
    let launch_timeout = tokio::time::sleep(BLOCKING_PHASE_TIMEOUT);
    tokio::pin!(launch_timeout);
    let mut started_open = true;
    let launch_result = loop {
        tokio::select! {
            result = &mut launch_result_rx => break Ok(result),
            _ = &mut started_rx, if started_open => {
                started_open = false;
            }
            cause = lifecycle.cancellation() => break Err(cause),
            () = &mut launch_timeout => break Err(CancellationCause::BlockerTimeout),
        }
    };
    let mut launched = match launch_result {
        Ok(Ok(Ok(launched))) => {
            launch_abort.disarm();
            launched
        }
        Ok(Ok(Err(error))) => return finish_prelaunch_error(&mut session, error).await,
        Ok(Err(error)) => {
            return finish_prelaunch_error(
                &mut session,
                io::Error::other(error.to_string()).into(),
            )
            .await;
        }
        Err(cause) => {
            let cleanup_owner = launch_abort.transfer_to_cleanup();
            tokio::spawn(supervise_canceled_launch(cleanup_owner, launch_result_rx));
            return finish_prelaunch_cancellation(&mut session, cause).await;
        }
    };
    let mut process_input = launched.input.take();
    let mut process_output = launched.output.take();
    let mut process_stderr = launched.stderr.take();
    let control = launched.control.clone();
    let mut process_guard = ProcessCleanupGuard::new(control.clone(), Some(launched.wait));

    let mut pty_ioctl_fd = None;
    if let Some((write_fd, read_fd, ioctl_fd)) = pty_handles {
        process_output = Some(Box::new(tokio::fs::File::from_std(read_fd.into())));
        process_input = Some(Box::new(tokio::fs::File::from_std(write_fd.into())));
        process_stderr = None;
        pty_ioctl_fd = Some(ioctl_fd);
    }

    let handle = session.handle().clone();
    let channel_id = session.channel_id();
    let mut signal_rx = session.take_signal_rx();
    let mut window_change_rx = session.take_window_change_rx();
    let mut session_buf = vec![0_u8; 4096];
    let mut pending_input = Vec::new();
    let mut pending_input_offset = 0;
    let mut stdout_buf = vec![0_u8; 4096];
    let mut stderr_buf = vec![0_u8; 4096];
    let mut child_exit = None;
    let mut forced_failure = false;
    let mut pumps_aborted = false;
    let mut term_deadline = None;
    let mut group_verify_deadline = None;
    let mut reap_deadline = None;
    let mut drain_deadline = None;
    let mut group_cleanup_started = false;
    let mut group_cleanup_confirmed = false;
    let mut group_cleanup_succeeded = false;
    let mut group_poll = tokio::time::interval(std::time::Duration::from_millis(25));
    group_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        if pumps_aborted {
            process_input = None;
            process_output = None;
            process_stderr = None;
            pending_input.clear();
            pending_input_offset = 0;
        }
        if child_exit.is_some()
            && process_output.is_none()
            && process_stderr.is_none()
            && term_deadline.is_none()
            && group_verify_deadline.is_none()
        {
            if group_cleanup_confirmed {
                break;
            }
            if !group_cleanup_started {
                group_cleanup_started = true;
                if !begin_process_termination(control.as_ref(), &mut term_deadline) {
                    group_cleanup_succeeded = true;
                    break;
                }
            }
        }

        tokio::select! {
            input = session.read(&mut session_buf), if process_input.is_some() && pending_input.is_empty() && term_deadline.is_none() => {
                match input {
                    Ok(0) => {
                        // SSH EOF is only an input half-close. The Session
                        // yields it after all queued frames have drained, so
                        // close child stdin without canceling the process or
                        // suppressing its remaining output. PTYs have no true
                        // close-write operation; send their configured VEOF.
                        if let (Some(input), Some(fd)) =
                            (process_input.as_mut(), pty_ioctl_fd.as_ref())
                        {
                            let eof = pty_eof_byte(fd.as_raw_fd());
                            // In canonical mode the first VEOF releases an
                            // unterminated buffered line; the second, now at
                            // an empty boundary, makes the following read
                            // return EOF.
                            let _ = input.write_all(&[eof, eof]).await;
                            let _ = input.flush().await;
                        }
                        process_input = None;
                    }
                    Err(_) => {
                        process_input = None;
                        forced_failure = true;
                        pumps_aborted = true;
                        let _ = begin_process_termination(control.as_ref(), &mut term_deadline);
                        session.exit(1).await;
                    }
                    Ok(count) => {
                        pending_input.extend_from_slice(&session_buf[..count]);
                        pending_input_offset = 0;
                    }
                }
            }
            written = async {
                process_input
                    .as_mut()
                    .unwrap()
                    .write(&pending_input[pending_input_offset..])
                    .await
            }, if process_input.is_some() && !pending_input.is_empty() => {
                match written {
                    Ok(0) | Err(_) => {
                        process_input = None;
                        pending_input.clear();
                        pending_input_offset = 0;
                    }
                    Ok(count) => {
                        pending_input_offset += count;
                        if pending_input_offset == pending_input.len() {
                            pending_input.clear();
                            pending_input_offset = 0;
                        }
                    }
                }
            }
            output = async { process_output.as_mut().unwrap().read(&mut stdout_buf).await }, if process_output.is_some() => {
                match output {
                    Ok(0) | Err(_) => process_output = None,
                    Ok(count) => {
                        let mut deliver = true;
                        if let Some(recorder) = recorder.as_ref() {
                            if matches!(recorder.write(RecordDir::Output, &stdout_buf[..count]), RecordResult::Failed) {
                                upload_result_rx = None;
                                recorder.abort_upload();
                                if recording_fail_closed {
                                    deliver = false;
                                    forced_failure = true;
                                    pumps_aborted = true;
                                    let _ = recorder.close();
                                    send_recording_termination(terminate_message.as_deref(), &handle, channel_id).await;
                                    let _ = begin_process_termination(control.as_ref(), &mut term_deadline);
                                    session.exit(1).await;
                                } else {
                                    log::warn!("SSH recorder transport failed; continuing per fail-open policy");
                                }
                            }
                        }
                        if deliver {
                            let _ = handle.data(channel_id, bytes::Bytes::copy_from_slice(&stdout_buf[..count])).await;
                        }
                        if child_exit.is_some() {
                            drain_deadline = Some(tokio::time::Instant::now() + OUTPUT_DRAIN_TIMEOUT);
                        }
                    }
                }
            }
            stderr = async { process_stderr.as_mut().unwrap().read(&mut stderr_buf).await }, if process_stderr.is_some() => {
                match stderr {
                    Ok(0) | Err(_) => process_stderr = None,
                    Ok(count) => {
                        let mut deliver = true;
                        if let Some(recorder) = recorder.as_ref() {
                            if matches!(recorder.write(RecordDir::Output, &stderr_buf[..count]), RecordResult::Failed) {
                                upload_result_rx = None;
                                recorder.abort_upload();
                                if recording_fail_closed {
                                    deliver = false;
                                    forced_failure = true;
                                    pumps_aborted = true;
                                    let _ = recorder.close();
                                    send_recording_termination(terminate_message.as_deref(), &handle, channel_id).await;
                                    let _ = begin_process_termination(control.as_ref(), &mut term_deadline);
                                    session.exit(1).await;
                                } else {
                                    log::warn!("SSH recorder transport failed; continuing per fail-open policy");
                                }
                            }
                        }
                        if deliver {
                            let data = bytes::Bytes::copy_from_slice(&stderr_buf[..count]);
                            let _ = handle.extended_data(channel_id, EXTENDED_DATA_STDERR, data).await;
                        }
                        if child_exit.is_some() {
                            drain_deadline = Some(tokio::time::Instant::now() + OUTPUT_DRAIN_TIMEOUT);
                        }
                    }
                }
            }
            result = wait_for_child(&mut process_guard.wait), if child_exit.is_none() => {
                reap_deadline = None;
                process_guard.wait = None;
                child_exit = Some(if let Ok(code) = result {
                    code
                } else {
                    forced_failure = true;
                    1
                });
                process_input = None;
                pending_input.clear();
                pending_input_offset = 0;
                if process_output.is_some() || process_stderr.is_some() {
                    drain_deadline = Some(tokio::time::Instant::now() + OUTPUT_DRAIN_TIMEOUT);
                }
            }
            () = wait_for_upload_result(&mut upload_result_rx), if upload_result_rx.is_some() => {
                upload_result_rx = None;
                if let Some(recorder) = recorder.as_ref() {
                    let _ = recorder.close();
                }
                if recording_fail_closed {
                    forced_failure = true;
                    pumps_aborted = true;
                    send_recording_termination(terminate_message.as_deref(), &handle, channel_id).await;
                    let _ = begin_process_termination(control.as_ref(), &mut term_deadline);
                    session.exit(1).await;
                } else {
                    log::warn!("SSH recorder transport failed; continuing per fail-open policy");
                }
            }
            cause = lifecycle.cancellation(), if term_deadline.is_none() && !forced_failure => {
                process_input = None;
                pending_input.clear();
                pending_input_offset = 0;
                forced_failure = true;
                pumps_aborted = true;
                send_cancellation(cause, lifecycle.duration, &handle, channel_id).await;
                let _ = begin_process_termination(control.as_ref(), &mut term_deadline);
                session.exit(1).await;
            }
            Some(signal) = signal_rx.recv(), if term_deadline.is_none() && !forced_failure => {
                let _ = control.signal_group(sig_to_libc(&signal));
            }
            Some(window) = window_change_rx.recv() => {
                if let Some(fd) = pty_ioctl_fd.as_ref() {
                    let _ = set_winsize(fd.as_raw_fd(), &window);
                }
            }
            () = wait_for_deadline(drain_deadline), if drain_deadline.is_some() => {
                drain_deadline = None;
                pumps_aborted = true;
                group_cleanup_started = true;
                let _ = begin_process_termination(control.as_ref(), &mut term_deadline);
            }
            () = wait_for_deadline(term_deadline), if term_deadline.is_some() => {
                term_deadline = None;
                // ESRCH is reported as `Ok(false)` by ProcessGroup. Other
                // signal errors are explicit cleanup failures, but still poll
                // so the group can be confirmed gone or reported persistent.
                if control.signal_group(libc::SIGKILL).is_err() {
                    forced_failure = true;
                }
                pumps_aborted = true;
                group_verify_deadline = Some(tokio::time::Instant::now() + PROCESS_KILL_TIMEOUT);
            }
            _ = group_poll.tick(), if group_verify_deadline.is_some() => {
                if let Ok(false) = control.group_exists() {
                    group_cleanup_confirmed = true;
                    group_cleanup_succeeded = true;
                    group_verify_deadline = None;
                    if child_exit.is_none() {
                        reap_deadline = Some(tokio::time::Instant::now() + PROCESS_KILL_TIMEOUT);
                    }
                }
            }
            () = wait_for_deadline(group_verify_deadline), if group_verify_deadline.is_some() => {
                log::warn!("SSH process group persisted after SIGKILL");
                forced_failure = true;
                group_cleanup_confirmed = true;
                group_verify_deadline = None;
                if child_exit.is_none() {
                    reap_deadline = Some(tokio::time::Instant::now() + PROCESS_KILL_TIMEOUT);
                }
            }
            () = wait_for_deadline(reap_deadline), if reap_deadline.is_some() => {
                log::warn!("SSH child could not be reaped after process-group cleanup");
                forced_failure = true;
                break;
            }
        }
    }

    let mut final_recording_failed = false;
    if let Some(recorder) = recorder.as_ref() {
        if recorder.close().is_err() {
            final_recording_failed = true;
        }
    }
    if let Some(result_rx) = upload_result_rx {
        match tokio::time::timeout(RECORDING_DRAIN_TIMEOUT, result_rx).await {
            Ok(Ok(Ok(()))) => {}
            Ok(_) => final_recording_failed = true,
            Err(_) => {
                final_recording_failed = true;
                if let Some(recorder) = recorder.as_ref() {
                    recorder.abort_upload();
                }
            }
        }
    }
    if final_recording_failed {
        if recording_fail_closed {
            forced_failure = true;
            send_recording_termination(terminate_message.as_deref(), &handle, channel_id).await;
        } else {
            log::warn!("SSH recorder upload failed during session teardown; failing open");
        }
    }

    let exit_code = if forced_failure {
        1
    } else {
        child_exit.unwrap_or(1)
    };
    if group_cleanup_succeeded && process_guard.wait.is_none() {
        process_guard.disarm();
    }
    session.exit(exit_code.max(0) as u32).await;
    Ok(exit_code)
}

#[cfg(unix)]
async fn finish_prelaunch_error(
    session: &mut Session,
    error: SessionHandlerError,
) -> Result<i32, SessionHandlerError> {
    session.exit(1).await;
    Err(error)
}

#[cfg(unix)]
async fn finish_prelaunch_cancellation(
    session: &mut Session,
    cause: CancellationCause,
) -> Result<i32, SessionHandlerError> {
    let handle = session.handle().clone();
    send_cancellation(
        cause,
        session.session_duration(),
        &handle,
        session.channel_id(),
    )
    .await;
    session.exit(1).await;
    Ok(1)
}

#[cfg(unix)]
async fn send_cancellation(
    cause: CancellationCause,
    duration: std::time::Duration,
    handle: &russh::server::Handle,
    channel_id: russh::ChannelId,
) {
    match cause {
        CancellationCause::Duration => {
            let message = format!("Session timeout of {duration:?} elapsed.");
            send_session_termination(&message, handle, channel_id).await;
        }
        CancellationCause::Policy => {
            send_session_termination("Access revoked.", handle, channel_id).await;
        }
        CancellationCause::BlockerTimeout => {
            send_session_termination("SSH session initialization timed out.", handle, channel_id)
                .await;
        }
        CancellationCause::Client => {}
    }
}

#[cfg(unix)]
async fn supervise_canceled_launch(
    cleanup: LaunchCleanupOwner,
    mut launch_result_rx: tokio::sync::oneshot::Receiver<
        Result<LaunchedSession, SessionHandlerError>,
    >,
) {
    match tokio::time::timeout(BLOCKING_PHASE_TIMEOUT, &mut launch_result_rx).await {
        Ok(Ok(Ok(launched))) => cleanup.adopt_result(launched),
        Ok(_) => {}
        Err(_) => {
            // If completion raced the timeout, atomically claim its result;
            // otherwise dropping the receiver transfers any later result to
            // the sender-side cleanup owner.
            if let Ok(Ok(launched)) = launch_result_rx.try_recv() {
                cleanup.adopt_result(launched);
            }
        }
    }
}

#[cfg(unix)]
fn begin_process_termination(
    control: &dyn ProcessControl,
    term_deadline: &mut Option<tokio::time::Instant>,
) -> bool {
    if term_deadline.is_some() {
        return true;
    }
    if let Ok(false) = control.signal_group(libc::SIGTERM) {
        false
    } else {
        *term_deadline = Some(tokio::time::Instant::now() + PROCESS_TERM_TIMEOUT);
        true
    }
}

#[cfg(unix)]
async fn send_session_termination(
    message: &str,
    handle: &russh::server::Handle,
    channel_id: russh::ChannelId,
) {
    let message = format!("\r\n\r\n{message}\r\n\r\n");
    let _ = handle.data(channel_id, message).await;
}

#[cfg(unix)]
async fn send_recording_termination(
    message: Option<&str>,
    handle: &russh::server::Handle,
    channel_id: russh::ChannelId,
) {
    log::warn!("SSH recorder transport failed; terminating session");
    if let Some(message) = message {
        send_session_termination(message, handle, channel_id).await;
    }
}

#[cfg(unix)]
async fn wait_for_child(wait: &mut Option<ChildWait>) -> io::Result<i32> {
    if let Some(wait) = wait.as_mut() {
        wait.await
    } else {
        std::future::pending().await
    }
}

async fn wait_for_upload_result(
    result_rx: &mut Option<tokio::sync::oneshot::Receiver<io::Result<()>>>,
) {
    if let Some(result_rx) = result_rx.as_mut() {
        let _ = result_rx.await;
    } else {
        std::future::pending::<()>().await;
    }
}

#[cfg(unix)]
async fn wait_for_deadline(deadline: Option<tokio::time::Instant>) {
    if let Some(deadline) = deadline {
        tokio::time::sleep_until(deadline).await;
    } else {
        std::future::pending::<()>().await;
    }
}

/// Tailscale SSH sessions require Unix user, process, and PTY primitives.
#[cfg(not(unix))]
pub async fn run_session(
    _session: Session,
    _rec_config: Option<RecordingConfig>,
) -> Result<i32, SessionHandlerError> {
    Err(SessionHandlerError::LocalUser(
        "SSH sessions are only supported on Unix".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_session_unknown_user() {
        let result = get_local_user("__nonexistent_user_xyz__");
        assert!(
            matches!(result, Err(SessionHandlerError::LocalUser(_))),
            "expected LocalUser error, got {result:?}"
        );
    }

    #[test]
    fn test_env_vars_set_correctly() {
        let local_user = LocalUser {
            uid: 1000,
            gid: 1000,
            gids: vec![1000],
            name: "testuser".into(),
            home_dir: "/home/testuser".into(),
            shell: "/bin/bash".into(),
        };

        let src_ip: IpAddr = "100.64.0.2".parse().unwrap();
        let dst_ip: IpAddr = "100.64.0.1".parse().unwrap();

        let env = build_env_vars(
            &[("TERM".into(), "xterm-256color".into())],
            &local_user,
            src_ip,
            54321,
            dst_ip,
            22,
            Some("/dev/pts/3"),
            Some("xterm-256color"),
        );

        let map: std::collections::HashMap<&str, &str> =
            env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

        assert_eq!(map.get("SSH_CLIENT").unwrap(), &"100.64.0.2 54321 22");
        assert_eq!(
            map.get("SSH_CONNECTION").unwrap(),
            &"100.64.0.2 54321 100.64.0.1 22"
        );
        assert_eq!(map.get("SSH_TTY").unwrap(), &"/dev/pts/3");
        assert_eq!(map.get("USER").unwrap(), &"testuser");
        assert_eq!(map.get("LOGNAME").unwrap(), &"testuser");
        assert_eq!(map.get("HOME").unwrap(), &"/home/testuser");
        assert_eq!(map.get("SHELL").unwrap(), &"/bin/bash");
        assert_eq!(map.get("PATH").unwrap(), &DEFAULT_PATH);
        assert_eq!(map.get("TERM").unwrap(), &"xterm-256color");
    }

    #[test]
    fn test_env_vars_no_pty() {
        let local_user = LocalUser {
            uid: 1000,
            gid: 1000,
            gids: vec![],
            name: "alice".into(),
            home_dir: "/home/alice".into(),
            shell: "/bin/zsh".into(),
        };

        let env = build_env_vars(
            &[],
            &local_user,
            "100.64.0.5".parse::<IpAddr>().unwrap(),
            12345,
            "100.64.0.1".parse::<IpAddr>().unwrap(),
            22,
            None,
            None,
        );

        let map: std::collections::HashMap<&str, &str> =
            env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

        assert!(!map.contains_key("SSH_TTY"));
        assert_eq!(map.get("SSH_CLIENT").unwrap(), &"100.64.0.5 12345 22");
    }

    #[cfg(unix)]
    #[cfg(unix)]
    #[tokio::test]
    async fn recorder_rejection_does_not_leak_pty_descriptors() {
        fn fd_count() -> usize {
            std::fs::read_dir("/dev/fd").map_or(0, Iterator::count)
        }

        // Other SSH tests also open PTYs and sockets. Let those parallel tests
        // settle before taking the process-wide descriptor baseline.
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let baseline = fd_count();
        let dial: DialFn = std::sync::Arc::new(|_| {
            Box::pin(async { Err(io::Error::other("injected recorder rejection")) })
        });
        let config = RecordingConfig {
            recorders: vec!["100.64.0.9:80".parse().unwrap()],
            on_failure: Some(rustscale_tailcfg::SSHRecorderFailureAction {
                RejectSessionWithMessage: "recording required".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        for _ in 0..32 {
            let (master, slave, _) = allocate_pty(&crate::session::Pty {
                term: "xterm".into(),
                window: Window {
                    width: 80,
                    height: 24,
                    ..Default::default()
                },
            })
            .unwrap();
            let result = init_recording(
                &config,
                CastHeader::new(
                    (80, 24),
                    "command".into(),
                    std::collections::HashMap::new(),
                    "requested".into(),
                    "mapped".into(),
                    "connection".into(),
                ),
                Some(dial.clone()),
            )
            .await;
            match result {
                Err(message) => assert_eq!(message, "recording required"),
                Ok(_) => panic!("recorder rejection unexpectedly succeeded"),
            }
            drop((master, slave));
        }
        let after = fd_count();
        assert!(
            after <= baseline + 3,
            "PTY descriptors grew across recorder failures: {baseline} -> {after}"
        );
    }

    #[tokio::test]
    async fn upload_header_failure_honors_fail_open_without_partial_recorder() {
        struct ClosedWriter;
        impl std::io::Write for ClosedWriter {
            fn write(&mut self, _data: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed recorder"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed recorder"))
            }
        }
        let header = || {
            CastHeader::new(
                (0, 0),
                "command".into(),
                std::collections::HashMap::new(),
                "requested".into(),
                "mapped".into(),
                "connection".into(),
            )
        };
        let connection = || {
            let (_result_tx, result_rx) = tokio::sync::oneshot::channel();
            let abort = crate::recording_upload::UploadAbort::test_handle();
            (
                crate::recording_upload::RecordingConnection {
                    writer: Box::new(ClosedWriter),
                    result_rx,
                    attempts: Vec::new(),
                    abort: abort.clone(),
                },
                abort,
            )
        };
        let fail_open = RecordingConfig {
            fail_open: true,
            ..Default::default()
        };
        let (connected, abort) = connection();
        assert!(initialize_upload_recording(&fail_open, header(), connected)
            .unwrap()
            .is_none());
        assert!(abort.is_aborted());

        let fail_closed = RecordingConfig {
            fail_open: false,
            ..Default::default()
        };
        let (connected, abort) = connection();
        match initialize_upload_recording(&fail_closed, header(), connected) {
            Err(error) => assert_eq!(error, "recording required"),
            Ok(_) => panic!("partial fail-closed recorder unexpectedly succeeded"),
        }
        assert!(abort.is_aborted());
    }

    #[tokio::test]
    async fn recorder_initialization_honors_explicit_fail_open_for_local_output() {
        let path = std::env::temp_dir(); // Opening a directory as a cast file fails.
        let header = || {
            CastHeader::new(
                (0, 0),
                "command".into(),
                std::collections::HashMap::new(),
                "requested".into(),
                "mapped".into(),
                "connection".into(),
            )
        };
        let fail_open = RecordingConfig {
            local_path: Some(path.clone()),
            fail_open: true,
            ..Default::default()
        };
        assert!(init_recording(&fail_open, header(), None)
            .await
            .unwrap()
            .is_none());

        let fail_closed = RecordingConfig {
            local_path: Some(path),
            fail_open: false,
            ..Default::default()
        };
        match init_recording(&fail_closed, header(), None).await {
            Err(error) => assert_eq!(error, "recording required"),
            Ok(_) => panic!("fail-closed local recording unexpectedly continued"),
        }
    }

    #[test]
    fn test_sig_to_libc_mapping() {
        assert_eq!(sig_to_libc(&Sig::INT), libc::SIGINT);
        assert_eq!(sig_to_libc(&Sig::TERM), libc::SIGTERM);
        assert_eq!(sig_to_libc(&Sig::HUP), libc::SIGHUP);
        assert_eq!(sig_to_libc(&Sig::QUIT), libc::SIGQUIT);
        assert_eq!(sig_to_libc(&Sig::KILL), libc::SIGKILL);
    }
}
