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
            Some(path) => SessionRecorder::with_file(path, cast_header, config.fail_open)
                .map(Some)
                .map_err(|_| "local recording could not start".to_string()),
            None => Ok(None),
        };
    }
    let Some(dial) = dial else {
        return recording_connect_failed(config, "no recorder dialer configured");
    };
    match crate::recording_upload::connect_to_recorder(&config.recorders, dial).await {
        Ok(connection) => SessionRecorder::with_upload(
            connection.writer,
            connection.result_rx,
            connection.abort,
            cast_header,
            config.fail_open,
        )
        .map(Some)
        .map_err(|_| "remote recording could not start".to_string()),
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
    let _ = error;
    log::warn!("SSH recording disabled after a recorder transport failure");
    Ok(None)
}

/// Extended data type code for stderr (RFC 4254 section 5.2).
#[cfg(unix)]
const EXTENDED_DATA_STDERR: u32 = 1;

/// Default PATH when the SSH client doesn't provide one.
const DEFAULT_PATH: &str = "/usr/local/bin:/usr/bin:/bin";
const RECORDING_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const OUTPUT_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);
const PROCESS_TERM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
const PROCESS_KILL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

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
}

#[cfg(unix)]
impl ProcessControl for ProcessGroup {
    fn signal_group(&self, signal: libc::c_int) -> io::Result<bool> {
        self.signal(signal)
    }
}

#[cfg(unix)]
pub(crate) struct LaunchedSession {
    pub input: Option<BoxWrite>,
    pub output: Option<BoxRead>,
    pub stderr: Option<BoxRead>,
    pub wait: std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<i32>> + Send>>,
    pub control: std::sync::Arc<dyn ProcessControl>,
}

/// Injectable launcher. Tests can validate identity and lifecycle behavior
/// without changing the test runner's uid.
#[cfg(unix)]
pub(crate) trait SessionLauncher: Send + Sync {
    fn launch(&self, args: IncubatorArgs) -> Result<LaunchedSession, SessionHandlerError>;
}

#[cfg(unix)]
struct IncubatorSessionLauncher;

#[cfg(unix)]
impl SessionLauncher for IncubatorSessionLauncher {
    fn launch(&self, args: IncubatorArgs) -> Result<LaunchedSession, SessionHandlerError> {
        let mut process = Incubator::new(args).spawn()?;
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
        &get_local_user,
        &IncubatorSessionLauncher,
    )
    .await
}

#[cfg(unix)]
pub(crate) async fn run_session_with(
    mut session: Session,
    rec_config: Option<RecordingConfig>,
    resolve_user: &(dyn Fn(&str) -> Result<LocalUser, SessionHandlerError> + Send + Sync),
    launcher: &dyn SessionLauncher,
) -> Result<i32, SessionHandlerError> {
    let session_duration = session.session_duration();
    let mut session_deadline =
        (!session_duration.is_zero()).then(|| tokio::time::Instant::now() + session_duration);
    let mut revalidate = session.take_revalidate();
    let local_user = resolve_user(session.local_user())?;

    let (src_ip, src_port, dst_ip, dst_port) = session.peer_addr().map_or(
        (
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            0,
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            22,
        ),
        |address| (address.ip(), address.port(), address.ip(), address.port()),
    );

    let (pty_master_fd, pty_slave_fd, tty_name, term) = if let Some(pty) = session.pty() {
        let (master, slave, name) = allocate_pty(pty)?;
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
            let initialized = if let Some(deadline) = session_deadline {
                if let Ok(result) = tokio::time::timeout_at(deadline, initialize).await {
                    result
                } else {
                    let message = format!("Session timeout of {session_duration:?} elapsed.");
                    send_session_termination(&message, session.handle(), session.channel_id())
                        .await;
                    session.exit(1).await;
                    return Ok(1);
                }
            } else {
                initialize.await
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
    let terminate_message = effective_recording_config
        .and_then(|config| config.on_failure)
        .map(|action| action.TerminateSessionWithMessage)
        .filter(|message| !message.is_empty());
    let mut upload_result_rx = recorder.as_ref().and_then(SessionRecorder::take_result_rx);

    // Duplicate all parent PTY roles before launch. Any allocation/duplication
    // error therefore drops every OwnedFd without spawning an orphan process.
    let pty_handles = if let Some(fd) = pty_master_fd {
        let read_fd = fd.try_clone().map_err(|error| {
            SessionHandlerError::Pty(format!("failed to duplicate PTY output: {error}"))
        })?;
        let ioctl_fd = fd.try_clone().map_err(|error| {
            SessionHandlerError::Pty(format!("failed to duplicate PTY control: {error}"))
        })?;
        Some((fd, read_fd, ioctl_fd))
    } else {
        None
    };

    if revalidate.as_ref().is_some_and(|check| !check()) {
        send_session_termination("Access revoked.", session.handle(), session.channel_id()).await;
        session.exit(1).await;
        return Ok(1);
    }
    if session_deadline.is_some_and(|deadline| deadline <= tokio::time::Instant::now()) {
        let message = format!("Session timeout of {session_duration:?} elapsed.");
        send_session_termination(&message, session.handle(), session.channel_id()).await;
        session.exit(1).await;
        return Ok(1);
    }

    let mut launched = launcher.launch(args)?;
    let mut process_input = launched.input.take();
    let mut process_output = launched.output.take();
    let mut process_stderr = launched.stderr.take();
    let control = launched.control.clone();
    let mut child_wait = launched.wait;

    let mut pty_ioctl_fd = None;
    if let Some((write_fd, read_fd, ioctl_fd)) = pty_handles {
        process_output = Some(Box::new(tokio::fs::File::from_std(read_fd.into())));
        process_input = Some(Box::new(tokio::fs::File::from_std(write_fd.into())));
        process_stderr = None;
        pty_ioctl_fd = Some(ioctl_fd);
    }

    let handle = session.handle().clone();
    let channel_id = session.channel_id();
    let mut policy_tick = tokio::time::interval(std::time::Duration::from_millis(250));
    policy_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut cancel_rx = session.take_cancel_rx();
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
    let mut kill_deadline = None;
    let mut drain_deadline = None;
    let mut group_cleanup_started = false;
    let mut policy_invalid_checks = 0_u8;

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
        {
            if forced_failure || kill_deadline.is_some() {
                break;
            }
            if group_cleanup_started {
                // TERM's bounded grace elapsed and SIGKILL was sent.
                break;
            }
            group_cleanup_started = true;
            if !begin_process_termination(control.as_ref(), &mut term_deadline) {
                break;
            }
        }

        tokio::select! {
            input = session.read(&mut session_buf), if process_input.is_some() && pending_input.is_empty() && term_deadline.is_none() => {
                match input {
                    Ok(0) | Err(_) => {
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
                                if terminate_message.is_some() {
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
                                if terminate_message.is_some() {
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
            result = &mut child_wait, if child_exit.is_none() => {
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
                if terminate_message.is_some() {
                    forced_failure = true;
                    pumps_aborted = true;
                    send_recording_termination(terminate_message.as_deref(), &handle, channel_id).await;
                    let _ = begin_process_termination(control.as_ref(), &mut term_deadline);
                    session.exit(1).await;
                } else {
                    log::warn!("SSH recorder transport failed; continuing per fail-open policy");
                }
            }
            () = wait_for_deadline(session_deadline), if session_deadline.is_some() && term_deadline.is_none() => {
                session_deadline = None;
                forced_failure = true;
                pumps_aborted = true;
                let message = format!("Session timeout of {session_duration:?} elapsed.");
                send_session_termination(&message, &handle, channel_id).await;
                let _ = begin_process_termination(control.as_ref(), &mut term_deadline);
                session.exit(1).await;
            }
            _ = policy_tick.tick(), if revalidate.is_some() && term_deadline.is_none() => {
                if revalidate.as_ref().is_some_and(|check| check()) {
                    policy_invalid_checks = 0;
                } else {
                    // A callback can be momentarily unavailable while the
                    // async netmap lock is being replaced. Require persistence
                    // across two polls, while still revoking within 500 ms.
                    policy_invalid_checks = policy_invalid_checks.saturating_add(1);
                    if policy_invalid_checks >= 2 {
                        revalidate = None;
                        forced_failure = true;
                        pumps_aborted = true;
                        send_session_termination("Access revoked.", &handle, channel_id).await;
                        let _ = begin_process_termination(control.as_ref(), &mut term_deadline);
                        session.exit(1).await;
                    }
                }
            }
            changed = cancel_rx.changed(), if term_deadline.is_none() && !forced_failure => {
                if changed.is_err() || *cancel_rx.borrow() {
                    process_input = None;
                    pending_input.clear();
                    pending_input_offset = 0;
                    forced_failure = true;
                    pumps_aborted = true;
                    let _ = begin_process_termination(control.as_ref(), &mut term_deadline);
                    session.exit(1).await;
                }
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
                let _ = begin_process_termination(control.as_ref(), &mut term_deadline);
            }
            () = wait_for_deadline(term_deadline), if term_deadline.is_some() => {
                term_deadline = None;
                let _ = control.signal_group(libc::SIGKILL);
                pumps_aborted = true;
                kill_deadline = Some(tokio::time::Instant::now() + PROCESS_KILL_TIMEOUT);
            }
            () = wait_for_deadline(kill_deadline), if kill_deadline.is_some() => {
                forced_failure = true;
                break;
            }
        }
    }

    if let Some(recorder) = recorder.as_ref() {
        let _ = recorder.close();
    }
    if let Some(result_rx) = upload_result_rx {
        match tokio::time::timeout(RECORDING_DRAIN_TIMEOUT, result_rx).await {
            Ok(Ok(Ok(()))) => {}
            Ok(_) => log::warn!("SSH recorder upload failed during session teardown"),
            Err(_) => {
                if let Some(recorder) = recorder.as_ref() {
                    recorder.abort_upload();
                }
            }
        }
    }

    let exit_code = if forced_failure {
        1
    } else {
        child_exit.unwrap_or(1)
    };
    session.exit(exit_code.max(0) as u32).await;
    Ok(exit_code)
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

    #[test]
    fn test_sig_to_libc_mapping() {
        assert_eq!(sig_to_libc(&Sig::INT), libc::SIGINT);
        assert_eq!(sig_to_libc(&Sig::TERM), libc::SIGTERM);
        assert_eq!(sig_to_libc(&Sig::HUP), libc::SIGHUP);
        assert_eq!(sig_to_libc(&Sig::QUIT), libc::SIGQUIT);
        assert_eq!(sig_to_libc(&Sig::KILL), libc::SIGKILL);
    }
}
