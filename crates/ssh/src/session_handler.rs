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
use crate::incubator::{Incubator, IncubatorArgs};
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
use std::os::fd::{FromRawFd, RawFd};
#[cfg(unix)]
use tokio::io::AsyncReadExt;

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
fn allocate_pty(pty: &crate::session::Pty) -> Result<(RawFd, RawFd, String), SessionHandlerError> {
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

    set_winsize(slave, &pty.window)?;

    let mut name_buf = vec![0u8; 256];
    let ret = unsafe {
        libc::ttyname_r(
            slave,
            name_buf.as_mut_ptr().cast::<libc::c_char>(),
            name_buf.len(),
        )
    };
    if ret != 0 {
        unsafe {
            libc::close(master);
            libc::close(slave);
        }
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

/// Run a session to completion: resolve user, spawn shell, pump I/O.
///
/// Mirrors Go's `handleSession` (tailssh.go). Returns the shell exit code.
///
/// # Arguments
/// * `session` — the accepted SSH session (from `SshListener::accept`)
/// * `rec_config` — optional recording configuration (None = no recording)
#[cfg(unix)]
pub async fn run_session(
    mut session: Session,
    rec_config: Option<RecordingConfig>,
) -> Result<i32, SessionHandlerError> {
    // 1. Resolve local user.
    let local_user = get_local_user(session.user())?;

    // 2. Determine peer/local addresses for SSH_CLIENT/SSH_CONNECTION.
    let (src_ip, src_port, dst_ip, dst_port) = session.peer_addr().map_or(
        (
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            0,
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            22,
        ),
        |a| (a.ip(), a.port(), a.ip(), a.port()),
    );

    // 3. Allocate PTY if requested.
    #[cfg(unix)]
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
    #[cfg(not(unix))]
    let (pty_master_fd, pty_slave_fd, tty_name, term) = (None, None, None, None);

    // 4. Build env vars.
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

    // 5. Build IncubatorArgs.
    let args = IncubatorArgs {
        login_shell: local_user.shell.clone(),
        uid: local_user.uid,
        gid: local_user.gid,
        gids: local_user.gids.clone(),
        local_user: local_user.name.clone(),
        home_dir: local_user.home_dir.clone(),
        remote_user: session.user().to_string(),
        remote_ip: src_ip.to_string(),
        tty_name: tty_name.clone().unwrap_or_default(),
        has_tty: pty_master_fd.is_some(),
        cmd: session.raw_command().to_string(),
        is_shell: session.is_shell(),
        is_sftp: false,
        env: env
            .iter()
            .map(|(k, v)| std::ffi::OsString::from(format!("{k}={v}")))
            .collect(),
        #[cfg(unix)]
        pty_slave_fd,
    };

    // 6. Take the recorder out of the session for the stdout pump.
    let recorder = session.take_recorder();
    let session_rec_config = session.take_recording_config();

    // 7. Spawn shell.
    let incubator = Incubator::new(args);
    let mut spawned = incubator.spawn()?;
    let pid = spawned.pid();

    // Upload completion is watched in the session pump. Any completion before
    // the process exits is a recording failure, including a clean recorder EOF.
    // Keeping the receiver here avoids detached teardown races.
    let terminate_message = rec_config
        .or(session_rec_config)
        .and_then(|config| config.on_failure)
        .map(|action| action.TerminateSessionWithMessage)
        .filter(|message| !message.is_empty());
    let mut upload_result_rx = recorder.as_ref().and_then(SessionRecorder::take_result_rx);
    let mut recording_failure_handled = false;

    // 8. Take I/O handles (None in PTY mode since Stdio::null was used).
    let mut child_stdin = spawned.take_stdin();
    let mut child_stdout = spawned.take_stdout();
    let mut child_stderr = spawned.take_stderr();

    // 9. Get handle + channel_id for sending data to the SSH client.
    let handle = session.handle().clone();
    let channel_id = session.channel_id();

    // 10. Take signal and window-change receivers.
    let mut signal_rx = session.take_signal_rx();
    let mut window_change_rx = session.take_window_change_rx();

    // 11. For PTY mode, dup the master fd so we have separate read/write fds.
    #[cfg(unix)]
    let (mut pty_read, mut pty_write, pty_ioctl_fd) = match pty_master_fd {
        Some(fd) => {
            let read_fd = unsafe { libc::dup(fd) };
            if read_fd < 0 {
                return Err(SessionHandlerError::Pty(
                    io::Error::last_os_error().to_string(),
                ));
            }
            let read_file =
                tokio::fs::File::from_std(unsafe { std::fs::File::from_raw_fd(read_fd) });
            let write_file = tokio::fs::File::from_std(unsafe { std::fs::File::from_raw_fd(fd) });
            (Some(read_file), Some(write_file), Some(read_fd))
        }
        None => (None, None, None),
    };

    // 12. Prepare the child-wait future (pinned for select!).
    let child_wait = spawned.wait();
    tokio::pin!(child_wait);

    let mut session_buf = vec![0u8; 4096];
    let mut stdout_buf = vec![0u8; 4096];
    let mut stderr_buf = vec![0u8; 4096];
    let exit_code;

    // 13. Main I/O pump loop.
    //
    // In PTY mode: read from SSH → write to pty_write; read from pty_read →
    //   write to SSH. No separate stderr.
    // In pipe mode: read from SSH → write to child_stdin; read from
    //   child_stdout → write to SSH; read from child_stderr → write to SSH
    //   extended data.
    loop {
        #[cfg(unix)]
        if let Some(ref mut pty_r) = pty_read {
            tokio::select! {
                // SSH channel → PTY master (shell input)
                r = session.read(&mut session_buf) => {
                    match r {
                        Ok(0) => {}
                        Ok(n) => {
                            if let Some(ref mut pw) = pty_write {
                                let _ = tokio::io::AsyncWriteExt::write_all(pw, &session_buf[..n]).await;
                            }
                        }
                        Err(_) => {}
                    }
                }
                // PTY master → SSH channel (shell output)
                r = pty_r.read(&mut stdout_buf) => {
                    match r {
                        Ok(0) => {}
                        Ok(n) => {
                            if let Some(ref rec) = recorder {
                                if matches!(rec.write(RecordDir::Output, &stdout_buf[..n]), RecordResult::Failed)
                                    && !recording_failure_handled
                                {
                                    recording_failure_handled = true;
                                    handle_recording_failure(pid, terminate_message.as_deref(), &handle, channel_id).await;
                                }
                            }
                            let _ = handle.data(channel_id, bytes::Bytes::copy_from_slice(&stdout_buf[..n])).await;
                        }
                        Err(_) => {}
                    }
                }
                // Signal forwarding
                Some(sig) = signal_rx.recv() => {
                    if let Some(pid) = pid {
                        let s = sig_to_libc(&sig);
                        let ret = unsafe { libc::kill(-(pid as libc::pid_t), s) };
                        if ret != 0 {
                            let _ = unsafe { libc::kill(pid as libc::pid_t, s) };
                        }
                    }
                }
                // Window change forwarding
                Some(win) = window_change_rx.recv() => {
                    if let Some(fd) = pty_ioctl_fd {
                        let _ = set_winsize(fd, &win);
                    }
                }
                // Recorder disconnected or ended while the process is live.
                () = wait_for_upload_result(&mut upload_result_rx), if upload_result_rx.is_some() => {
                    upload_result_rx = None;
                    if let Some(ref rec) = recorder {
                        let _ = rec.close();
                    }
                    if !recording_failure_handled {
                        recording_failure_handled = true;
                        handle_recording_failure(pid, terminate_message.as_deref(), &handle, channel_id).await;
                    }
                }
                // Child exited
                status = &mut child_wait => {
                    exit_code = status?;
                    break;
                }
            }
        } else {
            tokio::select! {
                // SSH channel → shell stdin
                r = session.read(&mut session_buf) => {
                    match r {
                        Ok(0) => {}
                        Ok(n) => {
                            if let Some(ref mut stdin) = child_stdin {
                                let _ = tokio::io::AsyncWriteExt::write_all(stdin, &session_buf[..n]).await;
                            }
                        }
                        Err(_) => {}
                    }
                }
                // Shell stdout → SSH channel
                r = async {
                    if let Some(ref mut stdout) = child_stdout {
                        stdout.read(&mut stdout_buf).await
                    } else {
                        Ok(0)
                    }
                } => {
                    match r {
                        Ok(0) => {}
                        Ok(n) => {
                            if let Some(ref rec) = recorder {
                                if matches!(rec.write(RecordDir::Output, &stdout_buf[..n]), RecordResult::Failed)
                                    && !recording_failure_handled
                                {
                                    recording_failure_handled = true;
                                    handle_recording_failure(pid, terminate_message.as_deref(), &handle, channel_id).await;
                                }
                            }
                            let _ = handle.data(channel_id, bytes::Bytes::copy_from_slice(&stdout_buf[..n])).await;
                        }
                        Err(_) => {}
                    }
                }
                // Shell stderr → SSH channel (extended data)
                r = async {
                    if let Some(ref mut stderr) = child_stderr {
                        stderr.read(&mut stderr_buf).await
                    } else {
                        Ok(0)
                    }
                } => {
                    match r {
                        Ok(0) => {}
                        Ok(n) => {
                            let data = bytes::Bytes::copy_from_slice(&stderr_buf[..n]);
                            let _ = handle.extended_data(channel_id, EXTENDED_DATA_STDERR, data).await;
                        }
                        Err(_) => {}
                    }
                }
                // Signal forwarding
                Some(sig) = signal_rx.recv() => {
                    if let Some(pid) = pid {
                        let s = sig_to_libc(&sig);
                        let ret = unsafe { libc::kill(-(pid as libc::pid_t), s) };
                        if ret != 0 {
                            let _ = unsafe { libc::kill(pid as libc::pid_t, s) };
                        }
                    }
                }
                // Window change (no PTY in pipe mode — ignore)
                Some(_) = window_change_rx.recv() => {}
                // Recorder disconnected or ended while the process is live.
                () = wait_for_upload_result(&mut upload_result_rx), if upload_result_rx.is_some() => {
                    upload_result_rx = None;
                    if let Some(ref rec) = recorder {
                        let _ = rec.close();
                    }
                    if !recording_failure_handled {
                        recording_failure_handled = true;
                        handle_recording_failure(pid, terminate_message.as_deref(), &handle, channel_id).await;
                    }
                }
                // Child exited
                status = &mut child_wait => {
                    exit_code = status?;
                    break;
                }
            }
        }

        #[cfg(not(unix))]
        {
            // Non-unix: pipe mode only, no PTY.
            tokio::select! {
                r = session.read(&mut session_buf) => {
                    match r {
                        Ok(0) => {}
                        Ok(n) => {
                            if let Some(ref mut stdin) = child_stdin {
                                let _ = tokio::io::AsyncWriteExt::write_all(stdin, &session_buf[..n]).await;
                            }
                        }
                        Err(_) => {}
                    }
                }
                r = async {
                    if let Some(ref mut stdout) = child_stdout {
                        stdout.read(&mut stdout_buf).await
                    } else {
                        Ok(0)
                    }
                } => {
                    match r {
                        Ok(0) => {}
                        Ok(n) => {
                            let data = bytes::Bytes::copy_from_slice(&stdout_buf[..n]);
                            let _ = handle.data(channel_id, data).await;
                        }
                        Err(_) => {}
                    }
                }
                status = &mut child_wait => {
                    exit_code = status?;
                    break;
                }
            }
        }
    }

    // 14. Close the producer, then give the bounded queue and transport a
    // finite interval to drain. Abort on timeout so no upload task outlives an
    // SSH session indefinitely.
    if let Some(ref rec) = recorder {
        let _ = rec.close();
    }
    if let Some(result_rx) = upload_result_rx {
        match tokio::time::timeout(RECORDING_DRAIN_TIMEOUT, result_rx).await {
            Ok(Ok(Ok(()))) => {}
            Ok(_) => log::warn!("SSH recorder upload failed during session teardown"),
            Err(_) => {
                log::warn!("SSH recorder upload drain timed out; aborting upload");
                if let Some(ref rec) = recorder {
                    rec.abort_upload();
                }
            }
        }
    }

    // 15. Report exit status to the SSH client after recorder teardown is
    // deterministic.
    session.exit(exit_code as u32).await;
    Ok(exit_code)
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
async fn handle_recording_failure(
    pid: Option<u32>,
    terminate_message: Option<&str>,
    handle: &russh::server::Handle,
    channel_id: russh::ChannelId,
) {
    if let Some(message) = terminate_message {
        log::warn!("SSH recorder transport failed; terminating session");
        if let Some(pid) = pid {
            // SAFETY: kill only receives integer process IDs returned by the
            // child spawner. Try the process group first, then the child.
            unsafe {
                let _ = libc::kill(-(pid as libc::pid_t), libc::SIGTERM);
                let _ = libc::kill(pid as libc::pid_t, libc::SIGTERM);
            }
        }
        let message = format!("\r\n\r\n{message}\r\n\r\n");
        let _ = handle.data(channel_id, message).await;
    } else {
        log::warn!("SSH recorder transport failed; continuing per fail-open policy");
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
    #[test]
    fn test_sig_to_libc_mapping() {
        assert_eq!(sig_to_libc(&Sig::INT), libc::SIGINT);
        assert_eq!(sig_to_libc(&Sig::TERM), libc::SIGTERM);
        assert_eq!(sig_to_libc(&Sig::HUP), libc::SIGHUP);
        assert_eq!(sig_to_libc(&Sig::QUIT), libc::SIGQUIT);
        assert_eq!(sig_to_libc(&Sig::KILL), libc::SIGKILL);
    }
}
