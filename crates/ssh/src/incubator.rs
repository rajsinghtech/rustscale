//! SSH incubator — manages the user shell process lifecycle.
//!
//! Ports Go's `ssh/tailssh/incubator.go`. The incubator spawns the login shell
//! (or SFTP handler), sets up the PTY, drops privileges to the target user, and
//! manages the process lifecycle (signals, exit status, window-size changes).
//!
//! In Go, this is done via a `tailscaled be-child ssh` subprocess that re-execs
//! tailscaled with special flags. In Rust we take a simpler approach: spawn the
//! shell directly with the appropriate uid/gid/pty. The `Incubator` struct
//! encapsulates the spawn + lifecycle management.
//!
//! This is a minimal implementation: it spawns the process and provides methods
//! for signaling and window resizing. A full implementation would handle
//! privilege dropping, SELinux, networked home directories, etc.

use crate::session::Pty;
use std::ffi::OsString;
use std::io;
use std::process::Stdio;

#[cfg(unix)]
#[allow(unused_imports)]
use std::os::unix::process::CommandExt;

#[cfg(unix)]
fn checked_group_count<T>(len: usize) -> io::Result<T>
where
    T: TryFrom<usize>,
{
    T::try_from(len)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "too many supplementary groups"))
}

/// Arguments for spawning an incubated process — mirrors Go's `incubatorArgs`.
#[derive(Clone, Debug, Default)]
pub struct IncubatorArgs {
    /// Path to the user's preferred login shell (e.g. `/bin/bash`).
    pub login_shell: String,
    /// UID of the local user to run as.
    pub uid: u32,
    /// GID of the local user.
    pub gid: u32,
    /// Additional group IDs.
    pub gids: Vec<u32>,
    /// Local username.
    pub local_user: String,
    /// Home directory path.
    pub home_dir: String,
    /// Remote (SSH client) username.
    pub remote_user: String,
    /// Remote IP address.
    pub remote_ip: String,
    /// TTY device name (e.g. `/dev/pts/3`).
    pub tty_name: String,
    /// Whether a TTY was allocated.
    pub has_tty: bool,
    /// Command to execute (empty = interactive shell).
    pub cmd: String,
    /// Whether this is an SFTP session.
    pub is_sftp: bool,
    /// Whether this is an interactive shell (no command).
    pub is_shell: bool,
    /// Environment variables as KEY=VALUE strings.
    pub env: Vec<OsString>,
    /// PTY slave fd — when set, the child's stdin/stdout/stderr are dup2'd
    /// onto this fd in pre_exec instead of using pipes.
    #[cfg(unix)]
    pub pty_slave_fd: Option<std::os::fd::RawFd>,
}

/// Error from the incubator.
#[derive(Debug, thiserror::Error)]
pub enum IncubatorError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("no login shell configured for user {0}")]
    NoShell(String),
    #[error("process not running")]
    NotRunning,
    #[error("SFTP requires tailscaled; not available in standalone mode")]
    SftpUnsupported,
}

/// A spawned incubated process — the shell or SFTP handler.
///
/// This wraps a `tokio::process::Child` with the metadata needed for
/// lifecycle management. The caller is responsible for pumping data between
/// the SSH channel and the process stdin/stdout/stderr.
pub struct SpawnedProcess {
    child: tokio::process::Child,
    #[allow(dead_code)]
    args: IncubatorArgs,
}

/// Safe controller for the dedicated process group created for an SSH shell.
#[derive(Clone, Debug)]
pub struct ProcessGroup {
    pid: u32,
}

impl ProcessGroup {
    /// Signal the whole shell process group, including descendants.
    #[cfg(unix)]
    pub fn signal(&self, signal: libc::c_int) -> io::Result<()> {
        // SAFETY: `pid` came from a successfully spawned child which calls
        // setpgid(0, 0) before exec. kill does not dereference memory.
        let result = unsafe { libc::kill(-(self.pid as libc::pid_t), signal) };
        if result == 0 {
            Ok(())
        } else {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                Ok(())
            } else {
                Err(error)
            }
        }
    }

    #[cfg(not(unix))]
    pub fn signal(&self, _signal: libc::c_int) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "process groups are only supported on Unix",
        ))
    }
}

impl SpawnedProcess {
    /// Send a signal to the process (SIGTERM, SIGKILL, etc.).
    ///
    /// On Unix, this uses the process ID. Returns Ok if the signal was sent.
    pub fn signal(&mut self, sig: libc::c_int) -> Result<(), IncubatorError> {
        let Some(pid) = self.child.id() else {
            return Err(IncubatorError::NotRunning);
        };
        #[cfg(unix)]
        {
            // SAFETY: kill() is safe for any pid/signal combination; it just
            // sends a signal. We're not dereferencing any pointers.
            let ret = unsafe { libc::kill(pid as libc::pid_t, sig) };
            if ret == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error().into())
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (pid, sig);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "process signals are only supported on Unix",
            )
            .into())
        }
    }

    /// Resize the PTY window. On a real implementation this would ioctl the
    /// master PTY fd. Minimal stub: just stores the new size.
    pub fn resize_window(&self, _pty: &Pty) {
        // TODO: ioctl TIOCSWINSZ on the PTY master fd.
        // This requires keeping the master fd in SpawnedProcess.
    }

    /// Wait for the process to exit and return the exit code.
    pub async fn wait(&mut self) -> io::Result<i32> {
        let status = self.child.wait().await?;
        Ok(status.code().unwrap_or(-1))
    }

    /// Kill the process (SIGKILL).
    pub async fn kill(&mut self) -> Result<(), IncubatorError> {
        self.child.kill().await.map_err(IncubatorError::from)
    }

    /// The PID of the spawned process, if still running.
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    pub fn process_group(&self) -> Option<ProcessGroup> {
        self.child.id().map(|pid| ProcessGroup { pid })
    }

    /// Take the stdin handle (for writing to the shell).
    pub fn take_stdin(&mut self) -> Option<tokio::process::ChildStdin> {
        self.child.stdin.take()
    }

    /// Take the stdout handle (for reading shell output).
    pub fn take_stdout(&mut self) -> Option<tokio::process::ChildStdout> {
        self.child.stdout.take()
    }

    /// Take the stderr handle.
    pub fn take_stderr(&mut self) -> Option<tokio::process::ChildStderr> {
        self.child.stderr.take()
    }
}

/// The incubator — spawns and manages the user's shell process.
///
/// In Go, `newIncubatorCommand` re-execs tailscaled as a child process with
/// `be-child ssh` flags. Here we spawn the login shell directly, which is the
/// fallback path Go uses when `tailscaledPath` is empty.
pub struct Incubator {
    args: IncubatorArgs,
}

impl Incubator {
    /// Create a new incubator with the given args.
    pub fn new(args: IncubatorArgs) -> Self {
        Self { args }
    }

    /// Build the shell command arguments from the incubator args.
    ///
    /// Mirrors Go's `shellArgs`: for an interactive shell, no extra args; for
    /// a command, `["-c", command]`.
    fn shell_args(&self) -> Vec<String> {
        if self.args.is_shell || self.args.cmd.is_empty() {
            Vec::new()
        } else {
            vec!["-c".to_string(), self.args.cmd.clone()]
        }
    }

    /// Spawn the shell process.
    ///
    /// If `has_tty` is true, the caller should have already allocated a PTY
    /// and pass the slave end as stdin/stdout/stderr. Otherwise, pipes are used.
    pub fn spawn(&self) -> Result<SpawnedProcess, IncubatorError> {
        if self.args.is_sftp {
            // SFTP requires the embedded SFTP server (Go uses tailscaled's
            // built-in handler). In standalone mode we can't serve SFTP.
            return Err(IncubatorError::SftpUnsupported);
        }
        let shell = if self.args.login_shell.is_empty() {
            return Err(IncubatorError::NoShell(self.args.local_user.clone()));
        } else {
            &self.args.login_shell
        };

        let args = self.shell_args();
        log::debug!(
            "incubator: spawning {shell} {args:?} for uid={} user={}",
            self.args.uid,
            self.args.local_user
        );

        let mut cmd = tokio::process::Command::new(shell);
        cmd.args(&args);
        cmd.env_clear();

        // Collect env vars as owned (OsString, OsString) pairs to avoid
        // lifetime issues with to_string_lossy temporaries.
        let env_pairs: Vec<(OsString, OsString)> = self
            .args
            .env
            .iter()
            .filter_map(|s| {
                let lossy = s.to_string_lossy();
                let pos = lossy.find('=')?;
                let (k, v) = lossy.split_at(pos);
                Some((OsString::from(k), OsString::from(&v[1..])))
            })
            .collect();
        cmd.envs(env_pairs);

        // Set working directory to home, falling back to / if inaccessible.
        let dir = if self.args.home_dir.is_empty() {
            "/".to_string()
        } else {
            self.args.home_dir.clone()
        };
        cmd.current_dir(&dir);

        // PTY mode: dup2 slave fd onto stdin/stdout/stderr in pre_exec.
        // Pipe mode: use Stdio::piped() for I/O pumping.
        #[cfg(unix)]
        if self.args.pty_slave_fd.is_some() {
            cmd.stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
        } else {
            cmd.stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
        }
        #[cfg(not(unix))]
        {
            cmd.stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
        }

        // On Unix, set uid/gid before exec, and dup2 PTY slave if present.
        #[cfg(unix)]
        {
            let gids = self.args.gids.clone();
            let uid = self.args.uid;
            let gid = self.args.gid;
            let pty_slave = self.args.pty_slave_fd;
            // Every SSH shell gets a dedicated process group so cancellation
            // cannot leave TERM-ignoring descendants behind.
            let current_uid = unsafe { libc::getuid() };
            let current_gid = unsafe { libc::getgid() };
            let credentials_specified = !self.args.local_user.is_empty();
            let need_priv_drop =
                credentials_specified && (uid != current_uid || gid != current_gid);
            // SAFETY: pre_exec closures run after fork before exec. The
            // setpgid/dup2/credential calls use values prepared above.
            unsafe {
                cmd.pre_exec(move || {
                    if libc::setpgid(0, 0) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    // If a PTY slave fd is set, dup2 it onto
                    // stdin/stdout/stderr.
                    if let Some(sfd) = pty_slave {
                        if libc::dup2(sfd, 0) < 0 {
                            return Err(io::Error::last_os_error());
                        }
                        if libc::dup2(sfd, 1) < 0 {
                            return Err(io::Error::last_os_error());
                        }
                        if libc::dup2(sfd, 2) < 0 {
                            return Err(io::Error::last_os_error());
                        }
                        if sfd > 2 {
                            libc::close(sfd);
                        }
                    }
                    if need_priv_drop {
                        // Set supplementary groups first.
                        if !gids.is_empty() {
                            let gids_v: Vec<libc::gid_t> =
                                gids.iter().map(|&g| g as libc::gid_t).collect();
                            // libc uses size_t on Linux and c_int on BSD-derived
                            // platforms, so let the target signature select the
                            // checked conversion type.
                            let group_count = checked_group_count(gids_v.len())?;
                            let ret = libc::setgroups(group_count, gids_v.as_ptr());
                            if ret != 0 {
                                return Err(io::Error::last_os_error());
                            }
                        }
                        if libc::setgid(gid as libc::gid_t) != 0 {
                            return Err(io::Error::last_os_error());
                        }
                        if libc::setuid(uid as libc::uid_t) != 0 {
                            return Err(io::Error::last_os_error());
                        }
                    }
                    Ok(())
                });
            }
        }

        let child = cmd.spawn();
        #[cfg(unix)]
        if let Some(slave) = self.args.pty_slave_fd {
            // The child inherited/duplicated its copy during spawn. Keeping the
            // parent copy open would prevent PTY EOF and output draining.
            unsafe {
                libc::close(slave);
            }
        }
        let child = child?;
        Ok(SpawnedProcess {
            child,
            args: self.args.clone(),
        })
    }

    /// The local user this incubator will run as.
    pub fn local_user(&self) -> &str {
        &self.args.local_user
    }

    /// Whether this is an SFTP session.
    pub fn is_sftp(&self) -> bool {
        self.args.is_sftp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_args_interactive() {
        let inc = Incubator::new(IncubatorArgs {
            login_shell: "/bin/sh".into(),
            is_shell: true,
            ..Default::default()
        });
        assert!(inc.shell_args().is_empty());
    }

    #[test]
    fn shell_args_command() {
        let inc = Incubator::new(IncubatorArgs {
            login_shell: "/bin/sh".into(),
            is_shell: false,
            cmd: "echo hello".into(),
            ..Default::default()
        });
        let args = inc.shell_args();
        assert_eq!(args, vec!["-c", "echo hello"]);
    }

    #[test]
    fn sftp_unsupported_standalone() {
        let inc = Incubator::new(IncubatorArgs {
            login_shell: "/bin/sh".into(),
            is_sftp: true,
            ..Default::default()
        });
        let result = inc.spawn();
        assert!(matches!(result, Err(IncubatorError::SftpUnsupported)));
    }

    #[test]
    fn no_shell_error() {
        let inc = Incubator::new(IncubatorArgs {
            login_shell: String::new(),
            local_user: "nobody".into(),
            ..Default::default()
        });
        let result = inc.spawn();
        assert!(matches!(result, Err(IncubatorError::NoShell(_))));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn process_group_kill_reaps_term_ignoring_descendant() {
        let pid_file =
            std::env::temp_dir().join(format!("rustscale-ssh-descendant-{}", std::process::id()));
        let _ = std::fs::remove_file(&pid_file);
        let command = format!(
            "trap '' TERM; (trap '' TERM; sleep 30) & echo $! > {}; wait",
            pid_file.display()
        );
        let inc = Incubator::new(IncubatorArgs {
            login_shell: "/bin/sh".into(),
            is_shell: false,
            cmd: command,
            env: vec![OsString::from("PATH=/usr/bin:/bin")],
            ..Default::default()
        });
        let mut process = inc.spawn().expect("spawn failed");
        drop(process.take_stdin());
        let group = process.process_group().expect("process group");

        let descendant = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Ok(pid) = std::fs::read_to_string(&pid_file) {
                    if let Ok(pid) = pid.trim().parse::<u32>() {
                        break pid;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("descendant pid");

        group.signal(libc::SIGTERM).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        group.signal(libc::SIGKILL).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), process.wait())
            .await
            .expect("process group did not exit")
            .expect("wait failed");

        let gone = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let status = tokio::process::Command::new("kill")
                    .args(["-0", &descendant.to_string()])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .await
                    .expect("kill -0");
                if !status.success() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await;
        let _ = std::fs::remove_file(pid_file);
        assert!(gone.is_ok(), "TERM-ignoring descendant remained alive");
    }

    #[tokio::test]
    async fn spawn_and_wait_simple_command() {
        let inc = Incubator::new(IncubatorArgs {
            login_shell: "/bin/sh".into(),
            is_shell: false,
            cmd: "exit 42".into(),
            env: vec![
                OsString::from("PATH=/usr/bin:/bin"),
                OsString::from("HOME=/tmp"),
            ],
            ..Default::default()
        });
        let mut proc = inc.spawn().expect("spawn failed");
        // Close stdin so the shell doesn't wait for input.
        drop(proc.take_stdin());
        let code = proc.wait().await.expect("wait failed");
        assert_eq!(code, 42);
    }
}
