//! Integration tests for the SSH crate — verifies the full pipeline
//! (SshServer → SshHandler → Session → run_session) without network I/O.
//!
//! These tests use `tokio::io::duplex` to connect a russh client and server
//! in-memory, then verify that `run_session` correctly spawns the shell,
//! pumps I/O, and reports exit status.

#![cfg(unix)]

use crate::host_key_from_node_key;
use crate::session_handler::{
    run_session, run_session_with, LaunchedSession, LocalUser, ProcessControl, SessionHandlerError,
    SessionLauncher,
};
use crate::{Session, SshServer, SshServerConfig};
use russh::server::Server as _;
use russh::{ChannelMsg, MethodSet};
use rustscale_key::NodePrivate;
use rustscale_tailcfg::{
    Node, SSHAction, SSHPolicy, SSHPrincipal, SSHRule, StableNodeID, UserProfile,
};
use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot};

fn peer_ip() -> IpAddr {
    "100.64.0.2".parse().unwrap()
}

fn test_node() -> Node {
    Node {
        ID: 42,
        StableID: StableNodeID::from("nodePeer"),
        Key: NodePrivate::generate().public(),
        ..Default::default()
    }
}

fn test_profile() -> UserProfile {
    UserProfile {
        ID: 42,
        LoginName: "alice@example.com".into(),
        DisplayName: "Alice".into(),
        ProfilePicURL: String::new(),
    }
}

fn policy_for(local_user: &str, session_duration: std::time::Duration) -> SSHPolicy {
    let mapping = local_user.to_string();
    SSHPolicy {
        Rules: vec![SSHRule {
            Principals: vec![SSHPrincipal {
                Any: true,
                ..Default::default()
            }],
            SSHUsers: {
                let mut m = BTreeMap::new();
                m.insert("*".into(), mapping);
                m
            },
            Action: Some(SSHAction {
                Accept: true,
                SessionDuration: session_duration,
                ..Default::default()
            }),
            ..Default::default()
        }],
    }
}

fn policy_map_any(local_user: &str) -> Arc<dyn Fn() -> Option<SSHPolicy> + Send + Sync> {
    let policy = policy_for(local_user, std::time::Duration::ZERO);
    Arc::new(move || Some(policy.clone()))
}

fn policy_allow_any() -> Arc<dyn Fn() -> Option<SSHPolicy> + Send + Sync> {
    policy_map_any("=")
}

fn whois_finds_peer() -> Arc<dyn Fn(IpAddr) -> Option<(Node, UserProfile)> + Send + Sync> {
    let node = test_node();
    let profile = test_profile();
    Arc::new(move |ip| {
        if ip == peer_ip() {
            Some((node.clone(), profile.clone()))
        } else {
            None
        }
    })
}

/// A minimal russh client handler that accepts any server key.
struct ClientHandler;

impl russh::client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// Run a full SSH session over an in-memory duplex stream.
///
/// `command` is sent as an exec request. The function returns the exit code
/// reported by `run_session`.
async fn run_pipeline_custom(
    command: &str,
    requested_user: &str,
    policy: Arc<dyn Fn() -> Option<SSHPolicy> + Send + Sync>,
    injected: Option<(
        &(dyn Fn(&str) -> Result<LocalUser, SessionHandlerError> + Send + Sync),
        &dyn SessionLauncher,
    )>,
    mutate_session: Option<&dyn Fn(&mut crate::session::SessionInit)>,
    client_eof_before_run: bool,
    request_pty: bool,
) -> (i32, Vec<u8>) {
    let host_key = host_key_from_node_key(&NodePrivate::generate());
    let (session_tx, mut session_rx) = mpsc::channel::<crate::session::SessionInit>(16);
    let config = SshServerConfig {
        host_keys: vec![host_key],
        session_tx,
        whois: whois_finds_peer(),
        policy,
        state_dir: None,
        dial_fn: None,
    };
    let mut server = SshServer::new(config);
    let russh_config = Arc::new(russh::server::Config {
        server_id: russh::SshId::Standard("SSH-2.0-rustscale-tailssh".into()),
        keys: server.russh_config().keys.clone(),
        methods: MethodSet::all(),
        auth_rejection_time: std::time::Duration::from_secs(0),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        max_auth_attempts: 10,
        inactivity_timeout: Some(std::time::Duration::from_secs(30)),
        ..Default::default()
    });

    // Create an in-memory duplex connection (no network I/O).
    let (client_io, server_io) = tokio::io::duplex(8192);

    // Spawn the SSH server on the server side of the duplex.
    let server_config = russh_config.clone();
    let handler = server.new_client(Some(SocketAddr::new(peer_ip(), 22)));
    tokio::spawn(async move {
        let running = russh::server::run_stream(server_config, server_io, handler)
            .await
            .expect("server run_stream");
        let _ = running.await;
    });

    // Connect the russh client on the client side.
    let client_config = Arc::new(russh::client::Config::default());
    let mut client = russh::client::connect_stream(client_config, client_io, ClientHandler)
        .await
        .expect("client connect");

    // Authenticate (the server's tailscale_auth accepts any peer in the policy).
    let authed = client
        .authenticate_password(requested_user, "")
        .await
        .expect("auth")
        .success();
    assert!(authed, "authentication should succeed");

    // Open a channel and send the exec request.
    let mut channel = client.channel_open_session().await.expect("channel open");
    if request_pty {
        channel
            .request_pty(false, "xterm", 80, 24, 0, 0, &[])
            .await
            .expect("pty request");
    }
    channel
        .exec(true, command.as_bytes())
        .await
        .expect("exec request");
    if client_eof_before_run {
        channel.eof().await.expect("channel eof");
    }

    // Accept the session on the server side and run it.
    let mut session_init = session_rx.recv().await.expect("session init received");
    if let Some(mutate_session) = mutate_session {
        mutate_session(&mut session_init);
    }
    let session = Session::from_init(session_init);
    let result = if let Some((resolver, launcher)) = injected {
        run_session_with(session, None, resolver, launcher)
            .await
            .expect("run_session_with")
    } else {
        run_session(session, None).await.expect("run_session")
    };

    // Wait for all output and the exit status on the client side. The server
    // must not close the channel until trailing process output has drained.
    let mut output = Vec::new();
    let mut reported = None;
    while let Some(message) = channel.wait().await {
        match message {
            ChannelMsg::Data { data } => output.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, .. } => output.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => reported = Some(exit_status as i32),
            _ => {}
        }
    }

    (reported.unwrap_or(result), output)
}

async fn run_pipeline_output(command: &str) -> (i32, Vec<u8>) {
    let requested_user = std::env::var("USER").unwrap_or_else(|_| "testuser".to_string());
    run_pipeline_custom(
        command,
        &requested_user,
        policy_allow_any(),
        None,
        None,
        false,
        false,
    )
    .await
}

async fn run_pipeline(command: &str) -> i32 {
    run_pipeline_output(command).await.0
}

#[derive(Default)]
struct NoopProcessControl;

impl ProcessControl for NoopProcessControl {
    fn signal_group(&self, _signal: libc::c_int) -> io::Result<bool> {
        Ok(false)
    }
}

#[derive(Default)]
struct CapturingLauncher {
    args: Mutex<Vec<crate::incubator::IncubatorArgs>>,
}

impl SessionLauncher for CapturingLauncher {
    fn launch(
        &self,
        args: crate::incubator::IncubatorArgs,
    ) -> Result<LaunchedSession, SessionHandlerError> {
        self.args.lock().unwrap().push(args);
        Ok(LaunchedSession {
            input: Some(Box::new(tokio::io::sink())),
            output: Some(Box::new(tokio::io::empty())),
            stderr: Some(Box::new(tokio::io::empty())),
            wait: Box::pin(async { Ok(0) }),
            control: Arc::new(NoopProcessControl),
        })
    }
}

#[tokio::test]
async fn policy_mapped_local_user_is_resolved_and_launched_not_requested_user() {
    let launcher = CapturingLauncher::default();
    let resolved = Arc::new(Mutex::new(Vec::new()));
    let resolver = {
        let resolved = resolved.clone();
        move |name: &str| {
            resolved.lock().unwrap().push(name.to_string());
            Ok(LocalUser {
                uid: 65_534,
                gid: 65_534,
                gids: vec![65_534],
                name: "nobody".into(),
                home_dir: "/nonexistent".into(),
                shell: "/bin/sh".into(),
            })
        }
    };

    let recording_path = std::env::temp_dir().join(format!(
        "rustscale-mapped-user-recording-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&recording_path);
    let mutate = |init: &mut crate::session::SessionInit| {
        init.recording_config = Some(crate::RecordingConfig {
            local_path: Some(recording_path.clone()),
            ..Default::default()
        });
        init.recording_header = Some(crate::CastHeader::new(
            (0, 0),
            "exit 0".into(),
            std::collections::HashMap::new(),
            "root".into(),
            "unresolved".into(),
            "connection".into(),
        ));
    };
    let (code, _) = run_pipeline_custom(
        "exit 0",
        "root",
        policy_map_any("nobody"),
        Some((&resolver, &launcher)),
        Some(&mutate),
        false,
        false,
    )
    .await;
    assert_eq!(code, 0);
    assert_eq!(&*resolved.lock().unwrap(), &["nobody"]);
    let args = launcher.args.lock().unwrap();
    assert_eq!(args.len(), 1);
    assert_eq!(args[0].local_user, "nobody");
    assert_eq!(args[0].uid, 65_534);
    assert_eq!(args[0].remote_user, "root");
    let recording = std::fs::read_to_string(&recording_path).unwrap();
    let header: serde_json::Value =
        serde_json::from_str(recording.lines().next().unwrap()).unwrap();
    assert_eq!(header["localUser"], "nobody");
    let _ = std::fs::remove_file(recording_path);
}

/// Watcher test: verifies the full pipeline (SshServer → SshHandler →
/// Session → run_session) without network I/O, using in-memory duplex.
struct EscalatingControl {
    signals: Mutex<Vec<libc::c_int>>,
    exit: Mutex<Option<oneshot::Sender<i32>>>,
}

impl ProcessControl for EscalatingControl {
    fn signal_group(&self, signal: libc::c_int) -> io::Result<bool> {
        self.signals.lock().unwrap().push(signal);
        if signal == libc::SIGKILL {
            if let Some(exit) = self.exit.lock().unwrap().take() {
                let _ = exit.send(137);
            }
        }
        Ok(true)
    }
}

struct TermIgnoringLauncher {
    control: Arc<EscalatingControl>,
    exit_rx: Mutex<Option<oneshot::Receiver<i32>>>,
    output: Mutex<Option<Vec<u8>>>,
    stderr: Mutex<Option<Vec<u8>>>,
    input_dropped: Arc<std::sync::atomic::AtomicBool>,
}

impl TermIgnoringLauncher {
    fn new(output: Vec<u8>) -> Self {
        let (exit, exit_rx) = oneshot::channel();
        Self {
            control: Arc::new(EscalatingControl {
                signals: Mutex::new(Vec::new()),
                exit: Mutex::new(Some(exit)),
            }),
            exit_rx: Mutex::new(Some(exit_rx)),
            output: Mutex::new(Some(output)),
            stderr: Mutex::new(None),
            input_dropped: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    fn with_stderr(stderr: Vec<u8>) -> Self {
        let launcher = Self::new(Vec::new());
        *launcher.stderr.lock().unwrap() = Some(stderr);
        launcher
    }
}

struct TrackingInput {
    dropped: Arc<std::sync::atomic::AtomicBool>,
}

impl tokio::io::AsyncWrite for TrackingInput {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::task::Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl Drop for TrackingInput {
    fn drop(&mut self) {
        self.dropped
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

impl SessionLauncher for TermIgnoringLauncher {
    fn launch(
        &self,
        _args: crate::incubator::IncubatorArgs,
    ) -> Result<LaunchedSession, SessionHandlerError> {
        let (mut output_writer, output_reader) = tokio::io::duplex(4096);
        let output = self.output.lock().unwrap().take().unwrap_or_default();
        tokio::spawn(async move {
            let _ = tokio::io::AsyncWriteExt::write_all(&mut output_writer, &output).await;
        });
        let (mut stderr_writer, stderr_reader) = tokio::io::duplex(4096);
        let stderr = self.stderr.lock().unwrap().take().unwrap_or_default();
        tokio::spawn(async move {
            let _ = tokio::io::AsyncWriteExt::write_all(&mut stderr_writer, &stderr).await;
        });
        let exit_rx = self.exit_rx.lock().unwrap().take().unwrap();
        Ok(LaunchedSession {
            input: Some(Box::new(TrackingInput {
                dropped: self.input_dropped.clone(),
            })),
            output: Some(Box::new(output_reader)),
            stderr: Some(Box::new(stderr_reader)),
            wait: Box::pin(async move {
                exit_rx
                    .await
                    .map_err(|_| io::Error::other("fake process waiter closed"))
            }),
            control: self.control.clone(),
        })
    }
}

#[derive(Clone, Default)]
struct CaptureWriter {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl io::Write for CaptureWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.bytes.lock().unwrap().extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct FailAfterHeader {
    wrote_header: bool,
}

impl io::Write for FailAfterHeader {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.wrote_header {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "injected recorder failure",
            ))
        } else {
            self.wrote_header = true;
            Ok(data.len())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn non_pty_stderr_is_recorded_before_client_forwarding() {
    let writer = CaptureWriter::default();
    let captured = writer.bytes.clone();
    let recorder = crate::SessionRecorder::with_test_writer(
        Box::new(writer),
        crate::CastHeader::new(
            (0, 0),
            "command".into(),
            std::collections::HashMap::new(),
            "requested".into(),
            "mapped".into(),
            "connection".into(),
        ),
        true,
    )
    .unwrap();
    let recorder = Mutex::new(Some(recorder));
    let mutate = |init: &mut crate::session::SessionInit| {
        init.recorder = recorder.lock().unwrap().take();
    };
    let requested_user = std::env::var("USER").unwrap_or_else(|_| "testuser".to_string());
    let (code, output) = run_pipeline_custom(
        "printf 'stdout-transcript'; printf 'stderr-transcript' >&2",
        &requested_user,
        policy_allow_any(),
        None,
        Some(&mutate),
        false,
        false,
    )
    .await;
    assert_eq!(code, 0);
    let transcript = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
    assert!(transcript.contains("stdout-transcript"));
    assert!(transcript.contains("stderr-transcript"));
    assert!(output
        .windows(b"stderr-transcript".len())
        .any(|window| window == b"stderr-transcript"));
}

#[tokio::test]
async fn fail_closed_drops_failed_chunk_and_escalates_whole_group() {
    let launcher = TermIgnoringLauncher::new(b"must-not-be-delivered".to_vec());
    let recorder = crate::SessionRecorder::with_test_writer(
        Box::new(FailAfterHeader {
            wrote_header: false,
        }),
        crate::CastHeader::new(
            (0, 0),
            "command".into(),
            std::collections::HashMap::new(),
            "requested".into(),
            "mapped".into(),
            "connection".into(),
        ),
        false,
    )
    .unwrap();
    let recorder = Mutex::new(Some(recorder));
    let mutate = |init: &mut crate::session::SessionInit| {
        init.recorder = recorder.lock().unwrap().take();
        init.recording_config = Some(crate::RecordingConfig {
            on_failure: Some(rustscale_tailcfg::SSHRecorderFailureAction {
                TerminateSessionWithMessage: "recording required".into(),
                ..Default::default()
            }),
            ..Default::default()
        });
    };
    let resolver = |_name: &str| {
        Ok(LocalUser {
            uid: 1000,
            gid: 1000,
            gids: vec![1000],
            name: "mapped".into(),
            home_dir: "/tmp".into(),
            shell: "/bin/sh".into(),
        })
    };

    let (code, output) = run_pipeline_custom(
        "ignored",
        "requested",
        policy_map_any("mapped"),
        Some((&resolver, &launcher)),
        Some(&mutate),
        false,
        false,
    )
    .await;
    assert_eq!(code, 1);
    assert!(!output
        .windows(b"must-not-be-delivered".len())
        .any(|window| window == b"must-not-be-delivered"));
    assert!(output
        .windows(b"recording required".len())
        .any(|window| window == b"recording required"));
    assert_eq!(
        &*launcher.control.signals.lock().unwrap(),
        &[libc::SIGTERM, libc::SIGKILL]
    );
}

#[tokio::test]
async fn fail_closed_stderr_chunk_is_suppressed() {
    let launcher = TermIgnoringLauncher::with_stderr(b"stderr-must-not-be-delivered".to_vec());
    let recorder = crate::SessionRecorder::with_test_writer(
        Box::new(FailAfterHeader {
            wrote_header: false,
        }),
        crate::CastHeader::new(
            (0, 0),
            "command".into(),
            std::collections::HashMap::new(),
            "requested".into(),
            "mapped".into(),
            "connection".into(),
        ),
        false,
    )
    .unwrap();
    let recorder = Mutex::new(Some(recorder));
    let mutate = |init: &mut crate::session::SessionInit| {
        init.recorder = recorder.lock().unwrap().take();
        init.recording_config = Some(crate::RecordingConfig {
            on_failure: Some(rustscale_tailcfg::SSHRecorderFailureAction {
                TerminateSessionWithMessage: "recording required".into(),
                ..Default::default()
            }),
            ..Default::default()
        });
    };
    let resolver = |_name: &str| {
        Ok(LocalUser {
            uid: 1000,
            gid: 1000,
            gids: vec![1000],
            name: "mapped".into(),
            home_dir: "/tmp".into(),
            shell: "/bin/sh".into(),
        })
    };

    let (code, output) = run_pipeline_custom(
        "ignored",
        "requested",
        policy_map_any("mapped"),
        Some((&resolver, &launcher)),
        Some(&mutate),
        false,
        false,
    )
    .await;
    assert_eq!(code, 1);
    assert!(!output
        .windows(b"stderr-must-not-be-delivered".len())
        .any(|window| window == b"stderr-must-not-be-delivered"));
    assert_eq!(
        &*launcher.control.signals.lock().unwrap(),
        &[libc::SIGTERM, libc::SIGKILL]
    );
}

#[tokio::test]
async fn zero_session_duration_does_not_cancel_session() {
    let code = run_pipeline("sleep 0.1; exit 0").await;
    assert_eq!(code, 0);
}

#[tokio::test]
async fn session_duration_terminates_and_escalates_process_group() {
    let launcher = TermIgnoringLauncher::new(Vec::new());
    let resolver = |_name: &str| {
        Ok(LocalUser {
            uid: 1000,
            gid: 1000,
            gids: vec![1000],
            name: "mapped".into(),
            home_dir: "/tmp".into(),
            shell: "/bin/sh".into(),
        })
    };
    let policy = policy_for("mapped", std::time::Duration::from_millis(50));
    let policy: Arc<dyn Fn() -> Option<SSHPolicy> + Send + Sync> =
        Arc::new(move || Some(policy.clone()));

    let (code, output) = run_pipeline_custom(
        "ignored",
        "requested",
        policy,
        Some((&resolver, &launcher)),
        None,
        false,
        false,
    )
    .await;
    assert_eq!(code, 1);
    assert!(String::from_utf8_lossy(&output).contains("Session timeout"));
    assert_eq!(
        &*launcher.control.signals.lock().unwrap(),
        &[libc::SIGTERM, libc::SIGKILL]
    );
}

#[tokio::test]
async fn live_policy_revocation_terminates_existing_session() {
    let launcher = TermIgnoringLauncher::new(Vec::new());
    let resolver = |_name: &str| {
        Ok(LocalUser {
            uid: 1000,
            gid: 1000,
            gids: vec![1000],
            name: "mapped".into(),
            home_dir: "/tmp".into(),
            shell: "/bin/sh".into(),
        })
    };
    let current_policy = Arc::new(Mutex::new(Some(policy_for(
        "mapped",
        std::time::Duration::ZERO,
    ))));
    let policy: Arc<dyn Fn() -> Option<SSHPolicy> + Send + Sync> = {
        let current_policy = current_policy.clone();
        Arc::new(move || current_policy.lock().unwrap().clone())
    };
    let revoke = {
        let current_policy = current_policy.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            *current_policy.lock().unwrap() = Some(SSHPolicy::default());
        })
    };

    let (code, output) = run_pipeline_custom(
        "ignored",
        "requested",
        policy,
        Some((&resolver, &launcher)),
        None,
        false,
        false,
    )
    .await;
    revoke.await.unwrap();
    assert_eq!(code, 1);
    assert!(String::from_utf8_lossy(&output).contains("Access revoked"));
    assert_eq!(
        &*launcher.control.signals.lock().unwrap(),
        &[libc::SIGTERM, libc::SIGKILL]
    );
}

#[tokio::test]
async fn client_eof_closes_stdin_and_cleans_up_term_ignoring_process() {
    let launcher = TermIgnoringLauncher::new(Vec::new());
    let resolver = |_name: &str| {
        Ok(LocalUser {
            uid: 1000,
            gid: 1000,
            gids: vec![1000],
            name: "mapped".into(),
            home_dir: "/tmp".into(),
            shell: "/bin/sh".into(),
        })
    };

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(7),
        run_pipeline_custom(
            "ignored",
            "requested",
            policy_map_any("mapped"),
            Some((&resolver, &launcher)),
            None,
            true,
            false,
        ),
    )
    .await
    .expect("EOF cleanup must be bounded");
    assert_eq!(result.0, 1);
    assert!(launcher
        .input_dropped
        .load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(
        &*launcher.control.signals.lock().unwrap(),
        &[libc::SIGTERM, libc::SIGKILL]
    );
}

#[tokio::test]
async fn watcher_full_pipeline() {
    // "echo hello" should exit 0.
    let code = run_pipeline("echo hello").await;
    assert_eq!(code, 0);
}

#[tokio::test]
async fn test_run_session_shell_command() {
    let code = run_pipeline("echo hello").await;
    assert_eq!(code, 0);
}

#[tokio::test]
async fn test_run_session_exit_code() {
    let code = run_pipeline("exit 42").await;
    assert_eq!(code, 42);
}

#[tokio::test]
async fn normal_exit_drains_trailing_output_before_channel_close() {
    let (code, output) = run_pipeline_output("printf 'trailing-output'").await;
    assert_eq!(code, 0);
    assert!(
        output
            .windows(b"trailing-output".len())
            .any(|window| window == b"trailing-output"),
        "missing trailing output: {:?}",
        String::from_utf8_lossy(&output)
    );
}

#[cfg(unix)]
#[tokio::test]
async fn normal_exit_drains_output_then_kills_background_descendant() {
    let (code, output) = run_pipeline_output(
        "printf 'before-background\\n'; (trap '' TERM; sleep 30) >/dev/null 2>&1 & echo $!",
    )
    .await;
    assert_eq!(code, 0);
    let output = String::from_utf8_lossy(&output);
    assert!(output.contains("before-background"));
    let descendant = output
        .lines()
        .find_map(|line| line.trim().parse::<u32>().ok())
        .expect("background pid in drained output");
    let status = tokio::process::Command::new("kill")
        .args(["-0", &descendant.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .expect("kill -0");
    assert!(
        !status.success(),
        "background descendant survived normal exit"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn normal_exit_drains_trailing_pty_output_before_channel_close() {
    let requested_user = std::env::var("USER").unwrap_or_else(|_| "testuser".to_string());
    let (code, output) = run_pipeline_custom(
        "printf 'trailing-pty'",
        &requested_user,
        policy_allow_any(),
        None,
        None,
        false,
        true,
    )
    .await;
    assert_eq!(code, 0);
    assert!(
        output
            .windows(b"trailing-pty".len())
            .any(|window| window == b"trailing-pty"),
        "missing trailing PTY output: {:?}",
        String::from_utf8_lossy(&output)
    );
}
