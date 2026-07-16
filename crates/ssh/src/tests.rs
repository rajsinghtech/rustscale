//! Integration tests for the SSH crate — verifies the full pipeline
//! (SshServer → SshHandler → Session → run_session) without network I/O.
//!
//! These tests use `tokio::io::duplex` to connect a russh client and server
//! in-memory, then verify that `run_session` correctly spawns the shell,
//! pumps I/O, and reports exit status.

#![cfg(unix)]

use crate::host_key_from_node_key;
use crate::session_handler::{
    run_session, run_session_with, LaunchStarted, LaunchedSession, LocalUser, ProcessControl,
    SessionHandlerError, SessionLauncher, UserResolver,
};
use crate::{Session, SshServer, SshServerConfig};
use russh::server::Server as _;
use russh::{ChannelMsg, MethodSet};
use rustscale_key::{NodePrivate, NodePublic};
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
    injected: Option<(Arc<UserResolver>, Arc<dyn SessionLauncher>)>,
    mutate_session: Option<&dyn Fn(&mut crate::session::SessionInit)>,
    client_close_before_run: bool,
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
        recording_notify: None,
        node_key: NodePublic::default(),
        capability_version: 0,
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
    if client_close_before_run {
        channel.close().await.expect("channel close");
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
            .unwrap_or(1)
    } else {
        run_session(session, None).await.unwrap_or(1)
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

#[tokio::test]
async fn data_before_start_and_eof_are_drained_as_an_input_half_close() {
    let host_key = host_key_from_node_key(&NodePrivate::generate());
    let (session_tx, mut session_rx) = mpsc::channel::<crate::session::SessionInit>(4);
    let config = SshServerConfig {
        host_keys: vec![host_key],
        session_tx,
        whois: whois_finds_peer(),
        policy: policy_allow_any(),
        state_dir: None,
        dial_fn: None,
        recording_notify: None,
        node_key: NodePublic::default(),
        capability_version: 0,
    };
    let mut server = SshServer::new(config);
    let server_config = server.russh_config();
    let (client_io, server_io) = tokio::io::duplex(32 * 1024);
    let handler = server.new_client(Some(SocketAddr::new(peer_ip(), 22)));
    tokio::spawn(async move {
        let running = russh::server::run_stream(server_config, server_io, handler)
            .await
            .unwrap();
        let _ = running.await;
    });
    let mut client = russh::client::connect_stream(
        Arc::new(russh::client::Config::default()),
        client_io,
        ClientHandler,
    )
    .await
    .unwrap();
    let requested_user = std::env::var("USER").unwrap_or_else(|_| "testuser".into());
    assert!(client
        .authenticate_password(&requested_user, "")
        .await
        .unwrap()
        .success());

    let mut channel = client.channel_open_session().await.unwrap();
    channel.data_bytes(b"first-".as_slice()).await.unwrap();
    channel.data_bytes(b"second".as_slice()).await.unwrap();
    channel
        .exec(true, b"cat; printf ':after-eof'")
        .await
        .unwrap();
    channel.eof().await.unwrap();

    let init = session_rx.recv().await.unwrap();
    let result = run_session(Session::from_init(init), None).await.unwrap();
    let mut output = Vec::new();
    let mut exit = None;
    while let Some(message) = channel.wait().await {
        match message {
            ChannelMsg::Data { data } => output.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status as i32),
            _ => {}
        }
    }
    assert_eq!(exit.unwrap_or(result), 0);
    assert_eq!(output, b"first-second:after-eof");

    let mut pty_channel = client.channel_open_session().await.unwrap();
    pty_channel
        .request_pty(false, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    pty_channel
        .data_bytes(b"unterminated-canonical-input".as_slice())
        .await
        .unwrap();
    pty_channel
        .exec(true, b"cat; printf ':pty-after-eof'")
        .await
        .unwrap();
    pty_channel.eof().await.unwrap();
    let init = session_rx.recv().await.unwrap();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        run_session(Session::from_init(init), None),
    )
    .await
    .expect("PTY EOF did not terminate canonical input")
    .unwrap();
    let mut output = Vec::new();
    let mut exit = None;
    while let Some(message) = pty_channel.wait().await {
        match message {
            ChannelMsg::Data { data } => output.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status as i32),
            _ => {}
        }
    }
    assert_eq!(exit.unwrap_or(result), 0);
    assert!(
        output
            .windows(b":pty-after-eof".len())
            .any(|window| window == b":pty-after-eof"),
        "PTY response missing: {}",
        String::from_utf8_lossy(&output)
    );
}

#[tokio::test]
async fn local_recording_path_failure_exits_closes_and_removes_channel_state() {
    let blocked_root = std::env::temp_dir().join(format!(
        "rustscale-ssh-recording-root-file-{}",
        std::process::id()
    ));
    std::fs::write(&blocked_root, b"not a directory").unwrap();
    let host_key = host_key_from_node_key(&NodePrivate::generate());
    let (session_tx, mut session_rx) = mpsc::channel::<crate::session::SessionInit>(2);
    let config = SshServerConfig {
        host_keys: vec![host_key],
        session_tx,
        whois: whois_finds_peer(),
        policy: policy_allow_any(),
        state_dir: Some(blocked_root.clone()),
        dial_fn: None,
        recording_notify: None,
        node_key: NodePublic::default(),
        capability_version: 0,
    };
    let mut server = SshServer::new(config);
    let server_config = server.russh_config();
    let (client_io, server_io) = tokio::io::duplex(16 * 1024);
    let handler = server.new_client(Some(SocketAddr::new(peer_ip(), 22)));
    tokio::spawn(async move {
        let running = russh::server::run_stream(server_config, server_io, handler)
            .await
            .unwrap();
        let _ = running.await;
    });
    let mut client = russh::client::connect_stream(
        Arc::new(russh::client::Config::default()),
        client_io,
        ClientHandler,
    )
    .await
    .unwrap();
    assert!(client
        .authenticate_password("alice", "")
        .await
        .unwrap()
        .success());
    let mut channel = client.channel_open_session().await.unwrap();
    channel.exec(true, b"ignored").await.unwrap();
    let exit = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        let mut exit = None;
        while let Some(message) = channel.wait().await {
            if let ChannelMsg::ExitStatus { exit_status } = message {
                exit = Some(exit_status);
            }
        }
        exit
    })
    .await
    .expect("local recording path failure left the channel open");
    assert_eq!(exit, Some(1));
    assert!(session_rx.try_recv().is_err());

    let mut channels = Vec::new();
    for _ in 0..16 {
        channels.push(client.channel_open_session().await.unwrap());
    }
    for channel in &channels {
        channel.close().await.unwrap();
    }
    let _ = std::fs::remove_file(blocked_root);
}

#[tokio::test]
async fn dropping_unfinished_session_reports_failure_and_closes_channel() {
    let host_key = host_key_from_node_key(&NodePrivate::generate());
    let (session_tx, mut session_rx) = mpsc::channel::<crate::session::SessionInit>(2);
    let config = SshServerConfig {
        host_keys: vec![host_key],
        session_tx,
        whois: whois_finds_peer(),
        policy: policy_allow_any(),
        state_dir: None,
        dial_fn: None,
        recording_notify: None,
        node_key: NodePublic::default(),
        capability_version: 0,
    };
    let mut server = SshServer::new(config);
    let server_config = server.russh_config();
    let (client_io, server_io) = tokio::io::duplex(16 * 1024);
    let handler = server.new_client(Some(SocketAddr::new(peer_ip(), 22)));
    tokio::spawn(async move {
        let running = russh::server::run_stream(server_config, server_io, handler)
            .await
            .unwrap();
        let _ = running.await;
    });
    let mut client = russh::client::connect_stream(
        Arc::new(russh::client::Config::default()),
        client_io,
        ClientHandler,
    )
    .await
    .unwrap();
    assert!(client
        .authenticate_password("alice", "")
        .await
        .unwrap()
        .success());
    let mut channel = client.channel_open_session().await.unwrap();
    channel.exec(true, b"ignored").await.unwrap();
    let unfinished = Session::from_init(session_rx.recv().await.unwrap());
    std::thread::spawn(move || drop(unfinished)).join().unwrap();

    let exit = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        let mut exit = None;
        while let Some(message) = channel.wait().await {
            if let ChannelMsg::ExitStatus { exit_status } = message {
                exit = Some(exit_status);
            }
        }
        exit
    })
    .await
    .expect("Session drop did not close the SSH channel");
    assert_eq!(exit, Some(1));
}

#[tokio::test]
async fn stalled_stdin_overflow_does_not_block_other_multiplexed_channel_state() {
    let host_key = host_key_from_node_key(&NodePrivate::generate());
    let (session_tx, mut session_rx) = mpsc::channel::<crate::session::SessionInit>(16);
    let mut policy = policy_for("=", std::time::Duration::ZERO);
    policy.Rules[0].Action.as_mut().unwrap().Recorders = vec!["100.64.0.9:80".parse().unwrap()];
    let config = SshServerConfig {
        host_keys: vec![host_key],
        session_tx,
        whois: whois_finds_peer(),
        policy: Arc::new(move || Some(policy.clone())),
        state_dir: None,
        dial_fn: None,
        recording_notify: None,
        node_key: NodePublic::default(),
        capability_version: 0,
    };
    let mut server = SshServer::new(config);
    let server_config = server.russh_config();
    let (client_io, server_io) = tokio::io::duplex(32 * 1024);
    let handler = server.new_client(Some(SocketAddr::new(peer_ip(), 22)));
    tokio::spawn(async move {
        let running = russh::server::run_stream(server_config, server_io, handler)
            .await
            .unwrap();
        let _ = running.await;
    });
    let mut client = russh::client::connect_stream(
        Arc::new(russh::client::Config::default()),
        client_io,
        ClientHandler,
    )
    .await
    .unwrap();
    assert!(client
        .authenticate_password("alice", "")
        .await
        .unwrap()
        .success());

    let channel_one = client.channel_open_session().await.unwrap();
    let channel_two = client.channel_open_session().await.unwrap();
    let mut extra_channels = Vec::new();
    for _ in 0..14 {
        extra_channels.push(client.channel_open_session().await.unwrap());
    }
    assert!(client.channel_open_session().await.is_err());
    for channel in &extra_channels {
        channel.close().await.unwrap();
    }
    drop(extra_channels);
    let replacement = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if let Ok(channel) = client.channel_open_session().await {
                break channel;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("closed channels were not removed from the bounded map");
    replacement.close().await.unwrap();
    drop(replacement);

    channel_one.set_env(false, "LANG", "one").await.unwrap();
    for index in 0..100 {
        channel_one
            .set_env(false, "LANG", format!("replacement-{index}"))
            .await
            .unwrap();
    }
    for index in 0..63 {
        channel_one
            .set_env(false, format!("LC_FLOOD_{index}"), "value")
            .await
            .unwrap();
    }
    channel_one
        .set_env(false, "LC_EXCESS", "must-not-be-stored")
        .await
        .unwrap();
    channel_one
        .set_env(false, "LC_BAD\n", "must-not-be-stored")
        .await
        .unwrap();
    channel_one
        .set_env(false, "LC_BAD", "line\nvalue")
        .await
        .unwrap();
    channel_one
        .set_env(false, format!("LC_{}", "X".repeat(128)), "too-long")
        .await
        .unwrap();
    channel_one
        .set_env(false, "LC_TOO_LARGE", "x".repeat(4097))
        .await
        .unwrap();
    channel_two.set_env(false, "LANG", "two").await.unwrap();
    channel_one
        .request_pty(false, "term-one", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    channel_two
        .request_pty(false, "term-two", 120, 40, 0, 0, &[])
        .await
        .unwrap();
    channel_one.exec(true, b"command-one").await.unwrap();
    channel_two.exec(true, b"command-two").await.unwrap();

    let mut one = session_rx.recv().await.unwrap();
    let mut two = session_rx.recv().await.unwrap();
    if one.command == "command-two" {
        std::mem::swap(&mut one, &mut two);
    }
    assert_eq!(one.command, "command-one");
    assert_eq!(two.command, "command-two");
    assert_eq!(one.env.len(), 64);
    assert_eq!(
        one.env.iter().find(|(name, _)| name == "LANG").unwrap().1,
        "replacement-99"
    );
    assert!(!one.env.iter().any(|(name, _)| name == "LC_EXCESS"));
    assert_eq!(two.env, [("LANG".into(), "two".into())]);
    assert_eq!(one.pty.as_ref().unwrap().term, "term-one");
    assert_eq!(two.pty.as_ref().unwrap().term, "term-two");
    assert_eq!(one.recording_config.as_ref().unwrap().recorders.len(), 1);
    assert_eq!(two.recording_config.as_ref().unwrap().recorders.len(), 1);
    assert_eq!(
        one.recording_header.as_ref().unwrap().command,
        "command-one"
    );
    assert_eq!(
        two.recording_header.as_ref().unwrap().command,
        "command-two"
    );

    channel_one
        .data_bytes(b"input-one".as_slice())
        .await
        .unwrap();
    channel_two
        .data_bytes(b"input-two".as_slice())
        .await
        .unwrap();
    channel_one.signal(russh::Sig::INT).await.unwrap();
    channel_two.signal(russh::Sig::TERM).await.unwrap();
    channel_one.window_change(81, 25, 1, 2).await.unwrap();
    channel_two.window_change(121, 41, 3, 4).await.unwrap();
    assert_eq!(one.data_rx.recv().await.unwrap(), b"input-one");
    assert_eq!(two.data_rx.recv().await.unwrap(), b"input-two");
    assert!(matches!(one.signal_rx.recv().await, Some(russh::Sig::INT)));
    assert!(matches!(two.signal_rx.recv().await, Some(russh::Sig::TERM)));
    assert_eq!(one.window_change_rx.recv().await.unwrap().width, 81);
    assert_eq!(two.window_change_rx.recv().await.unwrap().width, 121);

    // Stop consuming channel one's stdin and overflow only its bounded queue.
    // The handler must close/cancel it without blocking callbacks for channel two.
    let saturate = async {
        for _ in 0..128 {
            if channel_one.data_bytes(b"stalled".as_slice()).await.is_err() {
                break;
            }
        }
    };
    tokio::pin!(saturate);
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        tokio::select! {
            changed = one.cancel_rx.changed() => changed.unwrap(),
            () = &mut saturate => one.cancel_rx.changed().await.unwrap(),
        }
    })
    .await
    .expect("stalled channel overflow blocked cancellation");
    assert!(*one.cancel_rx.borrow());
    assert!(!*two.cancel_rx.borrow());

    channel_two
        .data_bytes(b"still-responsive".as_slice())
        .await
        .unwrap();
    channel_two.signal(russh::Sig::KILL).await.unwrap();
    channel_two.window_change(122, 42, 5, 6).await.unwrap();
    assert_eq!(two.data_rx.recv().await.unwrap(), b"still-responsive");
    assert!(matches!(two.signal_rx.recv().await, Some(russh::Sig::KILL)));
    assert_eq!(two.window_change_rx.recv().await.unwrap().width, 122);
    channel_two.close().await.unwrap();
    two.cancel_rx.changed().await.unwrap();
    assert!(*two.cancel_rx.borrow());
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

    fn group_exists(&self) -> io::Result<bool> {
        Ok(false)
    }
}

struct FailingLauncher;

impl SessionLauncher for FailingLauncher {
    fn launch(
        &self,
        _args: crate::incubator::IncubatorArgs,
        _started: LaunchStarted,
    ) -> Result<LaunchedSession, SessionHandlerError> {
        Err(io::Error::other("injected launcher failure").into())
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
        started: LaunchStarted,
    ) -> Result<LaunchedSession, SessionHandlerError> {
        self.args.lock().unwrap().push(args);
        let control: Arc<dyn ProcessControl> = Arc::new(NoopProcessControl);
        started(control.clone());
        Ok(LaunchedSession {
            input: Some(Box::new(tokio::io::sink())),
            output: Some(Box::new(tokio::io::empty())),
            stderr: Some(Box::new(tokio::io::empty())),
            wait: Box::pin(async { Ok(0) }),
            control,
        })
    }
}

fn mapped_test_user() -> LocalUser {
    LocalUser {
        uid: 1000,
        gid: 1000,
        gids: vec![1000],
        name: "mapped".into(),
        home_dir: "/tmp".into(),
        shell: "/bin/sh".into(),
    }
}

fn mapped_test_resolver() -> Arc<UserResolver> {
    Arc::new(|_name: String| Ok(mapped_test_user()))
}

#[tokio::test]
async fn injected_prelaunch_failures_report_nonzero_and_close_channels() {
    let user_error: Arc<UserResolver> = Arc::new(|_name: String| {
        Err(SessionHandlerError::LocalUser(
            "injected user lookup failure".into(),
        ))
    });
    let (code, _) = run_pipeline_custom(
        "ignored",
        "requested",
        policy_map_any("mapped"),
        Some((user_error, Arc::new(CapturingLauncher::default()))),
        None,
        false,
        false,
    )
    .await;
    assert_eq!(code, 1);

    let pty_failure = |init: &mut crate::session::SessionInit| {
        init.fail_pty_setup = true;
    };
    let launcher = Arc::new(CapturingLauncher::default());
    let (code, _) = run_pipeline_custom(
        "ignored",
        "requested",
        policy_map_any("mapped"),
        Some((mapped_test_resolver(), launcher.clone())),
        Some(&pty_failure),
        false,
        true,
    )
    .await;
    assert_eq!(code, 1);
    assert!(launcher.args.lock().unwrap().is_empty());

    let (code, _) = run_pipeline_custom(
        "ignored",
        "requested",
        policy_map_any("mapped"),
        Some((mapped_test_resolver(), Arc::new(FailingLauncher))),
        None,
        false,
        false,
    )
    .await;
    assert_eq!(code, 1);

    let recorder_failure = |init: &mut crate::session::SessionInit| {
        init.recording_config = Some(crate::RecordingConfig {
            recorders: vec!["100.64.0.9:80".parse().unwrap()],
            fail_open: false,
            on_failure: Some(rustscale_tailcfg::SSHRecorderFailureAction {
                RejectSessionWithMessage: "recording unavailable".into(),
                ..Default::default()
            }),
            ..Default::default()
        });
        init.recording_header = Some(crate::CastHeader::new(
            (0, 0),
            "ignored".into(),
            std::collections::HashMap::new(),
            "requested".into(),
            "mapped".into(),
            "connection".into(),
        ));
        init.recording_dial = Some(Arc::new(|_| {
            Box::pin(async { Err(io::Error::other("injected recorder failure")) })
        }));
    };
    let (code, output) = run_pipeline_custom(
        "ignored",
        "requested",
        policy_map_any("mapped"),
        Some((
            mapped_test_resolver(),
            Arc::new(CapturingLauncher::default()),
        )),
        Some(&recorder_failure),
        false,
        false,
    )
    .await;
    assert_eq!(code, 1);
    assert!(String::from_utf8_lossy(&output).contains("recording unavailable"));

    let local_open_failure = |init: &mut crate::session::SessionInit| {
        init.recording_config = Some(crate::RecordingConfig {
            local_path: Some(std::env::temp_dir()),
            fail_open: false,
            ..Default::default()
        });
        init.recording_header = Some(crate::CastHeader::new(
            (0, 0),
            "ignored".into(),
            std::collections::HashMap::new(),
            "requested".into(),
            "mapped".into(),
            "connection".into(),
        ));
    };
    let (code, output) = run_pipeline_custom(
        "ignored",
        "requested",
        policy_map_any("mapped"),
        Some((
            mapped_test_resolver(),
            Arc::new(CapturingLauncher::default()),
        )),
        Some(&local_open_failure),
        false,
        false,
    )
    .await;
    assert_eq!(code, 1);
    assert!(String::from_utf8_lossy(&output).contains("recording required"));
}

#[tokio::test]
async fn blocker_timeout_reports_nonzero_and_closes_channel() {
    let resolver: Arc<UserResolver> = Arc::new(|_name: String| {
        std::thread::sleep(std::time::Duration::from_millis(1500));
        Ok(mapped_test_user())
    });
    let launcher = Arc::new(CapturingLauncher::default());
    let (code, output) = run_pipeline_custom(
        "ignored",
        "requested",
        policy_map_any("mapped"),
        Some((resolver, launcher.clone())),
        None,
        false,
        false,
    )
    .await;
    assert_eq!(code, 1);
    assert!(String::from_utf8_lossy(&output).contains("initialization timed out"));
    assert!(launcher.args.lock().unwrap().is_empty());
}

#[tokio::test]
async fn policy_mapped_local_user_is_resolved_and_launched_not_requested_user() {
    let launcher = Arc::new(CapturingLauncher::default());
    let resolved = Arc::new(Mutex::new(Vec::new()));
    let resolver: Arc<UserResolver> = {
        let resolved = resolved.clone();
        Arc::new(move |name: String| {
            resolved.lock().unwrap().push(name.clone());
            Ok(LocalUser {
                uid: 65_534,
                gid: 65_534,
                gids: vec![65_534],
                name: "nobody".into(),
                home_dir: "/nonexistent".into(),
                shell: "/bin/sh".into(),
            })
        })
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
        Some((resolver.clone(), launcher.clone())),
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

    fn group_exists(&self) -> io::Result<bool> {
        Ok(self.exit.lock().unwrap().is_some())
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

#[derive(Default)]
struct BlockingGate {
    released: Mutex<bool>,
    changed: std::sync::Condvar,
}

impl BlockingGate {
    fn wait(&self) {
        let released = self.released.lock().unwrap();
        let _ = self
            .changed
            .wait_timeout_while(released, std::time::Duration::from_secs(5), |released| {
                !*released
            })
            .unwrap();
    }

    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.changed.notify_all();
    }
}

struct GatedLauncher {
    inner: Arc<TermIgnoringLauncher>,
    gate: Arc<BlockingGate>,
    entered: Mutex<Option<oneshot::Sender<()>>>,
}

impl SessionLauncher for GatedLauncher {
    fn launch(
        &self,
        args: crate::incubator::IncubatorArgs,
        started: LaunchStarted,
    ) -> Result<LaunchedSession, SessionHandlerError> {
        // Model a child that exists and has a process group, then hangs in
        // post-fork setup before the launch call can return.
        started(self.inner.control.clone());
        if let Some(entered) = self.entered.lock().unwrap().take() {
            let _ = entered.send(());
        }
        self.gate.wait();
        self.inner.launch(args, Box::new(|_| {}))
    }
}

#[derive(Default)]
struct PersistentControl {
    signals: Mutex<Vec<libc::c_int>>,
}

impl ProcessControl for PersistentControl {
    fn signal_group(&self, signal: libc::c_int) -> io::Result<bool> {
        self.signals.lock().unwrap().push(signal);
        Ok(true)
    }

    fn group_exists(&self) -> io::Result<bool> {
        Ok(true)
    }
}

#[derive(Default)]
struct KillFailureControl {
    signals: Mutex<Vec<libc::c_int>>,
    exists: std::sync::atomic::AtomicBool,
}

impl ProcessControl for KillFailureControl {
    fn signal_group(&self, signal: libc::c_int) -> io::Result<bool> {
        self.signals.lock().unwrap().push(signal);
        if signal == libc::SIGKILL {
            self.exists
                .store(false, std::sync::atomic::Ordering::SeqCst);
            Err(io::Error::other("injected SIGKILL failure"))
        } else {
            self.exists.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(true)
        }
    }

    fn group_exists(&self) -> io::Result<bool> {
        Ok(self.exists.load(std::sync::atomic::Ordering::SeqCst))
    }
}

struct CompletedLauncher {
    control: Arc<KillFailureControl>,
}

impl SessionLauncher for CompletedLauncher {
    fn launch(
        &self,
        _args: crate::incubator::IncubatorArgs,
        started: LaunchStarted,
    ) -> Result<LaunchedSession, SessionHandlerError> {
        started(self.control.clone());
        Ok(LaunchedSession {
            input: Some(Box::new(tokio::io::sink())),
            output: Some(Box::new(tokio::io::empty())),
            stderr: Some(Box::new(tokio::io::empty())),
            wait: Box::pin(std::future::ready(Ok(0))),
            control: self.control.clone(),
        })
    }
}

struct PersistentLauncher {
    control: Arc<PersistentControl>,
}

impl SessionLauncher for PersistentLauncher {
    fn launch(
        &self,
        _args: crate::incubator::IncubatorArgs,
        started: LaunchStarted,
    ) -> Result<LaunchedSession, SessionHandlerError> {
        started(self.control.clone());
        Ok(LaunchedSession {
            input: Some(Box::new(tokio::io::sink())),
            output: Some(Box::new(tokio::io::empty())),
            stderr: Some(Box::new(tokio::io::empty())),
            wait: Box::pin(std::future::pending()),
            control: self.control.clone(),
        })
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
        started: LaunchStarted,
    ) -> Result<LaunchedSession, SessionHandlerError> {
        started(self.control.clone());
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

#[derive(Default)]
struct FailFinalFlush {
    flushes: usize,
}

impl io::Write for FailFinalFlush {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flushes += 1;
        if self.flushes == 1 {
            Ok(())
        } else {
            Err(io::Error::other("injected final recorder close failure"))
        }
    }
}

struct FinalErrorWriter {
    result: Option<oneshot::Sender<io::Result<()>>>,
}

impl io::Write for FinalErrorWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for FinalErrorWriter {
    fn drop(&mut self) {
        if let Some(result) = self.result.take() {
            let _ = result.send(Err(io::Error::other("injected final upload failure")));
        }
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
async fn mandatory_final_recorder_close_failure_returns_non_success() {
    let recorder = crate::SessionRecorder::with_test_writer(
        Box::new(FailFinalFlush::default()),
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
            fail_open: false,
            on_failure: Some(rustscale_tailcfg::SSHRecorderFailureAction {
                TerminateSessionWithMessage: "recording required".into(),
                ..Default::default()
            }),
            ..Default::default()
        });
    };
    let requested_user = std::env::var("USER").unwrap_or_else(|_| "testuser".to_string());
    let (code, output) = run_pipeline_custom(
        "exit 0",
        &requested_user,
        policy_allow_any(),
        None,
        Some(&mutate),
        false,
        false,
    )
    .await;
    assert_eq!(code, 1);
    assert!(String::from_utf8_lossy(&output).contains("recording required"));
}

#[tokio::test]
async fn mandatory_final_upload_failure_returns_non_success() {
    let (result_tx, result_rx) = oneshot::channel();
    let recorder = crate::SessionRecorder::with_test_writer_result(
        Box::new(FinalErrorWriter {
            result: Some(result_tx),
        }),
        result_rx,
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
            fail_open: false,
            on_failure: Some(rustscale_tailcfg::SSHRecorderFailureAction {
                TerminateSessionWithMessage: "recording required".into(),
                ..Default::default()
            }),
            ..Default::default()
        });
    };
    let requested_user = std::env::var("USER").unwrap_or_else(|_| "testuser".to_string());
    let (code, output) = run_pipeline_custom(
        "printf 'recorded-before-finalize'",
        &requested_user,
        policy_allow_any(),
        None,
        Some(&mutate),
        false,
        false,
    )
    .await;
    assert_eq!(code, 1);
    assert!(String::from_utf8_lossy(&output).contains("recording required"));
}

#[tokio::test]
async fn mandatory_final_upload_timeout_returns_non_success() {
    let (result_tx, result_rx) = oneshot::channel();
    let recorder = crate::SessionRecorder::with_test_writer_result(
        Box::new(CaptureWriter::default()),
        result_rx,
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
            fail_open: false,
            on_failure: Some(rustscale_tailcfg::SSHRecorderFailureAction {
                TerminateSessionWithMessage: "recording required".into(),
                ..Default::default()
            }),
            ..Default::default()
        });
    };
    let requested_user = std::env::var("USER").unwrap_or_else(|_| "testuser".to_string());
    let (code, output) = run_pipeline_custom(
        "exit 0",
        &requested_user,
        policy_allow_any(),
        None,
        Some(&mutate),
        false,
        false,
    )
    .await;
    drop(result_tx);
    assert_eq!(code, 1);
    assert!(String::from_utf8_lossy(&output).contains("recording required"));
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
    let launcher = Arc::new(TermIgnoringLauncher::new(b"must-not-be-delivered".to_vec()));
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
    let resolver: Arc<UserResolver> = Arc::new(|_name: String| {
        Ok(LocalUser {
            uid: 1000,
            gid: 1000,
            gids: vec![1000],
            name: "mapped".into(),
            home_dir: "/tmp".into(),
            shell: "/bin/sh".into(),
        })
    });

    let (code, output) = run_pipeline_custom(
        "ignored",
        "requested",
        policy_map_any("mapped"),
        Some((resolver.clone(), launcher.clone())),
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
    let launcher = Arc::new(TermIgnoringLauncher::with_stderr(
        b"stderr-must-not-be-delivered".to_vec(),
    ));
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
    let resolver: Arc<UserResolver> = Arc::new(|_name: String| {
        Ok(LocalUser {
            uid: 1000,
            gid: 1000,
            gids: vec![1000],
            name: "mapped".into(),
            home_dir: "/tmp".into(),
            shell: "/bin/sh".into(),
        })
    });

    let (code, output) = run_pipeline_custom(
        "ignored",
        "requested",
        policy_map_any("mapped"),
        Some((resolver.clone(), launcher.clone())),
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
async fn duration_cancels_hung_nss_resolution_without_launching() {
    let launcher = Arc::new(CapturingLauncher::default());
    let gate = Arc::new(BlockingGate::default());
    let (entered_tx, entered_rx) = oneshot::channel();
    let entered = Arc::new(Mutex::new(Some(entered_tx)));
    let resolver: Arc<UserResolver> = {
        let entered = entered.clone();
        let gate = gate.clone();
        Arc::new(move |_name: String| {
            if let Some(entered) = entered.lock().unwrap().take() {
                let _ = entered.send(());
            }
            gate.wait();
            Ok(LocalUser {
                uid: 1000,
                gid: 1000,
                gids: vec![1000],
                name: "mapped".into(),
                home_dir: "/tmp".into(),
                shell: "/bin/sh".into(),
            })
        })
    };
    let policy = policy_for("mapped", std::time::Duration::from_millis(100));
    let policy: Arc<dyn Fn() -> Option<SSHPolicy> + Send + Sync> =
        Arc::new(move || Some(policy.clone()));
    let run = run_pipeline_custom(
        "ignored",
        "requested",
        policy,
        Some((resolver, launcher.clone())),
        None,
        false,
        false,
    );
    tokio::pin!(run);
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        tokio::select! {
            entered = entered_rx => entered.expect("NSS resolver entry signal dropped"),
            _ = &mut run => panic!("SSH pipeline completed before NSS resolver blocked"),
        }
    })
    .await
    .expect("NSS resolver did not start");
    let result = tokio::time::timeout(std::time::Duration::from_secs(1), &mut run).await;
    gate.release();
    let (code, output) = result.expect("duration did not cancel NSS resolution");
    assert_eq!(code, 1);
    assert!(String::from_utf8_lossy(&output).contains("Session timeout"));
    assert!(launcher.args.lock().unwrap().is_empty());
}

#[tokio::test]
async fn duration_kills_post_fork_child_while_launch_return_is_blocked() {
    let inner = Arc::new(TermIgnoringLauncher::new(Vec::new()));
    let gate = Arc::new(BlockingGate::default());
    let (entered_tx, entered_rx) = oneshot::channel();
    let launcher: Arc<dyn SessionLauncher> = Arc::new(GatedLauncher {
        inner: inner.clone(),
        gate: gate.clone(),
        entered: Mutex::new(Some(entered_tx)),
    });
    let resolver: Arc<UserResolver> = Arc::new(|_name: String| {
        Ok(LocalUser {
            uid: 1000,
            gid: 1000,
            gids: vec![1000],
            name: "mapped".into(),
            home_dir: "/tmp".into(),
            shell: "/bin/sh".into(),
        })
    });
    let policy = policy_for("mapped", std::time::Duration::from_millis(100));
    let policy: Arc<dyn Fn() -> Option<SSHPolicy> + Send + Sync> =
        Arc::new(move || Some(policy.clone()));
    let run = run_pipeline_custom(
        "ignored",
        "requested",
        policy,
        Some((resolver, launcher)),
        None,
        false,
        false,
    );
    tokio::pin!(run);
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        tokio::select! {
            entered = entered_rx => entered.expect("launcher entry signal dropped"),
            _ = &mut run => panic!("SSH pipeline completed before launcher blocked"),
        }
    })
    .await
    .expect("launcher did not start");
    let result = tokio::time::timeout(std::time::Duration::from_secs(1), &mut run).await;
    let (code, _) = result.expect("duration did not cancel process launch");
    assert_eq!(code, 1);
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if inner
                .control
                .signals
                .lock()
                .unwrap()
                .contains(&libc::SIGKILL)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("post-fork child was not killed while launch remained blocked");
    gate.release();
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while !inner
            .input_dropped
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("late launch result was not transferred to cleanup");
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert_eq!(
        &*inner.control.signals.lock().unwrap(),
        &[libc::SIGTERM, libc::SIGKILL],
        "launch cancellation must have exactly one signaling owner"
    );
}

#[tokio::test]
async fn aborting_session_future_kills_published_child_before_launcher_returns() {
    let inner = Arc::new(TermIgnoringLauncher::new(Vec::new()));
    let gate = Arc::new(BlockingGate::default());
    let (entered_tx, entered_rx) = oneshot::channel();
    let launcher: Arc<dyn SessionLauncher> = Arc::new(GatedLauncher {
        inner: inner.clone(),
        gate: gate.clone(),
        entered: Mutex::new(Some(entered_tx)),
    });
    let mut run = Box::pin(run_pipeline_custom(
        "ignored",
        "requested",
        policy_map_any("mapped"),
        Some((mapped_test_resolver(), launcher)),
        None,
        false,
        false,
    ));
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        tokio::select! {
            entered = entered_rx => entered.expect("launcher entry signal dropped"),
            _ = &mut run => panic!("session completed before launcher blocked"),
        }
    })
    .await
    .expect("launcher did not publish its child");
    drop(run);

    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if inner
                .control
                .signals
                .lock()
                .unwrap()
                .contains(&libc::SIGKILL)
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("aborted session did not clean up its published child");
    gate.release();
}

#[tokio::test]
async fn duration_cancels_hung_recorder_initialization_before_launch() {
    let launcher = Arc::new(CapturingLauncher::default());
    let resolver: Arc<UserResolver> = Arc::new(|_name: String| {
        Ok(LocalUser {
            uid: 1000,
            gid: 1000,
            gids: vec![1000],
            name: "mapped".into(),
            home_dir: "/tmp".into(),
            shell: "/bin/sh".into(),
        })
    });
    let dial: crate::DialFn = Arc::new(|_| Box::pin(std::future::pending()));
    let mutate = |init: &mut crate::session::SessionInit| {
        init.recording_config = Some(crate::RecordingConfig {
            recorders: vec!["100.64.0.9:80".parse().unwrap()],
            ..Default::default()
        });
        init.recording_header = Some(crate::CastHeader::new(
            (0, 0),
            "ignored".into(),
            std::collections::HashMap::new(),
            "requested".into(),
            "mapped".into(),
            "connection".into(),
        ));
        init.recording_dial = Some(dial.clone());
    };
    let policy = policy_for("mapped", std::time::Duration::from_millis(50));
    let policy: Arc<dyn Fn() -> Option<SSHPolicy> + Send + Sync> =
        Arc::new(move || Some(policy.clone()));
    let (code, output) = run_pipeline_custom(
        "ignored",
        "requested",
        policy,
        Some((resolver, launcher.clone())),
        Some(&mutate),
        false,
        false,
    )
    .await;
    assert_eq!(code, 1);
    assert!(String::from_utf8_lossy(&output).contains("Session timeout"));
    assert!(launcher.args.lock().unwrap().is_empty());
}

#[tokio::test]
async fn client_close_cancels_hung_recorder_initialization_before_launch() {
    let launcher = Arc::new(CapturingLauncher::default());
    let resolver: Arc<UserResolver> = Arc::new(|_name: String| {
        Ok(LocalUser {
            uid: 1000,
            gid: 1000,
            gids: vec![1000],
            name: "mapped".into(),
            home_dir: "/tmp".into(),
            shell: "/bin/sh".into(),
        })
    });
    let dial: crate::DialFn = Arc::new(|_| Box::pin(std::future::pending()));
    let mutate = |init: &mut crate::session::SessionInit| {
        init.recording_config = Some(crate::RecordingConfig {
            recorders: vec!["100.64.0.9:80".parse().unwrap()],
            ..Default::default()
        });
        init.recording_header = Some(crate::CastHeader::new(
            (0, 0),
            "ignored".into(),
            std::collections::HashMap::new(),
            "requested".into(),
            "mapped".into(),
            "connection".into(),
        ));
        init.recording_dial = Some(dial.clone());
    };
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        run_pipeline_custom(
            "ignored",
            "requested",
            policy_map_any("mapped"),
            Some((resolver, launcher.clone())),
            Some(&mutate),
            true,
            false,
        ),
    )
    .await
    .expect("client EOF did not cancel recorder initialization");
    assert_eq!(result.0, 1);
    assert!(launcher.args.lock().unwrap().is_empty());
}

#[tokio::test]
async fn zero_session_duration_does_not_cancel_session() {
    let code = run_pipeline("sleep 0.1; exit 0").await;
    assert_eq!(code, 0);
}

#[tokio::test]
async fn session_duration_terminates_and_escalates_process_group() {
    let launcher = Arc::new(TermIgnoringLauncher::new(Vec::new()));
    let resolver: Arc<UserResolver> = Arc::new(|_name: String| {
        Ok(LocalUser {
            uid: 1000,
            gid: 1000,
            gids: vec![1000],
            name: "mapped".into(),
            home_dir: "/tmp".into(),
            shell: "/bin/sh".into(),
        })
    });
    let policy = policy_for("mapped", std::time::Duration::from_millis(50));
    let policy: Arc<dyn Fn() -> Option<SSHPolicy> + Send + Sync> =
        Arc::new(move || Some(policy.clone()));

    let (code, output) = run_pipeline_custom(
        "ignored",
        "requested",
        policy,
        Some((resolver.clone(), launcher.clone())),
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
async fn sigkill_error_is_not_reported_as_success_after_group_disappears() {
    let control = Arc::new(KillFailureControl::default());
    let launcher: Arc<dyn SessionLauncher> = Arc::new(CompletedLauncher {
        control: control.clone(),
    });
    let resolver: Arc<UserResolver> = Arc::new(|_name: String| {
        Ok(LocalUser {
            uid: 1000,
            gid: 1000,
            gids: vec![1000],
            name: "mapped".into(),
            home_dir: "/tmp".into(),
            shell: "/bin/sh".into(),
        })
    });
    let (code, _) = run_pipeline_custom(
        "ignored",
        "requested",
        policy_map_any("mapped"),
        Some((resolver, launcher)),
        None,
        false,
        false,
    )
    .await;
    assert_eq!(code, 1);
    assert_eq!(
        &*control.signals.lock().unwrap(),
        &[libc::SIGTERM, libc::SIGKILL]
    );
}

#[tokio::test]
async fn persistent_process_group_returns_explicit_failure() {
    let control = Arc::new(PersistentControl::default());
    let launcher: Arc<dyn SessionLauncher> = Arc::new(PersistentLauncher {
        control: control.clone(),
    });
    let resolver: Arc<UserResolver> = Arc::new(|_name: String| {
        Ok(LocalUser {
            uid: 1000,
            gid: 1000,
            gids: vec![1000],
            name: "mapped".into(),
            home_dir: "/tmp".into(),
            shell: "/bin/sh".into(),
        })
    });
    let policy = policy_for("mapped", std::time::Duration::from_millis(50));
    let policy: Arc<dyn Fn() -> Option<SSHPolicy> + Send + Sync> =
        Arc::new(move || Some(policy.clone()));
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(4),
        run_pipeline_custom(
            "ignored",
            "requested",
            policy,
            Some((resolver, launcher)),
            None,
            false,
            false,
        ),
    )
    .await
    .expect("persistent group cleanup was not bounded");
    assert_eq!(result.0, 1);
    assert!(control
        .signals
        .lock()
        .unwrap()
        .starts_with(&[libc::SIGTERM, libc::SIGKILL]));
}

#[tokio::test]
async fn live_policy_revocation_terminates_existing_session() {
    let launcher = Arc::new(TermIgnoringLauncher::new(Vec::new()));
    let resolver: Arc<UserResolver> = Arc::new(|_name: String| {
        Ok(LocalUser {
            uid: 1000,
            gid: 1000,
            gids: vec![1000],
            name: "mapped".into(),
            home_dir: "/tmp".into(),
            shell: "/bin/sh".into(),
        })
    });
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
    let recording_events = Arc::new(Mutex::new(Vec::new()));
    let inject_recorder = {
        let recording_events = recording_events.clone();
        move |init: &mut crate::session::SessionInit| {
            let callback: crate::RecordingNotifyCallback = {
                let recording_events = recording_events.clone();
                Arc::new(move |_url, request| recording_events.lock().unwrap().push(request))
            };
            let notify = crate::RecordingFailureNotify::new(
                callback,
                "/machine/ssh/notify".into(),
                rustscale_tailcfg::SSHEventNotifyRequest::default(),
            );
            notify.set_attempts(&[rustscale_tailcfg::SSHRecordingAttempt {
                Recorder: "100.64.0.9:80".parse().unwrap(),
                FailureMessage: String::new(),
            }]);
            let header = crate::CastHeader::new(
                (0, 0),
                "ignored".into(),
                std::collections::HashMap::new(),
                "requested".into(),
                "mapped".into(),
                "connection".into(),
            );
            init.recorder = Some(
                crate::SessionRecorder::with_test_writer(Box::new(Vec::<u8>::new()), header, true)
                    .unwrap(),
            );
            init.recording_config = Some(crate::RecordingConfig {
                recorders: vec!["100.64.0.9:80".parse().unwrap()],
                on_failure: Some(rustscale_tailcfg::SSHRecorderFailureAction {
                    NotifyURL: "/machine/ssh/notify".into(),
                    ..Default::default()
                }),
                fail_open: true,
                notify: Some(notify),
                ..Default::default()
            });
        }
    };

    let (code, output) = run_pipeline_custom(
        "ignored",
        "requested",
        policy,
        Some((resolver.clone(), launcher.clone())),
        Some(&inject_recorder),
        false,
        false,
    )
    .await;
    revoke.await.unwrap();
    assert_eq!(code, 1);
    assert!(String::from_utf8_lossy(&output).contains("Access revoked"));
    assert!(
        recording_events.lock().unwrap().is_empty(),
        "policy revocation is not a recorder failure"
    );
    assert_eq!(
        &*launcher.control.signals.lock().unwrap(),
        &[libc::SIGTERM, libc::SIGKILL]
    );
}

#[tokio::test]
async fn client_close_cleans_up_term_ignoring_process() {
    let launcher = Arc::new(TermIgnoringLauncher::new(Vec::new()));
    let resolver: Arc<UserResolver> = Arc::new(|_name: String| {
        Ok(LocalUser {
            uid: 1000,
            gid: 1000,
            gids: vec![1000],
            name: "mapped".into(),
            home_dir: "/tmp".into(),
            shell: "/bin/sh".into(),
        })
    });

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(7),
        run_pipeline_custom(
            "ignored",
            "requested",
            policy_map_any("mapped"),
            Some((resolver.clone(), launcher.clone())),
            None,
            true,
            false,
        ),
    )
    .await
    .expect("EOF cleanup must be bounded");
    assert_eq!(result.0, 1);
    // Cancellation can win before the bounded launcher starts (no process),
    // or after it starts (covered by the late-launch supervisor test).
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
