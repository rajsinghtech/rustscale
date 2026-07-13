//! Integration tests for the SSH crate — verifies the full pipeline
//! (SshServer → SshHandler → Session → run_session) without network I/O.
//!
//! These tests use `tokio::io::duplex` to connect a russh client and server
//! in-memory, then verify that `run_session` correctly spawns the shell,
//! pumps I/O, and reports exit status.

use crate::host_key_from_node_key;
use crate::session_handler::run_session;
use crate::{Session, SshServer, SshServerConfig};
use russh::server::Server as _;
use russh::{ChannelMsg, MethodSet};
use rustscale_key::NodePrivate;
use rustscale_tailcfg::{
    Node, SSHAction, SSHPolicy, SSHPrincipal, SSHRule, StableNodeID, UserProfile,
};
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::mpsc;

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

fn policy_allow_any() -> Arc<dyn Fn() -> Option<SSHPolicy> + Send + Sync> {
    let policy = SSHPolicy {
        Rules: vec![SSHRule {
            Principals: vec![SSHPrincipal {
                Any: true,
                ..Default::default()
            }],
            SSHUsers: {
                let mut m = BTreeMap::new();
                m.insert("*".into(), "=".into());
                m
            },
            Action: Some(SSHAction {
                Accept: true,
                ..Default::default()
            }),
            ..Default::default()
        }],
    };
    Arc::new(move || Some(policy.clone()))
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
async fn run_pipeline(command: &str) -> i32 {
    let host_key = host_key_from_node_key(&NodePrivate::generate());
    let (session_tx, mut session_rx) = mpsc::channel::<crate::session::SessionInit>(16);
    let config = SshServerConfig {
        host_keys: vec![host_key],
        session_tx,
        whois: whois_finds_peer(),
        policy: policy_allow_any(),
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
        .authenticate_password(
            std::env::var("USER").unwrap_or_else(|_| "testuser".to_string()),
            "",
        )
        .await
        .expect("auth")
        .success();
    assert!(authed, "authentication should succeed");

    // Open a channel and send the exec request.
    let mut channel = client.channel_open_session().await.expect("channel open");
    channel
        .exec(true, command.as_bytes())
        .await
        .expect("exec request");

    // Accept the session on the server side and run it.
    let session_init = session_rx.recv().await.expect("session init received");
    let session = Session::from_init(session_init);
    let result = run_session(session, None).await.expect("run_session");

    // Wait for the exit status on the client side.
    loop {
        match channel.wait().await {
            Some(ChannelMsg::ExitStatus { exit_status }) => {
                return exit_status as i32;
            }
            Some(_) => continue,
            None => break,
        }
    }

    result
}

/// Watcher test: verifies the full pipeline (SshServer → SshHandler →
/// Session → run_session) without network I/O, using in-memory duplex.
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
