//! SSH server — ports Go's `ssh/tailssh/tailssh.go` and `listen.go`.

use crate::auth::{eval_ssh_policy, ConnInfo, EvalResult};
use crate::env::accept_env_pair;
use crate::recording::{default_recording_path, CastHeader, RecordingConfig};
use crate::recording_upload::DialFn;
use crate::session::{PeerIdentity, Pty, SessionInit, Window};
use crate::session_handler::init_recording;
use russh::keys::PrivateKey;
use russh::server::{Auth, Msg, Server as RusshServer, Session};
use russh::{Channel, ChannelId, MethodSet};
use rustscale_tailcfg::{Node, SSHPolicy, UserProfile};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

pub type WhoIsCallback = Arc<dyn Fn(IpAddr) -> Option<(Node, UserProfile)> + Send + Sync>;
pub type PolicyCallback = Arc<dyn Fn() -> Option<SSHPolicy> + Send + Sync>;

pub struct SshServerConfig {
    pub host_keys: Vec<PrivateKey>,
    pub session_tx: mpsc::Sender<SessionInit>,
    pub whois: WhoIsCallback,
    pub policy: PolicyCallback,
    /// State directory used only when the deprecated TS_DEBUG_LOG_SSH local
    /// recording knob is enabled by the embedding.
    pub state_dir: Option<PathBuf>,
    /// Tailnet TCP dialer for recorder nodes.
    pub dial_fn: Option<DialFn>,
}

pub struct SshServer {
    config: Arc<SshServerConfig>,
}

impl SshServer {
    pub fn new(config: SshServerConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
    pub fn russh_config(&self) -> Arc<russh::server::Config> {
        Arc::new(russh::server::Config {
            server_id: russh::SshId::Standard("SSH-2.0-rustscale-tailssh".into()),
            keys: self.config.host_keys.clone(),
            methods: MethodSet::all(),
            auth_rejection_time: std::time::Duration::from_secs(1),
            auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
            max_auth_attempts: 10,
            inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
            ..Default::default()
        })
    }
}

impl RusshServer for SshServer {
    type Handler = SshHandler;
    fn new_client(&mut self, peer_addr: Option<SocketAddr>) -> Self::Handler {
        SshHandler {
            config: self.config.clone(),
            peer_addr,
            ssh_user: String::new(),
            local_user: String::new(),
            accept_env: Vec::new(),
            peer_identity: None,
            channel_data_tx: None,
            env_vars: Vec::new(),
            pty: None,
            command: String::new(),
            signal_tx: None,
            window_change_tx: None,
            recording_config: None,
            connection_id: next_connection_id(),
        }
    }
    fn handle_session_error(&mut self, error: <Self::Handler as russh::server::Handler>::Error) {
        log::error!("SSH session error: {error:?}");
    }
}

fn next_connection_id() -> String {
    static NEXT_CONNECTION: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let sequence = u128::from(NEXT_CONNECTION.fetch_add(1, Ordering::Relaxed));
    let value = (nanos << 16) ^ sequence;
    // UUID-shaped, unique per process; its version and variant bits retain the
    // established v4 representation without requiring another dependency.
    format!(
        "{:08x}-{:04x}-4{:03x}-8{:03x}-{:012x}",
        value >> 96,
        (value >> 80) & 0xffff,
        (value >> 68) & 0x0fff,
        (value >> 52) & 0x0fff,
        value & 0x000f_ffff_ffff_ffff_ffff
    )
}

pub struct SshHandler {
    config: Arc<SshServerConfig>,
    peer_addr: Option<SocketAddr>,
    ssh_user: String,
    local_user: String,
    accept_env: Vec<String>,
    peer_identity: Option<PeerIdentity>,
    channel_data_tx: Option<mpsc::Sender<Vec<u8>>>,
    env_vars: Vec<(String, String)>,
    pty: Option<Pty>,
    command: String,
    signal_tx: Option<mpsc::Sender<russh::Sig>>,
    window_change_tx: Option<mpsc::Sender<Window>>,
    recording_config: Option<RecordingConfig>,
    connection_id: String,
}

impl SshHandler {
    fn tailscale_auth(&mut self, user: &str) -> Auth {
        let ssh_user = user.trim_end_matches("+password").to_string();
        if !ssh_user.is_empty() && ssh_user.chars().all(|c| c.is_ascii_digit()) {
            log::warn!("rejecting numeric username {ssh_user:?}");
            return Auth::reject();
        }
        let peer_ip = match self.peer_addr {
            Some(addr) => addr.ip(),
            None => return Auth::reject(),
        };
        let (node, user_profile) = if let Some(ident) = (self.config.whois)(peer_ip) {
            ident
        } else {
            log::warn!("SSH: unknown identity from {peer_ip}");
            return Auth::reject();
        };
        let policy = if let Some(p) = (self.config.policy)() {
            p
        } else {
            log::warn!("SSH: no policy configured");
            return Auth::reject();
        };
        let info = ConnInfo {
            ssh_user: ssh_user.clone(),
            src_ip: peer_ip,
            dst_ip: peer_ip,
            node: node.clone(),
            user_profile: user_profile.clone(),
        };
        let result = eval_ssh_policy(&policy, &info);
        match &result {
            EvalResult::Accept {
                action,
                action0,
                local_user,
                accept_env,
            } => {
                if !action.Message.is_empty() {
                    log::info!("SSH auth: {}", action.Message);
                }
                // A matched rule may carry a Reject action (Go's
                // `tailssh.go` checks `action.Reject` after evalSSHPolicy
                // returns `accepted`). Honour it here.
                if action.Reject {
                    log::warn!("SSH: policy rejects connection (reject action)");
                    return Auth::reject();
                }
                self.ssh_user = ssh_user;
                self.local_user.clone_from(local_user);
                self.accept_env.clone_from(accept_env);
                self.peer_identity = Some(PeerIdentity { node, user_profile });
                let (recorders, on_failure) = if action.Recorders.is_empty() {
                    action0.as_ref().map_or_else(
                        || (Vec::new(), None),
                        |initial| {
                            (
                                initial.Recorders.clone(),
                                initial.OnRecordingFailure.clone(),
                            )
                        },
                    )
                } else {
                    (action.Recorders.clone(), action.OnRecordingFailure.clone())
                };
                if on_failure
                    .as_ref()
                    .is_some_and(|failure| !failure.NotifyURL.is_empty())
                {
                    log::warn!("SSH recording NotifyURL is not implemented yet");
                }
                // Keep the root only as a local-recording marker here. A
                // unique path is allocated per SSH session below, including
                // multiplexed sessions on one connection.
                let local_path = recorders
                    .is_empty()
                    .then(|| self.config.state_dir.clone())
                    .flatten();
                self.recording_config = if recorders.is_empty() && local_path.is_none() {
                    None
                } else {
                    Some(RecordingConfig {
                        recorders,
                        fail_open: on_failure
                            .as_ref()
                            .is_none_or(|failure| failure.TerminateSessionWithMessage.is_empty()),
                        on_failure,
                        local_path,
                    })
                };
                Auth::Accept
            }
            EvalResult::RejectedUser => {
                log::warn!("SSH: policy rejects user {ssh_user:?}");
                Auth::reject()
            }
            EvalResult::Rejected | EvalResult::NoPolicy => {
                log::warn!("SSH: policy rejects connection");
                Auth::reject()
            }
        }
    }

    async fn send_session(
        &mut self,
        channel_id: ChannelId,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(64);
        let (done_tx, mut done_rx) = mpsc::channel::<()>(1);
        let (signal_tx, signal_rx) = mpsc::channel::<russh::Sig>(16);
        let (window_change_tx, window_change_rx) = mpsc::channel::<Window>(16);
        self.channel_data_tx = Some(data_tx);
        self.signal_tx = Some(signal_tx);
        self.window_change_tx = Some(window_change_tx);

        let handle = session.handle();
        let peer = self.peer_identity.clone().unwrap_or_default();
        let peer_addr = self.peer_addr;

        let mut recording_config = self.recording_config.clone();
        if let Some(config) = recording_config.as_mut() {
            if config.recorders.is_empty() && config.local_path.is_some() {
                if let Ok(path) = self
                    .config
                    .state_dir
                    .as_deref()
                    .map(default_recording_path)
                    .transpose()
                {
                    config.local_path = path;
                } else {
                    let _ = session.data(channel_id, "can't start new recording\r\n");
                    let _ = session.channel_failure(channel_id);
                    return Ok(());
                }
            }
        }
        let term = self
            .pty
            .as_ref()
            .map(|pty| pty.term.clone())
            .or_else(|| {
                self.env_vars
                    .iter()
                    .find(|(name, _)| name == "TERM")
                    .map(|(_, value)| value.clone())
            })
            .filter(|term| !term.is_empty())
            .unwrap_or_else(|| "xterm-256color".into());
        let mut cast_header = CastHeader::new(
            self.pty
                .as_ref()
                .map_or((0, 0), |pty| (pty.window.width, pty.window.height)),
            self.command.clone(),
            [("TERM".to_string(), term)].into_iter().collect(),
            self.ssh_user.clone(),
            self.local_user.clone(),
            self.connection_id.clone(),
        );
        cast_header.src_node = peer.node.Name.trim_end_matches('.').to_string();
        cast_header.src_node_id.clone_from(&peer.node.StableID);
        if peer.node.Tags.is_empty() {
            cast_header.src_node_user_id = (peer.node.User != 0).then_some(peer.node.User);
            if !peer.user_profile.LoginName.is_empty() {
                cast_header.src_node_user = Some(peer.user_profile.LoginName.clone());
            }
        } else {
            cast_header.src_node_tags.clone_from(&peer.node.Tags);
        }
        let recorder = match &recording_config {
            Some(config) => {
                match init_recording(config, cast_header, self.config.dial_fn.clone()).await {
                    Ok(recorder) => recorder,
                    Err(message) => {
                        let _ = session.data(channel_id, message);
                        let _ = session.channel_failure(channel_id);
                        return Ok(());
                    }
                }
            }
            None => None,
        };
        let init = SessionInit {
            peer,
            ssh_user: self.ssh_user.clone(),
            command: self.command.clone(),
            env: self.env_vars.clone(),
            pty: self.pty.clone(),
            handle,
            channel_id,
            data_rx,
            done_tx,
            recorder,
            recording_config,
            signal_rx,
            window_change_rx,
            peer_addr,
        };

        if self.config.session_tx.send(init).await.is_err() {
            return Err(russh::Error::Disconnect);
        }
        let _ = done_rx.recv().await;
        Ok(())
    }
}

impl russh::server::Handler for SshHandler {
    type Error = russh::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        Ok(self.tailscale_auth(user))
    }
    async fn auth_password(&mut self, user: &str, _password: &str) -> Result<Auth, Self::Error> {
        Ok(self.tailscale_auth(user))
    }
    async fn auth_publickey(
        &mut self,
        user: &str,
        _key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        Ok(self.tailscale_auth(user))
    }

    async fn auth_succeeded(&mut self, _session: &mut Session) -> Result<(), Self::Error> {
        log::info!(
            "SSH auth succeeded: {} -> {}",
            self.ssh_user,
            self.local_user
        );
        Ok(())
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn env_request(
        &mut self,
        _channel: ChannelId,
        name: &str,
        value: &str,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let kv = format!("{name}={value}");
        if accept_env_pair(&kv) || self.accept_env.iter().any(|p| p == name) {
            self.env_vars.push((name.to_string(), value.to_string()));
        }
        Ok(())
    }

    async fn pty_request(
        &mut self,
        _channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.pty = Some(Pty {
            term: term.to_string(),
            window: Window {
                width: col_width,
                height: row_height,
                width_pixels: pix_width,
                height_pixels: pix_height,
            },
        });
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.command.clear();
        let _ = session.channel_success(channel);
        self.send_session(channel, session).await?;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.command = String::from_utf8_lossy(data).to_string();
        let _ = session.channel_success(channel);
        self.send_session(channel, session).await?;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name == "sftp" {
            self.command.clear();
            let _ = session.channel_success(channel);
            self.send_session(channel, session).await?;
        } else {
            let _ = session.channel_failure(channel);
        }
        Ok(())
    }

    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(tx) = &self.channel_data_tx {
            let _ = tx.send(data.to_vec()).await;
        }
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        _channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let win = Window {
            width: col_width,
            height: row_height,
            width_pixels: pix_width,
            height_pixels: pix_height,
        };
        if let Some(ref mut pty) = self.pty {
            pty.window = win.clone();
        }
        if let Some(tx) = &self.window_change_tx {
            let _ = tx.try_send(win);
        }
        Ok(())
    }

    async fn signal(
        &mut self,
        _channel: ChannelId,
        signal: russh::Sig,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        log::debug!("SSH signal: {signal:?}");
        if let Some(tx) = &self.signal_tx {
            let _ = tx.try_send(signal);
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channel_data_tx = None;
        self.signal_tx = None;
        self.window_change_tx = None;
        Ok(())
    }

    async fn channel_close(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channel_data_tx = None;
        self.signal_tx = None;
        self.window_change_tx = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_key_from_node_key;
    use russh::server::Handler;
    use rustscale_key::NodePrivate;
    use rustscale_tailcfg::{SSHAction, SSHPolicy, SSHPrincipal, SSHRule, StableNodeID};
    use std::collections::BTreeMap;
    use std::net::{IpAddr, SocketAddr};

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

    /// Build an `SshServer` with the given policy + whois callbacks and
    /// return a fresh `SshHandler` for `peer_ip()`.
    fn make_handler(policy: PolicyCallback, whois: WhoIsCallback) -> SshHandler {
        let host_key = host_key_from_node_key(&NodePrivate::generate());
        let (session_tx, _rx) = mpsc::channel::<SessionInit>(16);
        let config = SshServerConfig {
            host_keys: vec![host_key],
            session_tx,
            whois,
            policy,
            state_dir: None,
            dial_fn: None,
        };
        let mut server = SshServer::new(config);
        <SshServer as RusshServer>::new_client(&mut server, Some(SocketAddr::new(peer_ip(), 22)))
    }

    fn whois_finds_peer() -> WhoIsCallback {
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

    fn whois_misses() -> WhoIsCallback {
        Arc::new(|_| None)
    }

    fn policy_allow_any() -> PolicyCallback {
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

    fn policy_none() -> PolicyCallback {
        Arc::new(|| None)
    }

    fn policy_no_match() -> PolicyCallback {
        let policy = SSHPolicy {
            Rules: vec![SSHRule {
                Principals: vec![SSHPrincipal {
                    UserLogin: "nobody@example.com".into(),
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

    fn policy_reject_action() -> PolicyCallback {
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
                    Reject: true,
                    Message: "banned".into(),
                    ..Default::default()
                }),
                ..Default::default()
            }],
        };
        Arc::new(move || Some(policy.clone()))
    }

    #[tokio::test]
    async fn auth_accept_allowed_peer() {
        let mut h = make_handler(policy_allow_any(), whois_finds_peer());
        let auth = h.auth_none("alice").await.unwrap();
        assert!(
            matches!(auth, Auth::Accept),
            "expected Accept, got {auth:?}"
        );
        assert_eq!(h.ssh_user, "alice");
        assert_eq!(h.local_user, "alice");
    }

    #[tokio::test]
    async fn auth_reject_no_policy() {
        let mut h = make_handler(policy_none(), whois_finds_peer());
        let auth = h.auth_none("alice").await.unwrap();
        assert!(
            matches!(auth, Auth::Reject { .. }),
            "expected Reject, got {auth:?}"
        );
    }

    #[tokio::test]
    async fn auth_reject_unknown_peer() {
        let mut h = make_handler(policy_allow_any(), whois_misses());
        let auth = h.auth_none("alice").await.unwrap();
        assert!(
            matches!(auth, Auth::Reject { .. }),
            "expected Reject, got {auth:?}"
        );
    }

    #[tokio::test]
    async fn auth_reject_no_match() {
        let mut h = make_handler(policy_no_match(), whois_finds_peer());
        let auth = h.auth_none("alice").await.unwrap();
        assert!(
            matches!(auth, Auth::Reject { .. }),
            "expected Reject, got {auth:?}"
        );
    }

    #[tokio::test]
    async fn auth_reject_action_is_honoured() {
        // A matched rule with a Reject action must reject, not accept.
        // Mirrors Go's `tailssh.go` `case action.Reject:` path.
        let mut h = make_handler(policy_reject_action(), whois_finds_peer());
        let auth = h.auth_none("alice").await.unwrap();
        assert!(
            matches!(auth, Auth::Reject { .. }),
            "expected Reject for reject-action, got {auth:?}"
        );
    }
}
