//! SSH server — ports Go's `ssh/tailssh/tailssh.go` and `listen.go`.

use crate::auth::{eval_ssh_policy, ConnInfo, EvalResult};
use crate::env::accept_env_name;
use crate::recording::{default_recording_path, CastHeader, RecordingConfig};
use crate::recording_upload::DialFn;
use crate::session::{PeerIdentity, Pty, RevalidateCallback, SessionInit, Window};
use russh::keys::PrivateKey;
use russh::server::{Auth, Msg, Server as RusshServer, Session};
use russh::{Channel, ChannelId, MethodSet};
use rustscale_tailcfg::{Node, SSHPolicy, UserProfile};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

const MAX_SESSION_CHANNELS: usize = 16;
const CHANNEL_STDIN_FRAMES: usize = 64;
const PRESTART_STDIN_BYTES: usize = 256 * 1024;
const GLOBAL_PRESTART_STDIN_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_ENV_VARS: usize = 64;
pub(crate) const MAX_ENV_NAME_BYTES: usize = 128;
pub(crate) const MAX_ENV_VALUE_BYTES: usize = 4 * 1024;
pub(crate) const MAX_ENV_BYTES: usize = 16 * 1024;

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
            channels: Arc::new(Mutex::new(HashMap::new())),
            recording_config: None,
            session_duration: std::time::Duration::ZERO,
            revalidate: None,
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

#[derive(Default)]
struct ChannelState {
    env_vars: Vec<(String, String)>,
    env_bytes: usize,
    pty: Option<Pty>,
    command: String,
    started: bool,
    data_tx: Option<mpsc::Sender<Vec<u8>>>,
    cancel: Option<tokio::sync::watch::Sender<bool>>,
    signal_tx: Option<mpsc::Sender<russh::Sig>>,
    window_change_tx: Option<mpsc::Sender<Window>>,
    pending_data: VecDeque<Vec<u8>>,
    pending_bytes: usize,
    input_eof: bool,
}

impl ChannelState {
    fn store_env(&mut self, name: &str, value: &str) -> bool {
        if self.started
            || !valid_env_name(name)
            || value.len() > MAX_ENV_VALUE_BYTES
            || value.chars().any(char::is_control)
        {
            return false;
        }

        let existing = self.env_vars.iter().position(|(key, _)| key == name);
        if existing.is_none() && self.env_vars.len() >= MAX_ENV_VARS {
            return false;
        }
        let old_bytes = existing.map_or(0, |index| {
            let (old_name, old_value) = &self.env_vars[index];
            old_name.len() + old_value.len()
        });
        let new_bytes = name.len() + value.len();
        let aggregate = self.env_bytes - old_bytes + new_bytes;
        if aggregate > MAX_ENV_BYTES {
            return false;
        }

        if let Some(index) = existing {
            self.env_vars[index].1 = value.to_string();
        } else {
            self.env_vars.push((name.to_string(), value.to_string()));
        }
        self.env_bytes = aggregate;
        true
    }
}

fn valid_env_name(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_ENV_NAME_BYTES {
        return false;
    }
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

pub struct SshHandler {
    config: Arc<SshServerConfig>,
    peer_addr: Option<SocketAddr>,
    ssh_user: String,
    local_user: String,
    accept_env: Vec<String>,
    peer_identity: Option<PeerIdentity>,
    channels: Arc<Mutex<HashMap<ChannelId, ChannelState>>>,
    recording_config: Option<RecordingConfig>,
    session_duration: std::time::Duration,
    revalidate: Option<RevalidateCallback>,
    connection_id: String,
}

impl Drop for SshHandler {
    fn drop(&mut self) {
        for (_, mut state) in self.channels.lock().unwrap().drain() {
            if let Some(cancel) = state.cancel.take() {
                cancel.send_replace(true);
            }
        }
    }
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
                local_user,
                accept_env,
            } => {
                if !action.Message.is_empty() {
                    log::info!("SSH auth: {}", action.Message);
                }
                self.ssh_user = ssh_user;
                self.local_user.clone_from(local_user);
                self.accept_env.clone_from(accept_env);
                self.peer_identity = Some(PeerIdentity { node, user_profile });
                self.session_duration = action.SessionDuration;
                let expected_local_user = local_user.clone();
                let policy = self.config.policy.clone();
                let info = info.clone();
                self.revalidate = Some(Arc::new(move || {
                    let Some(policy) = policy() else {
                        return false;
                    };
                    matches!(
                        eval_ssh_policy(&policy, &info),
                        EvalResult::Accept { local_user, .. } if local_user == expected_local_user
                    )
                }));
                // This is the final terminal action. Never inherit recorder
                // policy from an earlier/delegating action.
                let recorders = action.Recorders.clone();
                let on_failure = action.OnRecordingFailure.clone();
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
        let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(CHANNEL_STDIN_FRAMES);
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        let (done_tx, mut done_rx) = mpsc::channel::<()>(1);
        let (signal_tx, signal_rx) = mpsc::channel::<russh::Sig>(16);
        let (window_change_tx, window_change_rx) = mpsc::channel::<Window>(16);
        let (env_vars, pty, command, input_eof) = {
            let mut channels = self.channels.lock().unwrap();
            let Some(channel) = channels.get_mut(&channel_id) else {
                let _ = session.channel_failure(channel_id);
                return Ok(());
            };
            if channel.started {
                let _ = session.channel_failure(channel_id);
                return Ok(());
            }
            channel.started = true;
            while let Some(data) = channel.pending_data.pop_front() {
                // The pre-start queue has the same frame cap as this fresh
                // channel, so every accepted packet must fit in order.
                if data_tx.try_send(data).is_err() {
                    let _ = session.exit_status_request(channel_id, 1);
                    let _ = session.eof(channel_id);
                    let _ = session.close(channel_id);
                    channels.remove(&channel_id);
                    return Ok(());
                }
            }
            channel.pending_bytes = 0;
            channel.data_tx = (!channel.input_eof).then(|| data_tx.clone());
            channel.cancel = Some(cancel_tx);
            channel.signal_tx = Some(signal_tx);
            channel.window_change_tx = Some(window_change_tx);
            (
                channel.env_vars.clone(),
                channel.pty.clone(),
                channel.command.clone(),
                channel.input_eof,
            )
        };
        if input_eof {
            drop(data_tx);
        }

        let channels = self.channels.clone();
        tokio::spawn(async move {
            let _ = done_rx.recv().await;
            channels.lock().unwrap().remove(&channel_id);
        });

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
        let term = pty
            .as_ref()
            .map(|pty| pty.term.clone())
            .or_else(|| {
                env_vars
                    .iter()
                    .find(|(name, _)| name == "TERM")
                    .map(|(_, value)| value.clone())
            })
            .filter(|term| !term.is_empty())
            .unwrap_or_else(|| "xterm-256color".into());
        let mut cast_header = CastHeader::new(
            pty.as_ref()
                .map_or((0, 0), |pty| (pty.window.width, pty.window.height)),
            command.clone(),
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
        let recording_header = recording_config.as_ref().map(|_| cast_header);
        let init = SessionInit {
            peer,
            ssh_user: self.ssh_user.clone(),
            local_user: self.local_user.clone(),
            command,
            env: env_vars,
            pty,
            handle,
            channel_id,
            data_rx,
            cancel_rx,
            done_tx,
            recorder: None,
            recording_config,
            recording_header,
            recording_dial: self.config.dial_fn.clone(),
            session_duration: self.session_duration,
            revalidate: self.revalidate.clone(),
            signal_rx,
            window_change_rx,
            peer_addr,
            #[cfg(test)]
            fail_pty_setup: false,
        };

        if self.config.session_tx.send(init).await.is_err() {
            return Err(russh::Error::Disconnect);
        }
        // Do not block the russh handler on process completion. It must remain
        // available to deliver channel data, EOF, close, signals, and window
        // changes to the orchestrator.
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
        channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let accepted = {
            let mut channels = self.channels.lock().unwrap();
            if channels.len() >= MAX_SESSION_CHANNELS {
                false
            } else {
                channels.insert(channel.id(), ChannelState::default());
                true
            }
        };
        if accepted {
            reply.accept().await;
        } else {
            reply
                .reject(russh::ChannelOpenFailure::ResourceShortage)
                .await;
        }
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let permitted = accept_env_name(name) || self.accept_env.iter().any(|p| p == name);
        let accepted = permitted
            && self
                .channels
                .lock()
                .unwrap()
                .get_mut(&channel)
                .is_some_and(|state| state.store_env(name, value));
        if accepted {
            let _ = session.channel_success(channel);
        } else {
            let _ = session.channel_failure(channel);
        }
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(state) = self.channels.lock().unwrap().get_mut(&channel) {
            if !state.started {
                state.pty = Some(Pty {
                    term: term.to_string(),
                    window: Window {
                        width: col_width,
                        height: row_height,
                        width_pixels: pix_width,
                        height_pixels: pix_height,
                    },
                });
            }
        }
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(state) = self.channels.lock().unwrap().get_mut(&channel) {
            state.command.clear();
        }
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
        if let Some(state) = self.channels.lock().unwrap().get_mut(&channel) {
            state.command = String::from_utf8_lossy(data).to_string();
        }
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
            if let Some(state) = self.channels.lock().unwrap().get_mut(&channel) {
                state.command.clear();
            }
            let _ = session.channel_success(channel);
            self.send_session(channel, session).await?;
        } else {
            let _ = session.channel_failure(channel);
        }
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if data.is_empty() {
            return Ok(());
        }
        let close_channel = {
            let mut channels = self.channels.lock().unwrap();
            let global_pending: usize = channels.values().map(|state| state.pending_bytes).sum();
            let Some(state) = channels.get_mut(&channel) else {
                return Ok(());
            };
            let overflow = if state.input_eof {
                true
            } else if state.started {
                state
                    .data_tx
                    .as_ref()
                    .is_none_or(|tx| tx.try_send(data.to_vec()).is_err())
            } else if state.pending_data.len() >= CHANNEL_STDIN_FRAMES
                || state.pending_bytes.saturating_add(data.len()) > PRESTART_STDIN_BYTES
                || global_pending.saturating_add(data.len()) > GLOBAL_PRESTART_STDIN_BYTES
            {
                true
            } else {
                state.pending_data.push_back(data.to_vec());
                state.pending_bytes += data.len();
                false
            };

            if overflow {
                let started = state.started;
                state.input_eof = true;
                if let Some(cancel) = state.cancel.take() {
                    cancel.send_replace(true);
                }
                state.data_tx = None;
                state.signal_tx = None;
                state.window_change_tx = None;
                if !started {
                    channels.remove(&channel);
                }
                true
            } else {
                false
            }
        };
        if close_channel {
            // russh has already accepted this SSH data packet. Never wait on
            // an application queue and never silently discard it: report a
            // protocol failure and close only the offending channel.
            let _ = session.data(channel, "SSH input buffer exceeded or closed\r\n");
            let _ = session.exit_status_request(channel, 1);
            let _ = session.eof(channel);
            let _ = session.close(channel);
        }
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
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
        if let Some(state) = self.channels.lock().unwrap().get_mut(&channel) {
            if let Some(pty) = state.pty.as_mut() {
                pty.window = win.clone();
            }
            if let Some(tx) = &state.window_change_tx {
                let _ = tx.try_send(win);
            }
        }
        Ok(())
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: russh::Sig,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        log::debug!("SSH signal: {signal:?}");
        if let Some(tx) = self
            .channels
            .lock()
            .unwrap()
            .get(&channel)
            .and_then(|state| state.signal_tx.clone())
        {
            let _ = tx.try_send(signal);
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(state) = self.channels.lock().unwrap().get_mut(&channel) {
            // SSH EOF is a half-close. Dropping only the input sender causes
            // Session::read to drain every queued frame before yielding EOF;
            // signals, window changes, output, and process lifetime continue.
            state.input_eof = true;
            state.data_tx = None;
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(mut state) = self.channels.lock().unwrap().remove(&channel) {
            if let Some(cancel) = state.cancel.take() {
                cancel.send_replace(true);
            }
        }
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

    #[test]
    fn channel_environment_is_bounded_and_duplicates_replace() {
        let mut state = ChannelState::default();
        assert!(state.store_env("LANG", "first"));
        for index in 0..(MAX_ENV_VARS - 1) {
            assert!(state.store_env(&format!("LC_FLOOD_{index}"), "value"));
        }
        assert_eq!(state.env_vars.len(), MAX_ENV_VARS);
        let bytes_before = state.env_bytes;
        assert!(state.store_env("LANG", "x"));
        assert_eq!(state.env_vars.len(), MAX_ENV_VARS);
        assert_eq!(state.env_bytes, bytes_before - 4);
        assert_eq!(
            state
                .env_vars
                .iter()
                .find(|(name, _)| name == "LANG")
                .unwrap()
                .1,
            "x"
        );
        assert!(!state.store_env("LC_EXCESS", "value"));
    }

    #[test]
    fn channel_environment_rejects_invalid_and_aggregate_floods() {
        let mut state = ChannelState::default();
        assert!(!state.store_env("", "value"));
        assert!(!state.store_env("1BAD", "value"));
        assert!(!state.store_env("BAD-NAME", "value"));
        assert!(!state.store_env("LC_BAD\n", "value"));
        assert!(!state.store_env("LC_BAD\0", "value"));
        assert!(!state.store_env("LC_BAD", "line\nvalue"));
        assert!(!state.store_env("LC_BAD", "nul\0value"));
        assert!(!state.store_env(&format!("L{}", "X".repeat(MAX_ENV_NAME_BYTES)), "value"));
        assert!(!state.store_env("LANG", &"x".repeat(MAX_ENV_VALUE_BYTES + 1)));

        let large = "x".repeat(MAX_ENV_VALUE_BYTES);
        assert!(state.store_env("LC_ONE", &large));
        assert!(state.store_env("LC_TWO", &large));
        assert!(state.store_env("LC_THREE", &large));
        assert!(!state.store_env("LC_FOUR", &large));
        assert!(state.store_env("LC_ONE", "x"));
        assert!(state.store_env("LC_FOUR", &large));
        assert_eq!(state.env_vars.len(), 4);
        assert!(!state.store_env("LC_FIVE", &large));
        assert!(state.env_bytes <= MAX_ENV_BYTES);
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
    async fn recorder_policy_is_taken_from_terminal_accept_action() {
        let recorder: std::net::SocketAddr = "100.64.0.9:80".parse().unwrap();
        let policy = SSHPolicy {
            Rules: vec![SSHRule {
                Principals: vec![SSHPrincipal {
                    Any: true,
                    ..Default::default()
                }],
                SSHUsers: BTreeMap::from([("*".into(), "=".into())]),
                Action: Some(SSHAction {
                    Accept: true,
                    Recorders: vec![recorder],
                    ..Default::default()
                }),
                ..Default::default()
            }],
        };
        let mut handler = make_handler(Arc::new(move || Some(policy.clone())), whois_finds_peer());
        assert!(matches!(
            handler.auth_none("alice").await.unwrap(),
            Auth::Accept
        ));
        assert_eq!(
            handler.recording_config.as_ref().unwrap().recorders,
            vec![recorder]
        );
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
