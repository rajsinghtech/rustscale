//! SSH server loop — ports Go's `ssh/tailssh/tailssh.go` and `listen.go`.
//!
//! Implements the russh `Server` + `Handler` traits with Tailscale-specific
//! authentication: the SSH "none" auth method is used to trigger Tailscale
//! identity resolution (WhoIs) and SSHPolicy evaluation. No passwords or
//! client public keys are checked — the WireGuard tunnel + control plane
//! session IS the authentication.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use russh::server::{self, Auth, Channel, ChannelId, Handle, Msg, Session};
use russh::keys::PrivateKey;
use tokio::sync::mpsc;

use rustscale_tailcfg::{Node, SSHPolicy, UserProfile};

use crate::auth::{eval_ssh_policy, ConnInfo, EvalResult};
use crate::env::{accept_env_pair, filter_env};
use crate::session::{PeerIdentity, Pty, SessionInit, Window};

/// Callback type for resolving a peer's Tailscale identity from their
/// source IP address. Returns the peer's Node and UserProfile.
pub type WhoIsCallback = Arc<dyn Fn(IpAddr) -> Option<(Node, UserProfile)> + Send + Sync>;

/// Callback type for getting the current SSH policy from the netmap.
pub type PolicyCallback = Arc<dyn Fn() -> Option<SSHPolicy> + Send + Sync>;

/// Configuration for the Tailscale SSH server.
pub struct SshServerConfig {
    /// SSH host keys (typically generated from the node private key).
    pub host_keys: Vec<PrivateKey>,
    /// Channel for sending accepted sessions to the listener.
    pub session_tx: mpsc::Sender<SessionInit>,
    /// WhoIs lookup: resolves peer identity from source IP.
    pub whois: WhoIsCallback,
    /// SSH policy provider: returns the current SSHPolicy from the netmap.
    pub policy: PolicyCallback,
}

/// The SSH server factory. Implements `russh::server::Server`.
pub struct SshServer {
    config: Arc<SshServerConfig>,
}

impl SshServer {
    pub fn new(config: SshServerConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    /// Build a russh server config from the host keys.
    pub fn russh_config(&self) -> Arc<russh::server::Config> {
        Arc::new(russh::server::Config {
            server_id: russh::SshId::Standard("SSH-2.0-rustscale-tailssh".into()),
            keys: self.config.host_keys.clone(),
            methods: russh::MethodSet::none() | russh::MethodSet::password() | russh::MethodSet::publickey(),
            auth_rejection_time: std::time::Duration::from_secs(1),
            auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
            max_auth_attempts: 10,
            inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
            ..Default::default()
        })
    }
}

impl russh::server::Server for SshServer {
    type Handler = SshHandler;

    fn new_client(&mut self, peer_addr: Option<SocketAddr>) -> Self::Handler {
        SshHandler {
            config: self.config.clone(),
            peer_addr,
            auth_result: None,
            ssh_user: String::new(),
            local_user: String::new(),
            accept_env: Vec::new(),
            channel_id: None,
            channel_data_tx: None,
            env_vars: Vec::new(),
            pty: None,
            command: String::new(),
            done_tx: None,
        }
    }

    fn handle_session_error(&mut self, error: <Self::Handler as russh::server::Handler>::Error) {
        log::error!("SSH session error: {error:?}");
    }
}

/// Per-connection handler. Implements `russh::server::Handler`.
pub struct SshHandler {
    config: Arc<SshServerConfig>,
    peer_addr: Option<SocketAddr>,
    auth_result: Option<EvalResult>,
    ssh_user: String,
    local_user: String,
    accept_env: Vec<String>,
    channel_id: Option<ChannelId>,
    channel_data_tx: Option<mpsc::Sender<Vec<u8>>>,
    env_vars: Vec<(String, String)>,
    pty: Option<Pty>,
    command: String,
    done_tx: Option<mpsc::Sender<()>>,
}

impl SshHandler {
    /// Perform Tailscale authentication: resolve peer identity via WhoIs,
    /// evaluate the SSHPolicy, and return the auth result.
    fn tailscale_auth(&mut self, user: &str) -> Auth {
        let ssh_user = user.trim_end_matches("+password").to_string();

        if ssh_user.chars().all(|c| c.is_ascii_digit()) && !ssh_user.is_empty() {
            log::warn!(
                "rejecting username {ssh_user:?}: numeric usernames not allowed"
            );
            return Auth::Reject {
                proceed_with_methods: None,
            };
        }

        let peer_ip = match self.peer_addr {
            Some(addr) => addr.ip(),
            None => return Auth::Reject {
                proceed_with_methods: None,
            },
        };

        let (node, user_profile) = match (self.config.whois)(peer_ip) {
            Some(ident) => ident,
            None => {
                log::warn!("SSH: unknown Tailscale identity from {peer_ip}");
                return Auth::Reject {
                    proceed_with_methods: None,
                };
            }
        };

        let policy = match (self.config.policy)() {
            Some(p) => p,
            None => {
                log::warn!("SSH: no SSH policy configured");
                return Auth::Reject {
                    proceed_with_methods: None,
                };
            }
        };

        let info = ConnInfo {
            ssh_user: ssh_user.clone(),
            src_ip: peer_ip,
            dst_ip: self
                .peer_addr
                .map(|a| a.ip())
                .unwrap_or_else(|| "0.0.0.0".parse().unwrap()),
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
                    log::info!("SSH auth message: {}", action.Message);
                }
                self.ssh_user = ssh_user;
                self.local_user = local_user.clone();
                self.accept_env = accept_env.clone();
                self.auth_result = Some(result);
                Auth::Accept
            }
            EvalResult::RejectedUser => {
                log::warn!(
                    "SSH: tailnet policy does not permit {ssh_user:?} as user {ssh_user}"
                );
                Auth::Reject {
                    proceed_with_methods: None,
                }
            }
            EvalResult::Rejected | EvalResult::NoPolicy => {
                log::warn!("SSH: tailnet policy does not permit SSH to this node");
                Auth::Reject {
                    proceed_with_methods: None,
                }
            }
        }
    }

    /// Send the session to the listener and wait for the consumer to finish.
    async fn send_session(
        &mut self,
        channel_id: ChannelId,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(64);
        let (done_tx, mut done_rx) = mpsc::channel::<()>(1);

        self.channel_data_tx = Some(data_tx);
        self.done_tx = Some(done_tx);

        let handle = session.handle();

        let peer = PeerIdentity {
            node: self.auth_result.as_ref().and_then(|r| {
                if let EvalResult::Accept { .. } = r {
                    // We stored the peer info during auth, but we don't have
                    // direct access to it here. We need to re-resolve.
                    self.peer_addr
                        .and_then(|a| (self.config.whois)(a.ip()))
                        .map(|(n, u)| PeerIdentity {
                            node: n,
                            user_profile: u,
                        })
                } else {
                    None
                }
            }).unwrap_or_default(),
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
            done_tx: self.done_tx.take().unwrap_or_else(|| {
                let (tx, _) = mpsc::channel(1);
                tx
            }),
        };

        // Send the session to the listener. If the listener is closed,
        // reject the session.
        if self.config.session_tx.send(init).await.is_err() {
            return Err(russh::Error::Disconnect);
        }

        // Wait for the consumer to finish or the session to end.
        let _ = done_rx.recv().await;

        Ok(())
    }
}

impl russh::server::Handler for SshHandler {
    type Error = russh::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        Ok(self.tailscale_auth(user))
    }

    async fn auth_password(
        &mut self,
        user: &str,
        _password: &str,
    ) -> Result<Auth, Self::Error> {
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
            "SSH auth succeeded for user {:?} -> local user {:?}",
            self.ssh_user,
            self.local_user
        );
        Ok(())
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
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
        channel: ChannelId,
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
        self.channel_id = Some(channel);
        session.channel_success(channel);
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
        self.channel_id = Some(channel);
        session.channel_success(channel);
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
            self.command = String::new();
            self.channel_id = Some(channel);
            session.channel_success(channel);
            self.send_session(channel, session).await?;
        } else {
            session.channel_failure(channel);
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
        if let Some(ref mut pty) = self.pty {
            pty.window = Window {
                width: col_width,
                height: row_height,
                width_pixels: pix_width,
                height_pixels: pix_height,
            };
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
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(tx) = self.channel_data_tx.take() {
            drop(tx);
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(tx) = self.channel_data_tx.take() {
            drop(tx);
        }
        Ok(())
    }
}
