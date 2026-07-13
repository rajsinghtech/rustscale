//! Tailscale SSH listener for tsnet — feature-gated behind the `ssh` feature.
//!
//! Ports Go's `tsnet.Server.ListenSSH` and `ssh/tailssh/listen.go`.

use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use rustscale_ssh::session::SessionInit;
use rustscale_ssh::{handle_ssh_conn, host_key_from_node_key, Session, SshServer, SshServerConfig};

use crate::Server;

/// An SSH listener that yields [`Session`] values from its `accept()` method.
pub struct SshListener {
    init_rx: mpsc::Receiver<SessionInit>,
    _task: JoinHandle<()>,
}

impl SshListener {
    pub async fn accept(&mut self) -> Option<Session> {
        if let Some(init) = self.init_rx.recv().await {
            return Some(Session::from_init(init));
        }
        None
    }

    /// Accept the next SSH session and spawn an async task that runs it to
    /// completion (resolves local user, spawns shell, pumps I/O).
    ///
    /// The returned `JoinHandle` resolves to the shell exit code. Callers
    /// that want custom processing should use `accept()` and `run_session()`
    /// directly instead.
    pub async fn accept_and_run(
        &mut self,
    ) -> Option<JoinHandle<Result<i32, rustscale_ssh::SessionHandlerError>>> {
        let session = self.accept().await?;
        Some(tokio::spawn(async move {
            rustscale_ssh::run_session(session, None).await
        }))
    }
}

impl Server {
    /// Listen for incoming SSH connections on the given port (netstack mode
    /// only). Requires the `ssh` cargo feature.
    pub async fn listen_ssh(&self, port: u16) -> Result<SshListener, crate::TsnetError> {
        let inner = self.inner.as_ref().ok_or(crate::TsnetError::NotUp)?;

        let tcp_listener = match &inner.data_plane {
            crate::DataPlane::Netstack(ns) => ns.listen(port).await?,
            crate::DataPlane::Tun => return Err(crate::TsnetError::NotAvailableInTunMode),
        };

        let host_key = host_key_from_node_key(&inner.node_key);
        let host_keys = vec![host_key];

        let peers = inner.peers.clone();
        let user_profiles = inner.user_profiles.clone();
        let ssh_policy = inner.ssh_policy.clone();

        let whois: rustscale_ssh::WhoIsCallback = Arc::new(move |ip| {
            let peers_guard = peers.try_read();
            let ups_guard = user_profiles.try_read();
            if let (Ok(peers), Ok(ups)) = (peers_guard, ups_guard) {
                for peer in peers.iter() {
                    if crate::extract_node_ips(peer).contains(&ip) {
                        let profile = ups.get(&peer.User).cloned().unwrap_or_default();
                        return Some((peer.clone(), profile));
                    }
                }
            }
            None
        });

        // Policy callback: reads the current SSHPolicy from the shared netmap
        // state. Returns None (→ reject "no policy configured") until the
        // control server sends a policy; thereafter returns the latest policy
        // for eval_ssh_policy to evaluate against the connecting peer.
        // Mirrors Go's `conn.sshPolicy()` reading `netMap.SSHPolicy`.
        let policy: rustscale_ssh::PolicyCallback =
            Arc::new(move || ssh_policy.try_read().ok().and_then(|guard| guard.clone()));

        let (session_tx, init_rx) = mpsc::channel::<SessionInit>(16);
        let session_tx = Arc::new(session_tx);

        let russh_config = Arc::new(russh::server::Config {
            server_id: russh::SshId::Standard("SSH-2.0-rustscale-tailssh".into()),
            keys: host_keys.clone(),
            methods: russh::MethodSet::all(),
            auth_rejection_time: std::time::Duration::from_secs(1),
            auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
            max_auth_attempts: 10,
            inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
            ..Default::default()
        });

        let whois_clone = whois.clone();
        let policy_clone = policy.clone();
        let host_keys_clone = host_keys.clone();

        let task = tokio::spawn(async move {
            let mut tcp_listener = tcp_listener;
            loop {
                match tcp_listener.accept().await {
                    Ok(stream) => {
                        let peer_addr = stream.peer_addr();
                        let config = russh_config.clone();
                        let tx = (*session_tx).clone();
                        let whois = whois_clone.clone();
                        let policy = policy_clone.clone();
                        let hk = host_keys_clone.clone();

                        tokio::spawn(async move {
                            let ssh_config = SshServerConfig {
                                host_keys: hk,
                                session_tx: tx,
                                whois,
                                policy,
                            };
                            let mut server = SshServer::new(ssh_config);
                            let _ = handle_ssh_conn(config, &mut server, stream, peer_addr).await;
                        });
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(SshListener {
            init_rx,
            _task: task,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustscale_tailcfg::{SSHAction, SSHPolicy, SSHPrincipal, SSHRule};
    use std::collections::BTreeMap;
    use tokio::sync::RwLock;

    /// The policy callback installed by `listen_ssh` reads the current
    /// SSHPolicy from the shared netmap state (`inner.ssh_policy`). This
    /// test verifies that wiring: `None` until the control server sends a
    /// policy, then `Some(policy)` after.
    #[tokio::test]
    async fn policy_callback_reads_shared_state() {
        let ssh_policy: Arc<RwLock<Option<SSHPolicy>>> = Arc::new(RwLock::new(None));

        // Build the same closure pattern used in `listen_ssh`.
        let policy: rustscale_ssh::PolicyCallback = {
            let ssh_policy = ssh_policy.clone();
            Arc::new(move || ssh_policy.try_read().ok().and_then(|g| g.clone()))
        };

        // No policy yet → callback returns None (server rejects "no policy").
        assert!(policy().is_none());

        // Control server pushes a policy via the map update task.
        let test_policy = SSHPolicy {
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
        *ssh_policy.write().await = Some(test_policy.clone());

        // Callback now returns the policy.
        let got = policy().expect("policy should be available after write");
        assert_eq!(got, test_policy);
    }
}
