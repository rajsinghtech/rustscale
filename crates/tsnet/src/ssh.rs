//! Tailscale SSH listener for tsnet — feature-gated behind the `ssh` feature.
//!
//! Ports Go's `tsnet.Server.ListenSSH` and `ssh/tailssh/listen.go`.

use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use rustscale_ssh::session::SessionInit;
use rustscale_ssh::{
    handle_ssh_conn, host_key_from_node_key, host_key_public_string, Session, SshServer,
    SshServerConfig,
};

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
        *inner.ssh_host_keys.write().await = host_keys.iter().map(host_key_public_string).collect();

        let peers = inner.peers.clone();
        let recorder_peers = inner.peers.clone();
        let recorder_netstack = match &inner.data_plane {
            crate::DataPlane::Netstack(netstack) => netstack.clone(),
            crate::DataPlane::Tun => return Err(crate::TsnetError::NotAvailableInTunMode),
        };
        let state_dir = debug_local_recording_enabled()
            .then(|| self.config.state_dir.clone())
            .flatten();
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

        // Recorder endpoints are capability-derived values in the matched SSH
        // policy. Require each endpoint IP to identify a current, non-expired
        // netmap peer, then dial that exact address through the userspace
        // tailnet. There is deliberately no DNS or host-network fallback.
        let dial_fn: rustscale_ssh::DialFn = Arc::new(move |recorder| {
            let netstack = recorder_netstack.clone();
            let peers = recorder_peers.clone();
            Box::pin(async move {
                let authorized = recorder_is_authorized(&peers.read().await, recorder);
                if !authorized {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "recorder endpoint is not an authorized netmap peer",
                    ));
                }
                let stream = netstack
                    .dial(recorder)
                    .await
                    .map_err(std::io::Error::other)?;
                Ok(Box::new(stream) as rustscale_ssh::BoxedIo)
            })
        });

        // Admission is bound to the currently published map Noise generation.
        // This producer contains no machine/control credentials and cannot
        // establish a fresh transport.
        let control_notifier = inner.ssh_callbacks.notifier();
        let recording_notify: rustscale_ssh::RecordingNotifyCallback =
            Arc::new(move |notify_url, request| {
                if control_notifier.enqueue(notify_url, &request).is_err() {
                    // Do not log callback URLs, identities, recorder attempts,
                    // or control-generation details.
                    log::warn!("SSH recording callback could not be queued");
                }
            });
        let node_key = inner.node_key.public();

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
        let dial_fn_clone = dial_fn.clone();
        let state_dir_clone = state_dir.clone();
        let recording_notify_clone = recording_notify.clone();

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
                        let dial_fn = dial_fn_clone.clone();
                        let state_dir = state_dir_clone.clone();
                        let recording_notify = recording_notify_clone.clone();
                        let node_key = node_key.clone();

                        tokio::spawn(async move {
                            let ssh_config = SshServerConfig {
                                host_keys: hk,
                                session_tx: tx,
                                whois,
                                policy,
                                state_dir,
                                dial_fn: Some(dial_fn),
                                recording_notify: Some(recording_notify),
                                node_key,
                                capability_version: crate::CAPABILITY_VERSION,
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

fn recorder_is_authorized(
    peers: &[rustscale_tailcfg::Node],
    recorder: std::net::SocketAddr,
) -> bool {
    peers.iter().any(|node| {
        !node.Expired
            && !node.UnsignedPeerAPIOnly
            && crate::extract_node_ips(node).contains(&recorder.ip())
    })
}

fn debug_local_recording_enabled() -> bool {
    std::env::var("TS_DEBUG_LOG_SSH").is_ok_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustscale_tailcfg::{Node, SSHAction, SSHPolicy, SSHPrincipal, SSHRule};
    use std::collections::BTreeMap;
    use tokio::sync::RwLock;

    #[test]
    fn recorder_selection_requires_current_full_netmap_peer() {
        let recorder: std::net::SocketAddr = "100.64.0.9:80".parse().unwrap();
        let peer = Node {
            Addresses: vec!["100.64.0.9/32".into()],
            ..Default::default()
        };
        assert!(recorder_is_authorized(
            std::slice::from_ref(&peer),
            recorder
        ));
        assert!(!recorder_is_authorized(
            std::slice::from_ref(&peer),
            "100.64.0.10:80".parse().unwrap()
        ));

        let mut expired = peer.clone();
        expired.Expired = true;
        assert!(!recorder_is_authorized(&[expired], recorder));

        let mut peerapi_only = peer;
        peerapi_only.UnsignedPeerAPIOnly = true;
        assert!(!recorder_is_authorized(&[peerapi_only], recorder));
    }

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
