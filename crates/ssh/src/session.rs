//! SSH session type — ports Go's `ssh/tailssh/session.go`.
//!
//! A [`Session`] wraps an SSH channel with Tailscale peer identity
//! information. It implements [`tokio::io::AsyncRead`] + [`AsyncWrite`] so
//! callers that only need read/write/close can use it as a stream. Accessor
//! methods expose the peer identity, SSH user, command, environment, and PTY
//! info for callers that need richer SSH semantics.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use russh::server::Handle;
use russh::ChannelId;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex};

use rustscale_tailcfg::{Node, UserProfile};

/// PTY window dimensions.
#[derive(Clone, Debug, Default)]
pub struct Window {
    pub width: u32,
    pub height: u32,
    pub width_pixels: u32,
    pub height_pixels: u32,
}

/// PTY request information.
#[derive(Clone, Debug, Default)]
pub struct Pty {
    pub term: String,
    pub window: Window,
}

/// The Tailscale identity of the connecting SSH peer.
#[derive(Clone, Debug, Default)]
pub struct PeerIdentity {
    pub node: Node,
    pub user_profile: UserProfile,
}

/// Internal data sent from the SSH handler to the listener when a session
/// is ready (shell or exec request received).
pub(crate) struct SessionInit {
    pub peer: PeerIdentity,
    pub ssh_user: String,
    pub command: String,
    pub env: Vec<(String, String)>,
    pub pty: Option<Pty>,
    pub handle: Handle,
    pub channel_id: ChannelId,
    pub data_rx: mpsc::Receiver<Vec<u8>>,
    pub done_tx: mpsc::Sender<()>,
}

/// An accepted Tailscale SSH session. Wraps the SSH channel with peer
/// identity and metadata. Implements [`AsyncRead`] + [`AsyncWrite`] for
/// simple stream usage; use accessor methods for SSH-specific details.
pub struct Session {
    peer: PeerIdentity,
    ssh_user: String,
    command: String,
    env: Vec<(String, String)>,
    pty: Option<Pty>,
    handle: Handle,
    channel_id: ChannelId,
    data_rx: mpsc::Receiver<Vec<u8>>,
    read_buf: Vec<u8>,
    done_tx: Option<mpsc::Sender<()>>,
    closed: bool,
}

impl Session {
    pub(crate) fn from_init(init: SessionInit) -> Self {
        Self {
            peer: init.peer,
            ssh_user: init.ssh_user,
            command: init.command,
            env: init.env,
            pty: init.pty,
            handle: init.handle,
            channel_id: init.channel_id,
            data_rx: init.data_rx,
            read_buf: Vec::new(),
            done_tx: Some(init.done_tx),
            closed: false,
        }
    }

    /// The SSH username requested by the client.
    pub fn user(&self) -> &str {
        &self.ssh_user
    }

    /// The Tailscale identity of the remote peer (node + user profile).
    pub fn peer(&self) -> &PeerIdentity {
        &self.peer
    }

    /// The node of the connecting peer.
    pub fn peer_node(&self) -> &Node {
        &self.peer.node
    }

    /// The user profile of the connecting peer.
    pub fn peer_user_profile(&self) -> &UserProfile {
        &self.peer.user_profile
    }

    /// The exact command string provided by the client (empty for shell).
    pub fn raw_command(&self) -> &str {
        &self.command
    }

    /// Whether this is a shell session (no command).
    pub fn is_shell(&self) -> bool {
        self.command.is_empty()
    }

    /// Environment variables set by the client (filtered by policy).
    pub fn environ(&self) -> &[(String, String)] {
        &self.env
    }

    /// PTY info if a PTY was requested.
    pub fn pty(&self) -> Option<&Pty> {
        self.pty.as_ref()
    }

    /// Send an exit status to the client and close the session.
    pub async fn exit(&mut self, code: u32) {
        if self.closed {
            return;
        }
        self.closed = true;
        let _ = self.handle.exit_status_request(self.channel_id, code).await;
        let _ = self.handle.eof(self.channel_id).await;
        let _ = self.handle.close(self.channel_id).await;
        if let Some(tx) = self.done_tx.take() {
            let _ = tx.send(()).await;
        }
    }

    /// Close the session without an exit status.
    pub async fn close(&mut self) {
        self.exit(0).await;
    }
}

impl AsyncRead for Session {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();

        if this.closed {
            return std::task::Poll::Ready(Ok(()));
        }

        if !this.read_buf.is_empty() {
            let n = std::cmp::min(this.read_buf.len(), buf.remaining());
            buf.put_slice(&this.read_buf[..n]);
            this.read_buf.drain(..n);
            return std::task::Poll::Ready(Ok(()));
        }

        match this.data_rx.poll_recv(cx) {
            std::task::Poll::Ready(Some(data)) => {
                if data.is_empty() {
                    return std::task::Poll::Ready(Ok(()));
                }
                let n = std::cmp::min(data.len(), buf.remaining());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    this.read_buf.extend_from_slice(&data[n..]);
                }
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(None) => {
                this.closed = true;
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl AsyncWrite for Session {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.closed {
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "session closed",
            )));
        }

        let this = self.get_mut();
        let handle = this.handle.clone();
        let channel_id = this.channel_id;
        let data = buf.to_vec();

        // We need to spawn the async send operation. Since Handle::data is
        // async, we use a channel to bridge the sync poll_write with the
 // async send.
        let waker = cx.waker().clone();
        tokio::spawn(async move {
            let data = russh::CryptoVec::from(data);
            let _ = handle.data(channel_id, data).await;
            waker.wake();
        });

        std::task::Poll::Pending
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if !this.closed {
            this.closed = true;
            let handle = this.handle.clone();
            let channel_id = this.channel_id;
            tokio::spawn(async move {
                let _ = handle.eof(channel_id).await;
                let _ = handle.close(channel_id).await;
            });
        }
        std::task::Poll::Ready(Ok(()))
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Some(tx) = self.done_tx.take() {
            let _ = tx.try_send(());
        }
    }
}
