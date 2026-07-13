//! SSH session type — ports Go's `ssh/tailssh/session.go`.
#![allow(dead_code)]

use crate::recording::{RecordDir, RecordResult, SessionRecorder};
use russh::{ChannelId, Sig};
use rustscale_tailcfg::{Node, UserProfile};
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

#[derive(Clone, Debug, Default)]
pub struct Window {
    pub width: u32,
    pub height: u32,
    pub width_pixels: u32,
    pub height_pixels: u32,
}

#[derive(Clone, Debug, Default)]
pub struct Pty {
    pub term: String,
    pub window: Window,
}

#[derive(Clone, Debug, Default)]
pub struct PeerIdentity {
    pub node: Node,
    pub user_profile: UserProfile,
}

pub struct SessionInit {
    pub peer: PeerIdentity,
    pub ssh_user: String,
    pub command: String,
    pub env: Vec<(String, String)>,
    pub pty: Option<Pty>,
    pub handle: russh::server::Handle,
    pub channel_id: ChannelId,
    pub data_rx: mpsc::Receiver<Vec<u8>>,
    pub done_tx: mpsc::Sender<()>,
    /// Optional session recorder for capturing PTY output.
    pub recorder: Option<SessionRecorder>,
    /// Receiver for SSH signals (SIGINT, SIGTERM, etc.) forwarded by
    /// SshHandler::signal. Mirrors Go's signal handling in handleSession.
    pub signal_rx: mpsc::Receiver<Sig>,
    /// Receiver for PTY window-size changes forwarded by
    /// SshHandler::window_change_request.
    pub window_change_rx: mpsc::Receiver<Window>,
    /// TCP peer address of the SSH client (used for SSH_CLIENT/SSH_CONNECTION).
    pub peer_addr: Option<SocketAddr>,
}

pub struct Session {
    peer: PeerIdentity,
    ssh_user: String,
    command: String,
    env: Vec<(String, String)>,
    pty: Option<Pty>,
    handle: russh::server::Handle,
    channel_id: ChannelId,
    data_rx: mpsc::Receiver<Vec<u8>>,
    read_buf: Vec<u8>,
    done_tx: Option<mpsc::Sender<()>>,
    closed: bool,
    recorder: Option<SessionRecorder>,
    signal_rx: mpsc::Receiver<Sig>,
    window_change_rx: mpsc::Receiver<Window>,
    peer_addr: Option<SocketAddr>,
}

impl Session {
    pub fn from_init(init: SessionInit) -> Self {
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
            recorder: init.recorder,
            signal_rx: init.signal_rx,
            window_change_rx: init.window_change_rx,
            peer_addr: init.peer_addr,
        }
    }
    pub fn user(&self) -> &str {
        &self.ssh_user
    }
    pub fn peer(&self) -> &PeerIdentity {
        &self.peer
    }
    pub fn peer_node(&self) -> &Node {
        &self.peer.node
    }
    pub fn peer_user_profile(&self) -> &UserProfile {
        &self.peer.user_profile
    }
    pub fn raw_command(&self) -> &str {
        &self.command
    }
    pub fn is_shell(&self) -> bool {
        self.command.is_empty()
    }
    pub fn environ(&self) -> &[(String, String)] {
        &self.env
    }
    pub fn pty(&self) -> Option<&Pty> {
        self.pty.as_ref()
    }
    /// Returns the session recorder, if recording is enabled.
    pub fn recorder(&self) -> Option<&SessionRecorder> {
        self.recorder.as_ref()
    }
    /// Take the session recorder out of the Session, leaving None in its place.
    pub fn take_recorder(&mut self) -> Option<SessionRecorder> {
        self.recorder.take()
    }
    /// Returns the russh server handle (for sending data/extended_data/exit).
    pub fn handle(&self) -> &russh::server::Handle {
        &self.handle
    }
    /// Returns the SSH channel ID.
    pub fn channel_id(&self) -> ChannelId {
        self.channel_id
    }
    /// Returns the TCP peer address of the SSH client.
    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }
    /// Takes the signal receiver out of the Session.
    pub fn take_signal_rx(&mut self) -> mpsc::Receiver<Sig> {
        std::mem::replace(&mut self.signal_rx, mpsc::channel(1).1)
    }
    /// Takes the window-change receiver out of the Session.
    pub fn take_window_change_rx(&mut self) -> mpsc::Receiver<Window> {
        std::mem::replace(&mut self.window_change_rx, mpsc::channel(1).1)
    }

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
        // Record output to the session recorder before sending to the client.
        // Mirrors Go's `recording.writer("o", w)` wrapping the PTY output.
        if let Some(ref rec) = this.recorder {
            if matches!(rec.write(RecordDir::Output, buf), RecordResult::Failed) {
                log::warn!("SSH session recording failed; continuing per fail-open policy");
            }
        }
        let handle = this.handle.clone();
        let channel_id = this.channel_id;
        let data = buf.to_vec();
        let waker = cx.waker().clone();
        tokio::spawn(async move {
            let _ = handle.data(channel_id, russh::CryptoVec::from(data)).await;
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
