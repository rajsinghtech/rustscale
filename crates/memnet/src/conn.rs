use std::{
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
    task::{Context, Poll, Waker},
};

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

use crate::MemAddr;

/// One end of a connected in-memory byte stream.
pub struct MemConn {
    read: DuplexStream,
    write: DuplexStream,
    local_addr: MemAddr,
    remote_addr: MemAddr,
    read_gate: Gate,
    write_gate: Gate,
}

impl MemConn {
    /// Creates a connected `(client, server)` pair backed by bounded duplex streams.
    #[must_use]
    pub fn new_pair(name: &str, max_buf: usize) -> (Self, Self) {
        let (client_read, server_write) = tokio::io::duplex(max_buf);
        let (server_read, client_write) = tokio::io::duplex(max_buf);
        let address = MemAddr::new(name);
        (
            Self::new(client_read, client_write, address.clone(), address.clone()),
            Self::new(server_read, server_write, address.clone(), address),
        )
    }

    pub(crate) fn with_addrs(name: &str, max_buf: usize) -> (Self, Self) {
        Self::new_pair(name, max_buf)
    }

    fn new(
        read: DuplexStream,
        write: DuplexStream,
        local_addr: MemAddr,
        remote_addr: MemAddr,
    ) -> Self {
        Self {
            read,
            write,
            local_addr,
            remote_addr,
            read_gate: Gate::default(),
            write_gate: Gate::default(),
        }
    }

    /// Returns this connection's logical local address.
    #[must_use]
    pub const fn local_addr(&self) -> &MemAddr {
        &self.local_addr
    }

    /// Returns this connection's logical peer address.
    #[must_use]
    pub const fn remote_addr(&self) -> &MemAddr {
        &self.remote_addr
    }

    /// Stalls future reads until [`Self::unblock_read`] is called.
    pub fn block_read(&self) {
        self.read_gate.block();
    }

    /// Resumes reads stalled by [`Self::block_read`].
    pub fn unblock_read(&self) {
        self.read_gate.unblock();
    }

    /// Stalls future writes until [`Self::unblock_write`] is called.
    pub fn block_write(&self) {
        self.write_gate.block();
    }

    /// Resumes writes stalled by [`Self::block_write`].
    pub fn unblock_write(&self) {
        self.write_gate.unblock();
    }
}

impl AsyncRead for MemConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.read_gate.poll_ready(context).is_pending() {
            return Poll::Pending;
        }
        Pin::new(&mut self.read).poll_read(context, buffer)
    }
}

impl AsyncWrite for MemConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_gate.poll_ready(context).is_pending() {
            return Poll::Pending;
        }
        Pin::new(&mut self.write).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_gate.poll_ready(context).is_pending() {
            return Poll::Pending;
        }
        Pin::new(&mut self.write).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_gate.poll_ready(context).is_pending() {
            return Poll::Pending;
        }
        Pin::new(&mut self.write).poll_shutdown(context)
    }
}

#[derive(Default)]
struct Gate {
    blocked: AtomicBool,
    waiters: Mutex<Vec<Waker>>,
}

impl Gate {
    fn block(&self) {
        self.blocked.store(true, Ordering::Release);
    }

    fn unblock(&self) {
        self.blocked.store(false, Ordering::Release);
        let waiters = std::mem::take(&mut *self.waiters.lock().expect("gate mutex poisoned"));
        for waker in waiters {
            waker.wake();
        }
    }

    fn poll_ready(&self, context: &Context<'_>) -> Poll<()> {
        if !self.blocked.load(Ordering::Acquire) {
            return Poll::Ready(());
        }
        let mut waiters = self.waiters.lock().expect("gate mutex poisoned");
        if !self.blocked.load(Ordering::Acquire) {
            return Poll::Ready(());
        }
        if !waiters.iter().any(|waker| waker.will_wake(context.waker())) {
            waiters.push(context.waker().clone());
        }
        Poll::Pending
    }
}
