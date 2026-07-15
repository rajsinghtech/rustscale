use std::{
    fmt, io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{MemAddr, MemPipe};

/// One end of a connected, bounded in-memory byte stream.
///
/// A connection supports one concurrent reader and one concurrent writer via
/// `tokio::io::split`. Dropping or closing either endpoint closes both pipe
/// directions; already-buffered bytes remain readable before EOF.
pub struct MemConn {
    read: Arc<MemPipe>,
    write: Arc<MemPipe>,
    local_addr: MemAddr,
    remote_addr: MemAddr,
    read_waiter: Option<u64>,
    write_waiter: Option<u64>,
}

impl MemConn {
    /// Creates a connected `(first, second)` pair.
    ///
    /// The first endpoint reports `name|0` locally and `name|1` remotely; the
    /// second endpoint reports the reverse, matching Tailscale memnet.
    #[must_use]
    pub fn new_pair(name: &str, max_buf: usize) -> (Self, Self) {
        let read = Arc::new(MemPipe::new(format!("{name}|0"), max_buf));
        let write = Arc::new(MemPipe::new(format!("{name}|1"), max_buf));
        let first_addr = MemAddr::new(read.name());
        let second_addr = MemAddr::new(write.name());
        Self::from_pipes(read, write, first_addr, second_addr)
    }

    /// Creates a connected pair with TCP-style endpoint addresses.
    ///
    /// The first endpoint is local at `source` and remote at `destination`;
    /// the second reports the addresses in reverse.
    #[must_use]
    pub fn new_tcp_pair(
        source: SocketAddr,
        destination: SocketAddr,
        max_buf: usize,
    ) -> (Self, Self) {
        let read = Arc::new(MemPipe::new(source.to_string(), max_buf));
        let write = Arc::new(MemPipe::new(destination.to_string(), max_buf));
        Self::from_pipes(read, write, MemAddr::tcp(source), MemAddr::tcp(destination))
    }

    fn from_pipes(
        read: Arc<MemPipe>,
        write: Arc<MemPipe>,
        first_addr: MemAddr,
        second_addr: MemAddr,
    ) -> (Self, Self) {
        (
            Self {
                read: Arc::clone(&read),
                write: Arc::clone(&write),
                local_addr: first_addr.clone(),
                remote_addr: second_addr.clone(),
                read_waiter: None,
                write_waiter: None,
            },
            Self {
                read: write,
                write: read,
                local_addr: second_addr,
                remote_addr: first_addr,
                read_waiter: None,
                write_waiter: None,
            },
        )
    }

    /// Returns this endpoint's local address.
    #[must_use]
    pub const fn local_addr(&self) -> &MemAddr {
        &self.local_addr
    }

    /// Returns this endpoint's peer address.
    #[must_use]
    pub const fn remote_addr(&self) -> &MemAddr {
        &self.remote_addr
    }

    /// Sets or clears both read and write deadlines.
    pub fn set_deadline(&self, deadline: Option<Instant>) {
        self.set_read_deadline(deadline);
        self.set_write_deadline(deadline);
    }

    /// Sets or clears the read deadline.
    pub fn set_read_deadline(&self, deadline: Option<Instant>) {
        self.read.set_read_deadline(deadline);
    }

    /// Sets or clears the write deadline.
    pub fn set_write_deadline(&self, deadline: Option<Instant>) {
        self.write.set_write_deadline(deadline);
    }

    /// Blocks or unblocks this endpoint's reads.
    ///
    /// Because blocking applies to the directional pipe, blocking reads also
    /// stalls writes by the peer, as in Tailscale memnet.
    pub fn set_read_block(&self, blocked: bool) -> io::Result<()> {
        if blocked {
            self.read.block()
        } else {
            self.read.unblock()
        }
    }

    /// Blocks or unblocks this endpoint's writes.
    ///
    /// Because blocking applies to the directional pipe, blocking writes also
    /// stalls reads by the peer.
    pub fn set_write_block(&self, blocked: bool) -> io::Result<()> {
        if blocked {
            self.write.block()
        } else {
            self.write.unblock()
        }
    }

    /// Fully closes both directions of this connection.
    pub fn close(&self) {
        self.write.close();
        self.read.close();
    }
}

impl AsyncRead for MemConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let output = buffer.initialize_unfilled();
        match this.read.poll_read(cx, output, &mut this.read_waiter) {
            Poll::Ready(Ok(count)) => {
                buffer.advance(count);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for MemConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.write.poll_write(cx, input, &mut this.write_waiter)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().write.close();
        Poll::Ready(Ok(()))
    }
}

impl Drop for MemConn {
    fn drop(&mut self) {
        self.close();
    }
}

impl fmt::Debug for MemConn {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemConn")
            .field("local_addr", &self.local_addr)
            .field("remote_addr", &self.remote_addr)
            .finish_non_exhaustive()
    }
}
