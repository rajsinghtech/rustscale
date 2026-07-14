use std::{
    io::{self, ErrorKind},
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
};

use tokio::sync::{mpsc, watch, Mutex as AsyncMutex};

use crate::{MemAddr, MemConn};

pub(crate) const DEFAULT_BUFFER_SIZE: usize = 256 * 1024;

/// A name-bound in-memory listener.
pub struct MemListener {
    addr: MemAddr,
    tx: mpsc::Sender<MemConn>,
    rx: AsyncMutex<mpsc::Receiver<MemConn>>,
    closed: AtomicBool,
    close_tx: watch::Sender<bool>,
    on_close: Mutex<Option<Box<dyn FnOnce() + Send + 'static>>>,
}

impl MemListener {
    /// Creates a listener for `name` without registering it in a [`crate::Network`].
    #[must_use]
    pub fn listen(name: &str) -> Self {
        let (tx, rx) = mpsc::channel(1);
        let (close_tx, _) = watch::channel(false);
        Self {
            addr: MemAddr::new(name),
            tx,
            rx: AsyncMutex::new(rx),
            closed: AtomicBool::new(false),
            close_tx,
            on_close: Mutex::new(None),
        }
    }

    /// Returns the logical address to which this listener is bound.
    #[must_use]
    pub const fn addr(&self) -> &MemAddr {
        &self.addr
    }

    /// Waits for and returns the next incoming connection.
    pub async fn accept(&self) -> io::Result<MemConn> {
        let mut closed = self.close_tx.subscribe();
        if *closed.borrow() {
            return Err(closed_error());
        }
        let mut receiver = self.rx.lock().await;
        tokio::select! {
            biased;
            _ = closed.changed() => {
                drain(&mut receiver);
                Err(closed_error())
            },
            connection = receiver.recv() => connection.ok_or_else(closed_error),
        }
    }

    /// Connects to this listener's address.
    pub async fn dial(&self, addr: &str) -> io::Result<MemConn> {
        if addr != self.addr.as_str() {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "invalid memnet address",
            ));
        }
        let mut closed = self.close_tx.subscribe();
        if *closed.borrow() {
            return Err(closed_error());
        }

        let (client, server) = MemConn::with_addrs(addr, DEFAULT_BUFFER_SIZE);
        tokio::select! {
            biased;
            _ = closed.changed() => Err(closed_error()),
            result = self.tx.send(server) => result.map(|()| client).map_err(|_| closed_error()),
        }
    }

    /// Closes the listener and removes it from its network, if registered.
    pub fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.close_tx.send_replace(true);
        if let Ok(mut receiver) = self.rx.try_lock() {
            drain(&mut receiver);
        }
        if let Some(cleanup) = self
            .on_close
            .lock()
            .expect("listener mutex poisoned")
            .take()
        {
            cleanup();
        }
    }

    pub(crate) fn set_on_close(&self, cleanup: Box<dyn FnOnce() + Send + 'static>) {
        *self.on_close.lock().expect("listener mutex poisoned") = Some(cleanup);
    }
}

impl Drop for MemListener {
    fn drop(&mut self) {
        self.close();
    }
}

fn closed_error() -> io::Error {
    io::Error::new(ErrorKind::ConnectionAborted, "memnet listener is closed")
}

fn drain(receiver: &mut mpsc::Receiver<MemConn>) {
    while receiver.try_recv().is_ok() {}
}
