use std::{
    collections::VecDeque,
    fmt,
    io::{self, ErrorKind},
    sync::Mutex,
};

use tokio::sync::{oneshot, Mutex as AsyncMutex, Notify};

use crate::{MemAddr, MemConn};

pub(crate) const DEFAULT_BUFFER_SIZE: usize = 256 * 1024;

struct PendingConn {
    id: u64,
    server: MemConn,
    accepted: oneshot::Sender<()>,
}

#[derive(Default)]
struct ListenerState {
    pending: VecDeque<PendingConn>,
    next_id: u64,
    closed: bool,
}

struct PendingGuard<'a> {
    listener: &'a MemListener,
    id: u64,
}

impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.listener.lock_state();
        if let Some(position) = state
            .pending
            .iter()
            .position(|pending| pending.id == self.id)
        {
            state.pending.remove(position);
        }
    }
}

/// A logical-address in-memory listener with rendezvous dial semantics.
///
/// A dial does not complete until an accept operation takes its server half.
/// Closing the listener wakes pending accepts and dials and drops every queued
/// connection half.
pub struct MemListener {
    addr: MemAddr,
    state: Mutex<ListenerState>,
    accept_order: AsyncMutex<()>,
    changed: Notify,
    on_close: Mutex<Option<Box<dyn FnOnce() + Send + 'static>>>,
}

impl MemListener {
    /// Creates an unregistered listener at an arbitrary logical address.
    #[must_use]
    pub fn listen(address: impl Into<String>) -> Self {
        Self {
            addr: MemAddr::new(address),
            state: Mutex::new(ListenerState::default()),
            accept_order: AsyncMutex::new(()),
            changed: Notify::new(),
            on_close: Mutex::new(None),
        }
    }

    /// Returns the listener's logical address.
    #[must_use]
    pub const fn addr(&self) -> &MemAddr {
        &self.addr
    }

    /// Waits for the next successful dial or for listener close.
    ///
    /// Concurrent accepts are serialized in call order by Tokio's fair mutex.
    pub async fn accept(&self) -> io::Result<MemConn> {
        let _order = self.accept_order.lock().await;
        loop {
            // Register before inspecting state so a dial or close between the
            // inspection and await cannot be lost.
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            let pending = {
                let mut state = self.lock_state();
                if state.closed {
                    return Err(closed_error());
                }
                state.pending.pop_front()
            };
            if let Some(pending) = pending {
                // Cancellation normally removes the entry. If cancellation
                // races this handoff, the failed send identifies the orphan.
                if pending.accepted.send(()).is_ok() {
                    return Ok(pending.server);
                }
                continue;
            }
            notified.await;
        }
    }

    /// Dials this listener and waits until an accept operation receives it.
    ///
    /// Dropping this future cancels the dial. Cancellation before handoff is
    /// detected by `accept`, which discards the orphaned server half.
    pub async fn dial(&self, network: &str, address: &str) -> io::Result<MemConn> {
        validate_network(network)?;
        if address != self.addr.as_str() {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("invalid memnet address {address:?}"),
            ));
        }

        let (client, server) = MemConn::new_pair(address, DEFAULT_BUFFER_SIZE);
        let (accepted_tx, accepted_rx) = oneshot::channel();
        let id = {
            let mut state = self.lock_state();
            if state.closed {
                return Err(closed_error());
            }
            let id = state.next_id;
            state.next_id = state.next_id.wrapping_add(1);
            state.pending.push_back(PendingConn {
                id,
                server,
                accepted: accepted_tx,
            });
            id
        };
        let guard = PendingGuard { listener: self, id };
        self.changed.notify_one();

        let result = accepted_rx
            .await
            .map(|()| client)
            .map_err(|_| closed_error());
        drop(guard);
        result
    }

    /// Closes this listener. Repeated calls are harmless.
    pub fn close(&self) {
        {
            let mut state = self.lock_state();
            if state.closed {
                return;
            }
            state.closed = true;
            state.pending.clear();
        }
        self.changed.notify_waiters();
        if let Some(cleanup) = self
            .on_close
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            cleanup();
        }
    }

    /// Reports whether [`Self::close`] has been called.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.lock_state().closed
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, ListenerState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn set_on_close(&self, cleanup: Box<dyn FnOnce() + Send + 'static>) {
        *self
            .on_close
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(cleanup);
    }
}

impl Drop for MemListener {
    fn drop(&mut self) {
        self.close();
    }
}

impl fmt::Debug for MemListener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemListener")
            .field("addr", &self.addr)
            .field("closed", &self.is_closed())
            .finish_non_exhaustive()
    }
}

pub(crate) fn validate_network(network: &str) -> io::Result<()> {
    match network {
        "tcp" | "tcp4" | "tcp6" => Ok(()),
        _ => Err(io::Error::new(
            ErrorKind::Unsupported,
            format!("unknown memnet network {network:?}"),
        )),
    }
}

fn closed_error() -> io::Error {
    io::Error::new(ErrorKind::ConnectionAborted, "memnet listener is closed")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::MemListener;

    #[tokio::test]
    async fn cancel_removes_pending_dial_without_accept_or_close() {
        let listener = Arc::new(MemListener::listen("cancel-cleanup"));
        for _ in 0..128 {
            let dialing = Arc::clone(&listener);
            let dial = tokio::spawn(async move { dialing.dial("tcp", "cancel-cleanup").await });
            while listener.lock_state().pending.is_empty() {
                tokio::task::yield_now().await;
            }

            dial.abort();
            let _ = dial.await;
            assert!(listener.lock_state().pending.is_empty());
        }
    }
}
