//! Notification bus — a broadcast channel for [`Notify`] messages.
//!
//! Uses `tokio::sync::broadcast` so multiple `watch-ipn-bus` subscribers
//! can receive the same stream. Each subscriber gets its own
//! [`NotifyBusReceiver`] with an independent cursor.

use std::sync::Arc;

use tokio::sync::{broadcast, Notify as TokioNotify};

use crate::Notify;

/// Default channel capacity per subscriber. Matches Go's buffered channel
/// size of 128 in `WatchNotificationsAs`.
const CHANNEL_CAPACITY: usize = 128;

/// A broadcast bus for `Notify` messages.
///
/// Owned by the `IpnBackend` (which is `Arc`-shared between the tsnet
/// `Server` and `LocalApiState`). Each `watch-ipn-bus` connection calls
/// [`subscribe`] to get a [`NotifyBusReceiver`] and then loops on
/// `recv().await`.
///
/// [`subscribe`]: NotifyBus::subscribe
#[derive(Clone)]
pub struct NotifyBus {
    tx: broadcast::Sender<Notify>,
    /// Notify flag so `subscribe()` can wake up immediately after
    /// registration without waiting for the next broadcast.
    _notify: Arc<TokioNotify>,
}

impl NotifyBus {
    /// Create a new bus with the default channel capacity.
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(CHANNEL_CAPACITY);
        Self {
            tx,
            _notify: Arc::new(TokioNotify::new()),
        }
    }

    /// Broadcast a `Notify` to all current subscribers.
    ///
    /// Returns `false` if there are no subscribers (the message is dropped).
    /// This is non-blocking: if a subscriber's buffer is full, the oldest
    /// message is dropped from that subscriber's queue and the receiver
    /// will see a [`broadcast::error::RecvError::Lagged`] on next recv.
    pub fn send(&self, notify: Notify) -> bool {
        self.tx.send(notify).is_ok()
    }

    /// Subscribe to the bus. Returns a receiver that will see all messages
    /// broadcast after this call.
    pub fn subscribe(&self) -> NotifyBusReceiver {
        NotifyBusReceiver {
            rx: self.tx.subscribe(),
        }
    }

    /// Returns the number of active subscribers.
    pub fn receiver_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

impl Default for NotifyBus {
    fn default() -> Self {
        Self::new()
    }
}

/// A receiver for [`Notify`] messages from a [`NotifyBus`].
pub struct NotifyBusReceiver {
    rx: broadcast::Receiver<Notify>,
}

impl NotifyBusReceiver {
    /// Receive the next notification. Returns `None` when all senders have
    /// been dropped (i.e. the bus is shut down). Returns
    /// `Some(Err(Lagged(n)))` if the subscriber fell behind and `n`
    /// messages were lost.
    pub async fn recv(&mut self) -> Option<Result<Notify, broadcast::error::RecvError>> {
        match self.rx.recv().await {
            Ok(notify) => Some(Ok(notify)),
            Err(broadcast::error::RecvError::Closed) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::State;

    #[tokio::test]
    async fn bus_delivers_to_multiple_subscribers() {
        let bus = NotifyBus::new();
        let mut sub1 = bus.subscribe();
        let mut sub2 = bus.subscribe();

        bus.send(Notify::state(State::Running));

        let msg1 = sub1.recv().await.unwrap().unwrap();
        let msg2 = sub2.recv().await.unwrap().unwrap();

        assert_eq!(msg1.State, Some(State::Running));
        assert_eq!(msg2.State, Some(State::Running));
    }

    #[tokio::test]
    async fn bus_returns_false_with_no_subscribers() {
        let bus = NotifyBus::new();
        assert!(!bus.send(Notify::state(State::Running)));
    }

    #[tokio::test]
    async fn subscriber_only_sees_messages_after_subscribe() {
        let bus = NotifyBus::new();
        bus.send(Notify::state(State::Starting));

        let mut sub = bus.subscribe();
        bus.send(Notify::state(State::Running));

        let msg = sub.recv().await.unwrap().unwrap();
        assert_eq!(msg.State, Some(State::Running));
    }

    #[tokio::test]
    async fn bus_clone_shares_channel() {
        let bus = NotifyBus::new();
        let bus2 = bus.clone();
        let mut sub = bus.subscribe();

        bus2.send(Notify::state(State::Stopped));

        let msg = sub.recv().await.unwrap().unwrap();
        assert_eq!(msg.State, Some(State::Stopped));
    }

    #[tokio::test]
    async fn receiver_count_tracks_subscribers() {
        let bus = NotifyBus::new();
        assert_eq!(bus.receiver_count(), 0);

        let sub1 = bus.subscribe();
        assert_eq!(bus.receiver_count(), 1);

        let _sub2 = bus.subscribe();
        assert_eq!(bus.receiver_count(), 2);

        drop(sub1);
        assert_eq!(bus.receiver_count(), 1);
    }
}
