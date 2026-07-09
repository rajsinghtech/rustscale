//! The network change monitor: debounce loop, wall-time jump detection,
//! and pluggable OS event sources.
//!
//! Ports the semantics of Go's `net/netmon/netmon.go` (`Monitor.pump` +
//! `Monitor.debounce` + `handlePotentialChange`). A [`Monitor`] owns a
//! [`State`] snapshot, an OS event source (AF_ROUTE on macOS, polling
//! elsewhere), and a debounce task that coalesces rapid bursts of events
//! into callback invocations.

use std::sync::{atomic::AtomicBool, Arc, RwLock};
use std::time::{Duration, SystemTime};

use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;

use crate::state::{gather_state, State};

/// How often to check wall time for sleep/wake jumps.
const WALL_TICK: Duration = Duration::from_secs(15);

/// Minimum wall-clock elapsed time to treat as a time jump (sleep wake).
const TIME_JUMP_THRESHOLD: Duration = Duration::from_secs(60);

/// Debounce coalesce window (matches Go's 1s).
const DEBOUNCE: Duration = Duration::from_secs(1);

/// Default polling interval for the fallback OS source.
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(10);

/// Describes the difference between two network states.
pub struct ChangeDelta {
    /// Whether this is a major change (interface/IP change or time jump).
    pub major: bool,
    /// Whether a wall-clock time jump was detected (machine likely woke).
    pub time_jumped: bool,
    /// Approximate duration of the time jump (zero if none).
    pub jump_duration: Duration,
    /// The previous state (if known).
    pub old: Option<State>,
    /// The new network state.
    pub new: State,
}

/// A pluggable state provider for tests. Returns the current [`State`] on
/// demand. The real implementation calls [`gather_state`].
pub type StateProvider = Arc<dyn Fn() -> Option<State> + Send + Sync>;

/// Errors from constructing a [`Monitor`].
#[derive(Debug, thiserror::Error)]
pub enum NetmonError {
    /// Interface enumeration returned no state.
    #[error("network state unavailable")]
    StateUnavailable,
    /// I/O error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// The network change monitor.
///
/// Owns the current [`State`] and, once [`start`](Monitor::start)ed, a
/// debounce task plus an OS event source. Dropping the returned
/// [`MonitorHandle`] stops the monitor.
pub struct Monitor {
    current: RwLock<State>,
    provider: StateProvider,
    poll_interval: Duration,
}

impl Monitor {
    /// Create a new monitor using the real [`gather_state`] provider.
    pub fn new() -> Result<Self, NetmonError> {
        let provider: StateProvider = Arc::new(gather_state);
        Self::with_state_provider(provider)
    }

    /// Create a new monitor with a custom state provider (for tests).
    pub fn with_state_provider(provider: StateProvider) -> Result<Self, NetmonError> {
        let initial = provider().ok_or(NetmonError::StateUnavailable)?;
        Ok(Self {
            current: RwLock::new(initial),
            provider,
            poll_interval: DEFAULT_POLL_INTERVAL,
        })
    }

    /// Set the polling interval for the fallback OS source (default 10s).
    /// Must be called before [`start`](Monitor::start).
    pub fn with_poll_interval(mut self, d: Duration) -> Self {
        self.poll_interval = d;
        self
    }

    /// Snapshot the current state.
    pub fn current_state(&self) -> State {
        self.current.read().expect("state lock poisoned").clone()
    }

    /// Start the monitor: spawn the debounce task + OS event source.
    ///
    /// The callback is invoked (fire-and-forget, in its own task) for each
    /// detected change. Returns a [`MonitorHandle`] that stops the monitor
    /// when dropped.
    pub fn start<F, Fut>(self, callback: F) -> MonitorHandle
    where
        F: Fn(ChangeDelta) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let shutdown = Arc::new(Notify::new());
        let stopped = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let (signal_tx, signal_rx) = mpsc::channel::<()>(8);

        let provider = self.provider.clone();
        let current = Arc::new(RwLock::new(
            self.current.read().expect("state lock poisoned").clone(),
        ));
        let callback = Arc::new(callback);
        let shutdown_clone = shutdown.clone();

        let debounce_task = tokio::spawn(async move {
            let mut last_wall = SystemTime::now();
            let mut signal_rx = signal_rx;
            loop {
                tokio::select! {
                    () = shutdown_clone.notified() => break,
                    _ = signal_rx.recv() => {}
                    () = tokio::time::sleep(WALL_TICK) => {}
                }

                let Some(new_state) = provider() else {
                    continue;
                };

                let now = SystemTime::now();
                let elapsed = now.duration_since(last_wall).unwrap_or_default();
                last_wall = now;
                let time_jumped = elapsed > TIME_JUMP_THRESHOLD;
                let jump_duration = if time_jumped { elapsed } else { Duration::ZERO };

                let old = {
                    let guard = current.read().expect("state lock poisoned");
                    guard.clone()
                };

                if !time_jumped && old.equal(&new_state) {
                    continue;
                }

                let major = time_jumped || new_state.is_major_change_from(&old);

                {
                    let mut guard = current.write().expect("state lock poisoned");
                    *guard = new_state.clone();
                }

                let delta = ChangeDelta {
                    major,
                    time_jumped,
                    jump_duration,
                    old: Some(old),
                    new: new_state,
                };

                let cb = callback.clone();
                tokio::spawn(async move {
                    cb(delta).await;
                });

                tokio::time::sleep(DEBOUNCE).await;
            }
        });

        crate::os::spawn_os_source(signal_tx, stopped.clone(), self.poll_interval);

        MonitorHandle {
            shutdown,
            stopped,
            debounce_task,
        }
    }
}

/// Handle to a running monitor. Dropping it stops the monitor.
pub struct MonitorHandle {
    shutdown: Arc<Notify>,
    stopped: Arc<AtomicBool>,
    debounce_task: JoinHandle<()>,
}

impl MonitorHandle {
    /// Signal the monitor to stop.
    pub fn shutdown(&self) {
        self.stopped
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.shutdown.notify_one();
    }
}

impl Drop for MonitorHandle {
    fn drop(&mut self) {
        self.stopped
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.shutdown.notify_waiters();
        self.debounce_task.abort();
    }
}
