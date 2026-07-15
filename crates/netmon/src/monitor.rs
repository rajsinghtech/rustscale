//! The network change monitor: debounce loop, wall-time jump detection,
//! and pluggable OS event sources.
//!
//! Ports the semantics of Go's `net/netmon/netmon.go` (`Monitor.pump` +
//! `Monitor.debounce` + `handlePotentialChange`). A [`Monitor`] owns a
//! [`State`] snapshot, an OS event source (AF_ROUTE on macOS, polling
//! elsewhere), and a debounce task that coalesces rapid bursts of events
//! into callback invocations.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{atomic::AtomicBool, atomic::AtomicU64, atomic::Ordering, Arc, RwLock, Weak};
use std::time::{Duration, Instant, SystemTime};

use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;

use crate::state::{gather_state, has_cgnat_interface, likely_home_router_ip, State};

/// How often to check wall time for sleep/wake jumps.
const WALL_TICK: Duration = Duration::from_secs(15);

/// Minimum wall-clock elapsed time to treat as a *major* time jump
/// (sleep wake), requiring socket rebinding. Matches Go's
/// `majorTimeJumpThreshold = 10 * time.Minute`.
pub(crate) const MAJOR_TIME_JUMP_THRESHOLD: Duration = Duration::from_mins(10);

/// Tolerance for monotonic-vs-wall-clock scheduling jitter. If the wall
/// clock advances more than `monotonic_elapsed + TIME_JUMP_TOLERANCE`,
/// we consider a time jump to have occurred.
const TIME_JUMP_TOLERANCE: Duration = Duration::from_secs(2);

/// Debounce coalesce window (matches Go's 1s).
const DEBOUNCE: Duration = Duration::from_secs(1);

/// Default polling interval for the fallback OS source.
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(10);

/// A boxed async callback that receives [`ChangeDelta`] values.
type ChangeFunc = Arc<
    dyn Fn(ChangeDelta) -> Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>
        + Send
        + Sync
        + 'static,
>;

/// Describes the difference between two network states.
#[derive(Clone)]
pub struct ChangeDelta {
    /// Whether this is a major change (interface/IP change or major time jump
    /// >= 10 min). Maps to Go's `RebindLikelyRequired`.
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

/// Shared state between the monitor handle and the debounce task.
struct MonitorShared {
    current: RwLock<State>,
    callbacks: RwLock<BTreeMap<u64, ChangeFunc>>,
    next_callback_id: AtomicU64,
    gw: RwLock<Option<IpAddr>>,
    gw_self_ip: RwLock<Option<IpAddr>>,
    gw_valid: AtomicBool,
    provider: StateProvider,
}

/// The network change monitor.
///
/// Owns the initial [`State`] and, once [`start`](Monitor::start)ed, a
/// debounce task plus an OS event source. Dropping the returned
/// [`MonitorHandle`] stops the monitor.
pub struct Monitor {
    initial_state: State,
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
            initial_state: initial,
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

    /// Start the monitor: spawn the debounce task + OS event source.
    ///
    /// Returns a [`MonitorHandle`] that stops the monitor when dropped.
    /// Register callbacks via
    /// [`MonitorHandle::register_change_callback`].
    pub fn start(self) -> MonitorHandle {
        let shared = Arc::new(MonitorShared {
            current: RwLock::new(self.initial_state),
            callbacks: RwLock::new(BTreeMap::new()),
            next_callback_id: AtomicU64::new(0),
            gw: RwLock::new(None),
            gw_self_ip: RwLock::new(None),
            gw_valid: AtomicBool::new(false),
            provider: self.provider,
        });

        let shutdown = Arc::new(Notify::new());
        let stopped = Arc::new(AtomicBool::new(false));

        let (signal_tx, signal_rx) = mpsc::channel::<()>(8);

        let shared_clone = shared.clone();
        let shutdown_clone = shutdown.clone();
        let callback_stopped = stopped.clone();
        let callback_tasks = Arc::new(tokio::sync::Mutex::new(Vec::<JoinHandle<()>>::new()));
        let debounce_callback_tasks = callback_tasks.clone();

        let debounce_task = tokio::spawn(async move {
            let mut last_instant = Instant::now();
            let mut last_wall = SystemTime::now();
            let mut signal_rx = signal_rx;
            loop {
                if callback_stopped.load(Ordering::SeqCst) {
                    break;
                }
                tokio::select! {
                    () = shutdown_clone.notified() => break,
                    _ = signal_rx.recv() => {}
                    () = tokio::time::sleep(WALL_TICK) => {}
                }
                if callback_stopped.load(Ordering::SeqCst) {
                    break;
                }

                let Some(new_state) = (shared_clone.provider)() else {
                    continue;
                };

                let now_instant = Instant::now();
                let now_wall = SystemTime::now();
                let monotonic_elapsed = now_instant - last_instant;
                let wall_elapsed = now_wall.duration_since(last_wall).unwrap_or_default();
                last_instant = now_instant;
                last_wall = now_wall;

                let jump_duration = wall_elapsed.saturating_sub(monotonic_elapsed);
                let time_jumped = jump_duration > TIME_JUMP_TOLERANCE;
                let major_time_jump = jump_duration >= MAJOR_TIME_JUMP_THRESHOLD;

                let old = {
                    let guard = shared_clone.current.read().expect("state lock poisoned");
                    guard.clone()
                };

                if !time_jumped && old.equal(&new_state) {
                    continue;
                }

                let major = major_time_jump || new_state.is_major_change_from(&old);

                if major {
                    shared_clone.gw_valid.store(false, Ordering::SeqCst);
                }

                {
                    let mut guard = shared_clone.current.write().expect("state lock poisoned");
                    *guard = new_state.clone();
                }

                let delta = ChangeDelta {
                    major,
                    time_jumped,
                    jump_duration: if time_jumped {
                        jump_duration
                    } else {
                        Duration::ZERO
                    },
                    old: Some(old),
                    new: new_state,
                };

                let callbacks: Vec<ChangeFunc> = {
                    let guard = shared_clone
                        .callbacks
                        .read()
                        .expect("callback lock poisoned");
                    guard.values().cloned().collect()
                };
                for cb in callbacks {
                    if callback_stopped.load(Ordering::SeqCst) {
                        break;
                    }
                    let d = delta.clone();
                    let task = tokio::spawn(async move {
                        cb(d).await;
                    });
                    let mut tasks = debounce_callback_tasks.lock().await;
                    tasks.retain(|task| !task.is_finished());
                    tasks.push(task);
                }

                tokio::time::sleep(DEBOUNCE).await;
            }
        });

        crate::os::spawn_os_source(signal_tx, stopped.clone(), self.poll_interval);

        MonitorHandle {
            shared,
            shutdown,
            stopped,
            debounce_task: Some(debounce_task),
            callback_tasks,
        }
    }
}

/// Handle to a running monitor. Dropping it stops the monitor.
pub struct MonitorHandle {
    shared: Arc<MonitorShared>,
    shutdown: Arc<Notify>,
    stopped: Arc<AtomicBool>,
    debounce_task: Option<JoinHandle<()>>,
    callback_tasks: Arc<tokio::sync::Mutex<Vec<JoinHandle<()>>>>,
}

/// RAII handle for a registered change callback. Dropping it unregisters
/// the callback.
pub struct ChangeCallbackHandle {
    id: u64,
    shared: Weak<MonitorShared>,
}

impl ChangeCallbackHandle {
    /// Explicitly unregister this callback (equivalent to dropping the
    /// handle).
    pub fn unregister(self) {
        // Drop impl handles removal; this method consumes self.
        drop(self);
    }
}

impl Drop for ChangeCallbackHandle {
    fn drop(&mut self) {
        if let Some(shared) = self.shared.upgrade() {
            let mut guard = shared.callbacks.write().expect("callback lock poisoned");
            guard.remove(&self.id);
        }
    }
}

impl MonitorHandle {
    /// Snapshot the current state.
    pub fn current_state(&self) -> State {
        self.shared
            .current
            .read()
            .expect("state lock poisoned")
            .clone()
    }

    /// Register a callback for the lifetime of this monitor handle.
    ///
    /// This is intended for owner components whose callback and monitor share
    /// exactly the same lifecycle and therefore do not need an unregister
    /// token.
    pub fn register_owned_change_callback<F, Fut>(&self, callback: F)
    where
        F: Fn(ChangeDelta) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let id = self.shared.next_callback_id.fetch_add(1, Ordering::SeqCst);
        let boxed: ChangeFunc = Arc::new(move |delta| Box::pin(callback(delta)));
        self.shared
            .callbacks
            .write()
            .expect("callback lock poisoned")
            .insert(id, boxed);
    }

    /// Register a change callback. The callback is invoked (fire-and-forget,
    /// in its own task) for each detected change. Returns a
    /// [`ChangeCallbackHandle`] that unregisters the callback when dropped.
    ///
    /// Multiple callbacks may be registered simultaneously.
    pub fn register_change_callback<F, Fut>(&self, callback: F) -> ChangeCallbackHandle
    where
        F: Fn(ChangeDelta) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let id = self.shared.next_callback_id.fetch_add(1, Ordering::SeqCst);
        let boxed: ChangeFunc = Arc::new(move |delta| Box::pin(callback(delta)));
        {
            let mut guard = self
                .shared
                .callbacks
                .write()
                .expect("callback lock poisoned");
            guard.insert(id, boxed);
        }
        ChangeCallbackHandle {
            id,
            shared: Arc::downgrade(&self.shared),
        }
    }

    /// Returns the cached default gateway IP and this machine's IP on that
    /// gateway's interface, if known. Caches the result until a major
    /// change invalidates it.
    ///
    /// Mirrors Go's `Monitor.GatewayAndSelfIP`.
    pub fn gateway_and_self_ip(&self) -> Option<(IpAddr, IpAddr)> {
        if self.shared.gw_valid.load(Ordering::SeqCst) {
            let gw = *self.shared.gw.read().expect("gw lock");
            let self_ip = *self.shared.gw_self_ip.read().expect("gw_self lock");
            return gw.zip(self_ip);
        }
        let (gw, self_ip) = likely_home_router_ip()?;
        {
            let mut guard = self.shared.gw.write().expect("gw lock poisoned");
            *guard = Some(gw);
        }
        {
            let mut guard = self
                .shared
                .gw_self_ip
                .write()
                .expect("gw_self lock poisoned");
            *guard = Some(self_ip);
        }
        self.shared.gw_valid.store(true, Ordering::SeqCst);
        Some((gw, self_ip))
    }

    /// Whether any non-Tailscale, up interface has a CGNAT (100.64.0.0/10)
    /// address.
    ///
    /// Mirrors Go's `Monitor.HasCGNATInterface`.
    pub fn has_cgnat_interface(&self) -> bool {
        let state = self.current_state();
        has_cgnat_interface(&state)
    }

    /// Signal the monitor to stop.
    pub fn shutdown(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.shutdown.notify_one();
    }

    /// Stop and join the monitor loop and every callback it launched.
    /// Handles stay in this value across each await, so cancellation leaves a
    /// retryable owner instead of detaching callbacks from their resources.
    pub async fn shutdown_and_wait(&mut self) {
        self.shutdown();
        if let Some(task) = self.debounce_task.as_mut() {
            task.abort();
            let _ = (&mut *task).await;
        }
        self.debounce_task.take();

        let mut tasks = self.callback_tasks.lock().await;
        for task in tasks.iter() {
            task.abort();
        }
        while let Some(task) = tasks.first_mut() {
            let _ = (&mut *task).await;
            tasks.swap_remove(0);
        }
    }
}

impl Drop for MonitorHandle {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.shutdown.notify_waiters();
        if let Some(task) = &self.debounce_task {
            task.abort();
        }
        if let Ok(tasks) = self.callback_tasks.try_lock() {
            for task in tasks.iter() {
                task.abort();
            }
        }
    }
}
