use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use crate::{PolicyError, PolicyErrorKind, ProviderSubscription};

/// Smallest permitted polling interval. This caps watcher work and callback
/// production even when a caller supplies an invalidly aggressive interval.
pub const MIN_WATCH_INTERVAL: Duration = Duration::from_millis(10);
/// Largest permitted polling interval.
pub const MAX_WATCH_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// Largest permitted debounce window.
pub const MAX_WATCH_DEBOUNCE: Duration = Duration::from_secs(60);

/// Bounded polling and debounce settings for an opt-in provider watcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchOptions {
    poll_interval: Duration,
    debounce: Duration,
}

impl WatchOptions {
    /// Creates validated watcher settings.
    pub fn new(poll_interval: Duration, debounce: Duration) -> Result<Self, PolicyError> {
        if !(MIN_WATCH_INTERVAL..=MAX_WATCH_INTERVAL).contains(&poll_interval)
            || debounce > MAX_WATCH_DEBOUNCE
        {
            return Err(PolicyError::new(PolicyErrorKind::Provider));
        }
        Ok(Self {
            poll_interval,
            debounce,
        })
    }

    pub(crate) const fn poll_interval(self) -> Duration {
        self.poll_interval
    }

    pub(crate) const fn debounce(self) -> Duration {
        self.debounce
    }
}

impl Default for WatchOptions {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(1),
            debounce: Duration::from_millis(200),
        }
    }
}

#[derive(Default)]
pub(crate) struct WatchControl {
    cancelled: AtomicBool,
    wait_lock: Mutex<()>,
    changed: Condvar,
}

impl WatchControl {
    fn cancel(&self) {
        let _wait = self.wait_lock.lock().expect("watch control lock poisoned");
        self.cancelled.store(true, Ordering::Release);
        self.changed.notify_all();
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

pub(crate) trait WatchClock: Send + Sync {
    /// Returns true when cancellation was requested.
    fn wait(&self, control: &WatchControl, duration: Duration) -> bool;

    /// Wakes a waiter so it can observe cancellation.
    fn wake(&self);
}

#[derive(Default)]
pub(crate) struct SystemWatchClock;

impl WatchClock for SystemWatchClock {
    fn wait(&self, control: &WatchControl, duration: Duration) -> bool {
        let wait = control
            .wait_lock
            .lock()
            .expect("watch control lock poisoned");
        if control.is_cancelled() {
            return true;
        }
        let _ = control
            .changed
            .wait_timeout_while(wait, duration, |()| !control.is_cancelled())
            .expect("watch control lock poisoned");
        control.is_cancelled()
    }

    fn wake(&self) {}
}

pub(crate) struct PollingSubscription {
    control: Arc<WatchControl>,
    clock: Arc<dyn WatchClock>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl PollingSubscription {
    pub(crate) fn start<State>(
        name: &str,
        options: WatchOptions,
        clock: Arc<dyn WatchClock>,
        probe: impl Fn() -> State + Send + 'static,
        callback: Arc<dyn Fn() + Send + Sync>,
    ) -> Result<Box<dyn ProviderSubscription>, PolicyError>
    where
        State: Eq + Send + 'static,
    {
        let control = Arc::new(WatchControl::default());
        let worker_control = control.clone();
        let worker_clock = clock.clone();
        let worker = thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || {
                let mut previous = probe();
                let mut first_poll = true;
                loop {
                    if worker_clock.wait(&worker_control, options.poll_interval()) {
                        break;
                    }
                    let observed = probe();
                    if !first_poll && observed == previous {
                        continue;
                    }
                    // The first bounded poll always reloads. Subscription is
                    // established before the engine's initial load, so this
                    // closes an ABA race where the source changes and then
                    // returns to the watcher's baseline during that load.
                    first_poll = false;
                    if !options.debounce().is_zero()
                        && worker_clock.wait(&worker_control, options.debounce())
                    {
                        break;
                    }
                    // Re-sample after the debounce window. Any number of
                    // replacements in the burst produce one bounded event.
                    previous = probe();
                    if worker_control.is_cancelled() {
                        break;
                    }
                    callback();
                }
            })
            .map_err(|_| PolicyError::new(PolicyErrorKind::Provider))?;
        Ok(Box::new(Self {
            control,
            clock,
            worker: Mutex::new(Some(worker)),
        }))
    }
}

impl ProviderSubscription for PollingSubscription {}

impl Drop for PollingSubscription {
    fn drop(&mut self) {
        self.control.cancel();
        self.clock.wake();
        let worker = self
            .worker
            .get_mut()
            .expect("watch worker lock poisoned")
            .take();
        if let Some(worker) = worker {
            // Provider callbacks are deliberately tiny notification enqueues in
            // PolicyEngine, so engine-owned subscriptions are never dropped by
            // their own polling worker.
            if worker.thread().id() != thread::current().id() {
                let _ = worker.join();
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod test_clock {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    pub(crate) struct FakeWatchClock {
        state: Mutex<FakeState>,
        changed: Condvar,
        active_waiters: AtomicUsize,
        waits_started: AtomicUsize,
    }

    #[derive(Default)]
    struct FakeState {
        ticks: usize,
        wake: bool,
    }

    impl FakeWatchClock {
        pub(crate) fn tick(&self, count: usize) {
            let mut state = self.state.lock().unwrap();
            state.ticks = state.ticks.saturating_add(count);
            self.changed.notify_all();
        }

        pub(crate) fn active_waiters(&self) -> usize {
            self.active_waiters.load(Ordering::SeqCst)
        }

        pub(crate) fn waits_started(&self) -> usize {
            self.waits_started.load(Ordering::SeqCst)
        }
    }

    impl WatchClock for FakeWatchClock {
        fn wait(&self, control: &WatchControl, _duration: Duration) -> bool {
            self.active_waiters.fetch_add(1, Ordering::SeqCst);
            self.waits_started.fetch_add(1, Ordering::SeqCst);
            let mut state = self.state.lock().unwrap();
            while state.ticks == 0 && !state.wake && !control.is_cancelled() {
                state = self.changed.wait(state).unwrap();
            }
            if state.ticks != 0 {
                state.ticks -= 1;
            }
            state.wake = false;
            self.active_waiters.fetch_sub(1, Ordering::SeqCst);
            control.is_cancelled()
        }

        fn wake(&self) {
            self.state.lock().unwrap().wake = true;
            self.changed.notify_all();
        }
    }
}
