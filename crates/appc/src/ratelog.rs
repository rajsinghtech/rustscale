//! Rate-limited logging for route writes (per-minute and per-day).
//!
//! Ports Go's `rateLogger` from `appc/appconnector.go`. The rate logger
//! counts events per interval and invokes a callback with the count when the
//! interval rolls over.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A rate logger counts events per interval and invokes a callback with the
/// count when the interval rolls over.
///
/// Matches Go's `rateLogger`. The callback receives `(count, period_start,
/// total_routes)`.
pub struct RateLogger {
    inner: Mutex<RateLoggerInner>,
}

struct RateLoggerInner {
    interval: Duration,
    start: Instant,
    period_start: Instant,
    period_count: i64,
    now: Box<dyn Fn() -> Instant + Send + Sync>,
    callback: Box<dyn Fn(i64, Instant, i64) + Send + Sync>,
}

impl RateLogger {
    /// Create a new rate logger with the given interval and callback.
    pub fn new(
        now: impl Fn() -> Instant + Send + Sync + 'static,
        interval: Duration,
        callback: impl Fn(i64, Instant, i64) + Send + Sync + 'static,
    ) -> Self {
        let now_val = now();
        Self {
            inner: Mutex::new(RateLoggerInner {
                interval,
                start: now_val,
                period_start: now_val,
                period_count: 0,
                now: Box::new(now),
                callback: Box::new(callback),
            }),
        }
    }

    /// Record a write event. If the current interval has elapsed since the
    /// last period, the callback is invoked with the previous period's count.
    /// `num_routes` is the total number of routes at the time of the call.
    pub fn update(&self, num_routes: i64) {
        let mut inner = self.inner.lock().unwrap();
        let now = (inner.now)();
        let period_end = inner.period_start + inner.interval;
        if period_end < now {
            if inner.period_count != 0 {
                (inner.callback)(inner.period_count, inner.period_start, num_routes);
            }
            inner.period_count = 0;
            inner.period_start = current_interval_start(now, inner.start, inner.interval);
        }
        inner.period_count += 1;
    }
}

/// Compute the start of the current interval, matching Go's
/// `rateLogger.currentIntervalStart`.
fn current_interval_start(now: Instant, start: Instant, interval: Duration) -> Instant {
    let elapsed = now.duration_since(start);
    let millis_since = elapsed.as_millis() % interval.as_millis();
    now.checked_sub(Duration::from_millis(millis_since as u64))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
    use std::sync::Arc;

    #[test]
    fn rate_logger_fires_after_interval() {
        let clock = Arc::new(Mutex::new(Instant::now()));
        let clock_clone = clock.clone();
        let fired = Arc::new(AtomicBool::new(false));
        let fired_clone = fired.clone();

        let rl = RateLogger::new(
            move || *clock_clone.lock().unwrap(),
            Duration::from_secs(1),
            move |count, _, _| {
                assert_eq!(count, 3);
                fired_clone.store(true, Ordering::SeqCst);
            },
        );

        for _ in 0..3 {
            {
                let mut c = clock.lock().unwrap();
                *c += Duration::from_millis(1);
            }
            rl.update(0);
            assert!(!fired.load(Ordering::SeqCst));
        }

        {
            let mut c = clock.lock().unwrap();
            *c += Duration::from_secs(1);
        }
        rl.update(0);
        assert!(fired.load(Ordering::SeqCst));
    }

    #[test]
    fn rate_logger_hour_interval() {
        let clock = Arc::new(Mutex::new(Instant::now()));
        let clock_clone = clock.clone();
        let fired = Arc::new(AtomicBool::new(false));
        let fired_clone = fired.clone();

        let rl = RateLogger::new(
            move || *clock_clone.lock().unwrap(),
            Duration::from_secs(3600),
            move |count, _, _| {
                assert_eq!(count, 3);
                fired_clone.store(true, Ordering::SeqCst);
            },
        );

        for _ in 0..3 {
            {
                let mut c = clock.lock().unwrap();
                *c += Duration::from_secs(60);
            }
            rl.update(0);
            assert!(!fired.load(Ordering::SeqCst));
        }

        {
            let mut c = clock.lock().unwrap();
            *c += Duration::from_secs(3600);
        }
        rl.update(0);
        assert!(fired.load(Ordering::SeqCst));
    }

    #[test]
    fn rate_logger_no_fire_on_zero_count() {
        let clock = Arc::new(Mutex::new(Instant::now()));
        let clock_clone = clock.clone();
        let count_seen = Arc::new(AtomicI64::new(-1));
        let count_clone = count_seen.clone();

        let rl = RateLogger::new(
            move || *clock_clone.lock().unwrap(),
            Duration::from_secs(1),
            move |count, _, _| {
                count_clone.store(count, Ordering::SeqCst);
            },
        );

        // Advance past the interval without any updates — callback should
        // not fire because period_count is 0.
        {
            let mut c = clock.lock().unwrap();
            *c += Duration::from_secs(2);
        }
        rl.update(0);
        assert_eq!(count_seen.load(Ordering::SeqCst), -1);
    }
}
