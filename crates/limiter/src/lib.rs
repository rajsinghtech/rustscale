//! Token-bucket rate limiters for individual and keyed workloads.

#![forbid(unsafe_code)]

mod bucket;

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub use bucket::Bucket;

/// Source of monotonic time used by rate limiters.
pub trait Clock: Clone {
    /// Returns the current instant.
    fn now(&self) -> Instant;
}

/// Clock backed by [`Instant::now`].
#[derive(Clone, Copy, Debug, Default)]
pub struct WallClock;

impl Clock for WallClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Deterministic, manually advanced clock for tests and simulations.
#[derive(Clone, Debug)]
pub struct MockClock {
    now: Arc<Mutex<Instant>>,
}

impl MockClock {
    /// Creates a mock clock at `start`.
    pub fn new(start: Instant) -> Self {
        Self {
            now: Arc::new(Mutex::new(start)),
        }
    }

    /// Advances the clock by `duration`.
    pub fn advance(&self, duration: Duration) {
        let mut now = self.now.lock().expect("mock clock lock poisoned");
        *now += duration;
    }
}

impl Clock for MockClock {
    fn now(&self) -> Instant {
        *self.now.lock().expect("mock clock lock poisoned")
    }
}

/// Keyed token-bucket rate limiter with least-recently-used eviction.
pub struct Limiter<K, C = WallClock> {
    size: usize,
    max: u32,
    refill_interval: Duration,
    overdraft: u32,
    clock: C,
    buckets: HashMap<K, KeyBucket>,
    lru_order: Vec<K>,
}

struct KeyBucket {
    tokens: f64,
    last: Instant,
}

impl<K> Limiter<K, WallClock>
where
    K: Eq + Hash + Clone,
{
    /// Creates a wall-clock limiter.
    pub fn new(size: usize, max: u32, refill_interval: Duration, overdraft: u32) -> Self {
        Self::with_clock(size, max, refill_interval, overdraft, WallClock)
    }
}

impl<K, C> Limiter<K, C>
where
    K: Eq + Hash + Clone,
    C: Clock,
{
    /// Creates a limiter using `clock`.
    pub fn with_clock(
        size: usize,
        max: u32,
        refill_interval: Duration,
        overdraft: u32,
        clock: C,
    ) -> Self {
        Self {
            size,
            max,
            refill_interval,
            overdraft,
            clock,
            buckets: HashMap::new(),
            lru_order: Vec::new(),
        }
    }

    /// Charges one token to `key`.
    pub fn allow(&mut self, key: K) -> bool {
        self.allow_n(key, 1)
    }

    /// Charges `n` tokens to `key` if the bucket permits it.
    pub fn allow_n(&mut self, key: K, n: u32) -> bool {
        if self.size == 0 || self.max == 0 || self.refill_interval.is_zero() {
            return false;
        }
        let now = self.clock.now();
        self.touch_or_insert(key.clone(), now);
        let bucket = self.buckets.get_mut(&key).expect("bucket was inserted");
        refill(bucket, now, self.max, self.refill_interval);
        let next = bucket.tokens - f64::from(n);
        if next < -f64::from(self.overdraft) {
            return false;
        }
        bucket.tokens = next;
        true
    }

    /// Returns the currently stored token count for `key`.
    pub fn tokens(&self, key: &K) -> Option<i64> {
        self.buckets
            .get(key)
            .map(|bucket| bucket.tokens.floor() as i64)
    }

    fn touch_or_insert(&mut self, key: K, now: Instant) {
        if self.buckets.contains_key(&key) {
            self.touch(&key);
            return;
        }
        if self.buckets.len() == self.size {
            if let Some(oldest) = self.lru_order.first().cloned() {
                self.lru_order.remove(0);
                self.buckets.remove(&oldest);
            }
        }
        self.buckets.insert(
            key.clone(),
            KeyBucket {
                tokens: f64::from(self.max),
                last: now,
            },
        );
        self.lru_order.push(key);
    }

    fn touch(&mut self, key: &K) {
        if let Some(index) = self.lru_order.iter().position(|existing| existing == key) {
            let key = self.lru_order.remove(index);
            self.lru_order.push(key);
        }
    }
}

fn refill(bucket: &mut KeyBucket, now: Instant, max: u32, interval: Duration) {
    let elapsed = now.saturating_duration_since(bucket.last);
    bucket.tokens =
        (bucket.tokens + elapsed.as_secs_f64() / interval.as_secs_f64()).min(f64::from(max));
    bucket.last = now;
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{Bucket, Limiter, MockClock};

    fn clock() -> MockClock {
        MockClock::new(Instant::now())
    }

    #[test]
    fn bucket_burst() {
        let clock = clock();
        let mut bucket = Bucket::with_clock(100, 100, clock.clone());
        assert!(bucket.allow_n(100));
        assert!(!bucket.allow_n(1));
        clock.advance(Duration::from_millis(200));
        assert!(bucket.allow_n(20));
        assert!(!bucket.allow_n(1));
    }

    #[test]
    fn bucket_sustained() {
        let clock = clock();
        let mut bucket = Bucket::with_clock(1_000, 200, clock.clone());
        assert!(bucket.allow_n(200));
        let mut allowed = 0;
        for _ in 0..1_000 {
            clock.advance(Duration::from_millis(1));
            allowed += usize::from(bucket.allow_n(1));
        }
        assert!((995..=1_000).contains(&allowed));
    }

    #[test]
    fn bucket_overdraft() {
        let clock = clock();
        let mut bucket = Bucket::with_overdraft_and_clock(100, 10, 10, clock);
        assert!(bucket.allow_n(10));
        assert!(bucket.allow_n(5));
        assert!((bucket.tokens() + 5.0).abs() < f64::EPSILON);
        assert!(!bucket.allow_n(6));
    }

    #[test]
    fn limiter_simple() {
        let clock = clock();
        let mut limiter = Limiter::with_clock(2, 10, Duration::from_secs(1), 0, clock.clone());
        assert!(limiter.allow_n("a", 10));
        assert!(!limiter.allow("a"));
        clock.advance(Duration::from_secs(1));
        assert!(limiter.allow("a"));
    }

    #[test]
    fn limiter_lru_eviction() {
        let clock = clock();
        let mut limiter = Limiter::with_clock(2, 2, Duration::from_secs(1), 0, clock);
        assert!(limiter.allow_n("a", 2));
        assert!(limiter.allow("b"));
        assert!(limiter.allow("c"));
        assert_eq!(limiter.tokens(&"a"), None);
        assert!(limiter.allow_n("a", 2));
    }

    #[test]
    fn limiter_overdraft_cooldown() {
        let clock = clock();
        let mut limiter = Limiter::with_clock(1, 1, Duration::from_secs(1), 2, clock.clone());
        assert!(limiter.allow("k"));
        assert!(limiter.allow("k"));
        assert!(limiter.allow("k"));
        assert!(!limiter.allow("k"));
        clock.advance(Duration::from_secs(2));
        assert!(limiter.allow("k"));
    }

    #[test]
    fn limiter_allow_n() {
        let clock = clock();
        let mut limiter = Limiter::with_clock(1, 10, Duration::from_secs(1), 0, clock);
        assert!(limiter.allow_n("k", 5));
        assert_eq!(limiter.tokens(&"k"), Some(5));
    }
}
