use std::time::Instant;

use crate::{Clock, WallClock};

/// A rate-limited token bucket.
pub struct Bucket<C = WallClock> {
    rate: u32,
    burst: u32,
    overdraft: u32,
    tokens: f64,
    last: Instant,
    clock: C,
}

impl Bucket<WallClock> {
    /// Creates a bucket with no overdraft.
    pub fn new(rate: u32, burst: u32) -> Self {
        Self::with_overdraft(rate, burst, 0)
    }

    /// Creates a wall-clock bucket with an overdraft allowance.
    pub fn with_overdraft(rate: u32, burst: u32, overdraft: u32) -> Self {
        Self::with_overdraft_and_clock(rate, burst, overdraft, WallClock)
    }
}

impl<C: Clock> Bucket<C> {
    /// Creates a bucket with no overdraft using `clock`.
    pub fn with_clock(rate: u32, burst: u32, clock: C) -> Self {
        Self::with_overdraft_and_clock(rate, burst, 0, clock)
    }

    /// Creates a bucket with an overdraft allowance using `clock`.
    pub fn with_overdraft_and_clock(rate: u32, burst: u32, overdraft: u32, clock: C) -> Self {
        let last = clock.now();
        Self {
            rate,
            burst,
            overdraft,
            tokens: f64::from(burst),
            last,
            clock,
        }
    }

    /// Attempts to consume `n` tokens without waiting.
    pub fn allow_n(&mut self, n: u32) -> bool {
        self.refill();
        let next = self.tokens - f64::from(n);
        if next < -f64::from(self.overdraft) {
            return false;
        }
        self.tokens = next;
        true
    }

    /// Returns the current token balance after applying elapsed refill time.
    pub fn tokens(&mut self) -> f64 {
        self.refill();
        self.tokens
    }

    /// Restores the bucket to its full burst capacity.
    pub fn reset(&mut self) {
        self.tokens = f64::from(self.burst);
        self.last = self.clock.now();
    }

    fn refill(&mut self) {
        let now = self.clock.now();
        let elapsed = now.saturating_duration_since(self.last);
        self.tokens =
            (self.tokens + elapsed.as_secs_f64() * f64::from(self.rate)).min(f64::from(self.burst));
        self.last = now;
    }
}
