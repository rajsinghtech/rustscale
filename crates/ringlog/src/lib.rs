//! Fixed-capacity concurrency-safe ring buffer — port of Go's
//! `tailscale.com/util/ringlog`.
//!
//! [`RingLog<T>`] holds at most `max` entries, overwriting the oldest when
//! full. All methods take an internal mutex, matching the Go implementation.
//! For a nullable log (Go's nil-receiver pattern), use
//! `Option<RingLog<T>>` and check before calling.

#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::sync::Mutex;

/// A concurrency-safe fixed-size log window containing entries of `T`.
///
/// Created with [`RingLog::new`]. Once the log reaches `max` entries,
/// [`RingLog::add`] overwrites the oldest entry. [`RingLog::get_all`]
/// returns a snapshot in insertion order (oldest first).
pub struct RingLog<T> {
    inner: Mutex<Inner<T>>,
    max: usize,
}

struct Inner<T> {
    buf: VecDeque<T>,
}

impl<T> RingLog<T> {
    /// Create a new `RingLog` that holds at most `max` items.
    ///
    /// Panics if `max == 0` is not useful — a zero-capacity log silently
    /// drops all items (matching the "do nothing on full" spirit of the Go
    /// code, which would panic on `% 0`).
    pub fn new(max: usize) -> Self {
        RingLog {
            inner: Mutex::new(Inner {
                buf: VecDeque::with_capacity(max),
            }),
            max,
        }
    }

    /// Append a new item, overwriting the oldest if the log is full.
    ///
    /// If `max == 0` this is a no-op.
    pub fn add(&self, t: T) {
        let mut inner = self.inner.lock().expect("ringlog mutex poisoned");
        if self.max == 0 {
            return;
        }
        if inner.buf.len() >= self.max {
            inner.buf.pop_front();
        }
        inner.buf.push_back(t);
    }

    /// Number of elements currently in the log.
    pub fn len(&self) -> usize {
        self.inner.lock().expect("ringlog mutex poisoned").buf.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Empty the log.
    pub fn clear(&self) {
        let mut inner = self.inner.lock().expect("ringlog mutex poisoned");
        inner.buf.clear();
    }
}

impl<T: Clone> RingLog<T> {
    /// Return a copy of all entries in insertion order (oldest first).
    pub fn get_all(&self) -> Vec<T> {
        self.inner
            .lock()
            .expect("ringlog mutex poisoned")
            .buf
            .iter()
            .cloned()
            .collect()
    }
}

impl<T> Default for RingLog<T> {
    fn default() -> Self {
        RingLog::new(0)
    }
}

#[cfg(test)]
mod tests;
