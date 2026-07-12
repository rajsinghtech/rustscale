//! Health tracking for rustscale — a registry of warnable conditions.
//!
//! Ports the semantics of Go's `tailscale.com/health` package: a [`Tracker`]
//! holds a set of registered [`Warnable`]s, each identified by a string code.
//! Subsystems call [`Tracker::set_unhealthy`] / [`Tracker::set_healthy`] to
//! report their state; [`Tracker::current_warnings`] snapshots the active
//! warnings (id, severity, text, since).
//!
//! A [`Watchdog`] auto-fires a warning if not "fed" within an interval — used
//! for map-poll staleness (no `MapResponse` for >N minutes).
//!
//! Thread-safe: [`Tracker`] is `Arc<Mutex<_>>` under the hood, cheap to clone,
//! no async needed for the core API. Only [`Watchdog`] spawns a tokio task.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};

// ---------------------------------------------------------------------------
// Built-in warnable codes
// ---------------------------------------------------------------------------

/// Control-plane connection (map stream). High severity.
pub const WARN_CONTROL: &str = "control-connection";
/// Home DERP region unreachable. Medium severity.
pub const WARN_DERP_HOME: &str = "derp-home-unreachable";
/// Serving a self-signed / stale cert fallback. Low severity.
pub const WARN_CERT_FALLBACK: &str = "cert-fallback";
/// Network changed, re-probing endpoints. Low severity, transient.
pub const WARN_NETMON_CHANGE: &str = "network-changed";
/// Captive portal detected — traffic is being intercepted. High severity.
pub const WARN_CAPTIVE_PORTAL: &str = "captive-portal-detected";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// How serious a warning is. Higher = more urgent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub enum Severity {
    Low,
    Medium,
    High,
}

/// A registered warnable condition: an id, severity, and human title.
#[derive(Clone, Debug)]
pub struct Warnable {
    pub id: String,
    pub severity: Severity,
    pub title: String,
}

/// A currently-active warning snapshot, returned by [`Tracker::current_warnings`].
///
/// C-representable: a plain struct of an id string, a severity enum, a text
/// string, and an RFC-3339 timestamp. Serializes cleanly to JSON for the FFI
/// layer.
#[derive(Clone, Debug, serde::Serialize)]
pub struct Warning {
    pub id: String,
    pub severity: Severity,
    pub text: String,
    pub since: DateTime<Utc>,
}

struct Inner {
    /// Registered warnables, keyed by id.
    warnables: HashMap<String, Warnable>,
    /// Active warnings: id -> (text, since).
    active: HashMap<String, (String, DateTime<Utc>)>,
}

/// The health tracker. Cloneable and cheap — all clones share one inner state.
#[derive(Clone)]
pub struct Tracker {
    inner: Arc<Mutex<Inner>>,
}

impl Default for Tracker {
    fn default() -> Self {
        Self::new()
    }
}

impl Tracker {
    /// Create a new tracker with the built-in warnables pre-registered.
    pub fn new() -> Self {
        let t = Self {
            inner: Arc::new(Mutex::new(Inner {
                warnables: HashMap::new(),
                active: HashMap::new(),
            })),
        };
        t.register(Warnable {
            id: WARN_CONTROL.into(),
            severity: Severity::High,
            title: "Control connection".into(),
        });
        t.register(Warnable {
            id: WARN_DERP_HOME.into(),
            severity: Severity::Medium,
            title: "DERP home region".into(),
        });
        t.register(Warnable {
            id: WARN_CERT_FALLBACK.into(),
            severity: Severity::Low,
            title: "Certificate fallback".into(),
        });
        t.register(Warnable {
            id: WARN_NETMON_CHANGE.into(),
            severity: Severity::Low,
            title: "Network changed".into(),
        });
        t.register(Warnable {
            id: WARN_CAPTIVE_PORTAL.into(),
            severity: Severity::High,
            title: "Captive portal detected".into(),
        });
        t
    }

    /// Register (or replace) a warnable definition.
    pub fn register(&self, w: Warnable) {
        let mut g = self.inner.lock().expect("health mutex poisoned");
        g.warnables.insert(w.id.clone(), w);
    }

    /// Mark a warnable as unhealthy with the given detail text. If already
    /// unhealthy, the text is updated but the original `since` timestamp is
    /// preserved (matching Go's `setUnhealthyLocked`).
    pub fn set_unhealthy(&self, id: &str, text: impl Into<String>) {
        let mut g = self.inner.lock().expect("health mutex poisoned");
        let text = text.into();
        let since = g.active.get(id).map_or_else(Utc::now, |(_, s)| *s);
        g.active.insert(id.to_string(), (text, since));
    }

    /// Clear any active warning for `id`.
    pub fn set_healthy(&self, id: &str) {
        let mut g = self.inner.lock().expect("health mutex poisoned");
        g.active.remove(id);
    }

    /// Whether `id` currently has an active warning.
    pub fn is_unhealthy(&self, id: &str) -> bool {
        let g = self.inner.lock().expect("health mutex poisoned");
        g.active.contains_key(id)
    }

    /// Snapshot all active warnings, sorted by severity (High first) then id.
    pub fn current_warnings(&self) -> Vec<Warning> {
        let g = self.inner.lock().expect("health mutex poisoned");
        let mut out: Vec<Warning> = g
            .active
            .iter()
            .map(|(id, (text, since))| {
                let severity = g.warnables.get(id).map_or(Severity::Medium, |w| w.severity);
                Warning {
                    id: id.clone(),
                    severity,
                    text: text.clone(),
                    since: *since,
                }
            })
            .collect();
        out.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.id.cmp(&b.id)));
        out
    }
}

// ---------------------------------------------------------------------------
// Watchdog
// ---------------------------------------------------------------------------

/// A watchdog that auto-fires a warning if not [`fed`](Self::feed) within an
/// interval. Used for map-poll staleness: if no `MapResponse` arrives for more
/// than the configured interval, the warnable is marked unhealthy.
///
/// On construction, registers the warnable (if not already registered) and
/// spawns a tokio task that polls every 250 ms. Dropping the `Watchdog` stops
/// the task.
pub struct Watchdog {
    tracker: Tracker,
    id: String,
    last_fed: Arc<Mutex<DateTime<Utc>>>,
    shutdown: Arc<AtomicBool>,
}

impl Clone for Watchdog {
    fn clone(&self) -> Self {
        Self {
            tracker: self.tracker.clone(),
            id: self.id.clone(),
            last_fed: self.last_fed.clone(),
            shutdown: self.shutdown.clone(),
        }
    }
}

impl Watchdog {
    /// Create and start a watchdog.
    ///
    /// `interval` is how long without a `feed()` before the warning fires.
    /// The warnable is registered with the given severity/title if not already
    /// known to the tracker.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tracker: Tracker,
        id: &str,
        title: &str,
        severity: Severity,
        warn_text: impl Into<String>,
        interval: Duration,
    ) -> Self {
        tracker.register(Warnable {
            id: id.into(),
            severity,
            title: title.into(),
        });

        let last_fed = Arc::new(Mutex::new(Utc::now()));
        let shutdown = Arc::new(AtomicBool::new(false));

        let task_tracker = tracker.clone();
        let task_id = id.to_string();
        let task_text = warn_text.into();
        let task_last_fed = last_fed.clone();
        let task_shutdown = shutdown.clone();
        let chrono_interval =
            chrono::Duration::from_std(interval).unwrap_or(chrono::Duration::seconds(180));

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_millis(250));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                if task_shutdown.load(Ordering::Relaxed) {
                    break;
                }
                let last = *task_last_fed.lock().expect("watchdog mutex poisoned");
                if Utc::now().signed_duration_since(last) > chrono_interval {
                    task_tracker.set_unhealthy(&task_id, &task_text);
                }
            }
        });

        Self {
            tracker,
            id: id.to_string(),
            last_fed,
            shutdown,
        }
    }

    /// Reset the watchdog timer and clear any active warning for this warnable.
    pub fn feed(&self) {
        *self.last_fed.lock().expect("watchdog mutex poisoned") = Utc::now();
        self.tracker.set_healthy(&self.id);
    }

    /// Stop the background polling task.
    pub fn stop(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.stop();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_and_clear() {
        let t = Tracker::new();
        assert!(!t.is_unhealthy(WARN_CONTROL));
        t.set_unhealthy(WARN_CONTROL, "lost connection");
        assert!(t.is_unhealthy(WARN_CONTROL));
        let w = t.current_warnings();
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].id, WARN_CONTROL);
        assert_eq!(w[0].severity, Severity::High);
        assert_eq!(w[0].text, "lost connection");
        t.set_healthy(WARN_CONTROL);
        assert!(t.current_warnings().is_empty());
    }

    #[test]
    fn since_preserved_on_update() {
        let t = Tracker::new();
        t.set_unhealthy(WARN_DERP_HOME, "first");
        let before = t.current_warnings()[0].since;
        std::thread::sleep(Duration::from_millis(20));
        t.set_unhealthy(WARN_DERP_HOME, "second");
        let after = t.current_warnings()[0].since;
        assert_eq!(before, after, "since should be preserved on update");
        assert_eq!(t.current_warnings()[0].text, "second");
    }

    #[test]
    fn severity_ordering() {
        let t = Tracker::new();
        t.set_unhealthy(WARN_CERT_FALLBACK, "low");
        t.set_unhealthy(WARN_DERP_HOME, "med");
        t.set_unhealthy(WARN_CONTROL, "high");
        let w = t.current_warnings();
        assert_eq!(w[0].severity, Severity::High);
        assert_eq!(w[1].severity, Severity::Medium);
        assert_eq!(w[2].severity, Severity::Low);
    }

    #[test]
    fn unknown_warnable_defaults_medium() {
        let t = Tracker::new();
        t.set_unhealthy("custom-id", "oops");
        let w = t.current_warnings();
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].id, "custom-id");
        assert_eq!(w[0].severity, Severity::Medium);
    }

    #[test]
    fn clone_shares_state() {
        let t = Tracker::new();
        let t2 = t.clone();
        t.set_unhealthy(WARN_CONTROL, "x");
        assert!(t2.is_unhealthy(WARN_CONTROL));
    }

    #[tokio::test]
    async fn watchdog_fires_and_clears_on_feed() {
        let t = Tracker::new();
        let wd = Watchdog::new(
            t.clone(),
            "test-watchdog",
            "Test",
            Severity::Medium,
            "stale",
            Duration::from_millis(300),
        );
        // Initially healthy.
        assert!(!t.is_unhealthy("test-watchdog"));
        // Wait past the interval without feeding (250ms poll → needs >500ms).
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert!(t.is_unhealthy("test-watchdog"));
        // Feeding clears it.
        wd.feed();
        assert!(!t.is_unhealthy("test-watchdog"));
        // Feeding again before the deadline keeps it healthy.
        tokio::time::sleep(Duration::from_millis(100)).await;
        wd.feed();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!t.is_unhealthy("test-watchdog"));
    }

    #[tokio::test]
    async fn watchdog_stops_on_drop() {
        let t = Tracker::new();
        {
            let _wd = Watchdog::new(
                t.clone(),
                "ephemeral-wd",
                "Ephemeral",
                Severity::Low,
                "stale",
                Duration::from_millis(300),
            );
            assert!(!t.is_unhealthy("ephemeral-wd"));
        }
        // After drop the task should stop; even past the interval the
        // warning should not fire (the task is gone).
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(!t.is_unhealthy("ephemeral-wd"));
    }

    #[tokio::test]
    async fn watchdog_fires_only_after_interval() {
        let t = Tracker::new();
        let wd = Watchdog::new(
            t.clone(),
            "delayed-wd",
            "Delayed",
            Severity::Medium,
            "stale",
            Duration::from_millis(400),
        );
        // Before the interval: healthy.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!t.is_unhealthy("delayed-wd"));
        // Feed to reset.
        wd.feed();
        // Another 200ms — still under 400ms since feed.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!t.is_unhealthy("delayed-wd"));
    }
}
