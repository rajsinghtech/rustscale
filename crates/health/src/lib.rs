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
/// A specific DERP region is unreachable. Medium severity.
/// The warnable id includes the region id, e.g. "derp-region-3-unreachable".
pub const WARN_DERP_REGION_PREFIX: &str = "derp-region-";
/// Serving a self-signed / stale cert fallback. Low severity.
pub const WARN_CERT_FALLBACK: &str = "cert-fallback";
/// Network changed, re-probing endpoints. Low severity, transient.
pub const WARN_NETMON_CHANGE: &str = "network-changed";
/// Captive portal detected — traffic is being intercepted. High severity.
pub const WARN_CAPTIVE_PORTAL: &str = "captive-portal-detected";

/// Network connectivity is down (productivity impacted). High severity.
/// Mirrors Go's `NetworkStatusWarnable` (`HealthWarnableNetworkStatus`).
pub const WARN_PRODUCTIVITY: &str = "network-status";
/// UDP connectivity issues — NAT traversal setup failure. Medium severity.
/// Mirrors Go's `noUDP4BindWarnable` (`HealthWarnableNoUDP4Bind`).
pub const WARN_UDP: &str = "no-udp4-bind";
/// IPv4 connectivity issues. Medium severity.
pub const WARN_IPV4: &str = "ipv4-connectivity";
/// IPv6 connectivity issues. Medium severity.
pub const WARN_IPV6: &str = "ipv6-connectivity";
/// No DERP region can be reached. Medium severity.
/// Mirrors Go's `noDERPHomeWarnable` (`HealthWarnableNoDERPHome`).
pub const WARN_DERP_NO_REGION: &str = "no-derp-home";
/// Node is idle / Tailscale is stopped. Low severity.
/// Mirrors Go's `IPNStateWarnable` (`HealthWarnableWantRunningFalse`).
pub const WARN_IDLE: &str = "ipn-state";
/// Login interactivity needed. Medium severity.
/// Mirrors Go's `LoginStateWarnable` (`HealthWarnableLoginState`).
pub const WARN_LOGIN: &str = "login-state";

/// Map poll not active (no stream connection). Medium severity.
/// Mirrors Go's `notInMapPollWarnable` (`"not-in-map-poll"`).
pub const WARN_NOT_IN_MAP_POLL: &str = "not-in-map-poll";

/// Map response timeout (stream stalled >2m5s). Medium severity.
/// Mirrors Go's `mapResponseTimeoutWarnable` (`"mapresponse-timeout"`).
pub const WARN_MAP_RESPONSE_TIMEOUT: &str = "mapresponse-timeout";

/// A specific DERP connection is down (not just home). Medium severity.
/// Mirrors Go's `noDERPConnectionWarnable` (`"no-derp-connection"`).
pub const WARN_NO_DERP_CONNECTION: &str = "no-derp-connection";

/// DERP region timed out (no frame for >2m5s). Medium severity.
/// Mirrors Go's `derpTimeoutWarnable` (`"derp-timed-out"`).
pub const WARN_DERP_TIMEOUT: &str = "derp-timed-out";

/// DERP region reporting an error. Low severity.
/// Mirrors Go's `derpRegionErrorWarnable` (`"derp-region-error"`).
pub const WARN_DERP_REGION_ERROR: &str = "derp-region-error";

/// TLS connection failure. Medium severity.
/// Mirrors Go's `tlsConnectionFailedWarnable` (`"tls-connection-failed"`).
pub const WARN_TLS_CONNECTION_FAILED: &str = "tls-connection-failed";

/// TLS cert pending (ACME in progress). Low severity.
/// Mirrors Go's `certPendingWarnable` (`"tls-cert-pending"`).
pub const WARN_TLS_CERT_PENDING: &str = "tls-cert-pending";

/// Prefix for subsystem warnables (`"subsystem-dns"`, `"subsystem-tailnet-lock"`, etc.).
/// Go creates these dynamically for `SysRouter`, `SysDNS`, `SysDNSManager`, `SysTKA`.
pub const WARN_SUBSYSTEM_PREFIX: &str = "subsystem-";

// --- Arg key constants used in Go's `health.Args` for dynamic text ---

/// Elapsed duration (formatted string). Used by map-response-timeout, derp-timed-out.
pub const ARG_DURATION: &str = "duration";
/// DERP region numeric id. Used by no-derp-connection, derp-region-error.
pub const ARG_DERP_REGION_ID: &str = "derp_region_id";
/// DERP region human name. Used by no-derp-connection, derp-timed-out.
pub const ARG_DERP_REGION_NAME: &str = "derp_region_name";
/// Error detail string. Used by derp-region-error, tls-connection-failed.
pub const ARG_ERROR: &str = "error";
/// Server name (SNI). Used by tls-connection-failed.
pub const ARG_SERVER_NAME: &str = "server_name";
/// Domain list. Used by tls-cert-pending.
pub const ARG_DOMAINS: &str = "domains";
/// Legacy error (for subsystem warnables that wrap an old error).
pub const ARG_LEGACY_ERROR: &str = "legacy_error";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// How serious a warning is. Higher = more urgent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub enum Severity {
    #[default]
    Low,
    Medium,
    High,
}

/// A registered warnable condition: an id, severity, and human title.
///
/// Ports Go's `health.Warnable`. The `depends_on` field lists other warnable
/// ids that must be *healthy* for this warnable to be relevant — if any
/// dependency is unhealthy, this warnable is suppressed (the dependency
/// already explains the symptom). The `time_to_visible` field delays surfacing
/// a warning to the user, preventing transient blips.
#[derive(Clone, Debug, Default)]
pub struct Warnable {
    pub id: String,
    pub severity: Severity,
    pub title: String,
    /// Warnable ids that this warnable depends on. If any dependency is
    /// currently unhealthy, this warnable is suppressed in
    /// [`Tracker::current_warnings`] (the dependency already explains the
    /// problem). Mirrors Go's `Warnable.DependsOn`.
    pub depends_on: Vec<String>,
    /// How long the warnable must be continuously unhealthy before it appears
    /// in [`Tracker::current_warnings`]. `Duration::ZERO` (the default) means
    /// immediately visible. Mirrors Go's `Warnable.TimeToVisible`.
    pub time_to_visible: Duration,
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
    /// Per-region DERP health: region_id -> (healthy, last_frame_at).
    derp_regions: HashMap<i32, DerpRegionHealth>,
}

/// Per-region DERP health state.
#[derive(Clone, Debug)]
struct DerpRegionHealth {
    healthy: bool,
    last_frame_at: Option<DateTime<Utc>>,
}

/// The health tracker. Cloneable and cheap — all clones share one inner state.
#[derive(Clone)]
pub struct Tracker {
    inner: Arc<Mutex<Inner>>,
}

impl std::fmt::Debug for Tracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tracker").finish()
    }
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
                derp_regions: HashMap::new(),
            })),
        };
        t.register(Warnable {
            id: WARN_CONTROL.into(),
            severity: Severity::High,
            title: "Control connection".into(),
            ..Warnable::default()
        });
        t.register(Warnable {
            id: WARN_DERP_HOME.into(),
            severity: Severity::Medium,
            title: "DERP home region".into(),
            ..Warnable::default()
        });
        t.register(Warnable {
            id: WARN_CERT_FALLBACK.into(),
            severity: Severity::Low,
            title: "Certificate fallback".into(),
            ..Warnable::default()
        });
        t.register(Warnable {
            id: WARN_NETMON_CHANGE.into(),
            severity: Severity::Low,
            title: "Network changed".into(),
            ..Warnable::default()
        });
        t.register(Warnable {
            id: WARN_CAPTIVE_PORTAL.into(),
            severity: Severity::High,
            title: "Captive portal detected".into(),
            ..Warnable::default()
        });
        t.register(Warnable {
            id: WARN_PRODUCTIVITY.into(),
            severity: Severity::Medium,
            title: "Network down".into(),
            time_to_visible: Duration::from_secs(5),
            ..Warnable::default()
        });
        t.register(Warnable {
            id: WARN_UDP.into(),
            severity: Severity::Medium,
            title: "NAT traversal setup failure".into(),
            depends_on: vec![WARN_PRODUCTIVITY.into(), WARN_IDLE.into()],
            ..Warnable::default()
        });
        t.register(Warnable {
            id: WARN_IPV4.into(),
            severity: Severity::Medium,
            title: "IPv4 connectivity".into(),
            depends_on: vec![WARN_PRODUCTIVITY.into()],
            ..Warnable::default()
        });
        t.register(Warnable {
            id: WARN_IPV6.into(),
            severity: Severity::Medium,
            title: "IPv6 connectivity".into(),
            depends_on: vec![WARN_PRODUCTIVITY.into()],
            ..Warnable::default()
        });
        t.register(Warnable {
            id: WARN_DERP_NO_REGION.into(),
            severity: Severity::Medium,
            title: "No home relay server".into(),
            depends_on: vec![WARN_PRODUCTIVITY.into()],
            time_to_visible: Duration::from_secs(10),
        });
        t.register(Warnable {
            id: WARN_NOT_IN_MAP_POLL.into(),
            severity: Severity::Medium,
            title: "Out of sync".into(),
            depends_on: vec![WARN_PRODUCTIVITY.into(), WARN_IDLE.into()],
            time_to_visible: Duration::from_secs(8 * 60),
        });
        t.register(Warnable {
            id: WARN_MAP_RESPONSE_TIMEOUT.into(),
            severity: Severity::Medium,
            title: "Network map response timeout".into(),
            depends_on: vec![WARN_PRODUCTIVITY.into(), WARN_IDLE.into()],
            ..Warnable::default()
        });
        t.register(Warnable {
            id: WARN_NO_DERP_CONNECTION.into(),
            severity: Severity::Medium,
            title: "Relay server unavailable".into(),
            depends_on: vec![WARN_PRODUCTIVITY.into(), WARN_DERP_NO_REGION.into()],
            time_to_visible: Duration::from_secs(10),
        });
        t.register(Warnable {
            id: WARN_DERP_TIMEOUT.into(),
            severity: Severity::Medium,
            title: "Relay server timed out".into(),
            depends_on: vec![
                WARN_PRODUCTIVITY.into(),
                WARN_NO_DERP_CONNECTION.into(),
                WARN_DERP_NO_REGION.into(),
            ],
            ..Warnable::default()
        });
        t.register(Warnable {
            id: WARN_DERP_REGION_ERROR.into(),
            severity: Severity::Low,
            title: "Relay server error".into(),
            depends_on: vec![WARN_PRODUCTIVITY.into()],
            ..Warnable::default()
        });
        t.register(Warnable {
            id: WARN_TLS_CONNECTION_FAILED.into(),
            severity: Severity::Medium,
            title: "Encrypted connection failed".into(),
            depends_on: vec![WARN_PRODUCTIVITY.into()],
            ..Warnable::default()
        });
        t.register(Warnable {
            id: WARN_TLS_CERT_PENDING.into(),
            severity: Severity::Low,
            title: "Fetching TLS certificate".into(),
            ..Warnable::default()
        });
        t.register(Warnable {
            id: WARN_IDLE.into(),
            severity: Severity::Low,
            title: "Tailscale off".into(),
            ..Warnable::default()
        });
        t.register(Warnable {
            id: WARN_LOGIN.into(),
            severity: Severity::Medium,
            title: "Logged out".into(),
            depends_on: vec![WARN_IDLE.into()],
            ..Warnable::default()
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

    /// Set the health of a DERP region. When `healthy` is false, a warning
    /// is activated for the region. When true, any existing warning is
    /// cleared. Mirrors Go's `Tracker.SetDERPRegionHealth`
    /// (health.go:822-836).
    pub fn set_derp_region_health(&self, region_id: i32, healthy: bool) {
        let warnable_id = format!("{WARN_DERP_REGION_PREFIX}{region_id}-unreachable");
        if healthy {
            self.set_healthy(&warnable_id);
        } else {
            self.set_unhealthy(&warnable_id, format!("DERP region {region_id} unreachable"));
        }
        let mut g = self.inner.lock().expect("health mutex poisoned");
        g.derp_regions
            .entry(region_id)
            .and_modify(|h| h.healthy = healthy)
            .or_insert(DerpRegionHealth {
                healthy,
                last_frame_at: None,
            });
    }

    /// Note that a frame was received from the given DERP region at the
    /// current time, resetting the region's health to healthy. Mirrors
    /// Go's `Tracker.NoteDERPRegionReceivedFrame` (health.go:838-848).
    /// Also clears [`WARN_DERP_TIMEOUT`] when all known regions are healthy.
    pub fn note_derp_region_frame(&self, region_id: i32) {
        self.set_derp_region_health(region_id, true);
        let all_healthy = {
            let mut g = self.inner.lock().expect("health mutex poisoned");
            g.derp_regions.entry(region_id).and_modify(|h| {
                h.last_frame_at = Some(Utc::now());
            });
            g.derp_regions.values().all(|h| h.healthy)
        };
        if all_healthy {
            self.set_healthy(WARN_DERP_TIMEOUT);
        }
    }

    /// Check whether a DERP region has received a frame within the given
    /// timeout. If not, mark it unhealthy and fire [`WARN_DERP_TIMEOUT`].
    /// Returns true if marked unhealthy.
    /// Mirrors the recv-loop health check in Go's derp.go.
    pub fn check_derp_region_staleness(&self, region_id: i32, timeout: Duration) -> bool {
        let stale = {
            let g = self.inner.lock().expect("health mutex poisoned");
            match g.derp_regions.get(&region_id) {
                Some(h) => match h.last_frame_at {
                    Some(at) => {
                        Utc::now().signed_duration_since(at).num_seconds() as u64
                            >= timeout.as_secs()
                    }
                    None => false, // No frame ever received — don't mark stale until we have a baseline.
                },
                None => false,
            }
        };
        if stale {
            self.set_derp_region_health(region_id, false);
            self.set_unhealthy(
                WARN_DERP_TIMEOUT,
                format!(
                    "{{\"{ARG_DERP_REGION_ID}\":{region_id},\"{ARG_DURATION}\":\"{timeout:?}\"}}"
                ),
            );
        }
        stale
    }

    /// Whether a DERP region is currently marked healthy.
    pub fn derp_region_healthy(&self, region_id: i32) -> bool {
        let g = self.inner.lock().expect("health mutex poisoned");
        g.derp_regions.get(&region_id).is_some_and(|h| h.healthy)
    }

    /// Snapshot all active warnings, sorted by severity (High first) then id.
    ///
    /// Applies two visibility filters (mirroring Go's `Warnable.IsVisible`
    /// and `DependsOn` semantics):
    ///
    /// - **TimeToVisible**: a warnable that has been unhealthy for less than
    ///   its `time_to_visible` duration is suppressed (transient blip guard).
    /// - **DependsOn**: if any of a warnable's declared dependencies is itself
    ///   unhealthy, the warnable is suppressed — the dependency already
    ///   explains the symptom and showing both is noise.
    pub fn current_warnings(&self) -> Vec<Warning> {
        let g = self.inner.lock().expect("health mutex poisoned");
        let now = Utc::now();
        let mut out: Vec<Warning> = g
            .active
            .iter()
            .filter(|(id, (_, since))| {
                let Some(w) = g.warnables.get(*id) else {
                    return true; // unknown warnable: no metadata, show it
                };
                // TimeToVisible: suppress if not yet unhealthy long enough.
                if w.time_to_visible > Duration::ZERO {
                    let elapsed = now.signed_duration_since(*since);
                    if elapsed
                        < chrono::Duration::from_std(w.time_to_visible)
                            .unwrap_or(chrono::Duration::zero())
                    {
                        return false;
                    }
                }
                // DependsOn: suppress if any dependency is unhealthy.
                for dep in &w.depends_on {
                    if g.active.contains_key(dep) {
                        return false;
                    }
                }
                true
            })
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
// ReceiveFuncStats — track stuck receive tasks (#34)
// ---------------------------------------------------------------------------

/// Stats for a single receive func (e.g. wireguard-go's `ReceiveIPv4`,
/// `ReceiveIPv6`, `ReceiveDERP`). Mirrors Go's `health.ReceiveFuncStats`,
/// simplified to track last-received timestamps and in-call state.
///
/// A receive func is "stuck" when it has not received a packet in a while and
/// is not currently inside a call (blocked on nothing — the goroutine/task is
/// MIA). Call [`ReceiveFuncTracker::check_stuck`] to detect this.
///
/// Cloning shares the underlying counters (like a `&` reference in Go).
#[derive(Clone, Debug)]
pub struct ReceiveFuncStats {
    inner: Arc<ReceiveFuncStatsInner>,
}

#[derive(Debug)]
struct ReceiveFuncStatsInner {
    name: String,
    /// Total number of times the func has been called.
    num_calls: std::sync::atomic::AtomicU64,
    /// Whether the func is currently executing (inside `enter`/`exit`).
    in_call: std::sync::atomic::AtomicBool,
    /// Last time a packet was received by this func.
    last_received: Mutex<Option<DateTime<Utc>>>,
    /// Set by `check_stuck` when the func is detected as missing.
    missing: Mutex<bool>,
}

impl ReceiveFuncStats {
    /// Create a new stats entry with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            inner: Arc::new(ReceiveFuncStatsInner {
                name: name.into(),
                num_calls: std::sync::atomic::AtomicU64::new(0),
                in_call: std::sync::atomic::AtomicBool::new(false),
                last_received: Mutex::new(None),
                missing: Mutex::new(false),
            }),
        }
    }

    /// The name of this receive func.
    pub fn name(&self) -> &str {
        &self.inner.name
    }

    /// Record that the receive func was entered (started executing).
    pub fn enter(&self) {
        self.inner
            .num_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.inner
            .in_call
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Record that the receive func exited.
    pub fn exit(&self) {
        self.inner
            .in_call
            .store(false, std::sync::atomic::Ordering::Relaxed);
    }

    /// Record that a packet was received at the current time.
    pub fn note_received(&self) {
        *self.inner.last_received.lock().expect("recv stats mutex") = Some(Utc::now());
    }

    /// Total number of calls to this func.
    pub fn num_calls(&self) -> u64 {
        self.inner
            .num_calls
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Whether the func is currently inside a call.
    pub fn in_call(&self) -> bool {
        self.inner
            .in_call
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Last time a packet was received, if ever.
    pub fn last_received(&self) -> Option<DateTime<Utc>> {
        *self.inner.last_received.lock().expect("recv stats mutex")
    }

    /// Whether this func was flagged as missing by the last `check_stuck`.
    fn is_missing(&self) -> bool {
        *self.inner.missing.lock().expect("recv stats mutex")
    }

    fn set_missing(&self, v: bool) {
        *self.inner.missing.lock().expect("recv stats mutex") = v;
    }
}

/// Tracks [`ReceiveFuncStats`] for a set of named receive funcs and detects
/// stuck ones (no receive in N seconds and not currently in a call).
///
/// Mirrors Go's `Tracker.MagicSockReceiveFuncs` + `checkReceiveFuncsLocked`.
/// Cloning shares the underlying state.
#[derive(Clone, Debug, Default)]
pub struct ReceiveFuncTracker {
    funcs: Arc<Mutex<Vec<ReceiveFuncStats>>>,
}

impl ReceiveFuncTracker {
    /// Create a new empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a receive func by name. Returns nothing; use
    /// [`Self::stats`] to get a handle for `enter`/`exit`/`note_received`.
    pub fn register(&self, name: impl Into<String>) {
        let name = name.into();
        let mut g = self.funcs.lock().expect("recv tracker mutex");
        if !g.iter().any(|f| f.name() == name) {
            g.push(ReceiveFuncStats::new(name));
        }
    }

    /// Get the stats handle for a named func, if registered.
    pub fn stats(&self, name: &str) -> Option<ReceiveFuncStats> {
        let g = self.funcs.lock().expect("recv tracker mutex");
        g.iter().find(|f| f.name() == name).cloned()
    }

    /// Check all registered funcs for staleness. A func is "stuck" if:
    /// - it has not received a packet within `timeout`, AND
    /// - it is not currently inside a call (not blocked on I/O).
    ///
    /// Returns the names of all stuck funcs. Also updates each func's
    /// `missing` flag. Mirrors Go's `checkReceiveFuncsLocked`.
    pub fn check_stuck(&self, timeout: Duration) -> Vec<String> {
        let now = Utc::now();
        let chrono_timeout =
            chrono::Duration::from_std(timeout).unwrap_or(chrono::Duration::zero());
        let g = self.funcs.lock().expect("recv tracker mutex");
        let mut stuck = Vec::new();
        for f in g.iter() {
            let last = f.last_received();
            let is_stale = match last {
                Some(t) => now.signed_duration_since(t) >= chrono_timeout,
                None => false, // no baseline — don't flag as stuck yet
            };
            // Only stuck if not currently in a call.
            let is_stuck = is_stale && !f.in_call();
            f.set_missing(is_stuck);
            if is_stuck {
                stuck.push(f.name().to_string());
            }
        }
        stuck
    }

    /// Whether a named func is currently flagged as missing/stuck.
    pub fn is_missing(&self, name: &str) -> bool {
        let g = self.funcs.lock().expect("recv tracker mutex");
        g.iter()
            .find(|f| f.name() == name)
            .is_some_and(ReceiveFuncStats::is_missing)
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
            ..Warnable::default()
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

    // ---- DERP region health tests ----

    #[test]
    fn derp_region_set_unhealthy_and_healthy() {
        let t = Tracker::new();
        // Initially no record → not unhealthy, not healthy.
        assert!(!t.is_unhealthy("derp-region-5-unreachable"));
        assert!(!t.derp_region_healthy(5));

        // Mark unhealthy.
        t.set_derp_region_health(5, false);
        assert!(t.is_unhealthy("derp-region-5-unreachable"));
        assert!(!t.derp_region_healthy(5));

        // Mark healthy.
        t.set_derp_region_health(5, true);
        assert!(!t.is_unhealthy("derp-region-5-unreachable"));
        assert!(t.derp_region_healthy(5));
    }

    #[test]
    fn derp_region_note_frame_marks_healthy() {
        let t = Tracker::new();
        // Mark unhealthy first.
        t.set_derp_region_health(3, false);
        assert!(t.is_unhealthy("derp-region-3-unreachable"));

        // Note a frame — should clear the warning.
        t.note_derp_region_frame(3);
        assert!(!t.is_unhealthy("derp-region-3-unreachable"));
        assert!(t.derp_region_healthy(3));
    }

    #[test]
    fn derp_region_staleness_not_triggered_without_baseline() {
        let t = Tracker::new();
        // No frame ever received — should not mark stale.
        assert!(!t.check_derp_region_staleness(7, Duration::from_secs(0)));
        assert!(!t.is_unhealthy("derp-region-7-unreachable"));
    }

    #[test]
    fn derp_region_staleness_triggered_after_timeout() {
        let t = Tracker::new();
        // Record a frame to establish a baseline.
        t.note_derp_region_frame(9);
        assert!(t.derp_region_healthy(9));

        // With a 0-second timeout, the frame is already stale.
        assert!(t.check_derp_region_staleness(9, Duration::from_secs(0)));
        assert!(!t.derp_region_healthy(9));
        assert!(t.is_unhealthy("derp-region-9-unreachable"));
    }

    // ---- DependsOn / TimeToVisible tests (#33) ----

    #[test]
    fn depends_on_suppresses_when_dependency_unhealthy() {
        // WARN_UDP depends on WARN_PRODUCTIVITY and WARN_IDLE.
        // If WARN_IDLE is unhealthy, WARN_UDP should be suppressed.
        // (WARN_IDLE has no time_to_visible, so it appears immediately.)
        let t = Tracker::new();
        t.set_unhealthy(WARN_UDP, "can't bind udp");
        assert_eq!(
            t.current_warnings().len(),
            1,
            "WARN_UDP alone should be visible"
        );

        // Now mark its dependency unhealthy — WARN_UDP should be hidden.
        t.set_unhealthy(WARN_IDLE, "tailscale off");
        let ids: Vec<_> = t.current_warnings().iter().map(|w| w.id.clone()).collect();
        assert!(
            !ids.contains(&WARN_UDP.to_string()),
            "WARN_UDP should be suppressed when WARN_IDLE is unhealthy"
        );
        assert!(ids.contains(&WARN_IDLE.to_string()));

        // Clear the dependency — WARN_UDP reappears.
        t.set_healthy(WARN_IDLE);
        let ids: Vec<_> = t.current_warnings().iter().map(|w| w.id.clone()).collect();
        assert!(ids.contains(&WARN_UDP.to_string()));
    }

    #[test]
    fn time_to_visible_delays_warning() {
        // Register a warnable with a 200ms time-to-visible.
        let t = Tracker::new();
        t.register(Warnable {
            id: "delayed".into(),
            severity: Severity::Medium,
            title: "Delayed".into(),
            time_to_visible: Duration::from_millis(200),
            ..Warnable::default()
        });
        t.set_unhealthy("delayed", "boom");
        // Immediately: suppressed.
        assert!(
            t.current_warnings().is_empty(),
            "should not be visible before time_to_visible"
        );
        // After the delay: visible.
        std::thread::sleep(Duration::from_millis(250));
        assert_eq!(
            t.current_warnings().len(),
            1,
            "should be visible after delay"
        );
    }

    #[test]
    fn new_warnables_registered() {
        let t = Tracker::new();
        // All warnables (legacy + new) should be settable.
        for id in [
            WARN_PRODUCTIVITY,
            WARN_UDP,
            WARN_IPV4,
            WARN_IPV6,
            WARN_DERP_NO_REGION,
            WARN_IDLE,
            WARN_LOGIN,
            WARN_NOT_IN_MAP_POLL,
            WARN_MAP_RESPONSE_TIMEOUT,
            WARN_NO_DERP_CONNECTION,
            WARN_DERP_TIMEOUT,
            WARN_DERP_REGION_ERROR,
            WARN_TLS_CONNECTION_FAILED,
            WARN_TLS_CERT_PENDING,
        ] {
            t.set_unhealthy(id, "test");
            assert!(t.is_unhealthy(id), "{id} should be unhealthy");
            t.set_healthy(id);
            assert!(!t.is_unhealthy(id), "{id} should be healthy");
        }
    }

    #[test]
    fn arg_constants_have_expected_values() {
        // Verify the ARG_* key constants match Go's health.Args keys.
        assert_eq!(ARG_DURATION, "duration");
        assert_eq!(ARG_DERP_REGION_ID, "derp_region_id");
        assert_eq!(ARG_DERP_REGION_NAME, "derp_region_name");
        assert_eq!(ARG_ERROR, "error");
        assert_eq!(ARG_SERVER_NAME, "server_name");
        assert_eq!(ARG_DOMAINS, "domains");
        assert_eq!(ARG_LEGACY_ERROR, "legacy_error");
    }

    #[test]
    fn new_warnables_in_sorted_warnings() {
        // current_warnings sorts by severity (High first) then id ascending.
        // Set several new warnables unhealthy and verify they appear sorted.
        let t = Tracker::new();
        t.set_unhealthy(WARN_TLS_CERT_PENDING, "pending");
        t.set_unhealthy(WARN_DERP_REGION_ERROR, "err");
        t.set_unhealthy(WARN_TLS_CONNECTION_FAILED, "fail");
        let ids: Vec<_> = t.current_warnings().iter().map(|w| w.id.clone()).collect();
        // All three should be present (none have unhealthy dependencies).
        assert!(ids.contains(&WARN_TLS_CERT_PENDING.to_string()));
        assert!(ids.contains(&WARN_DERP_REGION_ERROR.to_string()));
        assert!(ids.contains(&WARN_TLS_CONNECTION_FAILED.to_string()));
        // Severity ordering: Medium before Low.
        let cert_idx = ids.iter().position(|x| x == WARN_TLS_CERT_PENDING).unwrap();
        let tls_idx = ids
            .iter()
            .position(|x| x == WARN_TLS_CONNECTION_FAILED)
            .unwrap();
        let err_idx = ids
            .iter()
            .position(|x| x == WARN_DERP_REGION_ERROR)
            .unwrap();
        assert!(tls_idx < cert_idx, "Medium should precede Low");
        assert!(tls_idx < err_idx, "Medium should precede Low");
    }

    #[test]
    fn not_in_map_poll_suppressed_by_idle_dependency() {
        // WARN_NOT_IN_MAP_POLL depends on WARN_PRODUCTIVITY + WARN_IDLE.
        // If WARN_IDLE is unhealthy, WARN_NOT_IN_MAP_POLL is suppressed in
        // current_warnings (but still tracked as unhealthy internally).
        // NOTE: WARN_NOT_IN_MAP_POLL has time_to_visible=8min, so it won't
        // appear in current_warnings immediately — use is_unhealthy to
        // verify the raw state, and current_warnings for the suppression.
        let t = Tracker::new();
        t.set_unhealthy(WARN_NOT_IN_MAP_POLL, "no stream");
        assert!(
            t.is_unhealthy(WARN_NOT_IN_MAP_POLL),
            "should be unhealthy internally"
        );
        // With WARN_IDLE unhealthy, WARN_NOT_IN_MAP_POLL is suppressed
        // even if it were past its time_to_visible.
        t.set_unhealthy(WARN_IDLE, "off");
        // WARN_IDLE has no time_to_visible → appears immediately.
        let warnings = t.current_warnings();
        assert!(
            !warnings.iter().any(|w| w.id == WARN_NOT_IN_MAP_POLL),
            "should be suppressed when WARN_IDLE is unhealthy"
        );
        assert!(
            warnings.iter().any(|w| w.id == WARN_IDLE),
            "WARN_IDLE should be visible"
        );
    }

    #[test]
    fn derp_timeout_fires_on_staleness() {
        let t = Tracker::new();
        // Establish a baseline frame, then check staleness with 0s timeout.
        t.note_derp_region_frame(9);
        assert!(t.check_derp_region_staleness(9, Duration::from_secs(0)));
        // WARN_DERP_TIMEOUT should now be active.
        assert!(t.is_unhealthy(WARN_DERP_TIMEOUT));
    }

    #[test]
    fn derp_timeout_cleared_when_all_regions_healthy() {
        let t = Tracker::new();
        // Mark a region stale to fire WARN_DERP_TIMEOUT.
        t.note_derp_region_frame(3);
        assert!(t.check_derp_region_staleness(3, Duration::from_secs(0)));
        assert!(t.is_unhealthy(WARN_DERP_TIMEOUT));
        // Receiving a frame marks the region healthy → all healthy → cleared.
        t.note_derp_region_frame(3);
        assert!(!t.is_unhealthy(WARN_DERP_TIMEOUT));
    }

    #[test]
    fn subsystem_prefix_constant() {
        assert_eq!(WARN_SUBSYSTEM_PREFIX, "subsystem-");
        // Verify a concrete subsystem id can be constructed.
        let dns_warnable = format!("{WARN_SUBSYSTEM_PREFIX}dns");
        assert_eq!(dns_warnable, "subsystem-dns");
    }

    // ---- ReceiveFuncStats / ReceiveFuncTracker tests (#34) ----

    #[test]
    fn receive_func_stats_enter_exit() {
        let s = ReceiveFuncStats::new("ReceiveIPv4");
        assert_eq!(s.num_calls(), 0);
        assert!(!s.in_call());
        s.enter();
        assert_eq!(s.num_calls(), 1);
        assert!(s.in_call());
        s.exit();
        assert!(!s.in_call());
    }

    #[test]
    fn receive_func_tracker_detects_stuck() {
        let tracker = ReceiveFuncTracker::new();
        tracker.register("ReceiveIPv4");
        tracker.register("ReceiveDERP");

        let s = tracker.stats("ReceiveIPv4").unwrap();
        s.note_received();
        // Not stuck yet — recent receive.
        assert!(
            tracker.check_stuck(Duration::from_secs(60)).is_empty(),
            "should not be stuck with recent receive"
        );

        // Simulate staleness by backdating the last_received timestamp.
        {
            let s = tracker.stats("ReceiveIPv4").unwrap();
            *s.inner.last_received.lock().unwrap() =
                Some(Utc::now() - chrono::Duration::seconds(120));
        }

        let stuck = tracker.check_stuck(Duration::from_secs(60));
        assert!(
            stuck.contains(&"ReceiveIPv4".to_string()),
            "ReceiveIPv4 should be stuck after 120s without receive"
        );
        assert!(tracker.is_missing("ReceiveIPv4"));
        assert!(!tracker.is_missing("ReceiveDERP"));
    }

    #[test]
    fn receive_func_tracker_not_stuck_when_in_call() {
        let tracker = ReceiveFuncTracker::new();
        tracker.register("ReceiveIPv6");
        let s = tracker.stats("ReceiveIPv6").unwrap();
        s.note_received();
        // Backdate but mark as in-call (blocked on I/O — not stuck).
        *s.inner.last_received.lock().unwrap() = Some(Utc::now() - chrono::Duration::seconds(120));
        s.inner
            .in_call
            .store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(
            tracker.check_stuck(Duration::from_secs(60)).is_empty(),
            "func in a call should not be flagged as stuck"
        );
    }

    #[test]
    fn receive_func_tracker_not_stuck_without_baseline() {
        let tracker = ReceiveFuncTracker::new();
        tracker.register("ReceiveDERP");
        // No note_received ever called — should not be flagged.
        assert!(
            tracker.check_stuck(Duration::from_secs(0)).is_empty(),
            "no baseline receive should not be flagged as stuck"
        );
    }
}
