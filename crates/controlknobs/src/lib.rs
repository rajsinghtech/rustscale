//! Dynamic feature flags ("control knobs") sent by the control plane.
//!
//! Ports Go's `control/controlknobs/controlknobs.go`. The control plane can
//! adjust client-side behavior at runtime by including node attributes
//! (capabilities) in `MapResponse.Node.CapMap`. This crate provides a generic
//! key-value store with typed accessors and change-notification callbacks so
//! downstream crates (magicsock, derp, netcheck, …) can query knob values
//! without coupling to the control-client internals.
//!
//! ## Usage
//!
//! ```no_run
//! use rustscale_controlknobs::ControlKnobs;
//! use std::collections::HashMap;
//! use std::sync::Arc;
//!
//! let knobs = Arc::new(ControlKnobs::new());
//!
//! // Apply a batch from the netmap.
//! let mut batch = HashMap::new();
//! batch.insert("debug-always-stun".into(), "true".into());
//! batch.insert("netcheck.freq".into(), "30".into());
//! knobs.apply(batch);
//!
//! assert!(knobs.get_bool("debug-always-stun", false));
//! assert!((knobs.get_float("netcheck.freq", 0.0) - 30.0).abs() < f64::EPSILON);
//! ```

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

/// A set of feature flags adjustable at runtime by the control plane.
///
/// Thread-safe: the knob map is behind a [`RwLock`] so multiple readers can
/// query concurrently; [`apply`](Self::apply) takes a write lock. Change
/// callbacks are invoked **after** the write lock is released to avoid
/// deadlocks if a callback itself reads other knobs.
pub struct ControlKnobs {
    knobs: Arc<RwLock<HashMap<String, String>>>,
    callbacks: Arc<Mutex<HashMap<String, Vec<Box<dyn Fn(Option<&str>) + Send>>>>>,
}

impl ControlKnobs {
    /// Create an empty knob set.
    pub fn new() -> Self {
        Self {
            knobs: Arc::new(RwLock::new(HashMap::new())),
            callbacks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Apply a batch of knob values from the netmap.
    ///
    /// Merges `incoming` into the current set: existing keys are overwritten,
    /// new keys are added, and keys absent from `incoming` are left untouched.
    /// Change callbacks fire only for keys whose value actually changed.
    pub fn apply(&self, incoming: HashMap<String, String>) {
        // Collect changes under the write lock, then fire callbacks after
        // releasing it so callbacks can safely read other knobs.
        let changes: Vec<(String, String)> = {
            let mut knobs = self.knobs.write().expect("knobs write lock poisoned");
            let mut changed = Vec::new();
            for (k, v) in &incoming {
                let old = knobs.get(k.as_str()).map(String::as_str);
                if old != Some(v.as_str()) {
                    knobs.insert(k.clone(), v.clone());
                    changed.push((k.clone(), v.clone()));
                }
            }
            changed
        };

        // Fire callbacks outside the knobs lock.
        let cbs = self.callbacks.lock().expect("callbacks lock poisoned");
        for (key, new_val) in &changes {
            if let Some(handlers) = cbs.get(key.as_str()) {
                for cb in handlers {
                    cb(Some(new_val.as_str()));
                }
            }
        }
    }

    /// Get a boolean knob by name.
    ///
    /// Accepts `"true"`, `"1"`, `"yes"`, `"on"` (case-insensitive) as `true`;
    /// everything else parses as `false`. Returns `default` when the knob is
    /// absent or the value fails to parse.
    pub fn get_bool(&self, name: &str, default: bool) -> bool {
        let knobs = self.knobs.read().expect("knobs read lock poisoned");
        match knobs.get(name) {
            Some(v) => parse_bool(v).unwrap_or(default),
            None => default,
        }
    }

    /// Get a float knob by name.
    ///
    /// Returns `default` when the knob is absent or the value fails to parse.
    pub fn get_float(&self, name: &str, default: f64) -> f64 {
        let knobs = self.knobs.read().expect("knobs read lock poisoned");
        match knobs.get(name) {
            Some(v) => v.parse::<f64>().unwrap_or(default),
            None => default,
        }
    }

    /// Get a string knob by name.
    ///
    /// Returns `default` when the knob is absent.
    pub fn get_string(&self, name: &str, default: &str) -> String {
        let knobs = self.knobs.read().expect("knobs read lock poisoned");
        knobs
            .get(name)
            .cloned()
            .unwrap_or_else(|| default.to_string())
    }

    /// Check if a knob with this name is present.
    pub fn has(&self, name: &str) -> bool {
        let knobs = self.knobs.read().expect("knobs read lock poisoned");
        knobs.contains_key(name)
    }

    /// Register a callback for when a specific knob changes.
    ///
    /// The callback receives `Some(new_value)` when the knob's value changes
    /// via [`apply`](Self::apply). Multiple callbacks can be registered for
    /// the same knob; they fire in registration order.
    pub fn on_change(&self, name: &str, callback: Box<dyn Fn(Option<&str>) + Send>) {
        let mut cbs = self.callbacks.lock().expect("callbacks lock poisoned");
        cbs.entry(name.to_string()).or_default().push(callback);
    }

    /// Get a snapshot of all current knobs (for testing/inspection).
    pub fn all(&self) -> HashMap<String, String> {
        let knobs = self.knobs.read().expect("knobs read lock poisoned");
        knobs.clone()
    }
}

impl Clone for ControlKnobs {
    fn clone(&self) -> Self {
        Self {
            knobs: Arc::clone(&self.knobs),
            callbacks: Arc::clone(&self.callbacks),
        }
    }
}

impl Default for ControlKnobs {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a boolean from a string knob value (case-insensitive).
fn parse_bool(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
