//! Client metric registry — ports Go's `util/clientmetric/clientmetric.go`.
//!
//! Provides a thread-safe registry where subsystems can register counters and
//! gauges. Metrics are exposed via the LocalAPI `/metrics` endpoint in
//! Prometheus text exposition format.
//!
//! Unlike Go's global singleton, this uses an explicit `Registry` struct so
//! that tests can create isolated registries and the LocalAPI can hold a single
//! shared instance.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

/// Metric type — counter (monotonic) or gauge (can go up or down).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MetricType {
    Counter,
    Gauge,
}

impl std::fmt::Display for MetricType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MetricType::Counter => write!(f, "counter"),
            MetricType::Gauge => write!(f, "gauge"),
        }
    }
}

/// A metric handle — either an atomic value or a function-backed gauge.
#[derive(Clone)]
pub struct Metric {
    name: String,
    typ: MetricType,
    value: Arc<AtomicI64>,
    /// Optional help text for Prometheus exposition.
    help: Arc<Mutex<String>>,
}

impl Metric {
    /// The metric name (e.g. `rustscale_packet_drops_total`).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The metric type.
    pub fn typ(&self) -> MetricType {
        self.typ
    }

    /// Current value of the metric.
    pub fn value(&self) -> i64 {
        self.value.load(Ordering::Relaxed)
    }

    /// Set the help text.
    pub fn set_help(&self, help: &str) {
        *self.help.lock().unwrap() = help.to_string();
    }

    /// Get the help text.
    pub fn help(&self) -> String {
        self.help.lock().unwrap().clone()
    }

    /// Add `n` to the counter. For counters, `n` should not be negative.
    pub fn add(&self, n: i64) {
        self.value.fetch_add(n, Ordering::Relaxed);
    }

    /// Set the gauge value to `v`.
    pub fn set(&self, v: i64) {
        self.value.store(v, Ordering::Relaxed);
    }

    /// Increment by 1.
    pub fn inc(&self) {
        self.add(1);
    }
}

/// A registry of client metrics — thread-safe, shared via `Arc`.
///
/// Subsystems register metrics at startup. The LocalAPI `/metrics` handler
/// calls `to_prometheus_text()` to render the Prometheus exposition format.
///
/// ```
/// use rustscale_clientmetric::Registry;
/// let reg = Registry::new();
/// let drops = reg.counter("rustscale_packet_drops_total");
/// drops.inc();
/// let text = reg.to_prometheus_text();
/// assert!(text.contains("rustscale_packet_drops_total 1"));
/// ```
#[derive(Clone, Default)]
pub struct Registry {
    metrics: Arc<Mutex<HashMap<String, Metric>>>,
}

impl Registry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new counter metric. Returns the metric handle.
    /// If a metric with the same name already exists, returns the existing one.
    pub fn counter(&self, name: &str) -> Metric {
        self.register(name, MetricType::Counter)
    }

    /// Register a new gauge metric. Returns the metric handle.
    /// If a metric with the same name already exists, returns the existing one.
    pub fn gauge(&self, name: &str) -> Metric {
        self.register(name, MetricType::Gauge)
    }

    /// Register a metric, or return the existing one if already present.
    fn register(&self, name: &str, typ: MetricType) -> Metric {
        let mut map = self.metrics.lock().unwrap();
        if let Some(m) = map.get(name) {
            return m.clone();
        }
        let metric = Metric {
            name: name.to_string(),
            typ,
            value: Arc::new(AtomicI64::new(0)),
            help: Arc::new(Mutex::new(String::new())),
        };
        map.insert(name.to_string(), metric.clone());
        metric
    }

    /// Register a counter with a help string.
    pub fn counter_with_help(&self, name: &str, help: &str) -> Metric {
        let m = self.counter(name);
        m.set_help(help);
        m
    }

    /// Register a gauge with a help string.
    pub fn gauge_with_help(&self, name: &str, help: &str) -> Metric {
        let m = self.gauge(name);
        m.set_help(help);
        m
    }

    /// Get a metric by name, if registered.
    pub fn get(&self, name: &str) -> Option<Metric> {
        self.metrics.lock().unwrap().get(name).cloned()
    }

    /// Render all metrics in Prometheus text exposition format.
    ///
    /// Each metric produces:
    /// ```text
    /// # HELP <name> <help>
    /// # TYPE <name> <type>
    /// <name> <value>
    /// ```
    pub fn to_prometheus_text(&self) -> String {
        use std::fmt::Write;
        let map = self.metrics.lock().unwrap();
        let mut names: Vec<&String> = map.keys().collect();
        names.sort();

        let mut out = String::new();
        for name in names {
            let m = &map[name];
            let help = m.help();
            if !help.is_empty() {
                let _ = writeln!(out, "# HELP {name} {help}");
            }
            let _ = writeln!(out, "# TYPE {name} {}", m.typ());
            let _ = writeln!(out, "{name} {}", m.value());
        }
        out
    }

    /// Render metrics as JSON (for the upload-client-metrics endpoint).
    ///
    /// Returns a vector of `MetricUpdate` objects.
    pub fn to_json(&self) -> Vec<MetricUpdate> {
        let map = self.metrics.lock().unwrap();
        map.values()
            .map(|m| MetricUpdate {
                name: m.name().to_string(),
                typ: m.typ(),
                value: m.value(),
            })
            .collect()
    }

    /// Number of registered metrics.
    pub fn len(&self) -> usize {
        self.metrics.lock().unwrap().len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.metrics.lock().unwrap().is_empty()
    }
}

/// A metric update for the JSON wire format (Go's `MetricUpdate`).
#[derive(Clone, Debug, serde::Serialize)]
pub struct MetricUpdate {
    pub name: String,
    #[serde(rename = "type")]
    pub typ: MetricType,
    pub value: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_increments() {
        let reg = Registry::new();
        let c = reg.counter("test_counter");
        c.inc();
        c.add(5);
        assert_eq!(c.value(), 6);
    }

    #[test]
    fn gauge_sets() {
        let reg = Registry::new();
        let g = reg.gauge("test_gauge");
        g.set(42);
        assert_eq!(g.value(), 42);
        g.set(10);
        assert_eq!(g.value(), 10);
    }

    #[test]
    fn duplicate_name_returns_same() {
        let reg = Registry::new();
        let c1 = reg.counter("dup");
        c1.inc();
        let c2 = reg.counter("dup");
        assert_eq!(c2.value(), 1);
        c2.inc();
        assert_eq!(c1.value(), 2);
    }

    #[test]
    fn prometheus_text_format() {
        let reg = Registry::new();
        let c = reg.counter_with_help("my_counter", "A test counter");
        c.add(3);
        let g = reg.gauge("my_gauge");
        g.set(7);

        let text = reg.to_prometheus_text();
        assert!(text.contains("# HELP my_counter A test counter"));
        assert!(text.contains("# TYPE my_counter counter"));
        assert!(text.contains("my_counter 3"));
        assert!(text.contains("# TYPE my_gauge gauge"));
        assert!(text.contains("my_gauge 7"));
    }

    #[test]
    fn json_format() {
        let reg = Registry::new();
        reg.counter("json_counter").add(5);
        let updates = reg.to_json();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].name, "json_counter");
        assert_eq!(updates[0].value, 5);
    }

    #[test]
    fn metric_type_display() {
        assert_eq!(MetricType::Counter.to_string(), "counter");
        assert_eq!(MetricType::Gauge.to_string(), "gauge");
    }

    #[test]
    fn empty_registry() {
        let reg = Registry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.to_prometheus_text(), "");
    }

    #[test]
    fn len_tracks_registrations() {
        let reg = Registry::new();
        reg.counter("a");
        reg.gauge("b");
        assert_eq!(reg.len(), 2);
    }
}
