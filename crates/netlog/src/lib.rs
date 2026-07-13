//! Network flow logging — port of Go's `wgengine/netlog` (695 loc).
//!
//! Aggregates per-connection packet/byte counts over 5s windows and
//! uploads them via logtail to the `tailtraffic.log.tailscale.io`
//! collection.
//!
//! Architecture: a [`Logger`] registers a [`ConnectionCounter`] callback
//! into the packet filter (virtual traffic, tun) and magicsock (physical
//! traffic, raw UDP). Every 5s the accumulated `Connection`+`Counts`
//! pairs are serialized as a [`Message`] JSON blob and written to
//! logtail.
//!
//! Phase 1: crate structure, types, logger with virtual traffic only
//! (tun path via the filter). Physical traffic from magicsock and
//! exit-node anonymization wiring are deferred to Phase 2.

pub mod record;
pub mod traffic;

pub use record::{ConnectionType, CountsAndType, Record};

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use rustscale_netlogtype::Node;
use rustscale_tsaddr::IpPrefix;
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::task::JoinHandle;

/// How often to flush the accumulated record and upload to logtail.
/// Mirrors Go's `pollPeriod`.
const POLL_PERIOD: std::time::Duration = std::time::Duration::from_secs(5);

/// Maximum JSON size for a single log message before early flush.
/// Mirrors Go's `maxLogSize = 256 << 10`.
const MAX_LOG_SIZE: usize = 256 << 10;

/// Callback for counting packets on a connection.
///
/// Mirrors Go's `netlogfunc.ConnectionCounter`:
/// `fn(proto, src, dst, packets, bytes, is_recv)`.
///
/// `recv=true` means the packet was received (Rx), `false` means
/// transmitted (Tx). The callback is `Send + Sync` so it can be stored
/// behind a `Mutex` (e.g. in the packet filter) and called from any
/// thread.
pub type ConnectionCounter =
    Arc<dyn Fn(u8, (IpAddr, u16), (IpAddr, u16), u64, u64, bool) + Send + Sync>;

/// Trait for devices that support connection counting. Mirrors Go's
/// `netlog.Device` interface.
pub trait ConnectionCountable {
    fn set_connection_counter(&self, counter: Option<ConnectionCounter>);
}

/// Node lookup interface for the netlog. Mirrors Go's `netlog.NodeSource`.
///
/// Methods are called from the logger's background task.
pub trait NodeSource: Send + Sync {
    /// The local node, or `None` if not yet known.
    fn self_node(&self) -> Option<Node>;
    /// The node assigned `addr`, or `None` if no node owns it.
    fn node_by_addr(&self, addr: IpAddr) -> Option<Node>;
}

/// Errors from the network logger.
#[derive(Debug, thiserror::Error)]
pub enum NetlogError {
    #[error("network logger already running")]
    AlreadyRunning,
    #[error("network logger not running")]
    NotRunning,
    #[error("network logger requires a non-nil NodeSource")]
    NoSource,
}

/// An event sent from a [`ConnectionCounter`] callback to the logger's
/// background aggregation task.
struct CountEvent {
    proto: u8,
    src: (IpAddr, u16),
    dst: (IpAddr, u16),
    packets: u64,
    bytes: u64,
    recv: bool,
    /// `true` = from tun (virtual traffic), `false` = from magicsock (physical).
    virtual_: bool,
}

/// Protected logger state — set at startup, read by the background task.
struct LoggerState {
    source: Option<Arc<dyn NodeSource>>,
    route_addrs: HashSet<IpAddr>,
    route_prefixes: Vec<IpPrefix>,
    logtail: Option<Arc<rustscale_logtail::LogTail>>,
    anonymize_exit: bool,
}

impl Default for LoggerState {
    fn default() -> Self {
        Self {
            source: None,
            route_addrs: HashSet::new(),
            route_prefixes: Vec::new(),
            logtail: None,
            anonymize_exit: true,
        }
    }
}

struct LoggerInner {
    /// Sender for the current run's channel. Replaced by `start()`.
    /// Guarded by a mutex, but only locked during `make_counter` (once
    /// per counter setup) and `start` — the hot-path callback uses a
    /// captured clone and never touches this mutex.
    counter_tx: Mutex<mpsc::UnboundedSender<CountEvent>>,
    state: Mutex<LoggerState>,
    shutdown: Notify,
}

/// Network flow logger. Mirrors Go's `netlog.Logger`.
///
/// The zero value is NOT ready for use — use [`Logger::new`] then
/// [`Logger::start`] to begin aggregation.
///
/// Hot-path callers (the packet filter) interact via a
/// [`ConnectionCounter`] obtained from [`Logger::make_counter`]. The
/// counter sends events through an unbounded channel to a background
/// tokio task that aggregates them into a [`Record`] and flushes every
/// 5 seconds.
pub struct Logger {
    inner: Arc<LoggerInner>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl Logger {
    /// Create a new logger (not yet started). Call [`Logger::start`] to
    /// begin aggregation and upload.
    ///
    /// A dummy channel is created so that [`Logger::make_counter`] can
    /// be called before `start` without panicking — events are simply
    /// discarded until the real channel is installed at startup.
    pub fn new() -> Self {
        let (tx, _rx) = mpsc::unbounded_channel::<CountEvent>();
        Self {
            inner: Arc::new(LoggerInner {
                counter_tx: Mutex::new(tx),
                state: Mutex::new(LoggerState::default()),
                shutdown: Notify::new(),
            }),
            handle: Mutex::new(None),
        }
    }

    /// Start the logger — spawn the aggregation + upload task.
    ///
    /// Mirrors Go's `Logger.Startup`. The `source` provides node
    /// lookups for traffic classification. The `logtail` handles upload
    /// to the `tailtraffic` collection.
    pub async fn start(
        &self,
        source: Arc<dyn NodeSource>,
        logtail: rustscale_logtail::LogTail,
    ) -> Result<(), NetlogError> {
        let mut handle_guard = self.handle.lock().await;
        if handle_guard.is_some() {
            return Err(NetlogError::AlreadyRunning);
        }

        // Create a fresh channel for this run so events from before
        // `start` don't mix with the new session.
        let (tx, rx) = mpsc::unbounded_channel::<CountEvent>();
        *self.inner.counter_tx.lock().await = tx;

        // Install source + logtail into the shared state.
        {
            let mut state = self.inner.state.lock().await;
            state.source = Some(source);
            state.logtail = Some(Arc::new(logtail));
        }

        // Spawn the aggregation + upload task.
        let inner = Arc::clone(&self.inner);
        let join = tokio::spawn(aggregation_task(inner, rx));
        *handle_guard = Some(join);
        Ok(())
    }

    /// Stop the logger, flush pending records, and wait for the
    /// background task to exit.
    ///
    /// Mirrors Go's `Logger.Shutdown`.
    pub async fn stop(&self) -> Result<(), NetlogError> {
        let mut handle_guard = self.handle.lock().await;
        let join = handle_guard.take().ok_or(NetlogError::NotRunning)?;
        // Signal the background task to do a final flush and exit.
        // `notify_one` stores a permit so the shutdown is not lost if
        // the task hasn't yet entered the `select!` loop.
        self.inner.shutdown.notify_one();
        // Wait for it to finish.
        let _ = join.await;
        // Purge state.
        let mut state = self.inner.state.lock().await;
        state.source = None;
        state.logtail = None;
        Ok(())
    }

    /// Whether the logger is currently running.
    pub async fn running(&self) -> bool {
        self.handle.lock().await.is_some()
    }

    /// Build a [`ConnectionCounter`] that sends events to this logger.
    ///
    /// `virtual_ = true` marks events as virtual (tun) traffic;
    /// `false` marks them as physical (magicsock) traffic.
    /// The counter is safe to call from any thread.
    pub async fn make_counter(&self, virtual_: bool) -> ConnectionCounter {
        let tx = self.inner.counter_tx.lock().await.clone();
        Arc::new(move |proto, src, dst, packets, bytes, recv| {
            // Non-blocking send — drop events if the channel is gone
            // (logger stopped). Unbounded channels never block.
            let _ = tx.send(CountEvent {
                proto,
                src,
                dst,
                packets,
                bytes,
                recv,
                virtual_,
            });
        })
    }

    /// Update the configured routes, used for subnet/exit classification.
    /// Mirrors Go's `Logger.ReconfigRoutes`.
    #[allow(clippy::implicit_hasher)]
    pub async fn reconfig_routes(&self, addrs: HashSet<IpAddr>, prefixes: Vec<IpPrefix>) {
        let mut state = self.inner.state.lock().await;
        state.route_addrs = addrs;
        state.route_prefixes = prefixes;
    }

    /// Set whether exit traffic is anonymized (ports and non-tailnet
    /// addresses scrubbed). Default: `true`.
    pub async fn set_anonymize_exit(&self, anonymize: bool) {
        self.inner.state.lock().await.anonymize_exit = anonymize;
    }
}

impl Default for Logger {
    fn default() -> Self {
        Self::new()
    }
}

/// The background aggregation + upload task.
///
/// Receives [`CountEvent`]s, accumulates them into a [`Record`], and
/// flushes every `POLL_PERIOD` (5s) or when the record would exceed
/// `MAX_LOG_SIZE`. On shutdown, does a final flush.
#[allow(clippy::single_match, clippy::ignored_unit_patterns)]
async fn aggregation_task(inner: Arc<LoggerInner>, mut rx: mpsc::UnboundedReceiver<CountEvent>) {
    let mut record = Record {
        self_node: None,
        start: chrono::Utc::now(),
        seen_nodes: HashMap::new(),
        virt_conns: HashMap::new(),
        phys_conns: HashMap::new(),
        json_len_estimate: 0,
    };
    let mut interval = tokio::time::interval(POLL_PERIOD);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased; // check shutdown first
            _ = inner.shutdown.notified() => {
                // Final flush, then exit.
                flush_record(&inner, &mut record).await;
                break;
            }
            // Drain pending events without waiting for the interval.
            maybe_ev = rx.recv() => {
                if let Some(ev) = maybe_ev {
                    process_event(&inner, &mut record, ev).await;
                } else {
                    // Channel closed — no more counters. Final flush.
                    flush_record(&inner, &mut record).await;
                    break;
                }
            }
            _ = interval.tick() => {
                // Periodic flush. Only flush if the record has data and
                // enough time has elapsed (matching Go's
                // `time.Since(start) > pollPeriod/2`).
                if !record.is_empty() {
                    let elapsed = chrono::Utc::now().signed_duration_since(record.start);
                    if elapsed.num_milliseconds() > (POLL_PERIOD.as_millis() as i64) / 2 {
                        flush_record(&inner, &mut record).await;
                    }
                }
            }
        }
    }
}

/// Process a single [`CountEvent`]: classify it and add it to the record.
async fn process_event(inner: &LoggerInner, record: &mut Record, ev: CountEvent) {
    let state = inner.state.lock().await;

    // Initialize the record with the self node if needed.
    if record.json_len_estimate == 0 {
        init_record(&state, record);
    }

    if ev.virtual_ {
        // Virtual traffic — classify into Virtual/Subnet/Exit/unknown.
        let self_id = record
            .self_node
            .as_ref()
            .map(|n| n.node_id.clone())
            .unwrap_or_default();

        // Look up src and dst nodes for classification.
        let src_node = state.source.as_ref().and_then(|s| s.node_by_addr(ev.src.0));
        let dst_node = state.source.as_ref().and_then(|s| s.node_by_addr(ev.dst.0));

        // Note seen nodes for the message's dstNodes.
        if let Some(ref n) = src_node {
            record.note_seen_node(ev.src.0, n.clone());
        }
        if let Some(ref n) = dst_node {
            record.note_seen_node(ev.dst.0, n.clone());
        }

        let src_is_self = src_node.as_ref().is_some_and(|n| n.node_id == self_id);
        let dst_node_valid = dst_node.is_some();

        // Check if adding this connection + node info would overflow.
        let extra = rustscale_netlogtype::MAX_CONNECTION_COUNTS_JSON_SIZE;
        if record.would_overflow(MAX_LOG_SIZE, extra) {
            // Flush early and start a fresh record.
            drop(state);
            flush_record(inner, record).await;
            let state = inner.state.lock().await;
            init_record(&state, record);
            let self_id = record
                .self_node
                .as_ref()
                .map(|n| n.node_id.clone())
                .unwrap_or_default();
            let src_is_self = src_node.as_ref().is_some_and(|n| n.node_id == self_id);
            let dst_node_valid = dst_node.is_some();
            let conn_type = traffic::classify_virtual_traffic(
                src_is_self,
                dst_node_valid,
                ev.src.0,
                ev.dst.0,
                &state.route_addrs,
                &state.route_prefixes,
            );
            record.add_virt(
                ev.proto, ev.src, ev.dst, ev.packets, ev.bytes, ev.recv, conn_type,
            );
            return;
        }

        let conn_type = traffic::classify_virtual_traffic(
            src_is_self,
            dst_node_valid,
            ev.src.0,
            ev.dst.0,
            &state.route_addrs,
            &state.route_prefixes,
        );
        record.add_virt(
            ev.proto, ev.src, ev.dst, ev.packets, ev.bytes, ev.recv, conn_type,
        );
    } else {
        // Physical traffic — no classification, just accumulate.
        let extra = rustscale_netlogtype::MAX_CONNECTION_COUNTS_JSON_SIZE;
        if record.would_overflow(MAX_LOG_SIZE, extra) {
            drop(state);
            flush_record(inner, record).await;
            let state = inner.state.lock().await;
            init_record(&state, record);
            // Note the source node for physical traffic.
            if let Some(ref source) = state.source {
                if let Some(n) = source.node_by_addr(ev.src.0) {
                    record.note_seen_node(ev.src.0, n);
                }
            }
            record.add_phys(ev.proto, ev.src, ev.dst, ev.packets, ev.bytes, ev.recv);
            return;
        }
        // Note the source node for physical traffic (matching Go's addNewPhysConnLocked).
        if let Some(ref source) = state.source {
            if let Some(n) = source.node_by_addr(ev.src.0) {
                record.note_seen_node(ev.src.0, n);
            }
        }
        record.add_phys(ev.proto, ev.src, ev.dst, ev.packets, ev.bytes, ev.recv);
    }
}

/// Initialize a fresh record from the current state.
fn init_record(state: &LoggerState, record: &mut Record) {
    record.clear();
    if let Some(ref source) = state.source {
        if let Some(self_node) = source.self_node() {
            record.self_node = Some(self_node);
        }
    }
    record.start = chrono::Utc::now();
    record.json_len_estimate = rustscale_netlogtype::MIN_MESSAGE_JSON_SIZE
        + record.self_node.as_ref().map_or(0, node_json_estimate);
}

/// Flush the current record: serialize as a [`Message`] and write to logtail.
/// Resets the record for the next window.
async fn flush_record(inner: &LoggerInner, record: &mut Record) {
    if record.json_len_estimate == 0 {
        return;
    }
    let end = chrono::Utc::now();
    let state = inner.state.lock().await;
    let msg = record.to_message(end, state.anonymize_exit);
    if let Some(msg) = msg {
        match serde_json::to_string(&msg) {
            Ok(json) => {
                if let Some(ref lt) = state.logtail {
                    lt.write(&json);
                }
            }
            Err(e) => {
                log::warn!("netlog: JSON serialize error: {e}");
            }
        }
    }
    record.clear();
}

/// Rough upper-bound JSON size for a [`Node`]. Used for the
/// `json_len_estimate` that triggers early flushes.
fn node_json_estimate(n: &Node) -> usize {
    let mut len = 2; // "{}"
    len += 8 + n.node_id.len() + 1; // "nodeId":"<id>",
    if !n.name.is_empty() {
        len += 7 + n.name.len() + 1;
    }
    if !n.addresses.is_empty() {
        len += 13;
        for a in &n.addresses {
            len += a.len() + 3;
        }
    }
    if !n.os.is_empty() {
        len += 5 + n.os.len() + 1;
    }
    if !n.user.is_empty() {
        len += 7 + n.user.len() + 1;
    }
    if !n.tags.is_empty() {
        len += 8;
        for t in &n.tags {
            len += t.len() + 3;
        }
    }
    len
}

#[cfg(test)]
mod tests;
