//! Per-label socket TX/RX byte counter collection.
//!
//! Ports Go's `net/sockstats` per-label tx/rx byte counter collection. Go
//! hooks into a modified runtime to intercept socket reads/writes; rustscale
//! uses **manual instrumentation** instead — each socket send/recv path calls
//! [`LabelHandle::record_tx`] / [`LabelHandle::record_rx`] on a cheap shared
//! atomic handle. This is less magical but works on std Rust with no runtime
//! modifications.
//!
//! The global registry ([`SockStats`]) is created once at startup and injected
//! into each subsystem. Snapshots are serialized to JSON by the C2N
//! `/sockstats` and PeerAPI `/v0/sockstats` debug endpoints.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A socket-statistics label, mirroring Go's `sockstats.Label`.
///
/// Each label identifies a logical socket owner. Counters are tracked
/// per-label so the operator can see how much traffic each subsystem
/// generates (control plane, DERP relay, DNS forwarder, magicsock UDP,
/// netcheck, portmapper, etc.).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Label {
    ControlClientAuto = 0,
    ControlClientDialer = 1,
    DERPHTTPClient = 2,
    LogtailLogger = 3,
    DNSForwarderDoH = 4,
    DNSForwarderUDP = 5,
    NetcheckClient = 6,
    PortmapperClient = 7,
    MagicsockConnUDP4 = 8,
    MagicsockConnUDP6 = 9,
    NetlogLogger = 10,
    SockstatlogLogger = 11,
    DNSForwarderTCP = 12,
}

impl Label {
    /// Stable human-readable name used as the JSON key (matches Go's
    /// `Label.String()`).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ControlClientAuto => "ControlClientAuto",
            Self::ControlClientDialer => "ControlClientDialer",
            Self::DERPHTTPClient => "DERPHTTPClient",
            Self::LogtailLogger => "LogtailLogger",
            Self::DNSForwarderDoH => "DNSForwarderDoH",
            Self::DNSForwarderUDP => "DNSForwarderUDP",
            Self::NetcheckClient => "NetcheckClient",
            Self::PortmapperClient => "PortmapperClient",
            Self::MagicsockConnUDP4 => "MagicsockConnUDP4",
            Self::MagicsockConnUDP6 => "MagicsockConnUDP6",
            Self::NetlogLogger => "NetlogLogger",
            Self::SockstatlogLogger => "SockstatlogLogger",
            Self::DNSForwarderTCP => "DNSForwarderTCP",
        }
    }

    /// Iterate over all known labels in discriminant order.
    pub const ALL: [Label; 13] = [
        Label::ControlClientAuto,
        Label::ControlClientDialer,
        Label::DERPHTTPClient,
        Label::LogtailLogger,
        Label::DNSForwarderDoH,
        Label::DNSForwarderUDP,
        Label::NetcheckClient,
        Label::PortmapperClient,
        Label::MagicsockConnUDP4,
        Label::MagicsockConnUDP6,
        Label::NetlogLogger,
        Label::SockstatlogLogger,
        Label::DNSForwarderTCP,
    ];
}

/// TX/RX byte counters for a single label at a point in time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabelCounters {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

/// Atomic counters backing a [`LabelHandle`], stored in the registry so that
/// every handle for a given label shares the same atomics.
struct LabelAtomicCounters {
    tx: Arc<AtomicU64>,
    rx: Arc<AtomicU64>,
}

#[derive(Default)]
struct SockStatsInner {
    counters: HashMap<Label, LabelAtomicCounters>,
    current_interface_cellular: bool,
}

/// The global socket-statistics registry.
///
/// Clone is cheap (single `Arc`); all clones share the same counters. Create
/// once at startup and inject into each subsystem via
/// [`SockStats::label_handle`].
#[derive(Clone, Default)]
pub struct SockStats {
    inner: Arc<Mutex<SockStatsInner>>,
}

impl SockStats {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(SockStatsInner {
                counters: HashMap::new(),
                current_interface_cellular: false,
            })),
        }
    }

    /// Get a handle to increment counters for `label`, creating the entry on
    /// first access. The handle shares the underlying atomics with the
    /// registry, so increments are immediately visible to [`Self::snapshot`].
    pub fn label_handle(&self, label: Label) -> LabelHandle {
        let mut inner = self.inner.lock().expect("sockstats lock poisoned");
        let entry = inner
            .counters
            .entry(label)
            .or_insert_with(|| LabelAtomicCounters {
                tx: Arc::new(AtomicU64::new(0)),
                rx: Arc::new(AtomicU64::new(0)),
            });
        LabelHandle {
            tx: entry.tx.clone(),
            rx: entry.rx.clone(),
        }
    }

    /// Snapshot all non-zero counters, keyed by label. Labels that have never
    /// been touched (no handle created) are omitted.
    #[must_use]
    pub fn snapshot(&self) -> HashMap<Label, LabelCounters> {
        let inner = self.inner.lock().expect("sockstats lock poisoned");
        inner
            .counters
            .iter()
            .map(|(&label, atomics)| {
                (
                    label,
                    LabelCounters {
                        tx_bytes: atomics.tx.load(Ordering::Relaxed),
                        rx_bytes: atomics.rx.load(Ordering::Relaxed),
                    },
                )
            })
            .collect()
    }

    /// Whether the current active interface is cellular.
    #[must_use]
    pub fn current_interface_cellular(&self) -> bool {
        self.inner
            .lock()
            .expect("sockstats lock poisoned")
            .current_interface_cellular
    }

    pub fn set_current_interface_cellular(&self, v: bool) {
        let mut inner = self.inner.lock().expect("sockstats lock poisoned");
        inner.current_interface_cellular = v;
    }

    /// Produce the JSON value emitted by the C2N `/sockstats` and PeerAPI
    /// `/v0/sockstats` debug endpoints:
    ///
    /// ```json
    /// {
    ///   "stats": {
    ///     "MagicsockConnUDP4": { "tx_bytes": 123, "rx_bytes": 456 }
    ///   },
    ///   "current_interface_cellular": false
    /// }
    /// ```
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let snap = self.snapshot();
        let cellular = self.current_interface_cellular();
        let mut stats = serde_json::Map::new();
        for label in Label::ALL {
            if let Some(c) = snap.get(&label) {
                if c.tx_bytes == 0 && c.rx_bytes == 0 {
                    continue;
                }
                stats.insert(
                    label.name().to_string(),
                    serde_json::to_value(c).unwrap_or(serde_json::Value::Null),
                );
            }
        }
        serde_json::json!({
            "stats": stats,
            "current_interface_cellular": cellular,
        })
    }
}

/// A cheap clone handle to a label's TX/RX atomics.
///
/// Record sends with [`LabelHandle::record_tx`] and receives with
/// [`LabelHandle::record_rx`]. Both are fire-and-forget relaxed atomic
/// increments — no error paths, no allocation.
#[derive(Clone)]
pub struct LabelHandle {
    tx: Arc<AtomicU64>,
    rx: Arc<AtomicU64>,
}

impl LabelHandle {
    /// Record `n` bytes sent on this label's socket.
    pub fn record_tx(&self, n: usize) {
        self.tx.fetch_add(n as u64, Ordering::Relaxed);
    }

    /// Record `n` bytes received on this label's socket.
    pub fn record_rx(&self, n: usize) {
        self.rx.fetch_add(n as u64, Ordering::Relaxed);
    }

    /// Current counter values for this handle.
    #[must_use]
    pub fn counters(&self) -> LabelCounters {
        LabelCounters {
            tx_bytes: self.tx.load(Ordering::Relaxed),
            rx_bytes: self.rx.load(Ordering::Relaxed),
        }
    }
}

impl Default for LabelHandle {
    fn default() -> Self {
        Self {
            tx: Arc::new(AtomicU64::new(0)),
            rx: Arc::new(AtomicU64::new(0)),
        }
    }
}

/// A wrapper around an async stream that counts bytes read and written through
/// two [`LabelHandle`]s. Use it to instrument TCP-based labels
/// (e.g. `DNSForwarderTCP`, `ControlClientDialer`) without sprinkling manual
/// `record_tx`/`record_rx` calls at every read/write site.
pub struct CountedStream<S> {
    inner: S,
    tx_handle: LabelHandle,
    rx_handle: LabelHandle,
}

impl<S> CountedStream<S> {
    pub fn new(inner: S, tx_handle: LabelHandle, rx_handle: LabelHandle) -> Self {
        Self {
            inner,
            tx_handle,
            rx_handle,
        }
    }

    pub fn inner(&self) -> &S {
        &self.inner
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountedStream<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = std::pin::Pin::new(&mut this.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let after = buf.filled().len();
            if after > before {
                this.rx_handle.record_rx(after - before);
            }
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountedStream<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let result = std::pin::Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &result {
            this.tx_handle.record_tx(*n);
        }
        result
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_names_match_go() {
        assert_eq!(Label::ControlClientAuto.name(), "ControlClientAuto");
        assert_eq!(Label::MagicsockConnUDP4.name(), "MagicsockConnUDP4");
        assert_eq!(Label::DERPHTTPClient.name(), "DERPHTTPClient");
        assert_eq!(Label::DNSForwarderTCP.name(), "DNSForwarderTCP");
    }

    #[test]
    fn handle_increments_are_visible_in_snapshot() {
        let stats = SockStats::new();
        let h = stats.label_handle(Label::MagicsockConnUDP4);
        h.record_tx(100);
        h.record_tx(50);
        h.record_rx(300);

        let snap = stats.snapshot();
        let c = snap
            .get(&Label::MagicsockConnUDP4)
            .copied()
            .unwrap_or_default();
        assert_eq!(c.tx_bytes, 150);
        assert_eq!(c.rx_bytes, 300);
    }

    #[test]
    fn handle_shares_atomics_with_registry() {
        let stats = SockStats::new();
        let h1 = stats.label_handle(Label::DERPHTTPClient);
        let h2 = stats.label_handle(Label::DERPHTTPClient);
        h1.record_tx(10);
        h2.record_tx(20);
        assert_eq!(h1.counters().tx_bytes, 30);
    }

    #[test]
    fn snapshot_omits_untouched_labels() {
        let stats = SockStats::new();
        let _ = stats.label_handle(Label::NetcheckClient);
        let snap = stats.snapshot();
        assert!(snap.contains_key(&Label::NetcheckClient));
        assert!(!snap.contains_key(&Label::PortmapperClient));
    }

    #[test]
    fn json_shape_has_stats_and_cellular() {
        let stats = SockStats::new();
        let h = stats.label_handle(Label::MagicsockConnUDP4);
        h.record_tx(123_456);
        h.record_rx(789_012);
        stats.set_current_interface_cellular(false);

        let v = stats.to_json();
        let obj = v.as_object().expect("json object");
        assert!(obj.contains_key("stats"));
        assert_eq!(
            obj.get("current_interface_cellular"),
            Some(&serde_json::Value::Bool(false))
        );

        let stats_obj = obj
            .get("stats")
            .and_then(|v| v.as_object())
            .expect("stats obj");
        let entry = stats_obj
            .get("MagicsockConnUDP4")
            .and_then(|v| v.as_object())
            .expect("MagicsockConnUDP4 entry");
        assert_eq!(entry.get("tx_bytes"), Some(&serde_json::json!(123_456)));
        assert_eq!(entry.get("rx_bytes"), Some(&serde_json::json!(789_012)));
    }

    #[test]
    fn json_omits_zero_counters() {
        let stats = SockStats::new();
        let _ = stats.label_handle(Label::NetcheckClient); // touched but zero
        let v = stats.to_json();
        let stats_obj = v
            .as_object()
            .and_then(|o| o.get("stats"))
            .and_then(|s| s.as_object())
            .expect("stats obj");
        assert!(
            stats_obj.is_empty(),
            "zero-counter labels should be omitted, got {stats_obj:?}"
        );
    }

    #[test]
    fn cellular_flag_round_trips() {
        let stats = SockStats::new();
        assert!(!stats.current_interface_cellular());
        stats.set_current_interface_cellular(true);
        assert!(stats.current_interface_cellular());
        let v = stats.to_json();
        assert_eq!(
            v.as_object()
                .and_then(|o| o.get("current_interface_cellular")),
            Some(&serde_json::Value::Bool(true))
        );
    }

    #[test]
    fn clone_shares_registry() {
        let stats = SockStats::new();
        let stats2 = stats.clone();
        let h = stats2.label_handle(Label::PortmapperClient);
        h.record_tx(42);
        let snap = stats.snapshot();
        assert_eq!(
            snap.get(&Label::PortmapperClient)
                .copied()
                .unwrap_or_default()
                .tx_bytes,
            42
        );
    }

    #[tokio::test]
    async fn counted_stream_counts_reads_and_writes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut client, server) = tokio::io::duplex(64);

        let tx_stats = SockStats::new();
        let rx_stats = tx_stats.clone();
        let tx_h = tx_stats.label_handle(Label::DNSForwarderTCP);
        let rx_h = rx_stats.label_handle(Label::DNSForwarderTCP);

        // Wrap the server side so reads count as rx on the server's handle.
        let mut counted = CountedStream::new(server, tx_h.clone(), rx_h.clone());

        client.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        counted.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        // The rx handle saw 5 bytes read.
        assert_eq!(rx_h.counters().rx_bytes, 5);

        // Now write back through the counted stream.
        counted.write_all(b"world").await.unwrap();
        let mut rbuf = [0u8; 5];
        client.read_exact(&mut rbuf).await.unwrap();
        assert_eq!(&rbuf, b"world");
        assert!(tx_h.counters().tx_bytes >= 5);
    }
}
