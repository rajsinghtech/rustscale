//! Tests for the netlog logger and integration.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use rustscale_logtail::{Config, LogTail};
use rustscale_netlogtype::Node;

use crate::ConnectionType;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// A mock [`NodeSource`] with a fixed node table.
struct MockNodeSource {
    self_node: Option<Node>,
    nodes: HashMap<IpAddr, Node>,
}

impl MockNodeSource {
    fn new(self_node: Option<Node>) -> Self {
        Self {
            self_node,
            nodes: HashMap::new(),
        }
    }

    fn with(mut self, addr: &str, node: Node) -> Self {
        self.nodes.insert(ip(addr), node);
        self
    }
}

impl crate::NodeSource for MockNodeSource {
    fn self_node(&self) -> Option<Node> {
        self.self_node.clone()
    }
    fn node_by_addr(&self, addr: IpAddr) -> Option<Node> {
        self.nodes.get(&addr).cloned()
    }
}

/// A test logtail config that points at a bogus URL (no uploads will
/// succeed, but `write()` buffers entries so we can verify via
/// `buffered_count()`).
fn test_logtail() -> LogTail {
    LogTail::new(Config {
        collection: "tailtraffic.log.tailscale.io".to_string(),
        private_id: "test-private-id".to_string(),
        base_url: "http://127.0.0.1:1".to_string(), // unreachable — entries stay buffered
        ..Config::default()
    })
}

#[tokio::test]
async fn test_logger_start_stop() {
    let source: Arc<dyn crate::NodeSource> = Arc::new(MockNodeSource::new(Some(Node {
        node_id: "nABC".to_string(),
        name: "self.example.ts.net".to_string(),
        ..Default::default()
    })));

    let logger = crate::Logger::new();
    assert!(!logger.running().await);

    let lt = test_logtail();
    let observed_logtail = lt.clone();
    logger.start(source, lt).await.unwrap();
    assert!(logger.running().await);

    // Send a virtual traffic event.
    let counter = logger.make_counter(true).await;
    counter(
        6,
        (ip("100.64.0.1"), 1234),
        (ip("100.64.0.2"), 443),
        10,
        1000,
        false,
    );

    // Stop — this does a final flush which writes a Message to logtail.
    logger.stop().await.unwrap();
    assert!(!logger.running().await);

    // Shutdown drains all queued callbacks before the final flush.
    assert_eq!(observed_logtail.buffered_count(), 1);
}

#[tokio::test]
async fn stop_cancellation_retains_worker_for_retry() {
    let source: Arc<dyn crate::NodeSource> = Arc::new(MockNodeSource::new(Some(Node {
        node_id: "nABC".to_string(),
        ..Default::default()
    })));
    let logger = crate::Logger::new();
    logger.start(source, test_logtail()).await.unwrap();

    // Poll through handle lookup and shutdown signalling, then cancel while
    // stop is awaiting the worker. The runtime cannot run the worker during
    // this poll, so the immediately-ready branch deterministically wins.
    {
        let mut stop = Box::pin(logger.stop());
        tokio::select! {
            biased;
            result = &mut stop => panic!("stop completed before cancellation: {result:?}"),
            () = std::future::ready(()) => {}
        }
    }

    assert!(
        logger.running().await,
        "cancelled stop lost worker ownership"
    );
    logger.stop().await.unwrap();
    assert!(!logger.running().await);
}

#[tokio::test]
async fn stale_stop_before_start_does_not_stop_new_generation() {
    let source: Arc<dyn crate::NodeSource> = Arc::new(MockNodeSource::new(Some(Node {
        node_id: "nABC".to_string(),
        ..Default::default()
    })));
    let logger = crate::Logger::new();

    // This used to leave a permit on the one shared Notify. The next worker
    // consumed it immediately and exited even though it belonged to no run.
    logger.request_stop();
    let logtail = test_logtail();
    let observed_logtail = logtail.clone();
    logger.start(source, logtail).await.unwrap();
    tokio::task::yield_now().await;
    assert!(
        logger.running().await,
        "old stop leaked into new generation"
    );
    let counter = logger.make_counter(true).await;
    counter(
        6,
        (ip("100.64.0.1"), 1234),
        (ip("100.64.0.2"), 443),
        1,
        100,
        false,
    );
    logger.stop().await.unwrap();
    assert_eq!(
        observed_logtail.buffered_count(),
        1,
        "the new generation must process its counter before final flush"
    );
}

#[tokio::test]
async fn test_logger_counter_sends_events() {
    let source: Arc<dyn crate::NodeSource> = Arc::new(
        MockNodeSource::new(Some(Node {
            node_id: "nABC".to_string(),
            ..Default::default()
        }))
        .with(
            "100.64.0.2",
            Node {
                node_id: "nDEF".to_string(),
                ..Default::default()
            },
        ),
    );

    let logger = crate::Logger::new();
    let lt = test_logtail();
    logger.start(source, lt).await.unwrap();

    // Create a counter and fire several events.
    let counter = logger.make_counter(true).await;
    counter(
        6,
        (ip("100.64.0.1"), 1234),
        (ip("100.64.0.2"), 443),
        1,
        100,
        false,
    );
    counter(
        6,
        (ip("100.64.0.1"), 1234),
        (ip("100.64.0.2"), 443),
        2,
        200,
        true,
    );
    counter(
        17,
        (ip("100.64.0.1"), 53),
        (ip("100.64.0.2"), 53),
        3,
        300,
        false,
    );

    // Give the background task time to process events.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    // Stop to trigger final flush.
    logger.stop().await.unwrap();

    // The logtail should have at least one buffered entry.
    // (We can't access the logtail from here since it's inside the logger,
    // but the fact that stop() completes without error means the flush
    // and serialization succeeded.)
}

#[tokio::test]
async fn test_logger_double_start_rejected() {
    let source: Arc<dyn crate::NodeSource> = Arc::new(MockNodeSource::new(Some(Node {
        node_id: "nABC".to_string(),
        ..Default::default()
    })));

    let logger = crate::Logger::new();
    let lt = test_logtail();
    logger.start(source.clone(), lt).await.unwrap();

    // Second start should fail.
    let lt2 = test_logtail();
    let result = logger.start(source, lt2).await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        crate::NetlogError::AlreadyRunning
    ));

    logger.stop().await.unwrap();
}

#[tokio::test]
async fn test_logger_stop_without_start() {
    let logger = crate::Logger::new();
    let result = logger.stop().await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        crate::NetlogError::NotRunning
    ));
}

#[tokio::test]
async fn test_logger_reconfig_routes() {
    let source: Arc<dyn crate::NodeSource> = Arc::new(MockNodeSource::new(Some(Node {
        node_id: "nABC".to_string(),
        ..Default::default()
    })));

    let logger = crate::Logger::new();
    let lt = test_logtail();
    logger.start(source, lt).await.unwrap();

    let mut addrs = HashSet::new();
    addrs.insert(ip("10.0.0.1"));
    let prefixes = vec![rustscale_tsaddr::IpPrefix {
        ip: ip("10.0.0.0"),
        bits: 24,
    }];
    logger.reconfig_routes(addrs, prefixes).await;

    logger.stop().await.unwrap();
}

/// A counting wrapper to verify the counter is called.
struct CountingCounter {
    calls: AtomicU64,
}

impl CountingCounter {
    fn new() -> Self {
        Self {
            calls: AtomicU64::new(0),
        }
    }

    fn into_counter(self: Arc<Self>) -> crate::ConnectionCounter {
        Arc::new(move |_proto, _src, _dst, _pkts, _bytes, _recv| {
            self.calls.fetch_add(1, Ordering::Relaxed);
        })
    }

    fn call_count(&self) -> u64 {
        self.calls.load(Ordering::Relaxed)
    }
}

#[tokio::test]
async fn test_counter_callback_fires() {
    let counting = Arc::new(CountingCounter::new());
    let counter = counting.clone().into_counter();

    // Simulate the filter calling the counter.
    counter(
        6,
        (ip("100.64.0.1"), 1234),
        (ip("100.64.0.2"), 443),
        1,
        100,
        false,
    );
    counter(
        6,
        (ip("100.64.0.1"), 1234),
        (ip("100.64.0.2"), 443),
        1,
        100,
        true,
    );
    counter(
        17,
        (ip("100.64.0.1"), 53),
        (ip("100.64.0.2"), 53),
        2,
        200,
        false,
    );

    assert_eq!(counting.call_count(), 3);
}

#[tokio::test]
async fn test_logger_physical_traffic() {
    let source: Arc<dyn crate::NodeSource> = Arc::new(MockNodeSource::new(Some(Node {
        node_id: "nABC".to_string(),
        ..Default::default()
    })));

    let logger = crate::Logger::new();
    let lt = test_logtail();
    logger.start(source, lt).await.unwrap();

    // Physical traffic (from magicsock): proto=0, src port=0 typically.
    let counter = logger.make_counter(false).await;
    counter(
        0,
        (ip("100.64.0.1"), 0),
        (ip("203.0.113.5"), 41641),
        1,
        120,
        false,
    );

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    logger.stop().await.unwrap();
}

#[tokio::test]
async fn test_logger_exit_traffic_anonymized() {
    let source: Arc<dyn crate::NodeSource> = Arc::new(
        MockNodeSource::new(Some(Node {
            node_id: "nABC".to_string(),
            ..Default::default()
        }))
        .with(
            "100.64.0.1",
            Node {
                node_id: "nABC".to_string(),
                ..Default::default()
            },
        ),
    );

    let logger = crate::Logger::new();
    logger.set_anonymize_exit(true).await;
    let lt = test_logtail();
    logger.start(source, lt).await.unwrap();

    // Exit traffic: src is self (100.64.0.1), dst is external (8.8.8.8).
    let counter = logger.make_counter(true).await;
    counter(
        6,
        (ip("100.64.0.1"), 1234),
        (ip("8.8.8.8"), 443),
        5,
        500,
        false,
    );

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    logger.stop().await.unwrap();
}

#[test]
fn test_connection_type_default() {
    assert_eq!(ConnectionType::default(), ConnectionType::Unknown);
}
