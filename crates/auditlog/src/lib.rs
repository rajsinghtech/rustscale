//! Persistent, retried delivery of client audit events to the control plane.
//!
//! This ports Go's `ipn/auditlog`: events are written before delivery, kept
//! across restarts, and removed only after successful or permanent delivery.

use std::collections::HashSet;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rand::RngCore;
use rustscale_ipn::store::Store;
use rustscale_tailcfg::{AuditLogRequest, ClientAuditAction};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const STORE_KEY_PREFIX: &str = "auditlog-";
const BACKOFF_MIN: Duration = Duration::from_millis(500);
const BACKOFF_MAX: Duration = Duration::from_secs(10);

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_epoch_time(v: &DateTime<Utc>) -> bool {
    *v == DateTime::UNIX_EPOCH
}

/// An audit event awaiting delivery. `EventID` and `Retries` are local-only.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Transaction {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub EventID: String,
    #[serde(default, skip_serializing_if = "is_zero_usize")]
    pub Retries: usize,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub Action: ClientAuditAction,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub Details: String,
    #[serde(default, skip_serializing_if = "is_epoch_time")]
    pub TimeStamp: DateTime<Utc>,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero_usize(v: &usize) -> bool {
    *v == 0
}

/// Persistent storage for a profile's audit transactions.
pub struct LogStore {
    store: Arc<dyn Store>,
}

impl LogStore {
    /// Create a log store backed by an IPN state store.
    pub fn new(store: Arc<dyn Store>) -> Self {
        Self { store }
    }

    fn key(profile_id: &str) -> Result<String, LoggerError> {
        if profile_id.is_empty() {
            return Err(LoggerError::NoProfileId);
        }
        Ok(format!("{STORE_KEY_PREFIX}{profile_id}"))
    }

    /// Save all pending transactions for `profile_id`.
    pub fn save(&self, profile_id: &str, txns: &[Transaction]) -> Result<(), LoggerError> {
        let data = serde_json::to_vec(txns)?;
        self.store.write_state(&Self::key(profile_id)?, &data)?;
        Ok(())
    }

    /// Load pending transactions for `profile_id`. A missing key is empty.
    pub fn load(&self, profile_id: &str) -> Result<Vec<Transaction>, LoggerError> {
        let Some(data) = self.store.read_state(&Self::key(profile_id)?)? else {
            return Ok(Vec::new());
        };
        Ok(serde_json::from_slice(&data)?)
    }
}

/// Error while persisting or operating the audit log.
#[derive(Debug, thiserror::Error)]
pub enum LoggerError {
    #[error("audit log storage failure: {0}")]
    Storage(#[from] io::Error),
    #[error("audit log JSON failure: {0}")]
    Json(#[from] serde_json::Error),
    #[error("profile ID must be set before enqueueing")]
    NoProfileId,
    #[error("profile ID cannot be changed once set")]
    ProfileIdChanged,
    #[error("audit logger already started")]
    AlreadyStarted,
    #[error("audit logger has no transport")]
    NoTransport,
}

/// A transport delivery failure and its retry classification.
#[derive(Clone, Debug, thiserror::Error)]
#[error("{message}")]
pub struct TransportError {
    message: String,
    /// Whether this failure is transient and should be retried.
    pub retryable: bool,
}

impl TransportError {
    pub fn new(message: impl Into<String>, retryable: bool) -> Self {
        Self {
            message: message.into(),
            retryable,
        }
    }
}

/// Sends audit events to their destination.
#[async_trait]
pub trait Transport: Send + Sync {
    async fn send_audit_log(&self, req: &AuditLogRequest) -> Result<(), TransportError>;
}

/// Configuration for [`Logger`].
pub struct LoggerOptions {
    /// Maximum delivery attempts for one transaction. A retryable failure is
    /// retained only while `retries + 1 < retry_limit`, exactly as in Go.
    pub retry_limit: usize,
    pub store: Arc<LogStore>,
}

struct LoggerState {
    profile_id: String,
    transport: Option<Arc<dyn Transport>>,
}

/// A persistent queue of audit transactions for one profile/control client.
pub struct Logger {
    retry_limit: usize,
    store: Arc<LogStore>,
    state: Mutex<LoggerState>,
    store_lock: Mutex<()>,
    flusher: mpsc::Sender<()>,
    receiver: Mutex<Option<mpsc::Receiver<()>>>,
    cancel: CancellationToken,
    worker: tokio::sync::Mutex<Option<JoinHandle<()>>>,
}

impl Logger {
    /// Construct a logger. Call [`set_profile_id`](Self::set_profile_id) and
    /// [`start`](Self::start) before normal delivery begins.
    pub fn new(options: LoggerOptions) -> Arc<Self> {
        let (flusher, receiver) = mpsc::channel(1);
        Arc::new(Self {
            retry_limit: options.retry_limit,
            store: options.store,
            state: Mutex::new(LoggerState {
                profile_id: String::new(),
                transport: None,
            }),
            store_lock: Mutex::new(()),
            flusher,
            receiver: Mutex::new(Some(receiver)),
            cancel: CancellationToken::new(),
            worker: tokio::sync::Mutex::new(None),
        })
    }

    /// Set the owning profile. Repeating the same profile ID is allowed.
    pub fn set_profile_id(&self, profile_id: impl AsRef<str>) -> Result<(), LoggerError> {
        let profile_id = profile_id.as_ref();
        let mut state = self.state.lock().expect("audit logger mutex poisoned");
        if !state.profile_id.is_empty() && state.profile_id != profile_id {
            return Err(LoggerError::ProfileIdChanged);
        }
        state.profile_id = profile_id.to_string();
        Ok(())
    }

    /// Start the asynchronous flush worker and immediately restore any queued
    /// transactions from the store.
    pub async fn start(self: &Arc<Self>, transport: Arc<dyn Transport>) -> Result<(), LoggerError> {
        {
            let mut state = self.state.lock().expect("audit logger mutex poisoned");
            if state.transport.is_some() {
                return Err(LoggerError::AlreadyStarted);
            }
            state.transport = Some(transport);
        }

        let receiver = self
            .receiver
            .lock()
            .expect("audit logger receiver mutex poisoned")
            .take()
            .expect("audit logger worker receiver missing");
        let pending = self.load_pending()?.len();
        let logger = Arc::clone(self);
        *self.worker.lock().await = Some(tokio::spawn(async move {
            logger.flush_worker(receiver).await;
        }));
        if pending != 0 {
            self.flush_async();
        }
        Ok(())
    }

    /// Queue an event, writing it to the store before returning.
    pub fn enqueue(
        &self,
        action: impl Into<ClientAuditAction>,
        details: impl Into<String>,
    ) -> Result<(), LoggerError> {
        let timestamp = Utc::now();
        let mut random = [0_u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let transaction = Transaction {
            EventID: format!("{timestamp}{}", hex::encode(random)),
            Retries: 0,
            Action: action.into(),
            Details: details.into(),
            TimeStamp: timestamp,
        };
        self.enqueue_transaction(transaction)
    }

    fn enqueue_transaction(&self, transaction: Transaction) -> Result<(), LoggerError> {
        self.append_to_store(&[transaction])?;
        if self
            .state
            .lock()
            .expect("audit logger mutex poisoned")
            .transport
            .is_some()
        {
            self.flush_async();
        }
        Ok(())
    }

    /// Request worker cancellation without relinquishing join ownership.
    pub fn request_stop(&self) {
        self.cancel.cancel();
    }

    /// Cancel the worker and make one bounded final flush attempt. Any events
    /// left unsent remain in the store.
    pub async fn flush_and_stop(&self, timeout: Duration) {
        self.request_stop();
        let mut worker_guard = self.worker.lock().await;
        if let Some(worker) = worker_guard.as_mut() {
            // Retain join ownership until the await completes. Cancellation
            // of this shutdown future leaves the same worker available for a
            // later retry instead of detaching it.
            let _ = (&mut *worker).await;
            worker_guard.take();
        }
        drop(worker_guard);
        let _ = tokio::time::timeout(timeout, self.flush_once(None)).await;
    }

    fn flush_async(&self) {
        let _ = self.flusher.try_send(());
    }

    async fn flush_worker(self: Arc<Self>, mut receiver: mpsc::Receiver<()>) {
        let mut retry_delay = None;
        loop {
            let should_flush = if let Some(delay) = retry_delay {
                tokio::select! {
                    () = self.cancel.cancelled() => return,
                    message = receiver.recv() => message.is_some(),
                    () = tokio::time::sleep(delay) => true,
                }
            } else {
                tokio::select! {
                    () = self.cancel.cancelled() => return,
                    message = receiver.recv() => message.is_some(),
                }
            };
            if !should_flush {
                return;
            }

            match self.flush_once(Some(&self.cancel)).await {
                Ok(true) => retry_delay = None,
                Ok(false) | Err(_) => {
                    retry_delay = Some(match retry_delay {
                        None => BACKOFF_MIN,
                        Some(delay) => (delay.saturating_mul(2)).min(BACKOFF_MAX),
                    });
                }
            }
        }
    }

    /// Returns whether every stored event was completed.
    async fn flush_once(&self, cancel: Option<&CancellationToken>) -> Result<bool, LoggerError> {
        let pending = self.load_pending()?;
        if pending.is_empty() {
            return Ok(true);
        }
        let transport = self
            .state
            .lock()
            .expect("audit logger mutex poisoned")
            .transport
            .clone()
            .ok_or(LoggerError::NoTransport)?;

        let mut complete = Vec::new();
        let mut unsent = Vec::new();
        for (index, mut transaction) in pending.iter().cloned().enumerate() {
            let request = AuditLogRequest {
                Action: transaction.Action.clone(),
                Details: transaction.Details.clone(),
                Timestamp: transaction.TimeStamp,
                ..Default::default()
            };
            let result = if let Some(cancel) = cancel {
                tokio::select! {
                    () = cancel.cancelled() => {
                        unsent.extend_from_slice(&pending[index..]);
                        break;
                    }
                    result = transport.send_audit_log(&request) => result,
                }
            } else {
                transport.send_audit_log(&request).await
            };

            match result {
                Ok(()) => complete.push(transaction),
                Err(error) if error.retryable && transaction.Retries + 1 < self.retry_limit => {
                    transaction.Retries += 1;
                    unsent.push(transaction);
                }
                Err(error) => {
                    eprintln!("auditlog: failed permanently: {error}");
                    complete.push(transaction);
                }
            }
        }

        self.mark_transactions_done(&complete)?;
        self.append_to_store(&unsent)?;
        Ok(unsent.is_empty())
    }

    fn profile_id(&self) -> String {
        self.state
            .lock()
            .expect("audit logger mutex poisoned")
            .profile_id
            .clone()
    }

    fn load_pending(&self) -> Result<Vec<Transaction>, LoggerError> {
        let _lock = self
            .store_lock
            .lock()
            .expect("audit logger store mutex poisoned");
        self.store.load(&self.profile_id())
    }

    fn append_to_store(&self, transactions: &[Transaction]) -> Result<(), LoggerError> {
        if transactions.is_empty() {
            return Ok(());
        }
        let _lock = self
            .store_lock
            .lock()
            .expect("audit logger store mutex poisoned");
        let profile_id = self.profile_id();
        let mut persisted = self.store.load(&profile_id)?;
        let mut merged = transactions.to_vec();
        merged.append(&mut persisted);
        self.store.save(&profile_id, &deduplicate_and_sort(merged))
    }

    fn mark_transactions_done(&self, complete: &[Transaction]) -> Result<(), LoggerError> {
        if complete.is_empty() {
            return Ok(());
        }
        let _lock = self
            .store_lock
            .lock()
            .expect("audit logger store mutex poisoned");
        let ids: HashSet<&str> = complete
            .iter()
            .map(|transaction| transaction.EventID.as_str())
            .collect();
        let profile_id = self.profile_id();
        let pending = self.store.load(&profile_id)?;
        let unsent: Vec<_> = pending
            .into_iter()
            .filter(|transaction| !ids.contains(transaction.EventID.as_str()))
            .collect();
        self.store.save(&profile_id, &unsent)
    }
}

fn deduplicate_and_sort(transactions: Vec<Transaction>) -> Vec<Transaction> {
    let mut seen = HashSet::new();
    let mut deduped: Vec<_> = transactions
        .into_iter()
        .filter(|transaction| seen.insert(transaction.EventID.clone()))
        .collect();
    deduped.sort_by_key(|transaction| transaction.TimeStamp);
    deduped
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use chrono::{Duration as ChronoDuration, Utc};
    use rustscale_ipn::store::{MemStore, Store};
    use rustscale_tailcfg::AUDIT_NODE_DISCONNECT;
    use tokio::sync::Notify;

    use super::*;

    struct MockTransport {
        outcomes: Mutex<VecDeque<Result<(), TransportError>>>,
        fallback: Result<(), TransportError>,
        sent: Mutex<Vec<AuditLogRequest>>,
        sent_notify: Notify,
    }

    impl MockTransport {
        fn scripted(outcomes: impl IntoIterator<Item = Result<(), TransportError>>) -> Self {
            Self {
                outcomes: Mutex::new(outcomes.into_iter().collect()),
                fallback: Ok(()),
                sent: Mutex::new(Vec::new()),
                sent_notify: Notify::new(),
            }
        }

        fn always_fails(error: TransportError) -> Self {
            Self {
                outcomes: Mutex::new(VecDeque::new()),
                fallback: Err(error),
                sent: Mutex::new(Vec::new()),
                sent_notify: Notify::new(),
            }
        }

        fn sent_count(&self) -> usize {
            self.sent.lock().unwrap().len()
        }
    }

    #[async_trait]
    impl Transport for MockTransport {
        async fn send_audit_log(&self, req: &AuditLogRequest) -> Result<(), TransportError> {
            self.sent.lock().unwrap().push(req.clone());
            self.sent_notify.notify_waiters();
            self.outcomes
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| self.fallback.clone())
        }
    }

    fn logger(store: Arc<dyn Store>, retry_limit: usize) -> (Arc<Logger>, Arc<LogStore>) {
        let log_store = Arc::new(LogStore::new(store));
        let logger = Logger::new(LoggerOptions {
            retry_limit,
            store: log_store.clone(),
        });
        logger.set_profile_id("profile").unwrap();
        (logger, log_store)
    }

    #[test]
    fn store_roundtrip_uses_profile_key() {
        let store: Arc<dyn Store> = Arc::new(MemStore::new());
        let log_store = LogStore::new(store.clone());
        let transaction = Transaction {
            EventID: "event".into(),
            Action: AUDIT_NODE_DISCONNECT.into(),
            Details: "cli".into(),
            TimeStamp: Utc::now(),
            ..Default::default()
        };
        log_store.save("alice", &[transaction.clone()]).unwrap();

        assert_eq!(log_store.load("alice").unwrap(), vec![transaction]);
        assert!(store.read_state("auditlog-alice").unwrap().is_some());
        assert_eq!(
            log_store.load("missing").unwrap(),
            Vec::<Transaction>::new()
        );
    }

    #[test]
    fn deduplicates_newest_transaction_before_sorting() {
        let store: Arc<dyn Store> = Arc::new(MemStore::new());
        let (logger, log_store) = logger(store, 3);
        let timestamp = Utc::now() - ChronoDuration::minutes(1);
        logger
            .enqueue_transaction(Transaction {
                EventID: "same".into(),
                Retries: 1,
                TimeStamp: timestamp,
                ..Default::default()
            })
            .unwrap();
        logger
            .enqueue_transaction(Transaction {
                EventID: "same".into(),
                Retries: 2,
                TimeStamp: timestamp,
                ..Default::default()
            })
            .unwrap();

        let pending = log_store.load("profile").unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].Retries, 2);
    }

    #[tokio::test]
    async fn enqueue_persists() {
        let store: Arc<dyn Store> = Arc::new(MemStore::new());
        let (logger, log_store) = logger(store, 3);
        logger.enqueue(AUDIT_NODE_DISCONNECT, "cli").unwrap();
        assert_eq!(log_store.load("profile").unwrap().len(), 1);
    }

    #[tokio::test]
    async fn retry_limit_exhaustion_completes() {
        let store: Arc<dyn Store> = Arc::new(MemStore::new());
        let (logger, log_store) = logger(store, 1);
        let transport = Arc::new(MockTransport::scripted([Err(TransportError::new(
            "temporary",
            true,
        ))]));
        logger.start(transport.clone()).await.unwrap();
        logger.enqueue(AUDIT_NODE_DISCONNECT, "cli").unwrap();
        logger.flush_and_stop(Duration::from_secs(1)).await;

        assert_eq!(transport.sent_count(), 1);
        assert!(log_store.load("profile").unwrap().is_empty());
    }

    #[tokio::test]
    async fn shutdown_cancellation_retains_worker_for_retry() {
        let store: Arc<dyn Store> = Arc::new(MemStore::new());
        let (logger, log_store) = logger(store, 3);
        let transport = Arc::new(MockTransport::scripted([]));
        logger.start(transport.clone()).await.unwrap();
        logger.enqueue(AUDIT_NODE_DISCONNECT, "cli").unwrap();

        // Cancel after flush_and_stop has retained and started awaiting the
        // worker. The worker cannot run during this poll, making cancellation
        // at the join deterministic.
        {
            let mut shutdown = Box::pin(logger.flush_and_stop(Duration::from_secs(1)));
            tokio::select! {
                biased;
                () = &mut shutdown => panic!("shutdown completed before cancellation"),
                () = std::future::ready(()) => {}
            }
        }

        logger.flush_and_stop(Duration::from_secs(1)).await;
        assert_eq!(transport.sent_count(), 1);
        assert!(log_store.load("profile").unwrap().is_empty());
    }

    #[tokio::test]
    async fn restore_on_start_flushes() {
        let store: Arc<dyn Store> = Arc::new(MemStore::new());
        let (logger, log_store) = logger(store, 3);
        log_store
            .save(
                "profile",
                &[Transaction {
                    EventID: "restored".into(),
                    Action: AUDIT_NODE_DISCONNECT.into(),
                    Details: "cli".into(),
                    TimeStamp: Utc::now(),
                    ..Default::default()
                }],
            )
            .unwrap();
        let transport = Arc::new(MockTransport::scripted([]));
        logger.start(transport.clone()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), transport.sent_notify.notified())
            .await
            .unwrap();
        logger.flush_and_stop(Duration::from_secs(1)).await;

        assert_eq!(transport.sent_count(), 1);
        assert!(log_store.load("profile").unwrap().is_empty());
    }

    #[test]
    fn profile_id_change_is_rejected() {
        let store: Arc<dyn Store> = Arc::new(MemStore::new());
        let (logger, _) = logger(store, 3);
        assert!(logger.set_profile_id("profile").is_ok());
        assert!(matches!(
            logger.set_profile_id("other"),
            Err(LoggerError::ProfileIdChanged)
        ));
    }

    #[tokio::test]
    async fn stop_persists_unsent() {
        let store: Arc<dyn Store> = Arc::new(MemStore::new());
        let (logger, log_store) = logger(store, 3);
        let transport = Arc::new(MockTransport::always_fails(TransportError::new(
            "temporary",
            true,
        )));
        logger.start(transport).await.unwrap();
        logger.enqueue(AUDIT_NODE_DISCONNECT, "cli").unwrap();
        logger.flush_and_stop(Duration::from_secs(1)).await;

        let pending = log_store.load("profile").unwrap();
        assert_eq!(pending.len(), 1);
        assert!(pending[0].Retries >= 1);
    }
}
