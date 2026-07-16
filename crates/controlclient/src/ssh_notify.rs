//! Generation-bound SSH recording-failure callbacks over the current map Noise session.
//!
//! Policy URLs contribute only a normalized path and query. Scheme and
//! authority are parsed and discarded, matching the upstream Noise transport:
//! no callback can select a network destination. Admission is fair per source
//! principal, bounded per control generation, and contains no control keys.

use rustscale_key::NodePublic;
use rustscale_tailcfg::{NodeID, SSHEventNotifyRequest};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::task::JoinSet;

const MAX_NOTIFY_URL_BYTES: usize = 2 * 1024;
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_BYTES: usize = 4 * 1024;
const GENERATION_QUEUE_CAPACITY: usize = 64;
const PRINCIPAL_QUEUE_CAPACITY: usize = 8;
const GENERATION_WORKERS: usize = 2;
const GLOBAL_WORKERS: usize = 8;
const QUEUE_TTL: Duration = Duration::from_secs(10);
const DISPATCH_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_REDIRECTS: usize = 4;
const CREATED: u16 = 201;

/// A callback could not be admitted. Errors contain no URL, identity,
/// recorder, session, or credential material.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum SshNotifyEnqueueError {
    #[error("invalid control callback URL")]
    InvalidUrl,
    #[error("SSH callback request exceeds the size limit")]
    RequestTooLarge,
    #[error("no current authenticated control generation")]
    NoGeneration,
    #[error("SSH callback principal quota is full")]
    PrincipalQuota,
    #[error("SSH callback generation queue is full")]
    QueueFull,
    #[error("SSH callback control generation was revoked")]
    Revoked,
}

/// Monotonic callback counters. Queue expiry and revocation drops are kept
/// distinct from dispatch failures so terminal policy is observable.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SshNotifyMetricsSnapshot {
    pub accepted: u64,
    pub delivered: u64,
    pub invalid_url: u64,
    pub request_too_large: u64,
    pub no_generation: u64,
    pub principal_quota: u64,
    pub queue_full: u64,
    pub queue_expired: u64,
    pub revoked_admission: u64,
    pub revoked_queued: u64,
    pub revoked_in_flight: u64,
    pub transport_failed: u64,
    pub dispatch_timeout: u64,
    pub status_failed: u64,
    pub response_too_large: u64,
    pub redirect_invalid: u64,
    pub redirect_loop: u64,
    pub redirect_limit: u64,
}

#[derive(Default)]
struct SshNotifyMetrics {
    accepted: AtomicU64,
    delivered: AtomicU64,
    invalid_url: AtomicU64,
    request_too_large: AtomicU64,
    no_generation: AtomicU64,
    principal_quota: AtomicU64,
    queue_full: AtomicU64,
    queue_expired: AtomicU64,
    revoked_admission: AtomicU64,
    revoked_queued: AtomicU64,
    revoked_in_flight: AtomicU64,
    transport_failed: AtomicU64,
    dispatch_timeout: AtomicU64,
    status_failed: AtomicU64,
    response_too_large: AtomicU64,
    redirect_invalid: AtomicU64,
    redirect_loop: AtomicU64,
    redirect_limit: AtomicU64,
}

impl SshNotifyMetrics {
    fn snapshot(&self) -> SshNotifyMetricsSnapshot {
        macro_rules! load {
            ($field:ident) => {
                self.$field.load(Ordering::Relaxed)
            };
        }
        SshNotifyMetricsSnapshot {
            accepted: load!(accepted),
            delivered: load!(delivered),
            invalid_url: load!(invalid_url),
            request_too_large: load!(request_too_large),
            no_generation: load!(no_generation),
            principal_quota: load!(principal_quota),
            queue_full: load!(queue_full),
            queue_expired: load!(queue_expired),
            revoked_admission: load!(revoked_admission),
            revoked_queued: load!(revoked_queued),
            revoked_in_flight: load!(revoked_in_flight),
            transport_failed: load!(transport_failed),
            dispatch_timeout: load!(dispatch_timeout),
            status_failed: load!(status_failed),
            response_too_large: load!(response_too_large),
            redirect_invalid: load!(redirect_invalid),
            redirect_loop: load!(redirect_loop),
            redirect_limit: load!(redirect_limit),
        }
    }
}

/// Profile-owned callback admission point. It never contains control keys or
/// opens a connection; the current map generation supplies the only sender.
#[derive(Clone, Default)]
pub struct SshCallbackDispatcher {
    inner: Arc<DispatcherInner>,
}

#[derive(Default)]
struct DispatcherInner {
    next_generation: AtomicU64,
    current: Mutex<Option<Arc<Generation>>>,
    metrics: Arc<SshNotifyMetrics>,
}

impl std::fmt::Debug for SshCallbackDispatcher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SshCallbackDispatcher")
            .field("generation", &"<opaque>")
            .finish()
    }
}

impl SshCallbackDispatcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn notifier(&self) -> SshEventNotifier {
        SshEventNotifier {
            dispatcher: self.clone(),
        }
    }

    pub fn metrics(&self) -> SshNotifyMetricsSnapshot {
        self.inner.metrics.snapshot()
    }

    /// Revoke and synchronously drain admission for the current generation.
    /// The map task still owns and tears down the corresponding Noise session.
    pub fn revoke_current(&self) {
        let generation = self
            .inner
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(generation) = generation {
            generation.revoke();
        }
    }

    pub(crate) fn activate(&self, node_key: NodePublic) -> GenerationLease {
        let token = self
            .inner
            .next_generation
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        let generation = Arc::new(Generation::new(
            token,
            node_key,
            Arc::clone(&self.inner.metrics),
        ));
        let previous = self
            .inner
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .replace(Arc::clone(&generation));
        if let Some(previous) = previous {
            previous.revoke();
        }
        GenerationLease {
            dispatcher: self.clone(),
            generation,
        }
    }

    fn deactivate(&self, token: u64) {
        let generation = {
            let mut current = self
                .inner
                .current
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if current
                .as_ref()
                .is_some_and(|current| current.token == token)
            {
                current.take()
            } else {
                None
            }
        };
        if let Some(generation) = generation {
            generation.revoke();
        }
    }

    fn enqueue_request(
        &self,
        path: String,
        request: &SSHEventNotifyRequest,
    ) -> Result<(), SshNotifyEnqueueError> {
        let generation = self
            .inner
            .current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let Some(generation) = generation else {
            self.inner
                .metrics
                .no_generation
                .fetch_add(1, Ordering::Relaxed);
            return Err(SshNotifyEnqueueError::NoGeneration);
        };
        let mut request = request.clone();
        request.NodeKey.clone_from(&generation.node_key);
        let payload = serde_json::to_vec(&request).map_err(|_| {
            self.inner
                .metrics
                .request_too_large
                .fetch_add(1, Ordering::Relaxed);
            SshNotifyEnqueueError::RequestTooLarge
        })?;
        if payload.len() > MAX_REQUEST_BYTES {
            self.inner
                .metrics
                .request_too_large
                .fetch_add(1, Ordering::Relaxed);
            return Err(SshNotifyEnqueueError::RequestTooLarge);
        }
        generation.enqueue(path, payload, request.SrcNode)
    }
}

/// Non-blocking SSH-side producer. Queued jobs contain only a nonsecret
/// generation token, normalized path, wire payload, and fairness principal.
#[derive(Clone, Debug)]
pub struct SshEventNotifier {
    dispatcher: SshCallbackDispatcher,
}

impl SshEventNotifier {
    pub fn enqueue(
        &self,
        notify_url: &str,
        request: &SSHEventNotifyRequest,
    ) -> Result<(), SshNotifyEnqueueError> {
        let path = match callback_path(notify_url, None) {
            Ok(path) => path,
            Err(error) => {
                self.dispatcher
                    .inner
                    .metrics
                    .invalid_url
                    .fetch_add(1, Ordering::Relaxed);
                return Err(error);
            }
        };
        self.dispatcher.enqueue_request(path, request)
    }
}

struct NotifyJob {
    generation: u64,
    principal: NodeID,
    path: String,
    payload: Vec<u8>,
    enqueued: Instant,
}

struct FairQueue {
    total: usize,
    order: VecDeque<NodeID>,
    principals: HashMap<NodeID, VecDeque<NotifyJob>>,
}

impl FairQueue {
    fn new() -> Self {
        Self {
            total: 0,
            order: VecDeque::new(),
            principals: HashMap::new(),
        }
    }

    fn push(&mut self, job: NotifyJob) -> Result<(), SshNotifyEnqueueError> {
        // Check without inserting first: rejected source IDs must not grow the
        // principal map while this generation is at either quota.
        if self
            .principals
            .get(&job.principal)
            .is_some_and(|queue| queue.len() >= PRINCIPAL_QUEUE_CAPACITY)
        {
            return Err(SshNotifyEnqueueError::PrincipalQuota);
        }
        if self.total >= GENERATION_QUEUE_CAPACITY {
            return Err(SshNotifyEnqueueError::QueueFull);
        }
        let queue = self.principals.entry(job.principal).or_default();
        if queue.is_empty() {
            self.order.push_back(job.principal);
        }
        queue.push_back(job);
        self.total += 1;
        Ok(())
    }

    fn expire(&mut self, now: Instant, metrics: &SshNotifyMetrics) {
        let mut expired = 0u64;
        self.principals.retain(|_, queue| {
            let before = queue.len();
            queue.retain(|job| now.saturating_duration_since(job.enqueued) <= QUEUE_TTL);
            expired += (before - queue.len()) as u64;
            !queue.is_empty()
        });
        self.order
            .retain(|principal| self.principals.contains_key(principal));
        self.total = self.principals.values().map(VecDeque::len).sum();
        metrics.queue_expired.fetch_add(expired, Ordering::Relaxed);
    }

    fn pop(&mut self, now: Instant, metrics: &SshNotifyMetrics) -> Option<NotifyJob> {
        self.expire(now, metrics);
        while let Some(principal) = self.order.pop_front() {
            let Some(queue) = self.principals.get_mut(&principal) else {
                continue;
            };
            let job = queue
                .pop_front()
                .expect("fair queue order references a nonempty principal");
            self.total -= 1;
            if queue.is_empty() {
                self.principals.remove(&principal);
            } else {
                self.order.push_back(principal);
            }
            return Some(job);
        }
        None
    }

    fn drain_for_revocation(&mut self, now: Instant, metrics: &SshNotifyMetrics) -> usize {
        let mut revoked = 0usize;
        let mut expired = 0u64;
        for job in self.principals.values().flat_map(VecDeque::iter) {
            if now.saturating_duration_since(job.enqueued) > QUEUE_TTL {
                expired += 1;
            } else {
                revoked += 1;
            }
        }
        self.total = 0;
        self.order.clear();
        self.principals.clear();
        metrics.queue_expired.fetch_add(expired, Ordering::Relaxed);
        revoked
    }
}

struct Generation {
    token: u64,
    node_key: NodePublic,
    revoked: AtomicBool,
    queue: Mutex<FairQueue>,
    wake: tokio::sync::Notify,
    next_task: AtomicU64,
    in_flight: Mutex<HashMap<u64, tokio::task::AbortHandle>>,
    metrics: Arc<SshNotifyMetrics>,
}

impl Generation {
    fn new(token: u64, node_key: NodePublic, metrics: Arc<SshNotifyMetrics>) -> Self {
        Self {
            token,
            node_key,
            revoked: AtomicBool::new(false),
            queue: Mutex::new(FairQueue::new()),
            wake: tokio::sync::Notify::new(),
            next_task: AtomicU64::new(0),
            in_flight: Mutex::new(HashMap::new()),
            metrics,
        }
    }

    fn enqueue(
        &self,
        path: String,
        payload: Vec<u8>,
        principal: NodeID,
    ) -> Result<(), SshNotifyEnqueueError> {
        if self.revoked.load(Ordering::Acquire) {
            self.metrics
                .revoked_admission
                .fetch_add(1, Ordering::Relaxed);
            return Err(SshNotifyEnqueueError::Revoked);
        }
        let now = Instant::now();
        let result = {
            let mut queue = self
                .queue
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // Expired residence never consumes a principal's reservation or
            // the generation quota for a fresh event.
            queue.expire(now, &self.metrics);
            queue.push(NotifyJob {
                generation: self.token,
                principal,
                path,
                payload,
                enqueued: now,
            })
        };
        match result {
            Ok(()) => {
                if self.revoked.load(Ordering::Acquire) {
                    self.metrics
                        .revoked_admission
                        .fetch_add(1, Ordering::Relaxed);
                    self.revoke();
                    return Err(SshNotifyEnqueueError::Revoked);
                }
                self.metrics.accepted.fetch_add(1, Ordering::Relaxed);
                self.wake.notify_one();
                Ok(())
            }
            Err(SshNotifyEnqueueError::PrincipalQuota) => {
                self.metrics.principal_quota.fetch_add(1, Ordering::Relaxed);
                Err(SshNotifyEnqueueError::PrincipalQuota)
            }
            Err(SshNotifyEnqueueError::QueueFull) => {
                self.metrics.queue_full.fetch_add(1, Ordering::Relaxed);
                Err(SshNotifyEnqueueError::QueueFull)
            }
            Err(error) => Err(error),
        }
    }

    fn pop(&self) -> Option<NotifyJob> {
        if self.revoked.load(Ordering::Acquire) {
            return None;
        }
        self.queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop(Instant::now(), &self.metrics)
    }

    fn revoke(&self) {
        if self.revoked.swap(true, Ordering::AcqRel) {
            return;
        }
        let dropped = self
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain_for_revocation(Instant::now(), &self.metrics);
        self.metrics
            .revoked_queued
            .fetch_add(dropped as u64, Ordering::Relaxed);
        let in_flight = self
            .in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain()
            .map(|(_, abort)| abort)
            .collect::<Vec<_>>();
        self.metrics
            .revoked_in_flight
            .fetch_add(in_flight.len() as u64, Ordering::Relaxed);
        for abort in in_flight {
            abort.abort();
        }
        self.wake.notify_waiters();
    }

    fn unregister(&self, task: u64) {
        self.in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&task);
    }
}

pub(crate) struct GenerationLease {
    dispatcher: SshCallbackDispatcher,
    generation: Arc<Generation>,
}

impl Drop for GenerationLease {
    fn drop(&mut self) {
        self.dispatcher.deactivate(self.generation.token);
        self.generation.revoke();
    }
}

struct InFlightGuard {
    generation: Arc<Generation>,
    task: u64,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.generation.unregister(self.task);
    }
}

struct GlobalWorkerBudget {
    permits: Arc<tokio::sync::Semaphore>,
    changed: tokio::sync::Notify,
}

fn global_worker_budget() -> &'static Arc<GlobalWorkerBudget> {
    static BUDGET: OnceLock<Arc<GlobalWorkerBudget>> = OnceLock::new();
    BUDGET.get_or_init(|| {
        Arc::new(GlobalWorkerBudget {
            permits: Arc::new(tokio::sync::Semaphore::new(GLOBAL_WORKERS)),
            changed: tokio::sync::Notify::new(),
        })
    })
}

struct GlobalWorkerPermit {
    budget: Arc<GlobalWorkerBudget>,
    _permit: tokio::sync::OwnedSemaphorePermit,
    notify_on_drop: bool,
}

impl Drop for GlobalWorkerPermit {
    fn drop(&mut self) {
        if self.notify_on_drop {
            self.budget.changed.notify_one();
        }
    }
}

fn try_global_worker() -> Option<GlobalWorkerPermit> {
    let budget = Arc::clone(global_worker_budget());
    let permit = Arc::clone(&budget.permits).try_acquire_owned().ok()?;
    Some(GlobalWorkerPermit {
        budget,
        _permit: permit,
        notify_on_drop: false,
    })
}

/// Runtime attached to exactly one authenticated map Noise/H2 generation.
pub(crate) struct CallbackGeneration {
    lease: GenerationLease,
    transport: Arc<H2CallbackTransport>,
    tasks: JoinSet<()>,
}

impl CallbackGeneration {
    pub(crate) fn new(
        dispatcher: SshCallbackDispatcher,
        sender: h2::client::SendRequest<bytes::Bytes>,
        node_key: NodePublic,
    ) -> Self {
        Self {
            lease: dispatcher.activate(node_key),
            transport: Arc::new(H2CallbackTransport { sender }),
            tasks: JoinSet::new(),
        }
    }

    fn dispatch_ready(&mut self) {
        while self.tasks.try_join_next().is_some() {}
        while self.tasks.len() < GENERATION_WORKERS {
            let Some(mut worker_permit) = try_global_worker() else {
                break;
            };
            let Some(job) = self.lease.generation.pop() else {
                break;
            };
            worker_permit.notify_on_drop = true;
            if job.generation != self.lease.generation.token {
                self.lease
                    .generation
                    .metrics
                    .revoked_queued
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let transport = Arc::clone(&self.transport);
            let generation = Arc::clone(&self.lease.generation);
            let metrics = Arc::clone(&generation.metrics);
            let task = generation.next_task.fetch_add(1, Ordering::Relaxed);
            let (start_tx, start_rx) = tokio::sync::oneshot::channel();
            let abort = self.tasks.spawn(async move {
                if start_rx.await.is_err() {
                    return;
                }
                let _worker_permit = worker_permit;
                let _guard = InFlightGuard { generation, task };
                let deadline = tokio::time::Instant::now() + DISPATCH_TIMEOUT;
                deliver_callback(transport.as_ref(), job, deadline, &metrics).await;
            });
            let admitted = {
                let mut in_flight = self
                    .lease
                    .generation
                    .in_flight
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if self.lease.generation.revoked.load(Ordering::Acquire) {
                    false
                } else {
                    in_flight.insert(task, abort.clone());
                    true
                }
            };
            if admitted {
                let _ = start_tx.send(());
            } else {
                self.lease
                    .generation
                    .metrics
                    .revoked_in_flight
                    .fetch_add(1, Ordering::Relaxed);
                abort.abort();
            }
        }
    }

    pub(crate) async fn recv_map_data(
        &mut self,
        body: &mut h2::RecvStream,
    ) -> Option<Result<bytes::Bytes, h2::Error>> {
        loop {
            self.dispatch_ready();
            if self.tasks.is_empty() {
                tokio::select! {
                    data = body.data() => return data,
                    () = self.lease.generation.wake.notified() => {},
                    () = global_worker_budget().changed.notified() => {}
                }
            } else if self.tasks.len() >= GENERATION_WORKERS {
                tokio::select! {
                    data = body.data() => return data,
                    _ = self.tasks.join_next() => {}
                }
            } else {
                tokio::select! {
                    data = body.data() => return data,
                    () = self.lease.generation.wake.notified() => {},
                    _ = self.tasks.join_next() => {},
                    () = global_worker_budget().changed.notified() => {}
                }
            }
        }
    }

    pub(crate) async fn shutdown(mut self) {
        self.lease.generation.revoke();
        while self.tasks.try_join_next().is_some() {}
        self.tasks.abort_all();
        while self.tasks.join_next().await.is_some() {}
    }
}

impl Drop for CallbackGeneration {
    fn drop(&mut self) {
        self.lease.generation.revoke();
        while self.tasks.try_join_next().is_some() {}
        self.tasks.abort_all();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CallbackMethod {
    Get,
    Post,
}

struct CallbackResponse {
    status: u16,
    location: Option<String>,
    body: Vec<u8>,
}

#[async_trait::async_trait]
trait CallbackTransport: Send + Sync {
    async fn request(
        &self,
        method: CallbackMethod,
        path: &str,
        body: &[u8],
    ) -> Result<CallbackResponse, ()>;
}

struct H2CallbackTransport {
    sender: h2::client::SendRequest<bytes::Bytes>,
}

#[async_trait::async_trait]
impl CallbackTransport for H2CallbackTransport {
    async fn request(
        &self,
        method: CallbackMethod,
        path: &str,
        body: &[u8],
    ) -> Result<CallbackResponse, ()> {
        let mut builder = http::Request::builder().uri(path);
        builder = match method {
            CallbackMethod::Get => builder.method("GET"),
            CallbackMethod::Post => builder
                .method("POST")
                .header("content-type", "application/json"),
        };
        let request = builder.body(()).map_err(|_| ())?;
        let mut sender = self.sender.clone().ready().await.map_err(|_| ())?;
        let (response, mut request_stream) = sender.send_request(request, false).map_err(|_| ())?;
        request_stream
            .send_data(bytes::Bytes::copy_from_slice(body), true)
            .map_err(|_| ())?;
        let response = response.await.map_err(|_| ())?;
        let status = response.status().as_u16();
        let location = response
            .headers()
            .get(http::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let mut response_stream = response.into_body();
        let mut response_body = Vec::new();
        while let Some(frame) = response_stream.data().await {
            let frame = frame.map_err(|_| ())?;
            let _ = response_stream.flow_control().release_capacity(frame.len());
            if response_body.len().saturating_add(frame.len()) > MAX_RESPONSE_BYTES {
                request_stream.send_reset(h2::Reason::CANCEL);
                return Ok(CallbackResponse {
                    status,
                    location,
                    body: vec![0; MAX_RESPONSE_BYTES + 1],
                });
            }
            response_body.extend_from_slice(&frame);
        }
        Ok(CallbackResponse {
            status,
            location,
            body: response_body,
        })
    }
}

async fn deliver_callback<T: CallbackTransport + ?Sized>(
    transport: &T,
    job: NotifyJob,
    deadline: tokio::time::Instant,
    metrics: &SshNotifyMetrics,
) {
    let mut path = job.path;
    let payload = job.payload;
    let mut method = CallbackMethod::Post;
    let mut seen = HashSet::new();
    seen.insert(path.clone());

    for redirects in 0..=MAX_REDIRECTS {
        let body = if method == CallbackMethod::Post {
            payload.as_slice()
        } else {
            &[]
        };
        let Ok(attempted) =
            tokio::time::timeout_at(deadline, transport.request(method, &path, body)).await
        else {
            metrics.dispatch_timeout.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let Ok(response) = attempted else {
            // The body may have committed before the response disappeared.
            // Upstream makes one attempt; never duplicate an ambiguous POST.
            metrics.transport_failed.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if response.body.len() > MAX_RESPONSE_BYTES {
            metrics.response_too_large.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if response.status == CREATED {
            metrics.delivered.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if !matches!(response.status, 301 | 302 | 303 | 307 | 308) {
            metrics.status_failed.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if redirects == MAX_REDIRECTS {
            metrics.redirect_limit.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let Some(location) = response.location else {
            metrics.redirect_invalid.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let Ok(next) = callback_path(&location, Some(&path)) else {
            metrics.redirect_invalid.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if !seen.insert(next.clone()) {
            metrics.redirect_loop.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if matches!(response.status, 301..=303) {
            method = CallbackMethod::Get;
        }
        path = next;
    }
}

/// Parse a policy or redirect URL, discard its destination, and return only
/// the normalized origin-form path/query used on the fixed Noise transport.
fn callback_path(input: &str, relative_to: Option<&str>) -> Result<String, SshNotifyEnqueueError> {
    if input.is_empty()
        || input.len() > MAX_NOTIFY_URL_BYTES
        || input
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'\\')
    {
        return Err(SshNotifyEnqueueError::InvalidUrl);
    }
    let base = if let Some(current) = relative_to {
        url::Url::parse(&format!("https://control.invalid{current}"))
            .map_err(|_| SshNotifyEnqueueError::InvalidUrl)?
    } else {
        url::Url::parse("https://control.invalid/")
            .map_err(|_| SshNotifyEnqueueError::InvalidUrl)?
    };
    let parsed = if input.starts_with('/') {
        base.join(input)
    } else {
        match url::Url::parse(input) {
            Ok(url) => Ok(url),
            Err(_) if relative_to.is_some() => base.join(input),
            Err(error) => Err(error),
        }
    }
    .map_err(|_| SshNotifyEnqueueError::InvalidUrl)?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(SshNotifyEnqueueError::InvalidUrl);
    }
    let mut path = parsed.path().to_string();
    if !path.starts_with('/') {
        return Err(SshNotifyEnqueueError::InvalidUrl);
    }
    if let Some(query) = parsed.query() {
        path.push('?');
        path.push_str(query);
    }
    if path.len() > MAX_NOTIFY_URL_BYTES {
        return Err(SshNotifyEnqueueError::InvalidUrl);
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(principal: NodeID) -> SSHEventNotifyRequest {
        SSHEventNotifyRequest {
            SrcNode: principal,
            ..Default::default()
        }
    }

    #[test]
    fn arbitrary_authority_is_discarded_and_malformed_urls_are_rejected() {
        assert_eq!(
            callback_path(
                "https://evil.example:444/notify/path?token=opaque#fragment",
                None
            )
            .unwrap(),
            "/notify/path?token=opaque"
        );
        assert_eq!(
            callback_path("//other.example/notify", None).unwrap(),
            "/notify"
        );
        assert_eq!(callback_path("/notify?q=1", None).unwrap(), "/notify?q=1");
        for invalid in [
            "notify",
            "javascript:alert(1)",
            "/notify\\evil",
            "/x\r\ny: z",
        ] {
            assert_eq!(
                callback_path(invalid, None),
                Err(SshNotifyEnqueueError::InvalidUrl)
            );
        }
    }

    #[test]
    fn key_rotation_generation_replacement_revokes_and_drains_old_jobs() {
        let dispatcher = SshCallbackDispatcher::new();
        let first = dispatcher.activate(NodePublic::from_raw32([1; 32]));
        let notifier = dispatcher.notifier();
        notifier
            .enqueue("https://any.invalid/one", &request(1))
            .unwrap();
        let second = dispatcher.activate(NodePublic::from_raw32([2; 32]));
        assert!(first.generation.revoked.load(Ordering::Acquire));
        assert!(first.generation.pop().is_none());
        assert_eq!(dispatcher.metrics().revoked_queued, 1);
        notifier
            .enqueue("https://another.invalid/two", &request(1))
            .unwrap();
        let queued = second.generation.pop().unwrap();
        let wire: SSHEventNotifyRequest = serde_json::from_slice(&queued.payload).unwrap();
        assert_eq!(wire.NodeKey, NodePublic::from_raw32([2; 32]));
        drop(second);
        assert_eq!(
            notifier.enqueue("https://any.invalid/three", &request(1)),
            Err(SshNotifyEnqueueError::NoGeneration)
        );
    }

    #[test]
    fn profile_logout_revokes_admission_before_transport_teardown() {
        let dispatcher = SshCallbackDispatcher::new();
        let generation = dispatcher.activate(NodePublic::default());
        let notifier = dispatcher.notifier();
        notifier
            .enqueue("https://any.invalid/queued", &request(1))
            .unwrap();
        dispatcher.revoke_current();
        assert!(generation.generation.revoked.load(Ordering::Acquire));
        assert!(generation.generation.pop().is_none());
        assert_eq!(dispatcher.metrics().revoked_queued, 1);
        assert_eq!(
            notifier.enqueue("https://any.invalid/late", &request(1)),
            Err(SshNotifyEnqueueError::NoGeneration)
        );
    }

    #[test]
    fn fair_queue_reserves_capacity_per_principal_and_expires_truthfully() {
        let metrics = SshNotifyMetrics::default();
        let now = Instant::now();
        let mut queue = FairQueue::new();
        for index in 0..PRINCIPAL_QUEUE_CAPACITY {
            queue
                .push(NotifyJob {
                    generation: 1,
                    principal: 1,
                    path: format!("/one/{index}"),
                    payload: Vec::new(),
                    enqueued: now,
                })
                .unwrap();
        }
        assert!(matches!(
            queue.push(NotifyJob {
                generation: 1,
                principal: 1,
                path: "/one/overflow".into(),
                payload: Vec::new(),
                enqueued: now,
            }),
            Err(SshNotifyEnqueueError::PrincipalQuota)
        ));
        assert_eq!(queue.principals.len(), 1);
        queue
            .push(NotifyJob {
                generation: 1,
                principal: 2,
                path: "/two".into(),
                payload: Vec::new(),
                enqueued: now,
            })
            .unwrap();
        assert_eq!(queue.pop(now, &metrics).unwrap().principal, 1);
        assert_eq!(queue.pop(now, &metrics).unwrap().principal, 2);

        let mut queue = FairQueue::new();
        queue
            .push(NotifyJob {
                generation: 1,
                principal: 3,
                path: "/expired".into(),
                payload: Vec::new(),
                enqueued: now,
            })
            .unwrap();
        let after_ttl = now + QUEUE_TTL + Duration::from_millis(1);
        queue.expire(after_ttl, &metrics);
        assert_eq!(queue.total, 0);
        queue
            .push(NotifyJob {
                generation: 1,
                principal: 3,
                path: "/fresh".into(),
                payload: Vec::new(),
                enqueued: after_ttl,
            })
            .unwrap();
        assert_eq!(metrics.snapshot().queue_expired, 1);

        let mut full = FairQueue::new();
        for principal in 0..(GENERATION_QUEUE_CAPACITY / PRINCIPAL_QUEUE_CAPACITY) {
            for index in 0..PRINCIPAL_QUEUE_CAPACITY {
                full.push(NotifyJob {
                    generation: 1,
                    principal: principal as NodeID,
                    path: format!("/{principal}/{index}"),
                    payload: Vec::new(),
                    enqueued: now,
                })
                .unwrap();
            }
        }
        assert_eq!(full.total, GENERATION_QUEUE_CAPACITY);
        assert_eq!(full.principals.len(), 8);
        assert_eq!(
            full.push(NotifyJob {
                generation: 1,
                principal: 999,
                path: "/rejected-source".into(),
                payload: Vec::new(),
                enqueued: now,
            }),
            Err(SshNotifyEnqueueError::QueueFull)
        );
        assert_eq!(full.principals.len(), 8);

        // A full profile generation has no shared queue state with another.
        let mut other_profile = FairQueue::new();
        other_profile
            .push(NotifyJob {
                generation: 2,
                principal: 999,
                path: "/other-profile".into(),
                payload: Vec::new(),
                enqueued: now,
            })
            .unwrap();
    }

    #[tokio::test]
    async fn callback_multiplexes_on_the_current_map_h2_generation() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (path_tx, path_rx) = tokio::sync::oneshot::channel();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (map_request, mut map_response) = connection.accept().await.unwrap().unwrap();
            assert_eq!(map_request.uri().path(), "/machine/map");
            let response = http::Response::builder().status(200).body(()).unwrap();
            let mut map_body = map_response.send_response(response, false).unwrap();

            let (callback, mut callback_response) = connection.accept().await.unwrap().unwrap();
            path_tx.send(callback.uri().to_string()).unwrap();
            let mut callback_body = callback.into_body();
            while callback_body.data().await.is_some() {}
            let response = http::Response::builder().status(CREATED).body(()).unwrap();
            callback_response.send_response(response, true).unwrap();
            map_body
                .send_data(bytes::Bytes::from_static(b"map-data"), true)
                .unwrap();
            tokio::pin!(done_rx);
            loop {
                tokio::select! {
                    _ = &mut done_rx => break,
                    request = connection.accept() => {
                        if request.is_none() {
                            break;
                        }
                    }
                }
            }
        });

        let (mut sender, connection) = h2::client::handshake(client_io).await.unwrap();
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let map_request = http::Request::builder()
            .method("POST")
            .uri("/machine/map")
            .body(())
            .unwrap();
        let (map_response, mut map_send) = sender.send_request(map_request, false).unwrap();
        map_send.send_data(bytes::Bytes::new(), true).unwrap();
        let mut map_body = map_response.await.unwrap().into_body();

        let dispatcher = SshCallbackDispatcher::new();
        let mut generation =
            CallbackGeneration::new(dispatcher.clone(), sender.clone(), NodePublic::default());
        dispatcher
            .notifier()
            .enqueue("https://arbitrary.invalid/ssh/event?q=1", &request(7))
            .unwrap();
        let data = tokio::time::timeout(
            Duration::from_secs(1),
            generation.recv_map_data(&mut map_body),
        )
        .await
        .unwrap()
        .unwrap()
        .unwrap();
        assert_eq!(&data[..], b"map-data");
        assert_eq!(path_rx.await.unwrap(), "/ssh/event?q=1");
        assert_eq!(dispatcher.metrics().delivered, 1);

        generation.shutdown().await;
        let _ = done_tx.send(());
        server.await.unwrap();
        driver.abort();
        let _ = driver.await;
    }

    #[tokio::test]
    async fn blocked_callback_does_not_block_map_and_revocation_shutdown_is_bounded() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (callback_tx, callback_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (_, mut map_response) = connection.accept().await.unwrap().unwrap();
            let response = http::Response::builder().status(200).body(()).unwrap();
            let mut map_body = map_response.send_response(response, false).unwrap();

            let (_callback, _callback_response) = connection.accept().await.unwrap().unwrap();
            map_body
                .send_data(bytes::Bytes::from_static(b"map-wins"), false)
                .unwrap();
            callback_tx.send(()).unwrap();
            while connection.accept().await.is_some() {}
        });

        let (mut sender, connection) = h2::client::handshake(client_io).await.unwrap();
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let map_request = http::Request::builder()
            .method("POST")
            .uri("/machine/map")
            .body(())
            .unwrap();
        let (map_response, mut map_send) = sender.send_request(map_request, false).unwrap();
        map_send.send_data(bytes::Bytes::new(), true).unwrap();
        let mut map_body = map_response.await.unwrap().into_body();

        let dispatcher = SshCallbackDispatcher::new();
        let mut generation =
            CallbackGeneration::new(dispatcher.clone(), sender, NodePublic::default());
        dispatcher
            .notifier()
            .enqueue("https://unused.invalid/blocked", &request(7))
            .unwrap();

        let data = tokio::time::timeout(
            Duration::from_secs(1),
            generation.recv_map_data(&mut map_body),
        )
        .await
        .expect("blocked callback hung map reads")
        .unwrap()
        .unwrap();
        assert_eq!(&data[..], b"map-wins");
        tokio::time::timeout(Duration::from_secs(1), callback_rx)
            .await
            .expect("callback stream was never dispatched")
            .unwrap();

        dispatcher.revoke_current();
        tokio::time::timeout(Duration::from_secs(1), generation.shutdown())
            .await
            .expect("revoked callback generation did not shut down");
        assert_eq!(dispatcher.metrics().revoked_in_flight, 1);

        server.abort();
        let _ = server.await;
        driver.abort();
        let _ = driver.await;
    }

    #[derive(Default)]
    struct FakeTransport {
        responses: Mutex<VecDeque<Result<CallbackResponse, ()>>>,
        requests: Mutex<Vec<(CallbackMethod, String)>>,
    }

    #[async_trait::async_trait]
    impl CallbackTransport for FakeTransport {
        async fn request(
            &self,
            method: CallbackMethod,
            path: &str,
            _body: &[u8],
        ) -> Result<CallbackResponse, ()> {
            self.requests.lock().unwrap().push((method, path.into()));
            self.responses.lock().unwrap().pop_front().unwrap()
        }
    }

    fn job(path: &str) -> NotifyJob {
        NotifyJob {
            generation: 1,
            principal: 1,
            path: path.into(),
            payload: b"wire-payload".to_vec(),
            enqueued: Instant::now(),
        }
    }

    #[tokio::test]
    async fn redirects_remain_path_only_and_are_hop_bounded() {
        let transport = FakeTransport::default();
        transport.responses.lock().unwrap().extend([
            Ok(CallbackResponse {
                status: 307,
                location: Some("https://attacker.invalid/second?x=1".into()),
                body: Vec::new(),
            }),
            Ok(CallbackResponse {
                status: CREATED,
                location: None,
                body: Vec::new(),
            }),
        ]);
        let metrics = SshNotifyMetrics::default();
        deliver_callback(
            &transport,
            job("/first"),
            tokio::time::Instant::now() + Duration::from_secs(1),
            &metrics,
        )
        .await;
        assert_eq!(
            *transport.requests.lock().unwrap(),
            vec![
                (CallbackMethod::Post, "/first".into()),
                (CallbackMethod::Post, "/second?x=1".into())
            ]
        );
        assert_eq!(metrics.snapshot().delivered, 1);
    }

    #[tokio::test]
    async fn redirects_switch_post_only_when_http_semantics_require_it_and_stop_at_limit() {
        let transport = FakeTransport::default();
        transport.responses.lock().unwrap().extend([
            Ok(CallbackResponse {
                status: 302,
                location: Some("child".into()),
                body: Vec::new(),
            }),
            Ok(CallbackResponse {
                status: 307,
                location: Some("/third".into()),
                body: Vec::new(),
            }),
            Ok(CallbackResponse {
                status: CREATED,
                location: None,
                body: Vec::new(),
            }),
        ]);
        let metrics = SshNotifyMetrics::default();
        deliver_callback(
            &transport,
            job("/root/first"),
            tokio::time::Instant::now() + Duration::from_secs(1),
            &metrics,
        )
        .await;
        assert_eq!(
            *transport.requests.lock().unwrap(),
            vec![
                (CallbackMethod::Post, "/root/first".into()),
                (CallbackMethod::Get, "/root/child".into()),
                (CallbackMethod::Get, "/third".into()),
            ]
        );

        let transport = FakeTransport::default();
        for hop in 0..=MAX_REDIRECTS {
            transport
                .responses
                .lock()
                .unwrap()
                .push_back(Ok(CallbackResponse {
                    status: 307,
                    location: Some(format!("/hop/{}", hop + 1)),
                    body: Vec::new(),
                }));
        }
        let metrics = SshNotifyMetrics::default();
        deliver_callback(
            &transport,
            job("/hop/0"),
            tokio::time::Instant::now() + Duration::from_secs(1),
            &metrics,
        )
        .await;
        assert_eq!(transport.requests.lock().unwrap().len(), MAX_REDIRECTS + 1);
        assert_eq!(metrics.snapshot().redirect_limit, 1);
    }

    #[tokio::test]
    async fn committed_request_with_dropped_response_is_never_duplicated() {
        let transport = FakeTransport::default();
        transport.responses.lock().unwrap().push_back(Err(()));
        let metrics = SshNotifyMetrics::default();
        deliver_callback(
            &transport,
            job("/commit-then-drop"),
            tokio::time::Instant::now() + Duration::from_secs(1),
            &metrics,
        )
        .await;
        assert_eq!(transport.requests.lock().unwrap().len(), 1);
        assert_eq!(metrics.snapshot().transport_failed, 1);
    }

    struct NeverTransport(AtomicU64);

    #[async_trait::async_trait]
    impl CallbackTransport for NeverTransport {
        async fn request(
            &self,
            _method: CallbackMethod,
            _path: &str,
            _body: &[u8],
        ) -> Result<CallbackResponse, ()> {
            self.0.fetch_add(1, Ordering::Relaxed);
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn dispatch_timeout_is_single_attempt_and_separately_counted() {
        let transport = NeverTransport(AtomicU64::new(0));
        let metrics = SshNotifyMetrics::default();
        deliver_callback(
            &transport,
            job("/timeout"),
            tokio::time::Instant::now() + Duration::from_millis(10),
            &metrics,
        )
        .await;
        assert_eq!(transport.0.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.snapshot().dispatch_timeout, 1);
        assert_eq!(metrics.snapshot().transport_failed, 0);
    }

    #[tokio::test]
    async fn redirect_loops_stop_without_replaying_forever() {
        let transport = FakeTransport::default();
        transport
            .responses
            .lock()
            .unwrap()
            .push_back(Ok(CallbackResponse {
                status: 302,
                location: Some("/first".into()),
                body: Vec::new(),
            }));
        let metrics = SshNotifyMetrics::default();
        deliver_callback(
            &transport,
            job("/first"),
            tokio::time::Instant::now() + Duration::from_secs(1),
            &metrics,
        )
        .await;
        assert_eq!(transport.requests.lock().unwrap().len(), 1);
        assert_eq!(metrics.snapshot().redirect_loop, 1);
    }
}
