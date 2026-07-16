//! Bounded delivery of SSH recording-failure callbacks over ts2021 Noise.
//!
//! Policy-provided callback URLs are reduced to same-control-origin
//! path-and-query values before they enter the worker queue. Workers use the
//! authenticated control client; they never open a socket to the URL host.

use crate::{ControlClient, NoiseRequestError, NoiseResponseBody, ProtocolVersion};
use rustscale_key::{MachinePrivate, MachinePublic, NodePublic};
use rustscale_tailcfg::SSHEventNotifyRequest;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

const MAX_NOTIFY_URL_BYTES: usize = 2 * 1024;
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_BYTES: usize = 4 * 1024;
const NOTIFY_WORKERS: usize = 2;
const NOTIFY_QUEUE_CAPACITY: usize = 64;
const MAX_ATTEMPTS: usize = 3;
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(3);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(10);
const RETRY_DELAY: Duration = Duration::from_millis(200);
const CREATED: u16 = 201;

/// A validated, authenticated producer for SSH recording-failure callbacks.
///
/// Enqueueing is synchronous and non-blocking. Once accepted, a callback is
/// owned by a process-lifetime bounded worker independently of the SSH
/// connection and caller runtime. Every job reaches a terminal state after a
/// fixed number of attempts and a fixed overall deadline.
#[derive(Clone)]
pub struct SshEventNotifier {
    params: Arc<ControlParams>,
}

struct ControlParams {
    control_url: String,
    machine_key: MachinePrivate,
    control_key: MachinePublic,
    protocol_version: ProtocolVersion,
    extra_root_certs: Vec<Vec<u8>>,
    node_key: NodePublic,
}

impl std::fmt::Debug for SshEventNotifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Control credentials and callback URLs can contain bearer material.
        formatter
            .debug_struct("SshEventNotifier")
            .field("credentials", &"<redacted>")
            .finish()
    }
}

/// A callback could not be accepted. This error deliberately contains no URL,
/// user, session, recorder, or key material.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum SshNotifyEnqueueError {
    #[error("invalid control callback URL")]
    InvalidUrl,
    #[error("SSH callback request exceeds the size limit")]
    RequestTooLarge,
    #[error("SSH callback worker queue is full")]
    QueueFull,
    #[error("SSH callback worker queue is unavailable")]
    Unavailable,
}

impl SshEventNotifier {
    pub fn new(
        control_url: impl Into<String>,
        machine_key: MachinePrivate,
        control_key: MachinePublic,
        protocol_version: ProtocolVersion,
        extra_root_certs: Vec<Vec<u8>>,
        node_key: NodePublic,
    ) -> Self {
        // Start the fixed process-owned workers during listener setup, never
        // on a fail-closed session termination path.
        let _ = scheduler();
        Self {
            params: Arc::new(ControlParams {
                control_url: control_url.into(),
                machine_key,
                control_key,
                protocol_version,
                extra_root_certs,
                node_key,
            }),
        }
    }

    /// Validate and enqueue one event for delivery. This never waits for
    /// control and therefore cannot delay fail-closed SSH termination.
    pub fn enqueue(
        &self,
        notify_url: &str,
        request: &SSHEventNotifyRequest,
    ) -> Result<(), SshNotifyEnqueueError> {
        let path = control_callback_path(&self.params.control_url, notify_url)?;
        let payload =
            serde_json::to_vec(request).map_err(|_| SshNotifyEnqueueError::RequestTooLarge)?;
        if payload.len() > MAX_REQUEST_BYTES {
            return Err(SshNotifyEnqueueError::RequestTooLarge);
        }
        scheduler()
            .sender
            .try_send(NotifyJob {
                params: Arc::clone(&self.params),
                path,
                payload,
                deadline: std::time::Instant::now() + TOTAL_TIMEOUT,
            })
            .map_err(|error| match error {
                std::sync::mpsc::TrySendError::Full(_) => SshNotifyEnqueueError::QueueFull,
                std::sync::mpsc::TrySendError::Disconnected(_) => {
                    SshNotifyEnqueueError::Unavailable
                }
            })
    }
}

struct NotifyJob {
    params: Arc<ControlParams>,
    path: String,
    payload: Vec<u8>,
    deadline: std::time::Instant,
}

struct NotifyScheduler {
    sender: std::sync::mpsc::SyncSender<NotifyJob>,
}

fn scheduler() -> &'static NotifyScheduler {
    static SCHEDULER: OnceLock<NotifyScheduler> = OnceLock::new();
    SCHEDULER.get_or_init(|| {
        let (sender, receiver) = std::sync::mpsc::sync_channel(NOTIFY_QUEUE_CAPACITY);
        let receiver = Arc::new(Mutex::new(receiver));
        for index in 0..NOTIFY_WORKERS {
            let receiver = Arc::clone(&receiver);
            if std::thread::Builder::new()
                .name(format!("rustscale-ssh-notify-{index}"))
                .spawn(move || notify_worker(receiver))
                .is_err()
            {
                log::error!("SSH recording callback worker could not be created");
            }
        }
        NotifyScheduler { sender }
    })
}

fn notify_worker(receiver: Arc<Mutex<std::sync::mpsc::Receiver<NotifyJob>>>) {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        log::error!("SSH recording callback worker could not start");
        return;
    };
    loop {
        let job = match receiver
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .recv()
        {
            Ok(job) => job,
            Err(_) => return,
        };
        if !runtime.block_on(deliver_job(job)) {
            // Never include the policy URL, payload, identities, recorder
            // attempts, or credential-bearing transport errors in logs.
            log::warn!("SSH recording callback reached its bounded terminal failure policy");
        }
    }
}

async fn deliver_job(job: NotifyJob) -> bool {
    let remaining = job
        .deadline
        .saturating_duration_since(std::time::Instant::now());
    if remaining.is_zero() {
        return false;
    }
    let params = Arc::clone(&job.params);
    deliver_with_retry(
        || {
            let params = Arc::clone(&params);
            let path = job.path.clone();
            let payload = job.payload.clone();
            async move { send_once(&params, &path, payload).await }
        },
        RetryPolicy {
            attempts: MAX_ATTEMPTS,
            attempt_timeout: ATTEMPT_TIMEOUT,
            total_timeout: remaining,
            retry_delay: RETRY_DELAY,
        },
    )
    .await
}

#[derive(Clone, Copy)]
struct RetryPolicy {
    attempts: usize,
    attempt_timeout: Duration,
    total_timeout: Duration,
    retry_delay: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AttemptResult {
    Delivered,
    Retryable,
    Terminal,
}

async fn deliver_with_retry<F, Fut>(mut send: F, policy: RetryPolicy) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = AttemptResult>,
{
    let deadline = tokio::time::Instant::now() + policy.total_timeout;
    for attempt in 0..policy.attempts {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }
        let timeout = policy.attempt_timeout.min(remaining);
        let result = tokio::time::timeout(timeout, send()).await;
        match result {
            Ok(AttemptResult::Delivered) => return true,
            Ok(AttemptResult::Terminal) => return false,
            Ok(AttemptResult::Retryable) | Err(_) => {}
        }
        if attempt + 1 == policy.attempts {
            break;
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining <= policy.retry_delay {
            break;
        }
        tokio::time::sleep(policy.retry_delay).await;
    }
    false
}

async fn send_once(params: &ControlParams, path: &str, payload: Vec<u8>) -> AttemptResult {
    let mut client = ControlClient::new(
        params.control_url.clone(),
        params.machine_key.clone(),
        params.control_key.clone(),
        params.protocol_version,
    );
    if !params.extra_root_certs.is_empty() {
        client.set_extra_root_certs(params.extra_root_certs.clone());
    }
    let transport = match client.connect().await {
        Ok(transport) => transport,
        Err(error) => return classify_transport_error(&error),
    };
    let result = match transport
        .post_json(path, payload, Some(&params.node_key))
        .await
    {
        Ok(response) => {
            let status = response.status();
            let mut body = response.into_body();
            if drain_response_limited(&mut body).await.is_err() {
                AttemptResult::Terminal
            } else {
                classify_status(status)
            }
        }
        Err(error) => classify_transport_error(&error),
    };
    transport.close();
    result
}

fn classify_status(status: u16) -> AttemptResult {
    if status == CREATED {
        AttemptResult::Delivered
    } else if status == 408 || status == 425 || status == 429 || (500..=599).contains(&status) {
        AttemptResult::Retryable
    } else {
        AttemptResult::Terminal
    }
}

fn classify_transport_error(_error: &NoiseRequestError) -> AttemptResult {
    // Noise/H2/I/O failures can all represent a dropped authenticated control
    // connection. Retry only within the job's strict attempt/deadline budget.
    AttemptResult::Retryable
}

async fn drain_response_limited(body: &mut NoiseResponseBody) -> Result<(), ()> {
    let mut received = 0usize;
    loop {
        let chunk = body.data().await.map_err(|_| ())?;
        let Some(chunk) = chunk else {
            return Ok(());
        };
        received = received.checked_add(chunk.len()).ok_or(())?;
        if received > MAX_RESPONSE_BYTES {
            body.cancel();
            return Err(());
        }
    }
}

/// Convert a policy callback URL to an origin-form path after proving it is
/// either relative to control or has exactly the configured control origin.
fn control_callback_path(
    control_url: &str,
    notify_url: &str,
) -> Result<String, SshNotifyEnqueueError> {
    if notify_url.is_empty()
        || notify_url.len() > MAX_NOTIFY_URL_BYTES
        || notify_url
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'\\')
    {
        return Err(SshNotifyEnqueueError::InvalidUrl);
    }

    if notify_url.starts_with('/') {
        if notify_url.starts_with("//") || notify_url.contains('#') {
            return Err(SshNotifyEnqueueError::InvalidUrl);
        }
        let uri: http::Uri = notify_url
            .parse()
            .map_err(|_| SshNotifyEnqueueError::InvalidUrl)?;
        if uri.scheme().is_some() || uri.authority().is_some() || uri.path().is_empty() {
            return Err(SshNotifyEnqueueError::InvalidUrl);
        }
        return Ok(uri
            .path_and_query()
            .ok_or(SshNotifyEnqueueError::InvalidUrl)?
            .as_str()
            .to_string());
    }

    let control = parse_control_url(control_url)?;
    let callback = url::Url::parse(notify_url).map_err(|_| SshNotifyEnqueueError::InvalidUrl)?;
    if !matches!(callback.scheme(), "http" | "https")
        || !callback.username().is_empty()
        || callback.password().is_some()
        || callback.fragment().is_some()
        || callback.host_str().is_none()
        || callback.scheme() != control.scheme()
        || callback.host_str() != control.host_str()
        || callback.port_or_known_default() != control.port_or_known_default()
    {
        return Err(SshNotifyEnqueueError::InvalidUrl);
    }
    let mut path = callback.path().to_string();
    if let Some(query) = callback.query() {
        path.push('?');
        path.push_str(query);
    }
    if path.is_empty() || path.len() > MAX_NOTIFY_URL_BYTES {
        return Err(SshNotifyEnqueueError::InvalidUrl);
    }
    Ok(path)
}

fn parse_control_url(control_url: &str) -> Result<url::Url, SshNotifyEnqueueError> {
    let candidate = if control_url.contains("://") {
        control_url.to_string()
    } else {
        format!("https://{control_url}")
    };
    let url = url::Url::parse(&candidate).map_err(|_| SshNotifyEnqueueError::InvalidUrl)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(SshNotifyEnqueueError::InvalidUrl);
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn callback_url_is_confined_to_control_origin() {
        let control = "https://control.example.com";
        assert_eq!(
            control_callback_path(control, "/machine/ssh/notify?token=opaque").unwrap(),
            "/machine/ssh/notify?token=opaque"
        );
        assert_eq!(
            control_callback_path(
                control,
                "https://control.example.com/machine/ssh/notify?token=opaque"
            )
            .unwrap(),
            "/machine/ssh/notify?token=opaque"
        );
        for attack in [
            "https://evil.example/machine/ssh/notify",
            "http://control.example.com/machine/ssh/notify",
            "https://control.example.com:444/machine/ssh/notify",
            "https://user@control.example.com/machine/ssh/notify",
            "//evil.example/notify",
            "notify",
            "/notify#fragment",
            "/notify\\evil",
            "/notify\r\nx-evil: yes",
        ] {
            assert_eq!(
                control_callback_path(control, attack),
                Err(SshNotifyEnqueueError::InvalidUrl),
                "accepted attack form"
            );
        }
    }

    #[test]
    fn only_created_succeeds_and_only_transient_statuses_retry() {
        assert_eq!(classify_status(201), AttemptResult::Delivered);
        assert_eq!(classify_status(200), AttemptResult::Terminal);
        assert_eq!(classify_status(400), AttemptResult::Terminal);
        assert_eq!(classify_status(429), AttemptResult::Retryable);
        assert_eq!(classify_status(503), AttemptResult::Retryable);
    }

    #[tokio::test]
    async fn retries_transient_failures_but_not_terminal_responses() {
        let calls = Arc::new(AtomicUsize::new(0));
        let call_counter = Arc::clone(&calls);
        let delivered = deliver_with_retry(
            move || {
                let call = call_counter.fetch_add(1, Ordering::SeqCst);
                async move {
                    if call < 2 {
                        AttemptResult::Retryable
                    } else {
                        AttemptResult::Delivered
                    }
                }
            },
            RetryPolicy {
                attempts: 3,
                attempt_timeout: Duration::from_secs(1),
                total_timeout: Duration::from_secs(2),
                retry_delay: Duration::ZERO,
            },
        )
        .await;
        assert!(delivered);
        assert_eq!(calls.load(Ordering::SeqCst), 3);

        calls.store(0, Ordering::SeqCst);
        let call_counter = Arc::clone(&calls);
        let delivered = deliver_with_retry(
            move || {
                call_counter.fetch_add(1, Ordering::SeqCst);
                async { AttemptResult::Terminal }
            },
            RetryPolicy {
                attempts: 3,
                attempt_timeout: Duration::from_secs(1),
                total_timeout: Duration::from_secs(2),
                retry_delay: Duration::ZERO,
            },
        )
        .await;
        assert!(!delivered);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn retries_and_each_attempt_have_bounded_deadlines() {
        let calls = Arc::new(AtomicUsize::new(0));
        struct CancellationGuard(Arc<AtomicUsize>);
        impl Drop for CancellationGuard {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let counter = Arc::clone(&calls);
        let cancelled = Arc::new(AtomicUsize::new(0));
        let cancellation_counter = Arc::clone(&cancelled);
        let delivered = deliver_with_retry(
            move || {
                counter.fetch_add(1, Ordering::SeqCst);
                let guard = CancellationGuard(Arc::clone(&cancellation_counter));
                async move {
                    let _guard = guard;
                    std::future::pending::<()>().await;
                    AttemptResult::Delivered
                }
            },
            RetryPolicy {
                attempts: 2,
                attempt_timeout: Duration::from_millis(10),
                total_timeout: Duration::from_millis(40),
                retry_delay: Duration::ZERO,
            },
        )
        .await;
        assert!(!delivered);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(cancelled.load(Ordering::SeqCst), 2);
    }
}
