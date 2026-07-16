//! Device posture identity collection and policy evaluation.
//!
//! The production service collects only serial numbers and non-loopback
//! interface hardware addresses. Collection is opt-in unless an injected
//! management policy explicitly enables it.

#![forbid(unsafe_code)]

mod hwaddr;
mod serial;

#[cfg(target_os = "linux")]
mod serial_linux;
#[cfg(target_os = "macos")]
mod serial_macos;
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
mod serial_stub;
#[cfg(any(target_os = "windows", test))]
mod serial_windows;

use std::sync::Mutex;
#[cfg(any(target_os = "windows", test))]
use std::time::Duration;
use std::time::Instant;

pub use tokio_util::sync::CancellationToken;

pub use hwaddr::get_hardware_addrs;
pub use rustscale_syspolicy::PreferenceOption;
pub use serial::{dedup_serials, get_serial_numbers, is_sentinel_serial};

/// Maximum accepted size of one platform serial-number value.
pub const MAX_SERIAL_LEN: usize = 256;
/// Maximum number of serial numbers reported for one machine.
pub const MAX_SERIALS: usize = 16;

/// Errors returned while collecting device posture identity data.
///
/// Error text deliberately contains no serial number, hardware address, path,
/// command output, or policy value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PostureError {
    /// The platform did not expose a usable serial number.
    #[error("serial number is unavailable")]
    CollectionFailed,
    /// Serial-number collection is unavailable on this platform.
    #[error("serial number collection is unsupported on this platform")]
    UnsupportedPlatform,
    /// A bounded platform operation timed out.
    #[error("platform collection timed out")]
    Timeout,
    /// A bounded platform operation was cancelled.
    #[error("platform collection was cancelled")]
    Cancelled,
    /// The globally bounded platform worker pool is occupied.
    #[error("platform collection worker capacity is unavailable")]
    WorkerCapacity,
    /// A platform worker terminated without returning a result.
    #[error("platform collection worker terminated")]
    WorkerTerminated,
    /// An operating-system operation failed.
    #[error("platform collection failed ({0:?})")]
    Io(std::io::ErrorKind),
    /// Platform data exceeded a collection bound or was malformed.
    #[error("platform collection returned invalid data")]
    InvalidData,
}

impl From<std::io::Error> for PostureError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error.kind())
    }
}

/// Privacy-safe policy lookup failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("posture policy is unavailable")]
    Unavailable,
}

/// Injectable policy source. It is queried for every request so policy
/// changes take effect without reconstructing the posture service.
pub trait PosturePolicy: Send + Sync {
    fn preference(&self) -> Result<PreferenceOption, PolicyError>;
}

/// Default policy: leave the choice to the persisted user preference.
#[derive(Debug, Default)]
pub struct UserDecidesPolicy;

impl PosturePolicy for UserDecidesPolicy {
    fn preference(&self) -> Result<PreferenceOption, PolicyError> {
        Ok(PreferenceOption::UserDecides)
    }
}

/// Live policy backed by the current syspolicy engine and immutable snapshots.
/// Each posture request reloads non-subscribing platform providers; providers
/// with subscriptions also update the same engine continuously. Missing policy
/// means `user-decides`, while provider and conversion failures fail closed in
/// [`IdentityService`].
pub struct SystemPolicy {
    engine: Option<rustscale_syspolicy::PolicyEngine>,
}

impl SystemPolicy {
    /// Creates a posture policy from an existing engine, useful for embedding
    /// and hermetic provider tests.
    pub fn from_engine(engine: rustscale_syspolicy::PolicyEngine) -> Self {
        Self {
            engine: Some(engine),
        }
    }

    fn snapshot_preference(
        snapshot: &rustscale_syspolicy::Snapshot,
    ) -> Result<PreferenceOption, PolicyError> {
        use rustscale_syspolicy::{PolicyErrorKind, PolicyKey, PolicyValue};

        match snapshot.get(PolicyKey::PostureChecking) {
            Ok(PolicyValue::PreferenceOption(preference)) => Ok(preference),
            Err(error) if error.kind == PolicyErrorKind::NotConfigured => {
                Ok(PreferenceOption::UserDecides)
            }
            Err(_) | Ok(_) => Err(PolicyError::Unavailable),
        }
    }
}

impl Default for SystemPolicy {
    fn default() -> Self {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        let engine =
            rustscale_syspolicy::default_engine(rustscale_syspolicy::PolicyScope::Device).ok();
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        let engine = None;
        Self { engine }
    }
}

impl PosturePolicy for SystemPolicy {
    fn preference(&self) -> Result<PreferenceOption, PolicyError> {
        let engine = self.engine.as_ref().ok_or(PolicyError::Unavailable)?;
        let snapshot = engine.reload().map_err(|_| PolicyError::Unavailable)?;
        Self::snapshot_preference(&snapshot)
    }
}

/// Deadline and cancellation authority for one posture collection.
#[derive(Clone, Debug)]
pub struct CollectionContext {
    deadline: Option<Instant>,
    cancellation: CancellationToken,
}

impl CollectionContext {
    /// Create a cancellable context with an optional monotonic deadline.
    pub fn new(deadline: Option<Instant>, cancellation: CancellationToken) -> Self {
        Self {
            deadline,
            cancellation,
        }
    }

    /// Create a fresh context that has no caller deadline.
    pub fn unbounded() -> Self {
        Self::new(None, CancellationToken::new())
    }

    /// Return a context no later than `timeout` from now.
    #[cfg(target_os = "windows")]
    pub(crate) fn bounded(&self, timeout: Duration) -> Self {
        let platform_deadline = Instant::now() + timeout;
        Self {
            deadline: Some(self.deadline.map_or(platform_deadline, |deadline| {
                deadline.min(platform_deadline)
            })),
            cancellation: self.cancellation.clone(),
        }
    }

    pub(crate) fn check(&self) -> Result<(), PostureError> {
        if self.cancellation.is_cancelled() {
            return Err(PostureError::Cancelled);
        }
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(PostureError::Timeout);
        }
        Ok(())
    }

    #[cfg(any(target_os = "windows", test))]
    pub(crate) fn wait_slice(&self, maximum: Duration) -> Result<Duration, PostureError> {
        self.check()?;
        Ok(self.deadline.map_or(maximum, |deadline| {
            maximum.min(deadline.saturating_duration_since(Instant::now()))
        }))
    }
}

impl Default for CollectionContext {
    fn default() -> Self {
        Self::unbounded()
    }
}

/// Injectable source of platform posture attributes.
pub trait PostureCollector: Send + Sync {
    fn serial_numbers(&self) -> Result<Vec<String>, PostureError>;
    fn hardware_addrs(&self) -> Result<Vec<String>, PostureError>;

    fn serial_numbers_cancellable(
        &self,
        context: &CollectionContext,
    ) -> Result<Vec<String>, PostureError> {
        context.check()?;
        let result = self.serial_numbers();
        context.check()?;
        result
    }

    fn hardware_addrs_cancellable(
        &self,
        context: &CollectionContext,
    ) -> Result<Vec<String>, PostureError> {
        context.check()?;
        let result = self.hardware_addrs();
        context.check()?;
        result
    }
}

/// Collector backed by RustScale's native platform readers.
#[derive(Debug, Default)]
pub struct SystemCollector;

impl PostureCollector for SystemCollector {
    fn serial_numbers(&self) -> Result<Vec<String>, PostureError> {
        get_serial_numbers()
    }

    fn hardware_addrs(&self) -> Result<Vec<String>, PostureError> {
        Ok(get_hardware_addrs())
    }

    fn serial_numbers_cancellable(
        &self,
        context: &CollectionContext,
    ) -> Result<Vec<String>, PostureError> {
        serial::get_serial_numbers_cancellable(context)
    }
}

/// Collected identity values. Serialization is owned by `tailcfg`'s exact C2N
/// wire model; this type keeps platform collection independent of control.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IdentityData {
    pub serial_numbers: Vec<String>,
    pub iface_hardware_addrs: Vec<String>,
    pub posture_disabled: bool,
}

/// Collection result plus non-sensitive diagnostics suitable for health/logs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CollectionResult {
    pub identity: IdentityData,
    pub policy_error: Option<PolicyError>,
    pub serial_error: Option<PostureError>,
    pub hardware_addr_error: Option<PostureError>,
}

/// Policy-aware posture collector with stable hardware-address reporting.
///
/// A successful non-empty hardware-address result becomes the last-known
/// value. A later empty result reuses it, matching upstream's workaround for
/// transient interface enumeration gaps.
pub struct IdentityService {
    collector: Box<dyn PostureCollector>,
    policy: Box<dyn PosturePolicy>,
    last_hardware_addrs: Mutex<Vec<String>>,
}

impl IdentityService {
    pub fn new(collector: Box<dyn PostureCollector>, policy: Box<dyn PosturePolicy>) -> Self {
        Self {
            collector,
            policy,
            last_hardware_addrs: Mutex::new(Vec::new()),
        }
    }

    /// Collect identity according to the latest policy and user preference.
    /// Hardware addresses are only touched when requested by control.
    pub fn collect(&self, user_enabled: bool, include_hardware_addrs: bool) -> CollectionResult {
        self.collect_cancellable(
            || user_enabled,
            include_hardware_addrs,
            &CollectionContext::unbounded(),
        )
        .unwrap_or_else(|error| CollectionResult {
            serial_error: Some(error),
            ..CollectionResult::default()
        })
    }

    /// Cancellable collection with a live user-preference reader.
    ///
    /// The management policy and `user_enabled` reader are checked both before
    /// collection and immediately before the result can be published. A late
    /// opt-out clears all collected identity and does not update last-known
    /// hardware addresses.
    pub fn collect_cancellable<F>(
        &self,
        user_enabled: F,
        include_hardware_addrs: bool,
        context: &CollectionContext,
    ) -> Result<CollectionResult, PostureError>
    where
        F: Fn() -> bool,
    {
        context.check()?;
        if let Some(disabled) = self.disabled_result(user_enabled()) {
            return Ok(disabled);
        }

        let (serial_numbers, serial_error) =
            match self.collector.serial_numbers_cancellable(context) {
                Ok(values) => (sanitize_serials(values), None),
                Err(PostureError::Cancelled) => return Err(PostureError::Cancelled),
                Err(PostureError::Timeout) => return Err(PostureError::Timeout),
                Err(error) => (Vec::new(), Some(error)),
            };

        context.check()?;
        let mut hardware_addr_error = None;
        let mut fresh_hardware_addrs = None;
        let iface_hardware_addrs = if include_hardware_addrs {
            match self.collector.hardware_addrs_cancellable(context) {
                Ok(values) => {
                    let values = normalize_hardware_addrs(values);
                    if values.is_empty() {
                        self.last_hardware_addrs
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .clone()
                    } else {
                        fresh_hardware_addrs = Some(values.clone());
                        values
                    }
                }
                Err(PostureError::Cancelled) => return Err(PostureError::Cancelled),
                Err(PostureError::Timeout) => return Err(PostureError::Timeout),
                Err(error) => {
                    hardware_addr_error = Some(error);
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };

        context.check()?;
        if let Some(disabled) = self.disabled_result(user_enabled()) {
            return Ok(disabled);
        }
        if let Some(values) = fresh_hardware_addrs {
            self.last_hardware_addrs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone_from(&values);
        }

        Ok(CollectionResult {
            identity: IdentityData {
                serial_numbers,
                iface_hardware_addrs,
                posture_disabled: false,
            },
            policy_error: None,
            serial_error,
            hardware_addr_error,
        })
    }

    /// Re-check live policy immediately before a caller publishes a completed
    /// result. Revocation replaces any stale identity with a disabled result.
    pub fn revalidate_for_publication(
        &self,
        user_enabled: bool,
        result: CollectionResult,
    ) -> CollectionResult {
        self.disabled_result(user_enabled).unwrap_or(result)
    }

    fn disabled_result(&self, user_enabled: bool) -> Option<CollectionResult> {
        let (preference, policy_error) = match self.policy.preference() {
            Ok(preference) => (preference, None),
            Err(error) => (PreferenceOption::Never, Some(error)),
        };
        (!preference.should_enable(user_enabled)).then(|| CollectionResult {
            identity: IdentityData {
                posture_disabled: true,
                ..IdentityData::default()
            },
            policy_error,
            ..CollectionResult::default()
        })
    }
}

impl Default for IdentityService {
    fn default() -> Self {
        Self::new(Box::new(SystemCollector), Box::new(SystemPolicy::default()))
    }
}

fn sanitize_serials(values: Vec<String>) -> Vec<String> {
    let values = values
        .into_iter()
        .take(MAX_SERIALS)
        .filter_map(|value| {
            let value = value.trim();
            (!is_sentinel_serial(value)
                && value.len() <= MAX_SERIAL_LEN
                && !value.chars().any(char::is_control))
            .then(|| value.to_owned())
        })
        .collect();
    dedup_serials(values)
}

fn normalize_hardware_addrs(mut values: Vec<String>) -> Vec<String> {
    values.retain(|value| {
        value.len() <= 32
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b':' || byte == b'-')
    });
    values.sort_unstable();
    values.dedup();
    values
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use super::*;

    struct FakeCollector {
        serial_calls: Arc<AtomicUsize>,
        hardware_calls: Arc<AtomicUsize>,
        serials: Vec<String>,
        hardware: Mutex<Vec<Vec<String>>>,
    }

    impl PostureCollector for FakeCollector {
        fn serial_numbers(&self) -> Result<Vec<String>, PostureError> {
            self.serial_calls.fetch_add(1, Ordering::Relaxed);
            Ok(self.serials.clone())
        }

        fn hardware_addrs(&self) -> Result<Vec<String>, PostureError> {
            self.hardware_calls.fetch_add(1, Ordering::Relaxed);
            let mut values = self.hardware.lock().unwrap();
            Ok(if values.is_empty() {
                Vec::new()
            } else {
                values.remove(0)
            })
        }
    }

    struct FixedPolicy(PreferenceOption);
    impl PosturePolicy for FixedPolicy {
        fn preference(&self) -> Result<PreferenceOption, PolicyError> {
            Ok(self.0)
        }
    }

    struct ErrorPolicy;
    impl PosturePolicy for ErrorPolicy {
        fn preference(&self) -> Result<PreferenceOption, PolicyError> {
            Err(PolicyError::Unavailable)
        }
    }

    struct MutablePolicy(Arc<AtomicU8>);
    impl PosturePolicy for MutablePolicy {
        fn preference(&self) -> Result<PreferenceOption, PolicyError> {
            Ok(match self.0.load(Ordering::Relaxed) {
                1 => PreferenceOption::Always,
                2 => PreferenceOption::Never,
                _ => PreferenceOption::UserDecides,
            })
        }
    }

    fn service(policy: PreferenceOption) -> (IdentityService, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let serial_calls = Arc::new(AtomicUsize::new(0));
        let hardware_calls = Arc::new(AtomicUsize::new(0));
        let collector = FakeCollector {
            serial_calls: serial_calls.clone(),
            hardware_calls: hardware_calls.clone(),
            serials: vec![" serial-1 ".into(), "serial-1".into()],
            hardware: Mutex::new(vec![vec!["aa:bb:cc:dd:ee:ff".into()], Vec::new()]),
        };
        (
            IdentityService::new(Box::new(collector), Box::new(FixedPolicy(policy))),
            serial_calls,
            hardware_calls,
        )
    }

    #[test]
    fn policy_enable_disable_and_user_choice() {
        let (never_service, serial_calls, _) = service(PreferenceOption::Never);
        assert!(never_service.collect(true, true).identity.posture_disabled);
        assert_eq!(serial_calls.load(Ordering::Relaxed), 0);

        let (always_service, serial_calls, _) = service(PreferenceOption::Always);
        assert!(
            !always_service
                .collect(false, false)
                .identity
                .posture_disabled
        );
        assert_eq!(serial_calls.load(Ordering::Relaxed), 1);

        let (user_service, serial_calls, _) = service(PreferenceOption::UserDecides);
        assert!(user_service.collect(false, false).identity.posture_disabled);
        assert_eq!(serial_calls.load(Ordering::Relaxed), 0);
    }

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[test]
    fn managed_platform_always_and_never_gate_collection() {
        let (never, serial_calls, _) = service(PreferenceOption::Never);
        assert!(never.collect(true, true).identity.posture_disabled);
        assert_eq!(serial_calls.load(Ordering::Relaxed), 0);

        let (always, serial_calls, _) = service(PreferenceOption::Always);
        assert!(!always.collect(false, false).identity.posture_disabled);
        assert_eq!(serial_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn policy_provider_failure_fails_closed() {
        let serial_calls = Arc::new(AtomicUsize::new(0));
        let service = IdentityService::new(
            Box::new(FakeCollector {
                serial_calls: serial_calls.clone(),
                hardware_calls: Arc::new(AtomicUsize::new(0)),
                serials: vec!["serial-1".into()],
                hardware: Mutex::new(Vec::new()),
            }),
            Box::new(ErrorPolicy),
        );
        let result = service.collect(true, true);
        assert!(result.identity.posture_disabled);
        assert_eq!(result.policy_error, Some(PolicyError::Unavailable));
        assert_eq!(serial_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn policy_updates_apply_without_rebuilding_service() {
        let policy = Arc::new(AtomicU8::new(2));
        let service = IdentityService::new(
            Box::new(FakeCollector {
                serial_calls: Arc::new(AtomicUsize::new(0)),
                hardware_calls: Arc::new(AtomicUsize::new(0)),
                serials: vec!["serial-1".into()],
                hardware: Mutex::new(Vec::new()),
            }),
            Box::new(MutablePolicy(policy.clone())),
        );
        assert!(service.collect(true, false).identity.posture_disabled);
        policy.store(1, Ordering::Relaxed);
        assert!(!service.collect(false, false).identity.posture_disabled);
    }

    #[test]
    fn preference_revoked_during_collection_suppresses_stale_identity() {
        struct RevokingCollector {
            policy: Arc<AtomicU8>,
            hardware_calls: Arc<AtomicUsize>,
        }

        impl PostureCollector for RevokingCollector {
            fn serial_numbers(&self) -> Result<Vec<String>, PostureError> {
                self.policy.store(2, Ordering::Release);
                Ok(vec!["stale-serial".into()])
            }

            fn hardware_addrs(&self) -> Result<Vec<String>, PostureError> {
                self.hardware_calls.fetch_add(1, Ordering::Relaxed);
                Ok(vec!["aa:bb:cc:dd:ee:ff".into()])
            }
        }

        let policy = Arc::new(AtomicU8::new(1));
        let hardware_calls = Arc::new(AtomicUsize::new(0));
        let service = IdentityService::new(
            Box::new(RevokingCollector {
                policy: policy.clone(),
                hardware_calls: hardware_calls.clone(),
            }),
            Box::new(MutablePolicy(policy)),
        );
        let result = service
            .collect_cancellable(
                || false,
                true,
                &CollectionContext::new(
                    Some(Instant::now() + Duration::from_secs(1)),
                    CancellationToken::new(),
                ),
            )
            .unwrap();
        assert!(result.identity.posture_disabled);
        assert!(result.identity.serial_numbers.is_empty());
        assert!(result.identity.iface_hardware_addrs.is_empty());
        assert_eq!(hardware_calls.load(Ordering::Relaxed), 1);
        assert!(service.last_hardware_addrs.lock().unwrap().is_empty());
    }

    #[test]
    fn system_policy_reads_live_typed_snapshots_and_fails_closed() {
        use rustscale_syspolicy::{MemoryProvider, PolicyEngine, PolicyKey, PolicyScope, RawValue};

        let provider = Arc::new(MemoryProvider::from_values(BTreeMap::from([(
            PolicyKey::PostureChecking,
            RawValue::String("never".into()),
        )])));
        let engine = PolicyEngine::well_known(PolicyScope::Device).unwrap();
        engine
            .add_provider("managed posture", PolicyScope::Device, provider.clone())
            .unwrap();
        let policy = SystemPolicy::from_engine(engine);

        assert_eq!(policy.preference(), Ok(PreferenceOption::Never));
        provider.set(
            PolicyKey::PostureChecking,
            RawValue::String("always".into()),
        );
        assert_eq!(policy.preference(), Ok(PreferenceOption::Always));
        provider.set(
            PolicyKey::PostureChecking,
            RawValue::String("invalid".into()),
        );
        assert_eq!(policy.preference(), Err(PolicyError::Unavailable));
    }

    #[test]
    fn hardware_addresses_are_opt_in_and_stable() {
        let (service, _, hardware_calls) = service(PreferenceOption::Always);
        assert!(service
            .collect(false, false)
            .identity
            .iface_hardware_addrs
            .is_empty());
        assert_eq!(hardware_calls.load(Ordering::Relaxed), 0);

        let first = service.collect(false, true).identity.iface_hardware_addrs;
        let second = service.collect(false, true).identity.iface_hardware_addrs;
        assert_eq!(first, vec!["aa:bb:cc:dd:ee:ff"]);
        assert_eq!(second, first);
        assert_eq!(hardware_calls.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn preference_parser_is_exact() {
        assert_eq!("always".parse(), Ok(PreferenceOption::Always));
        assert_eq!("never".parse(), Ok(PreferenceOption::Never));
        assert_eq!("user-decides".parse(), Ok(PreferenceOption::UserDecides));
        assert_eq!("true".parse::<PreferenceOption>(), Err(()));
    }

    #[test]
    fn errors_do_not_include_collected_values() {
        let text = PostureError::InvalidData.to_string();
        assert!(!text.contains("serial-1"));
        assert!(!text.contains('/'));
    }
}
