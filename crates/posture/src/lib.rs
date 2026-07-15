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
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod serial_stub;

use std::sync::Mutex;

pub use hwaddr::get_hardware_addrs;
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

/// Managed preference semantics used by Tailscale system policy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PreferenceOption {
    /// The persisted/user preference decides whether collection is enabled.
    #[default]
    UserDecides,
    /// Collection is forced on by management policy.
    Always,
    /// Collection is forced off by management policy.
    Never,
}

impl PreferenceOption {
    /// Parse the Go-compatible policy strings. Unknown values fail closed to
    /// the caller rather than silently forcing collection on.
    pub fn parse(value: &str) -> Result<Self, PolicyError> {
        match value {
            "always" => Ok(Self::Always),
            "never" => Ok(Self::Never),
            "user-decides" => Ok(Self::UserDecides),
            _ => Err(PolicyError::InvalidValue),
        }
    }

    /// Resolve this policy against the user's persisted preference.
    pub const fn should_enable(self, user_enabled: bool) -> bool {
        match self {
            Self::Always => true,
            Self::Never => false,
            Self::UserDecides => user_enabled,
        }
    }
}

/// Privacy-safe policy lookup failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("posture policy is unavailable")]
    Unavailable,
    #[error("posture policy has an invalid value")]
    InvalidValue,
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

/// Live OS-backed posture policy. Linux policy is re-read from the standard
/// bounded JSON policy path on every collection. Other current RustScale
/// targets have no default managed-policy reader here. Missing policy means
/// `user-decides`.
#[derive(Debug, Default)]
pub struct SystemPolicy;

impl PosturePolicy for SystemPolicy {
    fn preference(&self) -> Result<PreferenceOption, PolicyError> {
        use rustscale_syspolicy::{PolicyErrorKind, PolicyKey};

        #[cfg(target_os = "linux")]
        let store = {
            use std::io::Read;

            const MAX_POLICY_BYTES: u64 = 256 * 1024;
            let file = match std::fs::File::open(rustscale_syspolicy::DEFAULT_POLICY_PATH) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(PreferenceOption::UserDecides);
                }
                Err(_) => return Err(PolicyError::Unavailable),
            };
            let mut bytes = Vec::new();
            file.take(MAX_POLICY_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| PolicyError::Unavailable)?;
            if bytes.len() as u64 > MAX_POLICY_BYTES {
                return Err(PolicyError::Unavailable);
            }
            let json = std::str::from_utf8(&bytes).map_err(|_| PolicyError::Unavailable)?;
            rustscale_syspolicy::LinuxPolicyStore::from_json(json)
                .map_err(|_| PolicyError::Unavailable)?
        };
        #[cfg(not(target_os = "linux"))]
        let store = rustscale_syspolicy::default_store();

        match store.get_string(PolicyKey::PostureChecking) {
            Ok(value) => PreferenceOption::parse(&value),
            Err(error) if error.kind == PolicyErrorKind::NotConfigured => {
                Ok(PreferenceOption::UserDecides)
            }
            Err(_) => Err(PolicyError::Unavailable),
        }
    }
}

/// Injectable source of platform posture attributes.
pub trait PostureCollector: Send + Sync {
    fn serial_numbers(&self) -> Result<Vec<String>, PostureError>;
    fn hardware_addrs(&self) -> Result<Vec<String>, PostureError>;
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
        let (preference, policy_error) = match self.policy.preference() {
            Ok(preference) => (preference, None),
            Err(error) => (PreferenceOption::UserDecides, Some(error)),
        };
        if !preference.should_enable(user_enabled) {
            return CollectionResult {
                identity: IdentityData {
                    posture_disabled: true,
                    ..IdentityData::default()
                },
                policy_error,
                ..CollectionResult::default()
            };
        }

        let (serial_numbers, serial_error) = match self.collector.serial_numbers() {
            Ok(values) => (sanitize_serials(values), None),
            Err(error) => (Vec::new(), Some(error)),
        };

        let mut hardware_addr_error = None;
        let iface_hardware_addrs = if include_hardware_addrs {
            match self.collector.hardware_addrs() {
                Ok(values) => {
                    let values = normalize_hardware_addrs(values);
                    let mut previous = self
                        .last_hardware_addrs
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if values.is_empty() {
                        previous.clone()
                    } else {
                        previous.clone_from(&values);
                        values
                    }
                }
                Err(error) => {
                    hardware_addr_error = Some(error);
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };

        CollectionResult {
            identity: IdentityData {
                serial_numbers,
                iface_hardware_addrs,
                posture_disabled: false,
            },
            policy_error,
            serial_error,
            hardware_addr_error,
        }
    }
}

impl Default for IdentityService {
    fn default() -> Self {
        Self::new(Box::new(SystemCollector), Box::new(SystemPolicy))
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
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
    use std::sync::Arc;

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
        assert_eq!(
            PreferenceOption::parse("always"),
            Ok(PreferenceOption::Always)
        );
        assert_eq!(
            PreferenceOption::parse("never"),
            Ok(PreferenceOption::Never)
        );
        assert_eq!(
            PreferenceOption::parse("user-decides"),
            Ok(PreferenceOption::UserDecides)
        );
        assert_eq!(
            PreferenceOption::parse("true"),
            Err(PolicyError::InvalidValue)
        );
    }

    #[test]
    fn errors_do_not_include_collected_values() {
        let text = PostureError::InvalidData.to_string();
        assert!(!text.contains("serial-1"));
        assert!(!text.contains('/'));
    }
}
