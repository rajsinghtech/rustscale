use std::{
    collections::BTreeMap,
    env, fmt,
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, Weak,
    },
    time::{Duration, Instant, UNIX_EPOCH},
};

use serde_json::Value;

use crate::{
    watch::{PollingSubscription, SystemWatchClock, WatchClock, WatchControl},
    PolicyError, PolicyErrorKind, PolicyKey, RawValue, SettingDefinition, ValueType, WatchOptions,
};

/// Maximum accepted JSON policy file size (1 MiB).
pub const MAX_POLICY_FILE_SIZE: u64 = 1024 * 1024;
/// Maximum accepted value length in the environment provider (64 KiB).
pub const MAX_ENV_VALUE_SIZE: usize = 64 * 1024;
/// Maximum wall-clock time spent reading one managed JSON snapshot.
pub const MAX_POLICY_READ_TIME: Duration = Duration::from_secs(2);

/// Values returned by one provider load.
pub type ProviderValues = BTreeMap<PolicyKey, Result<RawValue, PolicyError>>;

/// Keeps a provider change subscription alive.
pub trait ProviderSubscription: Send + Sync {}

/// A concurrency-safe source of raw policy settings.
pub trait PolicyProvider: Send + Sync {
    /// Loads all requested settings as one consistent provider snapshot.
    fn load(&self, definitions: &[SettingDefinition]) -> Result<ProviderValues, PolicyError>;

    /// Subscribes to provider changes, when supported.
    fn subscribe(
        &self,
        _callback: Arc<dyn Fn() + Send + Sync>,
    ) -> Result<Option<Box<dyn ProviderSubscription>>, PolicyError> {
        Ok(None)
    }
}

/// Decides whether metadata for an already-open regular policy file is trusted.
pub trait FileTrustPolicy: Send + Sync {
    /// Returns true only when the opened file is trusted as managed policy.
    fn is_trusted(&self, metadata: &Metadata) -> bool;
}

impl<F> FileTrustPolicy for F
where
    F: Fn(&Metadata) -> bool + Send + Sync,
{
    fn is_trusted(&self, metadata: &Metadata) -> bool {
        self(metadata)
    }
}

/// Production trust policy for managed JSON files.
#[derive(Debug, Default)]
pub struct ProductionFileTrust;

impl FileTrustPolicy for ProductionFileTrust {
    fn is_trusted(&self, metadata: &Metadata) -> bool {
        if !metadata.is_file() {
            return false;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            metadata.uid() == 0 && metadata.mode() & 0o022 == 0
        }
        #[cfg(not(unix))]
        {
            // No ownership/mode proof is available through safe std APIs.
            // Platforms without that proof fail closed unless the embedding
            // application supplies an explicit trust policy.
            false
        }
    }
}

/// A provider backed by a bounded JSON object file.
///
/// Watching is disabled unless [`Self::with_watching`] or
/// [`Self::with_watch_options`] is used. Each subscription then owns one
/// bounded polling worker and joins it during cancellation.
#[derive(Clone)]
pub struct JsonFileProvider {
    path: PathBuf,
    missing_is_empty: bool,
    max_size: u64,
    watch_options: Option<WatchOptions>,
    watch_clock: Arc<dyn WatchClock>,
    trust: Arc<dyn FileTrustPolicy>,
}

impl fmt::Debug for JsonFileProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JsonFileProvider")
            .field("path", &self.path)
            .field("missing_is_empty", &self.missing_is_empty)
            .field("max_size", &self.max_size)
            .field("watch_options", &self.watch_options)
            .field("trust", &"configured")
            .finish_non_exhaustive()
    }
}

impl JsonFileProvider {
    /// Creates a provider for a required file.
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_owned(),
            missing_is_empty: false,
            max_size: MAX_POLICY_FILE_SIZE,
            watch_options: None,
            watch_clock: Arc::new(SystemWatchClock),
            trust: Arc::new(ProductionFileTrust),
        }
    }

    /// Creates a provider for an optional file. A missing file is an empty policy.
    pub fn optional(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_owned(),
            missing_is_empty: true,
            max_size: MAX_POLICY_FILE_SIZE,
            watch_options: None,
            watch_clock: Arc::new(SystemWatchClock),
            trust: Arc::new(ProductionFileTrust),
        }
    }

    /// Lowers the byte limit. Primarily useful for tests.
    pub fn with_max_size(mut self, max_size: u64) -> Self {
        self.max_size = max_size.min(MAX_POLICY_FILE_SIZE);
        self
    }

    /// Replaces the production root-ownership trust policy.
    ///
    /// Callers must not weaken this for production managed policy.
    pub fn with_file_trust(mut self, trust: Arc<dyn FileTrustPolicy>) -> Self {
        self.trust = trust;
        self
    }

    /// Enables polling with bounded default intervals.
    pub fn with_watching(mut self) -> Self {
        self.watch_options = Some(WatchOptions::default());
        self
    }

    /// Enables polling with validated caller-provided intervals.
    pub fn with_watch_options(mut self, options: WatchOptions) -> Self {
        self.watch_options = Some(options);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_watch_clock(mut self, clock: Arc<dyn WatchClock>) -> Self {
        self.watch_clock = clock;
        self
    }

    fn read_object(&self) -> Result<serde_json::Map<String, Value>, PolicyError> {
        let Some((mut file, metadata)) =
            open_managed_file(&self.path, self.missing_is_empty, self.trust.as_ref())?
        else {
            return Ok(serde_json::Map::new());
        };
        let contents = read_bounded(
            &mut file,
            metadata.len(),
            self.max_size,
            Instant::now() + MAX_POLICY_READ_TIME,
            None,
        )?;
        let value: Value = serde_json::from_slice(&contents)
            .map_err(|_| PolicyError::new(PolicyErrorKind::Parse))?;
        value
            .as_object()
            .cloned()
            .ok_or_else(|| PolicyError::new(PolicyErrorKind::Parse))
    }
}

fn open_managed_file(
    path: &Path,
    missing_is_empty: bool,
    trust: &dyn FileTrustPolicy,
) -> Result<Option<(File, Metadata)>, PolicyError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT prevents following the final reparse
        // point. The opened metadata is then required to be a regular file.
        options.custom_flags(0x0020_0000);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if missing_is_empty && error.kind() == io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(_) => return Err(PolicyError::new(PolicyErrorKind::Io)),
    };
    let metadata = file
        .metadata()
        .map_err(|_| PolicyError::new(PolicyErrorKind::Io))?;
    if !metadata.is_file() || !trust.is_trusted(&metadata) {
        return Err(PolicyError::new(PolicyErrorKind::Untrusted));
    }
    Ok(Some((file, metadata)))
}

fn read_bounded(
    reader: &mut impl Read,
    declared_size: u64,
    max_size: u64,
    deadline: Instant,
    control: Option<&WatchControl>,
) -> Result<Vec<u8>, PolicyError> {
    if declared_size > max_size {
        return Err(PolicyError::new(PolicyErrorKind::TooLarge));
    }
    let capacity = usize::try_from(max_size.min(64 * 1024)).unwrap_or(64 * 1024);
    let mut contents = Vec::with_capacity(capacity);
    let mut chunk = [0_u8; 16 * 1024];
    loop {
        if Instant::now() >= deadline || control.is_some_and(WatchControl::is_cancelled) {
            return Err(PolicyError::new(PolicyErrorKind::Io));
        }
        let remaining = max_size
            .saturating_add(1)
            .saturating_sub(u64::try_from(contents.len()).unwrap_or(u64::MAX));
        if remaining == 0 {
            return Err(PolicyError::new(PolicyErrorKind::TooLarge));
        }
        let read_limit = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(chunk.len());
        let count = reader
            .read(&mut chunk[..read_limit])
            .map_err(|_| PolicyError::new(PolicyErrorKind::Io))?;
        if count == 0 {
            break;
        }
        contents.extend_from_slice(&chunk[..count]);
    }
    if u64::try_from(contents.len()).unwrap_or(u64::MAX) > max_size {
        return Err(PolicyError::new(PolicyErrorKind::TooLarge));
    }
    Ok(contents)
}

impl PolicyProvider for JsonFileProvider {
    fn load(&self, definitions: &[SettingDefinition]) -> Result<ProviderValues, PolicyError> {
        let object = self.read_object()?;
        let mut result = BTreeMap::new();
        for definition in definitions {
            let Some(value) = object.get(definition.key.wire_name()) else {
                continue;
            };
            result.insert(
                definition.key,
                raw_from_json(definition.key, definition.value_type, value),
            );
        }
        Ok(result)
    }

    fn subscribe(
        &self,
        callback: Arc<dyn Fn() + Send + Sync>,
    ) -> Result<Option<Box<dyn ProviderSubscription>>, PolicyError> {
        let Some(options) = self.watch_options else {
            return Ok(None);
        };
        let path = self.path.clone();
        let max_size = self.max_size;
        let trust = self.trust.clone();
        PollingSubscription::start(
            "syspolicy-file-watch",
            options,
            self.watch_clock.clone(),
            move |control| file_observation(&path, max_size, trust.as_ref(), control),
            callback,
        )
        .map(Some)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileObservation {
    Missing,
    Error(PolicyErrorKind),
    Present {
        identity: u128,
        modified_nanos: u128,
        len: u64,
        hash: u64,
    },
}

fn file_observation(
    path: &Path,
    max_size: u64,
    trust: &dyn FileTrustPolicy,
    control: &WatchControl,
) -> FileObservation {
    let (mut file, metadata) = match open_managed_file(path, true, trust) {
        Ok(Some(opened)) => opened,
        Ok(None) => return FileObservation::Missing,
        Err(error) => return FileObservation::Error(error.kind),
    };
    let bytes = match read_bounded(
        &mut file,
        metadata.len(),
        max_size,
        Instant::now() + MAX_POLICY_READ_TIME,
        Some(control),
    ) {
        Ok(bytes) => bytes,
        Err(error) => return FileObservation::Error(error.kind),
    };
    let modified_nanos = metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |duration| duration.as_nanos());
    FileObservation::Present {
        identity: file_identity(&metadata),
        modified_nanos,
        len: metadata.len(),
        hash: bounded_hash(&bytes),
    }
}

#[cfg(unix)]
fn file_identity(metadata: &fs::Metadata) -> u128 {
    use std::os::unix::fs::MetadataExt;
    (u128::from(metadata.dev()) << 64) | u128::from(metadata.ino())
}

#[cfg(windows)]
fn file_identity(metadata: &fs::Metadata) -> u128 {
    use std::os::windows::fs::MetadataExt;
    u128::from(metadata.creation_time())
}

#[cfg(not(any(unix, windows)))]
fn file_identity(_metadata: &fs::Metadata) -> u128 {
    0
}

fn bounded_hash(bytes: &[u8]) -> u64 {
    // FNV-1a is sufficient for change detection and avoids retaining policy
    // bytes or introducing an unbounded parser into the polling path.
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn raw_from_json(
    key: PolicyKey,
    value_type: ValueType,
    value: &Value,
) -> Result<RawValue, PolicyError> {
    let mismatch = || PolicyError::for_key(PolicyErrorKind::TypeMismatch, key);
    match value_type {
        ValueType::Boolean => value.as_bool().map(RawValue::Boolean).ok_or_else(mismatch),
        ValueType::Integer => value.as_u64().map(RawValue::Integer).ok_or_else(mismatch),
        ValueType::String
        | ValueType::PreferenceOption
        | ValueType::Visibility
        | ValueType::Duration => value
            .as_str()
            .map(|value| RawValue::String(value.to_owned()))
            .ok_or_else(mismatch),
        ValueType::StringList => {
            let values = value.as_array().ok_or_else(mismatch)?;
            values
                .iter()
                .map(|value| value.as_str().map(ToOwned::to_owned).ok_or_else(mismatch))
                .collect::<Result<Vec<_>, _>>()
                .map(RawValue::StringList)
        }
    }
}

#[cfg(test)]
mod file_security_tests {
    use super::*;
    use std::thread;

    struct CancellingReader<'a> {
        control: &'a WatchControl,
        reads: usize,
    }

    impl Read for CancellingReader<'_> {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            self.reads += 1;
            output[0] = b'{';
            self.control.cancel();
            Ok(1)
        }
    }

    struct SlowReader {
        reads: usize,
    }

    impl Read for SlowReader {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            self.reads += 1;
            thread::sleep(Duration::from_millis(5));
            output[0] = b'{';
            Ok(1)
        }
    }

    #[test]
    fn bounded_read_honors_deadline_and_cancellation_between_chunks() {
        let control = WatchControl::default();
        let mut cancelling = CancellingReader {
            control: &control,
            reads: 0,
        };
        let error = read_bounded(
            &mut cancelling,
            2,
            MAX_POLICY_FILE_SIZE,
            Instant::now() + MAX_POLICY_READ_TIME,
            Some(&control),
        )
        .unwrap_err();
        assert_eq!(error.kind, PolicyErrorKind::Io);
        assert_eq!(cancelling.reads, 1);

        let mut slow = SlowReader { reads: 0 };
        let error = read_bounded(
            &mut slow,
            2,
            MAX_POLICY_FILE_SIZE,
            Instant::now() + Duration::from_millis(1),
            None,
        )
        .unwrap_err();
        assert_eq!(error.kind, PolicyErrorKind::Io);
        assert_eq!(slow.reads, 1);
    }
}

/// A provider for `TS_DEBUGSYSPOLICY_*` environment variables.
#[derive(Debug, Clone, Default)]
pub struct EnvironmentProvider {
    values: Option<Arc<BTreeMap<String, String>>>,
}

impl EnvironmentProvider {
    /// Creates a provider that reads the process environment on every load.
    pub const fn new() -> Self {
        Self { values: None }
    }

    /// Creates a deterministic environment provider, useful for tests.
    pub fn from_map(values: BTreeMap<String, String>) -> Self {
        Self {
            values: Some(Arc::new(values)),
        }
    }

    fn lookup(&self, name: &str) -> Option<Result<String, PolicyError>> {
        if let Some(values) = &self.values {
            return values.get(name).cloned().map(Ok);
        }
        env::var_os(name).map(|value| {
            value
                .into_string()
                .map_err(|_| PolicyError::new(PolicyErrorKind::Parse))
        })
    }
}

impl PolicyProvider for EnvironmentProvider {
    fn load(&self, definitions: &[SettingDefinition]) -> Result<ProviderValues, PolicyError> {
        let mut result = BTreeMap::new();
        for definition in definitions {
            let name = environment_variable_name(definition.key);
            let Some(value) = self.lookup(&name) else {
                continue;
            };
            let raw = value.and_then(|value| {
                if value.len() > MAX_ENV_VALUE_SIZE {
                    return Err(PolicyError::for_key(
                        PolicyErrorKind::TooLarge,
                        definition.key,
                    ));
                }
                raw_from_environment(definition.key, definition.value_type, value)
            });
            if !matches!(&raw, Err(error) if error.kind == PolicyErrorKind::NotConfigured) {
                result.insert(definition.key, raw);
            }
        }
        Ok(result)
    }
}

/// Returns the environment variable used for `key`.
pub fn environment_variable_name(key: PolicyKey) -> String {
    let mut words = vec!["TS_DEBUGSYSPOLICY".to_owned()];
    let mut current = String::new();
    let bytes = key.wire_name().as_bytes();
    for (index, &byte) in bytes.iter().enumerate() {
        if byte == b'/' || byte == b'.' {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            continue;
        }
        let is_upper = byte.is_ascii_uppercase();
        let is_lower = byte.is_ascii_lowercase();
        let is_digit = byte.is_ascii_digit();
        if !(is_upper || is_lower || is_digit) {
            continue;
        }
        let split = if current.is_empty() || index == 0 {
            false
        } else {
            let previous = bytes[index - 1];
            (is_upper
                && (!previous.is_ascii_uppercase()
                    || bytes.get(index + 1).is_some_and(u8::is_ascii_lowercase)))
                || (is_digit && !previous.is_ascii_digit())
                || (is_lower && !(previous.is_ascii_alphabetic()))
        };
        if split {
            words.push(std::mem::take(&mut current));
        }
        current.push(char::from(byte.to_ascii_uppercase()));
    }
    if !current.is_empty() {
        words.push(current);
    }
    words.join("_")
}

fn raw_from_environment(
    key: PolicyKey,
    value_type: ValueType,
    value: String,
) -> Result<RawValue, PolicyError> {
    let mismatch = || PolicyError::for_key(PolicyErrorKind::TypeMismatch, key);
    match value_type {
        ValueType::String
        | ValueType::PreferenceOption
        | ValueType::Visibility
        | ValueType::Duration => Ok(RawValue::String(value)),
        ValueType::Boolean if value.is_empty() => {
            Err(PolicyError::for_key(PolicyErrorKind::NotConfigured, key))
        }
        ValueType::Boolean => parse_go_bool(&value)
            .map(RawValue::Boolean)
            .ok_or_else(mismatch),
        ValueType::Integer if value.is_empty() => {
            Err(PolicyError::for_key(PolicyErrorKind::NotConfigured, key))
        }
        ValueType::Integer => parse_go_u64(&value)
            .map(RawValue::Integer)
            .ok_or_else(mismatch),
        ValueType::StringList => Ok(RawValue::StringList(
            value
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(ToOwned::to_owned)
                .collect(),
        )),
    }
}

fn parse_go_bool(value: &str) -> Option<bool> {
    match value {
        "1" | "t" | "T" | "true" | "TRUE" | "True" => Some(true),
        "0" | "f" | "F" | "false" | "FALSE" | "False" => Some(false),
        _ => None,
    }
}

fn parse_go_u64(value: &str) -> Option<u64> {
    let (radix, digits) = if let Some(value) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        (16, value)
    } else if let Some(value) = value
        .strip_prefix("0b")
        .or_else(|| value.strip_prefix("0B"))
    {
        (2, value)
    } else if let Some(value) = value
        .strip_prefix("0o")
        .or_else(|| value.strip_prefix("0O"))
    {
        (8, value)
    } else if value.len() > 1 && value.starts_with('0') {
        (8, &value[1..])
    } else {
        (10, value)
    };
    if digits.is_empty() {
        return (value == "0").then_some(0);
    }
    u64::from_str_radix(digits, radix).ok()
}

/// An empty provider used on platforms without a safe native implementation.
#[derive(Debug, Default)]
pub struct StubPolicyProvider;

impl StubPolicyProvider {
    /// Creates an empty provider.
    pub const fn new() -> Self {
        Self
    }
}

impl PolicyProvider for StubPolicyProvider {
    fn load(&self, _definitions: &[SettingDefinition]) -> Result<ProviderValues, PolicyError> {
        Ok(BTreeMap::new())
    }
}

type ChangeCallback = Arc<dyn Fn() + Send + Sync>;
type ChangeCallbacks = BTreeMap<u64, ChangeCallback>;

/// A mutable, concurrency-safe provider for tests and embedding overrides.
#[derive(Default)]
pub struct MemoryProvider {
    values: Mutex<ProviderValues>,
    callbacks: Arc<Mutex<ChangeCallbacks>>,
    next_callback: AtomicU64,
}

impl MemoryProvider {
    /// Creates an empty provider.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a provider populated with raw values.
    pub fn from_values(values: BTreeMap<PolicyKey, RawValue>) -> Self {
        Self {
            values: Mutex::new(
                values
                    .into_iter()
                    .map(|(key, value)| (key, Ok(value)))
                    .collect(),
            ),
            ..Self::default()
        }
    }

    /// Sets one value and notifies subscribers.
    pub fn set(&self, key: PolicyKey, value: RawValue) {
        self.values
            .lock()
            .expect("memory policy lock poisoned")
            .insert(key, Ok(value));
        self.notify();
    }

    /// Sets one item-level error and notifies subscribers.
    pub fn set_error(&self, key: PolicyKey, kind: PolicyErrorKind) {
        self.values
            .lock()
            .expect("memory policy lock poisoned")
            .insert(key, Err(PolicyError::for_key(kind, key)));
        self.notify();
    }

    /// Removes one value and notifies subscribers.
    pub fn remove(&self, key: PolicyKey) {
        self.values
            .lock()
            .expect("memory policy lock poisoned")
            .remove(&key);
        self.notify();
    }

    /// Emits a change notification without changing values.
    pub fn notify(&self) {
        let callbacks: Vec<_> = self
            .callbacks
            .lock()
            .expect("memory callback lock poisoned")
            .values()
            .cloned()
            .collect();
        for callback in callbacks {
            callback();
        }
    }
}

impl PolicyProvider for MemoryProvider {
    fn load(&self, definitions: &[SettingDefinition]) -> Result<ProviderValues, PolicyError> {
        let values = self.values.lock().expect("memory policy lock poisoned");
        Ok(definitions
            .iter()
            .filter_map(|definition| {
                values
                    .get(&definition.key)
                    .cloned()
                    .map(|value| (definition.key, value))
            })
            .collect())
    }

    fn subscribe(
        &self,
        callback: Arc<dyn Fn() + Send + Sync>,
    ) -> Result<Option<Box<dyn ProviderSubscription>>, PolicyError> {
        let id = self.next_callback.fetch_add(1, Ordering::Relaxed);
        self.callbacks
            .lock()
            .expect("memory callback lock poisoned")
            .insert(id, callback);
        Ok(Some(Box::new(MemorySubscription {
            callbacks: Arc::downgrade(&self.callbacks),
            id,
        })))
    }
}

struct MemorySubscription {
    callbacks: Weak<Mutex<ChangeCallbacks>>,
    id: u64,
}

impl ProviderSubscription for MemorySubscription {}

impl Drop for MemorySubscription {
    fn drop(&mut self) {
        if let Some(callbacks) = self.callbacks.upgrade() {
            let callback = callbacks
                .lock()
                .expect("memory callback lock poisoned")
                .remove(&self.id);
            // A callback may own another subscription whose Drop re-enters
            // this map. Release the mutex before dropping the closure.
            drop(callback);
        }
    }
}
