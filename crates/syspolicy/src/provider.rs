use std::{
    collections::BTreeMap,
    env,
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, Weak,
    },
};

use serde_json::Value;

use crate::{PolicyError, PolicyErrorKind, PolicyKey, RawValue, SettingDefinition, ValueType};

/// Maximum accepted JSON policy file size (1 MiB).
pub const MAX_POLICY_FILE_SIZE: u64 = 1024 * 1024;
/// Maximum accepted value length in the environment provider (64 KiB).
pub const MAX_ENV_VALUE_SIZE: usize = 64 * 1024;

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

/// A provider backed by a bounded JSON object file.
#[derive(Debug, Clone)]
pub struct JsonFileProvider {
    path: PathBuf,
    missing_is_empty: bool,
    max_size: u64,
}

impl JsonFileProvider {
    /// Creates a provider for a required file.
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_owned(),
            missing_is_empty: false,
            max_size: MAX_POLICY_FILE_SIZE,
        }
    }

    /// Creates a provider for an optional file. A missing file is an empty policy.
    pub fn optional(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_owned(),
            missing_is_empty: true,
            max_size: MAX_POLICY_FILE_SIZE,
        }
    }

    /// Overrides the byte limit. Primarily useful for tests.
    pub fn with_max_size(mut self, max_size: u64) -> Self {
        self.max_size = max_size;
        self
    }

    fn read_object(&self) -> Result<serde_json::Map<String, Value>, PolicyError> {
        let mut file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if self.missing_is_empty && error.kind() == io::ErrorKind::NotFound => {
                return Ok(serde_json::Map::new());
            }
            Err(_) => return Err(PolicyError::new(PolicyErrorKind::Io)),
        };
        if file
            .metadata()
            .ok()
            .is_some_and(|metadata| metadata.len() > self.max_size)
        {
            return Err(PolicyError::new(PolicyErrorKind::TooLarge));
        }

        let capacity = usize::try_from(self.max_size.min(64 * 1024)).unwrap_or(64 * 1024);
        let mut contents = Vec::with_capacity(capacity);
        file.by_ref()
            .take(self.max_size.saturating_add(1))
            .read_to_end(&mut contents)
            .map_err(|_| PolicyError::new(PolicyErrorKind::Io))?;
        if u64::try_from(contents.len()).unwrap_or(u64::MAX) > self.max_size {
            return Err(PolicyError::new(PolicyErrorKind::TooLarge));
        }
        let value: Value = serde_json::from_slice(&contents)
            .map_err(|_| PolicyError::new(PolicyErrorKind::Parse))?;
        value
            .as_object()
            .cloned()
            .ok_or_else(|| PolicyError::new(PolicyErrorKind::Parse))
    }
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
            callbacks
                .lock()
                .expect("memory callback lock poisoned")
                .remove(&self.id);
        }
    }
}
