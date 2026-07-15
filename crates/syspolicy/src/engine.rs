use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, RwLock, Weak,
    },
    thread,
    time::Duration,
};

use serde::{Deserialize, Serialize};

use crate::{
    well_known_definitions, PolicyError, PolicyErrorKind, PolicyKey, PolicyProvider, PolicyScope,
    PolicyValue, PreferenceOption, ProviderSubscription, RawValue, SettingDefinition, ValueType,
    Visibility,
};

/// The source and management scope of an effective setting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Origin {
    /// Human-readable provider name. It must not contain policy values.
    pub name: String,
    /// Scope at which the value was configured.
    pub scope: PolicyScope,
}

/// One effective setting, including its source or item-level read error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyItem {
    /// Converted value, absent when `error` is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<PolicyValue>,
    /// Item-level provider or conversion error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<PolicyError>,
    /// Winning provider.
    pub origin: Origin,
}

/// An immutable effective policy snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    scope: PolicyScope,
    generation: u64,
    settings: BTreeMap<PolicyKey, PolicyItem>,
}

impl Snapshot {
    fn empty(scope: PolicyScope) -> Self {
        Self {
            scope,
            generation: 0,
            settings: BTreeMap::new(),
        }
    }

    /// Scope for which this snapshot was merged.
    pub const fn scope(&self) -> &PolicyScope {
        &self.scope
    }

    /// Monotonically increasing reload generation.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Number of configured settings and item-level errors.
    pub fn len(&self) -> usize {
        self.settings.len()
    }

    /// Reports whether no settings are configured.
    pub fn is_empty(&self) -> bool {
        self.settings.is_empty()
    }

    /// Iterates settings in deterministic [`PolicyKey`] order.
    pub fn iter(&self) -> impl Iterator<Item = (&PolicyKey, &PolicyItem)> {
        self.settings.iter()
    }

    /// Returns an item, including origin and any item-level error.
    pub fn item(&self, key: PolicyKey) -> Option<&PolicyItem> {
        self.settings.get(&key)
    }

    /// Returns an effective value, a stored item error, or `NotConfigured`.
    pub fn get(&self, key: PolicyKey) -> Result<PolicyValue, PolicyError> {
        let item = self
            .settings
            .get(&key)
            .ok_or_else(|| PolicyError::for_key(PolicyErrorKind::NotConfigured, key))?;
        if let Some(error) = &item.error {
            return Err(error.clone());
        }
        item.value
            .clone()
            .ok_or_else(|| PolicyError::for_key(PolicyErrorKind::Provider, key))
    }
}

/// Old and new snapshots delivered after an effective item change.
#[derive(Debug, Clone)]
pub struct PolicyChange {
    /// Snapshot before the change.
    pub old: Arc<Snapshot>,
    /// Snapshot after the change.
    pub new: Arc<Snapshot>,
}

impl PolicyChange {
    /// Reports whether one effective item changed.
    pub fn has_changed(&self, key: PolicyKey) -> bool {
        self.old.item(key) != self.new.item(key)
    }

    /// Reports whether any listed effective item changed.
    pub fn has_changed_any(&self, keys: &[PolicyKey]) -> bool {
        keys.iter().copied().any(|key| self.has_changed(key))
    }
}

/// Stable identifier for a registered provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProviderId(u64);

struct SourceEntry {
    id: ProviderId,
    name: String,
    scope: PolicyScope,
    provider: Arc<dyn PolicyProvider>,
    _subscription: Option<Box<dyn ProviderSubscription>>,
}

#[derive(Clone)]
struct ReadSource {
    id: ProviderId,
    name: String,
    scope: PolicyScope,
    provider: Arc<dyn PolicyProvider>,
}

type ChangeCallback = Arc<dyn Fn(PolicyChange) + Send + Sync>;

struct EngineInner {
    scope: PolicyScope,
    definitions: BTreeMap<PolicyKey, SettingDefinition>,
    sources: RwLock<Vec<SourceEntry>>,
    snapshot: RwLock<Arc<Snapshot>>,
    reload: Mutex<()>,
    callbacks: Mutex<BTreeMap<u64, ChangeCallback>>,
    next_source: AtomicU64,
    next_callback: AtomicU64,
}

/// Concurrent effective-policy engine.
///
/// Providers are loaded concurrently, then merged deterministically. Device
/// scope wins over profile scope, which wins over user scope. For providers at
/// the same scope, the later registration wins.
#[derive(Clone)]
pub struct PolicyEngine {
    inner: Arc<EngineInner>,
}

impl PolicyEngine {
    /// Creates an engine with an explicit definition set.
    pub fn new(
        scope: PolicyScope,
        definitions: impl IntoIterator<Item = SettingDefinition>,
    ) -> Result<Self, PolicyError> {
        let mut definition_map = BTreeMap::new();
        for definition in definitions {
            if let Some(existing) = definition_map.insert(definition.key, definition) {
                if existing != definition {
                    return Err(PolicyError::for_key(
                        PolicyErrorKind::InvalidDefinition,
                        definition.key,
                    ));
                }
            }
        }
        let snapshot = Arc::new(Snapshot::empty(scope.clone()));
        Ok(Self {
            inner: Arc::new(EngineInner {
                scope,
                definitions: definition_map,
                sources: RwLock::new(Vec::new()),
                snapshot: RwLock::new(snapshot),
                reload: Mutex::new(()),
                callbacks: Mutex::new(BTreeMap::new()),
                next_source: AtomicU64::new(0),
                next_callback: AtomicU64::new(0),
            }),
        })
    }

    /// Creates an engine with all built-in definitions.
    pub fn well_known(scope: PolicyScope) -> Result<Self, PolicyError> {
        Self::new(scope, well_known_definitions())
    }

    /// Registers a named provider and immediately reloads the effective policy.
    pub fn add_provider(
        &self,
        name: impl Into<String>,
        scope: PolicyScope,
        provider: Arc<dyn PolicyProvider>,
    ) -> Result<ProviderId, PolicyError> {
        let id = ProviderId(self.inner.next_source.fetch_add(1, Ordering::Relaxed));
        let weak = Arc::downgrade(&self.inner);
        let callback: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            if let Some(inner) = weak.upgrade() {
                // Provider notifications are advisory. A failed refresh leaves
                // the last known-good snapshot installed.
                let _ = PolicyEngine { inner }.reload();
            }
        });
        let subscription = provider.subscribe(callback)?;
        self.inner
            .sources
            .write()
            .expect("policy sources lock poisoned")
            .push(SourceEntry {
                id,
                name: name.into(),
                scope,
                provider,
                _subscription: subscription,
            });
        if let Err(error) = self.reload() {
            self.inner
                .sources
                .write()
                .expect("policy sources lock poisoned")
                .retain(|source| source.id != id);
            return Err(error);
        }
        Ok(id)
    }

    /// Unregisters a provider and reloads the remaining sources.
    pub fn remove_provider(&self, id: ProviderId) -> Result<(), PolicyError> {
        self.inner
            .sources
            .write()
            .expect("policy sources lock poisoned")
            .retain(|source| source.id != id);
        self.reload().map(|_| ())
    }

    /// Returns the current immutable snapshot without provider I/O.
    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.inner
            .snapshot
            .read()
            .expect("policy snapshot lock poisoned")
            .clone()
    }

    /// Concurrently reloads providers and atomically installs the merged snapshot.
    ///
    /// If a provider-wide read fails, the old snapshot remains current. Errors
    /// for individual settings are retained in the new snapshot instead.
    pub fn reload(&self) -> Result<Arc<Snapshot>, PolicyError> {
        let reload_guard = self
            .inner
            .reload
            .lock()
            .expect("policy reload lock poisoned");
        let mut sources: Vec<_> = self
            .inner
            .sources
            .read()
            .expect("policy sources lock poisoned")
            .iter()
            .map(|source| ReadSource {
                id: source.id,
                name: source.name.clone(),
                scope: source.scope.clone(),
                provider: source.provider.clone(),
            })
            .filter(|source| source.scope.contains(&self.inner.scope))
            .collect();

        // Low precedence first. Stable IDs make same-scope last-registration
        // wins independent of provider completion or map iteration order.
        sources.sort_by(|a, b| {
            b.scope
                .kind()
                .cmp(&a.scope.kind())
                .then_with(|| a.id.cmp(&b.id))
        });

        let loaded = thread::scope(|thread_scope| {
            let mut handles = Vec::with_capacity(sources.len());
            for source in &sources {
                let definitions: Vec<_> = self
                    .inner
                    .definitions
                    .values()
                    .copied()
                    .filter(|definition| {
                        self.inner.scope.is_applicable(definition)
                            && source.scope.can_configure(definition)
                    })
                    .collect();
                handles.push(thread_scope.spawn(move || source.provider.load(&definitions)));
            }
            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .unwrap_or_else(|_| Err(PolicyError::new(PolicyErrorKind::Provider)))
                })
                .collect::<Vec<_>>()
        });

        let mut settings = BTreeMap::new();
        for (source, values) in sources.iter().zip(loaded) {
            let values = values?;
            let origin = Origin {
                name: source.name.clone(),
                scope: source.scope.clone(),
            };
            for (key, raw) in values {
                let Some(definition) = self.inner.definitions.get(&key) else {
                    continue;
                };
                let item = match raw
                    .and_then(|raw| PolicyValue::convert(key, definition.value_type, raw))
                {
                    Ok(value) => PolicyItem {
                        value: Some(value),
                        error: None,
                        origin: origin.clone(),
                    },
                    Err(error) if error.kind == PolicyErrorKind::NotConfigured => continue,
                    Err(error) => PolicyItem {
                        value: None,
                        error: Some(error),
                        origin: origin.clone(),
                    },
                };
                settings.insert(key, item);
            }
        }

        let old = self.snapshot();
        let new = Arc::new(Snapshot {
            scope: self.inner.scope.clone(),
            generation: old.generation.saturating_add(1),
            settings,
        });
        *self
            .inner
            .snapshot
            .write()
            .expect("policy snapshot lock poisoned") = new.clone();
        // Callbacks may request another reload, so never invoke them while the
        // reload serialization mutex is held.
        drop(reload_guard);

        if old.settings != new.settings {
            let callbacks: Vec<_> = self
                .inner
                .callbacks
                .lock()
                .expect("policy callbacks lock poisoned")
                .values()
                .cloned()
                .collect();
            let change = PolicyChange {
                old,
                new: new.clone(),
            };
            for callback in callbacks {
                callback(change.clone());
            }
        }
        Ok(new)
    }

    /// Registers an effective-policy change callback.
    pub fn register_change_callback(
        &self,
        callback: impl Fn(PolicyChange) + Send + Sync + 'static,
    ) -> CallbackRegistration {
        let id = self.inner.next_callback.fetch_add(1, Ordering::Relaxed);
        self.inner
            .callbacks
            .lock()
            .expect("policy callbacks lock poisoned")
            .insert(id, Arc::new(callback));
        CallbackRegistration {
            engine: Arc::downgrade(&self.inner),
            id,
        }
    }

    /// Installs a scoped, last-registered device policy override for tests.
    pub fn override_for_test(
        &self,
        values: BTreeMap<PolicyKey, RawValue>,
    ) -> Result<TestOverride, PolicyError> {
        let provider = Arc::new(crate::MemoryProvider::from_values(values));
        let id = self.add_provider("test override", PolicyScope::Device, provider)?;
        Ok(TestOverride {
            engine: Arc::downgrade(&self.inner),
            id,
        })
    }

    fn definition(&self, key: PolicyKey, value_type: ValueType) -> Result<(), PolicyError> {
        let definition = self
            .inner
            .definitions
            .get(&key)
            .ok_or_else(|| PolicyError::for_key(PolicyErrorKind::NoSuchKey, key))?;
        if definition.value_type != value_type {
            return Err(PolicyError::for_key(PolicyErrorKind::TypeMismatch, key));
        }
        Ok(())
    }

    /// Gets a string, using `default` only when it is not configured.
    pub fn get_string(&self, key: PolicyKey, default: &str) -> Result<String, PolicyError> {
        self.definition(key, ValueType::String)?;
        match self.snapshot().get(key) {
            Ok(PolicyValue::String(value)) => Ok(value),
            Err(error) if error.kind == PolicyErrorKind::NotConfigured => Ok(default.to_owned()),
            Err(error) => Err(error),
            _ => Err(PolicyError::for_key(PolicyErrorKind::TypeMismatch, key)),
        }
    }

    /// Gets a boolean, using `default` only when it is not configured.
    pub fn get_bool(&self, key: PolicyKey, default: bool) -> Result<bool, PolicyError> {
        self.definition(key, ValueType::Boolean)?;
        match self.snapshot().get(key) {
            Ok(PolicyValue::Boolean(value)) => Ok(value),
            Err(error) if error.kind == PolicyErrorKind::NotConfigured => Ok(default),
            Err(error) => Err(error),
            _ => Err(PolicyError::for_key(PolicyErrorKind::TypeMismatch, key)),
        }
    }

    /// Gets an integer, using `default` only when it is not configured.
    pub fn get_u64(&self, key: PolicyKey, default: u64) -> Result<u64, PolicyError> {
        self.definition(key, ValueType::Integer)?;
        match self.snapshot().get(key) {
            Ok(PolicyValue::Integer(value)) => Ok(value),
            Err(error) if error.kind == PolicyErrorKind::NotConfigured => Ok(default),
            Err(error) => Err(error),
            _ => Err(PolicyError::for_key(PolicyErrorKind::TypeMismatch, key)),
        }
    }

    /// Gets a string list, using `default` only when it is not configured.
    pub fn get_string_list(
        &self,
        key: PolicyKey,
        default: &[String],
    ) -> Result<Vec<String>, PolicyError> {
        self.definition(key, ValueType::StringList)?;
        match self.snapshot().get(key) {
            Ok(PolicyValue::StringList(value)) => Ok(value),
            Err(error) if error.kind == PolicyErrorKind::NotConfigured => Ok(default.to_vec()),
            Err(error) => Err(error),
            _ => Err(PolicyError::for_key(PolicyErrorKind::TypeMismatch, key)),
        }
    }

    /// Gets a preference option, using `default` only when it is not configured.
    pub fn get_preference_option(
        &self,
        key: PolicyKey,
        default: PreferenceOption,
    ) -> Result<PreferenceOption, PolicyError> {
        self.definition(key, ValueType::PreferenceOption)?;
        match self.snapshot().get(key) {
            Ok(PolicyValue::PreferenceOption(value)) => Ok(value),
            Err(error) if error.kind == PolicyErrorKind::NotConfigured => Ok(default),
            Err(error) => Err(error),
            _ => Err(PolicyError::for_key(PolicyErrorKind::TypeMismatch, key)),
        }
    }

    /// Gets visibility, defaulting to [`Visibility::Show`] only when absent.
    pub fn get_visibility(&self, key: PolicyKey) -> Result<Visibility, PolicyError> {
        self.definition(key, ValueType::Visibility)?;
        match self.snapshot().get(key) {
            Ok(PolicyValue::Visibility(value)) => Ok(value),
            Err(error) if error.kind == PolicyErrorKind::NotConfigured => Ok(Visibility::Show),
            Err(error) => Err(error),
            _ => Err(PolicyError::for_key(PolicyErrorKind::TypeMismatch, key)),
        }
    }

    /// Gets a duration, using `default` only when it is not configured.
    pub fn get_duration(&self, key: PolicyKey, default: Duration) -> Result<Duration, PolicyError> {
        self.definition(key, ValueType::Duration)?;
        match self.snapshot().get(key) {
            Ok(PolicyValue::Duration(value)) => Ok(value),
            Err(error) if error.kind == PolicyErrorKind::NotConfigured => Ok(default),
            Err(error) => Err(error),
            _ => Err(PolicyError::for_key(PolicyErrorKind::TypeMismatch, key)),
        }
    }
}

/// Unregisters a callback when dropped.
pub struct CallbackRegistration {
    engine: Weak<EngineInner>,
    id: u64,
}

impl Drop for CallbackRegistration {
    fn drop(&mut self) {
        if let Some(engine) = self.engine.upgrade() {
            engine
                .callbacks
                .lock()
                .expect("policy callbacks lock poisoned")
                .remove(&self.id);
        }
    }
}

/// Removes a test policy override when dropped.
pub struct TestOverride {
    engine: Weak<EngineInner>,
    id: ProviderId,
}

impl Drop for TestOverride {
    fn drop(&mut self) {
        if let Some(inner) = self.engine.upgrade() {
            let _ = PolicyEngine { inner }.remove_provider(self.id);
        }
    }
}
