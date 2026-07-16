use std::{
    collections::BTreeMap,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{self, RecvTimeoutError, SyncSender, TrySendError},
        Arc, Mutex, RwLock, Weak,
    },
    thread,
    time::Duration,
};

use serde::{Deserialize, Serialize};

use crate::{
    well_known_definitions, PolicyError, PolicyErrorKind, PolicyKey, PolicyProvider, PolicyScope,
    PolicyValue, PreferenceOption, ProviderSubscription, ProviderValues, RawValue,
    SettingDefinition, ValueType, Visibility,
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

    /// Monotonically increasing effective snapshot-commit generation.
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

/// A provider refresh result delivered inside the snapshot commit transaction.
#[derive(Debug, Clone)]
pub enum SnapshotCommit {
    /// A fully loaded effective snapshot.
    Applied(Arc<Snapshot>),
    /// A snapshot containing cached values because at least one provider load
    /// failed during a recovery operation.
    Degraded {
        snapshot: Arc<Snapshot>,
        error: PolicyError,
    },
    /// A provider refresh failure; the previous snapshot remains installed.
    Failed {
        snapshot: Arc<Snapshot>,
        /// Monotonic commit-attempt generation allocated to this failure.
        generation: u64,
        /// Privacy-safe provider failure.
        error: PolicyError,
    },
}

impl SnapshotCommit {
    /// Monotonic generation for this applied change or failed refresh.
    pub fn generation(&self) -> u64 {
        match self {
            Self::Applied(snapshot) | Self::Degraded { snapshot, .. } => snapshot.generation(),
            Self::Failed { generation, .. } => *generation,
        }
    }

    /// Snapshot installed for this status, or retained by a failed refresh.
    pub fn snapshot(&self) -> &Arc<Snapshot> {
        match self {
            Self::Applied(snapshot)
            | Self::Degraded { snapshot, .. }
            | Self::Failed { snapshot, .. } => snapshot,
        }
    }

    /// Whether this status includes stale cached values or a failed refresh.
    pub fn is_degraded(&self) -> bool {
        !matches!(self, Self::Applied(_))
    }
}

/// Stable identifier for a registered provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProviderId(u64);

/// Precedence among providers configured at the same management scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProviderPrecedence {
    /// Development-only environment overrides.
    Debug,
    /// Platform-native policy that is not protected managed policy.
    Platform,
    /// Protected policy, such as a root-owned file or machine policy store.
    Managed,
    /// Scoped test-only override.
    TestOverride,
}

struct SourceEntry {
    id: ProviderId,
    name: String,
    scope: PolicyScope,
    precedence: ProviderPrecedence,
    provider: Arc<dyn PolicyProvider>,
    cached_values: Option<ProviderValues>,
    _subscription: Option<Box<dyn ProviderSubscription>>,
}

#[derive(Clone)]
struct ReadSource {
    id: ProviderId,
    name: String,
    scope: PolicyScope,
    precedence: ProviderPrecedence,
    provider: Arc<dyn PolicyProvider>,
    cached_values: Option<ProviderValues>,
}

type ChangeCallback = Arc<dyn Fn(PolicyChange) + Send + Sync>;
type SnapshotCommitCallback = Arc<dyn Fn(SnapshotCommit) + Send + Sync>;

/// Releases an external transaction barrier acquired before a policy commit.
/// The engine invokes releases in reverse acquisition order after installing
/// commit state and capturing callbacks, and before invoking callbacks.
pub type SnapshotCommitRelease = Box<dyn FnOnce() + Send + 'static>;

type SnapshotPreCommitHook = Arc<dyn Fn(&SnapshotCommit) -> SnapshotCommitRelease + Send + Sync>;

struct CommitHookReleases {
    releases: Vec<SnapshotCommitRelease>,
}

impl CommitHookReleases {
    fn release(mut self) -> u64 {
        let mut panics = 0_u64;
        while let Some(release) = self.releases.pop() {
            if catch_unwind(AssertUnwindSafe(release)).is_err() {
                panics = panics.saturating_add(1);
            }
        }
        panics
    }
}

impl Drop for CommitHookReleases {
    fn drop(&mut self) {
        while let Some(release) = self.releases.pop() {
            let _ = catch_unwind(AssertUnwindSafe(release));
        }
    }
}

struct PendingSnapshotCommit {
    commit: SnapshotCommit,
    callbacks: Vec<SnapshotCommitCallback>,
}

type RefreshResult = (
    Arc<Snapshot>,
    Option<PolicyChange>,
    Option<PendingSnapshotCommit>,
);

struct EngineCommitState {
    snapshot: Arc<Snapshot>,
    commit: SnapshotCommit,
}

struct EngineInner {
    scope: PolicyScope,
    definitions: BTreeMap<PolicyKey, SettingDefinition>,
    sources: RwLock<Vec<SourceEntry>>,
    commit_state: RwLock<EngineCommitState>,
    reload: Mutex<()>,
    callbacks: Mutex<BTreeMap<u64, ChangeCallback>>,
    snapshot_commit_callbacks: Mutex<BTreeMap<u64, SnapshotCommitCallback>>,
    snapshot_pre_commit_hooks: Mutex<BTreeMap<u64, SnapshotPreCommitHook>>,
    next_source: AtomicU64,
    next_callback: AtomicU64,
    next_generation: AtomicU64,
    notification_tx: SyncSender<()>,
    last_reload_error: RwLock<Option<PolicyError>>,
    provider_errors: RwLock<BTreeMap<ProviderId, PolicyError>>,
    reload_attempts: AtomicU64,
    callback_panics: AtomicU64,
}

/// Concurrent effective-policy engine.
///
/// Providers are loaded concurrently, then merged deterministically. Device
/// scope wins over profile scope, which wins over user scope. Explicit
/// provider precedence resolves same-scope classes; within a class, the later
/// registration wins.
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
        let current_commit = SnapshotCommit::Applied(snapshot.clone());
        let (notification_tx, notification_rx) = mpsc::sync_channel(1);
        let inner = Arc::new(EngineInner {
            scope,
            definitions: definition_map,
            sources: RwLock::new(Vec::new()),
            commit_state: RwLock::new(EngineCommitState {
                snapshot,
                commit: current_commit,
            }),
            reload: Mutex::new(()),
            callbacks: Mutex::new(BTreeMap::new()),
            snapshot_commit_callbacks: Mutex::new(BTreeMap::new()),
            snapshot_pre_commit_hooks: Mutex::new(BTreeMap::new()),
            next_source: AtomicU64::new(0),
            next_callback: AtomicU64::new(0),
            next_generation: AtomicU64::new(0),
            notification_tx,
            last_reload_error: RwLock::new(None),
            provider_errors: RwLock::new(BTreeMap::new()),
            reload_attempts: AtomicU64::new(0),
            callback_panics: AtomicU64::new(0),
        });
        let weak = Arc::downgrade(&inner);
        thread::Builder::new()
            .name("syspolicy-reload".into())
            .spawn(move || {
                const INITIAL_RETRY: Duration = Duration::from_millis(10);
                const MAX_RETRY: Duration = Duration::from_secs(1);
                while notification_rx.recv().is_ok() {
                    while notification_rx.try_recv().is_ok() {}
                    let mut retry = INITIAL_RETRY;
                    loop {
                        let Some(inner) = weak.upgrade() else {
                            return;
                        };
                        let result = PolicyEngine { inner }.reload();
                        if result.is_ok() {
                            break;
                        }
                        // Keep the observation pending. A new observation
                        // coalesces into this retry loop and resets backoff;
                        // disconnect/cancellation exits without spinning.
                        match notification_rx.recv_timeout(retry) {
                            Ok(()) => {
                                while notification_rx.try_recv().is_ok() {}
                                retry = INITIAL_RETRY;
                            }
                            Err(RecvTimeoutError::Timeout) => {
                                retry = retry.saturating_mul(2).min(MAX_RETRY);
                            }
                            Err(RecvTimeoutError::Disconnected) => return,
                        }
                    }
                }
            })
            .map_err(|_| PolicyError::new(PolicyErrorKind::Provider))?;
        Ok(Self { inner })
    }

    /// Creates an engine with all built-in definitions.
    pub fn well_known(scope: PolicyScope) -> Result<Self, PolicyError> {
        Self::new(scope, well_known_definitions())
    }

    /// Registers a managed provider and immediately reloads effective policy.
    pub fn add_provider(
        &self,
        name: impl Into<String>,
        scope: PolicyScope,
        provider: Arc<dyn PolicyProvider>,
    ) -> Result<ProviderId, PolicyError> {
        self.add_provider_with_precedence(name, scope, ProviderPrecedence::Managed, provider)
    }

    /// Registers a provider with explicit same-scope precedence.
    pub fn add_provider_with_precedence(
        &self,
        name: impl Into<String>,
        scope: PolicyScope,
        precedence: ProviderPrecedence,
        provider: Arc<dyn PolicyProvider>,
    ) -> Result<ProviderId, PolicyError> {
        let id = ProviderId(self.inner.next_source.fetch_add(1, Ordering::Relaxed));
        let notification_tx = self.inner.notification_tx.clone();
        let callback: Arc<dyn Fn() + Send + Sync> =
            Arc::new(move || match notification_tx.try_send(()) {
                Ok(()) | Err(TrySendError::Full(()) | TrySendError::Disconnected(())) => {}
            });
        let subscription = provider.subscribe(callback)?;
        let reload_guard = self
            .inner
            .reload
            .lock()
            .expect("policy reload lock poisoned");
        self.inner
            .sources
            .write()
            .expect("policy sources lock poisoned")
            .push(SourceEntry {
                id,
                name: name.into(),
                scope,
                precedence,
                provider,
                cached_values: None,
                _subscription: subscription,
            });
        match self.refresh_locked(false) {
            Ok((_, change, pending_commit)) => {
                drop(reload_guard);
                if let Some(pending_commit) = pending_commit {
                    self.invoke_snapshot_commit(pending_commit);
                }
                self.invoke_change(change);
                Ok(id)
            }
            Err(error) => {
                let pending_commit = self.stage_failed_commit_locked(error.clone()).ok();
                let removed = self.take_source(id).map(|(_, source)| source);
                self.inner
                    .provider_errors
                    .write()
                    .expect("policy provider error lock poisoned")
                    .remove(&id);
                drop(reload_guard);
                if let Some(pending_commit) = pending_commit {
                    self.invoke_snapshot_commit(pending_commit);
                }
                drop(removed);
                Err(error)
            }
        }
    }

    /// Unregisters a provider and transactionally removes its effective items.
    /// A failing remaining provider contributes its last successful values and
    /// leaves a diagnostic rather than disappearing from effective policy.
    pub fn remove_provider(&self, id: ProviderId) -> Result<(), PolicyError> {
        let reload_guard = self
            .inner
            .reload
            .lock()
            .expect("policy reload lock poisoned");
        let Some((index, removed)) = self.take_source(id) else {
            drop(reload_guard);
            return Ok(());
        };
        let (_, change, pending_commit) = match self.refresh_locked(true) {
            Ok(result) => result,
            Err(error) => {
                let pending_commit = self.stage_failed_commit_locked(error.clone()).ok();
                self.inner
                    .sources
                    .write()
                    .expect("policy sources lock poisoned")
                    .insert(index, removed);
                drop(reload_guard);
                if let Some(pending_commit) = pending_commit {
                    self.invoke_snapshot_commit(pending_commit);
                }
                return Err(error);
            }
        };
        drop(reload_guard);
        if let Some(pending_commit) = pending_commit {
            self.invoke_snapshot_commit(pending_commit);
        }
        // Provider subscriptions may call back while being dropped. Never drop
        // them while either the source-list or reload mutex is held.
        drop(removed);
        self.inner
            .provider_errors
            .write()
            .expect("policy provider error lock poisoned")
            .remove(&id);
        self.invoke_change(change);
        Ok(())
    }

    fn take_source(&self, id: ProviderId) -> Option<(usize, SourceEntry)> {
        let mut sources = self
            .inner
            .sources
            .write()
            .expect("policy sources lock poisoned");
        let index = sources.iter().position(|source| source.id == id)?;
        Some((index, sources.remove(index)))
    }

    /// Returns the current immutable snapshot without provider I/O.
    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.inner
            .commit_state
            .read()
            .expect("policy commit state lock poisoned")
            .snapshot
            .clone()
    }

    /// Returns the current applied, degraded, or failed commit status without
    /// provider I/O.
    pub fn current_snapshot_commit(&self) -> SnapshotCommit {
        self.inner
            .commit_state
            .read()
            .expect("policy commit state lock poisoned")
            .commit
            .clone()
    }

    /// Concurrently reloads providers and atomically installs a changed merged
    /// snapshot. An unchanged successful refresh retains the current generation.
    ///
    /// If a provider-wide read fails, the old snapshot remains current and a
    /// synchronous failed commit event is emitted before return. Errors for
    /// individual settings are retained in a changed new snapshot instead.
    pub fn reload(&self) -> Result<Arc<Snapshot>, PolicyError> {
        let reload_guard = self
            .inner
            .reload
            .lock()
            .expect("policy reload lock poisoned");
        let result = self.refresh_locked(false);
        let failed_commit = result
            .as_ref()
            .err()
            .and_then(|error| self.stage_failed_commit_locked(error.clone()).ok());
        drop(reload_guard);
        match result {
            Ok((snapshot, change, pending_commit)) => {
                if let Some(pending_commit) = pending_commit {
                    self.invoke_snapshot_commit(pending_commit);
                }
                self.invoke_change(change);
                Ok(snapshot)
            }
            Err(error) => {
                if let Some(failed_commit) = failed_commit {
                    self.invoke_snapshot_commit(failed_commit);
                }
                Err(error)
            }
        }
    }

    fn refresh_locked(&self, recover_provider_errors: bool) -> Result<RefreshResult, PolicyError> {
        self.inner.reload_attempts.fetch_add(1, Ordering::Relaxed);
        let had_reload_error = self
            .inner
            .last_reload_error
            .read()
            .expect("policy error lock poisoned")
            .is_some();
        if recover_provider_errors {
            *self
                .inner
                .last_reload_error
                .write()
                .expect("policy error lock poisoned") = None;
        }
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
                precedence: source.precedence,
                provider: source.provider.clone(),
                cached_values: source.cached_values.clone(),
            })
            .filter(|source| source.scope.contains(&self.inner.scope))
            .collect();

        // Low precedence first. Scope precedence remains primary; explicit
        // provider precedence and stable IDs resolve same-scope conflicts.
        sources.sort_by(|a, b| {
            b.scope
                .kind()
                .cmp(&a.scope.kind())
                .then_with(|| a.precedence.cmp(&b.precedence))
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
                handles.push(thread_scope.spawn(move || {
                    let allowed: BTreeMap<_, _> = definitions
                        .iter()
                        .map(|definition| (definition.key, *definition))
                        .collect();
                    let values = source.provider.load(&definitions)?;
                    if values.keys().any(|key| !allowed.contains_key(key)) {
                        return Err(PolicyError::new(PolicyErrorKind::ProviderViolation));
                    }
                    Ok(values)
                }));
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

        {
            let mut diagnostics = self
                .inner
                .provider_errors
                .write()
                .expect("policy provider error lock poisoned");
            for (source, result) in sources.iter().zip(&loaded) {
                match result {
                    Ok(_) => {
                        diagnostics.remove(&source.id);
                    }
                    Err(error) => {
                        diagnostics.insert(source.id, error.clone());
                    }
                }
            }
        }

        let mut first_error = None;
        let mut staged_caches = Vec::new();
        let mut effective_values = Vec::with_capacity(sources.len());
        for (source, values) in sources.iter().zip(loaded) {
            match values {
                Ok(values) => {
                    staged_caches.push((source.id, values.clone()));
                    effective_values.push(values);
                }
                Err(error) if recover_provider_errors => {
                    let Some(cached) = source.cached_values.clone() else {
                        *self
                            .inner
                            .last_reload_error
                            .write()
                            .expect("policy error lock poisoned") = Some(error.clone());
                        return Err(error);
                    };
                    first_error.get_or_insert(error);
                    effective_values.push(cached);
                }
                Err(error) => {
                    *self
                        .inner
                        .last_reload_error
                        .write()
                        .expect("policy error lock poisoned") = Some(error.clone());
                    return Err(error);
                }
            }
        }

        let mut settings = BTreeMap::new();
        for (source, values) in sources.iter().zip(effective_values) {
            let origin = Origin {
                name: source.name.clone(),
                scope: source.scope.clone(),
            };
            for (key, raw) in values {
                let definition = self
                    .inner
                    .definitions
                    .get(&key)
                    .expect("provider allowlist validated");
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

        {
            let mut entries = self
                .inner
                .sources
                .write()
                .expect("policy sources lock poisoned");
            for (id, values) in staged_caches {
                if let Some(entry) = entries.iter_mut().find(|entry| entry.id == id) {
                    entry.cached_values = Some(values);
                }
            }
        }
        let degraded_error = first_error.clone();
        let retry_failed_provider = first_error.is_some();
        *self
            .inner
            .last_reload_error
            .write()
            .expect("policy error lock poisoned") = first_error;
        if retry_failed_provider {
            let _ = self.inner.notification_tx.try_send(());
        }
        let old = self.snapshot();
        let effective_change = old.settings != settings;
        if !effective_change && !had_reload_error && degraded_error.is_none() {
            return Ok((old, None, None));
        }
        let generation = self
            .inner
            .next_generation
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        let new = Arc::new(Snapshot {
            scope: self.inner.scope.clone(),
            generation,
            settings,
        });
        let commit = degraded_error.map_or_else(
            || SnapshotCommit::Applied(new.clone()),
            |error| SnapshotCommit::Degraded {
                snapshot: new.clone(),
                error,
            },
        );
        let pending_commit = match self.stage_snapshot_commit_locked(commit) {
            Ok(pending_commit) => pending_commit,
            Err(error) => {
                *self
                    .inner
                    .last_reload_error
                    .write()
                    .expect("policy error lock poisoned") = Some(error.clone());
                return Err(error);
            }
        };
        let change = effective_change.then(|| PolicyChange {
            old,
            new: new.clone(),
        });
        Ok((new, change, Some(pending_commit)))
    }

    fn stage_failed_commit_locked(
        &self,
        error: PolicyError,
    ) -> Result<PendingSnapshotCommit, PolicyError> {
        let generation = self
            .inner
            .next_generation
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        self.stage_snapshot_commit_locked(SnapshotCommit::Failed {
            snapshot: self.snapshot(),
            generation,
            error,
        })
    }

    fn stage_snapshot_commit_locked(
        &self,
        commit: SnapshotCommit,
    ) -> Result<PendingSnapshotCommit, PolicyError> {
        let hooks: Vec<_> = self
            .inner
            .snapshot_pre_commit_hooks
            .lock()
            .expect("policy snapshot pre-commit hooks lock poisoned")
            .values()
            .cloned()
            .collect();
        let mut releases = CommitHookReleases {
            releases: Vec::with_capacity(hooks.len()),
        };
        for hook in hooks {
            let Ok(release) = catch_unwind(AssertUnwindSafe(|| hook(&commit))) else {
                // Dropping `releases` invokes every barrier acquired before
                // the panic. Keep reload synchronization usable and leave
                // the previous commit installed.
                self.inner.callback_panics.fetch_add(1, Ordering::Relaxed);
                return Err(PolicyError::new(PolicyErrorKind::Provider));
            };
            releases.releases.push(release);
        }

        let snapshot = commit.snapshot().clone();
        *self
            .inner
            .commit_state
            .write()
            .expect("policy commit state lock poisoned") = EngineCommitState {
            snapshot,
            commit: commit.clone(),
        };
        let callbacks = self
            .inner
            .snapshot_commit_callbacks
            .lock()
            .expect("policy snapshot commit callbacks lock poisoned")
            .values()
            .cloned()
            .collect();

        // External barriers remain exclusive through state installation and
        // callback capture. Release before reload synchronization and callback
        // invocation so callbacks can safely re-enter this engine.
        let release_panics = releases.release();
        if release_panics != 0 {
            self.inner
                .callback_panics
                .fetch_add(release_panics, Ordering::Relaxed);
        }
        Ok(PendingSnapshotCommit { commit, callbacks })
    }

    fn invoke_snapshot_commit(&self, pending: PendingSnapshotCommit) {
        for callback in pending.callbacks {
            if catch_unwind(AssertUnwindSafe(|| callback(pending.commit.clone()))).is_err() {
                self.inner.callback_panics.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn invoke_change(&self, change: Option<PolicyChange>) {
        let Some(change) = change else {
            return;
        };
        let callbacks: Vec<_> = self
            .inner
            .callbacks
            .lock()
            .expect("policy callbacks lock poisoned")
            .values()
            .cloned()
            .collect();
        for callback in callbacks {
            if catch_unwind(AssertUnwindSafe(|| callback(change.clone()))).is_err() {
                self.inner.callback_panics.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Returns the number of provider refresh attempts, including failed ones.
    pub fn reload_attempt_count(&self) -> u64 {
        self.inner.reload_attempts.load(Ordering::Relaxed)
    }

    /// Returns the number of isolated change-callback panics.
    pub fn callback_panic_count(&self) -> u64 {
        self.inner.callback_panics.load(Ordering::Relaxed)
    }

    /// Returns the current provider-wide diagnostic for `id`, if any.
    pub fn provider_error(&self, id: ProviderId) -> Option<PolicyError> {
        self.inner
            .provider_errors
            .read()
            .expect("policy provider error lock poisoned")
            .get(&id)
            .cloned()
    }

    /// Returns the last provider-wide reload diagnostic, if any.
    pub fn last_reload_error(&self) -> Option<PolicyError> {
        self.inner
            .last_reload_error
            .read()
            .expect("policy error lock poisoned")
            .clone()
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

    /// Atomically installs a transactional pre-commit hook and commit callback,
    /// then returns the current commit under the same reload synchronization.
    ///
    /// `pre_commit` runs before applied, degraded, and failed status is
    /// installed. It returns a release closure for an external write barrier.
    /// The engine holds all such barriers through state installation and
    /// callback capture, releases them in reverse order, then invokes callbacks
    /// outside reload synchronization. A panicking hook releases every barrier
    /// acquired earlier, leaves this commit uninstalled, and returns a provider
    /// error without poisoning reload synchronization.
    pub fn subscribe_snapshot_commits_transactional(
        &self,
        pre_commit: impl Fn(&SnapshotCommit) -> SnapshotCommitRelease + Send + Sync + 'static,
        callback: impl Fn(SnapshotCommit) + Send + Sync + 'static,
    ) -> (SnapshotCommitRegistration, SnapshotCommit) {
        let _reload_guard = self
            .inner
            .reload
            .lock()
            .expect("policy reload lock poisoned");
        let id = self.inner.next_callback.fetch_add(1, Ordering::Relaxed);
        self.inner
            .snapshot_pre_commit_hooks
            .lock()
            .expect("policy snapshot pre-commit hooks lock poisoned")
            .insert(id, Arc::new(pre_commit));
        self.inner
            .snapshot_commit_callbacks
            .lock()
            .expect("policy snapshot commit callbacks lock poisoned")
            .insert(id, Arc::new(callback));
        let current = self
            .inner
            .commit_state
            .read()
            .expect("policy commit state lock poisoned")
            .commit
            .clone();
        (
            SnapshotCommitRegistration {
                engine: Arc::downgrade(&self.inner),
                id,
            },
            current,
        )
    }

    /// Atomically installs a commit callback and returns current commit status.
    pub fn subscribe_snapshot_commits(
        &self,
        callback: impl Fn(SnapshotCommit) + Send + Sync + 'static,
    ) -> (SnapshotCommitRegistration, SnapshotCommit) {
        self.subscribe_snapshot_commits_transactional(|_| Box::new(|| {}), callback)
    }

    /// Registers a commit callback without returning current status.
    pub fn register_snapshot_commit_callback(
        &self,
        callback: impl Fn(SnapshotCommit) + Send + Sync + 'static,
    ) -> SnapshotCommitRegistration {
        self.subscribe_snapshot_commits(callback).0
    }

    /// Installs a scoped, last-registered device policy override for tests.
    pub fn override_for_test(
        &self,
        values: BTreeMap<PolicyKey, RawValue>,
    ) -> Result<TestOverride, PolicyError> {
        let provider = Arc::new(crate::MemoryProvider::from_values(values));
        let id = self.add_provider_with_precedence(
            "test override",
            PolicyScope::Device,
            ProviderPrecedence::TestOverride,
            provider,
        )?;
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
            Err(error)
                if matches!(
                    error.kind,
                    PolicyErrorKind::NotConfigured
                        | PolicyErrorKind::Parse
                        | PolicyErrorKind::TypeMismatch
                ) =>
            {
                Ok(default)
            }
            Err(error) => Err(error),
            _ => Ok(default),
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
            let callback = engine
                .callbacks
                .lock()
                .expect("policy callbacks lock poisoned")
                .remove(&self.id);
            // The callback may own another registration whose Drop re-enters
            // this map. Release the mutex before dropping the closure.
            drop(callback);
        }
    }
}

/// Unregisters a snapshot commit callback and pre-commit hook when dropped.
pub struct SnapshotCommitRegistration {
    engine: Weak<EngineInner>,
    id: u64,
}

impl Drop for SnapshotCommitRegistration {
    fn drop(&mut self) {
        if let Some(engine) = self.engine.upgrade() {
            let hook = engine
                .snapshot_pre_commit_hooks
                .lock()
                .expect("policy snapshot pre-commit hooks lock poisoned")
                .remove(&self.id);
            let callback = engine
                .snapshot_commit_callbacks
                .lock()
                .expect("policy snapshot commit callbacks lock poisoned")
                .remove(&self.id);
            drop(hook);
            drop(callback);
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
