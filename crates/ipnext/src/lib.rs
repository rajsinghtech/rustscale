//! Ordered extension registration and lifecycle management for IPN backends.
//!
//! Definitions are instantiated in registration order. Extensions initialize
//! in that same order and shut down in reverse order. Registry snapshots are
//! taken before user code runs, so factories and callbacks are never invoked
//! while registry or host-state locks are held.

#![forbid(unsafe_code)]

use std::any::{Any, TypeId};
use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, Weak};

use async_trait::async_trait;
use rustscale_feature::{Hooks as FeatureHooks, Unavailable};
use rustscale_ipn::{LoginProfile, Prefs, State};
use rustscale_tsd::System;
use tokio::sync::oneshot;

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Error type used by extension factories and lifecycle methods.
pub type BoxError = Box<dyn Error + Send + Sync + 'static>;

/// Result type used by extension factories and lifecycle methods.
pub type ExtensionResult<T = ()> = Result<T, BoxError>;

/// Sentinel error indicating that an extension should intentionally be skipped.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct SkipExtension;

impl fmt::Display for SkipExtension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("skipping extension")
    }
}

impl Error for SkipExtension {}

fn is_skipped(error: &(dyn Error + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if error.downcast_ref::<SkipExtension>().is_some()
            || error.downcast_ref::<Unavailable>().is_some()
        {
            return true;
        }
        current = error.source();
    }
    false
}

/// An asynchronously initialized IPN extension.
///
/// Implementations must be safe for concurrent use. `shutdown` is called only
/// after `init` succeeded.
#[async_trait]
pub trait Extension: Any + Send + Sync {
    /// Unique extension name. It must match the registered definition name.
    fn name(&self) -> &str;

    /// Initializes the extension and registers any callbacks it needs.
    async fn init(&self, host: Host) -> ExtensionResult;

    /// Shuts down the extension.
    async fn shutdown(&self) -> ExtensionResult;

    /// Allows multiple registered instances of the same concrete extension
    /// type. This is primarily useful for parameterized test extensions.
    fn permit_duplicate_type(&self) -> bool {
        false
    }

    #[doc(hidden)]
    fn concrete_type_id(&self) -> TypeId {
        TypeId::of::<Self>()
    }
}

type Factory = dyn Fn(Arc<System>) -> ExtensionResult<Arc<dyn Extension>> + Send + Sync;

/// A registered extension definition.
#[derive(Clone)]
pub struct Definition {
    name: Arc<str>,
    factory: Arc<Factory>,
}

impl Definition {
    /// Creates a definition from an extension factory.
    pub fn new(
        name: impl Into<Arc<str>>,
        factory: impl Fn(Arc<System>) -> ExtensionResult<Arc<dyn Extension>> + Send + Sync + 'static,
    ) -> Self {
        Self {
            name: name.into(),
            factory: Arc::new(factory),
        }
    }

    /// Creates a definition that always returns the supplied extension.
    pub fn for_test(extension: Arc<dyn Extension>) -> Self {
        let name: Arc<str> = extension.name().into();
        Self::new(name, move |_| Ok(Arc::clone(&extension)))
    }

    /// Returns the registered extension name.
    pub fn name(&self) -> &str {
        &self.name
    }

    fn make_extension(&self, system: Arc<System>) -> Result<Arc<dyn Extension>, HostBuildError> {
        let extension = (self.factory)(system).map_err(|source| HostBuildError::Factory {
            name: self.name.to_string(),
            source,
        })?;
        if extension.name() != self.name.as_ref() {
            return Err(HostBuildError::NameMismatch {
                registered: self.name.to_string(),
                actual: extension.name().to_string(),
            });
        }
        Ok(extension)
    }
}

impl fmt::Debug for Definition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Definition")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// Thread-safe insertion-ordered extension registry.
#[derive(Debug, Default)]
pub struct ExtensionRegistry {
    definitions: Mutex<Vec<Definition>>,
}

impl ExtensionRegistry {
    /// Creates an empty extension registry.
    pub const fn new() -> Self {
        Self {
            definitions: Mutex::new(Vec::new()),
        }
    }

    /// Registers a definition, rejecting duplicate names.
    pub fn register(&self, definition: Definition) -> Result<(), RegistrationError> {
        let mut definitions = lock_unpoisoned(&self.definitions);
        if definitions
            .iter()
            .any(|existing| existing.name() == definition.name())
        {
            return Err(RegistrationError {
                name: definition.name().to_string(),
            });
        }
        definitions.push(definition);
        Ok(())
    }

    /// Returns a snapshot in registration order.
    pub fn definitions(&self) -> Vec<Definition> {
        lock_unpoisoned(&self.definitions).clone()
    }

    /// Returns the number of registered definitions.
    pub fn len(&self) -> usize {
        lock_unpoisoned(&self.definitions).len()
    }

    /// Returns whether no definitions have been registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Duplicate extension registration error.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RegistrationError {
    name: String,
}

impl RegistrationError {
    /// Returns the duplicated name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for RegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "duplicate extension name {:?}", self.name)
    }
}

impl Error for RegistrationError {}

static GLOBAL_REGISTRY: OnceLock<ExtensionRegistry> = OnceLock::new();

/// Returns the process-wide extension registry.
pub fn global_registry() -> &'static ExtensionRegistry {
    GLOBAL_REGISTRY.get_or_init(ExtensionRegistry::new)
}

/// Registers an extension factory in the process-wide registry.
pub fn register_extension(
    name: impl Into<Arc<str>>,
    factory: impl Fn(Arc<System>) -> ExtensionResult<Arc<dyn Extension>> + Send + Sync + 'static,
) -> Result<(), RegistrationError> {
    register_definition(Definition::new(name, factory))
}

/// Registers a pre-built definition in the process-wide registry.
pub fn register_definition(definition: Definition) -> Result<(), RegistrationError> {
    global_registry().register(definition)
}

/// Returns a process-wide registry snapshot in registration order.
pub fn extensions() -> Vec<Definition> {
    global_registry().definitions()
}

/// Backend-state callback type.
pub type BackendStateCallback = Arc<dyn Fn(State) + Send + Sync>;

/// Profile or preference state callback type.
pub type ProfileStateChangeCallback = Arc<dyn Fn(LoginProfile, Prefs, bool) + Send + Sync>;

/// Hooks available to extensions.
#[derive(Default)]
pub struct Hooks {
    /// Invoked after an IPN backend state transition.
    pub backend_state_change: FeatureHooks<BackendStateCallback>,
    /// Invoked after the current profile or its preferences change.
    pub profile_state_change: FeatureHooks<ProfileStateChangeCallback>,
}

impl fmt::Debug for Hooks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hooks")
            .field("backend_state_change", &self.backend_state_change.len())
            .field("profile_state_change", &self.profile_state_change.len())
            .finish()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ProfileSnapshot {
    profile: LoginProfile,
    prefs: Prefs,
}

#[derive(Clone)]
struct ManagedExtension {
    name: Arc<str>,
    extension: Arc<dyn Extension>,
}

const CREATED: u8 = 0;
const STARTING: u8 = 1;
const RUNNING: u8 = 2;
const SHUTTING_DOWN: u8 = 3;
const STOPPED: u8 = 4;
const SEEDING: u8 = 5;
const SHUTDOWN_FAILED: u8 = 6;

#[derive(Clone)]
enum Publication {
    Backend(State),
    Profile(Box<(LoginProfile, Prefs, bool)>),
}

struct PublicationState {
    accepting: bool,
    draining: bool,
    queue: VecDeque<Publication>,
}

struct PublicationQueue {
    state: Mutex<PublicationState>,
    idle: Condvar,
}

impl PublicationQueue {
    fn new() -> Self {
        Self {
            state: Mutex::new(PublicationState {
                accepting: false,
                draining: false,
                queue: VecDeque::new(),
            }),
            idle: Condvar::new(),
        }
    }

    fn start(&self) {
        lock_unpoisoned(&self.state).accepting = true;
    }

    fn enqueue(&self, core: &HostCore, publication: Publication) {
        let mut state = lock_unpoisoned(&self.state);
        if !state.accepting || core.lifecycle_state.load(Ordering::Acquire) != RUNNING {
            return;
        }
        state.queue.push_back(publication);
        let is_drainer = if state.draining {
            false
        } else {
            state.draining = true;
            true
        };
        drop(state);

        if is_drainer {
            self.drain(core);
        }
    }

    fn begin_shutdown(&self, core: &HostCore, expected: u8) -> Result<(), ()> {
        let mut state = lock_unpoisoned(&self.state);
        if state.draining {
            return Err(());
        }
        core.lifecycle_state
            .compare_exchange(expected, SHUTTING_DOWN, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ())?;
        state.accepting = false;
        Ok(())
    }

    fn drain(&self, core: &HostCore) {
        let mut first_panic = None;
        loop {
            let queued = {
                let mut state = lock_unpoisoned(&self.state);
                if let Some(publication) = state.queue.pop_front() {
                    publication
                } else {
                    state.draining = false;
                    self.idle.notify_all();
                    break;
                }
            };

            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                core.invoke_publication(queued);
            }));
            if first_panic.is_none() {
                first_panic = result.err();
            }
        }
        if let Some(payload) = first_panic {
            std::panic::resume_unwind(payload);
        }
    }

    fn stop_and_wait(&self) {
        let mut state = lock_unpoisoned(&self.state);
        state.accepting = false;
        while state.draining {
            state = self
                .idle
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}

struct HostCore {
    system: Arc<System>,
    hooks: Arc<Hooks>,
    profile: Mutex<ProfileSnapshot>,
    active: Mutex<Vec<ManagedExtension>>,
    publications: PublicationQueue,
    lifecycle_state: AtomicU8,
}

impl HostCore {
    fn invoke_publication(&self, publication: Publication) {
        match publication {
            Publication::Backend(state) => {
                for callback in self.hooks.backend_state_change.snapshot() {
                    callback(state);
                }
            }
            Publication::Profile(profile_state) => {
                let (profile, prefs, same_node) = *profile_state;
                *lock_unpoisoned(&self.profile) = ProfileSnapshot {
                    profile: profile.clone(),
                    prefs: prefs.clone(),
                };
                for callback in self.hooks.profile_state_change.snapshot() {
                    callback(profile.clone(), prefs.clone(), same_node);
                }
            }
        }
    }

    fn set_lifecycle_state(&self, state: u8) {
        self.lifecycle_state.store(state, Ordering::Release);
    }
}

/// Restricted, clonable API passed to extensions.
///
/// The handle is weak: retaining it does not create a reference cycle with an
/// active extension. Methods return [`Unavailable`] after the host is dropped.
#[derive(Clone)]
pub struct Host {
    core: Weak<HostCore>,
}

impl Host {
    fn core(&self) -> Result<Arc<HostCore>, Unavailable> {
        self.core.upgrade().ok_or(Unavailable)
    }

    /// Returns the daemon dependency container.
    pub fn system(&self) -> Result<Arc<System>, Unavailable> {
        Ok(Arc::clone(&self.core()?.system))
    }

    /// Returns extension hooks.
    pub fn hooks(&self) -> Result<Arc<Hooks>, Unavailable> {
        Ok(Arc::clone(&self.core()?.hooks))
    }

    /// Returns a snapshot of the current profile and preferences.
    pub fn current_profile_state(&self) -> Result<(LoginProfile, Prefs), Unavailable> {
        let core = self.core()?;
        let snapshot = lock_unpoisoned(&core.profile).clone();
        Ok((snapshot.profile, snapshot.prefs))
    }

    /// Finds an active extension by name.
    pub fn find_extension_by_name(
        &self,
        name: &str,
    ) -> Result<Option<Arc<dyn Extension>>, Unavailable> {
        let core = self.core()?;
        let extension = lock_unpoisoned(&core.active)
            .iter()
            .find(|extension| extension.name.as_ref() == name)
            .map(|extension| Arc::clone(&extension.extension));
        Ok(extension)
    }

    /// Publishes a backend state transition to registered callbacks.
    ///
    /// This is intended for backend integrations rather than extensions.
    pub fn publish_backend_state(&self, state: State) -> Result<(), Unavailable> {
        let core = self.core()?;
        core.publications
            .enqueue(&core, Publication::Backend(state));
        Ok(())
    }

    /// Publishes a profile or preference change to registered callbacks.
    ///
    /// The host snapshot is updated before callbacks run. No host lock is held
    /// while invoking callbacks.
    pub fn publish_profile_state(
        &self,
        profile: LoginProfile,
        prefs: Prefs,
        same_node: bool,
    ) -> Result<(), Unavailable> {
        let core = self.core()?;
        core.publications.enqueue(
            &core,
            Publication::Profile(Box::new((profile, prefs, same_node))),
        );
        Ok(())
    }
}

impl fmt::Debug for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Host")
            .field("available", &self.core.strong_count().gt(&0))
            .finish()
    }
}

/// Manages instantiated extensions and their async lifecycle.
pub struct ExtensionHost {
    core: Arc<HostCore>,
    all_extensions: Arc<Vec<ManagedExtension>>,
    construction_skips: Arc<Vec<String>>,
}

impl ExtensionHost {
    /// Instantiates definitions from a registry snapshot.
    ///
    /// Feature-unavailable and explicit skip errors omit that definition.
    /// Other factory failures, name mismatches, and duplicate concrete types
    /// fail host construction.
    pub fn new(registry: &ExtensionRegistry, system: Arc<System>) -> Result<Self, HostBuildError> {
        let definitions = registry.definitions();
        let mut all_extensions = Vec::with_capacity(definitions.len());
        let mut construction_skips = Vec::new();
        let mut extension_types = HashMap::<TypeId, String>::new();

        for definition in definitions {
            let registered_name = Arc::clone(&definition.name);
            let extension = match definition.make_extension(Arc::clone(&system)) {
                Ok(extension) => extension,
                Err(HostBuildError::Factory { name, source }) if is_skipped(source.as_ref()) => {
                    construction_skips.push(name);
                    continue;
                }
                Err(error) => return Err(error),
            };
            let extension_type = extension.concrete_type_id();
            let permits_duplicate = extension.permit_duplicate_type();
            if let Some(first) = extension_types.get(&extension_type) {
                if !permits_duplicate {
                    return Err(HostBuildError::DuplicateType {
                        first: first.clone(),
                        second: registered_name.to_string(),
                    });
                }
            } else {
                extension_types.insert(extension_type, registered_name.to_string());
            }
            all_extensions.push(ManagedExtension {
                name: registered_name,
                extension,
            });
        }

        Ok(Self {
            core: Arc::new(HostCore {
                system,
                hooks: Arc::new(Hooks::default()),
                profile: Mutex::new(ProfileSnapshot::default()),
                active: Mutex::new(Vec::new()),
                publications: PublicationQueue::new(),
                lifecycle_state: AtomicU8::new(CREATED),
            }),
            all_extensions: Arc::new(all_extensions),
            construction_skips: Arc::new(construction_skips),
        })
    }

    /// Returns whether the host has not started a lifecycle transition.
    pub fn is_created(&self) -> bool {
        self.core.lifecycle_state.load(Ordering::Acquire) == CREATED
    }

    /// Returns whether a lifecycle transition is currently in progress.
    pub fn is_transitioning(&self) -> bool {
        matches!(
            self.core.lifecycle_state.load(Ordering::Acquire),
            STARTING | SHUTTING_DOWN | SEEDING
        )
    }

    /// Returns whether the host has completed startup.
    pub fn is_running(&self) -> bool {
        self.core.lifecycle_state.load(Ordering::Acquire) == RUNNING
    }

    /// Returns a weak host API handle suitable for callbacks and extensions.
    pub fn host(&self) -> Host {
        Host {
            core: Arc::downgrade(&self.core),
        }
    }

    /// Seeds the profile snapshot visible to extensions during initialization.
    pub fn seed_profile_state(
        &self,
        profile: LoginProfile,
        prefs: Prefs,
    ) -> Result<(), LifecycleError> {
        if self
            .core
            .lifecycle_state
            .compare_exchange(CREATED, SEEDING, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return match self.core.lifecycle_state.load(Ordering::Acquire) {
                STOPPED => Err(LifecycleError::Stopped),
                _ => Err(LifecycleError::Busy),
            };
        }
        *lock_unpoisoned(&self.core.profile) = ProfileSnapshot { profile, prefs };
        self.core.set_lifecycle_state(CREATED);
        Ok(())
    }

    /// Initializes all extensions once, in registration order.
    ///
    /// Individual init failures are non-fatal and are returned in the report.
    /// Cancelling the caller aborts the in-progress init and rolls back every
    /// extension whose init completed. Reentrant calls return
    /// [`LifecycleError::Busy`].
    pub async fn start(&self) -> Result<StartupReport, LifecycleError> {
        loop {
            match self.core.lifecycle_state.load(Ordering::Acquire) {
                CREATED => {
                    if self
                        .core
                        .lifecycle_state
                        .compare_exchange(CREATED, STARTING, Ordering::AcqRel, Ordering::Acquire)
                        .is_err()
                    {
                        continue;
                    }
                    let (result_tx, result_rx) = oneshot::channel();
                    let core = Arc::clone(&self.core);
                    let extensions = Arc::clone(&self.all_extensions);
                    let skips = Arc::clone(&self.construction_skips);
                    tokio::spawn(async move {
                        let mut result_tx = result_tx;
                        let report =
                            run_start(Arc::clone(&core), extensions, skips, false, &mut result_tx)
                                .await
                                .map_err(|error| match error {
                                    StrictStartupError::Stopped => LifecycleError::Stopped,
                                    StrictStartupError::Busy => LifecycleError::Busy,
                                    StrictStartupError::Cancelled => LifecycleError::Cancelled,
                                    StrictStartupError::WorkerStopped => {
                                        LifecycleError::WorkerStopped
                                    }
                                    StrictStartupError::Init { .. } => {
                                        unreachable!(
                                            "non-strict startup cannot return an init error"
                                        )
                                    }
                                });
                        send_start_result(&core, result_tx, report).await;
                    });
                    return match result_rx.await {
                        Ok((result, acknowledged)) => {
                            let _ = acknowledged.send(());
                            result
                        }
                        Err(_) => Err(LifecycleError::WorkerStopped),
                    };
                }
                RUNNING => {
                    return Ok(StartupReport {
                        active: self.active_names(),
                        already_started: true,
                        ..StartupReport::default()
                    });
                }
                STOPPED => return Err(LifecycleError::Stopped),
                STARTING | SHUTTING_DOWN | SEEDING | SHUTDOWN_FAILED => {
                    return Err(LifecycleError::Busy);
                }
                _ => unreachable!("invalid extension lifecycle state"),
            }
        }
    }

    /// Strict startup variant that rolls back initialized extensions after
    /// the first non-skip init error.
    pub async fn start_strict(&self) -> Result<StartupReport, StrictStartupError> {
        loop {
            match self.core.lifecycle_state.load(Ordering::Acquire) {
                CREATED => {
                    if self
                        .core
                        .lifecycle_state
                        .compare_exchange(CREATED, STARTING, Ordering::AcqRel, Ordering::Acquire)
                        .is_err()
                    {
                        continue;
                    }
                    let (result_tx, result_rx) = oneshot::channel();
                    let core = Arc::clone(&self.core);
                    let extensions = Arc::clone(&self.all_extensions);
                    let skips = Arc::clone(&self.construction_skips);
                    tokio::spawn(async move {
                        let mut result_tx = result_tx;
                        let result =
                            run_start(Arc::clone(&core), extensions, skips, true, &mut result_tx)
                                .await;
                        send_start_result(&core, result_tx, result).await;
                    });
                    return match result_rx.await {
                        Ok((result, acknowledged)) => {
                            let _ = acknowledged.send(());
                            result
                        }
                        Err(_) => Err(StrictStartupError::WorkerStopped),
                    };
                }
                RUNNING => {
                    return Ok(StartupReport {
                        active: self.active_names(),
                        already_started: true,
                        ..StartupReport::default()
                    });
                }
                STOPPED => return Err(StrictStartupError::Stopped),
                STARTING | SHUTTING_DOWN | SEEDING | SHUTDOWN_FAILED => {
                    return Err(StrictStartupError::Busy);
                }
                _ => unreachable!("invalid extension lifecycle state"),
            }
        }
    }

    /// Stop accepting publications and wait for the active publication
    /// callback/queue to drain. The blocking waiter is independently owned,
    /// so cancelling this future does not re-enable or detach publication work.
    pub async fn stop_publications_and_wait(&self) {
        let core = Arc::clone(&self.core);
        let _ = tokio::task::spawn_blocking(move || {
            core.publications.stop_and_wait();
        })
        .await;
    }

    /// Shuts down initialized extensions once, in reverse init order.
    ///
    /// Publications already in progress complete before shutdown callbacks
    /// begin. The operation continues if its caller is cancelled. Calls made
    /// while another lifecycle transition is active return a busy error.
    pub async fn shutdown(&self) -> Result<(), ShutdownError> {
        loop {
            match self.core.lifecycle_state.load(Ordering::Acquire) {
                CREATED => {
                    if self
                        .core
                        .lifecycle_state
                        .compare_exchange(CREATED, STOPPED, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        self.core.publications.stop_and_wait();
                        return Ok(());
                    }
                }
                RUNNING | SHUTDOWN_FAILED => {
                    let expected = self.core.lifecycle_state.load(Ordering::Acquire);
                    if !matches!(expected, RUNNING | SHUTDOWN_FAILED) {
                        continue;
                    }
                    if self
                        .core
                        .publications
                        .begin_shutdown(&self.core, expected)
                        .is_err()
                    {
                        if self.core.lifecycle_state.load(Ordering::Acquire) == expected {
                            return Err(ShutdownError::busy());
                        }
                        continue;
                    }
                    let (result_tx, result_rx) = oneshot::channel();
                    let core = Arc::clone(&self.core);
                    tokio::spawn(async move {
                        let publications = Arc::clone(&core);
                        let _ = tokio::task::spawn_blocking(move || {
                            publications.publications.stop_and_wait();
                        })
                        .await;
                        let failures = shutdown_active(&core).await;
                        let result = if failures.is_empty() {
                            Ok(())
                        } else {
                            Err(ShutdownError::failures(failures))
                        };
                        let _ = result_tx.send(result);
                    });
                    #[cfg(test)]
                    const WAIT: std::time::Duration = std::time::Duration::from_millis(100);
                    #[cfg(not(test))]
                    const WAIT: std::time::Duration = std::time::Duration::from_secs(5);
                    return match tokio::time::timeout(WAIT, result_rx).await {
                        Ok(Ok(result)) => result,
                        Ok(Err(_)) => Err(ShutdownError::worker_stopped()),
                        Err(_) => Err(ShutdownError::busy()),
                    };
                }
                STOPPED => return Ok(()),
                STARTING | SHUTTING_DOWN | SEEDING => return Err(ShutdownError::busy()),
                _ => unreachable!("invalid extension lifecycle state"),
            }
        }
    }

    /// Returns active extension names in initialization order.
    pub fn active_names(&self) -> Vec<String> {
        lock_unpoisoned(&self.core.active)
            .iter()
            .map(|extension| extension.name.to_string())
            .collect()
    }
}

async fn send_start_result<T>(
    core: &Arc<HostCore>,
    result_tx: oneshot::Sender<(T, oneshot::Sender<()>)>,
    result: T,
) {
    let (acknowledged_tx, acknowledged_rx) = oneshot::channel();
    let acknowledged =
        result_tx.send((result, acknowledged_tx)).is_ok() && acknowledged_rx.await.is_ok();
    if acknowledged || core.lifecycle_state.load(Ordering::Acquire) != RUNNING {
        return;
    }

    if core
        .lifecycle_state
        .compare_exchange(RUNNING, SHUTTING_DOWN, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        let publications = Arc::clone(core);
        let _ = tokio::task::spawn_blocking(move || {
            publications.publications.stop_and_wait();
        })
        .await;
        let _ = shutdown_active(core).await;
    }
}

async fn run_start<T>(
    core: Arc<HostCore>,
    extensions: Arc<Vec<ManagedExtension>>,
    construction_skips: Arc<Vec<String>>,
    strict: bool,
    result_tx: &mut oneshot::Sender<T>,
) -> Result<StartupReport, StrictStartupError> {
    let host = Host {
        core: Arc::downgrade(&core),
    };
    let mut report = StartupReport {
        skipped: construction_skips.as_ref().clone(),
        ..StartupReport::default()
    };
    for extension in extensions.iter() {
        let init_result = match invoke_init(extension.clone(), host.clone(), result_tx).await {
            InitOutcome::Completed(result) => result,
            InitOutcome::CallerCancelled => {
                core.set_lifecycle_state(SHUTTING_DOWN);
                let _ = shutdown_active(&core).await;
                return Err(StrictStartupError::Cancelled);
            }
        };
        match init_result {
            Ok(()) => {
                lock_unpoisoned(&core.active).push(extension.clone());
                report.active.push(extension.name.to_string());
            }
            Err(error) if is_skipped(error.as_ref()) => {
                report.skipped.push(extension.name.to_string());
            }
            Err(source) if strict => {
                core.set_lifecycle_state(SHUTTING_DOWN);
                let rollback_failures = shutdown_active(&core).await;
                return Err(StrictStartupError::Init {
                    name: extension.name.to_string(),
                    source,
                    rollback_failures,
                });
            }
            Err(source) => report.failed.push(ExtensionFailure {
                name: extension.name.to_string(),
                source,
            }),
        }
    }
    if result_tx.is_closed() {
        core.set_lifecycle_state(SHUTTING_DOWN);
        let _ = shutdown_active(&core).await;
        return Err(StrictStartupError::Cancelled);
    }
    core.publications.start();
    core.set_lifecycle_state(RUNNING);
    Ok(report)
}

enum InitOutcome {
    Completed(ExtensionResult),
    CallerCancelled,
}

async fn invoke_init<T>(
    extension: ManagedExtension,
    host: Host,
    result_tx: &mut oneshot::Sender<T>,
) -> InitOutcome {
    let cleanup_extension = extension.clone();
    let mut task = tokio::spawn(async move { extension.extension.init(host).await });
    tokio::select! {
        biased;
        result = &mut task => {
            let result = result.map_err(join_error).and_then(std::convert::identity);
            if let Err(source) = result {
                let cleanup = cleanup_partial_init(cleanup_extension).await;
                InitOutcome::Completed(Err(combine_init_cleanup(source, cleanup)))
            } else {
                InitOutcome::Completed(Ok(()))
            }
        }
        () = result_tx.closed() => {
            task.abort();
            let _ = task.await;
            let _ = cleanup_partial_init(cleanup_extension).await;
            InitOutcome::CallerCancelled
        }
    }
}

#[derive(Debug)]
struct InitCleanupError {
    init: BoxError,
    cleanup: BoxError,
}

impl fmt::Display for InitCleanupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "extension init failed: {}; partial-init cleanup failed: {}",
            self.init, self.cleanup
        )
    }
}

impl std::error::Error for InitCleanupError {}

fn combine_init_cleanup(init: BoxError, cleanup: Option<BoxError>) -> BoxError {
    match cleanup {
        Some(cleanup) => Box::new(InitCleanupError { init, cleanup }),
        None => init,
    }
}

async fn cleanup_partial_init(extension: ManagedExtension) -> Option<BoxError> {
    #[cfg(test)]
    const TIMEOUT: std::time::Duration = std::time::Duration::from_millis(100);
    #[cfg(not(test))]
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    let mut cleanup = tokio::spawn(async move { extension.extension.shutdown().await });
    if let Ok(result) = tokio::time::timeout(TIMEOUT, &mut cleanup).await {
        return result
            .map_err(join_error)
            .and_then(std::convert::identity)
            .err();
    }
    cleanup.abort();
    let _ = cleanup.await;
    Some(Box::new(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "partial extension cleanup timed out",
    )))
}

async fn invoke_shutdown(extension: ManagedExtension) -> ExtensionResult {
    // The lifecycle worker, not an API waiter, owns this task. A bounded API
    // timeout must never abort and forget an extension that may still own
    // children or sockets. The host reaches STOPPED only after this join proves
    // the callback quiescent.
    tokio::spawn(async move { extension.extension.shutdown().await })
        .await
        .map_err(join_error)?
}

fn join_error(error: tokio::task::JoinError) -> BoxError {
    Box::new(std::io::Error::other(format!(
        "extension lifecycle task failed: {error}"
    )))
}

async fn shutdown_active(core: &HostCore) -> Vec<ExtensionFailure> {
    loop {
        // Keep the complete active registry visible while user shutdown code
        // runs. A dependent may need to resolve one of its dependencies in
        // order to release registrations or other shared state safely.
        let extension = lock_unpoisoned(&core.active).last().cloned();
        let Some(extension) = extension else {
            core.set_lifecycle_state(STOPPED);
            return Vec::new();
        };

        if let Err(source) = invoke_shutdown(extension.clone()).await {
            // This extension is a dependent of every earlier active entry.
            // Stop here: shutting down its dependencies would invalidate the
            // registry required by its retry and violate reverse-topological
            // ordering.
            core.set_lifecycle_state(SHUTDOWN_FAILED);
            return vec![ExtensionFailure {
                name: extension.name.to_string(),
                source,
            }];
        }

        let removed = lock_unpoisoned(&core.active)
            .pop()
            .expect("shutdown extension disappeared from active registry");
        debug_assert_eq!(removed.name, extension.name);
    }
}

impl fmt::Debug for ExtensionHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtensionHost")
            .field(
                "extensions",
                &self
                    .all_extensions
                    .iter()
                    .map(|extension| extension.name.as_ref())
                    .collect::<Vec<_>>(),
            )
            .field("active", &self.active_names())
            .finish_non_exhaustive()
    }
}

/// Fatal error while constructing an extension host.
#[derive(Debug)]
pub enum HostBuildError {
    /// An extension factory failed.
    Factory { name: String, source: BoxError },
    /// The extension's runtime name differs from its registered name.
    NameMismatch { registered: String, actual: String },
    /// Two definitions produced the same concrete extension type.
    DuplicateType { first: String, second: String },
}

impl fmt::Display for HostBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Factory { name, source } => {
                write!(f, "failed to create {name:?} extension: {source}")
            }
            Self::NameMismatch { registered, actual } => write!(
                f,
                "extension name mismatch: registered {registered:?}; actual {actual:?}"
            ),
            Self::DuplicateType { first, second } => {
                write!(f, "duplicate extension type for {first:?} and {second:?}")
            }
        }
    }
}

impl Error for HostBuildError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Factory { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

/// An extension lifecycle failure with its extension name.
#[derive(Debug)]
pub struct ExtensionFailure {
    /// Extension name.
    pub name: String,
    /// Error returned by the extension.
    pub source: BoxError,
}

/// Summary returned after non-strict startup.
#[derive(Debug, Default)]
pub struct StartupReport {
    /// Successfully initialized extensions, in init order.
    pub active: Vec<String>,
    /// Intentionally skipped or unavailable extensions.
    pub skipped: Vec<String>,
    /// Extensions whose initialization failed.
    pub failed: Vec<ExtensionFailure>,
    /// Whether this was an idempotent call after startup completed.
    pub already_started: bool,
}

/// Invalid lifecycle transition.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum LifecycleError {
    /// The host has already shut down and cannot restart.
    Stopped,
    /// A reentrant lifecycle call cannot wait for its own operation.
    Busy,
    /// The startup caller was cancelled and initialized extensions rolled back.
    Cancelled,
    /// The owned lifecycle worker stopped without reporting a result.
    WorkerStopped,
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stopped => f.write_str("extension host has already stopped"),
            Self::Busy => f.write_str("extension lifecycle operation is already in progress"),
            Self::Cancelled => f.write_str("extension startup was cancelled"),
            Self::WorkerStopped => f.write_str("extension lifecycle worker stopped unexpectedly"),
        }
    }
}

impl Error for LifecycleError {}

/// Strict startup failure, including rollback failures.
#[derive(Debug)]
pub enum StrictStartupError {
    /// The host has already stopped.
    Stopped,
    /// A reentrant lifecycle call cannot wait for its own operation.
    Busy,
    /// The startup caller was cancelled and initialized extensions rolled back.
    Cancelled,
    /// The owned lifecycle worker stopped without reporting a result.
    WorkerStopped,
    /// Extension initialization failed and initialized extensions were rolled back.
    Init {
        name: String,
        source: BoxError,
        rollback_failures: Vec<ExtensionFailure>,
    },
}

impl fmt::Display for StrictStartupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stopped => f.write_str("extension host has already stopped"),
            Self::Busy => f.write_str("extension lifecycle operation is already in progress"),
            Self::Cancelled => f.write_str("extension startup was cancelled"),
            Self::WorkerStopped => f.write_str("extension lifecycle worker stopped unexpectedly"),
            Self::Init { name, source, .. } => {
                write!(f, "failed to initialize {name:?} extension: {source}")
            }
        }
    }
}

impl Error for StrictStartupError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Init { source, .. } => Some(source.as_ref()),
            Self::Stopped | Self::Busy | Self::Cancelled | Self::WorkerStopped => None,
        }
    }
}

/// Aggregated shutdown failures. Failed extensions remain active for retry.
#[derive(Debug)]
pub struct ShutdownError {
    /// Failures in shutdown-call order.
    pub failures: Vec<ExtensionFailure>,
    lifecycle: Option<LifecycleError>,
}

impl ShutdownError {
    fn failures(failures: Vec<ExtensionFailure>) -> Self {
        Self {
            failures,
            lifecycle: None,
        }
    }

    fn busy() -> Self {
        Self {
            failures: Vec::new(),
            lifecycle: Some(LifecycleError::Busy),
        }
    }

    fn worker_stopped() -> Self {
        Self {
            failures: Vec::new(),
            lifecycle: Some(LifecycleError::WorkerStopped),
        }
    }

    /// Returns a lifecycle failure when shutdown could not run.
    pub fn lifecycle_error(&self) -> Option<LifecycleError> {
        self.lifecycle
    }
}

impl fmt::Display for ShutdownError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(error) = self.lifecycle {
            return error.fmt(f);
        }
        write!(
            f,
            "{} extension shutdown callback(s) failed",
            self.failures.len()
        )
    }
}

impl Error for ShutdownError {}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc, Mutex, OnceLock, Weak};
    use std::time::Duration;

    use tokio::sync::{Barrier, Notify};

    use async_trait::async_trait;
    use rustscale_feature::Unavailable;
    use rustscale_ipn::{LoginProfile, Prefs, State};
    use rustscale_tsd::System;

    use super::{
        lock_unpoisoned, Definition, Extension, ExtensionHost, ExtensionRegistry, ExtensionResult,
        Host, HostBuildError, LifecycleError, SkipExtension, StrictStartupError,
    };

    struct MockExtension {
        name: &'static str,
        events: Arc<Mutex<Vec<String>>>,
        init_error: Option<&'static str>,
        shutdown_error: bool,
    }

    #[async_trait]
    impl Extension for MockExtension {
        fn name(&self) -> &str {
            self.name
        }

        async fn init(&self, host: Host) -> ExtensionResult {
            self.events
                .lock()
                .unwrap()
                .push(format!("init:{}", self.name));
            if self.name == "hooks" {
                let events = Arc::clone(&self.events);
                host.hooks()?
                    .backend_state_change
                    .add(Arc::new(move |state| {
                        events.lock().unwrap().push(format!("state:{state}"));
                    }));
                let events = Arc::clone(&self.events);
                let current = host.clone();
                host.hooks()?
                    .profile_state_change
                    .add(Arc::new(move |profile, _, same_node| {
                        let (snapshot, _) = current.current_profile_state().unwrap();
                        assert_eq!(snapshot, profile);
                        events
                            .lock()
                            .unwrap()
                            .push(format!("profile:{}:{same_node}", profile.ID));
                    }));
            }
            match self.init_error {
                Some("skip") => Err(Box::new(SkipExtension)),
                Some(message) => Err(Box::new(io::Error::other(message))),
                None => Ok(()),
            }
        }

        async fn shutdown(&self) -> ExtensionResult {
            self.events
                .lock()
                .unwrap()
                .push(format!("shutdown:{}", self.name));
            if self.shutdown_error {
                Err(Box::new(io::Error::other("shutdown failed")))
            } else {
                Ok(())
            }
        }

        fn permit_duplicate_type(&self) -> bool {
            true
        }
    }

    fn definition(
        name: &'static str,
        events: &Arc<Mutex<Vec<String>>>,
        init_error: Option<&'static str>,
        shutdown_error: bool,
    ) -> Definition {
        let events = Arc::clone(events);
        Definition::new(name, move |_| {
            Ok(Arc::new(MockExtension {
                name,
                events: Arc::clone(&events),
                init_error,
                shutdown_error,
            }))
        })
    }

    #[test]
    fn registry_preserves_order_and_releases_lock_before_factories() {
        let registry = Arc::new(ExtensionRegistry::new());
        let factory_registry = Arc::clone(&registry);
        registry
            .register(Definition::new("first", move |_| {
                factory_registry
                    .register(Definition::new("later", |_| Err(Box::new(Unavailable))))
                    .unwrap();
                Err(Box::new(Unavailable))
            }))
            .unwrap();
        registry
            .register(Definition::new("second", |_| Err(Box::new(Unavailable))))
            .unwrap();

        let host = ExtensionHost::new(&registry, Arc::new(System::new())).unwrap();
        assert!(host.all_extensions.is_empty());
        assert_eq!(host.construction_skips.as_slice(), ["first", "second"]);
        assert_eq!(registry.len(), 3);
        assert!(registry
            .register(Definition::new("second", |_| Err(Box::new(Unavailable))))
            .is_err());
    }

    #[test]
    fn name_mismatch_is_fatal() {
        let registry = ExtensionRegistry::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        registry
            .register(Definition::new("registered", move |_| {
                Ok(Arc::new(MockExtension {
                    name: "actual",
                    events: Arc::clone(&events),
                    init_error: None,
                    shutdown_error: false,
                }))
            }))
            .unwrap();
        let error = ExtensionHost::new(&registry, Arc::new(System::new())).unwrap_err();
        assert!(matches!(error, HostBuildError::NameMismatch { .. }));
    }

    #[test]
    fn duplicate_concrete_extension_type_is_fatal() {
        struct DuplicateTypeExtension(&'static str);
        #[async_trait]
        impl Extension for DuplicateTypeExtension {
            fn name(&self) -> &str {
                self.0
            }
            async fn init(&self, _: Host) -> ExtensionResult {
                Ok(())
            }
            async fn shutdown(&self) -> ExtensionResult {
                Ok(())
            }
        }

        let registry = ExtensionRegistry::new();
        registry
            .register(Definition::new("first", |_| {
                Ok(Arc::new(DuplicateTypeExtension("first")))
            }))
            .unwrap();
        registry
            .register(Definition::new("second", |_| {
                Ok(Arc::new(DuplicateTypeExtension("second")))
            }))
            .unwrap();
        let error = ExtensionHost::new(&registry, Arc::new(System::new())).unwrap_err();
        assert!(matches!(error, HostBuildError::DuplicateType { .. }));
    }

    #[tokio::test]
    async fn lifecycle_order_skips_failures_and_shutdown_is_reverse() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let registry = ExtensionRegistry::new();
        registry
            .register(definition("a", &events, None, false))
            .unwrap();
        registry
            .register(definition("b", &events, Some("skip"), false))
            .unwrap();
        registry
            .register(definition("c", &events, Some("failed"), false))
            .unwrap();
        registry
            .register(definition("d", &events, None, true))
            .unwrap();
        let host = ExtensionHost::new(&registry, Arc::new(System::new())).unwrap();

        let report = host.start().await.unwrap();
        assert_eq!(report.active, ["a", "d"]);
        assert_eq!(report.skipped, ["b"]);
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.failed[0].name, "c");
        let again = host.start().await.unwrap();
        assert!(again.already_started);

        let error = host.shutdown().await.unwrap_err();
        assert_eq!(error.failures.len(), 1);
        assert_eq!(error.failures[0].name, "d");
        assert_eq!(host.active_names(), ["a", "d"]);
        assert_eq!(host.start().await.unwrap_err(), LifecycleError::Busy);
        assert_eq!(
            *events.lock().unwrap(),
            [
                "init:a",
                "init:b",
                "shutdown:b",
                "init:c",
                "shutdown:c",
                "init:d",
                "shutdown:d"
            ]
        );
    }

    #[tokio::test]
    async fn transient_shutdown_failure_retains_child_and_retries_only_failures() {
        struct ChildResource(Arc<AtomicBool>);
        impl Drop for ChildResource {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        struct SuccessfulShutdown(Arc<AtomicUsize>);
        #[async_trait]
        impl Extension for SuccessfulShutdown {
            fn name(&self) -> &'static str {
                "successful"
            }
            async fn init(&self, _: Host) -> ExtensionResult {
                Ok(())
            }
            async fn shutdown(&self) -> ExtensionResult {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }

        struct TransientShutdown {
            attempts: Arc<AtomicUsize>,
            child: Mutex<Option<ChildResource>>,
        }
        #[async_trait]
        impl Extension for TransientShutdown {
            fn name(&self) -> &'static str {
                "transient"
            }
            async fn init(&self, _: Host) -> ExtensionResult {
                Ok(())
            }
            async fn shutdown(&self) -> ExtensionResult {
                if self.attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                    return Err(Box::new(io::Error::other("transient shutdown failure")));
                }
                self.child.lock().unwrap().take();
                Ok(())
            }
        }

        let successful_calls = Arc::new(AtomicUsize::new(0));
        let transient_attempts = Arc::new(AtomicUsize::new(0));
        let child_dropped = Arc::new(AtomicBool::new(false));
        let registry = ExtensionRegistry::new();
        let factory_successful_calls = Arc::clone(&successful_calls);
        registry
            .register(Definition::new("successful", move |_| {
                Ok(Arc::new(SuccessfulShutdown(Arc::clone(
                    &factory_successful_calls,
                ))))
            }))
            .unwrap();
        let factory_attempts = Arc::clone(&transient_attempts);
        let factory_child_dropped = Arc::clone(&child_dropped);
        registry
            .register(Definition::new("transient", move |_| {
                Ok(Arc::new(TransientShutdown {
                    attempts: Arc::clone(&factory_attempts),
                    child: Mutex::new(Some(ChildResource(Arc::clone(&factory_child_dropped)))),
                }))
            }))
            .unwrap();
        let host = ExtensionHost::new(&registry, Arc::new(System::new())).unwrap();
        host.start().await.unwrap();

        let error = host.shutdown().await.unwrap_err();
        assert_eq!(error.failures.len(), 1);
        assert_eq!(error.failures[0].name, "transient");
        assert_eq!(host.active_names(), ["successful", "transient"]);
        assert_eq!(successful_calls.load(Ordering::SeqCst), 0);
        assert_eq!(transient_attempts.load(Ordering::SeqCst), 1);
        assert!(!child_dropped.load(Ordering::SeqCst));

        host.shutdown().await.unwrap();
        assert!(host.active_names().is_empty());
        assert_eq!(successful_calls.load(Ordering::SeqCst), 1);
        assert_eq!(transient_attempts.load(Ordering::SeqCst), 2);
        assert!(child_dropped.load(Ordering::SeqCst));
        host.shutdown().await.unwrap();
        assert_eq!(transient_attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn failed_dependent_keeps_dependency_resolvable_until_retry() {
        struct Dependency(Arc<AtomicUsize>);
        #[async_trait]
        impl Extension for Dependency {
            fn name(&self) -> &'static str {
                "dependency"
            }
            async fn init(&self, _: Host) -> ExtensionResult {
                Ok(())
            }
            async fn shutdown(&self) -> ExtensionResult {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }

        struct Dependent {
            host: Mutex<Option<Host>>,
            attempts: Arc<AtomicUsize>,
            resolutions: Arc<AtomicUsize>,
        }
        #[async_trait]
        impl Extension for Dependent {
            fn name(&self) -> &'static str {
                "dependent"
            }
            async fn init(&self, host: Host) -> ExtensionResult {
                *self.host.lock().unwrap() = Some(host);
                Ok(())
            }
            async fn shutdown(&self) -> ExtensionResult {
                let dependency = self
                    .host
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .find_extension_by_name("dependency")?;
                if dependency.is_none() {
                    return Err(Box::new(io::Error::other("dependency disappeared")));
                }
                self.resolutions.fetch_add(1, Ordering::SeqCst);
                if self.attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                    return Err(Box::new(io::Error::other("retry dependent later")));
                }
                Ok(())
            }
        }

        let dependency_shutdowns = Arc::new(AtomicUsize::new(0));
        let attempts = Arc::new(AtomicUsize::new(0));
        let resolutions = Arc::new(AtomicUsize::new(0));
        let registry = ExtensionRegistry::new();
        let factory_shutdowns = Arc::clone(&dependency_shutdowns);
        registry
            .register(Definition::new("dependency", move |_| {
                Ok(Arc::new(Dependency(Arc::clone(&factory_shutdowns))))
            }))
            .unwrap();
        let factory_attempts = Arc::clone(&attempts);
        let factory_resolutions = Arc::clone(&resolutions);
        registry
            .register(Definition::new("dependent", move |_| {
                Ok(Arc::new(Dependent {
                    host: Mutex::new(None),
                    attempts: Arc::clone(&factory_attempts),
                    resolutions: Arc::clone(&factory_resolutions),
                }))
            }))
            .unwrap();
        let host = ExtensionHost::new(&registry, Arc::new(System::new())).unwrap();
        host.start().await.unwrap();

        let error = host.shutdown().await.unwrap_err();
        assert_eq!(error.failures[0].name, "dependent");
        assert_eq!(host.active_names(), ["dependency", "dependent"]);
        assert_eq!(dependency_shutdowns.load(Ordering::SeqCst), 0);
        assert_eq!(resolutions.load(Ordering::SeqCst), 1);

        host.shutdown().await.unwrap();
        assert!(host.active_names().is_empty());
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(resolutions.load(Ordering::SeqCst), 2);
        assert_eq!(dependency_shutdowns.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn strict_startup_rolls_back_in_reverse_order() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let registry = ExtensionRegistry::new();
        registry
            .register(definition("a", &events, None, false))
            .unwrap();
        registry
            .register(definition("b", &events, None, false))
            .unwrap();
        registry
            .register(definition("c", &events, Some("failed"), false))
            .unwrap();
        let host = ExtensionHost::new(&registry, Arc::new(System::new())).unwrap();

        let error = host.start_strict().await.unwrap_err();
        assert!(matches!(error, StrictStartupError::Init { name, .. } if name == "c"));
        assert_eq!(
            *events.lock().unwrap(),
            [
                "init:a",
                "init:b",
                "init:c",
                "shutdown:c",
                "shutdown:b",
                "shutdown:a"
            ]
        );
        assert!(host.active_names().is_empty());
    }

    #[tokio::test]
    async fn state_and_profile_callbacks_run_without_host_locks() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let registry = ExtensionRegistry::new();
        registry
            .register(definition("hooks", &events, None, false))
            .unwrap();
        let host = ExtensionHost::new(&registry, Arc::new(System::new())).unwrap();
        host.start().await.unwrap();
        let handle = host.host();

        handle.publish_backend_state(State::Running).unwrap();
        handle
            .publish_profile_state(
                LoginProfile {
                    ID: "work".into(),
                    ..Default::default()
                },
                Prefs::default(),
                false,
            )
            .unwrap();
        assert_eq!(
            *events.lock().unwrap(),
            ["init:hooks", "state:Running", "profile:work:false"]
        );
    }

    #[tokio::test]
    async fn concurrent_start_initializes_once() {
        struct CountExtension(Arc<AtomicUsize>);
        #[async_trait]
        impl Extension for CountExtension {
            fn name(&self) -> &'static str {
                "count"
            }
            async fn init(&self, _: Host) -> ExtensionResult {
                self.0.fetch_add(1, Ordering::SeqCst);
                tokio::task::yield_now().await;
                Ok(())
            }
            async fn shutdown(&self) -> ExtensionResult {
                Ok(())
            }
        }

        let count = Arc::new(AtomicUsize::new(0));
        let registry = ExtensionRegistry::new();
        let factory_count = Arc::clone(&count);
        registry
            .register(Definition::new("count", move |_| {
                Ok(Arc::new(CountExtension(Arc::clone(&factory_count))))
            }))
            .unwrap();
        let host = Arc::new(ExtensionHost::new(&registry, Arc::new(System::new())).unwrap());
        let (left, right) = tokio::join!(host.start(), host.start());
        for result in [left, right] {
            assert!(result.is_ok() || matches!(result, Err(LifecycleError::Busy)));
        }
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn failed_init_runs_bounded_idempotent_partial_cleanup() {
        struct FailedInit {
            shutdowns: Arc<AtomicUsize>,
            block_cleanup: bool,
            cleanup_dropped: Arc<AtomicBool>,
        }
        struct DropFlag(Arc<AtomicBool>);
        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        #[async_trait]
        impl Extension for FailedInit {
            fn name(&self) -> &'static str {
                "failed-init"
            }
            async fn init(&self, _: Host) -> ExtensionResult {
                Err(Box::new(std::io::Error::other("init failed")))
            }
            async fn shutdown(&self) -> ExtensionResult {
                self.shutdowns.fetch_add(1, Ordering::SeqCst);
                if self.block_cleanup {
                    let _drop = DropFlag(Arc::clone(&self.cleanup_dropped));
                    std::future::pending::<()>().await;
                }
                Ok(())
            }
        }

        for block_cleanup in [false, true] {
            let shutdowns = Arc::new(AtomicUsize::new(0));
            let cleanup_dropped = Arc::new(AtomicBool::new(false));
            let registry = ExtensionRegistry::new();
            let factory_shutdowns = Arc::clone(&shutdowns);
            let factory_dropped = Arc::clone(&cleanup_dropped);
            registry
                .register(Definition::new("failed-init", move |_| {
                    Ok(Arc::new(FailedInit {
                        shutdowns: Arc::clone(&factory_shutdowns),
                        block_cleanup,
                        cleanup_dropped: Arc::clone(&factory_dropped),
                    }))
                }))
                .unwrap();
            let host = ExtensionHost::new(&registry, Arc::new(System::new())).unwrap();
            let report = tokio::time::timeout(Duration::from_secs(1), host.start())
                .await
                .expect("partial cleanup was not bounded")
                .unwrap();
            assert_eq!(report.failed.len(), 1);
            assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
            if block_cleanup {
                assert!(report.failed[0].source.to_string().contains("timed out"));
                assert!(cleanup_dropped.load(Ordering::SeqCst));
            }
            host.shutdown().await.unwrap();
            assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn cancelled_start_rolls_back_initialized_extensions_once() {
        struct CancelExtension {
            name: &'static str,
            block_init: bool,
            init_barrier: Arc<Barrier>,
            shutdowns: Arc<AtomicUsize>,
            shutdown_done: Arc<Notify>,
        }
        #[async_trait]
        impl Extension for CancelExtension {
            fn name(&self) -> &str {
                self.name
            }
            async fn init(&self, _: Host) -> ExtensionResult {
                if self.block_init {
                    self.init_barrier.wait().await;
                    std::future::pending::<()>().await;
                }
                Ok(())
            }
            async fn shutdown(&self) -> ExtensionResult {
                self.shutdowns.fetch_add(1, Ordering::SeqCst);
                self.shutdown_done.notify_one();
                Ok(())
            }
            fn permit_duplicate_type(&self) -> bool {
                true
            }
        }

        for strict in [false, true] {
            let barrier = Arc::new(Barrier::new(2));
            let shutdowns = Arc::new(AtomicUsize::new(0));
            let shutdown_done = Arc::new(Notify::new());
            let registry = ExtensionRegistry::new();
            for (name, block_init) in [("ready", false), ("blocked", true)] {
                let barrier = Arc::clone(&barrier);
                let shutdowns = Arc::clone(&shutdowns);
                let shutdown_done = Arc::clone(&shutdown_done);
                registry
                    .register(Definition::new(name, move |_| {
                        Ok(Arc::new(CancelExtension {
                            name,
                            block_init,
                            init_barrier: Arc::clone(&barrier),
                            shutdowns: Arc::clone(&shutdowns),
                            shutdown_done: Arc::clone(&shutdown_done),
                        }))
                    }))
                    .unwrap();
            }
            let host = Arc::new(ExtensionHost::new(&registry, Arc::new(System::new())).unwrap());
            let start_host = Arc::clone(&host);
            let start = tokio::spawn(async move {
                if strict {
                    let _ = start_host.start_strict().await;
                } else {
                    let _ = start_host.start().await;
                }
            });
            tokio::time::timeout(Duration::from_secs(1), barrier.wait())
                .await
                .expect("blocked init did not start");
            start.abort();
            let _ = start.await;
            tokio::time::timeout(Duration::from_secs(1), async {
                while shutdowns.load(Ordering::SeqCst) != 2 {
                    shutdown_done.notified().await;
                }
            })
            .await
            .expect("cancelled startup did not clean partial and active extensions");
            assert!(host.active_names().is_empty());
            host.shutdown().await.unwrap();
            assert_eq!(shutdowns.load(Ordering::SeqCst), 2);
        }
    }

    #[tokio::test]
    async fn cancelled_shutdown_continues_and_retry_waits_for_completion() {
        struct BlockingShutdown {
            name: &'static str,
            block: bool,
            entered: Arc<Barrier>,
            release: Arc<Barrier>,
            calls: Arc<AtomicUsize>,
        }
        #[async_trait]
        impl Extension for BlockingShutdown {
            fn name(&self) -> &str {
                self.name
            }
            async fn init(&self, _: Host) -> ExtensionResult {
                Ok(())
            }
            async fn shutdown(&self) -> ExtensionResult {
                self.calls.fetch_add(1, Ordering::SeqCst);
                if self.block {
                    self.entered.wait().await;
                    self.release.wait().await;
                }
                Ok(())
            }
            fn permit_duplicate_type(&self) -> bool {
                true
            }
        }

        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let calls = Arc::new(AtomicUsize::new(0));
        let registry = ExtensionRegistry::new();
        for (name, block) in [("blocked", true), ("last", false)] {
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            let calls = Arc::clone(&calls);
            registry
                .register(Definition::new(name, move |_| {
                    Ok(Arc::new(BlockingShutdown {
                        name,
                        block,
                        entered: Arc::clone(&entered),
                        release: Arc::clone(&release),
                        calls: Arc::clone(&calls),
                    }))
                }))
                .unwrap();
        }
        let host = Arc::new(ExtensionHost::new(&registry, Arc::new(System::new())).unwrap());
        host.start().await.unwrap();
        let shutdown_host = Arc::clone(&host);
        let shutdown = tokio::spawn(async move { shutdown_host.shutdown().await });
        tokio::time::timeout(Duration::from_secs(1), entered.wait())
            .await
            .expect("blocking shutdown did not start");
        shutdown.abort();
        let _ = shutdown.await;

        let busy = host.shutdown().await.unwrap_err();
        assert_eq!(busy.lifecycle_error(), Some(LifecycleError::Busy));
        release.wait().await;
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match host.shutdown().await {
                    Ok(()) => break,
                    Err(error) if error.lifecycle_error() == Some(LifecycleError::Busy) => {
                        tokio::task::yield_now().await;
                    }
                    Err(error) => panic!("unexpected shutdown error: {error}"),
                }
            }
        })
        .await
        .expect("shutdown retry deadlocked");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn shutdown_timeout_retains_operation_until_retry_observes_quiescence() {
        struct TimedShutdown {
            entered: Arc<Notify>,
            release: Arc<Notify>,
            dropped: Arc<AtomicBool>,
        }
        struct DropFlag(Arc<AtomicBool>);
        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        #[async_trait]
        impl Extension for TimedShutdown {
            fn name(&self) -> &'static str {
                "timed-shutdown"
            }
            async fn init(&self, _: Host) -> ExtensionResult {
                Ok(())
            }
            async fn shutdown(&self) -> ExtensionResult {
                let _alive = DropFlag(Arc::clone(&self.dropped));
                self.entered.notify_one();
                self.release.notified().await;
                Ok(())
            }
        }

        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let dropped = Arc::new(AtomicBool::new(false));
        let registry = ExtensionRegistry::new();
        let factory_entered = Arc::clone(&entered);
        let factory_release = Arc::clone(&release);
        let factory_dropped = Arc::clone(&dropped);
        registry
            .register(Definition::new("timed-shutdown", move |_| {
                Ok(Arc::new(TimedShutdown {
                    entered: Arc::clone(&factory_entered),
                    release: Arc::clone(&factory_release),
                    dropped: Arc::clone(&factory_dropped),
                }))
            }))
            .unwrap();
        let host = ExtensionHost::new(&registry, Arc::new(System::new())).unwrap();
        host.start().await.unwrap();

        let mut shutdown = Box::pin(host.shutdown());
        tokio::select! {
            () = entered.notified() => {}
            result = &mut shutdown => panic!("shutdown returned before callback blocked: {result:?}"),
        }
        let error = shutdown.await.unwrap_err();
        assert_eq!(error.lifecycle_error(), Some(LifecycleError::Busy));
        assert!(!dropped.load(Ordering::SeqCst));
        assert!(host.is_transitioning());
        assert_eq!(
            host.shutdown().await.unwrap_err().lifecycle_error(),
            Some(LifecycleError::Busy)
        );

        release.notify_one();
        tokio::time::timeout(Duration::from_secs(1), async {
            while host.is_transitioning() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("owned shutdown did not reach quiescence");
        assert!(dropped.load(Ordering::SeqCst));
        host.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn callback_children_can_publish_and_attempt_shutdown_without_deadlock() {
        struct CallbackExtension;
        #[async_trait]
        impl Extension for CallbackExtension {
            fn name(&self) -> &'static str {
                "callback-children"
            }
            async fn init(&self, host: Host) -> ExtensionResult {
                let events = host.system()?.get::<Arc<Mutex<Vec<State>>>>()?;
                let owner = host.system()?.get::<Arc<OnceLock<Weak<ExtensionHost>>>>()?;
                let hooks = host.hooks()?;
                hooks.backend_state_change.add(Arc::new(move |state| {
                    events.lock().unwrap().push(state);
                    if state != State::Running {
                        return;
                    }
                    let child_host = host.clone();
                    std::thread::spawn(move || {
                        child_host.publish_backend_state(State::NeedsLogin).unwrap();
                    })
                    .join()
                    .unwrap();

                    let owner = owner.get().unwrap().upgrade().unwrap();
                    let (done_tx, done_rx) = mpsc::channel();
                    tokio::spawn(async move {
                        done_tx.send(owner.shutdown().await).unwrap();
                    });
                    let shutdown = done_rx
                        .recv_timeout(Duration::from_secs(1))
                        .expect("child shutdown deadlocked in publication callback")
                        .unwrap_err();
                    assert_eq!(shutdown.lifecycle_error(), Some(LifecycleError::Busy));
                }));
                Ok(())
            }
            async fn shutdown(&self) -> ExtensionResult {
                Ok(())
            }
        }

        let system = Arc::new(System::new());
        let events = Arc::new(Mutex::new(Vec::<State>::new()));
        let owner = Arc::new(OnceLock::new());
        system.set_value(Arc::clone(&events)).unwrap();
        system.set_value(Arc::clone(&owner)).unwrap();
        let registry = ExtensionRegistry::new();
        registry
            .register(Definition::new("callback-children", |_| {
                Ok(Arc::new(CallbackExtension))
            }))
            .unwrap();
        let host = Arc::new(ExtensionHost::new(&registry, system).unwrap());
        owner.set(Arc::downgrade(&host)).unwrap();
        host.start().await.unwrap();
        let handle = host.host();
        tokio::time::timeout(Duration::from_secs(1), async move {
            handle.publish_backend_state(State::Running).unwrap();
        })
        .await
        .expect("publication callback deadlocked");
        assert_eq!(*events.lock().unwrap(), [State::Running, State::NeedsLogin]);
        host.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn reentrant_lifecycle_calls_fail_without_deadlock() {
        struct ReentrantExtension {
            owner: Arc<OnceLock<Weak<ExtensionHost>>>,
            init_busy: Arc<AtomicBool>,
            shutdown_busy: Arc<AtomicBool>,
        }
        #[async_trait]
        impl Extension for ReentrantExtension {
            fn name(&self) -> &'static str {
                "reentrant"
            }
            async fn init(&self, _: Host) -> ExtensionResult {
                let owner = self.owner.get().unwrap().upgrade().unwrap();
                let result = tokio::time::timeout(Duration::from_secs(1), async move {
                    tokio::spawn(async move { owner.start().await })
                        .await
                        .unwrap()
                })
                .await
                .expect("indirect reentrant start deadlocked");
                self.init_busy.store(
                    matches!(result, Err(LifecycleError::Busy)),
                    Ordering::SeqCst,
                );
                Ok(())
            }
            async fn shutdown(&self) -> ExtensionResult {
                let owner = self.owner.get().unwrap().upgrade().unwrap();
                let error = tokio::time::timeout(Duration::from_secs(1), async move {
                    tokio::spawn(async move { owner.shutdown().await })
                        .await
                        .unwrap()
                })
                .await
                .expect("indirect reentrant shutdown deadlocked")
                .unwrap_err();
                self.shutdown_busy.store(
                    error.lifecycle_error() == Some(LifecycleError::Busy),
                    Ordering::SeqCst,
                );
                Ok(())
            }
        }

        let owner = Arc::new(OnceLock::new());
        let init_busy = Arc::new(AtomicBool::new(false));
        let shutdown_busy = Arc::new(AtomicBool::new(false));
        let registry = ExtensionRegistry::new();
        let factory_owner = Arc::clone(&owner);
        let factory_init_busy = Arc::clone(&init_busy);
        let factory_shutdown_busy = Arc::clone(&shutdown_busy);
        registry
            .register(Definition::new("reentrant", move |_| {
                Ok(Arc::new(ReentrantExtension {
                    owner: Arc::clone(&factory_owner),
                    init_busy: Arc::clone(&factory_init_busy),
                    shutdown_busy: Arc::clone(&factory_shutdown_busy),
                }))
            }))
            .unwrap();
        let host = Arc::new(ExtensionHost::new(&registry, Arc::new(System::new())).unwrap());
        owner.set(Arc::downgrade(&host)).unwrap();
        host.start().await.unwrap();
        host.shutdown().await.unwrap();
        assert!(init_busy.load(Ordering::SeqCst));
        assert!(shutdown_busy.load(Ordering::SeqCst));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn publish_finishes_before_shutdown_and_profile_order_matches_snapshots() {
        struct PublishingExtension {
            host: Arc<OnceLock<Host>>,
            callback_entered: Arc<Notify>,
            callback_release: Arc<Mutex<mpsc::Receiver<()>>>,
            order: Arc<Mutex<Vec<String>>>,
            shutdown_called: Arc<AtomicBool>,
        }
        #[async_trait]
        impl Extension for PublishingExtension {
            fn name(&self) -> &'static str {
                "publisher"
            }
            async fn init(&self, host: Host) -> ExtensionResult {
                self.host.set(host.clone()).unwrap();
                let current = host.clone();
                let entered = Arc::clone(&self.callback_entered);
                let release = Arc::clone(&self.callback_release);
                let order = Arc::clone(&self.order);
                host.hooks()?
                    .profile_state_change
                    .add(Arc::new(move |profile, _, _| {
                        let (snapshot, _) = current.current_profile_state().unwrap();
                        assert_eq!(snapshot.ID, profile.ID);
                        order.lock().unwrap().push(profile.ID.clone());
                        if profile.ID == "first" {
                            entered.notify_one();
                            release.lock().unwrap().recv().unwrap();
                        }
                    }));
                Ok(())
            }
            async fn shutdown(&self) -> ExtensionResult {
                self.shutdown_called.store(true, Ordering::SeqCst);
                Ok(())
            }
        }

        let callback_entered = Arc::new(Notify::new());
        let (release_tx, release_rx) = mpsc::channel();
        let callback_release = Arc::new(Mutex::new(release_rx));
        let order = Arc::new(Mutex::new(Vec::new()));
        let shutdown_called = Arc::new(AtomicBool::new(false));
        let extension_host_handle = Arc::new(OnceLock::new());
        let registry = ExtensionRegistry::new();
        let factory_handle = Arc::clone(&extension_host_handle);
        let factory_entered = Arc::clone(&callback_entered);
        let factory_release = Arc::clone(&callback_release);
        let factory_order = Arc::clone(&order);
        let factory_shutdown = Arc::clone(&shutdown_called);
        registry
            .register(Definition::new("publisher", move |_| {
                Ok(Arc::new(PublishingExtension {
                    host: Arc::clone(&factory_handle),
                    callback_entered: Arc::clone(&factory_entered),
                    callback_release: Arc::clone(&factory_release),
                    order: Arc::clone(&factory_order),
                    shutdown_called: Arc::clone(&factory_shutdown),
                }))
            }))
            .unwrap();
        let host = Arc::new(ExtensionHost::new(&registry, Arc::new(System::new())).unwrap());
        host.start().await.unwrap();
        let api = extension_host_handle.get().unwrap().clone();

        let first_api = api.clone();
        let first = tokio::task::spawn_blocking(move || {
            first_api
                .publish_profile_state(
                    LoginProfile {
                        ID: "first".into(),
                        ..Default::default()
                    },
                    Prefs::default(),
                    false,
                )
                .unwrap();
        });
        tokio::time::timeout(Duration::from_secs(1), callback_entered.notified())
            .await
            .expect("first callback did not start");

        let second_api = api.clone();
        let second = tokio::task::spawn_blocking(move || {
            second_api
                .publish_profile_state(
                    LoginProfile {
                        ID: "second".into(),
                        ..Default::default()
                    },
                    Prefs::default(),
                    true,
                )
                .unwrap();
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if lock_unpoisoned(&host.core.publications.state).queue.len() == 1 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("second publication was not queued");
        let shutdown_host = Arc::clone(&host);
        let shutdown = tokio::spawn(async move { shutdown_host.shutdown().await });
        let busy = tokio::time::timeout(Duration::from_secs(1), shutdown)
            .await
            .expect("shutdown waited on a publication callback")
            .unwrap()
            .unwrap_err();
        assert_eq!(busy.lifecycle_error(), Some(LifecycleError::Busy));
        assert!(!shutdown_called.load(Ordering::SeqCst));
        assert_eq!(*order.lock().unwrap(), ["first"]);

        release_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), first)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), second)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), host.shutdown())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(*order.lock().unwrap(), ["first", "second"]);
        assert!(shutdown_called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn persisted_profile_is_visible_during_init() {
        struct SeedExtension(Arc<Mutex<Option<String>>>);
        #[async_trait]
        impl Extension for SeedExtension {
            fn name(&self) -> &'static str {
                "seed"
            }
            async fn init(&self, host: Host) -> ExtensionResult {
                let (profile, prefs) = host.current_profile_state()?;
                *self.0.lock().unwrap() = Some(format!("{}:{}", profile.ID, prefs.Hostname));
                Ok(())
            }
            async fn shutdown(&self) -> ExtensionResult {
                Ok(())
            }
        }

        let observed = Arc::new(Mutex::new(None));
        let registry = ExtensionRegistry::new();
        let factory_observed = Arc::clone(&observed);
        registry
            .register(Definition::new("seed", move |_| {
                Ok(Arc::new(SeedExtension(Arc::clone(&factory_observed))))
            }))
            .unwrap();
        let host = ExtensionHost::new(&registry, Arc::new(System::new())).unwrap();
        host.seed_profile_state(
            LoginProfile {
                ID: "persisted".into(),
                ..Default::default()
            },
            Prefs {
                Hostname: "node".into(),
                ..Default::default()
            },
        )
        .unwrap();
        host.start().await.unwrap();
        assert_eq!(observed.lock().unwrap().as_deref(), Some("persisted:node"));
    }

    #[tokio::test]
    async fn active_name_lookup_never_calls_extension_name_under_lock() {
        struct NameExtension {
            armed: Arc<AtomicBool>,
            calls_after_init: Arc<AtomicUsize>,
            host: Arc<OnceLock<Host>>,
        }
        #[async_trait]
        impl Extension for NameExtension {
            fn name(&self) -> &'static str {
                if self.armed.load(Ordering::SeqCst) {
                    self.calls_after_init.fetch_add(1, Ordering::SeqCst);
                    let _ = self.host.get().unwrap().find_extension_by_name("name");
                }
                "name"
            }
            async fn init(&self, host: Host) -> ExtensionResult {
                self.host.set(host).unwrap();
                self.armed.store(true, Ordering::SeqCst);
                Ok(())
            }
            async fn shutdown(&self) -> ExtensionResult {
                Ok(())
            }
        }

        let armed = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(AtomicUsize::new(0));
        let extension_host = Arc::new(OnceLock::new());
        let registry = ExtensionRegistry::new();
        let factory_armed = Arc::clone(&armed);
        let factory_calls = Arc::clone(&calls);
        let factory_host = Arc::clone(&extension_host);
        registry
            .register(Definition::new("name", move |_| {
                Ok(Arc::new(NameExtension {
                    armed: Arc::clone(&factory_armed),
                    calls_after_init: Arc::clone(&factory_calls),
                    host: Arc::clone(&factory_host),
                }))
            }))
            .unwrap();
        let host = ExtensionHost::new(&registry, Arc::new(System::new())).unwrap();
        host.start().await.unwrap();
        let api = host.host();
        let (done_tx, done_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let found = api.find_extension_by_name("name").unwrap().is_some();
            let _ = done_tx.send(found);
        });
        assert!(done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("reentrant name lookup deadlocked"));
        assert_eq!(host.active_names(), ["name"]);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        host.shutdown().await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}
