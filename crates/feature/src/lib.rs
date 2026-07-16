//! Feature registration and hooks.
//!
//! This crate provides the infrastructure used by optional features without
//! coupling the users of a feature to its implementation. Registries return
//! sorted snapshots, [`Hook`] stores one implementation, and [`Hooks`] stores
//! multiple implementations in registration order.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::{Arc, Condvar, OnceLock, RwLock};
use std::thread::{self, ThreadId};
use std::{sync::Mutex, vec::Vec};

/// Error returned when an optional feature is not included in the build.
///
/// This unit struct is also a comparable sentinel value, so callers can match
/// or compare it directly when handling optional feature results.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Unavailable;

impl fmt::Display for Unavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("feature not included in this build")
    }
}

impl Error for Unavailable {}

/// A thread-safe collection of linked feature names.
///
/// Registration is normally performed during startup. Snapshot reads are safe
/// to perform concurrently with registration and are sorted by feature name.
#[derive(Debug, Default)]
pub struct Registry {
    names: RwLock<BTreeSet<String>>,
}

impl Registry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            names: RwLock::new(BTreeSet::new()),
        }
    }

    /// Registers `name`.
    ///
    /// Returns an error if the name was already registered.
    pub fn register(&self, name: impl Into<String>) -> Result<(), DuplicateFeature> {
        let name = name.into();
        let mut names = self.names.write().expect("feature registry lock poisoned");
        if !names.insert(name.clone()) {
            return Err(DuplicateFeature { name });
        }
        Ok(())
    }

    /// Returns a sorted snapshot of all registered feature names.
    pub fn registered(&self) -> Vec<String> {
        self.names
            .read()
            .expect("feature registry lock poisoned")
            .iter()
            .cloned()
            .collect()
    }

    /// Returns whether `name` is registered.
    pub fn contains(&self, name: &str) -> bool {
        self.names
            .read()
            .expect("feature registry lock poisoned")
            .contains(name)
    }

    /// Returns the number of registered features.
    pub fn len(&self) -> usize {
        self.names
            .read()
            .expect("feature registry lock poisoned")
            .len()
    }

    /// Returns whether no features are registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// An error returned when a feature name is registered more than once.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DuplicateFeature {
    name: String,
}

impl DuplicateFeature {
    /// Returns the duplicate feature name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for DuplicateFeature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "duplicate feature registration for {}", self.name)
    }
}

impl Error for DuplicateFeature {}

static GLOBAL_REGISTRY: OnceLock<Registry> = OnceLock::new();

fn global_registry() -> &'static Registry {
    GLOBAL_REGISTRY.get_or_init(Registry::new)
}

/// Registers a feature in the process-wide registry.
pub fn register(name: impl Into<String>) -> Result<(), DuplicateFeature> {
    global_registry().register(name)
}

/// Returns a sorted snapshot of the process-wide registered features.
pub fn registered() -> Vec<String> {
    global_registry().registered()
}

/// Returns whether a feature is in the process-wide registry.
pub fn is_registered(name: &str) -> bool {
    global_registry().contains(name)
}

/// Boxed error returned across optional feature hook boundaries.
pub type BoxError = Box<dyn Error + Send + Sync + 'static>;

/// Owned, sendable future returned by asynchronous feature hooks.
pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// Parameters for resolving a one-use auth key through workload identity
/// federation. The type intentionally does not implement `Debug`: it contains
/// an identity token.
pub struct IdentityFederationRequest {
    pub base_url: String,
    pub client_id: String,
    pub id_token: String,
    pub audience: String,
    pub tags: Vec<String>,
}

/// Parameters for resolving an OAuth client secret into a one-use auth key.
/// The type intentionally does not implement `Debug`: it contains a secret.
pub struct OAuthAuthKeyRequest {
    pub client_secret: String,
    pub tags: Vec<String>,
}

/// Parameters for exchanging an identity JWT for a Tailscale access token.
/// The type intentionally does not implement `Debug`: it contains a JWT.
pub struct JwtExchangeRequest {
    pub base_url: String,
    pub client_id: String,
    pub id_token: String,
}

/// OAuth client-secret auth-key resolver hook.
pub type OAuthAuthKeyResolver =
    Arc<dyn Fn(OAuthAuthKeyRequest) -> BoxFuture<Result<String, BoxError>> + Send + Sync + 'static>;

/// Workload identity auth-key resolver hook.
pub type IdentityFederationResolver = Arc<
    dyn Fn(IdentityFederationRequest) -> BoxFuture<Result<String, BoxError>>
        + Send
        + Sync
        + 'static,
>;

/// Workload identity JWT exchange hook.
pub type JwtExchanger =
    Arc<dyn Fn(JwtExchangeRequest) -> BoxFuture<Result<String, BoxError>> + Send + Sync + 'static>;

/// Resolver installed by the OAuth auth-key feature package.
pub static RESOLVE_AUTH_KEY_VIA_OAUTH: Hook<OAuthAuthKeyResolver> = Hook::new();

/// Resolver installed by the workload identity federation package.
pub static RESOLVE_AUTH_KEY_VIA_WIF: Hook<IdentityFederationResolver> = Hook::new();

/// JWT exchanger installed by the workload identity federation package.
pub static EXCHANGE_JWT_FOR_TOKEN_VIA_WIF: Hook<JwtExchanger> = Hook::new();

#[derive(Debug)]
struct HookValue<F> {
    registered: Option<F>,
    overrides: Vec<(u64, F)>,
}

impl<F> HookValue<F> {
    const fn new() -> Self {
        Self {
            registered: None,
            overrides: Vec::new(),
        }
    }

    fn current(&self) -> Option<&F> {
        self.overrides
            .last()
            .map(|(_, function)| function)
            .or(self.registered.as_ref())
    }
}

#[derive(Debug)]
struct OverrideAccess {
    owner: Option<ThreadId>,
    depth: usize,
    next_id: u64,
}

impl OverrideAccess {
    const fn new() -> Self {
        Self {
            owner: None,
            depth: 0,
            next_id: 0,
        }
    }
}

/// A function or callback that can be registered only once.
///
/// Function pointers can be stored directly. Capturing closures can be stored
/// as an `Arc<dyn Fn(...) + Send + Sync>`; cloning the `Arc` makes retrieval
/// inexpensive. Reads are safe from multiple threads.
#[derive(Debug)]
pub struct Hook<F> {
    value: RwLock<HookValue<F>>,
    override_access: Mutex<OverrideAccess>,
    override_available: Condvar,
}

impl<F> Hook<F> {
    /// Creates an unset hook.
    pub const fn new() -> Self {
        Self {
            value: RwLock::new(HookValue::new()),
            override_access: Mutex::new(OverrideAccess::new()),
            override_available: Condvar::new(),
        }
    }

    /// Sets the hook, rejecting a second permanent registration.
    pub fn set(&self, function: F) -> Result<(), HookAlreadySet> {
        let mut value = self.value.write().expect("feature hook lock poisoned");
        if value.registered.is_some() {
            return Err(HookAlreadySet);
        }
        value.registered = Some(function);
        Ok(())
    }

    /// Reports whether the hook currently has a function.
    pub fn is_set(&self) -> bool {
        self.value
            .read()
            .expect("feature hook lock poisoned")
            .current()
            .is_some()
    }

    /// Temporarily replaces this hook and restores it when the guard drops.
    ///
    /// This is intended for tests. Override scopes on the same hook from
    /// different test threads are serialized, so parallel tests cannot replace
    /// one another's value. Nested overrides on one thread are supported.
    #[must_use = "dropping the guard immediately restores the hook"]
    pub fn override_for_test(&self, function: F) -> HookOverride<'_, F> {
        let current_thread = thread::current().id();
        let mut access = self
            .override_access
            .lock()
            .expect("feature hook override lock poisoned");
        while access
            .owner
            .as_ref()
            .is_some_and(|owner| *owner != current_thread)
        {
            access = self
                .override_available
                .wait(access)
                .expect("feature hook override lock poisoned");
        }

        access.owner.get_or_insert(current_thread);
        access.depth += 1;
        let id = access.next_id;
        access.next_id = access
            .next_id
            .checked_add(1)
            .expect("feature hook override ID exhausted");
        drop(access);

        self.value
            .write()
            .expect("feature hook lock poisoned")
            .overrides
            .push((id, function));

        HookOverride {
            hook: self,
            id,
            not_send: PhantomData,
        }
    }
}

impl<F: Clone> Hook<F> {
    /// Returns a clone of the current function.
    ///
    /// # Panics
    ///
    /// Panics if the hook is unset. Use [`try_get`](Self::try_get) when an
    /// unset hook is expected.
    pub fn get(&self) -> F {
        self.try_get()
            .expect("get on unset feature hook, without is_set")
    }

    /// Returns a clone of the current function, or `None` when unset.
    pub fn try_get(&self) -> Option<F> {
        self.value
            .read()
            .expect("feature hook lock poisoned")
            .current()
            .cloned()
    }
}

impl<F> Default for Hook<F> {
    fn default() -> Self {
        Self::new()
    }
}

/// An error returned when a single hook is set more than once.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct HookAlreadySet;

impl fmt::Display for HookAlreadySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("set on already-set feature hook")
    }
}

impl Error for HookAlreadySet {}

/// A scoped test override returned by [`Hook::override_for_test`].
///
/// The guard is deliberately not `Send`: keeping an override on its creating
/// thread lets nested scopes be distinguished from parallel test threads.
#[derive(Debug)]
pub struct HookOverride<'a, F> {
    hook: &'a Hook<F>,
    id: u64,
    not_send: PhantomData<Rc<()>>,
}

impl<F> Drop for HookOverride<'_, F> {
    fn drop(&mut self) {
        let mut value = self.hook.value.write().expect("feature hook lock poisoned");
        let position = value
            .overrides
            .iter()
            .position(|(id, _)| *id == self.id)
            .expect("active feature hook override missing");
        value.overrides.remove(position);
        drop(value);

        let mut access = self
            .hook
            .override_access
            .lock()
            .expect("feature hook override lock poisoned");
        access.depth = access
            .depth
            .checked_sub(1)
            .expect("feature hook override depth underflow");
        if access.depth == 0 {
            access.owner = None;
            self.hook.override_available.notify_one();
        }
    }
}

/// An ordered collection of callbacks installed by multiple parties.
#[derive(Debug)]
pub struct Hooks<F> {
    functions: RwLock<Vec<F>>,
}

impl<F> Hooks<F> {
    /// Creates an empty callback collection.
    pub const fn new() -> Self {
        Self {
            functions: RwLock::new(Vec::new()),
        }
    }

    /// Adds a callback at the end of the collection.
    pub fn add(&self, function: F) {
        self.functions
            .write()
            .expect("feature hooks lock poisoned")
            .push(function);
    }

    /// Returns the number of callbacks.
    pub fn len(&self) -> usize {
        self.functions
            .read()
            .expect("feature hooks lock poisoned")
            .len()
    }

    /// Returns whether no callbacks have been added.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<F: Clone> Hooks<F> {
    /// Returns a snapshot in callback registration order.
    pub fn snapshot(&self) -> Vec<F> {
        self.functions
            .read()
            .expect("feature hooks lock poisoned")
            .clone()
    }
}

impl<F> Default for Hooks<F> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::panic::{self, AssertUnwindSafe};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    use super::{
        is_registered, register, registered, Hook, HookAlreadySet, Hooks, Registry, Unavailable,
    };

    #[test]
    fn unavailable_is_a_comparable_standard_error() {
        fn optional_feature() -> Result<(), Unavailable> {
            Err(Unavailable)
        }

        let error = optional_feature().unwrap_err();
        assert_eq!(error, Unavailable);
        assert_eq!(error.to_string(), "feature not included in this build");

        let standard_error: &dyn std::error::Error = &error;
        assert!(standard_error.source().is_none());
    }

    #[test]
    fn process_registry_uses_the_same_sorted_snapshot_semantics() {
        register("feature-test-zebra").unwrap();
        register("feature-test-alpha").unwrap();

        assert!(is_registered("feature-test-alpha"));
        let names = registered();
        assert!(names.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(names.iter().any(|name| name == "feature-test-zebra"));
    }

    #[test]
    fn registry_lists_features_deterministically() {
        let registry = Registry::new();
        registry.register("zebra").unwrap();
        registry.register("alpha").unwrap();
        registry.register("middle").unwrap();

        assert_eq!(registry.registered(), ["alpha", "middle", "zebra"]);
        assert!(registry.contains("middle"));
        assert_eq!(registry.len(), 3);
    }

    #[test]
    fn registry_rejects_duplicate_names() {
        let registry = Registry::new();
        registry.register("capture").unwrap();

        let error = registry.register("capture").unwrap_err();
        assert_eq!(error.name(), "capture");
        assert_eq!(registry.registered(), ["capture"]);
    }

    #[test]
    fn registry_supports_concurrent_registration_and_reads() {
        const WRITERS: usize = 8;
        let registry = Arc::new(Registry::new());
        let start = Arc::new(Barrier::new(WRITERS + 2));
        let done = Arc::new(AtomicBool::new(false));
        let mut threads = Vec::new();

        for index in 0..WRITERS {
            let registry = Arc::clone(&registry);
            let start = Arc::clone(&start);
            threads.push(thread::spawn(move || {
                start.wait();
                for item in 0..100 {
                    registry
                        .register(format!("feature-{index:02}-{item:03}"))
                        .unwrap();
                }
            }));
        }

        let reader_registry = Arc::clone(&registry);
        let reader_start = Arc::clone(&start);
        let reader_done = Arc::clone(&done);
        let reader = thread::spawn(move || {
            reader_start.wait();
            while !reader_done.load(Ordering::Acquire) {
                let names = reader_registry.registered();
                assert!(names.windows(2).all(|pair| pair[0] < pair[1]));
            }
        });

        start.wait();
        for thread in threads {
            thread.join().unwrap();
        }
        done.store(true, Ordering::Release);
        reader.join().unwrap();
        assert_eq!(registry.len(), WRITERS * 100);
    }

    #[test]
    fn hook_retrieval_is_callable_and_duplicate_set_is_rejected() {
        let hook = Hook::<fn(usize) -> usize>::new();
        assert!(!hook.is_set());
        assert!(hook.try_get().is_none());

        hook.set(|value| value + 1).unwrap();
        assert!(hook.is_set());
        assert_eq!(hook.get()(41), 42);
        assert_eq!(hook.set(|value| value * 2), Err(HookAlreadySet));
        assert_eq!(hook.get()(4), 5);
    }

    #[test]
    fn get_panics_when_hook_is_unset() {
        let hook = Hook::<fn()>::new();
        assert!(panic::catch_unwind(|| hook.get()).is_err());
    }

    #[test]
    fn hook_reads_are_concurrent() {
        let hook = Arc::new(Hook::<fn(usize) -> usize>::new());
        hook.set(|value| value + 10).unwrap();
        let mut readers = Vec::new();

        for index in 0..16 {
            let hook = Arc::clone(&hook);
            readers.push(thread::spawn(move || {
                for _ in 0..1_000 {
                    assert_eq!(hook.get()(index), index + 10);
                }
            }));
        }
        for reader in readers {
            reader.join().unwrap();
        }
    }

    #[test]
    fn hook_test_override_restores_after_scope_and_panic() {
        let hook = Hook::<fn() -> usize>::new();
        hook.set(|| 1).unwrap();
        {
            let _override = hook.override_for_test(|| 2);
            assert_eq!(hook.get()(), 2);
            {
                let _nested = hook.override_for_test(|| 3);
                assert_eq!(hook.get()(), 3);
            }
            assert_eq!(hook.get()(), 2);
        }
        assert_eq!(hook.get()(), 1);

        let result = panic::catch_unwind(AssertUnwindSafe(|| {
            let _override = hook.override_for_test(|| 4);
            assert_eq!(hook.get()(), 4);
            panic!("exercise unwind restoration");
        }));
        assert!(result.is_err());
        assert_eq!(hook.get()(), 1);
    }

    #[test]
    fn override_of_unset_hook_restores_unset_state() {
        let hook = Hook::<fn() -> usize>::new();
        {
            let _override = hook.override_for_test(|| 9);
            assert_eq!(hook.get()(), 9);
        }
        assert!(!hook.is_set());
        assert!(hook.try_get().is_none());
    }

    #[test]
    fn parallel_test_overrides_are_serialized() {
        let hook = Arc::new(Hook::<fn() -> usize>::new());
        hook.set(|| 0).unwrap();
        let (first_entered_tx, first_entered_rx) = mpsc::channel();
        let (release_first_tx, release_first_rx) = mpsc::channel();
        let (second_attempted_tx, second_attempted_rx) = mpsc::channel();
        let (second_entered_tx, second_entered_rx) = mpsc::channel();

        let first_hook = Arc::clone(&hook);
        let first = thread::spawn(move || {
            let _override = first_hook.override_for_test(|| 1);
            first_entered_tx.send(()).unwrap();
            release_first_rx.recv().unwrap();
            assert_eq!(first_hook.get()(), 1);
        });
        first_entered_rx.recv().unwrap();

        let second_hook = Arc::clone(&hook);
        let second = thread::spawn(move || {
            second_attempted_tx.send(()).unwrap();
            let _override = second_hook.override_for_test(|| 2);
            assert_eq!(second_hook.get()(), 2);
            second_entered_tx.send(()).unwrap();
        });
        second_attempted_rx.recv().unwrap();
        assert!(second_entered_rx
            .recv_timeout(Duration::from_millis(50))
            .is_err());

        release_first_tx.send(()).unwrap();
        first.join().unwrap();
        second_entered_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap();
        second.join().unwrap();
        assert_eq!(hook.get()(), 0);
    }

    #[test]
    fn multiple_hooks_run_in_registration_order() {
        type Callback = Arc<dyn Fn(&AtomicUsize) -> usize + Send + Sync>;

        let hooks = Hooks::<Callback>::new();
        hooks.add(Arc::new(|sequence| sequence.fetch_add(1, Ordering::SeqCst)));
        hooks.add(Arc::new(|sequence| {
            sequence.fetch_add(10, Ordering::SeqCst)
        }));
        hooks.add(Arc::new(|sequence| {
            sequence.fetch_add(100, Ordering::SeqCst)
        }));

        let sequence = AtomicUsize::new(0);
        let observed: Vec<_> = hooks
            .snapshot()
            .into_iter()
            .map(|callback| callback(&sequence))
            .collect();
        assert_eq!(observed, [0, 1, 11]);
        assert_eq!(sequence.load(Ordering::SeqCst), 111);
        assert_eq!(hooks.len(), 3);
    }
}
