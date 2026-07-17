use std::{
    collections::BTreeMap,
    fs,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Barrier, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use tempfile::{tempdir, NamedTempFile};

use crate::watch::test_clock::FakeWatchClock;

use crate::*;

fn test_file_trust() -> Arc<dyn FileTrustPolicy> {
    Arc::new(|metadata: &fs::Metadata| metadata.is_file())
}

fn memory(values: impl IntoIterator<Item = (PolicyKey, RawValue)>) -> Arc<MemoryProvider> {
    Arc::new(MemoryProvider::from_values(values.into_iter().collect()))
}

fn wait_until(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !predicate() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(predicate(), "condition did not become true before timeout");
}

struct ToggleProvider {
    fail: AtomicBool,
    key: PolicyKey,
    value: RawValue,
}

impl ToggleProvider {
    fn new(key: PolicyKey, value: RawValue) -> Self {
        Self {
            fail: AtomicBool::new(false),
            key,
            value,
        }
    }
}

impl PolicyProvider for ToggleProvider {
    fn load(&self, _definitions: &[SettingDefinition]) -> Result<ProviderValues, PolicyError> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(PolicyError::new(PolicyErrorKind::Provider));
        }
        Ok(BTreeMap::from([(self.key, Ok(self.value.clone()))]))
    }
}

struct StoredCallbackProvider {
    callback: Arc<Mutex<Option<Arc<dyn Fn() + Send + Sync>>>>,
    loads: AtomicUsize,
}

impl StoredCallbackProvider {
    fn new() -> Self {
        Self {
            callback: Arc::new(Mutex::new(None)),
            loads: AtomicUsize::new(0),
        }
    }

    fn notify_many(&self, count: usize) {
        let callback = self.callback.lock().unwrap().clone().unwrap();
        for _ in 0..count {
            callback();
        }
    }
}

struct StoredCallbackSubscription {
    callback: Arc<Mutex<Option<Arc<dyn Fn() + Send + Sync>>>>,
    notify_on_drop: bool,
}

impl ProviderSubscription for StoredCallbackSubscription {}

impl Drop for StoredCallbackSubscription {
    fn drop(&mut self) {
        let callback = self.callback.lock().unwrap().take();
        if self.notify_on_drop {
            if let Some(callback) = callback {
                callback();
            }
        }
    }
}

struct RetryProvider {
    callback: Arc<Mutex<Option<Arc<dyn Fn() + Send + Sync>>>>,
    value: Mutex<String>,
    failures: AtomicUsize,
    loads: AtomicUsize,
}

impl RetryProvider {
    fn new(value: &str) -> Self {
        Self {
            callback: Arc::new(Mutex::new(None)),
            value: Mutex::new(value.into()),
            failures: AtomicUsize::new(0),
            loads: AtomicUsize::new(0),
        }
    }

    fn change_with_failures(&self, value: &str, failures: usize) {
        *self.value.lock().unwrap() = value.into();
        self.failures.store(failures, Ordering::SeqCst);
        self.callback.lock().unwrap().clone().unwrap()();
    }
}

impl PolicyProvider for RetryProvider {
    fn load(&self, _definitions: &[SettingDefinition]) -> Result<ProviderValues, PolicyError> {
        self.loads.fetch_add(1, Ordering::SeqCst);
        if self
            .failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                (remaining != 0).then(|| remaining - 1)
            })
            .is_ok()
        {
            return Err(PolicyError::new(PolicyErrorKind::Provider));
        }
        Ok(BTreeMap::from([(
            PolicyKey::Tailnet,
            Ok(RawValue::String(self.value.lock().unwrap().clone())),
        )]))
    }

    fn subscribe(
        &self,
        callback: Arc<dyn Fn() + Send + Sync>,
    ) -> Result<Option<Box<dyn ProviderSubscription>>, PolicyError> {
        *self.callback.lock().unwrap() = Some(callback);
        Ok(Some(Box::new(StoredCallbackSubscription {
            callback: self.callback.clone(),
            notify_on_drop: false,
        })))
    }
}

impl PolicyProvider for StoredCallbackProvider {
    fn load(&self, definitions: &[SettingDefinition]) -> Result<ProviderValues, PolicyError> {
        self.loads.fetch_add(1, Ordering::SeqCst);
        thread::sleep(Duration::from_millis(20));
        if definitions
            .iter()
            .any(|definition| definition.key == PolicyKey::Tailnet)
        {
            Ok(BTreeMap::from([(
                PolicyKey::Tailnet,
                Ok(RawValue::String("stored".into())),
            )]))
        } else {
            Ok(BTreeMap::new())
        }
    }

    fn subscribe(
        &self,
        callback: Arc<dyn Fn() + Send + Sync>,
    ) -> Result<Option<Box<dyn ProviderSubscription>>, PolicyError> {
        *self.callback.lock().unwrap() = Some(callback);
        Ok(Some(Box::new(StoredCallbackSubscription {
            callback: self.callback.clone(),
            notify_on_drop: true,
        })))
    }
}

#[test]
fn definitions_match_well_known_keys() {
    let definitions = well_known_definitions();
    assert_eq!(definitions.len(), PolicyKey::ALL.len());
    for definition in definitions {
        assert_eq!(definition, definition.key.definition());
        assert_eq!(
            PolicyKey::from_name(definition.key.wire_name()),
            Some(definition.key)
        );
    }
    assert_eq!(PolicyKey::ControlURL.wire_name(), "LoginURL");
    assert_eq!(PolicyKey::ApplyUpdates.wire_name(), "InstallUpdates");
    assert_eq!(PolicyKey::AutoUpdateVisibility.wire_name(), "ApplyUpdates");
}

#[test]
fn conflicting_definitions_are_rejected() {
    let error = PolicyEngine::new(
        PolicyScope::Device,
        [
            SettingDefinition::new(PolicyKey::Tailnet, Scope::Device, ValueType::String),
            SettingDefinition::new(PolicyKey::Tailnet, Scope::Device, ValueType::Boolean),
        ],
    )
    .err()
    .expect("conflicting definitions must fail");
    assert_eq!(error.kind, PolicyErrorKind::InvalidDefinition);
}

#[test]
fn scope_contains_and_definition_rules() {
    let device = PolicyScope::Device;
    let profile = PolicyScope::Profile(Some("p1".into()));
    let user = PolicyScope::User {
        user_id: Some("u1".into()),
        profile_id: Some("p1".into()),
    };
    assert!(device.contains(&profile));
    assert!(device.contains(&user));
    assert!(profile.contains(&user));
    assert!(!user.contains(&profile));
    assert!(user.is_applicable(&PolicyKey::Tailnet.definition()));
    assert!(!user.can_configure(&PolicyKey::Tailnet.definition()));
    assert!(device.can_configure(&PolicyKey::AdminConsoleVisibility.definition()));
}

#[test]
fn environment_names_and_values_follow_upstream_shape() {
    assert_eq!(
        environment_variable_name(PolicyKey::EnableDNSRegistration),
        "TS_DEBUGSYSPOLICY_ENABLE_DNS_REGISTRATION"
    );
    assert_eq!(
        environment_variable_name(PolicyKey::AlwaysOn),
        "TS_DEBUGSYSPOLICY_ALWAYS_ON_ENABLED"
    );

    let provider = EnvironmentProvider::from_map(BTreeMap::from([
        (
            "TS_DEBUGSYSPOLICY_LOG_SCM_INTERACTIONS".into(),
            "True".into(),
        ),
        (
            "TS_DEBUGSYSPOLICY_ALLOWED_SUGGESTED_EXIT_NODES".into(),
            " node-a, ,node-b ".into(),
        ),
    ]));
    let values = provider
        .load(&[
            PolicyKey::LogSCMInteractions.definition(),
            PolicyKey::AllowedSuggestedExitNodes.definition(),
        ])
        .unwrap();
    assert_eq!(
        values[&PolicyKey::LogSCMInteractions],
        Ok(RawValue::Boolean(true))
    );
    assert_eq!(
        values[&PolicyKey::AllowedSuggestedExitNodes],
        Ok(RawValue::StringList(vec!["node-a".into(), "node-b".into()]))
    );
}

#[test]
fn json_provider_is_bounded_and_preserves_item_errors() {
    let file = NamedTempFile::new().unwrap();
    fs::write(
        file.path(),
        r#"{"Tailnet":"example.ts.net","LogSCMInteractions":"yes"}"#,
    )
    .unwrap();
    let provider = JsonFileProvider::new(file.path()).with_file_trust(test_file_trust());
    let values = provider
        .load(&[
            PolicyKey::Tailnet.definition(),
            PolicyKey::LogSCMInteractions.definition(),
        ])
        .unwrap();
    assert_eq!(
        values[&PolicyKey::Tailnet],
        Ok(RawValue::String("example.ts.net".into()))
    );
    assert_eq!(
        values[&PolicyKey::LogSCMInteractions]
            .as_ref()
            .unwrap_err()
            .kind,
        PolicyErrorKind::TypeMismatch
    );

    let error = JsonFileProvider::new(file.path())
        .with_file_trust(test_file_trust())
        .with_max_size(8)
        .load(&[PolicyKey::Tailnet.definition()])
        .unwrap_err();
    assert_eq!(error.kind, PolicyErrorKind::TooLarge);
    assert_eq!(error.key, None);
}

#[cfg(unix)]
#[test]
fn managed_json_rejects_untrusted_modes_symlinks_and_fifos() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::process::Command;

    let directory = tempdir().unwrap();
    let regular = directory.path().join("policy.json");
    fs::write(&regular, r#"{"Tailnet":"managed"}"#).unwrap();
    fs::set_permissions(&regular, fs::Permissions::from_mode(0o666)).unwrap();
    let error = JsonFileProvider::new(&regular)
        .load(&[PolicyKey::Tailnet.definition()])
        .unwrap_err();
    assert_eq!(error.kind, PolicyErrorKind::Untrusted);

    let link = directory.path().join("policy-link.json");
    symlink(&regular, &link).unwrap();
    let error = JsonFileProvider::new(&link)
        .with_file_trust(test_file_trust())
        .load(&[PolicyKey::Tailnet.definition()])
        .unwrap_err();
    assert_eq!(error.kind, PolicyErrorKind::Io);

    let fifo = directory.path().join("policy.fifo");
    assert!(Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    let started = Instant::now();
    let error = JsonFileProvider::new(&fifo)
        .with_file_trust(test_file_trust())
        .load(&[PolicyKey::Tailnet.definition()])
        .unwrap_err();
    assert_eq!(error.kind, PolicyErrorKind::Untrusted);
    assert!(started.elapsed() < MAX_POLICY_READ_TIME);
}

#[test]
fn managed_json_trust_is_injectable_for_tests() {
    let file = NamedTempFile::new().unwrap();
    fs::write(file.path(), r#"{"Tailnet":"trusted-for-test"}"#).unwrap();
    let values = JsonFileProvider::new(file.path())
        .with_file_trust(test_file_trust())
        .load(&[PolicyKey::Tailnet.definition()])
        .unwrap();
    assert_eq!(
        values[&PolicyKey::Tailnet],
        Ok(RawValue::String("trusted-for-test".into()))
    );
}

#[test]
fn invalid_json_does_not_echo_contents_in_error() {
    let file = NamedTempFile::new().unwrap();
    fs::write(file.path(), r#"{"AuthKey":"tskey-secret-value""#).unwrap();
    let error = JsonFileProvider::new(file.path())
        .with_file_trust(test_file_trust())
        .load(&[PolicyKey::AuthKey.definition()])
        .unwrap_err();
    assert_eq!(error.kind, PolicyErrorKind::Parse);
    assert!(!error.to_string().contains("tskey-secret-value"));
}

#[test]
fn scoped_precedence_and_same_scope_order_are_deterministic() {
    let engine = PolicyEngine::well_known(PolicyScope::User {
        user_id: None,
        profile_id: None,
    })
    .unwrap();
    engine
        .add_provider(
            "user",
            PolicyScope::User {
                user_id: None,
                profile_id: None,
            },
            memory([(
                PolicyKey::AdminConsoleVisibility,
                RawValue::String("hide".into()),
            )]),
        )
        .unwrap();
    engine
        .add_provider(
            "device-first",
            PolicyScope::Device,
            memory([(
                PolicyKey::AdminConsoleVisibility,
                RawValue::String("show".into()),
            )]),
        )
        .unwrap();
    engine
        .add_provider(
            "device-last",
            PolicyScope::Device,
            memory([(
                PolicyKey::AdminConsoleVisibility,
                RawValue::String("hide".into()),
            )]),
        )
        .unwrap();

    for _ in 0..10 {
        engine.reload().unwrap();
        assert_eq!(
            engine.get_visibility(PolicyKey::AdminConsoleVisibility),
            Ok(Visibility::Hide)
        );
        assert_eq!(
            engine
                .snapshot()
                .item(PolicyKey::AdminConsoleVisibility)
                .unwrap()
                .origin
                .name,
            "device-last"
        );
    }
}

#[test]
fn providers_are_loaded_concurrently_but_merged_in_registration_order() {
    let engine = PolicyEngine::well_known(PolicyScope::Device).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let rendezvous = Arc::new(AtomicBool::new(false));

    struct RendezvousProvider {
        barrier: Arc<Barrier>,
        rendezvous: Arc<AtomicBool>,
        value: &'static str,
    }
    impl PolicyProvider for RendezvousProvider {
        fn load(&self, definitions: &[SettingDefinition]) -> Result<ProviderValues, PolicyError> {
            if self.rendezvous.load(Ordering::SeqCst) {
                self.barrier.wait();
            }
            let mut values = BTreeMap::new();
            if definitions
                .iter()
                .any(|definition| definition.key == PolicyKey::Tailnet)
            {
                values.insert(PolicyKey::Tailnet, Ok(RawValue::String(self.value.into())));
            }
            Ok(values)
        }
    }

    engine
        .add_provider(
            "first",
            PolicyScope::Device,
            Arc::new(RendezvousProvider {
                barrier: barrier.clone(),
                rendezvous: rendezvous.clone(),
                value: "first",
            }),
        )
        .unwrap();
    engine
        .add_provider(
            "second",
            PolicyScope::Device,
            Arc::new(RendezvousProvider {
                barrier,
                rendezvous: rendezvous.clone(),
                value: "second",
            }),
        )
        .unwrap();
    rendezvous.store(true, Ordering::SeqCst);
    engine.reload().unwrap();
    assert_eq!(
        engine.get_string(PolicyKey::Tailnet, ""),
        Ok("second".into())
    );
}

#[test]
fn strict_conversion_and_default_semantics() {
    let engine = PolicyEngine::well_known(PolicyScope::Device).unwrap();
    assert_eq!(
        engine.get_preference_option(PolicyKey::ApplyUpdates, PreferenceOption::Never),
        Ok(PreferenceOption::Never)
    );

    let provider = memory([
        (
            PolicyKey::ApplyUpdates,
            RawValue::String("sometimes".into()),
        ),
        (PolicyKey::ReconnectAfter, RawValue::String("1h30m".into())),
    ]);
    engine
        .add_provider("test", PolicyScope::Device, provider)
        .unwrap();
    assert_eq!(
        engine.get_preference_option(PolicyKey::ApplyUpdates, PreferenceOption::Always),
        Ok(PreferenceOption::Always)
    );
    assert_eq!(
        engine
            .snapshot()
            .item(PolicyKey::ApplyUpdates)
            .unwrap()
            .error
            .as_ref()
            .unwrap()
            .kind,
        PolicyErrorKind::Parse
    );
    assert_eq!(
        engine.get_duration(PolicyKey::ReconnectAfter, Duration::ZERO),
        Ok(Duration::from_secs(90 * 60))
    );
    assert_eq!(
        engine.get_bool(PolicyKey::Tailnet, false).unwrap_err().kind,
        PolicyErrorKind::TypeMismatch
    );
}

#[test]
fn go_duration_parser_is_strict() {
    assert_eq!(parse_go_duration("2h30m"), Ok(Duration::from_secs(9_000)));
    assert_eq!(parse_go_duration("1.5s"), Ok(Duration::from_millis(1_500)));
    assert_eq!(parse_go_duration("250ms"), Ok(Duration::from_millis(250)));
    assert!(parse_go_duration("soon").is_err());
    assert!(parse_go_duration("-1s").is_err());
    assert!(parse_go_duration("1").is_err());
}

#[test]
fn memory_changes_publish_snapshots_and_callbacks() {
    let engine = PolicyEngine::well_known(PolicyScope::Device).unwrap();
    let provider = memory([(PolicyKey::Tailnet, RawValue::String("old".into()))]);
    engine
        .add_provider("memory", PolicyScope::Device, provider.clone())
        .unwrap();

    let changes = Arc::new(Mutex::new(Vec::new()));
    let changes_for_callback = changes.clone();
    let registration = engine.register_change_callback(move |change| {
        changes_for_callback.lock().unwrap().push(change);
    });
    provider.set(PolicyKey::Tailnet, RawValue::String("new".into()));
    wait_until(|| changes.lock().unwrap().len() == 1);
    let changes = changes.lock().unwrap();
    assert!(changes[0].has_changed(PolicyKey::Tailnet));
    assert_eq!(engine.get_string(PolicyKey::Tailnet, ""), Ok("new".into()));
    drop(changes);
    drop(registration);

    provider.notify();
    assert_eq!(engine.get_string(PolicyKey::Tailnet, ""), Ok("new".into()));
}

#[test]
fn managed_provider_beats_later_debug_environment_provider() {
    let engine = PolicyEngine::well_known(PolicyScope::Device).unwrap();
    engine
        .add_provider_with_precedence(
            "managed",
            PolicyScope::Device,
            ProviderPrecedence::Managed,
            memory([(PolicyKey::Tailnet, RawValue::String("managed".into()))]),
        )
        .unwrap();
    engine
        .add_provider_with_precedence(
            "debug",
            PolicyScope::Device,
            ProviderPrecedence::Debug,
            memory([(PolicyKey::Tailnet, RawValue::String("debug".into()))]),
        )
        .unwrap();
    assert_eq!(
        engine.get_string(PolicyKey::Tailnet, ""),
        Ok("managed".into())
    );
    assert_eq!(
        engine
            .snapshot()
            .item(PolicyKey::Tailnet)
            .unwrap()
            .origin
            .name,
        "managed"
    );
}

#[test]
fn provider_cannot_return_key_outside_requested_scope_allowlist() {
    let engine = PolicyEngine::well_known(PolicyScope::User {
        user_id: None,
        profile_id: None,
    })
    .unwrap();
    let malicious = Arc::new(ToggleProvider::new(
        PolicyKey::Tailnet,
        RawValue::String("bypass".into()),
    ));
    let error = engine
        .add_provider(
            "user provider",
            PolicyScope::User {
                user_id: None,
                profile_id: None,
            },
            malicious,
        )
        .unwrap_err();
    assert_eq!(error.kind, PolicyErrorKind::ProviderViolation);
    assert!(engine.snapshot().item(PolicyKey::Tailnet).is_none());
}

#[test]
fn removal_retains_failed_provider_cache_without_removed_ghost_items() {
    let engine = PolicyEngine::well_known(PolicyScope::Device).unwrap();
    let base = engine
        .add_provider(
            "base",
            PolicyScope::Device,
            memory([(PolicyKey::Tailnet, RawValue::String("base".into()))]),
        )
        .unwrap();
    let flaky = Arc::new(ToggleProvider::new(
        PolicyKey::LogTarget,
        RawValue::String("log.example".into()),
    ));
    let flaky_id = engine
        .add_provider("flaky", PolicyScope::Device, flaky.clone())
        .unwrap();
    flaky.fail.store(true, Ordering::SeqCst);

    engine.remove_provider(base).unwrap();
    assert!(engine.snapshot().item(PolicyKey::Tailnet).is_none());
    assert_eq!(
        engine.get_string(PolicyKey::LogTarget, ""),
        Ok("log.example".into())
    );
    assert_eq!(
        engine.last_reload_error().unwrap().kind,
        PolicyErrorKind::Provider
    );
    assert_eq!(
        engine.provider_error(flaky_id).unwrap().kind,
        PolicyErrorKind::Provider
    );
}

#[test]
fn override_drop_restores_cached_managed_value_when_provider_fails() {
    let engine = PolicyEngine::well_known(PolicyScope::Device).unwrap();
    let flaky = Arc::new(ToggleProvider::new(
        PolicyKey::Tailnet,
        RawValue::String("base".into()),
    ));
    engine
        .add_provider("flaky", PolicyScope::Device, flaky.clone())
        .unwrap();
    let policy_override = engine
        .override_for_test(BTreeMap::from([(
            PolicyKey::Tailnet,
            RawValue::String("override".into()),
        )]))
        .unwrap();
    flaky.fail.store(true, Ordering::SeqCst);
    drop(policy_override);
    assert_eq!(engine.get_string(PolicyKey::Tailnet, ""), Ok("base".into()));
    assert_eq!(
        engine.last_reload_error().unwrap().kind,
        PolicyErrorKind::Provider
    );
}

#[test]
fn pending_notification_retries_without_stale_generation() {
    let engine = PolicyEngine::well_known(PolicyScope::Device).unwrap();
    let provider = Arc::new(RetryProvider::new("old"));
    let provider_id = engine
        .add_provider("retry", PolicyScope::Device, provider.clone())
        .unwrap();
    let initial_generation = engine.snapshot().generation();
    let initial_attempts = engine.reload_attempt_count();

    provider.change_with_failures("new", 2);
    wait_until(|| engine.get_string(PolicyKey::Tailnet, "").unwrap() == "new");
    assert!(engine.snapshot().generation() > initial_generation);
    assert!(engine.reload_attempt_count() >= initial_attempts + 3);
    assert_eq!(provider.loads.load(Ordering::SeqCst), 4);
    assert!(engine.last_reload_error().is_none());
    assert!(engine.provider_error(provider_id).is_none());
}

#[test]
fn callback_panics_are_isolated_and_reload_worker_survives() {
    let engine = PolicyEngine::well_known(PolicyScope::Device).unwrap();
    let provider = memory([(PolicyKey::Tailnet, RawValue::String("old".into()))]);
    engine
        .add_provider("memory", PolicyScope::Device, provider.clone())
        .unwrap();
    let panicking = engine.register_change_callback(|_| panic!("isolated callback panic"));
    let calls = Arc::new(AtomicUsize::new(0));
    let callback_calls = calls.clone();
    let healthy = engine.register_change_callback(move |_| {
        callback_calls.fetch_add(1, Ordering::SeqCst);
    });

    provider.set(PolicyKey::Tailnet, RawValue::String("one".into()));
    wait_until(|| calls.load(Ordering::SeqCst) == 1);
    assert_eq!(engine.callback_panic_count(), 1);
    provider.set(PolicyKey::Tailnet, RawValue::String("two".into()));
    wait_until(|| calls.load(Ordering::SeqCst) == 2);
    assert_eq!(engine.callback_panic_count(), 2);
    assert_eq!(engine.get_string(PolicyKey::Tailnet, ""), Ok("two".into()));
    drop((panicking, healthy));
}

#[test]
fn notifications_are_nonblocking_coalesced_and_subscription_drop_is_reentrant_safe() {
    let engine = PolicyEngine::well_known(PolicyScope::Device).unwrap();
    let provider = Arc::new(StoredCallbackProvider::new());
    let id = engine
        .add_provider("notifying", PolicyScope::Device, provider.clone())
        .unwrap();
    assert_eq!(provider.loads.load(Ordering::SeqCst), 1);

    let generation = engine.snapshot().generation();
    provider.notify_many(100);
    wait_until(|| provider.loads.load(Ordering::SeqCst) >= 2);
    thread::sleep(Duration::from_millis(80));
    assert!(
        provider.loads.load(Ordering::SeqCst) < 10,
        "notifications were not coalesced"
    );
    assert_eq!(
        engine.snapshot().generation(),
        generation,
        "unchanged provider refresh advanced snapshot generation"
    );

    // Dropping the subscription invokes its callback. remove_provider must
    // drop it after releasing source/reload locks, so this cannot deadlock or
    // resurrect the removed setting.
    engine.remove_provider(id).unwrap();
    assert!(engine.snapshot().item(PolicyKey::Tailnet).is_none());
}

#[cfg(windows)]
#[test]
fn windows_native_posture_provider_uses_current_provider_contract() {
    fn assert_provider<T: PolicyProvider>() {}
    assert_provider::<NativePostureProvider>();
}

#[test]
fn panicking_pre_commit_hook_releases_prior_barriers_and_keeps_engine_usable() {
    struct ManualProvider(Mutex<String>);

    impl PolicyProvider for ManualProvider {
        fn load(&self, definitions: &[SettingDefinition]) -> Result<ProviderValues, PolicyError> {
            let value = self.0.lock().unwrap().clone();
            Ok(definitions
                .iter()
                .filter(|definition| definition.key == PolicyKey::Tailnet)
                .map(|definition| (definition.key, Ok(RawValue::String(value.clone()))))
                .collect())
        }
    }

    let provider = Arc::new(ManualProvider(Mutex::new("old".into())));
    let engine = PolicyEngine::well_known(PolicyScope::Device).unwrap();
    engine
        .add_provider("manual", PolicyScope::Device, provider.clone())
        .unwrap();

    let barrier_held = Arc::new(AtomicBool::new(false));
    let acquire_flag = barrier_held.clone();
    let _barrier_hook = engine
        .subscribe_snapshot_commits_transactional(
            move |_| -> crate::SnapshotCommitRelease {
                assert!(!acquire_flag.swap(true, Ordering::SeqCst));
                let release_flag = acquire_flag.clone();
                Box::new(move || {
                    release_flag.store(false, Ordering::SeqCst);
                })
            },
            |_| {},
        )
        .0;
    let panic_once = Arc::new(AtomicBool::new(true));
    let panic_flag = panic_once.clone();
    let _panicking_hook = engine
        .subscribe_snapshot_commits_transactional(
            move |_| -> crate::SnapshotCommitRelease {
                assert!(
                    !panic_flag.swap(false, Ordering::SeqCst),
                    "pre-commit panic"
                );
                Box::new(|| {})
            },
            |_| {},
        )
        .0;

    *provider.0.lock().unwrap() = "new".into();
    assert!(engine.reload().is_err());
    assert!(!barrier_held.load(Ordering::SeqCst));
    assert!(matches!(
        engine.current_snapshot_commit(),
        SnapshotCommit::Failed { .. }
    ));
    assert_eq!(engine.callback_panic_count(), 1);

    engine.reload().unwrap();
    assert!(!barrier_held.load(Ordering::SeqCst));
    assert_eq!(
        engine.snapshot().get(PolicyKey::Tailnet),
        Ok(PolicyValue::String("new".into()))
    );
}

#[test]
fn snapshot_commit_subscription_cannot_miss_in_progress_commit() {
    struct BlockingProvider {
        value: Mutex<String>,
        gate: Mutex<
            Option<(
                std::sync::mpsc::SyncSender<()>,
                std::sync::mpsc::Receiver<()>,
            )>,
        >,
    }

    impl PolicyProvider for BlockingProvider {
        fn load(&self, definitions: &[SettingDefinition]) -> Result<ProviderValues, PolicyError> {
            let value = self.value.lock().unwrap().clone();
            if let Some((entered, release)) = self.gate.lock().unwrap().take() {
                entered.send(()).unwrap();
                release.recv().unwrap();
            }
            Ok(definitions
                .iter()
                .filter(|definition| definition.key == PolicyKey::Tailnet)
                .map(|definition| (definition.key, Ok(RawValue::String(value.clone()))))
                .collect())
        }
    }

    let provider = Arc::new(BlockingProvider {
        value: Mutex::new("old".into()),
        gate: Mutex::new(None),
    });
    let engine = PolicyEngine::well_known(PolicyScope::Device).unwrap();
    engine
        .add_provider("blocking", PolicyScope::Device, provider.clone())
        .unwrap();
    let old_generation = engine.snapshot().generation();
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    *provider.value.lock().unwrap() = "new".into();
    *provider.gate.lock().unwrap() = Some((entered_tx, release_rx));

    let reload_engine = engine.clone();
    let reload = thread::spawn(move || reload_engine.reload());
    entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();

    let calls = Arc::new(AtomicUsize::new(0));
    let callback_calls = calls.clone();
    let subscribe_engine = engine.clone();
    let (subscribed_tx, subscribed_rx) = std::sync::mpsc::sync_channel(1);
    let subscribe = thread::spawn(move || {
        let (_registration, current) = subscribe_engine.subscribe_snapshot_commits(move |_| {
            callback_calls.fetch_add(1, Ordering::SeqCst);
        });
        subscribed_tx
            .send((
                current.generation(),
                current.snapshot().get(PolicyKey::Tailnet),
            ))
            .unwrap();
    });
    assert!(matches!(
        subscribed_rx.recv_timeout(Duration::from_millis(50)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
    ));

    release_tx.send(()).unwrap();
    reload.join().unwrap().unwrap();
    let (generation, tailnet) = subscribed_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    subscribe.join().unwrap();
    assert!(generation > old_generation);
    assert_eq!(tailnet, Ok(PolicyValue::String("new".into())));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn snapshot_commit_callbacks_are_reentrant_and_late_subscription_sees_current() {
    struct ManualProvider(Mutex<String>);

    impl PolicyProvider for ManualProvider {
        fn load(&self, definitions: &[SettingDefinition]) -> Result<ProviderValues, PolicyError> {
            let value = self.0.lock().unwrap().clone();
            Ok(definitions
                .iter()
                .filter(|definition| definition.key == PolicyKey::Tailnet)
                .map(|definition| (definition.key, Ok(RawValue::String(value.clone()))))
                .collect())
        }
    }

    let provider = Arc::new(ManualProvider(Mutex::new("old".into())));
    let engine = PolicyEngine::well_known(PolicyScope::Device).unwrap();
    engine
        .add_provider("manual", PolicyScope::Device, provider.clone())
        .unwrap();
    let old_generation = engine.snapshot().generation();
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let release_rx = Mutex::new(release_rx);
    let reentrant_engine = engine.clone();
    let _blocker = engine.register_snapshot_commit_callback(move |_| {
        // Commit callbacks run after reload synchronization is released.
        reentrant_engine.reload().unwrap();
        entered_tx.send(()).unwrap();
        release_rx.lock().unwrap().recv().unwrap();
    });

    *provider.0.lock().unwrap() = "new".into();
    let reload_engine = engine.clone();
    let reload = thread::spawn(move || reload_engine.reload());
    entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();

    let late_calls = Arc::new(AtomicUsize::new(0));
    let callback_calls = late_calls.clone();
    let (_late_subscription, current) = engine.subscribe_snapshot_commits(move |_| {
        callback_calls.fetch_add(1, Ordering::SeqCst);
    });
    assert!(current.generation() > old_generation);
    assert_eq!(
        current.snapshot().get(PolicyKey::Tailnet),
        Ok(PolicyValue::String("new".into()))
    );
    assert_eq!(late_calls.load(Ordering::SeqCst), 0);

    release_tx.send(()).unwrap();
    reload.join().unwrap().unwrap();
    assert_eq!(late_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn callback_and_memory_subscription_drop_can_reenter_without_deadlock() {
    let engine = PolicyEngine::well_known(PolicyScope::Device).unwrap();
    let inner_registration = engine.register_change_callback(|_| {});
    let outer_registration = engine.register_change_callback(move |_| {
        let _keep_alive = &inner_registration;
    });
    // Removing the outer closure drops its captured inner registration. Both
    // removals target the same callback map and must happen without its mutex
    // being held across closure destruction.
    drop(outer_registration);

    let provider = MemoryProvider::new();
    let inner_subscription = provider
        .subscribe(Arc::new(|| {}))
        .unwrap()
        .expect("memory subscription");
    let outer_subscription = provider
        .subscribe(Arc::new(move || {
            let _keep_alive = &inner_subscription;
        }))
        .unwrap()
        .expect("memory subscription");
    drop(outer_subscription);
}

#[test]
fn scoped_test_override_restores_previous_snapshot() {
    let engine = PolicyEngine::well_known(PolicyScope::Device).unwrap();
    engine
        .add_provider(
            "base",
            PolicyScope::Device,
            memory([(PolicyKey::Tailnet, RawValue::String("base".into()))]),
        )
        .unwrap();
    {
        let _override = engine
            .override_for_test(BTreeMap::from([(
                PolicyKey::Tailnet,
                RawValue::String("override".into()),
            )]))
            .unwrap();
        assert_eq!(
            engine.get_string(PolicyKey::Tailnet, ""),
            Ok("override".into())
        );
    }
    assert_eq!(engine.get_string(PolicyKey::Tailnet, ""), Ok("base".into()));
}

#[cfg(target_os = "macos")]
#[test]
fn macos_effective_posture_preference_is_not_managed_policy() {
    assert_eq!(
        super::NATIVE_POSTURE_PRECEDENCE,
        ProviderPrecedence::Platform
    );
}

#[cfg(target_os = "windows")]
#[test]
fn windows_machine_posture_policy_is_managed() {
    assert_eq!(
        super::NATIVE_POSTURE_PRECEDENCE,
        ProviderPrecedence::Managed
    );
}

#[test]
fn watcher_intervals_are_bounded() {
    assert!(WatchOptions::new(Duration::ZERO, Duration::ZERO).is_err());
    assert!(
        WatchOptions::new(MAX_WATCH_INTERVAL + Duration::from_nanos(1), Duration::ZERO).is_err()
    );
    assert!(WatchOptions::new(
        MIN_WATCH_INTERVAL,
        MAX_WATCH_DEBOUNCE + Duration::from_nanos(1)
    )
    .is_err());
    assert!(WatchOptions::new(MIN_WATCH_INTERVAL, MAX_WATCH_DEBOUNCE).is_ok());
}

fn wait_for_watch(clock: &FakeWatchClock, previous_waits: usize) {
    wait_until(|| clock.waits_started() > previous_waits && clock.active_waiters() == 1);
}

fn advance_watch(clock: &FakeWatchClock) {
    let previous_waits = clock.waits_started();
    clock.tick(1);
    wait_for_watch(clock, previous_waits);
}

#[test]
fn watched_json_coalesces_atomic_replacement_deletion_and_recreation() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("policy.json");
    fs::write(&path, r#"{"Tailnet":"old"}"#).unwrap();
    let clock = Arc::new(FakeWatchClock::default());
    let provider = Arc::new(
        JsonFileProvider::optional(&path)
            .with_file_trust(test_file_trust())
            .with_watch_options(
                WatchOptions::new(Duration::from_millis(20), Duration::from_millis(10)).unwrap(),
            )
            .with_watch_clock(clock.clone()),
    );
    let engine = PolicyEngine::well_known(PolicyScope::Device).unwrap();
    let id = engine
        .add_provider("file", PolicyScope::Device, provider.clone())
        .unwrap();
    wait_until(|| clock.active_waiters() == 1);

    let changes = Arc::new(Mutex::new(Vec::new()));
    let callback_changes = changes.clone();
    let registration = engine.register_change_callback(move |change| {
        callback_changes.lock().unwrap().push(change);
    });

    // Replacement and two more writes all land in one fake debounce window.
    let replacement = directory.path().join("replacement.json");
    fs::write(&replacement, r#"{"Tailnet":"replacement"}"#).unwrap();
    fs::rename(&replacement, &path).unwrap();
    advance_watch(&clock); // polling observation; now waiting to debounce
    fs::write(&path, r#"{"Tailnet":"burst-a"}"#).unwrap();
    fs::write(&path, r#"{"Tailnet":"burst-final"}"#).unwrap();
    advance_watch(&clock); // debounce expires and emits exactly one notification
    wait_until(|| engine.get_string(PolicyKey::Tailnet, "").unwrap() == "burst-final");
    assert_eq!(changes.lock().unwrap().len(), 1);

    fs::remove_file(&path).unwrap();
    advance_watch(&clock);
    advance_watch(&clock);
    wait_until(|| engine.snapshot().item(PolicyKey::Tailnet).is_none());
    assert_eq!(changes.lock().unwrap().len(), 2);

    fs::write(&path, r#"{"Tailnet":"recreated"}"#).unwrap();
    advance_watch(&clock);
    advance_watch(&clock);
    wait_until(|| engine.get_string(PolicyKey::Tailnet, "").unwrap() == "recreated");
    assert_eq!(changes.lock().unwrap().len(), 3);

    engine.remove_provider(id).unwrap();
    assert_eq!(clock.active_waiters(), 0, "watch worker was not joined");
    drop(registration);

    // The same opt-in provider can own a fresh watcher after shutdown.
    let restarted = engine
        .add_provider("file-restarted", PolicyScope::Device, provider)
        .unwrap();
    wait_until(|| clock.active_waiters() == 1);
    fs::write(&path, r#"{"Tailnet":"after-restart"}"#).unwrap();
    advance_watch(&clock);
    advance_watch(&clock);
    wait_until(|| engine.get_string(PolicyKey::Tailnet, "").unwrap() == "after-restart");
    engine.remove_provider(restarted).unwrap();
    assert_eq!(clock.active_waiters(), 0);
}

#[test]
fn watched_json_retries_pending_error_with_bounded_backoff_until_recovery() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("policy.json");
    fs::write(&path, r#"{"Tailnet":"safe"}"#).unwrap();
    let clock = Arc::new(FakeWatchClock::default());
    let provider = Arc::new(
        JsonFileProvider::new(&path)
            .with_file_trust(test_file_trust())
            .with_max_size(64)
            .with_watch_options(
                WatchOptions::new(Duration::from_millis(20), Duration::from_millis(10)).unwrap(),
            )
            .with_watch_clock(clock.clone()),
    );
    let engine = PolicyEngine::well_known(PolicyScope::Device).unwrap();
    let id = engine
        .add_provider("file", PolicyScope::Device, provider)
        .unwrap();
    wait_until(|| clock.active_waiters() == 1);

    fs::write(&path, vec![b'x'; 65]).unwrap();
    advance_watch(&clock);
    advance_watch(&clock);
    wait_until(|| {
        engine
            .last_reload_error()
            .is_some_and(|error| error.kind == PolicyErrorKind::TooLarge)
    });
    assert_eq!(engine.get_string(PolicyKey::Tailnet, ""), Ok("safe".into()));
    let generation = engine.snapshot().generation();
    let attempts = engine.reload_attempt_count();

    // The failed observation remains pending, but exponential backoff bounds
    // retries and failed attempts never publish a stale generation.
    thread::sleep(Duration::from_millis(80));
    let retried_attempts = engine.reload_attempt_count();
    assert!(retried_attempts > attempts);
    assert!(retried_attempts <= attempts + 5);
    assert_eq!(engine.snapshot().generation(), generation);

    // Recovery succeeds from the pending retry without requiring another
    // watcher event.
    fs::write(&path, r#"{"Tailnet":"recovered"}"#).unwrap();
    wait_until(|| engine.get_string(PolicyKey::Tailnet, "").unwrap() == "recovered");
    assert!(engine.snapshot().generation() > generation);
    assert!(engine.last_reload_error().is_none());
    engine.remove_provider(id).unwrap();
}

#[test]
fn watcher_reentrant_self_cancellation_is_bounded_and_reaped() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("policy.json");
    fs::write(&path, r#"{"Tailnet":"old"}"#).unwrap();
    let clock = Arc::new(FakeWatchClock::default());
    let provider = JsonFileProvider::new(&path)
        .with_file_trust(test_file_trust())
        .with_watch_options(
            WatchOptions::new(Duration::from_millis(20), Duration::from_millis(10)).unwrap(),
        )
        .with_watch_clock(clock.clone());
    let holder: Arc<Mutex<Option<Box<dyn ProviderSubscription>>>> = Arc::new(Mutex::new(None));
    let callback_holder = holder.clone();
    let subscription = provider
        .subscribe(Arc::new(move || {
            callback_holder.lock().unwrap().take();
        }))
        .unwrap()
        .unwrap();
    *holder.lock().unwrap() = Some(subscription);
    wait_until(|| clock.active_waiters() == 1);

    fs::write(&path, r#"{"Tailnet":"new"}"#).unwrap();
    advance_watch(&clock);
    clock.tick(1);
    wait_until(|| holder.lock().unwrap().is_none() && clock.active_waiters() == 0);
}

#[test]
fn watched_callback_can_mutate_callbacks_and_remove_provider() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("policy.json");
    fs::write(&path, r#"{"Tailnet":"old"}"#).unwrap();
    let clock = Arc::new(FakeWatchClock::default());
    let provider = Arc::new(
        JsonFileProvider::new(&path)
            .with_file_trust(test_file_trust())
            .with_watch_options(
                WatchOptions::new(Duration::from_millis(20), Duration::from_millis(10)).unwrap(),
            )
            .with_watch_clock(clock.clone()),
    );
    let engine = PolicyEngine::well_known(PolicyScope::Device).unwrap();
    let id = engine
        .add_provider("file", PolicyScope::Device, provider)
        .unwrap();
    wait_until(|| clock.active_waiters() == 1);

    let victim_calls = Arc::new(AtomicUsize::new(0));
    let victim_calls_for_callback = victim_calls.clone();
    let victim = engine.register_change_callback(move |_| {
        victim_calls_for_callback.fetch_add(1, Ordering::SeqCst);
    });
    let victim = Arc::new(Mutex::new(Some(victim)));
    let provider_id = Arc::new(Mutex::new(Some(id)));
    let callback_engine = engine.clone();
    let callback_victim = victim.clone();
    let callback_provider_id = provider_id.clone();
    let mutation = engine.register_change_callback(move |_| {
        callback_victim.lock().unwrap().take();
        let id = callback_provider_id.lock().unwrap().take();
        if let Some(id) = id {
            callback_engine.remove_provider(id).unwrap();
        }
    });

    fs::write(&path, r#"{"Tailnet":"new"}"#).unwrap();
    advance_watch(&clock);
    clock.tick(1); // callback removes and joins the worker after this debounce tick
    wait_until(|| engine.snapshot().item(PolicyKey::Tailnet).is_none());
    assert_eq!(clock.active_waiters(), 0);
    assert_eq!(victim_calls.load(Ordering::SeqCst), 1);
    drop(mutation);
}
