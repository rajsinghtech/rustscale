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

use tempfile::NamedTempFile;

use crate::*;

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
    let provider = JsonFileProvider::new(file.path());
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
        .with_max_size(8)
        .load(&[PolicyKey::Tailnet.definition()])
        .unwrap_err();
    assert_eq!(error.kind, PolicyErrorKind::TooLarge);
    assert_eq!(error.key, None);
}

#[test]
fn invalid_json_does_not_echo_contents_in_error() {
    let file = NamedTempFile::new().unwrap();
    fs::write(file.path(), r#"{"AuthKey":"tskey-secret-value""#).unwrap();
    let error = JsonFileProvider::new(file.path())
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
fn removal_recovers_from_other_provider_error_without_ghost_items() {
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
    engine
        .add_provider("flaky", PolicyScope::Device, flaky.clone())
        .unwrap();
    flaky.fail.store(true, Ordering::SeqCst);

    engine.remove_provider(base).unwrap();
    assert!(engine.snapshot().item(PolicyKey::Tailnet).is_none());
    assert!(engine.snapshot().item(PolicyKey::LogTarget).is_none());
    assert_eq!(
        engine.last_reload_error().unwrap().kind,
        PolicyErrorKind::Provider
    );
}

#[test]
fn override_drop_cannot_leak_when_remaining_provider_fails() {
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
    assert!(engine.snapshot().item(PolicyKey::Tailnet).is_none());
}

#[test]
fn notifications_are_nonblocking_coalesced_and_subscription_drop_is_reentrant_safe() {
    let engine = PolicyEngine::well_known(PolicyScope::Device).unwrap();
    let provider = Arc::new(StoredCallbackProvider::new());
    let id = engine
        .add_provider("notifying", PolicyScope::Device, provider.clone())
        .unwrap();
    assert_eq!(provider.loads.load(Ordering::SeqCst), 1);

    provider.notify_many(100);
    wait_until(|| engine.snapshot().generation() >= 2);
    thread::sleep(Duration::from_millis(80));
    assert!(
        provider.loads.load(Ordering::SeqCst) < 10,
        "notifications were not coalesced"
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
