use std::{
    collections::BTreeMap,
    fs,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Barrier, Mutex,
    },
    time::Duration,
};

use tempfile::NamedTempFile;

use crate::*;

fn memory(values: impl IntoIterator<Item = (PolicyKey, RawValue)>) -> Arc<MemoryProvider> {
    Arc::new(MemoryProvider::from_values(values.into_iter().collect()))
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
        engine
            .get_preference_option(PolicyKey::ApplyUpdates, PreferenceOption::Always)
            .unwrap_err()
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
    let changes = changes.lock().unwrap();
    assert_eq!(changes.len(), 1);
    assert!(changes[0].has_changed(PolicyKey::Tailnet));
    assert_eq!(engine.get_string(PolicyKey::Tailnet, ""), Ok("new".into()));
    drop(changes);
    drop(registration);

    provider.notify();
    assert_eq!(engine.get_string(PolicyKey::Tailnet, ""), Ok("new".into()));
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
