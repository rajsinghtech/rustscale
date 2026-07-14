use std::{fs, str::FromStr};

use tempfile::NamedTempFile;

use crate::{
    macos::{parse_defaults_bool, parse_defaults_string_list},
    JsonFileStore, PolicyErrorKind, PolicyKey, PolicyStore, PolicyStoreSet, StubPolicyStore,
};

fn store(json: &str) -> JsonFileStore {
    JsonFileStore::from_json(json).expect("valid policy JSON")
}

fn error_kind<T: std::fmt::Debug>(result: Result<T, crate::PolicyError>) -> PolicyErrorKind {
    result.expect_err("expected an error").kind
}

#[test]
fn test_json_string() {
    assert_eq!(
        store(r#"{"Tailnet":"my.ts.net"}"#).get_string(PolicyKey::Tailnet),
        Ok("my.ts.net".to_owned())
    );
}

#[test]
fn test_json_bool() {
    assert_eq!(
        store(r#"{"LogSCMInteractions":true}"#).get_bool(PolicyKey::LogSCMInteractions),
        Ok(true)
    );
}

#[test]
fn test_json_string_list() {
    assert_eq!(
        store(r#"{"AllowedSuggestedExitNodes":["a","b"]}"#)
            .get_string_list(PolicyKey::AllowedSuggestedExitNodes),
        Ok(vec!["a".to_owned(), "b".to_owned()])
    );
}

#[test]
fn test_json_missing() {
    assert_eq!(
        error_kind(store("{}").get_string(PolicyKey::Tailnet)),
        PolicyErrorKind::NotConfigured
    );
}

#[test]
fn test_json_type_mismatch() {
    assert_eq!(
        error_kind(store(r#"{"ExitNodeID":true}"#).get_string(PolicyKey::ExitNodeID)),
        PolicyErrorKind::TypeMismatch
    );
}

#[test]
fn test_json_list_mismatch() {
    assert_eq!(
        error_kind(
            store(r#"{"AllowedSuggestedExitNodes":"not-a-list"}"#)
                .get_string_list(PolicyKey::AllowedSuggestedExitNodes)
        ),
        PolicyErrorKind::TypeMismatch
    );
}

#[test]
fn test_json_file_not_found() {
    assert_eq!(
        error_kind(JsonFileStore::new("/nonexistent/rustscale-policy.json")),
        PolicyErrorKind::Io
    );
}

#[test]
fn test_json_malformed() {
    let file = NamedTempFile::new().expect("temp file");
    fs::write(file.path(), "{invalid").expect("write malformed JSON");
    assert_eq!(
        error_kind(JsonFileStore::new(file.path())),
        PolicyErrorKind::Parse
    );
}

#[test]
fn test_wire_name_roundtrip() {
    for key in PolicyKey::ALL {
        assert_eq!(PolicyKey::from_str(key.wire_name()), Ok(key));
    }
}

#[test]
fn test_wire_name_values() {
    assert_eq!(PolicyKey::ControlURL.wire_name(), "LoginURL");
    assert_eq!(
        PolicyKey::EnableIncomingConnections.wire_name(),
        "AllowIncomingConnections"
    );
    assert_eq!(PolicyKey::AutoUpdateVisibility.wire_name(), "ApplyUpdates");
}

#[test]
fn test_from_str_unknown() {
    assert!("NonexistentKey".parse::<PolicyKey>().is_err());
}

#[test]
fn test_set_first_wins() {
    let stores: Vec<Box<dyn PolicyStore>> = vec![
        Box::new(store(r#"{"Tailnet":"first.ts.net"}"#)),
        Box::new(store(r#"{"Tailnet":"second.ts.net"}"#)),
    ];
    assert_eq!(
        PolicyStoreSet::new(stores).get_string(PolicyKey::Tailnet),
        Ok("first.ts.net".to_owned())
    );
}

#[test]
fn test_set_fallthrough() {
    let stores: Vec<Box<dyn PolicyStore>> = vec![
        Box::new(store("{}")),
        Box::new(store(r#"{"Tailnet":"next.ts.net"}"#)),
    ];
    assert_eq!(
        PolicyStoreSet::new(stores).get_string(PolicyKey::Tailnet),
        Ok("next.ts.net".to_owned())
    );
}

#[test]
fn test_set_all_missing() {
    let stores: Vec<Box<dyn PolicyStore>> = vec![Box::new(store("{}")), Box::new(store("{}"))];
    assert_eq!(
        error_kind(PolicyStoreSet::new(stores).get_string(PolicyKey::Tailnet)),
        PolicyErrorKind::NotConfigured
    );
}

#[test]
fn test_stub_always_not_configured() {
    let store = StubPolicyStore::new();
    assert_eq!(
        error_kind(store.get_string(PolicyKey::Tailnet)),
        PolicyErrorKind::NotConfigured
    );
    assert_eq!(
        error_kind(store.get_bool(PolicyKey::AlwaysOn)),
        PolicyErrorKind::NotConfigured
    );
    assert_eq!(
        error_kind(store.get_string_list(PolicyKey::AllowedSuggestedExitNodes)),
        PolicyErrorKind::NotConfigured
    );
}

#[test]
fn test_defaults_bool_parse() {
    assert_eq!(parse_defaults_bool("yes"), Some(true));
    assert_eq!(parse_defaults_bool("0"), Some(false));
    assert_eq!(parse_defaults_bool("maybe"), None);
}

#[test]
fn test_defaults_string_list_split() {
    assert_eq!(
        parse_defaults_string_list("(\n    \"node1\",\n    \"node2\"\n)"),
        vec!["node1", "node2"]
    );
}
