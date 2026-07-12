#![forbid(unsafe_code)]
#![allow(clippy::option_option)]

use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex, OnceLock};

fn seen() -> &'static Mutex<HashMap<String, String>> {
    static MAP: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

macro_rules! reg_map {
    ($name:ident, $t:ty) => {
        fn $name() -> &'static Mutex<HashMap<String, Arc<Mutex<$t>>>> {
            static MAP: OnceLock<Mutex<HashMap<String, Arc<Mutex<$t>>>>> = OnceLock::new();
            MAP.get_or_init(|| Mutex::new(HashMap::new()))
        }
    };
}

reg_map!(reg_str, Option<String>);
reg_map!(reg_bool, Option<bool>);
reg_map!(reg_opt_bool, Option<Option<bool>>);
reg_map!(reg_int, Option<i64>);

fn note_env(key: &str, val: &str) {
    let mut map = seen().lock().unwrap();
    if val.is_empty() {
        map.remove(key);
    } else {
        map.insert(key.to_string(), val.to_string());
    }
}

fn parse_bool(val: &str) -> Option<bool> {
    match val {
        "1" | "t" | "T" | "true" | "True" | "TRUE" => Some(true),
        "0" | "f" | "F" | "false" | "False" | "FALSE" => Some(false),
        _ => None,
    }
}

fn parse_opt_bool(val: &str) -> Option<Option<bool>> {
    if val.is_empty() {
        return Some(None);
    }
    parse_bool(val).map(Some)
}

fn parse_int(val: &str) -> Option<i64> {
    let val = val.trim();
    if val.is_empty() {
        return None;
    }
    if let Some(hex) = val.strip_prefix("0x").or_else(|| val.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).ok()
    } else if let Some(oct) = val.strip_prefix("0o").or_else(|| val.strip_prefix("0O")) {
        i64::from_str_radix(oct, 8).ok()
    } else if let Some(bin) = val.strip_prefix("0b").or_else(|| val.strip_prefix("0B")) {
        i64::from_str_radix(bin, 2).ok()
    } else {
        val.parse().ok()
    }
}

pub fn register_string(key: &str) -> impl Fn() -> Option<String> {
    let mut map = reg_str().lock().unwrap();
    let entry = map
        .entry(key.to_string())
        .or_insert_with(|| {
            let v = env::var(key).ok().filter(|s| !s.is_empty());
            if let Some(ref v) = v {
                note_env(key, v);
            }
            Arc::new(Mutex::new(v))
        })
        .clone();
    move || entry.lock().unwrap().clone()
}

pub fn register_bool(key: &str) -> impl Fn() -> Option<bool> {
    let mut map = reg_bool().lock().unwrap();
    let entry = map
        .entry(key.to_string())
        .or_insert_with(|| {
            let v = env::var(key).ok();
            let parsed = v.as_deref().and_then(parse_bool);
            if let Some(ref v) = v {
                if !v.is_empty() {
                    note_env(key, v);
                }
            }
            Arc::new(Mutex::new(parsed))
        })
        .clone();
    move || *entry.lock().unwrap()
}

pub fn register_opt_bool(key: &str) -> impl Fn() -> Option<Option<bool>> {
    let mut map = reg_opt_bool().lock().unwrap();
    let entry = map
        .entry(key.to_string())
        .or_insert_with(|| {
            let v = env::var(key).ok();
            let parsed = v.as_deref().and_then(parse_opt_bool);
            if let Some(ref v) = v {
                note_env(key, v);
            }
            Arc::new(Mutex::new(parsed))
        })
        .clone();
    move || *entry.lock().unwrap()
}

pub fn register_int(key: &str) -> impl Fn() -> Option<i64> {
    let mut map = reg_int().lock().unwrap();
    let entry = map
        .entry(key.to_string())
        .or_insert_with(|| {
            let v = env::var(key).ok();
            let parsed = v.as_deref().and_then(parse_int);
            if let Some(ref v) = v {
                note_env(key, v);
            }
            Arc::new(Mutex::new(parsed))
        })
        .clone();
    move || *entry.lock().unwrap()
}

pub fn string(key: &str) -> Option<String> {
    let v = env::var(key).ok().filter(|s| !s.is_empty());
    if let Some(ref v) = v {
        note_env(key, v);
    }
    v
}

pub fn bool(key: &str) -> Option<bool> {
    let v = env::var(key).ok();
    let parsed = v.as_deref().and_then(parse_bool);
    if let Some(ref v) = v {
        if !v.is_empty() {
            note_env(key, v);
        }
    }
    parsed
}

pub fn opt_bool(key: &str) -> Option<Option<bool>> {
    let v = env::var(key).ok();
    let parsed = v.as_deref().and_then(parse_opt_bool);
    if let Some(ref v) = v {
        note_env(key, v);
    }
    parsed
}

pub fn lookup_int(key: &str) -> Option<i64> {
    let v = env::var(key).ok();
    let parsed = v.as_deref().and_then(parse_int);
    if let Some(ref v) = v {
        note_env(key, v);
    }
    parsed
}

pub fn setenv(key: &str, val: &str) {
    env::set_var(key, val);
    note_env(key, val);

    if let Some(entry) = reg_str().lock().unwrap().get(key) {
        *entry.lock().unwrap() = Some(val.to_string());
    }
    if let Some(entry) = reg_bool().lock().unwrap().get(key) {
        *entry.lock().unwrap() = parse_bool(val);
    }
    if let Some(entry) = reg_opt_bool().lock().unwrap().get(key) {
        *entry.lock().unwrap() = parse_opt_bool(val);
    }
    if let Some(entry) = reg_int().lock().unwrap().get(key) {
        *entry.lock().unwrap() = parse_int(val);
    }
}

pub fn log_current(logf: impl Fn(&str)) {
    let map = seen().lock().unwrap();
    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort();
    for k in keys {
        logf(&format!("envknob: {}={:?}", k, map[k]));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn cleanup(key: &str) {
        env::remove_var(key);
    }

    #[test]
    fn test_string_not_set() {
        assert_eq!(string("ENVKNOB_TEST_STRING_UNSET"), None);
    }

    #[test]
    fn test_string_set() {
        env::set_var("ENVKNOB_TEST_STRING", "hello");
        assert_eq!(string("ENVKNOB_TEST_STRING"), Some("hello".to_string()));
        cleanup("ENVKNOB_TEST_STRING");
    }

    #[test]
    fn test_string_empty() {
        env::set_var("ENVKNOB_TEST_STRING_EMPTY", "");
        assert_eq!(string("ENVKNOB_TEST_STRING_EMPTY"), None);
        cleanup("ENVKNOB_TEST_STRING_EMPTY");
    }

    #[test]
    fn test_bool_true() {
        env::set_var("ENVKNOB_TEST_BOOL_TRUE", "true");
        assert_eq!(bool("ENVKNOB_TEST_BOOL_TRUE"), Some(true));
        cleanup("ENVKNOB_TEST_BOOL_TRUE");
    }

    #[test]
    fn test_bool_false() {
        env::set_var("ENVKNOB_TEST_BOOL_FALSE", "false");
        assert_eq!(bool("ENVKNOB_TEST_BOOL_FALSE"), Some(false));
        cleanup("ENVKNOB_TEST_BOOL_FALSE");
    }

    #[test]
    fn test_bool_invalid() {
        env::set_var("ENVKNOB_TEST_BOOL_INVALID", "garbage");
        assert_eq!(bool("ENVKNOB_TEST_BOOL_INVALID"), None);
        cleanup("ENVKNOB_TEST_BOOL_INVALID");
    }

    #[test]
    fn test_bool_unset() {
        assert_eq!(bool("ENVKNOB_TEST_BOOL_UNSET"), None);
    }

    #[test]
    fn test_bool_numeric_variants() {
        env::set_var("ENVKNOB_TEST_BOOL_1", "1");
        assert_eq!(bool("ENVKNOB_TEST_BOOL_1"), Some(true));
        env::set_var("ENVKNOB_TEST_BOOL_0", "0");
        assert_eq!(bool("ENVKNOB_TEST_BOOL_0"), Some(false));
        cleanup("ENVKNOB_TEST_BOOL_1");
        cleanup("ENVKNOB_TEST_BOOL_0");
    }

    #[test]
    fn test_opt_bool_unset() {
        assert_eq!(opt_bool("ENVKNOB_TEST_OPTBOOL_UNSET"), None);
    }

    #[test]
    fn test_opt_bool_empty() {
        env::set_var("ENVKNOB_TEST_OPTBOOL_EMPTY", "");
        assert_eq!(opt_bool("ENVKNOB_TEST_OPTBOOL_EMPTY"), Some(None));
        cleanup("ENVKNOB_TEST_OPTBOOL_EMPTY");
    }

    #[test]
    fn test_opt_bool_true() {
        env::set_var("ENVKNOB_TEST_OPTBOOL_TRUE", "true");
        assert_eq!(opt_bool("ENVKNOB_TEST_OPTBOOL_TRUE"), Some(Some(true)));
        cleanup("ENVKNOB_TEST_OPTBOOL_TRUE");
    }

    #[test]
    fn test_opt_bool_false() {
        env::set_var("ENVKNOB_TEST_OPTBOOL_FALSE", "false");
        assert_eq!(opt_bool("ENVKNOB_TEST_OPTBOOL_FALSE"), Some(Some(false)));
        cleanup("ENVKNOB_TEST_OPTBOOL_FALSE");
    }

    #[test]
    fn test_lookup_int_not_set() {
        assert_eq!(lookup_int("ENVKNOB_TEST_INT_UNSET"), None);
    }

    #[test]
    fn test_lookup_int_decimal() {
        env::set_var("ENVKNOB_TEST_INT_DEC", "42");
        assert_eq!(lookup_int("ENVKNOB_TEST_INT_DEC"), Some(42));
        cleanup("ENVKNOB_TEST_INT_DEC");
    }

    #[test]
    fn test_lookup_int_negative() {
        env::set_var("ENVKNOB_TEST_INT_NEG", "-7");
        assert_eq!(lookup_int("ENVKNOB_TEST_INT_NEG"), Some(-7));
        cleanup("ENVKNOB_TEST_INT_NEG");
    }

    #[test]
    fn test_lookup_int_hex() {
        env::set_var("ENVKNOB_TEST_INT_HEX", "0xff");
        assert_eq!(lookup_int("ENVKNOB_TEST_INT_HEX"), Some(255));
        cleanup("ENVKNOB_TEST_INT_HEX");
    }

    #[test]
    fn test_lookup_int_octal() {
        env::set_var("ENVKNOB_TEST_INT_OCT", "0o10");
        assert_eq!(lookup_int("ENVKNOB_TEST_INT_OCT"), Some(8));
        cleanup("ENVKNOB_TEST_INT_OCT");
    }

    #[test]
    fn test_lookup_int_binary() {
        env::set_var("ENVKNOB_TEST_INT_BIN", "0b1010");
        assert_eq!(lookup_int("ENVKNOB_TEST_INT_BIN"), Some(10));
        cleanup("ENVKNOB_TEST_INT_BIN");
    }

    #[test]
    fn test_lookup_int_invalid() {
        env::set_var("ENVKNOB_TEST_INT_INVALID", "notanumber");
        assert_eq!(lookup_int("ENVKNOB_TEST_INT_INVALID"), None);
        cleanup("ENVKNOB_TEST_INT_INVALID");
    }

    #[test]
    fn test_lookup_int_empty() {
        env::set_var("ENVKNOB_TEST_INT_EMPTY", "");
        assert_eq!(lookup_int("ENVKNOB_TEST_INT_EMPTY"), None);
        cleanup("ENVKNOB_TEST_INT_EMPTY");
    }

    #[test]
    fn test_register_string() {
        let getter = register_string("ENVKNOB_TEST_REG_STR");
        assert_eq!(getter(), None);
        setenv("ENVKNOB_TEST_REG_STR", "registered");
        assert_eq!(getter(), Some("registered".to_string()));
        cleanup("ENVKNOB_TEST_REG_STR");
    }

    #[test]
    fn test_register_bool() {
        let getter = register_bool("ENVKNOB_TEST_REG_BOOL");
        assert_eq!(getter(), None);
        setenv("ENVKNOB_TEST_REG_BOOL", "true");
        assert_eq!(getter(), Some(true));
        setenv("ENVKNOB_TEST_REG_BOOL", "false");
        assert_eq!(getter(), Some(false));
        cleanup("ENVKNOB_TEST_REG_BOOL");
    }

    #[test]
    fn test_register_opt_bool() {
        let getter = register_opt_bool("ENVKNOB_TEST_REG_OPTBOOL");
        assert_eq!(getter(), None);
        setenv("ENVKNOB_TEST_REG_OPTBOOL", "");
        assert_eq!(getter(), Some(None));
        setenv("ENVKNOB_TEST_REG_OPTBOOL", "true");
        assert_eq!(getter(), Some(Some(true)));
        cleanup("ENVKNOB_TEST_REG_OPTBOOL");
    }

    #[test]
    fn test_register_int() {
        let getter = register_int("ENVKNOB_TEST_REG_INT");
        assert_eq!(getter(), None);
        setenv("ENVKNOB_TEST_REG_INT", "99");
        assert_eq!(getter(), Some(99));
        setenv("ENVKNOB_TEST_REG_INT", "invalid");
        assert_eq!(getter(), None);
        setenv("ENVKNOB_TEST_REG_INT", "0x100");
        assert_eq!(getter(), Some(256));
        cleanup("ENVKNOB_TEST_REG_INT");
    }

    #[test]
    fn test_register_idempotent() {
        let getter1 = register_string("ENVKNOB_TEST_ONCE");
        setenv("ENVKNOB_TEST_ONCE", "first");
        let getter2 = register_string("ENVKNOB_TEST_ONCE");
        assert_eq!(getter1(), Some("first".to_string()));
        assert_eq!(getter2(), Some("first".to_string()));
        setenv("ENVKNOB_TEST_ONCE", "second");
        assert_eq!(getter1(), Some("second".to_string()));
        assert_eq!(getter2(), Some("second".to_string()));
        cleanup("ENVKNOB_TEST_ONCE");
    }

    #[test]
    fn test_setenv_updates_env() {
        setenv("ENVKNOB_TEST_SETENV", "setenv_value");
        assert_eq!(env::var("ENVKNOB_TEST_SETENV").unwrap(), "setenv_value");
        assert_eq!(
            string("ENVKNOB_TEST_SETENV"),
            Some("setenv_value".to_string())
        );
        cleanup("ENVKNOB_TEST_SETENV");
    }

    #[test]
    fn test_log_current() {
        setenv("ENVKNOB_TEST_LOG_A", "val_a");
        setenv("ENVKNOB_TEST_LOG_B", "val_b");

        let lines = RefCell::new(Vec::new());
        log_current(|s| lines.borrow_mut().push(s.to_string()));
        let lines = lines.into_inner();

        assert!(lines
            .iter()
            .any(|l| l.contains("ENVKNOB_TEST_LOG_A") && l.contains("val_a")));
        assert!(lines
            .iter()
            .any(|l| l.contains("ENVKNOB_TEST_LOG_B") && l.contains("val_b")));

        cleanup("ENVKNOB_TEST_LOG_A");
        cleanup("ENVKNOB_TEST_LOG_B");
    }

    #[test]
    fn test_parse_bool() {
        assert_eq!(parse_bool("true"), Some(true));
        assert_eq!(parse_bool("TRUE"), Some(true));
        assert_eq!(parse_bool("True"), Some(true));
        assert_eq!(parse_bool("1"), Some(true));
        assert_eq!(parse_bool("t"), Some(true));
        assert_eq!(parse_bool("T"), Some(true));
        assert_eq!(parse_bool("false"), Some(false));
        assert_eq!(parse_bool("FALSE"), Some(false));
        assert_eq!(parse_bool("False"), Some(false));
        assert_eq!(parse_bool("0"), Some(false));
        assert_eq!(parse_bool("f"), Some(false));
        assert_eq!(parse_bool("F"), Some(false));
        assert_eq!(parse_bool("garbage"), None);
        assert_eq!(parse_bool(""), None);
    }

    #[test]
    fn test_register_preexisting_env() {
        env::set_var("ENVKNOB_TEST_PREEXIST", "preexisting_value");
        let getter = register_string("ENVKNOB_TEST_PREEXIST");
        assert_eq!(getter(), Some("preexisting_value".to_string()));
        cleanup("ENVKNOB_TEST_PREEXIST");
    }
}
