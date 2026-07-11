use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

// ---------------------------------------------------------------------------
// Typed accessors with defaults
// ---------------------------------------------------------------------------

#[test]
fn get_bool_returns_default_when_absent() {
    let k = ControlKnobs::new();
    assert!(k.get_bool("missing", true));
    assert!(!k.get_bool("missing", false));
}

#[test]
fn get_bool_parses_true_values() {
    let k = ControlKnobs::new();
    let mut batch = HashMap::new();
    batch.insert("a".into(), "true".into());
    batch.insert("b".into(), "1".into());
    batch.insert("c".into(), "YES".into());
    batch.insert("d".into(), "On".into());
    batch.insert("e".into(), "false".into());
    batch.insert("f".into(), "0".into());
    batch.insert("g".into(), "no".into());
    batch.insert("h".into(), "off".into());
    batch.insert("bad".into(), "maybe".into());
    k.apply(batch);
    assert!(k.get_bool("a", false));
    assert!(k.get_bool("b", false));
    assert!(k.get_bool("c", false));
    assert!(k.get_bool("d", false));
    assert!(!k.get_bool("e", true));
    assert!(!k.get_bool("f", true));
    assert!(!k.get_bool("g", true));
    assert!(!k.get_bool("h", true));
    // Unparseable → default
    assert!(k.get_bool("bad", true));
    assert!(!k.get_bool("bad", false));
}

#[test]
fn get_float_returns_default_when_absent() {
    let k = ControlKnobs::new();
    assert!((k.get_float("missing", 2.71) - 2.71).abs() < f64::EPSILON);
}

#[test]
fn get_float_parses_values() {
    let k = ControlKnobs::new();
    let mut batch = HashMap::new();
    batch.insert("x".into(), "42.5".into());
    batch.insert("y".into(), "-1".into());
    batch.insert("z".into(), "notanumber".into());
    k.apply(batch);
    assert!((k.get_float("x", 0.0) - 42.5).abs() < f64::EPSILON);
    assert!((k.get_float("y", 0.0) - (-1.0)).abs() < f64::EPSILON);
    // Unparseable → default
    assert!((k.get_float("z", 9.9) - 9.9).abs() < f64::EPSILON);
}

#[test]
fn get_string_returns_default_when_absent() {
    let k = ControlKnobs::new();
    assert_eq!(k.get_string("missing", "fallback"), "fallback");
}

#[test]
fn get_string_returns_value_when_present() {
    let k = ControlKnobs::new();
    let mut batch = HashMap::new();
    batch.insert("name".into(), "shutdown.tailscale.com".into());
    k.apply(batch);
    assert_eq!(k.get_string("name", ""), "shutdown.tailscale.com");
}

// ---------------------------------------------------------------------------
// has()
// ---------------------------------------------------------------------------

#[test]
fn has_reports_presence() {
    let k = ControlKnobs::new();
    assert!(!k.has("foo"));
    let mut batch = HashMap::new();
    batch.insert("foo".into(), "bar".into());
    k.apply(batch);
    assert!(k.has("foo"));
    assert!(!k.has("baz"));
}

// ---------------------------------------------------------------------------
// all()
// ---------------------------------------------------------------------------

#[test]
fn all_returns_snapshot() {
    let k = ControlKnobs::new();
    let mut batch = HashMap::new();
    batch.insert("a".into(), "1".into());
    batch.insert("b".into(), "2".into());
    k.apply(batch);
    let snapshot = k.all();
    assert_eq!(snapshot.len(), 2);
    assert_eq!(snapshot.get("a"), Some(&"1".to_string()));
    assert_eq!(snapshot.get("b"), Some(&"2".to_string()));
}

// ---------------------------------------------------------------------------
// apply() overwriting
// ---------------------------------------------------------------------------

#[test]
fn apply_overwrites_existing_values() {
    let k = ControlKnobs::new();
    let mut b1 = HashMap::new();
    b1.insert("k".into(), "old".into());
    k.apply(b1);
    assert_eq!(k.get_string("k", ""), "old");

    let mut b2 = HashMap::new();
    b2.insert("k".into(), "new".into());
    k.apply(b2);
    assert_eq!(k.get_string("k", ""), "new");
}

#[test]
fn apply_merges_without_removing_absent_keys() {
    let k = ControlKnobs::new();
    let mut b1 = HashMap::new();
    b1.insert("a".into(), "1".into());
    b1.insert("b".into(), "2".into());
    k.apply(b1);

    let mut b2 = HashMap::new();
    b2.insert("a".into(), "10".into());
    k.apply(b2);

    // "a" updated, "b" untouched.
    assert_eq!(k.get_string("a", ""), "10");
    assert_eq!(k.get_string("b", ""), "2");
    assert_eq!(k.all().len(), 2);
}

#[test]
fn apply_does_not_fire_callback_when_value_unchanged() {
    let k = ControlKnobs::new();
    let count = Arc::new(AtomicUsize::new(0));
    let count_clone = count.clone();
    k.on_change(
        "stable",
        Box::new(move |_| {
            count_clone.fetch_add(1, Ordering::SeqCst);
        }),
    );

    let mut b1 = HashMap::new();
    b1.insert("stable".into(), "v1".into());
    k.apply(b1);
    assert_eq!(count.load(Ordering::SeqCst), 1);

    // Same value — callback should NOT fire.
    let mut b2 = HashMap::new();
    b2.insert("stable".into(), "v1".into());
    k.apply(b2);
    assert_eq!(count.load(Ordering::SeqCst), 1);

    // Different value — callback fires.
    let mut b3 = HashMap::new();
    b3.insert("stable".into(), "v2".into());
    k.apply(b3);
    assert_eq!(count.load(Ordering::SeqCst), 2);
}

// ---------------------------------------------------------------------------
// on_change callbacks
// ---------------------------------------------------------------------------

#[test]
fn on_change_fires_with_new_value() {
    let k = ControlKnobs::new();
    let captured = Arc::new(Mutex::new(None::<String>));
    let cap_clone = captured.clone();
    k.on_change(
        "debug.derp",
        Box::new(move |new_val| {
            *cap_clone.lock().unwrap() = new_val.map(str::to_string);
        }),
    );

    let mut batch = HashMap::new();
    batch.insert("debug.derp".into(), "true".into());
    k.apply(batch);
    assert_eq!(*captured.lock().unwrap(), Some("true".to_string()));
}

#[test]
fn on_change_multiple_callbacks_same_key() {
    let k = ControlKnobs::new();
    let count = Arc::new(AtomicUsize::new(0));

    for _ in 0..3 {
        let c = count.clone();
        k.on_change(
            "x",
            Box::new(move |_| {
                c.fetch_add(1, Ordering::SeqCst);
            }),
        );
    }

    let mut batch = HashMap::new();
    batch.insert("x".into(), "1".into());
    k.apply(batch);
    assert_eq!(count.load(Ordering::SeqCst), 3);
}

#[test]
fn on_change_does_not_fire_for_unrelated_keys() {
    let k = ControlKnobs::new();
    let count = Arc::new(AtomicUsize::new(0));
    let c = count.clone();
    k.on_change(
        "target",
        Box::new(move |_| {
            c.fetch_add(1, Ordering::SeqCst);
        }),
    );

    let mut batch = HashMap::new();
    batch.insert("other".into(), "1".into());
    k.apply(batch);
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

// ---------------------------------------------------------------------------
// Thread-safety: concurrent readers
// ---------------------------------------------------------------------------

#[test]
fn concurrent_readers() {
    let k = Arc::new(ControlKnobs::new());
    let mut batch = HashMap::new();
    for i in 0..100 {
        batch.insert(format!("k{i}"), format!("v{i}"));
    }
    k.apply(batch);

    let mut handles = Vec::new();
    for _ in 0..8 {
        let k2 = k.clone();
        handles.push(thread::spawn(move || {
            for i in 0..100 {
                let name = format!("k{i}");
                assert_eq!(k2.get_string(&name, "x"), format!("v{i}"));
                assert!(k2.has(&name));
                let _ = k2.get_bool(&name, false);
                let _ = k2.get_float(&name, 0.0);
                let _ = k2.all();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn concurrent_writer_and_readers() {
    let k = Arc::new(ControlKnobs::new());
    let mut handles = Vec::new();

    // Writer thread: apply batches in a loop.
    {
        let k2 = k.clone();
        handles.push(thread::spawn(move || {
            for i in 0..50 {
                let mut batch = HashMap::new();
                batch.insert("counter".into(), format!("{i}"));
                k2.apply(batch);
            }
        }));
    }

    // Reader threads: read concurrently.
    for _ in 0..4 {
        let k2 = k.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..1000 {
                let _ = k2.get_string("counter", "0");
                let _ = k2.has("counter");
                let _ = k2.all();
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }
    // Final state should be the last written value.
    assert_eq!(k.get_string("counter", "0"), "49");
}

// ---------------------------------------------------------------------------
// Clone shares state
// ---------------------------------------------------------------------------

#[test]
fn clone_shares_state() {
    let k1 = ControlKnobs::new();
    let k2 = k1.clone();

    let mut batch = HashMap::new();
    batch.insert("shared".into(), "yes".into());
    k1.apply(batch);

    // k2 sees the change because the inner Arc is shared.
    assert_eq!(k2.get_string("shared", ""), "yes");
    assert!(k2.has("shared"));
}

// ---------------------------------------------------------------------------
// Default
// ---------------------------------------------------------------------------

#[test]
fn default_is_empty() {
    let k = ControlKnobs::default();
    assert!(k.all().is_empty());
    assert!(!k.has("anything"));
}
