//! Port of `dnsname_test.go`.

use crate::*;

// ---------------------------------------------------------------------------
// TestFQDN
// ---------------------------------------------------------------------------

#[test]
fn test_fqdn() {
    struct Case {
        input: String,
        want: &'static str,
        want_err: bool,
        want_labels: usize,
    }

    let long_label = "a".repeat(100) + ".com";
    let many_labels = "aaaaa.".repeat(60) + "com";

    let cases: Vec<Case> = vec![
        Case {
            input: String::new(),
            want: ".",
            want_err: false,
            want_labels: 0,
        },
        Case {
            input: String::from("."),
            want: ".",
            want_err: false,
            want_labels: 0,
        },
        Case {
            input: String::from("foo.com"),
            want: "foo.com.",
            want_err: false,
            want_labels: 2,
        },
        Case {
            input: String::from("foo.com."),
            want: "foo.com.",
            want_err: false,
            want_labels: 2,
        },
        Case {
            input: String::from(".foo.com."),
            want: "foo.com.",
            want_err: false,
            want_labels: 2,
        },
        Case {
            input: String::from(".foo.com"),
            want: "foo.com.",
            want_err: false,
            want_labels: 2,
        },
        Case {
            input: String::from("com"),
            want: "com.",
            want_err: false,
            want_labels: 1,
        },
        Case {
            input: String::from("www.tailscale.com"),
            want: "www.tailscale.com.",
            want_err: false,
            want_labels: 3,
        },
        Case {
            input: String::from("_ssh._tcp.tailscale.com"),
            want: "_ssh._tcp.tailscale.com.",
            want_err: false,
            want_labels: 4,
        },
        Case {
            input: long_label,
            want: "",
            want_err: true,
            want_labels: 0,
        },
        Case {
            input: many_labels,
            want: "",
            want_err: true,
            want_labels: 0,
        },
        Case {
            input: String::from("foo..com"),
            want: "",
            want_err: true,
            want_labels: 0,
        },
    ];

    for c in &cases {
        let got = to_fqdn(&c.input);
        if c.want_err {
            assert!(got.is_err(), "to_fqdn({:?}) should error", c.input);
            continue;
        }
        let got = got.unwrap_or_else(|e| panic!("to_fqdn({:?}): {e}", c.input));
        assert_eq!(
            got.with_trailing_dot(),
            c.want,
            "to_fqdn({:?}).with_trailing_dot()",
            c.input
        );
        let want_no_dot = &c.want[..c.want.len() - 1];
        assert_eq!(
            got.without_trailing_dot(),
            want_no_dot,
            "to_fqdn({:?}).without_trailing_dot()",
            c.input
        );
        assert_eq!(
            got.num_labels(),
            c.want_labels,
            "to_fqdn({:?}).num_labels()",
            c.input
        );
    }
}

// ---------------------------------------------------------------------------
// TestFQDNTooLong
// ---------------------------------------------------------------------------

#[test]
fn test_fqdn_too_long() {
    // 254-char name (including trailing dot) is the maximum.
    let name = "aaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaa.example.com.";
    assert_eq!(name.len(), 254, "name should be 254 chars");
    let got = to_fqdn(name).expect("254-char name should be valid");
    assert_eq!(got.with_trailing_dot(), name);

    // 255-char name is too long.
    let too_long = format!("x{name}");
    let got = to_fqdn(&too_long);
    assert!(got.is_err(), "255-char name should error");
    let err = got.unwrap_err().to_string();
    assert!(
        err.ends_with("is too long to be a DNS name"),
        "error should end with 'is too long to be a DNS name', got: {err}"
    );
}

// ---------------------------------------------------------------------------
// TestFQDNContains
// ---------------------------------------------------------------------------

#[test]
fn test_fqdn_contains() {
    let cases: &[(&str, &str, bool)] = &[
        ("", "", true),
        ("", "foo.com", true),
        ("foo.com", "", false),
        ("tailscale.com", "www.tailscale.com", true),
        ("www.tailscale.com", "tailscale.com", false),
        ("scale.com", "tailscale.com", false),
        ("foo.com", "foo.com", true),
    ];
    for &(a, b, want) in cases {
        let fa = to_fqdn(a).unwrap_or_else(|e| panic!("to_fqdn({a:?}): {e}"));
        let fb = to_fqdn(b).unwrap_or_else(|e| panic!("to_fqdn({b:?}): {e}"));
        assert_eq!(fa.contains(&fb), want, "{}.contains({})", a, b);
    }
}

// ---------------------------------------------------------------------------
// TestFQDNParent
// ---------------------------------------------------------------------------

#[test]
fn test_fqdn_parent() {
    let cases: &[(&str, &str)] = &[
        ("", ""),
        (".", ""),
        ("com.", ""),
        ("foo.com.", "com."),
        ("www.foo.com.", "foo.com."),
        ("a.b.c.d.", "b.c.d."),
        ("sub.node.tailnet.ts.net.", "node.tailnet.ts.net."),
    ];
    for &(input, want) in cases {
        let f = to_fqdn(input).unwrap_or_else(|e| panic!("to_fqdn({input:?}): {e}"));
        let got = f.parent();
        assert_eq!(got.with_trailing_dot(), want, "to_fqdn({input:?}).parent()");
    }
}

// ---------------------------------------------------------------------------
// TestSanitizeLabel
// ---------------------------------------------------------------------------

#[test]
fn test_sanitize_label() {
    let cases: &[(&str, &str, &str)] = &[
        ("empty", "", ""),
        ("space", " ", ""),
        ("upper", "OBERON", "oberon"),
        ("mixed", "Avery's iPhone 4(SE)", "averys-iphone-4se"),
        ("dotted", "mon.ipn.dev", "mon-ipn-dev"),
        ("email", "admin@example.com", "admin-example-com"),
        ("boundary", ".bound.ary.", "bound-ary"),
        ("bad_trailing", "a-", "a"),
        ("bad_leading", "-a", "a"),
        ("bad_both", "-a-", "a"),
        (
            "overlong",
            &"test.".repeat(20),
            "test-test-test-test-test-test-test-test-test-test-test-test-tes",
        ),
    ];
    for &(name, input, want) in cases {
        let got = sanitize_label(input);
        assert_eq!(got, want, "sanitize_label({input:?}) [{name}]");
    }
}

// ---------------------------------------------------------------------------
// TestTrimCommonSuffixes
// ---------------------------------------------------------------------------

#[test]
fn test_trim_common_suffixes() {
    let cases: &[(&str, &str)] = &[
        ("computer.local", "computer"),
        ("computer.localdomain", "computer"),
        ("computer.lan", "computer"),
        ("computer.mynetwork", "computer.mynetwork"),
    ];
    for &(hostname, want) in cases {
        let got = trim_common_suffixes(hostname);
        assert_eq!(got, want, "trim_common_suffixes({hostname:?})");
    }
}

// ---------------------------------------------------------------------------
// TestHasSuffix
// ---------------------------------------------------------------------------

#[test]
fn test_has_suffix() {
    let cases: &[(&str, &str, bool)] = &[
        ("foo.com", "com", true),
        ("foo.com.", "com", true),
        ("foo.com.", "com.", true),
        ("foo.com", ".com", true),
        ("", "", false),
        ("foo.com.", "", false),
        ("foo.com.", "o.com", false),
    ];
    for &(name, suffix, want) in cases {
        let got = has_suffix(name, suffix);
        assert_eq!(got, want, "has_suffix({name:?}, {suffix:?})");
    }
}

// ---------------------------------------------------------------------------
// TestTrimSuffix
// ---------------------------------------------------------------------------

#[test]
fn test_trim_suffix() {
    let cases: &[(&str, &str, &str)] = &[
        ("foo.magicdnssuffix.", "magicdnssuffix", "foo"),
        ("foo.magicdnssuffix", "magicdnssuffix", "foo"),
        ("foo.magicdnssuffix", ".magicdnssuffix", "foo"),
        ("foo.anothersuffix", "magicdnssuffix", "foo.anothersuffix"),
        ("foo.anothersuffix.", "magicdnssuffix", "foo.anothersuffix"),
        ("a.b.c.d", "c.d", "a.b"),
        ("name.", "foo", "name"),
    ];
    for &(name, suffix, want) in cases {
        let got = trim_suffix(name, suffix);
        assert_eq!(got, want, "trim_suffix({name:?}, {suffix:?})");
    }
}

// ---------------------------------------------------------------------------
// TestValidHostname
// ---------------------------------------------------------------------------

#[test]
fn test_valid_hostname() {
    let long_63 = "a".repeat(63);
    let long_64 = "a".repeat(64);
    let four_labels_63 = format!("{}.", "a".repeat(63)).repeat(4);

    struct Case {
        hostname: String,
        want_err: &'static str,
    }

    let cases: Vec<Case> = vec![
        Case {
            hostname: "example".into(),
            want_err: "",
        },
        Case {
            hostname: "example.com".into(),
            want_err: "",
        },
        Case {
            hostname: " example".into(),
            want_err: "must start with a letter or number",
        },
        Case {
            hostname: "example-.com".into(),
            want_err: "must end with a letter or number",
        },
        Case {
            hostname: long_63,
            want_err: "",
        },
        Case {
            hostname: long_64,
            want_err: "is too long, max length is 63 bytes",
        },
        Case {
            hostname: four_labels_63,
            want_err: "is too long to be a DNS name",
        },
        Case {
            hostname: "www.what\u{1F926}lol.example.com".into(),
            want_err: "contains invalid character",
        },
    ];

    for c in &cases {
        let err = valid_hostname(&c.hostname);
        let ok = err.is_ok();
        let want_ok = c.want_err.is_empty();
        assert!(
            ok == want_ok,
            "valid_hostname({:?}) ok={ok}, want ok={want_ok}",
            c.hostname
        );
        if !want_ok {
            let msg = err.unwrap_err().to_string();
            assert!(
                msg.contains(c.want_err),
                "valid_hostname({:?}) error {msg:?} should contain {:?}",
                c.hostname,
                c.want_err
            );
        }
    }
}

// ---------------------------------------------------------------------------
// TestValidLabel (extra — exercises valid_label directly)
// ---------------------------------------------------------------------------

#[test]
fn test_valid_label() {
    assert!(valid_label("example").is_ok());
    assert!(valid_label("a").is_ok());
    assert!(valid_label("1").is_ok());
    assert!(valid_label("a1-b2").is_ok());
    assert!(valid_label(&"a".repeat(63)).is_ok());

    assert!(valid_label("").is_err());
    assert!(valid_label(&"a".repeat(64)).is_err());
    assert!(valid_label("-bad").is_err());
    assert!(valid_label("bad-").is_err());
    assert!(valid_label("bad label").is_err());
    assert!(valid_label("bad.label").is_err());
    assert!(valid_label("_under").is_err());
}

// ---------------------------------------------------------------------------
// TestNumLabels (extra — exercises the free function)
// ---------------------------------------------------------------------------

#[test]
fn test_num_labels_fn() {
    assert_eq!(num_labels(""), 0);
    assert_eq!(num_labels("."), 0);
    assert_eq!(num_labels("com"), 0);
    assert_eq!(num_labels("foo.com"), 1);
    assert_eq!(num_labels("foo.com."), 2);
    assert_eq!(num_labels("a.b.c.d."), 4);
}

// ---------------------------------------------------------------------------
// TestFirstLabel (extra)
// ---------------------------------------------------------------------------

#[test]
fn test_first_label() {
    assert_eq!(first_label("foo.com"), "foo");
    assert_eq!(first_label("foo.com."), "foo");
    assert_eq!(first_label("foo"), "foo");
    assert_eq!(first_label(""), "");
}

// ---------------------------------------------------------------------------
// TestSanitizeHostname (extra)
// ---------------------------------------------------------------------------

#[test]
fn test_sanitize_hostname() {
    assert_eq!(sanitize_hostname("computer.local"), "computer");
    assert_eq!(sanitize_hostname("My Computer.localdomain"), "my-computer");
    assert_eq!(sanitize_hostname("A.B.C.lan"), "a-b-c");
}

// ---------------------------------------------------------------------------
// BenchmarkToFQDN equivalents — just smoke-test that repeated calls work.
// ---------------------------------------------------------------------------

#[test]
fn bench_to_fqdn_smoke() {
    let inputs = [
        "www.tailscale.com.",
        "www.tailscale.com",
        ".www.tailscale.com",
        "_ssh._tcp.www.tailscale.com.",
        "_ssh._tcp.www.tailscale.com",
    ];
    let mut sink = Fqdn::default();
    for _ in 0..100 {
        for inp in &inputs {
            sink = to_fqdn(inp).unwrap();
        }
    }
    // Prevent optimizer from eliminating sink.
    assert_eq!(sink.with_trailing_dot(), "_ssh._tcp.www.tailscale.com.");
}

// ---------------------------------------------------------------------------
// Extra: Fqdn equality / ordering / display
// ---------------------------------------------------------------------------

#[test]
fn fqdn_eq_and_display() {
    let a = to_fqdn("foo.com").unwrap();
    let b = to_fqdn("foo.com.").unwrap();
    assert_eq!(a, b);
    assert_eq!(a.to_string(), "foo.com.");
    assert_eq!(a.as_ref(), "foo.com.");
    let s: String = a.into();
    assert_eq!(s, "foo.com.");
}

#[test]
fn fqdn_root() {
    let root = to_fqdn("").unwrap();
    assert_eq!(root.with_trailing_dot(), ".");
    assert_eq!(root.without_trailing_dot(), "");
    assert_eq!(root.num_labels(), 0);
}

#[test]
fn fqdn_leading_dot_stripped() {
    let a = to_fqdn(".foo.com").unwrap();
    let b = to_fqdn("foo.com").unwrap();
    assert_eq!(a, b);
}

#[test]
fn fqdn_preserves_case() {
    let f = to_fqdn("Foo.COM").unwrap();
    assert_eq!(f.with_trailing_dot(), "Foo.COM.");
}
