//! G4: Persistence restart matrix — write known-good state, simulate a
//! process restart by dropping all in-memory state and re-loading from disk,
//! then assert every field roundtrips.
//!
//! See docs/regression-strategy.md G4.

#![allow(non_snake_case)]

use rustscale_ipn::{AppConnectorPrefs, LoginProfile, NetworkProfile, Prefs, UserProfile};
use tempfile::tempdir;

// ---------------------------------------------------------------------------
// Prefs persistence — prefs.json
// ---------------------------------------------------------------------------

/// Build a Prefs with every field set to a non-default value.
fn full_prefs() -> Prefs {
    Prefs {
        ControlURL: "https://control.example.com".into(),
        WantRunning: true,
        LoggedOut: false,
        RouteAll: true,
        ExitNodeID: "nodeABC123".into(),
        ExitNodeIP: "100.64.0.1".into(),
        CorpDNS: true,
        ShieldsUp: true,
        Hostname: "my-test-node".into(),
        AdvertiseRoutes: vec!["10.0.0.0/24".into(), "192.168.1.0/24".into()],
        AdvertiseTags: vec!["tag:server".into(), "tag:prod".into()],
        OperatorUser: "admin".into(),
        Ephemeral: true,
        AcceptRoutes: true,
        AdvertiseExitNode: true,
        ExitNodeAllowLANAccess: true,
        AutoUpdate: Some(true),
        NetfilterMode: Some("on".into()),
        NoSNAT: true,
        PostureChecking: true,
        AppConnector: AppConnectorPrefs { Advertise: true },
        RunWebClient: true,
    }
}

#[test]
fn prefs_all_fields_roundtrip_after_restart() {
    let dir = tempdir().unwrap();
    let original = full_prefs();

    // Write to disk (simulates a running process persisting state).
    original.save(dir.path()).unwrap();

    // Simulate restart: drop all in-memory state, re-load from disk.
    let reloaded = Prefs::load(dir.path()).unwrap();

    assert_eq!(original, reloaded, "prefs fields mismatch after restart");
}

#[test]
fn prefs_default_roundtrip_after_restart() {
    let dir = tempdir().unwrap();
    let original = Prefs::default();

    original.save(dir.path()).unwrap();
    let reloaded = Prefs::load(dir.path()).unwrap();

    assert_eq!(original, reloaded);
}

#[test]
fn prefs_empty_exit_node_fields_roundtrip() {
    let dir = tempdir().unwrap();
    let original = Prefs {
        WantRunning: true,
        ExitNodeID: String::new(),
        ExitNodeIP: String::new(),
        ..Default::default()
    };

    original.save(dir.path()).unwrap();
    let reloaded = Prefs::load(dir.path()).unwrap();

    assert_eq!(original, reloaded);
    assert_eq!(reloaded.ExitNodeID, "");
    assert_eq!(reloaded.ExitNodeIP, "");
}

#[test]
fn prefs_auto_update_none_roundtrip() {
    let dir = tempdir().unwrap();
    let original = Prefs {
        WantRunning: true,
        AutoUpdate: None,
        NetfilterMode: None,
        ..Default::default()
    };

    original.save(dir.path()).unwrap();
    let reloaded = Prefs::load(dir.path()).unwrap();

    assert_eq!(original, reloaded);
    assert_eq!(reloaded.AutoUpdate, None);
    assert_eq!(reloaded.NetfilterMode, None);
}

#[test]
fn prefs_auto_update_some_false_roundtrip() {
    let dir = tempdir().unwrap();
    let original = Prefs {
        WantRunning: true,
        AutoUpdate: Some(false),
        ..Default::default()
    };

    original.save(dir.path()).unwrap();
    let reloaded = Prefs::load(dir.path()).unwrap();

    assert_eq!(original, reloaded);
    assert_eq!(reloaded.AutoUpdate, Some(false));
}

#[test]
fn prefs_load_returns_default_when_no_file() {
    let dir = tempdir().unwrap();
    let loaded = Prefs::load(dir.path()).unwrap();
    assert_eq!(loaded, Prefs::default());
}

#[test]
fn prefs_overwrite_after_restart() {
    let dir = tempdir().unwrap();

    // Write first state.
    let first = full_prefs();
    first.save(dir.path()).unwrap();

    // Overwrite with different state (simulates prefs change then restart).
    let second = Prefs {
        ControlURL: "https://different.control".into(),
        WantRunning: false,
        ExitNodeID: "nodeXYZ".into(),
        AdvertiseRoutes: vec!["172.16.0.0/12".into()],
        ..Default::default()
    };
    second.save(dir.path()).unwrap();

    let reloaded = Prefs::load(dir.path()).unwrap();
    assert_eq!(second, reloaded);
    // Ensure stale data from first save is gone.
    assert_ne!(reloaded.ControlURL, first.ControlURL);
}

// ---------------------------------------------------------------------------
// Profiles persistence — profiles.json + current-profile
// ---------------------------------------------------------------------------

/// Build a LoginProfile with every field set to a non-default value.
fn full_profile(id: &str, name: &str) -> LoginProfile {
    LoginProfile {
        ID: id.into(),
        Name: name.into(),
        NetworkProfile: NetworkProfile {
            DomainName: "example.com.ts.net".into(),
            DisplayName: "Example Corp".into(),
        },
        Key: format!("profile-{id}"),
        UserProfile: UserProfile {
            ID: 42,
            LoginName: name.into(),
            DisplayName: "Display Name".into(),
            ProfilePicURL: "https://example.com/avatar.png".into(),
        },
        NodeID: format!("node-{id}"),
        ControlURL: "https://control.example.com".into(),
    }
}

#[test]
fn profiles_two_profiles_roundtrip_after_restart() {
    let dir = tempdir().unwrap();
    let profiles = vec![
        full_profile("p1", "user1@work.com"),
        full_profile("p2", "user2@home.com"),
    ];

    // Persist profiles + current-profile pointer.
    LoginProfile::save_all(dir.path(), &profiles).unwrap();
    LoginProfile::save_current_id(dir.path(), "p1").unwrap();

    // Simulate restart: drop all in-memory state, re-load from disk.
    let reloaded = LoginProfile::load_all(dir.path()).unwrap();
    let current = LoginProfile::load_current_id(dir.path()).unwrap();

    assert_eq!(reloaded.len(), 2, "should have 2 profiles after restart");
    assert_eq!(reloaded, profiles, "profiles mismatch after restart");
    assert_eq!(current.as_deref(), Some("p1"), "current-profile mismatch");
}

#[test]
fn profiles_all_fields_roundtrip() {
    let dir = tempdir().unwrap();
    let profile = full_profile("single", "user@example.com");

    LoginProfile::save_all(dir.path(), &[profile.clone()]).unwrap();
    let reloaded = LoginProfile::load_all(dir.path()).unwrap();

    assert_eq!(reloaded.len(), 1);
    assert_eq!(reloaded[0], profile, "all profile fields must roundtrip");
}

#[test]
fn profiles_empty_roundtrip() {
    let dir = tempdir().unwrap();
    let profiles: Vec<LoginProfile> = vec![];

    LoginProfile::save_all(dir.path(), &profiles).unwrap();
    let reloaded = LoginProfile::load_all(dir.path()).unwrap();

    assert_eq!(reloaded.len(), 0);
}

#[test]
fn profiles_load_returns_empty_when_no_file() {
    let dir = tempdir().unwrap();
    let loaded = LoginProfile::load_all(dir.path()).unwrap();
    assert!(loaded.is_empty());
}

#[test]
fn profiles_current_id_none_when_no_file() {
    let dir = tempdir().unwrap();
    let current = LoginProfile::load_current_id(dir.path()).unwrap();
    assert!(current.is_none());
}

#[test]
fn profiles_current_id_roundtrip() {
    let dir = tempdir().unwrap();

    LoginProfile::save_current_id(dir.path(), "profile-xyz").unwrap();
    let reloaded = LoginProfile::load_current_id(dir.path()).unwrap();

    assert_eq!(reloaded.as_deref(), Some("profile-xyz"));
}

#[test]
fn profiles_current_id_overwrite() {
    let dir = tempdir().unwrap();

    LoginProfile::save_current_id(dir.path(), "p1").unwrap();
    LoginProfile::save_current_id(dir.path(), "p2").unwrap();

    let reloaded = LoginProfile::load_current_id(dir.path()).unwrap();
    assert_eq!(reloaded.as_deref(), Some("p2"));
}

// ---------------------------------------------------------------------------
// Full restart simulation: prefs + profiles together
// ---------------------------------------------------------------------------

#[test]
fn full_state_roundtrip_after_restart() {
    let dir = tempdir().unwrap();

    let prefs = full_prefs();
    let profiles = vec![
        full_profile("p1", "user1@work.com"),
        full_profile("p2", "user2@home.com"),
    ];

    // Persist everything.
    prefs.save(dir.path()).unwrap();
    LoginProfile::save_all(dir.path(), &profiles).unwrap();
    LoginProfile::save_current_id(dir.path(), "p1").unwrap();

    // Simulate restart: all in-memory state is dropped.
    drop(prefs);
    drop(profiles);

    // Re-load everything from disk.
    let reloaded_prefs = Prefs::load(dir.path()).unwrap();
    let reloaded_profiles = LoginProfile::load_all(dir.path()).unwrap();
    let reloaded_current = LoginProfile::load_current_id(dir.path()).unwrap();

    // Assert everything roundtrips.
    let expected_prefs = full_prefs();
    assert_eq!(
        reloaded_prefs, expected_prefs,
        "prefs mismatch after restart"
    );

    let expected_profiles = vec![
        full_profile("p1", "user1@work.com"),
        full_profile("p2", "user2@home.com"),
    ];
    assert_eq!(
        reloaded_profiles, expected_profiles,
        "profiles mismatch after restart"
    );
    assert_eq!(
        reloaded_current.as_deref(),
        Some("p1"),
        "current-profile mismatch after restart"
    );
}
