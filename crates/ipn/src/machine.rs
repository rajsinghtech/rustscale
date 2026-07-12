//! State machine — a port of Go's `nextStateLocked` truth table.
//!
//! The state machine is a pure function from [`BackendInputs`] + current
//! [`State`] → next [`State`]. It does not perform any side effects; the
//! caller ([`crate::IpnBackend`]) is responsible for emitting a `Notify`
//! when the state actually changes.

use crate::State;

/// Inputs to the state machine, mirroring the variables used by Go's
/// `nextStateLocked` in `ipn/ipnlocal/local.go:6835-6908`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StateMachineInputs {
    /// Whether the user wants the backend to be running (`WantRunning`).
    pub want_running: bool,
    /// Whether the user has explicitly logged out.
    pub logged_out: bool,
    /// Whether engine updates are blocked (e.g. waiting for auth).
    pub blocked: bool,
    /// Whether we have a persisted node private key.
    pub has_node_key: bool,
    /// Whether we have received at least one `MapResponse` (netmap is non-nil).
    pub netmap_present: bool,
    /// Whether auth cannot proceed without human interaction (AuthURL pending
    /// or register error).
    pub auth_cant_continue: bool,
    /// Whether the node key has expired.
    pub key_expired: bool,
    /// Whether the machine is authorized by the control plane.
    pub machine_authorized: bool,
    /// Number of live WireGuard peer sessions.
    pub num_live: i32,
    /// Number of active DERP relay connections.
    pub live_derps: i32,
}

/// The state machine truth table, ported from Go's `nextStateLocked`.
///
/// This is a pure function — it reads `inputs` and `current_state` and
/// returns the state the backend should be in. The caller is responsible
/// for detecting state changes and emitting notifications.
pub fn next_state(inputs: &StateMachineInputs, current_state: State) -> State {
    // Case 1: !wantRunning && !loggedOut && !blocked && hasNodeKey → Stopped
    if !inputs.want_running && !inputs.logged_out && !inputs.blocked && inputs.has_node_key {
        return State::Stopped;
    }

    // Case 2: netMap == nil
    if !inputs.netmap_present {
        if inputs.auth_cant_continue || inputs.logged_out {
            return State::NeedsLogin;
        }
        // Invariant 3: !want_running must not yield Running or Starting. Case 1
        // only catches !want_running when !blocked && has_node_key; the remaining
        // !want_running paths (blocked or no node key) must still drop to Stopped
        // rather than falling into the state switch below (which can return
        // Running/Starting).
        if !inputs.want_running {
            return State::Stopped;
        }
        // Invariant 1: blocked prevents remaining in Running even before the
        // netmap arrives.
        if inputs.blocked && current_state == State::Running {
            return State::NeedsLogin;
        }
        return match current_state {
            // If we were already Stopped, auth is in good shape — transition
            // to Starting right away.
            State::Stopped => State::Starting,
            // First time connecting; UIs should print "Loading...".
            State::NoState => State::NoState,
            // Keep the current state for Starting/Running/NeedsLogin.
            State::Starting | State::Running | State::NeedsLogin => current_state,
            // Any other state: keep it (Go logs "unexpected").
            _ => current_state,
        };
    }

    // Past here, netmap is present.

    // Invariant 2: logged_out forces NeedsLogin regardless of want_running or
    // any other input. Go only checks logged_out inside the no-netmap branch,
    // but the contract requires NeedsLogin whenever the user has logged out.
    if inputs.logged_out {
        return State::NeedsLogin;
    }

    // Case 3: !wantRunning → Stopped
    if !inputs.want_running {
        return State::Stopped;
    }

    // Case 4: keyExpired → NeedsLogin
    if inputs.key_expired {
        return State::NeedsLogin;
    }

    // Case 5: !machineAuthorized → NeedsMachineAuth
    if !inputs.machine_authorized {
        return State::NeedsMachineAuth;
    }

    // Case 6: state == NeedsMachineAuth → Starting (now authorized)
    if current_state == State::NeedsMachineAuth {
        return State::Starting;
    }

    // Case 7: state == Starting → Running if engine has live peers/DERPs
    if current_state == State::Starting {
        if inputs.num_live > 0 || inputs.live_derps > 0 {
            // Invariant 1: blocked prevents transition to Running.
            if inputs.blocked {
                return State::Starting;
            }
            return State::Running;
        }
        return State::Starting;
    }

    // Case 8: state == Running → Running (unless blocked)
    if current_state == State::Running {
        // Invariant 1: blocked prevents remaining in Running.
        if inputs.blocked {
            return State::NeedsLogin;
        }
        return State::Running;
    }

    // Default: Starting
    State::Starting
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        validate_notify_watch_opt, EngineStatus, Notify, NOTIFY_INITIAL_PREFS,
        NOTIFY_INITIAL_STATE, NOTIFY_INITIAL_STATUS, NOTIFY_PEER_CHANGES, NOTIFY_RATE_LIMIT,
    };

    /// Helper to build inputs with sensible defaults for testing.
    fn inputs() -> StateMachineInputs {
        StateMachineInputs {
            want_running: true,
            logged_out: false,
            blocked: false,
            has_node_key: true,
            netmap_present: true,
            auth_cant_continue: false,
            key_expired: false,
            machine_authorized: true,
            num_live: 0,
            live_derps: 0,
        }
    }

    /// Table-driven truth table mirroring Go's `nextStateLocked`.
    #[test]
    fn truth_table() {
        let cases: &[(&str, StateMachineInputs, State, State)] = &[
            // (name, inputs, current_state, expected_next)
            //
            // --- Case 1: !wantRunning && !loggedOut && !blocked && hasNodeKey ---
            (
                "stopped when want_running false with node key",
                StateMachineInputs {
                    want_running: false,
                    has_node_key: true,
                    ..inputs()
                },
                State::Running,
                State::Stopped,
            ),
            (
                "stopped when want_running false with node key from nostate",
                StateMachineInputs {
                    want_running: false,
                    has_node_key: true,
                    ..inputs()
                },
                State::NoState,
                State::Stopped,
            ),
            // --- Case 1 not met: no node key ---
            (
                "not stopped without node key",
                StateMachineInputs {
                    want_running: false,
                    has_node_key: false,
                    netmap_present: true,
                    ..inputs()
                },
                State::NoState,
                State::Stopped,
            ), // !wantRunning case 3
            // --- Case 2: netMap == nil ---
            (
                "nostate when no netmap and first connect",
                StateMachineInputs {
                    want_running: true,
                    has_node_key: true,
                    netmap_present: false,
                    ..inputs()
                },
                State::NoState,
                State::NoState,
            ),
            (
                "starting when no netmap but was stopped",
                StateMachineInputs {
                    want_running: true,
                    has_node_key: true,
                    netmap_present: false,
                    ..inputs()
                },
                State::Stopped,
                State::Starting,
            ),
            (
                "starting stays starting with no netmap",
                StateMachineInputs {
                    want_running: true,
                    has_node_key: true,
                    netmap_present: false,
                    ..inputs()
                },
                State::Starting,
                State::Starting,
            ),
            (
                "running stays running with no netmap",
                StateMachineInputs {
                    want_running: true,
                    has_node_key: true,
                    netmap_present: false,
                    ..inputs()
                },
                State::Running,
                State::Running,
            ),
            (
                "needs_login stays needs_login with no netmap",
                StateMachineInputs {
                    want_running: true,
                    has_node_key: true,
                    netmap_present: false,
                    ..inputs()
                },
                State::NeedsLogin,
                State::NeedsLogin,
            ),
            // --- Case 2 with auth_cant_continue ---
            (
                "needs_login when no netmap and auth cant continue",
                StateMachineInputs {
                    want_running: true,
                    has_node_key: true,
                    netmap_present: false,
                    auth_cant_continue: true,
                    ..inputs()
                },
                State::NoState,
                State::NeedsLogin,
            ),
            // --- Case 2 with logged_out ---
            (
                "needs_login when no netmap and logged out",
                StateMachineInputs {
                    want_running: true,
                    has_node_key: true,
                    netmap_present: false,
                    logged_out: true,
                    ..inputs()
                },
                State::NoState,
                State::NeedsLogin,
            ),
            // --- Case 3: !wantRunning with netmap ---
            (
                "stopped when want_running false with netmap",
                StateMachineInputs {
                    want_running: false,
                    has_node_key: false,
                    netmap_present: true,
                    ..inputs()
                },
                State::Running,
                State::Stopped,
            ),
            // --- Case 4: keyExpired ---
            (
                "needs_login when key expired",
                StateMachineInputs {
                    want_running: true,
                    has_node_key: true,
                    netmap_present: true,
                    key_expired: true,
                    ..inputs()
                },
                State::Running,
                State::NeedsLogin,
            ),
            // --- Case 5: !machineAuthorized ---
            (
                "needs_machine_auth when not authorized",
                StateMachineInputs {
                    want_running: true,
                    has_node_key: true,
                    netmap_present: true,
                    machine_authorized: false,
                    ..inputs()
                },
                State::Starting,
                State::NeedsMachineAuth,
            ),
            // --- Case 6: state == NeedsMachineAuth → Starting ---
            (
                "starting from needs_machine_auth when authorized",
                StateMachineInputs {
                    want_running: true,
                    has_node_key: true,
                    netmap_present: true,
                    machine_authorized: true,
                    ..inputs()
                },
                State::NeedsMachineAuth,
                State::Starting,
            ),
            // --- Case 7: state == Starting, no live peers ---
            (
                "starting stays starting with no live peers",
                StateMachineInputs {
                    want_running: true,
                    has_node_key: true,
                    netmap_present: true,
                    machine_authorized: true,
                    num_live: 0,
                    live_derps: 0,
                    ..inputs()
                },
                State::Starting,
                State::Starting,
            ),
            // --- Case 7: state == Starting, live peers ---
            (
                "running from starting with live peers",
                StateMachineInputs {
                    want_running: true,
                    has_node_key: true,
                    netmap_present: true,
                    machine_authorized: true,
                    num_live: 1,
                    live_derps: 0,
                    ..inputs()
                },
                State::Starting,
                State::Running,
            ),
            // --- Case 7: state == Starting, live DERPs ---
            (
                "running from starting with live derps",
                StateMachineInputs {
                    want_running: true,
                    has_node_key: true,
                    netmap_present: true,
                    machine_authorized: true,
                    num_live: 0,
                    live_derps: 1,
                    ..inputs()
                },
                State::Starting,
                State::Running,
            ),
            // --- Case 8: state == Running ---
            (
                "running stays running",
                StateMachineInputs {
                    want_running: true,
                    has_node_key: true,
                    netmap_present: true,
                    machine_authorized: true,
                    num_live: 0,
                    live_derps: 0,
                    ..inputs()
                },
                State::Running,
                State::Running,
            ),
            // --- Default: any other state → Starting ---
            (
                "default to starting from nostate with netmap",
                StateMachineInputs {
                    want_running: true,
                    has_node_key: true,
                    netmap_present: true,
                    machine_authorized: true,
                    num_live: 0,
                    live_derps: 0,
                    ..inputs()
                },
                State::NoState,
                State::Starting,
            ),
            // --- Edge: logged_out forces NeedsLogin even when want_running false ---
            (
                "needs_login when logged out and want_running false with netmap",
                StateMachineInputs {
                    want_running: false,
                    logged_out: true,
                    has_node_key: true,
                    netmap_present: true,
                    ..inputs()
                },
                State::NoState,
                State::NeedsLogin,
            ),
            // --- Edge: blocked with want_running false ---
            (
                "stopped when blocked and want_running false with netmap",
                StateMachineInputs {
                    want_running: false,
                    blocked: true,
                    has_node_key: true,
                    netmap_present: true,
                    ..inputs()
                },
                State::NoState,
                State::Stopped,
            ), // case 3: !wantRunning → Stopped (blocked only suppresses Case 1)
            // --- blocked=true + want_running=true → NOT Stopped ---
            (
                "starting not stopped when blocked and want_running true",
                StateMachineInputs {
                    want_running: true,
                    blocked: true,
                    has_node_key: true,
                    netmap_present: true,
                    machine_authorized: true,
                    ..inputs()
                },
                State::NoState,
                State::Starting,
            ),
            (
                "needs_machine_auth when blocked and want_running true but unauthorized",
                StateMachineInputs {
                    want_running: true,
                    blocked: true,
                    has_node_key: true,
                    netmap_present: true,
                    machine_authorized: false,
                    ..inputs()
                },
                State::NoState,
                State::NeedsMachineAuth,
            ),
            // --- logged_out=true + want_running=false + no netmap → NeedsLogin ---
            (
                "needs_login when logged out and want_running false without netmap",
                StateMachineInputs {
                    want_running: false,
                    logged_out: true,
                    has_node_key: true,
                    netmap_present: false,
                    ..inputs()
                },
                State::NoState,
                State::NeedsLogin,
            ),
        ];

        for (name, inp, current, expected) in cases {
            let got = next_state(inp, *current);
            assert_eq!(got, *expected, "test case: {name}");
        }
    }

    #[test]
    fn state_serializes_as_integer() {
        assert_eq!(serde_json::to_string(&State::NoState).unwrap(), "0");
        assert_eq!(serde_json::to_string(&State::Running).unwrap(), "6");
        assert_eq!(serde_json::to_string(&State::NeedsLogin).unwrap(), "2");
    }

    #[test]
    fn state_deserializes_from_integer() {
        let s: State = serde_json::from_str("6").unwrap();
        assert_eq!(s, State::Running);
        let s: State = serde_json::from_str("0").unwrap();
        assert_eq!(s, State::NoState);
    }

    #[test]
    fn state_invalid_value_rejected() {
        assert!(serde_json::from_str::<State>("99").is_err());
    }

    #[test]
    fn state_as_str_roundtrip() {
        for &s in &[
            State::NoState,
            State::InUseOtherUser,
            State::NeedsLogin,
            State::NeedsMachineAuth,
            State::Stopped,
            State::Starting,
            State::Running,
        ] {
            assert_eq!(State::from_str_name(s.as_str()), Some(s));
        }
    }

    #[test]
    fn notify_serializes_pascalcase_with_omitted_none() {
        let n = Notify::state(State::Running);
        let j = serde_json::to_string(&n).unwrap();
        assert!(j.contains("\"State\":6"), "json: {j}");
        // None fields should be absent.
        assert!(!j.contains("Version"), "json: {j}");
        assert!(!j.contains("SessionID"), "json: {j}");
        assert!(!j.contains("ErrMessage"), "json: {j}");
        assert!(!j.contains("BrowseToURL"), "json: {j}");
        assert!(!j.contains("Engine"), "json: {j}");
        assert!(!j.contains("LoginFinished"), "json: {j}");
        assert!(!j.contains("Prefs"), "json: {j}");
        assert!(!j.contains("InitialStatus"), "json: {j}");
    }

    #[test]
    fn notify_with_all_fields_serializes_all() {
        let n = Notify {
            Version: Some("1.0".into()),
            SessionID: Some("abc".into()),
            ErrMessage: Some("err".into()),
            LoginFinished: Some(true),
            State: Some(State::Running),
            Prefs: Some(serde_json::json!({})),
            Engine: Some(EngineStatus {
                NumLive: 1,
                ..Default::default()
            }),
            BrowseToURL: Some("https://example.com".into()),
            InitialStatus: Some(serde_json::json!({})),
            FilesWaiting: None,
            NetMap: None,
            PeersChanged: None,
            PeersRemoved: None,
            PeerChangedPatch: None,
            Health: None,
            ClientVersion: None,
            SuggestedExitNode: None,
            UserProfiles: None,
        };
        let j = serde_json::to_string(&n).unwrap();
        assert!(j.contains("\"Version\":\"1.0\""));
        assert!(j.contains("\"SessionID\":\"abc\""));
        assert!(j.contains("\"ErrMessage\":\"err\""));
        assert!(j.contains("\"LoginFinished\":true"));
        assert!(j.contains("\"State\":6"));
        assert!(j.contains("\"BrowseToURL\":\"https://example.com\""));
        assert!(j.contains("\"NumLive\":1"));
    }

    #[test]
    fn notify_empty_serializes_as_empty_object() {
        let n = Notify::default();
        let j = serde_json::to_string(&n).unwrap();
        assert_eq!(j, "{}");
    }

    #[test]
    fn validate_notify_watch_opt_accepts_valid_masks() {
        assert!(validate_notify_watch_opt(0).is_ok());
        assert!(validate_notify_watch_opt(NOTIFY_INITIAL_STATE).is_ok());
        assert!(validate_notify_watch_opt(NOTIFY_INITIAL_STATE | NOTIFY_INITIAL_PREFS).is_ok());
        assert!(validate_notify_watch_opt(NOTIFY_PEER_CHANGES | NOTIFY_INITIAL_STATUS).is_ok());
    }

    #[test]
    fn validate_notify_watch_opt_rejects_rate_limit_with_peer_changes() {
        let mask = NOTIFY_RATE_LIMIT | NOTIFY_PEER_CHANGES;
        let err = validate_notify_watch_opt(mask).unwrap_err();
        assert!(err.contains("NotifyRateLimit"));
    }

    #[test]
    fn validate_notify_watch_opt_rejects_rate_limit_with_initial_status() {
        let mask = NOTIFY_RATE_LIMIT | NOTIFY_INITIAL_STATUS;
        assert!(validate_notify_watch_opt(mask).is_err());
    }

    #[test]
    fn validate_notify_watch_opt_allows_rate_limit_alone() {
        let mask = NOTIFY_RATE_LIMIT | NOTIFY_INITIAL_STATE;
        assert!(validate_notify_watch_opt(mask).is_ok());
    }
}
