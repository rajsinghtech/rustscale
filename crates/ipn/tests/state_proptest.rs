//! G6: Property-based test for the IPN state machine.
//!
//! Generates random (State, StateMachineInputs) pairs and asserts
//! invariants after every transition. See docs/regression-strategy.md G6.
//!
//! Invariants:
//! 1. If result == Running, blocked must be false.
//! 2. If logged_out is true, the resulting state must be NeedsLogin.
//! 3. If WantRunning is false, the state must not be Running or Starting.
//! 4. The state machine must never panic on any input combination.
//!
//! Invariants 1-3 are enforced by `next_state` for all input combinations.
//! The regression tests below pin the specific cases that previously violated
//! them. Invariant 4 holds for all inputs.

#![allow(non_snake_case)]

use proptest::prelude::*;
use rustscale_ipn::{next_state, State, StateMachineInputs};

fn state_strategy() -> impl Strategy<Value = State> {
    prop_oneof![
        Just(State::NoState),
        Just(State::InUseOtherUser),
        Just(State::NeedsLogin),
        Just(State::NeedsMachineAuth),
        Just(State::Stopped),
        Just(State::Starting),
        Just(State::Running),
    ]
}

fn inputs_strategy() -> impl Strategy<Value = StateMachineInputs> {
    (
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        0..10i32,
        0..10i32,
    )
        .prop_map(
            |(
                want_running,
                logged_out,
                blocked,
                has_node_key,
                netmap_present,
                auth_cant_continue,
                key_expired,
                machine_authorized,
                num_live,
                live_derps,
            )| {
                StateMachineInputs {
                    want_running,
                    logged_out,
                    blocked,
                    has_node_key,
                    netmap_present,
                    auth_cant_continue,
                    key_expired,
                    machine_authorized,
                    num_live,
                    live_derps,
                }
            },
        )
}

proptest! {
    /// Invariant 4: the state machine must never panic on any input
    /// combination, and must always return a valid State.
    #[test]
    fn state_machine_never_panics(
        state in state_strategy(),
        inputs in inputs_strategy(),
    ) {
        let result = next_state(&inputs, state);
        prop_assert!(
            matches!(
                result,
                State::NoState
                    | State::InUseOtherUser
                    | State::NeedsLogin
                    | State::NeedsMachineAuth
                    | State::Stopped
                    | State::Starting
                    | State::Running
            ),
            "invalid state returned: {:?}",
            result
        );
    }
}

proptest! {
    /// Invariants 1-3: the state machine contract.
    ///
    /// All three invariants hold for every (state, input) combination.
    #[test]
    fn state_machine_contract_invariants(
        state in state_strategy(),
        inputs in inputs_strategy(),
    ) {
        let result = next_state(&inputs, state);

        // Invariant 1: if result == Running, blocked must be false.
        if result == State::Running {
            prop_assert!(
                !inputs.blocked,
                "invariant 1: Running state with blocked=true (current={:?}, inputs={:?})",
                state,
                inputs
            );
        }

        // Invariant 2: if logged_out, result must be NeedsLogin.
        if inputs.logged_out {
            prop_assert!(
                result == State::NeedsLogin,
                "invariant 2: logged_out=true but result={:?} (not NeedsLogin) (current={:?}, inputs={:?})",
                result,
                state,
                inputs
            );
        }

        // Invariant 3: if !want_running, result must not be Running or Starting.
        if !inputs.want_running {
            prop_assert!(
                result != State::Running && result != State::Starting,
                "invariant 3: !want_running but result={:?} (Running or Starting) (current={:?}, inputs={:?})",
                result,
                state,
                inputs
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Regression tests: specific (state, input) combinations that previously
// violated invariants 1-3. They assert the invariant (the contract), not the
// old buggy behavior, and now pass after the state machine was fixed.
// ---------------------------------------------------------------------------

/// Invariant 1: `next_state` must not return Running when `blocked=true`.
/// Previously Case 8 returned Running unconditionally for state==Running.
#[test]
fn invariant_1_running_with_blocked_true() {
    let inputs = StateMachineInputs {
        want_running: true,
        logged_out: false,
        blocked: true,
        has_node_key: true,
        netmap_present: true,
        auth_cant_continue: false,
        key_expired: false,
        machine_authorized: true,
        num_live: 0,
        live_derps: 0,
    };
    let result = next_state(&inputs, State::Running);
    assert_eq!(
        result,
        State::NeedsLogin,
        "invariant 1: blocked=true must prevent Running"
    );
}

/// Invariant 2: `next_state` must return NeedsLogin when `logged_out=true`.
/// Previously Case 3 returned Stopped for !want_running, ignoring logged_out.
#[test]
fn invariant_2_logged_out_returns_stopped_not_needs_login() {
    let inputs = StateMachineInputs {
        want_running: false,
        logged_out: true,
        blocked: false,
        has_node_key: true,
        netmap_present: true,
        auth_cant_continue: false,
        key_expired: false,
        machine_authorized: true,
        num_live: 0,
        live_derps: 0,
    };
    let result = next_state(&inputs, State::NoState);
    assert_eq!(
        result,
        State::NeedsLogin,
        "invariant 2: logged_out=true must result in NeedsLogin"
    );
}

/// Invariant 3: `next_state` must not return Running or Starting when
/// `want_running=false`. Previously Case 2 (no netmap) kept the current state
/// even when want_running was false.
#[test]
fn invariant_3_not_want_running_but_running() {
    let inputs = StateMachineInputs {
        want_running: false,
        logged_out: false,
        blocked: true,
        has_node_key: true,
        netmap_present: false,
        auth_cant_continue: false,
        key_expired: false,
        machine_authorized: true,
        num_live: 0,
        live_derps: 0,
    };
    let result = next_state(&inputs, State::Running);
    assert_ne!(
        result,
        State::Running,
        "invariant 3: !want_running must not result in Running"
    );
    assert_ne!(
        result,
        State::Starting,
        "invariant 3: !want_running must not result in Starting"
    );
}
