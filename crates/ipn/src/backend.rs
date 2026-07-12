//! IPN backend — holds the current state, its inputs, and the notification
//! bus. Provides methods to update inputs (triggering state re-evaluation
//! and emitting `Notify{State}` on transitions) and to emit one-shot
//! notifications (`BrowseToURL`, `LoginFinished`, `ErrMessage`, `Engine`).

use std::sync::Mutex;

use crate::machine::StateMachineInputs;
use crate::{next_state, Notify, NotifyBus, State};

/// Inputs that can be updated externally. This is a subset of
/// [`StateMachineInputs`] representing the fields the backend exposes for
/// mutation. The rest (`blocked`, `logged_out`) are managed internally.
#[derive(Clone, Debug, Default)]
pub struct BackendInputs {
    /// Whether the user wants the backend to be running.
    pub want_running: bool,
    /// Whether we have a persisted node private key.
    pub has_node_key: bool,
    /// Whether we have received at least one MapResponse.
    pub netmap_present: bool,
    /// Whether auth cannot proceed (AuthURL pending or register error).
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

struct BackendInner {
    state: State,
    inputs: BackendInputs,
    /// Whether engine updates are blocked (e.g. waiting for auth, key
    /// expired). Mirrors Go's `LocalBackend.blocked` field. Set via
    /// [`IpnBackend::set_blocked`].
    blocked: bool,
    /// Whether the user has explicitly logged out. Mirrors Go's
    /// `LocalBackend.loggedOut`, derived from `Prefs.LoggedOut`. Set via
    /// [`IpnBackend::set_logged_out`].
    logged_out: bool,
}

/// The IPN backend: current state + inputs + notification bus.
///
/// Thread-safe via a `std::sync::Mutex` (critical sections are short and
/// contain no await points). The [`NotifyBus`] is `Clone` and can be
/// passed to `LocalApiState` for `watch-ipn-bus` subscribers.
pub struct IpnBackend {
    inner: Mutex<BackendInner>,
    bus: NotifyBus,
    /// Version string included in the initial Notify message.
    version: String,
}

impl IpnBackend {
    /// Create a new backend in `NoState` with the given version string.
    pub fn new(version: impl Into<String>) -> Self {
        Self {
            inner: Mutex::new(BackendInner {
                state: State::NoState,
                inputs: BackendInputs::default(),
                blocked: false,
                logged_out: false,
            }),
            bus: NotifyBus::new(),
            version: version.into(),
        }
    }

    /// Get a clone of the notification bus for subscribing.
    pub fn bus(&self) -> NotifyBus {
        self.bus.clone()
    }

    /// Get the current state (lock-free read of a snapshot).
    pub fn state(&self) -> State {
        self.inner.lock().unwrap().state
    }

    /// Get a snapshot of the current inputs.
    pub fn inputs(&self) -> BackendInputs {
        self.inner.lock().unwrap().inputs.clone()
    }

    /// Get the current `blocked` flag.
    pub fn blocked(&self) -> bool {
        self.inner.lock().unwrap().blocked
    }

    /// Get the current `logged_out` flag.
    pub fn logged_out(&self) -> bool {
        self.inner.lock().unwrap().logged_out
    }

    /// Get the version string.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Update the backend inputs and re-evaluate the state machine.
    ///
    /// If the state changes, a `Notify{State}` is broadcast on the bus.
    /// Returns the new state.
    pub fn update_inputs(&self, update: impl FnOnce(&mut BackendInputs)) -> State {
        let mut inner = self.inner.lock().unwrap();
        update(&mut inner.inputs);

        let sm_inputs = StateMachineInputs {
            want_running: inner.inputs.want_running,
            logged_out: inner.logged_out,
            blocked: inner.blocked,
            has_node_key: inner.inputs.has_node_key,
            netmap_present: inner.inputs.netmap_present,
            auth_cant_continue: inner.inputs.auth_cant_continue,
            key_expired: inner.inputs.key_expired,
            machine_authorized: inner.inputs.machine_authorized,
            num_live: inner.inputs.num_live,
            live_derps: inner.inputs.live_derps,
        };

        let new_state = next_state(&sm_inputs, inner.state);
        if new_state != inner.state {
            inner.state = new_state;
            drop(inner);
            self.bus.send(Notify::state(new_state));
        }
        new_state
    }

    /// Set `want_running` to true and re-evaluate.
    pub fn set_want_running(&self) -> State {
        self.update_inputs(|i| i.want_running = true)
    }

    /// Set `has_node_key` and re-evaluate.
    pub fn set_has_node_key(&self, v: bool) -> State {
        self.update_inputs(|i| i.has_node_key = v)
    }

    /// Set `netmap_present` and re-evaluate.
    pub fn set_netmap_present(&self, v: bool) -> State {
        self.update_inputs(|i| i.netmap_present = v)
    }

    /// Set `auth_cant_continue` and re-evaluate.
    pub fn set_auth_cant_continue(&self, v: bool) -> State {
        self.update_inputs(|i| i.auth_cant_continue = v)
    }

    /// Set `key_expired` and re-evaluate.
    pub fn set_key_expired(&self, v: bool) -> State {
        self.update_inputs(|i| i.key_expired = v)
    }

    /// Set `machine_authorized` and re-evaluate.
    pub fn set_machine_authorized(&self, v: bool) -> State {
        self.update_inputs(|i| i.machine_authorized = v)
    }

    /// Set engine status (num_live, live_derps) and re-evaluate.
    pub fn set_engine_status(&self, num_live: i32, live_derps: i32) -> State {
        self.update_inputs(|i| {
            i.num_live = num_live;
            i.live_derps = live_derps;
        })
    }

    /// Set the `blocked` flag and re-evaluate the state machine.
    ///
    /// Mirrors Go's `blockEngineUpdatesLocked(block bool)` — the sole
    /// setter for `LocalBackend.blocked`. When `blocked=true`, Case 1
    /// (`!wantRunning && !blocked → Stopped`) is suppressed, allowing
    /// the backend to remain in `Starting`/`NeedsLogin` while engine
    /// updates are intentionally withheld.
    pub fn set_blocked(&self, blocked: bool) -> State {
        let mut inner = self.inner.lock().unwrap();
        inner.blocked = blocked;
        let sm_inputs = StateMachineInputs {
            want_running: inner.inputs.want_running,
            logged_out: inner.logged_out,
            blocked: inner.blocked,
            has_node_key: inner.inputs.has_node_key,
            netmap_present: inner.inputs.netmap_present,
            auth_cant_continue: inner.inputs.auth_cant_continue,
            key_expired: inner.inputs.key_expired,
            machine_authorized: inner.inputs.machine_authorized,
            num_live: inner.inputs.num_live,
            live_derps: inner.inputs.live_derps,
        };
        let new_state = next_state(&sm_inputs, inner.state);
        if new_state == inner.state {
            drop(inner);
        } else {
            inner.state = new_state;
            drop(inner);
            self.bus.send(Notify::state(new_state));
        }
        new_state
    }

    /// Set the `logged_out` flag and re-evaluate the state machine.
    ///
    /// Mirrors Go's `Logout` writing `Prefs{LoggedOut: true,
    /// WantRunning: false}` — `loggedOut` is read from prefs in
    /// `nextStateLocked`. When `logged_out=true` with no netmap, the
    /// state machine returns `NeedsLogin` instead of `Stopped`.
    pub fn set_logged_out(&self, logged_out: bool) -> State {
        let mut inner = self.inner.lock().unwrap();
        inner.logged_out = logged_out;
        let sm_inputs = StateMachineInputs {
            want_running: inner.inputs.want_running,
            logged_out: inner.logged_out,
            blocked: inner.blocked,
            has_node_key: inner.inputs.has_node_key,
            netmap_present: inner.inputs.netmap_present,
            auth_cant_continue: inner.inputs.auth_cant_continue,
            key_expired: inner.inputs.key_expired,
            machine_authorized: inner.inputs.machine_authorized,
            num_live: inner.inputs.num_live,
            live_derps: inner.inputs.live_derps,
        };
        let new_state = next_state(&sm_inputs, inner.state);
        if new_state == inner.state {
            drop(inner);
        } else {
            inner.state = new_state;
            drop(inner);
            self.bus.send(Notify::state(new_state));
        }
        new_state
    }

    /// Emit a `Notify{BrowseToURL}` on the bus.
    pub fn emit_browse_to_url(&self, url: impl Into<String>) {
        self.bus.send(Notify::browse_to_url(url));
    }

    /// Emit a `Notify{LoginFinished}` on the bus.
    pub fn emit_login_finished(&self) {
        self.bus.send(Notify::login_finished());
    }

    /// Emit a `Notify{ErrMessage}` on the bus.
    pub fn emit_err_message(&self, msg: impl Into<String>) {
        self.bus.send(Notify::err_message(msg));
    }

    /// Emit a `Notify{Engine}` on the bus.
    pub fn emit_engine(&self, engine: crate::EngineStatus) {
        self.bus.send(Notify::engine(engine));
    }

    /// Build the initial `Notify` message for a watch-ipn-bus session,
    /// based on the mask bits. This mirrors Go's `WatchNotificationsAs`
    /// initial-message logic for the bits rustscale supports:
    /// `NotifyInitialState`, `NotifyInitialPrefs`, `NotifyInitialStatus`.
    pub fn build_initial_notify(
        &self,
        mask: crate::NotifyWatchOpt,
        session_id: &str,
        initial_status: Option<serde_json::Value>,
        initial_prefs: Option<serde_json::Value>,
    ) -> Notify {
        use crate::{NOTIFY_INITIAL_PREFS, NOTIFY_INITIAL_STATE, NOTIFY_INITIAL_STATUS};

        let inner = self.inner.lock().unwrap();

        let mut notify = Notify {
            Version: Some(self.version.clone()),
            ..Default::default()
        };

        if mask & NOTIFY_INITIAL_STATE != 0 {
            notify.SessionID = Some(session_id.to_string());
            notify.State = Some(inner.state);
        }

        if mask & NOTIFY_INITIAL_PREFS != 0 {
            notify.Prefs = initial_prefs;
        }

        if mask & NOTIFY_INITIAL_STATUS != 0 {
            notify.InitialStatus = initial_status;
        }

        notify
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{State, NOTIFY_INITIAL_PREFS, NOTIFY_INITIAL_STATE, NOTIFY_INITIAL_STATUS};

    #[tokio::test]
    async fn backend_transitions_from_nostate_to_starting_to_running() {
        let backend = IpnBackend::new("test");
        assert_eq!(backend.state(), State::NoState);

        let mut sub = backend.bus().subscribe();

        // Set want_running + has_node_key → still NoState (no netmap, NoState
        // stays NoState per the truth table).
        backend.set_want_running();
        backend.set_has_node_key(true);
        assert_eq!(backend.state(), State::NoState);

        // Set netmap_present + machine_authorized → Starting (NoState with
        // netmap → default → Starting).
        backend.set_machine_authorized(true);
        backend.set_netmap_present(true);
        assert_eq!(backend.state(), State::Starting);

        // The transition should have been broadcast.
        let msg = sub.recv().await.unwrap().unwrap();
        assert_eq!(msg.State, Some(State::Starting));

        // Set engine status with live peers → Running.
        backend.set_engine_status(1, 0);
        assert_eq!(backend.state(), State::Running);

        let msg = sub.recv().await.unwrap().unwrap();
        assert_eq!(msg.State, Some(State::Running));
    }

    #[tokio::test]
    async fn backend_emits_browse_to_url() {
        let backend = IpnBackend::new("test");
        let mut sub = backend.bus().subscribe();

        backend.emit_browse_to_url("https://login.example.com");
        let msg = sub.recv().await.unwrap().unwrap();
        assert_eq!(msg.BrowseToURL, Some("https://login.example.com".into()));
    }

    #[tokio::test]
    async fn backend_emits_login_finished() {
        let backend = IpnBackend::new("test");
        let mut sub = backend.bus().subscribe();

        backend.emit_login_finished();
        let msg = sub.recv().await.unwrap().unwrap();
        assert_eq!(msg.LoginFinished, Some(true));
    }

    #[tokio::test]
    async fn backend_emits_err_message() {
        let backend = IpnBackend::new("test");
        let mut sub = backend.bus().subscribe();

        backend.emit_err_message("something went wrong");
        let msg = sub.recv().await.unwrap().unwrap();
        assert_eq!(msg.ErrMessage, Some("something went wrong".into()));
    }

    #[tokio::test]
    async fn backend_build_initial_notify_with_initial_state() {
        let backend = IpnBackend::new("v1.0");
        backend.set_want_running();
        backend.set_has_node_key(true);
        backend.set_netmap_present(true);
        backend.set_machine_authorized(true);
        backend.set_engine_status(1, 0);
        assert_eq!(backend.state(), State::Running);

        let notify = backend.build_initial_notify(NOTIFY_INITIAL_STATE, "session-abc", None, None);

        assert_eq!(notify.Version, Some("v1.0".into()));
        assert_eq!(notify.SessionID, Some("session-abc".into()));
        assert_eq!(notify.State, Some(State::Running));
        assert_eq!(notify.Prefs, None);
        assert_eq!(notify.InitialStatus, None);
    }

    #[tokio::test]
    async fn backend_build_initial_notify_with_all_bits() {
        let backend = IpnBackend::new("v1.0");

        let status = serde_json::json!({"BackendState": "Running"});
        let prefs = serde_json::json!({"hostname": "test"});

        let notify = backend.build_initial_notify(
            NOTIFY_INITIAL_STATE | NOTIFY_INITIAL_PREFS | NOTIFY_INITIAL_STATUS,
            "session-xyz",
            Some(status.clone()),
            Some(prefs.clone()),
        );

        assert_eq!(notify.SessionID, Some("session-xyz".into()));
        assert_eq!(notify.State, Some(State::NoState));
        assert_eq!(notify.Prefs, Some(prefs));
        assert_eq!(notify.InitialStatus, Some(status));
    }

    #[tokio::test]
    async fn backend_build_initial_notify_without_initial_state() {
        let backend = IpnBackend::new("v1.0");

        let notify = backend.build_initial_notify(0, "session", None, None);

        // No initial bits set → only Version.
        assert_eq!(notify.Version, Some("v1.0".into()));
        assert_eq!(notify.SessionID, None);
        assert_eq!(notify.State, None);
    }

    #[tokio::test]
    async fn backend_no_notify_when_state_unchanged() {
        let backend = IpnBackend::new("test");
        backend.set_want_running();
        backend.set_has_node_key(true);
        backend.set_machine_authorized(true);
        backend.set_netmap_present(true);
        assert_eq!(backend.state(), State::Starting);

        let mut sub = backend.bus().subscribe();

        // Setting the same inputs again should not produce a state change.
        backend.set_netmap_present(true);
        assert_eq!(backend.state(), State::Starting);

        // No message should be available (but the receiver won't hang
        // forever — we use a timeout).
        let result = tokio::time::timeout(std::time::Duration::from_millis(50), sub.recv()).await;
        assert!(
            result.is_err(),
            "should not receive a notify when state unchanged"
        );
    }

    #[tokio::test]
    async fn backend_set_blocked_suppresses_stopped() {
        let backend = IpnBackend::new("test");
        // Set up a Running state first.
        backend.set_want_running();
        backend.set_has_node_key(true);
        backend.set_netmap_present(true);
        backend.set_machine_authorized(true);
        backend.set_engine_status(1, 0);
        assert_eq!(backend.state(), State::Running);

        // Now block engine updates and set want_running=false. Without
        // blocked, this would be Stopped (Case 1). With blocked=true,
        // Case 1 is suppressed and Case 3 (!wantRunning → Stopped) is
        // also reached — but only when netmap is present. The key
        // scenario is: blocked + want_running=true → stays Starting,
        // not Stopped.
        backend.set_blocked(true);
        assert!(backend.blocked());
        assert_eq!(backend.state(), State::Running); // no change with netmap present

        // With want_running=true, blocked=true, no netmap, the state
        // should NOT be Stopped — it should be Starting (from NoState).
        let backend2 = IpnBackend::new("test");
        backend2.set_blocked(true);
        backend2.set_want_running();
        backend2.set_has_node_key(true);
        // netmap_present=false, current_state=NoState → NoState (stays)
        assert_ne!(backend2.state(), State::Stopped);
    }

    #[tokio::test]
    async fn backend_set_logged_out_transitions_to_needs_login() {
        let backend = IpnBackend::new("test");
        // Set up a Running state first.
        backend.set_want_running();
        backend.set_has_node_key(true);
        backend.set_netmap_present(true);
        backend.set_machine_authorized(true);
        backend.set_engine_status(1, 0);
        assert_eq!(backend.state(), State::Running);

        // Logout: set logged_out=true, want_running=false, clear netmap.
        backend.set_logged_out(true);
        assert!(backend.logged_out());
        backend.update_inputs(|i| {
            i.want_running = false;
            i.netmap_present = false;
            i.has_node_key = false;
        });
        // With logged_out=true, no netmap → NeedsLogin (not Stopped).
        assert_eq!(backend.state(), State::NeedsLogin);
    }

    #[tokio::test]
    async fn backend_set_blocked_false_on_auth_success() {
        let backend = IpnBackend::new("test");
        // Simulate NeedsLogin: blocked=true, auth_cant_continue=true.
        backend.set_blocked(true);
        backend.set_auth_cant_continue(true);
        backend.set_want_running();
        // No netmap yet, auth can't continue → NeedsLogin.
        assert_eq!(backend.state(), State::NeedsLogin);

        // Auth succeeds: unblock, clear auth_cant_continue, set node key.
        backend.set_blocked(false);
        backend.set_auth_cant_continue(false);
        backend.set_has_node_key(true);
        // Still no netmap, current_state=NeedsLogin → stays NeedsLogin
        // until netmap arrives. But blocked is now false.
        assert!(!backend.blocked());
    }

    #[tokio::test]
    async fn backend_notify_peers_changed() {
        let backend = IpnBackend::new("test");
        let mut sub = backend.bus().subscribe();

        // Send a Notify with PeersChanged directly on the bus.
        let node_json = serde_json::json!({"ID": 1, "Name": "peer1"});
        backend.bus().send(Notify {
            PeersChanged: Some(vec![node_json.clone()]),
            ..Default::default()
        });

        let msg = sub.recv().await.unwrap().unwrap();
        assert_eq!(msg.PeersChanged, Some(vec![node_json]));
    }

    #[tokio::test]
    async fn backend_notify_peers_removed() {
        let backend = IpnBackend::new("test");
        let mut sub = backend.bus().subscribe();

        backend.bus().send(Notify {
            PeersRemoved: Some(vec![1, 2, 3]),
            ..Default::default()
        });

        let msg = sub.recv().await.unwrap().unwrap();
        assert_eq!(msg.PeersRemoved, Some(vec![1, 2, 3]));
    }

    #[tokio::test]
    async fn backend_notify_deserializes_null_peer_fields() {
        // Go nil slices marshal as JSON null — ensure deserialization
        // doesn't fail.
        let json = r#"{"PeersChanged":null,"PeersRemoved":null,"PeerChangedPatch":null}"#;
        let n: Notify = serde_json::from_str(json).unwrap();
        assert_eq!(n.PeersChanged, None);
        assert_eq!(n.PeersRemoved, None);
        assert_eq!(n.PeerChangedPatch, None);
    }

    #[tokio::test]
    async fn notify_health_propagates_via_bus() {
        let backend = IpnBackend::new("test");
        let bus = backend.bus();
        let mut rx = bus.subscribe();

        // Send a health notify with warnings.
        backend.bus().send(Notify::health(vec![
            "control connection lost".into(),
            "captive portal detected".into(),
        ]));

        let n = rx
            .recv()
            .await
            .expect("should receive notify")
            .expect("should not lag");
        assert!(n.Health.is_some());
        let warnings = n.Health.as_ref().unwrap();
        assert_eq!(warnings.len(), 2);
        assert!(warnings[0].contains("control connection"));
        assert!(warnings[1].contains("captive portal"));
    }

    #[test]
    fn notify_new_fields_serialize_omitzero() {
        let n = Notify::default();
        let j = serde_json::to_string(&n).unwrap();
        assert_eq!(j, "{}");
        assert!(!j.contains("Health"));
        assert!(!j.contains("ClientVersion"));
        assert!(!j.contains("SuggestedExitNode"));
        assert!(!j.contains("UserProfiles"));
    }

    #[test]
    fn notify_health_round_trip() {
        let n = Notify {
            Health: Some(vec!["warning1".into()]),
            SuggestedExitNode: Some("nodeABC".into()),
            ..Default::default()
        };
        let j = serde_json::to_string(&n).unwrap();
        let n2: Notify = serde_json::from_str(&j).unwrap();
        assert_eq!(n2.Health, n.Health);
        assert_eq!(n2.SuggestedExitNode, n.SuggestedExitNode);
    }
}
