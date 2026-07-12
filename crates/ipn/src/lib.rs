//! IPN state machine and notification bus — a Rust port of Go's `ipn` package.
//!
//! This crate provides the wire types ([`State`], [`Notify`], [`NotifyWatchOpt`],
//! [`EngineStatus`]), a [`NotifyBus`] for broadcasting notifications to
//! multiple subscribers, a [`StateMachine`] implementing the `nextStateLocked`
//! truth table, and an [`IpnBackend`] that ties them together.
//!
//! # Wire compatibility
//!
//! - [`State`] serializes as a raw JSON integer (0–6), matching Go's
//!   `ipn.State` (`type State int`).
//! - [`Notify`] serializes as PascalCase JSON with `None` fields omitted,
//!   matching Go's `encoding/json` behaviour for pointer fields with
//!   `omitzero`/`omitempty` semantics.
//! - [`NotifyWatchOpt`] uses the same explicit bit values as Go (not iota)
//!   so they round-trip over LocalAPI identically.

#![allow(non_snake_case)]

mod backend;
mod bus;
mod machine;
mod prefs;
mod profiles;

pub use backend::{BackendInputs, IpnBackend};
pub use bus::{NotifyBus, NotifyBusReceiver};
pub use machine::{next_state, StateMachineInputs};
pub use prefs::{AppConnectorPrefs, MaskedPrefs, Prefs, StartOptions};
pub use profiles::{
    KeyExpiryState, LoginProfile, NetworkProfile, ProfileError, ProfileID, ProfileManager,
    StateChangeCallback, StateKey, SwitchResult, UserProfile,
};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// State enum
// ---------------------------------------------------------------------------

/// The IPN backend state machine state, mirroring Go's `ipn.State`.
///
/// Serializes as a raw JSON integer (0–6) so it is wire-compatible with
/// Go's `type State int`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum State {
    /// No state — the backend hasn't started yet or state is unknown.
    #[default]
    NoState = 0,
    /// The tailnet is in use by another user on this machine.
    InUseOtherUser = 1,
    /// The user needs to log in (no valid node key, auth URL pending, etc.).
    NeedsLogin = 2,
    /// The machine needs admin authorization.
    NeedsMachineAuth = 3,
    /// The backend is stopped (want_running is false but we have a node key).
    Stopped = 4,
    /// The backend is starting up (engine is configuring, no live peers yet).
    Starting = 5,
    /// The backend is fully running (engine has live peers or DERP links).
    Running = 6,
}

impl State {
    /// Returns the string name, matching Go's `stateStrings` table.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NoState => "NoState",
            Self::InUseOtherUser => "InUseOtherUser",
            Self::NeedsLogin => "NeedsLogin",
            Self::NeedsMachineAuth => "NeedsMachineAuth",
            Self::Stopped => "Stopped",
            Self::Starting => "Starting",
            Self::Running => "Running",
        }
    }

    /// Parse a state from its string name (inverse of [`as_str`](Self::as_str)).
    pub fn from_str_name(s: &str) -> Option<Self> {
        match s {
            "NoState" => Some(Self::NoState),
            "InUseOtherUser" => Some(Self::InUseOtherUser),
            "NeedsLogin" => Some(Self::NeedsLogin),
            "NeedsMachineAuth" => Some(Self::NeedsMachineAuth),
            "Stopped" => Some(Self::Stopped),
            "Starting" => Some(Self::Starting),
            "Running" => Some(Self::Running),
            _ => None,
        }
    }
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl serde::Serialize for State {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_u8(*self as u8)
    }
}

impl<'de> serde::Deserialize<'de> for State {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let v = u8::deserialize(de)?;
        match v {
            0 => Ok(Self::NoState),
            1 => Ok(Self::InUseOtherUser),
            2 => Ok(Self::NeedsLogin),
            3 => Ok(Self::NeedsMachineAuth),
            4 => Ok(Self::Stopped),
            5 => Ok(Self::Starting),
            6 => Ok(Self::Running),
            _ => Err(serde::de::Error::custom(format!(
                "invalid State value: {v}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// EngineStatus
// ---------------------------------------------------------------------------

/// WireGuard engine status, mirroring Go's `ipn.EngineStatus`.
///
/// The fields the state machine cares about are `NumLive` and `LiveDERPs`;
/// the byte counters are included for the `NotifyEngineUpdates` path.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineStatus {
    /// Bytes received from the WireGuard engine.
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub RBytes: i64,
    /// Bytes sent through the WireGuard engine.
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub WBytes: i64,
    /// Number of live WireGuard peer sessions.
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub NumLive: i32,
    /// Number of active DERP relay connections.
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub LiveDERPs: i32,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero_i32(v: &i32) -> bool {
    *v == 0
}

// ---------------------------------------------------------------------------
// NotifyWatchOpt bitmask
// ---------------------------------------------------------------------------

/// Bitmask of options for `watch-ipn-bus`, mirroring Go's
/// `ipn.NotifyWatchOpt`.
///
/// Values are explicit (not iota) because they are serialized over LocalAPI.
pub type NotifyWatchOpt = u64;

pub const NOTIFY_WATCH_ENGINE_UPDATES: NotifyWatchOpt = 1 << 0;
pub const NOTIFY_INITIAL_STATE: NotifyWatchOpt = 1 << 1;
pub const NOTIFY_INITIAL_PREFS: NotifyWatchOpt = 1 << 2;
pub const NOTIFY_INITIAL_NET_MAP: NotifyWatchOpt = 1 << 3;
pub const NOTIFY_NO_PRIVATE_KEYS: NotifyWatchOpt = 1 << 4;
pub const NOTIFY_INITIAL_DRIVE_SHARES: NotifyWatchOpt = 1 << 5;
pub const NOTIFY_INITIAL_OUTGOING_FILES: NotifyWatchOpt = 1 << 6;
pub const NOTIFY_INITIAL_HEALTH_STATE: NotifyWatchOpt = 1 << 7;
pub const NOTIFY_RATE_LIMIT: NotifyWatchOpt = 1 << 8;
pub const NOTIFY_HEALTH_ACTIONS: NotifyWatchOpt = 1 << 9;
pub const NOTIFY_INITIAL_SUGGESTED_EXIT_NODE: NotifyWatchOpt = 1 << 10;
pub const NOTIFY_INITIAL_CLIENT_VERSION: NotifyWatchOpt = 1 << 11;
pub const NOTIFY_PEER_CHANGES: NotifyWatchOpt = 1 << 12;
pub const NOTIFY_NO_NET_MAP: NotifyWatchOpt = 1 << 13;
pub const NOTIFY_INITIAL_STATUS: NotifyWatchOpt = 1 << 14;
pub const NOTIFY_PEER_PATCHES: NotifyWatchOpt = 1 << 15;
pub const NOTIFY_IN_PROCESS_NO_DISCONNECT: NotifyWatchOpt = 1 << 16;
pub const NOTIFY_PEER_WIRE_GUARD_STATE: NotifyWatchOpt = 1 << 18;

/// Bits that cannot be combined with [`NOTIFY_RATE_LIMIT`].
pub const NOTIFY_RATE_LIMIT_INCOMPATIBLE_BITS: NotifyWatchOpt =
    NOTIFY_PEER_CHANGES | NOTIFY_NO_NET_MAP | NOTIFY_INITIAL_STATUS | NOTIFY_PEER_PATCHES;

/// Validate a watch mask, mirroring Go's `ValidateNotifyWatchOpt`.
/// Returns `Err(message)` if the mask is invalid.
pub fn validate_notify_watch_opt(mask: NotifyWatchOpt) -> Result<(), String> {
    if mask & NOTIFY_RATE_LIMIT != 0 {
        let bad = mask & NOTIFY_RATE_LIMIT_INCOMPATIBLE_BITS;
        if bad != 0 {
            return Err(format!(
                "NotifyRateLimit is incompatible with new-style IPN bus subscription bits {bad}"
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Notify struct
// ---------------------------------------------------------------------------

/// A notification from the backend to frontend consumers, mirroring Go's
/// `ipn.Notify`.
///
/// All fields are optional (`Option`); `None` fields are omitted from JSON
/// (wire-compatible with Go's pointer-field semantics where nil pointers
/// produce no field). Field names are PascalCase to match Go's JSON
/// encoding.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Notify {
    /// IPN backend version string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub Version: Option<String>,

    /// Session ID — only set in the first message when `NotifyInitialState`
    /// is requested. Clients must store it; subsequent messages omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub SessionID: Option<String>,

    /// Critical error message (or non-critical detail for `InUseOtherUser`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ErrMessage: Option<String>,

    /// Non-nil when the login process succeeded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub LoginFinished: Option<bool>,

    /// The new or current IPN state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub State: Option<State>,

    /// Current preferences (opaque JSON for now).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub Prefs: Option<serde_json::Value>,

    /// WireGuard engine status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub Engine: Option<EngineStatus>,

    /// URL the UI should open in a browser for interactive login.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub BrowseToURL: Option<String>,

    /// Initial status snapshot (set when `NotifyInitialStatus` is requested).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub InitialStatus: Option<serde_json::Value>,

    /// Waiting files in the Taildrop inbox (set when new files arrive).
    /// Mirrors Go's `ipn.Notify.FilesWaiting`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub FilesWaiting: Option<Vec<WaitingFile>>,

    /// Full network map (sent on initial request or legacy platforms).
    /// Mirrors Go's `ipn.Notify.NetMap`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub NetMap: Option<serde_json::Value>,

    /// Peers that were added or changed (full Node JSON objects).
    /// Mirrors Go's `ipn.Notify.PeersChanged`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub PeersChanged: Option<Vec<serde_json::Value>>,

    /// Peer IDs that were removed.
    /// Mirrors Go's `ipn.Notify.PeersRemoved`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub PeersRemoved: Option<Vec<i64>>,

    /// Partial peer changes (patch format).
    /// Mirrors Go's `ipn.Notify.PeerChangedPatch`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_null_to_default"
    )]
    pub PeerChangedPatch: Option<Vec<serde_json::Value>>,

    /// Current health warnings (text strings). When non-nil, health state
    /// changed and the consumer should surface it. Mirrors Go's
    /// `ipn.Notify.Health` (a `*health.State`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub Health: Option<Vec<String>>,

    /// Client version info from control. Mirrors Go's
    /// `ipn.Notify.ClientVersion` (`*tailcfg.ClientVersion`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ClientVersion: Option<serde_json::Value>,

    /// Suggested exit node ID. Mirrors Go's
    /// `ipn.Notify.SuggestedExitNode` (`*tailcfg.StableNodeID`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub SuggestedExitNode: Option<String>,

    /// Map of user profiles. Mirrors Go's
    /// `ipn.Notify.UserProfiles`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub UserProfiles: Option<serde_json::Value>,
}

/// Serde helper: deserialize `null` as `Default` (Go nil slices marshal as `null`).
fn deserialize_null_to_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    let opt: Option<T> = Option::deserialize(deserializer)?;
    Ok(opt.unwrap_or_default())
}

/// A file waiting in the Taildrop inbox, mirroring Go's
/// `apitype.WaitingFile`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaitingFile {
    /// The file name (basename, no path).
    #[serde(default)]
    pub Name: String,
    /// The file size in bytes.
    #[serde(default)]
    pub Size: i64,
}

impl Notify {
    /// Create a Notify carrying only a state transition.
    pub fn state(state: State) -> Self {
        Self {
            State: Some(state),
            ..Default::default()
        }
    }

    /// Create a Notify carrying only a browse-to-URL.
    pub fn browse_to_url(url: impl Into<String>) -> Self {
        Self {
            BrowseToURL: Some(url.into()),
            ..Default::default()
        }
    }

    /// Create a Notify carrying only a login-finished signal.
    pub fn login_finished() -> Self {
        Self {
            LoginFinished: Some(true),
            ..Default::default()
        }
    }

    /// Create a Notify carrying only an error message.
    pub fn err_message(msg: impl Into<String>) -> Self {
        Self {
            ErrMessage: Some(msg.into()),
            ..Default::default()
        }
    }

    /// Create a Notify carrying only an engine status update.
    pub fn engine(engine: EngineStatus) -> Self {
        Self {
            Engine: Some(engine),
            ..Default::default()
        }
    }

    /// Create a Notify carrying only a health state update.
    pub fn health(warnings: Vec<String>) -> Self {
        Self {
            Health: Some(warnings),
            ..Default::default()
        }
    }
}
