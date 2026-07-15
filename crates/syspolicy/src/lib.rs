//! System-policy resolution for RustScale clients.
//!
//! The crate mirrors the production foundation of Tailscale's `util/syspolicy`:
//! typed definitions, scoped source precedence, immutable snapshots, change
//! callbacks, strict typed accessors, and concurrency-safe providers. Policy
//! values are never logged by this crate.

#![forbid(unsafe_code)]

mod engine;
mod keys;
mod provider;
mod value;

pub use engine::{
    CallbackRegistration, Origin, PolicyChange, PolicyEngine, PolicyItem, ProviderId, Snapshot,
    TestOverride,
};
pub use keys::{
    well_known_definitions, PolicyKey, PolicyScope, Scope, SettingDefinition, ValueType,
};
pub use provider::{
    environment_variable_name, EnvironmentProvider, JsonFileProvider, MemoryProvider,
    PolicyProvider, ProviderSubscription, ProviderValues, StubPolicyProvider, MAX_ENV_VALUE_SIZE,
    MAX_POLICY_FILE_SIZE,
};
pub use value::{
    parse_go_duration, DurationParseError, PolicyValue, PreferenceOption, RawValue, Visibility,
};

use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Conventional Unix policy file path.
pub const DEFAULT_POLICY_PATH: &str = "/etc/tailscale/policy.json";

/// Kinds of policy read and conversion failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyErrorKind {
    /// The key is known but has no configured value.
    NotConfigured,
    /// The key does not have a registered definition.
    NoSuchKey,
    /// A value's raw or requested type does not match its definition.
    TypeMismatch,
    /// A backing source could not be read.
    Io,
    /// A value or document could not be parsed.
    Parse,
    /// A bounded source exceeded its configured limit.
    TooLarge,
    /// Definitions conflict.
    InvalidDefinition,
    /// A provider failed or panicked without a more specific error.
    Provider,
}

/// A policy failure. It deliberately excludes raw values and filesystem paths
/// so callers can safely report it without disclosing policy secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("system policy {kind:?}{key_suffix}", key_suffix = .key.map_or(String::new(), |key| format!(" for {key}")))]
pub struct PolicyError {
    /// Failure category.
    pub kind: PolicyErrorKind,
    /// Setting involved, when this is an item-level failure.
    pub key: Option<PolicyKey>,
}

impl PolicyError {
    /// Creates a provider-wide error.
    pub const fn new(kind: PolicyErrorKind) -> Self {
        Self { kind, key: None }
    }

    /// Creates an item-level error.
    pub const fn for_key(kind: PolicyErrorKind, key: PolicyKey) -> Self {
        Self {
            kind,
            key: Some(key),
        }
    }
}

/// Creates a platform-default engine.
///
/// Unix uses an optional bounded JSON file followed by environment policy, so
/// environment settings win same-scope conflicts. Windows currently uses a
/// cfg-safe empty provider until a registry implementation can be added without
/// introducing unsafe code or a new platform dependency.
pub fn default_engine(scope: PolicyScope) -> Result<PolicyEngine, PolicyError> {
    let engine = PolicyEngine::well_known(scope)?;
    #[cfg(unix)]
    {
        engine.add_provider(
            "system policy file",
            PolicyScope::Device,
            Arc::new(JsonFileProvider::optional(DEFAULT_POLICY_PATH)),
        )?;
        engine.add_provider(
            "environment",
            PolicyScope::Device,
            Arc::new(EnvironmentProvider::new()),
        )?;
    }
    #[cfg(windows)]
    {
        engine.add_provider(
            "windows policy (unsupported)",
            PolicyScope::Device,
            Arc::new(StubPolicyProvider::new()),
        )?;
    }
    #[cfg(not(any(unix, windows)))]
    {
        engine.add_provider(
            "platform policy (unsupported)",
            PolicyScope::Device,
            Arc::new(StubPolicyProvider::new()),
        )?;
    }
    Ok(engine)
}

/// Backwards-compatible names for the original single-store skeleton.
pub type JsonFileStore = JsonFileProvider;
/// Linux uses the bounded JSON provider.
pub type LinuxPolicyStore = JsonFileProvider;
/// Empty fallback provider.
pub type StubPolicyStore = StubPolicyProvider;

#[cfg(test)]
mod tests;
