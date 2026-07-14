//! Enterprise and MDM policy readers for Rustscale clients.
//!
//! This crate reads one OS-backed policy source at a time. Layered policy
//! resolution and change monitoring are intentionally left to callers.

mod json_store;
mod keys;
mod linux;
mod macos;
mod stub;

pub use json_store::JsonFileStore;
pub use keys::{PolicyKey, ValueType};
pub use linux::{LinuxPolicyStore, DEFAULT_POLICY_PATH};
#[cfg(all(feature = "macos", target_os = "macos"))]
pub use macos::MacOsDefaultsStore;
pub use stub::StubPolicyStore;

/// Kinds of errors produced while reading policy values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyErrorKind {
    /// The key is known but has no configured value.
    NotConfigured,
    /// The key name is not known to this crate.
    NoSuchKey,
    /// A configured value has a different type than requested.
    TypeMismatch,
    /// The backing store could not be read.
    Io,
    /// A configured value could not be parsed.
    Parse,
}

/// An error associated with a policy key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("policy error for {key}: {kind:?}")]
pub struct PolicyError {
    /// The category of failure.
    pub kind: PolicyErrorKind,
    /// The policy key involved in the failure.
    pub key: PolicyKey,
}

impl PolicyError {
    /// Builds a missing-policy error.
    pub const fn not_configured(key: PolicyKey) -> Self {
        Self {
            kind: PolicyErrorKind::NotConfigured,
            key,
        }
    }

    const fn type_mismatch(key: PolicyKey) -> Self {
        Self {
            kind: PolicyErrorKind::TypeMismatch,
            key,
        }
    }

    const fn io() -> Self {
        Self {
            kind: PolicyErrorKind::Io,
            key: PolicyKey::ControlURL,
        }
    }
}

/// Typed access to an OS-backed policy source.
pub trait PolicyStore: Send + Sync {
    /// Reads a string policy value.
    fn get_string(&self, key: PolicyKey) -> Result<String, PolicyError>;

    /// Reads a boolean policy value.
    fn get_bool(&self, key: PolicyKey) -> Result<bool, PolicyError>;

    /// Reads a string-list policy value.
    fn get_string_list(&self, key: PolicyKey) -> Result<Vec<String>, PolicyError>;

    /// Reads an arbitrary string value by wire name.
    fn get_raw(&self, key: &str) -> Result<String, PolicyError> {
        Err(PolicyError {
            kind: PolicyErrorKind::NoSuchKey,
            key: PolicyKey::from_name(key).unwrap_or(PolicyKey::ControlURL),
        })
    }
}

/// An ordered collection of stores, returning the first configured value.
pub struct PolicyStoreSet {
    stores: Vec<Box<dyn PolicyStore>>,
}

impl PolicyStoreSet {
    /// Creates a layered store set in priority order.
    pub fn new(stores: Vec<Box<dyn PolicyStore>>) -> Self {
        Self { stores }
    }
}

impl PolicyStore for PolicyStoreSet {
    fn get_string(&self, key: PolicyKey) -> Result<String, PolicyError> {
        for store in &self.stores {
            match store.get_string(key) {
                Ok(value) => return Ok(value),
                Err(error) if error.kind == PolicyErrorKind::NotConfigured => {}
                Err(error) => return Err(error),
            }
        }
        Err(PolicyError::not_configured(key))
    }

    fn get_bool(&self, key: PolicyKey) -> Result<bool, PolicyError> {
        for store in &self.stores {
            match store.get_bool(key) {
                Ok(value) => return Ok(value),
                Err(error) if error.kind == PolicyErrorKind::NotConfigured => {}
                Err(error) => return Err(error),
            }
        }
        Err(PolicyError::not_configured(key))
    }

    fn get_string_list(&self, key: PolicyKey) -> Result<Vec<String>, PolicyError> {
        for store in &self.stores {
            match store.get_string_list(key) {
                Ok(value) => return Ok(value),
                Err(error) if error.kind == PolicyErrorKind::NotConfigured => {}
                Err(error) => return Err(error),
            }
        }
        Err(PolicyError::not_configured(key))
    }
}

/// Creates the current platform's default policy store.
pub fn default_store() -> Box<dyn PolicyStore> {
    #[cfg(all(feature = "macos", target_os = "macos"))]
    {
        Box::new(MacOsDefaultsStore::new("io.tailscale.ipn.macsys"))
    }
    #[cfg(not(all(feature = "macos", target_os = "macos")))]
    {
        Box::new(StubPolicyStore::new())
    }
}

#[cfg(test)]
mod tests;
