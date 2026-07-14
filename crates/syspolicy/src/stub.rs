use crate::{PolicyError, PolicyKey, PolicyStore};

/// Fallback policy store used when no platform implementation is configured.
#[derive(Debug, Default)]
pub struct StubPolicyStore;

impl StubPolicyStore {
    /// Creates an empty policy store.
    pub const fn new() -> Self {
        Self
    }
}

impl PolicyStore for StubPolicyStore {
    fn get_string(&self, key: PolicyKey) -> Result<String, PolicyError> {
        Err(PolicyError::not_configured(key))
    }

    fn get_bool(&self, key: PolicyKey) -> Result<bool, PolicyError> {
        Err(PolicyError::not_configured(key))
    }

    fn get_string_list(&self, key: PolicyKey) -> Result<Vec<String>, PolicyError> {
        Err(PolicyError::not_configured(key))
    }
}
