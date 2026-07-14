/// The conventional Linux policy file path.
pub const DEFAULT_POLICY_PATH: &str = "/etc/tailscale/policy.json";

/// Linux policy files use the generic JSON policy store.
pub use crate::json_store::JsonFileStore as LinuxPolicyStore;
