#[cfg(all(feature = "macos", target_os = "macos"))]
use crate::{PolicyError, PolicyErrorKind, PolicyKey, PolicyStore};

/// Parses the boolean spellings emitted by macOS `defaults`.
#[cfg(any(test, all(feature = "macos", target_os = "macos")))]
pub(crate) fn parse_defaults_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// Parses the plist-style array emitted by `defaults read`.
#[cfg(any(test, all(feature = "macos", target_os = "macos")))]
pub(crate) fn parse_defaults_string_list(value: &str) -> Vec<String> {
    let trimmed = value.trim();
    let trimmed = trimmed
        .strip_prefix('(')
        .unwrap_or(trimmed)
        .strip_suffix(')')
        .unwrap_or(trimmed)
        .trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    trimmed
        .split(',')
        .map(|item| item.trim().trim_matches(['\"', '\'']).to_owned())
        .filter(|item| !item.is_empty())
        .collect()
}

#[cfg(all(feature = "macos", target_os = "macos"))]
use std::process::Command;

/// macOS policy store backed by the current user's defaults domain.
#[cfg(all(feature = "macos", target_os = "macos"))]
#[derive(Debug, Clone)]
pub struct MacOsDefaultsStore {
    domain: String,
}

#[cfg(all(feature = "macos", target_os = "macos"))]
impl MacOsDefaultsStore {
    /// Creates a store that reads the supplied defaults domain.
    pub fn new(domain: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
        }
    }

    fn read(&self, key: &str, policy_key: PolicyKey) -> Result<String, PolicyError> {
        let output = Command::new("/usr/bin/defaults")
            .args(["read", &self.domain, key])
            .output()
            .map_err(|_| PolicyError::io())?;
        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        if output.status.code() == Some(1)
            && stderr.contains("The domain/default pair of")
            && stderr.contains("does not exist")
        {
            Err(PolicyError::not_configured(policy_key))
        } else {
            log::debug!("defaults read failed for {key}: {stderr}");
            Err(PolicyError::io())
        }
    }
}

#[cfg(all(feature = "macos", target_os = "macos"))]
impl PolicyStore for MacOsDefaultsStore {
    fn get_string(&self, key: PolicyKey) -> Result<String, PolicyError> {
        self.read(key.wire_name(), key)
    }

    fn get_bool(&self, key: PolicyKey) -> Result<bool, PolicyError> {
        let value = self.read(key.wire_name(), key)?;
        parse_defaults_bool(&value).ok_or(PolicyError {
            kind: PolicyErrorKind::Parse,
            key,
        })
    }

    fn get_string_list(&self, key: PolicyKey) -> Result<Vec<String>, PolicyError> {
        Ok(parse_defaults_string_list(
            &self.read(key.wire_name(), key)?,
        ))
    }

    fn get_raw(&self, key: &str) -> Result<String, PolicyError> {
        self.read(
            key,
            PolicyKey::from_name(key).unwrap_or(PolicyKey::ControlURL),
        )
    }
}
