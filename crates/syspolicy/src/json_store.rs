use std::{fs, path::Path};

use serde_json::Value;

use crate::{PolicyError, PolicyErrorKind, PolicyKey, PolicyStore};

/// A policy store backed by a JSON object.
#[derive(Debug, Clone)]
pub struct JsonFileStore {
    values: Value,
}

impl JsonFileStore {
    /// Reads and parses a policy file once.
    pub fn new(path: impl AsRef<Path>) -> Result<Self, PolicyError> {
        let contents = fs::read_to_string(path).map_err(|_| PolicyError::io())?;
        Self::from_json(&contents)
    }

    /// Parses a JSON policy document without reading the filesystem.
    pub fn from_json(contents: &str) -> Result<Self, PolicyError> {
        Ok(Self {
            values: parse_json_object(contents)?,
        })
    }

    fn value(&self, key: PolicyKey) -> Result<&Value, PolicyError> {
        self.values
            .get(key.wire_name())
            .ok_or_else(|| PolicyError::not_configured(key))
    }

    fn raw_value(&self, name: &str) -> Result<&Value, PolicyError> {
        self.values.get(name).ok_or_else(|| {
            PolicyError::not_configured(PolicyKey::from_name(name).unwrap_or(PolicyKey::ControlURL))
        })
    }
}

impl PolicyStore for JsonFileStore {
    fn get_string(&self, key: PolicyKey) -> Result<String, PolicyError> {
        self.value(key)?
            .as_str()
            .map(ToOwned::to_owned)
            .ok_or_else(|| PolicyError::type_mismatch(key))
    }

    fn get_bool(&self, key: PolicyKey) -> Result<bool, PolicyError> {
        self.value(key)?
            .as_bool()
            .ok_or_else(|| PolicyError::type_mismatch(key))
    }

    fn get_string_list(&self, key: PolicyKey) -> Result<Vec<String>, PolicyError> {
        let values = self
            .value(key)?
            .as_array()
            .ok_or_else(|| PolicyError::type_mismatch(key))?;
        values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| PolicyError::type_mismatch(key))
            })
            .collect()
    }

    fn get_raw(&self, key: &str) -> Result<String, PolicyError> {
        self.raw_value(key)?
            .as_str()
            .map(ToOwned::to_owned)
            .ok_or_else(|| {
                PolicyError::type_mismatch(
                    PolicyKey::from_name(key).unwrap_or(PolicyKey::ControlURL),
                )
            })
    }
}

/// Parses a policy JSON document into an object value.
pub(crate) fn parse_json_object(contents: &str) -> Result<Value, PolicyError> {
    let value: Value = serde_json::from_str(contents).map_err(|_| PolicyError {
        kind: PolicyErrorKind::Parse,
        key: PolicyKey::ControlURL,
    })?;
    if value.is_object() {
        Ok(value)
    } else {
        Err(PolicyError {
            kind: PolicyErrorKind::Parse,
            key: PolicyKey::ControlURL,
        })
    }
}
