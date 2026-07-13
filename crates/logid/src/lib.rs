//! Log collection identifiers, matching Go's `types/logid` package.

#![forbid(unsafe_code)]

use std::fmt;
use std::path::Path;
use std::str::FromStr;

use rand::RngCore;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

/// A private, random 32-byte log identifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateID([u8; 32]);

/// The public SHA-256 digest of a [`PrivateID`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicID([u8; 32]);

/// Errors loading or parsing a log identifier.
#[derive(Debug, thiserror::Error)]
pub enum LogIdError {
    /// The ID was not exactly 32 bytes when hex-decoded.
    #[error("log ID must be 32 bytes")]
    InvalidLength,
    /// The hex representation was malformed.
    #[error("invalid log ID hex: {0}")]
    Hex(#[from] hex::FromHexError),
    /// Persistence failed.
    #[error("log ID persistence failed: {0}")]
    Io(#[from] std::io::Error),
}

impl PrivateID {
    /// Generate a new random private identifier.
    pub fn new() -> Self {
        let mut bytes = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Return the corresponding public identifier.
    pub fn public(&self) -> PublicID {
        let mut hasher = Sha256::new();
        hasher.update(self.0);
        PublicID(hasher.finalize().into())
    }

    /// Load an ID from `path`, or generate and atomically persist one.
    pub fn load_or_create(path: &Path) -> Result<Self, LogIdError> {
        match std::fs::read_to_string(path) {
            Ok(value) => value.trim().parse(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let id = Self::new();
                rustscale_atomicfile::write_string(path, &id.to_string())?;
                Ok(id)
            }
            Err(error) => Err(error.into()),
        }
    }
}

impl Default for PrivateID {
    fn default() -> Self {
        Self::new()
    }
}

macro_rules! impl_hex_id {
    ($type:ident) => {
        impl fmt::Display for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&hex::encode(self.0))
            }
        }

        impl FromStr for $type {
            type Err = LogIdError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                let bytes = hex::decode(value)?;
                let bytes: [u8; 32] = bytes.try_into().map_err(|_| LogIdError::InvalidLength)?;
                Ok(Self(bytes))
            }
        }

        impl Serialize for $type {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.to_string())
            }
        }

        impl<'de> Deserialize<'de> for $type {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                value.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

impl_hex_id!(PrivateID);
impl_hex_id!(PublicID);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_id_is_sha256_of_private_id() {
        let private: PrivateID = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            .parse()
            .unwrap();
        assert_eq!(
            private.public().to_string(),
            "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8ab c1b8581bd710dd".replace(' ', "")
        );
    }

    #[test]
    fn hex_roundtrip() {
        let private = PrivateID::new();
        let encoded = private.to_string();
        assert_eq!(encoded.parse::<PrivateID>().unwrap(), private);
        let json = serde_json::to_string(&private).unwrap();
        assert_eq!(serde_json::from_str::<PrivateID>(&json).unwrap(), private);
    }

    #[test]
    fn load_or_create_persists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/logid");
        let first = PrivateID::load_or_create(&path).unwrap();
        let second = PrivateID::load_or_create(&path).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            std::fs::read_to_string(path).unwrap().trim(),
            first.to_string()
        );
    }
}
