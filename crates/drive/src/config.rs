use std::collections::{btree_map::Entry, BTreeMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use cap_std::ambient_authority;
use cap_std::fs::Dir;
use serde::{Deserialize, Serialize};

use crate::path::normalize_share_name;

/// A configured local directory exposed as a Taildrive share.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Share {
    pub name: String,
    pub path: PathBuf,
    /// Reserved for platform user-isolation implementations.
    #[serde(default, rename = "who", skip_serializing_if = "String::is_empty")]
    pub as_user: String,
    /// Reserved for macOS sandbox security-scoped bookmarks.
    #[serde(
        default,
        rename = "bookmarkData",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub bookmark_data: Vec<u8>,
}

impl Share {
    pub fn new(name: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            name: name.into(),
            path: path.into(),
            as_user: String::new(),
            bookmark_data: Vec::new(),
        }
    }
}

/// Resource and protocol limits applied by a [`Server`](crate::Server).
#[derive(Clone, Debug)]
pub struct Limits {
    pub max_shares: usize,
    pub max_grants: usize,
    pub max_grant_bytes: usize,
    pub max_path_bytes: usize,
    pub max_request_body: usize,
    pub max_response_body: usize,
    pub max_propfind_entries: usize,
    pub request_timeout: Duration,
    /// Filesystem roots such as `/` and `C:\` are rejected unless explicitly
    /// opted in. The default avoids an accidental whole-host share.
    pub allow_filesystem_root: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_shares: 128,
            max_grants: 128,
            max_grant_bytes: 64 * 1024,
            max_path_bytes: 4 * 1024,
            max_request_body: 16 * 1024 * 1024,
            max_response_body: 32 * 1024 * 1024,
            max_propfind_entries: 4096,
            request_timeout: Duration::from_secs(30),
            allow_filesystem_root: false,
        }
    }
}

pub(crate) struct ShareRoot {
    pub(crate) share: Share,
    pub(crate) dir: Dir,
}

/// Immutable, request-scoped view of the full Taildrive configuration.
///
/// Requests clone one `Arc<Snapshot>`, so they never observe a mixture of old
/// and new shares while configuration is replaced.
pub struct Snapshot {
    generation: u64,
    enabled: bool,
    pub(crate) shares: BTreeMap<String, ShareRoot>,
}

impl Snapshot {
    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn shares(&self) -> impl Iterator<Item = &Share> {
        self.shares.values().map(|root| &root.share)
    }
}

/// Atomically replaced Taildrive configuration.
pub struct ConfigStore {
    limits: Limits,
    current: RwLock<Arc<Snapshot>>,
}

impl ConfigStore {
    /// Construct a disabled store with no host filesystem exposure.
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            current: RwLock::new(Arc::new(Snapshot {
                generation: 0,
                enabled: false,
                shares: BTreeMap::new(),
            })),
        }
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    pub fn snapshot(&self) -> Arc<Snapshot> {
        match self.current.read() {
            Ok(current) => current.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Validate and replace all shares in one commit.
    ///
    /// Validation and capability opening happen before taking the write lock.
    /// A failed replacement leaves the prior snapshot untouched.
    pub fn replace(&self, enabled: bool, shares: Vec<Share>) -> Result<u64, ConfigError> {
        if shares.len() > self.limits.max_shares {
            return Err(ConfigError::TooManyShares);
        }
        if !enabled && !shares.is_empty() {
            return Err(ConfigError::DisabledWithShares);
        }

        let mut validated = BTreeMap::new();
        for mut share in shares {
            share.name = normalize_share_name(&share.name)?;
            if !share.as_user.is_empty() {
                return Err(ConfigError::UserIsolationUnavailable(share.as_user));
            }
            if !share.bookmark_data.is_empty() {
                return Err(ConfigError::BookmarkUnavailable);
            }
            validate_root_path(&share.path, &self.limits)?;
            let dir =
                Dir::open_ambient_dir(&share.path, ambient_authority()).map_err(|source| {
                    ConfigError::OpenRoot {
                        path: share.path.clone(),
                        source,
                    }
                })?;
            match validated.entry(share.name.clone()) {
                Entry::Vacant(entry) => {
                    entry.insert(ShareRoot { share, dir });
                }
                Entry::Occupied(_) => return Err(ConfigError::DuplicateShare(share.name)),
            }
        }

        let mut current = match self.current.write() {
            Ok(current) => current,
            Err(poisoned) => poisoned.into_inner(),
        };
        let generation = current.generation.saturating_add(1);
        *current = Arc::new(Snapshot {
            generation,
            enabled,
            shares: validated,
        });
        Ok(generation)
    }

    pub fn disable(&self) -> u64 {
        // Empty disabled configurations are always valid.
        self.replace(false, Vec::new())
            .expect("empty disabled Taildrive configuration must be valid")
    }
}

fn validate_root_path(path: &Path, limits: &Limits) -> Result<(), ConfigError> {
    if !path.is_absolute() {
        return Err(ConfigError::RootNotAbsolute(path.to_path_buf()));
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|source| ConfigError::OpenRoot {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() {
        return Err(ConfigError::RootIsSymlink(path.to_path_buf()));
    }
    if !metadata.is_dir() {
        return Err(ConfigError::RootNotDirectory(path.to_path_buf()));
    }
    if !limits.allow_filesystem_root && path.parent().is_none() {
        return Err(ConfigError::FilesystemRootDenied(path.to_path_buf()));
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error(transparent)]
    InvalidShareName(#[from] crate::PathError),
    #[error("too many Taildrive shares")]
    TooManyShares,
    #[error("a disabled Taildrive configuration must not contain shares")]
    DisabledWithShares,
    #[error("duplicate Taildrive share {0:?}")]
    DuplicateShare(String),
    #[error("Taildrive share root must be absolute: {0}")]
    RootNotAbsolute(PathBuf),
    #[error("Taildrive share root is not a directory: {0}")]
    RootNotDirectory(PathBuf),
    #[error("Taildrive share root must not be a symbolic link: {0}")]
    RootIsSymlink(PathBuf),
    #[error("sharing a filesystem root requires an explicit opt-in: {0}")]
    FilesystemRootDenied(PathBuf),
    #[error("unable to open Taildrive root {path}: {source}")]
    OpenRoot {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("sharing as user {0:?} is unavailable in this bounded implementation")]
    UserIsolationUnavailable(String),
    #[error("macOS security-scoped bookmarks are unavailable in this implementation")]
    BookmarkUnavailable,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacement_is_atomic_and_disabled_by_default() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ConfigStore::new(Limits::default());
        let initial = store.snapshot();
        assert!(!initial.enabled());
        assert_eq!(initial.shares().count(), 0);

        store
            .replace(true, vec![Share::new(" Docs ", tmp.path())])
            .unwrap();
        let before_failed_update = store.snapshot();
        assert_eq!(before_failed_update.shares().next().unwrap().name, "docs");
        assert!(store
            .replace(
                true,
                vec![
                    Share::new("same", tmp.path()),
                    Share::new("SAME", tmp.path()),
                ],
            )
            .is_err());
        let after = store.snapshot();
        assert_eq!(after.generation(), before_failed_update.generation());
        assert_eq!(after.shares().next().unwrap().name, "docs");
        // A request holding the old snapshot remains internally consistent.
        assert_eq!(initial.generation(), 0);
        assert!(!initial.enabled());
    }

    #[cfg(unix)]
    #[test]
    fn root_symlink_is_rejected() {
        use std::os::unix::fs::symlink;
        let tmp = tempfile::tempdir().unwrap();
        let link = tmp.path().join("link");
        symlink(tmp.path(), &link).unwrap();
        let store = ConfigStore::new(Limits::default());
        assert!(matches!(
            store.replace(true, vec![Share::new("docs", link)]),
            Err(ConfigError::RootIsSymlink(_))
        ));
    }
}
