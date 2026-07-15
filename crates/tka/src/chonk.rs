//! Durable storage for verified Authority Update Messages (AUMs).
//!
//! A `Chonk` stores immutable AUMs by their BLAKE2s hash and an independent
//! last-active-ancestor hint. The filesystem implementation uses hash-derived
//! paths only, verifies every file against its name, rejects symlinks, and
//! atomically replaces each persisted file.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use ciborium::value::Value;

use crate::aum::{
    decode_value, encode_value, expect_key, expect_map, expect_uint, Aum, AumHash, MAX_CBOR_BYTES,
};

const MAX_RECORD_BYTES: usize = MAX_CBOR_BYTES + 1024;

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RootIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
fn root_identity(metadata: &fs::Metadata) -> RootIdentity {
    use std::os::unix::fs::MetadataExt;
    RootIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(not(unix))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RootIdentity;

#[cfg(not(unix))]
fn root_identity(_metadata: &fs::Metadata) -> RootIdentity {
    RootIdentity
}

/// Storage failures. Corruption is distinct from absence so callers fail
/// closed instead of treating malformed durable state as missing state.
#[derive(Debug, thiserror::Error)]
pub enum ChonkError {
    #[error("AUM {0} was not found")]
    NotFound(AumHash),
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("corrupt Chonk data at {path}: {reason}")]
    Corrupt { path: PathBuf, reason: String },
    #[error("invalid Chonk root {path}: {reason}")]
    InvalidRoot { path: PathBuf, reason: String },
    #[error("Chonk lock was poisoned")]
    LockPoisoned,
}

impl ChonkError {
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound(_))
    }
}

fn io_error(path: &Path, source: io::Error) -> ChonkError {
    ChonkError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(unix)]
fn open_read_no_follow(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_read_no_follow(path: &Path) -> io::Result<fs::File> {
    fs::OpenOptions::new().read(true).open(path)
}

/// Storage backend for verified AUMs.
///
/// Implementations must be thread-safe. Callers must validate AUMs before
/// `store_verified_aums`; implementations still enforce content integrity.
pub trait Chonk: Send + Sync {
    fn aum(&self, hash: &AumHash) -> Result<Aum, ChonkError>;
    fn child_aums(&self, hash: &AumHash) -> Result<Vec<Aum>, ChonkError>;
    fn heads(&self) -> Result<Vec<Aum>, ChonkError>;
    fn last_active_ancestor(&self) -> Result<Option<AumHash>, ChonkError>;
    fn set_last_active_ancestor(&self, hash: AumHash) -> Result<(), ChonkError>;
    fn store_verified_aums(&self, aums: &[Aum]) -> Result<usize, ChonkError>;
}

#[derive(Default)]
struct MemState {
    aums: HashMap<AumHash, Aum>,
    children: HashMap<AumHash, Vec<AumHash>>,
    last_active: Option<AumHash>,
}

/// Thread-safe in-memory Chonk.
#[derive(Default)]
pub struct MemChonk {
    inner: RwLock<MemState>,
}

impl MemChonk {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Chonk for MemChonk {
    fn aum(&self, hash: &AumHash) -> Result<Aum, ChonkError> {
        self.inner
            .read()
            .map_err(|_| ChonkError::LockPoisoned)?
            .aums
            .get(hash)
            .cloned()
            .ok_or(ChonkError::NotFound(*hash))
    }

    fn child_aums(&self, hash: &AumHash) -> Result<Vec<Aum>, ChonkError> {
        let state = self.inner.read().map_err(|_| ChonkError::LockPoisoned)?;
        Ok(state
            .children
            .get(hash)
            .into_iter()
            .flatten()
            .filter_map(|child| state.aums.get(child).cloned())
            .collect())
    }

    fn heads(&self) -> Result<Vec<Aum>, ChonkError> {
        let state = self.inner.read().map_err(|_| ChonkError::LockPoisoned)?;
        let mut heads: Vec<_> = state
            .aums
            .iter()
            .filter(|(hash, _)| state.children.get(hash).is_none_or(Vec::is_empty))
            .map(|(_, aum)| aum.clone())
            .collect();
        heads.sort_by_key(Aum::hash);
        Ok(heads)
    }

    fn last_active_ancestor(&self) -> Result<Option<AumHash>, ChonkError> {
        Ok(self
            .inner
            .read()
            .map_err(|_| ChonkError::LockPoisoned)?
            .last_active)
    }

    fn set_last_active_ancestor(&self, hash: AumHash) -> Result<(), ChonkError> {
        self.inner
            .write()
            .map_err(|_| ChonkError::LockPoisoned)?
            .last_active = Some(hash);
        Ok(())
    }

    fn store_verified_aums(&self, aums: &[Aum]) -> Result<usize, ChonkError> {
        let mut state = self.inner.write().map_err(|_| ChonkError::LockPoisoned)?;
        let mut inserted = 0;
        for aum in aums {
            let hash = aum.hash();
            if state.aums.contains_key(&hash) {
                continue;
            }
            if let Some(parent) = aum.parent() {
                let children = state.children.entry(parent).or_default();
                if !children.contains(&hash) {
                    children.push(hash);
                }
            }
            state.aums.insert(hash, aum.clone());
            inserted += 1;
        }
        Ok(inserted)
    }
}

/// Atomic file-backed Chonk.
///
/// AUMs are stored in Tailscale's integer-keyed CBOR record envelope at
/// `<root>/<first-two-base32>/<hash>`. The ancestor hint is the raw 32-byte
/// hash at `last_active_ancestor`.
///
/// Writes use same-directory fsync+rename replacement. Each operation checks
/// that the root and hash-prefix are real directories; Unix additionally
/// checks the root device/inode to detect replacement. Previously observed
/// AUMs disappearing is corruption. These checks provide crash durability and
/// fail-closed handling, not integrity against a privileged process racing
/// between individual filesystem syscalls.
pub struct FsChonk {
    root: PathBuf,
    root_identity: RootIdentity,
    observed: Mutex<HashSet<AumHash>>,
    lock: RwLock<()>,
}

impl FsChonk {
    /// Open or create storage rooted at `root`.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, ChonkError> {
        let root = root.as_ref().to_path_buf();
        match fs::symlink_metadata(&root) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(ChonkError::InvalidRoot {
                    path: root,
                    reason: "root must not be a symlink".into(),
                });
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(ChonkError::InvalidRoot {
                    path: root,
                    reason: "root is not a directory".into(),
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir_all(&root).map_err(|error| io_error(&root, error))?;
            }
            Err(error) => return Err(io_error(&root, error)),
        }
        let metadata = fs::symlink_metadata(&root).map_err(|error| io_error(&root, error))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ChonkError::InvalidRoot {
                path: root,
                reason: "created root is not a real directory".into(),
            });
        }
        let root = fs::canonicalize(&root).map_err(|error| io_error(&root, error))?;
        let metadata = fs::symlink_metadata(&root).map_err(|error| io_error(&root, error))?;
        Ok(Self {
            root,
            root_identity: root_identity(&metadata),
            observed: Mutex::new(HashSet::new()),
            lock: RwLock::new(()),
        })
    }

    fn aum_path(&self, hash: &AumHash) -> PathBuf {
        let name = hash.to_string();
        self.root.join(&name[..2]).join(name)
    }

    fn verify_root(&self) -> Result<(), ChonkError> {
        let metadata = fs::symlink_metadata(&self.root).map_err(|error| ChonkError::Corrupt {
            path: self.root.clone(),
            reason: format!("storage root disappeared: {error}"),
        })?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || root_identity(&metadata) != self.root_identity
        {
            return Err(ChonkError::Corrupt {
                path: self.root.clone(),
                reason: "storage root was replaced or is not a real directory".into(),
            });
        }
        Ok(())
    }

    fn checked_read(path: &Path, max_bytes: usize) -> Result<Vec<u8>, ChonkError> {
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                ChonkError::Io {
                    path: path.to_path_buf(),
                    source: error,
                }
            } else {
                io_error(path, error)
            }
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ChonkError::Corrupt {
                path: path.to_path_buf(),
                reason: "expected a regular, non-symlink file".into(),
            });
        }
        let mut file = open_read_no_follow(path).map_err(|error| io_error(path, error))?;
        let opened_metadata = file.metadata().map_err(|error| io_error(path, error))?;
        if !opened_metadata.is_file() || opened_metadata.len() > max_bytes as u64 {
            return Err(ChonkError::Corrupt {
                path: path.to_path_buf(),
                reason: format!(
                    "file is too large or not regular: {} bytes",
                    opened_metadata.len()
                ),
            });
        }
        let mut bytes = Vec::with_capacity(opened_metadata.len() as usize);
        file.by_ref()
            .take(max_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| io_error(path, error))?;
        if bytes.len() > max_bytes {
            return Err(ChonkError::Corrupt {
                path: path.to_path_buf(),
                reason: format!("file grew beyond {max_bytes} bytes while reading"),
            });
        }
        Ok(bytes)
    }

    fn read_aum_unlocked(&self, hash: &AumHash) -> Result<Aum, ChonkError> {
        let path = self.aum_path(hash);
        let bytes = match Self::checked_read(&path, MAX_RECORD_BYTES) {
            Err(ChonkError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                let observed = self.observed.lock().map_err(|_| ChonkError::LockPoisoned)?;
                if observed.contains(hash) {
                    return Err(ChonkError::Corrupt {
                        path,
                        reason: "previously observed AUM disappeared".into(),
                    });
                }
                return Err(ChonkError::NotFound(*hash));
            }
            result => result?,
        };
        let value = decode_value(&bytes).map_err(|error| ChonkError::Corrupt {
            path: path.clone(),
            reason: error.to_string(),
        })?;
        let entries = expect_map(value).map_err(|error| ChonkError::Corrupt {
            path: path.clone(),
            reason: error.to_string(),
        })?;
        let mut aum_value = None;
        let mut purged = false;
        let mut seen = HashSet::new();
        for (key, value) in entries {
            let key = expect_key(&key).map_err(|error| ChonkError::Corrupt {
                path: path.clone(),
                reason: error.to_string(),
            })?;
            if !seen.insert(key) {
                return Err(ChonkError::Corrupt {
                    path,
                    reason: "duplicate record key".into(),
                });
            }
            match key {
                2 => aum_value = Some(value),
                3 => {
                    expect_uint(value).map_err(|error| ChonkError::Corrupt {
                        path: path.clone(),
                        reason: error.to_string(),
                    })?;
                }
                4 => {
                    purged = expect_uint(value).map_err(|error| ChonkError::Corrupt {
                        path: path.clone(),
                        reason: error.to_string(),
                    })? > 0;
                }
                _ => {}
            }
        }
        if purged {
            if self
                .observed
                .lock()
                .map_err(|_| ChonkError::LockPoisoned)?
                .contains(hash)
            {
                return Err(ChonkError::Corrupt {
                    path,
                    reason: "previously observed AUM was marked purged".into(),
                });
            }
            return Err(ChonkError::NotFound(*hash));
        }
        let aum_value = aum_value.ok_or_else(|| ChonkError::Corrupt {
            path: path.clone(),
            reason: "record has no AUM".into(),
        })?;
        if matches!(aum_value, Value::Null) {
            if self
                .observed
                .lock()
                .map_err(|_| ChonkError::LockPoisoned)?
                .contains(hash)
            {
                return Err(ChonkError::Corrupt {
                    path,
                    reason: "previously observed AUM content disappeared".into(),
                });
            }
            return Err(ChonkError::NotFound(*hash));
        }
        let aum = Aum::decode(&encode_value(&aum_value)).map_err(|error| ChonkError::Corrupt {
            path: path.clone(),
            reason: error.to_string(),
        })?;
        let actual = aum.hash();
        if actual != *hash {
            return Err(ChonkError::Corrupt {
                path,
                reason: format!("content hash is {actual}, filename is {hash}"),
            });
        }
        self.observed
            .lock()
            .map_err(|_| ChonkError::LockPoisoned)?
            .insert(*hash);
        Ok(aum)
    }

    fn encode_record(aum: &Aum) -> Vec<u8> {
        let aum_value: Value = ciborium::from_reader(aum.encode().as_slice())
            .expect("an AUM's canonical encoding always decodes");
        let created = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        encode_value(&Value::Map(vec![
            (Value::Integer(2.into()), aum_value),
            (Value::Integer(3.into()), Value::Integer(created.into())),
        ]))
    }

    fn all_hashes_unlocked(&self) -> Result<Vec<AumHash>, ChonkError> {
        self.verify_root()?;
        let mut hashes = Vec::new();
        let prefixes = fs::read_dir(&self.root).map_err(|error| io_error(&self.root, error))?;
        for prefix in prefixes {
            let prefix = prefix.map_err(|error| io_error(&self.root, error))?;
            let file_type = prefix
                .file_type()
                .map_err(|error| io_error(&prefix.path(), error))?;
            let prefix_name = prefix.file_name();
            let prefix_name = prefix_name.to_string_lossy();
            let valid_prefix = prefix_name.len() == 2
                && prefix_name
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte));
            if file_type.is_symlink() {
                return Err(ChonkError::Corrupt {
                    path: prefix.path(),
                    reason: "symlink entry in Chonk root".into(),
                });
            }
            if !file_type.is_dir() {
                if valid_prefix {
                    return Err(ChonkError::Corrupt {
                        path: prefix.path(),
                        reason: "valid AUM prefix is not a directory".into(),
                    });
                }
                continue;
            }
            let entries =
                fs::read_dir(prefix.path()).map_err(|error| io_error(&prefix.path(), error))?;
            if !valid_prefix {
                for entry in entries {
                    let entry = entry.map_err(|error| io_error(&prefix.path(), error))?;
                    if AumHash::from_str(&entry.file_name().to_string_lossy()).is_ok() {
                        return Err(ChonkError::Corrupt {
                            path: entry.path(),
                            reason: "AUM hash file is hidden in a non-prefix directory".into(),
                        });
                    }
                }
                continue;
            }
            for entry in entries {
                let entry = entry.map_err(|error| io_error(&prefix.path(), error))?;
                let name = entry.file_name();
                let name = name.to_string_lossy();
                let Ok(hash) = AumHash::from_str(&name) else {
                    // Atomic-write leftovers and unrelated OS files are ignored.
                    continue;
                };
                if hash.to_string()[..2] != prefix_name {
                    return Err(ChonkError::Corrupt {
                        path: entry.path(),
                        reason: "hash file is in the wrong prefix directory".into(),
                    });
                }
                match self.read_aum_unlocked(&hash) {
                    Ok(_) => hashes.push(hash),
                    Err(error) if error.is_not_found() => {}
                    Err(error) => return Err(error),
                }
            }
        }
        hashes.sort();
        hashes.dedup();
        let current: HashSet<_> = hashes.iter().copied().collect();
        let observed = self.observed.lock().map_err(|_| ChonkError::LockPoisoned)?;
        if let Some(missing) = observed.iter().find(|hash| !current.contains(hash)) {
            return Err(ChonkError::Corrupt {
                path: self.aum_path(missing),
                reason: "previously observed AUM disappeared from storage".into(),
            });
        }
        Ok(hashes)
    }

    fn ensure_prefix_dir(&self, path: &Path) -> Result<(), ChonkError> {
        self.verify_root()?;
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(ChonkError::Corrupt {
                    path: path.to_path_buf(),
                    reason: "AUM prefix is not a real directory".into(),
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(path).map_err(|error| io_error(path, error))?;
            }
            Err(error) => return Err(io_error(path, error)),
        }
        let metadata = fs::symlink_metadata(path).map_err(|error| io_error(path, error))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ChonkError::Corrupt {
                path: path.to_path_buf(),
                reason: "created AUM prefix is not a real directory".into(),
            });
        }
        let canonical = fs::canonicalize(path).map_err(|error| io_error(path, error))?;
        if canonical.parent() != Some(self.root.as_path()) {
            return Err(ChonkError::Corrupt {
                path: path.to_path_buf(),
                reason: "AUM prefix escapes the storage root".into(),
            });
        }
        Ok(())
    }
}

impl Chonk for FsChonk {
    fn aum(&self, hash: &AumHash) -> Result<Aum, ChonkError> {
        let _guard = self.lock.read().map_err(|_| ChonkError::LockPoisoned)?;
        self.verify_root()?;
        self.read_aum_unlocked(hash)
    }

    fn child_aums(&self, hash: &AumHash) -> Result<Vec<Aum>, ChonkError> {
        let _guard = self.lock.read().map_err(|_| ChonkError::LockPoisoned)?;
        let mut children = Vec::new();
        for candidate in self.all_hashes_unlocked()? {
            let aum = self.read_aum_unlocked(&candidate)?;
            if aum.parent() == Some(*hash) {
                children.push(aum);
            }
        }
        children.sort_by_key(Aum::hash);
        Ok(children)
    }

    fn heads(&self) -> Result<Vec<Aum>, ChonkError> {
        let _guard = self.lock.read().map_err(|_| ChonkError::LockPoisoned)?;
        let hashes = self.all_hashes_unlocked()?;
        let mut parents = HashSet::new();
        let mut all = Vec::with_capacity(hashes.len());
        for hash in hashes {
            let aum = self.read_aum_unlocked(&hash)?;
            if let Some(parent) = aum.parent() {
                parents.insert(parent);
            }
            all.push(aum);
        }
        all.retain(|aum| !parents.contains(&aum.hash()));
        all.sort_by_key(Aum::hash);
        Ok(all)
    }

    fn last_active_ancestor(&self) -> Result<Option<AumHash>, ChonkError> {
        let _guard = self.lock.read().map_err(|_| ChonkError::LockPoisoned)?;
        self.verify_root()?;
        let path = self.root.join("last_active_ancestor");
        let bytes = match Self::checked_read(&path, 32) {
            Err(ChonkError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                return Ok(None);
            }
            result => result?,
        };
        AumHash::from_slice(&bytes)
            .map(Some)
            .ok_or_else(|| ChonkError::Corrupt {
                path,
                reason: format!("ancestor hash has length {}, want 32", bytes.len()),
            })
    }

    fn set_last_active_ancestor(&self, hash: AumHash) -> Result<(), ChonkError> {
        let _guard = self.lock.write().map_err(|_| ChonkError::LockPoisoned)?;
        self.verify_root()?;
        let path = self.root.join("last_active_ancestor");
        rustscale_atomicfile::write(&path, hash.as_bytes()).map_err(|error| io_error(&path, error))
    }

    fn store_verified_aums(&self, aums: &[Aum]) -> Result<usize, ChonkError> {
        let _guard = self.lock.write().map_err(|_| ChonkError::LockPoisoned)?;
        let mut inserted = 0;
        for aum in aums {
            let hash = aum.hash();
            let path = self.aum_path(&hash);
            match self.read_aum_unlocked(&hash) {
                Ok(existing) if existing == *aum => continue,
                Ok(_) => {
                    return Err(ChonkError::Corrupt {
                        path,
                        reason: "existing AUM differs despite equal hash".into(),
                    });
                }
                Err(error) if error.is_not_found() => {}
                Err(error) => return Err(error),
            }
            let parent = path.parent().expect("hash path always has a parent");
            self.ensure_prefix_dir(parent)?;
            rustscale_atomicfile::write(&path, &Self::encode_record(aum))
                .map_err(|error| io_error(&path, error))?;
            // Read-after-write catches storage corruption before returning.
            self.read_aum_unlocked(&hash)?;
            inserted += 1;
        }
        Ok(inserted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aum::AumKind;

    fn aum(kind: AumKind, parent: Option<AumHash>) -> Aum {
        Aum {
            message_kind: kind,
            prev_aum_hash: parent.map(|hash| hash.0.to_vec()),
            key: None,
            key_id: None,
            state: None,
            votes: None,
            meta: None,
            signatures: Vec::new(),
        }
    }

    fn exercise(chonk: &dyn Chonk) {
        let parent = aum(AumKind::NoOp, None);
        let child = aum(AumKind::NoOp, Some(parent.hash()));
        assert_eq!(
            chonk
                .store_verified_aums(&[parent.clone(), child.clone()])
                .unwrap(),
            2
        );
        assert_eq!(
            chonk
                .store_verified_aums(std::slice::from_ref(&child))
                .unwrap(),
            0
        );
        assert_eq!(chonk.aum(&parent.hash()).unwrap(), parent);
        assert_eq!(
            chonk.child_aums(&parent.hash()).unwrap(),
            vec![child.clone()]
        );
        assert_eq!(chonk.heads().unwrap(), vec![child]);
    }

    #[test]
    fn memory_contract() {
        exercise(&MemChonk::new());
    }

    #[test]
    fn filesystem_persists_and_reopens() {
        let dir = tempfile::tempdir().unwrap();
        let parent = aum(AumKind::NoOp, None);
        let hash = parent.hash();
        {
            let chonk = FsChonk::open(dir.path()).unwrap();
            exercise(&chonk);
            chonk.set_last_active_ancestor(hash).unwrap();
        }
        let reopened = FsChonk::open(dir.path()).unwrap();
        assert_eq!(reopened.aum(&hash).unwrap(), parent);
        assert_eq!(reopened.last_active_ancestor().unwrap(), Some(hash));
    }

    #[test]
    fn filesystem_rejects_corruption_and_symlink_root() {
        let dir = tempfile::tempdir().unwrap();
        let chonk = FsChonk::open(dir.path()).unwrap();
        let update = aum(AumKind::NoOp, None);
        let hash = update.hash();
        chonk.store_verified_aums(&[update]).unwrap();
        fs::write(chonk.aum_path(&hash), b"not cbor").unwrap();
        assert!(matches!(chonk.aum(&hash), Err(ChonkError::Corrupt { .. })));

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let link = dir.path().join("link");
            symlink(dir.path(), &link).unwrap();
            assert!(matches!(
                FsChonk::open(link),
                Err(ChonkError::InvalidRoot { .. })
            ));
        }
    }

    #[test]
    fn oversized_record_is_rejected_before_reading() {
        let dir = tempfile::tempdir().unwrap();
        let chonk = FsChonk::open(dir.path()).unwrap();
        let update = aum(AumKind::NoOp, None);
        let hash = update.hash();
        chonk.store_verified_aums(&[update]).unwrap();
        fs::write(chonk.aum_path(&hash), vec![0; MAX_RECORD_BYTES + 1]).unwrap();
        assert!(matches!(chonk.aum(&hash), Err(ChonkError::Corrupt { .. })));
    }

    #[test]
    fn disappeared_head_is_corruption_not_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let chonk = FsChonk::open(dir.path()).unwrap();
        let parent = aum(AumKind::NoOp, None);
        let child = aum(AumKind::NoOp, Some(parent.hash()));
        chonk
            .store_verified_aums(&[parent.clone(), child.clone()])
            .unwrap();
        assert_eq!(chonk.heads().unwrap(), vec![child.clone()]);
        fs::remove_file(chonk.aum_path(&child.hash())).unwrap();
        assert!(matches!(chonk.heads(), Err(ChonkError::Corrupt { .. })));
    }

    #[test]
    fn renamed_prefix_cannot_hide_a_head() {
        let dir = tempfile::tempdir().unwrap();
        let chonk = FsChonk::open(dir.path()).unwrap();
        let update = aum(AumKind::NoOp, None);
        let hash = update.hash();
        chonk.store_verified_aums(&[update]).unwrap();
        let prefix = chonk.aum_path(&hash).parent().unwrap().to_path_buf();
        fs::rename(&prefix, dir.path().join("hidden-prefix")).unwrap();
        assert!(matches!(chonk.heads(), Err(ChonkError::Corrupt { .. })));
    }

    #[cfg(unix)]
    #[test]
    fn valid_prefix_symlink_and_hash_symlink_fail_closed() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let chonk = FsChonk::open(dir.path()).unwrap();
        let update = aum(AumKind::NoOp, None);
        let hash = update.hash();
        chonk.store_verified_aums(&[update]).unwrap();
        let path = chonk.aum_path(&hash);
        let prefix = path.parent().unwrap().to_path_buf();

        fs::remove_file(&path).unwrap();
        symlink(dir.path().join("missing-target"), &path).unwrap();
        assert!(matches!(chonk.aum(&hash), Err(ChonkError::Corrupt { .. })));
        fs::remove_file(&path).unwrap();
        fs::remove_dir(&prefix).unwrap();
        let target = dir.path().join("elsewhere");
        fs::create_dir(&target).unwrap();
        symlink(&target, &prefix).unwrap();
        assert!(matches!(chonk.heads(), Err(ChonkError::Corrupt { .. })));
    }

    #[cfg(unix)]
    #[test]
    fn root_replacement_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        let old_root = dir.path().join("old-root");
        let chonk = FsChonk::open(&root).unwrap();
        fs::rename(&root, &old_root).unwrap();
        fs::create_dir(&root).unwrap();
        assert!(matches!(chonk.heads(), Err(ChonkError::Corrupt { .. })));
    }

    #[test]
    fn corrupt_ancestor_is_not_treated_as_absent() {
        let dir = tempfile::tempdir().unwrap();
        let chonk = FsChonk::open(dir.path()).unwrap();
        fs::write(dir.path().join("last_active_ancestor"), b"short").unwrap();
        assert!(matches!(
            chonk.last_active_ancestor(),
            Err(ChonkError::Corrupt { .. })
        ));
    }
}
