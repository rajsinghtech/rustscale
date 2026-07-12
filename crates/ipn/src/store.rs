//! State persistence — a Rust port of Go's `ipn/store` package.
//!
//! Provides the [`Store`] trait (the equivalent of Go's `ipn.StateStore`
//! interface) plus two reference implementations:
//!
//! - [`MemStore`] — in-memory store backed by a `HashMap` (Go's
//!   `ipn/store/mem`).
//! - [`FileStore`] — on-disk store that persists each key as a file under a
//!   base directory (a simplified equivalent of Go's `ipn/store.FileStore`,
//!   which uses a single JSON file; here each key maps to its own file).
//!
//! Unlike the Go interface, `read_state` returns `Ok(None)` for a missing key
//! rather than a dedicated `ErrStateNotExist`, and `write_state` accepts an
//! empty slice to delete a key (matching Go's nil-bytes deletion semantics).

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::Mutex;

/// Persistent state store, mirroring Go's `ipn.StateStore` interface.
///
/// Keys are arbitrary strings; values are opaque byte blobs. Implementations
/// must be safe to share across threads (`Send + Sync`).
pub trait Store: Send + Sync {
    /// Read the value for `key`, or `Ok(None)` if it is not present.
    fn read_state(&self, key: &str) -> io::Result<Option<Vec<u8>>>;

    /// Write `data` for `key`. Writing an empty slice deletes the key, if
    /// present. Overwriting an existing key with new data replaces it.
    fn write_state(&self, key: &str, data: &[u8]) -> io::Result<()>;
}

/// In-memory [`Store`] backed by a `HashMap`, mirroring Go's
/// `ipn/store/mem.Store`.
#[derive(Default)]
pub struct MemStore {
    cache: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemStore {
    /// Create a new empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Store for MemStore {
    fn read_state(&self, key: &str) -> io::Result<Option<Vec<u8>>> {
        let cache = self.cache.lock().expect("mem store mutex poisoned");
        Ok(cache.get(key).cloned())
    }

    fn write_state(&self, key: &str, data: &[u8]) -> io::Result<()> {
        let mut cache = self.cache.lock().expect("mem store mutex poisoned");
        if data.is_empty() {
            cache.remove(key);
        } else {
            cache.insert(key.to_owned(), data.to_vec());
        }
        Ok(())
    }
}

/// On-disk [`Store`] that persists each key as a file under a base directory.
///
/// For a key `k`, the value lives at `base/k`. Reads of a missing file return
/// `Ok(None)`. Writes create the base directory if needed and overwrite any
/// existing file.
pub struct FileStore {
    base: PathBuf,
}

impl FileStore {
    /// Create a new file store rooted at `base`. The directory is created on
    /// the first write if it does not already exist.
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self { base: base.into() }
    }

    fn path_for(&self, key: &str) -> PathBuf {
        self.base.join(key)
    }
}

impl Store for FileStore {
    fn read_state(&self, key: &str) -> io::Result<Option<Vec<u8>>> {
        let path = self.path_for(key);
        match std::fs::read(&path) {
            Ok(data) => Ok(Some(data)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn write_state(&self, key: &str, data: &[u8]) -> io::Result<()> {
        let path = self.path_for(key);
        if data.is_empty() {
            match std::fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e),
            }
        } else {
            std::fs::create_dir_all(&self.base)?;
            std::fs::write(&path, data)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FileStore, MemStore, Store};
    use std::path::Path;

    fn assert_store_roundtrip<S: Store>(store: &S) {
        assert_eq!(store.read_state("missing").unwrap(), None);

        store.write_state("foo", b"bar").unwrap();
        assert_eq!(store.read_state("foo").unwrap(), Some(b"bar".to_vec()));

        store.write_state("foo", b"baz").unwrap();
        assert_eq!(store.read_state("foo").unwrap(), Some(b"baz".to_vec()));

        store.write_state("foo", b"").unwrap();
        assert_eq!(store.read_state("foo").unwrap(), None);
    }

    #[test]
    fn mem_store_basic() {
        let store = MemStore::new();
        assert_store_roundtrip(&store);
    }

    #[test]
    fn mem_store_independent_keys() {
        let store = MemStore::new();
        store.write_state("a", b"1").unwrap();
        store.write_state("b", b"2").unwrap();
        assert_eq!(store.read_state("a").unwrap(), Some(b"1".to_vec()));
        assert_eq!(store.read_state("b").unwrap(), Some(b"2".to_vec()));
        store.write_state("a", b"").unwrap();
        assert_eq!(store.read_state("a").unwrap(), None);
        assert_eq!(store.read_state("b").unwrap(), Some(b"2".to_vec()));
    }

    #[test]
    fn mem_store_shared_across_threads() {
        use std::sync::Arc;
        use std::thread;

        let store = Arc::new(MemStore::new());
        let s = store.clone();
        let h = thread::spawn(move || {
            s.write_state("k", b"v").unwrap();
        });
        h.join().unwrap();
        assert_eq!(store.read_state("k").unwrap(), Some(b"v".to_vec()));
    }

    #[test]
    fn file_store_basic() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileStore::new(tmp.path());
        assert_store_roundtrip(&store);
    }

    #[test]
    fn file_store_persists_across_instances() {
        let tmp = tempfile::tempdir().unwrap();
        let key = "persisted";
        {
            let store = FileStore::new(tmp.path());
            store.write_state(key, b"hello").unwrap();
            assert!(Path::new(tmp.path()).join(key).exists());
        }
        let store = FileStore::new(tmp.path());
        assert_eq!(store.read_state(key).unwrap(), Some(b"hello".to_vec()));
    }

    #[test]
    fn file_store_creates_base_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("nested").join("store");
        let store = FileStore::new(&base);
        store.write_state("k", b"v").unwrap();
        assert!(base.is_dir());
        assert_eq!(store.read_state("k").unwrap(), Some(b"v".to_vec()));
    }

    #[test]
    fn file_store_missing_key_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FileStore::new(tmp.path());
        assert_eq!(store.read_state("nope").unwrap(), None);
    }
}
