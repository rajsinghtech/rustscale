//! Atomic file writes with fsync and rename.
//!
//! Ports Go's `tailscale.com/atomicfile` package. Writes data to a temp file
//! in the same directory as the target, fsyncs the file, renames it into
//! place, then fsyncs the parent directory for crash safety. On any error the
//! temp file is cleaned up.

#![forbid(unsafe_code)]

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    format!("{pid:x}{nanos:x}{n:x}")
}

/// Set owner-only (0o600) permissions on Unix; no-op elsewhere.
#[cfg(unix)]
fn set_owner_only_perms(file: &mut fs::File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    let mode = file.metadata()?.permissions().mode() & 0o777;
    if mode != 0o600 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("temporary file mode is {mode:o}, want 600"),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn set_owner_only_perms(_file: &mut fs::File) -> io::Result<()> {
    Ok(())
}

/// Fsync the parent directory of `path` so the rename is durable (Unix only;
/// silently ignored on platforms where directory fsync is unavailable).
fn sync_parent(path: &Path) {
    if let Some(parent) = path.parent() {
        if let Ok(dir_file) = fs::File::open(parent) {
            let _ = dir_file.sync_all();
        }
    }
}

/// Create a uniquely-named temp file in `dir` prefixed with `base`.
///
/// Retries on name collisions (extremely unlikely given the pid + nanosecond
/// + counter suffix). Returns the open file handle and its path.
fn create_temp(dir: &Path, base: &str) -> io::Result<(fs::File, PathBuf)> {
    for _ in 0..16 {
        let tmp = dir.join(format!("{base}.tmp.{}", unique_suffix()));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        // The creation mode closes the pre-chmod confidentiality window: even
        // if the process crashes immediately after open(2), no group/other
        // read bits were ever present. The explicit permission update below
        // also normalizes unusual umasks/filesystem behavior before any write.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        match options.open(&tmp) {
            Ok(mut file) => {
                if let Err(error) = set_owner_only_perms(&mut file) {
                    drop(file);
                    let _ = fs::remove_file(&tmp);
                    return Err(error);
                }
                return Ok((file, tmp));
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not create unique temp file after 16 attempts",
    ))
}

/// Write `data` atomically to `path`.
///
/// Writes to a temp file in the same directory, fsyncs it, renames it into
/// place, then fsyncs the parent directory. On any error the temp file is
/// removed. If `path` already exists and is not a regular file, returns an
/// error (matching Go's atomicfile behavior).
pub fn write(path: &Path, data: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let base = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?
        .to_string_lossy()
        .into_owned();

    // If the target exists it must be a regular file (not a dir, symlink, etc).
    if let Ok(meta) = fs::metadata(path) {
        if !meta.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} already exists and is not a regular file",
                    path.display()
                ),
            ));
        }
    }

    let (mut file, tmp_path) = create_temp(dir, &base)?;

    let result = (|| -> io::Result<()> {
        file.write_all(data)?;
        set_owner_only_perms(&mut file)?;
        file.sync_all()?;
        // Close the file before rename (required on Windows; harmless on Unix).
        drop(file);
        fs::rename(&tmp_path, path)?;
        sync_parent(path);
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result
}

/// Write a string atomically to `path`. Convenience wrapper around [`write`].
pub fn write_string(path: &Path, s: &str) -> io::Result<()> {
    write(path, s.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let mut p = std::env::temp_dir();
            p.push(format!("rustscale-atomicfile-test-{}", unique_suffix()));
            fs::create_dir_all(&p).unwrap();
            Self(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    impl std::ops::Deref for TempDir {
        type Target = Path;
        fn deref(&self) -> &Path {
            &self.0
        }
    }

    #[cfg(unix)]
    #[test]
    fn temp_file_is_owner_only_before_any_write() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = TempDir::new();
        let (file, path) = create_temp(&dir, "secret").unwrap();
        let metadata = file.metadata().unwrap();
        assert_eq!(metadata.len(), 0, "test must inspect the pre-write file");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        drop(file);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn write_and_read_back() {
        let dir = TempDir::new();
        let path = dir.join("state.json");
        write(&path, b"hello world").unwrap();
        let content = fs::read(&path).unwrap();
        assert_eq!(content, b"hello world");
    }

    #[test]
    fn write_string_roundtrip() {
        let dir = TempDir::new();
        let path = dir.join("config.json");
        write_string(&path, "{\"key\":\"value\"}").unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content, "{\"key\":\"value\"}");
    }

    #[test]
    fn overwrite_existing_file() {
        let dir = TempDir::new();
        let path = dir.join("state.json");
        write(&path, b"old").unwrap();
        write(&path, b"new content").unwrap();
        let content = fs::read(&path).unwrap();
        assert_eq!(content, b"new content");
    }

    #[test]
    fn no_temp_files_remaining() {
        let dir = TempDir::new();
        let path = dir.join("state.json");
        write(&path, b"data").unwrap();
        for entry in fs::read_dir(&*dir).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().to_string();
            assert!(!name.contains(".tmp."), "temp file left behind: {name}");
        }
    }

    #[test]
    fn temp_file_cleaned_on_error() {
        let dir = TempDir::new();
        let nonexistent = dir.join("does-not-exist");
        let path = nonexistent.join("state.json");
        let result = write(&path, b"data");
        assert!(result.is_err());
        // The non-existent directory should not have been created.
        assert!(!nonexistent.exists());
    }

    #[test]
    fn reject_non_regular_file() {
        let dir = TempDir::new();
        let path = dir.join("subdir");
        fs::create_dir(&path).unwrap();
        let result = write(&path, b"data");
        assert!(result.is_err());
    }

    #[test]
    fn empty_file() {
        let dir = TempDir::new();
        let path = dir.join("empty.json");
        write(&path, b"").unwrap();
        let content = fs::read(&path).unwrap();
        assert!(content.is_empty());
    }

    #[test]
    fn large_file() {
        let dir = TempDir::new();
        let path = dir.join("big.bin");
        let data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
        write(&path, &data).unwrap();
        let content = fs::read(&path).unwrap();
        assert_eq!(content, data);
    }
}
