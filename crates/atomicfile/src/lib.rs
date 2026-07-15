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

/// Fsync the parent directory of `path` so a rename or permission repair is
/// durable. Failure is never ignored: callers use this for key material.
#[cfg(unix)]
fn sync_parent(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> io::Result<()> {
    // Private writes fail closed before reaching this path. Generic atomic
    // writes preserve existing Windows behavior where directories cannot be
    // opened for fsync through std::fs.
    Ok(())
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

    // Inspect the directory entry itself. `metadata` follows symlinks and
    // would permit replacing a link that happened to target a regular file.
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() || !meta.is_file() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} already exists and is not a regular, non-symlink file",
                    path.display()
                ),
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let (mut file, tmp_path) = create_temp(dir, &base)?;

    let result = (|| -> io::Result<()> {
        file.write_all(data)?;
        set_owner_only_perms(&mut file)?;
        file.sync_all()?;
        // Close the file before rename (required on Windows; harmless on Unix).
        drop(file);
        fs::rename(&tmp_path, path)?;
        sync_parent(path)
    })();

    if result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    result
}

/// Create or repair an owner-only directory used for private key material.
/// Existing symlinks, non-directories, and directories owned by another user
/// are rejected. Windows fails closed until an owner-only ACL implementation
/// is available.
#[cfg(unix)]
pub fn ensure_private_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{} is not a real directory", path.display()),
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "private directory has no parent",
                )
            })?;
            if !parent.exists() {
                ensure_private_dir(parent)?;
            }
            use std::os::unix::fs::DirBuilderExt as _;
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700).create(path)?;
            sync_parent(path)?;
        }
        Err(error) => return Err(error),
    }

    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is not a real directory", path.display()),
        ));
    }
    let current_uid = rustix::process::getuid().as_raw();
    if metadata.uid() != current_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is not owned by the current user", path.display()),
        ));
    }
    if metadata.permissions().mode() & 0o1000 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing to repurpose sticky shared directory {}",
                path.display()
            ),
        ));
    }
    if metadata.permissions().mode() & 0o777 != 0o700 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        fs::File::open(path)?.sync_all()?;
        sync_parent(path)?;
    }
    let repaired = fs::symlink_metadata(path)?;
    if repaired.permissions().mode() & 0o777 != 0o700 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} mode is not owner-only", path.display()),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn ensure_private_dir(_path: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "owner-only private state ACLs are not implemented on this platform",
    ))
}

/// Atomically persist private data after validating its directory and target.
pub fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "private file has no parent"))?;
    ensure_private_dir(parent)?;
    validate_private_target(path, true)?;
    write(path, data)?;
    validate_private_target(path, false)?;
    Ok(())
}

/// Read private data only from an owner-only regular file. Legacy Unix mode
/// bits are repaired to 0600 before bytes are returned.
pub fn read_private(path: &Path) -> io::Result<Vec<u8>> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "private file has no parent"))?;
    ensure_private_dir(parent)?;
    validate_private_target(path, false)?;
    fs::read(path)
}

/// Durably remove an owner-only regular private file.
pub fn remove_private(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "private file has no parent"))?;
    ensure_private_dir(parent)?;
    validate_private_target(path, false)?;
    fs::remove_file(path)?;
    sync_parent(path)
}

#[cfg(unix)]
fn validate_private_target(path: &Path, allow_missing: bool) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if allow_missing && error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is not a regular, non-symlink file", path.display()),
        ));
    }
    if metadata.uid() != rustix::process::getuid().as_raw() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is not owned by the current user", path.display()),
        ));
    }
    if metadata.permissions().mode() & 0o777 != 0o600 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        fs::File::open(path)?.sync_all()?;
        sync_parent(path)?;
    }
    let repaired = fs::symlink_metadata(path)?;
    if repaired.permissions().mode() & 0o777 != 0o600 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} mode is not owner-only", path.display()),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_target(_path: &Path, _allow_missing: bool) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "owner-only private state ACLs are not implemented on this platform",
    ))
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

    #[cfg(unix)]
    #[test]
    fn private_write_repairs_modes_and_rejects_symlink_target() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let root = TempDir::new();
        let private = root.join("private");
        fs::create_dir(&private).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o755)).unwrap();
        let path = private.join("state.json");
        fs::write(&path, b"legacy").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        write_private(&path, b"secret").unwrap();
        assert_eq!(
            fs::metadata(&private).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(read_private(&path).unwrap(), b"secret");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        fs::remove_file(&path).unwrap();
        let target = private.join("target");
        fs::write(&target, b"target").unwrap();
        symlink(&target, &path).unwrap();
        assert!(write_private(&path, b"replacement").is_err());
        assert_eq!(fs::read(&target).unwrap(), b"target");
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
