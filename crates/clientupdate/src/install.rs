use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use wait_timeout::ChildExt;

use crate::archive::BinaryPayloads;
use crate::{CommandOutput, CommandSpec, InstallMethod, OperatingSystem, Platform, UpdateError};

pub(crate) const RECEIPT_NAME: &str = ".rustscale-install-receipt-v1";
const RECEIPT_MAX_BYTES: usize = 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const COMMAND_OUTPUT_LIMIT: usize = 64 * 1024;

pub trait CommandRunner: Send + Sync {
    fn run(&self, command: &CommandSpec) -> Result<CommandOutput, UpdateError>;
}

#[derive(Default)]
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, command: &CommandSpec) -> Result<CommandOutput, UpdateError> {
        if !Path::new(&command.program).is_absolute() {
            return Err(UpdateError::Command(format!(
                "refusing non-absolute command path {:?}",
                command.program
            )));
        }
        let mut stdout = tempfile::tempfile()
            .map_err(|error| UpdateError::Command(format!("temporary stdout: {error}")))?;
        let mut stderr = tempfile::tempfile()
            .map_err(|error| UpdateError::Command(format!("temporary stderr: {error}")))?;
        let mut child = Command::new(&command.program)
            .args(&command.args)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout.try_clone().map_err(|error| {
                UpdateError::Command(format!("temporary stdout clone: {error}"))
            })?))
            .stderr(Stdio::from(stderr.try_clone().map_err(|error| {
                UpdateError::Command(format!("temporary stderr clone: {error}"))
            })?))
            .spawn()
            .map_err(|error| UpdateError::Command(format!("{}: {error}", command.program)))?;
        let status = if let Some(status) = child
            .wait_timeout(COMMAND_TIMEOUT)
            .map_err(|error| UpdateError::Command(format!("wait failed: {error}")))?
        {
            status
        } else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(UpdateError::Command(format!(
                "{} timed out after {} seconds",
                command.program,
                COMMAND_TIMEOUT.as_secs()
            )));
        };
        let stdout = read_command_output(&mut stdout)?;
        let stderr = read_command_output(&mut stderr)?;
        if !status.success() {
            return Err(UpdateError::Command(format!(
                "{} {:?} failed with {status}: {}",
                command.program,
                command.args,
                String::from_utf8_lossy(&stderr).trim()
            )));
        }
        Ok(CommandOutput { stdout, stderr })
    }
}

fn read_command_output(file: &mut fs::File) -> Result<Vec<u8>, UpdateError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| UpdateError::Command(format!("seek command output: {error}")))?;
    let mut bytes = Vec::new();
    file.take((COMMAND_OUTPUT_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| UpdateError::Command(format!("read command output: {error}")))?;
    if bytes.len() > COMMAND_OUTPUT_LIMIT {
        return Err(UpdateError::Command(
            "command output exceeded 64 KiB".into(),
        ));
    }
    Ok(bytes)
}

pub trait FileSystem: Send + Sync {
    fn is_regular_file(&self, path: &Path) -> bool;
    fn is_symlink(&self, path: &Path) -> bool;
    fn create_private_dir(&self, path: &Path) -> Result<(), UpdateError>;
    fn read_limited(&self, path: &Path, max_size: usize) -> Result<Vec<u8>, UpdateError>;
    fn write_new(&self, path: &Path, data: &[u8], mode: u32) -> Result<(), UpdateError>;
    fn copy(&self, from: &Path, to: &Path) -> Result<(), UpdateError>;
    fn mode(&self, path: &Path) -> Result<u32, UpdateError>;
    fn set_mode(&self, path: &Path, mode: u32) -> Result<(), UpdateError>;
    /// Perform only the rename mutation. Durability is a separate operation.
    fn rename(&self, from: &Path, to: &Path) -> Result<(), UpdateError>;
    fn sync_file(&self, path: &Path) -> Result<(), UpdateError>;
    fn sync_dir(&self, path: &Path) -> Result<(), UpdateError>;
    fn remove_file(&self, path: &Path) -> Result<(), UpdateError>;
    fn remove_dir_all(&self, path: &Path) -> Result<(), UpdateError>;
}

#[derive(Default)]
pub struct SystemFileSystem;

fn fs_error(operation: &str, path: &Path, error: std::io::Error) -> UpdateError {
    UpdateError::FileSystem(format!("{operation} {}: {error}", path.display()))
}

impl FileSystem for SystemFileSystem {
    fn is_regular_file(&self, path: &Path) -> bool {
        fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_file())
    }

    fn is_symlink(&self, path: &Path) -> bool {
        fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink())
    }

    fn create_private_dir(&self, path: &Path) -> Result<(), UpdateError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            builder
                .create(path)
                .map_err(|error| fs_error("create", path, error))?;
        }
        #[cfg(not(unix))]
        fs::create_dir(path).map_err(|error| fs_error("create", path, error))?;
        self.sync_dir(path)
    }

    fn read_limited(&self, path: &Path, max_size: usize) -> Result<Vec<u8>, UpdateError> {
        let metadata = fs::symlink_metadata(path).map_err(|error| fs_error("stat", path, error))?;
        if !metadata.file_type().is_file() || metadata.len() > max_size as u64 {
            return Err(UpdateError::FileSystem(format!(
                "{} is not a regular file within the {max_size}-byte limit",
                path.display()
            )));
        }
        fs::read(path).map_err(|error| fs_error("read", path, error))
    }

    fn write_new(&self, path: &Path, data: &[u8], mode: u32) -> Result<(), UpdateError> {
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|error| fs_error("create", path, error))?;
        file.write_all(data)
            .map_err(|error| fs_error("write", path, error))?;
        self.set_mode(path, mode)?;
        file.sync_all()
            .map_err(|error| fs_error("sync", path, error))
    }

    fn copy(&self, from: &Path, to: &Path) -> Result<(), UpdateError> {
        fs::copy(from, to).map_err(|error| fs_error("copy to", to, error))?;
        self.sync_file(to)
    }

    fn mode(&self, path: &Path) -> Result<u32, UpdateError> {
        let permissions = fs::metadata(path)
            .map_err(|error| fs_error("stat", path, error))?
            .permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            Ok(permissions.mode())
        }
        #[cfg(not(unix))]
        {
            Ok(if permissions.readonly() { 0o555 } else { 0o755 })
        }
    }

    fn set_mode(&self, path: &Path, mode: u32) -> Result<(), UpdateError> {
        #[cfg(unix)]
        let permissions = {
            use std::os::unix::fs::PermissionsExt;
            fs::Permissions::from_mode(mode)
        };
        #[cfg(not(unix))]
        let permissions = {
            let mut permissions = fs::metadata(path)
                .map_err(|error| fs_error("stat", path, error))?
                .permissions();
            permissions.set_readonly(mode & 0o200 == 0);
            permissions
        };
        fs::set_permissions(path, permissions).map_err(|error| fs_error("chmod", path, error))
    }

    fn rename(&self, from: &Path, to: &Path) -> Result<(), UpdateError> {
        fs::rename(from, to).map_err(|error| fs_error("rename to", to, error))
    }

    fn sync_file(&self, path: &Path) -> Result<(), UpdateError> {
        fs::File::open(path)
            .and_then(|file| file.sync_all())
            .map_err(|error| fs_error("sync", path, error))
    }

    fn sync_dir(&self, path: &Path) -> Result<(), UpdateError> {
        fs::File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| fs_error("sync directory", path, error))
    }

    fn remove_file(&self, path: &Path) -> Result<(), UpdateError> {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(fs_error("remove", path, error)),
        }
    }

    fn remove_dir_all(&self, path: &Path) -> Result<(), UpdateError> {
        match fs::remove_dir_all(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(fs_error("remove", path, error)),
        }
    }
}

pub fn detect_install_method(
    executable: &Path,
    platform: Platform,
    filesystem: &dyn FileSystem,
) -> InstallMethod {
    if platform.os == OperatingSystem::Windows {
        return unsupported("in-place Windows updates are not safe while rustscale.exe is running");
    }

    if let Some(command) = homebrew_plan(executable) {
        return InstallMethod::Homebrew { command };
    }
    if filesystem.is_symlink(executable) {
        return unsupported("the rustscale executable is a symlink owned by an unknown installer");
    }
    let Some(directory) = executable.parent() else {
        return unsupported("cannot determine the RustScale installation directory");
    };
    if directory.file_name().and_then(|name| name.to_str()) != Some("bin") {
        return unsupported("scripts/install.sh ownership requires a bin installation directory");
    }
    if executable.file_name().and_then(|name| name.to_str()) != Some("rustscale") {
        return unsupported("the running executable is not the installed rustscale binary");
    }
    if executable
        .as_os_str()
        .to_str()
        .is_none_or(|path| path.contains(['\n', '\r']))
    {
        return unsupported("the installation path contains unsupported characters");
    }

    let rustscale = directory.join("rustscale");
    let rustscaled = directory.join("rustscaled");
    let receipt = directory.join(RECEIPT_NAME);
    match validate_receipt(filesystem, &rustscale, &rustscaled, &receipt) {
        Ok(()) => InstallMethod::Archive {
            rustscale,
            rustscaled,
            receipt,
        },
        Err(error) => unsupported(format!(
            "archive updates require an intact scripts/install.sh ownership receipt: {error}"
        )),
    }
}

fn homebrew_plan(executable: &Path) -> Option<CommandSpec> {
    for (prefix, brew) in [
        ("/opt/homebrew", "/opt/homebrew/bin/brew"),
        ("/usr/local", "/usr/local/bin/brew"),
    ] {
        let cellar = Path::new(prefix).join("Cellar/rustscale");
        let Ok(relative) = executable.strip_prefix(&cellar) else {
            continue;
        };
        let components: Vec<_> = relative.components().collect();
        if components.len() == 3
            && components[1].as_os_str() == "bin"
            && components[2].as_os_str() == "rustscale"
            && components[0]
                .as_os_str()
                .to_str()
                .and_then(|version| semver::Version::parse(version).ok())
                .is_some()
        {
            return Some(CommandSpec {
                program: brew.into(),
                args: vec![
                    "upgrade".into(),
                    "--formula".into(),
                    "rajsinghtech/tap/rustscale".into(),
                ],
            });
        }
    }
    None
}

fn unsupported(reason: impl Into<String>) -> InstallMethod {
    InstallMethod::Unsupported {
        reason: reason.into(),
    }
}

#[derive(Debug)]
struct Receipt {
    rustscale_sha256: String,
    rustscaled_sha256: String,
}

fn validate_receipt(
    filesystem: &dyn FileSystem,
    rustscale: &Path,
    rustscaled: &Path,
    receipt_path: &Path,
) -> Result<(), UpdateError> {
    if !filesystem.is_regular_file(rustscale)
        || !filesystem.is_regular_file(rustscaled)
        || filesystem.is_symlink(rustscale)
        || filesystem.is_symlink(rustscaled)
        || !filesystem.is_regular_file(receipt_path)
        || filesystem.is_symlink(receipt_path)
    {
        return Err(UpdateError::Unsupported(
            "binaries and receipt must be regular, non-symlink files".into(),
        ));
    }
    let receipt = parse_receipt(&filesystem.read_limited(receipt_path, RECEIPT_MAX_BYTES)?)?;
    let cli = filesystem.read_limited(rustscale, crate::archive::MAX_ARCHIVE_BYTES)?;
    let daemon = filesystem.read_limited(rustscaled, crate::archive::MAX_ARCHIVE_BYTES)?;
    if sha256(&cli) != receipt.rustscale_sha256 || sha256(&daemon) != receipt.rustscaled_sha256 {
        return Err(UpdateError::Unsupported(
            "receipt hashes do not match the installed binaries".into(),
        ));
    }
    Ok(())
}

fn parse_receipt(bytes: &[u8]) -> Result<Receipt, UpdateError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| UpdateError::Unsupported(format!("receipt is not UTF-8: {error}")))?;
    let lines: Vec<_> = text.lines().collect();
    if lines.len() != 4
        || lines[0] != "rustscale-install-receipt-v1"
        || lines[1] != "installer=scripts/install.sh"
        || !lines[2].starts_with("rustscale_sha256=")
        || !lines[3].starts_with("rustscaled_sha256=")
    {
        return Err(UpdateError::Unsupported(
            "receipt has an unknown or malformed format".into(),
        ));
    }
    let rustscale_sha256 = lines[2]["rustscale_sha256=".len()..].to_owned();
    let rustscaled_sha256 = lines[3]["rustscaled_sha256=".len()..].to_owned();
    if !valid_digest(&rustscale_sha256) || !valid_digest(&rustscaled_sha256) {
        return Err(UpdateError::Unsupported(
            "receipt contains an invalid SHA-256 digest".into(),
        ));
    }
    Ok(Receipt {
        rustscale_sha256,
        rustscaled_sha256,
    })
}

fn receipt_bytes(rustscale: &[u8], rustscaled: &[u8]) -> Vec<u8> {
    format!(
        "rustscale-install-receipt-v1\ninstaller=scripts/install.sh\nrustscale_sha256={}\nrustscaled_sha256={}\n",
        sha256(rustscale),
        sha256(rustscaled)
    )
    .into_bytes()
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn apply_archive_transaction(
    filesystem: &dyn FileSystem,
    commands: &dyn CommandRunner,
    payloads: &BinaryPayloads,
    target_version: &str,
    rustscale: &Path,
    rustscaled: &Path,
    receipt: &Path,
) -> Result<(), UpdateError> {
    validate_receipt(filesystem, rustscale, rustscaled, receipt)?;
    let parent = rustscale
        .parent()
        .ok_or_else(|| UpdateError::Unsupported("binary has no parent directory".into()))?;
    if rustscaled.parent() != Some(parent)
        || receipt.parent() != Some(parent)
        || parent.file_name().and_then(|name| name.to_str()) != Some("bin")
        || rustscale.file_name().and_then(|name| name.to_str()) != Some("rustscale")
        || rustscaled.file_name().and_then(|name| name.to_str()) != Some("rustscaled")
        || receipt.file_name().and_then(|name| name.to_str()) != Some(RECEIPT_NAME)
    {
        return Err(UpdateError::Unsupported(
            "update targets do not match the scripts/install.sh bin layout".into(),
        ));
    }

    let work = parent.join(format!(".rustscale-update-{}", unique_token()));
    filesystem.create_private_dir(&work)?;
    let result = transaction_in_workdir(
        filesystem,
        commands,
        payloads,
        target_version,
        [rustscale, rustscaled, receipt],
        &work,
    );
    if !matches!(&result, Err(UpdateError::RollbackFailed { .. })) {
        let _ = filesystem.remove_dir_all(&work);
        let _ = filesystem.sync_dir(parent);
    }
    result
}

fn transaction_in_workdir(
    filesystem: &dyn FileSystem,
    commands: &dyn CommandRunner,
    payloads: &BinaryPayloads,
    target_version: &str,
    targets: [&Path; 3],
    work: &Path,
) -> Result<(), UpdateError> {
    let new_receipt = receipt_bytes(&payloads.rustscale, &payloads.rustscaled);
    let data = [
        &payloads.rustscale[..],
        &payloads.rustscaled[..],
        &new_receipt[..],
    ];
    let new_paths = [
        work.join("rustscale.new"),
        work.join("rustscaled.new"),
        work.join("receipt.new"),
    ];
    let backups = [
        work.join("rustscale.backup"),
        work.join("rustscaled.backup"),
        work.join("receipt.backup"),
    ];
    let mut modes = [0_u32; 3];

    for index in 0..3 {
        if !filesystem.is_regular_file(targets[index]) || filesystem.is_symlink(targets[index]) {
            return Err(UpdateError::Unsupported(format!(
                "{} changed after planning; refusing update",
                targets[index].display()
            )));
        }
        modes[index] = filesystem.mode(targets[index])?;
        filesystem.copy(targets[index], &backups[index])?;
        filesystem.set_mode(&backups[index], modes[index])?;
        filesystem.sync_file(&backups[index])?;
        filesystem.write_new(&new_paths[index], data[index], modes[index])?;
    }

    verify_binary_versions(commands, &new_paths[0], &new_paths[1], target_version)?;
    let journal = work.join("journal-v1");
    filesystem.write_new(
        &journal,
        b"rustscale-update-journal-v1\nbackups=rustscale.backup,rustscaled.backup,receipt.backup\ntargets=rustscale,rustscaled,.rustscale-install-receipt-v1\n",
        0o600,
    )?;
    filesystem.sync_dir(work)?;
    let parent = targets[0]
        .parent()
        .ok_or_else(|| UpdateError::Unsupported("update target has no parent".into()))?;
    filesystem.sync_dir(parent)?;

    let mut committed = [false; 3];
    for index in 0..3 {
        if let Err(error) = filesystem.rename(&new_paths[index], targets[index]) {
            return fail_after_mutation(
                filesystem, error, targets, &backups, &modes, committed, work,
            );
        }
        committed[index] = true;
        if let Err(error) = filesystem.sync_dir(parent) {
            return fail_after_mutation(
                filesystem, error, targets, &backups, &modes, committed, work,
            );
        }
    }

    if let Err(error) = verify_binary_versions(commands, targets[0], targets[1], target_version) {
        return fail_after_mutation(
            filesystem, error, targets, &backups, &modes, committed, work,
        );
    }
    if let Err(error) = validate_receipt(filesystem, targets[0], targets[1], targets[2]) {
        return fail_after_mutation(
            filesystem, error, targets, &backups, &modes, committed, work,
        );
    }
    Ok(())
}

fn fail_after_mutation(
    filesystem: &dyn FileSystem,
    cause: UpdateError,
    targets: [&Path; 3],
    backups: &[PathBuf; 3],
    modes: &[u32; 3],
    committed: [bool; 3],
    work: &Path,
) -> Result<(), UpdateError> {
    if !committed.iter().any(|value| *value) {
        return Err(cause);
    }
    let mut rollback_errors = Vec::new();
    for index in (0..3).rev().filter(|index| committed[*index]) {
        let staged = work.join(format!("rollback-{index}"));
        let restore = (|| {
            filesystem.copy(&backups[index], &staged)?;
            filesystem.set_mode(&staged, modes[index])?;
            filesystem.sync_file(&staged)?;
            filesystem.rename(&staged, targets[index])?;
            let parent = targets[index]
                .parent()
                .ok_or_else(|| UpdateError::Unsupported("rollback target has no parent".into()))?;
            filesystem.sync_dir(parent)
        })();
        if let Err(error) = restore {
            rollback_errors.push(format!("{}: {error}", targets[index].display()));
        }
    }
    if rollback_errors.is_empty() {
        return Err(UpdateError::Preserved(format!(
            "{cause}; all committed replacements were restored"
        )));
    }

    let marker = work.join("ROLLBACK-INCOMPLETE");
    let message = format!(
        "update_error={cause}\nrollback_errors={}\n",
        rollback_errors.join(" | ")
    );
    let _ = filesystem.write_new(&marker, message.as_bytes(), 0o600);
    let _ = filesystem.sync_dir(work);
    Err(UpdateError::RollbackFailed {
        update: cause.to_string(),
        rollback: rollback_errors.join("; "),
        recovery: work.to_path_buf(),
    })
}

fn verify_binary_versions(
    commands: &dyn CommandRunner,
    rustscale: &Path,
    rustscaled: &Path,
    target_version: &str,
) -> Result<(), UpdateError> {
    for (path, daemon) in [(rustscale, false), (rustscaled, true)] {
        let output = commands.run(&CommandSpec {
            program: path.display().to_string(),
            args: vec!["--version".into()],
        })?;
        let text = std::str::from_utf8(&output.stdout)
            .map_err(|error| UpdateError::VersionVerification(error.to_string()))?;
        if !version_output_matches(text, target_version, daemon) {
            return Err(UpdateError::VersionVerification(format!(
                "{} reported {:?}, expected {}",
                path.display(),
                text.trim(),
                target_version
            )));
        }
    }
    Ok(())
}

fn version_output_matches(output: &str, target: &str, daemon: bool) -> bool {
    let mut value = output.trim();
    if daemon {
        let Some(stripped) = value.strip_prefix("rustscaled ") else {
            return false;
        };
        value = stripped;
    }
    value = value.strip_prefix('v').unwrap_or(value);
    if let Some((version, suffix)) = value.rsplit_once("-0-g") {
        if !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            value = version;
        }
    }
    semver::Version::parse(value).ok() == semver::Version::parse(target).ok()
}

fn unique_token() -> String {
    let started = Instant::now();
    thread::yield_now();
    format!(
        "{}-{:x}-{:x}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos()),
        started.elapsed().as_nanos()
    )
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::*;

    #[test]
    fn receipt_rejects_missing_tampered_and_unknown_fields() {
        assert!(parse_receipt(b"bad\n").is_err());
        assert!(parse_receipt(b"rustscale-install-receipt-v1\ninstaller=scripts/install.sh\nrustscale_sha256=abc\nrustscaled_sha256=def\n").is_err());
        let valid = receipt_bytes(b"cli", b"daemon");
        assert!(parse_receipt(&valid).is_ok());
        let mut tampered = valid;
        tampered.extend_from_slice(b"extra=value\n");
        assert!(parse_receipt(&tampered).is_err());
    }

    #[test]
    fn homebrew_paths_are_exact_and_commands_are_absolute() {
        let plan = homebrew_plan(Path::new(
            "/opt/homebrew/Cellar/rustscale/1.2.3/bin/rustscale",
        ))
        .unwrap();
        assert_eq!(plan.program, "/opt/homebrew/bin/brew");
        assert_eq!(
            plan.args,
            ["upgrade", "--formula", "rajsinghtech/tap/rustscale"]
        );
        for path in [
            "/tmp/homebrew/Cellar/rustscale/1.2.3/bin/rustscale",
            "/opt/homebrew/Cellar/rustscale/1.2.3/bin/other",
            "/opt/homebrew/Cellar/rustscale/not-version/bin/rustscale",
            "/opt/homebrew/Cellar/rustscale/1.2.3/extra/bin/rustscale",
        ] {
            assert!(homebrew_plan(Path::new(path)).is_none(), "accepted {path}");
        }
    }

    #[test]
    fn version_outputs_are_strict() {
        assert!(version_output_matches("1.2.3\n", "1.2.3", false));
        assert!(version_output_matches("v1.2.3-0-gabc123\n", "1.2.3", false));
        assert!(version_output_matches("rustscaled 1.2.3\n", "1.2.3", true));
        assert!(!version_output_matches("1.2.30\n", "1.2.3", false));
        assert!(!version_output_matches("rustscaled 1.2.4\n", "1.2.3", true));
    }

    struct VersionRunner {
        outputs: Mutex<VecDeque<Result<CommandOutput, UpdateError>>>,
    }

    impl VersionRunner {
        fn successful() -> Self {
            Self {
                outputs: Mutex::new(VecDeque::from([
                    Ok(CommandOutput {
                        stdout: b"1.2.0\n".to_vec(),
                        stderr: vec![],
                    }),
                    Ok(CommandOutput {
                        stdout: b"rustscaled 1.2.0\n".to_vec(),
                        stderr: vec![],
                    }),
                    Ok(CommandOutput {
                        stdout: b"1.2.0\n".to_vec(),
                        stderr: vec![],
                    }),
                    Ok(CommandOutput {
                        stdout: b"rustscaled 1.2.0\n".to_vec(),
                        stderr: vec![],
                    }),
                ])),
            }
        }
    }

    impl CommandRunner for VersionRunner {
        fn run(&self, _command: &CommandSpec) -> Result<CommandOutput, UpdateError> {
            self.outputs.lock().unwrap().pop_front().unwrap()
        }
    }

    #[derive(Clone, Copy)]
    enum Fault {
        Rename(usize),
        TargetSync(usize),
        RollbackRename,
        RollbackSync,
    }

    struct FaultFs {
        inner: SystemFileSystem,
        fault: Option<Fault>,
        rename_count: Mutex<usize>,
        target_sync_count: Mutex<usize>,
        rollback_started: Mutex<bool>,
    }

    impl FaultFs {
        fn new(fault: Option<Fault>) -> Self {
            Self {
                inner: SystemFileSystem,
                fault,
                rename_count: Mutex::new(0),
                target_sync_count: Mutex::new(0),
                rollback_started: Mutex::new(false),
            }
        }
    }

    impl FileSystem for FaultFs {
        fn is_regular_file(&self, path: &Path) -> bool {
            self.inner.is_regular_file(path)
        }
        fn is_symlink(&self, path: &Path) -> bool {
            self.inner.is_symlink(path)
        }
        fn create_private_dir(&self, path: &Path) -> Result<(), UpdateError> {
            self.inner.create_private_dir(path)
        }
        fn read_limited(&self, path: &Path, max: usize) -> Result<Vec<u8>, UpdateError> {
            self.inner.read_limited(path, max)
        }
        fn write_new(&self, path: &Path, data: &[u8], mode: u32) -> Result<(), UpdateError> {
            self.inner.write_new(path, data, mode)
        }
        fn copy(&self, from: &Path, to: &Path) -> Result<(), UpdateError> {
            self.inner.copy(from, to)
        }
        fn mode(&self, path: &Path) -> Result<u32, UpdateError> {
            self.inner.mode(path)
        }
        fn set_mode(&self, path: &Path, mode: u32) -> Result<(), UpdateError> {
            self.inner.set_mode(path, mode)
        }
        fn rename(&self, from: &Path, to: &Path) -> Result<(), UpdateError> {
            let rollback = from
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("rollback-"));
            if rollback {
                *self.rollback_started.lock().unwrap() = true;
            }
            if rollback && matches!(self.fault, Some(Fault::RollbackRename)) {
                return Err(UpdateError::FileSystem("injected rollback rename".into()));
            }
            let mut count = self.rename_count.lock().unwrap();
            let current = *count;
            *count += 1;
            if !rollback && matches!(self.fault, Some(Fault::Rename(wanted)) if wanted == current) {
                return Err(UpdateError::FileSystem(format!(
                    "injected rename {current}"
                )));
            }
            self.inner.rename(from, to)
        }
        fn sync_file(&self, path: &Path) -> Result<(), UpdateError> {
            self.inner.sync_file(path)
        }
        fn sync_dir(&self, path: &Path) -> Result<(), UpdateError> {
            let is_target = path.file_name().and_then(|name| name.to_str()) == Some("bin");
            if is_target {
                let rollback = *self.rollback_started.lock().unwrap();
                if rollback && matches!(self.fault, Some(Fault::RollbackSync)) {
                    return Err(UpdateError::FileSystem("injected rollback sync".into()));
                }
                let mut count = self.target_sync_count.lock().unwrap();
                let current = *count;
                *count += 1;
                // Count 0 is the pre-mutation journal sync; failures 0..2 refer
                // to the sync immediately after each committed replacement.
                if !rollback
                    && matches!(self.fault, Some(Fault::TargetSync(wanted)) if wanted + 1 == current)
                {
                    return Err(UpdateError::FileSystem(format!(
                        "injected target sync {}",
                        current - 1
                    )));
                }
            }
            self.inner.sync_dir(path)
        }
        fn remove_file(&self, path: &Path) -> Result<(), UpdateError> {
            self.inner.remove_file(path)
        }
        fn remove_dir_all(&self, path: &Path) -> Result<(), UpdateError> {
            self.inner.remove_dir_all(path)
        }
    }

    fn setup_install() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let bin = temp.path().join("bin");
        fs::create_dir(&bin).unwrap();
        let cli = bin.join("rustscale");
        let daemon = bin.join("rustscaled");
        let receipt = bin.join(RECEIPT_NAME);
        fs::write(&cli, b"old-cli").unwrap();
        fs::write(&daemon, b"old-daemon").unwrap();
        fs::write(&receipt, receipt_bytes(b"old-cli", b"old-daemon")).unwrap();
        (temp, cli, daemon, receipt)
    }

    #[test]
    fn archive_detection_requires_an_intact_matching_receipt() {
        let (temp, cli, _daemon, receipt) = setup_install();
        let platform = Platform {
            os: OperatingSystem::Linux,
            arch: crate::Architecture::X86_64,
            libc: crate::Libc::Gnu,
        };
        assert!(matches!(
            detect_install_method(&cli, platform, &SystemFileSystem),
            InstallMethod::Archive { .. }
        ));

        fs::write(&cli, b"modified").unwrap();
        assert!(matches!(
            detect_install_method(&cli, platform, &SystemFileSystem),
            InstallMethod::Unsupported { .. }
        ));
        fs::write(&cli, b"old-cli").unwrap();
        fs::write(&receipt, b"tampered\n").unwrap();
        assert!(matches!(
            detect_install_method(&cli, platform, &SystemFileSystem),
            InstallMethod::Unsupported { .. }
        ));
        fs::remove_file(&receipt).unwrap();
        assert!(matches!(
            detect_install_method(&cli, platform, &SystemFileSystem),
            InstallMethod::Unsupported { .. }
        ));
        drop(temp);
    }

    fn assert_old(cli: &Path, daemon: &Path, receipt: &Path) {
        assert_eq!(fs::read(cli).unwrap(), b"old-cli");
        assert_eq!(fs::read(daemon).unwrap(), b"old-daemon");
        assert_eq!(
            parse_receipt(&fs::read(receipt).unwrap())
                .unwrap()
                .rustscale_sha256,
            sha256(b"old-cli")
        );
    }

    #[cfg(unix)]
    #[test]
    fn successful_transaction_verifies_staged_and_installed_versions() {
        let (_temp, cli, daemon, receipt) = setup_install();
        apply_archive_transaction(
            &FaultFs::new(None),
            &VersionRunner::successful(),
            &BinaryPayloads {
                rustscale: b"new-cli".to_vec(),
                rustscaled: b"new-daemon".to_vec(),
            },
            "1.2.0",
            &cli,
            &daemon,
            &receipt,
        )
        .unwrap();
        assert_eq!(fs::read(&cli).unwrap(), b"new-cli");
        assert_eq!(fs::read(&daemon).unwrap(), b"new-daemon");
        validate_receipt(&SystemFileSystem, &cli, &daemon, &receipt).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn post_install_version_mismatch_rolls_back_all_targets() {
        let (_temp, cli, daemon, receipt) = setup_install();
        let runner = VersionRunner {
            outputs: Mutex::new(VecDeque::from([
                Ok(CommandOutput {
                    stdout: b"1.2.0\n".to_vec(),
                    stderr: vec![],
                }),
                Ok(CommandOutput {
                    stdout: b"rustscaled 1.2.0\n".to_vec(),
                    stderr: vec![],
                }),
                Ok(CommandOutput {
                    stdout: b"1.2.9\n".to_vec(),
                    stderr: vec![],
                }),
            ])),
        };
        let error = apply_archive_transaction(
            &FaultFs::new(None),
            &runner,
            &BinaryPayloads {
                rustscale: b"new-cli".to_vec(),
                rustscaled: b"new-daemon".to_vec(),
            },
            "1.2.0",
            &cli,
            &daemon,
            &receipt,
        )
        .unwrap_err();
        assert!(matches!(error, UpdateError::Preserved(_)));
        assert_old(&cli, &daemon, &receipt);
    }

    #[cfg(unix)]
    #[test]
    fn failures_at_each_rename_and_post_rename_sync_restore_all_targets() {
        for fault in [
            Fault::Rename(0),
            Fault::Rename(1),
            Fault::Rename(2),
            Fault::TargetSync(0),
            Fault::TargetSync(1),
            Fault::TargetSync(2),
        ] {
            let (_temp, cli, daemon, receipt) = setup_install();
            let fs = FaultFs::new(Some(fault));
            let result = apply_archive_transaction(
                &fs,
                &VersionRunner::successful(),
                &BinaryPayloads {
                    rustscale: b"new-cli".to_vec(),
                    rustscaled: b"new-daemon".to_vec(),
                },
                "1.2.0",
                &cli,
                &daemon,
                &receipt,
            );
            assert!(result.is_err());
            assert_old(&cli, &daemon, &receipt);
        }
    }

    #[cfg(unix)]
    #[test]
    fn rollback_rename_or_sync_failure_retains_journal_and_backups() {
        for fault in [Fault::RollbackRename, Fault::RollbackSync] {
            let (_temp, cli, daemon, receipt) = setup_install();
            let fs = FaultFs::new(Some(fault));
            // Force a post-mutation version failure so rollback is attempted.
            let runner = VersionRunner {
                outputs: Mutex::new(VecDeque::from([
                    Ok(CommandOutput {
                        stdout: b"1.2.0\n".to_vec(),
                        stderr: vec![],
                    }),
                    Ok(CommandOutput {
                        stdout: b"rustscaled 1.2.0\n".to_vec(),
                        stderr: vec![],
                    }),
                    Err(UpdateError::VersionVerification("injected".into())),
                ])),
            };
            let error = apply_archive_transaction(
                &fs,
                &runner,
                &BinaryPayloads {
                    rustscale: b"new-cli".to_vec(),
                    rustscaled: b"new-daemon".to_vec(),
                },
                "1.2.0",
                &cli,
                &daemon,
                &receipt,
            )
            .unwrap_err();
            let UpdateError::RollbackFailed { recovery, .. } = error else {
                panic!("expected retained recovery")
            };
            assert!(recovery.join("journal-v1").is_file());
            assert!(recovery.join("rustscale.backup").is_file());
            assert!(recovery.join("rustscaled.backup").is_file());
            assert!(recovery.join("receipt.backup").is_file());
        }
    }
}
