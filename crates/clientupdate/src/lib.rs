//! Safe client-update planning and application for RustScale releases.
//!
//! Release metadata and assets come from the RustScale GitHub repository. The
//! update engine keeps lookup, download, command, and filesystem operations
//! injectable so callers can plan updates without mutation and tests never
//! need network access or a real package manager.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use rustscale_tailcfg::ClientVersion;
use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const GITHUB_RELEASES_API: &str =
    "https://api.github.com/repos/rajsinghtech/rustscale/releases?per_page=100";
pub const GITHUB_RELEASES_PAGE: &str = "https://github.com/rajsinghtech/rustscale/releases";

/// Release track understood by `rustscale update`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Track {
    Stable,
    Unstable,
    ReleaseCandidate,
}

impl Track {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Unstable => "unstable",
            Self::ReleaseCandidate => "release-candidate",
        }
    }
}

impl std::str::FromStr for Track {
    type Err = UpdateError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "stable" => Ok(Self::Stable),
            "unstable" => Ok(Self::Unstable),
            "release-candidate" => Ok(Self::ReleaseCandidate),
            _ => Err(UpdateError::InvalidArguments(format!(
                "unsupported track {value:?}; expected stable, release-candidate, or unstable"
            ))),
        }
    }
}

/// Arguments retained for users of the control-plane update checker.
#[derive(Clone, Debug, Default)]
pub struct UpdateArguments {
    pub version: String,
    pub track: Option<Track>,
    pub for_auto_update: bool,
}

/// Result derived from the control plane's `ClientVersion` field.
#[derive(Clone, Debug, Default)]
pub struct CheckResult {
    pub latest_version: String,
    pub running_latest: bool,
    pub urgent_security_update: bool,
    pub notify: bool,
    pub notify_url: String,
    pub notify_text: String,
}

impl CheckResult {
    pub fn update_available(&self) -> bool {
        !self.running_latest && !self.latest_version.is_empty()
    }
}

/// Control-plane update status used by `tsnet`.
pub struct ClientUpdater {
    current_version: String,
    last_check: ClientVersion,
}

impl ClientUpdater {
    pub fn new(current_version: &str) -> Self {
        Self {
            current_version: current_version.to_owned(),
            last_check: ClientVersion::default(),
        }
    }

    pub fn set_client_version(&mut self, cv: ClientVersion) {
        self.last_check = cv;
    }

    pub fn check(&self) -> CheckResult {
        let cv = &self.last_check;
        CheckResult {
            latest_version: cv.LatestVersion.clone(),
            running_latest: cv.RunningLatest,
            urgent_security_update: cv.UrgentSecurityUpdate,
            notify: cv.Notify,
            notify_url: cv.NotifyURL.clone(),
            notify_text: cv.NotifyText.clone(),
        }
    }

    /// Automatic mutation is intentionally unavailable through the status
    /// checker. Applying an update requires a release plan and an explicit
    /// confirmation through [`ReleaseUpdater::execute`].
    pub fn auto_apply(&self, _args: UpdateArguments) -> Result<(), UpdateError> {
        Err(UpdateError::Unsupported(
            "automatic application requires an explicitly confirmed release plan".into(),
        ))
    }

    pub fn current_version(&self) -> &str {
        &self.current_version
    }

    pub fn has_urgent_security_update(&self) -> bool {
        self.last_check.UrgentSecurityUpdate
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct ReleaseAsset {
    pub name: String,
    pub browser_download_url: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct GitHubRelease {
    pub tag_name: String,
    #[serde(default)]
    pub draft: bool,
    #[serde(default)]
    pub prerelease: bool,
    #[serde(default)]
    pub assets: Vec<ReleaseAsset>,
}

pub fn parse_github_releases(json: &[u8]) -> Result<Vec<GitHubRelease>, UpdateError> {
    serde_json::from_slice(json).map_err(|error| UpdateError::ReleaseLookup(error.to_string()))
}

pub trait ReleaseLookup: Send + Sync {
    fn releases(&self) -> Result<Vec<GitHubRelease>, UpdateError>;
}

pub trait Downloader: Send + Sync {
    fn download(&self, url: &str) -> Result<Vec<u8>, UpdateError>;
}

#[derive(Default)]
pub struct HttpClient;

impl Downloader for HttpClient {
    fn download(&self, url: &str) -> Result<Vec<u8>, UpdateError> {
        let response = reqwest::blocking::Client::builder()
            .user_agent(concat!("rustscale/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| UpdateError::Download(error.to_string()))?
            .get(url)
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .map_err(|error| UpdateError::Download(format!("{url}: {error}")))?;
        response
            .bytes()
            .map(|bytes| bytes.to_vec())
            .map_err(|error| UpdateError::Download(format!("{url}: {error}")))
    }
}

impl ReleaseLookup for HttpClient {
    fn releases(&self) -> Result<Vec<GitHubRelease>, UpdateError> {
        parse_github_releases(&self.download(GITHUB_RELEASES_API)?)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VersionSelector {
    Track(Track),
    Version(String),
}

pub fn version_to_track(version: &str) -> Option<Track> {
    let version = parse_version(version).ok()?;
    if version.pre.is_empty() {
        return Some(Track::Stable);
    }
    let pre = version.pre.as_str().to_ascii_lowercase();
    if pre.starts_with("rc") || pre.contains(".rc") {
        Some(Track::ReleaseCandidate)
    } else {
        Some(Track::Unstable)
    }
}

fn parse_version(value: &str) -> Result<Version, UpdateError> {
    Version::parse(value.strip_prefix('v').unwrap_or(value)).map_err(|_| {
        UpdateError::InvalidVersion(format!(
            "{value:?} is not a RustScale release version (expected x.y.z or vX.Y.Z)"
        ))
    })
}

pub fn select_release(
    releases: &[GitHubRelease],
    selector: &VersionSelector,
) -> Result<GitHubRelease, UpdateError> {
    let requested = match selector {
        VersionSelector::Version(value) => Some(parse_version(value)?),
        VersionSelector::Track(_) => None,
    };

    releases
        .iter()
        .filter(|release| !release.draft)
        .filter_map(|release| {
            let version = parse_version(&release.tag_name).ok()?;
            let included = match selector {
                VersionSelector::Version(_) => requested.as_ref() == Some(&version),
                VersionSelector::Track(Track::Stable) => {
                    !release.prerelease && version.pre.is_empty()
                }
                VersionSelector::Track(Track::ReleaseCandidate) => {
                    if version.pre.is_empty() {
                        !release.prerelease
                    } else {
                        let pre = version.pre.as_str().to_ascii_lowercase();
                        pre.starts_with("rc") || pre.contains(".rc")
                    }
                }
                VersionSelector::Track(Track::Unstable) => true,
            };
            included.then_some((version, release))
        })
        .max_by(|(a, _), (b, _)| a.cmp(b))
        .map(|(_, release)| release.clone())
        .ok_or_else(|| {
            UpdateError::ReleaseNotFound(match selector {
                VersionSelector::Version(value) => format!("version {value}"),
                VersionSelector::Track(track) => format!("{} track", track.as_str()),
            })
        })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperatingSystem {
    Linux,
    MacOs,
    Windows,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Architecture {
    X86_64,
    Aarch64,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Libc {
    Gnu,
    Musl,
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Platform {
    pub os: OperatingSystem,
    pub arch: Architecture,
    pub libc: Libc,
}

impl Platform {
    pub const fn current() -> Self {
        let os = if cfg!(target_os = "linux") {
            OperatingSystem::Linux
        } else if cfg!(target_os = "macos") {
            OperatingSystem::MacOs
        } else if cfg!(target_os = "windows") {
            OperatingSystem::Windows
        } else {
            OperatingSystem::Other
        };
        let arch = if cfg!(target_arch = "x86_64") {
            Architecture::X86_64
        } else if cfg!(target_arch = "aarch64") {
            Architecture::Aarch64
        } else {
            Architecture::Other
        };
        let libc = if cfg!(target_env = "gnu") {
            Libc::Gnu
        } else if cfg!(target_env = "musl") {
            Libc::Musl
        } else {
            Libc::Other
        };
        Self { os, arch, libc }
    }
}

pub fn asset_name(platform: Platform) -> Result<&'static str, UpdateError> {
    match (platform.os, platform.arch, platform.libc) {
        (OperatingSystem::MacOs, Architecture::X86_64 | Architecture::Aarch64, _) => {
            Ok("rustscale-universal-apple-darwin.tar.gz")
        }
        (OperatingSystem::Linux, Architecture::X86_64, Libc::Musl) => {
            Ok("rustscale-x86_64-unknown-linux-musl.tar.gz")
        }
        (OperatingSystem::Linux, Architecture::X86_64, _) => {
            Ok("rustscale-x86_64-unknown-linux-gnu.tar.gz")
        }
        (OperatingSystem::Linux, Architecture::Aarch64, _) => {
            Ok("rustscale-aarch64-unknown-linux-gnu.tar.gz")
        }
        (OperatingSystem::Windows, Architecture::X86_64, _) => {
            Ok("rustscale-x86_64-pc-windows-msvc.zip")
        }
        _ => Err(UpdateError::Unsupported(
            "RustScale does not publish a release asset for this OS/architecture".into(),
        )),
    }
}

fn release_asset<'a>(
    release: &'a GitHubRelease,
    name: &str,
) -> Result<&'a ReleaseAsset, UpdateError> {
    let asset = release
        .assets
        .iter()
        .find(|asset| asset.name == name)
        .ok_or_else(|| UpdateError::MissingAsset {
            release: release.tag_name.clone(),
            asset: name.to_owned(),
        })?;
    const TRUSTED_PREFIX: &str = "https://github.com/rajsinghtech/rustscale/releases/download/";
    if !asset.browser_download_url.starts_with(TRUSTED_PREFIX) {
        return Err(UpdateError::ReleaseLookup(format!(
            "release {} returned an untrusted URL for {}",
            release.tag_name, asset.name
        )));
    }
    Ok(asset)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommandOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub trait CommandRunner: Send + Sync {
    fn run(&self, command: &CommandSpec) -> Result<CommandOutput, UpdateError>;
}

#[derive(Default)]
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, command: &CommandSpec) -> Result<CommandOutput, UpdateError> {
        let output = Command::new(&command.program)
            .args(&command.args)
            .output()
            .map_err(|error| UpdateError::Command(format!("{}: {error}", command.program)))?;
        if output.status.success() {
            Ok(CommandOutput {
                stdout: output.stdout,
                stderr: output.stderr,
            })
        } else {
            Err(UpdateError::Command(format!(
                "{} {:?} failed with {}: {}",
                command.program,
                command.args,
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )))
        }
    }
}

pub trait FileSystem: Send + Sync {
    fn is_regular_file(&self, path: &Path) -> bool;
    fn is_symlink(&self, path: &Path) -> bool;
    fn create_dir(&self, path: &Path) -> Result<(), UpdateError>;
    fn read(&self, path: &Path) -> Result<Vec<u8>, UpdateError>;
    fn write_new(&self, path: &Path, data: &[u8], mode: u32) -> Result<(), UpdateError>;
    fn copy(&self, from: &Path, to: &Path) -> Result<(), UpdateError>;
    fn mode(&self, path: &Path) -> Result<u32, UpdateError>;
    fn set_mode(&self, path: &Path, mode: u32) -> Result<(), UpdateError>;
    fn rename_replace(&self, from: &Path, to: &Path) -> Result<(), UpdateError>;
    fn remove_file(&self, path: &Path) -> Result<(), UpdateError>;
    fn remove_dir_all(&self, path: &Path);
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

    fn create_dir(&self, path: &Path) -> Result<(), UpdateError> {
        fs::create_dir(path).map_err(|error| fs_error("create", path, error))
    }

    fn read(&self, path: &Path) -> Result<Vec<u8>, UpdateError> {
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
            .and_then(|()| file.sync_all())
            .map_err(|error| fs_error("write", path, error))?;
        self.set_mode(path, mode)
    }

    fn copy(&self, from: &Path, to: &Path) -> Result<(), UpdateError> {
        fs::copy(from, to).map_err(|error| fs_error("copy to", to, error))?;
        fs::File::open(to)
            .and_then(|file| file.sync_all())
            .map_err(|error| fs_error("sync", to, error))
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

    fn rename_replace(&self, from: &Path, to: &Path) -> Result<(), UpdateError> {
        fs::rename(from, to).map_err(|error| fs_error("rename to", to, error))?;
        if let Some(parent) = to.parent() {
            if let Ok(directory) = fs::File::open(parent) {
                directory
                    .sync_all()
                    .map_err(|error| fs_error("sync", parent, error))?;
            }
        }
        Ok(())
    }

    fn remove_file(&self, path: &Path) -> Result<(), UpdateError> {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(fs_error("remove", path, error)),
        }
    }

    fn remove_dir_all(&self, path: &Path) {
        let _ = fs::remove_dir_all(path);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstallMethod {
    /// A release archive can replace both colocated RustScale executables.
    Archive {
        rustscale: PathBuf,
        rustscaled: PathBuf,
    },
    /// Homebrew owns the installation and performs its own transactional update.
    Homebrew {
        command: CommandSpec,
    },
    Unsupported {
        reason: String,
    },
}

pub fn detect_install_method(
    executable: &Path,
    platform: Platform,
    filesystem: &dyn FileSystem,
) -> InstallMethod {
    if platform.os == OperatingSystem::Windows {
        return InstallMethod::Unsupported {
            reason: "in-place Windows updates are not safe while rustscale.exe is running; use scripts/install.ps1 or reinstall from the release page".into(),
        };
    }

    let text = executable.to_string_lossy();
    if text.contains("/Cellar/rustscale/") || text.contains("/homebrew/Cellar/rustscale/") {
        return InstallMethod::Homebrew {
            command: CommandSpec {
                program: "brew".into(),
                args: vec!["upgrade".into(), "rustscale".into()],
            },
        };
    }

    if filesystem.is_symlink(executable) {
        return InstallMethod::Unsupported {
            reason: "the rustscale executable is a symlink owned by an unknown installer".into(),
        };
    }
    let Some(directory) = executable.parent() else {
        return InstallMethod::Unsupported {
            reason: "cannot determine the RustScale installation directory".into(),
        };
    };
    let rustscale = directory.join(if platform.os == OperatingSystem::Windows {
        "rustscale.exe"
    } else {
        "rustscale"
    });
    let rustscaled = directory.join(if platform.os == OperatingSystem::Windows {
        "rustscaled.exe"
    } else {
        "rustscaled"
    });
    if filesystem.is_regular_file(&rustscale)
        && filesystem.is_regular_file(&rustscaled)
        && !filesystem.is_symlink(&rustscale)
        && !filesystem.is_symlink(&rustscaled)
    {
        InstallMethod::Archive {
            rustscale,
            rustscaled,
        }
    } else {
        InstallMethod::Unsupported {
            reason: "archive updates require regular, colocated rustscale and rustscaled binaries; use scripts/install.sh or your package manager".into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApplyPlan {
    Archive {
        archive: ReleaseAsset,
        checksums: ReleaseAsset,
        rustscale: PathBuf,
        rustscaled: PathBuf,
    },
    PackageManager(CommandSpec),
    Unsupported(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdatePlan {
    pub current_version: String,
    pub target_version: String,
    pub track: Track,
    pub already_current: bool,
    pub apply: ApplyPlan,
}

impl UpdatePlan {
    pub fn description(&self) -> String {
        if self.already_current {
            return format!("RustScale {} is already current", self.current_version);
        }
        match &self.apply {
            ApplyPlan::Archive {
                archive,
                rustscale,
                rustscaled,
                ..
            } => format!(
                "replace {} and {} from verified {}",
                rustscale.display(),
                rustscaled.display(),
                archive.name
            ),
            ApplyPlan::PackageManager(command) => {
                format!("run {} {}", command.program, command.args.join(" "))
            }
            ApplyPlan::Unsupported(reason) => format!("unsupported: {reason}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpdateOutcome {
    AlreadyCurrent,
    DryRun,
    Declined,
    Applied,
}

pub struct ReleaseUpdater<'a> {
    current_version: String,
    platform: Platform,
    install_method: InstallMethod,
    releases: &'a dyn ReleaseLookup,
    downloader: &'a dyn Downloader,
    commands: &'a dyn CommandRunner,
    filesystem: &'a dyn FileSystem,
}

impl<'a> ReleaseUpdater<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        current_version: &str,
        platform: Platform,
        install_method: InstallMethod,
        releases: &'a dyn ReleaseLookup,
        downloader: &'a dyn Downloader,
        commands: &'a dyn CommandRunner,
        filesystem: &'a dyn FileSystem,
    ) -> Self {
        Self {
            current_version: current_version.to_owned(),
            platform,
            install_method,
            releases,
            downloader,
            commands,
            filesystem,
        }
    }

    pub fn plan(&self, selector: VersionSelector) -> Result<UpdatePlan, UpdateError> {
        let releases = self.releases.releases()?;
        let release = select_release(&releases, &selector)?;
        let target = parse_version(&release.tag_name)?;
        let current = parse_version(&self.current_version)?;
        let track = match selector {
            VersionSelector::Track(track) => track,
            VersionSelector::Version(_) => version_to_track(&release.tag_name)
                .ok_or_else(|| UpdateError::InvalidVersion(release.tag_name.clone()))?,
        };
        let same_track = version_to_track(&self.current_version) == Some(track);
        let explicit_version = matches!(selector, VersionSelector::Version(_));
        let already_current =
            target == current || (!explicit_version && same_track && target < current);

        let apply = if already_current {
            ApplyPlan::Unsupported("no update is needed".into())
        } else {
            match &self.install_method {
                InstallMethod::Archive {
                    rustscale,
                    rustscaled,
                } => {
                    if self.platform.os == OperatingSystem::Windows {
                        ApplyPlan::Unsupported(
                            "in-place archive replacement is unsupported on Windows".into(),
                        )
                    } else {
                        let name = asset_name(self.platform)?;
                        ApplyPlan::Archive {
                            archive: release_asset(&release, name)?.clone(),
                            checksums: release_asset(&release, "SHA256SUMS")?.clone(),
                            rustscale: rustscale.clone(),
                            rustscaled: rustscaled.clone(),
                        }
                    }
                }
                InstallMethod::Homebrew { command } => {
                    if track != Track::Stable || explicit_version {
                        ApplyPlan::Unsupported(
                            "Homebrew updates support only the latest stable release; omit --version and use --track stable".into(),
                        )
                    } else {
                        ApplyPlan::PackageManager(command.clone())
                    }
                }
                InstallMethod::Unsupported { reason } => ApplyPlan::Unsupported(reason.clone()),
            }
        };

        Ok(UpdatePlan {
            current_version: self.current_version.clone(),
            target_version: target.to_string(),
            track,
            already_current,
            apply,
        })
    }

    /// Plan, optionally confirm, and apply an update. Dry runs never invoke the
    /// confirmation callback, downloader, command runner, or filesystem writes.
    pub fn execute<F>(
        &self,
        selector: VersionSelector,
        dry_run: bool,
        confirm: F,
    ) -> Result<(UpdatePlan, UpdateOutcome), UpdateError>
    where
        F: FnOnce(&UpdatePlan) -> bool,
    {
        let plan = self.plan(selector)?;
        if plan.already_current {
            return Ok((plan, UpdateOutcome::AlreadyCurrent));
        }
        if dry_run {
            return Ok((plan, UpdateOutcome::DryRun));
        }
        if matches!(plan.apply, ApplyPlan::Unsupported(_)) {
            return self.apply(&plan).map(|outcome| (plan, outcome));
        }
        if !confirm(&plan) {
            return Ok((plan, UpdateOutcome::Declined));
        }
        self.apply(&plan).map(|outcome| (plan, outcome))
    }

    pub fn apply(&self, plan: &UpdatePlan) -> Result<UpdateOutcome, UpdateError> {
        match &plan.apply {
            ApplyPlan::Archive {
                archive,
                checksums,
                rustscale,
                rustscaled,
            } => {
                self.apply_archive(archive, checksums, rustscale, rustscaled)?;
                Ok(UpdateOutcome::Applied)
            }
            ApplyPlan::PackageManager(command) => {
                self.commands.run(command)?;
                Ok(UpdateOutcome::Applied)
            }
            ApplyPlan::Unsupported(reason) => Err(UpdateError::Unsupported(reason.clone())),
        }
    }

    fn apply_archive(
        &self,
        archive: &ReleaseAsset,
        checksums: &ReleaseAsset,
        rustscale: &Path,
        rustscaled: &Path,
    ) -> Result<(), UpdateError> {
        let checksum_data = self.downloader.download(&checksums.browser_download_url)?;
        let archive_data = self.downloader.download(&archive.browser_download_url)?;
        verify_checksum(&archive.name, &archive_data, &checksum_data)?;

        let parent = rustscale.parent().ok_or_else(|| {
            UpdateError::Unsupported("cannot determine binary installation directory".into())
        })?;
        if rustscaled.parent() != Some(parent) {
            return Err(UpdateError::Unsupported(
                "rustscale and rustscaled must be on the same filesystem".into(),
            ));
        }
        let token = unique_token();
        let work = parent.join(format!(".rustscale-update-{token}"));
        self.filesystem.create_dir(&work)?;
        let result =
            self.apply_archive_in_workdir(archive, &archive_data, rustscale, rustscaled, &work);
        self.filesystem.remove_dir_all(&work);
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_archive_in_workdir(
        &self,
        archive: &ReleaseAsset,
        archive_data: &[u8],
        rustscale: &Path,
        rustscaled: &Path,
        work: &Path,
    ) -> Result<(), UpdateError> {
        let archive_path = work.join(&archive.name);
        self.filesystem
            .write_new(&archive_path, archive_data, 0o600)?;

        let list = self.commands.run(&CommandSpec {
            program: "tar".into(),
            args: vec!["tzf".into(), archive_path.display().to_string()],
        })?;
        let members = validated_archive_members(&list.stdout)?;

        let extracted = work.join("extracted");
        self.filesystem.create_dir(&extracted)?;
        self.commands.run(&CommandSpec {
            program: "tar".into(),
            args: vec![
                "xzf".into(),
                archive_path.display().to_string(),
                "-C".into(),
                extracted.display().to_string(),
                members[0].clone(),
                members[1].clone(),
            ],
        })?;

        let sources = [extracted.join("rustscale"), extracted.join("rustscaled")];
        for source in &sources {
            if !self.filesystem.is_regular_file(source) || self.filesystem.is_symlink(source) {
                return Err(UpdateError::UnsafeArchive(format!(
                    "{} is missing or is not a regular file",
                    source.display()
                )));
            }
        }

        let targets = [rustscale, rustscaled];
        // Keep staged files and backups in a private directory on the same
        // filesystem as the targets. Renames remain atomic, and any error
        // before replacement leaves no transaction artifacts beside binaries.
        let new_paths = [work.join("rustscale.new"), work.join("rustscaled.new")];
        let backups = [
            work.join("rustscale.backup"),
            work.join("rustscaled.backup"),
        ];

        for index in 0..2 {
            if !self.filesystem.is_regular_file(targets[index])
                || self.filesystem.is_symlink(targets[index])
            {
                return Err(UpdateError::Unsupported(format!(
                    "{} is no longer a regular file; refusing to replace it",
                    targets[index].display()
                )));
            }
            let mode = self.filesystem.mode(targets[index])?;
            self.filesystem.copy(targets[index], &backups[index])?;
            self.filesystem.set_mode(&backups[index], mode)?;
            let bytes = self.filesystem.read(&sources[index])?;
            self.filesystem.write_new(&new_paths[index], &bytes, mode)?;
        }

        if let Err(error) = self.filesystem.rename_replace(&new_paths[0], targets[0]) {
            self.cleanup_transaction(&new_paths, &backups);
            return Err(error);
        }
        if let Err(error) = self.filesystem.rename_replace(&new_paths[1], targets[1]) {
            let rollback = self.filesystem.rename_replace(&backups[0], targets[0]);
            self.cleanup_transaction(&new_paths, &backups);
            return match rollback {
                Ok(()) => Err(UpdateError::Preserved(format!(
                    "second binary replacement failed and the original installation was restored: {error}"
                ))),
                Err(rollback_error) => Err(UpdateError::RollbackFailed {
                    update: error.to_string(),
                    rollback: rollback_error.to_string(),
                }),
            };
        }

        for backup in &backups {
            let _ = self.filesystem.remove_file(backup);
        }
        Ok(())
    }

    fn cleanup_transaction(&self, new_paths: &[PathBuf; 2], backups: &[PathBuf; 2]) {
        for path in new_paths.iter().chain(backups) {
            let _ = self.filesystem.remove_file(path);
        }
    }
}

fn unique_token() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    format!("{}-{nanos:x}", std::process::id())
}

pub fn parse_checksums(data: &[u8]) -> Result<BTreeMap<String, String>, UpdateError> {
    let text = std::str::from_utf8(data)
        .map_err(|error| UpdateError::Checksum(format!("SHA256SUMS is not UTF-8: {error}")))?;
    let mut checksums = BTreeMap::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let mut fields = line.split_whitespace();
        let digest = fields.next().unwrap_or_default();
        let name = fields.next().unwrap_or_default().trim_start_matches('*');
        if digest.len() != 64
            || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
            || name.is_empty()
            || fields.next().is_some()
        {
            return Err(UpdateError::Checksum(format!(
                "malformed SHA256SUMS line {}",
                index + 1
            )));
        }
        checksums.insert(name.to_owned(), digest.to_ascii_lowercase());
    }
    Ok(checksums)
}

pub fn verify_checksum(name: &str, data: &[u8], sums: &[u8]) -> Result<(), UpdateError> {
    let expected = parse_checksums(sums)?
        .remove(name)
        .ok_or_else(|| UpdateError::Checksum(format!("SHA256SUMS has no entry for {name}")))?;
    let actual = format!("{:x}", Sha256::digest(data));
    if actual == expected {
        Ok(())
    } else {
        Err(UpdateError::Checksum(format!(
            "checksum mismatch for {name}: expected {expected}, got {actual}"
        )))
    }
}

pub fn validate_archive_listing(listing: &[u8]) -> Result<(), UpdateError> {
    validated_archive_members(listing).map(|_| ())
}

fn validated_archive_members(listing: &[u8]) -> Result<[String; 2], UpdateError> {
    let listing = std::str::from_utf8(listing).map_err(|error| {
        UpdateError::UnsafeArchive(format!("tar listing is not UTF-8: {error}"))
    })?;
    let mut members = BTreeMap::<&str, Vec<String>>::from([
        ("rustscale", Vec::new()),
        ("rustscaled", Vec::new()),
    ]);
    for name in listing
        .lines()
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        let path = Path::new(name);
        if path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
        {
            return Err(UpdateError::UnsafeArchive(format!(
                "unsafe archive path {name:?}"
            )));
        }
        // release.yml archives `.` from the dist directory, so real assets
        // contain `./rustscale`; accept that and the equivalent bare name.
        let normalized: PathBuf = path
            .components()
            .filter_map(|component| match component {
                Component::Normal(part) => Some(part),
                Component::CurDir => None,
                _ => None,
            })
            .collect();
        if let Some(found) = normalized
            .to_str()
            .and_then(|normalized| members.get_mut(normalized))
        {
            found.push(name.to_owned());
        }
    }
    if members.values().any(|found| found.len() != 1) {
        return Err(UpdateError::UnsafeArchive(
            "archive must contain exactly one top-level rustscale and rustscaled binary".into(),
        ));
    }
    Ok([
        members.remove("rustscale").unwrap().remove(0),
        members.remove("rustscaled").unwrap().remove(0),
    ])
}

#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    #[error("invalid update arguments: {0}")]
    InvalidArguments(String),
    #[error("invalid release version: {0}")]
    InvalidVersion(String),
    #[error("release lookup failed: {0}")]
    ReleaseLookup(String),
    #[error("no RustScale release found for {0}")]
    ReleaseNotFound(String),
    #[error("release {release} is missing required asset {asset}")]
    MissingAsset { release: String, asset: String },
    #[error("download failed: {0}")]
    Download(String),
    #[error("checksum verification failed: {0}")]
    Checksum(String),
    #[error("unsafe release archive: {0}")]
    UnsafeArchive(String),
    #[error("command failed: {0}")]
    Command(String),
    #[error("filesystem operation failed: {0}")]
    FileSystem(String),
    #[error("update is unsupported: {0}")]
    Unsupported(String),
    #[error("update failed safely: {0}")]
    Preserved(String),
    #[error("update failed ({update}) and rollback also failed ({rollback}); manual recovery is required")]
    RollbackFailed { update: String, rollback: String },
    #[error("update check failed: {0}")]
    CheckFailed(String),
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;

    use super::*;

    fn asset(name: &str) -> ReleaseAsset {
        ReleaseAsset {
            name: name.into(),
            browser_download_url: format!(
                "https://github.com/rajsinghtech/rustscale/releases/download/v1.2.0/{name}"
            ),
        }
    }

    fn release(tag: &str, prerelease: bool) -> GitHubRelease {
        GitHubRelease {
            tag_name: tag.into(),
            draft: false,
            prerelease,
            assets: vec![
                asset("rustscale-x86_64-unknown-linux-gnu.tar.gz"),
                asset("rustscale-x86_64-unknown-linux-musl.tar.gz"),
                asset("rustscale-aarch64-unknown-linux-gnu.tar.gz"),
                asset("rustscale-universal-apple-darwin.tar.gz"),
                asset("rustscale-x86_64-pc-windows-msvc.zip"),
                asset("SHA256SUMS"),
            ],
        }
    }

    #[test]
    fn control_plane_check_is_preserved() {
        let mut updater = ClientUpdater::new("0.1.0");
        updater.set_client_version(ClientVersion {
            RunningLatest: false,
            LatestVersion: "0.2.0".into(),
            UrgentSecurityUpdate: true,
            ..Default::default()
        });
        assert!(updater.check().update_available());
        assert!(updater.has_urgent_security_update());
        assert_eq!(updater.current_version(), "0.1.0");
    }

    #[test]
    fn version_tracks_follow_rustscale_prereleases() {
        assert_eq!(version_to_track("v1.2.3"), Some(Track::Stable));
        assert_eq!(version_to_track("1.3.0-beta.1"), Some(Track::Unstable));
        assert_eq!(
            version_to_track("1.3.0-rc.2"),
            Some(Track::ReleaseCandidate)
        );
        assert_eq!(version_to_track("not-a-version"), None);
    }

    #[test]
    fn selects_versions_by_track_and_explicit_tag() {
        let mut draft = release("v9.0.0", false);
        draft.draft = true;
        let releases = vec![
            release("v1.2.0", false),
            release("v1.3.0-rc.1", true),
            release("v1.3.0-beta.2", true),
            draft,
        ];
        assert_eq!(
            select_release(&releases, &VersionSelector::Track(Track::Stable))
                .unwrap()
                .tag_name,
            "v1.2.0"
        );
        assert_eq!(
            select_release(&releases, &VersionSelector::Track(Track::ReleaseCandidate))
                .unwrap()
                .tag_name,
            "v1.3.0-rc.1"
        );
        assert_eq!(
            select_release(&releases, &VersionSelector::Track(Track::Unstable))
                .unwrap()
                .tag_name,
            "v1.3.0-rc.1"
        );
        assert_eq!(
            select_release(&releases, &VersionSelector::Version("1.2.0".into()))
                .unwrap()
                .tag_name,
            "v1.2.0"
        );
    }

    #[test]
    fn parses_github_release_json() {
        let json = br#"[{"tag_name":"v1.2.0","draft":false,"prerelease":false,"assets":[{"name":"SHA256SUMS","browser_download_url":"https://example/SHA256SUMS"}]}]"#;
        let releases = parse_github_releases(json).unwrap();
        assert_eq!(releases.len(), 1);
        assert_eq!(releases[0].tag_name, "v1.2.0");
        assert_eq!(releases[0].assets[0].name, "SHA256SUMS");
    }

    #[test]
    fn selects_assets_for_all_published_platforms() {
        let cases = [
            (
                Platform {
                    os: OperatingSystem::Linux,
                    arch: Architecture::X86_64,
                    libc: Libc::Gnu,
                },
                "rustscale-x86_64-unknown-linux-gnu.tar.gz",
            ),
            (
                Platform {
                    os: OperatingSystem::Linux,
                    arch: Architecture::X86_64,
                    libc: Libc::Musl,
                },
                "rustscale-x86_64-unknown-linux-musl.tar.gz",
            ),
            (
                Platform {
                    os: OperatingSystem::Linux,
                    arch: Architecture::Aarch64,
                    libc: Libc::Gnu,
                },
                "rustscale-aarch64-unknown-linux-gnu.tar.gz",
            ),
            (
                Platform {
                    os: OperatingSystem::MacOs,
                    arch: Architecture::Aarch64,
                    libc: Libc::Other,
                },
                "rustscale-universal-apple-darwin.tar.gz",
            ),
            (
                Platform {
                    os: OperatingSystem::Windows,
                    arch: Architecture::X86_64,
                    libc: Libc::Other,
                },
                "rustscale-x86_64-pc-windows-msvc.zip",
            ),
        ];
        for (platform, expected) in cases {
            assert_eq!(asset_name(platform).unwrap(), expected);
        }
    }

    #[test]
    fn verifies_checksums_and_rejects_mismatch() {
        let data = b"release archive";
        let digest = format!("{:x}", Sha256::digest(data));
        let sums = format!("{digest}  archive.tar.gz\n");
        verify_checksum("archive.tar.gz", data, sums.as_bytes()).unwrap();
        assert!(matches!(
            verify_checksum("archive.tar.gz", b"tampered", sums.as_bytes()),
            Err(UpdateError::Checksum(_))
        ));
    }

    #[derive(Clone)]
    struct FakeLookup(Vec<GitHubRelease>);

    impl ReleaseLookup for FakeLookup {
        fn releases(&self) -> Result<Vec<GitHubRelease>, UpdateError> {
            Ok(self.0.clone())
        }
    }

    #[derive(Default)]
    struct FakeDownloader {
        values: HashMap<String, Vec<u8>>,
        calls: AtomicUsize,
    }

    impl Downloader for FakeDownloader {
        fn download(&self, url: &str) -> Result<Vec<u8>, UpdateError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.values
                .get(url)
                .cloned()
                .ok_or_else(|| UpdateError::Download(url.into()))
        }
    }

    #[derive(Default)]
    struct RecordingCommands {
        commands: Mutex<Vec<CommandSpec>>,
    }

    impl CommandRunner for RecordingCommands {
        fn run(&self, command: &CommandSpec) -> Result<CommandOutput, UpdateError> {
            self.commands.lock().unwrap().push(command.clone());
            Ok(CommandOutput::default())
        }
    }

    fn linux() -> Platform {
        Platform {
            os: OperatingSystem::Linux,
            arch: Architecture::X86_64,
            libc: Libc::Gnu,
        }
    }

    #[test]
    fn dry_run_has_no_mutating_side_effects_or_confirmation() {
        let lookup = FakeLookup(vec![release("v1.2.0", false)]);
        let downloads = FakeDownloader::default();
        let commands = RecordingCommands::default();
        let filesystem = SystemFileSystem;
        let updater = ReleaseUpdater::new(
            "1.0.0",
            linux(),
            InstallMethod::Archive {
                rustscale: "/tmp/rustscale".into(),
                rustscaled: "/tmp/rustscaled".into(),
            },
            &lookup,
            &downloads,
            &commands,
            &filesystem,
        );
        let confirmed = AtomicBool::new(false);
        let (_, outcome) = updater
            .execute(VersionSelector::Track(Track::Stable), true, |_| {
                confirmed.store(true, Ordering::SeqCst);
                true
            })
            .unwrap();
        assert_eq!(outcome, UpdateOutcome::DryRun);
        assert!(!confirmed.load(Ordering::SeqCst));
        assert_eq!(downloads.calls.load(Ordering::SeqCst), 0);
        assert!(commands.commands.lock().unwrap().is_empty());
    }

    #[test]
    fn declined_confirmation_preserves_installation() {
        let lookup = FakeLookup(vec![release("v1.2.0", false)]);
        let downloads = FakeDownloader::default();
        let commands = RecordingCommands::default();
        let filesystem = SystemFileSystem;
        let updater = ReleaseUpdater::new(
            "1.0.0",
            linux(),
            InstallMethod::Homebrew {
                command: CommandSpec {
                    program: "brew".into(),
                    args: vec!["upgrade".into(), "rustscale".into()],
                },
            },
            &lookup,
            &downloads,
            &commands,
            &filesystem,
        );
        let (_, outcome) = updater
            .execute(VersionSelector::Track(Track::Stable), false, |_| false)
            .unwrap();
        assert_eq!(outcome, UpdateOutcome::Declined);
        assert!(commands.commands.lock().unwrap().is_empty());
    }

    #[test]
    fn unsupported_install_is_explicit() {
        let lookup = FakeLookup(vec![release("v1.2.0", false)]);
        let downloads = FakeDownloader::default();
        let commands = RecordingCommands::default();
        let filesystem = SystemFileSystem;
        let updater = ReleaseUpdater::new(
            "1.0.0",
            linux(),
            InstallMethod::Unsupported {
                reason: "managed externally".into(),
            },
            &lookup,
            &downloads,
            &commands,
            &filesystem,
        );
        let error = updater
            .execute(VersionSelector::Track(Track::Stable), false, |_| true)
            .unwrap_err();
        assert!(
            matches!(error, UpdateError::Unsupported(message) if message == "managed externally")
        );
    }

    #[test]
    fn homebrew_command_plan_is_explicit_and_testable() {
        let fs = SystemFileSystem;
        let method = detect_install_method(
            Path::new("/opt/homebrew/Cellar/rustscale/1.0.0/bin/rustscale"),
            Platform {
                os: OperatingSystem::MacOs,
                arch: Architecture::Aarch64,
                libc: Libc::Other,
            },
            &fs,
        );
        assert_eq!(
            method,
            InstallMethod::Homebrew {
                command: CommandSpec {
                    program: "brew".into(),
                    args: vec!["upgrade".into(), "rustscale".into()]
                }
            }
        );
    }

    struct ExtractingRunner;

    impl CommandRunner for ExtractingRunner {
        fn run(&self, command: &CommandSpec) -> Result<CommandOutput, UpdateError> {
            if command.args.first().map(String::as_str) == Some("tzf") {
                return Ok(CommandOutput {
                    stdout: b"./\n./rustscale\n./rustscaled\n./LICENSE\n".to_vec(),
                    stderr: vec![],
                });
            }
            if command.args.first().map(String::as_str) == Some("xzf") {
                let directory = PathBuf::from(&command.args[3]);
                fs::write(directory.join("rustscale"), b"new-cli").unwrap();
                fs::write(directory.join("rustscaled"), b"new-daemon").unwrap();
                return Ok(CommandOutput::default());
            }
            Err(UpdateError::Command("unexpected command".into()))
        }
    }

    struct FailingFs {
        inner: SystemFileSystem,
        replaces: AtomicUsize,
        fail_second: bool,
    }

    impl FileSystem for FailingFs {
        fn is_regular_file(&self, path: &Path) -> bool {
            self.inner.is_regular_file(path)
        }
        fn is_symlink(&self, path: &Path) -> bool {
            self.inner.is_symlink(path)
        }
        fn create_dir(&self, path: &Path) -> Result<(), UpdateError> {
            self.inner.create_dir(path)
        }
        fn read(&self, path: &Path) -> Result<Vec<u8>, UpdateError> {
            self.inner.read(path)
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
        fn rename_replace(&self, from: &Path, to: &Path) -> Result<(), UpdateError> {
            let call = self.replaces.fetch_add(1, Ordering::SeqCst);
            if self.fail_second && call == 1 {
                Err(UpdateError::FileSystem(
                    "injected second rename failure".into(),
                ))
            } else {
                self.inner.rename_replace(from, to)
            }
        }
        fn remove_file(&self, path: &Path) -> Result<(), UpdateError> {
            self.inner.remove_file(path)
        }
        fn remove_dir_all(&self, path: &Path) {
            self.inner.remove_dir_all(path);
        }
    }

    #[cfg(unix)]
    #[test]
    fn archive_failure_restores_both_existing_binaries() {
        let temp = tempfile::tempdir().unwrap();
        let cli = temp.path().join("rustscale");
        let daemon = temp.path().join("rustscaled");
        fs::write(&cli, b"old-cli").unwrap();
        fs::write(&daemon, b"old-daemon").unwrap();

        let archive = b"fake archive".to_vec();
        let archive_asset = asset("rustscale-x86_64-unknown-linux-gnu.tar.gz");
        let checksum_asset = asset("SHA256SUMS");
        let digest = format!("{:x}", Sha256::digest(&archive));
        let mut downloads = FakeDownloader::default();
        downloads
            .values
            .insert(archive_asset.browser_download_url.clone(), archive);
        downloads.values.insert(
            checksum_asset.browser_download_url.clone(),
            format!("{digest}  {}\n", archive_asset.name).into_bytes(),
        );
        let lookup = FakeLookup(vec![release("v1.2.0", false)]);
        let commands = ExtractingRunner;
        let filesystem = FailingFs {
            inner: SystemFileSystem,
            replaces: AtomicUsize::new(0),
            fail_second: true,
        };
        let updater = ReleaseUpdater::new(
            "1.0.0",
            linux(),
            InstallMethod::Archive {
                rustscale: cli.clone(),
                rustscaled: daemon.clone(),
            },
            &lookup,
            &downloads,
            &commands,
            &filesystem,
        );
        let error = updater
            .execute(VersionSelector::Track(Track::Stable), false, |_| true)
            .unwrap_err();
        assert!(matches!(error, UpdateError::Preserved(_)));
        assert_eq!(fs::read(cli).unwrap(), b"old-cli");
        assert_eq!(fs::read(daemon).unwrap(), b"old-daemon");
    }

    #[cfg(unix)]
    #[test]
    fn archive_update_replaces_both_binaries_and_preserves_modes() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let cli = temp.path().join("rustscale");
        let daemon = temp.path().join("rustscaled");
        fs::write(&cli, b"old-cli").unwrap();
        fs::write(&daemon, b"old-daemon").unwrap();
        fs::set_permissions(&cli, fs::Permissions::from_mode(0o751)).unwrap();
        fs::set_permissions(&daemon, fs::Permissions::from_mode(0o750)).unwrap();

        let archive = b"fake archive".to_vec();
        let archive_asset = asset("rustscale-x86_64-unknown-linux-gnu.tar.gz");
        let checksum_asset = asset("SHA256SUMS");
        let digest = format!("{:x}", Sha256::digest(&archive));
        let mut downloads = FakeDownloader::default();
        downloads
            .values
            .insert(archive_asset.browser_download_url.clone(), archive);
        downloads.values.insert(
            checksum_asset.browser_download_url.clone(),
            format!("{digest}  {}\n", archive_asset.name).into_bytes(),
        );
        let lookup = FakeLookup(vec![release("v1.2.0", false)]);
        let commands = ExtractingRunner;
        let filesystem = FailingFs {
            inner: SystemFileSystem,
            replaces: AtomicUsize::new(0),
            fail_second: false,
        };
        let updater = ReleaseUpdater::new(
            "1.0.0",
            linux(),
            InstallMethod::Archive {
                rustscale: cli.clone(),
                rustscaled: daemon.clone(),
            },
            &lookup,
            &downloads,
            &commands,
            &filesystem,
        );
        let (_, outcome) = updater
            .execute(VersionSelector::Track(Track::Stable), false, |_| true)
            .unwrap();
        assert_eq!(outcome, UpdateOutcome::Applied);
        assert_eq!(fs::read(&cli).unwrap(), b"new-cli");
        assert_eq!(fs::read(&daemon).unwrap(), b"new-daemon");
        assert_eq!(
            fs::metadata(cli).unwrap().permissions().mode() & 0o777,
            0o751
        );
        assert_eq!(
            fs::metadata(daemon).unwrap().permissions().mode() & 0o777,
            0o750
        );
    }

    #[test]
    fn rejects_unsafe_or_incomplete_archives() {
        assert!(validate_archive_listing(b"./\n./rustscale\n./rustscaled\n./LICENSE\n").is_ok());
        assert!(validate_archive_listing(b"rustscale\nrustscaled\nLICENSE\n").is_ok());
        assert!(validate_archive_listing(b"../rustscale\nrustscaled\n").is_err());
        assert!(validate_archive_listing(b"rustscale\n").is_err());
        assert!(validate_archive_listing(b"rustscale\nrustscale\nrustscaled\n").is_err());
    }
}
