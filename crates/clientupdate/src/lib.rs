//! Fail-closed client-update planning and application for RustScale releases.
//!
//! Release assets are selected from the canonical RustScale GitHub repository.
//! `SHA256SUMS` verifies same-release download integrity; it is not an
//! independently signed authenticity statement. Offline signed manifests are
//! deferred until the public release pipeline has a reproducible signing-key
//! design.

#![forbid(unsafe_code)]

mod archive;
mod http;
mod install;

use std::collections::BTreeMap;
use std::path::PathBuf;

use rustscale_tailcfg::ClientVersion;
use semver::Version;
use serde::Deserialize;

pub use http::HttpClient;
pub use install::{
    detect_install_method, CommandRunner, FileSystem, SystemCommandRunner, SystemFileSystem,
};

pub const GITHUB_RELEASES_API: &str =
    "https://api.github.com/repos/rajsinghtech/rustscale/releases?per_page=100";
pub const GITHUB_RELEASES_PAGE: &str = "https://github.com/rajsinghtech/rustscale/releases";
const MAX_CHECKSUM_BYTES: usize = 1024 * 1024;

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

#[derive(Clone, Debug, Default)]
pub struct UpdateArguments {
    pub version: String,
    pub track: Option<Track>,
    pub for_auto_update: bool,
}

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

pub fn parse_github_release(json: &[u8]) -> Result<GitHubRelease, UpdateError> {
    serde_json::from_slice(json).map_err(|error| UpdateError::ReleaseLookup(error.to_string()))
}

pub trait ReleaseLookup: Send + Sync {
    fn releases(&self) -> Result<Vec<GitHubRelease>, UpdateError>;
    /// Fetch one tag directly so explicit versions are not constrained by list
    /// pagination.
    fn release_by_tag(&self, tag: &str) -> Result<GitHubRelease, UpdateError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Download {
    pub bytes: Vec<u8>,
    pub sha256: String,
}

pub trait Downloader: Send + Sync {
    fn download(&self, url: &str, max_size: usize) -> Result<Download, UpdateError>;
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
    if is_release_candidate(&pre) {
        Some(Track::ReleaseCandidate)
    } else {
        Some(Track::Unstable)
    }
}

pub(crate) fn parse_version(value: &str) -> Result<Version, UpdateError> {
    Version::parse(value.strip_prefix('v').unwrap_or(value)).map_err(|_| {
        UpdateError::InvalidVersion(format!(
            "{value:?} is not a RustScale release version (expected x.y.z or vX.Y.Z)"
        ))
    })
}

fn is_release_candidate(pre: &str) -> bool {
    pre.starts_with("rc") || pre.contains(".rc")
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
            let pre = version.pre.as_str().to_ascii_lowercase();
            let included = match selector {
                VersionSelector::Version(_) => requested.as_ref() == Some(&version),
                VersionSelector::Track(Track::Stable) => {
                    !release.prerelease && version.pre.is_empty()
                }
                VersionSelector::Track(Track::ReleaseCandidate) => {
                    (!release.prerelease && version.pre.is_empty())
                        || (release.prerelease && is_release_candidate(&pre))
                }
                VersionSelector::Track(Track::Unstable) => {
                    release.prerelease && !version.pre.is_empty() && !is_release_candidate(&pre)
                }
            };
            included.then_some((version, release))
        })
        .max_by(|(left, _), (right, _)| left.cmp(right))
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
        (OperatingSystem::Linux, Architecture::X86_64, Libc::Gnu) => {
            Ok("rustscale-x86_64-unknown-linux-gnu.tar.gz")
        }
        (OperatingSystem::Linux, Architecture::Aarch64, Libc::Gnu) => {
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
    validate_asset_url(&release.tag_name, asset)?;
    Ok(asset)
}

pub fn validate_asset_url(tag: &str, asset: &ReleaseAsset) -> Result<(), UpdateError> {
    let version = parse_version(tag)?;
    let canonical_tag = format!("v{version}");
    if tag != canonical_tag {
        return Err(UpdateError::ReleaseLookup(format!(
            "release tag {tag:?} is not canonical {canonical_tag:?}"
        )));
    }
    if asset.name.is_empty()
        || asset
            .name
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(UpdateError::ReleaseLookup(format!(
            "invalid release asset name {:?}",
            asset.name
        )));
    }
    let expected = format!(
        "https://github.com/rajsinghtech/rustscale/releases/download/{tag}/{}",
        asset.name
    );
    let parsed = reqwest::Url::parse(&asset.browser_download_url)
        .map_err(|error| UpdateError::ReleaseLookup(error.to_string()))?;
    if asset.browser_download_url != expected
        || parsed.scheme() != "https"
        || parsed.host_str() != Some("github.com")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(UpdateError::ReleaseLookup(format!(
            "release {tag} returned an untrusted or cross-tag URL for {}",
            asset.name
        )));
    }
    Ok(())
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InstallMethod {
    Archive {
        rustscale: PathBuf,
        rustscaled: PathBuf,
        receipt: PathBuf,
    },
    /// Homebrew is intentionally planning-only until post-install ownership
    /// and version checks are robust across supported Homebrew versions.
    Homebrew {
        command: CommandSpec,
    },
    Unsupported {
        reason: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApplyPlan {
    Archive {
        archive: ReleaseAsset,
        checksums: ReleaseAsset,
        rustscale: PathBuf,
        rustscaled: PathBuf,
        receipt: PathBuf,
    },
    HomebrewPlan(CommandSpec),
    Unsupported(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdatePlan {
    pub current_version: String,
    pub target_version: String,
    pub track: Track,
    pub already_current: bool,
    pub local_is_newer: bool,
    pub apply: ApplyPlan,
}

impl UpdatePlan {
    pub fn description(&self) -> String {
        if self.already_current {
            return format!("RustScale {} is already current", self.current_version);
        }
        if self.local_is_newer {
            return format!(
                "local RustScale {} is newer than selected {}",
                self.current_version, self.target_version
            );
        }
        match &self.apply {
            ApplyPlan::Archive {
                archive,
                rustscale,
                rustscaled,
                ..
            } => format!(
                "replace receipt-owned {} and {} after integrity-checking {}",
                rustscale.display(),
                rustscaled.display(),
                archive.name
            ),
            ApplyPlan::HomebrewPlan(command) => format!(
                "planning only; would run {} {}",
                command.program,
                command.args.join(" ")
            ),
            ApplyPlan::Unsupported(reason) => format!("unsupported: {reason}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpdateOutcome {
    AlreadyCurrent,
    NewerLocal,
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
        let (release, explicit_version) = match &selector {
            VersionSelector::Version(value) => {
                let tag = format!("v{}", parse_version(value)?);
                let release = self.releases.release_by_tag(&tag)?;
                if release.tag_name != tag || release.draft {
                    return Err(UpdateError::ReleaseNotFound(format!("version {value}")));
                }
                (release, true)
            }
            VersionSelector::Track(_) => {
                let releases = self.releases.releases()?;
                (select_release(&releases, &selector)?, false)
            }
        };
        let target = parse_version(&release.tag_name)?;
        let current = parse_version(&self.current_version)?;
        let track = match selector {
            VersionSelector::Track(track) => track,
            VersionSelector::Version(_) => version_to_track(&release.tag_name)
                .ok_or_else(|| UpdateError::InvalidVersion(release.tag_name.clone()))?,
        };
        let current_track = version_to_track(&self.current_version);
        let current_is_on_selected_track = match track {
            Track::ReleaseCandidate => {
                matches!(current_track, Some(Track::Stable | Track::ReleaseCandidate))
            }
            _ => current_track == Some(track),
        };
        let already_current = target == current;
        let local_is_newer = !explicit_version && current_is_on_selected_track && target < current;

        let apply = if already_current || local_is_newer {
            ApplyPlan::Unsupported("no replacement is needed".into())
        } else {
            match &self.install_method {
                InstallMethod::Archive {
                    rustscale,
                    rustscaled,
                    receipt,
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
                            receipt: receipt.clone(),
                        }
                    }
                }
                InstallMethod::Homebrew { command } => {
                    if explicit_version || track != Track::Stable || target < current {
                        ApplyPlan::Unsupported(
                            "Homebrew planning supports only non-downgrade latest-stable checks"
                                .into(),
                        )
                    } else {
                        ApplyPlan::HomebrewPlan(command.clone())
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
            local_is_newer,
            apply,
        })
    }

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
        if plan.local_is_newer {
            return Ok((plan, UpdateOutcome::NewerLocal));
        }
        if dry_run {
            return Ok((plan, UpdateOutcome::DryRun));
        }
        if matches!(
            plan.apply,
            ApplyPlan::Unsupported(_) | ApplyPlan::HomebrewPlan(_)
        ) {
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
                receipt,
            } => {
                let expected_archive = asset_name(self.platform)?;
                if archive.name != expected_archive || checksums.name != "SHA256SUMS" {
                    return Err(UpdateError::Unsupported(
                        "release plan assets do not match the current platform".into(),
                    ));
                }
                let tag = format!("v{}", parse_version(&plan.target_version)?);
                validate_asset_url(&tag, archive)?;
                validate_asset_url(&tag, checksums)?;
                let checksums_download = self
                    .downloader
                    .download(&checksums.browser_download_url, MAX_CHECKSUM_BYTES)?;
                let archive_download = self
                    .downloader
                    .download(&archive.browser_download_url, archive::MAX_ARCHIVE_BYTES)?;
                verify_checksum_digest(
                    &archive.name,
                    &archive_download.sha256,
                    &checksums_download.bytes,
                )?;
                let payloads = archive::extract_binaries(&archive_download.bytes)?;
                install::apply_archive_transaction(
                    self.filesystem,
                    self.commands,
                    &payloads,
                    &plan.target_version,
                    rustscale,
                    rustscaled,
                    receipt,
                )?;
                Ok(UpdateOutcome::Applied)
            }
            ApplyPlan::HomebrewPlan(command) => Err(UpdateError::Unsupported(format!(
                "Homebrew apply is disabled pending robust post-install verification; run the reviewed plan manually: {} {}",
                command.program,
                command.args.join(" ")
            ))),
            ApplyPlan::Unsupported(reason) => Err(UpdateError::Unsupported(reason.clone())),
        }
    }
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
            || name.contains(['/', '\\', '\n', '\r'])
            || fields.next().is_some()
            || checksums.contains_key(name)
        {
            return Err(UpdateError::Checksum(format!(
                "malformed or duplicate SHA256SUMS line {}",
                index + 1
            )));
        }
        checksums.insert(name.to_owned(), digest.to_ascii_lowercase());
    }
    Ok(checksums)
}

pub fn verify_checksum(name: &str, data: &[u8], sums: &[u8]) -> Result<(), UpdateError> {
    use sha2::{Digest, Sha256};
    verify_checksum_digest(name, &format!("{:x}", Sha256::digest(data)), sums)
}

fn verify_checksum_digest(name: &str, actual: &str, sums: &[u8]) -> Result<(), UpdateError> {
    let expected = parse_checksums(sums)?
        .remove(name)
        .ok_or_else(|| UpdateError::Checksum(format!("SHA256SUMS has no entry for {name}")))?;
    if actual == expected {
        Ok(())
    } else {
        Err(UpdateError::Checksum(format!(
            "checksum mismatch for {name}: expected {expected}, got {actual}"
        )))
    }
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
    #[error("checksum integrity verification failed: {0}")]
    Checksum(String),
    #[error("unsafe release archive: {0}")]
    UnsafeArchive(String),
    #[error("command failed: {0}")]
    Command(String),
    #[error("installed version verification failed: {0}")]
    VersionVerification(String),
    #[error("filesystem operation failed: {0}")]
    FileSystem(String),
    #[error("update is unsupported: {0}")]
    Unsupported(String),
    #[error("update failed safely: {0}")]
    Preserved(String),
    #[error("update failed ({update}) and rollback also failed ({rollback}); recovery journal and backups retained at {recovery}")]
    RollbackFailed {
        update: String,
        rollback: String,
        recovery: PathBuf,
    },
    #[error("update check failed: {0}")]
    CheckFailed(String),
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    use sha2::Digest;

    use super::*;

    fn asset(tag: &str, name: &str) -> ReleaseAsset {
        ReleaseAsset {
            name: name.into(),
            browser_download_url: format!(
                "https://github.com/rajsinghtech/rustscale/releases/download/{tag}/{name}"
            ),
        }
    }

    fn release(tag: &str, prerelease: bool) -> GitHubRelease {
        GitHubRelease {
            tag_name: tag.into(),
            draft: false,
            prerelease,
            assets: vec![
                asset(tag, "rustscale-x86_64-unknown-linux-gnu.tar.gz"),
                asset(tag, "rustscale-x86_64-unknown-linux-musl.tar.gz"),
                asset(tag, "rustscale-aarch64-unknown-linux-gnu.tar.gz"),
                asset(tag, "rustscale-universal-apple-darwin.tar.gz"),
                asset(tag, "rustscale-x86_64-pc-windows-msvc.zip"),
                asset(tag, "SHA256SUMS"),
            ],
        }
    }

    #[test]
    fn mixed_tracks_select_expected_release_sets() {
        let releases = vec![
            release("v2.0.0", false),
            release("v2.1.0-rc.2", true),
            release("v2.1.0-beta.3", true),
        ];
        assert_eq!(
            select_release(&releases, &VersionSelector::Track(Track::Stable))
                .unwrap()
                .tag_name,
            "v2.0.0"
        );
        assert_eq!(
            select_release(&releases, &VersionSelector::Track(Track::ReleaseCandidate))
                .unwrap()
                .tag_name,
            "v2.1.0-rc.2"
        );
        assert_eq!(
            select_release(&releases, &VersionSelector::Track(Track::Unstable))
                .unwrap()
                .tag_name,
            "v2.1.0-beta.3"
        );
        assert!(select_release(
            &[release("v2.0.0", false), release("v2.1.0-rc.1", true)],
            &VersionSelector::Track(Track::Unstable)
        )
        .is_err());
    }

    #[test]
    fn release_candidate_track_chooses_newest_stable_or_rc_semantically() {
        assert_eq!(
            select_release(
                &[
                    release("v2.1.0-rc.3", true),
                    release("v2.1.0", false),
                    release("v2.0.9", false),
                ],
                &VersionSelector::Track(Track::ReleaseCandidate),
            )
            .unwrap()
            .tag_name,
            "v2.1.0"
        );
        assert_eq!(
            select_release(
                &[release("v2.2.0", false), release("v2.3.0-rc.1", true)],
                &VersionSelector::Track(Track::ReleaseCandidate),
            )
            .unwrap()
            .tag_name,
            "v2.3.0-rc.1"
        );
        assert_eq!(
            select_release(
                &[release("v2.2.0", false)],
                &VersionSelector::Track(Track::ReleaseCandidate),
            )
            .unwrap()
            .tag_name,
            "v2.2.0"
        );
    }

    #[test]
    fn strict_asset_urls_reject_cross_tag_credentials_and_prefix_tricks() {
        let valid = asset("v1.2.3", "SHA256SUMS");
        validate_asset_url("v1.2.3", &valid).unwrap();
        for url in [
            "https://github.com/rajsinghtech/rustscale/releases/download/v1.2.4/SHA256SUMS",
            "https://user@github.com/rajsinghtech/rustscale/releases/download/v1.2.3/SHA256SUMS",
            "https://github.com.evil/rajsinghtech/rustscale/releases/download/v1.2.3/SHA256SUMS",
            "http://github.com/rajsinghtech/rustscale/releases/download/v1.2.3/SHA256SUMS",
        ] {
            let mut changed = valid.clone();
            changed.browser_download_url = url.into();
            assert!(validate_asset_url("v1.2.3", &changed).is_err());
        }
    }

    #[derive(Clone)]
    struct FakeLookup {
        releases: Vec<GitHubRelease>,
        tags: HashMap<String, GitHubRelease>,
        list_calls: std::sync::Arc<AtomicUsize>,
        tag_calls: std::sync::Arc<AtomicUsize>,
    }

    impl ReleaseLookup for FakeLookup {
        fn releases(&self) -> Result<Vec<GitHubRelease>, UpdateError> {
            self.list_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.releases.clone())
        }
        fn release_by_tag(&self, tag: &str) -> Result<GitHubRelease, UpdateError> {
            self.tag_calls.fetch_add(1, Ordering::SeqCst);
            self.tags
                .get(tag)
                .cloned()
                .ok_or_else(|| UpdateError::ReleaseNotFound(tag.into()))
        }
    }

    struct NoDownloads(AtomicUsize);
    impl Downloader for NoDownloads {
        fn download(&self, _url: &str, _max: usize) -> Result<Download, UpdateError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(UpdateError::Download("unexpected".into()))
        }
    }

    #[derive(Default)]
    struct NoCommands;
    impl CommandRunner for NoCommands {
        fn run(&self, _command: &CommandSpec) -> Result<CommandOutput, UpdateError> {
            Err(UpdateError::Command("unexpected".into()))
        }
    }

    fn lookup() -> FakeLookup {
        let stable = release("v1.2.0", false);
        FakeLookup {
            releases: vec![stable.clone()],
            tags: HashMap::from([("v1.2.0".into(), stable)]),
            list_calls: Arc::default(),
            tag_calls: Arc::default(),
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
    fn explicit_versions_use_tag_endpoint_not_paginated_list() {
        let lookup = lookup();
        let downloads = NoDownloads(AtomicUsize::new(0));
        let filesystem = SystemFileSystem;
        let updater = ReleaseUpdater::new(
            "1.0.0",
            linux(),
            InstallMethod::Unsupported {
                reason: "test".into(),
            },
            &lookup,
            &downloads,
            &NoCommands,
            &filesystem,
        );
        updater
            .plan(VersionSelector::Version("1.2.0".into()))
            .unwrap();
        assert_eq!(lookup.tag_calls.load(Ordering::SeqCst), 1);
        assert_eq!(lookup.list_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn aarch64_musl_is_unsupported_during_planning() {
        let lookup = lookup();
        let downloads = NoDownloads(AtomicUsize::new(0));
        let filesystem = SystemFileSystem;
        let updater = ReleaseUpdater::new(
            "1.0.0",
            Platform {
                os: OperatingSystem::Linux,
                arch: Architecture::Aarch64,
                libc: Libc::Musl,
            },
            InstallMethod::Archive {
                rustscale: "/prefix/bin/rustscale".into(),
                rustscaled: "/prefix/bin/rustscaled".into(),
                receipt: "/prefix/bin/.rustscale-install-receipt-v1".into(),
            },
            &lookup,
            &downloads,
            &NoCommands,
            &filesystem,
        );
        assert!(matches!(
            updater.plan(VersionSelector::Track(Track::Stable)),
            Err(UpdateError::Unsupported(_))
        ));
        assert_eq!(downloads.0.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn dry_run_and_confirmation_do_not_mutate() {
        let lookup = lookup();
        let downloads = NoDownloads(AtomicUsize::new(0));
        let filesystem = SystemFileSystem;
        let updater = ReleaseUpdater::new(
            "1.0.0",
            linux(),
            InstallMethod::Homebrew {
                command: CommandSpec {
                    program: "/opt/homebrew/bin/brew".into(),
                    args: vec![
                        "upgrade".into(),
                        "--formula".into(),
                        "rajsinghtech/tap/rustscale".into(),
                    ],
                },
            },
            &lookup,
            &downloads,
            &NoCommands,
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
        assert_eq!(downloads.0.load(Ordering::SeqCst), 0);
        let error = updater
            .execute(VersionSelector::Track(Track::Stable), false, |_| true)
            .unwrap_err();
        assert!(matches!(error, UpdateError::Unsupported(_)));
    }

    #[test]
    fn newer_local_is_not_called_current() {
        let lookup = lookup();
        let downloads = NoDownloads(AtomicUsize::new(0));
        let filesystem = SystemFileSystem;
        let updater = ReleaseUpdater::new(
            "1.4.0",
            linux(),
            InstallMethod::Unsupported {
                reason: "test".into(),
            },
            &lookup,
            &downloads,
            &NoCommands,
            &filesystem,
        );
        let (plan, outcome) = updater
            .execute(VersionSelector::Track(Track::Stable), true, |_| true)
            .unwrap();
        assert!(plan.local_is_newer);
        assert_eq!(outcome, UpdateOutcome::NewerLocal);
        assert!(plan.description().contains("newer than selected"));
    }

    #[test]
    fn release_candidate_track_does_not_downgrade_newer_stable_client() {
        let lookup = FakeLookup {
            releases: vec![release("v2.0.0", false), release("v2.1.0-rc.1", true)],
            tags: HashMap::new(),
            list_calls: Arc::default(),
            tag_calls: Arc::default(),
        };
        let downloads = NoDownloads(AtomicUsize::new(0));
        let filesystem = SystemFileSystem;
        let updater = ReleaseUpdater::new(
            "2.2.0",
            linux(),
            InstallMethod::Unsupported {
                reason: "test".into(),
            },
            &lookup,
            &downloads,
            &NoCommands,
            &filesystem,
        );
        let (plan, outcome) = updater
            .execute(
                VersionSelector::Track(Track::ReleaseCandidate),
                true,
                |_| true,
            )
            .unwrap();
        assert_eq!(plan.target_version, "2.1.0-rc.1");
        assert!(plan.local_is_newer);
        assert_eq!(outcome, UpdateOutcome::NewerLocal);
        assert_eq!(downloads.0.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn checksum_integrity_verification_rejects_duplicates_and_mismatch() {
        let data = b"archive";
        let digest = format!("{:x}", sha2::Sha256::digest(data));
        verify_checksum(
            "archive.tar.gz",
            data,
            format!("{digest}  archive.tar.gz\n").as_bytes(),
        )
        .unwrap();
        assert!(verify_checksum(
            "archive.tar.gz",
            b"bad",
            format!("{digest}  archive.tar.gz\n").as_bytes()
        )
        .is_err());
        assert!(parse_checksums(
            format!("{digest}  archive.tar.gz\n{digest}  archive.tar.gz\n").as_bytes()
        )
        .is_err());
    }

    #[test]
    fn platform_assets_match_release_pipeline() {
        assert_eq!(
            asset_name(linux()).unwrap(),
            "rustscale-x86_64-unknown-linux-gnu.tar.gz"
        );
        assert_eq!(
            asset_name(Platform {
                os: OperatingSystem::Linux,
                arch: Architecture::X86_64,
                libc: Libc::Musl
            })
            .unwrap(),
            "rustscale-x86_64-unknown-linux-musl.tar.gz"
        );
        assert_eq!(
            asset_name(Platform {
                os: OperatingSystem::Linux,
                arch: Architecture::Aarch64,
                libc: Libc::Gnu
            })
            .unwrap(),
            "rustscale-aarch64-unknown-linux-gnu.tar.gz"
        );
        assert!(matches!(
            asset_name(Platform {
                os: OperatingSystem::Linux,
                arch: Architecture::Aarch64,
                libc: Libc::Musl,
            }),
            Err(UpdateError::Unsupported(_))
        ));
        assert_eq!(
            asset_name(Platform {
                os: OperatingSystem::MacOs,
                arch: Architecture::Aarch64,
                libc: Libc::Other
            })
            .unwrap(),
            "rustscale-universal-apple-darwin.tar.gz"
        );
    }
}
