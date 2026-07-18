#![cfg(unix)]

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use flate2::{write::GzEncoder, Compression};
use rustscale_clientupdate::{
    asset_name, Download, Downloader, GitHubRelease, InstallMethod, Platform, ReleaseAsset,
    ReleaseLookup, ReleaseUpdater, SystemCommandRunner, SystemFileSystem, UpdateError,
    VersionSelector,
};
use sha2::{Digest, Sha256};

const CURRENT_VERSION: &str = "1.0.0";
const TARGET_VERSION: &str = "1.2.0";
const RECEIPT_NAME: &str = ".rustscale-install-receipt-v1";
const TAR_BLOCK: usize = 512;

struct FixtureSource {
    release: GitHubRelease,
    downloads: HashMap<String, Vec<u8>>,
}

impl ReleaseLookup for FixtureSource {
    fn releases(&self) -> Result<Vec<GitHubRelease>, UpdateError> {
        Ok(vec![self.release.clone()])
    }

    fn release_by_tag(&self, tag: &str) -> Result<GitHubRelease, UpdateError> {
        if self.release.tag_name == tag {
            Ok(self.release.clone())
        } else {
            Err(UpdateError::ReleaseNotFound(tag.to_owned()))
        }
    }
}

impl Downloader for FixtureSource {
    fn download(&self, url: &str, max_size: usize) -> Result<Download, UpdateError> {
        let bytes = self
            .downloads
            .get(url)
            .cloned()
            .ok_or_else(|| UpdateError::Download(format!("unexpected fixture URL {url}")))?;
        if bytes.len() > max_size {
            return Err(UpdateError::Download(
                "fixture exceeded caller limit".into(),
            ));
        }
        Ok(Download {
            sha256: sha256(&bytes),
            bytes,
        })
    }
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn asset(tag: &str, name: &str) -> ReleaseAsset {
    ReleaseAsset {
        name: name.to_owned(),
        browser_download_url: format!(
            "https://github.com/rajsinghtech/rustscale/releases/download/{tag}/{name}"
        ),
    }
}

fn fixture_source(platform: Platform, cli: &[u8], daemon: &[u8]) -> FixtureSource {
    let tag = format!("v{TARGET_VERSION}");
    let archive_name = asset_name(platform).expect("test platform has a release asset");
    let archive_asset = asset(&tag, archive_name);
    let sums_asset = asset(&tag, "SHA256SUMS");
    let archive = archive(&[("rustscale", cli), ("rustscaled", daemon)]);
    let sums = format!("{}  {archive_name}\n", sha256(&archive)).into_bytes();
    let downloads = HashMap::from([
        (archive_asset.browser_download_url.clone(), archive),
        (sums_asset.browser_download_url.clone(), sums),
    ]);
    FixtureSource {
        release: GitHubRelease {
            tag_name: tag,
            draft: false,
            prerelease: false,
            assets: vec![archive_asset, sums_asset],
        },
        downloads,
    }
}

fn archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut tar = Vec::new();
    for (name, body) in entries {
        let mut header = [0_u8; TAR_BLOCK];
        header[..name.len()].copy_from_slice(name.as_bytes());
        write_octal(&mut header[100..108], 0o755);
        write_octal(&mut header[108..116], 0);
        write_octal(&mut header[116..124], 0);
        write_octal(&mut header[124..136], body.len());
        write_octal(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum: usize = header.iter().map(|byte| usize::from(*byte)).sum();
        write_octal(&mut header[148..156], checksum);
        tar.extend_from_slice(&header);
        tar.extend_from_slice(body);
        tar.resize(tar.len().div_ceil(TAR_BLOCK) * TAR_BLOCK, 0);
    }
    tar.extend_from_slice(&[0_u8; TAR_BLOCK * 2]);

    let mut gzip = GzEncoder::new(Vec::new(), Compression::fast());
    gzip.write_all(&tar).unwrap();
    gzip.finish().unwrap()
}

fn write_octal(field: &mut [u8], value: usize) {
    field.fill(b'0');
    let text = format!("{value:o}");
    let start = field.len() - text.len() - 1;
    field[start..start + text.len()].copy_from_slice(text.as_bytes());
    field[field.len() - 1] = 0;
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
}

fn version_script(output: &str) -> Vec<u8> {
    format!("#!/bin/sh\nprintf '%s\\n' {output:?}\n").into_bytes()
}

fn staged_then_bad_installed_script(invocations: &Path) -> Vec<u8> {
    format!(
        "#!/bin/sh\nprintf '%s\\n' \"$0\" >> {}\ncase \"$0\" in\n  *.new) printf '%s\\n' {TARGET_VERSION:?} ;;\n  *) printf '%s\\n' {:?} ;;\nesac\n",
        shell_quote(invocations),
        "1.2.9"
    )
    .into_bytes()
}

fn staged_daemon_script(invocations: &Path) -> Vec<u8> {
    format!(
        "#!/bin/sh\nprintf '%s\\n' \"$0\" >> {}\nprintf 'rustscaled %s\\n' {TARGET_VERSION:?}\n",
        shell_quote(invocations)
    )
    .into_bytes()
}

fn write_executable(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn receipt(cli: &[u8], daemon: &[u8]) -> Vec<u8> {
    format!(
        "rustscale-install-receipt-v1\ninstaller=scripts/install.sh\nrustscale_sha256={}\nrustscaled_sha256={}\n",
        sha256(cli),
        sha256(daemon)
    )
    .into_bytes()
}

fn run_version(path: &Path) -> (i32, Vec<u8>, Vec<u8>) {
    let output = Command::new(path).arg("--version").output().unwrap();
    (output.status.code().unwrap(), output.stdout, output.stderr)
}

#[test]
fn real_version_process_failure_rolls_back_and_cleans_transaction_state() {
    let temp = tempfile::tempdir().unwrap();
    let bin = temp.path().join("installation/bin");
    fs::create_dir_all(&bin).unwrap();
    let cli_path = bin.join("rustscale");
    let daemon_path = bin.join("rustscaled");
    let receipt_path = bin.join(RECEIPT_NAME);
    let invocations = temp.path().join("version-processes.log");

    let old_cli = version_script(CURRENT_VERSION);
    let old_daemon = version_script(&format!("rustscaled {CURRENT_VERSION}"));
    let old_receipt = receipt(&old_cli, &old_daemon);
    write_executable(&cli_path, &old_cli);
    write_executable(&daemon_path, &old_daemon);
    fs::write(&receipt_path, &old_receipt).unwrap();
    fs::set_permissions(&receipt_path, fs::Permissions::from_mode(0o600)).unwrap();

    assert_eq!(run_version(&cli_path), (0, b"1.0.0\n".to_vec(), Vec::new()));
    assert_eq!(
        run_version(&daemon_path),
        (0, b"rustscaled 1.0.0\n".to_vec(), Vec::new())
    );

    let platform = Platform::current();
    let new_cli = staged_then_bad_installed_script(&invocations);
    let new_daemon = staged_daemon_script(&invocations);
    let source = fixture_source(platform, &new_cli, &new_daemon);
    let updater = ReleaseUpdater::new(
        CURRENT_VERSION,
        platform,
        InstallMethod::Archive {
            rustscale: cli_path.clone(),
            rustscaled: daemon_path.clone(),
            receipt: receipt_path.clone(),
        },
        &source,
        &source,
        &SystemCommandRunner,
        &SystemFileSystem,
    );

    let error = updater
        .execute(
            VersionSelector::Version(TARGET_VERSION.into()),
            false,
            |_| true,
        )
        .unwrap_err();
    let UpdateError::Preserved(detail) = error else {
        panic!("expected a safely preserved update, got {error}");
    };
    assert!(detail.contains("installed version verification failed"));
    assert!(detail.contains("all committed replacements were restored"));

    assert_eq!(fs::read(&cli_path).unwrap(), old_cli);
    assert_eq!(fs::read(&daemon_path).unwrap(), old_daemon);
    assert_eq!(fs::read(&receipt_path).unwrap(), old_receipt);
    assert_eq!(run_version(&cli_path), (0, b"1.0.0\n".to_vec(), Vec::new()));
    assert_eq!(
        run_version(&daemon_path),
        (0, b"rustscaled 1.0.0\n".to_vec(), Vec::new())
    );

    let invoked = fs::read_to_string(&invocations).unwrap();
    let lines = invoked.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 3, "unexpected verifier processes: {lines:?}");
    assert!(lines[0].ends_with("/rustscale.new"));
    assert!(lines[1].ends_with("/rustscaled.new"));
    assert_eq!(PathBuf::from(lines[2]), cli_path);
    assert!(
        fs::read_dir(&bin).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".rustscale-update-")
        }),
        "successful rollback must remove its journal/work directory"
    );
}
