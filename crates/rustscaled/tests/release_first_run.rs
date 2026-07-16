//! Installed Linux first-run release contract.
//!
//! This is intentionally an ignored test: it binds the real default LocalAPI
//! path, starts a root-owned daemon through sudo, and switches to `nobody` to
//! verify kernel-supplied Unix peer credentials. `tools/packaging/test-first-run.sh`
//! is the only supported entry point and runs it serially in CI.

#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use rustscale_testcontrol::Server as TestControl;

const DEFAULT_SOCKET: &str = "/var/run/rustscaled.sock";
const ARCHIVE: &str = "rustscale-x86_64-unknown-linux-gnu.tar.gz";

/// Exercise the installed, root-daemon first-run journey against only local
/// infrastructure. This is the release acceptance test, not a unit test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Linux, passwordless sudo, and exclusive /var/run/rustscaled.sock"]
async fn installed_first_run_journey() {
    require_sudo_and_exclusive_socket();
    if let Some(path) = std::env::var_os("RUSTSCALE_SOCKET_OWNERSHIP_FILE") {
        fs::write(path, b"owned\n").expect("record exclusive test socket ownership");
    }

    let mut control = TestControl::new();
    control.start().await.expect("start RustScale testcontrol");
    control.set_require_auth(true);

    let mut fixture = Fixture::install(&control.base_url());

    fixture.start_daemon();
    fixture.wait_for_operator_status("NeedsLogin");

    // Follow the documented one-time privileged setup instead of preloading
    // an operator in configuration. This proves the shipped CLI flag, live
    // preference update, NSS resolution, and subsequent non-root access.
    let operator = current_username();
    let configured = fixture.root_cli(&["set", "--operator", operator.as_str()]);
    assert!(
        configured.status.success(),
        "root could not configure the ordinary operator: {}",
        output_text(&configured)
    );

    // `nobody` is not the configured operator. Its GET succeeds, but its
    // mutating request receives a LocalAPI 403 from the real SO_PEERCRED path.
    let readonly = fixture.cli_as_nobody(&["status", "--json"]);
    assert!(
        readonly.status.success(),
        "unrelated user must retain read-only status access: {}",
        output_text(&readonly)
    );
    let denied = fixture.cli_as_nobody(&["logout"]);
    assert!(
        !denied.status.success(),
        "unrelated user unexpectedly mutated LocalAPI: {}",
        output_text(&denied)
    );
    assert!(
        output_text(&denied).contains("access denied"),
        "unrelated mutation did not fail closed: {}",
        output_text(&denied)
    );

    // `up` sends Start and LoginInteractive before the fake browser is
    // completed. Keep the completion deliberately delayed: a successful 204
    // acknowledgement must not mean that auth has already completed.
    let mut up = fixture.spawn_operator_cli(&["up", "--timeout", "45"]);
    let auth_url = wait_for_auth_url(&control, &mut up).await;
    assert!(
        up.try_wait().expect("poll rustscale up").is_none(),
        "rustscale up completed before fake browser auth: {auth_url}"
    );
    assert!(
        control.complete_auth(&auth_url),
        "fake browser could not complete the issued auth URL"
    );
    let up_result = wait_for_child(&mut up, Duration::from_secs(45));
    assert!(
        up_result.success(),
        "configured operator could not complete start/login: {up_result:?}"
    );
    fixture.wait_for_operator_status("Running");

    // A service restart must restore the persisted profile without another
    // Start/LoginInteractive interaction.
    fixture.stop_daemon();
    fixture.cleanup_socket();
    fixture.start_daemon();
    fixture.wait_for_operator_status("Running");

    let node_key = control
        .all_nodes()
        .into_iter()
        .next()
        .expect("testcontrol registered the installed daemon")
        .Key;
    let logout = fixture.operator_cli(&["logout"]);
    assert!(
        logout.status.success(),
        "configured operator logout failed: {}",
        output_text(&logout)
    );
    fixture.wait_for_daemon_exit();
    assert!(
        control.saw_logout(&node_key),
        "logout did not reach RustScale testcontrol"
    );
    fixture.cleanup_socket();
    fixture.cleanup_state();
    fixture.uninstall();
}

struct Fixture {
    _root: tempfile::TempDir,
    prefix: PathBuf,
    state: PathBuf,
    config: PathBuf,
    cli: PathBuf,
    daemon: PathBuf,
    daemon_child: Option<Child>,
    daemon_pgid_file: Option<PathBuf>,
}

impl Fixture {
    fn install(control_url: &str) -> Self {
        let root = if let Some(parent) = std::env::var_os("RUSTSCALE_FIXTURE_PARENT") {
            fs::create_dir_all(&parent).expect("create watchdog-owned fixture parent");
            tempfile::tempdir_in(parent).expect("create release fixture")
        } else {
            tempfile::tempdir().expect("create release fixture")
        };
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755))
            .expect("make fixture traversable for nobody");

        let release = root
            .path()
            .join("releases/download")
            .join(format!("v{}", env!("CARGO_PKG_VERSION")));
        let stage = root.path().join("stage");
        let prefix = root.path().join("installed");
        let state = root.path().join("state");
        let config = root.path().join("rustscale.json");
        fs::create_dir_all(&release).expect("create local release directory");
        fs::create_dir_all(&stage).expect("create archive stage");

        let cli = release_binary("RUSTSCALE_RELEASE_CLI", "rustscale");
        let daemon = release_binary("RUSTSCALE_RELEASE_DAEMON", "rustscaled");
        copy_executable(&cli, &stage.join("rustscale"));
        copy_executable(&daemon, &stage.join("rustscaled"));
        fs::copy(workspace_root().join("LICENSE"), stage.join("LICENSE")).expect("stage license");
        fs::copy(
            workspace_root().join("packaging/systemd/rustscaled.service"),
            stage.join("rustscaled.service"),
        )
        .expect("stage systemd unit");
        fs::copy(
            workspace_root().join("packaging/systemd/rustscaled.default"),
            stage.join("rustscaled.default"),
        )
        .expect("stage systemd defaults");

        let archive = release.join(ARCHIVE);
        run_success(
            Command::new("tar")
                .args(["--format=ustar", "-czf"])
                .arg(&archive)
                .arg("-C")
                .arg(&stage)
                .arg("."),
            "create real-binary release archive",
        );
        let checksum = sha256(&archive);
        fs::write(
            release.join("SHA256SUMS"),
            format!("{checksum}  {ARCHIVE}\n"),
        )
        .expect("write release checksums");

        fs::write(
            &config,
            format!("{{\"Version\":\"alpha0\",\"ServerURL\":{control_url:?}}}"),
        )
        .expect("write daemon configuration");

        let release_base = format!("file://{}", root.path().join("releases").display());
        let mut install = Command::new("sh");
        install
            .arg(workspace_root().join("scripts/install.sh"))
            .args(["--version", env!("CARGO_PKG_VERSION"), "--no-service"])
            .env("PREFIX", &prefix)
            .env("RUSTSCALE_RELEASE_BASE", release_base)
            .env("RUSTSCALE_UNAME_S", "Linux")
            .env("RUSTSCALE_UNAME_M", "x86_64")
            .env("RUSTSCALE_LIBC", "gnu")
            .env_remove("GH_TOKEN")
            .env_remove("GITHUB_TOKEN");
        run_success(&mut install, "install local real-binary release");

        Self {
            cli: prefix.join("bin/rustscale"),
            daemon: prefix.join("bin/rustscaled"),
            _root: root,
            prefix,
            state,
            config,
            daemon_child: None,
            daemon_pgid_file: std::env::var_os("RUSTSCALE_DAEMON_PGID_FILE").map(PathBuf::from),
        }
    }

    fn start_daemon(&mut self) {
        assert!(self.daemon_child.is_none(), "daemon already started");
        let mut command = Command::new("sudo");
        command
            .args(["-n", "--"])
            .arg(&self.daemon)
            .args(["run", "--state"])
            .arg(&self.state)
            .args(["--config"])
            .arg(&self.config)
            .arg("--no-logs-no-support")
            .env_remove("TS_AUTHKEY")
            .env_remove("TAILSCALE_AUTHKEY")
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            // One process group lets teardown signal sudo and the daemon.
            .process_group(0);
        self.daemon_child = Some(command.spawn().expect("start root daemon equivalent"));
        self.record_daemon_group();
    }

    fn stop_daemon(&mut self) {
        let Some(child) = self.daemon_child.as_mut() else {
            return;
        };
        let group = format!("-{}", child.id());
        run_success(
            Command::new("sudo").args(["-n", "kill", "-TERM", "--", &group]),
            "stop root daemon process group",
        );
        let status = wait_for_child(child, Duration::from_secs(20));
        assert!(
            status.success() || status.code().is_none(),
            "daemon stop: {status:?}"
        );
        self.daemon_child = None;
        self.clear_daemon_group_record();
    }

    fn wait_for_daemon_exit(&mut self) {
        let child = self
            .daemon_child
            .as_mut()
            .expect("daemon must still be running for logout");
        let status = wait_for_child(child, Duration::from_secs(30));
        assert!(
            status.success(),
            "daemon did not exit cleanly after logout: {status:?}"
        );
        self.daemon_child = None;
        self.clear_daemon_group_record();
    }

    fn cleanup_socket(&self) {
        run_success(
            Command::new("sudo")
                .args(["-n", "--"])
                .arg(&self.daemon)
                .args(["run", "--state"])
                .arg(&self.state)
                .arg("--cleanup"),
            "remove default LocalAPI socket",
        );
        assert!(
            !Path::new(DEFAULT_SOCKET).exists(),
            "cleanup left {DEFAULT_SOCKET} behind"
        );
    }

    fn cleanup_state(&self) {
        run_success(
            Command::new("sudo")
                .args(["-n", "rm", "-rf", "--"])
                .arg(&self.state),
            "remove root-owned temporary state",
        );
        assert!(!self.state.exists(), "cleanup left temporary state behind");
    }

    fn record_daemon_group(&self) {
        if let Some(path) = self.daemon_pgid_file.as_ref() {
            let child = self.daemon_child.as_ref().expect("daemon child recorded");
            fs::write(path, format!("{}\n", child.id())).expect("record daemon process group");
        }
    }

    fn clear_daemon_group_record(&self) {
        if let Some(path) = self.daemon_pgid_file.as_ref() {
            let _ = fs::remove_file(path);
        }
    }

    fn wait_for_operator_status(&self, expected: &str) {
        let deadline = Instant::now() + Duration::from_secs(25);
        loop {
            let output = self.operator_cli(&["status", "--json"]);
            if output.status.success()
                && serde_json::from_slice::<serde_json::Value>(&output.stdout)
                    .ok()
                    .and_then(|status| status["BackendState"].as_str().map(str::to_owned))
                    .as_deref()
                    == Some(expected)
            {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {expected}; last status: {}",
                output_text(&output)
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn spawn_operator_cli(&self, args: &[&str]) -> Child {
        let mut command = Command::new(&self.cli);
        command
            .args(args)
            .env_remove("TS_AUTHKEY")
            .env_remove("TAILSCALE_AUTHKEY")
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        command.spawn().expect("spawn installed rustscale")
    }

    fn operator_cli(&self, args: &[&str]) -> Output {
        cli_command(&self.cli, args)
            .output()
            .expect("run installed rustscale")
    }

    fn root_cli(&self, args: &[&str]) -> Output {
        let mut command = Command::new("sudo");
        command.args(["-n", "--"]).arg(&self.cli).args(args);
        command.output().expect("run rustscale as root")
    }

    fn cli_as_nobody(&self, args: &[&str]) -> Output {
        let mut command = Command::new("sudo");
        command
            .args(["-n", "-u", "nobody", "--"])
            .arg(&self.cli)
            .args(args);
        command.output().expect("run rustscale as unrelated user")
    }

    fn uninstall(&self) {
        let mut uninstall = Command::new("sh");
        uninstall
            .arg(workspace_root().join("scripts/install.sh"))
            .arg("--uninstall")
            .env("PREFIX", &self.prefix)
            .env("RUSTSCALE_UNAME_S", "Linux")
            .env("RUSTSCALE_UNAME_M", "x86_64")
            .env("RUSTSCALE_LIBC", "gnu");
        run_success(&mut uninstall, "uninstall local release");
        assert!(!self.prefix.join("bin/rustscale").exists());
        assert!(!self.prefix.join("bin/rustscaled").exists());
        assert!(!self
            .prefix
            .join("bin/.rustscale-install-receipt-v1")
            .exists());
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(mut child) = self.daemon_child.take() {
            terminate_daemon_group(&mut child);
        }
        self.clear_daemon_group_record();
        if Path::new(DEFAULT_SOCKET).exists() {
            let _ = Command::new("sudo")
                .args(["-n", "rm", "-f", "--", DEFAULT_SOCKET])
                .status();
        }
        if self.state.exists() {
            let _ = Command::new("sudo")
                .args(["-n", "rm", "-rf", "--"])
                .arg(&self.state)
                .status();
        }
    }
}

fn terminate_daemon_group(child: &mut Child) {
    let group = format!("-{}", child.id());
    let _ = Command::new("sudo")
        .args(["-n", "kill", "-TERM", "--", &group])
        .status();
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    if child.try_wait().ok().flatten().is_none() {
        let _ = Command::new("sudo")
            .args(["-n", "kill", "-KILL", "--", &group])
            .status();
        let _ = child.wait();
    }
}

fn require_sudo_and_exclusive_socket() {
    run_success(
        Command::new("sudo").args(["-n", "true"]),
        "require passwordless sudo",
    );
    assert!(
        !Path::new(DEFAULT_SOCKET).exists(),
        "refusing to touch an existing {DEFAULT_SOCKET}; run on an isolated Linux fixture"
    );
}

async fn wait_for_auth_url(control: &TestControl, child: &mut Child) -> String {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(url) = control.await_auth_url(Duration::from_millis(100)).await {
            return url;
        }
        if let Some(status) = child.try_wait().expect("poll rustscale up") {
            panic!("rustscale up exited before interactive auth URL: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for interactive auth URL"
        );
    }
}

fn wait_for_child(child: &mut Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("poll child") {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "child did not exit within {timeout:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn cli_command(cli: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(cli);
    command
        .args(args)
        .env_remove("TS_AUTHKEY")
        .env_remove("TAILSCALE_AUTHKEY");
    command
}

fn release_binary(variable: &str, binary: &str) -> PathBuf {
    let path = std::env::var_os(variable).map_or_else(
        || workspace_root().join("target/release").join(binary),
        PathBuf::from,
    );
    assert!(
        path.is_file(),
        "missing release binary {} at {}",
        binary,
        path.display()
    );
    path
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

fn current_username() -> String {
    let output = Command::new("id")
        .arg("-un")
        .output()
        .expect("resolve operator username");
    assert!(output.status.success(), "id -un failed");
    String::from_utf8(output.stdout)
        .expect("operator username utf-8")
        .trim()
        .to_owned()
}

fn copy_executable(from: &Path, to: &Path) {
    fs::copy(from, to).expect("copy release binary");
    fs::set_permissions(to, fs::Permissions::from_mode(0o755))
        .expect("make release binary executable");
}

fn sha256(path: &Path) -> String {
    let output = Command::new("sha256sum")
        .arg(path)
        .output()
        .expect("calculate archive checksum");
    assert!(
        output.status.success(),
        "sha256sum failed: {}",
        output_text(&output)
    );
    String::from_utf8(output.stdout)
        .expect("sha256sum output utf-8")
        .split_whitespace()
        .next()
        .expect("sha256sum digest")
        .to_owned()
}

fn run_success(command: &mut Command, description: &str) {
    let output = command
        .output()
        .unwrap_or_else(|error| panic!("{description}: {error}"));
    assert!(
        output.status.success(),
        "{description}: {}",
        output_text(&output)
    );
}

fn output_text(output: &Output) -> String {
    format!(
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
