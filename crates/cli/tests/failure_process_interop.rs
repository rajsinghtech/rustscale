#![cfg(unix)]

use std::fs;
use std::io::{ErrorKind, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use rustscale_safesocket::peercred::ConnIdentity;
use rustscale_safesocket::{Listener, ServerStream};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const DAEMON_MODE_ENV: &str = "RUSTSCALE_CLI_INTEROP_DAEMON_MODE";
const DAEMON_SOCKET_ENV: &str = "RUSTSCALE_CLI_INTEROP_SOCKET";
const DAEMON_CONTROL_ENV: &str = "RUSTSCALE_CLI_INTEROP_CONTROL";
const PROCESS_TIMEOUT: Duration = Duration::from_secs(8);
const READY_TIMEOUT: Duration = Duration::from_secs(5);
const ETAG_ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const ETAG_ONE: &str = "1111111111111111111111111111111111111111111111111111111111111111";

#[derive(Debug)]
struct ProcessOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

struct ManagedProcess {
    child: Option<Child>,
    stdout: tempfile::NamedTempFile,
    stderr: tempfile::NamedTempFile,
}

impl ManagedProcess {
    fn spawn(command: &mut Command, piped_stdin: bool) -> Self {
        let stdout = tempfile::NamedTempFile::new().unwrap();
        let stderr = tempfile::NamedTempFile::new().unwrap();
        command
            .stdin(if piped_stdin {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::from(stdout.reopen().unwrap()))
            .stderr(Stdio::from(stderr.reopen().unwrap()));
        let child = command.spawn().expect("spawn child process");
        Self {
            child: Some(child),
            stdout,
            stderr,
        }
    }

    fn id(&self) -> u32 {
        self.child.as_ref().expect("live child").id()
    }

    fn close_stdin_with(&mut self, bytes: &[u8]) {
        let mut stdin = self
            .child
            .as_mut()
            .expect("live child")
            .stdin
            .take()
            .expect("piped stdin");
        stdin.write_all(bytes).unwrap();
        drop(stdin);
    }

    fn signal_interrupt(&self) {
        let status = Command::new("/bin/kill")
            .args(["-INT", &self.id().to_string()])
            .status()
            .expect("send SIGINT");
        assert!(status.success(), "failed to interrupt child {}", self.id());
    }

    async fn wait(mut self, timeout: Duration) -> ProcessOutput {
        let deadline = Instant::now() + timeout;
        let status = loop {
            if let Some(status) = self
                .child
                .as_mut()
                .expect("live child")
                .try_wait()
                .expect("poll child")
            {
                break status;
            }
            if Instant::now() >= deadline {
                self.terminate();
                let stdout = read_temp(&mut self.stdout);
                let stderr = read_temp(&mut self.stderr);
                panic!(
                    "child process timed out after {timeout:?}\nstdout: {}\nstderr: {}",
                    String::from_utf8_lossy(&stdout),
                    String::from_utf8_lossy(&stderr)
                );
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        self.child.take();
        ProcessOutput {
            status,
            stdout: read_temp(&mut self.stdout),
            stderr: read_temp(&mut self.stderr),
        }
    }

    fn terminate(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for ManagedProcess {
    fn drop(&mut self) {
        self.terminate();
    }
}

fn read_temp(file: &mut tempfile::NamedTempFile) -> Vec<u8> {
    let mut bytes = Vec::new();
    file.as_file_mut().rewind().unwrap();
    file.read_to_end(&mut bytes).unwrap();
    bytes
}

fn rustscale_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rustscale"))
}

fn cli_command(socket: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(rustscale_bin());
    command
        .arg("--socket")
        .arg(socket)
        .args(args)
        .env("HTTP_PROXY", "http://127.0.0.1:1")
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .env("ALL_PROXY", "socks5://127.0.0.1:1");
    command
}

fn spawn_cli(socket: &Path, args: &[&str], piped_stdin: bool) -> ManagedProcess {
    ManagedProcess::spawn(&mut cli_command(socket, args), piped_stdin)
}

async fn run_cli(socket: &Path, args: &[&str]) -> ProcessOutput {
    spawn_cli(socket, args, false).wait(PROCESS_TIMEOUT).await
}

fn daemon_command(mode: &str, socket: &Path, control: &Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "scripted_daemon_process",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(DAEMON_MODE_ENV, mode)
        .env(DAEMON_SOCKET_ENV, socket)
        .env(DAEMON_CONTROL_ENV, control);
    command
}

async fn start_daemon(mode: &str, socket: &Path, control: &Path) -> ManagedProcess {
    fs::create_dir_all(control).unwrap();
    let process = ManagedProcess::spawn(&mut daemon_command(mode, socket, control), false);
    wait_for_file(&control.join("ready"), READY_TIMEOUT).await;
    process
}

async fn wait_for_file(path: &Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn assert_output(output: &ProcessOutput, code: i32, stdout: &[u8], stderr: &[u8]) {
    assert_eq!(
        output.status.code(),
        Some(code),
        "status: {:?}",
        output.status
    );
    assert_eq!(output.stdout, stdout, "stdout mismatch");
    assert_eq!(output.stderr, stderr, "stderr mismatch");
}

fn assert_daemon_ok(output: &ProcessOutput) {
    assert!(
        output.status.success(),
        "daemon helper failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

struct Request {
    stream: ServerStream,
    head: String,
    body: Vec<u8>,
    identity: ConnIdentity,
}

async fn accept_request(listener: &Listener) -> Request {
    tokio::time::timeout(PROCESS_TIMEOUT, async {
        let mut stream = listener.accept().await.expect("accept LocalAPI request");
        let identity = ConnIdentity::from_stream(&stream);
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            stream
                .read_exact(&mut byte)
                .await
                .expect("read request head");
            head.push(byte[0]);
            assert!(head.len() <= 64 * 1024, "request head exceeded limit");
        }
        let head = String::from_utf8(head).expect("ASCII request head");
        assert!(
            !head.to_ascii_lowercase().contains("authorization:"),
            "LocalAPI authorization must use kernel peer credentials"
        );
        let content_length = head
            .split("\r\n")
            .filter_map(|line| line.split_once(':'))
            .find_map(|(name, value)| {
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        assert!(content_length <= 1024 * 1024, "request body exceeded limit");
        let mut body = vec![0; content_length];
        stream
            .read_exact(&mut body)
            .await
            .expect("read request body");
        Request {
            stream,
            head,
            body,
            identity,
        }
    })
    .await
    .expect("LocalAPI request timed out")
}

fn assert_kernel_authorized(identity: &ConnIdentity) {
    if rustscale_safesocket::platform_uses_peer_creds() {
        assert!(identity.has_trusted_os_uid(), "missing trusted peer UID");
        assert!(identity.uid.is_some(), "missing peer UID");
        assert!(identity.pid.is_some(), "missing peer PID");
    }
}

fn assert_same_peer(left: &ConnIdentity, right: &ConnIdentity) {
    assert_eq!(left.uid, right.uid, "requests came from different UIDs");
    if left.pid.is_some_and(|pid| pid != 0) && right.pid.is_some_and(|pid| pid != 0) {
        assert_eq!(left.pid, right.pid, "requests came from different PIDs");
    }
}

async fn respond(stream: &mut ServerStream, status: &str, headers: &str, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    stream.shutdown().await.unwrap();
}

fn write_event(control: &Path, name: &str) {
    fs::write(control.join(name), b"ready\n").unwrap();
}

async fn serve_wait(mode: &str, listener: &Listener, control: &Path) {
    let mut request = accept_request(listener).await;
    assert_kernel_authorized(&request.identity);
    assert!(request
        .head
        .starts_with("GET /localapi/v0/watch-ipn-bus?mask=2 HTTP/1.1\r\n"));
    match mode {
        "wait-disconnect" => {
            request
                .stream
                .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{\"State\":5}\n")
                .await
                .unwrap();
            request.stream.shutdown().await.unwrap();
        }
        "wait-malformed" => {
            request
                .stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nz\r\n",
                )
                .await
                .unwrap();
            request.stream.shutdown().await.unwrap();
        }
        "wait-stall" => {
            request
                .stream
                .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{\"State\":5}\n")
                .await
                .unwrap();
            request.stream.flush().await.unwrap();
            write_event(control, "subscribed");
            let mut discarded = Vec::new();
            request.stream.read_to_end(&mut discarded).await.unwrap();
            write_event(control, "client-closed");
        }
        "wait-running" => {
            request
                .stream
                .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{\"State\":6}\n")
                .await
                .unwrap();
            request.stream.flush().await.unwrap();
            let watch_identity = request.identity;
            for _ in 0..2 {
                let mut status = accept_request(listener).await;
                assert_kernel_authorized(&status.identity);
                assert_same_peer(&watch_identity, &status.identity);
                assert!(status
                    .head
                    .starts_with("GET /localapi/v0/status?peers=false HTTP/1.1\r\n"));
                respond(
                    &mut status.stream,
                    "200 OK",
                    "Content-Type: application/json\r\n",
                    br#"{"TailscaleIPs":["100.64.0.1"],"TUN":false}"#,
                )
                .await;
            }
            match request.stream.shutdown().await {
                Ok(()) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::NotConnected | ErrorKind::BrokenPipe
                    ) =>
                {
                    // The successful CLI wait may close first. On macOS,
                    // shutting down that already-disconnected Unix stream
                    // reports ENOTCONN instead of succeeding idempotently.
                }
                Err(error) => panic!("wait response shutdown failed: {error}"),
            }
        }
        other => panic!("unknown wait mode {other}"),
    }
}

async fn accept_nc_status(listener: &Listener) -> ConnIdentity {
    let mut status = accept_request(listener).await;
    assert_kernel_authorized(&status.identity);
    assert!(status
        .head
        .starts_with("GET /localapi/v0/status HTTP/1.1\r\n"));
    respond(
        &mut status.stream,
        "200 OK",
        "Content-Type: application/json\r\n",
        br#"{"BackendState":"Running"}"#,
    )
    .await;
    status.identity
}

async fn serve_nc(mode: &str, listener: &Listener, control: &Path) {
    let status_identity = accept_nc_status(listener).await;
    let mut dial = accept_request(listener).await;
    assert_kernel_authorized(&dial.identity);
    assert_same_peer(&status_identity, &dial.identity);
    assert!(dial.head.starts_with("POST /localapi/v0/dial HTTP/1.1\r\n"));
    for header in [
        "Upgrade: ts-dial\r\n",
        "Connection: upgrade\r\n",
        "Dial-Host: peer\r\n",
        "Dial-Port: 8080\r\n",
        "Dial-Network: tcp\r\n",
    ] {
        assert!(dial.head.contains(header), "missing {header:?}");
    }
    if let Some(pid) = dial.identity.pid {
        fs::write(control.join("peer-pid"), format!("{pid}\n")).unwrap();
    }

    match mode {
        "nc-deny" => {
            respond(
                &mut dial.stream,
                "403 Forbidden",
                "Content-Type: application/json\r\n",
                br#"{"error":"peer credentials rejected"}"#,
            )
            .await;
        }
        "nc-half-close" | "nc-stall" => {
            dial.stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: ts-dial\r\n\r\n",
                )
                .await
                .unwrap();
            dial.stream.flush().await.unwrap();
            write_event(control, "upgraded");
            let mut received = Vec::new();
            dial.stream.read_to_end(&mut received).await.unwrap();
            if mode == "nc-half-close" {
                assert_eq!(received, b"request-needs-eof\0\xff");
                dial.stream
                    .write_all(b"response-after-eof\0\xfe")
                    .await
                    .unwrap();
                dial.stream.shutdown().await.unwrap();
            } else {
                assert!(received.is_empty());
                write_event(control, "client-closed");
            }
        }
        other => panic!("unknown nc mode {other}"),
    }
}

async fn serve_drive_cas(listener: &Listener) {
    let mut first_get = accept_request(listener).await;
    let mut second_get = accept_request(listener).await;
    for request in [&first_get, &second_get] {
        assert_kernel_authorized(&request.identity);
        assert!(request
            .head
            .starts_with("GET /localapi/v0/drive/config HTTP/1.1\r\n"));
    }
    respond(
        &mut first_get.stream,
        "200 OK",
        &format!("Content-Type: application/json\r\nETag: \"{ETAG_ZERO}\"\r\n"),
        br#"{"enabled":false,"shares":[]}"#,
    )
    .await;
    respond(
        &mut second_get.stream,
        "200 OK",
        &format!("Content-Type: application/json\r\nETag: \"{ETAG_ZERO}\"\r\n"),
        br#"{"enabled":false,"shares":[]}"#,
    )
    .await;

    let mut winner = accept_request(listener).await;
    assert_kernel_authorized(&winner.identity);
    assert!(winner
        .head
        .starts_with("PUT /localapi/v0/drive/config HTTP/1.1\r\n"));
    assert!(winner
        .head
        .contains(&format!("If-Match: \"{ETAG_ZERO}\"\r\n")));
    let committed: Value = serde_json::from_slice(&winner.body).unwrap();
    let status = serde_json::json!({
        "enabled": true,
        "sharingAllowed": false,
        "generation": 1,
        "shares": committed["shares"],
    });
    respond(
        &mut winner.stream,
        "200 OK",
        &format!("Content-Type: application/json\r\nETag: \"{ETAG_ONE}\"\r\n"),
        &serde_json::to_vec(&status).unwrap(),
    )
    .await;

    let mut stale = accept_request(listener).await;
    assert_kernel_authorized(&stale.identity);
    assert!(stale
        .head
        .starts_with("PUT /localapi/v0/drive/config HTTP/1.1\r\n"));
    assert!(stale
        .head
        .contains(&format!("If-Match: \"{ETAG_ZERO}\"\r\n")));
    respond(
        &mut stale.stream,
        "412 Precondition Failed",
        "Content-Type: application/json\r\n",
        br#"{"error":"Taildrive configuration changed concurrently; read it again before retrying"}"#,
    )
    .await;

    let mut list = accept_request(listener).await;
    assert_kernel_authorized(&list.identity);
    assert!(list
        .head
        .starts_with("GET /localapi/v0/drive/config HTTP/1.1\r\n"));
    respond(
        &mut list.stream,
        "200 OK",
        &format!("Content-Type: application/json\r\nETag: \"{ETAG_ONE}\"\r\n"),
        &serde_json::to_vec(&committed).unwrap(),
    )
    .await;
}

async fn run_daemon(mode: &str, socket: &Path, control: &Path) {
    let listener = rustscale_safesocket::listen(socket).expect("bind scripted daemon socket");
    write_event(control, "ready");
    if mode.starts_with("wait-") {
        serve_wait(mode, &listener, control).await;
    } else if mode.starts_with("nc-") {
        serve_nc(mode, &listener, control).await;
    } else if mode == "drive-cas" {
        serve_drive_cas(&listener).await;
    } else {
        panic!("unknown daemon mode {mode}");
    }
    drop(listener);
    assert!(
        rustscale_safesocket::remove_socket_file(socket).unwrap(),
        "daemon socket was not cleaned up"
    );
}

#[test]
fn scripted_daemon_process() {
    let Ok(mode) = std::env::var(DAEMON_MODE_ENV) else {
        return;
    };
    let socket = PathBuf::from(std::env::var_os(DAEMON_SOCKET_ENV).expect("daemon socket env"));
    let control = PathBuf::from(std::env::var_os(DAEMON_CONTROL_ENV).expect("control dir env"));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime
        .block_on(async {
            tokio::time::timeout(
                Duration::from_secs(30),
                run_daemon(&mode, &socket, &control),
            )
            .await
        })
        .expect("scripted daemon exceeded its hard deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wait_disconnect_restart_malformed_and_cancellation_are_exact() {
    let temp = tempfile::tempdir().unwrap();
    let socket = temp.path().join("wait.sock");

    let disconnect_control = temp.path().join("disconnect");
    let disconnect_daemon = start_daemon("wait-disconnect", &socket, &disconnect_control).await;
    let disconnected = run_cli(&socket, &["wait", "--timeout=3s"]).await;
    assert_output(
        &disconnected,
        1,
        b"",
        b"rustscale: wait: daemon connection closed\n",
    );
    assert_daemon_ok(&disconnect_daemon.wait(PROCESS_TIMEOUT).await);
    assert!(!socket.exists());

    let restart_control = temp.path().join("restart");
    let restart_daemon = start_daemon("wait-running", &socket, &restart_control).await;
    let restarted = run_cli(&socket, &["wait", "--timeout=3s"]).await;
    assert_output(&restarted, 0, b"", b"");
    assert_daemon_ok(&restart_daemon.wait(PROCESS_TIMEOUT).await);
    assert!(!socket.exists());

    let malformed_control = temp.path().join("malformed");
    let malformed_daemon = start_daemon("wait-malformed", &socket, &malformed_control).await;
    let malformed = run_cli(&socket, &["wait", "--timeout=3s"]).await;
    assert_output(
        &malformed,
        1,
        b"",
        b"rustscale: wait: I/O error: invalid watch HTTP framing: invalid chunk size\n",
    );
    assert_daemon_ok(&malformed_daemon.wait(PROCESS_TIMEOUT).await);
    assert!(!socket.exists());

    let cancel_control = temp.path().join("cancel");
    let cancel_daemon = start_daemon("wait-stall", &socket, &cancel_control).await;
    let wait = spawn_cli(&socket, &["wait", "--timeout=5s"], false);
    wait_for_file(&cancel_control.join("subscribed"), READY_TIMEOUT).await;
    wait.signal_interrupt();
    let cancelled = wait.wait(PROCESS_TIMEOUT).await;
    assert_output(&cancelled, 1, b"", b"rustscale: wait: canceled\n");
    wait_for_file(&cancel_control.join("client-closed"), READY_TIMEOUT).await;
    assert_daemon_ok(&cancel_daemon.wait(PROCESS_TIMEOUT).await);
    assert!(!socket.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nc_half_close_kernel_authorization_denial_and_cancellation_are_exact() {
    let temp = tempfile::tempdir().unwrap();
    let socket = temp.path().join("nc.sock");

    let half_close_control = temp.path().join("half-close");
    let half_close_daemon = start_daemon("nc-half-close", &socket, &half_close_control).await;
    let mut nc = spawn_cli(&socket, &["nc", "peer", "8080"], true);
    let nc_pid = nc.id();
    nc.close_stdin_with(b"request-needs-eof\0\xff");
    let output = nc.wait(PROCESS_TIMEOUT).await;
    assert_output(&output, 0, b"response-after-eof\0\xfe", b"");
    assert_daemon_ok(&half_close_daemon.wait(PROCESS_TIMEOUT).await);
    if rustscale_safesocket::platform_uses_peer_creds() {
        let peer_pid: u32 = fs::read_to_string(half_close_control.join("peer-pid"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        if peer_pid != 0 {
            assert_eq!(peer_pid, nc_pid, "daemon authenticated the wrong CLI PID");
        }
    }
    assert!(!socket.exists());

    let denial_control = temp.path().join("denial");
    let denial_daemon = start_daemon("nc-deny", &socket, &denial_control).await;
    let denied = run_cli(&socket, &["nc", "peer", "8080"]).await;
    assert_output(
        &denied,
        1,
        b"",
        b"rustscale: Dial(\"peer\", 8080): Access denied: peer credentials rejected\n",
    );
    assert_daemon_ok(&denial_daemon.wait(PROCESS_TIMEOUT).await);
    assert!(!socket.exists());

    let cancel_control = temp.path().join("cancel");
    let cancel_daemon = start_daemon("nc-stall", &socket, &cancel_control).await;
    let nc = spawn_cli(&socket, &["nc", "peer", "8080"], true);
    wait_for_file(&cancel_control.join("upgraded"), READY_TIMEOUT).await;
    nc.signal_interrupt();
    let cancelled = nc.wait(PROCESS_TIMEOUT).await;
    assert_output(&cancelled, 1, b"", b"rustscale: nc: canceled\n");
    wait_for_file(&cancel_control.join("client-closed"), READY_TIMEOUT).await;
    assert_daemon_ok(&cancel_daemon.wait(PROCESS_TIMEOUT).await);
    assert!(!socket.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn drive_cas_allows_one_process_and_preserves_the_winner_exactly() {
    let temp = tempfile::tempdir().unwrap();
    let socket = temp.path().join("drive.sock");
    let control = temp.path().join("daemon");
    let daemon = start_daemon("drive-cas", &socket, &control).await;
    let first_root = temp.path().join("first-root");
    let second_root = temp.path().join("second-root");
    fs::create_dir(&first_root).unwrap();
    fs::create_dir(&second_root).unwrap();
    let first_root = fs::canonicalize(first_root).unwrap();
    let second_root = fs::canonicalize(second_root).unwrap();

    let first = spawn_cli(
        &socket,
        &["drive", "share", "first", first_root.to_str().unwrap()],
        false,
    );
    let second = spawn_cli(
        &socket,
        &["drive", "share", "second", second_root.to_str().unwrap()],
        false,
    );
    let (first, second) = tokio::join!(first.wait(PROCESS_TIMEOUT), second.wait(PROCESS_TIMEOUT));

    let expected_error = b"rustscale: Preconditions failed: Taildrive configuration changed concurrently; read it again before retrying\n";
    let (winner_name, winner_root) = if first.status.success() {
        assert_output(
            &first,
            0,
            format!(
                "Sharing {:?} as \"first\"\n",
                first_root.display().to_string()
            )
            .as_bytes(),
            b"",
        );
        assert_output(&second, 1, b"", expected_error);
        ("first", &first_root)
    } else {
        assert_output(&first, 1, b"", expected_error);
        assert_output(
            &second,
            0,
            format!(
                "Sharing {:?} as \"second\"\n",
                second_root.display().to_string()
            )
            .as_bytes(),
            b"",
        );
        ("second", &second_root)
    };

    let listed = run_cli(&socket, &["drive", "list", "--json"]).await;
    let mut expected_list = serde_json::to_vec_pretty(&serde_json::json!([{
        "name": winner_name,
        "path": winner_root,
    }]))
    .unwrap();
    expected_list.push(b'\n');
    assert_output(&listed, 0, &expected_list, b"");
    assert_daemon_ok(&daemon.wait(PROCESS_TIMEOUT).await);
    assert!(!socket.exists());
}
