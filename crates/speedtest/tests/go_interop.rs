#![forbid(unsafe_code)]

use std::future::Future;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::task::{Context, Poll};
use std::thread;
use std::time::Duration;

use rustscale_speedtest::{
    run, CancellationToken, Direction, Result as SpeedtestResult, Server, SpeedtestError,
    BLOCK_SIZE, MAX_CONTROL_FRAME_SIZE, MAX_RESULT_COUNT, MIN_DURATION, MIN_INTERVAL,
    PROTOCOL_VERSION,
};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

const PEER_ENV: &str = "RUSTSCALE_SPEEDTEST_GO_PEER";
const TOOLCHAIN_ENV: &str = "RUSTSCALE_SPEEDTEST_GO_TOOLCHAIN";
const RUNTIME_ROOT_ENV: &str = "RUSTSCALE_SPEEDTEST_GO_RUNTIME_ROOT";
const EXPECTED_MODULE: &str = "tailscale.com@v1.100.0";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(5);
const SESSION_TIMEOUT: Duration = Duration::from_secs(12);
const PROCESS_EXIT_TIMEOUT: Duration = Duration::from_secs(5);
const GLOBAL_TIMEOUT: Duration = Duration::from_secs(35);
const MAX_CHILD_OUTPUT: usize = 16 * 1024;
const IO_FRAGMENT_SIZE: usize = 1009;

#[derive(Clone)]
struct GoHarness {
    peer: PathBuf,
    toolchain_dir: PathBuf,
    runtime_root: PathBuf,
}

fn canonical_env_path(name: &str) -> PathBuf {
    let path = PathBuf::from(
        std::env::var_os(name)
            .unwrap_or_else(|| panic!("missing required harness variable {name}")),
    );
    assert!(path.is_absolute(), "{name} must be absolute");
    path.canonicalize()
        .unwrap_or_else(|error| panic!("cannot canonicalize {name}: {error}"))
}

fn harness() -> Option<GoHarness> {
    if std::env::var_os(PEER_ENV).is_none() {
        eprintln!("skipping Go speedtest interop; run tools/speedtest-interop.sh");
        return None;
    }
    let peer = canonical_env_path(PEER_ENV);
    assert!(peer.is_file(), "Go peer is not a regular file");
    let toolchain = canonical_env_path(TOOLCHAIN_ENV);
    assert!(toolchain.is_file(), "Go toolchain is not a regular file");
    assert_eq!(
        toolchain.file_name().and_then(|name| name.to_str()),
        Some("go"),
        "validated toolchain executable must be named go"
    );
    let toolchain_dir = toolchain
        .parent()
        .expect("Go toolchain has no parent directory")
        .to_owned();
    let runtime_root = canonical_env_path(RUNTIME_ROOT_ENV);
    assert!(runtime_root.is_dir(), "runtime root is not a directory");
    assert!(
        runtime_root.starts_with(peer.parent().expect("Go peer has no parent")),
        "runtime root is outside the speedtest interop target directory"
    );
    for name in ["home", "gocache", "gomodcache", "gopath"] {
        assert!(
            runtime_root.join(name).is_dir(),
            "missing isolated runtime directory {name}"
        );
    }
    Some(GoHarness {
        peer,
        toolchain_dir,
        runtime_root,
    })
}

fn command(harness: &GoHarness) -> Command {
    let mut command = Command::new(&harness.peer);
    command
        .env_clear()
        .env("HOME", harness.runtime_root.join("home"))
        .env("GOCACHE", harness.runtime_root.join("gocache"))
        .env("GOMODCACHE", harness.runtime_root.join("gomodcache"))
        .env("GOPATH", harness.runtime_root.join("gopath"))
        .env("PATH", &harness.toolchain_dir)
        .env("GOENV", "off")
        .env("GOFLAGS", "")
        .env("GOWORK", "off")
        .env("GOPROXY", "off")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn read_limited(mut reader: impl Read) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    reader
        .by_ref()
        .take((MAX_CHILD_OUTPUT + 1) as u64)
        .read_to_end(&mut output)?;
    if output.len() > MAX_CHILD_OUTPUT {
        return Err(io::Error::other(format!(
            "child output exceeded {MAX_CHILD_OUTPUT} bytes"
        )));
    }
    Ok(output)
}

fn read_limited_line(mut reader: impl Read) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    while line.len() <= MAX_CONTROL_FRAME_SIZE {
        let mut byte = [0_u8; 1];
        match reader.read(&mut byte)? {
            0 => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "startup EOF")),
            1 => {
                line.push(byte[0]);
                if byte[0] == b'\n' {
                    return Ok(line);
                }
            }
            _ => unreachable!("one-byte read returned more than one byte"),
        }
    }
    Err(io::Error::other("startup line exceeded control limit"))
}

fn join_reader(handle: thread::JoinHandle<io::Result<Vec<u8>>>, name: &str) -> Vec<u8> {
    handle
        .join()
        .unwrap_or_else(|_| panic!("{name} reader thread panicked"))
        .unwrap_or_else(|error| panic!("failed reading bounded child {name}: {error}"))
}

struct ManagedChild {
    child: Child,
    stdout: Option<thread::JoinHandle<io::Result<Vec<u8>>>>,
    stderr: Option<thread::JoinHandle<io::Result<Vec<u8>>>>,
}

impl ManagedChild {
    fn spawn(harness: &GoHarness, arguments: &[&str]) -> Self {
        let mut child_command = command(harness);
        child_command.args(arguments);
        Self::spawn_command(child_command)
    }

    fn spawn_poisoned(harness: &GoHarness, name: &str, value: &str) -> Self {
        let mut child_command = command(harness);
        child_command.arg("server").env(name, value);
        Self::spawn_command(child_command)
    }

    fn spawn_command(mut command: Command) -> Self {
        let mut child = command
            .spawn()
            .unwrap_or_else(|error| panic!("failed to spawn Go peer: {error}"));
        let stdout = child.stdout.take().expect("Go peer stdout was not piped");
        let stderr = child.stderr.take().expect("Go peer stderr was not piped");
        Self {
            child,
            stdout: Some(thread::spawn(move || read_limited(stdout))),
            stderr: Some(thread::spawn(move || read_limited(stderr))),
        }
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

    async fn wait(mut self, timeout: Duration) -> ProcessOutput {
        let deadline = tokio::time::Instant::now() + timeout;
        let status = loop {
            match self.child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {}
                Err(error) => {
                    self.kill_and_reap();
                    panic!("failed waiting for Go peer: {error}");
                }
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                self.kill_and_reap();
                panic!("Go peer exceeded its {timeout:?} process deadline");
            }
            tokio::time::sleep_until((now + Duration::from_millis(10)).min(deadline)).await;
        };
        let stdout = join_reader(self.stdout.take().expect("missing stdout reader"), "stdout");
        let stderr = join_reader(self.stderr.take().expect("missing stderr reader"), "stderr");
        ProcessOutput {
            status,
            stdout,
            stderr,
        }
    }

    fn kill_and_reap(&mut self) {
        match self.child.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
            Err(_) => {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
        if let Some(stdout) = self.stdout.take() {
            let _ = stdout.join();
        }
        if let Some(stderr) = self.stderr.take() {
            let _ = stderr.join();
        }
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        self.kill_and_reap();
    }
}

struct ProcessOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

struct GoServer {
    child: Child,
    stderr: Option<thread::JoinHandle<io::Result<Vec<u8>>>>,
    address: SocketAddr,
}

fn fail_server_start(
    child: &mut Child,
    stderr: thread::JoinHandle<io::Result<Vec<u8>>>,
    reason: impl std::fmt::Display,
) -> ! {
    let _ = child.kill();
    let _ = child.wait();
    let diagnostics = join_reader(stderr, "stderr");
    panic!(
        "Go server startup failed: {reason}; stderr={}",
        String::from_utf8_lossy(&diagnostics)
    );
}

impl GoServer {
    fn start(harness: &GoHarness) -> Self {
        let mut command = command(harness);
        command.arg("server");
        let mut child = command
            .spawn()
            .unwrap_or_else(|error| panic!("failed to spawn Go server: {error}"));
        let stdout = child.stdout.take().expect("Go server stdout was not piped");
        let stderr = child.stderr.take().expect("Go server stderr was not piped");
        let stderr = thread::spawn(move || read_limited(stderr));
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let startup_reader = thread::spawn(move || {
            let _ = sender.send(read_limited_line(stdout));
        });

        let line = match receiver.recv_timeout(STARTUP_TIMEOUT) {
            Ok(Ok(line)) => line,
            Ok(Err(error)) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = startup_reader.join();
                let diagnostics = join_reader(stderr, "stderr");
                panic!(
                    "Go server startup failed: cannot read line: {error}; stderr={}",
                    String::from_utf8_lossy(&diagnostics)
                );
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = startup_reader.join();
                let diagnostics = join_reader(stderr, "stderr");
                panic!(
                    "Go server startup exceeded {STARTUP_TIMEOUT:?}: {error}; stderr={}",
                    String::from_utf8_lossy(&diagnostics)
                );
            }
        };
        if startup_reader.join().is_err() {
            fail_server_start(&mut child, stderr, "startup reader thread panicked");
        }
        let parsed_address = (|| -> Result<SocketAddr, String> {
            let startup: Value = serde_json::from_slice(&line)
                .map_err(|error| format!("invalid startup JSON: {error}"))?;
            if startup["module"].as_str() != Some(EXPECTED_MODULE) {
                return Err(format!("unexpected module provenance: {startup}"));
            }
            let address: SocketAddr = startup["address"]
                .as_str()
                .ok_or_else(|| "startup address was not a string".to_owned())?
                .parse()
                .map_err(|error| format!("invalid startup address: {error}"))?;
            if address.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
                return Err(format!("non-loopback startup address: {address}"));
            }
            Ok(address)
        })();
        let address = match parsed_address {
            Ok(address) => address,
            Err(error) => fail_server_start(&mut child, stderr, error),
        };

        Self {
            child,
            stderr: Some(stderr),
            address,
        }
    }

    fn stop(&mut self) {
        match self.child.try_wait() {
            Ok(Some(status)) if status.success() => {}
            Ok(Some(_)) => {}
            Ok(None) => {
                let _ = self.child.kill();
                self.child.wait().expect("failed to reap Go server");
            }
            Err(error) => panic!("failed checking Go server: {error}"),
        }
        if let Some(stderr) = self.stderr.take() {
            let diagnostics = join_reader(stderr, "stderr");
            assert!(
                diagnostics.len() <= MAX_CHILD_OUTPUT,
                "Go server diagnostics were not bounded"
            );
        }
    }
}

impl Drop for GoServer {
    fn drop(&mut self) {
        self.stop();
    }
}

struct RustServer {
    cancellation: CancellationToken,
    task: Option<tokio::task::JoinHandle<Result<(), SpeedtestError>>>,
}

impl RustServer {
    fn start(listener: TcpListener) -> Self {
        let cancellation = CancellationToken::new();
        let child_cancellation = cancellation.clone();
        let task = tokio::spawn(async move {
            Server::new(1)
                .expect("invalid bounded server")
                .serve(listener, child_cancellation)
                .await
        });
        Self {
            cancellation,
            task: Some(task),
        }
    }

    async fn cancel_and_drain(&mut self) {
        self.cancellation.cancel();
        let task = self.task.take().expect("Rust server already drained");
        tokio::time::timeout(PROCESS_EXIT_TIMEOUT, task)
            .await
            .expect("bounded Rust server did not drain after cancellation")
            .expect("bounded Rust server task panicked")
            .expect("bounded Rust server failed during cancellation");
    }
}

impl Drop for RustServer {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

struct FragmentedIo<S> {
    inner: S,
}

impl<S> FragmentedIo<S> {
    const fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FragmentedIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut scratch = [0_u8; IO_FRAGMENT_SIZE];
        let capacity = output.remaining().min(IO_FRAGMENT_SIZE);
        let mut limited = ReadBuf::new(&mut scratch[..capacity]);
        match Pin::new(&mut self.inner).poll_read(cx, &mut limited) {
            Poll::Ready(Ok(())) => {
                output.put_slice(limited.filled());
                Poll::Ready(Ok(()))
            }
            result => result,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FragmentedIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let length = input.len().min(IO_FRAGMENT_SIZE);
        Pin::new(&mut self.inner).poll_write(cx, &input[..length])
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

fn assert_rust_results(results: &[SpeedtestResult]) {
    assert!((3..=MAX_RESULT_COUNT).contains(&results.len()));
    let totals: Vec<_> = results.iter().filter(|result| result.is_total).collect();
    assert_eq!(totals.len(), 1, "expected exactly one total result");
    assert!(results.last().expect("missing results").is_total);
    let total = totals[0];
    assert!(total.bytes >= BLOCK_SIZE as u64);
    assert_eq!(total.bytes % BLOCK_SIZE as u64, 0);
    assert!(total.interval() >= MIN_DURATION);

    let interval_sum: u64 = results
        .iter()
        .filter(|result| !result.is_total)
        .map(|result| {
            assert!(result.interval() > MIN_INTERVAL);
            assert!(result.bytes >= BLOCK_SIZE as u64);
            assert_eq!(result.bytes % BLOCK_SIZE as u64, 0);
            result.bytes
        })
        .sum();
    assert!(interval_sum <= total.bytes);
}

fn assert_go_results(output: &ProcessOutput, direction: Direction) {
    assert!(
        output.status.success(),
        "Go client failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("invalid bounded Go output: {error}"));
    assert_eq!(value["module"], EXPECTED_MODULE);
    assert_eq!(value["direction"], direction.to_string());
    let results = value["results"]
        .as_array()
        .expect("Go results not an array");
    assert!((3..=MAX_RESULT_COUNT).contains(&results.len()));
    assert_eq!(
        results
            .iter()
            .filter(|result| result["total"] == true)
            .count(),
        1
    );
    assert_eq!(results.last().expect("missing Go results")["total"], true);

    let total = results.last().expect("missing Go total");
    let total_bytes = total["bytes"].as_u64().expect("invalid Go total bytes");
    assert!(total_bytes >= BLOCK_SIZE as u64);
    assert_eq!(total_bytes % BLOCK_SIZE as u64, 0);
    assert!(
        total["interval_ns"]
            .as_u64()
            .expect("invalid Go total interval")
            >= MIN_DURATION.as_nanos() as u64
    );
    let mut interval_sum = 0_u64;
    for result in results {
        let bytes = result["bytes"].as_u64().expect("invalid Go result bytes");
        assert!(bytes >= BLOCK_SIZE as u64);
        assert_eq!(bytes % BLOCK_SIZE as u64, 0);
        assert!(
            result["interval_ns"]
                .as_u64()
                .expect("invalid Go result interval")
                > MIN_INTERVAL.as_nanos() as u64
        );
        if result["total"] == false {
            interval_sum = interval_sum
                .checked_add(bytes)
                .expect("Go interval byte sum overflowed");
        }
    }
    assert!(interval_sum <= total_bytes);
}

async fn globally_bounded(future: impl Future<Output = ()>) {
    tokio::time::timeout(GLOBAL_TIMEOUT, future)
        .await
        .unwrap_or_else(|_| panic!("interop test exceeded global deadline {GLOBAL_TIMEOUT:?}"));
}

async fn run_go_client(
    harness: GoHarness,
    address: SocketAddr,
    direction: Direction,
) -> ProcessOutput {
    ManagedChild::spawn(
        &harness,
        &[
            "client",
            "--address",
            &address.to_string(),
            "--direction",
            &direction.to_string(),
            "--duration",
            "5s",
        ],
    )
    .wait(SESSION_TIMEOUT)
    .await
}

async fn read_control_line(stream: &mut TcpStream) -> Vec<u8> {
    let mut line = Vec::new();
    while line.len() <= MAX_CONTROL_FRAME_SIZE {
        let byte = stream.read_u8().await.expect("failed reading Go control");
        line.push(byte);
        if byte == b'\n' {
            return line;
        }
    }
    panic!("Go control response exceeded limit");
}

#[tokio::test]
async fn go_peer_rejects_poisoned_runtime_environment() {
    let Some(harness) = harness() else {
        return;
    };
    globally_bounded(async move {
        for (name, value) in [
            ("GOFLAGS", "-mod=mod"),
            ("GOWORK", "/poisoned/workspace"),
            ("GOPROXY", "https://poisoned.invalid"),
        ] {
            let output = ManagedChild::spawn_poisoned(&harness, name, value)
                .wait(PROCESS_EXIT_TIMEOUT)
                .await;
            assert!(!output.status.success(), "Go peer accepted poisoned {name}");
            assert!(output.stdout.is_empty(), "poisoned peer claimed startup");
            assert!(
                String::from_utf8_lossy(&output.stderr).contains(name),
                "poison rejection did not identify {name}"
            );
        }
    })
    .await;
}

#[tokio::test]
async fn rust_client_interoperates_with_go_server_in_both_directions() {
    let Some(harness) = harness() else {
        return;
    };
    globally_bounded(async move {
        let mut server = GoServer::start(&harness);
        for direction in [Direction::Upload, Direction::Download] {
            let stream = tokio::time::timeout(STARTUP_TIMEOUT, TcpStream::connect(server.address))
                .await
                .expect("Go server connect timed out")
                .expect("failed to connect to Go server");
            let mut stream = FragmentedIo::new(stream);
            let results =
                tokio::time::timeout(SESSION_TIMEOUT, run(&mut stream, direction, MIN_DURATION))
                    .await
                    .expect("Rust-to-Go session timed out")
                    .expect("Rust client rejected Go server");
            assert_rust_results(&results);
        }
        server.stop();
    })
    .await;
}

#[tokio::test]
async fn go_client_interoperates_with_bounded_rust_server_and_is_cancelled() {
    let Some(harness) = harness() else {
        return;
    };
    globally_bounded(async move {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed binding Rust speedtest server");
        let address = listener.local_addr().expect("missing Rust server address");
        assert!(address.ip().is_loopback());
        let mut server = RustServer::start(listener);

        for direction in [Direction::Upload, Direction::Download] {
            let output = run_go_client(harness.clone(), address, direction).await;
            assert_go_results(&output, direction);
        }

        let mut cancelled = ManagedChild::spawn(
            &harness,
            &[
                "client",
                "--address",
                &address.to_string(),
                "--direction",
                "upload",
                "--duration",
                "30s",
            ],
        );
        tokio::time::sleep(Duration::from_millis(750)).await;
        assert!(
            cancelled
                .try_wait()
                .expect("failed checking Go client")
                .is_none(),
            "Go cancellation client exited before server cancellation"
        );
        server.cancel_and_drain().await;
        let output = cancelled.wait(PROCESS_EXIT_TIMEOUT).await;
        assert!(
            !output.status.success(),
            "Go client unexpectedly succeeded after Rust server cancellation"
        );
    })
    .await;
}

#[tokio::test]
async fn go_server_newline_control_rejects_malformed_and_truncated_json() {
    let Some(harness) = harness() else {
        return;
    };
    globally_bounded(async move {
        for wire in [&b"not-json\n"[..], &b"{\"version\":"[..]] {
            let server = GoServer::start(&harness);
            let mut stream =
                tokio::time::timeout(STARTUP_TIMEOUT, TcpStream::connect(server.address))
                    .await
                    .expect("Go server connect timed out")
                    .expect("failed to connect to Go server");
            stream
                .write_all(wire)
                .await
                .expect("failed writing control");
            if !wire.ends_with(b"\n") {
                stream.shutdown().await.expect("failed truncating control");
            }
            let response = tokio::time::timeout(STARTUP_TIMEOUT, read_control_line(&mut stream))
                .await
                .expect("Go error response timed out");
            assert_eq!(response.last(), Some(&b'\n'));
            let value: Value = serde_json::from_slice(&response).expect("invalid Go error JSON");
            assert!(
                value["error"]
                    .as_str()
                    .is_some_and(|error| !error.is_empty()),
                "Go server accepted invalid control: {value}"
            );
        }

        let server = GoServer::start(&harness);
        let mut stream = TcpStream::connect(server.address)
            .await
            .expect("failed connecting for control vector");
        let control =
            format!("{{\"version\":{PROTOCOL_VERSION},\"time\":5000000000,\"direction\":1}}\n");
        stream
            .write_all(control.as_bytes())
            .await
            .expect("failed writing valid control");
        assert_eq!(
            tokio::time::timeout(STARTUP_TIMEOUT, read_control_line(&mut stream))
                .await
                .expect("Go acceptance response timed out"),
            b"{}\n"
        );
    })
    .await;
}
