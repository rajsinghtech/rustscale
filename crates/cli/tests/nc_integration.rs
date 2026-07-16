#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, Notify};

#[derive(Clone, Debug)]
enum Mode {
    Echo,
    DrainAfterEof(Vec<u8>),
    Refuse,
    Malformed,
    Disconnect,
    StallAfterUpgrade,
    StallBeforeUpgrade,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Event {
    DialRequest,
    Upgraded,
    ClientClosed,
}

struct FakeLocalApi {
    path: PathBuf,
    events: mpsc::UnboundedReceiver<Event>,
    release: Arc<Notify>,
    task: tokio::task::JoinHandle<()>,
    _temp: tempfile::TempDir,
}

impl FakeLocalApi {
    #[allow(clippy::unused_async)]
    async fn start(mode: Mode) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("localapi.sock");
        let listener = rustscale_safesocket::listen(&path).unwrap();
        let (event_tx, events) = mpsc::unbounded_channel();
        let release = Arc::new(Notify::new());
        let server_release = Arc::clone(&release);
        let task = tokio::spawn(async move {
            let mut status = listener.accept().await.unwrap();
            let request = read_request(&mut status).await;
            assert!(request.starts_with(b"GET /localapi/v0/status HTTP/1.1\r\n"));
            let body = br#"{"BackendState":"Running"}"#;
            status
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            status.write_all(body).await.unwrap();
            status.shutdown().await.unwrap();

            let mut dial = listener.accept().await.unwrap();
            let request = read_request(&mut dial).await;
            assert!(request.starts_with(b"POST /localapi/v0/dial HTTP/1.1\r\n"));
            for expected in [
                &b"Upgrade: ts-dial\r\n"[..],
                &b"Connection: upgrade\r\n"[..],
                &b"Dial-Host: peer\r\n"[..],
                &b"Dial-Port: 8080\r\n"[..],
                &b"Dial-Network: tcp\r\n"[..],
            ] {
                assert!(
                    request
                        .windows(expected.len())
                        .any(|window| window == expected),
                    "missing request header {:?}",
                    String::from_utf8_lossy(expected)
                );
            }
            event_tx.send(Event::DialRequest).unwrap();

            match mode {
                Mode::Refuse => {
                    let body = br#"{"error":"connection refused"}"#;
                    dial.write_all(
                        format!(
                            "HTTP/1.1 502 Bad Gateway\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                    dial.write_all(body).await.unwrap();
                }
                Mode::Malformed => {
                    dial.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: ts-dial\r\n\r\n")
                        .await
                        .unwrap();
                }
                Mode::StallBeforeUpgrade => {
                    let mut discarded = Vec::new();
                    dial.read_to_end(&mut discarded).await.unwrap();
                    event_tx.send(Event::ClientClosed).unwrap();
                }
                mode => {
                    dial.write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: ts-dial\r\n\r\n",
                    )
                    .await
                    .unwrap();
                    dial.flush().await.unwrap();
                    event_tx.send(Event::Upgraded).unwrap();
                    match mode {
                        Mode::Echo => {
                            let mut buffer = [0u8; 37];
                            loop {
                                let count = dial.read(&mut buffer).await.unwrap();
                                if count == 0 {
                                    break;
                                }
                                dial.write_all(&buffer[..count]).await.unwrap();
                            }
                            dial.shutdown().await.unwrap();
                        }
                        Mode::DrainAfterEof(reply) => {
                            let mut request_body = Vec::new();
                            dial.read_to_end(&mut request_body).await.unwrap();
                            assert_eq!(request_body, b"request-needs-eof");
                            dial.write_all(&reply).await.unwrap();
                            dial.shutdown().await.unwrap();
                        }
                        Mode::Disconnect => {
                            dial.shutdown().await.unwrap();
                        }
                        Mode::StallAfterUpgrade => {
                            // Keep both directions open and do not read until
                            // the test has demonstrated backpressure and sent
                            // SIGINT to the CLI.
                            server_release.notified().await;
                            let mut discarded = Vec::new();
                            dial.read_to_end(&mut discarded).await.unwrap();
                            event_tx.send(Event::ClientClosed).unwrap();
                        }
                        Mode::Refuse | Mode::Malformed | Mode::StallBeforeUpgrade => {
                            unreachable!()
                        }
                    }
                }
            }
        });
        Self {
            path,
            events,
            release,
            task,
            _temp: temp,
        }
    }

    async fn event(&mut self, expected: Event) {
        let event = tokio::time::timeout(Duration::from_secs(5), self.events.recv())
            .await
            .expect("fake LocalAPI event timeout")
            .expect("fake LocalAPI event channel closed");
        assert_eq!(event, expected);
    }

    async fn finish(self) {
        tokio::time::timeout(Duration::from_secs(5), self.task)
            .await
            .expect("fake LocalAPI did not finish")
            .expect("fake LocalAPI panicked");
    }
}

async fn read_request(stream: &mut rustscale_safesocket::ServerStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut byte = [0u8; 1];
    while !request.ends_with(b"\r\n\r\n") {
        assert!(request.len() < 64 * 1024, "request header too large");
        stream.read_exact(&mut byte).await.unwrap();
        request.push(byte[0]);
    }
    request
}

fn rustscale(path: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rustscale"));
    command
        .arg("--socket")
        .arg(path)
        .args(["nc", "peer", "8080"])
        .env("HTTP_PROXY", "http://127.0.0.1:1")
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .env("ALL_PROXY", "socks5://127.0.0.1:1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

#[allow(clippy::unused_async)]
async fn spawn(path: &Path) -> Child {
    rustscale(path).spawn().expect("spawn rustscale nc")
}

async fn finish_with_input(mut child: Child, input: &[u8]) -> std::process::Output {
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(input).await.unwrap();
    stdin.shutdown().await.unwrap();
    drop(stdin);
    tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .expect("rustscale nc did not exit")
        .unwrap()
}

fn send_sigint(child: &Child) {
    let pid = child.id().expect("child has no pid");
    let status = std::process::Command::new("/bin/kill")
        .args(["-INT", &pid.to_string()])
        .status()
        .expect("run /bin/kill");
    assert!(status.success(), "failed to signal child {pid}");
}

#[test]
fn nc_help_is_available_without_a_daemon() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_rustscale"))
        .args(["nc", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout)
        .contains("Usage: rustscale nc <hostname-or-IP> <port>"));
    assert!(output.stderr.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nc_completion_lists_peer_dns_names() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("completion.sock");
    let listener = rustscale_safesocket::listen(&path).unwrap();
    let server = tokio::spawn(async move {
        let mut stream = listener.accept().await.unwrap();
        let request = read_request(&mut stream).await;
        assert!(request.starts_with(b"GET /localapi/v0/status HTTP/1.1\r\n"));
        let body = br#"{"Peer":{"1":{"DNSName":"peer.example.ts.net."},"2":{"DNSName":"other.example.ts.net."}}}"#;
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        stream.write_all(body).await.unwrap();
    });
    let output = Command::new(env!("CARGO_BIN_EXE_rustscale"))
        .args(["__complete", "--", "--socket"])
        .arg(&path)
        .args(["nc", "pe"])
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "completion failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"peer.example.ts.net\n");
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn binary_roundtrip_ignores_proxy_environment() {
    let mut fake = FakeLocalApi::start(Mode::Echo).await;
    let child = spawn(&fake.path).await;
    let input = b"\x00\xff\x80binary\r\n\0tail";
    let output = finish_with_input(child, input).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, input);
    fake.event(Event::DialRequest).await;
    fake.event(Event::Upgraded).await;
    fake.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stdin_eof_half_closes_and_drains_remote_output() {
    let reply = b"response-after-request-eof\x00\xff".to_vec();
    let fake = FakeLocalApi::start(Mode::DrainAfterEof(reply.clone())).await;
    let child = spawn(&fake.path).await;
    let output = finish_with_input(child, b"request-needs-eof").await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, reply);
    fake.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refusal_and_malformed_upgrade_are_nonzero() {
    for (mode, message) in [
        (Mode::Refuse, "connection refused"),
        (Mode::Malformed, "invalid dial upgrade response headers"),
    ] {
        let fake = FakeLocalApi::start(mode).await;
        let child = spawn(&fake.path).await;
        let output = finish_with_input(child, b"").await;
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(message),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        fake.finish().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn orderly_remote_disconnect_ends_session_without_waiting_for_stdin() {
    let mut fake = FakeLocalApi::start(Mode::Disconnect).await;
    let mut child = spawn(&fake.path).await;
    fake.event(Event::DialRequest).await;
    fake.event(Event::Upgraded).await;
    // Keep stdin open: remote EOF must still end the session and cancel the
    // upload side rather than leaving a detached input pump.
    let _stdin = child.stdin.take().unwrap();
    let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .expect("nc waited for stdin after remote disconnect")
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    fake.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stalled_peer_applies_backpressure_and_ctrl_c_joins_pumps() {
    let mut fake = FakeLocalApi::start(Mode::StallAfterUpgrade).await;
    let mut child = spawn(&fake.path).await;
    fake.event(Event::DialRequest).await;
    fake.event(Event::Upgraded).await;

    let mut stdin = child.stdin.take().unwrap();
    let writer = tokio::spawn(async move {
        let bytes = vec![0x5a; 16 * 1024 * 1024];
        stdin.write_all(&bytes).await
    });
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(
        child.try_wait().unwrap().is_none(),
        "stalled nc exited early"
    );

    send_sigint(&child);
    let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .expect("canceled stalled nc did not exit")
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("nc: canceled"));
    let _ = writer.await;
    fake.release.notify_one();
    fake.event(Event::ClientClosed).await;
    fake.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ctrl_c_cancels_a_stalled_upgrade_handshake() {
    let mut fake = FakeLocalApi::start(Mode::StallBeforeUpgrade).await;
    let child = spawn(&fake.path).await;
    fake.event(Event::DialRequest).await;
    send_sigint(&child);
    let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .expect("canceled dial handshake did not exit")
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("nc: canceled"));
    fake.event(Event::ClientClosed).await;
    fake.finish().await;
}
