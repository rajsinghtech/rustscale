#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

fn rustscale_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rustscale"))
}

async fn run_wait(socket: &Path, args: &[&str]) -> Output {
    let socket = socket.to_owned();
    let args = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
    tokio::task::spawn_blocking(move || {
        Command::new(rustscale_bin())
            .arg("--socket")
            .arg(socket)
            .arg("wait")
            .args(args)
            .output()
            .expect("run rustscale wait")
    })
    .await
    .expect("join rustscale wait")
}

async fn accept_request(listener: &UnixListener) -> (UnixStream, String) {
    let (mut stream, _) = listener.accept().await.expect("accept LocalAPI client");
    let mut request = Vec::new();
    let mut byte = [0u8; 1];
    while !request.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.expect("read request");
        request.push(byte[0]);
        assert!(request.len() <= 64 * 1024, "request header was unbounded");
    }
    let request = String::from_utf8(request).expect("request is UTF-8");
    assert!(
        !request.to_ascii_lowercase().contains("authorization:"),
        "LocalAPI peer authentication must not be copied into HTTP headers"
    );
    (stream, request)
}

async fn write_watch(stream: &mut UnixStream, frames: &[&[u8]]) {
    stream
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    for frame in frames {
        stream.write_all(frame).await.unwrap();
        stream.write_all(b"\n").await.unwrap();
    }
    stream.flush().await.unwrap();
}

async fn serve_status(listener: &UnixListener) {
    let (mut stream, request) = accept_request(listener).await;
    assert!(request.starts_with("GET /localapi/v0/status?peers=false HTTP/1.1\r\n"));
    let body = br#"{"TailscaleIPs":["100.64.0.1"],"TUN":false}"#;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(response.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    stream.shutdown().await.unwrap();
}

fn assert_watch_request(request: &str) {
    assert!(request.starts_with("GET /localapi/v0/watch-ipn-bus?mask=2 HTTP/1.1\r\n",));
}

fn assert_failed(output: &Output, needle: &str) {
    assert_eq!(
        output.status.code(),
        Some(1),
        "unexpected status: {:?}",
        output.status
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(needle),
        "stderr {stderr:?} did not contain {needle:?}"
    );
    assert!(output.stdout.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wait_succeeds_when_running_was_already_reached() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("already.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (mut watch, request) = accept_request(&listener).await;
        assert_watch_request(&request);
        write_watch(&mut watch, &[br#"{"State":6}"#]).await;
        serve_status(&listener).await;
        serve_status(&listener).await;
    });

    let output = run_wait(&socket, &[]).await;
    assert!(
        output.status.success(),
        "wait failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wait_observes_a_transition_after_subscribing() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("transition.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (mut watch, request) = accept_request(&listener).await;
        assert_watch_request(&request);
        // Every valid non-Running IPN state is accepted and ignored.
        write_watch(
            &mut watch,
            &[
                br#"{"State":0}"#,
                br#"{"State":1}"#,
                br#"{"State":2}"#,
                br#"{"State":3}"#,
                br#"{"State":4}"#,
                br#"{"State":5}"#,
            ],
        )
        .await;
        tokio::time::sleep(Duration::from_millis(25)).await;
        watch.write_all(b"{\"State\":6}\n").await.unwrap();
        watch.flush().await.unwrap();
        serve_status(&listener).await;
        serve_status(&listener).await;
    });

    let output = run_wait(&socket, &[]).await;
    assert!(
        output.status.success(),
        "wait failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wait_rejects_an_invalid_ipn_state() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("invalid-state.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (mut watch, request) = accept_request(&listener).await;
        assert_watch_request(&request);
        write_watch(&mut watch, &[br#"{"State":99}"#]).await;
    });

    let output = run_wait(&socket, &[]).await;
    assert_failed(&output, "invalid watch notification");
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wait_timeout_covers_the_whole_command() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("timeout.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (mut watch, request) = accept_request(&listener).await;
        assert_watch_request(&request);
        write_watch(&mut watch, &[br#"{"State":5}"#]).await;
        tokio::time::sleep(Duration::from_secs(2)).await;
    });

    let output = run_wait(&socket, &["--timeout=100ms"]).await;
    assert_failed(&output, "timed out");
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wait_fails_if_the_server_disconnects() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("disconnect.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (mut watch, request) = accept_request(&listener).await;
        assert_watch_request(&request);
        write_watch(&mut watch, &[br#"{"State":5}"#]).await;
        watch.shutdown().await.unwrap();
    });

    let output = run_wait(&socket, &[]).await;
    assert_failed(&output, "daemon connection closed");
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wait_fails_closed_on_a_malformed_stream() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("malformed.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (mut watch, request) = accept_request(&listener).await;
        assert_watch_request(&request);
        write_watch(&mut watch, &[b"not JSON"]).await;
    });

    let output = run_wait(&socket, &[]).await;
    assert_failed(&output, "invalid watch notification");
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wait_bounds_the_status_response_body() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("oversized-status.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (mut watch, request) = accept_request(&listener).await;
        assert_watch_request(&request);
        write_watch(&mut watch, &[br#"{"State":6}"#]).await;
        let (mut status, request) = accept_request(&listener).await;
        assert!(request.starts_with("GET /localapi/v0/status?peers=false HTTP/1.1\r\n"));
        status
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4194305\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
    });

    let output = run_wait(&socket, &[]).await;
    assert_failed(&output, "response body too large");
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wait_ctrl_c_cancels_the_command() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("cancel.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let (subscribed_tx, subscribed_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut watch, request) = accept_request(&listener).await;
        assert_watch_request(&request);
        write_watch(&mut watch, &[br#"{"State":5}"#]).await;
        let _ = subscribed_tx.send(());
        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    let mut child = Command::new(rustscale_bin())
        .arg("--socket")
        .arg(&socket)
        .arg("wait")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rustscale wait");
    subscribed_rx.await.expect("wait subscribed");
    let signal = Command::new("kill")
        .arg("-INT")
        .arg(child.id().to_string())
        .output()
        .expect("send SIGINT");
    assert!(signal.status.success());

    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("wait did not cancel after SIGINT");
    let output = tokio::task::spawn_blocking(move || child.wait_with_output().unwrap())
        .await
        .unwrap();
    assert_failed(&output, "canceled");
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wait_help_is_successful_and_does_not_connect() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("absent.sock");
    let output = run_wait(&socket, &["--help"]).await;
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Usage: rustscale wait"));
    assert!(output.stderr.is_empty());
}
