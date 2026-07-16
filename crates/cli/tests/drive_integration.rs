#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

const ETAG_ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const ETAG_ONE: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn rustscale_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rustscale"))
}

async fn run_drive(socket: &Path, args: &[&str]) -> Output {
    let socket = socket.to_owned();
    let args = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
    tokio::task::spawn_blocking(move || {
        Command::new(rustscale_bin())
            .arg("--socket")
            .arg(socket)
            .arg("drive")
            .args(args)
            .output()
            .expect("run rustscale drive")
    })
    .await
    .expect("join rustscale drive")
}

async fn accept_request(listener: &UnixListener) -> (UnixStream, String, Vec<u8>) {
    let (mut stream, _) = listener.accept().await.expect("accept LocalAPI client");
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.expect("read request");
        head.push(byte[0]);
        assert!(head.len() <= 64 * 1024, "request header was unbounded");
    }
    let head = String::from_utf8(head).expect("request is UTF-8");
    assert!(
        !head.to_ascii_lowercase().contains("authorization:"),
        "LocalAPI authorization must come from peer credentials"
    );
    let content_length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    let mut body = vec![0; content_length];
    stream
        .read_exact(&mut body)
        .await
        .expect("read request body");
    (stream, head, body)
}

async fn respond_json(stream: &mut UnixStream, status: &str, etag: Option<&str>, body: &[u8]) {
    let etag = etag.map_or(String::new(), |value| format!("ETag: \"{value}\"\r\n"));
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\n{etag}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    stream.shutdown().await.unwrap();
}

fn assert_failed(output: &Output, needle: &str) {
    assert_eq!(output.status.code(), Some(1), "status: {:?}", output.status);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(needle),
        "stderr {stderr:?} did not contain {needle:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drive_list_matches_upstream_text_and_json_shapes() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("list.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let body = serde_json::to_vec(&serde_json::json!({
        "enabled": true,
        "shares": [{"name": "docs", "path": root, "who": ""}]
    }))
    .unwrap();
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, request, _) = accept_request(&listener).await;
            assert!(request.starts_with("GET /localapi/v0/drive/config HTTP/1.1\r\n"));
            respond_json(&mut stream, "200 OK", Some(ETAG_ONE), &body).await;
        }
        let (mut stream, request, _) = accept_request(&listener).await;
        assert!(request.starts_with("GET /localapi/v0/drive/status HTTP/1.1\r\n"));
        respond_json(
            &mut stream,
            "200 OK",
            None,
            br#"{"enabled":true,"sharingAllowed":true,"generation":7,"shares":[]}"#,
        )
        .await;
    });

    let text = run_drive(&socket, &["list"]).await;
    assert!(
        text.status.success(),
        "{}",
        String::from_utf8_lossy(&text.stderr)
    );
    let stdout = String::from_utf8_lossy(&text.stdout);
    assert!(stdout.starts_with("name    path"), "stdout: {stdout}");
    assert!(stdout.contains("docs"));

    let json = run_drive(&socket, &["list", "--json"]).await;
    assert!(
        json.status.success(),
        "{}",
        String::from_utf8_lossy(&json.stderr)
    );
    let shares: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(shares[0]["name"], "docs");

    let status = run_drive(&socket, &["status", "--json"]).await;
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    let status_json: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status_json["sharingAllowed"], true);
    assert_eq!(status_json["generation"], 7);
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_share_commands_use_one_etag_and_cannot_lose_an_update() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("cas.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let first_root = std::fs::canonicalize(dir.path()).unwrap();
    let second_dir = tempfile::tempdir().unwrap();
    let second_root = std::fs::canonicalize(second_dir.path()).unwrap();

    let first = Command::new(rustscale_bin())
        .arg("--socket")
        .arg(&socket)
        .args(["drive", "share", "first"])
        .arg(&first_root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let second = Command::new(rustscale_bin())
        .arg("--socket")
        .arg(&socket)
        .args(["drive", "share", "second"])
        .arg(&second_root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let empty = br#"{"enabled":false,"shares":[]}"#;
    let (mut get_one, request_one, _) = accept_request(&listener).await;
    let (mut get_two, request_two, _) = accept_request(&listener).await;
    assert!(request_one.starts_with("GET /localapi/v0/drive/config "));
    assert!(request_two.starts_with("GET /localapi/v0/drive/config "));
    respond_json(&mut get_one, "200 OK", Some(ETAG_ZERO), empty).await;
    respond_json(&mut get_two, "200 OK", Some(ETAG_ZERO), empty).await;

    let success_body = br#"{"enabled":true,"sharingAllowed":true,"generation":1,"shares":[]}"#;
    let (mut put_one, first_head, first_body) = accept_request(&listener).await;
    assert!(first_head.starts_with("PUT /localapi/v0/drive/config "));
    assert!(first_head.contains(&format!("If-Match: \"{ETAG_ZERO}\"")));
    respond_json(&mut put_one, "200 OK", Some(ETAG_ONE), success_body).await;

    let (mut put_two, second_head, second_body) = accept_request(&listener).await;
    assert!(second_head.starts_with("PUT /localapi/v0/drive/config "));
    assert!(second_head.contains(&format!("If-Match: \"{ETAG_ZERO}\"")));
    respond_json(
        &mut put_two,
        "412 Precondition Failed",
        None,
        br#"{"error":"Taildrive configuration changed concurrently"}"#,
    )
    .await;

    let requested_names = [first_body, second_body]
        .into_iter()
        .map(|body| {
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["shares"][0]["name"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert!(requested_names.contains(&"first".to_owned()));
    assert!(requested_names.contains(&"second".to_owned()));

    let (first_output, second_output) = tokio::join!(
        tokio::task::spawn_blocking(move || first.wait_with_output().unwrap()),
        tokio::task::spawn_blocking(move || second.wait_with_output().unwrap())
    );
    let outputs = [first_output.unwrap(), second_output.unwrap()];
    assert_eq!(
        outputs
            .iter()
            .filter(|output| output.status.success())
            .count(),
        1
    );
    let failed = outputs
        .iter()
        .find(|output| !output.status.success())
        .unwrap();
    assert!(String::from_utf8_lossy(&failed.stderr).contains("Preconditions failed"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drive_owner_denial_and_response_bounds_are_truthful() {
    let dir = tempfile::tempdir().unwrap();
    let denied_socket = dir.path().join("denied.sock");
    let denied_listener = UnixListener::bind(&denied_socket).unwrap();
    let denied_server = tokio::spawn(async move {
        let (mut stream, request, _) = accept_request(&denied_listener).await;
        assert!(request.starts_with("GET /localapi/v0/drive/config "));
        respond_json(
            &mut stream,
            "403 Forbidden",
            None,
            br#"{"error":"owner-only Taildrive configuration"}"#,
        )
        .await;
    });
    let denied = run_drive(&denied_socket, &["list"]).await;
    assert_failed(&denied, "access denied: owner-only Taildrive configuration");
    denied_server.await.unwrap();

    let mutation_socket = dir.path().join("mutation-denied.sock");
    let mutation_listener = UnixListener::bind(&mutation_socket).unwrap();
    let mutation_server = tokio::spawn(async move {
        let (mut get, request, _) = accept_request(&mutation_listener).await;
        assert!(request.starts_with("GET /localapi/v0/drive/config "));
        respond_json(
            &mut get,
            "200 OK",
            Some(ETAG_ZERO),
            br#"{"enabled":false,"shares":[]}"#,
        )
        .await;
        let (mut put, request, _) = accept_request(&mutation_listener).await;
        assert!(request.starts_with("PUT /localapi/v0/drive/config "));
        respond_json(
            &mut put,
            "403 Forbidden",
            None,
            br#"{"error":"Taildrive configuration requires root or the daemon user"}"#,
        )
        .await;
    });
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let mutation_denied =
        run_drive(&mutation_socket, &["share", "docs", root.to_str().unwrap()]).await;
    assert_failed(
        &mutation_denied,
        "OperatorUser cannot mutate Taildrive roots",
    );
    mutation_server.await.unwrap();

    let large_socket = dir.path().join("large.sock");
    let large_listener = UnixListener::bind(&large_socket).unwrap();
    let large_server = tokio::spawn(async move {
        let (mut stream, _, _) = accept_request(&large_listener).await;
        stream
            .write_all(
                format!("HTTP/1.1 200 OK\r\nETag: \"{ETAG_ZERO}\"\r\nContent-Length: 1048577\r\nConnection: close\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
    });
    let oversized = run_drive(&large_socket, &["list"]).await;
    assert_failed(&oversized, "response body too large");
    large_server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drive_rejects_name_symlink_special_and_remote_attacks_before_localapi() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let canonical = std::fs::canonicalize(dir.path()).unwrap();
    let missing_socket = canonical.join("absent.sock");
    let real = canonical.join("real");
    std::fs::create_dir(&real).unwrap();
    let link = canonical.join("link");
    symlink(&real, &link).unwrap();
    let special = canonical.join("special.sock");
    let _special_listener = std::os::unix::net::UnixListener::bind(&special).unwrap();

    let invalid_name = run_drive(
        &missing_socket,
        &["share", "../bad", real.to_str().unwrap()],
    )
    .await;
    assert_failed(&invalid_name, "invalid share name");
    let symlink_root = run_drive(&missing_socket, &["share", "docs", link.to_str().unwrap()]).await;
    assert_failed(&symlink_root, "unable to open Taildrive root");
    let special_root = run_drive(
        &missing_socket,
        &["share", "docs", special.to_str().unwrap()],
    )
    .await;
    assert_failed(&special_root, "unable to open Taildrive root");
    let traversal = canonical.join("real").join("..").join("real");
    let traversal_root = run_drive(
        &missing_socket,
        &["share", "docs", traversal.to_str().unwrap()],
    )
    .await;
    assert_failed(&traversal_root, "not a canonical absolute path");
    let remote = run_drive(&missing_socket, &["mount", "peer/docs"]).await;
    assert_failed(&remote, "remote Taildrive mounts");
    let bookmark = run_drive(&missing_socket, &["share", "docs", "--bookmark=data"]).await;
    assert_failed(&bookmark, "bookmarks are not supported");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drive_ctrl_c_cancels_an_inflight_localapi_request() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("cancel.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let (received_tx, received_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (_stream, request, _) = accept_request(&listener).await;
        assert!(request.starts_with("GET /localapi/v0/drive/config "));
        let _ = received_tx.send(());
        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    let mut child = Command::new(rustscale_bin())
        .arg("--socket")
        .arg(&socket)
        .args(["drive", "list"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    received_rx.await.unwrap();
    let signal = Command::new("kill")
        .arg("-INT")
        .arg(child.id().to_string())
        .output()
        .unwrap();
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
    .expect("drive did not cancel");
    let output = child.wait_with_output().unwrap();
    assert_failed(&output, "drive: canceled");
    server.abort();
}
