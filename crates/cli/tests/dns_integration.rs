#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

fn rustscale_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rustscale"))
}

async fn run_dns(socket: &Path, args: &[&str]) -> Output {
    let socket = socket.to_owned();
    let args = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
    tokio::task::spawn_blocking(move || {
        Command::new(rustscale_bin())
            .arg("--socket")
            .arg(socket)
            .arg("dns")
            .args(args)
            .output()
            .expect("run rustscale dns")
    })
    .await
    .expect("join rustscale dns")
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
    (
        stream,
        String::from_utf8(request).expect("request is UTF-8"),
    )
}

async fn respond_json(stream: &mut UnixStream, body: &[u8]) {
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    stream.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_dispatches_to_status_instead_of_querying_the_name_status() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("dns-status.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, request) = accept_request(&listener).await;
        assert!(request.starts_with("GET /localapi/v0/status HTTP/1.1\r\n"));
        assert!(!request.contains("dns-query"));
        assert!(!request.contains("name=status"));
        respond_json(
            &mut stream,
            br#"{"CurrentTailnet":{"MagicDNSEnabled":true,"MagicDNSSuffix":"tailnet.ts.net"},"CertDomains":["host.tailnet.ts.net"]}"#,
        )
        .await;
    });

    let output = run_dns(&socket, &["status"]).await;
    assert!(
        output.status.success(),
        "dns status failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "MagicDNS: enabled\nMagicDNS suffix: tailnet.ts.net\nCert domains: host.tailnet.ts.net\n"
    );
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn query_forwards_the_actual_name_and_type_and_filters_aaaa_results() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("dns-query.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, request) = accept_request(&listener).await;
        assert!(request.starts_with(
            "GET /localapi/v0/dns-query?name=host.tailnet.ts.net&type=AAAA HTTP/1.1\r\n"
        ));
        assert!(!request.contains("name=query"));
        respond_json(
            &mut stream,
            br#"{"name":"host.tailnet.ts.net","type":"AAAA","results":["100.64.0.8","fd7a:115c:a1e0::8"],"magicdns_enabled":true}"#,
        )
        .await;
    });

    let output = run_dns(&socket, &["query", "host.tailnet.ts.net", "aaaa"]).await;
    assert!(
        output.status.success(),
        "dns query failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "fd7a:115c:a1e0::8\n"
    );
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_arguments_fail_before_connecting_to_localapi() {
    let dir = tempfile::tempdir().unwrap();
    let missing_socket = dir.path().join("does-not-exist.sock");

    for (args, message) in [
        (&["query"][..], "missing required argument: name"),
        (&["query", "host", "TXT"][..], "supports only A and AAAA"),
        (
            &["status", "extra"][..],
            "unexpected argument for 'dns status'",
        ),
        (&["host.tailnet.ts.net"][..], "unknown DNS subcommand"),
    ] {
        let output = run_dns(&missing_socket, args).await;
        assert_eq!(output.status.code(), Some(1), "args: {args:?}");
        assert!(output.stdout.is_empty(), "args: {args:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stderr.contains(message),
            "stderr {stderr:?} did not contain {message:?} for {args:?}"
        );
        assert!(
            !stderr.contains("connect"),
            "validation reached LocalAPI: {stderr}"
        );
    }
}
