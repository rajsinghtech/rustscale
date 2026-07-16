use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(unix)]
use crate::{connect, connect_with_retries_with_handle, listen};

#[cfg(unix)]
#[test]
fn sync_apis_without_runtime_return_errors_without_panicking() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("no-runtime.sock");
    let result = std::panic::catch_unwind(|| listen(&path));
    let error = result
        .expect("must not panic")
        .expect_err("runtime is required");
    assert_eq!(error.kind(), std::io::ErrorKind::NotConnected);
    assert!(!path.exists(), "runtime check must precede socket creation");
}

#[cfg(unix)]
#[tokio::test]
async fn test_listen_connect_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("test.sock");

    let listener = listen(&sock).unwrap();
    assert!(sock.exists(), "socket file should exist after listen");

    let server = tokio::spawn(async move {
        let mut conn = listener.accept().await.unwrap();
        conn.write_all(b"hello").await.unwrap();

        let mut buf = [0u8; 1024];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"world");
    });

    let client = tokio::spawn(async move {
        let mut conn = connect(&sock).unwrap();
        conn.write_all(b"world").await.unwrap();

        let mut buf = [0u8; 1024];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
    });

    server.await.unwrap();
    client.await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn test_stale_socket_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("stale.sock");

    std::fs::write(&sock, b"stale").unwrap();
    assert!(sock.exists(), "stale file should exist");

    let listener = listen(&sock).unwrap();
    assert!(sock.exists(), "socket file should exist after re-listen");

    let conn = connect(&sock);
    assert!(conn.is_ok(), "should be able to connect to new listener");

    drop(listener);
}

#[cfg(unix)]
#[tokio::test]
async fn test_listen_addr_in_use() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("busy.sock");

    let _listener = listen(&sock).unwrap();

    let result = listen(&sock);
    assert!(
        result.is_err(),
        "second listen on a live socket should fail"
    );
    let err = result.unwrap_err();
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::AddrInUse,
        "error should be AddrInUse"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_listen_creates_parent_dir() {
    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("a/b/c");
    let sock = nested.join("test.sock");

    let listener = listen(&sock).unwrap();
    assert!(sock.exists(), "socket should exist in nested dir");

    drop(listener);
}

#[cfg(unix)]
#[test]
fn test_connect_nonexistent_path() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("nope.sock");

    let result = connect(&sock);
    assert!(
        result.is_err(),
        "connecting to nonexistent socket should fail"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_connect_with_retries_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("never.sock");

    let start = std::time::Instant::now();
    let handle = tokio::runtime::Handle::current();
    let result = tokio::task::spawn_blocking(move || {
        connect_with_retries_with_handle(&handle, &sock, Duration::from_millis(600))
    })
    .await
    .unwrap();
    let elapsed = start.elapsed();

    assert!(result.is_err(), "should fail after timeout");
    assert!(
        elapsed >= Duration::from_millis(500),
        "should have retried for at least ~500ms (elapsed: {elapsed:?})"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_connect_with_retries_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let sock: std::path::PathBuf = dir.path().join("late.sock");

    let sock_clone = sock.clone();
    let server = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let _listener = listen(&sock_clone).unwrap();
        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    let handle = tokio::runtime::Handle::current();
    let result = tokio::task::spawn_blocking({
        let sock = sock.clone();
        move || connect_with_retries_with_handle(&handle, &sock, Duration::from_secs(3))
    })
    .await
    .unwrap();
    assert!(result.is_ok(), "should connect after daemon starts");

    server.abort();
}

// ---------------------------------------------------------------------------
// Windows named-pipe loopback test
// ---------------------------------------------------------------------------

#[cfg(windows)]
#[tokio::test]
async fn test_named_pipe_loopback_echo() {
    use crate::windows;

    let pipe_name = format!(
        r"\\.\pipe\ProtectedPrefix\Administrators\Rustscale\test-{}",
        std::process::id()
    );
    let path = std::path::PathBuf::from(&pipe_name);

    let listener = windows::listen(&path).unwrap();

    let server = tokio::spawn(async move {
        let mut conn = listener.accept().await.unwrap();
        let mut buf = [0u8; 64];
        let n = conn.read(&mut buf).await.unwrap();
        conn.write_all(&buf[..n]).await.unwrap();
    });

    let client = tokio::spawn(async move {
        // Brief delay so the server has called accept/connect before we open.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut conn = windows::connect(&path).unwrap();
        conn.write_all(b"pipe-echo").await.unwrap();
        let mut buf = [0u8; 64];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"pipe-echo");
    });

    server.await.unwrap();
    client.await.unwrap();
}
