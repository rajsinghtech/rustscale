use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::thread;

#[cfg(unix)]
use crate::{connect, listen};

#[cfg(unix)]
#[test]
fn test_listen_connect_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("test.sock");

    let listener = listen(&sock).unwrap();
    assert!(sock.exists(), "socket file should exist after listen");

    let server = thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        conn.write_all(b"hello").unwrap();

        let mut buf = [0u8; 1024];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"world");
    });

    let client = thread::spawn(move || {
        let mut conn = connect(&sock).unwrap();
        conn.write_all(b"world").unwrap();

        let mut buf = [0u8; 1024];
        let n = conn.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
    });

    server.join().unwrap();
    client.join().unwrap();
}

#[cfg(unix)]
#[test]
fn test_stale_socket_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("stale.sock");

    fs::write(&sock, b"stale").unwrap();
    assert!(sock.exists(), "stale file should exist");

    let listener = listen(&sock).unwrap();
    assert!(sock.exists(), "socket file should exist after re-listen");

    let conn = connect(&sock);
    assert!(conn.is_ok(), "should be able to connect to new listener");

    drop(listener);
}

#[cfg(unix)]
#[test]
fn test_listen_addr_in_use() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("busy.sock");

    let listener = listen(&sock).unwrap();

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

    drop(listener);
}

#[cfg(unix)]
#[test]
fn test_listen_creates_parent_dir() {
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
#[test]
fn test_connect_with_retries_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("never.sock");

    let start = std::time::Instant::now();
    let result = crate::connect_with_retries(&sock, std::time::Duration::from_millis(600));
    let elapsed = start.elapsed();

    assert!(result.is_err(), "should fail after timeout");
    assert!(
        elapsed >= std::time::Duration::from_millis(500),
        "should have retried for at least ~500ms (elapsed: {elapsed:?})"
    );
}

#[cfg(unix)]
#[test]
fn test_connect_with_retries_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let sock: PathBuf = dir.path().join("late.sock");

    let sock_clone = sock.clone();
    let server = thread::spawn(move || {
        thread::sleep(std::time::Duration::from_millis(300));
        let _listener = listen(&sock_clone).unwrap();
        thread::sleep(std::time::Duration::from_secs(5));
    });

    let result = crate::connect_with_retries(&sock, std::time::Duration::from_secs(3));
    assert!(result.is_ok(), "should connect after daemon starts");

    server.join().unwrap();
}
