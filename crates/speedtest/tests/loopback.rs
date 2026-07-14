use std::time::Duration;

use rustscale_speedtest::{handle_connection, run, Config, ConfigResponse, Direction, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn start_server() -> std::io::Result<std::net::SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("server accepts connection");
        let _ = handle_connection(&mut stream).await;
    });
    Ok(address)
}

fn assert_results(results: &[Result]) {
    assert!(results.iter().any(|result| !result.is_total));
    assert!(results.last().is_some_and(|result| result.is_total));
    assert!(results.last().is_some_and(|result| result.bytes > 0));
    for result in results {
        assert!(result.interval_start <= result.interval_end);
        assert!(result.mbits_per_sec().is_finite());
        assert!(!result.mbits_per_sec().is_nan());
    }
    let intervals: Vec<_> = results.iter().filter(|result| !result.is_total).collect();
    for pair in intervals.windows(2) {
        assert!(pair[0].interval_start <= pair[1].interval_start);
        assert!(pair[0].interval_end <= pair[1].interval_end);
    }
}

async fn assert_loopback(direction: Direction) {
    match start_server().await {
        Ok(address) => {
            let mut stream = TcpStream::connect(address).await.unwrap();
            let results = run(&mut stream, direction, Duration::from_secs(2))
                .await
                .unwrap();
            assert_results(&results);
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            // Some sandboxed environments prohibit all socket operations. A duplex
            // stream still exercises the same handshake and data-phase code paths.
            let (mut client, mut server) = tokio::io::duplex(2 * 1024 * 1024);
            let server_task = tokio::spawn(async move { handle_connection(&mut server).await });
            let results = run(&mut client, direction, Duration::from_millis(100))
                .await
                .unwrap();
            assert_results(&results);
            server_task.await.unwrap().unwrap();
        }
        Err(error) => panic!("bind loopback server: {error}"),
    }
}

async fn write_config<S>(stream: &mut S, config: &Config)
where
    S: AsyncWrite + Unpin,
{
    let mut line = serde_json::to_vec(config).unwrap();
    line.push(b'\n');
    stream.write_all(&line).await.unwrap();
    stream.flush().await.unwrap();
}

async fn read_response<S>(stream: &mut S) -> ConfigResponse
where
    S: AsyncRead + Unpin,
{
    let mut line = Vec::new();
    loop {
        let byte = stream.read_u8().await.unwrap();
        if byte == b'\n' {
            return serde_json::from_slice(&line).unwrap();
        }
        line.push(byte);
    }
}

#[tokio::test]
async fn test_download_loopback() {
    assert_loopback(Direction::Download).await;
}

#[tokio::test]
async fn test_upload_loopback() {
    assert_loopback(Direction::Upload).await;
}

#[tokio::test]
async fn test_version_mismatch_rejected() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    let server_task = tokio::spawn(async move { handle_connection(&mut server).await });
    write_config(
        &mut client,
        &Config {
            version: 1,
            test_duration_ns: Duration::from_secs(2).as_nanos() as u64,
            direction: Direction::Download,
        },
    )
    .await;
    let response = read_response(&mut client).await;
    assert!(response
        .error
        .is_some_and(|error| error.starts_with("version mismatch!")));
    assert!(server_task.await.unwrap().is_err());
}

#[tokio::test]
async fn test_invalid_duration_rejected() {
    let (mut client, _server) = tokio::io::duplex(1024);
    let error = run(&mut client, Direction::Download, Duration::ZERO)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        rustscale_speedtest::SpeedtestError::InvalidDuration(_)
    ));
}
